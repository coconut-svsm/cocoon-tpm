// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Red Hat
// Author: Oliver Steffen <osteffen@redhat.com>

//! OpenSSL FFI backend ECDSA signature scheme implementation.
//!
//! Refer to NIST FIPS 186-5, sec. 6.4.1 ("ECDSA Signature Generation
//! Algorithm")

extern crate alloc;
use alloc::vec::Vec;

use cmpa::MpUIntCommon;
use cocoon_tpm_ossl_bare_sys as ossl_bare_sys;

use super::super::error::ossl_get_error;
use super::ossl_ec_key::OsslEcKey;
use crate::ecc::{curve, key};
use crate::utils_common::alloc::try_alloc_vec;
use crate::{CryptoError, rng};
use core::{ffi, ptr};

/// ECDSA signature creation.
///
/// # Arguments:
///
/// * `digest` - The message digest to sign.
/// * `key` - The signing key. Must have the private part available.
/// * `rng` - The [random number generator](rng::RngCore) used for generating
///   the random integer `k`. It  might not get invoked by the backend in case
///   that draws randomness from some alternative internal rng instance.
/// * `additional_rng_generate_input` - Additional input to pass along to the
///   `rng`'s [generate()](rng::RngCore::generate) primitive.
pub fn sign(
    digest: &[u8],
    key: &key::EccKey,
    _rng: &mut dyn rng::RngCoreDispatchable,
    _additional_rng_generate_input: Option<&[Option<&[u8]>]>,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    if key.priv_key().is_none() {
        return Err(CryptoError::NoKey);
    } else if digest.is_empty() {
        // Signing zero-length digests makes no sense, don't even bother with
        // handling a dangling digest.as_ptr().
        return Err(CryptoError::Internal);
    }

    let curve = curve::Curve::new(key.pub_key().get_curve_id())?;
    let curve_ops = curve.curve_ops()?;
    let mut ossl_ec_key = OsslEcKey::new_from_ecc_key(key, &curve_ops)?;
    let ossl_ecdsa_sig =
        unsafe { ossl_bare_sys::ECDSA_do_sign(digest.as_ptr(), digest.len() as ffi::c_int, ossl_ec_key.as_mut_ptr()) };
    if ossl_ecdsa_sig.is_null() {
        return Err(ossl_get_error());
    }
    drop(ossl_ec_key);

    let mut ossl_bn_r: *const ossl_bare_sys::BIGNUM = ptr::null();
    let mut ossl_bn_s: *const ossl_bare_sys::BIGNUM = ptr::null();
    unsafe {
        ossl_bare_sys::ECDSA_SIG_get0(
            ossl_ecdsa_sig,
            &mut ossl_bn_r as *mut *const ossl_bare_sys::BIGNUM,
            &mut ossl_bn_s as *mut *const ossl_bare_sys::BIGNUM,
        )
    };
    let r_len = match usize::try_from(unsafe { ossl_bare_sys::ossl_shim_BN_num_bytes(ossl_bn_r) })
        .map_err(|_| CryptoError::Internal)
    {
        Ok(r_len) => r_len,
        Err(e) => {
            unsafe { ossl_bare_sys::ECDSA_SIG_free(ossl_ecdsa_sig) };
            return Err(e);
        }
    };
    let s_len = match usize::try_from(unsafe { ossl_bare_sys::ossl_shim_BN_num_bytes(ossl_bn_s) })
        .map_err(|_| CryptoError::Internal)
    {
        Ok(s_len) => s_len,
        Err(e) => {
            unsafe { ossl_bare_sys::ECDSA_SIG_free(ossl_ecdsa_sig) };
            return Err(e);
        }
    };

    // Canonical format is to pad r/s to order.len().
    let order = curve.get_order();
    if r_len > order.len() || s_len > order.len() {
        unsafe { ossl_bare_sys::ECDSA_SIG_free(ossl_ecdsa_sig) };
        return Err(CryptoError::Internal);
    }

    let mut r_bytes = match try_alloc_vec(order.len()) {
        Ok(r_bytes) => r_bytes,
        Err(e) => {
            unsafe { ossl_bare_sys::ECDSA_SIG_free(ossl_ecdsa_sig) };
            return Err(CryptoError::from(e));
        }
    };
    let mut s_bytes = match try_alloc_vec(order.len()) {
        Ok(s_bytes) => s_bytes,
        Err(e) => {
            unsafe { ossl_bare_sys::ECDSA_SIG_free(ossl_ecdsa_sig) };
            return Err(CryptoError::from(e));
        }
    };
    if unsafe { ossl_bare_sys::ossl_shim_BN_bn2bin_padded(r_bytes.as_mut_ptr(), order.len(), ossl_bn_r) } == 0 {
        unsafe { ossl_bare_sys::ECDSA_SIG_free(ossl_ecdsa_sig) };
        return Err(ossl_get_error());
    }
    if unsafe { ossl_bare_sys::ossl_shim_BN_bn2bin_padded(s_bytes.as_mut_ptr(), order.len(), ossl_bn_s) } == 0 {
        unsafe { ossl_bare_sys::ECDSA_SIG_free(ossl_ecdsa_sig) };
        return Err(ossl_get_error());
    }
    unsafe { ossl_bare_sys::ECDSA_SIG_free(ossl_ecdsa_sig) };

    Ok((r_bytes, s_bytes))
}

/// ECDSA signature verification.
///
/// # Arguments:
///
/// * `digest` - The signed message digest.
/// * `signature` - The signature to verify.
/// * `pub_key` - The verification key.
pub fn verify(digest: &[u8], signature: (&[u8], &[u8]), pub_key: &key::EccPublicKey) -> Result<(), CryptoError> {
    if digest.is_empty() {
        // Signing zero-length digests makes no sense, don't even bother with
        // handling a dangling digest.as_ptr().
        return Err(CryptoError::Internal);
    } else if signature.0.is_empty() || signature.1.is_empty() {
        // Empty signature components don't authenticate anything.
        return Err(CryptoError::SignatureVerificationFailure);
    }

    let ossl_ecdsa_sig = unsafe { ossl_bare_sys::ECDSA_SIG_new() };
    if ossl_ecdsa_sig.is_null() {
        return Err(ossl_get_error());
    }

    let ossl_bn_r =
        unsafe { ossl_bare_sys::BN_bin2bn(signature.0.as_ptr(), signature.0.len() as ffi::c_int, ptr::null_mut()) };
    if ossl_bn_r.is_null() {
        unsafe { ossl_bare_sys::ECDSA_SIG_free(ossl_ecdsa_sig) };
        return Err(ossl_get_error());
    }
    let ossl_bn_s =
        unsafe { ossl_bare_sys::BN_bin2bn(signature.1.as_ptr(), signature.1.len() as ffi::c_int, ptr::null_mut()) };
    if ossl_bn_s.is_null() {
        unsafe { ossl_bare_sys::BN_free(ossl_bn_r) };
        unsafe { ossl_bare_sys::ECDSA_SIG_free(ossl_ecdsa_sig) };
        return Err(ossl_get_error());
    }
    // This transfers ownership of r and s into the sig.
    if unsafe { ossl_bare_sys::ECDSA_SIG_set0(ossl_ecdsa_sig, ossl_bn_r, ossl_bn_s) } == 0 {
        unsafe { ossl_bare_sys::BN_free(ossl_bn_s) };
        unsafe { ossl_bare_sys::BN_free(ossl_bn_r) };
        unsafe { ossl_bare_sys::ECDSA_SIG_free(ossl_ecdsa_sig) };
        return Err(ossl_get_error());
    }

    let curve = match curve::Curve::new(pub_key.get_curve_id()) {
        Ok(curve) => curve,
        Err(e) => {
            unsafe { ossl_bare_sys::ECDSA_SIG_free(ossl_ecdsa_sig) };
            return Err(e);
        }
    };
    let curve_ops = match curve.curve_ops() {
        Ok(curve_ops) => curve_ops,
        Err(e) => {
            unsafe { ossl_bare_sys::ECDSA_SIG_free(ossl_ecdsa_sig) };
            return Err(e);
        }
    };
    let mut ossl_ec_key = match OsslEcKey::new_from_ecc_pub_key(pub_key, &curve_ops) {
        Ok(ossl_ec_key) => ossl_ec_key,
        Err(e) => {
            unsafe { ossl_bare_sys::ECDSA_SIG_free(ossl_ecdsa_sig) };
            return Err(e);
        }
    };

    let r = unsafe {
        ossl_bare_sys::ECDSA_do_verify(
            digest.as_ptr(),
            digest.len() as ffi::c_int,
            ossl_ecdsa_sig,
            ossl_ec_key.as_mut_ptr(),
        )
    };
    drop(ossl_ec_key);
    unsafe { ossl_bare_sys::ECDSA_SIG_free(ossl_ecdsa_sig) };
    if r == 1 {
        Ok(())
    } else if r == 0 {
        Err(CryptoError::SignatureVerificationFailure)
    } else {
        Err(ossl_get_error())
    }
}
