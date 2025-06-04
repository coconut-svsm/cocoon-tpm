// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! BoringSSL FFI backend  ECDSA signature scheme implementation.
//!
//! Refer to NIST FIPS 186-5, sec. 6.4.1 ("ECDSA Signature Generation
//! Algorithm")

extern crate alloc;
use alloc::vec::Vec;

use cocoon_tpm_bssl_bare_sys as bssl_bare_sys;

use super::super::error::bssl_get_error;
use super::bssl_ec_key::BsslEcKey;
use crate::ecc::{curve, key};
use crate::utils_common::alloc::try_alloc_vec;
use crate::{rng, CryptoError};
use core::ptr;

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
    let bssl_ec_key = BsslEcKey::new_from_ecc_key(key, &curve_ops)?;
    let bssl_ecdsa_sig = unsafe { bssl_bare_sys::ECDSA_do_sign(digest.as_ptr(), digest.len(), bssl_ec_key.as_ptr()) };
    if bssl_ecdsa_sig.is_null() {
        return Err(bssl_get_error());
    }
    drop(bssl_ec_key);

    let mut bssl_bn_r: *const bssl_bare_sys::BIGNUM = ptr::null();
    let mut bssl_bn_s: *const bssl_bare_sys::BIGNUM = ptr::null();
    unsafe {
        bssl_bare_sys::ECDSA_SIG_get0(
            bssl_ecdsa_sig,
            &mut bssl_bn_r as *mut *const bssl_bare_sys::BIGNUM,
            &mut bssl_bn_s as *mut *const bssl_bare_sys::BIGNUM,
        )
    };
    let r_len =
        match usize::try_from(unsafe { bssl_bare_sys::BN_num_bytes(bssl_bn_r) }).map_err(|_| CryptoError::Internal) {
            Ok(r_len) => r_len,
            Err(e) => {
                unsafe { bssl_bare_sys::ECDSA_SIG_free(bssl_ecdsa_sig) };
                return Err(e);
            }
        };
    let s_len =
        match usize::try_from(unsafe { bssl_bare_sys::BN_num_bytes(bssl_bn_s) }).map_err(|_| CryptoError::Internal) {
            Ok(s_len) => s_len,
            Err(e) => {
                unsafe { bssl_bare_sys::ECDSA_SIG_free(bssl_ecdsa_sig) };
                return Err(e);
            }
        };

    let mut r_bytes = try_alloc_vec(r_len)?;
    let mut s_bytes = try_alloc_vec(s_len)?;
    if unsafe { bssl_bare_sys::BN_bn2bin_padded(r_bytes.as_mut_ptr(), r_len, bssl_bn_r) } < 0 {
        unsafe { bssl_bare_sys::ECDSA_SIG_free(bssl_ecdsa_sig) };
        return Err(bssl_get_error());
    }
    if unsafe { bssl_bare_sys::BN_bn2bin_padded(s_bytes.as_mut_ptr(), s_len, bssl_bn_s) } < 0 {
        unsafe { bssl_bare_sys::ECDSA_SIG_free(bssl_ecdsa_sig) };
        return Err(bssl_get_error());
    }
    unsafe { bssl_bare_sys::ECDSA_SIG_free(bssl_ecdsa_sig) };

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

    let bssl_ecdsa_sig = unsafe { bssl_bare_sys::ECDSA_SIG_new() };
    if bssl_ecdsa_sig.is_null() {
        return Err(bssl_get_error());
    }

    let bssl_bn_r = unsafe { bssl_bare_sys::BN_bin2bn(signature.0.as_ptr(), signature.0.len(), ptr::null_mut()) };
    if bssl_bn_r.is_null() {
        unsafe { bssl_bare_sys::ECDSA_SIG_free(bssl_ecdsa_sig) };
        return Err(bssl_get_error());
    }
    let bssl_bn_s = unsafe { bssl_bare_sys::BN_bin2bn(signature.1.as_ptr(), signature.1.len(), ptr::null_mut()) };
    if bssl_bn_s.is_null() {
        unsafe { bssl_bare_sys::BN_free(bssl_bn_r) };
        unsafe { bssl_bare_sys::ECDSA_SIG_free(bssl_ecdsa_sig) };
        return Err(bssl_get_error());
    }
    // This transfers ownership of r and s into the sig.
    if unsafe { bssl_bare_sys::ECDSA_SIG_set0(bssl_ecdsa_sig, bssl_bn_r, bssl_bn_s) } == 0 {
        unsafe { bssl_bare_sys::BN_free(bssl_bn_s) };
        unsafe { bssl_bare_sys::BN_free(bssl_bn_r) };
        unsafe { bssl_bare_sys::ECDSA_SIG_free(bssl_ecdsa_sig) };
        return Err(bssl_get_error());
    }

    let curve = curve::Curve::new(pub_key.get_curve_id())?;
    let curve_ops = curve.curve_ops()?;
    let bssl_ec_key = BsslEcKey::new_from_ecc_pub_key(pub_key, &curve_ops)?;

    let r =
        unsafe { bssl_bare_sys::ECDSA_do_verify(digest.as_ptr(), digest.len(), bssl_ecdsa_sig, bssl_ec_key.as_ptr()) };
    drop(bssl_ec_key);
    unsafe { bssl_bare_sys::ECDSA_SIG_free(bssl_ecdsa_sig) };
    if r == 1 {
        Ok(())
    } else if r == 0 {
        Err(CryptoError::SignatureVerificationFailure)
    } else {
        Err(bssl_get_error())
    }
}
