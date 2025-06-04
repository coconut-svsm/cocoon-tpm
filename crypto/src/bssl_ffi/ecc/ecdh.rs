// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! BoringSSL FFI backend  ECDH (C(1e, 1s) scheme) implementation.
//!
//! Refer to NIST SP800-56Ar3 and TCG TPM2 Library, Part 1, section C.6.1
//! ("ECDH").

extern crate alloc;
use alloc::vec::Vec;

use cocoon_tpm_bssl_bare_sys as bssl_bare_sys;

use super::super::{
    bssl_bn::{BsslBn, BsslBnCtx},
    error::{bssl_get_error, bssl_get_raw_error},
};
use super::bssl_ec_key::BsslEcKey;
use crate::ecc::{curve, ecdh, key};
use crate::{rng, CryptoError};
use crate::{
    tpm2_interface,
    utils_common::alloc::{try_alloc_vec, try_alloc_zeroizing_vec},
};
use core::ffi;

enum _EcdhCdhError {
    PointIsIdentity,
}

/// ECDH `Z` parameter computation primitive.
fn __ecdh_c_1_1_cdh_compute_z(
    curve_ops: &curve::CurveOps,
    local_priv_key: &BsslEcKey,
    remote_pub_key: &curve::AffinePoint,
) -> Result<Result<zeroize::Zeroizing<Vec<u8>>, _EcdhCdhError>, CryptoError> {
    let mut z_buf = try_alloc_zeroizing_vec::<u8>(curve_ops.get_curve().get_p_len())?;

    let r = unsafe {
        bssl_bare_sys::ECDH_compute_key(
            z_buf.as_mut_ptr() as *mut ffi::c_void,
            z_buf.len(),
            remote_pub_key.bssl_ec_point,
            local_priv_key.as_ptr(),
            None,
        )
    };
    if r < 0 {
        // Check for identity point. It cannot really happen with the prime orders of
        // any curve supported by BoringSSL, but still check it anyway for good measure.
        let err = bssl_get_raw_error().ok_or(CryptoError::Internal)?;
        if err.is_code(bssl_bare_sys::ERR_LIB_EC, bssl_bare_sys::EC_R_POINT_AT_INFINITY) {
            return Ok(Err(_EcdhCdhError::PointIsIdentity));
        }
        return Err(CryptoError::from(err));
    } else if r as usize != z_buf.len() {
        return Err(CryptoError::Internal);
    }

    Ok(Ok(z_buf))
}

pub(crate) fn _ecdh_c_1_1_cdh_compute_z(
    curve_ops: &curve::CurveOps,
    local_priv_key: &key::EccKey,
    remote_pub_key_plain: &tpm2_interface::TpmsEccPoint<'_>,
) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
    // First convert the externally provided TpmsEccPoint into the internal
    // EccPublicKey representation. Note thay this validates it.
    let remote_pub_key = key::EccPublicKey::try_from((curve_ops, remote_pub_key_plain))?;

    if local_priv_key.priv_key().is_none() {
        return Err(CryptoError::NoKey);
    }
    let local_priv_key = BsslEcKey::new_from_ecc_key(local_priv_key, curve_ops)?;

    // The CDH primitive would end up at the point at infinity only if the peer sent
    // some bogus ephemeral public key, abort in this case.
    __ecdh_c_1_1_cdh_compute_z(curve_ops, &local_priv_key, remote_pub_key.get_point())?
        .map_err(|_| CryptoError::InvalidResult)
}

/// Generate a shared encryption key on behalf of an initiator from a local
/// ephemeral private key and a remote public key.
///
/// The local ephemeral ECC key will get generated on the fly, with its private
/// key part being destroyed after the operation is complete.
/// The public part gets returned alongside the shared secret.
///
/// The KDF used for secret derivation is
/// [`KDFe()`](crate::kdf::tcg_tpm2_kdf_e::TcgTpm2KdfE), with
/// party `U` identifying the local initiator party contributing the ephemeral
/// key and party `V` the remote responder party supplying its static key's
/// public part. Refer to TCG TPM2 Library, Part 1, section 11.4.10.3 ("KDFe for
/// ECDH").
///
/// # Arguments:
///
/// * `kdf_hash_alg` - The hash algorithm to use for
///   [`KDFe()`](crate::kdf::tcg_tpm2_kdf_e::TcgTpm2KdfE). The produced shared
///   secret will have the same length as the digest.
/// * `kdf_label` - The label to use for the
///   [`KDFe()`](crate::kdf::tcg_tpm2_kdf_e::TcgTpm2KdfE)'s `usage` parameter.
/// * `curve_id`: The elliptic curve id.
/// * `pub_key_v_plain` - The remote public key.
/// * `rng` - The [random number generator](rng::RngCore) to be used for
///   generating the ephemeral local key. It might not get invoked by the
///   backend in case that draws randomness from some alternative internal rng
///   instance.
/// * `additional_rng_generate_input` - Additional input to pass along to the
///   `rng`'s [generate()](rng::RngCore::generate) primitive.
pub fn ecdh_c_1e_1s_cdh_party_u_key_gen(
    kdf_hash_alg: tpm2_interface::TpmiAlgHash,
    kdf_label: &str,
    curve_id: tpm2_interface::TpmEccCurve,
    pub_key_v_plain: &tpm2_interface::TpmsEccPoint<'_>,
    _rng: &mut dyn rng::RngCoreDispatchable,
    _additional_rng_generate_input: Option<&[Option<&[u8]>]>,
) -> Result<(zeroize::Zeroizing<Vec<u8>>, tpm2_interface::TpmsEccPoint<'static>), CryptoError> {
    // In the terminology of NIST SP800-56Ar3, party V contributes the static key,
    // party U (the local party) an ephemeral key. Generate the ephemeral key
    // first.
    let curve = curve::Curve::new(curve_id)?;
    let curve_ops = curve.curve_ops()?;

    // Convert the externally provided TpmsEccPoint into the internal
    // EccPublicKey representation. Note thay this validates it.
    let pub_key_v = key::EccPublicKey::try_from((&curve_ops, pub_key_v_plain))?;

    const MAX_RETRIES: u32 = 16;
    let mut remaining_retries = MAX_RETRIES;
    let (bssl_ec_key_u, z) = loop {
        if remaining_retries == 0 {
            return Err(CryptoError::RandomSamplingRetriesExceeded);
        }
        remaining_retries -= 1;

        let bssl_ec_key_u = BsslEcKey::generate(&curve_ops)?;
        let z = match __ecdh_c_1_1_cdh_compute_z(&curve_ops, &bssl_ec_key_u, pub_key_v.get_point())? {
            Ok(z) => z,
            Err(e) => match e {
                _EcdhCdhError::PointIsIdentity => {
                    continue;
                }
            },
        };

        break (bssl_ec_key_u, z);
    };

    // Convert the ephemeral public key of U into plain affine coordinates.  Don't
    // go through AffinePoint::to_plain_coordinates(), as constructing an
    // EC_POINT out from the EC_KEY would involve a EC_POINT_dup().
    let bssl_ec_point_pub_u = unsafe { bssl_bare_sys::EC_KEY_get0_public_key(bssl_ec_key_u.as_ptr()) };
    let mut bssl_bn_u_x = BsslBn::new()?;
    let mut bssl_bn_u_y = BsslBn::new()?;
    let mut bn_ctx = BsslBnCtx::new()?;
    if unsafe {
        bssl_bare_sys::EC_POINT_get_affine_coordinates(
            curve_ops.bssl_ec_group.as_ptr(),
            bssl_ec_point_pub_u,
            bssl_bn_u_x.as_mut_ptr(),
            bssl_bn_u_y.as_mut_ptr(),
            bn_ctx.as_mut_ptr(),
        )
    } == 0
    {
        return Err(bssl_get_error());
    }
    drop(bn_ctx);
    drop(bssl_ec_key_u);
    let mut pub_key_u_x = try_alloc_vec(curve.get_p_len())?;
    bssl_bn_u_x.to_be_bytes(&mut cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut pub_key_u_x))?;
    drop(bssl_bn_u_x);
    let mut pub_key_u_y = try_alloc_vec(curve.get_p_len())?;
    bssl_bn_u_y.to_be_bytes(&mut cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut pub_key_u_y))?;
    drop(bssl_bn_u_y);

    let pub_key_v_x = &pub_key_v_plain.x.buffer;

    let shared_secret =
        ecdh::_ecdh_c_1e_1s_cdh_derive_shared_secret(&z, kdf_hash_alg, kdf_label, &pub_key_u_x, pub_key_v_x)?;

    let pub_key_u_plain = tpm2_interface::TpmsEccPoint {
        x: tpm2_interface::Tpm2bEccParameter {
            buffer: tpm2_interface::TpmBuffer::Owned(pub_key_u_x),
        },
        y: tpm2_interface::Tpm2bEccParameter {
            buffer: tpm2_interface::TpmBuffer::Owned(pub_key_u_y),
        },
    };

    Ok((shared_secret, pub_key_u_plain))
}
