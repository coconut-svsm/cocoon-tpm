//! Pure Rust backend  ECDH (C(1e, 1s) scheme) implementation.
//!
//! Refer to NIST SP800-56Ar3 and TCG TPM2 Library, Part 1, section C.6.1
//! ("ECDH").

extern crate alloc;
use alloc::vec::Vec;

use crate::ecc::{curve, ecdh, key};
use crate::{CryptoError, rng};
use crate::{
    tpm2_interface,
    utils_common::{alloc::try_alloc_zeroizing_vec, zeroize},
};

enum _EcdhCdhError {
    PointIsIdentity,
}

/// ECDH `Z` parameter computation primitive.
fn __ecdh_c_1_1_cdh_compute_z(
    curve_ops: &curve::CurveOps,
    local_priv_key: &key::EccPrivateKey,
    remote_pub_key: &key::EccPublicKey,
) -> Result<Result<zeroize::Zeroizing<Vec<u8>>, _EcdhCdhError>, CryptoError> {
    let mut curve_ops_scratch = curve_ops.try_alloc_scratch()?;
    let d_q = curve_ops.point_scalar_mul(
        &local_priv_key.get_d(),
        remote_pub_key.get_point(),
        &mut curve_ops_scratch,
    )?;
    let h_d_q =
        curve_ops.point_double_repeated(d_q, curve_ops.get_curve().get_cofactor_log2(), &mut curve_ops_scratch)?;

    let mut z_buf = try_alloc_zeroizing_vec::<u8>(curve_ops.get_curve().get_p_len())?;
    let mut z = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut z_buf);
    h_d_q
        .into_affine_plain_coordinates(&mut z, None, curve_ops, Some(&mut curve_ops_scratch))
        .map(|r| {
            r.map(|_| z_buf).map_err(|e| match e {
                curve::ProjectivePointIntoAffineError::PointIsIdentity => _EcdhCdhError::PointIsIdentity,
            })
        })
}

pub(crate) fn _ecdh_c_1_1_cdh_compute_z(
    curve_ops: &curve::CurveOps,
    local_priv_key: &key::EccKey,
    remote_pub_key_plain: &tpm2_interface::TpmsEccPoint<'_>,
) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
    // First convert the externally provided TpmsEccPoint into the internal
    // EccPublicKey representation. Note thay this validates it.
    let remote_pub_key = key::EccPublicKey::try_from((curve_ops, remote_pub_key_plain))?;

    // The CDH primitive would end up at the point at infinity only if the peer sent
    // some bogus ephemeral public key, abort in this case.
    __ecdh_c_1_1_cdh_compute_z(
        curve_ops,
        local_priv_key.priv_key().ok_or(CryptoError::NoKey)?,
        &remote_pub_key,
    )?
    .map_err(|_| CryptoError::InvalidResult)
}

/// Generate a shared encryption key from a local ephemeral private key and a
/// remote public key.
///
/// The local ephemeral ECC key will get generated on the fly, with its private
/// key part being destroyed after the operation is complete.
/// The public part gets returned alongside the shared secret.
///
/// The KDF used for secret derivation is
/// [`KDFe()`](crate::kdf::tcg_tpm2_kdf_e::TcgTpm2KdfE), with
/// party `U` identifying the local party contributing the ephemeral key and
/// party `V` the remote party supplying its static key's public part.
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
    rng: &mut dyn rng::RngCoreDispatchable,
    additional_rng_generate_input: Option<&[Option<&[u8]>]>,
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
    let (pub_key_u, z) = loop {
        if remaining_retries == 0 {
            return Err(CryptoError::RandomSamplingRetriesExceeded);
        }
        remaining_retries -= 1;

        let key_u = key::EccKey::generate(&curve_ops, rng, additional_rng_generate_input)?;
        let priv_key_u = key_u.priv_key().unwrap();
        let z = match __ecdh_c_1_1_cdh_compute_z(&curve_ops, priv_key_u, &pub_key_v)? {
            Ok(z) => z,
            Err(e) => match e {
                _EcdhCdhError::PointIsIdentity => {
                    continue;
                }
            },
        };

        break (key_u.take_public(), z);
    };

    let pub_key_u_plain = pub_key_u.into_tpms_ecc_point(&curve_ops)?;
    let pub_key_u_x = &pub_key_u_plain.x.buffer;
    let pub_key_v_x = &pub_key_v_plain.x.buffer;

    Ok((
        ecdh::_ecdh_c_1e_1s_cdh_derive_shared_secret(&z, kdf_hash_alg, kdf_label, pub_key_u_x, pub_key_v_x)?,
        pub_key_u_plain,
    ))
}
