// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of ECDH (C(1e, 1s) scheme).
//!
//! Refer to NIST SP800-56Ar3 and TCG TPM2 Library, Part 1, section C.6.1
//! ("ECDH").

extern crate alloc;
use alloc::vec::Vec;

use super::{curve, key};

use crate::{
    CryptoError, hash,
    kdf::{self, Kdf as _},
};
use crate::{
    tpm2_interface,
    utils_common::{
        alloc::{try_alloc_vec, try_alloc_zeroizing_vec},
        io_slices::{self, IoSlicesIterCommon as _},
        zeroize,
    },
};

/// Derive a shared secret from `Z` by applying
/// [`KDFe()`](kdf::tcg_tpm2_kdf_e::TcgTpm2KdfE).
///
/// Apply [`KDFe()`](kdf::tcg_tpm2_kdf_e::TcgTpm2KdfE) to obtain a shared secret
/// from ECDH `Z`.
///
/// Refer to TCG TPM2 Library, Part 1, section C.6.1 ("ECDH") and section
/// 11.4.10.3 ("KDFe for ECDH").
///
/// # Arguments:
///
/// * `z`: `Z` output from the ECDH primitive operation.
/// * `kdf_hash_alg` - The hash algorithm to use for
///   [`KDFe()`](crate::kdf::tcg_tpm2_kdf_e::TcgTpm2KdfE). The produced shared
///   secret will have the same length as the digest.
/// * `kdf_label` - The label to use for the
///   [`KDFe()`](crate::kdf::tcg_tpm2_kdf_e::TcgTpm2KdfE)'s `usage` parameter.
/// * `pub_key_u_x` - x-coordinate of party `U`'s public key.
/// * `pub_key_v_x` - x-coordinate of party `V`'s public key.
pub(crate) fn _ecdh_c_1e_1s_cdh_derive_shared_secret(
    z: &[u8],
    kdf_hash_alg: tpm2_interface::TpmiAlgHash,
    kdf_label: &str,
    pub_key_u_x: &[u8],
    pub_key_v_x: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
    // TCG TPM2 Library, Part 1, section C.6.1 ("ECDH"): the shared secret's
    // ("seed" in the referenced section's terminology) length will be
    // the size of the digest produced by the hash algorithm.
    let digest_len = hash::hash_alg_digest_len(kdf_hash_alg);
    let mut shared_secret = try_alloc_zeroizing_vec::<u8>(digest_len as usize)?;

    // TCG TPM2 Library, Part 1, section C.6.1 ("ECDH"): PartyUInfo and
    // PartyVInfo respectively are to be set to the respective x-coordinates
    // of the parties' associated public keys each.
    let kdf_e = kdf::tcg_tpm2_kdf_e::TcgTpm2KdfE::new(
        kdf_hash_alg,
        z,
        kdf_label,
        pub_key_u_x,
        pub_key_v_x,
        8 * (digest_len as u32),
    )
    .unwrap();
    kdf_e.generate(io_slices::SingletonIoSliceMut::new(&mut shared_secret).map_infallible_err())?;
    Ok(shared_secret)
}

use crate::backend::ecc::ecdh::_ecdh_c_1_1_cdh_compute_z;

/// Compute the ECDH `Z` from a local private and a remote public key.
///
/// <div class="warning">
///
/// Do not use directly as an encryption key, `Z` must get run through a
/// suitable KDF.
///
/// </div>
///
/// # Arguments:
///
/// * `local_priv_key` - The local private key.
/// * `remote_pub_key_plain` - The remote public key.
pub fn ecdh_c_1_1_cdh_compute_z(
    local_priv_key: &key::EccKey,
    remote_pub_key_plain: &tpm2_interface::TpmsEccPoint<'_>,
) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
    let curve = curve::Curve::new(local_priv_key.pub_key().get_curve_id())?;
    let curve_ops = curve.curve_ops()?;
    _ecdh_c_1_1_cdh_compute_z(&curve_ops, local_priv_key, remote_pub_key_plain)
}

/// Generate a shared encryption on behalf of a responder from a local static
/// private key and a remote (ephemeral) public key.
///
/// The KDF used for secret derivation is
/// [`KDFe()`](crate::kdf::tcg_tpm2_kdf_e::TcgTpm2KdfE), with
/// party `U` identifying the remote initiator party contributing its
/// (ephemeral) key's public part and party `V` the local responder party
/// supplying its static private key. Refer to TCG TPM2 Library, Part 1, section
/// 11.4.10.3 ("KDFe for ECDH").
///
/// # Arguments:
///
/// * `kdf_hash_alg` - The hash algorithm to use for
///   [`KDFe()`](kdf::tcg_tpm2_kdf_e::TcgTpm2KdfE). The produced shared secret
///   will have the same length as the digest.
/// * `kdf_label` - The label to use for the
///   [`KDFe()`](kdf::tcg_tpm2_kdf_e::TcgTpm2KdfE)'s `usage` parameter.
/// * `key_v` - The local private key.
/// * `pub_key_u_plain` - The remote public key.
pub fn ecdh_c_1e_1s_cdh_party_v_key_gen(
    kdf_hash_alg: tpm2_interface::TpmiAlgHash,
    kdf_label: &str,
    key_v: &key::EccKey,
    pub_key_u_plain: &tpm2_interface::TpmsEccPoint<'_>,
) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
    // In the terminology of NIST SP800-56Ar3, party V (the local party) contributes
    // the static key, party U (the remote party) an ephemeral key.
    let curve = curve::Curve::new(key_v.pub_key().get_curve_id())?;
    let curve_ops = curve.curve_ops()?;

    // In the terminology of NIST SP800-56Ar3, party V (the local party) contributes
    // the static key, party U (the remote party) an ephemeral key.
    let z = _ecdh_c_1_1_cdh_compute_z(&curve_ops, key_v, pub_key_u_plain)?;

    let pub_key_u_x = &pub_key_u_plain.x.buffer;
    let mut pub_key_v_x = try_alloc_vec::<u8>(curve_ops.get_curve().get_p_len())?;
    key_v.pub_key().get_point().to_plain_coordinates(
        &mut cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut pub_key_v_x),
        None,
        &curve_ops,
    )?;

    _ecdh_c_1e_1s_cdh_derive_shared_secret(&z, kdf_hash_alg, kdf_label, pub_key_u_x, &pub_key_v_x)
}

pub use crate::backend::ecc::ecdh::ecdh_c_1e_1s_cdh_party_u_key_gen;

#[test]
fn test_ecdh_c_1e_1s_cdh_key_gen() {
    use crate::rng;

    // Test a pairwise key establishment and verify both parties end up at the same
    // shared secret.
    let curve_id = curve::test_curve_id();
    let curve = curve::Curve::new(curve_id).unwrap();
    let curve_ops = curve.curve_ops().unwrap();
    let kdf_hash_alg = hash::test_hash_alg();
    const KDF_LABEL: &str = "test ECDH key establishment";
    let mut drbg = rng::test_rng();

    // First generate a static test key for party V.
    let key_v = key::EccKey::generate(&curve_ops, &mut drbg, None).unwrap();
    let pub_key_v_plain = key_v.pub_key().to_tpms_ecc_point(&curve_ops).unwrap();

    // Let party U initiated the ECDH establishment.
    let (shared_secret_u, mut pub_key_u_plain) =
        ecdh_c_1e_1s_cdh_party_u_key_gen(kdf_hash_alg, KDF_LABEL, curve_id, &pub_key_v_plain, &mut drbg, None).unwrap();

    // And let party V establish the shared secret with the ephemeral public key
    // conveyed by party U.
    let shared_secret_v =
        ecdh_c_1e_1s_cdh_party_v_key_gen(kdf_hash_alg, KDF_LABEL, &key_v, &mut pub_key_u_plain).unwrap();

    assert_eq!(&shared_secret_u, &shared_secret_v);
}
