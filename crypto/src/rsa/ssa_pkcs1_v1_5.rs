// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of RFC 8017 RSASSA-PKCS-v1_5.

extern crate alloc;
use alloc::vec::Vec;

use super::key;
use crate::{CryptoError, hash};
use crate::{
    tpm2_interface,
    utils_common::{alloc::try_alloc_vec, zeroize::Zeroize as _},
};

// The signature containes a DER-encoded DigestInfo structure.
// From RFC 8017, sec. 9.2. ("EMSA-PKCS1-v1_5"):
//    DigestInfo ::= SEQUENCE {
//     digestAlgorithm AlgorithmIdentifier,
//     digest OCTET STRING
// }
//
// The TCG Algorithm Registry specifies for each hash algorithm the full DER
// encoding prefix, i.e. everything including TLVs, the encoded hash OID etc. so
// that prepending that to the actual, plain digest value will yield a
// DER-encoded DigestInfo. Reproduce these prefixes in what follows.
#[cfg(feature = "sha1")]
const DIGEST_INFO_DER_ENC_PREFIX_SHA1: &[u8] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14,
];

#[cfg(feature = "sha256")]
const DIGEST_INFO_DER_ENC_PREFIX_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
];

#[cfg(feature = "sha384")]
const DIGEST_INFO_DER_ENC_PREFIX_SHA384: &[u8] = &[
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
];

#[cfg(feature = "sha512")]
const DIGEST_INFO_DER_ENC_PREFIX_SHA512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
];

#[cfg(feature = "sha3_256")]
const DIGEST_INFO_DER_ENC_PREFIX_SHA3_256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x05, 0x00, 0x04, 0x20,
];

#[cfg(feature = "sha3_384")]
const DIGEST_INFO_DER_ENC_PREFIX_SHA3_384: &[u8] = &[
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09, 0x05, 0x00, 0x04, 0x30,
];

#[cfg(feature = "sha3_512")]
const DIGEST_INFO_DER_ENC_PREFIX_SHA3_512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a, 0x05, 0x00, 0x04, 0x40,
];

#[cfg(feature = "sm3_256")]
const DIGEST_INFO_DER_ENC_PREFIX_SM3_256: &[u8] = &[
    0x30, 0x30, 0x30, 0x0c, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0x81, 0x45, 0x01, 0x83, 0x11, 0x05, 0x00, 0x04, 0x20,
];

fn digest_info_der_enc_prefix_to_digest_len(der_enc_prefix: &[u8]) -> usize {
    // With DER short-form length encoding (which should be used for any digest
    // length <= 127 bytes, i.e. all), the last byte of the DigestInfo
    // encoding prefix contains the digest length.
    *der_enc_prefix.iter().last().unwrap() as usize
}

fn hash_alg_id_to_digest_info_der_enc_prefix(hash_alg: tpm2_interface::TpmiAlgHash) -> &'static [u8] {
    match hash_alg {
        #[cfg(feature = "sha1")]
        tpm2_interface::TpmiAlgHash::Sha1 => DIGEST_INFO_DER_ENC_PREFIX_SHA1,
        #[cfg(feature = "sha256")]
        tpm2_interface::TpmiAlgHash::Sha256 => DIGEST_INFO_DER_ENC_PREFIX_SHA256,
        #[cfg(feature = "sha384")]
        tpm2_interface::TpmiAlgHash::Sha384 => DIGEST_INFO_DER_ENC_PREFIX_SHA384,
        #[cfg(feature = "sha512")]
        tpm2_interface::TpmiAlgHash::Sha512 => DIGEST_INFO_DER_ENC_PREFIX_SHA512,
        #[cfg(feature = "sha3_256")]
        tpm2_interface::TpmiAlgHash::Sha3_256 => DIGEST_INFO_DER_ENC_PREFIX_SHA3_256,
        #[cfg(feature = "sha3_384")]
        tpm2_interface::TpmiAlgHash::Sha3_384 => DIGEST_INFO_DER_ENC_PREFIX_SHA3_384,
        #[cfg(feature = "sha3_512")]
        tpm2_interface::TpmiAlgHash::Sha3_512 => DIGEST_INFO_DER_ENC_PREFIX_SHA3_512,
        #[cfg(feature = "sm3_256")]
        tpm2_interface::TpmiAlgHash::Sm3_256 => DIGEST_INFO_DER_ENC_PREFIX_SM3_256,
    }
}

/// RFC 8017 RSASSA-PKCS-v1_5 signature creation.
///
/// For reference, see RFC 8017, sec 8.2.
///
/// # Arguments:
///
/// * `digest_hash_alg` - The hash algorithm used to produce `digest`.
/// * `digest` - The message digest to sign.
/// * `key` - The signing key. Must have the private part available.
pub fn sign(
    digest_hash_alg: tpm2_interface::TpmiAlgHash,
    digest: &[u8],
    key: &key::RsaKey,
) -> Result<Vec<u8>, CryptoError> {
    // Implementation according to RFC 8017, sec 8.2.1.

    // 8.2.1, step 1: apply EMSA-PKCS1-v1_5 encoding, specified in 9.2.
    // 9.2., steps 2-3.
    let digest_info_der_enc_prefix = hash_alg_id_to_digest_info_der_enc_prefix(digest_hash_alg);
    let digest_len = digest_info_der_enc_prefix_to_digest_len(digest_info_der_enc_prefix);
    if digest.len() != digest_len {
        return Err(CryptoError::Internal);
    }
    debug_assert_eq!(digest_len, hash::hash_alg_digest_len(digest_hash_alg) as usize);
    let digest_info_der_enc_len = digest_info_der_enc_prefix.len() + digest_len;
    let modulus_len = key.pub_key().modulus_len();
    if modulus_len < digest_info_der_enc_len + 11 {
        return Err(CryptoError::InvalidParams);
    }

    // signature corresponds to "EM" of 9.2.
    let mut signature = try_alloc_vec(modulus_len)?;
    let (ps, t) = signature.split_at_mut(modulus_len - digest_info_der_enc_len);

    t[..digest_info_der_enc_prefix.len()].copy_from_slice(digest_info_der_enc_prefix);
    t[digest_info_der_enc_prefix.len()..].copy_from_slice(digest);

    // 9.2. step 4-5.
    ps.fill(0xff);
    ps[0] = 0x00;
    ps[1] = 0x01;
    let ps_len = ps.len();
    ps[ps_len - 1] = 0x02;
    // The rest of step 5. is implicit.

    // 8.2.1, step 2: RSA signature.
    match key.decrypt(&mut signature) {
        Ok(()) => (),
        Err(e) => {
            signature.zeroize();
            return Err(e);
        }
    }
    Ok(signature)
}

/// RFC 8017 RSASSA-PKCS-v1_5 signature verification.
///
/// For reference, see RFC 8017, sec 8.2.
///
/// # Arguments:
///
/// * `digest_hash_alg` - The hash algorithm used to produce `digest`.
/// * `digest` - The signed message digest.
/// * `signature` - The signature to verify.
/// * `pub_key` - The verification key.
pub fn verify(
    digest_hash_alg: tpm2_interface::TpmiAlgHash,
    digest: &[u8],
    signature: &mut [u8],
    pub_key: &key::RsaPublicKey,
) -> Result<(), CryptoError> {
    // Implementation according to RFC 8017, sec 8.2.2.

    let digest_len = hash::hash_alg_digest_len(digest_hash_alg) as usize;
    if digest.len() != digest_len {
        return Err(CryptoError::Internal);
    }

    // 8.2.2, step 1.
    let modulus_len = pub_key.modulus_len();
    if signature.len() != modulus_len {
        return Err(CryptoError::SignatureVerificationFailure);
    }

    // 8.2.2, step 2.: RSA vecification.
    pub_key.encrypt(signature).map_err(|e| match e {
        CryptoError::InvalidMessageLength | CryptoError::InvalidParams => CryptoError::SignatureVerificationFailure,
        e => e,
    })?;

    // 8.2.2, steps 3.-4.: apply EMSA-PKCS1-v1_5 encoding, specified in 9.2, to
    // calculated digest and compare to the one found in the signature.
    // 9.2., steps 2-3.
    let digest_info_der_enc_prefix = hash_alg_id_to_digest_info_der_enc_prefix(digest_hash_alg);
    debug_assert_eq!(
        digest_info_der_enc_prefix_to_digest_len(digest_info_der_enc_prefix),
        digest_len
    );
    let digest_info_der_enc_len = digest_info_der_enc_prefix.len() + digest_len;
    if modulus_len < digest_info_der_enc_len + 11 {
        return Err(CryptoError::SignatureVerificationFailure);
    }

    let (ps, t) = signature.split_at(modulus_len - digest_info_der_enc_len);
    if &t[..digest_info_der_enc_prefix.len()] != digest_info_der_enc_prefix
        || &t[digest_info_der_enc_prefix.len()..] != digest
    {
        return Err(CryptoError::SignatureVerificationFailure);
    }

    // 9.2. step 4-5.
    let ps_len = ps.len();
    if ps[0] != 0x00 || ps[1] != 0x01 || ps[ps_len - 1] != 0x02 || ps[2..ps_len - 1].iter().any(|b| *b != 0xff) {
        return Err(CryptoError::SignatureVerificationFailure);
    }
    // The rest of step 5. is implicit.

    Ok(())
}

#[test]
fn test_ssa_pkcs1_v1_5() {
    extern crate alloc;
    use alloc::vec;

    let key = key::test_key();
    let digest_hash_alg = hash::test_hash_alg();
    let digest_len = hash::hash_alg_digest_len(digest_hash_alg) as usize;

    // Test a sign + verify pair and check that the latter comes out as positive.
    let digest = vec![0xccu8; digest_len];
    let mut signature = sign(digest_hash_alg, &digest, &key).unwrap();
    verify(digest_hash_alg, &digest, &mut signature, key.pub_key()).unwrap();

    // Test a sign + a subsequent verify with a different digest and check that the
    // latter comes out as negative.
    let mut signature = sign(digest_hash_alg, &digest, &key).unwrap();
    let mut wrong_digest = digest.clone();
    wrong_digest[0] = 0;
    assert!(matches!(
        verify(digest_hash_alg, &wrong_digest, &mut signature, key.pub_key(),),
        Err(CryptoError::SignatureVerificationFailure)
    ));

    // Test a sign + a subsequent verify on a modified signature, check that the
    // latter comes out as negative.
    let mut signature = sign(digest_hash_alg, &digest, &key).unwrap();
    signature[0] ^= 1;
    assert!(matches!(
        verify(digest_hash_alg, &digest, &mut signature, key.pub_key()),
        Err(CryptoError::SignatureVerificationFailure)
    ));
}
