// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of RFC 8017 RSASSA-PSS.

extern crate alloc;
use alloc::vec::Vec;

use super::key;
use crate::{
    CryptoError, hash,
    kdf::{self, Kdf as _},
    rng,
};
use crate::{
    tpm2_interface,
    utils_common::{
        alloc::try_alloc_vec,
        ct_cmp,
        io_slices::{self, IoSlicesIterCommon as _},
        zeroize::Zeroize as _,
    },
};

/// RFC 8017 RSASSA-PSS signature creation.
///
/// For reference, see RFC 8017, sec 8.1.
///
/// # Arguments:
///
/// * `digest` - The message digest to sign.
/// * `key` - The signing key. Must have the private part available.
/// * `m_prime_hash_alg` - The hash algorithm to be used for the scheme.
/// * `mgf1_hash_alg` - The hash algorithm to be used for the
///   [`MGF1`](kdf::mgf1).
/// * `rng` - The [random number generator](rng::RngCore) used for generating
///   the salt.
/// * `additional_rng_generate_input` - Additional input to pass along to the
///   `rng`'s [generate()](rng::RngCore::generate) primitive.
pub fn sign(
    digest: &[u8],
    key: &key::RsaKey,
    m_prime_hash_alg: tpm2_interface::TpmiAlgHash,
    mgf1_hash_alg: tpm2_interface::TpmiAlgHash,
    rng: &mut dyn rng::RngCoreDispatchable,
    additional_rng_generate_input: Option<&[Option<&[u8]>]>,
) -> Result<Vec<u8>, CryptoError> {
    // Implementation according to RFC 8017, sec 8.1.1.

    // 8.1.1, step 1: apply EMSA-PSS encoding, specified in 9.1.1.
    let modulus_len = key.pub_key().modulus_len();
    let hlen = hash::hash_alg_digest_len(m_prime_hash_alg) as usize;

    // 9.1.1., step 3.
    if modulus_len < hlen + 2 {
        return Err(CryptoError::InvalidParams);
    }

    // Select the salt length. Two relevant specs impose constraints:
    // - TCG TPM2 Library, Part 1 -- Architecture, B.7 RSASSA_PSS: "the random salt
    //   length will be the largest size allowed by the key size and message digest
    //   size". And further: "If the TPM implementation is required to be compliant
    //   with FIPS 186-4, then the random salt length will be the largest size
    //   allowed by that specification."
    // - NIST FIPS 186-5 (superseding 186-4), sec. 5.4 ("PKCS #1"), clause (g): "the
    //   length [...] of the salt [...] shall satisfy 0 ≤ sLen ≤ hLen".
    let slen = modulus_len - hlen - 2; // Maximum per key and digest size.
    let slen = slen.min(hlen); // FIPS 186-5 limit.

    // signature corresponds to "EM" of 9.1.1.
    let mut signature = try_alloc_vec(modulus_len)?;
    // See 9.1.1., step 12 for the partitioning.
    let db_len = modulus_len - 1 - hlen;
    debug_assert!(db_len > slen);
    let (db, signature_h) = signature.split_at_mut(db_len);
    // See 9.1.1, step 8. for the delimiter value and the partitioning.
    db[db_len - slen - 1] = 0x1;
    let (_, salt) = db.split_at_mut(db_len - slen);
    // See 9.1.1, step 12. for the delimiter value and the partitioning.
    signature_h[hlen] = 0xbc;
    let signature_h = &mut signature_h[..hlen];

    // 9.1.1., step 4.
    rng::rng_dyn_dispatch_generate(
        rng,
        io_slices::SingletonIoSliceMut::new(salt).map_infallible_err(),
        additional_rng_generate_input,
    )?;

    // 9.1.1., step 5-6.
    let mut h = hash::HashInstance::new(m_prime_hash_alg)?;
    h.update(io_slices::BuffersSliceIoSlicesIter::new(&[[0u8; 8].as_slice(), digest, salt]).map_infallible_err())?;
    h.finalize_into(signature_h)?;

    // 9.1.1., step 7-8. are implicit.

    // 9.1.1., step 9-10.
    let mgf_db_mask =
        kdf::BufferedFixedBlockOutputKdf::new(kdf::mgf1::RFC8017Mgf1::new(mgf1_hash_alg, db.len(), signature_h)?)?;
    mgf_db_mask.generate_and_xor(io_slices::SingletonIoSliceMut::new(db).map_infallible_err())?;

    // 9.1.1., step 11.
    db[0] &= !0x80u8;

    // 9.1.1., step 12 is implicit.

    // 8.1.1, step 2: RSA signature.
    match key.decrypt(&mut signature) {
        Ok(()) => (),
        Err(e) => {
            signature.zeroize();
            return Err(e);
        }
    }
    Ok(signature)
}

/// RFC 8017 RSASSA-PSS signature verification.
///
/// For reference, see RFC 8017, sec 8.1.
///
/// # Arguments:
///
/// * `digest` - The signed message digest.
/// * `signature` - The signature to verify.
/// * `pub_key` - The verification key.
/// * `m_prime_hash_alg` - The hash algorithm to be used for the scheme.
/// * `mgf1_hash_alg` - The hash algorithm to be used for the
///   [`MGF1`](kdf::mgf1).
pub fn verify(
    digest: &[u8],
    signature: &mut [u8],
    pub_key: &key::RsaPublicKey,
    m_prime_hash_alg: tpm2_interface::TpmiAlgHash,
    mgf1_hash_alg: tpm2_interface::TpmiAlgHash,
) -> Result<(), CryptoError> {
    // Implementation according to RFC 8017, sec 8.1.2.

    // 8.1.2., step 1.
    if signature.len() != pub_key.modulus_len() {
        return Err(CryptoError::SignatureVerificationFailure);
    }
    pub_key.encrypt(signature).map_err(|e| match e {
        CryptoError::InvalidMessageLength | CryptoError::InvalidParams => CryptoError::SignatureVerificationFailure,
        e => e,
    })?;

    // 8.1.2., step 3: apply EMSA-PSS verification, specified in 9.1.2.
    // 9.1.2, step 3.-4.
    let hlen = hash::hash_alg_digest_len(m_prime_hash_alg) as usize;
    if signature.len() < hlen + 2 || signature[signature.len() - 1] != 0xbc {
        return Err(CryptoError::SignatureVerificationFailure);
    }

    // 9.1.2, step 5.
    let (db, signature_h) = signature.split_at_mut(signature.len() - hlen - 1);
    let signature_h = &signature_h[..hlen];
    // 9.1.2, step 6.
    if db[0] & 0x80 != 0 {
        return Err(CryptoError::SignatureVerificationFailure);
    }

    // 9.1.2, step 7.-8.
    let mgf_db_mask =
        kdf::BufferedFixedBlockOutputKdf::new(kdf::mgf1::RFC8017Mgf1::new(mgf1_hash_alg, db.len(), signature_h)?)?;
    mgf_db_mask.generate_and_xor(io_slices::SingletonIoSliceMut::new(db).map_infallible_err())?;

    // 9.1.2., step 9.
    db[0] &= !0x80u8;

    // 9.1.2., step 10.-11.
    // Deviating from RFC 8017, the salt length is not an input parameter, but
    // determined from the encoding. Note that this is in line with NIST
    // FIPS 186-5, sec. 5.4 ("PKCS #1"), clause (g): "[...] sLen is the
    // actual byte length of the byte string following the leftmost (most
    // significant) nonzero byte (which should be 0x01) in the recovered DB".
    let db_pad_end_pos = db
        .iter()
        .position(|b| *b != 0)
        .ok_or(CryptoError::SignatureVerificationFailure)?;
    if db[db_pad_end_pos] != 0x01 {
        return Err(CryptoError::SignatureVerificationFailure);
    }
    let salt = &db[db_pad_end_pos + 1..];

    // 9.1.2., step 12-13.
    let mut h = hash::HashInstance::new(m_prime_hash_alg)?;
    h.update(io_slices::BuffersSliceIoSlicesIter::new(&[[0u8; 8].as_slice(), digest, salt]).map_infallible_err())?;
    let mut h_dst = try_alloc_vec(hlen)?;
    h.finalize_into(&mut h_dst)?;

    // 9.1.2., step 14.
    if ct_cmp::ct_bytes_eq(&h_dst, signature_h).unwrap() == 0 {
        return Err(CryptoError::SignatureVerificationFailure);
    }

    Ok(())
}

#[test]
fn test_pss() {
    let mut rng = rng::test_rng();
    let key = key::test_key();
    let hash_alg = hash::test_hash_alg();

    // Test a sign + verify pair and check that the latter comes out as positive.
    let digest = [0xccu8; 32];
    let mut signature = sign(&digest, &key, hash_alg, hash_alg, &mut rng, None).unwrap();
    verify(&digest, &mut signature, key.pub_key(), hash_alg, hash_alg).unwrap();

    // Test a sign + a subsequent verify with a different digest and check that the
    // latter comes out as negative.
    let mut signature = sign(&digest, &key, hash_alg, hash_alg, &mut rng, None).unwrap();
    let mut wrong_digest = digest;
    wrong_digest[0] = 0;
    assert!(matches!(
        verify(&wrong_digest, &mut signature, key.pub_key(), hash_alg, hash_alg),
        Err(CryptoError::SignatureVerificationFailure)
    ));

    // Test a sign + a subsequent verify on a modified signature, check that the
    // latter comes out as negative.
    let mut signature = sign(&digest, &key, hash_alg, hash_alg, &mut rng, None).unwrap();
    signature[0] ^= 1;
    assert!(matches!(
        verify(&digest, &mut signature, key.pub_key(), hash_alg, hash_alg),
        Err(CryptoError::SignatureVerificationFailure)
    ));
}
