// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of RFC 8017 RSAES-OAEP.

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
        alloc::{try_alloc_vec, try_alloc_zeroizing_vec},
        ct_cmp,
        io_slices::{self, IoSlicesIterCommon as _},
        zeroize::{self, Zeroize as _},
    },
};
use cmpa;

/// RFC8017 RSAES-OEAP scheme encryption.
///
/// For reference, see RFC 8017, sec 7.1.
///
/// # Arguments:
///
/// * `x` - The message to get encrypted.
/// * `label` - Optional label to be used in the scheme.
/// * `pub_key` - The encryption key.
/// * `hash_alg` - The hash algorithm to be used for the scheme.
/// * `mgf1_hash_alg` - The hash algorithm to be used for the
///   [`MGF1`](kdf::mgf1).
/// * `rng` - The [random number generator](rng::RngCore) used for generating
///   the seed.
/// * `additional_rng_generate_input` - Additional input to pass along to the
///   `rng`'s [generate()](rng::RngCore::generate) primitive.
pub fn encrypt(
    x: &[u8],
    label: Option<&[u8]>,
    pub_key: &key::RsaPublicKey,
    hash_alg: tpm2_interface::TpmiAlgHash,
    mgf1_hash_alg: tpm2_interface::TpmiAlgHash,
    rng: &mut dyn rng::RngCoreDispatchable,
    additional_rng_generate_input: Option<&[Option<&[u8]>]>,
) -> Result<Vec<u8>, CryptoError> {
    // Implementation according to RFC 8017, sec 7.1.1.

    // 7.1.1, step 1.
    let hlen = hash::hash_alg_digest_len(hash_alg) as usize;
    if pub_key.modulus_len() < 2 * hlen + 2 {
        return Err(CryptoError::InvalidParams);
    }
    let max_m_len = pub_key.modulus_len() - 2 * hlen - 2;
    if x.len() > max_m_len {
        return Err(CryptoError::InvalidMessageLength);
    }

    // Once y is encrypted, it doesn't need to get zeroized anymore. Wrap the Vec in
    // an Option, which can be taken from later.
    let mut y = zeroize::Zeroizing::new(Some(try_alloc_vec(pub_key.modulus_len())?));
    // EM = 0x00 || maskedSeed || maskedDB, with maskedSeed of length hlen.
    let (seed, db) = y.as_mut().unwrap().split_at_mut(1 + hlen);
    let seed = &mut seed[1..];

    // 7.1.1, step 2.a.
    let mut h = hash::HashInstance::new(hash_alg)?;
    if let Some(label) = label {
        h.update(io_slices::SingletonIoSlice::new(label).map_infallible_err())?;
    }
    h.finalize_into(&mut db[..hlen])?;

    // 7.1.1, step 2.b. is implicit.

    // 7.1.1, step 2.c.
    // DB = lHash || PS || 0x01 || M.
    let db_len = db.len();
    db[db_len - x.len() - 1] = 0x01;
    db[db_len - x.len()..].copy_from_slice(x);

    // 7.1.1, step 2.d.
    // Generate a random seed of hlen bytes.
    rng::rng_dyn_dispatch_generate(
        rng,
        io_slices::SingletonIoSliceMut::new(seed).map_infallible_err(),
        additional_rng_generate_input,
    )
    .map_err(CryptoError::from)?;

    // 7.1.1, step 2.e-f. (in place)
    let mgf_db_mask =
        kdf::BufferedFixedBlockOutputKdf::new(kdf::mgf1::RFC8017Mgf1::new(mgf1_hash_alg, db.len(), seed)?)?;
    mgf_db_mask.generate_and_xor(io_slices::SingletonIoSliceMut::new(db).map_infallible_err())?;

    // 7.1.1, step 2.g-h. (in place)
    let mgf_seed_mask =
        kdf::BufferedFixedBlockOutputKdf::new(kdf::mgf1::RFC8017Mgf1::new(mgf1_hash_alg, seed.len(), db)?)?;
    mgf_seed_mask.generate_and_xor(io_slices::SingletonIoSliceMut::new(seed).map_infallible_err())?;

    // 7.1.1, step 2.i. is implicit.

    // 7.1.1, step 3.
    pub_key.encrypt(y.as_mut().unwrap())?;

    Ok(y.take().unwrap())
}

/// RFC8017 RSAES-OEAP scheme decryption.
///
/// For reference, see RFC 8017, sec 7.1.
///
/// # Arguments:
///
/// * `y` - The message to get decrypted.
/// * `label` - Optional label to be used in the scheme.
/// * `key` - The decryption key. Must have the private part available.
/// * `hash_alg` - The hash algorithm to be used for the scheme.
/// * `mgf1_hash_alg` - The hash algorithm to be used for the
///   [`MGF1`](kdf::mgf1).
pub fn decrypt(
    y: &mut [u8],
    label: Option<&[u8]>,
    key: &key::RsaKey,
    hash_alg: tpm2_interface::TpmiAlgHash,
    mgf1_hash_alg: tpm2_interface::TpmiAlgHash,
) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
    // Implementation according to RFC 8017, sec 7.1.2.

    // 7.1.2, step 1.
    let modulus_len = key.pub_key().modulus_len();
    let hlen = hash::hash_alg_digest_len(hash_alg) as usize;
    if modulus_len < 2 * hlen + 2 {
        // Zeroization not really needed, but be consistent.
        y.zeroize();
        return Err(CryptoError::InvalidParams);
    } else if y.len() != modulus_len {
        // Zeroization not really needed, but be consistent.
        y.zeroize();
        return Err(CryptoError::InvalidMessageLength);
    }

    // 7.1.2, step 2.
    if let Err(e) = key.decrypt(y) {
        y.zeroize();
        return Err(e);
    }

    // 7.1.2, step 3.b.
    let (seed, db) = y.split_at_mut(1 + hlen);
    let first_byte = seed[0];
    let seed = &mut seed[1..];

    // 7.1.2, step 3.c-d.
    let mgf_seed_mask =
        match kdf::BufferedFixedBlockOutputKdf::new(match kdf::mgf1::RFC8017Mgf1::new(mgf1_hash_alg, seed.len(), db) {
            Ok(kdf) => kdf,
            Err(e) => {
                y.zeroize();
                return Err(e);
            }
        }) {
            Ok(kdf) => kdf,
            Err(e) => {
                y.zeroize();
                return Err(e);
            }
        };
    if let Err(e) = mgf_seed_mask.generate_and_xor(io_slices::SingletonIoSliceMut::new(seed).map_infallible_err()) {
        y.zeroize();
        return Err(e);
    }

    // 7.1.2, step 3.e-f.
    let mgf_db_mask =
        match kdf::BufferedFixedBlockOutputKdf::new(match kdf::mgf1::RFC8017Mgf1::new(mgf1_hash_alg, db.len(), seed) {
            Ok(kdf) => kdf,
            Err(e) => {
                y.zeroize();
                return Err(e);
            }
        }) {
            Ok(kdf) => kdf,
            Err(e) => {
                y.zeroize();
                return Err(e);
            }
        };
    if let Err(e) = mgf_db_mask.generate_and_xor(io_slices::SingletonIoSliceMut::new(db).map_infallible_err()) {
        y.zeroize();
        return Err(e);
    }

    // 7.1.2, step 3.a.
    let mut lhash = match try_alloc_zeroizing_vec(hlen) {
        Ok(lhash) => lhash,
        Err(e) => {
            y.zeroize();
            return Err(CryptoError::from(e));
        }
    };
    let mut h = hash::HashInstance::new(hash_alg)?;
    if let Some(label) = label {
        h.update(io_slices::SingletonIoSlice::new(label).map_infallible_err())?;
    }
    h.finalize_into(&mut lhash)?;

    // 7.1.2, step 3.g.
    let mut format_is_ok = cmpa::ct_eq_l_l(first_byte as cmpa::LimbType, 0);
    format_is_ok &= ct_cmp::ct_bytes_eq(&lhash, &db[..hlen]);
    drop(lhash);
    let db = &db[hlen..];

    let mut ps_end: Option<usize> = None;
    for (i, b) in db.iter().enumerate() {
        let b = *b as cmpa::LimbType;
        // For invalid encodings, the position of the first invalid byte must be
        // obfuscated timing-wise such that an attacker cannot iteratively
        // adapt the CCA. For a valid encoding OTOH, the length of the padding,
        // or alternatively, the length of the encrypted message is not
        // considered secret.
        format_is_ok &= cmpa::ct_leq_l_l(b, 1);
        let b = format_is_ok.select(0, b);
        if b == 1 {
            ps_end = Some(i);
            break;
        }
    }
    let ps_end = match ps_end {
        Some(ps_end) => ps_end,
        None => {
            y.zeroize();
            return Err(CryptoError::InvalidPadding);
        }
    };

    // 7.1.2, step 4.
    let m_begin = ps_end + 1;
    let m_len = db.len() - m_begin;
    let mut x = match try_alloc_zeroizing_vec(m_len) {
        Ok(x) => x,
        Err(e) => {
            y.zeroize();
            return Err(CryptoError::from(e));
        }
    };
    x.copy_from_slice(&db[m_begin..]);
    y.zeroize();

    Ok(x)
}

#[test]
fn test_oeap() {
    let mut rng = rng::test_rng();
    let key = key::test_key();

    // Test a encryption + decryption and verify that the decrypted secret matches
    // the original.
    let x = [3u8; 1];
    let label = "LABEL".as_bytes();
    let hash_alg = hash::test_hash_alg();
    let mut y = encrypt(&x, Some(label), key.pub_key(), hash_alg, hash_alg, &mut rng, None).unwrap();
    let decrypted_x = decrypt(&mut y, Some(label), &key, hash_alg, hash_alg).unwrap();
    assert_eq!(x.as_slice(), decrypted_x.as_slice());

    // Test a encryption + decryption, but mess with the ciphertext inbetween.
    // Decryption shall result in an error then.
    let x = [3u8; 1];
    let label = "LABEL".as_bytes();
    let hash_alg = hash::test_hash_alg();
    let mut y = encrypt(&x, Some(label), key.pub_key(), hash_alg, hash_alg, &mut rng, None).unwrap();
    let y_len = y.len();
    y[y_len - 1] = y[y_len - 1].wrapping_add(1);
    assert!(matches!(
        decrypt(&mut y, Some(label), &key, hash_alg, hash_alg),
        Err(CryptoError::InvalidPadding)
    ));
}
