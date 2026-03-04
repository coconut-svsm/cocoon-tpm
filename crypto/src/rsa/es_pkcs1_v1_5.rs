// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of RFC 8017 RSAES-PKCS-v1_5.

extern crate alloc;
use alloc::vec::Vec;

use super::key;
use crate::utils_common::{
    alloc::{try_alloc_vec, try_alloc_zeroizing_vec},
    io_slices::{self, IoSlicesIterCommon as _},
    zeroize::{self, Zeroize as _},
};
use crate::{CryptoError, rng};
use cmpa;

fn fill_padding_with_nonzero_random_bytes(
    mut padding: &mut [u8],
    rng: &mut dyn rng::RngCoreDispatchable,
    additional_rng_generate_input: Option<&[Option<&[u8]>]>,
) -> Result<(), CryptoError> {
    // This is an implementation of rejection sampling: whenever some produced octet
    // is zero, it is replaced with the next non-zero value. The consumed octet
    // will subsequently get refilled in another RngCore::generate() invocation.
    const MAX_RETRIES: u32 = 16u32;
    let mut retries = 0;
    while !padding.is_empty() && retries < MAX_RETRIES {
        rng::rng_dyn_dispatch_generate(
            rng,
            io_slices::SingletonIoSliceMut::new(padding).map_infallible_err(),
            additional_rng_generate_input,
        )
        .map_err(CryptoError::from)?;

        retries += 1;
        while let Some(zero_index) = padding.iter().position(|b| *b == 0x00) {
            padding = &mut padding[zero_index..];
            if let Some(non_zero_index) = padding.iter().skip(1).position(|b| *b != 0x00) {
                let non_zero_index = non_zero_index + 1; // Account for the skip.
                padding.copy_within(non_zero_index.., 0);
                let padding_len = padding.len();
                padding[padding_len - non_zero_index..].fill(0x00);
                padding = &mut padding[1..];

                // Some progess has been made, reset the retries counter.
                retries = 0
            } else {
                break;
            }
        }
    }

    if !padding.is_empty() && padding[0] == 0x00 {
        // Even after MAX_RETRIES retries, the RNG failed to produce a non-zero
        // byte. The probability for this is overwhelmingly small and it can
        // be considered a failure.
        return Err(CryptoError::RandomSamplingRetriesExceeded);
    }

    Ok(())
}

#[test]
fn test_fill_padding_with_nonzero_random_bytes() {
    extern crate alloc;
    use alloc::vec;

    let mut rng = rng::test_rng();
    let mut padding = vec![0u8; 8192];
    fill_padding_with_nonzero_random_bytes(&mut padding, &mut rng, None).unwrap();
    assert!(!padding.iter().any(|b| *b == 0x00));
}

/// RFC8017 RSAES--PKCS-v1_5 scheme encryption.
///
/// For reference, see RFC 8017, sec 7.2.
///
/// # Arguments:
///
/// * `x` - The message to get encrypted.
/// * `pub_key` - The encryption key.
/// * `rng` - The [random number generator](rng::RngCore) used for generating
///   the padding.
/// * `additional_rng_generate_input` - Additional input to pass along to the
///   `rng`'s [generate()](rng::RngCore::generate) primitive.
pub fn encrypt(
    x: &[u8],
    pub_key: &key::RsaPublicKey,
    rng: &mut dyn rng::RngCoreDispatchable,
    additional_rng_generate_input: Option<&[Option<&[u8]>]>,
) -> Result<Vec<u8>, CryptoError> {
    // Implementation according to RFC 8017, sec 7.2.1.

    // 7.2.1, step 1.
    let modulus_len = pub_key.modulus_len();
    if modulus_len < x.len() + 11 {
        return Err(CryptoError::InvalidMessageLength);
    }

    // Once y is encrypted, it doesn't need to get zeroized anymore. Wrap the Vec in
    // an Option, which can be taken from later.
    let mut y = zeroize::Zeroizing::new(Some(try_alloc_vec(pub_key.modulus_len())?));
    // 7.2.1, step 2: apply EME-PKCS1-v1_5 encoding.
    let (ps, m) = y.as_mut().unwrap().split_at_mut(modulus_len - x.len());
    let ps_len = ps.len();
    ps[0] = 0x00;
    ps[1] = 0x02;
    ps[ps_len - 1] = 0x00;
    let ps = &mut ps[2..ps_len - 1];
    fill_padding_with_nonzero_random_bytes(ps, rng, additional_rng_generate_input)?;
    m.clone_from_slice(x);

    // 7.2.1, step 3.
    pub_key.encrypt(y.as_mut().unwrap())?;

    Ok(y.take().unwrap())
}

/// RFC8017 RSAES--PKCS-v1_5 scheme decryption.
///
/// For reference, see RFC 8017, sec 7.2.
///
/// # Arguments:
///
/// * `y` - The message to get decrypted.
/// * `key` - The decryption key. Must have the private part available.
pub fn decrypt(y: &mut [u8], key: &key::RsaKey) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
    // Implementation according to RFC 8017, sec 7.2.2.

    // 7.2.2., step 1.
    let modulus_len = key.pub_key().modulus_len();
    if y.len() != modulus_len || modulus_len < 11 {
        // Zeroization not really needed, but be consistent.
        y.zeroize();
        return Err(CryptoError::InvalidMessageLength);
    }

    // 7.2.2, step 2.
    if let Err(e) = key.decrypt(y) {
        y.zeroize();
        return Err(e);
    }

    // 7.2.2, step 3.
    let mut format_is_ok = cmpa::ct_eq_l_l(y[0] as cmpa::LimbType, 0);
    format_is_ok &= cmpa::ct_eq_l_l(y[1] as cmpa::LimbType, 0x02);
    // Check that the padding has at least a length of 8 bytes. For invalid
    // encodings, the position of the first invalid byte must be obfuscated
    // timing-wise such that an attacker cannot iteratively adapt the CCA.
    for b in y.iter().skip(2).take(8) {
        format_is_ok &= cmpa::ct_neq_l_l(*b as cmpa::LimbType, 0);
    }

    let mut padding_end: Option<usize> = None;
    for (i, b) in y.iter().skip(10).enumerate() {
        // For a valid encoding, the length of the padding, or alternatively, the length
        // of the encrypted message is not considered secret.
        let b = *b as cmpa::LimbType;
        let b = format_is_ok.select(!0, b);
        if b == 0 {
            padding_end = Some(i);
            break;
        }
    }
    let padding_end = match padding_end {
        Some(padding_end) => padding_end + 10 + 1,
        None => {
            y.zeroize();
            return Err(CryptoError::InvalidPadding);
        }
    };

    let m_len = y.len() - padding_end;
    let mut x = match try_alloc_zeroizing_vec(m_len) {
        Ok(x) => x,
        Err(e) => {
            y.zeroize();
            return Err(CryptoError::from(e));
        }
    };
    x.copy_from_slice(&y[padding_end..]);
    y.zeroize();

    Ok(x)
}

#[test]
fn test_es_pkcs1_v1_5() {
    let mut rng = rng::test_rng();
    let key = key::test_key();

    // Test a encryption + decryption and verify that the decrypted secret matches
    // the original.
    let x = [3u8; 1];
    let mut y = encrypt(&x, key.pub_key(), &mut rng, None).unwrap();
    let decrypted_x = decrypt(&mut y, &key).unwrap();
    assert_eq!(x.as_slice(), decrypted_x.as_slice());

    // Test a encryption + decryption, but mess with the ciphertext inbetween.
    // Decryption shall result in an error then.
    let x = [3u8; 1];
    let mut y = encrypt(&x, key.pub_key(), &mut rng, None).unwrap();
    let y_len = y.len();
    y[y_len - 1] = y[y_len - 1].wrapping_add(1);
    assert!(matches!(decrypt(&mut y, &key), Err(CryptoError::InvalidPadding)));
}
