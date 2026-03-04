// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of the ECDSA signature scheme.
//!
//! Refer to NIST FIPS 186-5, sec. 6.4.1 ("ECDSA Signature Generation
//! Algorithm")

pub use crate::backend::ecc::ecdsa::*;

#[test]
fn test_ecdsa() {
    extern crate alloc;
    use alloc::vec;

    use crate::{
        CryptoError,
        ecc::{curve, key},
        rng,
    };

    let mut rng = rng::test_rng();
    let curve_id = curve::test_curve_id();
    let curve = curve::Curve::new(curve_id).unwrap();
    let curve_ops = curve.curve_ops().unwrap();
    let key = key::EccKey::generate(&curve_ops, &mut rng, None).unwrap();

    let mut test_digest = vec![0u8; 512];
    for (i, b) in test_digest.iter_mut().enumerate() {
        *b = (i % u8::MAX as usize) as u8;
    }

    let (r, s) = sign(&test_digest, &key, &mut rng, None).unwrap();
    verify(&test_digest, (&r, &s), key.pub_key()).unwrap();

    let r_len = r.len();
    let mut r_invalid = r.clone();
    r_invalid[r_len - 1] ^= 1;
    assert!(matches!(
        verify(&test_digest, (&r_invalid, &s), key.pub_key()),
        Err(CryptoError::SignatureVerificationFailure)
    ));

    let s_len = s.len();
    let mut s_invalid = s.clone();
    s_invalid[s_len - 1] ^= 1;
    assert!(matches!(
        verify(&test_digest, (&r, &s_invalid), key.pub_key()),
        Err(CryptoError::SignatureVerificationFailure)
    ));

    test_digest[0] ^= 1;
    assert!(matches!(
        verify(&test_digest, (&r, &s), key.pub_key()),
        Err(CryptoError::SignatureVerificationFailure)
    ));
}
