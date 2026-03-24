// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Constant-time comparisons of byte slices.

use cmpa::{self, LimbType};

fn _ct_bytes_all_zero(bytes: &[u8]) -> cmpa::LimbChoice {
    let mut any_nonzero: cmpa::LimbType = 0;
    for b in bytes.iter() {
        any_nonzero |= *b as LimbType;
    }
    cmpa::ct_eq_l_l(any_nonzero, 0)
}

/// Test in constant time whether a given byte slice contains only zeroes.
///
/// # Arguments:
///
/// * `bytes` - The slice to examine.
pub fn ct_bytes_all_zero(bytes: &[u8]) -> cmpa::LimbChoice {
    // Split bytes[] into regions of &[u8], &[LimbType], &[u8].
    let (bytes_head, limbs, bytes_tail) = unsafe { bytes.align_to::<cmpa::LimbType>() };
    let mut all_zero = _ct_bytes_all_zero(bytes_head);
    let mut limbs_any_nonzero: cmpa::LimbType = 0;
    for l in limbs.iter() {
        limbs_any_nonzero |= l;
    }
    all_zero &= cmpa::ct_eq_l_l(limbs_any_nonzero, 0);
    all_zero &= _ct_bytes_all_zero(bytes_tail);
    all_zero
}

#[test]
fn test_ct_bytes_all_zero() {
    use core::mem;

    let mut bytes = [0u8; 32 + mem::size_of::<cmpa::LimbType>() - 1];
    for i in 0..mem::size_of::<cmpa::LimbType>() - 1 {
        let bytes = &mut bytes[i..i + 32];
        bytes.fill(0);
        assert_ne!(ct_bytes_all_zero(bytes).unwrap(), 0);

        for j in 0..bytes.len() {
            bytes.fill(0);
            bytes[j] = 1;
            assert_eq!(ct_bytes_all_zero(bytes).unwrap(), 0);
        }
    }
}

fn _ct_bytes_eq<T>(bytes0: &[T], bytes1: &[T]) -> cmpa::LimbChoice
where
    T: Copy + Into<LimbType>,
{
    debug_assert_eq!(bytes0.len(), bytes1.len());
    let mut any_neq: cmpa::LimbType = 0;
    for (a, b) in bytes0.iter().zip(bytes1.iter()) {
        any_neq |= Into::<LimbType>::into(*a) ^ Into::<LimbType>::into(*b);
    }
    cmpa::ct_eq_l_l(any_neq, 0)
}

/// Test in constant time whether two bytes slices are equal.
///
/// # Arguments:
///
/// * `bytes0` - First slice to compare.
/// * `bytes1` - Second slice to compare.
pub fn ct_bytes_eq(bytes0: &[u8], bytes1: &[u8]) -> cmpa::LimbChoice {
    debug_assert_eq!(bytes0.len(), bytes1.len());

    // Split bytes0 and bytes1 into regions of &[u8], &[LimbType], &[u8] each.
    // SAFETY: `LimbType` is an integer type (`u64` or `u32`), so every possible
    // bit pattern of the source `u8` bytes is a valid `LimbType` value. The
    // `align_to_mut`/`align_to` methods handle alignment by only grouping
    // properly-aligned interior bytes into the middle `&[LimbType]` slice.
    let (bytes0_head, bytes0_limbs, bytes0_tail) = unsafe { bytes0.align_to::<cmpa::LimbType>() };
    let (bytes1_head, bytes1_limbs, bytes1_tail) = unsafe { bytes1.align_to::<cmpa::LimbType>() };

    if bytes0_head.len() != bytes1_head.len() {
        return _ct_bytes_eq(bytes0, bytes1);
    }

    let mut all_eq = _ct_bytes_eq(bytes0_head, bytes1_head);
    all_eq &= _ct_bytes_eq(bytes0_limbs, bytes1_limbs);
    all_eq &= _ct_bytes_eq(bytes0_tail, bytes1_tail);
    all_eq
}

#[test]
fn test_ct_bytes_eq() {
    use core::mem;

    const LEN: usize = 32;
    const EXTRA: usize = mem::size_of::<cmpa::LimbType>() - 1;
    let mut bytes0 = [0u8; LEN + EXTRA];
    let mut bytes1 = [0u8; LEN + EXTRA];

    let mut rng = fastrand::Rng::with_seed(0xdeadbeef);

    for i in 0..EXTRA {
        for j in 0..EXTRA {
            let bytes0 = &mut bytes0[i..i + LEN];
            let bytes1 = &mut bytes1[j..j + LEN];
            bytes0.fill_with(|| rng.u8(..));
            bytes1.copy_from_slice(bytes0);
            assert_ne!(ct_bytes_eq(bytes0, bytes1).unwrap(), 0);

            for k in 0..LEN {
                bytes0.fill_with(|| rng.u8(..));
                bytes1.copy_from_slice(bytes0);
                bytes0[k] = bytes1[k].wrapping_add(1);
                assert_eq!(ct_bytes_eq(bytes0, bytes1).unwrap(), 0);

                bytes0.fill_with(|| rng.u8(..));
                bytes1.copy_from_slice(bytes0);
                bytes1[k] = bytes0[k].wrapping_add(1);
                assert_eq!(ct_bytes_eq(bytes0, bytes1).unwrap(), 0);
            }
        }
    }
}
