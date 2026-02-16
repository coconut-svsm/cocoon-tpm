// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Xor two byte slices.

use cmpa;

fn _xor_slice<T>(dst: &mut [T], mask: &[T])
where
    T: core::ops::BitXorAssign + Copy,
{
    debug_assert_eq!(dst.len(), mask.len());

    for (d, m) in dst.iter_mut().zip(mask.iter()) {
        *d ^= *m;
    }
}

/// Xor two byte slices byte by byte.
///
/// The two byte slices **must** be of equal length.
///
/// # Arguments:
///
/// * `dst` - First operand and destination.
/// * `mask` - Second operand.
pub fn xor_bytes(dst: &mut [u8], mask: &[u8]) {
    debug_assert_eq!(dst.len(), mask.len());

    // Split dst and mask into regions of &[u8], &[LimbType], &[u8] each.
    // SAFETY: `LimbType` is an integer type (`u64` or `u32`), so every possible
    // bit pattern of the source `u8` bytes is a valid `LimbType` value. The
    // `align_to_mut`/`align_to` methods handle alignment by only grouping
    // properly-aligned interior bytes into the middle `&[LimbType]` slice.
    let (dst_bytes_head, dst_limbs, dst_bytes_tail) = unsafe { dst.align_to_mut::<cmpa::LimbType>() };
    let (mask_bytes_head, mask_limbs, mask_bytes_tail) = unsafe { mask.align_to::<cmpa::LimbType>() };

    if dst_bytes_head.len() != mask_bytes_head.len() {
        _xor_slice(dst, mask);
        return;
    }

    debug_assert_eq!(dst_limbs.len(), mask_limbs.len());
    debug_assert_eq!(dst_bytes_tail.len(), mask_bytes_tail.len());

    _xor_slice(dst_bytes_head, mask_bytes_head);
    _xor_slice(dst_limbs, mask_limbs);
    _xor_slice(dst_bytes_tail, mask_bytes_tail);
}

#[test]
fn test_xor_bytes() {
    use core::mem;

    let mut dst = [0u8; 32 + mem::size_of::<cmpa::LimbType>() - 1];
    let mask = [0x77u8; 32 + mem::size_of::<cmpa::LimbType>() - 1];
    let expected = [0xbbu8; 32];
    for i in 0..mem::size_of::<cmpa::LimbType>() - 1 {
        for j in 0..mem::size_of::<cmpa::LimbType>() - 1 {
            let dst = &mut dst[i..i + 32];
            dst.fill(0xccu8);
            let mask = &mask[j..j + 32];
            xor_bytes(dst, mask);
            assert_eq!(dst, expected);
        }
    }
}
