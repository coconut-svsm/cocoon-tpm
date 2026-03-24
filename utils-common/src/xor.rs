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

    const LEN: usize = 32;
    const EXTRA: usize = mem::size_of::<cmpa::LimbType>() - 1;
    let mut dst = [0u8; LEN + EXTRA];
    let mut mask = [0u8; LEN + EXTRA];
    let mut expected = [0u8; LEN];

    let mut rng = fastrand::Rng::with_seed(0xdeadbeef);

    for i in 0..EXTRA {
        for j in 0..EXTRA {
            dst.fill_with(|| rng.u8(..));
            mask.fill_with(|| rng.u8(..));

            let dst_slice = &mut dst[i..i + LEN];
            let mask_slice = &mask[j..j + LEN];

            // Compute expected result byte-by-byte.
            for k in 0..LEN {
                expected[k] = dst_slice[k] ^ mask_slice[k];
            }

            xor_bytes(dst_slice, mask_slice);
            assert_eq!(dst_slice, expected);
        }
    }
}
