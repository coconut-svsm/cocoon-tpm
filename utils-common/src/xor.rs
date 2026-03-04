// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Xor two byte slices.

use cmpa;
use core::mem;

fn _xor_bytes(dst: &mut [u8], mask: &[u8]) {
    debug_assert_eq!(dst.len(), mask.len());

    for i in dst.iter_mut().zip(mask.iter()) {
        *i.0 ^= i.1;
    }
}

/// Xor two byte slices byte by byte.
///
/// The two byte slices **must** be of equal length.
///
/// # Arguments:
///
/// * `dst` - First operand and destination..
/// * `src` - Second operand.
pub fn xor_bytes(dst: &mut [u8], mask: &[u8]) {
    debug_assert_eq!(dst.len(), mask.len());

    // Split dst and mask into regions of &[u8], &[LimbType], &[u8] each.
    let (dst_bytes_head, dst_limbs, dst_bytes_tail) = unsafe { dst.align_to_mut::<cmpa::LimbType>() };
    let (mask_bytes_head, mask_limbs, mask_bytes_tail) = unsafe { mask.align_to::<cmpa::LimbType>() };

    // Now, dst_bytes_head.len() is not necessarily equal to mask_bytes_head.len().
    // Grab the missing bytes back from the &[LimbType] region as appropriate
    let (dst_bytes_head_0, dst_bytes_head_1, dst_limbs, mask_bytes_head_0, mask_bytes_head_1, mask_limbs) =
        if dst_bytes_head.len() <= mask_bytes_head.len() {
            if (mask_bytes_head.len() - dst_bytes_head.len()) % mem::size_of::<cmpa::LimbType>() != 0 {
                // The LimbType regions are in no correspondence.
                _xor_bytes(dst, mask);
                return;
            }

            let dst_bytes_head_0 = dst_bytes_head;
            // mask_bytes_head_0 corresponds to dst_bytes_head_0, mask_bytes_head_1 to the
            // head of dst_limbs.
            let (mask_bytes_head_0, mask_bytes_head_1) = mask_bytes_head.split_at(dst_bytes_head_0.len());
            debug_assert_eq!(mask_bytes_head_1.len() % mem::size_of::<cmpa::LimbType>(), 0);
            if mask_bytes_head_1.len() >= mem::size_of_val(dst_limbs) {
                // All of dst's LimbType region would get converted back into bytes anyway.
                _xor_bytes(dst, mask);
                return;
            }
            let (dst_limbs_head, dst_limbs) =
                dst_limbs.split_at_mut(mask_bytes_head_1.len() / mem::size_of::<cmpa::LimbType>());
            let dst_bytes_head_1 = cmpa::limb_slice_as_bytes_mut(dst_limbs_head);
            debug_assert_eq!(dst_bytes_head_1.len(), mask_bytes_head_1.len());

            (
                dst_bytes_head_0,
                dst_bytes_head_1,
                dst_limbs,
                mask_bytes_head_0,
                mask_bytes_head_1,
                mask_limbs,
            )
        } else {
            if (dst_bytes_head.len() - mask_bytes_head.len()) % mem::size_of::<cmpa::LimbType>() != 0 {
                // The LimbType regions are in no correspondence.
                _xor_bytes(dst, mask);
                return;
            }

            let mask_bytes_head_0 = mask_bytes_head;
            // dst_bytes_head_0 corresponds to mask_bytes_head_0, dst_bytes_head_1 to the
            // head of mask_limbs.
            let (dst_bytes_head_0, dst_bytes_head_1) = dst_bytes_head.split_at_mut(mask_bytes_head_0.len());
            debug_assert_eq!(dst_bytes_head_1.len() % mem::size_of::<cmpa::LimbType>(), 0);
            if dst_bytes_head_1.len() >= mem::size_of_val(mask_limbs) {
                // All of mask's LimbType region would get converted back into bytes anyway.
                _xor_bytes(dst, mask);
                return;
            }
            let (mask_limbs_head, mask_limbs) =
                mask_limbs.split_at(dst_bytes_head_1.len() / mem::size_of::<cmpa::LimbType>());
            let mask_bytes_head_1 = cmpa::limb_slice_as_bytes(mask_limbs_head);
            debug_assert_eq!(mask_bytes_head_1.len(), dst_bytes_head_1.len());

            (
                dst_bytes_head_0,
                dst_bytes_head_1,
                dst_limbs,
                mask_bytes_head_0,
                mask_bytes_head_1,
                mask_limbs,
            )
        };
    debug_assert_eq!(dst_bytes_head_0.len(), mask_bytes_head_0.len());
    debug_assert_eq!(dst_bytes_head_1.len(), mask_bytes_head_1.len());

    let (dst_limbs, dst_bytes_tail_0, dst_bytes_tail_1, mask_limbs, mask_bytes_tail_0, mask_bytes_tail_1) =
        if mask_limbs.len() <= dst_limbs.len() {
            // mask_bytes_tail_0 corresponds to the tail part of dst_limbs,
            // mask_bytes_tail_1 to dst_bytes_tail.
            let dst_bytes_tail_1 = dst_bytes_tail;
            let (dst_limbs, dst_limbs_tail) = dst_limbs.split_at_mut(mask_limbs.len());
            let dst_bytes_tail_0 = cmpa::limb_slice_as_bytes_mut(dst_limbs_tail);
            let (mask_bytes_tail_0, mask_bytes_tail_1) = mask_bytes_tail.split_at(dst_bytes_tail_0.len());
            (
                dst_limbs,
                dst_bytes_tail_0,
                dst_bytes_tail_1,
                mask_limbs,
                mask_bytes_tail_0,
                mask_bytes_tail_1,
            )
        } else {
            // dst_bytes_tail_0 corresponds to the tail part of mask_limbs,
            // dst_bytes_tail_1 to mask_bytes_tail.
            let mask_bytes_tail_1 = mask_bytes_tail;
            let (mask_limbs, mask_limbs_tail) = mask_limbs.split_at(dst_limbs.len());
            let mask_bytes_tail_0 = cmpa::limb_slice_as_bytes(mask_limbs_tail);
            let (dst_bytes_tail_0, dst_bytes_tail_1) = dst_bytes_tail.split_at_mut(mask_bytes_tail_0.len());
            (
                dst_limbs,
                dst_bytes_tail_0,
                dst_bytes_tail_1,
                mask_limbs,
                mask_bytes_tail_0,
                mask_bytes_tail_1,
            )
        };
    debug_assert_eq!(dst_bytes_tail_0.len(), mask_bytes_tail_0.len());
    debug_assert_eq!(dst_bytes_tail_1.len(), mask_bytes_tail_1.len());

    _xor_bytes(dst_bytes_head_0, mask_bytes_head_0);
    _xor_bytes(dst_bytes_head_1, mask_bytes_head_1);
    for i in dst_limbs.iter_mut().zip(mask_limbs.iter()) {
        *i.0 ^= i.1;
    }
    _xor_bytes(dst_bytes_tail_0, mask_bytes_tail_0);
    _xor_bytes(dst_bytes_tail_1, mask_bytes_tail_1);
}

#[test]
fn test_xor_bytes() {
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
