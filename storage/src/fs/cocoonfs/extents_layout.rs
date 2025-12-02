// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`ExtentsLayout`].

use super::alloc_bitmap::BitmapWord;
use crate::{
    fs::{
        NvFsError,
        cocoonfs::{FormatError, layout},
    },
    nvfs_err_internal,
    utils_common::bitmanip::{BitManip as _, UBitManip as _},
};

/// Layout characteristics of a logical group of extents.
///
/// A single extent denotes a physically contiguous region on storage.
/// `ExtentsLayout` specifies the layout characteristics of a logical group of
/// such, e.g. for allocating one suitable for storing a certain filesystem
/// entity.
///
/// Each extent is always an integral multiple of the [Allocation Block
/// size](layout::ImageLayout::allocation_block_size_128b_log2) in length.
/// Further constraints on the [maximum
/// length](Self::max_extent_allocation_blocks) and [alignment
/// requirements](Self::extent_alignment_allocation_blocks_log2) may be imposed
/// on the extents in the group.
///
/// Each individual extent is split into a header and a payload part. Typically
/// the payload would be encrypted, while the headers are not. An [alignment
/// constraint](Self::extent_payload_len_alignment) may be imposed
/// on the lengths of the payloads, typically a block cipher block size.
///
/// Depending on the context the extent group is to be used in, it may be
/// required to
/// * store a header for the group as a whole, the common ["extents
///   header"](Self::extents_hdr_len), in one of its extents,
/// * or a header in each extent individually, the ["extent
///   header"](Self::extent_hdr_len),
/// * or both.
///
/// For example, a single block cipher mode IV might be needed for the extents
/// group as a whole, and an authentication tag for each extent in the group
/// individually.
///
/// Finally it may be required to reserve some fixed length [header-like portion
/// within each extent's aligned payload](Self::extent_payload_hdr_len) region.
/// For example when chaining extents, this may be used to store a chaining
/// pointer within the encrypted payload area.
#[derive(Clone)]
pub struct ExtentsLayout {
    /// Maximum length in units of [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2) any extent
    /// in the group may have.
    pub max_extent_allocation_blocks: layout::AllocBlockCount,
    /// Alignment constraint on the boundaries for any extent in the group,
    /// specified as the base-2 logarithm of the desired alignment in units
    /// of [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    ///
    /// May be zero for none.
    pub extent_alignment_allocation_blocks_log2: u8,

    /// The common "extents header" length in units of Bytes.
    pub extents_hdr_len: u32,
    /// The individual "extent header" length in units of Bytes.
    pub extent_hdr_len: u32,

    /// The payload header length to reserve from the aligned payload region in
    /// each extent.
    pub extent_payload_hdr_len: u32,
    /// The payload region length alignement within each extent in units of
    /// Bytes.
    ///
    /// Must not be zero, may be one for none.
    pub extent_payload_len_alignment: u8,

    /// Cached value of the [Allocation Block
    /// size](layout::ImageLayout::allocation_block_size_128b_log2).
    pub allocation_block_size_128b_log2: u8,
}

impl ExtentsLayout {
    /// Create a new [`ExtentsLayout`] instance.
    ///
    /// # Arguments:
    ///
    /// Refer to the [`ExtentsLayout`] individual fields' documentation for
    /// their meaning.
    pub fn new(
        max_extent_allocation_blocks: Option<layout::AllocBlockCount>,
        extent_alignment_allocation_blocks_log2: u8,
        extents_hdr_len: u32,
        extent_hdr_len: u32,

        extent_payload_hdr_len: u32,
        extent_payload_len_alignment: u8,

        allocation_block_size_128b_log2: u8,
    ) -> Result<Self, NvFsError> {
        // The rest of the code relies on the extents alignment unit being <= 2^63 Bytes
        // in size.
        if extent_alignment_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32 + 7 >= u64::BITS {
            return Err(nvfs_err_internal!());
        }
        // The extent_payload_len_alignment must be non-zero.
        if extent_payload_len_alignment == 0 {
            return Err(nvfs_err_internal!());
        }
        // The payload alignment must be <= the extent alignment.
        if (extent_payload_len_alignment as u64)
            >> (extent_alignment_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32 + 7)
            > 1
        {
            return Err(nvfs_err_internal!());
        }
        // The extents allocation code relies on the extents alignment being
        // sub-BitmapWord.
        if extent_alignment_allocation_blocks_log2 as u32 >= BitmapWord::BITS {
            return Err(nvfs_err_internal!());
        }

        let max_extent_allocation_blocks_upper_bound = u64::MAX >> (allocation_block_size_128b_log2 + 7);
        let max_extent_allocation_blocks = max_extent_allocation_blocks
            .map(|max_extent_allocation_blocks| {
                u64::from(max_extent_allocation_blocks).min(max_extent_allocation_blocks_upper_bound)
            })
            .unwrap_or(max_extent_allocation_blocks_upper_bound)
            .round_down_pow2(extent_alignment_allocation_blocks_log2 as u32);
        if max_extent_allocation_blocks == 0 {
            return Err(nvfs_err_internal!());
        }

        let extents_layout = Self {
            max_extent_allocation_blocks: layout::AllocBlockCount::from(max_extent_allocation_blocks),
            extent_alignment_allocation_blocks_log2,
            extents_hdr_len,
            extent_hdr_len,
            extent_payload_hdr_len,
            extent_payload_len_alignment,
            allocation_block_size_128b_log2,
        };

        // Verify that a minimum length extent does not exceed
        // max_extent_allocation_blocks. For the first extent, which stores the
        // extents header, the minimum allowed effective payload length is zero.
        // For any other "tail" extent, there must be at least one byte worth of
        // effective payload.
        if extents_hdr_len != 0 {
            let head_extent_min_allocation_blocks = extents_layout.extent_payload_len_to_allocation_blocks(0, true);
            if !head_extent_min_allocation_blocks.1 {
                // Saturated.
                return Err(NvFsError::from(FormatError::InvalidImageLayoutConfig));
            }
        }
        // If extents_hdr_len >= the payload alignment, then removing the extents
        // headers automatically yields at least that amount of payload for the
        // tail extents.
        if extents_hdr_len < extent_payload_len_alignment as u32 {
            let tail_extent_min_allocation_blocks = extents_layout.extent_payload_len_to_allocation_blocks(1, false);
            if !tail_extent_min_allocation_blocks.1 {
                // Saturated.
                return Err(NvFsError::from(FormatError::InvalidImageLayoutConfig));
            }
        }

        Ok(extents_layout)
    }

    /// Compute the effective payload storage length provided by some extent of
    /// specified dimensions.
    ///
    /// The effective payload length is computed from the total length by
    /// considering the different possible headers lengths as well as the
    /// payload alignment constraints as collectively specified in the
    /// [`ExtentsLayout`].
    ///
    /// # Arguments:
    ///
    /// * `extent_allocation_blocks` - The extent's length in units of
    ///   [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    /// * `extent_stores_extents_hdr` - Whether or not the extent stores the
    ///   extents group's [common extents header](Self::extents_hdr_len), i.e.
    ///   whether or not it is the first in the group.
    pub fn extent_effective_payload_len(
        &self,
        extent_allocation_blocks: layout::AllocBlockCount,
        extent_stores_extents_hdr: bool,
    ) -> u64 {
        debug_assert!(extent_allocation_blocks <= self.max_extent_allocation_blocks);
        debug_assert_ne!(u64::from(extent_allocation_blocks), 0);
        // No overflow, the max_extent_allocation_blocks upper bound ensures the size in
        // units of Bytes fits an u64.
        let total_extent_len = u64::from(extent_allocation_blocks) << (self.allocation_block_size_128b_log2 + 7);

        let total_payload_len = total_extent_len
            - if extent_stores_extents_hdr {
                self.extents_hdr_len as u64
            } else {
                0
            }
            - self.extent_hdr_len as u64;

        let payload_padding_len = if self.extent_payload_len_alignment.is_pow2() {
            total_payload_len & (self.extent_payload_len_alignment as u64 - 1)
        } else {
            total_payload_len % self.extent_payload_len_alignment as u64
        };

        total_payload_len - payload_padding_len - self.extent_payload_hdr_len as u64
    }

    /// Convert a given effective payload storage length to an extent size.
    ///
    /// Compute the minimum extent length capable of [providing an effective
    /// payload storage length](Self::extent_effective_payload_len) of
    /// at least `effective_payload_len`, if possible, considering the different
    /// possible headers lengths as well as the payload alignment
    /// constraints as collectively specified in the [`ExtentsLayout`].
    ///
    /// A pair of an extent length in units of [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2) and a
    /// `bool` is returned:
    ///
    /// * if an extent of the returned length provides at least the desired
    ///   `effective_payload_len` of effective payload storage, the `bool` is
    ///   set to `true`,
    /// * otherwise the extent length had been capped to the  [maximum allowed
    ///   extent length] (Self::max_extent_allocation_blocks) and the `bool` is
    ///   set to `false`.
    ///
    /// # Arguments:
    ///
    /// * `effective_payload_len` - The desired effective payload storage length
    ///   to be provided by the extent.
    /// * `extent_stores_extents_hdr` - Whether or not the extent stores the
    ///   extents group's [common extents header](Self::extents_hdr_len), i.e.
    ///   whether or not it is the first in the group.
    pub fn extent_payload_len_to_allocation_blocks(
        &self,
        effective_payload_len: u64,
        extent_stores_extents_hdr: bool,
    ) -> (layout::AllocBlockCount, bool) {
        if !extent_stores_extents_hdr && effective_payload_len == 0 {
            return (layout::AllocBlockCount::from(0), true);
        }

        let mut saturated = false;
        let mut payload_len = match effective_payload_len.checked_add(self.extent_payload_hdr_len as u64) {
            Some(payload_len) => payload_len,
            None => {
                saturated = true;
                u64::MAX
            }
        };
        let payload_len_padding = if self.extent_payload_len_alignment.is_pow2() {
            payload_len.wrapping_neg() & (self.extent_payload_len_alignment as u64 - 1)
        } else {
            let r = payload_len % self.extent_payload_len_alignment as u64;
            if r == 0 {
                0
            } else {
                self.extent_payload_len_alignment as u64 - r
            }
        };

        let mut extent_allocation_blocks = payload_len >> (self.allocation_block_size_128b_log2 + 7);
        payload_len -= extent_allocation_blocks << (self.allocation_block_size_128b_log2 + 7);

        // This will not overflow, all three addends are <= u32::MAX.
        let mut headers_len = if extent_stores_extents_hdr {
            self.extents_hdr_len as u64
        } else {
            0
        } + self.extent_hdr_len as u64
            + payload_len_padding;
        let headers_allocation_blocks = headers_len >> (self.allocation_block_size_128b_log2 + 7);
        headers_len -= headers_allocation_blocks << (self.allocation_block_size_128b_log2 + 7);
        // Does not overflow, the upper self.allocation_block_size_128b_log2 + 7 bits
        // of each addend are clear.
        extent_allocation_blocks += headers_allocation_blocks;

        // Does not overflow, both addends are strictly less than the allocation block
        // size, which is a power of two <= 2^63.
        let remaining_len = headers_len + payload_len;
        // This would not overflow, the addend is <= 1, as per the above.
        extent_allocation_blocks += remaining_len >> (self.allocation_block_size_128b_log2 + 7);
        if remaining_len & ((1u64 << (self.allocation_block_size_128b_log2 + 7)) - 1) != 0 {
            extent_allocation_blocks += 1;
        }

        let extent_allocation_blocks = if extent_allocation_blocks > u64::from(self.max_extent_allocation_blocks) {
            saturated = true;
            u64::from(self.max_extent_allocation_blocks)
        } else {
            extent_allocation_blocks
        };
        // The upper bound imposed above is aligned, so the aligned result will stay
        // within that upper bound.
        let extent_allocation_blocks =
            extent_allocation_blocks.round_up_pow2_unchecked(self.extent_alignment_allocation_blocks_log2 as u32);
        (layout::AllocBlockCount::from(extent_allocation_blocks), !saturated)
    }

    /// Determine the minimum possible length for any extent in a group
    /// formatted according to the [`ExtentsLayout`].
    ///
    /// A pair of two extents lengths in units of [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2) each is
    /// returned: the first entry specifies the lower bound on the length
    /// for the first extent storing the group's [common extents
    /// header](Self::extents_hdr_len), the second entry the one on the lengths
    /// of any of the other "continuation" tail extents.
    pub fn min_extents_allocation_blocks(&self) -> (layout::AllocBlockCount, layout::AllocBlockCount) {
        // Continuation "tail" extents must provide at least one Byte of payload.
        let tail_extent_min_allocation_blocks = self.extent_payload_len_to_allocation_blocks(1, false);
        debug_assert!(tail_extent_min_allocation_blocks.1);
        let tail_extent_min_allocation_blocks = tail_extent_min_allocation_blocks.0;
        let head_extent_min_allocation_blocks = if self.extents_hdr_len != 0 {
            let head_extent_min_allocation_blocks = self.extent_payload_len_to_allocation_blocks(0, true);
            debug_assert!(head_extent_min_allocation_blocks.1);
            head_extent_min_allocation_blocks.0
        } else {
            tail_extent_min_allocation_blocks
        };
        (head_extent_min_allocation_blocks, tail_extent_min_allocation_blocks)
    }

    /// Determine whether or not the cost of placing the extents group's [common
    /// extents header](Self::extents_hdr_len) is independent
    /// of the containing extent's dimensions.
    ///
    /// Depending on the size of the group's [common extents
    /// header](Self::extents_hdr_len) as well as the various alignment
    /// constrains imposed by the [`ExtentsLayout`], the amount of
    /// padding required when placing that header might depend on the
    /// containing extent's dimensions or not.
    ///
    /// Return `true` if the relative placement cost does not depend on the
    /// containing extent's length, `false` otherwise.
    pub fn extents_hdr_placement_cost_is_invariant(&self) -> bool {
        // Determine whether any extent's payload padding amount might depend on the
        // presence of the extents header. If it does, the padding amount would
        // depend on the respective extent's allocated size.
        if self.extents_hdr_len == 0 {
            true
        } else if self.extent_payload_len_alignment.is_pow2() {
            // The payload alignment is <= the extent alignment, c.f. Self::new().
            debug_assert!(
                self.extent_payload_len_alignment as u64
                    <= 1u64
                        << (self.extent_alignment_allocation_blocks_log2 + self.allocation_block_size_128b_log2 + 7)
            );
            true
        } else {
            self.extents_hdr_len % self.extent_payload_len_alignment as u32 == 0
        }
    }

    /// Determine the relative cost of placing the extents group's [common
    /// extents header](Self::extents_hdr_len) into an extent of specified
    /// dimensions.
    ///
    ///
    /// Depending on the size of the group's [common extents
    /// header](Self::extents_hdr_len) as well as the various alignment
    /// constrains imposed by the [`ExtentsLayout`], the amount of padding
    /// required when placing that header might depend on the containing
    /// extent's dimensions.
    ///
    /// Accordingly, when selecting an extent in the group to place that common
    /// header into, it might be worthwhile to minimize the relative cost.
    ///
    /// Compute the relative cost associated with placing the [common extents
    /// header](Self::extents_hdr_len) in an extent of length
    /// `extent_allocation_blocks`, defined as the amount of [`effective
    /// payload storage capacity`](Self::extent_effective_payload_len) lost when
    /// compared to not storing the header in that extent.
    pub fn extents_hdr_placement_cost(&self, extent_allocation_blocks: layout::AllocBlockCount) -> u64 {
        debug_assert!(extent_allocation_blocks <= self.max_extent_allocation_blocks);
        debug_assert_ne!(u64::from(extent_allocation_blocks), 0);
        if self.extents_hdr_len == 0 {
            0
        } else if self.extent_payload_len_alignment.is_pow2() {
            debug_assert!(self.extents_hdr_placement_cost_is_invariant());
            let payload_padding_wo_extents_hdr_len =
                (self.extent_hdr_len as u64).wrapping_neg() & (self.extent_payload_len_alignment as u64 - 1);
            let payload_padding_w_extents_hdr_len = (self.extents_hdr_len as u64 + self.extent_hdr_len as u64)
                .wrapping_neg()
                & (self.extent_payload_len_alignment as u64 - 1);
            // Does not overflow, extents_hdr_len is an u32 and the payload alignment even
            // fits an u8.
            self.extents_hdr_len as u64 + payload_padding_w_extents_hdr_len - payload_padding_wo_extents_hdr_len
        } else {
            // No overflow, the max_extent_allocation_blocks upper bound ensures the size in
            // units of bytes fits an u64.
            let total_extent_len = u64::from(extent_allocation_blocks) << (self.allocation_block_size_128b_log2 + 7);
            let total_payload_len_wo_extents_hdr = total_extent_len - self.extent_hdr_len as u64;
            let payload_padding_wo_extents_hdr_len =
                total_payload_len_wo_extents_hdr % self.extent_payload_len_alignment as u64;
            let total_payload_len_w_extents_hdr = total_payload_len_wo_extents_hdr - self.extents_hdr_len as u64;
            let payload_padding_w_extents_hdr_len =
                total_payload_len_w_extents_hdr % self.extent_payload_len_alignment as u64;
            // Does not overflow, extents_hdr_len is an u32 and the payload alignment even
            // fits an u8.
            self.extents_hdr_len as u64 + payload_padding_w_extents_hdr_len - payload_padding_wo_extents_hdr_len
        }
    }
}
