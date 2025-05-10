// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`AllocBitmap`].

extern crate alloc;
use alloc::vec::Vec;

use super::bitmap_word::{BITMAP_WORD_BITS_LOG2, BitmapWord, BitmapWordBlocksLsbsMaskTable};
use super::sparse_bitmap::{SparseAllocBitmap, SparseAllocBitmapUnion, SparseAllocBitmapUnionWordIterator};
use crate::{
    fs::{
        NvFsError, NvFsIoError,
        cocoonfs::{
            CocoonFsFormatError, extents,
            extents_layout::ExtentsLayout,
            layout::{self, BlockCount as _},
        },
    },
    nvfs_err_internal,
    utils_common::{
        alloc::try_alloc_vec,
        bitmanip::{BitManip as _, UBitManip as _},
    },
};
use core::cmp;

/// Details of an [`extents`](extents::PhysicalExtents) allocation request.
///
/// Allocation requests are always specified in terms of the total effective
/// payload capacity to be collectively provided by the allocated extents at
/// least. (Non-trivial) [`ExtentsLayout`] constraints may be imposed on the
/// group of to be allocated extents, possibly specifying the various possible
/// headers' lengths each, as well as alignment and size constraints.
#[derive(Clone)]
pub struct ExtentsAllocationRequest {
    /// Total effective payload length to allocate at least.
    pub total_effective_payload_len: u64,
    /// [`ExtentsLayout`] format applying to the to be allocated group of
    /// extents.
    layout: ExtentsLayout,
}

impl ExtentsAllocationRequest {
    /// Instantiate a new [`ExtentsAllocationRequest`].
    ///
    /// # Arguments:
    ///
    /// * `total_effective_payload_len` - The total effective payload storage
    ///   length to be provided at least by the to be allocated group of
    ///   extents.
    /// * `layout` - [`ExtentsLayout`] constraints applying to the to be
    ///   allocated group of extents.
    pub fn new(total_effective_payload_len: u64, layout: &ExtentsLayout) -> Self {
        Self {
            total_effective_payload_len,
            layout: layout.clone(),
        }
    }

    /// Get the associated [`ExtentsLayout`] constraint.
    pub fn get_layout(&self) -> &ExtentsLayout {
        &self.layout
    }

    /// Create a [extents reallocation request](ExtentsReallocationRequest).
    ///
    /// When resizing some existing filesystem entity, it might be worthwhile to
    /// retain some or all of its backing extents on storage as appropriate.
    /// In order to accomodate for a new effective payload length of
    /// `total_effective_payload_len`, the `preexisting_extents` might
    /// either
    ///
    /// * need to get shrunken in order to free up excess space, as indicated by
    ///   a return value of [`ExtentsReallocationRequest::Shrink`],
    /// * kept as-is, as indicated by a return value of
    ///   [`ExtentsReallocationRequest::Keep`],
    /// * or need to get extended, as indicated by
    ///   [`ExtentsReallocationRequest::Grow`] with its associated
    ///   [`ExtentsAllocationRequest`] suitable for allocating the extension
    ///   extents.
    ///
    /// In either case, it is assumed that the relative order of the retained
    /// `preexisting_extents` is preserved and, in case of a growing
    /// operation, that they will all be ordered before any additionally
    /// allocated extents in the resulting extents group. In particular, it is
    /// assumed the the extents group's [common extents
    /// header](ExtentsLayout::extents_hdr_len) will be placed into the first
    /// extent thereof, if any.
    ///
    /// Furthermore, all `preexisting_extents` must conform to the constraints
    /// imposed by the specified [`layout`](ExtentsLayout):
    ///
    /// * their boundaries must be aligned according to
    ///   [ExtentsLayout::extent_alignment_allocation_blocks_log2] and
    /// * their lengths must all be within the bounds as given by
    ///   [`ExtentsLayout::min_extents_allocation_blocks()`] and
    ///   [ExtentsLayout::max_extent_allocation_blocks].
    ///
    /// # Arguments:
    ///
    /// * `preexisting_extents` - The preexisting extents to reallocate.
    /// * `total_effective_payload_len` - The total effective payload storage
    ///   length to be provided at least by the to be reallocated group of
    ///   extents.
    /// * `layout` - [`ExtentsLayout`] constraints applying to the to be
    ///   reallocated group of extents.
    pub fn new_reallocate(
        preexisting_extents: &extents::PhysicalExtents,
        total_effective_payload_len: u64,
        layout: &ExtentsLayout,
    ) -> Result<ExtentsReallocationRequest, NvFsError> {
        let mut remaining_effective_payload_len = total_effective_payload_len;
        let mut is_first = true;
        for (preexisting_extent_index, preexisting_extent) in preexisting_extents.iter().enumerate() {
            // Determine the maximum possible extent length that could get allocated to move
            // towards request completion at the current point.
            let remaining_max_extent_allocation_blocks =
                layout.extent_payload_len_to_allocation_blocks(remaining_effective_payload_len, is_first);
            if remaining_max_extent_allocation_blocks.0 >= preexisting_extent.block_count() {
                // Excess space could still cause an underflow, so saturate.
                remaining_effective_payload_len = remaining_effective_payload_len
                    .saturating_sub(layout.extent_effective_payload_len(preexisting_extent.block_count(), is_first));
            } else {
                // The pre-existing allocation is too large and should get truncated.
                if preexisting_extent.block_count() > layout.max_extent_allocation_blocks {
                    // The current extent is even larger than the maximum allowed limit. In
                    // principle we could split the extent logically and
                    // continue, but don't even bother.
                    return Err(NvFsError::from(CocoonFsFormatError::InvalidExtents));
                }
                // When here, the current extent provides enough space to accomodate
                // the remaining_effective_payload_len.
                return Ok(ExtentsReallocationRequest::Shrink {
                    last_retained_extent_index: preexisting_extent_index,
                    last_retained_extent_allocation_blocks: remaining_max_extent_allocation_blocks.0,
                });
            }
            is_first = false;
        }

        if remaining_effective_payload_len == 0 {
            Ok(ExtentsReallocationRequest::Keep)
        } else {
            let mut layout = layout.clone();
            if !is_first {
                // Don't account for the extents_hdr when extending an existing allocation.
                layout.extents_hdr_len = 0;
            }
            Ok(ExtentsReallocationRequest::Grow {
                request: Self {
                    total_effective_payload_len: remaining_effective_payload_len,
                    layout,
                },
            })
        }
    }

    /// Determine the upper bound on the next extent's length to allocate in
    /// working towards completing the [`ExtentsAllocationRequest`].
    ///
    /// Assuming that the already allocated extents, if any, collectively
    /// provide a total effective payload capacity of
    /// `allocated_effective_payload_len`, determine the upper bound on the
    /// length of the next extent to be allocated in working towards
    /// completing the [`ExtentsAllocationRequest`].
    ///
    /// # Arguments:
    ///
    /// * `allocated_effective_payload_len` - The assumed total effective
    ///   payload length already allocated. Must not be greater than
    ///   `self.total_effective_payload_len`.
    fn remaining_max_extent_allocation_blocks(
        &self,
        allocated_effective_payload_len: u64,
    ) -> (layout::AllocBlockCount, bool) {
        debug_assert!(allocated_effective_payload_len <= self.total_effective_payload_len);
        if allocated_effective_payload_len == self.total_effective_payload_len {
            return (layout::AllocBlockCount::from(0), true);
        }

        let is_first = allocated_effective_payload_len == 0;

        let remaining_effective_payload_len = self.total_effective_payload_len - allocated_effective_payload_len;

        self.layout
            .extent_payload_len_to_allocation_blocks(remaining_effective_payload_len, is_first)
    }
}

/// Details of an [`extents`](extents::PhysicalExtents) reallocation request,
/// created through [`ExtentsAllocationRequest::new_reallocate()`].
pub enum ExtentsReallocationRequest {
    /// Keep the preexisting extents as-is.
    Keep,
    /// Shring the preexisting extents.
    Shrink {
        /// Index of last preexisting extent to retain in full or part.
        last_retained_extent_index: usize,
        /// Number of [Allocation
        /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2) to
        /// retain in the last extent identified by
        /// `last_retained_extent_index`.
        ///
        /// Can be zero!
        last_retained_extent_allocation_blocks: layout::AllocBlockCount,
    },
    /// Extend the preexisting extents by some newly allocated ones.
    Grow {
        /// [`ExtentsAllocationRequest`] suitable for allocating the extension.
        request: ExtentsAllocationRequest,
    },
}

/// Progress tracking data for an [`ExtentsAllocationRequest`].
struct ExtentsAllocationRequestProgress<'a> {
    /// The [`ExtentsAllocationRequest`] being worked on.
    request: &'a ExtentsAllocationRequest,
    /// Amount of effective payload capacity less than or equal to the requested
    /// [`ExtentsAllocationRequest::total_effective_payload_len`] allocated so
    /// far.
    ///
    /// If the current value is strictly less than
    /// `request.total_effective_payload_len`, then the
    /// [`allocated_excess_effective_payload_len`](Self::allocated_excess_effective_payload_len) is zero.
    allocated_effective_payload_len: u64,
    /// Amount of effective payload capacity beyond the requested
    /// [`ExtentsAllocationRequest::total_effective_payload_len`] allocated so
    /// far.
    ///
    /// If non-zero, then
    /// [`allocated_effective_payload_len`](Self::allocated_effective_payload_len)
    /// equals `request.total_effective_payload_len`.
    allocated_excess_effective_payload_len: u64,
    /// Cached value of
    /// [`ExtentsLayout::extents_hdr_placement_cost_is_invariant()`].
    extents_hdr_placement_cost_is_invariant: bool,
}

impl<'a> ExtentsAllocationRequestProgress<'a> {
    /// Instantiate a [`ExtentsAllocationRequestProgress`].
    fn new(request: &'a ExtentsAllocationRequest) -> Self {
        let extents_hdr_placement_cost_is_invariant = request.layout.extents_hdr_placement_cost_is_invariant();
        Self {
            request,
            allocated_effective_payload_len: 0,
            allocated_excess_effective_payload_len: 0,
            extents_hdr_placement_cost_is_invariant,
        }
    }

    /// Determine the remaining effective payload length to allocate.
    fn remaining_effective_payload_len(&self) -> u64 {
        let remaining_effective_len = self.request.total_effective_payload_len - self.allocated_effective_payload_len;
        debug_assert!(remaining_effective_len == 0 || self.allocated_excess_effective_payload_len == 0);
        remaining_effective_len
    }

    /// Refit an already allocated extent to a smaller effective payload length.
    ///
    /// It is assumed that the desired target
    /// `extent_accounted_target_effective_payload_len` is
    ///
    /// * less or equal than the total effective payload storage capacity
    ///   provided by the allocated extent's current length
    /// * and  equals that part of the current extent's total provided effective
    ///   payload storage capacity that is being considered to currently have
    ///   been accounted for at [`Self::allocated_effective_payload_len`] and
    ///   [`Self::allocated_excess_effective_payload_len`] respectively.
    ///
    /// For clarity on the latter point: in general, an extent's accounted
    /// effective payload length is always equal to its total capacity, but
    /// callers may artificially reduce it by some amount they somehow
    /// gained elsewhere and not accounted for yet, e.g. via header
    /// placement optimizations, for the purpose of invoking this function.
    /// Note that this effectively transfers the "accounted" status from a
    /// fraction of the extent's total effective payload capacity over to that
    /// gained payload.
    ///
    /// In a first step of the refitting procedure, the input
    /// `extent_accounted_target_effective_payload_len` gets further reduced as
    /// much as possible while still staying in the
    /// `max_final_remaining_effective_payload_len` realm, updating the
    /// accounting in the course. That is, it gets reduced by the maximum amount
    /// such that
    /// [`remaining_effective_payload_len()`](Self::remaining_effective_payload_len) would not
    /// exceed `max_final_remaining_effective_payload_len`. The intended usecase
    /// is to not overallocate too much by upwards alignment when doing full
    /// [`BitmapWord`] allocations in case the remainder, including headers,
    /// could fit into a subword allocation already.
    ///
    /// Afterwards, the minimum extent length compatible with the constraints
    /// imposed by the [`ExtentsAllocationRequest`]'s associated
    /// [`ExtentsLayout`] and capable of storing the resulting effective
    /// payload length is determined. Any additional payload capacity due to
    /// alignment is being accounted for and the resulting fitted extent length
    /// returned.
    ///
    /// # Arguments:
    ///
    /// * `extent_accounted_target_effective_payload_len` - The part of the
    ///   extent's total effective payload capacity being considered by the
    ///   caller as having been accounted for.
    /// * `extent_stores_extents_hdr` - Whether or not the extent in question
    ///   stores the [common extents header](ExtentsLayout::extents_hdr_len).
    /// * `max_final_remaining_effective_payload_len` - Upper bound on the value
    ///   [`remaining_effective_payload_len()`](Self::remaining_effective_payload_len)
    ///   may have after the refitting.
    /// * `min_extent_alignment_allocation_blocks_log2` - Alignment constrains
    ///   on the refitted extent.
    fn fit_allocated_extent_to_effective_payload_len(
        &mut self,
        mut extent_accounted_target_effective_payload_len: u64,
        extent_stores_extents_hdr: bool,
        max_final_remaining_effective_payload_len: u64,
        min_extent_alignment_allocation_blocks_log2: u32,
    ) -> layout::AllocBlockCount {
        debug_assert!(
            extent_accounted_target_effective_payload_len.wrapping_sub(self.allocated_excess_effective_payload_len)
                <= self.allocated_effective_payload_len
        );
        let min_extent_alignment_allocation_blocks_log2 = min_extent_alignment_allocation_blocks_log2
            .max(self.request.layout.extent_alignment_allocation_blocks_log2 as u32);

        // If there's already some allocated excess, stemming from previous upwards
        // alignment of this or a different extent, then deduct that from the
        // current target payload length and update the accounting accordingly.
        let x = extent_accounted_target_effective_payload_len.min(self.allocated_excess_effective_payload_len);
        extent_accounted_target_effective_payload_len -= x;
        self.allocated_excess_effective_payload_len -= x;
        debug_assert!(
            extent_accounted_target_effective_payload_len == 0 || self.allocated_excess_effective_payload_len == 0
        );

        // Determine the minimum amount of effective payload len this extent must
        // provide. The actual payload length capacity might get larger, due to
        // the upwards alignment (assuming no truncation to the
        // max_extent_allocation_blocks limit below).
        let remaining_effective_payload_len = self.remaining_effective_payload_len();
        let extent_min_allocated_effective_payload_len = extent_accounted_target_effective_payload_len
            .saturating_sub(max_final_remaining_effective_payload_len.saturating_sub(remaining_effective_payload_len));
        let extent_allocation_blocks = layout::AllocBlockCount::from(
            u64::from(
                self.request
                    .layout
                    .extent_payload_len_to_allocation_blocks(
                        extent_min_allocated_effective_payload_len,
                        extent_stores_extents_hdr,
                    )
                    .0,
            )
            // This should be a no-op, because the input
            // extent_accounted_target_effective_payload_len comes from an already allocated extent,
            // but better make it explicit.
            .min(
                u64::from(self.request.layout.max_extent_allocation_blocks)
                    .round_down_pow2(min_extent_alignment_allocation_blocks_log2),
            )
            .round_up_pow2_unchecked(min_extent_alignment_allocation_blocks_log2),
        );

        // Finally compute the actual effective payload length capacity and update the
        // internal bookkeeping in order to account for any differences from
        // original input extent_accounted_target_effective_payload_len.
        let extent_allocated_effective_len = self
            .request
            .layout
            .extent_effective_payload_len(extent_allocation_blocks, extent_stores_extents_hdr);
        debug_assert!(
            extent_stores_extents_hdr
                || extent_allocated_effective_len == 0
                || extent_accounted_target_effective_payload_len != 0
        );
        debug_assert!(
            extent_stores_extents_hdr
                || extent_allocated_effective_len == 0
                || self.allocated_excess_effective_payload_len == 0
        );
        if extent_allocated_effective_len >= extent_accounted_target_effective_payload_len {
            let x = extent_allocated_effective_len - extent_accounted_target_effective_payload_len;
            let y = x.min(remaining_effective_payload_len);
            self.allocated_effective_payload_len += y;
            self.allocated_excess_effective_payload_len += x - y;
        } else {
            debug_assert_ne!(extent_accounted_target_effective_payload_len, 0);
            debug_assert_eq!(self.allocated_excess_effective_payload_len, 0);
            let x = extent_accounted_target_effective_payload_len - extent_allocated_effective_len;
            self.allocated_effective_payload_len -= x;
        }

        extent_allocation_blocks
    }

    /// Find the shortest among a sequence of extents.
    ///
    /// If `extents` is non-empty, return the index of some extent of shortest
    /// length wrapped in a `Some`, `None` otherwise.
    fn find_shortest_extent(extents: &extents::PhysicalExtents) -> Option<usize> {
        if !extents.is_empty() {
            let mut shortest_extent = (0usize, extents.get_extent_range(0usize));
            for (cur_extent_index, cur_extent) in extents.iter().enumerate().skip(1) {
                let cur_extent_allocation_blocks = cur_extent.block_count();
                let shortest_extent_allocation_blocks = shortest_extent.1.block_count();
                // Prefer (in this order):
                // a.) shorter extents,
                // b.) extents at increasing positions.
                if cur_extent_allocation_blocks < shortest_extent_allocation_blocks
                    || (cur_extent_allocation_blocks == shortest_extent_allocation_blocks
                        && cur_extent.begin() > shortest_extent.1.begin())
                {
                    shortest_extent = (cur_extent_index, cur_extent);
                }
            }
            Some(shortest_extent.0)
        } else {
            None
        }
    }

    /// Minimize padding waste by optimizing placement of the [common extents
    /// header](ExtentsLayout::extents_hdr_len).
    ///
    /// On entry, it is assumed that the common extents header is currently
    /// stored within the first extent of `extents` and that the internal
    /// bookkeeping has been computed to reflect that fact.
    ///
    /// In case a better extent to store the common extents header is found, it
    /// will be swapped for the first and any gained additional effective
    /// payload length recorded at the internal bookkeeping. In case the
    /// gained effective payload length would render some portion of the
    /// already allocated effective payload length superfluous, some extent will
    /// get shrunken accordingly. To be more specific, it will be attempted
    /// to shrink the existing overall allocation by the extent possible
    /// while still keeping the amount of total unsatisfied effective length
    /// in the bounds specified by `max_final_remaining_effective_payload_len`.
    /// As for
    /// [`fit_allocated_extent_to_effective_payload_len()`](Self::fit_allocated_extent_to_effective_payload_len),
    /// the intended usecase is to not overallocate too much by upwards
    /// alignment when doing full [`BitmapWord`] allocations in case the
    /// remainder, including headers, could fit into a subword allocation
    /// already
    ///
    /// The return value is a pair of values, with the first entry equalling the
    /// number of extents removed from `extents` in the course of the
    /// shrinking process just described.
    ///
    /// As a by-product, the index of the shortest among all extents from
    /// `extents` will also be returned in the second slot, in case that had
    /// been needed in the course of the optimization search.
    ///
    /// # Arguments:
    ///
    /// * `extents` - The allocated extents to optimize the [common extents
    ///   header](ExtentsLayout::extents_hdr_len) over.
    /// * `shortest_extent_hint` - Index of the shortest extent if `Some`.
    /// * `head_extent_min_allocation_blocks` - Minimum length of an extent
    ///   storing the [common extents header](ExtentsLayout::extents_hdr_len),
    ///   as determined by [`ExtentsLayout::min_extents_allocation_blocks()`].
    /// * `max_final_remaining_effective_payload_len` - Upper bound on the value
    ///   [`remaining_effective_payload_len()`](Self::remaining_effective_payload_len)
    ///   may have after any potential extent shrinking.
    /// * `min_extent_alignment_allocation_blocks_log2` - Alignment constrains
    ///   on the individual extents each.
    fn optimize_extents_hdr_placement(
        &mut self,
        extents: &mut extents::PhysicalExtents,
        shortest_extent_hint: Option<usize>,
        head_extent_min_allocation_blocks: layout::AllocBlockCount,
        max_final_remaining_effective_payload_len: u64,
        min_extent_alignment_allocation_blocks_log2: u32,
    ) -> (u32, Option<usize>) {
        // Return the position of an extent of minimal length as a byproduct, if
        // possible.
        if extents.len() <= 1 || self.request.layout.extents_hdr_len == 0 {
            if extents.len() == 1 {
                return (0, Some(0));
            } else {
                return (0, None);
            }
        }

        if self.extents_hdr_placement_cost_is_invariant {
            // The extents header placement cost does not depend on the extent length,
            // use whatever extent is currently at the first position in extents.
            (0, shortest_extent_hint)
        } else {
            // The extents header placement cost does depend on the extent length,
            // store it in the best one. While traversing the extents anyway, also
            // determine and return the (first) shortest extent.
            let (
                mut prev_containing_extent_index,
                original_prev_containing_extent_allocation_blocks,
                original_extents_hdr_placement_cost,
                mut best_extents_hdr_placement_cost,
                mut shortest_extent,
            ) = {
                let first_extent = extents.get_extent_range(0);
                let original_prev_containing_extent_allocation_blocks = first_extent.block_count();
                let original_extents_hdr_placement_cost = self
                    .request
                    .layout
                    .extents_hdr_placement_cost(original_prev_containing_extent_allocation_blocks);

                let mut best_placement_extent = (0, first_extent, original_extents_hdr_placement_cost);
                let mut shortest_extent = (0, first_extent);
                for (cur_extent_index, cur_extent) in extents.iter().enumerate().skip(1) {
                    let cur_extent_allocation_blocks = cur_extent.block_count();

                    // For the shortest extent search, prefer (in this order):
                    // a.) shorter extents,
                    // b.) extents at increasing positions,
                    // compare to Self::find_shortest_extent().
                    let shortest_extent_allocation_blocks = shortest_extent.1.block_count();
                    if cur_extent_allocation_blocks < shortest_extent_allocation_blocks
                        || (cur_extent_allocation_blocks == shortest_extent_allocation_blocks
                            && cur_extent.begin() > shortest_extent.1.begin())
                    {
                        shortest_extent = (cur_extent_index, cur_extent);
                    }

                    if cur_extent_allocation_blocks < head_extent_min_allocation_blocks {
                        // The extent does not qualify for storing the extents header.
                        continue;
                    }

                    let cur_extent_extents_hdr_placement_cost = self
                        .request
                        .layout
                        .extents_hdr_placement_cost(cur_extent_allocation_blocks);
                    // For the extents header placement, prefer (in this oder):
                    // a.) extents with a smaller extents header placement cost
                    // b.) shorter extents (so that a potential future truncation
                    //     would free up larger ones),
                    // c.) extents located at smaller positions.
                    let best_placement_extent_allocation_blocks = best_placement_extent.1.block_count();
                    if cur_extent_extents_hdr_placement_cost < best_placement_extent.2
                        || (cur_extent_extents_hdr_placement_cost == best_placement_extent.2
                            && (cur_extent_allocation_blocks < best_placement_extent_allocation_blocks
                                || (cur_extent_allocation_blocks == best_placement_extent_allocation_blocks
                                    && cur_extent.begin() < best_placement_extent.1.begin())))
                    {
                        best_placement_extent = (cur_extent_index, cur_extent, cur_extent_extents_hdr_placement_cost);
                    }
                }

                extents.swap_extents(0, best_placement_extent.0);
                // The extent previously storing the extents header now has been swapped into
                // the former position of the better extent.
                let prev_containing_extent_index = best_placement_extent.0;
                // Conditionally update shortest_extent to account for the swap.
                if shortest_extent.0 == 0 {
                    shortest_extent.0 = best_placement_extent.0;
                } else if shortest_extent.0 == best_placement_extent.0 {
                    shortest_extent.0 = 0;
                }
                (
                    prev_containing_extent_index,
                    original_prev_containing_extent_allocation_blocks,
                    original_extents_hdr_placement_cost,
                    best_placement_extent.2,
                    shortest_extent,
                )
            };

            // The additional effective payload length gained due to the headers transfer,
            // but not accounted for at allocated_effective_payload_len and
            // allocated_excess_effective_payload_len respectively.
            let mut gained_effective_payload_len =
                original_extents_hdr_placement_cost - best_extents_hdr_placement_cost;
            debug_assert!(gained_effective_payload_len < self.request.layout.extent_payload_len_alignment as u64);

            // If there's more effective payload length to allocate, use the gained length
            // up to the point we'd get into the max_final_remaining_effective_payload_len
            // realm.
            let remaining_effective_payload_len = self.remaining_effective_payload_len();
            if remaining_effective_payload_len > max_final_remaining_effective_payload_len {
                let x = gained_effective_payload_len
                    .min(remaining_effective_payload_len - max_final_remaining_effective_payload_len);
                self.allocated_effective_payload_len += x;
                gained_effective_payload_len -= x;
            }

            // Any non-zero gained_effective_payload_len at this point is not reflected
            // in the allocated_effective_payload_len and
            // allocated_excess_effective_payload_len respectively, but is
            // effectively present in the allocated extents. Try to shrink
            // existing extents and update the accounting alongside. Start out with the
            // shortest extent in the hope it can get dropped alltogether.
            let mut n_extents_removed = 0u32;
            let shortest_extent = if gained_effective_payload_len != 0
                && shortest_extent.0 != 0
                && shortest_extent.0 != prev_containing_extent_index
            {
                let original_shortest_extent_block_count = shortest_extent.1.block_count();
                let mut shortest_extent_used_effective_payload_len = self
                    .request
                    .layout
                    .extent_effective_payload_len(original_shortest_extent_block_count, false);
                // Subtract the gained_effective_payload_len to reflect the actual accounting.
                let x = shortest_extent_used_effective_payload_len.min(gained_effective_payload_len);
                shortest_extent_used_effective_payload_len -= x;
                gained_effective_payload_len -= x;
                debug_assert!(shortest_extent_used_effective_payload_len == 0 || gained_effective_payload_len == 0);
                let updated_shortest_extent_allocation_blocks = self.fit_allocated_extent_to_effective_payload_len(
                    shortest_extent_used_effective_payload_len,
                    false,
                    max_final_remaining_effective_payload_len,
                    min_extent_alignment_allocation_blocks_log2,
                );
                if u64::from(updated_shortest_extent_allocation_blocks) != 0 {
                    debug_assert_ne!(shortest_extent_used_effective_payload_len, 0);
                    debug_assert_eq!(gained_effective_payload_len, 0);
                    if updated_shortest_extent_allocation_blocks < original_shortest_extent_block_count {
                        let removed = extents.shrink_extent_by(
                            shortest_extent.0,
                            original_shortest_extent_block_count - updated_shortest_extent_allocation_blocks,
                        );
                        debug_assert!(!removed);
                        // In principle, a shrinking of the extent might have turned it into an even
                        // better choice for the extents header placement. However, note that the
                        // total sum of multiple successive header placement gains is still bounded
                        // (strictly from above) by the payload alignment unit, because all those
                        // stem from iteratively and monotonically decreasing the required alignment
                        // padding.  When shortening (not removing in the general, but unrealistic
                        // case!) an existing extent (like just done here), the allocated effective
                        // payload "lost" is at least the size of a (two to the power of)
                        // min_extent_alignment_allocation_blocks_log2 sized block, aligned
                        // downwards to the requested payload alignment, which is at least one unit
                        // of that payload alignment in size, c.f. ExtentsLayout::new(). Thus in,
                        // summary, the net gain of the single extent shortening operation from
                        // above and any sequence of extents header placement optimization gains,
                        // including the initial placement optimization from above, is always
                        // negative in terms of allocated effective payload.
                        //
                        // Now assume there is some other extent, which can get truncated,
                        // i.e. shrunken by at least one (two to the power of)
                        // min_extent_alignment_allocation_blocks_log2 unit. Note that the current
                        // extent cannot have one more such unit removed, as per the fitting above.
                        // As the difference between that hypothetical and the current extent can only
                        // be due to different alignment paddings, it follows that
                        // we're less than one payload alignment unit
                        // into the max_final_remaining_effective_payload_len realm.
                        //
                        // Overall, in conclusion, it follows that another extent shrinking or
                        // removal would not be affordable without getting outside the
                        // max_final_remaining_effective_payload_len realm again.
                        if updated_shortest_extent_allocation_blocks >= head_extent_min_allocation_blocks {
                            let shortest_extent_extents_hdr_placement_cost = self
                                .request
                                .layout
                                .extents_hdr_placement_cost(updated_shortest_extent_allocation_blocks);
                            // On ties, prefer shorter extents, as in the initial search above.
                            if shortest_extent_extents_hdr_placement_cost <= best_extents_hdr_placement_cost {
                                extents.swap_extents(0, shortest_extent.0);
                                shortest_extent.0 = 0;
                                let gained_effective_payload_len =
                                    best_extents_hdr_placement_cost - shortest_extent_extents_hdr_placement_cost;
                                // The following assignment is dead, but for good measure do it anyway.
                                best_extents_hdr_placement_cost = shortest_extent_extents_hdr_placement_cost;
                                let x = gained_effective_payload_len.min(self.remaining_effective_payload_len());
                                self.allocated_effective_payload_len += x;
                                self.allocated_excess_effective_payload_len += gained_effective_payload_len - x;
                            }
                        }
                        Some((shortest_extent.0, extents.get_extent_range(shortest_extent.0)))
                    } else {
                        Some(shortest_extent)
                    }
                } else {
                    extents.swap_extents(shortest_extent.0, extents.len() - 1);
                    // Conditionally update prev_containing_extent_index to account for the swap.
                    if prev_containing_extent_index == extents.len() - 1 {
                        prev_containing_extent_index = shortest_extent.0
                    }
                    extents.pop_extent();
                    n_extents_removed += 1;
                    None
                }
            } else {
                Some(shortest_extent)
            };

            // If gained_effective_payload_len is still non-zero, proceed with the extent
            // the extents headers got moved away from.
            let shortest_extent_index = if gained_effective_payload_len != 0 {
                let prev_containing_extent_max_effective_payload_len = self
                    .request
                    .layout
                    .extent_effective_payload_len(original_prev_containing_extent_allocation_blocks, false);
                // As all the all the gained effective payload length stems from
                // headers removal from this extent, it is guaranteed that the
                // gain fits into it.
                debug_assert!(gained_effective_payload_len <= prev_containing_extent_max_effective_payload_len);
                // Subtract the gained_effective_payload_len to reflect the actual accounting.
                let prev_containing_extent_used_effective_payload_len =
                    prev_containing_extent_max_effective_payload_len - gained_effective_payload_len;
                let updated_prev_containing_extent_allocation_blocks = self
                    .fit_allocated_extent_to_effective_payload_len(
                        prev_containing_extent_used_effective_payload_len,
                        false,
                        max_final_remaining_effective_payload_len,
                        min_extent_alignment_allocation_blocks_log2,
                    );
                if u64::from(updated_prev_containing_extent_allocation_blocks) != 0 {
                    if updated_prev_containing_extent_allocation_blocks
                        < original_prev_containing_extent_allocation_blocks
                    {
                        let removed = extents.shrink_extent_by(
                            prev_containing_extent_index,
                            original_prev_containing_extent_allocation_blocks
                                - updated_prev_containing_extent_allocation_blocks,
                        );
                        debug_assert!(!removed);
                        let shortest_extent =
                            if updated_prev_containing_extent_allocation_blocks >= head_extent_min_allocation_blocks {
                                // In principle, a shrinking of the extent might have turned it into an even
                                // better choice for the extents header placement, just as in the case of
                                // when attempting to shrink the shortest extent
                                // above. The same comment re the impossiblity of
                                // multiple successive extent shrinkings apply.
                                let updated_prev_containing_extent_extents_hdr_placement_cost = self
                                    .request
                                    .layout
                                    .extents_hdr_placement_cost(updated_prev_containing_extent_allocation_blocks);
                                let cur_best_placement_extent = extents.get_extent_range(0);
                                // Prefer as in in the initial search above (in this order):
                                // a.) extents with a smaller extents header placement cost
                                // b.) shorter extents (so that a potential future truncation
                                //     would free up larger ones),
                                // c.) extents located at smaller positions.
                                if updated_prev_containing_extent_extents_hdr_placement_cost
                                    < best_extents_hdr_placement_cost
                                    || (updated_prev_containing_extent_extents_hdr_placement_cost
                                        == best_extents_hdr_placement_cost
                                        && (updated_prev_containing_extent_allocation_blocks
                                            < cur_best_placement_extent.block_count()
                                            || (updated_prev_containing_extent_allocation_blocks
                                                == cur_best_placement_extent.block_count()
                                                && extents.get_extent_range(prev_containing_extent_index).begin()
                                                    < cur_best_placement_extent.begin())))
                                {
                                    extents.swap_extents(0, prev_containing_extent_index);
                                    let shortest_extent = shortest_extent.map(|shortest_extent| {
                                        let shortest_extent_index = if shortest_extent.0 == 0 {
                                            prev_containing_extent_index
                                        } else {
                                            // No need to handle shortest_extent.0 ==
                                            // prev_containing_extent_index separately, it will be
                                            // caught by the conditional update of shortest_extent
                                            // further below, because the previously containing extent,
                                            // which would then coincide with the shortest extent, did
                                            // get shortened.
                                            debug_assert!(
                                                shortest_extent.0 != prev_containing_extent_index
                                                    || updated_prev_containing_extent_allocation_blocks
                                                        < shortest_extent.1.block_count()
                                            );
                                            shortest_extent.0
                                        };
                                        (shortest_extent_index, shortest_extent.1)
                                    });
                                    prev_containing_extent_index = 0;
                                    let gained_effective_payload_len = best_extents_hdr_placement_cost
                                        - updated_prev_containing_extent_extents_hdr_placement_cost;
                                    let x = gained_effective_payload_len.min(self.remaining_effective_payload_len());
                                    self.allocated_effective_payload_len += x;
                                    self.allocated_excess_effective_payload_len += gained_effective_payload_len - x;
                                    shortest_extent
                                } else {
                                    shortest_extent
                                }
                            } else {
                                shortest_extent
                            };

                        shortest_extent.map(|(shortest_extent_index, shortest_extent)| {
                            // The shrunken extent might now have become the shortest one.
                            let shortest_extent_allocation_blocks = shortest_extent.block_count();
                            if shortest_extent_allocation_blocks > updated_prev_containing_extent_allocation_blocks
                                || (shortest_extent_allocation_blocks
                                    == updated_prev_containing_extent_allocation_blocks
                                    && shortest_extent.begin()
                                        > extents.get_extent_range(prev_containing_extent_index).begin())
                            {
                                prev_containing_extent_index
                            } else {
                                shortest_extent_index
                            }
                        })
                    } else {
                        shortest_extent.map(|(shortest_extent_index, _)| shortest_extent_index)
                    }
                } else {
                    extents.swap_extents(prev_containing_extent_index, extents.len() - 1);
                    extents.pop_extent();
                    n_extents_removed += 1;
                    shortest_extent
                        .map(|(shortest_extent_index, _)| shortest_extent_index)
                        .filter(|shortest_extent_index| *shortest_extent_index != prev_containing_extent_index)
                }
            } else {
                shortest_extent.map(|(shortest_extent_index, _)| shortest_extent_index)
            };

            (n_extents_removed, shortest_extent_index)
        }
    }
}

/// Extent candidate filter queried by
/// [`AllocBitmap::_find_free_fullword_chunks()`] for deciding whether or not
/// some found free extent is eligible to be included in the allocation.
///
/// The intended usecase is to reject too short extent candidates from inclusion
/// in order to limit the total number of extents allocated for serving a
/// given [`ExtentsAllocationRequest`].
trait FindFreeFullwordChunksExtentCandiateFilter {
    /// Invoked whenever some new extent has been added to the allocation.
    fn account_extent_added(&mut self);

    /// Invoked whenever one or more extents have been from the allocation
    /// again.
    ///
    /// For each extent represented in `n_extents_dropped`,
    /// [`account_extent_added()`](Self::account_extent_added) had previously
    /// been invoked.
    fn account_extents_dropped(&mut self, n_extents_dropped: u32);

    /// Update internal accounting state.
    ///
    /// Run potentially costly internal state updates. `update_filter_state()`
    /// is guaranteed to get invoked at least once inbetween a subsequent
    /// [`extent_candidate_acceptable()`](Self::extent_candidate_acceptable) and
    /// any non-zero number of preceding
    /// [`account_extent_added()`](Self::account_extent_added) or
    /// [`account_extents_dropped()`](Self::account_extents_dropped)
    /// invocations.
    ///
    /// # Arguments:
    ///
    /// * `progress` - The current allocation operation's associated
    ///   [`ExtentsAllocationRequestProgress`] tracking.
    /// * `max_subword_extent_effective_payload_len` - The maximum effective
    ///   payload capacity of any extent less than [`BitmapWord::BITS`]
    ///   [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2) in
    ///   length.
    fn update_filter_state(
        &mut self,
        progress: &ExtentsAllocationRequestProgress,
        max_subword_extent_effective_payload_len: u64,
    );

    /// Decide whether or not some found free extent is eligible for inclusion
    /// in the allocation.
    ///
    /// # Arguments:
    ///
    /// * `candidate_extent_allocation_blocks` - The length of the found free
    ///   extent candidate.
    fn extent_candidate_acceptable(&self, candidate_extent_allocation_blocks: layout::AllocBlockCount) -> bool;
}

/// Unconstrained [extent allocation candidate
/// filter](FindFreeFullwordChunksExtentCandiateFilter).
///
/// Any free extent candidates are accepted for inclusion in the allocation.
struct FindFreeFullwordChunksExtentCandidateFilterUnconstrained {}

impl FindFreeFullwordChunksExtentCandiateFilter for FindFreeFullwordChunksExtentCandidateFilterUnconstrained {
    fn account_extent_added(&mut self) {}

    fn account_extents_dropped(&mut self, _n_extents_dropped: u32) {}

    fn update_filter_state(
        &mut self,
        _progress: &ExtentsAllocationRequestProgress,
        _max_subword_extent_effective_payload_len: u64,
    ) {
    }

    fn extent_candidate_acceptable(&self, _candidate_extent_allocation_blocks: layout::AllocBlockCount) -> bool {
        true
    }
}

/// Adaptive [extent allocation candidate
/// filter](FindFreeFullwordChunksExtentCandiateFilter) bounding the total
/// number of extents in an allocation.
///
/// The overall number of extents in an allocation is bounded roughly by the
/// base-2 logarithm (of a fixed fraction) of the request's total effective
/// payload length.
///
/// The filter is adaptive, i.e. candiate extents are accepted or rejected based
/// on whether or not the goal would still be achievable by some assumed
/// worst case extent length distribution after adding the current candidate
/// extent to the already accepted ones.
struct FindFreeFullwordChunksExtentCandidateFilterConstrainExtentsCount {
    budget: u32,
    min_accepted_extent_fullword_blocks: u64,
}

impl FindFreeFullwordChunksExtentCandidateFilterConstrainExtentsCount {
    /// Instantiate.
    ///
    /// # Arguments:
    ///
    /// * `allocation_request` - The [`ExtentsAllocationRequest`] to filter
    ///   candidate extents for.
    fn new(allocation_request: &ExtentsAllocationRequest) -> Self {
        // Try to limit the total number of extents by (adaptively) rejecting too short
        // runs of contiguous free fullword blocks. Many schemes are possible,
        // for example one could fix the upper limit on the number of extents
        // and require that each run is at least the total allocation request
        // size divided by that number in length. However, that would put
        // unreasonably strict constraints on possible chunk length distributions: if
        // the scan happened to find one significantly longer run by chance,
        // then one or more smaller ones could still be accepted while staying
        // within the bounds of the total extent number limit. On the other
        // hand, if the rejection scheme was to accept anything for all but the
        // last extent, no matter how short, then chances are that no suitable free run
        // of sufficient length covering the remaining allocation request size
        // can be found in the last iteration.
        //
        // Thus, a more adaptive approach is chosen here. First of all, the total number
        // of extents is limited to the log2 (rounded up) of the allocation
        // request size, in units of fullword blocks. Over the course of the
        // allocation, a budget of remaining extents is maintained. At any point
        // in time, the minimum acceptable free fullword block run length
        // is determined such that the overall remaining allocation request goal would
        // still be achievable with a worst case configuration of exponentially
        // growing chunks. To be more specific, those exponentially growing
        // chunk lengths in the assumed worst case scenario would correspond
        // (roughly) to the set bits in the remaining allocation request size
        // each. In particular the maximum imposed lower bound would be less or equal to
        // roughly half the remaining allocation request size.
        let mut budget = if allocation_request.total_effective_payload_len != 1 {
            (allocation_request.total_effective_payload_len - 1).ilog2() + 1
        } else {
            0
        } + 1;
        let fullword_block_len_log2 =
            allocation_request.layout.allocation_block_size_128b_log2 as u32 + 7 + BITMAP_WORD_BITS_LOG2;
        budget = budget.max(fullword_block_len_log2 + 1) - fullword_block_len_log2;

        Self {
            budget,
            min_accepted_extent_fullword_blocks: 1,
        }
    }
}

impl FindFreeFullwordChunksExtentCandiateFilter for FindFreeFullwordChunksExtentCandidateFilterConstrainExtentsCount {
    fn account_extent_added(&mut self) {
        // In case the maximum extent length is constrained by the request, we might
        // run out of budget early.
        self.budget = self.budget.wrapping_sub(1)
    }

    fn account_extents_dropped(&mut self, n_extents_dropped: u32) {
        // One or more extents got removed from the allocation again (because
        // they got e.g. absorbed into subsequently found larger ones),
        // revive the associated budget tickets, but only if the budget
        // had not dropped to zero in the meanwhile.
        if self.budget == 0 {
            return;
        }
        self.budget += n_extents_dropped;
    }

    fn update_filter_state(
        &mut self,
        progress: &ExtentsAllocationRequestProgress,
        max_subword_extent_effective_payload_len: u64,
    ) {
        debug_assert!(
            max_subword_extent_effective_payload_len
                < (BitmapWord::BITS as u64) << (progress.request.layout.allocation_block_size_128b_log2 + 7)
        );
        let remaining_effective_payload_len = progress.remaining_effective_payload_len();
        debug_assert!(remaining_effective_payload_len > max_subword_extent_effective_payload_len);

        // Split off the maximum effective payload len amount which would fit a
        // sub-bitmap word allocation for the accounting that follows below.
        // If, after aligning upwards, the fullwords allocation extends into that,
        // good; if not, a subsequent subword allocation search will take care of it.
        let remaining_effective_payload_len =
            remaining_effective_payload_len - max_subword_extent_effective_payload_len;

        // In case of an user-specified upper bound on the allocation_request's
        // max_extent_allocation_blocks, the budget might get exhausted prematurely, due
        // to the cap. Accept only extents of maximum length then.
        if self.budget == 0 {
            // If the budget has been exhausted, then this cannot be the first allocation.
            debug_assert_ne!(progress.allocated_effective_payload_len, 0);
            let remaining_request_max_extent_allocation_blocks = progress
                .request
                .layout
                .extent_payload_len_to_allocation_blocks(remaining_effective_payload_len, false)
                .0;
            let remaining_request_max_extent_allocation_blocks = remaining_request_max_extent_allocation_blocks.min(
                progress
                    .request
                    .layout
                    .max_extent_allocation_blocks
                    .align_down(BITMAP_WORD_BITS_LOG2),
            );
            // The imposed upper bound of max_extent_allocation_blocks is aligned, so
            // rounding up would not overflow.
            let remaining_request_max_extent_allocation_blocks =
                u64::from(remaining_request_max_extent_allocation_blocks)
                    .round_up_pow2_unchecked(BITMAP_WORD_BITS_LOG2);
            self.min_accepted_extent_fullword_blocks =
                remaining_request_max_extent_allocation_blocks >> BITMAP_WORD_BITS_LOG2;
            return;
        }

        let is_first = progress.allocated_effective_payload_len == 0;

        // First step: allocate the remaining "budget tickets" to the individual
        // positions in remaining_fullword_blocks.
        // - First allocate to all set bits in remaining_fullword_blocks, from most to
        //   least significant bits.
        // - Then fill up the unset bits in remaining_fullword_blocks, from most to
        //   least significant, until the budget is exhausted.
        // Note that the only thing that matters is the least signifcant bit position
        // with a "budget ticket" allocated to it, c.f. the second step below. So handle
        // three different cases, of increasing computational cost:
        // 1. The distance between the most and the least significant bits in
        //    remaining_fullword_blocks is less than the budget: in this case all set
        //    bits as well as the unset ones interspersed inbetween will receive a
        //    "budget ticket". The least significant bit receiving a "budget ticket"
        //    allocation will be located at or to the right of the least significant bit
        //    in remaining_fullword_blocks and can be computed directly.
        // 2. The number of set bits in remaining_fullword_blocks is less or equal to
        //    the budget: in this case, all set bits will have a "budget ticket"
        //    allocated to them, but not all their separating unset bits. The least
        //    significant bit receiving a "budget ticket" allocation will be indentical
        //    to the least significant set bit in remaining_fullword_blocks.
        // 3. In the remaining case, there are fewer budget tickets than set bits in
        //    remaining_fullword_blocks. Allocate them from most to least significant
        //    bits.
        let remaining_fullword_blocks = (remaining_effective_payload_len
            >> (progress.request.layout.allocation_block_size_128b_log2 as u32 + 7)
            >> BITMAP_WORD_BITS_LOG2)
            .max(1);
        let remaining_fullword_blocks_lsb = remaining_fullword_blocks & remaining_fullword_blocks.wrapping_neg();
        let remaining_fullword_blocks_lsb_log2 = remaining_fullword_blocks_lsb.ilog2();
        let budget_allocation_mask = if remaining_fullword_blocks_lsb_log2 + self.budget >= u64::BITS
            || remaining_fullword_blocks_lsb << self.budget > remaining_fullword_blocks
        {
            // Case 1.)
            1u64 << (remaining_fullword_blocks.ilog2().saturating_sub(self.budget - 1))
        } else if self.budget >= remaining_fullword_blocks.count_ones() {
            // Case 2.)
            remaining_fullword_blocks_lsb
        } else {
            // Case 3.)
            // Create a left aligned contiguous chunk of budget set bits and
            // scatter that over the set bits in remaining_fullword_blocks, starting
            // from the left.
            let budget_pool = !(u64::trailing_bits_mask(u64::BITS - self.budget));
            budget_pool.expand_from_left(remaining_fullword_blocks)
        };

        // Second step: determine the minimum acceptable fullword block run length from
        // the least significant bit that received a "budget ticket"
        // allocation to it. Require that the minimum fullword block run
        // will have sufficient length to accomodate for at least the modulo
        // of the remaining allocation request length by twice that least significant
        // bit. That is, if a run length of exactly that minimum length
        // would have been accepted, all the bits at and to the right of
        // this least significant bit position in
        // remaining_effective_payload_len would become clear thereafter.
        // Convert the mask from units of fullword blocks to bytes:
        let budget_allocation_mask = budget_allocation_mask
            << (progress.request.layout.allocation_block_size_128b_log2 + 7)
            << BITMAP_WORD_BITS_LOG2;
        let budget_allocation_mask = if budget_allocation_mask != 0 {
            // Set all bits at and to the right of the least significant bit, clear anything
            // above:
            budget_allocation_mask ^ (budget_allocation_mask - 1)
        } else {
            !0
        };
        let min_accepted_extent_effective_payload_len = remaining_effective_payload_len & budget_allocation_mask;
        // As an additional constraint to avoid an excessive number of small extents for
        // certain values of remaining_effective_payload_len with a longer
        // sequence of zeros towards the tail, require that the minimum is
        // at least equal to the least significant bit with a
        // "budget ticket" allocated to it. Isolate the LSB:
        let budget_allocation_mask_lsb = budget_allocation_mask & budget_allocation_mask.wrapping_neg();
        let min_accepted_extent_effective_payload_len = min_accepted_extent_effective_payload_len
            .max(budget_allocation_mask_lsb)
            .min(remaining_effective_payload_len);

        let min_accepted_extent_allocation_blocks = progress
            .request
            .layout
            .extent_payload_len_to_allocation_blocks(min_accepted_extent_effective_payload_len, is_first)
            .0;
        let min_accepted_extent_allocation_blocks = u64::from(min_accepted_extent_allocation_blocks);
        let min_accepted_extent_allocation_blocks = min_accepted_extent_allocation_blocks.min(
            u64::from(progress.request.layout.max_extent_allocation_blocks).round_down_pow2(BITMAP_WORD_BITS_LOG2),
        );
        // The imposed upper bound of max_extent_allocation_blocks is aligned, so
        // rounding up would not overflow.
        let min_accepted_extent_allocation_blocks =
            min_accepted_extent_allocation_blocks.round_up_pow2_unchecked(BITMAP_WORD_BITS_LOG2);
        self.min_accepted_extent_fullword_blocks = min_accepted_extent_allocation_blocks >> BITMAP_WORD_BITS_LOG2;
    }

    fn extent_candidate_acceptable(&self, candidate_extent_allocation_blocks: layout::AllocBlockCount) -> bool {
        u64::from(candidate_extent_allocation_blocks) >> BITMAP_WORD_BITS_LOG2
            >= self.min_accepted_extent_fullword_blocks
    }
}

/// In-memory representation of the filesystem instance's allocation bitmap.
pub struct AllocBitmap {
    pub(super) bitmap: Vec<BitmapWord>,
}

impl AllocBitmap {
    /// Instantiate an [`AllocBitmap`] initialized to all `false`.
    ///
    /// # Arguments:
    ///
    /// `image_allocation_blocks` - Total number of [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2) to track.
    pub fn new(image_allocation_blocks: layout::AllocBlockCount) -> Result<Self, NvFsError> {
        if u64::from(image_allocation_blocks) == 0 {
            return Ok(Self { bitmap: Vec::new() });
        }

        let bitmap_words = ((u64::from(image_allocation_blocks) - 1) >> BITMAP_WORD_BITS_LOG2) + 1;
        let bitmap_words = usize::try_from(bitmap_words).map_err(|_| NvFsError::DimensionsNotSupported)?;

        let bitmap = try_alloc_vec(bitmap_words)?;
        Ok(Self { bitmap })
    }

    /// Resize an [`AllocBitmap`].
    ///
    /// Any new entries added will get initialized with `false`.
    ///
    /// # Arguments:
    ///
    /// `image_allocation_blocks` - Updated total number of [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2) to track.
    pub fn resize(&mut self, image_allocation_blocks: layout::AllocBlockCount) -> Result<(), NvFsError> {
        if u64::from(image_allocation_blocks) == 0 {
            self.bitmap = Vec::new();
            return Ok(());
        }

        let bitmap_words = ((u64::from(image_allocation_blocks) - 1) >> BITMAP_WORD_BITS_LOG2) + 1;
        let bitmap_words = usize::try_from(bitmap_words).map_err(|_| NvFsError::DimensionsNotSupported)?;

        if bitmap_words < self.bitmap.len() {
            self.bitmap.truncate(bitmap_words);
            let bits_in_last_bitmap_word = u64::BITS
                - ((u64::from(image_allocation_blocks).wrapping_neg() & u64::trailing_bits_mask(BITMAP_WORD_BITS_LOG2))
                    as u32);
            self.bitmap[bitmap_words - 1] &= u64::trailing_bits_mask(bits_in_last_bitmap_word);
        } else {
            let prev_bitmap_words = self.bitmap.len();
            self.bitmap.try_reserve_exact(bitmap_words - prev_bitmap_words)?;
            self.bitmap.resize(bitmap_words, 0 as BitmapWord);
        }
        Ok(())
    }

    /// Iterate over individual [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2), starting
    /// at a specified position.
    ///
    /// # Arguments:
    ///
    ///  * `pending_allocs` - Pending allocations to apply virtually on top of
    ///    the state as currently found in the [`AllocBitmap`] for the purpose
    ///    of the iteration.
    ///  * `pending_frees` - Pending frees to apply virtually on top of the
    ///    state as currently found in the [`AllocBitmap`] for the purpose of
    ///    the iteration.
    ///  * `first_physical_allocation_block_index` - Starting position of the
    ///    returned iterator.
    pub fn iter_at_allocation_block<'a, const AN: usize, const FN: usize>(
        &'a self,
        pending_allocs: &'a SparseAllocBitmapUnion<'_, AN>,
        pending_frees: &'a SparseAllocBitmapUnion<'_, FN>,
        first_physical_allocation_block_index: layout::PhysicalAllocBlockIndex,
    ) -> AllocBitmapIterator<'a, AN, FN> {
        AllocBitmapIterator::new_at(
            self,
            pending_allocs,
            pending_frees,
            first_physical_allocation_block_index,
        )
    }

    /// Iterate over chunks of [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2), starting
    /// at a specified position.
    ///
    /// Iterate over the [`AllocBitmap`] in fixed chunks of a specified number
    /// of [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2) each, as
    /// specified by `chunk_allocation_blocks`.
    /// `chunk_allocation_blocks` must not exceed [`BitmapWord::BITS`] and the
    /// iterator returns [`BitmapWord`]s, one at a time, with the lower
    /// `chunk_allocation_blocks` bits representing the allocation status of
    /// each [Allocation
    /// Block](layout::ImageLayout::allocation_block_size_128b_log2) in the
    /// current chunk.
    ///
    /// # Arguments:
    ///
    ///  * `pending_allocs` - Pending allocations to apply virtually on top of
    ///    the state as currently found in the [`AllocBitmap`] for the purpose
    ///    of the iteration.
    ///  * `pending_frees` - Pending frees to apply virtually on top of the
    ///    state as currently found in the [`AllocBitmap`] for the purpose of
    ///    the iteration.
    ///  * `first_physical_allocation_block_index` - Starting position of the
    ///    returned iterator.
    ///  * `chunk_allocation_blocks` - Iteration chunk size in units of
    ///    [Allocation
    ///    Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    pub fn iter_chunked_at_allocation_block<'a, const AN: usize, const FN: usize>(
        &'a self,
        pending_allocs: &'a SparseAllocBitmapUnion<'_, AN>,
        pending_frees: &'a SparseAllocBitmapUnion<'_, FN>,
        first_physical_allocation_block_index: layout::PhysicalAllocBlockIndex,
        chunk_allocation_blocks: u32,
    ) -> AllocBitmapChunkedIterator<'a, AN, FN> {
        AllocBitmapChunkedIterator::new_at(
            self,
            pending_allocs,
            pending_frees,
            first_physical_allocation_block_index,
            chunk_allocation_blocks,
        )
    }

    /// Apply pending allocations or deallocations to the [`AllocBitmap`].
    ///
    /// # Arguments:
    ///
    /// * `pending` - The set of pending allocations or deallocations, with a
    ///   bit set for each member in the set.
    /// * `is_free` - `true` if `pending` is to get applied as a deallocation,
    ///   `false` if as an allocation.
    pub fn apply_pending(&mut self, pending: &SparseAllocBitmap, is_free: bool) -> Result<(), NvFsError> {
        if !is_free {
            for (allocation_blocks_begin, bitmap_word) in pending.iter() {
                let bitmap_word_index = usize::try_from(u64::from(allocation_blocks_begin) >> BITMAP_WORD_BITS_LOG2)
                    .map_err(|_| nvfs_err_internal!())?;
                self.bitmap[bitmap_word_index] |= bitmap_word;
            }
        } else {
            for (allocation_blocks_begin, bitmap_word) in pending.iter() {
                let bitmap_word_index = usize::try_from(u64::from(allocation_blocks_begin) >> BITMAP_WORD_BITS_LOG2)
                    .map_err(|_| nvfs_err_internal!())?;
                self.bitmap[bitmap_word_index] &= !bitmap_word;
            }
        }
        Ok(())
    }

    /// Set the bits in a range to a specified value.
    ///
    /// # Arguments:
    ///
    /// * `range` - The range to set the correspinding [`AllocBitmap`] bits for.
    /// * `value` - The value to set the specified `range`'s corresponding bits
    ///   to.
    pub fn set_in_range(&mut self, range: &layout::PhysicalAllocBlockRange, value: bool) -> Result<(), NvFsError> {
        let mut physical_allocation_block_count = u64::from(range.block_count());
        let first_physical_allocation_block_index = u64::from(range.begin());
        let bitmap_word_index_begin = first_physical_allocation_block_index >> BITMAP_WORD_BITS_LOG2;
        let mut offset_in_bitmap_word =
            (first_physical_allocation_block_index & u64::trailing_bits_mask(BITMAP_WORD_BITS_LOG2)) as u32;

        let bitmap_word_index_end = ((u64::from(range.end()) - 1) >> BITMAP_WORD_BITS_LOG2) + 1;
        let mut bitmap_word_index_end =
            usize::try_from(bitmap_word_index_end).map_err(|_| NvFsError::IoError(NvFsIoError::RegionOutOfRange))?;
        if bitmap_word_index_end > self.bitmap.len() {
            if value {
                return Err(NvFsError::IoError(NvFsIoError::RegionOutOfRange));
            } else {
                // The BitmapWord's beyond the end of the Allocation Bitmap are all implicitly
                // considered unset already. Modify only what's allocated.
                bitmap_word_index_end = self.bitmap.len();
                if bitmap_word_index_begin >= bitmap_word_index_end as u64 {
                    return Ok(());
                }
            }
        }
        let bitmap_word_index_begin = bitmap_word_index_begin as usize;

        let set_mask = if value { !0 } else { 0 };
        for bitmap_word_index in bitmap_word_index_begin..bitmap_word_index_end {
            let bits_in_word =
                physical_allocation_block_count.min((BitmapWord::BITS - offset_in_bitmap_word) as u64) as u32;
            let bits_in_word_mask = BitmapWord::trailing_bits_mask(bits_in_word) << offset_in_bitmap_word;
            self.bitmap[bitmap_word_index] &= !bits_in_word_mask;
            self.bitmap[bitmap_word_index] |= set_mask & bits_in_word_mask;
            physical_allocation_block_count -= bits_in_word as u64;
            offset_in_bitmap_word = 0;
        }

        Ok(())
    }

    /// Find a free aligned block of specified size.
    ///
    /// Find a free block of size as specified by
    /// `block_allocation_blocks_log2`, and aligned to that size.
    ///
    /// If needed, the search might return some subblock of a larger containing
    /// free block, but it tries to avoid that as much as possible in order
    /// to not unnecessarily split up such larger free blocks and to reduce
    /// fragmentation.
    ///
    /// # Arguments:
    ///
    ///  * `block_allocation_blocks_log2` - Base-2 logarithm of the free block's
    ///    size and alignment in units of [Allocation
    ///    Blocks](layout::ImageLayout::allocation_block_size_128b_log2). Must
    ///    be less than or equal to [`BitmapWord::BITS`].
    ///  * `allocated_fullword_chunks` - List of extents to consider virtually
    ///    as having been allocated, independent of the current state in the
    ///    [`AllocBitmap`].
    ///  * `pending_allocs` - Pending allocations to apply virtually on top of
    ///    the state as currently found in the [`AllocBitmap`].
    ///  * `pending_frees` - Pending frees to apply virtually on top of the
    ///    state as currently found in the [`AllocBitmap`].
    ///  * `image_size` - The filesystem image size. No [Allocation
    ///    Block](layout::ImageLayout::allocation_block_size_128b_log2) beyond
    ///    it will be considered for the allocation.
    pub fn find_free_block<const AN: usize, const FN: usize>(
        &self,
        block_allocation_blocks_log2: u32,
        mut allocated_fullword_chunks: Option<&extents::PhysicalExtents>,
        pending_allocs: &SparseAllocBitmapUnion<'_, AN>,
        pending_frees: &SparseAllocBitmapUnion<'_, FN>,
        image_size: layout::AllocBlockCount,
    ) -> Option<layout::PhysicalAllocBlockIndex> {
        let block_allocations_blocks = 1u32 << block_allocation_blocks_log2;
        debug_assert!(block_allocations_blocks <= BitmapWord::BITS);
        if block_allocations_blocks == BitmapWord::BITS {
            return self.find_free_fullword_block(allocated_fullword_chunks, pending_allocs, pending_frees, image_size);
        }

        // The addition does not overflow, image_size is in units of Allocation Blocks,
        // and has at least the upper 7 Bits clear.
        let image_bitmap_words = (u64::from(image_size) + (u64::BITS as u64 - 1)) >> BITMAP_WORD_BITS_LOG2;

        let word_blocks_lsbs_mask_table = BitmapWordBlocksLsbsMaskTable::new();
        let word_blocks_lsbs_mask = word_blocks_lsbs_mask_table.get_blocks_lsbs_mask(block_allocation_blocks_log2);
        let bitmaps_words_iter =
            AllocBitmapWordIterator::new_at_bitmap_word_index(self, pending_allocs, pending_frees, 0);
        let mut next_allocated_fullword_chunk: Option<layout::PhysicalAllocBlockRange> = None;
        struct FoundCandidate {
            bitmap_word_index: u64,
            bitmap_word: BitmapWord,
            split_block_allocation_blocks_log2: u32, // Minimize.
        }
        let mut best: Option<FoundCandidate> = None;
        for (bitmap_word_index, mut bitmap_word) in
            bitmaps_words_iter.take(usize::try_from(image_bitmap_words).unwrap_or(usize::MAX))
        {
            if bitmap_word_index + 1 == image_bitmap_words {
                // Set the excess high bits not backed by any actual storage.
                bitmap_word |= !BitmapWord::trailing_bits_mask(
                    BitmapWord::BITS - ((u64::from(image_size).wrapping_neg() & (BitmapWord::BITS as u64 - 1)) as u32),
                );
            }

            // Don't bother examining any further if all allocation blocks tracked by this
            // word are allocated already anyway.
            if bitmap_word == !0 {
                continue;
            }

            if bitmap_word == 0 {
                if best.is_none() {
                    // Check if the bitmap word is really free or has perhaps been previously
                    // allocated as part of a preceeding fullword chunks allocation
                    // round for processing the very same request.
                    next_allocated_fullword_chunk = next_allocated_fullword_chunk
                        .filter(|next_allocated_fullword_chunk| {
                            u64::from(next_allocated_fullword_chunk.end()) >> BITMAP_WORD_BITS_LOG2 > bitmap_word_index
                        })
                        .or_else(|| {
                            allocated_fullword_chunks
                                .map(|e| e.iter())
                                .into_iter()
                                .flatten()
                                .filter(|e| u64::from(e.end()) >> BITMAP_WORD_BITS_LOG2 > bitmap_word_index)
                                .min_by_key(|e| e.end())
                        });
                    if let Some(next_allocated_fullword_chunk) = next_allocated_fullword_chunk {
                        if u64::from(next_allocated_fullword_chunk.begin()) >> BITMAP_WORD_BITS_LOG2
                            <= bitmap_word_index
                        {
                            continue;
                        }
                    } else {
                        // No more extents at or after the current position, avoid another search..
                        allocated_fullword_chunks = None;
                    }

                    best = Some(FoundCandidate {
                        bitmap_word_index,
                        bitmap_word,
                        split_block_allocation_blocks_log2: BITMAP_WORD_BITS_LOG2,
                    });
                }
                continue;
            }

            let free_blocks_lsbs =
                Self::bitmap_word_free_blocks_lsbs(bitmap_word, block_allocation_blocks_log2, word_blocks_lsbs_mask);
            if free_blocks_lsbs == 0 {
                continue;
            }

            // It is possible to allocate the block from the range tracked by the current
            // word. See if it is the best candidate: determine the minimum
            // power-of-two sized block the allocation would split, if any, and
            // minimize that.
            let split_block_allocation_blocks_log2 = Self::bitmap_word_block_alloc_split_block_size_log2(
                free_blocks_lsbs,
                best.as_ref().map(
                    |FoundCandidate {
                         split_block_allocation_blocks_log2,
                         ..
                     }| {
                        debug_assert!(*split_block_allocation_blocks_log2 > block_allocation_blocks_log2);
                        *split_block_allocation_blocks_log2
                    },
                ),
                block_allocation_blocks_log2,
                word_blocks_lsbs_mask,
                &word_blocks_lsbs_mask_table,
            );

            if split_block_allocation_blocks_log2 == block_allocation_blocks_log2 {
                // It's a perfect fit.
                return Some(layout::PhysicalAllocBlockIndex::from(
                    bitmap_word_index * BitmapWord::BITS as u64
                        + Self::bitmap_word_block_alloc_select_block(
                            free_blocks_lsbs,
                            block_allocation_blocks_log2,
                            word_blocks_lsbs_mask,
                            &word_blocks_lsbs_mask_table,
                        ) as u64,
                ));
            } else if best
                .as_ref()
                .map(
                    |FoundCandidate {
                         split_block_allocation_blocks_log2: best_split_block_allocations_block_log2,
                         ..
                     }| {
                        *best_split_block_allocations_block_log2 > split_block_allocation_blocks_log2
                    },
                )
                .unwrap_or(true)
            {
                best = Some(FoundCandidate {
                    bitmap_word_index,
                    bitmap_word,
                    split_block_allocation_blocks_log2,
                });
            }
        }

        if let Some(FoundCandidate {
            bitmap_word_index,
            bitmap_word,
            split_block_allocation_blocks_log2,
        }) = best
        {
            let word_split_blocks_lsbs_mask =
                word_blocks_lsbs_mask_table.get_blocks_lsbs_mask(split_block_allocation_blocks_log2);
            let mut free_split_blocks_lsbs = Self::bitmap_word_free_blocks_lsbs(
                bitmap_word,
                split_block_allocation_blocks_log2,
                word_split_blocks_lsbs_mask,
            );
            if split_block_allocation_blocks_log2 < BITMAP_WORD_BITS_LOG2 - 1 {
                let double_split_block_allocations_block_log2 = split_block_allocation_blocks_log2 + 1;
                let word_double_split_blocks_lsbs_mask =
                    word_blocks_lsbs_mask_table.get_blocks_lsbs_mask(double_split_block_allocations_block_log2);
                free_split_blocks_lsbs = Self::bitmap_word_filter_blocks_with_free_buddy_lsbs(
                    free_split_blocks_lsbs,
                    free_split_blocks_lsbs,
                    split_block_allocation_blocks_log2,
                    word_double_split_blocks_lsbs_mask,
                );
            }
            debug_assert_ne!(free_split_blocks_lsbs, 0);
            Some(layout::PhysicalAllocBlockIndex::from(
                bitmap_word_index * BitmapWord::BITS as u64
                    + Self::bitmap_word_block_alloc_select_block(
                        free_split_blocks_lsbs,
                        split_block_allocation_blocks_log2,
                        word_split_blocks_lsbs_mask,
                        &word_blocks_lsbs_mask_table,
                    ) as u64,
            ))
        } else {
            None
        }
    }

    /// Find free [extents](extents::PhysicalExtents).
    ///
    /// Find free [extents](extents::PhysicalExtents) for serving the
    /// `allocation_request`.
    ///
    /// On success, a pair of the found extents and the amount of excess payload
    /// space is being returned.
    ///
    /// The [common extents header](ExtentsLayout::extents_hdr_len), if any, is
    /// expected to get placed into the first extent of the returned
    /// sequence.
    ///
    /// # Arguments:
    ///
    ///  * `allocation_request` - The allocation request parameters, the desired
    ///    total effective payload length as well as the [`ExtentsLayout`] to be
    ///    more specific.
    ///  * `pending_allocs` - Pending allocations to apply virtually on top of
    ///    the state as currently found in the [`AllocBitmap`].
    ///  * `pending_frees` - Pending frees to apply virtually on top of the
    ///    state as currently found in the [`AllocBitmap`].
    ///  * `image_size` - The filesystem image size. No [Allocation
    ///    Block](layout::ImageLayout::allocation_block_size_128b_log2) beyond
    ///    it will be considered for the allocation.
    pub fn find_free_extents<const AN: usize, const FN: usize>(
        &self,
        allocation_request: &ExtentsAllocationRequest,
        pending_allocs: &SparseAllocBitmapUnion<'_, AN>,
        pending_frees: &SparseAllocBitmapUnion<'_, FN>,
        image_size: layout::AllocBlockCount,
    ) -> Result<Option<(extents::PhysicalExtents, u64)>, NvFsError> {
        debug_assert!(
            allocation_request.layout.extent_alignment_allocation_blocks_log2 as u32 <= BITMAP_WORD_BITS_LOG2
        );

        if allocation_request.total_effective_payload_len == 0 {
            return Ok(Some((extents::PhysicalExtents::new(), 0)));
        }
        let (max_first_extent_allocation_blocks, max_first_extent_is_exhaustive) =
            allocation_request.remaining_max_extent_allocation_blocks(0);
        debug_assert_ne!(u64::from(max_first_extent_allocation_blocks), 0);

        if max_first_extent_is_exhaustive && u64::from(max_first_extent_allocation_blocks) < 2 * BitmapWord::BITS as u64
        {
            let total_allocated_effective_payload_len = allocation_request
                .layout
                .extent_effective_payload_len(max_first_extent_allocation_blocks, true);
            let allocated_excess_effective_payload_len =
                total_allocated_effective_payload_len - allocation_request.total_effective_payload_len;

            if u64::from(max_first_extent_allocation_blocks) <= BitmapWord::BITS as u64 {
                return match self.find_free_subword_chunk(
                    u64::from(max_first_extent_allocation_blocks) as u32,
                    allocation_request.layout.extent_alignment_allocation_blocks_log2 as u32,
                    None,
                    pending_allocs,
                    pending_frees,
                    image_size,
                ) {
                    Some(extent_allocation_blocks_begin) => {
                        let extent = layout::PhysicalAllocBlockRange::from((
                            extent_allocation_blocks_begin,
                            max_first_extent_allocation_blocks,
                        ));
                        let mut extents = extents::PhysicalExtents::new();
                        extents.push_extent(&extent, true)?;
                        Ok(Some((extents, allocated_excess_effective_payload_len)))
                    }
                    None => Ok(None),
                };
            } else if let Some(extent_allocation_blocks_begin) = self.find_free_sub_doubleword_chunk(
                u64::from(max_first_extent_allocation_blocks) as u32,
                pending_allocs,
                pending_frees,
                image_size,
            ) {
                let extent = layout::PhysicalAllocBlockRange::from((
                    extent_allocation_blocks_begin,
                    max_first_extent_allocation_blocks,
                ));
                let mut extents = extents::PhysicalExtents::new();
                extents.push_extent(&extent, true)?;
                return Ok(Some((extents, allocated_excess_effective_payload_len)));
            }
        }

        let (head_extent_min_allocation_blocks, tail_extent_min_allocation_blocks) =
            allocation_request.layout.min_extents_allocation_blocks();

        if u64::from(allocation_request.layout.max_extent_allocation_blocks) >= BitmapWord::BITS as u64 {
            let (mut progress, mut extents) = match self.find_free_fullword_chunks(
                allocation_request,
                pending_allocs,
                pending_frees,
                image_size,
                head_extent_min_allocation_blocks,
                tail_extent_min_allocation_blocks,
            )? {
                Some(result) => result,
                None => return Ok(None),
            };
            let remaining_effective_payload_len = progress.remaining_effective_payload_len();
            if remaining_effective_payload_len != 0 {
                let remainder_extent_allocation_blocks = progress
                    .request
                    .layout
                    .extent_payload_len_to_allocation_blocks(remaining_effective_payload_len, false)
                    .0;
                debug_assert!(u64::from(remainder_extent_allocation_blocks) < BitmapWord::BITS as u64);
                let remainder_extent = match self.find_free_subword_chunk(
                    u64::from(remainder_extent_allocation_blocks) as u32,
                    allocation_request.layout.extent_alignment_allocation_blocks_log2 as u32,
                    Some(&extents),
                    pending_allocs,
                    pending_frees,
                    image_size,
                ) {
                    Some(remainder_extent_allocation_blocks_begin) => layout::PhysicalAllocBlockRange::from((
                        remainder_extent_allocation_blocks_begin,
                        remainder_extent_allocation_blocks,
                    )),
                    None => return Ok(None),
                };
                extents.push_extent(&remainder_extent, true)?;
                let remainder_extent_effective_payload_len = allocation_request
                    .layout
                    .extent_effective_payload_len(remainder_extent_allocation_blocks, false);
                debug_assert_eq!(progress.allocated_excess_effective_payload_len, 0);
                progress.allocated_effective_payload_len += remaining_effective_payload_len;
                debug_assert_eq!(
                    progress.allocated_effective_payload_len,
                    allocation_request.total_effective_payload_len
                );
                progress.allocated_excess_effective_payload_len =
                    remainder_extent_effective_payload_len - remaining_effective_payload_len;
            }

            Ok(Some((extents, progress.allocated_excess_effective_payload_len)))
        } else {
            // The request's maxium allowed extent size is less than what's covered by a
            // fullword block. The overall strategy is to allocate (mostly)
            // fullword block extents and split all extents up as is necessary
            // afterwards.
            debug_assert!(u64::from(max_first_extent_allocation_blocks) < u64::BITS as u64);
            debug_assert!(!max_first_extent_is_exhaustive);

            // First, try to make the maximum extent length a power of two so that it
            // would evenly divide a fullword block extent.
            let max_extent_allocation_blocks = layout::AllocBlockCount::from(
                u64::from(allocation_request.layout.max_extent_allocation_blocks).round_down_next_pow2(),
            );

            if max_extent_allocation_blocks >= head_extent_min_allocation_blocks
                && max_extent_allocation_blocks >= tail_extent_min_allocation_blocks
            {
                // Determine how many of such extents of maximum size are needed
                // for satisfying the request. The remainder, if any, will get handled
                // below.
                let max_first_extent_effective_payload_len = allocation_request
                    .layout
                    .extent_effective_payload_len(max_extent_allocation_blocks, true);
                debug_assert!(max_first_extent_effective_payload_len < allocation_request.total_effective_payload_len);
                let max_tail_extent_effective_payload_len = allocation_request
                    .layout
                    .extent_effective_payload_len(max_extent_allocation_blocks, false);
                let n_max_extents = 1
                    + ((allocation_request.total_effective_payload_len - max_first_extent_effective_payload_len)
                        / max_tail_extent_effective_payload_len);
                // Compute the remainder to be allocated in an extent strictly smaller than the
                // maximum.
                let remainder_extent_min_effective_payload_len = allocation_request.total_effective_payload_len
                    - max_first_extent_effective_payload_len
                    - (n_max_extents - 1) * max_tail_extent_effective_payload_len;
                let remainder_extent_allocation_blocks = allocation_request
                    .layout
                    .extent_payload_len_to_allocation_blocks(remainder_extent_min_effective_payload_len, false)
                    .0;
                // All the allocated excess comes from this remainder extent, compute it now.
                let remainder_extent_allocated_effective_payload_len = allocation_request
                    .layout
                    .extent_effective_payload_len(remainder_extent_allocation_blocks, false);
                let allocated_excess_effective_payload_len =
                    remainder_extent_allocated_effective_payload_len - remainder_extent_min_effective_payload_len;

                // Now determine how many Allocation Blocks need to get allocated in total.
                let total_allocation_blocks = n_max_extents
                    .checked_mul(u64::from(max_extent_allocation_blocks))
                    .ok_or(NvFsError::DimensionsNotSupported)?;
                let total_allocation_blocks = total_allocation_blocks
                    .checked_add(u64::from(remainder_extent_allocation_blocks))
                    .ok_or(NvFsError::DimensionsNotSupported)?;
                if total_allocation_blocks
                    >> (u64::BITS - allocation_request.layout.allocation_block_size_128b_log2 as u32 - 7)
                    != 0
                {
                    return Err(NvFsError::DimensionsNotSupported);
                }

                // Allocate as many of the total Allocation Blocks to allocate in chunks of
                // (multiples of) fullword blocks, the remainder will get handled in
                // a single subword chunk allocation below.
                let fullwords_extents_allocation_blocks =
                    total_allocation_blocks.round_down_pow2(BITMAP_WORD_BITS_LOG2);
                let subword_extent_allocation_blocks = total_allocation_blocks - fullwords_extents_allocation_blocks;
                debug_assert!(
                    (allocation_request.layout.extent_alignment_allocation_blocks_log2 as u32) < BITMAP_WORD_BITS_LOG2
                );
                // Create a trivial dummy layout for the fullword allocations -- the original
                // request layout's header lengths, payload alignment and such had
                // already been accounted for when calculating the needed number of
                // extents of maximum size (n_max_extents), as well as the remainder
                // (tail_extent_allocation_blocks) above.
                let trivial_fullwords_extents_layout = ExtentsLayout::new(
                    None,
                    BITMAP_WORD_BITS_LOG2 as u8,
                    0,
                    0,
                    0,
                    1,
                    allocation_request.layout.allocation_block_size_128b_log2,
                )?;
                let fullwords_allocation_request = ExtentsAllocationRequest::new(
                    fullwords_extents_allocation_blocks << (allocation_request.layout.allocation_block_size_128b_log2),
                    &trivial_fullwords_extents_layout,
                );
                let fullwords_allocation_result = self.find_free_fullword_chunks(
                    &fullwords_allocation_request,
                    pending_allocs,
                    pending_frees,
                    image_size,
                    layout::AllocBlockCount::from(BitmapWord::BITS as u64),
                    layout::AllocBlockCount::from(BitmapWord::BITS as u64),
                )?;
                let mut unconstrained_extents = match fullwords_allocation_result {
                    Some((fullwords_allocation_progress, unconstrained_extents)) => {
                        debug_assert_eq!(fullwords_allocation_progress.remaining_effective_payload_len(), 0);
                        debug_assert_eq!(fullwords_allocation_progress.allocated_excess_effective_payload_len, 0);
                        unconstrained_extents
                    }
                    None => return Ok(None),
                };
                if subword_extent_allocation_blocks != 0 {
                    let subword_extent = match self.find_free_subword_chunk(
                        subword_extent_allocation_blocks as u32,
                        allocation_request.layout.extent_alignment_allocation_blocks_log2 as u32,
                        Some(&unconstrained_extents),
                        pending_allocs,
                        pending_frees,
                        image_size,
                    ) {
                        Some(subword_extent_allocation_blocks_begin) => layout::PhysicalAllocBlockRange::from((
                            subword_extent_allocation_blocks_begin,
                            layout::AllocBlockCount::from(subword_extent_allocation_blocks),
                        )),
                        None => return Ok(None),
                    };
                    unconstrained_extents.push_extent(&subword_extent, true)?;
                }

                let mut extents = extents::PhysicalExtents::new();
                for unconstrained_extent in unconstrained_extents.iter() {
                    let mut extent_begin = unconstrained_extent.begin();
                    let mut remaining_unconstrained_allocation_blocks = unconstrained_extent.block_count();
                    while u64::from(remaining_unconstrained_allocation_blocks) != 0 {
                        let constrained_allocation_blocks =
                            remaining_unconstrained_allocation_blocks.min(max_extent_allocation_blocks);
                        extents.push_extent(
                            &layout::PhysicalAllocBlockRange::from((extent_begin, constrained_allocation_blocks)),
                            true,
                        )?;
                        extent_begin += constrained_allocation_blocks;
                        remaining_unconstrained_allocation_blocks =
                            remaining_unconstrained_allocation_blocks - constrained_allocation_blocks;
                    }
                }

                Ok(Some((extents, allocated_excess_effective_payload_len)))
            } else {
                // The max_extent_allocation_blocks cannot get rounded down to power of two,
                // because that would drop to below the minimum extent length.
                // At this point in time, nothing would issue such requests, so
                // don't even bother supporting it.
                Err(NvFsError::from(CocoonFsFormatError::UnsupportedImageLayoutConfig))
            }
        }
    }

    /// Find a free block of size and alignment equal to [`BitmapWord::BITS`]
    /// [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    ///
    /// # Arguments:
    ///
    ///  * `allocated_fullword_chunks` - List of extents to consider virtually
    ///    as having been allocated, independent of the current state in the
    ///    [`AllocBitmap`].
    ///  * `pending_allocs` - Pending allocations to apply virtually on top of
    ///    the state as currently found in the [`AllocBitmap`].
    ///  * `pending_frees` - Pending frees to apply virtually on top of the
    ///    state as currently found in the [`AllocBitmap`].
    ///  * `image_size` - The filesystem image size. No [Allocation
    ///    Block](layout::ImageLayout::allocation_block_size_128b_log2) beyond
    ///    it will be considered for the allocation.
    fn find_free_fullword_block<const AN: usize, const FN: usize>(
        &self,
        allocated_fullword_chunks: Option<&extents::PhysicalExtents>,
        pending_allocs: &SparseAllocBitmapUnion<'_, AN>,
        pending_frees: &SparseAllocBitmapUnion<'_, FN>,
        image_size: layout::AllocBlockCount,
    ) -> Option<layout::PhysicalAllocBlockIndex> {
        let image_bitmap_words = u64::from(image_size) >> BITMAP_WORD_BITS_LOG2;
        let bitmaps_words_iter =
            AllocBitmapWordIterator::new_at_bitmap_word_index(self, pending_allocs, pending_frees, 0);
        let mut next_allocated_fullword_chunk: Option<layout::PhysicalAllocBlockRange> = None;
        for (bitmap_word_index, bitmap_word) in
            bitmaps_words_iter.take(usize::try_from(image_bitmap_words).unwrap_or(usize::MAX))
        {
            if bitmap_word == 0 {
                // Check if the bitmap word is really free or has perhaps been previously
                // allocated as part of a preceeding fullword chunks allocation
                // round for processing the very same request.
                next_allocated_fullword_chunk = next_allocated_fullword_chunk
                    .filter(|next_allocated_fullword_chunk| {
                        u64::from(next_allocated_fullword_chunk.end()) >> BITMAP_WORD_BITS_LOG2 > bitmap_word_index
                    })
                    .or_else(|| {
                        allocated_fullword_chunks
                            .map(|e| e.iter())
                            .into_iter()
                            .flatten()
                            .filter(|e| u64::from(e.end()) >> BITMAP_WORD_BITS_LOG2 > bitmap_word_index)
                            .min_by_key(|e| e.end())
                    });
                if let Some(next_allocated_fullword_chunk) = next_allocated_fullword_chunk {
                    if u64::from(next_allocated_fullword_chunk.begin()) >> BITMAP_WORD_BITS_LOG2 <= bitmap_word_index {
                        continue;
                    }
                }

                return Some(layout::PhysicalAllocBlockIndex::from(
                    bitmap_word_index * (BitmapWord::BITS as u64),
                ));
            }
        }
        None
    }

    /// Find a free extent of size and alignment less than[`BitmapWord::BITS`]
    /// [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    ///
    /// Find a free extent of size and alignment as specified by
    /// `chunk_allocation_blocks` and
    /// `chunk_alignment_allocation_blocks_log2` respectively.
    ///
    /// Note that the search procedure attempts to reduce fragmentation by
    /// avoiding to split up free blocks, i.e. free extents of length a power of
    /// two, if possible, and prefers to split up smaller blocks over larger
    /// ones.
    ///
    /// # Arguments:
    ///
    ///  * `chunk_allocation_blocks` - The desired extent length in units of
    ///    [Allocation
    ///    Blocks](layout::ImageLayout::allocation_block_size_128b_log2). Must
    ///    be strictly less than [`BitmapWord::BITS`] and a multiple of the
    ///    alignment specified via `chunk_alignment_allocation_blocks_log2`.
    ///  * `chunk_alignment_allocation_blocks_log2` - Base-2 logarithm of the
    ///    desired extent alignment in units of [Allocation
    ///    Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    ///  * `allocated_fullword_chunks` - List of extents to consider virtually
    ///    as having been allocated, independent of the current state in the
    ///    [`AllocBitmap`].
    ///  * `pending_allocs` - Pending allocations to apply virtually on top of
    ///    the state as currently found in the [`AllocBitmap`].
    ///  * `pending_frees` - Pending frees to apply virtually on top of the
    ///    state as currently found in the [`AllocBitmap`].
    ///  * `image_size` - The filesystem image size. No [Allocation
    ///    Block](layout::ImageLayout::allocation_block_size_128b_log2) beyond
    ///    it will be considered for the allocation.
    fn find_free_subword_chunk<const AN: usize, const FN: usize>(
        &self,
        chunk_allocation_blocks: u32,
        chunk_alignment_allocation_blocks_log2: u32,
        mut allocated_fullword_chunks: Option<&extents::PhysicalExtents>,
        pending_allocs: &SparseAllocBitmapUnion<'_, AN>,
        pending_frees: &SparseAllocBitmapUnion<'_, FN>,
        image_size: layout::AllocBlockCount,
    ) -> Option<layout::PhysicalAllocBlockIndex> {
        debug_assert_ne!(chunk_allocation_blocks, 0);
        debug_assert_eq!(
            chunk_allocation_blocks & u32::trailing_bits_mask(chunk_alignment_allocation_blocks_log2),
            0
        );
        debug_assert!(chunk_alignment_allocation_blocks_log2 <= BITMAP_WORD_BITS_LOG2);

        let containing_block_allocation_blocks = chunk_allocation_blocks.round_up_next_pow2().unwrap();
        let containing_block_allocation_blocks_log2 = containing_block_allocation_blocks.ilog2();

        if containing_block_allocation_blocks == chunk_allocation_blocks {
            return self.find_free_block(
                containing_block_allocation_blocks_log2,
                allocated_fullword_chunks,
                pending_allocs,
                pending_frees,
                image_size,
            );
        }
        debug_assert!(chunk_allocation_blocks >= 3);

        // The addition does not overflow, image_size is in units of Allocation Blocks,
        // and has at least the upper 7 Bits clear.
        let image_bitmap_words = (u64::from(image_size) + (u64::BITS as u64 - 1)) >> BITMAP_WORD_BITS_LOG2;

        let word_blocks_lsbs_mask_table = BitmapWordBlocksLsbsMaskTable::new();
        let word_containing_blocks_lsbs_mask =
            word_blocks_lsbs_mask_table.get_blocks_lsbs_mask(containing_block_allocation_blocks_log2);
        let word_chunk_alignment_anchors_mask =
            word_blocks_lsbs_mask_table.get_blocks_lsbs_mask(chunk_alignment_allocation_blocks_log2);

        let bitmaps_words_iter =
            AllocBitmapWordIterator::new_at_bitmap_word_index(self, pending_allocs, pending_frees, 0);
        let mut next_allocated_fullword_chunk: Option<layout::PhysicalAllocBlockRange> = None;

        enum FoundCandidate {
            FreeContainingBlock {
                bitmap_word_index: u64,
                bitmap_word: u64,
                split_block_allocation_blocks_log2: u32, // Minimize.
            },
            ChunkInPartialContainingBlock {
                bitmap_word_index: u64,
                chunk_begin: u32,
                excess_aligned_blocks_set: u32, // Maximize.
            },
        }
        // To be minimized first, start out with the worst case value.
        let mut best_excess_allocation_blocks = containing_block_allocation_blocks - chunk_allocation_blocks;
        // The best_excess_allocation_blocks value found so far, scattered across all
        // individual block fields in a bitmap word.
        let mut containing_blocks_max_excess_len =
            word_containing_blocks_lsbs_mask * best_excess_allocation_blocks as BitmapWord;
        // Similarly, the requested chunk_allocation_blocks distributed uniformly across
        // all block fields in a bitmap word.
        let containing_blocks_min_maxstr_len = word_containing_blocks_lsbs_mask * chunk_allocation_blocks as BitmapWord;
        let mut best: Option<FoundCandidate> = None;
        for (bitmap_word_index, mut bitmap_word) in
            bitmaps_words_iter.take(usize::try_from(image_bitmap_words).unwrap_or(usize::MAX))
        {
            if bitmap_word_index + 1 == image_bitmap_words {
                // Set the excess high bits not backed by any actual storage.
                bitmap_word |= !BitmapWord::trailing_bits_mask(
                    BitmapWord::BITS - ((u64::from(image_size).wrapping_neg() & (BitmapWord::BITS as u64 - 1)) as u32),
                );
            }

            // Don't bother examining any further if all allocation blocks tracked by this
            // word are allocated already anyway.
            if bitmap_word == !0 {
                continue;
            }

            if bitmap_word == 0 {
                if best.is_none() {
                    // Check if the bitmap word is really free or has perhaps been previously
                    // allocated as part of a preceeding fullword chunks allocation
                    // round for processing the very same request.
                    next_allocated_fullword_chunk = next_allocated_fullword_chunk
                        .filter(|next_allocated_fullword_chunk| {
                            u64::from(next_allocated_fullword_chunk.end()) >> BITMAP_WORD_BITS_LOG2 > bitmap_word_index
                        })
                        .or_else(|| {
                            allocated_fullword_chunks
                                .map(|e| e.iter())
                                .into_iter()
                                .flatten()
                                .filter(|e| u64::from(e.end()) >> BITMAP_WORD_BITS_LOG2 > bitmap_word_index)
                                .min_by_key(|e| e.end())
                        });
                    if let Some(next_allocated_fullword_chunk) = next_allocated_fullword_chunk {
                        if u64::from(next_allocated_fullword_chunk.begin()) >> BITMAP_WORD_BITS_LOG2
                            <= bitmap_word_index
                        {
                            continue;
                        }
                    } else {
                        // No more extents at or after the current position, avoid another search..
                        allocated_fullword_chunks = None;
                    }

                    best = Some(FoundCandidate::FreeContainingBlock {
                        bitmap_word_index,
                        bitmap_word,
                        // If containing_block_allocation_blocks_log2 == BITMAP_WORD_BITS_LOG2, the
                        // correct value would in fact be zero, but it won't be of any relevance in
                        // this particular case anyway.
                        split_block_allocation_blocks_log2: BITMAP_WORD_BITS_LOG2,
                    });
                }
                continue;
            }

            let (containing_blocks_max_aligned_maxstr_len, containing_blocks_aligned_maxstr_lens) =
                Self::bitmap_word_blocks_maxstr_lens(
                    !bitmap_word,
                    containing_block_allocation_blocks_log2,
                    word_containing_blocks_lsbs_mask,
                    chunk_alignment_allocation_blocks_log2,
                    word_chunk_alignment_anchors_mask,
                );
            if containing_blocks_max_aligned_maxstr_len < chunk_allocation_blocks {
                continue;
            }

            // Determine the set of candidate containing blocks by comparing the found
            // maxstr lengths against the lower bound as well as against the
            // upper bound as given by the best (minimum) match found so far.
            // Note that the upper bounding part is only a pre-filtering, as the
            // maxstr excesses are getting computed in terms of the maxstr
            // boundaries with alignment constraints imposed at this point, the actual
            // maxstr lengths might extend beyond that. A more thorough check
            // considering the actual, unconstrained excess lengths will be
            // conducted below for the remaining candidates.
            //
            // This does wrap for those blocks that don't have a string of consecutive free
            // blocks of sufficient length left. However, the single (unsigned)
            // comparison below would effectively test (the individual block
            // fields) for
            //      containing_blocks_min_maxstr_len
            //   <= containing_blocks_aligned_maxstr_lens
            //   <= containing_blocks_min_maxstr_len + containing_blocks_max_excess_len,
            // c.f. Hacker's Delight, 2nd edition, 4-1 ("Checking Bounds of Integers"),
            // which is what is needed.

            let mut containing_blocks_candidates_lsbs = {
                let containing_blocks_excess_lens = Self::bitmap_word_blocks_fields_sub(
                    containing_blocks_aligned_maxstr_lens,
                    containing_blocks_min_maxstr_len,
                    containing_block_allocation_blocks_log2,
                    word_containing_blocks_lsbs_mask,
                );
                Self::bitmap_word_blocks_fields_geq_lsbs(
                    containing_blocks_max_excess_len,
                    containing_blocks_excess_lens,
                    containing_block_allocation_blocks_log2,
                    word_containing_blocks_lsbs_mask,
                )
            };
            if containing_blocks_candidates_lsbs == 0 {
                continue;
            }

            if containing_blocks_max_aligned_maxstr_len == containing_block_allocation_blocks {
                // There is at least one fully free containing block.
                let free_containing_blocks_lsbs = Self::bitmap_word_free_blocks_lsbs(
                    bitmap_word,
                    containing_block_allocation_blocks_log2,
                    word_containing_blocks_lsbs_mask,
                );
                // The fully free blocks are a subset of all candidates.
                debug_assert_eq!(
                    containing_blocks_candidates_lsbs & free_containing_blocks_lsbs,
                    free_containing_blocks_lsbs
                );
                if free_containing_blocks_lsbs == containing_blocks_candidates_lsbs {
                    // All candidates are fully free blocks.
                    // The case that the full range covered by the bitmap_word is free has been
                    // handled separately above already.
                    debug_assert!(containing_block_allocation_blocks_log2 < BITMAP_WORD_BITS_LOG2);
                    let best_split_block_allocations_block_log2 = match best {
                        Some(FoundCandidate::FreeContainingBlock {
                            split_block_allocation_blocks_log2,
                            ..
                        }) => Some(split_block_allocation_blocks_log2),
                        Some(FoundCandidate::ChunkInPartialContainingBlock { .. }) => {
                            // At this point, the best (minimum) excess value found so far is known
                            // to not be smaller than that of a fully
                            // free containing block.
                            unreachable!();
                        }
                        None => None,
                    };

                    let split_block_allocation_blocks_log2 = Self::bitmap_word_block_alloc_split_block_size_log2(
                        free_containing_blocks_lsbs,
                        best_split_block_allocations_block_log2,
                        containing_block_allocation_blocks_log2,
                        word_containing_blocks_lsbs_mask,
                        &word_blocks_lsbs_mask_table,
                    );
                    if best_split_block_allocations_block_log2
                        .map(|best_split_block_allocations_block_log2| {
                            split_block_allocation_blocks_log2 < best_split_block_allocations_block_log2
                        })
                        .unwrap_or(true)
                    {
                        best = Some(FoundCandidate::FreeContainingBlock {
                            bitmap_word_index,
                            bitmap_word,
                            split_block_allocation_blocks_log2,
                        });
                        // No need to update the best_excess_allocation_blocks, it is still at
                        // its worst case value.
                        debug_assert_eq!(
                            best_excess_allocation_blocks,
                            containing_block_allocation_blocks - chunk_allocation_blocks
                        );
                    }
                    continue;
                }
                // There is at least one partially allocated containing block and it will get
                // rated better than the fully free ones. Mask off the latter as they won't win
                // anyway.
                containing_blocks_candidates_lsbs ^= free_containing_blocks_lsbs;
                debug_assert_ne!(containing_blocks_candidates_lsbs, 0);
            }

            // At this point, all (remaining) containing candidate blocks are known to
            // already have some other allocations in them. The
            // containing_block_allocation_blocks has been chosen such that it's
            // less than twice the chunk_allocation_blocks. It follows that
            // there is at most one maxstr of consecutive unallocated allocation blocks
            // whose length is >= chunk_allocation_blocks in each containing
            // block. Thus, when searching for the ends of such a maxstr (known
            // to exist), it suffices to find the tail of a 1-str of
            // length at least containing_block_allocation_blocks / 2. Note that as we do
            // know the length of each block's (aligned) maxstr already, the
            // respective (aligned) maxstrs' start can be computed from the
            // (aligned) end right away.
            let mut containing_blocks_maxstr_end_bits = !bitmap_word;
            let mut s = 1;
            while s < containing_block_allocation_blocks / 2 {
                // Retain those bits which are at the end (from least to most significant order)
                // of a string of consecutive ones at least 2 * s in length.
                containing_blocks_maxstr_end_bits =
                    containing_blocks_maxstr_end_bits & (containing_blocks_maxstr_end_bits << s);
                s *= 2;
            }

            let word_containing_block_field_mask = BitmapWord::trailing_bits_mask(containing_block_allocation_blocks);
            let mut containing_block_begin = 0;
            while containing_blocks_candidates_lsbs != 0 {
                let next_containing_block_candidate_offset = containing_blocks_candidates_lsbs.trailing_zeros();
                containing_block_begin += next_containing_block_candidate_offset;
                if next_containing_block_candidate_offset + containing_block_allocation_blocks != BitmapWord::BITS {
                    containing_blocks_candidates_lsbs >>=
                        next_containing_block_candidate_offset + containing_block_allocation_blocks;
                } else {
                    containing_blocks_candidates_lsbs = 0;
                }

                let containing_block_candidate_aligned_maxstr_len = (containing_blocks_aligned_maxstr_lens
                    >> containing_block_begin)
                    & word_containing_block_field_mask;
                debug_assert!(
                    containing_block_candidate_aligned_maxstr_len < containing_block_allocation_blocks as BitmapWord
                );
                let containing_block_candidate_aligned_maxstr_len =
                    containing_block_candidate_aligned_maxstr_len as u32;
                debug_assert!(containing_block_candidate_aligned_maxstr_len >= chunk_allocation_blocks);

                let containing_block_candidate_maxstr_end_bit =
                    (containing_blocks_maxstr_end_bits >> containing_block_begin) & word_containing_block_field_mask;
                debug_assert_ne!(containing_block_candidate_maxstr_end_bit, 0);
                let containing_block_candidate_maxstr_end = containing_block_candidate_maxstr_end_bit.ilog2() + 1;
                debug_assert!(containing_block_candidate_maxstr_end >= containing_block_candidate_aligned_maxstr_len);
                let containing_block_candidate_aligned_maxstr_end =
                    containing_block_candidate_maxstr_end.round_down_pow2(chunk_alignment_allocation_blocks_log2);
                let containing_block_candidate_aligned_maxstr_begin =
                    containing_block_candidate_aligned_maxstr_end - containing_block_candidate_aligned_maxstr_len;
                let containing_block_candidate_maxstr_begin = if chunk_alignment_allocation_blocks_log2 == 0 {
                    containing_block_candidate_aligned_maxstr_begin
                } else {
                    let containing_block_candidate_bitmap_subword_head = (bitmap_word >> containing_block_begin)
                        & u64::trailing_bits_mask(containing_block_candidate_aligned_maxstr_begin);
                    if containing_block_candidate_bitmap_subword_head != 0 {
                        containing_block_candidate_bitmap_subword_head.ilog2() + 1
                    } else {
                        debug_assert_eq!(containing_block_candidate_aligned_maxstr_begin, 0);
                        containing_block_candidate_aligned_maxstr_begin
                    }
                };
                let containing_block_candidate_maxstr_len =
                    containing_block_candidate_maxstr_end - containing_block_candidate_maxstr_begin;
                // Recompute the actual excess length, this time w/o any alignment constraints
                // imposed on the maxstr boundaries.
                let excess_allocation_blocks = containing_block_candidate_maxstr_len - chunk_allocation_blocks;
                if excess_allocation_blocks > best_excess_allocation_blocks {
                    // The actual, unconstrained maxstr length exceeds the best fit found so far,
                    // either because considering the alignment padding made its length to increase
                    // beyond the best fit found in some previous bitmap word or because a previous
                    // block from this very same word has been a better fit already.
                    containing_block_begin += containing_block_allocation_blocks;
                    continue;
                }

                if excess_allocation_blocks == 0 {
                    // It's a perfect fit, no need to look any further.
                    return Some(layout::PhysicalAllocBlockIndex::from(
                        bitmap_word_index * BitmapWord::BITS as u64
                            + containing_block_begin as u64
                            + containing_block_candidate_aligned_maxstr_begin as u64,
                    ));
                }

                // Determine the maximum possible alignment for the leftover excess space, the
                // more it is aligned, with the meaning to be specified in what
                // follows, the better. Logically, the excess space can be
                // viewed as a collection of differently sized blocks, one for
                // each bit set in excess_allocation_blocks, with a size
                // corresponding to that bit position. Example: for excess_allocation_blocks =
                // 0x15, the excess space would consist of three blocks: one of
                // size 1, another one of size 2^2 = 4 and a third one of size
                // 2^4 = 16. Now, depending on where the string of free blocks
                // starts and on the alignment of the chunk_allocation_blocks, it
                // might or might not be possible to place the allocation within the string of
                // free blocks to keep the remaining excess blocks aligned. In
                // general, the larger the maximum excess space block which is
                // aligned, the better the configuration.
                //
                // Neglecting the user specified alignment constraints for the moment, there are
                // two possibilities to place the new allocation relative to the
                // excess space: either in front or after it. Note that in
                // principle, there is more degree of freedom, as the allocation
                // could be placed somewhere "in the middle" of the excess space, but
                // none of these additional options would improve the best possible overall
                // excess blocks alignment. With the user specified alignment
                // constraints taken into account, the situation is basically
                // the same, except that there are fixed padding areas at the
                // head and tail before and after the aligned maxstr boundaries
                // respectively, with the "movable" leftover excess space also happening to be
                // aligned to the user specified alignment.
                //
                // For each of the possible excess starting points, either at
                // containing_block_candidate_aligned_maxstr_begin or at
                // containing_block_candidate_aligned_maxstr_begin + chunk_allocation_blocks,
                // determine the point of maximum alignment within the excess range (which
                // happens to be aligned to the maximum excess block, at least)
                // and split the excess space into two parts at this point. All
                // the blocks now found in the two individual parts can be
                // considered aligned: in the first part the sequence of blocks would
                // be ordered from from smallest to largest, and in the second part after the
                // point of maximum alignment from largest down to smallest.
                let excess_fixed_alignment_padding_head =
                    containing_block_candidate_aligned_maxstr_begin - containing_block_candidate_maxstr_begin;
                let excess_fixed_alignment_padding_tail =
                    containing_block_candidate_maxstr_end - containing_block_candidate_aligned_maxstr_end;
                let excess_fixed_alignment_padding_aligned_blocks_set =
                    excess_fixed_alignment_padding_head | excess_fixed_alignment_padding_tail;
                // As mentioned above, the "movable" part of the excess space is aligned to to
                // the user specified alignment.
                let movable_excess_allocation_blocks =
                    containing_block_candidate_aligned_maxstr_len - chunk_allocation_blocks;
                debug_assert_eq!(
                    excess_fixed_alignment_padding_head
                        + movable_excess_allocation_blocks
                        + excess_fixed_alignment_padding_tail,
                    excess_allocation_blocks
                );
                let max_movable_excess_block = u32::next_power_of_two(movable_excess_allocation_blocks + 1) >> 1;
                // First option: the allocation is placed after the (movable part of the) excess
                // space.
                // This computes the amount of excess space after the point point of maximum
                // alignment within the excess space, c.f. Hacker's Delight, 2nd edition, 3-3
                // ("Detecting a Power-of-2 Boundary Crossing").
                let movable_excess_aligned_blocks_set_after_1 = (containing_block_candidate_aligned_maxstr_begin
                    | max_movable_excess_block.wrapping_neg())
                .wrapping_add(movable_excess_allocation_blocks);
                let movable_excess_aligned_blocks_set_after_0 =
                    movable_excess_allocation_blocks - movable_excess_aligned_blocks_set_after_1;
                let movable_excess_aligned_blocks_set_after =
                    movable_excess_aligned_blocks_set_after_0 | movable_excess_aligned_blocks_set_after_1;
                // Second option: the allocation is placed before the (movable part of the)
                // excess space.
                let movable_excess_aligned_blocks_set_before_1 = ((containing_block_candidate_aligned_maxstr_begin
                    + chunk_allocation_blocks)
                    | max_movable_excess_block.wrapping_neg())
                .wrapping_add(movable_excess_allocation_blocks);
                let movable_excess_aligned_blocks_set_before_0 =
                    movable_excess_allocation_blocks - movable_excess_aligned_blocks_set_before_1;
                let movable_excess_aligned_blocks_set_before =
                    movable_excess_aligned_blocks_set_before_0 | movable_excess_aligned_blocks_set_before_1;
                let (chunk_begin, excess_aligned_blocks_set) = if movable_excess_aligned_blocks_set_after
                    > movable_excess_aligned_blocks_set_before
                {
                    (
                        containing_block_candidate_aligned_maxstr_begin + movable_excess_allocation_blocks,
                        movable_excess_aligned_blocks_set_after | excess_fixed_alignment_padding_aligned_blocks_set,
                    )
                } else {
                    (
                        containing_block_candidate_aligned_maxstr_begin,
                        movable_excess_aligned_blocks_set_before | excess_fixed_alignment_padding_aligned_blocks_set,
                    )
                };
                let chunk_begin = chunk_begin + containing_block_begin;
                if excess_allocation_blocks < best_excess_allocation_blocks {
                    best = Some(FoundCandidate::ChunkInPartialContainingBlock {
                        bitmap_word_index,
                        chunk_begin,
                        excess_aligned_blocks_set,
                    });
                    best_excess_allocation_blocks = excess_allocation_blocks;
                    // Update the containing_blocks_max_excess_len block fields accordingly:
                    // uniformly set all fields to the new effective upper bound for the subsequent
                    // search.
                    containing_blocks_max_excess_len =
                        word_containing_blocks_lsbs_mask * best_excess_allocation_blocks as BitmapWord;
                } else {
                    debug_assert_eq!(best_excess_allocation_blocks, excess_allocation_blocks);
                    let best_excess_aligned_blocks_set = match best.as_ref().unwrap() {
                        FoundCandidate::ChunkInPartialContainingBlock {
                            excess_aligned_blocks_set,
                            ..
                        } => *excess_aligned_blocks_set,
                        FoundCandidate::FreeContainingBlock { .. } => unreachable!(),
                    };
                    if excess_aligned_blocks_set > best_excess_aligned_blocks_set {
                        best = Some(FoundCandidate::ChunkInPartialContainingBlock {
                            bitmap_word_index,
                            chunk_begin,
                            excess_aligned_blocks_set,
                        });
                    }
                }
                containing_block_begin += containing_block_allocation_blocks;
            }
        }

        match best {
            Some(FoundCandidate::ChunkInPartialContainingBlock {
                bitmap_word_index,
                chunk_begin,
                excess_aligned_blocks_set: _,
            }) => Some(layout::PhysicalAllocBlockIndex::from(
                bitmap_word_index * BitmapWord::BITS as u64 + chunk_begin as u64,
            )),
            Some(FoundCandidate::FreeContainingBlock {
                bitmap_word_index,
                bitmap_word,
                split_block_allocation_blocks_log2,
            }) => {
                let word_split_blocks_lsbs_mask =
                    word_blocks_lsbs_mask_table.get_blocks_lsbs_mask(split_block_allocation_blocks_log2);
                let mut free_split_blocks_lsbs = Self::bitmap_word_free_blocks_lsbs(
                    bitmap_word,
                    split_block_allocation_blocks_log2,
                    word_split_blocks_lsbs_mask,
                );
                if split_block_allocation_blocks_log2 < BITMAP_WORD_BITS_LOG2 - 1 {
                    let double_split_block_allocations_block_log2 = split_block_allocation_blocks_log2 + 1;
                    let word_double_split_blocks_lsbs_mask =
                        word_blocks_lsbs_mask_table.get_blocks_lsbs_mask(double_split_block_allocations_block_log2);
                    free_split_blocks_lsbs = Self::bitmap_word_filter_blocks_with_free_buddy_lsbs(
                        free_split_blocks_lsbs,
                        free_split_blocks_lsbs,
                        split_block_allocation_blocks_log2,
                        word_double_split_blocks_lsbs_mask,
                    );
                }
                debug_assert_ne!(free_split_blocks_lsbs, 0);
                Some(layout::PhysicalAllocBlockIndex::from(
                    bitmap_word_index * BitmapWord::BITS as u64
                        + Self::bitmap_word_block_alloc_select_block(
                            free_split_blocks_lsbs,
                            split_block_allocation_blocks_log2,
                            word_split_blocks_lsbs_mask,
                            &word_blocks_lsbs_mask_table,
                        ) as u64,
                ))
            }
            None => None,
        }
    }

    /// Find a free extent of length in units of [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2) between
    /// [`BitmapWord::BITS`] and two times [`BitmapWord::BITS`].
    ///
    /// Find a free extent of size as specified by `chunk_allocation_blocks`.
    ///
    /// The resulting extent, if any, will be aligned to the maximum alignment
    /// `chunk_allocation_blocks` has.
    ///
    /// Note that the search procedure attempts to reduce fragmentation by
    /// avoiding to split up free blocks, i.e. free extents of length a power of
    /// two, if possible, and prefers to split up smaller blocks over larger
    /// ones.
    ///
    /// # Arguments:
    ///
    ///  * `chunk_allocation_blocks` - The desired extent length in units of
    ///    [Allocation
    ///    Blocks](layout::ImageLayout::allocation_block_size_128b_log2). Must
    ///    be between [`BitmapWord::BITS`] and two times [`BitmapWord::BITS`]
    ///    (both exlusive).
    ///  * `pending_allocs` - Pending allocations to apply virtually on top of
    ///    the state as currently found in the [`AllocBitmap`].
    ///  * `pending_frees` - Pending frees to apply virtually on top of the
    ///    state as currently found in the [`AllocBitmap`].
    ///  * `image_size` - The filesystem image size. No [Allocation
    ///    Block](layout::ImageLayout::allocation_block_size_128b_log2) beyond
    ///    it will be considered for the allocation.
    fn find_free_sub_doubleword_chunk<const AN: usize, const FN: usize>(
        &self,
        chunk_allocation_blocks: u32,
        pending_allocs: &SparseAllocBitmapUnion<'_, AN>,
        pending_frees: &SparseAllocBitmapUnion<'_, FN>,
        image_size: layout::AllocBlockCount,
    ) -> Option<layout::PhysicalAllocBlockIndex> {
        debug_assert!(chunk_allocation_blocks > BitmapWord::BITS);
        debug_assert!(chunk_allocation_blocks < 2 * BitmapWord::BITS);

        let subword_rem_allocation_blocks = chunk_allocation_blocks - BitmapWord::BITS;
        let subword_rem_free_head_word_mask = BitmapWord::trailing_bits_mask(subword_rem_allocation_blocks);
        let subword_rem_free_tail_word_mask =
            subword_rem_free_head_word_mask << (BitmapWord::BITS - subword_rem_allocation_blocks);

        // The addition does not overflow, image_size is in units of Allocation Blocks,
        // and has at least the upper 7 Bits clear.
        let image_bitmap_words = (u64::from(image_size) + (u64::BITS as u64 - 1)) >> BITMAP_WORD_BITS_LOG2;

        let mut previous_bitmap_word: Option<BitmapWord> = None;
        let bitmaps_words_iter =
            AllocBitmapWordIterator::new_at_bitmap_word_index(self, pending_allocs, pending_frees, 0);
        struct FoundCandidate {
            bitmap_word_index: u64,
            first_bitmap_word: u64,
            excess_allocation_blocks: u32, // Minimize.
        }
        let mut best: Option<FoundCandidate> = None;
        for (bitmap_word_index, mut bitmap_word) in
            bitmaps_words_iter.take(usize::try_from(image_bitmap_words).unwrap_or(usize::MAX))
        {
            if bitmap_word_index + 1 == image_bitmap_words {
                // Set the excess high bits not backed by any actual storage.
                bitmap_word |= !BitmapWord::trailing_bits_mask(
                    BitmapWord::BITS - ((u64::from(image_size).wrapping_neg() & (BitmapWord::BITS as u64 - 1)) as u32),
                );
            }

            // Don't bother examining any further if all allocation blocks tracked by this
            // word are allocated already anyway.
            if bitmap_word == !0 {
                previous_bitmap_word = None;
                continue;
            }

            if bitmap_word == 0 {
                match previous_bitmap_word {
                    Some(0) => {
                        if best.is_none() {
                            best = Some(FoundCandidate {
                                bitmap_word_index: bitmap_word_index - 1,
                                first_bitmap_word: 0,
                                excess_allocation_blocks: BitmapWord::BITS - subword_rem_allocation_blocks,
                            });
                        }
                    }
                    Some(previous_bitmap_word) => {
                        debug_assert_eq!(previous_bitmap_word & subword_rem_free_tail_word_mask, 0);
                        let excess_allocation_blocks =
                            previous_bitmap_word.leading_zeros() - subword_rem_allocation_blocks;
                        if best
                            .as_ref()
                            .map(|best| best.excess_allocation_blocks > excess_allocation_blocks)
                            .unwrap_or(true)
                        {
                            best = Some(FoundCandidate {
                                bitmap_word_index: bitmap_word_index - 1,
                                first_bitmap_word: previous_bitmap_word,
                                excess_allocation_blocks,
                            });
                            if excess_allocation_blocks == 0 {
                                // It's a perfect fit, no need to look any further.
                                break;
                            }
                        }
                    }
                    None => (),
                }
                previous_bitmap_word = Some(0);
                continue;
            } else if bitmap_word & subword_rem_free_head_word_mask == 0 {
                if let Some(0) = previous_bitmap_word {
                    let excess_allocation_blocks = bitmap_word.trailing_zeros() - subword_rem_allocation_blocks;
                    if best
                        .as_ref()
                        .map(|best| best.excess_allocation_blocks > excess_allocation_blocks)
                        .unwrap_or(true)
                    {
                        best = Some(FoundCandidate {
                            bitmap_word_index: bitmap_word_index - 1,
                            first_bitmap_word: 0,
                            excess_allocation_blocks,
                        });
                        if excess_allocation_blocks == 0 {
                            // It's a perfect fit, no need to look any further.
                            break;
                        }
                    }
                }
            }

            if bitmap_word & subword_rem_free_tail_word_mask == 0 {
                previous_bitmap_word = Some(bitmap_word);
            } else {
                previous_bitmap_word = None;
            }
        }

        match best {
            Some(FoundCandidate {
                bitmap_word_index,
                first_bitmap_word,
                ..
            }) => {
                let chunk_begin_in_fullword_block = if first_bitmap_word == 0 {
                    0
                } else {
                    BitmapWord::BITS - subword_rem_allocation_blocks
                };

                Some(layout::PhysicalAllocBlockIndex::from(
                    bitmap_word_index * BitmapWord::BITS as u64 + chunk_begin_in_fullword_block as u64,
                ))
            }
            None => None,
        }
    }

    /// Find free extents of lengths a multiple of [`BitmapWord::BITS`]
    /// [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2) each
    /// for serving an [`ExtentsAllocationRequest`].
    ///
    /// Attempt to find a sequence of free extents with lengths a multiple of
    /// [`BitmapWord::BITS`] [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2) each for
    /// serving an [`ExtentsAllocationRequest`] and collectively providing
    /// enough payload storage capacity so that the unsatisfied requested
    /// payload length remainder, if any, can be provided by one additional
    /// extent less than [`BitmapWord::BITS`] in length.
    ///
    /// In general, the search procedure always attempts to minimize the total
    /// number of extents allocated.
    ///
    /// In order to bound peak memory usage for tracking the set of extents
    /// allocated at any given point in time, if possible, the search
    /// proceeds in two phases: in a first search, an [extent candidate
    /// filter](FindFreeFullwordChunksExtentCandiateFilter) effectively limiting
    /// the number of extents in the list at any point is applied to each
    /// found free extent candidate. If that fails, another unconstrained
    /// search is conducted.
    ///
    /// # Arguments:
    ///
    ///  * `allocation_request` - The [`ExtentsAllocationRequest`] to find free
    ///    extents for.
    ///  * `pending_allocs` - Pending allocations to apply virtually on top of
    ///    the state as currently found in the [`AllocBitmap`].
    ///  * `pending_frees` - Pending frees to apply virtually on top of the
    ///    state as currently found in the [`AllocBitmap`].
    ///  * `image_size` - The filesystem image size. No [Allocation
    ///    Block](layout::ImageLayout::allocation_block_size_128b_log2) beyond
    ///    it will be considered for the allocation.
    ///  * `head_extent_min_allocation_blocks` - The head extent's minimum
    ///    length in units of [Allocation
    ///    Blocks](layout::ImageLayout::allocation_block_size_128b_log2), as
    ///    returned by [`ExtentsLayout::min_extents_allocation_blocks()`].
    ///  * `tail_extent_min_allocation_blocks` - Minimum length of any tail
    ///    "continuation" extent in units of [Allocation
    ///    Blocks](layout::ImageLayout::allocation_block_size_128b_log2), as
    ///    returned by [`ExtentsLayout::min_extents_allocation_blocks()`].
    fn find_free_fullword_chunks<'a, const AN: usize, const FN: usize>(
        &self,
        allocation_request: &'a ExtentsAllocationRequest,
        pending_allocs: &SparseAllocBitmapUnion<'_, AN>,
        pending_frees: &SparseAllocBitmapUnion<'_, FN>,
        image_size: layout::AllocBlockCount,
        head_extent_min_allocation_blocks: layout::AllocBlockCount,
        tail_extent_min_allocation_blocks: layout::AllocBlockCount,
    ) -> Result<Option<(ExtentsAllocationRequestProgress<'a>, extents::PhysicalExtents)>, NvFsError> {
        let extent_candidate_filter =
            FindFreeFullwordChunksExtentCandidateFilterConstrainExtentsCount::new(allocation_request);
        Ok(
            match self._find_free_fullword_chunks(
                allocation_request,
                extent_candidate_filter,
                pending_allocs,
                pending_frees,
                image_size,
                head_extent_min_allocation_blocks,
                tail_extent_min_allocation_blocks,
            )? {
                Some(result) => Some(result),
                None => {
                    let extent_candidate_filter = FindFreeFullwordChunksExtentCandidateFilterUnconstrained {};
                    self._find_free_fullword_chunks(
                        allocation_request,
                        extent_candidate_filter,
                        pending_allocs,
                        pending_frees,
                        image_size,
                        head_extent_min_allocation_blocks,
                        tail_extent_min_allocation_blocks,
                    )?
                }
            },
        )
    }

    /// Find free extents of lengths a multiple of [`BitmapWord::BITS`]
    /// [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2) and
    /// accepted by a specified [candidate
    /// filter](FindFreeFullwordChunksExtentCandiateFilter) each for serving an
    /// [`ExtentsAllocationRequest`].
    ///
    /// Attempt to find a sequence of free extents with lengths a multiple of
    /// [`BitmapWord::BITS`] [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2) each for
    /// serving an [`ExtentsAllocationRequest`] and collectively providing
    /// enough payload storage capacity so that the unsatisfied requested
    /// payload length remainder, if any, can be provided by one additional
    /// extent less than [`BitmapWord::BITS`] in length.
    ///
    /// Only free extents passing the `extent_candidate_filter` will be
    /// considered.
    ///
    /// In general, the search procedure always attempts to minimize the total
    /// number of extents allocated, even for an
    /// [unconstrained](FindFreeFullwordChunksExtentCandidateFilterUnconstrained)
    /// `extent_candidate_filter`.
    ///
    /// # Arguments:
    ///  * `allocation_request` - The [`ExtentsAllocationRequest`] to find free
    ///    extents for.
    ///  * `extent_candidate_filter` - The [extent candidate
    ///    filter](FindFreeFullwordChunksExtentCandiateFilter) to query about
    ///    any free candidate extent's eligibility for inclusion in the
    ///    resulting allocation.
    ///  * `pending_allocs` - Pending allocations to apply virtually on top of
    ///    the state as currently found in the [`AllocBitmap`].
    ///  * `pending_frees` - Pending frees to apply virtually on top of the
    ///    state as currently found in the [`AllocBitmap`].
    ///  * `image_size` - The filesystem image size. No [Allocation
    ///    Block](layout::ImageLayout::allocation_block_size_128b_log2) beyond
    ///    it will be considered for the allocation.
    ///  * `head_extent_min_allocation_blocks` - The head extent's minimum
    ///    length in units of [Allocation
    ///    Blocks](layout::ImageLayout::allocation_block_size_128b_log2), as
    ///    returned by [`ExtentsLayout::min_extents_allocation_blocks()`].
    ///  * `tail_extent_min_allocation_blocks` - Minimum length of any tail
    ///    "continuation" extent in units of [Allocation
    ///    Blocks](layout::ImageLayout::allocation_block_size_128b_log2), as
    ///    returned by [`ExtentsLayout::min_extents_allocation_blocks()`].
    #[allow(clippy::too_many_arguments)]
    fn _find_free_fullword_chunks<
        'a,
        const AN: usize,
        const FN: usize,
        ECF: FindFreeFullwordChunksExtentCandiateFilter,
    >(
        &self,
        allocation_request: &'a ExtentsAllocationRequest,
        mut extent_candidate_filter: ECF,
        pending_allocs: &SparseAllocBitmapUnion<'_, AN>,
        pending_frees: &SparseAllocBitmapUnion<'_, FN>,
        image_size: layout::AllocBlockCount,
        head_extent_min_allocation_blocks: layout::AllocBlockCount,
        tail_extent_min_allocation_blocks: layout::AllocBlockCount,
    ) -> Result<Option<(ExtentsAllocationRequestProgress<'a>, extents::PhysicalExtents)>, NvFsError> {
        debug_assert!(
            allocation_request.layout.extent_alignment_allocation_blocks_log2 as u32 <= BITMAP_WORD_BITS_LOG2
        );
        let mut progress = ExtentsAllocationRequestProgress::new(allocation_request);
        let mut extents = extents::PhysicalExtents::new();

        if u64::from(allocation_request.remaining_max_extent_allocation_blocks(0).0) < BitmapWord::BITS as u64 {
            return Ok(Some((progress, extents)));
        }
        debug_assert!(u64::from(allocation_request.layout.max_extent_allocation_blocks) >= BitmapWord::BITS as u64);

        // Stop condition for allocating further fullword blocks: once the remainder
        // (including additional extent + payload headers, as well as padding),
        // would fit into the next possible extent size smaller than a fullword
        // block, stop. Note that for remaining lengths larger than that, a
        // fullword allocation could have some excess space (due to saved
        // headers + padding) of up to, but less than, twice the size of a minimum
        // extent satisfying the alignment constraints
        // (extent_alignment_allocation_blocks_log2). The minimum extent
        // length is bounded by 2^63 from above, c.f. ExtentsAllocationRequest::new().
        // Hence the excess space will fit an u64, even in such unrealistic scenarios.
        debug_assert_eq!(
            tail_extent_min_allocation_blocks
                .align_down(allocation_request.layout.extent_alignment_allocation_blocks_log2 as u32),
            tail_extent_min_allocation_blocks
        );
        let (max_subword_extent_effective_payload_len, max_allocated_effective_payload_excess_len) =
            if u64::from(tail_extent_min_allocation_blocks) < BitmapWord::BITS as u64 {
                // Does not overflow, as per max_extent_allocation_blocks being >= the
                // BitmapWord::BITS when here.
                let max_subword_extent_effective_payload_len = allocation_request.layout.extent_effective_payload_len(
                    layout::AllocBlockCount::from(
                        (u64::BITS as u64)
                            - (1u64 << allocation_request.layout.extent_alignment_allocation_blocks_log2),
                    ),
                    false,
                );

                let fullword_block_len =
                    (BitmapWord::BITS as u64) << (allocation_request.layout.allocation_block_size_128b_log2 + 7);
                debug_assert_eq!(
                    fullword_block_len >> (allocation_request.layout.allocation_block_size_128b_log2 + 7),
                    BitmapWord::BITS as u64
                );
                let max_allocated_effective_payload_excess_len =
                    fullword_block_len - max_subword_extent_effective_payload_len - 1;
                (
                    max_subword_extent_effective_payload_len,
                    max_allocated_effective_payload_excess_len,
                )
            } else {
                // The minimum extent length is > than what's covered by a single
                // BitmapWord, and sub-BitmapWord extents are not possible. The maximum allowed
                // excess is one less than what's provided by an extent of
                // minimum possible length.
                let max_allocated_effective_payload_excess_len = allocation_request
                    .layout
                    .extent_effective_payload_len(tail_extent_min_allocation_blocks, false)
                    - 1;
                (0, max_allocated_effective_payload_excess_len)
            };

        // Cached shortest extent found (and used) so far: pair of index and length in
        // units of allocation blocks.
        let mut shortest_extent: Option<(usize, layout::AllocBlockCount)> = None;
        let image_bitmap_words = u64::from(image_size) >> BITMAP_WORD_BITS_LOG2;
        let mut bitmaps_words_iter =
            AllocBitmapWordIterator::new_at_bitmap_word_index(self, pending_allocs, pending_frees, 0)
                .take(usize::try_from(image_bitmap_words).unwrap_or(usize::MAX));
        let max_extent_fullword_blocks =
            usize::try_from(u64::from(allocation_request.layout.max_extent_allocation_blocks) >> BITMAP_WORD_BITS_LOG2)
                .unwrap_or(usize::MAX >> BITMAP_WORD_BITS_LOG2);
        while let Some((cur_free_run_begin_bitmap_word_index, _)) =
            bitmaps_words_iter.find(|(_, bitmap_word)| *bitmap_word == 0)
        {
            let cur_free_run_end_bitmap_word_index = (&mut bitmaps_words_iter)
                .map_while(|(bitmap_word_index, bitmap_word)| {
                    if bitmap_word == 0 {
                        Some(bitmap_word_index)
                    } else {
                        None
                    }
                })
                .take(max_extent_fullword_blocks - 1)
                .last()
                .unwrap_or(cur_free_run_begin_bitmap_word_index)
                + 1;
            // If the current free run is acceptable in terms of the current lower bound on
            // its length, consume all that is needed to satisfy the remaining
            // allocation request size.
            let cur_extent_max_fullword_blocks =
                cur_free_run_end_bitmap_word_index - cur_free_run_begin_bitmap_word_index;
            // No need to align, the alignment in units of Allocation Blocks is <=
            // BitmapWord::BITS.
            let cur_extent_max_allocation_blocks =
                layout::AllocBlockCount::from(cur_extent_max_fullword_blocks << BITMAP_WORD_BITS_LOG2);
            debug_assert_eq!(
                cur_extent_max_allocation_blocks
                    .align_down(allocation_request.layout.extent_alignment_allocation_blocks_log2 as u32),
                cur_extent_max_allocation_blocks
            );

            if cur_extent_max_allocation_blocks
                < if extents.is_empty() {
                    head_extent_min_allocation_blocks
                } else {
                    tail_extent_min_allocation_blocks
                }
            {
                continue;
            }

            let mut cur_extent_max_effective_payload_len = allocation_request
                .layout
                .extent_effective_payload_len(cur_extent_max_allocation_blocks, extents.is_empty());
            let mut cur_extent_used_effective_payload_len = 0;
            {
                let remaining_effective_payload_len = progress.remaining_effective_payload_len();
                if (extents.is_empty() || remaining_effective_payload_len > max_subword_extent_effective_payload_len)
                    && extent_candidate_filter.extent_candidate_acceptable(cur_extent_max_allocation_blocks)
                {
                    cur_extent_used_effective_payload_len =
                        cur_extent_max_effective_payload_len.min(remaining_effective_payload_len);
                    progress.allocated_effective_payload_len += cur_extent_used_effective_payload_len;
                }
            }

            // Use the remaining space in the current run, if any, to perhaps
            // replace one or more shorter extents already found before.
            let mut extents_hdr_transferred = false;
            while !extents.is_empty() && cur_extent_max_effective_payload_len > cur_extent_used_effective_payload_len {
                // Loop invariants:
                debug_assert!(
                    progress.allocated_excess_effective_payload_len == 0
                        || progress.remaining_effective_payload_len() == 0
                );
                debug_assert!(
                    progress.allocated_excess_effective_payload_len <= max_allocated_effective_payload_excess_len
                );

                shortest_extent = shortest_extent.or_else(|| {
                    ExtentsAllocationRequestProgress::find_shortest_extent(&extents).map(|shortest_extent_index| {
                        (
                            shortest_extent_index,
                            extents.get_extent_range(shortest_extent_index).block_count(),
                        )
                    })
                });
                let (shortest_extent_index, original_shortest_extent_allocation_blocks) = match shortest_extent {
                    Some(shortest_extent) => shortest_extent,
                    None => break,
                };

                // If the current run's total length is <= the shortest previously found one,
                // it would be counter-productive to shovel blocks from the latter over to the
                // former.
                // Also, it doesn't make any sense to replace a single small extent by a larger
                // one, truncating the latter in the course -- that would only
                // increase fragmentation.
                if original_shortest_extent_allocation_blocks >= cur_extent_max_allocation_blocks
                    || (cur_extent_used_effective_payload_len == 0
                        && extents
                            .iter()
                            .map(|e| e.block_count())
                            .filter(|c| *c < cur_extent_max_allocation_blocks)
                            .count()
                            < 2)
                {
                    break;
                }

                let shortest_extent_stores_extents_hdr = !extents_hdr_transferred
                    && allocation_request.layout.extents_hdr_len != 0
                    && shortest_extent_index == 0;
                if shortest_extent_stores_extents_hdr
                    && cur_extent_max_allocation_blocks >= head_extent_min_allocation_blocks
                {
                    // Recompute the current extent's maximum payload length if the extents header
                    // was transferred to it.
                    cur_extent_max_effective_payload_len = allocation_request
                        .layout
                        .extent_effective_payload_len(cur_extent_max_allocation_blocks, true);
                    if cur_extent_used_effective_payload_len > cur_extent_max_effective_payload_len {
                        break;
                    }

                    extents_hdr_transferred = true;
                }

                let mut shortest_extent_used_effective_payload_len =
                    allocation_request.layout.extent_effective_payload_len(
                        original_shortest_extent_allocation_blocks,
                        shortest_extent_stores_extents_hdr,
                    );
                if shortest_extent_used_effective_payload_len > progress.allocated_excess_effective_payload_len {
                    shortest_extent_used_effective_payload_len -= progress.allocated_excess_effective_payload_len;
                    progress.allocated_excess_effective_payload_len = 0;

                    let x = shortest_extent_used_effective_payload_len
                        .min(cur_extent_max_effective_payload_len - cur_extent_used_effective_payload_len);
                    cur_extent_used_effective_payload_len += x;
                    shortest_extent_used_effective_payload_len -= x;
                } else {
                    progress.allocated_excess_effective_payload_len -= shortest_extent_used_effective_payload_len;
                    shortest_extent_used_effective_payload_len = 0;
                }

                let updated_shortest_extent_allocation_blocks = progress.fit_allocated_extent_to_effective_payload_len(
                    shortest_extent_used_effective_payload_len,
                    false,
                    max_subword_extent_effective_payload_len,
                    BITMAP_WORD_BITS_LOG2,
                );

                if updated_shortest_extent_allocation_blocks < original_shortest_extent_allocation_blocks {
                    if u64::from(updated_shortest_extent_allocation_blocks) == 0 {
                        extents.swap_extents(shortest_extent_index, extents.len() - 1);
                        extents.pop_extent();
                        shortest_extent = None;
                        extent_candidate_filter.account_extents_dropped(1);
                    } else {
                        let removed = extents.shrink_extent_by(
                            shortest_extent_index,
                            original_shortest_extent_allocation_blocks - updated_shortest_extent_allocation_blocks,
                        );
                        debug_assert!(!removed);
                        shortest_extent = Some((shortest_extent_index, updated_shortest_extent_allocation_blocks));
                    }
                }
                // The loop invariants are still being upheld.
                debug_assert!(
                    progress.allocated_excess_effective_payload_len == 0
                        || progress.remaining_effective_payload_len() == 0
                );
                debug_assert!(
                    progress.allocated_excess_effective_payload_len <= max_allocated_effective_payload_excess_len
                );
            }

            let cur_extent_allocated_allocation_blocks = if cur_extent_used_effective_payload_len
                == cur_extent_max_effective_payload_len
            {
                // If all of the current extent is to be used, then there won't be any padding
                // and thus, no excess allocation from this current extent (a shorter one merged
                // partially into the current one can have padding/excess allocation though).
                cur_extent_max_allocation_blocks
            } else {
                // When here, not all available space of the current extent has been allocated.
                // If some has been allocated, then either all smaller extents got absorbed,
                // or the next one to merge would contain the extents header and the current
                // extent does not have enough space left to transfer these headers over to it.
                //
                // Regarding allocated excess space, note that excess space can emerge whenever
                // inserting or adjusting an extent's length (due to rounding the extent's
                // length upwards to make it align to
                // extent_alignment_allocation_blocks_log2). Allocations from
                // the current extent (cur_extent_used_effective_payload_len) will
                // have been made only above after the allocated_excess_effective_payload_len
                // dropped to zero (that is, when absorbing shorter extents, only the actual
                // part of payload needed will be accounted for). So the new
                // extent insertion below would be the only one potentially
                // contributing to excess, and thus, the amount of excess
                // will stay within the allowed bounds. There is one subtle corner case though:
                // if the extents headers got transferred, and
                // cur_extent_used_effective_payload_len is zero, because the
                // allocated excess at that time had been larger than the sum of
                // all shorter extents' payload lengths, the current extent still needs to get
                // inserted to have the headers placed somewhere.  When adding such extent
                // below, note that it will be of minimum possible length, and
                // the overall excess will not be worse than what it had been
                // before removing the extent previously storing the
                // extent headers.
                debug_assert!(
                    cur_extent_used_effective_payload_len == 0 || progress.allocated_excess_effective_payload_len == 0
                );

                progress.fit_allocated_extent_to_effective_payload_len(
                    cur_extent_used_effective_payload_len,
                    extents.is_empty() || extents_hdr_transferred,
                    max_subword_extent_effective_payload_len,
                    BITMAP_WORD_BITS_LOG2,
                )
            };
            // The loop invariants are still being upheld.
            debug_assert!(
                progress.allocated_excess_effective_payload_len == 0 || progress.remaining_effective_payload_len() == 0
            );
            debug_assert!(
                progress.allocated_excess_effective_payload_len <= max_allocated_effective_payload_excess_len
            );

            if u64::from(cur_extent_allocated_allocation_blocks) != 0 {
                let cur_extent_begin = layout::PhysicalAllocBlockIndex::from(
                    cur_free_run_begin_bitmap_word_index << BITMAP_WORD_BITS_LOG2,
                );
                extents.push_extent(
                    &layout::PhysicalAllocBlockRange::from((cur_extent_begin, cur_extent_allocated_allocation_blocks)),
                    true,
                )?;

                let mut cur_extent_index = extents.len() - 1;
                // If the common extents headers have been transferred from a shorter to
                // the current extent, then swap the latter into the first position.
                if extents_hdr_transferred {
                    extents.swap_extents(0, cur_extent_index);
                    if let Some((shortest_extent_index, shortest_extent_allocation_blocks)) = shortest_extent {
                        if shortest_extent_index == 0 {
                            shortest_extent = Some((cur_extent_index, shortest_extent_allocation_blocks));
                        }
                    }
                    cur_extent_index = 0;
                }

                // Try to update the cached shortest_extent if possible.
                if let Some((shortest_extent_index, shortest_extent_allocation_blocks)) = shortest_extent {
                    // Prefer (in this order):
                    // a.) shorter extents,
                    // b.) extents at increasing positions.
                    // compare to ExtentsAllocationRequestProgress::find_shortest_extent().
                    // Note that b.) is always true for the current extent, as the extent
                    // allocation search is in order of increasing positions..
                    if shortest_extent_allocation_blocks >= cur_extent_allocated_allocation_blocks {
                        debug_assert!(extents.get_extent_range(shortest_extent_index).begin() < cur_extent_begin);
                        shortest_extent = Some((cur_extent_index, cur_extent_allocated_allocation_blocks));
                    }
                }

                let (n_extents_removed, shortest_extent_index) = progress.optimize_extents_hdr_placement(
                    &mut extents,
                    shortest_extent.map(|(shortest_extent_index, _)| shortest_extent_index),
                    head_extent_min_allocation_blocks,
                    max_subword_extent_effective_payload_len,
                    BITMAP_WORD_BITS_LOG2,
                );
                shortest_extent = shortest_extent_index.map(|shortest_extent_index| {
                    (
                        shortest_extent_index,
                        extents.get_extent_range(shortest_extent_index).block_count(),
                    )
                });
                extent_candidate_filter.account_extents_dropped(n_extents_removed);

                // And now account for the allocation of the current extent above.
                extent_candidate_filter.account_extent_added();

                // Update the candidate filter, but do it only if needed as it can be costly. It
                // will be needed if we're still trying to satisfy the allocation request, i.e.
                // not yet merely trying to absorb smaller into larger extents.
                if progress.remaining_effective_payload_len() > max_subword_extent_effective_payload_len {
                    extent_candidate_filter.update_filter_state(&progress, max_subword_extent_effective_payload_len);
                } else {
                    // If all the requested effective payload length has been allocated and
                    // all extents (but one) have maximum length, then no further improvement
                    // is possible. Break out then.
                    if extents
                        .iter()
                        .map(|e| u64::from(e.block_count()) >> BITMAP_WORD_BITS_LOG2)
                        .filter(|c| {
                            *c < u64::from(allocation_request.layout.max_extent_allocation_blocks)
                                >> BITMAP_WORD_BITS_LOG2
                        })
                        .count()
                        == 1
                    {
                        break;
                    }
                }
            } else {
                debug_assert!(!extents_hdr_transferred);
            }
        }

        let result = if progress.remaining_effective_payload_len() <= max_subword_extent_effective_payload_len {
            // The request could be satisfied within the budget.
            // Sort the extents by (in this order)
            // a.) extent lengths (so that a potential future truncation
            //     would free up larger ones),
            // b.) their position.
            let sort_start_index = if progress.extents_hdr_placement_cost_is_invariant {
                0
            } else {
                1
            };
            let sort_end_index = extents.len();
            extents.sort_extents_by(
                sort_start_index..sort_end_index,
                |e0, e1| match e0.block_count().cmp(&e1.block_count()) {
                    cmp::Ordering::Less => cmp::Ordering::Less,
                    cmp::Ordering::Equal => e0.begin().cmp(&e1.begin()),
                    cmp::Ordering::Greater => cmp::Ordering::Greater,
                },
                true,
            );
            Some((progress, extents))
        } else {
            None
        };

        Ok(result)
    }

    /// Determine the minimum free block size greater than or equal to a given
    /// one within a [`BitmapWord`].
    ///
    /// When attempting to allocate some block of size and alignment as
    /// specified by `block_allocation_blocks_log2` in a given
    /// [`BitmapWord`], it is desirable to not unnecessarily split up some
    /// larger aligned free containing block, or, if not avoidable, to prefer
    /// splitting up a smaller containing free block over the larger ones.
    ///
    /// Determine the minimum size among all aligned free blocks within a
    /// [`BitmapWord`] greater than or equal to
    /// `block_allocation_blocks_log2` in length.
    ///
    /// # Arguments:
    ///
    /// * `bitmap_word_free_blocks_lsbs` - Proper, non-empty subset of the
    ///   `bitmap_word_blocks_lsbs_mask` corresponding to the free blocks of
    ///   size and alignment equal to two to the power of
    ///   `block_allocation_blocks_log2` each, as computed by
    ///   [`bitmap_word_free_blocks_lsbs()`](Self::bitmap_word_free_blocks_lsbs).
    /// * `max_split_block_allocation_blocks_log2` - Optional upper bound on the
    ///   split block size to return back. May be used as an optimization to
    ///   terminate the search early.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size to
    ///   examine containing free blocks for. Must be strictly less than
    ///   [`BitmapWord::BITS`].
    /// * `bitmap_word_blocks_lsbs_mask` - Mask of equidistant set bits,
    ///   separated by two to the power of `block_allocation_blocks_log2` each.
    /// * `bitmap_word_blocks_lsbs_mask_table` - Reference to a
    ///   [`BitmapWordBlocksLsbsMaskTable`] instance.
    fn bitmap_word_block_alloc_split_block_size_log2(
        bitmap_word_free_blocks_lsbs: BitmapWord,
        max_split_block_allocation_blocks_log2: Option<u32>,
        block_allocation_blocks_log2: u32,
        bitmap_word_blocks_lsbs_mask: BitmapWord,
        bitmap_word_blocks_lsbs_mask_table: &BitmapWordBlocksLsbsMaskTable,
    ) -> u32 {
        debug_assert_ne!(block_allocation_blocks_log2, BITMAP_WORD_BITS_LOG2);
        debug_assert_eq!(
            bitmap_word_blocks_lsbs_mask,
            bitmap_word_blocks_lsbs_mask_table.get_blocks_lsbs_mask(block_allocation_blocks_log2)
        );
        debug_assert_eq!(bitmap_word_free_blocks_lsbs & !bitmap_word_blocks_lsbs_mask, 0);
        debug_assert_ne!(bitmap_word_free_blocks_lsbs, 0);
        // At this point it is known that not all blocks are free, so the split block
        // size will be half the range covered by the word at most.
        debug_assert_ne!(bitmap_word_free_blocks_lsbs, bitmap_word_blocks_lsbs_mask);
        let max_split_block_allocation_blocks_log2 = max_split_block_allocation_blocks_log2
            .map(|m| m.min(BITMAP_WORD_BITS_LOG2 - 1))
            .unwrap_or(BITMAP_WORD_BITS_LOG2 - 1);
        let mut split_block_allocation_blocks_log2 = block_allocation_blocks_log2;
        let mut free_split_blocks_lsbs = bitmap_word_free_blocks_lsbs;
        while split_block_allocation_blocks_log2 < max_split_block_allocation_blocks_log2 {
            let double_split_block_allocations_block_log2 = split_block_allocation_blocks_log2 + 1;
            let word_double_split_blocks_lsbs_mask =
                bitmap_word_blocks_lsbs_mask_table.get_blocks_lsbs_mask(double_split_block_allocations_block_log2);
            if Self::bitmap_word_filter_blocks_with_free_buddy_lsbs(
                free_split_blocks_lsbs,
                free_split_blocks_lsbs,
                split_block_allocation_blocks_log2,
                word_double_split_blocks_lsbs_mask,
            ) != 0
            {
                break;
            }

            // All remaining candidate blocks of the current
            // split_block_allocation_blocks_log2 size have a free buddy,
            // meaning a block at least double that size must get split up.
            let split_block_allocation_blocks = 1u32 << split_block_allocation_blocks_log2;
            free_split_blocks_lsbs = (free_split_blocks_lsbs
                & (free_split_blocks_lsbs >> split_block_allocation_blocks))
                & word_double_split_blocks_lsbs_mask;
            debug_assert_ne!(free_split_blocks_lsbs, 0);
            split_block_allocation_blocks_log2 += 1;
        }
        split_block_allocation_blocks_log2
    }

    /// Select a free block of size and alignment a specified power of two
    /// within a [`BitmapWord`].
    ///
    /// Select a free block of size and alignment equal to two to the power of
    /// `block_allocation_blocks_log2`, under the assumption that there exists
    /// at least one such in the [`BitmapWord`] not in turn contained in some
    /// larger free aligned block.
    ///
    /// The position of the free block within the [`BitmapWord`] will get
    /// returned.
    ///
    /// # Arguments:
    ///
    /// * `bitmap_word_free_blocks_lsbs` - Subset of
    ///   `bitmap_word_blocks_lsbs_mask` corresponding to the free blocks of
    ///   size and alignment equal to two to the power of
    ///   `block_allocation_blocks_log2` each, as computed by
    ///   [`bitmap_word_free_blocks_lsbs()`](Self::bitmap_word_free_blocks_lsbs).
    ///   There must be at least one bit set with its buddy clear -- for
    ///   otherwise every free aligned block of size as specified by
    ///   `block_allocation_blocks_log2` would be contained in some larger
    ///   aligned block, in violation of the assumption.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size to
    ///   to select a free block of.
    /// * `bitmap_word_blocks_lsbs_mask` - Mask of equidistant set bits,
    ///   separated by two to the power of `block_allocation_blocks_log2` each.
    /// * `bitmap_word_blocks_lsbs_mask_table` - Reference to a
    ///   [`BitmapWordBlocksLsbsMaskTable`] instance.
    fn bitmap_word_block_alloc_select_block(
        mut bitmap_word_free_blocks_lsbs: BitmapWord,
        block_allocation_blocks_log2: u32,
        bitmap_word_blocks_lsbs_mask: BitmapWord,
        bitmap_word_blocks_lsbs_mask_table: &BitmapWordBlocksLsbsMaskTable,
    ) -> u32 {
        debug_assert_eq!(
            bitmap_word_blocks_lsbs_mask,
            bitmap_word_blocks_lsbs_mask_table.get_blocks_lsbs_mask(block_allocation_blocks_log2)
        );
        debug_assert_eq!(bitmap_word_free_blocks_lsbs & !bitmap_word_blocks_lsbs_mask, 0);
        // It is assumed that the input block_allocation_blocks_log2 has been increased
        // to the minimum required split block size already.
        debug_assert!(
            block_allocation_blocks_log2 == BITMAP_WORD_BITS_LOG2
                || block_allocation_blocks_log2
                    == Self::bitmap_word_block_alloc_split_block_size_log2(
                        bitmap_word_free_blocks_lsbs,
                        None,
                        block_allocation_blocks_log2,
                        bitmap_word_blocks_lsbs_mask,
                        bitmap_word_blocks_lsbs_mask_table
                    )
        );
        if block_allocation_blocks_log2 < BITMAP_WORD_BITS_LOG2 - 1 {
            let double_block_allocations_block_log2 = block_allocation_blocks_log2 + 1;
            let word_double_blocks_lsbs_mask =
                bitmap_word_blocks_lsbs_mask_table.get_blocks_lsbs_mask(double_block_allocations_block_log2);
            bitmap_word_free_blocks_lsbs = Self::bitmap_word_filter_blocks_with_free_buddy_lsbs(
                bitmap_word_free_blocks_lsbs,
                bitmap_word_free_blocks_lsbs,
                block_allocation_blocks_log2,
                word_double_blocks_lsbs_mask,
            );
        }
        debug_assert_ne!(bitmap_word_free_blocks_lsbs, 0);
        bitmap_word_free_blocks_lsbs.trailing_zeros()
    }

    /// Find free blocks of size and alignment a specified power of two in a
    /// [`BitmapWord`].
    ///
    /// Examine `bitmap_word` and set the least significant bit in each group of
    /// bits corresponding to a free block of size and alignment equal to two to
    /// the power of `block_allocation_blocks_log2` each.
    ///
    /// # Arguments:
    ///
    /// * `bitmap_word` - The [`BitmapWord`] to examine for free aligned blocks.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the desired block
    ///   size and alignment.
    /// * `bitmap_word_blocks_lsbs_mask` - Mask of equidistant set bits,
    ///   separated by two to the power of `block_allocation_blocks_log2` each.
    fn bitmap_word_free_blocks_lsbs(
        bitmap_word: BitmapWord,
        block_allocation_blocks_log2: u32,
        bitmap_word_blocks_lsbs_mask: BitmapWord,
    ) -> BitmapWord {
        Self::bitmap_word_nonzero_blocks_lsbs(bitmap_word, block_allocation_blocks_log2, bitmap_word_blocks_lsbs_mask)
            ^ bitmap_word_blocks_lsbs_mask
    }

    /// Filter free blocks within a [`BitmapWord`] with an associated free
    /// buddy.
    ///
    /// Partition the [`BitmapWord`]'s bits into "buddy" pairs of blocks, with
    /// each such block's size and alignment equal to two to the power of
    /// `block_allocation_blocks_log2`. Retain from the
    /// `bitmap_word_free_blocks_lsbs` only those least significant set bits
    /// in each group of bits corresponding to an aligned block of specified
    /// size for which the one from the associated buddy is clear.
    /// Finally, mask the result by `bitmap_word_candidate_blocks_lsbs`.
    ///
    /// # Arguments:
    ///
    /// * `bitmap_word_candidate_blocks_lsbs` - Mask to apply to the result
    ///   before returning.
    /// * `bitmap_word_free_blocks_lsbs` - Bitmask with its bits logically
    ///   partitioned into groups of the block size each, and the least
    ///   significant bit in each such group set if and only if the
    ///   corresponding block is considered free.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size
    ///   and alignment.
    /// * `bitmap_word_double_blocks_lsbs_mask` - Mask of equidistant set bits,
    ///   separated by twice the value of two to the power of
    ///   `block_allocation_blocks_log2` each.
    fn bitmap_word_filter_blocks_with_free_buddy_lsbs(
        bitmap_word_candidate_blocks_lsbs: BitmapWord,
        bitmap_word_free_blocks_lsbs: BitmapWord,
        block_allocation_blocks_log2: u32,
        bitmap_word_double_blocks_lsbs_masks: BitmapWord,
    ) -> BitmapWord {
        let block_allocation_blocks = 1u32 << block_allocation_blocks_log2;
        debug_assert!(block_allocation_blocks < BitmapWord::BITS);
        // Interchange the buddy block pairs in bitmap_word_free_blocks_lsbs.
        let t1 = (bitmap_word_free_blocks_lsbs ^ (bitmap_word_free_blocks_lsbs >> block_allocation_blocks))
            & bitmap_word_double_blocks_lsbs_masks;
        let t2 = t1 << block_allocation_blocks;
        let swapped_bitmap_word_free_blocks_lsbs = bitmap_word_free_blocks_lsbs ^ t1 ^ t2;
        // Invert to go from "free buddy" mask to "allocated buddy" mask.
        let mask = !swapped_bitmap_word_free_blocks_lsbs;
        bitmap_word_candidate_blocks_lsbs & mask
    }

    /// Find non-zero blocks of size and alignment equal to a specified power of
    /// two in a [`BitmapWord`].
    ///
    /// Partition a [`BitmapWord`]'s bit into blocks of size equal to two to the
    /// power of `block_allocation_blocks_log2` each and return the result of
    /// setting the least significant bit in each group if and only if the
    /// corresponding group in the input `bitmap_word` has at least one of its
    /// bits set.
    ///
    /// # Arguments:
    ///
    /// * `bitmap_word` - The [`BitmapWord`] value to examine.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size
    ///   and alignment.
    /// * `bitmap_word_blocks_lsbs_mask` - Mask of equidistant set bits,
    ///   separated by two to the power of `block_allocation_blocks_log2` each.
    fn bitmap_word_nonzero_blocks_lsbs(
        bitmap_word: BitmapWord,
        block_allocation_blocks_log2: u32,
        bitmap_word_blocks_lsbs_mask: BitmapWord,
    ) -> BitmapWord {
        let block_allocation_blocks = 1u32 << block_allocation_blocks_log2;
        (((((bitmap_word & !bitmap_word_blocks_lsbs_mask) >> 1) + ((!bitmap_word_blocks_lsbs_mask) >> 1))
            >> (block_allocation_blocks - 1))
            | bitmap_word)
            & bitmap_word_blocks_lsbs_mask
    }

    /// Create a block field selection [`BitmapWord`] mask.
    ///
    /// Partition a [`BitmapWord`]'s bits into groups of length equal to two to
    /// the power of `block_allocation_blocks_log2` each. Return a value
    /// with all bits set in each such group if and only if the corresponding
    /// group's least significant bit in the input `selected_blocks_lsbs` is
    /// set.
    ///
    /// # Arguments:
    ///
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size
    ///   and alignment.
    /// * `selected_blocks_lsbs` - Block selection mask. A block is selected if
    ///   and only if its least significant bit in this mask is set.
    fn bitmap_word_blocks_select_mask(
        block_allocation_blocks_log2: u32,
        selected_blocks_lsbs: BitmapWord,
    ) -> BitmapWord {
        let block_allocation_blocks = 1u32 << block_allocation_blocks_log2;
        let selected_blocks_msbs = selected_blocks_lsbs << (block_allocation_blocks - 1);
        (selected_blocks_msbs - selected_blocks_lsbs) | selected_blocks_msbs
    }

    /// Determine the lengths of longest 1-strings within each of a
    /// [`BitmapWord`]'s blocks of specified width.
    ///
    /// Partition the input `bitmap_word`'s bits into blocks of size equal to
    /// two to the power of `block_allocation_blocks_log2` each. Find
    /// the longest string of consecutive ones subject to the
    /// alignment contraints specified via
    /// `str_alignment_allocation_blocks_log2` within each such block.
    /// Return a pair of the longest string found among all of the blocks, as
    /// well as a packed integer specifying the per-block results in fields
    /// of the block width each.
    ///
    /// # Arguments:
    ///
    /// * `bitmap_word` - The [`BitmapWord`] value to examine.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size
    ///   and alignment.
    /// * `bitmap_word_blocks_lsbs_mask` - Mask of equidistant set bits,
    ///   separated by two to the power of `block_allocation_blocks_log2` each.
    /// * `str_alignment_allocation_blocks_log2` - Alignment constrained on the
    ///   1-strings.
    /// * `bitmap_word_str_alignment_anchors_mask` - Mask of equidistant set
    ///   bits, separated by two to the power of
    ///   `str_alignment_allocation_blocks_log2` each.
    fn bitmap_word_blocks_maxstr_lens(
        mut bitmap_word: BitmapWord,
        block_allocation_blocks_log2: u32,
        bitmap_word_blocks_lsbs_mask: BitmapWord,
        str_alignment_allocation_blocks_log2: u32,
        bitmap_word_str_alignment_anchors_mask: BitmapWord,
    ) -> (u32, BitmapWord) {
        debug_assert!(str_alignment_allocation_blocks_log2 < block_allocation_blocks_log2);
        // This is a modified variant of the algorithm from Hacker's Delight, 2nd
        // edition, 6-3 ("Find longest string of 1-Bits") working on individual
        // fields of block_allocation_blocks bit width each and, moreover,
        // considering only 1-strings of specified alignment, if desired.
        if bitmap_word == 0 {
            return (0, 0);
        }

        // "Zeroth", preprocessing part: enforce the specified alignment on the found
        // 1-strings.
        let mut s_log2 = 0u32;
        let mut mask = bitmap_word_blocks_lsbs_mask;
        while s_log2 < str_alignment_allocation_blocks_log2 {
            bitmap_word &= bitmap_word << (1 << s_log2);
            // Applying the mask prevents strings in neighbouring blocks from combining.
            bitmap_word &= !mask;
            mask |= mask << (1 << s_log2);
            s_log2 += 1;
        }
        // Only retain those bits at the head (most significant first order) of
        // *aligned* strings. This will henceforth ensure that all considered
        // 1-strings are aligned with respect to both, the starting position as
        // well as their respective lengths.
        bitmap_word &= bitmap_word_str_alignment_anchors_mask << ((1 << str_alignment_allocation_blocks_log2) - 1);
        if bitmap_word == 0 {
            return (0, 0);
        }

        // First part: determine the maximum power of two less or equal than the length
        // of the longest string of consecutive ones, it will be refined by the
        // backtracking part below.
        let block_allocation_blocks = 1u32 << block_allocation_blocks_log2;
        let mut s_per_block = Self::bitmap_word_nonzero_blocks_lsbs(
            bitmap_word,
            block_allocation_blocks_log2,
            bitmap_word_blocks_lsbs_mask,
        ) << str_alignment_allocation_blocks_log2;
        while s_log2 < block_allocation_blocks_log2 {
            // Test for bitstrings of lengths at least 2 * (1 << s_log2).
            // The heading bit(s) of any such string in the original input will remain set.
            let mut y = bitmap_word & (bitmap_word << (1 << s_log2));
            // Applying the mask prevents strings in neighbouring blocks from combining.
            y &= !mask;
            mask |= mask << (1 << s_log2);
            debug_assert!(y & bitmap_word_blocks_lsbs_mask == 0);
            let mut nonzero_blocks_lsbs = (((y >> 1) + (!bitmap_word_blocks_lsbs_mask >> 1))
                >> (block_allocation_blocks - 1))
                & bitmap_word_blocks_lsbs_mask;
            // Only consider blocks which are still in the game -- otherwise disconnected
            // chunks within a block might eventually combine, which would be
            // invalid.
            nonzero_blocks_lsbs &= s_per_block >> s_log2;
            if nonzero_blocks_lsbs == 0 {
                break;
            }
            // The addition actually doubles the value in each block field where
            // nonzero_blocks_lsbs is (still) set.
            s_per_block += nonzero_blocks_lsbs << s_log2;
            // Update the bitmap_word block fields with the non-zero ones from y.
            let nonzero_blocks_select_mask =
                Self::bitmap_word_blocks_select_mask(block_allocation_blocks_log2, nonzero_blocks_lsbs);
            bitmap_word = bitmap_word ^ ((bitmap_word ^ y) & nonzero_blocks_select_mask);
            s_log2 += 1;
        }

        // Second part: backtracking to refine the found s-value. From part 1 above, the
        // most significant set bit of each block's maximum 1-bit string length
        // is known. Process the remaining less significant bits of the
        // respective length values from most to least significant and set them
        // as appropriate.
        let mut s_max = 1u32 << s_log2;
        // For reporting an accurate s_max back, keep track of the set of blocks
        // (potentially still) having a maximum 1-bit string of the maximum
        // length across all blocks. To be more specific, this set comprises all
        // blocks with a common prefix in their respective maxstr length values
        // up to the current position, equal to the prefix of the of the maximum
        // across all blocks as determined up the current position.
        let mut blocks_with_max_str_lsbs = (s_per_block >> s_log2) & bitmap_word_blocks_lsbs_mask;
        // In each iteration, consider only those blocks which have an initial s-value
        // (as determined in the previous loop) greater than the current s_delta
        // below. Note that this set grows with decreasing s_log2.
        let mut blocks_with_s_str_lsbs: BitmapWord = blocks_with_max_str_lsbs;
        while s_log2 > 0 {
            s_log2 -= 1;
            let s_delta = 1u32 << s_log2;
            let y = bitmap_word & (bitmap_word << s_delta);
            if y != 0 {
                debug_assert!(y & blocks_with_s_str_lsbs == 0);
                // Instead of and'ing with bitmap_word_blocks_lsbs_mask, and with
                // blocks_with_s_str_lsbs directly to save an additional and
                // operation.
                let nonzero_blocks_lsbs = (((y >> 1) + (!bitmap_word_blocks_lsbs_mask >> 1))
                    >> (block_allocation_blocks - 1))
                    & blocks_with_s_str_lsbs;
                s_per_block |= nonzero_blocks_lsbs << s_log2;
                // Update the bitmap_word block fields with the non-zero ones from y.
                let nonzero_blocks_select_mask =
                    Self::bitmap_word_blocks_select_mask(block_allocation_blocks_log2, nonzero_blocks_lsbs);
                bitmap_word = bitmap_word ^ ((bitmap_word ^ y) & nonzero_blocks_select_mask);
                if blocks_with_max_str_lsbs & nonzero_blocks_lsbs != 0 {
                    // All blocks which do not have the current bit set in their resp. maxstr
                    // lengths, cannot attain the maximum across all blocks anymore.
                    blocks_with_max_str_lsbs &= nonzero_blocks_lsbs;
                    s_max |= s_delta;
                }
            }
            blocks_with_s_str_lsbs |= (s_per_block >> s_log2) & bitmap_word_blocks_lsbs_mask;
        }

        (s_max, s_per_block)
    }

    /// Packed integer `<=` comparison.
    ///
    /// Interpret `x` and `y` as sequences of packed integers with a width of
    /// two to the power of `block_allocation_blocks_log2` stored in a
    /// [`BitmapWord`] each. Compare the corresponding packed integer fields
    /// of `x` and `y` each and return the result as a sequence of packed
    /// integers of matching format with their least significant bits set if
    /// and only if the the corresponding packed integer field from `x` compares
    /// as less than or equal to the one from `y`.
    ///
    /// # Arguments:
    /// `x` - Packed first operand integers.
    /// `y` - Packed second operand integers.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size
    ///   and alignment.
    /// * `bitmap_word_blocks_lsbs_mask` - Mask of equidistant set bits,
    ///   separated by two to the power of `block_allocation_blocks_log2` each.
    fn bitmap_word_blocks_fields_geq_lsbs(
        x: BitmapWord,
        y: BitmapWord,
        block_allocation_blocks_log2: u32,
        bitmap_word_blocks_lsbs_mask: BitmapWord,
    ) -> BitmapWord {
        // Adapted from the subtraction algorithm in Hacker's Delight, 2nd edition,
        // 2-18 ("Multibyte Add, Subtract, Absolute Value")
        let block_allocation_blocks = 1u32 << block_allocation_blocks_log2;
        let bitmap_word_blocks_msbs_mask = bitmap_word_blocks_lsbs_mask << (block_allocation_blocks - 1);

        // The MSBs in each block of d are set iff there's no borrow carried into that
        // position.
        let d = (x | bitmap_word_blocks_msbs_mask) - (y & !bitmap_word_blocks_msbs_mask);
        // Set each block's MSB iff no borrow would be carried out of that position.
        let no_borrow_msbs = (x | (!y & d)) & (!y | d);
        (no_borrow_msbs >> (block_allocation_blocks - 1)) & bitmap_word_blocks_lsbs_mask
    }

    /// Packed integer subtraction.
    ///
    /// Interpret `x` and `y` as sequences of packed integers with a width of
    /// two to the power of `block_allocation_blocks_log2` stored in a
    /// [`BitmapWord`] each. Subtract the corresponding packed integer fields
    /// of `x` and `y` modulo (two to the power of) the block size each and
    /// return the result as a sequence of packed integers of matching
    /// format.
    ///
    /// # Arguments:
    /// `x` - Packed first operand integers.
    /// `y` - Packed second operand integers.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size
    ///   and alignment.
    /// * `bitmap_word_blocks_lsbs_mask` - Mask of equidistant set bits,
    ///   separated by two to the power of `block_allocation_blocks_log2` each.
    fn bitmap_word_blocks_fields_sub(
        x: BitmapWord,
        y: BitmapWord,
        block_allocation_blocks_log2: u32,
        bitmap_word_blocks_lsbs_mask: BitmapWord,
    ) -> BitmapWord {
        // C.f. Hacker's Delight, 2nd edition, 2-18 ("Multibyte Add, Subtract, Absolute
        // Value")
        let block_allocation_blocks = 1u32 << block_allocation_blocks_log2;
        let bitmap_word_blocks_msbs_mask = bitmap_word_blocks_lsbs_mask << (block_allocation_blocks - 1);

        let d = (x | bitmap_word_blocks_msbs_mask) - (y & !bitmap_word_blocks_msbs_mask);
        !(((x ^ y) | !bitmap_word_blocks_msbs_mask) ^ d)
    }
}

/// [`Iterator`] over an [`AllocBitmap`]'s [`BitmapWord`]s.
pub(super) struct AllocBitmapWordIterator<'a, const AN: usize, const FN: usize> {
    bitmap: &'a AllocBitmap,
    pending_allocs_iter: SparseAllocBitmapUnionWordIterator<'a, AN>,
    next_pending_alloc: Option<(u64, BitmapWord)>,
    pending_frees_iter: SparseAllocBitmapUnionWordIterator<'a, FN>,
    next_pending_free: Option<(u64, BitmapWord)>,
    next_bitmap_word_index: u64,
}

impl<'a, const AN: usize, const FN: usize> AllocBitmapWordIterator<'a, AN, FN> {
    pub(super) fn new_at_bitmap_word_index(
        bitmap: &'a AllocBitmap,
        pending_allocs: &'a SparseAllocBitmapUnion<'a, AN>,
        pending_frees: &'a SparseAllocBitmapUnion<'a, FN>,
        bitmap_word_index_begin: u64,
    ) -> Self {
        let (mut pending_allocs_iter, mut pending_frees_iter) = if bitmap_word_index_begin == 0 {
            (pending_allocs.iter(), pending_frees.iter())
        } else {
            (
                pending_allocs.iter_at_bitmap_word_index(bitmap_word_index_begin),
                pending_frees.iter_at_bitmap_word_index(bitmap_word_index_begin),
            )
        };

        let next_pending_alloc = pending_allocs_iter.next();
        let next_pending_free = pending_frees_iter.next();

        Self {
            bitmap,
            pending_allocs_iter,
            next_pending_alloc,
            pending_frees_iter,
            next_pending_free,
            next_bitmap_word_index: bitmap_word_index_begin,
        }
    }

    fn goto_bitmap_word_index(&mut self, bitmap_word_index: u64) {
        if self.next_bitmap_word_index == bitmap_word_index {
            return;
        }

        self.pending_allocs_iter.goto_bitmap_word_index(bitmap_word_index);
        self.next_pending_alloc = self.pending_allocs_iter.next();

        self.pending_frees_iter.goto_bitmap_word_index(bitmap_word_index);
        self.next_pending_free = self.pending_frees_iter.next();

        self.next_bitmap_word_index = bitmap_word_index;
    }
}

impl<'a, const AN: usize, const FN: usize> Iterator for AllocBitmapWordIterator<'a, AN, FN> {
    type Item = (u64, BitmapWord);

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_bitmap_word_index >= self.bitmap.bitmap.len() as u64 {
            return None;
        }

        let bitmap_word_index = self.next_bitmap_word_index;
        self.next_bitmap_word_index += 1;
        let mut bitmap_word = self.bitmap.bitmap[bitmap_word_index as usize];

        if let Some(pending_alloc) = &self.next_pending_alloc {
            if pending_alloc.0 == bitmap_word_index {
                bitmap_word |= pending_alloc.1;
                self.next_pending_alloc = self.pending_allocs_iter.next();
            }
        }
        if let Some(pending_free) = &self.next_pending_free {
            if pending_free.0 == bitmap_word_index {
                bitmap_word &= !pending_free.1;
                self.next_pending_free = self.pending_frees_iter.next();
            }
        }

        Some((bitmap_word_index, bitmap_word))
    }
}

/// [`Iterator`] returned by [`AllocBitmap::iter_at_allocation_block()`].
pub struct AllocBitmapIterator<'a, const AN: usize, const FN: usize> {
    bitmap_word_iter: AllocBitmapWordIterator<'a, AN, FN>,
    cur_bitmap_word: Option<BitmapWord>,
    next_pos_in_cur_bitmap_word: u32,
}

impl<'a, const AN: usize, const FN: usize> AllocBitmapIterator<'a, AN, FN> {
    fn new_at(
        bitmap: &'a AllocBitmap,
        pending_allocs: &'a SparseAllocBitmapUnion<'a, AN>,
        pending_frees: &'a SparseAllocBitmapUnion<'a, FN>,
        first_physical_allocation_block_index: layout::PhysicalAllocBlockIndex,
    ) -> Self {
        let first_physical_allocation_block_index = u64::from(first_physical_allocation_block_index);
        let bitmap_word_index_begin = first_physical_allocation_block_index >> BITMAP_WORD_BITS_LOG2;
        let next_pos_in_cur_bitmap_word =
            (first_physical_allocation_block_index & BitmapWord::trailing_bits_mask(BITMAP_WORD_BITS_LOG2)) as u32;

        let mut bitmap_word_iter = AllocBitmapWordIterator::new_at_bitmap_word_index(
            bitmap,
            pending_allocs,
            pending_frees,
            bitmap_word_index_begin,
        );
        let cur_bitmap_word = bitmap_word_iter.next().map(|v| v.1);
        Self {
            bitmap_word_iter,
            cur_bitmap_word,
            next_pos_in_cur_bitmap_word,
        }
    }
}

impl<'a, const AN: usize, const FN: usize> Iterator for AllocBitmapIterator<'a, AN, FN> {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        let cur_bitmap_word = self.cur_bitmap_word?;
        let bit = (cur_bitmap_word >> self.next_pos_in_cur_bitmap_word) & 1 != 0;
        self.next_pos_in_cur_bitmap_word += 1;
        if self.next_pos_in_cur_bitmap_word == BitmapWord::BITS {
            self.next_pos_in_cur_bitmap_word = 0;
            self.cur_bitmap_word = self.bitmap_word_iter.next().map(|v| v.1);
        }
        Some(bit)
    }
}

/// [`Iterator`] returned by
/// [`AllocBitmap::iter_chunked_at_allocation_block()`].
pub struct AllocBitmapChunkedIterator<'a, const AN: usize, const FN: usize> {
    bitmap_word_iter: AllocBitmapWordIterator<'a, AN, FN>,
    cur_bitmap_word: Option<BitmapWord>,
    next_pos_in_cur_bitmap_word: u32,
    chunk_allocation_blocks: u32,
}

impl<'a, const AN: usize, const FN: usize> AllocBitmapChunkedIterator<'a, AN, FN> {
    fn new_at(
        bitmap: &'a AllocBitmap,
        pending_allocs: &'a SparseAllocBitmapUnion<'a, AN>,
        pending_frees: &'a SparseAllocBitmapUnion<'a, FN>,
        first_physical_allocation_block_index: layout::PhysicalAllocBlockIndex,
        chunk_allocation_blocks: u32,
    ) -> Self {
        debug_assert!(chunk_allocation_blocks <= BitmapWord::BITS);
        let first_physical_allocation_block_index = u64::from(first_physical_allocation_block_index);
        let bitmap_word_index_begin = first_physical_allocation_block_index >> BITMAP_WORD_BITS_LOG2;
        let next_pos_in_cur_bitmap_word =
            (first_physical_allocation_block_index & BitmapWord::trailing_bits_mask(BITMAP_WORD_BITS_LOG2)) as u32;

        let mut bitmap_word_iter = AllocBitmapWordIterator::new_at_bitmap_word_index(
            bitmap,
            pending_allocs,
            pending_frees,
            bitmap_word_index_begin,
        );
        let cur_bitmap_word = bitmap_word_iter.next().map(|v| v.1);
        Self {
            bitmap_word_iter,
            cur_bitmap_word,
            next_pos_in_cur_bitmap_word,
            chunk_allocation_blocks,
        }
    }

    pub fn goto(&mut self, physical_allocation_block_index: layout::PhysicalAllocBlockIndex) {
        let physical_allocation_block_index = u64::from(physical_allocation_block_index);
        let bitmap_word_index = physical_allocation_block_index >> BITMAP_WORD_BITS_LOG2;
        self.next_pos_in_cur_bitmap_word =
            (physical_allocation_block_index & BitmapWord::trailing_bits_mask(BITMAP_WORD_BITS_LOG2)) as u32;
        self.bitmap_word_iter.goto_bitmap_word_index(bitmap_word_index);
        self.cur_bitmap_word = self.bitmap_word_iter.next().map(|v| v.1);
    }
}

impl<'a, const AN: usize, const FN: usize> Iterator for AllocBitmapChunkedIterator<'a, AN, FN> {
    type Item = BitmapWord;

    fn next(&mut self) -> Option<Self::Item> {
        let cur_bitmap_word = self.cur_bitmap_word?;
        let mut cur_chunk = cur_bitmap_word >> self.next_pos_in_cur_bitmap_word;
        self.next_pos_in_cur_bitmap_word += self.chunk_allocation_blocks;

        if self.next_pos_in_cur_bitmap_word >= BitmapWord::BITS {
            self.next_pos_in_cur_bitmap_word -= BitmapWord::BITS;
            self.cur_bitmap_word = self.bitmap_word_iter.next().map(|v| v.1);
            if self.next_pos_in_cur_bitmap_word > 0 {
                let cur_bitmap_word = self.cur_bitmap_word.unwrap_or(0);
                cur_chunk |= cur_bitmap_word << (self.chunk_allocation_blocks - self.next_pos_in_cur_bitmap_word)
            }
        }

        Some(cur_chunk & BitmapWord::trailing_bits_mask(self.chunk_allocation_blocks))
    }
}
