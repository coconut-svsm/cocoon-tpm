// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`TransactionWriteDirtyDataFuture`].

extern crate alloc;
use alloc::boxed::Box;

use super::{
    Transaction,
    auth_tree_data_blocks_update_states::{
        AllocationBlockUpdateNvSyncState, AllocationBlockUpdateNvSyncStateAllocated,
        AllocationBlockUpdateNvSyncStateAllocatedModified, AuthTreeDataBlocksUpdateStatesAllocationBlockIndex,
        AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets, AuthTreeDataBlocksUpdateStatesIndex,
        AuthTreeDataBlocksUpdateStatesIndexRange,
    },
    journal_allocations::TransactionAllocateJournalStagingCopiesFuture,
    read_missing_data::TransactionReadMissingDataFuture,
};
use crate::{
    blkdev::{self, ChunkedIoRegion, ChunkedIoRegionChunkRange},
    crypto::rng,
    fs::{
        NvFsError,
        cocoonfs::{
            fs::{CocoonFsSyncStateMemberRef, CocoonFsSyncStateReadFuture},
            layout,
        },
    },
    nvblkdev_err_internal, nvfs_err_internal,
    utils_async::sync_types,
    utils_common::{
        fixed_vec::FixedVec,
        io_slices::{self, IoSlicesIterCommon as _},
    },
};
use core::{pin, task};

#[cfg(doc)]
use super::auth_tree_data_blocks_update_states::{AuthTreeDataBlockUpdateState, AuthTreeDataBlocksUpdateStates};

/// Write dirty data to storage.
///
/// Write all data tracked as dirty within a specified [Allocation Block level
/// index range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange) in
/// the [`Transaction`]'s [storage tracking
/// states](AllocationBlockUpdateNvSyncState)' buffers to the associated
/// [journal
/// staging copies](AuthTreeDataBlockUpdateState::get_journal_staging_copy_allocation_blocks_begin)
/// on storage.
///
/// [Journal staging
/// copies](AuthTreeDataBlockUpdateState::get_journal_staging_copy_allocation_blocks_begin) will get
/// allocated as needed in case there's any dirty [storage tracking
/// state](AllocationBlockUpdateNvSyncState) in the range with none associated
/// yet.
///
/// Only
/// [`AllocationBlockUpdateState`](super::auth_tree_data_blocks_update_states::AllocationBlockUpdateState)s
/// existing within the requested range at the time of
/// `TransactionWriteDirtyDataFuture` instantiation will be considered.
/// Additional ones may get inserted, populated and written out as a byproduct
/// for [IO Block](layout::ImageLayout::io_block_allocation_blocks_log2)
/// alignment purposes in the course though.
pub(super) struct TransactionWriteDirtyDataFuture<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev> {
    request_states_allocation_blocks_index_range: AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    request_states_range_offsets: Option<AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets>,
    min_clean_block_allocation_blocks_log2: u8,
    remaining_states_allocation_blocks_index_range: AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    fut_state: TransactionWriteDirtyDataFutureState<ST, B>,
}

/// [`TransactionWriteDirtyDataFuture`] state-machine state.
enum TransactionWriteDirtyDataFutureState<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev> {
    Init {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<Transaction>>,
    },
    RegionReadMissing {
        cur_aligned_write_region_states_allocation_blocks_index_range:
            AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        cur_aligned_write_region_read_missing_fut: TransactionReadMissingDataFuture<B>,
    },
    RegionAllocateJournalStagingCopyBlocks {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        cur_aligned_write_region_states_allocation_blocks_index_range:
            AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        cur_aligned_write_region_allocate_journal_staging_copy_blocks_fut:
            TransactionAllocateJournalStagingCopiesFuture<ST, B>,
    },
    RegionWrite {
        cur_aligned_write_region_states_allocation_blocks_index_range:
            AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        cur_aligned_write_region_write_fut: B::WriteFuture<TransactionWriteDirtyDataNvBlkDevWriteRequest>,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev> TransactionWriteDirtyDataFuture<ST, B> {
    /// Instantiate a [`TransactionWriteDirtyDataFuture`].
    ///
    /// The [`TransactionWriteDirtyDataFuture`] assumes
    /// ownership of the `transaction` for the duration of the operation, it
    /// will eventually get returned back from [`poll()`](Self::poll) upon
    /// completion.
    ///
    /// # Arguments:
    ///
    /// * `transaction` - The [`Transaction`] whose [storage tracking
    ///   states](AllocationBlockUpdateNvSyncState)' buffers to populate.
    /// * `states_allocation_blocks_index_range` - The [Allocation Block level
    ///   entry index
    ///   range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange) to
    ///   write out dirty [storage tracking
    ///   states](AllocationBlockUpdateNvSyncState)' buffers within. Applicable
    ///   [correction
    ///   offsets](AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets)
    ///   will get returned from [`poll()`](Self::poll) upon completion in case
    ///   additional state entries had to get inserted in order to [fill
    ///   alignment gaps](AuthTreeDataBlocksUpdateStates::fill_states_index_range_regions_alignment_gaps).
    /// * `min_clean_block_allocation_blocks_log2` - Base-2 logarithm of the
    ///   Minimum Clean Block size in units of [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2). In
    ///   general, a [storage tracking state](AllocationBlockUpdateNvSyncState)'
    ///   buffer will not get written, dirty or not, unless its contained in
    ///   some Minimum Clean Block having some actual data modifications to it.
    pub fn new(
        transaction: Box<Transaction>,
        states_allocation_blocks_index_range: &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        min_clean_block_allocation_blocks_log2: u8,
    ) -> Result<Self, (Box<Transaction>, NvFsError)> {
        let allocation_block_size_128b_log2 = transaction.allocation_block_size_128b_log2 as u32;
        let blkdev_io_block_size_128b_log2 = transaction.blkdev_io_block_size_128b_log2;

        // If only_regions_with_modified_dirty is true, then write out regions aligned
        // to a block size as small as the minimum supported by the storage
        // device. If OTOH only_regions_with_modified_dirty is false, then full
        // IO Blocks (containing any modification, dirty or not) shall get moved
        // to the clean state as a whole.
        let io_block_allocation_blocks_log2 = transaction.io_block_allocation_blocks_log2 as u32;
        let min_write_block_allocation_blocks_log2 = Self::min_write_block_allocation_blocks_log2(
            blkdev_io_block_size_128b_log2,
            allocation_block_size_128b_log2,
        );
        if min_write_block_allocation_blocks_log2 > io_block_allocation_blocks_log2 {
            return Err((transaction, nvfs_err_internal!()));
        }

        // Possibly extend the range to also cover all already present states within the
        // reach of its Minimum Clean Block alignment padding, if any.
        let remaining_states_allocation_blocks_index_range = transaction
            .auth_tree_data_blocks_update_states
            .extend_states_allocation_blocks_index_range_within_alignment(
                states_allocation_blocks_index_range,
                min_write_block_allocation_blocks_log2.max(min_clean_block_allocation_blocks_log2 as u32),
            );

        Ok(Self {
            request_states_allocation_blocks_index_range: states_allocation_blocks_index_range.clone(),
            request_states_range_offsets: None,
            min_clean_block_allocation_blocks_log2,
            remaining_states_allocation_blocks_index_range,
            fut_state: TransactionWriteDirtyDataFutureState::Init {
                transaction: Some(transaction),
            },
        })
    }

    /// Determine the minimum IO block size.
    ///
    /// Return the base-2 logarithm of the minimum IO block size in units of
    /// [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    ///
    /// # Arguments:
    ///
    /// * `blkdev_io_block_size_128b_log2` - Value of
    ///   [`NvBlkDev::io_block_size_128b_log2()`](blkdev::NvBlkDev::io_block_size_128b_log2).
    /// * `allocation_block_size_128b_log2` - Verbatim value of
    ///   [`ImageLayout::allocation_block_size_128b_log2`](layout::ImageLayout::allocation_block_size_128b_log2).
    pub fn min_write_block_allocation_blocks_log2(
        blkdev_io_block_size_128b_log2: u32,
        allocation_block_size_128b_log2: u32,
    ) -> u32 {
        min_write_block_allocation_blocks_log2(blkdev_io_block_size_128b_log2, allocation_block_size_128b_log2)
    }

    /// Determine the next subrange to write.
    ///
    /// Return a pair of the next subrange to write, if any, and the remainder
    /// of `remaining_states_allocation_blocks_index_range` to process in a
    /// subsequent iteration.
    ///
    /// # Arguments:
    ///
    /// * `remaining_states_allocation_blocks_index_range` - Remaining part of
    ///   the initial request range not processed yet, extended to cover any
    ///   preexisting states within the vicinity of a [`minimum IO
    ///   Block`](Self::min_write_block_allocation_blocks_log2) or a Minimum
    ///   Clean Block as specified to [`new()`](Self::new), whichever is larger.
    fn determine_next_write_region(
        &self,
        transaction: &Transaction,
        remaining_states_allocation_blocks_index_range: &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    ) -> (
        Option<AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange>,
        AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    ) {
        if remaining_states_allocation_blocks_index_range.is_empty() {
            return (None, remaining_states_allocation_blocks_index_range.clone());
        }

        let allocation_block_size_128b_log2 = transaction.allocation_block_size_128b_log2 as u32;
        let auth_tree_data_block_allocation_blocks_log2 =
            transaction.auth_tree_data_block_allocation_blocks_log2 as u32;
        let io_block_allocation_blocks_log2 = transaction.io_block_allocation_blocks_log2 as u32;
        let blkdev_io_block_size_128b_log2 = transaction.blkdev_io_block_size_128b_log2;
        let preferred_blkdev_io_blocks_bulk_log2 = transaction.preferred_blkdev_io_blocks_bulk_log2;

        let mut remaining_states_allocation_blocks_index_range = remaining_states_allocation_blocks_index_range.clone();
        let states = &transaction.auth_tree_data_blocks_update_states;
        let min_write_block_allocation_blocks_log2 = Self::min_write_block_allocation_blocks_log2(
            blkdev_io_block_size_128b_log2,
            allocation_block_size_128b_log2,
        );
        let min_clean_block_allocation_blocks_log2 =
            min_write_block_allocation_blocks_log2.max(self.min_clean_block_allocation_blocks_log2 as u32);
        // Determine the preferred Bulk IO size: consider the value announced by the
        // NvBlkDev, but ramp it up to some larger reasonable value in order to
        // reduce the overall number of IO requests.
        let preferred_write_block_allocation_blocks_log2 = (preferred_blkdev_io_blocks_bulk_log2
            + blkdev_io_block_size_128b_log2)
            .saturating_sub(allocation_block_size_128b_log2)
            .min(usize::BITS - 1)
            .max(auth_tree_data_block_allocation_blocks_log2);

        let mut cur_min_write_block_any_dirty = false;
        // If the previous invocation returned a range ending in the middle of some
        // Minimum Clean Block, then it did find something to write, which
        // means it found something in modified state.
        let first_min_write_block_target_allocation_blocks_begin = states
            .get_allocation_block_target(remaining_states_allocation_blocks_index_range.begin())
            .align_down(min_write_block_allocation_blocks_log2);
        let mut cur_min_clean_block_any_modified = if let Some(preceding_states_allocation_block_index) =
            remaining_states_allocation_blocks_index_range
                .begin()
                .step_back(auth_tree_data_block_allocation_blocks_log2)
        {
            // Check whether this is a continuation of the same Minimum Clean Block stopped
            // within in the preceding invocation.
            (u64::from(first_min_write_block_target_allocation_blocks_begin)
                ^ u64::from(states.get_allocation_block_target(&preceding_states_allocation_block_index)))
                >> min_clean_block_allocation_blocks_log2
                == 0
        } else {
            false
        };

        // Last Allocation Block in a found candidate region of contiguous dirty states.
        // It might not be known for some tail part of whether it needs a
        // write-out, as that depends on whether the containing Miminum Clean
        // Block has any data modifications to it. Once that turns out to be
        // true, last_needing_write_states_allocation_block_index gets set to it.
        let mut last_with_dirty_states_allocation_block_index: Option<
            AuthTreeDataBlocksUpdateStatesAllocationBlockIndex,
        > = None;
        // Whether or not the found candidate region of contiguous dirty states can get
        // extended any further. If false, seek only for confirmation that the
        // found region's tail does actually need a write-out, i.e. whether or
        // not the containing Minimum Clean BLock has any data modifications to
        // it.
        let mut found_dirty_region_is_maximal = false;
        let mut last_needing_write_states_allocation_block_index: Option<
            AuthTreeDataBlocksUpdateStatesAllocationBlockIndex,
        > = None;
        let mut last_min_write_block_target_allocation_blocks_begin =
            first_min_write_block_target_allocation_blocks_begin;

        let mut cur_states_allocation_block_index = *remaining_states_allocation_blocks_index_range.begin();
        while cur_states_allocation_block_index != *remaining_states_allocation_blocks_index_range.end() {
            let cur_target_allocation_block = states.get_allocation_block_target(&cur_states_allocation_block_index);
            let cur_min_write_block_target_allocation_blocks_begin =
                cur_target_allocation_block.align_down(min_write_block_allocation_blocks_log2);
            // The states array is sorted by target Allocation Block index.
            debug_assert!(
                cur_min_write_block_target_allocation_blocks_begin
                    >= last_min_write_block_target_allocation_blocks_begin
            );

            // If crossing a Minimum Write Block boundary, determine if and how to proceed,
            // depending on what's been found so far.
            if cur_min_write_block_target_allocation_blocks_begin != last_min_write_block_target_allocation_blocks_begin
            {
                let prev_min_write_block_any_dirty = cur_min_write_block_any_dirty;
                let prev_min_clean_block_any_modified = cur_min_clean_block_any_modified;
                // Reinit.
                cur_min_write_block_any_dirty = false;
                let at_min_clean_block_boundary = (u64::from(cur_min_write_block_target_allocation_blocks_begin)
                    ^ u64::from(last_min_write_block_target_allocation_blocks_begin))
                    >> min_clean_block_allocation_blocks_log2
                    != 0;
                if at_min_clean_block_boundary {
                    // Reinit.
                    cur_min_clean_block_any_modified = false;
                }

                debug_assert!(
                    last_needing_write_states_allocation_block_index.is_none()
                        || last_with_dirty_states_allocation_block_index.is_some()
                );
                if let Some(last_with_dirty_states_allocation_block_index_val) =
                    last_with_dirty_states_allocation_block_index.as_ref()
                {
                    if last_needing_write_states_allocation_block_index.is_none() && at_min_clean_block_boundary {
                        // There had been been some dirty states in the previous Minimum Clean
                        // Block, but these don't qualify for a write-out, because that Block has no
                        // data modifications at all (dirty or not). Reset the found dirty candidate
                        // region.
                        debug_assert!(!prev_min_clean_block_any_modified);
                        last_with_dirty_states_allocation_block_index = None;
                        found_dirty_region_is_maximal = false;
                        // Dirty region candidate for write-out dismissed, advance the remaining
                        // region's beginning to the current position.
                        remaining_states_allocation_blocks_index_range =
                            AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::new(
                                &cur_states_allocation_block_index,
                                remaining_states_allocation_blocks_index_range.end(),
                            );
                    } else {
                        // Always write out contiguous regions at a time. If there's a Mininum Write
                        // Block gap with no dirty data, then don't extend the dirty candidate range
                        // over it any further.
                        found_dirty_region_is_maximal |= !prev_min_write_block_any_dirty;

                        // Don't extend over gaps of missing states either.
                        if cur_min_write_block_target_allocation_blocks_begin
                            - last_min_write_block_target_allocation_blocks_begin
                            != layout::AllocBlockCount::from(1u64 << min_write_block_allocation_blocks_log2)
                        {
                            found_dirty_region_is_maximal = true;
                        }

                        // If something had been found already and we're crossing a
                        // preferred_write_block_allocation_blocks_log2 boundary, then stop extending
                        // the dirty candidate region.
                        if (u64::from(last_min_write_block_target_allocation_blocks_begin)
                            ^ u64::from(cur_min_write_block_target_allocation_blocks_begin))
                            >> preferred_write_block_allocation_blocks_log2
                            != 0
                        {
                            found_dirty_region_is_maximal = true;
                        }

                        if last_needing_write_states_allocation_block_index.is_some() {
                            // If the previous Minimum Clean Block has no modifications, then none of it
                            // needs a write-out and there's a gap. Stop and process what's been found.
                            if at_min_clean_block_boundary && !prev_min_clean_block_any_modified {
                                break;
                            }

                            // If the dirty candidate range won't get extended any further, and the
                            // modification status of its pending tail's containing Minimum Clean Block is
                            // known by now (either because a modification has been found or because its end
                            // has been reached), then stop.
                            if found_dirty_region_is_maximal
                                && (at_min_clean_block_boundary || prev_min_clean_block_any_modified)
                            {
                                break;
                            }
                        }

                        // See if the associated Journal Staging Copy areas, if assigned already, extend
                        // contiguously as well.
                        if !found_dirty_region_is_maximal
                            && AuthTreeDataBlocksUpdateStatesIndex::from(cur_states_allocation_block_index)
                                != AuthTreeDataBlocksUpdateStatesIndex::from(
                                    *last_with_dirty_states_allocation_block_index_val,
                                )
                        {
                            // last_with_dirty_states_allocation_block_index is always getting advanced
                            // until the end of a Minimum Write Block having any dirty entries, even though
                            // that particular Allocation Block itself might not need a write out.
                            debug_assert_eq!(
                                last_with_dirty_states_allocation_block_index_val
                                    .step(auth_tree_data_block_allocation_blocks_log2),
                                cur_states_allocation_block_index
                            );

                            // Verify that allocated Journal Data Staging area extends contiguously from
                            // the last to the current position. If not, the region's write-out must get
                            // split into multiple, independent requests. Note that Journal Data Staging
                            // areas get allocated IO Block- as well as Authentication Tree Data Block
                            // wise, whichever is larger. At this point it is known per the condition
                            // above that we crossed an Authentication Tree Data Block boundary since
                            // the last found position needing a write-out.
                            let cur_io_block_target_allocation_blocks_begin =
                                cur_target_allocation_block.align_down(io_block_allocation_blocks_log2);
                            let last_io_block_target_allocation_blocks_begin =
                                last_min_write_block_target_allocation_blocks_begin
                                    .align_down(io_block_allocation_blocks_log2);
                            if cur_io_block_target_allocation_blocks_begin
                                != last_io_block_target_allocation_blocks_begin
                            {
                                // So, we're not in same IO block as the last position found to
                                // possibly need a write-out anymore. On the other hand, we do know
                                // at this point that we're at most one Device IO block ahead, as per
                                // the above logic stopping the dirty candidate range extension at
                                // Minimum Write Block sized gaps. As the Minimum Write Block is
                                // less or equal than an IO block in size, it follows that the
                                // current position is at most one IO Block ahead. This is
                                // important, because the same upper bound on the relative distance
                                // would apply to the allocated Journal Data Staging area as well
                                // (if contiguous), and this would in turn imply that any
                                // potentially missing states to be inserted inbetween right before
                                // write-out would inherit the corresponding regions within that
                                // area.
                                debug_assert!(
                                    min_write_block_allocation_blocks_log2 <= io_block_allocation_blocks_log2
                                );
                                debug_assert_eq!(
                                    cur_io_block_target_allocation_blocks_begin
                                        - last_io_block_target_allocation_blocks_begin,
                                    layout::AllocBlockCount::from(1u64 << io_block_allocation_blocks_log2)
                                );
                                match states[AuthTreeDataBlocksUpdateStatesIndex::from(
                                    *last_with_dirty_states_allocation_block_index_val,
                                )]
                                .get_journal_staging_copy_allocation_blocks_begin()
                                .zip(
                                    states
                                        [AuthTreeDataBlocksUpdateStatesIndex::from(cur_states_allocation_block_index)]
                                    .get_journal_staging_copy_allocation_blocks_begin(),
                                ) {
                                    Some((
                                        last_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin,
                                        cur_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin,
                                    )) => {
                                        if cur_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin
                                            < last_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin
                                        {
                                            found_dirty_region_is_maximal = true;
                                        } else if io_block_allocation_blocks_log2
                                            > auth_tree_data_block_allocation_blocks_log2
                                        {
                                            let last_io_block_journal_staging_copy_allocation_blocks_begin =
                                                last_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin
                                                    .align_down(io_block_allocation_blocks_log2);
                                            let cur_io_block_journal_staging_copy_allocation_blocks_begin =
                                                cur_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin
                                                    .align_down(io_block_allocation_blocks_log2);
                                            if cur_io_block_journal_staging_copy_allocation_blocks_begin
                                                - last_io_block_journal_staging_copy_allocation_blocks_begin
                                                != layout::AllocBlockCount::from(
                                                    1u64 << io_block_allocation_blocks_log2,
                                                )
                                            {
                                                found_dirty_region_is_maximal = true;
                                            }
                                        } else {
                                            debug_assert_eq!(
                                                usize::from(AuthTreeDataBlocksUpdateStatesIndex::from(
                                                    cur_states_allocation_block_index
                                                )),
                                                usize::from(AuthTreeDataBlocksUpdateStatesIndex::from(
                                                    *last_with_dirty_states_allocation_block_index_val
                                                )) + 1
                                            );
                                            if cur_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin
                                                - last_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin
                                                != layout::AllocBlockCount::from(
                                                    1u64 << auth_tree_data_block_allocation_blocks_log2,
                                                )
                                            {
                                                found_dirty_region_is_maximal = true;
                                            }
                                        }
                                    }
                                    None => {
                                        // Can't predict the upcoming Journal Data Staging Copy
                                        // allocations, if any, stop extending.
                                        found_dirty_region_is_maximal = true;
                                    }
                                }

                                // As found_dirty_region_is_maximal might have been flipped to true in the
                                // meanwhile, reevaluate the stop condition from above.
                                if last_needing_write_states_allocation_block_index.is_some()
                                    && found_dirty_region_is_maximal
                                    && (at_min_clean_block_boundary || prev_min_clean_block_any_modified)
                                {
                                    break;
                                }
                            }
                        }
                    }
                } else {
                    // No dirty region candidate for write-out found yet, advance the remaining
                    // region's beginning to the current position. Only doing so when entering a
                    // new Minimum Write Block is required for the returned region to comprise
                    // all of a Minimum Write Block's (already present) states in case the head
                    // is not dirty, but some interior region is.
                    remaining_states_allocation_blocks_index_range =
                        AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::new(
                            &cur_states_allocation_block_index,
                            remaining_states_allocation_blocks_index_range.end(),
                        );
                }
            }
            last_min_write_block_target_allocation_blocks_begin = cur_min_write_block_target_allocation_blocks_begin;

            let mut cur_allocation_block_is_modified = false;
            let mut cur_allocation_block_is_dirty = false;
            match &states[cur_states_allocation_block_index].nv_sync_state {
                AllocationBlockUpdateNvSyncState::Unallocated(unallocated_state) => {
                    cur_allocation_block_is_dirty = !unallocated_state.copied_to_journal;
                }
                AllocationBlockUpdateNvSyncState::Allocated(allocated_state) => match allocated_state {
                    AllocationBlockUpdateNvSyncStateAllocated::Unmodified(unmodified_state) => {
                        cur_allocation_block_is_dirty = !unmodified_state.copied_to_journal;
                    }
                    AllocationBlockUpdateNvSyncStateAllocated::Modified(modified_state) => {
                        cur_allocation_block_is_modified = true;
                        match modified_state {
                            AllocationBlockUpdateNvSyncStateAllocatedModified::JournalDirty { .. } => {
                                cur_allocation_block_is_dirty = true;
                            }
                            AllocationBlockUpdateNvSyncStateAllocatedModified::JournalClean { .. } => (),
                        }
                    }
                },
            };

            cur_min_clean_block_any_modified |= cur_allocation_block_is_modified;
            cur_min_write_block_any_dirty |= cur_allocation_block_is_dirty;

            // Even if the current Allocation Block itself is not dirty itself, but some
            // preceeding ones in the same containing Minimum Write Block are,
            // keep advancing
            // last_with_dirty_states_allocation_block_index to eventually move it to
            // the Minimum Write Block's last entry (at least to the extent as
            // it's currently being tracked in the states[]). It's not strictly
            // needed for correctness, but will automatically yield aligned
            // write regions (if the states[] happens to track all of
            // the Minimum Write Block already).
            if cur_min_write_block_any_dirty && !found_dirty_region_is_maximal {
                last_with_dirty_states_allocation_block_index = Some(cur_states_allocation_block_index);
            }
            // Dirty Minimum Write Blocks shall get written only if the containing Minimum
            // Clean Block has got some modification to it, dirty or not.
            if cur_min_clean_block_any_modified {
                last_needing_write_states_allocation_block_index = last_with_dirty_states_allocation_block_index;
            }

            cur_states_allocation_block_index =
                cur_states_allocation_block_index.step(auth_tree_data_block_allocation_blocks_log2);
        }

        if let Some(last_needing_write_states_allocation_block_index) = last_needing_write_states_allocation_block_index
        {
            let region_needing_write_states_allocation_blocks_index_range_begin =
                remaining_states_allocation_blocks_index_range.begin();
            let region_needing_write_states_allocation_blocks_index_range_end =
                last_needing_write_states_allocation_block_index.step(auth_tree_data_block_allocation_blocks_log2);
            debug_assert!(
                region_needing_write_states_allocation_blocks_index_range_end <= cur_states_allocation_block_index
            );
            (
                Some(AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::new(
                    region_needing_write_states_allocation_blocks_index_range_begin,
                    &region_needing_write_states_allocation_blocks_index_range_end,
                )),
                AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::new(
                    &cur_states_allocation_block_index,
                    remaining_states_allocation_blocks_index_range.end(),
                ),
            )
        } else {
            debug_assert!(
                cur_states_allocation_block_index >= *self.request_states_allocation_blocks_index_range.end()
            );
            (
                None,
                AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::new(
                    remaining_states_allocation_blocks_index_range.end(),
                    remaining_states_allocation_blocks_index_range.end(),
                ),
            )
        }
    }

    /// Fill [Minimum IO Block](Self::min_write_block_allocation_blocks_log2)
    /// alignment gaps within a given range of the [`Transaction`]'s [data
    /// update tracking
    /// states](super::auth_tree_data_blocks_update_states::AllocationBlockUpdateState).
    ///
    /// # Arguments:
    ///
    /// * `fs_instance_sync_state` - Reference to
    ///   [`CocoonFs::sync_state`](crate::fs::cocoonfs::fs::CocoonFs::sync_state).
    /// * `transaction` - The [`Transaction`].
    /// * `write_region_states_allocation_blocks_index_range` - [Allocation
    ///   Block level index
    ///   range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange) to
    ///   fill alignment gaps within.
    fn fill_write_region_states_min_write_block_alignment_gaps(
        &mut self,
        fs_instance_sync_state: &CocoonFsSyncStateMemberRef<'_, ST, B>,
        transaction: &mut Transaction,
        write_region_states_allocation_blocks_index_range:
         &mut AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    ) -> Result<(), NvFsError> {
        let auth_tree_data_block_allocation_blocks_log2 =
            transaction.auth_tree_data_block_allocation_blocks_log2 as u32;
        let allocation_block_size_128b_log2 = transaction.allocation_block_size_128b_log2 as u32;
        let blkdev_io_block_size_128b_log2 = transaction.blkdev_io_block_size_128b_log2;
        let min_write_block_allocation_blocks_log2 = Self::min_write_block_allocation_blocks_log2(
            blkdev_io_block_size_128b_log2,
            allocation_block_size_128b_log2,
        );
        // The code here assumes that all states alignment gaps will get filled up here
        // and that the subsequent TransactionReadMissingDataFuture would not have to
        // insert anything more in this regard.
        debug_assert!(
            min_write_block_allocation_blocks_log2
                >= TransactionReadMissingDataFuture::<B>::min_read_block_allocation_blocks_log2(
                    blkdev_io_block_size_128b_log2,
                    allocation_block_size_128b_log2
                )
        );

        let states = &mut transaction.auth_tree_data_blocks_update_states;
        // Fill alignment gaps in the current write region, adjust the original input
        // range as well as the remaining range in order to account for
        // the newly added states entries.
        //
        // Before doing the fill (and invalidating the index ranges), save away some
        // information needed to fixup the original input request index range
        // later.
        let (
            request_range_missing_states_before_in_write_range_count,
            request_range_missing_tail_states_in_write_range_count,
        ) = {
            let write_region_states_index_range = AuthTreeDataBlocksUpdateStatesIndexRange::from(
                write_region_states_allocation_blocks_index_range.clone(),
            );
            let request_states_index_range = AuthTreeDataBlocksUpdateStatesIndexRange::from(
                self.request_states_allocation_blocks_index_range.clone(),
            );
            // The effective write range does get extended within Minimum Write Block
            // alignment, but should always overlap with the original request.
            debug_assert!(request_states_index_range.begin() < write_region_states_index_range.end());
            debug_assert!(request_states_index_range.end() > write_region_states_index_range.begin());
            // Also, Self::determine_next_write_region() would always return ranges already
            // maximal within the alignment distance.
            debug_assert_eq!(
                states.extend_states_allocation_blocks_index_range_within_alignment(
                    write_region_states_allocation_blocks_index_range,
                    min_write_block_allocation_blocks_log2
                ),
                *write_region_states_allocation_blocks_index_range
            );
            // Also, there's no aligned gap in the write range, all missing states
            // will get filled up.
            debug_assert!(
                states.find_aligned_gap_after(
                    write_region_states_index_range.begin(),
                    min_write_block_allocation_blocks_log2
                ) >= write_region_states_index_range.end()
            );

            // The number of missing states within the write region index range and before
            // the request index range, if any. It's the difference of what is
            // expected and what's already there.
            let request_range_missing_states_before_in_write_range_count = if write_region_states_index_range.begin()
                <= request_states_index_range.begin()
            {
                let request_range_begin_auth_tree_data_blocks_offset_in_write_range = u64::from(
                    states[request_states_index_range.begin()].get_target_allocation_blocks_begin()
                        - states[write_region_states_index_range.begin()].get_target_allocation_blocks_begin(),
                )
                    >> auth_tree_data_block_allocation_blocks_log2;
                Some(
                    request_range_begin_auth_tree_data_blocks_offset_in_write_range
                        - AuthTreeDataBlocksUpdateStatesIndexRange::new(
                            write_region_states_index_range.begin(),
                            request_states_index_range.begin(),
                        )
                        .len() as u64,
                )
            } else {
                // The current write region's and the original input request's beginnings are
                // in different Minimum Write Blocks. In particular, all states filled up for
                // aligning the former will get inserted after the latter.
                debug_assert_ne!(
                    (u64::from(states[write_region_states_index_range.begin()].get_target_allocation_blocks_begin())
                        ^ u64::from(states[request_states_index_range.begin()].get_target_allocation_blocks_begin()))
                        >> min_write_block_allocation_blocks_log2,
                    0
                );
                None
            };
            // The number of missing states within the write region index range overlapping
            // with the request index range's tail, if any. It's the difference of
            // what is expected and what's already there.
            let request_range_missing_tail_states_in_write_range_count =
                if write_region_states_index_range.end() >= request_states_index_range.end() {
                    let request_range_end_auth_tree_data_blocks_offset_in_write_range = (u64::from(
                        states[request_states_index_range
                            .end()
                            .step_back()
                            .ok_or_else(|| nvfs_err_internal!())?]
                        .get_target_allocation_blocks_begin()
                            - states[write_region_states_index_range.begin()].get_target_allocation_blocks_begin(),
                    )
                        >> auth_tree_data_block_allocation_blocks_log2)
                        + 1;
                    Some(
                        request_range_end_auth_tree_data_blocks_offset_in_write_range
                            - AuthTreeDataBlocksUpdateStatesIndexRange::new(
                                write_region_states_index_range.begin(),
                                request_states_index_range.end(),
                            )
                            .len() as u64
                            - request_range_missing_states_before_in_write_range_count.unwrap_or(0),
                    )
                } else {
                    // The current write region's and the original input request's ends are
                    // in different Minimum Write Blocks. In particular, all states filled up for
                    // aligning the former will get inserted before the latter.
                    debug_assert_ne!(
                        (u64::from(
                            states[write_region_states_index_range.end().step_back().unwrap()]
                                .get_target_allocation_blocks_begin()
                                + layout::AllocBlockCount::from(1u64 << auth_tree_data_block_allocation_blocks_log2)
                        ) ^ u64::from(
                            states[request_states_index_range.end().step_back().unwrap()]
                                .get_target_allocation_blocks_begin()
                                + layout::AllocBlockCount::from(1u64 << auth_tree_data_block_allocation_blocks_log2)
                        )) >> min_write_block_allocation_blocks_log2,
                        0
                    );
                    None
                };

            (
                request_range_missing_states_before_in_write_range_count,
                request_range_missing_tail_states_in_write_range_count,
            )
        };

        // Do the actual fillup.
        let (aligned_write_region_states_allocation_blocks_index_range, write_range_states_insertion_info) = states
            .fill_states_allocation_blocks_index_range_regions_alignment_gaps(
                write_region_states_allocation_blocks_index_range,
                min_write_block_allocation_blocks_log2,
                &fs_instance_sync_state.alloc_bitmap,
                &transaction.allocs.pending_frees,
            );

        // Invalidated by now, and never fixed up again, avoid accidental use.
        let __write_region_states_allocation_blocks_index_range = write_region_states_allocation_blocks_index_range;

        // If some states had been inserted, adjust the index ranges accordingly in
        // order to account for the new offsets in the states array.
        if let Some(write_range_states_insertion_info) = write_range_states_insertion_info {
            // Handle the original input request range first, so that the accumulated needed
            // adjustments can eventually get returned back from the future.
            let cur_request_states_range_offsets = {
                let inserted_states_before_request_range_count =
                    request_range_missing_states_before_in_write_range_count
                        .map(|request_range_missing_states_before_in_write_range_count| {
                            (write_range_states_insertion_info.total_inserted_states_count() as u64).min(
                                write_range_states_insertion_info.inserted_states_before_range_count as u64
                                    + request_range_missing_states_before_in_write_range_count,
                            ) as usize
                        })
                        .unwrap_or(0);
                let remaining_inserted_states_count = write_range_states_insertion_info.total_inserted_states_count()
                    - inserted_states_before_request_range_count;

                let inserted_states_within_request_range_count = request_range_missing_tail_states_in_write_range_count
                    .map(|request_range_missing_tail_states_in_write_range_count| {
                        (remaining_inserted_states_count as u64)
                            .min(request_range_missing_tail_states_in_write_range_count)
                            as usize
                    })
                    .unwrap_or(remaining_inserted_states_count);
                let remaining_inserted_states_count =
                    remaining_inserted_states_count - inserted_states_within_request_range_count;

                let inserted_states_after_request_range_count = remaining_inserted_states_count;

                AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets {
                    inserted_states_before_range_count: inserted_states_before_request_range_count,
                    inserted_states_within_range_count: inserted_states_within_request_range_count,
                    inserted_states_after_range_count: inserted_states_after_request_range_count,
                    max_target_allocations_blocks_alignment_log2: min_write_block_allocation_blocks_log2,
                }
            };
            self.request_states_allocation_blocks_index_range = self
                .request_states_allocation_blocks_index_range
                .apply_states_insertions_offsets(
                    cur_request_states_range_offsets.inserted_states_before_range_count,
                    cur_request_states_range_offsets.inserted_states_within_range_count,
                );
            self.request_states_range_offsets = Some(
                self.request_states_range_offsets
                    .as_ref()
                    .map(|prev| prev.accumulate(&cur_request_states_range_offsets))
                    .unwrap_or(cur_request_states_range_offsets),
            );

            // Update the internally tracked index range of remaining regions to process.
            self.remaining_states_allocation_blocks_index_range = self
                .remaining_states_allocation_blocks_index_range
                .apply_states_insertions_offsets(write_range_states_insertion_info.total_inserted_states_count(), 0)
        }

        // Return upon failure only after the index ranges have been updated (it could
        // have failed midways).
        let aligned_write_region_states_allocation_blocks_index_range =
            aligned_write_region_states_allocation_blocks_index_range?;

        *__write_region_states_allocation_blocks_index_range =
            aligned_write_region_states_allocation_blocks_index_range;

        Ok(())
    }

    /// Prepare a storage write request.
    ///
    /// # Arguments:
    ///
    /// * `transaction` - The [`Transaction`].
    /// * `aligned_write_region_states_allocation_blocks_index_range` - [Minimum
    ///   IO Block](Self::min_write_block_allocation_blocks_log2) aligned
    ///   [Allocation Block level index
    ///   range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange) to
    ///   write out.
    /// * `rng` - The [random number generator](rng::RngCoreDispatchable) to
    ///   randomize unallocated [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2) with.
    fn prepare_write_request(
        mut transaction: Box<Transaction>,
        aligned_write_region_states_allocation_blocks_index_range:
        AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        rng: &mut dyn rng::RngCoreDispatchable,
    ) -> Result<TransactionWriteDirtyDataNvBlkDevWriteRequest, (Box<Transaction>, NvFsError)> {
        let allocation_block_size_128b_log2 = transaction.allocation_block_size_128b_log2 as u32;
        let allocation_block_size = 1usize << (allocation_block_size_128b_log2 + 7);
        let auth_tree_data_block_allocation_blocks_log2 =
            transaction.auth_tree_data_block_allocation_blocks_log2 as u32;

        let states = &mut transaction.auth_tree_data_blocks_update_states;
        let region_allocation_blocks_count = states
            .get_contiguous_region_target_range(&aligned_write_region_states_allocation_blocks_index_range)
            .block_count();
        let mut disguise_processor_and_buffers = match transaction
            .journal_staging_copy_disguise
            .as_ref()
            .map(|d| {
                let disguise_processor = d.0.instantiate_processor()?;
                // The regions returned by Self::determine_next_write_range() at a time are
                // guaranteed to not exceed usize::MAX in length as specified in
                // units of Allocation Blocks.
                let region_allocation_blocks_count = u64::from(region_allocation_blocks_count) as usize;
                let disguised_src_allocation_block_buffers =
                    FixedVec::new_with_default(region_allocation_blocks_count)?;
                Ok((disguise_processor, disguised_src_allocation_block_buffers))
            })
            .transpose()
        {
            Ok(disguise_processor_and_buffers) => disguise_processor_and_buffers,
            Err(e) => return Err((transaction, e)),
        };

        // Walk through all Allocation Blocks in the range, fill uninitialized ones with
        // random data, and disguise all buffers if enabled.
        for (i, update_states_allocation_block_index) in aligned_write_region_states_allocation_blocks_index_range
            .iter(auth_tree_data_block_allocation_blocks_log2)
            .enumerate()
        {
            // Save away before the mut borrow in states[] below.
            let target_allocation_block = states.get_allocation_block_target(&update_states_allocation_block_index);
            let journal_staging_copy_allocation_block =
                match states.get_allocation_block_journal_staging_copy(&update_states_allocation_block_index) {
                    Some(journal_staging_copy_allocation_block) => journal_staging_copy_allocation_block,
                    None => return Err((transaction, nvfs_err_internal!())),
                };

            let src_allocation_block_buffer: &[u8] =
                match &mut states[update_states_allocation_block_index].nv_sync_state {
                    AllocationBlockUpdateNvSyncState::Unallocated(unallocated_state) => {
                        match &unallocated_state.random_fillup {
                            None => {
                                // Fill any uninitialized Allocation Blocks in the range with random bytes.
                                debug_assert!(!unallocated_state.target_state.is_initialized());
                                debug_assert!(!unallocated_state.copied_to_journal);
                                let mut random_fillup = match FixedVec::new_with_default(allocation_block_size) {
                                    Ok(random_fillup) => random_fillup,
                                    Err(e) => return Err((transaction, NvFsError::from(e))),
                                };
                                if let Err(e) = rng::rng_dyn_dispatch_generate(
                                    rng,
                                    io_slices::SingletonIoSliceMut::new(&mut random_fillup).map_infallible_err(),
                                    None,
                                ) {
                                    return Err((transaction, NvFsError::from(e)));
                                }
                                unallocated_state.random_fillup.insert(random_fillup)
                            }
                            Some(random_fillup) => random_fillup,
                        }
                    }
                    AllocationBlockUpdateNvSyncState::Allocated(allocated_state) => {
                        match allocated_state {
                            AllocationBlockUpdateNvSyncStateAllocated::Unmodified(unmodified_state) => {
                                // Any missing Allocation Block data should have been read in before the
                                // write-out by now.
                                match unmodified_state.cached_encrypted_data.as_ref() {
                                    Some(cached_encrypted_data) => cached_encrypted_data.get_encrypted_data(),
                                    None => return Err((transaction, nvfs_err_internal!())),
                                }
                            }
                            AllocationBlockUpdateNvSyncStateAllocated::Modified(modified_state) => {
                                match modified_state {
                                    AllocationBlockUpdateNvSyncStateAllocatedModified::JournalDirty {
                                        authenticated_encrypted_data,
                                    } => authenticated_encrypted_data,
                                    AllocationBlockUpdateNvSyncStateAllocatedModified::JournalClean {
                                        cached_encrypted_data,
                                    } => {
                                        // Any missing Allocation Block data should have been read in before the
                                        // write-out.
                                        match cached_encrypted_data.as_ref() {
                                            Some(cached_encrypted_data) => cached_encrypted_data.get_encrypted_data(),
                                            None => return Err((transaction, nvfs_err_internal!())),
                                        }
                                    }
                                }
                            }
                        }
                    }
                };

            if let Some((disguise_processor, disguised_src_allocation_block_buffers)) =
                &mut disguise_processor_and_buffers
            {
                // Don't disguise if the Journal Data Staging Copy is not in fact a copy,
                // but refers to a freshly initialized target IO block to be
                // populated in place by the transaction.
                if target_allocation_block != journal_staging_copy_allocation_block {
                    let mut disguised_src_allocation_block_buffer =
                        match FixedVec::new_with_default(allocation_block_size) {
                            Ok(disguised_src_allocation_block_buffer) => disguised_src_allocation_block_buffer,
                            Err(e) => return Err((transaction, NvFsError::from(e))),
                        };
                    if let Err(e) = disguise_processor.disguise_journal_staging_copy_allocation_block(
                        journal_staging_copy_allocation_block,
                        target_allocation_block,
                        &mut disguised_src_allocation_block_buffer,
                        src_allocation_block_buffer,
                    ) {
                        return Err((transaction, e));
                    }
                    disguised_src_allocation_block_buffers[i] = Some(disguised_src_allocation_block_buffer);
                }
            }
        }

        let disguised_src_allocation_block_buffers = disguise_processor_and_buffers
            .map(|(_, disguised_src_allocation_block_buffers)| disguised_src_allocation_block_buffers);

        let region_journal_stagion_copy_allocation_blocks_begin = match states
            .get_allocation_block_journal_staging_copy(
                aligned_write_region_states_allocation_blocks_index_range.begin(),
            ) {
            Some(region_journal_stagion_copy_allocation_blocks_begin) => {
                region_journal_stagion_copy_allocation_blocks_begin
            }
            None => return Err((transaction, nvfs_err_internal!())),
        };
        let dst_allocation_blocks_range = layout::PhysicalAllocBlockRange::from((
            region_journal_stagion_copy_allocation_blocks_begin,
            region_allocation_blocks_count,
        ));
        let request_io_region = match ChunkedIoRegion::new(
            u64::from(dst_allocation_blocks_range.begin()) << allocation_block_size_128b_log2,
            u64::from(dst_allocation_blocks_range.end()) << allocation_block_size_128b_log2,
            allocation_block_size_128b_log2,
        )
        .map_err(|_| nvfs_err_internal!())
        {
            Ok(request_io_region) => request_io_region,
            Err(e) => return Err((transaction, e)),
        };

        Ok(TransactionWriteDirtyDataNvBlkDevWriteRequest {
            transaction,
            aligned_write_region_states_allocation_blocks_index_range,
            request_io_region,
            disguised_src_allocation_block_buffers,
        })
    }
}

impl<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev> CocoonFsSyncStateReadFuture<ST, B>
    for TransactionWriteDirtyDataFuture<ST, B>
{
    /// Output type of [`poll()`](Self::poll).
    ///
    /// A two-level [`Result`] is returned upon
    /// [future](CocoonFsSyncStateReadFuture) completion.
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering an internal error and the [`Transaction`] is lost.
    /// * `Ok((transaction, offsets, ...))` - Otherwise the outer level
    ///   [`Result`] is set to [`Ok`] and a tuple of the input [`Transaction`],
    ///   `transaction`, correction `offsets` to apply to the input [Allocation
    ///   Block level entry index
    ///   range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange) in
    ///   order to account for the insertion of new state entries, if any, and
    ///   the operation result will get returned within:
    ///     * `Ok((transaction, offsets, Err(e)))` - In case of an error, the
    ///       error reason `e` is returned in an [`Err`].
    ///     * `Ok((transaction, offsets, Ok(())))` -  Otherwise, `Ok(())` will
    ///       get returned for the operation result on success.
    type Output = Result<
        (
            Box<Transaction>,
            Option<AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets>,
            Result<(), NvFsError>,
        ),
        NvFsError,
    >;

    type AuxPollData<'a> = &'a mut dyn rng::RngCoreDispatchable;

    fn poll<'a>(
        mut self: pin::Pin<&mut Self>,
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, B>,
        aux_data: &mut Self::AuxPollData<'a>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let rng: &mut dyn rng::RngCoreDispatchable = *aux_data;
        loop {
            match &mut self.fut_state {
                TransactionWriteDirtyDataFutureState::Init { transaction } => {
                    let mut transaction = transaction.take().ok_or_else(|| nvfs_err_internal!())?;
                    self.fut_state = TransactionWriteDirtyDataFutureState::Done;

                    // Figure out which region to write out next, fill missing alignment gaps and
                    // submit a request to read in any missing data first.
                    let cur_write_region_states_allocation_blocks_index_range;
                    (
                        cur_write_region_states_allocation_blocks_index_range,
                        self.remaining_states_allocation_blocks_index_range,
                    ) = self.determine_next_write_region(
                        &transaction,
                        &self.remaining_states_allocation_blocks_index_range,
                    );

                    let mut cur_write_region_states_allocation_blocks_index_range =
                        match cur_write_region_states_allocation_blocks_index_range {
                            Some(cur_write_region_states_allocation_blocks_index_range) => {
                                cur_write_region_states_allocation_blocks_index_range
                            }
                            None => {
                                // No more regions to write, all done.
                                return task::Poll::Ready(Ok((
                                    transaction,
                                    self.request_states_range_offsets.take(),
                                    Ok(()),
                                )));
                            }
                        };

                    // Fill the state's Minimum Write Block alignment gaps, so that everything can
                    // get written out in multiples of that block size.
                    if let Err(e) = self.fill_write_region_states_min_write_block_alignment_gaps(
                        fs_instance_sync_state,
                        &mut transaction,
                        &mut cur_write_region_states_allocation_blocks_index_range,
                    ) {
                        return task::Poll::Ready(Ok((transaction, self.request_states_range_offsets.take(), Err(e))));
                    }
                    // cur_write_region_states_allocation_blocks_index_range is aligned now,
                    // rename it for clarity.
                    let cur_aligned_write_region_states_allocation_blocks_index_range =
                        cur_write_region_states_allocation_blocks_index_range;

                    // As a first step, read in any missing data in the current region.
                    let cur_aligned_write_region_read_missing_fut = match TransactionReadMissingDataFuture::new(
                        transaction,
                        &cur_aligned_write_region_states_allocation_blocks_index_range,
                    ) {
                        Ok(cur_aligned_write_region_read_missing_fut) => cur_aligned_write_region_read_missing_fut,
                        Err((transaction, e)) => {
                            return task::Poll::Ready(Ok((
                                transaction,
                                self.request_states_range_offsets.take(),
                                Err(e),
                            )));
                        }
                    };
                    self.fut_state = TransactionWriteDirtyDataFutureState::RegionReadMissing {
                        cur_aligned_write_region_states_allocation_blocks_index_range,
                        cur_aligned_write_region_read_missing_fut,
                    };
                }
                TransactionWriteDirtyDataFutureState::RegionReadMissing {
                    cur_aligned_write_region_states_allocation_blocks_index_range,
                    cur_aligned_write_region_read_missing_fut,
                } => {
                    let (fs_instance, _, fs_sync_state_alloc_bitmap, _, _, _, _, _) =
                        fs_instance_sync_state.fs_instance_and_destructure_borrow();
                    match TransactionReadMissingDataFuture::poll(
                        pin::Pin::new(cur_aligned_write_region_read_missing_fut),
                        &fs_instance.blkdev,
                        fs_sync_state_alloc_bitmap,
                        cx,
                    ) {
                        task::Poll::Pending => return task::Poll::Pending,
                        task::Poll::Ready(Err(e)) => {
                            self.fut_state = TransactionWriteDirtyDataFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Ready(Ok((transaction, read_request_states_range_offsets, result))) => {
                            // The write code here aligns the regions to the Minimum Write Block,
                            // which is assumed to be >= a Minimum Read
                            // Block. Thus, the
                            // TransactionReadMissingDataFuture should not have filled any more
                            // alignment gaps.
                            debug_assert!(read_request_states_range_offsets.is_none());
                            if let Err(e) = result {
                                self.fut_state = TransactionWriteDirtyDataFutureState::Done;
                                return task::Poll::Ready(Ok((
                                    transaction,
                                    self.request_states_range_offsets.take(),
                                    Err(e),
                                )));
                            }

                            // Any missing data within the region has been read in now. Proceed with
                            // allocating the Journal Staging Copy areas, if needed.
                            self.fut_state =
                                TransactionWriteDirtyDataFutureState::RegionAllocateJournalStagingCopyBlocks {
                                    cur_aligned_write_region_states_allocation_blocks_index_range:
                                        cur_aligned_write_region_states_allocation_blocks_index_range.clone(),
                                    cur_aligned_write_region_allocate_journal_staging_copy_blocks_fut:
                                        TransactionAllocateJournalStagingCopiesFuture::new(
                                            transaction,
                                            AuthTreeDataBlocksUpdateStatesIndexRange::from(
                                                cur_aligned_write_region_states_allocation_blocks_index_range.clone(),
                                            ),
                                        ),
                                };
                        }
                    }
                }
                TransactionWriteDirtyDataFutureState::RegionAllocateJournalStagingCopyBlocks {
                    cur_aligned_write_region_states_allocation_blocks_index_range,
                    cur_aligned_write_region_allocate_journal_staging_copy_blocks_fut,
                } => {
                    match CocoonFsSyncStateReadFuture::poll(
                        pin::Pin::new(cur_aligned_write_region_allocate_journal_staging_copy_blocks_fut),
                        fs_instance_sync_state,
                        &mut (),
                        cx,
                    ) {
                        task::Poll::Pending => return task::Poll::Pending,
                        task::Poll::Ready(Err(e)) => return task::Poll::Ready(Err(e)),
                        task::Poll::Ready(Ok((transaction, result))) => {
                            if let Err(e) = result {
                                self.fut_state = TransactionWriteDirtyDataFutureState::Done;
                                return task::Poll::Ready(Ok((
                                    transaction,
                                    self.request_states_range_offsets.take(),
                                    Err(e),
                                )));
                            }

                            // All of the current regions got Journal Staging Copy blocks allocated
                            // to it now. Proceed with preparing and
                            // submitting the actual write-out request.
                            let write_request = match Self::prepare_write_request(
                                transaction,
                                cur_aligned_write_region_states_allocation_blocks_index_range.clone(),
                                rng,
                            ) {
                                Ok(write_request) => write_request,
                                Err((transaction, e)) => {
                                    self.fut_state = TransactionWriteDirtyDataFutureState::Done;
                                    return task::Poll::Ready(Ok((
                                        transaction,
                                        self.request_states_range_offsets.take(),
                                        Err(e),
                                    )));
                                }
                            };

                            let fs_instance = fs_instance_sync_state.get_fs_ref();
                            let cur_aligned_write_region_write_fut = match fs_instance.blkdev.write(write_request) {
                                Ok(Ok(cur_aligned_write_region_write_fut)) => cur_aligned_write_region_write_fut,
                                Ok(Err((write_request, e))) => {
                                    self.fut_state = TransactionWriteDirtyDataFutureState::Done;
                                    return task::Poll::Ready(Ok((
                                        write_request.transaction,
                                        self.request_states_range_offsets.take(),
                                        Err(NvFsError::from(e)),
                                    )));
                                }
                                Err(e) => {
                                    self.fut_state = TransactionWriteDirtyDataFutureState::Done;
                                    return task::Poll::Ready(Err(NvFsError::from(e)));
                                }
                            };
                            self.fut_state = TransactionWriteDirtyDataFutureState::RegionWrite {
                                cur_aligned_write_region_states_allocation_blocks_index_range:
                                    cur_aligned_write_region_states_allocation_blocks_index_range.clone(),
                                cur_aligned_write_region_write_fut,
                            };
                        }
                    }
                }
                TransactionWriteDirtyDataFutureState::RegionWrite {
                    cur_aligned_write_region_states_allocation_blocks_index_range,
                    cur_aligned_write_region_write_fut,
                } => {
                    let fs_instance = fs_instance_sync_state.get_fs_ref();
                    match blkdev::NvBlkDevFuture::poll(
                        pin::Pin::new(cur_aligned_write_region_write_fut),
                        &fs_instance.blkdev,
                        cx,
                    ) {
                        task::Poll::Ready(Ok((write_request, Ok(())))) => {
                            let mut transaction = write_request.transaction;
                            transaction
                                .auth_tree_data_blocks_update_states
                                .mark_states_clean(cur_aligned_write_region_states_allocation_blocks_index_range);
                            self.fut_state = TransactionWriteDirtyDataFutureState::Init {
                                transaction: Some(transaction),
                            };
                        }
                        task::Poll::Ready(Ok((write_request, Err(e)))) => {
                            self.fut_state = TransactionWriteDirtyDataFutureState::Done;
                            return task::Poll::Ready(Ok((
                                write_request.transaction,
                                self.request_states_range_offsets.take(),
                                Err(NvFsError::from(e)),
                            )));
                        }
                        task::Poll::Ready(Err(e)) => {
                            self.fut_state = TransactionWriteDirtyDataFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    }
                }
                TransactionWriteDirtyDataFutureState::Done => unreachable!(),
            }
        }
    }
}

/// Determine the minimum IO block size for writes.
///
/// Return the base-2 logarithm of the minimum IO block size in units of
/// [Allocation
/// Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
///
/// # Arguments:
///
/// * `blkdev_io_block_size_128b_log2` - Value of
///   [`NvBlkDev::io_block_size_128b_log2()`](blkdev::NvBlkDev::io_block_size_128b_log2).
/// * `allocation_block_size_128b_log2` - Verbatim value of
///   [`ImageLayout::allocation_block_size_128b_log2`](layout::ImageLayout::allocation_block_size_128b_log2).
pub(super) fn min_write_block_allocation_blocks_log2(
    blkdev_io_block_size_128b_log2: u32,
    allocation_block_size_128b_log2: u32,
) -> u32 {
    // The minimum IO unit is the maximum of the Device IO block and the Allocation
    // Block sizes.
    blkdev_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2)
}

/// [`NvBlkDevWriteRequest`](blkdev::NvBlkDevWriteRequest) implementation used
/// internally by [`TransactionWriteDirtyDataFuture`].
struct TransactionWriteDirtyDataNvBlkDevWriteRequest {
    transaction: Box<Transaction>,
    aligned_write_region_states_allocation_blocks_index_range: AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    request_io_region: ChunkedIoRegion,
    disguised_src_allocation_block_buffers: Option<FixedVec<Option<FixedVec<u8, 7>>, 0>>,
}

impl blkdev::NvBlkDevWriteRequest for TransactionWriteDirtyDataNvBlkDevWriteRequest {
    fn region(&self) -> &ChunkedIoRegion {
        &self.request_io_region
    }

    /// Get access to the destination buffer slice associated with a
    /// [`ChunkedIoRegionChunkRange`].
    fn get_source_buffer(&self, range: &ChunkedIoRegionChunkRange) -> Result<&[u8], blkdev::NvBlkDevIoError> {
        let (allocation_block_index_in_request, _) = range.chunk().decompose_to_hierarchic_indices([]);

        // If the Allocation Block has been disguised for the Journal Staging Copy,
        // return a reference to the temporary holding the disguised contents.
        // Otherwise return a reference to the data cached at the transaction's
        // state entry for the block.
        if let Some(src_allocation_block_buffer) =
            self.disguised_src_allocation_block_buffers
                .as_ref()
                .and_then(|disguised_src_allocation_block_buffers| {
                    disguised_src_allocation_block_buffers[allocation_block_index_in_request].as_deref()
                })
        {
            return Ok(&src_allocation_block_buffer[range.range_in_chunk().clone()]);
        }

        let auth_tree_data_block_allocation_blocks_log2 =
            self.transaction.auth_tree_data_block_allocation_blocks_log2 as u32;
        let src_allocation_block_buffer = match &self.transaction.auth_tree_data_blocks_update_states[self
            .aligned_write_region_states_allocation_blocks_index_range
            .begin()
            .advance(
                layout::AllocBlockCount::from(allocation_block_index_in_request as u64),
                auth_tree_data_block_allocation_blocks_log2,
            )]
        .nv_sync_state
        {
            AllocationBlockUpdateNvSyncState::Unallocated(unallocated_state) => unallocated_state
                .random_fillup
                .as_deref()
                .ok_or_else(|| nvblkdev_err_internal!())?,
            AllocationBlockUpdateNvSyncState::Allocated(allocated_state) => match allocated_state {
                AllocationBlockUpdateNvSyncStateAllocated::Unmodified(unmodified_state) => unmodified_state
                    .cached_encrypted_data
                    .as_ref()
                    .map(|cached_encrypted_data| cached_encrypted_data.get_encrypted_data())
                    .ok_or_else(|| nvblkdev_err_internal!())?,
                AllocationBlockUpdateNvSyncStateAllocated::Modified(modified_state) => match modified_state {
                    AllocationBlockUpdateNvSyncStateAllocatedModified::JournalDirty {
                        authenticated_encrypted_data,
                    } => authenticated_encrypted_data,
                    AllocationBlockUpdateNvSyncStateAllocatedModified::JournalClean { cached_encrypted_data } => {
                        cached_encrypted_data
                            .as_ref()
                            .map(|cached_encrypted_data| cached_encrypted_data.get_encrypted_data())
                            .ok_or_else(|| nvblkdev_err_internal!())?
                    }
                },
            },
        };

        Ok(&src_allocation_block_buffer[range.range_in_chunk().clone()])
    }
}
