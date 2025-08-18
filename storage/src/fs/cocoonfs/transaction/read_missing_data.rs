// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`TransactionReadMissingDataFuture`].

extern crate alloc;
use alloc::boxed::Box;
use cocoon_tpm_utils_common::fixed_vec::FixedVec;

use super::{
    Transaction,
    auth_tree_data_blocks_update_states::{
        AllocationBlockUpdateNvSyncState, AllocationBlockUpdateNvSyncStateAllocated,
        AllocationBlockUpdateNvSyncStateAllocatedModified, AuthTreeDataBlocksUpdateStatesAllocationBlockIndex,
        AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets, AuthTreeDataBlocksUpdateStatesIndex,
        AuthTreeDataBlocksUpdateStatesIndexRange, CachedEncryptedAllocationBlockData,
    },
    journal,
    write_dirty_data::min_write_block_allocation_blocks_log2,
};
use crate::{
    chip::{self, ChunkedIoRegion, ChunkedIoRegionChunkRange},
    fs::{
        NvFsError,
        cocoonfs::{alloc_bitmap, layout},
    },
    nvfs_err_internal,
    utils_common::bitmanip::BitManip as _,
};
use core::{pin, task};

#[cfg(doc)]
use super::auth_tree_data_blocks_update_states::{AuthTreeDataBlockUpdateState, AuthTreeDataBlocksUpdateStates};
#[cfg(doc)]
use layout::ImageLayout;

/// Read missing data from storage.
///
/// Read all missing data from storage within a specified [Allocation Block
/// level index range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange)
/// into the [`Transaction`]'s [storage tracking
/// states](AllocationBlockUpdateNvSyncState)' buffers.
///
/// Does not authenticate, see
/// [TransactionReadAuthenticateDataFuture](super::read_authenticate_data::TransactionReadAuthenticateDataFuture)
/// for that.
///
/// Note that the data loaded for a particular [Allocation
/// Block](ImageLayout::allocation_block_size_128b_log2) might perhaps have been
/// superseded logically by [staged
/// updates](super::auth_tree_data_blocks_update_states::AllocationBlockUpdateStagedUpdate), but
/// could still be needed to form an authentication digest over the containing
/// [Authentication Tree
/// Data Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2).
///
/// Only
/// [`AllocationBlockUpdateState`](super::auth_tree_data_blocks_update_states::AllocationBlockUpdateState)s
/// existing within the requested range at the time of
/// `TransactionReadMissingDataFuture` instantiation will be considered.
/// Additional ones may get inserted and populated as a byproduct
/// for [IO Block](ImageLayout::io_block_allocation_blocks_log2) alignment
/// purposes in the course though.
pub(super) struct TransactionReadMissingDataFuture<C: chip::NvChip> {
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference
    // on Self.
    transaction: Option<Box<Transaction>>,
    request_states_allocation_blocks_index_range: AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    request_states_index_range_offsets: Option<AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets>,
    remaining_states_allocation_blocks_index_range: AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    cur_region_read_fut: Option<C::ReadFuture<TransactionReadMissingDataFutureNvChipReadRequest>>,
}

impl<C: chip::NvChip> TransactionReadMissingDataFuture<C> {
    /// Instantiate a [`TransactionReadMissingDataFuture`].
    ///
    /// The [`TransactionReadMissingDataFuture`] assumes
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
    ///   populate the [storage tracking
    ///   states](AllocationBlockUpdateNvSyncState)' buffers within.  Applicable
    ///   [correction
    ///   offsets](AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets)
    ///   will get returned from [`poll()`](Self::poll) upon completion in case
    ///   additional state entries had to get inserted in order to [fill
    ///   alignment gaps](AuthTreeDataBlocksUpdateStates::fill_states_index_range_regions_alignment_gaps).
    pub fn new(
        transaction: Box<Transaction>,
        states_allocation_blocks_index_range: &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    ) -> Result<Self, (Box<Transaction>, NvFsError)> {
        let allocation_block_size_128b_log2 = transaction.allocation_block_size_128b_log2 as u32;
        let chip_io_block_size_128b_log2 = transaction.chip_io_block_size_128b_log2;

        // Possibly extend the range to also cover all already present states within the
        // reach of its Minimum Read Block alignment padding, if any.
        let min_read_block_allocation_blocks_log2 =
            Self::min_read_block_allocation_blocks_log2(chip_io_block_size_128b_log2, allocation_block_size_128b_log2);
        let remaining_states_allocation_blocks_index_range = transaction
            .auth_tree_data_blocks_update_states
            .extend_states_allocation_blocks_index_range_within_alignment(
                states_allocation_blocks_index_range,
                min_read_block_allocation_blocks_log2,
            );

        Ok(Self {
            transaction: Some(transaction),
            request_states_allocation_blocks_index_range: states_allocation_blocks_index_range.clone(),
            request_states_index_range_offsets: None,
            remaining_states_allocation_blocks_index_range,
            cur_region_read_fut: None,
        })
    }

    /// Poll the [`TransactionReadMissingDataFuture`] to completion.
    ///
    /// A two-level [`Result`] is returned upon
    /// [future](TransactionReadMissingDataFuture) completion.
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
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `fs_sync_state_alloc_bitmap` - The [filesystem instance's allocation
    ///   bitmap](crate::fs::cocoonfs::fs::CocoonFsSyncState::alloc_bitmap).
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    #[allow(clippy::type_complexity)]
    pub fn poll(
        self: pin::Pin<&mut Self>,
        chip: &C,
        fs_sync_state_alloc_bitmap: &alloc_bitmap::AllocBitmap,
        cx: &mut core::task::Context<'_>,
    ) -> task::Poll<
        Result<
            (
                Box<Transaction>,
                Option<AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets>,
                Result<(), NvFsError>,
            ),
            NvFsError,
        >,
    > {
        let this = pin::Pin::into_inner(self);
        loop {
            let transaction = this.transaction.as_mut().ok_or_else(|| nvfs_err_internal!())?;
            if let Some(cur_region_read_fut) = this.cur_region_read_fut.as_mut() {
                match chip::NvChipFuture::poll(pin::Pin::new(cur_region_read_fut), chip, cx) {
                    task::Poll::Pending => {
                        return task::Poll::Pending;
                    }
                    task::Poll::Ready(Ok((completed_read_request, Ok(())))) => {
                        this.cur_region_read_fut = None;
                        if let Err(e) = Self::apply_read_request_result(transaction, completed_read_request) {
                            return task::Poll::Ready(
                                this.transaction
                                    .take()
                                    .map(|transaction| {
                                        (transaction, this.request_states_index_range_offsets.take(), Err(e))
                                    })
                                    .ok_or_else(|| nvfs_err_internal!()),
                            );
                        }
                    }
                    task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                        return task::Poll::Ready(
                            this.transaction
                                .take()
                                .map(|transaction| {
                                    (
                                        transaction,
                                        this.request_states_index_range_offsets.take(),
                                        Err(NvFsError::from(e)),
                                    )
                                })
                                .ok_or_else(|| nvfs_err_internal!()),
                        );
                    }
                }
            }

            let next_read_region_states_allocation_blocks_range;
            (
                next_read_region_states_allocation_blocks_range,
                this.remaining_states_allocation_blocks_index_range,
            ) = Self::determine_next_read_region(
                transaction,
                &this.remaining_states_allocation_blocks_index_range,
                &this.request_states_allocation_blocks_index_range,
            );
            let (next_read_region_states_allocation_blocks_range, read_from_target) =
                match next_read_region_states_allocation_blocks_range {
                    Some((next_read_region_states_allocation_blocks_range, read_from_target)) => {
                        (next_read_region_states_allocation_blocks_range, read_from_target)
                    }
                    None => {
                        return task::Poll::Ready(
                            this.transaction
                                .take()
                                .map(|transaction| {
                                    (transaction, this.request_states_index_range_offsets.take(), Ok(()))
                                })
                                .ok_or_else(|| nvfs_err_internal!()),
                        );
                    }
                };
            let read_request = match this.prepare_read_request(
                fs_sync_state_alloc_bitmap,
                next_read_region_states_allocation_blocks_range,
                read_from_target,
            ) {
                Ok(read_request) => read_request,
                Err(e) => {
                    return task::Poll::Ready(
                        this.transaction
                            .take()
                            .map(|transaction| (transaction, this.request_states_index_range_offsets.take(), Err(e)))
                            .ok_or_else(|| nvfs_err_internal!()),
                    );
                }
            };

            this.cur_region_read_fut = Some(match chip.read(read_request).and_then(|r| r.map_err(|(_, e)| e)) {
                Ok(next_region_read_fut) => next_region_read_fut,
                Err(e) => {
                    return task::Poll::Ready(
                        this.transaction
                            .take()
                            .map(|transaction| {
                                (
                                    transaction,
                                    this.request_states_index_range_offsets.take(),
                                    Err(NvFsError::from(e)),
                                )
                            })
                            .ok_or_else(|| nvfs_err_internal!()),
                    );
                }
            });
        }
    }

    /// Determine the minimum IO block size.
    ///
    /// Return the base-2 logarithm of the minimum IO block size in units of
    /// [Allocation Blocks](ImageLayout::allocation_block_size_128b_log2).
    ///
    /// # Arguments:
    ///
    /// * `chip_io_block_size_128b_log2` - Value of
    ///   [`NvChip::chip_io_block_size_128b_log2()`](chip::NvChip::chip_io_block_size_128b_log2).
    /// * `allocation_block_size_128b_log2` - Verbatim value of
    ///   [`ImageLayout::allocation_block_size_128b_log2`].
    pub fn min_read_block_allocation_blocks_log2(
        chip_io_block_size_128b_log2: u32,
        allocation_block_size_128b_log2: u32,
    ) -> u32 {
        // The minimum IO unit is the maximum of the Chip IO block and the Allocation
        // Block sizes.
        chip_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2)
    }

    /// Determine the preferred IO block size.
    ///
    /// Return the base-2 logarithm of the preferred IO block size in units of
    /// [Allocation Blocks](ImageLayout::allocation_block_size_128b_log2).
    ///
    /// # Arguments:
    ///
    /// * `chip_io_block_size_128b_log2` - Value of
    ///   [`NvChip::chip_io_block_size_128b_log2()`](chip::NvChip::chip_io_block_size_128b_log2).
    /// * `preferred_chip_io_blocks_bulk_log2` - Value of
    ///   [`NvChip::preferred_chip_io_blocks_bulk_log2()`](chip::NvChip::preferred_chip_io_blocks_bulk_log2).
    /// * `allocation_block_size_128b_log2` - Verbatim value of
    ///   [`ImageLayout::allocation_block_size_128b_log2`].
    /// * `auth_tree_data_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::auth_tree_data_block_allocation_blocks_log2`].
    pub fn preferred_read_block_allocation_blocks_log2(
        chip_io_block_size_128b_log2: u32,
        preferred_chip_io_blocks_bulk_log2: u32,
        allocation_block_size_128b_log2: u32,
        auth_tree_data_block_allocation_blocks_log2: u32,
    ) -> u32 {
        // Determine the preferred Bulk IO size: consider the value announced by the
        // NvChip, but ramp it up to some larger reasonable value in order to
        // reduce the overall number of IO requests.
        (preferred_chip_io_blocks_bulk_log2 + chip_io_block_size_128b_log2)
            .saturating_sub(allocation_block_size_128b_log2)
            .min(usize::BITS - 1)
            .max(auth_tree_data_block_allocation_blocks_log2)
    }

    /// Determine the next subrange to read.
    ///
    /// Return a pair with information about the next subrange to read, if any,
    /// stored in the first component, and the remainder of
    /// `remaining_states_allocation_blocks_index_range` to process
    /// in a subsequent iteration in the second. The information about the next
    /// subrange to read comprises the range itself, alongside an `bool`
    /// specifying where to read the data from -- either from the update
    /// states' associated [target location on
    /// storage](AuthTreeDataBlockUpdateState::get_target_allocation_blocks_begin) if true, or from
    /// the [journal staging
    /// copy](AuthTreeDataBlockUpdateState::get_journal_staging_copy_allocation_blocks_begin)
    /// otherwise.
    ///
    /// # Arguments:
    ///
    /// * `transaction` - The [`Transaction`].
    /// * `remaining_states_allocation_blocks_index_range` - Remaining part of
    ///   the `request_states_allocation_blocks_index_range` not processed yet,
    ///   extended to cover any preexisting states within the [`minimum IO
    ///   Block`](Self::min_read_block_allocation_blocks_log2) vicinity.
    /// * `request_states_allocation_blocks_range` - The original input request
    ///   range.
    fn determine_next_read_region(
        transaction: &Transaction,
        remaining_states_allocation_blocks_index_range: &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        request_states_allocation_blocks_index_range: &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    ) -> (
        Option<(AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange, bool)>,
        AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    ) {
        let allocation_block_size_128b_log2 = transaction.allocation_block_size_128b_log2 as u32;
        let auth_tree_data_block_allocation_blocks_log2 =
            transaction.auth_tree_data_block_allocation_blocks_log2 as u32;
        let io_block_allocation_blocks_log2 = transaction.io_block_allocation_blocks_log2 as u32;
        let chip_io_block_size_128b_log2 = transaction.chip_io_block_size_128b_log2;
        let preferred_chip_io_blocks_bulk_log2 = transaction.preferred_chip_io_blocks_bulk_log2;

        let mut remaining_states_allocation_blocks_index_range = remaining_states_allocation_blocks_index_range.clone();
        let states = &transaction.auth_tree_data_blocks_update_states;
        let min_read_block_allocation_blocks_log2 =
            Self::min_read_block_allocation_blocks_log2(chip_io_block_size_128b_log2, allocation_block_size_128b_log2);
        // The logic below assumes that a Minimum Read Block has either been written
        // fully to the Journal or not at all, which is implied by the
        // requirement that a Minimum Write Block is >= a Minimum Read Block.
        debug_assert!(
            min_read_block_allocation_blocks_log2
                <= min_write_block_allocation_blocks_log2(
                    chip_io_block_size_128b_log2,
                    allocation_block_size_128b_log2
                )
        );

        // Determine the preferred Bulk IO size: consider the value announced by the
        // NvChip, but ramp it up to some larger reasonable value in order to
        // reduce the overall number of IO requests.
        let preferred_read_block_allocation_blocks_log2 = Self::preferred_read_block_allocation_blocks_log2(
            chip_io_block_size_128b_log2,
            preferred_chip_io_blocks_bulk_log2,
            allocation_block_size_128b_log2,
            auth_tree_data_block_allocation_blocks_log2,
        );

        struct LastNeedingReadInfo {
            states_allocation_block_index: AuthTreeDataBlocksUpdateStatesAllocationBlockIndex,
            min_read_block_target_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        }
        let mut last_needing_read: Option<LastNeedingReadInfo> = None;
        let mut can_read_from_target = true;
        let mut can_read_from_journal = true;

        // Loop over Minimum Read Blocks, searching for the first maximal subsequence of
        // those needing data reads and which can get processed in one go.
        let mut cur_min_read_block_states_allocation_blocks_index_range_begin =
            *remaining_states_allocation_blocks_index_range.begin();
        while cur_min_read_block_states_allocation_blocks_index_range_begin
            != *remaining_states_allocation_blocks_index_range.end()
        {
            // Mind that Minimum Read Blocks might be tracked only partially by states[] at
            // this point, so there might be a gap at the beginning.
            let cur_target_allocation_block =
                states.get_allocation_block_target(&cur_min_read_block_states_allocation_blocks_index_range_begin);
            let cur_min_read_block_target_allocation_blocks_begin =
                cur_target_allocation_block.align_down(min_read_block_allocation_blocks_log2);
            if let Some(last_needing_read) = &last_needing_read {
                // The states array is sorted by target Allocation Block index.
                debug_assert!(
                    cur_min_read_block_target_allocation_blocks_begin
                        > last_needing_read.min_read_block_target_allocation_blocks_begin
                );

                // Always read in contiguous regions at a time. If there's a Mininum Read
                // Block gap not needing any read, then stop and process what
                // has been found so far.
                if cur_min_read_block_target_allocation_blocks_begin
                    - last_needing_read.min_read_block_target_allocation_blocks_begin
                    > layout::AllocBlockCount::from(1u64 << min_read_block_allocation_blocks_log2)
                {
                    break;
                }

                debug_assert!(
                    preferred_read_block_allocation_blocks_log2 >= auth_tree_data_block_allocation_blocks_log2
                );
                if AuthTreeDataBlocksUpdateStatesIndex::from(
                    cur_min_read_block_states_allocation_blocks_index_range_begin,
                ) != AuthTreeDataBlocksUpdateStatesIndex::from(last_needing_read.states_allocation_block_index)
                {
                    // If something had been found already and we're crossing a
                    // preferred_read_block_allocation_blocks_log2 boundary, then stop.
                    if last_needing_read
                        .min_read_block_target_allocation_blocks_begin
                        .align_down(preferred_read_block_allocation_blocks_log2)
                        != cur_min_read_block_target_allocation_blocks_begin
                            .align_down(preferred_read_block_allocation_blocks_log2)
                    {
                        break;
                    }
                }
            } else {
                // Nothing found yet in any of the previous Minimum Read Blocks, advance the
                // region's beginning to the current position.
                remaining_states_allocation_blocks_index_range =
                    AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::new(
                        &cur_min_read_block_states_allocation_blocks_index_range_begin,
                        remaining_states_allocation_blocks_index_range.end(),
                    );
            }

            let mut cur_min_read_block_has_gaps = false;
            let mut cur_min_read_block_any_needs_data_read = false;
            let mut cur_min_read_block_any_unitialized = false;
            let mut cur_min_read_block_any_not_unitialized = false;
            let mut cur_min_read_block_any_not_can_read_from_target = false;
            let mut cur_min_read_block_any_can_read_from_journal = false;
            let mut cur_min_read_block_any_not_can_read_from_journal = false;

            let mut cur_states_allocation_block_index = cur_min_read_block_states_allocation_blocks_index_range_begin;
            let mut next_states_allocation_block_index =
                cur_states_allocation_block_index.step(auth_tree_data_block_allocation_blocks_log2);
            if cur_target_allocation_block != cur_min_read_block_target_allocation_blocks_begin {
                // There's a gap of missing states at the beginning.
                cur_min_read_block_has_gaps = true;
            }
            let mut cur_target_allocation_block = cur_target_allocation_block;
            loop {
                enum AllocationBlockNvSyncStateInfo {
                    Uninitialized,
                    HasDataLoaded,
                    NeedsDataRead {
                        can_read_from_target: bool,
                        can_read_from_journal: bool,
                    },
                }

                fn inspect_allocation_block_nv_sync_state(
                    nv_sync_state: &AllocationBlockUpdateNvSyncState,
                ) -> AllocationBlockNvSyncStateInfo {
                    match nv_sync_state {
                        AllocationBlockUpdateNvSyncState::Unallocated(unallocated_state) => {
                            if !unallocated_state.target_state.is_initialized() && !unallocated_state.copied_to_journal
                            {
                                AllocationBlockNvSyncStateInfo::Uninitialized
                            } else if unallocated_state.random_fillup.is_some() {
                                AllocationBlockNvSyncStateInfo::HasDataLoaded
                            } else {
                                AllocationBlockNvSyncStateInfo::NeedsDataRead {
                                    can_read_from_target: unallocated_state.target_state.is_initialized(),
                                    can_read_from_journal: unallocated_state.copied_to_journal,
                                }
                            }
                        }
                        AllocationBlockUpdateNvSyncState::Allocated(allocated_state) => match allocated_state {
                            AllocationBlockUpdateNvSyncStateAllocated::Unmodified(unmodified_state) => {
                                if unmodified_state.cached_encrypted_data.is_some() {
                                    AllocationBlockNvSyncStateInfo::HasDataLoaded
                                } else {
                                    AllocationBlockNvSyncStateInfo::NeedsDataRead {
                                        can_read_from_target: true,
                                        can_read_from_journal: unmodified_state.copied_to_journal,
                                    }
                                }
                            }
                            AllocationBlockUpdateNvSyncStateAllocated::Modified(modified_state) => match modified_state
                            {
                                AllocationBlockUpdateNvSyncStateAllocatedModified::JournalDirty { .. } => {
                                    AllocationBlockNvSyncStateInfo::HasDataLoaded
                                }
                                AllocationBlockUpdateNvSyncStateAllocatedModified::JournalClean {
                                    cached_encrypted_data,
                                } => {
                                    if cached_encrypted_data.is_some() {
                                        AllocationBlockNvSyncStateInfo::HasDataLoaded
                                    } else {
                                        AllocationBlockNvSyncStateInfo::NeedsDataRead {
                                            can_read_from_target: false,
                                            can_read_from_journal: true,
                                        }
                                    }
                                }
                            },
                        },
                    }
                }
                let info =
                    inspect_allocation_block_nv_sync_state(&states[cur_states_allocation_block_index].nv_sync_state);
                match info {
                    AllocationBlockNvSyncStateInfo::Uninitialized => {
                        cur_min_read_block_any_unitialized = true;
                        cur_min_read_block_any_not_can_read_from_target = true;
                        cur_min_read_block_any_not_can_read_from_journal = true;
                    }
                    AllocationBlockNvSyncStateInfo::HasDataLoaded => {}
                    AllocationBlockNvSyncStateInfo::NeedsDataRead {
                        can_read_from_target,
                        can_read_from_journal,
                    } => {
                        // The Allocation Block would need a data read, but only if it's within the
                        // original requested range.
                        cur_min_read_block_any_needs_data_read |= cur_states_allocation_block_index
                            >= *request_states_allocation_blocks_index_range.begin()
                            && cur_states_allocation_block_index < *request_states_allocation_blocks_index_range.end();

                        cur_min_read_block_any_not_unitialized = true;
                        cur_min_read_block_any_not_can_read_from_target |= !can_read_from_target;
                        cur_min_read_block_any_can_read_from_journal |= can_read_from_journal;
                        cur_min_read_block_any_not_can_read_from_journal |= !can_read_from_journal;
                    }
                }

                // Advance to the next Allocation Block to process in the subsequent loop
                // iteration.
                if next_states_allocation_block_index == *remaining_states_allocation_blocks_index_range.end() {
                    break;
                }
                let next_target_allocation_block =
                    states.get_allocation_block_target(&next_states_allocation_block_index);
                if next_target_allocation_block.align_down(min_read_block_allocation_blocks_log2)
                    != cur_min_read_block_target_allocation_blocks_begin
                {
                    // Reached the end of the current Minimum Read Block, break out and analyze what
                    // has been found so far.
                    break;
                }
                if next_target_allocation_block - cur_target_allocation_block != layout::AllocBlockCount::from(1) {
                    // There's a gap of missing states.
                    cur_min_read_block_has_gaps = true;
                }
                cur_states_allocation_block_index = next_states_allocation_block_index;
                next_states_allocation_block_index =
                    cur_states_allocation_block_index.step(auth_tree_data_block_allocation_blocks_log2);
                cur_target_allocation_block = next_target_allocation_block;
            }
            let cur_min_read_block_last_states_allocation_block_index = cur_states_allocation_block_index;
            let cur_min_read_block_states_allocation_blocks_index_range_end = next_states_allocation_block_index;
            if cur_target_allocation_block - cur_min_read_block_target_allocation_blocks_begin
                != layout::AllocBlockCount::from(u64::trailing_bits_mask(min_read_block_allocation_blocks_log2))
            {
                // There's a gap of missing states at the end.
                cur_min_read_block_has_gaps = true;
            }

            // If there's any Allocation Block from the current Minimum Read Block
            // uninitialized, then all should be.
            debug_assert!(!cur_min_read_block_any_unitialized || !cur_min_read_block_any_not_unitialized);

            if cur_min_read_block_any_unitialized {
                // Never ever request the NvChip to read uninitialized data. Skip over it one
                // way or another.
                cur_min_read_block_states_allocation_blocks_index_range_begin =
                    cur_min_read_block_states_allocation_blocks_index_range_end;
                if last_needing_read.is_some() {
                    break;
                } else {
                    continue;
                }
            }

            // If there's anything staged in the Journal, then everything should be.
            debug_assert!(
                !cur_min_read_block_any_can_read_from_journal || !cur_min_read_block_any_not_can_read_from_journal
            );
            // If there's been anything been written to the Journal, then the whole
            // Minimum Read Block should be present.
            debug_assert!(!cur_min_read_block_any_can_read_from_journal || !cur_min_read_block_has_gaps);
            cur_min_read_block_any_not_can_read_from_journal |= cur_min_read_block_has_gaps;

            // If everything's there, skip over the current Minimum Read Block.
            if !cur_min_read_block_any_needs_data_read {
                cur_min_read_block_states_allocation_blocks_index_range_begin =
                    cur_min_read_block_states_allocation_blocks_index_range_end;
                if last_needing_read.is_some() {
                    break;
                } else {
                    continue;
                }
            }

            let mut cur_min_read_block_can_read_from_journal = !cur_min_read_block_any_not_can_read_from_journal;
            let cur_min_read_block_can_read_from_target = !cur_min_read_block_any_not_can_read_from_target;
            // If any data is not loaded in memory, it better ought to be possible to find
            // it somewhere else then.
            debug_assert!(cur_min_read_block_can_read_from_target || cur_min_read_block_can_read_from_journal);

            if let Some(last_needing_read) = last_needing_read.as_ref() {
                // If Journal Staging Copy disguising is enabled, prefer reads from the target
                // location in order to save some undisguise operations.
                if transaction.journal_staging_copy_disguise.is_some()
                    && can_read_from_target != cur_min_read_block_can_read_from_target
                {
                    break;
                }

                // For potential reads from the journal, verify that the associated Journal Data
                // Staging Copy area extends contiguously from the previously found batch to the
                // current Minimum Read Block under inverstigation. Otherwise reading from the
                // journal in one go is not possible and the request must get split up.
                //
                // Note that Journal Data Staging areas get allocated IO Block- as well as
                // Authentication Tree Data Block wise, whichever is larger. So, in order to
                // potentially save some work, check first whether the containing Authentication
                // Tree Data Block is even different.
                if cur_min_read_block_can_read_from_journal
                    && can_read_from_journal
                    && AuthTreeDataBlocksUpdateStatesIndex::from(
                        cur_min_read_block_states_allocation_blocks_index_range_begin,
                    ) != AuthTreeDataBlocksUpdateStatesIndex::from(last_needing_read.states_allocation_block_index)
                {
                    let last_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin = states
                        [AuthTreeDataBlocksUpdateStatesIndex::from(last_needing_read.states_allocation_block_index)]
                    .get_journal_staging_copy_allocation_blocks_begin()
                    .unwrap();
                    let cur_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin = states
                        [AuthTreeDataBlocksUpdateStatesIndex::from(
                            cur_min_read_block_states_allocation_blocks_index_range_begin,
                        )]
                    .get_journal_staging_copy_allocation_blocks_begin()
                    .unwrap();
                    if cur_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin
                        < last_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin
                    {
                        cur_min_read_block_can_read_from_journal = false;
                    } else {
                        // We know at this point that we're at most one Chip IO block ahead, as
                        // per the initial loop condition stopping the search at Minimum Read
                        // Block sized gaps. As the Minimum Read Block is less or equal than an
                        // IO block in size, it follows that the current position is at most one
                        // IO Block ahead. So a necessary and sufficient condition is that the
                        // two Journal Data Staging areas's beginnings are not separated by more
                        // than either an IO Block or Authentication Tree Data Block, whichever
                        // is larger.
                        debug_assert!(min_read_block_allocation_blocks_log2 <= io_block_allocation_blocks_log2);
                        debug_assert!(
                            cur_min_read_block_target_allocation_blocks_begin
                                .align_down(io_block_allocation_blocks_log2)
                                - last_needing_read
                                    .min_read_block_target_allocation_blocks_begin
                                    .align_down(io_block_allocation_blocks_log2)
                                <= layout::AllocBlockCount::from(1u64 << io_block_allocation_blocks_log2)
                        );
                        if cur_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin
                            - last_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin
                            > layout::AllocBlockCount::from(
                                1u64 << io_block_allocation_blocks_log2
                                    .max(auth_tree_data_block_allocation_blocks_log2),
                            )
                        {
                            cur_min_read_block_can_read_from_journal = false;
                        }
                    }
                }
            }

            debug_assert!(can_read_from_target || can_read_from_journal);
            if !cur_min_read_block_can_read_from_journal {
                if !can_read_from_target || !cur_min_read_block_can_read_from_target {
                    break;
                }
                can_read_from_journal = false;
            } else if !cur_min_read_block_can_read_from_target {
                if !can_read_from_journal {
                    break;
                }
                can_read_from_target = false;
            }

            last_needing_read = Some(LastNeedingReadInfo {
                states_allocation_block_index: cur_min_read_block_last_states_allocation_block_index,
                min_read_block_target_allocation_blocks_begin: cur_min_read_block_target_allocation_blocks_begin,
            });

            cur_min_read_block_states_allocation_blocks_index_range_begin =
                cur_min_read_block_states_allocation_blocks_index_range_end;
        }

        if let Some(last_needing_read_states_allocation_block_index) =
            last_needing_read.as_ref().map(|l| l.states_allocation_block_index)
        {
            let batch_needing_read_states_allocation_blocks_index_range_begin =
                remaining_states_allocation_blocks_index_range.begin();
            let batch_needing_read_states_allocation_blocks_index_range_end =
                last_needing_read_states_allocation_block_index.step(auth_tree_data_block_allocation_blocks_log2);
            debug_assert!(
                batch_needing_read_states_allocation_blocks_index_range_end
                    <= cur_min_read_block_states_allocation_blocks_index_range_begin
            );
            (
                Some((
                    AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::new(
                        batch_needing_read_states_allocation_blocks_index_range_begin,
                        &batch_needing_read_states_allocation_blocks_index_range_end,
                    ),
                    can_read_from_target,
                )),
                AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::new(
                    &cur_min_read_block_states_allocation_blocks_index_range_begin,
                    remaining_states_allocation_blocks_index_range.end(),
                ),
            )
        } else {
            debug_assert_eq!(
                cur_min_read_block_states_allocation_blocks_index_range_begin,
                *remaining_states_allocation_blocks_index_range.end()
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

    /// Prepare a storage read request.
    ///
    /// # Arguments:
    ///
    /// * `fs_sync_state_alloc_bitmap` - The [filesystem instance's allocation
    ///   bitmap](crate::fs::cocoonfs::fs::CocoonFsSyncState::alloc_bitmap).
    /// * `read_region_states_allocation_blocks_index_range` - [Allocation Block
    ///   level entry index
    ///   range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange) to
    ///   read in.
    /// * `read_from_target` - Where to read from -- either from the update
    ///   states' associated [target location on
    ///   storage](AuthTreeDataBlockUpdateState::get_target_allocation_blocks_begin)
    ///   if true, or from the [journal staging
    ///   copy](AuthTreeDataBlockUpdateState::get_journal_staging_copy_allocation_blocks_begin)
    ///   otherwise.
    fn prepare_read_request(
        &mut self,
        fs_sync_state_alloc_bitmap: &alloc_bitmap::AllocBitmap,
        read_region_states_allocation_blocks_index_range: AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        read_from_target: bool,
    ) -> Result<TransactionReadMissingDataFutureNvChipReadRequest, NvFsError> {
        let transaction = self.transaction.as_mut().ok_or_else(|| nvfs_err_internal!())?;
        let allocation_block_size_128b_log2 = transaction.allocation_block_size_128b_log2 as u32;
        let allocation_block_size = 1usize << (allocation_block_size_128b_log2 + 7);
        let auth_tree_data_block_allocation_blocks_log2 =
            transaction.auth_tree_data_block_allocation_blocks_log2 as u32;
        let chip_io_block_size_128b_log2 = transaction.chip_io_block_size_128b_log2;
        // The minimum IO unit is the maximum of the Chip IO block and the Allocation
        // Block sizes.
        let min_read_block_allocation_blocks_log2 =
            Self::min_read_block_allocation_blocks_log2(chip_io_block_size_128b_log2, allocation_block_size_128b_log2);

        let states = &mut transaction.auth_tree_data_blocks_update_states;
        // Fill alignment gaps in the current read region, adjust the original input
        // range as well as the remaining range in order to account for
        // the newly added states entries.
        //
        // Before doing the fill (and invalidating the index ranges), save away some
        // information needed to fixup the original input request index range
        // later.
        let (
            request_range_missing_states_before_in_read_range_count,
            request_range_missing_tail_states_in_read_range_count,
        ) = {
            let request_states_index_range = AuthTreeDataBlocksUpdateStatesIndexRange::from(
                self.request_states_allocation_blocks_index_range.clone(),
            );
            let read_region_states_index_range = AuthTreeDataBlocksUpdateStatesIndexRange::from(
                read_region_states_allocation_blocks_index_range.clone(),
            );
            // The effective read range does get extended within Minimum Read Block
            // alignment, but should always overlap with the original request.
            debug_assert!(request_states_index_range.begin() < read_region_states_index_range.end());
            debug_assert!(request_states_index_range.end() > read_region_states_index_range.begin());
            // Also, Self::determine_next_read_region() would always return ranges already
            // maximal within the alignment distance.
            debug_assert_eq!(
                states.extend_states_allocation_blocks_index_range_within_alignment(
                    &read_region_states_allocation_blocks_index_range,
                    min_read_block_allocation_blocks_log2
                ),
                read_region_states_allocation_blocks_index_range
            );
            // Also, there's no aligned gap in the read range, all missing states
            // will get filled up.
            debug_assert!(
                states.find_aligned_gap_after(
                    read_region_states_index_range.begin(),
                    min_read_block_allocation_blocks_log2
                ) >= read_region_states_index_range.end()
            );

            // The number of missing states within the read region index range and before
            // the request index range, if any. It's the difference of what is
            // expected and what's already there.
            let request_range_missing_states_before_in_read_range_count = if read_region_states_index_range.begin()
                <= request_states_index_range.begin()
            {
                let request_range_begin_auth_tree_data_blocks_offset_in_read_range = u64::from(
                    states[request_states_index_range.begin()].get_target_allocation_blocks_begin()
                        - states[read_region_states_index_range.begin()].get_target_allocation_blocks_begin(),
                )
                    >> auth_tree_data_block_allocation_blocks_log2;
                Some(
                    request_range_begin_auth_tree_data_blocks_offset_in_read_range
                        - AuthTreeDataBlocksUpdateStatesIndexRange::new(
                            read_region_states_index_range.begin(),
                            request_states_index_range.begin(),
                        )
                        .len() as u64,
                )
            } else {
                // The current read region's and the original input request's beginnings are
                // in different Minimum Read Blocks. In particular, all states filled up for
                // aligning the former will get inserted after the latter.
                debug_assert_eq!(
                    (u64::from(states[read_region_states_index_range.begin()].get_target_allocation_blocks_begin())
                        ^ u64::from(states[request_states_index_range.begin()].get_target_allocation_blocks_begin()))
                        >> min_read_block_allocation_blocks_log2,
                    0
                );
                None
            };
            // The number of missing states within the read region index range overlapping
            // with the request index range's tail, if any. It's the difference of
            // what is expected and what's already there.
            let request_range_missing_tail_states_in_read_range_count =
                if read_region_states_index_range.end() >= request_states_index_range.end() {
                    let request_range_end_auth_tree_data_blocks_offset_in_read_range = (u64::from(
                        states[request_states_index_range
                            .end()
                            .step_back()
                            .ok_or_else(|| nvfs_err_internal!())?]
                        .get_target_allocation_blocks_begin()
                            - states[read_region_states_index_range.begin()].get_target_allocation_blocks_begin(),
                    )
                        >> auth_tree_data_block_allocation_blocks_log2)
                        + 1;
                    Some(
                        request_range_end_auth_tree_data_blocks_offset_in_read_range
                            - AuthTreeDataBlocksUpdateStatesIndexRange::new(
                                read_region_states_index_range.begin(),
                                request_states_index_range.end(),
                            )
                            .len() as u64
                            - request_range_missing_states_before_in_read_range_count.unwrap_or(0),
                    )
                } else {
                    // The current read region's and the original input request's ends are
                    // in different Minimum Read Blocks. In particular, all states filled up for
                    // aligning the former will get inserted before the latter.
                    debug_assert_ne!(
                        (u64::from(
                            states[read_region_states_index_range.end().step_back().unwrap()]
                                .get_target_allocation_blocks_begin()
                                + layout::AllocBlockCount::from(1u64 << auth_tree_data_block_allocation_blocks_log2)
                        ) ^ u64::from(
                            states[request_states_index_range.end().step_back().unwrap()]
                                .get_target_allocation_blocks_begin()
                                + layout::AllocBlockCount::from(1u64 << auth_tree_data_block_allocation_blocks_log2)
                        )) >> min_read_block_allocation_blocks_log2,
                        0
                    );
                    None
                };

            (
                request_range_missing_states_before_in_read_range_count,
                request_range_missing_tail_states_in_read_range_count,
            )
        };

        // Do the actual fillup.
        let (aligned_read_region_states_allocation_blocks_index_range, read_states_range_offsets) = states
            .fill_states_allocation_blocks_index_range_regions_alignment_gaps(
                &read_region_states_allocation_blocks_index_range,
                min_read_block_allocation_blocks_log2,
                fs_sync_state_alloc_bitmap,
                &transaction.allocs.pending_frees,
            );

        // Invalidated by now, and never fixed up again, avoid accidental use.
        #[allow(clippy::drop_non_drop)]
        drop(read_region_states_allocation_blocks_index_range);

        // If some states had been inserted, adjust the index ranges accordingly in
        // order to account for the new offsets in the states array.
        if let Some(read_states_range_offsets) = read_states_range_offsets {
            // If anything new has been inserted, then Self::determine_next_read_region()
            // should not have concluded that it's possible to read this region
            // back from the journal.
            debug_assert!(read_from_target);

            // Handle the original input request range first, so that the accumulated needed
            // adjustments can eventually get returned back from the future.
            let cur_request_states_range_offsets = {
                let inserted_states_before_request_range_count =
                    request_range_missing_states_before_in_read_range_count
                        .map(|request_range_missing_states_before_in_read_range_count| {
                            (read_states_range_offsets.total_inserted_states_count() as u64).min(
                                read_states_range_offsets.inserted_states_before_range_count as u64
                                    + request_range_missing_states_before_in_read_range_count,
                            ) as usize
                        })
                        .unwrap_or(0);
                let remaining_inserted_states_count = read_states_range_offsets.total_inserted_states_count()
                    - inserted_states_before_request_range_count;

                let inserted_states_within_request_range_count = request_range_missing_tail_states_in_read_range_count
                    .map(|request_range_missing_tail_states_in_read_range_count| {
                        (remaining_inserted_states_count as u64)
                            .min(request_range_missing_tail_states_in_read_range_count) as usize
                    })
                    .unwrap_or(remaining_inserted_states_count);
                let remaining_inserted_states_count =
                    remaining_inserted_states_count - inserted_states_within_request_range_count;

                let inserted_states_after_request_range_count = remaining_inserted_states_count;

                AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets {
                    inserted_states_before_range_count: inserted_states_before_request_range_count,
                    inserted_states_within_range_count: inserted_states_within_request_range_count,
                    inserted_states_after_range_count: inserted_states_after_request_range_count,
                    max_target_allocations_blocks_alignment_log2: min_read_block_allocation_blocks_log2,
                }
            };
            self.request_states_allocation_blocks_index_range = self
                .request_states_allocation_blocks_index_range
                .apply_states_insertions_offsets(
                    cur_request_states_range_offsets.inserted_states_before_range_count,
                    cur_request_states_range_offsets.inserted_states_within_range_count,
                );
            self.request_states_index_range_offsets = Some(
                self.request_states_index_range_offsets
                    .as_ref()
                    .map(|prev| prev.accumulate(&cur_request_states_range_offsets))
                    .unwrap_or(cur_request_states_range_offsets),
            );

            // Update the internally tracked index range of remaining regions to process.
            self.remaining_states_allocation_blocks_index_range = self
                .remaining_states_allocation_blocks_index_range
                .apply_states_insertions_offsets(read_states_range_offsets.total_inserted_states_count(), 0)
        }

        // Return upon failure only after the index ranges have been updated (it could
        // have failed midways).
        let aligned_read_region_states_allocation_blocks_index_range =
            aligned_read_region_states_allocation_blocks_index_range?;

        let src_allocation_blocks_range = if read_from_target {
            states.get_contiguous_region_target_range(&aligned_read_region_states_allocation_blocks_index_range)
        } else {
            states
                .get_contiguous_region_journal_staging_copy_range(
                    &aligned_read_region_states_allocation_blocks_index_range,
                )
                .ok_or_else(|| nvfs_err_internal!())?
        };

        // Finally prepare the read destination buffers and the read request itself.
        // The regions never span more than the preferred read bulk size as determined
        // by Self::determine_next_read_range(). In particular the Allocation Block
        // count will fit an usize.
        let allocation_blocks_count =
            usize::try_from(u64::from(src_allocation_blocks_range.block_count())).map_err(|_| nvfs_err_internal!())?;
        let mut dst_allocation_block_buffers = FixedVec::new_with_default(allocation_blocks_count)?;
        for (i, update_states_allocation_block_index) in aligned_read_region_states_allocation_blocks_index_range
            .iter(auth_tree_data_block_allocation_blocks_log2)
            .enumerate()
        {
            let needs_read = match &states[update_states_allocation_block_index].nv_sync_state {
                AllocationBlockUpdateNvSyncState::Unallocated(unallocated_state) => {
                    // Completely uninitialized Chip IO Blocks would have been filtered by
                    // Self::determine_next_read_range().
                    debug_assert!(
                        unallocated_state.target_state.is_initialized() || unallocated_state.copied_to_journal
                    );
                    unallocated_state.random_fillup.is_none()
                }
                AllocationBlockUpdateNvSyncState::Allocated(allocated_state) => match allocated_state {
                    AllocationBlockUpdateNvSyncStateAllocated::Unmodified(unmodified_state) => {
                        unmodified_state.cached_encrypted_data.is_none()
                    }
                    AllocationBlockUpdateNvSyncStateAllocated::Modified(modified_state) => match modified_state {
                        AllocationBlockUpdateNvSyncStateAllocatedModified::JournalDirty { .. } => false,
                        AllocationBlockUpdateNvSyncStateAllocatedModified::JournalClean { cached_encrypted_data } => {
                            cached_encrypted_data.is_none()
                        }
                    },
                },
            };

            if needs_read {
                let dst_allocation_block_buffer = FixedVec::new_with_default(allocation_block_size)?;
                dst_allocation_block_buffers[i] = Some(dst_allocation_block_buffer);
            }
        }

        Ok(TransactionReadMissingDataFutureNvChipReadRequest {
            read_region_states_allocation_blocks_index_range: aligned_read_region_states_allocation_blocks_index_range,
            read_from_target,
            request_io_region: ChunkedIoRegion::new(
                u64::from(src_allocation_blocks_range.begin()) << allocation_block_size_128b_log2,
                u64::from(src_allocation_blocks_range.end()) << allocation_block_size_128b_log2,
                allocation_block_size_128b_log2,
            )
            .map_err(|_| nvfs_err_internal!())?,
            dst_allocation_block_buffers,
        })
    }

    /// Apply the results of a completed storage read request.
    ///
    /// # Arguments:
    ///
    /// * `transaction` - The [`Transaction`].
    /// * `completed_read_request` - The completed storage read request.
    fn apply_read_request_result(
        transaction: &mut Transaction,
        completed_read_request: TransactionReadMissingDataFutureNvChipReadRequest,
    ) -> Result<(), NvFsError> {
        let auth_tree_data_block_allocation_blocks_log2 =
            transaction.auth_tree_data_block_allocation_blocks_log2 as u32;

        let TransactionReadMissingDataFutureNvChipReadRequest {
            read_region_states_allocation_blocks_index_range,
            read_from_target,
            request_io_region: _,
            mut dst_allocation_block_buffers,
        } = completed_read_request;

        // If read from the Journal and disguising is enabled, undisguise first.
        if !read_from_target {
            if let Some(journal_data_copy_disguise) = transaction.journal_staging_copy_disguise.as_mut() {
                let journal_data_copy_undisguise = match journal_data_copy_disguise.1.as_ref() {
                    Some(journal_data_copy_undisguise) => journal_data_copy_undisguise,
                    None => journal_data_copy_disguise.1.insert(
                        journal::staging_copy_disguise::JournalStagingCopyUndisguise::new_from_disguise(
                            &journal_data_copy_disguise.0,
                        )?,
                    ),
                };
                let states = &transaction.auth_tree_data_blocks_update_states;
                let mut cur_allocation_block_target =
                    states.get_allocation_block_target(read_region_states_allocation_blocks_index_range.begin());
                let mut cur_allocation_block_journal_staging_copy = states
                    .get_allocation_block_journal_staging_copy(read_region_states_allocation_blocks_index_range.begin())
                    .ok_or_else(|| nvfs_err_internal!())?;
                // Don't (un)disguise if the Journal Data Staging Copy is not in fact a copy,
                // but refers to a freshly initialized target IO block to be
                // populated in place by the transaction.
                if cur_allocation_block_target != cur_allocation_block_journal_staging_copy {
                    let mut undisguise_processor = journal_data_copy_undisguise.instantiate_processor()?;
                    for dst_allocation_block_buf in dst_allocation_block_buffers.iter_mut() {
                        if let Some(dst_allocation_block_buf) = dst_allocation_block_buf {
                            undisguise_processor.undisguise_journal_staging_copy_allocation_block(
                                cur_allocation_block_journal_staging_copy,
                                cur_allocation_block_target,
                                dst_allocation_block_buf,
                            )?;
                        }
                        cur_allocation_block_target += layout::AllocBlockCount::from(1);
                        cur_allocation_block_journal_staging_copy += layout::AllocBlockCount::from(1);
                    }
                }
            }
        }

        // Now install the read Allocation Block buffers at their final location within
        // the states.
        let states = &mut transaction.auth_tree_data_blocks_update_states;
        let mut j = 0;
        for i in read_region_states_allocation_blocks_index_range.iter(auth_tree_data_block_allocation_blocks_log2) {
            let dst_allocation_block_buf = match dst_allocation_block_buffers[j].take() {
                Some(dst_allocation_block_buffer) => dst_allocation_block_buffer,
                None => {
                    j += 1;
                    continue;
                }
            };

            match &mut states[i].nv_sync_state {
                AllocationBlockUpdateNvSyncState::Unallocated(unallocated_state) => {
                    // Completely uninitialized Chip IO Blocks would have been filtered by
                    // Self::determine_next_read_range().
                    debug_assert!(
                        unallocated_state.target_state.is_initialized() || unallocated_state.copied_to_journal
                    );
                    // If the data is there already, we should not have attempted to
                    // reread it in the first place.
                    debug_assert!(unallocated_state.random_fillup.is_none());
                    unallocated_state.random_fillup = Some(dst_allocation_block_buf);
                }
                AllocationBlockUpdateNvSyncState::Allocated(allocated_state) => {
                    match allocated_state {
                        AllocationBlockUpdateNvSyncStateAllocated::Unmodified(unmodified_state) => {
                            // If the data is there already, we should not have attempted to
                            // reread it in the first place.
                            debug_assert!(unmodified_state.cached_encrypted_data.is_none());
                            unmodified_state.cached_encrypted_data =
                                Some(CachedEncryptedAllocationBlockData::new(dst_allocation_block_buf));
                        }
                        AllocationBlockUpdateNvSyncStateAllocated::Modified(modified_state) => {
                            match modified_state {
                                AllocationBlockUpdateNvSyncStateAllocatedModified::JournalDirty { .. } => {
                                    // If the data is there already, we should not have attempted to
                                    // reread it in the first place. In this case of modified data not yet
                                    // written out, we even can't.
                                    debug_assert!(false);
                                }
                                AllocationBlockUpdateNvSyncStateAllocatedModified::JournalClean {
                                    cached_encrypted_data,
                                } => {
                                    // If the data is there already, we should not have attempted to
                                    // reread it in the first place.
                                    debug_assert!(cached_encrypted_data.is_none());
                                    *cached_encrypted_data =
                                        Some(CachedEncryptedAllocationBlockData::new(dst_allocation_block_buf));
                                }
                            }
                        }
                    }
                }
            }

            j += 1;
        }
        Ok(())
    }
}

/// [`NvChipReadRequest`](chip::NvChipReadRequest) implementation used
/// internally by [`TransactionReadMissingDataFuture`].
struct TransactionReadMissingDataFutureNvChipReadRequest {
    read_region_states_allocation_blocks_index_range: AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    read_from_target: bool,
    request_io_region: ChunkedIoRegion,
    dst_allocation_block_buffers: FixedVec<Option<FixedVec<u8, 7>>, 0>,
}

impl chip::NvChipReadRequest for TransactionReadMissingDataFutureNvChipReadRequest {
    fn region(&self) -> &ChunkedIoRegion {
        &self.request_io_region
    }

    fn get_destination_buffer(
        &mut self,
        range: &ChunkedIoRegionChunkRange,
    ) -> Result<Option<&mut [u8]>, chip::NvChipIoError> {
        let (allocation_block_index, _) = range.chunk().decompose_to_hierarchic_indices([]);
        Ok(self.dst_allocation_block_buffers[allocation_block_index]
            .as_mut()
            .map(|b| &mut b[range.range_in_chunk().clone()]))
    }
}
