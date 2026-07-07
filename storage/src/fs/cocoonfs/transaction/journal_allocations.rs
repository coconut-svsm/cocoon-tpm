// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`TransactionAllocateJournalStagingCopiesFuture`] and
//! [`TransactionAllocateJournalExtentsFuture`].

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

use super::{
    Transaction, TransactionAllocationConstraints,
    auth_tree_data_blocks_update_states::AuthTreeDataBlocksUpdateStatesIndexRange,
};
use crate::{
    blkdev,
    fs::{
        NvFsError,
        cocoonfs::{
            alloc_bitmap::{self, ExtentsAllocationRequest},
            extents,
            fs::{
                AllocateBlocksFuture, AllocateExtentsFuture, CocoonFsSyncStateMemberRef, CocoonFsSyncStateReadFuture,
            },
            layout,
        },
    },
    nvfs_err_internal,
    utils_async::sync_types,
    utils_common::bitmanip::BitManip as _,
};
use core::{pin, task};

#[cfg(doc)]
use super::auth_tree_data_blocks_update_states::AuthTreeDataBlockUpdateState;

/// Allocate and assign [journal staging copy
/// blocks](AuthTreeDataBlockUpdateState::get_journal_staging_copy_allocation_blocks_begin) for a
/// [`Transaction`]'s [`AuthTreeDataBlockUpdateState`]s.
pub struct TransactionAllocateJournalStagingCopiesFuture<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev> {
    fut_state: TransactionAllocateJournalStagingCopiesFutureState<ST, B>,
}

/// [`TransactionAllocateJournalStagingCopiesFuture`] state-machine state.
enum TransactionAllocateJournalStagingCopiesFutureState<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev> {
    Init {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<Transaction>>,
        states_index_range: AuthTreeDataBlocksUpdateStatesIndexRange,
    },
    /// Allocate Journal Blocks with non-exclusive access to the
    /// CocoonFsSyncState, i.e. coordindate with other pending transactions,
    /// if any.
    AllocateBlocksSync {
        allocate_journal_staging_copy_blocks_fut: AllocateBlocksFuture<ST, B>,
        states_index_range: AuthTreeDataBlocksUpdateStatesIndexRange,
    },
    AssignAllocatedCopyBlocks {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<Transaction>>,
        states_index_range: AuthTreeDataBlocksUpdateStatesIndexRange,
        allocated_blocks: Vec<layout::PhysicalAllocBlockIndex>,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev> TransactionAllocateJournalStagingCopiesFuture<ST, B> {
    /// Instantiate a [`TransactionAllocateJournalStagingCopiesFuture`].
    ///
    /// The [`TransactionAllocateJournalStagingCopiesFuture`] assumes ownership
    /// of the `transaction` for the duration of the operation, it will
    /// eventually get returned back from [`poll()`](Self::poll) upon
    /// completion.
    ///
    /// # Arguments:
    ///
    /// * `transaction` - The [`Transaction`] to allocate journal staging copy
    ///   blocks for.
    /// * `states_index_range` - The [Authentication Tree Data Block level entry
    ///   index range](AuthTreeDataBlocksUpdateStatesIndexRange) in
    ///   [`Transaction::auth_tree_data_blocks_update_states`] to allocate
    ///   journal staging copy blocks for.
    pub fn new(transaction: Box<Transaction>, states_index_range: AuthTreeDataBlocksUpdateStatesIndexRange) -> Self {
        Self {
            fut_state: TransactionAllocateJournalStagingCopiesFutureState::Init {
                transaction: Some(transaction),
                states_index_range,
            },
        }
    }
}

impl<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev> CocoonFsSyncStateReadFuture<ST, B>
    for TransactionAllocateJournalStagingCopiesFuture<ST, B>
{
    type AuxPollData<'a> = ();

    /// Output type of [`poll()`](Self::poll).
    ///
    /// A two-level [`Result`] is returned upon
    /// [future](CocoonFsSyncStateReadFuture) completion.
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering an internal error and the [`Transaction`] is lost.
    /// * `Ok((transaction, ...))` - Otherwise the outer level [`Result`] is set
    ///   to [`Ok`] and a pair of the input [`Transaction`], `transaction`,  and
    ///   the operation result will get returned within:
    ///     * `Ok((transaction, Err(e)))` - In case of an error, the error
    ///       reason `e` is returned in an [`Err`].
    ///     * `Ok((transaction, Ok(())))` -  Otherwise, `Ok(())` will get
    ///       returned for the operation result on success.
    type Output = Result<(Box<Transaction>, Result<(), NvFsError>), NvFsError>;

    fn poll<'a>(
        self: pin::Pin<&mut Self>,
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, B>,
        _aux_data: &mut Self::AuxPollData<'a>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        let fs_instance = fs_instance_sync_state.get_fs_ref();
        let image_layout = &fs_instance.fs_config.image_layout;
        let journal_block_allocation_blocks_log2 = image_layout
            .io_block_allocation_blocks_log2
            .max(image_layout.auth_tree_data_block_allocation_blocks_log2)
            as u32;
        drop(fs_instance);

        loop {
            match &mut this.fut_state {
                TransactionAllocateJournalStagingCopiesFutureState::Init {
                    transaction,
                    states_index_range,
                } => {
                    let mut transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => {
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };
                    let states = &mut transaction.auth_tree_data_blocks_update_states;

                    // Count the number of needed Journal Staging Copy blocks and try to enable
                    // in-place writes by making the journal staging copy equal to the target in the
                    // course. This is possible only if all Allocation Blocks from a containing IO
                    // block had been unitialized before the transaction -- otherwise partial writes
                    // could destroy any exisiting data. In case the Authentication Tree Data block
                    // size is larger than the IO block size, this requirement applies collectively
                    // to all of an Authentication Tree Data Block's IO blocks, because the
                    // implementation assings a contiguous journal staging copy area to the former,
                    // so it's always all or nothing. The larger of an Authentication Tree Data
                    // Block and an IO block is called a "Journal Block".
                    //
                    // However, there's a catch: if multiple concurrent transactions own different
                    // parts of the same containing uninitialized Journal Block, and happen to write
                    // out to those during non-exclusive pre-commit time, they would interfere with
                    // each other. So establish the rule that a transaction must only write in-place
                    // if it owns the full containing Journal Block allocation-wise. An exception is
                    // being made for the single pending transaction uniquely marked as
                    // is_primary_pending, which is the common case.
                    let fs_sync_state_alloc_bitmap = &fs_instance_sync_state.alloc_bitmap;
                    let empty_sparse_alloc_bitmap = alloc_bitmap::SparseAllocBitmapUnion::new(&[]);
                    let mut alloc_bitmap_journal_blocks_iter = fs_sync_state_alloc_bitmap
                        .iter_chunked_at_allocation_block(
                            &empty_sparse_alloc_bitmap,
                            &empty_sparse_alloc_bitmap,
                            layout::PhysicalAllocBlockIndex::from(0u64),
                            1u32 << journal_block_allocation_blocks_log2,
                        );
                    let mut pending_allocs_journal_blocks_iter = transaction
                        .allocs
                        .pending_allocs
                        .block_iter(journal_block_allocation_blocks_log2);
                    let mut next_journal_block_pending_alloc_bitmap = pending_allocs_journal_blocks_iter.next();

                    let mut needed_blocks: usize = 0;
                    let mut last_journal_block_without_staging_copy_allocation_blocks_begin = None;
                    for cur_states_index in states_index_range.iter() {
                        let s = &states[cur_states_index];
                        if s.get_journal_staging_copy_allocation_blocks_begin().is_some() {
                            debug_assert!(
                                last_journal_block_without_staging_copy_allocation_blocks_begin
                                    .map(|last_journal_block_allocation_blocks_begin| {
                                        last_journal_block_allocation_blocks_begin
                                            != s.get_target_allocation_blocks_begin()
                                                .align_down(journal_block_allocation_blocks_log2)
                                    })
                                    .unwrap_or(true)
                            );
                            last_journal_block_without_staging_copy_allocation_blocks_begin = None;
                            continue;
                        }

                        let cur_journal_block_target_allocation_blocks_begin = s
                            .get_target_allocation_blocks_begin()
                            .align_down(journal_block_allocation_blocks_log2);
                        if last_journal_block_without_staging_copy_allocation_blocks_begin
                            .map(|last_journal_block_allocation_blocks_begin| {
                                last_journal_block_allocation_blocks_begin
                                    == cur_journal_block_target_allocation_blocks_begin
                            })
                            .unwrap_or(false)
                        {
                            // The previous and the current state's target areas are contained
                            // in the same Journal Block sized block, they'll share the
                            // Journal Data Staging Block as well.
                            continue;
                        }

                        // See if the Journal Block can get written in-place.
                        alloc_bitmap_journal_blocks_iter.goto(cur_journal_block_target_allocation_blocks_begin);
                        let cur_journal_block_alloc_bitmap = alloc_bitmap_journal_blocks_iter.next().unwrap_or(0);
                        if let Some((next_journal_block_pending_alloc_bitmap_covered_allocation_blocks_begin, _)) =
                            next_journal_block_pending_alloc_bitmap.as_ref()
                        {
                            if *next_journal_block_pending_alloc_bitmap_covered_allocation_blocks_begin
                                < cur_journal_block_target_allocation_blocks_begin
                            {
                                pending_allocs_journal_blocks_iter
                                    .skip_to(cur_journal_block_target_allocation_blocks_begin);
                                next_journal_block_pending_alloc_bitmap = pending_allocs_journal_blocks_iter.next();
                            }
                        }
                        let cur_journal_block_all_uninitialized = cur_journal_block_alloc_bitmap == 0;
                        if cur_journal_block_all_uninitialized
                            && (transaction.is_primary_pending
                                || next_journal_block_pending_alloc_bitmap
                                    .as_ref()
                                    .map(
                                        |(
                                            next_journal_block_pending_alloc_bitmap_covered_allocation_blocks_begin,
                                            next_journal_block_pending_alloc_bitmap,
                                        )| {
                                            *next_journal_block_pending_alloc_bitmap_covered_allocation_blocks_begin
                                                == cur_journal_block_target_allocation_blocks_begin
                                                && *next_journal_block_pending_alloc_bitmap
                                                    == alloc_bitmap::BitmapWord::trailing_bits_mask(
                                                        1u32 << journal_block_allocation_blocks_log2,
                                                    )
                                        },
                                    )
                                    .unwrap_or(false))
                        {
                            if let Err(e) = states.assign_journal_staging_copy_block(
                                cur_states_index,
                                cur_journal_block_target_allocation_blocks_begin,
                            ) {
                                this.fut_state = TransactionAllocateJournalStagingCopiesFutureState::Done;
                                return task::Poll::Ready(Ok((transaction, Err(e))));
                            }
                            last_journal_block_without_staging_copy_allocation_blocks_begin = None;
                            continue;
                        }

                        needed_blocks += 1;
                        last_journal_block_without_staging_copy_allocation_blocks_begin =
                            Some(cur_journal_block_target_allocation_blocks_begin);
                    }

                    if let CocoonFsSyncStateMemberRef::MutRef {
                        sync_state_write_guard: fs_instance_sync_state_write_guard,
                    } = fs_instance_sync_state
                    {
                        // Exclusive access to the fs_sync_state means there are no other pending
                        // transactions to coordinate with. Allocate directly.
                        let pending_allocs = [&transaction.allocs.pending_allocs, &transaction.allocs.journal_allocs];
                        let pending_allocs = alloc_bitmap::SparseAllocBitmapUnion::new(&pending_allocs);
                        // Do not repurpose pending_frees when allocating for the journal.
                        let pending_frees = [&transaction.allocs.journal_frees];
                        let pending_frees = alloc_bitmap::SparseAllocBitmapUnion::new(&pending_frees);

                        let mut allocated_blocks = Vec::new();
                        if let Err(e) = allocated_blocks.try_reserve_exact(needed_blocks) {
                            this.fut_state = TransactionAllocateJournalStagingCopiesFutureState::Done;
                            return task::Poll::Ready(Ok((transaction, Err(NvFsError::from(e)))));
                        }

                        while allocated_blocks.len() < needed_blocks {
                            // Mutable access to the filesystem instance's sync state means that there
                            // will be no subsequent allocations for long-living entities with placement
                            // optimization enabled. So disabling placement optimization here is fine.
                            let allocated_block_allocation_blocks_begin =
                                match fs_instance_sync_state_write_guard.alloc_bitmap.find_free_block(
                                    journal_block_allocation_blocks_log2,
                                    &allocated_blocks,
                                    None,
                                    &pending_allocs,
                                    &pending_frees,
                                    fs_instance_sync_state_write_guard.image_size,
                                    allocated_blocks.last().copied(),
                                    false,
                                ) {
                                    Some(allocated_block_allocations_begin) => allocated_block_allocations_begin,
                                    None => {
                                        this.fut_state = TransactionAllocateJournalStagingCopiesFutureState::Done;
                                        return task::Poll::Ready(Ok((transaction, Err(NvFsError::NoSpace))));
                                    }
                                };
                            let allocated_blocks_insertion_pos =
                                match allocated_blocks.binary_search(&allocated_block_allocation_blocks_begin) {
                                    Ok(_) => {
                                        // The block has been allocated twice now?!
                                        this.fut_state = TransactionAllocateJournalStagingCopiesFutureState::Done;
                                        return task::Poll::Ready(Ok((transaction, Err(nvfs_err_internal!()))));
                                    }
                                    Err(allocated_blocks_insertion_pos) => allocated_blocks_insertion_pos,
                                };
                            allocated_blocks
                                .insert(allocated_blocks_insertion_pos, allocated_block_allocation_blocks_begin);
                        }

                        if let Err(e) = transaction
                            .allocs
                            .journal_allocs
                            .add_blocks(allocated_blocks.iter().copied(), journal_block_allocation_blocks_log2)
                        {
                            this.fut_state = TransactionAllocateJournalStagingCopiesFutureState::Done;
                            return task::Poll::Ready(Ok((transaction, Err(e))));
                        }
                        transaction
                            .allocs
                            .journal_frees
                            .remove_blocks(allocated_blocks.iter().copied(), journal_block_allocation_blocks_log2);

                        this.fut_state =
                            TransactionAllocateJournalStagingCopiesFutureState::AssignAllocatedCopyBlocks {
                                transaction: Some(transaction),
                                states_index_range: states_index_range.clone(),
                                allocated_blocks,
                            };
                    } else {
                        let allocate_journal_staging_copy_blocks_fut = match AllocateBlocksFuture::new(
                            &fs_instance_sync_state.get_fs_ref(),
                            transaction,
                            journal_block_allocation_blocks_log2,
                            needed_blocks,
                            TransactionAllocationConstraints::Journal,
                        ) {
                            Ok(allocate_journal_staging_copy_blocks_fut) => allocate_journal_staging_copy_blocks_fut,
                            Err((mut transaction, e)) => {
                                this.fut_state = TransactionAllocateJournalStagingCopiesFutureState::Done;
                                return task::Poll::Ready(match transaction.take() {
                                    Some(transaction) => Ok((transaction, Err(e))),
                                    None => Err(e),
                                });
                            }
                        };
                        this.fut_state = TransactionAllocateJournalStagingCopiesFutureState::AllocateBlocksSync {
                            allocate_journal_staging_copy_blocks_fut,
                            states_index_range: states_index_range.clone(),
                        };
                    }
                }
                TransactionAllocateJournalStagingCopiesFutureState::AllocateBlocksSync {
                    allocate_journal_staging_copy_blocks_fut,
                    states_index_range,
                } => {
                    let (transaction, allocated_blocks) = match CocoonFsSyncStateReadFuture::poll(
                        pin::Pin::new(allocate_journal_staging_copy_blocks_fut),
                        fs_instance_sync_state,
                        &mut (),
                        cx,
                    ) {
                        task::Poll::Ready(Ok((transaction, Ok(allocated_blocks)))) => (transaction, allocated_blocks),
                        task::Poll::Ready(Ok((transaction, Err(e)))) => {
                            this.fut_state = TransactionAllocateJournalStagingCopiesFutureState::Done;
                            return task::Poll::Ready(Ok((transaction, Err(e))));
                        }
                        task::Poll::Ready(Err(e)) => {
                            this.fut_state = TransactionAllocateJournalStagingCopiesFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    this.fut_state = TransactionAllocateJournalStagingCopiesFutureState::AssignAllocatedCopyBlocks {
                        transaction: Some(transaction),
                        states_index_range: states_index_range.clone(),
                        allocated_blocks,
                    };
                }
                TransactionAllocateJournalStagingCopiesFutureState::AssignAllocatedCopyBlocks {
                    transaction,
                    states_index_range,
                    allocated_blocks,
                } => {
                    let mut transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => {
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    let mut next_allocated_blocks_index = 0;
                    let states = &mut transaction.auth_tree_data_blocks_update_states;
                    for cur_states_index in states_index_range.iter() {
                        let s = &states[cur_states_index];
                        if s.get_journal_staging_copy_allocation_blocks_begin().is_some() {
                            continue;
                        }

                        // This fails on internal errors only.
                        if let Err(e) = states.assign_journal_staging_copy_block(
                            cur_states_index,
                            allocated_blocks[next_allocated_blocks_index],
                        ) {
                            // Release any remaining unassigned blocks, if possible.
                            if transaction
                                .allocs
                                .journal_frees
                                .add_blocks(
                                    allocated_blocks[next_allocated_blocks_index..].iter().cloned(),
                                    journal_block_allocation_blocks_log2,
                                )
                                .is_ok()
                            {
                                transaction.allocs.journal_allocs.remove_blocks(
                                    allocated_blocks[next_allocated_blocks_index..].iter().cloned(),
                                    journal_block_allocation_blocks_log2,
                                );
                                transaction.allocs.journal_allocs.reset_remove_rollback();
                            }
                            this.fut_state = TransactionAllocateJournalStagingCopiesFutureState::Done;
                            return task::Poll::Ready(Ok((transaction, Err(e))));
                        }

                        next_allocated_blocks_index += 1;
                    }

                    debug_assert_eq!(next_allocated_blocks_index, allocated_blocks.len());

                    this.fut_state = TransactionAllocateJournalStagingCopiesFutureState::Done;
                    return task::Poll::Ready(Ok((transaction, Ok(()))));
                }
                TransactionAllocateJournalStagingCopiesFutureState::Done => unreachable!(),
            }
        }
    }
}

/// Allocate extents for the journal.
///
/// Used for allocating the non-fixed tail of the journal log's chained
/// encrypted extents.
pub struct TransactionAllocateJournalExtentsFuture<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev> {
    fut_state: TransactionAllocateJournalExtentsFutureState<ST, B>,
}

/// [`TransactionAllocateJournalExtentsFuture`] state-machine state.
enum TransactionAllocateJournalExtentsFutureState<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev> {
    Init {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<Transaction>>,
        allocation_request: ExtentsAllocationRequest,
    },
    /// Allocate Journal Extents with non-exclusive access to the
    /// CocoonFsSyncState, i.e. coordindate with other pending transactions,
    /// if any.
    AllocateExtentsSync {
        allocate_fut: AllocateExtentsFuture<ST, B>,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev> TransactionAllocateJournalExtentsFuture<ST, B> {
    /// Instantiate a [`TransactionAllocateJournalExtentsFuture`].
    ///
    /// The [`TransactionAllocateJournalExtentsFuture`] assumes ownership
    /// of the `transaction` for the duration of the operation, it will
    /// eventually get returned back from [`poll()`](Self::poll) upon
    /// completion.
    ///
    ///
    /// # Arguments:
    ///
    /// * `transaction` - The [`Transaction`] to allocate journal extents for.
    /// * `allocation_request` - The extents allocation request to serve.
    pub fn new(transaction: Box<Transaction>, allocation_request: ExtentsAllocationRequest) -> Self {
        Self {
            fut_state: TransactionAllocateJournalExtentsFutureState::Init {
                transaction: Some(transaction),
                allocation_request,
            },
        }
    }
}

impl<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev> CocoonFsSyncStateReadFuture<ST, B>
    for TransactionAllocateJournalExtentsFuture<ST, B>
{
    /// Output type of [`poll()`](Self::poll).
    ///
    /// A two-level [`Result`] is returned upon
    /// [future](CocoonFsSyncStateReadFuture) completion.
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering an internal error and the [`Transaction`] is lost.
    /// * `Ok((transaction, ...))` - Otherwise the outer level [`Result`] is set
    ///   to [`Ok`] and a pair of the input [`Transaction`], `transaction`,  and
    ///   the operation result will get returned within:
    ///     * `Ok((transaction, Err(e)))` - In case of an error, the error
    ///       reason `e` is returned in an [`Err`].
    ///     * `Ok((transaction, Ok(extents)))` -  Otherwise, the allocated
    ///       `extents` wrapped in an `Ok` are returned for the operation result
    ///       on success.
    type Output = Result<(Box<Transaction>, Result<extents::PhysicalExtents, NvFsError>), NvFsError>;

    type AuxPollData<'a> = ();

    fn poll<'a>(
        self: pin::Pin<&mut Self>,
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, B>,
        _aux_data: &mut Self::AuxPollData<'a>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                TransactionAllocateJournalExtentsFutureState::Init {
                    transaction,
                    allocation_request,
                } => {
                    let mut transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => {
                            this.fut_state = TransactionAllocateJournalExtentsFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    if allocation_request.total_effective_payload_len == 0 {
                        this.fut_state = TransactionAllocateJournalExtentsFutureState::Done;
                        return task::Poll::Ready(Ok((transaction, Ok(extents::PhysicalExtents::new()))));
                    }

                    if let CocoonFsSyncStateMemberRef::MutRef {
                        sync_state_write_guard: fs_instance_sync_state_write_guard,
                    } = fs_instance_sync_state
                    {
                        // Exclusive access to the fs_sync_state means there are no other pending
                        // transactions to coordinate with. Allocate directly.
                        // Do not repurpose pending_frees when allocating for the journal.
                        let pending_frees = [&transaction.allocs.journal_frees];
                        let pending_frees = alloc_bitmap::SparseAllocBitmapUnion::new(&pending_frees);

                        let pending_allocs = [&transaction.allocs.pending_allocs, &transaction.allocs.journal_allocs];
                        let pending_allocs = alloc_bitmap::SparseAllocBitmapUnion::new(&pending_allocs);

                        // Mutable access to the filesystem instance's sync state means that there
                        // will be no subsequent allocations for long-lived entities with placement
                        // optimization enabled. So disabling placement optimization here is fine.
                        let allocated_extents = match fs_instance_sync_state_write_guard.alloc_bitmap.find_free_extents(
                            allocation_request,
                            &pending_allocs,
                            &pending_frees,
                            fs_instance_sync_state_write_guard.image_size,
                            false,
                        ) {
                            Ok(Some((allocated_extents, _))) => allocated_extents,
                            Ok(None) => {
                                this.fut_state = TransactionAllocateJournalExtentsFutureState::Done;
                                return task::Poll::Ready(Ok((transaction, Err(NvFsError::NoSpace))));
                            }
                            Err(e) => {
                                this.fut_state = TransactionAllocateJournalExtentsFutureState::Done;
                                return task::Poll::Ready(Ok((transaction, Err(e))));
                            }
                        };

                        if let Err(e) = transaction.allocs.journal_allocs.add_extents(allocated_extents.iter()) {
                            this.fut_state = TransactionAllocateJournalExtentsFutureState::Done;
                            return task::Poll::Ready(Ok((transaction, Err(e))));
                        }
                        transaction
                            .allocs
                            .journal_frees
                            .remove_extents(allocated_extents.iter());

                        this.fut_state = TransactionAllocateJournalExtentsFutureState::Done;
                        return task::Poll::Ready(Ok((transaction, Ok(allocated_extents))));
                    } else {
                        let fs_instance = fs_instance_sync_state.get_fs_ref();
                        let allocate_fut = match AllocateExtentsFuture::new(
                            &fs_instance,
                            transaction,
                            allocation_request.clone(),
                            TransactionAllocationConstraints::Journal,
                        ) {
                            Ok(allocate_journal_extents_fut) => allocate_journal_extents_fut,
                            Err((transaction, e)) => {
                                this.fut_state = TransactionAllocateJournalExtentsFutureState::Done;
                                return task::Poll::Ready(match transaction {
                                    Some(transaction) => Ok((transaction, Err(e))),
                                    None => Err(e),
                                });
                            }
                        };
                        this.fut_state =
                            TransactionAllocateJournalExtentsFutureState::AllocateExtentsSync { allocate_fut };
                    }
                }
                TransactionAllocateJournalExtentsFutureState::AllocateExtentsSync { allocate_fut } => {
                    let (transaction, allocated_extents) = match CocoonFsSyncStateReadFuture::poll(
                        pin::Pin::new(allocate_fut),
                        fs_instance_sync_state,
                        &mut (),
                        cx,
                    ) {
                        task::Poll::Ready(Ok((transaction, Ok(allocated_extents)))) => {
                            (transaction, allocated_extents.0)
                        }
                        task::Poll::Ready(Ok((transaction, Err(e)))) => {
                            this.fut_state = TransactionAllocateJournalExtentsFutureState::Done;
                            return task::Poll::Ready(Ok((transaction, Err(e))));
                        }
                        task::Poll::Ready(Err(e)) => {
                            this.fut_state = TransactionAllocateJournalExtentsFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    this.fut_state = TransactionAllocateJournalExtentsFutureState::Done;
                    return task::Poll::Ready(Ok((transaction, Ok(allocated_extents))));
                }
                TransactionAllocateJournalExtentsFutureState::Done => unreachable!(),
            }
        }
    }
}
