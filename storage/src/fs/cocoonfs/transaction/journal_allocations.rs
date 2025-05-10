// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`TransactionAllocateJournalStagingCopiesFuture`] and
//! [`TransactionAllocateJournalExtentsFuture`].

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

use super::{auth_tree_data_blocks_update_states::AuthTreeDataBlocksUpdateStatesIndexRange, Transaction};
use crate::{
    chip,
    fs::{
        cocoonfs::{
            alloc_bitmap::{self, ExtentsAllocationRequest},
            extents,
            fs::{
                CocoonFsAllocateBlocksFuture, CocoonFsAllocateExtentsFuture, CocoonFsSyncStateMemberRef,
                CocoonFsSyncStateReadFuture,
            },
            layout,
        },
        NvFsError,
    },
    nvfs_err_internal,
    utils_async::sync_types,
    utils_common::bitmanip::BitManip as _,
};
use core::{mem, pin, task};

pub struct TransactionAllocateJournalStagingCopiesFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    fut_state: TransactionAllocateJournalStagingCopiesFutureState<ST, C>,
}

enum TransactionAllocateJournalStagingCopiesFutureState<ST: sync_types::SyncTypes, C: chip::NvChip> {
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
        allocate_journal_staging_copy_blocks_fut: CocoonFsAllocateBlocksFuture<ST, C>,
        states_index_range: AuthTreeDataBlocksUpdateStatesIndexRange,
        total_needed_blocks: usize,
    },
    AssignAllocatedCopyBlocks {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<Transaction>>,
        states_index_range: AuthTreeDataBlocksUpdateStatesIndexRange,
        allocated_blocks: Vec<layout::PhysicalAllocBlockIndex>,
        total_needed_blocks: usize,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> TransactionAllocateJournalStagingCopiesFuture<ST, C> {
    pub fn new(transaction: Box<Transaction>, states_index_range: AuthTreeDataBlocksUpdateStatesIndexRange) -> Self {
        Self {
            fut_state: TransactionAllocateJournalStagingCopiesFutureState::Init {
                transaction: Some(transaction),
                states_index_range,
            },
        }
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsSyncStateReadFuture<ST, C>
    for TransactionAllocateJournalStagingCopiesFuture<ST, C>
{
    type AuxPollData<'a> = ();
    type Output = Result<(Box<Transaction>, Result<(), NvFsError>), NvFsError>;

    fn poll<'a>(
        self: pin::Pin<&mut Self>,
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, C>,
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

                    let mut total_needed_blocks: usize = 0;
                    let mut last_journal_block_without_staging_copy_allocation_blocks_begin = None;
                    for cur_states_index in states_index_range.iter() {
                        let s = &states[cur_states_index];
                        if s.get_journal_staging_copy_allocation_blocks_begin().is_some() {
                            debug_assert!(last_journal_block_without_staging_copy_allocation_blocks_begin
                                .map(|last_journal_block_allocation_blocks_begin| {
                                    last_journal_block_allocation_blocks_begin
                                        != s.get_target_allocation_blocks_begin()
                                            .align_down(journal_block_allocation_blocks_log2)
                                })
                                .unwrap_or(true));
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

                        total_needed_blocks += 1;
                        last_journal_block_without_staging_copy_allocation_blocks_begin =
                            Some(cur_journal_block_target_allocation_blocks_begin);
                    }

                    if total_needed_blocks <= transaction.abandoned_journal_staging_copy_blocks.len() {
                        // The request can get served exclusively from the transaction's previously
                        // abandoned Journal Blocks.
                        this.fut_state =
                            TransactionAllocateJournalStagingCopiesFutureState::AssignAllocatedCopyBlocks {
                                transaction: Some(transaction),
                                states_index_range: states_index_range.clone(),
                                allocated_blocks: Vec::new(),
                                total_needed_blocks,
                            };
                    } else if let CocoonFsSyncStateMemberRef::MutRef {
                        sync_state_write_guard: fs_instance_sync_state_write_guard,
                    } = fs_instance_sync_state
                    {
                        // Exclusive access to the fs_sync_state means there are no other pending
                        // transactions to coordinate with. Allocate directly.
                        let empty_pending_frees = alloc_bitmap::SparseAllocBitmap::new();
                        // Do not repurpose pending frees when allocating for the journal.
                        let pending_frees = [&empty_pending_frees];
                        let pending_frees = alloc_bitmap::SparseAllocBitmapUnion::new(&pending_frees);

                        let mut request_pending_allocs = alloc_bitmap::SparseAllocBitmap::new();

                        let mut allocated_blocks = Vec::new();
                        if let Err(e) = allocated_blocks.try_reserve_exact(total_needed_blocks) {
                            this.fut_state = TransactionAllocateJournalStagingCopiesFutureState::Done;
                            return task::Poll::Ready(Ok((transaction, Err(NvFsError::from(e)))));
                        }

                        while allocated_blocks.len()
                            < total_needed_blocks - transaction.abandoned_journal_staging_copy_blocks.len()
                        {
                            let pending_allocs = [
                                &transaction.allocs.pending_allocs,
                                &transaction.allocs.journal_allocs,
                                &request_pending_allocs,
                            ];
                            let pending_allocs = alloc_bitmap::SparseAllocBitmapUnion::new(&pending_allocs);

                            let allocated_block_allocation_blocks_begin =
                                match fs_instance_sync_state_write_guard.alloc_bitmap.find_free_block(
                                    journal_block_allocation_blocks_log2,
                                    None,
                                    &pending_allocs,
                                    &pending_frees,
                                    fs_instance_sync_state_write_guard.image_size,
                                ) {
                                    Some(allocated_block_allocations_begin) => allocated_block_allocations_begin,
                                    None => {
                                        this.fut_state = TransactionAllocateJournalStagingCopiesFutureState::Done;
                                        return task::Poll::Ready(Ok((transaction, Err(NvFsError::NoSpace))));
                                    }
                                };

                            if let Err(e) = request_pending_allocs.add_block(
                                allocated_block_allocation_blocks_begin,
                                journal_block_allocation_blocks_log2,
                            ) {
                                this.fut_state = TransactionAllocateJournalStagingCopiesFutureState::Done;
                                return task::Poll::Ready(Ok((transaction, Err(e))));
                            }

                            allocated_blocks.push(allocated_block_allocation_blocks_begin);
                        }

                        if let Err(e) = transaction
                            .allocs
                            .journal_allocs
                            .add_blocks(allocated_blocks.iter().copied(), journal_block_allocation_blocks_log2)
                        {
                            this.fut_state = TransactionAllocateJournalStagingCopiesFutureState::Done;
                            return task::Poll::Ready(Ok((transaction, Err(e))));
                        }

                        this.fut_state =
                            TransactionAllocateJournalStagingCopiesFutureState::AssignAllocatedCopyBlocks {
                                transaction: Some(transaction),
                                states_index_range: states_index_range.clone(),
                                allocated_blocks,
                                total_needed_blocks,
                            };
                    } else {
                        let allocate_journal_staging_copy_blocks_fut = match CocoonFsAllocateBlocksFuture::new(
                            &fs_instance_sync_state.get_fs_ref(),
                            transaction,
                            journal_block_allocation_blocks_log2,
                            total_needed_blocks,
                            true,
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
                            total_needed_blocks,
                        };
                    }
                }
                TransactionAllocateJournalStagingCopiesFutureState::AllocateBlocksSync {
                    allocate_journal_staging_copy_blocks_fut,
                    states_index_range,
                    total_needed_blocks,
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
                        total_needed_blocks: *total_needed_blocks,
                    };
                }
                TransactionAllocateJournalStagingCopiesFutureState::AssignAllocatedCopyBlocks {
                    transaction,
                    states_index_range,
                    allocated_blocks,
                    total_needed_blocks,
                } => {
                    let mut transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => {
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    // Possibly complete the allocation request from the transaction's previously
                    // abandoned Journal Blocks.
                    if transaction.abandoned_journal_staging_copy_blocks.len()
                        < total_needed_blocks.saturating_sub(allocated_blocks.len())
                    {
                        // Release the unassigned blocks again. Note that these might still be
                        // registered in the CocoonFsPendingTransactionsSyncState, but would get
                        // transformed into abandoned blocks at next transaction commit then.
                        transaction
                            .allocs
                            .journal_allocs
                            .remove_blocks(allocated_blocks.iter().cloned(), journal_block_allocation_blocks_log2);
                        transaction.allocs.journal_allocs.reset_remove_rollback();
                        this.fut_state = TransactionAllocateJournalStagingCopiesFutureState::Done;
                        return task::Poll::Ready(Ok((transaction, Err(nvfs_err_internal!()))));
                    }

                    let mut next_unassigned_allocated_block_index = 0;
                    let states = &mut transaction.auth_tree_data_blocks_update_states;
                    for cur_states_index in states_index_range.iter() {
                        let s = &states[cur_states_index];
                        if s.get_journal_staging_copy_allocation_blocks_begin().is_some() {
                            continue;
                        }

                        let allocated_block = if next_unassigned_allocated_block_index < allocated_blocks.len() {
                            allocated_blocks[next_unassigned_allocated_block_index]
                        } else {
                            // Take the blocks from the back.
                            transaction.abandoned_journal_staging_copy_blocks[transaction
                                .abandoned_journal_staging_copy_blocks
                                .len()
                                - (next_unassigned_allocated_block_index - allocated_blocks.len())
                                - 1]
                        };

                        if let Err(e) = states.assign_journal_staging_copy_block(cur_states_index, allocated_block) {
                            if next_unassigned_allocated_block_index < allocated_blocks.len() {
                                // Release any remaining unassigned blocks. Note that these might still be
                                // registered in the CocoonFsPendingTransactionsSyncState, but would get
                                // transformed into abandoned blocks at transaction commit then.
                                transaction.allocs.journal_allocs.remove_blocks(
                                    allocated_blocks[next_unassigned_allocated_block_index..]
                                        .iter()
                                        .cloned(),
                                    journal_block_allocation_blocks_log2,
                                );
                                transaction.allocs.journal_allocs.reset_remove_rollback();
                            } else {
                                // Consume what's been assigned so far.
                                transaction.abandoned_journal_staging_copy_blocks.truncate(
                                    transaction.abandoned_journal_staging_copy_blocks.len()
                                        - (next_unassigned_allocated_block_index - allocated_blocks.len()),
                                );
                            }
                            this.fut_state = TransactionAllocateJournalStagingCopiesFutureState::Done;
                            return task::Poll::Ready(Ok((transaction, Err(e))));
                        }

                        next_unassigned_allocated_block_index += 1;
                    }

                    debug_assert_eq!(next_unassigned_allocated_block_index, *total_needed_blocks);
                    if *total_needed_blocks > allocated_blocks.len() {
                        // Pop off the consumed blocks.
                        transaction.abandoned_journal_staging_copy_blocks.truncate(
                            transaction.abandoned_journal_staging_copy_blocks.len()
                                - (*total_needed_blocks - allocated_blocks.len()),
                        );
                    }

                    this.fut_state = TransactionAllocateJournalStagingCopiesFutureState::Done;
                    return task::Poll::Ready(Ok((transaction, Ok(()))));
                }
                TransactionAllocateJournalStagingCopiesFutureState::Done => unreachable!(),
            }
        }
    }
}

pub struct TransactionAllocateJournalExtentsFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    fut_state: TransactionAllocateJournalExtentsFutureState<ST, C>,
}

enum TransactionAllocateJournalExtentsFutureState<ST: sync_types::SyncTypes, C: chip::NvChip> {
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
        allocate_fut: CocoonFsAllocateExtentsFuture<ST, C>,
        result_extents: extents::PhysicalExtents,
        transaction_abandoned_journal_staging_copy_blocks_truncated_len: usize,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> TransactionAllocateJournalExtentsFuture<ST, C> {
    pub fn new(transaction: Box<Transaction>, allocation_request: ExtentsAllocationRequest) -> Self {
        Self {
            fut_state: TransactionAllocateJournalExtentsFutureState::Init {
                transaction: Some(transaction),
                allocation_request,
            },
        }
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsSyncStateReadFuture<ST, C>
    for TransactionAllocateJournalExtentsFuture<ST, C>
{
    type Output = Result<(Box<Transaction>, Result<extents::PhysicalExtents, NvFsError>), NvFsError>;
    type AuxPollData<'a> = ();

    fn poll<'a>(
        self: pin::Pin<&mut Self>,
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, C>,
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

                    let fs_instance = fs_instance_sync_state.get_fs_ref();
                    let image_layout = &fs_instance.fs_config.image_layout;
                    let io_block_allocation_blocks_log2 = image_layout.io_block_allocation_blocks_log2 as u32;
                    let auth_tree_data_block_allocation_blocks_log2 =
                        image_layout.auth_tree_data_block_allocation_blocks_log2 as u32;
                    let journal_block_allocation_blocks_log2 =
                        io_block_allocation_blocks_log2.max(auth_tree_data_block_allocation_blocks_log2);
                    let journal_block_allocation_blocks =
                        layout::AllocBlockCount::from(1u64 << journal_block_allocation_blocks_log2);

                    let (first_extent_min_allocation_blocks, tail_extent_min_allocation_blocks) =
                        allocation_request.get_layout().min_extents_allocation_blocks();

                    let mut result_extents = extents::PhysicalExtents::new();
                    let mut transaction_abandoned_journal_staging_copy_blocks_truncated_len =
                        transaction.abandoned_journal_staging_copy_blocks.len();
                    if first_extent_min_allocation_blocks.max(tail_extent_min_allocation_blocks)
                        <= journal_block_allocation_blocks
                    {
                        debug_assert!(
                            allocation_request.get_layout().extent_alignment_allocation_blocks_log2 as u32
                                <= journal_block_allocation_blocks_log2
                        );
                        transaction.abandoned_journal_staging_copy_blocks.sort();
                        while !transaction.abandoned_journal_staging_copy_blocks.is_empty()
                            && allocation_request.total_effective_payload_len != 0
                        {
                            let max_extent_allocation_blocks = allocation_request
                                .get_layout()
                                .extent_payload_len_to_allocation_blocks(
                                    allocation_request.total_effective_payload_len,
                                    result_extents.is_empty(),
                                )
                                .0;
                            if max_extent_allocation_blocks < journal_block_allocation_blocks {
                                break;
                            }
                            let mut j = transaction_abandoned_journal_staging_copy_blocks_truncated_len - 1;
                            let mut last_journal_block_allocation_blocks_begin =
                                transaction.abandoned_journal_staging_copy_blocks[j];
                            while j > 0
                                && ((transaction_abandoned_journal_staging_copy_blocks_truncated_len - j) as u64)
                                    < u64::from(max_extent_allocation_blocks) >> journal_block_allocation_blocks_log2
                            {
                                let cur_journal_block_target_allocation_blocks_begin =
                                    transaction.abandoned_journal_staging_copy_blocks[j - 1];
                                if last_journal_block_allocation_blocks_begin
                                    - cur_journal_block_target_allocation_blocks_begin
                                    != journal_block_allocation_blocks
                                {
                                    break;
                                }
                                last_journal_block_allocation_blocks_begin =
                                    cur_journal_block_target_allocation_blocks_begin;
                                j -= 1;
                            }

                            let extent_allocation_blocks = layout::AllocBlockCount::from(
                                ((transaction_abandoned_journal_staging_copy_blocks_truncated_len - j) as u64)
                                    << journal_block_allocation_blocks_log2,
                            );
                            allocation_request.total_effective_payload_len =
                                allocation_request.total_effective_payload_len.saturating_sub(
                                    allocation_request.get_layout().extent_effective_payload_len(
                                        extent_allocation_blocks,
                                        result_extents.is_empty(),
                                    ),
                                );
                            if let Err(e) = result_extents.push_extent(
                                &layout::PhysicalAllocBlockRange::from((
                                    transaction.abandoned_journal_staging_copy_blocks[j],
                                    extent_allocation_blocks,
                                )),
                                true,
                            ) {
                                this.fut_state = TransactionAllocateJournalExtentsFutureState::Done;
                                return task::Poll::Ready(Ok((transaction, Err(e))));
                            }
                            transaction_abandoned_journal_staging_copy_blocks_truncated_len = j;
                        }

                        if allocation_request.total_effective_payload_len == 0 {
                            transaction
                                .abandoned_journal_staging_copy_blocks
                                .truncate(transaction_abandoned_journal_staging_copy_blocks_truncated_len);
                            this.fut_state = TransactionAllocateJournalExtentsFutureState::Done;
                            return task::Poll::Ready(Ok((transaction, Ok(result_extents))));
                        } else if !result_extents.is_empty() {
                            // If we've found something, the extents headers will be stored there Update
                            // the request layout for allocating the remainder.
                            let mut updated_request_layout = allocation_request.get_layout().clone();
                            updated_request_layout.extents_hdr_len = 0;
                            *allocation_request = ExtentsAllocationRequest::new(
                                allocation_request.total_effective_payload_len,
                                &updated_request_layout,
                            )
                        }
                    }

                    drop(fs_instance);
                    if let CocoonFsSyncStateMemberRef::MutRef {
                        sync_state_write_guard: fs_instance_sync_state_write_guard,
                    } = fs_instance_sync_state
                    {
                        // Exclusive access to the fs_sync_state means there are no other pending
                        // transactions to coordinate with. Allocate directly.
                        let empty_pending_frees = alloc_bitmap::SparseAllocBitmap::new();
                        // Do not repurpose pending frees when allocating for the journal.
                        let pending_frees = [&empty_pending_frees];
                        let pending_frees = alloc_bitmap::SparseAllocBitmapUnion::new(&pending_frees);

                        let pending_allocs = [&transaction.allocs.pending_allocs, &transaction.allocs.journal_allocs];
                        let pending_allocs = alloc_bitmap::SparseAllocBitmapUnion::new(&pending_allocs);

                        let allocated_extents = match fs_instance_sync_state_write_guard.alloc_bitmap.find_free_extents(
                            allocation_request,
                            &pending_allocs,
                            &pending_frees,
                            fs_instance_sync_state_write_guard.image_size,
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

                        if result_extents.is_empty() {
                            result_extents = allocated_extents;
                        } else if let Err(e) = result_extents.append_extents(&allocated_extents, false) {
                            transaction
                                .allocs
                                .journal_allocs
                                .remove_extents(allocated_extents.iter());
                            transaction.allocs.journal_allocs.reset_remove_rollback();
                            this.fut_state = TransactionAllocateJournalExtentsFutureState::Done;
                            return task::Poll::Ready(Ok((transaction, Err(e))));
                        }

                        transaction
                            .abandoned_journal_staging_copy_blocks
                            .truncate(transaction_abandoned_journal_staging_copy_blocks_truncated_len);

                        this.fut_state = TransactionAllocateJournalExtentsFutureState::Done;
                        return task::Poll::Ready(Ok((transaction, Ok(result_extents))));
                    } else {
                        let fs_instance = fs_instance_sync_state.get_fs_ref();
                        let allocate_fut = match CocoonFsAllocateExtentsFuture::new(
                            &fs_instance,
                            transaction,
                            allocation_request.clone(),
                            true,
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
                        this.fut_state = TransactionAllocateJournalExtentsFutureState::AllocateExtentsSync {
                            allocate_fut,
                            result_extents,
                            transaction_abandoned_journal_staging_copy_blocks_truncated_len,
                        };
                    }
                }
                TransactionAllocateJournalExtentsFutureState::AllocateExtentsSync {
                    allocate_fut,
                    result_extents,
                    transaction_abandoned_journal_staging_copy_blocks_truncated_len,
                } => {
                    let (mut transaction, allocated_extents) = match CocoonFsSyncStateReadFuture::poll(
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

                    let mut result_extents = mem::replace(result_extents, extents::PhysicalExtents::new());
                    if result_extents.is_empty() {
                        result_extents = allocated_extents;
                    } else if let Err(e) = result_extents.append_extents(&allocated_extents, false) {
                        // Release the allocated extents again. Note that these are still registered
                        // in the CocoonFsPendingTransactionsSyncState, but would get transformed
                        // into abandoned extents at next transaction commit.
                        transaction
                            .allocs
                            .journal_allocs
                            .remove_extents(allocated_extents.iter());
                        transaction.allocs.journal_allocs.reset_remove_rollback();
                        this.fut_state = TransactionAllocateJournalExtentsFutureState::Done;
                        return task::Poll::Ready(Ok((transaction, Err(e))));
                    }

                    transaction
                        .abandoned_journal_staging_copy_blocks
                        .truncate(*transaction_abandoned_journal_staging_copy_blocks_truncated_len);

                    this.fut_state = TransactionAllocateJournalExtentsFutureState::Done;
                    return task::Poll::Ready(Ok((transaction, Ok(result_extents))));
                }
                TransactionAllocateJournalExtentsFutureState::Done => unreachable!(),
            }
        }
    }
}
