// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`TransactionCleanupPreCommitCancelledFuture`] and
//! [`TransactionAbortJournalFuture`].

extern crate alloc;
use alloc::boxed::Box;

use super::{Transaction, auth_tree_data_blocks_update_states::AuthTreeDataBlocksUpdateStatesIndex};
use crate::{
    blkdev::{self, NvBlkDevIoError},
    fs::{
        NvFsError,
        cocoonfs::{
            alloc_bitmap,
            fs::CocoonFsSyncStateMemberMutRef,
            journal,
            layout::{self, BlockCount as _},
        },
    },
    nvfs_err_internal,
    utils_async::sync_types,
    utils_common::bitmanip::BitManip as _,
};
use core::{pin, task};

#[cfg(doc)]
use super::auth_tree_data_blocks_update_states::AuthTreeDataBlockUpdateState;

/// [Trim](blkdev::NvBlkDev::trim) any [IO
/// Block](layout::ImageLayout::io_block_allocation_blocks_log2) occupied by the
/// journal.
pub(super) struct TransactionTrimJournalFuture<B: blkdev::NvBlkDev> {
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
    // reference on Self.
    transaction: Option<Box<Transaction>>,
    retain_in_place_writes: bool,
    fut_state: TransactionTrimJournalFutureState<B>,
}

/// [`TransactionTrimJournalFuture`] state-machine state.
enum TransactionTrimJournalFutureState<B: blkdev::NvBlkDev> {
    Init,
    WriteBarrier {
        write_barrier_fut: B::WriteBarrierFuture,
    },
    TrimJournalStagingCopyRegionPrepare {
        next_update_states_index: AuthTreeDataBlocksUpdateStatesIndex,
    },
    TrimJournalStagingCopyRegion {
        region_trim_fut: B::TrimFuture,
        next_update_states_index: AuthTreeDataBlocksUpdateStatesIndex,
    },
    TrimJournalLogTailExtentsPrepare {
        next_extent_index: usize,
    },
    TrimJournalLogTailExtents {
        region_trim_fut: B::TrimFuture,
        next_extent_index: usize,
    },
    TrimAbandonedJournalStagingCopyPrepare {
        next_abandandoned_journal_staging_copy_block_index: usize,
    },
    TrimAbandonedJournalStagingCopy {
        region_trim_fut: B::TrimFuture,
        next_abandandoned_journal_staging_copy_block_index: usize,
    },
    TrimPendingTransactionsSyncStateAllocsPrepare {
        next_io_block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
    },
    TrimPendingTransactionsSyncStateAllocs {
        region_trim_fut: B::TrimFuture,
        next_io_block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
    },
    Done,
}

impl<B: blkdev::NvBlkDev> TransactionTrimJournalFuture<B> {
    /// Instantiate a [`TransactionTrimJournalFuture`].
    ///
    /// The [`TransactionTrimJournalFuture`] assumes ownership of the
    /// `transaction` for the duration of the operation. It will eventually
    /// get returned from [`poll()`](Self::poll) upon successful completion.
    ///
    /// # Arguments:
    ///
    /// * `transaction` - The [`Transaction`] the journal had been written for.
    /// * `retain_in_place_writes` - Whether to retain "in-place" writes that
    ///   didn't go through the [journal staging
    ///   copies](AuthTreeDataBlockUpdateState::get_journal_staging_copy_allocation_blocks_begin).
    ///   Should be set to `true` upon a successful [`Transaction`] commit,
    ///   `false` when cleaning up after a failed [`Transaction`] commit.
    pub fn new(transaction: Box<Transaction>, retain_in_place_writes: bool) -> Self {
        Self {
            transaction: Some(transaction),
            retain_in_place_writes,
            fut_state: TransactionTrimJournalFutureState::Init,
        }
    }

    /// Poll the [`TransactionTrimJournalFuture`] to completion.
    ///
    /// On successful completion, the input [`Transaction`] is returned back. On
    /// error, the [`Transaction`] is consumed and an error reason is
    /// returned.
    ///
    /// # Arguments:
    ///
    /// * `fs_instance_sync_state` - Exclusive reference to
    ///   [`CocoonFs::sync_state`](crate::fs::cocoonfs::fs::CocoonFs::sync_state).
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    pub fn poll<ST: sync_types::SyncTypes>(
        self: pin::Pin<&mut Self>,
        fs_instance_sync_state: CocoonFsSyncStateMemberMutRef<'_, ST, B>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<Box<Transaction>, NvFsError>> {
        let this = pin::Pin::into_inner(self);

        let fs_instance = fs_instance_sync_state.get_fs_ref();
        let image_layout = &fs_instance.fs_config.image_layout;

        let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
        let auth_tree_data_block_allocation_blocks_log2 =
            image_layout.auth_tree_data_block_allocation_blocks_log2 as u32;
        let io_block_allocation_blocks_log2 = image_layout.io_block_allocation_blocks_log2 as u32;
        // A Journal Block is the larger of an IO Block and an Authentication Tree Data
        // Block.
        let journal_block_allocation_blocks_log2 =
            auth_tree_data_block_allocation_blocks_log2.max(io_block_allocation_blocks_log2);

        let blkdev_io_block_size_128b_log2 = fs_instance.blkdev.io_block_size_128b_log2();
        let preferred_blkdev_io_blocks_bulk_log2 = fs_instance.blkdev.preferred_io_blocks_bulk_log2();

        // Trimming is done on a best-effort basis and any failure in doing so is
        // non-fatal.
        if blkdev_io_block_size_128b_log2 > io_block_allocation_blocks_log2 + allocation_block_size_128b_log2 {
            this.fut_state = TransactionTrimJournalFutureState::Done;
            return task::Poll::Ready(this.transaction.take().ok_or_else(|| nvfs_err_internal!()));
        }
        let blkdev_io_block_allocation_blocks_log2 =
            blkdev_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);
        let allocation_block_blkdev_io_blocks_log2 =
            allocation_block_size_128b_log2.saturating_sub(blkdev_io_block_size_128b_log2);
        debug_assert!(blkdev_io_block_allocation_blocks_log2 == 0 || allocation_block_blkdev_io_blocks_log2 == 0);

        let preferred_bulk_allocation_blocks_log2 = (preferred_blkdev_io_blocks_bulk_log2
            + blkdev_io_block_allocation_blocks_log2)
            .saturating_sub(allocation_block_blkdev_io_blocks_log2);

        loop {
            match &mut this.fut_state {
                TransactionTrimJournalFutureState::Init => {
                    if !fs_instance.fs_config.enable_trimming {
                        this.fut_state = TransactionTrimJournalFutureState::Done;
                        return task::Poll::Ready(this.transaction.take().ok_or_else(|| nvfs_err_internal!()));
                    }

                    let transaction = match this.transaction.as_mut() {
                        Some(transaction) => transaction,
                        None => {
                            this.fut_state = TransactionTrimJournalFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    // Sort the abandoned Journal Staging Copy blocks to enable larger trim
                    // requests.
                    transaction.abandoned_journal_staging_copy_blocks.sort();

                    // Remove from the grabbed CocoonFsPendingTransactionsSyncState's tracked
                    // allocations anything included in the transaction's
                    // journal allocations in order to avoid redundant trims.
                    transaction
                        .accumulated_fs_instance_pending_transactions_sync_state
                        .pending_allocs
                        .subtract(&transaction.allocs.journal_allocs);

                    // Remove from the grabbed CocoonFsPendingTransactionsSyncState's tracked
                    // allocations anything included in the transaction's "real" allocations in
                    // order to not trim data written in-place through that, and also, to avoid
                    // redundant trims.
                    transaction
                        .accumulated_fs_instance_pending_transactions_sync_state
                        .pending_allocs
                        .subtract(&transaction.allocs.pending_allocs);

                    // Now figure whether any trim might actually be needed and issue a write
                    // barrier before the subsequent trims if so.
                    if transaction
                        .auth_tree_data_blocks_update_states
                        .iter_auth_tree_data_blocks(None)
                        .all(|update_state| {
                            update_state
                                .get_journal_staging_copy_allocation_blocks_begin()
                                .is_none()
                        })
                        && transaction.journal_log_tail_extents.is_empty()
                        && transaction.abandoned_journal_staging_copy_blocks.is_empty()
                        && transaction
                            .accumulated_fs_instance_pending_transactions_sync_state
                            .pending_allocs
                            .is_empty()
                    {
                        this.fut_state = TransactionTrimJournalFutureState::Done;
                        return task::Poll::Ready(this.transaction.take().ok_or_else(|| nvfs_err_internal!()));
                    }

                    let write_barrier_fut = match fs_instance.blkdev.write_barrier() {
                        Ok(write_barrier_fut) => write_barrier_fut,
                        Err(_) => {
                            // Can't trim without a write barrier, but failure to trim is considered
                            // non-fatal. Simply return.
                            this.fut_state = TransactionTrimJournalFutureState::Done;
                            return task::Poll::Ready(this.transaction.take().ok_or_else(|| nvfs_err_internal!()));
                        }
                    };

                    this.fut_state = TransactionTrimJournalFutureState::WriteBarrier { write_barrier_fut };
                }
                TransactionTrimJournalFutureState::WriteBarrier { write_barrier_fut } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(write_barrier_fut), &fs_instance.blkdev, cx) {
                        task::Poll::Pending => return task::Poll::Pending,
                        task::Poll::Ready(Ok(_)) => {
                            this.fut_state = TransactionTrimJournalFutureState::TrimJournalStagingCopyRegionPrepare {
                                next_update_states_index: AuthTreeDataBlocksUpdateStatesIndex::from(0usize),
                            };
                        }
                        task::Poll::Ready(Err(_)) => {
                            // Can't trim without a write barrier, but failure to trim is considered
                            // non-fatal, so simply return.
                            this.fut_state = TransactionTrimJournalFutureState::Done;
                            return task::Poll::Ready(this.transaction.take().ok_or_else(|| nvfs_err_internal!()));
                        }
                    }
                }
                TransactionTrimJournalFutureState::TrimJournalStagingCopyRegionPrepare {
                    next_update_states_index,
                } => {
                    let transaction = match this.transaction.as_ref() {
                        Some(transaction) => transaction,
                        None => {
                            this.fut_state = TransactionTrimJournalFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    let update_states = &transaction.auth_tree_data_blocks_update_states;
                    let first_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin = loop {
                        if usize::from(*next_update_states_index) == update_states.len() {
                            break None;
                        }

                        let cur_update_state = &update_states[*next_update_states_index];
                        *next_update_states_index = next_update_states_index.step();

                        if let Some(cur_auth_data_block_journal_staging_copy_allocation_blocks_begin) =
                            cur_update_state.get_journal_staging_copy_allocation_blocks_begin()
                        {
                            if this.retain_in_place_writes
                                && cur_auth_data_block_journal_staging_copy_allocation_blocks_begin
                                    == cur_update_state.get_target_allocation_blocks_begin()
                            {
                                continue;
                            }
                            break Some(cur_auth_data_block_journal_staging_copy_allocation_blocks_begin);
                        }
                    };

                    let first_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin =
                        match first_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin {
                            Some(first_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin) => {
                                first_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin
                            }
                            None => {
                                this.fut_state = TransactionTrimJournalFutureState::TrimJournalLogTailExtentsPrepare {
                                    next_extent_index: 0,
                                };
                                continue;
                            }
                        };
                    let trim_region_allocation_blocks_begin =
                        first_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin
                            .align_down(blkdev_io_block_allocation_blocks_log2);
                    let mut last_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin =
                        first_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin;
                    while usize::from(*next_update_states_index) != update_states.len() {
                        let cur_update_state = &update_states[*next_update_states_index];
                        let cur_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin =
                            match cur_update_state.get_journal_staging_copy_allocation_blocks_begin() {
                                Some(cur_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin) => {
                                    cur_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin
                                }
                                None => break,
                            };
                        if this.retain_in_place_writes
                            && cur_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin
                                == cur_update_state.get_target_allocation_blocks_begin()
                        {
                            // Either all or nothing from a single Journal Block is written in-place.
                            debug_assert_ne!(
                                (u64::from(last_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin)
                                    ^ u64::from(cur_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin))
                                    >> journal_block_allocation_blocks_log2,
                                0
                            );
                            break;
                        }
                        if last_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin
                            > cur_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin
                            || u64::from(
                                cur_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin
                                    - last_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin,
                            ) >> auth_tree_data_block_allocation_blocks_log2
                                .max(blkdev_io_block_allocation_blocks_log2)
                                > 1
                        {
                            // There's a gap, stop and process anything up to it.
                            break;
                        }

                        if (u64::from(last_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin)
                            ^ u64::from(cur_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin))
                            >> preferred_bulk_allocation_blocks_log2
                            != 0
                        {
                            // Crossing a preferred IO block boundary, stop for
                            // now and process what's been accumulated.
                            break;
                        }

                        last_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin =
                            cur_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin;
                        *next_update_states_index = next_update_states_index.step();
                    }

                    let trim_region_allocation_blocks_count =
                        match (last_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin
                            - trim_region_allocation_blocks_begin
                            + layout::AllocBlockCount::from(1))
                        .align_up(
                            auth_tree_data_block_allocation_blocks_log2.max(blkdev_io_block_allocation_blocks_log2),
                        ) {
                            Some(trim_region_allocation_blocks_count) => trim_region_allocation_blocks_count,
                            None => {
                                // Cannot happen, but any failure to trim is considered non-fatal anyway.
                                // Continue with the next region.
                                continue;
                            }
                        };

                    let trim_region_blkdev_io_blocks_begin = u64::from(trim_region_allocation_blocks_begin)
                        >> blkdev_io_block_allocation_blocks_log2
                        << allocation_block_blkdev_io_blocks_log2;
                    let trim_region_blkdev_io_blocks_count = u64::from(trim_region_allocation_blocks_count)
                        >> blkdev_io_block_allocation_blocks_log2
                        << allocation_block_blkdev_io_blocks_log2;
                    let region_trim_fut = match fs_instance
                        .blkdev
                        .trim(trim_region_blkdev_io_blocks_begin, trim_region_blkdev_io_blocks_count)
                    {
                        Ok(region_trim_fut) => region_trim_fut,
                        Err(e) => {
                            // Failure to trim is considered non-fatal. Simply proceed to the next
                            // region, unless the storage backend indicates that trimming is not
                            // supported at all.
                            if e == NvBlkDevIoError::OperationNotSupported {
                                this.fut_state = TransactionTrimJournalFutureState::Done;
                                return task::Poll::Ready(this.transaction.take().ok_or_else(|| nvfs_err_internal!()));
                            }
                            continue;
                        }
                    };
                    this.fut_state = TransactionTrimJournalFutureState::TrimJournalStagingCopyRegion {
                        region_trim_fut,
                        next_update_states_index: *next_update_states_index,
                    };
                }
                TransactionTrimJournalFutureState::TrimJournalStagingCopyRegion {
                    region_trim_fut,
                    next_update_states_index,
                } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(region_trim_fut), &fs_instance.blkdev, cx) {
                        task::Poll::Pending => return task::Poll::Pending,
                        task::Poll::Ready(Ok(_)) | task::Poll::Ready(Err(_)) => {
                            // Failure to trim is considered non-fatal. So proceed to the next
                            // region without even examining the result.
                            this.fut_state = TransactionTrimJournalFutureState::TrimJournalStagingCopyRegionPrepare {
                                next_update_states_index: *next_update_states_index,
                            };
                        }
                    }
                }
                TransactionTrimJournalFutureState::TrimJournalLogTailExtentsPrepare { next_extent_index } => {
                    let transaction = match this.transaction.as_ref() {
                        Some(transaction) => transaction,
                        None => {
                            this.fut_state = TransactionTrimJournalFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    if *next_extent_index == transaction.journal_log_tail_extents.len() {
                        this.fut_state = TransactionTrimJournalFutureState::TrimAbandonedJournalStagingCopyPrepare {
                            next_abandandoned_journal_staging_copy_block_index: 0,
                        };
                        continue;
                    }

                    let extent = transaction
                        .journal_log_tail_extents
                        .get_extent_range(*next_extent_index);
                    *next_extent_index += 1;
                    let trim_region_blkdev_io_blocks_begin = u64::from(extent.begin())
                        >> blkdev_io_block_allocation_blocks_log2
                        << allocation_block_blkdev_io_blocks_log2;
                    let trim_region_blkdev_io_blocks_count = u64::from(extent.block_count())
                        >> blkdev_io_block_allocation_blocks_log2
                        << allocation_block_blkdev_io_blocks_log2;
                    let region_trim_fut = match fs_instance
                        .blkdev
                        .trim(trim_region_blkdev_io_blocks_begin, trim_region_blkdev_io_blocks_count)
                    {
                        Ok(region_trim_fut) => region_trim_fut,
                        Err(e) => {
                            // Failure to trim is considered non-fatal. Simply proceed to the next
                            // region, unless the storage backend indicates that trimming is not
                            // supported at all.
                            if e == NvBlkDevIoError::OperationNotSupported {
                                this.fut_state = TransactionTrimJournalFutureState::Done;
                                return task::Poll::Ready(this.transaction.take().ok_or_else(|| nvfs_err_internal!()));
                            }
                            continue;
                        }
                    };
                    this.fut_state = TransactionTrimJournalFutureState::TrimJournalLogTailExtents {
                        region_trim_fut,
                        next_extent_index: *next_extent_index,
                    };
                }
                TransactionTrimJournalFutureState::TrimJournalLogTailExtents {
                    region_trim_fut,
                    next_extent_index,
                } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(region_trim_fut), &fs_instance.blkdev, cx) {
                        task::Poll::Pending => return task::Poll::Pending,
                        task::Poll::Ready(Ok(_)) | task::Poll::Ready(Err(_)) => {
                            // Failure to trim is considered non-fatal. So proceed to the next
                            // region without even examining the result.
                            this.fut_state = TransactionTrimJournalFutureState::TrimJournalLogTailExtentsPrepare {
                                next_extent_index: *next_extent_index,
                            };
                        }
                    }
                }
                TransactionTrimJournalFutureState::TrimAbandonedJournalStagingCopyPrepare {
                    next_abandandoned_journal_staging_copy_block_index,
                } => {
                    let transaction = match this.transaction.as_ref() {
                        Some(transaction) => transaction,
                        None => {
                            this.fut_state = TransactionTrimJournalFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };
                    let abandoned_journal_staging_copy_blocks = &transaction.abandoned_journal_staging_copy_blocks;

                    if *next_abandandoned_journal_staging_copy_block_index
                        == abandoned_journal_staging_copy_blocks.len()
                    {
                        this.fut_state =
                            TransactionTrimJournalFutureState::TrimPendingTransactionsSyncStateAllocsPrepare {
                                next_io_block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex::from(0),
                            };
                        continue;
                    }

                    let trim_region_allocation_blocks_begin =
                        abandoned_journal_staging_copy_blocks[*next_abandandoned_journal_staging_copy_block_index];
                    *next_abandandoned_journal_staging_copy_block_index += 1;
                    let mut last_abandoned_journal_block_allocation_blocks_begin = trim_region_allocation_blocks_begin;
                    while *next_abandandoned_journal_staging_copy_block_index
                        != abandoned_journal_staging_copy_blocks.len()
                    {
                        let cur_abandoned_journal_block_allocation_blocks_begin =
                            abandoned_journal_staging_copy_blocks[*next_abandandoned_journal_staging_copy_block_index];
                        if u64::from(
                            cur_abandoned_journal_block_allocation_blocks_begin
                                - last_abandoned_journal_block_allocation_blocks_begin,
                        ) >> journal_block_allocation_blocks_log2
                            != 1
                        {
                            // There's a gap. Stop and process what's been accumulated so far.
                            break;
                        }

                        if (u64::from(last_abandoned_journal_block_allocation_blocks_begin)
                            ^ u64::from(cur_abandoned_journal_block_allocation_blocks_begin))
                            >> preferred_bulk_allocation_blocks_log2
                            != 0
                        {
                            // Crossing a preferred IO block boundary, stop for
                            // now and process what's been accumulated.
                            break;
                        }

                        last_abandoned_journal_block_allocation_blocks_begin =
                            cur_abandoned_journal_block_allocation_blocks_begin;
                        *next_abandandoned_journal_staging_copy_block_index += 1;
                    }

                    let trim_region_allocation_blocks_count = last_abandoned_journal_block_allocation_blocks_begin
                        - trim_region_allocation_blocks_begin
                        + layout::AllocBlockCount::from(1u64 << journal_block_allocation_blocks_log2);
                    let trim_region_blkdev_io_blocks_begin = u64::from(trim_region_allocation_blocks_begin)
                        >> blkdev_io_block_allocation_blocks_log2
                        << allocation_block_blkdev_io_blocks_log2;
                    let trim_region_blkdev_io_blocks_count = u64::from(trim_region_allocation_blocks_count)
                        >> blkdev_io_block_allocation_blocks_log2
                        << allocation_block_blkdev_io_blocks_log2;
                    let region_trim_fut = match fs_instance
                        .blkdev
                        .trim(trim_region_blkdev_io_blocks_begin, trim_region_blkdev_io_blocks_count)
                    {
                        Ok(region_trim_fut) => region_trim_fut,
                        Err(e) => {
                            // Failure to trim is considered non-fatal. Simply proceed to the next
                            // region, unless the storage backend indicates that trimming is not
                            // supported at all.
                            if e == NvBlkDevIoError::OperationNotSupported {
                                this.fut_state = TransactionTrimJournalFutureState::Done;
                                return task::Poll::Ready(this.transaction.take().ok_or_else(|| nvfs_err_internal!()));
                            }
                            continue;
                        }
                    };
                    this.fut_state = TransactionTrimJournalFutureState::TrimAbandonedJournalStagingCopy {
                        region_trim_fut,
                        next_abandandoned_journal_staging_copy_block_index:
                            *next_abandandoned_journal_staging_copy_block_index,
                    };
                }
                TransactionTrimJournalFutureState::TrimAbandonedJournalStagingCopy {
                    region_trim_fut,
                    next_abandandoned_journal_staging_copy_block_index,
                } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(region_trim_fut), &fs_instance.blkdev, cx) {
                        task::Poll::Pending => return task::Poll::Pending,
                        task::Poll::Ready(Ok(_)) | task::Poll::Ready(Err(_)) => {
                            // Failure to trim is considered non-fatal. So proceed to the next
                            // region without even examining the result.
                            this.fut_state =
                                TransactionTrimJournalFutureState::TrimAbandonedJournalStagingCopyPrepare {
                                    next_abandandoned_journal_staging_copy_block_index:
                                        *next_abandandoned_journal_staging_copy_block_index,
                                };
                        }
                    }
                }
                TransactionTrimJournalFutureState::TrimPendingTransactionsSyncStateAllocsPrepare {
                    next_io_block_allocation_blocks_begin,
                } => {
                    let transaction = match this.transaction.as_ref() {
                        Some(transaction) => transaction,
                        None => {
                            this.fut_state = TransactionTrimJournalFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };
                    let mut pending_allocs_io_blocks_iter = transaction
                        .accumulated_fs_instance_pending_transactions_sync_state
                        .pending_allocs
                        .block_iter_at(*next_io_block_allocation_blocks_begin, io_block_allocation_blocks_log2);
                    let allocated_io_block_allocs_bitmap_word_value =
                        alloc_bitmap::BitmapWord::trailing_bits_mask(1u32 << io_block_allocation_blocks_log2);
                    let first_io_block_allocation_blocks_begin = loop {
                        match pending_allocs_io_blocks_iter.next() {
                            Some((cur_io_block_allocation_blocks_begin, cur_io_block_allocs_bitmap_word)) => {
                                if cur_io_block_allocs_bitmap_word == allocated_io_block_allocs_bitmap_word_value {
                                    break cur_io_block_allocation_blocks_begin;
                                }
                            }
                            None => {
                                this.fut_state = TransactionTrimJournalFutureState::Done;
                                return task::Poll::Ready(this.transaction.take().ok_or_else(|| nvfs_err_internal!()));
                            }
                        }
                    };

                    let trim_region_allocation_blocks_begin = first_io_block_allocation_blocks_begin;
                    let mut last_io_block_allocation_blocks_begin = first_io_block_allocation_blocks_begin;
                    for (cur_io_block_allocation_blocks_begin, cur_io_block_allocs_bitmap_word) in
                        pending_allocs_io_blocks_iter
                    {
                        if u64::from(cur_io_block_allocation_blocks_begin - last_io_block_allocation_blocks_begin)
                            >> io_block_allocation_blocks_log2
                            != 1
                            || cur_io_block_allocs_bitmap_word != allocated_io_block_allocs_bitmap_word_value
                        {
                            // There's a gap or the current IO block is not fully allocated.
                            break;
                        }

                        if (u64::from(last_io_block_allocation_blocks_begin)
                            ^ u64::from(cur_io_block_allocation_blocks_begin))
                            >> preferred_bulk_allocation_blocks_log2
                            != 0
                        {
                            // Crossing a preferred IO block boundary, stop for
                            // now and process what's been accumulated.
                            break;
                        }

                        last_io_block_allocation_blocks_begin = cur_io_block_allocation_blocks_begin;
                    }

                    let trim_region_allocation_blocks_end = last_io_block_allocation_blocks_begin
                        + layout::AllocBlockCount::from(1u64 << io_block_allocation_blocks_log2);
                    *next_io_block_allocation_blocks_begin = trim_region_allocation_blocks_end;

                    let trim_region_blkdev_io_blocks_begin = u64::from(trim_region_allocation_blocks_begin)
                        >> blkdev_io_block_allocation_blocks_log2
                        << allocation_block_blkdev_io_blocks_log2;
                    let trim_region_blkdev_io_blocks_count =
                        u64::from(trim_region_allocation_blocks_end - trim_region_allocation_blocks_begin)
                            >> blkdev_io_block_allocation_blocks_log2
                            << allocation_block_blkdev_io_blocks_log2;
                    let region_trim_fut = match fs_instance
                        .blkdev
                        .trim(trim_region_blkdev_io_blocks_begin, trim_region_blkdev_io_blocks_count)
                    {
                        Ok(region_trim_fut) => region_trim_fut,
                        Err(e) => {
                            // Failure to trim is considered non-fatal. Simply proceed to the next
                            // region, unless the storage backend indicates that trimming is not
                            // supported at all.
                            if e == NvBlkDevIoError::OperationNotSupported {
                                this.fut_state = TransactionTrimJournalFutureState::Done;
                                return task::Poll::Ready(this.transaction.take().ok_or_else(|| nvfs_err_internal!()));
                            }
                            continue;
                        }
                    };
                    this.fut_state = TransactionTrimJournalFutureState::TrimPendingTransactionsSyncStateAllocs {
                        region_trim_fut,
                        next_io_block_allocation_blocks_begin: *next_io_block_allocation_blocks_begin,
                    };
                }
                TransactionTrimJournalFutureState::TrimPendingTransactionsSyncStateAllocs {
                    region_trim_fut,
                    next_io_block_allocation_blocks_begin,
                } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(region_trim_fut), &fs_instance.blkdev, cx) {
                        task::Poll::Pending => return task::Poll::Pending,
                        task::Poll::Ready(Ok(_)) | task::Poll::Ready(Err(_)) => {
                            // Failure to trim is considered non-fatal. So proceed to the next
                            // region without even examining the result.
                            this.fut_state =
                                TransactionTrimJournalFutureState::TrimPendingTransactionsSyncStateAllocsPrepare {
                                    next_io_block_allocation_blocks_begin: *next_io_block_allocation_blocks_begin,
                                };
                        }
                    }
                }
                TransactionTrimJournalFutureState::Done => unreachable!(),
            }
        }
    }
}

/// Cleanup the journal written for a [`Transaction`] that got cancelled
/// pre-commit.
///
/// Cleanup after a [`Transaction`] cancelled before the journal log head extent
/// got written to.
pub struct TransactionCleanupPreCommitCancelledFuture<B: blkdev::NvBlkDev> {
    trim_journal_fut: TransactionTrimJournalFuture<B>,
}

impl<B: blkdev::NvBlkDev> TransactionCleanupPreCommitCancelledFuture<B> {
    /// Instantiate a [`TransactionCleanupPreCommitCancelledFuture`].
    ///
    /// The [`TransactionCleanupPreCommitCancelledFuture`] consumes the
    /// `transaction`.
    ///
    /// # Arguments:
    ///
    /// * `transaction` - The [`Transaction`] after which to cleanup.
    pub fn new(transaction: Box<Transaction>) -> Self {
        Self {
            trim_journal_fut: TransactionTrimJournalFuture::new(transaction, false),
        }
    }

    /// Poll the [`TransactionCleanupPreCommitCancelledFuture`] to completion.
    ///
    /// Nothing is returned upon completion.
    ///
    /// # Arguments:
    ///
    /// * `fs_instance_sync_state` - Exclusive reference to
    ///   [`CocoonFs::sync_state`](crate::fs::cocoonfs::fs::CocoonFs::sync_state).
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    pub fn poll<ST: sync_types::SyncTypes>(
        mut self: pin::Pin<&mut Self>,
        fs_instance_sync_state: CocoonFsSyncStateMemberMutRef<'_, ST, B>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<()> {
        // Trimming failures are getting ignored deliberately.
        match TransactionTrimJournalFuture::poll(pin::Pin::new(&mut self.trim_journal_fut), fs_instance_sync_state, cx)
        {
            task::Poll::Ready(Ok(_)) | task::Poll::Ready(Err(_)) => task::Poll::Ready(()),
            task::Poll::Pending => task::Poll::Pending,
        }
    }
}

/// Invalidate and cleanup the journal written for a [`Transaction`].
///
/// Cleanup after a [`Transaction`] for which the final the journal log head
/// extent write failed, leaving it in an indeterminate state.
pub struct TransactionAbortJournalFuture<B: blkdev::NvBlkDev> {
    fut_state: TransactionAbortJournalFutureState<B>,
}

/// [`TransactionAbortJournalFuture`] state-machine state.
enum TransactionAbortJournalFutureState<B: blkdev::NvBlkDev> {
    Init {
        // Is optional, but None only on internal error or memory allocation failures.
        transaction: Option<Box<Transaction>>,
    },
    InvalidateJournalLogPrepare {
        // Is optional, but None only on internal error or memory allocation failures.
        transaction: Option<Box<Transaction>>,
    },
    InvalidateJournalLog {
        // Is optional, but None only on internal error or memory allocation failures.
        transaction: Option<Box<Transaction>>,
        invalidate_journal_log_fut: journal::log::JournalLogInvalidateFuture<B>,
    },
    TrimJournal {
        trim_journal_fut: TransactionTrimJournalFuture<B>,
    },
    Done,
}

impl<B: blkdev::NvBlkDev> TransactionAbortJournalFuture<B> {
    /// Instantiate a [`TransactionAbortJournalFuture`].
    ///
    /// The [`TransactionAbortJournalFuture`] assumes ownership of
    /// `transaction`, if any, and returns it back from
    /// [`poll()`](Self::poll) upon completion with failure.
    ///
    /// # Arguments:
    ///
    /// * `transaction` - The [`Transaction`] for which the journal had been
    ///   written, if still available. If `None`, the journal log will only get
    ///   invalidated and no further cleanup will take place.
    /// * `_fs_instance_sync_state` - Exclusive reference to
    ///   [`CocoonFs::sync_state`](crate::fs::cocoonfs::fs::CocoonFs::sync_state).
    /// * `low_memory` - Whether the system is in a low memory condition.
    pub fn new<ST: sync_types::SyncTypes>(
        mut transaction: Option<Box<Transaction>>,
        _fs_instance_sync_state: CocoonFsSyncStateMemberMutRef<'_, ST, B>,
        low_memory: bool,
    ) -> Result<Self, (Option<Box<Transaction>>, NvFsError)> {
        if low_memory {
            Self::enter_low_memory(&mut transaction);
        }
        Ok(Self {
            fut_state: TransactionAbortJournalFutureState::Init { transaction },
        })
    }

    /// Poll the [`TransactionAbortJournalFuture`] to completion.
    ///
    /// Nothing is returned on successful completion. Otherwise, on error,
    /// a pair of the input [`Transaction`] initially passed to
    /// [`new()`](Self::new) and the error reason is returned.
    ///
    /// # Arguments:
    ///
    /// * `fs_instance_sync_state` - Exclusive reference to
    ///   [`CocoonFs::sync_state`](crate::fs::cocoonfs::fs::CocoonFs::sync_state).
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    #[allow(clippy::type_complexity)]
    pub fn poll<ST: sync_types::SyncTypes>(
        self: pin::Pin<&mut Self>,
        fs_instance_sync_state: CocoonFsSyncStateMemberMutRef<'_, ST, B>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), (Option<Box<Transaction>>, NvFsError)>> {
        let this = pin::Pin::into_inner(self);
        loop {
            match &mut this.fut_state {
                TransactionAbortJournalFutureState::Init { transaction } => {
                    this.fut_state = TransactionAbortJournalFutureState::InvalidateJournalLogPrepare {
                        transaction: transaction.take(),
                    };
                }
                TransactionAbortJournalFutureState::InvalidateJournalLogPrepare { transaction } => {
                    let invalidate_journal_log_fut = journal::log::JournalLogInvalidateFuture::new(true);
                    this.fut_state = TransactionAbortJournalFutureState::InvalidateJournalLog {
                        transaction: transaction.take(),
                        invalidate_journal_log_fut,
                    };
                }
                TransactionAbortJournalFutureState::InvalidateJournalLog {
                    transaction,
                    invalidate_journal_log_fut,
                } => {
                    let fs_instance = fs_instance_sync_state.get_fs_ref();
                    let fs_config = &fs_instance.fs_config;
                    match journal::log::JournalLogInvalidateFuture::poll(
                        pin::Pin::new(invalidate_journal_log_fut),
                        &fs_instance.blkdev,
                        &fs_config.image_layout,
                        fs_config.image_header_end,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => {
                            let mut transaction = transaction.take();
                            if e == NvFsError::MemoryAllocationFailure && Self::enter_low_memory(&mut transaction) {
                                this.fut_state =
                                    TransactionAbortJournalFutureState::InvalidateJournalLogPrepare { transaction };
                                continue;
                            } else {
                                this.fut_state = TransactionAbortJournalFutureState::Done;
                                return task::Poll::Ready(Err((transaction, e)));
                            }
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    if !fs_config.enable_trimming {
                        this.fut_state = TransactionAbortJournalFutureState::Done;
                        return task::Poll::Ready(Ok(()));
                    }

                    let transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => {
                            // Failure to trim is non-fatal.
                            this.fut_state = TransactionAbortJournalFutureState::Done;
                            return task::Poll::Ready(Ok(()));
                        }
                    };

                    let trim_journal_fut = TransactionTrimJournalFuture::new(transaction, false);
                    this.fut_state = TransactionAbortJournalFutureState::TrimJournal { trim_journal_fut };
                }
                TransactionAbortJournalFutureState::TrimJournal { trim_journal_fut } => {
                    match TransactionTrimJournalFuture::poll(
                        pin::Pin::new(trim_journal_fut),
                        fs_instance_sync_state,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(_)) | task::Poll::Ready(Err(_)) => {
                            // Failure to trim is non-fatal.
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    }

                    this.fut_state = TransactionAbortJournalFutureState::Done;
                    return task::Poll::Ready(Ok(()));
                }
                TransactionAbortJournalFutureState::Done => unreachable!(),
            }
        }
    }

    /// Enter a low memory condition.
    ///
    /// Try to free up some memory to reduce the pressure when subsequently
    /// attempting another try. Return `true` if some memory could get freed up.
    ///
    ///
    /// # Arguments:
    //
    /// * `transaction` - `mut` reference to the `transaction` initially passed
    ///   to [`new()`](Self::new()).
    fn enter_low_memory(transaction: &mut Option<Box<Transaction>>) -> bool {
        // Drop the transaction with all its data. This will render the best-effort trim
        // operation into a nop.
        transaction.take().is_some()
    }
}
