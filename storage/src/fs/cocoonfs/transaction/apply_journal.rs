// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`TransactionApplyJournalFuture`].

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

use super::{
    Transaction,
    auth_tree_data_blocks_update_states::{
        AllocationBlockUpdateNvSyncState, AllocationBlockUpdateNvSyncStateAllocated,
        AllocationBlockUpdateNvSyncStateAllocatedModified, AllocationBlockUpdateStagedUpdate,
        AuthTreeDataBlocksUpdateStates, AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        AuthTreeDataBlocksUpdateStatesIndex, AuthTreeDataBlocksUpdateStatesIndexRange,
    },
    cleanup::TransactionTrimJournalFuture,
    read_missing_data::TransactionReadMissingDataFuture,
};
use crate::{
    chip::{self, ChunkedIoRegion, ChunkedIoRegionChunkRange, ChunkedIoRegionError},
    fs::{
        NvFsError,
        cocoonfs::{
            alloc_bitmap, auth_tree, extents, fs::CocoonFsSyncStateMemberMutRef, inode_index, journal, layout,
            read_buffer,
        },
    },
    nvfs_err_internal,
    utils_async::sync_types,
};
use core::{iter, mem, pin, task};

#[cfg(doc)]
use layout::ImageLayout;
#[cfg(doc)]
use super::auth_tree_data_blocks_update_states::AuthTreeDataBlockUpdateState;

/// Apply a committing [`Transaction`]'s journal online.
///
/// It is expected that the journal [has been
/// written](super::write_journal::TransactionWriteJournalFuture) beforehand,
/// and thus, the changes staged at the [`Transaction`] are considered
/// effective.
pub struct TransactionApplyJournalFuture<C: chip::NvChip> {
    fut_state: TransactionApplyJournalFutureState<C>,
    low_memory: u32,
    low_memory_at_init: bool,
}

#[repr(u32)]
enum TransactionApplyJournalFutureState<C: chip::NvChip> {
    Init {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<Transaction>>,
    },
    ApplyAuthTreeUpdatesPrepare {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<Transaction>>,
    },
    ApplyAuthTreeUpdates {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<Transaction>>,
        auth_tree_apply_updates_fut: auth_tree::AuthTreeApplyUpdatesFuture<C>,
    },
    WriteDataUpdatesPrepare {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<Transaction>>,
    },
    WriteDataUpdates {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        write_data_updates_fut: TransactionWriteDataUpdatesFuture<C>,
    },
    InvalidateJournalLogPrepare {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<Transaction>>,
    },
    InvalidateJournalLog {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<Transaction>>,
        invalidate_journal_log_fut: journal::log::JournalLogInvalidateFuture<C>,
    },
    WriteBarrierBeforeTrim {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<Transaction>>,
        write_barrier_fut: C::WriteBarrierFuture,
    },
    TrimDeallocatedIoBlocks {
        trim_deallocated_io_blocks_fut: TransactionTrimDeallocatedIoBlocksFuture<C>,
    },
    TrimJournal {
        trim_journal_fut: TransactionTrimJournalFuture<C>,
    },
    Done,
}

impl<C: chip::NvChip> TransactionApplyJournalFuture<C> {
    /// Instantiate a [`TransactionApplyJournalFuture`].
    ///
    /// The [`TransactionApplyJournalFuture`] assumes
    /// ownership of the `transaction` for the duration of the operation, it
    /// will eventually get returned back from [`poll()`](Self::poll) upon
    /// completion with failure.
    ///
    /// # Arguments:
    ///
    /// * `transaction` - The committing [`Transaction`].
    /// * `_fs_instance_sync_state` - Reference to
    ///   [`crate::fs::cocoonfs::fs::CocoonFs::sync_state`](crate::fs::cocoonfs::fs::CocoonFs::sync_state).
    /// * `low_memory` - Whether the system is in a low memory condition.
    pub fn new<ST: sync_types::SyncTypes>(
        transaction: Box<Transaction>,
        _fs_instance_sync_state: CocoonFsSyncStateMemberMutRef<'_, ST, C>,
        low_memory: bool,
    ) -> Result<Self, (Box<Transaction>, NvFsError)> {
        Ok(Self {
            fut_state: TransactionApplyJournalFutureState::Init {
                transaction: Some(transaction),
            },
            low_memory: 0u32,
            low_memory_at_init: low_memory,
        })
    }

    /// Poll the [`TransactionApplyJournalFuture`] to completion.
    ///
    /// On successful completion, `Ok(())` is returned. Otherwise on error, the
    /// input [`Transaction`], if still available, is returned back alongside
    /// the error reason.
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
        mut fs_instance_sync_state: CocoonFsSyncStateMemberMutRef<'_, ST, C>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), (Option<Box<Transaction>>, NvFsError)>> {
        let this = pin::Pin::into_inner(self);

        // This Future needs to be idempotent on error: the journal log has been
        // written, and application will get retried until succeeds.  Also, as
        // we're at a point of no return (success might have been reported back
        // to the initiator already), the future must try hard to succeed
        // eventually upon retries.
        let (transaction, e) = loop {
            match &mut this.fut_state {
                TransactionApplyJournalFutureState::Init { transaction } => {
                    let mut transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => break (None, nvfs_err_internal!()),
                    };

                    #[cfg(test)]
                    if transaction.test_fail_apply_journal {
                        break (Some(transaction), NvFsError::IoError(crate::fs::NvFsIoError::IoFailure));
                    }

                    // Apply changes to the allocation bitmap.
                    // After that, the pending_allocs/pending_frees will only be used
                    // for trimming at cleanup.
                    if let Err(e) = fs_instance_sync_state
                        .alloc_bitmap
                        .apply_pending(&transaction.allocs.pending_frees, true)
                    {
                        debug_assert_eq!(e, NvFsError::Internal);
                        break (Some(transaction), e);
                    }
                    if let Err(e) = fs_instance_sync_state
                        .alloc_bitmap
                        .apply_pending(&transaction.allocs.pending_allocs, false)
                    {
                        debug_assert_eq!(e, NvFsError::Internal);
                        break (Some(transaction), e);
                    }

                    // If in a low memory condition already, free anything not strictly needed for
                    // what follows.
                    if this.low_memory_at_init {
                        this.enter_low_memory(&mut transaction, fs_instance_sync_state.make_borrow());
                    }

                    // Apply changes to the inode index.
                    let transaction_update_states = &transaction.auth_tree_data_blocks_update_states;
                    fs_instance_sync_state.inode_index.apply_updates(
                        &mut transaction.inode_index_updates,
                        |cached_inode_index_tree_node_allocation_blocks_range| {
                            let cached_inode_index_node_states_allocation_blocks_index_range =
                                match transaction_update_states.lookup_allocation_blocks_update_states_index_range(
                                    cached_inode_index_tree_node_allocation_blocks_range,
                                ) {
                                    Ok(inode_index_node_states_allocation_blocks_index_range) => {
                                        inode_index_node_states_allocation_blocks_index_range
                                    }
                                    Err(_) => {
                                        // No overlapping update states found.
                                        return false;
                                    }
                                };

                            // If any of the Allocation Blocks had been updated, the cached node
                            // entry is stale.
                            transaction_update_states
                                .iter_allocation_blocks(Some(
                                    &cached_inode_index_node_states_allocation_blocks_index_range,
                                ))
                                .any(|allocation_block_update_state| {
                                    allocation_block_update_state.1.has_modified_data()
                                })
                        },
                    );
                    // Reset, it's not needed anymore.
                    transaction.inode_index_updates =
                        inode_index::TransactionInodeIndexUpdates::new(&fs_instance_sync_state.inode_index);

                    this.fut_state = TransactionApplyJournalFutureState::ApplyAuthTreeUpdatesPrepare {
                        transaction: Some(transaction),
                    };
                }
                TransactionApplyJournalFutureState::ApplyAuthTreeUpdatesPrepare { transaction } => {
                    let mut transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => break (None, nvfs_err_internal!()),
                    };

                    let auth_tree_apply_updates_fut = auth_tree::AuthTreeApplyUpdatesFuture::new(mem::take(
                        &mut transaction.pending_auth_tree_updates.pending_nodes_updates,
                    ));
                    this.fut_state = TransactionApplyJournalFutureState::ApplyAuthTreeUpdates {
                        transaction: Some(transaction),
                        auth_tree_apply_updates_fut,
                    };
                }
                TransactionApplyJournalFutureState::ApplyAuthTreeUpdates {
                    transaction: fut_transaction,
                    auth_tree_apply_updates_fut,
                } => {
                    let mut transaction = match fut_transaction.take() {
                        Some(transaction) => transaction,
                        None => break (None, nvfs_err_internal!()),
                    };

                    let (
                        fs_instance,
                        _fs_sync_state_image_size,
                        _fs_sync_state_alloc_bitmap,
                        _fs_sync_state_alloc_bitmap_file,
                        fs_sync_state_auth_tree,
                        _fs_sync_state_inode_index,
                        _fs_sync_state_read_buffer,
                        _fs_sync_state_keys_cache,
                    ) = fs_instance_sync_state.fs_instance_and_destructure_borrow_mut();
                    match auth_tree::AuthTreeApplyUpdatesFuture::poll(
                        pin::Pin::new(auth_tree_apply_updates_fut),
                        &fs_instance.chip,
                        fs_sync_state_auth_tree,
                        &transaction.pending_auth_tree_updates.updated_root_hmac_digest,
                        cx,
                    ) {
                        task::Poll::Ready((pending_auth_tree_nodes_updates, result)) => {
                            // Idempotency on error: move the pending_nodes_updates back into
                            // the transaction on error. Note that if an error happened in a later
                            // stage, the Authentication Tree updates application on an empty
                            // pending_nodes_updates upon retry would be a nop.
                            if let Err(e) = result {
                                transaction.pending_auth_tree_updates.pending_nodes_updates =
                                    pending_auth_tree_nodes_updates;

                                drop(fs_instance);
                                if e == NvFsError::MemoryAllocationFailure
                                    && this.enter_low_memory(&mut transaction, fs_instance_sync_state.make_borrow())
                                {
                                    // Some additional memory could potentially get freed. Retry.
                                    this.fut_state = TransactionApplyJournalFutureState::ApplyAuthTreeUpdatesPrepare {
                                        transaction: Some(transaction),
                                    };
                                    continue;
                                }

                                break (Some(transaction), e);
                            }
                        }
                        task::Poll::Pending => {
                            *fut_transaction = Some(transaction);
                            return task::Poll::Pending;
                        }
                    };

                    this.fut_state = TransactionApplyJournalFutureState::WriteDataUpdatesPrepare {
                        transaction: Some(transaction),
                    };
                }
                TransactionApplyJournalFutureState::WriteDataUpdatesPrepare { transaction } => {
                    let transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => break (None, nvfs_err_internal!()),
                    };

                    let fs_instance = fs_instance_sync_state.get_fs_ref();
                    let image_layout = &fs_instance.fs_config.image_layout;
                    let all_update_states_index_range = AuthTreeDataBlocksUpdateStatesIndexRange::new(
                        AuthTreeDataBlocksUpdateStatesIndex::from(0),
                        AuthTreeDataBlocksUpdateStatesIndex::from(
                            transaction.auth_tree_data_blocks_update_states.len(),
                        ),
                    );
                    let write_data_updates_fut = TransactionWriteDataUpdatesFuture::new(
                        transaction,
                        &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::from(all_update_states_index_range),
                        this.low_memory != 0,
                        image_layout.io_block_allocation_blocks_log2 as u32,
                    );
                    this.fut_state = TransactionApplyJournalFutureState::WriteDataUpdates { write_data_updates_fut };
                }
                TransactionApplyJournalFutureState::WriteDataUpdates { write_data_updates_fut } => {
                    let mut transaction = match TransactionWriteDataUpdatesFuture::poll(
                        pin::Pin::new(write_data_updates_fut),
                        fs_instance_sync_state.make_borrow(),
                        cx,
                    ) {
                        task::Poll::Ready(Ok((transaction, Ok(())))) => transaction,
                        task::Poll::Ready(Ok((mut transaction, Err(e)))) => {
                            if e == NvFsError::MemoryAllocationFailure
                                && this.enter_low_memory(&mut transaction, fs_instance_sync_state.make_borrow())
                            {
                                // Some additional memory could potentially get freed. Retry.
                                this.fut_state = TransactionApplyJournalFutureState::WriteDataUpdatesPrepare {
                                    transaction: Some(transaction),
                                };
                                continue;
                            }

                            break (Some(transaction), e);
                        }
                        task::Poll::Ready(Err(e)) => break (None, e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    // Now that the data updates have been written, which might potentially have
                    // taken advantage of any data cached at the transactions' Allocation Block
                    // update states, update the read buffer. This will move data cached at the
                    // Allocation Block update states over into the read buffer as appropriate.
                    if this.low_memory == 0 {
                        Self::update_fs_sync_state_read_buffer(
                            &mut fs_instance_sync_state.read_buffer,
                            &mut transaction.auth_tree_data_blocks_update_states,
                            &transaction.allocs.pending_frees,
                        )
                    } else {
                        // Should have happened already, but make it explicit, as it's crucial.
                        fs_instance_sync_state.read_buffer.clear_caches();
                    }

                    this.fut_state = TransactionApplyJournalFutureState::InvalidateJournalLogPrepare {
                        transaction: Some(transaction),
                    };
                }
                TransactionApplyJournalFutureState::InvalidateJournalLogPrepare { transaction } => {
                    let transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => break (None, nvfs_err_internal!()),
                    };

                    let invalidate_journal_log_fut = journal::log::JournalLogInvalidateFuture::new(false);
                    this.fut_state = TransactionApplyJournalFutureState::InvalidateJournalLog {
                        transaction: Some(transaction),
                        invalidate_journal_log_fut,
                    };
                }
                TransactionApplyJournalFutureState::InvalidateJournalLog {
                    transaction,
                    invalidate_journal_log_fut,
                } => {
                    let fs_instance = fs_instance_sync_state.get_fs_ref();
                    let fs_config = &fs_instance.fs_config;
                    match journal::log::JournalLogInvalidateFuture::poll(
                        pin::Pin::new(invalidate_journal_log_fut),
                        &fs_instance.chip,
                        &fs_config.image_layout,
                        fs_config.image_header_end,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => {
                            let mut transaction = match transaction.take() {
                                Some(transaction) => transaction,
                                None => break (None, e),
                            };

                            drop(fs_instance);
                            if e == NvFsError::MemoryAllocationFailure
                                && this.enter_low_memory(&mut transaction, fs_instance_sync_state.make_borrow())
                            {
                                // Some additional memory could potentially get freed. Retry.
                                this.fut_state = TransactionApplyJournalFutureState::InvalidateJournalLogPrepare {
                                    transaction: Some(transaction),
                                };
                                continue;
                            }

                            break (Some(transaction), e);
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    // If everything needed for trimming had been flushed due to a low memory
                    // condition, then don't even bother.
                    if fs_instance.fs_config.enable_trimming && this.low_memory < 2 {
                        let write_barrier_fut = match fs_instance.chip.write_barrier() {
                            Ok(write_barrier_fut) => write_barrier_fut,
                            Err(_) => {
                                // A write barrier is needed before trimming, but
                                // failure to trim is non-fatal. Simply return.
                                this.fut_state = TransactionApplyJournalFutureState::Done;
                                return task::Poll::Ready(Ok(()));
                            }
                        };
                        this.fut_state = TransactionApplyJournalFutureState::WriteBarrierBeforeTrim {
                            transaction: transaction.take(),
                            write_barrier_fut,
                        };
                    } else {
                        this.fut_state = TransactionApplyJournalFutureState::Done;
                        return task::Poll::Ready(Ok(()));
                    }
                }
                TransactionApplyJournalFutureState::WriteBarrierBeforeTrim {
                    transaction,
                    write_barrier_fut,
                } => {
                    let fs_instance = fs_instance_sync_state.get_fs_ref();
                    match chip::NvChipFuture::poll(pin::Pin::new(write_barrier_fut), &fs_instance.chip, cx) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(_)) => {
                            // A write barrier is needed before trimming, but
                            // failure to trim is non-fatal. Simply return.
                            this.fut_state = TransactionApplyJournalFutureState::Done;
                            return task::Poll::Ready(Ok(()));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    // The remaining work to be done is trimming. Any failure is non-fatal.
                    let transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => return task::Poll::Ready(Ok(())),
                    };
                    let trim_deallocated_io_blocks_fut = TransactionTrimDeallocatedIoBlocksFuture::new(transaction);
                    this.fut_state = TransactionApplyJournalFutureState::TrimDeallocatedIoBlocks {
                        trim_deallocated_io_blocks_fut,
                    };
                }
                TransactionApplyJournalFutureState::TrimDeallocatedIoBlocks {
                    trim_deallocated_io_blocks_fut,
                } => {
                    let transaction = match TransactionTrimDeallocatedIoBlocksFuture::poll(
                        pin::Pin::new(trim_deallocated_io_blocks_fut),
                        fs_instance_sync_state.make_borrow(),
                        cx,
                    ) {
                        task::Poll::Ready(Ok(transaction)) => transaction,
                        task::Poll::Ready(Err(_)) => {
                            // Trimming errors are non-fatal and deliberately
                            // ignored.
                            this.fut_state = TransactionApplyJournalFutureState::Done;
                            return task::Poll::Ready(Ok(()));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let trim_journal_fut = TransactionTrimJournalFuture::new(transaction, true);
                    this.fut_state = TransactionApplyJournalFutureState::TrimJournal { trim_journal_fut };
                }
                TransactionApplyJournalFutureState::TrimJournal { trim_journal_fut } => {
                    match TransactionTrimJournalFuture::poll(
                        pin::Pin::new(trim_journal_fut),
                        fs_instance_sync_state,
                        cx,
                    ) {
                        task::Poll::Ready(_) => {
                            // Trimming errors are non-fatal and deliberately
                            // ignored.
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    this.fut_state = TransactionApplyJournalFutureState::Done;
                    return task::Poll::Ready(Ok(()));
                }
                TransactionApplyJournalFutureState::Done => unreachable!(),
            }
        };

        this.fut_state = TransactionApplyJournalFutureState::Done;
        task::Poll::Ready(Err((transaction, e)))
    }

    /// Enter a low memory condition.
    ///
    /// Free up some caches and otherwise no longer needed state in order to
    /// reduce memory pressure for a subsequent retry. Return `true` if some
    /// memory could be freed up.
    ///
    /// # Arguments:
    ///
    /// * `transaction` - The committing [`Transaction`].
    /// * `fs_instance_sync_state` - Exclusive reference to
    ///   [`CocoonFs::sync_state`](crate::fs::cocoonfs::fs::CocoonFs::sync_state).
    fn enter_low_memory<ST: sync_types::SyncTypes>(
        &mut self,
        transaction: &mut Transaction,
        fs_instance_sync_state: CocoonFsSyncStateMemberMutRef<'_, ST, C>,
    ) -> bool {
        let low_memory = self.low_memory;

        // Unconditionally clear caches.
        fs_instance_sync_state.clear_caches();
        transaction_drop_data_buffers(&mut transaction.auth_tree_data_blocks_update_states, None);
        transaction.inode_index_updates.clear_caches();
        self.low_memory = 1;

        // If this is a retry already, or trimming is not enabled, deallocated anything
        // needed exclusively for trimming.
        let fs_instance = fs_instance_sync_state.get_fs_ref();
        if low_memory != 0 || !fs_instance.fs_config.enable_trimming {
            transaction.allocs.pending_allocs = alloc_bitmap::SparseAllocBitmap::new();
            transaction.allocs.pending_frees = alloc_bitmap::SparseAllocBitmap::new();
            transaction.allocs.journal_allocs = alloc_bitmap::SparseAllocBitmap::new();
            transaction.journal_log_tail_extents = extents::PhysicalExtents::new();
            transaction.abandoned_journal_staging_copy_blocks = Vec::new();
            transaction
                .accumulated_fs_instance_pending_transactions_sync_state
                .pending_allocs = alloc_bitmap::SparseAllocBitmap::new();
            self.low_memory = 2;

            // The transaction's update states are needed only for copying the data updates
            // from the Journal Staging Copies to their target locations as well
            // as for trimming. If the former has happened, deallocate them.  As
            // a side-effect, if another TransactionApplyJournalFuture is
            // subsequently instantiated and polled on the transaction, because
            // the low memory condition prevails and the current one cannot get
            // driven to successful completion, then the WriteDataUpdates step would
            // effectively become a nop, thereby avoiding another redundant
            // write-out.
            if match &self.fut_state {
                TransactionApplyJournalFutureState::Init { .. }
                | TransactionApplyJournalFutureState::ApplyAuthTreeUpdatesPrepare { .. }
                | TransactionApplyJournalFutureState::ApplyAuthTreeUpdates { .. }
                | TransactionApplyJournalFutureState::WriteDataUpdatesPrepare { .. }
                | TransactionApplyJournalFutureState::WriteDataUpdates { .. } => false,
                TransactionApplyJournalFutureState::InvalidateJournalLogPrepare { .. }
                | TransactionApplyJournalFutureState::InvalidateJournalLog { .. }
                | TransactionApplyJournalFutureState::WriteBarrierBeforeTrim { .. }
                | TransactionApplyJournalFutureState::TrimDeallocatedIoBlocks { .. }
                | TransactionApplyJournalFutureState::TrimJournal { .. }
                | TransactionApplyJournalFutureState::Done => true,
            } {
                transaction.auth_tree_data_blocks_update_states.clear();
                self.low_memory = 3;
            }
        }

        low_memory < self.low_memory
    }

    /// Apply updates from the [`Transaction`] to the [filesystem
    /// instance's read
    /// buffer](crate::fs::cocoonfs::fs::CocoonFsSyncState::read_buffer).
    ///
    /// # Arguments:
    ///
    /// * `read_buffer` - The [filesystem instance's read
    ///   buffer](crate::fs::cocoonfs::fs::CocoonFsSyncState::read_buffer).
    /// * `transaction_update_states` - `mut` reference to
    ///   [`Transaction::auth_tree_data_blocks_update_states`].
    /// * `transaction_pending_frees` - Reference to the
    ///   [`Transaction::allocs`]'
    ///   [`TransactionAllocations::pending_frees`](super::TransactionAllocations::pending_frees).
    fn update_fs_sync_state_read_buffer<ST: sync_types::SyncTypes>(
        read_buffer: &mut read_buffer::ReadBuffer<ST>,
        transaction_update_states: &mut AuthTreeDataBlocksUpdateStates,
        transaction_pending_frees: &alloc_bitmap::SparseAllocBitmap,
    ) {
        // Handle any Allocation Blocks cached as authenticated in the ReadBuffer.
        if let Some(buffered_authenticated_range) = read_buffer.get_buffered_authenticated_range() {
            // Mark any cached Allocation Blocks in the ReadBuffer as deallocated if freed
            // by the transaction. In particular, that drops their cached data,
            // if any.
            for pending_free in transaction_pending_frees.iter_at(buffered_authenticated_range.begin()) {
                if pending_free.0 >= buffered_authenticated_range.end() {
                    break;
                }
                let (mut cur_allocation_block_index, mut bitmap_word) = if buffered_authenticated_range.begin()
                    <= pending_free.0
                {
                    (pending_free.0, pending_free.1)
                } else {
                    (
                        buffered_authenticated_range.begin(),
                        pending_free.1
                            >> ((u64::from(buffered_authenticated_range.begin()) - u64::from(pending_free.0)) as u32),
                    )
                };

                read_buffer.update_authenticated_buffers(
                    cur_allocation_block_index,
                    iter::from_fn(|| {
                        if cur_allocation_block_index >= buffered_authenticated_range.end() {
                            return None;
                        }

                        let update = if bitmap_word & 1 != 0 {
                            read_buffer::ReadBufferAllocationBlockUpdate::Unallocated
                        } else {
                            read_buffer::ReadBufferAllocationBlockUpdate::Retain
                        };

                        bitmap_word >>= 1;
                        cur_allocation_block_index += layout::AllocBlockCount::from(1);

                        Some(update)
                    }),
                );
            }

            // Invalidate any modified Allocation Blocks cached in the ReadBuffer. If the
            // updated data is still available at the transaction and
            // authenticated, install it in the ReadBuffer.
            if let Ok(mut states_allocation_blocks_index_range) = transaction_update_states
                .lookup_allocation_blocks_update_states_index_range(&buffered_authenticated_range)
            {
                while !states_allocation_blocks_index_range.is_empty() {
                    let cur_subrange_states_allocation_blocks_index_range = transaction_update_states
                        .allocation_blocks_range_contiguous_head_subrange(&states_allocation_blocks_index_range);
                    states_allocation_blocks_index_range =
                        AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::new(
                            cur_subrange_states_allocation_blocks_index_range.end(),
                            states_allocation_blocks_index_range.end(),
                        );
                    let cur_subrange_target_allocation_blocks_begin = transaction_update_states
                        .get_allocation_block_target(cur_subrange_states_allocation_blocks_index_range.begin());
                    read_buffer.update_authenticated_buffers(
                        cur_subrange_target_allocation_blocks_begin,
                        transaction_update_states
                            .iter_allocation_blocks_mut(Some(&cur_subrange_states_allocation_blocks_index_range))
                            .map(|allocation_block_update_state| {
                                if !matches!(
                                    allocation_block_update_state.1.staged_update,
                                    AllocationBlockUpdateStagedUpdate::None
                                ) {
                                    // At this point, the transaction should have been applied and there
                                    // better ought to be no more staged updates.
                                    debug_assert!(false);
                                    return read_buffer::ReadBufferAllocationBlockUpdate::Invalidate;
                                }
                                match &mut allocation_block_update_state.1.nv_sync_state {
                                    AllocationBlockUpdateNvSyncState::Unallocated(..) => {
                                        read_buffer::ReadBufferAllocationBlockUpdate::Unallocated
                                    }
                                    AllocationBlockUpdateNvSyncState::Allocated(allocated_state) => {
                                        match allocated_state {
                                            AllocationBlockUpdateNvSyncStateAllocated::Unmodified(unmodified_state) => {
                                                match unmodified_state.cached_encrypted_data.take_if(
                                                    |cached_encrypted_data| cached_encrypted_data.is_authenticated(),
                                                ) {
                                                    Some(cached_encrypted_data) => {
                                                        read_buffer::ReadBufferAllocationBlockUpdate::Update {
                                                            data: cached_encrypted_data.into_encrypted_data(),
                                                        }
                                                    }
                                                    None => read_buffer::ReadBufferAllocationBlockUpdate::Retain,
                                                }
                                            }
                                            AllocationBlockUpdateNvSyncStateAllocated::Modified(modified_state) => {
                                                match modified_state {
                                                AllocationBlockUpdateNvSyncStateAllocatedModified::JournalDirty {
                                                    ..
                                                } => {
                                                    // At this point, the transaction should have been applied and there
                                                    // better ought to be no more dirty Allocation Blocks.
                                                    debug_assert!(false);
                                                    read_buffer::ReadBufferAllocationBlockUpdate::Invalidate
                                                }
                                                AllocationBlockUpdateNvSyncStateAllocatedModified::JournalClean {
                                                    cached_encrypted_data,
                                                } => {
                                                    match cached_encrypted_data.take_if(|cached_encrypted_data| {
                                                        cached_encrypted_data.is_authenticated()
                                                    }) {
                                                        Some(cached_encrypted_data) => {
                                                            read_buffer::ReadBufferAllocationBlockUpdate::Update {
                                                                data: cached_encrypted_data.into_encrypted_data(),
                                                            }
                                                        }
                                                        None => {
                                                            read_buffer::ReadBufferAllocationBlockUpdate::Invalidate
                                                        }
                                                    }
                                                }
                                            }
                                            }
                                        }
                                    }
                                }
                            }),
                    );
                }
            }
        }

        // Handle any Allocation Blocks cached as unauthenticated in the ReadBuffer.
        if let Some(buffered_unauthenticated_range) = read_buffer.get_buffered_unauthenticated_range() {
            // Mark any cached Allocation Blocks in the ReadBuffer as deallocated if freed
            // by the transaction. In particular, that drops their cached data,
            // if any.
            for pending_free in transaction_pending_frees.iter_at(buffered_unauthenticated_range.begin()) {
                if pending_free.0 >= buffered_unauthenticated_range.end() {
                    break;
                }
                let (mut cur_allocation_block_index, mut bitmap_word) = if buffered_unauthenticated_range.begin()
                    <= pending_free.0
                {
                    (pending_free.0, pending_free.1)
                } else {
                    (
                        buffered_unauthenticated_range.begin(),
                        pending_free.1
                            >> ((u64::from(buffered_unauthenticated_range.begin()) - u64::from(pending_free.0)) as u32),
                    )
                };

                read_buffer.update_authenticated_buffers(
                    cur_allocation_block_index,
                    iter::from_fn(|| {
                        if cur_allocation_block_index >= buffered_unauthenticated_range.end() {
                            return None;
                        }

                        let update = if bitmap_word & 1 != 0 {
                            read_buffer::ReadBufferAllocationBlockUpdate::Unallocated
                        } else {
                            read_buffer::ReadBufferAllocationBlockUpdate::Retain
                        };

                        bitmap_word >>= 1;
                        cur_allocation_block_index += layout::AllocBlockCount::from(1);

                        Some(update)
                    }),
                );
            }

            // Invalidate any modified Allocation Blocks cached in the ReadBuffer. If the
            // updated data is still available at the transaction, install it in
            // the ReadBuffer.
            if let Ok(mut states_allocation_blocks_index_range) = transaction_update_states
                .lookup_allocation_blocks_update_states_index_range(&buffered_unauthenticated_range)
            {
                while !states_allocation_blocks_index_range.is_empty() {
                    let cur_subrange_states_allocation_blocks_index_range = transaction_update_states
                        .allocation_blocks_range_contiguous_head_subrange(&states_allocation_blocks_index_range);
                    states_allocation_blocks_index_range =
                        AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::new(
                            cur_subrange_states_allocation_blocks_index_range.end(),
                            states_allocation_blocks_index_range.end(),
                        );
                    let cur_subrange_target_allocation_blocks_begin = transaction_update_states
                        .get_allocation_block_target(cur_subrange_states_allocation_blocks_index_range.begin());
                    read_buffer.update_unauthenticated_buffers(
                        cur_subrange_target_allocation_blocks_begin,
                        transaction_update_states
                            .iter_allocation_blocks_mut(Some(&cur_subrange_states_allocation_blocks_index_range))
                            .map(|allocation_block_update_state| {
                                if !matches!(
                                    allocation_block_update_state.1.staged_update,
                                    AllocationBlockUpdateStagedUpdate::None
                                ) {
                                    // At this point, the transaction should have been applied and there
                                    // better ought to be no more staged updates.
                                    debug_assert!(false);
                                    return read_buffer::ReadBufferAllocationBlockUpdate::Invalidate;
                                }
                                match &mut allocation_block_update_state.1.nv_sync_state {
                                    AllocationBlockUpdateNvSyncState::Unallocated(..) => {
                                        read_buffer::ReadBufferAllocationBlockUpdate::Unallocated
                                    }
                                    AllocationBlockUpdateNvSyncState::Allocated(allocated_state) => {
                                        match allocated_state {
                                            AllocationBlockUpdateNvSyncStateAllocated::Unmodified(unmodified_state) => {
                                                match unmodified_state.cached_encrypted_data.take() {
                                                    Some(cached_encrypted_data) => {
                                                        read_buffer::ReadBufferAllocationBlockUpdate::Update {
                                                            data: cached_encrypted_data.into_encrypted_data(),
                                                        }
                                                    }
                                                    None => read_buffer::ReadBufferAllocationBlockUpdate::Retain,
                                                }
                                            }
                                            AllocationBlockUpdateNvSyncStateAllocated::Modified(modified_state) => {
                                                match modified_state {
                                                AllocationBlockUpdateNvSyncStateAllocatedModified::JournalDirty {
                                                    ..
                                                } => {
                                                    // At this point, the transaction should have been applied and there
                                                    // better ought to be no more dirty Allocation Blocks.
                                                    debug_assert!(false);
                                                    read_buffer::ReadBufferAllocationBlockUpdate::Invalidate
                                                }
                                                AllocationBlockUpdateNvSyncStateAllocatedModified::JournalClean {
                                                    cached_encrypted_data,
                                                } => match cached_encrypted_data.take() {
                                                    Some(cached_encrypted_data) => {
                                                        read_buffer::ReadBufferAllocationBlockUpdate::Update {
                                                            data: cached_encrypted_data.into_encrypted_data(),
                                                        }
                                                    }
                                                    None => read_buffer::ReadBufferAllocationBlockUpdate::Invalidate,
                                                },
                                            }
                                            }
                                        }
                                    }
                                }
                            }),
                    );
                }
            }
        }
    }
}

/// Drop a [`Transaction`]'s cached data buffers.
///
/// # Arguments:
///
/// * `transaction_update_states` - `mut` reference to
///   [`Transaction::auth_tree_data_blocks_update_states`].
/// * `update_states_allocation_blocks_index_range` - Optional [Allocation Block
///   level index
///   range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange) in
///   `transaction_update_states` to restrict the operation to.
fn transaction_drop_data_buffers(
    transaction_update_states: &mut AuthTreeDataBlocksUpdateStates,
    update_states_allocation_blocks_index_range: Option<&AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange>,
) {
    for allocation_block_update_state in
        transaction_update_states.iter_allocation_blocks_mut(update_states_allocation_blocks_index_range)
    {
        match &mut allocation_block_update_state.1.nv_sync_state {
            AllocationBlockUpdateNvSyncState::Unallocated(unallocated_state) => {
                unallocated_state.random_fillup = None;
            }
            AllocationBlockUpdateNvSyncState::Allocated(allocated_state) => {
                match allocated_state {
                    AllocationBlockUpdateNvSyncStateAllocated::Unmodified(unmodified_state) => {
                        unmodified_state.cached_encrypted_data = None;
                    }
                    AllocationBlockUpdateNvSyncStateAllocated::Modified(modified_state) => {
                        match modified_state {
                            AllocationBlockUpdateNvSyncStateAllocatedModified::JournalDirty {
                                authenticated_encrypted_data,
                            } => {
                                // At this point, the transaction should have been applied and there
                                // better ought to be no more dirty Allocation Blocks.
                                debug_assert!(false);
                                *authenticated_encrypted_data = Vec::new();
                            }
                            AllocationBlockUpdateNvSyncStateAllocatedModified::JournalClean {
                                cached_encrypted_data,
                            } => {
                                *cached_encrypted_data = None;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Apply the [`Transaction`]'s data writes to their final target storage
/// location.
///
/// Write all modified data within a specified [Allocation Block level index
/// range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange) in the
/// [`Transaction`]'s [storage tracking
/// states](AllocationBlockUpdateNvSyncState) to their associated [target
/// locations](AuthTreeDataBlockUpdateState::get_target_allocation_blocks_begin)
/// on storage.
///
/// Data currently not cached in the [`Transaction`]'s buffers will get read in
/// in the course.
struct TransactionWriteDataUpdatesFuture<C: chip::NvChip> {
    fut_state: TransactionWriteDataUpdatesFutureState<C>,
    remaining_states_allocation_blocks_index_range: AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    low_memory: bool,
}

/// [`TransactionWriteDataUpdatesFuture`] state-machine state.
enum TransactionWriteDataUpdatesFutureState<C: chip::NvChip> {
    Init {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<Transaction>>,
    },
    ReadMissingRegionData {
        cur_region_states_allocation_blocks_index_range: AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        read_missing_data_fut: TransactionReadMissingDataFuture<C>,
    },
    WriteRegion {
        cur_region_states_allocation_blocks_index_range: AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        write_fut: C::WriteFuture<TransactionWriteDataUpdatesNvChipRequest>,
    },
    Done,
}

impl<C: chip::NvChip> TransactionWriteDataUpdatesFuture<C> {
    /// Instantiate [`TransactionWriteDataUpdatesFuture`].
    ///
    /// The [`TransactionWriteDataUpdatesFuture`] assumes
    /// ownership of the `transaction` for the duration of the operation, it
    /// will eventually get returned back from [`poll()`](Self::poll) upon
    /// completion with failure.
    ///
    /// # Arguments:
    ///
    /// * `transaction` - The committing [`Transaction`].
    /// * `states_allocation_blocks_index_range` - The [Allocation Block level
    ///   entry index
    ///   range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange) to
    ///   write updates from the [storage tracking
    ///   states](AllocationBlockUpdateNvSyncState)' to their respective target
    ///   locations in.
    /// * `low_memory` - Whether the system is in a low memory condition.
    /// * `io_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::io_block_allocation_blocks_log2`].
    pub fn new(
        transaction: Box<Transaction>,
        states_allocation_blocks_index_range: &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        low_memory: bool,
        io_block_allocation_blocks_log2: u32,
    ) -> Self {
        let states_allocation_blocks_index_range = transaction
            .auth_tree_data_blocks_update_states
            .extend_states_allocation_blocks_index_range_within_alignment(
                states_allocation_blocks_index_range,
                io_block_allocation_blocks_log2,
            );
        Self {
            fut_state: TransactionWriteDataUpdatesFutureState::Init {
                transaction: Some(transaction),
            },
            remaining_states_allocation_blocks_index_range: states_allocation_blocks_index_range,
            low_memory,
        }
    }

    /// Poll the [`TransactionWriteDataUpdatesFuture`] to completion.
    ///
    /// A two-level [`Result`] is returned upon
    /// [future](TransactionWriteDataUpdatesFuture) completion.
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering an internal error and the [`Transaction`] is lost.
    /// * `Ok((transaction, ...))` - Otherwise the outer level [`Result`] is set
    ///   to [`Ok`] and a pair of the input [`Transaction`], `transaction`, and
    ///   the operation result will get returned within:
    ///     * `Ok((transaction, Err(e)))` - In case of an error, the error
    ///       reason `e` is returned in an [`Err`].
    ///     * `Ok((transaction, Ok(())))` -  Otherwise, `Ok(())` will get
    ///       returned for the operation result on success.
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
        fs_instance_sync_state: CocoonFsSyncStateMemberMutRef<'_, ST, C>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(Box<Transaction>, Result<(), NvFsError>), NvFsError>> {
        let this = pin::Pin::into_inner(self);
        loop {
            match &mut this.fut_state {
                TransactionWriteDataUpdatesFutureState::Init { transaction } => {
                    let transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => {
                            this.fut_state = TransactionWriteDataUpdatesFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    let fs_instance = fs_instance_sync_state.get_fs_ref();
                    let fs_config = &fs_instance.fs_config;
                    let image_layout = &fs_config.image_layout;
                    let (
                        cur_write_region_states_allocation_blocks_index_range,
                        remaining_states_allocation_blocks_index_range,
                    ) = match Self::determine_next_write_region(
                        &transaction,
                        &this.remaining_states_allocation_blocks_index_range,
                        this.low_memory,
                        image_layout.io_block_allocation_blocks_log2 as u32,
                        image_layout.auth_tree_data_block_allocation_blocks_log2 as u32,
                    ) {
                        Ok((
                            next_write_region_states_allocation_blocks_index_range,
                            remaining_states_allocation_blocks_index_range,
                        )) => (
                            next_write_region_states_allocation_blocks_index_range,
                            remaining_states_allocation_blocks_index_range,
                        ),
                        Err(e) => {
                            this.fut_state = TransactionWriteDataUpdatesFutureState::Done;
                            return task::Poll::Ready(Ok((transaction, Err(e))));
                        }
                    };

                    this.remaining_states_allocation_blocks_index_range =
                        remaining_states_allocation_blocks_index_range;
                    let cur_write_region_states_allocation_blocks_index_range =
                        match cur_write_region_states_allocation_blocks_index_range {
                            Some(cur_write_region_states_allocation_blocks_index_range) => {
                                cur_write_region_states_allocation_blocks_index_range
                            }
                            None => {
                                this.fut_state = TransactionWriteDataUpdatesFutureState::Done;
                                return task::Poll::Ready(Ok((transaction, Ok(()))));
                            }
                        };

                    let read_missing_data_fut = match TransactionReadMissingDataFuture::new(
                        transaction,
                        &cur_write_region_states_allocation_blocks_index_range,
                    ) {
                        Ok(read_missing_data_fut) => read_missing_data_fut,
                        Err((transaction, e)) => {
                            this.fut_state = TransactionWriteDataUpdatesFutureState::Done;
                            return task::Poll::Ready(Ok((transaction, Err(e))));
                        }
                    };
                    this.fut_state = TransactionWriteDataUpdatesFutureState::ReadMissingRegionData {
                        cur_region_states_allocation_blocks_index_range:
                            cur_write_region_states_allocation_blocks_index_range,
                        read_missing_data_fut,
                    };
                }
                TransactionWriteDataUpdatesFutureState::ReadMissingRegionData {
                    cur_region_states_allocation_blocks_index_range,
                    read_missing_data_fut,
                } => {
                    let fs_instance = fs_instance_sync_state.get_fs_ref();
                    let transaction = match TransactionReadMissingDataFuture::poll(
                        pin::Pin::new(read_missing_data_fut),
                        &fs_instance.chip,
                        &fs_instance_sync_state.alloc_bitmap,
                        cx,
                    ) {
                        task::Poll::Ready(Ok((
                            transaction,
                            cur_write_region_states_allocation_blocks_index_range_offsets,
                            Ok(()),
                        ))) => {
                            if cur_write_region_states_allocation_blocks_index_range_offsets.is_some() {
                                // No alignment gaps should have been filled, it is assumed that
                                // everything's aligned to the IO block size already at this stage.
                                this.fut_state = TransactionWriteDataUpdatesFutureState::Done;
                                return task::Poll::Ready(Ok((transaction, Err(nvfs_err_internal!()))));
                            }
                            transaction
                        }
                        task::Poll::Ready(Ok((transaction, _, Err(e)))) => {
                            this.fut_state = TransactionWriteDataUpdatesFutureState::Done;
                            return task::Poll::Ready(Ok((transaction, Err(e))));
                        }
                        task::Poll::Ready(Err(e)) => {
                            this.fut_state = TransactionWriteDataUpdatesFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let image_layout = &fs_instance.fs_config.image_layout;
                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                    let target_range = transaction
                        .auth_tree_data_blocks_update_states
                        .get_contiguous_region_target_range(cur_region_states_allocation_blocks_index_range);
                    let target_range_begin_128b = u64::from(target_range.begin()) << allocation_block_size_128b_log2;
                    let target_range_end_128b = u64::from(target_range.end()) << allocation_block_size_128b_log2;
                    let write_request_io_region = match ChunkedIoRegion::new(
                        target_range_begin_128b,
                        target_range_end_128b,
                        allocation_block_size_128b_log2,
                    ) {
                        Ok(write_request_io_region) => write_request_io_region,
                        Err(e) => {
                            let e = match e {
                                ChunkedIoRegionError::ChunkSizeOverflow | ChunkedIoRegionError::ChunkIndexOverflow => {
                                    NvFsError::DimensionsNotSupported
                                }
                                ChunkedIoRegionError::InvalidBounds | ChunkedIoRegionError::RegionUnaligned => {
                                    nvfs_err_internal!()
                                }
                            };
                            this.fut_state = TransactionWriteDataUpdatesFutureState::Done;
                            return task::Poll::Ready(Ok((transaction, Err(e))));
                        }
                    };
                    let write_request = TransactionWriteDataUpdatesNvChipRequest {
                        transaction,
                        aligned_write_region_states_allocation_blocks_index_range:
                            cur_region_states_allocation_blocks_index_range.clone(),
                        request_io_region: write_request_io_region,
                    };
                    let write_fut = match fs_instance.chip.write(write_request) {
                        Ok(Ok(write_fut)) => write_fut,
                        Ok(Err((write_request, e))) => {
                            let TransactionWriteDataUpdatesNvChipRequest { transaction, .. } = write_request;
                            this.fut_state = TransactionWriteDataUpdatesFutureState::Done;
                            return task::Poll::Ready(Ok((transaction, Err(NvFsError::from(e)))));
                        }
                        Err(e) => {
                            this.fut_state = TransactionWriteDataUpdatesFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    this.fut_state = TransactionWriteDataUpdatesFutureState::WriteRegion {
                        cur_region_states_allocation_blocks_index_range:
                            cur_region_states_allocation_blocks_index_range.clone(),
                        write_fut,
                    };
                }
                TransactionWriteDataUpdatesFutureState::WriteRegion {
                    cur_region_states_allocation_blocks_index_range,
                    write_fut,
                } => {
                    let fs_instance = fs_instance_sync_state.get_fs_ref();
                    let mut transaction =
                        match chip::NvChipFuture::poll(pin::Pin::new(write_fut), &fs_instance.chip, cx) {
                            task::Poll::Ready(Ok((write_request, Ok(())))) => {
                                let TransactionWriteDataUpdatesNvChipRequest { transaction, .. } = write_request;
                                transaction
                            }
                            task::Poll::Ready(Ok((write_request, Err(e)))) => {
                                let TransactionWriteDataUpdatesNvChipRequest { transaction, .. } = write_request;
                                this.fut_state = TransactionWriteDataUpdatesFutureState::Done;
                                return task::Poll::Ready(Ok((transaction, Err(NvFsError::from(e)))));
                            }
                            task::Poll::Ready(Err(e)) => {
                                this.fut_state = TransactionWriteDataUpdatesFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(e)));
                            }
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    // If in a low memory condition, drop all data buffers just written out.
                    if this.low_memory {
                        transaction_drop_data_buffers(
                            &mut transaction.auth_tree_data_blocks_update_states,
                            Some(cur_region_states_allocation_blocks_index_range),
                        );
                    }

                    this.fut_state = TransactionWriteDataUpdatesFutureState::Init {
                        transaction: Some(transaction),
                    };
                }
                TransactionWriteDataUpdatesFutureState::Done => unreachable!(),
            }
        }
    }

    /// Determine the next subrange to write.
    ///
    /// Return a pair of the next subrange to write, if any, and the remainder
    /// of `remaining_states_allocation_blocks_index_range` to process in a
    /// subsequent iteration.
    ///
    /// # Arguments:
    ///
    /// * `transaction` - The committing [`Transaction`].
    /// * `remaining_states_allocation_blocks_index_range` - Remaining part of
    ///   the initial request range not processed yet, extended to cover any
    ///   preexisting states within the vicinity of a [IO
    ///   Block](ImageLayout::io_block_allocation_blocks_log2) size as
    ///   specified by `io_block_allocation_blocks_log2`.
    /// * `low_memory` - Whether the system is in a low memory condition.
    /// * `io_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::io_block_allocation_blocks_log2`].
    /// * `auth_tree_data_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::auth_tree_data_block_allocation_blocks_log2`].
    fn determine_next_write_region(
        transaction: &Transaction,
        remaining_states_allocation_blocks_index_range: &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        low_memory: bool,
        io_block_allocation_blocks_log2: u32,
        auth_tree_data_block_allocation_blocks_log2: u32,
    ) -> Result<
        (
            Option<AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange>,
            AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        ),
        NvFsError,
    > {
        if remaining_states_allocation_blocks_index_range.is_empty() {
            return Ok((None, remaining_states_allocation_blocks_index_range.clone()));
        }

        let allocation_block_size_128b_log2 = transaction.allocation_block_size_128b_log2 as u32;
        let chip_io_block_size_128b_log2 = transaction.chip_io_block_size_128b_log2;
        let preferred_chip_io_blocks_bulk_log2 = transaction.preferred_chip_io_blocks_bulk_log2;
        // Ramp it up to some reasonable value. Note that the subsequent code relies on
        // always writing multiples of an IO Block. In low memory conditions it would
        // even be better to write the absolute minimum of a single Chip IO
        // block at a time, but that would further complicate the logic.
        let preferred_write_allocation_blocks_log2 = if !low_memory {
            (preferred_chip_io_blocks_bulk_log2 + chip_io_block_size_128b_log2)
                .saturating_sub(allocation_block_size_128b_log2)
                .min(usize::BITS - 1)
                .max(auth_tree_data_block_allocation_blocks_log2)
        } else {
            0
        }
        .max(io_block_allocation_blocks_log2);
        let io_block_allocation_blocks = layout::AllocBlockCount::from(1u64 << io_block_allocation_blocks_log2);

        let update_states = &transaction.auth_tree_data_blocks_update_states;
        let mut remaining_states_allocation_blocks_index_range = remaining_states_allocation_blocks_index_range.clone();
        let mut cur_states_allocation_block_index = *remaining_states_allocation_blocks_index_range.begin();
        let mut write_region_states_allocation_blocks_index_range_end = None;
        // Initialize to make compilers happy.
        let mut last_io_block_target_allocation_blocks_begin = layout::PhysicalAllocBlockIndex::from(0u64);
        loop {
            let cur_io_block_target_allocation_blocks_begin =
                update_states.get_allocation_block_target(&cur_states_allocation_block_index);
            if write_region_states_allocation_blocks_index_range_end.is_some()
                && (u64::from(
                    cur_io_block_target_allocation_blocks_begin - last_io_block_target_allocation_blocks_begin,
                ) >> io_block_allocation_blocks_log2
                    != 1
                    || (u64::from(cur_io_block_target_allocation_blocks_begin)
                        ^ u64::from(last_io_block_target_allocation_blocks_begin))
                        >> preferred_write_allocation_blocks_log2
                        != 0)
            {
                // Something's been found already and either the range cannot get contiguously
                // extented or we're crossing a preferred block boundary. Stop for now and
                // process everything up to this point.
                break;
            }
            last_io_block_target_allocation_blocks_begin = cur_io_block_target_allocation_blocks_begin;

            let cur_io_block_states_allocation_blocks_index_range_end = cur_states_allocation_block_index
                .advance(io_block_allocation_blocks, auth_tree_data_block_allocation_blocks_log2);
            // All IO block alignment gaps in the update states should have been filled by
            // now.
            if usize::from(AuthTreeDataBlocksUpdateStatesIndex::from(
                cur_io_block_states_allocation_blocks_index_range_end,
            )) > update_states.len()
            {
                return Err(nvfs_err_internal!());
            }
            let cur_io_block_states_allocation_block_index_range =
                AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::new(
                    &cur_states_allocation_block_index,
                    &cur_io_block_states_allocation_blocks_index_range_end,
                );
            // All IO block alignment gaps in the update states should have been filled by
            // now.
            if !update_states.is_contiguous_aligned_allocation_blocks_region(
                &cur_io_block_states_allocation_block_index_range,
                io_block_allocation_blocks_log2,
            ) {
                return Err(nvfs_err_internal!());
            }

            let io_block_written_in_place = update_states
                .get_allocation_block_journal_staging_copy(&cur_states_allocation_block_index)
                .map(|cur_io_block_journal_staging_copy_allocation_blocks_begin| {
                    cur_io_block_journal_staging_copy_allocation_blocks_begin
                        == cur_io_block_target_allocation_blocks_begin
                })
                .unwrap_or(false);

            let cur_io_block_needs_write = !io_block_written_in_place
                && cur_io_block_states_allocation_block_index_range
                    .iter(auth_tree_data_block_allocation_blocks_log2)
                    .any(|cur_states_allocation_block_index| {
                        update_states[cur_states_allocation_block_index].has_modified_data()
                    });
            if cur_io_block_needs_write {
                write_region_states_allocation_blocks_index_range_end =
                    Some(cur_io_block_states_allocation_blocks_index_range_end);
            } else if write_region_states_allocation_blocks_index_range_end.is_none() {
                // No write region found yet, advance the remaining
                // region's beginning to the current position.
                remaining_states_allocation_blocks_index_range =
                    AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::new(
                        &cur_io_block_states_allocation_blocks_index_range_end,
                        remaining_states_allocation_blocks_index_range.end(),
                    );
            }

            cur_states_allocation_block_index = cur_io_block_states_allocation_blocks_index_range_end;
            if usize::from(AuthTreeDataBlocksUpdateStatesIndex::from(
                cur_io_block_states_allocation_blocks_index_range_end,
            )) == update_states.len()
            {
                break;
            }
        }

        if let Some(write_region_states_allocation_blocks_index_range_end) =
            write_region_states_allocation_blocks_index_range_end
        {
            let write_region_states_allocation_blocks_index_range_begin =
                remaining_states_allocation_blocks_index_range.begin();
            debug_assert!(write_region_states_allocation_blocks_index_range_end <= cur_states_allocation_block_index);
            Ok((
                Some(AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::new(
                    write_region_states_allocation_blocks_index_range_begin,
                    &write_region_states_allocation_blocks_index_range_end,
                )),
                AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::new(
                    &cur_states_allocation_block_index,
                    remaining_states_allocation_blocks_index_range.end(),
                ),
            ))
        } else {
            Ok((
                None,
                AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::new(
                    remaining_states_allocation_blocks_index_range.end(),
                    remaining_states_allocation_blocks_index_range.end(),
                ),
            ))
        }
    }
}

/// [`NvChipWriteRequest`](chip::NvChipWriteRequest) implementation used
/// internally by [`TransactionWriteDataUpdatesFuture`].
struct TransactionWriteDataUpdatesNvChipRequest {
    transaction: Box<Transaction>,
    aligned_write_region_states_allocation_blocks_index_range: AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    request_io_region: ChunkedIoRegion,
}

impl chip::NvChipWriteRequest for TransactionWriteDataUpdatesNvChipRequest {
    fn region(&self) -> &ChunkedIoRegion {
        &self.request_io_region
    }

    fn get_source_buffer(&self, range: &ChunkedIoRegionChunkRange) -> Result<&[u8], chip::NvChipIoError> {
        let (allocation_block_index_in_request, _) = range.chunk().decompose_to_hierarchic_indices([]);

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
                .ok_or(chip::NvChipIoError::Internal)?,
            AllocationBlockUpdateNvSyncState::Allocated(allocated_state) => match allocated_state {
                AllocationBlockUpdateNvSyncStateAllocated::Unmodified(unmodified_state) => unmodified_state
                    .cached_encrypted_data
                    .as_ref()
                    .map(|cached_encrypted_data| cached_encrypted_data.get_encrypted_data())
                    .ok_or(chip::NvChipIoError::Internal)?,
                AllocationBlockUpdateNvSyncStateAllocated::Modified(modified_state) => match modified_state {
                    AllocationBlockUpdateNvSyncStateAllocatedModified::JournalDirty {
                        authenticated_encrypted_data,
                    } => authenticated_encrypted_data,
                    AllocationBlockUpdateNvSyncStateAllocatedModified::JournalClean { cached_encrypted_data } => {
                        cached_encrypted_data
                            .as_ref()
                            .map(|cached_encrypted_data| cached_encrypted_data.get_encrypted_data())
                            .ok_or(chip::NvChipIoError::Internal)?
                    }
                },
            },
        };

        Ok(&src_allocation_block_buffer[range.range_in_chunk().clone()])
    }
}

/// [Trim](chip::NvChip::trim) [IO
/// Blocks](ImageLayout::io_block_allocation_blocks_log2) that became
/// fully unallocated with a [`Transaction`].
struct TransactionTrimDeallocatedIoBlocksFuture<C: chip::NvChip> {
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
    // reference on Self.
    transaction: Option<Box<Transaction>>,
    next_io_block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
    fut_state: TransactionTrimDeallocatedIoBlocksFutureState<C>,
}

/// [`TransactionTrimDeallocatedIoBlocksFuture`] state-machine state.
enum TransactionTrimDeallocatedIoBlocksFutureState<C: chip::NvChip> {
    Init,
    TrimRegion { trim_fut: C::TrimFuture },
}

impl<C: chip::NvChip> TransactionTrimDeallocatedIoBlocksFuture<C> {
    /// Instantiate a [`TransactionTrimDeallocatedIoBlocksFuture`].
    ///
    /// The [`TransactionTrimDeallocatedIoBlocksFuture`] assumes
    /// ownership of the `transaction` for the duration of the operation, it
    /// will eventually get returned back from [`poll()`](Self::poll) upon
    /// successful completion.
    ///
    /// # Arguments:
    ///
    /// * `transaction` - The committing [`Transaction`].
    pub fn new(transaction: Box<Transaction>) -> Self {
        Self {
            transaction: Some(transaction),
            next_io_block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex::from(0u64),
            fut_state: TransactionTrimDeallocatedIoBlocksFutureState::Init,
        }
    }

    /// Poll the [`TransactionTrimDeallocatedIoBlocksFuture`] to completion.
    ///
    /// Upon successful [future](TransactionTrimDeallocatedIoBlocksFuture)
    /// completion, the [`Transaction`] initially passed to [`new()`](Self::new)
    /// is returned back. Otherwise, on error, the [`Transaction`] is
    /// consumed and the error reason is returned.
    ///
    /// # Arguments:
    ///
    /// * `fs_instance_sync_state` - Exclusive reference to
    ///   [`CocoonFs::sync_state`](crate::fs::cocoonfs::fs::CocoonFs::sync_state).
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    pub fn poll<ST: sync_types::SyncTypes>(
        self: pin::Pin<&mut Self>,
        fs_instance_sync_state: CocoonFsSyncStateMemberMutRef<'_, ST, C>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<Box<Transaction>, NvFsError>> {
        let this = pin::Pin::into_inner(self);
        let transaction = match this.transaction.take() {
            Some(transaction) => transaction,
            None => return task::Poll::Ready(Err(nvfs_err_internal!())),
        };

        let fs_instance = fs_instance_sync_state.get_fs_ref();
        let image_layout = &fs_instance.fs_config.image_layout;
        let io_block_allocation_blocks_log2 = image_layout.io_block_allocation_blocks_log2 as u32;
        let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
        let chip_io_block_size_128b_log2 = fs_instance.chip.chip_io_block_size_128b_log2();
        if chip_io_block_size_128b_log2 > io_block_allocation_blocks_log2 + allocation_block_size_128b_log2 {
            // Failure to trim is considered non-fatal.
            return task::Poll::Ready(Ok(transaction));
        }
        let chip_io_block_allocation_blocks_log2 =
            chip_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);
        let allocation_block_chip_io_blocks_log2 =
            allocation_block_size_128b_log2.saturating_sub(chip_io_block_size_128b_log2);

        loop {
            match &mut this.fut_state {
                TransactionTrimDeallocatedIoBlocksFutureState::Init => {
                    let next_trim_region = match Self::determine_next_trim_region(
                        &fs_instance_sync_state.alloc_bitmap,
                        &transaction.allocs.pending_frees,
                        this.next_io_block_allocation_blocks_begin,
                        io_block_allocation_blocks_log2,
                    ) {
                        Some(next_trim_region) => next_trim_region,
                        None => return task::Poll::Ready(Ok(transaction)),
                    };
                    // The IO Block immediately following the trim region doesn't need trimming,
                    // skip over it.
                    this.next_io_block_allocation_blocks_begin =
                        next_trim_region.end() + layout::AllocBlockCount::from(1u64 << io_block_allocation_blocks_log2);

                    let trim_region_chip_io_blocks_begin = u64::from(next_trim_region.begin())
                        >> chip_io_block_allocation_blocks_log2
                        << allocation_block_chip_io_blocks_log2;
                    let trim_region_chip_io_blocks_count = u64::from(next_trim_region.block_count())
                        >> chip_io_block_allocation_blocks_log2
                        << allocation_block_chip_io_blocks_log2;
                    let trim_fut = match fs_instance
                        .chip
                        .trim(trim_region_chip_io_blocks_begin, trim_region_chip_io_blocks_count)
                    {
                        Ok(trim_fut) => trim_fut,
                        Err(_) => {
                            // Failure to trim is considered non-fatal, simply proceed to the next region,
                            // if any.
                            continue;
                        }
                    };
                    this.fut_state = TransactionTrimDeallocatedIoBlocksFutureState::TrimRegion { trim_fut };
                }
                TransactionTrimDeallocatedIoBlocksFutureState::TrimRegion { trim_fut } => {
                    match chip::NvChipFuture::poll(pin::Pin::new(trim_fut), &fs_instance.chip, cx) {
                        task::Poll::Ready(Ok(_)) | task::Poll::Ready(Err(_)) => {
                            // Failure to trim is considered non-fatal. So
                            // proceed to the next
                            // region without even examining the result.
                        }
                        task::Poll::Pending => {
                            // Put the transaction back for the next poll invocation.
                            this.transaction = Some(transaction);
                            return task::Poll::Pending;
                        }
                    }

                    this.fut_state = TransactionTrimDeallocatedIoBlocksFutureState::Init;
                }
            }
        }
    }

    /// Determine the next region to trim.
    ///
    /// Return the next region on physical storage to trim, if any.
    ///
    /// # Arguments:
    ///
    /// * `fs_sync_state_alloc_bitmap` - The [filesystem instance's allocation
    ///   bitmap](crate::fs::cocoonfs::fs::CocoonFsSyncState::alloc_bitmap).
    /// * `transaction_pending_frees` - Reference to the
    ///   [`Transaction::allocs`]'
    ///   [`TransactionAllocations::pending_frees`](super::TransactionAllocations::pending_frees).
    /// * `next_io_block_allocation_blocks_begin` - The current position on
    ///   storage.
    /// * `io_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::io_block_allocation_blocks_log2`].
    fn determine_next_trim_region(
        fs_sync_state_alloc_bitmap: &alloc_bitmap::AllocBitmap,
        transaction_pending_frees: &alloc_bitmap::SparseAllocBitmap,
        next_io_block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        io_block_allocation_blocks_log2: u32,
    ) -> Option<layout::PhysicalAllocBlockRange> {
        let io_block_allocation_blocks = 1u32 << io_block_allocation_blocks_log2;

        // Find the next IO block that becomes fully free due to deallocations from the
        // transaction.
        let mut transaction_pending_frees_iter = transaction_pending_frees
            .block_iter_at(next_io_block_allocation_blocks_begin, io_block_allocation_blocks_log2);
        let empty_sparse_alloc_bitmap = alloc_bitmap::SparseAllocBitmapUnion::new(&[]);
        let (region_allocation_blocks_begin, mut alloc_bitmap_io_block_iter) = loop {
            let pending_free = transaction_pending_frees_iter.next()?;
            let mut alloc_bitmap_io_block_iter = fs_sync_state_alloc_bitmap.iter_chunked_at_allocation_block(
                &empty_sparse_alloc_bitmap,
                &empty_sparse_alloc_bitmap,
                pending_free.0,
                io_block_allocation_blocks,
            );
            let io_block_alloc_bitmap_word = alloc_bitmap_io_block_iter.next().unwrap_or(0);
            if io_block_alloc_bitmap_word & !pending_free.1 == 0 {
                // The complete IO block became free.
                break (pending_free.0, alloc_bitmap_io_block_iter);
            }
        };

        // Extend the region until there's a gap.
        let mut region_allocation_blocks = io_block_allocation_blocks as u64;
        let mut last_io_block_allocation_blocks_begin = region_allocation_blocks_begin;
        for next_pending_free in transaction_pending_frees_iter {
            if next_pending_free.0 - last_io_block_allocation_blocks_begin
                != layout::AllocBlockCount::from(io_block_allocation_blocks as u64)
            {
                break;
            }
            let io_block_alloc_bitmap_word = alloc_bitmap_io_block_iter.next().unwrap_or(0);
            if io_block_alloc_bitmap_word & !next_pending_free.1 != 0 {
                break;
            }

            region_allocation_blocks += io_block_allocation_blocks as u64;
            last_io_block_allocation_blocks_begin = next_pending_free.0;
        }

        Some(layout::PhysicalAllocBlockRange::from((
            region_allocation_blocks_begin,
            layout::AllocBlockCount::from(region_allocation_blocks),
        )))
    }
}
