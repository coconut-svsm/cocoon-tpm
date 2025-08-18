// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`TransactionWriteJournalFuture`].

extern crate alloc;
use super::{
    Transaction,
    auth_tree_data_blocks_update_states::{
        self, AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange, AuthTreeDataBlocksUpdateStatesIndex,
        AuthTreeDataBlocksUpdateStatesIndexRange,
    },
    auth_tree_updates::{
        TransactionAuthTreeDataBlocksDigestsUpdatesIterator, TransactionJournalUpdateAuthDigestsScriptIterator,
    },
    journal_allocations::{TransactionAllocateJournalExtentsFuture, TransactionAllocateJournalStagingCopiesFuture},
    prepare_staged_updates_application::TransactionPrepareStagedUpdatesApplicationFuture,
    write_dirty_data::TransactionWriteDirtyDataFuture,
};
use crate::{
    chip::{self, ChunkedIoRegion, ChunkedIoRegionChunkRange},
    crypto::hash,
    fs::{
        NvFsError,
        cocoonfs::{
            CocoonFsFormatError, alloc_bitmap, auth_tree,
            encryption_entities::EncryptedChainedExtentsAssociatedDataAuthSubjectDataSuffix,
            extents,
            fs::{
                CocoonFsPendingTransactionsSyncState, CocoonFsSyncStateMemberMutRef, CocoonFsSyncStateMemberRef,
                CocoonFsSyncStateReadFuture,
            },
            image_header, inode_index, journal,
            layout::{self, BlockCount as _},
            leb128, transaction,
        },
    },
    nvfs_err_internal,
    utils_async::sync_types,
    utils_common::{
        fixed_vec::FixedVec,
        io_slices::{self, IoSlicesIterCommon as _, PeekableIoSlicesIter as _},
        zeroize,
    },
};
use alloc::boxed::Box;
use core::{mem, pin, task};

#[cfg(doc)]
use crate::fs::cocoonfs::fs::CocoonFs;
#[cfg(doc)]
use journal::extents_covering_auth_digests::ExtentsCoveringAuthDigests;

/// Write the journal for a to be committed [`Transaction`].
pub struct TransactionWriteJournalFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    fut_state: TransactionWriteJournalFutureState<ST, C>,
    encoded_alloc_bitmap_file_auth_digests_for_auth_tree_reconstruction: FixedVec<u8, 0>,
    issue_sync: bool,
}

/// [`TransactionWriteJournalFuture`] state-machine state.
enum TransactionWriteJournalFutureState<ST: sync_types::SyncTypes, C: chip::NvChip> {
    Init {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<Transaction>>,
    },
    InodeIndexApplyStagedUpdates {
        update_root_inode_fut: inode_index::InodeIndexUpdateRootNodeInodeFuture<ST, C>,
    },
    Canonicalize {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<Transaction>>,
    },
    UpdateStatesApplyStagedUpdates {
        prepare_staged_updates_application_fut: TransactionPrepareStagedUpdatesApplicationFuture<ST, C>,
    },
    AllocateJournalStagingCopies {
        allocate_journal_staging_copies_fut: TransactionAllocateJournalStagingCopiesFuture<ST, C>,
    },
    UpdateStatesWriteDirtyData {
        write_dirty_data_fut: TransactionWriteDirtyDataFuture<ST, C>,
    },
    CollectAllocBitmapFileAuthDigestsForAuthTreeReconstruction {
        collect_auth_digests_fut: TransactionCollectExtentsCoveringAuthDigestsFuture<C>,
    },
    PrepareAuthTreeUpdates {
        prepare_auth_tree_updates_fut:
            auth_tree::AuthTreePrepareUpdatesFuture<ST, C, TransactionAuthTreeDataBlocksDigestsUpdatesIterator<ST, C>>,
    },
    WriteHeaderUpdates {
        write_dirty_data_fut: TransactionWriteDirtyDataFuture<ST, C>,
    },
    AllocateJournalLog {
        allocate_fut: TransactionAllocateJournalExtentsFuture<ST, C>,
        journal_log_head_extent: layout::PhysicalAllocBlockRange,
        journal_log_encode_buf_layout: journal::log::JournalLogEncodeBufferLayout,
    },
    PrepareJournalLog {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<Transaction>>,
        journal_log_head_extent: layout::PhysicalAllocBlockRange,
        journal_log_encode_buf_layout: journal::log::JournalLogEncodeBufferLayout,
    },
    PrepareWriteJournalLogTailExtent {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<Transaction>>,
        journal_log_head_extent: layout::PhysicalAllocBlockRange,
        journal_log_head_extent_buf: FixedVec<u8, 7>,
        journal_log_tail_extents_bufs: FixedVec<FixedVec<u8, 7>, 0>,
        next_tail_extent_index: usize,
    },
    WriteJournalLogTailExtent {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<Transaction>>,
        journal_log_head_extent: layout::PhysicalAllocBlockRange,
        journal_log_head_extent_buf: FixedVec<u8, 7>,
        journal_log_tail_extents_bufs: FixedVec<FixedVec<u8, 7>, 0>,
        cur_tail_extent_index: usize,
        write_extent_fut: C::WriteFuture<WriteJournalLogExtentChipRequest>,
    },
    WriteBarrierBeforeJournalLogHeadWrite {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<Transaction>>,
        journal_log_head_extent: layout::PhysicalAllocBlockRange,
        journal_log_head_extent_buf: FixedVec<u8, 7>,
        write_barrier_fut: C::WriteBarrierFuture,
    },
    WriteJournalLogHeadExtent {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<Transaction>>,
        write_extent_fut: C::WriteFuture<WriteJournalLogExtentChipRequest>,
    },
    WriteSyncAfterJournalLogHeadWrite {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<Transaction>>,
        write_sync_fut: C::WriteSyncFuture,
    },
    WriteBarrierAfterJournalLogHeadWrite {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<Transaction>>,
        write_barrier_fut: C::WriteBarrierFuture,
    },

    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> TransactionWriteJournalFuture<ST, C> {
    /// Instantiate a [`TransactionWriteJournalFuture`].
    ///
    /// The [`TransactionWriteJournalFuture`] assumes
    /// ownership of the `transaction` for the duration of the operation, it
    /// will eventually get returned back from [`poll()`](Self::poll) upon
    /// completion.
    ///
    /// # Arguments:
    ///
    /// * `transaction` - The committing [`Transaction`].
    /// * `issue_sync` - Whether or not to submit a [synchronization
    ///   barrier](chip::NvChip::write_sync) to the backing storage after the
    ///   journal has been written.
    /// * `_fs_instance_sync_state` - Reference to [`CocoonFs::sync_state`].
    /// * `accumulated_pending_transactions_sync_state` - The accumulated
    ///   [`CocoonFsPendingTransactionsSyncState`] taken from
    ///   [`CocoonFs::pending_transactions_sync_state`] upon starting the commit
    ///   process for `transaction`.
    pub fn new(
        mut transaction: Box<Transaction>,
        issue_sync: bool,
        _fs_instance_sync_state: CocoonFsSyncStateMemberMutRef<'_, ST, C>,
        accumulated_pending_transactions_sync_state: CocoonFsPendingTransactionsSyncState,
    ) -> Result<Self, (Box<Transaction>, NvFsError)> {
        transaction.accumulated_fs_instance_pending_transactions_sync_state =
            accumulated_pending_transactions_sync_state;

        // Check if there's any staged update in a failed state, meaning
        // some prior update staging operation failed and it hasn't got rectified.
        if transaction
            .auth_tree_data_blocks_update_states
            .iter_allocation_blocks(None)
            .any(|allocation_block_update_state| {
                matches!(
                    allocation_block_update_state.1.staged_update,
                    auth_tree_data_blocks_update_states::AllocationBlockUpdateStagedUpdate::FailedUpdate
                )
            })
        {
            return Err((transaction, NvFsError::FailedDataUpdateRead));
        }

        Ok(Self {
            fut_state: TransactionWriteJournalFutureState::Init {
                transaction: Some(transaction),
            },
            encoded_alloc_bitmap_file_auth_digests_for_auth_tree_reconstruction: FixedVec::new_empty(),
            issue_sync,
        })
    }

    /// Poll the [`TransactionWriteJournalFuture`] to completion.
    ///
    /// On successful completion, the input [`Transaction`] is returned back. On
    /// error, a triplet consisting of a `bool` indicating whether the
    /// journal is in an indeterminate state and might or might not be
    /// effective at a subsequent filesystem opening operation, the input
    /// [`Transaction`] if still available and the error reason is being
    /// returned.
    ///
    /// # Arguments:
    ///
    /// * `fs_instance_sync_state` - Exclusive reference to
    ///   [`CocoonFs::sync_state`].
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    #[allow(clippy::type_complexity)]
    pub fn poll(
        self: pin::Pin<&mut Self>,
        mut fs_instance_sync_state: CocoonFsSyncStateMemberMutRef<'_, ST, C>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<Box<Transaction>, (bool, Option<Box<Transaction>>, NvFsError)>> {
        let this = pin::Pin::into_inner(self);

        let (need_journal_abort, transaction, e) = 'outer: loop {
            match &mut this.fut_state {
                TransactionWriteJournalFutureState::Init { transaction } => {
                    let mut transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => break (false, None, nvfs_err_internal!()),
                    };

                    transaction
                        .accumulated_fs_instance_pending_transactions_sync_state
                        .pending_allocs
                        .subtract(&transaction.allocs.pending_allocs);
                    transaction
                        .accumulated_fs_instance_pending_transactions_sync_state
                        .pending_allocs
                        .subtract(&transaction.allocs.journal_allocs);

                    this.fut_state = TransactionWriteJournalFutureState::InodeIndexApplyStagedUpdates {
                        update_root_inode_fut: inode_index::InodeIndexUpdateRootNodeInodeFuture::new(transaction),
                    };
                }
                TransactionWriteJournalFutureState::InodeIndexApplyStagedUpdates { update_root_inode_fut } => {
                    let mut transaction = match CocoonFsSyncStateReadFuture::poll(
                        pin::Pin::new(update_root_inode_fut),
                        &mut CocoonFsSyncStateMemberRef::from(&mut fs_instance_sync_state),
                        &mut (),
                        cx,
                    ) {
                        task::Poll::Ready(Ok((transaction, Ok(())))) => transaction,
                        task::Poll::Ready(Ok((transaction, Err(e)))) => break (false, Some(transaction), e),
                        task::Poll::Ready(Err(e)) => break (false, None, e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let mut fs_instance_sync_state = CocoonFsSyncStateMemberRef::from(&mut fs_instance_sync_state);
                    let (
                        fs_instance,
                        _fs_sync_state_image_size,
                        fs_sync_state_alloc_bitmap,
                        _fs_sync_state_alloc_bitmap_file,
                        _fs_sync_state_auth_tree,
                        fs_sync_state_inode_index,
                        _fs_sync_state_read_buffer,
                        mut fs_sync_state_keys_cache,
                    ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();

                    if let Err(e) = transaction.inode_index_updates.apply_all_tree_nodes_staged_updates(
                        &transaction.allocs,
                        &mut transaction.auth_tree_data_blocks_update_states,
                        transaction.rng.as_mut(),
                        &fs_instance.fs_config,
                        fs_sync_state_alloc_bitmap,
                        fs_sync_state_inode_index,
                        &mut fs_sync_state_keys_cache,
                    ) {
                        break (false, Some(transaction), e);
                    }

                    this.fut_state = TransactionWriteJournalFutureState::Canonicalize {
                        transaction: Some(transaction),
                    };
                }
                TransactionWriteJournalFutureState::Canonicalize { transaction } => {
                    let mut transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => break (false, None, nvfs_err_internal!()),
                    };

                    let mut fs_instance_sync_state = CocoonFsSyncStateMemberRef::from(&mut fs_instance_sync_state);
                    let (
                        fs_instance,
                        _fs_sync_state_image_size,
                        fs_sync_state_alloc_bitmap,
                        fs_sync_state_alloc_bitmap_file,
                        _fs_sync_state_auth_tree,
                        _fs_sync_state_inode_index,
                        _fs_sync_state_read_buffer,
                        mut fs_sync_state_keys_cache,
                    ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();

                    let fs_config = &fs_instance.fs_config;

                    // Normalize the pending allocations and frees, and stage updates to
                    // allocation bitmap file.
                    transaction
                        .allocs
                        .pending_allocs
                        .clear_redundant(fs_sync_state_alloc_bitmap, false);
                    transaction
                        .allocs
                        .pending_frees
                        .clear_redundant(fs_sync_state_alloc_bitmap, true);
                    if let Err(e) = fs_sync_state_alloc_bitmap_file.write_updates(
                        &mut transaction.auth_tree_data_blocks_update_states,
                        &transaction.allocs.pending_allocs,
                        &transaction.allocs.pending_frees,
                        fs_sync_state_alloc_bitmap,
                        &fs_config.image_layout,
                        &fs_config.root_key,
                        &mut fs_sync_state_keys_cache,
                        transaction.rng.as_mut(),
                    ) {
                        break (false, Some(transaction), e);
                    }

                    // Prune any unneeded update states before proceeding further.
                    if let Err(e) = transaction.auth_tree_data_blocks_update_states.prune_unmodified(
                        &mut transaction.abandoned_journal_staging_copy_blocks,
                        fs_config.image_header_end,
                    ) {
                        break (false, Some(transaction), e);
                    }
                    // Subsequent code would attempt to repurpose abandandoned Journal Staging Copy
                    // Blocks for allocations, make sure that they're recorded in journal_allocs to
                    // avoid potentially allocating the same block twice: once through the abandoned
                    // list and once through the regular allocation primitives. Note that most
                    // abandoned Journal Staging Copy Blocks should already be present in
                    // journal_allocs, this is relevant only for those that qualified for in-place
                    // writes.
                    let image_layout = &fs_config.image_layout;
                    let io_block_allocation_blocks_log2 = image_layout.io_block_allocation_blocks_log2 as u32;
                    let auth_tree_data_block_allocation_blocks_log2 =
                        image_layout.auth_tree_data_block_allocation_blocks_log2 as u32;
                    let journal_block_allocation_blocks_log2 =
                        io_block_allocation_blocks_log2.max(auth_tree_data_block_allocation_blocks_log2);
                    if let Err(e) = transaction.allocs.journal_allocs.add_blocks(
                        transaction.abandoned_journal_staging_copy_blocks.iter().copied(),
                        journal_block_allocation_blocks_log2,
                    ) {
                        break (false, Some(transaction), e);
                    }

                    let all_update_states_index_range = AuthTreeDataBlocksUpdateStatesIndexRange::new(
                        AuthTreeDataBlocksUpdateStatesIndex::from(0),
                        AuthTreeDataBlocksUpdateStatesIndex::from(
                            transaction.auth_tree_data_blocks_update_states.len(),
                        ),
                    );
                    let prepare_staged_updates_application_fut = TransactionPrepareStagedUpdatesApplicationFuture::new(
                        transaction,
                        AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::from(all_update_states_index_range),
                    );

                    this.fut_state = TransactionWriteJournalFutureState::UpdateStatesApplyStagedUpdates {
                        prepare_staged_updates_application_fut,
                    };
                }
                TransactionWriteJournalFutureState::UpdateStatesApplyStagedUpdates {
                    prepare_staged_updates_application_fut,
                } => {
                    let mut transaction = match CocoonFsSyncStateReadFuture::poll(
                        pin::Pin::new(prepare_staged_updates_application_fut),
                        &mut CocoonFsSyncStateMemberRef::from(&mut fs_instance_sync_state),
                        &mut (),
                        cx,
                    ) {
                        task::Poll::Ready(Ok((transaction, _, Ok(())))) => transaction,
                        task::Poll::Ready(Ok((transaction, _, Err(e)))) => break (false, Some(transaction), e),
                        task::Poll::Ready(Err(e)) => break (false, None, e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    transaction
                        .auth_tree_data_blocks_update_states
                        .apply_allocation_blocks_staged_updates(None, &fs_instance_sync_state.alloc_bitmap);

                    let all_update_states_index_range = AuthTreeDataBlocksUpdateStatesIndexRange::new(
                        AuthTreeDataBlocksUpdateStatesIndex::from(0),
                        AuthTreeDataBlocksUpdateStatesIndex::from(
                            transaction.auth_tree_data_blocks_update_states.len(),
                        ),
                    );
                    // In preparation of writing dirty data, fill all IO block alignment gaps.
                    let fs_instance = fs_instance_sync_state.get_fs_ref();
                    let io_block_allocation_blocks_log2 =
                        fs_instance.fs_config.image_layout.io_block_allocation_blocks_log2 as u32;
                    if let Err(e) = transaction
                        .auth_tree_data_blocks_update_states
                        .fill_states_allocation_blocks_index_range_regions_alignment_gaps(
                            &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::from(
                                all_update_states_index_range,
                            ),
                            io_block_allocation_blocks_log2,
                            &fs_instance_sync_state.alloc_bitmap,
                            &transaction.allocs.pending_frees,
                        )
                        .0
                    {
                        break (false, Some(transaction), e);
                    }

                    // Before actually writing dirty data, allocate Journal staging copies. Doing it
                    // upfront potentially enables write request coalescing.
                    //
                    // Before allocating Journal staging copies, insert placeholder update states
                    // for the mutable image header, which will always receive an update because the
                    // root authentication digest is being stored there. Having
                    // placeholder update states (with allocated Journal staging
                    // copies) for the image header in place will make sure
                    // these will get considered when generating the
                    // JournalApplyWritesScript.
                    let salt_len = match u8::try_from(fs_instance.fs_config.salt.len()) {
                        Ok(salt_len) => salt_len,
                        Err(_) => {
                            break (
                                false,
                                Some(transaction),
                                NvFsError::from(CocoonFsFormatError::InvalidSaltLength),
                            );
                        }
                    };
                    let image_layout = &fs_instance.fs_config.image_layout;
                    let mutable_image_header_region = image_header::MutableImageHeader::physical_location(
                        &fs_instance.fs_config.image_layout,
                        salt_len,
                    );
                    // Align to the IO Block size before the states insertion, otherwise alignment
                    // gaps would have to get filled later on.
                    let mutable_image_header_region =
                        match mutable_image_header_region.align(image_layout.io_block_allocation_blocks_log2 as u32) {
                            Some(mutable_image_header_location) => mutable_image_header_location,
                            None => {
                                // As an IO Block in units of Bytes is <= 2^63, it follows that an
                                // IO Block in units of Allocation Blocks is <= 2^(63 - 7). The
                                // mutable header's beginning is at the first IO Block alignment
                                // boundary following the static header, hence <= that upper
                                // bound. The mutable header is certainly <= that value in length as
                                // well, hence the mutable header's end aligned to the next IO block
                                // boundary is <= twice that value, which fits an u64 comfortably.
                                break (false, Some(transaction), nvfs_err_internal!());
                            }
                        };
                    if let Err((e, _)) = transaction.auth_tree_data_blocks_update_states.insert_missing_in_range(
                        mutable_image_header_region,
                        &fs_instance_sync_state.alloc_bitmap,
                        &transaction.allocs.pending_frees,
                        None,
                    ) {
                        break (false, Some(transaction), e);
                    }

                    let all_update_states_index_range = AuthTreeDataBlocksUpdateStatesIndexRange::new(
                        AuthTreeDataBlocksUpdateStatesIndex::from(0),
                        AuthTreeDataBlocksUpdateStatesIndex::from(
                            transaction.auth_tree_data_blocks_update_states.len(),
                        ),
                    );
                    let allocate_journal_staging_copies_fut =
                        TransactionAllocateJournalStagingCopiesFuture::new(transaction, all_update_states_index_range);
                    this.fut_state = TransactionWriteJournalFutureState::AllocateJournalStagingCopies {
                        allocate_journal_staging_copies_fut,
                    };
                }
                TransactionWriteJournalFutureState::AllocateJournalStagingCopies {
                    allocate_journal_staging_copies_fut,
                } => {
                    let transaction = match CocoonFsSyncStateReadFuture::poll(
                        pin::Pin::new(allocate_journal_staging_copies_fut),
                        &mut CocoonFsSyncStateMemberRef::from(&mut fs_instance_sync_state),
                        &mut (),
                        cx,
                    ) {
                        task::Poll::Ready(Ok((transaction, Ok(())))) => transaction,
                        task::Poll::Ready(Ok((transaction, Err(e)))) => break (false, Some(transaction), e),
                        task::Poll::Ready(Err(e)) => break (false, None, e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    // Note: this might write out the unmodified mutable image header region, which
                    // will get updated and rewritten later again, namely if the mutable image
                    // header's end does not align with the IO block size and there are some
                    // unrelated data modification to the remainder. However, this is expected to
                    // happen rarely and probably not worth any extra logic
                    let all_update_states_index_range = AuthTreeDataBlocksUpdateStatesIndexRange::new(
                        AuthTreeDataBlocksUpdateStatesIndex::from(0),
                        AuthTreeDataBlocksUpdateStatesIndex::from(
                            transaction.auth_tree_data_blocks_update_states.len(),
                        ),
                    );
                    let fs_instance = fs_instance_sync_state.get_fs_ref();
                    let write_dirty_data_fut = match TransactionWriteDirtyDataFuture::new(
                        transaction,
                        &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::from(all_update_states_index_range),
                        fs_instance.fs_config.image_layout.io_block_allocation_blocks_log2,
                    ) {
                        Ok(write_dirty_data_fut) => write_dirty_data_fut,
                        Err((transaction, e)) => break (false, Some(transaction), e),
                    };
                    this.fut_state =
                        TransactionWriteJournalFutureState::UpdateStatesWriteDirtyData { write_dirty_data_fut };
                }
                TransactionWriteJournalFutureState::UpdateStatesWriteDirtyData { write_dirty_data_fut } => {
                    let mut transaction = match CocoonFsSyncStateReadFuture::poll(
                        pin::Pin::new(write_dirty_data_fut),
                        &mut CocoonFsSyncStateMemberRef::from(&mut fs_instance_sync_state),
                        &mut (),
                        cx,
                    ) {
                        task::Poll::Ready(Ok((transaction, _, Ok(())))) => transaction,
                        task::Poll::Ready(Ok((transaction, _, Err(e)))) => break (false, Some(transaction), e),
                        task::Poll::Ready(Err(e)) => break (false, None, e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    // Now compute updated authentication digests for the modified Authentication
                    // Tree Data Blocks.
                    let fs_instance = fs_instance_sync_state.get_fs_ref();
                    if let Err(e) = transaction.auth_tree_data_blocks_update_states.update_auth_digests(
                        None,
                        fs_instance_sync_state.auth_tree.get_config(),
                        fs_instance.fs_config.image_header_end,
                    ) {
                        break (false, Some(transaction), e);
                    }

                    // As the digests will get stolen from the transaction's update states when
                    // computing the pending Authentication Tree Node updates later on, retrieve the
                    // needed authentication digests for (parts of) the Allocation Bitmap File
                    // beforehand.
                    let fs_config = &fs_instance.fs_config;
                    let image_layout = &fs_config.image_layout;
                    let auth_tree_data_block_allocation_blocks_log2 =
                        image_layout.auth_tree_data_block_allocation_blocks_log2;
                    let alloc_bitmap_file_blocks_for_auth_tree_reconstruction =
                        match journal::auth_tree_updates::collect_alloc_bitmap_blocks_for_auth_tree_reconstruction(
                            TransactionJournalUpdateAuthDigestsScriptIterator::new(
                                &transaction.auth_tree_data_blocks_update_states,
                                &transaction.allocs.pending_frees,
                                fs_config.image_header_end,
                                auth_tree_data_block_allocation_blocks_log2,
                            ),
                            &fs_instance_sync_state.alloc_bitmap_file,
                            fs_instance_sync_state.auth_tree.get_config(),
                            auth_tree_data_block_allocation_blocks_log2,
                        ) {
                            Ok(alloc_bitmap_file_blocks_for_auth_tree_reconstruction) => {
                                alloc_bitmap_file_blocks_for_auth_tree_reconstruction
                            }
                            Err(e) => break (false, Some(transaction), e),
                        };
                    let alloc_bitmap_file_extents_for_auth_tree_reconstruction =
                        match journal::auth_tree_updates::alloc_bitmap_file_block_indices_to_physical_extents(
                            &alloc_bitmap_file_blocks_for_auth_tree_reconstruction,
                            fs_instance_sync_state.alloc_bitmap_file.get_extents(),
                            image_layout,
                        ) {
                            Ok(alloc_bitmap_file_extents_for_auth_tree_reconstruction) => {
                                alloc_bitmap_file_extents_for_auth_tree_reconstruction
                            }
                            Err(e) => break (false, Some(transaction), e),
                        };
                    drop(alloc_bitmap_file_blocks_for_auth_tree_reconstruction);

                    let encoded_alloc_bitmap_file_auth_digests_for_auth_tree_reconstruction_len =
                        match journal::extents_covering_auth_digests::ExtentsCoveringAuthDigests::encoded_len(
                            &alloc_bitmap_file_extents_for_auth_tree_reconstruction,
                            image_layout.auth_tree_data_block_allocation_blocks_log2,
                            hash::hash_alg_digest_len(image_layout.auth_tree_data_hmac_hash_alg) as usize,
                        ) {
                            Ok(encoded_alloc_bitmap_file_auth_digests_for_auth_tree_reconstruction_len) => {
                                encoded_alloc_bitmap_file_auth_digests_for_auth_tree_reconstruction_len
                            }
                            Err(e) => break (false, Some(transaction), e),
                        };
                    let encoded_alloc_bitmap_file_auth_digests_for_auth_tree_reconstruction =
                        match FixedVec::new_with_default(
                            encoded_alloc_bitmap_file_auth_digests_for_auth_tree_reconstruction_len,
                        ) {
                            Ok(encoded_alloc_bitmap_file_auth_digests_for_auth_tree_reconstruction) => {
                                encoded_alloc_bitmap_file_auth_digests_for_auth_tree_reconstruction
                            }
                            Err(e) => break (false, Some(transaction), NvFsError::from(e)),
                        };

                    this.fut_state =
                        TransactionWriteJournalFutureState::CollectAllocBitmapFileAuthDigestsForAuthTreeReconstruction {
                            collect_auth_digests_fut: TransactionCollectExtentsCoveringAuthDigestsFuture::new(
                                transaction,
                                alloc_bitmap_file_extents_for_auth_tree_reconstruction,
                                encoded_alloc_bitmap_file_auth_digests_for_auth_tree_reconstruction,
                                0,
                            )
                        };
                }
                TransactionWriteJournalFutureState::CollectAllocBitmapFileAuthDigestsForAuthTreeReconstruction {
                    collect_auth_digests_fut,
                } => {
                    let (
                        transaction,
                        encoded_alloc_bitmap_file_auth_digests_for_auth_tree_reconstruction,
                        encoded_alloc_bitmap_file_auth_digests_for_auth_tree_reconstruction_len,
                    ) = match TransactionCollectExtentsCoveringAuthDigestsFuture::poll(
                        pin::Pin::new(collect_auth_digests_fut),
                        fs_instance_sync_state.make_borrow(),
                        cx,
                    ) {
                        task::Poll::Ready((
                            encoded_alloc_bitmap_file_auth_digests_for_auth_tree_reconstruction,
                            Ok((transaction, encoded_alloc_bitmap_file_auth_digests_for_auth_tree_reconstruction_len)),
                        )) => (
                            transaction,
                            encoded_alloc_bitmap_file_auth_digests_for_auth_tree_reconstruction,
                            encoded_alloc_bitmap_file_auth_digests_for_auth_tree_reconstruction_len,
                        ),
                        task::Poll::Ready((_, Err((transaction, e)))) => break (false, transaction, e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    if encoded_alloc_bitmap_file_auth_digests_for_auth_tree_reconstruction_len
                        != encoded_alloc_bitmap_file_auth_digests_for_auth_tree_reconstruction.len()
                    {
                        break (false, Some(transaction), nvfs_err_internal!());
                    }
                    this.encoded_alloc_bitmap_file_auth_digests_for_auth_tree_reconstruction =
                        encoded_alloc_bitmap_file_auth_digests_for_auth_tree_reconstruction;

                    let fs_instance = fs_instance_sync_state.get_fs_ref();
                    let fs_config = &fs_instance.fs_config;
                    let transaction_auth_tree_data_blocks_digests_updates_iter =
                        TransactionAuthTreeDataBlocksDigestsUpdatesIterator::new(
                            transaction,
                            fs_config.image_layout.auth_tree_data_block_allocation_blocks_log2,
                            fs_config.image_header_end,
                        );
                    let prepare_auth_tree_updates_fut = auth_tree::AuthTreePrepareUpdatesFuture::new(
                        transaction_auth_tree_data_blocks_digests_updates_iter,
                    );
                    this.fut_state = TransactionWriteJournalFutureState::PrepareAuthTreeUpdates {
                        prepare_auth_tree_updates_fut,
                    };
                }
                TransactionWriteJournalFutureState::PrepareAuthTreeUpdates {
                    prepare_auth_tree_updates_fut,
                } => {
                    // Note: this steals the Authentication Tree Data Block digests from the
                    // transaction's updated states and moves them over into the
                    // pending_auth_tree_nodes_updates.
                    let (mut transaction, updated_auth_tree_root_hmac_digest, pending_auth_tree_nodes_updates) =
                        match CocoonFsSyncStateReadFuture::poll(
                            pin::Pin::new(prepare_auth_tree_updates_fut),
                            &mut CocoonFsSyncStateMemberRef::from(&mut fs_instance_sync_state),
                            &mut (),
                            cx,
                        ) {
                            task::Poll::Ready(Ok((
                                transaction_auth_tree_data_blocks_digests_updates_iter,
                                Ok((updated_root_hmac_digest, pending_auth_tree_nodes_updates)),
                            ))) => {
                                let transaction =
                                    match transaction_auth_tree_data_blocks_digests_updates_iter.into_transaction() {
                                        Ok(transaction) => transaction,
                                        Err(e) => break (false, None, e),
                                    };
                                (transaction, updated_root_hmac_digest, pending_auth_tree_nodes_updates)
                            }
                            task::Poll::Ready(Ok((transaction_auth_tree_data_blocks_digests_updates_iter, Err(e)))) => {
                                let transaction = transaction_auth_tree_data_blocks_digests_updates_iter
                                    .into_transaction()
                                    .ok();
                                break (false, transaction, e);
                            }
                            task::Poll::Ready(Err(e)) => break (false, None, e),
                            task::Poll::Pending => return task::Poll::Pending,
                        };
                    transaction.pending_auth_tree_updates = transaction::TransactionPendingAuthTreeUpdates {
                        updated_root_hmac_digest: updated_auth_tree_root_hmac_digest,
                        pending_nodes_updates: pending_auth_tree_nodes_updates,
                    };

                    // Now that the updated Authentication Tree Root digest is available, prepare
                    // updates to the mutable image header.
                    let fs_instance = fs_instance_sync_state.get_fs_ref();
                    let fs_config = &fs_instance.fs_config;
                    let salt_len = match u8::try_from(fs_config.salt.len()) {
                        Ok(salt_len) => salt_len,
                        Err(_) => {
                            break (
                                false,
                                Some(transaction),
                                NvFsError::from(CocoonFsFormatError::InvalidSaltLength),
                            );
                        }
                    };
                    let image_layout = &fs_instance.fs_config.image_layout;
                    let mutable_image_header_region =
                        image_header::MutableImageHeader::physical_location(&fs_config.image_layout, salt_len);
                    let update_states = &mut transaction.auth_tree_data_blocks_update_states;
                    let mutable_image_header_update_states_allocation_blocks_range = match update_states
                        .lookup_allocation_blocks_update_states_index_range(&mutable_image_header_region)
                    {
                        Ok(mutable_image_header_update_states_allocation_blocks_range) => {
                            mutable_image_header_update_states_allocation_blocks_range
                        }
                        Err(_) => {
                            // The update states corresponding to the mutable image header had
                            // been inserted above.
                            break (false, Some(transaction), nvfs_err_internal!());
                        }
                    };
                    if let Err(e) = update_states.allocate_allocation_blocks_update_staging_bufs(
                        &mutable_image_header_update_states_allocation_blocks_range,
                        image_layout.allocation_block_size_128b_log2 as u32,
                    ) {
                        break (false, Some(transaction), e);
                    }
                    let mutable_image_header_update_staging_bufs_iter = match update_states
                        .iter_allocation_blocks_update_staging_bufs_mut(
                            &mutable_image_header_update_states_allocation_blocks_range,
                        ) {
                        Ok(mutable_image_header_update_staging_bufs_iter) => {
                            mutable_image_header_update_staging_bufs_iter
                        }
                        Err(e) => break (false, Some(transaction), e),
                    };
                    let inode_index_entry_leaf_node_preauth_cca_protection_digest = match transaction
                        .inode_index_updates
                        .get_updated_entry_leaf_node_preauth_cca_protection_digest()
                    {
                        Some(updated_inode_index_entryleaf_node_preauth_cca_protection_digest) => {
                            updated_inode_index_entryleaf_node_preauth_cca_protection_digest
                        }
                        None => fs_instance_sync_state
                            .inode_index
                            .get_entry_leaf_node_preauth_cca_protection_digest(),
                    };
                    if let Err(e) = image_header::MutableImageHeader::encode(
                        mutable_image_header_update_staging_bufs_iter.map_err(NvFsError::from),
                        &transaction.pending_auth_tree_updates.updated_root_hmac_digest,
                        inode_index_entry_leaf_node_preauth_cca_protection_digest,
                        &fs_config.inode_index_entry_leaf_node_block_ptr,
                        fs_instance_sync_state.image_size,
                    ) {
                        break (false, Some(transaction), e);
                    }
                    // The image header is not authenticated through the Authentication Tree, hence
                    // the containing Authentication Tree Data Blocks' authentication digests don't
                    // need to get recomputed and we can skip the staged update application
                    // preparation and apply + write-out directly.
                    update_states.apply_allocation_blocks_staged_updates(
                        Some(&mutable_image_header_update_states_allocation_blocks_range),
                        &fs_instance_sync_state.alloc_bitmap,
                    );
                    let write_dirty_data_fut = match TransactionWriteDirtyDataFuture::new(
                        transaction,
                        &mutable_image_header_update_states_allocation_blocks_range,
                        fs_instance.fs_config.image_layout.io_block_allocation_blocks_log2,
                    ) {
                        Ok(write_dirty_data_fut) => write_dirty_data_fut,
                        Err((transaction, e)) => break (false, Some(transaction), e),
                    };
                    this.fut_state = TransactionWriteJournalFutureState::WriteHeaderUpdates { write_dirty_data_fut };
                }
                TransactionWriteJournalFutureState::WriteHeaderUpdates { write_dirty_data_fut } => {
                    let transaction = match CocoonFsSyncStateReadFuture::poll(
                        pin::Pin::new(write_dirty_data_fut),
                        &mut CocoonFsSyncStateMemberRef::from(&mut fs_instance_sync_state),
                        &mut (),
                        cx,
                    ) {
                        task::Poll::Ready(Ok((transaction, _, Ok(())))) => transaction,
                        task::Poll::Ready(Ok((transaction, _, Err(e)))) => break (false, Some(transaction), e),
                        task::Poll::Ready(Err(e)) => break (false, None, e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    // Finally, prepare and write the Journal Log.
                    let fs_instance = fs_instance_sync_state.get_fs_ref();
                    let fs_config = &fs_instance.fs_config;
                    let journal_log_encode_buf_layout = match journal::log::JournalLogEncodeBufferLayout::new(
                        fs_config,
                        &fs_instance_sync_state.alloc_bitmap,
                        &transaction,
                        fs_instance_sync_state.auth_tree.get_config().get_auth_tree_extents(),
                        fs_instance_sync_state.alloc_bitmap_file.get_extents(),
                        this.encoded_alloc_bitmap_file_auth_digests_for_auth_tree_reconstruction
                            .len(),
                    ) {
                        Ok(journal_log_encode_buf_layout) => journal_log_encode_buf_layout,
                        Err(e) => break (false, Some(transaction), e),
                    };

                    let (journal_log_head_extent, journal_log_head_extent_effective_payload_len) =
                        match journal::log::JournalLog::head_extent_physical_location(
                            &fs_config.image_layout,
                            fs_config.image_header_end,
                        ) {
                            Ok((journal_log_head_extent, journal_log_head_extent_effective_payload_len)) => {
                                (journal_log_head_extent, journal_log_head_extent_effective_payload_len)
                            }
                            Err(e) => break (false, Some(transaction), e),
                        };

                    // Add one for the CBC padding.
                    let journal_log_total_payload_len =
                        match u64::try_from(journal_log_encode_buf_layout.get_encoded_total_len())
                            .ok()
                            .and_then(|journal_log_total_encoded_len| journal_log_total_encoded_len.checked_add(1))
                        {
                            Some(journal_log_total_encoded_len) => journal_log_total_encoded_len,
                            None => {
                                break (
                                    false,
                                    Some(transaction),
                                    NvFsError::from(CocoonFsFormatError::InvalidFileSize),
                                );
                            }
                        };

                    let journal_log_allocate_payload_len =
                        journal_log_total_payload_len.saturating_sub(journal_log_head_extent_effective_payload_len);
                    if journal_log_allocate_payload_len == 0 {
                        this.fut_state = TransactionWriteJournalFutureState::PrepareJournalLog {
                            transaction: Some(transaction),
                            journal_log_head_extent,
                            journal_log_encode_buf_layout,
                        };
                    } else {
                        let mut journal_log_extents_layout = match journal::log::JournalLog::extents_encryption_layout(
                            &fs_config.image_layout,
                        )
                        .and_then(|journal_log_extents_encryption_layout| {
                            journal_log_extents_encryption_layout.get_extents_layout()
                        }) {
                            Ok(journal_log_extents_layout) => journal_log_extents_layout,
                            Err(e) => break (false, Some(transaction), e),
                        };
                        // The extents headers are stored the first extent, which is fixed in the
                        // case of the Journal Log extents -- here we allocate the tail extents.
                        journal_log_extents_layout.extents_hdr_len = 0;
                        // Limit the individual allocated extents' length to what's representable by
                        // an usize.
                        let max_extent_allocation_blocks = layout::AllocBlockCount::from(
                            u64::try_from(usize::MAX).unwrap_or(u64::MAX)
                                >> (fs_config.image_layout.allocation_block_size_128b_log2 as u32 + 7),
                        )
                        .align_down(journal_log_extents_layout.extent_alignment_allocation_blocks_log2 as u32);
                        if max_extent_allocation_blocks < journal_log_extents_layout.min_extents_allocation_blocks().1
                            || max_extent_allocation_blocks < journal_log_head_extent.block_count()
                        {
                            break (false, Some(transaction), NvFsError::DimensionsNotSupported);
                        }
                        journal_log_extents_layout.max_extent_allocation_blocks = journal_log_extents_layout
                            .max_extent_allocation_blocks
                            .min(max_extent_allocation_blocks);

                        let allocate_fut = TransactionAllocateJournalExtentsFuture::new(
                            transaction,
                            alloc_bitmap::ExtentsAllocationRequest::new(
                                journal_log_allocate_payload_len,
                                &journal_log_extents_layout,
                            ),
                        );
                        this.fut_state = TransactionWriteJournalFutureState::AllocateJournalLog {
                            allocate_fut,
                            journal_log_head_extent,
                            journal_log_encode_buf_layout,
                        };
                    }
                }
                TransactionWriteJournalFutureState::AllocateJournalLog {
                    allocate_fut,
                    journal_log_head_extent,
                    journal_log_encode_buf_layout,
                } => {
                    let (mut transaction, journal_log_tail_extents) = match CocoonFsSyncStateReadFuture::poll(
                        pin::Pin::new(allocate_fut),
                        &mut CocoonFsSyncStateMemberRef::from(&mut fs_instance_sync_state),
                        &mut (),
                        cx,
                    ) {
                        task::Poll::Ready(Ok((transaction, Ok(journal_log_tail_extents)))) => {
                            (transaction, journal_log_tail_extents)
                        }
                        task::Poll::Ready(Ok((transaction, Err(e)))) => break (false, Some(transaction), e),
                        task::Poll::Ready(Err(e)) => break (false, None, e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    transaction.journal_log_tail_extents = journal_log_tail_extents;

                    this.fut_state = TransactionWriteJournalFutureState::PrepareJournalLog {
                        transaction: Some(transaction),
                        journal_log_head_extent: *journal_log_head_extent,
                        journal_log_encode_buf_layout: journal_log_encode_buf_layout.clone(),
                    };
                }
                TransactionWriteJournalFutureState::PrepareJournalLog {
                    transaction,
                    journal_log_head_extent,
                    journal_log_encode_buf_layout,
                } => {
                    let mut transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => break (false, None, nvfs_err_internal!()),
                    };

                    // Encode the journal log in plain, and encrypt it as chained extents.
                    let journal_log_total_encoded_len = journal_log_encode_buf_layout.get_encoded_total_len();
                    let journal_log_encode_buf =
                        match FixedVec::<u8, 0>::new_with_default(journal_log_total_encoded_len) {
                            Ok(journal_log_encode_buf) => journal_log_encode_buf,
                            Err(e) => break (false, Some(transaction), NvFsError::from(e)),
                        };
                    let mut journal_log_encode_buf = zeroize::Zeroizing::new(journal_log_encode_buf);

                    let mut fs_instance_sync_state = CocoonFsSyncStateMemberRef::from(&mut fs_instance_sync_state);
                    let (
                        fs_instance,
                        _fs_sync_state_image_size,
                        fs_sync_state_alloc_bitmap,
                        fs_sync_state_alloc_bitmap_file,
                        fs_sync_state_auth_tree,
                        _fs_sync_state_inode_index,
                        _fs_sync_state_read_buffer,
                        mut fs_sync_state_keys_cache,
                    ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();
                    match journal::log::JournalLog::encode(
                        &mut journal_log_encode_buf,
                        journal_log_encode_buf_layout,
                        &fs_instance.fs_config,
                        fs_sync_state_alloc_bitmap,
                        &mut fs_sync_state_keys_cache,
                        &transaction,
                        fs_sync_state_auth_tree.get_config().get_auth_tree_extents(),
                        fs_sync_state_alloc_bitmap_file.get_extents(),
                        &this.encoded_alloc_bitmap_file_auth_digests_for_auth_tree_reconstruction,
                    ) {
                        Ok(remaining_encode_buf) => {
                            if !remaining_encode_buf.is_empty() {
                                break (false, Some(transaction), nvfs_err_internal!());
                            }
                        }
                        Err(e) => break (false, Some(transaction), e),
                    }

                    // Allocate the encryption target buffers, one for each extent. None of the
                    // extents' length exceeds an usize, as has been checked above in the previous
                    // step.
                    let allocation_block_size_128b_log2 =
                        fs_instance.fs_config.image_layout.allocation_block_size_128b_log2 as u32;
                    let journal_log_head_extent_len = (u64::from(journal_log_head_extent.block_count())
                        << (allocation_block_size_128b_log2 + 7))
                        as usize;
                    let mut journal_log_head_extent_buf = match FixedVec::new_with_default(journal_log_head_extent_len)
                    {
                        Ok(journal_log_head_extent_buf) => journal_log_head_extent_buf,
                        Err(e) => break (false, Some(transaction), NvFsError::from(e)),
                    };
                    // Encode the magic stored in plain.
                    *match <&mut [u8; 8]>::try_from(&mut journal_log_head_extent_buf[..8])
                        .map_err(|_| nvfs_err_internal!())
                    {
                        Ok(magic_dst) => magic_dst,
                        Err(e) => break (false, Some(transaction), e),
                    } = *b"CCFSJRNL";

                    let journal_log_tail_extents = &transaction.journal_log_tail_extents;
                    let mut journal_log_tail_extents_bufs =
                        match FixedVec::new_with_default(journal_log_tail_extents.len()) {
                            Ok(journal_log_tail_extents_bufs) => journal_log_tail_extents_bufs,
                            Err(e) => break (false, Some(transaction), NvFsError::from(e)),
                        };
                    for (i, journal_log_tail_extent) in journal_log_tail_extents.iter().enumerate() {
                        let journal_log_tail_extent_len = (u64::from(journal_log_tail_extent.block_count())
                            << (allocation_block_size_128b_log2 + 7))
                            as usize;
                        let journal_log_tail_extent_buf = match FixedVec::new_with_default(journal_log_tail_extent_len)
                        {
                            Ok(journal_log_tail_extent_buf) => journal_log_tail_extent_buf,
                            Err(e) => break 'outer (false, Some(transaction), NvFsError::from(e)),
                        };
                        journal_log_tail_extents_bufs[i] = journal_log_tail_extent_buf;
                    }

                    let mut journal_log_extents_encryption_instance =
                        match journal::log::JournalLog::extents_encryption_instance(
                            &fs_instance.fs_config.image_layout,
                            &fs_instance.fs_config.root_key,
                            &mut fs_sync_state_keys_cache,
                        ) {
                            Ok(journal_log_extents_encryption_instance) => journal_log_extents_encryption_instance,
                            Err(e) => break (false, Some(transaction), e),
                        };

                    let encoded_image_layout = match fs_instance.fs_config.image_layout.encode() {
                        Ok(encoded_image_layout) => encoded_image_layout,
                        Err(e) => break (false, Some(transaction), e),
                    };
                    let auth_context_subject_id_suffix = [
                        0u8, // Version of the authenticated data's format.
                        EncryptedChainedExtentsAssociatedDataAuthSubjectDataSuffix::JournalLog as u8,
                    ];
                    let authenticated_associated_data = [
                        encoded_image_layout.as_slice(),
                        auth_context_subject_id_suffix.as_slice(),
                    ];
                    let authenticated_associated_data =
                        io_slices::BuffersSliceIoSlicesIter::new(&authenticated_associated_data).map_infallible_err();

                    let mut journal_log_encode_buf_io_slice =
                        io_slices::SingletonIoSlice::new(&journal_log_encode_buf).map_infallible_err();

                    if let Err(e) = journal_log_extents_encryption_instance.encrypt_one_extent(
                        io_slices::SingletonIoSliceMut::new(&mut journal_log_head_extent_buf).map_infallible_err(),
                        &mut journal_log_encode_buf_io_slice,
                        authenticated_associated_data.decoupled_borrow(),
                        journal_log_head_extent.block_count(),
                        (!journal_log_tail_extents.is_empty())
                            .then(|| journal_log_tail_extents.get_extent_range(0))
                            .as_ref(),
                        transaction.rng.as_mut(),
                    ) {
                        break (false, Some(transaction), e);
                    }
                    for (i, journal_log_tail_extent) in journal_log_tail_extents.iter().enumerate() {
                        if let Err(e) = journal_log_extents_encryption_instance.encrypt_one_extent(
                            io_slices::SingletonIoSliceMut::new(&mut journal_log_tail_extents_bufs[i])
                                .map_infallible_err(),
                            &mut journal_log_encode_buf_io_slice,
                            authenticated_associated_data.decoupled_borrow(),
                            journal_log_tail_extent.block_count(),
                            (i != journal_log_tail_extents.len() - 1)
                                .then(|| journal_log_tail_extents.get_extent_range(i + 1))
                                .as_ref(),
                            transaction.rng.as_mut(),
                        ) {
                            break 'outer (false, Some(transaction), e);
                        }
                    }

                    this.fut_state = TransactionWriteJournalFutureState::PrepareWriteJournalLogTailExtent {
                        transaction: Some(transaction),
                        journal_log_head_extent: *journal_log_head_extent,
                        journal_log_head_extent_buf,
                        journal_log_tail_extents_bufs,
                        next_tail_extent_index: 0,
                    };
                }
                TransactionWriteJournalFutureState::PrepareWriteJournalLogTailExtent {
                    transaction,
                    journal_log_head_extent,
                    journal_log_head_extent_buf,
                    journal_log_tail_extents_bufs,
                    next_tail_extent_index,
                } => {
                    let transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => break (false, None, nvfs_err_internal!()),
                    };

                    let fs_instance = fs_instance_sync_state.get_fs_ref();
                    let journal_log_tail_extents = &transaction.journal_log_tail_extents;
                    if *next_tail_extent_index == journal_log_tail_extents.len() {
                        let write_barrier_fut = match fs_instance.chip.write_barrier() {
                            Ok(write_barrier_fut) => write_barrier_fut,
                            Err(e) => break (false, Some(transaction), NvFsError::from(e)),
                        };
                        this.fut_state = TransactionWriteJournalFutureState::WriteBarrierBeforeJournalLogHeadWrite {
                            transaction: Some(transaction),
                            journal_log_head_extent: *journal_log_head_extent,
                            journal_log_head_extent_buf: mem::take(journal_log_head_extent_buf),
                            write_barrier_fut,
                        };
                    } else {
                        let write_extent_request = match WriteJournalLogExtentChipRequest::new(
                            &journal_log_tail_extents.get_extent_range(*next_tail_extent_index),
                            mem::take(&mut journal_log_tail_extents_bufs[*next_tail_extent_index]),
                            fs_instance.fs_config.image_layout.allocation_block_size_128b_log2,
                        ) {
                            Ok(write_extent_request) => write_extent_request,
                            Err(e) => break (false, Some(transaction), e),
                        };
                        let write_extent_fut = match fs_instance
                            .chip
                            .write(write_extent_request)
                            .and_then(|r| r.map_err(|(_, e)| e))
                        {
                            Ok(write_extent_fut) => write_extent_fut,
                            Err(e) => break (false, Some(transaction), NvFsError::from(e)),
                        };
                        this.fut_state = TransactionWriteJournalFutureState::WriteJournalLogTailExtent {
                            transaction: Some(transaction),
                            journal_log_head_extent: *journal_log_head_extent,
                            journal_log_head_extent_buf: mem::take(journal_log_head_extent_buf),
                            journal_log_tail_extents_bufs: mem::take(journal_log_tail_extents_bufs),
                            cur_tail_extent_index: *next_tail_extent_index,
                            write_extent_fut,
                        };
                    }
                }
                TransactionWriteJournalFutureState::WriteJournalLogTailExtent {
                    transaction,
                    journal_log_head_extent,
                    journal_log_head_extent_buf,
                    journal_log_tail_extents_bufs,
                    cur_tail_extent_index,
                    write_extent_fut,
                } => {
                    let fs_instance = fs_instance_sync_state.get_fs_ref();
                    match chip::NvChipFuture::poll(pin::Pin::new(write_extent_fut), &fs_instance.chip, cx) {
                        task::Poll::Ready(Ok((_, Ok(())))) => (),
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                            break (false, transaction.take(), NvFsError::from(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    this.fut_state = TransactionWriteJournalFutureState::PrepareWriteJournalLogTailExtent {
                        transaction: transaction.take(),
                        journal_log_head_extent: *journal_log_head_extent,
                        journal_log_head_extent_buf: mem::take(journal_log_head_extent_buf),
                        journal_log_tail_extents_bufs: mem::take(journal_log_tail_extents_bufs),
                        next_tail_extent_index: *cur_tail_extent_index + 1,
                    };
                }
                TransactionWriteJournalFutureState::WriteBarrierBeforeJournalLogHeadWrite {
                    transaction,
                    journal_log_head_extent,
                    journal_log_head_extent_buf,
                    write_barrier_fut,
                } => {
                    let fs_instance = fs_instance_sync_state.get_fs_ref();
                    match chip::NvChipFuture::poll(pin::Pin::new(write_barrier_fut), &fs_instance.chip, cx) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => break (false, transaction.take(), NvFsError::from(e)),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let write_extent_request = match WriteJournalLogExtentChipRequest::new(
                        journal_log_head_extent,
                        mem::take(journal_log_head_extent_buf),
                        fs_instance.fs_config.image_layout.allocation_block_size_128b_log2,
                    ) {
                        Ok(write_extent_request) => write_extent_request,
                        Err(e) => break (false, transaction.take(), e),
                    };
                    let write_extent_fut = match fs_instance
                        .chip
                        .write(write_extent_request)
                        .and_then(|r| r.map_err(|(_, e)| e))
                    {
                        Ok(write_extent_fut) => write_extent_fut,
                        Err(e) => break (true, transaction.take(), NvFsError::from(e)),
                    };
                    this.fut_state = TransactionWriteJournalFutureState::WriteJournalLogHeadExtent {
                        transaction: transaction.take(),
                        write_extent_fut,
                    };
                }
                TransactionWriteJournalFutureState::WriteJournalLogHeadExtent {
                    transaction,
                    write_extent_fut,
                } => {
                    let fs_instance = fs_instance_sync_state.get_fs_ref();
                    match chip::NvChipFuture::poll(pin::Pin::new(write_extent_fut), &fs_instance.chip, cx) {
                        task::Poll::Ready(Ok((_, Ok(())))) => (),
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                            break (true, transaction.take(), NvFsError::from(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    if this.issue_sync {
                        let write_sync_fut = match fs_instance.chip.write_sync() {
                            Ok(write_sync_fut) => write_sync_fut,
                            Err(e) => break (true, transaction.take(), NvFsError::from(e)),
                        };
                        this.fut_state = TransactionWriteJournalFutureState::WriteSyncAfterJournalLogHeadWrite {
                            transaction: transaction.take(),
                            write_sync_fut,
                        };
                    } else {
                        let write_barrier_fut = match fs_instance.chip.write_barrier() {
                            Ok(write_barrier_fut) => write_barrier_fut,
                            Err(e) => break (true, transaction.take(), NvFsError::from(e)),
                        };
                        this.fut_state = TransactionWriteJournalFutureState::WriteBarrierAfterJournalLogHeadWrite {
                            transaction: transaction.take(),
                            write_barrier_fut,
                        };
                    }
                }
                TransactionWriteJournalFutureState::WriteSyncAfterJournalLogHeadWrite {
                    transaction,
                    write_sync_fut,
                } => {
                    let fs_instance = fs_instance_sync_state.get_fs_ref();
                    match chip::NvChipFuture::poll(pin::Pin::new(write_sync_fut), &fs_instance.chip, cx) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => break (true, transaction.take(), NvFsError::from(e)),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => break (true, None, nvfs_err_internal!()),
                    };

                    this.fut_state = TransactionWriteJournalFutureState::Done;
                    return task::Poll::Ready(Ok(transaction));
                }
                TransactionWriteJournalFutureState::WriteBarrierAfterJournalLogHeadWrite {
                    transaction,
                    write_barrier_fut,
                } => {
                    let fs_instance = fs_instance_sync_state.get_fs_ref();
                    match chip::NvChipFuture::poll(pin::Pin::new(write_barrier_fut), &fs_instance.chip, cx) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => break (true, transaction.take(), NvFsError::from(e)),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => break (true, None, nvfs_err_internal!()),
                    };

                    this.fut_state = TransactionWriteJournalFutureState::Done;
                    return task::Poll::Ready(Ok(transaction));
                }
                TransactionWriteJournalFutureState::Done => unreachable!(),
            }
        };

        this.fut_state = TransactionWriteJournalFutureState::Done;

        // Before returning, bring the transaction's internal tracking data back into a
        // consistent state for good measure: move the Authentication Tree Data
        // Blocks' authentication digests previously stolen from the
        // transaction's update states, if any. With that, the journal write-out
        // could in principle be retried.
        let transaction = match transaction {
            Some(mut transaction) => {
                transaction.pending_auth_tree_updates.updated_root_hmac_digest = FixedVec::new_empty();
                let auth_tree_config = fs_instance_sync_state.auth_tree.get_config();
                let fs_instance = fs_instance_sync_state.get_fs_ref();
                let fs_config = &fs_instance.fs_config;
                let pending_auth_tree_nodes_updates = mem::replace(
                    &mut transaction.pending_auth_tree_updates.pending_nodes_updates,
                    auth_tree::AuthTreePendingNodesUpdates::new(),
                );
                if transaction
                    .restore_update_states_auth_digests(
                        pending_auth_tree_nodes_updates.into_updated_data_blocks(auth_tree_config),
                        fs_config.image_layout.auth_tree_data_block_allocation_blocks_log2,
                        fs_config.image_header_end,
                    )
                    .is_err()
                {
                    // A consistent state cannot get restored (because of an internal
                    // error). Consume the transaction.
                    None
                } else {
                    Some(transaction)
                }
            }
            None => None,
        };

        task::Poll::Ready(Err((need_journal_abort, transaction, e)))
    }
}

/// Collect and encode some [`ExtentsCoveringAuthDigests`].
struct TransactionCollectExtentsCoveringAuthDigestsFuture<C: chip::NvChip> {
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
    // reference on Self.
    transaction: Option<Box<Transaction>>,
    covered_extents: extents::PhysicalExtents,
    next_covered_extents_index: usize,
    last_auth_tree_data_block_allocation_blocks_end: layout::PhysicalAllocBlockIndex,
    out_buffer: FixedVec<u8, 0>,
    out_buffer_pos: usize,
    fut_state: TransactionCollectExtentsCoveringAuthDigestsFutureState<C>,
}

/// [`TransactionCollectExtentsCoveringAuthDigestsFuture`] state-machine state.
enum TransactionCollectExtentsCoveringAuthDigestsFutureState<C: chip::NvChip> {
    Init,
    LookupModified,
    LoadAuthTreeLeafNode {
        cur_auth_tree_data_block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        cur_auth_tree_data_block_index: auth_tree::AuthTreeDataBlockIndex,
        next_transaction_update_states_index: AuthTreeDataBlocksUpdateStatesIndex,
        auth_tree_leaf_node_id: auth_tree::AuthTreeNodeId,
        auth_tree_leaf_node_load_fut: auth_tree::AuthTreeNodeLoadFuture<C>,
    },
    Done,
}

impl<C: chip::NvChip> TransactionCollectExtentsCoveringAuthDigestsFuture<C> {
    /// Instantiate a [`TransactionCollectExtentsCoveringAuthDigestsFuture`].
    ///
    /// The [`TransactionCollectExtentsCoveringAuthDigestsFuture`] assumes
    /// ownership of the `transaction` and the `out_buffer` for the duration
    /// of the operation, they will eventually get returned back from
    /// [`poll()`](Self::poll) upon completion.
    ///
    /// # Arguments:
    ///
    /// * `transaction` - The committing [`Transaction`].
    /// * `covered_extents` - The extents to collect covering authentication
    ///   digests for. Must be sorted by ascending storage location.
    /// * `out_buffer` - The output buffer to encode the resulting
    ///   [`ExtentsCoveringAuthDigests`] to, starting at the position specified
    ///   by `out_buffer_destination_offset`. The remainder of `out_buffer` must
    ///   have at least the size as determined by
    ///   [`ExtentsCoveringAuthDigests::encoded_len()`].
    fn new(
        transaction: Box<Transaction>,
        covered_extents: extents::PhysicalExtents,
        out_buffer: FixedVec<u8, 0>,
        out_buffer_destination_offset: usize,
    ) -> Self {
        Self {
            transaction: Some(transaction),
            covered_extents,
            next_covered_extents_index: 0,
            last_auth_tree_data_block_allocation_blocks_end: layout::PhysicalAllocBlockIndex::from(0u64),
            out_buffer,
            out_buffer_pos: out_buffer_destination_offset,
            fut_state: TransactionCollectExtentsCoveringAuthDigestsFutureState::Init,
        }
    }

    /// Poll the [`TransactionCollectExtentsCoveringAuthDigestsFuture`] to
    /// completion.
    ///
    /// A pair of the output buffer initially passed to [`new()`](Self::new) and
    /// the operation result is returned back upon
    /// [`future`](TransactionCollectExtentsCoveringAuthDigestsFuture)
    /// completion. On success, a pair of the [`Transaction`] and the position
    /// in the output buffer immediately past the encoded contents is
    /// returned back for the result. Otherwise, on error,
    /// the [`Transaction`], if still available, gets returned back alongside
    /// the error reason.
    ///
    /// # Arguments:
    ///
    /// * `fs_instance_sync_state` - Exclusive reference to
    ///   [`CocoonFs::sync_state`].
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    #[allow(clippy::type_complexity)]
    pub fn poll<ST: sync_types::SyncTypes>(
        self: pin::Pin<&mut Self>,
        mut fs_instance_sync_state: CocoonFsSyncStateMemberMutRef<'_, ST, C>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<(
        FixedVec<u8, 0>,
        Result<(Box<Transaction>, usize), (Option<Box<Transaction>>, NvFsError)>,
    )> {
        let this = pin::Pin::into_inner(self);
        loop {
            match &mut this.fut_state {
                TransactionCollectExtentsCoveringAuthDigestsFutureState::Init => {
                    if this.covered_extents.is_empty() {
                        this.fut_state = TransactionCollectExtentsCoveringAuthDigestsFutureState::Done;
                        let transaction = match this.transaction.take() {
                            Some(transaction) => transaction,
                            None => {
                                return task::Poll::Ready((
                                    mem::take(&mut this.out_buffer),
                                    Err((None, nvfs_err_internal!())),
                                ));
                            }
                        };
                        return task::Poll::Ready((
                            mem::take(&mut this.out_buffer),
                            Ok((transaction, this.out_buffer_pos)),
                        ));
                    }

                    this.fut_state = TransactionCollectExtentsCoveringAuthDigestsFutureState::LookupModified;
                }
                TransactionCollectExtentsCoveringAuthDigestsFutureState::LookupModified => {
                    let transaction = match this.transaction.take() {
                        Some(transaction) => transaction,
                        None => {
                            this.fut_state = TransactionCollectExtentsCoveringAuthDigestsFutureState::Done;
                            return task::Poll::Ready((
                                mem::take(&mut this.out_buffer),
                                Err((None, nvfs_err_internal!())),
                            ));
                        }
                    };

                    let auth_tree_data_block_allocation_blocks_log2 = fs_instance_sync_state
                        .get_fs_ref()
                        .fs_config
                        .image_layout
                        .auth_tree_data_block_allocation_blocks_log2
                        as u32;

                    debug_assert!(this.next_covered_extents_index < this.covered_extents.len());
                    let mut cur_covered_extent = this.covered_extents.get_extent_range(this.next_covered_extents_index);
                    debug_assert!(cur_covered_extent.end() > this.last_auth_tree_data_block_allocation_blocks_end);

                    let mut cur_auth_tree_data_block_allocation_blocks_begin = cur_covered_extent
                        .begin()
                        .align_down(auth_tree_data_block_allocation_blocks_log2)
                        .max(this.last_auth_tree_data_block_allocation_blocks_end);
                    let update_states = &transaction.auth_tree_data_blocks_update_states;
                    let mut update_states_index = match update_states.lookup_auth_tree_data_block_update_state_index(
                        cur_auth_tree_data_block_allocation_blocks_begin,
                    ) {
                        Ok(update_states_index) => update_states_index,
                        Err(update_states_index) => update_states_index,
                    };
                    // Take as much consecutive digests starting at the current position in the
                    // transactions' update states as possible.
                    while usize::from(update_states_index) != update_states.len()
                        && cur_auth_tree_data_block_allocation_blocks_begin
                            == update_states[update_states_index].get_target_allocation_blocks_begin()
                    {
                        let auth_tree_data_block_digest = match update_states[update_states_index].get_auth_digest() {
                            Some(auth_tree_data_block_digest) => auth_tree_data_block_digest,
                            None => {
                                // The Authentication Tree Data Block's update state has no
                                // authentication digest, meaning there are no modifications to it.
                                update_states_index = update_states_index.step();
                                break;
                            }
                        };
                        let out_buffer = &mut this.out_buffer[this.out_buffer_pos..];
                        let remaining_len = leb128::leb128u_u64_encode(
                            out_buffer,
                            u64::from(
                                cur_auth_tree_data_block_allocation_blocks_begin
                                    - this.last_auth_tree_data_block_allocation_blocks_end,
                            ) >> auth_tree_data_block_allocation_blocks_log2,
                        )
                        .len();
                        this.out_buffer_pos += out_buffer.len() - remaining_len;
                        let digest_len = auth_tree_data_block_digest.len();
                        if digest_len > remaining_len {
                            this.fut_state = TransactionCollectExtentsCoveringAuthDigestsFutureState::Done;
                            return task::Poll::Ready((
                                mem::take(&mut this.out_buffer),
                                Err((Some(transaction), nvfs_err_internal!())),
                            ));
                        }
                        this.out_buffer[this.out_buffer_pos..this.out_buffer_pos + digest_len]
                            .copy_from_slice(auth_tree_data_block_digest);
                        this.out_buffer_pos += digest_len;

                        cur_auth_tree_data_block_allocation_blocks_begin +=
                            layout::AllocBlockCount::from(1u64 << auth_tree_data_block_allocation_blocks_log2);
                        this.last_auth_tree_data_block_allocation_blocks_end =
                            cur_auth_tree_data_block_allocation_blocks_begin;
                        update_states_index = update_states_index.step();

                        // Advance the position within the to be covered extent to the end of what's
                        // been covered up to now.
                        while cur_covered_extent.end() <= this.last_auth_tree_data_block_allocation_blocks_end {
                            let last_extent_allocation_blocks_end = cur_covered_extent.end();
                            this.next_covered_extents_index += 1;
                            if this.next_covered_extents_index == this.covered_extents.len() {
                                this.fut_state = TransactionCollectExtentsCoveringAuthDigestsFutureState::Done;
                                return task::Poll::Ready((
                                    mem::take(&mut this.out_buffer),
                                    Ok((transaction, this.out_buffer_pos)),
                                ));
                            }
                            cur_covered_extent = this.covered_extents.get_extent_range(this.next_covered_extents_index);
                            if cur_covered_extent.begin() < last_extent_allocation_blocks_end {
                                // The extents are not sorted, but they should.
                                this.fut_state = TransactionCollectExtentsCoveringAuthDigestsFutureState::Done;
                                return task::Poll::Ready((
                                    mem::take(&mut this.out_buffer),
                                    Err((Some(transaction), nvfs_err_internal!())),
                                ));
                            }
                            cur_auth_tree_data_block_allocation_blocks_begin = cur_covered_extent
                                .begin()
                                .align_down(auth_tree_data_block_allocation_blocks_log2)
                                .max(this.last_auth_tree_data_block_allocation_blocks_end);
                        }
                    }

                    debug_assert_ne!(this.next_covered_extents_index, this.covered_extents.len());
                    if usize::from(update_states_index) != update_states.len()
                        && update_states[update_states_index].get_target_allocation_blocks_begin()
                            < cur_auth_tree_data_block_allocation_blocks_begin
                    {
                        // The next update states index entry corresponds to a position before the
                        // current one (which is possible only if the code above advanced to the
                        // next extent in covered_extents), redo the lookup.
                        this.transaction = Some(transaction);
                        continue;
                    }
                    debug_assert!(
                        usize::from(update_states_index) == update_states.len()
                            || update_states[update_states_index].get_target_allocation_blocks_begin()
                                > cur_auth_tree_data_block_allocation_blocks_begin
                    );

                    // Authentication Tree Data Block is not modified by the transaction. Obtain the
                    // digest from the tree.
                    let auth_tree_config = fs_instance_sync_state.auth_tree.get_config();
                    let cur_auth_tree_data_block_index = auth_tree_config
                        .translate_physical_to_data_block_index(cur_auth_tree_data_block_allocation_blocks_begin);
                    let auth_tree_leaf_node_id = auth_tree_config.covering_leaf_node_id(cur_auth_tree_data_block_index);
                    let auth_tree_leaf_node_load_fut = auth_tree::AuthTreeNodeLoadFuture::new(auth_tree_leaf_node_id);
                    this.transaction = Some(transaction);
                    this.fut_state = TransactionCollectExtentsCoveringAuthDigestsFutureState::LoadAuthTreeLeafNode {
                        cur_auth_tree_data_block_allocation_blocks_begin,
                        cur_auth_tree_data_block_index,
                        next_transaction_update_states_index: update_states_index,
                        auth_tree_leaf_node_id,
                        auth_tree_leaf_node_load_fut,
                    };
                }
                TransactionCollectExtentsCoveringAuthDigestsFutureState::LoadAuthTreeLeafNode {
                    cur_auth_tree_data_block_allocation_blocks_begin,
                    cur_auth_tree_data_block_index,
                    next_transaction_update_states_index,
                    auth_tree_leaf_node_id,
                    auth_tree_leaf_node_load_fut,
                } => {
                    let mut fs_instance_sync_state = CocoonFsSyncStateMemberRef::from(&mut fs_instance_sync_state);
                    let (
                        fs_instance,
                        _fs_sync_state_image_size,
                        _fs_sync_state_alloc_bitmap,
                        _fs_sync_state_alloc_bitmap_file,
                        mut fs_sync_state_auth_tree,
                        _fs_sync_state_inode_index,
                        _fs_sync_state_read_buffer,
                        _fs_sync_state_keys_cache,
                    ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();

                    let (auth_tree_config, auth_tree_root_hmac_digest, mut auth_tree_node_cache) =
                        fs_sync_state_auth_tree.destructure_borrow();
                    let leaf_node = match auth_tree::AuthTreeNodeLoadFuture::poll(
                        pin::Pin::new(auth_tree_leaf_node_load_fut),
                        &fs_instance.chip,
                        auth_tree_config,
                        auth_tree_root_hmac_digest,
                        &mut auth_tree_node_cache,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(leaf_node)) => leaf_node,
                        task::Poll::Ready(Err(e)) => {
                            this.fut_state = TransactionCollectExtentsCoveringAuthDigestsFutureState::Done;
                            return task::Poll::Ready((
                                mem::take(&mut this.out_buffer),
                                Err((this.transaction.take(), e)),
                            ));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let transaction = match this.transaction.take() {
                        Some(transaction) => transaction,
                        None => {
                            this.fut_state = TransactionCollectExtentsCoveringAuthDigestsFutureState::Done;
                            return task::Poll::Ready((
                                mem::take(&mut this.out_buffer),
                                Err((None, nvfs_err_internal!())),
                            ));
                        }
                    };
                    let transaction_update_states = &transaction.auth_tree_data_blocks_update_states;

                    let auth_tree_data_block_allocation_blocks_log2 = fs_instance
                        .fs_config
                        .image_layout
                        .auth_tree_data_block_allocation_blocks_log2
                        as u32;

                    // Now that we've got the Authentication Tree leaf node loaded, obtain all
                    // digests in its range from it. Note that the covered range might be
                    // interspersed with Authentication Tree Data Blocks modified by the
                    // transaction, in which case the corresponding updated digests must be taken
                    // from there.
                    let auth_tree_leaf_node_last_covered_data_block_index =
                        auth_tree_leaf_node_id.last_covered_data_block();
                    loop {
                        let out_buffer = &mut this.out_buffer[this.out_buffer_pos..];
                        let remaining_len = leb128::leb128u_u64_encode(
                            out_buffer,
                            u64::from(
                                *cur_auth_tree_data_block_allocation_blocks_begin
                                    - this.last_auth_tree_data_block_allocation_blocks_end,
                            ) >> auth_tree_data_block_allocation_blocks_log2,
                        )
                        .len();
                        this.out_buffer_pos += out_buffer.len() - remaining_len;
                        let auth_tree_data_block_digest = match auth_tree_config
                            .get_data_block_digest_entry_from_tree(&leaf_node, *cur_auth_tree_data_block_index)
                        {
                            Ok(auth_tree_data_block_digest) => auth_tree_data_block_digest,
                            Err(e) => {
                                this.fut_state = TransactionCollectExtentsCoveringAuthDigestsFutureState::Done;
                                return task::Poll::Ready((
                                    mem::take(&mut this.out_buffer),
                                    Err((Some(transaction), e)),
                                ));
                            }
                        };
                        let digest_len = auth_tree_data_block_digest.len();
                        if digest_len > remaining_len {
                            this.fut_state = TransactionCollectExtentsCoveringAuthDigestsFutureState::Done;
                            return task::Poll::Ready((
                                mem::take(&mut this.out_buffer),
                                Err((Some(transaction), nvfs_err_internal!())),
                            ));
                        }
                        this.out_buffer[this.out_buffer_pos..this.out_buffer_pos + digest_len]
                            .copy_from_slice(auth_tree_data_block_digest);
                        this.out_buffer_pos += digest_len;

                        *cur_auth_tree_data_block_allocation_blocks_begin +=
                            layout::AllocBlockCount::from(1u64 << auth_tree_data_block_allocation_blocks_log2);
                        this.last_auth_tree_data_block_allocation_blocks_end =
                            *cur_auth_tree_data_block_allocation_blocks_begin;
                        *cur_auth_tree_data_block_index += auth_tree::AuthTreeDataBlockCount::from(1u64);

                        // Advance the position within the to be covered extent to the end of what's
                        // been covered up to now.
                        let mut crossed_extent = false;
                        let mut cur_covered_extent =
                            this.covered_extents.get_extent_range(this.next_covered_extents_index);
                        while cur_covered_extent.end() <= this.last_auth_tree_data_block_allocation_blocks_end {
                            let last_extent_allocation_blocks_end = cur_covered_extent.end();
                            this.next_covered_extents_index += 1;
                            if this.next_covered_extents_index == this.covered_extents.len() {
                                this.fut_state = TransactionCollectExtentsCoveringAuthDigestsFutureState::Done;
                                return task::Poll::Ready((
                                    mem::take(&mut this.out_buffer),
                                    Ok((transaction, this.out_buffer_pos)),
                                ));
                            }
                            crossed_extent = true;
                            cur_covered_extent = this.covered_extents.get_extent_range(this.next_covered_extents_index);
                            if cur_covered_extent.begin() < last_extent_allocation_blocks_end {
                                // The extents are not sorted, but they should.
                                this.fut_state = TransactionCollectExtentsCoveringAuthDigestsFutureState::Done;
                                return task::Poll::Ready((
                                    mem::take(&mut this.out_buffer),
                                    Err((Some(transaction), nvfs_err_internal!())),
                                ));
                            }
                            *cur_auth_tree_data_block_allocation_blocks_begin = cur_covered_extent
                                .begin()
                                .align_down(auth_tree_data_block_allocation_blocks_log2)
                                .max(this.last_auth_tree_data_block_allocation_blocks_end);
                        }
                        debug_assert_ne!(this.next_covered_extents_index, this.covered_extents.len());

                        if usize::from(*next_transaction_update_states_index) != transaction_update_states.len()
                            && transaction_update_states[*next_transaction_update_states_index]
                                .get_target_allocation_blocks_begin()
                                < *cur_auth_tree_data_block_allocation_blocks_begin
                        {
                            // The current cursor into the transaction's update states corresponds
                            // to a position before the current one (which is possible only if the
                            // code above advanced to the next extent in covered_extents). If the
                            // latter is still covered by the current containing Authentication Tree
                            // leaf node, then simply advance by a linear search (of bounded
                            // distance). Otherwise continue from scratch with a binary search
                            // lookup within the update states.

                            // If in a new extent, then the Authentication Tree Data Block index cannot
                            // simply get incremented linearly (as it's been
                            // done up to point), but must be found through a lookup.
                            if crossed_extent {
                                *cur_auth_tree_data_block_index = auth_tree_config
                                    .translate_physical_to_data_block_index(
                                        *cur_auth_tree_data_block_allocation_blocks_begin,
                                    );
                                crossed_extent = false;
                            }
                            debug_assert!(u64::from(*cur_auth_tree_data_block_index) != 0);
                            if auth_tree::AuthTreeDataBlockIndex::from(
                                u64::from(*cur_auth_tree_data_block_index) - 1u64,
                            ) <= auth_tree_leaf_node_last_covered_data_block_index
                            {
                                loop {
                                    *next_transaction_update_states_index = next_transaction_update_states_index.step();
                                    if usize::from(*next_transaction_update_states_index)
                                        == transaction_update_states.len()
                                        || transaction_update_states[*next_transaction_update_states_index]
                                            .get_target_allocation_blocks_begin()
                                            >= *cur_auth_tree_data_block_allocation_blocks_begin
                                    {
                                        break;
                                    }
                                }
                            } else {
                                this.transaction = Some(transaction);
                                this.fut_state =
                                    TransactionCollectExtentsCoveringAuthDigestsFutureState::LookupModified;
                                break;
                            }
                        }
                        debug_assert!(
                            usize::from(*next_transaction_update_states_index) == transaction_update_states.len()
                                || transaction_update_states[*next_transaction_update_states_index]
                                    .get_target_allocation_blocks_begin()
                                    >= *cur_auth_tree_data_block_allocation_blocks_begin
                        );

                        while usize::from(*next_transaction_update_states_index) != transaction_update_states.len()
                            && *cur_auth_tree_data_block_allocation_blocks_begin
                                == transaction_update_states[*next_transaction_update_states_index]
                                    .get_target_allocation_blocks_begin()
                        {
                            let auth_tree_data_block_digest = match transaction_update_states
                                [*next_transaction_update_states_index]
                                .get_auth_digest()
                            {
                                Some(auth_tree_data_block_digest) => auth_tree_data_block_digest,
                                None => {
                                    // The Authentication Tree Data Block's update state has no
                                    // authentication digest, meaning there are no modifications to it.
                                    *next_transaction_update_states_index = next_transaction_update_states_index.step();
                                    break;
                                }
                            };
                            let out_buffer = &mut this.out_buffer[this.out_buffer_pos..];
                            let remaining_len = leb128::leb128u_u64_encode(
                                out_buffer,
                                u64::from(
                                    *cur_auth_tree_data_block_allocation_blocks_begin
                                        - this.last_auth_tree_data_block_allocation_blocks_end,
                                ) >> auth_tree_data_block_allocation_blocks_log2,
                            )
                            .len();
                            this.out_buffer_pos += out_buffer.len() - remaining_len;
                            let digest_len = auth_tree_data_block_digest.len();
                            if digest_len > remaining_len {
                                this.fut_state = TransactionCollectExtentsCoveringAuthDigestsFutureState::Done;
                                return task::Poll::Ready((
                                    mem::take(&mut this.out_buffer),
                                    Err((Some(transaction), nvfs_err_internal!())),
                                ));
                            }
                            this.out_buffer[this.out_buffer_pos..this.out_buffer_pos + digest_len]
                                .copy_from_slice(auth_tree_data_block_digest);
                            this.out_buffer_pos += digest_len;

                            *cur_auth_tree_data_block_allocation_blocks_begin +=
                                layout::AllocBlockCount::from(1u64 << auth_tree_data_block_allocation_blocks_log2);
                            this.last_auth_tree_data_block_allocation_blocks_end =
                                *cur_auth_tree_data_block_allocation_blocks_begin;
                            *cur_auth_tree_data_block_index += auth_tree::AuthTreeDataBlockCount::from(1u64);
                            *next_transaction_update_states_index = next_transaction_update_states_index.step();

                            // Advance the position within the to be covered extent to the end of what's
                            // been covered up to now.
                            while cur_covered_extent.end() <= this.last_auth_tree_data_block_allocation_blocks_end {
                                let last_extent_allocation_blocks_end = cur_covered_extent.end();
                                this.next_covered_extents_index += 1;
                                if this.next_covered_extents_index == this.covered_extents.len() {
                                    this.fut_state = TransactionCollectExtentsCoveringAuthDigestsFutureState::Done;
                                    return task::Poll::Ready((
                                        mem::take(&mut this.out_buffer),
                                        Ok((transaction, this.out_buffer_pos)),
                                    ));
                                }
                                crossed_extent = true;
                                cur_covered_extent =
                                    this.covered_extents.get_extent_range(this.next_covered_extents_index);
                                if cur_covered_extent.begin() < last_extent_allocation_blocks_end {
                                    // The extents are not sorted, but they should.
                                    this.fut_state = TransactionCollectExtentsCoveringAuthDigestsFutureState::Done;
                                    return task::Poll::Ready((
                                        mem::take(&mut this.out_buffer),
                                        Err((Some(transaction), nvfs_err_internal!())),
                                    ));
                                }
                                *cur_auth_tree_data_block_allocation_blocks_begin = cur_covered_extent
                                    .begin()
                                    .align_down(auth_tree_data_block_allocation_blocks_log2)
                                    .max(this.last_auth_tree_data_block_allocation_blocks_end);
                            }
                        }
                        debug_assert_ne!(this.next_covered_extents_index, this.covered_extents.len());
                        debug_assert!(
                            usize::from(*next_transaction_update_states_index) == transaction_update_states.len()
                                || *cur_auth_tree_data_block_allocation_blocks_begin
                                    < transaction_update_states[*next_transaction_update_states_index]
                                        .get_target_allocation_blocks_begin()
                        );
                        // If in a new extent, then the Authentication Tree Data Block index cannot
                        // simply get incremented linearly (as it's been
                        // done up to point), but must be found through a lookup.
                        if crossed_extent {
                            *cur_auth_tree_data_block_index = auth_tree_config.translate_physical_to_data_block_index(
                                *cur_auth_tree_data_block_allocation_blocks_begin,
                            );
                        }

                        // The Authentication Tree Data Block at the current position had not been
                        // modified by the transaction.  What to do next depends on whether we're
                        // still within the current Authentication Tree Leaf node's covered range.
                        // If yes, then loop over and read the next digest from it. Otherwise
                        // continue with loading the next leaf node.
                        if *cur_auth_tree_data_block_index > auth_tree_leaf_node_last_covered_data_block_index {
                            *auth_tree_leaf_node_id =
                                auth_tree_config.covering_leaf_node_id(*cur_auth_tree_data_block_index);
                            *auth_tree_leaf_node_load_fut =
                                auth_tree::AuthTreeNodeLoadFuture::new(*auth_tree_leaf_node_id);
                            this.transaction = Some(transaction);
                            break;
                        }
                    }
                }
                TransactionCollectExtentsCoveringAuthDigestsFutureState::Done => unreachable!(),
            }
        }
    }
}

/// [`NvChipWriteRequest`](chip::NvChipWriteRequest) implementation used
/// internally by [`TransactionWriteJournalFuture`].
struct WriteJournalLogExtentChipRequest {
    region: ChunkedIoRegion,
    src: FixedVec<u8, 7>,
    allocation_block_size_128b_log2: u8,
}

impl WriteJournalLogExtentChipRequest {
    pub fn new(
        extent: &layout::PhysicalAllocBlockRange,
        src: FixedVec<u8, 7>,
        allocation_block_size_128b_log2: u8,
    ) -> Result<Self, NvFsError> {
        let physical_begin_128b = u64::from(extent.begin()) << (allocation_block_size_128b_log2 as u32);
        if physical_begin_128b >> (allocation_block_size_128b_log2 as u32) != u64::from(extent.begin()) {
            return Err(nvfs_err_internal!());
        }
        let physical_end_128b = u64::from(extent.end()) << (allocation_block_size_128b_log2 as u32);
        if physical_end_128b >> (allocation_block_size_128b_log2 as u32) != u64::from(extent.end()) {
            return Err(nvfs_err_internal!());
        }
        // The buffer is not chunked, simply use the maximum possible safe value of an
        // Allocation Block size.
        let region = ChunkedIoRegion::new(
            physical_begin_128b,
            physical_end_128b,
            allocation_block_size_128b_log2 as u32,
        )
        .map_err(|_| nvfs_err_internal!())?;

        Ok(Self {
            region,
            src,
            allocation_block_size_128b_log2,
        })
    }
}

impl chip::NvChipWriteRequest for WriteJournalLogExtentChipRequest {
    fn region(&self) -> &ChunkedIoRegion {
        &self.region
    }

    fn get_source_buffer(&self, range: &ChunkedIoRegionChunkRange) -> Result<&[u8], chip::NvChipIoError> {
        let allocation_block_index = range.chunk().decompose_to_hierarchic_indices([]).0;
        let allocation_block_offset_in_src =
            allocation_block_index << (self.allocation_block_size_128b_log2 as u32 + 7);
        let range_in_allocation_block = range.range_in_chunk();
        Ok(
            &self.src[allocation_block_offset_in_src + range_in_allocation_block.start
                ..allocation_block_offset_in_src + range_in_allocation_block.end],
        )
    }
}
