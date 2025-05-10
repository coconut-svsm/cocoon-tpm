// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`WriteInodeDataFuture`].

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

use crate::{
    chip,
    crypto::symcipher,
    fs::{
        cocoonfs::{
            alloc_bitmap::{self, ExtentsAllocationRequest, ExtentsReallocationRequest},
            encryption_entities::{EncryptedExtentsEncryptionInstance, EncryptedExtentsLayout},
            extents,
            fs::{CocoonFsAllocateExtentsFuture, CocoonFsSyncStateMemberRef, CocoonFsSyncStateReadFuture},
            inode_extents_list::{InodeExtentsListReadFuture, InodeExtentsListWriteFuture},
            inode_index::{
                InodeIndexInsertEntryFuture, InodeIndexKeyType, InodeIndexLookupForInsertFuture,
                InodeIndexLookupForInsertResult, InodeKeySubdomain,
            },
            keys, layout, transaction, CocoonFsFormatError,
        },
        NvFsError,
    },
    nvfs_err_internal, tpm2_interface,
    utils_async::sync_types,
    utils_common::{
        io_slices::{self, IoSlicesIterCommon as _},
        zeroize,
    },
};
use core::{default, mem, pin, task};

pub struct WriteInodeDataFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    inode: InodeIndexKeyType,
    data: zeroize::Zeroizing<Vec<u8>>,
    fut_state: WriteInodeDataFutureState<ST, C>,
}

#[allow(clippy::large_enum_variant)]
enum WriteInodeDataFutureState<ST: sync_types::SyncTypes, C: chip::NvChip> {
    LookupInode {
        inode_index_lookup_fut: InodeIndexLookupForInsertFuture<ST, C>,
    },
    ReadInodeExtentsList {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        inode_index_lookup_result: Option<InodeIndexLookupForInsertResult>,
        read_inode_extents_list_fut: InodeExtentsListReadFuture<ST, C>,
    },
    AllocateInodeExtentsPrepare {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<transaction::Transaction>>,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        inode_index_lookup_result: Option<InodeIndexLookupForInsertResult>,
        preexisting_inode_extents: Option<PreexistingInodeExtents>,
    },
    AllocateInodeExtents {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        inode_index_lookup_result: Option<InodeIndexLookupForInsertResult>,
        preexisting_inode_extents: Option<PreexistingInodeExtents>,
        inode_extents_encryption_layout: EncryptedExtentsLayout,
        allocate_fut: CocoonFsAllocateExtentsFuture<ST, C>,
    },
    WriteInodeDataUpdates {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<transaction::Transaction>>,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        inode_index_lookup_result: Option<InodeIndexLookupForInsertResult>,
        preexisting_inode_extents_list_extents: Option<extents::PhysicalExtents>,
        inode_extents_encryption_layout: EncryptedExtentsLayout,
        new_inode_extents: extents::PhysicalExtents,
        pending_inode_extents_reallocation: InodeExtentsPendingReallocation,
    },
    UpdateInodeExtentsList {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        inode_index_lookup_result: Option<InodeIndexLookupForInsertResult>,
        pending_inode_extents_reallocation: InodeExtentsPendingReallocation,
        write_inode_extents_list_fut: InodeExtentsListWriteFuture<ST, C>,
    },
    UpdateInodeIndex {
        new_inode_extents: extents::PhysicalExtents,
        inode_index_insert_entry_fut: InodeIndexInsertEntryFuture<ST, C>,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> WriteInodeDataFuture<ST, C> {
    pub fn new(
        mut transaction: Box<transaction::Transaction>,
        inode: InodeIndexKeyType,
        data: zeroize::Zeroizing<Vec<u8>>,
    ) -> Self {
        // Start in a clean rollback state.
        transaction.allocs.reset_rollback();
        let inode_index_lookup_fut = InodeIndexLookupForInsertFuture::new(transaction, inode);
        Self {
            inode,
            data,
            fut_state: WriteInodeDataFutureState::LookupInode { inode_index_lookup_fut },
        }
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsSyncStateReadFuture<ST, C> for WriteInodeDataFuture<ST, C> {
    type Output = Result<
        (
            Box<transaction::Transaction>,
            zeroize::Zeroizing<Vec<u8>>,
            Result<(), NvFsError>,
        ),
        NvFsError,
    >;

    type AuxPollData<'a> = ();

    fn poll<'a>(
        self: pin::Pin<&mut Self>,
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, C>,
        _aux_data: &mut Self::AuxPollData<'a>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        let (mut transaction, e) = 'outer: loop {
            match &mut this.fut_state {
                WriteInodeDataFutureState::LookupInode { inode_index_lookup_fut } => {
                    let (transaction, inode_index_lookup_result) = match CocoonFsSyncStateReadFuture::poll(
                        pin::Pin::new(inode_index_lookup_fut),
                        fs_instance_sync_state,
                        &mut (),
                        cx,
                    ) {
                        task::Poll::Ready(Ok((transaction, Ok(inode_index_lookup_result)))) => {
                            (transaction, inode_index_lookup_result)
                        }
                        task::Poll::Ready(Ok((transaction, Err(e)))) => break (Some(transaction), e),
                        task::Poll::Ready(Err(e)) => break (None, e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    if let Some(inode_index_entry_preexisting_extent_ptr) =
                        inode_index_lookup_result.get_preexisting_extent_ptr()
                    {
                        let (
                            fs_instance,
                            _fs_sync_state_image_size,
                            _fs_sync_state_alloc_bitmap,
                            _fs_sync_state_alloc_bitmap_file,
                            _fs_sync_state_auth_tree,
                            _fs_sync_state_inode_index,
                            _fs_sync_state_read_buffer,
                            mut fs_sync_state_keys_cache,
                        ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();
                        match inode_index_entry_preexisting_extent_ptr
                            .decode(fs_instance.fs_config.image_layout.allocation_block_size_128b_log2 as u32)
                        {
                            Ok(Some((inode_extent, false))) => {
                                // The inode index entry references the inode's (single) extent directly.
                                let preexisting_inode_extents = match PreexistingInodeExtents::new_direct(inode_extent)
                                {
                                    Ok(preexisting_inode_extents) => preexisting_inode_extents,
                                    Err(e) => break (Some(transaction), e),
                                };
                                this.fut_state = WriteInodeDataFutureState::AllocateInodeExtentsPrepare {
                                    transaction: Some(transaction),
                                    inode_index_lookup_result: Some(inode_index_lookup_result),
                                    preexisting_inode_extents: Some(preexisting_inode_extents),
                                };
                            }
                            Ok(Some((_first_inode_extents_list_extent, true))) => {
                                // The inode index entry references an indirect inode extents list.
                                let read_inode_extents_list_fut = match InodeExtentsListReadFuture::new(
                                    Some(transaction),
                                    this.inode,
                                    &inode_index_entry_preexisting_extent_ptr,
                                    &fs_instance.fs_config.root_key,
                                    &mut fs_sync_state_keys_cache,
                                    &fs_instance.fs_config.image_layout,
                                ) {
                                    Ok(read_inode_extents_list_fut) => read_inode_extents_list_fut,
                                    Err((transaction, e)) => break (transaction, e),
                                };
                                this.fut_state = WriteInodeDataFutureState::ReadInodeExtentsList {
                                    inode_index_lookup_result: Some(inode_index_lookup_result),
                                    read_inode_extents_list_fut,
                                };
                            }
                            Ok(None) => {
                                // The inode exists, but the extents reference is nil.
                                break (Some(transaction), NvFsError::from(CocoonFsFormatError::InvalidExtents));
                            }
                            Err(e) => break (Some(transaction), e),
                        };
                    } else {
                        // The inode does not exist yet.
                        this.fut_state = WriteInodeDataFutureState::AllocateInodeExtentsPrepare {
                            transaction: Some(transaction),
                            inode_index_lookup_result: Some(inode_index_lookup_result),
                            preexisting_inode_extents: None,
                        };
                    }
                }
                WriteInodeDataFutureState::ReadInodeExtentsList {
                    inode_index_lookup_result,
                    read_inode_extents_list_fut,
                } => {
                    let (transaction, preexisting_inode_extents_list_extents, preexisting_inode_extents) =
                        match CocoonFsSyncStateReadFuture::poll(
                            pin::Pin::new(read_inode_extents_list_fut),
                            fs_instance_sync_state,
                            &mut (),
                            cx,
                        ) {
                            task::Poll::Ready((
                                transaction,
                                Ok((preexisting_inode_extents_list_extents, preexisting_inode_extents)),
                            )) => {
                                let transaction = match transaction {
                                    Some(transaction) => transaction,
                                    None => break (None, nvfs_err_internal!()),
                                };
                                (
                                    transaction,
                                    preexisting_inode_extents_list_extents,
                                    preexisting_inode_extents,
                                )
                            }
                            task::Poll::Ready((transaction, Err(e))) => break (transaction, e),
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    let preexisting_inode_extents = PreexistingInodeExtents::new_indirect(
                        preexisting_inode_extents_list_extents,
                        preexisting_inode_extents,
                    );
                    this.fut_state = WriteInodeDataFutureState::AllocateInodeExtentsPrepare {
                        transaction: Some(transaction),
                        inode_index_lookup_result: inode_index_lookup_result.take(),
                        preexisting_inode_extents: Some(preexisting_inode_extents),
                    };
                }
                WriteInodeDataFutureState::AllocateInodeExtentsPrepare {
                    transaction,
                    inode_index_lookup_result,
                    preexisting_inode_extents: fut_preexisting_inode_extents,
                } => {
                    let transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => break (None, nvfs_err_internal!()),
                    };
                    let image_layout = &fs_instance_sync_state.get_fs_ref().fs_config.image_layout;
                    let inode_extents_encryption_layout = match EncryptedExtentsLayout::new(
                        image_layout.block_cipher_alg,
                        image_layout.allocation_block_size_128b_log2,
                    ) {
                        Ok(inode_extents_encryption_layout) => inode_extents_encryption_layout,
                        Err(e) => break (Some(transaction), e),
                    };
                    let inode_extents_allocation_layout = match inode_extents_encryption_layout.get_extents_layout() {
                        Ok(inode_extents_allocation_layout) => inode_extents_allocation_layout,
                        Err(e) => break (Some(transaction), e),
                    };

                    // Plus one for the CBC padding.
                    let data_len = match u64::try_from(this.data.len())
                        .ok()
                        .and_then(|data_len| data_len.checked_add(1))
                    {
                        Some(data_len) => data_len,
                        None => {
                            break (Some(transaction), NvFsError::from(CocoonFsFormatError::InvalidFileSize));
                        }
                    };

                    let inode_extents_allocation_request = match fut_preexisting_inode_extents.take() {
                        Some(mut preexisting_inode_extents) => {
                            match ExtentsAllocationRequest::new_reallocate(
                                &preexisting_inode_extents.extents,
                                data_len,
                                &inode_extents_allocation_layout,
                            ) {
                                Ok(ExtentsReallocationRequest::Keep) => {
                                    let preexisting_inode_extents_list_extents =
                                        preexisting_inode_extents.extents_list_extents.take();
                                    let pending_inode_extents_reallocation = InodeExtentsPendingReallocation::None;
                                    // The new inode data fits exactly into preexisting extents
                                    // extents. Jump directly to the update.
                                    this.fut_state = WriteInodeDataFutureState::WriteInodeDataUpdates {
                                        transaction: Some(transaction),
                                        inode_index_lookup_result: inode_index_lookup_result.take(),
                                        preexisting_inode_extents_list_extents,
                                        inode_extents_encryption_layout,
                                        new_inode_extents: mem::replace(
                                            &mut preexisting_inode_extents.extents,
                                            extents::PhysicalExtents::new(),
                                        ),
                                        pending_inode_extents_reallocation,
                                    };
                                    continue;
                                }
                                Ok(ExtentsReallocationRequest::Shrink {
                                    last_retained_extent_index,
                                    last_retained_extent_allocation_blocks,
                                }) => {
                                    let preexisting_inode_extents_list_extents =
                                        preexisting_inode_extents.extents_list_extents.take();
                                    let preexisting_inode_extents = mem::replace(
                                        &mut preexisting_inode_extents.extents,
                                        extents::PhysicalExtents::new(),
                                    );
                                    // The new inode extents lists fits into less space than what's
                                    // provided by the preexisting extents. Split off excess, free
                                    // it and jump directly to the update.
                                    let (retained_inode_extents, excess_preexisting_inode_extents) =
                                        match preexisting_inode_extents
                                            .split(last_retained_extent_index, last_retained_extent_allocation_blocks)
                                        {
                                            Ok((head_extents, tail_extents)) => (head_extents, tail_extents),
                                            Err(e) => break (Some(transaction), e),
                                        };
                                    // Don't mark the excess extents as freed until after the index tree had
                                    // been updated: allocations made in the course of index tree node
                                    // splittings cannot get rolled back, so make sure that excess extents from
                                    // here will not get repurposed for index tree node blocks in the tree
                                    // update to follow shortly.
                                    let pending_inode_extents_reallocation =
                                        InodeExtentsPendingReallocation::Truncation {
                                            excess_preexisting_inode_extents,
                                            freed: false,
                                        };
                                    this.fut_state = WriteInodeDataFutureState::WriteInodeDataUpdates {
                                        transaction: Some(transaction),
                                        inode_index_lookup_result: inode_index_lookup_result.take(),
                                        preexisting_inode_extents_list_extents,
                                        inode_extents_encryption_layout,
                                        new_inode_extents: retained_inode_extents,
                                        pending_inode_extents_reallocation,
                                    };
                                    continue;
                                }
                                Ok(ExtentsReallocationRequest::Grow { request }) => {
                                    *fut_preexisting_inode_extents = Some(preexisting_inode_extents);
                                    request
                                }
                                Err(e) => break (Some(transaction), e),
                            }
                        }
                        None => ExtentsAllocationRequest::new(data_len, &inode_extents_allocation_layout),
                    };

                    let allocate_fut = match CocoonFsAllocateExtentsFuture::new(
                        &fs_instance_sync_state.get_fs_ref(),
                        transaction,
                        inode_extents_allocation_request,
                        false,
                    ) {
                        Ok(allocate_fut) => allocate_fut,
                        Err((transaction, e)) => break (transaction, e),
                    };
                    this.fut_state = WriteInodeDataFutureState::AllocateInodeExtents {
                        inode_index_lookup_result: inode_index_lookup_result.take(),
                        preexisting_inode_extents: fut_preexisting_inode_extents.take(),
                        inode_extents_encryption_layout,
                        allocate_fut,
                    };
                }
                WriteInodeDataFutureState::AllocateInodeExtents {
                    inode_index_lookup_result,
                    preexisting_inode_extents,
                    inode_extents_encryption_layout,
                    allocate_fut,
                } => {
                    let (transaction, allocated_extents) = match CocoonFsSyncStateReadFuture::poll(
                        pin::Pin::new(allocate_fut),
                        fs_instance_sync_state,
                        &mut (),
                        cx,
                    ) {
                        task::Poll::Ready(Ok((transaction, Ok(allocated_extents)))) => {
                            (transaction, allocated_extents.0)
                        }
                        task::Poll::Ready(Ok((transaction, Err(e)))) => break (Some(transaction), e),
                        task::Poll::Ready(Err(e)) => break (None, e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let (preexisting_inode_extents_list_extents, new_inode_extents) =
                        match preexisting_inode_extents.take() {
                            Some(PreexistingInodeExtents {
                                extents_list_extents: preexisting_inode_extents_list_extents,
                                extents: mut preexisting_inode_extents,
                            }) => {
                                if let Err(e) = preexisting_inode_extents.append_extents(&allocated_extents, false) {
                                    break match transaction.rollback_extents_allocation(
                                        allocated_extents.iter(),
                                        &fs_instance_sync_state.alloc_bitmap,
                                    ) {
                                        Ok(transaction) => (Some(transaction), e),
                                        Err(e) => (None, e),
                                    };
                                }
                                (preexisting_inode_extents_list_extents, preexisting_inode_extents)
                            }
                            None => match allocated_extents.try_clone() {
                                Ok(new_inode_extents) => (None, new_inode_extents),
                                Err(e) => {
                                    break match transaction.rollback_extents_allocation(
                                        allocated_extents.iter(),
                                        &fs_instance_sync_state.alloc_bitmap,
                                    ) {
                                        Ok(transaction) => (Some(transaction), e),
                                        Err(e) => (None, e),
                                    };
                                }
                            },
                        };

                    let pending_inode_extents_reallocation = InodeExtentsPendingReallocation::Extension {
                        allocated_inode_extents: allocated_extents,
                    };
                    this.fut_state = WriteInodeDataFutureState::WriteInodeDataUpdates {
                        transaction: Some(transaction),
                        inode_index_lookup_result: inode_index_lookup_result.take(),
                        preexisting_inode_extents_list_extents,
                        inode_extents_encryption_layout: inode_extents_encryption_layout.clone(),
                        new_inode_extents,
                        pending_inode_extents_reallocation,
                    };
                }
                WriteInodeDataFutureState::WriteInodeDataUpdates {
                    transaction,
                    inode_index_lookup_result,
                    preexisting_inode_extents_list_extents,
                    inode_extents_encryption_layout,
                    new_inode_extents,
                    pending_inode_extents_reallocation,
                } => {
                    let rollback = |mut transaction: Box<transaction::Transaction>,
                                    new_inode_extents: &extents::PhysicalExtents,
                                    pending_inode_extents_reallocation: InodeExtentsPendingReallocation,
                                    alloc_bitmap: &alloc_bitmap::AllocBitmap| {
                        // Only rollback the inode's extents reallocation, but not any data staged
                        // for update: there are no promises made for the contents upon failure
                        // except that the metadata is consistent. This allows for skipping the
                        // application of staged data on the data itself, if any, before the update
                        // operation here commences, on the downside that the previous state cannot
                        // get restored. Mark the inode's data intederminate.
                        transaction
                            .auth_tree_data_blocks_update_states
                            .reset_staged_extents_updates_to_failed(new_inode_extents.iter());
                        pending_inode_extents_reallocation.rollback(transaction, alloc_bitmap)
                    };

                    let mut transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => break (None, nvfs_err_internal!()),
                    };

                    // Prepare an encryption instance for the inode's data extents.
                    let (
                        fs_instance,
                        _fs_sync_state_image_size,
                        fs_sync_state_alloc_bitmap,
                        _fs_sync_state_alloc_bitmap_file,
                        _fs_sync_state_auth_tree,
                        _fs_sync_state_inode_index,
                        _fs_sync_state_read_buffer,
                        mut fs_sync_state_keys_cache,
                    ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();
                    let fs_root_key = &fs_instance.fs_config.root_key;
                    let image_layout = &fs_instance.fs_config.image_layout;
                    let extents_encryption_key = match keys::KeyCache::get_key(
                        &mut fs_sync_state_keys_cache,
                        fs_root_key,
                        &keys::KeyId::new(
                            this.inode,
                            InodeKeySubdomain::InodeData as u32,
                            keys::KeyPurpose::Encryption,
                        ),
                    ) {
                        Ok(extents_encryption_key) => extents_encryption_key,
                        Err(e) => {
                            break match rollback(
                                transaction,
                                new_inode_extents,
                                mem::take(pending_inode_extents_reallocation),
                                fs_sync_state_alloc_bitmap,
                            ) {
                                Ok(transaction) => (Some(transaction), e),
                                Err(e) => (None, e),
                            };
                        }
                    };
                    let extents_encryption_block_cipher_instance =
                        match symcipher::SymBlockCipherModeEncryptionInstance::new(
                            tpm2_interface::TpmiAlgCipherMode::Cbc,
                            &image_layout.block_cipher_alg,
                            &extents_encryption_key,
                        ) {
                            Ok(extents_encryption_block_cipher_instance) => extents_encryption_block_cipher_instance,
                            Err(e) => {
                                break match rollback(
                                    transaction,
                                    new_inode_extents,
                                    mem::take(pending_inode_extents_reallocation),
                                    fs_sync_state_alloc_bitmap,
                                ) {
                                    Ok(transaction) => (Some(transaction), NvFsError::from(e)),
                                    Err(e) => (None, e),
                                };
                            }
                        };
                    drop(extents_encryption_key);

                    let mut inode_extents_encryption_instance = match EncryptedExtentsEncryptionInstance::new(
                        inode_extents_encryption_layout,
                        extents_encryption_block_cipher_instance,
                    ) {
                        Ok(inode_extents_encryption_instance) => inode_extents_encryption_instance,
                        Err(e) => {
                            break match rollback(
                                transaction,
                                new_inode_extents,
                                mem::take(pending_inode_extents_reallocation),
                                fs_sync_state_alloc_bitmap,
                            ) {
                                Ok(transaction) => (Some(transaction), e),
                                Err(e) => (None, e),
                            };
                        }
                    };

                    // Walk through the inode extent extents one by one, prepare the destination
                    // staged update states and encrypt into them as we go.
                    let mut data = io_slices::SingletonIoSlice::new(&this.data).map_infallible_err();
                    for inode_extents_index in 0..new_inode_extents.len() {
                        let cur_inode_extent = new_inode_extents.get_extent_range(inode_extents_index);
                        let cur_update_states_allocation_blocks_range =
                            match transaction.auth_tree_data_blocks_update_states.insert_missing_in_range(
                                cur_inode_extent,
                                fs_sync_state_alloc_bitmap,
                                &transaction.allocs.pending_frees,
                                None,
                            ) {
                                Ok((cur_update_states_allocation_blocks_range, _)) => {
                                    cur_update_states_allocation_blocks_range
                                }
                                Err((e, _)) => {
                                    break 'outer match rollback(
                                        transaction,
                                        new_inode_extents,
                                        mem::take(pending_inode_extents_reallocation),
                                        fs_sync_state_alloc_bitmap,
                                    ) {
                                        Ok(transaction) => (Some(transaction), e),
                                        Err(e) => (None, e),
                                    };
                                }
                            };
                        if let Err(e) = transaction
                            .auth_tree_data_blocks_update_states
                            .allocate_allocation_blocks_update_staging_bufs(
                                &cur_update_states_allocation_blocks_range,
                                image_layout.allocation_block_size_128b_log2 as u32,
                            )
                        {
                            break 'outer match rollback(
                                transaction,
                                new_inode_extents,
                                mem::take(pending_inode_extents_reallocation),
                                fs_sync_state_alloc_bitmap,
                            ) {
                                Ok(transaction) => (Some(transaction), e),
                                Err(e) => (None, e),
                            };
                        }
                        let cur_update_states_allocation_blocks_update_staging_bufs_iter = match transaction
                            .auth_tree_data_blocks_update_states
                            .iter_allocation_blocks_update_staging_bufs_mut(&cur_update_states_allocation_blocks_range)
                        {
                            Ok(cur_update_states_allocation_blocks_update_staging_bufs_iter) => {
                                cur_update_states_allocation_blocks_update_staging_bufs_iter
                            }
                            Err(e) => {
                                break 'outer match rollback(
                                    transaction,
                                    new_inode_extents,
                                    mem::take(pending_inode_extents_reallocation),
                                    fs_sync_state_alloc_bitmap,
                                ) {
                                    Ok(transaction) => (Some(transaction), e),
                                    Err(e) => (None, e),
                                };
                            }
                        };

                        if let Err(e) = inode_extents_encryption_instance.encrypt_one_extent(
                            cur_update_states_allocation_blocks_update_staging_bufs_iter,
                            &mut data,
                            cur_inode_extent.block_count(),
                            transaction.rng.as_mut(),
                        ) {
                            break 'outer match rollback(
                                transaction,
                                new_inode_extents,
                                mem::take(pending_inode_extents_reallocation),
                                fs_sync_state_alloc_bitmap,
                            ) {
                                Ok(transaction) => (Some(transaction), e),
                                Err(e) => (None, e),
                            };
                        }
                    }

                    // All of the data should have been encrypted now.
                    if let Err(e) = data.is_empty().map_err(NvFsError::from).and_then(|is_empty| {
                        if is_empty {
                            Ok(())
                        } else {
                            Err(nvfs_err_internal!())
                        }
                    }) {
                        break match rollback(
                            transaction,
                            new_inode_extents,
                            mem::take(pending_inode_extents_reallocation),
                            fs_sync_state_alloc_bitmap,
                        ) {
                            Ok(transaction) => (Some(transaction), e),
                            Err(e) => (None, e),
                        };
                    }

                    // Update the Inode's extents list.
                    let inode_extents = mem::replace(new_inode_extents, extents::PhysicalExtents::new());
                    let write_inode_extents_list_fut = InodeExtentsListWriteFuture::new(
                        transaction,
                        this.inode,
                        inode_extents,
                        preexisting_inode_extents_list_extents.take(),
                    );
                    this.fut_state = WriteInodeDataFutureState::UpdateInodeExtentsList {
                        inode_index_lookup_result: inode_index_lookup_result.take(),
                        pending_inode_extents_reallocation: mem::take(pending_inode_extents_reallocation),
                        write_inode_extents_list_fut,
                    };
                }

                WriteInodeDataFutureState::UpdateInodeExtentsList {
                    inode_index_lookup_result,
                    pending_inode_extents_reallocation,
                    write_inode_extents_list_fut,
                } => {
                    let (transaction, new_inode_extents, pending_inode_extents_list_update) =
                        match CocoonFsSyncStateReadFuture::poll(
                            pin::Pin::new(write_inode_extents_list_fut),
                            fs_instance_sync_state,
                            &mut (),
                            cx,
                        ) {
                            task::Poll::Ready(Ok((
                                transaction,
                                new_inode_extents,
                                Ok(pending_inode_extents_list_update),
                            ))) => (transaction, new_inode_extents, pending_inode_extents_list_update),
                            task::Poll::Ready(Ok((mut transaction, new_inode_extents, Err(e)))) => {
                                // Only rollback the inode's extents reallocation, but not any data
                                // staged for update: there are no promises made for the contents
                                // upon failure except that the metadata is consistent. This allows
                                // for skipping the application of staged data on the data itself,
                                // if any, before the update operation here commences, on the
                                // downside that the previous state cannot get restored. Mark the
                                // inode's data intederminate.
                                transaction
                                    .auth_tree_data_blocks_update_states
                                    .reset_staged_extents_updates_to_failed(new_inode_extents.iter());
                                break match mem::take(pending_inode_extents_reallocation)
                                    .rollback(transaction, &fs_instance_sync_state.alloc_bitmap)
                                {
                                    Ok(transaction) => (Some(transaction), e),
                                    Err(e) => (None, e),
                                };
                            }
                            task::Poll::Ready(Err(e)) => break (None, e),
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    let inode_index_lookup_result = match inode_index_lookup_result.take() {
                        Some(inode_index_lookup_result) => inode_index_lookup_result,
                        None => break (None, nvfs_err_internal!()),
                    };
                    let pending_inode_extents_reallocation = mem::take(pending_inode_extents_reallocation);
                    let inode_index_insert_entry_fut = InodeIndexInsertEntryFuture::new(
                        transaction,
                        inode_index_lookup_result,
                        pending_inode_extents_reallocation,
                        pending_inode_extents_list_update,
                    );
                    this.fut_state = WriteInodeDataFutureState::UpdateInodeIndex {
                        new_inode_extents,
                        inode_index_insert_entry_fut,
                    };
                }
                WriteInodeDataFutureState::UpdateInodeIndex {
                    new_inode_extents,
                    inode_index_insert_entry_fut,
                } => {
                    let mut transaction = match CocoonFsSyncStateReadFuture::poll(
                        pin::Pin::new(inode_index_insert_entry_fut),
                        fs_instance_sync_state,
                        &mut (),
                        cx,
                    ) {
                        task::Poll::Ready(Ok((transaction, Ok(())))) => transaction,
                        task::Poll::Ready(Ok((
                            mut transaction,
                            Err((pending_inode_extents_reallocation, pending_inode_extents_list_update, e)),
                        ))) => {
                            // Only rollback the inode's extents reallocation, but not any data
                            // staged for update already: there are no promises made for the
                            // contents upon failure except that the metadata is consistent. Any
                            // data updates staged will simply get reset to free the buffers, if
                            // any.
                            transaction
                                .auth_tree_data_blocks_update_states
                                .reset_staged_extents_updates_to_failed(new_inode_extents.iter());
                            let transaction = match pending_inode_extents_list_update
                                .rollback(transaction, &fs_instance_sync_state.alloc_bitmap)
                            {
                                Ok(transaction) => transaction,
                                Err(e) => break (None, e),
                            };
                            break match pending_inode_extents_reallocation
                                .rollback(transaction, &fs_instance_sync_state.alloc_bitmap)
                            {
                                Ok(transaction) => (Some(transaction), e),
                                Err(e) => (None, e),
                            };
                        }
                        task::Poll::Ready(Err(e)) => break (None, e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    // All done.
                    transaction.allocs.reset_rollback();
                    this.fut_state = WriteInodeDataFutureState::Done;
                    return task::Poll::Ready(Ok((transaction, mem::take(&mut this.data), Ok(()))));
                }
                WriteInodeDataFutureState::Done => unreachable!(),
            }
        };

        this.fut_state = WriteInodeDataFutureState::Done;
        task::Poll::Ready(match transaction.take() {
            Some(mut transaction) => {
                transaction.allocs.reset_rollback();
                Ok((transaction, mem::take(&mut this.data), Err(e)))
            }
            None => Err(e),
        })
    }
}

struct PreexistingInodeExtents {
    extents_list_extents: Option<extents::PhysicalExtents>,
    extents: extents::PhysicalExtents,
}

impl PreexistingInodeExtents {
    pub fn new_direct(inode_extent: layout::PhysicalAllocBlockRange) -> Result<Self, NvFsError> {
        let mut extents = extents::PhysicalExtents::new();
        extents.push_extent(&inode_extent, true)?;
        Ok(Self {
            extents_list_extents: None,
            extents,
        })
    }

    pub fn new_indirect(
        inode_extents_list_extents: extents::PhysicalExtents,
        inode_extents: extents::PhysicalExtents,
    ) -> Self {
        Self {
            extents_list_extents: Some(inode_extents_list_extents),
            extents: inode_extents,
        }
    }
}

pub enum InodeExtentsPendingReallocation {
    None,
    Truncation {
        excess_preexisting_inode_extents: extents::PhysicalExtents,
        freed: bool,
    },
    Extension {
        allocated_inode_extents: extents::PhysicalExtents,
    },
}

impl InodeExtentsPendingReallocation {
    pub fn free_excess_preexisting_inode_extents(
        &mut self,
        transaction_allocs: &mut transaction::TransactionAllocations,
        transaction_updates_states: &mut transaction::AuthTreeDataBlocksUpdateStates,
    ) -> Result<(), NvFsError> {
        if let Self::Truncation {
            excess_preexisting_inode_extents,
            freed,
        } = self
        {
            if !*freed {
                match transaction::Transaction::free_extents(
                    transaction_allocs,
                    transaction_updates_states,
                    excess_preexisting_inode_extents.iter(),
                ) {
                    Ok(()) => *freed = true,
                    Err(e) => return Err(e),
                };
            };
        }
        Ok(())
    }

    pub fn rollback_excess_preexisting_inode_extents_free(
        &mut self,
        transaction: Box<transaction::Transaction>,
        alloc_bitmap: &alloc_bitmap::AllocBitmap,
    ) -> Result<Box<transaction::Transaction>, NvFsError> {
        if let Self::Truncation {
            excess_preexisting_inode_extents,
            freed,
        } = self
        {
            if *freed {
                *freed = false;
                return transaction.rollback_extents_allocation(excess_preexisting_inode_extents.iter(), alloc_bitmap);
            }
        }
        Ok(transaction)
    }

    pub fn rollback(
        self,
        transaction: Box<transaction::Transaction>,
        alloc_bitmap: &alloc_bitmap::AllocBitmap,
    ) -> Result<Box<transaction::Transaction>, NvFsError> {
        match self {
            Self::None => Ok(transaction),
            Self::Truncation {
                excess_preexisting_inode_extents,
                freed,
            } => {
                if freed {
                    // The retained extents might have been gotten written to, so mark the truncated
                    // ones as being in an indeterminate state now.
                    transaction.rollback_extents_free(excess_preexisting_inode_extents.iter(), alloc_bitmap, true)
                } else {
                    Ok(transaction)
                }
            }
            Self::Extension {
                allocated_inode_extents,
            } => transaction.rollback_extents_allocation(allocated_inode_extents.iter(), alloc_bitmap),
        }
    }
}

impl default::Default for InodeExtentsPendingReallocation {
    fn default() -> Self {
        Self::None
    }
}
