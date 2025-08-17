// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`ReadInodeDataFuture`].

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

use crate::{
    chip,
    crypto::symcipher,
    fs::{
        NvFsError,
        cocoonfs::{
            CocoonFsFormatError,
            encryption_entities::{self, EncryptedExtentsDecryptionInstance, EncryptedExtentsLayout},
            extents,
            fs::{CocoonFsSyncStateMemberRef, CocoonFsSyncStateReadFuture},
            inode_extents_list::InodeExtentsListReadFuture,
            inode_index::{InodeIndexKeyType, InodeIndexLookupFuture, InodeKeySubdomain},
            keys,
            read_authenticate_extent::ReadAuthenticateExtentFuture,
            transaction,
        },
    },
    tpm2_interface,
    utils_async::sync_types,
    utils_common::{
        alloc::try_alloc_zeroizing_vec,
        io_slices::{self, IoSlicesIterCommon as _},
        zeroize,
    },
};
use core::{mem, pin, task};

/// Read an inode's data, optionally through a pending
/// [`Transaction`](transaction::Transaction).
///
/// Used for the implementation of
/// [`NvFs::read_inode()`](crate::fs::NvFs::read_inode).
pub struct ReadInodeDataFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    inode: InodeIndexKeyType,
    fut_state: ReadInodeDataFutureState<ST, C>,
}

/// [`ReadInodeDataFuture`] state-machine state.
#[allow(clippy::large_enum_variant)]
enum ReadInodeDataFutureState<ST: sync_types::SyncTypes, C: chip::NvChip> {
    LookupInode {
        inode_index_lookup_fut: InodeIndexLookupFuture<ST, C>,
    },
    ReadInodeExtentsList {
        read_inode_extents_list_fut: InodeExtentsListReadFuture<ST, C>,
    },
    ReadInodeDataExtentsPrepare {
        transaction: Option<Box<transaction::Transaction>>,
        inode_extents: extents::PhysicalExtents,
    },
    ReadInodeDataExtent {
        inode_extents: extents::PhysicalExtents,
        cur_inode_extent_index: usize,
        inode_extents_decryption_instance: EncryptedExtentsDecryptionInstance,
        result_buf: zeroize::Zeroizing<Vec<u8>>,
        cur_result_pos: usize,
        read_fut: ReadAuthenticateExtentFuture<ST, C>,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> ReadInodeDataFuture<ST, C> {
    /// Instantiate a [`ReadInodeDataFuture`].
    ///
    /// If `transaction` is specified, then the inode's data will be read at the
    /// state as if the `transaction` had already been committed. The
    /// `ReadInodeDataFuture` assumes ownership of the `transaction` for the
    /// duration of the operation, it will eventually get returned back from
    /// [`poll`](Self::poll) upon completion.
    ///
    /// # Arguments:
    ///
    /// * `transaction` - Optional [`Transaction`](transaction::Transaction) to
    ///   read through.
    /// * `inode` - The inode whose data to read.
    pub fn new(transaction: Option<Box<transaction::Transaction>>, inode: InodeIndexKeyType) -> Self {
        Self {
            inode,
            fut_state: ReadInodeDataFutureState::LookupInode {
                inode_index_lookup_fut: InodeIndexLookupFuture::new(transaction, inode),
            },
        }
    }

    /// Instantiate a [`ReadInodeDataFuture`] with known inode data extents.
    ///
    /// If `transaction` is specified, then the inode's data will be read at the
    /// state as if the `transaction` had already been committed. The
    /// `ReadInodeDataFuture` assumes ownership of the `transaction` for the
    /// duration of the operation, it will eventually get returned back from
    /// [`poll`](Self::poll) upon completion.
    ///
    /// # Arguments:
    ///
    /// * `transaction` - Optional [`Transaction`](transaction::Transaction) to
    ///   read through.
    /// * `inode` - The inode whose data to read.
    /// * `inode_extents` - The `inode`'s data extents previously obtained from
    ///   the inode index. If `transaction` is specified, then they must be
    ///   consistent with its view on the inode index state.
    pub fn new_with_inode_extents(
        transaction: Option<Box<transaction::Transaction>>,
        inode: InodeIndexKeyType,
        inode_extents: extents::PhysicalExtents,
    ) -> Self {
        Self {
            inode,
            fut_state: ReadInodeDataFutureState::ReadInodeDataExtentsPrepare {
                transaction,
                inode_extents,
            },
        }
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsSyncStateReadFuture<ST, C> for ReadInodeDataFuture<ST, C> {
    /// Output type of [`poll()`](Self::poll).
    ///
    /// The [`Transaction`](transaction::Transaction) initially passed to
    /// [`new()`](Self::new()) is returned in the first component.
    /// The second components holds the read result, which on success is either
    /// the inode data wrapped in `Some` if the inode exists, or `None` if
    /// it doesn't.
    type Output = (
        Option<Box<transaction::Transaction>>,
        Result<Option<zeroize::Zeroizing<Vec<u8>>>, NvFsError>,
    );

    type AuxPollData<'a> = ();

    fn poll<'a>(
        self: pin::Pin<&mut Self>,
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, C>,
        _aux_data: &mut Self::AuxPollData<'a>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        let (returned_transaction, e) = loop {
            match &mut this.fut_state {
                ReadInodeDataFutureState::LookupInode { inode_index_lookup_fut } => {
                    let (transaction, inode_index_entry_extent_ptr) = match CocoonFsSyncStateReadFuture::poll(
                        pin::Pin::new(inode_index_lookup_fut),
                        fs_instance_sync_state,
                        &mut (),
                        cx,
                    ) {
                        task::Poll::Ready((transaction, Ok(inode_index_entry_extent_ptr))) => {
                            (transaction, inode_index_entry_extent_ptr)
                        }
                        task::Poll::Ready((transaction, Err(e))) => break (transaction, e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let inode_index_entry_extent_ptr = match inode_index_entry_extent_ptr {
                        Some(inode_index_entry_extent_ptr) => inode_index_entry_extent_ptr,
                        None => {
                            // Inode does not exist.
                            this.fut_state = ReadInodeDataFutureState::Done;
                            return task::Poll::Ready((transaction, Ok(None)));
                        }
                    };

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
                    match inode_index_entry_extent_ptr
                        .decode(fs_instance.fs_config.image_layout.allocation_block_size_128b_log2 as u32)
                    {
                        Ok(Some((inode_extent, false))) => {
                            // The inode index entry references the inode's (single) extent directly.
                            let mut inode_extents = extents::PhysicalExtents::new();
                            if let Err(e) = inode_extents.push_extent(&inode_extent, true) {
                                break (transaction, e);
                            }
                            this.fut_state = ReadInodeDataFutureState::ReadInodeDataExtentsPrepare {
                                transaction,
                                inode_extents,
                            };
                        }
                        Ok(Some((_first_inode_extents_list_extent, true))) => {
                            let read_inode_extents_list_fut = match InodeExtentsListReadFuture::new(
                                transaction,
                                this.inode,
                                &inode_index_entry_extent_ptr,
                                &fs_instance.fs_config.root_key,
                                &mut fs_sync_state_keys_cache,
                                &fs_instance.fs_config.image_layout,
                            ) {
                                Ok(read_inode_extents_list_fut) => read_inode_extents_list_fut,
                                Err((transaction, e)) => break (transaction, e),
                            };
                            this.fut_state = ReadInodeDataFutureState::ReadInodeExtentsList {
                                read_inode_extents_list_fut,
                            };
                        }
                        Ok(None) => {
                            // The inode exists, but the extents reference is nil, which is invalid.
                            break (transaction, NvFsError::from(CocoonFsFormatError::InvalidExtents));
                        }
                        Err(e) => break (transaction, e),
                    }
                }
                ReadInodeDataFutureState::ReadInodeExtentsList {
                    read_inode_extents_list_fut,
                } => {
                    let (transaction, inode_extents) = match CocoonFsSyncStateReadFuture::poll(
                        pin::Pin::new(read_inode_extents_list_fut),
                        fs_instance_sync_state,
                        &mut (),
                        cx,
                    ) {
                        task::Poll::Ready((transaction, Ok((_inode_extents_list_extents, inode_extents)))) => {
                            (transaction, inode_extents)
                        }
                        task::Poll::Ready((transaction, Err(e))) => break (transaction, e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    if inode_extents.is_empty() {
                        break (transaction, NvFsError::from(CocoonFsFormatError::InvalidExtents));
                    }

                    this.fut_state = ReadInodeDataFutureState::ReadInodeDataExtentsPrepare {
                        transaction,
                        inode_extents,
                    };
                }
                ReadInodeDataFutureState::ReadInodeDataExtentsPrepare {
                    transaction,
                    inode_extents,
                } => {
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
                    let image_layout = &fs_instance.fs_config.image_layout;
                    let inode_extents_encryption_layout = match EncryptedExtentsLayout::new(
                        image_layout.block_cipher_alg,
                        image_layout.allocation_block_size_128b_log2,
                    ) {
                        Ok(inode_extents_encryption_layout) => inode_extents_encryption_layout,
                        Err(e) => break (transaction.take(), e),
                    };
                    let extents_encryption_key = match keys::KeyCache::get_key(
                        &mut fs_sync_state_keys_cache,
                        &fs_instance.fs_config.root_key,
                        &keys::KeyId::new(
                            this.inode,
                            InodeKeySubdomain::InodeData as u32,
                            keys::KeyPurpose::Encryption,
                        ),
                    ) {
                        Ok(extents_encryption_key) => extents_encryption_key,
                        Err(e) => break (transaction.take(), e),
                    };
                    let extents_decryption_block_cipher_instance =
                        match symcipher::SymBlockCipherModeDecryptionInstance::new(
                            tpm2_interface::TpmiAlgCipherMode::Cbc,
                            &image_layout.block_cipher_alg,
                            &extents_encryption_key,
                        ) {
                            Ok(extents_decryption_block_cipher_instance) => extents_decryption_block_cipher_instance,
                            Err(e) => break (transaction.take(), NvFsError::from(e)),
                        };
                    drop(extents_encryption_key);

                    let inode_extents_decryption_instance = match EncryptedExtentsDecryptionInstance::new(
                        inode_extents_encryption_layout,
                        extents_decryption_block_cipher_instance,
                    ) {
                        Ok(inode_extents_decryption_instance) => inode_extents_decryption_instance,
                        Err(e) => break (transaction.take(), e),
                    };

                    let total_decrypted_len =
                        match inode_extents_decryption_instance.max_extents_decrypted_len(inode_extents.iter()) {
                            Ok(total_decrypted_len) => total_decrypted_len,
                            Err(e) => break (transaction.take(), e),
                        };
                    let result_buf = match try_alloc_zeroizing_vec(total_decrypted_len) {
                        Ok(result_buf) => result_buf,
                        Err(e) => break (transaction.take(), NvFsError::from(e)),
                    };

                    let read_fut =
                        ReadAuthenticateExtentFuture::new(transaction.take(), &inode_extents.get_extent_range(0));
                    this.fut_state = ReadInodeDataFutureState::ReadInodeDataExtent {
                        inode_extents: mem::replace(inode_extents, extents::PhysicalExtents::new()),
                        cur_inode_extent_index: 0,
                        inode_extents_decryption_instance,
                        result_buf,
                        cur_result_pos: 0,
                        read_fut,
                    };
                }
                ReadInodeDataFutureState::ReadInodeDataExtent {
                    inode_extents,
                    cur_inode_extent_index,
                    inode_extents_decryption_instance,
                    result_buf,
                    cur_result_pos,
                    read_fut,
                } => {
                    let encrypted_extent_ref = match CocoonFsSyncStateReadFuture::poll(
                        pin::Pin::new(read_fut),
                        fs_instance_sync_state,
                        &mut (),
                        cx,
                    ) {
                        task::Poll::Ready(Ok(encrypted_extent)) => encrypted_extent,
                        task::Poll::Ready(Err((transaction, e))) => break (transaction, e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let extent_allocation_blocks =
                        inode_extents.get_extent_range(*cur_inode_extent_index).block_count();
                    let decrypted_extent_len = match inode_extents_decryption_instance
                        .max_extent_decrypted_len(extent_allocation_blocks, *cur_inode_extent_index == 0)
                    {
                        Ok(decrypted_extent_len) => decrypted_extent_len,
                        Err(e) => break (encrypted_extent_ref.into_transaction(), e),
                    };
                    let mut decrypted_extent_buf = io_slices::SingletonIoSliceMut::new(
                        &mut result_buf[*cur_result_pos..*cur_result_pos + decrypted_extent_len],
                    )
                    .map_infallible_err();
                    if let Err(e) = inode_extents_decryption_instance.decrypt_one_extent(
                        &mut decrypted_extent_buf,
                        io_slices::GenericIoSlicesIter::new(encrypted_extent_ref.iter_allocation_blocks_bufs(), None),
                        extent_allocation_blocks,
                    ) {
                        break (encrypted_extent_ref.into_transaction(), e);
                    }
                    *cur_result_pos += decrypted_extent_len;

                    let transaction = encrypted_extent_ref.into_transaction();
                    *cur_inode_extent_index += 1;
                    if *cur_inode_extent_index < inode_extents.len() {
                        *read_fut = ReadAuthenticateExtentFuture::new(
                            transaction,
                            &inode_extents.get_extent_range(*cur_inode_extent_index),
                        );
                    } else {
                        // All done, verify and strip the CBC padding and return the result.
                        let padding_len = match encryption_entities::check_cbc_padding(
                            io_slices::SingletonIoSlice::new(result_buf).map_infallible_err(),
                        ) {
                            Ok(padding_len) => padding_len,
                            Err(e) => break (transaction, e),
                        };
                        let mut result_buf = mem::take(result_buf);
                        let original_result_buf_len = result_buf.len();
                        result_buf.resize(original_result_buf_len - padding_len, 0u8);

                        this.fut_state = ReadInodeDataFutureState::Done;
                        return task::Poll::Ready((transaction, Ok(Some(result_buf))));
                    }
                }
                ReadInodeDataFutureState::Done => unreachable!(),
            }
        };

        this.fut_state = ReadInodeDataFutureState::Done;
        task::Poll::Ready((returned_transaction, Err(e)))
    }
}
