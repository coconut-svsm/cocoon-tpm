// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`ReadAuthenticateExtentFuture`].

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

use crate::{
    chip,
    crypto::CryptoError,
    fs::{
        NvFsError,
        cocoonfs::{
            fs::{CocoonFsSyncStateMemberRef, CocoonFsSyncStateReadFuture},
            layout,
            read_buffer::BufferedReadAuthenticateDataFuture,
            transaction::{
                Transaction,
                auth_tree_data_blocks_update_states::{
                    AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
                    AuthTreeDataBlocksUpdateStatesAllocationBlocksIter,
                },
                read_authenticate_data::TransactionReadAuthenticateDataFuture,
            },
        },
    },
    nvfs_err_internal,
    utils_async::sync_types,
};
use core::{marker, pin, slice, task};

/// Result of [`ReadAuthenticateExtentFuture`].
///
/// Depending on whether or not a pending [`Transaction`] had initially been
/// passed to [`ReadAuthenticateExtentFuture::new()`] for reading at the state
/// as if the transaction had already been applied, and on whether or not the
/// requested storage extent has been modified by that transaction, the read
/// result is either a reference to buffers held by transaction or some owned
/// ones. The `ReadAuthenticateExtentFutureResult` enum is capable of
/// representing either case.
///
/// Independent of the enum variant, the buffers may always be iterated over via
/// [`iter_allocation_blocks_bufs()`](Self::iter_allocation_blocks_bufs) and the
/// [`Transaction`] initially passed to [`ReadAuthenticateExtentFuture::new()`],
/// if any, may be obtained back via
/// [`into_transaction()`](Self::into_transaction).
pub enum ReadAuthenticateExtentFutureResult {
    /// Owned data buffer.
    ///
    /// Either no [`Transaction`] had initially been
    /// passed to [`ReadAuthenticateExtentFuture::new()`] or the transaction has
    /// no updates to the requested storage extent pending.
    Owned {
        /// The [`Transaction`] initially passed to
        /// [`ReadAuthenticateExtentFuture::new()`], if any,
        /// returned back.
        returned_transaction: Option<Box<Transaction>>,
        /// Authenticated extent contents, provided in units of Allocation
        /// Blocks.
        allocation_blocks_bufs: Vec<Vec<u8>>,
    },
    /// Reference to data modified by the [`Transaction`] initially passed to
    /// [`ReadAuthenticateExtentFuture::new()`].
    PendingTransactionUpdatesRef {
        /// The [`Transaction`].
        transaction: Box<Transaction>,
        /// Index range in the
        /// [`Transaction::auth_tree_data_blocks_update_states`] corresponding
        /// to the requested storage extent to read.
        update_states_allocation_blocks_range: AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    },
}

impl ReadAuthenticateExtentFutureResult {
    /// Iterate over the read data in units of [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    pub fn iter_allocation_blocks_bufs(&self) -> ReadAuthenticateExtentFutureResultAllocationBlocksBufsIter<'_> {
        match self {
            Self::Owned {
                returned_transaction: _,
                allocation_blocks_bufs,
            } => ReadAuthenticateExtentFutureResultAllocationBlocksBufsIter::Owned {
                iter: allocation_blocks_bufs.iter(),
            },
            Self::PendingTransactionUpdatesRef {
                transaction,
                update_states_allocation_blocks_range,
            } => ReadAuthenticateExtentFutureResultAllocationBlocksBufsIter::PendingTransactionUpdatesRef {
                iter: transaction
                    .auth_tree_data_blocks_update_states
                    .iter_allocation_blocks(Some(update_states_allocation_blocks_range)),
            },
        }
    }

    /// Obtain the [`Transaction`] initially passed to
    /// [`ReadAuthenticateExtentFuture::new()`], if any, back.
    pub fn into_transaction(self) -> Option<Box<Transaction>> {
        match self {
            Self::Owned {
                mut returned_transaction,
                allocation_blocks_bufs: _,
            } => returned_transaction.take(),
            Self::PendingTransactionUpdatesRef {
                transaction,
                update_states_allocation_blocks_range: _,
            } => Some(transaction),
        }
    }
}

/// [`Iterator`] returned by
/// [`ReadAuthenticateExtentFutureResult::iter_allocation_blocks_bufs`].
#[derive(Clone)]
pub enum ReadAuthenticateExtentFutureResultAllocationBlocksBufsIter<'a> {
    /// Iterator for the [`ReadAuthenticateExtentFutureResult::Owned`] case.
    Owned { iter: slice::Iter<'a, Vec<u8>> },
    /// Iterator for the
    /// [`ReadAuthenticateExtentFutureResult::PendingTransactionUpdatesRef`]
    /// case.
    PendingTransactionUpdatesRef {
        iter: AuthTreeDataBlocksUpdateStatesAllocationBlocksIter<'a>,
    },
}

impl<'a> Iterator for ReadAuthenticateExtentFutureResultAllocationBlocksBufsIter<'a> {
    type Item = Result<&'a [u8], CryptoError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Owned { iter } => iter
                .next()
                .map(|allocation_block_buf| Ok(allocation_block_buf.as_slice())),
            Self::PendingTransactionUpdatesRef { iter } => iter.next().map(|allocation_block_update_state| {
                allocation_block_update_state
                    .1
                    .get_authenticated_encrypted_data()
                    .map_err(|_| CryptoError::Internal)
            }),
        }
    }
}

/// Read and authenticate a given data storage extent, optionally through a
/// pending [`Transaction`].
pub struct ReadAuthenticateExtentFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    fut_state: ReadAuthenticateExtentFutureState<C>,
    _phantom: marker::PhantomData<fn() -> *const ST>,
}

/// [`ReadAuthenticateExtentFuture`] state-machine state.
enum ReadAuthenticateExtentFutureState<C: chip::NvChip> {
    Init {
        transaction: Option<Box<Transaction>>,
        request_range: layout::PhysicalAllocBlockRange,
    },
    ReadCommitted {
        returned_transaction: Option<Box<Transaction>>,
        read_fut: BufferedReadAuthenticateDataFuture<C>,
    },
    ReadUncommited {
        update_states_allocation_blocks_range: AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        read_fut: TransactionReadAuthenticateDataFuture<C>,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> ReadAuthenticateExtentFuture<ST, C> {
    /// Instantiate a [`ReadAuthenticateExtentFuture`].
    ///
    /// The requested storage extent, as specified through `request_range`, may
    /// either be read in a state as if some pending [`Transaction`] passed
    /// for `transaction` had already been commited, or, if `transaction` is
    /// set to `None`, in the state as last committed to storage.
    ///
    /// The instantiated [`ReadAuthenticateExtentFuture`] assumes ownership of
    /// the `transaction`. It will get returned back upon completion from
    /// [`poll()`](Self::poll), either directly in case of an error, or
    /// indirectly as part of a [`ReadAuthenticateExtentFutureResult`] on
    /// success.
    ///
    /// # Arguments:
    ///
    /// * `transaction` - Optional [`Transaction`] to read through.
    /// * `request_range` - The storage extent to read and authenticate. It is
    ///   assumed that the extent is contained in some filesystem entity,
    ///   meaning that if `transaction` is specified, then it has either updates
    ///   to all of it staged or none at all.
    pub fn new(transaction: Option<Box<Transaction>>, request_range: &layout::PhysicalAllocBlockRange) -> Self {
        Self {
            fut_state: ReadAuthenticateExtentFutureState::Init {
                transaction,
                request_range: *request_range,
            },
            _phantom: marker::PhantomData,
        }
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsSyncStateReadFuture<ST, C>
    for ReadAuthenticateExtentFuture<ST, C>
{
    /// Output type of [`poll()`](Self::poll).
    ///
    /// On success, a [`ReadAuthenticateExtentFutureResult`] providing access to
    /// the read data is returned. On failure, a pair of the [`Transaction`]
    /// initially passed to [`new()`](Self::new) and the error reason is
    /// returned.
    type Output = Result<ReadAuthenticateExtentFutureResult, (Option<Box<Transaction>>, NvFsError)>;
    type AuxPollData<'a> = ();

    fn poll<'a>(
        self: core::pin::Pin<&mut Self>,
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, C>,
        _aux_data: &mut Self::AuxPollData<'a>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                ReadAuthenticateExtentFutureState::Init {
                    transaction: fut_transaction,
                    request_range,
                } => {
                    // If a transaction has been supplied, and it has the (probably updated)
                    // requested data, read from there.
                    if let Some(transaction) = fut_transaction.take() {
                        let transaction_update_states = &transaction.auth_tree_data_blocks_update_states;
                        if let Ok(update_states_allocation_blocks_range) =
                            transaction_update_states.lookup_allocation_blocks_update_states_index_range(request_range)
                        {
                            let all_allocation_block_update_states_present = transaction_update_states
                                .is_contiguous_allocation_blocks_region(&update_states_allocation_blocks_range);
                            let mut any_has_modified_data = false;
                            let mut all_have_modified_data = all_allocation_block_update_states_present;
                            let mut all_have_data_loaded = all_allocation_block_update_states_present;
                            let mut all_loaded_data_is_authenticated = true;
                            for allocation_block_update_state in transaction_update_states
                                .iter_allocation_blocks(Some(&update_states_allocation_blocks_range))
                            {
                                let has_modified_data = allocation_block_update_state.1.has_modified_data();
                                any_has_modified_data |= has_modified_data;
                                all_have_modified_data &= has_modified_data;
                                match allocation_block_update_state.1.has_encrypted_data_loaded() {
                                    Some(loaded_encrypted_data_is_authenticated) => {
                                        all_loaded_data_is_authenticated &= loaded_encrypted_data_is_authenticated;
                                    }
                                    None => {
                                        all_have_data_loaded = false;
                                    }
                                }
                            }

                            // If any Allocation Block had been modified, then all should be.
                            if any_has_modified_data != all_have_modified_data {
                                this.fut_state = ReadAuthenticateExtentFutureState::Done;
                                return task::Poll::Ready(Err((Some(transaction), nvfs_err_internal!())));
                            } else if all_have_data_loaded && all_loaded_data_is_authenticated {
                                this.fut_state = ReadAuthenticateExtentFutureState::Done;
                                return task::Poll::Ready(Ok(
                                    ReadAuthenticateExtentFutureResult::PendingTransactionUpdatesRef {
                                        transaction,
                                        update_states_allocation_blocks_range,
                                    },
                                ));
                            } else if any_has_modified_data {
                                let read_fut = TransactionReadAuthenticateDataFuture::new(
                                    transaction,
                                    &update_states_allocation_blocks_range,
                                    true,
                                    true,
                                );
                                this.fut_state = ReadAuthenticateExtentFutureState::ReadUncommited {
                                    update_states_allocation_blocks_range,
                                    read_fut,
                                };
                                continue;
                            }
                        }
                        // Return the transaction back and continue with reading from committed data
                        // instead.
                        *fut_transaction = Some(transaction);
                    }

                    let fs_instance = fs_instance_sync_state.get_fs_ref();
                    let read_fut = match BufferedReadAuthenticateDataFuture::new(
                        request_range,
                        &fs_instance.fs_config.image_layout,
                        fs_instance_sync_state.auth_tree.get_config(),
                        &fs_instance.chip,
                    ) {
                        Ok(read_fut) => read_fut,
                        Err(e) => {
                            let transaction = fut_transaction.take();
                            this.fut_state = ReadAuthenticateExtentFutureState::Done;
                            return task::Poll::Ready(Err((transaction, e)));
                        }
                    };
                    this.fut_state = ReadAuthenticateExtentFutureState::ReadCommitted {
                        returned_transaction: fut_transaction.take(),
                        read_fut,
                    };
                }
                ReadAuthenticateExtentFutureState::ReadCommitted {
                    returned_transaction,
                    read_fut,
                } => {
                    let (
                        fs_instance,
                        _fs_sync_state_image_size,
                        fs_sync_state_alloc_bitmap,
                        _fs_sync_state_alloc_bitmap_file,
                        mut fs_sync_state_auth_tree,
                        _fs_sync_state_inode_index,
                        fs_sync_state_read_buffer,
                        _fs_sync_state_keys_cache,
                    ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();
                    let fs_config = &fs_instance.fs_config;
                    match BufferedReadAuthenticateDataFuture::poll(
                        pin::Pin::new(read_fut),
                        &fs_instance.chip,
                        &fs_config.image_layout,
                        fs_config.image_header_end,
                        fs_sync_state_alloc_bitmap,
                        &mut fs_sync_state_auth_tree,
                        fs_sync_state_read_buffer,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(allocation_blocks_bufs)) => {
                            let returned_transaction = returned_transaction.take();
                            this.fut_state = ReadAuthenticateExtentFutureState::Done;
                            return task::Poll::Ready(Ok(ReadAuthenticateExtentFutureResult::Owned {
                                returned_transaction,
                                allocation_blocks_bufs,
                            }));
                        }
                        task::Poll::Ready(Err(e)) => {
                            let returned_transaction = returned_transaction.take();
                            this.fut_state = ReadAuthenticateExtentFutureState::Done;
                            return task::Poll::Ready(Err((returned_transaction, e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    }
                }
                ReadAuthenticateExtentFutureState::ReadUncommited {
                    update_states_allocation_blocks_range,
                    read_fut,
                } => {
                    let (fs_instance, _, fs_sync_state_alloc_bitmap, _, mut fs_sync_state_auth_tree, _, _, _) =
                        fs_instance_sync_state.fs_instance_and_destructure_borrow();
                    match TransactionReadAuthenticateDataFuture::poll(
                        pin::Pin::new(read_fut),
                        &fs_instance.chip,
                        &fs_instance.fs_config,
                        fs_sync_state_alloc_bitmap,
                        &mut fs_sync_state_auth_tree,
                        cx,
                    ) {
                        task::Poll::Ready(Ok((
                            transaction,
                            update_states_allocation_blocks_range_index_offsets,
                            result,
                        ))) => {
                            let mut update_states_allocation_blocks_range =
                                update_states_allocation_blocks_range.clone();

                            this.fut_state = ReadAuthenticateExtentFutureState::Done;
                            if let Err(e) = result {
                                return task::Poll::Ready(Err((Some(transaction), e)));
                            }

                            if let Some(update_states_allocation_blocks_range_index_offsets) =
                                update_states_allocation_blocks_range_index_offsets
                            {
                                update_states_allocation_blocks_range = update_states_allocation_blocks_range
                                    .apply_states_insertions_offsets(
                                        update_states_allocation_blocks_range_index_offsets
                                            .inserted_states_before_range_count,
                                        update_states_allocation_blocks_range_index_offsets
                                            .inserted_states_within_range_count,
                                    );
                            }

                            return task::Poll::Ready(Ok(
                                ReadAuthenticateExtentFutureResult::PendingTransactionUpdatesRef {
                                    transaction,
                                    update_states_allocation_blocks_range,
                                },
                            ));
                        }
                        task::Poll::Ready(Err(e)) => {
                            return task::Poll::Ready(Err((None, e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    }
                }
                ReadAuthenticateExtentFutureState::Done => unreachable!(),
            }
        }
    }
}
