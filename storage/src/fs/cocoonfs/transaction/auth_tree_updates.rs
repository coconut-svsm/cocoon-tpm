// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`TransactionAuthTreeDataBlocksDigestsUpdatesIterator`]
//! and [`TransactionJournalUpdateAuthDigestsScriptIterator`].

extern crate alloc;

use alloc::{boxed::Box, vec::Vec};

use super::{
    Transaction,
    auth_tree_data_blocks_update_states::{AuthTreeDataBlocksUpdateStates, AuthTreeDataBlocksUpdateStatesIndex},
};
use crate::{
    chip,
    fs::{
        NvFsError,
        cocoonfs::{
            alloc_bitmap, auth_tree,
            fs::{CocoonFsConfig, CocoonFsSyncStateMemberRef, CocoonFsSyncStateReadFuture},
            journal, layout, read_buffer,
        },
    },
    nvfs_err_internal,
    utils_async::sync_types,
    utils_common::{alloc::try_alloc_vec, bitmanip::BitManip as _},
};
use core::{marker, pin, task};

#[cfg(doc)]
use super::auth_tree_data_blocks_update_states::AuthTreeDataBlockUpdateState;
#[cfg(doc)]
use layout::ImageLayout;

/// Compute the updated digest of an [Authentication Tree Data
/// Blocks](ImageLayout::auth_tree_data_block_allocation_blocks_log2) with some
/// deallocations but no data modifications in it.
struct RedigestAuthTreeDataBlockFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    auth_tree_data_block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
    updated_auth_tree_data_block_alloc_bitmap: alloc_bitmap::BitmapWord,
    auth_tree_data_block_allocation_blocks_bufs: Vec<Option<Vec<u8>>>,
    fut_state: RedigestAuthTreeDataBlockFutureState<C>,
    _phantom: marker::PhantomData<fn() -> *const ST>,
}

/// [`RedigestAuthTreeDataBlockFuture`] state-machine state.
#[allow(clippy::large_enum_variant)]
enum RedigestAuthTreeDataBlockFutureState<C: chip::NvChip> {
    DetermineNextReadAuthenticateSubrange {
        next_allocation_block_index: layout::PhysicalAllocBlockIndex,
    },
    ReadAuthenticateSubrange {
        subrange: layout::PhysicalAllocBlockRange,
        read_auth_subrange_fut: read_buffer::BufferedReadAuthenticateDataFuture<C>,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> RedigestAuthTreeDataBlockFuture<ST, C> {
    /// Instantiate a [`RedigestAuthTreeDataBlockFuture`].
    ///
    /// # Arguments:
    ///
    /// * `fs_config` - The filesystem instance's [`CocoonFsConfig`].
    /// * `auth_tree_data_block_allocation_blocks_begin` - Storage location of
    ///   the [Authentication Tree Data
    ///   Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) whose
    ///   digest to recompute.
    /// * `updated_auth_tree_data_block_alloc_bitmap` -
    ///   [`BitmapWord`](alloc_bitmap::BitmapWord) representing the updated
    ///   allocation status of the [Authentication Tree Data
    ///   Block's](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    ///   [Allocation Blocks](ImageLayout::allocation_block_size_128b_log2)
    ///   each.
    fn new(
        fs_config: &CocoonFsConfig,
        auth_tree_data_block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        mut updated_auth_tree_data_block_alloc_bitmap: alloc_bitmap::BitmapWord,
    ) -> Result<Self, NvFsError> {
        // Anything before image_header_end is considered unallocated for the purpose of
        // computing the authentication digest.
        let image_header_end = fs_config.image_header_end;
        if auth_tree_data_block_allocation_blocks_begin < image_header_end {
            updated_auth_tree_data_block_alloc_bitmap &= !alloc_bitmap::BitmapWord::trailing_bits_mask(
                u64::from(image_header_end - auth_tree_data_block_allocation_blocks_begin)
                    .min(alloc_bitmap::BitmapWord::BITS as u64) as u32,
            );
        }

        let auth_tree_data_block_allocation_blocks =
            1usize << (fs_config.image_layout.auth_tree_data_block_allocation_blocks_log2 as u32);
        let auth_tree_data_block_allocation_blocks_bufs = try_alloc_vec(auth_tree_data_block_allocation_blocks)?;
        Ok(Self {
            auth_tree_data_block_allocation_blocks_begin,
            updated_auth_tree_data_block_alloc_bitmap,
            auth_tree_data_block_allocation_blocks_bufs,
            fut_state: RedigestAuthTreeDataBlockFutureState::DetermineNextReadAuthenticateSubrange {
                next_allocation_block_index: auth_tree_data_block_allocation_blocks_begin,
            },
            _phantom: marker::PhantomData,
        })
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsSyncStateReadFuture<ST, C>
    for RedigestAuthTreeDataBlockFuture<ST, C>
{
    /// Output type of [`poll()`](Self::poll).
    ///
    /// On successful completion, the recomputed digest over the [Authentication
    /// Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) is
    /// returned.
    type Output = Result<Vec<u8>, NvFsError>;
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
                RedigestAuthTreeDataBlockFutureState::DetermineNextReadAuthenticateSubrange {
                    next_allocation_block_index,
                } => {
                    // Fits an u32, because an Authentication Tree Data Block's individual
                    // Allocation Blocks can get tracked in a single BitmapWord, whose width fits an
                    // u32.
                    let offset_in_auth_tree_data_block =
                        u64::from(*next_allocation_block_index - this.auth_tree_data_block_allocation_blocks_begin)
                            as u32;

                    let updated_auth_tree_data_block_alloc_bitmap = this.updated_auth_tree_data_block_alloc_bitmap
                        & !alloc_bitmap::BitmapWord::trailing_bits_mask(offset_in_auth_tree_data_block);
                    if updated_auth_tree_data_block_alloc_bitmap == 0 {
                        // All of the Authentication Tree Data Block's allocated Allocation Blocks
                        // have been loaded and authenticated. Compute the Authentication Tree Data
                        // Block digest and return.
                        let fs_instance = fs_instance_sync_state.get_fs_ref();
                        let auth_tree_config = fs_instance_sync_state.auth_tree.get_config();
                        let data_block_index = auth_tree_config
                            .translate_physical_to_data_block_index(this.auth_tree_data_block_allocation_blocks_begin);
                        let auth_digest = match auth_tree_config.digest_data_block(
                            data_block_index,
                            this.auth_tree_data_block_allocation_blocks_bufs
                                .iter()
                                .map(|buf| Ok(buf.as_deref())),
                            fs_instance.fs_config.image_header_end,
                        ) {
                            Ok(auth_digest) => auth_digest,
                            Err(e) => {
                                this.fut_state = RedigestAuthTreeDataBlockFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                        };
                        this.fut_state = RedigestAuthTreeDataBlockFutureState::Done;
                        return task::Poll::Ready(Ok(auth_digest));
                    }

                    // There are some more Allocation Blocks to read and authenticate left.
                    // Determine the next (least significant) run of 1s in the bitmap word.
                    let next_subrange_begin_in_auth_tree_data_block =
                        updated_auth_tree_data_block_alloc_bitmap.trailing_zeros();
                    let next_subrange_end_in_auth_tree_data_block = next_subrange_begin_in_auth_tree_data_block
                        + (!updated_auth_tree_data_block_alloc_bitmap >> next_subrange_begin_in_auth_tree_data_block)
                            .trailing_zeros();
                    let next_subrange = layout::PhysicalAllocBlockRange::new(
                        this.auth_tree_data_block_allocation_blocks_begin
                            + layout::AllocBlockCount::from(next_subrange_begin_in_auth_tree_data_block as u64),
                        this.auth_tree_data_block_allocation_blocks_begin
                            + layout::AllocBlockCount::from(next_subrange_end_in_auth_tree_data_block as u64),
                    );
                    let fs_instance = fs_instance_sync_state.get_fs_ref();
                    let read_auth_next_subrange_fut = match read_buffer::BufferedReadAuthenticateDataFuture::new(
                        &next_subrange,
                        &fs_instance.fs_config.image_layout,
                        fs_instance_sync_state.auth_tree.get_config(),
                        &fs_instance.chip,
                    ) {
                        Ok(read_auth_next_subrange_fut) => read_auth_next_subrange_fut,
                        Err(e) => {
                            this.fut_state = RedigestAuthTreeDataBlockFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    this.fut_state = RedigestAuthTreeDataBlockFutureState::ReadAuthenticateSubrange {
                        subrange: next_subrange,
                        read_auth_subrange_fut: read_auth_next_subrange_fut,
                    };
                }
                RedigestAuthTreeDataBlockFutureState::ReadAuthenticateSubrange {
                    subrange,
                    read_auth_subrange_fut,
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
                    let mut subrange_allocation_blocks_bufs =
                        match read_buffer::BufferedReadAuthenticateDataFuture::poll(
                            pin::Pin::new(read_auth_subrange_fut),
                            &fs_instance.chip,
                            &fs_config.image_layout,
                            fs_config.image_header_end,
                            fs_sync_state_alloc_bitmap,
                            &mut fs_sync_state_auth_tree,
                            fs_sync_state_read_buffer,
                            cx,
                        ) {
                            task::Poll::Ready(Ok(subrange_allocation_blocks_bufs)) => subrange_allocation_blocks_bufs,
                            task::Poll::Ready(Err(e)) => {
                                this.fut_state = RedigestAuthTreeDataBlockFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    debug_assert_eq!(
                        subrange_allocation_blocks_bufs.len(),
                        u64::from(subrange.block_count()) as usize
                    );
                    let offset_in_auth_tree_data_block =
                        u64::from(subrange.begin() - this.auth_tree_data_block_allocation_blocks_begin) as usize;
                    for (i, allocation_block_buf) in subrange_allocation_blocks_bufs.drain(..).enumerate() {
                        this.auth_tree_data_block_allocation_blocks_bufs[offset_in_auth_tree_data_block + i] =
                            Some(allocation_block_buf);
                    }

                    let next_allocation_block_index = subrange.end();
                    this.fut_state = RedigestAuthTreeDataBlockFutureState::DetermineNextReadAuthenticateSubrange {
                        next_allocation_block_index,
                    };
                }
                RedigestAuthTreeDataBlockFutureState::Done => unreachable!(),
            };
        }
    }
}

/// [`AuthTreeDataBlocksUpdatesIterator`](auth_tree::AuthTreeDataBlocksUpdatesIterator) implementation over
/// a [`Transaction`].
///
/// Used for [preparing](auth_tree::AuthTreePrepareUpdatesFuture) updates to the
/// authentication tree upon [`Transaction`] commit.
pub struct TransactionAuthTreeDataBlocksDigestsUpdatesIterator<ST: sync_types::SyncTypes, C: chip::NvChip> {
    transaction: Option<Box<Transaction>>,
    next_auth_tree_data_block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
    next_update_states_index: AuthTreeDataBlocksUpdateStatesIndex,
    next_pending_free: Option<(layout::PhysicalAllocBlockIndex, alloc_bitmap::BitmapWord)>,
    redigest_auth_tree_data_block_fut: Option<RedigestAuthTreeDataBlockFuture<ST, C>>,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> TransactionAuthTreeDataBlocksDigestsUpdatesIterator<ST, C> {
    /// Instantiate a new
    /// [`TransactionAuthTreeDataBlocksDigestsUpdatesIterator`].
    ///
    /// The [`TransactionAuthTreeDataBlocksDigestsUpdatesIterator`] assumes
    /// ownership of the `transaction` for the duration of its lifetime. It
    /// may eventually get obtained back via
    /// [`into_transaction()`](Self::into_transaction).
    ///
    /// # Arguments:
    ///
    /// * `transaction` - The [`Transaction`] to compute authentication tree
    ///   updates for.
    /// * `auth_tree_data_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::auth_tree_data_block_allocation_blocks_log2`].
    /// * `image_header_end` - [End of the filesystem image header on
    ///   storage](crate::fs::cocoonfs::image_header::MutableImageHeader::physical_location).
    pub fn new(
        transaction: Box<Transaction>,
        auth_tree_data_block_allocation_blocks_log2: u8,
        image_header_end: layout::PhysicalAllocBlockIndex,
    ) -> Self {
        let auth_tree_data_block_allocation_blocks_log2 = auth_tree_data_block_allocation_blocks_log2 as u32;
        let auth_tree_data_block_allocation_blocks =
            layout::AllocBlockCount::from(1u64 << auth_tree_data_block_allocation_blocks_log2);

        let next_update_states_index = Self::skip_to_auth_tree_update_state_with_modified_data(
            &transaction.auth_tree_data_blocks_update_states,
            AuthTreeDataBlocksUpdateStatesIndex::from(0usize),
            image_header_end,
            auth_tree_data_block_allocation_blocks,
        );

        let next_pending_free = transaction
            .allocs
            .pending_frees
            .block_iter(auth_tree_data_block_allocation_blocks_log2)
            .next();

        Self {
            transaction: Some(transaction),
            next_auth_tree_data_block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex::from(0u64),
            next_update_states_index,
            next_pending_free,
            redigest_auth_tree_data_block_fut: None,
        }
    }

    /// Obtain the [`Transaction`] initially passed to [`new()`](Self::new)
    /// back.
    pub fn into_transaction(self) -> Result<Box<Transaction>, NvFsError> {
        self.transaction.ok_or_else(|| nvfs_err_internal!())
    }

    /// Skip over the [`Transaction`]'s [`AuthTreeDataBlockUpdateState`]s with
    /// no recorded data modifications.
    ///
    /// Return the new index corresponding to the new position in
    /// `update_states`.
    ///
    /// Arguments:
    ///
    /// * `update_states` - Reference to
    ///   [`Transaction::auth_tree_data_blocks_update_states`].
    /// * `update_states_index` - Current position in `update_states`.
    /// * `image_header_end` - [End of the filesystem image header on
    ///   storage](crate::fs::cocoonfs::image_header::MutableImageHeader::physical_location).
    /// * `auth_tree_data_block_allocation_blocks` - Number of [Allocation
    ///   Blocks](ImageLayout::allocation_block_size_128b_log2) in an
    ///   [Authentication Tree Data
    ///   Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2).
    fn skip_to_auth_tree_update_state_with_modified_data(
        update_states: &AuthTreeDataBlocksUpdateStates,
        mut update_states_index: AuthTreeDataBlocksUpdateStatesIndex,
        image_header_end: layout::PhysicalAllocBlockIndex,
        auth_tree_data_block_allocation_blocks: layout::AllocBlockCount,
    ) -> AuthTreeDataBlocksUpdateStatesIndex {
        while usize::from(update_states_index) < update_states.len() {
            let update_state = &update_states[update_states_index];
            if update_state
                .iter_allocation_blocks()
                .skip(
                    u64::from(image_header_end)
                        .saturating_sub(u64::from(update_state.get_target_allocation_blocks_begin()))
                        .min(u64::from(auth_tree_data_block_allocation_blocks)) as usize,
                )
                .any(|allocation_block_update_state| allocation_block_update_state.has_modified_data())
            {
                break;
            }
            update_states_index = update_states_index.step();
        }
        update_states_index
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> auth_tree::AuthTreeDataBlocksUpdatesIterator<ST, C>
    for TransactionAuthTreeDataBlocksDigestsUpdatesIterator<ST, C>
{
    fn poll_for_next(
        self: pin::Pin<&mut Self>,
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, C>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<Option<auth_tree::PhysicalAuthTreeDataBlockUpdate>, NvFsError>> {
        let this = pin::Pin::into_inner(self);

        let transaction = match this.transaction.as_mut() {
            Some(transaction) => transaction,
            None => return task::Poll::Ready(Err(nvfs_err_internal!())),
        };

        let auth_tree_data_block_allocation_blocks_log2 = fs_instance_sync_state
            .get_fs_ref()
            .fs_config
            .image_layout
            .auth_tree_data_block_allocation_blocks_log2
            as u32;
        let auth_tree_data_block_allocation_blocks =
            layout::AllocBlockCount::from(1u64 << auth_tree_data_block_allocation_blocks_log2);

        loop {
            if let Some(redigest_auth_tree_data_block_fut) = this.redigest_auth_tree_data_block_fut.as_mut() {
                let auth_digest = match CocoonFsSyncStateReadFuture::poll(
                    pin::Pin::new(redigest_auth_tree_data_block_fut),
                    fs_instance_sync_state,
                    &mut (),
                    cx,
                ) {
                    task::Poll::Ready(Ok(auth_digest)) => auth_digest,
                    task::Poll::Ready(Err(e)) => return task::Poll::Ready(Err(e)),
                    task::Poll::Pending => return task::Poll::Pending,
                };
                this.redigest_auth_tree_data_block_fut = None;

                let cur_auth_tree_data_block_allocation_blocks_begin =
                    this.next_auth_tree_data_block_allocation_blocks_begin;
                this.next_auth_tree_data_block_allocation_blocks_begin += auth_tree_data_block_allocation_blocks;
                this.next_pending_free = transaction
                    .allocs
                    .pending_frees
                    .block_iter_at(
                        this.next_auth_tree_data_block_allocation_blocks_begin,
                        auth_tree_data_block_allocation_blocks_log2,
                    )
                    .next();

                return task::Poll::Ready(Ok(Some(auth_tree::PhysicalAuthTreeDataBlockUpdate {
                    data_block_allocation_blocks_begin: cur_auth_tree_data_block_allocation_blocks_begin,
                    data_block_digest: auth_digest,
                })));
            }

            let fs_instance = fs_instance_sync_state.get_fs_ref();
            let fs_config = &fs_instance.fs_config;
            let update_states = &mut transaction.auth_tree_data_blocks_update_states;
            if let Some(next_pending_free) = this.next_pending_free.take_if(|next_pending_free| {
                usize::from(this.next_update_states_index) == update_states.len()
                    || update_states[this.next_update_states_index].get_target_allocation_blocks_begin()
                        > next_pending_free.0
            }) {
                this.next_auth_tree_data_block_allocation_blocks_begin = next_pending_free.0;
                // Compute the updated Authentication Tree Data Block's allocation bitmap. To
                // save some lookups in the transaction's pending_allocs and
                // pending_frees bitmaps, it is assumed that the two had been
                // normalized and that all entries from pending_allocs have data
                // modifications pending to them as well, meaning there are none in the
                // current Authentication Tree Data Block.
                let fs_sync_state_alloc_bitmap = &fs_instance_sync_state.alloc_bitmap;
                let empty_sparse_alloc_bitmap = alloc_bitmap::SparseAllocBitmapUnion::new(&[]);
                let original_auth_tree_data_block_alloc_bitmap = match fs_sync_state_alloc_bitmap
                    .iter_chunked_at_allocation_block(
                        &empty_sparse_alloc_bitmap,
                        &empty_sparse_alloc_bitmap,
                        this.next_auth_tree_data_block_allocation_blocks_begin,
                        u64::from(auth_tree_data_block_allocation_blocks) as u32,
                    )
                    .next()
                {
                    Some(original_auth_tree_data_block_alloc_bitmap) => original_auth_tree_data_block_alloc_bitmap,
                    None => return task::Poll::Ready(Err(nvfs_err_internal!())),
                };
                // It is assumed that the transaction's pending_frees is normalized, i.e. there
                // are no frees for unallocated Allocation Blocks.
                debug_assert!(next_pending_free.1 & original_auth_tree_data_block_alloc_bitmap == next_pending_free.1);
                let updated_auth_tree_data_block_alloc_bitmap =
                    original_auth_tree_data_block_alloc_bitmap & !next_pending_free.1;
                let redigest_auth_tree_data_block_fut = match RedigestAuthTreeDataBlockFuture::new(
                    fs_config,
                    this.next_auth_tree_data_block_allocation_blocks_begin,
                    updated_auth_tree_data_block_alloc_bitmap,
                ) {
                    Ok(redigest_auth_tree_data_block_fut) => redigest_auth_tree_data_block_fut,
                    Err(e) => return task::Poll::Ready(Err(e)),
                };
                this.redigest_auth_tree_data_block_fut = Some(redigest_auth_tree_data_block_fut);
            } else if usize::from(this.next_update_states_index) < update_states.len() {
                let update_state = &mut update_states[this.next_update_states_index];
                let cur_auth_tree_data_block_allocation_blocks_begin =
                    update_state.get_target_allocation_blocks_begin();
                let auth_digest = match update_state.steal_auth_digest() {
                    Some(auth_digest) => auth_digest,
                    None => return task::Poll::Ready(Err(nvfs_err_internal!())),
                };
                this.next_auth_tree_data_block_allocation_blocks_begin =
                    cur_auth_tree_data_block_allocation_blocks_begin + auth_tree_data_block_allocation_blocks;
                this.next_update_states_index = Self::skip_to_auth_tree_update_state_with_modified_data(
                    update_states,
                    this.next_update_states_index.step(),
                    fs_config.image_header_end,
                    auth_tree_data_block_allocation_blocks,
                );
                if this
                    .next_pending_free
                    .as_ref()
                    .map(|next_pending_free| next_pending_free.0 == cur_auth_tree_data_block_allocation_blocks_begin)
                    .unwrap_or(false)
                {
                    this.next_pending_free = transaction
                        .allocs
                        .pending_frees
                        .block_iter_at(
                            this.next_auth_tree_data_block_allocation_blocks_begin,
                            auth_tree_data_block_allocation_blocks_log2,
                        )
                        .next();
                }
                return task::Poll::Ready(Ok(Some(auth_tree::PhysicalAuthTreeDataBlockUpdate {
                    data_block_allocation_blocks_begin: cur_auth_tree_data_block_allocation_blocks_begin,
                    data_block_digest: auth_digest,
                })));
            } else {
                return task::Poll::Ready(Ok(None));
            }
        }
    }

    fn return_digests_on_error(
        &mut self,
        fs_config: &CocoonFsConfig,
        returned_updates: auth_tree::AuthTreePendingNodesUpdatesIntoDataUpdatesIter,
    ) -> Result<(), NvFsError> {
        let transaction = self.transaction.as_mut().ok_or_else(|| nvfs_err_internal!())?;
        transaction.restore_update_states_auth_digests(
            returned_updates,
            fs_config.image_layout.auth_tree_data_block_allocation_blocks_log2,
            fs_config.image_header_end,
        )
    }

    fn return_digest_on_error(
        &mut self,
        fs_config: &CocoonFsConfig,
        returned_update: auth_tree::PhysicalAuthTreeDataBlockUpdate,
    ) -> Result<(), NvFsError> {
        let transaction = self.transaction.as_mut().ok_or_else(|| nvfs_err_internal!())?;

        let auth_tree_data_block_allocation_blocks_log2 =
            fs_config.image_layout.auth_tree_data_block_allocation_blocks_log2 as u32;
        let auth_tree_data_block_allocation_blocks =
            layout::AllocBlockCount::from(1u64 << auth_tree_data_block_allocation_blocks_log2);
        let image_header_end = fs_config.image_header_end;

        let update_states = &mut transaction.auth_tree_data_blocks_update_states;
        let update_states_index = match update_states
            .lookup_auth_tree_data_block_update_state_index(returned_update.data_block_allocation_blocks_begin)
        {
            Ok(update_states_index) => update_states_index,
            Err(_) => return Ok(()),
        };
        let update_state = &mut update_states[update_states_index];

        // Don't store returned digests for Authentication Tree Data Blocks with no data
        // modifications. Getting such one back means there had been a redigest because
        // of changes in the allocation bitmap.
        if !update_state
            .iter_allocation_blocks()
            .skip(
                u64::from(image_header_end)
                    .saturating_sub(u64::from(update_state.get_target_allocation_blocks_begin()))
                    .min(u64::from(auth_tree_data_block_allocation_blocks)) as usize,
            )
            .any(|allocation_block_update_state| allocation_block_update_state.has_modified_data())
        {
            return Ok(());
        }

        if update_state.get_auth_digest().is_some() {
            return Err(nvfs_err_internal!());
        }
        update_state.set_auth_digest(returned_update.data_block_digest);

        Ok(())
    }
}

impl Transaction {
    /// Restore the [`Transaction`]'s
    /// [`AuthTreeDataBlockUpdateState::auth_digest`]s from an
    /// [`AuthTreePendingNodesUpdatesIntoDataUpdatesIter`](auth_tree::AuthTreePendingNodesUpdatesIntoDataUpdatesIter).
    ///
    /// Invoked by [`TransactionAuthTreeDataBlocksDigestsUpdatesIterator`] to
    /// restore the [`Transaction`]'s
    /// [`AuthTreeDataBlockUpdateState::auth_digest`]s on error.
    ///
    /// # Arguments:
    ///
    /// * `returned_updates` -
    ///   [`AuthTreePendingNodesUpdatesIntoDataUpdatesIter`](auth_tree::AuthTreePendingNodesUpdatesIntoDataUpdatesIter`)
    ///   over the returned digests.
    /// * `auth_tree_data_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::auth_tree_data_block_allocation_blocks_log2`].
    /// * `image_header_end` - [End of the filesystem image header on
    ///   storage](crate::fs::cocoonfs::image_header::MutableImageHeader::physical_location).
    pub(super) fn restore_update_states_auth_digests(
        &mut self,
        returned_updates: auth_tree::AuthTreePendingNodesUpdatesIntoDataUpdatesIter,
        auth_tree_data_block_allocation_blocks_log2: u8,
        image_header_end: layout::PhysicalAllocBlockIndex,
    ) -> Result<(), NvFsError> {
        let auth_tree_data_block_allocation_blocks =
            layout::AllocBlockCount::from(1u64 << (auth_tree_data_block_allocation_blocks_log2 as u32));

        let update_states = &mut self.auth_tree_data_blocks_update_states;
        let mut update_states_index = AuthTreeDataBlocksUpdateStatesIndex::from(0usize);
        for returned_update in returned_updates {
            let returned_update = returned_update?;
            // Skip over all update states for (unmodified) Authentication Tree Data Blocks
            // before the returned update's associated position.
            let update_state = loop {
                if usize::from(update_states_index) == update_states.len() {
                    return Ok(());
                }

                let update_state = &mut update_states[update_states_index];
                if update_state.get_target_allocation_blocks_begin()
                    >= returned_update.data_block_allocation_blocks_begin
                {
                    break update_state;
                }

                // The current update state doesn't receive a digest back. It should not have
                // any data modifications.
                if update_state
                    .iter_allocation_blocks()
                    .skip(
                        u64::from(image_header_end)
                            .saturating_sub(u64::from(update_state.get_target_allocation_blocks_begin()))
                            .min(u64::from(auth_tree_data_block_allocation_blocks)) as usize,
                    )
                    .any(|allocation_block_update_state| allocation_block_update_state.has_modified_data())
                {
                    return Err(nvfs_err_internal!());
                }
                update_states_index = update_states_index.step();
            };
            if update_state.get_target_allocation_blocks_begin() != returned_update.data_block_allocation_blocks_begin {
                continue;
            }

            update_states_index = update_states_index.step();

            // Don't store returned digests for Authentication Tree Data Blocks with no data
            // modifications. Getting such one back means there had been a redigest because
            // of changes in the allocation bitmap.
            if !update_state
                .iter_allocation_blocks()
                .skip(
                    u64::from(image_header_end)
                        .saturating_sub(u64::from(update_state.get_target_allocation_blocks_begin()))
                        .min(u64::from(auth_tree_data_block_allocation_blocks)) as usize,
                )
                .any(|allocation_block_update_state| allocation_block_update_state.has_modified_data())
            {
                continue;
            }

            if update_state.get_auth_digest().is_some() {
                return Err(nvfs_err_internal!());
            }
            update_state.set_auth_digest(returned_update.data_block_digest);
        }

        Ok(())
    }
}

/// Implementation of
/// [`JournalUpdateAuthDigestsScriptIterator`](journal::apply_script::JournalUpdateAuthDigestsScriptIterator)
/// over a [`Transaction`].
///
/// Used for [encoding](journal::apply_script::JournalUpdateAuthDigestsScript::encode) the journal
/// log's [`UpdateAuthDigestsScript`
/// field](journal::log::JournalLogFieldTag::UpdateAuthDigestsScript) at
/// [`Transaction`] commit.
#[derive(Clone)]
pub struct TransactionJournalUpdateAuthDigestsScriptIterator<'a> {
    transaction_update_states: &'a AuthTreeDataBlocksUpdateStates,
    next_update_states_index: AuthTreeDataBlocksUpdateStatesIndex,
    image_header_end: layout::PhysicalAllocBlockIndex,
    transaction_pending_frees_iter: alloc_bitmap::SparseAllocBitmapBlockIterator<'a>,
    next_pending_free: Option<layout::PhysicalAllocBlockIndex>,
    auth_tree_data_block_allocation_blocks_log2: u8,
}

impl<'a> TransactionJournalUpdateAuthDigestsScriptIterator<'a> {
    /// Instantiate a [`TransactionJournalUpdateAuthDigestsScriptIterator`].
    ///
    /// # Arguments:
    ///
    /// * `transaction_update_states` - `mut` reference to
    ///   [`Transaction::auth_tree_data_blocks_update_states`].
    /// * `transaction_pending_frees` - Reference to the
    ///   [`Transaction::allocs`]'
    ///   [`TransactionAllocations::pending_frees`](super::TransactionAllocations::pending_frees).
    /// * `image_header_end` - [End of the filesystem image header on
    ///   storage](crate::fs::cocoonfs::image_header::MutableImageHeader::physical_location).
    /// * `auth_tree_data_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::auth_tree_data_block_allocation_blocks_log2`].
    pub fn new(
        transaction_update_states: &'a AuthTreeDataBlocksUpdateStates,
        transaction_pending_frees: &'a alloc_bitmap::SparseAllocBitmap,
        image_header_end: layout::PhysicalAllocBlockIndex,
        auth_tree_data_block_allocation_blocks_log2: u8,
    ) -> Self {
        let mut transaction_pending_frees_iter =
            transaction_pending_frees.block_iter(auth_tree_data_block_allocation_blocks_log2 as u32);
        let next_pending_free = transaction_pending_frees_iter
            .next()
            .map(|next_pending_free| next_pending_free.0);

        Self {
            transaction_update_states,
            next_update_states_index: AuthTreeDataBlocksUpdateStatesIndex::from(0usize),
            image_header_end,
            transaction_pending_frees_iter,
            next_pending_free,
            auth_tree_data_block_allocation_blocks_log2,
        }
    }
}

impl<'a> journal::apply_script::JournalUpdateAuthDigestsScriptIterator
    for TransactionJournalUpdateAuthDigestsScriptIterator<'a>
{
    fn next(&mut self) -> Result<Option<journal::apply_script::JournalUpdateAuthDigestsScriptEntry>, NvFsError> {
        let update_states = self.transaction_update_states;

        let auth_tree_data_block_allocation_blocks =
            layout::AllocBlockCount::from(1u64 << (self.auth_tree_data_block_allocation_blocks_log2 as u32));

        // Skip over any Authentication Tree Data blocks at the current position whose
        // data is not modified. Note that because it is being assumed that
        // unmodified states had been pruned at this point, this is possible
        // only of the IO Block size is larger than that of an Authentication
        // Tree Data Block.
        while usize::from(self.next_update_states_index) != update_states.len() {
            let cur_auth_tree_data_block_update_state = &update_states[self.next_update_states_index];
            // The Allocation Blocks from the image header are not included in an digest
            // content-wise.
            let cur_auth_tree_data_block_allocation_blocks_begin =
                cur_auth_tree_data_block_update_state.get_target_allocation_blocks_begin();
            let skip_count = if self.image_header_end <= cur_auth_tree_data_block_allocation_blocks_begin {
                0usize
            } else {
                // The number of Allocation Blocks in an Authentication Tree Data Block fits an
                // usize.
                usize::try_from(u64::from(
                    self.image_header_end - cur_auth_tree_data_block_allocation_blocks_begin,
                ))
                .unwrap_or(usize::MAX)
            };
            let cur_auth_tree_data_block_any_modified = cur_auth_tree_data_block_update_state
                .iter_allocation_blocks()
                .skip(skip_count)
                .any(|allocation_block_update_state| allocation_block_update_state.has_modified_data());
            if cur_auth_tree_data_block_any_modified {
                break;
            } else {
                self.next_update_states_index = self.next_update_states_index.step();
            }
        }

        let region_allocation_blocks_begin = match self.next_pending_free.as_ref().copied() {
            Some(next_auth_tree_data_block_with_pending_free_allocation_blocks_begin) => {
                if usize::from(self.next_update_states_index) != update_states.len() {
                    let next_auth_tree_data_block_with_modified_data_allocation_blocks_begin =
                        update_states[self.next_update_states_index].get_target_allocation_blocks_begin();
                    if next_auth_tree_data_block_with_pending_free_allocation_blocks_begin
                        <= next_auth_tree_data_block_with_modified_data_allocation_blocks_begin
                    {
                        self.next_pending_free = self
                            .transaction_pending_frees_iter
                            .next()
                            .map(|next_pending_free| next_pending_free.0);
                        if next_auth_tree_data_block_with_pending_free_allocation_blocks_begin
                            == next_auth_tree_data_block_with_modified_data_allocation_blocks_begin
                        {
                            self.next_update_states_index = self.next_update_states_index.step();
                        }
                        next_auth_tree_data_block_with_pending_free_allocation_blocks_begin
                    } else {
                        self.next_update_states_index = self.next_update_states_index.step();
                        next_auth_tree_data_block_with_modified_data_allocation_blocks_begin
                    }
                } else {
                    self.next_pending_free = self
                        .transaction_pending_frees_iter
                        .next()
                        .map(|next_pending_free| next_pending_free.0);
                    next_auth_tree_data_block_with_pending_free_allocation_blocks_begin
                }
            }
            None => {
                if usize::from(self.next_update_states_index) == update_states.len() {
                    return Ok(None);
                }
                let next_auth_tree_data_block_with_modified_data_allocation_blocks_begin =
                    update_states[self.next_update_states_index].get_target_allocation_blocks_begin();
                self.next_update_states_index = self.next_update_states_index.step();
                next_auth_tree_data_block_with_modified_data_allocation_blocks_begin
            }
        };

        let mut region_allocation_blocks = auth_tree_data_block_allocation_blocks;
        let mut last_auth_tree_data_block_allocation_blocks_begin = region_allocation_blocks_begin;
        while usize::from(self.next_update_states_index) < update_states.len() || self.next_pending_free.is_some() {
            let mut cur_auth_tree_data_block_needs_redigest = false;

            if usize::from(self.next_update_states_index) < update_states.len() {
                let cur_auth_tree_data_block_update_state = &update_states[self.next_update_states_index];
                debug_assert!(
                    cur_auth_tree_data_block_update_state.get_target_allocation_blocks_begin()
                        > last_auth_tree_data_block_allocation_blocks_begin
                );
                if cur_auth_tree_data_block_update_state.get_target_allocation_blocks_begin()
                    - last_auth_tree_data_block_allocation_blocks_begin
                    == auth_tree_data_block_allocation_blocks
                {
                    self.next_update_states_index = self.next_update_states_index.step();
                    let cur_auth_tree_data_block_any_modified = cur_auth_tree_data_block_update_state
                        .iter_allocation_blocks()
                        .any(|allocation_block_update_state| allocation_block_update_state.has_modified_data());
                    cur_auth_tree_data_block_needs_redigest |= cur_auth_tree_data_block_any_modified;
                }
            }

            if let Some(next_auth_tree_data_block_with_pending_free_allocation_blocks_begin) =
                self.next_pending_free.as_ref().copied()
            {
                debug_assert!(
                    next_auth_tree_data_block_with_pending_free_allocation_blocks_begin
                        > last_auth_tree_data_block_allocation_blocks_begin
                );
                if next_auth_tree_data_block_with_pending_free_allocation_blocks_begin
                    - last_auth_tree_data_block_allocation_blocks_begin
                    == auth_tree_data_block_allocation_blocks
                {
                    self.next_pending_free = self
                        .transaction_pending_frees_iter
                        .next()
                        .map(|next_pending_free| next_pending_free.0);
                    cur_auth_tree_data_block_needs_redigest = true;
                }
            }

            if cur_auth_tree_data_block_needs_redigest {
                region_allocation_blocks = region_allocation_blocks + auth_tree_data_block_allocation_blocks;
                last_auth_tree_data_block_allocation_blocks_begin += auth_tree_data_block_allocation_blocks;
            } else {
                break;
            }
        }

        let target_range =
            layout::PhysicalAllocBlockRange::from((region_allocation_blocks_begin, region_allocation_blocks));
        Ok(Some(journal::apply_script::JournalUpdateAuthDigestsScriptEntry::new(
            &target_range,
        )))
    }
}
