// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Definition of [`CocoonFs`] and implementation of the [`NvFs`](fs::NvFs)
//! trait.

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

use crate::{
    chip,
    crypto::rng,
    fs::{
        self, NvFsError,
        cocoonfs::{
            alloc_bitmap, auth_tree, extent_ptr, extents, inode_index, keys, layout, read_buffer,
            read_inode_data::ReadInodeDataFuture, transaction, write_inode_data::WriteInodeDataFuture,
        },
    },
    nvfs_err_internal,
    utils_async::{
        self, asynchronous,
        sync_types::{self, Lock as _, RwLock as _, SyncRcPtrRef as _},
    },
    utils_common::{alloc::box_try_new, bitmanip::UBitManip as _, fixed_vec::FixedVec, zeroize},
};
use core::{
    convert, future, marker, mem, ops,
    ops::{Deref as _, DerefMut as _},
    pin,
    sync::atomic,
    task,
};

/// [`SyncRcPtr`](sync_types::SyncRcPtr) to a [`CocoonFs`] instance.
pub type CocoonFsSyncRcPtrType<ST, C> = pin::Pin<
    <<ST as sync_types::SyncTypes>::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>::SyncRcPtr<CocoonFs<ST, C>>,
>;

/// [`SyncRcPtrRef`](sync_types::SyncRcPtrRef) to a [`CocoonFs`] instance.
pub(super) type CocoonFsSyncRcPtrRefType<'a, ST, C> =
    <CocoonFsSyncRcPtrType<ST, C> as sync_types::SyncRcPtr<CocoonFs<ST, C>>>::SyncRcPtrRef<'a>;

/// A CocoonFs instance in operational state.
///
/// A [`CocoonFs`] instance may be obtained either by
/// [opening](super::CocoonFsOpenFsFuture) an existing filesystem on storage, or
/// by [creating a new one](super::CocoonFsMkFsFuture).
///
/// Once instantiated, the generic [`NvFs`](fs::NvFs) trait interface is
/// supposed to be used for operating on it.
pub struct CocoonFs<ST: sync_types::SyncTypes, C: chip::NvChip> {
    /// The filesystem's backing storage.
    pub(super) chip: C,
    /// Static filesystem parameters never modified throughout the [`CocoonFs`]
    /// instance's lifetime.
    pub(super) fs_config: CocoonFsConfig,
    /// Dynamic filesystem state.
    ///
    /// Only the filesystem instance's currently committing transaction, i.e.
    /// the [`ProgressCommittingTransactionFuture`] stored at
    /// [`Self::committing_transaction`], if any, ever gains exclusive write
    /// access by means of holding an [`CocoonFsSyncStateMemberWriteGuard`].
    ///
    /// Any readers, including transactions in their preparation phase, always
    /// only obtain mere [`CocoonFsSyncStateMemberReadGuard`]s on the
    /// `sync_state`. For robustness against "abandoned" readers, i.e.
    /// readers never polled again for some reason, the
    /// [`CocoonFsSyncStateMemberReadGuard`] is reacquired upon each
    /// `poll()` invocation and released again before return. That is, no
    /// [`CocoonFsSyncStateMemberReadGuard`] is ever held across multiple
    /// `poll()` invocations. To still establish consistency across multiple
    /// `poll()` invocations, the reader's associated
    /// [`CocoonFsConsistentReadSequence`] gets revalidated upon each `poll()`
    /// entry, c.f. [`CocoonFsConsistentReadSequence::continue_sequence()`].
    sync_state: CocoonFsSyncStateMemberType<ST>,
    /// State to coordinate between multiple transaction in their preparation
    /// phase.
    ///
    /// A [`FutureQueue`](asynchronous::FutureQueue) of
    /// [`PendingTransactionsSyncFuture`] entries, for coordinating storage
    /// allocations potentially subject to pre-commit writes.
    pending_transactions_sync_state: CocoonFsPendingTransactionsSyncStateMemberType<ST, C>,
    /// Transaction commit sequence number used for validating
    /// [`CocoonFsConsistentReadSequence`]s.
    ///
    /// Incremented
    /// * while holding a [`CocoonFsSyncStateMemberWriteGuard`] on
    ///   [`Self::sync_state`] and
    /// * before resetting the [`Self::committing_transaction`].
    transaction_commit_gen: atomic::AtomicU64,
    /// Whether or not any not yet committed transaction is pending.
    ///
    /// Reset to zero upon transaction commit, transitioned to non-zero
    /// upon a subsequent [`CocoonFsStartTransactionFuture`] completion.
    ///
    /// Used for selecting the first among a number of pending transactions as
    /// the "primary" one, enabling more freedom regarding in-place
    /// writes for it.
    any_transaction_pending: atomic::AtomicUsize,
    /// The currently committing transaction, if any.
    ///
    /// The initiating [`CocoonFsCommitTransactionFuture`] and any subsequently
    /// started [`CocoonFsStartReadSequenceFuture`] or
    /// [`CocoonFsStartTransactionFuture`] cooperate to drive progress
    /// forward.
    committing_transaction: ST::Lock<CommittingTransactionState<ST, C>>,
}

/// Static [`CocoonFs`] filesystem parameters.
pub(super) struct CocoonFsConfig {
    pub image_layout: layout::ImageLayout,
    pub salt: FixedVec<u8, 4>,
    pub inode_index_entry_leaf_node_block_ptr: extent_ptr::EncodedBlockPtr,
    pub enable_trimming: bool,
    pub root_key: keys::RootKey,
    pub image_header_end: layout::PhysicalAllocBlockIndex,
}

/// Dynamic [`CocoonFs`] instance state.
///
/// Maintained at [`CocoonFs::sync_state`].
pub(super) struct CocoonFsSyncState<ST: sync_types::SyncTypes> {
    pub image_size: layout::AllocBlockCount,
    pub alloc_bitmap: alloc_bitmap::AllocBitmap,
    pub alloc_bitmap_file: alloc_bitmap::AllocBitmapFile,
    pub auth_tree: auth_tree::AuthTree<ST>,
    pub read_buffer: read_buffer::ReadBuffer<ST>,
    pub inode_index: inode_index::InodeIndex<ST>,
    pub keys_cache: ST::RwLock<keys::KeyCache>,
}

impl<ST: sync_types::SyncTypes> CocoonFsSyncState<ST> {
    /// Clear all caches.
    pub fn clear_caches(&self) {
        self.auth_tree.clear_caches();
        self.read_buffer.clear_caches();
        self.inode_index.clear_caches();
        self.keys_cache.write().clear();
    }
}

/// State shared between pending transactions in their pre-commit preparation
/// phase.
///
/// Maintained at [`CocoonFs::pending_transactions_sync_state`] and accessed via
/// [`PendingTransactionsSyncFuture`] instances enqueued to the serializing
/// [`FutureQueue`](asynchronous::FutureQueue).
pub(super) struct CocoonFsPendingTransactionsSyncState {
    /// Allocations made on behalf any pending transactions potentially subject
    /// to pre-commit writes.
    ///
    /// In general, transactions will may to storage during their pre-commit
    /// preparation phase only if the containing "Journal Block", i.e. the
    /// larger of an [Authentication Tree Data
    /// Block](layout::ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// and an [IO Block](layout::ImageLayout::io_block_allocation_blocks_log2)
    /// had previously been unallocated (in the filesystem's most recently
    /// committed state).
    ///
    /// Multiple such transactions issuing writes concurrently during their
    /// preparation phase could still interfere badly with each other
    /// though. In order to prevent this, establish the additional rule that
    /// * a transaction may write pre-commit only if it allocated the full
    ///   Journal Block,
    /// * except for one selected out of all pending transactions, the "primary"
    ///   one.
    ///
    /// Track all pre-commit allocations from any pending transaction
    /// potentially subject to pre-commit writes, i.e. those contained in
    /// some previously free Journal Blocks.
    pub pending_allocs: alloc_bitmap::SparseAllocBitmap,
}

impl CocoonFsPendingTransactionsSyncState {
    /// Create a [`CocoonFsPendingTransactionsSyncState`] in its initial state.
    pub fn new() -> Self {
        Self {
            pending_allocs: alloc_bitmap::SparseAllocBitmap::new(),
        }
    }

    /// Register a block as allocated on behalf of a transaction.
    ///
    /// # Arguments:
    ///
    /// * `fs_instance_sync_state` - Reference to [`CocoonFs::sync_state`].
    /// * `block_allocation_blocks_begin` - Beginning of the block. Must be
    ///   aligned by two to the power of `block_allocation_blocks_log2`.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size in
    ///   units of [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    pub fn register_allocated_block<ST: sync_types::SyncTypes, C: chip::NvChip>(
        &mut self,
        fs_instance_sync_state: &CocoonFsSyncStateMemberRef<'_, ST, C>,
        block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        block_allocation_blocks_log2: u32,
    ) -> Result<(), fs::NvFsError> {
        assert!(block_allocation_blocks_log2 <= alloc_bitmap::BITMAP_WORD_BITS_LOG2);
        let fs_instance = fs_instance_sync_state.get_fs_ref();
        let image_layout = &fs_instance.fs_config.image_layout;

        // The transaction preparation phase may write to
        // journal_block_allocation_blocks_log2 sized blocks before commit
        // already, if a complete such block had been unallocated before the
        // transaction. In order to ensure that concurrent transactions don't interfere
        // with each other there, track allocation of such potential pre-commit
        // write candidates at a central place.
        let journal_block_allocation_blocks_log2 = (image_layout.auth_tree_data_block_allocation_blocks_log2 as u32)
            .max(image_layout.io_block_allocation_blocks_log2 as u32);
        assert!(journal_block_allocation_blocks_log2 <= alloc_bitmap::BITMAP_WORD_BITS_LOG2);

        let block_journal_blocks_allocation_blocks_begin = layout::PhysicalAllocBlockIndex::from(
            u64::from(block_allocation_blocks_begin).round_down_pow2(journal_block_allocation_blocks_log2),
        );
        let block_journal_blocks_log2 =
            block_allocation_blocks_log2.saturating_sub(journal_block_allocation_blocks_log2);
        let block_journal_blocks = 1u32 << block_journal_blocks_log2;
        let empty_sparse_alloc_bitmap = alloc_bitmap::SparseAllocBitmapUnion::new(&[]);
        let mut journal_block_chunked_alloc_bitmap_iter =
            fs_instance_sync_state.alloc_bitmap.iter_chunked_at_allocation_block(
                &empty_sparse_alloc_bitmap,
                &empty_sparse_alloc_bitmap,
                block_journal_blocks_allocation_blocks_begin,
                1u32 << journal_block_allocation_blocks_log2,
            );
        let mut block_journal_block_index: u32 = 0;
        while block_journal_block_index < block_journal_blocks {
            // Consider everything beyond the end of the region tracked by the allocation
            // bitmap as unallocated -- there might be a grow operation ongoing.
            let journal_block_alloc_bitmap_word = journal_block_chunked_alloc_bitmap_iter.next().unwrap_or(0);

            // Some parts of the journal block had been allocated before the transaction,
            // the transaction will not write to it when preparing the journal,
            // i.e. before the actual commit.
            if journal_block_alloc_bitmap_word != 0 {
                block_journal_block_index += 1;
                continue;
            }

            // Otherwise register the allocation at a central place so that concurrent
            // transaction preparations will not stomp on each other's feet.
            if let Err(e) = self.pending_allocs.add_block(
                block_allocation_blocks_begin
                    + layout::AllocBlockCount::from(
                        (block_journal_block_index as u64) << journal_block_allocation_blocks_log2,
                    ),
                journal_block_allocation_blocks_log2.min(block_allocation_blocks_log2),
            ) {
                // Rollback.
                self.pending_allocs
                    .remove_block(block_allocation_blocks_begin, block_allocation_blocks_log2);
                self.pending_allocs.reset_remove_rollback();
                return Err(e);
            }

            block_journal_block_index += 1;
        }

        Ok(())
    }

    /// Deregister a block previously registered as allocated on behalf of a
    /// transaction.
    ///
    /// # Arguments:
    ///
    /// * `_fs_instance_sync_state` - Reference to [`CocoonFs::sync_state`].
    /// * `block_allocation_blocks_begin` - Beginning of the block. Must be
    ///   aligned by two to the power of `block_allocation_blocks_log2`.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size in
    ///   units of [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    pub fn deregister_allocated_block<ST: sync_types::SyncTypes, C: chip::NvChip>(
        &mut self,
        _fs_instance_sync_state: &CocoonFsSyncStateMemberRef<'_, ST, C>,
        block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        block_allocation_blocks_log2: u32,
    ) {
        self.pending_allocs
            .remove_block(block_allocation_blocks_begin, block_allocation_blocks_log2);
        self.pending_allocs.reset_remove_rollback();
    }

    /// Register a set of blocks as allocated on behalf of a transaction.
    ///
    /// # Arguments:
    ///
    /// * `fs_instance_sync_state` - Reference to [`CocoonFs::sync_state`].
    /// * `blocks_allocation_blocks_begin` - Beginnings of the respective
    ///   blocks. Must all be aligned by two to the power of
    ///   `block_allocation_blocks_log2`.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size in
    ///   units of [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    pub fn register_allocated_blocks<ST: sync_types::SyncTypes, C: chip::NvChip>(
        &mut self,
        fs_instance_sync_state: &CocoonFsSyncStateMemberRef<'_, ST, C>,
        blocks_allocation_blocks_begin: &[layout::PhysicalAllocBlockIndex],
        block_allocation_blocks_log2: u32,
    ) -> Result<(), fs::NvFsError> {
        for i in 0..blocks_allocation_blocks_begin.len() {
            if let Err(e) = self.register_allocated_block(
                fs_instance_sync_state,
                blocks_allocation_blocks_begin[i],
                block_allocation_blocks_log2,
            ) {
                for block_allocation_blocks_begin in blocks_allocation_blocks_begin.iter().take(i) {
                    // Rollback.
                    self.deregister_allocated_block(
                        fs_instance_sync_state,
                        *block_allocation_blocks_begin,
                        block_allocation_blocks_log2,
                    );
                }
                return Err(e);
            }
        }

        Ok(())
    }

    /// Deregister a set of blocks previously registered as allocated on behalf
    /// of a transaction.
    ///
    /// # Arguments:
    ///
    /// * `fs_instance_sync_state` - Reference to [`CocoonFs::sync_state`].
    /// * `blocks_allocation_blocks_begin` - Beginnings of the respective
    ///   blocks. Must all be aligned by two to the power of
    ///   `block_allocation_blocks_log2`.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size in
    ///   units of [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    pub fn deregister_allocated_blocks<ST: sync_types::SyncTypes, C: chip::NvChip>(
        &mut self,
        fs_instance_sync_state: &CocoonFsSyncStateMemberRef<'_, ST, C>,
        blocks_allocation_blocks_begin: &[layout::PhysicalAllocBlockIndex],
        block_allocation_blocks_log2: u32,
    ) {
        for block_allocation_blocks_begin in blocks_allocation_blocks_begin {
            self.deregister_allocated_block(
                fs_instance_sync_state,
                *block_allocation_blocks_begin,
                block_allocation_blocks_log2,
            );
        }
    }

    /// Register an extent as allocated on behalf of a transaction.
    ///
    /// # Arguments:
    ///
    /// * `fs_instance_sync_state` - Reference to [`CocoonFs::sync_state`].
    /// * `extent` - The extent's location.
    pub fn register_allocated_extent<ST: sync_types::SyncTypes, C: chip::NvChip>(
        &mut self,
        fs_instance_sync_state: &CocoonFsSyncStateMemberRef<'_, ST, C>,
        extent: &layout::PhysicalAllocBlockRange,
    ) -> Result<(), NvFsError> {
        let fs_instance = fs_instance_sync_state.get_fs_ref();
        let image_layout = &fs_instance.fs_config.image_layout;

        // The transaction preparation phase may write to
        // journal_block_allocation_blocks_log2 sized blocks before commit
        // already, if a complete such block had been unallocated before the
        // transaction. In order to ensure that concurrent transactions don't interfere
        // with each other there, track allocation of such potential pre-commit
        // write candidates at a central place.
        let journal_block_allocation_blocks_log2 = (image_layout.auth_tree_data_block_allocation_blocks_log2 as u32)
            .max(image_layout.io_block_allocation_blocks_log2 as u32);
        assert!(journal_block_allocation_blocks_log2 <= alloc_bitmap::BITMAP_WORD_BITS_LOG2);
        let mut aligned_remaining_extent_allocation_blocks_begin =
            extent.begin().align_down(journal_block_allocation_blocks_log2);
        let empty_sparse_alloc_bitmap = alloc_bitmap::SparseAllocBitmapUnion::new(&[]);
        let mut journal_block_chunked_alloc_bitmap_iter =
            fs_instance_sync_state.alloc_bitmap.iter_chunked_at_allocation_block(
                &empty_sparse_alloc_bitmap,
                &empty_sparse_alloc_bitmap,
                aligned_remaining_extent_allocation_blocks_begin,
                1u32 << journal_block_allocation_blocks_log2,
            );
        let mut found_region_allocation_blocks_begin = extent.begin();
        loop {
            // Consider everything beyond the end of the region tracked by the allocation
            // bitmap as unallocated -- there might be a grow operation ongoing.
            let journal_block_alloc_bitmap_word = journal_block_chunked_alloc_bitmap_iter.next().unwrap_or(0);

            let mut found_region_allocation_blocks_end = aligned_remaining_extent_allocation_blocks_begin;
            aligned_remaining_extent_allocation_blocks_begin +=
                layout::AllocBlockCount::from(1u64 << journal_block_allocation_blocks_log2);

            if journal_block_alloc_bitmap_word != 0 || aligned_remaining_extent_allocation_blocks_begin >= extent.end()
            {
                if journal_block_alloc_bitmap_word == 0 {
                    found_region_allocation_blocks_end = extent.end();
                }
                if found_region_allocation_blocks_begin < found_region_allocation_blocks_end {
                    if let Err(e) = self.pending_allocs.add_extent(&layout::PhysicalAllocBlockRange::new(
                        found_region_allocation_blocks_begin,
                        found_region_allocation_blocks_end,
                    )) {
                        // Rollback.
                        self.pending_allocs.remove_extent(&layout::PhysicalAllocBlockRange::new(
                            extent.begin(),
                            found_region_allocation_blocks_end,
                        ));
                        self.pending_allocs.reset_remove_rollback();
                        return Err(e);
                    }
                }

                if aligned_remaining_extent_allocation_blocks_begin >= extent.end() {
                    break;
                }

                found_region_allocation_blocks_begin = aligned_remaining_extent_allocation_blocks_begin;
            }
        }

        Ok(())
    }

    /// Deregister an extent previously registered as allocated on behalf of a
    /// transaction.
    ///
    /// # Arguments:
    ///
    /// * `_fs_instance_sync_state` - Reference to [`CocoonFs::sync_state`].
    /// * `extent` - The extent's location.
    pub fn deregister_allocated_extent<ST: sync_types::SyncTypes, C: chip::NvChip>(
        &mut self,
        _fs_instance_sync_state: &CocoonFsSyncStateMemberRef<'_, ST, C>,
        extent: &layout::PhysicalAllocBlockRange,
    ) {
        self.pending_allocs.remove_extent(extent);
        self.pending_allocs.reset_remove_rollback();
    }

    /// Register some extents as allocated on behalf of a transaction.
    ///
    /// # Arguments:
    ///
    /// * `fs_instance_sync_state` - Reference to [`CocoonFs::sync_state`].
    /// * `extents` - The extents.
    pub fn register_allocated_extents<ST: sync_types::SyncTypes, C: chip::NvChip>(
        &mut self,
        fs_instance_sync_state: &CocoonFsSyncStateMemberRef<'_, ST, C>,
        extents: &extents::PhysicalExtents,
    ) -> Result<(), NvFsError> {
        for (i, extent) in extents.iter().enumerate() {
            if let Err(e) = self.register_allocated_extent(fs_instance_sync_state, &extent) {
                // Rollback.
                for extent in extents.iter().take(i) {
                    self.deregister_allocated_extent(fs_instance_sync_state, &extent);
                }
                return Err(e);
            }
        }

        Ok(())
    }

    /// Deregister some extents previously registered as allocated on behalf of
    /// a transaction.
    ///
    /// # Arguments:
    ///
    /// * `fs_instance_sync_state` - Reference to [`CocoonFs::sync_state`].
    /// * `extents` - The extents.
    pub fn deregister_allocated_extents<ST: sync_types::SyncTypes, C: chip::NvChip>(
        &mut self,
        fs_instance_sync_state: &CocoonFsSyncStateMemberRef<'_, ST, C>,
        extents: &extents::PhysicalExtents,
    ) {
        for extent in extents.iter() {
            self.deregister_allocated_extent(fs_instance_sync_state, &extent);
        }
    }
}

/// Type of the [`CocoonFs::sync_state`] member.
type CocoonFsSyncStateMemberType<ST> = asynchronous::AsyncRwLock<ST, CocoonFsSyncState<ST>>;

/// Type of the [`CocoonFs::pending_transactions_sync_state`] member.
type CocoonFsPendingTransactionsSyncStateMemberType<ST, C> =
    asynchronous::FutureQueue<ST, CocoonFsPendingTransactionsSyncState, PendingTransactionsSyncFuture<ST, C>>;

/// [`DerefInnerByTag`](sync_types::DerefInnerByTag) `TAG` for derefencing
/// [`CocoonFs::sync_state`].
pub(super) struct DerefCocoonFsSyncStateMemberTag {}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> sync_types::DerefInnerByTag<DerefCocoonFsSyncStateMemberTag>
    for CocoonFs<ST, C>
{
    utils_async::impl_deref_inner_by_tag!(sync_state, CocoonFsSyncStateMemberType<ST>);
}

/// [`SyncRcPtrPtrForInner`](sync_types::SyncRcPtrForInner) to
/// [`CocoonFs::sync_state`].
type CocoonFsSyncStateMemberSyncRcPtrType<ST, C> =
    sync_types::SyncRcPtrForInner<CocoonFs<ST, C>, CocoonFsSyncRcPtrType<ST, C>, DerefCocoonFsSyncStateMemberTag>;

/// [`SyncRcPtrPtrRefForInner`](sync_types::SyncRcPtrRefForInner) to
/// [`CocoonFs::sync_state`].
type CocoonFsSyncStateMemberSyncRcPtrRefType<'a, ST, C> =
    <CocoonFsSyncStateMemberSyncRcPtrType<ST, C> as sync_types::SyncRcPtr<
        CocoonFsSyncStateMemberType<ST>,
    >>::SyncRcPtrRef<'a>;

/// [`AsyncRwLockWriteGuard`](asynchronous::AsyncRwLockWriteGuard) for
/// [`CocoonFs::sync_state`].
type CocoonFsSyncStateMemberWriteGuard<ST, C> =
    asynchronous::AsyncRwLockWriteGuard<ST, CocoonFsSyncState<ST>, CocoonFsSyncStateMemberSyncRcPtrType<ST, C>>;

/// [`AsyncRwLockWriteWeakGuard`](asynchronous::AsyncRwLockWriteWeakGuard) for
/// [`CocoonFs::sync_state`].
type CocoonFsSyncStateMemberWriteWeakGuard<ST, C> =
    asynchronous::AsyncRwLockWriteWeakGuard<ST, CocoonFsSyncState<ST>, CocoonFsSyncStateMemberSyncRcPtrType<ST, C>>;

/// [`AsyncRwLockWriteFuture`](asynchronous::AsyncRwLockWriteFuture) for
/// obtaining an [`CocoonFsSyncStateMemberWriteGuard`]
/// on [`CocoonFs::sync_state`].
type CocoonFsSyncStateMemberWriteFuture<ST, C> =
    asynchronous::AsyncRwLockWriteFuture<ST, CocoonFsSyncState<ST>, CocoonFsSyncStateMemberSyncRcPtrType<ST, C>>;

/// [`AsyncRwLockReadGuard`](asynchronous::AsyncRwLockReadGuard) for
/// [`CocoonFs::sync_state`].
type CocoonFsSyncStateMemberReadGuard<ST, C> =
    asynchronous::AsyncRwLockReadGuard<ST, CocoonFsSyncState<ST>, CocoonFsSyncStateMemberSyncRcPtrType<ST, C>>;

/// Multiplexer for [`CocoonFsSyncStateMemberReadGuard`] or
/// [`CocoonFsSyncStateMemberWriteGuard`].
///
/// Many of the internal APIs can operate well on a shared
/// [`CocoonFs::sync_state`] reference, but can enable certain optimization like
/// avoiding to take some locks when exclusive access is granted.
///
/// In order to support either case through common interfaces, define
/// [`CocoonFsSyncStateMemberRef`] as a wrapper to either a
/// [`CocoonFsSyncStateMemberReadGuard`] or a
/// [`CocoonFsSyncStateMemberWriteGuard`].
pub(super) enum CocoonFsSyncStateMemberRef<'a, ST: sync_types::SyncTypes, C: chip::NvChip> {
    Ref {
        sync_state_read_guard: &'a CocoonFsSyncStateMemberReadGuard<ST, C>,
    },
    MutRef {
        sync_state_write_guard: &'a mut CocoonFsSyncStateMemberWriteGuard<ST, C>,
    },
}

impl<'a, ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsSyncStateMemberRef<'a, ST, C> {
    /// Reborrow the [`CocoonFsSyncStateMemberRef`].
    ///
    /// [`CocoonFsSyncStateMemberRef`] is not covariant. `make_borrow()` allows
    /// for reborrowing with an adjusted lifetime.
    #[allow(dead_code)]
    pub fn make_borrow(&mut self) -> CocoonFsSyncStateMemberRef<'_, ST, C> {
        match self {
            Self::Ref { sync_state_read_guard } => CocoonFsSyncStateMemberRef::Ref { sync_state_read_guard },
            Self::MutRef { sync_state_write_guard } => CocoonFsSyncStateMemberRef::MutRef { sync_state_write_guard },
        }
    }

    /// Get the containing [`CocoonFs`] instance.
    ///
    /// Get the container of the [`CocoonFs::sync_state`] referenced by `self`.
    pub fn get_fs_ref(&self) -> CocoonFsSyncRcPtrRefType<'_, ST, C> {
        match self {
            Self::Ref { sync_state_read_guard } => sync_state_read_guard.get_rwlock().get_container().clone(),
            Self::MutRef { sync_state_write_guard } => sync_state_write_guard.get_rwlock().get_container().clone(),
        }
    }

    /// Destructure into references to the [`CocoonFsSyncState`]'s constituent
    /// members.
    ///
    /// Return a tuple of the containing [`CocoonFs`] instance as the first
    /// element and references to the [`CocoonFsSyncState`]'s constituent
    /// members for the remainder.
    #[allow(clippy::type_complexity)]
    pub fn fs_instance_and_destructure_borrow<'b>(
        &'b mut self,
    ) -> (
        CocoonFsSyncRcPtrRefType<'b, ST, C>,
        &'b layout::AllocBlockCount,
        &'b alloc_bitmap::AllocBitmap,
        &'b alloc_bitmap::AllocBitmapFile,
        auth_tree::AuthTreeRef<'b, ST>,
        &'b inode_index::InodeIndex<ST>,
        &'b read_buffer::ReadBuffer<ST>,
        keys::KeyCacheRef<'b, ST>,
    ) {
        match self {
            Self::Ref { sync_state_read_guard } => {
                let fs_instance = sync_state_read_guard.get_rwlock().get_container().clone();
                (
                    fs_instance,
                    &sync_state_read_guard.image_size,
                    &sync_state_read_guard.alloc_bitmap,
                    &sync_state_read_guard.alloc_bitmap_file,
                    auth_tree::AuthTreeRef::Ref {
                        tree: &sync_state_read_guard.auth_tree,
                    },
                    &sync_state_read_guard.inode_index,
                    &sync_state_read_guard.read_buffer,
                    keys::KeyCacheRef::Ref {
                        cache: &sync_state_read_guard.keys_cache,
                    },
                )
            }
            Self::MutRef { sync_state_write_guard } => {
                // Not needed, but make the types explicit to be sure we're indeed getting a mut
                // ref on the sync_state.
                let (rwlock_ptr_ref, sync_state) = sync_state_write_guard.borrow_outer_inner_mut();
                let fs_instance = rwlock_ptr_ref.get_container().clone();
                (
                    fs_instance,
                    &sync_state.image_size,
                    &sync_state.alloc_bitmap,
                    &sync_state.alloc_bitmap_file,
                    auth_tree::AuthTreeRef::MutRef {
                        tree: &mut sync_state.auth_tree,
                    },
                    &sync_state.inode_index,
                    &sync_state.read_buffer,
                    keys::KeyCacheRef::MutRef {
                        cache: sync_state.keys_cache.get_mut(),
                    },
                )
            }
        }
    }
}

impl<'a, ST: sync_types::SyncTypes, C: chip::NvChip> convert::From<&'a CocoonFsSyncStateMemberReadGuard<ST, C>>
    for CocoonFsSyncStateMemberRef<'a, ST, C>
{
    fn from(value: &'a CocoonFsSyncStateMemberReadGuard<ST, C>) -> Self {
        Self::Ref {
            sync_state_read_guard: value,
        }
    }
}

impl<'a, ST: sync_types::SyncTypes, C: chip::NvChip> convert::From<&'a mut CocoonFsSyncStateMemberWriteGuard<ST, C>>
    for CocoonFsSyncStateMemberRef<'a, ST, C>
{
    fn from(value: &'a mut CocoonFsSyncStateMemberWriteGuard<ST, C>) -> Self {
        Self::MutRef {
            sync_state_write_guard: value,
        }
    }
}

impl<'a, 'b, ST: sync_types::SyncTypes, C: chip::NvChip> convert::From<&'a mut CocoonFsSyncStateMemberMutRef<'b, ST, C>>
    for CocoonFsSyncStateMemberRef<'a, ST, C>
{
    fn from(value: &'a mut CocoonFsSyncStateMemberMutRef<'b, ST, C>) -> Self {
        Self::MutRef {
            sync_state_write_guard: value.sync_state_write_guard,
        }
    }
}

impl<'a, ST: sync_types::SyncTypes, C: chip::NvChip> ops::Deref for CocoonFsSyncStateMemberRef<'a, ST, C> {
    type Target = CocoonFsSyncState<ST>;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Ref { sync_state_read_guard } => sync_state_read_guard,
            Self::MutRef { sync_state_write_guard } => sync_state_write_guard,
        }
    }
}

impl<'a, 'b, ST: sync_types::SyncTypes, C: chip::NvChip> convert::From<&'a mut CocoonFsSyncStateMemberRef<'b, ST, C>>
    for auth_tree::AuthTreeRef<'a, ST>
{
    fn from(value: &'a mut CocoonFsSyncStateMemberRef<'b, ST, C>) -> Self {
        match value {
            CocoonFsSyncStateMemberRef::Ref { sync_state_read_guard } => auth_tree::AuthTreeRef::Ref {
                tree: &sync_state_read_guard.auth_tree,
            },
            CocoonFsSyncStateMemberRef::MutRef { sync_state_write_guard } => auth_tree::AuthTreeRef::MutRef {
                tree: &mut sync_state_write_guard.auth_tree,
            },
        }
    }
}

/// Wrapper around [`CocoonFsSyncStateMemberWriteGuard`] with destructuring
/// functionality.
pub(super) struct CocoonFsSyncStateMemberMutRef<'a, ST: sync_types::SyncTypes, C: chip::NvChip> {
    sync_state_write_guard: &'a mut CocoonFsSyncStateMemberWriteGuard<ST, C>,
}

impl<'a, ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsSyncStateMemberMutRef<'a, ST, C> {
    /// Reborrow the [`CocoonFsSyncStateMemberMutRef`].
    ///
    /// [`CocoonFsSyncStateMemberMutRef`] is not covariant. `make_borrow()`
    /// allows for reborrowing with an adjusted lifetime.
    pub fn make_borrow(&mut self) -> CocoonFsSyncStateMemberMutRef<'_, ST, C> {
        CocoonFsSyncStateMemberMutRef {
            sync_state_write_guard: self.sync_state_write_guard,
        }
    }

    /// Get the containing [`CocoonFs`] instance.
    ///
    /// Get the container of the [`CocoonFs::sync_state`] referenced by `self`.
    pub fn get_fs_ref(&self) -> CocoonFsSyncRcPtrRefType<'_, ST, C> {
        self.sync_state_write_guard.get_rwlock().get_container().clone()
    }

    /// Destructure into references to the [`CocoonFsSyncState`]'s constituent
    /// members.
    ///
    /// Return a tuple of the containing [`CocoonFs`] instance as the first
    /// element and `mut` references to the [`CocoonFsSyncState`]'s constituent
    /// members for the remainder.
    #[allow(clippy::type_complexity)]
    pub fn fs_instance_and_destructure_borrow_mut<'b>(
        &'b mut self,
    ) -> (
        CocoonFsSyncRcPtrRefType<'b, ST, C>,
        &'b mut layout::AllocBlockCount,
        &'b mut alloc_bitmap::AllocBitmap,
        &'b mut alloc_bitmap::AllocBitmapFile,
        &'b mut auth_tree::AuthTree<ST>,
        &'b mut inode_index::InodeIndex<ST>,
        &'b mut read_buffer::ReadBuffer<ST>,
        &'b mut keys::KeyCache,
    ) {
        // Not needed, but make the types explicit to be sure we're indeed getting a mut
        // ref on the sync_state.
        let (rwlock_ptr_ref, sync_state) = self.sync_state_write_guard.borrow_outer_inner_mut();
        let fs_instance = rwlock_ptr_ref.get_container().clone();
        (
            fs_instance,
            &mut sync_state.image_size,
            &mut sync_state.alloc_bitmap,
            &mut sync_state.alloc_bitmap_file,
            &mut sync_state.auth_tree,
            &mut sync_state.inode_index,
            &mut sync_state.read_buffer,
            sync_state.keys_cache.get_mut(),
        )
    }
}

impl<'a, ST: sync_types::SyncTypes, C: chip::NvChip> convert::From<&'a mut CocoonFsSyncStateMemberWriteGuard<ST, C>>
    for CocoonFsSyncStateMemberMutRef<'a, ST, C>
{
    fn from(value: &'a mut CocoonFsSyncStateMemberWriteGuard<ST, C>) -> Self {
        Self {
            sync_state_write_guard: value,
        }
    }
}

impl<'a, ST: sync_types::SyncTypes, C: chip::NvChip> ops::Deref for CocoonFsSyncStateMemberMutRef<'a, ST, C> {
    type Target = CocoonFsSyncState<ST>;

    fn deref(&self) -> &Self::Target {
        self.sync_state_write_guard.deref()
    }
}

impl<'a, ST: sync_types::SyncTypes, C: chip::NvChip> ops::DerefMut for CocoonFsSyncStateMemberMutRef<'a, ST, C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.sync_state_write_guard.deref_mut()
    }
}

/// [`DerefInnerByTag`](sync_types::DerefInnerByTag) `TAG` for derefencing
/// [`CocoonFs::pending_transactions_sync_state`].
struct DerefCocoonFsPendingTransactionsSyncStateMemberTag {}

impl<ST: sync_types::SyncTypes, C: chip::NvChip>
    sync_types::DerefInnerByTag<DerefCocoonFsPendingTransactionsSyncStateMemberTag> for CocoonFs<ST, C>
{
    utils_async::impl_deref_inner_by_tag!(
        pending_transactions_sync_state,
        CocoonFsPendingTransactionsSyncStateMemberType<ST, C>
    );
}

/// Plain [`SyncRcPtrPtrForInner`](sync_types::SyncRcPtrForInner) to
/// [`CocoonFs::pending_transactions_sync_state`] not wrapped in
/// [`Pin`](pin::Pin).
type PlainCocoonFsPendingTransactionsSyncStateMemberSyncRcPtrType<ST, C> = sync_types::SyncRcPtrForInner<
    CocoonFs<ST, C>,
    CocoonFsSyncRcPtrType<ST, C>,
    DerefCocoonFsPendingTransactionsSyncStateMemberTag,
>;

/// Plain [`SyncRcPtrPtrRefForInner`](sync_types::SyncRcPtrRefForInner) to
/// [`CocoonFs::pending_transactions_sync_state`] not wrapped in
/// [`Pin`](pin::Pin).
type PlainCocoonFsPendingTransactionsSyncStateMemberSyncRcPtrRefType<'a, ST, C> =
    <PlainCocoonFsPendingTransactionsSyncStateMemberSyncRcPtrType<ST, C> as sync_types::SyncRcPtr<
        CocoonFsPendingTransactionsSyncStateMemberType<ST, C>,
    >>::SyncRcPtrRef<'a>;

/// [Pinned](pin::Pin) [`SyncRcPtrPtrForInner`](sync_types::SyncRcPtrForInner)
/// to [`CocoonFs::pending_transactions_sync_state`].
type CocoonFsPendingTransactionsSyncStateMemberSyncRcPtrType<ST, C> =
    pin::Pin<PlainCocoonFsPendingTransactionsSyncStateMemberSyncRcPtrType<ST, C>>;

/// [Pinned](pin::Pin)
/// [`SyncRcPtrPtrRefForInner`](sync_types::SyncRcPtrRefForInner) to
/// [`CocoonFs::pending_transactions_sync_state`].
type CocoonFsPendingTransactionsSyncStateMemberSyncRcPtrRefType<'a, ST, C> =
    <CocoonFsPendingTransactionsSyncStateMemberSyncRcPtrType<ST, C> as sync_types::SyncRcPtr<
        CocoonFsPendingTransactionsSyncStateMemberType<ST, C>,
    >>::SyncRcPtrRef<'a>;

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFs<ST, C> {
    /// Construct a [`CocoonFs`] instance from its constituent parts.
    pub(super) fn new(chip: C, fs_config: CocoonFsConfig, fs_sync_state: CocoonFsSyncState<ST>) -> Self {
        Self {
            chip,
            fs_config,
            sync_state: CocoonFsSyncStateMemberType::new(fs_sync_state),
            pending_transactions_sync_state: CocoonFsPendingTransactionsSyncStateMemberType::new(
                CocoonFsPendingTransactionsSyncState::new(),
            ),
            transaction_commit_gen: atomic::AtomicU64::new(0),
            any_transaction_pending: atomic::AtomicUsize::new(0),
            committing_transaction: ST::Lock::from(CommittingTransactionState::None),
        }
    }

    /// Get a [`CocoonFsSyncStateMemberSyncRcPtrRefType`] for
    /// [`Self::sync_state`].
    fn get_sync_state_ref<'a>(
        this: &CocoonFsSyncRcPtrRefType<'a, ST, C>,
    ) -> CocoonFsSyncStateMemberSyncRcPtrRefType<'a, ST, C> {
        CocoonFsSyncStateMemberSyncRcPtrRefType::new(this)
    }

    /// Get a [`CocoonFsPendingTransactionsSyncStateMemberSyncRcPtrRefType`] for
    /// [`Self::pending_transactions_sync_state`].
    fn get_pending_transactions_sync_state_ref<'a>(
        this: &CocoonFsSyncRcPtrRefType<'a, ST, C>,
    ) -> CocoonFsPendingTransactionsSyncStateMemberSyncRcPtrRefType<'a, ST, C> {
        // This is sound: the outer 'this' is pinned, and so remains the member.
        unsafe { PlainCocoonFsPendingTransactionsSyncStateMemberSyncRcPtrRefType::new_projection_pin(this) }
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> fs::NvFs for CocoonFs<ST, C> {
    type SyncRcPtr = CocoonFsSyncRcPtrType<ST, C>;
    type SyncRcPtrRef<'a> = <Self::SyncRcPtr as sync_types::SyncRcPtr<Self>>::SyncRcPtrRef<'a>;

    type ConsistentReadSequence = CocoonFsConsistentReadSequence;
    type Transaction = CocoonFsTransaction;

    type StartReadSequenceFut = CocoonFsStartReadSequenceFuture<ST, C>;

    fn start_read_sequence(_this: &Self::SyncRcPtrRef<'_>) -> Self::StartReadSequenceFut {
        let start_read_sequence_fut = StartReadSequenceFuture::new();
        CocoonFsStartReadSequenceFuture {
            start_read_sequence_fut,
        }
    }

    type StartTransactionFut = CocoonFsStartTransactionFuture<ST, C>;

    fn start_transaction(
        _this: &Self::SyncRcPtrRef<'_>,
        continued_read_sequence: Option<&Self::ConsistentReadSequence>,
    ) -> Self::StartTransactionFut {
        CocoonFsStartTransactionFuture::new(continued_read_sequence)
    }

    type CommitTransactionFut = CocoonFsCommitTransactionFuture<ST, C>;

    fn commit_transaction(
        _this: &Self::SyncRcPtrRef<'_>,
        transaction: Self::Transaction,
        pre_commit_validate_cb: Option<fs::PreCommitValidateCallbackType>,
        post_commit_cb: Option<fs::PostCommitCallbackType>,
        issue_sync: bool,
    ) -> Self::CommitTransactionFut {
        CocoonFsCommitTransactionFuture::new(transaction, pre_commit_validate_cb, post_commit_cb, issue_sync)
    }

    type TryCleanupIndeterminateCommitLogFut = CocoonFsTryCleanupIntermediateCommitLogFuture<ST, C>;

    fn try_cleanup_indeterminate_commit_log(
        _this: &Self::SyncRcPtrRef<'_>,
    ) -> Self::TryCleanupIndeterminateCommitLogFut {
        CocoonFsTryCleanupIntermediateCommitLogFuture::new()
    }

    type ReadInodeFut = CocoonFsReadInodeFuture<ST, C>;

    fn read_inode(
        _this: &Self::SyncRcPtrRef<'_>,
        context: Option<fs::NvFsReadContext<Self>>,
        inode: u32,
    ) -> Self::ReadInodeFut {
        CocoonFsReadInodeFuture::new(context, inode)
    }

    type WriteInodeFut = CocoonFsWriteInodeFuture<ST, C>;

    fn write_inode(
        _this: &Self::SyncRcPtrRef<'_>,
        transaction: Self::Transaction,
        inode: u32,
        data: zeroize::Zeroizing<Vec<u8>>,
    ) -> Self::WriteInodeFut {
        CocoonFsWriteInodeFuture::new(transaction, inode, data)
    }

    type EnumerateCursor = CocoonFsEnumerateCursor<ST, C>;

    fn enumerate_cursor(
        _this: &Self::SyncRcPtrRef<'_>,
        context: fs::NvFsReadContext<Self>,
        inodes_enumerate_range: ops::RangeInclusive<u32>,
    ) -> Result<Result<Self::EnumerateCursor, (fs::NvFsReadContext<Self>, NvFsError)>, NvFsError> {
        Ok(CocoonFsEnumerateCursor::new(context, inodes_enumerate_range))
    }

    type UnlinkCursor = CocoonFsUnlinkCursor<ST, C>;

    fn unlink_cursor(
        _this: &Self::SyncRcPtrRef<'_>,
        transaction: Self::Transaction,
        inodes_unlink_range: ops::RangeInclusive<u32>,
    ) -> Result<Result<Self::UnlinkCursor, (Self::Transaction, NvFsError)>, NvFsError> {
        Ok(CocoonFsUnlinkCursor::new(transaction, inodes_unlink_range))
    }
}

/// [`NvFs::ConsistentReadSequence`](fs::NvFs::ConsistentReadSequence)
/// implementation for [`CocoonFs`].
#[derive(Clone, Copy)]
pub struct CocoonFsConsistentReadSequence {
    /// Snapshot of the [`CocoonFs::transaction_commit_gen`] sequence number.
    base_transaction_commit_gen: u64,
}

impl CocoonFsConsistentReadSequence {
    /// Try to continue a previously started [`CocoonFsConsistentReadSequence`].
    ///
    /// If the read sequence, as previously started via
    /// [`StartReadSequenceFuture`] has not been rendered stale
    /// by some intermediate transaction commit, continue on it and return a
    /// [`CocoonFsSyncStateMemberReadGuard`] on the `fs_instance`'s
    /// [`sync_state`](CocoonFs::sync_state) member. Otherwise return an [`Err`]
    /// of [`NvFsError::Retry`].
    fn continue_sequence<ST: sync_types::SyncTypes, C: chip::NvChip>(
        &self,
        fs_instance: &CocoonFsSyncRcPtrRefType<ST, C>,
    ) -> Result<CocoonFsSyncStateMemberReadGuard<ST, C>, NvFsError> {
        // Do not block on read locks: a read lock future could get abandonned, i.e.
        // never polled again, and subsequently block all transaction commits
        // forever. This is also the reason why the read lock guard is not kept
        // across poll invocations.
        let sync_state_read_guard =
            match CocoonFsSyncStateMemberType::try_read(&CocoonFs::get_sync_state_ref(fs_instance)) {
                Some(sync_state_read_guard) => sync_state_read_guard,
                None => {
                    // The try_read() failing means there is currently an exclusive lock
                    // established, which means there is a transaction commit ongoing.
                    // This would invalidate the read_sequence anyway.
                    return Err(NvFsError::Retry);
                }
            };

        let sync_state = CocoonFsSyncStateMemberRef::from(&sync_state_read_guard);
        // The fs instance's ->transaction_commit_gen gets incremented
        // when holding a sync_state write guard, whose release semantics
        // is being relied upon to pair with the above read acquire.
        if (&sync_state.get_fs_ref() as &CocoonFs<ST, C>)
            .transaction_commit_gen
            .load(atomic::Ordering::Relaxed)
            != self.base_transaction_commit_gen
        {
            return Err(NvFsError::Retry);
        }

        Ok(sync_state_read_guard)
    }
}

impl<'a> convert::From<&'a CocoonFsTransaction> for CocoonFsConsistentReadSequence {
    fn from(value: &'a CocoonFsTransaction) -> Self {
        value.read_sequence
    }
}

/// [`NvFs::Transaction`](fs::NvFs::Transaction) implementation for
/// [`CocoonFs`].
pub struct CocoonFsTransaction {
    read_sequence: CocoonFsConsistentReadSequence,
    transaction: Box<transaction::Transaction>,
}

#[cfg(test)]
impl CocoonFsTransaction {
    pub fn test_set_fail_apply_journal(&mut self) {
        self.transaction.test_fail_apply_journal = true;
    }
}

/// [`NvFs::StartReadSequenceFut`](fs::NvFs::StartReadSequenceFut)
/// implementation  for [`CocoonFs`].
pub struct CocoonFsStartReadSequenceFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    start_read_sequence_fut: StartReadSequenceFuture<ST, C>,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> fs::NvFsFuture<CocoonFs<ST, C>>
    for CocoonFsStartReadSequenceFuture<ST, C>
{
    type Output = Result<CocoonFsConsistentReadSequence, NvFsError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        fs_instance: &CocoonFsSyncRcPtrRefType<ST, C>,
        rng: &mut dyn rng::RngCoreDispatchable,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        fs::NvFsFuture::poll(pin::Pin::new(&mut this.start_read_sequence_fut), fs_instance, rng, cx)
    }
}

/// [`NvFs::StartTransactionFut`](fs::NvFs::StartTransactionFut) implementation
/// for [`CocoonFs`].
pub struct CocoonFsStartTransactionFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    fut_state: CocoonFsStartTransactionFutureState<ST, C>,
}

/// Internal [`CocoonFsStartTransactionFuture`] state-machine state.
enum CocoonFsStartTransactionFutureState<ST: sync_types::SyncTypes, C: chip::NvChip> {
    ContinueReadSequence {
        read_sequence: CocoonFsConsistentReadSequence,
    },
    StartReadSequence {
        start_read_sequence_fut: StartReadSequenceFuture<ST, C>,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsStartTransactionFuture<ST, C> {
    fn new(mut continued_read_sequence: Option<&CocoonFsConsistentReadSequence>) -> Self {
        if let Some(read_sequence) = continued_read_sequence.take().copied() {
            return Self {
                fut_state: CocoonFsStartTransactionFutureState::ContinueReadSequence { read_sequence },
            };
        }

        Self {
            fut_state: CocoonFsStartTransactionFutureState::StartReadSequence {
                start_read_sequence_fut: StartReadSequenceFuture::new(),
            },
        }
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> fs::NvFsFuture<CocoonFs<ST, C>>
    for CocoonFsStartTransactionFuture<ST, C>
{
    type Output = Result<CocoonFsTransaction, NvFsError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        fs_instance: &CocoonFsSyncRcPtrRefType<ST, C>,
        rng: &mut dyn rng::RngCoreDispatchable,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        let read_sequence = match &mut this.fut_state {
            CocoonFsStartTransactionFutureState::ContinueReadSequence { read_sequence } => {
                let read_sequence = *read_sequence;
                this.fut_state = CocoonFsStartTransactionFutureState::Done;
                read_sequence
            }
            CocoonFsStartTransactionFutureState::StartReadSequence {
                start_read_sequence_fut,
            } => match fs::NvFsFuture::poll(pin::Pin::new(start_read_sequence_fut), fs_instance, rng, cx) {
                task::Poll::Ready(Ok(read_sequence)) => {
                    this.fut_state = CocoonFsStartTransactionFutureState::Done;
                    read_sequence
                }
                task::Poll::Ready(Err(e)) => {
                    this.fut_state = CocoonFsStartTransactionFutureState::Done;
                    return task::Poll::Ready(Err(e));
                }
                task::Poll::Pending => return task::Poll::Pending,
            },
            CocoonFsStartTransactionFutureState::Done => unreachable!(),
        };

        let sync_state_read_guard = match read_sequence.continue_sequence(fs_instance) {
            Ok(sync_state_read_guard) => sync_state_read_guard,
            Err(e) => {
                this.fut_state = CocoonFsStartTransactionFutureState::Done;
                return task::Poll::Ready(Err(e));
            }
        };
        let mut sync_state = CocoonFsSyncStateMemberRef::from(&sync_state_read_guard);

        // The first in a series of concurrently started transactions is blessed and has
        // a bit more freedom regarding in-place journal writes.
        let is_primary_pending = fs_instance.any_transaction_pending.swap(1, atomic::Ordering::Relaxed) == 0;

        let transaction = match transaction::Transaction::new::<ST, _>(&mut sync_state, is_primary_pending, rng) {
            Ok(transaction) => transaction,
            Err(e) => return task::Poll::Ready(Err(e)),
        };
        let transaction = match box_try_new(transaction) {
            Ok(transaction) => transaction,
            Err(e) => {
                return task::Poll::Ready(Err(NvFsError::from(e)));
            }
        };
        task::Poll::Ready(Ok(CocoonFsTransaction {
            read_sequence,
            transaction,
        }))
    }
}

/// [`NvFs::CommitTransactionFut`](fs::NvFs::CommitTransactionFut)
/// implementation for [`CocoonFs`].
pub struct CocoonFsCommitTransactionFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    fut_state: CocoonFsCommitTransactionFutureState<ST, C>,
}

/// Internal [`CocoonFsCommitTransactionFuture`] state-machine state.
enum CocoonFsCommitTransactionFutureState<ST: sync_types::SyncTypes, C: chip::NvChip> {
    Init {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<CocoonFsTransaction>,
        pre_commit_validate_cb: Option<fs::PreCommitValidateCallbackType>,
        post_commit_cb: Option<fs::PostCommitCallbackType>,
        issue_sync: bool,
    },
    ProgressCommitting {
        progress_committing_transaction_subscription_fut:
            ProgressCommittingTransactionBroadcastFutureSubscriptionType<ST, C>,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsCommitTransactionFuture<ST, C> {
    fn new(
        transaction: CocoonFsTransaction,
        pre_commit_validate_cb: Option<fs::PreCommitValidateCallbackType>,
        post_commit_cb: Option<fs::PostCommitCallbackType>,
        issue_sync: bool,
    ) -> Self {
        Self {
            fut_state: CocoonFsCommitTransactionFutureState::Init {
                transaction: Some(transaction),
                pre_commit_validate_cb,
                post_commit_cb,
                issue_sync,
            },
        }
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> fs::NvFsFuture<CocoonFs<ST, C>>
    for CocoonFsCommitTransactionFuture<ST, C>
{
    type Output = Result<(), fs::TransactionCommitError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        fs_instance: &CocoonFsSyncRcPtrRefType<ST, C>,
        mut rng: &mut dyn rng::RngCoreDispatchable,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                CocoonFsCommitTransactionFutureState::Init {
                    transaction,
                    pre_commit_validate_cb,
                    post_commit_cb,
                    issue_sync,
                } => {
                    let transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => {
                            this.fut_state = CocoonFsCommitTransactionFutureState::Done;
                            return task::Poll::Ready(Err(fs::TransactionCommitError::LogStateClean {
                                reason: nvfs_err_internal!(),
                            }));
                        }
                    };

                    let CocoonFsTransaction {
                        read_sequence: transaction_read_sequence,
                        transaction,
                    } = transaction;

                    // Optimistically prepare a broadcast future outside the lock.
                    let sync_state_write_fut = match asynchronous::AsyncRwLock::write(
                        &CocoonFsSyncStateMemberSyncRcPtrRefType::new(fs_instance),
                    )
                    .map_err(|e| match e {
                        asynchronous::AsyncRwLockError::StaleRwLock => NvFsError::Retry,
                        asynchronous::AsyncRwLockError::MemoryAllocationFailure => NvFsError::MemoryAllocationFailure,
                        asynchronous::AsyncRwLockError::Internal => nvfs_err_internal!(),
                    }) {
                        Ok(sync_state_write_fut) => sync_state_write_fut,
                        Err(e) => {
                            this.fut_state = CocoonFsCommitTransactionFutureState::Done;
                            return task::Poll::Ready(Err(fs::TransactionCommitError::LogStateClean { reason: e }));
                        }
                    };
                    let progress_broadcast_fut = match <ST::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>::try_new(
                        ProgressCommittingTransactionBroadcastFutureType::new(
                            ProgressCommittingTransactionFuture::AcquireCocoonFsSyncStateMemberWriteLock {
                                transaction: Some(transaction),
                                pre_commit_validate_cb: pre_commit_validate_cb.take(),
                                post_commit_cb: post_commit_cb.take(),
                                issue_sync: *issue_sync,
                                sync_state_write_fut,
                            },
                        ),
                    )
                    .map_err(|e| match e {
                        sync_types::SyncRcPtrTryNewError::AllocationFailure => NvFsError::MemoryAllocationFailure,
                    }) {
                        Ok(progress_broadcast_fut) => progress_broadcast_fut,
                        Err(e) => {
                            this.fut_state = CocoonFsCommitTransactionFutureState::Done;
                            return task::Poll::Ready(Err(fs::TransactionCommitError::LogStateClean { reason: e }));
                        }
                    };

                    // Sound, never moved out of or otherwise invalidated.
                    let progress_broadcast_fut = unsafe { pin::Pin::new_unchecked(progress_broadcast_fut) };

                    // Subscribe to the broadcast future just created.
                    let progress_committing_transaction_subscription_fut =
                        match ProgressCommittingTransactionBroadcastFutureType::subscribe(<pin::Pin<
                            ProgressCommittingTransactionBroadcastFutureSyncRcPtrType<ST, C>,
                        > as sync_types::SyncRcPtr<
                            ProgressCommittingTransactionBroadcastFutureType<ST, C>,
                        >>::as_ref(
                            &progress_broadcast_fut
                        ))
                        .map_err(|e| match e {
                            asynchronous::BroadcastFutureError::MemoryAllocationFailure => {
                                NvFsError::MemoryAllocationFailure
                            }
                        }) {
                            Ok(progress_committing_transaction_subscription_fut) => {
                                progress_committing_transaction_subscription_fut
                            }
                            Err(e) => {
                                this.fut_state = CocoonFsCommitTransactionFutureState::Done;
                                return task::Poll::Ready(Err(fs::TransactionCommitError::LogStateClean { reason: e }));
                            }
                        };

                    // Now actually take the lock and verify that no other transaction had
                    // invalidated the given one.  Regarding memory ordering and
                    // ->transaction_commit_gen: note that a prior transaction commit
                    // operation would have incremented ->transaction_commit_gen before
                    // removing itself from ->committing_transaction and the release semantics of
                    // subsequently dropping the lock on the latter pair with the acquire
                    // from here.
                    let mut committing_transaction = fs_instance.committing_transaction.lock();
                    if !matches!(committing_transaction.deref(), CommittingTransactionState::None)
                        || (fs_instance.transaction_commit_gen.load(atomic::Ordering::Relaxed)
                            != transaction_read_sequence.base_transaction_commit_gen)
                    {
                        this.fut_state = CocoonFsCommitTransactionFutureState::Done;
                        return task::Poll::Ready(Err(fs::TransactionCommitError::LogStateClean {
                            reason: NvFsError::Retry,
                        }));
                    }

                    *committing_transaction = CommittingTransactionState::Progressing { progress_broadcast_fut };
                    this.fut_state = CocoonFsCommitTransactionFutureState::ProgressCommitting {
                        progress_committing_transaction_subscription_fut,
                    };
                }
                CocoonFsCommitTransactionFutureState::ProgressCommitting {
                    progress_committing_transaction_subscription_fut,
                } => {
                    match ProgressCommittingTransactionBroadcastFutureSubscriptionType::poll(
                        pin::Pin::new(progress_committing_transaction_subscription_fut),
                        &mut rng,
                        cx,
                    ) {
                        task::Poll::Ready(r) => {
                            let r = match r {
                                ProgressCommittingTransactionFutureResult::Ok => Ok(()),
                                ProgressCommittingTransactionFutureResult::CommitOkApplyJournalErr {
                                    apply_journal_error: _,
                                } => {
                                    // Even though the journal application failed, the changes have been written
                                    // to storage and will be effective even in case of power cuts.
                                    Ok(())
                                }
                                ProgressCommittingTransactionFutureResult::CommitErrAbortJournalOk { commit_error } => {
                                    Err(fs::TransactionCommitError::LogStateClean { reason: commit_error })
                                }
                                ProgressCommittingTransactionFutureResult::CommitErrAbortJournalErr {
                                    commit_error,
                                    abort_journal_error: _,
                                } => Err(fs::TransactionCommitError::LogStateIndeterminate { reason: commit_error }),
                                ProgressCommittingTransactionFutureResult::RetryJournalAbortOk => {
                                    // As this is a retry, it cannot happen from the original commit future,
                                    // because that would have been failed before the retry. Still handle it
                                    // properly though.
                                    Err(fs::TransactionCommitError::LogStateClean {
                                        reason: nvfs_err_internal!(),
                                    })
                                }
                                ProgressCommittingTransactionFutureResult::RetryJournalAbortErr {
                                    abort_journal_error: _,
                                } => {
                                    // Likewise here, it's not possible to encounter a result from a retry at
                                    // this point.
                                    Err(fs::TransactionCommitError::LogStateIndeterminate {
                                        reason: nvfs_err_internal!(),
                                    })
                                }
                            };
                            this.fut_state = CocoonFsCommitTransactionFutureState::Done;
                            return task::Poll::Ready(r);
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    }
                }
                CocoonFsCommitTransactionFutureState::Done => unreachable!(),
            }
        }
    }
}

/// [`NvFs::TryCleanupIndeterminateCommitLogFut`](fs::NvFs::TryCleanupIndeterminateCommitLogFut)
/// implementation for [`CocoonFs`].
pub struct CocoonFsTryCleanupIntermediateCommitLogFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    start_read_sequence_fut: StartReadSequenceFuture<ST, C>,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsTryCleanupIntermediateCommitLogFuture<ST, C> {
    fn new() -> Self {
        Self {
            start_read_sequence_fut: StartReadSequenceFuture::new(),
        }
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> fs::NvFsFuture<CocoonFs<ST, C>>
    for CocoonFsTryCleanupIntermediateCommitLogFuture<ST, C>
{
    type Output = Result<(), NvFsError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        fs_instance: &CocoonFsSyncRcPtrRefType<ST, C>,
        rng: &mut dyn rng::RngCoreDispatchable,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        match fs::NvFsFuture::poll(pin::Pin::new(&mut this.start_read_sequence_fut), fs_instance, rng, cx) {
            task::Poll::Ready(Ok(_)) => task::Poll::Ready(Ok(())),
            task::Poll::Ready(Err(e)) => task::Poll::Ready(Err(e)),
            task::Poll::Pending => task::Poll::Pending,
        }
    }
}

/// [`NvFs::ReadInodeFut`](fs::NvFs::ReadInodeFut) implementation for
/// [`CocoonFs`].
pub struct CocoonFsReadInodeFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    fut_state: CocoonFsReadInodeFutureState<ST, C>,
}

/// Internal [`CocoonFsReadInodeFuture`] state-machine state.
#[allow(clippy::large_enum_variant)]
enum CocoonFsReadInodeFutureState<ST: sync_types::SyncTypes, C: chip::NvChip> {
    StartReadSequence {
        start_read_sequence_fut: StartReadSequenceFuture<ST, C>,
        inode: u32,
    },
    ReadInodeDataPrepare {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        context: Option<fs::NvFsReadContext<CocoonFs<ST, C>>>,
        inode: u32,
    },
    ReadInodeData {
        read_sequence: CocoonFsConsistentReadSequence,
        with_transaction: bool,
        read_inode_data_fut: ReadInodeDataFuture<ST, C>,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsReadInodeFuture<ST, C> {
    fn new(context: Option<fs::NvFsReadContext<CocoonFs<ST, C>>>, inode: u32) -> Self {
        Self {
            fut_state: match context {
                Some(context) => CocoonFsReadInodeFutureState::ReadInodeDataPrepare {
                    context: Some(context),
                    inode,
                },
                None => CocoonFsReadInodeFutureState::StartReadSequence {
                    start_read_sequence_fut: StartReadSequenceFuture::Init,
                    inode,
                },
            },
        }
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> fs::NvFsFuture<CocoonFs<ST, C>> for CocoonFsReadInodeFuture<ST, C> {
    type Output = Result<
        (
            fs::NvFsReadContext<CocoonFs<ST, C>>,
            Result<Option<zeroize::Zeroizing<Vec<u8>>>, NvFsError>,
        ),
        NvFsError,
    >;

    fn poll(
        self: pin::Pin<&mut Self>,
        fs_instance: &CocoonFsSyncRcPtrRefType<ST, C>,
        rng: &mut dyn rng::RngCoreDispatchable,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                CocoonFsReadInodeFutureState::StartReadSequence {
                    start_read_sequence_fut,
                    inode,
                } => match fs::NvFsFuture::poll(pin::Pin::new(start_read_sequence_fut), fs_instance, rng, cx) {
                    task::Poll::Ready(Ok(read_sequence)) => {
                        this.fut_state = CocoonFsReadInodeFutureState::ReadInodeDataPrepare {
                            context: Some(fs::NvFsReadContext::Committed { seq: read_sequence }),
                            inode: *inode,
                        };
                    }
                    task::Poll::Ready(Err(e)) => {
                        this.fut_state = CocoonFsReadInodeFutureState::Done;
                        return task::Poll::Ready(Err(e));
                    }
                    task::Poll::Pending => return task::Poll::Pending,
                },
                CocoonFsReadInodeFutureState::ReadInodeDataPrepare { context, inode } => {
                    let context = match context.take() {
                        Some(context) => context,
                        None => {
                            this.fut_state = CocoonFsReadInodeFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    if *inode <= inode_index::SPECIAL_INODE_MAX {
                        this.fut_state = CocoonFsReadInodeFutureState::Done;
                        return task::Poll::Ready(Ok((context, Err(NvFsError::InodeReserved))));
                    }

                    let (read_sequence, transaction) = match context {
                        fs::NvFsReadContext::Committed { seq } => (seq, None),
                        fs::NvFsReadContext::Transaction { transaction } => {
                            (transaction.read_sequence, Some(transaction.transaction))
                        }
                    };

                    let with_transaction = transaction.is_some();
                    let read_inode_data_fut = ReadInodeDataFuture::new(transaction, *inode);
                    this.fut_state = CocoonFsReadInodeFutureState::ReadInodeData {
                        read_sequence,
                        with_transaction,
                        read_inode_data_fut,
                    };
                }
                CocoonFsReadInodeFutureState::ReadInodeData {
                    read_sequence,
                    with_transaction,
                    read_inode_data_fut,
                } => {
                    let sync_state_read_guard = match read_sequence.continue_sequence::<ST, C>(fs_instance) {
                        Ok(sync_state) => sync_state,
                        Err(e) => {
                            this.fut_state = CocoonFsReadInodeFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    let mut sync_state = CocoonFsSyncStateMemberRef::from(&sync_state_read_guard);

                    let (transaction, result) = match CocoonFsSyncStateReadFuture::poll(
                        pin::Pin::new(read_inode_data_fut),
                        &mut sync_state,
                        &mut (),
                        cx,
                    ) {
                        task::Poll::Ready((transaction, result)) => (transaction, result),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let context = match transaction {
                        Some(transaction) => fs::NvFsReadContext::Transaction {
                            transaction: CocoonFsTransaction {
                                read_sequence: *read_sequence,
                                transaction,
                            },
                        },
                        None => {
                            // We started out with some transaction, but it got lost somewhere on
                            // the way.
                            if *with_transaction {
                                this.fut_state = CocoonFsReadInodeFutureState::Done;
                                return task::Poll::Ready(Err(nvfs_err_internal!()));
                            }

                            fs::NvFsReadContext::Committed { seq: *read_sequence }
                        }
                    };

                    this.fut_state = CocoonFsReadInodeFutureState::Done;
                    return task::Poll::Ready(Ok((context, result)));
                }
                CocoonFsReadInodeFutureState::Done => unreachable!(),
            };
        }
    }
}

/// [`NvFs::WriteInodeFut`](fs::NvFs::WriteInodeFut) implementation for
/// [`CocoonFs`].
pub struct CocoonFsWriteInodeFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    fut_state: CocoonFsWriteInodeFutureState<ST, C>,
}

/// Internal [`CocoonFsWriteInodeFuture`] state-machine state.
#[allow(clippy::large_enum_variant)]
enum CocoonFsWriteInodeFutureState<ST: sync_types::SyncTypes, C: chip::NvChip> {
    Init {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<CocoonFsTransaction>,
        inode: u32,
        data: zeroize::Zeroizing<Vec<u8>>,
    },
    WriteInodeData {
        read_sequence: CocoonFsConsistentReadSequence,
        write_inode_data_fut: WriteInodeDataFuture<ST, C>,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsWriteInodeFuture<ST, C> {
    fn new(transaction: CocoonFsTransaction, inode: u32, data: zeroize::Zeroizing<Vec<u8>>) -> Self {
        Self {
            fut_state: CocoonFsWriteInodeFutureState::Init {
                transaction: Some(transaction),
                inode,
                data,
            },
        }
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> fs::NvFsFuture<CocoonFs<ST, C>> for CocoonFsWriteInodeFuture<ST, C> {
    type Output = Result<(CocoonFsTransaction, zeroize::Zeroizing<Vec<u8>>, Result<(), NvFsError>), NvFsError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        fs_instance: &CocoonFsSyncRcPtrRefType<ST, C>,
        mut rng: &mut dyn rng::RngCoreDispatchable,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                CocoonFsWriteInodeFutureState::Init {
                    transaction,
                    inode,
                    data,
                } => {
                    let transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => {
                            this.fut_state = CocoonFsWriteInodeFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    if *inode <= inode_index::SPECIAL_INODE_MAX {
                        let data = mem::take(data);
                        this.fut_state = CocoonFsWriteInodeFutureState::Done;
                        return task::Poll::Ready(Ok((transaction, data, Err(NvFsError::InodeReserved))));
                    }

                    let CocoonFsTransaction {
                        read_sequence,
                        transaction,
                    } = transaction;
                    let write_inode_data_fut = WriteInodeDataFuture::new(transaction, *inode, mem::take(data));
                    this.fut_state = CocoonFsWriteInodeFutureState::WriteInodeData {
                        read_sequence,
                        write_inode_data_fut,
                    };
                }
                CocoonFsWriteInodeFutureState::WriteInodeData {
                    read_sequence,
                    write_inode_data_fut,
                } => {
                    let sync_state_read_guard = match read_sequence.continue_sequence::<ST, C>(fs_instance) {
                        Ok(sync_state) => sync_state,
                        Err(e) => {
                            this.fut_state = CocoonFsWriteInodeFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    let mut sync_state = CocoonFsSyncStateMemberRef::from(&sync_state_read_guard);

                    let (transaction, data, result) = match CocoonFsSyncStateReadFuture::poll(
                        pin::Pin::new(write_inode_data_fut),
                        &mut sync_state,
                        &mut rng,
                        cx,
                    ) {
                        task::Poll::Ready(Ok((transaction, data, result))) => (transaction, data, result),
                        task::Poll::Ready(Err(e)) => {
                            this.fut_state = CocoonFsWriteInodeFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let transaction = CocoonFsTransaction {
                        read_sequence: *read_sequence,
                        transaction,
                    };
                    this.fut_state = CocoonFsWriteInodeFutureState::Done;
                    return task::Poll::Ready(Ok((transaction, data, result)));
                }
                CocoonFsWriteInodeFutureState::Done => unreachable!(),
            }
        }
    }
}

/// [`NvFs::EnumerateCursor`](fs::NvFs::EnumerateCursor) implementation for
/// [`CocoonFs`].
pub struct CocoonFsEnumerateCursor<ST: sync_types::SyncTypes, C: chip::NvChip> {
    cursor: Box<inode_index::InodeIndexEnumerateCursor<ST, C>>,
    read_sequence: CocoonFsConsistentReadSequence,
    with_transaction: bool,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsEnumerateCursor<ST, C> {
    fn new(
        context: fs::NvFsReadContext<CocoonFs<ST, C>>,
        inodes_enumerate_range: ops::RangeInclusive<u32>,
    ) -> Result<Self, (fs::NvFsReadContext<CocoonFs<ST, C>>, NvFsError)> {
        let (read_sequence, transaction) = match context {
            fs::NvFsReadContext::Committed { seq } => (seq, None),
            fs::NvFsReadContext::Transaction { transaction } => {
                let CocoonFsTransaction {
                    read_sequence,
                    transaction,
                } = transaction;
                (read_sequence, Some(transaction))
            }
        };

        let with_transaction = transaction.is_some();
        inode_index::InodeIndexEnumerateCursor::new(transaction, inodes_enumerate_range)
            .map(|cursor| Self {
                cursor,
                read_sequence,
                with_transaction,
            })
            .map_err(|(transaction, e)| {
                let context = match transaction {
                    Some(transaction) => fs::NvFsReadContext::Transaction {
                        transaction: CocoonFsTransaction {
                            read_sequence,
                            transaction,
                        },
                    },
                    None => {
                        debug_assert!(!with_transaction);
                        fs::NvFsReadContext::Committed { seq: read_sequence }
                    }
                };
                (context, e)
            })
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> fs::NvFsEnumerateCursor<CocoonFs<ST, C>>
    for CocoonFsEnumerateCursor<ST, C>
{
    fn into_context(self) -> Result<fs::NvFsReadContext<CocoonFs<ST, C>>, NvFsError> {
        let Self {
            cursor,
            read_sequence,
            with_transaction,
        } = self;

        match cursor.into_transaction() {
            Some(transaction) => Ok(fs::NvFsReadContext::Transaction {
                transaction: CocoonFsTransaction {
                    read_sequence,
                    transaction,
                },
            }),
            None => {
                if !with_transaction {
                    Ok(fs::NvFsReadContext::Committed { seq: read_sequence })
                } else {
                    // We started out with some transaction, but it got lost on the way somehow.
                    Err(nvfs_err_internal!())
                }
            }
        }
    }

    type NextFut = CocoonFsEnumerateCursorNextFuture<ST, C>;

    fn next(self) -> Self::NextFut {
        let Self {
            cursor,
            read_sequence,
            with_transaction,
        } = self;
        CocoonFsEnumerateCursorNextFuture {
            next_fut: cursor.next(),
            read_sequence,
            with_transaction,
        }
    }

    type ReadInodeDataFut = CocoonFsEnumerateCursorReadInodeDataFuture<ST, C>;

    fn read_current_inode_data(self) -> Self::ReadInodeDataFut {
        let Self {
            cursor,
            read_sequence,
            with_transaction,
        } = self;

        CocoonFsEnumerateCursorReadInodeDataFuture {
            read_inode_data_fut: cursor.read_inode_data(),
            read_sequence,
            with_transaction,
        }
    }
}
/// [`NvFsEnumerateCursor::NextFut`](fs::NvFsEnumerateCursor::NextFut)
/// implementation for [`CocoonFsEnumerateCursor`].
pub struct CocoonFsEnumerateCursorNextFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    next_fut: inode_index::InodeIndexEnumerateCursorNextFuture<ST, C>,
    read_sequence: CocoonFsConsistentReadSequence,
    with_transaction: bool,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> fs::NvFsFuture<CocoonFs<ST, C>>
    for CocoonFsEnumerateCursorNextFuture<ST, C>
{
    type Output = Result<(CocoonFsEnumerateCursor<ST, C>, Result<Option<u32>, NvFsError>), NvFsError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        fs_instance: &<CocoonFs<ST, C> as fs::NvFs>::SyncRcPtrRef<'_>,
        _rng: &mut dyn rng::RngCoreDispatchable,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        let sync_state_read_guard = match this.read_sequence.continue_sequence::<ST, C>(fs_instance) {
            Ok(sync_state) => sync_state,
            Err(e) => {
                return task::Poll::Ready(Err(e));
            }
        };
        let mut sync_state = CocoonFsSyncStateMemberRef::from(&sync_state_read_guard);

        match CocoonFsSyncStateReadFuture::poll(pin::Pin::new(&mut this.next_fut), &mut sync_state, &mut (), cx) {
            task::Poll::Ready(Ok((cursor, result))) => task::Poll::Ready(Ok((
                CocoonFsEnumerateCursor {
                    cursor,
                    read_sequence: this.read_sequence,
                    with_transaction: this.with_transaction,
                },
                result,
            ))),
            task::Poll::Ready(Err(e)) => task::Poll::Ready(Err(e)),
            task::Poll::Pending => task::Poll::Pending,
        }
    }
}

/// [`NvFsEnumerateCursor::ReadInodeDataFut`](fs::NvFsEnumerateCursor::ReadInodeDataFut)
/// implementation for [`CocoonFsEnumerateCursor`].
pub struct CocoonFsEnumerateCursorReadInodeDataFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    read_inode_data_fut: inode_index::InodeIndexEnumerateCursorReadInodeDataFuture<ST, C>,
    read_sequence: CocoonFsConsistentReadSequence,
    with_transaction: bool,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> fs::NvFsFuture<CocoonFs<ST, C>>
    for CocoonFsEnumerateCursorReadInodeDataFuture<ST, C>
{
    type Output = Result<
        (
            CocoonFsEnumerateCursor<ST, C>,
            Result<zeroize::Zeroizing<Vec<u8>>, NvFsError>,
        ),
        NvFsError,
    >;

    fn poll(
        self: pin::Pin<&mut Self>,
        fs_instance: &<CocoonFs<ST, C> as fs::NvFs>::SyncRcPtrRef<'_>,
        _rng: &mut dyn rng::RngCoreDispatchable,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        let sync_state_read_guard = match this.read_sequence.continue_sequence::<ST, C>(fs_instance) {
            Ok(sync_state) => sync_state,
            Err(e) => {
                return task::Poll::Ready(Err(e));
            }
        };
        let mut sync_state = CocoonFsSyncStateMemberRef::from(&sync_state_read_guard);

        match CocoonFsSyncStateReadFuture::poll(
            pin::Pin::new(&mut this.read_inode_data_fut),
            &mut sync_state,
            &mut (),
            cx,
        ) {
            task::Poll::Ready(Ok((cursor, result))) => task::Poll::Ready(Ok((
                CocoonFsEnumerateCursor {
                    cursor,
                    read_sequence: this.read_sequence,
                    with_transaction: this.with_transaction,
                },
                result,
            ))),
            task::Poll::Ready(Err(e)) => task::Poll::Ready(Err(e)),
            task::Poll::Pending => task::Poll::Pending,
        }
    }
}

/// [`NvFs::UnlinkCursor`](fs::NvFs::UnlinkCursor) implementation for
/// [`CocoonFs`].
pub struct CocoonFsUnlinkCursor<ST: sync_types::SyncTypes, C: chip::NvChip> {
    cursor: Box<inode_index::InodeIndexUnlinkCursor<ST, C>>,
    read_sequence: CocoonFsConsistentReadSequence,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsUnlinkCursor<ST, C> {
    fn new(
        transaction: CocoonFsTransaction,
        inodes_unlink_range: ops::RangeInclusive<u32>,
    ) -> Result<Self, (CocoonFsTransaction, NvFsError)> {
        let CocoonFsTransaction {
            read_sequence,
            transaction,
        } = transaction;
        inode_index::InodeIndexUnlinkCursor::new(transaction, inodes_unlink_range)
            .map(|cursor| Self { cursor, read_sequence })
            .map_err(|(transaction, e)| {
                (
                    CocoonFsTransaction {
                        read_sequence,
                        transaction,
                    },
                    e,
                )
            })
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> fs::NvFsUnlinkCursor<CocoonFs<ST, C>> for CocoonFsUnlinkCursor<ST, C> {
    fn into_transaction(self) -> Result<CocoonFsTransaction, NvFsError> {
        let Self { cursor, read_sequence } = self;
        let transaction = cursor.into_transaction()?;
        Ok(CocoonFsTransaction {
            read_sequence,
            transaction,
        })
    }

    type NextFut = CocoonFsUnlinkCursorNextFuture<ST, C>;

    fn next(self) -> Self::NextFut {
        let Self { cursor, read_sequence } = self;
        CocoonFsUnlinkCursorNextFuture {
            next_fut: cursor.next(),
            read_sequence,
        }
    }

    type UnlinkInodeFut = CocoonFsUnlinkCursorUnlinkInodeFuture<ST, C>;

    fn unlink_current_inode(self) -> Self::UnlinkInodeFut {
        let Self { cursor, read_sequence } = self;
        CocoonFsUnlinkCursorUnlinkInodeFuture {
            unlink_inode_fut: cursor.unlink_inode(),
            read_sequence,
        }
    }

    type ReadInodeDataFut = CocoonFsUnlinkCursorReadInodeDataFuture<ST, C>;

    fn read_current_inode_data(self) -> Self::ReadInodeDataFut {
        let Self { cursor, read_sequence } = self;
        CocoonFsUnlinkCursorReadInodeDataFuture {
            read_inode_data_fut: cursor.read_inode_data(),
            read_sequence,
        }
    }
}

/// [`NvFsUnlinkCursor::NextFut`](fs::NvFsUnlinkCursor::NextFut) implementation
/// for [`CocoonFsUnlinkCursor`].
pub struct CocoonFsUnlinkCursorNextFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    next_fut: inode_index::InodeIndexUnlinkCursorNextFuture<ST, C>,
    read_sequence: CocoonFsConsistentReadSequence,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> fs::NvFsFuture<CocoonFs<ST, C>>
    for CocoonFsUnlinkCursorNextFuture<ST, C>
{
    type Output = Result<(CocoonFsUnlinkCursor<ST, C>, Result<Option<u32>, NvFsError>), NvFsError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        fs_instance: &<CocoonFs<ST, C> as fs::NvFs>::SyncRcPtrRef<'_>,
        _rng: &mut dyn rng::RngCoreDispatchable,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        let sync_state_read_guard = match this.read_sequence.continue_sequence::<ST, C>(fs_instance) {
            Ok(sync_state) => sync_state,
            Err(e) => {
                return task::Poll::Ready(Err(e));
            }
        };
        let mut sync_state = CocoonFsSyncStateMemberRef::from(&sync_state_read_guard);

        match CocoonFsSyncStateReadFuture::poll(pin::Pin::new(&mut this.next_fut), &mut sync_state, &mut (), cx) {
            task::Poll::Ready(Ok((cursor, result))) => task::Poll::Ready(Ok((
                CocoonFsUnlinkCursor {
                    cursor,
                    read_sequence: this.read_sequence,
                },
                result,
            ))),
            task::Poll::Ready(Err(e)) => task::Poll::Ready(Err(e)),
            task::Poll::Pending => task::Poll::Pending,
        }
    }
}

/// [`NvFsUnlinkCursor::UnlinkInodeFut`](fs::NvFsUnlinkCursor::UnlinkInodeFut)
/// implementation for [`CocoonFsUnlinkCursor`].
pub struct CocoonFsUnlinkCursorUnlinkInodeFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    unlink_inode_fut: inode_index::InodeIndexUnlinkCursorUnlinkInodeFuture<ST, C>,
    read_sequence: CocoonFsConsistentReadSequence,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> fs::NvFsFuture<CocoonFs<ST, C>>
    for CocoonFsUnlinkCursorUnlinkInodeFuture<ST, C>
{
    type Output = Result<(CocoonFsUnlinkCursor<ST, C>, Result<(), NvFsError>), NvFsError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        fs_instance: &<CocoonFs<ST, C> as fs::NvFs>::SyncRcPtrRef<'_>,
        mut rng: &mut dyn rng::RngCoreDispatchable,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        let sync_state_read_guard = match this.read_sequence.continue_sequence::<ST, C>(fs_instance) {
            Ok(sync_state) => sync_state,
            Err(e) => {
                return task::Poll::Ready(Err(e));
            }
        };
        let mut sync_state = CocoonFsSyncStateMemberRef::from(&sync_state_read_guard);

        match CocoonFsSyncStateReadFuture::poll(
            pin::Pin::new(&mut this.unlink_inode_fut),
            &mut sync_state,
            &mut rng,
            cx,
        ) {
            task::Poll::Ready(Ok((cursor, result))) => task::Poll::Ready(Ok((
                CocoonFsUnlinkCursor {
                    cursor,
                    read_sequence: this.read_sequence,
                },
                result,
            ))),
            task::Poll::Ready(Err(e)) => task::Poll::Ready(Err(e)),
            task::Poll::Pending => task::Poll::Pending,
        }
    }
}

/// [`NvFsUnlinkCursor::ReadInodeDataFut`](fs::NvFsUnlinkCursor::ReadInodeDataFut) implementation
/// for [`CocoonFsUnlinkCursor`].
pub struct CocoonFsUnlinkCursorReadInodeDataFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    read_inode_data_fut: inode_index::InodeIndexUnlinkCursorReadInodeDataFuture<ST, C>,
    read_sequence: CocoonFsConsistentReadSequence,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> fs::NvFsFuture<CocoonFs<ST, C>>
    for CocoonFsUnlinkCursorReadInodeDataFuture<ST, C>
{
    type Output = Result<
        (
            CocoonFsUnlinkCursor<ST, C>,
            Result<zeroize::Zeroizing<Vec<u8>>, NvFsError>,
        ),
        NvFsError,
    >;

    fn poll(
        self: pin::Pin<&mut Self>,
        fs_instance: &<CocoonFs<ST, C> as fs::NvFs>::SyncRcPtrRef<'_>,
        _rng: &mut dyn rng::RngCoreDispatchable,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        let sync_state_read_guard = match this.read_sequence.continue_sequence::<ST, C>(fs_instance) {
            Ok(sync_state) => sync_state,
            Err(e) => {
                return task::Poll::Ready(Err(e));
            }
        };
        let mut sync_state = CocoonFsSyncStateMemberRef::from(&sync_state_read_guard);

        match CocoonFsSyncStateReadFuture::poll(
            pin::Pin::new(&mut this.read_inode_data_fut),
            &mut sync_state,
            &mut (),
            cx,
        ) {
            task::Poll::Ready(Ok((cursor, result))) => task::Poll::Ready(Ok((
                CocoonFsUnlinkCursor {
                    cursor,
                    read_sequence: this.read_sequence,
                },
                result,
            ))),
            task::Poll::Ready(Err(e)) => task::Poll::Ready(Err(e)),
            task::Poll::Pending => task::Poll::Pending,
        }
    }
}

/// [`CocoonFs::committing_transaction`] state.
enum CommittingTransactionState<ST: sync_types::SyncTypes, C: chip::NvChip> {
    /// No transaction commit in progress.
    None,
    /// A transaction commit is currently in the works.
    ///
    /// New instances of [`StartReadSequenceFuture`] may subscribe to
    /// `progress_broadcast_fut` and help out driving progress by polling on the
    /// subscription.
    Progressing {
        progress_broadcast_fut: pin::Pin<ProgressCommittingTransactionBroadcastFutureSyncRcPtrType<ST, C>>,
    },
    /// A previous attempt to commit the transaction had been completed
    /// successfully up to (and including) the journal write-out, but the
    /// subsequent journal application failed.
    ///
    /// Success has been reported to the initiating
    /// [`CocoonFsCommitTransactionFuture`], and the journal application
    /// needs to get retried until it succeeds eventually.
    RetryApplyJournal {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        sync_state_write_guard: Option<CocoonFsSyncStateMemberWriteWeakGuard<ST, C>>,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<transaction::Transaction>>,
        low_memory: bool,
    },
    /// A previous attempt to commit the transaction had failed and the journal
    /// (log head) is left in an indeterminate state.
    ///
    /// If the filesystem image was to get opened at that point, the journal,
    /// and hence the changes, might get applied or not. The journal log
    /// needs cleared to bring the filesystem back into a definitive state
    /// again.
    RetryAbortJournal {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        sync_state_write_guard: Option<CocoonFsSyncStateMemberWriteWeakGuard<ST, C>>,
        // Is optional, but None only on internal error or memory allocation failures.
        transaction: Option<Box<transaction::Transaction>>,
        low_memory: bool,
    },
    /// Internal logic error causing a permanent failure. No progress is
    /// possible anymore and the [`CocoonFs`] instance is effectively
    /// disfunctional.
    PermanentInternalFailure {
        // Is optional and meant to keep a lock on the sync state for forever for good measure, if
        // possible. Not needed for correctness, as a FS instance in this state will not allow any
        // further operation whatsoever anyway.
        _sync_state_write_guard: Option<CocoonFsSyncStateMemberWriteWeakGuard<ST, C>>,
    },
}

// Unfortunately rustc runs into a recursion limit when trying to prove this.
// The reason seems to be that CommittingTransactionState contains a
// CocoonFsSyncStateMemberWriteWeakGuard, which ultimately contains a
// CocoonFsSyncRcPtrType::WeakSyncRcPtr and CocoonFs (the pointed to type)
// contains the CommittingTransactionState.
// SAFETY: all members are Send.
unsafe impl<ST: sync_types::SyncTypes, C: chip::NvChip> marker::Send for CommittingTransactionState<ST, C> {}

/// Result from a [`ProgressCommittingTransactionFuture`].
#[derive(Clone, Copy)]
enum ProgressCommittingTransactionFutureResult {
    /// The transaction commit was successful.
    Ok,
    /// The journal had been written successfully, but its subsequent
    /// application failed.
    ///
    /// The changes are considered effective, and the initiating
    /// [`CocoonFsCommitTransactionFuture`] will complete with success.
    ///
    /// Subscribed [`StartReadSequenceFuture`]s will also complete for now with
    /// a failure of `apply_journal_error`.
    ///
    /// Subsequently started [`StartReadSequenceFuture`]s will find the
    /// [`CocoonFs::committing_transaction`] in a state of
    /// [`CommittingTransactionState::RetryApplyJournal`] and retry the journal
    /// application.
    CommitOkApplyJournalErr { apply_journal_error: NvFsError },
    /// The transaction commit failed, but the journal is in a determinate
    /// state.
    ///
    /// The initiating
    /// [`CocoonFsCommitTransactionFuture`], will complete with a failure of
    /// `commit_error`.
    ///
    /// Subscribed [`StartReadSequenceFuture`]s will complete with success.
    CommitErrAbortJournalOk { commit_error: NvFsError },
    /// The transaction commit failed and the journal has been left in an
    /// indeterminate state.
    ///
    /// The initiating
    /// [`CocoonFsCommitTransactionFuture`], will complete with a failure of
    /// `commit_error`.
    ///
    /// Subscribed [`StartReadSequenceFuture`]s will also complete for now with
    /// a failure of `abort_journal_error`.
    ///
    /// Subsequently started [`StartReadSequenceFuture`]s will find the
    /// [`CocoonFs::committing_transaction`] in a state of
    /// [`CommittingTransactionState::RetryAbortJournal`] and retry the journal
    /// cleanup.
    CommitErrAbortJournalErr {
        commit_error: NvFsError,
        abort_journal_error: NvFsError,
    },
    /// The transaction commit failed and the journal had originally been left
    /// in an indeterminate state, but been cleaned up in the meanwhile.
    ///
    /// Subscribed [`StartReadSequenceFuture`]s will complete with success.
    RetryJournalAbortOk,
    /// The transaction commit failed and the journal had originally been left
    /// in an indeterminate state, and subsequent attempts to clean it up
    /// failed either.
    ///
    /// Subscribed [`StartReadSequenceFuture`]s will complete for now with
    /// a failure of `abort_journal_error`.
    ///
    /// Subsequently started [`StartReadSequenceFuture`]s will find the
    /// [`CocoonFs::committing_transaction`] in a state of
    /// [`CommittingTransactionState::RetryAbortJournal`] and retry the journal
    /// cleanup.
    RetryJournalAbortErr { abort_journal_error: NvFsError },
}

/// [`BroadcastFuture`](asynchronous::BroadcastFuture) wrapping a
/// [`ProgressCommittingTransactionFuture`].
///
/// Wrapped in a [`ProgressCommittingTransactionBroadcastFutureSyncRcPtrType`]
/// and stored in [`CommittingTransactionState::Progressing`] at
/// [`CocoonFs::committing_transaction`].
type ProgressCommittingTransactionBroadcastFutureType<ST, C> =
    asynchronous::BroadcastFuture<ST, ProgressCommittingTransactionFuture<ST, C>>;

/// [`SyncRcPtr`](sync_types::SyncRcPtr) to the
/// [`ProgressCommittingTransactionBroadcastFutureType`].
///
/// Stored in [`CommittingTransactionState::Progressing`] at
/// [`CocoonFs::committing_transaction`].
type ProgressCommittingTransactionBroadcastFutureSyncRcPtrType<ST, C> =
    <<ST as sync_types::SyncTypes>::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>::SyncRcPtr<
        ProgressCommittingTransactionBroadcastFutureType<ST, C>,
    >;

/// Subscription to a ProgressCommittingTransactionBroadcastFutureType.
type ProgressCommittingTransactionBroadcastFutureSubscriptionType<ST, C> = asynchronous::BroadcastFutureSubscription<
    ST,
    ProgressCommittingTransactionFuture<ST, C>,
    ProgressCommittingTransactionBroadcastFutureSyncRcPtrType<ST, C>,
>;

/// Attempt to drive progress on the currently committing transaction forward.
///
/// Either proceeed with the commit or cancel the journal, as is appropriate.
///
/// When done, update [`CocoonFs::committing_transaction`] depending on the
/// outcome and current state: either clear it or request another try from
/// subsequently issued [`StartReadSequenceFuture`]s.
#[allow(clippy::large_enum_variant)]
enum ProgressCommittingTransactionFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    AcquireCocoonFsSyncStateMemberWriteLock {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<transaction::Transaction>>,
        pre_commit_validate_cb: Option<fs::PreCommitValidateCallbackType>,
        post_commit_cb: Option<fs::PostCommitCallbackType>,
        issue_sync: bool,
        sync_state_write_fut: CocoonFsSyncStateMemberWriteFuture<ST, C>,
    },
    GrabPendingTransactionsSyncStateForCommit {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        sync_state_write_guard: Option<CocoonFsSyncStateMemberWriteWeakGuard<ST, C>>,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<transaction::Transaction>>,
        pre_commit_validate_cb: Option<fs::PreCommitValidateCallbackType>,
        post_commit_cb: Option<fs::PostCommitCallbackType>,
        issue_sync: bool,
        grab_pending_transactions_sync_state_fut: QueuedPendingTransactionsSyncFuture<ST, C>,
    },

    CleanupOnPreCommitError {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        sync_state_write_guard: Option<CocoonFsSyncStateMemberWriteWeakGuard<ST, C>>,
        cleanup_fut: transaction::TransactionCleanupPreCommitCancelledFuture<C>,
        pre_commit_error: NvFsError,
    },

    WriteJournal {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        sync_state_write_guard: Option<CocoonFsSyncStateMemberWriteWeakGuard<ST, C>>,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        post_commit_cb: Option<fs::PostCommitCallbackType>,
        write_journal_fut: transaction::TransactionWriteJournalFuture<ST, C>,
    },

    DoApplyJournal {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        sync_state_write_guard: Option<CocoonFsSyncStateMemberWriteWeakGuard<ST, C>>,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<transaction::Transaction>>,
        low_memory: bool,
    },
    ApplyJournal {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        sync_state_write_guard: Option<CocoonFsSyncStateMemberWriteWeakGuard<ST, C>>,
        apply_journal_fut: transaction::TransactionApplyJournalFuture<C>,
        low_memory: bool,
    },

    DoAbortJournal {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        sync_state_write_guard: Option<CocoonFsSyncStateMemberWriteWeakGuard<ST, C>>,
        // Is optional, but None only on internal error or memory allocation failures.
        transaction: Option<Box<transaction::Transaction>>,
        transaction_commit_error: Option<(NvFsError, Option<fs::PostCommitCallbackType>)>,
        low_memory: bool,
    },
    AbortJournal {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        sync_state_write_guard: Option<CocoonFsSyncStateMemberWriteWeakGuard<ST, C>>,
        transaction_commit_error: Option<(NvFsError, Option<fs::PostCommitCallbackType>)>,
        abort_journal_fut: transaction::TransactionAbortJournalFuture<C>,
        low_memory: bool,
    },

    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> asynchronous::BroadcastedFuture
    for ProgressCommittingTransactionFuture<ST, C>
{
    type Output = ProgressCommittingTransactionFutureResult;
    type AuxPollData<'a> = &'a mut dyn rng::RngCoreDispatchable;

    fn poll<'a>(
        self: pin::Pin<&mut Self>,
        aux_data: &mut Self::AuxPollData<'a>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        let rng: &mut dyn rng::RngCoreDispatchable = *aux_data;
        // All but the first future states keep a
        // CocoonFsSyncStateMemberWriteWeakGuard, the first represents the
        // task to obtain a non-weak one. Try to obtain a non-weak
        // CocoonFsSyncStateMemberWriteGuard in either case here once at the entry,
        // in order to avoid downgrading and upgrading over and over again when
        // transitioning between the future states without returning
        // (task::Poll::Pending) inbetween.
        let mut sync_state_write_guard = match this {
            Self::AcquireCocoonFsSyncStateMemberWriteLock {
                transaction,
                pre_commit_validate_cb,
                post_commit_cb,
                issue_sync,
                sync_state_write_fut,
            } => match future::Future::poll(pin::Pin::new(sync_state_write_fut), cx) {
                task::Poll::Ready(Ok(sync_state_write_guard)) => {
                    let fs_instance = sync_state_write_guard.get_rwlock().get_container().clone();
                    let pending_transactions_sync_state =
                        CocoonFs::get_pending_transactions_sync_state_ref(&fs_instance).make_clone();
                    let grab_pending_transactions_sync_state_fut = match asynchronous::FutureQueue::enqueue(
                        pending_transactions_sync_state,
                        PendingTransactionsSyncFuture::GrabTransactionsSyncStateForCommit,
                    ) {
                        Ok(grab_pending_transactions_sync_state_fut) => grab_pending_transactions_sync_state_fut,
                        Err((_, asynchronous::FutureQueueError::MemoryAllocationFailure)) => {
                            // Drop the sync_state write guard _before_ clearing out
                            // committing_transaction.  Threads seeing committing_transaction ==
                            // None expect to be able to grab the sync_state for read.
                            drop(fs_instance);
                            let fs_instance = sync_state_write_guard.into_rwlock().into_container();
                            *fs_instance.committing_transaction.lock() = CommittingTransactionState::None;
                            *this = Self::Done;
                            let r = ProgressCommittingTransactionFutureResult::CommitErrAbortJournalOk {
                                commit_error: NvFsError::MemoryAllocationFailure,
                            };
                            return task::Poll::Ready(r);
                        }
                    };
                    *this = Self::GrabPendingTransactionsSyncStateForCommit {
                        // Will receive the CocoonFsSyncStateMemberWriteGuard::into_weak() upon
                        // return from this poll() function.
                        sync_state_write_guard: None,
                        transaction: transaction.take(),
                        pre_commit_validate_cb: pre_commit_validate_cb.take(),
                        post_commit_cb: post_commit_cb.take(),
                        issue_sync: *issue_sync,
                        grab_pending_transactions_sync_state_fut,
                    };
                    drop(fs_instance);
                    sync_state_write_guard
                }
                task::Poll::Ready(Err(e)) => {
                    let e = match e {
                        asynchronous::AsyncRwLockError::MemoryAllocationFailure => NvFsError::MemoryAllocationFailure,
                        asynchronous::AsyncRwLockError::StaleRwLock => {
                            // It cannot happen, because we're polling right now on behalf
                            // of someone who does own a reference, but handle it anyway.
                            NvFsError::Retry
                        }
                        asynchronous::AsyncRwLockError::Internal => nvfs_err_internal!(),
                    };
                    match sync_state_write_fut.get_rwlock() {
                        Some(fs_instance_sync_state_member) => {
                            let fs_instance = fs_instance_sync_state_member.get_container();
                            *fs_instance.committing_transaction.lock() = CommittingTransactionState::None;
                        }
                        None => {
                            // Likewise here, it cannot happen, because we're polling right now on
                            // behalf of someone who does own a reference, but handle it anyway.
                            *this = Self::Done;
                            let r = ProgressCommittingTransactionFutureResult::CommitErrAbortJournalOk {
                                commit_error: NvFsError::Retry,
                            };
                            return task::Poll::Ready(r);
                        }
                    };
                    *this = Self::Done;
                    let r = ProgressCommittingTransactionFutureResult::CommitErrAbortJournalOk { commit_error: e };
                    return task::Poll::Ready(r);
                }
                task::Poll::Pending => {
                    return task::Poll::Pending;
                }
            },

            Self::GrabPendingTransactionsSyncStateForCommit {
                sync_state_write_guard, ..
            }
            | Self::CleanupOnPreCommitError {
                sync_state_write_guard, ..
            }
            | Self::WriteJournal {
                sync_state_write_guard, ..
            }
            | Self::DoApplyJournal {
                sync_state_write_guard, ..
            }
            | Self::ApplyJournal {
                sync_state_write_guard, ..
            }
            | Self::DoAbortJournal {
                sync_state_write_guard, ..
            }
            | Self::AbortJournal {
                sync_state_write_guard, ..
            } => {
                match sync_state_write_guard
                    .take()
                    .ok_or(NvFsError::PermanentInternalFailure)
                    .and_then(|sync_state_write_guard| sync_state_write_guard.upgrade().ok_or(NvFsError::Retry))
                {
                    Ok(sync_state_write_guard) => sync_state_write_guard,
                    Err(e) => {
                        // It cannot happen, because we're polling on someone's behalf who does own
                        // a reference, but still handle it correctly. Note that if the CocoonFs
                        // instance has been deallocated, no one will be able to issue writes to it
                        // and so there is no consistency issue.
                        let r = match this {
                            Self::AcquireCocoonFsSyncStateMemberWriteLock { .. } => {
                                // Would have been handled above though.
                                ProgressCommittingTransactionFutureResult::CommitErrAbortJournalOk { commit_error: e }
                            }
                            Self::GrabPendingTransactionsSyncStateForCommit { .. } => {
                                ProgressCommittingTransactionFutureResult::CommitErrAbortJournalOk { commit_error: e }
                            }
                            Self::CleanupOnPreCommitError { .. } => {
                                ProgressCommittingTransactionFutureResult::CommitErrAbortJournalOk { commit_error: e }
                            }
                            Self::WriteJournal { .. } => {
                                // It's unknown to which extent the journal has been written,
                                // so consider this a CommitErrAbortJournalErr.
                                ProgressCommittingTransactionFutureResult::CommitErrAbortJournalErr {
                                    commit_error: e,
                                    abort_journal_error: e,
                                }
                            }
                            Self::DoApplyJournal { .. } | Self::ApplyJournal { .. } => {
                                ProgressCommittingTransactionFutureResult::CommitOkApplyJournalErr {
                                    apply_journal_error: e,
                                }
                            }
                            Self::DoAbortJournal {
                                transaction_commit_error,
                                ..
                            }
                            | Self::AbortJournal {
                                transaction_commit_error,
                                ..
                            } => match transaction_commit_error {
                                Some((transaction_commit_error, _)) => {
                                    ProgressCommittingTransactionFutureResult::CommitErrAbortJournalErr {
                                        commit_error: *transaction_commit_error,
                                        abort_journal_error: e,
                                    }
                                }
                                None => ProgressCommittingTransactionFutureResult::RetryJournalAbortErr {
                                    abort_journal_error: e,
                                },
                            },
                            Self::Done => unreachable!(),
                        };

                        // Do not reset CocoonFs::committing_transaction so that the wrapping
                        // BroadcastFuture it will return the same error over and over again if
                        // tried. Note that in case sync_state_write_guard was None, it would have
                        // not even been possible to set the committing_transaction to
                        // PermanentInternalFailure, as any reference to the FS instance is gone,
                        // even though it might have been made sense logically.
                        *this = Self::Done;
                        return task::Poll::Ready(r);
                    }
                }
            }
            Self::Done => unreachable!(),
        };

        // Now, after having obtained a proper CocoonFsSyncStateMemberWriteGuard,
        // do the actual work.
        loop {
            match this {
                Self::AcquireCocoonFsSyncStateMemberWriteLock { .. } => {
                    // Handled above.
                    unreachable!();
                }

                Self::GrabPendingTransactionsSyncStateForCommit {
                    sync_state_write_guard: fut_sync_state_write_guard,
                    transaction,
                    pre_commit_validate_cb,
                    post_commit_cb,
                    issue_sync,
                    grab_pending_transactions_sync_state_fut,
                } => {
                    let mut queued_fut_poll_aux_data = &CocoonFsSyncStateMemberRef::from(&mut sync_state_write_guard);
                    match grab_pending_transactions_sync_state_fut.poll(&mut queued_fut_poll_aux_data, cx) {
                        task::Poll::Ready(
                            PendingTransactionsSyncFutureResult::GrabTransactionsSyncStateForCommit {
                                pending_transactions_sync_state,
                            },
                        ) => {
                            // The CocoonFsPendingTransactionsSyncState has just been grabbed from
                            // under any concurrent pending transaction. Now is a good time to
                            // invalidate those.
                            let fs_sync_state_rwlock = sync_state_write_guard.get_rwlock();
                            let fs_instance = fs_sync_state_rwlock.get_container();
                            fs_instance
                                .transaction_commit_gen
                                .fetch_add(1, atomic::Ordering::Relaxed);
                            // And reset the pending_transactions counter.
                            fs_instance.any_transaction_pending.store(0, atomic::Ordering::Relaxed);

                            let transaction = match transaction.take() {
                                Some(transaction) => transaction,
                                None => {
                                    let r = ProgressCommittingTransactionFutureResult::CommitErrAbortJournalOk {
                                        commit_error: nvfs_err_internal!(),
                                    };
                                    // Drop the sync_state write guard _before_ clearing out
                                    // committing_transaction. Threads seeing committing_transaction
                                    // == None expect to be able to grab the sync_state for read.
                                    drop(fs_sync_state_rwlock);
                                    let fs_instance = sync_state_write_guard.into_rwlock().into_container();
                                    *fs_instance.committing_transaction.lock() = CommittingTransactionState::None;
                                    *this = Self::Done;
                                    return task::Poll::Ready(r);
                                }
                            };

                            if let Some(pre_commit_validate_cb) = pre_commit_validate_cb.take() {
                                if let Err(e) = pre_commit_validate_cb() {
                                    *this = Self::CleanupOnPreCommitError {
                                        // Will receive the
                                        // CocoonFsSyncStateMemberWriteGuard::into_weak() upon
                                        // return from this poll() function.
                                        sync_state_write_guard: None,
                                        cleanup_fut: transaction::TransactionCleanupPreCommitCancelledFuture::new(
                                            transaction,
                                        ),
                                        pre_commit_error: e,
                                    };
                                    continue;
                                }
                            }

                            drop(fs_sync_state_rwlock);

                            let write_journal_fut = match transaction::TransactionWriteJournalFuture::new(
                                transaction,
                                *issue_sync,
                                CocoonFsSyncStateMemberMutRef::from(&mut sync_state_write_guard),
                                pending_transactions_sync_state,
                            ) {
                                Ok(write_journal_fut) => write_journal_fut,
                                Err((transaction, e)) => {
                                    *this = Self::CleanupOnPreCommitError {
                                        // Will receive the
                                        // CocoonFsSyncStateMemberWriteGuard::into_weak() upon
                                        // return from this poll() function.
                                        sync_state_write_guard: None,
                                        cleanup_fut: transaction::TransactionCleanupPreCommitCancelledFuture::new(
                                            transaction,
                                        ),
                                        pre_commit_error: e,
                                    };
                                    continue;
                                }
                            };

                            *this = Self::WriteJournal {
                                // Will receive the
                                // CocoonFsSyncStateMemberWriteGuard::into_weak() upon return
                                // from this poll() function.
                                sync_state_write_guard: None,
                                post_commit_cb: post_commit_cb.take(),
                                write_journal_fut,
                            }
                        }
                        task::Poll::Ready(_) => {
                            // This cannot happen, the result for the respective
                            // PendingTransactionsSyncFuture future variants match the respective
                            // result type variant. Handle it properly for good measure though.
                            // Here too, as the CocoonFsPendingTransactionsSyncState has just been
                            // grabbed from under any concurrent pending transaction, they ought to
                            // get invalidated before releasing the sync_state_write_guard.
                            let fs_sync_state_rwlock = sync_state_write_guard.get_rwlock();
                            let fs_instance = fs_sync_state_rwlock.get_container();
                            fs_instance
                                .transaction_commit_gen
                                .fetch_add(1, atomic::Ordering::Relaxed);

                            let r = ProgressCommittingTransactionFutureResult::CommitErrAbortJournalOk {
                                commit_error: nvfs_err_internal!(),
                            };
                            // Drop the sync_state write guard _before_ clearing out
                            // committing_transaction. Threads seeing committing_transaction == None
                            // expect to be able to grab the sync_state for read.
                            drop(fs_sync_state_rwlock);
                            let fs_instance = sync_state_write_guard.into_rwlock().into_container();
                            *fs_instance.committing_transaction.lock() = CommittingTransactionState::None;
                            *this = Self::Done;
                            return task::Poll::Ready(r);
                        }
                        task::Poll::Pending => {
                            *fut_sync_state_write_guard = Some(sync_state_write_guard.into_weak());
                            return task::Poll::Pending;
                        }
                    }
                }

                Self::CleanupOnPreCommitError {
                    sync_state_write_guard: fut_sync_state_write_guard,
                    cleanup_fut,
                    pre_commit_error,
                } => {
                    match transaction::TransactionCleanupPreCommitCancelledFuture::poll(
                        pin::Pin::new(cleanup_fut),
                        CocoonFsSyncStateMemberMutRef::from(&mut sync_state_write_guard),
                        cx,
                    ) {
                        task::Poll::Ready(()) => {
                            // Drop the sync_state write guard _before_ clearing out
                            // committing_transaction. Threads seeing committing_transaction == None
                            // expect to be able to grab the sync_state for read.
                            let fs_instance = sync_state_write_guard.into_rwlock().into_container();
                            *fs_instance.committing_transaction.lock() = CommittingTransactionState::None;
                            let r = ProgressCommittingTransactionFutureResult::CommitErrAbortJournalOk {
                                commit_error: *pre_commit_error,
                            };
                            *this = Self::Done;
                            return task::Poll::Ready(r);
                        }
                        task::Poll::Pending => {
                            *fut_sync_state_write_guard = Some(sync_state_write_guard.into_weak());
                            return task::Poll::Pending;
                        }
                    }
                }

                Self::WriteJournal {
                    sync_state_write_guard: fut_sync_state_write_guard,
                    post_commit_cb,
                    write_journal_fut,
                } => {
                    match transaction::TransactionWriteJournalFuture::poll(
                        pin::Pin::new(write_journal_fut),
                        CocoonFsSyncStateMemberMutRef::from(&mut sync_state_write_guard),
                        rng,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(transaction)) => {
                            // The journal has not been applied yet, but the changes have been
                            // written to the storage and will get applied one way or another, even
                            // after power cuts. Invoke the post_commit_cb, if any, and inform it
                            // about the good news.
                            if let Some(post_commit_cb) = post_commit_cb.take() {
                                post_commit_cb(Ok(()));
                            }
                            *this = Self::DoApplyJournal {
                                // Will receive the
                                // CocoonFsSyncStateMemberWriteGuard::into_weak() upon return
                                // from this poll() function.
                                sync_state_write_guard: None,
                                transaction: Some(transaction),
                                low_memory: false,
                            }
                        }
                        task::Poll::Ready(Err((need_journal_abort, transaction, e))) => {
                            if !need_journal_abort {
                                if let Some(post_commit_cb) = post_commit_cb.take() {
                                    post_commit_cb(Err(fs::TransactionCommitError::LogStateClean { reason: e }));
                                }

                                match transaction {
                                    Some(transaction) => {
                                        *this = Self::CleanupOnPreCommitError {
                                            // Will receive the
                                            // CocoonFsSyncStateMemberWriteGuard::into_weak() upon
                                            // return from this poll() function.
                                            sync_state_write_guard: None,
                                            cleanup_fut: transaction::TransactionCleanupPreCommitCancelledFuture::new(
                                                transaction,
                                            ),
                                            pre_commit_error: e,
                                        };
                                        continue;
                                    }
                                    None => {
                                        let r = ProgressCommittingTransactionFutureResult::CommitErrAbortJournalOk {
                                            commit_error: nvfs_err_internal!(),
                                        };
                                        // Drop the sync_state write guard _before_ clearing out
                                        // committing_transaction. Threads seeing
                                        // committing_transaction == None expect to be able to grab
                                        // the sync_state for read.
                                        let fs_instance = sync_state_write_guard.into_rwlock().into_container();
                                        *fs_instance.committing_transaction.lock() = CommittingTransactionState::None;
                                        *this = Self::Done;
                                        return task::Poll::Ready(r);
                                    }
                                }
                            }

                            *this = Self::DoAbortJournal {
                                // Will receive the
                                // CocoonFsSyncStateMemberWriteGuard::into_weak() upon return
                                // from this poll() function.
                                sync_state_write_guard: None,
                                transaction,
                                transaction_commit_error: Some((e, post_commit_cb.take())),
                                low_memory: e == NvFsError::MemoryAllocationFailure,
                            };
                        }
                        task::Poll::Pending => {
                            *fut_sync_state_write_guard = Some(sync_state_write_guard.into_weak());
                            return task::Poll::Pending;
                        }
                    }
                }

                Self::DoApplyJournal {
                    sync_state_write_guard: _,
                    transaction,
                    low_memory,
                } => {
                    let transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => {
                            // The journal got written, hence the changes are considered effective
                            // and success might have been reported back to the original
                            // initiator. Yet the transaction is somehow gone due to an internal
                            // error. There's really not much that could be done to drive progress
                            // forward at this point.
                            let fs_instance = sync_state_write_guard.get_rwlock().get_container().make_clone();
                            *fs_instance.committing_transaction.lock() =
                                CommittingTransactionState::PermanentInternalFailure {
                                    _sync_state_write_guard: Some(sync_state_write_guard.into_weak()),
                                };
                            *this = Self::Done;
                            let r = ProgressCommittingTransactionFutureResult::CommitOkApplyJournalErr {
                                apply_journal_error: nvfs_err_internal!(),
                            };
                            return task::Poll::Ready(r);
                        }
                    };

                    let apply_journal_fut = match transaction::TransactionApplyJournalFuture::new(
                        transaction,
                        CocoonFsSyncStateMemberMutRef::from(&mut sync_state_write_guard),
                        *low_memory,
                    ) {
                        Ok(apply_journal_fut) => apply_journal_fut,
                        Err((transaction, e)) => {
                            // This attempt to apply the journal failed. As the changes have been
                            // committed to storage now and will get applied one way or the other,
                            // even after power cuts, still complete the outermost future to allow
                            // for some progress. Leave an indication at the fs'
                            // commiting_transaction so that the next attempt to do anything on the
                            // fs (read or write) will first retry the journal application operation
                            // before proceeding any further.
                            let fs_instance = sync_state_write_guard.get_rwlock().get_container().make_clone();
                            *fs_instance.committing_transaction.lock() =
                                CommittingTransactionState::RetryApplyJournal {
                                    sync_state_write_guard: Some(sync_state_write_guard.into_weak()),
                                    transaction: Some(transaction),
                                    low_memory: *low_memory | (e == NvFsError::MemoryAllocationFailure),
                                };
                            *this = Self::Done;
                            let r = ProgressCommittingTransactionFutureResult::CommitOkApplyJournalErr {
                                apply_journal_error: e,
                            };
                            return task::Poll::Ready(r);
                        }
                    };

                    *this = Self::ApplyJournal {
                        // Will receive the CocoonFsSyncStateMemberWriteGuard::into_weak() upon
                        // return from this poll() function.
                        sync_state_write_guard: None,
                        apply_journal_fut,
                        low_memory: *low_memory,
                    };
                }

                Self::ApplyJournal {
                    sync_state_write_guard: fut_sync_state_write_guard,
                    apply_journal_fut,
                    low_memory,
                } => {
                    match transaction::TransactionApplyJournalFuture::poll(
                        pin::Pin::new(apply_journal_fut),
                        CocoonFsSyncStateMemberMutRef::from(&mut sync_state_write_guard),
                        cx,
                    ) {
                        task::Poll::Ready(Ok(())) => {
                            // Drop the sync_state write guard _before_ clearing out
                            // committing_transaction. Threads seeing committing_transaction == None
                            // expect to be able to grab the sync_state for read.
                            let fs_instance = sync_state_write_guard.into_rwlock().into_container();
                            *fs_instance.committing_transaction.lock() = CommittingTransactionState::None;
                            *this = Self::Done;
                            return task::Poll::Ready(ProgressCommittingTransactionFutureResult::Ok);
                        }
                        task::Poll::Ready(Err((transaction, e))) => {
                            // This attempt to apply the journal failed. As the changes have been
                            // committed to storage now and will get applied one way or the other,
                            // even after power cuts, still complete the outermost future to allow
                            // for some progress. Leave an indication at the fs'
                            // commiting_transaction so that the next attempt to do anything on the
                            // fs (read or write) will first retry the journal application operation
                            // before proceeding any further.
                            let fs_instance = sync_state_write_guard.get_rwlock().get_container().make_clone();
                            let e = match transaction {
                                Some(transaction) => {
                                    *fs_instance.committing_transaction.lock() =
                                        CommittingTransactionState::RetryApplyJournal {
                                            sync_state_write_guard: Some(sync_state_write_guard.into_weak()),
                                            transaction: Some(transaction),
                                            low_memory: *low_memory | (e == NvFsError::MemoryAllocationFailure),
                                        };
                                    e
                                }
                                None => {
                                    // The transaction is somehow gone due to an internal
                                    // error. There's really not much that could be done to drive
                                    // progress forward at this point.
                                    *fs_instance.committing_transaction.lock() =
                                        CommittingTransactionState::PermanentInternalFailure {
                                            _sync_state_write_guard: Some(sync_state_write_guard.into_weak()),
                                        };
                                    nvfs_err_internal!()
                                }
                            };
                            *this = Self::Done;
                            let r = ProgressCommittingTransactionFutureResult::CommitOkApplyJournalErr {
                                apply_journal_error: e,
                            };
                            return task::Poll::Ready(r);
                        }
                        task::Poll::Pending => {
                            *fut_sync_state_write_guard = Some(sync_state_write_guard.into_weak());
                            return task::Poll::Pending;
                        }
                    }
                }

                Self::DoAbortJournal {
                    sync_state_write_guard: _,
                    transaction,
                    transaction_commit_error,
                    low_memory,
                } => {
                    let abort_journal_fut = match transaction::TransactionAbortJournalFuture::new(
                        transaction.take(),
                        CocoonFsSyncStateMemberMutRef::from(&mut sync_state_write_guard),
                        *low_memory,
                    ) {
                        Ok(abort_journal_fut) => abort_journal_fut,
                        Err((transaction, e)) => {
                            // This attempt to abort the journal failed. Still complete the
                            // outermost commit future to allow for progress and leave an indication
                            // at the fs' -> commiting_transaction so that the next attempt to do
                            // anything on the fs (read or write) will first retry the journal
                            // abortion operation before proceeding any further.
                            let fs_instance = sync_state_write_guard.get_rwlock().get_container().make_clone();
                            *fs_instance.committing_transaction.lock() =
                                CommittingTransactionState::RetryAbortJournal {
                                    sync_state_write_guard: Some(sync_state_write_guard.into_weak()),
                                    transaction,
                                    low_memory: *low_memory | (e == NvFsError::MemoryAllocationFailure),
                                };

                            let r = match transaction_commit_error.take() {
                                Some((transaction_commit_error, post_commit_cb)) => {
                                    if let Some(post_commit_cb) = post_commit_cb {
                                        // The user supplied post_commit_cb has not been invoked yet. Do
                                        // it now and convey the bad news.
                                        post_commit_cb(Err(fs::TransactionCommitError::LogStateIndeterminate {
                                            reason: transaction_commit_error,
                                        }));
                                    }

                                    ProgressCommittingTransactionFutureResult::CommitErrAbortJournalErr {
                                        commit_error: transaction_commit_error,
                                        abort_journal_error: e,
                                    }
                                }
                                None => ProgressCommittingTransactionFutureResult::RetryJournalAbortErr {
                                    abort_journal_error: e,
                                },
                            };

                            *this = Self::Done;
                            return task::Poll::Ready(r);
                        }
                    };
                    *this = Self::AbortJournal {
                        // Will receive the CocoonFsSyncStateMemberWriteGuard::into_weak() upon
                        // return from this poll() function.
                        sync_state_write_guard: None,
                        transaction_commit_error: transaction_commit_error.take(),
                        abort_journal_fut,
                        low_memory: *low_memory,
                    };
                }

                Self::AbortJournal {
                    sync_state_write_guard: fut_sync_state_write_guard,
                    transaction_commit_error,
                    abort_journal_fut,
                    low_memory,
                } => {
                    match transaction::TransactionAbortJournalFuture::poll(
                        pin::Pin::new(abort_journal_fut),
                        CocoonFsSyncStateMemberMutRef::from(&mut sync_state_write_guard),
                        cx,
                    ) {
                        task::Poll::Ready(Ok(())) => {
                            let r = match transaction_commit_error.take() {
                                Some((transaction_commit_error, post_commit_cb)) => {
                                    if let Some(post_commit_cb) = post_commit_cb {
                                        // The post_commit_cb had not been called yet. Spread the
                                        // good news that we're in a consistent state, at
                                        // least.
                                        post_commit_cb(Err(fs::TransactionCommitError::LogStateClean {
                                            reason: transaction_commit_error,
                                        }));
                                    }
                                    ProgressCommittingTransactionFutureResult::CommitErrAbortJournalOk {
                                        commit_error: transaction_commit_error,
                                    }
                                }
                                None => ProgressCommittingTransactionFutureResult::RetryJournalAbortOk,
                            };
                            // Drop the sync_state write guard _before_ clearing out
                            // committing_transaction. Threads seeing committing_transaction == None
                            // expect to be able to grab the sync_state for read.
                            let fs_instance = sync_state_write_guard.into_rwlock().into_container();
                            *fs_instance.committing_transaction.lock() = CommittingTransactionState::None;
                            *this = Self::Done;
                            return task::Poll::Ready(r);
                        }
                        task::Poll::Ready(Err((transaction, e))) => {
                            // This attempt to abort the journal failed. Still complete the
                            // outermost commit future to allow for progress and leave an indication
                            // at the fs' -> commiting_transaction so that the next attempt to do
                            // anything on the fs (read or write) will first retry the journal
                            // abortion operation before proceeding any further.
                            let fs_instance = sync_state_write_guard.get_rwlock().get_container().make_clone();
                            *fs_instance.committing_transaction.lock() =
                                CommittingTransactionState::RetryAbortJournal {
                                    sync_state_write_guard: Some(sync_state_write_guard.into_weak()),
                                    transaction,
                                    low_memory: *low_memory | (e == NvFsError::MemoryAllocationFailure),
                                };

                            let r = match transaction_commit_error.take() {
                                Some((transaction_commit_error, post_commit_cb)) => {
                                    if let Some(post_commit_cb) = post_commit_cb {
                                        // The user supplied post_commit_cb has not been invoked yet. Do
                                        // it now and convey the bad news.
                                        post_commit_cb(Err(fs::TransactionCommitError::LogStateIndeterminate {
                                            reason: transaction_commit_error,
                                        }));
                                    }

                                    ProgressCommittingTransactionFutureResult::CommitErrAbortJournalErr {
                                        commit_error: transaction_commit_error,
                                        abort_journal_error: e,
                                    }
                                }
                                None => ProgressCommittingTransactionFutureResult::RetryJournalAbortErr {
                                    abort_journal_error: e,
                                },
                            };

                            *this = Self::Done;
                            return task::Poll::Ready(r);
                        }
                        task::Poll::Pending => {
                            *fut_sync_state_write_guard = Some(sync_state_write_guard.into_weak());
                            return task::Poll::Pending;
                        }
                    }
                }

                Self::Done => unreachable!(),
            }
        }
    }
}

/// Start a [`CocoonFsConsistentReadSequence`].
///
/// If there's a committing transaction at [`CocoonFs::committing_transaction`],
/// help out driving its progress forward and eventually return a snapshot of
/// [`CocoonFs::transaction_commit_gen`] wrapped in a
/// [`CocoonFsConsistentReadSequence`].
enum StartReadSequenceFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    Init,
    ProgressCommittingTransaction {
        progress_committing_transaction_subscription_fut:
            ProgressCommittingTransactionBroadcastFutureSubscriptionType<ST, C>,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> StartReadSequenceFuture<ST, C> {
    fn new() -> Self {
        Self::Init
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> fs::NvFsFuture<CocoonFs<ST, C>> for StartReadSequenceFuture<ST, C> {
    type Output = Result<CocoonFsConsistentReadSequence, NvFsError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        fs_instance: &CocoonFsSyncRcPtrRefType<ST, C>,
        mut rng: &mut dyn rng::RngCoreDispatchable,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        loop {
            match this {
                Self::Init => {
                    let mut committing_transaction = fs_instance.committing_transaction.lock();
                    'recheck: loop {
                        match committing_transaction.deref_mut() {
                            CommittingTransactionState::None => {
                                // No Transaction in progress, return a snapshot of the commit generation
                                // counter.
                                let base_transaction_commit_gen =
                                    fs_instance.transaction_commit_gen.load(atomic::Ordering::Relaxed);

                                *this = Self::Done;
                                return task::Poll::Ready(Ok(CocoonFsConsistentReadSequence {
                                    base_transaction_commit_gen,
                                }));
                            }
                            CommittingTransactionState::Progressing { progress_broadcast_fut } => {
                                // A transaction commit is in progress. Subscribe and help out to complete it in
                                // case the original submitter abandoned its request.
                                // Do any potential allocation outside the lock.
                                let progress_broadcast_fut = &progress_broadcast_fut.clone();
                                drop(committing_transaction);
                                let progress_committing_transaction_subscription_fut =
                                    match ProgressCommittingTransactionBroadcastFutureType::subscribe(<pin::Pin<
                                        ProgressCommittingTransactionBroadcastFutureSyncRcPtrType<ST, C>,
                                    > as sync_types::SyncRcPtr<
                                        ProgressCommittingTransactionBroadcastFutureType<ST, C>,
                                    >>::as_ref(
                                        progress_broadcast_fut,
                                    ))
                                    .map_err(|e| match e {
                                        asynchronous::BroadcastFutureError::MemoryAllocationFailure => {
                                            NvFsError::MemoryAllocationFailure
                                        }
                                    }) {
                                        Ok(progress_committing_transaction_subscription_fut) => {
                                            progress_committing_transaction_subscription_fut
                                        }
                                        Err(e) => {
                                            *this = Self::Done;
                                            return task::Poll::Ready(Err(e));
                                        }
                                    };
                                *this = Self::ProgressCommittingTransaction {
                                    progress_committing_transaction_subscription_fut,
                                };
                                break;
                            }
                            CommittingTransactionState::RetryApplyJournal { .. } => {
                                // A previous transaction commit's journal write completed
                                // successfully, but the journal application
                                // failed. Retry to complete before proceeding any further.
                                // Don't allocate under the lock.
                                drop(committing_transaction);
                                let progress_broadcast_fut;
                                (progress_broadcast_fut, committing_transaction) =
                                    match <ST::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>::try_new_with(|| {
                                        // When here, the SyncRcPtr memory allocation has happened and was
                                        // successful. Reacquire the lock and grab the sync_state_write_guard +
                                        // transaction, the remaining construction cannot fail.
                                        let mut committing_transaction = fs_instance.committing_transaction.lock();
                                        match committing_transaction.deref_mut() {
                                            CommittingTransactionState::RetryApplyJournal {
                                                sync_state_write_guard,
                                                transaction,
                                                low_memory,
                                            } => Ok((
                                                ProgressCommittingTransactionBroadcastFutureType::new(
                                                    ProgressCommittingTransactionFuture::DoApplyJournal {
                                                        sync_state_write_guard: sync_state_write_guard.take(),
                                                        transaction: transaction.take(),
                                                        low_memory: *low_memory,
                                                    },
                                                ),
                                                committing_transaction,
                                            )),
                                            _ => {
                                                // The contents of committing_transaction have changed since
                                                // dropping the lock.
                                                Err((NvFsError::Retry, committing_transaction))
                                            }
                                        }
                                    }) {
                                        Ok(r) => r,
                                        Err(e) => {
                                            match e {
                                                sync_types::SyncRcPtrTryNewWithError::TryNewError(e) => match e {
                                                    sync_types::SyncRcPtrTryNewError::AllocationFailure => {
                                                        if let CommittingTransactionState::RetryApplyJournal {
                                                            low_memory,
                                                            ..
                                                        } = fs_instance.committing_transaction.lock().deref_mut()
                                                        {
                                                            *low_memory = true;
                                                        }
                                                        *this = Self::Done;
                                                        return task::Poll::Ready(Err(
                                                            NvFsError::MemoryAllocationFailure,
                                                        ));
                                                    }
                                                },
                                                sync_types::SyncRcPtrTryNewWithError::WithError((
                                                    e,
                                                    reacquired_committing_transaction,
                                                )) => {
                                                    // Avoid infinite retry cycles and loop over only if the
                                                    // next iteration is guaranteed to succeed.
                                                    if e == NvFsError::Retry
                                                        && matches!(
                                                            reacquired_committing_transaction.deref(),
                                                            CommittingTransactionState::None
                                                        )
                                                    {
                                                        committing_transaction = reacquired_committing_transaction;
                                                        continue 'recheck;
                                                    }
                                                    *this = Self::Done;
                                                    return task::Poll::Ready(Err(e));
                                                }
                                            };
                                        }
                                    };

                                // Sound, never moved out of or otherwise invalidated.
                                let progress_broadcast_fut = unsafe { pin::Pin::new_unchecked(progress_broadcast_fut) };

                                // Install the broadcast future at the fs' instances ->committing_transaction.
                                *committing_transaction = CommittingTransactionState::Progressing {
                                    progress_broadcast_fut: progress_broadcast_fut.clone(),
                                };

                                // Subscribe to the broadcast future just created.
                                // Don't subscribe under the lock.
                                drop(committing_transaction);

                                let progress_committing_transaction_subscription_fut =
                                    match ProgressCommittingTransactionBroadcastFutureType::subscribe(<pin::Pin<
                                        ProgressCommittingTransactionBroadcastFutureSyncRcPtrType<ST, C>,
                                    > as sync_types::SyncRcPtr<
                                        ProgressCommittingTransactionBroadcastFutureType<ST, C>,
                                    >>::as_ref(
                                        &progress_broadcast_fut,
                                    ))
                                    .map_err(|e| match e {
                                        asynchronous::BroadcastFutureError::MemoryAllocationFailure => {
                                            NvFsError::MemoryAllocationFailure
                                        }
                                    }) {
                                        Ok(progress_committing_transaction_subscription_fut) => {
                                            progress_committing_transaction_subscription_fut
                                        }
                                        Err(e) => {
                                            *this = Self::Done;
                                            return task::Poll::Ready(Err(e));
                                        }
                                    };
                                *this = Self::ProgressCommittingTransaction {
                                    progress_committing_transaction_subscription_fut,
                                };
                                break;
                            }
                            CommittingTransactionState::RetryAbortJournal { .. } => {
                                // A previous transaction commit's journal write failed, and
                                // the subsequent journal abort
                                // operation did as well. Retry to complete before
                                // proceeding any further.
                                drop(committing_transaction);
                                let progress_broadcast_fut;
                                (progress_broadcast_fut, committing_transaction) =
                                    match <ST::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>::try_new_with(|| {
                                        // When here, the SyncRcPtr memory allocation has happened and was
                                        // successful. Reacquire the lock and grab the the
                                        // sync_state_write_guard + transaction, the remaining construction
                                        // cannot fail.
                                        let mut committing_transaction = fs_instance.committing_transaction.lock();
                                        match committing_transaction.deref_mut() {
                                            CommittingTransactionState::RetryAbortJournal {
                                                sync_state_write_guard,
                                                transaction,
                                                low_memory,
                                            } => Ok((
                                                ProgressCommittingTransactionBroadcastFutureType::new(
                                                    ProgressCommittingTransactionFuture::DoAbortJournal {
                                                        sync_state_write_guard: sync_state_write_guard.take(),
                                                        transaction: transaction.take(),
                                                        transaction_commit_error: None,
                                                        low_memory: *low_memory,
                                                    },
                                                ),
                                                committing_transaction,
                                            )),
                                            _ => {
                                                // The contents of committing_transaction have changed since
                                                // dropping the lock.
                                                Err((NvFsError::Retry, committing_transaction))
                                            }
                                        }
                                    }) {
                                        Ok(r) => r,
                                        Err(e) => {
                                            match e {
                                                sync_types::SyncRcPtrTryNewWithError::TryNewError(e) => match e {
                                                    sync_types::SyncRcPtrTryNewError::AllocationFailure => {
                                                        if let CommittingTransactionState::RetryAbortJournal {
                                                            low_memory,
                                                            ..
                                                        } = fs_instance.committing_transaction.lock().deref_mut()
                                                        {
                                                            *low_memory = true;
                                                        }
                                                        *this = Self::Done;
                                                        return task::Poll::Ready(Err(
                                                            NvFsError::MemoryAllocationFailure,
                                                        ));
                                                    }
                                                },
                                                sync_types::SyncRcPtrTryNewWithError::WithError((
                                                    e,
                                                    reacquired_committing_transaction,
                                                )) => {
                                                    // Avoid infinite retry cycles and loop over only if the
                                                    // next iteration is guaranteed to succeed.
                                                    if e == NvFsError::Retry
                                                        && matches!(
                                                            reacquired_committing_transaction.deref(),
                                                            CommittingTransactionState::None
                                                        )
                                                    {
                                                        committing_transaction = reacquired_committing_transaction;
                                                        continue 'recheck;
                                                    }
                                                    *this = Self::Done;
                                                    return task::Poll::Ready(Err(e));
                                                }
                                            };
                                        }
                                    };

                                // Sound, never moved out of or otherwise invalidated.
                                let progress_broadcast_fut = unsafe { pin::Pin::new_unchecked(progress_broadcast_fut) };

                                // Install the broadcast future at the fs' instances ->committing_transaction.
                                *committing_transaction = CommittingTransactionState::Progressing {
                                    progress_broadcast_fut: progress_broadcast_fut.clone(),
                                };

                                // Subscribe to the broadcast future just created.
                                // Don't subscribe under the lock.
                                drop(committing_transaction);

                                let progress_committing_transaction_subscription_fut =
                                    match ProgressCommittingTransactionBroadcastFutureType::subscribe(<pin::Pin<
                                        ProgressCommittingTransactionBroadcastFutureSyncRcPtrType<ST, C>,
                                    > as sync_types::SyncRcPtr<
                                        ProgressCommittingTransactionBroadcastFutureType<ST, C>,
                                    >>::as_ref(
                                        &progress_broadcast_fut,
                                    ))
                                    .map_err(|e| match e {
                                        asynchronous::BroadcastFutureError::MemoryAllocationFailure => {
                                            NvFsError::MemoryAllocationFailure
                                        }
                                    }) {
                                        Ok(progress_committing_transaction_subscription_fut) => {
                                            progress_committing_transaction_subscription_fut
                                        }
                                        Err(e) => {
                                            *this = Self::Done;
                                            return task::Poll::Ready(Err(e));
                                        }
                                    };
                                *this = Self::ProgressCommittingTransaction {
                                    progress_committing_transaction_subscription_fut,
                                };
                                break;
                            }
                            CommittingTransactionState::PermanentInternalFailure {
                                _sync_state_write_guard: _,
                            } => {
                                *this = Self::Done;
                                return task::Poll::Ready(Err(NvFsError::PermanentInternalFailure));
                            }
                        };
                    }
                }
                Self::ProgressCommittingTransaction {
                    progress_committing_transaction_subscription_fut,
                } => {
                    // In case that progressing the committing transaction failed, complete the
                    // future here to allow for progress. Any subsequent attempt to
                    // use the the fs instance will find the uncompleted transaction
                    // back in ->committing_transaction again and retry before
                    // proceeding any further.
                    match ProgressCommittingTransactionBroadcastFutureSubscriptionType::poll(
                        pin::Pin::new(progress_committing_transaction_subscription_fut),
                        &mut rng,
                        cx,
                    ) {
                        task::Poll::Ready(r) => match r {
                            ProgressCommittingTransactionFutureResult::Ok => (),
                            ProgressCommittingTransactionFutureResult::CommitOkApplyJournalErr {
                                apply_journal_error,
                            } => {
                                *this = Self::Done;
                                return task::Poll::Ready(Err(apply_journal_error));
                            }
                            ProgressCommittingTransactionFutureResult::CommitErrAbortJournalOk { .. }
                            | ProgressCommittingTransactionFutureResult::RetryJournalAbortOk => (),
                            ProgressCommittingTransactionFutureResult::CommitErrAbortJournalErr {
                                commit_error: _,
                                abort_journal_error,
                            }
                            | ProgressCommittingTransactionFutureResult::RetryJournalAbortErr { abort_journal_error } =>
                            {
                                *this = Self::Done;
                                return task::Poll::Ready(Err(abort_journal_error));
                            }
                        },
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let base_transaction_commit_gen =
                        fs_instance.transaction_commit_gen.load(atomic::Ordering::Relaxed);
                    *this = Self::Done;
                    return task::Poll::Ready(Ok(CocoonFsConsistentReadSequence {
                        base_transaction_commit_gen,
                    }));
                }
                Self::Done => unreachable!(),
            }
        }
    }
}

/// Common trait for internal futures requiring non-exclusive access to the
/// [`CocoonFs::sync_state`].
pub trait CocoonFsSyncStateReadFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    /// Output type of [`poll()`](Self::poll).
    type Output;
    /// Auxiliary data to pass to [`poll()`](Self::poll).
    type AuxPollData<'a>;

    /// Poll for future completion.
    ///
    /// # Arguments:
    ///
    /// * `fs_instance_sync_state` - Non-exlusive [`CocoonFsSyncStateMemberRef`]
    ///   to the [`CocoonFs::sync_state`].
    /// * `aux_data` - Auxiliary data.
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    fn poll<'a>(
        self: pin::Pin<&mut Self>,
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, C>,
        aux_data: &mut Self::AuxPollData<'a>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output>;
}

/// [`Subscription`](asynchronous::EnqueuedFutureSubscription) to an
/// [`PendingTransactionsSyncFuture`] enqueued
/// to the [`CocoonFs::pending_transactions_sync_state`]
/// [`FutureQueue`](asynchronous::FutureQueue).
type QueuedPendingTransactionsSyncFuture<ST, C> = asynchronous::EnqueuedFutureSubscription<
    ST,
    CocoonFsPendingTransactionsSyncState,
    PendingTransactionsSyncFuture<ST, C>,
    PlainCocoonFsPendingTransactionsSyncStateMemberSyncRcPtrType<ST, C>,
>;

/// Implementation demultiplexing [`QueuedFuture`](asynchronous::QueuedFuture)
/// to be enqueued the [`CocoonFs::pending_transactions_sync_state`]
/// [`FutureQueue`](asynchronous::FutureQueue).
///
/// Implementation backend for [`CocoonFsAllocateBlockFuture`],
/// [`CocoonFsAllocateBlocksFuture`] and [`CocoonFsAllocateExtentsFuture`],
/// which all require exlusive access to
/// [`CocoonFs::pending_transactions_sync_state`], as is provided by the
/// [`FutureQueue`](asynchronous::FutureQueue)'s serialization.
enum PendingTransactionsSyncFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    GrabTransactionsSyncStateForCommit,
    /// Serve a [`CocoonFsAllocateExtentsFuture`].
    AllocateExtents {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<transaction::Transaction>>,
        request: alloc_bitmap::ExtentsAllocationRequest,
        for_journal: bool,
    },
    /// Serve a [`CocoonFsAllocateBlockFuture`].
    AllocateBlock {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<transaction::Transaction>>,
        block_allocation_blocks_log2: u32,
        for_journal: bool,
    },
    /// Serve a [`CocoonFsAllocateBlocksFuture`].
    AllocateBlocks {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<transaction::Transaction>>,
        block_allocation_blocks_log2: u32,
        count: usize,
        for_journal: bool,
        request_pending_allocs: alloc_bitmap::SparseAllocBitmap,
        result: Vec<layout::PhysicalAllocBlockIndex>,
    },
    Done(marker::PhantomData<fn() -> (ST, C)>),
}

/// Result type of [`PendingTransactionsSyncFuture`].
enum PendingTransactionsSyncFutureResult {
    GrabTransactionsSyncStateForCommit {
        pending_transactions_sync_state: CocoonFsPendingTransactionsSyncState,
    },
    /// The result in case the [`PendingTransactionsSyncFuture`] operated on
    /// behalf of a [`CocoonFsAllocateExtentsFuture`].
    AllocateExtents {
        #[allow(clippy::type_complexity)]
        result: Result<
            (
                Box<transaction::Transaction>,
                Result<(extents::PhysicalExtents, u64), NvFsError>,
            ),
            NvFsError,
        >,
    },
    /// The result in case the [`PendingTransactionsSyncFuture`] operated on
    /// behalf of a [`CocoonFsAllocateBlockFuture`].
    AllocateBlock {
        #[allow(clippy::type_complexity)]
        result: Result<
            (
                Box<transaction::Transaction>,
                Result<layout::PhysicalAllocBlockIndex, NvFsError>,
            ),
            NvFsError,
        >,
    },
    /// The result in case the [`PendingTransactionsSyncFuture`] operated on
    /// behalf of a [`CocoonFsAllocateBlocksFuture`].
    AllocateBlocks {
        #[allow(clippy::type_complexity)]
        result: Result<
            (
                Box<transaction::Transaction>,
                Result<Vec<layout::PhysicalAllocBlockIndex>, NvFsError>,
            ),
            NvFsError,
        >,
    },
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> PendingTransactionsSyncFuture<ST, C> {
    fn into_transaction(self) -> Option<Box<transaction::Transaction>> {
        match self {
            Self::GrabTransactionsSyncStateForCommit => None,
            Self::AllocateExtents { mut transaction, .. } => transaction.take(),
            Self::AllocateBlock { mut transaction, .. } => transaction.take(),
            Self::AllocateBlocks { mut transaction, .. } => transaction.take(),
            Self::Done(..) => None,
        }
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> asynchronous::QueuedFuture<CocoonFsPendingTransactionsSyncState>
    for PendingTransactionsSyncFuture<ST, C>
{
    type Output = PendingTransactionsSyncFutureResult;
    type AuxPollData<'a> = &'a CocoonFsSyncStateMemberRef<'a, ST, C>;

    fn poll<'a>(
        self: pin::Pin<&mut Self>,
        pending_transactions_sync_state: &mut CocoonFsPendingTransactionsSyncState,
        aux_data: &mut Self::AuxPollData<'a>,
        _cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        match this {
            Self::GrabTransactionsSyncStateForCommit => {
                let pending_transactions_sync_state = mem::replace(
                    pending_transactions_sync_state,
                    CocoonFsPendingTransactionsSyncState::new(),
                );
                *this = Self::Done(marker::PhantomData);
                task::Poll::Ready(
                    PendingTransactionsSyncFutureResult::GrabTransactionsSyncStateForCommit {
                        pending_transactions_sync_state,
                    },
                )
            }
            Self::AllocateExtents {
                transaction,
                request,
                for_journal,
            } => {
                let mut transaction = match transaction.take() {
                    Some(transaction) => transaction,
                    None => {
                        *this = Self::Done(marker::PhantomData);
                        return task::Poll::Ready(PendingTransactionsSyncFutureResult::AllocateExtents {
                            result: Err(nvfs_err_internal!()),
                        });
                    }
                };
                let pending_transactions_allocs = &pending_transactions_sync_state.pending_allocs;
                let fs_sync_state = *aux_data;
                let empty_pending_frees = alloc_bitmap::SparseAllocBitmap::new();
                // Do not repurpose pending frees if allocating for the journal.
                let transaction_pending_frees = if *for_journal {
                    &empty_pending_frees
                } else {
                    &transaction.allocs.pending_frees
                };

                let pending_allocs = [
                    &transaction.allocs.pending_allocs,
                    &transaction.allocs.journal_allocs,
                    pending_transactions_allocs,
                ];
                let pending_allocs = alloc_bitmap::SparseAllocBitmapUnion::new(&pending_allocs);
                let pending_frees = [transaction_pending_frees];
                let pending_frees = alloc_bitmap::SparseAllocBitmapUnion::new(&pending_frees);

                let result = fs_sync_state.alloc_bitmap.find_free_extents(
                    request,
                    &pending_allocs,
                    &pending_frees,
                    fs_sync_state.image_size,
                    true,
                );
                let result = match result {
                    Ok(Some(result)) => {
                        if let Err(e) =
                            pending_transactions_sync_state.register_allocated_extents(fs_sync_state, &result.0)
                        {
                            Err(e)
                        } else if let Err(e) = if *for_journal {
                            &mut transaction.allocs.journal_allocs
                        } else {
                            &mut transaction.allocs.pending_allocs
                        }
                        .add_extents(result.0.iter())
                        {
                            pending_transactions_sync_state.deregister_allocated_extents(fs_sync_state, &result.0);
                            Err(e)
                        } else {
                            transaction.allocs.pending_frees.remove_extents(result.0.iter());
                            Ok(result)
                        }
                    }
                    Ok(None) => Err(NvFsError::NoSpace),
                    Err(e) => Err(e),
                };
                *this = Self::Done(marker::PhantomData);
                task::Poll::Ready(PendingTransactionsSyncFutureResult::AllocateExtents {
                    result: Ok((transaction, result)),
                })
            }
            Self::AllocateBlock {
                transaction,
                block_allocation_blocks_log2,
                for_journal,
            } => {
                let mut transaction = match transaction.take() {
                    Some(transaction) => transaction,
                    None => {
                        *this = Self::Done(marker::PhantomData);
                        return task::Poll::Ready(PendingTransactionsSyncFutureResult::AllocateBlock {
                            result: Err(nvfs_err_internal!()),
                        });
                    }
                };
                let pending_transactions_allocs = &pending_transactions_sync_state.pending_allocs;
                let fs_sync_state = *aux_data;
                let empty_pending_frees = alloc_bitmap::SparseAllocBitmap::new();
                // Do not repurpose pending frees if allocating for the journal.
                let transaction_pending_frees = if *for_journal {
                    &empty_pending_frees
                } else {
                    &transaction.allocs.pending_frees
                };

                let pending_allocs = [
                    &transaction.allocs.pending_allocs,
                    &transaction.allocs.journal_allocs,
                    pending_transactions_allocs,
                ];
                let pending_allocs = alloc_bitmap::SparseAllocBitmapUnion::new(&pending_allocs);
                let pending_frees = [transaction_pending_frees];
                let pending_frees = alloc_bitmap::SparseAllocBitmapUnion::new(&pending_frees);

                let result = fs_sync_state.alloc_bitmap.find_free_block(
                    *block_allocation_blocks_log2,
                    None,
                    &pending_allocs,
                    &pending_frees,
                    fs_sync_state.image_size,
                    None,
                    true,
                );
                let result = match result {
                    Some(allocated_block) => {
                        if let Err(e) = pending_transactions_sync_state.register_allocated_block(
                            fs_sync_state,
                            allocated_block,
                            *block_allocation_blocks_log2,
                        ) {
                            Err(e)
                        } else if let Err(e) = if *for_journal {
                            &mut transaction.allocs.journal_allocs
                        } else {
                            &mut transaction.allocs.pending_allocs
                        }
                        .add_block(allocated_block, *block_allocation_blocks_log2)
                        {
                            pending_transactions_sync_state.deregister_allocated_block(
                                fs_sync_state,
                                allocated_block,
                                *block_allocation_blocks_log2,
                            );
                            Err(e)
                        } else {
                            transaction
                                .allocs
                                .pending_frees
                                .remove_block(allocated_block, *block_allocation_blocks_log2);
                            Ok(allocated_block)
                        }
                    }
                    None => Err(NvFsError::NoSpace),
                };
                *this = Self::Done(marker::PhantomData);
                task::Poll::Ready(PendingTransactionsSyncFutureResult::AllocateBlock {
                    result: Ok((transaction, result)),
                })
            }
            Self::AllocateBlocks {
                transaction,
                block_allocation_blocks_log2,
                count,
                for_journal,
                request_pending_allocs,
                result: allocated_blocks,
            } => {
                let mut transaction = match transaction.take() {
                    Some(transaction) => transaction,
                    None => {
                        *this = Self::Done(marker::PhantomData);
                        return task::Poll::Ready(PendingTransactionsSyncFutureResult::AllocateBlocks {
                            result: Err(nvfs_err_internal!()),
                        });
                    }
                };
                let pending_transactions_allocs = &pending_transactions_sync_state.pending_allocs;
                let fs_sync_state = *aux_data;
                let empty_pending_frees = alloc_bitmap::SparseAllocBitmap::new();
                // Do not repurpose pending frees if allocating for the journal.
                let transaction_pending_frees = if *for_journal {
                    &empty_pending_frees
                } else {
                    &transaction.allocs.pending_frees
                };

                let pending_frees = [transaction_pending_frees];
                let pending_frees = alloc_bitmap::SparseAllocBitmapUnion::new(&pending_frees);

                while allocated_blocks.len() < *count {
                    let pending_allocs = [
                        &transaction.allocs.pending_allocs,
                        &transaction.allocs.journal_allocs,
                        pending_transactions_allocs,
                        request_pending_allocs,
                    ];
                    let pending_allocs = alloc_bitmap::SparseAllocBitmapUnion::new(&pending_allocs);

                    let allocated_block_allocation_blocks_begin = match fs_sync_state.alloc_bitmap.find_free_block(
                        *block_allocation_blocks_log2,
                        None,
                        &pending_allocs,
                        &pending_frees,
                        fs_sync_state.image_size,
                        allocated_blocks.last().copied(),
                        true,
                    ) {
                        Some(allocated_block_allocation_blocks_begin) => allocated_block_allocation_blocks_begin,
                        None => {
                            *this = Self::Done(marker::PhantomData);
                            return task::Poll::Ready(PendingTransactionsSyncFutureResult::AllocateBlocks {
                                result: Err(NvFsError::NoSpace),
                            });
                        }
                    };

                    if let Err(e) = request_pending_allocs
                        .add_block(allocated_block_allocation_blocks_begin, *block_allocation_blocks_log2)
                    {
                        *this = Self::Done(marker::PhantomData);
                        return task::Poll::Ready(PendingTransactionsSyncFutureResult::AllocateBlocks {
                            result: Err(e),
                        });
                    }

                    allocated_blocks.push(allocated_block_allocation_blocks_begin);
                }

                let result = if let Err(e) = pending_transactions_sync_state.register_allocated_blocks(
                    fs_sync_state,
                    allocated_blocks,
                    *block_allocation_blocks_log2,
                ) {
                    Err(e)
                } else if let Err(e) = if *for_journal {
                    &mut transaction.allocs.journal_allocs
                } else {
                    &mut transaction.allocs.pending_allocs
                }
                .add_blocks(allocated_blocks.iter().copied(), *block_allocation_blocks_log2)
                {
                    pending_transactions_sync_state.deregister_allocated_blocks(
                        fs_sync_state,
                        allocated_blocks,
                        *block_allocation_blocks_log2,
                    );
                    Err(e)
                } else {
                    transaction
                        .allocs
                        .pending_frees
                        .remove_blocks(allocated_blocks.iter().copied(), *block_allocation_blocks_log2);
                    Ok(mem::take(allocated_blocks))
                };

                *this = Self::Done(marker::PhantomData);
                task::Poll::Ready(PendingTransactionsSyncFutureResult::AllocateBlocks {
                    result: Ok((transaction, result)),
                })
            }

            Self::Done(_) => unreachable!(),
        }
    }
}

/// Allocate extents on behalf of a transaction at pre-commit time.
///
/// [`CocoonFsAllocateExtentsFuture`] assumes ownership of the
/// [`Transaction`](transaction::Transaction) for the duration of the operation
/// and eventually returns it back from [`poll()`](Self::poll) upon future
/// completion.
///
/// On success, the allocation may get rolled back again by invoking
/// [`Transaction::rollback_extents_allocation()`](transaction::Transaction::rollback_extents_allocation),
/// unless [`reset_rollback()`](transaction::TransactionAllocations::reset_rollback) has been called
/// on [`Transaction::allocs`](transaction::Transaction::allocs) in the
/// meanwhile. Maintaing the ability to rollback incurs some memory overhead
/// though, so
/// [`reset_rollback()`](transaction::TransactionAllocations::reset_rollback)
/// should get invoked once its no longer needed.
pub(super) struct CocoonFsAllocateExtentsFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    pending_transactions_sync_state_fut: QueuedPendingTransactionsSyncFuture<ST, C>,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsAllocateExtentsFuture<ST, C> {
    /// Instantiate a [`CocoonFsAllocateExtentsFuture`].
    ///
    /// On success, the new [`CocoonFsAllocateExtentsFuture`] instance will get
    /// returned.
    ///
    /// On failure, a pair of the input `transaction` (if not lost due to an
    /// internal error) and the error reason will get returned.
    ///
    /// # Arguments:
    ///
    /// * `fs_instance` - The [`CocoonFs`] instance.
    /// * `transaction` - The [`Transaction`](transaction::Transaction) on whose
    ///   behalf to allocate. Will get returned back from [`poll()`](Self::poll)
    ///   upon future completion.
    /// * `request` - The allocation request.
    /// * `for_journal` - Whether or not the allocation is for the journal.
    pub fn new(
        fs_instance: &CocoonFsSyncRcPtrRefType<ST, C>,
        transaction: Box<transaction::Transaction>,
        request: alloc_bitmap::ExtentsAllocationRequest,
        for_journal: bool,
    ) -> Result<Self, (Option<Box<transaction::Transaction>>, NvFsError)> {
        let pending_transactions_sync_state_fut = asynchronous::FutureQueue::enqueue(
            CocoonFs::get_pending_transactions_sync_state_ref(fs_instance).make_clone(),
            PendingTransactionsSyncFuture::AllocateExtents {
                transaction: Some(transaction),
                request,
                for_journal,
            },
        )
        .map_err(|(f, e)| {
            (
                f.into_transaction(),
                match e {
                    asynchronous::FutureQueueError::MemoryAllocationFailure => NvFsError::MemoryAllocationFailure,
                },
            )
        })?;

        Ok(Self {
            pending_transactions_sync_state_fut,
        })
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsSyncStateReadFuture<ST, C>
    for CocoonFsAllocateExtentsFuture<ST, C>
{
    /// Output type of [`poll()`](Self::poll).
    ///
    /// A two-level result is returned upon
    /// [future](CocoonFsSyncStateReadFuture) completion.
    ///
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering an internal error and the
    ///   [`Transaction`](transaction::Transaction) is lost.
    /// * `Ok((transaction, ...))` - Otherwise the outer level [`Result`] is set
    ///   to [`Ok`] and a pair of the input
    ///   `Transaction`](transaction::Transaction) and the operation result will
    ///   get returned within:
    ///   * `Ok((transaction, Ok((extents, excess)))` - The allocation was
    ///     successful, the `extents` had been allocated with an excess payload
    ///     length of `excess` over the originally requested one.
    ///   * `Ok((transaction, Err(e))` - The allocation failed with error `e`.
    type Output = Result<
        (
            Box<transaction::Transaction>,
            Result<(extents::PhysicalExtents, u64), NvFsError>,
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
        let mut aux_poll_data = &*fs_instance_sync_state;
        match this.pending_transactions_sync_state_fut.poll(&mut aux_poll_data, cx) {
            task::Poll::Ready(r) => {
                match r {
                    PendingTransactionsSyncFutureResult::AllocateExtents { result } => task::Poll::Ready(result),
                    _ => {
                        // Cannot happen, it's expected that the future result variant
                        // matches the original future variant.
                        task::Poll::Ready(Err(nvfs_err_internal!()))
                    }
                }
            }
            task::Poll::Pending => task::Poll::Pending,
        }
    }
}

/// Allocate a block on behalf of a transaction at pre-commit time.
///
/// [`CocoonFsAllocateBlockFuture`] assumes ownership of the
/// [`Transaction`](transaction::Transaction) for the duration of the operation
/// and returns it back  from [`poll()`](Self::poll) upon future completion.
///
/// On success, the allocation may get rolled back again by invoking
/// [`Transaction::rollback_block_allocation()`](transaction::Transaction::rollback_block_allocation),
/// unless [`reset_rollback()`](transaction::TransactionAllocations::reset_rollback) has been called
/// on [`Transaction::allocs`](transaction::Transaction::allocs) in the
/// meanwhile. Maintaing the ability to rollback incurs some memory overhead
/// though, so
/// [`reset_rollback()`](transaction::TransactionAllocations::reset_rollback)
/// should get invoked once its no longer needed.
pub(super) struct CocoonFsAllocateBlockFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    pending_transactions_sync_state_fut: QueuedPendingTransactionsSyncFuture<ST, C>,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsAllocateBlockFuture<ST, C> {
    /// Instantiate a [`CocoonFsAllocateBlockFuture`].
    ///
    /// On success, the new [`CocoonFsAllocateBlockFuture`] instance will get
    /// returned.
    ///
    /// On failure, a pair of the input `transaction` (if not lost due to an
    /// internal error) and the error reason will get returned.
    ///
    /// # Arguments:
    ///
    /// * `fs_instance` - The [`CocoonFs`] instance.
    /// * `transaction` - The [`Transaction`](transaction::Transaction) on whose
    ///   behalf to allocate. Will get returned from [`poll()`](Self::poll) upon
    ///   future completion.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the desired block
    ///   size in units of [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    /// * `for_journal` - Whether or not the allocation is for the journal.
    pub fn new(
        fs_instance: &CocoonFsSyncRcPtrRefType<ST, C>,
        transaction: Box<transaction::Transaction>,
        block_allocation_blocks_log2: u32,
        for_journal: bool,
    ) -> Result<Self, (Option<Box<transaction::Transaction>>, NvFsError)> {
        let pending_transactions_sync_state_fut = asynchronous::FutureQueue::enqueue(
            CocoonFs::get_pending_transactions_sync_state_ref(fs_instance).make_clone(),
            PendingTransactionsSyncFuture::AllocateBlock {
                transaction: Some(transaction),
                block_allocation_blocks_log2,
                for_journal,
            },
        )
        .map_err(|(f, e)| {
            (
                f.into_transaction(),
                match e {
                    asynchronous::FutureQueueError::MemoryAllocationFailure => NvFsError::MemoryAllocationFailure,
                },
            )
        })?;

        Ok(Self {
            pending_transactions_sync_state_fut,
        })
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsSyncStateReadFuture<ST, C>
    for CocoonFsAllocateBlockFuture<ST, C>
{
    /// Output type of [`poll()`](Self::poll).
    ///
    /// A two-level result is returned upon
    /// [future](CocoonFsSyncStateReadFuture) completion.
    ///
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering an internal error and the
    ///   [`Transaction`](transaction::Transaction) is lost.
    /// * `Ok((transaction, ...))` - Otherwise the outer level [`Result`] is set
    ///   to [`Ok`] and a pair of the input
    ///   `Transaction`](transaction::Transaction) and the operation result will
    ///   get returned within:
    ///   * `Ok((transaction, Ok(block_allocation_blocks_begin))` - The
    ///     allocation was successful, the block starting at
    ///     `block_allocation_blocks_begin` had been allocated.
    ///   * `Ok((transaction, Err(e))` - The allocation failed with error `e`.
    type Output = Result<
        (
            Box<transaction::Transaction>,
            Result<layout::PhysicalAllocBlockIndex, NvFsError>,
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
        let mut aux_poll_data = &*fs_instance_sync_state;
        match this.pending_transactions_sync_state_fut.poll(&mut aux_poll_data, cx) {
            task::Poll::Ready(r) => {
                match r {
                    PendingTransactionsSyncFutureResult::AllocateBlock { result } => task::Poll::Ready(result),
                    _ => {
                        // Cannot happen, it's expected that the future result variant
                        // matches the original future variant.
                        task::Poll::Ready(Err(nvfs_err_internal!()))
                    }
                }
            }
            task::Poll::Pending => task::Poll::Pending,
        }
    }
}

/// Allocate a specified number of blocks on behalf of a transaction at
/// pre-commit time.
///
/// [`CocoonFsAllocateBlocksFuture`] assumes ownership of the
/// [`Transaction`](transaction::Transaction) for the duration of the operation
/// and returns it back from [`poll()`](Self::poll) upon future completion.
///
/// On success, the allocation may get rolled back again by invoking
/// [`Transaction::rollback_blocks_allocation()`](transaction::Transaction::rollback_blocks_allocation),
/// unless [`reset_rollback()`](transaction::TransactionAllocations::reset_rollback) has been called
/// on [`Transaction::allocs`](transaction::Transaction::allocs) in the
/// meanwhile. Maintaing the ability to rollback incurs some memory overhead
/// though, so
/// [`reset_rollback()`](transaction::TransactionAllocations::reset_rollback)
/// should get invoked once its no longer needed.
pub(super) struct CocoonFsAllocateBlocksFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    pending_transactions_sync_state_fut: QueuedPendingTransactionsSyncFuture<ST, C>,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsAllocateBlocksFuture<ST, C> {
    /// Instantiate a [`CocoonFsAllocateBlocksFuture`].
    ///
    /// On success, the new [`CocoonFsAllocateBlockFuture`] instance will get
    /// returned.
    ///
    /// On failure, a pair of the input `transaction` (if not lost due to an
    /// internal error) and the error reason will get returned.
    ///
    /// # Arguments:
    ///
    /// * `fs_instance` - The [`CocoonFs`] instance.
    /// * `transaction` - The [`Transaction`](transaction::Transaction) on whose
    ///   behalf to allocate. Will get returned back from [`poll()`](Self::poll)
    ///   upon future completion.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the desired block
    ///   size in units of [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    /// * `count` - The number of blocks to allocate.
    /// * `for_journal` - Whether or not the allocation is for the journal.
    pub fn new(
        fs_instance: &CocoonFsSyncRcPtrRefType<ST, C>,
        transaction: Box<transaction::Transaction>,
        block_allocation_blocks_log2: u32,
        count: usize,
        for_journal: bool,
    ) -> Result<Self, (Option<Box<transaction::Transaction>>, NvFsError)> {
        let mut result = Vec::new();
        if let Err(e) = result.try_reserve_exact(count) {
            return Err((Some(transaction), NvFsError::from(e)));
        }
        let pending_transactions_sync_state_fut = asynchronous::FutureQueue::enqueue(
            CocoonFs::get_pending_transactions_sync_state_ref(fs_instance).make_clone(),
            PendingTransactionsSyncFuture::AllocateBlocks {
                transaction: Some(transaction),
                block_allocation_blocks_log2,
                count,
                for_journal,
                request_pending_allocs: alloc_bitmap::SparseAllocBitmap::new(),
                result,
            },
        )
        .map_err(|(f, e)| {
            (
                f.into_transaction(),
                match e {
                    asynchronous::FutureQueueError::MemoryAllocationFailure => NvFsError::MemoryAllocationFailure,
                },
            )
        })?;

        Ok(Self {
            pending_transactions_sync_state_fut,
        })
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsSyncStateReadFuture<ST, C>
    for CocoonFsAllocateBlocksFuture<ST, C>
{
    /// Output type of [`poll()`](Self::poll).
    ///
    /// A two-level result is returned upon
    /// [future](CocoonFsSyncStateReadFuture) completion.
    ///
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering an internal error and the
    ///   [`Transaction`](transaction::Transaction) is lost.
    /// * `Ok((transaction, ...))` - Otherwise the outer level [`Result`] is set
    ///   to [`Ok`] and a pair of the input
    ///   `Transaction`](transaction::Transaction) and the operation result will
    ///   get returned within:
    ///   * `Ok((transaction, Ok(blocks_allocation_blocks_begin))` - The
    ///     allocation was successful, the blocks starting at the location found
    ///     in the respective `blocks_allocation_blocks_begin` entries had been
    ///     allocated.
    ///   * `Ok((transaction, Err(e))` - The allocation failed with error `e`.
    type Output = Result<
        (
            Box<transaction::Transaction>,
            Result<Vec<layout::PhysicalAllocBlockIndex>, NvFsError>,
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
        let mut aux_poll_data = &*fs_instance_sync_state;
        match this.pending_transactions_sync_state_fut.poll(&mut aux_poll_data, cx) {
            task::Poll::Ready(r) => {
                match r {
                    PendingTransactionsSyncFutureResult::AllocateBlocks { result } => task::Poll::Ready(result),
                    _ => {
                        // Cannot happen, it's expected that the future result variant
                        // matches the original future variant.
                        task::Poll::Ready(Err(nvfs_err_internal!()))
                    }
                }
            }
            task::Poll::Pending => task::Poll::Pending,
        }
    }
}
