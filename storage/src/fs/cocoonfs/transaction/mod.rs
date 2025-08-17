// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`Transaction`].

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

use crate::{
    chip,
    crypto::rng,
    fs::{
        NvFsError,
        cocoonfs::{
            alloc_bitmap, auth_tree, extents,
            fs::{CocoonFsPendingTransactionsSyncState, CocoonFsSyncStateMemberRef},
            inode_index, journal, layout,
        },
    },
    utils_async::sync_types,
};

use core::marker;

pub(super) mod auth_tree_data_blocks_update_states;
pub use auth_tree_data_blocks_update_states::AuthTreeDataBlocksUpdateStates;
mod prepare_staged_updates_application;
pub(super) use prepare_staged_updates_application::TransactionPrepareStagedUpdatesApplicationFuture;
mod apply_journal;
mod auth_tree_updates;
mod cleanup;
mod journal_allocations;
pub(super) mod read_authenticate_data;
mod read_missing_data;
mod write_dirty_data;
mod write_journal;

#[cfg(doc)]
use crate::fs::cocoonfs::fs::CocoonFs;
#[cfg(doc)]
use auth_tree_data_blocks_update_states::AllocationBlockUpdateStagedUpdate;
#[cfg(doc)]
use layout::ImageLayout;

/// Internal representation of a pending transaction.
pub struct Transaction {
    /// Pending updates to data on storage.
    pub(super) auth_tree_data_blocks_update_states: AuthTreeDataBlocksUpdateStates,

    /// The [random number generator](rng::RngCoreDispatchable) used
    /// by the transaction for initializing unallocated stoage, unused padding
    /// and for generating IVs.
    pub(super) rng: Box<dyn rng::RngCoreDispatchable + marker::Send>,

    /// Optional journal staging copy disguising.
    ///
    /// If `None`, journal staging copy disguising is disabled, otherwise
    /// the `Some` wraps a pair of an
    /// [`JournalStagingCopyDisguise`](journal::staging_copy_disguise::JournalStagingCopyDisguise)
    /// instance alongside its associated, lazily instantiated
    /// [`JournalStagingCopyUndisguise`](journal::staging_copy_disguise::JournalStagingCopyUndisguise).
    pub(super) journal_staging_copy_disguise: Option<(
        journal::staging_copy_disguise::JournalStagingCopyDisguise,
        Option<journal::staging_copy_disguise::JournalStagingCopyUndisguise>,
    )>,

    /// Verbatim value of [`ImageLayout::allocation_block_size_128b_log2`].
    allocation_block_size_128b_log2: u8,
    /// Verbatim value of
    /// [`ImageLayout::auth_tree_data_block_allocation_blocks_log2`].
    auth_tree_data_block_allocation_blocks_log2: u8,
    /// Verbatim value of [`ImageLayout::io_block_allocation_blocks_log2`].
    io_block_allocation_blocks_log2: u8,
    /// Cached value of
    /// [NvChip::chip_io_block_size_128b_log2()](chip::NvChip::chip_io_block_size_128b_log2).
    chip_io_block_size_128b_log2: u32,
    /// Cached value of
    /// [NvChip::preferred_chip_io_blocks_bulk_log2()](chip::NvChip::preferred_chip_io_blocks_bulk_log2).
    preferred_chip_io_blocks_bulk_log2: u32,

    /// Allocations and deallocations staged on behalf of the [`Transaction`].
    pub(super) allocs: TransactionAllocations,

    /// List of recollected abandoned journal staging copy blocks.
    ///
    /// Collection of blocks, all equal to the larger of the [Authentication
    /// Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) and the
    /// [IO Block](ImageLayout::io_block_allocation_blocks_log2) size,
    /// identified by their respective beginning on storage.
    abandoned_journal_staging_copy_blocks: Vec<layout::PhysicalAllocBlockIndex>,

    /// Whether the [`Transaction`] has been elected as the primary one among
    /// the pending.
    ///
    /// The primary [`Transaction`] has more freedom regarding in-place writes.
    pub(super) is_primary_pending: bool,

    /// State transferred from [`CocoonFs::pending_transactions_sync_state`]
    /// upon [`Transaction`] commit.
    accumulated_fs_instance_pending_transactions_sync_state: CocoonFsPendingTransactionsSyncState,

    /// Updates to the inode index staged at the [`Transaction`].
    pub(super) inode_index_updates: inode_index::TransactionInodeIndexUpdates,

    /// Pending updates to the authentication tree.
    ///
    /// Populated at [`Transaction`] commit and applied to the authentication
    /// tree once the journal has been written.
    pending_auth_tree_updates: TransactionPendingAuthTreeUpdates,

    /// The extents allocated to the journal log's chained encrypted extents'
    /// tail.
    ///
    /// Comprises all the journal log's extents but the head stored at the
    /// fixed, well-known location.
    journal_log_tail_extents: extents::PhysicalExtents,

    /// Whether to fail the online journal application.
    ///
    /// Used for testing journal replay.
    #[cfg(test)]
    pub(super) test_fail_apply_journal: bool,
}

impl Transaction {
    /// Instantiate a new [`Transaction`].
    ///
    /// # Arguments:
    ///
    /// * `fs_instance_sync_state` - Reference to [`CocoonFs::sync_state`].
    /// * `is_primary_pending` - Whether the [`Transaction`] is the primary one
    ///   among the pending. There must be at most one pending with this
    ///   attribute at any time.
    /// * `rng` - The [random number generator](rng::RngCoreDispatchable) used
    ///   by the transaction for initializing unallocated stoage, unused padding
    ///   and for generating IVs.
    pub fn new<ST: sync_types::SyncTypes, C: chip::NvChip>(
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, C>,
        is_primary_pending: bool,
        mut rng: Box<dyn rng::RngCoreDispatchable + marker::Send>,
    ) -> Result<Self, NvFsError> {
        let fs_instance = fs_instance_sync_state.get_fs_ref();
        let image_layout = &fs_instance.fs_config.image_layout;
        let journal_staging_copy_disguise = journal::staging_copy_disguise::JournalStagingCopyDisguise::generate(
            image_layout.block_cipher_alg,
            rng.as_mut(),
        )?;

        let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2;
        let auth_tree_data_block_allocation_blocks_log2 = image_layout.auth_tree_data_block_allocation_blocks_log2;
        let io_block_allocation_blocks_log2 = image_layout.io_block_allocation_blocks_log2;
        let chip = &fs_instance.chip;
        let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();
        let preferred_chip_io_blocks_bulk_log2 = chip.preferred_chip_io_blocks_bulk_log2();

        Ok(Self {
            auth_tree_data_blocks_update_states: AuthTreeDataBlocksUpdateStates::new(
                io_block_allocation_blocks_log2,
                auth_tree_data_block_allocation_blocks_log2,
                allocation_block_size_128b_log2,
            ),
            rng,
            journal_staging_copy_disguise: Some((journal_staging_copy_disguise, None)),
            allocation_block_size_128b_log2,
            auth_tree_data_block_allocation_blocks_log2,
            io_block_allocation_blocks_log2,
            chip_io_block_size_128b_log2,
            preferred_chip_io_blocks_bulk_log2,
            allocs: TransactionAllocations::new(),
            abandoned_journal_staging_copy_blocks: Vec::new(),
            is_primary_pending,
            accumulated_fs_instance_pending_transactions_sync_state: CocoonFsPendingTransactionsSyncState::new(),
            inode_index_updates: inode_index::TransactionInodeIndexUpdates::new(&fs_instance_sync_state.inode_index),
            pending_auth_tree_updates: TransactionPendingAuthTreeUpdates::new(),
            journal_log_tail_extents: extents::PhysicalExtents::new(),
            #[cfg(test)]
            test_fail_apply_journal: false,
        })
    }

    /// Deallocate a power-of-two sized, aligned block.
    ///
    /// Mark the block identified by `block_allocation_blocks_begin` and of size
    /// as determined by `block_allocation_blocks_log2` as freed at
    /// [`Transaction::allocs`] and move any of the
    /// existing [`Transaction::auth_tree_data_blocks_update_states`]'
    /// [Allocation Block level
    /// entries](auth_tree_data_blocks_update_states::AllocationBlockUpdateState) overlapping with
    /// it to the [`AllocationBlockUpdateStagedUpdate::Deallocate`] staged
    /// update state.
    ///
    /// The changes made to [`Transaction::allocs`] may get [rolled
    /// back](Self::rollback_block_free) again unless
    /// [`TransactionAllocations::reset_rollback()`] has been invoked on it. Any
    /// data updates previously staged however cannot be recovered. They
    /// need to [get
    /// applied](AuthTreeDataBlocksUpdateStates::apply_allocation_blocks_staged_updates) first
    /// before the deallocation should that be needed.  Note that the ability to
    /// rollback comes at some additional memory overhead, so users should
    /// invoke [`TransactionAllocations::reset_rollback()`] on
    /// [`Transaction::allocs`] once it's not longer needed.
    ///
    /// # Arguments:
    ///
    /// * `transaction_allocs` - `mut` reference to [`Transaction::allocs`].
    /// * `transaction_updates_states` - `mut` reference to
    ///   [`Transaction::auth_tree_data_blocks_update_states`].
    /// * `block_allocation_blocks_begin` - Beginning of the block on storage.
    ///   Must be aligned to the size as determined by
    ///   `block_allocation_blocks_log2`.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size in
    ///   units of [Allocation
    ///   Blocks](ImageLayout::allocation_block_size_128b_log2).
    pub fn free_block(
        transaction_allocs: &mut TransactionAllocations,
        transaction_updates_states: &mut AuthTreeDataBlocksUpdateStates,
        block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        block_allocation_blocks_log2: u32,
    ) -> Result<(), NvFsError> {
        transaction_allocs
            .pending_frees
            .add_block(block_allocation_blocks_begin, block_allocation_blocks_log2)?;
        transaction_allocs
            .pending_allocs
            .remove_block(block_allocation_blocks_begin, block_allocation_blocks_log2);
        transaction_updates_states
            .stage_block_deallocation_updates(block_allocation_blocks_begin, block_allocation_blocks_log2);
        Ok(())
    }

    /// Deallocate some power-of-two sized, aligned blocks.
    ///
    /// Mark the blocks at the locations obtained from
    /// `blocks_allocation_blocks_begin_iter` and of size as determined by
    /// `block_allocation_blocks_log2` each as freed at
    /// [`Transaction::allocs`] and move any of the existing
    /// [`Transaction::auth_tree_data_blocks_update_states`]' [Allocation Block
    /// level
    /// entries](auth_tree_data_blocks_update_states::AllocationBlockUpdateState) overlapping with
    /// them to the [`AllocationBlockUpdateStagedUpdate::Deallocate`] staged
    /// update state.
    ///
    /// The changes made to [`Transaction::allocs`] may get [rolled
    /// back](Self::rollback_blocks_free) again unless
    /// [`TransactionAllocations::reset_rollback()`] has been invoked on it.
    /// Any data updates previously staged however cannot be recovered. They
    /// need to [get
    /// applied](AuthTreeDataBlocksUpdateStates::apply_allocation_blocks_staged_updates) first
    /// before the deallocation should that be needed.
    ///
    /// # Arguments:
    ///
    /// * `transaction_allocs` - `mut` reference to [`Transaction::allocs`].
    /// * `transaction_updates_states` - `mut` reference to
    ///   [`Transaction::auth_tree_data_blocks_update_states`].
    /// * `block_allocation_blocks_begin_iter` - Iterator over the blocks'
    ///   beginnings of the block on storage each. Must be aligned to the size
    ///   as determined by `block_allocation_blocks_log2`.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size in
    ///   units of [Allocation
    ///   Blocks](ImageLayout::allocation_block_size_128b_log2).
    #[allow(dead_code)]
    pub fn free_blocks<BI: Iterator<Item = layout::PhysicalAllocBlockIndex> + Clone>(
        transaction_allocs: &mut TransactionAllocations,
        transaction_updates_states: &mut AuthTreeDataBlocksUpdateStates,
        blocks_allocation_blocks_begin_iter: BI,
        block_allocation_blocks_log2: u32,
    ) -> Result<(), NvFsError> {
        transaction_allocs.pending_frees.add_blocks(
            blocks_allocation_blocks_begin_iter.clone(),
            block_allocation_blocks_log2,
        )?;
        transaction_allocs.pending_allocs.remove_blocks(
            blocks_allocation_blocks_begin_iter.clone(),
            block_allocation_blocks_log2,
        );
        transaction_updates_states
            .stage_blocks_deallocation_updates(blocks_allocation_blocks_begin_iter, block_allocation_blocks_log2);
        Ok(())
    }

    /// Deallocate some storage extents.
    ///
    /// Mark the extents obtained from `extents_iter` as freed at
    /// [`Transaction::allocs`] and move any of the existing
    /// [`Transaction::auth_tree_data_blocks_update_states`]' [Allocation Block
    /// level entries](auth_tree_data_blocks_update_states::AllocationBlockUpdateState) overlapping
    /// with them to the [`AllocationBlockUpdateStagedUpdate::Deallocate`]
    /// staged update state.
    ///
    /// The changes made to [`Transaction::allocs`] may get [rolled
    /// back](Self::rollback_extents_free) again unless
    /// [`TransactionAllocations::reset_rollback()`] has been invoked on it.
    /// Any data updates previously staged however cannot be recovered. They
    /// need to [get
    /// applied](AuthTreeDataBlocksUpdateStates::apply_allocation_blocks_staged_updates) first
    /// before the deallocation should that be needed.
    ///
    /// # Arguments:
    ///
    /// * `transaction_allocs` - `mut` reference to [`Transaction::allocs`].
    /// * `transaction_updates_states` - `mut` reference to
    ///   [`Transaction::auth_tree_data_blocks_update_states`].
    /// * `extents_iter` - Iterator over the extents.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size in
    ///   units of [Allocation
    ///   Blocks](ImageLayout::allocation_block_size_128b_log2).
    pub fn free_extents<EI: Iterator<Item = layout::PhysicalAllocBlockRange> + Clone>(
        transaction_allocs: &mut TransactionAllocations,
        transaction_updates_states: &mut AuthTreeDataBlocksUpdateStates,
        extents_iter: EI,
    ) -> Result<(), NvFsError> {
        transaction_allocs.pending_frees.add_extents(extents_iter.clone())?;
        transaction_allocs.pending_allocs.remove_extents(extents_iter.clone());
        transaction_updates_states.stage_extents_deallocation_updates(extents_iter);
        Ok(())
    }

    /// Rollback the allocation of a power-of-two sized, aligned block.
    ///
    /// Rollback the allocation of the block identified by
    /// `block_allocation_blocks_begin` and of size as determined by
    /// `block_allocation_blocks_log2` at [`Transaction::allocs`] and move any
    /// of the existing [`Transaction::auth_tree_data_blocks_update_states`]'
    /// [Allocation Block
    /// level entries](auth_tree_data_blocks_update_states::AllocationBlockUpdateState) overlapping
    /// with it to the [`AllocationBlockUpdateStagedUpdate::Deallocate`] staged
    /// update state.
    ///
    /// Must get invoked only if [`TransactionAllocations::reset_rollback()`]
    /// has not been invoked on [`Transaction::allocs`] since the allocation,
    /// and is failsafe then.
    ///
    /// # Arguments:
    ///
    /// * `block_allocation_blocks_begin` - Beginning of the block on storage.
    ///   Must be aligned to the size as determined by
    ///   `block_allocation_blocks_log2`.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size in
    ///   units of [Allocation
    ///   Blocks](ImageLayout::allocation_block_size_128b_log2).
    /// * `alloc_bitmap` - The filesystem's
    ///   [`AllocBitmap`](alloc_bitmap::AllocBitmap) in the state from before
    ///   the [`Transaction`].
    pub fn rollback_block_allocation(
        mut self: Box<Self>,
        block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        block_allocation_blocks_log2: u32,
        alloc_bitmap: &alloc_bitmap::AllocBitmap,
    ) -> Result<Box<Self>, NvFsError> {
        self.allocs
            .pending_allocs
            .remove_block(block_allocation_blocks_begin, block_allocation_blocks_log2);
        // If something had been allocated, it must have been free before.
        self.allocs.pending_frees.rollback_remove_block(
            block_allocation_blocks_begin,
            block_allocation_blocks_log2,
            alloc_bitmap,
            false,
        )?;

        self.auth_tree_data_blocks_update_states
            .stage_block_deallocation_updates(block_allocation_blocks_begin, block_allocation_blocks_log2);

        Ok(self)
    }

    /// Rollback the deallocation of a power-of-two sized, aligned block.
    ///
    /// Rollback the deallocation of the block identified by
    /// `block_allocation_blocks_begin` and of size as determined by
    /// `block_allocation_blocks_log2` at [`Transaction::allocs`] and reset
    /// any updates staged at the
    /// [`Transaction::auth_tree_data_blocks_update_states`]' [Allocation Block
    /// level entries](auth_tree_data_blocks_update_states::AllocationBlockUpdateState)
    /// overlapping with it.
    ///
    /// Must get invoked only if [`TransactionAllocations::reset_rollback()`]
    /// has not been invoked on [`Transaction::allocs`] since the deallocation,
    /// and is failsafe then.
    ///
    /// # Arguments:
    ///
    /// * `block_allocation_blocks_begin` - Beginning of the block on storage.
    ///   Must be aligned to the size as determined by
    ///   `block_allocation_blocks_log2`.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size in
    ///   units of [Allocation
    ///   Blocks](ImageLayout::allocation_block_size_128b_log2).
    /// * `alloc_bitmap` - The filesystem's
    ///   [`AllocBitmap`](alloc_bitmap::AllocBitmap) in the state from before
    ///   the [`Transaction`].
    pub fn rollback_block_free(
        mut self: Box<Self>,
        block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        block_allocation_blocks_log2: u32,
        alloc_bitmap: &alloc_bitmap::AllocBitmap,
    ) -> Result<Box<Self>, NvFsError> {
        self.allocs
            .pending_frees
            .remove_block(block_allocation_blocks_begin, block_allocation_blocks_log2);
        // If something had been freed, it must have been allocated before.
        self.allocs.pending_allocs.rollback_remove_block(
            block_allocation_blocks_begin,
            block_allocation_blocks_log2,
            alloc_bitmap,
            true,
        )?;

        self.auth_tree_data_blocks_update_states
            .reset_staged_block_updates(block_allocation_blocks_begin, block_allocation_blocks_log2);

        Ok(self)
    }

    /// Rollback the allocation of some power-of-two sized, aligned blocks.
    ///
    /// Rollback the allocation of the blocks at the locations obtained from
    /// `blocks_allocation_blocks_begin_iter` and of size as determined by
    /// `block_allocation_blocks_log2` each at [`Transaction::allocs`] and move
    /// any of the existing
    /// [`Transaction::auth_tree_data_blocks_update_states`]' [Allocation Block
    /// level
    /// entries](auth_tree_data_blocks_update_states::AllocationBlockUpdateState) overlapping with
    /// them to the [`AllocationBlockUpdateStagedUpdate::Deallocate`] staged
    /// update state.
    ///
    /// Must get invoked only if [`TransactionAllocations::reset_rollback()`]
    /// has not been invoked on [`Transaction::allocs`] since the allocation,
    /// and is failsafe then.
    ///
    /// # Arguments:
    ///
    /// * `block_allocation_blocks_begin_iter` - Iterator over the blocks'
    ///   beginnings of the block on storage each. Must be aligned to the size
    ///   as determined by `block_allocation_blocks_log2`.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size in
    ///   units of [Allocation
    ///   Blocks](ImageLayout::allocation_block_size_128b_log2).
    /// * `alloc_bitmap` - The filesystem's
    ///   [`AllocBitmap`](alloc_bitmap::AllocBitmap) in the state from before
    ///   the [`Transaction`].
    pub fn rollback_blocks_allocation<BI: Iterator<Item = layout::PhysicalAllocBlockIndex> + Clone>(
        mut self: Box<Self>,
        blocks_allocation_blocks_begin_iter: BI,
        block_allocation_blocks_log2: u32,
        alloc_bitmap: &alloc_bitmap::AllocBitmap,
    ) -> Result<Box<Self>, NvFsError> {
        self.allocs.pending_allocs.remove_blocks(
            blocks_allocation_blocks_begin_iter.clone(),
            block_allocation_blocks_log2,
        );
        // If something had been allocated, it must have been free before.
        self.allocs.pending_frees.rollback_remove_blocks(
            blocks_allocation_blocks_begin_iter.clone(),
            block_allocation_blocks_log2,
            alloc_bitmap,
            false,
        )?;

        self.auth_tree_data_blocks_update_states
            .stage_blocks_deallocation_updates(blocks_allocation_blocks_begin_iter, block_allocation_blocks_log2);

        Ok(self)
    }

    /// Rollback the deallocation of some power-of-two sized, aligned blocks.
    ///
    /// Rollback the deallocation of the blocks at the locations obtained from
    /// `blocks_allocation_blocks_begin_iter` and of size as determined by
    /// `block_allocation_blocks_log2` each at [`Transaction::allocs`] and reset
    /// any updates staged at the
    /// [`Transaction::auth_tree_data_blocks_update_states`]' [Allocation Block
    /// level entries](auth_tree_data_blocks_update_states::AllocationBlockUpdateState)
    /// overlapping with them.
    ///
    /// Must get invoked only if [`TransactionAllocations::reset_rollback()`]
    /// has not been invoked on [`Transaction::allocs`] since the allocation,
    /// and is failsafe then.
    ///
    /// # Arguments:
    ///
    /// * `block_allocation_blocks_begin_iter` - Iterator over the blocks'
    ///   beginnings of the block on storage each. Must all be aligned to the
    ///   size as determined by `block_allocation_blocks_log2`.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size in
    ///   units of [Allocation
    ///   Blocks](ImageLayout::allocation_block_size_128b_log2).
    /// * `alloc_bitmap` - The filesystem's
    ///   [`AllocBitmap`](alloc_bitmap::AllocBitmap) in the state from before
    ///   the [`Transaction`].
    #[allow(dead_code)]
    pub fn rollback_blocks_free<BI: Iterator<Item = layout::PhysicalAllocBlockIndex> + Clone>(
        mut self: Box<Self>,
        blocks_allocation_blocks_begin_iter: BI,
        block_allocation_blocks_log2: u32,
        alloc_bitmap: &alloc_bitmap::AllocBitmap,
    ) -> Result<Box<Self>, NvFsError> {
        self.allocs.pending_frees.remove_blocks(
            blocks_allocation_blocks_begin_iter.clone(),
            block_allocation_blocks_log2,
        );
        // If something had been freed, it must have been allocated before.
        self.allocs.pending_allocs.rollback_remove_blocks(
            blocks_allocation_blocks_begin_iter.clone(),
            block_allocation_blocks_log2,
            alloc_bitmap,
            true,
        )?;

        self.auth_tree_data_blocks_update_states
            .reset_staged_blocks_updates(blocks_allocation_blocks_begin_iter, block_allocation_blocks_log2);

        Ok(self)
    }

    /// Rollback the allocation of some extents.
    ///
    /// Rollback the allocation of the extents obtained from `extents_iter` at
    /// [`Transaction::allocs`] and move any of the existing
    /// [`Transaction::auth_tree_data_blocks_update_states`]' [Allocation Block
    /// level
    /// entries](auth_tree_data_blocks_update_states::AllocationBlockUpdateState) overlapping with
    /// them to the [`AllocationBlockUpdateStagedUpdate::Deallocate`] staged
    /// update state.
    ///
    /// Must get invoked only if [`TransactionAllocations::reset_rollback()`]
    /// has not been invoked on [`Transaction::allocs`] since the allocation,
    /// and is failsafe then.
    ///
    /// # Arguments:
    ///
    /// * `extents_iter` - Iterator over the extents.
    /// * `alloc_bitmap` - The filesystem's
    ///   [`AllocBitmap`](alloc_bitmap::AllocBitmap) in the state from before
    ///   the [`Transaction`].
    pub fn rollback_extents_allocation<EI: Iterator<Item = layout::PhysicalAllocBlockRange> + Clone>(
        mut self: Box<Self>,
        extents_iter: EI,
        alloc_bitmap: &alloc_bitmap::AllocBitmap,
    ) -> Result<Box<Self>, NvFsError> {
        self.allocs.pending_allocs.remove_extents(extents_iter.clone());
        // If something had been allocated, it must have been free before.
        self.allocs
            .pending_frees
            .rollback_remove_extents(extents_iter.clone(), alloc_bitmap, false)?;

        self.auth_tree_data_blocks_update_states
            .stage_extents_deallocation_updates(extents_iter);

        Ok(self)
    }

    /// Rollback the deallocation of some extents.
    ///
    /// Rollback the deallocation of the extents obtained from `extents_iter` at
    /// [`Transaction::allocs`] and reset
    /// any updates staged at the
    /// [`Transaction::auth_tree_data_blocks_update_states`]' [Allocation Block
    /// level entries](auth_tree_data_blocks_update_states::AllocationBlockUpdateState)
    /// overlapping with them.
    ///
    /// Must get invoked only if [`TransactionAllocations::reset_rollback()`]
    /// has not been invoked on [`Transaction::allocs`] since the allocation,
    /// and is failsafe then.
    ///
    /// # Arguments:
    ///
    /// * `extents_iter` - Iterator over the extents.
    /// * `alloc_bitmap` - The filesystem's
    ///   [`AllocBitmap`](alloc_bitmap::AllocBitmap) in the state from before
    ///   the [`Transaction`].
    /// * `contents_indeterminate` - Whether the reset of the updates staged at
    ///   the [`Transaction::auth_tree_data_blocks_update_states`] makes the the
    ///   extents' contents indeterminate. Should be set to `true` if the
    ///   previously staged updates from before the corresponding deallocation
    ///   had not been
    ///   [applied](AuthTreeDataBlocksUpdateStates::apply_allocation_blocks_staged_updates)
    ///   first before that deallocation.
    pub fn rollback_extents_free<EI: Iterator<Item = layout::PhysicalAllocBlockRange> + Clone>(
        mut self: Box<Self>,
        extents_iter: EI,
        alloc_bitmap: &alloc_bitmap::AllocBitmap,
        contents_indeterminate: bool,
    ) -> Result<Box<Self>, NvFsError> {
        self.allocs.pending_frees.remove_extents(extents_iter.clone());
        // If something had been freed, it must have been allocated before.
        self.allocs
            .pending_allocs
            .rollback_remove_extents(extents_iter.clone(), alloc_bitmap, true)?;

        if !contents_indeterminate {
            self.auth_tree_data_blocks_update_states
                .reset_staged_extents_updates(extents_iter);
        } else {
            // If the staged updates possibly present at the time of the deallocation had
            // not been applied before the free, then the contents are
            // indeterminate now.
            self.auth_tree_data_blocks_update_states
                .reset_staged_extents_updates_to_failed(extents_iter);
        }

        Ok(self)
    }
}

/// Allocations and deallocations made on behalf of the [`Transaction`].
///
/// Track allocations and deallocations relative to
/// the filesystem's [`AllocBitmap`](alloc_bitmap::AllocBitmap) from before the
/// [`Transaction`].
pub(super) struct TransactionAllocations {
    /// New, to be committed allocations.
    pub pending_allocs: alloc_bitmap::SparseAllocBitmap,
    /// New, to be committed deallocations.
    pub pending_frees: alloc_bitmap::SparseAllocBitmap,
    /// Temporary allocations for the lifetime of the journal.
    pub journal_allocs: alloc_bitmap::SparseAllocBitmap,
}

impl TransactionAllocations {
    /// Instantiate a new, empty [`TransactionAllocations`].
    pub fn new() -> Self {
        Self {
            pending_allocs: alloc_bitmap::SparseAllocBitmap::new(),
            pending_frees: alloc_bitmap::SparseAllocBitmap::new(),
            journal_allocs: alloc_bitmap::SparseAllocBitmap::new(),
        }
    }

    /// Reset the rollback memory reserves.
    pub fn reset_rollback(&mut self) {
        self.pending_allocs.reset_remove_rollback();
        self.pending_frees.reset_remove_rollback();
    }
}

/// Pending authentication tree updates to get applied once the journal has been
/// written.
///
/// Populated only at [`Transaction`] commit.
pub(super) struct TransactionPendingAuthTreeUpdates {
    /// The updated authentication tree root HMAC.
    updated_root_hmac_digest: Vec<u8>,
    /// Updates to the authentication tree's nodes.
    pending_nodes_updates: auth_tree::AuthTreePendingNodesUpdates,
}

impl TransactionPendingAuthTreeUpdates {
    /// Instantiate a new, empty [`TransactionPendingAuthTreeUpdates`].
    fn new() -> Self {
        Self {
            updated_root_hmac_digest: Vec::new(),
            pending_nodes_updates: auth_tree::AuthTreePendingNodesUpdates::new(),
        }
    }
}

pub(super) use apply_journal::TransactionApplyJournalFuture;
pub(super) use auth_tree_updates::TransactionJournalUpdateAuthDigestsScriptIterator;
pub(super) use cleanup::{TransactionAbortJournalFuture, TransactionCleanupPreCommitCancelledFuture};
pub(super) use write_journal::TransactionWriteJournalFuture;
