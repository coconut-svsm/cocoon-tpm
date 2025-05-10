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
        cocoonfs::{
            alloc_bitmap, auth_tree, extents,
            fs::{CocoonFsPendingTransactionsSyncState, CocoonFsSyncStateMemberRef},
            inode_index, journal, layout,
        },
        NvFsError,
    },
    utils_async::sync_types,
};

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

use core::marker;

pub struct Transaction {
    pub(super) auth_tree_data_blocks_update_states: AuthTreeDataBlocksUpdateStates,

    pub(super) rng: Box<dyn rng::RngCoreDispatchable + marker::Send>,
    pub(super) journal_staging_copy_disguise: Option<(
        journal::staging_copy_disguise::JournalStagingCopyDisguise,
        Option<journal::staging_copy_disguise::JournalStagingCopyUndisguise>,
    )>,

    allocation_block_size_128b_log2: u8,
    auth_tree_data_block_allocation_blocks_log2: u8,
    io_block_allocation_blocks_log2: u8,
    chip_io_block_size_128b_log2: u32,
    preferred_chip_io_blocks_bulk_log2: u32,

    pub(super) allocs: TransactionAllocations,

    abandoned_journal_staging_copy_blocks: Vec<layout::PhysicalAllocBlockIndex>,

    pub(super) is_primary_pending: bool,
    accumulated_fs_instance_pending_transactions_sync_state: CocoonFsPendingTransactionsSyncState,

    pub(super) inode_index_updates: inode_index::TransactionInodeIndexUpdates,

    pending_auth_tree_updates: TransactionPendingAuthTreeUpdates,

    journal_log_tail_extents: extents::PhysicalExtents,

    #[cfg(test)]
    pub(super) test_fail_apply_journal: bool,
}

impl Transaction {
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

pub(super) struct TransactionAllocations {
    pub pending_allocs: alloc_bitmap::SparseAllocBitmap,
    pub pending_frees: alloc_bitmap::SparseAllocBitmap,
    pub journal_allocs: alloc_bitmap::SparseAllocBitmap,
}

impl TransactionAllocations {
    pub fn new() -> Self {
        Self {
            pending_allocs: alloc_bitmap::SparseAllocBitmap::new(),
            pending_frees: alloc_bitmap::SparseAllocBitmap::new(),
            journal_allocs: alloc_bitmap::SparseAllocBitmap::new(),
        }
    }

    pub fn reset_rollback(&mut self) {
        self.pending_allocs.reset_remove_rollback();
        self.pending_frees.reset_remove_rollback();
    }
}

pub(super) struct TransactionPendingAuthTreeUpdates {
    updated_root_hmac_digest: Vec<u8>,
    pending_nodes_updates: auth_tree::AuthTreePendingNodesUpdates,
}

impl TransactionPendingAuthTreeUpdates {
    fn new() -> Self {
        Self {
            updated_root_hmac_digest: Vec::new(),
            pending_nodes_updates: auth_tree::AuthTreePendingNodesUpdates::new(),
        }
    }
}

pub(super) use apply_journal::TransactionApplyJournalFuture;
pub(super) use auth_tree_updates::TransactionJournalUpdateAuthDigestsScriptIterator;
pub(super) use cleanup::{TransactionAbortJournalFuture, TransactionCleanupPreCommitCancelled};
pub(super) use write_journal::TransactionWriteJournalFuture;
