// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`SparseAllocBitmap`] and [`SparseAllocBitmapUnion`].

extern crate alloc;
use alloc::vec::Vec;

use super::{
    AllocBitmap,
    bitmap::AllocBitmapWordIterator,
    bitmap_word::{BITMAP_WORD_BITS_LOG2, BitmapWord},
};
use crate::{
    fs::{NvFsError, cocoonfs::layout},
    nvfs_err_internal,
    utils_common::bitmanip::BitManip as _,
};
use core::{array, cmp, iter};

/// Entry in a [`SparseAllocBitmap`].
struct SparseAllocBitmapEntry {
    /// Associated storage location represented as an index on physical storage
    /// in units of [`BitmapWord::BITS`] [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    bitmap_word_index: u64,
    /// The [`BitmapWord`] valie.
    bitmap_word: BitmapWord,
}

/// Sparse allocation bitmap.
///
/// A `SparseAllocBitmap` stores only the non-zero [`BitmapWord`]s, alongside
/// their respective associated storage locations.
///
/// `SparseAllocBitmap` instances are typically used for tracking pending
/// allocations and deallocations before eventually committing them to
/// the full [`AllocBitmap`].
pub struct SparseAllocBitmap {
    /// The entries, sorted by associated location on storage.
    entries: Vec<SparseAllocBitmapEntry>,
    /// Additional [capacity](Vec::capacity) emergency reserve to include in
    /// reallocations of [`entries`](Self::entries).
    ///
    /// Used for guaranteeing infallible reinsertions of previously removed
    /// entries in case of a rollback.
    remove_rollback_reserve_capacity: usize,
}

impl SparseAllocBitmap {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            remove_rollback_reserve_capacity: 0,
        }
    }

    /// Test if the [`SparseAllocBitmap`] has no non-zero entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Reset the removal rollback reserve memory capacity.
    ///
    /// The bit clearing primitives, i.e.
    /// [`remove_block()`](Self::remove_block),
    /// [`remove_blocks()`](Self::remove_blocks),
    /// [`remove_extent()`](Self::remove_extent) and
    /// [`remove_extents()`](Self::remove_extents), all maintain an internal
    /// removal rollback memory reserve guaranteeing a failsave subsequent
    /// rollback of the respective removal operation, if needed.
    ///
    /// That reserve capacity can accumulate over time, resulting in
    /// unnecessarily large reallocation requests. `reset_remove_rollback()`
    /// resets the reserve to zero, at the cost of rendering
    /// rollbacks of any prior removal via
    /// [`rollback_remove_block()`](Self::rollback_remove_block),
    /// [`rollback_remove_blocks()`](Self::rollback_remove_blocks),
    /// [`rollback_remove_extent()`](Self::rollback_remove_extent) or
    /// [`rollback_remove_extents()`](Self::rollback_remove_extents) impossible.
    pub fn reset_remove_rollback(&mut self) {
        self.remove_rollback_reserve_capacity = 0
    }

    /// Set bits corresponding to a block of size and alignment a specified
    /// power of two.
    ///
    /// # Arguments:
    ///
    /// * `block_allocation_blocks_begin` - The block's beginning on physical
    ///   storage. Must be aligned to the block size as specified through
    ///   `block_allocation_blocks_log2`.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size in
    ///   units of [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2). Must be
    ///   less than or equal to [`BitmapWord::BITS`].
    pub fn add_block(
        &mut self,
        block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        block_allocation_blocks_log2: u32,
    ) -> Result<(), NvFsError> {
        let range = layout::PhysicalAllocBlockRange::from((
            block_allocation_blocks_begin,
            layout::AllocBlockCount::from(1u64 << block_allocation_blocks_log2),
        ));
        let first_entry_index = self.populate_missing_in_range(&range)?;
        self.set_in_range(&range, Some(first_entry_index), true);
        Ok(())
    }

    /// Clear bits corresponding to a block of size and alignment a specified
    /// power of two.
    ///
    /// An emergency rollback reserve memory capacity will get maintained
    /// internally up to the next invocation of
    /// [`reset_remove_rollback()`](Self::reset_remove_rollback),
    /// guaranteeing an infallible reinsertion of the removed block via
    /// [`rollback_remove_block()`](Self::rollback_remove_block), if needed.
    /// The rollback reserve can accumulate over time, possibly resulting
    /// in unnecessarily large reallocation requests.
    /// [`reset_remove_rollback()`](Self::reset_remove_rollback) should get
    /// invoked at points for which it is known that no prior removal
    /// operation would subsequently get rolled back.
    ///
    /// # Arguments:
    ///
    /// * `block_allocation_blocks_begin` - The block's beginning on physical
    ///   storage. Must be aligned to the block size as specified through
    ///   `block_allocation_blocks_log2`.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size in
    ///   units of [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2). Must be
    ///   less than or equal to [`BitmapWord::BITS`].
    pub fn remove_block(
        &mut self,
        block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        block_allocation_blocks_log2: u32,
    ) {
        self._remove_block(block_allocation_blocks_begin, block_allocation_blocks_log2, true);
    }

    /// Block removal implementation.
    ///
    /// Clear bits corresponding to a block of size and alignment a specified
    /// power of two.
    ///
    /// If `prepare_for_rollback` is true, an emergency rollback reserve memory
    /// capacity will get maintained internally up to the next invocation of
    /// [`reset_remove_rollback()`](Self::reset_remove_rollback),
    /// guaranteeing an infallible reinsertion of the removed block via
    /// [`rollback_remove_block()`](Self::rollback_remove_block) or as part of
    /// [`rollback_remove_blocks()`](Self::rollback_remove_blocks), if needed.
    ///
    /// If set `prepare_for_rollback` is set to `false`, the rollback guarantees
    /// for any previous removal from the same [`BitmapWord`] covering the block
    /// becomes void!
    ///
    /// # Arguments:
    ///
    /// * `block_allocation_blocks_begin` - The block's beginning on physical
    ///   storage. Must be aligned to the block size as specified through
    ///   `block_allocation_blocks_log2`.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size in
    ///   units of [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2). Must be
    ///   less than or equal to [`BitmapWord::BITS`].
    /// * `prepare_for_rollback` - Whether or not to maintain a rollback
    ///   emergency reserve memory capacity.
    fn _remove_block(
        &mut self,
        block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        block_allocation_blocks_log2: u32,
        prepare_for_rollback: bool,
    ) {
        let range = layout::PhysicalAllocBlockRange::from((
            block_allocation_blocks_begin,
            layout::AllocBlockCount::from(1u64 << block_allocation_blocks_log2),
        ));
        let first_entry_index = self.set_in_range(&range, None, false);
        self.prune_unused_in_range(&range, Some(first_entry_index), prepare_for_rollback);
    }

    /// Failsafe rollback of a previous [`remove_block()`](Self::remove_block)
    /// operation.
    ///
    /// Any memory needed is drawn from the rollback reserve. There must not
    /// have been any invocation of
    /// [`reset_remove_rollback()`](Self::reset_remove_rollback) after the
    /// [`remove_block()`](Self::remove_block) attempted to get rolled back.
    ///
    /// # Arguments:
    ///
    /// * `block_allocation_blocks_begin` - The block's beginning on physical
    ///   storage. Must be aligned to the block size as specified through
    ///   `block_allocation_blocks_log2`.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size in
    ///   units of [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2). Must be
    ///   less than or equal to [`BitmapWord::BITS`].
    /// * `alloc_bitmap` - The [`AllocBitmap`] relative to which the
    ///   [`SparseAllocBitmap`] is considered to track changes.
    /// * `alloc_bitmap_value` - The [`AllocBitmap`] bit value a set bit in the
    ///   [`SparseAllocBitmap`] corresponds to: if `true`, then the
    ///   [`SparseAllocBitmap`] tracks new allocations, or if `false`,
    ///   deallocations.
    pub fn rollback_remove_block(
        &mut self,
        block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        block_allocation_blocks_log2: u32,
        alloc_bitmap: &AllocBitmap,
        alloc_bitmap_value: bool,
    ) -> Result<(), NvFsError> {
        let range = layout::PhysicalAllocBlockRange::from((
            block_allocation_blocks_begin,
            layout::AllocBlockCount::from(1u64 << block_allocation_blocks_log2),
        ));
        self.repopulate_set_range_for_rollback(&range, alloc_bitmap, alloc_bitmap_value)
    }

    /// Set bits corresponding to a set of blocks of size and alignment
    /// specified power of two each.
    ///
    /// # Arguments:
    ///
    /// * `block_allocation_blocks_begin_iter` - Iterator over the blocks'
    ///   beginning on physical storage each. All returned locations must be
    ///   aligned to the block size as specified through
    ///   `block_allocation_blocks_log2`.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size in
    ///   units of [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2). Must be
    ///   less than or equal to [`BitmapWord::BITS`].
    pub fn add_blocks<BI: Iterator<Item = layout::PhysicalAllocBlockIndex> + Clone>(
        &mut self,
        blocks_allocation_blocks_begin_iter: BI,
        block_allocation_blocks_log2: u32,
    ) -> Result<(), NvFsError> {
        for (i, block_allocation_blocks_begin) in blocks_allocation_blocks_begin_iter.clone().enumerate() {
            if let Err(e) = self.add_block(block_allocation_blocks_begin, block_allocation_blocks_log2) {
                // Rollback
                for block_allocation_blocks_begin in blocks_allocation_blocks_begin_iter.take(i) {
                    self._remove_block(block_allocation_blocks_begin, block_allocation_blocks_log2, false);
                }
                return Err(e);
            }
        }
        Ok(())
    }

    /// Clear bits corresponding to a set of blocks of size and alignment
    /// specified power of two each.
    ///
    /// An emergency rollback reserve memory capacity will get maintained
    /// internally up to the next invocation of
    /// [`reset_remove_rollback()`](Self::reset_remove_rollback),
    /// guaranteeing an infallible reinsertion of the removed blocks via
    /// [`rollback_remove_blocks()`](Self::rollback_remove_blocks), if needed.
    /// The rollback reserve can accumulate over time, possibly resulting
    /// in unnecessarily large reallocation requests.
    /// [`reset_remove_rollback()`](Self::reset_remove_rollback) should get
    /// invoked at points for which it is known that no prior removal
    /// operation would subsequently get rolled back.
    ///
    /// # Arguments:
    ///
    /// * `block_allocation_blocks_begin_iter` - Iterator over the blocks'
    ///   beginning on physical storage each. All returned locations must be
    ///   aligned to the block size as specified through
    ///   `block_allocation_blocks_log2`.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size in
    ///   units of [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2). Must be
    ///   less than or equal to [`BitmapWord::BITS`].
    pub fn remove_blocks<BI: Iterator<Item = layout::PhysicalAllocBlockIndex>>(
        &mut self,
        blocks_allocation_blocks_begin_iter: BI,
        block_allocation_blocks_log2: u32,
    ) {
        for block_allocation_blocks_begin in blocks_allocation_blocks_begin_iter {
            self.remove_block(block_allocation_blocks_begin, block_allocation_blocks_log2);
        }
    }

    /// Failsafe rollback of a previous [`remove_blocks()`](Self::remove_blocks)
    /// operation.
    ///
    /// Any memory needed is drawn from the rollback reserve. There must not
    /// have been any invocation of
    /// [`reset_remove_rollback()`](Self::reset_remove_rollback) after the
    /// [`remove_blocks()`](Self::remove_blocks) attempted to get rolled back.
    ///
    /// # Arguments:
    ///
    /// * `block_allocation_blocks_begin_iter` - Iterator over the blocks'
    ///   beginning on physical storage each. All returned locations must be
    ///   aligned to the block size as specified through
    ///   `block_allocation_blocks_log2`.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size in
    ///   units of [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2). Must be
    ///   less than or equal to [`BitmapWord::BITS`].
    /// * `alloc_bitmap` - The [`AllocBitmap`] relative to which the
    ///   [`SparseAllocBitmap`] is considered to track changes.
    /// * `alloc_bitmap_value` - The [`AllocBitmap`] bit value a set bit in the
    ///   [`SparseAllocBitmap`] corresponds to: if `true`, then the
    ///   [`SparseAllocBitmap`] tracks new allocations, or if `false`,
    ///   deallocations.
    pub fn rollback_remove_blocks<BI: Iterator<Item = layout::PhysicalAllocBlockIndex>>(
        &mut self,
        blocks_allocation_blocks_begin_iter: BI,
        block_allocation_blocks_log2: u32,
        alloc_bitmap: &AllocBitmap,
        alloc_bitmap_value: bool,
    ) -> Result<(), NvFsError> {
        for block_allocation_blocks_begin in blocks_allocation_blocks_begin_iter {
            self.rollback_remove_block(
                block_allocation_blocks_begin,
                block_allocation_blocks_log2,
                alloc_bitmap,
                alloc_bitmap_value,
            )?;
        }
        Ok(())
    }

    /// Set bits corresponding to an arbitrary extent.
    ///
    /// # Arguments:
    ///
    /// * `extent` - The extent whose corresponding bits to set in the
    ///   [`SparseAllocBitmap`].
    pub fn add_extent(&mut self, extent: &layout::PhysicalAllocBlockRange) -> Result<(), NvFsError> {
        let first_entry_index = self.populate_missing_in_range(extent)?;
        self.set_in_range(extent, Some(first_entry_index), true);
        Ok(())
    }

    /// Clear bits corresponding to an arbitrary extent.
    ///
    /// An emergency rollback reserve memory capacity will get maintained
    /// internally up to the next invocation of
    /// [`reset_remove_rollback()`](Self::reset_remove_rollback),
    /// guaranteeing an infallible reinsertion of the removed extent via
    /// [`rollback_remove_extent()`](Self::rollback_remove_extent), if needed.
    /// The rollback reserve can accumulate over time, possibly resulting
    /// in unnecessarily large reallocation requests.
    /// [`reset_remove_rollback()`](Self::reset_remove_rollback) should get
    /// invoked at points for which it is known that no prior removal
    /// operation would subsequently get rolled back.
    ///
    /// # Arguments:
    ///
    /// * `extent` - The extent whose corresponding bits to clear in the
    ///   [`SparseAllocBitmap`].
    pub fn remove_extent(&mut self, extent: &layout::PhysicalAllocBlockRange) {
        let first_entry_index = self.set_in_range(extent, None, false);
        self.prune_unused_in_range(extent, Some(first_entry_index), true);
    }

    /// Failsafe rollback of a previous [`remove_extent()`](Self::remove_extent)
    /// operation.
    ///
    /// Any memory needed is drawn from the rollback reserve. There must not
    /// have been any invocation of
    /// [`reset_remove_rollback()`](Self::reset_remove_rollback) after the
    /// [`remove_extent()`](Self::remove_extent) attempted to get rolled back.
    ///
    /// # Arguments:
    ///
    /// * `extent` - The extent whose corresponding bits to set again in the
    ///   [`SparseAllocBitmap`].
    /// * `alloc_bitmap` - The [`AllocBitmap`] relative to which the
    ///   [`SparseAllocBitmap`] is considered to track changes.
    /// * `alloc_bitmap_value` - The [`AllocBitmap`] bit value a set bit in the
    ///   [`SparseAllocBitmap`] corresponds to: if `true`, then the
    ///   [`SparseAllocBitmap`] tracks new allocations, or if `false`,
    ///   deallocations.
    pub fn rollback_remove_extent(
        &mut self,
        extent: &layout::PhysicalAllocBlockRange,
        alloc_bitmap: &AllocBitmap,
        alloc_bitmap_value: bool,
    ) -> Result<(), NvFsError> {
        self.repopulate_set_range_for_rollback(extent, alloc_bitmap, alloc_bitmap_value)
    }

    /// Set bits corresponding to a set of arbitrary extents.
    ///
    /// # Arguments:
    ///
    /// * `extent_iter` - Iterator over the extents whose corresponding bits to
    ///   set in the [`SparseAllocBitmap`] each.
    pub fn add_extents<EI: Iterator<Item = layout::PhysicalAllocBlockRange> + Clone>(
        &mut self,
        extents_iter: EI,
    ) -> Result<(), NvFsError> {
        let mut first_entry_index_hint = None;
        let mut reset_first_entry_index_hint = false;
        for (i, extent) in extents_iter.clone().enumerate() {
            match self.populate_missing_in_range(&extent) {
                Ok(first_entry_index) => {
                    if first_entry_index_hint.is_none() {
                        first_entry_index_hint = Some(first_entry_index);
                    } else {
                        // The extents are not necessarily ordered and inserting subsequent ones might
                        // shift the location of previous on in the sparse bitmap.
                        reset_first_entry_index_hint = true;
                    }
                }
                Err(e) => {
                    // Rollback on error.
                    for extent in extents_iter.take(i) {
                        self.prune_unused_in_range(&extent, first_entry_index_hint, false);
                        first_entry_index_hint = None;
                    }
                    return Err(e);
                }
            }
        }

        if reset_first_entry_index_hint {
            first_entry_index_hint = None;
        }

        // Setting bits only after all allocations have succeeded.
        for extent in extents_iter {
            self.set_in_range(&extent, first_entry_index_hint, true);
            first_entry_index_hint = None;
        }
        Ok(())
    }

    /// Set bits corresponding to a set of arbitrary extents.
    ///
    /// An emergency rollback reserve memory capacity will get maintained
    /// internally up to the next invocation of
    /// [`reset_remove_rollback()`](Self::reset_remove_rollback),
    /// guaranteeing an infallible reinsertion of the removed extents via
    /// [`rollback_remove_extents()`](Self::rollback_remove_extents), if needed.
    /// The rollback reserve can accumulate over time, possibly resulting
    /// in unnecessarily large reallocation requests.
    /// [`reset_remove_rollback()`](Self::reset_remove_rollback) should get
    /// invoked at points for which it is known that no prior removal
    /// operation would subsequently get rolled back.
    ///
    /// # Arguments:
    ///
    /// * `extent_iter` - Iterator over the extents whose corresponding bits to
    ///   clear in the [`SparseAllocBitmap`] each.
    pub fn remove_extents<EI: Iterator<Item = layout::PhysicalAllocBlockRange>>(&mut self, extents_iter: EI) {
        for extent in extents_iter {
            let first_entry_index = self.set_in_range(&extent, None, false);
            self.prune_unused_in_range(&extent, Some(first_entry_index), true);
        }
    }

    /// Failsafe rollback of a previous
    /// [`remove_extents()`](Self::remove_extents) operation.
    ///
    /// Any memory needed is drawn from the rollback reserve. There must not
    /// have been any invocation of
    /// [`reset_remove_rollback()`](Self::reset_remove_rollback) after the
    /// [`remove_extents()`](Self::remove_extents) attempted to get rolled back.
    ///
    /// # Arguments:
    ///
    /// * `extent_iter` - Iterator over the extents whose corresponding bits to
    ///   set again in the [`SparseAllocBitmap`] each.
    /// * `alloc_bitmap` - The [`AllocBitmap`] relative to which the
    ///   [`SparseAllocBitmap`] is considered to track changes.
    /// * `alloc_bitmap_value` - The [`AllocBitmap`] bit value a set bit in the
    ///   [`SparseAllocBitmap`] corresponds to: if `true`, then the
    ///   [`SparseAllocBitmap`] tracks new allocations, or if `false`,
    ///   deallocations.
    pub fn rollback_remove_extents<EI: Iterator<Item = layout::PhysicalAllocBlockRange>>(
        &mut self,
        extents_iter: EI,
        alloc_bitmap: &AllocBitmap,
        alloc_bitmap_value: bool,
    ) -> Result<(), NvFsError> {
        for extent in extents_iter {
            self.rollback_remove_extent(&extent, alloc_bitmap, alloc_bitmap_value)?;
        }
        Ok(())
    }

    /// Iterate over the [`SparseAllocBitmap`]'s entries.
    ///
    /// The returned iterator yields one [`BitmapWord`] for each entry,
    /// alongside the location of the first [Allocation
    /// Block](layout::ImageLayout::allocation_block_size_128b_log2) tracked
    /// therein on physical storage.
    pub fn iter(&self) -> SparseAllocBitmapIterator<'_> {
        SparseAllocBitmapIterator::new(self)
    }

    /// Iterate over the [`SparseAllocBitmap`]'s entries, starting from a
    /// given physical storage location.
    ///
    /// The returned iterator yields one [`BitmapWord`] for each entry,
    /// alongside the location of the first [Allocation
    /// Block](layout::ImageLayout::allocation_block_size_128b_log2) tracked
    /// therein on physical storage.
    ///
    /// The iteration starts at the first entry overlapping with or following
    /// the physical [Allocation
    /// Block](layout::ImageLayout::allocation_block_size_128b_log2) specified
    /// by `physical_allocation_block_index`.
    ///
    /// # Arguments:
    ///
    /// * `physical_allocation_block_index` - Starting position of the
    ///   iteration.
    pub fn iter_at(
        &self,
        physical_allocation_block_index: layout::PhysicalAllocBlockIndex,
    ) -> SparseAllocBitmapIterator<'_> {
        SparseAllocBitmapIterator::new_at(self, physical_allocation_block_index)
    }

    /// Iterate over [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2) in blocks
    /// of size and alignment a specified power of two.
    ///
    /// Iterate over the [`SparseAllocBitmap`]'s bits in blocks of size and
    /// alignment equal to `block_allocation_blocks_log2`.
    ///
    /// The returned iterator yields one [`BitmapWord`] per block at a time,
    /// with its least significant bits being set to the respective bit values
    /// in the current block, alongside the location of the block's first
    /// [Allocation
    /// Block](layout::ImageLayout::allocation_block_size_128b_log2) on physical
    /// storage.
    ///
    /// # Arguments:
    ///
    /// * `block_allocation_blocks_log2` - The block size and alignment, must be
    ///   less than or equal to [`BitmapWord::BITS`].
    pub fn block_iter(&self, block_allocation_blocks_log2: u32) -> SparseAllocBitmapBlockIterator<'_> {
        SparseAllocBitmapBlockIterator::new(self, block_allocation_blocks_log2)
    }

    /// Iterate over [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2) in blocks
    /// of size and alignment a specified power of two, starting from a
    /// given physical storage location.
    ///
    /// Iterate over the [`SparseAllocBitmap`]'s bits in blocks of size and
    /// alignment equal to `block_allocation_blocks_log2`. The iteration
    /// starts at the first block at or subsequent to the physical
    /// [Allocation
    /// Block](layout::ImageLayout::allocation_block_size_128b_log2) specified
    /// by `physical_allocation_blocks_begin` and covered by some entry in the
    /// [`SparseAllocBitmap`].
    ///
    /// The returned iterator yields one [`BitmapWord`] per block at a time,
    /// with its least significant bits being set to the respective bit values
    /// in the current block, alongside the location of the block's first
    /// [Allocation
    /// Block](layout::ImageLayout::allocation_block_size_128b_log2) on physical
    /// storage.
    ///
    /// # Arguments:
    ///
    /// * `physical_allocation_blocks_begin` - Starting location, must be
    ///   aligned by two to power of  `block_allocation_blocks_log2`.
    /// * `block_allocation_blocks_log2` - The block size and alignment, must be
    ///   less than or equal to [`BitmapWord::BITS`].
    pub fn block_iter_at(
        &self,
        block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        block_allocation_blocks_log2: u32,
    ) -> SparseAllocBitmapBlockIterator<'_> {
        SparseAllocBitmapBlockIterator::new_at(self, block_allocation_blocks_begin, block_allocation_blocks_log2)
    }

    /// Clear bits redundant to the state found in a base [`AllocBitmap`].
    ///
    /// Take the [`SparseAllocBitmap`] as representing pending changes to some
    /// base `alloc_bitmap`, i.e. either pending allocations or
    /// deallocation, and clear any bits for which the corresponding ones in the
    /// `alloc_bitmap` are already in the desired target state.
    ///
    /// A [`reset_remove_rollback()`](Self::reset_remove_rollback) is implied.
    ///
    /// # Arguments:
    ///
    /// * `alloc_bitmap` - The base [`AllocBitmap`] to compare against.
    /// * `is_free` - If true, the [`SparseAllocBitmap`] is tracking
    ///   deallocations, if false it's tracking new allocations.
    pub fn clear_redundant(&mut self, alloc_bitmap: &AllocBitmap, is_free: bool) {
        self.reset_remove_rollback();

        let mut entry_index = 0;
        let mut remove_begin = None;
        // All ones if is_free is false, zero otherwise.
        let alloc_bitmap_word_invert_mask = (1 as BitmapWord - is_free as BitmapWord).wrapping_neg();
        while entry_index < self.entries.len() {
            let entry = &mut self.entries[entry_index];
            let alloc_bitmap_word = usize::try_from(entry.bitmap_word_index)
                .ok()
                .and_then(|bitmap_word_index| alloc_bitmap.bitmap.get(bitmap_word_index).copied())
                .unwrap_or(0);
            entry.bitmap_word &= alloc_bitmap_word ^ alloc_bitmap_word_invert_mask;
            if entry.bitmap_word != 0 {
                if let Some(remove_begin) = remove_begin.take() {
                    self.entries.drain(remove_begin..entry_index);
                    entry_index = remove_begin;
                }
            } else {
                remove_begin = remove_begin.or(Some(entry_index));
            }
            entry_index += 1;
        }
        if let Some(remove_begin) = remove_begin {
            self.entries.truncate(remove_begin);
        }
    }

    /// Form a set difference.
    ///
    /// Clear any bit in `self` for which the corresponding bit in `other` is
    /// set.
    ///
    /// A [`reset_remove_rollback()`](Self::reset_remove_rollback) is implied.
    pub fn subtract(&mut self, other: &Self) {
        self.reset_remove_rollback();

        if self.is_empty() || other.is_empty() {
            return;
        }
        let mut this_entry_index = 0;
        let mut other_entry_index = 0;
        let mut remove_begin = None;
        'outer: loop {
            debug_assert!(this_entry_index < self.entries.len());
            debug_assert!(other_entry_index < other.entries.len());
            if self.entries[this_entry_index].bitmap_word_index < other.entries[other_entry_index].bitmap_word_index {
                if let Some(remove_begin) = remove_begin.take() {
                    self.entries.drain(remove_begin..this_entry_index);
                    this_entry_index = remove_begin;
                }

                while self.entries[this_entry_index].bitmap_word_index
                    < other.entries[other_entry_index].bitmap_word_index
                {
                    this_entry_index += 1;
                    if this_entry_index == self.entries.len() {
                        debug_assert!(remove_begin.is_none());
                        return;
                    }
                }
            }
            debug_assert!(
                this_entry_index < self.entries.len()
                    && self.entries[this_entry_index].bitmap_word_index
                        >= other.entries[other_entry_index].bitmap_word_index
            );
            while self.entries[this_entry_index].bitmap_word_index > other.entries[other_entry_index].bitmap_word_index
            {
                other_entry_index += 1;
                if other_entry_index == other.entries.len() {
                    break 'outer;
                }
            }

            while self.entries[this_entry_index].bitmap_word_index == other.entries[other_entry_index].bitmap_word_index
            {
                self.entries[this_entry_index].bitmap_word &= !other.entries[other_entry_index].bitmap_word;

                if self.entries[this_entry_index].bitmap_word == 0 {
                    if remove_begin.is_none() {
                        remove_begin = Some(this_entry_index);
                    }
                } else if let Some(remove_begin) = remove_begin.take() {
                    self.entries.drain(remove_begin..this_entry_index);
                    this_entry_index = remove_begin;
                }

                this_entry_index += 1;
                if this_entry_index == self.entries.len() {
                    break 'outer;
                }
                other_entry_index += 1;
                if other_entry_index == other.entries.len() {
                    break 'outer;
                }
            }
        }

        if let Some(remove_begin) = remove_begin {
            self.entries.drain(remove_begin..this_entry_index);
        }
    }

    /// Lookup an entry in the [`SparseAllocBitmap`] by physical location.
    ///
    /// An index into [`Self::entries`] is returned, either wrapped in an `Ok`
    /// on an exact match or in an `Err` if it denotes the insertion
    /// position for a new entry corresponding to the specified physical
    /// location.
    ///
    /// # Arguments:
    ///
    /// * `bitmap_word_index` - Physical storage location to lookup the
    ///   [`Self::entries`] index for, specified as an index in units of
    ///   [`BitmapWord::BITS`] [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2) into the
    ///   physical storage.
    fn find_entry_position(&self, bitmap_word_index: u64) -> Result<usize, usize> {
        self.entries
            .binary_search_by(|e| e.bitmap_word_index.cmp(&bitmap_word_index))
    }

    /// Populate missing entries for tracking a given
    /// [`PhysicalAllocBlockRange`](layout::PhysicalAllocBlockRange).
    ///
    /// Insert new entries into [`Self::entries`] so that all of `range` is
    /// covered.
    ///
    /// On success, the index into [`Self::entries`] of the first entry
    /// overlapping with `range` is returned wrapped in an `Ok`.
    ///
    /// # Arguments:
    ///
    /// * `range` - The physical range to add tracking entries to the
    ///   [`SparseAllocBitmap`] for.
    fn populate_missing_in_range(&mut self, range: &layout::PhysicalAllocBlockRange) -> Result<usize, NvFsError> {
        let (mut bitmap_word_index, mut bitmap_words_count) = {
            let physical_allocation_block_count = u64::from(range.block_count());
            let physical_allocation_block = u64::from(range.begin());
            let bitmap_word_index = physical_allocation_block >> BITMAP_WORD_BITS_LOG2;
            let offset_in_bitmap_word = physical_allocation_block & u64::trailing_bits_mask(BITMAP_WORD_BITS_LOG2);
            // Align the range to a multiple of the Bitmap Words.
            let physical_allocation_block_count = physical_allocation_block_count + offset_in_bitmap_word;
            let mut bitmap_words_count = physical_allocation_block_count >> BITMAP_WORD_BITS_LOG2;
            if bitmap_words_count << BITMAP_WORD_BITS_LOG2 != physical_allocation_block_count {
                bitmap_words_count += 1; // Also align the range in the upwards
                // direction.
            }
            let bitmap_words_count =
                usize::try_from(bitmap_words_count).map_err(|_| NvFsError::MemoryAllocationFailure)?;
            (bitmap_word_index, bitmap_words_count)
        };

        let (first_entry_index, mut next_entry_index) = match self.find_entry_position(bitmap_word_index) {
            Ok(entry_index) => {
                bitmap_word_index += 1;
                bitmap_words_count = bitmap_words_count.saturating_sub(1);
                (entry_index, entry_index + 1)
            }
            Err(entry_index) => (entry_index, entry_index),
        };
        while bitmap_words_count != 0 {
            let entries_len = self.entries.len();
            if next_entry_index == entries_len {
                if self
                    .entries
                    .try_reserve_exact(bitmap_words_count + self.remove_rollback_reserve_capacity)
                    .is_err()
                {
                    // Rollback.
                    self.prune_unused_in_range(range, Some(first_entry_index), false);
                    return Err(NvFsError::MemoryAllocationFailure);
                }

                let new_entries_len = match entries_len.checked_add(bitmap_words_count) {
                    Some(new_entries_len) => new_entries_len,
                    None => {
                        // Rollback.
                        self.prune_unused_in_range(range, Some(first_entry_index), false);
                        return Err(NvFsError::MemoryAllocationFailure);
                    }
                };
                self.entries.resize_with(new_entries_len, || {
                    let cur_bitmap_word_index = bitmap_word_index;
                    bitmap_word_index += 1;
                    SparseAllocBitmapEntry {
                        bitmap_word_index: cur_bitmap_word_index,
                        bitmap_word: 0,
                    }
                });
                next_entry_index += bitmap_words_count;
                bitmap_words_count = 0;
            } else if self.entries[next_entry_index].bitmap_word_index != bitmap_word_index {
                let missing_bitmap_words_until_next = (self.entries[next_entry_index].bitmap_word_index
                    - bitmap_word_index)
                    .min(bitmap_words_count as u64) as usize;
                if self
                    .entries
                    .try_reserve_exact(missing_bitmap_words_until_next + self.remove_rollback_reserve_capacity)
                    .is_err()
                {
                    // Rollback.
                    self.prune_unused_in_range(range, Some(first_entry_index), false);
                    return Err(NvFsError::MemoryAllocationFailure);
                }

                self.entries.splice(
                    next_entry_index..next_entry_index,
                    iter::repeat_with(|| {
                        let cur_bitmap_word_index = bitmap_word_index;
                        bitmap_word_index += 1;
                        SparseAllocBitmapEntry {
                            bitmap_word_index: cur_bitmap_word_index,
                            bitmap_word: 0,
                        }
                    })
                    .take(missing_bitmap_words_until_next),
                );
                bitmap_words_count -= missing_bitmap_words_until_next;
                next_entry_index += missing_bitmap_words_until_next;
                debug_assert!(
                    bitmap_words_count == 0 || bitmap_word_index == self.entries[next_entry_index].bitmap_word_index
                );

                bitmap_words_count = bitmap_words_count.saturating_sub(1);
                next_entry_index += 1;
            } else {
                bitmap_word_index += 1;
                bitmap_words_count -= 1;
                next_entry_index += 1;
            }
        }

        Ok(first_entry_index)
    }

    /// Prune unused entries in a given range.
    ///
    /// Prune entries overlapping with `range` that have their [bitmap
    /// word](SparseAllocBitmapEntry::bitmap_word) zero.
    ///
    /// # Arguments:
    ///
    /// * `range` - The physical range to prune overlapping entries in.
    /// * `first_entry_index_hint` - Optional hint specifying the index of the
    ///   first entry in [`Self::entries`] overlapping with `range`.
    /// * `prepare_for_rollback` - Whether to prepare for rollback of entry
    ///   removal, i.e. whether to record any removed entries at the
    ///   [`remove_rollback_reserve_capacity`](Self::remove_rollback_reserve_capacity).
    fn prune_unused_in_range(
        &mut self,
        range: &layout::PhysicalAllocBlockRange,
        first_entry_index_hint: Option<usize>,
        prepare_for_rollback: bool,
    ) {
        let (mut bitmap_word_index, mut bitmap_words_count) = {
            let physical_allocation_block_count = u64::from(range.block_count());
            let physical_allocation_block = u64::from(range.begin());
            let bitmap_word_index = physical_allocation_block >> BITMAP_WORD_BITS_LOG2;
            let offset_in_bitmap_word = physical_allocation_block & u64::trailing_bits_mask(BITMAP_WORD_BITS_LOG2);
            // Align the range to a multiple of the Bitmap Words.
            let physical_allocation_block_count = physical_allocation_block_count + offset_in_bitmap_word;
            let mut bitmap_words_count = physical_allocation_block_count >> BITMAP_WORD_BITS_LOG2;
            if bitmap_words_count << BITMAP_WORD_BITS_LOG2 != physical_allocation_block_count {
                bitmap_words_count += 1; // Also align the range in the upwards
                // direction.
            }
            (bitmap_word_index, bitmap_words_count)
        };

        let mut entry_index = match first_entry_index_hint {
            Some(first_entry_index_hint) => {
                debug_assert!(
                    first_entry_index_hint == self.entries.len()
                        || bitmap_word_index <= self.entries[first_entry_index_hint].bitmap_word_index
                );
                debug_assert!(
                    first_entry_index_hint == 0
                        || bitmap_word_index > self.entries[first_entry_index_hint - 1].bitmap_word_index
                );
                first_entry_index_hint
            }
            None => match self.find_entry_position(bitmap_word_index) {
                Ok(entry_index) => entry_index,
                Err(entry_index) => entry_index,
            },
        };

        while entry_index < self.entries.len() && bitmap_words_count != 0 {
            let next_bitmap_word_index = self.entries[entry_index].bitmap_word_index;
            debug_assert!(bitmap_word_index <= next_bitmap_word_index);
            bitmap_words_count = bitmap_words_count.saturating_sub(next_bitmap_word_index - bitmap_word_index);
            bitmap_word_index = next_bitmap_word_index;
            if bitmap_words_count == 0 {
                break;
            }

            if self.entries[entry_index].bitmap_word == 0 {
                let cur_batch_len = self.entries[entry_index + 1..]
                    .iter()
                    .enumerate()
                    .find(|(_i, e)| e.bitmap_word != 0 || e.bitmap_word_index - bitmap_word_index >= bitmap_words_count)
                    .map(|(i, _e)| i)
                    .unwrap_or(0)
                    + 1;

                let next_bitmap_word_index = self.entries[entry_index + cur_batch_len - 1].bitmap_word_index + 1;
                bitmap_words_count -= next_bitmap_word_index - bitmap_word_index;
                bitmap_word_index = next_bitmap_word_index;

                self.entries.drain(entry_index..entry_index + cur_batch_len);

                if prepare_for_rollback {
                    // Whenever reallocating, make sure there's enough capacity to readd the just
                    // removed words back.
                    self.remove_rollback_reserve_capacity += cur_batch_len;
                }
            } else {
                bitmap_word_index += 1;
                bitmap_words_count -= 1;
                entry_index += 1;
            }
        }
    }

    /// Set all bits in a given range to some specified value.
    ///
    /// Set any bit corresponding to some [Allocation
    /// Block](layout::ImageLayout::allocation_block_size_128b_log2) within
    /// `range` to the specified `value`.
    ///
    /// Only existing entries in the range will get updated and no new ones will
    /// be inserted,
    /// c.f. [populate_missing_in_range()](Self::populate_missing_in_range) for
    /// populating missing entries.
    ///
    /// * `range` - The physical range to set corresponding bits in.
    /// * `first_entry_index_hint` - Optional hint specifying the index of the
    ///   first entry in [`Self::entries`] overlapping with `range`.
    /// * `value` - The value to set the bits corresponding to [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2) in
    ///   `range` to.
    fn set_in_range(
        &mut self,
        range: &layout::PhysicalAllocBlockRange,
        first_entry_index_hint: Option<usize>,
        value: bool,
    ) -> usize {
        let mut physical_allocation_block_count = u64::from(range.block_count());
        let physical_allocation_block = u64::from(range.begin());
        let mut bitmap_word_index = physical_allocation_block >> BITMAP_WORD_BITS_LOG2;
        let mut offset_in_bitmap_word =
            (physical_allocation_block & u64::trailing_bits_mask(BITMAP_WORD_BITS_LOG2)) as u32;

        let first_entry_index = match first_entry_index_hint {
            Some(first_entry_index_hint) => {
                debug_assert!(
                    first_entry_index_hint == self.entries.len()
                        || bitmap_word_index <= self.entries[first_entry_index_hint].bitmap_word_index
                );
                debug_assert!(
                    first_entry_index_hint == 0
                        || bitmap_word_index > self.entries[first_entry_index_hint - 1].bitmap_word_index
                );
                first_entry_index_hint
            }
            None => match self.find_entry_position(bitmap_word_index) {
                Ok(entry_index) => entry_index,
                Err(entry_index) => entry_index,
            },
        };

        let set_mask = if value { !0 } else { 0 };
        let mut entry_index = first_entry_index;
        while entry_index != self.entries.len() && physical_allocation_block_count != 0 {
            let next_bitmap_word_index = self.entries[entry_index].bitmap_word_index;
            if next_bitmap_word_index != bitmap_word_index {
                let bits_in_words = ((next_bitmap_word_index - bitmap_word_index - 1) << BITMAP_WORD_BITS_LOG2)
                    + (u64::BITS - offset_in_bitmap_word) as u64;
                let bits_in_words = bits_in_words.min(physical_allocation_block_count);
                physical_allocation_block_count -= bits_in_words;
                bitmap_word_index = next_bitmap_word_index;
                offset_in_bitmap_word = 0;
                if physical_allocation_block_count == 0 {
                    break;
                }
            }

            let bits_in_word =
                physical_allocation_block_count.min((BitmapWord::BITS - offset_in_bitmap_word) as u64) as u32;
            let bits_in_word_mask = BitmapWord::trailing_bits_mask(bits_in_word) << offset_in_bitmap_word;
            self.entries[entry_index].bitmap_word &= !bits_in_word_mask;
            self.entries[entry_index].bitmap_word |= set_mask & bits_in_word_mask;

            physical_allocation_block_count -= bits_in_word as u64;
            bitmap_word_index += 1;
            offset_in_bitmap_word = 0;
            entry_index += 1;
        }

        first_entry_index
    }

    /// Failsafe rollback of a previous
    /// [`prune_unused_in_range()`](Self::prune_unused_in_range) operation.
    ///
    /// Any memory needed is drawn from the rollback reserve. The prior
    /// [`prune_unused_in_range()`](Self::prune_unused_in_range) to get rolled
    /// back must have been invoked with its `prepare_for_rollback` argument set
    /// to `true` and there must not
    /// have been any call to
    /// [`reset_remove_rollback()`](Self::reset_remove_rollback) in the
    /// meanwhile.
    ///
    /// # Arguments:
    ///
    /// * `range` - The physical range to add tracking entries to the
    ///   [`SparseAllocBitmap`] back for.
    /// * `alloc_bitmap` - The [`AllocBitmap`] relative to which the
    ///   [`SparseAllocBitmap`] is considered to track changes.
    /// * `alloc_bitmap_value` - The [`AllocBitmap`] bit value a set bit in the
    ///   [`SparseAllocBitmap`] corresponds to: if `true`, then the
    ///   [`SparseAllocBitmap`] tracks new allocations, or if `false`,
    ///   deallocations.
    fn repopulate_set_range_for_rollback(
        &mut self,
        range: &layout::PhysicalAllocBlockRange,
        alloc_bitmap: &AllocBitmap,
        alloc_bitmap_value: bool,
    ) -> Result<(), NvFsError> {
        if self.entries.capacity() - self.entries.len() < self.remove_rollback_reserve_capacity {
            return Err(nvfs_err_internal!());
        }

        let mut physical_allocation_block_count = u64::from(range.block_count());
        let physical_allocation_block = u64::from(range.begin());
        let mut bitmap_word_index = physical_allocation_block >> BITMAP_WORD_BITS_LOG2;
        let mut offset_in_bitmap_word =
            (physical_allocation_block & u64::trailing_bits_mask(BITMAP_WORD_BITS_LOG2)) as u32;

        let mut entry_index = match self.find_entry_position(bitmap_word_index) {
            Ok(entry_index) => entry_index,
            Err(entry_index) => entry_index,
        };

        let empty_sparse_alloc_bitmap = SparseAllocBitmapUnion::new(&[]);
        let mut alloc_bitmap_words_iter = AllocBitmapWordIterator::new_at_bitmap_word_index(
            alloc_bitmap,
            &empty_sparse_alloc_bitmap,
            &empty_sparse_alloc_bitmap,
            bitmap_word_index,
        );

        while bitmap_word_index << BITMAP_WORD_BITS_LOG2 < u64::from(range.end()) {
            let bits_in_word =
                physical_allocation_block_count.min((BitmapWord::BITS - offset_in_bitmap_word) as u64) as u32;
            physical_allocation_block_count -= bits_in_word as u64;
            let bits_in_word_mask = BitmapWord::trailing_bits_mask(bits_in_word) << offset_in_bitmap_word;
            offset_in_bitmap_word = 0;

            if entry_index < self.entries.len() && self.entries[entry_index].bitmap_word_index == bitmap_word_index {
                // A bitmap word had already been allocated for the current position, so no new
                // allocation needed. Just set the value without further
                // inspection.
                self.entries[entry_index].bitmap_word |= bits_in_word_mask;
                bitmap_word_index += 1;
                entry_index += 1;
                alloc_bitmap_words_iter.next();
                continue;
            }

            // Otherwise a new bitmap word allocation would be needed for the sparse bitmap.
            // Be careful to stay within the rollback capacity reserve and readd
            // only entries that had definitiely been present in the sparse
            // bitmap before the operation currently being rolled back removed them. That is
            // guaranteed only if there's a mismatch between the state rolled back to and
            // what's originally been in the alloc_bitmap.
            let alloc_bitmap_word = alloc_bitmap_words_iter
                .next()
                .map(|(_, bitmap_word)| bitmap_word)
                .unwrap_or(0);
            if alloc_bitmap_word & bits_in_word_mask == if alloc_bitmap_value { bits_in_word_mask } else { 0 } {
                // The alloc_bitmap has the value rolled back to, no entry in the sparse bitmap
                // needed.
                bitmap_word_index += 1;
                continue;
            }

            // The entry is needed again and must get readded.
            if self.remove_rollback_reserve_capacity == 0 {
                return Err(nvfs_err_internal!());
            }
            self.remove_rollback_reserve_capacity -= 1;

            self.entries.insert(
                entry_index,
                SparseAllocBitmapEntry {
                    bitmap_word_index,
                    bitmap_word: bits_in_word_mask,
                },
            );

            bitmap_word_index += 1;
            entry_index += 1;
        }

        Ok(())
    }
}

/// [`Iterator`] returned by [`SparseAllocBitmap::iter()`] and
/// [`SparseAllocBitmap::iter_at()`].
///
/// The iterator yields one [`BitmapWord`] for each entry in the associated
/// [`SparseAllocBitmap`], alongside the location of the first [Allocation
/// Block](layout::ImageLayout::allocation_block_size_128b_log2) tracked
/// therein on physical storage.
#[derive(Clone)]
pub struct SparseAllocBitmapIterator<'a> {
    sparse_bitmap: &'a SparseAllocBitmap,
    next_sparse_entry_index: usize,
}

impl<'a> SparseAllocBitmapIterator<'a> {
    /// Create a new [`SparseAllocBitmapIterator`] over a [`SparseAllocBitmap`],
    /// starting at its first entry.
    ///
    /// # Arguments:
    ///
    /// * `sparse_bitmap` - The [`SparseAllocBitmap`] whose entries to iterate
    ///   over.
    pub fn new(sparse_bitmap: &'a SparseAllocBitmap) -> Self {
        Self {
            sparse_bitmap,
            next_sparse_entry_index: 0,
        }
    }

    /// Create a new [`SparseAllocBitmapIterator`] over a [`SparseAllocBitmap`],
    /// starting from a given physical storage location.
    ///
    /// The iteration starts at the first [`SparseAllocBitmap`] entry
    /// overlapping with or following the physical [Allocation
    /// Block](layout::ImageLayout::allocation_block_size_128b_log2) specified
    /// by `physical_allocation_block_index`.
    ///
    /// # Arguments:
    ///
    /// * `sparse_bitmap` - The [`SparseAllocBitmap`] whose entries to iterate
    ///   over.
    /// * `physical_allocation_block_index` - Starting position of the
    ///   iteration.
    pub fn new_at(
        sparse_bitmap: &'a SparseAllocBitmap,
        physical_allocation_block_index: layout::PhysicalAllocBlockIndex,
    ) -> Self {
        let mut it = Self {
            sparse_bitmap,
            next_sparse_entry_index: 0,
        };
        it.skip_to(physical_allocation_block_index);
        it
    }

    /// Skip the [`SparseAllocBitmapIterator`] to a specified physical location.
    ///
    /// The iteration will continue with the next [`SparseAllocBitmap`] entry
    /// overlapping with or following the physical [Allocation
    /// Block](layout::ImageLayout::allocation_block_size_128b_log2) specified
    /// by `physical_allocation_block_index`.
    ///
    /// # Arguments:
    ///
    /// * `physical_allocation_block_index` - Position on physical storage to
    ///   skip to.
    pub fn skip_to(&mut self, physical_allocation_block_index: layout::PhysicalAllocBlockIndex) {
        let bitmap_word_index = u64::from(physical_allocation_block_index) >> BITMAP_WORD_BITS_LOG2;
        let sparse_bitmap_entries = &self.sparse_bitmap.entries;
        debug_assert!(
            self.next_sparse_entry_index == 0
                || sparse_bitmap_entries[self.next_sparse_entry_index - 1].bitmap_word_index < bitmap_word_index
        );

        if self.next_sparse_entry_index == sparse_bitmap_entries.len()
            || sparse_bitmap_entries[self.next_sparse_entry_index].bitmap_word_index >= bitmap_word_index
        {
            return;
        }

        self.next_sparse_entry_index += match sparse_bitmap_entries[self.next_sparse_entry_index..]
            .binary_search_by(|e| e.bitmap_word_index.cmp(&bitmap_word_index))
        {
            Ok(offset) => offset,
            Err(offset) => offset,
        }
    }
}

impl<'a> Iterator for SparseAllocBitmapIterator<'a> {
    type Item = (layout::PhysicalAllocBlockIndex, BitmapWord);

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_sparse_entry_index != self.sparse_bitmap.entries.len() {
            let entry = &self.sparse_bitmap.entries[self.next_sparse_entry_index];
            self.next_sparse_entry_index += 1;
            Some((
                layout::PhysicalAllocBlockIndex::from(entry.bitmap_word_index << BITMAP_WORD_BITS_LOG2),
                entry.bitmap_word,
            ))
        } else {
            None
        }
    }
}

/// [`Iterator`] returned by [`SparseAllocBitmap::block_iter()`] and
/// [`SparseAllocBitmap::block_iter_at()`].
///
/// The iterator yields one [`BitmapWord`] per block at a time, with its least
/// significant bits being set to the respective bit values in the current
/// block, alongside the location of the block's first [Allocation
/// Block](layout::ImageLayout::allocation_block_size_128b_log2) on
/// physical storage.
#[derive(Clone)]
pub struct SparseAllocBitmapBlockIterator<'a> {
    sparse_bitmap_iter: SparseAllocBitmapIterator<'a>,
    cur_sparse_bitmap_word: Option<(layout::PhysicalAllocBlockIndex, BitmapWord)>,
    next_pos_in_cur_sparse_bitmap_word: u32,
    block_allocation_blocks_log2: u32,
}

impl<'a> SparseAllocBitmapBlockIterator<'a> {
    /// Create a new [`SparseAllocBitmapBlockIterator`] over a
    /// [`SparseAllocBitmap`], starting at its first entry.
    ///
    /// # Arguments:
    ///
    /// * `sparse_bitmap` - The [`SparseAllocBitmap`] whose entries to iterate
    ///   over.
    /// * `block_allocation_blocks_log2` - The block size and alignment, must be
    ///   less than or equal to [`BitmapWord::BITS`].
    pub fn new(sparse_bitmap: &'a SparseAllocBitmap, block_allocation_blocks_log2: u32) -> Self {
        debug_assert!(block_allocation_blocks_log2 <= BITMAP_WORD_BITS_LOG2);
        let mut sparse_bitmap_iter = SparseAllocBitmapIterator::new(sparse_bitmap);
        let cur_sparse_bitmap_word = sparse_bitmap_iter.next();

        Self {
            sparse_bitmap_iter,
            cur_sparse_bitmap_word,
            next_pos_in_cur_sparse_bitmap_word: 0,
            block_allocation_blocks_log2,
        }
    }

    /// Create a new [`SparseAllocBitmapBlockIterator`] over a
    /// [`SparseAllocBitmap`], starting from a given physical storage
    /// location.
    ///
    /// The iteration starts at the first block at or subsequent to the physical
    /// [Allocation
    /// Block](layout::ImageLayout::allocation_block_size_128b_log2) specified
    /// by `physical_allocation_blocks_begin` and covered by some entry in
    /// the [`SparseAllocBitmap`].
    ///
    /// # Arguments:
    ///
    /// * `sparse_bitmap` - The [`SparseAllocBitmap`] whose entries to iterate
    ///   over.
    /// * `physical_allocation_blocks_begin` - Starting location, must be
    ///   aligned by two to power of  `block_allocation_blocks_log2`.
    /// * `block_allocation_blocks_log2` - The block size and alignment, must be
    ///   less than or equal to [`BitmapWord::BITS`].
    pub fn new_at(
        sparse_bitmap: &'a SparseAllocBitmap,
        block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        block_allocation_blocks_log2: u32,
    ) -> Self {
        debug_assert!(block_allocation_blocks_log2 <= BITMAP_WORD_BITS_LOG2);
        debug_assert!(u64::from(block_allocation_blocks_begin).is_aligned_pow2(block_allocation_blocks_log2));
        let mut sparse_bitmap_iter = SparseAllocBitmapIterator::new_at(sparse_bitmap, block_allocation_blocks_begin);
        let cur_sparse_bitmap_word = sparse_bitmap_iter.next();
        let next_pos_in_cur_sparse_bitmap_word = if cur_sparse_bitmap_word
            .as_ref()
            .map(|cur_sparse_bitmap_word| {
                (u64::from(cur_sparse_bitmap_word.0) ^ u64::from(block_allocation_blocks_begin))
                    >> BITMAP_WORD_BITS_LOG2
                    == 0
            })
            .unwrap_or(false)
        {
            (u64::from(block_allocation_blocks_begin) & u64::trailing_bits_mask(BITMAP_WORD_BITS_LOG2)) as u32
        } else {
            0
        };

        Self {
            sparse_bitmap_iter,
            cur_sparse_bitmap_word,
            next_pos_in_cur_sparse_bitmap_word,
            block_allocation_blocks_log2,
        }
    }

    /// Skip the [`SparseAllocBitmapBlockIterator`] to a specified physical
    /// location.
    ///
    /// The iteration will continue with the next block at or subsequent to the
    /// physical [Allocation
    /// Block](layout::ImageLayout::allocation_block_size_128b_log2) specified
    /// by `physical_allocation_blocks_begin` and covered by some entry in
    /// the [`SparseAllocBitmap`].
    ///
    /// # Arguments:
    ///
    /// * `block_allocation_blocks_begin` - Position on physical storage to skip
    ///   to.
    pub fn skip_to(&mut self, block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex) {
        debug_assert!(u64::from(block_allocation_blocks_begin).is_aligned_pow2(self.block_allocation_blocks_log2));
        let cur_sparse_bitmap_word = match &self.cur_sparse_bitmap_word {
            Some(cur_sparse_bitmap_word) => cur_sparse_bitmap_word,
            None => return,
        };

        debug_assert!(block_allocation_blocks_begin >= cur_sparse_bitmap_word.0);
        if (u64::from(block_allocation_blocks_begin) ^ u64::from(cur_sparse_bitmap_word.0)) >> BITMAP_WORD_BITS_LOG2
            != 0
        {
            self.sparse_bitmap_iter.skip_to(block_allocation_blocks_begin);
            self.cur_sparse_bitmap_word = self.sparse_bitmap_iter.next();
            if self
                .cur_sparse_bitmap_word
                .as_ref()
                .map(|cur_sparse_bitmap_word| {
                    (u64::from(cur_sparse_bitmap_word.0) ^ u64::from(block_allocation_blocks_begin))
                        >> BITMAP_WORD_BITS_LOG2
                        != 0
                })
                .unwrap_or(true)
            {
                self.next_pos_in_cur_sparse_bitmap_word = 0;
                return;
            }
        }

        self.next_pos_in_cur_sparse_bitmap_word =
            (u64::from(block_allocation_blocks_begin) & u64::trailing_bits_mask(BITMAP_WORD_BITS_LOG2)) as u32;
    }
}

impl<'a> Iterator for SparseAllocBitmapBlockIterator<'a> {
    type Item = (layout::PhysicalAllocBlockIndex, BitmapWord);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let cur_sparse_bitmap_word = self.cur_sparse_bitmap_word?;
            let block_allocation_blocks = 1u32 << self.block_allocation_blocks_log2;
            let cur_block_allocation_blocks_begin = cur_sparse_bitmap_word.0
                + layout::AllocBlockCount::from(self.next_pos_in_cur_sparse_bitmap_word as u64);
            let cur_block_allocation_bitmap = (cur_sparse_bitmap_word.1 >> self.next_pos_in_cur_sparse_bitmap_word)
                & BitmapWord::trailing_bits_mask(block_allocation_blocks);
            self.next_pos_in_cur_sparse_bitmap_word += block_allocation_blocks;

            if self.next_pos_in_cur_sparse_bitmap_word >= BitmapWord::BITS {
                debug_assert!(self.next_pos_in_cur_sparse_bitmap_word == BitmapWord::BITS);
                self.next_pos_in_cur_sparse_bitmap_word = 0;
                self.cur_sparse_bitmap_word = self.sparse_bitmap_iter.next();
            }

            // Only yield blocks that have some bits set within them.
            if cur_block_allocation_bitmap == 0 {
                continue;
            }

            return Some((cur_block_allocation_blocks_begin, cur_block_allocation_bitmap));
        }
    }
}

/// Lightweight set union view over a fixed list of [`SparseAllocBitmap`]s.
pub struct SparseAllocBitmapUnion<'a, const N: usize> {
    bitmaps: &'a [&'a SparseAllocBitmap; N],
}

impl<'a, const N: usize> SparseAllocBitmapUnion<'a, N> {
    /// Create a [`SparseAllocBitmapUnion`] over a list of [`SparseAllocBitmap`]
    /// references.
    ///
    /// # Arguments:
    ///
    /// * `bitmaps` - References to the [`SparseAllocBitmap`]s to form the set
    ///   union view over.
    pub fn new(bitmaps: &'a [&'a SparseAllocBitmap; N]) -> Self {
        Self { bitmaps }
    }

    /// Iterate over the virtually merged [`SparseAllocBitmap`]s' entries.
    ///
    /// The returned iterator yields one [`BitmapWord`] for each entry from the
    /// union, alongside the location of the first [Allocation
    /// Block](layout::ImageLayout::allocation_block_size_128b_log2) tracked
    /// therein on physical storage in units of [`BitmapWord::BITS`] [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    pub fn iter(&self) -> SparseAllocBitmapUnionWordIterator<'_, N> {
        SparseAllocBitmapUnionWordIterator::new(self)
    }

    /// Iterate over the virtually merged [`SparseAllocBitmap`]s' entries,
    /// starting from a given physical storage location.
    ///
    /// The returned iterator yields one [`BitmapWord`] for each entry from the
    /// union, alongside the location of the first [Allocation
    /// Block](layout::ImageLayout::allocation_block_size_128b_log2) tracked
    /// therein on physical storage in units of [`BitmapWord::BITS`] [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    ///
    /// The iteration starts at the first entry corresponding to a physical
    /// location at or after the one specified
    /// by `bitmap_word_index_begin` as an index into physical storage in units
    /// of [`BitmapWord::BITS`] [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    ///
    /// # Arguments:
    ///
    /// * `bitmap_word_index_begin` - Starting position of the iteration,
    ///   specified as an index into physical storage in units of
    ///   [`BitmapWord::BITS`] [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    pub(super) fn iter_at_bitmap_word_index(
        &self,
        bitmap_word_index_begin: u64,
    ) -> SparseAllocBitmapUnionWordIterator<'_, N> {
        SparseAllocBitmapUnionWordIterator::new_at_bitmap_word_index(self, bitmap_word_index_begin)
    }
}

pub struct SparseAllocBitmapUnionWordIterator<'a, const N: usize> {
    bitmap_union: &'a SparseAllocBitmapUnion<'a, N>,
    next_sparse_entry_indices: [Option<usize>; N],
}

impl<'a, const N: usize> SparseAllocBitmapUnionWordIterator<'a, N> {
    /// Create a new [`SparseAllocBitmapUnionWordIterator`] associated with a
    /// given [`SparseAllocBitmapUnion`], starting at the virtual union's first
    /// entry.
    ///
    /// # Arguments:
    ///
    /// * `bitmap_union` - The union whose entries to iterate over.
    fn new(bitmap_union: &'a SparseAllocBitmapUnion<'a, N>) -> Self {
        let next_sparse_entry_indices = array::from_fn(|i| {
            if !bitmap_union.bitmaps[i].entries.is_empty() {
                Some(0)
            } else {
                None
            }
        });
        Self {
            bitmap_union,
            next_sparse_entry_indices,
        }
    }

    /// Create a new [`SparseAllocBitmapUnionWordIterator`] associated with a
    /// given [`SparseAllocBitmapUnion`], starting at the virtual union's
    /// first entry at or after a given physical storage location.
    ///
    /// # Arguments:
    ///
    /// * `bitmap_union` - The union whose entries to iterate over.
    /// * `bitmap_word_index_begin` - Starting position of the iteration,
    ///   specified as an index into physical storage in units of
    ///   [`BitmapWord::BITS`] [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    fn new_at_bitmap_word_index(bitmap_union: &'a SparseAllocBitmapUnion<'a, N>, bitmap_word_index_begin: u64) -> Self {
        let next_sparse_entry_indices =
            array::from_fn(
                |i| match bitmap_union.bitmaps[i].find_entry_position(bitmap_word_index_begin) {
                    Ok(next_sparse_index) => Some(next_sparse_index),
                    Err(next_sparse_index) => {
                        if next_sparse_index != bitmap_union.bitmaps[i].entries.len() {
                            Some(next_sparse_index)
                        } else {
                            None
                        }
                    }
                },
            );
        Self {
            bitmap_union,
            next_sparse_entry_indices,
        }
    }

    /// Move the [`SparseAllocBitmapUnionWordIterator`] to a given physical
    /// storage location.
    ///
    /// The iteration will continue with  the virtual union's first entry
    /// corresponding to a physical location at or after the one specified
    /// by `bitmap_word_index` as an index into physical storage in units
    /// of [`BitmapWord::BITS`] [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    ///
    /// "Jumping back" from the current iterators current position is explicitly
    /// supported.
    ///
    /// # Arguments:
    ///
    /// * `bitmap_word_index` - Position to move to, specified as an index into
    ///   physical storage in units of [`BitmapWord::BITS`] [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    pub(super) fn goto_bitmap_word_index(&mut self, bitmap_word_index: u64) {
        for i in 0..self.next_sparse_entry_indices.len() {
            // Handle the trivial cases directly if possible.
            if let Some(next_sparse_index) = self.next_sparse_entry_indices[i] {
                let entry_next_bitmap_word_index =
                    self.bitmap_union.bitmaps[i].entries[next_sparse_index].bitmap_word_index;
                if entry_next_bitmap_word_index == bitmap_word_index {
                    continue;
                } else if entry_next_bitmap_word_index + 1 == bitmap_word_index {
                    self.next_sparse_entry_indices[i] =
                        if next_sparse_index + 1 != self.bitmap_union.bitmaps[i].entries.len() {
                            Some(next_sparse_index + 1)
                        } else {
                            None
                        };
                    continue;
                }
            }

            // Otherwise do a lookup.
            self.next_sparse_entry_indices[i] =
                match self.bitmap_union.bitmaps[i].find_entry_position(bitmap_word_index) {
                    Ok(next_sparse_index) => Some(next_sparse_index),
                    Err(next_sparse_index) => {
                        if next_sparse_index != self.bitmap_union.bitmaps[i].entries.len() {
                            Some(next_sparse_index)
                        } else {
                            None
                        }
                    }
                };
        }
    }
}

impl<'a, const N: usize> Iterator for SparseAllocBitmapUnionWordIterator<'a, N> {
    type Item = (u64, BitmapWord);

    fn next(&mut self) -> Option<Self::Item> {
        // The compiler might be able to deduce that on its own, but help it out a bit
        // in case not.
        if N == 0 {
            return None;
        }
        let (mut i, next_sparse_index) =
            self.next_sparse_entry_indices
                .iter()
                .enumerate()
                .find_map(|(i, next_sparse_entry_index)| {
                    next_sparse_entry_index.map(|next_sparse_entry_index| (i, next_sparse_entry_index))
                })?;
        let mut next_bitmap_word_index = self.bitmap_union.bitmaps[i].entries[next_sparse_index].bitmap_word_index;
        let mut bitmap_word = self.bitmap_union.bitmaps[i].entries[next_sparse_index].bitmap_word;

        for j in i + 1..N {
            if let Some(next_sparse_index) = self.next_sparse_entry_indices[j] {
                let entry_next_bitmap_word_index =
                    self.bitmap_union.bitmaps[j].entries[next_sparse_index].bitmap_word_index;
                match entry_next_bitmap_word_index.cmp(&next_bitmap_word_index) {
                    cmp::Ordering::Less => {
                        i = j;
                        next_bitmap_word_index = entry_next_bitmap_word_index;
                        bitmap_word = self.bitmap_union.bitmaps[j].entries[next_sparse_index].bitmap_word;
                    }
                    cmp::Ordering::Equal => {
                        bitmap_word |= self.bitmap_union.bitmaps[j].entries[next_sparse_index].bitmap_word;
                    }
                    cmp::Ordering::Greater => (),
                }
            }
        }
        for j in i..N {
            if let Some(mut next_sparse_index) = self.next_sparse_entry_indices[j] {
                let entry_next_bitmap_word_index =
                    self.bitmap_union.bitmaps[j].entries[next_sparse_index].bitmap_word_index;
                if entry_next_bitmap_word_index == next_bitmap_word_index {
                    next_sparse_index += 1;
                    if next_sparse_index != self.bitmap_union.bitmaps[j].entries.len() {
                        self.next_sparse_entry_indices[j] = Some(next_sparse_index);
                    } else {
                        self.next_sparse_entry_indices[j] = None;
                    }
                }
            }
        }
        Some((next_bitmap_word_index, bitmap_word))
    }
}
