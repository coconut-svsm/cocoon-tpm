// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Defininitions and functionality related to an
//! [`AllocBitmap`](super::AllocBitmap)'s [`BitmapWord`].

/// [`AllocBitmap`](super::AllocBitmap) word.
pub type BitmapWord = u64;

/// Base-2 logarithm of [`BitmapWord::BITS`].
pub const BITMAP_WORD_BITS_LOG2: u32 = BitmapWord::BITS.ilog2();

/// Table of [`BitmapWord`] constants with a set of equidistant bits set, for
/// different power of two distances each.
pub struct BitmapWordBlocksLsbsMaskTable {
    word_blocks_lsbs_masks_table: [BitmapWord; BITMAP_WORD_BITS_LOG2 as usize - 1],
}

impl BitmapWordBlocksLsbsMaskTable {
    pub const fn new() -> Self {
        Self {
            word_blocks_lsbs_masks_table: Self::init_word_blocks_lsbs_masks_table(),
        }
    }

    /// Retrieve a table entry.
    ///
    /// Group the [`BitmapWord`]'s bits into equally sized blocks of
    /// *2<sup>`block_allocation_blocks_log2`</sup> bits and set the least
    /// significant one in each.
    pub const fn get_blocks_lsbs_mask(&self, block_allocation_blocks_log2: u32) -> BitmapWord {
        if block_allocation_blocks_log2 == 0 {
            !0
        } else if block_allocation_blocks_log2 == BITMAP_WORD_BITS_LOG2 {
            1
        } else {
            self.word_blocks_lsbs_masks_table[block_allocation_blocks_log2 as usize - 1]
        }
    }

    /// Initialize the [`Self::word_blocks_lsbs_masks_table`].
    const fn init_word_blocks_lsbs_masks_table() -> [BitmapWord; BITMAP_WORD_BITS_LOG2 as usize - 1] {
        let mut blocks_lsbs_masks_table = [0; BITMAP_WORD_BITS_LOG2 as usize - 1];
        let mut blocks_lsbs_mask = 1 as BitmapWord;
        let mut block_allocation_blocks_log2 = BITMAP_WORD_BITS_LOG2;
        while block_allocation_blocks_log2 > 1 {
            block_allocation_blocks_log2 -= 1;
            let block_allocation_blocks = 1u32 << block_allocation_blocks_log2;
            blocks_lsbs_mask = blocks_lsbs_mask | (blocks_lsbs_mask << block_allocation_blocks);
            blocks_lsbs_masks_table[block_allocation_blocks_log2 as usize - 1] = blocks_lsbs_mask;
        }
        blocks_lsbs_masks_table
    }

    /// Compute a table entry directly without a table lookup.
    #[allow(dead_code)]
    const fn compute_blocks_lsbs_mask(block_allocation_blocks_log2: u32) -> BitmapWord {
        if block_allocation_blocks_log2 == BITMAP_WORD_BITS_LOG2 {
            1
        } else {
            let block_allocation_blocks = 1u32 << block_allocation_blocks_log2;
            let block_allocation_blocks_mask = ((1 as BitmapWord) << block_allocation_blocks) - 1;
            !(0 as BitmapWord) / block_allocation_blocks_mask
        }
    }
}
