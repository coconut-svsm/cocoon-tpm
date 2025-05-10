// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Functionality related to the allocation bitmap.

mod bitmap;
mod bitmap_word;
mod file;
mod sparse_bitmap;

pub use bitmap::{AllocBitmap, ExtentsAllocationRequest, ExtentsReallocationRequest};
pub use bitmap_word::{BITMAP_WORD_BITS_LOG2, BitmapWord};
pub use file::{
    AllocBitmapFile, AllocBitmapFileInitializeFuture, AllocBitmapFileReadFuture,
    AllocBitmapFileReadJournalFragmentsFuture,
};
pub use sparse_bitmap::{SparseAllocBitmap, SparseAllocBitmapBlockIterator, SparseAllocBitmapUnion};
