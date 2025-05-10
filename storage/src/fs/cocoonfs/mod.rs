// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! [`CocoonFs`] -- a secure [`NvFs`](crate::fs::NvFs) implementation.

mod alloc_bitmap;
mod auth_subject_ids;
mod auth_tree;
mod encryption_entities;
mod extent_ptr;
mod extents;
mod extents_layout;
mod fs;
mod image_header;
mod inode_extents_list;
mod inode_index;
mod journal;
mod keys;
mod layout;
mod leb128;
mod mkfs;
mod openfs;
mod read_authenticate_extent;
mod read_buffer;
mod read_inode_data;
mod read_preauth;
mod set_assoc_cache;
mod transaction;
mod write_blocks;
mod write_inode_data;

#[cfg(test)]
mod test;

use crate::fs::NvFsError;
use core::convert;

/// [`CocoonFs`] specific [filesystem format
/// errors](crate::fs::NvFsError::FsFormatError).
pub enum CocoonFsFormatError {
    InvalidDeviceParameter = 1,
    InvalidImageHeaderFormat = 2,
    InvalidImageHeaderMagic = 3,
    UnsupportedFormatVersion = 4,
    InvalidImageLayoutConfig = 5,
    UnsupportedImageLayoutConfig = 6,
    UnsupportedCryptoAlgorithm = 7,
    InvalidSaltLength = 8,
    IoBlockSizeNotSupportedByDevice = 9,
    InvalidImageSize = 10,
    InvalidAuthTreeConfig = 11,
    UnsupportedAuthTreeConfig = 12,
    UnalignedAuthTreeExtents = 13,
    InvalidAuthTreeDimensions = 14,
    InvalidAllocationBitmapFileConfig = 15,
    UnalignedAllocationBitmapFileExtents = 16,
    InvalidAllocationBitmapFileSize = 17,
    InconsistentAllocBitmapFileExtents = 18,
    InvalidDigestLength = 19,
    InvalidFileSize = 20,
    BlockOutOfRange = 21,
    InvalidExtents = 22,
    InvalidPadding = 23,
    InvalidIndexConfig = 24,
    InvalidIndexNode = 25,
    InvalidIndexRootExtents = 26,
    SpecialInodeMissing = 27,
    UnalignedJournalExtents = 28,

    InvalidJournalLogFieldTagEncoding = 29,
    InvalidJournalLogFieldLengthEncoding = 30,
    InvalidJournalLogFieldTag = 31,
    JournalLogFieldLengthOverflow = 32,

    IncompleteJournalLog = 33,
    UnexpectedJournalLogField = 34,
    JournalLogFieldLengthOutOfBounds = 35,
    ExcessJournalLogFieldLength = 36,

    InvalidJournalExtentsCoveringAuthDigestsFormat = 37,
    InvalidJournalExtentsCoveringAuthDigestsEntry = 38,
    UnexpectedJournalExtentsCoveringAuthDigestsEntry = 39,

    InvalidJournalApplyWritesScriptFormat = 40,
    InvalidJournalApplyWritesScriptEntry = 41,
    InvalidJournalUpdateAuthDigestsScriptFormat = 42,
    InvalidJournalUpdateAuthDigestsScriptEntry = 43,
    InvalidJournalTrimsScriptFormat = 44,
    InvalidJournalTrimsScriptEntry = 45,
}

impl convert::From<CocoonFsFormatError> for NvFsError {
    fn from(value: CocoonFsFormatError) -> Self {
        Self::FsFormatError(value as isize)
    }
}

pub use fs::CocoonFs;
pub use mkfs::CocoonFsMkFsFuture;
pub use openfs::CocoonFsOpenFsFuture;
