// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! [`CocoonFs`] -- a secure [`NvFs`](crate::fs::NvFs) implementation.
//!
//! CocoonFs is a special purpose filesystem format designed for the secure
//! storage of sensitive data in e.g. a TEE setting. In addition to its primary
//! design focus on strong security properties, the format implements support
//! for some features of particular relevance to the intended use-case, such as
//! support for [keyless storage volume provisiong](WriteMkFsInfoHeaderFuture)
//! and robustness against service interruptions by means of a journal.
//!
//! For the format specification, refer to file `cocoonfs-format.md` distributed
//! with the code, see
//! [here](https://coconut-svsm.github.io/cocoon-tpm/cocoonfs/cocoonfs-format.html)
//! for a rendered version.

mod alloc_bitmap;
mod auth_subject_ids;
mod auth_tree;
mod crc32;
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
pub enum FormatError {
    InvalidDeviceParameter = 1,
    InvalidImageHeaderFormat = 2,
    InvalidImageHeaderMagic = 3,
    UnsupportedFormatVersion = 4,
    InvalidImageHeaderChecksum = 5,
    InvalidImageLayoutConfig = 6,
    UnsupportedImageLayoutConfig = 7,
    UnsupportedCryptoAlgorithm = 8,
    InvalidSaltLength = 9,
    IoBlockSizeNotSupportedByDevice = 10,
    InvalidImageSize = 11,
    InvalidAuthTreeConfig = 12,
    UnsupportedAuthTreeConfig = 13,
    UnalignedAuthTreeExtents = 14,
    InvalidAuthTreeDimensions = 15,
    InvalidAllocationBitmapFileConfig = 16,
    UnalignedAllocationBitmapFileExtents = 17,
    InvalidAllocationBitmapFileSize = 18,
    InconsistentAllocBitmapFileExtents = 19,
    InvalidDigestLength = 20,
    InvalidFileSize = 21,
    BlockOutOfRange = 22,
    InvalidExtents = 23,
    InvalidPadding = 24,
    InvalidIndexConfig = 25,
    InvalidIndexNode = 26,
    InvalidIndexRootExtents = 27,
    SpecialInodeMissing = 28,
    UnalignedJournalExtents = 29,

    InvalidJournalLogFieldTagEncoding = 30,
    InvalidJournalLogFieldLengthEncoding = 31,
    InvalidJournalLogFieldTag = 32,
    JournalLogFieldLengthOverflow = 33,

    IncompleteJournalLog = 34,
    UnexpectedJournalLogField = 35,
    JournalLogFieldLengthOutOfBounds = 36,
    ExcessJournalLogFieldLength = 37,

    InvalidJournalExtentsCoveringAuthDigestsFormat = 38,
    InvalidJournalExtentsCoveringAuthDigestsEntry = 39,
    UnexpectedJournalExtentsCoveringAuthDigestsEntry = 40,

    InvalidJournalApplyWritesScriptFormat = 41,
    InvalidJournalApplyWritesScriptEntry = 42,
    InvalidJournalUpdateAuthDigestsScriptFormat = 43,
    InvalidJournalUpdateAuthDigestsScriptEntry = 44,
    InvalidJournalTrimsScriptFormat = 45,
    InvalidJournalTrimsScriptEntry = 46,
}

impl convert::From<FormatError> for NvFsError {
    fn from(value: FormatError) -> Self {
        Self::FsFormatError(value as isize)
    }
}

pub use fs::CocoonFs;
pub use layout::ImageLayout;
pub use mkfs::{MkFsFuture, WriteMkFsInfoHeaderFuture};
pub use openfs::OpenFsFuture;
