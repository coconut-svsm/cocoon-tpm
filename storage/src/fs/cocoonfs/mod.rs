// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 SUSE LLC
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
mod checksum;
mod crc32;
mod encryption_entities;
mod extent_ptr;
mod extents;
mod extents_layout;
mod fs;
mod image_header;
mod inode_extents_list;
mod inode_index;
mod integrity;
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
mod write_inode_data;

#[cfg(test)]
mod test;

use crate::fs::NvFsError;
use core::convert;

/// [`CocoonFs`] specific [filesystem format
/// errors](crate::fs::NvFsError::FsFormatError).
pub enum FormatError {
    InvalidDeviceParameter = 1,
    InvalidImageHeader = 2,
    UnsupportedFormatVersion = 3,
    InvalidImageLayoutConfig = 4,
    UnsupportedImageLayoutConfig = 5,
    UnsupportedCryptoAlgorithm = 6,
    InvalidSaltLength = 7,
    IoBlockSizeNotSupportedByDevice = 8,
    InvalidImageSize = 9,
    InvalidAuthTreeConfig = 10,
    UnsupportedAuthTreeConfig = 11,
    UnalignedAuthTreeExtents = 12,
    InvalidAuthTreeDimensions = 13,
    InvalidAllocationBitmapFileConfig = 14,
    UnalignedAllocationBitmapFileExtents = 15,
    InvalidAllocationBitmapFileSize = 16,
    InconsistentAllocBitmapFileExtents = 17,
    InvalidDigestLength = 18,
    InvalidFileSize = 19,
    BlockOutOfRange = 20,
    InvalidExtents = 21,
    InvalidPadding = 22,
    InvalidIndexConfig = 23,
    InvalidIndexNode = 24,
    InvalidIndexRootExtents = 25,
    SpecialInodeMissing = 26,
    UnalignedJournalExtents = 27,

    InvalidJournalLogFieldTagEncoding = 28,
    InvalidJournalLogFieldLengthEncoding = 29,
    InvalidJournalLogFieldTag = 30,
    JournalLogFieldLengthOverflow = 31,

    IncompleteJournalLog = 32,
    UnexpectedJournalLogField = 33,
    JournalLogFieldLengthOutOfBounds = 34,
    ExcessJournalLogFieldLength = 35,

    InvalidJournalExtentsCoveringAuthDigestsFormat = 36,
    InvalidJournalExtentsCoveringAuthDigestsEntry = 37,
    UnexpectedJournalExtentsCoveringAuthDigestsEntry = 38,

    InvalidJournalApplyWritesScriptFormat = 39,
    InvalidJournalApplyWritesScriptEntry = 40,
    InvalidJournalUpdateAuthDigestsScriptFormat = 41,
    InvalidJournalUpdateAuthDigestsScriptEntry = 42,
    InvalidJournalTrimsScriptFormat = 43,
    InvalidJournalTrimsScriptEntry = 44,
}

impl convert::From<FormatError> for NvFsError {
    fn from(value: FormatError) -> Self {
        Self::FsFormatError(value as isize)
    }
}

pub use fs::CocoonFs;
pub use layout::ImageLayout;
pub use mkfs::{MkFsFuture, WriteMkFsInfoHeaderFuture};
pub use openfs::{FsMetadata, OpenFsFuture, ReadFsMetadataFuture};
