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
mod aux_fs_metadata;
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
    InconsistentBackupMkFsInfoHeader = 7,
    InvalidAuxFsMetadataChecksum = 8,
    InvalidAuxFsMetadataSize = 9,
    InvalidAuxFsMetadataExtent = 10,
    UnalignedAuxFsMetadataExtent = 11,
    IncoherentAuxFsMetadataExtents = 12,
    InconsistentAuxFsMetadataExtentsChain = 13,
    InvalidAuxFsMetadataExtentFormat = 14,
    InvalidAuxFsMetadataFormat = 15,
    InvalidSaltLength = 16,
    IoBlockSizeNotSupportedByDevice = 17,
    InvalidImageSize = 18,
    InvalidAuthTreeConfig = 19,
    UnsupportedAuthTreeConfig = 20,
    UnalignedAuthTreeExtents = 21,
    InvalidAuthTreeDimensions = 22,
    InvalidAllocationBitmapFileConfig = 23,
    UnalignedAllocationBitmapFileExtents = 24,
    InvalidAllocationBitmapFileSize = 25,
    InconsistentAllocBitmapFileExtents = 26,
    InvalidDigestLength = 27,
    InvalidFileSize = 28,
    BlockOutOfRange = 29,
    InvalidExtents = 30,
    InvalidPadding = 31,
    InvalidIndexConfig = 32,
    InvalidIndexNode = 33,
    InvalidIndexRootExtents = 34,
    SpecialInodeMissing = 35,
    UnalignedJournalExtents = 36,

    InvalidJournalLogFieldTagEncoding = 37,
    InvalidJournalLogFieldLengthEncoding = 38,
    InvalidJournalLogFieldTag = 39,
    JournalLogFieldLengthOverflow = 40,

    IncompleteJournalLog = 41,
    UnexpectedJournalLogField = 42,
    JournalLogFieldLengthOutOfBounds = 43,
    ExcessJournalLogFieldLength = 44,

    InvalidJournalExtentsCoveringAuthDigestsFormat = 45,
    InvalidJournalExtentsCoveringAuthDigestsEntry = 46,
    UnexpectedJournalExtentsCoveringAuthDigestsEntry = 47,

    InvalidJournalApplyWritesScriptFormat = 48,
    InvalidJournalApplyWritesScriptEntry = 49,
    InvalidJournalUpdateAuthDigestsScriptFormat = 50,
    InvalidJournalUpdateAuthDigestsScriptEntry = 51,
    InvalidJournalTrimsScriptFormat = 52,
    InvalidJournalTrimsScriptEntry = 53,
}

impl convert::From<FormatError> for NvFsError {
    fn from(value: FormatError) -> Self {
        Self::FsFormatError(value as isize)
    }
}

pub use aux_fs_metadata::{AuxFsMetadata, AuxFsMetadataIter, AuxFsMetadataPushError};
pub use fs::CocoonFs;
pub use image_header::FsMetadataMkFsInfo;
pub use layout::ImageLayout;
pub use mkfs::{MkFsFuture, WriteMkFsInfoHeaderFuture};
pub use openfs::{FsMetadata, FsMetadataFormatted, OpenFsFuture, ReadFsMetadataFuture};
