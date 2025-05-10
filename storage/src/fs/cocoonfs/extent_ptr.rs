// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`EncodedExtentPtr`] and [`EncodedBlockPtr`].

use crate::{
    fs::{
        NvFsError,
        cocoonfs::{CocoonFsFormatError, layout},
    },
    nvfs_err_internal,
};
use core::{convert, mem, ops};

/// Encoded extent pointer format.
///
/// An encoded extent pointer, if non-NIL, specifies the location of an extent
/// of up to 64 [Allocation
/// Blocks](layout::ImageLayout::allocation_block_size_128b_log2) in length.
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct EncodedExtentPtr {
    encoded_extent_ptr: [u8; mem::size_of::<u64>()],
}

impl EncodedExtentPtr {
    /// Number of bits used for encoding the extent length.
    const EXTENT_ALLOCATION_BLOCKS_ENCODING_BITS: u32 = 6u32;
    /// Maximum extent length that can be encoded.
    pub const MAX_EXTENT_ALLOCATION_BLOCKS: u64 = 1u64 << Self::EXTENT_ALLOCATION_BLOCKS_ENCODING_BITS;

    /// Encoded length of an [`EncodedExtentPtr`].
    pub const ENCODED_SIZE: u32 = mem::size_of::<u64>() as u32;

    /// Encode an [`EncodedExtentPtr`].
    ///
    /// # Arguments:
    ///
    /// * `extent` - The extent location wrapped in a `Some`, or `None` to
    ///   encode a special "NIL" value. If an extent is given, then its length
    ///   must not exceed
    ///   [`MAX_EXTENT_ALLOCATION_BLOCKS`](Self::MAX_EXTENT_ALLOCATION_BLOCKS).
    /// * `indirect` - Whether or not to set the "indirect" bit in the
    ///   [`EncodedExtentPtr`], i.e. whether `extent` refers to some inode's
    ///   extents list head extent or not.
    pub fn encode(extent: Option<&layout::PhysicalAllocBlockRange>, indirect: bool) -> Result<Self, NvFsError> {
        let extent = match extent {
            Some(extent) => extent,
            None => return Ok(Self::encode_nil()),
        };

        let extent_allocation_blocks = u64::from(extent.block_count());
        if extent_allocation_blocks == 0 || extent_allocation_blocks > Self::MAX_EXTENT_ALLOCATION_BLOCKS {
            return Err(nvfs_err_internal!());
        }
        let encoded_extent_allocation_blocks = extent_allocation_blocks - 1;

        let extent_allocation_block_begin = u64::from(extent.begin());
        let encoded_extent_allocations_blocks_begin =
            extent_allocation_block_begin << (Self::EXTENT_ALLOCATION_BLOCKS_ENCODING_BITS + 1);
        if encoded_extent_allocations_blocks_begin >> (Self::EXTENT_ALLOCATION_BLOCKS_ENCODING_BITS + 1)
            != extent_allocation_block_begin
        {
            return Err(nvfs_err_internal!());
        }

        let encoded_extent_ptr =
            encoded_extent_allocations_blocks_begin | (encoded_extent_allocation_blocks << 1) | indirect as u64;
        let encoded_extent_ptr = encoded_extent_ptr.to_le_bytes();
        Ok(Self { encoded_extent_ptr })
    }

    /// Encode the special "NIL" value.
    pub fn encode_nil() -> Self {
        Self {
            encoded_extent_ptr: (!0u64).to_le_bytes(),
        }
    }

    /// Decode the [`EncodedExtentPtr`].
    ///
    /// If non-NIL, a pair of the encoded extent and the "indirect" flag is
    /// returned wrapped in a `Some`, `None` otherwise.
    pub fn decode(
        &self,
        allocation_block_size_128b_log2: u32,
    ) -> Result<Option<(layout::PhysicalAllocBlockRange, bool)>, NvFsError> {
        let mut encoded_extent_ptr = u64::from_le_bytes(self.encoded_extent_ptr);
        if encoded_extent_ptr == !0 {
            return Ok(None);
        }
        let indirect = encoded_extent_ptr & 1 != 0;
        encoded_extent_ptr >>= 1;
        let encoded_extent_allocation_blocks =
            encoded_extent_ptr & ((1u64 << Self::EXTENT_ALLOCATION_BLOCKS_ENCODING_BITS) - 1);
        let extent_allocation_blocks = encoded_extent_allocation_blocks + 1;
        let extent_allocation_blocks_begin = encoded_extent_ptr >> Self::EXTENT_ALLOCATION_BLOCKS_ENCODING_BITS;

        let extent_allocation_blocks_end = extent_allocation_blocks_begin + extent_allocation_blocks;
        if extent_allocation_blocks_end >> (u64::BITS - (allocation_block_size_128b_log2 + 7)) != 0 {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidExtents));
        }

        Ok(Some((
            layout::PhysicalAllocBlockRange::from((
                layout::PhysicalAllocBlockIndex::from(extent_allocation_blocks_begin),
                layout::AllocBlockCount::from(extent_allocation_blocks),
            )),
            indirect,
        )))
    }
}

impl ops::Deref for EncodedExtentPtr {
    type Target = [u8; mem::size_of::<u64>()];

    fn deref(&self) -> &Self::Target {
        &self.encoded_extent_ptr
    }
}

impl convert::From<[u8; mem::size_of::<u64>()]> for EncodedExtentPtr {
    fn from(value: [u8; mem::size_of::<u64>()]) -> Self {
        Self {
            encoded_extent_ptr: value,
        }
    }
}

/// Encoded block pointer format.
///
/// An encoded block pointer, if non-NIL, specifies the location of some block
/// on storage, whose dimensions are implicit from the context.
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct EncodedBlockPtr {
    encoded_block_ptr: [u8; mem::size_of::<u64>()],
}

impl EncodedBlockPtr {
    /// Number of reserved bits in an [`EncodedBlockPtr`].
    const RESERVED_ENCODING_BITS: u32 = 7u32;
    /// Encoded length of an [`EncodedBlockPtr`].
    pub const ENCODED_SIZE: u32 = mem::size_of::<u64>() as u32;

    /// Encode an [`EncodedBlockPtr`].
    ///
    /// # Arguments:
    ///
    /// * `block_allocation_blocks_begin` - The beginning of the block wrapped
    ///   in a `Some`, or `None` to encode a special "NIL" value.
    pub fn encode(block_allocation_blocks_begin: Option<layout::PhysicalAllocBlockIndex>) -> Result<Self, NvFsError> {
        let block_allocation_blocks_begin = match block_allocation_blocks_begin {
            Some(block_allocation_blocks_begin) => block_allocation_blocks_begin,
            None => return Ok(Self::encode_nil()),
        };

        let block_allocation_blocks_begin = u64::from(block_allocation_blocks_begin);
        let encoded_block_allocation_blocks_begin = block_allocation_blocks_begin << Self::RESERVED_ENCODING_BITS;
        if encoded_block_allocation_blocks_begin >> Self::RESERVED_ENCODING_BITS != block_allocation_blocks_begin {
            return Err(nvfs_err_internal!());
        }

        let encoded_block_ptr = encoded_block_allocation_blocks_begin.to_le_bytes();
        Ok(Self { encoded_block_ptr })
    }

    /// Encode the special "NIL" value.
    pub fn encode_nil() -> Self {
        Self {
            encoded_block_ptr: (!0u64).to_le_bytes(),
        }
    }

    /// Decode the [`EncodedBlockPtr`].
    ///
    /// If non-NIL, return the beginning of the block wrapped in a `Some`,
    /// `None` otherwise.
    pub fn decode(
        &self,
        allocation_block_size_128b_log2: u32,
    ) -> Result<Option<layout::PhysicalAllocBlockIndex>, NvFsError> {
        let encoded_block_allocation_blocks_begin = u64::from_le_bytes(self.encoded_block_ptr);
        if encoded_block_allocation_blocks_begin == !0 {
            return Ok(None);
        }

        let block_allocation_blocks_begin = encoded_block_allocation_blocks_begin >> Self::RESERVED_ENCODING_BITS;
        if block_allocation_blocks_begin << Self::RESERVED_ENCODING_BITS != encoded_block_allocation_blocks_begin {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidExtents));
        }

        if block_allocation_blocks_begin >> (u64::BITS - (allocation_block_size_128b_log2 + 7)) != 0 {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidExtents));
        }

        Ok(Some(layout::PhysicalAllocBlockIndex::from(
            block_allocation_blocks_begin,
        )))
    }
}

impl ops::Deref for EncodedBlockPtr {
    type Target = [u8; mem::size_of::<u64>()];

    fn deref(&self) -> &Self::Target {
        &self.encoded_block_ptr
    }
}

impl convert::From<[u8; mem::size_of::<u64>()]> for EncodedBlockPtr {
    fn from(value: [u8; mem::size_of::<u64>()]) -> Self {
        Self {
            encoded_block_ptr: value,
        }
    }
}
