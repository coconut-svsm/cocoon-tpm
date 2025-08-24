// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Functionality related to the filesystem image header.

use crate::{
    chip::{self, ChunkedIoRegion, ChunkedIoRegionChunkRange, ChunkedIoRegionError, NvChipIoError},
    crypto::hash,
    fs::{
        NvFsError, NvFsIoError,
        cocoonfs::{CocoonFsFormatError, crc32, extent_ptr, layout},
    },
    nvfs_err_internal,
    utils_common::{
        bitmanip::{BitManip as _, UBitManip as _},
        fixed_vec::FixedVec,
        io_slices::{self, IoSlicesIter as _, IoSlicesIterCommon as _, IoSlicesMutIter as _},
    },
};
use core::{marker, mem, ops::Deref as _, pin, task};

#[cfg(doc)]
use layout::ImageLayout;

/// Static image header prefix of minimum possible length.
///
/// Used to decode the salt length needed for determining the actual filesystem
/// header size.
#[derive(Clone)]
struct MinStaticImageHeader {
    encoded_image_layout: [u8; layout::ImageLayout::encoded_len() as usize],
    salt_len: u8,
}

impl MinStaticImageHeader {
    /// Encoded length of a [`MinStaticImageHeader`].
    const fn encoded_len() -> u8 {
        const ENCODED_LEN: u32 = {
            // Magic 'COCOONFS'.
            let mut encoded_len = 8u32;
            // The u8 image format version.
            encoded_len += mem::size_of::<u8>() as u32;
            // The encoded ImageLayout.
            encoded_len += layout::ImageLayout::encoded_len() as u32;
            // The length of the salt as an u8.
            encoded_len += mem::size_of::<u8>() as u32;

            encoded_len
        };

        #[allow(clippy::assertions_on_constants)]
        let _: () = assert!(ENCODED_LEN <= 128);

        ENCODED_LEN as u8
    }

    /// Decode the [`MinStaticImageHeader`] from a buffer.
    ///
    /// # Arguments:
    ///
    /// * `buf` - The source buffer. Must be at least
    ///   [`encoded_len()`](Self::encoded_len) in length.
    fn decode(buf: &[u8]) -> Result<Self, NvFsError> {
        if buf.len() < Self::encoded_len() as usize {
            return Err(nvfs_err_internal!());
        }

        let expected_magic = b"COCOONFS";
        let (magic, buf) = buf.split_at(expected_magic.len());
        if magic != expected_magic {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidImageHeaderMagic));
        }

        let (version, buf) = buf.split_at(mem::size_of::<u8>());
        // The from_le_bytes() is a nop for an u8, but this mirrors the encoding part.
        let version =
            u8::from_le_bytes(*<&[u8; mem::size_of::<u8>()]>::try_from(version).map_err(|_| nvfs_err_internal!())?);
        if version != 0 {
            return Err(NvFsError::from(CocoonFsFormatError::UnsupportedFormatVersion));
        }

        let (encoded_image_layout, buf) = buf.split_at(layout::ImageLayout::encoded_len() as usize);
        let encoded_image_layout = <&[u8; layout::ImageLayout::encoded_len() as usize]>::try_from(encoded_image_layout)
            .map_err(|_| nvfs_err_internal!())?;

        let (salt_len, _) = buf.split_at(mem::size_of::<u8>());
        // The from_le_bytes() is a nop for an u8, as is the usize::try_from()
        // conversion, but this mirrors the encoding part.
        let salt_len =
            u8::from_le_bytes(*<&[u8; mem::size_of::<u8>()]>::try_from(salt_len).map_err(|_| nvfs_err_internal!())?);

        Ok(Self {
            encoded_image_layout: *encoded_image_layout,
            salt_len,
        })
    }
}

/// Static image header.
pub struct StaticImageHeader {
    /// The filesystem's [`ImageLayout`] configuration parameters.
    pub image_layout: layout::ImageLayout,
    /// The filesystem's salt value.
    pub salt: FixedVec<u8, 4>,
}

impl StaticImageHeader {
    /// Encoded length of a static image header.
    ///
    /// Returns the encoded length of a static image header with a salt length
    /// of `salt_len` without any of the padding to align to the next [IO
    /// Block](layout::ImageLayout::io_block_allocation_blocks_log2) boundary
    /// included.
    ///
    /// # Arguments:
    ///
    /// * `salt_len` - Length of the salt stored in the static image header.
    fn encoded_len(salt_len: u8) -> u32 {
        // The minimal common header containing everything needed to deduce the full
        // header's length.
        let mut encoded_len = MinStaticImageHeader::encoded_len() as u32;

        // And the image salt.
        encoded_len += salt_len as u32;

        // The length of two CRCs -- one on the plain image header data, one with all
        // neighboring bits swapped each.
        encoded_len += 2 * (mem::size_of::<u32>() as u32);

        encoded_len
    }

    /// [IO Block](layout::ImageLayout::io_block_allocation_blocks_log2) aligned
    /// length of a static image header.
    ///
    /// The static image header gets padded to the next [IO
    /// Block](layout::ImageLayout::io_block_allocation_blocks_log2) boundary so
    /// that no writes to the filesystem image will ever affect its
    /// contents.
    ///
    /// Return the length of a static image header with a salt length
    /// of `salt_len` aligned to the next [IO
    /// Block](layout::ImageLayout::io_block_allocation_blocks_log2) boundary in
    /// units of [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    ///
    /// # Arguments:
    ///
    /// * `salt_len` - Length of the salt stored in the static image header.
    /// * `io_block_allocation_blocks_log2` - Verbatim copy of
    ///   [`ImageLayout::io_block_allocation_blocks_log2`].
    /// * `allocation_block_size_128b_log2` - Verbatim copy of
    ///   [`ImageLayout::allocation_block_size_128b_log2`].
    pub fn io_block_aligned_encoded_len_allocation_blocks(
        salt_len: u8,
        io_block_allocation_blocks_log2: u32,
        allocation_block_size_128b_log2: u32,
    ) -> layout::AllocBlockCount {
        let encoded_len = Self::encoded_len(salt_len) as u64;

        // The length always fits a few multiples (<= 3) of 128 Bytes, hence is
        // definitely <= than 2^63. The size of an IO Block in units of Bytes is
        // a power of two and <= 1^63 also. Hence the aligned result (in units
        // of Bytes) will be <= that uppber bound as well.
        layout::AllocBlockCount::from(
            encoded_len.round_up_pow2_unchecked(io_block_allocation_blocks_log2 + allocation_block_size_128b_log2 + 7)
                >> (allocation_block_size_128b_log2 + 7),
        )
    }

    /// Encode a static image header.
    ///
    /// # Arguments:
    ///
    /// * `dst` - The destination buffers. Their total length must be at least
    ///   that returned by [`encoded_len()`](Self::encoded_len).
    /// * `image_layout` - The filesystem image's [`ImageLayout`] to be stored
    ///   in the static image header.
    /// * `salt` - The salt to be stored in the image header. It's length must
    ///   not exceed `u8::MAX`.
    pub fn encode<'a, DI: io_slices::IoSlicesMutIter<'a, BackendIteratorError = NvFsError>>(
        mut dst: DI,
        image_layout: &layout::ImageLayout,
        salt: &[u8],
    ) -> Result<(), NvFsError> {
        // CRC of the header data.
        let mut crc = crc32::crc32le_init();
        // CRC of the header data with all neighboring bits swapped each.
        let mut crc_snb = crc32::crc32le_init();

        let magic = b"COCOONFS";
        crc = crc32::crc32le_update_data(crc, magic.as_slice());
        crc_snb = crc32::crc32le_update_data_snb(crc_snb, magic.as_slice());
        let mut magic = io_slices::SingletonIoSlice::new(magic.as_slice()).map_infallible_err();
        dst.copy_from_iter(&mut magic)?;
        if !magic.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let version = 0u8.to_le_bytes();
        crc = crc32::crc32le_update_data(crc, &version);
        crc_snb = crc32::crc32le_update_data_snb(crc_snb, &version);
        let mut version = io_slices::SingletonIoSlice::new(version.as_slice()).map_infallible_err();
        dst.copy_from_iter(&mut version)?;
        if !version.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let encoded_image_layout = image_layout.encode()?;
        crc = crc32::crc32le_update_data(crc, &encoded_image_layout);
        crc_snb = crc32::crc32le_update_data_snb(crc_snb, &encoded_image_layout);
        let mut encoded_image_layout =
            io_slices::SingletonIoSlice::new(encoded_image_layout.as_slice()).map_infallible_err();
        dst.copy_from_iter(&mut encoded_image_layout)?;
        if !encoded_image_layout.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let salt_len = u8::try_from(salt.len())
            .map_err(|_| NvFsError::from(CocoonFsFormatError::InvalidSaltLength))?
            .to_le_bytes();
        crc = crc32::crc32le_update_data(crc, &salt_len);
        crc_snb = crc32::crc32le_update_data_snb(crc_snb, &salt_len);
        let mut salt_len = io_slices::SingletonIoSlice::new(salt_len.as_slice()).map_infallible_err();
        dst.copy_from_iter(&mut salt_len)?;
        if !salt_len.is_empty()? {
            return Err(nvfs_err_internal!());
        }
        crc = crc32::crc32le_update_data(crc, salt);
        crc_snb = crc32::crc32le_update_data_snb(crc_snb, salt);
        let mut salt = io_slices::SingletonIoSlice::new(salt).map_infallible_err();
        dst.copy_from_iter(&mut salt)?;
        if !salt.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let crc = crc32::crc32le_finish_send(crc).to_le_bytes();
        let mut crc = io_slices::SingletonIoSlice::new(&crc).map_infallible_err();
        dst.copy_from_iter(&mut crc)?;
        if !crc.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let crc_snb = crc32::crc32le_finish_send(crc_snb).to_le_bytes();
        let mut crc_snb = io_slices::SingletonIoSlice::new(&crc_snb).map_infallible_err();
        dst.copy_from_iter(&mut crc_snb)?;
        if !crc_snb.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        Ok(())
    }
}

/// Mutable image header.
pub struct MutableImageHeader {
    /// The current authentication tree root digest.
    pub root_hmac_digest: FixedVec<u8, 5>,
    /// The current inode index entry leaf node preauthentication CCA protection
    /// digest.
    pub inode_index_entry_leaf_node_preauth_cca_protection_digest: FixedVec<u8, 5>,
    /// Location of the inode index entry leaf node.
    pub inode_index_entry_leaf_node_block_ptr: extent_ptr::EncodedBlockPtr,
    /// The filesystem image size.
    pub image_size: layout::AllocBlockCount,
}

impl MutableImageHeader {
    /// Encoded length of a mutable image header.
    ///
    /// Returns the encoded length of a mutable image header without any of the
    /// padding to align to the next [Allocation
    /// Block](layout::ImageLayout::allocation_block_size_128b_log2) boundary
    /// included.
    ///
    /// # Arguments:
    pub fn encoded_len(image_layout: &layout::ImageLayout) -> u32 {
        // The root hmac.
        let mut encoded_len = hash::hash_alg_digest_len(image_layout.auth_tree_root_hmac_hash_alg) as u32;
        // The inode index entry node pre-authentication CCA protection digest.
        encoded_len += hash::hash_alg_digest_len(image_layout.preauth_cca_protection_hmac_hash_alg) as u32;
        // The inode index entry leaf node pointer.
        encoded_len += extent_ptr::EncodedBlockPtr::ENCODED_SIZE;
        // The size of the image in units of Allocation Blocks.
        encoded_len += mem::size_of::<u64>() as u32;

        encoded_len
    }

    /// Determine the location of the mutable image header on storage.
    ///
    /// # Arguments:
    ///
    /// * `image_layout` - The filesystem's [`ImageLayout`].
    /// * `salt_len` - Length of the salt stored in the static image header.
    pub fn physical_location(image_layout: &layout::ImageLayout, salt_len: u8) -> layout::PhysicalAllocBlockRange {
        let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
        let io_block_allocation_blocks_log2 = image_layout.io_block_allocation_blocks_log2 as u32;

        // The mutable header is located at the first IO block boundary following the
        // static header.
        // The beginning in units of Bytes is <= 2^63.
        let mutable_header_allocation_blocks_begin = layout::PhysicalAllocBlockIndex::from(0u64)
            + StaticImageHeader::io_block_aligned_encoded_len_allocation_blocks(
                salt_len,
                io_block_allocation_blocks_log2,
                allocation_block_size_128b_log2,
            );
        let mutable_header_encoded_len: u32 = MutableImageHeader::encoded_len(image_layout);
        let mutable_header_allocation_blocks_count = layout::AllocBlockCount::from(
            ((mutable_header_encoded_len as u64 - 1) >> (allocation_block_size_128b_log2 + 7)) + 1,
        );
        // The addition of the length to the beginning, even in units of Bytes, i.e. the
        // addition of an u32 to a value <= 2^63, does not overflow either.
        layout::PhysicalAllocBlockRange::from((
            mutable_header_allocation_blocks_begin,
            mutable_header_allocation_blocks_count,
        ))
    }

    /// Encode a mutable image header.
    ///
    /// # Arguments:
    ///
    /// * `dst` - The destination buffers. Their total length must be at least
    ///   that returned by [`encoded_len()`](Self::encoded_len).
    /// * `root_hmac_digest` - The current authentication tree root digest. Its
    ///   length must match that of digests produced by
    ///   [`ImageLayout::auth_tree_root_hmac_hash_alg`] exactly.
    /// * `inode_index_entry_leaf_node_preauth_cca_protection_digest` - The
    ///   current inode index entry leaf node preauthentication CCA protection
    ///   digest. Its length must match that of digests produced by
    ///   [`ImageLayout::preauth_cca_protection_hmac_hash_alg`] exactly.
    /// * `inode_index_entry_leaf_node_block_ptr` - Location of the inode index
    ///   entry leaf node.
    /// * `image_size` - The filesystem image size.
    pub fn encode<'a, DI: io_slices::IoSlicesMutIter<'a, BackendIteratorError = NvFsError>>(
        mut dst: DI,
        root_hmac_digest: &[u8],
        inode_index_entry_leaf_node_preauth_cca_protection_digest: &[u8],
        inode_index_entry_leaf_node_block_ptr: &extent_ptr::EncodedBlockPtr,
        image_size: layout::AllocBlockCount,
    ) -> Result<(), NvFsError> {
        let mut root_hmac_digest = io_slices::SingletonIoSlice::new(root_hmac_digest).map_infallible_err();
        dst.copy_from_iter(&mut root_hmac_digest)?;
        if !root_hmac_digest.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let mut inode_index_entry_leaf_node_preauth_cca_protection_digest =
            io_slices::SingletonIoSlice::new(inode_index_entry_leaf_node_preauth_cca_protection_digest)
                .map_infallible_err();
        dst.copy_from_iter(&mut inode_index_entry_leaf_node_preauth_cca_protection_digest)?;
        if !inode_index_entry_leaf_node_preauth_cca_protection_digest.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let mut inode_index_entry_leaf_node_block_ptr =
            io_slices::SingletonIoSlice::new(inode_index_entry_leaf_node_block_ptr.deref()).map_infallible_err();
        dst.copy_from_iter(&mut inode_index_entry_leaf_node_block_ptr)?;
        if !inode_index_entry_leaf_node_block_ptr.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let image_size = u64::from(image_size).to_le_bytes();
        let mut image_size = io_slices::SingletonIoSlice::new(image_size.as_slice()).map_infallible_err();
        dst.copy_from_iter(&mut image_size)?;
        if !image_size.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        Ok(())
    }

    /// Decode a mutable image header.
    ///
    /// # Arguments:
    ///
    /// * `src` - The source buffers. Their total length must be at least that
    ///   returned by [`encoded_len()`](Self::encoded_len).
    /// * `image_layout` - The filesystem's [`ImageLayout`].
    pub fn decode<'a, SI: io_slices::IoSlicesIter<'a, BackendIteratorError = NvFsError>>(
        mut src: SI,
        image_layout: &layout::ImageLayout,
    ) -> Result<Self, NvFsError> {
        // And the root HMAC.
        let root_hmac_digest_len = hash::hash_alg_digest_len(image_layout.auth_tree_root_hmac_hash_alg) as usize;
        let mut root_hmac_digest = FixedVec::new_with_default(root_hmac_digest_len)?;
        let mut root_hmac_digest_io_slice =
            io_slices::SingletonIoSliceMut::new(&mut root_hmac_digest).map_infallible_err();
        root_hmac_digest_io_slice.copy_from_iter(&mut src)?;
        if !root_hmac_digest_io_slice.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        // The Inode Index Tree entry leaf node block's Pre-authentication CCA
        // protection digest.
        let inode_index_entry_leaf_node_preauth_cca_protection_digest_len =
            hash::hash_alg_digest_len(image_layout.preauth_cca_protection_hmac_hash_alg) as usize;
        let mut inode_index_entry_leaf_node_preauth_cca_protection_digest =
            FixedVec::new_with_default(inode_index_entry_leaf_node_preauth_cca_protection_digest_len)?;
        let mut inode_index_entry_leaf_node_preauth_cca_protection_digest_io_slice =
            io_slices::SingletonIoSliceMut::new(&mut inode_index_entry_leaf_node_preauth_cca_protection_digest)
                .map_infallible_err();
        inode_index_entry_leaf_node_preauth_cca_protection_digest_io_slice.copy_from_iter(&mut src)?;
        if !inode_index_entry_leaf_node_preauth_cca_protection_digest_io_slice.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        // The Inode Index Tree entry leaf node block pointer.
        let mut inode_index_entry_leaf_node_block_ptr = [0u8; extent_ptr::EncodedBlockPtr::ENCODED_SIZE as usize];
        let mut inode_index_entry_leaf_node_block_ptr_io_slice =
            io_slices::SingletonIoSliceMut::new(&mut inode_index_entry_leaf_node_block_ptr)
                .map_infallible_err::<SI::BackendIteratorError>();
        inode_index_entry_leaf_node_block_ptr_io_slice.copy_from_iter(&mut src)?;
        if !inode_index_entry_leaf_node_block_ptr_io_slice.is_empty()? {
            return Err(nvfs_err_internal!());
        }
        let inode_index_entry_leaf_node_block_ptr =
            extent_ptr::EncodedBlockPtr::from(inode_index_entry_leaf_node_block_ptr);
        match inode_index_entry_leaf_node_block_ptr.decode(image_layout.allocation_block_size_128b_log2 as u32) {
            Ok(Some(_)) => (),
            Ok(None) => return Err(NvFsError::from(CocoonFsFormatError::InvalidExtents)),
            Err(e) => return Err(e),
        }

        // The image size in units of Allocation Blocks.
        let mut image_size = [0u8; mem::size_of::<u64>()];
        let mut image_size_io_slice = io_slices::SingletonIoSliceMut::new(&mut image_size).map_infallible_err();
        image_size_io_slice.copy_from_iter(&mut src)?;
        if !image_size_io_slice.is_empty()? {
            return Err(nvfs_err_internal!());
        }
        let image_size = u64::from_le_bytes(image_size);
        if image_size << (image_layout.allocation_block_size_128b_log2 as u32 + 7)
            >> (image_layout.allocation_block_size_128b_log2 as u32 + 7)
            != image_size
            || !image_size.is_aligned_pow2(image_layout.io_block_allocation_blocks_log2 as u32)
        {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidImageSize));
        }
        let image_size = layout::AllocBlockCount::from(image_size);

        Ok(Self {
            root_hmac_digest,
            inode_index_entry_leaf_node_preauth_cca_protection_digest,
            inode_index_entry_leaf_node_block_ptr,
            image_size,
        })
    }
}

/// [`NvChipReadRequest`](chip::NvChipReadRequest) implementation used
/// internally by [`ReadCoreImageHeaderFuture`] and
/// [`ReadMutableImageHeaderFuture`] for reading parts of the image header.
struct ReadImageHeaderPartChipRequest {
    region: ChunkedIoRegion,
    dst: FixedVec<u8, 7>,
}

impl ReadImageHeaderPartChipRequest {
    pub fn new(
        read_region_begin_chip_io_blocks: u64,
        read_region_chip_io_blocks: u64,
        chip_io_block_size_128b_log2: u32,
    ) -> Result<Self, NvFsError> {
        if chip_io_block_size_128b_log2 >= u64::BITS - 7 {
            return Err(NvFsError::IoError(NvFsIoError::RegionOutOfRange));
        }

        let read_region_begin_128b = read_region_begin_chip_io_blocks << chip_io_block_size_128b_log2;
        if read_region_begin_128b >> chip_io_block_size_128b_log2 != read_region_begin_chip_io_blocks {
            return Err(NvFsError::IoError(NvFsIoError::RegionOutOfRange));
        }
        let read_region_len_128b = read_region_chip_io_blocks << chip_io_block_size_128b_log2;
        if read_region_len_128b >> chip_io_block_size_128b_log2 != read_region_chip_io_blocks {
            return Err(NvFsError::IoError(NvFsIoError::RegionOutOfRange));
        }
        let read_region_end_128b = read_region_begin_128b
            .checked_add(read_region_len_128b)
            .ok_or(NvFsError::IoError(NvFsIoError::RegionOutOfRange))?;

        let read_region = ChunkedIoRegion::new(
            read_region_begin_128b,
            read_region_end_128b,
            chip_io_block_size_128b_log2,
        )
        .map_err(|e| match e {
            ChunkedIoRegionError::ChunkSizeOverflow | ChunkedIoRegionError::ChunkIndexOverflow => {
                NvFsError::DimensionsNotSupported
            }
            ChunkedIoRegionError::InvalidBounds | ChunkedIoRegionError::RegionUnaligned => nvfs_err_internal!(),
        })?;

        let read_region_len = read_region_len_128b << 7;
        if read_region_len >> 7 != read_region_len_128b {
            return Err(NvFsError::IoError(NvFsIoError::RegionOutOfRange));
        }
        let read_region_len = usize::try_from(read_region_len).map_err(|_| NvFsError::DimensionsNotSupported)?;
        let dst = FixedVec::new_with_default(read_region_len)?;

        Ok(Self {
            region: read_region,
            dst,
        })
    }
}

impl chip::NvChipReadRequest for ReadImageHeaderPartChipRequest {
    fn region(&self) -> &ChunkedIoRegion {
        &self.region
    }

    fn get_destination_buffer(
        &mut self,
        range: &ChunkedIoRegionChunkRange,
    ) -> Result<Option<&mut [u8]>, chip::NvChipIoError> {
        let request_chip_io_block_index = range.chunk().decompose_to_hierarchic_indices::<0>([]).0;
        let chip_io_block_size_log2 = self.region.chunk_size_128b_log2();
        let dst_begin = request_chip_io_block_index << (chip_io_block_size_log2 + 7);
        Ok(Some(&mut self.dst[dst_begin..][range.range_in_chunk().clone()]))
    }
}

/// Result returned by [`ReadCoreImageHeaderFuture`].
///
/// A valid filesystem header is either a regular [`StaticImageHeader`] in case
/// the filesystem had been created ("mkfs") before, or a [`MkFsInfoHeader`], in
/// which case the filsystem is supposed to get created at first filesystem
/// opening time.
pub enum ReadCoreImageHeaderFutureResult {
    /// The filesystem image has a valid regular [`StaticImageHeader`] already.
    StaticImageHeader(StaticImageHeader),
    /// The filesysyem has a [`MkFsInfoHeader`], from which the filesystem is
    /// to be created at first filesystem opening time.
    MkFsInfoHeader { header: MkFsInfoHeader, from_backup: bool },
}

/// Read the core filesystem header.
pub struct ReadCoreImageHeaderFuture<C: chip::NvChip> {
    fut_state: ReadCoreImageHeaderFutureState<C>,
}

/// [`ReadCoreImageHeaderFuture`] state-machine state.
enum ReadCoreImageHeaderFutureState<C: chip::NvChip> {
    Init {
        _phantom: marker::PhantomData<fn() -> *const C>,
    },
    ReadMinHeader {
        read_fut: C::ReadFuture<ReadImageHeaderPartChipRequest>,
    },
    ReadStaticImageHeaderRemainder {
        read_fut: C::ReadFuture<ReadImageHeaderPartChipRequest>,
        min_header: MinStaticImageHeader,
        static_header_len: usize,
        first_header_part: FixedVec<u8, 7>,
    },
    DecodeStaticImageHeader {
        min_header: MinStaticImageHeader,
        static_header_len: usize,
        first_header_part: FixedVec<u8, 7>,
        second_header_part: FixedVec<u8, 7>,
    },
    ReadMkFsInfoHeaderRemainder {
        read_fut: C::ReadFuture<ReadImageHeaderPartChipRequest>,
        min_header: MinMkFsInfoHeader,
        mkfsinfo_header_len: usize,
        first_header_part: FixedVec<u8, 7>,
        first_error: Option<NvFsError>,
    },
    DecodeMkFsInfoHeader {
        min_header: MinMkFsInfoHeader,
        mkfsinfo_header_len: usize,
        first_header_part: FixedVec<u8, 7>,
        second_header_part: FixedVec<u8, 7>,
        first_error: Option<NvFsError>,
    },
    PrepareReadBackupMinMkFsInfoHeader {
        first_error: NvFsError,
    },
    ReadBackupMinMkFsInfoHeader {
        read_fut: C::ReadFuture<ReadImageHeaderPartChipRequest>,
        backup_location_chip_io_blocks_begin: u64,
        first_error: NvFsError,
    },
    Done,
}

impl<C: chip::NvChip> ReadCoreImageHeaderFuture<C> {
    pub fn new() -> Self {
        Self {
            fut_state: ReadCoreImageHeaderFutureState::Init {
                _phantom: marker::PhantomData,
            },
        }
    }
}

impl<C: chip::NvChip> chip::NvChipFuture<C> for ReadCoreImageHeaderFuture<C> {
    type Output = Result<ReadCoreImageHeaderFutureResult, NvFsError>;

    fn poll(self: pin::Pin<&mut Self>, chip: &C, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                ReadCoreImageHeaderFutureState::Init { _phantom } => {
                    let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();

                    // Read the first Chip minimum IO Block, which is always >= 128 bytes by
                    // definition, which suffices to store the MinStaticImageHeader as well as the
                    // MinMkFsInfoHeader, which in turn contain all information
                    // to subsequently deduce the full header size.
                    const _: () = assert!(MinStaticImageHeader::encoded_len() <= 128);
                    const _: () = assert!(MinMkFsInfoHeader::encoded_len() <= 128);
                    let read_request = match ReadImageHeaderPartChipRequest::new(0, 1, chip_io_block_size_128b_log2) {
                        Ok(read_request) => read_request,
                        Err(e) => {
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    let read_fut = chip.read(read_request).and_then(|r| r.map_err(|(_, e)| e));
                    let read_fut = match read_fut {
                        Ok(read_fut) => read_fut,
                        Err(e) => {
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    this.fut_state = ReadCoreImageHeaderFutureState::ReadMinHeader { read_fut };
                }
                ReadCoreImageHeaderFutureState::ReadMinHeader { read_fut } => {
                    let first_header_part = match chip::NvChipFuture::poll(pin::Pin::new(read_fut), chip, cx) {
                        task::Poll::Ready(Ok((read_request, Ok(())))) => {
                            let ReadImageHeaderPartChipRequest { region: _, dst } = read_request;
                            dst
                        }
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    // See whether there's a static image header or a MkFsInfoHeader and proceed
                    // accordingly.
                    match MinStaticImageHeader::decode(&first_header_part) {
                        Ok(min_static_image_header) => {
                            // Now that the MinStaticImageHeader has been read and decoded, deduce the total
                            // header length from it, read the remainder, if any, and continue with the
                            // decoding.
                            let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();
                            debug_assert_eq!(first_header_part.len(), 1usize << (chip_io_block_size_128b_log2 + 7));
                            let static_header_len = StaticImageHeader::encoded_len(min_static_image_header.salt_len);
                            // Remember from above: it is known by now that the Chip IO Block size fits an
                            // u64.
                            let remaining_static_header_len =
                                (static_header_len as u64).saturating_sub(first_header_part.len() as u64);
                            if remaining_static_header_len == 0 {
                                this.fut_state = ReadCoreImageHeaderFutureState::DecodeStaticImageHeader {
                                    min_header: min_static_image_header,
                                    static_header_len: static_header_len as usize,
                                    first_header_part,
                                    second_header_part: FixedVec::new_empty(),
                                };
                                continue;
                            }

                            let mut remaining_header_chip_io_blocks =
                                remaining_static_header_len >> (chip_io_block_size_128b_log2 + 7);
                            if remaining_header_chip_io_blocks << (chip_io_block_size_128b_log2 + 7)
                                != remaining_static_header_len
                            {
                                remaining_header_chip_io_blocks += 1;
                            };
                            let read_request = match ReadImageHeaderPartChipRequest::new(
                                1,
                                remaining_header_chip_io_blocks,
                                chip_io_block_size_128b_log2,
                            ) {
                                Ok(read_request) => read_request,
                                Err(e) => {
                                    this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                    return task::Poll::Ready(Err(e));
                                }
                            };
                            let read_fut = chip.read(read_request).and_then(|r| r.map_err(|(_, e)| e));
                            let read_fut = match read_fut {
                                Ok(read_fut) => read_fut,
                                Err(NvChipIoError::IoBlockNotMapped) => {
                                    // There is a static image header magic, but the IO request
                                    // setup failed. This can only happen if the encoded salt length
                                    // determining the total header size is invalid. Try to read the
                                    // backup MkFsInfoHeader, if any, instead.
                                    this.fut_state =
                                        ReadCoreImageHeaderFutureState::PrepareReadBackupMinMkFsInfoHeader {
                                            first_error: NvFsError::from(NvChipIoError::IoBlockNotMapped),
                                        };
                                    continue;
                                }
                                Err(e) => {
                                    this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                    return task::Poll::Ready(Err(NvFsError::from(e)));
                                }
                            };
                            this.fut_state = ReadCoreImageHeaderFutureState::ReadStaticImageHeaderRemainder {
                                read_fut,
                                min_header: min_static_image_header,
                                static_header_len: static_header_len as usize,
                                first_header_part,
                            };
                        }
                        Err(NvFsError::Internal) => {
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::Internal));
                        }
                        Err(static_image_header_read_error) => {
                            // Try to decode a MinMkFsInfoHeader instead.
                            match MinMkFsInfoHeader::decode(&first_header_part) {
                                Ok(min_mkfsinfo_header) => {
                                    // Ok, there is something which seems to be a
                                    // MkFsInfoHeader. Try to read its remainder, if any.
                                    let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();
                                    debug_assert_eq!(
                                        first_header_part.len(),
                                        1usize << (chip_io_block_size_128b_log2 + 7)
                                    );
                                    let mkfsinfo_header_len = MkFsInfoHeader::encoded_len(min_mkfsinfo_header.salt_len);
                                    // Remember from above: it is known by now that the Chip IO Block size fits an
                                    // u64.
                                    let remaining_mkfsinfo_header_len =
                                        (mkfsinfo_header_len as u64).saturating_sub(first_header_part.len() as u64);
                                    if remaining_mkfsinfo_header_len == 0 {
                                        this.fut_state = ReadCoreImageHeaderFutureState::DecodeMkFsInfoHeader {
                                            min_header: min_mkfsinfo_header,
                                            mkfsinfo_header_len: mkfsinfo_header_len as usize,
                                            first_header_part,
                                            second_header_part: FixedVec::new_empty(),
                                            first_error: None,
                                        };

                                        continue;
                                    }

                                    let mut remaining_header_chip_io_blocks =
                                        remaining_mkfsinfo_header_len >> (chip_io_block_size_128b_log2 + 7);
                                    if remaining_header_chip_io_blocks << (chip_io_block_size_128b_log2 + 7)
                                        != remaining_mkfsinfo_header_len
                                    {
                                        remaining_header_chip_io_blocks += 1;
                                    };
                                    let read_request = match ReadImageHeaderPartChipRequest::new(
                                        1,
                                        remaining_header_chip_io_blocks,
                                        chip_io_block_size_128b_log2,
                                    ) {
                                        Ok(read_request) => read_request,
                                        Err(e) => {
                                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                            return task::Poll::Ready(Err(e));
                                        }
                                    };
                                    let read_fut = chip.read(read_request).and_then(|r| r.map_err(|(_, e)| e));
                                    let read_fut = match read_fut {
                                        Ok(read_fut) => read_fut,
                                        Err(NvChipIoError::IoBlockNotMapped) => {
                                            // There is a MkFsInfoHeader magic, but the IO request setup
                                            // failed.  This can only happen if the
                                            // encoded salt length determining the total header size is invalid. Try to
                                            // read the backup MkFsInfoHeader, if any,
                                            // instead.
                                            this.fut_state =
                                                ReadCoreImageHeaderFutureState::PrepareReadBackupMinMkFsInfoHeader {
                                                    first_error: NvFsError::from(NvChipIoError::IoBlockNotMapped),
                                                };
                                            continue;
                                        }
                                        Err(e) => {
                                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                            return task::Poll::Ready(Err(NvFsError::from(e)));
                                        }
                                    };
                                    this.fut_state = ReadCoreImageHeaderFutureState::ReadMkFsInfoHeaderRemainder {
                                        read_fut,
                                        min_header: min_mkfsinfo_header,
                                        mkfsinfo_header_len: mkfsinfo_header_len as usize,
                                        first_header_part,
                                        first_error: None,
                                    };
                                }
                                Err(NvFsError::Internal) => {
                                    this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                    return task::Poll::Ready(Err(NvFsError::Internal));
                                }
                                Err(e) => {
                                    // No MinMkFsInfoHeader found, try the backup.
                                    this.fut_state =
                                        ReadCoreImageHeaderFutureState::PrepareReadBackupMinMkFsInfoHeader {
                                            first_error: if static_image_header_read_error
                                                != NvFsError::from(CocoonFsFormatError::InvalidImageHeaderMagic)
                                            {
                                                debug_assert_eq!(
                                                    e,
                                                    NvFsError::from(CocoonFsFormatError::InvalidImageHeaderMagic,)
                                                );
                                                static_image_header_read_error
                                            } else {
                                                e
                                            },
                                        };
                                }
                            };
                        }
                    };
                }
                ReadCoreImageHeaderFutureState::ReadStaticImageHeaderRemainder {
                    read_fut,
                    min_header,
                    static_header_len,
                    first_header_part,
                } => {
                    let second_header_part = match chip::NvChipFuture::poll(pin::Pin::new(read_fut), chip, cx) {
                        task::Poll::Ready(Ok((read_request, Ok(())))) => {
                            let ReadImageHeaderPartChipRequest { region: _, dst } = read_request;
                            dst
                        }
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                            match e {
                                NvChipIoError::IoBlockNotMapped => {
                                    // There is a static image header magic, but the IO request to
                                    // read the remainder failed. This can only happen if the
                                    // encoded salt length determining the total header size is
                                    // invalid. Try to read the backup MkFsInfoHeader, if any,
                                    // instead.
                                    this.fut_state =
                                        ReadCoreImageHeaderFutureState::PrepareReadBackupMinMkFsInfoHeader {
                                            first_error: NvFsError::from(NvChipIoError::IoBlockNotMapped),
                                        };
                                    continue;
                                }
                                _ => {
                                    this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                    return task::Poll::Ready(Err(NvFsError::from(e)));
                                }
                            };
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let first_header_part = mem::take(first_header_part);
                    this.fut_state = ReadCoreImageHeaderFutureState::DecodeStaticImageHeader {
                        min_header: min_header.clone(),
                        static_header_len: *static_header_len,
                        first_header_part,
                        second_header_part,
                    };
                }
                ReadCoreImageHeaderFutureState::DecodeStaticImageHeader {
                    min_header,
                    static_header_len,
                    first_header_part,
                    second_header_part,
                } => {
                    // Verify the checksums.
                    let mut header_io_slice = io_slices::SingletonIoSlice::new(first_header_part)
                        .chain(io_slices::SingletonIoSlice::new(second_header_part));
                    // CRC of the header data.
                    let mut crc = crc32::crc32le_init();
                    // CRC of the header data with all neighboring bits swapped each.
                    let mut crc_snb = crc32::crc32le_init();

                    let mut checksummed_header_io_slice = header_io_slice.as_ref().take_exact(*static_header_len - 8);
                    while let Some(checksummed_header_part) = match checksummed_header_io_slice.next_slice(None) {
                        Ok(checksummed_header_part) => checksummed_header_part,
                        Err(e) => {
                            // Infallible.
                            match e {
                                io_slices::IoSlicesIterError::BackendIteratorError(e) => {
                                    // Infallible.
                                    match e {}
                                }
                                io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                                    io_slices::IoSlicesError::BuffersExhausted => {
                                        this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                        return task::Poll::Ready(Err(nvfs_err_internal!()));
                                    }
                                },
                            }
                        }
                    } {
                        crc = crc32::crc32le_update_data(crc, checksummed_header_part);
                        crc_snb = crc32::crc32le_update_data_snb(crc_snb, checksummed_header_part);
                    }

                    let mut expected_crc = [0u8; mem::size_of::<u32>()];
                    let mut expected_crc_io_slice = io_slices::SingletonIoSliceMut::new(&mut expected_crc);
                    if let Err(e) = expected_crc_io_slice.as_ref().copy_from_iter(&mut header_io_slice) {
                        // Infallible.
                        match e {}
                    }
                    if !match expected_crc_io_slice.is_empty() {
                        Ok(is_empty) => is_empty,
                        Err(e) => {
                            // Infallible.
                            match e {}
                        }
                    } {
                        this.fut_state = ReadCoreImageHeaderFutureState::Done;
                        return task::Poll::Ready(Err(nvfs_err_internal!()));
                    }
                    let expected_crc = u32::from_le_bytes(expected_crc);

                    let mut expected_crc_snb = [0u8; mem::size_of::<u32>()];
                    let mut expected_crc_snb_io_slice = io_slices::SingletonIoSliceMut::new(&mut expected_crc_snb);
                    if let Err(e) = expected_crc_snb_io_slice.as_ref().copy_from_iter(&mut header_io_slice) {
                        // Infallible.
                        match e {}
                    }
                    if !match expected_crc_snb_io_slice.is_empty() {
                        Ok(is_empty) => is_empty,
                        Err(e) => {
                            // Infallible.
                            match e {}
                        }
                    } {
                        this.fut_state = ReadCoreImageHeaderFutureState::Done;
                        return task::Poll::Ready(Err(nvfs_err_internal!()));
                    }
                    let expected_crc_snb = u32::from_le_bytes(expected_crc_snb);

                    if !crc32::crc32le_finish_receive(crc, expected_crc)
                        || !crc32::crc32le_finish_receive(crc_snb, expected_crc_snb)
                    {
                        // Checksum mismatch. Proceed with attempting to read the backup MkFsInfoHeader,
                        // if any.
                        this.fut_state = ReadCoreImageHeaderFutureState::PrepareReadBackupMinMkFsInfoHeader {
                            first_error: NvFsError::from(CocoonFsFormatError::InvalidImageHeaderChecksum),
                        };
                        continue;
                    }

                    // Decode the static image header.
                    let mut header_io_slice = io_slices::SingletonIoSlice::new(first_header_part)
                        .chain(io_slices::SingletonIoSlice::new(second_header_part));

                    if let Err(e) = header_io_slice.skip(MinStaticImageHeader::encoded_len() as usize) {
                        let e = match e {
                            io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                                io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
                            },
                            io_slices::IoSlicesIterError::BackendIteratorError(e) => {
                                // Infallible.
                                match e {}
                            }
                        };
                        this.fut_state = ReadCoreImageHeaderFutureState::Done;
                        return task::Poll::Ready(Err(e));
                    }

                    // Decode the ImageLayout. This validates the configuration.
                    let image_layout = match layout::ImageLayout::decode(&min_header.encoded_image_layout) {
                        Ok(image_layout) => image_layout,
                        Err(e) => {
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };

                    // Verify at this point that the backend storage's minimum IO size is <= the one
                    // supported by the image. As an IO Block size is guaranteed to fit an u64 (and
                    // an usize as well), this will henceforth apply to the Chip IO Block size as
                    // well then.
                    let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();
                    if (image_layout.io_block_allocation_blocks_log2 as u32
                        + image_layout.allocation_block_size_128b_log2 as u32)
                        < chip_io_block_size_128b_log2
                    {
                        this.fut_state = ReadCoreImageHeaderFutureState::Done;
                        return task::Poll::Ready(Err(NvFsError::from(
                            CocoonFsFormatError::IoBlockSizeNotSupportedByDevice,
                        )));
                    }

                    // Decode the remainder of the image header.
                    // The salt.
                    let mut salt = match FixedVec::new_with_default(min_header.salt_len as usize) {
                        Ok(salt) => salt,
                        Err(e) => {
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    let mut salt_io_slice = io_slices::SingletonIoSliceMut::new(&mut salt);
                    if let Err(e) = salt_io_slice.copy_from_iter(&mut header_io_slice) {
                        // Infallible
                        match e {}
                    }
                    match salt_io_slice.is_empty() {
                        Ok(true) => (),
                        Ok(false) => {
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                        Err(e) => {
                            // Infallible.
                            match e {}
                        }
                    }

                    this.fut_state = ReadCoreImageHeaderFutureState::Done;
                    return task::Poll::Ready(Ok(ReadCoreImageHeaderFutureResult::StaticImageHeader(
                        StaticImageHeader { image_layout, salt },
                    )));
                }
                ReadCoreImageHeaderFutureState::ReadMkFsInfoHeaderRemainder {
                    read_fut,
                    min_header,
                    mkfsinfo_header_len,
                    first_header_part,
                    first_error,
                } => {
                    let second_header_part = match chip::NvChipFuture::poll(pin::Pin::new(read_fut), chip, cx) {
                        task::Poll::Ready(Ok((read_request, Ok(())))) => {
                            let ReadImageHeaderPartChipRequest { region: _, dst } = read_request;
                            dst
                        }
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                            match e {
                                NvChipIoError::IoBlockNotMapped => {
                                    match *first_error {
                                        None => {
                                            // Reading the MkFsInfoHeader remainder at the image's
                                            // beginning.  There is a MkFsInfoHeader magic, but the
                                            // IO request to read the remainder failed. This can
                                            // only happen if the encoded salt length determining
                                            // the total header size is invalid. Try to read the
                                            // backup MkFsInfoHeader, if any, instead.
                                            this.fut_state =
                                                ReadCoreImageHeaderFutureState::PrepareReadBackupMinMkFsInfoHeader {
                                                    first_error: NvFsError::from(NvChipIoError::IoBlockNotMapped),
                                                };
                                            continue;
                                        }
                                        Some(first_error) => {
                                            // Reading the MkFsInfoHeader remainder from the backup
                                            // location failied, give up.
                                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                            return task::Poll::Ready(Err(first_error));
                                        }
                                    }
                                }
                                _ => {
                                    this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                    return task::Poll::Ready(Err(NvFsError::from(e)));
                                }
                            };
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let first_header_part = mem::take(first_header_part);
                    this.fut_state = ReadCoreImageHeaderFutureState::DecodeMkFsInfoHeader {
                        min_header: min_header.clone(),
                        mkfsinfo_header_len: *mkfsinfo_header_len,
                        first_header_part,
                        second_header_part,
                        first_error: *first_error,
                    };
                }
                ReadCoreImageHeaderFutureState::DecodeMkFsInfoHeader {
                    min_header,
                    mkfsinfo_header_len,
                    first_header_part,
                    second_header_part,
                    first_error,
                } => {
                    // Verify the checksums.
                    let mut header_io_slice = io_slices::SingletonIoSlice::new(first_header_part)
                        .chain(io_slices::SingletonIoSlice::new(second_header_part));
                    // CRC of the header data.
                    let mut crc = crc32::crc32le_init();
                    // CRC of the header data with all neighboring bits swapped each.
                    let mut crc_snb = crc32::crc32le_init();

                    let mut checksummed_header_io_slice = header_io_slice.as_ref().take_exact(*mkfsinfo_header_len - 8);
                    while let Some(checksummed_header_part) = match checksummed_header_io_slice.next_slice(None) {
                        Ok(checksummed_header_part) => checksummed_header_part,
                        Err(e) => {
                            // Infallible.
                            match e {
                                io_slices::IoSlicesIterError::BackendIteratorError(e) => {
                                    // Infallible.
                                    match e {}
                                }
                                io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                                    io_slices::IoSlicesError::BuffersExhausted => {
                                        this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                        return task::Poll::Ready(Err(nvfs_err_internal!()));
                                    }
                                },
                            }
                        }
                    } {
                        crc = crc32::crc32le_update_data(crc, checksummed_header_part);
                        crc_snb = crc32::crc32le_update_data_snb(crc_snb, checksummed_header_part);
                    }

                    let mut expected_crc = [0u8; mem::size_of::<u32>()];
                    let mut expected_crc_io_slice = io_slices::SingletonIoSliceMut::new(&mut expected_crc);
                    if let Err(e) = expected_crc_io_slice.as_ref().copy_from_iter(&mut header_io_slice) {
                        // Infallible.
                        match e {}
                    }
                    if !match expected_crc_io_slice.is_empty() {
                        Ok(is_empty) => is_empty,
                        Err(e) => {
                            // Infallible.
                            match e {}
                        }
                    } {
                        this.fut_state = ReadCoreImageHeaderFutureState::Done;
                        return task::Poll::Ready(Err(nvfs_err_internal!()));
                    }
                    let expected_crc = u32::from_le_bytes(expected_crc);

                    let mut expected_crc_snb = [0u8; mem::size_of::<u32>()];
                    let mut expected_crc_snb_io_slice = io_slices::SingletonIoSliceMut::new(&mut expected_crc_snb);
                    if let Err(e) = expected_crc_snb_io_slice.as_ref().copy_from_iter(&mut header_io_slice) {
                        // Infallible.
                        match e {}
                    }
                    if !match expected_crc_snb_io_slice.is_empty() {
                        Ok(is_empty) => is_empty,
                        Err(e) => {
                            // Infallible.
                            match e {}
                        }
                    } {
                        this.fut_state = ReadCoreImageHeaderFutureState::Done;
                        return task::Poll::Ready(Err(nvfs_err_internal!()));
                    }
                    let expected_crc_snb = u32::from_le_bytes(expected_crc_snb);

                    if !crc32::crc32le_finish_receive(crc, expected_crc)
                        || !crc32::crc32le_finish_receive(crc_snb, expected_crc_snb)
                    {
                        // Checksum mismatch. Proceed with attempting to read the backup MkFsInfoHeader,
                        // if not currently there yet.
                        match *first_error {
                            None => {
                                this.fut_state = ReadCoreImageHeaderFutureState::PrepareReadBackupMinMkFsInfoHeader {
                                    first_error: NvFsError::from(CocoonFsFormatError::InvalidImageHeaderChecksum),
                                };
                                continue;
                            }
                            Some(first_error) => {
                                // Just failed to read the backup MkFsInfoHeader.
                                this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                return task::Poll::Ready(Err(first_error));
                            }
                        }
                    }

                    // Decode the mkfsinfo image header.
                    let mut header_io_slice = io_slices::SingletonIoSlice::new(first_header_part)
                        .chain(io_slices::SingletonIoSlice::new(second_header_part));

                    if let Err(e) = header_io_slice.skip(MinMkFsInfoHeader::encoded_len() as usize) {
                        let e = match e {
                            io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                                io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
                            },
                            io_slices::IoSlicesIterError::BackendIteratorError(e) => {
                                // Infallible.
                                match e {}
                            }
                        };
                        this.fut_state = ReadCoreImageHeaderFutureState::Done;
                        return task::Poll::Ready(Err(e));
                    }

                    // Decode the ImageLayout. This validates the configuration.
                    let image_layout = match layout::ImageLayout::decode(&min_header.encoded_image_layout) {
                        Ok(image_layout) => image_layout,
                        Err(e) => {
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };

                    // Verify at this point that the backend storage's minimum IO size is <= the one
                    // supported by the image. As an IO Block size is guaranteed to fit an u64 (and
                    // an usize as well), this will henceforth apply to the Chip IO Block size as
                    // well then.
                    let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();
                    if (image_layout.io_block_allocation_blocks_log2 as u32
                        + image_layout.allocation_block_size_128b_log2 as u32)
                        < chip_io_block_size_128b_log2
                    {
                        this.fut_state = ReadCoreImageHeaderFutureState::Done;
                        return task::Poll::Ready(Err(NvFsError::from(
                            CocoonFsFormatError::IoBlockSizeNotSupportedByDevice,
                        )));
                    }

                    // Decode the remainder of the MkFsInfoHeader.
                    // The salt.
                    let mut salt = match FixedVec::new_with_default(min_header.salt_len as usize) {
                        Ok(salt) => salt,
                        Err(e) => {
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    let mut salt_io_slice = io_slices::SingletonIoSliceMut::new(&mut salt);
                    if let Err(e) = salt_io_slice.copy_from_iter(&mut header_io_slice) {
                        // Infallible
                        match e {}
                    }
                    match salt_io_slice.is_empty() {
                        Ok(true) => (),
                        Ok(false) => {
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                        Err(e) => {
                            // Infallible.
                            match e {}
                        }
                    }

                    let image_size = min_header.image_size;
                    let from_backup = first_error.is_some();
                    this.fut_state = ReadCoreImageHeaderFutureState::Done;
                    return task::Poll::Ready(Ok(ReadCoreImageHeaderFutureResult::MkFsInfoHeader {
                        header: MkFsInfoHeader {
                            image_layout,
                            image_size,
                            salt,
                        },
                        from_backup,
                    }));
                }
                ReadCoreImageHeaderFutureState::PrepareReadBackupMinMkFsInfoHeader { first_error } => {
                    let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();
                    let chip_io_blocks = chip.chip_io_blocks();
                    let chip_io_blocks = chip_io_blocks.min(u64::MAX >> (chip_io_block_size_128b_log2 + 7));
                    let backup_location_chip_io_blocks_begin =
                        match MkFsInfoHeader::physical_backup_location_chip_io_blocks_begin(
                            chip_io_blocks,
                            chip_io_block_size_128b_log2,
                        ) {
                            Ok(backup_location_chip_io_blocks_begin) => backup_location_chip_io_blocks_begin,
                            Err(_) => {
                                // Failure to deduce the backup location from the storage dimensions
                                // indicates that they're invalid/unusable anyway.
                                let first_error = *first_error;
                                this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                return task::Poll::Ready(Err(first_error));
                            }
                        };

                    // Read the first Chip minimum IO Block at the backup location, which is always
                    // >= 128 bytes by definition, which suffices to store the MinMkFsInfoHeader,
                    // which in turn contain all information to subsequently deduce the full header
                    // size.
                    const _: () = assert!(MinMkFsInfoHeader::encoded_len() <= 128);
                    let read_request = match ReadImageHeaderPartChipRequest::new(
                        backup_location_chip_io_blocks_begin,
                        1,
                        chip_io_block_size_128b_log2,
                    ) {
                        Ok(read_request) => read_request,
                        Err(e) => {
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    let read_fut = chip.read(read_request).and_then(|r| r.map_err(|(_, e)| e));
                    let read_fut = match read_fut {
                        Ok(read_fut) => read_fut,
                        Err(NvChipIoError::IoBlockNotMapped) => {
                            // There doesn't seem to be a backup.
                            let first_error = *first_error;
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(first_error));
                        }
                        Err(e) => {
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    this.fut_state = ReadCoreImageHeaderFutureState::ReadBackupMinMkFsInfoHeader {
                        read_fut,
                        backup_location_chip_io_blocks_begin,
                        first_error: *first_error,
                    };
                }
                ReadCoreImageHeaderFutureState::ReadBackupMinMkFsInfoHeader {
                    read_fut,
                    backup_location_chip_io_blocks_begin,
                    first_error,
                } => {
                    let first_header_part = match chip::NvChipFuture::poll(pin::Pin::new(read_fut), chip, cx) {
                        task::Poll::Ready(Ok((read_request, Ok(())))) => {
                            let ReadImageHeaderPartChipRequest { region: _, dst } = read_request;
                            dst
                        }
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                            match e {
                                NvChipIoError::IoBlockNotMapped => {
                                    // There doesn't seem to be a backup.
                                    let first_error = *first_error;
                                    this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                    return task::Poll::Ready(Err(first_error));
                                }
                                _ => {
                                    this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                    return task::Poll::Ready(Err(NvFsError::from(e)));
                                }
                            };
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    // Try to decode the MinMkFsInfoHeader read from the backup location.
                    match MinMkFsInfoHeader::decode(&first_header_part) {
                        Ok(min_mkfsinfo_header) => {
                            // Ok, there is something which seems to be a
                            // MkFsInfoHeader. Try to read its remainder, if any.
                            let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();
                            debug_assert_eq!(first_header_part.len(), 1usize << (chip_io_block_size_128b_log2 + 7));
                            let mkfsinfo_header_len = MkFsInfoHeader::encoded_len(min_mkfsinfo_header.salt_len);
                            // Remember from above: it is known by now that the Chip IO Block size fits an
                            // u64.
                            let remaining_mkfsinfo_header_len =
                                (mkfsinfo_header_len as u64).saturating_sub(first_header_part.len() as u64);
                            if remaining_mkfsinfo_header_len == 0 {
                                this.fut_state = ReadCoreImageHeaderFutureState::DecodeMkFsInfoHeader {
                                    min_header: min_mkfsinfo_header,
                                    mkfsinfo_header_len: mkfsinfo_header_len as usize,
                                    first_header_part,
                                    second_header_part: FixedVec::new_empty(),
                                    first_error: Some(*first_error),
                                };

                                continue;
                            }

                            let mut remaining_header_chip_io_blocks =
                                remaining_mkfsinfo_header_len >> (chip_io_block_size_128b_log2 + 7);
                            if remaining_header_chip_io_blocks << (chip_io_block_size_128b_log2 + 7)
                                != remaining_mkfsinfo_header_len
                            {
                                remaining_header_chip_io_blocks += 1;
                            };
                            let read_request = match ReadImageHeaderPartChipRequest::new(
                                *backup_location_chip_io_blocks_begin + 1,
                                remaining_header_chip_io_blocks,
                                chip_io_block_size_128b_log2,
                            ) {
                                Ok(read_request) => read_request,
                                Err(e) => {
                                    this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                    return task::Poll::Ready(Err(e));
                                }
                            };
                            let read_fut = chip.read(read_request).and_then(|r| r.map_err(|(_, e)| e));
                            let read_fut = match read_fut {
                                Ok(read_fut) => read_fut,
                                Err(NvChipIoError::IoBlockNotMapped) => {
                                    // There is a MkFsInfoHeader magic, but the IO request setup
                                    // failed.  This can only happen if the encoded salt length
                                    // determining the total header size is invalid.
                                    let first_error = *first_error;
                                    this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                    return task::Poll::Ready(Err(first_error));
                                }
                                Err(e) => {
                                    this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                    return task::Poll::Ready(Err(NvFsError::from(e)));
                                }
                            };
                            this.fut_state = ReadCoreImageHeaderFutureState::ReadMkFsInfoHeaderRemainder {
                                read_fut,
                                min_header: min_mkfsinfo_header,
                                mkfsinfo_header_len: mkfsinfo_header_len as usize,
                                first_header_part,
                                first_error: Some(*first_error),
                            };
                        }
                        Err(NvFsError::Internal) => {
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::Internal));
                        }
                        Err(_) => {
                            // No MinMkFsInfoHeader found at the backup location.
                            let first_error = *first_error;
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(first_error));
                        }
                    };
                }
                ReadCoreImageHeaderFutureState::Done => unreachable!(),
            }
        }
    }
}

/// Read the [`MutableImageHeader`].
pub struct ReadMutableImageHeaderFuture<C: chip::NvChip> {
    image_layout: layout::ImageLayout,
    salt_len: u8,
    fut_state: ReadMutableImageHeaderFutureState<C>,
}

/// [`ReadMutableImageHeaderFuture`] state-machine state.
enum ReadMutableImageHeaderFutureState<C: chip::NvChip> {
    Init {
        _phantom: marker::PhantomData<fn() -> *const C>,
    },
    ReadHeader {
        read_fut: C::ReadFuture<ReadImageHeaderPartChipRequest>,
    },
    Done,
}

impl<C: chip::NvChip> ReadMutableImageHeaderFuture<C> {
    pub fn new(static_image_header: &StaticImageHeader) -> Result<Self, NvFsError> {
        let salt_len = u8::try_from(static_image_header.salt.len())
            .map_err(|_| NvFsError::from(CocoonFsFormatError::InvalidSaltLength))?;

        Ok(Self {
            image_layout: static_image_header.image_layout.clone(),
            salt_len,
            fut_state: ReadMutableImageHeaderFutureState::Init {
                _phantom: marker::PhantomData,
            },
        })
    }
}

impl<C: chip::NvChip> chip::NvChipFuture<C> for ReadMutableImageHeaderFuture<C> {
    type Output = Result<MutableImageHeader, NvFsError>;

    fn poll(self: pin::Pin<&mut Self>, chip: &C, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                ReadMutableImageHeaderFutureState::Init { _phantom } => {
                    let image_layout = &this.image_layout;
                    let mutable_header_allocation_blocks_range =
                        MutableImageHeader::physical_location(image_layout, this.salt_len);
                    // The mutable header's beginning is aligned to an IO Block boundary, which
                    // means it's also aligned to a Chip IO block boundary.
                    debug_assert_eq!(
                        mutable_header_allocation_blocks_range
                            .begin()
                            .align_down(image_layout.io_block_allocation_blocks_log2 as u32),
                        mutable_header_allocation_blocks_range.begin()
                    );

                    let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();
                    let chip_io_block_allocation_blocks_log2 = chip_io_block_size_128b_log2
                        .saturating_sub(image_layout.allocation_block_size_128b_log2 as u32);
                    let allocation_block_chip_io_blocks_log2 = (image_layout.allocation_block_size_128b_log2 as u32)
                        .saturating_sub(chip_io_block_allocation_blocks_log2);
                    let mutable_header_chip_io_blocks_begin = u64::from(mutable_header_allocation_blocks_range.begin())
                        >> chip_io_block_allocation_blocks_log2
                        << allocation_block_chip_io_blocks_log2;
                    let mutable_header_chip_io_blocks_count =
                        ((u64::from(mutable_header_allocation_blocks_range.block_count()) - 1)
                            >> chip_io_block_allocation_blocks_log2)
                            + 1;
                    if mutable_header_chip_io_blocks_count << allocation_block_chip_io_blocks_log2
                        >> allocation_block_chip_io_blocks_log2
                        != mutable_header_chip_io_blocks_count
                    {
                        this.fut_state = ReadMutableImageHeaderFutureState::Done;
                        return task::Poll::Ready(Err(NvFsError::IoError(NvFsIoError::RegionOutOfRange)));
                    }
                    let mutable_header_chip_io_blocks_count =
                        mutable_header_chip_io_blocks_count << allocation_block_chip_io_blocks_log2;

                    let read_request = match ReadImageHeaderPartChipRequest::new(
                        mutable_header_chip_io_blocks_begin,
                        mutable_header_chip_io_blocks_count,
                        chip_io_block_size_128b_log2,
                    ) {
                        Ok(read_request) => read_request,
                        Err(e) => {
                            this.fut_state = ReadMutableImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    let read_fut = match chip.read(read_request).and_then(|r| r.map_err(|(_, e)| e)) {
                        Ok(read_fut) => read_fut,
                        Err(e) => {
                            this.fut_state = ReadMutableImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    this.fut_state = ReadMutableImageHeaderFutureState::ReadHeader { read_fut };
                }
                ReadMutableImageHeaderFutureState::ReadHeader { read_fut } => {
                    let encoded_header = match chip::NvChipFuture::poll(pin::Pin::new(read_fut), chip, cx) {
                        task::Poll::Ready(Ok((read_request, Ok(())))) => {
                            let ReadImageHeaderPartChipRequest { region: _, dst } = read_request;
                            dst
                        }
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                            this.fut_state = ReadMutableImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    this.fut_state = ReadMutableImageHeaderFutureState::Done;
                    return task::Poll::Ready(MutableImageHeader::decode(
                        io_slices::SingletonIoSlice::new(&encoded_header).map_infallible_err(),
                        &this.image_layout,
                    ));
                }
                ReadMutableImageHeaderFutureState::Done => unreachable!(),
            }
        }
    }
}

/// Filesystem creation info header prefix of minimum possible length.
///
/// Used to decode the salt length needed for determining the actual filesystem
/// header size.
#[derive(Clone)]
struct MinMkFsInfoHeader {
    encoded_image_layout: [u8; layout::ImageLayout::encoded_len() as usize],
    image_size: layout::AllocBlockCount,
    salt_len: u8,
}

impl MinMkFsInfoHeader {
    /// Encoded length of a [`MinMkFsInfoHeader`].
    const fn encoded_len() -> u8 {
        const ENCODED_LEN: u32 = {
            // Magic 'CCFSMKFS'.
            let mut encoded_len = 8u32;
            // The u8 image format version.
            encoded_len += mem::size_of::<u8>() as u32;
            // The encoded ImageLayout.
            encoded_len += layout::ImageLayout::encoded_len() as u32;
            // The desired filesystem image size in units of Allocation Blocks.
            encoded_len += mem::size_of::<u64>() as u32;
            // The length of the salt as an u8.
            encoded_len += mem::size_of::<u8>() as u32;

            encoded_len
        };

        #[allow(clippy::assertions_on_constants)]
        let _: () = assert!(ENCODED_LEN <= 128);

        ENCODED_LEN as u8
    }

    /// Decode the [`MinMkFsInfoHeader`] from a buffer.
    ///
    /// # Arguments:
    ///
    /// * `buf` - The source buffer. Must be at least
    ///   [`encoded_len()`](Self::encoded_len) in length.
    fn decode(buf: &[u8]) -> Result<Self, NvFsError> {
        if buf.len() < Self::encoded_len() as usize {
            return Err(nvfs_err_internal!());
        }

        let expected_magic = b"CCFSMKFS";
        let (magic, buf) = buf.split_at(expected_magic.len());
        if magic != expected_magic {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidImageHeaderMagic));
        }

        let (version, buf) = buf.split_at(mem::size_of::<u8>());
        // The from_le_bytes() is a nop for an u8, but this mirrors the encoding part.
        let version =
            u8::from_le_bytes(*<&[u8; mem::size_of::<u8>()]>::try_from(version).map_err(|_| nvfs_err_internal!())?);
        if version != 0 {
            return Err(NvFsError::from(CocoonFsFormatError::UnsupportedFormatVersion));
        }

        let (encoded_image_layout, buf) = buf.split_at(layout::ImageLayout::encoded_len() as usize);
        let encoded_image_layout = <&[u8; layout::ImageLayout::encoded_len() as usize]>::try_from(encoded_image_layout)
            .map_err(|_| nvfs_err_internal!())?;

        let (image_size, buf) = buf.split_at(mem::size_of::<u64>());
        let image_size = layout::AllocBlockCount::from(u64::from_le_bytes(
            *<&[u8; mem::size_of::<u64>()]>::try_from(image_size).map_err(|_| nvfs_err_internal!())?,
        ));

        let (salt_len, _) = buf.split_at(mem::size_of::<u8>());
        // The from_le_bytes() is a nop for an u8, as is the usize::try_from()
        // conversion, but this mirrors the encoding part.
        let salt_len =
            u8::from_le_bytes(*<&[u8; mem::size_of::<u8>()]>::try_from(salt_len).map_err(|_| nvfs_err_internal!())?);

        Ok(Self {
            encoded_image_layout: *encoded_image_layout,
            image_size,
            salt_len,
        })
    }
}

/// Filesystem creation info header.
///
/// In order to enable initial filesystem image provisioning by a third party
/// not in possession of the root key, a valid filesystem may have a
/// `MkFsInfoHeader` at the place where the regulat [`StaticImageHeader`]
/// would normally be found, i.e. at the storage head. If such one is found
/// at first filesystem opening time, which always requires access to the root
/// key, the filesystem will get created then.
///
/// Note that during that process, the `MkFsInfoHeader` on storage will
/// necessarily get overwritten by a [`StaticImageHeader`] at some point.  For
/// robustness against possible service interruptions during that write, a copy
/// of the `MkfsInfoHeader` header will get placed at a well defined
/// location determined exclusively from the storage's dimensions. If header
/// checksum verification fails during the [`core header
/// read`](ReadCoreImageHeaderFuture), that routine will attempt to
/// load a `MkFsInfoHeader` from that backup location instead. For
/// interoperability with hardware having a possibly larger native [IO block
/// size](chip::NvChip::chip_io_block_size_128b_log2), meaningful error
/// reporting in particular, the location is chosen such that it has a large
/// alignment. More specifically: the largest possible power of two is chosen
/// such that the storage can accomodate at least 16 blocks of that size. The
/// backup header is then placed at the beginning of the last such block.
pub struct MkFsInfoHeader {
    /// The filesystem's [`ImageLayout`] configuration parameters.
    pub image_layout: layout::ImageLayout,
    /// The desired filesystem image size in units of Allocation Blocks.
    pub image_size: layout::AllocBlockCount,
    /// The filesystem's salt value.
    pub salt: FixedVec<u8, 4>,
}

impl MkFsInfoHeader {
    /// Encoded length of a [`MkFsInfoHeader`].
    ///
    /// Returns the encoded length of a [`MkFsInfoHeader`] with a salt length
    /// of `salt_len` without any of the padding to align to the next [IO
    /// Block](layout::ImageLayout::io_block_allocation_blocks_log2) boundary
    /// included.
    ///
    /// # Arguments:
    ///
    /// * `salt_len` - Length of the salt stored in the [`MkFsInfoHeader`].
    pub fn encoded_len(salt_len: u8) -> u32 {
        // The minimal common header containing everything needed to deduce the full
        // header's length.
        let mut encoded_len = MinMkFsInfoHeader::encoded_len() as u32;

        // And the image salt.
        encoded_len += salt_len as u32;

        // The length of two CRCs -- one on the plain mkfs header data, one with all
        // neighboring bits swapped each.
        encoded_len += 2 * (mem::size_of::<u32>() as u32);

        encoded_len
    }

    /// Determine the beginning of the backup [`MkFsInfoHeader`]'s location in
    /// units of 128B multiples.
    ///
    /// Returns a pair of the backup header's beginning on storage and the
    /// base-2 logarithm of the location's alignment, both in units of 128B
    /// multiples. The alignment is guaranteed to be no less than four times
    /// 128B, i.e. 512B, and there will be at least one full block of that
    /// alignment size available at the returned position on storage.
    ///
    /// # Arguments:
    ///
    /// * `chip_io_blocks` - Value of
    ///   [`NvChip::chip_io_blocks()`](chip::NvChip::chip_io_blocks).
    /// * `chip_io_block_size_128b_log2` - Value of
    ///   [`NvChip::chip_io_block_size_128b_log2()`](chip::NvChip::chip_io_block_size_128b_log2).
    fn physical_backup_location_begin_128b(
        chip_io_blocks: u64,
        chip_io_block_size_128b_log2: u32,
    ) -> Result<(u64, u32), NvFsError> {
        if chip_io_block_size_128b_log2 >= u64::BITS - 7 {
            return Err(NvFsError::IoError(NvFsIoError::RegionOutOfRange));
        }

        let chip_size_128b = chip_io_blocks << chip_io_block_size_128b_log2;
        if chip_size_128b == 0 || chip_size_128b >> chip_io_block_size_128b_log2 != chip_io_blocks {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidImageSize));
        }

        // Partition the image into blocks of largest possible alignment, such that
        // there are at least 16 of these and take the last.
        let chip_size_128b_log2 = chip_size_128b.ilog2();
        // The aligned blocks should be able to contain the MkfsInfoHeader in full,
        // which may need 3 * 128b < 2^2 * 128b.
        if chip_size_128b_log2 < 4 + 2 {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidImageSize));
        }

        let backup_location_begin_alignment_128b_log2 = chip_size_128b_log2 - 4;
        // The last aligned block on storage.
        let backup_location_begin_128b = ((chip_size_128b >> backup_location_begin_alignment_128b_log2) - 1)
            << backup_location_begin_alignment_128b_log2;
        debug_assert!(backup_location_begin_128b < chip_size_128b);
        debug_assert!(chip_size_128b - backup_location_begin_128b >= 4);
        // The backup is in the storage's last octile.
        debug_assert!(backup_location_begin_128b >= chip_size_128b - chip_size_128b.div_ceil(8));
        Ok((backup_location_begin_128b, backup_location_begin_alignment_128b_log2))
    }

    /// Determine the beginning of the backup [`MkFsInfoHeader`]'s location in
    /// units of [Chip IO Blocks](chip::NvChip::chip_io_block_size_128b_log2).
    ///
    /// Returns the backup header's beginning on storage in units of [Chip IO
    /// Blocks](chip::NvChip::chip_io_block_size_128b_log2). The location is
    /// guaranteed to be aligned by the [`Chip IO
    /// Block`](chip::NvChip::chip_io_block_size_128b_log2) size,
    /// and there will be at least one block of that size or 512B available at
    /// that location on storage, whichever is larger.
    ///
    /// # Arguments:
    ///
    /// * `chip_io_blocks` - Value of
    ///   [`NvChip::chip_io_blocks()`](chip::NvChip::chip_io_blocks).
    /// * `chip_io_block_size_128b_log2` - Value of
    ///   [`NvChip::chip_io_block_size_128b_log2()`](chip::NvChip::chip_io_block_size_128b_log2).
    fn physical_backup_location_chip_io_blocks_begin(
        chip_io_blocks: u64,
        chip_io_block_size_128b_log2: u32,
    ) -> Result<u64, NvFsError> {
        let (backup_location_begin_128b, backup_location_begin_alignment_128b_log2) =
            Self::physical_backup_location_begin_128b(chip_io_blocks, chip_io_block_size_128b_log2)?;
        if backup_location_begin_alignment_128b_log2 < chip_io_block_size_128b_log2 {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidImageSize));
        }
        debug_assert!(backup_location_begin_128b.is_aligned_pow2(chip_io_block_size_128b_log2));
        Ok(backup_location_begin_128b >> chip_io_block_size_128b_log2)
    }

    /// Determine the backup [`MkFsInfoHeader`]'s location on storage.
    ///
    /// Returns the backup header's [extent](layout::PhysicalAllocBlockRange) on
    /// storage. The returned extent is guaranteed to be aligned by the
    /// [`Chip IO Block`](chip::NvChip::chip_io_block_size_128b_log2) size,
    /// and within the bounds of the backing storage.
    ///
    /// The extent's beginning, but not necessarily its end, is also aligned to
    /// the block size determined by `io_block_allocation_blocks_log2`. The
    /// backing storage will provide at least one full block of that size at
    /// the location, even though the returned extent might not fully extend
    /// through it.
    ///
    /// # Arguments:
    ///
    /// * `salt_len` - Length of the filesystem salt to be stored in the
    ///   [`MkFsInfoHeader`].
    /// * `chip_io_blocks` - Value of
    ///   [`NvChip::chip_io_blocks()`](chip::NvChip::chip_io_blocks).
    /// * `chip_io_block_size_128b_log2` - Value of
    ///   [`NvChip::chip_io_block_size_128b_log2()`](chip::NvChip::chip_io_block_size_128b_log2).
    /// * `io_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::io_block_allocation_blocks_log2`].
    /// * `allocation_block_size_128b_log2` - Verbatim value of
    ///   [`ImageLayout::allocation_block_size_128b_log2`].
    pub fn physical_backup_location(
        salt_len: u8,
        chip_io_blocks: u64,
        chip_io_block_size_128b_log2: u32,
        io_block_allocation_blocks_log2: u32,
        allocation_block_size_128b_log2: u32,
    ) -> Result<layout::PhysicalAllocBlockRange, NvFsError> {
        let (backup_location_begin_128b, backup_location_begin_alignment_128b_log2) =
            Self::physical_backup_location_begin_128b(chip_io_blocks, chip_io_block_size_128b_log2)?;
        // Any HW with a compatible chip_io_block_size_128b_log2 should be guaranteed
        // to arrive at the same location and discover the backup.
        if backup_location_begin_alignment_128b_log2 < io_block_allocation_blocks_log2 + allocation_block_size_128b_log2
        {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidImageSize));
        }
        debug_assert!(
            backup_location_begin_128b
                .is_aligned_pow2(io_block_allocation_blocks_log2 + allocation_block_size_128b_log2)
        );
        let backup_location_allocation_blocks_begin =
            layout::PhysicalAllocBlockIndex::from(backup_location_begin_128b >> allocation_block_size_128b_log2);

        let encoded_len = Self::encoded_len(salt_len);
        // Make the returned extent to align with the Chip IO Block size. There will be
        // enough room at the end of the storage: one block of size as specified
        // by backup_location_begin_alignment_128b_log2 is large enough to hold
        // the MkFsInfoHeader.
        let chip_io_block_allocation_blocks_log2 =
            chip_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);
        let header_chip_io_blocks =
            ((encoded_len - 1) >> (chip_io_block_allocation_blocks_log2 + allocation_block_size_128b_log2 + 7)) + 1;
        let header_allocation_blocks =
            layout::AllocBlockCount::from((header_chip_io_blocks as u64) << chip_io_block_allocation_blocks_log2);

        Ok(layout::PhysicalAllocBlockRange::from((
            backup_location_allocation_blocks_begin,
            header_allocation_blocks,
        )))
    }

    /// Encode a [`MkFsInfoHeader`].
    ///
    /// # Arguments:
    ///
    /// * `dst` - The destination buffers. Their total length must be at least
    ///   that returned by [`encoded_len()`](Self::encoded_len).
    /// * `image_layout` - The filesystem image's [`ImageLayout`] to be stored
    ///   in the [`MkFsInfoHeader`].
    /// * `image_size` - The desired filesystem image size to be stored in the
    ///   [`MkFsInfoHeader`].
    /// * `salt` - The filesystem salt to be stored in the [`MkFsInfoHeader`].
    ///   It's length must not exceed `u8::MAX`.
    pub fn encode<'a, DI: io_slices::IoSlicesMutIter<'a, BackendIteratorError = NvFsError>>(
        mut dst: DI,
        image_layout: &layout::ImageLayout,
        image_size: layout::AllocBlockCount,
        salt: &[u8],
    ) -> Result<(), NvFsError> {
        // CRC of the header data.
        let mut crc = crc32::crc32le_init();
        // CRC of the header data with all neighboring bits swapped each.
        let mut crc_snb = crc32::crc32le_init();

        let magic = b"CCFSMKFS";
        crc = crc32::crc32le_update_data(crc, magic.as_slice());
        crc_snb = crc32::crc32le_update_data_snb(crc_snb, magic.as_slice());
        let mut magic = io_slices::SingletonIoSlice::new(magic.as_slice()).map_infallible_err();
        dst.copy_from_iter(&mut magic)?;
        if !magic.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let version = 0u8.to_le_bytes();
        crc = crc32::crc32le_update_data(crc, &version);
        crc_snb = crc32::crc32le_update_data_snb(crc_snb, &version);
        let mut version = io_slices::SingletonIoSlice::new(version.as_slice()).map_infallible_err();
        dst.copy_from_iter(&mut version)?;
        if !version.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let encoded_image_layout = image_layout.encode()?;
        crc = crc32::crc32le_update_data(crc, &encoded_image_layout);
        crc_snb = crc32::crc32le_update_data_snb(crc_snb, &encoded_image_layout);
        let mut encoded_image_layout =
            io_slices::SingletonIoSlice::new(encoded_image_layout.as_slice()).map_infallible_err();
        dst.copy_from_iter(&mut encoded_image_layout)?;
        if !encoded_image_layout.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let image_size = u64::from(image_size).to_le_bytes();
        crc = crc32::crc32le_update_data(crc, &image_size);
        crc_snb = crc32::crc32le_update_data_snb(crc_snb, &image_size);
        let mut image_size = io_slices::SingletonIoSlice::new(image_size.as_slice()).map_infallible_err();
        dst.copy_from_iter(&mut image_size)?;
        if !image_size.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let salt_len = u8::try_from(salt.len())
            .map_err(|_| NvFsError::from(CocoonFsFormatError::InvalidSaltLength))?
            .to_le_bytes();
        crc = crc32::crc32le_update_data(crc, &salt_len);
        crc_snb = crc32::crc32le_update_data_snb(crc_snb, &salt_len);
        let mut salt_len = io_slices::SingletonIoSlice::new(salt_len.as_slice()).map_infallible_err();
        dst.copy_from_iter(&mut salt_len)?;
        if !salt_len.is_empty()? {
            return Err(nvfs_err_internal!());
        }
        crc = crc32::crc32le_update_data(crc, salt);
        crc_snb = crc32::crc32le_update_data_snb(crc_snb, salt);
        let mut salt = io_slices::SingletonIoSlice::new(salt).map_infallible_err();
        dst.copy_from_iter(&mut salt)?;
        if !salt.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let crc = crc32::crc32le_finish_send(crc).to_le_bytes();
        let mut crc = io_slices::SingletonIoSlice::new(&crc).map_infallible_err();
        dst.copy_from_iter(&mut crc)?;
        if !crc.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let crc_snb = crc32::crc32le_finish_send(crc_snb).to_le_bytes();
        let mut crc_snb = io_slices::SingletonIoSlice::new(&crc_snb).map_infallible_err();
        dst.copy_from_iter(&mut crc_snb)?;
        if !crc_snb.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        Ok(())
    }
}
