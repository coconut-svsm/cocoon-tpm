// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Functionality related to the filesystem image header.

extern crate alloc;
use alloc::vec::Vec;

use crate::{
    chip::{self, ChunkedIoRegion, ChunkedIoRegionChunkRange, ChunkedIoRegionError},
    crypto::hash,
    fs::{
        cocoonfs::{extent_ptr, layout, CocoonFsFormatError},
        NvFsError, NvFsIoError,
    },
    nvfs_err_internal,
    utils_common::{
        alloc::try_alloc_vec,
        bitmanip::{BitManip as _, UBitManip as _},
        io_slices::{self, IoSlicesIter as _, IoSlicesIterCommon as _, IoSlicesMutIter as _},
    },
};
use core::{marker, mem, ops::Deref as _, pin, task};

/// Static image header of minimum possible length.
#[derive(Clone)]
struct MinStaticImageHeader {
    image_layout: layout::ImageLayout,
    salt_len: u8,
}

impl MinStaticImageHeader {
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
        let image_layout = layout::ImageLayout::decode(encoded_image_layout)?;

        let (salt_len, _) = buf.split_at(mem::size_of::<u8>());
        // The from_le_bytes() is a nop for an u8, as is the usize::try_from()
        // conversion, but this mirrors the encoding part.
        let salt_len =
            u8::from_le_bytes(*<&[u8; mem::size_of::<u8>()]>::try_from(salt_len).map_err(|_| nvfs_err_internal!())?);

        Ok(Self { image_layout, salt_len })
    }
}

/// Static image header.
pub struct StaticImageHeader {
    pub image_layout: layout::ImageLayout,
    pub salt: Vec<u8>,
}

impl StaticImageHeader {
    fn encoded_len(salt_len: u8) -> u32 {
        // The minimal common header containing everything needed to deduce the full
        // header's length.
        let mut encoded_len = MinStaticImageHeader::encoded_len() as u32;

        // And the image salt.
        // Verify that the salt length can get encoded in an u8.
        encoded_len += salt_len as u32;

        encoded_len
    }

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

    pub fn encode<'a, DI: io_slices::IoSlicesMutIter<'a, BackendIteratorError = NvFsError>>(
        mut dst: DI,
        image_layout: &layout::ImageLayout,
        salt: &[u8],
    ) -> Result<(), NvFsError> {
        let magic = b"COCOONFS";
        let mut magic = io_slices::SingletonIoSlice::new(magic.as_slice()).map_infallible_err();
        dst.copy_from_iter(&mut magic)?;
        if !magic.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let version = 0u8.to_le_bytes();
        let mut version = io_slices::SingletonIoSlice::new(version.as_slice()).map_infallible_err();
        dst.copy_from_iter(&mut version)?;
        if !version.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let encoded_image_layout = image_layout.encode()?;
        let mut encoded_image_layout =
            io_slices::SingletonIoSlice::new(encoded_image_layout.as_slice()).map_infallible_err();
        dst.copy_from_iter(&mut encoded_image_layout)?;
        if !encoded_image_layout.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let salt_len = u8::try_from(salt.len())
            .map_err(|_| NvFsError::from(CocoonFsFormatError::InvalidSaltLength))?
            .to_le_bytes();
        let mut salt_len = io_slices::SingletonIoSlice::new(salt_len.as_slice()).map_infallible_err();
        dst.copy_from_iter(&mut salt_len)?;
        if !salt_len.is_empty()? {
            return Err(nvfs_err_internal!());
        }
        let mut salt = io_slices::SingletonIoSlice::new(salt).map_infallible_err();
        dst.copy_from_iter(&mut salt)?;
        if !salt.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        Ok(())
    }
}

/// Mutable image header.
pub struct MutableImageHeader {
    pub root_hmac_digest: Vec<u8>,
    pub inode_index_entry_leaf_node_preauth_cca_protection_digest: Vec<u8>,
    pub inode_index_entry_leaf_node_block_ptr: extent_ptr::EncodedBlockPtr,
    pub image_size: layout::AllocBlockCount,
}

impl MutableImageHeader {
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

    pub fn decode<'a, SI: io_slices::IoSlicesIter<'a, BackendIteratorError = NvFsError>>(
        mut src: SI,
        image_layout: &layout::ImageLayout,
    ) -> Result<Self, NvFsError> {
        // And the root HMAC.
        let root_hmac_digest_len = hash::hash_alg_digest_len(image_layout.auth_tree_root_hmac_hash_alg) as usize;
        let mut root_hmac_digest = try_alloc_vec(root_hmac_digest_len)?;
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
            try_alloc_vec(inode_index_entry_leaf_node_preauth_cca_protection_digest_len)?;
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

struct ReadImageHeaderPartChipRequest {
    region: ChunkedIoRegion,
    dst: Vec<u8>,
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
        let dst = try_alloc_vec(read_region_len)?;

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

/// Read the [`StaticImageHeader`].
pub struct ReadStaticImageHeaderFuture<C: chip::NvChip> {
    fut_state: ReadStaticImageHeaderFutureState<C>,
}

enum ReadStaticImageHeaderFutureState<C: chip::NvChip> {
    Init {
        _phantom: marker::PhantomData<fn() -> *const C>,
    },
    ReadMinHeader {
        read_fut: C::ReadFuture<ReadImageHeaderPartChipRequest>,
    },
    ReadHeaderRemainder {
        read_fut: C::ReadFuture<ReadImageHeaderPartChipRequest>,
        min_header: MinStaticImageHeader,
        first_header_part: Vec<u8>,
    },
    DecodeHeaderRemainder {
        min_header: MinStaticImageHeader,
        first_header_part: Vec<u8>,
        second_header_part: Vec<u8>,
    },
    Done,
}

impl<C: chip::NvChip> ReadStaticImageHeaderFuture<C> {
    pub fn new() -> Self {
        Self {
            fut_state: ReadStaticImageHeaderFutureState::Init {
                _phantom: marker::PhantomData,
            },
        }
    }
}

impl<C: chip::NvChip> chip::NvChipFuture<C> for ReadStaticImageHeaderFuture<C> {
    type Output = Result<StaticImageHeader, NvFsError>;

    fn poll(self: pin::Pin<&mut Self>, chip: &C, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                ReadStaticImageHeaderFutureState::Init { _phantom } => {
                    let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();

                    // Read the first Chip minimum IO Block, which is always >= 128 bytes by
                    // definition, which suffices to store the MinStaticImageHeader, which in turn
                    // contains all information to subsequently deduce the full header size.
                    const _: () = assert!(MinStaticImageHeader::encoded_len() <= 128);
                    let read_request = match ReadImageHeaderPartChipRequest::new(0, 1, chip_io_block_size_128b_log2) {
                        Ok(read_request) => read_request,
                        Err(e) => {
                            this.fut_state = ReadStaticImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    let read_fut = chip.read(read_request).and_then(|r| r.map_err(|(_, e)| e));
                    let read_fut = match read_fut {
                        Ok(read_fut) => read_fut,
                        Err(e) => {
                            this.fut_state = ReadStaticImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    this.fut_state = ReadStaticImageHeaderFutureState::ReadMinHeader { read_fut };
                }
                ReadStaticImageHeaderFutureState::ReadMinHeader { read_fut } => {
                    let first_header_part = match chip::NvChipFuture::poll(pin::Pin::new(read_fut), chip, cx) {
                        task::Poll::Ready(Ok((read_request, Ok(())))) => {
                            let ReadImageHeaderPartChipRequest { region: _, dst } = read_request;
                            dst
                        }
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                            this.fut_state = ReadStaticImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let min_header = match MinStaticImageHeader::decode(&first_header_part) {
                        Ok(min_header) => min_header,
                        Err(e) => {
                            this.fut_state = ReadStaticImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };

                    // Verify at this point that the backend storage's minimum IO size is <= the one
                    // supported by the image. As an IO Block size is guaranteed to fit an u64 (and
                    // an usize as well), this will henceforth apply to the Chip IO Block size as
                    // well then.
                    let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();
                    if (min_header.image_layout.io_block_allocation_blocks_log2 as u32
                        + min_header.image_layout.allocation_block_size_128b_log2 as u32)
                        < chip_io_block_size_128b_log2
                    {
                        this.fut_state = ReadStaticImageHeaderFutureState::Done;
                        return task::Poll::Ready(Err(NvFsError::from(
                            CocoonFsFormatError::IoBlockSizeNotSupportedByDevice,
                        )));
                    }

                    // Now that the MinStaticImageHeader has been read and decoded, deduce the total
                    // header length from it, read the remainder, if any, and continue with the
                    // decoding.
                    let static_header_len = StaticImageHeader::encoded_len(min_header.salt_len) as u64;
                    debug_assert_eq!(first_header_part.len(), 1usize << (chip_io_block_size_128b_log2 + 7));
                    // Remember from above: it is known by now that the Chip IO Block size fits an
                    // u64.
                    let remaining_static_header_len = static_header_len.saturating_sub(first_header_part.len() as u64);
                    if remaining_static_header_len == 0 {
                        this.fut_state = ReadStaticImageHeaderFutureState::DecodeHeaderRemainder {
                            min_header,
                            first_header_part,
                            second_header_part: Vec::new(),
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
                            this.fut_state = ReadStaticImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    let read_fut = chip.read(read_request).and_then(|r| r.map_err(|(_, e)| e));
                    let read_fut = match read_fut {
                        Ok(read_fut) => read_fut,
                        Err(e) => {
                            this.fut_state = ReadStaticImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    this.fut_state = ReadStaticImageHeaderFutureState::ReadHeaderRemainder {
                        read_fut,
                        min_header,
                        first_header_part,
                    };
                }
                ReadStaticImageHeaderFutureState::ReadHeaderRemainder {
                    read_fut,
                    min_header,
                    first_header_part,
                } => {
                    let second_header_part = match chip::NvChipFuture::poll(pin::Pin::new(read_fut), chip, cx) {
                        task::Poll::Ready(Ok((read_request, Ok(())))) => {
                            let ReadImageHeaderPartChipRequest { region: _, dst } = read_request;
                            dst
                        }
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                            this.fut_state = ReadStaticImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let first_header_part = mem::take(first_header_part);
                    this.fut_state = ReadStaticImageHeaderFutureState::DecodeHeaderRemainder {
                        min_header: min_header.clone(),
                        first_header_part,
                        second_header_part,
                    };
                }
                ReadStaticImageHeaderFutureState::DecodeHeaderRemainder {
                    min_header,
                    first_header_part,
                    second_header_part,
                } => {
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
                        this.fut_state = ReadStaticImageHeaderFutureState::Done;
                        return task::Poll::Ready(Err(e));
                    }

                    // Decode the remainder of the image header.
                    // The salt.
                    let mut salt = match try_alloc_vec(min_header.salt_len as usize) {
                        Ok(salt) => salt,
                        Err(e) => {
                            this.fut_state = ReadStaticImageHeaderFutureState::Done;
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
                            this.fut_state = ReadStaticImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                        Err(e) => {
                            // Infallible.
                            match e {}
                        }
                    }

                    let image_layout = min_header.image_layout.clone();
                    this.fut_state = ReadStaticImageHeaderFutureState::Done;
                    return task::Poll::Ready(Ok(StaticImageHeader { image_layout, salt }));
                }
                ReadStaticImageHeaderFutureState::Done => unreachable!(),
            }
        }
    }
}

/// Read the [`MutableImageHeader`].
pub struct ReadMutableImageHeaderFuture<C: chip::NvChip> {
    min_static_image_header: MinStaticImageHeader,
    fut_state: ReadMutableImageHeaderFutureState<C>,
}

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
            min_static_image_header: MinStaticImageHeader {
                image_layout: static_image_header.image_layout.clone(),
                salt_len,
            },
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
                    let min_header = &this.min_static_image_header;
                    let image_layout = &min_header.image_layout;
                    let mutable_header_allocation_blocks_range =
                        MutableImageHeader::physical_location(image_layout, min_header.salt_len);
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
                        &this.min_static_image_header.image_layout,
                    ));
                }
                ReadMutableImageHeaderFutureState::Done => unreachable!(),
            }
        }
    }
}
