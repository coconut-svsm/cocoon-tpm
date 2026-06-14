// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Functionality related to the filesystem image header.

use crate::{
    blkdev::{self, NvBlkDevIoError},
    crypto::hash,
    fs::{
        NvFsError, NvFsIoError,
        cocoonfs::{
            FormatError, ImageLayout, extent_ptr,
            integrity::{
                ExtentIntegrityState, ExtentTier0IntegrityState, extent_integrity_protections_apply,
                extent_integrity_protections_len, extent_integrity_protections_verify_and_remove,
                extent_tier0_integrity_protection_verify_and_remove,
            },
            layout,
        },
    },
    nvfs_err_internal,
    utils_common::{
        bitmanip::{BitManip as _, UBitManip as _},
        fixed_vec::FixedVec,
        io_slices::{self, IoSlicesIter as _, IoSlicesIterCommon as _, IoSlicesMutIter as _},
    },
};
use core::{marker, mem, ops::Deref as _, pin, task};

const MAGIC_COCOONFS: &[u8; 8] = b"COCOONFS";
const MAGIC_MKFS: &[u8; 8] = b"CCFSMKFS";

/// Static image header prefix of minimum possible length.
///
/// Used to decode the salt length needed for determining the actual filesystem
/// header size.
#[derive(Clone)]
struct MinStaticImageHeader {
    image_layout: layout::ImageLayout,
    salt_len: u8,
}

impl MinStaticImageHeader {
    /// Encoded length of a [`MinStaticImageHeader`].
    const fn encoded_len() -> u8 {
        const ENCODED_LEN: u32 = {
            // Magic 'COCOONFS'.
            let mut encoded_len = MAGIC_COCOONFS.len() as u32;
            // The u8 image format version.
            encoded_len += mem::size_of::<u8>() as u32;
            // The encoded ImageLayout.
            encoded_len += layout::ImageLayout::encoded_len() as u32;
            // The length of the salt as an u8.
            encoded_len += mem::size_of::<u8>() as u32;

            encoded_len
        };

        // The integrity protection section's offset, which follows the
        // MinStaticImageHeader, must be small enough that the minimum possible
        // integrity protection section is located within the first 128B, as per
        // the requirements of the integrity protection scheme.
        #[allow(clippy::assertions_on_constants)]
        let _: () = assert!(ENCODED_LEN <= 128 - extent_integrity_protections_len(0, 0));

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

        let (magic, buf) = buf.split_at(MAGIC_COCOONFS.len());
        if magic != MAGIC_COCOONFS {
            return Err(NvFsError::from(FormatError::InvalidImageHeader));
        }

        let (version, buf) = buf.split_at(mem::size_of::<u8>());
        // The from_le_bytes() is a nop for an u8, but this mirrors the encoding part.
        let version =
            u8::from_le_bytes(*<&[u8; mem::size_of::<u8>()]>::try_from(version).map_err(|_| nvfs_err_internal!())?);
        if version != 0 {
            return Err(NvFsError::from(FormatError::UnsupportedFormatVersion));
        }

        let (encoded_image_layout, buf) = buf.split_at(layout::ImageLayout::encoded_len() as usize);
        let image_layout = ImageLayout::decode(encoded_image_layout)?;
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
    /// The filesystem's [`ImageLayout`] configuration parameters.
    pub image_layout: layout::ImageLayout,
    /// The filesystem's salt value.
    pub salt: FixedVec<u8, 4>,
}

impl StaticImageHeader {
    /// Encoded length of a static image header.
    ///
    /// Returns the encoded length of a static image header with
    /// an [IO Block size](ImageLayout::io_block_allocation_blocks_log2) as
    /// specified by `io_block_allocation_blocks_log2`, an [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) as specified by
    /// `allocation_block_size_128b_log2` and with a salt length
    /// of `salt_len`, without any of the padding to align to the next [IO
    /// Block](layout::ImageLayout::io_block_allocation_blocks_log2) boundary
    /// included.
    ///
    /// The encoded length is guaranteed to not exceed the larger of `3 * 128`
    /// and the size of one
    /// [IO Block](ImageLayout::io_block_allocation_blocks_log2).
    ///
    /// # Arguments:
    ///
    /// * `io_block_allocation_blocks_log2` - Verbatim copy of
    ///   [`ImageLayout::io_block_allocation_blocks_log2`].
    /// * `allocation_block_size_128b_log2` - Verbatim copy of
    ///   [`ImageLayout::allocation_block_size_128b_log2`].
    /// * `salt_len` - Length of the salt stored in the static image header.
    ///
    /// # See also:
    ///
    /// * [`io_block_aligned_encoded_len_allocation_blocks()`](Self::io_block_aligned_encoded_len_allocation_blocks)
    fn encoded_len(io_block_allocation_blocks_log2: u8, allocation_block_size_128b_log2: u8, salt_len: u8) -> u32 {
        // The encoded length always is <= the larger of 3 * 128 and the IO Block size.
        // Verify case that the IO Block size <= 2 * 128:
        const _: () = assert!(
            3u64 * 128 - extent_integrity_protections_len(1, 0) as u64
                >= MinStaticImageHeader::encoded_len() as u64 + u8::MAX as u64
        );
        // Verify case that the IO Block size >= 4 * 128:
        const _: () = assert!(
            (1u64 << (2 + 7)) - extent_integrity_protections_len(2, 0) as u64
                >= MinStaticImageHeader::encoded_len() as u64 + u8::MAX as u64
        );

        // The minimal common header containing everything needed to deduce the full
        // header's length.
        let mut encoded_len = MinStaticImageHeader::encoded_len() as u32;

        // The integrity protection section.
        encoded_len +=
            extent_integrity_protections_len(io_block_allocation_blocks_log2, allocation_block_size_128b_log2);

        // And the image salt.
        encoded_len += salt_len as u32;

        encoded_len
    }

    /// [IO Block](layout::ImageLayout::io_block_allocation_blocks_log2) aligned
    /// length of a static image header.
    ///
    /// The static image header gets padded to the next [IO
    /// Block](ImageLayout::io_block_allocation_blocks_log2) boundary so
    /// that no writes to the filesystem image will ever affect its
    /// contents.
    ///
    /// Return the length of a static image header with
    /// an [IO Block size](ImageLayout::io_block_allocation_blocks_log2) as
    /// specified by `io_block_allocation_blocks_log2`, an [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) as specified by
    /// `allocation_block_size_128b_log2` and a salt length
    /// of `salt_len`, aligned to the next [IO
    /// Block](layout::ImageLayout::io_block_allocation_blocks_log2) boundary in
    /// units of [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    ///
    /// The aligned length in units of Bytes is guaranteed to never exceed the
    /// larger of `4 * 128` and one IO Block size.
    ///
    /// # Arguments:
    ///
    /// * `io_block_allocation_blocks_log2` - Verbatim copy of
    ///   [`ImageLayout::io_block_allocation_blocks_log2`].
    /// * `allocation_block_size_128b_log2` - Verbatim copy of
    ///   [`ImageLayout::allocation_block_size_128b_log2`].
    /// * `salt_len` - Length of the salt stored in the static image header.
    ///
    /// # See also:
    ///
    /// * [`encoded_len()`](Self::encoded_len).
    pub fn io_block_aligned_encoded_len_allocation_blocks(
        io_block_allocation_blocks_log2: u8,
        allocation_block_size_128b_log2: u8,
        salt_len: u8,
    ) -> layout::AllocBlockCount {
        let encoded_len = Self::encoded_len(
            io_block_allocation_blocks_log2,
            allocation_block_size_128b_log2,
            salt_len,
        ) as u64;

        // The length always fits the larger of a few multiples (<= 3) of 128 Bytes and
        // the IO Block size, as per the documented guarantees of encoded_len(),
        // hence is definitely <= than 2^63. The size of an IO Block in units of
        // Bytes is a power of two and <= 1^63 also. Hence the aligned result
        // (in units of Bytes) will be <= that uppber bound as well.
        layout::AllocBlockCount::from(
            encoded_len.round_up_pow2_unchecked(
                io_block_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32 + 7,
            ) >> (allocation_block_size_128b_log2 + 7),
        )
    }

    /// Encode a static image header.
    ///
    /// # Arguments:
    ///
    /// * `dst` - The destination buffers. Their total length must be exactly
    ///   that returned by
    ///   [`io_block_aligned_encoded_len_allocation_blocks()`](Self::io_block_aligned_encoded_len_allocation_blocks).
    /// * `image_layout` - The filesystem image's [`ImageLayout`] to be stored
    ///   in the static image header.
    /// * `salt` - The salt to be stored in the image header. It's length must
    ///   not exceed `u8::MAX`.
    pub fn encode<'a, DI: io_slices::MutPeekableIoSlicesMutIter<'a, BackendIteratorError = NvFsError>>(
        mut dst: DI,
        image_layout: &layout::ImageLayout,
        salt: &[u8],
    ) -> Result<(), NvFsError> {
        let mut encoding_dst = dst.decoupled_borrow_mut();
        let mut magic = io_slices::SingletonIoSlice::new(MAGIC_COCOONFS.as_slice()).map_infallible_err();
        encoding_dst.copy_from_iter(&mut magic)?;
        if !magic.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let version = 0u8.to_le_bytes();
        let mut version = io_slices::SingletonIoSlice::new(version.as_slice()).map_infallible_err();
        encoding_dst.copy_from_iter(&mut version)?;
        if !version.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let encoded_image_layout = image_layout.encode()?;
        let mut encoded_image_layout =
            io_slices::SingletonIoSlice::new(encoded_image_layout.as_slice()).map_infallible_err();
        encoding_dst.copy_from_iter(&mut encoded_image_layout)?;
        if !encoded_image_layout.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let salt_len = u8::try_from(salt.len())
            .map_err(|_| NvFsError::from(FormatError::InvalidSaltLength))?
            .to_le_bytes();
        let mut salt_len = io_slices::SingletonIoSlice::new(salt_len.as_slice()).map_infallible_err();
        encoding_dst.copy_from_iter(&mut salt_len)?;
        if !salt_len.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let integrity_protections_len = usize::try_from(extent_integrity_protections_len(
            image_layout.io_block_allocation_blocks_log2,
            image_layout.allocation_block_size_128b_log2,
        ))
        .map_err(|_| NvFsError::DimensionsNotSupported)?;
        encoding_dst.skip(integrity_protections_len).map_err(|e| match e {
            io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
            },
            io_slices::IoSlicesIterError::BackendIteratorError(e) => e,
        })?;

        let mut salt = io_slices::SingletonIoSlice::new(salt).map_infallible_err();
        encoding_dst.copy_from_iter(&mut salt)?;
        if !salt.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        drop(encoding_dst);

        extent_integrity_protections_apply(
            dst,
            MAGIC_COCOONFS.len(),
            MinStaticImageHeader::encoded_len() as usize - MAGIC_COCOONFS.len(),
            &ExtentIntegrityState::new_clean(),
            image_layout.io_block_allocation_blocks_log2,
            image_layout.allocation_block_size_128b_log2,
            1, // Only used for debug assertions.
        )?;

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
        // The mutable header is located at the first IO block boundary following the
        // static header.
        // The beginning in units of Bytes is <= 2^63.
        let mutable_header_allocation_blocks_begin = layout::PhysicalAllocBlockIndex::from(0u64)
            + StaticImageHeader::io_block_aligned_encoded_len_allocation_blocks(
                image_layout.io_block_allocation_blocks_log2,
                image_layout.allocation_block_size_128b_log2,
                salt_len,
            );
        let mutable_header_encoded_len: u32 = MutableImageHeader::encoded_len(image_layout);
        let mutable_header_allocation_blocks_count = layout::AllocBlockCount::from(
            ((mutable_header_encoded_len as u64 - 1) >> (image_layout.allocation_block_size_128b_log2 as u32 + 7)) + 1,
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
            Ok(None) => return Err(NvFsError::from(FormatError::InvalidExtents)),
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
            return Err(NvFsError::from(FormatError::InvalidImageSize));
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
pub struct ReadCoreImageHeaderFuture<B: blkdev::NvBlkDev> {
    fut_state: ReadCoreImageHeaderFutureState<B>,
}

/// [`ReadCoreImageHeaderFuture`] state-machine state.
enum ReadCoreImageHeaderFutureState<B: blkdev::NvBlkDev> {
    Init {
        _phantom: marker::PhantomData<fn() -> *const B>,
    },
    ReadMinHeader {
        read_fut: blkdev::helpers::NvBlkDevReadRegionFuture<B, FixedVec<u8, 7>>,
    },
    ReadStaticImageHeaderRemainder {
        read_fut: blkdev::helpers::NvBlkDevReadRegionFuture<B, FixedVec<u8, 7>>,
        min_header: MinStaticImageHeader,
        first_header_part: FixedVec<u8, 7>,
        tier0_integrity_state: ExtentTier0IntegrityState,
    },
    DecodeStaticImageHeader {
        min_header: MinStaticImageHeader,
        first_header_part: FixedVec<u8, 7>,
        second_header_part: FixedVec<u8, 7>,
        tier0_integrity_state: ExtentTier0IntegrityState,
    },
    TryDecodeMinMkFsInfoHeader {
        mkfsinfo_header_blkdev_io_blocks_begin: u64,
        first_header_part: FixedVec<u8, 7>,
    },
    ReadMkFsInfoHeaderRemainder {
        read_fut: blkdev::helpers::NvBlkDevReadRegionFuture<B, FixedVec<u8, 7>>,
        min_header: MinMkFsInfoHeader,
        first_header_part: FixedVec<u8, 7>,
        tier0_integrity_state: ExtentTier0IntegrityState,
        from_backup: bool,
    },
    DecodeMkFsInfoHeader {
        min_header: MinMkFsInfoHeader,
        first_header_part: FixedVec<u8, 7>,
        second_header_part: FixedVec<u8, 7>,
        tier0_integrity_state: ExtentTier0IntegrityState,
        from_backup: bool,
    },
    PrepareReadBackupMinMkFsInfoHeader,
    ReadBackupMinMkFsInfoHeader {
        read_fut: blkdev::helpers::NvBlkDevReadRegionFuture<B, FixedVec<u8, 7>>,
        backup_location_blkdev_io_blocks_begin: u64,
    },
    Done,
}

impl<B: blkdev::NvBlkDev> ReadCoreImageHeaderFuture<B> {
    pub fn new() -> Self {
        Self {
            fut_state: ReadCoreImageHeaderFutureState::Init {
                _phantom: marker::PhantomData,
            },
        }
    }
}

impl<B: blkdev::NvBlkDev> blkdev::NvBlkDevFuture<B> for ReadCoreImageHeaderFuture<B> {
    type Output = Result<ReadCoreImageHeaderFutureResult, NvFsError>;

    fn poll(self: pin::Pin<&mut Self>, blkdev: &B, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                ReadCoreImageHeaderFutureState::Init { _phantom } => {
                    let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();

                    // Read the first Device IO Block, which is always >= 128 bytes by definition,
                    // which suffices to store the MinStaticImageHeader as well as the
                    // MinMkFsInfoHeader, which in turn contain all information to subsequently
                    // deduce the full header size.
                    const _: () = assert!(MinStaticImageHeader::encoded_len() <= 128);
                    const _: () = assert!(MinMkFsInfoHeader::encoded_len() <= 128);
                    if blkdev_io_block_size_128b_log2 >= u64::BITS - 7 {
                        this.fut_state = ReadCoreImageHeaderFutureState::Done;
                        return task::Poll::Ready(Err(NvFsError::IoError(NvFsIoError::RegionOutOfRange)));
                    } else if blkdev_io_block_size_128b_log2 >= usize::BITS - 7 {
                        this.fut_state = ReadCoreImageHeaderFutureState::Done;
                        return task::Poll::Ready(Err(NvFsError::DimensionsNotSupported));
                    }
                    let first_header_part =
                        match FixedVec::new_with_default(1usize << (blkdev_io_block_size_128b_log2 + 7)) {
                            Ok(first_header_part) => first_header_part,
                            Err(e) => {
                                this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(e)));
                            }
                        };
                    let read_fut = blkdev::helpers::NvBlkDevReadRegionFuture::new(
                        0,
                        1,
                        blkdev_io_block_size_128b_log2 as u8,
                        first_header_part,
                        0,
                        blkdev_io_block_size_128b_log2 as u8,
                    );
                    this.fut_state = ReadCoreImageHeaderFutureState::ReadMinHeader { read_fut };
                }
                ReadCoreImageHeaderFutureState::ReadMinHeader { read_fut } => {
                    let mut first_header_part = match blkdev::NvBlkDevFuture::poll(pin::Pin::new(read_fut), blkdev, cx)
                    {
                        task::Poll::Ready(Ok((first_header_part, Ok(())))) => first_header_part,
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                            match e {
                                NvBlkDevIoError::IoBlockOutOfRange => {
                                    // If reading the first device IO Block is out of range already,
                                    // then so would be the backup MkFsInfoHeader. Give up.
                                    this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                    return task::Poll::Ready(Err(NvFsError::from(FormatError::InvalidImageHeader)));
                                }
                                NvBlkDevIoError::IoBlockNotMapped => {
                                    // There's still some hope.
                                    this.fut_state = ReadCoreImageHeaderFutureState::PrepareReadBackupMinMkFsInfoHeader;
                                    continue;
                                }
                                _ => {
                                    this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                    return task::Poll::Ready(Err(NvFsError::from(e)));
                                }
                            }
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    if &first_header_part[..MAGIC_COCOONFS.len()] == MAGIC_COCOONFS {
                        let (is_valid, tier0_integrity_state) =
                            match extent_tier0_integrity_protection_verify_and_remove(
                                io_slices::SingletonIoSliceMut::new(first_header_part.as_mut_slice()),
                                MAGIC_COCOONFS.len(),
                                MinStaticImageHeader::encoded_len() as usize - MAGIC_COCOONFS.len(),
                            ) {
                                Ok((is_valid, tier0_integrity_state)) => (is_valid, tier0_integrity_state),
                                Err(e) => {
                                    this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                    return task::Poll::Ready(Err(e));
                                }
                            };

                        if is_valid {
                            // Tier 0 integrity protection verification has passed, and the encoded
                            // MinStaticImageHeader is within the tier 0 protection domain. It is
                            // now expected that there's a valid MinStaticImageHeader, otherwise
                            // error out.
                            // This decodes the ImageLayout and validates the configuration.
                            let min_static_image_header = match MinStaticImageHeader::decode(&first_header_part) {
                                Ok(min_static_image_header) => min_static_image_header,
                                Err(e) => {
                                    this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                    return task::Poll::Ready(Err(e));
                                }
                            };

                            // Verify at this point that the backend storage's minimum IO size is <= the one
                            // supported by the image. As an IO Block size is guaranteed to fit an u64 (and
                            // an usize as well), this will henceforth apply to the Device IO Block size as
                            // well then.
                            let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();
                            let image_layout = &min_static_image_header.image_layout;
                            if (image_layout.io_block_allocation_blocks_log2 as u32
                                + image_layout.allocation_block_size_128b_log2 as u32)
                                < blkdev_io_block_size_128b_log2
                            {
                                this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(
                                    FormatError::IoBlockSizeNotSupportedByDevice,
                                )));
                            }

                            // Now that the MinStaticImageHeader has been read and decoded, deduce the total
                            // header length from it, read the remainder, if any, and continue with the
                            // decoding.
                            // The IO Block aligned length in units of Bytes never exceeds the larger of
                            // 4 * 128B and the IO Block size, c.f. the documentation of
                            // StaticImageHeader::io_block_aligned_encoded_len_allocation_blocks(). Either
                            // way, both can be represented as an u64 and the
                            // shift will not overflow.
                            let static_header_len =
                                u64::from(StaticImageHeader::io_block_aligned_encoded_len_allocation_blocks(
                                    image_layout.io_block_allocation_blocks_log2,
                                    image_layout.allocation_block_size_128b_log2,
                                    min_static_image_header.salt_len,
                                )) << (image_layout.allocation_block_size_128b_log2 as u32 + 7);

                            // Remember from above: it is known by now that the Device IO Block size fits an
                            // u64.
                            debug_assert_eq!(first_header_part.len(), 1usize << (blkdev_io_block_size_128b_log2 + 7));
                            let remaining_static_header_len = static_header_len - first_header_part.len() as u64;
                            if remaining_static_header_len == 0 {
                                this.fut_state = ReadCoreImageHeaderFutureState::DecodeStaticImageHeader {
                                    min_header: min_static_image_header,
                                    first_header_part,
                                    second_header_part: FixedVec::new_empty(),
                                    tier0_integrity_state,
                                };
                            } else {
                                let second_header_part = match usize::try_from(remaining_static_header_len)
                                    .map_err(|_| NvFsError::DimensionsNotSupported)
                                    .and_then(|remaining_static_header_len| {
                                        FixedVec::new_with_default(remaining_static_header_len).map_err(NvFsError::from)
                                    }) {
                                    Ok(second_header_part) => second_header_part,
                                    Err(e) => {
                                        this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                        return task::Poll::Ready(Err(e));
                                    }
                                };
                                let read_fut = blkdev::helpers::NvBlkDevReadRegionFuture::new(
                                    1,
                                    remaining_static_header_len >> (blkdev_io_block_size_128b_log2 + 7),
                                    blkdev_io_block_size_128b_log2 as u8,
                                    second_header_part,
                                    0,
                                    blkdev_io_block_size_128b_log2 as u8,
                                );
                                this.fut_state = ReadCoreImageHeaderFutureState::ReadStaticImageHeaderRemainder {
                                    read_fut,
                                    min_header: min_static_image_header,
                                    first_header_part,
                                    tier0_integrity_state,
                                };
                            }
                        } else {
                            // Magic is "COCOONFS", but tier 0 integrity protection failed.
                            // Proceed to reading the backup MkFsInfoHeader.
                            this.fut_state = ReadCoreImageHeaderFutureState::PrepareReadBackupMinMkFsInfoHeader;
                        }
                    } else {
                        // Magic is not "COCOONFS". Attempt to decode a MkFsInfoHeader.
                        this.fut_state = ReadCoreImageHeaderFutureState::TryDecodeMinMkFsInfoHeader {
                            mkfsinfo_header_blkdev_io_blocks_begin: 0,
                            first_header_part,
                        };
                    }
                }
                ReadCoreImageHeaderFutureState::ReadStaticImageHeaderRemainder {
                    read_fut,
                    min_header,
                    first_header_part,
                    tier0_integrity_state,
                } => {
                    let second_header_part = match blkdev::NvBlkDevFuture::poll(pin::Pin::new(read_fut), blkdev, cx) {
                        task::Poll::Ready(Ok((second_header_part, Ok(())))) => second_header_part,
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    this.fut_state = ReadCoreImageHeaderFutureState::DecodeStaticImageHeader {
                        min_header: min_header.clone(),
                        first_header_part: mem::take(first_header_part),
                        second_header_part,
                        tier0_integrity_state: *tier0_integrity_state,
                    };
                }
                ReadCoreImageHeaderFutureState::DecodeStaticImageHeader {
                    min_header,
                    first_header_part,
                    second_header_part,
                    tier0_integrity_state,
                } => {
                    // Complete the integrity protection verification.
                    let image_layout = &min_header.image_layout;
                    let is_valid = match extent_integrity_protections_verify_and_remove(
                        io_slices::BuffersSliceIoSlicesMutIter::new(&mut [
                            first_header_part.as_mut_slice(),
                            second_header_part.as_mut_slice(),
                        ]),
                        MAGIC_COCOONFS.len(),
                        MinStaticImageHeader::encoded_len() as usize - MAGIC_COCOONFS.len(),
                        Some(tier0_integrity_state),
                        image_layout.io_block_allocation_blocks_log2,
                        image_layout.allocation_block_size_128b_log2,
                        blkdev.io_block_size_128b_log2(),
                    ) {
                        Ok((is_valid, _)) => is_valid,
                        Err(e) => {
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };

                    if !is_valid {
                        this.fut_state = ReadCoreImageHeaderFutureState::PrepareReadBackupMinMkFsInfoHeader;
                        continue;
                    }

                    // Decode the static image header.
                    let mut header_io_slice = io_slices::SingletonIoSlice::new(first_header_part)
                        .chain(io_slices::SingletonIoSlice::new(second_header_part));

                    // Skip over the already decoded MinStaticImageHeader.
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

                    // Skip over the integrity protections section.
                    let integrity_protections_len = match usize::try_from(extent_integrity_protections_len(
                        image_layout.io_block_allocation_blocks_log2,
                        image_layout.allocation_block_size_128b_log2,
                    )) {
                        Ok(integrity_protections_len) => integrity_protections_len,
                        Err(_) => {
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::DimensionsNotSupported));
                        }
                    };
                    if let Err(e) = header_io_slice.skip(integrity_protections_len) {
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

                    let image_layout = image_layout.clone();
                    this.fut_state = ReadCoreImageHeaderFutureState::Done;
                    return task::Poll::Ready(Ok(ReadCoreImageHeaderFutureResult::StaticImageHeader(
                        StaticImageHeader {
                            image_layout: image_layout.clone(),
                            salt,
                        },
                    )));
                }
                ReadCoreImageHeaderFutureState::TryDecodeMinMkFsInfoHeader {
                    mkfsinfo_header_blkdev_io_blocks_begin,
                    first_header_part,
                } => {
                    let from_backup = *mkfsinfo_header_blkdev_io_blocks_begin != 0;
                    if &first_header_part[..MAGIC_MKFS.len()] != MAGIC_MKFS {
                        if !from_backup {
                            this.fut_state = ReadCoreImageHeaderFutureState::PrepareReadBackupMinMkFsInfoHeader;
                            continue;
                        } else {
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(FormatError::InvalidImageHeader)));
                        }
                    }

                    let (is_valid, tier0_integrity_state) = match extent_tier0_integrity_protection_verify_and_remove(
                        io_slices::SingletonIoSliceMut::new(first_header_part.as_mut_slice()),
                        MAGIC_MKFS.len(),
                        MinMkFsInfoHeader::encoded_len() as usize - MAGIC_MKFS.len(),
                    ) {
                        Ok((is_valid, tier0_integrity_state)) => (is_valid, tier0_integrity_state),
                        Err(e) => {
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };

                    if !is_valid {
                        if !from_backup {
                            this.fut_state = ReadCoreImageHeaderFutureState::PrepareReadBackupMinMkFsInfoHeader;
                            continue;
                        } else {
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(FormatError::InvalidImageHeader)));
                        }
                    }

                    // Tier 0 integrity protection verification has passed, and the encoded
                    // MinMkFsInfoHeader is within the tier 0 protection domain. It is
                    // now expected that there's a valid MinMkFsInfoHeader, otherwise
                    // error out.
                    // This decodes the ImageLayout and validates the configuration.
                    let min_mkfsinfo_header = match MinMkFsInfoHeader::decode(first_header_part) {
                        Ok(min_mkfsinfo_header) => min_mkfsinfo_header,
                        Err(e) => {
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };

                    // Verify at this point that the backend storage's minimum IO size is <= the one
                    // supported by the image. As an IO Block size is guaranteed to fit an u64 (and
                    // an usize as well), this will henceforth apply to the Device IO Block size as
                    // well then.
                    let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();
                    let image_layout = &min_mkfsinfo_header.image_layout;
                    if (image_layout.io_block_allocation_blocks_log2 as u32
                        + image_layout.allocation_block_size_128b_log2 as u32)
                        < blkdev_io_block_size_128b_log2
                    {
                        this.fut_state = ReadCoreImageHeaderFutureState::Done;
                        return task::Poll::Ready(Err(NvFsError::from(FormatError::IoBlockSizeNotSupportedByDevice)));
                    }

                    // Now that the MinMkFsInfoImageHeader has been read and decoded, deduce the
                    // total header length from it, read the remainder, if any,
                    // and continue with the decoding.
                    // The IO Block aligned length in units of Bytes never exceeds the larger of
                    // 4 * 128B and the IO Block size, c.f. the documentation of
                    // MkFsInfoHeader::io_block_aligned_encoded_len_allocation_blocks(). Either
                    // way, both can be represented as an u64 and the shift will not overflow.
                    let mkfsinfo_header_len =
                        u64::from(MkFsInfoHeader::io_block_aligned_encoded_len_allocation_blocks(
                            image_layout.io_block_allocation_blocks_log2,
                            image_layout.allocation_block_size_128b_log2,
                            min_mkfsinfo_header.salt_len,
                        )) << (image_layout.allocation_block_size_128b_log2 as u32 + 7);

                    // Remember from above: it is known by now that the Device IO Block size fits an
                    // u64.
                    debug_assert_eq!(first_header_part.len(), 1usize << (blkdev_io_block_size_128b_log2 + 7));
                    let remaining_mkfsinfo_header_len = mkfsinfo_header_len - first_header_part.len() as u64;
                    if remaining_mkfsinfo_header_len == 0 {
                        this.fut_state = ReadCoreImageHeaderFutureState::DecodeMkFsInfoHeader {
                            min_header: min_mkfsinfo_header,
                            first_header_part: mem::take(first_header_part),
                            second_header_part: FixedVec::new_empty(),
                            tier0_integrity_state,
                            from_backup,
                        };
                    } else {
                        let second_header_part = match usize::try_from(remaining_mkfsinfo_header_len)
                            .map_err(|_| NvFsError::DimensionsNotSupported)
                            .and_then(|remaining_mkfsinfo_header_len| {
                                FixedVec::new_with_default(remaining_mkfsinfo_header_len).map_err(NvFsError::from)
                            }) {
                            Ok(second_header_part) => second_header_part,
                            Err(e) => {
                                this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                        };
                        let read_fut = blkdev::helpers::NvBlkDevReadRegionFuture::new(
                            *mkfsinfo_header_blkdev_io_blocks_begin + 1,
                            remaining_mkfsinfo_header_len >> (blkdev_io_block_size_128b_log2 + 7),
                            blkdev_io_block_size_128b_log2 as u8,
                            second_header_part,
                            0,
                            blkdev_io_block_size_128b_log2 as u8,
                        );
                        this.fut_state = ReadCoreImageHeaderFutureState::ReadMkFsInfoHeaderRemainder {
                            read_fut,
                            min_header: min_mkfsinfo_header,
                            first_header_part: mem::take(first_header_part),
                            tier0_integrity_state,
                            from_backup,
                        };
                    }
                }
                ReadCoreImageHeaderFutureState::ReadMkFsInfoHeaderRemainder {
                    read_fut,
                    min_header,
                    first_header_part,
                    tier0_integrity_state,
                    from_backup,
                } => {
                    let second_header_part = match blkdev::NvBlkDevFuture::poll(pin::Pin::new(read_fut), blkdev, cx) {
                        task::Poll::Ready(Ok((second_header_part, Ok(())))) => second_header_part,
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    this.fut_state = ReadCoreImageHeaderFutureState::DecodeMkFsInfoHeader {
                        min_header: min_header.clone(),
                        first_header_part: mem::take(first_header_part),
                        second_header_part,
                        tier0_integrity_state: *tier0_integrity_state,
                        from_backup: *from_backup,
                    };
                }
                ReadCoreImageHeaderFutureState::DecodeMkFsInfoHeader {
                    min_header,
                    first_header_part,
                    second_header_part,
                    tier0_integrity_state,
                    from_backup,
                } => {
                    // Complete the integrity protection verification.
                    let image_layout = &min_header.image_layout;
                    let is_valid = match extent_integrity_protections_verify_and_remove(
                        io_slices::BuffersSliceIoSlicesMutIter::new(&mut [
                            first_header_part.as_mut_slice(),
                            second_header_part.as_mut_slice(),
                        ]),
                        MAGIC_MKFS.len(),
                        MinMkFsInfoHeader::encoded_len() as usize - MAGIC_MKFS.len(),
                        Some(tier0_integrity_state),
                        image_layout.io_block_allocation_blocks_log2,
                        image_layout.allocation_block_size_128b_log2,
                        blkdev.io_block_size_128b_log2(),
                    ) {
                        Ok((is_valid, _)) => is_valid,
                        Err(e) => {
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };

                    if !is_valid {
                        if !*from_backup {
                            this.fut_state = ReadCoreImageHeaderFutureState::PrepareReadBackupMinMkFsInfoHeader;
                            continue;
                        } else {
                            // No more options to try, give up.
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(FormatError::InvalidImageHeader)));
                        }
                    }

                    // Decode the MkFsInfoHeader header.
                    let mut header_io_slice = io_slices::SingletonIoSlice::new(first_header_part)
                        .chain(io_slices::SingletonIoSlice::new(second_header_part));

                    // Skip over the already decoded MinMkFsInfoHeader.
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

                    // Skip over the integrity protections section.
                    let integrity_protections_len = match usize::try_from(extent_integrity_protections_len(
                        image_layout.io_block_allocation_blocks_log2,
                        image_layout.allocation_block_size_128b_log2,
                    )) {
                        Ok(integrity_protections_len) => integrity_protections_len,
                        Err(_) => {
                            this.fut_state = ReadCoreImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::DimensionsNotSupported));
                        }
                    };
                    if let Err(e) = header_io_slice.skip(integrity_protections_len) {
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

                    let image_layout = image_layout.clone();
                    let image_size = min_header.image_size;
                    let from_backup = *from_backup;
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
                ReadCoreImageHeaderFutureState::PrepareReadBackupMinMkFsInfoHeader => {
                    let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();
                    let blkdev_io_blocks = blkdev.io_blocks();
                    let blkdev_io_blocks = blkdev_io_blocks.min(u64::MAX >> (blkdev_io_block_size_128b_log2 + 7));
                    let backup_location_blkdev_io_blocks_begin =
                        match MkFsInfoHeader::physical_backup_location_blkdev_io_blocks_begin(
                            blkdev_io_blocks,
                            blkdev_io_block_size_128b_log2,
                        ) {
                            Ok(backup_location_blkdev_io_blocks_begin) => backup_location_blkdev_io_blocks_begin,
                            Err(_) => {
                                // Failure to deduce the backup location from the storage dimensions
                                // indicates that they're invalid/unusable anyway.
                                this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(FormatError::InvalidImageHeader)));
                            }
                        };

                    // Read the first Device minimum IO Block at the backup location, which is
                    // always >= 128 bytes by definition, which suffices to
                    // store the MinMkFsInfoHeader, which in turn contain all
                    // information to subsequently deduce the full header size.
                    const _: () = assert!(MinMkFsInfoHeader::encoded_len() <= 128);
                    let first_header_part =
                        match FixedVec::new_with_default(1usize << (blkdev_io_block_size_128b_log2 + 7)) {
                            Ok(first_header_part) => first_header_part,
                            Err(e) => {
                                this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(e)));
                            }
                        };
                    let read_fut = blkdev::helpers::NvBlkDevReadRegionFuture::new(
                        backup_location_blkdev_io_blocks_begin,
                        1,
                        blkdev_io_block_size_128b_log2 as u8,
                        first_header_part,
                        0,
                        blkdev_io_block_size_128b_log2 as u8,
                    );

                    this.fut_state = ReadCoreImageHeaderFutureState::ReadBackupMinMkFsInfoHeader {
                        read_fut,
                        backup_location_blkdev_io_blocks_begin,
                    };
                }
                ReadCoreImageHeaderFutureState::ReadBackupMinMkFsInfoHeader {
                    read_fut,
                    backup_location_blkdev_io_blocks_begin,
                } => {
                    let first_header_part = match blkdev::NvBlkDevFuture::poll(pin::Pin::new(read_fut), blkdev, cx) {
                        task::Poll::Ready(Ok((first_header_part, Ok(())))) => first_header_part,
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                            match e {
                                NvBlkDevIoError::IoBlockNotMapped => {
                                    // There doesn't seem to be a backup. Give up.
                                    this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                    return task::Poll::Ready(Err(NvFsError::from(FormatError::InvalidImageHeader)));
                                }
                                _ => {
                                    this.fut_state = ReadCoreImageHeaderFutureState::Done;
                                    return task::Poll::Ready(Err(NvFsError::from(e)));
                                }
                            };
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    this.fut_state = ReadCoreImageHeaderFutureState::TryDecodeMinMkFsInfoHeader {
                        mkfsinfo_header_blkdev_io_blocks_begin: *backup_location_blkdev_io_blocks_begin,
                        first_header_part,
                    };
                }
                ReadCoreImageHeaderFutureState::Done => unreachable!(),
            }
        }
    }
}

/// Read the [`MutableImageHeader`].
pub struct ReadMutableImageHeaderFuture<B: blkdev::NvBlkDev> {
    image_layout: layout::ImageLayout,
    salt_len: u8,
    fut_state: ReadMutableImageHeaderFutureState<B>,
}

/// [`ReadMutableImageHeaderFuture`] state-machine state.
enum ReadMutableImageHeaderFutureState<B: blkdev::NvBlkDev> {
    Init {
        _phantom: marker::PhantomData<fn() -> *const B>,
    },
    ReadHeader {
        read_fut: blkdev::helpers::NvBlkDevReadRegionFuture<B, FixedVec<u8, 7>>,
    },
    Done,
}

impl<B: blkdev::NvBlkDev> ReadMutableImageHeaderFuture<B> {
    pub fn new(static_image_header: &StaticImageHeader) -> Result<Self, NvFsError> {
        let salt_len = u8::try_from(static_image_header.salt.len())
            .map_err(|_| NvFsError::from(FormatError::InvalidSaltLength))?;

        Ok(Self {
            image_layout: static_image_header.image_layout.clone(),
            salt_len,
            fut_state: ReadMutableImageHeaderFutureState::Init {
                _phantom: marker::PhantomData,
            },
        })
    }
}

impl<B: blkdev::NvBlkDev> blkdev::NvBlkDevFuture<B> for ReadMutableImageHeaderFuture<B> {
    type Output = Result<MutableImageHeader, NvFsError>;

    fn poll(self: pin::Pin<&mut Self>, blkdev: &B, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                ReadMutableImageHeaderFutureState::Init { _phantom } => {
                    let image_layout = &this.image_layout;
                    let mutable_header_allocation_blocks_range =
                        MutableImageHeader::physical_location(image_layout, this.salt_len);
                    // The mutable header's beginning is aligned to an IO Block boundary, which
                    // means it's also aligned to a Device IO block boundary.
                    debug_assert_eq!(
                        mutable_header_allocation_blocks_range
                            .begin()
                            .align_down(image_layout.io_block_allocation_blocks_log2 as u32),
                        mutable_header_allocation_blocks_range.begin()
                    );

                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                    if u64::from(mutable_header_allocation_blocks_range.block_count())
                        > u64::MAX >> (allocation_block_size_128b_log2 + 7)
                    {
                        this.fut_state = ReadMutableImageHeaderFutureState::Done;
                        return task::Poll::Ready(Err(NvFsError::IoError(NvFsIoError::RegionOutOfRange)));
                    }
                    let encoded_mutable_header_len = match usize::try_from(
                        u64::from(mutable_header_allocation_blocks_range.block_count())
                            << (allocation_block_size_128b_log2 + 7),
                    ) {
                        Ok(mutable_header_len) => mutable_header_len,
                        Err(_) => {
                            this.fut_state = ReadMutableImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::DimensionsNotSupported));
                        }
                    };
                    let encoded_mutable_header = match FixedVec::new_with_default(encoded_mutable_header_len) {
                        Ok(encoded_mutable_header) => encoded_mutable_header,
                        Err(e) => {
                            this.fut_state = ReadMutableImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };

                    let read_fut = blkdev::helpers::NvBlkDevReadRegionFuture::new(
                        u64::from(mutable_header_allocation_blocks_range.begin()),
                        u64::from(mutable_header_allocation_blocks_range.block_count()),
                        allocation_block_size_128b_log2 as u8,
                        encoded_mutable_header,
                        0,
                        allocation_block_size_128b_log2 as u8,
                    );

                    this.fut_state = ReadMutableImageHeaderFutureState::ReadHeader { read_fut };
                }
                ReadMutableImageHeaderFutureState::ReadHeader { read_fut } => {
                    let encoded_mutable_header = match blkdev::NvBlkDevFuture::poll(pin::Pin::new(read_fut), blkdev, cx)
                    {
                        task::Poll::Ready(Ok((encoded_mutable_header, Ok(())))) => encoded_mutable_header,
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                            this.fut_state = ReadMutableImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    this.fut_state = ReadMutableImageHeaderFutureState::Done;
                    return task::Poll::Ready(MutableImageHeader::decode(
                        io_slices::SingletonIoSlice::new(&encoded_mutable_header).map_infallible_err(),
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
    image_layout: ImageLayout,
    image_size: layout::AllocBlockCount,
    salt_len: u8,
}

impl MinMkFsInfoHeader {
    /// Encoded length of a [`MinMkFsInfoHeader`].
    const fn encoded_len() -> u8 {
        const ENCODED_LEN: u32 = {
            // Magic 'CCFSMKFS'.
            let mut encoded_len = MAGIC_MKFS.len() as u32;
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

        // The integrity protection section's offset, which follows the
        // MinMkfsInfoHeader, must be small enough that the minimum possible
        // integrity protection section is located within the first 128B, as per
        // the requirements of the integrity protection scheme.
        #[allow(clippy::assertions_on_constants)]
        let _: () = assert!(ENCODED_LEN <= 128 - extent_integrity_protections_len(0, 0));

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

        let (magic, buf) = buf.split_at(MAGIC_MKFS.len());
        if magic != MAGIC_MKFS {
            return Err(NvFsError::from(FormatError::InvalidImageHeader));
        }

        let (version, buf) = buf.split_at(mem::size_of::<u8>());
        // The from_le_bytes() is a nop for an u8, but this mirrors the encoding part.
        let version =
            u8::from_le_bytes(*<&[u8; mem::size_of::<u8>()]>::try_from(version).map_err(|_| nvfs_err_internal!())?);
        if version != 0 {
            return Err(NvFsError::from(FormatError::UnsupportedFormatVersion));
        }

        let (encoded_image_layout, buf) = buf.split_at(layout::ImageLayout::encoded_len() as usize);
        let image_layout = ImageLayout::decode(encoded_image_layout)?;

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
            image_layout,
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
/// interoperability with hardware having a possibly larger native [Device IO
/// block size](blkdev::NvBlkDev::io_block_size_128b_log2), meaningful error
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
    /// Returns the encoded length of a [`MkFsInfoHeader`] with
    /// an [IO Block size](ImageLayout::io_block_allocation_blocks_log2) as
    /// specified by `io_block_allocation_blocks_log2`, an [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) as specified by
    /// `allocation_block_size_128b_log2` and with a salt length
    /// of `salt_len`, without any of the padding to align to the next [IO
    /// Block](layout::ImageLayout::io_block_allocation_blocks_log2) boundary
    /// included.
    ///
    /// The encoded length is guaranteed to not exceed the larger of `3 * 128`
    /// and the size of one
    /// [IO Block](ImageLayout::io_block_allocation_blocks_log2).
    ///
    /// # Arguments:
    ///
    /// * `io_block_allocation_blocks_log2` - Verbatim copy of
    ///   [`ImageLayout::io_block_allocation_blocks_log2`].
    /// * `allocation_block_size_128b_log2` - Verbatim copy of
    ///   [`ImageLayout::allocation_block_size_128b_log2`].
    /// * `salt_len` - Length of the salt stored in the [`MkFsInfoHeader`].
    ///
    /// # See also:
    ///
    /// * [`io_block_aligned_encoded_len_allocation_blocks()`](Self::io_block_aligned_encoded_len_allocation_blocks)
    pub fn encoded_len(io_block_allocation_blocks_log2: u8, allocation_block_size_128b_log2: u8, salt_len: u8) -> u32 {
        // The encoded length always is <= the larger of 3 * 128 and the IO Block size.
        // Verify case that the IO Block size <= 2 * 128:
        const _: () = assert!(
            3u64 * 128 - extent_integrity_protections_len(1, 0) as u64
                >= MinMkFsInfoHeader::encoded_len() as u64 + u8::MAX as u64
        );
        // Verify case that the IO Block size >= 4 * 128:
        const _: () = assert!(
            (1u64 << (2 + 7)) - extent_integrity_protections_len(2, 0) as u64
                >= MinMkFsInfoHeader::encoded_len() as u64 + u8::MAX as u64
        );

        // The minimal common header containing everything needed to deduce the full
        // header's length.
        let mut encoded_len = MinMkFsInfoHeader::encoded_len() as u32;

        // The integrity protection section.
        encoded_len +=
            extent_integrity_protections_len(io_block_allocation_blocks_log2, allocation_block_size_128b_log2);

        // And the image salt.
        encoded_len += salt_len as u32;

        encoded_len
    }

    /// [IO Block](layout::ImageLayout::io_block_allocation_blocks_log2) aligned
    /// length of [`MkFsInfoHeader`].
    ///
    /// The [`MkFsInfoHeader`]'s length on storage gets padded to the next [IO
    /// Block](ImageLayout::io_block_allocation_blocks_log2) boundary, so that
    /// the generic integrity protections are applicable to it.
    ///
    /// Return the length of a [`MkFsInfoHeader`] with
    /// an [IO Block size](ImageLayout::io_block_allocation_blocks_log2) as
    /// specified by `io_block_allocation_blocks_log2`, an [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) as specified by
    /// `allocation_block_size_128b_log2` and a salt length
    /// of `salt_len`, aligned to the next [IO
    /// Block](layout::ImageLayout::io_block_allocation_blocks_log2) boundary in
    /// units of [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    ///
    /// The aligned length in units of Bytes is guaranteed to never exceed the
    /// larger of `4 * 128` and one IO Block size.
    ///
    /// # Arguments:
    ///
    /// * `io_block_allocation_blocks_log2` - Verbatim copy of
    ///   [`ImageLayout::io_block_allocation_blocks_log2`].
    /// * `allocation_block_size_128b_log2` - Verbatim copy of
    ///   [`ImageLayout::allocation_block_size_128b_log2`].
    /// * `salt_len` - Length of the salt stored in the static image header.
    ///
    /// # See also:
    ///
    /// * [`encoded_len()`](Self::encoded_len).
    pub fn io_block_aligned_encoded_len_allocation_blocks(
        io_block_allocation_blocks_log2: u8,
        allocation_block_size_128b_log2: u8,
        salt_len: u8,
    ) -> layout::AllocBlockCount {
        let encoded_len = Self::encoded_len(
            io_block_allocation_blocks_log2,
            allocation_block_size_128b_log2,
            salt_len,
        ) as u64;

        // The length always fits the larger of a few multiples (<= 3) of 128 Bytes and
        // the IO Block size, as per the documented guarantees of encoded_len(),
        // hence is definitely <= than 2^63. The size of an IO Block in units of
        // Bytes is a power of two and <= 1^63 also. Hence the aligned result
        // (in units of Bytes) will be <= that uppber bound as well.
        layout::AllocBlockCount::from(
            encoded_len.round_up_pow2_unchecked(
                io_block_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32 + 7,
            ) >> (allocation_block_size_128b_log2 + 7),
        )
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
    /// * `blkdev_io_blocks` - Value of
    ///   [`NvBlkDev::io_blocks()`](blkdev::NvBlkDev::io_blocks).
    /// * `blkdev_io_block_size_128b_log2` - Value of
    ///   [`NvBlkDev::io_block_size_128b_log2()`](blkdev::NvBlkDev::io_block_size_128b_log2).
    fn physical_backup_location_begin_128b(
        blkdev_io_blocks: u64,
        blkdev_io_block_size_128b_log2: u32,
    ) -> Result<(u64, u32), NvFsError> {
        if blkdev_io_block_size_128b_log2 >= u64::BITS - 7 {
            return Err(NvFsError::IoError(NvFsIoError::RegionOutOfRange));
        }

        let blkdev_size_128b = blkdev_io_blocks << blkdev_io_block_size_128b_log2;
        if blkdev_size_128b == 0 || blkdev_size_128b >> blkdev_io_block_size_128b_log2 != blkdev_io_blocks {
            return Err(NvFsError::from(FormatError::InvalidImageSize));
        }

        // Partition the image into blocks of largest possible alignment, such that
        // there are at least 16 of these and take the last.
        let blkdev_size_128b_log2 = blkdev_size_128b.ilog2();
        // The aligned blocks should be at least 4 * 128B in size.
        if blkdev_size_128b_log2 < 4 + 2 {
            return Err(NvFsError::from(FormatError::InvalidImageSize));
        }

        let backup_location_begin_alignment_128b_log2 = blkdev_size_128b_log2 - 4;
        // The last aligned block on storage.
        let backup_location_begin_128b = ((blkdev_size_128b >> backup_location_begin_alignment_128b_log2) - 1)
            << backup_location_begin_alignment_128b_log2;
        debug_assert!(backup_location_begin_128b < blkdev_size_128b);
        debug_assert!(blkdev_size_128b - backup_location_begin_128b >= 4);
        // The backup is in the storage's last octile.
        debug_assert!(backup_location_begin_128b >= blkdev_size_128b - blkdev_size_128b.div_ceil(8));
        Ok((backup_location_begin_128b, backup_location_begin_alignment_128b_log2))
    }

    /// Determine the beginning of the backup [`MkFsInfoHeader`]'s location in
    /// units of [Device IO Blocks](blkdev::NvBlkDev::io_block_size_128b_log2).
    ///
    /// Returns the backup header's beginning on storage in units of [Device IO
    /// Blocks](blkdev::NvBlkDev::io_block_size_128b_log2). The location is
    /// guaranteed to be aligned by the [`Device IO
    /// Block`](blkdev::NvBlkDev::io_block_size_128b_log2) size,
    /// and there will be at least one block of that size or 512B available at
    /// that location on storage, whichever is larger.
    ///
    /// # Arguments:
    ///
    /// * `blkdev_io_blocks` - Value of
    ///   [`NvBlkDev::io_blocks()`](blkdev::NvBlkDev::io_blocks).
    /// * `io_block_size_128b_log2` - Value of
    ///   [`NvBlkDev::io_block_size_128b_log2()`](blkdev::NvBlkDev::io_block_size_128b_log2).
    fn physical_backup_location_blkdev_io_blocks_begin(
        blkdev_io_blocks: u64,
        blkdev_io_block_size_128b_log2: u32,
    ) -> Result<u64, NvFsError> {
        let (backup_location_begin_128b, backup_location_begin_alignment_128b_log2) =
            Self::physical_backup_location_begin_128b(blkdev_io_blocks, blkdev_io_block_size_128b_log2)?;
        if backup_location_begin_alignment_128b_log2 < blkdev_io_block_size_128b_log2 {
            return Err(NvFsError::from(FormatError::InvalidImageSize));
        }
        debug_assert!(backup_location_begin_128b.is_aligned_pow2(blkdev_io_block_size_128b_log2));
        Ok(backup_location_begin_128b >> blkdev_io_block_size_128b_log2)
    }

    /// Determine the backup [`MkFsInfoHeader`]'s location on storage.
    ///
    /// Returns the backup header's [extent](layout::PhysicalAllocBlockRange) on
    /// storage. The returned extent is guaranteed to be aligned by the
    /// [`Device IO Block`](blkdev::NvBlkDev::io_block_size_128b_log2) size,
    /// and within the bounds of the backing storage.
    ///
    /// The returned extent's boundaries are aligned to the block size
    /// determined by `io_block_allocation_blocks_log2` and within the
    /// storage volume's limits.
    ///
    /// # Arguments:
    ///
    /// * `io_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::io_block_allocation_blocks_log2`].
    /// * `allocation_block_size_128b_log2` - Verbatim value of
    ///   [`ImageLayout::allocation_block_size_128b_log2`].
    /// * `salt_len` - Length of the filesystem salt to be stored in the
    ///   [`MkFsInfoHeader`].
    /// * `blkdev_io_blocks` - Value of
    ///   [`NvBlkDev::io_blocks()`](blkdev::NvBlkDev::io_blocks).
    /// * `blkdev_io_block_size_128b_log2` - Value of
    ///   [`NvBlkDev::io_block_size_128b_log2()`](blkdev::NvBlkDev::io_block_size_128b_log2).
    pub fn physical_backup_location(
        io_block_allocation_blocks_log2: u8,
        allocation_block_size_128b_log2: u8,
        salt_len: u8,
        blkdev_io_blocks: u64,
        blkdev_io_block_size_128b_log2: u32,
    ) -> Result<layout::PhysicalAllocBlockRange, NvFsError> {
        let (backup_location_begin_128b, backup_location_begin_alignment_128b_log2) =
            Self::physical_backup_location_begin_128b(blkdev_io_blocks, blkdev_io_block_size_128b_log2)?;
        // Any HW with a compatible blkdev_io_block_size_128b_log2 should be guaranteed
        // to arrive at the same location and discover the backup.
        if backup_location_begin_alignment_128b_log2
            < io_block_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32
        {
            return Err(NvFsError::from(FormatError::InvalidImageSize));
        }
        debug_assert!(
            backup_location_begin_128b
                .is_aligned_pow2(io_block_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32)
        );
        let backup_location_allocation_blocks_begin =
            layout::PhysicalAllocBlockIndex::from(backup_location_begin_128b >> allocation_block_size_128b_log2);

        // Make the returned extent to align with the IO Block size. There will be
        // enough room at the end of storage:
        // - The IO Block aligned length is always <= the maximum of 4 * 128B and the IO
        //   Block size, c.f. the documentation of
        //   Self::io_block_allocation_blocks_log2(), while
        // - there is at least one block of size as specified by
        //   backup_location_begin_alignment_128b_log2 available at the end, and that is
        //   >= the IO Block size (verified above), and >= 4 * 128B, as per the
        //   documentation of Self::physical_backup_location_begin_128b().
        Ok(layout::PhysicalAllocBlockRange::from((
            backup_location_allocation_blocks_begin,
            Self::io_block_aligned_encoded_len_allocation_blocks(
                io_block_allocation_blocks_log2,
                allocation_block_size_128b_log2,
                salt_len,
            ),
        )))
    }

    /// Encode a [`MkFsInfoHeader`].
    ///
    /// # Arguments:
    ///
    /// * `dst` - The destination buffers. Their total length must be exactly
    ///   that returned by
    ///   [`io_block_aligned_encoded_len_allocation_blocks()`](Self::io_block_aligned_encoded_len_allocation_blocks).
    /// * `image_layout` - The filesystem image's [`ImageLayout`] to be stored
    ///   in the [`MkFsInfoHeader`].
    /// * `image_size` - The desired filesystem image size to be stored in the
    ///   [`MkFsInfoHeader`].
    /// * `salt` - The filesystem salt to be stored in the [`MkFsInfoHeader`].
    ///   It's length must not exceed `u8::MAX`.
    pub fn encode<'a, DI: io_slices::MutPeekableIoSlicesMutIter<'a, BackendIteratorError = NvFsError>>(
        mut dst: DI,
        image_layout: &layout::ImageLayout,
        image_size: layout::AllocBlockCount,
        salt: &[u8],
    ) -> Result<(), NvFsError> {
        let mut encoding_dst = dst.decoupled_borrow_mut();
        let mut magic = io_slices::SingletonIoSlice::new(MAGIC_MKFS.as_slice()).map_infallible_err();
        encoding_dst.copy_from_iter(&mut magic)?;
        if !magic.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let version = 0u8.to_le_bytes();
        let mut version = io_slices::SingletonIoSlice::new(version.as_slice()).map_infallible_err();
        encoding_dst.copy_from_iter(&mut version)?;
        if !version.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let encoded_image_layout = image_layout.encode()?;
        let mut encoded_image_layout =
            io_slices::SingletonIoSlice::new(encoded_image_layout.as_slice()).map_infallible_err();
        encoding_dst.copy_from_iter(&mut encoded_image_layout)?;
        if !encoded_image_layout.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let image_size = u64::from(image_size).to_le_bytes();
        let mut image_size = io_slices::SingletonIoSlice::new(image_size.as_slice()).map_infallible_err();
        encoding_dst.copy_from_iter(&mut image_size)?;
        if !image_size.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let salt_len = u8::try_from(salt.len())
            .map_err(|_| NvFsError::from(FormatError::InvalidSaltLength))?
            .to_le_bytes();
        let mut salt_len = io_slices::SingletonIoSlice::new(salt_len.as_slice()).map_infallible_err();
        encoding_dst.copy_from_iter(&mut salt_len)?;
        if !salt_len.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let integrity_protections_len = usize::try_from(extent_integrity_protections_len(
            image_layout.io_block_allocation_blocks_log2,
            image_layout.allocation_block_size_128b_log2,
        ))
        .map_err(|_| NvFsError::DimensionsNotSupported)?;
        encoding_dst.skip(integrity_protections_len).map_err(|e| match e {
            io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
            },
            io_slices::IoSlicesIterError::BackendIteratorError(e) => e,
        })?;

        let mut salt = io_slices::SingletonIoSlice::new(salt).map_infallible_err();
        encoding_dst.copy_from_iter(&mut salt)?;
        if !salt.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        drop(encoding_dst);

        extent_integrity_protections_apply(
            dst,
            MAGIC_MKFS.len(),
            MinMkFsInfoHeader::encoded_len() as usize - MAGIC_MKFS.len(),
            &ExtentIntegrityState::new_clean(),
            image_layout.io_block_allocation_blocks_log2,
            image_layout.allocation_block_size_128b_log2,
            1, // Only used for debug assertions.
        )?;

        Ok(())
    }
}
