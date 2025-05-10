// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`CocoonFsMkFsFuture`].

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

use crate::{
    chip,
    crypto::{hash, rng, CryptoError},
    fs::{
        cocoonfs::{
            alloc_bitmap, auth_tree, encryption_entities, extent_ptr, extents,
            fs::{CocoonFs, CocoonFsConfig, CocoonFsSyncRcPtrType, CocoonFsSyncState},
            image_header, inode_extents_list, inode_index, journal, keys,
            layout::{self, BlockCount as _, BlockIndex as _},
            read_buffer, write_blocks, CocoonFsFormatError,
        },
        {NvFsError, NvFsIoError},
    },
    nvfs_err_internal,
    utils_async::sync_types,
    utils_common::{
        alloc::try_alloc_vec,
        bitmanip::BitManip as _,
        io_slices::{self, IoSlicesIterCommon as _, IoSlicesMutIter as _},
    },
};
use core::{future, iter, marker, mem, pin, task};

/// Filesystem layout description internal to [`CocoonFsMkFsFuture`].
struct CocoonFsMkFsLayout {
    image_layout: layout::ImageLayout,
    salt: Vec<u8>,
    image_header_end: layout::PhysicalAllocBlockIndex,
    image_size: layout::AllocBlockCount,
    allocated_image_allocation_blocks_end: layout::PhysicalAllocBlockIndex,
    root_key: keys::RootKey,
    inode_index_entry_leaf_node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
    journal_log_head_extent: layout::PhysicalAllocBlockRange,
    auth_tree_extent: layout::PhysicalAllocBlockRange,
    alloc_bitmap_file_extent: layout::PhysicalAllocBlockRange,
    auth_tree_inode_extents_list_extents: Option<extents::PhysicalExtents>,
    alloc_bitmap_inode_extents_list_extents: Option<extents::PhysicalExtents>,
}

impl CocoonFsMkFsLayout {
    pub fn new(
        image_layout: &layout::ImageLayout,
        salt: Vec<u8>,
        image_size: layout::AllocBlockCount,
        root_key: keys::RootKey,
    ) -> Result<Self, NvFsError> {
        let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
        let io_block_allocation_blocks_log2 = image_layout.io_block_allocation_blocks_log2 as u32;
        let auth_tree_data_block_allocation_blocks_log2 =
            image_layout.auth_tree_data_block_allocation_blocks_log2 as u32;
        let journal_block_allocation_blocks_log2 =
            io_block_allocation_blocks_log2.max(auth_tree_data_block_allocation_blocks_log2);

        let salt_len = u8::try_from(salt.len()).map_err(|_| NvFsError::from(CocoonFsFormatError::InvalidSaltLength))?;
        let image_header_end = image_header::MutableImageHeader::physical_location(image_layout, salt_len).end();

        let image_size = image_size.min(layout::AllocBlockCount::from(
            u64::MAX >> (allocation_block_size_128b_log2 + 7),
        ));

        let journal_log_head_extent =
            journal::log::JournalLog::head_extent_physical_location(image_layout, image_header_end)?.0;
        debug_assert!(
            (u64::from(journal_log_head_extent.begin()) | u64::from(journal_log_head_extent.end()))
                .is_aligned_pow2(journal_block_allocation_blocks_log2)
        );

        let (auth_tree_node_count, uncovered_image_allocation_blocks_remainder) =
            auth_tree::AuthTreeConfig::image_allocation_blocks_to_auth_tree_node_count(image_layout, image_size)?;
        let auth_tree_extent_allocation_blocks = layout::AllocBlockCount::from(
            auth_tree_node_count
                << (image_layout.auth_tree_node_io_blocks_log2 as u32 + io_block_allocation_blocks_log2),
        );
        // The auth_tree_extent_allocation_blocks has at least the upper 7 bits clear,
        // hence the alignment below cannot overflow. Note the value is aligned
        // to the IO Block size already, thus it has an effect only if the
        // Authentication Tree Data Block size is larger than that.
        debug_assert!(auth_tree_extent_allocation_blocks <= image_size);
        let aligned_auth_tree_extent_allocation_blocks = auth_tree_extent_allocation_blocks
            .align_up(journal_block_allocation_blocks_log2)
            .ok_or_else(|| nvfs_err_internal!())?;
        // Remove from the image_size any Allocation Blocks which are not covered by the
        // Authentication Tree. This can happen if there's not enough space to
        // accommodate for another path down to the bottom in the tree.
        let image_size = image_size
            - layout::AllocBlockCount::from(u64::from(uncovered_image_allocation_blocks_remainder).saturating_sub(
                u64::from(aligned_auth_tree_extent_allocation_blocks) - u64::from(auth_tree_extent_allocation_blocks),
            ));
        // Finally align the image_size downwards to the IO block size, as it makes no
        // sense to have a last partial IO block.
        let image_size = image_size.align_down(io_block_allocation_blocks_log2);
        if image_size < aligned_auth_tree_extent_allocation_blocks
            || u64::from(image_size - aligned_auth_tree_extent_allocation_blocks)
                < u64::from(journal_log_head_extent.end())
        {
            return Err(NvFsError::NoSpace);
        }
        let auth_tree_extent = layout::PhysicalAllocBlockRange::new(
            journal_log_head_extent.end(),
            journal_log_head_extent.end() + aligned_auth_tree_extent_allocation_blocks,
        );
        debug_assert!(
            (u64::from(auth_tree_extent.begin()) | u64::from(auth_tree_extent.end()))
                .is_aligned_pow2(journal_block_allocation_blocks_log2)
        );

        let alloc_bitmap_file_blocks =
            alloc_bitmap::AllocBitmapFile::image_allocation_blocks_to_file_blocks(image_layout, image_size)?;
        let alloc_bitmap_file_allocation_blocks = layout::AllocBlockCount::from(
            alloc_bitmap_file_blocks << (image_layout.allocation_bitmap_file_block_allocation_blocks_log2 as u32),
        );
        if u64::from(alloc_bitmap_file_allocation_blocks)
            >> (image_layout.allocation_bitmap_file_block_allocation_blocks_log2 as u32)
            != alloc_bitmap_file_blocks
        {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidImageSize));
        }
        // The Allocation Bitmap File's extents must be aligned to the Authentication
        // Tree Data Block size. The beginning, i.e. auth_tree_extent.end(), is
        // already, so align the length as well.
        let alloc_bitmap_file_allocation_blocks = alloc_bitmap_file_allocation_blocks
            .align_up(auth_tree_data_block_allocation_blocks_log2)
            .ok_or(NvFsError::NoSpace)?;
        if u64::from(image_size) - u64::from(auth_tree_extent.end()) < u64::from(alloc_bitmap_file_allocation_blocks) {
            return Err(NvFsError::NoSpace);
        }
        let alloc_bitmap_file_extent = layout::PhysicalAllocBlockRange::new(
            auth_tree_extent.end(),
            auth_tree_extent.end() + alloc_bitmap_file_allocation_blocks,
        );

        let mut allocated_image_allocation_blocks_end = alloc_bitmap_file_extent.end();

        // Place the Inode Index entry leaf node. If there's enough space inbetween the
        // image header and the journal log head, put it there for improved
        // locality -- updating the entry leaf node will also involve updating
        // the mutable header part.
        let inode_index_entry_leaf_node_allocation_blocks =
            layout::AllocBlockCount::from(1u64 << (image_layout.index_tree_node_allocation_blocks_log2 as u32));
        let inode_index_entry_leaf_node_allocation_blocks_begin =
            if journal_log_head_extent.begin() - image_header_end >= inode_index_entry_leaf_node_allocation_blocks {
                image_header_end
            } else {
                if u64::from(image_size) - u64::from(allocated_image_allocation_blocks_end)
                    < u64::from(inode_index_entry_leaf_node_allocation_blocks)
                {
                    return Err(NvFsError::NoSpace);
                }
                let inode_index_entry_leaf_node_allocation_blocks_begin = allocated_image_allocation_blocks_end;
                allocated_image_allocation_blocks_end += inode_index_entry_leaf_node_allocation_blocks;
                inode_index_entry_leaf_node_allocation_blocks_begin
            };

        // The Authentication Tree inode's extent gets referenced from the index. If a
        // direct reference is not possible, allocate an extents list.
        let auth_tree_inode_extents_list_extents = if auth_tree_extent.block_count()
            > layout::AllocBlockCount::from(extent_ptr::EncodedExtentPtr::MAX_EXTENT_ALLOCATION_BLOCKS)
        {
            let auth_tree_inode_extents_list_extents;
            (
                auth_tree_inode_extents_list_extents,
                allocated_image_allocation_blocks_end,
            ) = Self::place_preauth_cca_protected_inode_extents_list_extents(
                &auth_tree_extent,
                allocated_image_allocation_blocks_end,
                image_layout,
                image_size,
            )?;
            Some(auth_tree_inode_extents_list_extents)
        } else {
            None
        };

        // The Allocation Bitmap File inode's extent gets likewise referenced from the
        // index. If a direct reference is not possible, allocate an extents
        // list.
        let alloc_bitmap_inode_extents_list_extents = if alloc_bitmap_file_extent.block_count()
            > layout::AllocBlockCount::from(extent_ptr::EncodedExtentPtr::MAX_EXTENT_ALLOCATION_BLOCKS)
        {
            let alloc_bitmap_file_inode_extents_list_extents;
            (
                alloc_bitmap_file_inode_extents_list_extents,
                allocated_image_allocation_blocks_end,
            ) = Self::place_preauth_cca_protected_inode_extents_list_extents(
                &alloc_bitmap_file_extent,
                allocated_image_allocation_blocks_end,
                image_layout,
                image_size,
            )?;
            Some(alloc_bitmap_file_inode_extents_list_extents)
        } else {
            None
        };

        Ok(Self {
            image_layout: image_layout.clone(),
            salt,
            image_header_end,
            image_size,
            allocated_image_allocation_blocks_end,
            root_key,
            inode_index_entry_leaf_node_allocation_blocks_begin,
            journal_log_head_extent,
            auth_tree_extent,
            alloc_bitmap_file_extent,
            auth_tree_inode_extents_list_extents,
            alloc_bitmap_inode_extents_list_extents,
        })
    }

    fn place_preauth_cca_protected_inode_extents_list_extents(
        inode_extent: &layout::PhysicalAllocBlockRange,
        mut allocated_image_allocation_blocks_end: layout::PhysicalAllocBlockIndex,
        image_layout: &layout::ImageLayout,
        image_size: layout::AllocBlockCount,
    ) -> Result<(extents::PhysicalExtents, layout::PhysicalAllocBlockIndex), NvFsError> {
        let encoded_inode_extents_list_len =
            inode_extents_list::indirect_extents_list_encoded_len(iter::once(*inode_extent))?;
        let inode_extents_list_extents_layout = encryption_entities::EncryptedChainedExtentsLayout::new(
            0,
            image_layout.block_cipher_alg,
            Some(image_layout.preauth_cca_protection_hmac_hash_alg),
            0,
            image_layout.allocation_block_size_128b_log2,
        )?
        .get_extents_layout()?;
        let mut inode_extents_list_extents = extents::PhysicalExtents::new();
        // Add one for the CBC padding.
        let mut remaining_payload_len = encoded_inode_extents_list_len as u64 + 1;
        while remaining_payload_len != 0 {
            let next_inode_extents_list_extent_allocations_blocks = inode_extents_list_extents_layout
                .extent_payload_len_to_allocation_blocks(remaining_payload_len, inode_extents_list_extents.is_empty())
                .0;
            let next_inode_extents_list_extent_allocation_blocks_begin = allocated_image_allocation_blocks_end;
            if u64::from(image_size) - u64::from(allocated_image_allocation_blocks_end)
                < u64::from(next_inode_extents_list_extent_allocations_blocks)
            {
                return Err(NvFsError::NoSpace);
            }
            remaining_payload_len =
                remaining_payload_len.saturating_sub(inode_extents_list_extents_layout.extent_effective_payload_len(
                    next_inode_extents_list_extent_allocations_blocks,
                    inode_extents_list_extents.is_empty(),
                ));
            allocated_image_allocation_blocks_end += next_inode_extents_list_extent_allocations_blocks;
            inode_extents_list_extents.push_extent(
                &layout::PhysicalAllocBlockRange::new(
                    next_inode_extents_list_extent_allocation_blocks_begin,
                    allocated_image_allocation_blocks_end,
                ),
                true,
            )?;
        }

        Ok((inode_extents_list_extents, allocated_image_allocation_blocks_end))
    }
}

/// Format a CocoonFS filesystem instance.
///
/// A two-level [`Result`] is returned from the
/// [`Future::poll()`](future::Future::poll):
///
/// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon encountering
///   an internal error.
/// * `Ok(...)` - Otherwise the outer level [`Result`] is set to [`Ok`]:
///   * `Ok(Err((chip, e)))` - In case of an error, a pair of the
///     [`NvChip`](chip::NvChip) instance `chip` and the error reason `e` is
///     returned in an [`Err`].
///   * `Ok(Ok(fs_instance))` - Otherwise an opened [`CocoonFs`] instance
///     `fs_instance` associated with the filesystem just created is returned in
///     an [`Ok`].
pub struct CocoonFsMkFsFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self.
    fs_init_data: Option<CocoonFsMkFsFutureFsInitData<ST, C>>,

    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self.
    auth_tree_initialization_cursor: Option<Box<auth_tree::AuthTreeInitializationCursor>>,

    encrypted_inode_index_entry_leaf_node: Vec<u8>,

    // Initialized when the Allocation Bitmap File has been written out.
    alloc_bitmap_file: Option<alloc_bitmap::AllocBitmapFile>,

    // Initialized after the Authentication Tree has been initialized and the
    // final root digest computed.
    root_hmac_digest: Vec<u8>,

    // Initialized after the Authentication Tree has been initialized and nodes from the
    // initialization might first get added to the cache.
    auth_tree_node_cache: Option<auth_tree::AuthTreeNodeCache>,

    // Initialized after the header data to write out has been setup.
    first_static_image_header_chip_io_block: Vec<Vec<u8>>,

    rng: Box<dyn rng::RngCoreDispatchable + marker::Send>,

    fut_state: CocoonFsMkFsFutureState<C>,
}

struct CocoonFsMkFsFutureFsInitData<ST: sync_types::SyncTypes, C: chip::NvChip> {
    chip: C,
    mkfs_layout: CocoonFsMkFsLayout,
    alloc_bitmap: alloc_bitmap::AllocBitmap,
    auth_tree_config: auth_tree::AuthTreeConfig,
    keys_cache: keys::KeyCache,
    inode_index: inode_index::InodeIndex<ST>,

    enable_trimming: bool,
}

#[allow(clippy::large_enum_variant)]
enum CocoonFsMkFsFutureState<C: chip::NvChip> {
    Init,
    AdvanceAuthTreeCursorToInodeIndexEntryLeafNode {
        advance_fut: auth_tree::AuthTreeInitializationCursorAdvanceFuture<C>,
    },
    AuthTreeUpdateInodeIndexEntryLeafNodeRange {
        next_allocation_block_in_inode_index_entry_leaf_node: usize,
        auth_tree_write_part_fut: Option<auth_tree::AuthTreeInitializationCursorWritePartFuture<C>>,
    },
    AdvanceAuthTreeCursorToAllocBitmapFile {
        advance_fut: auth_tree::AuthTreeInitializationCursorAdvanceFuture<C>,
    },
    InitializeAllocBitmapFile {
        initialize_fut: alloc_bitmap::AllocBitmapFileInitializeFuture<C>,
    },
    AuthTreeUpdateTailDataRange {
        tail_data_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        tail_data_allocation_blocks_end: layout::PhysicalAllocBlockIndex,
        aligned_tail_data_allocation_blocks_end: layout::PhysicalAllocBlockIndex,
        tail_data_allocation_blocks: Vec<Vec<u8>>,
        next_allocation_block_in_tail_data: usize,
        auth_tree_write_part_fut: Option<auth_tree::AuthTreeInitializationCursorWritePartFuture<C>>,
    },
    WriteTailData {
        write_fut: write_blocks::WriteBlocksFuture<C>,
    },
    AdvanceAuthTreeCursorToImageEndPrepare,
    AdvanceAuthTreeCursorToImageEnd {
        advance_fut: auth_tree::AuthTreeInitializationCursorAdvanceFuture<C>,
    },
    WriteHeadData {
        write_fut: write_blocks::WriteBlocksFuture<C>,
    },
    ClearJournalLogHead {
        write_fut: write_blocks::WriteBlocksFuture<C>,
    },
    RandomizeHeadDataPadding {
        write_fut: WriteRandomDataFuture<C>,
    },
    RandomizeImageRemainderPrepare,
    RandomizeImageRemainder {
        write_fut: WriteRandomDataFuture<C>,
    },
    WriteBarrierBeforeStaticImageHeaderWritePrepare,
    WriteBarrierBeforeStaticImageHeaderWrite {
        write_barrier_fut: C::WriteBarrierFuture,
    },
    WriteStaticImageHeader {
        write_fut: write_blocks::WriteBlocksFuture<C>,
    },
    WriteSyncAfterStaticImageHaderWrite {
        write_sync_fut: C::WriteSyncFuture,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsMkFsFuture<ST, C> {
    pub fn new(
        chip: C,
        image_layout: &layout::ImageLayout,
        salt: Vec<u8>,
        image_size: Option<layout::AllocBlockCount>,
        root_key: &[u8],
        enable_trimming: bool,
        mut rng: Box<dyn rng::RngCoreDispatchable + marker::Send>,
    ) -> Result<Self, (C, NvFsError)> {
        let root_key = match keys::RootKey::new(
            root_key,
            &salt,
            image_layout.kdf_hash_alg,
            image_layout.auth_tree_root_hmac_hash_alg,
            image_layout.auth_tree_node_hash_alg,
            image_layout.auth_tree_data_hmac_hash_alg,
            image_layout.preauth_cca_protection_hmac_hash_alg,
            &image_layout.block_cipher_alg,
        ) {
            Ok(root_key) => root_key,
            Err(e) => return Err((chip, e)),
        };

        let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
        let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();
        let chip_io_block_allocation_blocks_log2 =
            chip_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);
        if chip_io_block_allocation_blocks_log2 > image_layout.io_block_allocation_blocks_log2 as u32 {
            return Err((
                chip,
                NvFsError::from(CocoonFsFormatError::IoBlockSizeNotSupportedByDevice),
            ));
        }
        let allocation_block_chip_io_blocks_log2 =
            allocation_block_size_128b_log2.saturating_sub(chip_io_block_size_128b_log2);
        let chip_io_blocks = chip.chip_io_blocks();
        let chip_allocation_blocks = layout::AllocBlockCount::from(
            chip_io_blocks << chip_io_block_allocation_blocks_log2 >> allocation_block_chip_io_blocks_log2,
        );
        let image_size = match image_size {
            Some(image_size) => {
                if image_size > chip_allocation_blocks {
                    return Err((chip, NvFsError::IoError(NvFsIoError::RegionOutOfRange)));
                }
                image_size
            }
            None => chip_allocation_blocks,
        };

        let mkfs_layout = match CocoonFsMkFsLayout::new(image_layout, salt, image_size, root_key) {
            Ok(mkfs_layout) => mkfs_layout,
            Err(e) => return Err((chip, e)),
        };

        let mut alloc_bitmap = match alloc_bitmap::AllocBitmap::new(
            mkfs_layout.allocated_image_allocation_blocks_end - layout::PhysicalAllocBlockIndex::from(0u64),
        ) {
            Ok(alloc_bitmap) => alloc_bitmap,
            Err(e) => return Err((chip, e)),
        };
        if let Err(e) = alloc_bitmap.set_in_range(
            &layout::PhysicalAllocBlockRange::new(
                layout::PhysicalAllocBlockIndex::from(0u64),
                mkfs_layout.image_header_end,
            ),
            true,
        ) {
            return Err((chip, e));
        }
        if let Err(e) = alloc_bitmap.set_in_range(
            &layout::PhysicalAllocBlockRange::from((
                mkfs_layout.inode_index_entry_leaf_node_allocation_blocks_begin,
                layout::AllocBlockCount::from(1u64 << (image_layout.index_tree_node_allocation_blocks_log2 as u32)),
            )),
            true,
        ) {
            return Err((chip, e));
        }
        if let Err(e) = alloc_bitmap.set_in_range(&mkfs_layout.journal_log_head_extent, true) {
            return Err((chip, e));
        }
        if let Err(e) = alloc_bitmap.set_in_range(&mkfs_layout.auth_tree_extent, true) {
            return Err((chip, e));
        }
        if let Err(e) = alloc_bitmap.set_in_range(&mkfs_layout.alloc_bitmap_file_extent, true) {
            return Err((chip, e));
        }
        if let Some(auth_tree_inode_extents_list_extents) = mkfs_layout.auth_tree_inode_extents_list_extents.as_ref() {
            for auth_tree_inode_extents_list_extent in auth_tree_inode_extents_list_extents.iter() {
                if let Err(e) = alloc_bitmap.set_in_range(&auth_tree_inode_extents_list_extent, true) {
                    return Err((chip, e));
                }
            }
        }
        if let Some(alloc_bitmap_file_inode_extents_list_extents) =
            mkfs_layout.alloc_bitmap_inode_extents_list_extents.as_ref()
        {
            for alloc_bitmap_file_inode_extents_list_extent in alloc_bitmap_file_inode_extents_list_extents.iter() {
                if let Err(e) = alloc_bitmap.set_in_range(&alloc_bitmap_file_inode_extents_list_extent, true) {
                    return Err((chip, e));
                }
            }
        }

        let inode_index_entry_leaf_node_block_ptr = match extent_ptr::EncodedBlockPtr::encode(Some(
            mkfs_layout.inode_index_entry_leaf_node_allocation_blocks_begin,
        )) {
            Ok(inode_index_entry_leaf_node_block_ptr) => inode_index_entry_leaf_node_block_ptr,
            Err(e) => return Err((chip, e)),
        };
        let mut auth_tree_extents = extents::PhysicalExtents::new();
        if let Err(e) = auth_tree_extents.push_extent(&mkfs_layout.auth_tree_extent, true) {
            return Err((chip, e));
        }
        let auth_tree_extents = extents::LogicalExtents::from(auth_tree_extents);
        let mut alloc_bitmap_file_extents = extents::PhysicalExtents::new();
        if let Err(e) = alloc_bitmap_file_extents.push_extent(&mkfs_layout.alloc_bitmap_file_extent, true) {
            return Err((chip, e));
        }
        let auth_tree_config = match auth_tree::AuthTreeConfig::new(
            &mkfs_layout.root_key,
            &mkfs_layout.image_layout,
            &inode_index_entry_leaf_node_block_ptr,
            mkfs_layout.image_size,
            auth_tree_extents,
            &alloc_bitmap_file_extents,
        ) {
            Ok(auth_tree_config) => auth_tree_config,
            Err(e) => return Err((chip, e)),
        };
        let auth_tree_initialization_cursor = match auth_tree::AuthTreeInitializationCursor::new(
            &auth_tree_config,
            mkfs_layout.image_header_end,
            mkfs_layout.image_size,
        ) {
            Ok(auth_tree_initialization_cursor) => auth_tree_initialization_cursor,
            Err(e) => return Err((chip, e)),
        };

        let mut keys_cache = match keys::KeyCache::new() {
            Ok(keys_cache) => keys_cache,
            Err(e) => return Err((chip, e)),
        };

        let auth_tree_inode_entry_extent_ptr = match match mkfs_layout.auth_tree_inode_extents_list_extents.as_ref() {
            Some(auth_tree_inode_extents_list_extents) => extent_ptr::EncodedExtentPtr::encode(
                Some(&auth_tree_inode_extents_list_extents.get_extent_range(0)),
                true,
            ),
            None => extent_ptr::EncodedExtentPtr::encode(Some(&mkfs_layout.auth_tree_extent), false),
        } {
            Ok(auth_tree_inode_entry_extent_ptr) => auth_tree_inode_entry_extent_ptr,
            Err(e) => return Err((chip, e)),
        };
        let alloc_bitmap_inode_entry_extent_ptr =
            match match mkfs_layout.alloc_bitmap_inode_extents_list_extents.as_ref() {
                Some(alloc_bitmap_file_inode_extents_list_extents) => extent_ptr::EncodedExtentPtr::encode(
                    Some(&alloc_bitmap_file_inode_extents_list_extents.get_extent_range(0)),
                    true,
                ),
                None => extent_ptr::EncodedExtentPtr::encode(Some(&mkfs_layout.alloc_bitmap_file_extent), false),
            } {
                Ok(alloc_bitmap_file_inode_entry_extent_ptr) => alloc_bitmap_file_inode_entry_extent_ptr,
                Err(e) => return Err((chip, e)),
            };
        let (inode_index, encrypted_inode_index_entry_leaf_node) = match inode_index::InodeIndex::initialize(
            mkfs_layout.inode_index_entry_leaf_node_allocation_blocks_begin,
            auth_tree_inode_entry_extent_ptr,
            alloc_bitmap_inode_entry_extent_ptr,
            image_layout,
            &mkfs_layout.root_key,
            &mut keys::KeyCacheRef::MutRef { cache: &mut keys_cache },
            &mut *rng,
        ) {
            Ok((inode_index, encrypted_inode_index_entry_leaf_node)) => {
                (inode_index, encrypted_inode_index_entry_leaf_node)
            }
            Err(e) => return Err((chip, e)),
        };

        Ok(Self {
            fs_init_data: Some(CocoonFsMkFsFutureFsInitData {
                chip,
                mkfs_layout,
                alloc_bitmap,
                auth_tree_config,
                keys_cache,
                inode_index,
                enable_trimming,
            }),
            auth_tree_initialization_cursor: Some(auth_tree_initialization_cursor),
            encrypted_inode_index_entry_leaf_node,
            alloc_bitmap_file: None,
            root_hmac_digest: Vec::new(),
            auth_tree_node_cache: None,
            first_static_image_header_chip_io_block: Vec::new(),
            rng,
            fut_state: CocoonFsMkFsFutureState::Init,
        })
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> future::Future for CocoonFsMkFsFuture<ST, C>
where
    <ST as sync_types::SyncTypes>::RwLock<inode_index::InodeIndexTreeNodeCache>: marker::Unpin,
{
    type Output = Result<Result<CocoonFsSyncRcPtrType<ST, C>, (C, NvFsError)>, NvFsError>;

    fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        let fs_init_data = match this.fs_init_data.as_mut() {
            Some(fs_init_data) => fs_init_data,
            None => {
                this.fut_state = CocoonFsMkFsFutureState::Done;
                return task::Poll::Ready(Err(nvfs_err_internal!()));
            }
        };

        let e = 'outer: loop {
            match &mut this.fut_state {
                CocoonFsMkFsFutureState::Init => {
                    // Advance the auth_tree_initialization_cursor. See CocoonFsMkFsLayout::new():
                    // the inode index tree node might perhaps come first (if there's enough space),
                    // followed by Journal Log Head and the Authentication Tree, which are
                    // themselves not authenticated, and in turned followed by the Allocation Bitmap
                    // File, which is.
                    let auth_tree_initialization_cursor = match this.auth_tree_initialization_cursor.take() {
                        Some(auth_tree_initialization_cursor) => auth_tree_initialization_cursor,
                        None => break nvfs_err_internal!(),
                    };
                    let mkfs_layout = &fs_init_data.mkfs_layout;
                    if mkfs_layout.inode_index_entry_leaf_node_allocation_blocks_begin
                        < mkfs_layout.journal_log_head_extent.begin()
                    {
                        let advance_fut = match auth_tree_initialization_cursor
                            .advance_to(mkfs_layout.inode_index_entry_leaf_node_allocation_blocks_begin)
                        {
                            Ok(advance_fut) => advance_fut,
                            Err((_, e)) => break e,
                        };
                        this.fut_state =
                            CocoonFsMkFsFutureState::AdvanceAuthTreeCursorToInodeIndexEntryLeafNode { advance_fut };
                    } else {
                        let advance_fut = match auth_tree_initialization_cursor
                            .advance_to(mkfs_layout.alloc_bitmap_file_extent.begin())
                        {
                            Ok(advance_fut) => advance_fut,
                            Err((_, e)) => break e,
                        };
                        this.fut_state =
                            CocoonFsMkFsFutureState::AdvanceAuthTreeCursorToAllocBitmapFile { advance_fut };
                    }
                }
                CocoonFsMkFsFutureState::AdvanceAuthTreeCursorToInodeIndexEntryLeafNode { advance_fut } => {
                    let auth_tree_initialization_cursor =
                        match auth_tree::AuthTreeInitializationCursorAdvanceFuture::poll(
                            pin::Pin::new(advance_fut),
                            &fs_init_data.chip,
                            &fs_init_data.auth_tree_config,
                            cx,
                        ) {
                            task::Poll::Ready(Ok(auth_tree_initialization_cursor)) => auth_tree_initialization_cursor,
                            task::Poll::Ready(Err(e)) => break e,
                            task::Poll::Pending => return task::Poll::Pending,
                        };
                    this.auth_tree_initialization_cursor = Some(auth_tree_initialization_cursor);

                    this.fut_state = CocoonFsMkFsFutureState::AuthTreeUpdateInodeIndexEntryLeafNodeRange {
                        next_allocation_block_in_inode_index_entry_leaf_node: 0,
                        auth_tree_write_part_fut: None,
                    };
                }
                CocoonFsMkFsFutureState::AuthTreeUpdateInodeIndexEntryLeafNodeRange {
                    next_allocation_block_in_inode_index_entry_leaf_node,
                    auth_tree_write_part_fut,
                } => {
                    let auth_tree_initialization_cursor = 'write_auth_tree_part: loop {
                        let mut auth_tree_initialization_cursor =
                            if let Some(auth_tree_write_part_fut) = auth_tree_write_part_fut.as_mut() {
                                match auth_tree::AuthTreeInitializationCursorWritePartFuture::poll(
                                    pin::Pin::new(auth_tree_write_part_fut),
                                    &fs_init_data.chip,
                                    &fs_init_data.auth_tree_config,
                                    cx,
                                ) {
                                    task::Poll::Ready(Ok(auth_tree_initialization_cursor)) => {
                                        auth_tree_initialization_cursor
                                    }
                                    task::Poll::Ready(Err(e)) => break 'outer e,
                                    task::Poll::Pending => return task::Poll::Pending,
                                }
                            } else {
                                match this.auth_tree_initialization_cursor.take() {
                                    Some(auth_tree_initialization_cursor) => auth_tree_initialization_cursor,
                                    None => break 'outer nvfs_err_internal!(),
                                }
                            };

                        let image_layout = &fs_init_data.mkfs_layout.image_layout;
                        let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                        let allocation_blocks_in_inode_index_tree_node =
                            1usize << (image_layout.index_tree_node_allocation_blocks_log2 as u32);
                        while *next_allocation_block_in_inode_index_entry_leaf_node
                            != allocation_blocks_in_inode_index_tree_node
                        {
                            let cur_allocation_block_in_inode_index_entry_leaf_node =
                                *next_allocation_block_in_inode_index_entry_leaf_node;
                            *next_allocation_block_in_inode_index_entry_leaf_node += 1;
                            auth_tree_initialization_cursor = match auth_tree_initialization_cursor.update(
                                &fs_init_data.auth_tree_config,
                                &this.encrypted_inode_index_entry_leaf_node
                                    [cur_allocation_block_in_inode_index_entry_leaf_node
                                        << (allocation_block_size_128b_log2 + 7)
                                        ..(cur_allocation_block_in_inode_index_entry_leaf_node + 1)
                                            << (allocation_block_size_128b_log2 + 7)],
                            ) {
                                Ok(auth_tree::AuthTreeInitializationCursorUpdateResult::NeedAuthTreePartWrite {
                                    write_fut,
                                }) => {
                                    *auth_tree_write_part_fut = Some(write_fut);
                                    continue 'write_auth_tree_part;
                                }
                                Ok(auth_tree::AuthTreeInitializationCursorUpdateResult::Done { cursor }) => cursor,
                                Err(e) => break 'outer e,
                            };
                        }

                        break auth_tree_initialization_cursor;
                    };

                    let advance_fut = match auth_tree_initialization_cursor
                        .advance_to(fs_init_data.mkfs_layout.alloc_bitmap_file_extent.begin())
                    {
                        Ok(advance_fut) => advance_fut,
                        Err((_, e)) => break e,
                    };
                    this.fut_state = CocoonFsMkFsFutureState::AdvanceAuthTreeCursorToAllocBitmapFile { advance_fut };
                }
                CocoonFsMkFsFutureState::AdvanceAuthTreeCursorToAllocBitmapFile { advance_fut } => {
                    let auth_tree_initialization_cursor =
                        match auth_tree::AuthTreeInitializationCursorAdvanceFuture::poll(
                            pin::Pin::new(advance_fut),
                            &fs_init_data.chip,
                            &fs_init_data.auth_tree_config,
                            cx,
                        ) {
                            task::Poll::Ready(Ok(auth_tree_initialization_cursor)) => auth_tree_initialization_cursor,
                            task::Poll::Ready(Err(e)) => break e,
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    let mkfs_layout = &fs_init_data.mkfs_layout;
                    let initialize_alloc_bitmap_file_fut =
                        match alloc_bitmap::AllocBitmapFileInitializeFuture::<C>::new::<ST>(
                            &mkfs_layout.alloc_bitmap_file_extent,
                            &fs_init_data.chip,
                            auth_tree_initialization_cursor,
                            &mkfs_layout.image_layout,
                            &mkfs_layout.root_key,
                            &mut keys::KeyCacheRef::MutRef {
                                cache: &mut fs_init_data.keys_cache,
                            },
                        ) {
                            Ok(initialize_alloc_bitmap_file_fut) => initialize_alloc_bitmap_file_fut,
                            Err((_, e)) => break e,
                        };
                    this.fut_state = CocoonFsMkFsFutureState::InitializeAllocBitmapFile {
                        initialize_fut: initialize_alloc_bitmap_file_fut,
                    };
                }
                CocoonFsMkFsFutureState::InitializeAllocBitmapFile { initialize_fut } => {
                    let mkfs_layout = &fs_init_data.mkfs_layout;
                    let (
                        alloc_bitmap_file,
                        alloc_bitmap_partial_chip_io_block_file_blocks,
                        auth_tree_initialization_cursor,
                    ) = match alloc_bitmap::AllocBitmapFileInitializeFuture::poll(
                        pin::Pin::new(initialize_fut),
                        &fs_init_data.chip,
                        &fs_init_data.alloc_bitmap,
                        &mkfs_layout.image_layout,
                        &fs_init_data.auth_tree_config,
                        &mut *this.rng,
                        cx,
                    ) {
                        task::Poll::Ready(Ok((
                            alloc_bitmap_file,
                            alloc_bitmap_file_partial_chip_io_block_data,
                            auth_tree_initialization_cursor,
                        ))) => (
                            alloc_bitmap_file,
                            alloc_bitmap_file_partial_chip_io_block_data,
                            auth_tree_initialization_cursor,
                        ),
                        task::Poll::Ready(Err(e)) => break e,
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    this.alloc_bitmap_file = Some(alloc_bitmap_file);
                    this.auth_tree_initialization_cursor = Some(auth_tree_initialization_cursor);

                    let image_layout = &mkfs_layout.image_layout;
                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                    let chip_io_block_size_128b_log2 = fs_init_data.chip.chip_io_block_size_128b_log2();
                    let chip_io_block_allocation_blocks_log2 =
                        chip_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);

                    let tail_data_allocation_blocks_begin = mkfs_layout
                        .alloc_bitmap_file_extent
                        .end()
                        .align_down(chip_io_block_allocation_blocks_log2);
                    // The Allocation Bitmap File's beginning is even aligned to the IO Block size.
                    debug_assert!(tail_data_allocation_blocks_begin >= mkfs_layout.alloc_bitmap_file_extent.begin());
                    // The not yet written Allocation Bitmap File data equals exactly to the partial
                    // Chip IO block size in length.
                    debug_assert_eq!(
                        (u64::from(mkfs_layout.alloc_bitmap_file_extent.end() - tail_data_allocation_blocks_begin)
                            >> (image_layout.index_tree_node_allocation_blocks_log2 as u32))
                            as usize,
                        alloc_bitmap_partial_chip_io_block_file_blocks.len(),
                    );
                    // The remaining tail data consists of
                    // - the partial Chip IO block remainder from the Allocation Bitmap File,
                    // - the Inode Index entry leaf node if it could not get placed right after the
                    //   mutable image header,
                    // - the Authentication Tree inode's extents list, if any,
                    // - the Allocation Bitmap File inode's extents list, if any,
                    // - plus randomized padding to align the end with the IO block size.
                    let tail_data_allocation_blocks_end = mkfs_layout.allocated_image_allocation_blocks_end;
                    let aligned_tail_data_allocation_blocks_end = match tail_data_allocation_blocks_end
                        .align_up(image_layout.io_block_allocation_blocks_log2 as u32)
                    {
                        Some(aligned_tail_data_allocation_blocks_end) => aligned_tail_data_allocation_blocks_end,
                        None => break NvFsError::NoSpace,
                    };
                    if aligned_tail_data_allocation_blocks_end
                        > layout::PhysicalAllocBlockIndex::from(0u64) + mkfs_layout.image_size
                    {
                        break NvFsError::NoSpace;
                    }
                    if aligned_tail_data_allocation_blocks_end == tail_data_allocation_blocks_begin {
                        // No tail data to write, skip this part.
                        this.fut_state = CocoonFsMkFsFutureState::AdvanceAuthTreeCursorToImageEndPrepare;
                        continue;
                    }
                    let tail_data_allocation_blocks_count = match usize::try_from(u64::from(
                        aligned_tail_data_allocation_blocks_end - tail_data_allocation_blocks_begin,
                    )) {
                        Ok(tail_data_allocation_blocks_count) => tail_data_allocation_blocks_count,
                        Err(_) => break NvFsError::DimensionsNotSupported,
                    };
                    let mut tail_data_allocation_blocks =
                        match try_alloc_vec::<Vec<u8>>(tail_data_allocation_blocks_count) {
                            Ok(tail_data_allocation_blocks) => tail_data_allocation_blocks,
                            Err(e) => break NvFsError::from(e),
                        };
                    let allocation_block_size = 1usize << (allocation_block_size_128b_log2 + 7);
                    for tail_data_allocation_block in tail_data_allocation_blocks.iter_mut() {
                        *tail_data_allocation_block = match try_alloc_vec(allocation_block_size) {
                            Ok(tail_data_allocation_block) => tail_data_allocation_block,
                            Err(e) => break 'outer NvFsError::from(e),
                        };
                    }

                    let mut next_tail_data_allocation_block_index = alloc_bitmap_partial_chip_io_block_file_blocks
                        .len()
                        << (image_layout.allocation_bitmap_file_block_allocation_blocks_log2 as u32);
                    if let Err(e) = io_slices::BuffersSliceIoSlicesMutIter::new(
                        &mut tail_data_allocation_blocks[..next_tail_data_allocation_block_index],
                    )
                    .copy_from_iter_exhaustive(io_slices::BuffersSliceIoSlicesIter::new(
                        &alloc_bitmap_partial_chip_io_block_file_blocks,
                    )) {
                        match e {
                            io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                                io_slices::IoSlicesError::BuffersExhausted => break nvfs_err_internal!(),
                            },
                            io_slices::IoSlicesIterError::BackendIteratorError(e) => match e {},
                        }
                    }
                    drop(alloc_bitmap_partial_chip_io_block_file_blocks);

                    if mkfs_layout.inode_index_entry_leaf_node_allocation_blocks_begin
                        >= mkfs_layout.alloc_bitmap_file_extent.end()
                    {
                        debug_assert_eq!(
                            mkfs_layout.inode_index_entry_leaf_node_allocation_blocks_begin,
                            mkfs_layout.alloc_bitmap_file_extent.end()
                        );
                        let cur_tail_data_allocation_block_index = next_tail_data_allocation_block_index;
                        next_tail_data_allocation_block_index +=
                            1usize << (image_layout.index_tree_node_allocation_blocks_log2 as u32);
                        if let Err(e) = io_slices::BuffersSliceIoSlicesMutIter::new(
                            &mut tail_data_allocation_blocks
                                [cur_tail_data_allocation_block_index..next_tail_data_allocation_block_index],
                        )
                        .copy_from_iter_exhaustive(io_slices::SingletonIoSlice::new(
                            &this.encrypted_inode_index_entry_leaf_node,
                        )) {
                            match e {
                                io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                                    io_slices::IoSlicesError::BuffersExhausted => break nvfs_err_internal!(),
                                },
                                io_slices::IoSlicesIterError::BackendIteratorError(e) => match e {},
                            }
                        }
                        this.encrypted_inode_index_entry_leaf_node = Vec::new();
                    } else {
                        debug_assert!(
                            mkfs_layout.inode_index_entry_leaf_node_allocation_blocks_begin
                                < mkfs_layout.journal_log_head_extent.begin()
                        )
                    }

                    if let Some(auth_tree_inode_extents_list_extents) =
                        mkfs_layout.auth_tree_inode_extents_list_extents.as_ref()
                    {
                        let cur_tail_data_allocation_block_index = next_tail_data_allocation_block_index;
                        next_tail_data_allocation_block_index += u64::from(
                            auth_tree_inode_extents_list_extents
                                .get_extent_range(auth_tree_inode_extents_list_extents.len() - 1)
                                .end()
                                - auth_tree_inode_extents_list_extents.get_extent_range(0).begin(),
                        ) as usize;
                        if let Err(e) = inode_extents_list::inode_extents_list_encrypt_into::<ST, _, _, _>(
                            io_slices::BuffersSliceIoSlicesMutIter::new(
                                &mut tail_data_allocation_blocks
                                    [cur_tail_data_allocation_block_index..next_tail_data_allocation_block_index],
                            )
                            .map_infallible_err(),
                            inode_index::SpecialInode::AuthTree as u32,
                            iter::once(mkfs_layout.auth_tree_extent),
                            auth_tree_inode_extents_list_extents.iter(),
                            image_layout,
                            &mkfs_layout.root_key,
                            &mut keys::KeyCacheRef::MutRef {
                                cache: &mut fs_init_data.keys_cache,
                            },
                            &mut *this.rng,
                        ) {
                            break e;
                        }
                    }

                    if let Some(alloc_bitmap_inode_extents_list_extents) =
                        mkfs_layout.alloc_bitmap_inode_extents_list_extents.as_ref()
                    {
                        let cur_tail_data_allocation_block_index = next_tail_data_allocation_block_index;
                        next_tail_data_allocation_block_index += u64::from(
                            alloc_bitmap_inode_extents_list_extents
                                .get_extent_range(alloc_bitmap_inode_extents_list_extents.len() - 1)
                                .end()
                                - alloc_bitmap_inode_extents_list_extents.get_extent_range(0).begin(),
                        ) as usize;
                        if let Err(e) = inode_extents_list::inode_extents_list_encrypt_into::<ST, _, _, _>(
                            io_slices::BuffersSliceIoSlicesMutIter::new(
                                &mut tail_data_allocation_blocks
                                    [cur_tail_data_allocation_block_index..next_tail_data_allocation_block_index],
                            )
                            .map_infallible_err(),
                            inode_index::SpecialInode::AllocBitmap as u32,
                            iter::once(mkfs_layout.alloc_bitmap_file_extent),
                            alloc_bitmap_inode_extents_list_extents.iter(),
                            image_layout,
                            &mkfs_layout.root_key,
                            &mut keys::KeyCacheRef::MutRef {
                                cache: &mut fs_init_data.keys_cache,
                            },
                            &mut *this.rng,
                        ) {
                            break e;
                        }
                    }

                    debug_assert_eq!(
                        next_tail_data_allocation_block_index,
                        u64::from(tail_data_allocation_blocks_end - tail_data_allocation_blocks_begin) as usize
                    );
                    // Fill up the remainder up to the next IO Block boundary with random bytes.
                    if let Err(e) = rng::rng_dyn_dispatch_generate(
                        this.rng.as_mut(),
                        io_slices::BuffersSliceIoSlicesMutIter::new(
                            &mut tail_data_allocation_blocks[next_tail_data_allocation_block_index..],
                        )
                        .map_infallible_err(),
                        None,
                    )
                    .map_err(|e| NvFsError::from(CryptoError::from(e)))
                    {
                        break e;
                    }

                    this.fut_state = CocoonFsMkFsFutureState::AuthTreeUpdateTailDataRange {
                        tail_data_allocation_blocks_begin,
                        tail_data_allocation_blocks_end,
                        aligned_tail_data_allocation_blocks_end,
                        tail_data_allocation_blocks,
                        next_allocation_block_in_tail_data: 0,
                        auth_tree_write_part_fut: None,
                    };
                }
                CocoonFsMkFsFutureState::AuthTreeUpdateTailDataRange {
                    tail_data_allocation_blocks_begin,
                    tail_data_allocation_blocks_end,
                    aligned_tail_data_allocation_blocks_end,
                    tail_data_allocation_blocks,
                    next_allocation_block_in_tail_data,
                    auth_tree_write_part_fut,
                } => {
                    let auth_tree_initialization_cursor = 'write_auth_tree_part: loop {
                        let mut auth_tree_initialization_cursor =
                            if let Some(auth_tree_write_part_fut) = auth_tree_write_part_fut.as_mut() {
                                match auth_tree::AuthTreeInitializationCursorWritePartFuture::poll(
                                    pin::Pin::new(auth_tree_write_part_fut),
                                    &fs_init_data.chip,
                                    &fs_init_data.auth_tree_config,
                                    cx,
                                ) {
                                    task::Poll::Ready(Ok(auth_tree_initialization_cursor)) => {
                                        auth_tree_initialization_cursor
                                    }
                                    task::Poll::Ready(Err(e)) => break 'outer e,
                                    task::Poll::Pending => return task::Poll::Pending,
                                }
                            } else {
                                match this.auth_tree_initialization_cursor.take() {
                                    Some(auth_tree_initialization_cursor) => auth_tree_initialization_cursor,
                                    None => break 'outer nvfs_err_internal!(),
                                }
                            };

                        while *next_allocation_block_in_tail_data
                            != u64::from(*tail_data_allocation_blocks_end - *tail_data_allocation_blocks_begin) as usize
                        {
                            let cur_allocation_block_in_tail_data = *next_allocation_block_in_tail_data;
                            *next_allocation_block_in_tail_data += 1;
                            auth_tree_initialization_cursor = match auth_tree_initialization_cursor.update(
                                &fs_init_data.auth_tree_config,
                                &tail_data_allocation_blocks[cur_allocation_block_in_tail_data],
                            ) {
                                Ok(auth_tree::AuthTreeInitializationCursorUpdateResult::NeedAuthTreePartWrite {
                                    write_fut,
                                }) => {
                                    *auth_tree_write_part_fut = Some(write_fut);
                                    continue 'write_auth_tree_part;
                                }
                                Ok(auth_tree::AuthTreeInitializationCursorUpdateResult::Done { cursor }) => cursor,
                                Err(e) => break 'outer e,
                            };
                        }

                        break auth_tree_initialization_cursor;
                    };
                    this.auth_tree_initialization_cursor = Some(auth_tree_initialization_cursor);

                    let image_layout = &fs_init_data.mkfs_layout.image_layout;
                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                    // A Chip IO block is <= the FS IO Block in size, as has been verified
                    // Self::new(), hence the cast to u8 can't overflow.
                    let chip_io_block_allocation_blocks_log2 = fs_init_data
                        .chip
                        .chip_io_block_size_128b_log2()
                        .saturating_sub(allocation_block_size_128b_log2)
                        as u8;
                    let write_fut = write_blocks::WriteBlocksFuture::new(
                        &layout::PhysicalAllocBlockRange::new(
                            *tail_data_allocation_blocks_begin,
                            *aligned_tail_data_allocation_blocks_end,
                        ),
                        mem::take(tail_data_allocation_blocks),
                        0,
                        chip_io_block_allocation_blocks_log2,
                        image_layout.allocation_block_size_128b_log2,
                    );
                    this.fut_state = CocoonFsMkFsFutureState::WriteTailData { write_fut };
                }
                CocoonFsMkFsFutureState::WriteTailData { write_fut } => {
                    match chip::NvChipFuture::poll(pin::Pin::new(write_fut), &fs_init_data.chip, cx) {
                        task::Poll::Ready(Ok((_, Ok(())))) => (),
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => break e,
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    this.fut_state = CocoonFsMkFsFutureState::AdvanceAuthTreeCursorToImageEndPrepare;
                }
                CocoonFsMkFsFutureState::AdvanceAuthTreeCursorToImageEndPrepare => {
                    // Move the auth_tree_initialization_cursor all the way to the end,
                    // digesting all of the image remainder as unallocated, and thereby completing
                    // the Authentication Tree initialization.
                    let auth_tree_initialization_cursor = match this.auth_tree_initialization_cursor.take() {
                        Some(auth_tree_initialization_cursor) => auth_tree_initialization_cursor,
                        None => break nvfs_err_internal!(),
                    };
                    let advance_fut = match auth_tree_initialization_cursor
                        .advance_to(layout::PhysicalAllocBlockIndex::from(0) + fs_init_data.mkfs_layout.image_size)
                    {
                        Ok(advance_fut) => advance_fut,
                        Err((_, e)) => break e,
                    };
                    this.fut_state = CocoonFsMkFsFutureState::AdvanceAuthTreeCursorToImageEnd { advance_fut };
                }
                CocoonFsMkFsFutureState::AdvanceAuthTreeCursorToImageEnd { advance_fut } => {
                    let auth_tree_initialization_cursor =
                        match auth_tree::AuthTreeInitializationCursorAdvanceFuture::poll(
                            pin::Pin::new(advance_fut),
                            &fs_init_data.chip,
                            &fs_init_data.auth_tree_config,
                            cx,
                        ) {
                            task::Poll::Ready(Ok(auth_tree_initialization_cursor)) => auth_tree_initialization_cursor,
                            task::Poll::Ready(Err(e)) => break e,
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    let mkfs_layout = &fs_init_data.mkfs_layout;
                    let image_layout = &mkfs_layout.image_layout;
                    let auth_tree_node_cache = match auth_tree::AuthTreeNodeCache::new(&fs_init_data.auth_tree_config) {
                        Ok(auth_tree_node_cache) => auth_tree_node_cache,
                        Err(e) => break e,
                    };
                    let auth_tree_node_cache = this.auth_tree_node_cache.insert(auth_tree_node_cache);
                    let root_hmac_digest_len =
                        hash::hash_alg_digest_len(image_layout.auth_tree_root_hmac_hash_alg) as usize;
                    let mut root_hmac_digest = match try_alloc_vec(root_hmac_digest_len) {
                        Ok(root_hmac_digest) => root_hmac_digest,
                        Err(e) => break NvFsError::from(e),
                    };
                    if let Err(e) = auth_tree_initialization_cursor.finalize_into(
                        &mut root_hmac_digest,
                        &fs_init_data.auth_tree_config,
                        Some(auth_tree_node_cache),
                    ) {
                        break e;
                    };
                    this.root_hmac_digest = root_hmac_digest;

                    // The data to write out before the Journal Log Head extent consists of the
                    // Static + Mutable image Headers, possibly followed by the Inode Index Tree
                    // entry leaf node, if there was enough room to place it there.
                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                    let io_block_allocation_blocks_log2 = image_layout.io_block_allocation_blocks_log2 as u32;
                    let salt_len = match u8::try_from(mkfs_layout.salt.len()) {
                        Ok(salt_len) => salt_len,
                        Err(_) => break NvFsError::from(CocoonFsFormatError::InvalidSaltLength),
                    };
                    let mutable_image_header_allocation_blocks_range =
                        image_header::MutableImageHeader::physical_location(image_layout, salt_len);
                    debug_assert!(u64::from(mutable_image_header_allocation_blocks_range.begin())
                        .is_aligned_pow2(io_block_allocation_blocks_log2));
                    let padded_static_image_header_end = mutable_image_header_allocation_blocks_range.begin();
                    debug_assert!(
                        u64::from(padded_static_image_header_end).is_aligned_pow2(io_block_allocation_blocks_log2)
                    );
                    let head_data_allocation_blocks_end = if mkfs_layout
                        .inode_index_entry_leaf_node_allocation_blocks_begin
                        < mkfs_layout.journal_log_head_extent.begin()
                    {
                        debug_assert_eq!(
                            mkfs_layout.inode_index_entry_leaf_node_allocation_blocks_begin,
                            mutable_image_header_allocation_blocks_range.end()
                        );
                        mkfs_layout.inode_index_entry_leaf_node_allocation_blocks_begin
                            + layout::AllocBlockCount::from(
                                1u64 << (image_layout.index_tree_node_allocation_blocks_log2 as u32),
                            )
                    } else {
                        mutable_image_header_allocation_blocks_range.end()
                    };
                    let aligned_head_data_allocation_blocks_end =
                        match head_data_allocation_blocks_end.align_up(io_block_allocation_blocks_log2) {
                            Some(aligned_head_data_allocation_blocks_end) => aligned_head_data_allocation_blocks_end,
                            None => {
                                // Impossible, it's already known that the Journal Log Head etc. are located
                                // after.
                                break nvfs_err_internal!();
                            }
                        };
                    debug_assert!(
                        aligned_head_data_allocation_blocks_end <= mkfs_layout.journal_log_head_extent.begin()
                    );

                    let chip_io_block_allocation_blocks_log2 = fs_init_data
                        .chip
                        .chip_io_block_size_128b_log2()
                        .saturating_sub(allocation_block_size_128b_log2);
                    // It is already known that the Chip IO Block size is <= the FS' IO Block size.
                    debug_assert!(chip_io_block_allocation_blocks_log2 <= io_block_allocation_blocks_log2);
                    let chip_io_block_size =
                        1usize << (chip_io_block_allocation_blocks_log2 + allocation_block_size_128b_log2 + 7);

                    // The first Chip IO BLock of the image header will get written separately at
                    // the very end, after a write barrier.
                    // Make the first Chip IO Block buffer a trivial Vec of a an u8 Vec, so that
                    // WriteBlocksFuture can be used to write that out as well.
                    let mut first_static_image_header_chip_io_block = match try_alloc_vec::<Vec<u8>>(1) {
                        Ok(first_static_image_header_chip_io_block) => first_static_image_header_chip_io_block,
                        Err(e) => break NvFsError::from(e),
                    };
                    first_static_image_header_chip_io_block[0] = match try_alloc_vec(chip_io_block_size) {
                        Ok(first_static_image_header_chip_io_block) => first_static_image_header_chip_io_block,
                        Err(e) => break NvFsError::from(e),
                    };

                    let first_static_image_header_chip_io_block_allocation_blocks_end =
                        layout::PhysicalAllocBlockIndex::from(1u64 << chip_io_block_allocation_blocks_log2);
                    let head_tail_data_allocation_blocks_count = aligned_head_data_allocation_blocks_end
                        - first_static_image_header_chip_io_block_allocation_blocks_end;
                    let head_tail_data_chip_io_blocks_count = match usize::try_from(
                        u64::from(head_tail_data_allocation_blocks_count) >> chip_io_block_allocation_blocks_log2,
                    ) {
                        Ok(head_tail_data_chip_io_blocks_count) => head_tail_data_chip_io_blocks_count,
                        Err(_) => break NvFsError::DimensionsNotSupported,
                    };
                    let mut head_tail_data_chip_io_blocks =
                        match try_alloc_vec::<Vec<u8>>(head_tail_data_chip_io_blocks_count) {
                            Ok(head_tail_data_chip_io_blocks) => head_tail_data_chip_io_blocks,
                            Err(e) => break NvFsError::from(e),
                        };
                    for head_tail_data_chip_io_block in head_tail_data_chip_io_blocks.iter_mut() {
                        *head_tail_data_chip_io_block = match try_alloc_vec(chip_io_block_size) {
                            Ok(head_tail_data_chip_io_block) => head_tail_data_chip_io_block,
                            Err(e) => break 'outer NvFsError::from(e),
                        };
                    }
                    // Encode the static image header.
                    if let Err(e) = image_header::StaticImageHeader::encode(
                        io_slices::SingletonIoSliceMut::new(&mut first_static_image_header_chip_io_block[0])
                            .chain(io_slices::BuffersSliceIoSlicesMutIter::new(
                                &mut head_tail_data_chip_io_blocks[..(u64::from(
                                    padded_static_image_header_end
                                        - first_static_image_header_chip_io_block_allocation_blocks_end,
                                ) >> chip_io_block_allocation_blocks_log2)
                                    as usize],
                            ))
                            .map_infallible_err(),
                        image_layout,
                        &mkfs_layout.salt,
                    ) {
                        break e;
                    }
                    // Save away for eventually writing it out at the end.
                    this.first_static_image_header_chip_io_block = first_static_image_header_chip_io_block;

                    // And encode the rest in what follows.
                    let mut head_tail_data_chip_io_blocks_io_slices_iter = io_slices::BuffersSliceIoSlicesMutIter::new(
                        &mut head_tail_data_chip_io_blocks[(u64::from(
                            padded_static_image_header_end
                                - first_static_image_header_chip_io_block_allocation_blocks_end,
                        ) >> chip_io_block_allocation_blocks_log2)
                            as usize..],
                    );

                    // Encode the mutable image header.
                    let inode_index_entry_leaf_node_block_ptr = match extent_ptr::EncodedBlockPtr::encode(Some(
                        mkfs_layout.inode_index_entry_leaf_node_allocation_blocks_begin,
                    )) {
                        Ok(inode_index_entry_leaf_node_block_ptr) => inode_index_entry_leaf_node_block_ptr,
                        Err(e) => break e,
                    };
                    if let Err(e) = image_header::MutableImageHeader::encode(
                        head_tail_data_chip_io_blocks_io_slices_iter
                            .as_ref()
                            .map_err(|e| match e {}),
                        &this.root_hmac_digest,
                        fs_init_data
                            .inode_index
                            .get_entry_leaf_node_preauth_cca_protection_digest(),
                        &inode_index_entry_leaf_node_block_ptr,
                        mkfs_layout.image_size,
                    ) {
                        break e;
                    }
                    // Complete the Allocation Block.
                    let mutable_image_header_padding_len =
                        (image_header::MutableImageHeader::encoded_len(image_layout) as usize).wrapping_neg()
                            & ((1usize << (allocation_block_size_128b_log2 + 7)) - 1);
                    if let Err(e) = io_slices::IoSlicesIter::skip(
                        &mut head_tail_data_chip_io_blocks_io_slices_iter,
                        mutable_image_header_padding_len,
                    ) {
                        match e {
                            io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                                io_slices::IoSlicesError::BuffersExhausted => break nvfs_err_internal!(),
                            },
                            io_slices::IoSlicesIterError::BackendIteratorError(e) => match e {},
                        }
                    };

                    // Copy the Inode Index entry leaf node if placed right after the mutable image
                    // header.
                    if mkfs_layout.inode_index_entry_leaf_node_allocation_blocks_begin
                        < mkfs_layout.journal_log_head_extent.begin()
                    {
                        if let Err(e) = head_tail_data_chip_io_blocks_io_slices_iter
                            .as_ref()
                            .take_exact(this.encrypted_inode_index_entry_leaf_node.len())
                            .map_err(|e| match e {
                                io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                                    io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
                                },
                                io_slices::IoSlicesIterError::BackendIteratorError(e) => match e {},
                            })
                            .copy_from_iter_exhaustive(
                                io_slices::SingletonIoSlice::new(&this.encrypted_inode_index_entry_leaf_node)
                                    .map_infallible_err(),
                            )
                        {
                            match e {
                                io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                                    io_slices::IoSlicesError::BuffersExhausted => break nvfs_err_internal!(),
                                },
                                io_slices::IoSlicesIterError::BackendIteratorError(e) => break e,
                            }
                        }
                        this.encrypted_inode_index_entry_leaf_node = Vec::new();
                    }

                    // And fill the last IO Block's remainder, if any, with random data.
                    if let Err(e) = rng::rng_dyn_dispatch_generate(
                        this.rng.as_mut(),
                        head_tail_data_chip_io_blocks_io_slices_iter.map_infallible_err(),
                        None,
                    )
                    .map_err(|e| NvFsError::from(CryptoError::from(e)))
                    {
                        break e;
                    }

                    // And issue the write.
                    // A Chip IO block is <= the FS IO Block in size, as has been verified
                    // Self::new(), hence the cast to u8 can't overflow.
                    let chip_io_block_allocation_blocks_log2 = chip_io_block_allocation_blocks_log2 as u8;
                    let write_fut = write_blocks::WriteBlocksFuture::new(
                        &layout::PhysicalAllocBlockRange::new(
                            first_static_image_header_chip_io_block_allocation_blocks_end,
                            aligned_head_data_allocation_blocks_end,
                        ),
                        head_tail_data_chip_io_blocks,
                        chip_io_block_allocation_blocks_log2,
                        chip_io_block_allocation_blocks_log2,
                        image_layout.allocation_block_size_128b_log2,
                    );
                    this.fut_state = CocoonFsMkFsFutureState::WriteHeadData { write_fut };
                }
                CocoonFsMkFsFutureState::WriteHeadData { write_fut } => {
                    match chip::NvChipFuture::poll(pin::Pin::new(write_fut), &fs_init_data.chip, cx) {
                        task::Poll::Ready(Ok((_, Ok(())))) => (),
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => break e,
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    // Clear the Journal Log head extent.
                    let mkfs_layout = &fs_init_data.mkfs_layout;
                    let image_layout = &mkfs_layout.image_layout;
                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                    let io_block_allocation_blocks_log2 = image_layout.io_block_allocation_blocks_log2 as u32;
                    let journal_log_head_io_blocks_count = match usize::try_from(
                        u64::from(mkfs_layout.journal_log_head_extent.block_count()) >> io_block_allocation_blocks_log2,
                    ) {
                        Ok(journal_log_head_io_blocks_count) => journal_log_head_io_blocks_count,
                        Err(_) => break NvFsError::DimensionsNotSupported,
                    };
                    let mut journal_log_head_io_blocks =
                        match try_alloc_vec::<Vec<u8>>(journal_log_head_io_blocks_count) {
                            Ok(journal_log_head_io_blocks) => journal_log_head_io_blocks,
                            Err(e) => break NvFsError::from(e),
                        };
                    let io_block_size =
                        1usize << (io_block_allocation_blocks_log2 + allocation_block_size_128b_log2 + 7);
                    for journal_log_head_io_block in journal_log_head_io_blocks.iter_mut() {
                        *journal_log_head_io_block = match try_alloc_vec(io_block_size) {
                            Ok(journal_log_head_io_block) => journal_log_head_io_block,
                            Err(e) => break 'outer NvFsError::from(e),
                        };
                    }
                    // A Chip IO block is <= the FS IO Block in size, as has been verified
                    // Self::new(), hence the cast to u8 can't overflow.
                    let chip_io_block_allocation_blocks_log2 = fs_init_data
                        .chip
                        .chip_io_block_size_128b_log2()
                        .saturating_sub(allocation_block_size_128b_log2)
                        as u8;
                    let write_fut = write_blocks::WriteBlocksFuture::new(
                        &mkfs_layout.journal_log_head_extent,
                        journal_log_head_io_blocks,
                        image_layout.io_block_allocation_blocks_log2,
                        chip_io_block_allocation_blocks_log2,
                        image_layout.allocation_block_size_128b_log2,
                    );
                    this.fut_state = CocoonFsMkFsFutureState::ClearJournalLogHead { write_fut };
                }
                CocoonFsMkFsFutureState::ClearJournalLogHead { write_fut } => {
                    match chip::NvChipFuture::poll(pin::Pin::new(write_fut), &fs_init_data.chip, cx) {
                        task::Poll::Ready(Ok((_, Ok(())))) => (),
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => break e,
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    if fs_init_data.enable_trimming {
                        // No data randomization of fully unallocated IO blocks. Proceed directly to
                        // the final static header write.
                        this.fut_state = CocoonFsMkFsFutureState::WriteBarrierBeforeStaticImageHeaderWritePrepare;
                    } else {
                        // Randomize the unused region after the head data, i.e. the mutable header
                        // or possibly the Inode Index entry leaf node and the Journal Log head
                        // extent, if any.
                        let mkfs_layout = &fs_init_data.mkfs_layout;
                        let image_layout = &mkfs_layout.image_layout;
                        let head_data_allocation_blocks_end = if mkfs_layout
                            .inode_index_entry_leaf_node_allocation_blocks_begin
                            < mkfs_layout.journal_log_head_extent.begin()
                        {
                            debug_assert_eq!(
                                mkfs_layout.inode_index_entry_leaf_node_allocation_blocks_begin,
                                mkfs_layout.image_header_end,
                            );
                            mkfs_layout.inode_index_entry_leaf_node_allocation_blocks_begin
                                + layout::AllocBlockCount::from(
                                    1u64 << (image_layout.index_tree_node_allocation_blocks_log2 as u32),
                                )
                        } else {
                            mkfs_layout.image_header_end
                        };
                        let aligned_head_data_allocation_blocks_end = match head_data_allocation_blocks_end
                            .align_up(image_layout.io_block_allocation_blocks_log2 as u32)
                        {
                            Some(aligned_head_data_allocation_blocks_end) => aligned_head_data_allocation_blocks_end,
                            None => {
                                // Impossible, it's already known that the Journal Log Head etc. are located
                                // after.
                                break nvfs_err_internal!();
                            }
                        };
                        debug_assert!(
                            aligned_head_data_allocation_blocks_end <= mkfs_layout.journal_log_head_extent.begin()
                        );

                        let head_data_padding_allocation_blocks_begin = aligned_head_data_allocation_blocks_end;
                        let head_data_padding_allocation_blocks_end = mkfs_layout.journal_log_head_extent.begin();
                        if head_data_padding_allocation_blocks_begin == head_data_padding_allocation_blocks_end {
                            // There's no padding between the head data and the Journal Log head
                            // extent. Proceed to randomizing all IO Blocks at the image's tail.
                            this.fut_state = CocoonFsMkFsFutureState::RandomizeImageRemainderPrepare;
                        } else {
                            let write_fut = match WriteRandomDataFuture::new(
                                &layout::PhysicalAllocBlockRange::new(
                                    head_data_padding_allocation_blocks_begin,
                                    head_data_padding_allocation_blocks_end,
                                ),
                                image_layout,
                                &fs_init_data.chip,
                            ) {
                                Ok(write_fut) => write_fut,
                                Err(e) => break e,
                            };
                            this.fut_state = CocoonFsMkFsFutureState::RandomizeHeadDataPadding { write_fut };
                        }
                    }
                }
                CocoonFsMkFsFutureState::RandomizeHeadDataPadding { write_fut } => {
                    match WriteRandomDataFuture::poll(pin::Pin::new(write_fut), &fs_init_data.chip, &mut *this.rng, cx)
                    {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => break e,
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    this.fut_state = CocoonFsMkFsFutureState::RandomizeImageRemainderPrepare;
                }
                CocoonFsMkFsFutureState::RandomizeImageRemainderPrepare => {
                    let mkfs_layout = &fs_init_data.mkfs_layout;
                    let image_layout = &mkfs_layout.image_layout;
                    let tail_data_allocation_blocks_end = mkfs_layout.allocated_image_allocation_blocks_end;
                    let aligned_tail_data_allocation_blocks_end = match tail_data_allocation_blocks_end
                        .align_up(image_layout.io_block_allocation_blocks_log2 as u32)
                    {
                        Some(aligned_tail_data_allocation_blocks_end) => aligned_tail_data_allocation_blocks_end,
                        None => {
                            // The very same alignment had been conducted when preparing the tail
                            // data write further above.
                            break nvfs_err_internal!();
                        }
                    };
                    let image_remainder_allocation_blocks_begin = aligned_tail_data_allocation_blocks_end;
                    let image_remainder_allocation_blocks_end =
                        layout::PhysicalAllocBlockIndex::from(0u64) + mkfs_layout.image_size;
                    if image_remainder_allocation_blocks_begin != image_remainder_allocation_blocks_end {
                        let write_fut = match WriteRandomDataFuture::new(
                            &layout::PhysicalAllocBlockRange::new(
                                image_remainder_allocation_blocks_begin,
                                image_remainder_allocation_blocks_end,
                            ),
                            image_layout,
                            &fs_init_data.chip,
                        ) {
                            Ok(write_fut) => write_fut,
                            Err(e) => break e,
                        };
                        this.fut_state = CocoonFsMkFsFutureState::RandomizeImageRemainder { write_fut };
                    } else {
                        this.fut_state = CocoonFsMkFsFutureState::WriteBarrierBeforeStaticImageHeaderWritePrepare;
                    }
                }
                CocoonFsMkFsFutureState::RandomizeImageRemainder { write_fut } => {
                    match WriteRandomDataFuture::poll(pin::Pin::new(write_fut), &fs_init_data.chip, &mut *this.rng, cx)
                    {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => break e,
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    this.fut_state = CocoonFsMkFsFutureState::WriteBarrierBeforeStaticImageHeaderWritePrepare;
                }
                CocoonFsMkFsFutureState::WriteBarrierBeforeStaticImageHeaderWritePrepare => {
                    let write_barrier_fut = match fs_init_data.chip.write_barrier() {
                        Ok(write_barrier_fut) => write_barrier_fut,
                        Err(e) => break NvFsError::from(e),
                    };
                    this.fut_state =
                        CocoonFsMkFsFutureState::WriteBarrierBeforeStaticImageHeaderWrite { write_barrier_fut };
                }
                CocoonFsMkFsFutureState::WriteBarrierBeforeStaticImageHeaderWrite { write_barrier_fut } => {
                    match chip::NvChipFuture::poll(pin::Pin::new(write_barrier_fut), &fs_init_data.chip, cx) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => break NvFsError::from(e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let mkfs_layout = &fs_init_data.mkfs_layout;
                    let image_layout = &mkfs_layout.image_layout;
                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2;
                    // A Chip IO block is <= the FS IO Block in size, as has been verified
                    // Self::new(), hence the cast to u8 can't overflow.
                    let chip_io_block_allocation_blocks_log2 = fs_init_data
                        .chip
                        .chip_io_block_size_128b_log2()
                        .saturating_sub(allocation_block_size_128b_log2 as u32)
                        as u8;

                    let first_static_image_header_chip_io_block_allocation_blocks_end =
                        layout::PhysicalAllocBlockIndex::from(1u64 << (chip_io_block_allocation_blocks_log2 as u32));
                    let write_fut = write_blocks::WriteBlocksFuture::new(
                        &layout::PhysicalAllocBlockRange::new(
                            layout::PhysicalAllocBlockIndex::from(0u64),
                            first_static_image_header_chip_io_block_allocation_blocks_end,
                        ),
                        mem::take(&mut this.first_static_image_header_chip_io_block),
                        chip_io_block_allocation_blocks_log2,
                        chip_io_block_allocation_blocks_log2,
                        allocation_block_size_128b_log2,
                    );
                    this.fut_state = CocoonFsMkFsFutureState::WriteStaticImageHeader { write_fut };
                }
                CocoonFsMkFsFutureState::WriteStaticImageHeader { write_fut } => {
                    match chip::NvChipFuture::poll(pin::Pin::new(write_fut), &fs_init_data.chip, cx) {
                        task::Poll::Ready(Ok((_, Ok(())))) => (),
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => break e,
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let write_sync_fut = match fs_init_data.chip.write_sync() {
                        Ok(write_sync_fut) => write_sync_fut,
                        Err(e) => break NvFsError::from(e),
                    };
                    this.fut_state = CocoonFsMkFsFutureState::WriteSyncAfterStaticImageHaderWrite { write_sync_fut };
                }
                CocoonFsMkFsFutureState::WriteSyncAfterStaticImageHaderWrite { write_sync_fut } => {
                    match chip::NvChipFuture::poll(pin::Pin::new(write_sync_fut), &fs_init_data.chip, cx) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => break NvFsError::from(e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    // And, finally, create a CocoonFs instance.
                    this.fut_state = CocoonFsMkFsFutureState::Done;
                    let fs_init_data = match this.fs_init_data.take() {
                        Some(fs_init_data) => fs_init_data,
                        None => break nvfs_err_internal!(),
                    };
                    let CocoonFsMkFsFutureFsInitData {
                        chip,
                        mkfs_layout,
                        mut alloc_bitmap,
                        auth_tree_config,
                        keys_cache,
                        inode_index,
                        enable_trimming,
                    } = fs_init_data;
                    let CocoonFsMkFsLayout {
                        image_layout,
                        salt,
                        image_header_end,
                        image_size,
                        allocated_image_allocation_blocks_end: _,
                        root_key,
                        inode_index_entry_leaf_node_allocation_blocks_begin,
                        journal_log_head_extent: _,
                        auth_tree_extent: _,
                        alloc_bitmap_file_extent: _,
                        auth_tree_inode_extents_list_extents: _,
                        alloc_bitmap_inode_extents_list_extents: _,
                    } = mkfs_layout;
                    let alloc_bitmap_file = match this.alloc_bitmap_file.take() {
                        Some(alloc_bitmap_file) => alloc_bitmap_file,
                        None => return task::Poll::Ready(Ok(Err((chip, nvfs_err_internal!())))),
                    };
                    let root_hmac_digest = mem::take(&mut this.root_hmac_digest);
                    let auth_tree_node_cache = match this.auth_tree_node_cache.take() {
                        Some(auth_tree_node_cache) => auth_tree_node_cache,
                        None => return task::Poll::Ready(Ok(Err((chip, nvfs_err_internal!())))),
                    };

                    let inode_index_entry_leaf_node_block_ptr = match extent_ptr::EncodedBlockPtr::encode(Some(
                        inode_index_entry_leaf_node_allocation_blocks_begin,
                    )) {
                        Ok(inode_index_entry_leaf_node_block_ptr) => inode_index_entry_leaf_node_block_ptr,
                        Err(e) => return task::Poll::Ready(Ok(Err((chip, e)))),
                    };
                    let fs_config = CocoonFsConfig {
                        image_layout: image_layout.clone(),
                        salt,
                        inode_index_entry_leaf_node_block_ptr,
                        enable_trimming,
                        root_key,
                        image_header_end,
                    };

                    // Up to know, the alloc_bitmap had been just large enough to cover everything
                    // allocated only. Extend to the full image size.
                    if let Err(e) = alloc_bitmap.resize(mkfs_layout.image_size) {
                        return task::Poll::Ready(Ok(Err((chip, e))));
                    }
                    let auth_tree = auth_tree::AuthTree::<ST>::new_from_parts(
                        auth_tree_config,
                        root_hmac_digest,
                        auth_tree_node_cache,
                    );
                    let read_buffer = match read_buffer::ReadBuffer::new(&image_layout, &chip) {
                        Ok(read_buffer) => read_buffer,
                        Err(e) => return task::Poll::Ready(Ok(Err((chip, e)))),
                    };
                    let fs_sync_state = CocoonFsSyncState {
                        image_size,
                        alloc_bitmap,
                        alloc_bitmap_file,
                        auth_tree,
                        read_buffer,
                        inode_index,
                        keys_cache: ST::RwLock::from(keys_cache),
                    };

                    let mut chip = Some(chip);
                    let fs = match <ST::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>::try_new_with(|| {
                        let chip = match chip.take() {
                            Some(chip) => chip,
                            None => return Err(nvfs_err_internal!()),
                        };
                        Ok((CocoonFs::new(chip, fs_config, fs_sync_state), ()))
                    }) {
                        Ok((fs, _)) => fs,
                        Err(e) => {
                            let chip = match chip.take() {
                                Some(chip) => chip,
                                None => return task::Poll::Ready(Err(nvfs_err_internal!())),
                            };
                            let e = match e {
                                sync_types::SyncRcPtrTryNewWithError::TryNewError(e) => match e {
                                    sync_types::SyncRcPtrTryNewError::AllocationFailure => {
                                        NvFsError::MemoryAllocationFailure
                                    }
                                },
                                sync_types::SyncRcPtrTryNewWithError::WithError(e) => e,
                            };
                            return task::Poll::Ready(Ok(Err((chip, e))));
                        }
                    };

                    // Safety: the fs is new and never moved out from again.
                    let fs = unsafe { pin::Pin::new_unchecked(fs) };
                    return task::Poll::Ready(Ok(Ok(fs)));
                }
                CocoonFsMkFsFutureState::Done => unreachable!(),
            }
        };

        this.fut_state = CocoonFsMkFsFutureState::Done;
        match this.fs_init_data.take() {
            Some(CocoonFsMkFsFutureFsInitData { chip, .. }) => task::Poll::Ready(Ok(Err((chip, e)))),
            None => task::Poll::Ready(Err(e)),
        }
    }
}

/// Helper for [`CocoonFsMkFsFuture`] for filling unallocated blocks with random
/// data.
struct WriteRandomDataFuture<C: chip::NvChip> {
    extent: layout::PhysicalAllocBlockRange,
    next_allocation_block_index: layout::PhysicalAllocBlockIndex,
    allocation_block_size_128b_log2: u8,
    io_block_allocation_blocks_log2: u8,
    preferred_bulk_io_blocks_log2: u8,
    fut_state: WriteRandomDataFutureState<C>,
}

enum WriteRandomDataFutureState<C: chip::NvChip> {
    Init,
    RandomDataBulkWritePrepare {
        bulk_io_blocks: Vec<Vec<u8>>,
    },
    WriteRandomDataBulk {
        write_fut: write_blocks::WriteBlocksFuture<C>,
    },
    Done,
}

impl<C: chip::NvChip> WriteRandomDataFuture<C> {
    fn new(
        extent: &layout::PhysicalAllocBlockRange,
        image_layout: &layout::ImageLayout,
        chip: &C,
    ) -> Result<Self, NvFsError> {
        let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
        let io_block_allocation_blocks_log2 = image_layout.io_block_allocation_blocks_log2 as u32;
        if !(u64::from(extent.begin()) | u64::from(extent.end())).is_aligned_pow2(io_block_allocation_blocks_log2) {
            return Err(nvfs_err_internal!());
        }

        let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();
        // Make sure the preferred bulk size is at least an IO Block in size
        // and fits an usize in units of IO Blocks.
        let preferred_bulk_io_blocks_log2 = ((chip
            .preferred_chip_io_blocks_bulk_log2()
            .saturating_add(chip_io_block_size_128b_log2)
            .saturating_sub(allocation_block_size_128b_log2)
            .min(u64::BITS - 1)
            .max(io_block_allocation_blocks_log2)
            .min(usize::BITS - 1 + io_block_allocation_blocks_log2))
            - io_block_allocation_blocks_log2) as u8;
        Ok(Self {
            extent: *extent,
            next_allocation_block_index: extent.begin(),
            allocation_block_size_128b_log2: image_layout.allocation_block_size_128b_log2,
            io_block_allocation_blocks_log2: image_layout.io_block_allocation_blocks_log2,
            preferred_bulk_io_blocks_log2,
            fut_state: WriteRandomDataFutureState::Init,
        })
    }

    fn poll(
        self: pin::Pin<&mut Self>,
        chip: &C,
        rng: &mut dyn rng::RngCoreDispatchable,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), NvFsError>> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                WriteRandomDataFutureState::Init => {
                    // The preferred bulk size in units of IO blocks fits an usize,
                    // c.f. Self::new(). Also, don't bother allocating more IO blocks than the
                    // extent size, if that's smaller.
                    let bulk_io_blocks_count = (1u64 << this.preferred_bulk_io_blocks_log2)
                        .min(u64::from(this.extent.block_count()) >> (this.io_block_allocation_blocks_log2))
                        as usize;
                    let mut bulk_io_blocks = match try_alloc_vec::<Vec<u8>>(bulk_io_blocks_count) {
                        Ok(bulk_io_blocks) => bulk_io_blocks,
                        Err(e) => {
                            this.fut_state = WriteRandomDataFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    let io_block_size = 1usize
                        << (this.io_block_allocation_blocks_log2 as u32
                            + this.allocation_block_size_128b_log2 as u32
                            + 7);
                    for bulk_io_block in bulk_io_blocks.iter_mut() {
                        *bulk_io_block = match try_alloc_vec(io_block_size) {
                            Ok(bulk_io_block) => bulk_io_block,
                            Err(e) => {
                                this.fut_state = WriteRandomDataFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(e)));
                            }
                        };
                    }
                    this.fut_state = WriteRandomDataFutureState::RandomDataBulkWritePrepare { bulk_io_blocks }
                }
                WriteRandomDataFutureState::RandomDataBulkWritePrepare { bulk_io_blocks } => {
                    let cur_bulk_allocation_blocks_begin = this.next_allocation_block_index;
                    if cur_bulk_allocation_blocks_begin == this.extent.end() {
                        this.fut_state = WriteRandomDataFutureState::Done;
                        return task::Poll::Ready(Ok(()));
                    }
                    let cur_bulk_allocation_blocks_end = (cur_bulk_allocation_blocks_begin
                        + layout::AllocBlockCount::from(1u64))
                    .align_up(this.preferred_bulk_io_blocks_log2 as u32 + this.io_block_allocation_blocks_log2 as u32)
                    .unwrap_or(this.extent.end())
                    .min(this.extent.end());
                    this.next_allocation_block_index = cur_bulk_allocation_blocks_end;

                    // The preferred bulk size in units of IO Blocks fits an usize,
                    // c.f. Self::new().
                    let cur_bulk_io_blocks_count =
                        (u64::from(cur_bulk_allocation_blocks_end - cur_bulk_allocation_blocks_begin)
                            >> (this.io_block_allocation_blocks_log2 as u32)) as usize;
                    if let Err(e) = rng::rng_dyn_dispatch_generate(
                        rng,
                        io_slices::BuffersSliceIoSlicesMutIter::new(&mut bulk_io_blocks[..cur_bulk_io_blocks_count])
                            .map_infallible_err(),
                        None,
                    ) {
                        this.fut_state = WriteRandomDataFutureState::Done;
                        return task::Poll::Ready(Err(NvFsError::from(e)));
                    }

                    // It's been checked in CocoonFsMkFsFuture::new() that the Chip IO block size <=
                    // the FS' IO block size, in particular the cast to u8 won't overflow.
                    let chip_io_block_allocation_blocks_log2 =
                        chip.chip_io_block_size_128b_log2()
                            .saturating_sub(this.allocation_block_size_128b_log2 as u32) as u8;
                    let write_fut = write_blocks::WriteBlocksFuture::new(
                        &layout::PhysicalAllocBlockRange::new(
                            cur_bulk_allocation_blocks_begin,
                            cur_bulk_allocation_blocks_end,
                        ),
                        mem::take(bulk_io_blocks),
                        this.io_block_allocation_blocks_log2,
                        chip_io_block_allocation_blocks_log2,
                        this.allocation_block_size_128b_log2,
                    );
                    this.fut_state = WriteRandomDataFutureState::WriteRandomDataBulk { write_fut };
                }
                WriteRandomDataFutureState::WriteRandomDataBulk { write_fut } => {
                    let bulk_io_blocks = match chip::NvChipFuture::poll(pin::Pin::new(write_fut), chip, cx) {
                        task::Poll::Ready(Ok((bulk_io_blocks, Ok(())))) => bulk_io_blocks,
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                            this.fut_state = WriteRandomDataFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    this.fut_state = WriteRandomDataFutureState::RandomDataBulkWritePrepare { bulk_io_blocks };
                }
                WriteRandomDataFutureState::Done => unreachable!(),
            }
        }
    }
}
