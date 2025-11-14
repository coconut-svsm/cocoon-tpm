// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`CocoonFsMkFsFuture`].

extern crate alloc;
use alloc::boxed::Box;

use crate::{
    blkdev::{self, NvBlkDevIoError},
    crypto::{CryptoError, hash, rng},
    fs::{
        NvFsError, NvFsIoError,
        cocoonfs::{
            CocoonFsFormatError, CocoonFsImageLayout, alloc_bitmap, auth_tree, encryption_entities, extent_ptr,
            extents,
            fs::{CocoonFs, CocoonFsConfig, CocoonFsSyncRcPtrType, CocoonFsSyncState},
            image_header, inode_extents_list, inode_index, journal, keys,
            layout::{self, BlockCount as _, BlockIndex as _},
            read_buffer, write_blocks,
        },
    },
    nvfs_err_internal,
    utils_async::sync_types,
    utils_common::{
        bitmanip::BitManip as _,
        fixed_vec::FixedVec,
        io_slices::{self, IoSlicesIterCommon as _, IoSlicesMutIter as _},
    },
};
use core::{future, iter, marker, mem, pin, task};

/// Format a CocoonFs filesystem instance.
///
/// Directly format a filesystem instance, without considering any
/// filesystem creation info header existing on storage, if any.
///
/// # See also:
///
/// * [`CocoonFsWriteMkfsInfoHeaderFuture`] for a way to provision a storage
///   volume for CocoonFs usage without access to the root key.
pub struct CocoonFsMkFsFuture<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev> {
    mkfs_fut: MkFsFuture<ST, B>,
}

impl<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev> CocoonFsMkFsFuture<ST, B> {
    /// Instantiate a [`CocoonFsMkFsFuture`].
    ///
    /// On error, the input `blkdev` and `rng` are returned directly as part of
    /// the `Err`. On success, the [`CocoonFsMkFsFuture`] assumes ownership
    /// of the `blkdev` and `rng` for the duration of the operation. They will
    /// get either returned back from [`poll()`](Self::poll) at completion,
    /// or will be passed onwards to the resulting [`CocoonFs`] instance as
    /// appropriate.
    ///
    /// # Arguments:
    ///
    /// * `blkdev` - The storage to create a filesystem on.
    /// * `image_layout` - The filesystem's [`CocoonFsImageLayout`].
    /// * `salt` - The filsystem salt to be stored in the static image header.
    ///   Its length must not exceed [`u8::MAX`].
    /// * `image_size` - Optional desired filesystem image size in units of
    ///   Bytes to get recorded in the mutable image header. If not specified,
    ///   the maximum possible value within the backing storage's
    ///   [dimensions](blkdev::NvBlkDev::io_blocks) will be used.
    /// * `raw_root_key` - The filesystem's raw root key material supplied from
    ///   extern.
    /// * `enable_trimming` - Whether to enable the submission of [trim
    ///   commands](blkdev::NvBlkDev::trim) to the underlying storage for the
    ///   [`CocoonFs`] instance eventually returned from [`poll()`](Self::poll)
    ///   upon successful completion. The setting of this value also controls
    ///   whether whether unallocated storage will get initialized with random
    ///   data in the course of the filesystem formatting -- unallocated storage
    ///   will get randomized if and only if `enable_trimming` is off.
    /// * `rng` - The [random number generator](rng::RngCoreDispatchable) used
    ///   for generating IVs, as well as randomizing padding in data structures
    ///   and for initializing unallocated storage if `enable_trimming` is off.
    pub fn new(
        blkdev: B,
        image_layout: &CocoonFsImageLayout,
        salt: FixedVec<u8, 4>,
        image_size: Option<u64>,
        raw_root_key: &[u8],
        enable_trimming: bool,
        rng: Box<dyn rng::RngCoreDispatchable + marker::Send>,
    ) -> Result<Self, (B, Box<dyn rng::RngCoreDispatchable + marker::Send>, NvFsError)> {
        // Convert from units of Bytes to Allocation Blocks.
        let image_size = image_size.map(|image_size| {
            layout::AllocBlockCount::from(image_size >> (image_layout.allocation_block_size_128b_log2 as u32 + 7))
        });
        Ok(Self {
            mkfs_fut: MkFsFuture::new(
                blkdev,
                image_layout,
                salt,
                image_size,
                raw_root_key,
                None,
                enable_trimming,
                rng,
            )?,
        })
    }
}

impl<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev> future::Future for CocoonFsMkFsFuture<ST, B>
where
    <ST as sync_types::SyncTypes>::RwLock<inode_index::InodeIndexTreeNodeCache>: marker::Unpin,
{
    /// Output type of [`poll()`](Self::poll).
    ///
    /// A two-level [`Result`] is returned from the
    /// [`Future::poll()`](future::Future::poll):
    ///
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering an internal error and the input
    ///   [`NvBlkDev`](blkdev::NvBlkDev) as and  [random number
    ///   generator](rng::RngCoreDispatchable) lost.
    /// * `Ok((rng, ...))` - Otherwise the outer level [`Result`] is set to
    ///   [`Ok`] and a pair of the input [random number
    ///   generator](rng::RngCoreDispatchable), `rng`, and the operation result
    ///   will get returned within:
    ///   * `Ok((rng, Err((blkdev, e))))` - In case of an error, a pair of the
    ///     [`NvBlkDev`](blkdev::NvBlkDev) instance `blkdev` and the error
    ///     reason `e` is returned in an [`Err`].
    ///   * `Ok((rng, Ok(fs_instance)))` - Otherwise an opened [`CocoonFs`]
    ///     instance `fs_instance` associated with the filesystem just created
    ///     is returned in an [`Ok`].
    type Output = Result<
        (
            Box<dyn rng::RngCoreDispatchable + marker::Send>,
            Result<CocoonFsSyncRcPtrType<ST, B>, (B, NvFsError)>,
        ),
        NvFsError,
    >;

    fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        future::Future::poll(pin::Pin::new(&mut pin::Pin::into_inner(self).mkfs_fut), cx)
    }
}

/// Filesystem layout description internal to [`MkFsFuture`].
struct MkFsLayout {
    image_layout: layout::ImageLayout,
    salt: FixedVec<u8, 4>,
    image_header_end: layout::PhysicalAllocBlockIndex,
    image_size: layout::AllocBlockCount,
    allocated_image_allocation_blocks_end: layout::PhysicalAllocBlockIndex,
    inode_index_entry_leaf_node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
    journal_log_head_extent: layout::PhysicalAllocBlockRange,
    auth_tree_extent: layout::PhysicalAllocBlockRange,
    alloc_bitmap_file_extent: layout::PhysicalAllocBlockRange,
    auth_tree_inode_extents_list_extents: Option<extents::PhysicalExtents>,
    alloc_bitmap_inode_extents_list_extents: Option<extents::PhysicalExtents>,
}

impl MkFsLayout {
    /// Instantiate a [`MkFsLayout`].
    ///
    /// # Arguments:
    ///
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `salt` - The filsystem salt to be stored in the
    ///   [`StaticImageHeader::salt`](image_header::StaticImageHeader::salt).
    /// * `image_size` - The filesystem image size to get recorded in the
    ///   [`MutableImageHeader::image_size`](image_header::MutableImageHeader::image_size).
    pub fn new(
        image_layout: &layout::ImageLayout,
        salt: FixedVec<u8, 4>,
        image_size: layout::AllocBlockCount,
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MkFsFutureBackupMkfsInfoHeaderWriteControl {
    Write,
    RetainExisting,
}

/// Internal filesystem creation ("mkfs") primitive.
pub struct MkFsFuture<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev> {
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self.
    fs_init_data: Option<MkFsFutureFsInitData<ST, B>>,

    // Always valid, initialized from Self::new().
    backup_mkfsinfo_header_write_control: Option<MkFsFutureBackupMkfsInfoHeaderWriteControl>,

    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self.
    auth_tree_initialization_cursor: Option<Box<auth_tree::AuthTreeInitializationCursor>>,

    encrypted_inode_index_entry_leaf_node: FixedVec<u8, 7>,

    // Initialized when the Allocation Bitmap File has been written out.
    alloc_bitmap_file: Option<alloc_bitmap::AllocBitmapFile>,

    // Initialized after the Authentication Tree has been initialized and the
    // final root digest computed.
    root_hmac_digest: FixedVec<u8, 5>,

    // Initialized after the Authentication Tree has been initialized and nodes from the
    // initialization might first get added to the cache.
    auth_tree_node_cache: Option<auth_tree::AuthTreeNodeCache>,

    // Initialized after the header data to write out has been setup.
    first_static_image_header_blkdev_io_block: FixedVec<FixedVec<u8, 7>, 0>,

    #[cfg(test)]
    pub(super) test_fail_write_static_image_header: bool,

    fut_state: MkFsFutureState<B>,
}

/// Part of the internal [`MkFsFuture`] state valid throughout the whole
/// lifetime.
///
/// Various state bundled together so that only one [`Option`] needs to get
/// examined upon each [`poll()`](MkFsFuture::poll) invocation.
struct MkFsFutureFsInitData<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev> {
    blkdev: B,
    rng: Box<dyn rng::RngCoreDispatchable + marker::Send>,
    mkfs_layout: MkFsLayout,
    root_key: keys::RootKey,
    alloc_bitmap: alloc_bitmap::AllocBitmap,
    auth_tree_config: auth_tree::AuthTreeConfig,
    keys_cache: keys::KeyCache,
    inode_index: inode_index::InodeIndex<ST>,

    enable_trimming: bool,
}

/// [`MkFsFuture`] state-machine state.
#[allow(clippy::large_enum_variant)]
enum MkFsFutureState<B: blkdev::NvBlkDev> {
    Init,
    ResizeBlkDev {
        resize_fut: B::ResizeFuture,
    },
    WriteBackupMkFsInfoHeader {
        write_backup_mkfsinfo_header_fut: WriteMkFsInfoHeaderFuture<B>,
    },
    WriteBarrierAfterBackupMkFsInfoHeaderWrite {
        write_barrier_fut: B::WriteBarrierFuture,
    },
    PrepareAdvanceAuthTreeCursorToInitPos,
    AdvanceAuthTreeCursorToInodeIndexEntryLeafNode {
        advance_fut: auth_tree::AuthTreeInitializationCursorAdvanceFuture<B>,
    },
    AuthTreeUpdateInodeIndexEntryLeafNodeRange {
        next_allocation_block_in_inode_index_entry_leaf_node: usize,
        auth_tree_write_part_fut: Option<auth_tree::AuthTreeInitializationCursorWritePartFuture<B>>,
    },
    AdvanceAuthTreeCursorToAllocBitmapFile {
        advance_fut: auth_tree::AuthTreeInitializationCursorAdvanceFuture<B>,
    },
    InitializeAllocBitmapFile {
        initialize_fut: alloc_bitmap::AllocBitmapFileInitializeFuture<B>,
    },
    AuthTreeUpdateTailDataRange {
        tail_data_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        tail_data_allocation_blocks_end: layout::PhysicalAllocBlockIndex,
        aligned_tail_data_allocation_blocks_end: layout::PhysicalAllocBlockIndex,
        tail_data_allocation_blocks: FixedVec<FixedVec<u8, 7>, 0>,
        next_allocation_block_in_tail_data: usize,
        auth_tree_write_part_fut: Option<auth_tree::AuthTreeInitializationCursorWritePartFuture<B>>,
    },
    WriteTailData {
        write_fut: write_blocks::WriteBlocksFuture<B>,
    },
    AdvanceAuthTreeCursorToImageEndPrepare,
    AdvanceAuthTreeCursorToImageEnd {
        advance_fut: auth_tree::AuthTreeInitializationCursorAdvanceFuture<B>,
    },
    WriteHeadData {
        write_fut: write_blocks::WriteBlocksFuture<B>,
    },
    ClearJournalLogHead {
        write_fut: write_blocks::WriteBlocksFuture<B>,
    },
    RandomizeHeadDataPadding {
        write_fut: WriteRandomDataFuture<B>,
    },
    RandomizeImageRemainderPrepare,
    RandomizeImageRemainder {
        write_fut: WriteRandomDataFuture<B>,
        remaining_randomization_range: Option<layout::PhysicalAllocBlockRange>,
    },
    WriteBarrierBeforeStaticImageHeaderWritePrepare,
    WriteBarrierBeforeStaticImageHeaderWrite {
        write_barrier_fut: B::WriteBarrierFuture,
    },
    WriteStaticImageHeader {
        write_fut: write_blocks::WriteBlocksFuture<B>,
    },
    WriteSyncAfterStaticImageHeaderWrite {
        write_sync_fut: B::WriteSyncFuture,
    },
    InvalidateBackupMkFsInfoHeader {
        invalidate_backup_mkfsinfo_header_fut: InvalidateBackupMkFsInfoHeaderFuture<B>,
    },
    Finalize,
    Done,
}

impl<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev> MkFsFuture<ST, B> {
    /// Instantiate a [`MkFsFuture`].
    ///
    /// On error, the input `blkdev` and `rng` are returned directly as part of
    /// the `Err`. On success, the [`MkFsFuture`] assumes ownership of the
    /// `blkdev` and `rng` for the duration of the operation. It will get either
    /// returned back from [`poll()`](Self::poll) at completion, or will be
    /// passed onwards to the resulting [`CocoonFs`] instance as
    /// appropriate.
    ///
    /// # Arguments:
    ///
    /// * `blkdev` - The storage to create a filesystem on.
    /// * `image_layout` - The filesystem's [`CocoonFsImageLayout`].
    /// * `salt` - The filsystem salt to be stored in the static image header.
    /// * `image_size` - Optional filesystem image size to get recorded in the
    ///   mutable image header. If specified, it must not exceed the undelying
    ///   storage's size, as reported by
    ///   [`NvBlkDev::io_blocks()`](blkdev::NvBlkDev::io_blocks) on `blkdev`. If
    ///   not specified, the maximum possible value will be used.
    /// * `raw_root_key` - The filesystem's raw root key material supplied from
    ///   extern.
    /// * `enable_trimming` - Whether to enable the submission of [trim
    ///   commands](blkdev::NvBlkDev::trim) to the underlying storage for the
    ///   [`CocoonFs`] instance eventually returned from [`poll()`](Self::poll)
    ///   upon successful completion. The setting of this value also controls
    ///   whether whether unallocated storage will get initialized with random
    ///   data in the course of the filesystem formatting -- unallocated storage
    ///   will get randomized if and only if `enable_trimming` is off.
    /// * `rng` - The [random number generator](rng::RngCoreDispatchable) used
    ///   for generating IVs, as well as randomizing padding in data structures
    ///   and for initializing unallocated storage if `enable_trimming` is off.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        blkdev: B,
        image_layout: &CocoonFsImageLayout,
        salt: FixedVec<u8, 4>,
        image_size: Option<layout::AllocBlockCount>,
        raw_root_key: &[u8],
        backup_mkfsinfo_header_write_control: Option<MkFsFutureBackupMkfsInfoHeaderWriteControl>,
        enable_trimming: bool,
        mut rng: Box<dyn rng::RngCoreDispatchable + marker::Send>,
    ) -> Result<Self, (B, Box<dyn rng::RngCoreDispatchable + marker::Send>, NvFsError)> {
        let root_key = match keys::RootKey::new(
            raw_root_key,
            &salt,
            image_layout.kdf_hash_alg,
            image_layout.auth_tree_root_hmac_hash_alg,
            image_layout.auth_tree_node_hash_alg,
            image_layout.auth_tree_data_hmac_hash_alg,
            image_layout.preauth_cca_protection_hmac_hash_alg,
            &image_layout.block_cipher_alg,
        ) {
            Ok(root_key) => root_key,
            Err(e) => return Err((blkdev, rng, e)),
        };

        let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
        let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();
        let blkdev_io_block_allocation_blocks_log2 =
            blkdev_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);
        if blkdev_io_block_allocation_blocks_log2 > image_layout.io_block_allocation_blocks_log2 as u32 {
            return Err((
                blkdev,
                rng,
                NvFsError::from(CocoonFsFormatError::IoBlockSizeNotSupportedByDevice),
            ));
        }
        let allocation_block_blkdev_io_blocks_log2 =
            allocation_block_size_128b_log2.saturating_sub(blkdev_io_block_size_128b_log2);
        let blkdev_io_blocks = blkdev.io_blocks();
        let blkdev_io_blocks = blkdev_io_blocks.min(u64::MAX >> (blkdev_io_block_size_128b_log2 + 7));
        let blkdev_allocation_blocks = layout::AllocBlockCount::from(
            blkdev_io_blocks << blkdev_io_block_allocation_blocks_log2 >> allocation_block_blkdev_io_blocks_log2,
        );
        let image_size = image_size.unwrap_or(blkdev_allocation_blocks);
        let mkfs_layout = match MkFsLayout::new(image_layout, salt, image_size) {
            Ok(mkfs_layout) => mkfs_layout,
            Err(e) => return Err((blkdev, rng, e)),
        };

        if let Some(backup_mkfsinfo_header_write_control) = backup_mkfsinfo_header_write_control {
            if backup_mkfsinfo_header_write_control == MkFsFutureBackupMkfsInfoHeaderWriteControl::RetainExisting
                && mkfs_layout.image_size > blkdev_allocation_blocks
            {
                // If the backup MkFsInfoHeader is to be retained, the storage resizing
                // operation is assumed to have taken place already. In either
                // case it cannot be attempted once more, because the backup
                // MkFsInfoHeader location is determined by the storage size.
                return Err((blkdev, rng, NvFsError::IoError(NvFsIoError::RegionOutOfRange)));
            }

            // Verify that the desired image size is valid (large enough) for writing the
            // backup mkfsinfo header.
            // MkfsLayout::new() verifies that the salt length fits an u8.
            let salt_len = mkfs_layout.salt.len() as u8;
            let backup_mkfsinfo_header_location = match image_header::MkFsInfoHeader::physical_backup_location(
                salt_len,
                match backup_mkfsinfo_header_write_control {
                    MkFsFutureBackupMkfsInfoHeaderWriteControl::RetainExisting => {
                        // No attempt to resize will be made, see above.
                        blkdev_io_blocks
                    }
                    MkFsFutureBackupMkfsInfoHeaderWriteControl::Write => {
                        // An attempt to resize will be made. In either case the storage will be >=
                        // the image_size in the end.
                        u64::from(mkfs_layout.image_size) << allocation_block_blkdev_io_blocks_log2
                            >> blkdev_io_block_allocation_blocks_log2
                    }
                },
                blkdev_io_block_size_128b_log2,
                image_layout.io_block_allocation_blocks_log2 as u32,
                allocation_block_size_128b_log2,
            ) {
                Ok(backup_mkfsinfo_header_location) => backup_mkfsinfo_header_location,
                Err(e) => return Err((blkdev, rng, e)),
            };

            // Check that the storage allocated to the initial metadata structures does not
            // extend into the backup MkFsInfoHeader.
            if backup_mkfsinfo_header_location.begin() < mkfs_layout.allocated_image_allocation_blocks_end {
                return Err((blkdev, rng, NvFsError::NoSpace));
            }
        }

        let mut alloc_bitmap = match alloc_bitmap::AllocBitmap::new(
            mkfs_layout.allocated_image_allocation_blocks_end - layout::PhysicalAllocBlockIndex::from(0u64),
        ) {
            Ok(alloc_bitmap) => alloc_bitmap,
            Err(e) => return Err((blkdev, rng, e)),
        };
        if let Err(e) = alloc_bitmap.set_in_range(
            &layout::PhysicalAllocBlockRange::new(
                layout::PhysicalAllocBlockIndex::from(0u64),
                mkfs_layout.image_header_end,
            ),
            true,
        ) {
            return Err((blkdev, rng, e));
        }
        if let Err(e) = alloc_bitmap.set_in_range(
            &layout::PhysicalAllocBlockRange::from((
                mkfs_layout.inode_index_entry_leaf_node_allocation_blocks_begin,
                layout::AllocBlockCount::from(1u64 << (image_layout.index_tree_node_allocation_blocks_log2 as u32)),
            )),
            true,
        ) {
            return Err((blkdev, rng, e));
        }
        if let Err(e) = alloc_bitmap.set_in_range(&mkfs_layout.journal_log_head_extent, true) {
            return Err((blkdev, rng, e));
        }
        if let Err(e) = alloc_bitmap.set_in_range(&mkfs_layout.auth_tree_extent, true) {
            return Err((blkdev, rng, e));
        }
        if let Err(e) = alloc_bitmap.set_in_range(&mkfs_layout.alloc_bitmap_file_extent, true) {
            return Err((blkdev, rng, e));
        }
        if let Some(auth_tree_inode_extents_list_extents) = mkfs_layout.auth_tree_inode_extents_list_extents.as_ref() {
            for auth_tree_inode_extents_list_extent in auth_tree_inode_extents_list_extents.iter() {
                if let Err(e) = alloc_bitmap.set_in_range(&auth_tree_inode_extents_list_extent, true) {
                    return Err((blkdev, rng, e));
                }
            }
        }
        if let Some(alloc_bitmap_file_inode_extents_list_extents) =
            mkfs_layout.alloc_bitmap_inode_extents_list_extents.as_ref()
        {
            for alloc_bitmap_file_inode_extents_list_extent in alloc_bitmap_file_inode_extents_list_extents.iter() {
                if let Err(e) = alloc_bitmap.set_in_range(&alloc_bitmap_file_inode_extents_list_extent, true) {
                    return Err((blkdev, rng, e));
                }
            }
        }

        let inode_index_entry_leaf_node_block_ptr = match extent_ptr::EncodedBlockPtr::encode(Some(
            mkfs_layout.inode_index_entry_leaf_node_allocation_blocks_begin,
        )) {
            Ok(inode_index_entry_leaf_node_block_ptr) => inode_index_entry_leaf_node_block_ptr,
            Err(e) => return Err((blkdev, rng, e)),
        };
        let mut auth_tree_extents = extents::PhysicalExtents::new();
        if let Err(e) = auth_tree_extents.push_extent(&mkfs_layout.auth_tree_extent, true) {
            return Err((blkdev, rng, e));
        }
        let auth_tree_extents = extents::LogicalExtents::from(auth_tree_extents);
        let mut alloc_bitmap_file_extents = extents::PhysicalExtents::new();
        if let Err(e) = alloc_bitmap_file_extents.push_extent(&mkfs_layout.alloc_bitmap_file_extent, true) {
            return Err((blkdev, rng, e));
        }
        let auth_tree_config = match auth_tree::AuthTreeConfig::new(
            &root_key,
            &mkfs_layout.image_layout,
            &inode_index_entry_leaf_node_block_ptr,
            mkfs_layout.image_size,
            auth_tree_extents,
            &alloc_bitmap_file_extents,
        ) {
            Ok(auth_tree_config) => auth_tree_config,
            Err(e) => return Err((blkdev, rng, e)),
        };
        let auth_tree_initialization_cursor = match auth_tree::AuthTreeInitializationCursor::new(
            &auth_tree_config,
            mkfs_layout.image_header_end,
            mkfs_layout.image_size,
        ) {
            Ok(auth_tree_initialization_cursor) => auth_tree_initialization_cursor,
            Err(e) => return Err((blkdev, rng, e)),
        };

        let mut keys_cache = match keys::KeyCache::new() {
            Ok(keys_cache) => keys_cache,
            Err(e) => return Err((blkdev, rng, e)),
        };

        let auth_tree_inode_entry_extent_ptr = match match mkfs_layout.auth_tree_inode_extents_list_extents.as_ref() {
            Some(auth_tree_inode_extents_list_extents) => extent_ptr::EncodedExtentPtr::encode(
                Some(&auth_tree_inode_extents_list_extents.get_extent_range(0)),
                true,
            ),
            None => extent_ptr::EncodedExtentPtr::encode(Some(&mkfs_layout.auth_tree_extent), false),
        } {
            Ok(auth_tree_inode_entry_extent_ptr) => auth_tree_inode_entry_extent_ptr,
            Err(e) => return Err((blkdev, rng, e)),
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
                Err(e) => return Err((blkdev, rng, e)),
            };
        let (inode_index, encrypted_inode_index_entry_leaf_node) = match inode_index::InodeIndex::initialize(
            mkfs_layout.inode_index_entry_leaf_node_allocation_blocks_begin,
            auth_tree_inode_entry_extent_ptr,
            alloc_bitmap_inode_entry_extent_ptr,
            image_layout,
            &root_key,
            &mut keys::KeyCacheRef::MutRef { cache: &mut keys_cache },
            &mut *rng,
        ) {
            Ok((inode_index, encrypted_inode_index_entry_leaf_node)) => {
                (inode_index, encrypted_inode_index_entry_leaf_node)
            }
            Err(e) => return Err((blkdev, rng, e)),
        };

        Ok(Self {
            fs_init_data: Some(MkFsFutureFsInitData {
                blkdev,
                rng,
                mkfs_layout,
                root_key,
                alloc_bitmap,
                auth_tree_config,
                keys_cache,
                inode_index,
                enable_trimming,
            }),
            backup_mkfsinfo_header_write_control,
            auth_tree_initialization_cursor: Some(auth_tree_initialization_cursor),
            encrypted_inode_index_entry_leaf_node,
            alloc_bitmap_file: None,
            root_hmac_digest: FixedVec::new_empty(),
            auth_tree_node_cache: None,
            first_static_image_header_blkdev_io_block: FixedVec::new_empty(),
            #[cfg(test)]
            test_fail_write_static_image_header: false,
            fut_state: MkFsFutureState::Init,
        })
    }
}
impl<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev> future::Future for MkFsFuture<ST, B>
where
    <ST as sync_types::SyncTypes>::RwLock<inode_index::InodeIndexTreeNodeCache>: marker::Unpin,
{
    /// Output type of [`poll()`](Self::poll).
    ///
    /// A two-level [`Result`] is returned from the
    /// [`Future::poll()`](future::Future::poll):
    ///
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering an internal error and the input
    ///   [`NvBlkDev`](blkdev::NvBlkDev) and  [random number
    ///   generator](rng::RngCoreDispatchable) are lost.
    /// * `Ok((rng, ...))` - Otherwise the outer level [`Result`] is set to
    ///   [`Ok`] and a pair of the input [random number
    ///   generator](rng::RngCoreDispatchable), `rng`, and the operation result
    ///   will get returned within:
    ///   * `Ok((rng, Err((blkdev, e))))` - In case of an error, a pair of the
    ///     [`NvBlkDev`](blkdev::NvBlkDev) instance `blkdev` and the error
    ///     reason `e` is returned in an [`Err`].
    ///   * `Ok((rng, Ok(fs_instance)))` - Otherwise an opened [`CocoonFs`]
    ///     instance `fs_instance` associated with the filesystem just created
    ///     is returned in an [`Ok`].
    type Output = Result<
        (
            Box<dyn rng::RngCoreDispatchable + marker::Send>,
            Result<CocoonFsSyncRcPtrType<ST, B>, (B, NvFsError)>,
        ),
        NvFsError,
    >;

    fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        let fs_init_data = match this.fs_init_data.as_mut() {
            Some(fs_init_data) => fs_init_data,
            None => {
                this.fut_state = MkFsFutureState::Done;
                return task::Poll::Ready(Err(nvfs_err_internal!()));
            }
        };

        let e = 'outer: loop {
            match &mut this.fut_state {
                MkFsFutureState::Init => {
                    let image_layout = &fs_init_data.mkfs_layout.image_layout;
                    let blkdev = &fs_init_data.blkdev;
                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                    let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();
                    let blkdev_io_block_allocation_blocks_log2 =
                        blkdev_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);
                    let allocation_block_blkdev_io_blocks_log2 =
                        allocation_block_size_128b_log2.saturating_sub(blkdev_io_block_size_128b_log2);
                    let blkdev_io_blocks = blkdev.io_blocks();
                    let blkdev_io_blocks = blkdev_io_blocks.min(u64::MAX >> (blkdev_io_block_size_128b_log2 + 7));
                    let blkdev_allocation_blocks = layout::AllocBlockCount::from(
                        blkdev_io_blocks << blkdev_io_block_allocation_blocks_log2
                            >> allocation_block_blkdev_io_blocks_log2,
                    );

                    if this.backup_mkfsinfo_header_write_control
                        == Some(MkFsFutureBackupMkfsInfoHeaderWriteControl::RetainExisting)
                    {
                        // It's been checked from Self::new() that the storage size is >= the desired
                        // image size.
                        debug_assert!(blkdev_allocation_blocks >= fs_init_data.mkfs_layout.image_size);
                        this.fut_state = MkFsFutureState::PrepareAdvanceAuthTreeCursorToInitPos;
                        continue;
                    }

                    if fs_init_data.mkfs_layout.image_size != blkdev_allocation_blocks {
                        match blkdev.resize(
                            u64::from(fs_init_data.mkfs_layout.image_size) << allocation_block_blkdev_io_blocks_log2
                                >> blkdev_io_block_allocation_blocks_log2,
                        ) {
                            Ok(resize_fut) => {
                                this.fut_state = MkFsFutureState::ResizeBlkDev { resize_fut };
                                continue;
                            }
                            Err(e) => {
                                // Only consider failures to shrink as fatal.
                                if fs_init_data.mkfs_layout.image_size > blkdev_allocation_blocks {
                                    break NvFsError::from(match e {
                                        NvBlkDevIoError::OperationNotSupported => NvBlkDevIoError::IoBlockOutOfRange,
                                        _ => e,
                                    });
                                }
                            }
                        }
                    }

                    match this.backup_mkfsinfo_header_write_control {
                        Some(MkFsFutureBackupMkfsInfoHeaderWriteControl::RetainExisting) => {
                            // Handled above, so is unreachable, but for the sake of
                            // completeness, handle it here as well
                            this.fut_state = MkFsFutureState::PrepareAdvanceAuthTreeCursorToInitPos;
                        }
                        Some(MkFsFutureBackupMkfsInfoHeaderWriteControl::Write) => {
                            this.fut_state = MkFsFutureState::WriteBackupMkFsInfoHeader {
                                write_backup_mkfsinfo_header_fut: WriteMkFsInfoHeaderFuture::new(true),
                            };
                        }
                        None => {
                            this.fut_state = MkFsFutureState::PrepareAdvanceAuthTreeCursorToInitPos;
                        }
                    }
                }
                MkFsFutureState::ResizeBlkDev { resize_fut } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(resize_fut), &fs_init_data.blkdev, cx) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => {
                            // Only consider failures to shrink as fatal.
                            let image_layout = &fs_init_data.mkfs_layout.image_layout;
                            let blkdev = &fs_init_data.blkdev;
                            let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                            let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();
                            let blkdev_io_block_allocation_blocks_log2 =
                                blkdev_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);
                            let allocation_block_blkdev_io_blocks_log2 =
                                allocation_block_size_128b_log2.saturating_sub(blkdev_io_block_size_128b_log2);
                            let blkdev_io_blocks = blkdev.io_blocks();
                            let blkdev_io_blocks =
                                blkdev_io_blocks.min(u64::MAX >> (blkdev_io_block_size_128b_log2 + 7));
                            let blkdev_allocation_blocks = layout::AllocBlockCount::from(
                                blkdev_io_blocks << blkdev_io_block_allocation_blocks_log2
                                    >> allocation_block_blkdev_io_blocks_log2,
                            );
                            if blkdev_allocation_blocks < fs_init_data.mkfs_layout.image_size {
                                break NvFsError::from(match e {
                                    NvBlkDevIoError::OperationNotSupported => NvBlkDevIoError::IoBlockOutOfRange,
                                    _ => e,
                                });
                            }
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    }

                    match this.backup_mkfsinfo_header_write_control {
                        Some(MkFsFutureBackupMkfsInfoHeaderWriteControl::RetainExisting) => {
                            // If there's already a backup MkFsInfoHeader to retain, a storage resizing
                            // operation wouldn't have been attempted in the first place.
                            break nvfs_err_internal!();
                        }
                        Some(MkFsFutureBackupMkfsInfoHeaderWriteControl::Write) => {
                            this.fut_state = MkFsFutureState::WriteBackupMkFsInfoHeader {
                                write_backup_mkfsinfo_header_fut: WriteMkFsInfoHeaderFuture::new(true),
                            };
                        }
                        None => {
                            this.fut_state = MkFsFutureState::PrepareAdvanceAuthTreeCursorToInitPos;
                        }
                    }
                }
                MkFsFutureState::WriteBackupMkFsInfoHeader {
                    write_backup_mkfsinfo_header_fut,
                } => {
                    let blkdev = &fs_init_data.blkdev;
                    match WriteMkFsInfoHeaderFuture::poll(
                        pin::Pin::new(write_backup_mkfsinfo_header_fut),
                        blkdev,
                        &fs_init_data.mkfs_layout.image_layout,
                        &fs_init_data.mkfs_layout.salt,
                        fs_init_data.mkfs_layout.image_size,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => break e,
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let write_barrier_fut = match blkdev.write_barrier() {
                        Ok(write_barrier_fut) => write_barrier_fut,
                        Err(e) => break NvFsError::from(e),
                    };
                    this.fut_state = MkFsFutureState::WriteBarrierAfterBackupMkFsInfoHeaderWrite { write_barrier_fut };
                }
                MkFsFutureState::WriteBarrierAfterBackupMkFsInfoHeaderWrite { write_barrier_fut } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(write_barrier_fut), &fs_init_data.blkdev, cx) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => break NvFsError::from(e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    this.fut_state = MkFsFutureState::PrepareAdvanceAuthTreeCursorToInitPos;
                }
                MkFsFutureState::PrepareAdvanceAuthTreeCursorToInitPos => {
                    // Advance the auth_tree_initialization_cursor. See MkFsLayout::new(): the inode
                    // index tree node might perhaps come first (if there's enough space), followed
                    // by Journal Log Head and the Authentication Tree, which are themselves not
                    // authenticated, and in turn followed by the Allocation Bitmap File, which
                    // is.
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
                            MkFsFutureState::AdvanceAuthTreeCursorToInodeIndexEntryLeafNode { advance_fut };
                    } else {
                        let advance_fut = match auth_tree_initialization_cursor
                            .advance_to(mkfs_layout.alloc_bitmap_file_extent.begin())
                        {
                            Ok(advance_fut) => advance_fut,
                            Err((_, e)) => break e,
                        };
                        this.fut_state = MkFsFutureState::AdvanceAuthTreeCursorToAllocBitmapFile { advance_fut };
                    }
                }
                MkFsFutureState::AdvanceAuthTreeCursorToInodeIndexEntryLeafNode { advance_fut } => {
                    let auth_tree_initialization_cursor =
                        match auth_tree::AuthTreeInitializationCursorAdvanceFuture::poll(
                            pin::Pin::new(advance_fut),
                            &fs_init_data.blkdev,
                            &fs_init_data.auth_tree_config,
                            cx,
                        ) {
                            task::Poll::Ready(Ok(auth_tree_initialization_cursor)) => auth_tree_initialization_cursor,
                            task::Poll::Ready(Err(e)) => break e,
                            task::Poll::Pending => return task::Poll::Pending,
                        };
                    this.auth_tree_initialization_cursor = Some(auth_tree_initialization_cursor);

                    this.fut_state = MkFsFutureState::AuthTreeUpdateInodeIndexEntryLeafNodeRange {
                        next_allocation_block_in_inode_index_entry_leaf_node: 0,
                        auth_tree_write_part_fut: None,
                    };
                }
                MkFsFutureState::AuthTreeUpdateInodeIndexEntryLeafNodeRange {
                    next_allocation_block_in_inode_index_entry_leaf_node,
                    auth_tree_write_part_fut,
                } => {
                    let auth_tree_initialization_cursor = 'write_auth_tree_part: loop {
                        let mut auth_tree_initialization_cursor =
                            if let Some(auth_tree_write_part_fut) = auth_tree_write_part_fut.as_mut() {
                                match auth_tree::AuthTreeInitializationCursorWritePartFuture::poll(
                                    pin::Pin::new(auth_tree_write_part_fut),
                                    &fs_init_data.blkdev,
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
                    this.fut_state = MkFsFutureState::AdvanceAuthTreeCursorToAllocBitmapFile { advance_fut };
                }
                MkFsFutureState::AdvanceAuthTreeCursorToAllocBitmapFile { advance_fut } => {
                    let auth_tree_initialization_cursor =
                        match auth_tree::AuthTreeInitializationCursorAdvanceFuture::poll(
                            pin::Pin::new(advance_fut),
                            &fs_init_data.blkdev,
                            &fs_init_data.auth_tree_config,
                            cx,
                        ) {
                            task::Poll::Ready(Ok(auth_tree_initialization_cursor)) => auth_tree_initialization_cursor,
                            task::Poll::Ready(Err(e)) => break e,
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    let mkfs_layout = &fs_init_data.mkfs_layout;
                    let initialize_alloc_bitmap_file_fut =
                        match alloc_bitmap::AllocBitmapFileInitializeFuture::<B>::new::<ST>(
                            &mkfs_layout.alloc_bitmap_file_extent,
                            &fs_init_data.blkdev,
                            auth_tree_initialization_cursor,
                            &mkfs_layout.image_layout,
                            &fs_init_data.root_key,
                            &mut keys::KeyCacheRef::MutRef {
                                cache: &mut fs_init_data.keys_cache,
                            },
                        ) {
                            Ok(initialize_alloc_bitmap_file_fut) => initialize_alloc_bitmap_file_fut,
                            Err((_, e)) => break e,
                        };
                    this.fut_state = MkFsFutureState::InitializeAllocBitmapFile {
                        initialize_fut: initialize_alloc_bitmap_file_fut,
                    };
                }
                MkFsFutureState::InitializeAllocBitmapFile { initialize_fut } => {
                    let mkfs_layout = &fs_init_data.mkfs_layout;
                    let (
                        alloc_bitmap_file,
                        alloc_bitmap_partial_blkdev_io_block_file_blocks,
                        auth_tree_initialization_cursor,
                    ) = match alloc_bitmap::AllocBitmapFileInitializeFuture::poll(
                        pin::Pin::new(initialize_fut),
                        &fs_init_data.blkdev,
                        &fs_init_data.alloc_bitmap,
                        &mkfs_layout.image_layout,
                        &fs_init_data.auth_tree_config,
                        &mut *fs_init_data.rng,
                        cx,
                    ) {
                        task::Poll::Ready(Ok((
                            alloc_bitmap_file,
                            alloc_bitmap_file_partial_blkdev_io_block_data,
                            auth_tree_initialization_cursor,
                        ))) => (
                            alloc_bitmap_file,
                            alloc_bitmap_file_partial_blkdev_io_block_data,
                            auth_tree_initialization_cursor,
                        ),
                        task::Poll::Ready(Err(e)) => break e,
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    this.alloc_bitmap_file = Some(alloc_bitmap_file);
                    this.auth_tree_initialization_cursor = Some(auth_tree_initialization_cursor);

                    let image_layout = &mkfs_layout.image_layout;
                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                    let blkdev_io_block_size_128b_log2 = fs_init_data.blkdev.io_block_size_128b_log2();
                    let blkdev_io_block_allocation_blocks_log2 =
                        blkdev_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);

                    let tail_data_allocation_blocks_begin = mkfs_layout
                        .alloc_bitmap_file_extent
                        .end()
                        .align_down(blkdev_io_block_allocation_blocks_log2);
                    // The Allocation Bitmap File's beginning is even aligned to the IO Block size.
                    debug_assert!(tail_data_allocation_blocks_begin >= mkfs_layout.alloc_bitmap_file_extent.begin());
                    // The not yet written Allocation Bitmap File data equals exactly to the partial
                    // Device IO block size in length.
                    debug_assert_eq!(
                        (u64::from(mkfs_layout.alloc_bitmap_file_extent.end() - tail_data_allocation_blocks_begin)
                            >> (image_layout.index_tree_node_allocation_blocks_log2 as u32))
                            as usize,
                        alloc_bitmap_partial_blkdev_io_block_file_blocks.len(),
                    );
                    // The remaining tail data consists of
                    // - the partial Device IO block remainder from the Allocation Bitmap File,
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
                        this.fut_state = MkFsFutureState::AdvanceAuthTreeCursorToImageEndPrepare;
                        continue;
                    }
                    let tail_data_allocation_blocks_count = match usize::try_from(u64::from(
                        aligned_tail_data_allocation_blocks_end - tail_data_allocation_blocks_begin,
                    )) {
                        Ok(tail_data_allocation_blocks_count) => tail_data_allocation_blocks_count,
                        Err(_) => break NvFsError::DimensionsNotSupported,
                    };
                    let mut tail_data_allocation_blocks =
                        match FixedVec::new_with_default(tail_data_allocation_blocks_count) {
                            Ok(tail_data_allocation_blocks) => tail_data_allocation_blocks,
                            Err(e) => break NvFsError::from(e),
                        };
                    let allocation_block_size = 1usize << (allocation_block_size_128b_log2 + 7);
                    for tail_data_allocation_block in tail_data_allocation_blocks.iter_mut() {
                        *tail_data_allocation_block = match FixedVec::new_with_default(allocation_block_size) {
                            Ok(tail_data_allocation_block) => tail_data_allocation_block,
                            Err(e) => break 'outer NvFsError::from(e),
                        };
                    }

                    let mut next_tail_data_allocation_block_index = alloc_bitmap_partial_blkdev_io_block_file_blocks
                        .len()
                        << (image_layout.allocation_bitmap_file_block_allocation_blocks_log2 as u32);
                    if let Err(e) = io_slices::BuffersSliceIoSlicesMutIter::new(
                        &mut tail_data_allocation_blocks[..next_tail_data_allocation_block_index],
                    )
                    .copy_from_iter_exhaustive(io_slices::BuffersSliceIoSlicesIter::new(
                        &alloc_bitmap_partial_blkdev_io_block_file_blocks,
                    )) {
                        match e {
                            io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                                io_slices::IoSlicesError::BuffersExhausted => break nvfs_err_internal!(),
                            },
                            io_slices::IoSlicesIterError::BackendIteratorError(e) => match e {},
                        }
                    }
                    drop(alloc_bitmap_partial_blkdev_io_block_file_blocks);

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
                        this.encrypted_inode_index_entry_leaf_node = FixedVec::new_empty();
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
                            &fs_init_data.root_key,
                            &mut keys::KeyCacheRef::MutRef {
                                cache: &mut fs_init_data.keys_cache,
                            },
                            &mut *fs_init_data.rng,
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
                            &fs_init_data.root_key,
                            &mut keys::KeyCacheRef::MutRef {
                                cache: &mut fs_init_data.keys_cache,
                            },
                            &mut *fs_init_data.rng,
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
                        &mut *fs_init_data.rng,
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

                    this.fut_state = MkFsFutureState::AuthTreeUpdateTailDataRange {
                        tail_data_allocation_blocks_begin,
                        tail_data_allocation_blocks_end,
                        aligned_tail_data_allocation_blocks_end,
                        tail_data_allocation_blocks,
                        next_allocation_block_in_tail_data: 0,
                        auth_tree_write_part_fut: None,
                    };
                }
                MkFsFutureState::AuthTreeUpdateTailDataRange {
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
                                    &fs_init_data.blkdev,
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
                    // A Device IO block is <= the FS IO Block in size, as has been verified
                    // Self::new(), hence the cast to u8 can't overflow.
                    let blkdev_io_block_allocation_blocks_log2 = fs_init_data
                        .blkdev
                        .io_block_size_128b_log2()
                        .saturating_sub(allocation_block_size_128b_log2)
                        as u8;
                    let write_fut = write_blocks::WriteBlocksFuture::new(
                        &layout::PhysicalAllocBlockRange::new(
                            *tail_data_allocation_blocks_begin,
                            *aligned_tail_data_allocation_blocks_end,
                        ),
                        mem::take(tail_data_allocation_blocks),
                        0,
                        blkdev_io_block_allocation_blocks_log2,
                        image_layout.allocation_block_size_128b_log2,
                    );
                    this.fut_state = MkFsFutureState::WriteTailData { write_fut };
                }
                MkFsFutureState::WriteTailData { write_fut } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(write_fut), &fs_init_data.blkdev, cx) {
                        task::Poll::Ready(Ok((_, Ok(())))) => (),
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => break e,
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    this.fut_state = MkFsFutureState::AdvanceAuthTreeCursorToImageEndPrepare;
                }
                MkFsFutureState::AdvanceAuthTreeCursorToImageEndPrepare => {
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
                    this.fut_state = MkFsFutureState::AdvanceAuthTreeCursorToImageEnd { advance_fut };
                }
                MkFsFutureState::AdvanceAuthTreeCursorToImageEnd { advance_fut } => {
                    let auth_tree_initialization_cursor =
                        match auth_tree::AuthTreeInitializationCursorAdvanceFuture::poll(
                            pin::Pin::new(advance_fut),
                            &fs_init_data.blkdev,
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
                    let mut root_hmac_digest = match FixedVec::new_with_default(root_hmac_digest_len) {
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
                    debug_assert!(
                        u64::from(mutable_image_header_allocation_blocks_range.begin())
                            .is_aligned_pow2(io_block_allocation_blocks_log2)
                    );
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

                    let blkdev_io_block_allocation_blocks_log2 = fs_init_data
                        .blkdev
                        .io_block_size_128b_log2()
                        .saturating_sub(allocation_block_size_128b_log2);
                    // It is already known that the Device IO Block size is <= the FS' IO Block
                    // size.
                    debug_assert!(blkdev_io_block_allocation_blocks_log2 <= io_block_allocation_blocks_log2);
                    let blkdev_io_block_size =
                        1usize << (blkdev_io_block_allocation_blocks_log2 + allocation_block_size_128b_log2 + 7);

                    // The first Device IO BLock of the image header will get written separately at
                    // the very end, after a write barrier.  Make the first Device IO Block buffer a
                    // trivial FixedVec of a an u8 FixedVec, so that WriteBlocksFuture can be used
                    // to write that out as well.
                    let mut first_static_image_header_blkdev_io_block = match FixedVec::new_with_default(1) {
                        Ok(first_static_image_header_blkdev_io_block) => first_static_image_header_blkdev_io_block,
                        Err(e) => break NvFsError::from(e),
                    };
                    first_static_image_header_blkdev_io_block[0] =
                        match FixedVec::new_with_default(blkdev_io_block_size) {
                            Ok(first_static_image_header_blkdev_io_block) => first_static_image_header_blkdev_io_block,
                            Err(e) => break NvFsError::from(e),
                        };

                    let first_static_image_header_blkdev_io_block_allocation_blocks_end =
                        layout::PhysicalAllocBlockIndex::from(1u64 << blkdev_io_block_allocation_blocks_log2);
                    let head_tail_data_allocation_blocks_count = aligned_head_data_allocation_blocks_end
                        - first_static_image_header_blkdev_io_block_allocation_blocks_end;
                    let head_tail_data_blkdev_io_blocks_count = match usize::try_from(
                        u64::from(head_tail_data_allocation_blocks_count) >> blkdev_io_block_allocation_blocks_log2,
                    ) {
                        Ok(head_tail_data_blkdev_io_blocks_count) => head_tail_data_blkdev_io_blocks_count,
                        Err(_) => break NvFsError::DimensionsNotSupported,
                    };
                    let mut head_tail_data_blkdev_io_blocks =
                        match FixedVec::new_with_default(head_tail_data_blkdev_io_blocks_count) {
                            Ok(head_tail_data_blkdev_io_blocks) => head_tail_data_blkdev_io_blocks,
                            Err(e) => break NvFsError::from(e),
                        };
                    for head_tail_data_blkdev_io_block in head_tail_data_blkdev_io_blocks.iter_mut() {
                        *head_tail_data_blkdev_io_block = match FixedVec::new_with_default(blkdev_io_block_size) {
                            Ok(head_tail_data_blkdev_io_block) => head_tail_data_blkdev_io_block,
                            Err(e) => break 'outer NvFsError::from(e),
                        };
                    }
                    // Encode the static image header.
                    if let Err(e) = image_header::StaticImageHeader::encode(
                        io_slices::SingletonIoSliceMut::new(&mut first_static_image_header_blkdev_io_block[0])
                            .chain(io_slices::BuffersSliceIoSlicesMutIter::new(
                                &mut head_tail_data_blkdev_io_blocks[..(u64::from(
                                    padded_static_image_header_end
                                        - first_static_image_header_blkdev_io_block_allocation_blocks_end,
                                ) >> blkdev_io_block_allocation_blocks_log2)
                                    as usize],
                            ))
                            .map_infallible_err(),
                        image_layout,
                        &mkfs_layout.salt,
                    ) {
                        break e;
                    }
                    // Save away for eventually writing it out at the end.
                    this.first_static_image_header_blkdev_io_block = first_static_image_header_blkdev_io_block;

                    // And encode the rest in what follows.
                    let mut head_tail_data_blkdev_io_blocks_io_slices_iter =
                        io_slices::BuffersSliceIoSlicesMutIter::new(
                            &mut head_tail_data_blkdev_io_blocks[(u64::from(
                                padded_static_image_header_end
                                    - first_static_image_header_blkdev_io_block_allocation_blocks_end,
                            ) >> blkdev_io_block_allocation_blocks_log2)
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
                        head_tail_data_blkdev_io_blocks_io_slices_iter
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
                        &mut head_tail_data_blkdev_io_blocks_io_slices_iter,
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
                        if let Err(e) = head_tail_data_blkdev_io_blocks_io_slices_iter
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
                        this.encrypted_inode_index_entry_leaf_node = FixedVec::new_empty();
                    }

                    // And fill the last IO Block's remainder, if any, with random data.
                    if let Err(e) = rng::rng_dyn_dispatch_generate(
                        &mut *fs_init_data.rng,
                        head_tail_data_blkdev_io_blocks_io_slices_iter.map_infallible_err(),
                        None,
                    )
                    .map_err(|e| NvFsError::from(CryptoError::from(e)))
                    {
                        break e;
                    }

                    // And issue the write.
                    // A Device IO block is <= the FS IO Block in size, as has been verified
                    // Self::new(), hence the cast to u8 can't overflow.
                    let blkdev_io_block_allocation_blocks_log2 = blkdev_io_block_allocation_blocks_log2 as u8;
                    let write_fut = write_blocks::WriteBlocksFuture::new(
                        &layout::PhysicalAllocBlockRange::new(
                            first_static_image_header_blkdev_io_block_allocation_blocks_end,
                            aligned_head_data_allocation_blocks_end,
                        ),
                        head_tail_data_blkdev_io_blocks,
                        blkdev_io_block_allocation_blocks_log2,
                        blkdev_io_block_allocation_blocks_log2,
                        image_layout.allocation_block_size_128b_log2,
                    );
                    this.fut_state = MkFsFutureState::WriteHeadData { write_fut };
                }
                MkFsFutureState::WriteHeadData { write_fut } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(write_fut), &fs_init_data.blkdev, cx) {
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
                        match FixedVec::new_with_default(journal_log_head_io_blocks_count) {
                            Ok(journal_log_head_io_blocks) => journal_log_head_io_blocks,
                            Err(e) => break NvFsError::from(e),
                        };
                    let io_block_size =
                        1usize << (io_block_allocation_blocks_log2 + allocation_block_size_128b_log2 + 7);
                    for journal_log_head_io_block in journal_log_head_io_blocks.iter_mut() {
                        *journal_log_head_io_block = match FixedVec::new_with_default(io_block_size) {
                            Ok(journal_log_head_io_block) => journal_log_head_io_block,
                            Err(e) => break 'outer NvFsError::from(e),
                        };
                    }
                    // A Device IO block is <= the FS IO Block in size, as has been verified
                    // Self::new(), hence the cast to u8 can't overflow.
                    let blkdev_io_block_allocation_blocks_log2 = fs_init_data
                        .blkdev
                        .io_block_size_128b_log2()
                        .saturating_sub(allocation_block_size_128b_log2)
                        as u8;
                    let write_fut = write_blocks::WriteBlocksFuture::new(
                        &mkfs_layout.journal_log_head_extent,
                        journal_log_head_io_blocks,
                        image_layout.io_block_allocation_blocks_log2,
                        blkdev_io_block_allocation_blocks_log2,
                        image_layout.allocation_block_size_128b_log2,
                    );
                    this.fut_state = MkFsFutureState::ClearJournalLogHead { write_fut };
                }
                MkFsFutureState::ClearJournalLogHead { write_fut } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(write_fut), &fs_init_data.blkdev, cx) {
                        task::Poll::Ready(Ok((_, Ok(())))) => (),
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => break e,
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    if fs_init_data.enable_trimming {
                        // No data randomization of fully unallocated IO blocks. Proceed directly to
                        // the final static header write.
                        this.fut_state = MkFsFutureState::WriteBarrierBeforeStaticImageHeaderWritePrepare;
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
                            this.fut_state = MkFsFutureState::RandomizeImageRemainderPrepare;
                        } else {
                            let write_fut = match WriteRandomDataFuture::new(
                                &layout::PhysicalAllocBlockRange::new(
                                    head_data_padding_allocation_blocks_begin,
                                    head_data_padding_allocation_blocks_end,
                                ),
                                image_layout,
                                &fs_init_data.blkdev,
                            ) {
                                Ok(write_fut) => write_fut,
                                Err(e) => break e,
                            };
                            this.fut_state = MkFsFutureState::RandomizeHeadDataPadding { write_fut };
                        }
                    }
                }
                MkFsFutureState::RandomizeHeadDataPadding { write_fut } => {
                    match WriteRandomDataFuture::poll(
                        pin::Pin::new(write_fut),
                        &fs_init_data.blkdev,
                        &mut *fs_init_data.rng,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => break e,
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    this.fut_state = MkFsFutureState::RandomizeImageRemainderPrepare;
                }
                MkFsFutureState::RandomizeImageRemainderPrepare => {
                    let mkfs_layout = &fs_init_data.mkfs_layout;
                    let image_layout = &mkfs_layout.image_layout;
                    let tail_data_allocation_blocks_end = mkfs_layout.allocated_image_allocation_blocks_end;
                    let io_block_allocation_blocks_log2 = image_layout.io_block_allocation_blocks_log2 as u32;
                    let aligned_tail_data_allocation_blocks_end =
                        match tail_data_allocation_blocks_end.align_up(io_block_allocation_blocks_log2) {
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
                    // MkFsLayout::new() aligns the image_size to the IO Block size.
                    debug_assert!(
                        u64::from(image_remainder_allocation_blocks_end)
                            .is_aligned_pow2(io_block_allocation_blocks_log2)
                    );
                    // If there's a backup MkFsInfoHeader, then be careful not to overwrite it.
                    // Split the image remainder to randomize in (up to two) regions then: one
                    // before it and/or another one subsequent to it.
                    let randomization_ranges = if this.backup_mkfsinfo_header_write_control.is_some() {
                        // MkfsLayout::new() verifies that the salt length fits an u8.
                        let salt_len = mkfs_layout.salt.len() as u8;
                        let blkdev = &fs_init_data.blkdev;
                        let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();
                        let blkdev_io_blocks = blkdev.io_blocks();
                        let blkdev_io_blocks = blkdev_io_blocks.min(u64::MAX >> (blkdev_io_block_size_128b_log2 + 7));
                        let backup_mkfsinfo_header_location =
                            match image_header::MkFsInfoHeader::physical_backup_location(
                                salt_len,
                                blkdev_io_blocks,
                                blkdev_io_block_size_128b_log2,
                                io_block_allocation_blocks_log2,
                                image_layout.allocation_block_size_128b_log2 as u32,
                            ) {
                                Ok(backup_mkfsinfo_header_location) => backup_mkfsinfo_header_location,
                                Err(e) => break e,
                            };
                        debug_assert!(
                            backup_mkfsinfo_header_location.begin() >= image_remainder_allocation_blocks_begin
                        );
                        // The WriteRandomDataFuture needs an IO Block aligned region, so align the
                        // region to skip over.
                        let backup_mkfsinfo_header_location =
                            if backup_mkfsinfo_header_location.begin() < image_remainder_allocation_blocks_end {
                                // MkFsInfoHeader::physical_backup_location() verifies that the
                                // backup location's beginning is aligned to the IO Block size.
                                debug_assert!(
                                    u64::from(backup_mkfsinfo_header_location.begin())
                                        .is_aligned_pow2(io_block_allocation_blocks_log2)
                                );
                                backup_mkfsinfo_header_location
                                    .align(io_block_allocation_blocks_log2)
                                    .unwrap_or(layout::PhysicalAllocBlockRange::new(
                                        backup_mkfsinfo_header_location.begin(),
                                        image_remainder_allocation_blocks_end,
                                    ))
                            } else {
                                backup_mkfsinfo_header_location
                            };

                        if backup_mkfsinfo_header_location.end() >= image_remainder_allocation_blocks_end {
                            let randomization_range_end =
                                image_remainder_allocation_blocks_end.min(backup_mkfsinfo_header_location.begin());
                            if image_remainder_allocation_blocks_begin != randomization_range_end {
                                Some((
                                    layout::PhysicalAllocBlockRange::new(
                                        image_remainder_allocation_blocks_begin,
                                        randomization_range_end,
                                    ),
                                    None,
                                ))
                            } else {
                                None
                            }
                        } else if backup_mkfsinfo_header_location.begin() == image_remainder_allocation_blocks_begin {
                            debug_assert!(
                                backup_mkfsinfo_header_location.end() < image_remainder_allocation_blocks_end
                            );
                            Some((
                                layout::PhysicalAllocBlockRange::new(
                                    backup_mkfsinfo_header_location.end(),
                                    image_remainder_allocation_blocks_end,
                                ),
                                None,
                            ))
                        } else {
                            debug_assert!(
                                backup_mkfsinfo_header_location.begin() > image_remainder_allocation_blocks_begin
                            );
                            debug_assert!(
                                backup_mkfsinfo_header_location.end() < image_remainder_allocation_blocks_end
                            );
                            Some((
                                layout::PhysicalAllocBlockRange::new(
                                    image_remainder_allocation_blocks_begin,
                                    backup_mkfsinfo_header_location.begin(),
                                ),
                                Some(layout::PhysicalAllocBlockRange::new(
                                    backup_mkfsinfo_header_location.end(),
                                    image_remainder_allocation_blocks_end,
                                )),
                            ))
                        }
                    } else if image_remainder_allocation_blocks_begin != image_remainder_allocation_blocks_end {
                        Some((
                            layout::PhysicalAllocBlockRange::new(
                                image_remainder_allocation_blocks_begin,
                                image_remainder_allocation_blocks_end,
                            ),
                            None,
                        ))
                    } else {
                        None
                    };

                    if let Some((first_randomization_range, remaining_randomization_range)) = randomization_ranges {
                        let write_fut = match WriteRandomDataFuture::new(
                            &first_randomization_range,
                            image_layout,
                            &fs_init_data.blkdev,
                        ) {
                            Ok(write_fut) => write_fut,
                            Err(e) => break e,
                        };
                        this.fut_state = MkFsFutureState::RandomizeImageRemainder {
                            write_fut,
                            remaining_randomization_range,
                        };
                    } else {
                        this.fut_state = MkFsFutureState::WriteBarrierBeforeStaticImageHeaderWritePrepare;
                    }
                }
                MkFsFutureState::RandomizeImageRemainder {
                    write_fut,
                    remaining_randomization_range,
                } => {
                    match WriteRandomDataFuture::poll(
                        pin::Pin::new(write_fut),
                        &fs_init_data.blkdev,
                        &mut *fs_init_data.rng,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => break e,
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    if let Some(remaining_randomization_range) = remaining_randomization_range.take() {
                        *write_fut = match WriteRandomDataFuture::new(
                            &remaining_randomization_range,
                            &fs_init_data.mkfs_layout.image_layout,
                            &fs_init_data.blkdev,
                        ) {
                            Ok(write_fut) => write_fut,
                            Err(e) => break e,
                        };
                    } else {
                        this.fut_state = MkFsFutureState::WriteBarrierBeforeStaticImageHeaderWritePrepare;
                    }
                }
                MkFsFutureState::WriteBarrierBeforeStaticImageHeaderWritePrepare => {
                    let write_barrier_fut = match fs_init_data.blkdev.write_barrier() {
                        Ok(write_barrier_fut) => write_barrier_fut,
                        Err(e) => break NvFsError::from(e),
                    };
                    this.fut_state = MkFsFutureState::WriteBarrierBeforeStaticImageHeaderWrite { write_barrier_fut };
                }
                MkFsFutureState::WriteBarrierBeforeStaticImageHeaderWrite { write_barrier_fut } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(write_barrier_fut), &fs_init_data.blkdev, cx) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => break NvFsError::from(e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let mkfs_layout = &fs_init_data.mkfs_layout;
                    let image_layout = &mkfs_layout.image_layout;
                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2;
                    // A Device IO block is <= the FS IO Block in size, as has been verified
                    // Self::new(), hence the cast to u8 can't overflow.
                    let blkdev_io_block_allocation_blocks_log2 = fs_init_data
                        .blkdev
                        .io_block_size_128b_log2()
                        .saturating_sub(allocation_block_size_128b_log2 as u32)
                        as u8;

                    // If the static image header write is supposed to fail for testing,
                    // mangle its contents so that the checksums will fail to validate it.
                    #[cfg(test)]
                    if this.test_fail_write_static_image_header {
                        // The byte right after the version field.
                        this.first_static_image_header_blkdev_io_block[0][10] ^= 0xffu8;
                    }

                    let first_static_image_header_blkdev_io_block_allocation_blocks_end =
                        layout::PhysicalAllocBlockIndex::from(1u64 << (blkdev_io_block_allocation_blocks_log2 as u32));
                    let write_fut = write_blocks::WriteBlocksFuture::new(
                        &layout::PhysicalAllocBlockRange::new(
                            layout::PhysicalAllocBlockIndex::from(0u64),
                            first_static_image_header_blkdev_io_block_allocation_blocks_end,
                        ),
                        mem::take(&mut this.first_static_image_header_blkdev_io_block),
                        blkdev_io_block_allocation_blocks_log2,
                        blkdev_io_block_allocation_blocks_log2,
                        allocation_block_size_128b_log2,
                    );
                    this.fut_state = MkFsFutureState::WriteStaticImageHeader { write_fut };
                }
                MkFsFutureState::WriteStaticImageHeader { write_fut } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(write_fut), &fs_init_data.blkdev, cx) {
                        task::Poll::Ready(Ok((_, Ok(())))) => (),
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => break e,
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    #[cfg(test)]
                    if this.test_fail_write_static_image_header {
                        // See above, a header failing checksum validation has been written.
                        // Actually return a failure now.
                        break NvFsError::IoError(NvFsIoError::IoFailure);
                    }

                    let write_sync_fut = match fs_init_data.blkdev.write_sync() {
                        Ok(write_sync_fut) => write_sync_fut,
                        Err(e) => break NvFsError::from(e),
                    };
                    this.fut_state = MkFsFutureState::WriteSyncAfterStaticImageHeaderWrite { write_sync_fut };
                }
                MkFsFutureState::WriteSyncAfterStaticImageHeaderWrite { write_sync_fut } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(write_sync_fut), &fs_init_data.blkdev, cx) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => break NvFsError::from(e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    if this.backup_mkfsinfo_header_write_control.is_some() {
                        let invalidate_backup_mkfsinfo_header_fut = match InvalidateBackupMkFsInfoHeaderFuture::new(
                            &fs_init_data.blkdev,
                            &fs_init_data.mkfs_layout.image_layout,
                            fs_init_data.mkfs_layout.salt.len() as u8,
                            fs_init_data.mkfs_layout.image_size,
                            fs_init_data.enable_trimming,
                        ) {
                            Ok(invalidate_backup_mkfsinfo_header_fut) => invalidate_backup_mkfsinfo_header_fut,
                            Err(e) => break e,
                        };
                        this.fut_state = MkFsFutureState::InvalidateBackupMkFsInfoHeader {
                            invalidate_backup_mkfsinfo_header_fut,
                        };
                    } else {
                        this.fut_state = MkFsFutureState::Finalize;
                    }
                }
                MkFsFutureState::InvalidateBackupMkFsInfoHeader {
                    invalidate_backup_mkfsinfo_header_fut,
                } => {
                    match InvalidateBackupMkFsInfoHeaderFuture::poll(
                        pin::Pin::new(invalidate_backup_mkfsinfo_header_fut),
                        &fs_init_data.blkdev,
                        &fs_init_data.mkfs_layout.image_layout,
                        &mut *fs_init_data.rng,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => break e,
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    this.fut_state = MkFsFutureState::Finalize;
                }
                MkFsFutureState::Finalize => {
                    // And, finally, create a CocoonFs instance.
                    this.fut_state = MkFsFutureState::Done;
                    let fs_init_data = match this.fs_init_data.take() {
                        Some(fs_init_data) => fs_init_data,
                        None => break nvfs_err_internal!(),
                    };
                    let MkFsFutureFsInitData {
                        blkdev,
                        rng,
                        mkfs_layout,
                        root_key,
                        mut alloc_bitmap,
                        auth_tree_config,
                        keys_cache,
                        inode_index,
                        enable_trimming,
                    } = fs_init_data;
                    let MkFsLayout {
                        image_layout,
                        salt,
                        image_header_end,
                        image_size,
                        allocated_image_allocation_blocks_end: _,
                        inode_index_entry_leaf_node_allocation_blocks_begin,
                        journal_log_head_extent: _,
                        auth_tree_extent: _,
                        alloc_bitmap_file_extent: _,
                        auth_tree_inode_extents_list_extents: _,
                        alloc_bitmap_inode_extents_list_extents: _,
                    } = mkfs_layout;
                    let alloc_bitmap_file = match this.alloc_bitmap_file.take() {
                        Some(alloc_bitmap_file) => alloc_bitmap_file,
                        None => return task::Poll::Ready(Ok((rng, Err((blkdev, nvfs_err_internal!()))))),
                    };
                    let root_hmac_digest = mem::take(&mut this.root_hmac_digest);
                    let auth_tree_node_cache = match this.auth_tree_node_cache.take() {
                        Some(auth_tree_node_cache) => auth_tree_node_cache,
                        None => return task::Poll::Ready(Ok((rng, Err((blkdev, nvfs_err_internal!()))))),
                    };

                    let inode_index_entry_leaf_node_block_ptr = match extent_ptr::EncodedBlockPtr::encode(Some(
                        inode_index_entry_leaf_node_allocation_blocks_begin,
                    )) {
                        Ok(inode_index_entry_leaf_node_block_ptr) => inode_index_entry_leaf_node_block_ptr,
                        Err(e) => return task::Poll::Ready(Ok((rng, Err((blkdev, e))))),
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
                        return task::Poll::Ready(Ok((rng, Err((blkdev, e)))));
                    }
                    let auth_tree = auth_tree::AuthTree::<ST>::new_from_parts(
                        auth_tree_config,
                        root_hmac_digest,
                        auth_tree_node_cache,
                    );
                    let read_buffer = match read_buffer::ReadBuffer::new(&image_layout, &blkdev) {
                        Ok(read_buffer) => read_buffer,
                        Err(e) => return task::Poll::Ready(Ok((rng, Err((blkdev, e))))),
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

                    let mut blkdev = Some(blkdev);
                    let fs = match <ST::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>::try_new_with(|| {
                        let blkdev = match blkdev.take() {
                            Some(blkdev) => blkdev,
                            None => return Err(nvfs_err_internal!()),
                        };
                        Ok((CocoonFs::new(blkdev, fs_config, fs_sync_state), ()))
                    }) {
                        Ok((fs, _)) => fs,
                        Err(e) => {
                            let blkdev = match blkdev.take() {
                                Some(blkdev) => blkdev,
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
                            return task::Poll::Ready(Ok((rng, Err((blkdev, e)))));
                        }
                    };

                    // Safety: the fs is new and never moved out from again.
                    let fs = unsafe { pin::Pin::new_unchecked(fs) };
                    return task::Poll::Ready(Ok((rng, Ok(fs))));
                }
                MkFsFutureState::Done => unreachable!(),
            }
        };

        this.fut_state = MkFsFutureState::Done;
        match this.fs_init_data.take() {
            Some(MkFsFutureFsInitData { blkdev, rng, .. }) => task::Poll::Ready(Ok((rng, Err((blkdev, e))))),
            None => task::Poll::Ready(Err(e)),
        }
    }
}

/// Helper for [`MkFsFuture`] for filling unallocated blocks with random data.
struct WriteRandomDataFuture<B: blkdev::NvBlkDev> {
    extent: layout::PhysicalAllocBlockRange,
    next_allocation_block_index: layout::PhysicalAllocBlockIndex,
    allocation_block_size_128b_log2: u8,
    io_block_allocation_blocks_log2: u8,
    preferred_bulk_io_blocks_log2: u8,
    fut_state: WriteRandomDataFutureState<B>,
}

/// [`WriteRandomDataFuture`] state-machine state.
enum WriteRandomDataFutureState<B: blkdev::NvBlkDev> {
    Init,
    RandomDataBulkWritePrepare {
        bulk_io_blocks: FixedVec<FixedVec<u8, 7>, 0>,
    },
    WriteRandomDataBulk {
        write_fut: write_blocks::WriteBlocksFuture<B>,
    },
    Done,
}

impl<B: blkdev::NvBlkDev> WriteRandomDataFuture<B> {
    /// Instantiate a [`WriteRandomDataFuture`].
    ///
    /// # Arguments:
    ///
    /// * `extent` - The storage extent to initialize with random data. Must be
    ///   aligned to the [IO
    ///   Block](layout::ImageLayout::io_block_allocation_blocks_log2) size.
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `blkdev` - The storage the filesystem is being created on.
    fn new(
        extent: &layout::PhysicalAllocBlockRange,
        image_layout: &layout::ImageLayout,
        blkdev: &B,
    ) -> Result<Self, NvFsError> {
        let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
        let io_block_allocation_blocks_log2 = image_layout.io_block_allocation_blocks_log2 as u32;
        if !(u64::from(extent.begin()) | u64::from(extent.end())).is_aligned_pow2(io_block_allocation_blocks_log2) {
            return Err(nvfs_err_internal!());
        }

        let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();
        // Make sure the preferred bulk size is at least an IO Block in size
        // and fits an usize in units of IO Blocks.
        let preferred_bulk_io_blocks_log2 = ((blkdev
            .preferred_io_blocks_bulk_log2()
            .saturating_add(blkdev_io_block_size_128b_log2)
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

    /// Poll the [`WriteRandomDataFuture`] to completion.
    ///
    /// # Arguments:
    ///
    /// * `blkdev` - The storage the filesystem is being created on.
    /// * `rng` - The [random number generator](rng::RngCoreDispatchable) used
    ///   for the randomization.
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    fn poll(
        self: pin::Pin<&mut Self>,
        blkdev: &B,
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
                    let mut bulk_io_blocks = match FixedVec::new_with_default(bulk_io_blocks_count) {
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
                        *bulk_io_block = match FixedVec::new_with_default(io_block_size) {
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

                    // It's been checked in MkFsFuture::new() that the Device IO block size <= the
                    // FS' IO block size, in particular the cast to u8 won't
                    // overflow.
                    let blkdev_io_block_allocation_blocks_log2 = blkdev
                        .io_block_size_128b_log2()
                        .saturating_sub(this.allocation_block_size_128b_log2 as u32)
                        as u8;
                    let write_fut = write_blocks::WriteBlocksFuture::new(
                        &layout::PhysicalAllocBlockRange::new(
                            cur_bulk_allocation_blocks_begin,
                            cur_bulk_allocation_blocks_end,
                        ),
                        mem::take(bulk_io_blocks),
                        this.io_block_allocation_blocks_log2,
                        blkdev_io_block_allocation_blocks_log2,
                        this.allocation_block_size_128b_log2,
                    );
                    this.fut_state = WriteRandomDataFutureState::WriteRandomDataBulk { write_fut };
                }
                WriteRandomDataFutureState::WriteRandomDataBulk { write_fut } => {
                    let bulk_io_blocks = match blkdev::NvBlkDevFuture::poll(pin::Pin::new(write_fut), blkdev, cx) {
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

/// Helper for [`MkFsFuture`] for invalidating the backup
/// [`MkFsInfoHeader`](image_header::MkFsInfoHeader) when done.
struct InvalidateBackupMkFsInfoHeaderFuture<B: blkdev::NvBlkDev> {
    fut_state: InvalidateBackupMkFsInfoHeaderFutureState<B>,
    backup_mkfsinfo_header_location: layout::PhysicalAllocBlockRange,
    image_size: layout::AllocBlockCount,
    enable_trimming: bool,
}

/// [`InvalidateBackupMkFsInfoHeaderFuture`] state-machine state.
enum InvalidateBackupMkFsInfoHeaderFutureState<B: blkdev::NvBlkDev> {
    Init,
    Randomize {
        write_fut: WriteRandomDataFuture<B>,
    },
    PrepareWriteZeroes {
        extent: layout::PhysicalAllocBlockRange,
    },
    WriteZeroes {
        write_fut: write_blocks::WriteBlocksFuture<B>,
        extent: layout::PhysicalAllocBlockRange,
    },
    Trim {
        trim_fut: B::TrimFuture,
    },
    PrepareWriteBarrierAfterInvalidate,
    WriteBarrierAfterInvalidate {
        write_barrier_fut: B::WriteBarrierFuture,
    },
    Done,
}

impl<B: blkdev::NvBlkDev> InvalidateBackupMkFsInfoHeaderFuture<B> {
    /// Instantiate a [`InvalidateBackupMkFsInfoHeaderFuture`].
    ///
    /// # Arguments:
    ///
    /// * `blkdev` - The storage the filsystem is being created on.
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `salt_len`- The filesystem salt's length.
    /// * `image_size` - The created filesystem image's size.
    /// * `enable_trimming` - Whether to enable the submission of [trim
    ///   commands](blkdev::NvBlkDev::trim) to the underlying storage. When off,
    ///   the backup [`MkFsInfoHeader`](image_header::MkFsInfoHeader)'s backing
    ///   storage region will get overwritten with random data. Trimming of
    ///   backup [`MkFsInfoHeader`](image_header::MkFsInfoHeader) regions beyond
    ///   the filesystem's `image_size` will always be attempted.
    fn new(
        blkdev: &B,
        image_layout: &layout::ImageLayout,
        salt_len: u8,
        image_size: layout::AllocBlockCount,
        enable_trimming: bool,
    ) -> Result<Self, NvFsError> {
        let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();
        let blkdev_io_blocks = blkdev.io_blocks();
        let blkdev_io_blocks = blkdev_io_blocks.min(u64::MAX >> (blkdev_io_block_size_128b_log2 + 7));

        let backup_mkfsinfo_header_location = image_header::MkFsInfoHeader::physical_backup_location(
            salt_len,
            blkdev_io_blocks,
            blkdev_io_block_size_128b_log2,
            image_layout.io_block_allocation_blocks_log2 as u32,
            image_layout.allocation_block_size_128b_log2 as u32,
        )?;

        Ok(Self {
            fut_state: InvalidateBackupMkFsInfoHeaderFutureState::Init,
            backup_mkfsinfo_header_location,
            image_size,
            enable_trimming,
        })
    }

    /// Poll the [`InvalidateBackupMkFsInfoHeaderFuture`] to completion.
    ///
    /// # Arguments:
    ///
    /// * `blkdev` - The storage the filesystem is being created on.
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `rng` - The [random number generator](rng::RngCoreDispatchable) used
    ///   for the randomizing the backup
    ///   [`MkFsInfoHeader`](image_header::MkFsInfoHeader)'s backing storage
    ///   region.
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    fn poll(
        self: pin::Pin<&mut Self>,
        blkdev: &B,
        image_layout: &layout::ImageLayout,
        rng: &mut dyn rng::RngCoreDispatchable,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), NvFsError>> {
        let this = pin::Pin::into_inner(self);
        loop {
            match &mut this.fut_state {
                InvalidateBackupMkFsInfoHeaderFutureState::Init => {
                    if this.enable_trimming
                        || this.backup_mkfsinfo_header_location.begin()
                            >= layout::PhysicalAllocBlockIndex::from(0u64) + this.image_size
                    {
                        // Still overwrite with zeroes before the trimming.
                        this.fut_state = InvalidateBackupMkFsInfoHeaderFutureState::PrepareWriteZeroes {
                            extent: this.backup_mkfsinfo_header_location,
                        };
                        continue;
                    }

                    // Randomize the parts in range of image_size. Be careful to
                    // align the region to the IO Block size, as the WriteRandomDataFuture requires
                    // that.
                    let io_block_allocation_blocks_log2 = image_layout.io_block_allocation_blocks_log2 as u32;
                    // MkFsInfoHeader::physical_backup_location() verifies that the
                    // backup location's beginning is aligned to the IO Block size.
                    debug_assert!(
                        u64::from(this.backup_mkfsinfo_header_location.begin())
                            .is_aligned_pow2(io_block_allocation_blocks_log2)
                    );
                    // MkFsLayout::new() aligns the image_size to the IO Block size.
                    debug_assert!(u64::from(this.image_size).is_aligned_pow2(io_block_allocation_blocks_log2));
                    let write_fut = match WriteRandomDataFuture::new(
                        &layout::PhysicalAllocBlockRange::new(
                            this.backup_mkfsinfo_header_location.begin(),
                            this.backup_mkfsinfo_header_location
                                .end()
                                .align_up(io_block_allocation_blocks_log2)
                                .unwrap_or(layout::PhysicalAllocBlockIndex::from(0u64) + this.image_size)
                                .min(layout::PhysicalAllocBlockIndex::from(0u64) + this.image_size),
                        ),
                        image_layout,
                        blkdev,
                    ) {
                        Ok(write_fut) => write_fut,
                        Err(e) => {
                            this.fut_state = InvalidateBackupMkFsInfoHeaderFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    this.fut_state = InvalidateBackupMkFsInfoHeaderFutureState::Randomize { write_fut };
                }
                InvalidateBackupMkFsInfoHeaderFutureState::Randomize { write_fut } => {
                    match WriteRandomDataFuture::poll(pin::Pin::new(write_fut), blkdev, rng, cx) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => {
                            this.fut_state = InvalidateBackupMkFsInfoHeaderFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    if this.backup_mkfsinfo_header_location.end()
                        > layout::PhysicalAllocBlockIndex::from(0u64) + this.image_size
                    {
                        // Zeroize and trim the range beyond the image_size.
                        this.fut_state = InvalidateBackupMkFsInfoHeaderFutureState::PrepareWriteZeroes {
                            extent: layout::PhysicalAllocBlockRange::new(
                                layout::PhysicalAllocBlockIndex::from(0u64) + this.image_size,
                                this.backup_mkfsinfo_header_location.end(),
                            ),
                        };
                    } else {
                        this.fut_state = InvalidateBackupMkFsInfoHeaderFutureState::PrepareWriteBarrierAfterInvalidate;
                    }
                }
                InvalidateBackupMkFsInfoHeaderFutureState::PrepareWriteZeroes { extent } => {
                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                    let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();
                    let blkdev_io_block_allocation_blocks_log2 =
                        blkdev_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);
                    debug_assert!(
                        (u64::from(extent.begin()) | u64::from(extent.end()))
                            .is_aligned_pow2(blkdev_io_block_allocation_blocks_log2)
                    );
                    let extent_blkdev_io_blocks =
                        (u64::from(extent.block_count())) >> blkdev_io_block_allocation_blocks_log2;
                    // Does not overflow: the total encoded mkfsinfo header length never
                    // exceeds 3 * 128 Bytes.
                    debug_assert!(extent_blkdev_io_blocks <= 3);
                    let mut blkdev_io_block_buffers = match FixedVec::new_with_default(extent_blkdev_io_blocks as usize)
                    {
                        Ok(buffers) => buffers,
                        Err(e) => {
                            this.fut_state = InvalidateBackupMkFsInfoHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    for blkdev_io_block_buffer in blkdev_io_block_buffers.iter_mut() {
                        *blkdev_io_block_buffer = match FixedVec::new_with_default(
                            1usize << (blkdev_io_block_allocation_blocks_log2 + allocation_block_size_128b_log2 + 7),
                        ) {
                            Ok(blkdev_io_block_buffer) => blkdev_io_block_buffer,
                            Err(e) => {
                                this.fut_state = InvalidateBackupMkFsInfoHeaderFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(e)));
                            }
                        };
                    }

                    let write_fut = write_blocks::WriteBlocksFuture::new(
                        extent,
                        blkdev_io_block_buffers,
                        blkdev_io_block_allocation_blocks_log2 as u8,
                        blkdev_io_block_allocation_blocks_log2 as u8,
                        image_layout.allocation_block_size_128b_log2,
                    );
                    this.fut_state = InvalidateBackupMkFsInfoHeaderFutureState::WriteZeroes {
                        write_fut,
                        extent: *extent,
                    };
                }
                InvalidateBackupMkFsInfoHeaderFutureState::WriteZeroes { write_fut, extent } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(write_fut), blkdev, cx) {
                        task::Poll::Ready(Ok((_, Ok(())))) => (),
                        task::Poll::Ready(Err(e) | Ok((_, Err(e)))) => {
                            this.fut_state = InvalidateBackupMkFsInfoHeaderFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                    let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();
                    let blkdev_io_block_allocation_blocks_log2 =
                        blkdev_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);
                    let allocation_block_blkdev_io_blocks_log2 =
                        allocation_block_size_128b_log2.saturating_sub(blkdev_io_block_size_128b_log2);
                    debug_assert!(
                        (u64::from(extent.begin()) | u64::from(extent.end()))
                            .is_aligned_pow2(blkdev_io_block_allocation_blocks_log2)
                    );
                    let trim_fut = match blkdev.trim(
                        u64::from(extent.begin()) << allocation_block_blkdev_io_blocks_log2
                            >> blkdev_io_block_allocation_blocks_log2,
                        u64::from(extent.block_count()) << allocation_block_blkdev_io_blocks_log2
                            >> blkdev_io_block_allocation_blocks_log2,
                    ) {
                        Ok(trim_fut) => trim_fut,
                        Err(_) => {
                            // Failure to trim is considered non-fatal.
                            this.fut_state =
                                InvalidateBackupMkFsInfoHeaderFutureState::PrepareWriteBarrierAfterInvalidate;
                            continue;
                        }
                    };
                    this.fut_state = InvalidateBackupMkFsInfoHeaderFutureState::Trim { trim_fut };
                }
                InvalidateBackupMkFsInfoHeaderFutureState::Trim { trim_fut } => {
                    // Failure to trim is considered non-fatal.
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(trim_fut), blkdev, cx) {
                        task::Poll::Ready(Ok(()) | Err(_)) => (),
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    this.fut_state = InvalidateBackupMkFsInfoHeaderFutureState::PrepareWriteBarrierAfterInvalidate;
                }
                InvalidateBackupMkFsInfoHeaderFutureState::PrepareWriteBarrierAfterInvalidate => {
                    let write_barrier_fut = match blkdev.write_barrier() {
                        Ok(write_barrier_fut) => write_barrier_fut,
                        Err(e) => {
                            this.fut_state = InvalidateBackupMkFsInfoHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    this.fut_state =
                        InvalidateBackupMkFsInfoHeaderFutureState::WriteBarrierAfterInvalidate { write_barrier_fut };
                }
                InvalidateBackupMkFsInfoHeaderFutureState::WriteBarrierAfterInvalidate { write_barrier_fut } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(write_barrier_fut), blkdev, cx) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => {
                            this.fut_state = InvalidateBackupMkFsInfoHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    }

                    this.fut_state = InvalidateBackupMkFsInfoHeaderFutureState::Done;
                    return task::Poll::Ready(Ok(()));
                }
                InvalidateBackupMkFsInfoHeaderFutureState::Done => unreachable!(),
            }
        }
    }
}

/// Internal [`MkFsInfoHeader`](image_header::MkFsInfoHeader) writing primitive.
struct WriteMkFsInfoHeaderFuture<B: blkdev::NvBlkDev> {
    fut_state: WriteMkFsInfoHeaderFutureState<B>,
}

/// [`WriteMkFsInfoHeaderFuture`] state-machine state.
enum WriteMkFsInfoHeaderFutureState<B: blkdev::NvBlkDev> {
    Init {
        to_backup_location: bool,
    },
    Write {
        write_fut: write_blocks::WriteBlocksFuture<B>,
    },
    Done,
}

impl<B: blkdev::NvBlkDev> WriteMkFsInfoHeaderFuture<B> {
    /// Instantiate a [`WriteMkFsInfoHeaderFuture`].
    ///
    /// # Arguments:
    ///
    /// * `to_backup_location` - If `true`, the
    ///   [`MkFsInfoHeader`](image_header::MkFsInfoHeader) is to be written to
    ///   the backup location, to the storage's beginning otherwise.
    fn new(to_backup_location: bool) -> Self {
        Self {
            fut_state: WriteMkFsInfoHeaderFutureState::Init { to_backup_location },
        }
    }

    /// Poll the [`WriteMkFsInfoHeaderFuture`] to completion.
    ///
    /// # Arguments:
    ///
    /// * `blkdev` - The storage the filesystem is to be created on.
    /// * `image_layout` - The filesystem's [`ImageLayout`](layout::ImageLayout)
    ///   to record in the [`MkFsInfoHeader`](image_header::MkFsInfoHeader).
    /// * `salt` - The to be created filesystem's salt. Its lenght must not
    ///   exceed [`u8::MAX`].
    /// * `image_size` - The filesystem's desired image size.
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    fn poll(
        self: pin::Pin<&mut Self>,
        blkdev: &B,
        image_layout: &layout::ImageLayout,
        salt: &FixedVec<u8, 4>,
        image_size: layout::AllocBlockCount,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), NvFsError>> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                WriteMkFsInfoHeaderFutureState::Init { to_backup_location } => {
                    let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();
                    if blkdev_io_block_size_128b_log2
                        > image_layout.io_block_allocation_blocks_log2 as u32
                            + image_layout.allocation_block_size_128b_log2 as u32
                    {
                        this.fut_state = WriteMkFsInfoHeaderFutureState::Done;
                        return task::Poll::Ready(Err(NvFsError::from(
                            CocoonFsFormatError::IoBlockSizeNotSupportedByDevice,
                        )));
                    }
                    // As the ImageLayout's IO Block size fits an usize, this applies to the Device
                    // IO Block size as well.
                    debug_assert!(blkdev_io_block_size_128b_log2 < usize::BITS - 7);

                    let salt_len = match u8::try_from(salt.len()) {
                        Ok(salt_len) => salt_len,
                        Err(_) => {
                            this.fut_state = WriteMkFsInfoHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(CocoonFsFormatError::InvalidSaltLength)));
                        }
                    };

                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                    let blkdev_io_block_allocation_blocks_log2 =
                        blkdev_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);
                    let mkfsinfo_header_location = if *to_backup_location {
                        let blkdev_io_blocks = blkdev.io_blocks();
                        let blkdev_io_blocks = blkdev_io_blocks.min(u64::MAX >> (blkdev_io_block_size_128b_log2 + 7));
                        match image_header::MkFsInfoHeader::physical_backup_location(
                            salt_len,
                            blkdev_io_blocks,
                            blkdev_io_block_size_128b_log2,
                            image_layout.io_block_allocation_blocks_log2 as u32,
                            allocation_block_size_128b_log2,
                        ) {
                            Ok(backup_mkfsinfo_header_location) => backup_mkfsinfo_header_location,
                            Err(e) => {
                                this.fut_state = WriteMkFsInfoHeaderFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                        }
                    } else {
                        let encoded_header_len = image_header::MkFsInfoHeader::encoded_len(salt_len);
                        let header_blkdev_io_blocks = ((encoded_header_len - 1)
                            >> (blkdev_io_block_allocation_blocks_log2 + allocation_block_size_128b_log2 + 7))
                            + 1;
                        let header_allocation_blocks = layout::AllocBlockCount::from(
                            (header_blkdev_io_blocks as u64) << blkdev_io_block_allocation_blocks_log2,
                        );
                        layout::PhysicalAllocBlockRange::from((
                            layout::PhysicalAllocBlockIndex::from(0u64),
                            header_allocation_blocks,
                        ))
                    };

                    debug_assert!(
                        (u64::from(mkfsinfo_header_location.begin()) | u64::from(mkfsinfo_header_location.end()))
                            .is_aligned_pow2(blkdev_io_block_allocation_blocks_log2)
                    );
                    let header_blkdev_io_blocks =
                        u64::from(mkfsinfo_header_location.block_count()) >> blkdev_io_block_allocation_blocks_log2;
                    // Does not overflow: the total encoded mkfsinfo header length never
                    // exceeds 3 * 128 Bytes.
                    debug_assert!(header_blkdev_io_blocks <= 3);

                    let mut blkdev_io_block_buffers = match FixedVec::new_with_default(header_blkdev_io_blocks as usize)
                    {
                        Ok(buffers) => buffers,
                        Err(e) => {
                            this.fut_state = WriteMkFsInfoHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    for blkdev_io_block_buffer in blkdev_io_block_buffers.iter_mut() {
                        *blkdev_io_block_buffer = match FixedVec::new_with_default(
                            1usize << (blkdev_io_block_allocation_blocks_log2 + allocation_block_size_128b_log2 + 7),
                        ) {
                            Ok(blkdev_io_block_buffer) => blkdev_io_block_buffer,
                            Err(e) => {
                                this.fut_state = WriteMkFsInfoHeaderFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(e)));
                            }
                        };
                    }

                    if let Err(e) = image_header::MkFsInfoHeader::encode(
                        io_slices::BuffersSliceIoSlicesMutIter::new(&mut blkdev_io_block_buffers).map_infallible_err(),
                        image_layout,
                        image_size,
                        salt,
                    ) {
                        this.fut_state = WriteMkFsInfoHeaderFutureState::Done;
                        return task::Poll::Ready(Err(e));
                    }

                    let write_fut = write_blocks::WriteBlocksFuture::new(
                        &mkfsinfo_header_location,
                        blkdev_io_block_buffers,
                        blkdev_io_block_allocation_blocks_log2 as u8,
                        blkdev_io_block_allocation_blocks_log2 as u8,
                        image_layout.allocation_block_size_128b_log2,
                    );
                    this.fut_state = WriteMkFsInfoHeaderFutureState::Write { write_fut };
                }
                WriteMkFsInfoHeaderFutureState::Write { write_fut } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(write_fut), blkdev, cx) {
                        task::Poll::Ready(Ok((_, Ok(())))) => {
                            this.fut_state = WriteMkFsInfoHeaderFutureState::Done;
                            return task::Poll::Ready(Ok(()));
                        }
                        task::Poll::Ready(Err(e) | Ok((_, Err(e)))) => {
                            this.fut_state = WriteMkFsInfoHeaderFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                }
                WriteMkFsInfoHeaderFutureState::Done => unreachable!(),
            }
        }
    }
}

/// Write a filesystem creation info header.
///
/// In order to enable third parties not in possession of the root key to
/// provision a storage volume for use with CocoonFs, they may write a
/// "filesystem creation info" header" containing all the required core
/// filesystem configuration parameters to it. The filesystem will then get
/// created ("mkfs") at first use, i.e. at the first attempt to open it.
///
/// # See also:
///
/// * [`CocoonFsMkFsFuture`] for direct filesystem creation without a filesystem
///   creation info header.
pub struct CocoonFsWriteMkfsInfoHeaderFuture<B: blkdev::NvBlkDev> {
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self.
    blkdev: Option<B>,
    image_layout: layout::ImageLayout,
    salt: FixedVec<u8, 4>,
    image_size: layout::AllocBlockCount,
    fut_state: CocoonFsWriteMkfsInfoHeaderFutureState<B>,
}

/// [`CocoonFsWriteMkfsInfoHeaderFuture`] state-machine state.
enum CocoonFsWriteMkfsInfoHeaderFutureState<B: blkdev::NvBlkDev> {
    ResizeBlkDev {
        resize_fut: B::ResizeFuture,
    },
    WriteMkFsInfoHeader {
        write_mkfsinfo_header_fut: WriteMkFsInfoHeaderFuture<B>,
    },
    WriteSyncAfterBackupMkFsInfoHeaderWrite {
        write_sync_fut: B::WriteSyncFuture,
    },
    Done,
}

impl<B: blkdev::NvBlkDev> CocoonFsWriteMkfsInfoHeaderFuture<B> {
    /// Instantiate a [`CocoonFsWriteMkfsInfoHeaderFuture`].
    ///
    /// On error, the input `blkdev` is returned directly as part of
    /// the `Err`. On success, the [`CocoonFsWriteMkfsInfoHeaderFuture`] assumes
    /// ownership of the `blkdev` for the duration of the operation. It will
    /// eventually get returned back from [`poll()`](Self::poll) at
    /// completion.
    ///
    /// # Arguments:
    ///
    /// * `blkdev` - The storage the filesystem is to be created on.
    /// * `image_layout` - The filesystem's [`CocoonFsImageLayout`].
    /// * `salt` - The filsystem salt to be stored in the static image header.
    ///   Its length must not exceed [`u8::MAX`].
    /// * `image_size` - Optional desired filesystem image size in units of
    ///   Bytes to eventually get recorded in the filesystem's mutable image
    ///   header in the course of the actual filesystem creation. If not
    ///   specified, the maximum possible value within the backing storage's
    ///   [dimensions](blkdev::NvBlkDev::io_blocks) will be used.
    /// * `resize_image_to_final_size` - Whether to attempt to
    ///   [resize](blkdev::NvBlkDev::resize) the image to its full final
    ///   `image_size` before writing the header. Otherwise the backing storage
    ///   will only resized to accomodate for the to be written header, and only
    ///   if neeeded.
    pub fn new(
        blkdev: B,
        image_layout: &CocoonFsImageLayout,
        salt: FixedVec<u8, 4>,
        image_size: Option<u64>,
        resize_image_to_final_size: bool,
    ) -> Result<Self, (B, NvFsError)> {
        let io_block_allocation_blocks_log2 = image_layout.io_block_allocation_blocks_log2 as u32;
        let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
        let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();
        let blkdev_io_block_allocation_blocks_log2 =
            blkdev_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);
        if blkdev_io_block_allocation_blocks_log2 > io_block_allocation_blocks_log2 {
            return Err((
                blkdev,
                NvFsError::from(CocoonFsFormatError::IoBlockSizeNotSupportedByDevice),
            ));
        }
        let allocation_block_blkdev_io_blocks_log2 =
            allocation_block_size_128b_log2.saturating_sub(blkdev_io_block_size_128b_log2);
        let blkdev_io_blocks = blkdev.io_blocks();
        let blkdev_io_blocks = blkdev_io_blocks.min(u64::MAX >> (blkdev_io_block_size_128b_log2 + 7));
        let blkdev_allocation_blocks = layout::AllocBlockCount::from(
            blkdev_io_blocks << blkdev_io_block_allocation_blocks_log2 >> allocation_block_blkdev_io_blocks_log2,
        );

        // Convert from units of Bytes to Allocation Blocks.
        let image_size = image_size
            .map(|image_size| layout::AllocBlockCount::from(image_size >> (allocation_block_size_128b_log2 + 7)));
        let image_size = image_size.unwrap_or(blkdev_allocation_blocks);

        // Before writing anything, verify that the to be created filesystem can get
        // layout properly on a storage of size image_size.
        let mkfs_layout = match MkFsLayout::new(image_layout, salt, image_size) {
            Ok(mkfs_layout) => mkfs_layout,
            Err(e) => {
                return Err((blkdev, e));
            }
        };
        let MkFsLayout {
            salt,
            image_size,
            allocated_image_allocation_blocks_end,
            ..
        } = mkfs_layout;
        // Verify that the desired image size is valid (large enough) for writing the
        // backup mkfsinfo header at filesystem opening time.
        // MkfsLayout::new() verifies that the salt length fits an u8.
        let salt_len = salt.len() as u8;
        let backup_mkfsinfo_header_location = match image_header::MkFsInfoHeader::physical_backup_location(
            salt_len,
            u64::from(image_size) << allocation_block_blkdev_io_blocks_log2 >> blkdev_io_block_allocation_blocks_log2,
            blkdev_io_block_size_128b_log2,
            io_block_allocation_blocks_log2,
            allocation_block_size_128b_log2,
        ) {
            Ok(backup_mkfsinfo_header_location) => backup_mkfsinfo_header_location,
            Err(e) => return Err((blkdev, e)),
        };

        // Check that the storage allocated to the initial metadata structures does not
        // extend into the backup MkFsInfoHeader.
        if backup_mkfsinfo_header_location.begin() < allocated_image_allocation_blocks_end {
            return Err((blkdev, NvFsError::NoSpace));
        }

        // Ok, check whether we need to resize the backing storage to write the
        // mkfsinfo header at least.
        let mkfsinfo_header_len = image_header::MkFsInfoHeader::encoded_len(salt_len);
        let mkfsinfo_header_blkdev_io_blocks = ((mkfsinfo_header_len - 1)
            >> (blkdev_io_block_allocation_blocks_log2 + allocation_block_size_128b_log2 + 7))
            + 1;
        let mkfsinfo_header_allocation_blocks = layout::AllocBlockCount::from(
            (mkfsinfo_header_blkdev_io_blocks as u64) << blkdev_io_block_allocation_blocks_log2,
        );

        let fut_state = if mkfsinfo_header_allocation_blocks > blkdev_allocation_blocks
            || resize_image_to_final_size && image_size != blkdev_allocation_blocks
        {
            let resize_target_allocation_blocks = if resize_image_to_final_size {
                image_size
            } else {
                mkfsinfo_header_allocation_blocks
            };
            let resize_fut = match blkdev.resize(
                u64::from(resize_target_allocation_blocks) << allocation_block_blkdev_io_blocks_log2
                    >> blkdev_io_block_allocation_blocks_log2,
            ) {
                Ok(resize_fut) => resize_fut,
                Err(e) => {
                    return Err((
                        blkdev,
                        NvFsError::from(match e {
                            NvBlkDevIoError::OperationNotSupported => NvBlkDevIoError::IoBlockOutOfRange,
                            _ => e,
                        }),
                    ));
                }
            };
            CocoonFsWriteMkfsInfoHeaderFutureState::ResizeBlkDev { resize_fut }
        } else {
            CocoonFsWriteMkfsInfoHeaderFutureState::WriteMkFsInfoHeader {
                write_mkfsinfo_header_fut: WriteMkFsInfoHeaderFuture::new(false),
            }
        };

        Ok(Self {
            blkdev: Some(blkdev),
            image_layout: image_layout.clone(),
            salt,
            image_size,
            fut_state,
        })
    }
}

impl<B: blkdev::NvBlkDev> future::Future for CocoonFsWriteMkfsInfoHeaderFuture<B> {
    /// Output type of [`poll()`](Self::poll).
    ///
    /// A two-level [`Result`] is returned from the
    /// [`Future::poll()`](future::Future::poll):
    ///
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering an internal error and the input
    ///   [`NvBlkDev`](blkdev::NvBlkDev) is lost.
    /// * `Ok((blkdev, ...))` - Otherwise the outer level [`Result`] is set to
    ///   [`Ok`] and a pair of the input [`NvBlkDev`](blkdev::NvBlkDev),
    ///   `blkdev`, and the operation result will get returned within:
    ///   * `Ok((blkdev, Err(e)))` - In case of an error, the error reason `e`
    ///     is returned in an [`Err`].
    ///   * `Ok((blkdev, Ok(())))` - Otherwise an `Ok(())` is returned on
    ///     success.
    type Output = Result<(B, Result<(), NvFsError>), NvFsError>;

    fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        let blkdev = match this.blkdev.as_mut() {
            Some(blkdev) => blkdev,
            None => {
                this.fut_state = CocoonFsWriteMkfsInfoHeaderFutureState::Done;
                return task::Poll::Ready(Err(nvfs_err_internal!()));
            }
        };

        let result = loop {
            match &mut this.fut_state {
                CocoonFsWriteMkfsInfoHeaderFutureState::ResizeBlkDev { resize_fut } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(resize_fut), blkdev, cx) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => {
                            break Err(NvFsError::from(match e {
                                NvBlkDevIoError::OperationNotSupported => NvBlkDevIoError::IoBlockOutOfRange,
                                _ => e,
                            }));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    this.fut_state = CocoonFsWriteMkfsInfoHeaderFutureState::WriteMkFsInfoHeader {
                        write_mkfsinfo_header_fut: WriteMkFsInfoHeaderFuture::new(false),
                    };
                }
                CocoonFsWriteMkfsInfoHeaderFutureState::WriteMkFsInfoHeader {
                    write_mkfsinfo_header_fut,
                } => {
                    match WriteMkFsInfoHeaderFuture::poll(
                        pin::Pin::new(write_mkfsinfo_header_fut),
                        blkdev,
                        &this.image_layout,
                        &this.salt,
                        this.image_size,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => break Err(e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let write_sync_fut = match blkdev.write_sync() {
                        Ok(write_sync_fut) => write_sync_fut,
                        Err(e) => break Err(NvFsError::from(e)),
                    };
                    this.fut_state = CocoonFsWriteMkfsInfoHeaderFutureState::WriteSyncAfterBackupMkFsInfoHeaderWrite {
                        write_sync_fut,
                    };
                }
                CocoonFsWriteMkfsInfoHeaderFutureState::WriteSyncAfterBackupMkFsInfoHeaderWrite { write_sync_fut } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(write_sync_fut), blkdev, cx) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => break Err(NvFsError::from(e)),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    break Ok(());
                }
                CocoonFsWriteMkfsInfoHeaderFutureState::Done => unreachable!(),
            }
        };

        this.fut_state = CocoonFsWriteMkfsInfoHeaderFutureState::Done;
        let blkdev = match this.blkdev.take() {
            Some(blkdev) => blkdev,
            None => {
                return task::Poll::Ready(Err(nvfs_err_internal!()));
            }
        };
        task::Poll::Ready(Ok((blkdev, result)))
    }
}
