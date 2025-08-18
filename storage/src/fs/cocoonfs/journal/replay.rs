// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`JournalReplayFuture`].

extern crate alloc;
use alloc::boxed::Box;

use super::{
    apply_script::{JournalApplyWritesScript, JournalTrimsScript, JournalUpdateAuthDigestsScript},
    extents_covering_auth_digests::ExtentsCoveringAuthDigests,
    log::{JournalLog, JournalLogInvalidateFuture, JournalLogReadFuture},
    staging_copy_disguise::JournalStagingCopyUndisguise,
};
use crate::{
    chip::{self, ChunkedIoRegion, ChunkedIoRegionChunkRange, ChunkedIoRegionError, NvChipIoError},
    fs::{
        NvFsError, NvFsIoError,
        cocoonfs::{
            CocoonFsFormatError, alloc_bitmap, auth_tree, extents, image_header, keys,
            layout::{self, BlockIndex as _},
        },
    },
    nvfs_err_internal,
    utils_async::sync_types,
    utils_common::{
        bitmanip::BitManip as _,
        fixed_vec::FixedVec,
        io_slices::{self, IoSlicesIterCommon as _},
    },
};
use core::{mem, pin, task};

/// Replay the journal at filesystem opening time if needed.
///
/// Check if the journal is active and needs replay. If so, do that and cleanup
/// afterwards, including an invalidation of the journal.
pub struct JournalReplayFuture<C: chip::NvChip> {
    enable_trimming: bool,

    // Populated after the Journal Log has been read.
    journal_log_extents: Option<extents::PhysicalExtents>,

    // Populated after the Journal Log has been read.
    apply_writes_script: Option<JournalApplyWritesScript>,
    // Populated after the Journal Log has been read. Taken for applying writes.
    update_auth_digests_script: Option<JournalUpdateAuthDigestsScript>,
    // Populated after the Journal Log has been read.
    trim_script: Option<JournalTrimsScript>,
    // Populated after the Journal Log has been read.
    journal_staging_copy_undisguise: Option<JournalStagingCopyUndisguise>,

    // Populated after the mutable image header has been read.
    mutable_image_header: Option<image_header::MutableImageHeader>,

    // Populated after the mutable image header has been read.
    auth_tree_config: Option<auth_tree::AuthTreeConfig>,

    fut_state: JournalReplayFutureState<C>,
}

/// [`JournalReplayFuture`] state-machine state.
enum JournalReplayFutureState<C: chip::NvChip> {
    ReadLog {
        read_log_fut: JournalLogReadFuture<C>,
    },
    ReadMutableImageHeader {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        auth_tree_extents: Option<extents::LogicalExtents>,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        alloc_bitmap_file_extents: Option<extents::PhysicalExtents>,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        alloc_bitmap_file_fragments_auth_digests: Option<ExtentsCoveringAuthDigests>,

        read_mutable_image_header_fut: JournalReadMutableImageHeaderFuture<C>,
    },
    ReadAllocBitmapJournalFragments {
        alloc_bitmap_file: alloc_bitmap::AllocBitmapFile,
        image_header_end: layout::PhysicalAllocBlockIndex,
        read_alloc_bitmap_journal_fragments_fut: alloc_bitmap::AllocBitmapFileReadJournalFragmentsFuture<C>,
    },
    ReplayWrites {
        replay_writes_fut: JournalReplayWritesFuture<C>,
    },
    Cleanup {
        cleanup_fut: JournalCleanupFuture<C>,
    },
    Done,
}

impl<C: chip::NvChip> JournalReplayFuture<C> {
    /// Instantiate a [`JournalReplayFuture`].
    ///
    /// # Arguments:
    ///
    /// * `enable_trimming` - Whether or not to submit [trim
    ///   commands](chip::NvChip::trim) to the underlying storage for cleanup.
    pub fn new(enable_trimming: bool) -> Self {
        let read_log_fut = JournalLogReadFuture::new();
        Self {
            enable_trimming,
            journal_log_extents: None,
            apply_writes_script: None,
            update_auth_digests_script: None,
            trim_script: None,
            journal_staging_copy_undisguise: None,
            mutable_image_header: None,
            auth_tree_config: None,
            fut_state: JournalReplayFutureState::ReadLog { read_log_fut },
        }
    }

    /// Poll the [`JournalReplayFuture`] to completion.
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `salt_len` - Length of the salt found in the filesystem's
    ///   [`StaticImageHeader`](image_header::StaticImageHeader).
    /// * `root_key` - The filesystem's root key.
    /// * `keys_cache` - A [`KeyCache`](keys::KeyCache) instantiated for the
    ///   filesystem.
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    pub fn poll<ST: sync_types::SyncTypes>(
        self: pin::Pin<&mut Self>,
        chip: &C,
        image_layout: &layout::ImageLayout,
        salt_len: u8,
        root_key: &keys::RootKey,
        keys_cache: &mut keys::KeyCacheRef<'_, ST>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), NvFsError>> {
        let this = pin::Pin::into_inner(self);
        loop {
            match &mut this.fut_state {
                JournalReplayFutureState::ReadLog { read_log_fut } => {
                    let journal_log = match JournalLogReadFuture::poll(
                        pin::Pin::new(read_log_fut),
                        chip,
                        image_layout,
                        salt_len,
                        root_key,
                        keys_cache,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(journal_log)) => journal_log,
                        task::Poll::Ready(Err(e)) => {
                            this.fut_state = JournalReplayFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    let journal_log = match journal_log {
                        Some(journal_log) => journal_log,
                        None => {
                            // No Journal active, nothing to do.
                            this.fut_state = JournalReplayFutureState::Done;
                            return task::Poll::Ready(Ok(()));
                        }
                    };
                    let JournalLog {
                        log_extents: journal_log_extents,
                        auth_tree_extents,
                        alloc_bitmap_file_extents,
                        alloc_bitmap_file_fragments_auth_digests,
                        apply_writes_script,
                        update_auth_digests_script,
                        trim_script,
                        journal_staging_copy_undisguise,
                    } = journal_log;
                    this.journal_log_extents = Some(journal_log_extents);
                    this.apply_writes_script = Some(apply_writes_script);
                    this.update_auth_digests_script = Some(update_auth_digests_script);
                    this.trim_script = trim_script;
                    this.journal_staging_copy_undisguise = journal_staging_copy_undisguise;

                    let read_mutable_image_header_fut =
                        match JournalReadMutableImageHeaderFuture::new(chip, image_layout, salt_len) {
                            Ok(read_mutable_image_header_fut) => read_mutable_image_header_fut,
                            Err(e) => {
                                this.fut_state = JournalReplayFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                        };
                    let auth_tree_extents = extents::LogicalExtents::from(auth_tree_extents);
                    this.fut_state = JournalReplayFutureState::ReadMutableImageHeader {
                        auth_tree_extents: Some(auth_tree_extents),
                        alloc_bitmap_file_extents: Some(alloc_bitmap_file_extents),
                        alloc_bitmap_file_fragments_auth_digests: Some(alloc_bitmap_file_fragments_auth_digests),
                        read_mutable_image_header_fut,
                    };
                }
                JournalReplayFutureState::ReadMutableImageHeader {
                    auth_tree_extents,
                    alloc_bitmap_file_extents,
                    alloc_bitmap_file_fragments_auth_digests,
                    read_mutable_image_header_fut,
                } => {
                    let apply_writes_script = match this.apply_writes_script.as_ref() {
                        Some(apply_writes_script) => apply_writes_script,
                        None => {
                            this.fut_state = JournalReplayFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };
                    let mutable_image_header = match JournalReadMutableImageHeaderFuture::poll(
                        pin::Pin::new(read_mutable_image_header_fut),
                        chip,
                        image_layout,
                        apply_writes_script,
                        this.journal_staging_copy_undisguise.as_ref(),
                        cx,
                    ) {
                        task::Poll::Ready(Ok(mutable_image_header)) => mutable_image_header,
                        task::Poll::Ready(Err(e)) => {
                            this.fut_state = JournalReplayFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let auth_tree_extents = match auth_tree_extents.take() {
                        Some(auth_tree_extents) => auth_tree_extents,
                        None => {
                            this.fut_state = JournalReplayFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };
                    let alloc_bitmap_file_extents = match alloc_bitmap_file_extents.take() {
                        Some(alloc_bitmap_file_extents) => alloc_bitmap_file_extents,
                        None => {
                            this.fut_state = JournalReplayFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    let auth_tree_config = match auth_tree::AuthTreeConfig::new(
                        root_key,
                        image_layout,
                        &mutable_image_header.inode_index_entry_leaf_node_block_ptr,
                        mutable_image_header.image_size,
                        auth_tree_extents,
                        &alloc_bitmap_file_extents,
                    ) {
                        Ok(auth_tree_config) => auth_tree_config,
                        Err(e) => {
                            this.fut_state = JournalReplayFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    this.auth_tree_config = Some(auth_tree_config);
                    this.mutable_image_header = Some(mutable_image_header);

                    let alloc_bitmap_file =
                        match alloc_bitmap::AllocBitmapFile::new(image_layout, alloc_bitmap_file_extents) {
                            Ok(alloc_bitmap_file) => alloc_bitmap_file,
                            Err(e) => {
                                this.fut_state = JournalReplayFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                        };

                    let alloc_bitmap_file_fragments_auth_digests = match alloc_bitmap_file_fragments_auth_digests.take()
                    {
                        Some(alloc_bitmap_file_fragments_auth_digests) => alloc_bitmap_file_fragments_auth_digests,
                        None => {
                            this.fut_state = JournalReplayFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    let read_alloc_bitmap_journal_fragments_fut =
                        match alloc_bitmap::AllocBitmapFileReadJournalFragmentsFuture::new(
                            chip,
                            alloc_bitmap_file_fragments_auth_digests,
                            &alloc_bitmap_file,
                            image_layout,
                            root_key,
                            keys_cache,
                        ) {
                            Ok(read_alloc_bitmap_journal_fragments_fut) => read_alloc_bitmap_journal_fragments_fut,
                            Err(e) => {
                                this.fut_state = JournalReplayFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                        };

                    this.fut_state = JournalReplayFutureState::ReadAllocBitmapJournalFragments {
                        alloc_bitmap_file,
                        image_header_end: image_header::MutableImageHeader::physical_location(image_layout, salt_len)
                            .end(),
                        read_alloc_bitmap_journal_fragments_fut,
                    };
                }
                JournalReplayFutureState::ReadAllocBitmapJournalFragments {
                    alloc_bitmap_file,
                    image_header_end,
                    read_alloc_bitmap_journal_fragments_fut,
                } => {
                    let apply_writes_script = match this.apply_writes_script.as_ref() {
                        Some(apply_writes_script) => apply_writes_script,
                        None => {
                            this.fut_state = JournalReplayFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };
                    let auth_tree_config = match this.auth_tree_config.as_ref() {
                        Some(auth_tree_config) => auth_tree_config,
                        None => {
                            this.fut_state = JournalReplayFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };
                    let alloc_bitmap_journal_fragments =
                        match alloc_bitmap::AllocBitmapFileReadJournalFragmentsFuture::poll(
                            pin::Pin::new(read_alloc_bitmap_journal_fragments_fut),
                            chip,
                            alloc_bitmap_file,
                            image_layout,
                            auth_tree_config,
                            *image_header_end,
                            apply_writes_script,
                            this.journal_staging_copy_undisguise.as_ref(),
                            cx,
                        ) {
                            task::Poll::Ready(Ok(alloc_bitmap_journal_fragments)) => alloc_bitmap_journal_fragments,
                            task::Poll::Ready(Err(e)) => {
                                this.fut_state = JournalReplayFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    let mutable_image_header = match this.mutable_image_header.as_ref() {
                        Some(mutable_image_header) => mutable_image_header,
                        None => {
                            this.fut_state = JournalReplayFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    let journal_log_head_extent =
                        match JournalLog::head_extent_physical_location(image_layout, *image_header_end) {
                            Ok(journal_log_head_extent) => journal_log_head_extent.0,
                            Err(e) => {
                                this.fut_state = JournalReplayFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                        };

                    let update_auth_digests_script = match this.update_auth_digests_script.take() {
                        Some(update_auth_digests_script) => update_auth_digests_script,
                        None => {
                            this.fut_state = JournalReplayFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    let replay_writes_fut = match JournalReplayWritesFuture::new(
                        chip,
                        image_layout,
                        auth_tree_config,
                        *image_header_end,
                        &journal_log_head_extent,
                        mutable_image_header.image_size,
                        alloc_bitmap_journal_fragments,
                        update_auth_digests_script,
                    ) {
                        Ok(replay_writes_fut) => replay_writes_fut,
                        Err(e) => {
                            this.fut_state = JournalReplayFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    this.fut_state = JournalReplayFutureState::ReplayWrites { replay_writes_fut };
                }
                JournalReplayFutureState::ReplayWrites { replay_writes_fut } => {
                    let apply_writes_script = match this.apply_writes_script.as_ref() {
                        Some(apply_writes_script) => apply_writes_script,
                        None => {
                            this.fut_state = JournalReplayFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };
                    let auth_tree_config = match this.auth_tree_config.as_ref() {
                        Some(auth_tree_config) => auth_tree_config,
                        None => {
                            this.fut_state = JournalReplayFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    match JournalReplayWritesFuture::poll(
                        pin::Pin::new(replay_writes_fut),
                        chip,
                        auth_tree_config,
                        apply_writes_script,
                        this.journal_staging_copy_undisguise.as_ref(),
                        cx,
                    ) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => {
                            this.fut_state = JournalReplayFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let cleanup_fut = JournalCleanupFuture::new(this.enable_trimming);
                    this.fut_state = JournalReplayFutureState::Cleanup { cleanup_fut };
                }
                JournalReplayFutureState::Cleanup { cleanup_fut } => {
                    let apply_writes_script = match this.apply_writes_script.as_ref() {
                        Some(apply_writes_script) => apply_writes_script,
                        None => {
                            this.fut_state = JournalReplayFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };
                    let journal_log_extents = match this.journal_log_extents.as_ref() {
                        Some(journal_log_extents) => journal_log_extents,
                        None => {
                            this.fut_state = JournalReplayFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    match JournalCleanupFuture::poll(
                        pin::Pin::new(cleanup_fut),
                        chip,
                        image_layout,
                        salt_len,
                        journal_log_extents,
                        apply_writes_script,
                        this.trim_script.as_ref(),
                        cx,
                    ) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => {
                            this.fut_state = JournalReplayFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    this.fut_state = JournalReplayFutureState::Done;
                    return task::Poll::Ready(Ok(()));
                }
                JournalReplayFutureState::Done => unreachable!(),
            }
        }
    }
}

/// Read the filesystem's
/// [`MutableImageHeader`](image_header::MutableImageHeader) through
/// the journal.
///
/// Read the filesystem's
/// [`MutableImageHeader`](image_header::MutableImageHeader) in the state as if
/// the any updates to it recorded in the journal had been applied already.
struct JournalReadMutableImageHeaderFuture<C: chip::NvChip> {
    mutable_image_header_allocation_blocks_range: layout::PhysicalAllocBlockRange,
    cur_target_allocation_block_index: layout::PhysicalAllocBlockIndex,
    apply_writes_script_index: usize,
    buffer: FixedVec<u8, 7>,
    fut_state: JournalReadMutableImageHeaderFutureState<C>,
}

/// [`JournalReadMutableImageHeaderFuture`] state-machine state.
enum JournalReadMutableImageHeaderFutureState<C: chip::NvChip> {
    PrepareReadPart,
    ReadPart {
        cur_read_range_allocation_blocks: layout::AllocBlockCount,
        read_fut: C::ReadFuture<JournalReadMutableImageHeaderPartNvChipRequest>,
    },
    Done,
}

impl<C: chip::NvChip> JournalReadMutableImageHeaderFuture<C> {
    /// Instantiate a [`JournalReadMutableImageHeaderFuture`].
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `salt_len` - Length of the salt found in the filesystem's
    ///   [`StaticImageHeader`](image_header::StaticImageHeader).
    fn new(chip: &C, image_layout: &layout::ImageLayout, salt_len: u8) -> Result<Self, NvFsError> {
        let mutable_image_header_allocation_blocks_range =
            image_header::MutableImageHeader::physical_location(image_layout, salt_len);
        let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
        let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();
        let chip_io_block_allocation_blocks_log2 =
            chip_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);
        // The mutable header's beginning is aligned to the IO Block size, hence to the
        // Chip IO Block size.
        debug_assert_eq!(
            mutable_image_header_allocation_blocks_range
                .begin()
                .align_down(chip_io_block_allocation_blocks_log2),
            mutable_image_header_allocation_blocks_range.begin()
        );
        let aligned_mutable_image_header_allocation_blocks_end = mutable_image_header_allocation_blocks_range
            .end()
            .align_up(chip_io_block_allocation_blocks_log2)
            .ok_or(NvFsError::IoError(NvFsIoError::RegionOutOfRange))?;
        if u64::from(aligned_mutable_image_header_allocation_blocks_end)
            > u64::MAX >> (allocation_block_size_128b_log2 + 7)
        {
            return Err(NvFsError::IoError(NvFsIoError::RegionOutOfRange));
        }
        let mutable_image_header_allocation_blocks_range = layout::PhysicalAllocBlockRange::new(
            mutable_image_header_allocation_blocks_range.begin(),
            aligned_mutable_image_header_allocation_blocks_end,
        );

        let buffer_len = usize::try_from(
            u64::from(mutable_image_header_allocation_blocks_range.block_count())
                << (allocation_block_size_128b_log2 + 7),
        )
        .map_err(|_| NvFsError::DimensionsNotSupported)?;
        let buffer = FixedVec::new_with_default(buffer_len)?;

        Ok(Self {
            mutable_image_header_allocation_blocks_range,
            cur_target_allocation_block_index: mutable_image_header_allocation_blocks_range.begin(),
            apply_writes_script_index: 0,
            buffer,
            fut_state: JournalReadMutableImageHeaderFutureState::PrepareReadPart,
        })
    }

    /// Poll the [`JournalReadMutableImageHeaderFuture`] to completion.
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `apply_writes_script` - The [`JournalLog::apply_writes_script`].
    /// * `journal_staging_copy_undisguise` - The
    ///   [`JournalLog::journal_staging_copy_undisguise`].
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    fn poll(
        self: pin::Pin<&mut Self>,
        chip: &C,
        image_layout: &layout::ImageLayout,
        apply_writes_script: &JournalApplyWritesScript,
        journal_staging_copy_undisguise: Option<&JournalStagingCopyUndisguise>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<image_header::MutableImageHeader, NvFsError>> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                JournalReadMutableImageHeaderFutureState::PrepareReadPart => {
                    if this.cur_target_allocation_block_index == this.mutable_image_header_allocation_blocks_range.end()
                    {
                        // All read, decode and return.
                        this.fut_state = JournalReadMutableImageHeaderFutureState::Done;
                        return task::Poll::Ready(image_header::MutableImageHeader::decode(
                            io_slices::SingletonIoSlice::new(&this.buffer).map_infallible_err(),
                            image_layout,
                        ));
                    }

                    while this.apply_writes_script_index != apply_writes_script.len()
                        && apply_writes_script[this.apply_writes_script_index]
                            .get_target_range()
                            .end()
                            <= this.cur_target_allocation_block_index
                    {
                        this.apply_writes_script_index += 1;
                    }

                    let read_range = if this.apply_writes_script_index == apply_writes_script.len() {
                        layout::PhysicalAllocBlockRange::new(
                            this.cur_target_allocation_block_index,
                            this.mutable_image_header_allocation_blocks_range.end(),
                        )
                    } else {
                        let apply_writes_script_entry = &apply_writes_script[this.apply_writes_script_index];

                        if this.cur_target_allocation_block_index < apply_writes_script_entry.get_target_range().begin()
                        {
                            layout::PhysicalAllocBlockRange::new(
                                this.cur_target_allocation_block_index,
                                this.mutable_image_header_allocation_blocks_range
                                    .end()
                                    .min(apply_writes_script_entry.get_target_range().begin()),
                            )
                        } else {
                            layout::PhysicalAllocBlockRange::new(
                                apply_writes_script_entry.get_journal_staging_copy_allocation_blocks_begin()
                                    + (this.cur_target_allocation_block_index
                                        - apply_writes_script_entry.get_target_range().begin()),
                                apply_writes_script_entry.get_journal_staging_copy_allocation_blocks_begin()
                                    + (this
                                        .mutable_image_header_allocation_blocks_range
                                        .end()
                                        .min(apply_writes_script_entry.get_target_range().end())
                                        - apply_writes_script_entry.get_target_range().begin()),
                            )
                        }
                    };

                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                    let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();
                    let request_region = match ChunkedIoRegion::new(
                        u64::from(read_range.begin()) << allocation_block_size_128b_log2,
                        u64::from(read_range.end()) << allocation_block_size_128b_log2,
                        chip_io_block_size_128b_log2,
                    )
                    .map_err(|e| match e {
                        ChunkedIoRegionError::ChunkSizeOverflow => nvfs_err_internal!(),
                        ChunkedIoRegionError::InvalidBounds => nvfs_err_internal!(),
                        ChunkedIoRegionError::ChunkIndexOverflow => {
                            // Even the total region's length in units of Bytes fits an usize.
                            nvfs_err_internal!()
                        }
                        ChunkedIoRegionError::RegionUnaligned => {
                            // All read requests are aligned to the Chip IO block size.
                            nvfs_err_internal!()
                        }
                    }) {
                        Ok(request_region) => request_region,
                        Err(e) => {
                            this.fut_state = JournalReadMutableImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    let chip_io_block_allocation_blocks_log2 =
                        chip_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);
                    let allocation_bock_chip_io_blocks_log2 =
                        allocation_block_size_128b_log2.saturating_sub(chip_io_block_size_128b_log2);
                    let chip_io_block_index_offset = (u64::from(
                        this.cur_target_allocation_block_index
                            - this.mutable_image_header_allocation_blocks_range.begin(),
                    ) >> chip_io_block_allocation_blocks_log2
                        << allocation_bock_chip_io_blocks_log2)
                        as usize;
                    let read_request = JournalReadMutableImageHeaderPartNvChipRequest {
                        region: request_region,
                        buffer: mem::take(&mut this.buffer),
                        chip_io_block_index_offset,
                    };
                    let read_fut = match chip.read(read_request) {
                        Ok(Ok(read_fut)) => read_fut,
                        Err(e) | Ok(Err((_, e))) => {
                            this.fut_state = JournalReadMutableImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    this.fut_state = JournalReadMutableImageHeaderFutureState::ReadPart {
                        cur_read_range_allocation_blocks: read_range.block_count(),
                        read_fut,
                    };
                }
                JournalReadMutableImageHeaderFutureState::ReadPart {
                    cur_read_range_allocation_blocks,
                    read_fut,
                } => {
                    let read_request = match chip::NvChipFuture::poll(pin::Pin::new(read_fut), chip, cx) {
                        task::Poll::Ready(Ok((read_request, Ok(())))) => read_request,
                        task::Poll::Ready(Err(e) | Ok((_, Err(e)))) => {
                            this.fut_state = JournalReadMutableImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    let JournalReadMutableImageHeaderPartNvChipRequest {
                        region: _,
                        buffer,
                        chip_io_block_index_offset: _,
                    } = read_request;
                    this.buffer = buffer;

                    // If the part had been read from the Journal Staging Copy and disguising is
                    // enabled, undisguise.
                    if let Some(journal_staging_copy_undisguise) = journal_staging_copy_undisguise {
                        if this.apply_writes_script_index < apply_writes_script.len()
                            && apply_writes_script[this.apply_writes_script_index]
                                .get_target_range()
                                .begin()
                                <= this.cur_target_allocation_block_index
                        {
                            let mut undisguise_processor = match journal_staging_copy_undisguise.instantiate_processor()
                            {
                                Ok(undisguise_processor) => undisguise_processor,
                                Err(e) => {
                                    this.fut_state = JournalReadMutableImageHeaderFutureState::Done;
                                    return task::Poll::Ready(Err(e));
                                }
                            };

                            let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                            let apply_writes_script_entry = &apply_writes_script[this.apply_writes_script_index];
                            for allocation_block_index_in_cur_read_range in
                                0..u64::from(*cur_read_range_allocation_blocks)
                            {
                                let cur_target_allocation_block_index = this.cur_target_allocation_block_index
                                    + layout::AllocBlockCount::from(allocation_block_index_in_cur_read_range);
                                let cur_journal_staging_copy_allocation_block_index = apply_writes_script_entry
                                    .get_journal_staging_copy_allocation_blocks_begin()
                                    + (cur_target_allocation_block_index
                                        - apply_writes_script_entry.get_target_range().begin());

                                let allocation_block_buf = &mut this.buffer[(u64::from(
                                    cur_target_allocation_block_index
                                        - this.mutable_image_header_allocation_blocks_range.begin(),
                                ) as usize)
                                    << (allocation_block_size_128b_log2 + 7)
                                    ..(u64::from(
                                        cur_target_allocation_block_index
                                            - this.mutable_image_header_allocation_blocks_range.begin(),
                                    ) as usize
                                        + 1)
                                        << (allocation_block_size_128b_log2 + 7)];
                                if let Err(e) = undisguise_processor.undisguise_journal_staging_copy_allocation_block(
                                    cur_journal_staging_copy_allocation_block_index,
                                    cur_target_allocation_block_index,
                                    allocation_block_buf,
                                ) {
                                    this.fut_state = JournalReadMutableImageHeaderFutureState::Done;
                                    return task::Poll::Ready(Err(e));
                                }
                            }
                        }
                    }

                    this.cur_target_allocation_block_index += *cur_read_range_allocation_blocks;
                    this.fut_state = JournalReadMutableImageHeaderFutureState::PrepareReadPart;
                }
                JournalReadMutableImageHeaderFutureState::Done => unreachable!(),
            }
        }
    }
}

/// [`NvChipReadRequest`](chip::NvChipReadRequest) implementation used
/// internally by [`JournalReadMutableImageHeaderFuture`].
struct JournalReadMutableImageHeaderPartNvChipRequest {
    region: ChunkedIoRegion,
    buffer: FixedVec<u8, 7>,
    chip_io_block_index_offset: usize,
}

impl chip::NvChipReadRequest for JournalReadMutableImageHeaderPartNvChipRequest {
    fn region(&self) -> &ChunkedIoRegion {
        &self.region
    }

    fn get_destination_buffer(
        &mut self,
        range: &ChunkedIoRegionChunkRange,
    ) -> Result<Option<&mut [u8]>, chip::NvChipIoError> {
        let chip_io_block_index = self.chip_io_block_index_offset + range.chunk().decompose_to_hierarchic_indices([]).0;
        let chip_io_block_size_128b_log2 = self.region.chunk_size_128b_log2();
        Ok(Some(
            &mut self.buffer[chip_io_block_index << (chip_io_block_size_128b_log2 + 7)
                ..(chip_io_block_index + 1) << (chip_io_block_size_128b_log2 + 7)][range.range_in_chunk().clone()],
        ))
    }
}

/// Replay the data writes recorded in [`JournalLog::apply_writes_script`] and
/// update the authentication tree in the course.
struct JournalReplayWritesFuture<C: chip::NvChip> {
    image_size: layout::AllocBlockCount,
    apply_writes_script_index: usize,
    next_target_allocation_block_index: layout::PhysicalAllocBlockIndex,
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self.
    auth_tree_updates_replay_cursor: Option<Box<auth_tree::AuthTreeReplayJournalUpdateScriptCursor>>,
    buffers: FixedVec<FixedVec<u8, 7>, 0>,
    fut_state: JournalReplayWritesFutureState<C>,
    allocation_block_size_128b_log2: u8,
    chip_io_block_allocation_blocks_log2: u8,
    preferred_chip_io_bulk_allocation_blocks_log2: u8,
}

/// [`JournalReplayWritesFuture`] state-machine state.
enum JournalReplayWritesFutureState<C: chip::NvChip> {
    Init,
    AdvanceAuthTreeCursor {
        advance_auth_tree_cursor_fut: auth_tree::AuthTreeReplayJournalUpdateScriptCursorAdvanceFuture<C>,
    },
    PrepareReadStagingCopy,
    ReadStagingCopy {
        cur_target_range: layout::PhysicalAllocBlockRange,
        read_fut: C::ReadFuture<ReadJournalStagingCopyNvChipRequest>,
    },
    WriteToTarget {
        cur_target_range_allocation_blocks: layout::AllocBlockCount,
        write_fut: C::WriteFuture<WriteTargetNvChipRequest>,
    },
    UpdateAuthTree {
        next_allocation_block_index_in_cur_target_range: layout::AllocBlockCount,
        cur_target_range_allocation_blocks: layout::AllocBlockCount,
        auth_tree_write_part_fut: Option<auth_tree::AuthTreeReplayJournalUpdateScriptCursorWritePartFuture<C>>,
    },
    FinalizeAuthTreeUpdatesReplay {
        auth_tree_replay_remainder_fut: auth_tree::AuthTreeReplayJournalUpdateScriptCursorAdvanceFuture<C>,
    },
    Done,
}

impl<C: chip::NvChip> JournalReplayWritesFuture<C> {
    /// Instantiate a [`JournalReplayWritesFuture`].
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `auth_tree_config` - The filesystem's
    ///   [`AuthTreeConfig`](auth_tree::AuthTreeConfig).
    /// * `image_header_end` - [End of the filesystem image header on
    ///   storage](image_header::MutableImageHeader::physical_location).
    /// * `journal_log_head_extent` - The filesystem's fixed [journal log head
    ///   extent](JournalLog::head_extent_physical_location)
    /// * `image_size` - The filesystem image size as found in the filesystem's
    ///   [`MutableImageHeader::image_size`](image_header::MutableImageHeader::image_size).
    /// * `alloc_bitmap_journal_fragments` - Allocation bitmap with valid
    ///   entries for the parts covered by
    ///   [`JournalLog::alloc_bitmap_file_fragments_auth_digests`].
    /// * `update_auth_digests_script` - The
    ///   [`JournalLog::update_auth_digests_script`].
    #[allow(clippy::too_many_arguments)]
    fn new(
        chip: &C,
        image_layout: &layout::ImageLayout,
        auth_tree_config: &auth_tree::AuthTreeConfig,
        image_header_end: layout::PhysicalAllocBlockIndex,
        journal_log_head_extent: &layout::PhysicalAllocBlockRange,
        image_size: layout::AllocBlockCount,
        alloc_bitmap_journal_fragments: alloc_bitmap::AllocBitmap,
        update_auth_digests_script: JournalUpdateAuthDigestsScript,
    ) -> Result<Self, NvFsError> {
        let auth_tree_updates_replay_cursor = auth_tree::AuthTreeReplayJournalUpdateScriptCursor::new(
            image_layout,
            auth_tree_config,
            image_header_end,
            journal_log_head_extent,
            image_size,
            alloc_bitmap_journal_fragments,
            update_auth_digests_script,
        )?;

        let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
        let io_block_allocation_blocks_log2 = image_layout.io_block_allocation_blocks_log2 as u32;
        let auth_tree_data_block_allocation_blocks_log2 =
            image_layout.auth_tree_data_block_allocation_blocks_log2 as u32;
        let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();
        let chip_io_block_allocation_blocks_log2 =
            chip_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);
        // Determine the chip's preferred bulk IO block size, ramp it up to a reasonable
        // value.
        let preferred_chip_io_bulk_allocation_blocks_log2 = (chip.preferred_chip_io_blocks_bulk_log2()
            + chip_io_block_size_128b_log2)
            .saturating_sub(allocation_block_size_128b_log2)
            .min(usize::BITS - 1 + chip_io_block_allocation_blocks_log2)
            .max(io_block_allocation_blocks_log2)
            .max(auth_tree_data_block_allocation_blocks_log2);

        let mut buffers = FixedVec::new_with_default(
            1usize << (preferred_chip_io_bulk_allocation_blocks_log2 - chip_io_block_allocation_blocks_log2),
        )?;
        for buffer in buffers.iter_mut() {
            *buffer = FixedVec::new_with_default(
                1usize << (chip_io_block_allocation_blocks_log2 + allocation_block_size_128b_log2 + 7),
            )?;
        }

        Ok(Self {
            image_size,
            apply_writes_script_index: 0,
            next_target_allocation_block_index: layout::PhysicalAllocBlockIndex::from(0u64),
            auth_tree_updates_replay_cursor: Some(auth_tree_updates_replay_cursor),
            buffers,
            fut_state: JournalReplayWritesFutureState::Init,
            allocation_block_size_128b_log2: image_layout.allocation_block_size_128b_log2,
            chip_io_block_allocation_blocks_log2: chip_io_block_allocation_blocks_log2 as u8,
            preferred_chip_io_bulk_allocation_blocks_log2: preferred_chip_io_bulk_allocation_blocks_log2 as u8,
        })
    }

    /// Poll the [`JournalReplayWritesFuture`] to completion.
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `auth_tree_config` - The filesystem's
    ///   [`AuthTreeConfig`](auth_tree::AuthTreeConfig).
    /// * `apply_writes_script` - The [`JournalLog::apply_writes_script`].
    /// * `journal_staging_copy_undisguise` - The
    ///   [`JournalLog::journal_staging_copy_undisguise`].
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    fn poll(
        self: pin::Pin<&mut Self>,
        chip: &C,
        auth_tree_config: &auth_tree::AuthTreeConfig,
        apply_writes_script: &JournalApplyWritesScript,
        journal_staging_copy_undisguise: Option<&JournalStagingCopyUndisguise>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), NvFsError>> {
        let this = pin::Pin::into_inner(self);

        'outer: loop {
            match &mut this.fut_state {
                JournalReplayWritesFutureState::Init => {
                    while this.apply_writes_script_index != apply_writes_script.len() {
                        let cur_apply_writes_script_entry = &apply_writes_script[this.apply_writes_script_index];
                        if cur_apply_writes_script_entry.get_journal_staging_copy_allocation_blocks_begin()
                            != cur_apply_writes_script_entry.get_target_range().begin()
                            && this.next_target_allocation_block_index
                                < cur_apply_writes_script_entry.get_target_range().end()
                        {
                            break;
                        }

                        this.apply_writes_script_index += 1;
                    }
                    if this.apply_writes_script_index == apply_writes_script.len() {
                        let auth_tree_updates_replay_cursor = match this.auth_tree_updates_replay_cursor.take() {
                            Some(auth_tree_updates_replay_cursor) => auth_tree_updates_replay_cursor,
                            None => {
                                this.fut_state = JournalReplayWritesFutureState::Done;
                                return task::Poll::Ready(Err(nvfs_err_internal!()));
                            }
                        };
                        let auth_tree_replay_remainder_fut = match auth_tree_updates_replay_cursor.advance_to(
                            chip,
                            layout::PhysicalAllocBlockIndex::from(0u64) + this.image_size,
                            auth_tree_config,
                        ) {
                            Ok(auth_tree_replay_remainder_fut) => auth_tree_replay_remainder_fut,
                            Err(e) => {
                                this.fut_state = JournalReplayWritesFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                        };
                        this.fut_state = JournalReplayWritesFutureState::FinalizeAuthTreeUpdatesReplay {
                            auth_tree_replay_remainder_fut,
                        };
                        continue;
                    }

                    let cur_apply_writes_script_entry = &apply_writes_script[this.apply_writes_script_index];
                    if this.next_target_allocation_block_index
                        <= cur_apply_writes_script_entry.get_target_range().begin()
                    {
                        if cur_apply_writes_script_entry.get_target_range().end()
                            > layout::PhysicalAllocBlockIndex::from(0u64) + this.image_size
                        {
                            this.fut_state = JournalReplayWritesFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(
                                CocoonFsFormatError::InvalidJournalApplyWritesScriptEntry,
                            )));
                        }
                        this.next_target_allocation_block_index =
                            cur_apply_writes_script_entry.get_target_range().begin();
                        let auth_tree_updates_replay_cursor = match this.auth_tree_updates_replay_cursor.take() {
                            Some(auth_tree_updates_replay_cursor) => auth_tree_updates_replay_cursor,
                            None => {
                                this.fut_state = JournalReplayWritesFutureState::Done;
                                return task::Poll::Ready(Err(nvfs_err_internal!()));
                            }
                        };
                        let advance_auth_tree_cursor_fut = match auth_tree_updates_replay_cursor.advance_to(
                            chip,
                            cur_apply_writes_script_entry.get_target_range().begin(),
                            auth_tree_config,
                        ) {
                            Ok(advance_auth_tree_cursor_fut) => advance_auth_tree_cursor_fut,
                            Err(e) => {
                                this.fut_state = JournalReplayWritesFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                        };
                        this.fut_state = JournalReplayWritesFutureState::AdvanceAuthTreeCursor {
                            advance_auth_tree_cursor_fut,
                        };
                    } else {
                        this.fut_state = JournalReplayWritesFutureState::PrepareReadStagingCopy;
                    }
                }
                JournalReplayWritesFutureState::AdvanceAuthTreeCursor {
                    advance_auth_tree_cursor_fut,
                } => {
                    let auth_tree_updates_replay_cursor =
                        match auth_tree::AuthTreeReplayJournalUpdateScriptCursorAdvanceFuture::poll(
                            pin::Pin::new(advance_auth_tree_cursor_fut),
                            chip,
                            auth_tree_config,
                            cx,
                        ) {
                            task::Poll::Ready(Ok(auth_tree_updates_replay_cursor)) => auth_tree_updates_replay_cursor,
                            task::Poll::Ready(Err(e)) => {
                                this.fut_state = JournalReplayWritesFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                            task::Poll::Pending => return task::Poll::Pending,
                        };
                    this.auth_tree_updates_replay_cursor = Some(auth_tree_updates_replay_cursor);
                    this.fut_state = JournalReplayWritesFutureState::PrepareReadStagingCopy;
                }
                JournalReplayWritesFutureState::PrepareReadStagingCopy => {
                    let allocation_block_size_128b_log2 = this.allocation_block_size_128b_log2 as u32;
                    let chip_io_block_allocation_blocks_log2 = this.chip_io_block_allocation_blocks_log2 as u32;
                    let preferred_chip_io_bulk_allocation_blocks_log2 =
                        this.preferred_chip_io_bulk_allocation_blocks_log2 as u32;
                    debug_assert!(
                        u64::from(this.next_target_allocation_block_index)
                            .is_aligned_pow2(chip_io_block_allocation_blocks_log2)
                    );
                    debug_assert!(this.apply_writes_script_index < apply_writes_script.len());
                    let cur_apply_writes_script_entry = &apply_writes_script[this.apply_writes_script_index];
                    debug_assert_ne!(
                        cur_apply_writes_script_entry.get_target_range().begin(),
                        cur_apply_writes_script_entry.get_journal_staging_copy_allocation_blocks_begin()
                    );
                    debug_assert!(
                        (u64::from(cur_apply_writes_script_entry.get_target_range().begin())
                            | u64::from(cur_apply_writes_script_entry.get_target_range().end())
                            | u64::from(
                                cur_apply_writes_script_entry.get_journal_staging_copy_allocation_blocks_begin()
                            ))
                        .is_aligned_pow2(chip_io_block_allocation_blocks_log2)
                    );
                    debug_assert!(
                        this.next_target_allocation_block_index
                            >= cur_apply_writes_script_entry.get_target_range().begin()
                    );
                    if this.next_target_allocation_block_index == cur_apply_writes_script_entry.get_target_range().end()
                    {
                        // The current entry has been completed, continue with the next.
                        this.fut_state = JournalReplayWritesFutureState::Init;
                        continue;
                    }
                    let mut cur_target_range_allocation_blocks_end = this.next_target_allocation_block_index
                        + layout::AllocBlockCount::from(1u64 << chip_io_block_allocation_blocks_log2);
                    debug_assert!(
                        cur_target_range_allocation_blocks_end
                            <= cur_apply_writes_script_entry.get_target_range().end()
                    );
                    while cur_target_range_allocation_blocks_end
                        < cur_apply_writes_script_entry.get_target_range().end()
                    {
                        if (u64::from(this.next_target_allocation_block_index)
                            ^ u64::from(cur_target_range_allocation_blocks_end))
                            >> preferred_chip_io_bulk_allocation_blocks_log2
                            != 0
                        {
                            // Crossing a preferred Chip IO bulk boundary, stop
                            // and process what's been found so far.
                            break;
                        }
                        cur_target_range_allocation_blocks_end +=
                            layout::AllocBlockCount::from(1u64 << chip_io_block_allocation_blocks_log2);
                    }
                    let cur_target_range = layout::PhysicalAllocBlockRange::new(
                        this.next_target_allocation_block_index,
                        cur_target_range_allocation_blocks_end,
                    );
                    this.next_target_allocation_block_index = cur_target_range_allocation_blocks_end;

                    let cur_journal_staging_copy_range_allocation_blocks_begin = cur_apply_writes_script_entry
                        .get_journal_staging_copy_allocation_blocks_begin()
                        + (cur_target_range.begin() - cur_apply_writes_script_entry.get_target_range().begin());
                    let cur_journal_staging_copy_range = layout::PhysicalAllocBlockRange::from((
                        cur_journal_staging_copy_range_allocation_blocks_begin,
                        cur_target_range.block_count(),
                    ));

                    let request_region = match ChunkedIoRegion::new(
                        u64::from(cur_journal_staging_copy_range.begin()) << allocation_block_size_128b_log2,
                        u64::from(cur_journal_staging_copy_range.end()) << allocation_block_size_128b_log2,
                        chip_io_block_allocation_blocks_log2 + allocation_block_size_128b_log2,
                    )
                    .map_err(|e| {
                        match e {
                            ChunkedIoRegionError::ChunkSizeOverflow => nvfs_err_internal!(),
                            ChunkedIoRegionError::InvalidBounds => nvfs_err_internal!(),
                            ChunkedIoRegionError::ChunkIndexOverflow => {
                                // The preferred_chip_io_bulk_allocation_blocks_log2
                                // had been chosen such that it would not overflow an usize in
                                // units of Allocation Blocks.
                                nvfs_err_internal!()
                            }
                            ChunkedIoRegionError::RegionUnaligned => {
                                // All read requests are aligned to the Chip IO block size.
                                nvfs_err_internal!()
                            }
                        }
                    }) {
                        Ok(request_region) => request_region,
                        Err(e) => {
                            this.fut_state = JournalReplayWritesFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    let read_request = ReadJournalStagingCopyNvChipRequest {
                        region: request_region,
                        buffers: mem::take(&mut this.buffers),
                    };
                    let read_fut = match chip.read(read_request) {
                        Ok(Ok(read_fut)) => read_fut,
                        Err(e) | Ok(Err((_, e))) => {
                            this.fut_state = JournalReplayWritesFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    this.fut_state = JournalReplayWritesFutureState::ReadStagingCopy {
                        cur_target_range,
                        read_fut,
                    };
                }
                JournalReplayWritesFutureState::ReadStagingCopy {
                    cur_target_range,
                    read_fut,
                } => {
                    let read_request = match chip::NvChipFuture::poll(pin::Pin::new(read_fut), chip, cx) {
                        task::Poll::Ready(Ok((read_request, Ok(())))) => read_request,
                        task::Poll::Ready(Err(e) | Ok((_, Err(e)))) => {
                            this.fut_state = JournalReplayWritesFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    let ReadJournalStagingCopyNvChipRequest { region: _, mut buffers } = read_request;

                    // Undisguise the Journal Staging Copy in case it's been disguised.
                    let allocation_block_size_128b_log2 = this.allocation_block_size_128b_log2 as u32;
                    let chip_io_block_allocation_blocks_log2 = this.chip_io_block_allocation_blocks_log2 as u32;
                    if let Some(journal_staging_copy_undisguise) = journal_staging_copy_undisguise {
                        let mut undisguise_processor = match journal_staging_copy_undisguise.instantiate_processor() {
                            Ok(undisguise_processor) => undisguise_processor,
                            Err(e) => {
                                this.fut_state = JournalReplayWritesFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                        };

                        let mut cur_target_allocation_block_index = cur_target_range.begin();
                        let cur_apply_writes_script_entry = &apply_writes_script[this.apply_writes_script_index];
                        let mut cur_journal_staging_copy_allocation_block_index = cur_apply_writes_script_entry
                            .get_journal_staging_copy_allocation_blocks_begin()
                            + (cur_target_allocation_block_index
                                - cur_apply_writes_script_entry.get_target_range().begin());

                        while cur_target_allocation_block_index != cur_target_range.end() {
                            let chip_io_block_index =
                                (u64::from(cur_target_allocation_block_index - cur_target_range.begin())
                                    >> chip_io_block_allocation_blocks_log2) as usize;
                            let chip_io_block_buf = &mut buffers[chip_io_block_index];
                            for allocation_block_in_chip_io_block_index in
                                0..1usize << chip_io_block_allocation_blocks_log2
                            {
                                let allocation_block_buf = &mut chip_io_block_buf
                                    [allocation_block_in_chip_io_block_index << (allocation_block_size_128b_log2 + 7)
                                        ..(allocation_block_in_chip_io_block_index + 1)
                                            << (allocation_block_size_128b_log2 + 7)];
                                if let Err(e) = undisguise_processor.undisguise_journal_staging_copy_allocation_block(
                                    cur_journal_staging_copy_allocation_block_index,
                                    cur_target_allocation_block_index,
                                    allocation_block_buf,
                                ) {
                                    this.fut_state = JournalReplayWritesFutureState::Done;
                                    return task::Poll::Ready(Err(e));
                                }
                                cur_target_allocation_block_index += layout::AllocBlockCount::from(1);
                                cur_journal_staging_copy_allocation_block_index += layout::AllocBlockCount::from(1);
                            }
                        }
                    }

                    let request_region = match ChunkedIoRegion::new(
                        u64::from(cur_target_range.begin()) << allocation_block_size_128b_log2,
                        u64::from(cur_target_range.end()) << allocation_block_size_128b_log2,
                        chip_io_block_allocation_blocks_log2 + allocation_block_size_128b_log2,
                    )
                    .map_err(|e| {
                        match e {
                            ChunkedIoRegionError::ChunkSizeOverflow => nvfs_err_internal!(),
                            ChunkedIoRegionError::InvalidBounds => nvfs_err_internal!(),
                            ChunkedIoRegionError::ChunkIndexOverflow => {
                                // The preferred_chip_io_bulk_allocation_blocks_log2
                                // had been chosen such that it would not overflow an usize in
                                // units of Allocation Blocks.
                                nvfs_err_internal!()
                            }
                            ChunkedIoRegionError::RegionUnaligned => {
                                // All read requests are aligned to the Chip IO block size.
                                nvfs_err_internal!()
                            }
                        }
                    }) {
                        Ok(request_region) => request_region,
                        Err(e) => {
                            this.fut_state = JournalReplayWritesFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    let write_request = WriteTargetNvChipRequest {
                        region: request_region,
                        buffers,
                    };
                    let write_fut = match chip.write(write_request) {
                        Ok(Ok(write_fut)) => write_fut,
                        Err(e) | Ok(Err((_, e))) => {
                            this.fut_state = JournalReplayWritesFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    this.fut_state = JournalReplayWritesFutureState::WriteToTarget {
                        cur_target_range_allocation_blocks: cur_target_range.block_count(),
                        write_fut,
                    };
                }
                JournalReplayWritesFutureState::WriteToTarget {
                    cur_target_range_allocation_blocks,
                    write_fut,
                } => {
                    let write_request = match chip::NvChipFuture::poll(pin::Pin::new(write_fut), chip, cx) {
                        task::Poll::Ready(Ok((write_request, Ok(())))) => write_request,
                        task::Poll::Ready(Err(e) | Ok((_, Err(e)))) => {
                            this.fut_state = JournalReplayWritesFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    let WriteTargetNvChipRequest { region: _, buffers } = write_request;
                    this.buffers = buffers;

                    this.fut_state = JournalReplayWritesFutureState::UpdateAuthTree {
                        next_allocation_block_index_in_cur_target_range: layout::AllocBlockCount::from(0u64),
                        cur_target_range_allocation_blocks: *cur_target_range_allocation_blocks,
                        auth_tree_write_part_fut: None,
                    };
                }
                JournalReplayWritesFutureState::UpdateAuthTree {
                    next_allocation_block_index_in_cur_target_range,
                    cur_target_range_allocation_blocks,
                    auth_tree_write_part_fut: fut_auth_tree_write_part_fut,
                } => {
                    let mut auth_tree_updates_replay_cursor = match fut_auth_tree_write_part_fut {
                        Some(auth_tree_write_part_fut) => {
                            match auth_tree::AuthTreeReplayJournalUpdateScriptCursorWritePartFuture::poll(
                                pin::Pin::new(auth_tree_write_part_fut),
                                chip,
                                auth_tree_config,
                                cx,
                            ) {
                                task::Poll::Ready(Ok(auth_tree_updates_replay_cursor)) => {
                                    *fut_auth_tree_write_part_fut = None;
                                    auth_tree_updates_replay_cursor
                                }
                                task::Poll::Ready(Err(e)) => {
                                    this.fut_state = JournalReplayWritesFutureState::Done;
                                    return task::Poll::Ready(Err(e));
                                }
                                task::Poll::Pending => return task::Poll::Pending,
                            }
                        }
                        None => match this.auth_tree_updates_replay_cursor.take() {
                            Some(auth_tree_updates_replay_cursor) => auth_tree_updates_replay_cursor,
                            None => {
                                this.fut_state = JournalReplayWritesFutureState::Done;
                                return task::Poll::Ready(Err(nvfs_err_internal!()));
                            }
                        },
                    };

                    let allocation_block_size_128b_log2 = this.allocation_block_size_128b_log2 as u32;
                    let chip_io_block_allocation_blocks_log2 = this.chip_io_block_allocation_blocks_log2 as u32;
                    while next_allocation_block_index_in_cur_target_range != cur_target_range_allocation_blocks {
                        let chip_io_block_index = u64::from(*next_allocation_block_index_in_cur_target_range)
                            >> chip_io_block_allocation_blocks_log2;
                        let allocation_block_in_chip_io_block_index =
                            (u64::from(*next_allocation_block_index_in_cur_target_range)
                                - (chip_io_block_index << chip_io_block_allocation_blocks_log2))
                                as usize;
                        let chip_io_block_index = chip_io_block_index as usize;
                        *next_allocation_block_index_in_cur_target_range =
                            *next_allocation_block_index_in_cur_target_range + layout::AllocBlockCount::from(1u64);

                        let allocation_block_buf = &this.buffers[chip_io_block_index]
                            [allocation_block_in_chip_io_block_index << (allocation_block_size_128b_log2 + 7)
                                ..(allocation_block_in_chip_io_block_index + 1)
                                    << (allocation_block_size_128b_log2 + 7)];
                        auth_tree_updates_replay_cursor = match auth_tree_updates_replay_cursor
                            .update(auth_tree_config, allocation_block_buf)
                        {
                            Ok(auth_tree::AuthTreeReplayJournalUpdateScriptCursorUpdateResult::Done { cursor }) => {
                                cursor
                            }
                            Ok(
                                auth_tree::AuthTreeReplayJournalUpdateScriptCursorUpdateResult::NeedAuthTreePartWrite {
                                    write_fut,
                                },
                            ) => {
                                *fut_auth_tree_write_part_fut = Some(write_fut);
                                continue 'outer;
                            }
                            Err(e) => {
                                this.fut_state = JournalReplayWritesFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                        };
                    }

                    this.auth_tree_updates_replay_cursor = Some(auth_tree_updates_replay_cursor);
                    this.fut_state = JournalReplayWritesFutureState::PrepareReadStagingCopy;
                }
                JournalReplayWritesFutureState::FinalizeAuthTreeUpdatesReplay {
                    auth_tree_replay_remainder_fut,
                } => {
                    match auth_tree::AuthTreeReplayJournalUpdateScriptCursorAdvanceFuture::poll(
                        pin::Pin::new(auth_tree_replay_remainder_fut),
                        chip,
                        auth_tree_config,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(_auth_tree_updates_replay_cursor)) => (),
                        task::Poll::Ready(Err(e)) => {
                            this.fut_state = JournalReplayWritesFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    this.fut_state = JournalReplayWritesFutureState::Done;
                    return task::Poll::Ready(Ok(()));
                }
                JournalReplayWritesFutureState::Done => unreachable!(),
            }
        }
    }
}

/// [`NvChipReadRequest`](chip::NvChipReadRequest) implementation used
/// internally by [`JournalReplayWritesFuture`].
struct ReadJournalStagingCopyNvChipRequest {
    region: ChunkedIoRegion,
    buffers: FixedVec<FixedVec<u8, 7>, 0>,
}

impl chip::NvChipReadRequest for ReadJournalStagingCopyNvChipRequest {
    fn region(&self) -> &chip::ChunkedIoRegion {
        &self.region
    }

    fn get_destination_buffer(
        &mut self,
        range: &ChunkedIoRegionChunkRange,
    ) -> Result<Option<&mut [u8]>, chip::NvChipIoError> {
        let chip_io_block_index = range.chunk().decompose_to_hierarchic_indices([]).0;
        Ok(Some(
            &mut self.buffers[chip_io_block_index][range.range_in_chunk().clone()],
        ))
    }
}

/// [`NvChipWriteRequest`](chip::NvChipWriteRequest) implementation used
/// internally by [`JournalReplayWritesFuture`].
struct WriteTargetNvChipRequest {
    region: chip::ChunkedIoRegion,
    buffers: FixedVec<FixedVec<u8, 7>, 0>,
}

impl chip::NvChipWriteRequest for WriteTargetNvChipRequest {
    fn region(&self) -> &ChunkedIoRegion {
        &self.region
    }

    fn get_source_buffer(&self, range: &ChunkedIoRegionChunkRange) -> Result<&[u8], chip::NvChipIoError> {
        let chip_io_block_index = range.chunk().decompose_to_hierarchic_indices([]).0;
        Ok(&self.buffers[chip_io_block_index][range.range_in_chunk().clone()])
    }
}

/// Invalidate and cleanup the journal after replay.
struct JournalCleanupFuture<C: chip::NvChip> {
    enable_trimming: bool,
    fut_state: JournalCleanupFutureState<C>,
}

/// [`JournalCleanupFuture`] state-machine state.
enum JournalCleanupFutureState<C: chip::NvChip> {
    Init,
    InvalidateJournalLogHead {
        image_header_end: layout::PhysicalAllocBlockIndex,
        invalidate_journal_log_fut: JournalLogInvalidateFuture<C>,
    },
    WriteBarrierBeforeTrim {
        write_barrier_fut: C::WriteBarrierFuture,
    },
    TrimJournalLogExtentPrepare {
        journal_log_extents_index: usize,
    },
    TrimJournalLogExtent {
        next_journal_log_extents_index: usize,
        trim_fut: C::TrimFuture,
    },
    TrimJournalStagingCopyPrepare {
        apply_writes_script_index: usize,
    },
    TrimJournalStagingCopy {
        next_apply_writes_script_index: usize,
        trim_fut: C::TrimFuture,
    },
    TrimTrimScriptEntryPrepare {
        trim_script_index: usize,
    },
    TrimTrimScriptEntry {
        next_trim_script_index: usize,
        trim_fut: C::TrimFuture,
    },
    Done,
}

impl<C: chip::NvChip> JournalCleanupFuture<C> {
    /// Instantiate a [`JournalCleanupFuture`].
    ///
    /// # Arguments:
    ///
    /// * `enable_trimming` - Whether or not to submit [trim
    ///   commands](chip::NvChip::trim) to the underlying storage.
    fn new(enable_trimming: bool) -> Self {
        Self {
            enable_trimming,
            fut_state: JournalCleanupFutureState::Init,
        }
    }

    /// Poll the [`JournalCleanupFuture`] to completion.
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `salt_len` - Length of the salt found in the filesystem's
    ///   [`StaticImageHeader`](image_header::StaticImageHeader).
    /// * `journal_log_extents` - The [`JournalLog::log_extents`].
    /// * `apply_writes_script` - The [`JournalLog::apply_writes_script`].
    /// * `trim_script` - The [`JournalLog::trim_script`].
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    #[allow(clippy::too_many_arguments)]
    fn poll(
        self: pin::Pin<&mut Self>,
        chip: &C,
        image_layout: &layout::ImageLayout,
        salt_len: u8,
        journal_log_extents: &extents::PhysicalExtents,
        apply_writes_script: &JournalApplyWritesScript,
        trim_script: Option<&JournalTrimsScript>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), NvFsError>> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                JournalCleanupFutureState::Init => {
                    let image_header_end =
                        image_header::MutableImageHeader::physical_location(image_layout, salt_len).end();
                    let invalidate_journal_log_fut = JournalLogInvalidateFuture::new(false);
                    this.fut_state = JournalCleanupFutureState::InvalidateJournalLogHead {
                        image_header_end,
                        invalidate_journal_log_fut,
                    };
                }
                JournalCleanupFutureState::InvalidateJournalLogHead {
                    image_header_end,
                    invalidate_journal_log_fut,
                } => {
                    match JournalLogInvalidateFuture::poll(
                        pin::Pin::new(invalidate_journal_log_fut),
                        chip,
                        image_layout,
                        *image_header_end,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => {
                            this.fut_state = JournalCleanupFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    // If trimming had been disabled now or at Journal write-out time, skip it.
                    if !this.enable_trimming || trim_script.is_none() {
                        this.fut_state = JournalCleanupFutureState::Done;
                        return task::Poll::Ready(Ok(()));
                    }

                    let write_barrier_fut = match chip.write_barrier() {
                        Ok(write_barrier_fut) => write_barrier_fut,
                        Err(_) => {
                            // A write barrier is needed before trimming, but failure to trim is considered
                            // non-fatal. Simply return.
                            this.fut_state = JournalCleanupFutureState::Done;
                            return task::Poll::Ready(Ok(()));
                        }
                    };
                    this.fut_state = JournalCleanupFutureState::WriteBarrierBeforeTrim { write_barrier_fut };
                }
                JournalCleanupFutureState::WriteBarrierBeforeTrim { write_barrier_fut } => {
                    match chip::NvChipFuture::poll(pin::Pin::new(write_barrier_fut), chip, cx) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(_)) => {
                            // A write barrier is needed before trimming, but failure to trim is considered
                            // non-fatal, return with success.
                            this.fut_state = JournalCleanupFutureState::Done;
                            return task::Poll::Ready(Ok(()));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    // Don't trim the Journal Log head extent, so start at index 1.
                    this.fut_state = JournalCleanupFutureState::TrimJournalLogExtentPrepare {
                        journal_log_extents_index: 1,
                    };
                }
                JournalCleanupFutureState::TrimJournalLogExtentPrepare {
                    journal_log_extents_index,
                } => {
                    if *journal_log_extents_index == journal_log_extents.len() {
                        this.fut_state = JournalCleanupFutureState::TrimJournalStagingCopyPrepare {
                            apply_writes_script_index: 0,
                        };
                        continue;
                    }
                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                    let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();
                    let chip_io_block_allocation_blocks_log2 =
                        chip_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);
                    let allocation_block_chip_io_blocks_log2 =
                        allocation_block_size_128b_log2.saturating_sub(chip_io_block_size_128b_log2);
                    let journal_log_extent = journal_log_extents.get_extent_range(*journal_log_extents_index);
                    let trim_region_chip_io_blocks_begin = u64::from(journal_log_extent.begin())
                        >> chip_io_block_allocation_blocks_log2
                        << allocation_block_chip_io_blocks_log2;
                    let trim_region_chip_io_blocks_count = u64::from(journal_log_extent.block_count())
                        >> chip_io_block_allocation_blocks_log2
                        << allocation_block_chip_io_blocks_log2;
                    let trim_fut = match chip.trim(trim_region_chip_io_blocks_begin, trim_region_chip_io_blocks_count) {
                        Ok(trim_fut) => trim_fut,
                        Err(e) => {
                            if e == NvChipIoError::OperationNotSupported {
                                // If the operation is not supported, don't even bother to submit
                                // any more trim requests.
                                this.fut_state = JournalCleanupFutureState::Done;
                                return task::Poll::Ready(Ok(()));
                            } else {
                                // Failure to trim is considered non-fatal. Advance to the next region.
                                *journal_log_extents_index += 1;
                                continue;
                            }
                        }
                    };
                    this.fut_state = JournalCleanupFutureState::TrimJournalLogExtent {
                        next_journal_log_extents_index: *journal_log_extents_index + 1,
                        trim_fut,
                    };
                }
                JournalCleanupFutureState::TrimJournalLogExtent {
                    next_journal_log_extents_index,
                    trim_fut,
                } => {
                    match chip::NvChipFuture::poll(pin::Pin::new(trim_fut), chip, cx) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(_)) => {
                            // Failure to trim is considered non-fatal, advance
                            // to the next region.
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    this.fut_state = JournalCleanupFutureState::TrimJournalLogExtentPrepare {
                        journal_log_extents_index: *next_journal_log_extents_index,
                    };
                }
                JournalCleanupFutureState::TrimJournalStagingCopyPrepare {
                    apply_writes_script_index,
                } => {
                    while *apply_writes_script_index < apply_writes_script.len()
                        && apply_writes_script[*apply_writes_script_index]
                            .get_journal_staging_copy_allocation_blocks_begin()
                            == apply_writes_script[*apply_writes_script_index]
                                .get_target_range()
                                .begin()
                    {
                        *apply_writes_script_index += 1;
                    }
                    if *apply_writes_script_index == apply_writes_script.len() {
                        this.fut_state = JournalCleanupFutureState::TrimTrimScriptEntryPrepare { trim_script_index: 0 };
                        continue;
                    }
                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                    let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();
                    let chip_io_block_allocation_blocks_log2 =
                        chip_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);
                    let allocation_block_chip_io_blocks_log2 =
                        allocation_block_size_128b_log2.saturating_sub(chip_io_block_size_128b_log2);
                    let apply_writes_script_entry = &apply_writes_script[*apply_writes_script_index];
                    let trim_region_chip_io_blocks_begin =
                        u64::from(apply_writes_script_entry.get_journal_staging_copy_allocation_blocks_begin())
                            >> chip_io_block_allocation_blocks_log2
                            << allocation_block_chip_io_blocks_log2;
                    let trim_region_chip_io_blocks_count =
                        u64::from(apply_writes_script_entry.get_target_range().block_count())
                            >> chip_io_block_allocation_blocks_log2
                            << allocation_block_chip_io_blocks_log2;
                    let trim_fut = match chip.trim(trim_region_chip_io_blocks_begin, trim_region_chip_io_blocks_count) {
                        Ok(trim_fut) => trim_fut,
                        Err(e) => {
                            if e == NvChipIoError::OperationNotSupported {
                                // If the operation is not supported, don't even bother to submit
                                // any more trim requests.
                                this.fut_state = JournalCleanupFutureState::Done;
                                return task::Poll::Ready(Ok(()));
                            } else {
                                // Failure to trim is considered non-fatal. Advance to the next region.
                                *apply_writes_script_index += 1;
                                continue;
                            }
                        }
                    };
                    this.fut_state = JournalCleanupFutureState::TrimJournalStagingCopy {
                        next_apply_writes_script_index: *apply_writes_script_index + 1,
                        trim_fut,
                    };
                }
                JournalCleanupFutureState::TrimJournalStagingCopy {
                    next_apply_writes_script_index,
                    trim_fut,
                } => {
                    match chip::NvChipFuture::poll(pin::Pin::new(trim_fut), chip, cx) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(_)) => {
                            // Failure to trim is considered non-fatal, advance
                            // to the next region.
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    this.fut_state = JournalCleanupFutureState::TrimJournalStagingCopyPrepare {
                        apply_writes_script_index: *next_apply_writes_script_index,
                    };
                }
                JournalCleanupFutureState::TrimTrimScriptEntryPrepare { trim_script_index } => {
                    let trim_script = match trim_script {
                        Some(trim_script) => trim_script,
                        None => {
                            this.fut_state = JournalCleanupFutureState::Done;
                            return task::Poll::Ready(Ok(()));
                        }
                    };
                    if *trim_script_index == trim_script.len() {
                        this.fut_state = JournalCleanupFutureState::Done;
                        return task::Poll::Ready(Ok(()));
                    }
                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                    let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();
                    let chip_io_block_allocation_blocks_log2 =
                        chip_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);
                    let allocation_block_chip_io_blocks_log2 =
                        allocation_block_size_128b_log2.saturating_sub(chip_io_block_size_128b_log2);
                    let trim_script_entry = &trim_script[*trim_script_index];
                    let trim_region_chip_io_blocks_begin = u64::from(trim_script_entry.get_target_range().begin())
                        >> chip_io_block_allocation_blocks_log2
                        << allocation_block_chip_io_blocks_log2;
                    let trim_region_chip_io_blocks_count =
                        u64::from(trim_script_entry.get_target_range().block_count())
                            >> chip_io_block_allocation_blocks_log2
                            << allocation_block_chip_io_blocks_log2;
                    let trim_fut = match chip.trim(trim_region_chip_io_blocks_begin, trim_region_chip_io_blocks_count) {
                        Ok(trim_fut) => trim_fut,
                        Err(e) => {
                            if e == NvChipIoError::OperationNotSupported {
                                // If the operation is not supported, don't even bother to submit
                                // any more trim requests.
                                this.fut_state = JournalCleanupFutureState::Done;
                                return task::Poll::Ready(Ok(()));
                            } else {
                                // Failure to trim is considered non-fatal. Advance to the next region.
                                *trim_script_index += 1;
                                continue;
                            }
                        }
                    };
                    this.fut_state = JournalCleanupFutureState::TrimTrimScriptEntry {
                        next_trim_script_index: *trim_script_index + 1,
                        trim_fut,
                    };
                }
                JournalCleanupFutureState::TrimTrimScriptEntry {
                    next_trim_script_index,
                    trim_fut,
                } => {
                    match chip::NvChipFuture::poll(pin::Pin::new(trim_fut), chip, cx) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(_)) => {
                            // Failure to trim is considered non-fatal, advance
                            // to the next region.
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    this.fut_state = JournalCleanupFutureState::TrimTrimScriptEntryPrepare {
                        trim_script_index: *next_trim_script_index,
                    };
                }
                JournalCleanupFutureState::Done => unreachable!(),
            }
        }
    }
}
