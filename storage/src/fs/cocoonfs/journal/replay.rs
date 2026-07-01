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
    blkdev::{self, NvBlkDevIoError},
    fs::{
        NvFsError, NvFsIoError,
        cocoonfs::{
            FormatError, alloc_bitmap, auth_tree,
            aux_fs_metadata::{AuxFsMetadataEncodedExtentsPtrsPair, FindAuxFsMetadataExtentsFuture},
            extents, image_header,
            integrity::ExtentIntegrityState,
            keys, layout,
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

#[cfg(doc)]
use crate::fs::cocoonfs::aux_fs_metadata::AuxFsMetadata;

use core::{mem, pin, task};

/// Replay the journal at filesystem opening time if needed.
///
/// Check if the journal is active and needs replay. If so, do that and cleanup
/// afterwards, including an invalidation of the journal.
///
/// In either case the journal log head extent's [`ExtentIntegrityState`]
/// information required to maintain protection against torn [device IO
/// Block](blkdev::NvBlkDev::io_block_size_128b_log2) writes for the first
/// journal log update is returned from [`poll()`](Self::poll).
pub struct JournalReplayFuture<B: blkdev::NvBlkDev> {
    enable_trimming: bool,

    // Populated after the Journal Log has been read.
    journal_log_head_integrity_state: ExtentIntegrityState,

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

    fut_state: JournalReplayFutureState<B>,
}

/// [`JournalReplayFuture`] state-machine state.
enum JournalReplayFutureState<B: blkdev::NvBlkDev> {
    ReadLog {
        aux_fs_metadata_extents: Option<extents::PhysicalExtents>,
        read_log_fut: JournalLogReadFuture<B>,
    },
    ReadMutableImageHeader {
        aux_fs_metadata_extents: Option<extents::PhysicalExtents>,
        journal_log_aux_fs_metadata_update_groups_heads: AuxFsMetadataEncodedExtentsPtrsPair,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        auth_tree_extents: Option<extents::LogicalExtents>,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        alloc_bitmap_file_extents: Option<extents::PhysicalExtents>,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        alloc_bitmap_file_fragments_auth_digests: Option<ExtentsCoveringAuthDigests>,

        read_mutable_image_header_fut: JournalReadMutableImageHeaderFuture<B>,
    },
    FindAuxFsMetadataExtents {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        alloc_bitmap_file_extents: Option<extents::PhysicalExtents>,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        alloc_bitmap_file_fragments_auth_digests: Option<ExtentsCoveringAuthDigests>,

        find_aux_metadata_extents_fut: FindAuxFsMetadataExtentsFuture<B>,
    },
    ReadAllocBitmapJournalFragmentsPrepare {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        aux_fs_metadata_extents: Option<extents::PhysicalExtents>,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        alloc_bitmap_file_extents: Option<extents::PhysicalExtents>,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        alloc_bitmap_file_fragments_auth_digests: Option<ExtentsCoveringAuthDigests>,
    },
    ReadAllocBitmapJournalFragments {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        aux_fs_metadata_extents: Option<extents::PhysicalExtents>,
        alloc_bitmap_file: alloc_bitmap::AllocBitmapFile,
        image_header_end: layout::PhysicalAllocBlockIndex,
        read_alloc_bitmap_journal_fragments_fut: alloc_bitmap::AllocBitmapFileReadJournalFragmentsFuture<B>,
    },
    ReplayWrites {
        replay_writes_fut: JournalReplayWritesFuture<B>,
    },
    Cleanup {
        cleanup_fut: JournalCleanupFuture<B>,
    },
    Done,
}

impl<B: blkdev::NvBlkDev> JournalReplayFuture<B> {
    /// Instantiate a [`JournalReplayFuture`].
    ///
    /// # Arguments:
    ///
    /// * `enable_trimming` - Whether or not to submit [trim
    ///   commands](blkdev::NvBlkDev::trim) to the underlying storage for
    ///   cleanup.
    /// * `aux_fs_metadata_extents` - The extents of the [`AuxFsMetadata`] on
    ///   storage, which may optionally be provided if already available in
    ///   order to avoid some duplicate work. If not provided,
    ///   `JournalReplayFuture` will determine the extents itself as part of its
    ///   operation.
    pub fn new(enable_trimming: bool, aux_fs_metadata_extents: Option<extents::PhysicalExtents>) -> Self {
        let read_log_fut = JournalLogReadFuture::new();
        Self {
            enable_trimming,
            journal_log_head_integrity_state: ExtentIntegrityState::new_indeterminate(),
            journal_log_extents: None,
            apply_writes_script: None,
            update_auth_digests_script: None,
            trim_script: None,
            journal_staging_copy_undisguise: None,
            mutable_image_header: None,
            auth_tree_config: None,
            fut_state: JournalReplayFutureState::ReadLog {
                aux_fs_metadata_extents,
                read_log_fut,
            },
        }
    }

    /// Poll the [`JournalReplayFuture`] to completion.
    ///
    /// On success, the journal log head extent's [`ExtentIntegrityState`]
    /// information required to maintain protection against torn [device IO
    /// Block](blkdev::NvBlkDev::io_block_size_128b_log2) writes for the first
    /// journal log update is returned from [`poll()`](Self::poll).
    ///
    /// # Arguments:
    ///
    /// * `blkdev` - The filesystem image backing storage.
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
        blkdev: &B,
        image_layout: &layout::ImageLayout,
        salt_len: u8,
        root_key: &keys::RootKey,
        keys_cache: &mut keys::KeyCacheRef<'_, ST>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<ExtentIntegrityState, NvFsError>> {
        let this = pin::Pin::into_inner(self);
        loop {
            match &mut this.fut_state {
                JournalReplayFutureState::ReadLog {
                    aux_fs_metadata_extents,
                    read_log_fut,
                } => {
                    let journal_log;
                    (journal_log, this.journal_log_head_integrity_state) = match JournalLogReadFuture::poll(
                        pin::Pin::new(read_log_fut),
                        blkdev,
                        image_layout,
                        salt_len,
                        root_key,
                        keys_cache,
                        cx,
                    ) {
                        task::Poll::Ready(Ok((journal_log, journal_log_head_integrity_state))) => {
                            (journal_log, journal_log_head_integrity_state)
                        }
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
                            return task::Poll::Ready(Ok(this.journal_log_head_integrity_state));
                        }
                    };
                    let JournalLog {
                        log_extents: journal_log_extents,
                        aux_fs_metadata_update_groups_heads: journal_log_aux_fs_metadata_update_groups_heads,
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

                    let auth_tree_extents = extents::LogicalExtents::from(auth_tree_extents);
                    let read_mutable_image_header_fut =
                        match JournalReadMutableImageHeaderFuture::new(blkdev, image_layout, salt_len) {
                            Ok(read_mutable_image_header_fut) => read_mutable_image_header_fut,
                            Err(e) => {
                                this.fut_state = JournalReplayFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                        };
                    this.fut_state = JournalReplayFutureState::ReadMutableImageHeader {
                        aux_fs_metadata_extents: aux_fs_metadata_extents.take(),
                        journal_log_aux_fs_metadata_update_groups_heads,
                        auth_tree_extents: Some(auth_tree_extents),
                        alloc_bitmap_file_extents: Some(alloc_bitmap_file_extents),
                        alloc_bitmap_file_fragments_auth_digests: Some(alloc_bitmap_file_fragments_auth_digests),
                        read_mutable_image_header_fut,
                    };
                }
                JournalReplayFutureState::ReadMutableImageHeader {
                    aux_fs_metadata_extents,
                    journal_log_aux_fs_metadata_update_groups_heads,
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
                        blkdev,
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

                    // The pointers to the AuxFsMetadata update groups' heads found
                    // in the journal log and in the mutable image header should match.
                    // Verify that.
                    // Note that in case the aux_fs_metadata_extents had been provided from extern,
                    // i.e. retrieved independently through the journal log head's plaintext header,
                    // there still wasn't any TOCTOU issue -- the aux_fs_metadata_extents are used
                    // exclusively for determining Authentication Tree Data Blocks authenticated as
                    // unallocated when reconstructing the Authentication Tree during journal replay
                    // and all that could happen upon bogus aux_fs_metadata_extents would be an
                    // authentication failure.  So this check is really only a consistency check to
                    // protect against bugs potentially leading to an unusable filesystem image.
                    if *journal_log_aux_fs_metadata_update_groups_heads
                        != mutable_image_header.aux_fs_metadata_update_groups_heads
                    {
                        this.fut_state = JournalReplayFutureState::Done;
                        return task::Poll::Ready(Err(NvFsError::from(
                            FormatError::InconsistentAuxFsMetadataExtentsChain,
                        )));
                    }

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

                    // If the auxiliary FS metadata extents had been provided at
                    // initialization, proceed directly to
                    // reading the Allocation Bitmap File fragments.
                    // Otherwise find them first.
                    if aux_fs_metadata_extents.is_none() {
                        let find_aux_metadata_extents_fut = FindAuxFsMetadataExtentsFuture::new(
                            *journal_log_aux_fs_metadata_update_groups_heads,
                            image_layout,
                        );
                        this.fut_state = JournalReplayFutureState::FindAuxFsMetadataExtents {
                            alloc_bitmap_file_extents: Some(alloc_bitmap_file_extents),
                            alloc_bitmap_file_fragments_auth_digests: alloc_bitmap_file_fragments_auth_digests.take(),
                            find_aux_metadata_extents_fut,
                        };
                    } else {
                        this.fut_state = JournalReplayFutureState::ReadAllocBitmapJournalFragmentsPrepare {
                            aux_fs_metadata_extents: aux_fs_metadata_extents.take(),
                            alloc_bitmap_file_extents: Some(alloc_bitmap_file_extents),
                            alloc_bitmap_file_fragments_auth_digests: alloc_bitmap_file_fragments_auth_digests.take(),
                        };
                    }
                }
                JournalReplayFutureState::FindAuxFsMetadataExtents {
                    alloc_bitmap_file_extents,
                    alloc_bitmap_file_fragments_auth_digests,
                    find_aux_metadata_extents_fut,
                } => {
                    let aux_fs_metadata_extents =
                        match blkdev::NvBlkDevFuture::poll(pin::Pin::new(find_aux_metadata_extents_fut), blkdev, cx) {
                            task::Poll::Ready(Ok(aux_fs_metadata_extents)) => aux_fs_metadata_extents,
                            task::Poll::Ready(Err(e)) => {
                                this.fut_state = JournalReplayFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    this.fut_state = JournalReplayFutureState::ReadAllocBitmapJournalFragmentsPrepare {
                        aux_fs_metadata_extents: Some(aux_fs_metadata_extents),
                        alloc_bitmap_file_extents: alloc_bitmap_file_extents.take(),
                        alloc_bitmap_file_fragments_auth_digests: alloc_bitmap_file_fragments_auth_digests.take(),
                    };
                }
                JournalReplayFutureState::ReadAllocBitmapJournalFragmentsPrepare {
                    aux_fs_metadata_extents,
                    alloc_bitmap_file_extents,
                    alloc_bitmap_file_fragments_auth_digests,
                } => {
                    let alloc_bitmap_file_extents = match alloc_bitmap_file_extents.take() {
                        Some(alloc_bitmap_file_extents) => alloc_bitmap_file_extents,
                        None => {
                            this.fut_state = JournalReplayFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

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
                            blkdev,
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
                        aux_fs_metadata_extents: aux_fs_metadata_extents.take(),
                        alloc_bitmap_file,
                        image_header_end: image_header::MutableImageHeader::physical_location(image_layout, salt_len)
                            .end(),
                        read_alloc_bitmap_journal_fragments_fut,
                    };
                }
                JournalReplayFutureState::ReadAllocBitmapJournalFragments {
                    aux_fs_metadata_extents,
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
                            blkdev,
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

                    let aux_fs_metadata_extents = match aux_fs_metadata_extents.as_ref() {
                        Some(aux_fs_metadata_extents) => aux_fs_metadata_extents,
                        None => {
                            this.fut_state = JournalReplayFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
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
                        blkdev,
                        image_layout,
                        auth_tree_config,
                        *image_header_end,
                        &journal_log_head_extent,
                        aux_fs_metadata_extents,
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
                        blkdev,
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
                        blkdev,
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

                    // The JournalCleanupFuture cleared the journal log head.
                    this.journal_log_head_integrity_state.record_clear();

                    this.fut_state = JournalReplayFutureState::Done;
                    return task::Poll::Ready(Ok(this.journal_log_head_integrity_state));
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
struct JournalReadMutableImageHeaderFuture<B: blkdev::NvBlkDev> {
    mutable_image_header_allocation_blocks_range: layout::PhysicalAllocBlockRange,
    cur_target_allocation_block_index: layout::PhysicalAllocBlockIndex,
    apply_writes_script_index: usize,
    buffer: FixedVec<u8, 7>,
    fut_state: JournalReadMutableImageHeaderFutureState<B>,
}

/// [`JournalReadMutableImageHeaderFuture`] state-machine state.
enum JournalReadMutableImageHeaderFutureState<B: blkdev::NvBlkDev> {
    PrepareReadPart,
    ReadPart {
        cur_read_range_allocation_blocks: layout::AllocBlockCount,
        read_fut: blkdev::helpers::NvBlkDevReadRegionFuture<B, FixedVec<u8, 7>>,
    },
    Done,
}

impl<B: blkdev::NvBlkDev> JournalReadMutableImageHeaderFuture<B> {
    /// Instantiate a [`JournalReadMutableImageHeaderFuture`].
    ///
    /// # Arguments:
    ///
    /// * `blkdev` - The filesystem image backing storage.
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `salt_len` - Length of the salt found in the filesystem's
    ///   [`StaticImageHeader`](image_header::StaticImageHeader).
    fn new(blkdev: &B, image_layout: &layout::ImageLayout, salt_len: u8) -> Result<Self, NvFsError> {
        let mutable_image_header_allocation_blocks_range =
            image_header::MutableImageHeader::physical_location(image_layout, salt_len);
        let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
        let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();
        let blkdev_io_block_allocation_blocks_log2 =
            blkdev_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);
        // The mutable header's beginning is aligned to the IO Block size, hence to the
        // Device IO Block size.
        debug_assert_eq!(
            mutable_image_header_allocation_blocks_range
                .begin()
                .align_down(blkdev_io_block_allocation_blocks_log2),
            mutable_image_header_allocation_blocks_range.begin()
        );

        if u64::from(mutable_image_header_allocation_blocks_range.block_count())
            > u64::MAX >> (allocation_block_size_128b_log2 + 7)
        {
            return Err(NvFsError::IoError(NvFsIoError::RegionOutOfRange));
        }
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
    /// * `blkdev` - The filesystem image backing storage.
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `apply_writes_script` - The [`JournalLog::apply_writes_script`].
    /// * `journal_staging_copy_undisguise` - The
    ///   [`JournalLog::journal_staging_copy_undisguise`].
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    fn poll(
        self: pin::Pin<&mut Self>,
        blkdev: &B,
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

                    let read_fut = blkdev::helpers::NvBlkDevReadRegionFuture::new(
                        u64::from(read_range.begin()),
                        u64::from(read_range.block_count()),
                        image_layout.allocation_block_size_128b_log2,
                        mem::take(&mut this.buffer),
                        u64::from(
                            this.cur_target_allocation_block_index
                                - this.mutable_image_header_allocation_blocks_range.begin(),
                        ) as usize,
                        image_layout.allocation_block_size_128b_log2,
                    );

                    this.fut_state = JournalReadMutableImageHeaderFutureState::ReadPart {
                        cur_read_range_allocation_blocks: read_range.block_count(),
                        read_fut,
                    };
                }
                JournalReadMutableImageHeaderFutureState::ReadPart {
                    cur_read_range_allocation_blocks,
                    read_fut,
                } => {
                    this.buffer = match blkdev::NvBlkDevFuture::poll(pin::Pin::new(read_fut), blkdev, cx) {
                        task::Poll::Ready(Ok((buffer, Ok(())))) => buffer,
                        task::Poll::Ready(Err(e) | Ok((_, Err(e)))) => {
                            this.fut_state = JournalReadMutableImageHeaderFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

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

/// Replay the data writes recorded in [`JournalLog::apply_writes_script`] and
/// update the authentication tree in the course.
struct JournalReplayWritesFuture<B: blkdev::NvBlkDev> {
    image_size: layout::AllocBlockCount,
    apply_writes_script_index: usize,
    next_target_allocation_block_index: layout::PhysicalAllocBlockIndex,
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self.
    auth_tree_updates_replay_cursor: Option<Box<auth_tree::AuthTreeReplayJournalUpdateScriptCursor>>,
    buffers: FixedVec<FixedVec<u8, 7>, 0>,
    fut_state: JournalReplayWritesFutureState<B>,
    allocation_block_size_128b_log2: u8,
    blkdev_io_block_allocation_blocks_log2: u8,
    preferred_blkdev_io_bulk_allocation_blocks_log2: u8,
}

/// [`JournalReplayWritesFuture`] state-machine state.
enum JournalReplayWritesFutureState<B: blkdev::NvBlkDev> {
    Init,
    AdvanceAuthTreeCursor {
        advance_auth_tree_cursor_fut: auth_tree::AuthTreeReplayJournalUpdateScriptCursorAdvanceFuture<B>,
    },
    PrepareReadStagingCopy,
    ReadStagingCopy {
        cur_target_range: layout::PhysicalAllocBlockRange,
        read_fut: blkdev::helpers::NvBlkDevReadRegionBlocksScatterFuture<B, FixedVec<FixedVec<u8, 7>, 0>>,
    },
    WriteToTarget {
        cur_target_range_allocation_blocks: layout::AllocBlockCount,
        write_fut: blkdev::helpers::NvBlkDevWriteRegionBlocksGatherFuture<B, FixedVec<FixedVec<u8, 7>, 0>>,
    },
    UpdateAuthTree {
        next_allocation_block_index_in_cur_target_range: layout::AllocBlockCount,
        cur_target_range_allocation_blocks: layout::AllocBlockCount,
        auth_tree_write_part_fut: Option<auth_tree::AuthTreeReplayJournalUpdateScriptCursorWritePartFuture<B>>,
    },
    FinalizeAuthTreeUpdatesReplay {
        auth_tree_replay_remainder_fut: auth_tree::AuthTreeReplayJournalUpdateScriptCursorAdvanceFuture<B>,
    },
    Done,
}

impl<B: blkdev::NvBlkDev> JournalReplayWritesFuture<B> {
    /// Instantiate a [`JournalReplayWritesFuture`].
    ///
    /// # Arguments:
    ///
    /// * `blkdev` - The filesystem image backing storage.
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `auth_tree_config` - The filesystem's
    ///   [`AuthTreeConfig`](auth_tree::AuthTreeConfig).
    /// * `image_header_end` - [End of the filesystem image header on
    ///   storage](image_header::MutableImageHeader::physical_location).
    /// * `journal_log_head_extent` - The filesystem's fixed [journal log head
    ///   extent](JournalLog::head_extent_physical_location)
    /// * `aux_fs_metadata_extents` - The extents of the [`AuxFsMetadata`] on
    ///   storage.
    /// * `image_size` - The filesystem image size as found in the filesystem's
    ///   [`MutableImageHeader::image_size`](image_header::MutableImageHeader::image_size).
    /// * `alloc_bitmap_journal_fragments` - Allocation bitmap with valid
    ///   entries for the parts covered by
    ///   [`JournalLog::alloc_bitmap_file_fragments_auth_digests`].
    /// * `update_auth_digests_script` - The
    ///   [`JournalLog::update_auth_digests_script`].
    #[allow(clippy::too_many_arguments)]
    fn new(
        blkdev: &B,
        image_layout: &layout::ImageLayout,
        auth_tree_config: &auth_tree::AuthTreeConfig,
        image_header_end: layout::PhysicalAllocBlockIndex,
        journal_log_head_extent: &layout::PhysicalAllocBlockRange,
        aux_fs_metadata_extents: &extents::PhysicalExtents,
        image_size: layout::AllocBlockCount,
        alloc_bitmap_journal_fragments: alloc_bitmap::AllocBitmap,
        update_auth_digests_script: JournalUpdateAuthDigestsScript,
    ) -> Result<Self, NvFsError> {
        let auth_tree_updates_replay_cursor = auth_tree::AuthTreeReplayJournalUpdateScriptCursor::new(
            image_layout,
            auth_tree_config,
            image_header_end,
            journal_log_head_extent,
            aux_fs_metadata_extents,
            image_size,
            alloc_bitmap_journal_fragments,
            update_auth_digests_script,
        )?;

        let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
        let io_block_allocation_blocks_log2 = image_layout.io_block_allocation_blocks_log2 as u32;
        let auth_tree_data_block_allocation_blocks_log2 =
            image_layout.auth_tree_data_block_allocation_blocks_log2 as u32;
        let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();
        let blkdev_io_block_allocation_blocks_log2 =
            blkdev_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);
        // Determine the device's preferred bulk IO block size, ramp it up to a
        // reasonable value.
        let preferred_blkdev_io_bulk_allocation_blocks_log2 = (blkdev.preferred_io_blocks_bulk_log2()
            + blkdev_io_block_size_128b_log2)
            .min(usize::BITS - 1 - 7)
            .saturating_sub(allocation_block_size_128b_log2)
            .max(io_block_allocation_blocks_log2)
            .max(auth_tree_data_block_allocation_blocks_log2);

        let mut buffers = FixedVec::new_with_default(
            1usize << (preferred_blkdev_io_bulk_allocation_blocks_log2 - blkdev_io_block_allocation_blocks_log2),
        )?;
        for buffer in buffers.iter_mut() {
            *buffer = FixedVec::new_with_default(
                1usize << (blkdev_io_block_allocation_blocks_log2 + allocation_block_size_128b_log2 + 7),
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
            blkdev_io_block_allocation_blocks_log2: blkdev_io_block_allocation_blocks_log2 as u8,
            preferred_blkdev_io_bulk_allocation_blocks_log2: preferred_blkdev_io_bulk_allocation_blocks_log2 as u8,
        })
    }

    /// Poll the [`JournalReplayWritesFuture`] to completion.
    ///
    /// # Arguments:
    ///
    /// * `blkdev` - The filesystem image backing storage.
    /// * `auth_tree_config` - The filesystem's
    ///   [`AuthTreeConfig`](auth_tree::AuthTreeConfig).
    /// * `apply_writes_script` - The [`JournalLog::apply_writes_script`].
    /// * `journal_staging_copy_undisguise` - The
    ///   [`JournalLog::journal_staging_copy_undisguise`].
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    fn poll(
        self: pin::Pin<&mut Self>,
        blkdev: &B,
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
                            blkdev,
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
                                FormatError::InvalidJournalApplyWritesScriptEntry,
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
                            blkdev,
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
                            blkdev,
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
                    let blkdev_io_block_allocation_blocks_log2 = this.blkdev_io_block_allocation_blocks_log2 as u32;
                    let preferred_blkdev_io_bulk_allocation_blocks_log2 =
                        this.preferred_blkdev_io_bulk_allocation_blocks_log2 as u32;
                    debug_assert!(
                        u64::from(this.next_target_allocation_block_index)
                            .is_aligned_pow2(blkdev_io_block_allocation_blocks_log2)
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
                        .is_aligned_pow2(blkdev_io_block_allocation_blocks_log2)
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
                        + layout::AllocBlockCount::from(1u64 << blkdev_io_block_allocation_blocks_log2);
                    debug_assert!(
                        cur_target_range_allocation_blocks_end
                            <= cur_apply_writes_script_entry.get_target_range().end()
                    );
                    while cur_target_range_allocation_blocks_end
                        < cur_apply_writes_script_entry.get_target_range().end()
                    {
                        if (u64::from(this.next_target_allocation_block_index)
                            ^ u64::from(cur_target_range_allocation_blocks_end))
                            >> preferred_blkdev_io_bulk_allocation_blocks_log2
                            != 0
                        {
                            // Crossing a preferred Device IO bulk boundary, stop
                            // and process what's been found so far.
                            break;
                        }
                        cur_target_range_allocation_blocks_end +=
                            layout::AllocBlockCount::from(1u64 << blkdev_io_block_allocation_blocks_log2);
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

                    let read_fut = blkdev::helpers::NvBlkDevReadRegionBlocksScatterFuture::new(
                        u64::from(cur_journal_staging_copy_range.begin()),
                        u64::from(cur_journal_staging_copy_range.block_count()),
                        allocation_block_size_128b_log2 as u8,
                        mem::take(&mut this.buffers),
                        0,
                        (blkdev_io_block_allocation_blocks_log2 + allocation_block_size_128b_log2) as u8,
                    );

                    this.fut_state = JournalReplayWritesFutureState::ReadStagingCopy {
                        cur_target_range,
                        read_fut,
                    };
                }
                JournalReplayWritesFutureState::ReadStagingCopy {
                    cur_target_range,
                    read_fut,
                } => {
                    let mut buffers = match blkdev::NvBlkDevFuture::poll(pin::Pin::new(read_fut), blkdev, cx) {
                        task::Poll::Ready(Ok((buffers, Ok(())))) => buffers,
                        task::Poll::Ready(Err(e) | Ok((_, Err(e)))) => {
                            this.fut_state = JournalReplayWritesFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    // Undisguise the Journal Staging Copy in case it's been disguised.
                    let allocation_block_size_128b_log2 = this.allocation_block_size_128b_log2 as u32;
                    let blkdev_io_block_allocation_blocks_log2 = this.blkdev_io_block_allocation_blocks_log2 as u32;
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
                            let blkdev_io_block_index =
                                (u64::from(cur_target_allocation_block_index - cur_target_range.begin())
                                    >> blkdev_io_block_allocation_blocks_log2) as usize;
                            let blkdev_io_block_buf = &mut buffers[blkdev_io_block_index];
                            for allocation_block_in_blkdev_io_block_index in
                                0..1usize << blkdev_io_block_allocation_blocks_log2
                            {
                                let allocation_block_begin_in_blkdev_io_block =
                                    allocation_block_in_blkdev_io_block_index << (allocation_block_size_128b_log2 + 7);
                                let allocation_block_end_in_blkdev_io_block = (allocation_block_in_blkdev_io_block_index
                                    + 1)
                                    << (allocation_block_size_128b_log2 + 7);
                                let allocation_block_buf = &mut blkdev_io_block_buf
                                    [allocation_block_begin_in_blkdev_io_block
                                        ..allocation_block_end_in_blkdev_io_block];
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

                    let write_fut = blkdev::helpers::NvBlkDevWriteRegionBlocksGatherFuture::new(
                        u64::from(cur_target_range.begin()),
                        u64::from(cur_target_range.block_count()),
                        allocation_block_size_128b_log2 as u8,
                        buffers,
                        0,
                        (blkdev_io_block_allocation_blocks_log2 + allocation_block_size_128b_log2) as u8,
                    );

                    this.fut_state = JournalReplayWritesFutureState::WriteToTarget {
                        cur_target_range_allocation_blocks: cur_target_range.block_count(),
                        write_fut,
                    };
                }
                JournalReplayWritesFutureState::WriteToTarget {
                    cur_target_range_allocation_blocks,
                    write_fut,
                } => {
                    this.buffers = match blkdev::NvBlkDevFuture::poll(pin::Pin::new(write_fut), blkdev, cx) {
                        task::Poll::Ready(Ok((buffers, Ok(())))) => buffers,
                        task::Poll::Ready(Err(e) | Ok((_, Err(e)))) => {
                            this.fut_state = JournalReplayWritesFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

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
                                blkdev,
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
                    let blkdev_io_block_allocation_blocks_log2 = this.blkdev_io_block_allocation_blocks_log2 as u32;
                    while next_allocation_block_index_in_cur_target_range != cur_target_range_allocation_blocks {
                        let blkdev_io_block_index = u64::from(*next_allocation_block_index_in_cur_target_range)
                            >> blkdev_io_block_allocation_blocks_log2;
                        let allocation_block_in_blkdev_io_block_index =
                            (u64::from(*next_allocation_block_index_in_cur_target_range)
                                - (blkdev_io_block_index << blkdev_io_block_allocation_blocks_log2))
                                as usize;
                        let blkdev_io_block_index = blkdev_io_block_index as usize;
                        *next_allocation_block_index_in_cur_target_range =
                            *next_allocation_block_index_in_cur_target_range + layout::AllocBlockCount::from(1u64);

                        let allocation_block_buf = &this.buffers[blkdev_io_block_index]
                            [allocation_block_in_blkdev_io_block_index << (allocation_block_size_128b_log2 + 7)
                                ..(allocation_block_in_blkdev_io_block_index + 1)
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
                        blkdev,
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

/// Invalidate and cleanup the journal after replay.
struct JournalCleanupFuture<B: blkdev::NvBlkDev> {
    enable_trimming: bool,
    fut_state: JournalCleanupFutureState<B>,
}

/// [`JournalCleanupFuture`] state-machine state.
enum JournalCleanupFutureState<B: blkdev::NvBlkDev> {
    Init,
    InvalidateJournalLogHead {
        image_header_end: layout::PhysicalAllocBlockIndex,
        invalidate_journal_log_fut: JournalLogInvalidateFuture<B>,
    },
    TrimJournalLogExtentPrepare {
        journal_log_extents_index: usize,
    },
    TrimJournalLogExtent {
        next_journal_log_extents_index: usize,
        trim_fut: B::TrimFuture,
    },
    TrimJournalStagingCopyPrepare {
        apply_writes_script_index: usize,
    },
    TrimJournalStagingCopy {
        next_apply_writes_script_index: usize,
        trim_fut: B::TrimFuture,
    },
    TrimTrimScriptEntryPrepare {
        trim_script_index: usize,
    },
    TrimTrimScriptEntry {
        next_trim_script_index: usize,
        trim_fut: B::TrimFuture,
    },
    Done,
}

impl<B: blkdev::NvBlkDev> JournalCleanupFuture<B> {
    /// Instantiate a [`JournalCleanupFuture`].
    ///
    /// # Arguments:
    ///
    /// * `enable_trimming` - Whether or not to submit [trim
    ///   commands](blkdev::NvBlkDev::trim) to the underlying storage.
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
    /// * `blkdev` - The filesystem image backing storage.
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
        blkdev: &B,
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
                        blkdev,
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
                    let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();
                    let blkdev_io_block_allocation_blocks_log2 =
                        blkdev_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);
                    let allocation_block_blkdev_io_blocks_log2 =
                        allocation_block_size_128b_log2.saturating_sub(blkdev_io_block_size_128b_log2);
                    let journal_log_extent = journal_log_extents.get_extent_range(*journal_log_extents_index);
                    let trim_region_blkdev_io_blocks_begin = u64::from(journal_log_extent.begin())
                        >> blkdev_io_block_allocation_blocks_log2
                        << allocation_block_blkdev_io_blocks_log2;
                    let trim_region_blkdev_io_blocks_count = u64::from(journal_log_extent.block_count())
                        >> blkdev_io_block_allocation_blocks_log2
                        << allocation_block_blkdev_io_blocks_log2;
                    let trim_fut =
                        match blkdev.trim(trim_region_blkdev_io_blocks_begin, trim_region_blkdev_io_blocks_count) {
                            Ok(trim_fut) => trim_fut,
                            Err(e) => {
                                if e == NvBlkDevIoError::OperationNotSupported {
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
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(trim_fut), blkdev, cx) {
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
                    let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();
                    let blkdev_io_block_allocation_blocks_log2 =
                        blkdev_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);
                    let allocation_block_blkdev_io_blocks_log2 =
                        allocation_block_size_128b_log2.saturating_sub(blkdev_io_block_size_128b_log2);
                    let apply_writes_script_entry = &apply_writes_script[*apply_writes_script_index];
                    let trim_region_blkdev_io_blocks_begin =
                        u64::from(apply_writes_script_entry.get_journal_staging_copy_allocation_blocks_begin())
                            >> blkdev_io_block_allocation_blocks_log2
                            << allocation_block_blkdev_io_blocks_log2;
                    let trim_region_blkdev_io_blocks_count =
                        u64::from(apply_writes_script_entry.get_target_range().block_count())
                            >> blkdev_io_block_allocation_blocks_log2
                            << allocation_block_blkdev_io_blocks_log2;
                    let trim_fut =
                        match blkdev.trim(trim_region_blkdev_io_blocks_begin, trim_region_blkdev_io_blocks_count) {
                            Ok(trim_fut) => trim_fut,
                            Err(e) => {
                                if e == NvBlkDevIoError::OperationNotSupported {
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
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(trim_fut), blkdev, cx) {
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
                    let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();
                    let blkdev_io_block_allocation_blocks_log2 =
                        blkdev_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);
                    let allocation_block_blkdev_io_blocks_log2 =
                        allocation_block_size_128b_log2.saturating_sub(blkdev_io_block_size_128b_log2);
                    let trim_script_entry = &trim_script[*trim_script_index];
                    let trim_region_blkdev_io_blocks_begin = u64::from(trim_script_entry.get_target_range().begin())
                        >> blkdev_io_block_allocation_blocks_log2
                        << allocation_block_blkdev_io_blocks_log2;
                    let trim_region_blkdev_io_blocks_count =
                        u64::from(trim_script_entry.get_target_range().block_count())
                            >> blkdev_io_block_allocation_blocks_log2
                            << allocation_block_blkdev_io_blocks_log2;
                    let trim_fut =
                        match blkdev.trim(trim_region_blkdev_io_blocks_begin, trim_region_blkdev_io_blocks_count) {
                            Ok(trim_fut) => trim_fut,
                            Err(e) => {
                                if e == NvBlkDevIoError::OperationNotSupported {
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
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(trim_fut), blkdev, cx) {
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
