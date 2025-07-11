// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`CocoonFsOpenFsFuture`].

extern crate alloc;
use alloc::vec::Vec;

use crate::{
    chip,
    fs::{
        cocoonfs::{
            alloc_bitmap, auth_tree, extent_ptr, extents,
            fs::{CocoonFs, CocoonFsConfig, CocoonFsSyncRcPtrType, CocoonFsSyncState},
            image_header, inode_extents_list, inode_index, journal, keys, layout, read_buffer, CocoonFsFormatError,
        },
        NvFsError,
    },
    nvfs_err_internal,
    utils_async::sync_types,
    utils_common::zeroize,
};
use core::{future, marker, mem, pin, task};

/// Open a CocoonFS instance.
pub struct CocoonFsOpenFsFuture<ST: sync_types::SyncTypes, C: chip::NvChip + marker::Unpin>
where
    auth_tree::AuthTree<ST>: marker::Unpin,
    read_buffer::ReadBuffer<ST>: marker::Unpin,
    ST::RwLock<inode_index::InodeIndexTreeNodeCache>: marker::Unpin,
{
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self.
    chip: Option<C>,

    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self.
    raw_root_key: Option<zeroize::Zeroizing<Vec<u8>>>,

    // Initialized after the static + mutable image headers have been read.
    fs_config: Option<CocoonFsConfig>,

    // Initialized after the static + mutable image headers have been read.
    // Gets moved into the AuthTree once constructed.
    root_hmac_digest: Vec<u8>,

    // Initialized after the static + mutable image headers have been read.
    // Gets moved into the InodeIndex once constructed.
    inode_index_entry_leaf_node_preauth_cca_protection_digest: Vec<u8>,

    // Initialized after the static + mutable image headers have been read.
    image_size: layout::AllocBlockCount,

    // Is initialized after the Authentication Tree + Alloc Bitmap File
    // extents are known.
    auth_tree: Option<auth_tree::AuthTree<ST>>,

    // Is initialized after the Alloc Bitmap File extents are known.
    alloc_bitmap_file: Option<alloc_bitmap::AllocBitmapFile>,

    // Is initialized right before the Allocation Bitmap File is read in.
    read_buffer: Option<read_buffer::ReadBuffer<ST>>,

    // Is initialized after the Alloc Bitmap File has been read in.
    alloc_bitmap: Option<alloc_bitmap::AllocBitmap>,

    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self.
    keys_cache: Option<keys::KeyCache>,

    fut_state: CocoonFsOpenFsFutureState<ST, C>,
}

#[allow(clippy::large_enum_variant)]
enum CocoonFsOpenFsFutureState<ST: sync_types::SyncTypes, C: chip::NvChip>
where
    ST::RwLock<inode_index::InodeIndexTreeNodeCache>: marker::Unpin,
{
    Init {
        enable_trimming: bool,
    },
    ReadStaticImageHeader {
        enable_trimming: bool,
        read_static_image_header_fut: image_header::ReadStaticImageHeaderFuture<C>,
    },
    ReplayJournal {
        enable_trimming: bool,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        static_image_header: Option<image_header::StaticImageHeader>,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        root_key: Option<keys::RootKey>,
        replay_journal_fut: journal::replay::JournalReplayFuture<C>,
    },
    ReadMutableImageHeader {
        enable_trimming: bool,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        static_image_header: Option<image_header::StaticImageHeader>,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        root_key: Option<keys::RootKey>,
        read_mutable_image_header_fut: image_header::ReadMutableImageHeaderFuture<C>,
    },
    ReadInodeIndexEntryLeafNode {
        read_inode_index_entry_leaf_node_fut: inode_index::InodeIndexReadEntryLeafTreeNodePreauthCcaProtectedFuture<C>,
    },
    ReadAuthTreeInodeExtentsList {
        read_auth_tree_inode_extents_list_fut: inode_extents_list::InodeExtentsListReadPreAuthFuture<C>,
        alloc_bitmap_inode_entry_extent_ptr: extent_ptr::EncodedExtentPtr,
    },
    ReadAllocBitmapInodeExtentsListPrepare {
        alloc_bitmap_inode_entry_extent_ptr: extent_ptr::EncodedExtentPtr,
        auth_tree_extents: extents::LogicalExtents,
    },
    ReadAllocBitmapInodeExtentsList {
        read_alloc_bitmap_inode_extents_list_fut: inode_extents_list::InodeExtentsListReadPreAuthFuture<C>,
        auth_tree_extents: extents::LogicalExtents,
    },
    ReadAllocBitmapFilePrepare {
        auth_tree_extents: extents::LogicalExtents,
        alloc_bitmap_extents: extents::PhysicalExtents,
    },
    ReadAllocBitmapFile {
        read_alloc_bitmap_file_fut: alloc_bitmap::AllocBitmapFileReadFuture<C>,
    },
    BootstrapInodeIndex {
        bootstrap_inode_index_fut: inode_index::InodeIndexBootstrapFuture<ST, C>,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsOpenFsFuture<ST, C>
where
    auth_tree::AuthTree<ST>: marker::Unpin,
    read_buffer::ReadBuffer<ST>: marker::Unpin,
    ST::RwLock<inode_index::InodeIndexTreeNodeCache>: marker::Unpin,
{
    pub fn new(
        chip: C,
        raw_root_key: zeroize::Zeroizing<Vec<u8>>,
        enable_trimming: bool,
    ) -> Result<Self, (C, zeroize::Zeroizing<Vec<u8>>, NvFsError)> {
        let keys_cache = match keys::KeyCache::new() {
            Ok(keys_cache) => keys_cache,
            Err(e) => {
                return Err((chip, raw_root_key, e));
            }
        };

        Ok(Self {
            chip: Some(chip),
            raw_root_key: Some(raw_root_key),
            fs_config: None,
            root_hmac_digest: Vec::new(),
            inode_index_entry_leaf_node_preauth_cca_protection_digest: Vec::new(),
            image_size: layout::AllocBlockCount::from(0u64),
            auth_tree: None,
            alloc_bitmap_file: None,
            read_buffer: None,
            alloc_bitmap: None,
            keys_cache: Some(keys_cache),
            fut_state: CocoonFsOpenFsFutureState::Init { enable_trimming },
        })
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> future::Future for CocoonFsOpenFsFuture<ST, C>
where
    auth_tree::AuthTree<ST>: marker::Unpin,
    read_buffer::ReadBuffer<ST>: marker::Unpin,
    ST::RwLock<inode_index::InodeIndexTreeNodeCache>: marker::Unpin,
{
    type Output = Result<Result<CocoonFsSyncRcPtrType<ST, C>, (C, zeroize::Zeroizing<Vec<u8>>, NvFsError)>, NvFsError>;

    fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        let chip = match this.chip.as_mut() {
            Some(chip) => chip,
            None => {
                this.fut_state = CocoonFsOpenFsFutureState::Done;
                return task::Poll::Ready(Err(nvfs_err_internal!()));
            }
        };

        let result = loop {
            match &mut this.fut_state {
                CocoonFsOpenFsFutureState::Init { enable_trimming } => {
                    let read_static_image_header_fut = image_header::ReadStaticImageHeaderFuture::new();
                    this.fut_state = CocoonFsOpenFsFutureState::ReadStaticImageHeader {
                        enable_trimming: *enable_trimming,
                        read_static_image_header_fut,
                    };
                }
                CocoonFsOpenFsFutureState::ReadStaticImageHeader {
                    enable_trimming,
                    read_static_image_header_fut,
                } => {
                    let static_image_header =
                        match chip::NvChipFuture::poll(pin::Pin::new(read_static_image_header_fut), chip, cx) {
                            task::Poll::Ready(Ok(static_image_header)) => static_image_header,
                            task::Poll::Ready(Err(e)) => break Err(e),
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    let image_layout = &static_image_header.image_layout;
                    let raw_root_key = match this.raw_root_key.as_ref() {
                        Some(raw_root_key) => raw_root_key,
                        None => break Err(nvfs_err_internal!()),
                    };
                    let root_key = match keys::RootKey::new(
                        raw_root_key,
                        &static_image_header.salt,
                        image_layout.kdf_hash_alg,
                        image_layout.auth_tree_root_hmac_hash_alg,
                        image_layout.auth_tree_node_hash_alg,
                        image_layout.auth_tree_data_hmac_hash_alg,
                        image_layout.preauth_cca_protection_hmac_hash_alg,
                        &image_layout.block_cipher_alg,
                    ) {
                        Ok(root_key) => root_key,
                        Err(e) => break Err(e),
                    };

                    let replay_journal_fut = journal::replay::JournalReplayFuture::new(*enable_trimming);
                    this.fut_state = CocoonFsOpenFsFutureState::ReplayJournal {
                        enable_trimming: *enable_trimming,
                        static_image_header: Some(static_image_header),
                        root_key: Some(root_key),
                        replay_journal_fut,
                    };
                }
                CocoonFsOpenFsFutureState::ReplayJournal {
                    enable_trimming,
                    static_image_header: fut_static_image_header,
                    root_key: fut_root_key,
                    replay_journal_fut,
                } => {
                    let static_image_header = match fut_static_image_header.as_ref() {
                        Some(static_image_header) => static_image_header,
                        None => break Err(nvfs_err_internal!()),
                    };
                    let image_layout = &static_image_header.image_layout;
                    let salt_len = match u8::try_from(static_image_header.salt.len()) {
                        Ok(salt_len) => salt_len,
                        Err(_) => break Err(NvFsError::from(CocoonFsFormatError::InvalidSaltLength)),
                    };

                    let root_key = match fut_root_key.as_ref() {
                        Some(root_key) => root_key,
                        None => break Err(nvfs_err_internal!()),
                    };

                    let keys_cache = match this.keys_cache.as_mut() {
                        Some(keys_cache) => keys_cache,
                        None => break Err(nvfs_err_internal!()),
                    };
                    let mut keys_cache = keys::KeyCacheRef::<ST>::new_mut(keys_cache);

                    match journal::replay::JournalReplayFuture::poll(
                        pin::Pin::new(replay_journal_fut),
                        chip,
                        image_layout,
                        salt_len,
                        root_key,
                        &mut keys_cache,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => break Err(e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let read_mutable_image_header_fut =
                        match image_header::ReadMutableImageHeaderFuture::new(static_image_header) {
                            Ok(read_mutable_image_header_fut) => read_mutable_image_header_fut,
                            Err(e) => break Err(e),
                        };

                    this.fut_state = CocoonFsOpenFsFutureState::ReadMutableImageHeader {
                        enable_trimming: *enable_trimming,
                        static_image_header: fut_static_image_header.take(),
                        root_key: fut_root_key.take(),
                        read_mutable_image_header_fut,
                    };
                }
                CocoonFsOpenFsFutureState::ReadMutableImageHeader {
                    enable_trimming,
                    static_image_header,
                    root_key,
                    read_mutable_image_header_fut,
                } => {
                    let mutable_image_header =
                        match chip::NvChipFuture::poll(pin::Pin::new(read_mutable_image_header_fut), chip, cx) {
                            task::Poll::Ready(Ok(mutable_image_header)) => mutable_image_header,
                            task::Poll::Ready(Err(e)) => break Err(e),
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    // Create a CocoonFsConfig from the static + mutable image headers.
                    let static_image_header = match static_image_header.take() {
                        Some(static_image_header) => static_image_header,
                        None => break Err(nvfs_err_internal!()),
                    };
                    let image_header::StaticImageHeader { image_layout, salt } = static_image_header;
                    let image_header::MutableImageHeader {
                        root_hmac_digest,
                        inode_index_entry_leaf_node_preauth_cca_protection_digest,
                        inode_index_entry_leaf_node_block_ptr,
                        image_size,
                    } = mutable_image_header;
                    this.root_hmac_digest = root_hmac_digest;
                    this.inode_index_entry_leaf_node_preauth_cca_protection_digest =
                        inode_index_entry_leaf_node_preauth_cca_protection_digest;
                    this.image_size = image_size;

                    let salt_len = match u8::try_from(salt.len()) {
                        Ok(salt_len) => salt_len,
                        Err(_) => break Err(NvFsError::from(CocoonFsFormatError::InvalidSaltLength)),
                    };
                    let image_header_end =
                        image_header::MutableImageHeader::physical_location(&image_layout, salt_len).end();

                    let root_key = match root_key.take() {
                        Some(root_key) => root_key,
                        None => break Err(nvfs_err_internal!()),
                    };

                    let fs_config = CocoonFsConfig {
                        image_layout: image_layout.clone(),
                        salt,
                        inode_index_entry_leaf_node_block_ptr,
                        enable_trimming: *enable_trimming,
                        root_key,
                        image_header_end,
                    };
                    let fs_config = this.fs_config.insert(fs_config);

                    // Proceed to reading the Inode Index Tree entry leaf node.
                    let image_layout = &fs_config.image_layout;
                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                    let inode_index_entry_leaf_node_allocation_blocks_begin = match fs_config
                        .inode_index_entry_leaf_node_block_ptr
                        .decode(allocation_block_size_128b_log2)
                    {
                        Ok(Some(inode_index_entry_leaf_node_allocation_blocks_begin)) => {
                            inode_index_entry_leaf_node_allocation_blocks_begin
                        }
                        Ok(None) => break Err(nvfs_err_internal!()),
                        Err(e) => break Err(e),
                    };

                    let read_inode_index_entry_leaf_node_fut =
                        inode_index::InodeIndexReadEntryLeafTreeNodePreauthCcaProtectedFuture::new(
                            inode_index_entry_leaf_node_allocation_blocks_begin,
                        );
                    this.fut_state = CocoonFsOpenFsFutureState::ReadInodeIndexEntryLeafNode {
                        read_inode_index_entry_leaf_node_fut,
                    };
                }
                CocoonFsOpenFsFutureState::ReadInodeIndexEntryLeafNode {
                    read_inode_index_entry_leaf_node_fut,
                } => {
                    let fs_config = match this.fs_config.as_ref() {
                        Some(fs_config) => fs_config,
                        None => break Err(nvfs_err_internal!()),
                    };
                    let image_layout = &fs_config.image_layout;
                    let keys_cache = match this.keys_cache.as_mut() {
                        Some(keys_cache) => keys_cache,
                        None => break Err(nvfs_err_internal!()),
                    };
                    let mut keys_cache = keys::KeyCacheRef::<ST>::new_mut(keys_cache);

                    let (inode_index_entry_leaf_node, inode_index_tree_layout) =
                        match inode_index::InodeIndexReadEntryLeafTreeNodePreauthCcaProtectedFuture::poll(
                            pin::Pin::new(read_inode_index_entry_leaf_node_fut),
                            chip,
                            &this.inode_index_entry_leaf_node_preauth_cca_protection_digest,
                            image_layout,
                            &fs_config.root_key,
                            &mut keys_cache,
                            cx,
                        ) {
                            task::Poll::Ready(Ok((inode_index_entry_leaf_node, inode_index_tree_layout))) => {
                                (inode_index_entry_leaf_node, inode_index_tree_layout)
                            }
                            task::Poll::Ready(Err(e)) => break Err(e),
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    // Lookup the entries for the AuthTree and AllocBitmap special inodes.
                    let auth_tree_inode_entry_index = match inode_index_entry_leaf_node
                        .lookup(inode_index::SpecialInode::AuthTree as u32, &inode_index_tree_layout)
                    {
                        Ok(Ok(auth_tree_entry_index)) => auth_tree_entry_index,
                        Ok(Err(_)) => break Err(NvFsError::from(CocoonFsFormatError::SpecialInodeMissing)),
                        Err(e) => break Err(e),
                    };
                    let auth_tree_extent_ptr = match inode_index_entry_leaf_node
                        .entry_extent_ptr(auth_tree_inode_entry_index, &inode_index_tree_layout)
                    {
                        Ok(auth_tree_extent_ptr) => auth_tree_extent_ptr,
                        Err(e) => break Err(e),
                    };

                    let alloc_bitmap_inode_entry_index = match inode_index_entry_leaf_node
                        .lookup(inode_index::SpecialInode::AllocBitmap as u32, &inode_index_tree_layout)
                    {
                        Ok(Ok(alloc_bitmap_entry_index)) => alloc_bitmap_entry_index,
                        Ok(Err(_)) => break Err(NvFsError::from(CocoonFsFormatError::SpecialInodeMissing)),
                        Err(e) => break Err(e),
                    };
                    let alloc_bitmap_inode_entry_extent_ptr = match inode_index_entry_leaf_node
                        .entry_extent_ptr(alloc_bitmap_inode_entry_index, &inode_index_tree_layout)
                    {
                        Ok(alloc_bitmap_inode_entry_extent_ptr) => alloc_bitmap_inode_entry_extent_ptr,
                        Err(e) => break Err(e),
                    };

                    // Now see whether these are direct or indirect extent pointers and proceed to
                    // reading the inode extents lists as appropriate.
                    match auth_tree_extent_ptr.decode(image_layout.allocation_block_size_128b_log2 as u32) {
                        Ok(Some((_, true))) => {
                            // Indirect extent.
                            let read_auth_tree_inode_extents_list_fut =
                                match inode_extents_list::InodeExtentsListReadPreAuthFuture::new(
                                    inode_index::SpecialInode::AuthTree as u32,
                                    &auth_tree_extent_ptr,
                                    &fs_config.root_key,
                                    &mut keys_cache,
                                    image_layout,
                                ) {
                                    Ok(read_auth_tree_inode_extents_list_fut) => read_auth_tree_inode_extents_list_fut,
                                    Err(e) => break Err(e),
                                };
                            this.fut_state = CocoonFsOpenFsFutureState::ReadAuthTreeInodeExtentsList {
                                read_auth_tree_inode_extents_list_fut,
                                alloc_bitmap_inode_entry_extent_ptr,
                            };
                        }
                        Ok(Some((auth_tree_extent, false))) => {
                            // Direct extent. Add it and proceed to the Allocation Bitmap.
                            let mut auth_tree_extents = extents::PhysicalExtents::new();
                            if let Err(e) = auth_tree_extents.push_extent(&auth_tree_extent, true) {
                                break Err(e);
                            }
                            this.fut_state = CocoonFsOpenFsFutureState::ReadAllocBitmapInodeExtentsListPrepare {
                                alloc_bitmap_inode_entry_extent_ptr,
                                auth_tree_extents: extents::LogicalExtents::from(auth_tree_extents),
                            };
                        }
                        Ok(None) => {
                            // The inode exists, but the extents reference is nil, which is invalid.
                            break Err(NvFsError::from(CocoonFsFormatError::InvalidExtents));
                        }
                        Err(e) => break Err(e),
                    }
                }
                CocoonFsOpenFsFutureState::ReadAuthTreeInodeExtentsList {
                    read_auth_tree_inode_extents_list_fut,
                    alloc_bitmap_inode_entry_extent_ptr,
                } => {
                    let auth_tree_extents = match chip::NvChipFuture::poll(
                        pin::Pin::new(read_auth_tree_inode_extents_list_fut),
                        chip,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(auth_tree_extents)) => auth_tree_extents,
                        task::Poll::Ready(Err(e)) => break Err(e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    this.fut_state = CocoonFsOpenFsFutureState::ReadAllocBitmapInodeExtentsListPrepare {
                        alloc_bitmap_inode_entry_extent_ptr: *alloc_bitmap_inode_entry_extent_ptr,
                        auth_tree_extents: extents::LogicalExtents::from(auth_tree_extents),
                    };
                }
                CocoonFsOpenFsFutureState::ReadAllocBitmapInodeExtentsListPrepare {
                    alloc_bitmap_inode_entry_extent_ptr,
                    auth_tree_extents,
                } => {
                    let fs_config = match this.fs_config.as_ref() {
                        Some(fs_config) => fs_config,
                        None => break Err(nvfs_err_internal!()),
                    };
                    let image_layout = &fs_config.image_layout;

                    match alloc_bitmap_inode_entry_extent_ptr
                        .decode(image_layout.allocation_block_size_128b_log2 as u32)
                    {
                        Ok(Some((_, true))) => {
                            // Indirect extent.
                            let keys_cache = match this.keys_cache.as_mut() {
                                Some(keys_cache) => keys_cache,
                                None => break Err(nvfs_err_internal!()),
                            };
                            let mut keys_cache = keys::KeyCacheRef::<ST>::new_mut(keys_cache);

                            let read_alloc_bitmap_inode_extents_list_fut =
                                match inode_extents_list::InodeExtentsListReadPreAuthFuture::new(
                                    inode_index::SpecialInode::AllocBitmap as u32,
                                    alloc_bitmap_inode_entry_extent_ptr,
                                    &fs_config.root_key,
                                    &mut keys_cache,
                                    image_layout,
                                ) {
                                    Ok(read_alloc_bitmap_inode_extents_list_fut) => {
                                        read_alloc_bitmap_inode_extents_list_fut
                                    }
                                    Err(e) => break Err(e),
                                };
                            this.fut_state = CocoonFsOpenFsFutureState::ReadAllocBitmapInodeExtentsList {
                                read_alloc_bitmap_inode_extents_list_fut,
                                auth_tree_extents: mem::replace(auth_tree_extents, extents::LogicalExtents::new()),
                            };
                        }
                        Ok(Some((alloc_bitmap_extent, false))) => {
                            // Direct extent. Add it and proceed to the Allocation Bitmap.
                            let mut alloc_bitmap_extents = extents::PhysicalExtents::new();
                            if let Err(e) = alloc_bitmap_extents.push_extent(&alloc_bitmap_extent, true) {
                                break Err(e);
                            }
                            this.fut_state = CocoonFsOpenFsFutureState::ReadAllocBitmapFilePrepare {
                                auth_tree_extents: mem::replace(auth_tree_extents, extents::LogicalExtents::new()),
                                alloc_bitmap_extents,
                            };
                        }
                        Ok(None) => {
                            // The inode exists, but the extents reference is nil, which is invalid.
                            break Err(NvFsError::from(CocoonFsFormatError::InvalidExtents));
                        }
                        Err(e) => break Err(e),
                    }
                }
                CocoonFsOpenFsFutureState::ReadAllocBitmapInodeExtentsList {
                    read_alloc_bitmap_inode_extents_list_fut,
                    auth_tree_extents,
                } => {
                    let alloc_bitmap_extents = match chip::NvChipFuture::poll(
                        pin::Pin::new(read_alloc_bitmap_inode_extents_list_fut),
                        chip,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(auth_tree_extents)) => auth_tree_extents,
                        task::Poll::Ready(Err(e)) => break Err(e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    this.fut_state = CocoonFsOpenFsFutureState::ReadAllocBitmapFilePrepare {
                        auth_tree_extents: mem::replace(auth_tree_extents, extents::LogicalExtents::new()),
                        alloc_bitmap_extents,
                    };
                }
                CocoonFsOpenFsFutureState::ReadAllocBitmapFilePrepare {
                    auth_tree_extents,
                    alloc_bitmap_extents,
                } => {
                    let fs_config = match this.fs_config.as_ref() {
                        Some(fs_config) => fs_config,
                        None => break Err(nvfs_err_internal!()),
                    };
                    let image_layout = &fs_config.image_layout;
                    let keys_cache = match this.keys_cache.as_mut() {
                        Some(keys_cache) => keys_cache,
                        None => break Err(nvfs_err_internal!()),
                    };
                    let mut keys_cache = keys::KeyCacheRef::<ST>::new_mut(keys_cache);

                    let auth_tree_extents = mem::replace(auth_tree_extents, extents::LogicalExtents::new());
                    let alloc_bitmap_extents = mem::replace(alloc_bitmap_extents, extents::PhysicalExtents::new());

                    // Bootstrap the authentication through the Authentication
                    // Tree.
                    // The Allocation Bitmap's extents are aligned to the
                    // Authentication Tree Data Block size.
                    // Also they're clearly allocated. That means everything to
                    // authenticate the Allocation Bitmap through the
                    // Authentication Tree is available now.
                    // Once the Allocation Bitmap has been read, everything else
                    // can get authenticated through the
                    // tree as well. (In general, the Allocation
                    // Bitmap is needed for authentications, to determine how to
                    // handle each Allocation Block within a
                    // single Authentication Tree Data Block).
                    let auth_tree = match auth_tree::AuthTree::new(
                        &fs_config.root_key,
                        image_layout,
                        &fs_config.inode_index_entry_leaf_node_block_ptr,
                        this.image_size,
                        auth_tree_extents,
                        &alloc_bitmap_extents,
                        mem::take(&mut this.root_hmac_digest),
                    ) {
                        Ok(auth_tree) => auth_tree,
                        Err(e) => break Err(e),
                    };
                    this.auth_tree = Some(auth_tree);

                    // The ReadBuffer is used for reading in the Allocation Bitmap File, create it.
                    let read_buffer = match read_buffer::ReadBuffer::new(image_layout, chip) {
                        Ok(read_buffer) => read_buffer,
                        Err(e) => break Err(e),
                    };
                    this.read_buffer = Some(read_buffer);

                    let alloc_bitmap_file = match alloc_bitmap::AllocBitmapFile::new(image_layout, alloc_bitmap_extents)
                    {
                        Ok(alloc_bitmap_file) => alloc_bitmap_file,
                        Err(e) => break Err(e),
                    };
                    let alloc_bitmap_file = this.alloc_bitmap_file.insert(alloc_bitmap_file);

                    let read_alloc_bitmap_file_fut = match alloc_bitmap::AllocBitmapFileReadFuture::new(
                        alloc_bitmap_file,
                        image_layout,
                        &fs_config.root_key,
                        &mut keys_cache,
                    ) {
                        Ok(read_alloc_bitmap_file_fut) => read_alloc_bitmap_file_fut,
                        Err(e) => break Err(e),
                    };
                    this.fut_state = CocoonFsOpenFsFutureState::ReadAllocBitmapFile {
                        read_alloc_bitmap_file_fut,
                    };
                }
                CocoonFsOpenFsFutureState::ReadAllocBitmapFile {
                    read_alloc_bitmap_file_fut,
                } => {
                    let fs_config = match this.fs_config.as_ref() {
                        Some(fs_config) => fs_config,
                        None => break Err(nvfs_err_internal!()),
                    };
                    let image_layout = &fs_config.image_layout;

                    let auth_tree = match this.auth_tree.as_mut() {
                        Some(auth_tree) => auth_tree,
                        None => break Err(nvfs_err_internal!()),
                    };
                    let mut auth_tree = auth_tree::AuthTreeRef::MutRef { tree: auth_tree };

                    let alloc_bitmap_file = match this.alloc_bitmap_file.as_ref() {
                        Some(alloc_bitmap_file) => alloc_bitmap_file,
                        None => break Err(nvfs_err_internal!()),
                    };

                    let read_buffer = match this.read_buffer.as_ref() {
                        Some(read_buffer) => read_buffer,
                        None => break Err(nvfs_err_internal!()),
                    };

                    let alloc_bitmap = match alloc_bitmap::AllocBitmapFileReadFuture::poll(
                        pin::Pin::new(read_alloc_bitmap_file_fut),
                        chip,
                        alloc_bitmap_file,
                        image_layout,
                        fs_config.image_header_end,
                        &mut auth_tree,
                        read_buffer,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(alloc_bitmap)) => alloc_bitmap,
                        task::Poll::Ready(Err(e)) => break Err(e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    this.alloc_bitmap = Some(alloc_bitmap);

                    // Finally open the Inode Index.
                    let keys_cache = match this.keys_cache.as_mut() {
                        Some(keys_cache) => keys_cache,
                        None => break Err(nvfs_err_internal!()),
                    };
                    let mut keys_cache = keys::KeyCacheRef::new_mut(keys_cache);

                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                    let inode_index_entry_leaf_node_allocation_blocks_begin = match fs_config
                        .inode_index_entry_leaf_node_block_ptr
                        .decode(allocation_block_size_128b_log2)
                    {
                        Ok(Some(inode_index_entry_leaf_node_allocation_blocks_begin)) => {
                            inode_index_entry_leaf_node_allocation_blocks_begin
                        }
                        Ok(None) => break Err(nvfs_err_internal!()),
                        Err(e) => break Err(e),
                    };
                    let bootstrap_inode_index_fut = match inode_index::InodeIndexBootstrapFuture::new(
                        inode_index_entry_leaf_node_allocation_blocks_begin,
                        mem::take(&mut this.inode_index_entry_leaf_node_preauth_cca_protection_digest),
                        image_layout,
                        &fs_config.root_key,
                        &mut keys_cache,
                    ) {
                        Ok(bootstrap_inode_index_fut) => bootstrap_inode_index_fut,
                        Err(e) => break Err(e),
                    };
                    this.fut_state = CocoonFsOpenFsFutureState::BootstrapInodeIndex {
                        bootstrap_inode_index_fut,
                    };
                }
                CocoonFsOpenFsFutureState::BootstrapInodeIndex {
                    bootstrap_inode_index_fut,
                } => {
                    let fs_config = match this.fs_config.as_ref() {
                        Some(fs_config) => fs_config,
                        None => break Err(nvfs_err_internal!()),
                    };

                    let auth_tree = match this.auth_tree.as_mut() {
                        Some(auth_tree) => auth_tree,
                        None => break Err(nvfs_err_internal!()),
                    };
                    let mut auth_tree = auth_tree::AuthTreeRef::MutRef { tree: auth_tree };

                    let read_buffer = match this.read_buffer.as_ref() {
                        Some(read_buffer) => read_buffer,
                        None => break Err(nvfs_err_internal!()),
                    };

                    let alloc_bitmap = match this.alloc_bitmap.as_ref() {
                        Some(alloc_bitmap) => alloc_bitmap,
                        None => break Err(nvfs_err_internal!()),
                    };

                    let inode_index = match inode_index::InodeIndexBootstrapFuture::poll(
                        pin::Pin::new(bootstrap_inode_index_fut),
                        chip,
                        fs_config,
                        alloc_bitmap,
                        &mut auth_tree,
                        read_buffer,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(inode_index)) => inode_index,
                        task::Poll::Ready(Err(e)) => break Err(e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    // All done, construct the CocoonFs instance and return it.
                    let fs_config = match this.fs_config.take() {
                        Some(fs_config) => fs_config,
                        None => break Err(nvfs_err_internal!()),
                    };

                    let auth_tree = match this.auth_tree.take() {
                        Some(auth_tree) => auth_tree,
                        None => break Err(nvfs_err_internal!()),
                    };

                    let alloc_bitmap_file = match this.alloc_bitmap_file.take() {
                        Some(alloc_bitmap_file) => alloc_bitmap_file,
                        None => break Err(nvfs_err_internal!()),
                    };

                    let read_buffer = match this.read_buffer.take() {
                        Some(read_buffer) => read_buffer,
                        None => break Err(nvfs_err_internal!()),
                    };

                    let alloc_bitmap = match this.alloc_bitmap.take() {
                        Some(alloc_bitmap) => alloc_bitmap,
                        None => break Err(nvfs_err_internal!()),
                    };

                    let keys_cache = match this.keys_cache.take() {
                        Some(keys_cache) => keys_cache,
                        None => break Err(nvfs_err_internal!()),
                    };

                    let fs_sync_state = CocoonFsSyncState {
                        image_size: this.image_size,
                        alloc_bitmap,
                        alloc_bitmap_file,
                        auth_tree,
                        read_buffer,
                        inode_index,
                        keys_cache: ST::RwLock::from(keys_cache),
                    };

                    let fs = match <ST::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>::try_new_with(|| {
                        let chip = match this.chip.take() {
                            Some(chip) => chip,
                            None => return Err(nvfs_err_internal!()),
                        };
                        Ok((CocoonFs::new(chip, fs_config, fs_sync_state), ()))
                    }) {
                        Ok((fs, _)) => fs,
                        Err(sync_types::SyncRcPtrTryNewWithError::TryNewError(e)) => {
                            break Err(match e {
                                sync_types::SyncRcPtrTryNewError::AllocationFailure => {
                                    NvFsError::MemoryAllocationFailure
                                }
                            });
                        }
                        Err(sync_types::SyncRcPtrTryNewWithError::WithError(e)) => break Err(e),
                    };

                    // Safety: the fs is new and never moved out from again.
                    let fs = unsafe { pin::Pin::new_unchecked(fs) };
                    break Ok(fs);
                }
                CocoonFsOpenFsFutureState::Done => unreachable!(),
            }
        };

        this.fut_state = CocoonFsOpenFsFutureState::Done;
        match result {
            Ok(fs_instance) => task::Poll::Ready(Ok(Ok(fs_instance))),
            Err(e) => {
                let chip = match this.chip.take() {
                    Some(chip) => chip,
                    None => return task::Poll::Ready(Err(e)),
                };
                let raw_root_key = match this.raw_root_key.take() {
                    Some(raw_root_key) => raw_root_key,
                    None => return task::Poll::Ready(Err(e)),
                };
                task::Poll::Ready(Ok(Err((chip, raw_root_key, e))))
            }
        }
    }
}
