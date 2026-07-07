// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`OpenFsFuture`].

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

use crate::{
    blkdev,
    crypto::{rng, symcipher},
    fs::{
        self, NvFsError,
        cocoonfs::{
            FormatError, alloc_bitmap, auth_tree,
            aux_fs_metadata::{
                self, AuxFsMetadata, AuxFsMetadataEncodedExtentsPtrsPair,
                DetermineAuxFsMetadataExtentsReallocationNeededStateFuture,
            },
            extent_ptr, extents,
            fs::{CocoonFs, CocoonFsConfig, CocoonFsSyncRcPtrType, CocoonFsSyncState, CocoonFsSyncStateFilesystemUpdateCounter},
            image_header::{self, FsMetadataMkFsInfo},
            inode_extents_list, inode_index,
            integrity::ExtentIntegrityState,
            journal, keys, layout, mkfs,
            mkfs::MkFsFuture,
            read_buffer,
        },
    },
    nvfs_err_internal, tpm2_interface,
    utils_async::sync_types,
    utils_common::{
        fixed_vec::FixedVec,
        io_slices::{self, IoSlicesIterCommon as _},
        zeroize,
    },
};

#[cfg(doc)]
use crate::fs::cocoonfs::image_header::ReadCoreImageHeaderFutureResult;

use core::{convert, future, marker, mem, pin, task};

/// CocoonFs filesystem metadata.
///
/// Prior to [opening](OpenFsFuture) a CocoonFs instance, it may be required
/// to [read some of its metadata](ReadFsMetadataFuture) first, e.g. when
/// that information is needed to obtain the filesystem root key from a remote
/// party. `FsMetadata` encapsulates that information.
///
/// It may get read in via [`ReadFsMetadataFuture`], and then optionally
/// provided to a subsequent [`OpenFsFuture::new()`] later on. If passed to an
/// [`OpenFsFuture`], that will not re-read the information from storage, as is
/// required to maintain the validity of a `FsMetadata` prior attestation by
/// some external means.
///
/// In case the `FsMetadata` is found to be in the [`FsMetadata::MkFsInfo`]
/// state, the [`OpenFsFuture`] would invoke a [`MkFsFuture`] in the course
/// of the opening operation. Alternatively, if a more fine-grained control over
/// the filesystem creation operation beyond the defaults applied by the
/// [`OpenFsFuture`] is needed, users may pass the [`FsMetadataMkFsInfo`]
/// directly to a [`MkFsFuture::new_with_mkfsinfo()`] themselves instead. Most
/// notably such use cases could include amendments to the initial
/// [`AuxFsMetadata`] found alongside the filesystem creation info header before
/// writing it to the final filesystem image.
///
/// # See also:
///
/// * [`ReadFsMetadataFuture`].
/// * [`OpenFsFuture::new()`].
/// # [`MkFsFuture::new_with_mkfsinfo()`]
pub enum FsMetadata {
    /// The filesystem is formatted.
    Formatted(FsMetadataFormatted),

    /// The filesystem hasn't been formatted yet and contains a filesystem
    /// creation info header only.
    ///
    /// The filesystem will get initialized on storage in the course of
    /// executing the [`OpenFsFuture`]. Alternatively, if more fine-grained
    /// control is needed over the filesystem creation, users may invoke
    /// [`MkFsFuture::new_with_mkfsinfo()`] directly. Most notably such use
    /// cases could include amendments to the initial [`AuxFsMetadata`]
    /// found alongside the filesystem creation info header before writing
    /// it to the final filesystem image.
    MkFsInfo(FsMetadataMkFsInfo),
}

impl FsMetadata {
    /// Get the filesystem instance's salt.
    pub fn get_salt(&self) -> &[u8] {
        match self {
            Self::Formatted(formatted) => formatted.get_salt(),
            Self::MkFsInfo(mkfsinfo) => mkfsinfo.get_salt(),
        }
    }

    /// Get the filesystem instance's configuration parameters.
    ///
    /// Note that the [`ImageLayout`](layout::ImageLayout) includes all of the
    /// filesystem instance's cryptography related parameters, i.e. the
    /// algorithms selection for the various purposes.
    pub fn get_config(&self) -> &layout::ImageLayout {
        match self {
            Self::Formatted(formatted) => formatted.get_config(),
            Self::MkFsInfo(mkfsinfo) => mkfsinfo.get_config(),
        }
    }

    /// Get the filesystem instance's auxiliary metadata.
    pub fn get_aux(&self) -> &aux_fs_metadata::AuxFsMetadata {
        match self {
            Self::Formatted(formatted) => formatted.get_aux(),
            Self::MkFsInfo(mkfsinfo) => mkfsinfo.get_aux(),
        }
    }
}

/// [`FsMetadata::Formatted`] variant details.
pub struct FsMetadataFormatted {
    /// The filesystem's [`StaticImageHeader`](image_header::StaticImageHeader).
    pub(super) header: image_header::StaticImageHeader,
    /// Information about the journal state.
    ///
    /// The journal state is obtained as a byproduct when reading the
    /// [`aux_fs_metadata`](AuxFsMetadata): the journal log head needs to get
    /// examined in order to find a possibly updated [`AuxFsMetadata`] head
    /// extent.
    journal_state: FsMetaDataJournalState,
    /// The [`AuxFsMetadata`] update groups' heads, if any.
    pub(super) aux_fs_metadata_update_groups_heads: AuxFsMetadataEncodedExtentsPtrsPair,
    /// The [`AuxFsMetadata`]'s extents.
    ///
    /// The `aux_fs_metadata_extents` are obtained as a byproduct when
    /// reading the [`aux_fs_metadata`](Self::aux_fs_metadata).
    aux_fs_metadata_extents: extents::PhysicalExtents,
    /// Whether a [`AuxFsMetadata`] extents reallocation is needed.
    ///
    /// A reallocation might be needed for reestablishing the [extra reserve
    /// capacity](AuxFsMetadata::set_extra_reserve_capacity).
    aux_fs_metadata_extents_reallocation_needed: bool,
    /// The filesystem's [`AuxFsMetadata`].
    pub(super) aux_fs_metadata: AuxFsMetadata,
}

impl FsMetadataFormatted {
    /// Get the filesystem instance's salt.
    pub fn get_salt(&self) -> &[u8] {
        &self.header.salt
    }

    /// Get the filesystem instance's configuration parameters.
    ///
    /// Note that the [`ImageLayout`](layout::ImageLayout) includes all of the
    /// filesystem instance's cryptography related parameters, i.e. the
    /// algorithms selection for the various purposes.
    pub fn get_config(&self) -> &layout::ImageLayout {
        &self.header.image_layout
    }

    /// Get the filesystem instance's auxiliary metadata.
    pub fn get_aux(&self) -> &aux_fs_metadata::AuxFsMetadata {
        &self.aux_fs_metadata
    }
}

/// Journal state information kept at [`FsMetadataFormatted::journal_state`].
#[derive(Clone, Copy, Debug)]
enum FsMetaDataJournalState {
    /// The journal is inactive and doesn't need to get reexamined at filesystem
    /// opening time.
    JournalInactive {
        /// The journal log head extent's [`ExtentIntegrityState`].
        journal_log_head_integrity_state: ExtentIntegrityState,
    },
    /// The journal is active.
    JournalLogActive,
}

/// Read a CocoonFs' instance's [`FsMetadata`] from a [block
/// device](blkdev::NvBlkDev).
///
/// # See also:
///
/// * [`FsMetadata`].
/// * [`OpenFsFuture::new()`].
pub struct ReadFsMetadataFuture<B: blkdev::NvBlkDev + marker::Unpin> {
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self. Returned back upon Future completion.
    blkdev: Option<B>,
    fut_state: ReadFsMetadataFutureState<B>,
}

enum ReadFsMetadataFutureState<B: blkdev::NvBlkDev + marker::Unpin> {
    Init,
    ReadCoreImageHeader {
        read_core_image_header_fut: image_header::ReadCoreImageHeaderFuture<B>,
    },
    ReadJournalLogHead {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        static_image_header: Option<image_header::StaticImageHeader>,
        read_journal_log_head_fut: journal::log::JournalLogReadHeadExtentFuture<B>,
    },
    ReadMutableImageHeader {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        static_image_header: Option<image_header::StaticImageHeader>,
        journal_state: FsMetaDataJournalState,
        read_fut: blkdev::helpers::NvBlkDevReadRegionFuture<B, FixedVec<u8, 7>>,
    },
    ReadAuxFsMetaData {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        static_image_header: Option<image_header::StaticImageHeader>,
        journal_state: FsMetaDataJournalState,
        aux_fs_metadata_update_groups_heads: AuxFsMetadataEncodedExtentsPtrsPair,
        read_aux_fs_metadata_fut: aux_fs_metadata::ReadAuxFsMetadataFuture<B>,
    },
    Done,
}

impl<B: blkdev::NvBlkDev + marker::Unpin> ReadFsMetadataFuture<B> {
    /// Instantiate a [`ReadFsMetadataFuture`].
    ///
    /// On error, the input `blkdev` is returned directly as part of the `Err`.
    /// On success, the [`ReadFsMetadataFuture`] assumes its ownership for
    /// the duration of the operation. It will get eventually returned back
    /// from [`poll()`](Self::poll) upon completion.
    ///
    /// # Arguments:
    ///
    /// * `blkdev` - The filesystem image backing storage.
    pub fn new(blkdev: B) -> Result<Self, (B, NvFsError)> {
        Ok(Self {
            blkdev: Some(blkdev),
            fut_state: ReadFsMetadataFutureState::Init,
        })
    }
}

impl<B: blkdev::NvBlkDev + marker::Unpin> future::Future for ReadFsMetadataFuture<B> {
    /// Output type of [`poll()`](Self::poll).
    ///
    /// A two-level [`Result`] is returned from the
    /// [`Future::poll()`](future::Future::poll):
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering an internal error and the input
    ///   [`NvBlkDev`](blkdev::NvBlkDev) is lost.
    /// * `Ok((blkdev, ...))` - Otherwise the outer level [`Result`] is set to
    ///   [`Ok`] and a pair of the input `blkdev` and the operation result will
    ///   get returned within:
    ///   * `Ok((blkdev, Err(e)))` - In case of an error, the error reason `e`
    ///     is returned in an [`Err`].
    ///   * `Ok((blkdev, Ok(metadata)))` - Otherwise the filesystem metadata
    ///     read from the `blkdev` is returned.
    type Output = Result<(B, Result<FsMetadata, NvFsError>), NvFsError>;

    fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        let result = loop {
            match &mut this.fut_state {
                ReadFsMetadataFutureState::Init => {
                    this.fut_state = ReadFsMetadataFutureState::ReadCoreImageHeader {
                        read_core_image_header_fut: image_header::ReadCoreImageHeaderFuture::new(),
                    };
                }
                ReadFsMetadataFutureState::ReadCoreImageHeader {
                    read_core_image_header_fut,
                } => {
                    let blkdev = match this.blkdev.as_mut() {
                        Some(blkdev) => blkdev,
                        None => {
                            this.fut_state = ReadFsMetadataFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(read_core_image_header_fut), blkdev, cx) {
                        task::Poll::Ready(Ok(image_header::ReadCoreImageHeaderFutureResult::StaticImageHeader(
                            static_image_header,
                        ))) => {
                            // The auxiliary filesystem metadata might have been updated by a pending
                            // journal. Proceed to examining the journal log head and obtain
                            // the pointers to the AuxFsMetadata update groups' heads from its plaintext
                            // header if one is active.
                            let salt_len = match u8::try_from(static_image_header.salt.len()) {
                                Ok(salt_len) => salt_len,
                                Err(_) => {
                                    break Err(NvFsError::from(FormatError::InvalidSaltLength));
                                }
                            };
                            let image_header_end = image_header::MutableImageHeader::physical_location(
                                &static_image_header.image_layout,
                                salt_len,
                            )
                            .end();
                            let journal_log_head_extent = match journal::log::JournalLog::head_extent_physical_location(
                                &static_image_header.image_layout,
                                image_header_end,
                            ) {
                                Ok(journal_log_head_extent) => journal_log_head_extent.0,
                                Err(e) => break Err(e),
                            };

                            this.fut_state = ReadFsMetadataFutureState::ReadJournalLogHead {
                                static_image_header: Some(static_image_header),
                                read_journal_log_head_fut: journal::log::JournalLogReadHeadExtentFuture::new(
                                    journal_log_head_extent,
                                ),
                            };
                        }
                        task::Poll::Ready(Ok(image_header::ReadCoreImageHeaderFutureResult::MkFsInfoHeader(
                            mkfsinfo,
                        ))) => {
                            break Ok(FsMetadata::MkFsInfo(mkfsinfo));
                        }
                        task::Poll::Ready(Err(e)) => break Err(e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                }
                ReadFsMetadataFutureState::ReadJournalLogHead {
                    static_image_header: fut_static_image_header,
                    read_journal_log_head_fut,
                } => {
                    let blkdev = match this.blkdev.as_mut() {
                        Some(blkdev) => blkdev,
                        None => {
                            this.fut_state = ReadFsMetadataFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };
                    let static_image_header = match fut_static_image_header.as_ref() {
                        Some(static_image_header) => static_image_header,
                        None => break Err(nvfs_err_internal!()),
                    };
                    let image_layout = &static_image_header.image_layout;
                    let (journal_log_head_extent, journal_log_head_integrity_state) =
                        match journal::log::JournalLogReadHeadExtentFuture::poll(
                            pin::Pin::new(read_journal_log_head_fut),
                            blkdev,
                            image_layout,
                            cx,
                        ) {
                            task::Poll::Ready(Ok((journal_log_head_extent, journal_log_head_integrity_state))) => {
                                (journal_log_head_extent, journal_log_head_integrity_state)
                            }
                            task::Poll::Ready(Err(e)) => break Err(e),
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    match journal_log_head_extent {
                        Some([journal_log_head_extent_head, journal_log_head_extent_tail]) => {
                            // The journal is active, obtain the pointers to the AuxFsMetadata update
                            // groups' heads from its plaintext header.
                            let aux_fs_metadata_update_groups_heads =
                                match journal::log::JournalLog::plaintext_header_decode_aux_fs_metadata_update_groups_heads(
                                    io_slices::BuffersSliceIoSlicesIter::new(&[
                                        &journal_log_head_extent_head,
                                        &journal_log_head_extent_tail,
                                    ]),
                                    image_layout,
                                ) {
                                    Ok(aux_fs_metadata_update_groups_heads) => aux_fs_metadata_update_groups_heads,
                                    Err(e) => break Err(e),
                                };
                            let read_aux_fs_metadata_fut = aux_fs_metadata::ReadAuxFsMetadataFuture::new(
                                aux_fs_metadata_update_groups_heads,
                                image_layout,
                            );
                            this.fut_state = ReadFsMetadataFutureState::ReadAuxFsMetaData {
                                static_image_header: fut_static_image_header.take(),
                                journal_state: FsMetaDataJournalState::JournalLogActive,
                                aux_fs_metadata_update_groups_heads,
                                read_aux_fs_metadata_fut,
                            };
                        }
                        None => {
                            // The journal log is inactive. Proceed to reading the
                            // MutableImageHeader and obtain the pointers to the AuxFsMetadata
                            // update groups from there.
                            let salt_len = match u8::try_from(static_image_header.salt.len()) {
                                Ok(salt_len) => salt_len,
                                Err(_) => {
                                    break Err(NvFsError::from(FormatError::InvalidSaltLength));
                                }
                            };
                            // We only need the first few bytes, so read the minimum possible of
                            // 128B. Note that the beginning in units of Bytes is always <= 2^63.
                            let mutable_image_header_allocation_blocks_begin =
                                image_header::MutableImageHeader::physical_location(image_layout, salt_len).begin();
                            let mutable_image_header_buf = match FixedVec::new_with_default(128) {
                                Ok(mutable_image_header_buf) => mutable_image_header_buf,
                                Err(e) => break Err(NvFsError::from(e)),
                            };
                            let read_fut = blkdev::helpers::NvBlkDevReadRegionFuture::new(
                                u64::from(mutable_image_header_allocation_blocks_begin)
                                    << (image_layout.allocation_block_size_128b_log2 as u32),
                                1,
                                0,
                                mutable_image_header_buf,
                                0,
                                0,
                            );
                            this.fut_state = ReadFsMetadataFutureState::ReadMutableImageHeader {
                                static_image_header: fut_static_image_header.take(),
                                journal_state: FsMetaDataJournalState::JournalInactive {
                                    journal_log_head_integrity_state,
                                },
                                read_fut,
                            };
                        }
                    }
                }
                ReadFsMetadataFutureState::ReadMutableImageHeader {
                    static_image_header,
                    journal_state,
                    read_fut,
                } => {
                    let blkdev = match this.blkdev.as_mut() {
                        Some(blkdev) => blkdev,
                        None => {
                            this.fut_state = ReadFsMetadataFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    let mutable_image_header_buf =
                        match blkdev::NvBlkDevFuture::poll(pin::Pin::new(read_fut), blkdev, cx) {
                            task::Poll::Ready(Ok((mutable_image_header_buf, Ok(())))) => mutable_image_header_buf,
                            task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => break Err(NvFsError::from(e)),
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    let aux_fs_metadata_update_groups_heads =
                        match image_header::MutableImageHeader::decode_aux_fs_metadata_update_groups_heads(
                            io_slices::SingletonIoSlice::new(&mutable_image_header_buf).map_infallible_err(),
                        ) {
                            Ok(aux_fs_metadata_update_groups_heads) => aux_fs_metadata_update_groups_heads,
                            Err(e) => break Err(e),
                        };

                    let static_image_header = match static_image_header.take() {
                        Some(static_image_header) => static_image_header,
                        None => {
                            break Err(nvfs_err_internal!());
                        }
                    };
                    let image_layout = &static_image_header.image_layout;
                    let read_aux_fs_metadata_fut = aux_fs_metadata::ReadAuxFsMetadataFuture::new(
                        aux_fs_metadata_update_groups_heads,
                        image_layout,
                    );
                    this.fut_state = ReadFsMetadataFutureState::ReadAuxFsMetaData {
                        static_image_header: Some(static_image_header),
                        journal_state: *journal_state,
                        aux_fs_metadata_update_groups_heads,
                        read_aux_fs_metadata_fut,
                    };
                }
                ReadFsMetadataFutureState::ReadAuxFsMetaData {
                    static_image_header,
                    journal_state,
                    aux_fs_metadata_update_groups_heads,
                    read_aux_fs_metadata_fut,
                } => {
                    let blkdev = match this.blkdev.as_mut() {
                        Some(blkdev) => blkdev,
                        None => {
                            this.fut_state = ReadFsMetadataFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    let (aux_fs_metadata_extents, aux_fs_metadata_extents_reallocation_needed, aux_fs_metadata) =
                        match blkdev::NvBlkDevFuture::poll(pin::Pin::new(read_aux_fs_metadata_fut), blkdev, cx) {
                            task::Poll::Ready(Ok((
                                aux_fs_metadata_extents,
                                aux_fs_metadata_extents_reallocation_needed,
                                aux_fs_metadata,
                            ))) => (
                                aux_fs_metadata_extents,
                                aux_fs_metadata_extents_reallocation_needed,
                                aux_fs_metadata,
                            ),
                            task::Poll::Ready(Err(e)) => break Err(e),
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    let static_image_header = match static_image_header.take() {
                        Some(static_image_header) => static_image_header,
                        None => {
                            break Err(nvfs_err_internal!());
                        }
                    };

                    break Ok(FsMetadata::Formatted(FsMetadataFormatted {
                        header: static_image_header,
                        journal_state: *journal_state,
                        aux_fs_metadata_update_groups_heads: *aux_fs_metadata_update_groups_heads,
                        aux_fs_metadata_extents,
                        aux_fs_metadata_extents_reallocation_needed,
                        aux_fs_metadata,
                    }));
                }
                ReadFsMetadataFutureState::Done => unreachable!(),
            }
        };

        this.fut_state = ReadFsMetadataFutureState::Done;
        let blkdev = match this.blkdev.take() {
            Some(blkdev) => blkdev,
            None => return task::Poll::Ready(Err(nvfs_err_internal!())),
        };

        task::Poll::Ready(Ok((blkdev, result)))
    }
}

/// Open a CocoonFs instance.
///
/// Prior to opening a CocoonFs filesystem, its [`FsMetadata`] may get
/// [read in separately](ReadFsMetadataFuture) first if required, e.g. as input
/// to some external workflow for obtaining the filesystem root key. The
/// [`FsMetadata`] instance may then get subsequently passed onwards to
/// [`OpenFsFuture::new()`] in order to avoid a re-read from storage, to avoid
/// TOCTOU issues in particular.
///
/// If a filesystem creation info header is found on the storage, the filesystem
/// will get created ("mkfs") first in the course of the opening operation.
///
/// In case a previously obtained [`FsMetadata`] indicates the presence of a
/// filesystem creation info header, i.e. is in the [`FsMetadata::MkFsInfo`]
/// state, users may invoke a [`MkFsFuture::new_with_mkfsinfo()`] on it directly
/// themselves instead of running it though a `OpenFsFuture` if a more
/// fine-grained control over the creation beyond the defaults applied by the
/// `OpenFsFuture` is needed. Most notably such use cases could include
/// amendments to the initial [`AuxFsMetadata`] found alongside the filesystem
/// creation info header before writing it to the final filesystem image.
///
/// # See also:
///
/// * [`ReadFsMetadataFuture`].
/// * [`WriteMkFsInfoHeaderFuture`](super::WriteMkFsInfoHeaderFuture).
/// * [`MkFsFuture::new_with_mkfsinfo()`].
pub struct OpenFsFuture<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev + marker::Unpin>
where
    auth_tree::AuthTree<ST>: marker::Unpin,
    read_buffer::ReadBuffer<ST>: marker::Unpin,
    ST::RwLock<inode_index::InodeIndexTreeNodeCache>: marker::Unpin,
{
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self. Transferred to the inner MkFsFuture in case a [`MkFsInfoHeader`] is found.
    blkdev: Option<B>,

    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self. Transferred to the inner MkFsFuture in case a [`MkFsInfoHeader`] is found.
    rng: Option<Box<dyn rng::RngCoreDispatchable + marker::Send>>,

    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self.
    raw_root_key: Option<zeroize::Zeroizing<Vec<u8>>>,

    // Initialized after the journal has been replayed.
    journal_log_head_integrity_state: ExtentIntegrityState,

    // Initialized after the static + mutable image headers have been read.
    fs_config: Option<CocoonFsConfig>,

    // Initialized after the static + mutable image headers have been read.
    aux_fs_metadata_update_groups_heads: AuxFsMetadataEncodedExtentsPtrsPair,

    // Initialized after the static + mutable image headers have been read.
    // Gets moved into the AuthTree once constructed.
    root_hmac_digest: FixedVec<u8, 5>,

    // Initialized after the static + mutable image headers have been read.
    // Gets moved into the AuthTree once constructed.
    encrypted_filesystem_update_counter: FixedVec<u8, 4>,

    // Initialized after the static + mutable image headers have been read.
    // Gets moved into the InodeIndex once constructed.
    inode_index_entry_leaf_node_preauth_cca_protection_digest: FixedVec<u8, 5>,

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

    // Initialized either from the input FsMetadataFormatted::aux_fs_metadata_extents_reallocation_needed, if any,
    // or determined from storage.
    aux_fs_metadata_extents_reallocation_needed: Option<bool>,

    #[cfg(test)]
    pub(super) test_fail_apply_mkfsinfo_header: bool,

    fut_state: OpenFsFutureState<ST, B>,
}

/// [`OpenFsFuture`] state-machine state.
#[allow(clippy::large_enum_variant)]
enum OpenFsFutureState<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev>
where
    ST::RwLock<inode_index::InodeIndexTreeNodeCache>: marker::Unpin,
{
    Init {
        enable_trimming: bool,
    },
    ReadCoreImageHeader {
        enable_trimming: bool,
        read_core_image_header_fut: image_header::ReadCoreImageHeaderFuture<B>,
    },
    HaveCoreImageInfo {
        enable_trimming: bool,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        core_image_info: Option<OpenFsFutureCoreImageInfo>,
    },
    MkFs {
        mkfs_fut: mkfs::MkFsFuture<ST, B>,
    },
    ReplayJournal {
        enable_trimming: bool,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        static_image_header: Option<image_header::StaticImageHeader>,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        root_key: Option<keys::RootKey>,
        replay_journal_fut: journal::replay::JournalReplayFuture<B>,
    },
    ReadMutableImageHeaderPrepare {
        enable_trimming: bool,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        static_image_header: Option<image_header::StaticImageHeader>,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        root_key: Option<keys::RootKey>,
    },
    ReadMutableImageHeader {
        enable_trimming: bool,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        static_image_header: Option<image_header::StaticImageHeader>,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        root_key: Option<keys::RootKey>,
        read_mutable_image_header_fut: image_header::ReadMutableImageHeaderFuture<B>,
    },
    ReadInodeIndexEntryLeafNode {
        read_inode_index_entry_leaf_node_fut: inode_index::InodeIndexReadEntryLeafTreeNodePreauthCcaProtectedFuture<B>,
    },
    ReadAuthTreeInodeExtentsList {
        read_auth_tree_inode_extents_list_fut: inode_extents_list::InodeExtentsListReadPreAuthFuture<B>,
        alloc_bitmap_inode_entry_extent_ptr: extent_ptr::EncodedExtentPtr,
    },
    ReadAllocBitmapInodeExtentsListPrepare {
        alloc_bitmap_inode_entry_extent_ptr: extent_ptr::EncodedExtentPtr,
        auth_tree_extents: extents::LogicalExtents,
    },
    ReadAllocBitmapInodeExtentsList {
        read_alloc_bitmap_inode_extents_list_fut: inode_extents_list::InodeExtentsListReadPreAuthFuture<B>,
        auth_tree_extents: extents::LogicalExtents,
    },
    ReadAllocBitmapFilePrepare {
        auth_tree_extents: extents::LogicalExtents,
        alloc_bitmap_extents: extents::PhysicalExtents,
    },
    ReadAllocBitmapFile {
        read_alloc_bitmap_file_fut: alloc_bitmap::AllocBitmapFileReadFuture<B>,
    },
    BootstrapInodeIndex {
        bootstrap_inode_index_fut: inode_index::InodeIndexBootstrapFuture<ST, B>,
    },
    DetermineAuxFsMetadataReallocationNeededState {
        determine_state_fut: DetermineAuxFsMetadataExtentsReallocationNeededStateFuture<B>,
        fs_instance: CocoonFsSyncRcPtrType<ST, B>,
    },
    ReallocateAuxFsMetadataExtents {
        reallocate_fut: OpenFsReallocateAuxFsMetadataExtentsFuture<ST, B>,
        fs_instance: CocoonFsSyncRcPtrType<ST, B>,
    },
    Done,
}

/// Representation of core filesystem information internal to [`OpenFsFuture`].
///
/// The `OpenFsFutureCoreImageInfo` is obtained in either of two ways:
///
/// * through [`OpenFsFutureCoreImageInfo::from<FsMetadata>()`], invoked on the
///   [`FsMetadata`] obtained from a prior [`ReadFsMetadataFuture`] invocation
///   and passed to [`OpenFsFuture::new()`], if any, or
/// * through [`OpenFsFutureCoreImageInfo::from<ReadCoreImageHeaderFutureResult>()`] in case no
///   [`FsMetadata`] had been provided to [`OpenFsFuture::new()`] and the [`OpenFsFuture`] needs to
///   bootstrap the required information itself.
enum OpenFsFutureCoreImageInfo {
    /// The filesystem is formatted.
    Formatted {
        header: image_header::StaticImageHeader,
        /// The journal state found in the [`FsMetadata`] obtained from
        /// a prior [`ReadFsMetadataFuture`] and passed into the
        /// [`OpenFsFuture::new()`].
        journal_state: Option<OpenFsFutureCoreImageInfoJournalState>,
    },
    /// The filesystem hasn't been formatted yet and contains a filesystem
    /// creation info header only.
    ///
    /// The filesystem will get initialized on storage in the course of
    /// executing the [`OpenFsFuture`].
    MkFsInfo(FsMetadataMkFsInfo),
}

/// Representation of the
/// [`OpenFsFutureCoreImageInfo::Formatted::journal_state`] field.
///
/// The `OpenFsFutureCoreImageInfoJournalState`represents the
/// information about the journal state relevant to the [`OpenFsFuture`] as
/// found in a previously obtained [`FsMetadata`] provided to
/// [`OpenFsFuture::new()`].
enum OpenFsFutureCoreImageInfoJournalState {
    /// The journal has been found to be inactive
    ///
    /// The [`OpenFsFuture`] will not attempt to replay the journal as an
    /// optimization.
    JournalInactive {
        /// The journal log head extent's [`ExtentIntegrityState`].
        ///
        /// The journal log head extent's initial [`ExtentIntegrityState`] will
        /// get passed through to the runtime filesystem instance and
        /// will be needed when first writing the journal.
        journal_log_head_integrity_state: ExtentIntegrityState,
    },
    /// The journal has been found to be active and is subject to replay.
    JournalActive {
        /// The [`AuxFsMetadata`] extents made available as a
        /// side-effect (of reading the AuxFsMetadata prior to) opening
        /// the filesystem already.
        ///
        /// The [`AuxFsMetadata`] extents will be needed for reconstructing
        /// the authentication tree during journal replay.
        aux_fs_metadata_extents: extents::PhysicalExtents,
    },
}

impl<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev> OpenFsFuture<ST, B>
where
    auth_tree::AuthTree<ST>: marker::Unpin,
    read_buffer::ReadBuffer<ST>: marker::Unpin,
    ST::RwLock<inode_index::InodeIndexTreeNodeCache>: marker::Unpin,
{
    /// Instantiate a [`OpenFsFuture`].
    ///
    /// On error, the input `blkdev`, `raw_root_key` and `rng` are returned
    /// directly as part of the `Err`. On success, the [`OpenFsFuture`]
    /// assumes their ownership. They will get either get returned back from
    /// [`poll()`](Self::poll) on completion or will be passed onwards to the
    /// resulting [`CocoonFs`] instance as appropriate.
    ///
    /// # Arguments:
    ///
    /// * `blkdev` - The filesystem image backing storage.
    /// * `metadata` - Optional [`FsMetadata`] previously read from `blkdev` via
    ///   a [`ReadFsMetadataFuture`]. If provided, it is assumed that the
    ///   `metadata` has been validated through some external means and the
    ///   information will not get read in again from storage as part of the
    ///   filesystem opening process.
    /// * `raw_root_key` - The filesystem's raw root key material supplied from
    ///   extern.
    /// * `enable_trimming` - Whether to enable the submission of [trim
    ///   commands](blkdev::NvBlkDev::trim) to the underlying storage for the
    ///   [`CocoonFs`] instance eventually returned from [`poll()`](Self::poll)
    ///   upon successful completion.
    /// * `rng` - The [random number generator](rng::RngCoreDispatchable) used
    ///   for the fileystem initialization ("mkfs") in case a filesystem
    ///   creation info header header is found. See
    ///   [`MkFsFuture::new()`](mkfs::MkFsFuture::new) for details.
    #[allow(clippy::type_complexity)]
    pub fn new(
        blkdev: B,
        metadata: Option<FsMetadata>,
        raw_root_key: zeroize::Zeroizing<Vec<u8>>,
        enable_trimming: bool,
        rng: Box<dyn rng::RngCoreDispatchable + marker::Send>,
    ) -> Result<
        Self,
        (
            B,
            zeroize::Zeroizing<Vec<u8>>,
            Box<dyn rng::RngCoreDispatchable + marker::Send>,
            NvFsError,
        ),
    > {
        let keys_cache = match keys::KeyCache::new() {
            Ok(keys_cache) => keys_cache,
            Err(e) => {
                return Err((blkdev, raw_root_key, rng, e));
            }
        };

        let aux_fs_metadata_extents_reallocation_needed =
            if let Some(FsMetadata::Formatted(metadata)) = metadata.as_ref() {
                Some(metadata.aux_fs_metadata_extents_reallocation_needed)
            } else {
                None
            };

        Ok(Self {
            blkdev: Some(blkdev),
            rng: Some(rng),
            raw_root_key: Some(raw_root_key),
            journal_log_head_integrity_state: ExtentIntegrityState::new_indeterminate(),
            fs_config: None,
            aux_fs_metadata_update_groups_heads: AuxFsMetadataEncodedExtentsPtrsPair::new_nil(),
            root_hmac_digest: FixedVec::new_empty(),
            encrypted_filesystem_update_counter: FixedVec::new_empty(),
            inode_index_entry_leaf_node_preauth_cca_protection_digest: FixedVec::new_empty(),
            image_size: layout::AllocBlockCount::from(0u64),
            auth_tree: None,
            alloc_bitmap_file: None,
            read_buffer: None,
            alloc_bitmap: None,
            keys_cache: Some(keys_cache),
            aux_fs_metadata_extents_reallocation_needed,
            #[cfg(test)]
            test_fail_apply_mkfsinfo_header: false,
            fut_state: match metadata {
                Some(metadata) => OpenFsFutureState::HaveCoreImageInfo {
                    enable_trimming,
                    core_image_info: Some(OpenFsFutureCoreImageInfo::from(metadata)),
                },
                None => OpenFsFutureState::Init { enable_trimming },
            },
        })
    }
}

impl<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev> future::Future for OpenFsFuture<ST, B>
where
    auth_tree::AuthTree<ST>: marker::Unpin,
    read_buffer::ReadBuffer<ST>: marker::Unpin,
    ST::RwLock<inode_index::InodeIndexTreeNodeCache>: marker::Unpin,
{
    /// Output type of [`poll()`](Self::poll).
    ///
    /// A two-level [`Result`] is returned from the
    /// [`Future::poll()`](future::Future::poll):
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering an internal error and the input
    ///   [`NvBlkDev`](blkdev::NvBlkDev), raw root key and input [random number
    ///   generator](rng::RngCoreDispatchable) are lost.
    /// * `Ok((rng, ...))` - Otherwise the outer level [`Result`] is set to
    ///   [`Ok`] and a pair of the input [random number
    ///   generator](rng::RngCoreDispatchable), `rng`, and the operation result
    ///   will get returned within:
    ///   * `Ok((rng, Err((blkdev, raw_root_key, e))))` - In case of an error, a
    ///     tuple of the [`NvBlkDev`](blkdev::NvBlkDev) instance, `blkdev`, the
    ///     input root key material `raw_root_key` and the error reason `e` is
    ///     returned in an [`Err`].
    ///   * `Ok((rng, Ok(fs_instance)))` - Otherwise an opened [`CocoonFs`]
    ///     instance `fs_instance` associated with the filesystem just opened is
    ///     returned in an [`Ok`].
    type Output = Result<
        (
            Box<dyn rng::RngCoreDispatchable + marker::Send>,
            Result<CocoonFsSyncRcPtrType<ST, B>, (B, zeroize::Zeroizing<Vec<u8>>, NvFsError)>,
        ),
        NvFsError,
    >;

    fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        let e = loop {
            match &mut this.fut_state {
                OpenFsFutureState::Init { enable_trimming } => {
                    let read_core_image_header_fut = image_header::ReadCoreImageHeaderFuture::new();
                    this.fut_state = OpenFsFutureState::ReadCoreImageHeader {
                        enable_trimming: *enable_trimming,
                        read_core_image_header_fut,
                    };
                }
                OpenFsFutureState::ReadCoreImageHeader {
                    enable_trimming,
                    read_core_image_header_fut,
                } => {
                    let blkdev = match this.blkdev.as_mut() {
                        Some(blkdev) => blkdev,
                        None => break nvfs_err_internal!(),
                    };
                    let image_header =
                        match blkdev::NvBlkDevFuture::poll(pin::Pin::new(read_core_image_header_fut), blkdev, cx) {
                            task::Poll::Ready(Ok(image_header)) => image_header,
                            task::Poll::Ready(Err(e)) => break e,
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    this.fut_state = OpenFsFutureState::HaveCoreImageInfo {
                        enable_trimming: *enable_trimming,
                        core_image_info: Some(OpenFsFutureCoreImageInfo::from(image_header)),
                    };
                }
                OpenFsFutureState::HaveCoreImageInfo {
                    enable_trimming,
                    core_image_info,
                } => {
                    let core_image_info = match core_image_info.take() {
                        Some(core_image_info) => core_image_info,
                        None => break nvfs_err_internal!(),
                    };

                    let raw_root_key = match this.raw_root_key.as_ref() {
                        Some(raw_root_key) => raw_root_key,
                        None => break nvfs_err_internal!(),
                    };

                    match core_image_info {
                        OpenFsFutureCoreImageInfo::Formatted {
                            header: static_image_header,
                            journal_state,
                        } => {
                            // The common case: there's a valid static image header, proceed with opening
                            // the FS.
                            let image_layout = &static_image_header.image_layout;
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
                                Err(e) => break e,
                            };

                            match journal_state {
                                Some(OpenFsFutureCoreImageInfoJournalState::JournalInactive {
                                    journal_log_head_integrity_state,
                                }) => {
                                    // The journal is already known to be inactive, as per the FsMetadata passed to
                                    // Self::new(). Skip the attempt to replay.
                                    this.journal_log_head_integrity_state = journal_log_head_integrity_state;
                                    this.fut_state = OpenFsFutureState::ReadMutableImageHeaderPrepare {
                                        enable_trimming: *enable_trimming,
                                        static_image_header: Some(static_image_header),
                                        root_key: Some(root_key),
                                    };
                                }
                                Some(OpenFsFutureCoreImageInfoJournalState::JournalActive {
                                    aux_fs_metadata_extents,
                                }) => {
                                    // The journal is already known to be active, as per the
                                    // FsMetadata procided to Self::new(). Proceed to replaying the
                                    // journal, and provide the aux_fs_metadata_extents also
                                    // obtained already from the ReadAuxFsMetadataFuture as a
                                    // byproduct. It will need them for reconstructing the
                                    // authentication tree.
                                    let replay_journal_fut = journal::replay::JournalReplayFuture::new(
                                        *enable_trimming,
                                        Some(aux_fs_metadata_extents),
                                    );
                                    this.fut_state = OpenFsFutureState::ReplayJournal {
                                        enable_trimming: *enable_trimming,
                                        static_image_header: Some(static_image_header),
                                        root_key: Some(root_key),
                                        replay_journal_fut,
                                    };
                                }
                                None => {
                                    // No FsMetadata provided to Self::new() and the journal state
                                    // is not known yet. Attempt to replay the journal, the
                                    // JournalReplayFuture will examine the state on storage itself for
                                    // figuring out what to do.
                                    let replay_journal_fut =
                                        journal::replay::JournalReplayFuture::new(*enable_trimming, None);
                                    this.fut_state = OpenFsFutureState::ReplayJournal {
                                        enable_trimming: *enable_trimming,
                                        static_image_header: Some(static_image_header),
                                        root_key: Some(root_key),
                                        replay_journal_fut,
                                    };
                                }
                            }
                        }
                        OpenFsFutureCoreImageInfo::MkFsInfo(mkfsinfo) => {
                            // The filesystem has not been formatted yet, but there's a MkFsInfoHeader. Do
                            // it now.
                            let blkdev = match this.blkdev.take() {
                                Some(blkdev) => blkdev,
                                None => break nvfs_err_internal!(),
                            };
                            let rng = match this.rng.take() {
                                Some(rng) => rng,
                                None => break nvfs_err_internal!(),
                            };

                            let mkfs_fut = match mkfs::MkFsFuture::new_with_mkfsinfo(
                                blkdev,
                                mkfsinfo,
                                None,
                                raw_root_key,
                                *enable_trimming,
                                rng,
                            ) {
                                Ok(mkfs_fut) => mkfs_fut,
                                Err((blkdev, rng, e)) => {
                                    this.blkdev = Some(blkdev);
                                    this.rng = Some(rng);
                                    break e;
                                }
                            };
                            #[cfg(test)]
                            let mkfs_fut = if this.test_fail_apply_mkfsinfo_header {
                                let mut mkfs_fut = mkfs_fut;
                                mkfs_fut.test_fail_write_static_image_header = true;
                                mkfs_fut
                            } else {
                                mkfs_fut
                            };
                            this.fut_state = OpenFsFutureState::MkFs { mkfs_fut }
                        }
                    }
                }
                OpenFsFutureState::MkFs { mkfs_fut } => {
                    match MkFsFuture::poll(pin::Pin::new(mkfs_fut), cx) {
                        task::Poll::Ready(Ok((rng, Ok(fs_instance)))) => {
                            this.fut_state = OpenFsFutureState::Done;
                            return task::Poll::Ready(Ok((rng, Ok(fs_instance))));
                        }
                        task::Poll::Ready(Ok((rng, Err((blkdev, e))))) => {
                            this.blkdev = Some(blkdev);
                            this.rng = Some(rng);
                            break e;
                        }
                        task::Poll::Ready(Err(e)) => break e,
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                }
                OpenFsFutureState::ReplayJournal {
                    enable_trimming,
                    static_image_header: fut_static_image_header,
                    root_key: fut_root_key,
                    replay_journal_fut,
                } => {
                    let blkdev = match this.blkdev.as_mut() {
                        Some(blkdev) => blkdev,
                        None => break nvfs_err_internal!(),
                    };

                    let static_image_header = match fut_static_image_header.as_ref() {
                        Some(static_image_header) => static_image_header,
                        None => break nvfs_err_internal!(),
                    };
                    let image_layout = &static_image_header.image_layout;
                    let salt_len = match u8::try_from(static_image_header.salt.len()) {
                        Ok(salt_len) => salt_len,
                        Err(_) => break NvFsError::from(FormatError::InvalidSaltLength),
                    };

                    let root_key = match fut_root_key.as_ref() {
                        Some(root_key) => root_key,
                        None => break nvfs_err_internal!(),
                    };

                    let keys_cache = match this.keys_cache.as_mut() {
                        Some(keys_cache) => keys_cache,
                        None => break nvfs_err_internal!(),
                    };
                    let mut keys_cache = keys::KeyCacheRef::<ST>::new_mut(keys_cache);

                    this.journal_log_head_integrity_state = match journal::replay::JournalReplayFuture::poll(
                        pin::Pin::new(replay_journal_fut),
                        blkdev,
                        image_layout,
                        salt_len,
                        root_key,
                        &mut keys_cache,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(journal_log_head_integrity_state)) => journal_log_head_integrity_state,
                        task::Poll::Ready(Err(e)) => break e,
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    this.fut_state = OpenFsFutureState::ReadMutableImageHeaderPrepare {
                        enable_trimming: *enable_trimming,
                        static_image_header: fut_static_image_header.take(),
                        root_key: fut_root_key.take(),
                    };
                }
                OpenFsFutureState::ReadMutableImageHeaderPrepare {
                    enable_trimming,
                    static_image_header: fut_static_image_header,
                    root_key,
                } => {
                    let static_image_header = match fut_static_image_header.as_ref() {
                        Some(static_image_header) => static_image_header,
                        None => break nvfs_err_internal!(),
                    };

                    let read_mutable_image_header_fut =
                        match image_header::ReadMutableImageHeaderFuture::new(static_image_header) {
                            Ok(read_mutable_image_header_fut) => read_mutable_image_header_fut,
                            Err(e) => break e,
                        };

                    this.fut_state = OpenFsFutureState::ReadMutableImageHeader {
                        enable_trimming: *enable_trimming,
                        static_image_header: fut_static_image_header.take(),
                        root_key: root_key.take(),
                        read_mutable_image_header_fut,
                    };
                }
                OpenFsFutureState::ReadMutableImageHeader {
                    enable_trimming,
                    static_image_header,
                    root_key,
                    read_mutable_image_header_fut,
                } => {
                    let blkdev = match this.blkdev.as_mut() {
                        Some(blkdev) => blkdev,
                        None => break nvfs_err_internal!(),
                    };

                    let mutable_image_header =
                        match blkdev::NvBlkDevFuture::poll(pin::Pin::new(read_mutable_image_header_fut), blkdev, cx) {
                            task::Poll::Ready(Ok(mutable_image_header)) => mutable_image_header,
                            task::Poll::Ready(Err(e)) => break e,
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    // Create a CocoonFsConfig from the static + mutable image headers.
                    let static_image_header = match static_image_header.take() {
                        Some(static_image_header) => static_image_header,
                        None => break nvfs_err_internal!(),
                    };
                    let image_header::StaticImageHeader { image_layout, salt } = static_image_header;
                    let image_header::MutableImageHeader {
                        aux_fs_metadata_update_groups_heads,
                        root_hmac_digest,
                        encrypted_filesystem_update_counter,
                        inode_index_entry_leaf_node_preauth_cca_protection_digest,
                        inode_index_entry_leaf_node_block_ptr,
                        image_size,
                    } = mutable_image_header;
                    this.aux_fs_metadata_update_groups_heads = aux_fs_metadata_update_groups_heads;
                    this.root_hmac_digest = root_hmac_digest;
                    this.encrypted_filesystem_update_counter = encrypted_filesystem_update_counter;
                    this.inode_index_entry_leaf_node_preauth_cca_protection_digest =
                        inode_index_entry_leaf_node_preauth_cca_protection_digest;
                    this.image_size = image_size;

                    let salt_len = match u8::try_from(salt.len()) {
                        Ok(salt_len) => salt_len,
                        Err(_) => break NvFsError::from(FormatError::InvalidSaltLength),
                    };
                    let image_header_end =
                        image_header::MutableImageHeader::physical_location(&image_layout, salt_len).end();

                    let root_key = match root_key.take() {
                        Some(root_key) => root_key,
                        None => break nvfs_err_internal!(),
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
                        Ok(None) => break nvfs_err_internal!(),
                        Err(e) => break e,
                    };

                    let read_inode_index_entry_leaf_node_fut =
                        inode_index::InodeIndexReadEntryLeafTreeNodePreauthCcaProtectedFuture::new(
                            inode_index_entry_leaf_node_allocation_blocks_begin,
                        );
                    this.fut_state = OpenFsFutureState::ReadInodeIndexEntryLeafNode {
                        read_inode_index_entry_leaf_node_fut,
                    };
                }
                OpenFsFutureState::ReadInodeIndexEntryLeafNode {
                    read_inode_index_entry_leaf_node_fut,
                } => {
                    let blkdev = match this.blkdev.as_mut() {
                        Some(blkdev) => blkdev,
                        None => break nvfs_err_internal!(),
                    };

                    let fs_config = match this.fs_config.as_ref() {
                        Some(fs_config) => fs_config,
                        None => break nvfs_err_internal!(),
                    };
                    let image_layout = &fs_config.image_layout;
                    let keys_cache = match this.keys_cache.as_mut() {
                        Some(keys_cache) => keys_cache,
                        None => break nvfs_err_internal!(),
                    };
                    let mut keys_cache = keys::KeyCacheRef::<ST>::new_mut(keys_cache);

                    let (inode_index_entry_leaf_node, inode_index_tree_layout) =
                        match inode_index::InodeIndexReadEntryLeafTreeNodePreauthCcaProtectedFuture::poll(
                            pin::Pin::new(read_inode_index_entry_leaf_node_fut),
                            blkdev,
                            &this.inode_index_entry_leaf_node_preauth_cca_protection_digest,
                            image_layout,
                            &fs_config.root_key,
                            &mut keys_cache,
                            cx,
                        ) {
                            task::Poll::Ready(Ok((inode_index_entry_leaf_node, inode_index_tree_layout))) => {
                                (inode_index_entry_leaf_node, inode_index_tree_layout)
                            }
                            task::Poll::Ready(Err(e)) => break e,
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    // Lookup the entries for the AuthTree and AllocBitmap special inodes.
                    let auth_tree_inode_entry_index = match inode_index_entry_leaf_node.lookup(
                        inode_index::SpecialInode::AuthTree as inode_index::InodeIndexKeyType,
                        &inode_index_tree_layout,
                    ) {
                        Ok(Ok(auth_tree_entry_index)) => auth_tree_entry_index,
                        Ok(Err(_)) => break NvFsError::from(FormatError::SpecialInodeMissing),
                        Err(e) => break e,
                    };
                    let auth_tree_extent_ptr = match inode_index_entry_leaf_node
                        .entry_extent_ptr(auth_tree_inode_entry_index, &inode_index_tree_layout)
                    {
                        Ok(auth_tree_extent_ptr) => auth_tree_extent_ptr,
                        Err(e) => break e,
                    };

                    let alloc_bitmap_inode_entry_index = match inode_index_entry_leaf_node.lookup(
                        inode_index::SpecialInode::AllocBitmap as inode_index::InodeIndexKeyType,
                        &inode_index_tree_layout,
                    ) {
                        Ok(Ok(alloc_bitmap_entry_index)) => alloc_bitmap_entry_index,
                        Ok(Err(_)) => break NvFsError::from(FormatError::SpecialInodeMissing),
                        Err(e) => break e,
                    };
                    let alloc_bitmap_inode_entry_extent_ptr = match inode_index_entry_leaf_node
                        .entry_extent_ptr(alloc_bitmap_inode_entry_index, &inode_index_tree_layout)
                    {
                        Ok(alloc_bitmap_inode_entry_extent_ptr) => alloc_bitmap_inode_entry_extent_ptr,
                        Err(e) => break e,
                    };

                    // Now see whether these are direct or indirect extent pointers and proceed to
                    // reading the inode extents lists as appropriate.
                    match auth_tree_extent_ptr.decode(image_layout.allocation_block_size_128b_log2 as u32) {
                        Ok(Some((_, true))) => {
                            // Indirect extent.
                            let read_auth_tree_inode_extents_list_fut =
                                match inode_extents_list::InodeExtentsListReadPreAuthFuture::new(
                                    inode_index::SpecialInode::AuthTree as inode_index::InodeIndexKeyType,
                                    &auth_tree_extent_ptr,
                                    &fs_config.root_key,
                                    &mut keys_cache,
                                    image_layout,
                                ) {
                                    Ok(read_auth_tree_inode_extents_list_fut) => read_auth_tree_inode_extents_list_fut,
                                    Err(e) => break e,
                                };
                            this.fut_state = OpenFsFutureState::ReadAuthTreeInodeExtentsList {
                                read_auth_tree_inode_extents_list_fut,
                                alloc_bitmap_inode_entry_extent_ptr,
                            };
                        }
                        Ok(Some((auth_tree_extent, false))) => {
                            // Direct extent. Add it and proceed to the Allocation Bitmap.
                            let mut auth_tree_extents = extents::PhysicalExtents::new();
                            if let Err(e) = auth_tree_extents.push_extent(&auth_tree_extent, true) {
                                break e;
                            }
                            this.fut_state = OpenFsFutureState::ReadAllocBitmapInodeExtentsListPrepare {
                                alloc_bitmap_inode_entry_extent_ptr,
                                auth_tree_extents: extents::LogicalExtents::from(auth_tree_extents),
                            };
                        }
                        Ok(None) => {
                            // The inode exists, but the extents reference is nil, which is invalid.
                            break NvFsError::from(FormatError::InvalidExtents);
                        }
                        Err(e) => break e,
                    }
                }
                OpenFsFutureState::ReadAuthTreeInodeExtentsList {
                    read_auth_tree_inode_extents_list_fut,
                    alloc_bitmap_inode_entry_extent_ptr,
                } => {
                    let blkdev = match this.blkdev.as_mut() {
                        Some(blkdev) => blkdev,
                        None => break nvfs_err_internal!(),
                    };

                    let auth_tree_extents = match blkdev::NvBlkDevFuture::poll(
                        pin::Pin::new(read_auth_tree_inode_extents_list_fut),
                        blkdev,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(auth_tree_extents)) => auth_tree_extents,
                        task::Poll::Ready(Err(e)) => break e,
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    this.fut_state = OpenFsFutureState::ReadAllocBitmapInodeExtentsListPrepare {
                        alloc_bitmap_inode_entry_extent_ptr: *alloc_bitmap_inode_entry_extent_ptr,
                        auth_tree_extents: extents::LogicalExtents::from(auth_tree_extents),
                    };
                }
                OpenFsFutureState::ReadAllocBitmapInodeExtentsListPrepare {
                    alloc_bitmap_inode_entry_extent_ptr,
                    auth_tree_extents,
                } => {
                    let fs_config = match this.fs_config.as_ref() {
                        Some(fs_config) => fs_config,
                        None => break nvfs_err_internal!(),
                    };
                    let image_layout = &fs_config.image_layout;

                    match alloc_bitmap_inode_entry_extent_ptr
                        .decode(image_layout.allocation_block_size_128b_log2 as u32)
                    {
                        Ok(Some((_, true))) => {
                            // Indirect extent.
                            let keys_cache = match this.keys_cache.as_mut() {
                                Some(keys_cache) => keys_cache,
                                None => break nvfs_err_internal!(),
                            };
                            let mut keys_cache = keys::KeyCacheRef::<ST>::new_mut(keys_cache);

                            let read_alloc_bitmap_inode_extents_list_fut =
                                match inode_extents_list::InodeExtentsListReadPreAuthFuture::new(
                                    inode_index::SpecialInode::AllocBitmap as inode_index::InodeIndexKeyType,
                                    alloc_bitmap_inode_entry_extent_ptr,
                                    &fs_config.root_key,
                                    &mut keys_cache,
                                    image_layout,
                                ) {
                                    Ok(read_alloc_bitmap_inode_extents_list_fut) => {
                                        read_alloc_bitmap_inode_extents_list_fut
                                    }
                                    Err(e) => break e,
                                };
                            this.fut_state = OpenFsFutureState::ReadAllocBitmapInodeExtentsList {
                                read_alloc_bitmap_inode_extents_list_fut,
                                auth_tree_extents: mem::replace(auth_tree_extents, extents::LogicalExtents::new()),
                            };
                        }
                        Ok(Some((alloc_bitmap_extent, false))) => {
                            // Direct extent. Add it and proceed to the Allocation Bitmap.
                            let mut alloc_bitmap_extents = extents::PhysicalExtents::new();
                            if let Err(e) = alloc_bitmap_extents.push_extent(&alloc_bitmap_extent, true) {
                                break e;
                            }
                            this.fut_state = OpenFsFutureState::ReadAllocBitmapFilePrepare {
                                auth_tree_extents: mem::replace(auth_tree_extents, extents::LogicalExtents::new()),
                                alloc_bitmap_extents,
                            };
                        }
                        Ok(None) => {
                            // The inode exists, but the extents reference is nil, which is invalid.
                            break NvFsError::from(FormatError::InvalidExtents);
                        }
                        Err(e) => break e,
                    }
                }
                OpenFsFutureState::ReadAllocBitmapInodeExtentsList {
                    read_alloc_bitmap_inode_extents_list_fut,
                    auth_tree_extents,
                } => {
                    let blkdev = match this.blkdev.as_mut() {
                        Some(blkdev) => blkdev,
                        None => break nvfs_err_internal!(),
                    };

                    let alloc_bitmap_extents = match blkdev::NvBlkDevFuture::poll(
                        pin::Pin::new(read_alloc_bitmap_inode_extents_list_fut),
                        blkdev,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(auth_tree_extents)) => auth_tree_extents,
                        task::Poll::Ready(Err(e)) => break e,
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    this.fut_state = OpenFsFutureState::ReadAllocBitmapFilePrepare {
                        auth_tree_extents: mem::replace(auth_tree_extents, extents::LogicalExtents::new()),
                        alloc_bitmap_extents,
                    };
                }
                OpenFsFutureState::ReadAllocBitmapFilePrepare {
                    auth_tree_extents,
                    alloc_bitmap_extents,
                } => {
                    let blkdev = match this.blkdev.as_mut() {
                        Some(blkdev) => blkdev,
                        None => break nvfs_err_internal!(),
                    };

                    let fs_config = match this.fs_config.as_ref() {
                        Some(fs_config) => fs_config,
                        None => break nvfs_err_internal!(),
                    };
                    let image_layout = &fs_config.image_layout;
                    let keys_cache = match this.keys_cache.as_mut() {
                        Some(keys_cache) => keys_cache,
                        None => break nvfs_err_internal!(),
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
                        mem::take(&mut this.encrypted_filesystem_update_counter),
                    ) {
                        Ok(auth_tree) => auth_tree,
                        Err(e) => break e,
                    };
                    this.auth_tree = Some(auth_tree);

                    // The ReadBuffer is used for reading in the Allocation Bitmap File, create it.
                    let read_buffer = match read_buffer::ReadBuffer::new(image_layout, blkdev) {
                        Ok(read_buffer) => read_buffer,
                        Err(e) => break e,
                    };
                    this.read_buffer = Some(read_buffer);

                    let alloc_bitmap_file = match alloc_bitmap::AllocBitmapFile::new(image_layout, alloc_bitmap_extents)
                    {
                        Ok(alloc_bitmap_file) => alloc_bitmap_file,
                        Err(e) => break e,
                    };
                    let alloc_bitmap_file = this.alloc_bitmap_file.insert(alloc_bitmap_file);

                    let read_alloc_bitmap_file_fut = match alloc_bitmap::AllocBitmapFileReadFuture::new(
                        alloc_bitmap_file,
                        image_layout,
                        &fs_config.root_key,
                        &mut keys_cache,
                    ) {
                        Ok(read_alloc_bitmap_file_fut) => read_alloc_bitmap_file_fut,
                        Err(e) => break e,
                    };
                    this.fut_state = OpenFsFutureState::ReadAllocBitmapFile {
                        read_alloc_bitmap_file_fut,
                    };
                }
                OpenFsFutureState::ReadAllocBitmapFile {
                    read_alloc_bitmap_file_fut,
                } => {
                    let blkdev = match this.blkdev.as_mut() {
                        Some(blkdev) => blkdev,
                        None => break nvfs_err_internal!(),
                    };

                    let fs_config = match this.fs_config.as_ref() {
                        Some(fs_config) => fs_config,
                        None => break nvfs_err_internal!(),
                    };
                    let image_layout = &fs_config.image_layout;

                    let auth_tree = match this.auth_tree.as_mut() {
                        Some(auth_tree) => auth_tree,
                        None => break nvfs_err_internal!(),
                    };
                    let mut auth_tree = auth_tree::AuthTreeRef::MutRef { tree: auth_tree };

                    let alloc_bitmap_file = match this.alloc_bitmap_file.as_ref() {
                        Some(alloc_bitmap_file) => alloc_bitmap_file,
                        None => break nvfs_err_internal!(),
                    };

                    let read_buffer = match this.read_buffer.as_ref() {
                        Some(read_buffer) => read_buffer,
                        None => break nvfs_err_internal!(),
                    };

                    let alloc_bitmap = match alloc_bitmap::AllocBitmapFileReadFuture::poll(
                        pin::Pin::new(read_alloc_bitmap_file_fut),
                        blkdev,
                        alloc_bitmap_file,
                        image_layout,
                        fs_config.image_header_end,
                        &mut auth_tree,
                        read_buffer,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(alloc_bitmap)) => alloc_bitmap,
                        task::Poll::Ready(Err(e)) => break e,
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    this.alloc_bitmap = Some(alloc_bitmap);

                    // Finally open the Inode Index.
                    let keys_cache = match this.keys_cache.as_mut() {
                        Some(keys_cache) => keys_cache,
                        None => break nvfs_err_internal!(),
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
                        Ok(None) => break nvfs_err_internal!(),
                        Err(e) => break e,
                    };
                    let bootstrap_inode_index_fut = match inode_index::InodeIndexBootstrapFuture::new(
                        inode_index_entry_leaf_node_allocation_blocks_begin,
                        mem::take(&mut this.inode_index_entry_leaf_node_preauth_cca_protection_digest),
                        image_layout,
                        &fs_config.root_key,
                        &mut keys_cache,
                    ) {
                        Ok(bootstrap_inode_index_fut) => bootstrap_inode_index_fut,
                        Err(e) => break e,
                    };
                    this.fut_state = OpenFsFutureState::BootstrapInodeIndex {
                        bootstrap_inode_index_fut,
                    };
                }
                OpenFsFutureState::BootstrapInodeIndex {
                    bootstrap_inode_index_fut,
                } => {
                    let blkdev = match this.blkdev.as_mut() {
                        Some(blkdev) => blkdev,
                        None => break nvfs_err_internal!(),
                    };

                    let fs_config = match this.fs_config.as_ref() {
                        Some(fs_config) => fs_config,
                        None => break nvfs_err_internal!(),
                    };

                    let auth_tree = match this.auth_tree.as_mut() {
                        Some(auth_tree) => auth_tree,
                        None => break nvfs_err_internal!(),
                    };
                    let mut auth_tree = auth_tree::AuthTreeRef::MutRef { tree: auth_tree };

                    let read_buffer = match this.read_buffer.as_ref() {
                        Some(read_buffer) => read_buffer,
                        None => break nvfs_err_internal!(),
                    };

                    let alloc_bitmap = match this.alloc_bitmap.as_ref() {
                        Some(alloc_bitmap) => alloc_bitmap,
                        None => break nvfs_err_internal!(),
                    };

                    let inode_index = match inode_index::InodeIndexBootstrapFuture::poll(
                        pin::Pin::new(bootstrap_inode_index_fut),
                        blkdev,
                        fs_config,
                        alloc_bitmap,
                        &mut auth_tree,
                        read_buffer,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(inode_index)) => inode_index,
                        task::Poll::Ready(Err(e)) => break e,
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    // The encrypted filesystem update counter got authenticated now as a
                    // side-effect of verifying the Authentication Tree Root HMAC at least once in
                    // the course of bootstrapping the inode index. Decrypt it.
                    let filesystem_update_counter_encryption_key =
                        match fs_config.root_key.derive_key(&keys::KeyId::new(
                            inode_index::SpecialInode::FilesystemUpdateCounter as u64,
                            inode_index::InodeKeySubdomain::InodeData as u32,
                            keys::KeyPurpose::Encryption,
                        )) {
                            Ok(filesystem_update_counter_encryption_key) => filesystem_update_counter_encryption_key,
                            Err(e) => break e,
                        };
                    let filesystem_update_counter_decryption_instance =
                        match symcipher::SymBlockCipherModeDecryptionInstance::new(
                            tpm2_interface::TpmiAlgCipherMode::Cbc,
                            &fs_config.image_layout.block_cipher_alg,
                            &filesystem_update_counter_encryption_key,
                        ) {
                            Ok(filesystem_update_counter_decryption_instance) => {
                                filesystem_update_counter_decryption_instance
                            }
                            Err(e) => break NvFsError::from(e),
                        };
                    let encrypted_filesystem_update_counter = auth_tree.get_encrypted_filesystem_update_counter();
                    let mut decrypted_filesystem_update_counter =
                        match FixedVec::<u8, 4>::new_with_default(encrypted_filesystem_update_counter.len()) {
                            Ok(decrypted_filesystem_update_counter) => decrypted_filesystem_update_counter,
                            Err(e) => break NvFsError::from(e),
                        };
                    // The filesystem update counter always gets encrypted with an all-zeros IV.
                    let all_zeros_iv = match FixedVec::<u8, 4>::new_with_default(
                        filesystem_update_counter_decryption_instance.iv_len(),
                    ) {
                        Ok(all_zeros_iv) => all_zeros_iv,
                        Err(e) => break NvFsError::from(e),
                    };
                    if let Err(e) = filesystem_update_counter_decryption_instance.decrypt(
                        &all_zeros_iv,
                        io_slices::SingletonIoSliceMut::new(&mut decrypted_filesystem_update_counter)
                            .map_infallible_err(),
                        io_slices::SingletonIoSlice::new(encrypted_filesystem_update_counter).map_infallible_err(),
                        None,
                    ) {
                        break NvFsError::from(e);
                    }
                    // The counter in little-endian representation is taken modulo 2^128.
                    let mut filesystem_update_counter_value =
                        [0u8; image_header::FILESYSTEM_UPDATE_COUNTER_LEN as usize];
                    filesystem_update_counter_value.copy_from_slice(
                        &decrypted_filesystem_update_counter[..image_header::FILESYSTEM_UPDATE_COUNTER_LEN as usize],
                    );
                    drop(decrypted_filesystem_update_counter);
                    drop(all_zeros_iv);
                    drop(filesystem_update_counter_decryption_instance);
                    let filesystem_update_counter_encryption_instance =
                        match symcipher::SymBlockCipherModeEncryptionInstance::new(
                            tpm2_interface::TpmiAlgCipherMode::Cbc,
                            &fs_config.image_layout.block_cipher_alg,
                            &filesystem_update_counter_encryption_key,
                        ) {
                            Ok(filesystem_update_counter_encryption_instance) => {
                                filesystem_update_counter_encryption_instance
                            }
                            Err(e) => break NvFsError::from(e),
                        };
                    drop(filesystem_update_counter_encryption_key);

                    // All done, construct the CocoonFs instance and return it.
                    let fs_config = match this.fs_config.take() {
                        Some(fs_config) => fs_config,
                        None => break nvfs_err_internal!(),
                    };

                    let auth_tree = match this.auth_tree.take() {
                        Some(auth_tree) => auth_tree,
                        None => break nvfs_err_internal!(),
                    };

                    let alloc_bitmap_file = match this.alloc_bitmap_file.take() {
                        Some(alloc_bitmap_file) => alloc_bitmap_file,
                        None => break nvfs_err_internal!(),
                    };

                    let read_buffer = match this.read_buffer.take() {
                        Some(read_buffer) => read_buffer,
                        None => break nvfs_err_internal!(),
                    };

                    let alloc_bitmap = match this.alloc_bitmap.take() {
                        Some(alloc_bitmap) => alloc_bitmap,
                        None => break nvfs_err_internal!(),
                    };

                    let keys_cache = match this.keys_cache.take() {
                        Some(keys_cache) => keys_cache,
                        None => break nvfs_err_internal!(),
                    };

                    let fs_sync_state = CocoonFsSyncState {
                        aux_fs_metadata_update_groups_heads: this.aux_fs_metadata_update_groups_heads,
                        image_size: this.image_size,
                        journal_log_head_integrity_state: this.journal_log_head_integrity_state,
                        alloc_bitmap,
                        alloc_bitmap_file,
                        auth_tree,
                        filesystem_update_counter: CocoonFsSyncStateFilesystemUpdateCounter {
                            encryption_instance: filesystem_update_counter_encryption_instance,
                            value: filesystem_update_counter_value,
                        },
                        read_buffer,
                        inode_index,
                        keys_cache: ST::RwLock::from(keys_cache),
                    };

                    let fs = match <ST::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>::try_new_with(|| {
                        let blkdev = match this.blkdev.take() {
                            Some(blkdev) => blkdev,
                            None => return Err(nvfs_err_internal!()),
                        };
                        Ok((CocoonFs::new(blkdev, fs_config, fs_sync_state), ()))
                    }) {
                        Ok((fs, _)) => fs,
                        Err(sync_types::SyncRcPtrTryNewWithError::TryNewError(e)) => {
                            break match e {
                                sync_types::SyncRcPtrTryNewError::AllocationFailure => {
                                    NvFsError::MemoryAllocationFailure
                                }
                            };
                        }
                        Err(sync_types::SyncRcPtrTryNewWithError::WithError(e)) => {
                            break e;
                        }
                    };

                    // Safety: the fs is new and never moved out from again.
                    let fs_instance = unsafe { pin::Pin::new_unchecked(fs) };

                    // Finally do some maintenance work to be conducted at filesystem opening time,
                    // if any.
                    match this.aux_fs_metadata_extents_reallocation_needed {
                        Some(false) => {
                            // The AuxFsMetadata extents are known to not need a reallocation,
                            // as per the result from a prior ReadFsMetadataFuture. All done.
                            let rng = match this.rng.take() {
                                Some(rng) => rng,
                                None => break nvfs_err_internal!(),
                            };
                            this.fut_state = OpenFsFutureState::Done;
                            return task::Poll::Ready(Ok((rng, Ok(fs_instance))));
                        }
                        Some(true) => {
                            let reallocate_fut = OpenFsReallocateAuxFsMetadataExtentsFuture::Init {
                                aux_fs_metadata_update_groups_heads: this.aux_fs_metadata_update_groups_heads,
                            };
                            this.fut_state = OpenFsFutureState::ReallocateAuxFsMetadataExtents {
                                reallocate_fut,
                                fs_instance,
                            };
                        }
                        None => {
                            // It's not known yet whether the AuxFsMetadata extents need a reallocation
                            // perhaps. Figure it out.
                            let image_layout = &fs_instance.fs_config.image_layout;
                            let determine_state_fut = DetermineAuxFsMetadataExtentsReallocationNeededStateFuture::new(
                                this.aux_fs_metadata_update_groups_heads,
                                image_layout.io_block_allocation_blocks_log2,
                                image_layout.auth_tree_data_block_allocation_blocks_log2,
                                image_layout.allocation_block_size_128b_log2,
                            );
                            this.fut_state = OpenFsFutureState::DetermineAuxFsMetadataReallocationNeededState {
                                determine_state_fut,
                                fs_instance,
                            };
                        }
                    }
                }
                OpenFsFutureState::DetermineAuxFsMetadataReallocationNeededState {
                    determine_state_fut,
                    fs_instance,
                } => {
                    let aux_fs_metadata_extents_reallocation_needed =
                        match blkdev::NvBlkDevFuture::poll(pin::Pin::new(determine_state_fut), &fs_instance.blkdev, cx)
                        {
                            task::Poll::Ready(Ok(aux_fs_metadata_extents_reallocation_needed)) => {
                                aux_fs_metadata_extents_reallocation_needed
                            }
                            task::Poll::Ready(Err(e)) => break e,
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    if !aux_fs_metadata_extents_reallocation_needed {
                        let rng = match this.rng.take() {
                            Some(rng) => rng,
                            None => break nvfs_err_internal!(),
                        };
                        let fs_instance = fs_instance.clone();
                        this.fut_state = OpenFsFutureState::Done;
                        return task::Poll::Ready(Ok((rng, Ok(fs_instance))));
                    } else {
                        let reallocate_fut = OpenFsReallocateAuxFsMetadataExtentsFuture::Init {
                            aux_fs_metadata_update_groups_heads: this.aux_fs_metadata_update_groups_heads,
                        };
                        this.fut_state = OpenFsFutureState::ReallocateAuxFsMetadataExtents {
                            reallocate_fut,
                            fs_instance: fs_instance.clone(),
                        };
                    }
                }
                OpenFsFutureState::ReallocateAuxFsMetadataExtents {
                    reallocate_fut,
                    fs_instance,
                } => {
                    let rng = match this.rng.as_mut() {
                        Some(rng) => rng,
                        None => break nvfs_err_internal!(),
                    };
                    // Deliberately ignore errors. A failure to reallocate the AuxFsMetadata extents
                    // should not prevent the filesystem from getting opened.
                    match fs::NvFsFuture::poll(
                        pin::Pin::new(reallocate_fut),
                        &sync_types::SyncRcPtr::as_ref(fs_instance),
                        rng.as_mut(),
                        cx,
                    ) {
                        task::Poll::Ready(Ok(()) | Err(_)) => (),
                        task::Poll::Pending => return task::Poll::Pending,
                    }

                    let rng = match this.rng.take() {
                        Some(rng) => rng,
                        None => break nvfs_err_internal!(),
                    };
                    let fs_instance = fs_instance.clone();
                    this.fut_state = OpenFsFutureState::Done;
                    return task::Poll::Ready(Ok((rng, Ok(fs_instance))));
                }
                OpenFsFutureState::Done => unreachable!(),
            }
        };

        this.fut_state = OpenFsFutureState::Done;
        let blkdev = match this.blkdev.take() {
            Some(blkdev) => blkdev,
            None => return task::Poll::Ready(Err(e)),
        };
        let rng = match this.rng.take() {
            Some(rng) => rng,
            None => return task::Poll::Ready(Err(e)),
        };
        let raw_root_key = match this.raw_root_key.take() {
            Some(raw_root_key) => raw_root_key,
            None => return task::Poll::Ready(Err(e)),
        };
        task::Poll::Ready(Ok((rng, Err((blkdev, raw_root_key, e)))))
    }
}

impl convert::From<FsMetadata> for OpenFsFutureCoreImageInfo {
    fn from(value: FsMetadata) -> Self {
        match value {
            FsMetadata::Formatted(FsMetadataFormatted {
                header,
                journal_state,
                aux_fs_metadata_extents,
                ..
            }) => Self::Formatted {
                header,
                journal_state: Some(match journal_state {
                    FsMetaDataJournalState::JournalInactive {
                        journal_log_head_integrity_state,
                    } => OpenFsFutureCoreImageInfoJournalState::JournalInactive {
                        journal_log_head_integrity_state,
                    },
                    FsMetaDataJournalState::JournalLogActive => OpenFsFutureCoreImageInfoJournalState::JournalActive {
                        aux_fs_metadata_extents,
                    },
                }),
            },
            FsMetadata::MkFsInfo(mkfsinfo) => Self::MkFsInfo(mkfsinfo),
        }
    }
}

impl convert::From<image_header::ReadCoreImageHeaderFutureResult> for OpenFsFutureCoreImageInfo {
    fn from(value: image_header::ReadCoreImageHeaderFutureResult) -> Self {
        match value {
            image_header::ReadCoreImageHeaderFutureResult::StaticImageHeader(static_image_header) => Self::Formatted {
                header: static_image_header,
                journal_state: None,
            },
            image_header::ReadCoreImageHeaderFutureResult::MkFsInfoHeader(mkfsinfo) => Self::MkFsInfo(mkfsinfo),
        }
    }
}

/// Helper for the [`OpenFsFuture`] implementation for doing the
/// [`AuxFsMetadata`] reallocation work, if needed.
enum OpenFsReallocateAuxFsMetadataExtentsFuture<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev> {
    Init {
        aux_fs_metadata_update_groups_heads: AuxFsMetadataEncodedExtentsPtrsPair,
    },
    ReadAuxFsMetadata {
        read_aux_fs_metadata_fut: aux_fs_metadata::ReadAuxFsMetadataFuture<B>,
    },
    StartTransaction {
        aux_fs_metadata: AuxFsMetadata,
        start_transaction_fut: <CocoonFs<ST, B> as fs::NvFs>::StartTransactionFut,
    },
    WriteAuxFsMetadata {
        write_aux_fs_metadata_fut: super::fs::WriteAuxFsMetadataFuture<ST, B>,
    },
    CommitTransaction {
        commit_transaction_fut: <CocoonFs<ST, B> as fs::NvFs>::CommitTransactionFut,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, B: blkdev::NvBlkDev> fs::NvFsFuture<CocoonFs<ST, B>>
    for OpenFsReallocateAuxFsMetadataExtentsFuture<ST, B>
{
    type Output = Result<(), NvFsError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        fs_instance: &<CocoonFs<ST, B> as fs::NvFs>::SyncRcPtrRef<'_>,
        rng: &mut dyn rng::RngCoreDispatchable,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        loop {
            match this {
                Self::Init {
                    aux_fs_metadata_update_groups_heads,
                } => {
                    let read_aux_fs_metadata_fut = aux_fs_metadata::ReadAuxFsMetadataFuture::new(
                        *aux_fs_metadata_update_groups_heads,
                        &fs_instance.fs_config.image_layout,
                    );
                    *this = Self::ReadAuxFsMetadata {
                        read_aux_fs_metadata_fut,
                    };
                }
                Self::ReadAuxFsMetadata {
                    read_aux_fs_metadata_fut,
                } => {
                    let aux_fs_metadata = match blkdev::NvBlkDevFuture::poll(
                        pin::Pin::new(read_aux_fs_metadata_fut),
                        &fs_instance.blkdev,
                        cx,
                    ) {
                        task::Poll::Ready(Ok((
                            _aux_fs_metadata_extents,
                            _aux_fs_metadata_extents_reallocation_needed,
                            aux_fs_metadata,
                        ))) => aux_fs_metadata,
                        task::Poll::Ready(Err(e)) => {
                            *this = Self::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let start_transaction_fut = <CocoonFs<ST, B> as fs::NvFs>::start_transaction(fs_instance, None);
                    *this = Self::StartTransaction {
                        aux_fs_metadata,
                        start_transaction_fut,
                    };
                }
                Self::StartTransaction {
                    aux_fs_metadata,
                    start_transaction_fut,
                } => {
                    let transaction =
                        match fs::NvFsFuture::poll(pin::Pin::new(start_transaction_fut), fs_instance, rng, cx) {
                            task::Poll::Ready(Ok(transaction)) => transaction,
                            task::Poll::Ready(Err(e)) => {
                                *this = Self::Done;
                                return task::Poll::Ready(Err(e));
                            }
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    // Simply write out the AuxFsMetadata through a transaction. That will
                    // reallocate as a side-effect.
                    let write_aux_fs_metadata_fut =
                        CocoonFs::<ST, B>::write_aux_fs_metadata(fs_instance, transaction, mem::take(aux_fs_metadata));
                    *this = Self::WriteAuxFsMetadata {
                        write_aux_fs_metadata_fut,
                    };
                }
                Self::WriteAuxFsMetadata {
                    write_aux_fs_metadata_fut,
                } => {
                    let transaction =
                        match fs::NvFsFuture::poll(pin::Pin::new(write_aux_fs_metadata_fut), fs_instance, rng, cx) {
                            task::Poll::Ready((_aux_fs_metadata, Ok((transaction, Ok(()))))) => transaction,
                            task::Poll::Ready((_aux_fs_metadata, Ok((_, Err(e))) | Err(e))) => {
                                *this = Self::Done;
                                return task::Poll::Ready(Err(e));
                            }
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    let commit_transaction_fut =
                        <CocoonFs<ST, B> as fs::NvFs>::commit_transaction(fs_instance, transaction, None, None, false);
                    *this = Self::CommitTransaction { commit_transaction_fut }
                }
                Self::CommitTransaction { commit_transaction_fut } => {
                    match fs::NvFsFuture::poll(pin::Pin::new(commit_transaction_fut), fs_instance, rng, cx) {
                        task::Poll::Ready(result) => {
                            *this = Self::Done;
                            return task::Poll::Ready(result.map_err(|e| match e {
                                fs::TransactionCommitError::LogStateClean { reason }
                                | fs::TransactionCommitError::LogStateIndeterminate { reason } => reason,
                            }));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    }
                }
                Self::Done => unreachable!(),
            }
        }
    }
}
