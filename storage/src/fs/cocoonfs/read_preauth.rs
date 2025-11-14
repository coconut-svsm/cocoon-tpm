// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`ReadExtentUnauthenticatedFuture`] and
//! [`ReadChainedExtentsPreAuthCcaProtectedFuture`].

extern crate alloc;
use alloc::vec::Vec;

use crate::{
    blkdev::{self, ChunkedIoRegion, ChunkedIoRegionChunkRange, ChunkedIoRegionError},
    crypto::{hash, symcipher},
    fs::{
        NvFsError, NvFsIoError,
        cocoonfs::{CocoonFsFormatError, encryption_entities, keys, layout},
    },
    nvfs_err_internal, tpm2_interface,
    utils_async::sync_types,
    utils_common::{
        alloc::try_alloc_zeroizing_vec,
        fixed_vec::FixedVec,
        io_slices::{self, IoSlicesIterCommon as _},
        zeroize,
    },
};
use core::{mem, pin, task};

#[cfg(doc)]
use crate::blkdev::NvBlkDevFuture as _;

/// Read an extent from storage without authentication.
pub struct ReadExtentUnauthenticatedFuture<B: blkdev::NvBlkDev> {
    fut_state: ReadExtentUnauthenticatedFutureState<B>,
}

/// [`ReadExtentUnauthenticatedFuture`] state-machine state.
enum ReadExtentUnauthenticatedFutureState<B: blkdev::NvBlkDev> {
    Init {
        extent_range: layout::PhysicalAllocBlockRange,
        allocation_block_size_128b_log2: u8,
    },
    Read {
        read_fut: B::ReadFuture<ReadExtentUnauthenticatedNvBlkDevReadRequest>,
    },
    Done,
}

impl<B: blkdev::NvBlkDev> ReadExtentUnauthenticatedFuture<B> {
    /// Instantiate a [`ReadExtentUnauthenticatedFuture`].
    ///
    /// # Arguments:
    ///
    /// * `extent_range` - The extent to read.
    /// * `allocation_block_size_128b_log2` - Verbatim value of
    ///   [`ImageLayout::allocation_block_size_128b_log2`](layout::ImageLayout::allocation_block_size_128b_log2).
    pub fn new(extent_range: &layout::PhysicalAllocBlockRange, allocation_block_size_128b_log2: u8) -> Self {
        Self {
            fut_state: ReadExtentUnauthenticatedFutureState::Init {
                extent_range: *extent_range,
                allocation_block_size_128b_log2,
            },
        }
    }
}

impl<B: blkdev::NvBlkDev> blkdev::NvBlkDevFuture<B> for ReadExtentUnauthenticatedFuture<B> {
    /// Output type of [`poll()`](Self::poll).
    ///
    /// On success, the extent's data read from storage is returned.
    type Output = Result<FixedVec<u8, 7>, NvFsError>;

    fn poll(self: pin::Pin<&mut Self>, blkdev: &B, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                ReadExtentUnauthenticatedFutureState::Init {
                    extent_range,
                    allocation_block_size_128b_log2,
                } => {
                    let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();
                    let read_req = match ReadExtentUnauthenticatedNvBlkDevReadRequest::new(
                        extent_range,
                        blkdev_io_block_size_128b_log2,
                        *allocation_block_size_128b_log2,
                    ) {
                        Ok(read_req) => read_req,
                        Err(e) => {
                            this.fut_state = ReadExtentUnauthenticatedFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    let read_fut = match blkdev.read(read_req) {
                        Ok(Ok(read_fut)) => read_fut,
                        Ok(Err((_, e))) | Err(e) => {
                            this.fut_state = ReadExtentUnauthenticatedFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    this.fut_state = ReadExtentUnauthenticatedFutureState::Read { read_fut };
                }
                ReadExtentUnauthenticatedFutureState::Read { read_fut } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(read_fut), blkdev, cx) {
                        task::Poll::Ready(Ok((read_req, Ok(())))) => {
                            this.fut_state = ReadExtentUnauthenticatedFutureState::Done;
                            let ReadExtentUnauthenticatedNvBlkDevReadRequest { dst_buf, .. } = read_req;
                            return task::Poll::Ready(Ok(dst_buf));
                        }
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                            this.fut_state = ReadExtentUnauthenticatedFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    }
                }
                ReadExtentUnauthenticatedFutureState::Done => unreachable!(),
            }
        }
    }
}

/// [`NvBlkDevReadRequest`](blkdev::NvBlkDevReadRequest) implementation used
/// internally by [`ReadExtentUnauthenticatedFuture`].
struct ReadExtentUnauthenticatedNvBlkDevReadRequest {
    dst_buf: FixedVec<u8, 7>,
    extent_range: layout::PhysicalAllocBlockRange,
    read_request_io_region: ChunkedIoRegion,
    blkdev_io_block_size_128b_log2: u32,
    allocation_block_size_128b_log2: u8,
}

impl ReadExtentUnauthenticatedNvBlkDevReadRequest {
    fn new(
        extent_range: &layout::PhysicalAllocBlockRange,
        blkdev_io_block_size_128b_log2: u32,
        allocation_block_size_128b_log2: u8,
    ) -> Result<Self, NvFsError> {
        // The extent's end in units of Bytes shall not exceed the maximum allowed image
        // size, which is u64::MAX.
        if u64::from(extent_range.end()) << (allocation_block_size_128b_log2 as u32 + 7)
            >> (allocation_block_size_128b_log2 as u32 + 7)
            != u64::from(extent_range.end())
        {
            return Err(NvFsError::IoError(NvFsIoError::RegionOutOfRange));
        }

        let extent_allocation_blocks = extent_range.block_count();
        let extent_size =
            usize::try_from(u64::from(extent_allocation_blocks) << (allocation_block_size_128b_log2 as u32 + 7))
                .map_err(|_| NvFsError::DimensionsNotSupported)?;
        let dst_buf = FixedVec::new_with_default(extent_size)?;

        let blkdev_io_block_allocation_blocks_log2 =
            blkdev_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2 as u32);
        let aligned_extent_range = extent_range
            .align(blkdev_io_block_allocation_blocks_log2)
            .ok_or(NvFsError::IoError(NvFsIoError::RegionOutOfRange))?;

        let read_request_io_region = ChunkedIoRegion::new(
            u64::from(aligned_extent_range.begin()) << (allocation_block_size_128b_log2 as u32),
            u64::from(aligned_extent_range.end()) << (allocation_block_size_128b_log2 as u32),
            allocation_block_size_128b_log2 as u32,
        )
        .map_err(|e| match e {
            ChunkedIoRegionError::ChunkSizeOverflow => NvFsError::from(CocoonFsFormatError::InvalidImageLayoutConfig),
            ChunkedIoRegionError::ChunkIndexOverflow => NvFsError::DimensionsNotSupported,
            ChunkedIoRegionError::InvalidBounds | ChunkedIoRegionError::RegionUnaligned => nvfs_err_internal!(),
        })?;

        Ok(Self {
            dst_buf,
            extent_range: *extent_range,
            read_request_io_region,
            blkdev_io_block_size_128b_log2,
            allocation_block_size_128b_log2,
        })
    }
}

impl blkdev::NvBlkDevReadRequest for ReadExtentUnauthenticatedNvBlkDevReadRequest {
    fn region(&self) -> &ChunkedIoRegion {
        &self.read_request_io_region
    }

    fn get_destination_buffer(
        &mut self,
        range: &ChunkedIoRegionChunkRange,
    ) -> Result<Option<&mut [u8]>, blkdev::NvBlkDevIoError> {
        // The index is relative to the aligned region.
        let (allocation_block_index, _) = range.chunk().decompose_to_hierarchic_indices([]);

        let allocation_block_size_128b_log2 = self.allocation_block_size_128b_log2 as u32;
        let blkdev_io_block_allocation_blocks_log2 = self
            .blkdev_io_block_size_128b_log2
            .saturating_sub(allocation_block_size_128b_log2);

        // It is known as per the successful instantiation of the read_request_io_region
        // that the total number of Allocation Blocks in the Device IO Block
        // aligned range fits an usize.
        let head_padding_allocation_blocks = u64::from(
            self.extent_range.begin()
                - self
                    .extent_range
                    .begin()
                    .align_down(blkdev_io_block_allocation_blocks_log2),
        ) as usize;
        if allocation_block_index < head_padding_allocation_blocks {
            return Ok(None);
        }
        let allocation_block_index = allocation_block_index - head_padding_allocation_blocks;
        // Likewise here: the number of Allocation Blocks fits an usize.
        if allocation_block_index >= u64::from(self.extent_range.block_count()) as usize {
            // Is in tail alignment padding.
            return Ok(None);
        }

        Ok(Some(
            &mut self.dst_buf[allocation_block_index << (allocation_block_size_128b_log2 + 7)
                ..(allocation_block_index + 1) << (allocation_block_size_128b_log2 + 7)]
                [range.range_in_chunk().clone()],
        ))
    }
}

/// Read some filesystem entity stored in "chained encrypted extents" and
/// authenticate by means of the inline preauthentication CCA protection digests
/// stored inline to it.
///
/// Used early at filesystem opening time when the authentication tree based
/// authentication is not yet available.
pub struct ReadChainedExtentsPreAuthCcaProtectedFuture<B: blkdev::NvBlkDev> {
    decrypted_extents: Vec<zeroize::Zeroizing<Vec<u8>>>,
    authenticated_associated_data: Vec<u8>,
    chained_extents_decryption_instance: encryption_entities::EncryptedChainedExtentsDecryptionInstance,
    allocation_block_size_128b_log2: u8,
    fut_state: ReadChainedExtentsPreauthCcaProtectedFutureState<B>,
}

/// [`ReadChainedExtentsPreAuthCcaProtectedFuture`] state-machine state.
enum ReadChainedExtentsPreauthCcaProtectedFutureState<B: blkdev::NvBlkDev> {
    ReadNextExtentPrepare {
        next_extent: layout::PhysicalAllocBlockRange,
    },
    ReadNextExtent {
        extent_allocation_blocks: layout::AllocBlockCount,
        read_fut: ReadExtentUnauthenticatedFuture<B>,
    },
    Done,
}

impl<B: blkdev::NvBlkDev> ReadChainedExtentsPreAuthCcaProtectedFuture<B> {
    /// Instantiate a [`ReadChainedExtentsPreAuthCcaProtectedFuture`].
    ///
    /// # Arguments:
    ///
    /// * `first_extent` - The head extent of the chain.
    /// * `plain_data_extents_hdr_len` - Length of the plain header stored in
    ///   `first_extent`, c.f.
    ///   [`EncryptedChainedExtentsLayout::new()`](encryption_entities::EncryptedChainedExtentsLayout::new).
    /// * `authenticated_associated_data` - Associated data authenticated with
    ///   the "encrypted chained extents"' inline preauthentication CCA
    ///   protection digests.
    /// * `extent_alignment_allocation_blocks_log2` - Base-2 logarithm of the
    ///   alignment of any extent in the chain in units of [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2), c.f.
    ///   [`EncryptedChainedExtentsLayout::new()`](encryption_entities::EncryptedChainedExtentsLayout::new).
    /// * `key_domain` - The key derivation domain associated with the
    ///   filesystem entity stored in the "chained encrypted extents", c.f.
    ///   [`KeyId::new()`](keys::KeyId::new).
    /// * `key_subdomain` - The key derivation subdomain associated with the
    ///   filesystem entity stored in the "chained encrypted extents", c.f.
    ///   [`KeyId::new()`](keys::KeyId::new).
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `root_key` - The filesystem's root key.
    /// * `keys_cache` - A [`KeyCache`](keys::KeyCache) instantiated for the
    ///   filesystem.
    #[allow(clippy::too_many_arguments)]
    pub fn new<ST: sync_types::SyncTypes>(
        first_extent: &layout::PhysicalAllocBlockRange,
        plain_data_extents_hdr_len: usize,
        authenticated_associated_data: Vec<u8>,
        extent_alignment_allocation_blocks_log2: u8,
        key_domain: u32,
        key_subdomain: u32,
        image_layout: &layout::ImageLayout,
        root_key: &keys::RootKey,
        keys_cache: &mut keys::KeyCacheRef<'_, ST>,
    ) -> Result<Self, NvFsError> {
        let chained_extents_encryption_key = keys::KeyCache::get_key(
            keys_cache,
            root_key,
            &keys::KeyId::new(key_domain, key_subdomain, keys::KeyPurpose::Encryption),
        )?;
        let chained_extents_decryption_block_cipher_instance = symcipher::SymBlockCipherModeDecryptionInstance::new(
            tpm2_interface::TpmiAlgCipherMode::Cbc,
            &image_layout.block_cipher_alg,
            &chained_extents_encryption_key,
        )
        .map_err(NvFsError::from)?;
        drop(chained_extents_encryption_key);

        let chained_extents_inline_authentication_key = keys::KeyCache::get_key(
            keys_cache,
            root_key,
            &keys::KeyId::new(
                key_domain,
                key_subdomain,
                keys::KeyPurpose::PreAuthCcaProtectionAuthentication,
            ),
        )?;
        let chained_extents_inline_authentication_hmac_instance = hash::HmacInstance::new(
            image_layout.preauth_cca_protection_hmac_hash_alg,
            &chained_extents_inline_authentication_key,
        )?;
        drop(chained_extents_inline_authentication_key);

        let chained_extents_encryption_layout = encryption_entities::EncryptedChainedExtentsLayout::new(
            plain_data_extents_hdr_len,
            image_layout.block_cipher_alg,
            Some(image_layout.preauth_cca_protection_hmac_hash_alg),
            extent_alignment_allocation_blocks_log2,
            image_layout.allocation_block_size_128b_log2,
        )?;
        let chained_extents_decryption_instance = encryption_entities::EncryptedChainedExtentsDecryptionInstance::new(
            &chained_extents_encryption_layout,
            chained_extents_decryption_block_cipher_instance,
            Some(chained_extents_inline_authentication_hmac_instance),
        )?;

        Ok(Self {
            decrypted_extents: Vec::new(),
            authenticated_associated_data,
            chained_extents_decryption_instance,
            allocation_block_size_128b_log2: image_layout.allocation_block_size_128b_log2,
            fut_state: ReadChainedExtentsPreauthCcaProtectedFutureState::ReadNextExtentPrepare {
                next_extent: *first_extent,
            },
        })
    }
}

impl<B: blkdev::NvBlkDev> blkdev::NvBlkDevFuture<B> for ReadChainedExtentsPreAuthCcaProtectedFuture<B> {
    /// Output type of [`poll()`](Self::poll).
    ///
    /// On success, the entity's decrypted payload data, distributed over
    /// one or more buffers, possibly of different sizes each, is being
    /// returned.
    type Output = Result<Vec<zeroize::Zeroizing<Vec<u8>>>, NvFsError>;
    fn poll(self: pin::Pin<&mut Self>, blkdev: &B, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                ReadChainedExtentsPreauthCcaProtectedFutureState::ReadNextExtentPrepare { next_extent } => {
                    let read_fut =
                        ReadExtentUnauthenticatedFuture::new(next_extent, this.allocation_block_size_128b_log2);
                    this.fut_state = ReadChainedExtentsPreauthCcaProtectedFutureState::ReadNextExtent {
                        extent_allocation_blocks: next_extent.block_count(),
                        read_fut,
                    };
                }
                ReadChainedExtentsPreauthCcaProtectedFutureState::ReadNextExtent {
                    extent_allocation_blocks,
                    read_fut,
                } => {
                    let encrypted_extent = match blkdev::NvBlkDevFuture::poll(pin::Pin::new(read_fut), blkdev, cx) {
                        task::Poll::Ready(Ok(encrypted_extent)) => encrypted_extent,
                        task::Poll::Ready(Err(e)) => {
                            this.fut_state = ReadChainedExtentsPreauthCcaProtectedFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    // Decrypt the extent just read. First reserve a plaintext destination buffer.
                    let decrypted_extent_len = match this
                        .chained_extents_decryption_instance
                        .max_extent_decrypted_len(*extent_allocation_blocks, this.decrypted_extents.is_empty())
                    {
                        Ok(max_decrypted_len) => max_decrypted_len,
                        Err(e) => {
                            this.fut_state = ReadChainedExtentsPreauthCcaProtectedFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };

                    let mut decrypted_extent = match try_alloc_zeroizing_vec(decrypted_extent_len) {
                        Ok(decrypted_extent) => decrypted_extent,
                        Err(e) => {
                            this.fut_state = ReadChainedExtentsPreauthCcaProtectedFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };

                    let next_extent = match this.chained_extents_decryption_instance.decrypt_one_extent(
                        io_slices::SingletonIoSliceMut::new(&mut decrypted_extent).map_infallible_err(),
                        io_slices::SingletonIoSlice::new(&encrypted_extent).map_infallible_err(),
                        io_slices::SingletonIoSlice::new(&this.authenticated_associated_data).map_infallible_err(),
                        *extent_allocation_blocks,
                    ) {
                        Ok(next_extent) => next_extent,
                        Err(e) => {
                            this.fut_state = ReadChainedExtentsPreauthCcaProtectedFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    drop(encrypted_extent);

                    if let Err(e) = this.decrypted_extents.try_reserve(1) {
                        this.fut_state = ReadChainedExtentsPreauthCcaProtectedFutureState::Done;
                        return task::Poll::Ready(Err(NvFsError::from(e)));
                    };
                    this.decrypted_extents.push(decrypted_extent);

                    if let Some(next_extent) = next_extent {
                        this.fut_state =
                            ReadChainedExtentsPreauthCcaProtectedFutureState::ReadNextExtentPrepare { next_extent };
                        continue;
                    }

                    // All chained extents list extents read and decrypted. Find the terminating CBC
                    // padding.
                    this.fut_state = ReadChainedExtentsPreauthCcaProtectedFutureState::Done;
                    let mut padding_len = match encryption_entities::check_cbc_padding(
                        io_slices::BuffersSliceIoSlicesIter::new(&this.decrypted_extents).map_infallible_err(),
                    ) {
                        Ok(padding_len) => padding_len,
                        Err(e) => {
                            return task::Poll::Ready(Err(e));
                        }
                    };

                    // Truncate the CBC padding off.
                    while padding_len != 0 {
                        let last_decrypted_extent = match this.decrypted_extents.last_mut() {
                            Some(last_decrypted_extent) => last_decrypted_extent,
                            None => return task::Poll::Ready(Err(nvfs_err_internal!())),
                        };
                        let last_decrypted_extent_len = last_decrypted_extent.len();
                        if last_decrypted_extent_len > padding_len {
                            last_decrypted_extent.truncate(last_decrypted_extent_len - padding_len);
                            padding_len = 0
                        } else {
                            padding_len -= last_decrypted_extent_len;
                            this.decrypted_extents.pop();
                        }
                    }

                    return task::Poll::Ready(Ok(mem::take(&mut this.decrypted_extents)));
                }
                ReadChainedExtentsPreauthCcaProtectedFutureState::Done => unreachable!(),
            }
        }
    }
}
