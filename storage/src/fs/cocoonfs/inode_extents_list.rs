// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Functionality related to inode extents lists.

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

use crate::{
    chip,
    crypto::{self, hash, rng, symcipher},
    fs::{
        NvFsError,
        cocoonfs::{
            CocoonFsFormatError,
            alloc_bitmap::{self, ExtentsAllocationRequest, ExtentsReallocationRequest},
            encryption_entities::{
                EncryptedChainedExtentsAssociatedDataAuthSubjectDataSuffix, EncryptedChainedExtentsDecryptionInstance,
                EncryptedChainedExtentsEncryptionInstance, EncryptedChainedExtentsLayout, check_cbc_padding,
            },
            extent_ptr::{self, EncodedExtentPtr},
            extents,
            fs::{CocoonFsAllocateExtentsFuture, CocoonFsSyncStateMemberRef, CocoonFsSyncStateReadFuture},
            inode_index::{InodeIndexKeyType, InodeKeySubdomain, SpecialInode},
            keys, layout, leb128,
            read_authenticate_extent::ReadAuthenticateExtentFuture,
            read_preauth,
            transaction::{
                self, auth_tree_data_blocks_update_states::AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
            },
        },
    },
    nvfs_err_internal, tpm2_interface,
    utils_async::sync_types,
    utils_common::{
        alloc::try_alloc_vec,
        fixed_vec::FixedVec,
        io_slices::{self, IoSlicesIterCommon as _, PeekableIoSlicesIter as _},
    },
};
use core::{default, mem, pin, task};

#[cfg(doc)]
use transaction::Transaction;

/// Determine whether a given inode's extents list, if any, must get inline
/// authenticated.
///
/// Check whether `inode` is among the few special inodes that have their
/// extents lists, if any, inline authenticated for preauthentication CCA
/// protection.
///
/// # Arguments:
///
/// * `inode` - The inode number.
fn extents_list_is_pre_auth_cca_protected(inode: InodeIndexKeyType) -> bool {
    inode == SpecialInode::AuthTree as u32 || inode == SpecialInode::AllocBitmap as u32
}

/// Check whether an inode's extents qualify for a direct [`EncodedExtentPtr`]
/// reference or need an extents list.
///
/// An inode's data extents qualify for a direct [`EncodedExtentPtr`] reference
/// from the inode index entry if there's only one single extent and that
/// extent's length does not exceed the maximum extent length encodable in an
/// [`EncodedExtentPtr`].
///
/// # Arguments:
///
/// * `inode_extents` - The inode's data extent.
pub fn can_encode_direct(inode_extents: &extents::PhysicalExtents) -> bool {
    inode_extents.is_empty()
        || inode_extents.len() == 1
            && inode_extents.get_extent_range(0).block_count()
                <= layout::AllocBlockCount::from(EncodedExtentPtr::MAX_EXTENT_ALLOCATION_BLOCKS)
}

/// Encode a direct [`EncodedExtentPtr`] reference to an inode's (single) data
/// extent.
///
/// # Arguments:
///
/// * `inode_extents` - The inode data extents. Must qualify for a direct
///   [`EncodedExtentPtr`] reference, as determined by [`can_encode_direct()`].
pub fn extent_ptr_encode_direct(inode_extents: &extents::PhysicalExtents) -> Result<EncodedExtentPtr, NvFsError> {
    if !can_encode_direct(inode_extents) {
        return Err(nvfs_err_internal!());
    }
    match inode_extents.iter().next() {
        None => Ok(EncodedExtentPtr::encode_nil()),
        Some(inode_extent) => EncodedExtentPtr::encode(Some(&inode_extent), false),
    }
}

/// Determine the length of an extents list encoding.
///
/// # Arguments:
///
/// * `extents`  - [`Iterator`] over the extents to encode in an extents list.
pub fn indirect_extents_list_encoded_len<EI: Iterator<Item = layout::PhysicalAllocBlockRange>>(
    extents: EI,
) -> Result<usize, NvFsError> {
    let mut encoded_len = 2usize; // Terminating leb128 encoding of (0, 0).

    let mut last_inode_extent_end = 0u64;
    for inode_extent in extents {
        // Note: the cast to i64 is well-defined in Rust's two's complement
        // representation.
        let delta = u64::from(inode_extent.begin()).wrapping_sub(last_inode_extent_end) as i64;
        encoded_len = encoded_len
            .checked_add(
                leb128::leb128s_i64_encoded_len(delta)
                    + leb128::leb128u_u64_encoded_len(u64::from(inode_extent.block_count())),
            )
            .ok_or(NvFsError::DimensionsNotSupported)?;
        last_inode_extent_end = u64::from(inode_extent.end());
    }

    Ok(encoded_len)
}

/// Encode an extents list into a preallocated buffer.
///
/// Encode an extents list of `extents` into `dst`. The unused remainder of
/// `dst` is returned upon success.
///
/// # Arguments:
///
/// * `dst` - The destination buffer. Must have at least the length as
///   determined by [`indirect_extents_list_encoded_len()`].
/// * `extents`  - [`Iterator`] over the extents to encode in an extents list.
pub fn indirect_extents_list_encode_into<EI: Iterator<Item = layout::PhysicalAllocBlockRange>>(
    mut dst: &mut [u8],
    extents: EI,
) -> &mut [u8] {
    let mut last_inode_extent_end = 0u64;
    for inode_extent in extents {
        // Note: the cast to i64 is well-defined in Rust's two's complement
        // representation.
        let delta = u64::from(inode_extent.begin()).wrapping_sub(last_inode_extent_end) as i64;
        dst = leb128::leb128s_i64_encode(dst, delta);
        dst = leb128::leb128u_u64_encode(dst, u64::from(inode_extent.block_count()));
        last_inode_extent_end = u64::from(inode_extent.end());
    }

    // Encode teminating (0, 0).
    debug_assert!(dst.len() >= 2);
    dst[0] = 0;
    dst[1] = 0;

    &mut dst[2..]
}

/// Encode an extents list into a newly allocated buffer.
///
/// # Arguments:
///
/// * `extents`  - [`Iterator`] over the extents to encode in an extents list.
/// * `encoded_len` - The result of [`indirect_extents_list_encoded_len()`]
///   wrapped in a `Some` if available, `None` otherwise.
pub fn indirect_extents_list_encode<EI: Clone + Iterator<Item = layout::PhysicalAllocBlockRange>>(
    extents: EI,
    encoded_len: Option<usize>,
) -> Result<FixedVec<u8, 0>, NvFsError> {
    let encoded_len = match encoded_len {
        Some(encoded_len) => encoded_len,
        None => indirect_extents_list_encoded_len(extents.clone())?,
    };
    let mut encoded = FixedVec::new_with_default(encoded_len)?;
    indirect_extents_list_encode_into(&mut encoded, extents);

    Ok(encoded)
}

/// Decode an extents list.
///
/// # Arguments:
///
/// * `src` - The buffers containing the encoded extents list.
pub fn indirect_extents_list_decode<'a, SI: io_slices::IoSlicesIter<'a, BackendIteratorError = NvFsError>>(
    mut src: SI,
) -> Result<extents::PhysicalExtents, NvFsError> {
    // The maximum image size in units of Bytes fits an u64. The Minimum Allocation
    // Block size is 128 Bytes.  With that, the maximum number of Allocation
    // Blocks is bounded from above (exclusive) by 2^(64 - 7). The exact value
    // doesn't really matter, actutally -- what's being checked here is that any
    // of the computations done on the extents would not ever exceed an u64.
    const MAX_IMAGE_ALLOCATION_BLOCKS_LOG2: u32 = u64::BITS - 7;
    let mut total_inode_extents_allocation_blocks = 0;

    let mut inode_extents = extents::PhysicalExtents::new();

    // One leb128-encoded 64 bit integer, signed or unsigned, is at most 10 bytes
    // long.
    let mut decode_buf: [u8; 20] = [0u8; 20];
    let mut decode_buf_len = 0;
    let mut src_exhausted = false;
    let mut last_inode_extent_end = 0u64;
    loop {
        // Refill the decode_buf.
        while !src_exhausted && decode_buf_len < decode_buf.len() {
            let src_slice = match src.next_slice(Some(decode_buf.len() - decode_buf_len))? {
                Some(src_slice) => src_slice,
                None => {
                    src_exhausted = true;
                    break;
                }
            };
            decode_buf[decode_buf_len..decode_buf_len + src_slice.len()].copy_from_slice(src_slice);
            decode_buf_len += src_slice.len();
        }

        if decode_buf_len < 2 {
            // No terminating (0, 0).
            return Err(NvFsError::from(CocoonFsFormatError::InvalidExtents));
        } else if decode_buf_len == 2 {
            if decode_buf[0] != 0 || decode_buf[1] != 0 {
                // No terminating (0, 0).
                return Err(NvFsError::from(CocoonFsFormatError::InvalidExtents));
            }
            return Ok(inode_extents);
        }

        // Decode one (delta, length) pair.
        let mut remaining_decode_buf = &decode_buf[..decode_buf_len];
        let delta;
        (delta, remaining_decode_buf) = match leb128::leb128s_i64_decode(remaining_decode_buf) {
            Ok((delta, remaining_decode_buf)) => (delta, remaining_decode_buf),
            Err(_) => return Err(NvFsError::from(CocoonFsFormatError::InvalidExtents)),
        };
        let inode_extent_allocation_blocks;
        (inode_extent_allocation_blocks, remaining_decode_buf) = match leb128::leb128u_u64_decode(remaining_decode_buf)
        {
            Ok((extent_allocation_blocks, remaining_decode_buf)) => (extent_allocation_blocks, remaining_decode_buf),
            Err(_) => return Err(NvFsError::from(CocoonFsFormatError::InvalidExtents)),
        };

        // Move the remaining bytes in decode_buf to the front.
        let consumed = decode_buf_len - remaining_decode_buf.len();
        decode_buf_len -= consumed;
        decode_buf.copy_within(consumed..consumed + decode_buf_len, 0);

        // And add the extent. Convert the value encoded as signed leb128 to u64 in
        // two's complement and add with wraparound  -- this way the full
        // possible u64 range can be covered).
        let delta = delta as u64;
        if inode_extent_allocation_blocks == 0 {
            // Invalid (delta, length) pair, possibly a premature termination marker.
            return Err(NvFsError::from(CocoonFsFormatError::InvalidExtents));
        }
        let inode_extent_allocation_blocks_begin = last_inode_extent_end.wrapping_add(delta);
        if (inode_extent_allocation_blocks_begin | inode_extent_allocation_blocks) >> MAX_IMAGE_ALLOCATION_BLOCKS_LOG2
            != 0
        {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidExtents));
        }
        // Neither of the two following sums can overflow, as per all summands being <
        // 2^63 (< 2^(64 - 7 actually)).
        let inode_extent_allocation_blocks_end = inode_extent_allocation_blocks_begin + inode_extent_allocation_blocks;
        total_inode_extents_allocation_blocks += inode_extent_allocation_blocks;
        // Check that the result of both sums is less than the upper limit each.
        if (inode_extent_allocation_blocks_end | total_inode_extents_allocation_blocks)
            >> MAX_IMAGE_ALLOCATION_BLOCKS_LOG2
            != 0
        {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidExtents));
        }
        last_inode_extent_end = inode_extent_allocation_blocks_end;

        inode_extents.push_extent(
            &layout::PhysicalAllocBlockRange::new(
                layout::PhysicalAllocBlockIndex::from(inode_extent_allocation_blocks_begin),
                layout::PhysicalAllocBlockIndex::from(inode_extent_allocation_blocks_end),
            ),
            true,
        )?;
    }
}

/// Read, authenticate, decrypt and decode an inode's encoded extents list.
///
/// The extents list may be either read as previously committed to storage, or
/// in the state as if a given [`Transaction`] had already been applied. In the
/// latter case, the `InodeExtentsListReadFuture` assumes ownership of the
/// [`Transaction`] and eventually returns it back from [`poll()`](Self::poll)
/// upon future completion.
pub struct InodeExtentsListReadFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    inode_extents_list_decryption_instance: EncryptedChainedExtentsDecryptionInstance,
    inode_extents_list_extents: extents::PhysicalExtents,
    decrypted_inode_extents_list_extents: Vec<Vec<u8>>,
    fut_state: InodeExtentsListReadFutureState<ST, C>,
}

/// [`InodeExtentsListReadFuture`] state-machine state.
#[allow(clippy::large_enum_variant)]
enum InodeExtentsListReadFutureState<ST: sync_types::SyncTypes, C: chip::NvChip> {
    ReadExtentsListExtentPrepare {
        transaction: Option<Box<transaction::Transaction>>,
        next_inode_extents_list_extent: layout::PhysicalAllocBlockRange,
    },
    ReadExtentsListExtent {
        cur_inode_extents_list_extent_allocation_blocks: layout::AllocBlockCount,
        read_fut: ReadAuthenticateExtentFuture<ST, C>,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> InodeExtentsListReadFuture<ST, C> {
    /// Instantiate a [`InodeExtentsListReadFuture`].
    ///
    /// # Arguments:
    ///
    /// * `transaction` - Optional [`Transaction`] to read through. If `Some`,
    ///   the state will be read as if `transaction` had been committed.
    ///   Otherwise it will be read as previously committed to storage. Will
    ///   eventually get returned back from [`poll`](Self::poll) upon future
    ///   completion.
    /// * `inode` - The inode's whose associated extents list to read.
    /// * `inode_index_entry_extent_ptr` - The indirect [`EncodedExtentPtr`]
    ///   from the inode's inode index entry referencing the first extent in the
    ///   chain of extents storing the inode's extents list.
    /// * `fs_root_key` - The filesystem's root key.
    /// * `fs_sync_state_keys_cache` - The [filesystem instance's key
    ///   cache](crate::fs::cocoonfs::fs::CocoonFsSyncState::keys_cache).
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    pub fn new(
        mut transaction: Option<Box<transaction::Transaction>>,
        inode: InodeIndexKeyType,
        inode_index_entry_extent_ptr: &EncodedExtentPtr,
        fs_root_key: &keys::RootKey,
        fs_sync_state_keys_cache: &mut keys::KeyCacheRef<'_, ST>,
        image_layout: &layout::ImageLayout,
    ) -> Result<Self, (Option<Box<transaction::Transaction>>, NvFsError)> {
        let extents_list_encryption_key = match keys::KeyCache::get_key(
            fs_sync_state_keys_cache,
            fs_root_key,
            &keys::KeyId::new(
                inode,
                InodeKeySubdomain::InodeExtentsList as u32,
                keys::KeyPurpose::Encryption,
            ),
        ) {
            Ok(extents_list_encryption_key) => extents_list_encryption_key,
            Err(e) => return Err((transaction.take(), e)),
        };

        let extents_list_decryption_block_cipher_instance = match symcipher::SymBlockCipherModeDecryptionInstance::new(
            tpm2_interface::TpmiAlgCipherMode::Cbc,
            &image_layout.block_cipher_alg,
            &extents_list_encryption_key,
        ) {
            Ok(extents_list_encryption_block_cipher_instance) => extents_list_encryption_block_cipher_instance,
            Err(e) => return Err((transaction.take(), NvFsError::CryptoError(e))),
        };
        drop(extents_list_encryption_key);
        let extents_list_inline_authentication_hmac_alg =
            extents_list_is_pre_auth_cca_protected(inode).then_some(image_layout.preauth_cca_protection_hmac_hash_alg);
        let extents_list_encryption_layout = match EncryptedChainedExtentsLayout::new(
            0,
            symcipher::SymBlockCipherAlg::from(&extents_list_decryption_block_cipher_instance),
            extents_list_inline_authentication_hmac_alg,
            0,
            image_layout.allocation_block_size_128b_log2,
        ) {
            Ok(extents_list_encryption_layout) => extents_list_encryption_layout,
            Err(e) => return Err((transaction.take(), e)),
        };
        let inode_extents_list_decryption_instance = match EncryptedChainedExtentsDecryptionInstance::new(
            &extents_list_encryption_layout,
            extents_list_decryption_block_cipher_instance,
            None,
        ) {
            Ok(inode_extents_list_decryption_instance) => inode_extents_list_decryption_instance,
            Err(e) => return Err((transaction.take(), e)),
        };

        let first_inode_extents_list_extent =
            match inode_index_entry_extent_ptr.decode(image_layout.allocation_block_size_128b_log2 as u32) {
                Ok(Some((first_inode_extents_list_extent, indirect))) => {
                    if !indirect {
                        return Err((transaction.take(), nvfs_err_internal!()));
                    }
                    first_inode_extents_list_extent
                }
                Ok(None) => return Err((transaction.take(), nvfs_err_internal!())),
                Err(e) => return Err((transaction.take(), e)),
            };

        Ok(Self {
            inode_extents_list_decryption_instance,
            inode_extents_list_extents: extents::PhysicalExtents::new(),
            decrypted_inode_extents_list_extents: Vec::new(),
            fut_state: InodeExtentsListReadFutureState::ReadExtentsListExtentPrepare {
                transaction: transaction.take(),
                next_inode_extents_list_extent: first_inode_extents_list_extent,
            },
        })
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsSyncStateReadFuture<ST, C>
    for InodeExtentsListReadFuture<ST, C>
{
    /// Output type of [`poll()`](Self::poll).
    ///
    /// In case a [`Transaction`] had been passed to [`Self::new()`], and no
    /// internal error causing it to get lost occured, it will get returned
    /// back as the pair's first component.
    ///
    /// The operation result is returned at the pair's second component,
    /// which, on success, is a pair of the extents storing the inode's extents
    /// list and the decoded extents list.
    type Output = (
        Option<Box<transaction::Transaction>>,
        Result<(extents::PhysicalExtents, extents::PhysicalExtents), NvFsError>,
    );
    type AuxPollData<'a> = ();

    fn poll<'a>(
        self: core::pin::Pin<&mut Self>,
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, C>,
        _aux_data: &mut Self::AuxPollData<'a>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                InodeExtentsListReadFutureState::ReadExtentsListExtentPrepare {
                    transaction,
                    next_inode_extents_list_extent,
                } => {
                    if let Err(e) = this
                        .inode_extents_list_extents
                        .push_extent(next_inode_extents_list_extent, true)
                    {
                        let transaction = transaction.take();
                        this.fut_state = InodeExtentsListReadFutureState::Done;
                        return task::Poll::Ready((transaction, Err(e)));
                    }

                    let read_fut =
                        ReadAuthenticateExtentFuture::new(transaction.take(), next_inode_extents_list_extent);
                    this.fut_state = InodeExtentsListReadFutureState::ReadExtentsListExtent {
                        cur_inode_extents_list_extent_allocation_blocks: next_inode_extents_list_extent.block_count(),
                        read_fut,
                    };
                }
                InodeExtentsListReadFutureState::ReadExtentsListExtent {
                    cur_inode_extents_list_extent_allocation_blocks,
                    read_fut,
                } => {
                    let read_extents_list_extent_result = match CocoonFsSyncStateReadFuture::poll(
                        pin::Pin::new(read_fut),
                        fs_instance_sync_state,
                        &mut (),
                        cx,
                    ) {
                        task::Poll::Ready(Ok(read_result)) => read_result,
                        task::Poll::Ready(Err((transaction, e))) => {
                            this.fut_state = InodeExtentsListReadFutureState::Done;
                            return task::Poll::Ready((transaction, Err(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    // Decrypt the extents list extent just read. First reserve a plaintext
                    // destination buffer.
                    let decrypted_extent_len =
                        match this.inode_extents_list_decryption_instance.max_extent_decrypted_len(
                            *cur_inode_extents_list_extent_allocation_blocks,
                            this.inode_extents_list_extents.len() == 1,
                        ) {
                            Ok(max_decrypted_len) => max_decrypted_len,
                            Err(e) => {
                                this.fut_state = InodeExtentsListReadFutureState::Done;
                                return task::Poll::Ready((read_extents_list_extent_result.into_transaction(), Err(e)));
                            }
                        };

                    let mut decrypted_extent = match try_alloc_vec(decrypted_extent_len) {
                        Ok(decrypted_extent) => decrypted_extent,
                        Err(e) => {
                            return task::Poll::Ready((
                                read_extents_list_extent_result.into_transaction(),
                                Err(NvFsError::from(e)),
                            ));
                        }
                    };

                    let next_chained_inode_extents_list_extent =
                        match this.inode_extents_list_decryption_instance.decrypt_one_extent(
                            io_slices::SingletonIoSliceMut::new(decrypted_extent.as_mut_slice()).map_infallible_err(),
                            io_slices::GenericIoSlicesIter::new(
                                read_extents_list_extent_result.iter_allocation_blocks_bufs(),
                                None,
                            ),
                            io_slices::EmptyIoSlices::default().map_infallible_err(),
                            *cur_inode_extents_list_extent_allocation_blocks,
                        ) {
                            Ok(next_chained_inode_extents_list_extent) => next_chained_inode_extents_list_extent,
                            Err(e) => {
                                this.fut_state = InodeExtentsListReadFutureState::Done;
                                return task::Poll::Ready((read_extents_list_extent_result.into_transaction(), Err(e)));
                            }
                        };
                    let transaction = read_extents_list_extent_result.into_transaction();

                    // Append the decrypted extents list extent to the list of extents decrypted to
                    // this point.
                    if let Err(e) = this.decrypted_inode_extents_list_extents.try_reserve(1) {
                        this.fut_state = InodeExtentsListReadFutureState::Done;
                        return task::Poll::Ready((transaction, Err(NvFsError::from(e))));
                    }
                    this.decrypted_inode_extents_list_extents.push(decrypted_extent);

                    // If there's another extents list extent chained from the current one, continue
                    // with reading + decrpyting that.
                    if let Some(next_chained_inode_extents_list_extent) = next_chained_inode_extents_list_extent {
                        this.fut_state = InodeExtentsListReadFutureState::ReadExtentsListExtentPrepare {
                            transaction,
                            next_inode_extents_list_extent: next_chained_inode_extents_list_extent,
                        };
                        continue;
                    }

                    // All chained extents list extents read and decrypted. Find the terminating CBC
                    // padding, and decode the extents list.
                    this.fut_state = InodeExtentsListReadFutureState::Done;
                    let mut padding_len = match check_cbc_padding(
                        io_slices::BuffersSliceIoSlicesIter::new(&this.decrypted_inode_extents_list_extents)
                            .map_infallible_err(),
                    ) {
                        Ok(padding_len) => padding_len,
                        Err(e) => {
                            return task::Poll::Ready((transaction, Err(e)));
                        }
                    };

                    // Truncate the CBC padding off.
                    while padding_len != 0 {
                        let last_decrypted_extent = match this.decrypted_inode_extents_list_extents.last_mut() {
                            Some(last_decrypted_extent) => last_decrypted_extent,
                            None => return task::Poll::Ready((transaction, Err(nvfs_err_internal!()))),
                        };
                        let last_decrypted_extent_len = last_decrypted_extent.len();
                        if last_decrypted_extent_len > padding_len {
                            last_decrypted_extent.truncate(last_decrypted_extent_len - padding_len);
                            padding_len = 0
                        } else {
                            padding_len -= last_decrypted_extent_len;
                            this.decrypted_inode_extents_list_extents.pop();
                        }
                    }

                    // And finally, decode the extents list.
                    let inode_extents = match indirect_extents_list_decode(
                        io_slices::BuffersSliceIoSlicesIter::new(&this.decrypted_inode_extents_list_extents)
                            .map_infallible_err(),
                    ) {
                        Ok(inode_extents) => inode_extents,
                        Err(e) => return task::Poll::Ready((transaction, Err(e))),
                    };
                    this.decrypted_inode_extents_list_extents = Vec::new(); // Not needed any longer.

                    // Return the result.
                    let inode_extents_list_extents =
                        mem::replace(&mut this.inode_extents_list_extents, extents::PhysicalExtents::new());

                    return task::Poll::Ready((transaction, Ok((inode_extents_list_extents, inode_extents))));
                }
                InodeExtentsListReadFutureState::Done => unreachable!(),
            }
        }
    }
}

/// Read, authenticate, decrypt and decode an inodes' encoded extent list at
/// filesystem opening time before the tree based authentication is available.
///
/// Authentication is done via preauthentication CCA protection tags stored
/// inline to the encrypted chained extents each.
pub struct InodeExtentsListReadPreAuthFuture<C: chip::NvChip> {
    read_extents_list_extents_fut: read_preauth::ReadChainedExtentsPreAuthCcaProtectedFuture<C>,
}

impl<C: chip::NvChip> InodeExtentsListReadPreAuthFuture<C> {
    /// Instantiate a [`InodeExtentsListReadPreAuthFuture`].
    ///
    /// # Arguments:
    ///
    /// * `inode` - The inode's whose associated extents list to read. Must be
    ///   among the special inodes having their extents list inline
    ///   authenticated, c.f. [`extents_list_is_pre_auth_cca_protected()`].
    /// * `inode_index_entry_extent_ptr` - The indirect [`EncodedExtentPtr`]
    ///   from the inode's inode index entry referencing the first extent in the
    ///   chain of extents storing the inode's extents list.
    /// * `root_key` - The filesystem's root key.
    /// * `keys_cache` - A [`KeyCache`](keys::KeyCache) instantiated for the
    ///   filesystem.
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    pub fn new<ST: sync_types::SyncTypes>(
        inode: InodeIndexKeyType,
        inode_index_entry_extent_ptr: &EncodedExtentPtr,
        root_key: &keys::RootKey,
        keys_cache: &mut keys::KeyCacheRef<'_, ST>,
        image_layout: &layout::ImageLayout,
    ) -> Result<Self, NvFsError> {
        if !extents_list_is_pre_auth_cca_protected(inode) {
            return Err(nvfs_err_internal!());
        }

        let first_inode_extents_list_extent =
            match inode_index_entry_extent_ptr.decode(image_layout.allocation_block_size_128b_log2 as u32) {
                Ok(Some((first_inode_extents_list_extent, indirect))) => {
                    if !indirect {
                        return Err(nvfs_err_internal!());
                    }
                    first_inode_extents_list_extent
                }
                Ok(None) => return Err(nvfs_err_internal!()),
                Err(e) => return Err(e),
            };

        // Construct the authenticated associated data for the chained extent's inline
        // authentication.
        let auth_context_subject_id_suffix = [
            0u8, // Version of the authenticated data's format.
            EncryptedChainedExtentsAssociatedDataAuthSubjectDataSuffix::InodeExtentsListPreauthCcaProtection as u8,
        ];
        let inode_id = inode.to_le_bytes();
        let authenticated_associated_data_len = inode_id.len() + auth_context_subject_id_suffix.len();
        let mut authenticated_associated_data = try_alloc_vec(authenticated_associated_data_len)?;
        authenticated_associated_data[..inode_id.len()].copy_from_slice(&inode_id);
        authenticated_associated_data[inode_id.len()..].copy_from_slice(&auth_context_subject_id_suffix);

        let read_extents_list_extents_fut = read_preauth::ReadChainedExtentsPreAuthCcaProtectedFuture::new(
            &first_inode_extents_list_extent,
            0,
            authenticated_associated_data,
            0,
            inode,
            InodeKeySubdomain::InodeExtentsList as u32,
            image_layout,
            root_key,
            keys_cache,
        )?;

        Ok(Self {
            read_extents_list_extents_fut,
        })
    }
}

impl<C: chip::NvChip> chip::NvChipFuture<C> for InodeExtentsListReadPreAuthFuture<C> {
    type Output = Result<extents::PhysicalExtents, NvFsError>;

    fn poll(self: pin::Pin<&mut Self>, chip: &C, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        let decrypted_inode_extents_list_extents =
            match chip::NvChipFuture::poll(pin::Pin::new(&mut this.read_extents_list_extents_fut), chip, cx) {
                task::Poll::Ready(Ok(decrypted_inode_extents_list_extents)) => decrypted_inode_extents_list_extents,
                task::Poll::Ready(Err(e)) => return task::Poll::Ready(Err(e)),
                task::Poll::Pending => return task::Poll::Pending,
            };

        // And finally, decode the extents list.
        let inode_extents = match indirect_extents_list_decode(
            io_slices::BuffersSliceIoSlicesIter::new(&decrypted_inode_extents_list_extents).map_infallible_err(),
        ) {
            Ok(inode_extents) => inode_extents,
            Err(e) => return task::Poll::Ready(Err(e)),
        };

        // This is unauthenticated data. While the indirect_extents_list_decode() does
        // already verify all individual extents are well-formed, it does not
        // check for overlaps.  Do it now.
        if inode_extents.is_empty() {
            return task::Poll::Ready(Ok(inode_extents));
        }
        let mut extents_end_high_watermark = inode_extents.get_extent_range(0).end();
        for (i, cur_extent) in inode_extents.iter().enumerate() {
            if cur_extent.begin() >= extents_end_high_watermark {
                extents_end_high_watermark = cur_extent.end();
                continue;
            }

            for j in 0..i {
                if inode_extents.get_extent_range(j).overlaps_with(&cur_extent) {
                    return task::Poll::Ready(Err(NvFsError::from(CocoonFsFormatError::InvalidExtents)));
                }
            }
        }

        task::Poll::Ready(Ok(inode_extents))
    }
}

/// Stage updates to an inode's extents list at a [`Transaction`] with rollback
/// support.
///
/// Allocate extents for storing the extents list, reallocating preexisting
/// storage in the course if needed, encode, encrypt and stage the updates to an
/// inode's extents list at a [`Transaction`].
///
/// The updates will be staged at the [`Transaction`] so that they can still get
/// [rolled back](InodeExtentsListPendingUpdate::rollback) to the previous
/// state, should it be needed.
///
/// The `InodeExtentsListWriteFuture` assumes ownership of the [`Transaction`]
/// to which to stage the updates to for the duration of the operation and
/// eventually returns it back from [`poll()`](Self::poll) upon future
/// completion. Likewise for the inode's
/// [`PhysicalExtents`](extents::PhysicalExtents) to encode in the extents
/// lists.
pub struct InodeExtentsListWriteFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    inode: InodeIndexKeyType,
    inode_extents: extents::PhysicalExtents,
    fut_state: InodeExtentsListWriteFutureState<ST, C>,
}

/// [`InodeExtentsListWriteFuture`] state-machine state.
#[allow(clippy::large_enum_variant)]
enum InodeExtentsListWriteFutureState<ST: sync_types::SyncTypes, C: chip::NvChip> {
    Init {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<transaction::Transaction>>,
        preexisting_inode_extents_list_extents: Option<extents::PhysicalExtents>,
    },
    PreparePreexistingInodeExtentsListExtentsPrepare {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<transaction::Transaction>>,
        preexisting_inode_extents_list_extents: extents::PhysicalExtents,
        next_preexisting_inode_extents_list_extent_index: usize,
    },
    PreparePreexistingInodeExtentsListExtents {
        prepare_staged_updates_application_fut: transaction::TransactionPrepareStagedUpdatesApplicationFuture<ST, C>,
        preexisting_inode_extents_list_extents: extents::PhysicalExtents,
        cur_preexisting_inode_extents_list_extent_index: usize,
        cur_update_states_allocation_blocks_range: AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    },
    AllocateInodeExtentsListExtentsPrepare {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<transaction::Transaction>>,
        preexisting_inode_extents_list_extents: Option<extents::PhysicalExtents>,
    },
    AllocateInodeExtentsListExtents {
        preexisting_inode_extents_list_extents: Option<extents::PhysicalExtents>,
        encoded_inode_extents_list_len: usize,
        inode_extents_list_encryption_layout: EncryptedChainedExtentsLayout,
        allocate_fut: CocoonFsAllocateExtentsFuture<ST, C>,
    },
    StageInodeExtentsListUpdates {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<transaction::Transaction>>,
        result: InodeExtentsListPendingUpdate,
        encoded_inode_extents_list_len: usize,
        inode_extents_list_encryption_layout: EncryptedChainedExtentsLayout,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> InodeExtentsListWriteFuture<ST, C> {
    /// Instantiate a new [`InodeExtentsListWriteFuture`].
    ///
    /// # Arguments:
    ///
    /// * `transaction` - The [`Transaction`] to stage the updates at. Will get
    ///   returned back from [`poll()`](Self::poll) upon future completion.
    /// * `inode` - The inode whose extents list to update.
    /// * `inode_extents` - The `inode`'s data extents to encode in the extents
    ///   list. Will get returned back from [`poll()`](Self::poll) upon future
    ///   completion.
    /// * `preexisting_inode_extents_list_extents` - Preexisting extents storing
    ///   the inode's former extents list, if any. Will get reallocated and
    ///   reused for the new extents list as appropriate.
    pub fn new(
        transaction: Box<transaction::Transaction>,
        inode: InodeIndexKeyType,
        inode_extents: extents::PhysicalExtents,
        preexisting_inode_extents_list_extents: Option<extents::PhysicalExtents>,
    ) -> Self {
        Self {
            inode,
            inode_extents,
            fut_state: InodeExtentsListWriteFutureState::Init {
                transaction: Some(transaction),
                preexisting_inode_extents_list_extents,
            },
        }
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsSyncStateReadFuture<ST, C>
    for InodeExtentsListWriteFuture<ST, C>
{
    /// Output type of [`poll()`](Self::poll).
    ///
    /// A two-level result is returned upon
    /// [future](CocoonFsSyncStateReadFuture) completion.
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering an internal error and the [`Transaction`] as well as the
    ///   input [`PhysicalExtents`](extents::PhysicalExtents) are lost.
    /// * `Ok((transaction, inode_extents, ...))` - Otherwise the outer level
    ///   [`Result`] is set to [`Ok`] and a tuple of the input [`Transaction`],
    ///   the input [`PhysicalExtents`](extents::PhysicalExtents) and the
    ///   operation result will get returned within:
    ///   * `Ok((transaction, inode_extents,
    ///     Ok(inode_extents_list_pending_update)))` - The operation was
    ///     successful, information about the staged updated is returned in
    ///     [`inode_extents_list_pending_update`](InodeExtentsListPendingUpdate)
    ///     for further processing or rollback.
    ///   * `Ok((transaction, inode_extents, Err(e))` - The operation failed
    ///     with error `e`.
    type Output = Result<
        (
            Box<transaction::Transaction>,
            extents::PhysicalExtents,
            Result<InodeExtentsListPendingUpdate, NvFsError>,
        ),
        NvFsError,
    >;

    type AuxPollData<'a> = &'a mut dyn rng::RngCoreDispatchable;

    fn poll<'a>(
        self: pin::Pin<&mut Self>,
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, C>,
        aux_data: &mut Self::AuxPollData<'a>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        let rng: &mut dyn rng::RngCoreDispatchable = *aux_data;

        let (mut transaction, e) = 'outer: loop {
            match &mut this.fut_state {
                InodeExtentsListWriteFutureState::Init {
                    transaction,
                    preexisting_inode_extents_list_extents,
                } => {
                    if let Some(preexisting_inode_extents_list_extents) = preexisting_inode_extents_list_extents.take()
                    {
                        // Before touching anything from the preexisting inode extents list's
                        // extents, apply updates previously staged for them so that any
                        // modfications done here can get rolled back upon error.
                        this.fut_state =
                            InodeExtentsListWriteFutureState::PreparePreexistingInodeExtentsListExtentsPrepare {
                                transaction: transaction.take(),
                                preexisting_inode_extents_list_extents,
                                next_preexisting_inode_extents_list_extent_index: 0,
                            };
                    } else {
                        // Otherwise jump directly to the extents list's extents allocation.
                        this.fut_state = InodeExtentsListWriteFutureState::AllocateInodeExtentsListExtentsPrepare {
                            transaction: transaction.take(),
                            preexisting_inode_extents_list_extents: None,
                        }
                    }
                }
                InodeExtentsListWriteFutureState::PreparePreexistingInodeExtentsListExtentsPrepare {
                    transaction,
                    preexisting_inode_extents_list_extents,
                    next_preexisting_inode_extents_list_extent_index,
                } => {
                    let transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => break (None, nvfs_err_internal!()),
                    };

                    // Apply any staged updates in the preexisting inode extents list's extents so
                    // that the subsequent modifications can get rolled back on
                    // error.
                    while *next_preexisting_inode_extents_list_extent_index
                        < preexisting_inode_extents_list_extents.len()
                    {
                        let cur_update_states_allocation_blocks_range = match transaction
                            .auth_tree_data_blocks_update_states
                            .lookup_allocation_blocks_update_states_index_range(
                                &preexisting_inode_extents_list_extents
                                    .get_extent_range(*next_preexisting_inode_extents_list_extent_index),
                            ) {
                            Ok(cur_update_states_allocation_blocks_range) => cur_update_states_allocation_blocks_range,
                            Err(_) => {
                                *next_preexisting_inode_extents_list_extent_index += 1;
                                continue;
                            }
                        };

                        let prepare_staged_updates_application_fut =
                            transaction::TransactionPrepareStagedUpdatesApplicationFuture::new(
                                transaction,
                                cur_update_states_allocation_blocks_range.clone(),
                            );

                        this.fut_state = InodeExtentsListWriteFutureState::PreparePreexistingInodeExtentsListExtents {
                            prepare_staged_updates_application_fut,
                            preexisting_inode_extents_list_extents: mem::replace(
                                preexisting_inode_extents_list_extents,
                                extents::PhysicalExtents::new(),
                            ),
                            cur_preexisting_inode_extents_list_extent_index:
                                *next_preexisting_inode_extents_list_extent_index,
                            cur_update_states_allocation_blocks_range,
                        };
                        continue 'outer;
                    }
                    debug_assert_eq!(
                        *next_preexisting_inode_extents_list_extent_index,
                        preexisting_inode_extents_list_extents.len()
                    );
                    // No more updates staged for the preexisting inode extents list's
                    // extents. Jump to the allocation step.
                    this.fut_state = InodeExtentsListWriteFutureState::AllocateInodeExtentsListExtentsPrepare {
                        transaction: Some(transaction),
                        preexisting_inode_extents_list_extents: Some(mem::replace(
                            preexisting_inode_extents_list_extents,
                            extents::PhysicalExtents::new(),
                        )),
                    };
                }
                InodeExtentsListWriteFutureState::PreparePreexistingInodeExtentsListExtents {
                    prepare_staged_updates_application_fut,
                    preexisting_inode_extents_list_extents,
                    cur_preexisting_inode_extents_list_extent_index,
                    cur_update_states_allocation_blocks_range,
                } => {
                    let (mut transaction, cur_update_states_allocation_blocks_range_offsets) =
                        match CocoonFsSyncStateReadFuture::poll(
                            pin::Pin::new(prepare_staged_updates_application_fut),
                            fs_instance_sync_state,
                            &mut (),
                            cx,
                        ) {
                            task::Poll::Ready(Ok((
                                transaction,
                                cur_update_states_allocation_blocks_range_offsets,
                                Ok(()),
                            ))) => (transaction, cur_update_states_allocation_blocks_range_offsets),
                            task::Poll::Ready(Ok((transaction, _, Err(e)))) => {
                                break (Some(transaction), e);
                            }
                            task::Poll::Ready(Err(e)) => break (None, e),
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    if let Some(cur_update_states_allocation_blocks_range_offsets) =
                        cur_update_states_allocation_blocks_range_offsets
                    {
                        *cur_update_states_allocation_blocks_range = cur_update_states_allocation_blocks_range
                            .apply_states_insertions_offsets(
                                cur_update_states_allocation_blocks_range_offsets.inserted_states_before_range_count,
                                cur_update_states_allocation_blocks_range_offsets.inserted_states_within_range_count,
                            );
                    }

                    transaction
                        .auth_tree_data_blocks_update_states
                        .apply_allocation_blocks_staged_updates(
                            Some(cur_update_states_allocation_blocks_range),
                            &fs_instance_sync_state.alloc_bitmap,
                        );

                    this.fut_state =
                        InodeExtentsListWriteFutureState::PreparePreexistingInodeExtentsListExtentsPrepare {
                            transaction: Some(transaction),
                            preexisting_inode_extents_list_extents: mem::replace(
                                preexisting_inode_extents_list_extents,
                                extents::PhysicalExtents::new(),
                            ),
                            next_preexisting_inode_extents_list_extent_index:
                                *cur_preexisting_inode_extents_list_extent_index + 1,
                        };
                }
                InodeExtentsListWriteFutureState::AllocateInodeExtentsListExtentsPrepare {
                    transaction,
                    preexisting_inode_extents_list_extents: fut_preexisting_inode_extents_list_extents,
                } => {
                    let transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => break (None, nvfs_err_internal!()),
                    };

                    if can_encode_direct(&this.inode_extents) {
                        let direct_extent_ptr = match extent_ptr_encode_direct(&this.inode_extents) {
                            Ok(direct_extent_ptr) => direct_extent_ptr,
                            Err(e) => break (Some(transaction), e),
                        };

                        // Don't mark the excess extents as freed until after the index tree had
                        // been updated: allocations made in the course of index tree node
                        // splittings cannot get rolled back, so make sure that excess extents from
                        // here will not get repurposed for index tree node blocks in the tree
                        // update to follow shortly.
                        let inode_extents_list_extents_reallocation =
                            match fut_preexisting_inode_extents_list_extents.take() {
                                Some(preexisting_inode_extents_list_extents) => {
                                    InodeExtentsListExtentsPendingReallocation::Truncation {
                                        excess_preexisting_inode_extents_list_extents:
                                            preexisting_inode_extents_list_extents,
                                        freed: false,
                                    }
                                }
                                None => InodeExtentsListExtentsPendingReallocation::None,
                            };

                        this.fut_state = InodeExtentsListWriteFutureState::Done;
                        return task::Poll::Ready(Ok((
                            transaction,
                            mem::replace(&mut this.inode_extents, extents::PhysicalExtents::new()),
                            Ok(InodeExtentsListPendingUpdate {
                                inode_index_entry_extent_ptr: direct_extent_ptr,
                                new_inode_extents_list_extents: extents::PhysicalExtents::new(),
                                inode_extents_list_extents_reallocation,
                            }),
                        )));
                    }

                    // An indirect extents list is needed. Setup the encryption entity layout for
                    // the inode extents list, as it will be needed for the allocation.
                    let fs_instance = fs_instance_sync_state.get_fs_ref();
                    let image_layout = &fs_instance.fs_config.image_layout;
                    let inode_extents_list_inline_authentication_hmac_alg =
                        extents_list_is_pre_auth_cca_protected(this.inode)
                            .then_some(image_layout.preauth_cca_protection_hmac_hash_alg);
                    let inode_extents_list_encryption_layout = match EncryptedChainedExtentsLayout::new(
                        0,
                        image_layout.block_cipher_alg,
                        inode_extents_list_inline_authentication_hmac_alg,
                        0,
                        image_layout.allocation_block_size_128b_log2,
                    ) {
                        Ok(extents_list_encryption_layout) => extents_list_encryption_layout,
                        Err(e) => break (Some(transaction), e),
                    };

                    let encoded_inode_extents_list_len =
                        match indirect_extents_list_encoded_len(this.inode_extents.iter()) {
                            Ok(encoded_inode_extents_list_len) => encoded_inode_extents_list_len,
                            Err(e) => break (Some(transaction), e),
                        };
                    // Add one for the CBC padding.
                    let encoded_inode_extents_list_alloc_len = match encoded_inode_extents_list_len.checked_add(1) {
                        Some(encoded_inode_extents_list_alloc_len) => encoded_inode_extents_list_alloc_len,
                        None => break (Some(transaction), NvFsError::DimensionsNotSupported),
                    };

                    let inode_extents_list_extents_allocation_layout =
                        match inode_extents_list_encryption_layout.get_extents_layout() {
                            Ok(inode_extents_list_extents_allocation_layout) => {
                                inode_extents_list_extents_allocation_layout
                            }
                            Err(e) => break (Some(transaction), e),
                        };
                    let inode_extents_list_extents_allocation_request = match fut_preexisting_inode_extents_list_extents
                        .take()
                    {
                        Some(preexisting_inode_extents_list_extents) => {
                            match ExtentsAllocationRequest::new_reallocate(
                                &preexisting_inode_extents_list_extents,
                                encoded_inode_extents_list_alloc_len as u64,
                                &inode_extents_list_extents_allocation_layout,
                            ) {
                                Ok(ExtentsReallocationRequest::Keep) => {
                                    // The new inode extents lists fits exactly into preexisting
                                    // extents list's extents. Jump directly to the update.
                                    let inode_index_entry_extent_ptr = match EncodedExtentPtr::encode(
                                        Some(&preexisting_inode_extents_list_extents.get_extent_range(0)),
                                        true,
                                    ) {
                                        Ok(inode_index_entry_extent_ptr) => inode_index_entry_extent_ptr,
                                        Err(e) => break (Some(transaction), e),
                                    };
                                    this.fut_state = InodeExtentsListWriteFutureState::StageInodeExtentsListUpdates {
                                        transaction: Some(transaction),
                                        result: InodeExtentsListPendingUpdate {
                                            inode_index_entry_extent_ptr,
                                            new_inode_extents_list_extents: preexisting_inode_extents_list_extents,
                                            inode_extents_list_extents_reallocation:
                                                InodeExtentsListExtentsPendingReallocation::None,
                                        },
                                        encoded_inode_extents_list_len,
                                        inode_extents_list_encryption_layout,
                                    };
                                    continue;
                                }
                                Ok(ExtentsReallocationRequest::Shrink {
                                    last_retained_extent_index,
                                    last_retained_extent_allocation_blocks,
                                }) => {
                                    // The new inode extents lists fits into less space than what's
                                    // provided by the preexisting extents list's extents. Split off
                                    // excess, free it and jump directly to the update.
                                    let (
                                        retained_inode_extents_list_extents,
                                        excess_preexisting_inode_extents_list_extents,
                                    ) = match preexisting_inode_extents_list_extents
                                        .split(last_retained_extent_index, last_retained_extent_allocation_blocks)
                                    {
                                        Ok((head_extents, tail_extents)) => (head_extents, tail_extents),
                                        Err(e) => break (Some(transaction), e),
                                    };
                                    // Don't mark the excess extents as freed until after the index tree had
                                    // been updated: allocations made in the course of index tree node
                                    // splittings cannot get rolled back, so make sure that excess extents from
                                    // here will not get repurposed for index tree node blocks in the tree
                                    // update to follow shortly.
                                    let inode_extents_list_extents_reallocation =
                                        InodeExtentsListExtentsPendingReallocation::Truncation {
                                            excess_preexisting_inode_extents_list_extents,
                                            freed: false,
                                        };

                                    let inode_index_entry_extent_ptr = match EncodedExtentPtr::encode(
                                        Some(&retained_inode_extents_list_extents.get_extent_range(0)),
                                        true,
                                    ) {
                                        Ok(inode_index_entry_extent_ptr) => inode_index_entry_extent_ptr,
                                        Err(e) => break (Some(transaction), e),
                                    };

                                    this.fut_state = InodeExtentsListWriteFutureState::StageInodeExtentsListUpdates {
                                        transaction: Some(transaction),
                                        result: InodeExtentsListPendingUpdate {
                                            inode_index_entry_extent_ptr,
                                            new_inode_extents_list_extents: retained_inode_extents_list_extents,
                                            inode_extents_list_extents_reallocation,
                                        },
                                        encoded_inode_extents_list_len,
                                        inode_extents_list_encryption_layout,
                                    };
                                    continue;
                                }
                                Ok(ExtentsReallocationRequest::Grow { request }) => {
                                    *fut_preexisting_inode_extents_list_extents =
                                        Some(preexisting_inode_extents_list_extents);
                                    request
                                }
                                Err(e) => break (Some(transaction), e),
                            }
                        }
                        None => ExtentsAllocationRequest::new(
                            encoded_inode_extents_list_alloc_len as u64,
                            &inode_extents_list_extents_allocation_layout,
                        ),
                    };

                    let allocate_fut = match CocoonFsAllocateExtentsFuture::new(
                        &fs_instance_sync_state.get_fs_ref(),
                        transaction,
                        inode_extents_list_extents_allocation_request,
                        false,
                    ) {
                        Ok(allocate_fut) => allocate_fut,
                        Err((transaction, e)) => break (transaction, e),
                    };
                    this.fut_state = InodeExtentsListWriteFutureState::AllocateInodeExtentsListExtents {
                        preexisting_inode_extents_list_extents: fut_preexisting_inode_extents_list_extents.take(),
                        encoded_inode_extents_list_len,
                        inode_extents_list_encryption_layout,
                        allocate_fut,
                    };
                }
                InodeExtentsListWriteFutureState::AllocateInodeExtentsListExtents {
                    preexisting_inode_extents_list_extents,
                    encoded_inode_extents_list_len,
                    inode_extents_list_encryption_layout,
                    allocate_fut,
                } => {
                    let (transaction, allocated_extents) = match CocoonFsSyncStateReadFuture::poll(
                        pin::Pin::new(allocate_fut),
                        fs_instance_sync_state,
                        &mut (),
                        cx,
                    ) {
                        task::Poll::Ready(Ok((transaction, Ok(allocated_extents)))) => {
                            (transaction, allocated_extents.0)
                        }
                        task::Poll::Ready(Ok((transaction, Err(e)))) => break (Some(transaction), e),
                        task::Poll::Ready(Err(e)) => break (None, e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let new_inode_extents_list_extents = match preexisting_inode_extents_list_extents.take() {
                        Some(mut preexisting_inode_extents_list_extents) => {
                            if let Err(e) =
                                preexisting_inode_extents_list_extents.append_extents(&allocated_extents, true)
                            {
                                break match transaction.rollback_extents_allocation(
                                    allocated_extents.iter(),
                                    &fs_instance_sync_state.alloc_bitmap,
                                ) {
                                    Ok(transaction) => (Some(transaction), e),
                                    Err(e) => (None, e),
                                };
                            }
                            preexisting_inode_extents_list_extents
                        }
                        None => match allocated_extents.try_clone() {
                            Ok(new_inode_extents_list_extents) => new_inode_extents_list_extents,
                            Err(e) => {
                                break match transaction.rollback_extents_allocation(
                                    allocated_extents.iter(),
                                    &fs_instance_sync_state.alloc_bitmap,
                                ) {
                                    Ok(transaction) => (Some(transaction), e),
                                    Err(e) => (None, e),
                                };
                            }
                        },
                    };

                    let inode_extents_list_extents_reallocation =
                        InodeExtentsListExtentsPendingReallocation::Extension {
                            allocated_inode_extents_list_extents: allocated_extents,
                        };

                    let inode_index_entry_extent_ptr =
                        match EncodedExtentPtr::encode(Some(&new_inode_extents_list_extents.get_extent_range(0)), true)
                        {
                            Ok(inode_index_entry_extent_ptr) => inode_index_entry_extent_ptr,
                            Err(e) => break (Some(transaction), e),
                        };

                    this.fut_state = InodeExtentsListWriteFutureState::StageInodeExtentsListUpdates {
                        transaction: Some(transaction),
                        result: InodeExtentsListPendingUpdate {
                            inode_index_entry_extent_ptr,
                            new_inode_extents_list_extents,
                            inode_extents_list_extents_reallocation,
                        },
                        encoded_inode_extents_list_len: *encoded_inode_extents_list_len,
                        inode_extents_list_encryption_layout: inode_extents_list_encryption_layout.clone(),
                    };
                }
                InodeExtentsListWriteFutureState::StageInodeExtentsListUpdates {
                    transaction,
                    result,
                    encoded_inode_extents_list_len,
                    inode_extents_list_encryption_layout,
                } => {
                    let rollback = |transaction: Box<transaction::Transaction>,
                                    result: &mut InodeExtentsListPendingUpdate,
                                    alloc_bitmap: &alloc_bitmap::AllocBitmap| {
                        mem::take(result).rollback(transaction, alloc_bitmap)
                    };

                    let mut transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => break (None, nvfs_err_internal!()),
                    };

                    // Encode the inode extents list into a buffer.
                    let encoded_inode_extents_list = match indirect_extents_list_encode(
                        this.inode_extents.iter(),
                        Some(*encoded_inode_extents_list_len),
                    ) {
                        Ok(encoded_inode_extents_list) => encoded_inode_extents_list,
                        Err(e) => {
                            break match rollback(transaction, result, &fs_instance_sync_state.alloc_bitmap) {
                                Ok(transaction) => (Some(transaction), e),
                                Err(e) => (None, e),
                            };
                        }
                    };
                    let mut encoded_inode_extents_list =
                        io_slices::SingletonIoSlice::new(encoded_inode_extents_list.as_slice()).map_infallible_err();

                    // Prepare an encryption instance for the extents list.
                    let (
                        fs_instance,
                        _fs_sync_state_image_size,
                        fs_sync_state_alloc_bitmap,
                        _fs_sync_state_alloc_bitmap_file,
                        _fs_sync_state_auth_tree,
                        _fs_sync_state_inode_index,
                        _fs_sync_state_read_buffer,
                        mut fs_sync_state_keys_cache,
                    ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();
                    let fs_root_key = &fs_instance.fs_config.root_key;
                    let image_layout = &fs_instance.fs_config.image_layout;
                    let extents_list_encryption_key = match keys::KeyCache::get_key(
                        &mut fs_sync_state_keys_cache,
                        fs_root_key,
                        &keys::KeyId::new(
                            this.inode,
                            InodeKeySubdomain::InodeExtentsList as u32,
                            keys::KeyPurpose::Encryption,
                        ),
                    ) {
                        Ok(extents_list_encryption_key) => extents_list_encryption_key,
                        Err(e) => {
                            break match rollback(transaction, result, fs_sync_state_alloc_bitmap) {
                                Ok(transaction) => (Some(transaction), e),
                                Err(e) => (None, e),
                            };
                        }
                    };
                    let extents_list_encryption_block_cipher_instance =
                        match symcipher::SymBlockCipherModeEncryptionInstance::new(
                            tpm2_interface::TpmiAlgCipherMode::Cbc,
                            &image_layout.block_cipher_alg,
                            &extents_list_encryption_key,
                        ) {
                            Ok(extents_list_encryption_block_cipher_instance) => {
                                extents_list_encryption_block_cipher_instance
                            }
                            Err(e) => {
                                break match rollback(transaction, result, fs_sync_state_alloc_bitmap) {
                                    Ok(transaction) => (Some(transaction), NvFsError::from(e)),
                                    Err(e) => (None, e),
                                };
                            }
                        };
                    drop(extents_list_encryption_key);

                    let extents_list_inline_authentication_hmac_instance =
                        if extents_list_is_pre_auth_cca_protected(this.inode) {
                            let extents_list_inline_authentication_key = match keys::KeyCache::get_key(
                                &mut fs_sync_state_keys_cache,
                                fs_root_key,
                                &keys::KeyId::new(
                                    this.inode,
                                    InodeKeySubdomain::InodeExtentsList as u32,
                                    keys::KeyPurpose::PreAuthCcaProtectionAuthentication,
                                ),
                            ) {
                                Ok(extents_list_inline_authentication_key) => extents_list_inline_authentication_key,
                                Err(e) => {
                                    break match rollback(transaction, result, fs_sync_state_alloc_bitmap) {
                                        Ok(transaction) => (Some(transaction), e),
                                        Err(e) => (None, e),
                                    };
                                }
                            };
                            let extents_list_inline_authentication_hmac_instance = match hash::HmacInstance::new(
                                image_layout.preauth_cca_protection_hmac_hash_alg,
                                &extents_list_inline_authentication_key,
                            ) {
                                Ok(extents_list_inline_authentication_hmac_instance) => {
                                    extents_list_inline_authentication_hmac_instance
                                }
                                Err(e) => {
                                    break match rollback(transaction, result, fs_sync_state_alloc_bitmap) {
                                        Ok(transaction) => (Some(transaction), NvFsError::from(e)),
                                        Err(e) => (None, e),
                                    };
                                }
                            };
                            Some(extents_list_inline_authentication_hmac_instance)
                        } else {
                            None
                        };

                    // Construct the authenticated associated data. Ignored if no inline
                    // authentication is being done.
                    let auth_context_subject_id_suffix = [
                        0u8, // Version of the authenticated data's format.
                        EncryptedChainedExtentsAssociatedDataAuthSubjectDataSuffix::InodeExtentsListPreauthCcaProtection
                            as u8,
                    ];
                    let inode_id = this.inode.to_le_bytes();
                    let authenticated_associated_data =
                        [inode_id.as_slice(), auth_context_subject_id_suffix.as_slice()];
                    let authenticated_associated_data =
                        io_slices::BuffersSliceIoSlicesIter::new(&authenticated_associated_data).map_infallible_err();

                    let mut inode_extents_list_encryption_instance =
                        match EncryptedChainedExtentsEncryptionInstance::new(
                            inode_extents_list_encryption_layout,
                            extents_list_encryption_block_cipher_instance,
                            extents_list_inline_authentication_hmac_instance,
                        ) {
                            Ok(inode_extents_list_encryption_instance) => inode_extents_list_encryption_instance,
                            Err(e) => {
                                break match rollback(transaction, result, fs_sync_state_alloc_bitmap) {
                                    Ok(transaction) => (Some(transaction), e),
                                    Err(e) => (None, e),
                                };
                            }
                        };

                    // Walk through the inode extent list's extents one by one, prepare the
                    // destination staged update states and encrypt into them as we go.
                    for inode_extents_list_extents_index in 0..result.new_inode_extents_list_extents.len() {
                        let cur_inode_extents_list_extent = result
                            .new_inode_extents_list_extents
                            .get_extent_range(inode_extents_list_extents_index);
                        let cur_update_states_allocation_blocks_range =
                            match transaction.auth_tree_data_blocks_update_states.insert_missing_in_range(
                                cur_inode_extents_list_extent,
                                fs_sync_state_alloc_bitmap,
                                &transaction.allocs.pending_frees,
                                None,
                            ) {
                                Ok((cur_update_states_allocation_blocks_range, _)) => {
                                    cur_update_states_allocation_blocks_range
                                }
                                Err((e, _)) => {
                                    break 'outer match rollback(transaction, result, fs_sync_state_alloc_bitmap) {
                                        Ok(transaction) => (Some(transaction), e),
                                        Err(e) => (None, e),
                                    };
                                }
                            };
                        if let Err(e) = transaction
                            .auth_tree_data_blocks_update_states
                            .allocate_allocation_blocks_update_staging_bufs(
                                &cur_update_states_allocation_blocks_range,
                                image_layout.allocation_block_size_128b_log2 as u32,
                            )
                        {
                            break 'outer match rollback(transaction, result, fs_sync_state_alloc_bitmap) {
                                Ok(transaction) => (Some(transaction), e),
                                Err(e) => (None, e),
                            };
                        }
                        let cur_update_states_allocation_blocks_update_staging_bufs_iter = match transaction
                            .auth_tree_data_blocks_update_states
                            .iter_allocation_blocks_update_staging_bufs_mut(&cur_update_states_allocation_blocks_range)
                        {
                            Ok(cur_update_states_allocation_blocks_update_staging_bufs_iter) => {
                                cur_update_states_allocation_blocks_update_staging_bufs_iter
                            }
                            Err(e) => {
                                break 'outer match rollback(transaction, result, fs_sync_state_alloc_bitmap) {
                                    Ok(transaction) => (Some(transaction), e),
                                    Err(e) => (None, e),
                                };
                            }
                        };

                        let next_chained_inode_extents_list_extent =
                            if inode_extents_list_extents_index + 1 != result.new_inode_extents_list_extents.len() {
                                Some(
                                    result
                                        .new_inode_extents_list_extents
                                        .get_extent_range(inode_extents_list_extents_index + 1),
                                )
                            } else {
                                None
                            };
                        if let Err(e) = inode_extents_list_encryption_instance.encrypt_one_extent(
                            cur_update_states_allocation_blocks_update_staging_bufs_iter,
                            &mut encoded_inode_extents_list,
                            authenticated_associated_data.decoupled_borrow(),
                            cur_inode_extents_list_extent.block_count(),
                            next_chained_inode_extents_list_extent.as_ref(),
                            rng,
                        ) {
                            break 'outer match rollback(transaction, result, fs_sync_state_alloc_bitmap) {
                                Ok(transaction) => (Some(transaction), e),
                                Err(e) => (None, e),
                            };
                        }
                    }

                    // All of the encoded_inode_extents_list should have been encrypted now.
                    if let Err(e) = encoded_inode_extents_list
                        .is_empty()
                        .map_err(NvFsError::from)
                        .and_then(|is_empty| if is_empty { Ok(()) } else { Err(nvfs_err_internal!()) })
                    {
                        break match rollback(transaction, result, fs_sync_state_alloc_bitmap) {
                            Ok(transaction) => (Some(transaction), e),
                            Err(e) => (None, e),
                        };
                    }

                    // All done.
                    let result = mem::take(result);
                    this.fut_state = InodeExtentsListWriteFutureState::Done;
                    return task::Poll::Ready(Ok((
                        transaction,
                        mem::replace(&mut this.inode_extents, extents::PhysicalExtents::new()),
                        Ok(result),
                    )));
                }
                InodeExtentsListWriteFutureState::Done => unreachable!(),
            }
        };

        this.fut_state = InodeExtentsListWriteFutureState::Done;
        task::Poll::Ready(match transaction.take() {
            Some(transaction) => Ok((
                transaction,
                mem::replace(&mut this.inode_extents, extents::PhysicalExtents::new()),
                Err(e),
            )),
            None => Err(e),
        })
    }
}

/// Encode and encrypt an inode's extents list.
///
/// The encoded `inode_extents` list will get encrypted in the
/// ["encrypted chained extents"](EncryptedChainedExtentsLayout) format, with
/// the extents forming the chain given by `inode_extents_list_extents`. The
/// respective resulting encrypted chained extents' data is written back to back
/// into the `dst` [buffers iterator](crypto::CryptoMutPeekableIoSlicesMutIter).
///
/// # Arguments:
///
/// * `dst` - The destination buffers. Their total size must match the total
///   size of the `inode_extents_list_extents` exactly.
/// * `inode` - The inode whose extents list to encode and encrypt.
/// * `inode_extents` - The extents to encode into the extents list.
/// * `inode_extents_list_extents` - The extents to store the encoded extents
///   list as encrypted with the ["encrypted chained
///   extents"](EncryptedChainedExtentsLayout) format into. Their collectively
///   provided total [effective
///   payload](EncryptedChainedExtentsLayout::effective_payload_len) must match
///   that of [`indirect_extents_list_encoded_len()`] (plus one byte for the
///   PKCS#7 padding) and there must not be any excess extents.
/// * `image_layout` - The filesystem's [`ImageLayout`](layout::ImageLayout).
/// * `root_key` - The filesystem's root key.
/// * `keys_cache` - A [`KeyCache`](keys::KeyCache) instantiated for the
///   filesystem.
/// * `rng` - The [random number generator](rng::RngCoreDispatchable) used for
///   generating the IV and filling padding, if any.
#[allow(clippy::too_many_arguments)]
pub fn inode_extents_list_encrypt_into<
    'a,
    ST: sync_types::SyncTypes,
    DI: crypto::CryptoMutPeekableIoSlicesMutIter<'a>,
    EI: Iterator<Item = layout::PhysicalAllocBlockRange> + Clone,
    ELEI: Iterator<Item = layout::PhysicalAllocBlockRange>,
>(
    mut dst: DI,
    inode: InodeIndexKeyType,
    inode_extents: EI,
    mut inode_extents_list_extents: ELEI,
    image_layout: &layout::ImageLayout,
    root_key: &keys::RootKey,
    keys_cache: &mut keys::KeyCacheRef<'_, ST>,
    rng: &mut dyn rng::RngCoreDispatchable,
) -> Result<(), NvFsError> {
    let encoded_inode_extents_list = indirect_extents_list_encode(inode_extents, None)?;
    let mut encoded_inode_extents_list =
        io_slices::SingletonIoSlice::new(&encoded_inode_extents_list).map_infallible_err();

    let extents_list_encryption_key = keys::KeyCache::get_key(
        keys_cache,
        root_key,
        &keys::KeyId::new(
            inode,
            InodeKeySubdomain::InodeExtentsList as u32,
            keys::KeyPurpose::Encryption,
        ),
    )?;
    let extents_list_encryption_block_cipher_instance = symcipher::SymBlockCipherModeEncryptionInstance::new(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        &image_layout.block_cipher_alg,
        &extents_list_encryption_key,
    )?;
    drop(extents_list_encryption_key);

    let extents_list_inline_authentication_hmac_instance = if extents_list_is_pre_auth_cca_protected(inode) {
        let extents_list_inline_authentication_key = keys::KeyCache::get_key(
            keys_cache,
            root_key,
            &keys::KeyId::new(
                inode,
                InodeKeySubdomain::InodeExtentsList as u32,
                keys::KeyPurpose::PreAuthCcaProtectionAuthentication,
            ),
        )?;
        Some(hash::HmacInstance::new(
            image_layout.preauth_cca_protection_hmac_hash_alg,
            &extents_list_inline_authentication_key,
        )?)
    } else {
        None
    };
    let inode_extents_list_encryption_layout = EncryptedChainedExtentsLayout::new(
        0,
        image_layout.block_cipher_alg,
        extents_list_inline_authentication_hmac_instance
            .as_ref()
            .map(tpm2_interface::TpmiAlgHash::from),
        0,
        image_layout.allocation_block_size_128b_log2,
    )?;

    let mut inode_extents_list_encryption_instance = EncryptedChainedExtentsEncryptionInstance::new(
        &inode_extents_list_encryption_layout,
        extents_list_encryption_block_cipher_instance,
        extents_list_inline_authentication_hmac_instance,
    )?;

    // Construct the authenticated associated data. Ignored if no inline
    // authentication is being done.
    let auth_context_subject_id_suffix = [
        0u8, // Version of the authenticated data's format.
        EncryptedChainedExtentsAssociatedDataAuthSubjectDataSuffix::InodeExtentsListPreauthCcaProtection as u8,
    ];
    let inode_id = inode.to_le_bytes();
    let authenticated_associated_data = [inode_id.as_slice(), auth_context_subject_id_suffix.as_slice()];
    let authenticated_associated_data =
        io_slices::BuffersSliceIoSlicesIter::new(&authenticated_associated_data).map_infallible_err();

    // Walk through the inode extent list's extents one by one and encrypt them back
    // to back to dst.
    let mut cur_inode_extents_list_extent = match inode_extents_list_extents.next() {
        Some(first_extents_list_extent) => first_extents_list_extent,
        None => return Err(nvfs_err_internal!()),
    };
    let mut next_chained_inode_extents_list_extent = inode_extents_list_extents.next();
    loop {
        let cur_inode_extents_list_extent_len = usize::try_from(
            u64::from(cur_inode_extents_list_extent.block_count())
                << (image_layout.allocation_block_size_128b_log2 as u32 + 7),
        )
        .map_err(|_| NvFsError::DimensionsNotSupported)?;
        inode_extents_list_encryption_instance.encrypt_one_extent(
            dst.as_ref()
                .take_exact(cur_inode_extents_list_extent_len)
                .map_err(|e| match e {
                    io_slices::IoSlicesIterError::BackendIteratorError(e) => e,
                    io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                        io_slices::IoSlicesError::BuffersExhausted => crypto::CryptoError::Internal,
                    },
                }),
            &mut encoded_inode_extents_list,
            authenticated_associated_data.decoupled_borrow(),
            cur_inode_extents_list_extent.block_count(),
            next_chained_inode_extents_list_extent.as_ref(),
            rng,
        )?;

        cur_inode_extents_list_extent = match next_chained_inode_extents_list_extent.take() {
            Some(cur_inode_extents_list_extent) => {
                next_chained_inode_extents_list_extent = inode_extents_list_extents.next();
                cur_inode_extents_list_extent
            }
            None => break,
        };
    }

    // All of the encoded_inode_extents_list should have been encrypted now.
    encoded_inode_extents_list
        .is_empty()
        .map_err(NvFsError::from)
        .and_then(|is_empty| if is_empty { Ok(()) } else { Err(nvfs_err_internal!()) })?;
    // And all of the destination buffers should have been filled.
    dst.is_empty().map_err(NvFsError::from).and_then(
        |is_empty| {
            if is_empty { Ok(()) } else { Err(nvfs_err_internal!()) }
        },
    )
}

/// Info about updates to an inode's extents list needed to update the inode
/// index or roll back.
///
/// Always associated with some inode extents list update staged via
/// [`InodeExtentsListWriteFuture`] at a [`Transaction`].
pub struct InodeExtentsListPendingUpdate {
    inode_index_entry_extent_ptr: extent_ptr::EncodedExtentPtr,
    new_inode_extents_list_extents: extents::PhysicalExtents,
    inode_extents_list_extents_reallocation: InodeExtentsListExtentsPendingReallocation,
}

impl InodeExtentsListPendingUpdate {
    /// Get the (indirect) [`EncodedExtentPtr`] referencing the inode extents
    /// list extents chain's first extent.
    ///
    /// Return an [`EncodedExtentPtr`] suitable for storage in the inode's inode
    /// index entry.
    pub fn get_inode_index_entry_extent_ptr(&self) -> extent_ptr::EncodedExtentPtr {
        self.inode_index_entry_extent_ptr
    }

    /// Deallocate any preexisting excess extents list extents.
    ///
    /// The deallocation can get rolled back via
    /// [`rollback_excess_preexisting_inode_extents_list_extents_free()`](Self::rollback_excess_preexisting_inode_extents_list_extents_free)
    /// unless the [`Transaction::allocs`]'s rollback state had been
    /// [reset](transaction::TransactionAllocations::reset_rollback) in the
    /// meanwhile.
    ///
    /// # Arguments:
    ///
    /// * `transaction_allocs` - Reference to the associated [`Transaction`]'s
    ///   [`Transaction::allocs`] member.
    /// * `transaction_updates_states` - Reference to the associated
    ///   [`Transaction`]'s [`Transaction::auth_tree_data_blocks_update_states`]
    ///   member.
    pub fn free_excess_preexisting_inode_extents_list_extents(
        &mut self,
        transaction_allocs: &mut transaction::TransactionAllocations,
        transaction_updates_states: &mut transaction::AuthTreeDataBlocksUpdateStates,
    ) -> Result<(), NvFsError> {
        self.inode_extents_list_extents_reallocation
            .free_excess_preexisting_inode_extents_list_extents(transaction_allocs, transaction_updates_states)
    }

    /// Rollback a prior
    /// [`free_excess_preexisting_inode_extents_list_extents()`](Self::free_excess_preexisting_inode_extents_list_extents)
    /// operation.
    ///
    /// May only get called if the [`Transaction::allocs`]'s rollback state had
    /// not been
    /// [reset](transaction::TransactionAllocations::reset_rollback) in the
    /// meanwhile.
    ///
    /// # Arguments:
    ///
    /// * `transaction` - The [`Transaction`] associated with `self`. Returned
    ///   back on success.
    /// * `alloc_bitmap` - The [filesystem instance's allocation
    ///   bitmap](crate::fs::cocoonfs::fs::CocoonFsSyncState::alloc_bitmap)
    pub fn rollback_excess_preexisting_inode_extents_list_extents_free(
        &mut self,
        transaction: Box<transaction::Transaction>,
        alloc_bitmap: &alloc_bitmap::AllocBitmap,
    ) -> Result<Box<transaction::Transaction>, NvFsError> {
        self.inode_extents_list_extents_reallocation
            .rollback_excess_preexisting_inode_extents_list_extents_free(transaction, alloc_bitmap)
    }

    /// Roll the staged inode extents list update back.
    ///
    /// Unstage the update to the inode's extents list staged at `transaction`
    /// again, i.e. revert the extents list to its previous state.
    ///
    /// May only get called if the [`Transaction::allocs`]'s rollback state had
    /// not been
    /// [reset](transaction::TransactionAllocations::reset_rollback) in the
    /// meanwhile and no further updates to the inode's extents list have
    /// been made.
    ///
    /// # Arguments:
    ///
    /// * `transaction` - The [`Transaction`] associated with `self`. Returned
    ///   back on success.
    /// * `alloc_bitmap` - The [filesystem instance's allocation
    ///   bitmap](crate::fs::cocoonfs::fs::CocoonFsSyncState::alloc_bitmap)
    pub fn rollback(
        self,
        mut transaction: Box<transaction::Transaction>,
        alloc_bitmap: &alloc_bitmap::AllocBitmap,
    ) -> Result<Box<transaction::Transaction>, NvFsError> {
        // Reset any updates staged so far. Note that before an inode extents list's
        // extents update commences, all previously pending ones had been
        // applied, so the Allocation Block's contents are affectively getting
        // reverted to the former ones by the reset.
        transaction
            .auth_tree_data_blocks_update_states
            .reset_staged_extents_updates(self.new_inode_extents_list_extents.iter());
        // And restore the original inode extents list's extents allocations.
        self.inode_extents_list_extents_reallocation
            .rollback(transaction, alloc_bitmap)
    }
}

impl default::Default for InodeExtentsListPendingUpdate {
    fn default() -> Self {
        Self {
            inode_index_entry_extent_ptr: EncodedExtentPtr::encode_nil(),
            new_inode_extents_list_extents: extents::PhysicalExtents::new(),
            inode_extents_list_extents_reallocation: InodeExtentsListExtentsPendingReallocation::None,
        }
    }
}

/// Reallocation info about the (chained) extents storing an inode's extent
/// list.
enum InodeExtentsListExtentsPendingReallocation {
    /// The preexisting inode extents list extents could be used as-is and had
    /// not been reallocated.
    None,
    /// The preexisting inode extents list extents need to get truncated.
    Truncation {
        /// The excess extents to free up.
        excess_preexisting_inode_extents_list_extents: extents::PhysicalExtents,
        /// Whether or not the excess extents have been
        /// [deallocated](transaction::Transaction::free_extents) at the
        /// associated [`Transaction`] already.
        freed: bool,
    },
    /// There had been no preexisting inode extents list extents or they
    /// have been extended in a reallocation.
    Extension {
        /// The newly allocated extents.
        allocated_inode_extents_list_extents: extents::PhysicalExtents,
    },
}

impl InodeExtentsListExtentsPendingReallocation {
    /// Deallocate any preexisting excess extents list extents.
    ///
    /// The deallocation can get rolled back via
    /// [`rollback_excess_preexisting_inode_extents_list_extents_free()`](Self::rollback_excess_preexisting_inode_extents_list_extents_free)
    /// unless the [`Transaction::allocs`]'s rollback state had been
    /// [reset](transaction::TransactionAllocations::reset_rollback) in the
    /// meanwhile.
    ///
    /// # Arguments:
    ///
    /// * `transaction_allocs` - Reference to the associated [`Transaction`]'s
    ///   [`Transaction::allocs`](transaction::Transaction::allocs) member.
    /// * `transaction_updates_states` - Reference to the associated
    ///   [`Transaction`]'s [`Transaction::auth_tree_data_blocks_update_states`]
    ///   member.
    fn free_excess_preexisting_inode_extents_list_extents(
        &mut self,
        transaction_allocs: &mut transaction::TransactionAllocations,
        transaction_updates_states: &mut transaction::AuthTreeDataBlocksUpdateStates,
    ) -> Result<(), NvFsError> {
        if let Self::Truncation {
            excess_preexisting_inode_extents_list_extents,
            freed,
        } = self
        {
            if !*freed {
                match transaction::Transaction::free_extents(
                    transaction_allocs,
                    transaction_updates_states,
                    excess_preexisting_inode_extents_list_extents.iter(),
                ) {
                    Ok(()) => *freed = true,
                    Err(e) => return Err(e),
                };
            };
        }
        Ok(())
    }

    /// Rollback a prior
    /// [`free_excess_preexisting_inode_extents_list_extents()`](Self::free_excess_preexisting_inode_extents_list_extents)
    /// operation.
    ///
    /// May only get called if the [`Transaction::allocs`]'s rollback state had
    /// not been
    /// [reset](transaction::TransactionAllocations::reset_rollback) in the
    /// meanwhile.
    ///
    /// # Arguments:
    ///
    /// * `transaction` - The [`Transaction`] associated with `self`. Returned
    ///   back on success.
    /// * `alloc_bitmap` - The [filesystem instance's allocation
    ///   bitmap](crate::fs::cocoonfs::fs::CocoonFsSyncState::alloc_bitmap)
    fn rollback_excess_preexisting_inode_extents_list_extents_free(
        &mut self,
        transaction: Box<transaction::Transaction>,
        alloc_bitmap: &alloc_bitmap::AllocBitmap,
    ) -> Result<Box<transaction::Transaction>, NvFsError> {
        if let Self::Truncation {
            excess_preexisting_inode_extents_list_extents,
            freed,
        } = self
        {
            if *freed {
                *freed = false;
                return transaction.rollback_extents_free(
                    excess_preexisting_inode_extents_list_extents.iter(),
                    alloc_bitmap,
                    false,
                );
            }
        }
        Ok(transaction)
    }

    /// Roll the reallocation back.
    ///
    /// May only get called if the [`Transaction::allocs`]'s rollback state had
    /// not been
    /// [reset](transaction::TransactionAllocations::reset_rollback) in the
    /// meanwhile.
    ///
    /// # Arguments:
    ///
    /// * `transaction` - The [`Transaction`] associated with `self`. Returned
    ///   back on success.
    /// * `alloc_bitmap` - The [filesystem instance's allocation
    ///   bitmap](crate::fs::cocoonfs::fs::CocoonFsSyncState::alloc_bitmap)
    fn rollback(
        self,
        transaction: Box<transaction::Transaction>,
        alloc_bitmap: &alloc_bitmap::AllocBitmap,
    ) -> Result<Box<transaction::Transaction>, NvFsError> {
        match self {
            Self::None => Ok(transaction),
            Self::Truncation {
                excess_preexisting_inode_extents_list_extents,
                freed,
            } => {
                if freed {
                    transaction.rollback_extents_free(
                        excess_preexisting_inode_extents_list_extents.iter(),
                        alloc_bitmap,
                        false,
                    )
                } else {
                    Ok(transaction)
                }
            }
            Self::Extension {
                allocated_inode_extents_list_extents,
            } => transaction.rollback_extents_allocation(allocated_inode_extents_list_extents.iter(), alloc_bitmap),
        }
    }
}

impl default::Default for InodeExtentsListExtentsPendingReallocation {
    fn default() -> Self {
        Self::None
    }
}
