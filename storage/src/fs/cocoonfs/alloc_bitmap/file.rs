// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`AllocBitmapFile`] and related functionality.

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

use super::{
    AllocBitmap, SparseAllocBitmap,
    bitmap_word::{BITMAP_WORD_BITS_LOG2, BitmapWord},
};
use crate::{
    chip::{self, ChunkedIoRegion, ChunkedIoRegionChunkRange, ChunkedIoRegionError},
    crypto::{rng, symcipher},
    fs::{
        NvFsError, NvFsIoError,
        cocoonfs::{
            CocoonFsFormatError, auth_tree, encryption_entities, extents, inode_index,
            journal::{self, extents_covering_auth_digests::ExtentsCoveringAuthDigests},
            keys,
            layout::{self, BlockIndex as _},
            read_buffer, transaction, write_blocks,
        },
    },
    nvfs_err_internal, tpm2_interface,
    utils_async::sync_types,
    utils_common::{
        alloc::try_alloc_vec,
        bitmanip::{BitManip as _, UBitManip as _},
        fixed_vec::FixedVec,
        io_slices::{self, IoSlicesIterCommon as _},
    },
};
use core::{cmp, convert, mem, pin, task};

#[cfg(doc)]
use transaction::Transaction;

/// Information about the allocation bitmap file on storage.
pub struct AllocBitmapFile {
    /// Number of bitmap words stored in a single [Allocation Bitmap File
    /// Block](layout::ImageLayout::allocation_bitmap_file_block_allocation_blocks_log2).
    bitmap_words_per_file_block: u64,

    /// Multiplier for dividing by
    /// [`bitmap_words_per_file_block`](Self::bitmap_words_per_file_block) by a
    /// multiply + shift operation.
    bitmap_words_per_file_block_inv_mul: u64,
    /// Shift distance for dividing by
    /// [`bitmap_words_per_file_block`](Self::bitmap_words_per_file_block) by a
    /// multiply + shift operation.
    bitmap_words_per_file_block_inv_shift: u32,

    /// The allocation bitmap file's extents on storage.
    extents: extents::LogicalExtents,

    /// Total number of [Allocation Bitmap File
    /// Blocks](layout::ImageLayout::allocation_bitmap_file_block_allocation_blocks_log2) stored in
    /// the file.
    total_file_blocks: u64,
}

impl AllocBitmapFile {
    /// Base-2 logarithm of the maximum possible allocation bitmap word count.
    const MAX_BITMAP_WORDS_INDEX_LOG2: u32 = u64::BITS - BITMAP_WORD_BITS_LOG2 - 7;

    /// Instantiate an [`AllocBitmapFile`].
    ///
    /// # Arguments:
    ///
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `extents` - The allocation bitmap file's storage location.
    pub fn new(image_layout: &layout::ImageLayout, extents: extents::PhysicalExtents) -> Result<Self, NvFsError> {
        let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2;
        let file_block_allocation_blocks_log2 = image_layout.allocation_bitmap_file_block_allocation_blocks_log2;
        let auth_tree_data_block_allocation_blocks_log2 = image_layout.auth_tree_data_block_allocation_blocks_log2;

        let file_block_size_log2 =
            file_block_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32 + 7;
        if file_block_size_log2 >= u64::BITS {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidAllocationBitmapFileConfig));
        } else if file_block_size_log2 >= usize::BITS {
            return Err(NvFsError::DimensionsNotSupported);
        }

        let file_block_encryption_layout = encryption_entities::EncryptedBlockLayout::new(
            image_layout.block_cipher_alg,
            file_block_allocation_blocks_log2,
            allocation_block_size_128b_log2,
        )?;
        let file_block_payload_len: usize = file_block_encryption_layout.effective_payload_len()?;
        let bitmap_words_per_file_block: usize = file_block_payload_len / mem::size_of::<BitmapWord>();
        let bitmap_words_per_file_block = match u64::try_from(bitmap_words_per_file_block) {
            Ok(bitmap_words_per_file_file_block) => bitmap_words_per_file_file_block,
            Err(_) => return Err(NvFsError::DimensionsNotSupported),
        };
        let (bitmap_words_per_file_block_inv_mul, bitmap_words_per_file_block_inv_shift) =
            Self::compute_bitmap_words_per_file_block_inv(bitmap_words_per_file_block)?;

        // Verify that all extents' lengths are aligned to the file block size, that the
        // extents's boundaries are aligned to the Authentication Tree Data
        // Block size, as is needed for bootstrapping, and count the total
        // number of such blocks.
        let mut total_file_blocks = 0u64;
        for extent in extents.iter() {
            if !(u64::from(extent.block_count())).is_aligned_pow2(file_block_allocation_blocks_log2 as u32)
                || !(u64::from(extent.begin()) | u64::from(extent.end()))
                    .is_aligned_pow2(auth_tree_data_block_allocation_blocks_log2 as u32)
            {
                return Err(NvFsError::from(
                    CocoonFsFormatError::UnalignedAllocationBitmapFileExtents,
                ));
            }

            total_file_blocks = match total_file_blocks
                .checked_add(u64::from(extent.block_count()) >> file_block_allocation_blocks_log2)
            {
                Some(total_file_blocks) => total_file_blocks,
                None => return Err(NvFsError::from(CocoonFsFormatError::InvalidAllocationBitmapFileSize)),
            };
        }

        // Check that the total number of file blocks does not exceed the maximum
        // possible number.
        let max_total_file_blocks = Self::_bitmap_word_index_to_file_block_index(
            (1u64 << Self::MAX_BITMAP_WORDS_INDEX_LOG2) - 1,
            bitmap_words_per_file_block_inv_mul,
            bitmap_words_per_file_block_inv_shift,
        )? + 1;
        debug_assert_eq!(
            ((1u64 << Self::MAX_BITMAP_WORDS_INDEX_LOG2) - 1) / bitmap_words_per_file_block + 1,
            max_total_file_blocks
        );
        if total_file_blocks > max_total_file_blocks {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidAllocationBitmapFileSize));
        }

        // Verify that each of the Allocation Bitmap File extents is covered by the
        // bitmap.
        for extent in extents.iter() {
            let bitmap_word_index = (u64::from(extent.end()) - 1) >> BITMAP_WORD_BITS_LOG2;
            if (bitmap_word_index > (1u64 << Self::MAX_BITMAP_WORDS_INDEX_LOG2))
                || Self::_bitmap_word_index_to_file_block_index(
                    bitmap_word_index,
                    bitmap_words_per_file_block_inv_mul,
                    bitmap_words_per_file_block_inv_shift,
                )? >= total_file_blocks
            {
                return Err(NvFsError::from(CocoonFsFormatError::InconsistentAllocBitmapFileExtents));
            }
        }

        // Finally, verify that the total number of bitmap words stored in the file
        // would fit an usize.
        if total_file_blocks
            .checked_mul(bitmap_words_per_file_block)
            .map(|total_bitmap_words| usize::try_from(total_bitmap_words).is_err())
            .unwrap_or(true)
        {
            return Err(NvFsError::DimensionsNotSupported);
        }

        // Convert the provided extents from physical to logical.
        let extents = extents::LogicalExtents::from(extents);

        Ok(Self {
            bitmap_words_per_file_block,
            bitmap_words_per_file_block_inv_mul,
            bitmap_words_per_file_block_inv_shift,
            extents,
            total_file_blocks,
        })
    }

    /// Determine the number of [Allocation Bitmap File
    /// Blocks](layout::ImageLayout::allocation_bitmap_file_block_allocation_blocks_log2)
    /// neeeded to cover a filesystem image of specified size.
    ///
    /// Used for determining the minimum required allocation bitmap file
    /// dimensions at filesystem creation ("mkfs") time.
    ///
    /// # Arguments:
    ///
    /// * `image_layout` - The to be created filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `image_allocation_blocks` - The to be created filesystem image's size
    ///   in units of [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    pub fn image_allocation_blocks_to_file_blocks(
        image_layout: &layout::ImageLayout,
        image_allocation_blocks: layout::AllocBlockCount,
    ) -> Result<u64, NvFsError> {
        if u64::from(image_allocation_blocks) == 0 {
            return Ok(0);
        }

        let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2;
        let file_block_allocation_blocks_log2 = image_layout.allocation_bitmap_file_block_allocation_blocks_log2;

        let file_block_size_log2 =
            file_block_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32 + 7;
        if file_block_size_log2 >= u64::BITS {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidAllocationBitmapFileConfig));
        }

        let file_block_encryption_layout = encryption_entities::EncryptedBlockLayout::new(
            image_layout.block_cipher_alg,
            file_block_allocation_blocks_log2,
            allocation_block_size_128b_log2,
        )?;
        let file_block_payload_len: usize = file_block_encryption_layout.effective_payload_len()?;
        let bitmap_words_per_file_block: usize = file_block_payload_len / mem::size_of::<BitmapWord>();
        let bitmap_words_per_file_block = match u64::try_from(bitmap_words_per_file_block) {
            Ok(bitmap_words_per_file_file_block) => bitmap_words_per_file_file_block,
            Err(_) => return Err(NvFsError::DimensionsNotSupported),
        };

        Ok(
            ((((u64::from(image_allocation_blocks) - 1) >> BITMAP_WORD_BITS_LOG2) + 1) - 1)
                / bitmap_words_per_file_block
                + 1,
        )
    }

    /// Compute pair of multiplier and shift distance for dividing by the number
    /// of [`BitmapWord`]s in a [Allocation Bitmap File
    /// Block](layout::ImageLayout::allocation_bitmap_file_block_allocation_blocks_log2) via a
    /// multiply + shift operation.
    ///
    /// A pair of multiplier and shift distance is returned upon success.
    ///
    /// # Arguments:
    ///
    /// * `bitmap_words_per_file_block` - Number of [`BitmapWord`]s that can be
    ///   stored in a single [Allocation Bitmap File
    ///   Block](layout::ImageLayout::allocation_bitmap_file_block_allocation_blocks_log2).
    fn compute_bitmap_words_per_file_block_inv(bitmap_words_per_file_block: u64) -> Result<(u64, u32), NvFsError> {
        // Compute the multiplier + shift for dividing by bitmap_words_per_file_block,
        // c.f. Hacker's Delight, 2nd edition, 10 ("Integer Division by
        // Constants"). Note that because the possible bitmap word index range
        // doesn't need a full u64's bits for its representation, there are some
        // spare bits available, which means the multiplier will not overflow an
        // u64. Also, from inspecting the proofs found in the reference from above, a
        // search for the strictly minimum p is not needed for correctness.
        if bitmap_words_per_file_block <= 1 {
            // It's not possible to divide by 1 via the multiply + shift. As this means we'd
            // have less than 16 bytes worth of payload available in an
            // Allocation Block (which is of size 128 bytes, at least), it's not
            // worth supporthing this.
            return Err(NvFsError::DimensionsNotSupported);
        }

        let d = bitmap_words_per_file_block;
        // 1 << MAX_BITMAP_WORDS_INDEX_LOG2 is a upper bound for the n_c.
        let p = u64::BITS - (d - 1).leading_zeros() + Self::MAX_BITMAP_WORDS_INDEX_LOG2;
        let p = p.max(u64::BITS);
        let m = ((1u128 << p) + (d - 1) as u128) / d as u128;
        if m >> u64::BITS != 0 {
            return Err(nvfs_err_internal!());
        }
        Ok((m as u64, p))
    }

    /// Obtain the number of [`BitmapWord`]s that can be stored in a single
    /// [Allocation Bitmap File
    /// Block](layout::ImageLayout::allocation_bitmap_file_block_allocation_blocks_log2).
    pub fn get_bitmap_words_per_file_block(&self) -> u64 {
        self.bitmap_words_per_file_block
    }

    /// Determine a given [`BitmapWord`]'s containing [Allocation Bitmap File
    /// Block](layout::ImageLayout::allocation_bitmap_file_block_allocation_blocks_log2).
    ///
    /// Compute the index of the [Allocation Bitmap File
    /// Block](layout::ImageLayout::allocation_bitmap_file_block_allocation_blocks_log2) storing the
    /// [`BitmapWord`] of index `bitmap_word_index`.
    ///
    /// # Arguments:
    ///
    /// * `bitmap_word_index` - Index of the [`BitmapWord`] whose containing
    ///   [Allocation Bitmap File
    ///   Block](layout::ImageLayout::allocation_bitmap_file_block_allocation_blocks_log2)
    ///   to determine.
    pub fn bitmap_word_index_to_file_block_index(&self, bitmap_word_index: u64) -> Result<u64, NvFsError> {
        Self::_bitmap_word_index_to_file_block_index(
            bitmap_word_index,
            self.bitmap_words_per_file_block_inv_mul,
            self.bitmap_words_per_file_block_inv_shift,
        )
    }

    /// Implementation of [`Self::bitmap_word_index_to_file_block_index()`].
    ///
    /// Compute the index of the [Allocation Bitmap File
    /// Block](layout::ImageLayout::allocation_bitmap_file_block_allocation_blocks_log2) storing the
    /// [`BitmapWord`] of index `bitmap_word_index` by a division implemented as
    /// a multiply + shift operation.
    ///
    /// # Arguments:
    ///
    /// * `bitmap_word_index` - Index of the [`BitmapWord`] whose containing
    ///   [Allocation Bitmap File
    ///   Block](layout::ImageLayout::allocation_bitmap_file_block_allocation_blocks_log2)
    ///   to determine.
    /// * `bitmap_words_per_file_block_inv_mul` - The multiplier as computed by
    ///   [`compute_bitmap_words_per_file_block_inv()`](Self::compute_bitmap_words_per_file_block_inv).
    /// * `bitmap_words_per_file_block_inv_shift` - The shift distance as
    ///   computed by
    ///   [`compute_bitmap_words_per_file_block_inv()`](Self::compute_bitmap_words_per_file_block_inv).
    fn _bitmap_word_index_to_file_block_index(
        bitmap_word_index: u64,
        bitmap_words_per_file_block_inv_mul: u64,
        bitmap_words_per_file_block_inv_shift: u32,
    ) -> Result<u64, NvFsError> {
        if bitmap_word_index >> Self::MAX_BITMAP_WORDS_INDEX_LOG2 > 1 {
            return Err(nvfs_err_internal!());
        }

        // A multiply high is needed, but u64::widening_mul() is unstable. However, the
        // compiler seems smart enough to recognize the following pattern as a
        // mulhi + shift as desired.
        Ok(
            (((bitmap_word_index as u128 * bitmap_words_per_file_block_inv_mul as u128) >> u64::BITS) as u64)
                >> (bitmap_words_per_file_block_inv_shift - u64::BITS),
        )
    }

    /// Get the allocation bitmap file's backing storage location.
    pub fn get_extents(&self) -> &extents::LogicalExtents {
        &self.extents
    }

    /// Stage pending updates to the allocation bitmap file at a
    /// [`Transaction`].
    ///
    /// Translate a [`Transaction`]'s pending allocations and deallocations
    /// relative to a base [`alloc_bitmap` into updates to the allocation
    /// bitmap file's contents on storage and stage them for write out at
    /// transaction commit at the
    /// [`Transaction::auth_tree_data_blocks_update_states`].
    ///
    /// # Arguments:
    ///
    /// * `transaction_updates_states` - `mut` reference to the
    ///   [`Transaction`]'s
    ///   [`auth_tree_data_blocks_update_states`](Transaction::auth_tree_data_blocks_update_states)
    ///   member to stage the allocation bitmap file content updates at.
    /// * `transaction_pending_allocs` - The [`Transaction`'s pending
    ///   allocations](transaction::TransactionAllocations::pending_allocs] to
    ///   translate into allocation bitmap file content updates.
    /// * `transaction_pending_frees` - The [`Transaction`'s pending
    ///   deallocations](transaction::TransactionAllocations::pending_frees] to
    ///   translate into allocation bitmap file content updates.
    /// * `alloc_bitmap` - Base [`AllocBitmap`] state relative to which
    ///   `transaction_pending_allocs` and `transaction_pending_frees` are
    ///   defined.
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `fs_root_key` - The filesystem's root key.
    /// * `fs_sync_state_keys_cache` - The [filesystem instance's key
    ///   cache](crate::fs::cocoonfs::fs::CocoonFsSyncState::keys_cache).
    /// * `rng` - Random number generator to generate IVs and randomize padding
    ///   with.
    #[allow(clippy::too_many_arguments)]
    pub fn write_updates<ST: sync_types::SyncTypes>(
        &self,
        transaction_updates_states: &mut transaction::AuthTreeDataBlocksUpdateStates,
        transaction_pending_allocs: &SparseAllocBitmap,
        transaction_pending_frees: &SparseAllocBitmap,
        alloc_bitmap: &AllocBitmap,
        image_layout: &layout::ImageLayout,
        fs_root_key: &keys::RootKey,
        fs_sync_state_keys_cache: &mut keys::KeyCacheRef<'_, ST>,
        rng: &mut dyn rng::RngCoreDispatchable,
    ) -> Result<(), NvFsError> {
        if transaction_pending_allocs.is_empty() && transaction_pending_frees.is_empty() {
            return Ok(());
        }

        // Does not overflow, a block's total payload length has been verified to fit an
        // usize in Self::new().
        let mut file_block_buf = FixedVec::<u8, 0>::new_with_default(
            self.bitmap_words_per_file_block as usize * mem::size_of::<BitmapWord>(),
        )?;

        let file_block_encryption_layout = encryption_entities::EncryptedBlockLayout::new(
            image_layout.block_cipher_alg,
            image_layout.allocation_bitmap_file_block_allocation_blocks_log2,
            image_layout.allocation_block_size_128b_log2,
        )?;
        let file_block_encryption_key = keys::KeyCache::get_key(
            fs_sync_state_keys_cache,
            fs_root_key,
            &keys::KeyId::new(
                inode_index::SpecialInode::AllocBitmap as u32,
                inode_index::InodeKeySubdomain::InodeData as u32,
                keys::KeyPurpose::Encryption,
            ),
        )?;
        let file_block_encryption_instance = encryption_entities::EncryptedBlockEncryptionInstance::new(
            file_block_encryption_layout,
            symcipher::SymBlockCipherModeEncryptionInstance::new(
                tpm2_interface::TpmiAlgCipherMode::Cbc,
                &image_layout.block_cipher_alg,
                &file_block_encryption_key,
            )?,
        )?;

        let mut transaction_allocs_iter = transaction_pending_allocs.iter();
        let mut transaction_frees_iter = transaction_pending_frees.iter();
        let mut next_transaction_alloc = transaction_allocs_iter.next();
        let mut next_transaction_free = transaction_frees_iter.next();
        while let Some(next_modified_bitmap_word_covered_allocation_blocks_begin) = next_transaction_alloc
            .map(|next_transaction_alloc| {
                next_transaction_free
                    .map(|next_transaction_free| next_transaction_alloc.0.min(next_transaction_free.0))
                    .unwrap_or(next_transaction_alloc.0)
            })
            .or_else(|| next_transaction_free.map(|next_transaction_free| next_transaction_free.0))
        {
            let next_modified_bitmap_word_index =
                u64::from(next_modified_bitmap_word_covered_allocation_blocks_begin) >> BITMAP_WORD_BITS_LOG2;
            let file_block_index = self.bitmap_word_index_to_file_block_index(next_modified_bitmap_word_index)?;
            if file_block_index >= self.total_file_blocks {
                return Err(nvfs_err_internal!());
            }

            // Prepare the updated allocation bitmap file block's contents.
            let file_block_bitmap_words_index_offset = file_block_index * self.bitmap_words_per_file_block;
            for file_block_bitmap_word_index in 0..self.bitmap_words_per_file_block {
                let cur_bitmap_word_index = file_block_bitmap_words_index_offset + file_block_bitmap_word_index;
                // The cast to usize does not overflow, it's been checked in Self::new() that
                // the total number of bitmap words fits into one.
                let mut updated_bitmap_word = alloc_bitmap
                    .bitmap
                    .get(cur_bitmap_word_index as usize)
                    .copied()
                    .unwrap_or(0);
                let cur_bitmap_word_new_allocs = if let Some(next_alloc) = next_transaction_alloc.as_ref() {
                    if u64::from(next_alloc.0) >> BITMAP_WORD_BITS_LOG2 == cur_bitmap_word_index {
                        let cur_bitmap_word_new_allocs = next_alloc.1;
                        updated_bitmap_word |= cur_bitmap_word_new_allocs;
                        next_transaction_alloc = transaction_allocs_iter.next();
                        cur_bitmap_word_new_allocs
                    } else {
                        0
                    }
                } else {
                    0
                };
                if let Some(next_free) = next_transaction_free.as_ref() {
                    if u64::from(next_free.0) >> BITMAP_WORD_BITS_LOG2 == cur_bitmap_word_index {
                        if next_free.1 & cur_bitmap_word_new_allocs != 0 {
                            // There's some Allocation Block which is getting both allocated and freed
                            // by the transaction.
                            return Err(nvfs_err_internal!());
                        }
                        updated_bitmap_word &= !next_free.1;
                        next_transaction_free = transaction_frees_iter.next();
                    }
                }

                let cur_bitmap_word_begin_in_file_block_buf =
                    file_block_bitmap_word_index as usize * mem::size_of::<BitmapWord>();
                let cur_bitmap_word_end_in_file_block_buf =
                    cur_bitmap_word_begin_in_file_block_buf + mem::size_of::<BitmapWord>();
                *<&mut [u8; mem::size_of::<BitmapWord>()]>::try_from(
                    &mut file_block_buf[cur_bitmap_word_begin_in_file_block_buf..cur_bitmap_word_end_in_file_block_buf],
                )
                .map_err(|_| nvfs_err_internal!())? = updated_bitmap_word.to_le_bytes();
            }

            // Find the allocation bitmap file block's physical extents, prepare the
            // transaction's corresponding update staging states and encrypt the
            // updated block to there.
            let file_block_logical_allocation_blocks_begin = layout::LogicalAllocBlockIndex::from(
                file_block_index << (image_layout.allocation_bitmap_file_block_allocation_blocks_log2 as u32),
            );
            let file_block_logical_allocation_blocks_range = layout::LogicalAllocBlockRange::from((
                file_block_logical_allocation_blocks_begin,
                layout::AllocBlockCount::from(
                    1u64 << (image_layout.allocation_bitmap_file_block_allocation_blocks_log2 as u32),
                ),
            ));
            let mut file_block_logical_extents_iter = self
                .extents
                .iter_range(&file_block_logical_allocation_blocks_range)
                .ok_or_else(|| nvfs_err_internal!())?;
            // It's been verified already that the Allocation Bitmap File's individual
            // extents' lengths are aligned to the block size.
            let file_block_logical_extent = file_block_logical_extents_iter
                .next()
                .ok_or_else(|| nvfs_err_internal!())?;
            if file_block_logical_extents_iter.next().is_some() {
                return Err(nvfs_err_internal!());
            }
            let file_block_physical_allocation_blocks_range = file_block_logical_extent.physical_range();

            // Prepare the transaction's update states.
            let file_block_update_states_allocation_blocks_range = transaction_updates_states
                .insert_missing_in_range(
                    file_block_physical_allocation_blocks_range,
                    alloc_bitmap,
                    transaction_pending_frees,
                    None,
                )
                .map(|(file_block_update_states_allocation_blocks_range, _)| {
                    file_block_update_states_allocation_blocks_range
                })
                .map_err(|(e, _)| e)?;
            transaction_updates_states.allocate_allocation_blocks_update_staging_bufs(
                &file_block_update_states_allocation_blocks_range,
                image_layout.allocation_block_size_128b_log2 as u32,
            )?;

            // And encrypt the block to there.
            file_block_encryption_instance.encrypt_one_block(
                transaction_updates_states.iter_allocation_blocks_update_staging_bufs_mut(
                    &file_block_update_states_allocation_blocks_range,
                )?,
                io_slices::SingletonIoSlice::new(file_block_buf.as_slice()).map_infallible_err(),
                rng,
            )?
        }

        Ok(())
    }
}

/// Read an [`AllocBitmap`] from an [`AllocBitmapFile`] on storage.
///
/// Read an allocation bitmap from storage into memory at filesystem opening
/// time.
pub struct AllocBitmapFileReadFuture<C: chip::NvChip> {
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self.
    bitmap: Option<AllocBitmap>,
    bitmap_word_index: usize,

    file_extent_index: usize,
    file_block_in_extent_index: u64,

    file_block_decryption_instance: encryption_entities::EncryptedBlockDecryptionInstance,
    file_block_decryption_buf: FixedVec<u8, 0>,

    fut_state: AllocBitmapFileReadFutureState<C>,
}

/// Internal [`AllocBitmapFileReadFuture::poll()`] state-machine state.
#[allow(clippy::large_enum_variant)]
enum AllocBitmapFileReadFutureState<C: chip::NvChip> {
    Init,
    ReadAuthenticateFileBlock {
        read_fut: read_buffer::BufferedReadAuthenticateDataFuture<C>,
    },
    Done,
}

impl<C: chip::NvChip> AllocBitmapFileReadFuture<C> {
    /// Instantiate a [`AllocBitmapFileReadFuture`].
    ///
    /// # Arguments:
    ///
    /// * `file` - The [`AllocBitmapFile`] to read in.
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `root_key` - The filesystem's root key.
    /// * `keys_cache` - A [KeyCache](keys::KeyCache) instance associated with
    ///   the `root_key`.
    pub fn new<ST: sync_types::SyncTypes>(
        file: &AllocBitmapFile,
        image_layout: &layout::ImageLayout,
        root_key: &keys::RootKey,
        keys_cache: &mut keys::KeyCacheRef<ST>,
    ) -> Result<Self, NvFsError> {
        // AllocBitmapFile::new() checks this wouldn't overflow.
        let total_bitmap_words = (file.total_file_blocks * file.bitmap_words_per_file_block) as usize;
        let bitmap = try_alloc_vec(total_bitmap_words)?;
        let mut bitmap = AllocBitmap { bitmap };

        // The authentication code assumes all Allocation Blocks from to be
        // authenticated extents are allocated.  The the Allocation Bitmap
        // File's corresponding bits for bootstrapping.
        for file_extent in file.extents.iter() {
            bitmap.set_in_range(&file_extent.physical_range(), true)?;
        }

        let file_block_encryption_layout = encryption_entities::EncryptedBlockLayout::new(
            image_layout.block_cipher_alg,
            image_layout.allocation_bitmap_file_block_allocation_blocks_log2,
            image_layout.allocation_block_size_128b_log2,
        )?;
        let file_block_encryption_key = keys::KeyCache::get_key(
            keys_cache,
            root_key,
            &keys::KeyId::new(
                inode_index::SpecialInode::AllocBitmap as u32,
                inode_index::InodeKeySubdomain::InodeData as u32,
                keys::KeyPurpose::Encryption,
            ),
        )?;
        let file_block_decryption_instance = encryption_entities::EncryptedBlockDecryptionInstance::new(
            file_block_encryption_layout,
            symcipher::SymBlockCipherModeDecryptionInstance::new(
                tpm2_interface::TpmiAlgCipherMode::Cbc,
                &image_layout.block_cipher_alg,
                &file_block_encryption_key,
            )?,
        )?;
        drop(file_block_encryption_key);

        // Does not overflow, c.f. AllocBitmapFile::new().
        let file_block_decrypted_len: usize =
            (file.bitmap_words_per_file_block as usize) * mem::size_of::<BitmapWord>();
        let file_block_decryption_buf = FixedVec::new_with_default(file_block_decrypted_len)?;

        Ok(Self {
            bitmap: Some(bitmap),
            bitmap_word_index: 0,
            file_extent_index: 0,
            file_block_in_extent_index: 0,
            file_block_decryption_instance,
            file_block_decryption_buf,
            fut_state: AllocBitmapFileReadFutureState::Init,
        })
    }

    /// Poll the [`AllocBitmapFileReadFuture`] instance to completion.
    ///
    /// The future polling semantics are that of standard Rust
    /// [`Future::poll()`](core::future::Future::poll), but `poll()` takes some
    /// additional arguments in order to alleviate the need to store
    /// (lifetime managed) references in `Self` itself.
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `file` - The [`AllocBitmapFile`] to read in.
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `image_header_end` - [End of the filesystem image header on
    ///   storage](crate::fs::cocoonfs::image_header::MutableImageHeader::physical_location).
    /// * `auth_tree` - The filesystem's [`AuthTree`](auth_tree::AuthTree).
    /// * `read_buffer` - A [`ReadBuffer`](read_buffer::ReadBuffer) instance
    ///   associated with the invoking filesystem opening operation.
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    #[allow(clippy::too_many_arguments)]
    pub fn poll<ST: sync_types::SyncTypes>(
        self: pin::Pin<&mut Self>,
        chip: &C,
        file: &AllocBitmapFile,
        image_layout: &layout::ImageLayout,
        image_header_end: layout::PhysicalAllocBlockIndex,
        auth_tree: &mut auth_tree::AuthTreeRef<'_, ST>,
        read_buffer: &read_buffer::ReadBuffer<ST>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<AllocBitmap, NvFsError>> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                AllocBitmapFileReadFutureState::Init => {
                    if this.file_extent_index >= file.extents.len() {
                        this.fut_state = AllocBitmapFileReadFutureState::Done;
                        debug_assert_eq!(this.file_block_in_extent_index, 0);
                        debug_assert_eq!(
                            this.bitmap_word_index,
                            (file.total_file_blocks * file.bitmap_words_per_file_block) as usize
                        );
                        // It is crucial to clear the read_buffer: it's possibly been used with the
                        // initial bootstrapping Allocation Bitmap having most bits clear. That
                        // might have caused some Allocation Blocks in the near vincity of the
                        // Bitmap File itself to have been wronly inserted as "unallocated".
                        read_buffer.clear_caches();
                        return task::Poll::Ready(match this.bitmap.take() {
                            Some(bitmap) => Ok(bitmap),
                            None => Err(nvfs_err_internal!()),
                        });
                    }

                    let file_block_allocation_blocks_log2 =
                        image_layout.allocation_bitmap_file_block_allocation_blocks_log2 as u32;
                    let cur_file_extent = file.extents.get_extent(this.file_extent_index).physical_range();
                    let file_block_allocation_blocks_begin = cur_file_extent.begin()
                        + layout::AllocBlockCount::from(
                            this.file_block_in_extent_index << file_block_allocation_blocks_log2,
                        );
                    let file_block_allocation_blocks_end = file_block_allocation_blocks_begin
                        + layout::AllocBlockCount::from(1u64 << file_block_allocation_blocks_log2);
                    match file_block_allocation_blocks_end.cmp(&cur_file_extent.end()) {
                        cmp::Ordering::Less => {
                            this.file_block_in_extent_index += 1;
                        }
                        cmp::Ordering::Equal => {
                            this.file_extent_index += 1;
                            this.file_block_in_extent_index = 0;
                        }
                        cmp::Ordering::Greater => {
                            this.fut_state = AllocBitmapFileReadFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    let read_fut = match read_buffer::BufferedReadAuthenticateDataFuture::new(
                        &layout::PhysicalAllocBlockRange::new(
                            file_block_allocation_blocks_begin,
                            file_block_allocation_blocks_end,
                        ),
                        image_layout,
                        auth_tree.get_config(),
                        chip,
                    ) {
                        Ok(read_fut) => read_fut,
                        Err(e) => {
                            this.fut_state = AllocBitmapFileReadFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    this.fut_state = AllocBitmapFileReadFutureState::ReadAuthenticateFileBlock { read_fut };
                }
                AllocBitmapFileReadFutureState::ReadAuthenticateFileBlock { read_fut } => {
                    let bitmap = match this.bitmap.as_mut() {
                        Some(bitmap) => bitmap,
                        None => {
                            this.fut_state = AllocBitmapFileReadFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };
                    let encryted_file_block = match read_buffer::BufferedReadAuthenticateDataFuture::poll(
                        pin::Pin::new(read_fut),
                        chip,
                        image_layout,
                        image_header_end,
                        bitmap,
                        auth_tree,
                        read_buffer,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(encryted_file_block)) => encryted_file_block,
                        task::Poll::Ready(Err(e)) => {
                            this.fut_state = AllocBitmapFileReadFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    // Decrypt the Allocation Bitmap File Block.
                    if let Err(e) = this.file_block_decryption_instance.decrypt_one_block(
                        io_slices::SingletonIoSliceMut::new(&mut this.file_block_decryption_buf).map_infallible_err(),
                        io_slices::BuffersSliceIoSlicesIter::new(&encryted_file_block).map_infallible_err(),
                    ) {
                        this.fut_state = AllocBitmapFileReadFutureState::Done;
                        return task::Poll::Ready(Err(e));
                    }

                    // And decode the individual bitmap words from the decryption buffer to
                    // the Allocation Bitmap.
                    for encoded_bitmap_word in this
                        .file_block_decryption_buf
                        .chunks_exact(mem::size_of::<BitmapWord>())
                    {
                        let encoded_bitmap_word =
                            match <&[u8; mem::size_of::<BitmapWord>()]>::try_from(encoded_bitmap_word) {
                                Ok(encoded_bitmap_word) => *encoded_bitmap_word,
                                Err(_) => {
                                    this.fut_state = AllocBitmapFileReadFutureState::Done;
                                    return task::Poll::Ready(Err(nvfs_err_internal!()));
                                }
                            };
                        bitmap.bitmap[this.bitmap_word_index] = BitmapWord::from_le_bytes(encoded_bitmap_word);
                        this.bitmap_word_index += 1;
                    }

                    // And proceed to the next Allocation Bitmap File Block.
                    this.fut_state = AllocBitmapFileReadFutureState::Init;
                }
                AllocBitmapFileReadFutureState::Done => unreachable!(),
            }
        }
    }
}

/// Initialize an allocation bitmap file on storage at filesystem creation
/// ("mkfs") time.
pub struct AllocBitmapFileInitializeFuture<C: chip::NvChip> {
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self.
    auth_tree_initialization_cursor: Option<Box<auth_tree::AuthTreeInitializationCursor>>,
    file_block_encryption_instance: encryption_entities::EncryptedBlockEncryptionInstance,
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self.
    file: Option<AllocBitmapFile>,
    file_extent: layout::PhysicalAllocBlockRange,
    file_block_encode_buf: FixedVec<u8, 0>,
    encrypted_file_blocks: FixedVec<FixedVec<u8, 7>, 0>,
    next_file_extent_allocation_block_index: layout::PhysicalAllocBlockIndex,
    next_bitmap_word_index: usize,
    chip_io_block_allocation_blocks_log2: u8,
    preferred_bulk_allocation_blocks_log2: u8,
    fut_state: AllocBitmapFileInitializeFutureState<C>,
}

/// Internal [`AllocBitmapFileInitializeFuture::poll()`] state-machine state.
enum AllocBitmapFileInitializeFutureState<C: chip::NvChip> {
    PrepareFileBlocksBatch,
    AuthTreeUpdateFileBlocksBatchRange {
        cur_file_extent_range_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        cur_file_extent_range_allocation_blocks_end: layout::PhysicalAllocBlockIndex,
        cur_file_extent_range_write_allocation_blocks_end: layout::PhysicalAllocBlockIndex,
        cur_file_extent_range_next_allocation_block_index: layout::PhysicalAllocBlockIndex,
        auth_tree_write_part_fut: Option<auth_tree::AuthTreeInitializationCursorWritePartFuture<C>>,
    },
    WriteFileBlocksBatch {
        cur_file_extent_range_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        cur_file_extent_range_allocation_blocks_end: layout::PhysicalAllocBlockIndex,
        cur_file_extent_range_write_allocation_blocks_end: layout::PhysicalAllocBlockIndex,
        write_fut: write_blocks::WriteBlocksFuture<C>,
    },
    Done,
}

impl<C: chip::NvChip> AllocBitmapFileInitializeFuture<C> {
    /// Instantiate a [`AllocBitmapFileReadFuture`].
    ///
    /// The [`AllocBitmapFileReadFuture`] assumes ownership of the
    /// `auth_tree_initialization_cursor` for the duration of the operation.
    /// It will get returned back either from here upon error, or eventually
    /// from [`poll()`](Self::poll) upon (successful) future completion.
    ///
    /// # Arguments:
    ///
    /// * `file_extent` - The allocation bitmap file's backing extent on
    ///   storage. Note that it is expected that the file spans a single extent
    ///   only at filesystem creation time. Further, it is expected that the
    ///   `file_extent` has been placed right after the authentication tree
    ///   storage, hence that its beginning is aligned to the larger of the
    ///   [Authentication Tree Data
    ///   Block](layout::ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    ///   and the [IO
    ///   Block](layout::ImageLayout::io_block_allocation_blocks_log2) size. No
    ///   alignment constraints apply to the `file_extent`'s end though.
    /// * `chip` - The filesystem image backing storage.
    /// * `auth_tree_initialization_cursor` - The
    ///   [`AuthTreeInitializationCursor`](auth_tree::AuthTreeInitializationCursor)
    ///   to push data updates in the course of writing for the purpose of
    ///   initializing the authentication treen part covering the allocation
    ///   bitmap file.
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `root_key` - The filesystem's root key.
    /// * `keys_cache` - A [KeyCache](keys::KeyCache) instance associated with
    ///   the `root_key`.
    pub fn new<ST: sync_types::SyncTypes>(
        file_extent: &layout::PhysicalAllocBlockRange,
        chip: &C,
        auth_tree_initialization_cursor: Box<auth_tree::AuthTreeInitializationCursor>,
        image_layout: &layout::ImageLayout,
        root_key: &keys::RootKey,
        keys_cache: &mut keys::KeyCacheRef<'_, ST>,
    ) -> Result<Self, (Box<auth_tree::AuthTreeInitializationCursor>, NvFsError)> {
        if auth_tree_initialization_cursor.next_physical_allocation_block_index() != file_extent.begin() {
            return Err((auth_tree_initialization_cursor, nvfs_err_internal!()));
        }

        // It is assumed that the file_extent has been placed right after the
        // Authentication Tree's extent. That is, the beginning is assumed to be
        // aligned to the larger of the IO Block and the Authentication Tree
        // Data Block size, the end to the latter only.
        if !u64::from(file_extent.begin()).is_aligned_pow2(
            (image_layout.io_block_allocation_blocks_log2 as u32)
                .max(image_layout.auth_tree_data_block_allocation_blocks_log2 as u32),
        ) || !u64::from(file_extent.end())
            .is_aligned_pow2(image_layout.auth_tree_data_block_allocation_blocks_log2 as u32)
        {
            return Err((auth_tree_initialization_cursor, nvfs_err_internal!()));
        }

        let mut file_extents = extents::PhysicalExtents::new();
        if let Err(e) = file_extents.push_extent(file_extent, true) {
            return Err((auth_tree_initialization_cursor, e));
        }
        let file = match AllocBitmapFile::new(image_layout, file_extents) {
            Ok(file) => file,
            Err(e) => return Err((auth_tree_initialization_cursor, e)),
        };
        // Does not overflow, a block's total payload length has been verified to fit an
        // usize in AllocBitmapFile::new().
        let file_block_used_payload_len = file.bitmap_words_per_file_block as usize * mem::size_of::<BitmapWord>();
        let file_block_encode_buf = match FixedVec::new_with_default(file_block_used_payload_len) {
            Ok(file_block_encode_buf) => file_block_encode_buf,
            Err(e) => return Err((auth_tree_initialization_cursor, NvFsError::from(e))),
        };

        let file_block_encryption_layout = match encryption_entities::EncryptedBlockLayout::new(
            image_layout.block_cipher_alg,
            image_layout.allocation_bitmap_file_block_allocation_blocks_log2,
            image_layout.allocation_block_size_128b_log2,
        ) {
            Ok(file_block_encryption_layout) => file_block_encryption_layout,
            Err(e) => return Err((auth_tree_initialization_cursor, e)),
        };
        let file_block_encryption_key = match keys::KeyCache::get_key(
            keys_cache,
            root_key,
            &keys::KeyId::new(
                inode_index::SpecialInode::AllocBitmap as u32,
                inode_index::InodeKeySubdomain::InodeData as u32,
                keys::KeyPurpose::Encryption,
            ),
        ) {
            Ok(file_block_encryption_key) => file_block_encryption_key,
            Err(e) => return Err((auth_tree_initialization_cursor, e)),
        };
        let file_block_encryption_block_cipher_instance = match symcipher::SymBlockCipherModeEncryptionInstance::new(
            tpm2_interface::TpmiAlgCipherMode::Cbc,
            &image_layout.block_cipher_alg,
            &file_block_encryption_key,
        ) {
            Ok(file_block_encryption_block_cipher_instance) => file_block_encryption_block_cipher_instance,
            Err(e) => return Err((auth_tree_initialization_cursor, NvFsError::from(e))),
        };
        let file_block_encryption_instance = match encryption_entities::EncryptedBlockEncryptionInstance::new(
            file_block_encryption_layout,
            file_block_encryption_block_cipher_instance,
        ) {
            Ok(file_block_encryption_instance) => file_block_encryption_instance,
            Err(e) => return Err((auth_tree_initialization_cursor, e)),
        };
        drop(file_block_encryption_key);

        let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();
        let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
        let file_block_allocation_blocks_log2 = image_layout.allocation_bitmap_file_block_allocation_blocks_log2 as u32;
        let chip_io_block_allocation_blocks_log2 =
            chip_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2) as u8;
        let preferred_chip_io_blocks_bulk_log2 =
            chip.preferred_chip_io_blocks_bulk_log2()
                .min(u64::BITS - 1 - chip_io_block_size_128b_log2 - 7) as u8;
        let preferred_bulk_allocation_blocks_log2 =
            (preferred_chip_io_blocks_bulk_log2 as u32 + chip_io_block_size_128b_log2)
                .saturating_sub(allocation_block_size_128b_log2)
                .max(image_layout.io_block_allocation_blocks_log2 as u32)
                .max(file_block_allocation_blocks_log2)
                .min(usize::BITS - 1 + file_block_allocation_blocks_log2) as u8;
        debug_assert!(preferred_bulk_allocation_blocks_log2 >= chip_io_block_allocation_blocks_log2);

        let preferred_bulk_file_blocks_log2 =
            preferred_bulk_allocation_blocks_log2 as u32 - file_block_allocation_blocks_log2;
        let mut encrypted_file_blocks = match FixedVec::new_with_default(1usize << preferred_bulk_file_blocks_log2) {
            Ok(encrypted_file_blocks) => encrypted_file_blocks,
            Err(e) => return Err((auth_tree_initialization_cursor, NvFsError::from(e))),
        };
        // Does not overflow, the Allocation Bitmap File Block size had been checked to
        // fit an usize in AllocBitmapFile::new().
        let file_block_size = 1usize << (file_block_allocation_blocks_log2 + allocation_block_size_128b_log2 + 7);
        for encrypted_file_block in encrypted_file_blocks.iter_mut() {
            *encrypted_file_block = match FixedVec::new_with_default(file_block_size) {
                Ok(encrypted_file_block) => encrypted_file_block,
                Err(e) => return Err((auth_tree_initialization_cursor, NvFsError::from(e))),
            };
        }

        Ok(Self {
            auth_tree_initialization_cursor: Some(auth_tree_initialization_cursor),
            file_block_encryption_instance,
            file: Some(file),
            file_extent: *file_extent,
            file_block_encode_buf,
            encrypted_file_blocks,
            next_file_extent_allocation_block_index: file_extent.begin(),
            next_bitmap_word_index: 0,
            chip_io_block_allocation_blocks_log2,
            preferred_bulk_allocation_blocks_log2,
            fut_state: AllocBitmapFileInitializeFutureState::PrepareFileBlocksBatch,
        })
    }

    /// Poll the [`AllocBitmapFileInitializeFuture`] instance to completion.
    ///
    /// The future polling semantics are that of standard Rust
    /// [`Future::poll()`](core::future::Future::poll), but `poll()` takes some
    /// additional arguments in order to alleviate the need to store
    /// (lifetime managed) references in `Self` itself.
    ///
    /// Upon successful future completion,  a tuple consisting of the following
    /// is returned:
    ///
    /// * An [`AllocBitmapFile`] instance corresponding to the allocation bitmap
    ///   file just initialized.
    /// * A possibly empty list of buffers corresponding to the file's tail not
    ///   written out yet. The list is non-empty if and only if the
    ///   `file_extent` as passed initially passed to [`Self::new()`] does not
    ///   end at a location aligned to the [Chip IO Block
    ///   size](chip::NvChip::chip_io_block_size_128b_log2). Each buffer in the
    ///   list corresponds to exactly one [Allocation Bitmap File
    ///   Block](layout::ImageLayout::allocation_bitmap_file_block_allocation_blocks_log2)
    ///   and is of that size.  It is the caller's responsibility to write the
    ///   remaining buffers, as well as to push their contents to the returned
    ///   [`AuthTreeInitializationCursor`](auth_tree::AuthTreeInitializationCursor),
    ///   possibly in the course of writing some subsequent data, if any.
    /// * The [`AuthTreeInitializationCursor`](auth_tree::AuthTreeInitializationCursor)
    ///   instance initially passed to [`Self::new()`].
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `bitmap` - The [`AllocBitmap`] to write to the newly initialized
    ///   allocation bitmap file.
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `auth_tree_config` - The filesystem's
    ///   [`AuthTreeConfig`](auth_tree::AuthTreeConfig).
    /// * `rng` - Random number generator to generate IVs and randomize padding
    ///   with.
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    #[allow(clippy::type_complexity)]
    pub fn poll(
        self: pin::Pin<&mut Self>,
        chip: &C,
        bitmap: &AllocBitmap,
        image_layout: &layout::ImageLayout,
        auth_tree_config: &auth_tree::AuthTreeConfig,
        rng: &mut dyn rng::RngCoreDispatchable,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<
        Result<
            (
                AllocBitmapFile,
                FixedVec<FixedVec<u8, 7>, 0>,
                Box<auth_tree::AuthTreeInitializationCursor>,
            ),
            NvFsError,
        >,
    > {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                AllocBitmapFileInitializeFutureState::PrepareFileBlocksBatch => {
                    let file = match this.file.as_ref() {
                        Some(file) => file,
                        None => {
                            this.fut_state = AllocBitmapFileInitializeFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };
                    let file_block_allocation_blocks_log2 =
                        image_layout.allocation_bitmap_file_block_allocation_blocks_log2 as u32;
                    let cur_file_extent_range_allocation_blocks_begin = this.next_file_extent_allocation_block_index;
                    debug_assert!(
                        u64::from(cur_file_extent_range_allocation_blocks_begin - this.file_extent.begin())
                            .is_aligned_pow2(file_block_allocation_blocks_log2)
                    );

                    if cur_file_extent_range_allocation_blocks_begin == this.file_extent.end() {
                        let file = match this.file.take() {
                            Some(file) => file,
                            None => {
                                this.fut_state = AllocBitmapFileInitializeFutureState::Done;
                                return task::Poll::Ready(Err(nvfs_err_internal!()));
                            }
                        };
                        let auth_tree_initialization_cursor = match this.auth_tree_initialization_cursor.take() {
                            Some(auth_tree_initialization_cursor) => auth_tree_initialization_cursor,
                            None => {
                                this.fut_state = AllocBitmapFileInitializeFutureState::Done;
                                return task::Poll::Ready(Err(nvfs_err_internal!()));
                            }
                        };
                        this.fut_state = AllocBitmapFileInitializeFutureState::Done;
                        return task::Poll::Ready(Ok((file, FixedVec::new_empty(), auth_tree_initialization_cursor)));
                    }

                    let cur_file_extent_range_allocation_blocks_end = (this.next_file_extent_allocation_block_index
                        + layout::AllocBlockCount::from(1))
                    .align_up(this.preferred_bulk_allocation_blocks_log2 as u32)
                    .unwrap_or(this.file_extent.end())
                    .min(this.file_extent.end());
                    // We started at file_extent.begin(), which is known to be aligned to the IO
                    // block as well as to the Authentication Tree Data Block size. From there, we
                    // incremented by a multiple of the File Block size. file_extent.end() is a
                    // multiple of the File Block size (relative to the file_extent.begin()) aligned
                    // upwards to the Authentication Tree Data Block size, hence
                    // file_extent.block_count() is aligned to the File Block size: trivial if the
                    // File Block size is <= the Authentication Tree Data Block size as the extent's
                    // boundaries are both aligned, otherwise observe that there will no padding,
                    // because advancing from aligned file_extent.begin() by a multiple of the File
                    // Block size would always result in an aligned position.
                    debug_assert!(
                        u64::from(cur_file_extent_range_allocation_blocks_end - this.file_extent.begin())
                            .is_aligned_pow2(file_block_allocation_blocks_log2)
                    );
                    let cur_file_extent_range_allocation_blocks =
                        cur_file_extent_range_allocation_blocks_end - cur_file_extent_range_allocation_blocks_begin;
                    debug_assert!(
                        u64::from(cur_file_extent_range_allocation_blocks)
                            <= 1u64 << (this.preferred_bulk_allocation_blocks_log2 as u32)
                    );
                    debug_assert_ne!(u64::from(cur_file_extent_range_allocation_blocks), 0);
                    // preferred_bulk_allocation_blocks_log2 as been capped in Self::new() so that
                    // the number of File Blocks in a bulk would always fit an usize.
                    let cur_file_extent_range_file_blocks = (u64::from(cur_file_extent_range_allocation_blocks)
                        >> file_block_allocation_blocks_log2)
                        as usize;
                    debug_assert!(cur_file_extent_range_file_blocks <= this.encrypted_file_blocks.len());

                    for i in 0..cur_file_extent_range_file_blocks {
                        let mut bitmap_word_in_file_block_index = 0;
                        // bitmap_words_per_file_block fits an usize, c.f AllocBitmapFile::new().
                        while this.next_bitmap_word_index < bitmap.bitmap.len()
                            && bitmap_word_in_file_block_index < file.bitmap_words_per_file_block as usize
                        {
                            let encoded_bitmap_word = match <&mut [u8; mem::size_of::<BitmapWord>()]>::try_from(
                                &mut this.file_block_encode_buf[bitmap_word_in_file_block_index
                                    * mem::size_of::<BitmapWord>()
                                    ..(bitmap_word_in_file_block_index + 1) * mem::size_of::<BitmapWord>()],
                            ) {
                                Ok(encoded_bitmap_word) => encoded_bitmap_word,
                                Err(_) => {
                                    this.fut_state = AllocBitmapFileInitializeFutureState::Done;
                                    return task::Poll::Ready(Err(nvfs_err_internal!()));
                                }
                            };
                            *encoded_bitmap_word = bitmap.bitmap[this.next_bitmap_word_index].to_le_bytes();
                            this.next_bitmap_word_index += 1;
                            bitmap_word_in_file_block_index += 1;
                        }
                        this.file_block_encode_buf[bitmap_word_in_file_block_index * mem::size_of::<BitmapWord>()..]
                            .fill(0u8);

                        if let Err(e) = this.file_block_encryption_instance.encrypt_one_block(
                            io_slices::SingletonIoSliceMut::new(&mut this.encrypted_file_blocks[i])
                                .map_infallible_err(),
                            io_slices::SingletonIoSlice::new(&this.file_block_encode_buf).map_infallible_err(),
                            rng,
                        ) {
                            this.fut_state = AllocBitmapFileInitializeFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    }

                    let cur_file_extent_range_write_allocation_blocks_end = cur_file_extent_range_allocation_blocks_end
                        .align_down(this.chip_io_block_allocation_blocks_log2 as u32);
                    debug_assert!(
                        cur_file_extent_range_allocation_blocks_end == this.file_extent.end()
                            || cur_file_extent_range_write_allocation_blocks_end
                                == cur_file_extent_range_allocation_blocks_end
                    );

                    if cur_file_extent_range_write_allocation_blocks_end
                        == cur_file_extent_range_allocation_blocks_begin
                    {
                        // In the last Chip IO block and its only partially filled by Allocation
                        // Bitmap File Blocks. Return the remainder for the caller to handle it
                        // alongside other data subsequent to the Allocation Bitmap File.
                        let file = match this.file.take() {
                            Some(file) => file,
                            None => {
                                this.fut_state = AllocBitmapFileInitializeFutureState::Done;
                                return task::Poll::Ready(Err(nvfs_err_internal!()));
                            }
                        };
                        let auth_tree_initialization_cursor = match this.auth_tree_initialization_cursor.take() {
                            Some(auth_tree_initialization_cursor) => auth_tree_initialization_cursor,
                            None => {
                                this.fut_state = AllocBitmapFileInitializeFutureState::Done;
                                return task::Poll::Ready(Err(nvfs_err_internal!()));
                            }
                        };

                        let remainder_encrypted_file_blocks = match FixedVec::new_from_fn(
                            cur_file_extent_range_file_blocks,
                            |i| -> Result<FixedVec<u8, 7>, convert::Infallible> {
                                Ok(mem::take(&mut this.encrypted_file_blocks[i]))
                            },
                        ) {
                            Ok(remainder_encrypted_file_blocks) => remainder_encrypted_file_blocks,
                            Err(e) => {
                                this.fut_state = AllocBitmapFileInitializeFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(e)));
                            }
                        };

                        this.fut_state = AllocBitmapFileInitializeFutureState::Done;
                        return task::Poll::Ready(Ok((
                            file,
                            remainder_encrypted_file_blocks,
                            auth_tree_initialization_cursor,
                        )));
                    }

                    this.fut_state = AllocBitmapFileInitializeFutureState::AuthTreeUpdateFileBlocksBatchRange {
                        cur_file_extent_range_allocation_blocks_begin,
                        cur_file_extent_range_allocation_blocks_end,
                        cur_file_extent_range_write_allocation_blocks_end,
                        cur_file_extent_range_next_allocation_block_index:
                            cur_file_extent_range_allocation_blocks_begin,
                        auth_tree_write_part_fut: None,
                    };
                }
                AllocBitmapFileInitializeFutureState::AuthTreeUpdateFileBlocksBatchRange {
                    cur_file_extent_range_allocation_blocks_begin,
                    cur_file_extent_range_allocation_blocks_end,
                    cur_file_extent_range_write_allocation_blocks_end,
                    cur_file_extent_range_next_allocation_block_index,
                    auth_tree_write_part_fut,
                } => {
                    let file_block_allocation_blocks_log2 =
                        image_layout.allocation_bitmap_file_block_allocation_blocks_log2 as u32;
                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;

                    'write_auth_tree_part: loop {
                        let mut auth_tree_initialization_cursor =
                            if let Some(auth_tree_write_part_fut) = auth_tree_write_part_fut.as_mut() {
                                match auth_tree::AuthTreeInitializationCursorWritePartFuture::poll(
                                    pin::Pin::new(auth_tree_write_part_fut),
                                    chip,
                                    auth_tree_config,
                                    cx,
                                ) {
                                    task::Poll::Ready(Ok(auth_tree_initialization_cursor)) => {
                                        auth_tree_initialization_cursor
                                    }
                                    task::Poll::Ready(Err(e)) => {
                                        this.fut_state = AllocBitmapFileInitializeFutureState::Done;
                                        return task::Poll::Ready(Err(e));
                                    }
                                    task::Poll::Pending => return task::Poll::Pending,
                                }
                            } else {
                                match this.auth_tree_initialization_cursor.take() {
                                    Some(auth_tree_initialization_cursor) => auth_tree_initialization_cursor,
                                    None => {
                                        this.fut_state = AllocBitmapFileInitializeFutureState::Done;
                                        return task::Poll::Ready(Err(nvfs_err_internal!()));
                                    }
                                }
                            };

                        while *cur_file_extent_range_next_allocation_block_index
                            != *cur_file_extent_range_write_allocation_blocks_end
                        {
                            let allocation_block_in_cur_file_extent_range_index = u64::from(
                                *cur_file_extent_range_next_allocation_block_index
                                    - *cur_file_extent_range_allocation_blocks_begin,
                            );
                            let file_block_index = (allocation_block_in_cur_file_extent_range_index
                                >> file_block_allocation_blocks_log2)
                                as usize;
                            let allocation_block_in_file_block_index = (allocation_block_in_cur_file_extent_range_index
                                & u64::trailing_bits_mask(file_block_allocation_blocks_log2))
                                as usize;
                            *cur_file_extent_range_next_allocation_block_index += layout::AllocBlockCount::from(1);

                            auth_tree_initialization_cursor = match auth_tree_initialization_cursor.update(
                                auth_tree_config,
                                &this.encrypted_file_blocks[file_block_index][allocation_block_in_file_block_index
                                    << (allocation_block_size_128b_log2 + 7)
                                    ..(allocation_block_in_file_block_index + 1)
                                        << (allocation_block_size_128b_log2 + 7)],
                            ) {
                                Ok(auth_tree::AuthTreeInitializationCursorUpdateResult::NeedAuthTreePartWrite {
                                    write_fut,
                                }) => {
                                    *auth_tree_write_part_fut = Some(write_fut);
                                    continue 'write_auth_tree_part;
                                }
                                Ok(auth_tree::AuthTreeInitializationCursorUpdateResult::Done { cursor }) => cursor,
                                Err(e) => {
                                    this.fut_state = AllocBitmapFileInitializeFutureState::Done;
                                    return task::Poll::Ready(Err(e));
                                }
                            };
                        }

                        this.auth_tree_initialization_cursor = Some(auth_tree_initialization_cursor);
                        break;
                    }

                    let write_fut = write_blocks::WriteBlocksFuture::new(
                        &layout::PhysicalAllocBlockRange::new(
                            *cur_file_extent_range_allocation_blocks_begin,
                            *cur_file_extent_range_write_allocation_blocks_end,
                        ),
                        mem::take(&mut this.encrypted_file_blocks),
                        image_layout.allocation_bitmap_file_block_allocation_blocks_log2,
                        this.chip_io_block_allocation_blocks_log2,
                        image_layout.allocation_block_size_128b_log2,
                    );
                    this.fut_state = AllocBitmapFileInitializeFutureState::WriteFileBlocksBatch {
                        cur_file_extent_range_allocation_blocks_begin: *cur_file_extent_range_allocation_blocks_begin,
                        cur_file_extent_range_allocation_blocks_end: *cur_file_extent_range_allocation_blocks_end,
                        cur_file_extent_range_write_allocation_blocks_end:
                            *cur_file_extent_range_write_allocation_blocks_end,
                        write_fut,
                    };
                }
                AllocBitmapFileInitializeFutureState::WriteFileBlocksBatch {
                    cur_file_extent_range_allocation_blocks_begin,
                    cur_file_extent_range_allocation_blocks_end,
                    cur_file_extent_range_write_allocation_blocks_end,
                    write_fut,
                } => {
                    this.encrypted_file_blocks = match chip::NvChipFuture::poll(pin::Pin::new(write_fut), chip, cx) {
                        task::Poll::Ready(Ok((encrypted_file_blocks, Ok(())))) => encrypted_file_blocks,
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                            this.fut_state = AllocBitmapFileInitializeFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    this.next_file_extent_allocation_block_index = *cur_file_extent_range_allocation_blocks_end;
                    if *cur_file_extent_range_write_allocation_blocks_end
                        != *cur_file_extent_range_allocation_blocks_end
                    {
                        // At the end and the last Chip IO block is only partially filled by
                        // Allocation Bitmap File Blocks. Return the remainder for the caller to
                        // handle it alongside other data subsequent to the Allocation Bitmap File.
                        debug_assert_eq!(*cur_file_extent_range_allocation_blocks_end, this.file_extent.end());
                        let file = match this.file.take() {
                            Some(file) => file,
                            None => {
                                this.fut_state = AllocBitmapFileInitializeFutureState::Done;
                                return task::Poll::Ready(Err(nvfs_err_internal!()));
                            }
                        };
                        let auth_tree_initialization_cursor = match this.auth_tree_initialization_cursor.take() {
                            Some(auth_tree_initialization_cursor) => auth_tree_initialization_cursor,
                            None => {
                                this.fut_state = AllocBitmapFileInitializeFutureState::Done;
                                return task::Poll::Ready(Err(nvfs_err_internal!()));
                            }
                        };

                        let remainder_encrypted_file_blocks = match FixedVec::new_from_fn(
                            u64::from(
                                *cur_file_extent_range_allocation_blocks_end
                                    - *cur_file_extent_range_write_allocation_blocks_end,
                            ) as usize,
                            |i| -> Result<FixedVec<u8, 7>, convert::Infallible> {
                                Ok(mem::take(
                                    &mut this.encrypted_file_blocks[u64::from(
                                        *cur_file_extent_range_write_allocation_blocks_end
                                            - *cur_file_extent_range_allocation_blocks_begin,
                                    ) as usize
                                        + i],
                                ))
                            },
                        ) {
                            Ok(remainder_encrypted_file_blocks) => remainder_encrypted_file_blocks,
                            Err(e) => {
                                this.fut_state = AllocBitmapFileInitializeFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(e)));
                            }
                        };

                        this.fut_state = AllocBitmapFileInitializeFutureState::Done;
                        return task::Poll::Ready(Ok((
                            file,
                            remainder_encrypted_file_blocks,
                            auth_tree_initialization_cursor,
                        )));
                    }

                    this.fut_state = AllocBitmapFileInitializeFutureState::PrepareFileBlocksBatch;
                }
                AllocBitmapFileInitializeFutureState::Done => unreachable!(),
            };
        }
    }
}

/// Read allocation bitmap file fragments needed for authentication tree
/// reconstruction during journal replay.
///
/// Read the allocation bitmap fragment's covered by the digest entries in the
/// journal log's
/// [`AllocBitmapFileFragmentsAuthDigests`](journal::log::JournalLogFieldTag::AllocBitmapFileFragmentsAuthDigests`)
/// field, authenticate therethrough, decrypt and finally load them into an
///  [`AllocBitmap`] instance.
///
/// For clarity: the resulting [`AllocBitmap`] instance will be incomplete in
/// that only the regions corresponding to the fragments read contain valid
/// allocation state data, everything else is tracked as unallocated for
/// definiteness.
///
/// The allocation bitmap file fragments' contents are read in the state as if
/// the journal had been replayed already: in particular, any regions affected
/// by some entry in the
/// [`JournalApplyWritesScript`](journal::apply_script::JournalApplyWritesScript)
/// are read from the respective journal staging copy.
pub struct AllocBitmapFileReadJournalFragmentsFuture<C: chip::NvChip> {
    fut_state: AllocBitmapFileReadJournalFragmentsFutureState<C>,
    fragments_auth_digests: ExtentsCoveringAuthDigests,
    /// Indices into file_extents, sorted by the extents' relative order.
    ordered_file_extents: Vec<usize>,
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self.
    bitmap: Option<AllocBitmap>,
    file_block_decryption_instance: encryption_entities::EncryptedBlockDecryptionInstance,
    file_block_decryption_buf: FixedVec<u8, 0>,
    read_buffers: FixedVec<FixedVec<u8, 7>, 0>,
    fragments_auth_digests_index: usize,
    ordered_file_extents_index: usize,
    apply_writes_script_index: usize,
    preferred_chip_io_bulk_allocation_blocks_log2: u8,
    read_buffers_total_allocation_blocks_log2: u8,
}

/// Internal [`AllocBitmapFileReadJournalFragmentsFuture::poll()`] state-machine
/// state.
enum AllocBitmapFileReadJournalFragmentsFutureState<C: chip::NvChip> {
    PrepareReadRegion {
        fragments_auth_digests_index: usize,
        offset_allocation_blocks_in_fragment_auth_tree_data_block: layout::AllocBlockCount,
    },
    ReadRegion {
        read_fut: C::ReadFuture<AllocBitmapFileReadJournalFragmentsNvChipReadRequest>,
        read_region_src_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        read_region_first_fragments_auth_digests_index: usize,
        fragments_auth_digests_index: usize,
        offset_allocation_blocks_in_fragment_auth_tree_data_block: layout::AllocBlockCount,
        from_journal: bool,
    },
    Process {
        fragments_auth_digests_index: usize,
    },
    Done,
}

impl<C: chip::NvChip> AllocBitmapFileReadJournalFragmentsFuture<C> {
    /// Instantiate a [`AllocBitmapFileReadJournalFragmentsFuture`].
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `fragments_auth_digests` - The fragment's authentication digests, as
    ///   [decoded](ExtentsCoveringAuthDigests::decode) from the
    ///   [`AllocBitmapFileFragmentsAuthDigests`](journal::log::JournalLogFieldTag::AllocBitmapFileFragmentsAuthDigests`)
    ///   journal log field. The `fragments_auth_digests` must have been
    ///   authenticated as a whole. Each [Allocation Bitmap File
    ///   Block](layout::ImageLayout::allocation_bitmap_file_block_allocation_blocks_log2)
    ///   overlapping with some region covered by an entry in the list must be
    ///   covered in full.
    /// * `file` - The [`AllocBitmapFile`] to read fragments from.
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `root_key` - The filesystem's root key.
    /// * `keys_cache` - A [KeyCache](keys::KeyCache) instance associated with
    ///   the `root_key`.
    pub fn new<ST: sync_types::SyncTypes>(
        chip: &C,
        fragments_auth_digests: ExtentsCoveringAuthDigests,
        file: &AllocBitmapFile,
        image_layout: &layout::ImageLayout,
        root_key: &keys::RootKey,
        keys_cache: &mut keys::KeyCacheRef<'_, ST>,
    ) -> Result<Self, NvFsError> {
        let mut ordered_file_extents = Vec::new();
        ordered_file_extents.try_reserve_exact(file.extents.len())?;
        ordered_file_extents.extend(0..file.extents.len());
        ordered_file_extents.sort_by(|i, j| {
            // The extents are non-overlapping and non-empty.
            file.extents
                .get_extent(*i)
                .physical_range()
                .begin()
                .cmp(&file.extents.get_extent(*j).physical_range().begin())
        });

        let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
        let auth_tree_data_block_allocation_blocks_log2 =
            image_layout.auth_tree_data_block_allocation_blocks_log2 as u32;
        let file_block_allocation_blocks_log2 = image_layout.allocation_bitmap_file_block_allocation_blocks_log2 as u32;
        let file_block_auth_tree_data_blocks_log2 =
            file_block_allocation_blocks_log2.saturating_sub(auth_tree_data_block_allocation_blocks_log2);
        let fragment_allocation_blocks_log2 =
            file_block_auth_tree_data_blocks_log2 + auth_tree_data_block_allocation_blocks_log2;
        debug_assert_eq!(
            fragment_allocation_blocks_log2,
            file_block_allocation_blocks_log2.max(auth_tree_data_block_allocation_blocks_log2)
        );
        let fragment_file_blocks_log2 = fragment_allocation_blocks_log2 - file_block_allocation_blocks_log2;
        let mut ordered_file_extents_index = 0;
        let mut fragments_auth_digests_index = 0;
        let mut max_covered_file_block_index = 0u64;
        while fragments_auth_digests_index < fragments_auth_digests.len() {
            // Advance to the first extent not before the current fragments_auth_digests
            // entry's associated position.
            let cur_fragments_auth_digests_entry_allocation_blocks_begin =
                fragments_auth_digests[fragments_auth_digests_index].0;
            while ordered_file_extents_index < ordered_file_extents.len()
                && file
                    .extents
                    .get_extent(ordered_file_extents[ordered_file_extents_index])
                    .physical_range()
                    .end()
                    <= cur_fragments_auth_digests_entry_allocation_blocks_begin
            {
                ordered_file_extents_index += 1;
            }
            if ordered_file_extents_index == ordered_file_extents.len() {
                // No overlap with any Allocation Bitmap file extent.
                return Err(NvFsError::from(
                    CocoonFsFormatError::UnexpectedJournalExtentsCoveringAuthDigestsEntry,
                ));
            }
            let cur_extent = file
                .extents
                .get_extent(ordered_file_extents[ordered_file_extents_index]);
            let cur_physical_extent = cur_extent.physical_range();
            if cur_physical_extent.begin() > cur_fragments_auth_digests_entry_allocation_blocks_begin
                || !u64::from(cur_fragments_auth_digests_entry_allocation_blocks_begin - cur_physical_extent.begin())
                    .is_aligned_pow2(file_block_allocation_blocks_log2)
            {
                // No overlap with any Allocation Bitmap file extent or the fragment does not
                // align with a Allocation Bitmap File Block's beginning.
                return Err(NvFsError::from(
                    CocoonFsFormatError::UnexpectedJournalExtentsCoveringAuthDigestsEntry,
                ));
            }
            if (fragments_auth_digests.len() - fragments_auth_digests_index) >> file_block_auth_tree_data_blocks_log2
                == 0
                || u64::from(
                    fragments_auth_digests
                        [fragments_auth_digests_index + (1 << file_block_auth_tree_data_blocks_log2) - 1]
                        .0
                        - cur_fragments_auth_digests_entry_allocation_blocks_begin,
                ) >> auth_tree_data_block_allocation_blocks_log2
                    != (1 << file_block_auth_tree_data_blocks_log2) - 1
            {
                // The current Allocation Bitmap File Block is not fully covered.
                return Err(NvFsError::from(
                    CocoonFsFormatError::UnexpectedJournalExtentsCoveringAuthDigestsEntry,
                ));
            }

            max_covered_file_block_index = (u64::from(
                cur_extent.logical_range().begin()
                    + (cur_fragments_auth_digests_entry_allocation_blocks_begin - cur_physical_extent.begin()),
            ) >> file_block_allocation_blocks_log2)
                + ((1u64 << fragment_file_blocks_log2) - 1);

            fragments_auth_digests_index += 1 << file_block_auth_tree_data_blocks_log2;
        }
        // The size does not overflow, as per the checks in AllocBitmapFile::new().
        let bitmap = try_alloc_vec(((max_covered_file_block_index + 1) * file.bitmap_words_per_file_block) as usize)?;
        let bitmap = AllocBitmap { bitmap };

        let file_block_encryption_layout = encryption_entities::EncryptedBlockLayout::new(
            image_layout.block_cipher_alg,
            image_layout.allocation_bitmap_file_block_allocation_blocks_log2,
            image_layout.allocation_block_size_128b_log2,
        )?;
        let file_block_encryption_key = keys::KeyCache::get_key(
            keys_cache,
            root_key,
            &keys::KeyId::new(
                inode_index::SpecialInode::AllocBitmap as u32,
                inode_index::InodeKeySubdomain::InodeData as u32,
                keys::KeyPurpose::Encryption,
            ),
        )?;
        let file_block_decryption_instance = encryption_entities::EncryptedBlockDecryptionInstance::new(
            file_block_encryption_layout,
            symcipher::SymBlockCipherModeDecryptionInstance::new(
                tpm2_interface::TpmiAlgCipherMode::Cbc,
                &image_layout.block_cipher_alg,
                &file_block_encryption_key,
            )?,
        )?;
        drop(file_block_encryption_key);

        // Does not overflow, c.f. AllocBitmapFile::new().
        let file_block_decrypted_len: usize =
            (file.bitmap_words_per_file_block as usize) * mem::size_of::<BitmapWord>();
        let file_block_decryption_buf = FixedVec::new_with_default(file_block_decrypted_len)?;

        // Unit of authentication + decryption, a "fragment", is the larger of the
        // Allocation Bitmap File Block and Authentication Tree Data Block size:
        // if one Allocation Bitmap File Block comprises multiple Authentication
        // Tree Data Blocks, the individual Authentication Tree Data Blocks all
        // need to get authenticated before the Allocation Bitmap File Blocks
        // can get decrypted and otherwise, if one Authentication
        // Tree Data Block comprise multiple Allocation Bitmap File Blocks, the
        // former needs to get authenticated before decrypting all the latter.
        let fragment_allocation_blocks_log2 =
            file_block_auth_tree_data_blocks_log2 + auth_tree_data_block_allocation_blocks_log2;
        debug_assert_eq!(
            fragment_allocation_blocks_log2,
            file_block_allocation_blocks_log2.max(auth_tree_data_block_allocation_blocks_log2)
        );

        let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();
        // Preferred Chip IO read size. Ramp it up to a reasonable value still
        // compatible with the Allocation Bitmap File's extents' guaranteed
        // alignment, i.e. to an Authentication Tree Data Block.
        let preferred_chip_io_bulk_allocation_blocks_log2 =
            (chip.preferred_chip_io_blocks_bulk_log2() + chip_io_block_size_128b_log2)
                .saturating_sub(allocation_block_size_128b_log2)
                .min(usize::BITS - 1)
                .max(auth_tree_data_block_allocation_blocks_log2) as u8;
        // The read buffers should be able to hold the larger of the preferred Chip IO
        // block size and the fragment size.
        let read_buffers_total_allocation_blocks_log2 = (preferred_chip_io_bulk_allocation_blocks_log2 as u32)
            .max(fragment_allocation_blocks_log2)
            .min(usize::BITS - 1) as u8;

        let mut read_buffers = FixedVec::new_with_default(
            1usize << (read_buffers_total_allocation_blocks_log2 as u32 - fragment_allocation_blocks_log2),
        )?;
        for read_buffer in read_buffers.iter_mut() {
            // Does not overflow the usize, c.f. AllocBitmapFile::new().
            *read_buffer = FixedVec::new_with_default(
                1usize << (fragment_allocation_blocks_log2 + allocation_block_size_128b_log2 + 7),
            )?;
        }

        Ok(Self {
            fut_state: AllocBitmapFileReadJournalFragmentsFutureState::PrepareReadRegion {
                fragments_auth_digests_index: 0,
                offset_allocation_blocks_in_fragment_auth_tree_data_block: layout::AllocBlockCount::from(0u64),
            },
            fragments_auth_digests,
            ordered_file_extents,
            bitmap: Some(bitmap),
            file_block_decryption_instance,
            file_block_decryption_buf,
            read_buffers,
            fragments_auth_digests_index: 0,
            ordered_file_extents_index: 0,
            apply_writes_script_index: 0,
            preferred_chip_io_bulk_allocation_blocks_log2,
            read_buffers_total_allocation_blocks_log2,
        })
    }

    /// Poll the [`AllocBitmapFileReadFuture`] instance to completion.
    ///
    /// The future polling semantics are that of standard Rust
    /// [`Future::poll()`](core::future::Future::poll), but `poll()` takes some
    /// additional arguments in order to alleviate the need to store
    /// (lifetime managed) references in `Self` itself.
    ///
    /// On successful completion, an [`AllocBitmap`] with the read allocation
    /// bitmap file fragments loaded is returned. Regions not corresponding
    /// to any such fragment are tracked as unallocated for definiteness.
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `file` - The [`AllocBitmapFile`] to read fragments from.
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `auth_tree_config` - The filesystem's
    ///   [`AuthTreeConfig`](auth_tree::AuthTreeConfig).
    /// * `image_header_end` - [End of the filesystem image header on
    ///   storage](crate::fs::cocoonfs::image_header::MutableImageHeader::physical_location).
    /// * `apply_writes_script` - The decoded contents of the journal log's
    ///   [`ApplyWritesScript`](journal::log::JournalLogFieldTag::ApplyWritesScript)
    ///   field.
    /// * `journal_staging_copy_undisguise` -
    ///   [`JournalStagingCopyUndisguise`](journal::staging_copy_disguise::JournalStagingCopyUndisguise)
    ///   instance created from the contents of the journal log's
    ///   [`JournalStagingCopyDisguise`](journal::log::JournalLogFieldTag::JournalStagingCopyDisguise)
    ///   field, if present.
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    #[allow(clippy::too_many_arguments)]
    pub fn poll(
        self: pin::Pin<&mut Self>,
        chip: &C,
        file: &AllocBitmapFile,
        image_layout: &layout::ImageLayout,
        auth_tree_config: &auth_tree::AuthTreeConfig,
        image_header_end: layout::PhysicalAllocBlockIndex,
        apply_writes_script: &journal::apply_script::JournalApplyWritesScript,
        journal_staging_copy_undisguise: Option<&journal::staging_copy_disguise::JournalStagingCopyUndisguise>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<AllocBitmap, NvFsError>> {
        let this = pin::Pin::into_inner(self);
        loop {
            match &mut this.fut_state {
                AllocBitmapFileReadJournalFragmentsFutureState::PrepareReadRegion {
                    fragments_auth_digests_index,
                    offset_allocation_blocks_in_fragment_auth_tree_data_block,
                } => {
                    if this.fragments_auth_digests_index == this.fragments_auth_digests.len() {
                        // Done.
                        this.fut_state = AllocBitmapFileReadJournalFragmentsFutureState::Done;
                        let bitmap = match this.bitmap.take() {
                            Some(bitmap) => bitmap,
                            None => {
                                return task::Poll::Ready(Err(nvfs_err_internal!()));
                            }
                        };
                        return task::Poll::Ready(Ok(bitmap));
                    } else if *fragments_auth_digests_index == this.fragments_auth_digests.len() {
                        // All read up to the end, process.
                        this.fut_state = AllocBitmapFileReadJournalFragmentsFutureState::Process {
                            fragments_auth_digests_index: *fragments_auth_digests_index,
                        };
                        continue;
                    }

                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                    let auth_tree_data_block_allocation_blocks_log2 =
                        image_layout.auth_tree_data_block_allocation_blocks_log2 as u32;
                    let file_block_allocation_blocks_log2 =
                        image_layout.allocation_bitmap_file_block_allocation_blocks_log2 as u32;
                    // C.f. Self::new().
                    let file_block_auth_tree_data_blocks_log2 =
                        file_block_allocation_blocks_log2.saturating_sub(auth_tree_data_block_allocation_blocks_log2);
                    let fragment_allocation_blocks_log2 =
                        file_block_auth_tree_data_blocks_log2 + auth_tree_data_block_allocation_blocks_log2;
                    let chip_io_block_allocation_blocks_log2 = chip
                        .chip_io_block_size_128b_log2()
                        .saturating_sub(allocation_block_size_128b_log2);
                    let preferred_chip_io_bulk_allocation_blocks_log2 =
                        this.preferred_chip_io_bulk_allocation_blocks_log2 as u32;
                    let read_buffers_total_allocation_blocks_log2 =
                        this.read_buffers_total_allocation_blocks_log2 as u32;

                    let read_region_first_fragments_auth_digests_index = *fragments_auth_digests_index;
                    let read_region_first_fragments_auth_digests_entry_allocation_blocks_begin =
                        this.fragments_auth_digests[*fragments_auth_digests_index].0;
                    let cur_read_region_allocation_blocks_begin =
                        read_region_first_fragments_auth_digests_entry_allocation_blocks_begin
                            + *offset_allocation_blocks_in_fragment_auth_tree_data_block;
                    if *fragments_auth_digests_index == this.fragments_auth_digests_index
                        && u64::from(*offset_allocation_blocks_in_fragment_auth_tree_data_block) == 0
                    {
                        // Start of new region to process in a batch.
                        // Advance to the extent overlapping with the current fragment's position. As
                        // per Self::new() there is one.
                        while file
                            .extents
                            .get_extent(this.ordered_file_extents[this.ordered_file_extents_index])
                            .physical_range()
                            .end()
                            <= read_region_first_fragments_auth_digests_entry_allocation_blocks_begin
                        {
                            this.ordered_file_extents_index += 1;
                        }

                        // Move the apply script entry to the next entry at or after the current
                        // position by lookup.
                        if this.apply_writes_script_index < apply_writes_script.len()
                            && apply_writes_script[this.apply_writes_script_index]
                                .get_target_range()
                                .end()
                                <= read_region_first_fragments_auth_digests_entry_allocation_blocks_begin
                        {
                            this.apply_writes_script_index = match apply_writes_script
                                .lookup(read_region_first_fragments_auth_digests_entry_allocation_blocks_begin)
                            {
                                Ok(apply_writes_script_index) => apply_writes_script_index,
                                Err(apply_writes_script_index) => apply_writes_script_index,
                            }
                        }
                    } else {
                        // If at the end of the current Allocation Bitmap File extent or about to
                        // exceed the read buffer capacity, stop and process what's been read so
                        // far.
                        if cur_read_region_allocation_blocks_begin
                            >= file
                                .extents
                                .get_extent(this.ordered_file_extents[this.ordered_file_extents_index])
                                .physical_range()
                                .end()
                            || u64::from(
                                cur_read_region_allocation_blocks_begin
                                    - this.fragments_auth_digests[this.fragments_auth_digests_index].0,
                            ) >> (this.read_buffers_total_allocation_blocks_log2 as u32)
                                != 0
                        {
                            debug_assert_eq!(u64::from(*offset_allocation_blocks_in_fragment_auth_tree_data_block), 0);
                            debug_assert!(
                                u64::from(cur_read_region_allocation_blocks_begin)
                                    .is_aligned_pow2(fragment_allocation_blocks_log2)
                            );
                            this.fut_state = AllocBitmapFileReadJournalFragmentsFutureState::Process {
                                fragments_auth_digests_index: *fragments_auth_digests_index,
                            };
                            continue;
                        }

                        // Move the apply script entry to the next entry at or after the current
                        // position by linear search.
                        while this.apply_writes_script_index < apply_writes_script.len()
                            && apply_writes_script[this.apply_writes_script_index]
                                .get_target_range()
                                .end()
                                <= cur_read_region_allocation_blocks_begin
                        {
                            this.apply_writes_script_index += 1;
                        }
                    };

                    let cur_file_extent = file
                        .extents
                        .get_extent(this.ordered_file_extents[this.ordered_file_extents_index])
                        .physical_range();
                    debug_assert!(
                        (u64::from(cur_file_extent.begin()) | u64::from(cur_file_extent.end()))
                            .is_aligned_pow2(auth_tree_data_block_allocation_blocks_log2)
                    );
                    debug_assert!(
                        u64::from(cur_file_extent.block_count()).is_aligned_pow2(file_block_allocation_blocks_log2)
                    );

                    let mut cur_read_region_allocation_blocks_end = cur_read_region_allocation_blocks_begin;
                    // Attempt to complete the larger of the current fragment in a single loop
                    // iteration. The authentication digests for that range are all guaranteed to
                    // exist, c.f. Self::new(). Inititalize for the first iteration.
                    let mut max_cur_read_region_end_step_allocation_blocks = (1u64 << fragment_allocation_blocks_log2)
                        - (u64::from(cur_read_region_allocation_blocks_end - cur_file_extent.begin())
                            & u64::trailing_bits_mask(fragment_allocation_blocks_log2));
                    // Distance to the next preferred Chip IO boundary or Journal Apply script
                    // discontinuity, whichever comes first.
                    let mut cur_read_region_max_end_distance_allocation_blocks = (1u64
                        << preferred_chip_io_bulk_allocation_blocks_log2)
                        - (u64::from(cur_read_region_allocation_blocks_end)
                            & u64::trailing_bits_mask(preferred_chip_io_bulk_allocation_blocks_log2));
                    if this.apply_writes_script_index < apply_writes_script.len() {
                        let next_apply_writes_script_entry = &apply_writes_script[this.apply_writes_script_index];
                        let next_apply_writes_script_discontinuity_allocation_block_index =
                            if cur_read_region_allocation_blocks_begin
                                < next_apply_writes_script_entry.get_target_range().begin()
                            {
                                next_apply_writes_script_entry.get_target_range().begin()
                            } else {
                                next_apply_writes_script_entry.get_target_range().end()
                            };
                        // Journal apply script entries' associated boundaries are always
                        // aligned to the IO Block size, hence also to the Chip IO Block size.
                        debug_assert!(
                            u64::from(next_apply_writes_script_discontinuity_allocation_block_index)
                                .is_aligned_pow2(chip_io_block_allocation_blocks_log2)
                        );
                        cur_read_region_max_end_distance_allocation_blocks =
                            cur_read_region_max_end_distance_allocation_blocks.min(u64::from(
                                next_apply_writes_script_discontinuity_allocation_block_index
                                    - cur_read_region_allocation_blocks_end,
                            ));
                    }
                    loop {
                        // Limit the read region to not exceed past the next preferred Chip IO boundary
                        // or Journal Apply script discontinuity.
                        debug_assert!(
                            u64::from(*offset_allocation_blocks_in_fragment_auth_tree_data_block)
                                .is_aligned_pow2(chip_io_block_allocation_blocks_log2)
                        );
                        debug_assert!(
                            chip_io_block_allocation_blocks_log2 < auth_tree_data_block_allocation_blocks_log2
                                || u64::from(*offset_allocation_blocks_in_fragment_auth_tree_data_block) == 0
                        );
                        // The preferred Chip IO boundaries are aligned to the larger of
                        // a Chip IO block and an Authentication Tree Data Block's size, c.f.
                        // Self::new().
                        debug_assert!(
                            preferred_chip_io_bulk_allocation_blocks_log2
                                >= chip_io_block_allocation_blocks_log2
                                    .max(auth_tree_data_block_allocation_blocks_log2)
                        );
                        if cur_read_region_max_end_distance_allocation_blocks
                            < max_cur_read_region_end_step_allocation_blocks
                        {
                            let cur_auth_tree_data_block_remaining_unread_allocation_blocks = (1u64
                                << auth_tree_data_block_allocation_blocks_log2)
                                - (u64::from(cur_read_region_allocation_blocks_end)
                                    & u64::trailing_bits_mask(auth_tree_data_block_allocation_blocks_log2));
                            cur_read_region_allocation_blocks_end +=
                                layout::AllocBlockCount::from(cur_read_region_max_end_distance_allocation_blocks);
                            if cur_read_region_max_end_distance_allocation_blocks
                                < cur_auth_tree_data_block_remaining_unread_allocation_blocks
                            {
                                *offset_allocation_blocks_in_fragment_auth_tree_data_block =
                                    *offset_allocation_blocks_in_fragment_auth_tree_data_block
                                        + layout::AllocBlockCount::from(
                                            cur_read_region_max_end_distance_allocation_blocks,
                                        );
                            } else {
                                cur_read_region_max_end_distance_allocation_blocks -=
                                    cur_auth_tree_data_block_remaining_unread_allocation_blocks;
                                *fragments_auth_digests_index += 1;

                                let cur_read_region_end_step_auth_tree_data_blocks =
                                    cur_read_region_max_end_distance_allocation_blocks
                                        >> auth_tree_data_block_allocation_blocks_log2;
                                cur_read_region_max_end_distance_allocation_blocks -=
                                    cur_read_region_end_step_auth_tree_data_blocks
                                        << auth_tree_data_block_allocation_blocks_log2;
                                *fragments_auth_digests_index +=
                                    cur_read_region_end_step_auth_tree_data_blocks as usize;
                                *offset_allocation_blocks_in_fragment_auth_tree_data_block =
                                    layout::AllocBlockCount::from(cur_read_region_max_end_distance_allocation_blocks);
                            }

                            // The invariants still hold.
                            debug_assert!(
                                u64::from(*offset_allocation_blocks_in_fragment_auth_tree_data_block)
                                    .is_aligned_pow2(chip_io_block_allocation_blocks_log2)
                            );
                            debug_assert!(
                                chip_io_block_allocation_blocks_log2 < auth_tree_data_block_allocation_blocks_log2
                                    || u64::from(*offset_allocation_blocks_in_fragment_auth_tree_data_block) == 0
                            );

                            break;
                        }

                        // Advancing to the end of the current fragment is possible.
                        // max_cur_read_region_end_step_allocation_blocks equals exactly that
                        // distance.
                        cur_read_region_allocation_blocks_end +=
                            layout::AllocBlockCount::from(max_cur_read_region_end_step_allocation_blocks);
                        let cur_read_region_end_step_auth_tree_data_blocks =
                            max_cur_read_region_end_step_allocation_blocks
                                >> auth_tree_data_block_allocation_blocks_log2;
                        *fragments_auth_digests_index += cur_read_region_end_step_auth_tree_data_blocks as usize;
                        if cur_read_region_end_step_auth_tree_data_blocks << auth_tree_data_block_allocation_blocks_log2
                            != max_cur_read_region_end_step_allocation_blocks
                        {
                            // The current read region's first overlapping Authentication Tree Data
                            // Block had been filled partially by a previous read and its remainder
                            // has now been filled up.
                            debug_assert_ne!(u64::from(*offset_allocation_blocks_in_fragment_auth_tree_data_block), 0);
                            *fragments_auth_digests_index += 1;
                        }
                        *offset_allocation_blocks_in_fragment_auth_tree_data_block = layout::AllocBlockCount::from(0);

                        cur_read_region_max_end_distance_allocation_blocks -=
                            max_cur_read_region_end_step_allocation_blocks;
                        max_cur_read_region_end_step_allocation_blocks = 1u64 << fragment_allocation_blocks_log2;

                        if *fragments_auth_digests_index >= this.fragments_auth_digests.len() {
                            break;
                        }

                        let cur_fragment_allocation_blocks_begin =
                            this.fragments_auth_digests[*fragments_auth_digests_index].0;
                        debug_assert!(
                            u64::from(cur_fragment_allocation_blocks_begin - cur_file_extent.begin(),)
                                .is_aligned_pow2(fragment_allocation_blocks_log2)
                        );

                        // If crossing a preferred Chip IO boundary, stop and read what's been found
                        // so far.
                        if (u64::from(cur_fragment_allocation_blocks_begin)
                            ^ u64::from(cur_read_region_allocation_blocks_begin))
                            >> preferred_chip_io_bulk_allocation_blocks_log2
                            != 0
                        {
                            break;
                        }

                        // If about to move past the current Allocation Bitmap File extent, stop and
                        // read (and subsequently process) what's been found so
                        // far.
                        if cur_fragment_allocation_blocks_begin >= cur_file_extent.end() {
                            break;
                        }

                        // If about to exceed the read buffer capacity, stop and read (and subsequently
                        // process) what's been found so far.
                        if u64::from(
                            cur_fragment_allocation_blocks_begin
                                - this.fragments_auth_digests[this.fragments_auth_digests_index].0,
                        ) >> read_buffers_total_allocation_blocks_log2
                            != 0
                        {
                            break;
                        }

                        // If there's a Chip IO block sized gap, stop and read what's been found so
                        // far.
                        if (u64::from(cur_fragment_allocation_blocks_begin)
                            - (u64::from(cur_read_region_allocation_blocks_end) - 1)
                                .round_down_pow2(chip_io_block_allocation_blocks_log2))
                            >> chip_io_block_allocation_blocks_log2
                            > 1
                        {
                            break;
                        }
                    }

                    debug_assert_ne!(
                        cur_read_region_allocation_blocks_begin,
                        cur_read_region_allocation_blocks_end
                    );
                    debug_assert!(
                        u64::from(
                            cur_read_region_allocation_blocks_end
                                - this.fragments_auth_digests[this.fragments_auth_digests_index].0
                        ) <= 1u64 << read_buffers_total_allocation_blocks_log2
                    );
                    debug_assert!(
                        u64::from(cur_read_region_allocation_blocks_end - cur_read_region_allocation_blocks_begin)
                            <= 1u64 << preferred_chip_io_bulk_allocation_blocks_log2
                    );

                    // Read the found region.
                    // First translate to the journal staging copy area, if any.
                    let (
                        cur_read_region_src_allocation_blocks_begin,
                        cur_read_region_src_allocation_blocks_end,
                        from_journal,
                    ) = if this.apply_writes_script_index < apply_writes_script.len()
                        && apply_writes_script[this.apply_writes_script_index]
                            .get_target_range()
                            .begin()
                            <= cur_read_region_allocation_blocks_begin
                    {
                        let apply_writes_script_entry = &apply_writes_script[this.apply_writes_script_index];
                        let cur_read_region_src_allocation_blocks_begin = apply_writes_script_entry
                            .get_journal_staging_copy_allocation_blocks_begin()
                            + (cur_read_region_allocation_blocks_begin
                                - apply_writes_script_entry.get_target_range().begin());
                        let cur_read_region_src_allocation_blocks_end = apply_writes_script_entry
                            .get_journal_staging_copy_allocation_blocks_begin()
                            + (cur_read_region_allocation_blocks_end
                                - apply_writes_script_entry.get_target_range().begin());
                        (
                            cur_read_region_src_allocation_blocks_begin,
                            cur_read_region_src_allocation_blocks_end,
                            true,
                        )
                    } else {
                        (
                            cur_read_region_allocation_blocks_begin,
                            cur_read_region_allocation_blocks_end,
                            false,
                        )
                    };

                    let aligned_cur_read_region_src = match layout::PhysicalAllocBlockRange::new(
                        cur_read_region_src_allocation_blocks_begin,
                        cur_read_region_src_allocation_blocks_end,
                    )
                    .align(chip_io_block_allocation_blocks_log2)
                    {
                        Some(aligned_cur_read_region_src) => aligned_cur_read_region_src,
                        None => {
                            this.fut_state = AllocBitmapFileReadJournalFragmentsFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::IoError(NvFsIoError::RegionOutOfRange)));
                        }
                    };

                    let aligned_cur_read_region_src_begin_128b =
                        u64::from(aligned_cur_read_region_src.begin()) << allocation_block_size_128b_log2;
                    let aligned_cur_read_region_src_end_128b =
                        u64::from(aligned_cur_read_region_src.end()) << allocation_block_size_128b_log2;
                    if aligned_cur_read_region_src_end_128b >> allocation_block_size_128b_log2
                        != u64::from(aligned_cur_read_region_src.end())
                        || aligned_cur_read_region_src_end_128b > (u64::MAX >> 7)
                    {
                        this.fut_state = AllocBitmapFileReadJournalFragmentsFutureState::Done;
                        return task::Poll::Ready(Err(NvFsError::IoError(NvFsIoError::RegionOutOfRange)));
                    }

                    let read_request_region = match ChunkedIoRegion::new(
                        aligned_cur_read_region_src_begin_128b,
                        aligned_cur_read_region_src_end_128b,
                        allocation_block_size_128b_log2,
                    ) {
                        Ok(read_request_region) => read_request_region,
                        Err(e) => {
                            this.fut_state = AllocBitmapFileReadJournalFragmentsFutureState::Done;
                            return task::Poll::Ready(Err(match e {
                                ChunkedIoRegionError::ChunkSizeOverflow => {
                                    // The Allocation Block size always fits an usize.
                                    nvfs_err_internal!()
                                }
                                ChunkedIoRegionError::InvalidBounds => {
                                    nvfs_err_internal!()
                                }
                                ChunkedIoRegionError::ChunkIndexOverflow => {
                                    // No more that the preferred Chip IO block size is ever read at once and
                                    // that in units of Allocation Blocks has been capped to fit an usize.
                                    nvfs_err_internal!()
                                }
                                ChunkedIoRegionError::RegionUnaligned => nvfs_err_internal!(),
                            }));
                        }
                    };
                    let read_request = AllocBitmapFileReadJournalFragmentsNvChipReadRequest {
                        region: read_request_region,
                        read_buffers_base_target_allocation_block_index: this.fragments_auth_digests
                            [this.fragments_auth_digests_index]
                            .0,
                        read_region_target_allocation_blocks_begin: cur_read_region_allocation_blocks_begin,
                        read_buffers: mem::take(&mut this.read_buffers),
                        read_buffer_allocation_blocks_log2: fragment_allocation_blocks_log2 as u8,
                        allocation_block_size_128b_log2: image_layout.allocation_block_size_128b_log2,
                        chip_io_block_allocation_blocks_log2: chip_io_block_allocation_blocks_log2 as u8,
                    };
                    let read_fut = match chip.read(read_request) {
                        Ok(Ok(read_fut)) => read_fut,
                        Err(e) | Ok(Err((_, e))) => {
                            this.fut_state = AllocBitmapFileReadJournalFragmentsFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    this.fut_state = AllocBitmapFileReadJournalFragmentsFutureState::ReadRegion {
                        read_fut,
                        read_region_src_allocation_blocks_begin: cur_read_region_src_allocation_blocks_begin,
                        read_region_first_fragments_auth_digests_index,
                        fragments_auth_digests_index: *fragments_auth_digests_index,
                        offset_allocation_blocks_in_fragment_auth_tree_data_block:
                            *offset_allocation_blocks_in_fragment_auth_tree_data_block,
                        from_journal,
                    };
                }
                AllocBitmapFileReadJournalFragmentsFutureState::ReadRegion {
                    read_fut,
                    read_region_src_allocation_blocks_begin,
                    read_region_first_fragments_auth_digests_index,
                    fragments_auth_digests_index,
                    offset_allocation_blocks_in_fragment_auth_tree_data_block,
                    from_journal,
                } => {
                    let read_request = match chip::NvChipFuture::poll(pin::Pin::new(read_fut), chip, cx) {
                        task::Poll::Ready(Ok((read_request, Ok(())))) => read_request,
                        task::Poll::Ready(Err(e) | Ok((_, Err(e)))) => {
                            this.fut_state = AllocBitmapFileReadJournalFragmentsFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let AllocBitmapFileReadJournalFragmentsNvChipReadRequest {
                        read_region_target_allocation_blocks_begin,
                        read_buffers,
                        ..
                    } = read_request;
                    this.read_buffers = read_buffers;

                    if let Some(journal_staging_copy_undisguise) =
                        (*from_journal).then_some(()).and(journal_staging_copy_undisguise)
                    {
                        let mut undisguise_processor = match journal_staging_copy_undisguise.instantiate_processor() {
                            Ok(undisguise_processor) => undisguise_processor,
                            Err(e) => {
                                this.fut_state = AllocBitmapFileReadJournalFragmentsFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                        };

                        let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                        let auth_tree_data_block_allocation_blocks_log2 =
                            image_layout.auth_tree_data_block_allocation_blocks_log2 as u32;
                        let file_block_allocation_blocks_log2 =
                            image_layout.allocation_bitmap_file_block_allocation_blocks_log2 as u32;
                        let file_block_auth_tree_data_blocks_log2 = file_block_allocation_blocks_log2
                            .saturating_sub(auth_tree_data_block_allocation_blocks_log2);
                        let fragment_allocation_blocks_log2 =
                            file_block_auth_tree_data_blocks_log2 + auth_tree_data_block_allocation_blocks_log2;

                        let mut cur_fragments_auth_digests_index = *read_region_first_fragments_auth_digests_index;
                        debug_assert!(
                            this.fragments_auth_digests[cur_fragments_auth_digests_index].0
                                <= read_region_target_allocation_blocks_begin
                        );
                        let mut cur_offset_allocation_blocks_in_fragment_auth_tree_data_block =
                            read_region_target_allocation_blocks_begin
                                - this.fragments_auth_digests[cur_fragments_auth_digests_index].0;
                        debug_assert_eq!(
                            u64::from(cur_offset_allocation_blocks_in_fragment_auth_tree_data_block)
                                >> auth_tree_data_block_allocation_blocks_log2,
                            0
                        );
                        debug_assert!(
                            cur_fragments_auth_digests_index < *fragments_auth_digests_index
                                || cur_fragments_auth_digests_index == *fragments_auth_digests_index
                                    && cur_offset_allocation_blocks_in_fragment_auth_tree_data_block
                                        < *offset_allocation_blocks_in_fragment_auth_tree_data_block
                        );
                        loop {
                            let cur_target_allocation_block_index =
                                this.fragments_auth_digests[cur_fragments_auth_digests_index].0
                                    + cur_offset_allocation_blocks_in_fragment_auth_tree_data_block;
                            let cur_journal_staging_copy_allocation_block_index =
                                *read_region_src_allocation_blocks_begin
                                    + (cur_target_allocation_block_index - read_region_target_allocation_blocks_begin);

                            // Does not overflow an usize: the total read_buffers size in units of
                            // Allocation Blocks fits an usize.
                            let allocation_block_index_in_read_buffers = u64::from(
                                cur_target_allocation_block_index
                                    - this.fragments_auth_digests[this.fragments_auth_digests_index].0,
                            ) as usize;

                            let read_buffer_index =
                                allocation_block_index_in_read_buffers >> fragment_allocation_blocks_log2;
                            let allocation_block_in_read_buffer_index = allocation_block_index_in_read_buffers
                                - (read_buffer_index << fragment_allocation_blocks_log2);

                            let allocation_block_buf = &mut this.read_buffers[read_buffer_index]
                                [allocation_block_in_read_buffer_index << (allocation_block_size_128b_log2 + 7)
                                    ..(allocation_block_in_read_buffer_index + 1)
                                        << (allocation_block_size_128b_log2 + 7)];

                            if let Err(e) = undisguise_processor.undisguise_journal_staging_copy_allocation_block(
                                cur_journal_staging_copy_allocation_block_index,
                                cur_target_allocation_block_index,
                                allocation_block_buf,
                            ) {
                                this.fut_state = AllocBitmapFileReadJournalFragmentsFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }

                            cur_offset_allocation_blocks_in_fragment_auth_tree_data_block =
                                cur_offset_allocation_blocks_in_fragment_auth_tree_data_block
                                    + layout::AllocBlockCount::from(1u64);
                            if u64::from(cur_offset_allocation_blocks_in_fragment_auth_tree_data_block)
                                >> auth_tree_data_block_allocation_blocks_log2
                                != 0
                            {
                                cur_offset_allocation_blocks_in_fragment_auth_tree_data_block =
                                    layout::AllocBlockCount::from(0);
                                cur_fragments_auth_digests_index += 1;
                            }
                            if cur_fragments_auth_digests_index == *fragments_auth_digests_index
                                && cur_offset_allocation_blocks_in_fragment_auth_tree_data_block
                                    == *offset_allocation_blocks_in_fragment_auth_tree_data_block
                            {
                                break;
                            }
                        }
                    }

                    this.fut_state = AllocBitmapFileReadJournalFragmentsFutureState::PrepareReadRegion {
                        fragments_auth_digests_index: *fragments_auth_digests_index,
                        offset_allocation_blocks_in_fragment_auth_tree_data_block:
                            *offset_allocation_blocks_in_fragment_auth_tree_data_block,
                    };
                }
                AllocBitmapFileReadJournalFragmentsFutureState::Process {
                    fragments_auth_digests_index,
                } => {
                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                    let auth_tree_data_block_allocation_blocks_log2 =
                        image_layout.auth_tree_data_block_allocation_blocks_log2 as u32;
                    let file_block_allocation_blocks_log2 =
                        image_layout.allocation_bitmap_file_block_allocation_blocks_log2 as u32;
                    let file_block_auth_tree_data_blocks_log2 =
                        file_block_allocation_blocks_log2.saturating_sub(auth_tree_data_block_allocation_blocks_log2);
                    let fragment_allocation_blocks_log2 =
                        file_block_auth_tree_data_blocks_log2 + auth_tree_data_block_allocation_blocks_log2;

                    let read_buffers_base_target_allocation_block_index =
                        this.fragments_auth_digests[this.fragments_auth_digests_index].0;
                    debug_assert!(
                        u64::from(read_buffers_base_target_allocation_block_index)
                            .is_aligned_pow2(fragment_allocation_blocks_log2)
                    );
                    // All of the read_buffers' contents comes from a single physically contiguous
                    // Allocation Bitmap File extent, hence its also contiguous
                    // in the Authentication Tree Data Block index domain.
                    let read_buffers_base_auth_tree_data_block_index = auth_tree_config
                        .translate_physical_to_data_block_index(read_buffers_base_target_allocation_block_index);

                    let cur_file_extent = file
                        .extents
                        .get_extent(this.ordered_file_extents[this.ordered_file_extents_index]);
                    let bitmap = match this.bitmap.as_mut() {
                        Some(bitmap) => bitmap,
                        None => {
                            this.fut_state = AllocBitmapFileReadJournalFragmentsFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    debug_assert!(
                        this.fragments_auth_digests_index
                            .is_aligned_pow2(file_block_auth_tree_data_blocks_log2)
                    );
                    debug_assert!(fragments_auth_digests_index.is_aligned_pow2(file_block_auth_tree_data_blocks_log2));
                    while this.fragments_auth_digests_index != *fragments_auth_digests_index {
                        let cur_fragment_first_fragments_auth_digests_entry =
                            &this.fragments_auth_digests[this.fragments_auth_digests_index];
                        let cur_fragment_allocation_blocks_begin = cur_fragment_first_fragments_auth_digests_entry.0;
                        debug_assert!(
                            u64::from(cur_fragment_allocation_blocks_begin - cur_file_extent.physical_range().begin())
                                .is_aligned_pow2(fragment_allocation_blocks_log2,)
                        );

                        // The usize does not overflow, the read_buffers total size in units of
                        // Allocation Blocks fits an usize, c.f. Self::new().
                        let read_buffers_index = (u64::from(
                            cur_fragment_allocation_blocks_begin - read_buffers_base_target_allocation_block_index,
                        ) >> fragment_allocation_blocks_log2) as usize;
                        let fragment = &this.read_buffers[read_buffers_index];
                        // First authenticate.
                        for cur_auth_tree_data_block_in_fragment_index in
                            0..1usize << file_block_auth_tree_data_blocks_log2
                        {
                            let cur_fragments_auth_digests_entry = &this.fragments_auth_digests
                                [this.fragments_auth_digests_index + cur_auth_tree_data_block_in_fragment_index];
                            // All of a fragment's authentication tree data block's digests are there, c.f.
                            // Self::new().
                            debug_assert_eq!(
                                u64::from(cur_fragments_auth_digests_entry.0 - cur_fragment_allocation_blocks_begin)
                                    >> auth_tree_data_block_allocation_blocks_log2,
                                cur_auth_tree_data_block_in_fragment_index as u64
                            );
                            let cur_auth_tree_data_block_index = read_buffers_base_auth_tree_data_block_index
                                + auth_tree::AuthTreeDataBlockCount::from(
                                    u64::from(
                                        cur_fragments_auth_digests_entry.0
                                            - read_buffers_base_target_allocation_block_index,
                                    ) >> auth_tree_data_block_allocation_blocks_log2,
                                );
                            let cur_auth_tree_data_block = &fragment[cur_auth_tree_data_block_in_fragment_index
                                << (auth_tree_data_block_allocation_blocks_log2 + allocation_block_size_128b_log2 + 7)
                                ..(cur_auth_tree_data_block_in_fragment_index + 1)
                                    << (auth_tree_data_block_allocation_blocks_log2
                                        + allocation_block_size_128b_log2
                                        + 7)];
                            if let Err(e) = auth_tree_config.authenticate_data_block(
                                &cur_fragments_auth_digests_entry.1,
                                cur_auth_tree_data_block_index,
                                cur_auth_tree_data_block
                                    .chunks(1usize << (allocation_block_size_128b_log2 + 7))
                                    .map(|allocation_block| Ok(Some(allocation_block))),
                                image_header_end,
                            ) {
                                this.fut_state = AllocBitmapFileReadJournalFragmentsFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                        }

                        // Decrypt all the fragment's Allocation Bitmap File Blocks and store the result
                        // in the bitmap.
                        let cur_fragment_first_file_block_index_in_file = u64::from(
                            cur_file_extent.logical_range().begin()
                                + (cur_fragment_allocation_blocks_begin - cur_file_extent.physical_range().begin()),
                        ) >> file_block_allocation_blocks_log2;
                        // The total number of Allocation Bitmap words fits an usize, as per the
                        // checks in AllocBitmapFile::new()
                        let mut cur_bitmap_word_index =
                            (cur_fragment_first_file_block_index_in_file * file.bitmap_words_per_file_block) as usize;
                        for cur_file_block_in_fragment_index in
                            0..1usize << (fragment_allocation_blocks_log2 - file_block_allocation_blocks_log2)
                        {
                            let encrypted_file_block = &fragment[cur_file_block_in_fragment_index
                                << (file_block_allocation_blocks_log2 + allocation_block_size_128b_log2 + 7)
                                ..(cur_file_block_in_fragment_index + 1)
                                    << (file_block_allocation_blocks_log2 + allocation_block_size_128b_log2 + 7)];

                            if let Err(e) = this.file_block_decryption_instance.decrypt_one_block(
                                io_slices::SingletonIoSliceMut::new(&mut this.file_block_decryption_buf)
                                    .map_infallible_err(),
                                io_slices::SingletonIoSlice::new(encrypted_file_block).map_infallible_err(),
                            ) {
                                this.fut_state = AllocBitmapFileReadJournalFragmentsFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }

                            for bitmap_word in this.file_block_decryption_buf.chunks(mem::size_of::<BitmapWord>()) {
                                let bitmap_word = match <&[u8; mem::size_of::<BitmapWord>()]>::try_from(bitmap_word) {
                                    Ok(bitmap_word) => BitmapWord::from_le_bytes(*bitmap_word),
                                    Err(_) => {
                                        this.fut_state = AllocBitmapFileReadJournalFragmentsFutureState::Done;
                                        return task::Poll::Ready(Err(nvfs_err_internal!()));
                                    }
                                };
                                bitmap.bitmap[cur_bitmap_word_index] = bitmap_word;
                                cur_bitmap_word_index += 1;
                            }
                        }

                        this.fragments_auth_digests_index += 1usize << file_block_auth_tree_data_blocks_log2;
                    }

                    this.fut_state = AllocBitmapFileReadJournalFragmentsFutureState::PrepareReadRegion {
                        fragments_auth_digests_index: *fragments_auth_digests_index,
                        offset_allocation_blocks_in_fragment_auth_tree_data_block: layout::AllocBlockCount::from(0),
                    };
                }
                AllocBitmapFileReadJournalFragmentsFutureState::Done => unreachable!(),
            }
        }
    }
}

/// [`NvChipReadRequest`](chip::NvChipReadRequest) implementation used
/// internally by  [`AllocBitmapFileReadJournalFragmentsFuture`].
struct AllocBitmapFileReadJournalFragmentsNvChipReadRequest {
    region: ChunkedIoRegion,
    read_buffers_base_target_allocation_block_index: layout::PhysicalAllocBlockIndex,
    read_region_target_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
    read_buffers: FixedVec<FixedVec<u8, 7>, 0>,
    read_buffer_allocation_blocks_log2: u8,
    allocation_block_size_128b_log2: u8,
    chip_io_block_allocation_blocks_log2: u8,
}

impl chip::NvChipReadRequest for AllocBitmapFileReadJournalFragmentsNvChipReadRequest {
    fn region(&self) -> &ChunkedIoRegion {
        &self.region
    }

    fn get_destination_buffer(
        &mut self,
        range: &ChunkedIoRegionChunkRange,
    ) -> Result<Option<&mut [u8]>, chip::NvChipIoError> {
        let (allocation_block_index_in_aligned_region, _) = range.chunk().decompose_to_hierarchic_indices([]);
        let read_region_head_alignment_allocation_blocks = (u64::from(self.read_region_target_allocation_blocks_begin)
            & u64::trailing_bits_mask(self.chip_io_block_allocation_blocks_log2 as u32))
            as usize;
        if allocation_block_index_in_aligned_region < read_region_head_alignment_allocation_blocks {
            return Ok(None);
        }

        let allocation_block_index_in_region =
            allocation_block_index_in_aligned_region - read_region_head_alignment_allocation_blocks;

        // Does not overflow an usize: the total read_buffers size in units of
        // Allocation Blocks fits an usize.
        let region_allocation_blocks_offset_in_read_buffers = u64::from(
            self.read_region_target_allocation_blocks_begin - self.read_buffers_base_target_allocation_block_index,
        ) as usize;
        // Likewise, the shift does not overflow for the same reason.
        if (self.read_buffers.len() << (self.read_buffer_allocation_blocks_log2 as u32))
            - region_allocation_blocks_offset_in_read_buffers
            <= allocation_block_index_in_region
        {
            // Padding for Chip IO block alignment at the tail. Note that the condition does
            // not catch all padding reads, only those beyond the read_buffers,
            // but that's Ok.
            return Ok(None);
        }

        let allocation_block_index_in_read_buffers =
            region_allocation_blocks_offset_in_read_buffers + allocation_block_index_in_region;
        let read_buffer_index =
            allocation_block_index_in_read_buffers >> (self.read_buffer_allocation_blocks_log2 as u32);
        let allocation_block_in_read_buffer_index = allocation_block_index_in_read_buffers
            - (read_buffer_index << (self.read_buffer_allocation_blocks_log2 as u32));

        Ok(Some(
            &mut self.read_buffers[read_buffer_index][allocation_block_in_read_buffer_index
                << (self.allocation_block_size_128b_log2 as u32 + 7)
                ..(allocation_block_in_read_buffer_index + 1) << (self.allocation_block_size_128b_log2 as u32 + 7)]
                [range.range_in_chunk().clone()],
        ))
    }
}
