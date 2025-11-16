// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Functionality related to the journal log.

extern crate alloc;
use alloc::vec::Vec;

use super::{
    apply_script::{self, TransactionJournalApplyWritesScriptIterator, TransactionJournalTrimsScriptIterator},
    extents_covering_auth_digests::ExtentsCoveringAuthDigests,
    staging_copy_disguise::JournalStagingCopyUndisguise,
};
use crate::{
    blkdev::{self, ChunkedIoRegion, ChunkedIoRegionChunkRange, ChunkedIoRegionError},
    crypto::{CryptoError, hash, symcipher},
    fs::{
        NvFsError, NvFsIoError,
        cocoonfs::{
            FormatError, alloc_bitmap,
            auth_subject_ids::AuthSubjectDataSuffix,
            encryption_entities::{
                EncryptedChainedExtentsAssociatedDataAuthSubjectDataSuffix, EncryptedChainedExtentsDecryptionInstance,
                EncryptedChainedExtentsEncryptionInstance, EncryptedChainedExtentsLayout, check_cbc_padding,
            },
            extents,
            fs::CocoonFsConfig,
            image_header, inode_extents_list, inode_index, keys,
            layout::{self, BlockIndex as _},
            leb128,
            transaction::{Transaction, TransactionJournalUpdateAuthDigestsScriptIterator},
        },
    },
    nvfs_err_internal, tpm2_interface,
    utils_async::sync_types,
    utils_common::{
        alloc::try_alloc_zeroizing_vec,
        bitmanip::BitManip as _,
        fixed_vec::FixedVec,
        io_slices::{
            self, IoSlicesIter as _, IoSlicesIterCommon as _, IoSlicesMutIter as _, WalkableIoSlicesIter as _,
        },
        zeroize,
    },
};
use core::{convert, mem, num, pin, task};

/// Enum value of [`JournalLogFieldTag::AuthTreeExtents`].
const JOURNAL_LOG_FIELD_TAG_AUTH_TREE_EXTENTS_VALUE: u8 = 1u8;
/// Enum value of [`JournalLogFieldTag::AllocBitmapFileExtents`].
const JOURNAL_LOG_FIELD_TAG_ALLOC_BITMAP_FILE_EXTENTS_VALUE: u8 = 2u8;
/// Enum value of [`JournalLogFieldTag::AllocBitmapFileFragmentsAuthDigests`].
const JOURNAL_LOG_FIELD_TAG_ALLOC_BITMAP_FILE_FRAGMENTS_AUTH_DIGESTS_VALUE: u8 = 3u8;
/// Enum value of [`JournalLogFieldTag::ApplyWritesScript`].
const JOURNAL_LOG_FIELD_TAG_APPLY_WRITES_SCRIPT_VALUE: u8 = 4u8;
/// Enum value of [`JournalLogFieldTag::UpdateAuthDigestsScript`].
const JOURNAL_LOG_FIELD_TAG_UPDATE_AUTH_DIGESTS_SCRIPT_VALUE: u8 = 5u8;
/// Enum value of [`JournalLogFieldTag::TrimScript`].
const JOURNAL_LOG_FIELD_TAG_TRIM_SCRIPT_VALUE: u8 = 6u8;
/// Enum value of [`JournalLogFieldTag::JournalStagingCopyDisguise`].
const JOURNAL_LOG_FIELD_TAG_JOURNAL_STAGING_COPY_DISGUISE_VALUE: u8 = 7u8;

/// Tags identifying encoded journal log fields.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum JournalLogFieldTag {
    AuthTreeExtents = JOURNAL_LOG_FIELD_TAG_AUTH_TREE_EXTENTS_VALUE,
    AllocBitmapFileExtents = JOURNAL_LOG_FIELD_TAG_ALLOC_BITMAP_FILE_EXTENTS_VALUE,
    AllocBitmapFileFragmentsAuthDigests = JOURNAL_LOG_FIELD_TAG_ALLOC_BITMAP_FILE_FRAGMENTS_AUTH_DIGESTS_VALUE,
    ApplyWritesScript = JOURNAL_LOG_FIELD_TAG_APPLY_WRITES_SCRIPT_VALUE,
    UpdateAuthDigestsScript = JOURNAL_LOG_FIELD_TAG_UPDATE_AUTH_DIGESTS_SCRIPT_VALUE,
    TrimScript = JOURNAL_LOG_FIELD_TAG_TRIM_SCRIPT_VALUE,
    JournalStagingCopyDisguise = JOURNAL_LOG_FIELD_TAG_JOURNAL_STAGING_COPY_DISGUISE_VALUE,
}

/// Determine a [`JournalLogFieldTag`]'s encoded length.
///
/// # Arguments:
///
/// * `tag` - The [`JournalLogFieldTag`] value.
fn encoded_field_tag_len(tag: JournalLogFieldTag) -> usize {
    // The field tag is encoded as an unsigned leb128. However, all currently
    // allocated tag values are < 0x80, meaning the encoding is just the plain
    // value cast to an u8.
    debug_assert!((tag as u32) < 0x80);
    1
}

/// Encode a [`JournalLogFieldTag`].
///
/// Encode `tag` into `dst` and return the remainder of `dst`.
///
/// # Arguments:
///
/// * `dst` - Destination buffer. Must have at least the size as determined by
///   [`encoded_field_tag_len()`].
/// * `tag` - The [`JournalLogFieldTag`] to encode.
fn encode_field_tag(dst: &mut [u8], tag: JournalLogFieldTag) -> &mut [u8] {
    // The field tag is encoded as an unsigned leb128. However, all currently
    // allocated tag values are < 0x80, meaning the encoding is just the plain
    // value cast to an u8.
    debug_assert!((tag as u32) < 0x80);
    dst[0] = tag as u8;
    &mut dst[1..]
}

/// Decode a [`JournalLogFieldTag`].
///
/// If any tag is left in `src`, decode it, advance `src` by the consumed
/// length, and return the decoded tag wrapped in a `Some`. Otherwise, if `src`
/// has been exhausted already, return `None`.
///
/// # Arguments:
///
/// `src` - The source buffer to decode from. Will get advanced by the consumed
/// length.
fn decode_field_tag<'a, SI: io_slices::IoSlicesIter<'a, BackendIteratorError = convert::Infallible>>(
    mut src: SI,
) -> Result<Option<JournalLogFieldTag>, NvFsError> {
    if src.is_empty()? {
        return Ok(None);
    }
    // The field tag is encoded as an unsigned leb128. However, all currently
    // allocated tag values are < 0x80, meaning the encoding is just the plain
    // value cast to an u8.
    let mut tag = [0u8; 1];
    io_slices::SingletonIoSliceMut::new(&mut tag)
        .map_infallible_err()
        .copy_from_iter(&mut src)?;
    let tag = tag[0];
    if tag & 0x80 != 0 {
        return Err(NvFsError::from(FormatError::InvalidJournalLogFieldTagEncoding));
    }
    let tag = match tag {
        JOURNAL_LOG_FIELD_TAG_AUTH_TREE_EXTENTS_VALUE => JournalLogFieldTag::AuthTreeExtents,
        JOURNAL_LOG_FIELD_TAG_ALLOC_BITMAP_FILE_EXTENTS_VALUE => JournalLogFieldTag::AllocBitmapFileExtents,
        JOURNAL_LOG_FIELD_TAG_ALLOC_BITMAP_FILE_FRAGMENTS_AUTH_DIGESTS_VALUE => {
            JournalLogFieldTag::AllocBitmapFileFragmentsAuthDigests
        }
        JOURNAL_LOG_FIELD_TAG_APPLY_WRITES_SCRIPT_VALUE => JournalLogFieldTag::ApplyWritesScript,
        JOURNAL_LOG_FIELD_TAG_UPDATE_AUTH_DIGESTS_SCRIPT_VALUE => JournalLogFieldTag::UpdateAuthDigestsScript,
        JOURNAL_LOG_FIELD_TAG_TRIM_SCRIPT_VALUE => JournalLogFieldTag::TrimScript,
        JOURNAL_LOG_FIELD_TAG_JOURNAL_STAGING_COPY_DISGUISE_VALUE => JournalLogFieldTag::JournalStagingCopyDisguise,
        _ => return Err(NvFsError::from(FormatError::InvalidJournalLogFieldTag)),
    };

    Ok(Some(tag))
}

/// Determine the encoded length of a pair of [`JournalLogFieldTag`] and field
/// payload length.
///
/// # Arguments:
///
/// * `tag` - The [`JournalLogFieldTag`] value.
/// * `value_len` - The field's payload length.
fn encoded_field_tag_and_len_len(tag: JournalLogFieldTag, value_len: usize) -> Result<usize, NvFsError> {
    let encoded_tag_len = encoded_field_tag_len(tag);
    let encoded_len_len = leb128::leb128u_u64_encoded_len(
        u64::try_from(value_len).map_err(|_| NvFsError::from(FormatError::JournalLogFieldLengthOverflow))?,
    );
    Ok(encoded_tag_len + encoded_len_len)
}

/// Encode a pair of [`JournalLogFieldTag`] and field payload length.
///
/// Encode the pair of `tag` and `value_len` into `dst` and return the remainder
/// of `dst`.
///
/// # Arguments:
///
/// * `dst` - Destination buffer. Must have at least the size as determined by
///   [`encoded_field_tag_and_len_len()`].
/// * `tag` - The [`JournalLogFieldTag`] value to encode.
/// * `value_len` - The field's payload length to encode.
fn encode_field_tag_and_len(
    mut dst: &mut [u8],
    tag: JournalLogFieldTag,
    value_len: usize,
) -> Result<&mut [u8], NvFsError> {
    let value_len =
        u64::try_from(value_len).map_err(|_| NvFsError::from(FormatError::JournalLogFieldLengthOverflow))?;
    dst = encode_field_tag(dst, tag);
    dst = leb128::leb128u_u64_encode(dst, value_len);
    Ok(dst)
}

/// Decode a pair of [`JournalLogFieldTag`] and field payload length.
///
/// If any bytes are left in `src`, decode a pair of tag and length, advance
/// `src` by the consumed length, and return the decoded pair wrapped in a
/// `Some`. Otherwise, if `src` has been exhausted already, return `None`.
///
/// # Arguments:
///
/// * `src` - The source buffer to decode from. Will get advanced by the
///   consumed length.
fn decode_field_tag_and_len<'a, SI: io_slices::PeekableIoSlicesIter<'a, BackendIteratorError = convert::Infallible>>(
    mut src: SI,
) -> Result<Option<(JournalLogFieldTag, usize)>, NvFsError> {
    let tag = decode_field_tag(&mut src)?;
    let tag = match tag {
        Some(tag) => tag,
        None => return Ok(None),
    };

    // Decode the length field.
    // One leb128-encoded 64 bit integer, signed or unsigned, is at most 10 bytes
    // long.
    let mut decode_buf: [u8; 10] = [0u8; 10];
    let decode_buf_len = decode_buf.len();
    // Attempt to fill up the whole decode_buf by peeking on src.
    let mut decode_buf_io_slice = io_slices::SingletonIoSliceMut::new(&mut decode_buf);
    (&mut decode_buf_io_slice)
        .map_infallible_err()
        .copy_from_iter(&mut src.decoupled_borrow())?;
    let decode_buf_len = decode_buf_len - decode_buf_io_slice.total_len()?;
    let decode_buf = &decode_buf[..decode_buf_len];

    let (value_len, decode_buf_remainder) = leb128::leb128u_u64_decode(decode_buf)
        .map_err(|_| NvFsError::from(FormatError::InvalidJournalLogFieldLengthEncoding))?;
    // Advance the peeked src iterator past the encoded length value.
    src.skip(decode_buf.len() - decode_buf_remainder.len())
        .map_err(|e| match e {
            io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
            io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
            },
        })?;

    let value_len = usize::try_from(value_len).map_err(|_| NvFsError::DimensionsNotSupported)?;

    Ok(Some((tag, value_len)))
}

/// [`JournalLog`] encoding buffer layout.
///
/// Before a [`JournalLog`] can get [encoded](JournalLog::encode), buffers of a
/// suitable total size must get allocated. `JournalLogEncodeBufferLayout`
/// provides a means to determine that total size, and to cache some
/// intermediate encoding buffer layout results for reuse when doing the
/// actual encoding later on.
#[derive(Clone)]
pub struct JournalLogEncodeBufferLayout {
    encoded_auth_tree_extents_value_len: usize,
    encoded_alloc_bitmap_file_extents_value_len: usize,
    encoded_alloc_bitmap_file_fragments_auth_digests_value_len: usize,
    encoded_apply_writes_script_value_len: usize,
    encoded_update_auth_digests_script_value_len: usize,
    encoded_trim_script_value_len: Option<num::NonZeroUsize>,
    encoded_journal_staging_copy_disguise_value_len: Option<num::NonZeroUsize>,
    encoded_total_len: usize,
}

impl JournalLogEncodeBufferLayout {
    /// Instantiate a [`JournalLogEncodeBufferLayout`].
    ///
    /// # Arguments:
    ///
    /// * `fs_config` - The filesystem instance's [`CocoonFsConfig`].
    /// * `fs_sync_state_alloc_bitmap` - The [filesystem instance's allocation
    ///   bitmap](crate::fs::cocoonfs::fs::CocoonFsSyncState::alloc_bitmap).
    /// * `transaction` - The [`Transaction`] to commit to the journal.
    /// * `auth_tree_extents` - The [authentication tree's
    ///   extents](crate::fs::cocoonfs::auth_tree::AuthTreeConfig::get_auth_tree_extents).
    /// * `alloc_bitmap_file_extents` - The [allocation bitmap file's
    ///   extents](alloc_bitmap::AllocBitmapFile::get_extents).
    /// * `encoded_alloc_bitmap_file_fragments_auth_digests_len` - [Encoded
    ///   length of the
    ///   `ExtentsCoveringAuthDigests`](ExtentsCoveringAuthDigests::encoded_len)
    ///   for the [allocation bitmap file fragments needed for authentication
    ///   tree reconstruction during journal
    ///   replay](super::auth_tree_updates::collect_alloc_bitmap_blocks_for_auth_tree_reconstruction).
    pub fn new(
        fs_config: &CocoonFsConfig,
        fs_sync_state_alloc_bitmap: &alloc_bitmap::AllocBitmap,
        transaction: &Transaction,
        auth_tree_extents: &extents::LogicalExtents,
        alloc_bitmap_file_extents: &extents::LogicalExtents,
        encoded_alloc_bitmap_file_fragments_auth_digests_len: usize,
    ) -> Result<Self, NvFsError> {
        let image_layout = &fs_config.image_layout;

        let encoded_auth_tree_extents_value_len = inode_extents_list::indirect_extents_list_encoded_len(
            auth_tree_extents
                .iter()
                .map(|logical_extent| logical_extent.physical_range()),
        )?;
        let encoded_auth_tree_extents_tag_and_len_len =
            encoded_field_tag_and_len_len(JournalLogFieldTag::AuthTreeExtents, encoded_auth_tree_extents_value_len)?;

        let encoded_alloc_bitmap_file_extents_value_len = inode_extents_list::indirect_extents_list_encoded_len(
            alloc_bitmap_file_extents
                .iter()
                .map(|logical_extent| logical_extent.physical_range()),
        )?;
        let encoded_alloc_bitmap_file_extents_tag_and_len_len = encoded_field_tag_and_len_len(
            JournalLogFieldTag::AllocBitmapFileExtents,
            encoded_alloc_bitmap_file_extents_value_len,
        )?;

        // A Preauth CCA protection digest will get appended to the Allocation Bitmap
        // File authentication digests journal log field.
        let encoded_alloc_bitmap_file_fragments_auth_digests_value_len =
            encoded_alloc_bitmap_file_fragments_auth_digests_len
                .checked_add(hash::hash_alg_digest_len(image_layout.preauth_cca_protection_hmac_hash_alg) as usize)
                .ok_or(NvFsError::DimensionsNotSupported)?;
        let encoded_alloc_bitmap_file_fragments_auth_digests_tag_and_len_len = encoded_field_tag_and_len_len(
            JournalLogFieldTag::AllocBitmapFileFragmentsAuthDigests,
            encoded_alloc_bitmap_file_fragments_auth_digests_value_len,
        )?;

        let salt_len =
            u8::try_from(fs_config.salt.len()).map_err(|_| NvFsError::from(FormatError::InvalidSaltLength))?;
        let encoded_apply_writes_script_value_len = apply_script::JournalApplyWritesScript::encoded_len(
            TransactionJournalApplyWritesScriptIterator::new(
                &transaction.auth_tree_data_blocks_update_states,
                &fs_config.image_layout,
                salt_len,
            ),
            image_layout.io_block_allocation_blocks_log2 as u32,
        )?;
        let encoded_apply_writes_script_tag_and_len_len = encoded_field_tag_and_len_len(
            JournalLogFieldTag::ApplyWritesScript,
            encoded_apply_writes_script_value_len,
        )?;

        let encoded_update_auth_digests_script_value_len = apply_script::JournalUpdateAuthDigestsScript::encoded_len(
            TransactionJournalUpdateAuthDigestsScriptIterator::new(
                &transaction.auth_tree_data_blocks_update_states,
                &transaction.allocs.pending_frees,
                fs_config.image_header_end,
                image_layout.auth_tree_data_block_allocation_blocks_log2,
            ),
            image_layout.auth_tree_data_block_allocation_blocks_log2 as u32,
        )?;
        let encoded_update_auth_digests_script_tag_and_len_len = encoded_field_tag_and_len_len(
            JournalLogFieldTag::UpdateAuthDigestsScript,
            encoded_update_auth_digests_script_value_len,
        )?;

        let mut encoded_total_len = encoded_auth_tree_extents_tag_and_len_len
            .checked_add(encoded_auth_tree_extents_value_len)
            .and_then(|acc| acc.checked_add(encoded_alloc_bitmap_file_extents_tag_and_len_len))
            .and_then(|acc| acc.checked_add(encoded_alloc_bitmap_file_extents_value_len))
            .and_then(|acc| acc.checked_add(encoded_alloc_bitmap_file_fragments_auth_digests_tag_and_len_len))
            .and_then(|acc| acc.checked_add(encoded_alloc_bitmap_file_fragments_auth_digests_value_len))
            .and_then(|acc| acc.checked_add(encoded_apply_writes_script_tag_and_len_len))
            .and_then(|acc| acc.checked_add(encoded_apply_writes_script_value_len))
            .and_then(|acc| acc.checked_add(encoded_update_auth_digests_script_tag_and_len_len))
            .and_then(|acc| acc.checked_add(encoded_update_auth_digests_script_value_len));

        let encoded_trim_script_value_len = if fs_config.enable_trimming {
            let encoded_trim_script_value_len = num::NonZeroUsize::new(apply_script::JournalTrimsScript::encoded_len(
                TransactionJournalTrimsScriptIterator::new(
                    fs_sync_state_alloc_bitmap,
                    &transaction.allocs.pending_frees,
                    image_layout.io_block_allocation_blocks_log2,
                ),
                image_layout.io_block_allocation_blocks_log2 as u32,
            )?);

            if let Some(encoded_trim_script_value_len) = encoded_trim_script_value_len {
                let encoded_trim_script_tag_and_len_len =
                    encoded_field_tag_and_len_len(JournalLogFieldTag::TrimScript, encoded_trim_script_value_len.get())?;
                encoded_total_len = encoded_total_len
                    .and_then(|acc| acc.checked_add(encoded_trim_script_tag_and_len_len))
                    .and_then(|acc| acc.checked_add(encoded_trim_script_value_len.get()));
            }

            encoded_trim_script_value_len
        } else {
            None
        };

        let encoded_journal_staging_copy_disguise_value_len = if let Some(transaction_journal_staging_copy_disguise) =
            transaction
                .journal_staging_copy_disguise
                .as_ref()
                .map(|journal_staging_copy_disguise| &journal_staging_copy_disguise.0)
        {
            let encoded_journal_staging_copy_disguise_value_len =
                num::NonZeroUsize::new(transaction_journal_staging_copy_disguise.encoded_len())
                    .ok_or_else(|| nvfs_err_internal!())?;
            let encoded_journal_staging_copy_disguise_tag_and_len_len = encoded_field_tag_and_len_len(
                JournalLogFieldTag::JournalStagingCopyDisguise,
                encoded_journal_staging_copy_disguise_value_len.get(),
            )?;
            encoded_total_len = encoded_total_len
                .and_then(|acc| acc.checked_add(encoded_journal_staging_copy_disguise_tag_and_len_len))
                .and_then(|acc| acc.checked_add(encoded_journal_staging_copy_disguise_value_len.get()));
            Some(encoded_journal_staging_copy_disguise_value_len)
        } else {
            None
        };

        let encoded_total_len = encoded_total_len.ok_or(NvFsError::DimensionsNotSupported)?;
        Ok(Self {
            encoded_auth_tree_extents_value_len,
            encoded_alloc_bitmap_file_extents_value_len,
            encoded_alloc_bitmap_file_fragments_auth_digests_value_len,
            encoded_apply_writes_script_value_len,
            encoded_update_auth_digests_script_value_len,
            encoded_trim_script_value_len,
            encoded_journal_staging_copy_disguise_value_len,
            encoded_total_len,
        })
    }

    /// Get the [`JournalLog`]'s total encoded length.
    pub fn get_encoded_total_len(&self) -> usize {
        self.encoded_total_len
    }
}

/// To be encrypted journal log plaintext contents.
pub struct JournalLog {
    /// The extents forming the journal log's encrypted chained extents.
    ///
    /// Always starts
    /// with the filesystem's fixed [journal log head
    /// extent](Self::head_extent_physical_location)
    pub log_extents: extents::PhysicalExtents,
    /// Contents of the [`AuthTreeExtents`](JournalLogFieldTag::AuthTreeExtents)
    /// field.
    pub auth_tree_extents: extents::PhysicalExtents,
    /// Contents of the
    /// [`AllocBitmapFileExtents`](JournalLogFieldTag::AllocBitmapFileExtents)
    /// field.
    pub alloc_bitmap_file_extents: extents::PhysicalExtents,
    /// Contents of the
    /// [`AllocBitmapFileFragmentsAuthDigests`](JournalLogFieldTag::AllocBitmapFileFragmentsAuthDigests)
    /// field.
    pub alloc_bitmap_file_fragments_auth_digests: ExtentsCoveringAuthDigests,
    /// Contents of the
    /// [`ApplyWritesScript`](JournalLogFieldTag::ApplyWritesScript) field.
    pub apply_writes_script: apply_script::JournalApplyWritesScript,
    /// Contents of the
    /// [`UpdateAuthDigestsScript`](JournalLogFieldTag::UpdateAuthDigestsScript)
    /// field.
    pub update_auth_digests_script: apply_script::JournalUpdateAuthDigestsScript,
    /// Contents of the optional
    /// [`TrimScript`](JournalLogFieldTag::TrimScript) field.
    pub trim_script: Option<apply_script::JournalTrimsScript>,
    /// [`JournalStagingCopyUndisguise`] created from the contents of the
    /// [`JournalStagingCopyDisguise`](JournalLogFieldTag::JournalStagingCopyDisguise) field, if any.
    pub journal_staging_copy_undisguise: Option<JournalStagingCopyUndisguise>,
}

impl JournalLog {
    /// Instantiate a [`EncryptedChainedExtentsLayout`] suitable for the journal
    /// log.
    ///
    /// # Arguments:
    ///
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    pub fn extents_encryption_layout(
        image_layout: &layout::ImageLayout,
    ) -> Result<EncryptedChainedExtentsLayout, NvFsError> {
        let auth_tree_data_block_allocation_blocks_log2 = image_layout.auth_tree_data_block_allocation_blocks_log2;
        let io_block_allocation_blocks_log2 = image_layout.io_block_allocation_blocks_log2;
        // Journal Log extents are aligned to the larger of the Authentication Tree Data
        // Block and the IO block sizes.
        let journal_block_allocation_blocks_log2 =
            auth_tree_data_block_allocation_blocks_log2.max(io_block_allocation_blocks_log2);

        EncryptedChainedExtentsLayout::new(
            8, // For the magic.
            image_layout.block_cipher_alg,
            Some(image_layout.preauth_cca_protection_hmac_hash_alg),
            journal_block_allocation_blocks_log2,
            image_layout.allocation_block_size_128b_log2,
        )
    }

    /// Instantiate a [`EncryptedChainedExtentsEncryptionInstance`] suitable for
    /// the journal log.
    ///
    /// # Arguments:
    ///
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `fs_root_key` - The filesystem's root key.
    /// * `fs_sync_state_keys_cache` - The [filesystem instance's key
    ///   cache](crate::fs::cocoonfs::fs::CocoonFsSyncState::keys_cache).
    pub fn extents_encryption_instance<ST: sync_types::SyncTypes>(
        image_layout: &layout::ImageLayout,
        fs_root_key: &keys::RootKey,
        fs_sync_state_keys_cache: &mut keys::KeyCacheRef<'_, ST>,
    ) -> Result<EncryptedChainedExtentsEncryptionInstance, NvFsError> {
        let encryption_key = keys::KeyCache::get_key(
            fs_sync_state_keys_cache,
            fs_root_key,
            &keys::KeyId::new(
                inode_index::SpecialInode::JournalLog as u32,
                inode_index::InodeKeySubdomain::InodeData as u32,
                keys::KeyPurpose::Encryption,
            ),
        )?;
        let block_cipher_instance = symcipher::SymBlockCipherModeEncryptionInstance::new(
            tpm2_interface::TpmiAlgCipherMode::Cbc,
            &image_layout.block_cipher_alg,
            &encryption_key,
        )?;
        drop(encryption_key);

        let inline_authentication_key = keys::KeyCache::get_key(
            fs_sync_state_keys_cache,
            fs_root_key,
            &keys::KeyId::new(
                inode_index::SpecialInode::JournalLog as u32,
                inode_index::InodeKeySubdomain::InodeData as u32,
                keys::KeyPurpose::PreAuthCcaProtectionAuthentication,
            ),
        )?;
        let inline_authentication_hmac_instance = hash::HmacInstance::new(
            image_layout.preauth_cca_protection_hmac_hash_alg,
            &inline_authentication_key,
        )?;
        drop(inline_authentication_key);

        let extents_encryption_layout = Self::extents_encryption_layout(image_layout)?;
        EncryptedChainedExtentsEncryptionInstance::new(
            &extents_encryption_layout,
            block_cipher_instance,
            Some(inline_authentication_hmac_instance),
        )
    }

    /// Instantiate a [`EncryptedChainedExtentsDecryptionInstance`] suitable for
    /// the journal log.
    ///
    /// # Arguments:
    ///
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `fs_root_key` - The filesystem's root key.
    /// * `fs_sync_state_keys_cache` - The [filesystem instance's key
    ///   cache](crate::fs::cocoonfs::fs::CocoonFsSyncState::keys_cache).
    pub fn extents_decryption_instance<ST: sync_types::SyncTypes>(
        image_layout: &layout::ImageLayout,
        fs_root_key: &keys::RootKey,
        fs_sync_state_keys_cache: &mut keys::KeyCacheRef<'_, ST>,
    ) -> Result<EncryptedChainedExtentsDecryptionInstance, NvFsError> {
        let encryption_key = keys::KeyCache::get_key(
            fs_sync_state_keys_cache,
            fs_root_key,
            &keys::KeyId::new(
                inode_index::SpecialInode::JournalLog as u32,
                inode_index::InodeKeySubdomain::InodeData as u32,
                keys::KeyPurpose::Encryption,
            ),
        )?;
        let block_cipher_instance = symcipher::SymBlockCipherModeDecryptionInstance::new(
            tpm2_interface::TpmiAlgCipherMode::Cbc,
            &image_layout.block_cipher_alg,
            &encryption_key,
        )?;
        drop(encryption_key);

        let inline_authentication_key = keys::KeyCache::get_key(
            fs_sync_state_keys_cache,
            fs_root_key,
            &keys::KeyId::new(
                inode_index::SpecialInode::JournalLog as u32,
                inode_index::InodeKeySubdomain::InodeData as u32,
                keys::KeyPurpose::PreAuthCcaProtectionAuthentication,
            ),
        )?;
        let inline_authentication_hmac_instance = hash::HmacInstance::new(
            image_layout.preauth_cca_protection_hmac_hash_alg,
            &inline_authentication_key,
        )?;
        drop(inline_authentication_key);

        let extents_encryption_layout = Self::extents_encryption_layout(image_layout)?;
        EncryptedChainedExtentsDecryptionInstance::new(
            &extents_encryption_layout,
            block_cipher_instance,
            Some(inline_authentication_hmac_instance),
        )
    }

    /// Determine the (fixed) location of the journal log's chained encrypted
    /// extents' head extent.
    ///
    /// # Arguments:
    ///
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `image_header_end` - [End of the filesystem image header on
    ///   storage](image_header::MutableImageHeader::physical_location).
    pub fn head_extent_physical_location(
        image_layout: &layout::ImageLayout,
        image_header_end: layout::PhysicalAllocBlockIndex,
    ) -> Result<(layout::PhysicalAllocBlockRange, u64), NvFsError> {
        let auth_tree_data_block_allocation_blocks_log2 = image_layout.auth_tree_data_block_allocation_blocks_log2;
        let io_block_allocation_blocks_log2 = image_layout.io_block_allocation_blocks_log2;
        // Journal Log extents are aligned to the larger of the Authentication Tree Data
        // Block and the IO block sizes.
        let journal_block_allocation_blocks_log2 =
            auth_tree_data_block_allocation_blocks_log2.max(io_block_allocation_blocks_log2);
        // The maximum possible IO Block or Authentication Tree Data Block size in units
        // of Allocation Blocks is 2^56 (otherwise a single such block would
        // cover >= 2^64 Bytes).
        debug_assert!((journal_block_allocation_blocks_log2 as u32) < u64::BITS - 7);

        // The first Journal Log extent is located at the first possible alignment
        // boundary following the image header. In the extreme case of a maximum
        // possible IO block size, and a minimum Allocation Block size, the IO
        // block aligned image header end is at 2 * 2^56 == 2^57 Allocation
        // Blocks, meaning the below alignment cannot overflow.
        let head_extent_allocation_blocks_begin = image_header_end
            .align_up(journal_block_allocation_blocks_log2 as u32)
            .ok_or_else(|| nvfs_err_internal!())?;

        // Determine the length of the first extent as the minimum possible aligned
        // length.
        let journal_extents_layout = Self::extents_encryption_layout(image_layout)?.get_extents_layout()?;

        // Minimum possible size of the first extent is found by requiring an effective
        // payload size of zero.
        let head_extent_allocation_blocks_count = journal_extents_layout.min_extents_allocation_blocks().0;
        let head_extent_payload_len =
            journal_extents_layout.extent_effective_payload_len(head_extent_allocation_blocks_count, true);

        // The extent size in units of Allocation Blocks is <= 2^56, too, meaning
        // the addition would not overflow either.
        let head_extent_allocation_blocks_end =
            head_extent_allocation_blocks_begin + head_extent_allocation_blocks_count;
        // But check that the end in units of Bytes is still <= 2^64.
        if u64::from(head_extent_allocation_blocks_end)
            >> (u64::BITS - 7 - image_layout.allocation_block_size_128b_log2 as u32)
            > 1
        {
            return Err(NvFsError::from(FormatError::InvalidImageLayoutConfig));
        }

        Ok((
            layout::PhysicalAllocBlockRange::new(
                head_extent_allocation_blocks_begin,
                head_extent_allocation_blocks_end,
            ),
            head_extent_payload_len,
        ))
    }

    /// Encode a [`JournalLog`].
    ///
    /// Encode the journal log's to be encrypted payload into `dst` and return
    /// the remainder of `dst`.
    ///
    /// # Arguments:
    ///
    /// * `dst` - The destination buffer. It must be at least
    ///   [`encoded_buf_layout.
    ///   get_encoded_total_len()`](JournalLogEncodeBufferLayout::get_encoded_total_len)
    ///   in size.
    /// * `encode_buf_layout` - The [`JournalLogEncodeBufferLayout`] obtained
    ///   previously when computing the needed `dst` buffer size. Must have
    ///   instantiated with arguments consistent with the ones passed here.
    /// * `fs_config` - The filesystem instance's [`CocoonFsConfig`].
    /// * `fs_sync_state_alloc_bitmap` - The [filesystem instance's allocation
    ///   bitmap](crate::fs::cocoonfs::fs::CocoonFsSyncState::alloc_bitmap).
    /// * `fs_sync_state_keys_cache` - The [filesystem instance's key
    ///   cache](crate::fs::cocoonfs::fs::CocoonFsSyncState::keys_cache).
    /// * `transaction` - The [`Transaction`] to commit to the journal.
    /// * `auth_tree_extents` - The [authentication tree's
    ///   extents](crate::fs::cocoonfs::auth_tree::AuthTreeConfig::get_auth_tree_extents).
    /// * `alloc_bitmap_file_extents` - The [allocation bitmap file's
    ///   extents](alloc_bitmap::AllocBitmapFile::get_extents).
    /// * `encoded_alloc_bitmap_file_fragments_auth_digests` - [Encoded
    ///   `ExtentsCoveringAuthDigests`](ExtentsCoveringAuthDigests) for the
    ///   [allocation bitmap file fragments needed for authentication tree
    ///   reconstruction during journal
    ///   replay](super::auth_tree_updates::collect_alloc_bitmap_blocks_for_auth_tree_reconstruction).
    #[allow(clippy::too_many_arguments)]
    pub fn encode<'a, ST: sync_types::SyncTypes>(
        mut dst: &'a mut [u8],
        encode_buf_layout: &JournalLogEncodeBufferLayout,
        fs_config: &CocoonFsConfig,
        fs_sync_state_alloc_bitmap: &alloc_bitmap::AllocBitmap,
        fs_sync_state_keys_cache: &mut keys::KeyCacheRef<'_, ST>,
        transaction: &Transaction,
        auth_tree_extents: &extents::LogicalExtents,
        alloc_bitmap_file_extents: &extents::LogicalExtents,
        encoded_alloc_bitmap_file_fragments_auth_digests: &[u8],
    ) -> Result<&'a mut [u8], NvFsError> {
        let image_layout = &fs_config.image_layout;

        // Journal log field: Authentication Tree File extents.
        dst = encode_field_tag_and_len(
            dst,
            JournalLogFieldTag::AuthTreeExtents,
            encode_buf_layout.encoded_auth_tree_extents_value_len,
        )?;
        dst = inode_extents_list::indirect_extents_list_encode_into(
            dst,
            auth_tree_extents
                .iter()
                .map(|logical_extent| logical_extent.physical_range()),
        );

        // Journal log field: Allocation Bitmap File extents.
        dst = encode_field_tag_and_len(
            dst,
            JournalLogFieldTag::AllocBitmapFileExtents,
            encode_buf_layout.encoded_alloc_bitmap_file_extents_value_len,
        )?;
        let dst_alloc_bitmap_file_extents;
        (dst_alloc_bitmap_file_extents, dst) =
            dst.split_at_mut(encode_buf_layout.encoded_alloc_bitmap_file_extents_value_len);
        if !inode_extents_list::indirect_extents_list_encode_into(
            dst_alloc_bitmap_file_extents,
            alloc_bitmap_file_extents
                .iter()
                .map(|logical_extent| logical_extent.physical_range()),
        )
        .is_empty()
        {
            return Err(nvfs_err_internal!());
        }

        // Journal log field: Allocation Bitmap File digests.
        dst = encode_field_tag_and_len(
            dst,
            JournalLogFieldTag::AllocBitmapFileFragmentsAuthDigests,
            encode_buf_layout.encoded_alloc_bitmap_file_fragments_auth_digests_value_len,
        )?;
        debug_assert_eq!(
            encode_buf_layout.encoded_alloc_bitmap_file_fragments_auth_digests_value_len,
            encoded_alloc_bitmap_file_fragments_auth_digests.len()
                + hash::hash_alg_digest_len(image_layout.preauth_cca_protection_hmac_hash_alg) as usize
        );
        let dst_encoded_alloc_bitmap_file_fragments_auth_digests;
        (dst_encoded_alloc_bitmap_file_fragments_auth_digests, dst) =
            dst.split_at_mut(encoded_alloc_bitmap_file_fragments_auth_digests.len());
        dst_encoded_alloc_bitmap_file_fragments_auth_digests
            .copy_from_slice(encoded_alloc_bitmap_file_fragments_auth_digests);

        let dst_alloc_bitmap_file_fragments_auth_digests_cca_protection_hmac_digest;
        (
            dst_alloc_bitmap_file_fragments_auth_digests_cca_protection_hmac_digest,
            dst,
        ) = dst.split_at_mut(hash::hash_alg_digest_len(image_layout.preauth_cca_protection_hmac_hash_alg) as usize);
        let alloc_bitmap_file_fragments_auth_digests_preauth_cca_protection_hmac_key = keys::KeyCache::get_key(
            fs_sync_state_keys_cache,
            &fs_config.root_key,
            &keys::KeyId::new(
                inode_index::SpecialInode::AllocBitmap as u32,
                inode_index::InodeKeySubdomain::InodeData as u32,
                keys::KeyPurpose::PreAuthCcaProtectionAuthentication,
            ),
        )?;
        let mut alloc_bitmap_file_fragments_auth_digests_preauth_cca_protection_hmac_instance =
            hash::HmacInstance::new(
                image_layout.preauth_cca_protection_hmac_hash_alg,
                &alloc_bitmap_file_fragments_auth_digests_preauth_cca_protection_hmac_key,
            )?;
        drop(alloc_bitmap_file_fragments_auth_digests_preauth_cca_protection_hmac_key);

        // See above, leb128 encoding coincides with the plain value.
        debug_assert!((JournalLogFieldTag::AllocBitmapFileFragmentsAuthDigests as u32) < 0x80);
        let auth_context_subject_id_suffix = [
            0u8, // Version of the authenticated data's "inner" format.
            JournalLogFieldTag::AllocBitmapFileFragmentsAuthDigests as u8,
            0u8, // Version of the authenticated data's "outer" envelope format.
            AuthSubjectDataSuffix::JournalLogField as u8,
        ];
        let encoded_image_layout = image_layout.encode()?;
        alloc_bitmap_file_fragments_auth_digests_preauth_cca_protection_hmac_instance.update(
            io_slices::BuffersSliceIoSlicesIter::new(&[
                encoded_image_layout.as_slice(),
                dst_alloc_bitmap_file_extents,
                dst_encoded_alloc_bitmap_file_fragments_auth_digests,
                auth_context_subject_id_suffix.as_slice(),
            ])
            .map_infallible_err(),
        )?;
        alloc_bitmap_file_fragments_auth_digests_preauth_cca_protection_hmac_instance
            .finalize_into(dst_alloc_bitmap_file_fragments_auth_digests_cca_protection_hmac_digest)?;

        // Journal log field: apply script.
        dst = encode_field_tag_and_len(
            dst,
            JournalLogFieldTag::ApplyWritesScript,
            encode_buf_layout.encoded_apply_writes_script_value_len,
        )?;
        let salt_len =
            u8::try_from(fs_config.salt.len()).map_err(|_| NvFsError::from(FormatError::InvalidSaltLength))?;
        dst = apply_script::JournalApplyWritesScript::encode(
            dst,
            TransactionJournalApplyWritesScriptIterator::new(
                &transaction.auth_tree_data_blocks_update_states,
                &fs_config.image_layout,
                salt_len,
            ),
            image_layout.io_block_allocation_blocks_log2 as u32,
        )?;

        // Journal log field: data authentication digests update script.
        dst = encode_field_tag_and_len(
            dst,
            JournalLogFieldTag::UpdateAuthDigestsScript,
            encode_buf_layout.encoded_update_auth_digests_script_value_len,
        )?;
        dst = apply_script::JournalUpdateAuthDigestsScript::encode(
            dst,
            TransactionJournalUpdateAuthDigestsScriptIterator::new(
                &transaction.auth_tree_data_blocks_update_states,
                &transaction.allocs.pending_frees,
                fs_config.image_header_end,
                image_layout.auth_tree_data_block_allocation_blocks_log2,
            ),
            image_layout.auth_tree_data_block_allocation_blocks_log2 as u32,
        )?;

        // Journal log field: trim script, if trimming is enabled and there's any IO
        // block to trim.
        if let Some(encoded_trim_script_value_len) = encode_buf_layout.encoded_trim_script_value_len {
            debug_assert!(fs_config.enable_trimming);
            dst = encode_field_tag_and_len(dst, JournalLogFieldTag::TrimScript, encoded_trim_script_value_len.get())?;
            dst = apply_script::JournalTrimsScript::encode(
                dst,
                TransactionJournalTrimsScriptIterator::new(
                    fs_sync_state_alloc_bitmap,
                    &transaction.allocs.pending_frees,
                    image_layout.io_block_allocation_blocks_log2,
                ),
                image_layout.io_block_allocation_blocks_log2 as u32,
            )?;
        }

        // Journal log field: journal staging copy disguise.
        if let Some(transaction_journal_staging_copy_disguise) = transaction
            .journal_staging_copy_disguise
            .as_ref()
            .map(|journal_staging_copy_disguise| &journal_staging_copy_disguise.0)
        {
            let encoded_journal_staging_copy_disguise_value_len = encode_buf_layout
                .encoded_journal_staging_copy_disguise_value_len
                .ok_or_else(|| nvfs_err_internal!())?;
            dst = encode_field_tag_and_len(
                dst,
                JournalLogFieldTag::JournalStagingCopyDisguise,
                encoded_journal_staging_copy_disguise_value_len.get(),
            )?;
            dst = transaction_journal_staging_copy_disguise.encode(dst)?;
        }

        Ok(dst)
    }

    /// Decode a [`JournalLog`].
    ///
    /// # Arguments:
    ///
    /// * `src` - Buffers to decode from. Must have the CBC padding from the
    ///   encryption stripped. `src` gets advanced past the decoded data, i.e.
    ///   is empty upon (successful) return.
    /// * `log_extents` - The extents forming the journal log's encrypted
    ///   chained extents. Always starts with the filesystem's fixed [journal
    ///   log head extent](Self::head_extent_physical_location)
    /// * `root_key` - The filesystem's root key.
    /// * `keys_cache` - A [`KeyCache`](keys::KeyCache) instantiated for the
    ///   filesystem.
    pub fn decode<
        'a,
        ST: sync_types::SyncTypes,
        SI: io_slices::PeekableIoSlicesIter<'a, BackendIteratorError = convert::Infallible>,
    >(
        mut src: SI,
        log_extents: extents::PhysicalExtents,
        image_layout: &layout::ImageLayout,
        root_key: &keys::RootKey,
        keys_cache: &mut keys::KeyCacheRef<'_, ST>,
    ) -> Result<Self, NvFsError> {
        let io_block_allocation_blocks_log2 = image_layout.io_block_allocation_blocks_log2 as u32;
        let auth_tree_data_block_allocation_blocks_log2 =
            image_layout.auth_tree_data_block_allocation_blocks_log2 as u32;
        let journal_block_allocation_blocks_log2 =
            io_block_allocation_blocks_log2.max(auth_tree_data_block_allocation_blocks_log2);

        // Journal log field: Authentication Tree File extents.
        let (tag, encoded_auth_tree_extents_len) =
            decode_field_tag_and_len(src.as_ref())?.ok_or(NvFsError::from(FormatError::IncompleteJournalLog))?;
        if tag != JournalLogFieldTag::AuthTreeExtents {
            return Err(NvFsError::from(FormatError::UnexpectedJournalLogField));
        }
        let mut encoded_auth_tree_extents =
            src.as_ref()
                .take_exact(encoded_auth_tree_extents_len)
                .map_err(|e| match e {
                    io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
                    io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                        io_slices::IoSlicesError::BuffersExhausted => {
                            NvFsError::from(FormatError::JournalLogFieldLengthOutOfBounds)
                        }
                    },
                });
        let auth_tree_extents = inode_extents_list::indirect_extents_list_decode(&mut encoded_auth_tree_extents)?;
        if !encoded_auth_tree_extents.is_empty()? {
            return Err(NvFsError::from(FormatError::ExcessJournalLogFieldLength));
        }
        // This is considered unauthenticated data, because the encoded extents might
        // span multiple, independently authenticated Journal log extents. While the
        // indirect_extents_list_decode() does  already verify all individual
        // extents are well-formed, it does not check for overlaps.  Do it now.
        let mut extents_end_high_watermark = layout::PhysicalAllocBlockIndex::from(0u64);
        for (i, cur_extent) in auth_tree_extents.iter().enumerate() {
            if !(u64::from(cur_extent.begin()) | u64::from(cur_extent.end()))
                .is_aligned_pow2(journal_block_allocation_blocks_log2)
            {
                return Err(NvFsError::from(FormatError::UnalignedAuthTreeExtents));
            }

            if cur_extent.begin() >= extents_end_high_watermark {
                extents_end_high_watermark = cur_extent.end();
                continue;
            }

            for j in 0..i {
                if auth_tree_extents.get_extent_range(j).overlaps_with(&cur_extent) {
                    return Err(NvFsError::from(FormatError::InvalidExtents));
                }
            }
        }

        // The Allocation Bitmap File extents and its needed Authentication Tree Data
        // Block digests are authenticated together. Start the digest now and
        // update incrementally as the fields are decoded.
        let alloc_bitmap_file_fragments_auth_digests_preauth_cca_protection_hmac_key = keys::KeyCache::get_key(
            keys_cache,
            root_key,
            &keys::KeyId::new(
                inode_index::SpecialInode::AllocBitmap as u32,
                inode_index::InodeKeySubdomain::InodeData as u32,
                keys::KeyPurpose::PreAuthCcaProtectionAuthentication,
            ),
        )?;
        let mut alloc_bitmap_file_fragments_auth_digests_preauth_cca_protection_hmac_instance =
            hash::HmacInstance::new(
                image_layout.preauth_cca_protection_hmac_hash_alg,
                &alloc_bitmap_file_fragments_auth_digests_preauth_cca_protection_hmac_key,
            )?;
        drop(alloc_bitmap_file_fragments_auth_digests_preauth_cca_protection_hmac_key);
        let encoded_image_layout = image_layout.encode()?;
        alloc_bitmap_file_fragments_auth_digests_preauth_cca_protection_hmac_instance
            .update(io_slices::SingletonIoSlice::new(&encoded_image_layout).map_infallible_err())?;

        // Journal log field: Allocation Bitmap File extents.
        let (tag, encoded_alloc_bitmap_file_extents_len) =
            decode_field_tag_and_len(src.as_ref())?.ok_or(NvFsError::from(FormatError::IncompleteJournalLog))?;
        if tag != JournalLogFieldTag::AllocBitmapFileExtents {
            return Err(NvFsError::from(FormatError::UnexpectedJournalLogField));
        }

        if src.total_len()? < encoded_alloc_bitmap_file_extents_len {
            return Err(NvFsError::from(FormatError::JournalLogFieldLengthOutOfBounds));
        }
        alloc_bitmap_file_fragments_auth_digests_preauth_cca_protection_hmac_instance.update(
            src.decoupled_borrow()
                .take_exact(encoded_alloc_bitmap_file_extents_len)
                .map_err(|e| match e {
                    io_slices::IoSlicesIterError::BackendIteratorError(e) => CryptoError::from(e),
                    io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                        io_slices::IoSlicesError::BuffersExhausted => CryptoError::Internal,
                    },
                }),
        )?;

        let mut encoded_alloc_bitmap_file_extents = src
            .as_ref()
            .take_exact(encoded_alloc_bitmap_file_extents_len)
            .map_err(|e| match e {
                io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
                io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                    io_slices::IoSlicesError::BuffersExhausted => {
                        nvfs_err_internal!()
                    }
                },
            });
        let alloc_bitmap_file_extents =
            inode_extents_list::indirect_extents_list_decode(&mut encoded_alloc_bitmap_file_extents)?;
        if !encoded_alloc_bitmap_file_extents.is_empty()? {
            return Err(NvFsError::from(FormatError::ExcessJournalLogFieldLength));
        }
        // This is considered unauthenticated data, because the encoded extents might
        // span multiple, independently authenticated Journal log extents. While the
        // indirect_extents_list_decode() does  already verify all individual
        // extents are well-formed, it does not check for overlaps.  Do it now.
        let mut extents_end_high_watermark = layout::PhysicalAllocBlockIndex::from(0u64);
        for (i, cur_extent) in alloc_bitmap_file_extents.iter().enumerate() {
            if cur_extent.begin() >= extents_end_high_watermark {
                extents_end_high_watermark = cur_extent.end();
                continue;
            }

            for j in 0..i {
                if alloc_bitmap_file_extents.get_extent_range(j).overlaps_with(&cur_extent) {
                    return Err(NvFsError::from(FormatError::InvalidExtents));
                }
            }
        }

        // Journal log field: Allocation Bitmap File digests.
        let (tag, encoded_alloc_bitmap_file_fragments_auth_digests_len) =
            decode_field_tag_and_len(src.as_ref())?.ok_or(NvFsError::from(FormatError::IncompleteJournalLog))?;
        if tag != JournalLogFieldTag::AllocBitmapFileFragmentsAuthDigests {
            return Err(NvFsError::from(FormatError::UnexpectedJournalLogField));
        }

        let preauth_cca_protection_digest_len =
            hash::hash_alg_digest_len(image_layout.preauth_cca_protection_hmac_hash_alg) as usize;
        if encoded_alloc_bitmap_file_fragments_auth_digests_len < preauth_cca_protection_digest_len {
            return Err(NvFsError::from(
                FormatError::InvalidJournalExtentsCoveringAuthDigestsFormat,
            ));
        }

        if src.total_len()? < encoded_alloc_bitmap_file_extents_len {
            return Err(NvFsError::from(FormatError::JournalLogFieldLengthOutOfBounds));
        }
        alloc_bitmap_file_fragments_auth_digests_preauth_cca_protection_hmac_instance.update(
            src.decoupled_borrow()
                .take_exact(encoded_alloc_bitmap_file_fragments_auth_digests_len - preauth_cca_protection_digest_len)
                .map_err(|e| match e {
                    io_slices::IoSlicesIterError::BackendIteratorError(e) => CryptoError::from(e),
                    io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                        io_slices::IoSlicesError::BuffersExhausted => CryptoError::Internal,
                    },
                }),
        )?;

        let mut encoded_alloc_bitmap_file_fragments_auth_digests = src
            .as_ref()
            .take_exact(encoded_alloc_bitmap_file_fragments_auth_digests_len - preauth_cca_protection_digest_len)
            .map_err(|e| match e {
                io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
                io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                    io_slices::IoSlicesError::BuffersExhausted => {
                        nvfs_err_internal!()
                    }
                },
            });
        let alloc_bitmap_file_fragments_auth_digests = ExtentsCoveringAuthDigests::decode(
            encoded_alloc_bitmap_file_fragments_auth_digests.as_ref(),
            image_layout.auth_tree_data_block_allocation_blocks_log2,
            image_layout.allocation_block_size_128b_log2,
            hash::hash_alg_digest_len(image_layout.preauth_cca_protection_hmac_hash_alg) as usize,
        )?;
        if !encoded_alloc_bitmap_file_fragments_auth_digests.is_empty()? {
            return Err(NvFsError::from(FormatError::ExcessJournalLogFieldLength));
        }

        // Verify the digest over all.
        debug_assert!((JournalLogFieldTag::AllocBitmapFileFragmentsAuthDigests as u32) < 0x80);
        let auth_context_subject_id_suffix = [
            0u8, // Version of the authenticated data's "inner" format.
            JournalLogFieldTag::AllocBitmapFileFragmentsAuthDigests as u8,
            0u8, // Version of the authenticated data's "outer" envelope format.
            AuthSubjectDataSuffix::JournalLogField as u8,
        ];
        alloc_bitmap_file_fragments_auth_digests_preauth_cca_protection_hmac_instance
            .update(io_slices::SingletonIoSlice::new(&auth_context_subject_id_suffix).map_infallible_err())?;
        let mut alloc_bitmap_file_fragments_auth_digests_preauth_cca_protection_digest =
            zeroize::Zeroizing::new(FixedVec::<u8, 5>::new_with_default(preauth_cca_protection_digest_len)?);
        alloc_bitmap_file_fragments_auth_digests_preauth_cca_protection_hmac_instance
            .finalize_into(&mut alloc_bitmap_file_fragments_auth_digests_preauth_cca_protection_digest)?;
        if io_slices::SingletonIoSlice::new(&alloc_bitmap_file_fragments_auth_digests_preauth_cca_protection_digest)
            .map_infallible_err()
            .ct_eq_with_iter(
                src.as_ref()
                    .take_exact(preauth_cca_protection_digest_len)
                    .map_err(|e| match e {
                        io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
                        io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                            io_slices::IoSlicesError::BuffersExhausted => {
                                nvfs_err_internal!()
                            }
                        },
                    }),
            )?
            .unwrap()
            == 0
        {
            return Err(NvFsError::AuthenticationFailure);
        }
        drop(alloc_bitmap_file_fragments_auth_digests_preauth_cca_protection_digest);

        // Journal log field: apply script.
        let (tag, encoded_apply_writes_script_len) =
            decode_field_tag_and_len(src.as_ref())?.ok_or(NvFsError::from(FormatError::IncompleteJournalLog))?;
        if tag != JournalLogFieldTag::ApplyWritesScript {
            return Err(NvFsError::from(FormatError::UnexpectedJournalLogField));
        }
        let mut encoded_apply_writes_script =
            src.as_ref()
                .take_exact(encoded_apply_writes_script_len)
                .map_err(|e| match e {
                    io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
                    io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                        io_slices::IoSlicesError::BuffersExhausted => {
                            NvFsError::from(FormatError::JournalLogFieldLengthOutOfBounds)
                        }
                    },
                });
        let apply_writes_script = apply_script::JournalApplyWritesScript::decode(
            encoded_apply_writes_script.as_ref(),
            image_layout.io_block_allocation_blocks_log2 as u32,
            image_layout.allocation_bitmap_file_block_allocation_blocks_log2 as u32,
        )?;
        if !encoded_apply_writes_script.is_empty()? {
            return Err(NvFsError::from(FormatError::ExcessJournalLogFieldLength));
        }

        // Journal log field: data authentication digests update script.
        let (tag, encoded_update_auth_digests_script_len) =
            decode_field_tag_and_len(src.as_ref())?.ok_or(NvFsError::from(FormatError::IncompleteJournalLog))?;
        if tag != JournalLogFieldTag::UpdateAuthDigestsScript {
            return Err(NvFsError::from(FormatError::UnexpectedJournalLogField));
        }
        let mut encoded_update_auth_digests_script = src
            .as_ref()
            .take_exact(encoded_update_auth_digests_script_len)
            .map_err(|e| match e {
                io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
                io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                    io_slices::IoSlicesError::BuffersExhausted => {
                        NvFsError::from(FormatError::JournalLogFieldLengthOutOfBounds)
                    }
                },
            });
        let update_auth_digests_script = apply_script::JournalUpdateAuthDigestsScript::decode(
            encoded_update_auth_digests_script.as_ref(),
            image_layout.auth_tree_data_block_allocation_blocks_log2 as u32,
            image_layout.allocation_bitmap_file_block_allocation_blocks_log2 as u32,
        )?;
        if !encoded_update_auth_digests_script.is_empty()? {
            return Err(NvFsError::from(FormatError::ExcessJournalLogFieldLength));
        }

        // Optional journal log fields.
        let mut trim_script = None;
        let mut journal_staging_copy_undisguise = None;
        while let Some((tag, encoded_field_len)) = decode_field_tag_and_len(src.as_ref())? {
            if tag == JournalLogFieldTag::TrimScript {
                if trim_script.is_some() {
                    return Err(NvFsError::from(FormatError::UnexpectedJournalLogField));
                }

                let mut encoded_trim_script = src.as_ref().take_exact(encoded_field_len).map_err(|e| match e {
                    io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
                    io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                        io_slices::IoSlicesError::BuffersExhausted => {
                            NvFsError::from(FormatError::JournalLogFieldLengthOutOfBounds)
                        }
                    },
                });
                trim_script = Some(apply_script::JournalTrimsScript::decode(
                    encoded_trim_script.as_ref(),
                    image_layout.io_block_allocation_blocks_log2 as u32,
                    image_layout.allocation_bitmap_file_block_allocation_blocks_log2 as u32,
                )?);
                if !encoded_trim_script.is_empty()? {
                    return Err(NvFsError::from(FormatError::ExcessJournalLogFieldLength));
                }
            } else if tag == JournalLogFieldTag::JournalStagingCopyDisguise {
                if journal_staging_copy_undisguise.is_some() {
                    return Err(NvFsError::from(FormatError::UnexpectedJournalLogField));
                }

                let mut encoded_journal_staging_copy_disguise =
                    src.as_ref().take_exact(encoded_field_len).map_err(|e| match e {
                        io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
                        io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                            io_slices::IoSlicesError::BuffersExhausted => {
                                NvFsError::from(FormatError::JournalLogFieldLengthOutOfBounds)
                            }
                        },
                    });
                journal_staging_copy_undisguise = Some(JournalStagingCopyUndisguise::decode(
                    encoded_journal_staging_copy_disguise.as_ref(),
                )?);
                if !encoded_journal_staging_copy_disguise.is_empty()? {
                    return Err(NvFsError::from(FormatError::ExcessJournalLogFieldLength));
                }
            } else {
                return Err(NvFsError::from(FormatError::UnexpectedJournalLogField));
            }
        }

        Ok(Self {
            log_extents,
            auth_tree_extents,
            alloc_bitmap_file_extents,
            alloc_bitmap_file_fragments_auth_digests,
            apply_writes_script,
            update_auth_digests_script,
            trim_script,
            journal_staging_copy_undisguise,
        })
    }
}

/// Invalidate the journal log.
///
/// Overwrite the filesystem's [journal log
/// head](JournalLog::head_extent_physical_location) such that no more attempts
/// to replay it will be made.
pub struct JournalLogInvalidateFuture<B: blkdev::NvBlkDev> {
    fut_state: JournalLogInvalidateFutureState<B>,
    issue_sync: bool,
}

/// [`JournalLogInvalidateFuture`] state-machine state.
enum JournalLogInvalidateFutureState<B: blkdev::NvBlkDev> {
    Init,
    WriteBarrierBeforeInvalidate {
        write_barrier_fut: B::WriteBarrierFuture,
    },
    InvalidateJournalLogHead {
        overwrite_journal_log_head_fut: B::WriteFuture<JournalLogInvalidateNvBlkDevWriteRequest>,
    },
    WriteSyncAfterInvalidate {
        write_sync_fut: B::WriteSyncFuture,
    },
    Done,
}

impl<B: blkdev::NvBlkDev> JournalLogInvalidateFuture<B> {
    /// Instantiate a [`JournalLogInvalidateFuture`].
    ///
    /// # Arguments:
    ///
    /// * `issue_sync` - Whether or not to submit a [synchronization
    ///   barrier](blkdev::NvBlkDev::write_sync) to the backing storage after
    ///   the journal log invalidation.
    pub fn new(issue_sync: bool) -> Self {
        Self {
            fut_state: JournalLogInvalidateFutureState::Init,
            issue_sync,
        }
    }

    /// Poll the [`JournalLogInvalidateFuture`] to completion.
    ///
    /// # Arguments:
    ///
    /// * `blkdev` - The filesystem image backing storage.
    /// * `image_layout` - The filesystem's
    ///   [`ImageLayout`](layout::ImageLayout).
    /// * `image_header_end` - [End of the filesystem image header on
    ///   storage](image_header::MutableImageHeader::physical_location).
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    pub fn poll(
        self: pin::Pin<&mut Self>,
        blkdev: &B,
        image_layout: &layout::ImageLayout,
        image_header_end: layout::PhysicalAllocBlockIndex,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), NvFsError>> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                JournalLogInvalidateFutureState::Init => {
                    let write_barrier_fut = match blkdev.write_barrier() {
                        Ok(write_barrier_fut) => write_barrier_fut,
                        Err(e) => {
                            this.fut_state = JournalLogInvalidateFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    this.fut_state =
                        JournalLogInvalidateFutureState::WriteBarrierBeforeInvalidate { write_barrier_fut };
                }
                JournalLogInvalidateFutureState::WriteBarrierBeforeInvalidate { write_barrier_fut } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(write_barrier_fut), blkdev, cx) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => {
                            this.fut_state = JournalLogInvalidateFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let journal_log_head_extent =
                        match JournalLog::head_extent_physical_location(image_layout, image_header_end) {
                            Ok((journal_log_head_extent, _)) => journal_log_head_extent,
                            Err(e) => {
                                this.fut_state = JournalLogInvalidateFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                        };
                    let overwrite_journal_log_head_request = match JournalLogInvalidateNvBlkDevWriteRequest::new(
                        &journal_log_head_extent,
                        image_layout.allocation_block_size_128b_log2 as u32,
                        blkdev,
                    ) {
                        Ok(overwrite_journal_log_head_request) => overwrite_journal_log_head_request,
                        Err(e) => {
                            this.fut_state = JournalLogInvalidateFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    let overwrite_journal_log_head_fut = match blkdev
                        .write(overwrite_journal_log_head_request)
                        .and_then(|r| r.map_err(|(_, e)| e))
                    {
                        Ok(overwrite_journal_log_head_fut) => overwrite_journal_log_head_fut,
                        Err(e) => {
                            this.fut_state = JournalLogInvalidateFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    this.fut_state = JournalLogInvalidateFutureState::InvalidateJournalLogHead {
                        overwrite_journal_log_head_fut,
                    };
                }
                JournalLogInvalidateFutureState::InvalidateJournalLogHead {
                    overwrite_journal_log_head_fut,
                } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(overwrite_journal_log_head_fut), blkdev, cx) {
                        task::Poll::Ready(Ok((_, Ok(())))) => (),
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                            this.fut_state = JournalLogInvalidateFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let write_sync_fut = match blkdev.write_sync() {
                        Ok(write_sync_fut) => write_sync_fut,
                        Err(e) => {
                            this.fut_state = JournalLogInvalidateFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    if this.issue_sync {
                        this.fut_state = JournalLogInvalidateFutureState::WriteSyncAfterInvalidate { write_sync_fut };
                    } else {
                        this.fut_state = JournalLogInvalidateFutureState::Done;
                        return task::Poll::Ready(Ok(()));
                    }
                }
                JournalLogInvalidateFutureState::WriteSyncAfterInvalidate { write_sync_fut } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(write_sync_fut), blkdev, cx) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => {
                            this.fut_state = JournalLogInvalidateFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    this.fut_state = JournalLogInvalidateFutureState::Done;
                    return task::Poll::Ready(Ok(()));
                }
                JournalLogInvalidateFutureState::Done => unreachable!(),
            }
        }
    }
}

/// [`NvBlkDevWriteRequest`](blkdev::NvBlkDevWriteRequest) implementation used
/// internally by [`JournalLogInvalidateFuture`].
struct JournalLogInvalidateNvBlkDevWriteRequest {
    region: ChunkedIoRegion,
    overwrite_buf: FixedVec<u8, 7>,
}

impl JournalLogInvalidateNvBlkDevWriteRequest {
    fn new<B: blkdev::NvBlkDev>(
        journal_log_head_extent: &layout::PhysicalAllocBlockRange,
        allocation_block_size_128b_log2: u32,
        blkdev: &B,
    ) -> Result<Self, NvFsError> {
        // Allocate a buffer of the minimum length filled with zeroes. 128 Bytes is the
        // minimum chunk size.
        let overwrite_buf = FixedVec::new_with_value(128, 0u8)?;

        let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();
        let journal_log_head_extent_begin_128b =
            u64::from(journal_log_head_extent.begin()) << allocation_block_size_128b_log2;
        // Only the magic needs to get invalidated. Overwrite the minimum possible IO
        // unit at the beginning of the journal log.
        let journal_log_head_extent_overwrite_end_128b = journal_log_head_extent_begin_128b
            .checked_add(1u64 << blkdev_io_block_size_128b_log2)
            .ok_or(NvFsError::from(blkdev::NvBlkDevIoError::IoBlockOutOfRange))?;
        let region = ChunkedIoRegion::new(
            journal_log_head_extent_begin_128b,
            journal_log_head_extent_overwrite_end_128b,
            0,
        )
        .map_err(|_| nvfs_err_internal!())?;
        Ok(Self { region, overwrite_buf })
    }
}

impl blkdev::NvBlkDevWriteRequest for JournalLogInvalidateNvBlkDevWriteRequest {
    fn region(&self) -> &ChunkedIoRegion {
        &self.region
    }

    fn get_source_buffer(&self, range: &ChunkedIoRegionChunkRange) -> Result<&[u8], blkdev::NvBlkDevIoError> {
        // The chunk size is 128 Bytes, i.e. the size of overwrite_buf. Ignore the chunk
        // index and provide the corresponding region from zero-filled
        // overwrite_buf.
        Ok(&self.overwrite_buf[range.range_in_chunk().clone()])
    }
}

/// Read the journal log at filesystem opening time.
pub struct JournalLogReadFuture<B: blkdev::NvBlkDev> {
    fut_state: JournalLogReadFutureState<B>,
    log_extents: extents::PhysicalExtents,
    extents_decryption_instance: Option<EncryptedChainedExtentsDecryptionInstance>,
    decrypted_journal_log_extents: Vec<zeroize::Zeroizing<Vec<u8>>>,
}

/// [`JournalLogReadFuture`] state-machine state.
enum JournalLogReadFutureState<B: blkdev::NvBlkDev> {
    Init,
    ReadJournalLogHeadExtentHead {
        read_fut: B::ReadFuture<JournalLogReadExtentNvBlkDevReadRequest>,
        journal_log_head_extent: layout::PhysicalAllocBlockRange,
        journal_log_head_extent_effective_payload_len: usize,
    },
    ReadJournalLogHeadExtentTail {
        read_fut: B::ReadFuture<JournalLogReadExtentNvBlkDevReadRequest>,
        journal_log_head_extent_head: FixedVec<u8, 7>,
        journal_log_head_extent_allocation_blocks: layout::AllocBlockCount,
        journal_log_head_extent_effective_payload_len: usize,
    },
    DecryptJournalLogHeadExtent {
        journal_log_head_extent_head: FixedVec<u8, 7>,
        journal_log_head_extent_tail: FixedVec<u8, 7>,
        journal_log_head_extent_allocation_blocks: layout::AllocBlockCount,
        journal_log_head_extent_effective_payload_len: usize,
    },
    ReadNextJournalLogTailExtentPrepare {
        next_journal_log_tail_extent: layout::PhysicalAllocBlockRange,
    },
    ReadNextJournalLogTailExtent {
        read_fut: B::ReadFuture<JournalLogReadExtentNvBlkDevReadRequest>,
        next_journal_log_tail_extent_allocation_blocks: layout::AllocBlockCount,
    },
    DecodeJournalLog,
    Done,
}

impl<B: blkdev::NvBlkDev> JournalLogReadFuture<B> {
    /// Instantiate a [`JournalLogReadFuture`].
    pub fn new() -> Self {
        Self {
            fut_state: JournalLogReadFutureState::Init,
            log_extents: extents::PhysicalExtents::new(),
            extents_decryption_instance: None,
            decrypted_journal_log_extents: Vec::new(),
        }
    }

    /// Poll the [`JournalLogReadFuture`] to completion.
    ///
    /// On successful completion, a [`JournalLog`] wrapped in a `Some` is
    /// returned if a journal to get replayed has been found, or a `None` in
    /// case the journal is inactive.
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
    ) -> task::Poll<Result<Option<JournalLog>, NvFsError>> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                JournalLogReadFutureState::Init => {
                    let image_header_end =
                        image_header::MutableImageHeader::physical_location(image_layout, salt_len).end();

                    let (journal_log_head_extent, journal_log_head_extent_effective_payload_len) =
                        match JournalLog::head_extent_physical_location(image_layout, image_header_end) {
                            Ok((journal_log_head_extent, journal_log_head_extent_effective_payload_len)) => {
                                (journal_log_head_extent, journal_log_head_extent_effective_payload_len)
                            }
                            Err(e) => {
                                this.fut_state = JournalLogReadFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                        };
                    let journal_log_head_extent_effective_payload_len =
                        match usize::try_from(journal_log_head_extent_effective_payload_len) {
                            Ok(journal_log_head_extent_effective_payload_len) => {
                                journal_log_head_extent_effective_payload_len
                            }
                            Err(_) => {
                                this.fut_state = JournalLogReadFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::DimensionsNotSupported));
                            }
                        };
                    if let Err(e) = this.log_extents.push_extent(&journal_log_head_extent, false) {
                        this.fut_state = JournalLogReadFutureState::Done;
                        return task::Poll::Ready(Err(e));
                    }

                    // Read the very first Device IO block from the Journal log and check if the
                    // magic is there, otherwise the Journal is not active.
                    let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();
                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                    let journal_log_head_extent_begin_128b =
                        u64::from(journal_log_head_extent.begin()) << allocation_block_size_128b_log2;
                    let journal_log_head_extent_head_read_request = match JournalLogReadExtentNvBlkDevReadRequest::new(
                        journal_log_head_extent_begin_128b,
                        journal_log_head_extent_begin_128b + (1 << blkdev_io_block_size_128b_log2),
                        blkdev_io_block_size_128b_log2,
                    ) {
                        Ok(journal_log_head_extent_head_read_request) => journal_log_head_extent_head_read_request,
                        Err(e) => {
                            this.fut_state = JournalLogReadFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    let read_fut = match blkdev.read(journal_log_head_extent_head_read_request) {
                        Ok(Ok(read_fut)) => read_fut,
                        Err(e) | Ok(Err((_, e))) => {
                            this.fut_state = JournalLogReadFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    this.fut_state = JournalLogReadFutureState::ReadJournalLogHeadExtentHead {
                        read_fut,
                        journal_log_head_extent,
                        journal_log_head_extent_effective_payload_len,
                    };
                }
                JournalLogReadFutureState::ReadJournalLogHeadExtentHead {
                    read_fut,
                    journal_log_head_extent,
                    journal_log_head_extent_effective_payload_len,
                } => {
                    let journal_log_head_extent_head_read_request =
                        match blkdev::NvBlkDevFuture::poll(pin::Pin::new(read_fut), blkdev, cx) {
                            task::Poll::Ready(Ok((journal_log_head_extent_head_read_request, Ok(())))) => {
                                journal_log_head_extent_head_read_request
                            }
                            task::Poll::Ready(Err(e) | Ok((_, Err(e)))) => {
                                this.fut_state = JournalLogReadFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(e)));
                            }
                            task::Poll::Pending => return task::Poll::Pending,
                        };
                    let journal_log_head_extent_head = journal_log_head_extent_head_read_request.into_dst_buf();
                    if &journal_log_head_extent_head[..8] != b"CCFSJRNL".as_slice() {
                        // Magic not found, journal is not active, all done.
                        this.fut_state = JournalLogReadFutureState::Done;
                        return task::Poll::Ready(Ok(None));
                    }

                    // Read the remainder from the log's head extent.
                    let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();
                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                    let journal_log_head_extent_begin_128b =
                        u64::from(journal_log_head_extent.begin()) << allocation_block_size_128b_log2;
                    let journal_log_head_extent_tail_begin_128b =
                        journal_log_head_extent_begin_128b + (1 << blkdev_io_block_size_128b_log2);
                    let journal_log_head_extent_end_128b =
                        u64::from(journal_log_head_extent.end()) << allocation_block_size_128b_log2;
                    if journal_log_head_extent_tail_begin_128b == journal_log_head_extent_end_128b {
                        this.fut_state = JournalLogReadFutureState::DecryptJournalLogHeadExtent {
                            journal_log_head_extent_head,
                            journal_log_head_extent_tail: FixedVec::new_empty(),
                            journal_log_head_extent_allocation_blocks: journal_log_head_extent.block_count(),
                            journal_log_head_extent_effective_payload_len:
                                *journal_log_head_extent_effective_payload_len,
                        };
                        continue;
                    }
                    let journal_log_head_extent_tail_read_request = match JournalLogReadExtentNvBlkDevReadRequest::new(
                        journal_log_head_extent_tail_begin_128b,
                        journal_log_head_extent_end_128b,
                        blkdev_io_block_size_128b_log2,
                    ) {
                        Ok(journal_log_head_extent_tail_read_request) => journal_log_head_extent_tail_read_request,
                        Err(e) => {
                            this.fut_state = JournalLogReadFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    let read_fut = match blkdev.read(journal_log_head_extent_tail_read_request) {
                        Ok(Ok(read_fut)) => read_fut,
                        Err(e) | Ok(Err((_, e))) => {
                            this.fut_state = JournalLogReadFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    this.fut_state = JournalLogReadFutureState::ReadJournalLogHeadExtentTail {
                        read_fut,
                        journal_log_head_extent_head,
                        journal_log_head_extent_allocation_blocks: journal_log_head_extent.block_count(),
                        journal_log_head_extent_effective_payload_len: *journal_log_head_extent_effective_payload_len,
                    };
                }
                JournalLogReadFutureState::ReadJournalLogHeadExtentTail {
                    read_fut,
                    journal_log_head_extent_head,
                    journal_log_head_extent_allocation_blocks,
                    journal_log_head_extent_effective_payload_len,
                } => {
                    let journal_log_head_extent_tail_read_request =
                        match blkdev::NvBlkDevFuture::poll(pin::Pin::new(read_fut), blkdev, cx) {
                            task::Poll::Ready(Ok((journal_log_head_extent_tail_read_request, Ok(())))) => {
                                journal_log_head_extent_tail_read_request
                            }
                            task::Poll::Ready(Err(e) | Ok((_, Err(e)))) => {
                                this.fut_state = JournalLogReadFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(e)));
                            }
                            task::Poll::Pending => return task::Poll::Pending,
                        };
                    let journal_log_head_extent_tail = journal_log_head_extent_tail_read_request.into_dst_buf();
                    this.fut_state = JournalLogReadFutureState::DecryptJournalLogHeadExtent {
                        journal_log_head_extent_head: mem::take(journal_log_head_extent_head),
                        journal_log_head_extent_tail,
                        journal_log_head_extent_allocation_blocks: *journal_log_head_extent_allocation_blocks,
                        journal_log_head_extent_effective_payload_len: *journal_log_head_extent_effective_payload_len,
                    };
                }
                JournalLogReadFutureState::DecryptJournalLogHeadExtent {
                    journal_log_head_extent_head,
                    journal_log_head_extent_tail,
                    journal_log_head_extent_allocation_blocks,
                    journal_log_head_extent_effective_payload_len,
                } => {
                    let extents_decryption_instance =
                        match JournalLog::extents_decryption_instance(image_layout, root_key, keys_cache) {
                            Ok(extents_decryption_instance) => extents_decryption_instance,
                            Err(e) => {
                                this.fut_state = JournalLogReadFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                        };
                    let extents_decryption_instance =
                        this.extents_decryption_instance.insert(extents_decryption_instance);

                    let mut decrypted_journal_log_head_extent =
                        match try_alloc_zeroizing_vec(*journal_log_head_extent_effective_payload_len) {
                            Ok(decrypted_journal_log_head_extent) => decrypted_journal_log_head_extent,
                            Err(e) => {
                                this.fut_state = JournalLogReadFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(e)));
                            }
                        };

                    let encoded_image_layout = match image_layout.encode() {
                        Ok(encoded_image_layout) => encoded_image_layout,
                        Err(e) => {
                            this.fut_state = JournalLogReadFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    let auth_context_subject_id_suffix = [
                        0u8, // Version of the authenticated data's format.
                        EncryptedChainedExtentsAssociatedDataAuthSubjectDataSuffix::JournalLog as u8,
                    ];
                    let authenticated_associated_data = [
                        encoded_image_layout.as_slice(),
                        auth_context_subject_id_suffix.as_slice(),
                    ];
                    let authenticated_associated_data =
                        io_slices::BuffersSliceIoSlicesIter::new(&authenticated_associated_data).map_infallible_err();

                    let next_chained_extent = match extents_decryption_instance.decrypt_one_extent(
                        io_slices::SingletonIoSliceMut::new(decrypted_journal_log_head_extent.as_mut_slice())
                            .map_infallible_err(),
                        io_slices::SingletonIoSlice::new(journal_log_head_extent_head)
                            .chain(io_slices::SingletonIoSlice::new(journal_log_head_extent_tail))
                            .map_infallible_err(),
                        authenticated_associated_data,
                        *journal_log_head_extent_allocation_blocks,
                    ) {
                        Ok(next_chained_extent) => next_chained_extent,
                        Err(NvFsError::AuthenticationFailure) => {
                            // An authentication failure for the Journal log's first "entry" extent
                            // is non-fatal and silently ignored -- the write to it might have been
                            // incomplete, i.e. interrupted by a power cut, in which case the
                            // Journal is considered to be non-existant.
                            this.fut_state = JournalLogReadFutureState::Done;
                            return task::Poll::Ready(Ok(None));
                        }
                        Err(e) => {
                            this.fut_state = JournalLogReadFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    if let Err(e) = this.decrypted_journal_log_extents.try_reserve(1) {
                        this.fut_state = JournalLogReadFutureState::Done;
                        return task::Poll::Ready(Err(NvFsError::from(e)));
                    };
                    this.decrypted_journal_log_extents
                        .push(decrypted_journal_log_head_extent);

                    this.fut_state = match next_chained_extent {
                        Some(next_journal_log_tail_extent) => {
                            JournalLogReadFutureState::ReadNextJournalLogTailExtentPrepare {
                                next_journal_log_tail_extent,
                            }
                        }
                        None => JournalLogReadFutureState::DecodeJournalLog,
                    };
                }
                JournalLogReadFutureState::ReadNextJournalLogTailExtentPrepare {
                    next_journal_log_tail_extent,
                } => {
                    if let Err(e) = this.log_extents.push_extent(next_journal_log_tail_extent, false) {
                        this.fut_state = JournalLogReadFutureState::Done;
                        return task::Poll::Ready(Err(e));
                    }

                    let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
                    let io_block_allocation_blocks_log2 = image_layout.io_block_allocation_blocks_log2 as u32;
                    let auth_tree_data_block_allocation_blocks_log2 =
                        image_layout.auth_tree_data_block_allocation_blocks_log2 as u32;
                    let journal_block_allocation_blocks_log2 =
                        io_block_allocation_blocks_log2.max(auth_tree_data_block_allocation_blocks_log2);
                    let next_journal_log_tail_extent_begin_128b =
                        u64::from(next_journal_log_tail_extent.begin()) << allocation_block_size_128b_log2;
                    let next_journal_log_tail_extent_end_128b =
                        u64::from(next_journal_log_tail_extent.end()) << allocation_block_size_128b_log2;
                    let next_journal_log_tail_extent_read_request = match JournalLogReadExtentNvBlkDevReadRequest::new(
                        next_journal_log_tail_extent_begin_128b,
                        next_journal_log_tail_extent_end_128b,
                        journal_block_allocation_blocks_log2,
                    ) {
                        Ok(next_journal_log_tail_extent_read_request) => next_journal_log_tail_extent_read_request,
                        Err(e) => {
                            this.fut_state = JournalLogReadFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    let read_fut = match blkdev.read(next_journal_log_tail_extent_read_request) {
                        Ok(Ok(read_fut)) => read_fut,
                        Err(e) | Ok(Err((_, e))) => {
                            this.fut_state = JournalLogReadFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    this.fut_state = JournalLogReadFutureState::ReadNextJournalLogTailExtent {
                        read_fut,
                        next_journal_log_tail_extent_allocation_blocks: next_journal_log_tail_extent.block_count(),
                    };
                }
                JournalLogReadFutureState::ReadNextJournalLogTailExtent {
                    read_fut,
                    next_journal_log_tail_extent_allocation_blocks,
                } => {
                    let next_journal_log_tail_extent_read_request =
                        match blkdev::NvBlkDevFuture::poll(pin::Pin::new(read_fut), blkdev, cx) {
                            task::Poll::Ready(Ok((journal_log_read_next_tail_extent_request, Ok(())))) => {
                                journal_log_read_next_tail_extent_request
                            }
                            task::Poll::Ready(Err(e) | Ok((_, Err(e)))) => {
                                this.fut_state = JournalLogReadFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(e)));
                            }
                            task::Poll::Pending => return task::Poll::Pending,
                        };
                    let next_journal_log_tail_extent = next_journal_log_tail_extent_read_request.into_dst_buf();

                    let extents_decryption_instance = match this.extents_decryption_instance.as_mut() {
                        Some(extents_decryption_instance) => extents_decryption_instance,
                        None => {
                            this.fut_state = JournalLogReadFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };
                    let next_journal_log_tail_extent_effective_payload_len = match extents_decryption_instance
                        .max_extent_decrypted_len(*next_journal_log_tail_extent_allocation_blocks, false)
                    {
                        Ok(next_journal_log_tail_extent_effective_payload_len) => {
                            next_journal_log_tail_extent_effective_payload_len
                        }
                        Err(e) => {
                            this.fut_state = JournalLogReadFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    let mut decrypted_next_journal_log_tail_extent =
                        match try_alloc_zeroizing_vec(next_journal_log_tail_extent_effective_payload_len) {
                            Ok(decrypted_next_journal_log_tail_extent) => decrypted_next_journal_log_tail_extent,
                            Err(e) => {
                                this.fut_state = JournalLogReadFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(e)));
                            }
                        };

                    let encoded_image_layout = match image_layout.encode() {
                        Ok(encoded_image_layout) => encoded_image_layout,
                        Err(e) => {
                            this.fut_state = JournalLogReadFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    let auth_context_subject_id_suffix = [
                        0u8, // Version of the authenticated data's format.
                        EncryptedChainedExtentsAssociatedDataAuthSubjectDataSuffix::JournalLog as u8,
                    ];
                    let authenticated_associated_data = [
                        encoded_image_layout.as_slice(),
                        auth_context_subject_id_suffix.as_slice(),
                    ];
                    let authenticated_associated_data =
                        io_slices::BuffersSliceIoSlicesIter::new(&authenticated_associated_data).map_infallible_err();

                    // In contrast to the first journal log "entry" extent, failure to authenticate
                    // a tail extent is fatal. It is assumed the tail extents
                    // had been written before the head extent, with a write barrier inbetween.
                    let next_chained_extent = match extents_decryption_instance.decrypt_one_extent(
                        io_slices::SingletonIoSliceMut::new(decrypted_next_journal_log_tail_extent.as_mut_slice())
                            .map_infallible_err(),
                        io_slices::SingletonIoSlice::new(&next_journal_log_tail_extent).map_infallible_err(),
                        authenticated_associated_data,
                        *next_journal_log_tail_extent_allocation_blocks,
                    ) {
                        Ok(next_chained_extent) => next_chained_extent,
                        Err(e) => {
                            this.fut_state = JournalLogReadFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    if let Err(e) = this.decrypted_journal_log_extents.try_reserve(1) {
                        this.fut_state = JournalLogReadFutureState::Done;
                        return task::Poll::Ready(Err(NvFsError::from(e)));
                    };
                    this.decrypted_journal_log_extents
                        .push(decrypted_next_journal_log_tail_extent);

                    this.fut_state = match next_chained_extent {
                        Some(next_journal_log_tail_extent) => {
                            JournalLogReadFutureState::ReadNextJournalLogTailExtentPrepare {
                                next_journal_log_tail_extent,
                            }
                        }
                        None => JournalLogReadFutureState::DecodeJournalLog,
                    };
                }
                JournalLogReadFutureState::DecodeJournalLog => {
                    // The decryption instance is no longer needed, free it up.
                    this.extents_decryption_instance = None;

                    // All Journal log extents read and decrypted.  Find the terminating CBC
                    // padding and truncate it off.
                    let mut padding_len = match check_cbc_padding(
                        io_slices::BuffersSliceIoSlicesIter::new(&this.decrypted_journal_log_extents)
                            .map_infallible_err(),
                    ) {
                        Ok(padding_len) => padding_len,
                        Err(e) => {
                            this.fut_state = JournalLogReadFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };

                    // Truncate the CBC padding off.
                    while padding_len != 0 {
                        let last_decrypted_extent = match this.decrypted_journal_log_extents.last_mut() {
                            Some(last_decrypted_extent) => last_decrypted_extent,
                            None => {
                                this.fut_state = JournalLogReadFutureState::Done;
                                return task::Poll::Ready(Err(nvfs_err_internal!()));
                            }
                        };
                        let last_decrypted_extent_len = last_decrypted_extent.len();
                        if last_decrypted_extent_len > padding_len {
                            last_decrypted_extent.truncate(last_decrypted_extent_len - padding_len);
                            padding_len = 0
                        } else {
                            padding_len -= last_decrypted_extent_len;
                            this.decrypted_journal_log_extents.pop();
                        }
                    }

                    let journal_log = match JournalLog::decode(
                        io_slices::BuffersSliceIoSlicesIter::new(&this.decrypted_journal_log_extents)
                            .map_infallible_err(),
                        mem::take(&mut this.log_extents),
                        image_layout,
                        root_key,
                        keys_cache,
                    ) {
                        Ok(journal_log) => journal_log,
                        Err(e) => {
                            this.fut_state = JournalLogReadFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    this.decrypted_journal_log_extents = Vec::new();
                    this.fut_state = JournalLogReadFutureState::Done;
                    return task::Poll::Ready(Ok(Some(journal_log)));
                }
                JournalLogReadFutureState::Done => unreachable!(),
            }
        }
    }
}

/// [`NvBlkDevReadRequest`](blkdev::NvBlkDevReadRequest) implementation used
/// internally by [`JournalLogReadFuture`].
struct JournalLogReadExtentNvBlkDevReadRequest {
    region: ChunkedIoRegion,
    dst: FixedVec<u8, 7>,
}

impl JournalLogReadExtentNvBlkDevReadRequest {
    fn new(physical_begin_128b: u64, physical_end_128b: u64, chunk_size_128b_log2: u32) -> Result<Self, NvFsError> {
        debug_assert!(chunk_size_128b_log2 < u64::BITS - 7);
        let region_len_128b = physical_end_128b - physical_begin_128b;
        let region_len = region_len_128b << 7;
        if region_len >> 7 != region_len_128b {
            return Err(NvFsError::IoError(NvFsIoError::RegionOutOfRange));
        }
        let region_len = usize::try_from(region_len).map_err(|_| NvFsError::DimensionsNotSupported)?;
        let dst = FixedVec::new_with_default(region_len)?;
        let region = blkdev::ChunkedIoRegion::new(physical_begin_128b, physical_end_128b, chunk_size_128b_log2)
            .map_err(|e| match e {
                ChunkedIoRegionError::ChunkSizeOverflow => nvfs_err_internal!(),
                ChunkedIoRegionError::InvalidBounds => nvfs_err_internal!(),
                ChunkedIoRegionError::ChunkIndexOverflow => NvFsError::DimensionsNotSupported,
                ChunkedIoRegionError::RegionUnaligned => {
                    NvFsError::FsFormatError(FormatError::UnalignedJournalExtents as isize)
                }
            })?;
        Ok(Self { region, dst })
    }

    pub fn into_dst_buf(self) -> FixedVec<u8, 7> {
        let Self { region: _, dst } = self;
        dst
    }
}

impl blkdev::NvBlkDevReadRequest for JournalLogReadExtentNvBlkDevReadRequest {
    fn region(&self) -> &ChunkedIoRegion {
        &self.region
    }

    fn get_destination_buffer(
        &mut self,
        range: &ChunkedIoRegionChunkRange,
    ) -> Result<Option<&mut [u8]>, blkdev::NvBlkDevIoError> {
        let chunk_size_128b_log2 = self.region.chunk_size_128b_log2();
        let (chunk_index, _) = range.chunk().decompose_to_hierarchic_indices([]);
        let dst_chunk =
            &mut self.dst[chunk_index << (chunk_size_128b_log2 + 7)..(chunk_index + 1) << (chunk_size_128b_log2 + 7)];
        Ok(Some(&mut dst_chunk[range.range_in_chunk().clone()]))
    }
}
