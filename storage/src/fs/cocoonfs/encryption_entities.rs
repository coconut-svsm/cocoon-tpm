// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Encrypt to and decrypt from the various defined encryption entity formats.

extern crate alloc;
use alloc::vec::Vec;

use crate::{
    crypto::{
        CryptoDoubleEndedIoSlicesIter, CryptoError, CryptoMutPeekableIoSlicesMutIter, CryptoPeekableIoSlicesIter,
        CryptoWalkableIoSlicesIter, CryptoWalkableIoSlicesMutIter, hash, rng, symcipher,
    },
    fs::{
        NvFsError,
        cocoonfs::{
            CocoonFsFormatError, auth_subject_ids::AuthSubjectDataSuffix, extent_ptr::EncodedExtentPtr,
            extents_layout::ExtentsLayout, layout,
        },
    },
    nvfs_err_internal, tpm2_interface,
    utils_common::{
        alloc::try_alloc_vec,
        bitmanip::BitManip as _,
        io_slices::{
            self, IoSlicesIter as _, IoSlicesIterCommon as _, IoSlicesMutIter as _, WalkableIoSlicesIter as _,
        },
    },
};
use core::{convert, mem, ops::Deref as _};

/// Convert from units of [Allocation
/// Blocks](layout::ImageLayout::allocation_block_size_128b_log2) to units of
/// bytes.
///
/// # Arguments:
///
/// * `allocation_blocks` - The size in units of [Allocation
///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2) to convert
///   from.
/// * `allocation_block_size_128b_log2` - Verbatim copy of
///   [`ImageLayout::allocation_block_size_128b_log2`](layout::ImageLayout::allocation_block_size_128b_log2).
fn allocation_blocks_to_len(
    allocation_blocks: layout::AllocBlockCount,
    allocation_block_size_128b_log2: u32,
) -> Result<usize, NvFsError> {
    let allocation_blocks = u64::from(allocation_blocks);
    let len = allocation_blocks << (allocation_block_size_128b_log2 + 7);
    if len >> (allocation_block_size_128b_log2 + 7) != allocation_blocks {
        return Err(NvFsError::DimensionsNotSupported);
    }
    usize::try_from(len).map_err(|_| NvFsError::DimensionsNotSupported)
}

/// Align a length downwards to a multiple of some block cipher block length.
///
/// Returns a pair of the aligned value and padding removed.
///
/// # Arguments:
///
/// * `len` - The length to align.
/// * `block_cipher_alg_block_len` - The block cipher block length.
fn align_len_down_to_block_cipher_alg_block_len(
    len: usize,
    block_cipher_alg_block_len: usize,
) -> Result<(usize, usize), NvFsError> {
    if !block_cipher_alg_block_len.is_pow2() {
        return Err(nvfs_err_internal!());
    }
    let excess = len & (block_cipher_alg_block_len - 1);
    let aligned_len = len - excess;
    Ok((aligned_len, excess))
}

/// Align a length upwards to a multiple of some block cipher block length.
///
/// Returns a pair of the aligned value and padding added.
///
/// # Arguments:
///
/// * `len` - The length to align.
/// * `block_cipher_alg_block_len` - The block cipher block length.
fn align_len_up_to_block_cipher_alg_block_len(
    len: usize,
    block_cipher_alg_block_len: usize,
) -> Result<(usize, usize), NvFsError> {
    if !block_cipher_alg_block_len.is_pow2() {
        return Err(nvfs_err_internal!());
    }
    // Distance to next alignment boundary.
    let required_alignment_padding = len.wrapping_neg() & (block_cipher_alg_block_len - 1);
    Ok((
        len.checked_add(required_alignment_padding)
            .ok_or(NvFsError::DimensionsNotSupported)?,
        required_alignment_padding,
    ))
}

/// Find and validate a PKCS#7 padding.
///
/// Search `decrypted_extents` from the back for the first non-zero byte and
/// confirm it's the last byte of a valid PKCS#7 padding.
///
/// The total number of padding bytes, i.e. the size of the PKCS#7 padding plus
/// any trailing zero bytes will get returned.
///
/// # Arguments:
///
/// * `decrypted_extents` - The decrypted data to find an validate the PKCS#7
///   padding in.
pub fn check_cbc_padding<'a, DI: CryptoDoubleEndedIoSlicesIter<'a>>(
    mut decrypted_extents: DI,
) -> Result<usize, NvFsError> {
    // The used padding is PKCS#7 plus possibly a fillup of zeroes all the way to
    // the extents' end.
    // No constant-time constraints, only authenticated data is getting decrypted.
    let mut trailing_zeroes_len: usize = 0;
    while let Some(tail_slice) = decrypted_extents.next_back_slice(None)? {
        let last_nonzero_pos = match tail_slice.iter().rposition(|b| *b != 0) {
            Some(last_nonzero_pos) => last_nonzero_pos,
            None => {
                trailing_zeroes_len = trailing_zeroes_len
                    .checked_add(tail_slice.len())
                    .ok_or(NvFsError::DimensionsNotSupported)?;
                continue;
            }
        };

        trailing_zeroes_len = trailing_zeroes_len
            .checked_add(tail_slice.len() - last_nonzero_pos - 1)
            .ok_or(NvFsError::DimensionsNotSupported)?;

        let cbc_padding_len = tail_slice[last_nonzero_pos];
        if (cbc_padding_len - 1) as usize > last_nonzero_pos {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidPadding));
        }
        if tail_slice[last_nonzero_pos - (cbc_padding_len - 1) as usize..last_nonzero_pos]
            .iter()
            .any(|b| *b != cbc_padding_len)
        {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidPadding));
        }

        return Ok(trailing_zeroes_len + cbc_padding_len as usize);
    }
    Err(NvFsError::from(CocoonFsFormatError::InvalidPadding))
}

/// Information about a given [block cipher
/// algorithm](symcipher::SymBlockCipherAlg) to be used for the encryption or
/// decryption of some filesystem entity.
#[derive(Clone)]
struct EncryptedEntityBlockCipherAlg {
    /// The block cipher algorithm.
    block_cipher_alg: symcipher::SymBlockCipherAlg,
    /// Block length of [`block_cipher_alg`](Self::block_cipher_alg).
    block_cipher_block_len: usize,
    /// IV length of [`block_cipher_alg`](Self::block_cipher_alg) used in CBC
    /// mode.
    ///
    /// The value is equal to
    /// [`block_cipher_block_len`](Self::block_cipher_block_len), but
    /// maintain it in a dedicated field for a more expressive naming.
    cbc_iv_len: usize,
}

impl convert::From<symcipher::SymBlockCipherAlg> for EncryptedEntityBlockCipherAlg {
    fn from(block_cipher_alg: symcipher::SymBlockCipherAlg) -> Self {
        Self {
            block_cipher_alg,
            block_cipher_block_len: block_cipher_alg.block_len(),
            cbc_iv_len: block_cipher_alg.iv_len_for_mode(tpm2_interface::TpmiAlgCipherMode::Cbc),
        }
    }
}

/// Information about a given [hash algorithm](tpm2_interface::TpmiAlgHash) to
/// be used in a HMAC construction for the the inline authentication of some
/// encrypted filesystem entity.
#[derive(Clone)]
struct EncryptedEntityInlineAuthenticationHmacHashAlg {
    /// The hash algorithm to be used in the HMAC construction.
    hmac_hash_alg: tpm2_interface::TpmiAlgHash,
    /// The length of a digest produced by
    /// [`hmac_hash_alg`](Self::hmac_hash_alg).
    digest_len: usize,
}

impl convert::From<tpm2_interface::TpmiAlgHash> for EncryptedEntityInlineAuthenticationHmacHashAlg {
    fn from(hmac_hash_alg: tpm2_interface::TpmiAlgHash) -> Self {
        Self {
            hmac_hash_alg,
            digest_len: hash::hash_alg_digest_len(hmac_hash_alg) as usize,
        }
    }
}

/// Layout parameters for an "encrypted block" format entity.
#[derive(Clone)]
pub struct EncryptedBlockLayout {
    /// The block cipher algorithm to use for the encryption or decryption
    /// respectively.
    block_cipher_alg: EncryptedEntityBlockCipherAlg,
    /// Base-2 logarithm of the encrypted block's size in units of [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    block_allocation_blocks_log2: u8,
    /// Verbatim copy of
    /// [`ImageLayout::allocation_block_size_128b_log2`](layout::ImageLayout::allocation_block_size_128b_log2).
    allocation_block_size_128b_log2: u8,
}

impl EncryptedBlockLayout {
    /// Create an [`EncryptedBlockLayout`] instance.
    ///
    /// # Arguments:
    ///
    /// * `block_cipher_alg` - The block cipher algorithm to use for the
    ///   encryption or decryption respectively.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the encrypted
    ///   block's size in units of [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    /// * `allocation_block_size_128b_log2` - Verbatim copy of
    ///   [`ImageLayout::allocation_block_size_128b_log2`](layout::ImageLayout::allocation_block_size_128b_log2).
    pub fn new(
        block_cipher_alg: symcipher::SymBlockCipherAlg,
        block_allocation_blocks_log2: u8,
        allocation_block_size_128b_log2: u8,
    ) -> Result<Self, NvFsError> {
        Ok(Self {
            block_cipher_alg: EncryptedEntityBlockCipherAlg::from(block_cipher_alg),
            block_allocation_blocks_log2,
            allocation_block_size_128b_log2,
        })
    }

    /// Get the encrypted block size in units of [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    fn block_allocation_blocks(&self) -> layout::AllocBlockCount {
        let block_allocation_blocks_log2 = self.block_allocation_blocks_log2 as u32;
        layout::AllocBlockCount::from(1u64 << block_allocation_blocks_log2)
    }

    /// Get the encrypted block size in units of bytes.
    fn block_len(&self) -> Result<usize, NvFsError> {
        allocation_blocks_to_len(
            self.block_allocation_blocks(),
            self.allocation_block_size_128b_log2 as u32,
        )
    }

    /// Get an encrypted block's maximum payload size in units of bytes.
    pub fn effective_payload_len(&self) -> Result<usize, NvFsError> {
        align_len_down_to_block_cipher_alg_block_len(
            self.block_len()? - self.block_cipher_alg.cbc_iv_len,
            self.block_cipher_alg.block_cipher_block_len,
        )
        .map(|l| l.0)
    }

    /// Get the internal copy of
    /// [`ImageLayout::allocation_block_size_128b_log2`](layout::ImageLayout::allocation_block_size_128b_log2).
    pub fn get_allocation_block_size_128b_log2(&self) -> u8 {
        self.allocation_block_size_128b_log2
    }

    /// Get the base-2 logarithm of the encrypted block size in units of
    /// [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    pub fn get_block_allocation_blocks_log2(&self) -> u8 {
        self.block_allocation_blocks_log2
    }
}

/// Encrypt an "encrypted block" format entity.
///
/// The instance may be used for [encrypting](Self::encrypt_one_block) multiple
/// independent blocks.
pub struct EncryptedBlockEncryptionInstance {
    /// The [`EncryptedBlockLayout`] describing the "encrypted block" format
    /// entity.
    layout: EncryptedBlockLayout,
    /// The the [CBC block cipher mode](tpm2_interface::TpmiAlgCipherMode::Cbc)
    /// [`SymBlockCipherModeEncryptionInstance`](symcipher::SymBlockCipherModeEncryptionInstance) to
    /// be used for encryptions.
    block_cipher_instance: symcipher::SymBlockCipherModeEncryptionInstance,
}

impl EncryptedBlockEncryptionInstance {
    /// Create an [`EncryptedBlockEncryptionInstance`].
    ///
    /// # Arguments:
    ///
    /// * `layout` - The [`EncryptedBlockLayout`] describing the "encrypted
    ///   block" format entity.
    /// * `block_cipher_instance` - A
    ///   [`SymBlockCipherModeEncryptionInstance`](symcipher::SymBlockCipherModeEncryptionInstance)
    ///   to be used for encryption. Must be consistent with the
    ///   [`SymBlockCipherAlg`](symcipher::SymBlockCipherAlg) `layout` had been
    ///   created with, and been initialized for operating in the [CBC block
    ///   cipher mode](tpm2_interface::TpmiAlgCipherMode::Cbc).
    pub fn new(
        layout: EncryptedBlockLayout,
        block_cipher_instance: symcipher::SymBlockCipherModeEncryptionInstance,
    ) -> Result<Self, NvFsError> {
        if layout.block_cipher_alg.block_cipher_alg != symcipher::SymBlockCipherAlg::from(&block_cipher_instance)
            || tpm2_interface::TpmiAlgCipherMode::from(&block_cipher_instance) != tpm2_interface::TpmiAlgCipherMode::Cbc
        {
            return Err(nvfs_err_internal!());
        }
        Ok(Self {
            layout,
            block_cipher_instance,
        })
    }

    /// Encrypt one "encrypted block" format entity.
    ///
    /// # Arguments:
    ///
    /// * `dst` - Ciphertext destination buffers. Their total size must match
    ///   the length of one encrypted block of the associated
    ///   [`EncryptedBlockLayout`] format.
    /// * `src` - Plaintext source plaintext buffers. Must not exceed
    ///   [`EncryptedBlockLayout::effective_payload_len()`] in length, but may
    ///   be smaller -- any unusued remainder will get filled up with `rng`.
    /// * `rng` - The [random number generator](rng::RngCoreDispatchable) used
    ///   for generating the IV and filling unused padding, if any.
    pub fn encrypt_one_block<'a, 'b, DI: CryptoWalkableIoSlicesMutIter<'a>, SI: CryptoWalkableIoSlicesIter<'b>>(
        &self,
        mut dst: DI,
        src: SI,
        rng: &mut dyn rng::RngCoreDispatchable,
    ) -> Result<(), NvFsError> {
        let block_len = self.layout.block_len()?;
        debug_assert_eq!(dst.total_len()?, block_len);
        let effective_payload_len = self.layout.effective_payload_len()?;
        debug_assert_eq!(
            effective_payload_len % self.block_cipher_instance.block_cipher_block_len(),
            0
        );
        let src_len = src.total_len()?;
        if src_len > effective_payload_len {
            return Err(nvfs_err_internal!());
        }

        let iv_len = self.layout.block_cipher_alg.cbc_iv_len;
        let dst_iv = dst.next_slice_mut(Some(iv_len))?;
        let dst_iv = match dst_iv {
            Some(dst_iv) => dst_iv,
            None => return Err(nvfs_err_internal!()),
        };
        // It is expected that the first slice from dst is large enough to accommodate
        // the IV.
        if dst_iv.len() != iv_len {
            return Err(nvfs_err_internal!());
        }

        // Fill the IV.
        rng::rng_dyn_dispatch_generate(
            rng,
            io_slices::SingletonIoSliceMut::new(dst_iv).map_infallible_err(),
            None,
        )?;

        // Fill any alignment padding inbetween the IV and the beginning of the
        // encrypted data with random bytes. The padding at this location will
        // be empty in practice, but be consistent with the other entity
        // formats.
        rng::rng_dyn_dispatch_generate(
            rng,
            dst.as_ref()
                .take_exact(block_len - iv_len - effective_payload_len)
                .map_err(CryptoError::from),
            None,
        )?;

        // If the to be encrypted source is not a multiple of the block cipher block
        // length, it will get padded with zeroes.
        let src_padding_len =
            align_len_up_to_block_cipher_alg_block_len(src_len, self.block_cipher_instance.block_cipher_block_len())?.1;

        self.block_cipher_instance.encrypt(
            dst_iv,
            dst.as_ref()
                .take_exact(src_len + src_padding_len)
                .map_err(CryptoError::from),
            src.chain(io_slices::ZeroFilledIoSlices::new(src_padding_len).map_infallible_err()),
            None,
        )?;

        // Fill the unused remainder with random bytes.
        rng::rng_dyn_dispatch_generate(rng, dst, None)?;

        Ok(())
    }
}

/// Decrypt an "encrypted block" format entity.
///
/// The instance may be used for [decrypting](Self::decrypt_one_block) multiple
/// independent blocks.
pub struct EncryptedBlockDecryptionInstance {
    /// The [`EncryptedBlockLayout`] describing the "encrypted block" format
    /// entity.
    layout: EncryptedBlockLayout,
    /// The the [CBC block cipher mode](tpm2_interface::TpmiAlgCipherMode::Cbc)
    /// [`SymBlockCipherModeDecryptionInstance`](symcipher::SymBlockCipherModeDecryptionInstance) to
    /// be used for encryptions.
    block_cipher_instance: symcipher::SymBlockCipherModeDecryptionInstance,
}

impl EncryptedBlockDecryptionInstance {
    /// Create an [`EncryptedBlockEncryptionInstance`].
    ///
    /// # Arguments:
    ///
    /// * `layout` - The [`EncryptedBlockLayout`] describing the "encrypted
    ///   block" format entity.
    /// * `block_cipher_instance` - A
    ///   [`SymBlockCipherModeDecryptionInstance`](symcipher::SymBlockCipherModeDecryptionInstance)
    ///   to be used for encryption. Must be consistent with the
    ///   [`SymBlockCipherAlg`](symcipher::SymBlockCipherAlg) `layout` had been
    ///   created with, and been initialized for operating in the [CBC block
    ///   cipher mode](tpm2_interface::TpmiAlgCipherMode::Cbc).
    pub fn new(
        layout: EncryptedBlockLayout,
        block_cipher_instance: symcipher::SymBlockCipherModeDecryptionInstance,
    ) -> Result<Self, NvFsError> {
        if layout.block_cipher_alg.block_cipher_alg != symcipher::SymBlockCipherAlg::from(&block_cipher_instance)
            || tpm2_interface::TpmiAlgCipherMode::from(&block_cipher_instance) != tpm2_interface::TpmiAlgCipherMode::Cbc
        {
            return Err(nvfs_err_internal!());
        }
        Ok(Self {
            layout,
            block_cipher_instance,
        })
    }

    /// Decrypt one "encrypted block" format entity.
    ///
    /// # Arguments:
    ///
    /// * `dst` - Plaintext destination buffers. Must not exceed
    ///   [`EncryptedBlockLayout::effective_payload_len()`] in length, but may
    ///   be smaller -- any remainder will get discarded.
    /// * `src` - Ciphertext source buffers. Their total size must match the
    ///   length of one encrypted block of the associated
    ///   [`EncryptedBlockLayout`] format.
    pub fn decrypt_one_block<'a, 'b, DI: CryptoWalkableIoSlicesMutIter<'a>, SI: CryptoWalkableIoSlicesIter<'b>>(
        &self,
        mut dst: DI,
        mut src: SI,
    ) -> Result<(), NvFsError> {
        let block_len = self.layout.block_len()?;
        debug_assert_eq!(src.total_len()?, block_len);
        let effective_payload_len = self.layout.effective_payload_len()?;
        debug_assert_eq!(
            effective_payload_len % self.block_cipher_instance.block_cipher_block_len(),
            0
        );
        let dst_len = dst.total_len()?;
        if dst_len > effective_payload_len {
            return Err(nvfs_err_internal!());
        }

        let iv_len = self.layout.block_cipher_alg.cbc_iv_len;
        let src_iv = src.next_slice(Some(iv_len))?;
        let src_iv = match src_iv {
            Some(src_iv) => src_iv,
            None => return Err(nvfs_err_internal!()),
        };
        // It is expected that the first slice from src is large enough to accommodate
        // the IV.
        if src_iv.len() != iv_len {
            return Err(nvfs_err_internal!());
        }

        // Skip over padding after the IV for aligning the encrypted data. It will be
        // empty in practice, but be consistent with the other formats.
        src.skip(block_len - iv_len - effective_payload_len)
            .map_err(CryptoError::from)?;

        // If the destination to be decrypted to is not a multiple of the block cipher
        // block length, provide a scratch buffer to receive the padding.
        let dst_padding_len =
            align_len_up_to_block_cipher_alg_block_len(dst_len, self.block_cipher_instance.block_cipher_block_len())?.1;
        let mut dst_padding_scratch = if dst_padding_len != 0 {
            try_alloc_vec(dst_padding_len)?
        } else {
            Vec::<u8>::new()
        };

        self.block_cipher_instance.decrypt(
            src_iv,
            dst.as_ref()
                .chain(io_slices::SingletonIoSliceMut::new(&mut dst_padding_scratch).map_infallible_err()),
            src.take_exact(dst_len + dst_padding_len).map_err(CryptoError::from),
            None,
        )?;

        Ok(())
    }
}

/// Layout parameters for an "encrypted extents" format entity.
#[derive(Clone)]
pub struct EncryptedExtentsLayout {
    /// The block cipher algorithm to use for the encryption or decryption
    /// respectively.
    block_cipher_alg: EncryptedEntityBlockCipherAlg,
    /// Verbatim copy of
    /// [`ImageLayout::allocation_block_size_128b_log2`](layout::ImageLayout::allocation_block_size_128b_log2).
    allocation_block_size_128b_log2: u8,
}

impl EncryptedExtentsLayout {
    /// Create an [`EncryptedExtentsLayout`] instance.
    ///
    /// # Arguments:
    ///
    /// * `block_cipher_alg` - The block cipher algorithm to use for the
    ///   encryption or decryption respectively.
    /// * `allocation_block_size_128b_log2` - Verbatim copy of
    ///   [`ImageLayout::allocation_block_size_128b_log2`](layout::ImageLayout::allocation_block_size_128b_log2).
    pub fn new(
        block_cipher_alg: symcipher::SymBlockCipherAlg,
        allocation_block_size_128b_log2: u8,
    ) -> Result<Self, NvFsError> {
        Ok(Self {
            block_cipher_alg: EncryptedEntityBlockCipherAlg::from(block_cipher_alg),
            allocation_block_size_128b_log2,
        })
    }

    /// Obtain an [`ExtentsLayout`] instance for allocating extents suitable
    /// for an "encrypted extents" format entity described by the
    /// [`EncryptedExtentsLayout`].
    pub fn get_extents_layout(&self) -> Result<ExtentsLayout, NvFsError> {
        ExtentsLayout::new(
            None,
            0,
            self.block_cipher_alg.cbc_iv_len as u32,
            0,
            0,
            u8::try_from(self.block_cipher_alg.block_cipher_block_len).map_err(|_| nvfs_err_internal!())?,
            self.allocation_block_size_128b_log2,
        )
    }

    /// Compute the length of one extent in units of bytes.
    ///
    /// # Arguments:
    ///
    /// * `extent_allocation_blocks` - Extent length in units of [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    fn extent_len(&self, extent_allocation_blocks: layout::AllocBlockCount) -> Result<usize, NvFsError> {
        allocation_blocks_to_len(extent_allocation_blocks, self.allocation_block_size_128b_log2 as u32)
    }

    /// Compute the effective payload length in units of bytes that can be
    /// stored in a given extent.
    ///
    /// Note that the final PKCS#7 padding is not being accounted for, i.e. it's
    /// being considered as part of the (total) payload length.
    ///
    /// # Arguments:
    ///
    /// * `extent_allocation_blocks` - Extent length in units of [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    /// * `is_first` - Whether or not the extent is the first one in an
    ///   "encrypted extents" format entity.
    fn effective_payload_len(
        &self,
        extent_allocation_blocks: layout::AllocBlockCount,
        is_first: bool,
    ) -> Result<usize, NvFsError> {
        let iv_len = if is_first { self.block_cipher_alg.cbc_iv_len } else { 0 };

        align_len_down_to_block_cipher_alg_block_len(
            self.extent_len(extent_allocation_blocks)? - iv_len,
            self.block_cipher_alg.block_cipher_block_len,
        )
        .map(|l| l.0)
    }
}

/// Encrypt an "encrypted extents" format entity.
///
/// The entity's extents are to be [encrypted](Self::encrypt_one_extent) one
/// after another with the instance.
pub struct EncryptedExtentsEncryptionInstance {
    /// The [`EncryptedExtentsLayout`] describing the "encrypted extents" format
    /// entity.
    layout: EncryptedExtentsLayout,
    /// The the [CBC block cipher mode](tpm2_interface::TpmiAlgCipherMode::Cbc)
    /// [`SymBlockCipherModeEncryptionInstance`](symcipher::SymBlockCipherModeEncryptionInstance) to
    /// be used for encryptions.
    block_cipher_instance: symcipher::SymBlockCipherModeEncryptionInstance,
    /// The "carry-over" CBC extent to be used for the next extent in the
    /// sequence.
    next_iv: Vec<u8>,
}

impl EncryptedExtentsEncryptionInstance {
    /// Create an [`EncryptedExtentsEncryptionInstance`].
    ///
    /// # Arguments:
    ///
    /// * `layout` - The [`EncryptedExtentsLayout`] describing the "encrypted
    ///   extents" format entity.
    /// * `block_cipher_instance` - A
    ///   [`SymBlockCipherModeEncryptionInstance`](symcipher::SymBlockCipherModeEncryptionInstance)
    ///   to be used for encryption. Must be consistent with the
    ///   [`SymBlockCipherAlg`](symcipher::SymBlockCipherAlg) `layout` had been
    ///   created with, and been initialized for operating in the [CBC block
    ///   cipher mode](tpm2_interface::TpmiAlgCipherMode::Cbc).
    pub fn new(
        layout: &EncryptedExtentsLayout,
        block_cipher_instance: symcipher::SymBlockCipherModeEncryptionInstance,
    ) -> Result<Self, NvFsError> {
        if layout.block_cipher_alg.block_cipher_alg != symcipher::SymBlockCipherAlg::from(&block_cipher_instance)
            || tpm2_interface::TpmiAlgCipherMode::from(&block_cipher_instance) != tpm2_interface::TpmiAlgCipherMode::Cbc
        {
            return Err(nvfs_err_internal!());
        }
        Ok(Self {
            layout: layout.clone(),
            block_cipher_instance,
            next_iv: Vec::new(),
        })
    }

    /// Encrypt one extent in a sequence of an "encrypted extents" format
    /// entity's extents.
    ///
    /// Encrypt as much of `src` into `dst` as fits into the extent's payload.
    /// `src` will get advanced by the consumed amount, so that a `mut`
    /// reference to a single [iterator](CryptoWalkableIoSlicesIter)
    /// instance over all of the entity's plaintext can get conveniently
    /// passed to a series of `encrypt_one_extent()` invocations.
    ///
    /// Once the plaintext remaining in `src` becomes less than the payload that
    /// fits the destination extent, indicating that this is the "encrypted
    /// extents" format entity's last extent, the payload will get amended
    /// by a PKCS#7 padding. It is a logic error to invoke
    /// `encrypt_one_extent()` more than once with the remaining `src`
    /// length being less than the respective extent payload length.
    ///
    /// # Arguments:
    ///
    /// * `dst` - The current extent's ciphertext destination buffers.
    /// * `src` - The plaintext source buffers. Will get advanced by the amount
    ///   consumed.
    /// * `extent_allocation_blocks` - Size of the current extent in units of
    ///   [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2). Must be
    ///   consistent with `dst`'s total length.
    /// * `rng` - The [random number generator](rng::RngCoreDispatchable) used
    ///   for generating the IV and filling padding, if any.
    pub fn encrypt_one_extent<'a, 'b, DI: CryptoWalkableIoSlicesMutIter<'a>, SI: CryptoWalkableIoSlicesIter<'b>>(
        &mut self,
        mut dst: DI,
        mut src: SI,
        extent_allocation_blocks: layout::AllocBlockCount,
        rng: &mut dyn rng::RngCoreDispatchable,
    ) -> Result<(), NvFsError> {
        let is_first = self.next_iv.is_empty();
        let extent_len = self.layout.extent_len(extent_allocation_blocks)?;
        debug_assert_eq!(dst.total_len()?, extent_len);
        let effective_payload_len = self.layout.effective_payload_len(extent_allocation_blocks, is_first)?;
        debug_assert_eq!(
            effective_payload_len % self.block_cipher_instance.block_cipher_block_len(),
            0
        );

        let total_src_len = src.total_len()?;
        // Apply PKCS#7 padding if at the last extent, otherwise use all the extent's
        // available (and aligned) payload.
        let (src_len, src_padding_len) = if total_src_len < effective_payload_len {
            let mut src_padding_len = align_len_up_to_block_cipher_alg_block_len(
                total_src_len,
                self.block_cipher_instance.block_cipher_block_len(),
            )?
            .1;
            if src_padding_len == 0 {
                src_padding_len = self.block_cipher_instance.block_cipher_block_len();
            }
            // effective_payload_len is aligned to the block cipher block length.
            debug_assert!(total_src_len + src_padding_len <= effective_payload_len);
            (total_src_len, src_padding_len)
        } else {
            (effective_payload_len, 0)
        };
        let mut src_padding = Vec::<u8>::new();
        if src_padding_len != 0 {
            src_padding.try_reserve_exact(src_padding_len)?;
            src_padding.resize(src_padding_len, src_padding_len as u8);
        }

        let iv_len = self.layout.block_cipher_alg.cbc_iv_len;
        if is_first {
            self.next_iv = try_alloc_vec(iv_len)?;
            rng::rng_dyn_dispatch_generate(
                rng,
                io_slices::SingletonIoSliceMut::new(&mut self.next_iv).map_infallible_err(),
                None,
            )?;

            // Copy the IV to the destination.
            dst.as_ref()
                .take_exact(iv_len)
                .copy_from_iter_exhaustive(io_slices::SingletonIoSlice::new(&self.next_iv).map_infallible_err())
                .map_err(CryptoError::from)?;

            // Fill any alignment padding inbetween the IV and the beginning of the
            // encrypted data with random bytes. The padding at this location will
            // be empty in practice, but be consistent with the other entity
            // formats.
            rng::rng_dyn_dispatch_generate(
                rng,
                dst.as_ref()
                    .take_exact(extent_len - iv_len - effective_payload_len)
                    .map_err(CryptoError::from),
                None,
            )?;
        } else {
            // Fill any alignment padding inbetween the start of the destination buffer and
            // the beginning of the encrypted data with random bytes. The
            // padding at this location will be empty in practice, but be
            // consistent with the other entity formats.
            rng::rng_dyn_dispatch_generate(
                rng,
                dst.as_ref()
                    .take_exact(extent_len - effective_payload_len)
                    .map_err(CryptoError::from),
                None,
            )?;
        }
        debug_assert_eq!(dst.total_len()?, effective_payload_len);

        let mut iv_out = try_alloc_vec(iv_len)?;
        self.block_cipher_instance.encrypt(
            &self.next_iv,
            dst,
            src.as_ref()
                .take_exact(src_len)
                .map_err(CryptoError::from)
                .chain(io_slices::SingletonIoSlice::new(&src_padding).map_infallible_err())
                .chain(
                    io_slices::ZeroFilledIoSlices::new(effective_payload_len - src_len - src_padding_len)
                        .map_infallible_err(),
                ),
            Some(&mut iv_out),
        )?;
        self.next_iv = iv_out;

        Ok(())
    }
}

/// Decrypt an "encrypted extents" format entity.
///
/// The entity's extents are to be [decrypted](Self::decrypt_one_extent) one
/// after another in encryption order with the instance.
pub struct EncryptedExtentsDecryptionInstance {
    /// The [`EncryptedExtentsLayout`] describing the "encrypted extents" format
    /// entity.
    layout: EncryptedExtentsLayout,
    /// The the [CBC block cipher mode](tpm2_interface::TpmiAlgCipherMode::Cbc)
    /// [`SymBlockCipherModeDecryptionInstance`](symcipher::SymBlockCipherModeDecryptionInstance) to
    /// be used for decryptions.
    block_cipher_instance: symcipher::SymBlockCipherModeDecryptionInstance,
    /// The "carry-over" CBC extent to be used for the next extent in the
    /// sequence.
    next_iv: Vec<u8>,
}

impl EncryptedExtentsDecryptionInstance {
    /// Create an [`EncryptedExtentsDecryptionInstance`].
    ///
    /// # Arguments:
    ///
    /// * `layout` - The [`EncryptedExtentsLayout`] describing the "encrypted
    ///   extents" format entity.
    /// * `block_cipher_instance` - A
    ///   [`SymBlockCipherModeDecryptionInstance`](symcipher::SymBlockCipherModeDecryptionInstance)
    ///   to be used for decryption. Must be consistent with the
    ///   [`SymBlockCipherAlg`](symcipher::SymBlockCipherAlg) `layout` had been
    ///   created with, and been initialized for operating in the [CBC block
    ///   cipher mode](tpm2_interface::TpmiAlgCipherMode::Cbc).
    pub fn new(
        layout: EncryptedExtentsLayout,
        block_cipher_instance: symcipher::SymBlockCipherModeDecryptionInstance,
    ) -> Result<Self, NvFsError> {
        if layout.block_cipher_alg.block_cipher_alg != symcipher::SymBlockCipherAlg::from(&block_cipher_instance)
            || tpm2_interface::TpmiAlgCipherMode::from(&block_cipher_instance) != tpm2_interface::TpmiAlgCipherMode::Cbc
        {
            return Err(nvfs_err_internal!());
        }
        Ok(Self {
            layout,
            block_cipher_instance,
            next_iv: Vec::new(),
        })
    }

    /// Determine the maximum plaintext length the ciphertext in an extent of
    /// given length would decrypt to.
    ///
    /// Note that the extent of the specified length would in fact decrypt to a
    /// length exactly equal to the returned value. The actual payload
    /// obtained after stripping off the terminating PKCS#7 padding will be
    /// shorter in length though.
    ///
    /// # Arguments:
    ///
    /// * `extent_allocation_blocks` - The extent size in units of [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    /// * `is_first` - Whether or not the extent is the first in the entity's
    ///   sequence of extents.
    pub fn max_extent_decrypted_len(
        &self,
        extent_allocation_blocks: layout::AllocBlockCount,
        is_first: bool,
    ) -> Result<usize, NvFsError> {
        let total_effective_payload_len = self.layout.effective_payload_len(extent_allocation_blocks, is_first)?;
        debug_assert_eq!(
            total_effective_payload_len % self.block_cipher_instance.block_cipher_block_len(),
            0
        );
        Ok(total_effective_payload_len)
    }

    /// Determine the maximum plaintext length the ciphertext stored
    /// collectively in an "encrypted extents" format entity's extent would
    /// decrypt to.
    ///
    /// Note that the extents of the specified length would in fact collectively
    /// decrypt to a length exactly equal to the returned value. The actual
    /// payload obtained after stripping off the terminating PKCS#7 padding
    /// will be shorter in length though.
    ///
    /// # Arguments:
    ///
    /// * `extents` - [`Iterator`] yielding the entity's extents' lengths.
    pub fn max_extents_decrypted_len<EI: Iterator<Item = layout::PhysicalAllocBlockRange>>(
        &self,
        extents: EI,
    ) -> Result<usize, NvFsError> {
        let mut is_first = true;
        let mut total_effective_payload_len = 0usize;
        for extent in extents {
            total_effective_payload_len = match total_effective_payload_len
                .checked_add(self.max_extent_decrypted_len(extent.block_count(), is_first)?)
            {
                Some(total_effective_payload_len) => total_effective_payload_len,
                None => return Err(NvFsError::DimensionsNotSupported),
            };
            is_first = false;
        }
        Ok(total_effective_payload_len)
    }

    /// Decrypt one extent in a sequence of an "encrypted extents" format
    /// entity's extents.
    ///
    /// Decrypt `src` into `dst`. `dst` will get advanced by the decrypted
    /// plaintext's length, so that a `mut` reference to a single
    /// [iterator](CryptoWalkableIoSlicesMutIter) instance wrapping some
    /// destination buffers to eventually receive all of the entity's
    /// plaintext can get conveniently passed to a series of
    /// `decrypt_one_extent()` invocations.
    ///
    /// The entity's total decrypted plaintext, i.e. the concatention of all its
    /// extents' individual plaintexts, will have a PKCS#7 padding
    /// plus possibly some trailing zeros left and `decrypt_one_extent()` would
    /// not strip those. It's the caller's responsibility to eventually find
    /// the payload plaintext's end by means of [`check_cbc_padding()`].
    ///
    /// # Arguments:
    ///
    /// * `dst` - The plaintext destination buffers. Must have at least enough
    ///   capacity left to accomodate for the current extent's decrypted
    ///   payload, as determined by
    ///   [`max_extent_decrypted_len()`](Self::max_extent_decrypted_len).
    /// * `src` - The extent's ciphertext source buffers.
    /// * `extent_allocation_blocks` - Size of the current extent in units of
    ///   [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2). Must be
    ///   consistent with `src`'s total length.
    pub fn decrypt_one_extent<'a, 'b, DI: CryptoWalkableIoSlicesMutIter<'a>, SI: CryptoWalkableIoSlicesIter<'b>>(
        &mut self,
        mut dst: DI,
        mut src: SI,
        extent_allocation_blocks: layout::AllocBlockCount,
    ) -> Result<(), NvFsError> {
        let is_first = self.next_iv.is_empty();
        let extent_len = self.layout.extent_len(extent_allocation_blocks)?;
        debug_assert_eq!(src.total_len()?, extent_len);
        let effective_payload_len = self.layout.effective_payload_len(extent_allocation_blocks, is_first)?;
        debug_assert_eq!(
            effective_payload_len % self.block_cipher_instance.block_cipher_block_len(),
            0
        );
        let dst_len = dst.total_len()?;
        if dst_len < effective_payload_len {
            return Err(nvfs_err_internal!());
        }

        let iv_len = self.layout.block_cipher_alg.cbc_iv_len;
        if is_first {
            // Copy the IV from the source.
            self.next_iv = try_alloc_vec(iv_len)?;
            io_slices::SingletonIoSliceMut::new(&mut self.next_iv)
                .map_infallible_err()
                .copy_from_iter_exhaustive(src.as_ref().take_exact(iv_len))
                .map_err(CryptoError::from)?;

            // Skip over padding after the IV for aligning the encrypted data. It will be
            // empty in practice, but be consistent with the other formats.
            src.skip(extent_len - iv_len - effective_payload_len)
                .map_err(CryptoError::from)?
        } else {
            // Skip any alignment padding inbetween the start of the destination buffer and
            // the beginning of the encrypted data. The padding at this location
            // will be empty in practice, but be consistent with the other
            // entity formats.
            src.skip(extent_len - effective_payload_len)
                .map_err(CryptoError::from)?
        }
        debug_assert_eq!(src.total_len()?, effective_payload_len);

        let mut iv_out = try_alloc_vec(iv_len)?;
        self.block_cipher_instance.decrypt(
            &self.next_iv,
            dst.as_ref()
                .take_exact(effective_payload_len)
                .map_err(CryptoError::from),
            src,
            Some(&mut iv_out),
        )?;
        self.next_iv = iv_out;

        Ok(())
    }
}

/// Layout parameters for an "encrypted chained extents" format entity.
#[derive(Clone)]
pub struct EncryptedChainedExtentsLayout {
    /// Length of a header to be stored in plain at the beginning of the
    /// entity's first extent, like e.g. a magic.
    plain_data_extents_hdr_len: usize,
    /// The block cipher algorithm to use for the encryption or decryption
    /// respectively.
    block_cipher_alg: EncryptedEntityBlockCipherAlg,
    /// The HMAC hash algorithm to use for the entity's inline authentication,
    /// if any.
    inline_authentication_hmac_hash_alg: Option<EncryptedEntityInlineAuthenticationHmacHashAlg>,
    /// Alignment constraint on the entity's extents.
    extent_alignment_allocation_blocks_log2: u8,
    /// Verbatim copy of
    /// [`ImageLayout::allocation_block_size_128b_log2`](layout::ImageLayout::allocation_block_size_128b_log2).
    allocation_block_size_128b_log2: u8,
}

impl EncryptedChainedExtentsLayout {
    /// Create an [`EncryptedChainedExtentsLayout`] instance.
    ///
    /// # Arguments:
    ///
    /// * `plain_data_extents_hdr_len` - Length of a header to be stored in
    ///   plain at the beginning of the entity's first extent, like e.g. a
    ///   magic.
    /// * `block_cipher_alg` - The block cipher algorithm to use for the
    ///   encryption or decryption respectively.
    /// * `inline_authentication_hmac_hash_alg` - The HMAC hash algorithm to use
    ///   for the entity's inline authentication, if any.
    /// * `extent_alignment_allocation_blocks_log2` - Alignment constraint on
    ///   the entity's extents.
    /// * `allocation_block_size_128b_log2` - Verbatim copy of
    ///   [`ImageLayout::allocation_block_size_128b_log2`](layout::ImageLayout::allocation_block_size_128b_log2).
    pub fn new(
        plain_data_extents_hdr_len: usize,
        block_cipher_alg: symcipher::SymBlockCipherAlg,
        inline_authentication_hmac_hash_alg: Option<tpm2_interface::TpmiAlgHash>,
        extent_alignment_allocation_blocks_log2: u8,
        allocation_block_size_128b_log2: u8,
    ) -> Result<Self, NvFsError> {
        if extent_alignment_allocation_blocks_log2 as u32 > u64::BITS
            || 1u64 << extent_alignment_allocation_blocks_log2 > EncodedExtentPtr::MAX_EXTENT_ALLOCATION_BLOCKS
        {
            return Err(nvfs_err_internal!());
        }

        let block_cipher_alg = EncryptedEntityBlockCipherAlg::from(block_cipher_alg);

        if plain_data_extents_hdr_len
            .checked_add(block_cipher_alg.cbc_iv_len)
            .is_none()
        {
            return Err(NvFsError::DimensionsNotSupported);
        }

        Ok(Self {
            plain_data_extents_hdr_len,
            block_cipher_alg,
            inline_authentication_hmac_hash_alg: inline_authentication_hmac_hash_alg.map(
                |inline_authentication_hmac_hash_alg| {
                    EncryptedEntityInlineAuthenticationHmacHashAlg::from(inline_authentication_hmac_hash_alg)
                },
            ),
            extent_alignment_allocation_blocks_log2,
            allocation_block_size_128b_log2,
        })
    }

    /// Obtain an [`ExtentsLayout`] instance for allocating extents suitable
    /// for an "encrypted chained extents" format entity described by the
    /// [`EncryptedChainedExtentsLayout`].
    pub fn get_extents_layout(&self) -> Result<ExtentsLayout, NvFsError> {
        let extents_hdr_len = u32::try_from(self.plain_data_extents_hdr_len + self.block_cipher_alg.cbc_iv_len)
            .map_err(|_| NvFsError::DimensionsNotSupported)?;
        ExtentsLayout::new(
            Some(layout::AllocBlockCount::from(
                EncodedExtentPtr::MAX_EXTENT_ALLOCATION_BLOCKS,
            )),
            self.extent_alignment_allocation_blocks_log2,
            extents_hdr_len,
            self.inline_authentication_hmac_hash_alg
                .as_ref()
                .map(|inline_authentication_hmac_hash_alg| inline_authentication_hmac_hash_alg.digest_len as u32)
                .unwrap_or(0),
            EncodedExtentPtr::ENCODED_SIZE,
            u8::try_from(self.block_cipher_alg.block_cipher_block_len).map_err(|_| nvfs_err_internal!())?,
            self.allocation_block_size_128b_log2,
        )
    }

    /// Compute the length of one extent in units of bytes.
    ///
    /// # Arguments:
    ///
    /// * `extent_allocation_blocks` - Extent length in units of [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    fn extent_len(&self, extent_allocation_blocks: layout::AllocBlockCount) -> Result<usize, NvFsError> {
        allocation_blocks_to_len(extent_allocation_blocks, self.allocation_block_size_128b_log2 as u32)
    }

    /// Compute the effective payload length in units of bytes that can be
    /// stored in a given extent.
    ///
    /// Note that the final PKCS#7 padding is not being accounted for, i.e. it's
    /// being considered as part of the (total) payload length.
    ///
    /// # Arguments:
    ///
    /// * `extent_allocation_blocks` - Extent length in units of [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    /// * `is_first` - Whether or not the extent is the first one in an
    ///   "encrypted chained extents" format entity.
    fn effective_payload_len(
        &self,
        extent_allocation_blocks: layout::AllocBlockCount,
        is_first: bool,
    ) -> Result<usize, NvFsError> {
        let extents_hdr_len = if is_first {
            self.plain_data_extents_hdr_len + self.block_cipher_alg.cbc_iv_len
        } else {
            0
        };

        let inline_authentication_digest_len = self
            .inline_authentication_hmac_hash_alg
            .as_ref()
            .map(|inline_authentication_hmac_hash_alg| inline_authentication_hmac_hash_alg.digest_len)
            .unwrap_or(0);

        let total_hdr_len = extents_hdr_len
            .checked_add(inline_authentication_digest_len)
            .ok_or(NvFsError::DimensionsNotSupported)?;

        let extent_len = self.extent_len(extent_allocation_blocks)?;
        if total_hdr_len > extent_len {
            return Err(nvfs_err_internal!());
        }

        align_len_down_to_block_cipher_alg_block_len(
            extent_len - total_hdr_len,
            self.block_cipher_alg.block_cipher_block_len,
        )
        .map(|l| l.0)
    }
}

/// Authentication subject identifiers to be used for associated data to be
/// authenticated with "encrypted chained extents" format entities' inline
/// authentication, if any.
#[repr(u8)]
pub enum EncryptedChainedExtentsAssociatedDataAuthSubjectDataSuffix {
    /// The entity in "encrypted chained extents" format is the journal log.
    JournalLog = 1,
    /// The entity in "encrypted chained extents" format is some (special)
    /// inode's associated extents list.
    InodeExtentsListPreauthCcaProtection = 2,
}

/// Encrypt an "encrypted chained extents" format entity.
///
/// The entity's extents are to be [encrypted](Self::encrypt_one_extent) one
/// after another with the instance, supplying the link to the next extent in
/// the linked list for each.
pub struct EncryptedChainedExtentsEncryptionInstance {
    /// The [`EncryptedChainedExtentsLayout`] describing the "encrypted chained
    /// extents" format entity.
    layout: EncryptedChainedExtentsLayout,
    /// The the [CBC block cipher mode](tpm2_interface::TpmiAlgCipherMode::Cbc)
    /// [`SymBlockCipherModeEncryptionInstance`](symcipher::SymBlockCipherModeEncryptionInstance) to
    /// be used for encryptions.
    block_cipher_instance: symcipher::SymBlockCipherModeEncryptionInstance,
    /// The "carry-over" CBC extent to be used for the next extent in the
    /// sequence.
    next_iv: Vec<u8>,
    /// If inline authentication is enabled: a pair of a
    /// [`HmacInstance`](hash::HmacInstance) in its initial state and the
    /// entity's previous extents' associated digest, if any.
    inline_authentication: Option<(hash::HmacInstance, Vec<u8>)>,
}

impl EncryptedChainedExtentsEncryptionInstance {
    /// Create an [`EncryptedChainedExtentsEncryptionInstance`].
    ///
    /// # Arguments:
    ///
    /// * `layout` - The [`EncryptedChainedExtentsLayout`] describing the
    ///   "encrypted chained extents" format entity.
    /// * `block_cipher_instance` - A
    ///   [`SymBlockCipherModeEncryptionInstance`](symcipher::SymBlockCipherModeEncryptionInstance)
    ///   to be used for encryption. Must be consistent with the
    ///   [`SymBlockCipherAlg`](symcipher::SymBlockCipherAlg) `layout` had been
    ///   created with, and been initialized for operating in the [CBC block
    ///   cipher mode](tpm2_interface::TpmiAlgCipherMode::Cbc).
    /// * `inline_authentication_hmac_instance` - Optional
    ///   [`HmacInstance`](hash::HmacInstance) in its initial state. Must be
    ///   provided if and only if some [`hash
    ///   algorithm`](tpm2_interface::TpmiAlgHash) to be used for the inline
    ///   authentication had been specified at the creation of `layout`, and
    ///   must be consistent with that if so.
    pub fn new(
        layout: &EncryptedChainedExtentsLayout,
        block_cipher_instance: symcipher::SymBlockCipherModeEncryptionInstance,
        inline_authentication_hmac_instance: Option<hash::HmacInstance>,
    ) -> Result<Self, NvFsError> {
        if layout.block_cipher_alg.block_cipher_alg != symcipher::SymBlockCipherAlg::from(&block_cipher_instance)
            || tpm2_interface::TpmiAlgCipherMode::from(&block_cipher_instance) != tpm2_interface::TpmiAlgCipherMode::Cbc
        {
            return Err(nvfs_err_internal!());
        }

        match layout.inline_authentication_hmac_hash_alg.as_ref() {
            Some(inline_authentication_hmac_hash_alg) => {
                match inline_authentication_hmac_instance.as_ref() {
                    Some(inline_authentication_hmac_instance) => {
                        if inline_authentication_hmac_hash_alg.hmac_hash_alg
                            != tpm2_interface::TpmiAlgHash::from(inline_authentication_hmac_instance)
                        {
                            return Err(nvfs_err_internal!());
                        }
                    }
                    None => {
                        // The authentication digest must always get updated at encryption.
                        return Err(nvfs_err_internal!());
                    }
                }
            }
            None => {
                // Inline authentication not specifed for the layout, yet an instance has been
                // provided.
                if inline_authentication_hmac_instance.is_some() {
                    return Err(nvfs_err_internal!());
                }
            }
        }

        Ok(Self {
            layout: layout.clone(),
            block_cipher_instance,
            next_iv: Vec::new(),
            inline_authentication: inline_authentication_hmac_instance
                .map(|inline_authentication_hmac_instance| (inline_authentication_hmac_instance, Vec::<u8>::new())),
        })
    }

    /// Encrypt one extent in a sequence of an "encrypted chained extents"
    /// format entity's extents.
    ///
    /// Encrypt as much of `src` into `dst` as fits into the extent's payload.
    /// `src` will get advanced by the consumed amount, so that a `mut`
    /// reference to a single [iterator](CryptoWalkableIoSlicesIter)
    /// instance over all of the entity's plaintext can get conveniently
    /// passed to a series of `encrypt_one_extent()` invocations.
    ///
    /// Once the plaintext remaining in `src` becomes less than the payload that
    /// fits the destination extent, indicating that this is the "encrypted
    /// extents" format entity's last extent, the payload will get amended
    /// by a PKCS#7 padding. It is a logic error to invoke
    /// `encrypt_one_extent()` more than once with the remaining `src`
    /// length being less than the respective extent payload length.
    ///
    /// If some non-zero plain header length had been specified at the creation
    /// of the associated [`EncryptedChainedExtentsLayout`], then it is
    /// expected that a header of that length has been written to the
    /// beginning of the entity's first extent's `dst` already. If inline
    /// authentication is enabled for the entity, then that header will be
    /// considered in the authentication.
    ///
    /// # Arguments:
    ///
    /// * `dst` - The current extent's ciphertext destination buffers.
    /// * `src` - The plaintext source buffers. Will get advanced by the amount
    ///   consumed.
    /// * `authenticated_associated_data` - Additional data to be considered for
    ///   the inline authentication if enabled for the entity, ignored
    ///   otherwise.
    /// * `extent_allocation_blocks` - Size of the current extent in units of
    ///   [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2). Must be
    ///   consistent with `dst`'s total length.
    /// * `next_chained_extent` - The location of the next extent in the
    ///   sequence of the "encryted chained extents" format entity's extents.
    /// * `rng` - The [random number generator](rng::RngCoreDispatchable) used
    ///   for generating the IV and filling padding, if any.
    pub fn encrypt_one_extent<
        'a,
        'b,
        'c,
        DI: CryptoMutPeekableIoSlicesMutIter<'a>,
        SI: CryptoWalkableIoSlicesIter<'b>,
        AI: CryptoWalkableIoSlicesIter<'c>,
    >(
        &mut self,
        mut dst: DI,
        mut src: SI,
        authenticated_associated_data: AI,
        extent_allocation_blocks: layout::AllocBlockCount,
        next_chained_extent: Option<&layout::PhysicalAllocBlockRange>,
        rng: &mut dyn rng::RngCoreDispatchable,
    ) -> Result<(), NvFsError> {
        let is_first = self.next_iv.is_empty();
        let extent_len = self.layout.extent_len(extent_allocation_blocks)?;
        debug_assert_eq!(dst.total_len()?, extent_len);
        let total_effective_payload_len = self.layout.effective_payload_len(extent_allocation_blocks, is_first)?;
        debug_assert_eq!(
            total_effective_payload_len % self.block_cipher_instance.block_cipher_block_len(),
            0
        );

        if total_effective_payload_len < EncodedExtentPtr::ENCODED_SIZE as usize
            || !is_first && total_effective_payload_len == EncodedExtentPtr::ENCODED_SIZE as usize
        {
            return Err(nvfs_err_internal!());
        }
        let available_effective_payload_len = total_effective_payload_len - EncodedExtentPtr::ENCODED_SIZE as usize;

        let total_src_len = src.total_len()?;
        // Apply PKCS#7 padding if at the last extent, otherwise use all the extent's
        // available payload.
        let (src_len, src_padding_len) = if total_src_len < available_effective_payload_len {
            if next_chained_extent.is_some() {
                return Err(nvfs_err_internal!());
            }
            let mut src_padding_len = align_len_up_to_block_cipher_alg_block_len(
                total_src_len + EncodedExtentPtr::ENCODED_SIZE as usize,
                self.block_cipher_instance.block_cipher_block_len(),
            )?
            .1;
            if src_padding_len == 0 {
                src_padding_len = self.block_cipher_instance.block_cipher_block_len();
            }
            // total_effective_payload_len is aligned to the block cipher block length.
            debug_assert!(total_src_len + src_padding_len <= available_effective_payload_len);
            (total_src_len, src_padding_len)
        } else {
            if next_chained_extent.is_none() {
                return Err(nvfs_err_internal!());
            }
            (available_effective_payload_len, 0)
        };
        let mut src_padding = Vec::<u8>::new();
        if src_padding_len != 0 {
            src_padding.try_reserve_exact(src_padding_len)?;
            src_padding.resize(src_padding_len, src_padding_len as u8);
        }

        let inline_authentication_digest_len = self
            .inline_authentication
            .as_ref()
            .map(|inline_authentication| inline_authentication.0.digest_len())
            .unwrap_or(0);

        // Decouple from the dst iterator for encryption, a second pass will
        // be needed for the inline authentication, if any.
        let mut dst_encrypt = dst.decoupled_borrow_mut();
        if is_first {
            dst_encrypt
                .skip(self.layout.plain_data_extents_hdr_len)
                .map_err(CryptoError::from)?;
        }
        dst_encrypt
            .skip(inline_authentication_digest_len)
            .map_err(CryptoError::from)?;

        let iv_len = self.layout.block_cipher_alg.cbc_iv_len;
        if is_first {
            self.next_iv = try_alloc_vec(iv_len)?;
            rng::rng_dyn_dispatch_generate(
                rng,
                io_slices::SingletonIoSliceMut::new(&mut self.next_iv).map_infallible_err(),
                None,
            )?;

            // Copy the IV to the destination.
            dst_encrypt
                .as_ref()
                .take_exact(iv_len)
                .copy_from_iter_exhaustive(io_slices::SingletonIoSlice::new(&self.next_iv).map_infallible_err())
                .map_err(CryptoError::from)?;

            // Fill any alignment padding inbetween the IV and the beginning of the
            // encrypted data with random bytes.
            rng::rng_dyn_dispatch_generate(
                rng,
                dst_encrypt
                    .as_ref()
                    .take_exact(
                        extent_len
                            - self.layout.plain_data_extents_hdr_len
                            - inline_authentication_digest_len
                            - iv_len
                            - total_effective_payload_len,
                    )
                    .map_err(CryptoError::from),
                None,
            )?;
        } else {
            // Fill any alignment padding inbetween the start of the destination buffer and
            // the beginning of the encrypted data with random bytes.
            rng::rng_dyn_dispatch_generate(
                rng,
                dst_encrypt
                    .as_ref()
                    .take_exact(extent_len - inline_authentication_digest_len - total_effective_payload_len)
                    .map_err(CryptoError::from),
                None,
            )?;
        }
        debug_assert_eq!(dst_encrypt.total_len()?, total_effective_payload_len);

        let encoded_extent_ptr = EncodedExtentPtr::encode(next_chained_extent, false)?;

        let mut iv_out = try_alloc_vec(iv_len)?;
        self.block_cipher_instance.encrypt(
            &self.next_iv,
            dst_encrypt,
            io_slices::SingletonIoSlice::new(encoded_extent_ptr.deref())
                .map_infallible_err()
                .chain(src.as_ref().take_exact(src_len).map_err(CryptoError::from))
                .chain(io_slices::SingletonIoSlice::new(&src_padding).map_infallible_err())
                .chain(
                    io_slices::ZeroFilledIoSlices::new(available_effective_payload_len - src_len - src_padding_len)
                        .map_infallible_err(),
                ),
            Some(&mut iv_out),
        )?;
        // Don't update self.next_iv with iv_out until after the authentication digest
        // has been computed below.

        // Now compute and serialize the inline authentication digest, if requested.
        if let Some(inline_authentication) = self.inline_authentication.as_mut() {
            let (inline_authentication_hmac_instance, prev_extent_inline_authentication_digest) = inline_authentication;

            let mut inline_authentication_hmac_instance = inline_authentication_hmac_instance.try_clone()?;
            let mut dst_auth = dst.decoupled_borrow();
            if is_first {
                inline_authentication_hmac_instance.update(
                    dst_auth
                        .as_ref()
                        .take_exact(self.layout.plain_data_extents_hdr_len)
                        .map_err(CryptoError::from),
                )?;

                // The first extent has virtual zeroes filled into the authentication digest
                // region.
                inline_authentication_hmac_instance.update(
                    io_slices::ZeroFilledIoSlices::new(inline_authentication_digest_len).map_infallible_err(),
                )?;
                dst_auth
                    .skip(inline_authentication_digest_len)
                    .map_err(CryptoError::from)?;
                // The position is now at the IV serialized above.
            } else {
                // With respect to CCA-protection, an extent within the extent
                // chain is interpreted as a single, isolated
                // ciphertext. So for that, authentication of
                // the IV in combination with the extent's to be
                // decrypted contents is needed.
                //
                // Including the previous extent's authentication digest
                // provides integrity protection, but *not*
                // authentication of the overall extent chain as a whole (or
                // it does, but only at the security level of collision
                // resistance rather than that of the MAC, i.e.
                // at approx. a half). For the Journal Record Area integrity
                // protection is highly desired, and we're getting it almost for
                // free by implementing this hash chain on top
                // of the authentication needed anyway. For
                // simplicity, chain the digests unconditionally, not only when
                // integrity protection is desired.
                inline_authentication_hmac_instance.update(
                    io_slices::SingletonIoSlice::new(prev_extent_inline_authentication_digest).map_infallible_err(),
                )?;
                dst_auth
                    .skip(inline_authentication_digest_len)
                    .map_err(CryptoError::from)?;
            }

            // Digest the encrypted data, including any randomized alignment padding. For
            // the first extent, this also includes the IV.
            inline_authentication_hmac_instance.update(dst_auth)?;

            // Now digest the context suffix.
            // For continuation extents, this includes the IV.
            if !is_first {
                inline_authentication_hmac_instance
                    .update(io_slices::SingletonIoSlice::new(&self.next_iv).map_infallible_err())?;
            }

            // Then comes the associated data, if any.
            let authenticated_associated_data_len = u64::try_from(authenticated_associated_data.total_len()?)
                .map_err(|_| nvfs_err_internal!())?
                .to_le_bytes();
            inline_authentication_hmac_instance.update(authenticated_associated_data)?;

            // The remainder authentication context suffix uniquely encodes the semantics of
            // the rest.
            let auth_context_subject_id_suffix = [
                !is_first as u8,
                0u8, // Version of the authenticated data's format.
                AuthSubjectDataSuffix::EncryptionEntityChainedExtents as u8,
            ];
            let auth_context_enc_params = {
                let block_cipher_alg = symcipher::SymBlockCipherAlg::from(&self.block_cipher_instance);
                let (block_cipher_alg_id, block_cipher_key_size) =
                    <(tpm2_interface::TpmiAlgSymObject, u16)>::from(&block_cipher_alg);
                let mut auth_context_enc_params =
                    [0u8; tpm2_interface::TpmiAlgSymObject::marshalled_size() as usize + mem::size_of::<u16>()];
                let context_buf = block_cipher_alg_id
                    .marshal(&mut auth_context_enc_params)
                    .map_err(|_| nvfs_err_internal!())?;
                tpm2_interface::marshal_u16(context_buf, block_cipher_key_size).map_err(|_| nvfs_err_internal!())?;
                auth_context_enc_params
            };
            inline_authentication_hmac_instance.update(
                io_slices::BuffersSliceIoSlicesIter::new(&[
                    authenticated_associated_data_len.as_slice(),
                    auth_context_enc_params.as_slice(),
                    auth_context_subject_id_suffix.as_slice(),
                ])
                .map_infallible_err(),
            )?;

            if prev_extent_inline_authentication_digest.is_empty() {
                *prev_extent_inline_authentication_digest = try_alloc_vec(inline_authentication_digest_len)?;
            }
            // Produce the digest and copy it to the destination.
            inline_authentication_hmac_instance
                .finalize_into(prev_extent_inline_authentication_digest.as_mut_slice())?;
            if is_first {
                dst.skip(self.layout.plain_data_extents_hdr_len)
                    .map_err(CryptoError::from)?;
            }
            dst.as_ref()
                .take_exact(inline_authentication_digest_len)
                .map_err(CryptoError::from)
                .copy_from_iter_exhaustive(
                    io_slices::SingletonIoSlice::new(prev_extent_inline_authentication_digest).map_infallible_err(),
                )
                .map_err(CryptoError::from)?;
        }
        debug_assert_eq!(
            dst.total_len()?,
            extent_len
                - if is_first {
                    self.layout.plain_data_extents_hdr_len
                } else {
                    0
                }
                - inline_authentication_digest_len
        );
        // Now that the authentication digest has been computed, the IV to be used for
        // the next continuation extent can get stored away.
        self.next_iv = iv_out;

        // Finally, advance the original iterator to past the processed position in case
        // the user somehow relies on it.
        dst.skip(
            extent_len
                - if is_first {
                    self.layout.plain_data_extents_hdr_len
                } else {
                    0
                }
                - inline_authentication_digest_len,
        )
        .map_err(CryptoError::from)?;
        debug_assert!(dst.is_empty()?);

        Ok(())
    }
}

/// Decrypt an "encrypted chained extents" format entity.
///
/// The entity's extents are to be [decrypted](Self::decrypt_one_extent) one
/// after another in encryption order with the instance. Note that the
/// decryption of one extents yields the pointer to the next, if any.
pub struct EncryptedChainedExtentsDecryptionInstance {
    layout: EncryptedChainedExtentsLayout,
    block_cipher_instance: symcipher::SymBlockCipherModeDecryptionInstance,
    next_iv: Vec<u8>,
    inline_authentication: Option<(hash::HmacInstance, Vec<u8>)>,
}

impl EncryptedChainedExtentsDecryptionInstance {
    /// Create an [`EncryptedChainedExtentsDecryptionInstance`].
    ///
    /// # Arguments:
    ///
    /// * `layout` - The [`EncryptedChainedExtentsLayout`] describing the
    ///   "encrypted chained extents" format entity.
    /// * `block_cipher_instance` - A
    ///   [`SymBlockCipherModeDecryptionInstance`](symcipher::SymBlockCipherModeDecryptionInstance)
    ///   to be used for decryption. Must be consistent with the
    ///   [`SymBlockCipherAlg`](symcipher::SymBlockCipherAlg) `layout` had been
    ///   created with, and been initialized for operating in the [CBC block
    ///   cipher mode](tpm2_interface::TpmiAlgCipherMode::Cbc).
    /// * `inline_authentication_hmac_instance` - Optional
    ///   [`HmacInstance`](hash::HmacInstance) in its initial state. Must be
    ///   provided only if some [`hash algorithm`](tpm2_interface::TpmiAlgHash)
    ///   to be used for the inline authentication had been specified at the
    ///   creation of `layout`, and must be consistent with that. The entity's
    ///   inline authentication will get verified in the course of decryption if
    ///   provided.
    pub fn new(
        layout: &EncryptedChainedExtentsLayout,
        block_cipher_instance: symcipher::SymBlockCipherModeDecryptionInstance,
        inline_authentication_hmac_instance: Option<hash::HmacInstance>,
    ) -> Result<Self, NvFsError> {
        if layout.block_cipher_alg.block_cipher_alg != symcipher::SymBlockCipherAlg::from(&block_cipher_instance)
            || tpm2_interface::TpmiAlgCipherMode::from(&block_cipher_instance) != tpm2_interface::TpmiAlgCipherMode::Cbc
        {
            return Err(nvfs_err_internal!());
        }

        match layout.inline_authentication_hmac_hash_alg.as_ref() {
            Some(inline_authentication_hmac_hash_alg) => {
                if let Some(inline_authentication_hmac_instance) = inline_authentication_hmac_instance.as_ref() {
                    if inline_authentication_hmac_hash_alg.hmac_hash_alg
                        != tpm2_interface::TpmiAlgHash::from(inline_authentication_hmac_instance)
                    {
                        return Err(nvfs_err_internal!());
                    }
                }
            }
            None => {
                // Inline authentication not specifed for the layout, yet an instance has been
                // provided.
                if inline_authentication_hmac_instance.is_some() {
                    return Err(nvfs_err_internal!());
                }
            }
        }

        Ok(Self {
            layout: layout.clone(),
            block_cipher_instance,
            next_iv: Vec::new(),
            inline_authentication: inline_authentication_hmac_instance
                .map(|inline_authentication_hmac_instance| (inline_authentication_hmac_instance, Vec::<u8>::new())),
        })
    }

    /// Determine the maximum plaintext length the ciphertext in an extent of
    /// given length would decrypt to.
    ///
    /// Note that the extent of the specified length would in fact decrypt to a
    /// length exactly equal to the returned value. The actual payload
    /// obtained after stripping off the terminating PKCS#7 padding will be
    /// shorter in length though.
    ///
    /// # Arguments:
    ///
    /// * `extent_allocation_blocks` - The extent size in units of [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    /// * `is_first` - Whether or not the extent is the first in the entity's
    ///   sequence of extents.
    pub fn max_extent_decrypted_len(
        &self,
        extent_allocation_blocks: layout::AllocBlockCount,
        is_first: bool,
    ) -> Result<usize, NvFsError> {
        let total_effective_payload_len = self.layout.effective_payload_len(extent_allocation_blocks, is_first)?;
        debug_assert_eq!(
            total_effective_payload_len % self.block_cipher_instance.block_cipher_block_len(),
            0
        );

        if total_effective_payload_len < EncodedExtentPtr::ENCODED_SIZE as usize
            || !is_first && total_effective_payload_len == EncodedExtentPtr::ENCODED_SIZE as usize
        {
            return Err(nvfs_err_internal!());
        }
        Ok(total_effective_payload_len - EncodedExtentPtr::ENCODED_SIZE as usize)
    }

    /// Decrypt one extent in a sequence of an "encrypted chained extents"
    /// format entity's extents.
    ///
    /// Decrypt `src` into `dst` and return the next chained extent's location,
    /// if any.
    ///
    /// `dst` will get advanced by the decrypted
    /// plaintext's length, so that a `mut` reference to a single
    /// [iterator](CryptoWalkableIoSlicesMutIter) instance wrapping some
    /// destination buffers to eventually receive all of the entity's
    /// plaintext can get conveniently passed to a series of
    /// `decrypt_one_extent()` invocations.
    ///
    /// The entity's total decrypted plaintext, i.e. the concatention of all its
    /// extents' individual plaintexts, will have a PKCS#7 padding
    /// plus possibly some trailing zeros left and `decrypt_one_extent()` would
    /// not strip those. It's the caller's responsibility to eventually find
    /// the payload plaintext's end by means of [`check_cbc_padding()`].
    ///
    /// If some non-zero plain header length had been specified at the creation
    /// of the associated [`EncryptedChainedExtentsLayout`], then it is
    /// expected that a header of that length is stored to the beginning of
    /// the entity's first extent's `src`. If inline authentication is
    /// enabled, then that header will be considered for verifying the
    /// authentication.
    ///
    /// # Arguments:
    ///
    /// * `dst` - The plaintext destination buffers. Must have at least enough
    ///   capacity left to accomodate for the current extent's decrypted
    ///   payload, as determined by
    ///   [`max_extent_decrypted_len()`](Self::max_extent_decrypted_len).
    /// * `src` - The extent's ciphertext source buffers.
    /// * `authenticated_associated_data` - Additional data to be considered for
    ///   the inline authentication if enabled for the entity, ignored
    ///   otherwise.
    /// * `extent_allocation_blocks` - Size of the current extent in units of
    ///   [Allocation
    ///   Blocks](layout::ImageLayout::allocation_block_size_128b_log2). Must be
    ///   consistent with `src`'s total length.
    pub fn decrypt_one_extent<
        'a,
        'b,
        'c,
        DI: CryptoMutPeekableIoSlicesMutIter<'a>,
        SI: CryptoPeekableIoSlicesIter<'b>,
        AI: CryptoWalkableIoSlicesIter<'c>,
    >(
        &mut self,
        mut dst: DI,
        mut src: SI,
        authenticated_associated_data: AI,
        extent_allocation_blocks: layout::AllocBlockCount,
    ) -> Result<Option<layout::PhysicalAllocBlockRange>, NvFsError> {
        let is_first = self.next_iv.is_empty();
        let extent_len = self.layout.extent_len(extent_allocation_blocks)?;
        debug_assert_eq!(src.total_len()?, extent_len);
        let total_effective_payload_len = self.layout.effective_payload_len(extent_allocation_blocks, is_first)?;
        debug_assert_eq!(
            total_effective_payload_len % self.block_cipher_instance.block_cipher_block_len(),
            0
        );

        if total_effective_payload_len < EncodedExtentPtr::ENCODED_SIZE as usize
            || !is_first && total_effective_payload_len == EncodedExtentPtr::ENCODED_SIZE as usize
        {
            return Err(nvfs_err_internal!());
        }
        let available_effective_payload_len = total_effective_payload_len - EncodedExtentPtr::ENCODED_SIZE as usize;

        let dst_len = dst.total_len()?;
        if dst_len < available_effective_payload_len {
            return Err(nvfs_err_internal!());
        }

        // Unconditionally obtain the inline authentication digest length from the
        // layout in case verification is not enabled for this decryption
        // request (like for pre-auth CCA protection when proper authentication
        // is available).
        let inline_authentication_digest_len = self
            .layout
            .inline_authentication_hmac_hash_alg
            .as_ref()
            .map(|inline_authentication_hmac_hash_alg| inline_authentication_hmac_hash_alg.digest_len)
            .unwrap_or(0);

        // Verify the inline authentication digest, if requested.
        if let Some(inline_authentication) = self.inline_authentication.as_mut() {
            let (inline_authentication_hmac_instance, prev_extent_inline_authentication_digest) = inline_authentication;

            let mut inline_authentication_hmac_instance = inline_authentication_hmac_instance.try_clone()?;

            let mut src_auth = src.decoupled_borrow();
            if is_first {
                inline_authentication_hmac_instance.update(
                    src_auth
                        .as_ref()
                        .take_exact(self.layout.plain_data_extents_hdr_len)
                        .map_err(CryptoError::from),
                )?;

                // The first extent has virtual zeroes filled into the authentication digest
                // region.
                inline_authentication_hmac_instance.update(
                    io_slices::ZeroFilledIoSlices::new(inline_authentication_digest_len).map_infallible_err(),
                )?;
                src_auth
                    .skip(inline_authentication_digest_len)
                    .map_err(CryptoError::from)?;
                // The position is now at the IV.
            } else {
                // C.f. the comment in the encryption routine about the rationale for including
                // the preceding extent's authentication digest.
                inline_authentication_hmac_instance.update(
                    io_slices::SingletonIoSlice::new(prev_extent_inline_authentication_digest).map_infallible_err(),
                )?;
                src_auth
                    .skip(inline_authentication_digest_len)
                    .map_err(CryptoError::from)?;
            }

            // Digest the encrypted data, including any randomized alignment padding. For
            // the first extent, this also includes the IV.
            inline_authentication_hmac_instance.update(src_auth)?;

            // Now digest the context suffix.
            // For continuation extents, this includes the IV.
            if !is_first {
                inline_authentication_hmac_instance
                    .update(io_slices::SingletonIoSlice::new(&self.next_iv).map_infallible_err())?;
            }

            // Then comes the associated data, if any.
            let authenticated_associated_data_len = u64::try_from(authenticated_associated_data.total_len()?)
                .map_err(|_| nvfs_err_internal!())?
                .to_le_bytes();
            inline_authentication_hmac_instance.update(authenticated_associated_data)?;

            // The remainder authentication context suffix uniquely encodes the semantics of
            // the rest.
            let auth_context_subject_id_suffix = [
                !is_first as u8,
                0u8, // Version of the authenticated data's format.
                AuthSubjectDataSuffix::EncryptionEntityChainedExtents as u8,
            ];
            let auth_context_enc_params = {
                let block_cipher_alg = symcipher::SymBlockCipherAlg::from(&self.block_cipher_instance);
                let (block_cipher_alg_id, block_cipher_key_size) =
                    <(tpm2_interface::TpmiAlgSymObject, u16)>::from(&block_cipher_alg);
                let mut auth_context_enc_params =
                    [0u8; tpm2_interface::TpmiAlgSymObject::marshalled_size() as usize + mem::size_of::<u16>()];
                let context_buf = block_cipher_alg_id
                    .marshal(&mut auth_context_enc_params)
                    .map_err(|_| nvfs_err_internal!())?;
                tpm2_interface::marshal_u16(context_buf, block_cipher_key_size).map_err(|_| nvfs_err_internal!())?;
                auth_context_enc_params
            };
            inline_authentication_hmac_instance.update(
                io_slices::BuffersSliceIoSlicesIter::new(&[
                    authenticated_associated_data_len.as_slice(),
                    auth_context_enc_params.as_slice(),
                    auth_context_subject_id_suffix.as_slice(),
                ])
                .map_infallible_err(),
            )?;

            if prev_extent_inline_authentication_digest.is_empty() {
                *prev_extent_inline_authentication_digest = try_alloc_vec(inline_authentication_digest_len)?;
            }
            // Produce the digest and compare with what's expected.
            inline_authentication_hmac_instance
                .finalize_into(prev_extent_inline_authentication_digest.as_mut_slice())?;

            if is_first {
                src.skip(self.layout.plain_data_extents_hdr_len)
                    .map_err(CryptoError::from)?;
            }
            if src
                .as_ref()
                .take_exact(inline_authentication_digest_len)
                .map_err(CryptoError::from)
                .ct_eq_with_iter(
                    io_slices::SingletonIoSlice::new(prev_extent_inline_authentication_digest).map_infallible_err(),
                )?
                .unwrap()
                == 0
            {
                return Err(NvFsError::AuthenticationFailure);
            }
        } else {
            // Don't authenticate, but skip the iterator over the inline authentication
            // digest.
            if is_first {
                src.skip(self.layout.plain_data_extents_hdr_len)
                    .map_err(CryptoError::from)?;
            }
            src.skip(inline_authentication_digest_len).map_err(CryptoError::from)?;
        }
        debug_assert_eq!(
            src.total_len()?,
            extent_len
                - inline_authentication_digest_len
                - if is_first {
                    self.layout.plain_data_extents_hdr_len
                } else {
                    0
                }
        );

        let iv_len = self.layout.block_cipher_alg.cbc_iv_len;
        if is_first {
            // Copy the IV out from the first source extent.
            self.next_iv = try_alloc_vec(iv_len)?;
            io_slices::SingletonIoSliceMut::new(&mut self.next_iv)
                .map_infallible_err()
                .copy_from_iter_exhaustive(src.as_ref().take_exact(iv_len).map_err(CryptoError::from))
                .map_err(CryptoError::from)?;
        }

        // Skip over any alignment inserted before the encrypted data.
        src.skip(
            extent_len
                - inline_authentication_digest_len
                - if is_first {
                    self.layout.plain_data_extents_hdr_len + iv_len
                } else {
                    0
                }
                - total_effective_payload_len,
        )
        .map_err(CryptoError::from)?;
        debug_assert_eq!(src.total_len()?, total_effective_payload_len);

        // And decrypt.
        let mut encoded_next_chained_extent = [0u8; EncodedExtentPtr::ENCODED_SIZE as usize];

        let mut iv_out = try_alloc_vec(iv_len)?;
        self.block_cipher_instance.decrypt(
            &self.next_iv,
            io_slices::SingletonIoSliceMut::new(&mut encoded_next_chained_extent)
                .map_infallible_err()
                .chain(
                    dst.as_ref()
                        .take_exact(available_effective_payload_len)
                        .map_err(CryptoError::from),
                ),
            src,
            Some(&mut iv_out),
        )?;
        self.next_iv = iv_out;

        let next_chained_extent = EncodedExtentPtr::from(encoded_next_chained_extent)
            .decode(self.layout.allocation_block_size_128b_log2 as u32)?;
        let next_chained_extent = match next_chained_extent {
            Some((next_chained_extent, is_indirect)) => {
                // Chained continuation extents are always direct.
                if is_indirect {
                    return Err(NvFsError::from(CocoonFsFormatError::InvalidExtents));
                }
                Some(next_chained_extent)
            }
            None => None,
        };

        Ok(next_chained_extent)
    }
}
