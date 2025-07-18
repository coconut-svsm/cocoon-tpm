// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

extern crate alloc;
use alloc::vec::Vec;

use crate::{
    crypto::{rng, symcipher, CryptoError},
    fs::{
        cocoonfs::{layout, CocoonFsFormatError},
        NvFsError,
    },
    nvfs_err_internal, tpm2_interface,
    utils_common::{
        alloc::try_alloc_zeroizing_vec,
        io_slices::{self, IoSlicesIterCommon as _, IoSlicesMutIter as _},
        zeroize,
    },
};
use core::{convert::TryFrom as _, mem};

/// Disguise the identity of Journal Data Copy
/// [`IO blocks`](layout::ImageLayout::io_block_allocation_blocks_log2).
///
/// The journal stages data updates in units of
/// [`IO blocks`](layout::ImageLayout::io_block_allocation_blocks_log2)
/// before copying the contents over to their target destination.
/// If these journal staging copies had been made verbatim, it would enable an
/// adversary to easily identify them as such by simply attempting to match the
/// staging copy candiates' contents to potential target locations: either in
/// full after the transaction had been applied or by searching for partial
/// matches.
///
/// Note that this type of content matching attack is of concern primarily for
/// data at rest: if an adversary was able to observe write patterns during
/// transaction preparation, there would certainly exist more straight-forward
/// strategies of revealing the Journal Data Copy
/// [`IO blocks`](layout::ImageLayout::io_block_allocation_blocks_log2)'
/// identities. However, as those copies might potentially stay around for a
/// long time after the original transaction and perhaps even subsequent ones
/// have completed, the "data at rest" scenario is still of real practical
/// relevance.
///
/// To counter this sort of Journal Data Copy
/// [`IO blocks`](layout::ImageLayout::io_block_allocation_blocks_log2)
/// identification attack by content matching as outlined above, provide support
/// for disguising their identity by obscuring their contents. This is achieved
/// by unauthenticated CBC-ESSIV encryption with a one-time key generated
/// freshly for each new transaction. It should be stressed for clarity at this
/// point, that the plaintext inputs to this CBC-ESSIV encryption are actually
/// the ciphertext outputs from a prior, full-fledged encryption scheme and
/// authenticated.
///
/// The CBC-ESSIV obfuscation scheme **does not** protect against adversaries
/// capable of actively modifying externally stored data while transaction
/// preparation is in progress. Not mitigating against such adversaries is a
/// trade-off decision, as the gains would not outweigh the costs of
/// the additional countermeasures required:
/// - As outlined above the primary interest is in the "data at rest" scenario.
/// - To protect against attackers attempting to probe for Journal Data Copy
///   [`IO block`](layout::ImageLayout::io_block_allocation_blocks_log2)
///   matchings by Chosen Ciphertext Attacks (CCA), another, fairly costly level
///   of authentication would be required.
/// - While (legitimate) plaintexts input to the CBC-ESSIV obfuscation scheme
///   are ciphertexts themselves, and thus, can effectively be assumed to have
///   unique first block cipher blocks as is sufficient for establishing
///   IND-CPA-UFB (IND-CPA with "Unique First Block"), c.f. "Full Disk
///   Encryption: Bridging Theory and Practice", Louiza Khati, Nicky Mouha, and
///   Damien Vergnaud, this would have to get enforced throughout by verifying
///   the legitimacy of said plaintexts. That would introduce additional
///   complexity and constraints on the implementation as well as to incur some
///   potential runtime cost.
///
/// That being said, the CBC-ESSIV obfuscation scheme (by itself, disregarding
/// IO pattern analysis) is robust against passive adversaries as well as
/// against ones cabable of manipulating data before the associated transaction
/// has started or after it has completed, it is IND-CPA-UFB secure and CCA is
/// not relevant in this setting, to be more specific.
pub struct JournalStagingCopyDisguise {
    block_cipher_alg: symcipher::SymBlockCipherAlg,
    encryption_key: zeroize::Zeroizing<Vec<u8>>,
    iv_gen_key: zeroize::Zeroizing<Vec<u8>>,
    encryption_block_cipher_instance: symcipher::SymBlockCipherModeEncryptionInstance,
    iv_gen_block_cipher_instance: symcipher::SymBlockCipherModeEncryptionInstance,
}

impl JournalStagingCopyDisguise {
    pub fn generate(
        block_cipher_alg: symcipher::SymBlockCipherAlg,
        rng: &mut dyn rng::RngCoreDispatchable,
    ) -> Result<Self, NvFsError> {
        let encryption_key = symcipher::SymBlockCipherKey::generate(block_cipher_alg, rng, None)?;
        let iv_gen_key = symcipher::SymBlockCipherKey::generate(block_cipher_alg, rng, None)?;
        let encryption_block_cipher_instance =
            encryption_key.instantiate_block_cipher_mode_enc(tpm2_interface::TpmiAlgCipherMode::Cbc)?;
        let iv_gen_block_cipher_instance =
            iv_gen_key.instantiate_block_cipher_mode_enc(tpm2_interface::TpmiAlgCipherMode::Ecb)?;
        let encryption_key = encryption_key.take_key();
        let iv_gen_key = iv_gen_key.take_key();
        Ok(Self {
            block_cipher_alg,
            encryption_key,
            iv_gen_key,
            encryption_block_cipher_instance,
            iv_gen_block_cipher_instance,
        })
    }

    pub fn encoded_len(&self) -> usize {
        tpm2_interface::TpmiAlgSymObject::marshalled_size() as usize
            + mem::size_of::<u16>()
            + self.encryption_key.len()
            + self.iv_gen_key.len()
    }

    pub fn encode<'a>(&self, mut dst: &'a mut [u8]) -> Result<&'a mut [u8], NvFsError> {
        let (block_cipher_alg_id, block_cipher_key_size) =
            <(tpm2_interface::TpmiAlgSymObject, u16)>::from(&self.block_cipher_alg);
        dst = block_cipher_alg_id.marshal(dst).map_err(|_| nvfs_err_internal!())?;
        dst = tpm2_interface::marshal_u16(dst, block_cipher_key_size).map_err(|_| nvfs_err_internal!())?;

        let dst_encryption_key;
        (dst_encryption_key, dst) = dst.split_at_mut(self.encryption_key.len());
        dst_encryption_key.copy_from_slice(&self.encryption_key);

        let dst_iv_gen_key;
        (dst_iv_gen_key, dst) = dst.split_at_mut(self.iv_gen_key.len());
        dst_iv_gen_key.copy_from_slice(&self.iv_gen_key);

        Ok(dst)
    }

    pub fn instantiate_processor(&self) -> Result<JournalDataCopyDisguiseAllocationBlockProcessor<'_>, NvFsError> {
        let iv_buf = try_alloc_zeroizing_vec::<u8>(self.iv_len())?;
        Ok(JournalDataCopyDisguiseAllocationBlockProcessor { disguise: self, iv_buf })
    }

    fn iv_len(&self) -> usize {
        let iv_len = self.iv_gen_block_cipher_instance.block_cipher_block_len();
        debug_assert_eq!(iv_len, self.encryption_block_cipher_instance.iv_len());
        iv_len
    }

    fn disguise_journal_staging_copy_allocation_block(
        &self,
        journal_staging_copy_allocation_block: layout::PhysicalAllocBlockIndex,
        update_target_allocation_block: layout::PhysicalAllocBlockIndex,
        dst: &mut [u8],
        src: &[u8],
        iv_buf: &mut [u8],
    ) -> Result<(), NvFsError> {
        produce_iv(
            iv_buf,
            &self.iv_gen_block_cipher_instance,
            journal_staging_copy_allocation_block,
            update_target_allocation_block,
        )?;
        Ok(self.encryption_block_cipher_instance.encrypt(
            iv_buf,
            io_slices::SingletonIoSliceMut::new(dst).map_infallible_err(),
            io_slices::SingletonIoSlice::new(src).map_infallible_err(),
            None,
        )?)
    }
}

pub struct JournalDataCopyDisguiseAllocationBlockProcessor<'a> {
    disguise: &'a JournalStagingCopyDisguise,
    iv_buf: zeroize::Zeroizing<Vec<u8>>,
}

impl<'a> JournalDataCopyDisguiseAllocationBlockProcessor<'a> {
    pub fn disguise_journal_staging_copy_allocation_block(
        &mut self,
        journal_staging_copy_allocation_block: layout::PhysicalAllocBlockIndex,
        update_target_allocation_block: layout::PhysicalAllocBlockIndex,
        dst: &mut [u8],
        src: &[u8],
    ) -> Result<(), NvFsError> {
        self.disguise.disguise_journal_staging_copy_allocation_block(
            journal_staging_copy_allocation_block,
            update_target_allocation_block,
            dst,
            src,
            &mut self.iv_buf,
        )
    }
}

pub struct JournalStagingCopyUndisguise {
    decryption_block_cipher_instance: symcipher::SymBlockCipherModeDecryptionInstance,
    iv_gen_block_cipher_instance: symcipher::SymBlockCipherModeEncryptionInstance,
}

impl JournalStagingCopyUndisguise {
    pub fn new_from_disguise(disguise: &JournalStagingCopyDisguise) -> Result<Self, NvFsError> {
        let decryption_block_cipher_instance = symcipher::SymBlockCipherModeDecryptionInstance::new(
            tpm2_interface::TpmiAlgCipherMode::Cbc,
            &disguise.block_cipher_alg,
            &disguise.encryption_key,
        )?;
        let iv_gen_block_cipher_instance = disguise.iv_gen_block_cipher_instance.try_clone()?;
        Ok(Self {
            decryption_block_cipher_instance,
            iv_gen_block_cipher_instance,
        })
    }

    fn new(
        block_cipher_alg: symcipher::SymBlockCipherAlg,
        encryption_key: zeroize::Zeroizing<Vec<u8>>,
        iv_gen_key: zeroize::Zeroizing<Vec<u8>>,
    ) -> Result<Self, NvFsError> {
        let encryption_key = symcipher::SymBlockCipherKey::try_from((block_cipher_alg, encryption_key))?;
        let iv_gen_key = symcipher::SymBlockCipherKey::try_from((block_cipher_alg, iv_gen_key))?;
        let decryption_block_cipher_instance =
            encryption_key.instantiate_block_cipher_mode_dec(tpm2_interface::TpmiAlgCipherMode::Cbc)?;
        let iv_gen_block_cipher_instance =
            iv_gen_key.instantiate_block_cipher_mode_enc(tpm2_interface::TpmiAlgCipherMode::Ecb)?;
        Ok(Self {
            decryption_block_cipher_instance,
            iv_gen_block_cipher_instance,
        })
    }

    pub fn decode<'a, SI: io_slices::IoSlicesIter<'a, BackendIteratorError = NvFsError>>(
        mut src: SI,
    ) -> Result<Self, NvFsError> {
        let mut encoded_block_cipher_alg_id = [0u8; tpm2_interface::TpmiAlgSymObject::marshalled_size() as usize];
        let mut encoded_block_cipher_alg_id_io_slice =
            io_slices::SingletonIoSliceMut::new(&mut encoded_block_cipher_alg_id).map_infallible_err();
        encoded_block_cipher_alg_id_io_slice.copy_from_iter(&mut src)?;
        if !encoded_block_cipher_alg_id_io_slice.is_empty()? {
            return Err(nvfs_err_internal!());
        }
        let (_, block_cipher_alg_id) = tpm2_interface::TpmiAlgSymObject::unmarshal(&encoded_block_cipher_alg_id)
            .map_err(|e| match e {
                tpm2_interface::TpmErr::Rc(tpm2_interface::TpmRc::SYMMETRIC) => {
                    NvFsError::from(CocoonFsFormatError::UnsupportedCryptoAlgorithm)
                }
                _ => nvfs_err_internal!(),
            })?;

        let mut encoded_block_cipher_key_size = [0u8; mem::size_of::<u16>()];
        let mut encoded_block_cipher_key_size_io_slice =
            io_slices::SingletonIoSliceMut::new(&mut encoded_block_cipher_key_size).map_infallible_err();
        encoded_block_cipher_key_size_io_slice.copy_from_iter(&mut src)?;
        if !encoded_block_cipher_key_size_io_slice.is_empty()? {
            return Err(nvfs_err_internal!());
        }
        let (_, block_cipher_key_size) =
            tpm2_interface::unmarshal_u16(&encoded_block_cipher_key_size).map_err(|_| nvfs_err_internal!())?;

        let block_cipher_alg = symcipher::SymBlockCipherAlg::try_from((block_cipher_alg_id, block_cipher_key_size))
            .map_err(|e| match e {
                CryptoError::InvalidParams => NvFsError::from(CocoonFsFormatError::UnsupportedCryptoAlgorithm),
                _ => nvfs_err_internal!(),
            })?;
        let block_cipher_key_len = block_cipher_alg.key_len();

        let mut encryption_key = try_alloc_zeroizing_vec(block_cipher_key_len)?;
        let mut encryption_key_io_slice = io_slices::SingletonIoSliceMut::new(&mut encryption_key).map_infallible_err();
        encryption_key_io_slice.copy_from_iter(&mut src)?;
        if !encryption_key_io_slice.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        let mut iv_gen_key = try_alloc_zeroizing_vec(block_cipher_key_len)?;
        let mut iv_gen_key_io_slice = io_slices::SingletonIoSliceMut::new(&mut iv_gen_key).map_infallible_err();
        iv_gen_key_io_slice.copy_from_iter(&mut src)?;
        if !iv_gen_key_io_slice.is_empty()? {
            return Err(nvfs_err_internal!());
        }

        Self::new(block_cipher_alg, encryption_key, iv_gen_key)
    }

    pub fn instantiate_processor(&self) -> Result<JournalDataCopyUndisguiseAllocationBlockProcessor<'_>, NvFsError> {
        let iv_buf = try_alloc_zeroizing_vec::<u8>(self.iv_len())?;
        Ok(JournalDataCopyUndisguiseAllocationBlockProcessor {
            undisguise: self,
            iv_buf,
        })
    }

    fn iv_len(&self) -> usize {
        let iv_len = self.iv_gen_block_cipher_instance.block_cipher_block_len();
        debug_assert_eq!(iv_len, self.decryption_block_cipher_instance.iv_len());
        iv_len
    }

    fn undisguise_journal_staging_copy_allocation_block(
        &self,
        journal_staging_copy_allocation_block: layout::PhysicalAllocBlockIndex,
        update_target_allocation_block: layout::PhysicalAllocBlockIndex,
        dst: &mut [u8],
        iv_buf: &mut [u8],
    ) -> Result<(), NvFsError> {
        produce_iv(
            iv_buf,
            &self.iv_gen_block_cipher_instance,
            journal_staging_copy_allocation_block,
            update_target_allocation_block,
        )?;
        Ok(self.decryption_block_cipher_instance.decrypt_in_place(
            iv_buf,
            io_slices::SingletonIoSliceMut::new(dst).map_infallible_err(),
            None,
        )?)
    }
}

pub struct JournalDataCopyUndisguiseAllocationBlockProcessor<'a> {
    undisguise: &'a JournalStagingCopyUndisguise,
    iv_buf: zeroize::Zeroizing<Vec<u8>>,
}

impl<'a> JournalDataCopyUndisguiseAllocationBlockProcessor<'a> {
    pub fn undisguise_journal_staging_copy_allocation_block(
        &mut self,
        journal_staging_copy_allocation_block: layout::PhysicalAllocBlockIndex,
        update_target_allocation_block: layout::PhysicalAllocBlockIndex,
        dst: &mut [u8],
    ) -> Result<(), NvFsError> {
        self.undisguise.undisguise_journal_staging_copy_allocation_block(
            journal_staging_copy_allocation_block,
            update_target_allocation_block,
            dst,
            &mut self.iv_buf,
        )
    }
}

fn produce_iv(
    iv_out: &mut [u8],
    iv_gen_block_cipher_instance: &symcipher::SymBlockCipherModeEncryptionInstance,
    journal_staging_copy_allocation_block: layout::PhysicalAllocBlockIndex,
    update_target_allocation_block: layout::PhysicalAllocBlockIndex,
) -> Result<(), NvFsError> {
    debug_assert_eq!(
        tpm2_interface::TpmiAlgCipherMode::from(iv_gen_block_cipher_instance),
        tpm2_interface::TpmiAlgCipherMode::Ecb
    );
    // The IV is produced by encrypting the Journal Data Copy Allocation Block Index
    // with a separate, independent key, as proposed in "Nonce-Based
    // Symmetric Encryption", Phillip Rogaway. The assumption of Nonce
    // uniqueness made in that paper is potentially being violated though,
    // as a single Journal Data Copy Allocation Block might get updated
    // multiple times over the course of preparing a single transaction. However,
    // this method here is arguably at least en par with the ESSIV IV
    // generation method described in "New Methods in Hard Disk Encryption",
    // Clemens Fruhwirth, sec. 4.1.2, because it's basically the same, but
    // with a second, independent key rather than one derived by hashing.
    let iv_len = iv_out.len();
    debug_assert_eq!(iv_gen_block_cipher_instance.block_cipher_block_len(), iv_len);
    iv_out.fill(0);
    debug_assert!(iv_len >= mem::size_of::<u64>());
    let (iv_out_head, iv_out_tail) = iv_out.split_at_mut(iv_len - mem::size_of::<u64>());
    iv_out_tail.copy_from_slice(&u64::from(journal_staging_copy_allocation_block).to_le_bytes());

    if !iv_out_head.is_empty() {
        let iv_out_head_len = iv_out_head.len();
        let enc_len = iv_out_head_len.min(mem::size_of::<u64>());
        iv_out_head[iv_out_head_len - enc_len..].copy_from_slice(
            &u64::from(update_target_allocation_block).to_le_bytes().as_slice()[mem::size_of::<u64>() - enc_len..],
        );
    }

    Ok(iv_gen_block_cipher_instance.encrypt_in_place(
        &[],
        io_slices::SingletonIoSliceMut::new(iv_out).map_infallible_err(),
        None,
    )?)
}
