// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Common interface to symmetric cipher algorithm implementations.
//!
//! # High level overview:
//!
//! For the encryption with block ciphers, a
//! [`SymBlockCipherModeEncryptionInstance`] must first get instantiated either
//! [directly with a raw key byte slice](SymBlockCipherModeEncryption
//! Instance::new) or through a
//! [`SymBlockCipherKey`](SymBlockCipherKey::instantiate_block_cipher_mode_enc).
//! That instance can then be used to
//! [encrypt](SymBlockCipherModeEncryptionInstance::encrypt) one or more
//! messages.
//!
//! Similarly, for the decryption with block ciphers, a
//! [`SymBlockCipherModeDecryptionInstance`] must first get instantiated either
//! [directly with a raw key byte slice](SymBlockCipherModeDecryption
//! Instance::new) or through a
//! [`SymBlockCipherKey`](SymBlockCipherKey::instantiate_block_cipher_mode_dec).
//! That instance can then be used to
//! [decrypt](SymBlockCipherModeDecryptionInstance::decrypt) one or more
//! messages.

// Lifetimes are not obvious at first sight here, make the explicit.
#![allow(clippy::needless_lifetimes)]

extern crate alloc;
use alloc::vec::Vec;

use crate::{
    CryptoError,
    io_slices::{CryptoPeekableIoSlicesMutIter, CryptoWalkableIoSlicesIter, CryptoWalkableIoSlicesMutIter},
    rng,
};
use crate::{
    tpm2_interface,
    utils_common::{
        alloc::try_alloc_zeroizing_vec,
        bitmanip::BitManip as _,
        io_slices::{self, IoSlicesIterCommon as _, IoSlicesMutIter as _},
        zeroize,
    },
};
use core::convert;

/// AES key sizes.
#[cfg(feature = "aes")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SymBlockCipherAesKeySize {
    Aes128,
    Aes192,
    Aes256,
}

/// Camellia key sizes.
#[cfg(feature = "camellia")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SymBlockCipherCamelliaKeySize {
    Camellia128,
    Camellia192,
    Camellia256,
}

/// SM4 key sizes.
#[cfg(feature = "sm4")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SymBlockCipherSm4KeySize {
    Sm4_128,
}

/// Indentify a symmetric block cipher algorithm together with a selected key
/// size.
///
/// For example `SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128)`
/// would identify "Aes128".
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SymBlockCipherAlg {
    #[cfg(feature = "aes")]
    Aes(SymBlockCipherAesKeySize),
    #[cfg(feature = "camellia")]
    Camellia(SymBlockCipherCamelliaKeySize),
    #[cfg(feature = "sm4")]
    Sm4(SymBlockCipherSm4KeySize),
}

/// Map pair of (symbolic block cipher, key size) to the block length.
macro_rules! block_cipher_to_block_len {
    (Aes, 128) => {
        16
    };
    (Aes, 192) => {
        16
    };
    (Aes, 256) => {
        16
    };
    (Camellia, 128) => {
        16
    };
    (Camellia, 192) => {
        16
    };
    (Camellia, 256) => {
        16
    };
    (Sm4, 128) => {
        16
    };
}

/// Map pair of (symbolic block cipher, key size) to the key length in bytes.
macro_rules! block_cipher_to_key_len {
    (Aes, 128) => {
        16
    };
    (Aes, 192) => {
        24
    };
    (Aes, 256) => {
        32
    };
    (Camellia, 128) => {
        16
    };
    (Camellia, 192) => {
        24
    };
    (Camellia, 256) => {
        32
    };
    (Sm4, 128) => {
        16
    };
}

/// Generate a `match {}` on SymBlockCipherAlg and invoke a macro in the body of
/// each match arm.
///
/// The supplied macro `m` gets invoked with (`$args`, symbolic block cipher,
/// key size) for each arm.
macro_rules! gen_match_on_block_cipher_alg {
    ($block_cipher_alg_value:expr, $m:ident $(, $($args:tt),*)?) => {
        match $block_cipher_alg_value {
            #[cfg(feature = "aes")]
            SymBlockCipherAlg::Aes(key_size) => {
                match key_size {
                    SymBlockCipherAesKeySize::Aes128 => {
                        $m!($($($args),*,)? Aes, 128)
                    },
                    SymBlockCipherAesKeySize::Aes192 => {
                        $m!($($($args),*,)? Aes, 192)
                    },
                    SymBlockCipherAesKeySize::Aes256 => {
                        $m!($($($args),*,)? Aes, 256)
                    },
                }
            },
            #[cfg(feature = "camellia")]
            SymBlockCipherAlg::Camellia(key_size) => {
                match key_size {
                    SymBlockCipherCamelliaKeySize::Camellia128 => {
                        $m!($($($args),*,)? Camellia, 128)
                    },
                    SymBlockCipherCamelliaKeySize::Camellia192 => {
                        $m!($($($args),*,)? Camellia, 192)
                    },
                    SymBlockCipherCamelliaKeySize::Camellia256 => {
                        $m!($($($args),*,)? Camellia, 256)
                    },
                }
            },
            #[cfg(feature = "sm4")]
            SymBlockCipherAlg::Sm4(key_size) => {
                match key_size {
                    SymBlockCipherSm4KeySize::Sm4_128 => {
                        $m!($($($args),*,)? Sm4, 128)
                    },
                }
            },
        }
    };
}

macro_rules! gen_match_on_tpmi_alg_cipher_mode {
    ($mode_value:expr, $m:ident $(, $($args:tt),*)?) => {
        match $mode_value {
            #[cfg(feature = "ctr")]
            tpm2_interface::TpmiAlgCipherMode::Ctr => {
                $m!($($($args),*,)? Ctr)
            },
            #[cfg(feature = "ofb")]
            tpm2_interface::TpmiAlgCipherMode::Ofb => {
                $m!($($($args),*,)? Ofb)
            },
            #[cfg(feature = "cbc")]
            tpm2_interface::TpmiAlgCipherMode::Cbc => {
                $m!($($($args),*,)? Cbc)
            },
            #[cfg(feature = "cfb")]
            tpm2_interface::TpmiAlgCipherMode::Cfb => {
                $m!($($($args),*,)? Cfb)
            },
            #[cfg(feature = "ecb")]
            tpm2_interface::TpmiAlgCipherMode::Ecb => {
                $m!($($($args),*,)? Ecb)
            },
        }
    };
}

// This gets invoked with the symbolic mode identifier appended to the args.
macro_rules! __gen_match_on_tpmi_alg_cipher_mode_and_block_cipher_alg {
    ($block_cipher_alg_value:tt, $m:ident, $($args_and_mode_id:tt),*) => {
        gen_match_on_block_cipher_alg!($block_cipher_alg_value, $m, $($args_and_mode_id),*)
    };
}

/// Generated a nested `match {}` on a pair of
/// [`TpmiAlgCipherMode`](tpm2_interface::TpmiAlgCipherMode) and
/// [`SymBlockCipherAlg`]. The macro `$m` will get invoked within each match arm
/// with the `$args` passed through and extended by a triplet of (symbolic mode,
/// symbolic block cipher, key size) at the tail.
macro_rules! gen_match_on_tpmi_alg_cipher_mode_and_block_cipher_alg {
    ($mode_value:expr, $block_cipher_alg_value:expr, $m:ident $(, $($args:tt),*)?) => {
        gen_match_on_tpmi_alg_cipher_mode!(
            $mode_value,
            __gen_match_on_tpmi_alg_cipher_mode_and_block_cipher_alg, $block_cipher_alg_value, $m $(,$($args),*)?
        )
    };
}

/// Map a triplet of (symbolic mode, symbolic block cipher, key size) to the IV
/// length.
macro_rules! mode_and_block_cipher_to_iv_len {
    (Ctr, $block_alg_id:ident, $key_size:tt) => {
        block_cipher_to_block_len!($block_alg_id, $key_size)
    };
    (Ofb, $block_alg_id:ident, $key_size:tt) => {
        block_cipher_to_block_len!($block_alg_id, $key_size)
    };
    (Cbc, $block_alg_id:ident, $key_size:tt) => {
        block_cipher_to_block_len!($block_alg_id, $key_size)
    };
    (Cfb, $block_alg_id:ident, $key_size:tt) => {
        block_cipher_to_block_len!($block_alg_id, $key_size)
    };
    (Ecb, $_block_alg_id:ident, $_key_size:tt) => {
        0
    };
}

#[cfg(test)]
macro_rules! mode_supports_partial_last_block {
    (Ctr) => {
        true
    };
    (Ofb) => {
        true
    };
    (Cbc) => {
        false
    };
    (Cfb) => {
        true
    };
    (Ecb) => {
        false
    };
}

impl SymBlockCipherAlg {
    /// Determine the key length associated with the symmetric block cipher
    /// algorithm.
    pub fn key_len(&self) -> usize {
        macro_rules! gen_block_cipher_key_len {
            ($block_alg_id:ident,
             $key_size:tt) => {
                block_cipher_to_key_len!($block_alg_id, $key_size)
            };
        }
        gen_match_on_block_cipher_alg!(self, gen_block_cipher_key_len)
    }

    /// Determine the block length associated with the symmetric block cipher
    /// algorithm.
    pub fn block_len(&self) -> usize {
        macro_rules! gen_block_cipher_block_len {
            ($block_alg_id:ident,
             $key_size:tt) => {
                block_cipher_to_block_len!($block_alg_id, $key_size)
            };
        }
        gen_match_on_block_cipher_alg!(self, gen_block_cipher_block_len)
    }

    /// Determine the IV length for a [block cipher
    /// mode](tpm2_interface::TpmiAlgCipherMode) operating on the symmetric
    /// block cipher algorithm.
    pub fn iv_len_for_mode(&self, mode: tpm2_interface::TpmiAlgCipherMode) -> usize {
        gen_match_on_tpmi_alg_cipher_mode_and_block_cipher_alg!(mode, self, mode_and_block_cipher_to_iv_len)
    }
}

impl convert::TryFrom<(tpm2_interface::TpmiAlgSymObject, u16)> for SymBlockCipherAlg {
    type Error = CryptoError;

    /// Convert a pair of [TCG block cipher algorithm
    /// identifier](tpm2_interface::TpmiAlgSymObject) and key size to
    /// a [symmetric block cipher algorithm identifier](SymBlockCipherAlg).
    fn try_from(value: (tpm2_interface::TpmiAlgSymObject, u16)) -> Result<Self, Self::Error> {
        let (block_alg, key_size) = value;

        match block_alg {
            #[cfg(feature = "aes")]
            tpm2_interface::TpmiAlgSymObject::Aes => match key_size {
                128 => Ok(Self::Aes(SymBlockCipherAesKeySize::Aes128)),
                192 => Ok(Self::Aes(SymBlockCipherAesKeySize::Aes192)),
                256 => Ok(Self::Aes(SymBlockCipherAesKeySize::Aes256)),
                _ => Err(CryptoError::InvalidParams),
            },
            #[cfg(feature = "camellia")]
            tpm2_interface::TpmiAlgSymObject::Camellia => match key_size {
                128 => Ok(Self::Camellia(SymBlockCipherCamelliaKeySize::Camellia128)),
                192 => Ok(Self::Camellia(SymBlockCipherCamelliaKeySize::Camellia192)),
                256 => Ok(Self::Camellia(SymBlockCipherCamelliaKeySize::Camellia256)),
                _ => Err(CryptoError::InvalidParams),
            },
            #[cfg(feature = "sm4")]
            tpm2_interface::TpmiAlgSymObject::Sm4 => match key_size {
                128 => Ok(Self::Sm4(SymBlockCipherSm4KeySize::Sm4_128)),
                _ => Err(CryptoError::InvalidParams),
            },
        }
    }
}

impl convert::From<&SymBlockCipherAlg> for (tpm2_interface::TpmiAlgSymObject, u16) {
    /// Convert a [symmetric block cipher algorithm
    /// identifier](SymBlockCipherAlg) into a pair of [TCG block cipher
    /// algorithm identifier](tpm2_interface::TpmiAlgSymObject) and key size.
    fn from(value: &SymBlockCipherAlg) -> Self {
        match value {
            #[cfg(feature = "aes")]
            SymBlockCipherAlg::Aes(key_size) => (
                tpm2_interface::TpmiAlgSymObject::Aes,
                match key_size {
                    SymBlockCipherAesKeySize::Aes128 => 128,
                    SymBlockCipherAesKeySize::Aes192 => 192,
                    SymBlockCipherAesKeySize::Aes256 => 256,
                },
            ),
            #[cfg(feature = "camellia")]
            SymBlockCipherAlg::Camellia(key_size) => (
                tpm2_interface::TpmiAlgSymObject::Camellia,
                match key_size {
                    SymBlockCipherCamelliaKeySize::Camellia128 => 128,
                    SymBlockCipherCamelliaKeySize::Camellia192 => 192,
                    SymBlockCipherCamelliaKeySize::Camellia256 => 256,
                },
            ),
            #[cfg(feature = "sm4")]
            SymBlockCipherAlg::Sm4(key_size) => (
                tpm2_interface::TpmiAlgSymObject::Sm4,
                match key_size {
                    SymBlockCipherSm4KeySize::Sm4_128 => 128,
                },
            ),
        }
    }
}

/// A symmetric block cipher key.
///
/// Associate the raw key material with a [symmetric block cipher algorithm
/// identifier](SymBlockCipherAlg).
///
/// May get instantiate either through [key generation](Self::generate) or from
/// an existing raw key via [`TryFrom`].
pub struct SymBlockCipherKey {
    block_cipher_alg: SymBlockCipherAlg,
    key: zeroize::Zeroizing<Vec<u8>>,
}

impl SymBlockCipherKey {
    /// Get the key's associated [symmetric block cipher algorithm
    /// identifier](SymBlockCipherAlg).
    pub fn get_block_cipher_alg(&self) -> SymBlockCipherAlg {
        self.block_cipher_alg
    }

    /// Take the key.
    pub fn take_key(self) -> zeroize::Zeroizing<Vec<u8>> {
        let Self {
            block_cipher_alg: _,
            key,
        } = self;
        key
    }

    /// Generate a new block cipher key.
    ///
    /// # Arguments:
    /// * `block_cipher_alg` - The block cipher algorithm to generate a key for.
    /// * `rng` - The random number generator to obtain key material from.
    /// * `additional_rng_generate_input` - Additional input to pass along to
    ///   the `rng`'s [generate()](rng::RngCore::generate) primitive.
    pub fn generate(
        block_cipher_alg: SymBlockCipherAlg,
        rng: &mut dyn rng::RngCoreDispatchable,
        additional_rng_generate_input: Option<&[Option<&[u8]>]>,
    ) -> Result<Self, CryptoError> {
        let mut key = try_alloc_zeroizing_vec(block_cipher_alg.key_len())?;
        rng::rng_dyn_dispatch_generate(
            rng,
            io_slices::SingletonIoSliceMut::new(&mut key).map_infallible_err(),
            additional_rng_generate_input,
        )?;
        Ok(Self { block_cipher_alg, key })
    }

    /// Instantiate a block cipher mode encryption instance for the key.
    ///
    /// # Arguments:
    ///
    /// * `mode` - The block cipher mode to instantiate an encryption instance
    ///   with the key for.
    pub fn instantiate_block_cipher_mode_enc(
        &self,
        mode: tpm2_interface::TpmiAlgCipherMode,
    ) -> Result<SymBlockCipherModeEncryptionInstance, CryptoError> {
        SymBlockCipherModeEncryptionInstance::new(mode, &self.block_cipher_alg, &self.key)
    }

    /// Instantiate a block cipher mode decryption instance for the key.
    ///
    /// # Arguments:
    ///
    /// * `mode` - The block cipher mode to instantiate an decryption instance
    ///   with the key for.
    pub fn instantiate_block_cipher_mode_dec(
        &self,
        mode: tpm2_interface::TpmiAlgCipherMode,
    ) -> Result<SymBlockCipherModeDecryptionInstance, CryptoError> {
        SymBlockCipherModeDecryptionInstance::new(mode, &self.block_cipher_alg, &self.key)
    }
}

impl convert::TryFrom<(SymBlockCipherAlg, &[u8])> for SymBlockCipherKey {
    type Error = CryptoError;

    /// Construct a [`SymBlockCipherKey`] from a pair of [symmetric block cipher
    /// algorithm identifier](SymBlockCipherAlg) and a raw key byte slice.
    fn try_from(value: (SymBlockCipherAlg, &[u8])) -> Result<Self, Self::Error> {
        let (block_cipher_alg, supplied_key) = value;

        if supplied_key.len() != block_cipher_alg.key_len() {
            return Err(CryptoError::KeySize);
        }

        let mut key = try_alloc_zeroizing_vec::<u8>(block_cipher_alg.key_len())?;
        key.copy_from_slice(supplied_key);

        Ok(Self { block_cipher_alg, key })
    }
}

impl convert::TryFrom<(SymBlockCipherAlg, zeroize::Zeroizing<Vec<u8>>)> for SymBlockCipherKey {
    type Error = CryptoError;

    /// Destructure a [`SymBlockCipherKey`] into a pair of [symmetric block
    /// cipher algorithm identifier](SymBlockCipherAlg) and a raw key byte
    /// `Vec`.
    fn try_from(value: (SymBlockCipherAlg, zeroize::Zeroizing<Vec<u8>>)) -> Result<Self, Self::Error> {
        let (block_cipher_alg, supplied_key) = value;

        if supplied_key.len() != block_cipher_alg.key_len() {
            return Err(CryptoError::KeySize);
        }

        Ok(Self {
            block_cipher_alg,
            key: supplied_key,
        })
    }
}

impl zeroize::ZeroizeOnDrop for SymBlockCipherKey {}

pub(crate) fn transform_next_blocks<
    'a,
    'b,
    const ENABLE_PARTIAL_LAST_BLOCK: bool,
    BT: FnMut(&mut [u8], Option<&[u8]>),
>(
    dst: &mut dyn CryptoWalkableIoSlicesMutIter<'a>,
    src: &mut dyn CryptoWalkableIoSlicesIter<'b>,
    mut block_transform: BT,
    block_len: usize,
    scratch_block_buf: &mut [u8],
) -> Result<bool, CryptoError> {
    let first_dst_slice_len = dst.next_slice_len()?;
    // Try to process a batch of multiple block cipher blocks at once.
    if first_dst_slice_len >= 2 * block_len {
        let first_src_slice_len = src.next_slice_len()?;
        if first_src_slice_len >= 2 * block_len {
            let batch_len = first_dst_slice_len.min(first_src_slice_len);
            let batch_len = if block_len.is_pow2() {
                batch_len & !(block_len - 1)
            } else {
                batch_len - (batch_len % block_len)
            };
            let batch_dst_slice = match dst.next_slice_mut(Some(batch_len))? {
                Some(batch_dst_slice) => batch_dst_slice,
                None => return Err(CryptoError::Internal),
            };
            let batch_src_slice = match src.next_slice(Some(batch_len))? {
                Some(batch_src_slice) => batch_src_slice,
                None => return Err(CryptoError::Internal),
            };

            let mut pos_in_batch_slice = 0;
            while pos_in_batch_slice != batch_len {
                block_transform(
                    &mut batch_dst_slice[pos_in_batch_slice..pos_in_batch_slice + block_len],
                    Some(&batch_src_slice[pos_in_batch_slice..pos_in_batch_slice + block_len]),
                );
                pos_in_batch_slice += block_len
            }
            return Ok(true);
        }
    }

    let first_dst_slice = match dst.next_slice_mut(Some(block_len))? {
        Some(first_dst_slice) => first_dst_slice,
        None => {
            if !src.is_empty()? {
                return Err(CryptoError::Internal);
            }
            return Ok(false);
        }
    };
    let first_src_slice = match src.next_slice(Some(block_len))? {
        Some(first_src_slice) => first_src_slice,
        None => return Err(CryptoError::Internal),
    };
    if first_src_slice.len() == block_len && first_dst_slice.len() == block_len {
        block_transform(first_dst_slice, Some(first_src_slice));
    } else {
        debug_assert_eq!(scratch_block_buf.len(), block_len);
        let mut src_block_len = first_src_slice.len();
        scratch_block_buf[..src_block_len].copy_from_slice(first_src_slice);
        src_block_len += io_slices::SingletonIoSliceMut::new(&mut scratch_block_buf[src_block_len..])
            .map_infallible_err::<CryptoError>()
            .copy_from_iter(src)?;
        if src_block_len != block_len {
            if !ENABLE_PARTIAL_LAST_BLOCK {
                return Err(CryptoError::Internal);
            } else {
                scratch_block_buf[src_block_len..].fill(0);
            }
        } else if src_block_len < first_dst_slice.len() {
            return Err(CryptoError::Internal);
        }

        block_transform(scratch_block_buf, None);

        let mut dst_block_len = first_dst_slice.len();
        first_dst_slice.copy_from_slice(&scratch_block_buf[..dst_block_len]);
        dst_block_len += dst.copy_from_iter(
            &mut io_slices::SingletonIoSlice::new(&scratch_block_buf[dst_block_len..src_block_len])
                .map_infallible_err(),
        )?;
        if dst_block_len != src_block_len {
            return Err(CryptoError::Internal);
        }
    }

    Ok(true)
}

pub(crate) fn transform_next_blocks_in_place<
    'a,
    'b,
    const ENABLE_PARTIAL_LAST_BLOCK: bool,
    BT: FnMut(&mut [u8]),
    DI: CryptoPeekableIoSlicesMutIter<'a>,
>(
    dst: &mut DI,
    mut block_transform: BT,
    block_len: usize,
    scratch_block_buf: &mut [u8],
) -> Result<bool, CryptoError> {
    let first_dst_slice_len = dst.next_slice_len()?;
    // Try to process a batch of multiple block cipher blocks at once.
    if first_dst_slice_len >= 2 * block_len {
        let batch_len = if block_len.is_pow2() {
            first_dst_slice_len & !(block_len - 1)
        } else {
            first_dst_slice_len - (first_dst_slice_len % block_len)
        };
        let batch_dst_slice = match dst.next_slice_mut(Some(batch_len))? {
            Some(batch_dst_slice) => batch_dst_slice,
            None => return Err(CryptoError::Internal),
        };

        let mut pos_in_batch_slice = 0;
        while pos_in_batch_slice != batch_len {
            block_transform(&mut batch_dst_slice[pos_in_batch_slice..pos_in_batch_slice + block_len]);
            pos_in_batch_slice += block_len
        }
        return Ok(true);
    }

    let first_dst_slice = match dst.next_slice_mut(Some(block_len))? {
        Some(first_dst_slice) => first_dst_slice,
        None => {
            return Ok(false);
        }
    };
    if first_dst_slice.len() == block_len {
        block_transform(first_dst_slice);
    } else {
        debug_assert_eq!(scratch_block_buf.len(), block_len);
        let mut src_block_len = first_dst_slice.len();
        scratch_block_buf[..src_block_len].copy_from_slice(first_dst_slice);
        // When copying from the destination into the scratch buffer, retain the
        // original IOSlicesMut, so that the result can later get written back again.
        src_block_len += io_slices::SingletonIoSliceMut::new(&mut scratch_block_buf[src_block_len..])
            .map_infallible_err()
            .copy_from_iter(&mut dst.decoupled_borrow())?;
        if src_block_len != block_len {
            if !ENABLE_PARTIAL_LAST_BLOCK {
                return Err(CryptoError::Internal);
            } else {
                scratch_block_buf[src_block_len..].fill(0);
            }
        }

        block_transform(scratch_block_buf);

        let mut dst_block_len = first_dst_slice.len();
        first_dst_slice.copy_from_slice(&scratch_block_buf[..dst_block_len]);
        dst_block_len += dst.copy_from_iter(
            &mut io_slices::SingletonIoSlice::new(&scratch_block_buf[dst_block_len..]).map_infallible_err(),
        )?;
        debug_assert_eq!(dst_block_len, src_block_len);
    }

    Ok(true)
}

pub use super::backend::symcipher::*;

#[cfg(test)]
fn test_mode_supports_partial_last_block(mode: tpm2_interface::TpmiAlgCipherMode) -> bool {
    gen_match_on_tpmi_alg_cipher_mode!(mode, mode_supports_partial_last_block)
}

#[cfg(test)]
fn test_encrypt_decrypt(mode: tpm2_interface::TpmiAlgCipherMode, block_cipher_alg: SymBlockCipherAlg) {
    use alloc::vec;

    let key_len = block_cipher_alg.key_len();
    let key = vec![0xffu8; key_len];
    let key = SymBlockCipherKey::try_from((block_cipher_alg, key.as_slice())).unwrap();

    let block_cipher_mode_encryption_instance = key.instantiate_block_cipher_mode_enc(mode).unwrap();

    let block_len = block_cipher_alg.block_len();
    let mode_supports_partial_last_block = test_mode_supports_partial_last_block(mode);
    let msg_len = if mode_supports_partial_last_block {
        4 * block_len - 1
    } else {
        4 * block_len
    };
    let mut msg = vec![0u8; msg_len];
    for (i, b) in msg.iter_mut().enumerate() {
        *b = (i % u8::MAX as usize) as u8
    }

    let iv_len = block_cipher_mode_encryption_instance.iv_len();
    let mut encrypted = vec![0u8; msg_len];
    let mut iv_out = vec![0xccu8; iv_len];
    // Encrypt in two steps for testing the intermediate IV extraction code.
    for (r, is_last) in [(0..3 * block_len, false), (3 * block_len..msg_len, true)] {
        let iv = iv_out.clone();
        let r_len = r.len();
        let (src0, src1) = msg[r.clone()].split_at(r_len / 4);
        let (dst0, dst1) = encrypted[r].split_at_mut(r_len / 4 * 3);
        block_cipher_mode_encryption_instance
            .encrypt(
                &iv,
                io_slices::BuffersSliceIoSlicesMutIter::new(&mut [dst0, dst1]).map_infallible_err(),
                io_slices::BuffersSliceIoSlicesIter::new(&[src0, src1]).map_infallible_err(),
                (!is_last || !mode_supports_partial_last_block).then_some(&mut iv_out),
            )
            .unwrap();
    }
    assert_ne!(&msg, &encrypted);

    // Decrypt, also in two steps, and compare the result with the original message.
    let block_cipher_mode_decryption_instance = key.instantiate_block_cipher_mode_dec(mode).unwrap();
    let mut decrypted = vec![0u8; msg_len];
    let mut iv_out = vec![0xccu8; iv_len];
    // Encrypt in two steps for testing the intermediate IV extraction code.
    for (r, is_last) in [(0..2 * block_len, false), (2 * block_len..msg_len, true)] {
        let iv = iv_out.clone();
        let r_len = r.len();
        let (src0, src1) = encrypted[r.clone()].split_at(r_len / 4);
        let (dst0, dst1) = decrypted[r].split_at_mut(r_len / 4 * 3);
        block_cipher_mode_decryption_instance
            .decrypt(
                &iv,
                io_slices::BuffersSliceIoSlicesMutIter::new(&mut [dst0, dst1]).map_infallible_err(),
                io_slices::BuffersSliceIoSlicesIter::new(&[src0, src1]).map_infallible_err(),
                (!is_last || !mode_supports_partial_last_block).then_some(&mut iv_out),
            )
            .unwrap();
    }
    assert_eq!(&msg, &decrypted);
}

#[cfg(all(feature = "ctr", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ctr_aes128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "ofb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ofb_aes128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "cbc", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_cbc_aes128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "cfb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_cfb_aes128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "ecb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ecb_aes128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "ctr", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ctr_aes192() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "ofb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ofb_aes192() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "cbc", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_cbc_aes192() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "cfb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_cfb_aes192() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "ecb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ecb_aes192() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "ctr", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ctr_aes256() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "ofb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ofb_aes256() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "cbc", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_cbc_aes256() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "cfb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_cfb_aes256() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "ecb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ecb_aes256() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "ctr", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ctr_camellia128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "ofb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ofb_camellia128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "cbc", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_cbc_camellia128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "cfb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_cfb_camellia128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "ecb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ecb_camellia128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "ctr", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ctr_camellia192() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "ofb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ofb_camellia192() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "cbc", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_cbc_camellia192() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "cfb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_cfb_camellia192() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "ecb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ecb_camellia192() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "ctr", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ctr_camellia256() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "ofb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ofb_camellia256() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "cbc", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_cbc_camellia256() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "cfb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_cfb_camellia256() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "ecb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ecb_camellia256() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "ctr", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_ctr_sm4_128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(all(feature = "ofb", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_ofb_sm4_128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(all(feature = "cbc", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_cbc_sm4_128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(all(feature = "cfb", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_cfb_sm4_128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(all(feature = "ecb", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_ecb_sm4_128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(test)]
fn test_encrypt_decrypt_in_place(mode: tpm2_interface::TpmiAlgCipherMode, block_cipher_alg: SymBlockCipherAlg) {
    use alloc::vec;

    let key_len = block_cipher_alg.key_len();
    let key = vec![0xffu8; key_len];
    let key = SymBlockCipherKey::try_from((block_cipher_alg, key.as_slice())).unwrap();

    let block_cipher_mode_encryption_instance = key.instantiate_block_cipher_mode_enc(mode).unwrap();

    let block_len = block_cipher_alg.block_len();
    let mode_supports_partial_last_block = test_mode_supports_partial_last_block(mode);
    let msg_len = if mode_supports_partial_last_block {
        4 * block_len - 1
    } else {
        4 * block_len
    };
    let mut msg = vec![0u8; msg_len];
    for (i, b) in msg.iter_mut().enumerate() {
        *b = (i % u8::MAX as usize) as u8
    }

    let iv_len = block_cipher_mode_encryption_instance.iv_len();
    let mut dst = vec![0u8; msg_len];
    dst.copy_from_slice(&msg);
    let mut iv_out = vec![0xccu8; iv_len];
    // Encrypt in two steps for testing the intermediate IV extraction code.
    for (r, is_last) in [(0..3 * block_len, false), (3 * block_len..msg_len, true)] {
        let iv = iv_out.clone();
        let r_len = r.len();
        let (dst0, dst1) = dst[r].split_at_mut(r_len / 4);
        block_cipher_mode_encryption_instance
            .encrypt_in_place(
                &iv,
                io_slices::BuffersSliceIoSlicesMutIter::new(&mut [dst0, dst1]).map_infallible_err(),
                (!is_last || !mode_supports_partial_last_block).then_some(&mut iv_out),
            )
            .unwrap();
    }
    assert_ne!(&msg, &dst);

    // Decrypt, also in two steps, and compare the result with the original message.
    let block_cipher_mode_decryption_instance = key.instantiate_block_cipher_mode_dec(mode).unwrap();
    let mut iv_out = vec![0xccu8; iv_len];
    // Encrypt in two steps for testing the intermediate IV extraction code.
    for (r, is_last) in [(0..2 * block_len, false), (2 * block_len..msg_len, true)] {
        let iv = iv_out.clone();
        let r_len = r.len();
        let (dst0, dst1) = dst[r].split_at_mut(r_len / 4 * 3);
        block_cipher_mode_decryption_instance
            .decrypt_in_place(
                &iv,
                io_slices::BuffersSliceIoSlicesMutIter::new(&mut [dst0, dst1]).map_infallible_err(),
                (!is_last || !mode_supports_partial_last_block).then_some(&mut iv_out),
            )
            .unwrap();
    }
    assert_eq!(&msg, &dst);
}

#[cfg(all(feature = "ctr", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ctr_aes128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "ofb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ofb_aes128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "cbc", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_cbc_aes128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "cfb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_cfb_aes128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "ecb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ecb_aes128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "ctr", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ctr_aes192() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "ofb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ofb_aes192() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "cbc", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_cbc_aes192() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "cfb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_cfb_aes192() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "ecb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ecb_aes192() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "ctr", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ctr_aes256() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "ofb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ofb_aes256() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "cbc", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_cbc_aes256() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "cfb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_cfb_aes256() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "ecb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ecb_aes256() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "ctr", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ctr_camellia128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "ofb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ofb_camellia128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "cbc", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_cbc_camellia128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "cfb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_cfb_camellia128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "ecb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ecb_camellia128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "ctr", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ctr_camellia192() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "ofb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ofb_camellia192() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "cbc", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_cbc_camellia192() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "cfb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_cfb_camellia192() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "ecb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ecb_camellia192() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "ctr", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ctr_camellia256() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "ofb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ofb_camellia256() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "cbc", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_cbc_camellia256() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "cfb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_cfb_camellia256() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "ecb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ecb_camellia256() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "ctr", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_in_place_ctr_sm4_128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(all(feature = "ofb", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_in_place_ofb_sm4_128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(all(feature = "cbc", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_in_place_cbc_sm4_128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(all(feature = "cfb", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_in_place_cfb_sm4_128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(all(feature = "ecb", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_in_place_ecb_sm4_128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

macro_rules! cfg_select_block_cipher_alg {
    (($f:literal, $id:expr)) => {
        #[cfg(feature = $f)]
        return $id;
        #[cfg(not(feature = $f))]
        {
            "Force compile error for no block cipher configured"
        }
    };
    (($f:literal, $id:expr), $(($f_more:literal, $id_more:expr)),+) => {
        #[cfg(feature = $f)]
        return $id;
        #[cfg(not(feature = $f))]
        {
            cfg_select_hash!($(($f_more, $id_more)),+)
        }
    };
}

pub const fn test_block_cipher_alg() -> SymBlockCipherAlg {
    cfg_select_block_cipher_alg!(
        ("aes", SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128)),
        (
            "camellia",
            SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128)
        ),
        ("sm4", SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128))
    );
}
