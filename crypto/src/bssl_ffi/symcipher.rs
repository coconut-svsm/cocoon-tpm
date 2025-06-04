// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! BoringSSL FFI backend for symmetric block ciphers.
//!
//! Use the low-level AES interface rather than EVP, because
//! * the [`SymBlockCipherModeEncryptionInstance`] and
//!   [`SymBlockCipherModeDecryptionInstance`] can be made
//!   [`Sync`](core::marker::Sync) then -- they're effectively immutable and
//! * Boring SSL provides the CFB mode through EVP only through the decrepit
//!   library.

// Lifetimes are not obvious at first sight here, make the explicit.
#![allow(clippy::needless_lifetimes)]

extern crate alloc;
use alloc::boxed::Box;

use cocoon_tpm_bssl_bare_sys as bssl_bare_sys;

use super::error::bssl_get_error;
use crate::symcipher::{self, transform_next_blocks, transform_next_blocks_in_place, SymBlockCipherAlg};
use crate::{
    io_slices::{CryptoPeekableIoSlicesMutIter, CryptoWalkableIoSlicesIter, CryptoWalkableIoSlicesMutIter},
    CryptoError,
};
use crate::{
    tpm2_interface,
    utils_common::{alloc::box_try_new_with, zeroize},
};
use core::{convert, ffi};

// Boring SSL supports only AES.
#[cfg(not(feature = "aes"))]
compile_error!("AES Cargo feature must be enabled for BoringSSL backend");

const AES_BLOCK_SIZE: usize = 16;

macro_rules! block_cipher_to_block_len {
    (Aes) => {
        AES_BLOCK_SIZE
    };
}

/// Boring SSL AES_KEY wrapper.
struct BsslAesKey {
    key: zeroize::ZeroizingFlat<bssl_bare_sys::AES_KEY>,
    key_size: symcipher::SymBlockCipherAesKeySize,
}

macro_rules! key_size_to_key_len {
    (128) => {
        16
    };
    (192) => {
        24
    };
    (256) => {
        32
    };
}

/// Generate a `match {}` on SymBlockCipherAesKeySize and invoke a macro in the
/// body of each match arm.
///
/// The supplied macro `m` gets invoked with (`$args`, key size) for each arm.
macro_rules! gen_match_on_aes_key_size {
    ($aes_key_size_value:expr, $m:ident $(, $($args:tt),*)?) => {
        match $aes_key_size_value {
            symcipher::SymBlockCipherAesKeySize::Aes128 => $m!($($($args:tt),*,)? 128),
            symcipher::SymBlockCipherAesKeySize::Aes192 => $m!($($($args:tt),*,)? 192),
            symcipher::SymBlockCipherAesKeySize::Aes256 => $m!($($($args:tt),*,)? 256),
        }
    };
}

fn aes_key_size_to_key_len(aes_key_size: symcipher::SymBlockCipherAesKeySize) -> usize {
    gen_match_on_aes_key_size!(aes_key_size, key_size_to_key_len)
}

impl BsslAesKey {
    fn new(
        key: &[u8],
        key_size: symcipher::SymBlockCipherAesKeySize,
        for_encrypt: bool,
    ) -> Result<Box<Self>, CryptoError> {
        let expected_key_len = aes_key_size_to_key_len(key_size);
        if key.len() != expected_key_len {
            return Err(CryptoError::KeySize);
        }

        let mut aes_key = box_try_new_with(|| -> Result<Self, convert::Infallible> {
            Ok(Self {
                key: zeroize::ZeroizingFlat::new(bssl_bare_sys::AES_KEY {
                    rd_key: [0u32; 60],
                    rounds: 0,
                }),
                key_size,
            })
        })?;

        let p_aes_key = &mut *aes_key.key as *mut bssl_bare_sys::AES_KEY;
        let p_key = key.as_ptr();
        let r = if for_encrypt {
            unsafe { bssl_bare_sys::AES_set_encrypt_key(p_key, 8 * expected_key_len as ffi::c_uint, p_aes_key) }
        } else {
            unsafe { bssl_bare_sys::AES_set_decrypt_key(p_key, 8 * expected_key_len as ffi::c_uint, p_aes_key) }
        };
        if r != 0 {
            return Err(bssl_get_error());
        }

        Ok(aes_key)
    }

    fn try_clone(&self) -> Result<Box<Self>, CryptoError> {
        // Constructing right into the allocated memory potentially saves a copy over
        // the stack.
        box_try_new_with(|| -> Result<Self, convert::Infallible> {
            Ok(Self {
                key: self.key.clone(),
                key_size: self.key_size,
            })
        })
        .map_err(CryptoError::from)
    }
}

/// [`BsslAesKey`] instantiated for encryption.
struct BsslAesEncKey {
    aes_key: Box<BsslAesKey>,
}

impl BsslAesEncKey {
    fn new(key: &[u8], key_size: symcipher::SymBlockCipherAesKeySize) -> Result<Self, CryptoError> {
        Ok(Self {
            aes_key: BsslAesKey::new(key, key_size, true)?,
        })
    }

    fn try_clone(&self) -> Result<Self, CryptoError> {
        Ok(Self {
            aes_key: self.aes_key.try_clone()?,
        })
    }

    fn as_ptr(&self) -> *const bssl_bare_sys::AES_KEY {
        &*self.aes_key.key as *const bssl_bare_sys::AES_KEY
    }

    fn get_aes_key_size(&self) -> symcipher::SymBlockCipherAesKeySize {
        self.aes_key.key_size
    }
}

/// [`BsslAesKey`] instantiated for decryption.
#[allow(unused)]
struct BsslAesDecKey {
    aes_key: Box<BsslAesKey>,
}

#[allow(unused)]
impl BsslAesDecKey {
    fn new(key: &[u8], key_size: symcipher::SymBlockCipherAesKeySize) -> Result<Self, CryptoError> {
        Ok(Self {
            aes_key: BsslAesKey::new(key, key_size, false)?,
        })
    }

    fn try_clone(&self) -> Result<Self, CryptoError> {
        Ok(Self {
            aes_key: self.aes_key.try_clone()?,
        })
    }

    fn as_ptr(&self) -> *const bssl_bare_sys::AES_KEY {
        &*self.aes_key.key as *const bssl_bare_sys::AES_KEY
    }

    fn get_aes_key_size(&self) -> symcipher::SymBlockCipherAesKeySize {
        self.aes_key.key_size
    }
}

#[cfg(feature = "ctr")]
struct BsslCtrAesEncryptor<'a> {
    aes_key: &'a BsslAesEncKey,
    ivec: [u8; AES_BLOCK_SIZE],
    ecount_buf: zeroize::ZeroizingFlat<[u8; AES_BLOCK_SIZE]>,
    num: ffi::c_uint,
}

#[cfg(feature = "ctr")]
impl<'a> BsslCtrAesEncryptor<'a> {
    fn new(aes_key: &'a BsslAesEncKey, iv: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            aes_key,
            ivec: *<&[u8; AES_BLOCK_SIZE]>::try_from(iv).map_err(|_| CryptoError::InvalidIV)?,
            ecount_buf: zeroize::ZeroizingFlat::new([0u8; AES_BLOCK_SIZE]),
            num: 0,
        })
    }

    fn transform(&mut self, dst: &mut [u8], src: Option<&[u8]>) {
        debug_assert!(src.map(|src| src.len() == dst.len()).unwrap_or(true));
        let len = dst.len();
        let p_aes_key: *const bssl_bare_sys::AES_KEY = self.aes_key.as_ptr();
        let p_dst = dst.as_mut_ptr();
        let p_src = src.map(|src| src.as_ptr()).unwrap_or(p_dst);
        let p_ivec = self.ivec.as_mut_ptr();
        let p_ecount_buf = self.ecount_buf.as_mut_ptr();
        let p_num = &mut self.num as *mut ffi::c_uint;

        unsafe { bssl_bare_sys::AES_ctr128_encrypt(p_src, p_dst, len, p_aes_key, p_ivec, p_ecount_buf, p_num) };
    }

    fn grab_iv(&self, iv_out: &mut [u8]) {
        // No IV retrieval after partial block processing.
        debug_assert_eq!(self.num, 0);
        debug_assert_eq!(iv_out.len(), self.ivec.len());
        iv_out.copy_from_slice(&self.ivec);
    }
}

#[cfg(feature = "ctr")]
type BsslCtrAesDecryptor<'a> = BsslCtrAesEncryptor<'a>;

#[cfg(feature = "ofb")]
struct BsslOfbAesEncryptor<'a> {
    aes_key: &'a BsslAesEncKey,
    ivec: zeroize::ZeroizingFlat<[u8; AES_BLOCK_SIZE]>,
    num: ffi::c_int,
}

#[cfg(feature = "ofb")]
impl<'a> BsslOfbAesEncryptor<'a> {
    fn new(aes_key: &'a BsslAesEncKey, iv: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            aes_key,
            ivec: zeroize::ZeroizingFlat::new(
                *<&[u8; AES_BLOCK_SIZE]>::try_from(iv).map_err(|_| CryptoError::InvalidIV)?,
            ),
            num: 0,
        })
    }

    fn transform(&mut self, dst: &mut [u8], src: Option<&[u8]>) {
        debug_assert!(src.map(|src| src.len() == dst.len()).unwrap_or(true));
        let len = dst.len();
        let p_aes_key: *const bssl_bare_sys::AES_KEY = self.aes_key.as_ptr();
        let p_dst = dst.as_mut_ptr();
        let p_src = src.map(|src| src.as_ptr()).unwrap_or(p_dst);
        let p_ivec = self.ivec.as_mut_ptr();
        let p_num = &mut self.num as *mut ffi::c_int;

        unsafe { bssl_bare_sys::AES_ofb128_encrypt(p_src, p_dst, len, p_aes_key, p_ivec, p_num) };
    }

    fn grab_iv(&self, iv_out: &mut [u8]) {
        // No IV retrieval after partial block processing.
        debug_assert_eq!(self.num, 0);
        debug_assert_eq!(iv_out.len(), self.ivec.len());
        iv_out.copy_from_slice(&*self.ivec);
    }
}

#[cfg(feature = "ofb")]
type BsslOfbAesDecryptor<'a> = BsslOfbAesEncryptor<'a>;

#[cfg(feature = "cbc")]
struct BsslCbcAesEncryptor<'a> {
    aes_key: &'a BsslAesEncKey,
    ivec: [u8; AES_BLOCK_SIZE],
}

#[cfg(feature = "cbc")]
impl<'a> BsslCbcAesEncryptor<'a> {
    fn new(aes_key: &'a BsslAesEncKey, iv: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            aes_key,
            ivec: *<&[u8; AES_BLOCK_SIZE]>::try_from(iv).map_err(|_| CryptoError::InvalidIV)?,
        })
    }

    fn transform(&mut self, dst: &mut [u8], src: Option<&[u8]>) {
        debug_assert!(src.map(|src| src.len() == dst.len()).unwrap_or(true));
        let len = dst.len();
        debug_assert_eq!(len % AES_BLOCK_SIZE, 0);
        let p_aes_key: *const bssl_bare_sys::AES_KEY = self.aes_key.as_ptr();
        let p_dst = dst.as_mut_ptr();
        let p_src = src.map(|src| src.as_ptr()).unwrap_or(p_dst);
        let p_ivec = self.ivec.as_mut_ptr();

        unsafe { bssl_bare_sys::AES_cbc_encrypt(p_src, p_dst, len, p_aes_key, p_ivec, bssl_bare_sys::AES_ENCRYPT) };
    }

    fn grab_iv(&self, iv_out: &mut [u8]) {
        // No IV retrieval after partial block processing.
        debug_assert_eq!(iv_out.len(), self.ivec.len());
        iv_out.copy_from_slice(&self.ivec);
    }
}

#[cfg(feature = "cbc")]
struct BsslCbcAesDecryptor<'a> {
    aes_key: &'a BsslAesDecKey,
    ivec: [u8; AES_BLOCK_SIZE],
}

#[cfg(feature = "cbc")]
impl<'a> BsslCbcAesDecryptor<'a> {
    fn new(aes_key: &'a BsslAesDecKey, iv: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            aes_key,
            ivec: *<&[u8; AES_BLOCK_SIZE]>::try_from(iv).map_err(|_| CryptoError::InvalidIV)?,
        })
    }

    fn transform(&mut self, dst: &mut [u8], src: Option<&[u8]>) {
        debug_assert!(src.map(|src| src.len() == dst.len()).unwrap_or(true));
        let len = dst.len();
        debug_assert_eq!(len % AES_BLOCK_SIZE, 0);
        let p_aes_key: *const bssl_bare_sys::AES_KEY = self.aes_key.as_ptr();
        let p_dst = dst.as_mut_ptr();
        let p_src = src.map(|src| src.as_ptr()).unwrap_or(p_dst);
        let p_ivec = self.ivec.as_mut_ptr();

        unsafe { bssl_bare_sys::AES_cbc_encrypt(p_src, p_dst, len, p_aes_key, p_ivec, bssl_bare_sys::AES_DECRYPT) };
    }

    fn grab_iv(&self, iv_out: &mut [u8]) {
        // No IV retrieval after partial block processing.
        debug_assert_eq!(iv_out.len(), self.ivec.len());
        iv_out.copy_from_slice(&self.ivec);
    }
}

#[cfg(feature = "cfb")]
struct BsslCfbAesEncryptorImpl<'a, const ENCRYPT: bool> {
    aes_key: &'a BsslAesEncKey,
    ivec: [u8; AES_BLOCK_SIZE],
    num: ffi::c_int,
}

#[cfg(feature = "cfb")]
impl<'a, const ENCRYPT: bool> BsslCfbAesEncryptorImpl<'a, ENCRYPT> {
    fn new(aes_key: &'a BsslAesEncKey, iv: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            aes_key,
            ivec: *<&[u8; AES_BLOCK_SIZE]>::try_from(iv).map_err(|_| CryptoError::InvalidIV)?,
            num: 0,
        })
    }

    fn transform(&mut self, dst: &mut [u8], src: Option<&[u8]>) {
        debug_assert!(src.map(|src| src.len() == dst.len()).unwrap_or(true));
        let len = dst.len();
        let p_aes_key: *const bssl_bare_sys::AES_KEY = self.aes_key.as_ptr();
        let p_dst = dst.as_mut_ptr();
        let p_src = src.map(|src| src.as_ptr()).unwrap_or(p_dst);
        let p_ivec = self.ivec.as_mut_ptr();
        let p_num = &mut self.num as *mut ffi::c_int;

        unsafe {
            bssl_bare_sys::AES_cfb128_encrypt(
                p_src,
                p_dst,
                len,
                p_aes_key,
                p_ivec,
                p_num,
                if ENCRYPT {
                    bssl_bare_sys::AES_ENCRYPT
                } else {
                    bssl_bare_sys::AES_DECRYPT
                },
            )
        };
    }

    fn grab_iv(&self, iv_out: &mut [u8]) {
        // No IV retrieval after partial block processing.
        debug_assert_eq!(self.num, 0);
        debug_assert_eq!(iv_out.len(), self.ivec.len());
        iv_out.copy_from_slice(&self.ivec);
    }
}

#[cfg(feature = "cfb")]
type BsslCfbAesEncryptor<'a> = BsslCfbAesEncryptorImpl<'a, true>;

#[cfg(feature = "cfb")]
type BsslCfbAesDecryptor<'a> = BsslCfbAesEncryptorImpl<'a, false>;

#[cfg(feature = "ecb")]
struct BsslEcbAesEncryptor<'a> {
    aes_key: &'a BsslAesEncKey,
}

#[cfg(feature = "ecb")]
impl<'a> BsslEcbAesEncryptor<'a> {
    fn new(aes_key: &'a BsslAesEncKey) -> Result<Self, CryptoError> {
        Ok(Self { aes_key })
    }

    fn transform(&mut self, dst: &mut [u8], src: Option<&[u8]>) {
        debug_assert!(src.map(|src| src.len() == dst.len()).unwrap_or(true));
        let mut len = dst.len();
        debug_assert_eq!(len % AES_BLOCK_SIZE, 0);
        let p_aes_key: *const bssl_bare_sys::AES_KEY = self.aes_key.as_ptr();
        let mut p_dst = dst.as_mut_ptr();
        let mut p_src = src.map(|src| src.as_ptr()).unwrap_or(p_dst);

        while len != 0 {
            unsafe { bssl_bare_sys::AES_ecb_encrypt(p_src, p_dst, p_aes_key, bssl_bare_sys::AES_ENCRYPT) };
            len -= AES_BLOCK_SIZE;
            p_dst = unsafe { p_dst.add(AES_BLOCK_SIZE) };
            p_src = unsafe { p_src.add(AES_BLOCK_SIZE) };
        }
    }
}

#[cfg(feature = "ecb")]
struct BsslEcbAesDecryptor<'a> {
    aes_key: &'a BsslAesDecKey,
}

#[cfg(feature = "ecb")]
impl<'a> BsslEcbAesDecryptor<'a> {
    fn new(aes_key: &'a BsslAesDecKey) -> Result<Self, CryptoError> {
        Ok(Self { aes_key })
    }

    fn transform(&mut self, dst: &mut [u8], src: Option<&[u8]>) {
        debug_assert!(src.map(|src| src.len() == dst.len()).unwrap_or(true));
        let mut len = dst.len();
        debug_assert_eq!(len % AES_BLOCK_SIZE, 0);
        let p_aes_key: *const bssl_bare_sys::AES_KEY = self.aes_key.as_ptr();
        let mut p_dst = dst.as_mut_ptr();
        let mut p_src = src.map(|src| src.as_ptr()).unwrap_or(p_dst);

        while len != 0 {
            unsafe { bssl_bare_sys::AES_ecb_encrypt(p_src, p_dst, p_aes_key, bssl_bare_sys::AES_DECRYPT) };
            len -= AES_BLOCK_SIZE;
            p_dst = unsafe { p_dst.add(AES_BLOCK_SIZE) };
            p_src = unsafe { p_src.add(AES_BLOCK_SIZE) };
        }
    }
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

/// Map a pair of (symbolic mode, symbolic block cipher) to the IV length.
macro_rules! mode_and_block_cipher_to_iv_len {
    (Ctr, $block_alg_id:ident) => {
        block_cipher_to_block_len!($block_alg_id)
    };
    (Ofb, $block_alg_id:ident) => {
        block_cipher_to_block_len!($block_alg_id)
    };
    (Cbc, $block_alg_id:ident) => {
        block_cipher_to_block_len!($block_alg_id)
    };
    (Cfb, $block_alg_id:ident) => {
        block_cipher_to_block_len!($block_alg_id)
    };
    (Ecb, $_block_alg_id:ident) => {
        0
    };
}

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

// Used internally from multiple functions of
// SymBlockCipherModeEncryptionInstanceState
// and SymBlockCipherModeDecryptionInstanceState.
macro_rules! sym_block_cipher_mode_instance_gen_transform {
    ($gen_mode_transform_new_impl_instance_snippet:ident,
     $gen_mode_transform_grab_iv_snippet:ident,
     $dst_io_slices:ident,
     $src_io_slices:ident,
     $iv:ident, $iv_out_opt:ident,
     $mode_id:ident, $block_alg_id:ident, $block_cipher_key_instance:ident) => {{
        const MODE_SUPPORTS_PARTIAL_LAST_BLOCK: bool = mode_supports_partial_last_block!($mode_id);
        const BLOCK_LEN: usize = block_cipher_to_block_len!($block_alg_id);
        let dst_len = $dst_io_slices.total_len()?;
        if dst_len % BLOCK_LEN != 0 {
            if !MODE_SUPPORTS_PARTIAL_LAST_BLOCK {
                return Err(CryptoError::InvalidMessageLength);
            } else if $iv_out_opt.is_some() {
                // Don't allow iv_out retrieval for partial last blocks.
                return Err(CryptoError::Internal);
            }
        }
        if $src_io_slices.total_len()? != dst_len {
            return Err(CryptoError::Internal);
        }

        let mut mode_transform_impl_instance = $gen_mode_transform_new_impl_instance_snippet!(
            $mode_id,
            $block_alg_id,
            $block_cipher_key_instance,
            $iv,
            $iv_out_opt,
        )?;

        let mut scratch_block_buf = zeroize::Zeroizing::from([0u8; BLOCK_LEN]);

        loop {
            if !transform_next_blocks::<MODE_SUPPORTS_PARTIAL_LAST_BLOCK, _>(
                $dst_io_slices,
                $src_io_slices,
                |dst_blocks: &mut [u8], src_blocks: Option<&[u8]>| {
                    mode_transform_impl_instance.transform(dst_blocks, src_blocks);
                },
                BLOCK_LEN,
                scratch_block_buf.as_mut_slice(),
            )? {
                break;
            }
        }

        $gen_mode_transform_grab_iv_snippet!($mode_id, $block_alg_id, mode_transform_impl_instance, $iv_out_opt);
    }};
}

// Used internally from multiple functions of
// SymBlockCipherModeEncryptionInstanceState
// and SymBlockCipherModeDecryptionInstanceState.
macro_rules! sym_block_cipher_mode_instance_gen_transform_in_place {
    ($gen_mode_transform_new_impl_instance_snippet:ident,
     $gen_mode_transform_grab_iv_snippet:ident,
     $dst_io_slices:ident,
     $iv:ident, $iv_out_opt:ident,
     $mode_id:ident, $block_alg_id:ident, $block_cipher_key_instance:ident) => {{
        const MODE_SUPPORTS_PARTIAL_LAST_BLOCK: bool = mode_supports_partial_last_block!($mode_id);
        const BLOCK_LEN: usize = block_cipher_to_block_len!($block_alg_id);
        let dst_len = $dst_io_slices.total_len()?;
        if dst_len % BLOCK_LEN != 0 {
            if !MODE_SUPPORTS_PARTIAL_LAST_BLOCK {
                return Err(CryptoError::InvalidMessageLength);
            } else if $iv_out_opt.is_some() {
                // Don't allow iv_out retrieval for partial last blocks.
                return Err(CryptoError::Internal);
            }
        }

        let mut mode_transform_impl_instance = $gen_mode_transform_new_impl_instance_snippet!(
            $mode_id,
            $block_alg_id,
            $block_cipher_key_instance,
            $iv,
            $iv_out_opt,
        )?;

        let mut scratch_block_buf = zeroize::Zeroizing::from([0u8; BLOCK_LEN]);

        loop {
            if !transform_next_blocks_in_place::<MODE_SUPPORTS_PARTIAL_LAST_BLOCK, _, _>(
                &mut $dst_io_slices,
                |dst_blocks: &mut [u8]| mode_transform_impl_instance.transform(dst_blocks, None),
                BLOCK_LEN,
                scratch_block_buf.as_mut_slice(),
            )? {
                break;
            }
        }

        $gen_mode_transform_grab_iv_snippet!($mode_id, $block_alg_id, mode_transform_impl_instance, $iv_out_opt);
    }};
}

// Generate code snippet for obtaining the IV from for (external) mode
// implementations.
//
// Common to SymBlockCipherModeEncryptionInstanceState::encrypt()/
// ::encrypt_in_place() and
// SymBlockCipherModeDecryptionInstanceState::decrypt()/ ::decrypt_in_place().
macro_rules! gen_mode_transform_grab_iv_snippet {
    (Ecb, $_block_alg_id:ident, $_mode_transform_impl_instance:ident, $iv_out_opt:ident) => {{
        debug_assert!($iv_out_opt.map(|iv_out| iv_out.is_empty()).unwrap_or(true));
    }};
    ($_mode_id:ident, Aes, $mode_transform_impl_instance:ident, $iv_out_opt:ident) => {{
        if let Some(iv_out) = $iv_out_opt {
            $mode_transform_impl_instance.grab_iv(iv_out);
        }
    }};
}

pub struct SymBlockCipherModeEncryptionInstance {
    state: SymBlockCipherModeEncryptionInstanceState,
}

impl SymBlockCipherModeEncryptionInstance {
    /// Instantiate a `SymBlockCipherModeEncryptionInstance` from a triplet of
    /// [block cipher mode identifier](tpm2_interface::TpmiAlgCipherMode),
    /// [symmetric block cipher algorithm identifier](SymBlockCipherAlg) and
    /// a raw key byte slice.
    ///
    /// # Arguments:
    ///
    /// * `mode_id`  - The [block cipher
    ///   mode](tpm2_interface::TpmiAlgCipherMode) to use.
    /// * `alg_id` - The [symmetric block cipher algorithm](SymBlockCipherAlg)
    ///   to be used for this instance.
    /// * `key` - The raw key bytes. It's length must match the [expected key
    ///   length](SymBlockCipherAlg::key_len) for `alg` or an error will get
    ///   returned.
    #[inline(never)]
    pub fn new(
        mode_id: tpm2_interface::TpmiAlgCipherMode,
        alg_id: &SymBlockCipherAlg,
        key: &[u8],
    ) -> Result<Self, CryptoError> {
        Ok(Self {
            state: SymBlockCipherModeEncryptionInstanceState::new(mode_id, alg_id, key)?,
        })
    }

    /// Try to clone a `SymBlockModeCipherEncryptionInstance`.
    #[inline(never)]
    pub fn try_clone(&self) -> Result<Self, CryptoError> {
        Ok(Self {
            state: self.state.try_clone()?,
        })
    }

    /// Obtain the instance's associated block cipher algorithm's block length.
    ///
    /// Equivalent to
    /// [`SymBlockCipherAlg::block_len()`](SymBlockCipherAlg::block_len).
    pub fn block_cipher_block_len(&self) -> usize {
        self.state.block_cipher_block_len()
    }

    /// Determine the IV length for use with
    /// `SymBlockCipherModeEncryptionInstance`.
    ///
    /// Equivalent to
    /// [`SymBlockCipherAlg::iv_len_for_mode()`](SymBlockCipherAlg::iv_len_for_mode).
    pub fn iv_len(&self) -> usize {
        self.state.iv_len()
    }

    /// Encrypt data from buffer to buffer.
    ///
    /// The source and destination buffers must be equal in length or an error
    /// will get returned. Depending on the block cipher mode, their lengths
    /// must perhaps be aligned to the [block cipher block
    /// length](Self::block_cipher_block_len), an error will get returned
    /// otherwise. No padding will get inserted.
    ///
    /// Processing a request does not alter `self`'s state -- in particular the
    /// IV must get provided for each new requst anew.
    ///
    /// # Arguments:
    ///
    /// * `iv` - The IV to use. Its length must match the expected [IV
    ///   length](Self::iv_len).
    /// * `dst` - The destination buffers to write the encrypted message to.
    /// * `src` - The source buffers holding the cleartext message to encrypt.
    /// * `iv_out` - Optional buffer receiving the final IV as ouput from the
    ///   block cipher mode. Attempting to retrieve the final IV when the to be
    ///   encrypted data's length is not an integral multiple of the [block
    ///   cipher block size ](Self::block_cipher_block_len) is ill-defined and
    ///   considered an error.
    pub fn encrypt<'a, 'b, DI: CryptoWalkableIoSlicesMutIter<'a>, SI: CryptoWalkableIoSlicesIter<'b>>(
        &self,
        iv: &[u8],
        mut dst: DI,
        mut src: SI,
        iv_out: Option<&mut [u8]>,
    ) -> Result<(), CryptoError> {
        self.state.encrypt(iv, &mut dst, &mut src, iv_out)
    }

    /// Encrypt data in place.
    ///
    /// Depending on the block cipher mode, the source/destination buffer's
    /// length must perhaps be aligned to the [block cipher block
    /// length](Self::block_cipher_block_len), an error will get returned
    /// otherwise. No padding will get inserted.
    ///
    /// Processing a request does not alter `self`'s state -- in particular the
    /// IV must get provided for each new requst anew.
    ///
    /// <div class="warning">
    ///
    /// Unlike it's the case with [`encrypt()`](Self::encrypt), the
    /// source/destination buffer's generic `DI` type is not `dyn`
    /// compatible. The compiler will emit a separate instance for each
    /// individual `DI` `encrypt_in_place()` gets invoked with. Be vigilant
    /// of template bloat, prefer [`encrypt()`](Self::encrypt) if feasible and
    /// try to not use too exotic types for `DI` here otherwise.
    ///
    /// </div>
    ///
    /// # Arguments:
    ///
    /// * `iv` - The IV to use. Its length must match the expected [IV
    ///   length](Self::iv_len).
    /// * `dst` - The source/destination buffers initially holding the cleartext
    ///   message and receiving the encrypted result.
    /// * `iv_out` - Optional buffer receiving the final IV as ouput from the
    ///   block cipher mode. Attempting to retrieve the final IV when the to be
    ///   encrypted data's length is not an integral multiple of the [block
    ///   cipher block size ](Self::block_cipher_block_len) is ill-defined and
    ///   considered an error.
    pub fn encrypt_in_place<'a, 'b, DI: CryptoPeekableIoSlicesMutIter<'a>>(
        &self,
        iv: &[u8],
        dst: DI,
        iv_out: Option<&mut [u8]>,
    ) -> Result<(), CryptoError> {
        self.state.encrypt_in_place(iv, dst, iv_out)
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for SymBlockCipherModeEncryptionInstance {}

impl convert::From<&SymBlockCipherModeEncryptionInstance> for SymBlockCipherAlg {
    fn from(value: &SymBlockCipherModeEncryptionInstance) -> Self {
        SymBlockCipherAlg::from(&value.state)
    }
}

/// Map a symbolic mode to either BsslAesEncKey or BsslAesDecKey as is suitable
/// for encryption with that mode
macro_rules! enc_mode_to_bssl_aes_key_impl {
    (Ctr) => {
        BsslAesEncKey
    };
    (Ofb) => {
        BsslAesEncKey
    };
    (Cbc) => {
        BsslAesEncKey
    };
    (Cfb) => {
        BsslAesEncKey
    };
    (Ecb) => {
        BsslAesEncKey
    };
}

#[allow(clippy::enum_variant_names)]
enum SymBlockCipherModeEncryptionInstanceState {
    #[cfg(all(feature = "ctr", feature = "aes"))]
    CtrAes(enc_mode_to_bssl_aes_key_impl!(Ctr)),
    #[cfg(all(feature = "ofb", feature = "aes"))]
    OfbAes(enc_mode_to_bssl_aes_key_impl!(Ofb)),
    #[cfg(all(feature = "cbc", feature = "aes"))]
    CbcAes(enc_mode_to_bssl_aes_key_impl!(Cbc)),
    #[cfg(all(feature = "cfb", feature = "aes"))]
    CfbAes(enc_mode_to_bssl_aes_key_impl!(Cfb)),
    #[cfg(all(feature = "ecb", feature = "aes"))]
    EcbAes(enc_mode_to_bssl_aes_key_impl!(Ecb)),
}

/// Generate a `match {}` on SymBlockCipherModeEncryptionInstanceState and
/// invoke a macro in the body of each match arm.
///
/// The supplied macro `m` gets invoked with (`$args`, symbolic mode, symbolic
/// block cipher, $block_cipher_key_instance`) for each arm, where identifier
/// `$block_cipher_key_instance` is bound to the variant's respective block
/// cipher key instance member. The symbolic block cipher is 'Aes' always,
/// because nothing else is supported by BoringSSL.
macro_rules! gen_match_on_block_cipher_mode_encryption_instance {
    ($block_cipher_mode_instance_value:expr, $m:ident, $block_cipher_key_instance:ident $(, $($args:tt),*)?) => {
        match $block_cipher_mode_instance_value {
            #[cfg(all(feature = "ctr", feature = "aes"))]
            SymBlockCipherModeEncryptionInstanceState::CtrAes($block_cipher_key_instance) => {
                $m!($($($args),*,)? Ctr, Aes, $block_cipher_key_instance)
            },
            #[cfg(all(feature = "ofb", feature = "aes"))]
            SymBlockCipherModeEncryptionInstanceState::OfbAes($block_cipher_key_instance) => {
                $m!($($($args),*,)? Ofb, Aes, $block_cipher_key_instance)
            },
            #[cfg(all(feature = "cbc", feature = "aes"))]
            SymBlockCipherModeEncryptionInstanceState::CbcAes($block_cipher_key_instance) => {
                $m!($($($args),*,)? Cbc, Aes, $block_cipher_key_instance)
            },
            #[cfg(all(feature = "cfb", feature = "aes"))]
            SymBlockCipherModeEncryptionInstanceState::CfbAes($block_cipher_key_instance) => {
                $m!($($($args),*,)? Cfb, Aes, $block_cipher_key_instance)
            },
            #[cfg(all(feature = "ecb", feature = "aes"))]
            SymBlockCipherModeEncryptionInstanceState::EcbAes($block_cipher_key_instance) => {
                $m!($($($args),*,)? Ecb, Aes, $block_cipher_key_instance)
            },
        }
    };
}

/// Map a pair of (symbolic mode, symbolic block cipher) to a variant of
/// SymBlockCipherModeEncryptionInstanceState. The symbolic block cipher must be
/// 'Aes', because nothing else is supported by BoringSSL.
macro_rules! mode_and_block_cipher_to_block_cipher_mode_encryption_instance_variant {
    (Ctr, Aes) => {
        SymBlockCipherModeEncryptionInstanceState::CtrAes
    };
    (Ofb, Aes) => {
        SymBlockCipherModeEncryptionInstanceState::OfbAes
    };
    (Cbc, Aes) => {
        SymBlockCipherModeEncryptionInstanceState::CbcAes
    };
    (Cfb, Aes) => {
        SymBlockCipherModeEncryptionInstanceState::CfbAes
    };
    (Ecb, Aes) => {
        SymBlockCipherModeEncryptionInstanceState::EcbAes
    };
}

macro_rules! mode_to_aes_enc_impl {
    (Ctr) => {
        BsslCtrAesEncryptor
    };
    (Ofb) => {
        BsslOfbAesEncryptor
    };
    (Cbc) => {
        BsslCbcAesEncryptor
    };
    (Cfb) => {
        BsslCfbAesEncryptor
    };
    (Ecb) => {
        BsslEcbAesEncryptor
    };
}

// Instantiate a block cipher mode implementation wrapping a block cipher
// key instance. Used from SymBlockCipherModeEncryptionInstanceState::encrypt()
// and SymBlockCipherModeEncryptionInstanceState::encrypt_in_place().
macro_rules! gen_mode_encryptor_impl_new_instance_snippet {
    (Ecb,
     Aes,
     $block_cipher_key_instance:ident,
     $iv:ident,
     $iv_out_opt:ident,
    ) => {{
        if $iv.len() != 0 {
            return Err(CryptoError::InvalidIV);
        } else if !$iv_out_opt.as_ref().map(|iv_out| iv_out.is_empty()).unwrap_or(true) {
            return Err(CryptoError::Internal);
        }

        <mode_to_aes_enc_impl!(Ecb)>::new($block_cipher_key_instance)
    }};
    ($mode_id:ident,
     Aes,
     $block_cipher_key_instance:ident,
     $iv:ident,
     $iv_out_opt:ident,
    ) => {{
        let expected_iv_len = AES_BLOCK_SIZE;
        if $iv.len() != expected_iv_len {
            return Err(CryptoError::InvalidIV);
        } else if $iv_out_opt
            .as_ref()
            .map(|iv_out| iv_out.len() != expected_iv_len)
            .unwrap_or(false)
        {
            return Err(CryptoError::Internal);
        }

        <mode_to_aes_enc_impl!($mode_id)>::new($block_cipher_key_instance, $iv)
    }};
}

impl SymBlockCipherModeEncryptionInstanceState {
    fn new(mode: tpm2_interface::TpmiAlgCipherMode, alg: &SymBlockCipherAlg, key: &[u8]) -> Result<Self, CryptoError> {
        macro_rules! gen_instantiate {
            (Aes, $aes_key_size_value:expr, $mode_id:ident) => {
                mode_and_block_cipher_to_block_cipher_mode_encryption_instance_variant!($mode_id, Aes)(
                    <enc_mode_to_bssl_aes_key_impl!($mode_id)>::new(key, $aes_key_size_value)?,
                )
            };
        }

        match alg {
            #[cfg(feature = "aes")]
            SymBlockCipherAlg::Aes(aes_key_size) => Ok(gen_match_on_tpmi_alg_cipher_mode!(
                mode,
                gen_instantiate,
                Aes,
                (*aes_key_size)
            )),
            #[cfg(feature = "camellia")]
            SymBlockCipherAlg::Camellia(_) => {
                compile_error!("Camellia cipher not supported with BoringSSL backend");
            }
            #[cfg(feature = "sm4")]
            SymBlockCipherAlg::Sm4(_) => {
                compile_error!("SM4 cipher not supported with BoringSSL backend");
            }
        }
    }

    fn try_clone(&self) -> Result<Self, CryptoError> {
        macro_rules! gen_try_clone {
            ($mode_id:ident, $block_cipher_alg_id:ident, $block_cipher_key_instance:ident) => {
                mode_and_block_cipher_to_block_cipher_mode_encryption_instance_variant!($mode_id, $block_cipher_alg_id)(
                    $block_cipher_key_instance.try_clone()?,
                )
            };
        }

        Ok(gen_match_on_block_cipher_mode_encryption_instance!(
            self,
            gen_try_clone,
            block_cipher_key_instance
        ))
    }

    fn block_cipher_block_len(&self) -> usize {
        macro_rules! gen_block_cipher_block_len {
            ($_mode_id:ident, $block_cipher_alg_id:ident, $_block_cipher_key_instance:ident) => {
                block_cipher_to_block_len!($block_cipher_alg_id)
            };
        }
        gen_match_on_block_cipher_mode_encryption_instance!(
            self,
            gen_block_cipher_block_len,
            _block_cipher_key_instance
        )
    }

    fn iv_len(&self) -> usize {
        macro_rules! gen_iv_len_for_mode_and_block_cipher {
            ($mode_id:ident,
              $block_alg_id:ident,
              $_block_cipher_key_instance:ident) => {
                mode_and_block_cipher_to_iv_len!($mode_id, $block_alg_id)
            };
        }
        gen_match_on_block_cipher_mode_encryption_instance!(
            self,
            gen_iv_len_for_mode_and_block_cipher,
            _block_cipher_instance
        )
    }

    #[inline(never)]
    fn encrypt<'a, 'b>(
        &self,
        iv: &[u8],
        dst: &mut dyn CryptoWalkableIoSlicesMutIter<'a>,
        src: &mut dyn CryptoWalkableIoSlicesIter<'b>,
        iv_out: Option<&mut [u8]>,
    ) -> Result<(), CryptoError> {
        gen_match_on_block_cipher_mode_encryption_instance!(
            self,
            sym_block_cipher_mode_instance_gen_transform,
            block_cipher_key_instance,
            gen_mode_encryptor_impl_new_instance_snippet,
            gen_mode_transform_grab_iv_snippet,
            dst,
            src,
            iv,
            iv_out
        );

        Ok(())
    }

    #[inline(never)]
    fn encrypt_in_place<'a, DI: CryptoPeekableIoSlicesMutIter<'a>>(
        &self,
        iv: &[u8],
        mut dst: DI,
        iv_out: Option<&mut [u8]>,
    ) -> Result<(), CryptoError> {
        gen_match_on_block_cipher_mode_encryption_instance!(
            self,
            sym_block_cipher_mode_instance_gen_transform_in_place,
            block_cipher_instance,
            gen_mode_encryptor_impl_new_instance_snippet,
            gen_mode_transform_grab_iv_snippet,
            dst,
            iv,
            iv_out
        );

        Ok(())
    }
}

impl convert::From<&SymBlockCipherModeEncryptionInstanceState> for SymBlockCipherAlg {
    fn from(value: &SymBlockCipherModeEncryptionInstanceState) -> Self {
        macro_rules! gen_block_cipher_to_block_cipher_alg {
            ($_mode_id:ident,
             Aes,
             $block_cipher_key_instance:ident) => {
                SymBlockCipherAlg::Aes($block_cipher_key_instance.get_aes_key_size())
            };
        }
        gen_match_on_block_cipher_mode_encryption_instance!(
            value,
            gen_block_cipher_to_block_cipher_alg,
            block_cipher_key_instance
        )
    }
}

pub struct SymBlockCipherModeDecryptionInstance {
    state: SymBlockCipherModeDecryptionInstanceState,
}

impl SymBlockCipherModeDecryptionInstance {
    /// Instantiate a `SymBlockCipherModeDecryptionInstance` from a triplet of
    /// [block cipher mode identifier](tpm2_interface::TpmiAlgCipherMode),
    /// [symmetric block cipher algorithm identifier](SymBlockCipherAlg) and
    /// a raw key byte slice.
    ///
    /// # Arguments:
    ///
    /// * `mode_id`  - The [block cipher
    ///   mode](tpm2_interface::TpmiAlgCipherMode) to use.
    /// * `alg_id` - The [symmetric block cipher algorithm](SymBlockCipherAlg)
    ///   to be used for this instance.
    /// * `key` - The raw key bytes. It's length must match the [expected key
    ///   length](SymBlockCipherAlg::key_len) for `alg` or an error will get
    ///   returned.
    #[inline(never)]
    pub fn new(
        mode_id: tpm2_interface::TpmiAlgCipherMode,
        alg_id: &SymBlockCipherAlg,
        key: &[u8],
    ) -> Result<Self, CryptoError> {
        Ok(Self {
            state: SymBlockCipherModeDecryptionInstanceState::new(mode_id, alg_id, key)?,
        })
    }

    /// Try to clone a `SymBlockCipherDecryptionInstance`.
    #[inline(never)]
    pub fn try_clone(&self) -> Result<Self, CryptoError> {
        Ok(Self {
            state: self.state.try_clone()?,
        })
    }

    /// Obtain the instance's associated block cipher algorithm's block length.
    ///
    /// Equivalent to
    /// [`SymBlockCipherAlg::block_len()`](SymBlockCipherAlg::block_len).
    pub fn block_cipher_block_len(&self) -> usize {
        self.state.block_cipher_block_len()
    }

    /// Determine the IV length for use with
    /// `SymBlockCipherModeDecryptionInstance`.
    ///
    /// Equivalent to
    /// [`SymBlockCipherAlg::iv_len_for_mode()`](SymBlockCipherAlg::iv_len_for_mode).
    pub fn iv_len(&self) -> usize {
        self.state.iv_len()
    }

    /// Decrypt data from buffer to buffer.
    ///
    /// The source and destination buffers must be equal in length or an error
    /// will get returned. Depending on the block cipher mode, their lengths
    /// must perhaps be aligned to the [block cipher block
    /// length](Self::block_cipher_block_len), an error will get returned
    /// otherwise. No padding format verification will be done.
    ///
    /// Processing a request does not alter `self`'s state -- in particular the
    /// IV must get provided for each new requst anew.
    ///
    /// # Arguments:
    ///
    /// * `iv` - The IV to use. Its length must match the expected [IV
    ///   length](Self::iv_len).
    /// * `dst` - The destination buffers to write the decrypted message to.
    /// * `src` - The source buffers holding the encrypted message.
    /// * `iv_out` - Optional buffer receiving the final IV as ouput from the
    ///   block cipher mode. Attempting to retrieve the final IV when the to be
    ///   encrypted data's length is not an integral multiple of the [block
    ///   cipher block size ](Self::block_cipher_block_len) is ill-defined and
    ///   considered an error.
    pub fn decrypt<'a, 'b, DI: CryptoWalkableIoSlicesMutIter<'a>, SI: CryptoWalkableIoSlicesIter<'b>>(
        &self,
        iv: &[u8],
        mut dst: DI,
        mut src: SI,
        iv_out: Option<&mut [u8]>,
    ) -> Result<(), CryptoError> {
        self.state.decrypt(iv, &mut dst, &mut src, iv_out)
    }

    /// Decrypt data in place.
    ///
    /// Depending on the block cipher mode, the source/destination buffer's
    /// length must perhaps be aligned to the [block cipher block
    /// length](Self::block_cipher_block_len), an error will get
    /// returned otherwise. . No padding format verification will be done.
    ///
    /// Processing a request does not alter `self`'s state -- in particular the
    /// IV must get provided for each new requst anew.
    ///
    /// <div class="warning">
    ///
    /// Unlike it's the case with [`decrypt()`](Self::decrypt), the
    /// source/destination buffer's generic `DI` type is not `dyn`
    /// compatible. The compiler will emit a separate instance for each
    /// individual `DI` `decrypt_in_place()` gets invoked with. Be vigilant
    /// of template bloat, prefer [`decrypt()`](Self::decrypt) if feasible and
    /// try to not use too exotic types for `DI` here otherwise.
    ///
    /// </div>
    ///
    /// # Arguments:
    ///
    /// * `iv` - The IV to use. Its length must match the expected [IV
    ///   length](Self::iv_len).
    /// * `dst` - The source/destination buffers initially holding the encryted
    ///   message and receiving the decrypted cleartext result.
    /// * `iv_out` - Optional buffer receiving the final IV as ouput from the
    ///   block cipher mode. Attempting to retrieve the final IV when the to be
    ///   encrypted data's length is not an integral multiple of the [block
    ///   cipher block size ](Self::block_cipher_block_len) is ill-defined and
    ///   considered an error.
    pub fn decrypt_in_place<'a, 'b, DI: CryptoPeekableIoSlicesMutIter<'a>>(
        &self,
        iv: &[u8],
        dst: DI,
        iv_out: Option<&mut [u8]>,
    ) -> Result<(), CryptoError> {
        self.state.decrypt_in_place(iv, dst, iv_out)
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for SymBlockCipherModeDecryptionInstance {}

impl convert::From<&SymBlockCipherModeDecryptionInstance> for SymBlockCipherAlg {
    fn from(value: &SymBlockCipherModeDecryptionInstance) -> Self {
        SymBlockCipherAlg::from(&value.state)
    }
}

/// Map a symbolic mode to either BsslAesEncKey or BsslAesDecKey as is suitable
/// for decryption with that mode
macro_rules! dec_mode_to_bssl_aes_key_impl {
    (Ctr) => {
        BsslAesEncKey
    };
    (Ofb) => {
        BsslAesEncKey
    };
    (Cbc) => {
        BsslAesDecKey
    };
    (Cfb) => {
        BsslAesEncKey
    };
    (Ecb) => {
        BsslAesDecKey
    };
}

#[allow(clippy::enum_variant_names)]
enum SymBlockCipherModeDecryptionInstanceState {
    #[cfg(all(feature = "ctr", feature = "aes"))]
    CtrAes(dec_mode_to_bssl_aes_key_impl!(Ctr)),
    #[cfg(all(feature = "ofb", feature = "aes"))]
    OfbAes(dec_mode_to_bssl_aes_key_impl!(Ofb)),
    #[cfg(all(feature = "cbc", feature = "aes"))]
    CbcAes(dec_mode_to_bssl_aes_key_impl!(Cbc)),
    #[cfg(all(feature = "cfb", feature = "aes"))]
    CfbAes(dec_mode_to_bssl_aes_key_impl!(Cfb)),
    #[cfg(all(feature = "ecb", feature = "aes"))]
    EcbAes(dec_mode_to_bssl_aes_key_impl!(Ecb)),
}

/// Generate a `match {}` on SymBlockCipherModeDecryptionInstanceState and
/// invoke a macro in the body of each match arm.
///
/// The supplied macro `m` gets invoked with (`$args`, symbolic mode, symbolic
/// block cipher, $block_cipher_key_instance`) for each arm, where identifier
/// `$block_cipher_key_instance` is bound to the variant's respective block
/// cipher key instance member. The symbolic block cipher is 'Aes' always,
/// because nothing else is supported by BoringSSL.
macro_rules! gen_match_on_block_cipher_mode_decryption_instance {
    ($block_cipher_mode_instance_value:expr, $m:ident, $block_cipher_key_instance:ident $(, $($args:tt),*)?) => {
        match $block_cipher_mode_instance_value {
            #[cfg(all(feature = "ctr", feature = "aes"))]
            SymBlockCipherModeDecryptionInstanceState::CtrAes($block_cipher_key_instance) => {
                $m!($($($args),*,)? Ctr, Aes, $block_cipher_key_instance)
            },
            #[cfg(all(feature = "ofb", feature = "aes"))]
            SymBlockCipherModeDecryptionInstanceState::OfbAes($block_cipher_key_instance) => {
                $m!($($($args),*,)? Ofb, Aes, $block_cipher_key_instance)
            },
            #[cfg(all(feature = "cbc", feature = "aes"))]
            SymBlockCipherModeDecryptionInstanceState::CbcAes($block_cipher_key_instance) => {
                $m!($($($args),*,)? Cbc, Aes, $block_cipher_key_instance)
            },
            #[cfg(all(feature = "cfb", feature = "aes"))]
            SymBlockCipherModeDecryptionInstanceState::CfbAes($block_cipher_key_instance) => {
                $m!($($($args),*,)? Cfb, Aes, $block_cipher_key_instance)
            },
            #[cfg(all(feature = "ecb", feature = "aes"))]
            SymBlockCipherModeDecryptionInstanceState::EcbAes($block_cipher_key_instance) => {
                $m!($($($args),*,)? Ecb, Aes, $block_cipher_key_instance)
            },
        }
    };
}

/// Map a pair of (symbolic mode, symbolic block cipher) to a variant of
/// SymBlockCipherModeDecryptionInstanceState. The symbolic block cipher must be
/// 'Aes', because nothing else is supported by BoringSSL.
macro_rules! mode_and_block_cipher_to_block_cipher_mode_decryption_instance_variant {
    (Ctr, Aes) => {
        SymBlockCipherModeDecryptionInstanceState::CtrAes
    };
    (Ofb, Aes) => {
        SymBlockCipherModeDecryptionInstanceState::OfbAes
    };
    (Cbc, Aes) => {
        SymBlockCipherModeDecryptionInstanceState::CbcAes
    };
    (Cfb, Aes) => {
        SymBlockCipherModeDecryptionInstanceState::CfbAes
    };
    (Ecb, Aes) => {
        SymBlockCipherModeDecryptionInstanceState::EcbAes
    };
}

macro_rules! mode_to_aes_dec_impl {
    (Ctr) => {
        BsslCtrAesDecryptor
    };
    (Ofb) => {
        BsslOfbAesDecryptor
    };
    (Cbc) => {
        BsslCbcAesDecryptor
    };
    (Cfb) => {
        BsslCfbAesDecryptor
    };
    (Ecb) => {
        BsslEcbAesDecryptor
    };
}

// Instantiate a block cipher mode implementation wrapping a block cipher
// key instance. Used from SymBlockCipherModeDecryptionInstanceState::decrypt()
// and SymBlockCipherModeDecryptionInstanceState::decrypt_in_place().
macro_rules! gen_mode_decryptor_impl_new_instance_snippet {
    (Ecb,
     Aes,
     $block_cipher_key_instance:ident,
     $iv:ident,
     $iv_out_opt:ident,
    ) => {{
        if $iv.len() != 0 {
            return Err(CryptoError::InvalidIV);
        } else if !$iv_out_opt.as_ref().map(|iv_out| iv_out.is_empty()).unwrap_or(true) {
            return Err(CryptoError::Internal);
        }

        <mode_to_aes_dec_impl!(Ecb)>::new($block_cipher_key_instance)
    }};
    ($mode_id:ident,
     Aes,
     $block_cipher_key_instance:ident,
     $iv:ident,
     $iv_out_opt:ident,
    ) => {{
        let expected_iv_len = AES_BLOCK_SIZE;
        if $iv.len() != expected_iv_len {
            return Err(CryptoError::InvalidIV);
        } else if $iv_out_opt
            .as_ref()
            .map(|iv_out| iv_out.len() != expected_iv_len)
            .unwrap_or(false)
        {
            return Err(CryptoError::Internal);
        }

        <mode_to_aes_dec_impl!($mode_id)>::new($block_cipher_key_instance, $iv)
    }};
}

impl SymBlockCipherModeDecryptionInstanceState {
    fn new(mode: tpm2_interface::TpmiAlgCipherMode, alg: &SymBlockCipherAlg, key: &[u8]) -> Result<Self, CryptoError> {
        macro_rules! gen_instantiate {
            (Aes, $aes_key_size_value:expr, $mode_id:ident) => {
                mode_and_block_cipher_to_block_cipher_mode_decryption_instance_variant!($mode_id, Aes)(
                    <dec_mode_to_bssl_aes_key_impl!($mode_id)>::new(key, $aes_key_size_value)?,
                )
            };
        }

        match alg {
            #[cfg(feature = "aes")]
            SymBlockCipherAlg::Aes(aes_key_size) => Ok(gen_match_on_tpmi_alg_cipher_mode!(
                mode,
                gen_instantiate,
                Aes,
                (*aes_key_size)
            )),
            #[cfg(feature = "camellia")]
            SymBlockCipherAlg::Camellia(_) => {
                compile_error!("Camellia cipher not supported with BoringSSL backend");
            }
            #[cfg(feature = "sm4")]
            SymBlockCipherAlg::Sm4(_) => {
                compile_error!("SM4 cipher not supported with BoringSSL backend");
            }
        }
    }

    fn try_clone(&self) -> Result<Self, CryptoError> {
        macro_rules! gen_try_clone {
            ($mode_id:ident, $block_cipher_alg_id:ident, $block_cipher_key_instance:ident) => {
                mode_and_block_cipher_to_block_cipher_mode_decryption_instance_variant!($mode_id, $block_cipher_alg_id)(
                    $block_cipher_key_instance.try_clone()?,
                )
            };
        }

        Ok(gen_match_on_block_cipher_mode_decryption_instance!(
            self,
            gen_try_clone,
            block_cipher_key_instance
        ))
    }

    fn block_cipher_block_len(&self) -> usize {
        macro_rules! gen_block_cipher_block_len {
            ($_mode_id:ident, $block_cipher_alg_id:ident, $_block_cipher_key_instance:ident) => {
                block_cipher_to_block_len!($block_cipher_alg_id)
            };
        }
        gen_match_on_block_cipher_mode_decryption_instance!(
            self,
            gen_block_cipher_block_len,
            _block_cipher_key_instance
        )
    }

    fn iv_len(&self) -> usize {
        macro_rules! gen_iv_len_for_mode_and_block_cipher {
            ($mode_id:ident,
              $block_alg_id:ident,
              $_block_cipher_key_instance:ident) => {
                mode_and_block_cipher_to_iv_len!($mode_id, $block_alg_id)
            };
        }
        gen_match_on_block_cipher_mode_decryption_instance!(
            self,
            gen_iv_len_for_mode_and_block_cipher,
            _block_cipher_instance
        )
    }

    #[inline(never)]
    fn decrypt<'a, 'b>(
        &self,
        iv: &[u8],
        dst: &mut dyn CryptoWalkableIoSlicesMutIter<'a>,
        src: &mut dyn CryptoWalkableIoSlicesIter<'b>,
        iv_out: Option<&mut [u8]>,
    ) -> Result<(), CryptoError> {
        gen_match_on_block_cipher_mode_decryption_instance!(
            self,
            sym_block_cipher_mode_instance_gen_transform,
            block_cipher_key_instance,
            gen_mode_decryptor_impl_new_instance_snippet,
            gen_mode_transform_grab_iv_snippet,
            dst,
            src,
            iv,
            iv_out
        );

        Ok(())
    }

    #[inline(never)]
    fn decrypt_in_place<'a, DI: CryptoPeekableIoSlicesMutIter<'a>>(
        &self,
        iv: &[u8],
        mut dst: DI,
        iv_out: Option<&mut [u8]>,
    ) -> Result<(), CryptoError> {
        gen_match_on_block_cipher_mode_decryption_instance!(
            self,
            sym_block_cipher_mode_instance_gen_transform_in_place,
            block_cipher_instance,
            gen_mode_decryptor_impl_new_instance_snippet,
            gen_mode_transform_grab_iv_snippet,
            dst,
            iv,
            iv_out
        );

        Ok(())
    }
}

impl convert::From<&SymBlockCipherModeDecryptionInstanceState> for SymBlockCipherAlg {
    fn from(value: &SymBlockCipherModeDecryptionInstanceState) -> Self {
        macro_rules! gen_block_cipher_to_block_cipher_alg {
            ($_mode_id:ident,
             Aes,
             $block_cipher_key_instance:ident) => {
                SymBlockCipherAlg::Aes($block_cipher_key_instance.get_aes_key_size())
            };
        }
        gen_match_on_block_cipher_mode_decryption_instance!(
            value,
            gen_block_cipher_to_block_cipher_alg,
            block_cipher_key_instance
        )
    }
}
