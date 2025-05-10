// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Pure Rust, RustCrypto based backend for symmetric block ciphers.

// Lifetimes are not obvious at first sight here, make the explicit.
#![allow(clippy::needless_lifetimes)]

extern crate alloc;
use alloc::boxed::Box;

#[cfg(feature = "aes")]
use crate::symcipher::SymBlockCipherAesKeySize;
#[cfg(feature = "camellia")]
use crate::symcipher::SymBlockCipherCamelliaKeySize;
#[cfg(feature = "sm4")]
use crate::symcipher::SymBlockCipherSm4KeySize;
use crate::symcipher::{transform_next_blocks, transform_next_blocks_in_place, SymBlockCipherAlg};
use crate::{
    io_slices::{CryptoPeekableIoSlicesMutIter, CryptoWalkableIoSlicesIter, CryptoWalkableIoSlicesMutIter},
    CryptoError,
};
use crate::{
    tpm2_interface,
    utils_common::{alloc::box_try_new_with, zeroize},
};
use core::{convert, ops::Deref as _};

use cipher::{BlockDecryptMut as _, BlockEncryptMut as _, IvState as _};
#[allow(unused_imports)]
use crypto_common::{
    self, BlockSizeUser as _, InnerInit as _, InnerIvInit as _, IvSizeUser as _, KeyInit as _, KeySizeUser as _,
};
use generic_array::typenum::Unsigned as _;

#[cfg(feature = "ctr")]
mod ctr_impl;

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

/// Map a pair of (symbolic block cipher alg, key size) to a variant of
/// SymBlockCipherAlg.
macro_rules! block_cipher_to_sym_block_cipher_alg_variant {
    (Aes, 128) => {
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128)
    };
    (Aes, 192) => {
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192)
    };
    (Aes, 256) => {
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256)
    };
    (Camellia, 128) => {
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128)
    };
    (Camellia, 192) => {
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192)
    };
    (Camellia, 256) => {
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256)
    };
    (Sm4, 128) => {
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128)
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

// Convert a symbolic mode to the corresponding TpmiAlgCipherMode variant.
macro_rules! mode_to_tpmi_alg_cipher_mode {
    (Ctr) => {
        tpm2_interface::TpmiAlgCipherMode::Ctr
    };
    (Ofb) => {
        tpm2_interface::TpmiAlgCipherMode::Ofb
    };
    (Cbc) => {
        tpm2_interface::TpmiAlgCipherMode::Cbc
    };
    (Cfb) => {
        tpm2_interface::TpmiAlgCipherMode::Cfb
    };
    (Ecb) => {
        tpm2_interface::TpmiAlgCipherMode::Ecb
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
     $gen_mode_block_transform_cb_snippet:ident,
     $gen_mode_transform_grab_iv_snippet:ident,
     $dst_io_slices:ident,
     $src_io_slices:ident,
     $iv:ident, $iv_out_opt:ident,
     $mode_id:ident, $block_alg_id:ident, $key_size:tt, $block_cipher_instance:ident) => {{
        const MODE_SUPPORTS_PARTIAL_LAST_BLOCK: bool = mode_supports_partial_last_block!($mode_id);
        const BLOCK_LEN: usize = block_cipher_to_block_len!($block_alg_id, $key_size);
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
            $key_size,
            $block_cipher_instance,
            $iv,
            $iv_out_opt,
        );

        let mut scratch_block_buf = zeroize::Zeroizing::from([0u8; BLOCK_LEN]);

        loop {
            if !transform_next_blocks::<MODE_SUPPORTS_PARTIAL_LAST_BLOCK, _>(
                $dst_io_slices,
                $src_io_slices,
                $gen_mode_block_transform_cb_snippet!(mode_transform_impl_instance),
                BLOCK_LEN,
                scratch_block_buf.as_mut_slice(),
            )? {
                break;
            }
        }

        $gen_mode_transform_grab_iv_snippet!(
            $mode_id,
            $block_alg_id,
            $key_size,
            mode_transform_impl_instance,
            $iv_out_opt
        );
    }};
}

// Used internally from multiple functions of
// SymBlockCipherModeEncryptionInstanceState
// and SymBlockCipherModeDecryptionInstanceState.
macro_rules! sym_block_cipher_mode_instance_gen_transform_in_place {
    ($gen_mode_transform_new_impl_instance_snippet:ident,
     $gen_mode_block_transform_cb_snippet:ident,
     $gen_mode_transform_grab_iv_snippet:ident,
     $dst_io_slices:ident,
     $iv:ident, $iv_out_opt:ident,
     $mode_id:ident, $block_alg_id:ident, $key_size:tt, $block_cipher_instance:ident) => {{
        const MODE_SUPPORTS_PARTIAL_LAST_BLOCK: bool = mode_supports_partial_last_block!($mode_id);
        const BLOCK_LEN: usize = block_cipher_to_block_len!($block_alg_id, $key_size);
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
            $key_size,
            $block_cipher_instance,
            $iv,
            $iv_out_opt,
        );

        let mut scratch_block_buf = zeroize::Zeroizing::from([0u8; BLOCK_LEN]);

        loop {
            if !transform_next_blocks_in_place::<MODE_SUPPORTS_PARTIAL_LAST_BLOCK, _, _>(
                &mut $dst_io_slices,
                $gen_mode_block_transform_cb_snippet!(mode_transform_impl_instance),
                BLOCK_LEN,
                scratch_block_buf.as_mut_slice(),
            )? {
                break;
            }
        }

        $gen_mode_transform_grab_iv_snippet!(
            $mode_id,
            $block_alg_id,
            $key_size,
            mode_transform_impl_instance,
            $iv_out_opt
        );
    }};
}

pub struct SymBlockCipherModeEncryptionInstance {
    state: Box<SymBlockCipherModeEncryptionInstanceState>,
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
            state: box_try_new_with(
                || -> Result<SymBlockCipherModeEncryptionInstanceState, convert::Infallible> {
                    Ok(self.state.deref().clone())
                },
            )?,
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

// All supported block cipher implementations possibly wrapped implement
// ZeroizeOnDrop.
#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for SymBlockCipherModeEncryptionInstance {}

/// Map a triplet of (mode, block cipher, key length) to a block cipher
/// implementation suitable for encryption with that mode.
macro_rules! enc_mode_and_block_cipher_to_block_cipher_impl {
    (Ctr, Aes, 128) => {
        aes::Aes128Enc
    };
    (Ctr, Aes, 192) => {
        aes::Aes192Enc
    };
    (Ctr, Aes, 256) => {
        aes::Aes256Enc
    };
    (Ctr, Camellia, 128) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia128
    };
    (Ctr, Camellia, 192) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia192
    };
    (Ctr, Camellia, 256) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia256
    };
    (Ctr, Sm4, 128) => {
        // No differentiation between encryptor/decryptor made in sm4 crate.
        sm4::Sm4
    };

    (Ofb, Aes, 128) => {
        aes::Aes128Enc
    };
    (Ofb, Aes, 192) => {
        aes::Aes192Enc
    };
    (Ofb, Aes, 256) => {
        aes::Aes256Enc
    };
    (Ofb, Camellia, 128) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia128
    };
    (Ofb, Camellia, 192) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia192
    };
    (Ofb, Camellia, 256) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia256
    };
    (Ofb, Sm4, 128) => {
        // No differentiation between encryptor/decryptor made in sm4 crate.
        sm4::Sm4
    };

    (Cbc, Aes, 128) => {
        aes::Aes128Enc
    };
    (Cbc, Aes, 192) => {
        aes::Aes192Enc
    };
    (Cbc, Aes, 256) => {
        aes::Aes256Enc
    };
    (Cbc, Camellia, 128) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia128
    };
    (Cbc, Camellia, 192) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia192
    };
    (Cbc, Camellia, 256) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia256
    };
    (Cbc, Sm4, 128) => {
        // No differentiation between encryptor/decryptor made in sm4 crate.
        sm4::Sm4
    };

    (Cfb, Aes, 128) => {
        // cfb_mode needs a Decryptor to impl IvState.
        aes::Aes128
    };
    (Cfb, Aes, 192) => {
        // cfb_mode needs a Decryptor to impl IvState.
        aes::Aes192
    };
    (Cfb, Aes, 256) => {
        // cfb_mode needs a Decryptor to impl IvState.
        aes::Aes256
    };
    (Cfb, Camellia, 128) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia128
    };
    (Cfb, Camellia, 192) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia192
    };
    (Cfb, Camellia, 256) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia256
    };
    (Cfb, Sm4, 128) => {
        // No differentiation between encryptor/decryptor made in sm4 crate.
        sm4::Sm4
    };

    (Ecb, Aes, 128) => {
        aes::Aes128Enc
    };
    (Ecb, Aes, 192) => {
        aes::Aes192Enc
    };
    (Ecb, Aes, 256) => {
        aes::Aes256Enc
    };
    (Ecb, Camellia, 128) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia128
    };
    (Ecb, Camellia, 192) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia192
    };
    (Ecb, Camellia, 256) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia256
    };
    (Ecb, Sm4, 128) => {
        // No differentiation between encryptor/decryptor made in sm4 crate.
        sm4::Sm4
    };
}

#[derive(Clone)]
enum SymBlockCipherModeEncryptionInstanceState {
    #[cfg(all(feature = "ctr", feature = "aes"))]
    CtrAes128(enc_mode_and_block_cipher_to_block_cipher_impl!(Ctr, Aes, 128)),
    #[cfg(all(feature = "ctr", feature = "aes"))]
    CtrAes192(enc_mode_and_block_cipher_to_block_cipher_impl!(Ctr, Aes, 192)),
    #[cfg(all(feature = "ctr", feature = "aes"))]
    CtrAes256(enc_mode_and_block_cipher_to_block_cipher_impl!(Ctr, Aes, 256)),
    #[cfg(all(feature = "ctr", feature = "camellia"))]
    CtrCamellia128(enc_mode_and_block_cipher_to_block_cipher_impl!(Ctr, Camellia, 128)),
    #[cfg(all(feature = "ctr", feature = "camellia"))]
    CtrCamellia192(enc_mode_and_block_cipher_to_block_cipher_impl!(Ctr, Camellia, 192)),
    #[cfg(all(feature = "ctr", feature = "camellia"))]
    CtrCamellia256(enc_mode_and_block_cipher_to_block_cipher_impl!(Ctr, Camellia, 256)),
    #[cfg(all(feature = "ctr", feature = "sm4"))]
    CtrSm4_128(enc_mode_and_block_cipher_to_block_cipher_impl!(Ctr, Sm4, 128)),

    #[cfg(all(feature = "ofb", feature = "aes"))]
    OfbAes128(enc_mode_and_block_cipher_to_block_cipher_impl!(Ofb, Aes, 128)),
    #[cfg(all(feature = "ofb", feature = "aes"))]
    OfbAes192(enc_mode_and_block_cipher_to_block_cipher_impl!(Ofb, Aes, 192)),
    #[cfg(all(feature = "ofb", feature = "aes"))]
    OfbAes256(enc_mode_and_block_cipher_to_block_cipher_impl!(Ofb, Aes, 256)),
    #[cfg(all(feature = "ofb", feature = "camellia"))]
    OfbCamellia128(enc_mode_and_block_cipher_to_block_cipher_impl!(Ofb, Camellia, 128)),
    #[cfg(all(feature = "ofb", feature = "camellia"))]
    OfbCamellia192(enc_mode_and_block_cipher_to_block_cipher_impl!(Ofb, Camellia, 192)),
    #[cfg(all(feature = "ofb", feature = "camellia"))]
    OfbCamellia256(enc_mode_and_block_cipher_to_block_cipher_impl!(Ofb, Camellia, 256)),
    #[cfg(all(feature = "ofb", feature = "sm4"))]
    OfbSm4_128(enc_mode_and_block_cipher_to_block_cipher_impl!(Ofb, Sm4, 128)),

    #[cfg(all(feature = "cbc", feature = "aes"))]
    CbcAes128(enc_mode_and_block_cipher_to_block_cipher_impl!(Cbc, Aes, 128)),
    #[cfg(all(feature = "cbc", feature = "aes"))]
    CbcAes192(enc_mode_and_block_cipher_to_block_cipher_impl!(Cbc, Aes, 192)),
    #[cfg(all(feature = "cbc", feature = "aes"))]
    CbcAes256(enc_mode_and_block_cipher_to_block_cipher_impl!(Cbc, Aes, 256)),
    #[cfg(all(feature = "cbc", feature = "camellia"))]
    CbcCamellia128(enc_mode_and_block_cipher_to_block_cipher_impl!(Cbc, Camellia, 128)),
    #[cfg(all(feature = "cbc", feature = "camellia"))]
    CbcCamellia192(enc_mode_and_block_cipher_to_block_cipher_impl!(Cbc, Camellia, 192)),
    #[cfg(all(feature = "cbc", feature = "camellia"))]
    CbcCamellia256(enc_mode_and_block_cipher_to_block_cipher_impl!(Cbc, Camellia, 256)),
    #[cfg(all(feature = "cbc", feature = "sm4"))]
    CbcSm4_128(enc_mode_and_block_cipher_to_block_cipher_impl!(Cbc, Sm4, 128)),

    #[cfg(all(feature = "cfb", feature = "aes"))]
    CfbAes128(enc_mode_and_block_cipher_to_block_cipher_impl!(Cfb, Aes, 128)),
    #[cfg(all(feature = "cfb", feature = "aes"))]
    CfbAes192(enc_mode_and_block_cipher_to_block_cipher_impl!(Cfb, Aes, 192)),
    #[cfg(all(feature = "cfb", feature = "aes"))]
    CfbAes256(enc_mode_and_block_cipher_to_block_cipher_impl!(Cfb, Aes, 256)),
    #[cfg(all(feature = "cfb", feature = "camellia"))]
    CfbCamellia128(enc_mode_and_block_cipher_to_block_cipher_impl!(Cfb, Camellia, 128)),
    #[cfg(all(feature = "cfb", feature = "camellia"))]
    CfbCamellia192(enc_mode_and_block_cipher_to_block_cipher_impl!(Cfb, Camellia, 192)),
    #[cfg(all(feature = "cfb", feature = "camellia"))]
    CfbCamellia256(enc_mode_and_block_cipher_to_block_cipher_impl!(Cfb, Camellia, 256)),
    #[cfg(all(feature = "cfb", feature = "sm4"))]
    CfbSm4_128(enc_mode_and_block_cipher_to_block_cipher_impl!(Cfb, Sm4, 128)),

    #[cfg(all(feature = "ecb", feature = "aes"))]
    EcbAes128(enc_mode_and_block_cipher_to_block_cipher_impl!(Ecb, Aes, 128)),
    #[cfg(all(feature = "ecb", feature = "aes"))]
    EcbAes192(enc_mode_and_block_cipher_to_block_cipher_impl!(Ecb, Aes, 192)),
    #[cfg(all(feature = "ecb", feature = "aes"))]
    EcbAes256(enc_mode_and_block_cipher_to_block_cipher_impl!(Ecb, Aes, 256)),
    #[cfg(all(feature = "ecb", feature = "camellia"))]
    EcbCamellia128(enc_mode_and_block_cipher_to_block_cipher_impl!(Ecb, Camellia, 128)),
    #[cfg(all(feature = "ecb", feature = "camellia"))]
    EcbCamellia192(enc_mode_and_block_cipher_to_block_cipher_impl!(Ecb, Camellia, 192)),
    #[cfg(all(feature = "ecb", feature = "camellia"))]
    EcbCamellia256(enc_mode_and_block_cipher_to_block_cipher_impl!(Ecb, Camellia, 256)),
    #[cfg(all(feature = "ecb", feature = "sm4"))]
    EcbSm4_128(enc_mode_and_block_cipher_to_block_cipher_impl!(Ecb, Sm4, 128)),
}

/// Generate a `match {}` on SymBlockCipherModeEncryptionInstanceState and
/// invoke a macro in the body of each match arm.
///
/// The supplied macro `m` gets invoked with (`$args`, symbolic mode, symbolic
/// block cipher, key size, `$block_cipher_instance`) for each arm, where
/// identifier `$block_cipher_instance` is bound to the variant's respective
/// block cipher implementation instance member.
macro_rules! gen_match_on_block_cipher_mode_encryption_instance {
    ($block_cipher_mode_instance_value:expr, $m:ident, $block_cipher_instance:ident $(, $($args:tt),*)?) => {
        match $block_cipher_mode_instance_value {
            #[cfg(all(feature = "ctr", feature = "aes"))]
            SymBlockCipherModeEncryptionInstanceState::CtrAes128($block_cipher_instance) => {
                $m!($($($args),*,)? Ctr, Aes, 128, $block_cipher_instance)
            },
            #[cfg(all(feature = "ctr", feature = "aes"))]
            SymBlockCipherModeEncryptionInstanceState::CtrAes192($block_cipher_instance) => {
                $m!($($($args),*,)? Ctr, Aes, 192, $block_cipher_instance)
            },
            #[cfg(all(feature = "ctr", feature = "aes"))]
            SymBlockCipherModeEncryptionInstanceState::CtrAes256($block_cipher_instance) => {
                $m!($($($args),*,)? Ctr, Aes, 256, $block_cipher_instance)
            },
            #[cfg(all(feature = "ctr", feature = "camellia"))]
            SymBlockCipherModeEncryptionInstanceState::CtrCamellia128($block_cipher_instance) => {
                $m!($($($args),*,)? Ctr, Camellia, 128, $block_cipher_instance)
            },
            #[cfg(all(feature = "ctr", feature = "camellia"))]
            SymBlockCipherModeEncryptionInstanceState::CtrCamellia192($block_cipher_instance) => {
                $m!($($($args),*,)? Ctr, Camellia, 192, $block_cipher_instance)
            },
            #[cfg(all(feature = "ctr", feature = "camellia"))]
            SymBlockCipherModeEncryptionInstanceState::CtrCamellia256($block_cipher_instance) => {
                $m!($($($args),*,)? Ctr, Camellia, 256, $block_cipher_instance)
            },
            #[cfg(all(feature = "ctr", feature = "sm4"))]
            SymBlockCipherModeEncryptionInstanceState::CtrSm4_128($block_cipher_instance) => {
                $m!($($($args),*,)? Ctr, Sm4, 128, $block_cipher_instance)
            },

            #[cfg(all(feature = "ofb", feature = "aes"))]
            SymBlockCipherModeEncryptionInstanceState::OfbAes128($block_cipher_instance) => {
                $m!($($($args),*,)? Ofb, Aes, 128, $block_cipher_instance)
            },
            #[cfg(all(feature = "ofb", feature = "aes"))]
            SymBlockCipherModeEncryptionInstanceState::OfbAes192($block_cipher_instance) => {
                $m!($($($args),*,)? Ofb, Aes, 192, $block_cipher_instance)
            },
            #[cfg(all(feature = "ofb", feature = "aes"))]
            SymBlockCipherModeEncryptionInstanceState::OfbAes256($block_cipher_instance) => {
                $m!($($($args),*,)? Ofb, Aes, 256, $block_cipher_instance)
            },
            #[cfg(all(feature = "ofb", feature = "camellia"))]
            SymBlockCipherModeEncryptionInstanceState::OfbCamellia128($block_cipher_instance) => {
                $m!($($($args),*,)? Ofb, Camellia, 128, $block_cipher_instance)
            },
            #[cfg(all(feature = "ofb", feature = "camellia"))]
            SymBlockCipherModeEncryptionInstanceState::OfbCamellia192($block_cipher_instance) => {
                $m!($($($args),*,)? Ofb, Camellia, 192, $block_cipher_instance)
            },
            #[cfg(all(feature = "ofb", feature = "camellia"))]
            SymBlockCipherModeEncryptionInstanceState::OfbCamellia256($block_cipher_instance) => {
                $m!($($($args),*,)? Ofb, Camellia, 256, $block_cipher_instance)
            },
            #[cfg(all(feature = "ofb", feature = "sm4"))]
            SymBlockCipherModeEncryptionInstanceState::OfbSm4_128($block_cipher_instance) => {
                $m!($($($args),*,)? Ofb, Sm4, 128, $block_cipher_instance)
            },

            #[cfg(all(feature = "cbc", feature = "aes"))]
            SymBlockCipherModeEncryptionInstanceState::CbcAes128($block_cipher_instance) => {
                $m!($($($args),*,)? Cbc, Aes, 128, $block_cipher_instance)
            },
            #[cfg(all(feature = "cbc", feature = "aes"))]
            SymBlockCipherModeEncryptionInstanceState::CbcAes192($block_cipher_instance) => {
                $m!($($($args),*,)? Cbc, Aes, 192, $block_cipher_instance)
            },
            #[cfg(all(feature = "cbc", feature = "aes"))]
            SymBlockCipherModeEncryptionInstanceState::CbcAes256($block_cipher_instance) => {
                $m!($($($args),*,)? Cbc, Aes, 256, $block_cipher_instance)
            },
            #[cfg(all(feature = "cbc", feature = "camellia"))]
            SymBlockCipherModeEncryptionInstanceState::CbcCamellia128($block_cipher_instance) => {
                $m!($($($args),*,)? Cbc, Camellia, 128, $block_cipher_instance)
            },
            #[cfg(all(feature = "cbc", feature = "camellia"))]
            SymBlockCipherModeEncryptionInstanceState::CbcCamellia192($block_cipher_instance) => {
                $m!($($($args),*,)? Cbc, Camellia, 192, $block_cipher_instance)
            },
            #[cfg(all(feature = "cbc", feature = "camellia"))]
            SymBlockCipherModeEncryptionInstanceState::CbcCamellia256($block_cipher_instance) => {
                $m!($($($args),*,)? Cbc, Camellia, 256, $block_cipher_instance)
            },
            #[cfg(all(feature = "cbc", feature = "sm4"))]
            SymBlockCipherModeEncryptionInstanceState::CbcSm4_128($block_cipher_instance) => {
                $m!($($($args),*,)? Cbc, Sm4, 128, $block_cipher_instance)
            },

            #[cfg(all(feature = "cfb", feature = "aes"))]
            SymBlockCipherModeEncryptionInstanceState::CfbAes128($block_cipher_instance) => {
                $m!($($($args),*,)? Cfb, Aes, 128, $block_cipher_instance)
            },
            #[cfg(all(feature = "cfb", feature = "aes"))]
            SymBlockCipherModeEncryptionInstanceState::CfbAes192($block_cipher_instance) => {
                $m!($($($args),*,)? Cfb, Aes, 192, $block_cipher_instance)
            },
            #[cfg(all(feature = "cfb", feature = "aes"))]
            SymBlockCipherModeEncryptionInstanceState::CfbAes256($block_cipher_instance) => {
                $m!($($($args),*,)? Cfb, Aes, 256, $block_cipher_instance)
            },
            #[cfg(all(feature = "cfb", feature = "camellia"))]
            SymBlockCipherModeEncryptionInstanceState::CfbCamellia128($block_cipher_instance) => {
                $m!($($($args),*,)? Cfb, Camellia, 128, $block_cipher_instance)
            },
            #[cfg(all(feature = "cfb", feature = "camellia"))]
            SymBlockCipherModeEncryptionInstanceState::CfbCamellia192($block_cipher_instance) => {
                $m!($($($args),*,)? Cfb, Camellia, 192, $block_cipher_instance)
            },
            #[cfg(all(feature = "cfb", feature = "camellia"))]
            SymBlockCipherModeEncryptionInstanceState::CfbCamellia256($block_cipher_instance) => {
                $m!($($($args),*,)? Cfb, Camellia, 256, $block_cipher_instance)
            },
            #[cfg(all(feature = "cfb", feature = "sm4"))]
            SymBlockCipherModeEncryptionInstanceState::CfbSm4_128($block_cipher_instance) => {
                $m!($($($args),*,)? Cfb, Sm4, 128, $block_cipher_instance)
            },

            #[cfg(all(feature = "ecb", feature = "aes"))]
            SymBlockCipherModeEncryptionInstanceState::EcbAes128($block_cipher_instance) => {
                $m!($($($args),*,)? Ecb, Aes, 128, $block_cipher_instance)
            },
            #[cfg(all(feature = "ecb", feature = "aes"))]
            SymBlockCipherModeEncryptionInstanceState::EcbAes192($block_cipher_instance) => {
                $m!($($($args),*,)? Ecb, Aes, 192, $block_cipher_instance)
            },
            #[cfg(all(feature = "ecb", feature = "aes"))]
            SymBlockCipherModeEncryptionInstanceState::EcbAes256($block_cipher_instance) => {
                $m!($($($args),*,)? Ecb, Aes, 256, $block_cipher_instance)
            },
            #[cfg(all(feature = "ecb", feature = "camellia"))]
            SymBlockCipherModeEncryptionInstanceState::EcbCamellia128($block_cipher_instance) => {
                $m!($($($args),*,)? Ecb, Camellia, 128, $block_cipher_instance)
            },
            #[cfg(all(feature = "ecb", feature = "camellia"))]
            SymBlockCipherModeEncryptionInstanceState::EcbCamellia192($block_cipher_instance) => {
                $m!($($($args),*,)? Ecb, Camellia, 192, $block_cipher_instance)
            },
            #[cfg(all(feature = "ecb", feature = "camellia"))]
            SymBlockCipherModeEncryptionInstanceState::EcbCamellia256($block_cipher_instance) => {
                $m!($($($args),*,)? Ecb, Camellia, 256, $block_cipher_instance)
            },
            #[cfg(all(feature = "ecb", feature = "sm4"))]
            SymBlockCipherModeEncryptionInstanceState::EcbSm4_128($block_cipher_instance) => {
                $m!($($($args),*,)? Ecb, Sm4, 128, $block_cipher_instance)
            },
        }
    };
}

/// Map a triplet of (symbolic mode, symbolic block cipher, key size) to a
/// variant of SymBlockCipherModeEncryptionInstanceState.
macro_rules! mode_and_block_cipher_to_block_cipher_mode_encryption_instance_variant {
    (Ctr, Aes, 128) => {
        SymBlockCipherModeEncryptionInstanceState::CtrAes128
    };
    (Ctr, Aes, 192) => {
        SymBlockCipherModeEncryptionInstanceState::CtrAes192
    };
    (Ctr, Aes, 256) => {
        SymBlockCipherModeEncryptionInstanceState::CtrAes256
    };
    (Ctr, Camellia, 128) => {
        SymBlockCipherModeEncryptionInstanceState::CtrCamellia128
    };
    (Ctr, Camellia, 192) => {
        SymBlockCipherModeEncryptionInstanceState::CtrCamellia192
    };
    (Ctr, Camellia, 256) => {
        SymBlockCipherModeEncryptionInstanceState::CtrCamellia256
    };
    (Ctr, Sm4, 128) => {
        SymBlockCipherModeEncryptionInstanceState::CtrSm4_128
    };

    (Ofb, Aes, 128) => {
        SymBlockCipherModeEncryptionInstanceState::OfbAes128
    };
    (Ofb, Aes, 192) => {
        SymBlockCipherModeEncryptionInstanceState::OfbAes192
    };
    (Ofb, Aes, 256) => {
        SymBlockCipherModeEncryptionInstanceState::OfbAes256
    };
    (Ofb, Camellia, 128) => {
        SymBlockCipherModeEncryptionInstanceState::OfbCamellia128
    };
    (Ofb, Camellia, 192) => {
        SymBlockCipherModeEncryptionInstanceState::OfbCamellia192
    };
    (Ofb, Camellia, 256) => {
        SymBlockCipherModeEncryptionInstanceState::OfbCamellia256
    };
    (Ofb, Sm4, 128) => {
        SymBlockCipherModeEncryptionInstanceState::OfbSm4_128
    };

    (Cbc, Aes, 128) => {
        SymBlockCipherModeEncryptionInstanceState::CbcAes128
    };
    (Cbc, Aes, 192) => {
        SymBlockCipherModeEncryptionInstanceState::CbcAes192
    };
    (Cbc, Aes, 256) => {
        SymBlockCipherModeEncryptionInstanceState::CbcAes256
    };
    (Cbc, Camellia, 128) => {
        SymBlockCipherModeEncryptionInstanceState::CbcCamellia128
    };
    (Cbc, Camellia, 192) => {
        SymBlockCipherModeEncryptionInstanceState::CbcCamellia192
    };
    (Cbc, Camellia, 256) => {
        SymBlockCipherModeEncryptionInstanceState::CbcCamellia256
    };
    (Cbc, Sm4, 128) => {
        SymBlockCipherModeEncryptionInstanceState::CbcSm4_128
    };

    (Cfb, Aes, 128) => {
        SymBlockCipherModeEncryptionInstanceState::CfbAes128
    };
    (Cfb, Aes, 192) => {
        SymBlockCipherModeEncryptionInstanceState::CfbAes192
    };
    (Cfb, Aes, 256) => {
        SymBlockCipherModeEncryptionInstanceState::CfbAes256
    };
    (Cfb, Camellia, 128) => {
        SymBlockCipherModeEncryptionInstanceState::CfbCamellia128
    };
    (Cfb, Camellia, 192) => {
        SymBlockCipherModeEncryptionInstanceState::CfbCamellia192
    };
    (Cfb, Camellia, 256) => {
        SymBlockCipherModeEncryptionInstanceState::CfbCamellia256
    };
    (Cfb, Sm4, 128) => {
        SymBlockCipherModeEncryptionInstanceState::CfbSm4_128
    };

    (Ecb, Aes, 128) => {
        SymBlockCipherModeEncryptionInstanceState::EcbAes128
    };
    (Ecb, Aes, 192) => {
        SymBlockCipherModeEncryptionInstanceState::EcbAes192
    };
    (Ecb, Aes, 256) => {
        SymBlockCipherModeEncryptionInstanceState::EcbAes256
    };
    (Ecb, Camellia, 128) => {
        SymBlockCipherModeEncryptionInstanceState::EcbCamellia128
    };
    (Ecb, Camellia, 192) => {
        SymBlockCipherModeEncryptionInstanceState::EcbCamellia192
    };
    (Ecb, Camellia, 256) => {
        SymBlockCipherModeEncryptionInstanceState::EcbCamellia256
    };
    (Ecb, Sm4, 128) => {
        SymBlockCipherModeEncryptionInstanceState::EcbSm4_128
    };
}

macro_rules! mode_to_enc_impl {
    (Ctr, $block_cipher_impl:ty) => {
        ctr_impl::Encryptor::<&$block_cipher_impl>
    };
    (Ofb, $block_cipher_impl:ty) => {
        ofb::OfbCore::<&$block_cipher_impl>
    };
    (Cbc, $block_cipher_impl:ty) => {
        cbc::Encryptor::<&$block_cipher_impl>
    };
    (Cfb, $block_cipher_impl:ty) => {
        cfb_mode::Encryptor::<&$block_cipher_impl>
    };
    (Ecb, $block_cipher_impl:ty) => {
        ecb::Encryptor::<&$block_cipher_impl>
    };
}

// Instantiate a block cipher mode implementation wrapping a block cipher
// instance. Used from SymBlockCipherModeEncryptionInstanceState::encrypt() and
// SymBlockCipherModeEncryptionInstanceState::encrypt_in_place().
macro_rules! gen_mode_encryptor_impl_new_instance_snippet {
    (Ecb,
     $block_alg_id:ident,
     $key_size:tt,
     $block_cipher_instance:ident,
     $iv:ident,
     $iv_out_opt:ident,
    ) => {{
        if $iv.len() != 0 {
            return Err(CryptoError::InvalidIV);
        } else if !$iv_out_opt.as_ref().map(|iv_out| iv_out.is_empty()).unwrap_or(true) {
            return Err(CryptoError::Internal);
        }

        // Note that the block cipher instance is a reference, which implements
        // crypto_common's BlockEncrypt, hence BlockEncryptMut. This reduces the
        // mode instance's size on the stack significantly. Also, all (possibly
        // external) block cipher mode implementations impl ZeroizeOnDrop.
        <mode_to_enc_impl!(
            Ecb,
            enc_mode_and_block_cipher_to_block_cipher_impl!(Ecb, $block_alg_id, $key_size)
        )>::inner_init($block_cipher_instance)
    }};
    ($mode_id:ident,
     $block_alg_id:ident,
     $key_size:tt,
     $block_cipher_instance:ident,
     $iv:ident,
     $iv_out_opt:ident,
    ) => {{
        let expected_iv_len = mode_and_block_cipher_to_iv_len!($mode_id, $block_alg_id, $key_size);
        if $iv.len() != expected_iv_len {
            return Err(CryptoError::InvalidIV);
        } else if $iv_out_opt
            .as_ref()
            .map(|iv_out| iv_out.len() != expected_iv_len)
            .unwrap_or(false)
        {
            return Err(CryptoError::Internal);
        }

        let iv = crypto_common::Iv::<
            mode_to_enc_impl!(
                $mode_id,
                enc_mode_and_block_cipher_to_block_cipher_impl!($mode_id, $block_alg_id, $key_size)
            ),
        >::from_slice($iv);

        // Note that the block cipher instance is a reference, which implements
        // crypto_common's BlockEncrypt, hence BlockEncryptMut. This reduces the
        // mode instance's size on the stack significantly. Also, all (possibly
        // external) block cipher mode implementations impl ZeroizeOnDrop.
        <mode_to_enc_impl!(
            $mode_id,
            enc_mode_and_block_cipher_to_block_cipher_impl!($mode_id, $block_alg_id, $key_size)
        )>::inner_iv_init($block_cipher_instance, iv)
    }};
}

// Generate code snippet for obtaining the IV from for (external) mode
// implementations.
//
// Common to SymBlockCipherModeEncryptionInstanceState::encrypt()/
// ::encrypt_in_place() and
// SymBlockCipherModeDecryptionInstanceState::decrypt()/ ::decrypt_in_place().
macro_rules! gen_mode_transform_grab_iv_snippet {
    (Ecb, $_block_alg_id:ident, $_key_size:tt, $_mode_transform_impl_instance:ident, $iv_out_opt:ident) => {{
        debug_assert!($iv_out_opt.map(|iv_out| iv_out.is_empty()).unwrap_or(true));
    }};
    ($_mode_id:ident, $_block_alg_id:ident, $_key_size:tt, $mode_transform_impl_instance:ident, $iv_out_opt:ident) => {{
        if let Some(iv_out) = $iv_out_opt {
            iv_out.copy_from_slice($mode_transform_impl_instance.iv_state().deref());
        }
    }};
}

impl SymBlockCipherModeEncryptionInstanceState {
    fn new(
        mode: tpm2_interface::TpmiAlgCipherMode,
        alg: &SymBlockCipherAlg,
        key: &[u8],
    ) -> Result<Box<Self>, CryptoError> {
        macro_rules! gen_instantiate {
            ($mode_id:ident, $block_alg_id:ident, $key_size:tt) => {{
                // Don't use crypto_common's convenience KeyInit::from_slice() for instantiating
                // the cipher, but wrap the key explictly first to have all possible
                // error paths out of the way, thereby enabling a zero copy construction
                // right into the Box' memory.
                let expected_key_len = <enc_mode_and_block_cipher_to_block_cipher_impl!(
                    $mode_id,
                    $block_alg_id,
                    $key_size
                ) as crypto_common::KeySizeUser>::KeySize::to_usize();
                debug_assert_eq!(8 * expected_key_len, $key_size);
                if key.len() != expected_key_len {
                    return Err(CryptoError::KeySize);
                }

                let key = crypto_common::Key::<
                    enc_mode_and_block_cipher_to_block_cipher_impl!($mode_id, $block_alg_id, $key_size),
                >::from_slice(key);

                box_try_new_with(|| -> Result<Self, convert::Infallible> {
                    Ok(
                        mode_and_block_cipher_to_block_cipher_mode_encryption_instance_variant!(
                            $mode_id,
                            $block_alg_id,
                            $key_size
                        )(<enc_mode_and_block_cipher_to_block_cipher_impl!(
                            $mode_id,
                            $block_alg_id,
                            $key_size
                        )>::new(key)),
                    )
                })?
            }};
        }

        Ok(gen_match_on_tpmi_alg_cipher_mode_and_block_cipher_alg!(
            mode,
            alg,
            gen_instantiate
        ))
    }

    fn block_cipher_block_len(&self) -> usize {
        macro_rules! gen_block_cipher_block_len {
            ($_mode_id:ident, $block_cipher_alg_id:ident, $key_size:tt, $_block_cipher_instance:ident) => {
                block_cipher_to_block_len!($block_cipher_alg_id, $key_size)
            };
        }
        gen_match_on_block_cipher_mode_encryption_instance!(self, gen_block_cipher_block_len, _block_cipher_instance)
    }

    fn iv_len(&self) -> usize {
        macro_rules! gen_iv_len_for_mode_and_block_cipher {
            ($mode_id:ident,
              $block_alg_id:ident,
              $key_size:tt,
              $_block_cipher_instance:ident) => {
                mode_and_block_cipher_to_iv_len!($mode_id, $block_alg_id, $key_size)
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
        // Generate code snippet for the block transform callback passed to
        // transform_next_blocks() for (external) mode encryption
        // implementations implementing the cipher::BlockEncryptMut trait.
        macro_rules! gen_block_encrypt_trait_mode_block_encrypt_transform_cb_snippet {
            ($mode_transform_impl_instance:ident) => {
                |dst_blocks: &mut [u8], src_blocks: Option<&[u8]>| {
                    if let Some(src_blocks) = src_blocks {
                        $mode_transform_impl_instance.encrypt_block_b2b_mut(src_blocks.into(), dst_blocks.into());
                    } else {
                        $mode_transform_impl_instance.encrypt_block_mut(dst_blocks.into());
                    }
                }
            };
        }

        gen_match_on_block_cipher_mode_encryption_instance!(
            self,
            sym_block_cipher_mode_instance_gen_transform,
            block_cipher_instance,
            gen_mode_encryptor_impl_new_instance_snippet,
            gen_block_encrypt_trait_mode_block_encrypt_transform_cb_snippet,
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
        // Generate code snippet for the block transform callback passed to
        // transform_next_blocks() for (external) mode encryption
        // implementations implementing the cipher::BlockEncryptMut trait.
        macro_rules! gen_block_encrypt_trait_mode_block_encrypt_transform_cb_snippet {
            ($mode_transform_impl_instance:ident) => {
                |dst_blocks: &mut [u8]| {
                    $mode_transform_impl_instance.encrypt_block_mut(dst_blocks.into());
                }
            };
        }

        gen_match_on_block_cipher_mode_encryption_instance!(
            self,
            sym_block_cipher_mode_instance_gen_transform_in_place,
            block_cipher_instance,
            gen_mode_encryptor_impl_new_instance_snippet,
            gen_block_encrypt_trait_mode_block_encrypt_transform_cb_snippet,
            gen_mode_transform_grab_iv_snippet,
            dst,
            iv,
            iv_out
        );

        Ok(())
    }
}

impl convert::From<&SymBlockCipherModeEncryptionInstance> for SymBlockCipherAlg {
    fn from(value: &SymBlockCipherModeEncryptionInstance) -> Self {
        macro_rules! gen_block_cipher_to_block_cipher_alg {
            ($_mode_id:ident,
             $block_alg_id:ident,
             $key_size:tt,
             $_block_cipher_instance:ident) => {
                block_cipher_to_sym_block_cipher_alg_variant!($block_alg_id, $key_size)
            };
        }
        gen_match_on_block_cipher_mode_encryption_instance!(
            &*value.state,
            gen_block_cipher_to_block_cipher_alg,
            _block_cipher_instance
        )
    }
}

impl convert::From<&SymBlockCipherModeEncryptionInstance> for tpm2_interface::TpmiAlgCipherMode {
    fn from(value: &SymBlockCipherModeEncryptionInstance) -> Self {
        macro_rules! gen_block_cipher_to_tpmi_alg_cipher_mode {
            ($mode_id:ident,
             $_block_alg_id:ident,
             $_key_size:tt,
             $_block_cipher_instance:ident) => {
                mode_to_tpmi_alg_cipher_mode!($mode_id)
            };
        }
        gen_match_on_block_cipher_mode_encryption_instance!(
            &*value.state,
            gen_block_cipher_to_tpmi_alg_cipher_mode,
            _block_cipher_instance
        )
    }
}

pub struct SymBlockCipherModeDecryptionInstance {
    state: Box<SymBlockCipherModeDecryptionInstanceState>,
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
            state: box_try_new_with(
                || -> Result<SymBlockCipherModeDecryptionInstanceState, convert::Infallible> {
                    Ok(self.state.deref().clone())
                },
            )?,
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

// All supported block cipher implementations possibly wrapped implement
// ZeroizeOnDrop.
#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for SymBlockCipherModeDecryptionInstance {}

/// Map a triplet of (symbolic mode, symbolic block cipher, key length) to a
/// block cipher implementation suitable for decryption with that mode.
macro_rules! dec_mode_and_block_cipher_to_block_cipher_impl {
    (Ctr, Aes, 128) => {
        aes::Aes128Enc
    };
    (Ctr, Aes, 192) => {
        aes::Aes192Enc
    };
    (Ctr, Aes, 256) => {
        aes::Aes256Enc
    };
    (Ctr, Camellia, 128) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia128
    };
    (Ctr, Camellia, 192) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia192
    };
    (Ctr, Camellia, 256) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia256
    };
    (Ctr, Sm4, 128) => {
        // No differentiation between encryptor/decryptor made in sm4 crate.
        sm4::Sm4
    };

    (Ofb, Aes, 128) => {
        aes::Aes128Enc
    };
    (Ofb, Aes, 192) => {
        aes::Aes192Enc
    };
    (Ofb, Aes, 256) => {
        aes::Aes256Enc
    };
    (Ofb, Camellia, 128) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia128
    };
    (Ofb, Camellia, 192) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia192
    };
    (Ofb, Camellia, 256) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia256
    };
    (Ofb, Sm4, 128) => {
        // No differentiation between encryptor/decryptor made in sm4 crate.
        sm4::Sm4
    };

    (Cbc, Aes, 128) => {
        aes::Aes128Dec
    };
    (Cbc, Aes, 192) => {
        aes::Aes192Dec
    };
    (Cbc, Aes, 256) => {
        aes::Aes256Dec
    };
    (Cbc, Camellia, 128) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia128
    };
    (Cbc, Camellia, 192) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia192
    };
    (Cbc, Camellia, 256) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia256
    };
    (Cbc, Sm4, 128) => {
        // No differentiation between encryptor/decryptor made in sm4 crate.
        sm4::Sm4
    };

    (Cfb, Aes, 128) => {
        // cfb_mode needs a Decryptor to impl IvState.
        aes::Aes128
    };
    (Cfb, Aes, 192) => {
        // cfb_mode needs a Decryptor to impl IvState.
        aes::Aes192
    };
    (Cfb, Aes, 256) => {
        // cfb_mode needs a Decryptor to impl IvState.
        aes::Aes256
    };
    (Cfb, Camellia, 128) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia128
    };
    (Cfb, Camellia, 192) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia192
    };
    (Cfb, Camellia, 256) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia256
    };
    (Cfb, Sm4, 128) => {
        // No differentiation between encryptor/decryptor made in sm4 crate.
        sm4::Sm4
    };

    (Ecb, Aes, 128) => {
        aes::Aes128Dec
    };
    (Ecb, Aes, 192) => {
        aes::Aes192Dec
    };
    (Ecb, Aes, 256) => {
        aes::Aes256Dec
    };
    (Ecb, Camellia, 128) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia128
    };
    (Ecb, Camellia, 192) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia192
    };
    (Ecb, Camellia, 256) => {
        // No differentiation between encryptor/decryptor made in camellia crate.
        camellia::Camellia256
    };
    (Ecb, Sm4, 128) => {
        // No differentiation between encryptor/decryptor made in sm4 crate.
        sm4::Sm4
    };
}

#[derive(Clone)]
enum SymBlockCipherModeDecryptionInstanceState {
    #[cfg(all(feature = "ctr", feature = "aes"))]
    CtrAes128(dec_mode_and_block_cipher_to_block_cipher_impl!(Ctr, Aes, 128)),
    #[cfg(all(feature = "ctr", feature = "aes"))]
    CtrAes192(dec_mode_and_block_cipher_to_block_cipher_impl!(Ctr, Aes, 192)),
    #[cfg(all(feature = "ctr", feature = "aes"))]
    CtrAes256(dec_mode_and_block_cipher_to_block_cipher_impl!(Ctr, Aes, 256)),
    #[cfg(all(feature = "ctr", feature = "camellia"))]
    CtrCamellia128(dec_mode_and_block_cipher_to_block_cipher_impl!(Ctr, Camellia, 128)),
    #[cfg(all(feature = "ctr", feature = "camellia"))]
    CtrCamellia192(dec_mode_and_block_cipher_to_block_cipher_impl!(Ctr, Camellia, 192)),
    #[cfg(all(feature = "ctr", feature = "camellia"))]
    CtrCamellia256(dec_mode_and_block_cipher_to_block_cipher_impl!(Ctr, Camellia, 256)),
    #[cfg(all(feature = "ctr", feature = "sm4"))]
    CtrSm4_128(dec_mode_and_block_cipher_to_block_cipher_impl!(Ctr, Sm4, 128)),

    #[cfg(all(feature = "ofb", feature = "aes"))]
    OfbAes128(dec_mode_and_block_cipher_to_block_cipher_impl!(Ofb, Aes, 128)),
    #[cfg(all(feature = "ofb", feature = "aes"))]
    OfbAes192(dec_mode_and_block_cipher_to_block_cipher_impl!(Ofb, Aes, 192)),
    #[cfg(all(feature = "ofb", feature = "aes"))]
    OfbAes256(dec_mode_and_block_cipher_to_block_cipher_impl!(Ofb, Aes, 256)),
    #[cfg(all(feature = "ofb", feature = "camellia"))]
    OfbCamellia128(dec_mode_and_block_cipher_to_block_cipher_impl!(Ofb, Camellia, 128)),
    #[cfg(all(feature = "ofb", feature = "camellia"))]
    OfbCamellia192(dec_mode_and_block_cipher_to_block_cipher_impl!(Ofb, Camellia, 192)),
    #[cfg(all(feature = "ofb", feature = "camellia"))]
    OfbCamellia256(dec_mode_and_block_cipher_to_block_cipher_impl!(Ofb, Camellia, 256)),
    #[cfg(all(feature = "ofb", feature = "sm4"))]
    OfbSm4_128(dec_mode_and_block_cipher_to_block_cipher_impl!(Ofb, Sm4, 128)),

    #[cfg(all(feature = "cbc", feature = "aes"))]
    CbcAes128(dec_mode_and_block_cipher_to_block_cipher_impl!(Cbc, Aes, 128)),
    #[cfg(all(feature = "cbc", feature = "aes"))]
    CbcAes192(dec_mode_and_block_cipher_to_block_cipher_impl!(Cbc, Aes, 192)),
    #[cfg(all(feature = "cbc", feature = "aes"))]
    CbcAes256(dec_mode_and_block_cipher_to_block_cipher_impl!(Cbc, Aes, 256)),
    #[cfg(all(feature = "cbc", feature = "camellia"))]
    CbcCamellia128(dec_mode_and_block_cipher_to_block_cipher_impl!(Cbc, Camellia, 128)),
    #[cfg(all(feature = "cbc", feature = "camellia"))]
    CbcCamellia192(dec_mode_and_block_cipher_to_block_cipher_impl!(Cbc, Camellia, 192)),
    #[cfg(all(feature = "cbc", feature = "camellia"))]
    CbcCamellia256(dec_mode_and_block_cipher_to_block_cipher_impl!(Cbc, Camellia, 256)),
    #[cfg(all(feature = "cbc", feature = "sm4"))]
    CbcSm4_128(dec_mode_and_block_cipher_to_block_cipher_impl!(Cbc, Sm4, 128)),

    #[cfg(all(feature = "cfb", feature = "aes"))]
    CfbAes128(dec_mode_and_block_cipher_to_block_cipher_impl!(Cfb, Aes, 128)),
    #[cfg(all(feature = "cfb", feature = "aes"))]
    CfbAes192(dec_mode_and_block_cipher_to_block_cipher_impl!(Cfb, Aes, 192)),
    #[cfg(all(feature = "cfb", feature = "aes"))]
    CfbAes256(dec_mode_and_block_cipher_to_block_cipher_impl!(Cfb, Aes, 256)),
    #[cfg(all(feature = "cfb", feature = "camellia"))]
    CfbCamellia128(dec_mode_and_block_cipher_to_block_cipher_impl!(Cfb, Camellia, 128)),
    #[cfg(all(feature = "cfb", feature = "camellia"))]
    CfbCamellia192(dec_mode_and_block_cipher_to_block_cipher_impl!(Cfb, Camellia, 192)),
    #[cfg(all(feature = "cfb", feature = "camellia"))]
    CfbCamellia256(dec_mode_and_block_cipher_to_block_cipher_impl!(Cfb, Camellia, 256)),
    #[cfg(all(feature = "cfb", feature = "sm4"))]
    CfbSm4_128(dec_mode_and_block_cipher_to_block_cipher_impl!(Cfb, Sm4, 128)),

    #[cfg(all(feature = "ecb", feature = "aes"))]
    EcbAes128(dec_mode_and_block_cipher_to_block_cipher_impl!(Ecb, Aes, 128)),
    #[cfg(all(feature = "ecb", feature = "aes"))]
    EcbAes192(dec_mode_and_block_cipher_to_block_cipher_impl!(Ecb, Aes, 192)),
    #[cfg(all(feature = "ecb", feature = "aes"))]
    EcbAes256(dec_mode_and_block_cipher_to_block_cipher_impl!(Ecb, Aes, 256)),
    #[cfg(all(feature = "ecb", feature = "camellia"))]
    EcbCamellia128(dec_mode_and_block_cipher_to_block_cipher_impl!(Ecb, Camellia, 128)),
    #[cfg(all(feature = "ecb", feature = "camellia"))]
    EcbCamellia192(dec_mode_and_block_cipher_to_block_cipher_impl!(Ecb, Camellia, 192)),
    #[cfg(all(feature = "ecb", feature = "camellia"))]
    EcbCamellia256(dec_mode_and_block_cipher_to_block_cipher_impl!(Ecb, Camellia, 256)),
    #[cfg(all(feature = "ecb", feature = "sm4"))]
    EcbSm4_128(dec_mode_and_block_cipher_to_block_cipher_impl!(Ecb, Sm4, 128)),
}

/// Generate a `match {}` on SymBlockCipherModeDecryptionInstanceState and
/// invoke a macro in the body of each match arm.
///
/// The supplied macro `m` gets invoked with (`$args`, symbolic mode, symbolic
/// block cipher, key size, `$block_cipher_instance`) for each arm, where
/// identifier `$block_cipher_instance` is bound to the variant's respective
/// block cipher implementation instance member.
macro_rules! gen_match_on_block_cipher_mode_decryption_instance {
    ($block_cipher_mode_instance_value:expr, $m:ident, $block_cipher_instance:ident $(, $($args:tt),*)?) => {
        match $block_cipher_mode_instance_value {
            #[cfg(all(feature = "ctr", feature = "aes"))]
            SymBlockCipherModeDecryptionInstanceState::CtrAes128($block_cipher_instance) => {
                $m!($($($args),*,)? Ctr, Aes, 128, $block_cipher_instance)
            },
            #[cfg(all(feature = "ctr", feature = "aes"))]
            SymBlockCipherModeDecryptionInstanceState::CtrAes192($block_cipher_instance) => {
                $m!($($($args),*,)? Ctr, Aes, 192, $block_cipher_instance)
            },
            #[cfg(all(feature = "ctr", feature = "aes"))]
            SymBlockCipherModeDecryptionInstanceState::CtrAes256($block_cipher_instance) => {
                $m!($($($args),*,)? Ctr, Aes, 256, $block_cipher_instance)
            },
            #[cfg(all(feature = "ctr", feature = "camellia"))]
            SymBlockCipherModeDecryptionInstanceState::CtrCamellia128($block_cipher_instance) => {
                $m!($($($args),*,)? Ctr, Camellia, 128, $block_cipher_instance)
            },
            #[cfg(all(feature = "ctr", feature = "camellia"))]
            SymBlockCipherModeDecryptionInstanceState::CtrCamellia192($block_cipher_instance) => {
                $m!($($($args),*,)? Ctr, Camellia, 192, $block_cipher_instance)
            },
            #[cfg(all(feature = "ctr", feature = "camellia"))]
            SymBlockCipherModeDecryptionInstanceState::CtrCamellia256($block_cipher_instance) => {
                $m!($($($args),*,)? Ctr, Camellia, 256, $block_cipher_instance)
            },
            #[cfg(all(feature = "ctr", feature = "sm4"))]
            SymBlockCipherModeDecryptionInstanceState::CtrSm4_128($block_cipher_instance) => {
                $m!($($($args),*,)? Ctr, Sm4, 128, $block_cipher_instance)
            },

            #[cfg(all(feature = "ofb", feature = "aes"))]
            SymBlockCipherModeDecryptionInstanceState::OfbAes128($block_cipher_instance) => {
                $m!($($($args),*,)? Ofb, Aes, 128, $block_cipher_instance)
            },
            #[cfg(all(feature = "ofb", feature = "aes"))]
            SymBlockCipherModeDecryptionInstanceState::OfbAes192($block_cipher_instance) => {
                $m!($($($args),*,)? Ofb, Aes, 192, $block_cipher_instance)
            },
            #[cfg(all(feature = "ofb", feature = "aes"))]
            SymBlockCipherModeDecryptionInstanceState::OfbAes256($block_cipher_instance) => {
                $m!($($($args),*,)? Ofb, Aes, 256, $block_cipher_instance)
            },
            #[cfg(all(feature = "ofb", feature = "camellia"))]
            SymBlockCipherModeDecryptionInstanceState::OfbCamellia128($block_cipher_instance) => {
                $m!($($($args),*,)? Ofb, Camellia, 128, $block_cipher_instance)
            },
            #[cfg(all(feature = "ofb", feature = "camellia"))]
            SymBlockCipherModeDecryptionInstanceState::OfbCamellia192($block_cipher_instance) => {
                $m!($($($args),*,)? Ofb, Camellia, 192, $block_cipher_instance)
            },
            #[cfg(all(feature = "ofb", feature = "camellia"))]
            SymBlockCipherModeDecryptionInstanceState::OfbCamellia256($block_cipher_instance) => {
                $m!($($($args),*,)? Ofb, Camellia, 256, $block_cipher_instance)
            },
            #[cfg(all(feature = "ofb", feature = "sm4"))]
            SymBlockCipherModeDecryptionInstanceState::OfbSm4_128($block_cipher_instance) => {
                $m!($($($args),*,)? Ofb, Sm4, 128, $block_cipher_instance)
            },

            #[cfg(all(feature = "cbc", feature = "aes"))]
            SymBlockCipherModeDecryptionInstanceState::CbcAes128($block_cipher_instance) => {
                $m!($($($args),*,)? Cbc, Aes, 128, $block_cipher_instance)
            },
            #[cfg(all(feature = "cbc", feature = "aes"))]
            SymBlockCipherModeDecryptionInstanceState::CbcAes192($block_cipher_instance) => {
                $m!($($($args),*,)? Cbc, Aes, 192, $block_cipher_instance)
            },
            #[cfg(all(feature = "cbc", feature = "aes"))]
            SymBlockCipherModeDecryptionInstanceState::CbcAes256($block_cipher_instance) => {
                $m!($($($args),*,)? Cbc, Aes, 256, $block_cipher_instance)
            },
            #[cfg(all(feature = "cbc", feature = "camellia"))]
            SymBlockCipherModeDecryptionInstanceState::CbcCamellia128($block_cipher_instance) => {
                $m!($($($args),*,)? Cbc, Camellia, 128, $block_cipher_instance)
            },
            #[cfg(all(feature = "cbc", feature = "camellia"))]
            SymBlockCipherModeDecryptionInstanceState::CbcCamellia192($block_cipher_instance) => {
                $m!($($($args),*,)? Cbc, Camellia, 192, $block_cipher_instance)
            },
            #[cfg(all(feature = "cbc", feature = "camellia"))]
            SymBlockCipherModeDecryptionInstanceState::CbcCamellia256($block_cipher_instance) => {
                $m!($($($args),*,)? Cbc, Camellia, 256, $block_cipher_instance)
            },
            #[cfg(all(feature = "cbc", feature = "sm4"))]
            SymBlockCipherModeDecryptionInstanceState::CbcSm4_128($block_cipher_instance) => {
                $m!($($($args),*,)? Cbc, Sm4, 128, $block_cipher_instance)
            },

            #[cfg(all(feature = "cfb", feature = "aes"))]
            SymBlockCipherModeDecryptionInstanceState::CfbAes128($block_cipher_instance) => {
                $m!($($($args),*,)? Cfb, Aes, 128, $block_cipher_instance)
            },
            #[cfg(all(feature = "cfb", feature = "aes"))]
            SymBlockCipherModeDecryptionInstanceState::CfbAes192($block_cipher_instance) => {
                $m!($($($args),*,)? Cfb, Aes, 192, $block_cipher_instance)
            },
            #[cfg(all(feature = "cfb", feature = "aes"))]
            SymBlockCipherModeDecryptionInstanceState::CfbAes256($block_cipher_instance) => {
                $m!($($($args),*,)? Cfb, Aes, 256, $block_cipher_instance)
            },
            #[cfg(all(feature = "cfb", feature = "camellia"))]
            SymBlockCipherModeDecryptionInstanceState::CfbCamellia128($block_cipher_instance) => {
                $m!($($($args),*,)? Cfb, Camellia, 128, $block_cipher_instance)
            },
            #[cfg(all(feature = "cfb", feature = "camellia"))]
            SymBlockCipherModeDecryptionInstanceState::CfbCamellia192($block_cipher_instance) => {
                $m!($($($args),*,)? Cfb, Camellia, 192, $block_cipher_instance)
            },
            #[cfg(all(feature = "cfb", feature = "camellia"))]
            SymBlockCipherModeDecryptionInstanceState::CfbCamellia256($block_cipher_instance) => {
                $m!($($($args),*,)? Cfb, Camellia, 256, $block_cipher_instance)
            },
            #[cfg(all(feature = "cfb", feature = "sm4"))]
            SymBlockCipherModeDecryptionInstanceState::CfbSm4_128($block_cipher_instance) => {
                $m!($($($args),*,)? Cfb, Sm4, 128, $block_cipher_instance)
            },

            #[cfg(all(feature = "ecb", feature = "aes"))]
            SymBlockCipherModeDecryptionInstanceState::EcbAes128($block_cipher_instance) => {
                $m!($($($args),*,)? Ecb, Aes, 128, $block_cipher_instance)
            },
            #[cfg(all(feature = "ecb", feature = "aes"))]
            SymBlockCipherModeDecryptionInstanceState::EcbAes192($block_cipher_instance) => {
                $m!($($($args),*,)? Ecb, Aes, 192, $block_cipher_instance)
            },
            #[cfg(all(feature = "ecb", feature = "aes"))]
            SymBlockCipherModeDecryptionInstanceState::EcbAes256($block_cipher_instance) => {
                $m!($($($args),*,)? Ecb, Aes, 256, $block_cipher_instance)
            },
            #[cfg(all(feature = "ecb", feature = "camellia"))]
            SymBlockCipherModeDecryptionInstanceState::EcbCamellia128($block_cipher_instance) => {
                $m!($($($args),*,)? Ecb, Camellia, 128, $block_cipher_instance)
            },
            #[cfg(all(feature = "ecb", feature = "camellia"))]
            SymBlockCipherModeDecryptionInstanceState::EcbCamellia192($block_cipher_instance) => {
                $m!($($($args),*,)? Ecb, Camellia, 192, $block_cipher_instance)
            },
            #[cfg(all(feature = "ecb", feature = "camellia"))]
            SymBlockCipherModeDecryptionInstanceState::EcbCamellia256($block_cipher_instance) => {
                $m!($($($args),*,)? Ecb, Camellia, 256, $block_cipher_instance)
            },
            #[cfg(all(feature = "ecb", feature = "sm4"))]
            SymBlockCipherModeDecryptionInstanceState::EcbSm4_128($block_cipher_instance) => {
                $m!($($($args),*,)? Ecb, Sm4, 128, $block_cipher_instance)
            },
        }
    };
}

/// Map a triplet of (symbolic mode, symbolic block cipher, key size) to a
/// variant of SymBlockCipherModeDecryptionInstanceState.
macro_rules! mode_and_block_cipher_to_block_cipher_mode_decryption_instance_variant {
    (Ctr, Aes, 128) => {
        SymBlockCipherModeDecryptionInstanceState::CtrAes128
    };
    (Ctr, Aes, 192) => {
        SymBlockCipherModeDecryptionInstanceState::CtrAes192
    };
    (Ctr, Aes, 256) => {
        SymBlockCipherModeDecryptionInstanceState::CtrAes256
    };
    (Ctr, Camellia, 128) => {
        SymBlockCipherModeDecryptionInstanceState::CtrCamellia128
    };
    (Ctr, Camellia, 192) => {
        SymBlockCipherModeDecryptionInstanceState::CtrCamellia192
    };
    (Ctr, Camellia, 256) => {
        SymBlockCipherModeDecryptionInstanceState::CtrCamellia256
    };
    (Ctr, Sm4, 128) => {
        SymBlockCipherModeDecryptionInstanceState::CtrSm4_128
    };

    (Ofb, Aes, 128) => {
        SymBlockCipherModeDecryptionInstanceState::OfbAes128
    };
    (Ofb, Aes, 192) => {
        SymBlockCipherModeDecryptionInstanceState::OfbAes192
    };
    (Ofb, Aes, 256) => {
        SymBlockCipherModeDecryptionInstanceState::OfbAes256
    };
    (Ofb, Camellia, 128) => {
        SymBlockCipherModeDecryptionInstanceState::OfbCamellia128
    };
    (Ofb, Camellia, 192) => {
        SymBlockCipherModeDecryptionInstanceState::OfbCamellia192
    };
    (Ofb, Camellia, 256) => {
        SymBlockCipherModeDecryptionInstanceState::OfbCamellia256
    };
    (Ofb, Sm4, 128) => {
        SymBlockCipherModeDecryptionInstanceState::OfbSm4_128
    };

    (Cbc, Aes, 128) => {
        SymBlockCipherModeDecryptionInstanceState::CbcAes128
    };
    (Cbc, Aes, 192) => {
        SymBlockCipherModeDecryptionInstanceState::CbcAes192
    };
    (Cbc, Aes, 256) => {
        SymBlockCipherModeDecryptionInstanceState::CbcAes256
    };
    (Cbc, Camellia, 128) => {
        SymBlockCipherModeDecryptionInstanceState::CbcCamellia128
    };
    (Cbc, Camellia, 192) => {
        SymBlockCipherModeDecryptionInstanceState::CbcCamellia192
    };
    (Cbc, Camellia, 256) => {
        SymBlockCipherModeDecryptionInstanceState::CbcCamellia256
    };
    (Cbc, Sm4, 128) => {
        SymBlockCipherModeDecryptionInstanceState::CbcSm4_128
    };

    (Cfb, Aes, 128) => {
        SymBlockCipherModeDecryptionInstanceState::CfbAes128
    };
    (Cfb, Aes, 192) => {
        SymBlockCipherModeDecryptionInstanceState::CfbAes192
    };
    (Cfb, Aes, 256) => {
        SymBlockCipherModeDecryptionInstanceState::CfbAes256
    };
    (Cfb, Camellia, 128) => {
        SymBlockCipherModeDecryptionInstanceState::CfbCamellia128
    };
    (Cfb, Camellia, 192) => {
        SymBlockCipherModeDecryptionInstanceState::CfbCamellia192
    };
    (Cfb, Camellia, 256) => {
        SymBlockCipherModeDecryptionInstanceState::CfbCamellia256
    };
    (Cfb, Sm4, 128) => {
        SymBlockCipherModeDecryptionInstanceState::CfbSm4_128
    };

    (Ecb, Aes, 128) => {
        SymBlockCipherModeDecryptionInstanceState::EcbAes128
    };
    (Ecb, Aes, 192) => {
        SymBlockCipherModeDecryptionInstanceState::EcbAes192
    };
    (Ecb, Aes, 256) => {
        SymBlockCipherModeDecryptionInstanceState::EcbAes256
    };
    (Ecb, Camellia, 128) => {
        SymBlockCipherModeDecryptionInstanceState::EcbCamellia128
    };
    (Ecb, Camellia, 192) => {
        SymBlockCipherModeDecryptionInstanceState::EcbCamellia192
    };
    (Ecb, Camellia, 256) => {
        SymBlockCipherModeDecryptionInstanceState::EcbCamellia256
    };
    (Ecb, Sm4, 128) => {
        SymBlockCipherModeDecryptionInstanceState::EcbSm4_128
    };
}

macro_rules! mode_to_dec_impl {
    (Ctr, $block_cipher_impl:ty) => {
        ctr_impl::Decryptor::<&$block_cipher_impl>
    };
    (Ofb, $block_cipher_impl:ty) => {
        ofb::OfbCore::<&$block_cipher_impl>
    };
    (Cbc, $block_cipher_impl:ty) => {
        cbc::Decryptor::<&$block_cipher_impl>
    };
    (Cfb, $block_cipher_impl:ty) => {
        cfb_mode::Decryptor::<&$block_cipher_impl>
    };
    (Ecb, $block_cipher_impl:ty) => {
        ecb::Decryptor::<&$block_cipher_impl>
    };
}

// Instantiate a block cipher mode implementation wrapping a block cipher
// instance. Used from SymBlockCipherDecryptionInstanceState::decrypt() and
// SymBlockCipherDecryptionInstanceState::decrypt_in_place().
macro_rules! gen_mode_decryptor_impl_new_instance_snippet {
    (Ecb,
     $block_alg_id:ident,
     $key_size:tt,
     $block_cipher_instance:ident,
     $iv:ident,
     $iv_out_opt:ident,
    ) => {{
        if $iv.len() != 0 {
            return Err(CryptoError::InvalidIV);
        } else if !$iv_out_opt.as_ref().map(|iv_out| iv_out.is_empty()).unwrap_or(true) {
            return Err(CryptoError::Internal);
        }

        // Note that the block cipher instance is a reference, which implements
        // crypto_common's BlockDecrypt, hence BlockDecryptMut. This reduces the
        // mode instance's size on the stack significantly. Also, all (possibly
        // external) block cipher mode implementations impl ZeroizeOnDrop.
        <mode_to_dec_impl!(
            Ecb,
            dec_mode_and_block_cipher_to_block_cipher_impl!(Ecb, $block_alg_id, $key_size)
        )>::inner_init($block_cipher_instance)
    }};
    ($mode_id:ident,
     $block_alg_id:ident,
     $key_size:tt,
     $block_cipher_instance:ident,
     $iv:ident,
     $iv_out_opt:ident,
    ) => {{
        let expected_iv_len = mode_and_block_cipher_to_iv_len!($mode_id, $block_alg_id, $key_size);
        if $iv.len() != expected_iv_len {
            return Err(CryptoError::InvalidIV);
        } else if $iv_out_opt
            .as_ref()
            .map(|iv_out| iv_out.len() != expected_iv_len)
            .unwrap_or(false)
        {
            return Err(CryptoError::Internal);
        }

        let iv = crypto_common::Iv::<
            mode_to_dec_impl!(
                $mode_id,
                dec_mode_and_block_cipher_to_block_cipher_impl!($mode_id, $block_alg_id, $key_size)
            ),
        >::from_slice($iv);

        // Note that the block cipher instance is a reference, which implements
        // crypto_common's BlockDecrypt, hence BlockDecryptMut. This reduces the
        // mode instance's size on the stack significantly. Also, all (possibly
        // external) block cipher mode implementations impl ZeroizeOnDrop.
        <mode_to_dec_impl!(
            $mode_id,
            dec_mode_and_block_cipher_to_block_cipher_impl!($mode_id, $block_alg_id, $key_size)
        )>::inner_iv_init($block_cipher_instance, iv)
    }};
}

impl SymBlockCipherModeDecryptionInstanceState {
    fn new(
        mode: tpm2_interface::TpmiAlgCipherMode,
        alg: &SymBlockCipherAlg,
        key: &[u8],
    ) -> Result<Box<Self>, CryptoError> {
        macro_rules! gen_instantiate {
            ($mode_id:ident, $block_alg_id:ident, $key_size:tt) => {{
                // Don't use crypto_common's convenience KeyInit::from_slice() for instantiating
                // the cipher, but wrap the key explictly first to have all possible
                // error paths out of the way, thereby enabling a zero copy construction
                // right into the Box' memory.
                let expected_key_len = <dec_mode_and_block_cipher_to_block_cipher_impl!(
                    $mode_id,
                    $block_alg_id,
                    $key_size
                ) as crypto_common::KeySizeUser>::KeySize::to_usize();
                debug_assert_eq!(8 * expected_key_len, $key_size);
                if key.len() != expected_key_len {
                    return Err(CryptoError::KeySize);
                }

                let key = crypto_common::Key::<
                    dec_mode_and_block_cipher_to_block_cipher_impl!($mode_id, $block_alg_id, $key_size),
                >::from_slice(key);

                box_try_new_with(|| -> Result<Self, convert::Infallible> {
                    Ok(
                        mode_and_block_cipher_to_block_cipher_mode_decryption_instance_variant!(
                            $mode_id,
                            $block_alg_id,
                            $key_size
                        )(<dec_mode_and_block_cipher_to_block_cipher_impl!(
                            $mode_id,
                            $block_alg_id,
                            $key_size
                        )>::new(key)),
                    )
                })?
            }};
        }

        Ok(gen_match_on_tpmi_alg_cipher_mode_and_block_cipher_alg!(
            mode,
            alg,
            gen_instantiate
        ))
    }

    fn block_cipher_block_len(&self) -> usize {
        macro_rules! gen_block_cipher_block_len {
            ($_mode_id:ident, $block_cipher_alg_id:ident, $key_size:tt, $_block_cipher_instance:ident) => {
                block_cipher_to_block_len!($block_cipher_alg_id, $key_size)
            };
        }
        gen_match_on_block_cipher_mode_decryption_instance!(self, gen_block_cipher_block_len, _block_cipher_instance)
    }

    fn iv_len(&self) -> usize {
        macro_rules! gen_iv_len_for_mode_and_block_cipher {
            ($mode_id:ident,
              $block_alg_id:ident,
              $key_size:tt,
              $_block_cipher_instance:ident) => {
                mode_and_block_cipher_to_iv_len!($mode_id, $block_alg_id, $key_size)
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
        // Generate code snippet for the block transform callback passed to
        // transform_next_blocks() for (external) mode implementations
        // implementing the cipher::BlockDecryptMut trait.
        macro_rules! gen_block_decrypt_trait_mode_block_decrypt_transform_cb_snippet {
            ($mode_transform_impl_instance:ident) => {
                |dst_blocks: &mut [u8], src_blocks: Option<&[u8]>| {
                    if let Some(src_blocks) = src_blocks {
                        $mode_transform_impl_instance.decrypt_block_b2b_mut(src_blocks.into(), dst_blocks.into());
                    } else {
                        $mode_transform_impl_instance.decrypt_block_mut(dst_blocks.into());
                    }
                }
            };
        }

        gen_match_on_block_cipher_mode_decryption_instance!(
            self,
            sym_block_cipher_mode_instance_gen_transform,
            block_cipher_instance,
            gen_mode_decryptor_impl_new_instance_snippet,
            gen_block_decrypt_trait_mode_block_decrypt_transform_cb_snippet,
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
        // Generate code snippet for the block transform callback passed to
        // transform_next_blocks_in_place() for (external) mode implementations
        // implementing the cipher::BlockDecryptMut trait.
        macro_rules! gen_block_decrypt_trait_mode_block_decrypt_transform_cb_snippet {
            ($mode_transform_impl_instance:ident) => {
                |dst_blocks: &mut [u8]| {
                    $mode_transform_impl_instance.decrypt_block_mut(dst_blocks.into());
                }
            };
        }

        gen_match_on_block_cipher_mode_decryption_instance!(
            self,
            sym_block_cipher_mode_instance_gen_transform_in_place,
            block_cipher_instance,
            gen_mode_decryptor_impl_new_instance_snippet,
            gen_block_decrypt_trait_mode_block_decrypt_transform_cb_snippet,
            gen_mode_transform_grab_iv_snippet,
            dst,
            iv,
            iv_out
        );

        Ok(())
    }
}

impl convert::From<&SymBlockCipherModeDecryptionInstance> for SymBlockCipherAlg {
    fn from(value: &SymBlockCipherModeDecryptionInstance) -> Self {
        macro_rules! gen_block_cipher_to_block_cipher_alg {
            ($_mode_id:ident,
             $block_alg_id:ident,
             $key_size:tt,
             $_block_cipher_instance:ident) => {
                block_cipher_to_sym_block_cipher_alg_variant!($block_alg_id, $key_size)
            };
        }
        gen_match_on_block_cipher_mode_decryption_instance!(
            &*value.state,
            gen_block_cipher_to_block_cipher_alg,
            _block_cipher_instance
        )
    }
}

impl convert::From<&SymBlockCipherModeDecryptionInstance> for tpm2_interface::TpmiAlgCipherMode {
    fn from(value: &SymBlockCipherModeDecryptionInstance) -> Self {
        macro_rules! gen_block_cipher_to_tpmi_alg_cipher_mode {
            ($mode_id:ident,
             $_block_alg_id:ident,
             $_key_size:tt,
             $_block_cipher_instance:ident) => {
                mode_to_tpmi_alg_cipher_mode!($mode_id)
            };
        }
        gen_match_on_block_cipher_mode_decryption_instance!(
            &*value.state,
            gen_block_cipher_to_tpmi_alg_cipher_mode,
            _block_cipher_instance
        )
    }
}
