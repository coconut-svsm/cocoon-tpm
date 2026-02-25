// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Key derivation function interface traits and implementations.
//!
//! The main interface for use with any key generation primitives is
//! [`VariableChunkOutputKdf`], which implements [`RngCore`](rng::RngCore)
//! commonly expected by those.

// Lifetimes are not obvious at first sight here, make the explicit.
#![allow(clippy::needless_lifetimes)]

extern crate alloc;
use alloc::vec::Vec;

use crate::utils_common::{
    alloc::try_alloc_zeroizing_vec,
    io_slices::{self, IoSlicesIterCommon as _, IoSlicesMutIter as _},
    zeroize,
};
use crate::{
    CryptoError,
    io_slices::{CryptoPeekableIoSlicesIter, CryptoWalkableIoSlicesMutIter},
    rng,
};

pub mod mgf1;
pub mod tcg_tpm2_kdf_a;
pub mod tcg_tpm2_kdf_e;

/// Common interface to the minimal functionality provided by all key derivation
/// function implementations.
pub trait Kdf {
    /// Determine the maximum possible length of a key generation request.
    fn max_output_len(&self) -> Option<usize>;

    /// Generate key material.
    ///
    /// Note that this is a one-shot operation consuming the instance. For an
    /// interface capable of serving multiple requests
    /// see [`VariableChunkOutputKdf::generate_chunk()`](VariableChunkOutputKdf::generate_chunk).
    ///
    /// # Arguments:
    ///
    /// * `output` - Destination buffers to write the generated key to.
    fn generate<'a, OI: CryptoWalkableIoSlicesMutIter<'a>>(self, output: OI) -> Result<(), CryptoError>;

    /// Generate key material and xor into existing data.
    ///
    /// Note that this is a one-shot operation consuming the instance. For an
    /// interface capable of serving multiple requests
    /// see [`VariableChunkOutputKdf::generate_and_xor_chunk()`](VariableChunkOutputKdf::generate_and_xor_chunk).
    ///
    /// # Arguments:
    ///
    /// * `output` - Destination buffers to xor the generated key to.
    fn generate_and_xor<'a, OI: CryptoWalkableIoSlicesMutIter<'a>>(self, output: OI) -> Result<(), CryptoError>;
}

/// Common interface to key derivation function implementations capable of
/// serving multiple requests from a single instance.
///
/// A [`RngCore`](rng::RngCore) implementation is provided for implementators of
/// `VariableChunkOutputKdf` so that these can seaminglessly serve as the
/// randomness source for any key generation primitives (which would then
/// become key derivation primitives, strictly speaking).
pub trait VariableChunkOutputKdf {
    /// Determine the maximum possible total length of all subsequent key
    /// generation requests combined.
    fn max_remaining_len(&self) -> Option<usize>;

    /// Generate key material.
    ///
    /// # Arguments:
    ///
    /// * `output` - Destination buffers to write the generated key to.
    fn generate_chunk<'a, OI: CryptoWalkableIoSlicesMutIter<'a>>(&mut self, output: OI) -> Result<(), CryptoError>;

    /// Generate key material and xor into existing data.
    ///
    /// # Arguments:
    ///
    /// * `output` - Destination buffers to xor the generated key to.
    fn generate_and_xor_chunk<'a, OI: CryptoWalkableIoSlicesMutIter<'a>>(
        &mut self,
        output: OI,
    ) -> Result<(), CryptoError>;
}

impl<VK: VariableChunkOutputKdf> Kdf for VK {
    fn max_output_len(&self) -> Option<usize> {
        self.max_remaining_len()
    }

    fn generate<'a, OI: CryptoWalkableIoSlicesMutIter<'a>>(mut self, output: OI) -> Result<(), CryptoError> {
        self.generate_chunk(output)
    }

    fn generate_and_xor<'a, OI: CryptoWalkableIoSlicesMutIter<'a>>(mut self, output: OI) -> Result<(), CryptoError> {
        self.generate_and_xor_chunk(output)
    }
}

/// Convenience implementation helper trait definining an interface to KDF
/// implementations operating on units of a fixed block length.
///
/// Implementations of this trait get wrapped in a `BufferedFixedBlockOutputKdf`
/// to obtain an implementation of [`VariableChunkOutputKdf`].
pub trait FixedBlockOutputKdf: Sized {
    /// Determine the key derivation function implementation's underlying block
    /// length.
    fn block_len(&self) -> usize;

    /// Determine the maximum possible total length of all subsequent key
    /// generation requests combined.
    fn max_remaining_len(&self) -> Option<usize>;

    /// Generate one block of key material.
    /// # Arguments:
    ///
    /// * `output` - Destination buffer of size [`block_len()`](Self::block_len)
    ///   to write the generated key block to.
    fn generate_block(&mut self, output: &mut [u8]) -> Result<usize, CryptoError>;

    /// Serve aribtrarily sized key generation request, buffering any generated
    /// excess bytes away for future use.
    ///
    /// Default implementation used internally by
    /// [`BufferedFixedBlockOutputKdf::generate_chunk()`](BufferedFixedBlockOutputKdf::generate_chunk).
    ///
    /// Returns the number of valid excess key material bytes remaining in
    /// `block_buf`.
    ///
    /// # Arguments:
    ///
    /// * `output` - Request destination buffers to fill with generated key
    ///   material to.
    /// * `block_buf` - Excess key byte buffer of size
    ///   [`block_len()`](Self::block_len). Contains unused excess key material
    ///   of length `block_buf_remaining_len` from previous requests at entry.
    ///   Receives any excess key material from the last block generated to
    ///   fulfill the current request upon return.
    /// * `block_buf_remaining_len` - Number of valid bytes in `block_buf` on
    ///   entry.
    fn generate_chunk_impl<'a>(
        &mut self,
        output: &mut dyn CryptoWalkableIoSlicesMutIter<'a>,
        block_buf: &mut [u8],
        mut block_buf_remaining_len: usize,
    ) -> Result<usize, CryptoError> {
        if let Some(max_remaining_len) = self.max_remaining_len() {
            if output.total_len()? > max_remaining_len + block_buf_remaining_len {
                return Err(CryptoError::RequestTooBig);
            }
        }

        block_buf_remaining_len -= output.copy_from_iter(
            &mut io_slices::SingletonIoSlice::new(&block_buf[block_buf.len() - block_buf_remaining_len..])
                .map_infallible_err(),
        )?;
        debug_assert!(block_buf_remaining_len == 0 || output.is_empty()?);

        let block_len = self.block_len();
        while let Some(cur_output_slice) = output.next_slice_mut(Some(block_len))? {
            let cur_output_slice_len = cur_output_slice.len();
            if cur_output_slice_len == block_len {
                let cur_block_len = self.generate_block(cur_output_slice)?;
                debug_assert_eq!(cur_block_len, block_len);
            } else {
                debug_assert_eq!(block_buf.len(), block_len);
                let cur_block_len = self.generate_block(block_buf)?;
                debug_assert!(
                    cur_block_len == block_len || (cur_block_len >= cur_output_slice_len && output.is_empty()?)
                );
                if cur_block_len != block_len {
                    // The buffered output will get consumed from the tail of the block_buf[]. Move
                    // the result from generate_block() there.
                    block_buf.copy_within(..cur_block_len, block_len - cur_block_len);
                }
                block_buf_remaining_len = cur_block_len;
                let mut block_buf_remaining =
                    io_slices::SingletonIoSlice::new(&block_buf[block_buf.len() - block_buf_remaining_len..]);
                block_buf_remaining_len -=
                    io_slices::SingletonIoSliceMut::new(cur_output_slice).copy_from_iter(&mut block_buf_remaining)?;
                block_buf_remaining_len -= output.copy_from_iter(&mut block_buf_remaining.map_infallible_err())?;
            }
        }

        // Wipe out the bytes consumed from the block_buf[]. Note that callers are
        // allowed to pass an empty block_buf[] in case they can guarantee for the
        // given configuration of output slices that it wouldn't get used
        // anyway.
        if !block_buf.is_empty() {
            zeroize::Zeroize::zeroize(&mut block_buf[..block_len - block_buf_remaining_len]);
        }

        Ok(block_buf_remaining_len)
    }

    /// Serve aribtrarily sized requests to xor generated key material into
    /// preexisting data, buffering any generated excess bytes away for
    /// futre use.
    ///
    /// Default implementation used internally by
    /// [`BufferedFixedBlockOutputKdf::generate_and_xor_chunk()`](BufferedFixedBlockOutputKdf::generate_and_xor_chunk).
    ///
    /// Returns the number of valid excess key material bytes remaining in
    /// `block_buf`.
    ///
    /// # Arguments:
    ///
    /// * `output` - Request destination buffers to xor the generated key
    ///   material to.
    /// * `block_buf` - Excess key byte buffer of size
    ///   [`block_len()`](Self::block_len). Contains unused excess key material
    ///   of length `block_buf_remaining_len` from previous requests at entry.
    ///   Receives any excess key material from the last block generated to
    ///   fulfill the current request upon return.
    /// * `block_buf_remaining_len` - Number of valid bytes in `block_buf` on
    ///   entry.
    fn generate_and_xor_chunk_impl<'a>(
        &mut self,
        output: &mut dyn CryptoWalkableIoSlicesMutIter<'a>,
        block_buf: &mut [u8],
        mut block_buf_remaining_len: usize,
    ) -> Result<usize, CryptoError> {
        if let Some(max_remaining_len) = self.max_remaining_len() {
            if output.total_len()? > max_remaining_len + block_buf_remaining_len {
                return Err(CryptoError::RequestTooBig);
            }
        }

        block_buf_remaining_len -= output.xor_from_iter(
            &mut io_slices::SingletonIoSlice::new(&block_buf[block_buf.len() - block_buf_remaining_len..])
                .map_infallible_err(),
        )?;
        debug_assert!(block_buf_remaining_len == 0 || output.is_empty()?);

        let block_len = self.block_len();
        while !output.is_empty()? {
            debug_assert_eq!(block_buf.len(), block_len);
            let cur_block_len = self.generate_block(block_buf)?;
            debug_assert!(cur_block_len == block_len || (cur_block_len >= output.total_len()?));
            if cur_block_len != block_len {
                // The buffered output will get consumed from the tail of the block_buf[]. Move
                // the result from generate_block() there.
                block_buf.copy_within(..cur_block_len, block_len - cur_block_len);
            }
            block_buf_remaining_len = cur_block_len;
            block_buf_remaining_len -= output.xor_from_iter(
                &mut io_slices::SingletonIoSlice::new(&block_buf[block_buf.len() - block_buf_remaining_len..])
                    .map_infallible_err(),
            )?;
        }

        // Wipe out the bytes consumed from the block_buf[].
        zeroize::Zeroize::zeroize(&mut block_buf[..block_len - block_buf_remaining_len]);

        Ok(block_buf_remaining_len)
    }
}

/// [`FixedBlockOutputKdf`] adaptor implementing [`VariableChunkOutputKdf`].
pub struct BufferedFixedBlockOutputKdf<BK: FixedBlockOutputKdf> {
    block_kdf: BK,
    block_buf: zeroize::Zeroizing<Vec<u8>>,
    block_buf_remaining_len: usize,
}

impl<BK: FixedBlockOutputKdf> BufferedFixedBlockOutputKdf<BK> {
    /// Wrap a [`FixedBlockOutputKdf`] instance to implement
    /// [`VariableChunkOutputKdf`] for.
    ///
    /// # Arguments;
    ///
    /// * `block_kdf` - The [`FixedBlockOutputKdf`] instance to wrap.
    pub fn new(block_kdf: BK) -> Result<Self, CryptoError> {
        let block_len = block_kdf.block_len();
        let block_buf = try_alloc_zeroizing_vec::<u8>(block_len)?;
        Ok(Self {
            block_kdf,
            block_buf,
            block_buf_remaining_len: 0,
        })
    }
}

impl<BK: FixedBlockOutputKdf> VariableChunkOutputKdf for BufferedFixedBlockOutputKdf<BK> {
    fn max_remaining_len(&self) -> Option<usize> {
        self.block_kdf
            .max_remaining_len()
            .map(|max_remaining: usize| max_remaining + self.block_buf_remaining_len)
    }

    fn generate_chunk<'a, OI: CryptoWalkableIoSlicesMutIter<'a>>(&mut self, mut output: OI) -> Result<(), CryptoError> {
        self.block_buf_remaining_len = self.block_kdf.generate_chunk_impl(
            &mut output,
            self.block_buf.as_mut_slice(),
            self.block_buf_remaining_len,
        )?;
        Ok(())
    }

    fn generate_and_xor_chunk<'a, OI: CryptoWalkableIoSlicesMutIter<'a>>(
        &mut self,
        mut output: OI,
    ) -> Result<(), CryptoError> {
        self.block_buf_remaining_len = self.block_kdf.generate_and_xor_chunk_impl(
            &mut output,
            self.block_buf.as_mut_slice(),
            self.block_buf_remaining_len,
        )?;
        Ok(())
    }
}

// For code-uniformity of e.g. key derivation + generation primitives,
// provide a trivial RngCore implementation for VariableChunkOutputKdf.
impl<VK: VariableChunkOutputKdf> rng::RngCore for VK {
    fn generate<'a, 'b, OI: CryptoWalkableIoSlicesMutIter<'a>, AII: CryptoPeekableIoSlicesIter<'b>>(
        &mut self,
        output: OI,
        _additional_input: Option<AII>,
    ) -> Result<(), rng::RngGenerateError> {
        self.generate_chunk(output).map_err(rng::RngGenerateError::CryptoError)
    }
}
