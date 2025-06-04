// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! BoringSSL FFI backend [Random Number Generator](rng) implementations.

use cocoon_tpm_bssl_bare_sys as bssl_bare_sys;

use super::error::bssl_get_error;
use crate::{io_slices, rng};

/// [`RngCore`](rng::RngCore) interface wrapper to BoringSSL's `RAND_bytes()`.
///
/// `BsslRandBytesRng` is a lightweight ZST wrapper around `RAND_bytes()`.
///
/// <div class="warning">
///
/// Note that BoringSSL's `RAND_bytes()` terminates with `abort()` in case of of
/// a failure, on failure of collecting sufficient entropy in particular.
///
/// </div>
#[derive(Default)]
pub struct BsslRandBytesRng {}

impl BsslRandBytesRng {
    pub fn new() -> Self {
        BsslRandBytesRng {}
    }
}

impl rng::RngCore for BsslRandBytesRng {
    fn generate<
        'a,
        'b,
        OI: io_slices::CryptoWalkableIoSlicesMutIter<'a>,
        AII: io_slices::CryptoPeekableIoSlicesIter<'b>,
    >(
        &mut self,
        mut output: OI,
        _additional_input: Option<AII>,
    ) -> Result<(), rng::RngGenerateError> {
        while let Some(out_slice) = output.next_slice_mut(None)? {
            // IO slices iterators filter empty slices.
            debug_assert!(!out_slice.is_empty());
            // Note that BoringSSL calls abort() on failure.
            if unsafe { bssl_bare_sys::RAND_bytes(out_slice.as_mut_ptr(), out_slice.len()) } <= 0 {
                return Err(bssl_get_error())?;
            }
        }
        Ok(())
    }
}
