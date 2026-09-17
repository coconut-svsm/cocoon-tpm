// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Red Hat
// Author: Oliver Steffen <osteffen@redhat.com>

//! OpenSSL FFI backend [Random Number Generator](rng) implementations.

use cocoon_tpm_ossl_bare_sys as ossl_bare_sys;

use super::error::ossl_get_error;
use crate::{io_slices, rng};
use core::ffi;

/// [`RngCore`](rng::RngCore) interface wrapper to OpenSSL's `RAND_bytes()`.
///
/// `OsslRandBytesRng` is a lightweight ZST wrapper around `RAND_bytes()`.
#[derive(Default)]
pub struct OsslRandBytesRng {}

impl OsslRandBytesRng {
    pub fn new() -> Self {
        OsslRandBytesRng {}
    }
}

impl rng::RngCore for OsslRandBytesRng {
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
            if unsafe { ossl_bare_sys::RAND_bytes(out_slice.as_mut_ptr(), out_slice.len() as ffi::c_int) } <= 0 {
                return Err(ossl_get_error())?;
            }
        }
        Ok(())
    }
}
