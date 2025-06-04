// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! BoringSSL FFI BIGNUM bindings.

use cocoon_tpm_bssl_bare_sys as bssl_bare_sys;

use super::error::bssl_get_error;
use crate::utils_common::alloc::try_alloc_zeroizing_vec;
use crate::CryptoError;
use cmpa::MpMutUInt as _;
use core::{convert, ptr};

pub struct BsslBnCtx {
    ctx: *mut bssl_bare_sys::BN_CTX,
}

impl BsslBnCtx {
    pub fn new() -> Result<Self, CryptoError> {
        let ctx = unsafe { bssl_bare_sys::BN_CTX_new() };
        if ctx.is_null() {
            return Err(bssl_get_error());
        }
        Ok(Self { ctx })
    }

    pub fn as_mut_ptr(&mut self) -> *mut bssl_bare_sys::BN_CTX {
        self.ctx
    }
}

impl Drop for BsslBnCtx {
    fn drop(&mut self) {
        unsafe { bssl_bare_sys::BN_CTX_free(self.ctx) };
    }
}

pub struct BsslBn {
    bn: *mut bssl_bare_sys::BIGNUM,
}

impl BsslBn {
    pub fn new() -> Result<Self, CryptoError> {
        let bn = unsafe { bssl_bare_sys::BN_new() };
        if bn.is_null() {
            return Err(bssl_get_error());
        }

        Ok(Self { bn })
    }

    pub fn as_ptr(&self) -> *const bssl_bare_sys::BIGNUM {
        self.bn as *const bssl_bare_sys::BIGNUM
    }

    pub fn as_mut_ptr(&mut self) -> *mut bssl_bare_sys::BIGNUM {
        self.bn
    }

    pub fn len(&self) -> Result<usize, CryptoError> {
        usize::try_from(unsafe { bssl_bare_sys::BN_num_bytes(self.bn) }).map_err(|_| CryptoError::Internal)
    }

    pub fn to_be_bytes(&self, dst: &mut cmpa::MpMutBigEndianUIntByteSlice<'_>) -> Result<(), CryptoError> {
        let bytes = <&mut [u8]>::from(dst);
        let bytes_len = bytes.len();
        if bytes_len < self.len()? {
            return Err(CryptoError::Internal);
        } else if bytes_len == 0 {
            return Ok(())
        }

        if unsafe { bssl_bare_sys::BN_bn2bin_padded(bytes.as_mut_ptr(), bytes_len, self.bn) } < 0 {
            return Err(bssl_get_error());
        }
        Ok(())
    }

    pub fn try_from_cmpa_mp_uint<T: cmpa::MpUIntCommon>(value: &T) -> Result<Self, CryptoError> {
        // The copy could be avoided in case T was a MpBigEndianUIntByteSlice already,
        // but we don't have specialization.
        let len = value.len();
        let mut be_bytes = try_alloc_zeroizing_vec(len)?;
        cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut be_bytes).copy_from(value);
        Self::try_from(cmpa::MpBigEndianUIntByteSlice::from_bytes(&be_bytes))
    }
}

impl Drop for BsslBn {
    fn drop(&mut self) {
        unsafe { bssl_bare_sys::BN_clear_free(self.bn) };
    }
}

impl zeroize::ZeroizeOnDrop for BsslBn {}

impl<'a> convert::TryFrom<cmpa::MpBigEndianUIntByteSlice<'a>> for BsslBn {
    type Error = CryptoError;

    fn try_from(value: cmpa::MpBigEndianUIntByteSlice<'a>) -> Result<Self, Self::Error> {
        let bytes = <&[u8]>::from(value);
        if bytes.is_empty() {
            return BsslBn::new();
        }
        let bn = unsafe { bssl_bare_sys::BN_bin2bn(bytes.as_ptr(), bytes.len(), ptr::null_mut()) };
        if bn.is_null() {
            return Err(bssl_get_error());
        }

        Ok(Self { bn })
    }
}
