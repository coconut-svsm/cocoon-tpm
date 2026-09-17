// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Red Hat
// Author: Oliver Steffen <osteffen@redhat.com>

//! OpenSSL FFI BIGNUM bindings.

use cocoon_tpm_ossl_bare_sys as ossl_bare_sys;

use super::error::ossl_get_error;
use crate::CryptoError;
use crate::utils_common::{
    alloc::try_alloc_zeroizing_vec,
    zeroize,
};
use cmpa::MpMutUInt as _;
use core::{convert, ffi, ptr};

pub struct OsslBnCtx {
    ctx: *mut ossl_bare_sys::BN_CTX,
}

impl OsslBnCtx {
    pub fn new() -> Result<Self, CryptoError> {
        let ctx = unsafe { ossl_bare_sys::BN_CTX_new() };
        if ctx.is_null() {
            return Err(ossl_get_error());
        }
        Ok(Self { ctx })
    }

    pub fn as_mut_ptr(&mut self) -> *mut ossl_bare_sys::BN_CTX {
        self.ctx
    }
}

impl Drop for OsslBnCtx {
    fn drop(&mut self) {
        unsafe { ossl_bare_sys::BN_CTX_free(self.ctx) };
    }
}

pub struct OsslBn {
    bn: *mut ossl_bare_sys::BIGNUM,
}

impl OsslBn {
    pub fn new() -> Result<Self, CryptoError> {
        let bn = unsafe { ossl_bare_sys::BN_new() };
        if bn.is_null() {
            return Err(ossl_get_error());
        }

        Ok(Self { bn })
    }

    pub fn as_ptr(&self) -> *const ossl_bare_sys::BIGNUM {
        self.bn as *const ossl_bare_sys::BIGNUM
    }

    pub fn as_mut_ptr(&mut self) -> *mut ossl_bare_sys::BIGNUM {
        self.bn
    }

    pub fn len(&self) -> Result<usize, CryptoError> {
        usize::try_from(unsafe { ossl_bare_sys::ossl_shim_BN_num_bytes(self.bn) }).map_err(|_| CryptoError::Internal)
    }

    pub fn to_be_bytes(&self, dst: &mut cmpa::MpMutBigEndianUIntByteSlice<'_>) -> Result<(), CryptoError> {
        let bytes = <&mut [u8]>::from(dst);
        let bytes_len = bytes.len();
        if bytes_len < self.len()? {
            return Err(CryptoError::Internal);
        } else if bytes_len == 0 {
            return Ok(());
        }

        if unsafe { ossl_bare_sys::ossl_shim_BN_bn2bin_padded(bytes.as_mut_ptr(), bytes_len, self.bn) } == 0 {
            return Err(ossl_get_error());
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

impl Drop for OsslBn {
    fn drop(&mut self) {
        unsafe { ossl_bare_sys::BN_clear_free(self.bn) };
    }
}

impl zeroize::ZeroizeOnDrop for OsslBn {}

impl<'a> convert::TryFrom<cmpa::MpBigEndianUIntByteSlice<'a>> for OsslBn {
    type Error = CryptoError;

    fn try_from(value: cmpa::MpBigEndianUIntByteSlice<'a>) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl<'a> convert::TryFrom<&cmpa::MpBigEndianUIntByteSlice<'a>> for OsslBn {
    type Error = CryptoError;

    fn try_from(value: &cmpa::MpBigEndianUIntByteSlice<'a>) -> Result<Self, Self::Error> {
        let bytes = value.as_bytes();
        if bytes.is_empty() {
            return OsslBn::new();
        }
        let bn = unsafe { ossl_bare_sys::BN_bin2bn(bytes.as_ptr(), bytes.len() as ffi::c_int, ptr::null_mut()) };
        if bn.is_null() {
            return Err(ossl_get_error());
        }

        Ok(Self { bn })
    }
}
