// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Red Hat
// Author: Oliver Steffen <osteffen@redhat.com>

use cocoon_tpm_ossl_bare_sys as ossl_bare_sys;

use crate::error::CryptoError;

use core::{convert, ffi};

/// Extract the library code from a packed OpenSSL error.
fn err_get_lib(packed_error: ffi::c_ulong) -> ffi::c_int {
    unsafe { ossl_bare_sys::ossl_shim_ERR_GET_LIB(packed_error) }
}

/// Extract the reason code from a packed OpenSSL error.
fn err_get_reason(packed_error: ffi::c_ulong) -> ffi::c_int {
    unsafe { ossl_bare_sys::ossl_shim_ERR_GET_REASON(packed_error) }
}

pub struct OsslError {
    pub packed_error: ffi::c_ulong,
}

impl OsslError {
    pub fn is_code(&self, expected_lib: ffi::c_int, expected_reason: ffi::c_int) -> bool {
        let unpacked_lib = err_get_lib(self.packed_error);
        let unpacked_reason = err_get_reason(self.packed_error);
        unpacked_lib == expected_lib && unpacked_reason == expected_reason
    }
}

pub fn ossl_get_raw_error() -> Option<OsslError> {
    let packed_error = unsafe { ossl_bare_sys::ERR_get_error() };
    if packed_error != 0 {
        // Clear the rest from the queue.
        unsafe { ossl_bare_sys::ERR_clear_error() };
        Some(OsslError { packed_error })
    } else {
        None
    }
}

pub fn ossl_get_error() -> CryptoError {
    ossl_get_raw_error()
        .map(CryptoError::from)
        .unwrap_or(CryptoError::Internal)
}

impl convert::From<OsslError> for CryptoError {
    fn from(value: OsslError) -> Self {
        let reason = err_get_reason(value.packed_error);

        // Global reason codes.
        if reason == ossl_bare_sys::ERR_R_FATAL as ffi::c_int {
            return CryptoError::Internal;
        }
        if reason == ossl_bare_sys::ERR_R_MALLOC_FAILURE as ffi::c_int {
            return CryptoError::MemoryAllocationFailure;
        }
        if reason == ossl_bare_sys::ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED as ffi::c_int {
            return CryptoError::Internal;
        }
        if reason == ossl_bare_sys::ERR_R_PASSED_NULL_PARAMETER as ffi::c_int {
            return CryptoError::Internal;
        }
        if reason == ossl_bare_sys::ERR_R_INTERNAL_ERROR as ffi::c_int {
            return CryptoError::Internal;
        }

        let lib = err_get_lib(value.packed_error);
        match lib {
            x if x == ossl_bare_sys::ERR_LIB_NONE as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_SYS as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_BN as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_RSA as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_DH as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_EVP as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_BUF as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_OBJ as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_PEM as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_DSA as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_X509 as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_ASN1 as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_CONF as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_CRYPTO as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_EC as ffi::c_int => match reason {
                x if x == ossl_bare_sys::EC_R_BUFFER_TOO_SMALL as ffi::c_int => CryptoError::Internal,
                x if x == ossl_bare_sys::EC_R_COORDINATES_OUT_OF_RANGE as ffi::c_int => CryptoError::InvalidPoint,
                x if x == ossl_bare_sys::EC_R_EC_GROUP_NEW_BY_NAME_FAILURE as ffi::c_int => {
                    CryptoError::UnspecifiedFailure
                }
                x if x == ossl_bare_sys::EC_R_INCOMPATIBLE_OBJECTS as ffi::c_int => CryptoError::Internal,
                x if x == ossl_bare_sys::EC_R_INVALID_COMPRESSED_POINT as ffi::c_int => CryptoError::UnspecifiedFailure,
                x if x == ossl_bare_sys::EC_R_INVALID_COMPRESSION_BIT as ffi::c_int => CryptoError::UnspecifiedFailure,
                x if x == ossl_bare_sys::EC_R_INVALID_ENCODING as ffi::c_int => CryptoError::UnspecifiedFailure,
                x if x == ossl_bare_sys::EC_R_INVALID_FIELD as ffi::c_int => CryptoError::UnspecifiedFailure,
                x if x == ossl_bare_sys::EC_R_INVALID_FORM as ffi::c_int => CryptoError::UnspecifiedFailure,
                x if x == ossl_bare_sys::EC_R_INVALID_GROUP_ORDER as ffi::c_int => CryptoError::UnspecifiedFailure,
                x if x == ossl_bare_sys::EC_R_INVALID_PRIVATE_KEY as ffi::c_int => CryptoError::UnspecifiedFailure,
                x if x == ossl_bare_sys::EC_R_MISSING_PARAMETERS as ffi::c_int => CryptoError::UnspecifiedFailure,
                x if x == ossl_bare_sys::EC_R_MISSING_PRIVATE_KEY as ffi::c_int => CryptoError::KeyBinding,
                x if x == ossl_bare_sys::EC_R_NOT_INITIALIZED as ffi::c_int => CryptoError::Internal,
                x if x == ossl_bare_sys::EC_R_POINT_AT_INFINITY as ffi::c_int => CryptoError::Internal,
                x if x == ossl_bare_sys::EC_R_POINT_IS_NOT_ON_CURVE as ffi::c_int => CryptoError::InvalidPoint,
                x if x == ossl_bare_sys::EC_R_SLOT_FULL as ffi::c_int => CryptoError::UnspecifiedFailure,
                x if x == ossl_bare_sys::EC_R_UNDEFINED_GENERATOR as ffi::c_int => CryptoError::UnspecifiedFailure,
                x if x == ossl_bare_sys::EC_R_UNKNOWN_GROUP as ffi::c_int => CryptoError::UnspecifiedFailure,
                x if x == ossl_bare_sys::EC_R_UNKNOWN_ORDER as ffi::c_int => CryptoError::UnspecifiedFailure,
                x if x == ossl_bare_sys::EC_R_WRONG_ORDER as ffi::c_int => CryptoError::UnspecifiedFailure,
                x if x == ossl_bare_sys::EC_R_BIGNUM_OUT_OF_RANGE as ffi::c_int => CryptoError::UnspecifiedFailure,
                x if x == ossl_bare_sys::EC_R_WRONG_CURVE_PARAMETERS as ffi::c_int => CryptoError::UnspecifiedFailure,
                x if x == ossl_bare_sys::EC_R_DECODE_ERROR as ffi::c_int => CryptoError::UnspecifiedFailure,
                x if x == ossl_bare_sys::EC_R_INVALID_COFACTOR as ffi::c_int => CryptoError::UnspecifiedFailure,
                _ => CryptoError::UnspecifiedFailure,
            },
            x if x == ossl_bare_sys::ERR_LIB_SSL as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_BIO as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_PKCS7 as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_X509V3 as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_RAND as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_ENGINE as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_OCSP as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_UI as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_COMP as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_ECDSA as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_ECDH as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_HMAC as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_CMS as ffi::c_int => CryptoError::UnspecifiedFailure,
            x if x == ossl_bare_sys::ERR_LIB_USER as ffi::c_int => CryptoError::UnspecifiedFailure,
            _ => CryptoError::Internal,
        }
    }
}
