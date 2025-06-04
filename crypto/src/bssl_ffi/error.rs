// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use cocoon_tpm_bssl_bare_sys as bssl_bare_sys;

use crate::error::CryptoError;

use core::{convert, ffi};

/// Reimplementation of BoringSSL's `ERR_GET_LIB()`.
///
/// BoringSSL's ERR_GET_LIB() is inlined and thus, inaccessible through bindgen if static
/// functions haven't been wrapped up.
fn err_get_lib(packed_error: u32) -> ffi::c_int {
    ((packed_error >> 24) & 0xff) as ffi::c_int
}

/// Reimplementation of BoringSSL's `ERR_GET_REASON()`.
///
/// BoringSSL's ERR_GET_REASON() is inlined and thus, inaccessible through bindgen if static
/// functions haven't been wrapped up.
fn err_get_reason(packed_error: u32) -> ffi::c_int {
    (packed_error & 0xfffu32) as ffi::c_int
}

pub struct BSSLError {
    pub packed_error: u32,
}

impl BSSLError {
    pub fn is_code(&self, expected_lib: ffi::c_uint, expected_reason: ffi::c_int) -> bool {
        let unpacked_lib = err_get_lib(self.packed_error);
        let unpacked_reason = err_get_reason(self.packed_error);
        unpacked_lib as ffi::c_uint == expected_lib && unpacked_reason == expected_reason
    }
}

pub fn bssl_get_raw_error() -> Option<BSSLError> {
    let packed_error = unsafe { bssl_bare_sys::ERR_get_error() };
    if packed_error != 0 {
        // Clear the rest from the queue.
        unsafe { bssl_bare_sys::ERR_clear_error() };
        Some(BSSLError { packed_error })
    } else {
        None
    }
}

pub fn bssl_get_error() -> CryptoError {
    bssl_get_raw_error()
        .map(CryptoError::from)
        .unwrap_or(CryptoError::Internal)
}

impl convert::From<BSSLError> for CryptoError {
    fn from(value: BSSLError) -> Self {
        let reason = err_get_reason(value.packed_error);

        // "The following values are global reason codes. They may occur in any
        // library."
        match reason {
            bssl_bare_sys::ERR_R_FATAL => return CryptoError::Internal,
            bssl_bare_sys::ERR_R_MALLOC_FAILURE => return CryptoError::MemoryAllocationFailure,
            bssl_bare_sys::ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED => return CryptoError::Internal,
            bssl_bare_sys::ERR_R_PASSED_NULL_PARAMETER => return CryptoError::Internal,
            bssl_bare_sys::ERR_R_INTERNAL_ERROR => return CryptoError::Internal,
            bssl_bare_sys::ERR_R_OVERFLOW => return CryptoError::Internal,
            _ => (),
        }

        let lib = err_get_lib(value.packed_error);
        match lib as ffi::c_uint {
            bssl_bare_sys::ERR_LIB_NONE => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_SYS => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_BN => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_RSA => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_DH => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_EVP => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_BUF => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_OBJ => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_PEM => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_DSA => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_X509 => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_ASN1 => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_CONF => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_CRYPTO => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_EC => match reason {
                bssl_bare_sys::EC_R_BUFFER_TOO_SMALL => CryptoError::Internal,
                bssl_bare_sys::EC_R_COORDINATES_OUT_OF_RANGE => CryptoError::InvalidPoint,
                bssl_bare_sys::EC_R_D2I_ECPKPARAMETERS_FAILURE => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_EC_GROUP_NEW_BY_NAME_FAILURE => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_GROUP2PKPARAMETERS_FAILURE => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_I2D_ECPKPARAMETERS_FAILURE => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_INCOMPATIBLE_OBJECTS => CryptoError::Internal,
                bssl_bare_sys::EC_R_INVALID_COMPRESSED_POINT => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_INVALID_COMPRESSION_BIT => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_INVALID_ENCODING => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_INVALID_FIELD => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_INVALID_FORM => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_INVALID_GROUP_ORDER => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_INVALID_PRIVATE_KEY => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_MISSING_PARAMETERS => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_MISSING_PRIVATE_KEY => CryptoError::KeyBinding,
                bssl_bare_sys::EC_R_NON_NAMED_CURVE => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_NOT_INITIALIZED => CryptoError::Internal,
                bssl_bare_sys::EC_R_PKPARAMETERS2GROUP_FAILURE => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_POINT_AT_INFINITY => CryptoError::Internal,
                bssl_bare_sys::EC_R_POINT_IS_NOT_ON_CURVE => CryptoError::InvalidPoint,
                bssl_bare_sys::EC_R_SLOT_FULL => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_UNDEFINED_GENERATOR => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_UNKNOWN_GROUP => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_UNKNOWN_ORDER => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_WRONG_ORDER => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_BIGNUM_OUT_OF_RANGE => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_WRONG_CURVE_PARAMETERS => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_DECODE_ERROR => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_ENCODE_ERROR => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_GROUP_MISMATCH => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_INVALID_COFACTOR => CryptoError::UnspecifiedFailure,
                bssl_bare_sys::EC_R_PUBLIC_KEY_VALIDATION_FAILED => CryptoError::KeyBinding,
                _ => CryptoError::UnspecifiedFailure,
            },
            bssl_bare_sys::ERR_LIB_SSL => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_BIO => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_PKCS7 => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_PKCS8 => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_X509V3 => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_RAND => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_ENGINE => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_OCSP => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_UI => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_COMP => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_ECDSA => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_ECDH => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_HMAC => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_DIGEST => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_CIPHER => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_HKDF => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_TRUST_TOKEN => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_CMS => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_USER => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_NUM_LIBS => CryptoError::UnspecifiedFailure,
            _ => CryptoError::Internal,
        }
    }
}
