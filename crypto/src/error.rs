// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Crypto related error type definitions.

use crate::utils_common;
use core::convert;

const CRYPTO_ERROR_CODE_MEMORY_ALLOCATION_FAILURE: isize = 1;
const CRYPTO_ERROR_CODE_INTERNAL: isize = 2;
const CRYPTO_ERROR_CODE_BUFFER_STATE_INDETERMINATE: isize = 3;
const CRYPTO_ERROR_CODE_RNG_FAILURE: isize = 4;
const CRYPTO_ERROR_CODE_INSUFFICIENT_SEED_LENGTH: isize = 5;
const CRYPTO_ERROR_CODE_RANDOM_SAMPLING_RETRIES_EXCEEDED: isize = 6;
const CRYPTO_ERROR_CODE_REQUEST_TOO_BIG: isize = 7;
const CRYPTO_ERROR_CODE_NO_KEY: isize = 8;
const CRYPTO_ERROR_CODE_KEY_SIZE: isize = 9;
const CRYPTO_ERROR_CODE_KEY_BINDING: isize = 10;
const CRYPTO_ERROR_CODE_SIGNATURE_VERIFICATION_FAILURE: isize = 11;
const CRYPTO_ERROR_CODE_UNSUPPORTED_SECURITY_STRENGTH: isize = 12;
const CRYPTO_ERROR_CODE_UNSUPPORTED_PARAMS: isize = 13;
const CRYPTO_ERROR_CODE_UNSPECIFIED_FAILURE: isize = 14;
const CRYPTO_ERROR_CODE_INVALID_PARAMS: isize = 15;
const CRYPTO_ERROR_CODE_INVALID_IV: isize = 16;
const CRYPTO_ERROR_CODE_INVALID_MESSAGE_LENGTH: isize = 17;
const CRYPTO_ERROR_CODE_INVALID_PADDING: isize = 18;
const CRYPTO_ERROR_CODE_INVALID_POINT: isize = 19;
const CRYPTO_ERROR_CODE_INVALID_RESULT: isize = 20;

/// Common error returned by cryptographic primitives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// Memory allocation failure.
    MemoryAllocationFailure = CRYPTO_ERROR_CODE_MEMORY_ALLOCATION_FAILURE,
    /// Internal logic error.
    Internal = CRYPTO_ERROR_CODE_INTERNAL,
    /// A source or destination buffer was found in indeterminate state.
    ///
    /// To be returned from operand [IO slice
    /// iterators](utils_common::io_slices) when encountering a buffer in
    /// indeterminate state. Indicates an internal logic error.
    BufferStateIndeterminate = CRYPTO_ERROR_CODE_BUFFER_STATE_INDETERMINATE,
    /// Unspecified random number generator failure condition.
    RngFailure = CRYPTO_ERROR_CODE_RNG_FAILURE,
    /// Attempt to seed a random number generator with a seed of insufficient
    /// length.
    InsufficientSeedLength = CRYPTO_ERROR_CODE_INSUFFICIENT_SEED_LENGTH,
    /// Some probabilistic sampling algorithm exceeded the maximum number of
    /// retries.
    RandomSamplingRetriesExceeded = CRYPTO_ERROR_CODE_RANDOM_SAMPLING_RETRIES_EXCEEDED,
    /// Request size is not supported.
    RequestTooBig = CRYPTO_ERROR_CODE_REQUEST_TOO_BIG,
    /// Private key required for some operation is missing.
    NoKey = CRYPTO_ERROR_CODE_NO_KEY,
    /// Key size is not supported by an algorithm.
    KeySize = CRYPTO_ERROR_CODE_KEY_SIZE,
    /// Inconsistency between parts of a key.
    ///
    /// This most commonly indicates a mismatch between the public and private
    /// parts of an asymmetric key pair, but could also get returned for
    /// impossible private keys not in the expected domain.
    KeyBinding = CRYPTO_ERROR_CODE_KEY_BINDING,
    /// Signature verification failure.
    SignatureVerificationFailure = CRYPTO_ERROR_CODE_SIGNATURE_VERIFICATION_FAILURE,
    /// Requested security strength is not supported.
    UnsupportedSecurityStrength = CRYPTO_ERROR_CODE_UNSUPPORTED_SECURITY_STRENGTH,
    /// Request parameters not supported.
    UnsupportedParams = CRYPTO_ERROR_CODE_UNSUPPORTED_PARAMS,

    /// Some unspecified failure.
    UnspecifiedFailure = CRYPTO_ERROR_CODE_UNSPECIFIED_FAILURE,

    /// Invalid parameters.
    InvalidParams = CRYPTO_ERROR_CODE_INVALID_PARAMS,

    /// Invalid block cipher mode IV length.
    InvalidIV = CRYPTO_ERROR_CODE_INVALID_IV,
    /// Invalid message length.
    InvalidMessageLength = CRYPTO_ERROR_CODE_INVALID_MESSAGE_LENGTH,
    /// Invalid padding in message.
    InvalidPadding = CRYPTO_ERROR_CODE_INVALID_PADDING,
    /// A point is not in the expected domain.
    InvalidPoint = CRYPTO_ERROR_CODE_INVALID_POINT,
    /// A computation resulted in an invalid result.
    InvalidResult = CRYPTO_ERROR_CODE_INVALID_RESULT,
}

impl CryptoError {
    const fn from_int(value: isize) -> Self {
        match value {
            CRYPTO_ERROR_CODE_MEMORY_ALLOCATION_FAILURE => Self::MemoryAllocationFailure,
            CRYPTO_ERROR_CODE_INTERNAL => Self::Internal,
            CRYPTO_ERROR_CODE_BUFFER_STATE_INDETERMINATE => Self::BufferStateIndeterminate,
            CRYPTO_ERROR_CODE_RNG_FAILURE => Self::RngFailure,
            CRYPTO_ERROR_CODE_INSUFFICIENT_SEED_LENGTH => Self::InsufficientSeedLength,
            CRYPTO_ERROR_CODE_RANDOM_SAMPLING_RETRIES_EXCEEDED => Self::RandomSamplingRetriesExceeded,
            CRYPTO_ERROR_CODE_REQUEST_TOO_BIG => Self::RequestTooBig,
            CRYPTO_ERROR_CODE_NO_KEY => Self::NoKey,
            CRYPTO_ERROR_CODE_KEY_SIZE => Self::KeySize,
            CRYPTO_ERROR_CODE_KEY_BINDING => Self::KeyBinding,
            CRYPTO_ERROR_CODE_SIGNATURE_VERIFICATION_FAILURE => Self::SignatureVerificationFailure,
            CRYPTO_ERROR_CODE_UNSUPPORTED_SECURITY_STRENGTH => Self::UnsupportedSecurityStrength,
            CRYPTO_ERROR_CODE_UNSUPPORTED_PARAMS => Self::UnsupportedParams,
            CRYPTO_ERROR_CODE_UNSPECIFIED_FAILURE => Self::UnspecifiedFailure,
            CRYPTO_ERROR_CODE_INVALID_PARAMS => Self::InvalidParams,
            CRYPTO_ERROR_CODE_INVALID_IV => Self::InvalidIV,
            CRYPTO_ERROR_CODE_INVALID_MESSAGE_LENGTH => Self::InvalidMessageLength,
            CRYPTO_ERROR_CODE_INVALID_PADDING => Self::InvalidPadding,
            CRYPTO_ERROR_CODE_INVALID_POINT => Self::InvalidPoint,
            CRYPTO_ERROR_CODE_INVALID_RESULT => Self::InvalidResult,
            _ => {
                debug_assert!(false);
                Self::Internal
            }
        }
    }

    pub fn anonymize_any_sensitive(self, anonymized_value: Self) -> Self {
        const UNFILTERED_SET: [CryptoError; 13] = [
            CryptoError::MemoryAllocationFailure,
            CryptoError::BufferStateIndeterminate,
            CryptoError::RngFailure,
            CryptoError::InsufficientSeedLength,
            CryptoError::RandomSamplingRetriesExceeded,
            CryptoError::RequestTooBig,
            CryptoError::NoKey,
            CryptoError::KeySize,
            CryptoError::KeyBinding,
            CryptoError::SignatureVerificationFailure,
            CryptoError::UnsupportedSecurityStrength,
            CryptoError::UnsupportedParams,
            CryptoError::UnspecifiedFailure,
        ];
        let value = self as cmpa::LimbType;
        let mut is_unfiltered = cmpa::LimbChoice::new(0);
        for unfiltered in UNFILTERED_SET {
            is_unfiltered |= cmpa::ct_eq_l_l(value, unfiltered as cmpa::LimbType);
        }
        Self::from_int(is_unfiltered.select(anonymized_value as cmpa::LimbType, value) as isize)
    }

    pub fn map(self, from_code: Self, to_code: Self) -> Self {
        Self::from_int(
            cmpa::ct_eq_l_l(self as cmpa::LimbType, from_code as cmpa::LimbType)
                .select(self as cmpa::LimbType, to_code as cmpa::LimbType) as isize,
        )
    }
}

impl convert::From<convert::Infallible> for CryptoError {
    fn from(value: convert::Infallible) -> Self {
        match value {}
    }
}

impl convert::From<utils_common::alloc::TryNewError> for CryptoError {
    fn from(value: utils_common::alloc::TryNewError) -> Self {
        match value {
            utils_common::alloc::TryNewError::MemoryAllocationFailure => CryptoError::MemoryAllocationFailure,
        }
    }
}

impl convert::From<utils_common::alloc::TryNewWithError<CryptoError>> for CryptoError {
    fn from(value: utils_common::alloc::TryNewWithError<CryptoError>) -> Self {
        match value {
            utils_common::alloc::TryNewWithError::TryNew(e) => match e {
                utils_common::alloc::TryNewError::MemoryAllocationFailure => CryptoError::MemoryAllocationFailure,
            },
            utils_common::alloc::TryNewWithError::With(e) => e,
        }
    }
}

impl convert::From<utils_common::alloc::TryNewWithError<convert::Infallible>> for CryptoError {
    fn from(value: utils_common::alloc::TryNewWithError<convert::Infallible>) -> Self {
        match value {
            utils_common::alloc::TryNewWithError::TryNew(e) => match e {
                utils_common::alloc::TryNewError::MemoryAllocationFailure => CryptoError::MemoryAllocationFailure,
            },
            utils_common::alloc::TryNewWithError::With(e) => match e {},
        }
    }
}

impl convert::From<utils_common::fixed_vec::FixedVecMemoryAllocationFailure> for CryptoError {
    fn from(_value: utils_common::fixed_vec::FixedVecMemoryAllocationFailure) -> Self {
        Self::MemoryAllocationFailure
    }
}

impl convert::From<utils_common::fixed_vec::FixedVecNewFromFnError<CryptoError>> for CryptoError {
    fn from(value: utils_common::fixed_vec::FixedVecNewFromFnError<CryptoError>) -> Self {
        match value {
            utils_common::fixed_vec::FixedVecNewFromFnError::MemoryAllocationFailure => Self::MemoryAllocationFailure,
            utils_common::fixed_vec::FixedVecNewFromFnError::FnError(e) => e,
        }
    }
}

impl convert::From<utils_common::fixed_vec::FixedVecNewFromFnError<convert::Infallible>> for CryptoError {
    fn from(value: utils_common::fixed_vec::FixedVecNewFromFnError<convert::Infallible>) -> Self {
        Self::from(utils_common::fixed_vec::FixedVecMemoryAllocationFailure::from(value))
    }
}

impl<BackendIteratorError> convert::From<utils_common::io_slices::IoSlicesIterError<BackendIteratorError>>
    for CryptoError
where
    CryptoError: convert::From<BackendIteratorError>,
{
    fn from(value: utils_common::io_slices::IoSlicesIterError<BackendIteratorError>) -> Self {
        match value {
            utils_common::io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                utils_common::io_slices::IoSlicesError::BuffersExhausted => CryptoError::Internal,
            },
            utils_common::io_slices::IoSlicesIterError::BackendIteratorError(e) => Self::from(e),
        }
    }
}
