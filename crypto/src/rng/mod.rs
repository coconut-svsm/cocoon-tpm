// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Cryptographic random number generator interface traits and implementations.

use crate::utils_common::{
    alloc::try_alloc_zeroizing_vec,
    io_slices::{self, IoSlicesIterCommon as _},
};
/// Traits related to and implementation of cryptographic random number
/// generators.
use crate::{
    io_slices::{CryptoPeekableIoSlicesIter, CryptoWalkableIoSlicesMutIter, EmptyCryptoIoSlices},
    CryptoError,
};

use core::convert;

/// Error type returned by [`RngCore::generate()`](RngCore::generate).
#[derive(Debug)]
pub enum RngGenerateError {
    /// A reseed is required before producing more random data.
    ReseedRequired,
    /// Some crypto primitive failed its operation.
    CryptoError(CryptoError),
}

impl convert::From<RngGenerateError> for CryptoError {
    fn from(value: RngGenerateError) -> Self {
        match value {
            RngGenerateError::ReseedRequired => CryptoError::RngFailure,
            RngGenerateError::CryptoError(e) => e,
        }
    }
}

/// Main functionality implemented by cryptographic random number generators.
pub trait RngCore {
    /// Generate random bytes.
    ///
    /// # Arguments:
    ///
    /// * `output` - Destination buffers to fill with random data.
    /// * `additional_input` - Optional additional input to consider from the
    ///   random number generation process. How it's used depend on the actual
    ///   implementation, the most common cases being that the additional data
    ///   is either not considered at all or that it's getting mixed into the
    ///   random number generators internal state in a non-destructive manner
    ///   before generating random output.
    fn generate<'a, 'b, OI: CryptoWalkableIoSlicesMutIter<'a>, AII: CryptoPeekableIoSlicesIter<'b>>(
        &mut self,
        output: OI,
        additional_input: Option<AII>,
    ) -> Result<(), RngGenerateError>;
}

/// Cryptographic random number generator interface qualifying a a
/// `dyn`-compatible trait.
///
/// Don't use it directly, see [`rng_dyn_dispatch_generate()`].
pub trait RngCoreDispatchable {
    // The output argument should get consumed as the iterator gets exhausted, but
    // support for unsized fn params is unstable. For the time being, make the
    // member function internal and provide the rng_dyn_dispatch_generate()
    // helper.
    /// Generate random bytes.
    ///
    /// # Arguments:
    ///
    /// * `output` - Destination buffers to fill with random data.
    /// * `additional_input` - Optional additional input to consider from the
    ///   random number generation process.
    fn _generate<'a, 'b>(
        &mut self,
        output: &'a mut dyn CryptoWalkableIoSlicesMutIter<'b>,
        additional_input: Option<&[Option<&[u8]>]>,
    ) -> Result<(), RngGenerateError>;
}

impl<R: RngCore> RngCoreDispatchable for R {
    fn _generate<'a, 'b>(
        &mut self,
        output: &'a mut dyn CryptoWalkableIoSlicesMutIter<'b>,
        additional_input: Option<&[Option<&[u8]>]>,
    ) -> Result<(), RngGenerateError> {
        self.generate(
            output,
            additional_input.map(|additional_input| {
                io_slices::GenericIoSlicesIter::new(additional_input.iter().filter_map(|b| b.map(Ok)), None)
                    .map_infallible_err()
            }),
        )
    }
}

/// Generate random bytes from a [random number generator `dyn`
/// object](RngCoreDispatchable).
///
/// # Arguments:
///
/// * `output` - Destination buffers to fill with random data.
/// * `additional_input` - Optional additional input to consider from the random
///   number generation process. How it's used depend on the actual
///   implementation, the most common cases being that the additional data is
///   either not considered at all or that it's getting mixed into the random
///   number generators internal state in a non-destructive manner before
///   generating random output.
pub fn rng_dyn_dispatch_generate<'a, OI: CryptoWalkableIoSlicesMutIter<'a>>(
    rng: &mut dyn RngCoreDispatchable,
    mut output: OI,
    additional_input: Option<&[Option<&[u8]>]>,
) -> Result<(), RngGenerateError> {
    RngCoreDispatchable::_generate(rng, &mut output, additional_input)
}

/// Error type returned by
/// [`ReseedableRngCore::reseed()`](ReseedableRngCore::reseed).
#[derive(Debug)]
pub enum RngReseedError {
    CryptoError(CryptoError),
}

/// Error type returned by
/// [`ReseedableRngCore::reseed_from_parent()`](ReseedableRngCore::reseed_from_parent).
#[derive(Debug)]
pub enum RngReseedFromParentError {
    ParentGenerateFailure(RngGenerateError),
    CryptoError(CryptoError),
}

/// Reseedable random number generator.
pub trait ReseedableRngCore: RngCore + Sized {
    /// Minimum entropy data length in units of Bytes required for a reseed.
    fn min_seed_entropy_len(&self) -> usize;

    /// Reseed the random number generator.
    ///
    /// # Arguments:
    ///
    /// * `entropy` - The entropy to reseed the random number generator from.
    /// * `additional_data` - Optional additional data to consider for the
    ///   reseed process. How it's used depend on the actual implementation, the
    ///   most common cases being that the additional data is either not
    ///   considered at all or that it's getting mixed into the random number
    ///   generators internal state alongside the `entropy`.
    fn reseed<'a, AII: CryptoPeekableIoSlicesIter<'a>>(
        &mut self,
        entropy: &[u8],
        additional_input: Option<AII>,
    ) -> Result<(), RngReseedError>;

    /// Reseed the random number generator from the random output of another
    /// one.
    ///
    /// # Arguments:
    ///
    /// * `parent` - The random number generator to obtain fresh entropy for the
    ///   reseed from.
    /// * `additional_data` - Optional additional data to consider for the
    ///   reseed process. How it's used depend on the actual implementation, the
    ///   most common cases being that the additional data is either not
    ///   considered at all or that it's getting mixed into the random number
    ///   generators internal state alongside the `entropy`.
    fn reseed_from_parent<'a, P: RngCore, AII: CryptoPeekableIoSlicesIter<'a>>(
        &mut self,
        parent: &mut P,
        additional_input: Option<AII>,
    ) -> Result<(), RngReseedFromParentError> {
        let entropy_len = self.min_seed_entropy_len();
        let mut entropy = try_alloc_zeroizing_vec::<u8>(entropy_len)
            .map_err(|e| RngReseedFromParentError::CryptoError(CryptoError::from(e)))?;
        parent
            .generate::<_, EmptyCryptoIoSlices>(
                &mut io_slices::SingletonIoSliceMut::new(entropy.as_mut_slice()).map_infallible_err(),
                None,
            )
            .map_err(RngReseedFromParentError::ParentGenerateFailure)?;

        self.reseed(entropy.as_slice(), additional_input).map_err(|e| match e {
            RngReseedError::CryptoError(e) => RngReseedFromParentError::CryptoError(e),
        })?;

        Ok(())
    }
}
