// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Chained [Random number generator](RngCore) implementation.

use super::{ReseedableRngCore, RngCore, RngGenerateError, RngReseedFromParentError};
use crate::{
    CryptoError,
    io_slices::{CryptoPeekableIoSlicesIter, CryptoWalkableIoSlicesMutIter, EmptyCryptoIoSlices},
};

/// [Random number generator](RngCore) adaptor automatically reseeding a child
/// from a parent.
///
/// Serve all [generate](RngCore::generate) requests from the child, reseed that
/// with randomness obtained from the parent whenever it reports a
/// [`ReseedRequired`](RngGenerateError::ReseedRequired) condition.
///
/// For possible constraints, refer to NIST NIST SP 800-90C, which, at the time
/// of writing, is in draft state.
pub struct ChainedRng<P: RngCore, C: RngCore + ReseedableRngCore> {
    parent: P,
    child: C,
}

impl<P: RngCore, C: RngCore + ReseedableRngCore> ChainedRng<P, C> {
    /// Instantiate a `ChainedRng`.
    ///
    /// # Arguments:
    /// * `parent` - The parent [Random number generator](RngCore) to obtain
    ///   randomness from for reseeding the `child`.
    /// * `child` - The child to serve [generate](RngCore::generate) from.
    pub fn chain(parent: P, child: C) -> Self {
        Self { parent, child }
    }
}

impl<P: RngCore, C: RngCore + ReseedableRngCore> RngCore for ChainedRng<P, C> {
    fn generate<'a, 'b, OI: CryptoWalkableIoSlicesMutIter<'a>, AII: CryptoPeekableIoSlicesIter<'b>>(
        &mut self,
        mut output: OI,
        mut additional_input: Option<AII>,
    ) -> Result<(), RngGenerateError> {
        while !output.is_empty().map_err(RngGenerateError::CryptoError)? {
            match self.child.generate(
                output.as_ref(),
                additional_input
                    .as_mut()
                    .map(|additional_input| additional_input.as_ref()),
            ) {
                Ok(()) => (),
                Err(RngGenerateError::ReseedRequired) => {
                    self.child
                        .reseed_from_parent::<_, EmptyCryptoIoSlices>(&mut self.parent, None)
                        .map_err(|e| match e {
                            RngReseedFromParentError::ParentGenerateFailure(e) => {
                                RngGenerateError::CryptoError(CryptoError::from(e))
                            }
                            RngReseedFromParentError::CryptoError(e) => RngGenerateError::CryptoError(e),
                        })?;
                }
                Err(e) => {
                    return Err(e);
                }
            };
        }
        Ok(())
    }
}
