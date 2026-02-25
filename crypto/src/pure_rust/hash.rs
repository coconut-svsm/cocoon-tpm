// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Pure Rust, RustCrypto based backend for hash algorithms.

// Lifetimes are not obvious at first sight here, make the explicit.
#![allow(clippy::needless_lifetimes)]

extern crate alloc;
use alloc::boxed::Box;

use crate::{CryptoError, io_slices::CryptoIoSlicesIter};
use crate::{
    tpm2_interface,
    utils_common::{
        alloc::{box_try_new_with, try_alloc_zeroizing_vec},
        zeroize,
    },
};
use core::{convert, mem, ops::Deref as _};

use crypto_common::{self, KeyInit as _};
use digest::{self, Digest as _};
use hmac::{self, Hmac};

/// A hash instance.
pub struct HashInstance {
    state: HashInstanceState,
}

impl HashInstance {
    /// Create a new hash instance for the specified algorithm.
    ///
    /// # Arguments:
    ///
    /// * `alg` - The hash algorithm to create an instance for.
    pub fn new(alg: tpm2_interface::TpmiAlgHash) -> Result<Self, convert::Infallible> {
        Ok(Self {
            state: HashInstanceState::new(alg),
        })
    }

    pub fn try_clone(&self) -> Result<Self, convert::Infallible> {
        Ok(Self {
            state: self.state.clone(),
        })
    }

    /// Append to the digested data.
    ///
    /// # Arguments:
    ///
    /// * `data` - The data to digest.
    pub fn update<'a, DI: CryptoIoSlicesIter<'a>>(&mut self, mut data: DI) -> Result<(), CryptoError> {
        self.state.update(&mut data)
    }

    /// Produce a digest into a provided buffer and reset the hash instance.
    ///
    /// Produce a digest into `digest` and reset the hash instance to the state
    /// it would have had right after [`Self::new()`](Self::new()).
    ///
    /// # Arguments:
    ///
    /// * `digest` - Destination to write the produced digest to.
    pub fn finalize_into_reset(&mut self, digest: &mut [u8]) -> Result<(), convert::Infallible> {
        self.state.finalize_into_reset(digest);
        Ok(())
    }

    /// Produce the final digest into a provided buffer..
    ///
    /// # Arguments:
    ///
    /// * `digest` - Destination to write the produced digest to.
    pub fn finalize_into(self, digest: &mut [u8]) -> Result<(), convert::Infallible> {
        self.state.finalize_into(digest);
        Ok(())
    }

    /// Produce a digest and reset the hash instance.
    ///
    /// Allocate a buffer suitable for the instance's digest length,  produce a
    /// digest into it and reset the hash instance to the state it
    /// would have had right after [`Self::new()`](Self::new()).
    pub fn finalize_reset(&mut self) -> Result<tpm2_interface::TpmtHa<'static>, CryptoError> {
        self.state.finalize_reset()
    }

    /// Produce the final digest.
    ///
    /// Allocate a buffer suitable for the instance's digest length and produce
    /// the final digest into it.
    pub fn finalize(self) -> Result<tpm2_interface::TpmtHa<'static>, CryptoError> {
        self.state.finalize()
    }

    /// Determine the instance's associated hash algorithm's digest length.
    pub fn digest_len(&self) -> usize {
        self.state.digest_len()
    }
}

#[derive(Clone)]
enum HashInstanceState {
    #[cfg(feature = "sha1")]
    Sha1(sha1::Sha1),
    #[cfg(feature = "sha256")]
    Sha256(sha2::Sha256),
    #[cfg(feature = "sha384")]
    Sha384(sha2::Sha384),
    #[cfg(feature = "sha512")]
    Sha512(sha2::Sha512),
    #[cfg(feature = "sha3_256")]
    Sha3_256(sha3::Sha3_256),
    #[cfg(feature = "sha3_384")]
    Sha3_384(sha3::Sha3_384),
    #[cfg(feature = "sha3_512")]
    Sha3_512(sha3::Sha3_512),
    #[cfg(feature = "sm3_256")]
    Sm3_256(sm3::Sm3),
}

impl HashInstanceState {
    fn new(alg: tpm2_interface::TpmiAlgHash) -> Self {
        match alg {
            #[cfg(feature = "sha1")]
            tpm2_interface::TpmiAlgHash::Sha1 => Self::Sha1(sha1::Sha1::new()),
            #[cfg(feature = "sha256")]
            tpm2_interface::TpmiAlgHash::Sha256 => Self::Sha256(sha2::Sha256::new()),
            #[cfg(feature = "sha384")]
            tpm2_interface::TpmiAlgHash::Sha384 => Self::Sha384(sha2::Sha384::new()),
            #[cfg(feature = "sha512")]
            tpm2_interface::TpmiAlgHash::Sha512 => Self::Sha512(sha2::Sha512::new()),
            #[cfg(feature = "sm3_256")]
            tpm2_interface::TpmiAlgHash::Sm3_256 => Self::Sm3_256(sm3::Sm3::new()),
            #[cfg(feature = "sha3_256")]
            tpm2_interface::TpmiAlgHash::Sha3_256 => Self::Sha3_256(sha3::Sha3_256::new()),
            #[cfg(feature = "sha3_384")]
            tpm2_interface::TpmiAlgHash::Sha3_384 => Self::Sha3_384(sha3::Sha3_384::new()),
            #[cfg(feature = "sha3_512")]
            tpm2_interface::TpmiAlgHash::Sha3_512 => Self::Sha3_512(sha3::Sha3_512::new()),
        }
    }

    fn update<'a>(&mut self, data: &mut dyn CryptoIoSlicesIter<'a>) -> Result<(), CryptoError> {
        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1(instance) => {
                while let Some(data) = data.next_slice(None)? {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sha256")]
            Self::Sha256(instance) => {
                while let Some(data) = data.next_slice(None)? {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sha384")]
            Self::Sha384(instance) => {
                while let Some(data) = data.next_slice(None)? {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sha512")]
            Self::Sha512(instance) => {
                while let Some(data) = data.next_slice(None)? {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256(instance) => {
                while let Some(data) = data.next_slice(None)? {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384(instance) => {
                while let Some(data) = data.next_slice(None)? {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512(instance) => {
                while let Some(data) = data.next_slice(None)? {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256(instance) => {
                while let Some(data) = data.next_slice(None)? {
                    digest::Update::update(instance, data);
                }
            }
        }
        Ok(())
    }

    fn finalize_into_reset(&mut self, digest: &mut [u8]) {
        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1(instance) => {
                let digest: &mut crypto_common::Output<sha1::Sha1> = digest.into();
                digest::FixedOutputReset::finalize_into_reset(instance, digest);
            }
            #[cfg(feature = "sha256")]
            Self::Sha256(instance) => {
                let digest: &mut crypto_common::Output<sha2::Sha256> = digest.into();
                digest::FixedOutputReset::finalize_into_reset(instance, digest);
            }
            #[cfg(feature = "sha384")]
            Self::Sha384(instance) => {
                let digest: &mut crypto_common::Output<sha2::Sha384> = digest.into();
                digest::FixedOutputReset::finalize_into_reset(instance, digest);
            }
            #[cfg(feature = "sha512")]
            Self::Sha512(instance) => {
                let digest: &mut crypto_common::Output<sha2::Sha512> = digest.into();
                digest::FixedOutputReset::finalize_into_reset(instance, digest);
            }
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256(instance) => {
                let digest: &mut crypto_common::Output<sha3::Sha3_256> = digest.into();
                digest::FixedOutputReset::finalize_into_reset(instance, digest);
            }
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384(instance) => {
                let digest: &mut crypto_common::Output<sha3::Sha3_384> = digest.into();
                digest::FixedOutputReset::finalize_into_reset(instance, digest);
            }
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512(instance) => {
                let digest: &mut crypto_common::Output<sha3::Sha3_512> = digest.into();
                digest::FixedOutputReset::finalize_into_reset(instance, digest);
            }
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256(instance) => {
                let digest: &mut crypto_common::Output<sm3::Sm3> = digest.into();
                digest::FixedOutputReset::finalize_into_reset(instance, digest);
            }
        }
    }

    fn finalize_into(mut self, digest: &mut [u8]) {
        self.finalize_into_reset(digest)
    }

    fn finalize_reset(&mut self) -> Result<tpm2_interface::TpmtHa<'static>, CryptoError> {
        let digest_len = self.digest_len();
        let mut digest_buf = try_alloc_zeroizing_vec::<u8>(digest_len)?;
        self.finalize_into_reset(&mut digest_buf);
        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1(_) => Ok(tpm2_interface::TpmtHa::Sha1(tpm2_interface::TpmBuffer::Owned(
                mem::take(&mut digest_buf),
            ))),
            #[cfg(feature = "sha256")]
            Self::Sha256(_) => Ok(tpm2_interface::TpmtHa::Sha256(tpm2_interface::TpmBuffer::Owned(
                mem::take(&mut digest_buf),
            ))),
            #[cfg(feature = "sha384")]
            Self::Sha384(_) => Ok(tpm2_interface::TpmtHa::Sha384(tpm2_interface::TpmBuffer::Owned(
                mem::take(&mut digest_buf),
            ))),
            #[cfg(feature = "sha512")]
            Self::Sha512(_) => Ok(tpm2_interface::TpmtHa::Sha512(tpm2_interface::TpmBuffer::Owned(
                mem::take(&mut digest_buf),
            ))),
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256(_) => Ok(tpm2_interface::TpmtHa::Sha3_256(tpm2_interface::TpmBuffer::Owned(
                mem::take(&mut digest_buf),
            ))),
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384(_) => Ok(tpm2_interface::TpmtHa::Sha3_384(tpm2_interface::TpmBuffer::Owned(
                mem::take(&mut digest_buf),
            ))),
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512(_) => Ok(tpm2_interface::TpmtHa::Sha3_512(tpm2_interface::TpmBuffer::Owned(
                mem::take(&mut digest_buf),
            ))),
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256(_) => Ok(tpm2_interface::TpmtHa::Sm3_256(tpm2_interface::TpmBuffer::Owned(
                mem::take(&mut digest_buf),
            ))),
        }
    }

    fn finalize(mut self) -> Result<tpm2_interface::TpmtHa<'static>, CryptoError> {
        self.finalize_reset()
    }

    fn digest_len(&self) -> usize {
        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1(_) => <sha1::Sha1 as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sha256")]
            Self::Sha256(_) => <sha2::Sha256 as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sha384")]
            Self::Sha384(_) => <sha2::Sha384 as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sha512")]
            Self::Sha512(_) => <sha2::Sha512 as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256(_) => <sha3::Sha3_256 as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384(_) => <sha3::Sha3_384 as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512(_) => <sha3::Sha3_512 as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256(_) => <sm3::Sm3 as crypto_common::OutputSizeUser>::output_size(),
        }
    }
}

impl convert::From<&HashInstance> for tpm2_interface::TpmiAlgHash {
    fn from(instance: &HashInstance) -> Self {
        match &instance.state {
            #[cfg(feature = "sha1")]
            HashInstanceState::Sha1(_) => tpm2_interface::TpmiAlgHash::Sha1,
            #[cfg(feature = "sha256")]
            HashInstanceState::Sha256(_) => tpm2_interface::TpmiAlgHash::Sha256,
            #[cfg(feature = "sha384")]
            HashInstanceState::Sha384(_) => tpm2_interface::TpmiAlgHash::Sha384,
            #[cfg(feature = "sha512")]
            HashInstanceState::Sha512(_) => tpm2_interface::TpmiAlgHash::Sha512,
            #[cfg(feature = "sha3_256")]
            HashInstanceState::Sha3_256(_) => tpm2_interface::TpmiAlgHash::Sha3_256,
            #[cfg(feature = "sha3_384")]
            HashInstanceState::Sha3_384(_) => tpm2_interface::TpmiAlgHash::Sha3_384,
            #[cfg(feature = "sha3_512")]
            HashInstanceState::Sha3_512(_) => tpm2_interface::TpmiAlgHash::Sha3_512,
            #[cfg(feature = "sm3_256")]
            HashInstanceState::Sm3_256(_) => tpm2_interface::TpmiAlgHash::Sm3_256,
        }
    }
}

/// A HMAC instance.
pub struct HmacInstance {
    state: Box<zeroize::ZeroizingFlat<HmacInstanceState>>,
}

impl HmacInstance {
    /// Create a new hash instance for the specified underlying hash algorithm.
    ///
    /// # Arguments:
    ///
    /// * `alg` - The hash algorithm to create a HMAC instance for.
    pub fn new(alg: tpm2_interface::TpmiAlgHash, key: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            state: HmacInstanceState::new(alg, key)?,
        })
    }

    /// Try to clone a HMAC instance.
    pub fn try_clone(&self) -> Result<Self, CryptoError> {
        Ok(Self {
            state: box_try_new_with(
                || -> Result<zeroize::ZeroizingFlat<HmacInstanceState>, convert::Infallible> {
                    Ok(self.state.as_ref().clone())
                },
            )?,
        })
    }

    /// Reset an existing HMAC instance's state to that of another one.
    ///
    /// Prefer [`repurpose_for_clone_of()`](Self::repurpose_for_clone_of) if
    /// possible, as that might enable the compiler to elide some stack
    /// copies.
    ///
    /// # Arguments:
    ///
    /// * `instance` - The instance to reset `self`'s state to.
    pub fn reset_to(&mut self, instance: &Self) -> Result<(), convert::Infallible> {
        self.state.replace(instance.state.deref().deref().clone());
        Ok(())
    }

    /// Repurpose a HMAC instance's memory for the clone of another one.
    ///
    /// It is functionally equivalent to [`reset_to`](Self::reset_to), but might
    /// enable the compiler to elide some stack copies.
    ///
    /// # Arguments:
    ///
    /// * `instance` - The instance to reset `self`'s state to.
    pub fn repurpose_for_clone_of(self, instance: &Self) -> Result<Self, convert::Infallible> {
        let Self { state } = self;
        let state = state.replace_boxed_with(|| instance.state.deref().deref().clone());
        Ok(Self { state })
    }

    /// Append to the digested data.
    ///
    /// # Arguments:
    ///
    /// * `data` - The data to digest.
    pub fn update<'a, DI: CryptoIoSlicesIter<'a>>(&mut self, mut data: DI) -> Result<(), CryptoError> {
        self.state.update(&mut data)
    }
    /// Produce the final digest into a provided buffer..
    ///
    /// # Arguments:
    ///
    /// * `digest` - Destination to write the produced digest to.
    pub fn finalize_into(self, digest: &mut [u8]) -> Result<(), convert::Infallible> {
        self.state.take_boxed_with(|state| state.finalize_into(digest));
        Ok(())
    }

    /// Determine the instance's associated hash algorithm's digest length.
    pub fn digest_len(&self) -> usize {
        self.state.digest_len()
    }
}

impl convert::From<&HmacInstance> for tpm2_interface::TpmiAlgHash {
    fn from(instance: &HmacInstance) -> Self {
        tpm2_interface::TpmiAlgHash::from(instance.state.deref().deref())
    }
}

#[derive(Clone)]
enum HmacInstanceState {
    #[cfg(feature = "sha1")]
    Sha1(hmac::Hmac<sha1::Sha1>),
    #[cfg(feature = "sha256")]
    Sha256(hmac::Hmac<sha2::Sha256>),
    #[cfg(feature = "sha384")]
    Sha384(hmac::Hmac<sha2::Sha384>),
    #[cfg(feature = "sha512")]
    Sha512(hmac::Hmac<sha2::Sha512>),
    #[cfg(feature = "sha3_256")]
    Sha3_256(hmac::Hmac<sha3::Sha3_256>),
    #[cfg(feature = "sha3_384")]
    Sha3_384(hmac::Hmac<sha3::Sha3_384>),
    #[cfg(feature = "sha3_512")]
    Sha3_512(hmac::Hmac<sha3::Sha3_512>),
    #[cfg(feature = "sm3_256")]
    Sm3_256(hmac::Hmac<sm3::Sm3>),
}

impl HmacInstanceState {
    #[inline(never)]
    fn new(alg: tpm2_interface::TpmiAlgHash, key: &[u8]) -> Result<Box<zeroize::ZeroizingFlat<Self>>, CryptoError> {
        match alg {
            #[cfg(feature = "sha1")]
            tpm2_interface::TpmiAlgHash::Sha1 => {
                // This in fact never fails and is always inlined, so the compiler can prove
                // it's infallible.
                let hmac_core = hmac::HmacCore::<sha1::Sha1>::new_from_slice(key).map_err(|_| CryptoError::KeySize)?;

                // The infallible enables zero-copy construction in place.
                box_try_new_with(|| -> Result<_, convert::Infallible> {
                    Ok(zeroize::ZeroizingFlat::from(Self::Sha1(hmac::Hmac::from_core(
                        hmac_core,
                    ))))
                })
                .map_err(CryptoError::from)
            }
            #[cfg(feature = "sha256")]
            tpm2_interface::TpmiAlgHash::Sha256 => {
                // This in fact never fails and is always inlined, so the compiler can prove
                // it's infallible.
                let hmac_core =
                    hmac::HmacCore::<sha2::Sha256>::new_from_slice(key).map_err(|_| CryptoError::KeySize)?;

                // The infallible enables zero-copy construction in place.
                box_try_new_with(|| -> Result<_, convert::Infallible> {
                    Ok(zeroize::ZeroizingFlat::from(Self::Sha256(hmac::Hmac::from_core(
                        hmac_core,
                    ))))
                })
                .map_err(CryptoError::from)
            }
            #[cfg(feature = "sha384")]
            tpm2_interface::TpmiAlgHash::Sha384 => {
                // This in fact never fails and is always inlined, so the compiler can prove
                // it's infallible.
                let hmac_core =
                    hmac::HmacCore::<sha2::Sha384>::new_from_slice(key).map_err(|_| CryptoError::KeySize)?;

                // The infallible enables zero-copy construction in place.
                box_try_new_with(|| -> Result<_, convert::Infallible> {
                    Ok(zeroize::ZeroizingFlat::from(Self::Sha384(hmac::Hmac::from_core(
                        hmac_core,
                    ))))
                })
                .map_err(CryptoError::from)
            }
            #[cfg(feature = "sha512")]
            tpm2_interface::TpmiAlgHash::Sha512 => {
                // This in fact never fails and is always inlined, so the compiler can prove
                // it's infallible.
                let hmac_core =
                    hmac::HmacCore::<sha2::Sha512>::new_from_slice(key).map_err(|_| CryptoError::KeySize)?;

                // The infallible enables zero-copy construction in place.
                box_try_new_with(|| -> Result<_, convert::Infallible> {
                    Ok(zeroize::ZeroizingFlat::from(Self::Sha512(hmac::Hmac::from_core(
                        hmac_core,
                    ))))
                })
                .map_err(CryptoError::from)
            }
            #[cfg(feature = "sha3_256")]
            tpm2_interface::TpmiAlgHash::Sha3_256 => {
                // This in fact never fails and is always inlined, so the compiler can prove
                // it's infallible.
                let hmac_core =
                    hmac::HmacCore::<sha3::Sha3_256>::new_from_slice(key).map_err(|_| CryptoError::KeySize)?;

                // The infallible enables zero-copy construction in place.
                box_try_new_with(|| -> Result<_, convert::Infallible> {
                    Ok(zeroize::ZeroizingFlat::from(Self::Sha3_256(hmac::Hmac::from_core(
                        hmac_core,
                    ))))
                })
                .map_err(CryptoError::from)
            }
            #[cfg(feature = "sha3_384")]
            tpm2_interface::TpmiAlgHash::Sha3_384 => {
                // This in fact never fails and is always inlined, so the compiler can prove
                // it's infallible.
                let hmac_core =
                    hmac::HmacCore::<sha3::Sha3_384>::new_from_slice(key).map_err(|_| CryptoError::KeySize)?;

                // The infallible enables zero-copy construction in place.
                box_try_new_with(|| -> Result<_, convert::Infallible> {
                    Ok(zeroize::ZeroizingFlat::from(Self::Sha3_384(hmac::Hmac::from_core(
                        hmac_core,
                    ))))
                })
                .map_err(CryptoError::from)
            }
            #[cfg(feature = "sha3_512")]
            tpm2_interface::TpmiAlgHash::Sha3_512 => {
                // This in fact never fails and is always inlined, so the compiler can prove
                // it's infallible.
                let hmac_core =
                    hmac::HmacCore::<sha3::Sha3_512>::new_from_slice(key).map_err(|_| CryptoError::KeySize)?;

                // The infallible enables zero-copy construction in place.
                box_try_new_with(|| -> Result<_, convert::Infallible> {
                    Ok(zeroize::ZeroizingFlat::from(Self::Sha3_512(hmac::Hmac::from_core(
                        hmac_core,
                    ))))
                })
                .map_err(CryptoError::from)
            }
            #[cfg(feature = "sm3_256")]
            tpm2_interface::TpmiAlgHash::Sm3_256 => {
                // This in fact never fails and is always inlined, so the compiler can prove
                // it's infallible.
                let hmac_core = hmac::HmacCore::<sm3::Sm3>::new_from_slice(key).map_err(|_| CryptoError::KeySize)?;

                // The infallible enables zero-copy construction in place.
                box_try_new_with(|| -> Result<_, convert::Infallible> {
                    Ok(zeroize::ZeroizingFlat::from(Self::Sm3_256(hmac::Hmac::from_core(
                        hmac_core,
                    ))))
                })
                .map_err(CryptoError::from)
            }
        }
    }

    fn update<'a>(&mut self, data: &mut dyn CryptoIoSlicesIter<'a>) -> Result<(), CryptoError> {
        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1(instance) => {
                while let Some(data) = data.next_slice(None)? {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sha256")]
            Self::Sha256(instance) => {
                while let Some(data) = data.next_slice(None)? {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sha384")]
            Self::Sha384(instance) => {
                while let Some(data) = data.next_slice(None)? {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sha512")]
            Self::Sha512(instance) => {
                while let Some(data) = data.next_slice(None)? {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256(instance) => {
                while let Some(data) = data.next_slice(None)? {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384(instance) => {
                while let Some(data) = data.next_slice(None)? {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512(instance) => {
                while let Some(data) = data.next_slice(None)? {
                    digest::Update::update(instance, data);
                }
            }
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256(instance) => {
                while let Some(data) = data.next_slice(None)? {
                    digest::Update::update(instance, data);
                }
            }
        }
        Ok(())
    }

    fn finalize_into(self, digest: &mut [u8]) {
        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1(instance) => {
                let digest: &mut crypto_common::Output<Hmac<sha1::Sha1>> = digest.into();
                digest::FixedOutput::finalize_into(instance, digest);
            }
            #[cfg(feature = "sha256")]
            Self::Sha256(instance) => {
                let digest: &mut crypto_common::Output<Hmac<sha2::Sha256>> = digest.into();
                digest::FixedOutput::finalize_into(instance, digest);
            }
            #[cfg(feature = "sha384")]
            Self::Sha384(instance) => {
                let digest: &mut crypto_common::Output<Hmac<sha2::Sha384>> = digest.into();
                digest::FixedOutput::finalize_into(instance, digest);
            }
            #[cfg(feature = "sha512")]
            Self::Sha512(instance) => {
                let digest: &mut crypto_common::Output<Hmac<sha2::Sha512>> = digest.into();
                digest::FixedOutput::finalize_into(instance, digest);
            }
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256(instance) => {
                let digest: &mut crypto_common::Output<Hmac<sha3::Sha3_256>> = digest.into();
                digest::FixedOutput::finalize_into(instance, digest);
            }
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384(instance) => {
                let digest: &mut crypto_common::Output<Hmac<sha3::Sha3_384>> = digest.into();
                digest::FixedOutput::finalize_into(instance, digest);
            }
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512(instance) => {
                let digest: &mut crypto_common::Output<Hmac<sha3::Sha3_512>> = digest.into();
                digest::FixedOutput::finalize_into(instance, digest);
            }
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256(instance) => {
                let digest: &mut crypto_common::Output<Hmac<sm3::Sm3>> = digest.into();
                digest::FixedOutput::finalize_into(instance, digest);
            }
        }
    }

    fn digest_len(&self) -> usize {
        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1(_) => <Hmac<sha1::Sha1> as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sha256")]
            Self::Sha256(_) => <Hmac<sha2::Sha256> as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sha384")]
            Self::Sha384(_) => <Hmac<sha2::Sha384> as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sha512")]
            Self::Sha512(_) => <Hmac<sha2::Sha512> as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256(_) => <Hmac<sha3::Sha3_256> as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384(_) => <Hmac<sha3::Sha3_384> as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512(_) => <Hmac<sha3::Sha3_512> as crypto_common::OutputSizeUser>::output_size(),
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256(_) => <Hmac<sm3::Sm3> as crypto_common::OutputSizeUser>::output_size(),
        }
    }
}

impl convert::From<&HmacInstanceState> for tpm2_interface::TpmiAlgHash {
    fn from(instance_state: &HmacInstanceState) -> Self {
        match instance_state {
            #[cfg(feature = "sha1")]
            HmacInstanceState::Sha1(_) => tpm2_interface::TpmiAlgHash::Sha1,
            #[cfg(feature = "sha256")]
            HmacInstanceState::Sha256(_) => tpm2_interface::TpmiAlgHash::Sha256,
            #[cfg(feature = "sha384")]
            HmacInstanceState::Sha384(_) => tpm2_interface::TpmiAlgHash::Sha384,
            #[cfg(feature = "sha512")]
            HmacInstanceState::Sha512(_) => tpm2_interface::TpmiAlgHash::Sha512,
            #[cfg(feature = "sha3_256")]
            HmacInstanceState::Sha3_256(_) => tpm2_interface::TpmiAlgHash::Sha3_256,
            #[cfg(feature = "sha3_384")]
            HmacInstanceState::Sha3_384(_) => tpm2_interface::TpmiAlgHash::Sha3_384,
            #[cfg(feature = "sha3_512")]
            HmacInstanceState::Sha3_512(_) => tpm2_interface::TpmiAlgHash::Sha3_512,
            #[cfg(feature = "sm3_256")]
            HmacInstanceState::Sm3_256(_) => tpm2_interface::TpmiAlgHash::Sm3_256,
        }
    }
}
