// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! BoringSSL FFI backend for hash algorithms.

// Lifetimes are not obvious at first sight here, make the explicit.
#![allow(clippy::needless_lifetimes)]

extern crate alloc;

use cocoon_tpm_bssl_bare_sys as bssl_bare_sys;

use crate::bssl_ffi;
use crate::hash::hash_alg_digest_len;
use crate::{io_slices::CryptoIoSlicesIter, CryptoError};
use crate::{
    tpm2_interface,
    utils_common::{alloc::try_alloc_zeroizing_vec, zeroize},
};
use core::{convert, ffi, marker, mem, ptr};

fn map_to_evp_md(alg: tpm2_interface::TpmiAlgHash) -> Result<*const bssl_bare_sys::EVP_MD, CryptoError> {
    let md = match alg {
        #[cfg(feature = "sha1")]
        tpm2_interface::TpmiAlgHash::Sha1 => unsafe { bssl_bare_sys::EVP_sha1 },
        #[cfg(feature = "sha256")]
        tpm2_interface::TpmiAlgHash::Sha256 => unsafe { bssl_bare_sys::EVP_sha256() },
        #[cfg(feature = "sha384")]
        tpm2_interface::TpmiAlgHash::Sha384 => unsafe { bssl_bare_sys::EVP_sha384() },
        #[cfg(feature = "sha512")]
        tpm2_interface::TpmiAlgHash::Sha512 => unsafe { bssl_bare_sys::EVP_sha512() },
        #[cfg(feature = "sha3_256")]
        tpm2_interface::TpmiAlgHash::Sha3_256 => {
            compile_error!("SHA-3 not supported with BoringSSL backend.")
        }
        #[cfg(feature = "sha3_384")]
        tpm2_interface::TpmiAlgHash::Sha3_384 => {
            compile_error!("SHA-3 not supported with BoringSSL backend.")
        }
        #[cfg(feature = "sha3_512")]
        tpm2_interface::TpmiAlgHash::Sha3_512 => {
            compile_error!("SHA-3 not supported with BoringSSL backend.")
        }
        #[cfg(feature = "sm3_256")]
        tpm2_interface::TpmiAlgHash::Sm3_256 => {
            compile_error!("SM3 not supported with BoringSSL backend.")
        }
    };

    if !md.is_null() {
        Ok(md)
    } else {
        Err(bssl_ffi::error::bssl_get_error())
    }
}

/// A hash instance.
pub struct HashInstance {
    ctx: ptr::NonNull<bssl_bare_sys::EVP_MD_CTX>,
    alg: tpm2_interface::TpmiAlgHash,
    reinit_failed: bool,
}

impl HashInstance {
    /// Create a new hash instance for the specified algorithm.
    ///
    /// # Arguments:
    ///
    /// * `alg` - The hash algorithm to create an instance for.
    pub fn new(alg: tpm2_interface::TpmiAlgHash) -> Result<Self, CryptoError> {
        let md = map_to_evp_md(alg)?;

        // Consistency check: hash_alg_digest_len() will be used for Self::digest_len()
        // and should return consistent results.
        let digest_size: usize = unsafe { bssl_bare_sys::EVP_MD_size(md) };
        if hash_alg_digest_len(alg) as usize != digest_size {
            return Err(CryptoError::Internal);
        }

        let ctx = { unsafe { bssl_bare_sys::EVP_MD_CTX_new() } };
        let ctx = ptr::NonNull::new(ctx).ok_or_else(bssl_ffi::error::bssl_get_error)?;

        if { unsafe { bssl_bare_sys::EVP_DigestInit_ex(ctx.as_ptr(), md, ptr::null_mut::<bssl_bare_sys::ENGINE>()) } }
            == 0
        {
            unsafe { bssl_bare_sys::EVP_MD_CTX_free(ctx.as_ptr()) };
            return Err(bssl_ffi::error::bssl_get_error());
        }

        Ok(Self {
            ctx,
            alg,
            reinit_failed: false,
        })
    }

    pub fn try_clone(&self) -> Result<Self, CryptoError> {
        if self.reinit_failed {
            return Err(CryptoError::Internal);
        }

        let md = unsafe { bssl_bare_sys::EVP_MD_CTX_get0_md(self.ctx.as_ptr()) };
        if md.is_null() {
            return Err(bssl_ffi::error::bssl_get_error());
        }

        let ctx = { unsafe { bssl_bare_sys::EVP_MD_CTX_new() } };
        let ctx = ptr::NonNull::new(ctx).ok_or_else(bssl_ffi::error::bssl_get_error)?;

        if { unsafe { bssl_bare_sys::EVP_DigestInit_ex(ctx.as_ptr(), md, ptr::null_mut::<bssl_bare_sys::ENGINE>()) } }
            == 0
        {
            unsafe { bssl_bare_sys::EVP_MD_CTX_free(ctx.as_ptr()) };
            return Err(bssl_ffi::error::bssl_get_error());
        }

        if unsafe { bssl_bare_sys::EVP_MD_CTX_copy_ex(ctx.as_ptr(), self.ctx.as_ptr()) } == 0 {
            unsafe { bssl_bare_sys::EVP_MD_CTX_free(ctx.as_ptr()) };
            return Err(bssl_ffi::error::bssl_get_error());
        }

        Ok(Self {
            ctx,
            alg: self.alg,
            reinit_failed: false,
        })
    }

    /// Append to the digested data.
    ///
    /// # Arguments:
    ///
    /// * `data` - The data to digest.
    pub fn update<'a, DI: CryptoIoSlicesIter<'a>>(&mut self, mut data: DI) -> Result<(), CryptoError> {
        if self.reinit_failed {
            return Err(CryptoError::Internal);
        }

        while let Some(slice) = data.next_slice(None)? {
            // Io slices iterators filter empty slices.
            if slice.is_empty() {
                return Err(CryptoError::Internal);
            }

            if {
                unsafe {
                    bssl_bare_sys::EVP_DigestUpdate(
                        self.ctx.as_ptr(),
                        slice.as_ptr() as *const ffi::c_void,
                        slice.len(),
                    )
                }
            } == 0
            {
                return Err(bssl_ffi::error::bssl_get_error());
            }
        }

        Ok(())
    }

    /// Produce a digest into a provided buffer and reset the hash instance.
    ///
    /// Produce a digest into `digest` and reset the hash instance to the state
    /// it would have had right after [`Self::new()`](Self::new()).
    ///
    /// # Arguments:
    ///
    /// * `digest` - Destination to write the produced digest to.
    pub fn finalize_into_reset(&mut self, digest: &mut [u8]) -> Result<(), CryptoError> {
        if self.reinit_failed {
            return Err(CryptoError::Internal);
        }

        let digest_size: usize = { unsafe { bssl_bare_sys::EVP_MD_CTX_size(self.ctx.as_ptr()) } };
        if digest_size > digest.len() {
            return Err(CryptoError::Internal);
        }

        let md = unsafe { bssl_bare_sys::EVP_MD_CTX_get0_md(self.ctx.as_ptr()) };
        if md.is_null() {
            return Err(bssl_ffi::error::bssl_get_error());
        }

        if unsafe {
            bssl_bare_sys::EVP_DigestFinal_ex(self.ctx.as_mut(), digest.as_mut_ptr(), ptr::null_mut::<ffi::c_uint>())
        } == 0
        {
            return Err(bssl_ffi::error::bssl_get_error());
        }

        if {
            unsafe { bssl_bare_sys::EVP_DigestInit_ex(self.ctx.as_ptr(), md, ptr::null_mut::<bssl_bare_sys::ENGINE>()) }
        } == 0
        {
            self.reinit_failed = true;
            return Err(bssl_ffi::error::bssl_get_error());
        }

        Ok(())
    }

    /// Produce the final digest into a provided buffer..
    ///
    /// # Arguments:
    ///
    /// * `digest` - Destination to write the produced digest to.
    pub fn finalize_into(mut self, digest: &mut [u8]) -> Result<(), CryptoError> {
        if self.reinit_failed {
            return Err(CryptoError::Internal);
        }

        let digest_size: usize = { unsafe { bssl_bare_sys::EVP_MD_CTX_size(self.ctx.as_ptr()) } };
        if digest_size > digest.len() {
            return Err(CryptoError::Internal);
        }

        if unsafe {
            bssl_bare_sys::EVP_DigestFinal_ex(self.ctx.as_mut(), digest.as_mut_ptr(), ptr::null_mut::<ffi::c_uint>())
        } == 0
        {
            return Err(bssl_ffi::error::bssl_get_error());
        }

        Ok(())
    }

    /// Produce a digest and reset the hash instance.
    ///
    /// Allocate a buffer suitable for the instance's digest length,  produce a
    /// digest into it and reset the hash instance to the state it
    /// would have had right after [`Self::new()`](Self::new()).
    pub fn finalize_reset(&mut self) -> Result<tpm2_interface::TpmtHa<'static>, CryptoError> {
        if self.reinit_failed {
            return Err(CryptoError::Internal);
        }

        let digest_size: usize = { unsafe { bssl_bare_sys::EVP_MD_CTX_size(self.ctx.as_ptr()) } };

        let mut digest = try_alloc_zeroizing_vec(digest_size as usize)?;
        self.finalize_into_reset(&mut digest)?;
        let digest = tpm2_interface::TpmBuffer::Owned(mem::take(&mut digest));

        Ok(match self.alg {
            #[cfg(feature = "sha1")]
            tpm2_interface::TpmiAlgHash::Sha1 => tpm2_interface::TpmtHa::Sha1(digest),
            #[cfg(feature = "sha256")]
            tpm2_interface::TpmiAlgHash::Sha256 => tpm2_interface::TpmtHa::Sha256(digest),
            #[cfg(feature = "sha384")]
            tpm2_interface::TpmiAlgHash::Sha384 => tpm2_interface::TpmtHa::Sha384(digest),
            #[cfg(feature = "sha512")]
            tpm2_interface::TpmiAlgHash::Sha512 => tpm2_interface::TpmtHa::Sha512(digest),
            #[cfg(feature = "sha3_256")]
            tpm2_interface::TpmiAlgHash::Sha3_256 => {
                compile_error!("SHA-3 not supported with BoringSSL backend.")
            }
            #[cfg(feature = "sha3_384")]
            tpm2_interface::TpmiAlgHash::Sha3_384 => {
                compile_error!("SHA-3 not supported with BoringSSL backend.")
            }
            #[cfg(feature = "sha3_512")]
            tpm2_interface::TpmiAlgHash::Sha3_512 => {
                compile_error!("SHA-3 not supported with BoringSSL backend.")
            }
            #[cfg(feature = "sm3_256")]
            tpm2_interface::TpmiAlgHash::Sm3_256 => {
                compile_error!("SM3 not supported with BoringSSL backend.")
            }
        })
    }

    /// Produce the final digest.
    ///
    /// Allocate a buffer suitable for the instance's digest length and produce
    /// the final digest into it.
    pub fn finalize(self) -> Result<tpm2_interface::TpmtHa<'static>, CryptoError> {
        if self.reinit_failed {
            return Err(CryptoError::Internal);
        }

        let digest_size: usize = { unsafe { bssl_bare_sys::EVP_MD_CTX_size(self.ctx.as_ptr()) } };

        let alg = self.alg;
        let mut digest = try_alloc_zeroizing_vec(digest_size as usize)?;
        self.finalize_into(&mut digest)?;
        let digest = tpm2_interface::TpmBuffer::Owned(mem::take(&mut digest));

        Ok(match alg {
            #[cfg(feature = "sha1")]
            tpm2_interface::TpmiAlgHash::Sha1 => tpm2_interface::TpmtHa::Sha1(digest),
            #[cfg(feature = "sha256")]
            tpm2_interface::TpmiAlgHash::Sha256 => tpm2_interface::TpmtHa::Sha256(digest),
            #[cfg(feature = "sha384")]
            tpm2_interface::TpmiAlgHash::Sha384 => tpm2_interface::TpmtHa::Sha384(digest),
            #[cfg(feature = "sha512")]
            tpm2_interface::TpmiAlgHash::Sha512 => tpm2_interface::TpmtHa::Sha512(digest),
            #[cfg(feature = "sha3_256")]
            tpm2_interface::TpmiAlgHash::Sha3_256 => {
                compile_error!("SHA-3 not supported with BoringSSL backend.")
            }
            #[cfg(feature = "sha3_384")]
            tpm2_interface::TpmiAlgHash::Sha3_384 => {
                compile_error!("SHA-3 not supported with BoringSSL backend.")
            }
            #[cfg(feature = "sha3_512")]
            tpm2_interface::TpmiAlgHash::Sha3_512 => {
                compile_error!("SHA-3 not supported with BoringSSL backend.")
            }
            #[cfg(feature = "sm3_256")]
            tpm2_interface::TpmiAlgHash::Sm3_256 => {
                compile_error!("SM3 not supported with BoringSSL backend.")
            }
        })
    }

    /// Determine the instance's associated hash algorithm's digest length.
    pub fn digest_len(&self) -> usize {
        hash_alg_digest_len(self.alg) as usize
    }
}

impl Drop for HashInstance {
    fn drop(&mut self) {
        unsafe { bssl_bare_sys::EVP_MD_CTX_cleanse(self.ctx.as_ptr()) };
        unsafe { bssl_bare_sys::EVP_MD_CTX_free(self.ctx.as_ptr()) };
    }
}

// Safety: never mutated through an immutable reference and the pointer doesn't
// alias.
unsafe impl marker::Send for HashInstance {}

// Safety: never mutated through an immutable reference and the pointer doesn't
// alias.
unsafe impl marker::Sync for HashInstance {}

impl zeroize::ZeroizeOnDrop for HashInstance {}

/// A HMAC instance.
pub struct HmacInstance {
    ctx: ptr::NonNull<bssl_bare_sys::HMAC_CTX>,
    alg: tpm2_interface::TpmiAlgHash,
    reinit_failed: bool,
}

impl HmacInstance {
    /// Create a new hash instance for the specified underlying hash algorithm.
    ///
    /// # Arguments:
    ///
    /// * `alg` - The hash algorithm to create a HMAC instance for.
    pub fn new(alg: tpm2_interface::TpmiAlgHash, key: &[u8]) -> Result<Self, CryptoError> {
        let md = map_to_evp_md(alg)?;

        // Consistency check: hash_alg_digest_len() will be used for Self::digest_len()
        // and should return consistent results.
        let digest_size: usize = unsafe { bssl_bare_sys::EVP_MD_size(md) };
        if hash_alg_digest_len(alg) as usize != digest_size {
            return Err(CryptoError::Internal);
        }

        let ctx = { unsafe { bssl_bare_sys::HMAC_CTX_new() } };
        let ctx = ptr::NonNull::new(ctx).ok_or_else(bssl_ffi::error::bssl_get_error)?;

        let key_len = key.len();
        let key = if !key.is_empty() { key.as_ptr() } else { ptr::null() };
        if unsafe { bssl_bare_sys::HMAC_Init_ex(ctx.as_ptr(), key as *const ffi::c_void, key_len, md, ptr::null_mut()) }
            == 0
        {
            unsafe { bssl_bare_sys::HMAC_CTX_free(ctx.as_ptr()) };
            return Err(bssl_ffi::error::bssl_get_error());
        }

        Ok(Self {
            ctx,
            alg,
            reinit_failed: false,
        })
    }

    /// Try to clone a HMAC instance.
    pub fn try_clone(&self) -> Result<Self, CryptoError> {
        if self.reinit_failed {
            return Err(CryptoError::Internal);
        }

        let md = unsafe { bssl_bare_sys::HMAC_CTX_get_md(self.ctx.as_ptr()) };
        if md.is_null() {
            return Err(bssl_ffi::error::bssl_get_error());
        }

        let ctx = { unsafe { bssl_bare_sys::HMAC_CTX_new() } };
        let ctx = ptr::NonNull::new(ctx).ok_or_else(bssl_ffi::error::bssl_get_error)?;

        if unsafe { bssl_bare_sys::HMAC_CTX_copy(ctx.as_ptr(), self.ctx.as_ptr()) } == 0 {
            unsafe { bssl_bare_sys::HMAC_CTX_free(ctx.as_ptr()) };
            return Err(bssl_ffi::error::bssl_get_error());
        }

        Ok(Self {
            ctx,
            alg: self.alg,
            reinit_failed: false,
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
    pub fn reset_to(&mut self, instance: &Self) -> Result<(), CryptoError> {
        if instance.reinit_failed || self.alg != instance.alg {
            return Err(CryptoError::Internal);
        }

        if self.reinit_failed {
            unsafe { bssl_bare_sys::HMAC_CTX_cleanup(self.ctx.as_ptr()) };
            unsafe { bssl_bare_sys::HMAC_CTX_init(self.ctx.as_ptr()) };
            self.reinit_failed = false;
        }

        if unsafe { bssl_bare_sys::HMAC_CTX_copy_ex(self.ctx.as_ptr(), instance.ctx.as_ptr()) } == 0 {
            self.reinit_failed = true;
            return Err(bssl_ffi::error::bssl_get_error());
        }

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
    pub fn repurpose_for_clone_of(mut self, instance: &Self) -> Result<Self, CryptoError> {
        self.reset_to(instance)?;
        Ok(self)
    }

    /// Append to the digested data.
    ///
    /// # Arguments:
    ///
    /// * `data` - The data to digest.
    pub fn update<'a, DI: CryptoIoSlicesIter<'a>>(&mut self, mut data: DI) -> Result<(), CryptoError> {
        if self.reinit_failed {
            return Err(CryptoError::Internal);
        }

        while let Some(slice) = data.next_slice(None)? {
            // Io slices iterators filter empty slices.
            if slice.is_empty() {
                return Err(CryptoError::Internal);
            }

            if { unsafe { bssl_bare_sys::HMAC_Update(self.ctx.as_ptr(), slice.as_ptr(), slice.len()) } } == 0 {
                return Err(bssl_ffi::error::bssl_get_error());
            }
        }

        Ok(())
    }
    /// Produce the final digest into a provided buffer..
    ///
    /// # Arguments:
    ///
    /// * `digest` - Destination to write the produced digest to.
    pub fn finalize_into(self, digest: &mut [u8]) -> Result<(), CryptoError> {
        if self.reinit_failed {
            return Err(CryptoError::Internal);
        }

        let digest_size = unsafe { bssl_bare_sys::HMAC_size(self.ctx.as_ptr()) };
        if digest_size > digest.len() {
            return Err(CryptoError::Internal);
        }

        if unsafe { bssl_bare_sys::HMAC_Final(self.ctx.as_ptr(), digest.as_mut_ptr(), ptr::null_mut::<ffi::c_uint>()) }
            == 0
        {
            return Err(bssl_ffi::error::bssl_get_error());
        }

        Ok(())
    }

    /// Determine the instance's associated hash algorithm's digest length.
    pub fn digest_len(&self) -> usize {
        hash_alg_digest_len(self.alg) as usize
    }
}

// Safety: never mutated through an immutable reference and the pointer doesn't
// alias.
unsafe impl marker::Send for HmacInstance {}

// Safety: never mutated through an immutable reference and the pointer doesn't
// alias.
unsafe impl marker::Sync for HmacInstance {}

impl zeroize::ZeroizeOnDrop for HmacInstance {}

impl convert::From<&HmacInstance> for tpm2_interface::TpmiAlgHash {
    fn from(instance: &HmacInstance) -> Self {
        instance.alg
    }
}
