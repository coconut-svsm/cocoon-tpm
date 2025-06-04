// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! BoringSSL FFI EC_KEY bindings.

extern crate alloc;
use alloc::vec::Vec;

use cocoon_tpm_bssl_bare_sys as bssl_bare_sys;

use super::super::{bssl_bn::BsslBn, error::bssl_get_error};
use super::curve;
use crate::utils_common::{alloc::try_alloc_zeroizing_vec, zeroize};
use crate::{ecc, CryptoError};

pub struct BsslEcKey {
    bssl_ec_key: *mut bssl_bare_sys::EC_KEY,
}

impl BsslEcKey {
    /// Convert an [EccKey](ecc::EccKey) to a BoringSSL `EC_KEY`.
    #[allow(unused)]
    pub fn new_from_ecc_key(ecc_key: &ecc::EccKey, curve_ops: &curve::CurveOps) -> Result<Self, CryptoError> {
        if curve_ops.curve.get_curve_id() != ecc_key.pub_key().get_curve_id() {
            return Err(CryptoError::Internal);
        }

        let bssl_ec_key = unsafe { bssl_bare_sys::EC_KEY_new() };
        if bssl_ec_key.is_null() {
            return Err(bssl_get_error());
        }
        let mut bssl_ec_key = Self { bssl_ec_key };
        if unsafe { bssl_bare_sys::EC_KEY_set_group(bssl_ec_key.as_mut_ptr(), curve_ops.bssl_ec_group.as_ptr()) } == 0 {
            return Err(bssl_get_error());
        }

        if let Some(priv_key) = ecc_key.priv_key() {
            let priv_key = BsslBn::try_from(priv_key.get_d())?;
            if unsafe { bssl_bare_sys::EC_KEY_set_private_key(bssl_ec_key.as_mut_ptr(), priv_key.as_ptr()) } == 0 {
                return Err(bssl_get_error());
            }
        }

        if unsafe {
            bssl_bare_sys::EC_KEY_set_public_key(bssl_ec_key.as_mut_ptr(), ecc_key.pub_key().get_point().bssl_ec_point)
        } == 0
        {
            return Err(bssl_get_error());
        }

        Ok(bssl_ec_key)
    }

    /// Convert an [EccPublicKey](ecc::EccPublicKey) to a BoringSSL `EC_KEY`.
    #[allow(unused)]
    pub fn new_from_ecc_pub_key(
        ecc_pub_key: &ecc::EccPublicKey,
        curve_ops: &curve::CurveOps,
    ) -> Result<Self, CryptoError> {
        if curve_ops.curve.get_curve_id() != ecc_pub_key.get_curve_id() {
            return Err(CryptoError::Internal);
        }
        let bssl_ec_key = unsafe { bssl_bare_sys::EC_KEY_new() };
        if bssl_ec_key.is_null() {
            return Err(bssl_get_error());
        }
        let mut bssl_ec_key = Self { bssl_ec_key };
        if unsafe { bssl_bare_sys::EC_KEY_set_group(bssl_ec_key.as_mut_ptr(), curve_ops.bssl_ec_group.as_ptr()) } == 0 {
            return Err(bssl_get_error());
        }

        if unsafe {
            bssl_bare_sys::EC_KEY_set_public_key(bssl_ec_key.as_mut_ptr(), ecc_pub_key.get_point().bssl_ec_point)
        } == 0
        {
            return Err(bssl_get_error());
        }

        Ok(bssl_ec_key)
    }

    /// Convert a BoringSSL `EC_KEY` to a an
    /// [`AffinePoint`](curve::AffinePoint).
    pub fn to_public_point(&self, curve_ops: &curve::CurveOps) -> Result<curve::AffinePoint, CryptoError> {
        let pub_key = unsafe { bssl_bare_sys::EC_KEY_get0_public_key(self.as_ptr()) };
        if pub_key.is_null() {
            return Err(bssl_get_error());
        }
        let pub_key = unsafe { bssl_bare_sys::EC_POINT_dup(pub_key, curve_ops.bssl_ec_group.as_ptr()) };
        if pub_key.is_null() {
            return Err(bssl_get_error());
        }
        Ok(curve::AffinePoint { bssl_ec_point: pub_key })
    }

    /// Convert a BoringSSL `EC_KEY` to a a pair of
    /// [`AffinePoint`](curve::AffinePoint) and private key if available.
    #[allow(clippy::type_complexity)]
    pub fn to_key_pair(
        &self,
        curve_ops: &curve::CurveOps,
    ) -> Result<(curve::AffinePoint, Option<zeroize::Zeroizing<Vec<u8>>>), CryptoError> {
        let pub_key = self.to_public_point(curve_ops)?;

        let priv_key = unsafe { bssl_bare_sys::EC_KEY_get0_private_key(self.as_ptr()) };
        let priv_key_bytes = if !priv_key.is_null() {
            let priv_key_len =
                usize::try_from(unsafe { bssl_bare_sys::BN_num_bytes(priv_key) }).map_err(|_| CryptoError::Internal)?;
            let mut priv_key_bytes = try_alloc_zeroizing_vec(priv_key_len)?;
            if unsafe { bssl_bare_sys::BN_bn2bin_padded(priv_key_bytes.as_mut_ptr(), priv_key_len, priv_key) } < 0 {
                return Err(bssl_get_error());
            }
            Some(priv_key_bytes)
        } else {
            None
        };

        Ok((pub_key, priv_key_bytes))
    }

    pub fn generate(curve_ops: &curve::CurveOps) -> Result<Self, CryptoError> {
        let bssl_ec_key = unsafe { bssl_bare_sys::EC_KEY_new() };
        if bssl_ec_key.is_null() {
            return Err(bssl_get_error());
        }
        let mut bssl_ec_key = Self { bssl_ec_key };
        if unsafe { bssl_bare_sys::EC_KEY_set_group(bssl_ec_key.as_mut_ptr(), curve_ops.bssl_ec_group.as_ptr()) } == 0 {
            return Err(bssl_get_error());
        }

        if unsafe { bssl_bare_sys::EC_KEY_generate_key(bssl_ec_key.as_mut_ptr()) } == 0 {
            return Err(bssl_get_error());
        }

        Ok(bssl_ec_key)
    }

    pub fn as_ptr(&self) -> *const bssl_bare_sys::EC_KEY {
        self.bssl_ec_key
    }

    pub fn as_mut_ptr(&mut self) -> *mut bssl_bare_sys::EC_KEY {
        self.bssl_ec_key
    }
}

impl Drop for BsslEcKey {
    fn drop(&mut self) {
        if !self.bssl_ec_key.is_null() {
            unsafe { bssl_bare_sys::EC_KEY_free(self.bssl_ec_key) };
        }
    }
}
