// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! BoringSSL FFI backend for ECC point operations.

use cocoon_tpm_bssl_bare_sys as bssl_bare_sys;

use super::super::{
    bssl_bn::{BsslBn, BsslBnCtx},
    error::bssl_get_error,
};
use super::bssl_ec_key::BsslEcKey;
use crate::CryptoError;
use crate::{
    ecc::{curve, key},
    rng,
};
use crate::{tpm2_interface, utils_common::zeroize};
use cmpa::{self, MpUIntCommon as _};
use core::{ffi, marker, mem, ptr};

/// ECC point in a representation with efficient storage characteristics.
///
/// Even though the name suggests the point representation is in affine
/// coordinates, it is completely internal to the backend implementation and
/// opaque to the user.
///
/// An `AffinePoint` may be converted to and from an external representation in
/// big-endian format by
/// means of [`try_from_plain_coordinates()`](Self::try_from_plain_coordinates)
/// and [`into_plain_coordinates()`](Self::into_plain_coordinates) or
/// [`to_plain_coordinates()`](Self::to_plain_coordinates) respectively.
///
/// In general, it is expected that if a backend uses different representations
/// for `AffinePoint` and [`ProjectivePoint`], then an `AffinePoint` has better
/// storage characteristics while a [`ProjectivePoint`] has some computational
/// advantages, especially when chaining multiple arithmetic operations.
///
/// Certain [`operations on points`](CurveOps) expect a [`ProjectivePoint`] for
/// their input accordingly. Conversion of an [`AffinePoint`] to and from the
/// [`ProjectivePoint`] representation is possible via
/// [`AffinePoint::into_projective()`](AffinePoint::into_projective) and
/// [ProjectivePoint::into_affine()](ProjectivePoint::into_affine).
///
/// Users may assume that the conversion to a [`ProjectivePoint`] has negligible
/// computational demands (it may require a memory allocation though), whereas
/// the inverse direction *may* involve e.g. a modular inversion.
pub struct AffinePoint {
    /// For Boring SSL, don't care about the actual representation.
    pub(super) bssl_ec_point: *mut bssl_bare_sys::EC_POINT,
}

impl AffinePoint {
    fn _try_from_plain_coordinates(
        x: &cmpa::MpBigEndianUIntByteSlice,
        y: &cmpa::MpBigEndianUIntByteSlice,
        curve_ops: &CurveOps,
    ) -> Result<Self, CryptoError> {
        let x = BsslBn::try_from(x.clone())?;
        let y = BsslBn::try_from(y.clone())?;
        let point = unsafe { bssl_bare_sys::EC_POINT_new(curve_ops.bssl_ec_group.as_ptr()) };
        if point.is_null() {
            return Err(bssl_get_error());
        }

        let mut bn_ctx = BsslBnCtx::new()?;
        if unsafe {
            bssl_bare_sys::EC_POINT_set_affine_coordinates(
                curve_ops.bssl_ec_group.as_ptr(),
                point,
                x.as_ptr(),
                y.as_ptr(),
                bn_ctx.as_mut_ptr(),
            )
        } == 0
        {
            return Err(bssl_get_error());
        }
        Ok(AffinePoint { bssl_ec_point: point })
    }

    /// Create an `AffinePoint` from "plain" affine coordinates.
    ///
    /// <div class="warning">
    ///
    /// A successful load of the point doesn't indicate it's mathematically
    /// valid. Use
    /// [`CurveOps::point_is_in_generator_subgroup()`](CurveOps::point_is_in_generator_subgroup) for
    /// a verification.
    ///
    /// </div>
    pub fn try_from_plain_coordinates(
        x: &cmpa::MpBigEndianUIntByteSlice,
        y: &cmpa::MpBigEndianUIntByteSlice,
        curve_ops: &CurveOps,
    ) -> Result<Self, CryptoError> {
        let p = curve_ops.curve.get_p();
        if !x.len_is_compatible_with(p.len())
            || !y.len_is_compatible_with(p.len())
            || cmpa::ct_geq_mp_mp(x, &p).unwrap() != 0
            || cmpa::ct_geq_mp_mp(y, &p).unwrap() != 0
        {
            return Err(CryptoError::InvalidPoint);
        }
        Self::_try_from_plain_coordinates(x, y, curve_ops)
    }

    /// Convert an `AffinePoint` into "plain" affine coordinates.
    ///
    /// May save a scratch buffer allocation as compared to
    /// [`to_plain_coordinates()`](Self::to_plain_coordinates), depending on the
    /// backend implementation.
    pub fn into_plain_coordinates(
        self,
        result_x: &mut cmpa::MpMutBigEndianUIntByteSlice,
        result_y: Option<&mut cmpa::MpMutBigEndianUIntByteSlice>,
        curve_ops: &CurveOps,
    ) -> Result<(), CryptoError> {
        self.to_plain_coordinates(result_x, result_y, curve_ops)
    }

    /// Convert an `AffinePoint` to "plain" affine coordinates.
    pub fn to_plain_coordinates(
        &self,
        result_x: &mut cmpa::MpMutBigEndianUIntByteSlice,
        result_y: Option<&mut cmpa::MpMutBigEndianUIntByteSlice>,
        curve_ops: &CurveOps,
    ) -> Result<(), CryptoError> {
        let mut x = BsslBn::new()?;
        let mut y = if result_y.is_some() { Some(BsslBn::new()?) } else { None };
        let mut bn_ctx = BsslBnCtx::new()?;
        if unsafe {
            bssl_bare_sys::EC_POINT_get_affine_coordinates(
                curve_ops.bssl_ec_group.as_ptr(),
                self.bssl_ec_point,
                x.as_mut_ptr(),
                y.as_mut().map(|y| y.as_mut_ptr()).unwrap_or(ptr::null_mut()),
                bn_ctx.as_mut_ptr(),
            )
        } == 0
        {
            return Err(bssl_get_error());
        }
        x.to_be_bytes(result_x)?;
        if let Some((y, result_y)) = y.zip(result_y) {
            y.to_be_bytes(result_y)?;
        }

        Ok(())
    }

    /// Convert into [`ProjectivePoint`] representation.
    #[allow(unused)]
    pub fn into_projective(mut self, curve_ops: &CurveOps) -> Result<ProjectivePoint, CryptoError> {
        // For Boring SSL, the same representation is use for AffinePoint and
        // ProjectivePoint.
        Ok(ProjectivePoint {
            bssl_ec_point: mem::replace(&mut self.bssl_ec_point, ptr::null_mut()),
        })
    }
}

impl Drop for AffinePoint {
    fn drop(&mut self) {
        if !self.bssl_ec_point.is_null() {
            unsafe { bssl_bare_sys::EC_POINT_clear_free(self.bssl_ec_point) };
        }
    }
}

// Safety: never mutated and the pointer doesn't alias.
unsafe impl marker::Send for AffinePoint {}

// Safety: never mutated and the pointer doesn't alias.
unsafe impl marker::Sync for AffinePoint {}

impl zeroize::ZeroizeOnDrop for AffinePoint {}

/// ECC point in a representation with efficient computational characteristics.
///
/// Even though the name suggests the point representation is in projective
/// coordinates, it is completely internal to the backend implementation and
/// opaque to the user.
///
/// A `ProjectivePoint` may be converted to an external representation with
/// affine coordinates in big-endian format by
/// means of [`into_affine_plain_coordinates()`](Self::into_affine_plain_coordinates).
/// It is not possible to instantiate a `ProjectivePoint` directly from such
/// though -- an [`AffinePoint`] would have to get
/// [constructed](AffinePoint::try_from_plain_coordinates) first
/// and then [converted](AffinePoint::into_projective) into the
/// `ProjectivePoint` representation.
///
/// In general, it is expected that if a backend uses different representations
/// for `ProjectivePoint` and [`AffinePoint`], then an `AffinePoint` has better
/// storage characteristics while a [`ProjectivePoint`] has some computational
/// advantages, especially when chaining multiple arithmetic operations.
///
/// Conversion of a `ProjectivePoint` to and from the [`ProjectivePoint`]
/// representation is possible
/// via [ProjectivePoint::into_affine()](ProjectivePoint::into_affine) and
/// [`AffinePoint::into_projective()`](AffinePoint::into_projective).
///
/// Users may assume that the conversion from an [`AffinePoint`] has negligible
/// computational demands (it may require a memory allocation though), whereas
/// the inverse direction *may* involve e.g. a modular inversion.
pub struct ProjectivePoint {
    /// For Boring SSL, don't care about the actual representation.
    pub(super) bssl_ec_point: *mut bssl_bare_sys::EC_POINT,
}

impl ProjectivePoint {
    /// Convert into an [`AffinePoint`].
    pub fn into_affine(
        mut self,
        curve_ops: &CurveOps,
        _scratch: Option<&mut CurveOpsScratch>,
    ) -> Result<Result<AffinePoint, curve::ProjectivePointIntoAffineError>, CryptoError> {
        // For Boring SSL, the same representation is use for AffinePoint and
        // ProjectivePoint.  But still check that the point could in principle
        // get converted to affine coordinates, otherwise a subsequent
        // AffinePoint::to_plain_coordinates() could run into an error condition
        // it cannot report properly.
        if unsafe { bssl_bare_sys::EC_POINT_is_at_infinity(curve_ops.bssl_ec_group.as_ptr(), self.bssl_ec_point) } != 0
        {
            return Ok(Err(curve::ProjectivePointIntoAffineError::PointIsIdentity));
        }
        Ok(Ok(AffinePoint {
            bssl_ec_point: mem::replace(&mut self.bssl_ec_point, ptr::null_mut()),
        }))
    }

    pub fn into_affine_plain_coordinates(
        self,
        result_x: &mut cmpa::MpMutBigEndianUIntByteSlice,
        result_y: Option<&mut cmpa::MpMutBigEndianUIntByteSlice>,
        curve_ops: &CurveOps,
        scratch: Option<&mut CurveOpsScratch>,
    ) -> Result<Result<(), curve::ProjectivePointIntoAffineError>, CryptoError> {
        if unsafe { bssl_bare_sys::EC_POINT_is_at_infinity(curve_ops.bssl_ec_group.as_ptr(), self.bssl_ec_point) } != 0
        {
            return Ok(Err(curve::ProjectivePointIntoAffineError::PointIsIdentity));
        }

        let affine = match self.into_affine(curve_ops, scratch)? {
            Ok(affine) => affine,
            Err(e) => return Ok(Err(e)),
        };

        Ok(Ok(affine.into_plain_coordinates(result_x, result_y, curve_ops)?))
    }
}

impl Drop for ProjectivePoint {
    fn drop(&mut self) {
        if !self.bssl_ec_point.is_null() {
            unsafe { bssl_bare_sys::EC_POINT_clear_free(self.bssl_ec_point) };
        }
    }
}

// Safety: never mutated and the pointer doesn't alias.
unsafe impl marker::Send for ProjectivePoint {}

// Safety: never mutated and the pointer doesn't alias.
unsafe impl marker::Sync for ProjectivePoint {}

impl zeroize::ZeroizeOnDrop for ProjectivePoint {}

/// Scratch space for use by arithmetic primitives implemented at [`CurveOps`].
pub struct CurveOpsScratch {
    bn_ctx: BsslBnCtx,
}

impl CurveOpsScratch {
    fn try_new() -> Result<Self, CryptoError> {
        Ok(Self {
            bn_ctx: BsslBnCtx::new()?,
        })
    }
}

/// ECC point arithmetic.
///
/// Never instantiated directly, but usually obtained through
/// [`Curve::curve_ops()`](curve::Curve::curve_ops).
pub struct CurveOps<'a> {
    pub(super) curve: &'a curve::Curve,
    pub(super) bssl_ec_group: ptr::NonNull<bssl_bare_sys::EC_GROUP>,
}

impl<'a> CurveOps<'a> {
    pub(crate) fn try_new(curve: &'a curve::Curve) -> Result<Self, CryptoError> {
        let curve_nid = match curve.get_curve_id() {
            tpm2_interface::TpmEccCurve::None => return Err(CryptoError::InvalidParams),
            #[cfg(feature = "ecc_nist_p192")]
            tpm2_interface::TpmEccCurve::NistP192 => {
                compile_error!("NIST P-192 curve not supported with Boring SSL backend");
            }
            #[cfg(feature = "ecc_nist_p224")]
            tpm2_interface::TpmEccCurve::NistP224 => bssl_bare_sys::NID_secp224r1,
            #[cfg(feature = "ecc_nist_p256")]
            tpm2_interface::TpmEccCurve::NistP256 => bssl_bare_sys::NID_X9_62_prime256v1,
            #[cfg(feature = "ecc_nist_p384")]
            tpm2_interface::TpmEccCurve::NistP384 => bssl_bare_sys::NID_secp384r1,
            #[cfg(feature = "ecc_nist_p521")]
            tpm2_interface::TpmEccCurve::NistP521 => bssl_bare_sys::NID_secp521r1,
            #[cfg(any(
                feature = "ecc_bn_p256",
                feature = "ecc_bn_p638",
                feature = "ecc_bp_p256_r1",
                feature = "ecc_bp_p384_r1",
                feature = "ecc_bp_p512_r1",
                feature = "ecc_sm2_p256"
            ))]
            _ => compile_error!("Only NIST curves are supported with Boring SSL backend"),
        };

        let bssl_ec_group = unsafe { bssl_bare_sys::EC_GROUP_new_by_curve_name(curve_nid) };
        let bssl_ec_group = ptr::NonNull::new(bssl_ec_group).ok_or_else(bssl_get_error)?;
        let curve_ops = Self { curve, bssl_ec_group };

        if cfg!(debug_assertions) {
            // Verify that the parameters from BoringSSL and the ones provided through
            // 'curve' match.
            let mut bn_ctx = BsslBnCtx::new()?;
            let mut bssl_p = BsslBn::new()?;
            let mut bssl_a = BsslBn::new()?;
            let mut bssl_b = BsslBn::new()?;
            if unsafe {
                bssl_bare_sys::EC_GROUP_get_curve_GFp(
                    curve_ops.bssl_ec_group.as_ptr(),
                    bssl_p.as_mut_ptr(),
                    bssl_a.as_mut_ptr(),
                    bssl_b.as_mut_ptr(),
                    bn_ctx.as_mut_ptr(),
                )
            } == 0
            {
                return Err(bssl_get_error());
            }
            let curve_p = BsslBn::try_from(curve.get_p())?;
            if unsafe { bssl_bare_sys::BN_ucmp(curve_p.as_ptr(), bssl_p.as_ptr()) } != 0 {
                return Err(CryptoError::Internal);
            }
            drop(curve_p);
            drop(bssl_p);

            let (curve_a, curve_b) = curve.get_curve_coefficients();
            let curve_a = BsslBn::try_from(curve_a)?;
            if unsafe { bssl_bare_sys::BN_ucmp(curve_a.as_ptr(), bssl_a.as_ptr()) } != 0 {
                return Err(CryptoError::Internal);
            }
            drop(curve_a);
            drop(bssl_a);
            let curve_b = BsslBn::try_from(curve_b)?;
            if unsafe { bssl_bare_sys::BN_ucmp(curve_b.as_ptr(), bssl_b.as_ptr()) } != 0 {
                return Err(CryptoError::Internal);
            }
            drop(curve_b);
            drop(bssl_b);

            // Ownership of the returned BIGNUM remains at the EC_GROUP.
            let bssl_order = unsafe { bssl_bare_sys::EC_GROUP_get0_order(curve_ops.bssl_ec_group.as_ptr()) };
            if bssl_order.is_null() {
                return Err(bssl_get_error());
            }
            let curve_order = BsslBn::try_from(curve.get_order())?;
            if unsafe { bssl_bare_sys::BN_ucmp(curve_order.as_ptr(), bssl_order) } != 0 {
                return Err(CryptoError::Internal);
            }
            drop(curve_order);

            let mut bssl_cofactor = BsslBn::new()?;
            if unsafe {
                bssl_bare_sys::EC_GROUP_get_cofactor(
                    curve_ops.bssl_ec_group.as_ptr(),
                    bssl_cofactor.as_mut_ptr(),
                    bn_ctx.as_mut_ptr(),
                )
            } == 0
            {
                return Err(bssl_get_error());
            }
            let mut curve_cofactor = BsslBn::new()?;
            if unsafe {
                bssl_bare_sys::BN_set_bit(curve_cofactor.as_mut_ptr(), curve.get_cofactor_log2() as ffi::c_int)
            } == 0
            {
                return Err(bssl_get_error());
            }
            if unsafe { bssl_bare_sys::BN_ucmp(curve_cofactor.as_ptr(), bssl_cofactor.as_ptr()) } != 0 {
                return Err(CryptoError::Internal);
            }
            drop(curve_cofactor);
            drop(bssl_cofactor);

            let bssl_generator = unsafe { bssl_bare_sys::EC_GROUP_get0_generator(curve_ops.bssl_ec_group.as_ptr()) };
            if bssl_generator.is_null() {
                return Err(bssl_get_error());
            }
            let (curve_generator_x, curve_generator_y) = curve.get_generator_coordinates();
            let curve_generator =
                AffinePoint::try_from_plain_coordinates(&curve_generator_x, &curve_generator_y, &curve_ops)?;
            let r = unsafe {
                bssl_bare_sys::EC_POINT_cmp(
                    curve_ops.bssl_ec_group.as_ptr(),
                    curve_generator.bssl_ec_point,
                    bssl_generator,
                    bn_ctx.as_mut_ptr(),
                )
            };
            if r < 0 {
                return Err(bssl_get_error());
            } else if r != 0 {
                return Err(CryptoError::Internal);
            }
        }

        Ok(curve_ops)
    }

    /// Allocate a [`CurveOpsScratch`] instance suitable for use with this
    /// `CurveOps`.
    pub fn try_alloc_scratch(&self) -> Result<CurveOpsScratch, CryptoError> {
        CurveOpsScratch::try_new()
    }

    /// Get the curve's (subgroup) generator point in [`AffinePoint`]
    /// representation.
    pub fn generator(&self) -> Result<AffinePoint, CryptoError> {
        // The returned point is borrowed in that it ownership is retained at the
        // EC_GROUP. In particular its lifetime is bound to that.
        let borrowed_generator: *const bssl_bare_sys::EC_POINT =
            unsafe { bssl_bare_sys::EC_GROUP_get0_generator(self.bssl_ec_group.as_ptr()) };
        if borrowed_generator.is_null() {
            return Err(bssl_get_error());
        }

        // Make a clone to disentangle it from the EC_GROUP's lifetime.
        let cloned_generator = unsafe { bssl_bare_sys::EC_POINT_dup(borrowed_generator, self.bssl_ec_group.as_ptr()) };
        if cloned_generator.is_null() {
            return Err(bssl_get_error());
        }

        Ok(AffinePoint {
            bssl_ec_point: cloned_generator,
        })
    }

    /// Get the associated curve.
    pub fn get_curve(&self) -> &curve::Curve {
        self.curve
    }

    /// Multiply a scalar with a curve point.
    fn _point_scalar_mul<ST: cmpa::MpUIntCommon>(
        &self,
        scalar: &ST,
        point: &AffinePoint,
        scratch: &mut CurveOpsScratch,
    ) -> Result<ProjectivePoint, CryptoError> {
        // The scalar is always strictly less than the order, except for the
        // point_is_in_generator_subgroup() check.
        debug_assert!(scalar.len_is_compatible_with(self.curve.get_nbits().div_ceil(8)));
        debug_assert!(cmpa::ct_gt_mp_mp(scalar, &self.curve.get_order()).unwrap() == 0);
        let scalar = BsslBn::try_from_cmpa_mp_uint(scalar)?;
        let result = unsafe { bssl_bare_sys::EC_POINT_new(self.bssl_ec_group.as_ptr()) };
        if result.is_null() {
            return Err(bssl_get_error());
        }
        if unsafe {
            bssl_bare_sys::EC_POINT_mul(
                self.bssl_ec_group.as_ptr(),
                result,
                ptr::null(),
                point.bssl_ec_point,
                scalar.as_ptr(),
                scratch.bn_ctx.as_mut_ptr(),
            )
        } == 0
        {
            unsafe { bssl_bare_sys::EC_POINT_clear_free(result) };
            return Err(bssl_get_error());
        }

        Ok(ProjectivePoint { bssl_ec_point: result })
    }

    /// Multiply a scalar with a curve point.
    pub fn point_scalar_mul<ST: cmpa::MpUIntCommon>(
        &self,
        scalar: &ST,
        point: &AffinePoint,
        scratch: &mut CurveOpsScratch,
    ) -> Result<ProjectivePoint, CryptoError> {
        self.curve.validate_scalar(scalar)?;
        self._point_scalar_mul(scalar, point, scratch)
    }

    /// Add two curve points.
    pub fn point_add(
        &self,
        op0: &ProjectivePoint,
        op1: &ProjectivePoint,
        scratch: &mut CurveOpsScratch,
    ) -> Result<ProjectivePoint, CryptoError> {
        let result = unsafe { bssl_bare_sys::EC_POINT_new(self.bssl_ec_group.as_ptr()) };
        if result.is_null() {
            return Err(bssl_get_error());
        }

        if unsafe {
            bssl_bare_sys::EC_POINT_add(
                self.bssl_ec_group.as_ptr(),
                result,
                op0.bssl_ec_point,
                op1.bssl_ec_point,
                scratch.bn_ctx.as_mut_ptr(),
            )
        } == 0
        {
            unsafe { bssl_bare_sys::EC_POINT_clear_free(result) };
            return Err(bssl_get_error());
        }

        Ok(ProjectivePoint { bssl_ec_point: result })
    }

    /// Double a curve point a specified number of times.
    pub fn point_double_repeated(
        &self,
        op0: ProjectivePoint,
        mut repeat_count: u8,
        scratch: &mut CurveOpsScratch,
    ) -> Result<ProjectivePoint, CryptoError> {
        if repeat_count == 0 {
            let cloned = unsafe { bssl_bare_sys::EC_POINT_dup(op0.bssl_ec_point, self.bssl_ec_group.as_ptr()) };
            if cloned.is_null() {
                return Err(bssl_get_error());
            }
            return Ok(ProjectivePoint { bssl_ec_point: cloned });
        }

        let dbl_dst = unsafe { bssl_bare_sys::EC_POINT_new(self.bssl_ec_group.as_ptr()) };
        if dbl_dst.is_null() {
            return Err(bssl_get_error());
        }
        if unsafe {
            bssl_bare_sys::EC_POINT_dbl(
                self.bssl_ec_group.as_ptr(),
                dbl_dst,
                op0.bssl_ec_point,
                scratch.bn_ctx.as_mut_ptr(),
            )
        } == 0
        {
            unsafe { bssl_bare_sys::EC_POINT_clear_free(dbl_dst) };
            return Err(bssl_get_error());
        }
        repeat_count -= 1;
        if repeat_count == 0 {
            return Ok(ProjectivePoint { bssl_ec_point: dbl_dst });
        }

        let mut dbl_src = dbl_dst;
        let mut dbl_dst = unsafe { bssl_bare_sys::EC_POINT_new(self.bssl_ec_group.as_ptr()) };
        if dbl_dst.is_null() {
            unsafe { bssl_bare_sys::EC_POINT_clear_free(dbl_src) };
            return Err(bssl_get_error());
        }
        while repeat_count != 0 {
            if unsafe {
                bssl_bare_sys::EC_POINT_dbl(
                    self.bssl_ec_group.as_ptr(),
                    dbl_dst,
                    dbl_src,
                    scratch.bn_ctx.as_mut_ptr(),
                )
            } == 0
            {
                unsafe { bssl_bare_sys::EC_POINT_clear_free(dbl_dst) };
                return Err(bssl_get_error());
            }
            repeat_count -= 1;
            mem::swap(&mut dbl_src, &mut dbl_dst);
        }

        unsafe { bssl_bare_sys::EC_POINT_clear_free(dbl_dst) };
        Ok(ProjectivePoint { bssl_ec_point: dbl_src })
    }

    /// Test whether a point is on the curve.
    pub fn point_is_on_curve(
        &self,
        point: &AffinePoint,
        mut scratch: Option<&mut CurveOpsScratch>,
    ) -> Result<bool, CryptoError> {
        let mut bn_ctx: Option<BsslBnCtx> = None;
        let bn_ctx = if let Some(scratch) = scratch.as_mut() {
            &mut scratch.bn_ctx
        } else {
            bn_ctx.insert(BsslBnCtx::new()?)
        };
        let r = unsafe {
            bssl_bare_sys::EC_POINT_is_on_curve(self.bssl_ec_group.as_ptr(), point.bssl_ec_point, bn_ctx.as_mut_ptr())
        };
        if r < 0 {
            return Err(bssl_get_error());
        }

        Ok(r != 0)
    }

    /// Test whether a point is in the subgroup generated by the [generator
    /// point](Self::generator).
    pub fn point_is_in_generator_subgroup(
        &self,
        point: &AffinePoint,
        scratch: &mut CurveOpsScratch,
    ) -> Result<bool, CryptoError> {
        if !self.point_is_on_curve(point, Some(scratch))? {
            return Ok(false);
        }

        // C.f. NIST SP800-65Ar3, section 5.6.2.3.3 ("ECC Full Public-Key
        // Validation Routine") or NIST SP800-186, section D.1.1.2.
        // ("Full Public Key Validation"). If the cofactor equals one,
        // this test could be skipped. But NIST says otherwise, so do
        // it.
        let identity = self._point_scalar_mul(&self.curve.get_order(), point, scratch)?;
        let r = unsafe { bssl_bare_sys::EC_POINT_is_at_infinity(self.bssl_ec_group.as_ptr(), identity.bssl_ec_point) };
        if r < 0 {
            return Err(bssl_get_error());
        }
        Ok(r != 0)
    }

    /// Generate an EC key with the implementation backend's key generation
    /// method of choice.
    ///
    /// # Arguments:
    ///
    /// * `rng` - The random number generator to draw random bytes from. It
    ///   might not get invoked by the backend in case that draws randomness
    ///   from some alternative internal rng instance.
    /// * `additional_rng_generate_input` - Additional input to pass along to
    ///   the `rng`'s [generate()](rng::RngCore::generate) primitive.
    pub fn generate_key(
        &self,
        _rng: &mut dyn rng::RngCoreDispatchable,
        _additional_rng_generate_input: Option<&[Option<&[u8]>]>,
    ) -> Result<key::EccKey, CryptoError> {
        let bssl_ec_key = BsslEcKey::generate(self)?;
        let (public_point, private_key) = bssl_ec_key.to_key_pair(self)?;
        Ok(key::EccKey::new_from_raw(
            self.curve.get_curve_id(),
            public_point,
            private_key,
        ))
    }
}

impl<'a> Drop for CurveOps<'a> {
    fn drop(&mut self) {
        unsafe {
            bssl_bare_sys::EC_GROUP_free(self.bssl_ec_group.as_mut());
        }
    }
}
