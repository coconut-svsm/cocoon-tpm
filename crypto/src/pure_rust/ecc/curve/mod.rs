// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Pure Rust backend for ECC point operations.

extern crate alloc;
use alloc::vec::Vec;

use crate::{ecc::{curve, key}, rng};
use crate::utils_common::{
    alloc::{try_alloc_vec, try_alloc_zeroizing_vec},
    zeroize,
};
use crate::CryptoError;
use cmpa::{self, MpMutUInt as _, MpUIntCommon as _};

mod weierstrass_arithmetic;

/// Operations on a curve's associated scalar prime field.
///
/// Most notably conversion of scalars to and from Montgomery form and
/// arithmetic on such ones.
struct CurveFieldOps {
    p: cmpa::MpBigEndianUIntByteSlice<'static>,
    mg_neg_p0_inv_mod_l: cmpa::LimbType,
    mg_radix2_mod_p: Vec<cmpa::LimbType>,
}

impl CurveFieldOps {
    /// Create a `CurveFieldOps` instance.
    ///
    /// # Arguments:
    ///
    /// * `p` - The scalar field's prime.
    fn try_new(p: cmpa::MpBigEndianUIntByteSlice<'static>) -> Result<Self, CryptoError> {
        let mut mg_radix2_mod_p =
            try_alloc_vec::<cmpa::LimbType>(cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(p.len()))?;

        cmpa::ct_montgomery_radix2_mod_n_mp(
            &mut cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut mg_radix2_mod_p),
            &p,
        )
        .unwrap();
        let mg_neg_p0_inv_mod_l = cmpa::ct_montgomery_neg_n0_inv_mod_l_mp(&p).map_err(|_| CryptoError::Internal)?;
        Ok(Self {
            p,
            mg_radix2_mod_p,
            mg_neg_p0_inv_mod_l,
        })
    }

    /// Get the scalar field's prime.
    #[allow(unused)]
    pub fn get_p(&self) -> &cmpa::MpBigEndianUIntByteSlice<'_> {
        &self.p
    }

    /// Convert a scalar back from Montomery form.
    fn convert_from_mg_form(&self, element: &mut cmpa::MpMutNativeEndianUIntLimbsSlice) {
        debug_assert!(self.p.len_is_compatible_with(element.len()));
        debug_assert_ne!(cmpa::ct_lt_mp_mp(element, &self.p).unwrap(), 0);
        cmpa::ct_montgomery_redc_mp(element, &self.p, self.mg_neg_p0_inv_mod_l).unwrap();
    }

    fn _convert_to_mg_form<ET: cmpa::MpUIntCommon>(
        &self,
        mg_result: &mut cmpa::MpMutNativeEndianUIntLimbsSlice,
        element: &ET,
    ) {
        debug_assert_ne!(cmpa::ct_lt_mp_mp(element, &self.p).unwrap(), 0);
        debug_assert!(self.p.len_is_compatible_with(mg_result.len()));

        cmpa::ct_to_montgomery_form_mp(
            mg_result,
            element,
            &self.p,
            self.mg_neg_p0_inv_mod_l,
            &self.get_mg_radix2_mod_p(),
        )
        .unwrap();
    }

    /// Convert scalar to Montomery form.
    fn convert_to_mg_form<ET: cmpa::MpUIntCommon>(&self, element: &ET) -> Result<Vec<cmpa::LimbType>, CryptoError> {
        let mut mg_element_buf =
            try_alloc_vec::<cmpa::LimbType>(cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(self.p.len()))?;
        let mut mg_element = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut mg_element_buf);
        self._convert_to_mg_form(&mut mg_element, element);
        Ok(mg_element_buf)
    }

    /// Compute the Montgomery form of the scalar prime field's unit.
    fn mg_identity(&self) -> Result<Vec<cmpa::LimbType>, CryptoError> {
        let mut mg_identity_buf =
            try_alloc_vec::<cmpa::LimbType>(cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(self.p.len()))?;
        let mut mg_identity = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut mg_identity_buf);
        mg_identity.copy_from(&self.get_mg_radix2_mod_p());
        cmpa::ct_montgomery_redc_mp(&mut mg_identity, &self.p, self.mg_neg_p0_inv_mod_l).unwrap();
        Ok(mg_identity_buf)
    }

    /// Get *(Montgomery radix)<sup>2</sup> mod p*.
    fn get_mg_radix2_mod_p(&self) -> cmpa::MpNativeEndianUIntLimbsSlice<'_> {
        cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&self.mg_radix2_mod_p)
    }

    /// Add two scalars in Montgomery form.
    pub fn add<T1: cmpa::MpUIntCommon>(&self, mg_op0: &mut cmpa::MpMutNativeEndianUIntLimbsSlice, mg_op1: &T1) {
        cmpa::ct_add_mod_mp_mp(mg_op0, mg_op1, &self.p).unwrap();
    }

    /// Subtract two scalars in Montgomery form.
    pub fn sub<T1: cmpa::MpUIntCommon>(&self, mg_op0: &mut cmpa::MpMutNativeEndianUIntLimbsSlice, mg_op1: &T1) {
        cmpa::ct_sub_mod_mp_mp(mg_op0, mg_op1, &self.p).unwrap();
    }

    /// Multiply two scalars in Montgomery form.
    pub fn mul<T0: cmpa::MpUIntCommon, T1: cmpa::MpUIntCommon>(
        &self,
        mg_result: &mut cmpa::MpMutNativeEndianUIntLimbsSlice,
        mg_op0: &T0,
        mg_op1: &T1,
    ) {
        cmpa::ct_montgomery_mul_mod_mp_mp(mg_result, mg_op0, mg_op1, &self.p, self.mg_neg_p0_inv_mod_l).unwrap();
    }
}

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
    /// x component in Montgomery form.
    mg_x: zeroize::Zeroizing<Vec<cmpa::LimbType>>,
    /// y component in Montgomery form.
    mg_y: zeroize::Zeroizing<Vec<cmpa::LimbType>>,
}

impl AffinePoint {
    fn _try_from_plain_coordinates(
        x: &cmpa::MpBigEndianUIntByteSlice,
        y: &cmpa::MpBigEndianUIntByteSlice,
        field_ops: &CurveFieldOps,
    ) -> Result<Self, CryptoError> {
        let mg_x = field_ops.convert_to_mg_form(x)?;
        let mg_x = zeroize::Zeroizing::from(mg_x);
        let mg_y = field_ops.convert_to_mg_form(y)?;
        let mg_y = zeroize::Zeroizing::from(mg_y);
        Ok(Self { mg_x, mg_y })
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
        let field_ops = curve_ops.get_field_ops();
        if !x.len_is_compatible_with(field_ops.p.len())
            || !y.len_is_compatible_with(field_ops.p.len())
            || cmpa::ct_geq_mp_mp(x, &field_ops.p).unwrap() != 0
            || cmpa::ct_geq_mp_mp(y, &field_ops.p).unwrap() != 0
        {
            return Err(CryptoError::InvalidPoint);
        }
        Self::_try_from_plain_coordinates(x, y, field_ops)
    }

    /// Convert an `AffinePoint` into "plain" affine coordinates.
    ///
    /// May save a scratch buffer allocation as compared to
    /// [`to_plain_coordinates()`](Self::to_plain_coordinates), depending on the
    /// backend implementation.
    pub fn into_plain_coordinates(
        mut self,
        result_x: &mut cmpa::MpMutBigEndianUIntByteSlice,
        result_y: Option<&mut cmpa::MpMutBigEndianUIntByteSlice>,
        curve_ops: &CurveOps,
    ) -> Result<(), CryptoError> {
        let field_ops = curve_ops.get_field_ops();
        debug_assert!(field_ops.p.len_is_compatible_with(result_x.len()));
        let mut src_x = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut self.mg_x);
        field_ops.convert_from_mg_form(&mut src_x);
        result_x.copy_from(&src_x);
        if let Some(result_y) = result_y {
            debug_assert!(field_ops.p.len_is_compatible_with(result_y.len()));
            let mut src_y = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut self.mg_y);
            field_ops.convert_from_mg_form(&mut src_y);
            result_y.copy_from(&src_y);
        }

        Ok(())
    }

    /// Convert an `AffinePoint` to "plain" affine coordinates.
    pub fn to_plain_coordinates(
        &self,
        result_x: &mut cmpa::MpMutBigEndianUIntByteSlice,
        result_y: Option<&mut cmpa::MpMutBigEndianUIntByteSlice>,
        curve_ops: &CurveOps,
    ) -> Result<(), CryptoError> {
        let field_ops = curve_ops.get_field_ops();
        debug_assert!(field_ops.p.len_is_compatible_with(result_x.len()));
        let mut scratch = try_alloc_zeroizing_vec::<cmpa::LimbType>(
            cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(field_ops.p.len()),
        )?;
        let mut scratch = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch);
        let (mg_x, mg_y) = self.get_mg_coordinates();
        scratch.copy_from(&mg_x);
        field_ops.convert_from_mg_form(&mut scratch);
        result_x.copy_from(&scratch);
        if let Some(result_y) = result_y {
            debug_assert!(field_ops.p.len_is_compatible_with(result_y.len()));
            scratch.copy_from(&mg_y);
            field_ops.convert_from_mg_form(&mut scratch);
            result_y.copy_from(&scratch);
        }
        Ok(())
    }

    /// Convert into [`ProjectivePoint`] representation.
    #[allow(unused)]
    pub fn into_projective(self, curve_ops: &CurveOps) -> Result<ProjectivePoint, CryptoError> {
        let field_ops = curve_ops.get_field_ops();
        let mg_z = zeroize::Zeroizing::from(field_ops.mg_identity()?);
        Ok(ProjectivePoint {
            mg_x: self.mg_x,
            mg_y: self.mg_y,
            mg_z,
        })
    }

    /// Access the coordinates in Montgomery form.
    fn get_mg_coordinates(&self) -> (cmpa::MpNativeEndianUIntLimbsSlice<'_>, cmpa::MpNativeEndianUIntLimbsSlice<'_>) {
        (
            cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&self.mg_x),
            cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&self.mg_y),
        )
    }
}

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
    /// x component in Montgomery form.
    mg_x: zeroize::Zeroizing<Vec<cmpa::LimbType>>,
    /// y component in Montgomery form.
    mg_y: zeroize::Zeroizing<Vec<cmpa::LimbType>>,
    /// z component in Montgomery form.
    mg_z: zeroize::Zeroizing<Vec<cmpa::LimbType>>,
}

impl ProjectivePoint {
    /// Create the neutal element in the ECC group.
    fn try_new_identity(field_ops: &CurveFieldOps) -> Result<Self, CryptoError> {
        let p_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(field_ops.p.len());
        let mg_x_buf = try_alloc_zeroizing_vec::<cmpa::LimbType>(p_nlimbs)?;
        let mg_y_buf = field_ops.mg_identity()?;
        let mg_z_buf = try_alloc_zeroizing_vec::<cmpa::LimbType>(p_nlimbs)?;
        Ok(Self {
            mg_x: mg_x_buf,
            mg_y: zeroize::Zeroizing::from(mg_y_buf),
            mg_z: mg_z_buf,
        })
    }

    /// Create a new projective point with all three coordinates initialized to
    /// zero.
    fn try_new(p_len: usize) -> Result<Self, CryptoError> {
        let p_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(p_len);
        let mg_x_buf = try_alloc_zeroizing_vec::<cmpa::LimbType>(p_nlimbs)?;
        let mg_y_buf = try_alloc_zeroizing_vec::<cmpa::LimbType>(p_nlimbs)?;
        let mg_z_buf = try_alloc_zeroizing_vec::<cmpa::LimbType>(p_nlimbs)?;
        Ok(Self {
            mg_x: mg_x_buf,
            mg_y: mg_y_buf,
            mg_z: mg_z_buf,
        })
    }

    /// Access the point's coordinates in Montgomery form.
    fn get_mg_coordinates(
        &self,
    ) -> (
        cmpa::MpNativeEndianUIntLimbsSlice<'_>,
        cmpa::MpNativeEndianUIntLimbsSlice<'_>,
        cmpa::MpNativeEndianUIntLimbsSlice<'_>,
    ) {
        (
            cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&self.mg_x),
            cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&self.mg_y),
            cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&self.mg_z),
        )
    }

    /// Obtain `mut` references the point's coordinates in Montgomery form.
    fn get_mg_coordinates_mut(
        &mut self,
    ) -> (
        cmpa::MpMutNativeEndianUIntLimbsSlice<'_>,
        cmpa::MpMutNativeEndianUIntLimbsSlice<'_>,
        cmpa::MpMutNativeEndianUIntLimbsSlice<'_>,
    ) {
        (
            cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut self.mg_x),
            cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut self.mg_y),
            cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut self.mg_z),
        )
    }

    /// Overwrite with another point.
    fn copy_from(&mut self, src: &ProjectivePoint) {
        let (mut mg_x, mut mg_y, mut mg_z) = self.get_mg_coordinates_mut();
        let (src_mg_x, src_mg_y, src_mg_z) = src.get_mg_coordinates();
        mg_x.copy_from(&src_mg_x);
        mg_y.copy_from(&src_mg_y);
        mg_z.copy_from(&src_mg_z);
    }

    /// Conditionally overwrite with another point.
    fn copy_from_cond(&mut self, src: &ProjectivePoint, cond: cmpa::LimbChoice) {
        let (mut mg_x, mut mg_y, mut mg_z) = self.get_mg_coordinates_mut();
        let (src_mg_x, src_mg_y, src_mg_z) = src.get_mg_coordinates();
        mg_x.copy_from_cond(&src_mg_x, cond);
        mg_y.copy_from_cond(&src_mg_y, cond);
        mg_z.copy_from_cond(&src_mg_z, cond);
    }

    /// Convert into an [`AffinePoint`].
    pub fn into_affine(
        mut self,
        curve_ops: &CurveOps,
        scratch: Option<&mut CurveOpsScratch>,
    ) -> Result<Result<AffinePoint, curve::ProjectivePointIntoAffineError>, CryptoError> {
        let field_ops = curve_ops.get_field_ops();
        let mut scratch0: zeroize::Zeroizing<Vec<cmpa::LimbType>> = zeroize::Zeroizing::from(Vec::new());
        let mut scratch1: zeroize::Zeroizing<Vec<cmpa::LimbType>> = zeroize::Zeroizing::from(Vec::new());
        let mut scratch2: zeroize::Zeroizing<Vec<cmpa::LimbType>> = zeroize::Zeroizing::from(Vec::new());
        let (scratch0, scratch1, scratch2) = if let Some(scratch) = scratch {
            (
                &mut scratch.scratch.scratch0,
                &mut scratch.scratch.scratch1,
                &mut scratch.scratch.scratch2,
            )
        } else {
            let p_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(field_ops.p.len());
            for s in [&mut scratch0, &mut scratch1, &mut scratch2].iter_mut() {
                **s = try_alloc_zeroizing_vec::<cmpa::LimbType>(p_nlimbs)?;
            }
            (&mut scratch0, &mut scratch1, &mut scratch2)
        };

        // Redc z back from Montgomery form.
        let mut z = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut self.mg_z);
        field_ops.convert_from_mg_form(&mut z);

        // Invert z modulo p.
        let mut z_inv = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(scratch2);
        match cmpa::ct_inv_mod_odd_mp_mp(&mut z_inv, &mut z, &field_ops.p, [scratch0, scratch1]) {
            Ok(()) => (),
            Err(e) => match e {
                cmpa::CtInvModOddMpMpError::OperandsNotCoprime => {
                    return Ok(Err(curve::ProjectivePointIntoAffineError::PointIsIdentity));
                }
                _ => unreachable!(),
            },
        };
        // And bring z_inv back into Montgomery form.
        let mut mg_z_inv = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(scratch0);
        field_ops._convert_to_mg_form(&mut mg_z_inv, &z_inv);

        // Divide x and y by z.
        let Self {
            mg_x: mg_x_buf,
            mg_y: mg_y_buf,
            mg_z: mg_z_buf,
        } = self;
        let mg_x = cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&mg_x_buf);
        let mg_y = cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&mg_y_buf);
        // Recycle self.mg_z_buf for resulting x component.
        let mut affine_mg_x_buf = mg_z_buf;
        let mut affine_mg_x = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut affine_mg_x_buf);
        field_ops.mul(&mut affine_mg_x, &mg_x, &mg_z_inv);
        // Recycle self.mg_x_buf for resulting y component.
        let mut affine_mg_y_buf = mg_x_buf;
        let mut affine_mg_y = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut affine_mg_y_buf);
        field_ops.mul(&mut affine_mg_y, &mg_y, &mg_z_inv);

        Ok(Ok(AffinePoint {
            mg_x: affine_mg_x_buf,
            mg_y: affine_mg_y_buf,
        }))
    }

    /// Convert into an affine point with "plain" coordinates.
    #[allow(clippy::type_complexity)]
    pub fn into_affine_plain_coordinates(
        mut self,
        result_x: &mut cmpa::MpMutBigEndianUIntByteSlice,
        result_y: Option<&mut cmpa::MpMutBigEndianUIntByteSlice>,
        curve_ops: &CurveOps,
        scratch: Option<&mut CurveOpsScratch>,
    ) -> Result<Result<(), curve::ProjectivePointIntoAffineError>, CryptoError> {
        let field_ops = curve_ops.get_field_ops();
        let mut scratch0: zeroize::Zeroizing<Vec<cmpa::LimbType>> = zeroize::Zeroizing::from(Vec::new());
        let mut scratch1: zeroize::Zeroizing<Vec<cmpa::LimbType>> = zeroize::Zeroizing::from(Vec::new());
        let mut scratch2: zeroize::Zeroizing<Vec<cmpa::LimbType>> = zeroize::Zeroizing::from(Vec::new());
        let (scratch0, scratch1, scratch2) = if let Some(scratch) = scratch {
            (
                &mut scratch.scratch.scratch0,
                &mut scratch.scratch.scratch1,
                &mut scratch.scratch.scratch2,
            )
        } else {
            let p_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(field_ops.p.len());
            for s in [&mut scratch0, &mut scratch1, &mut scratch2].iter_mut() {
                **s = try_alloc_zeroizing_vec::<cmpa::LimbType>(p_nlimbs)?;
            }
            (&mut scratch0, &mut scratch1, &mut scratch2)
        };

        // Redc z back from Montgomery form.
        let (_, _, mut z) = self.get_mg_coordinates_mut();
        cmpa::ct_montgomery_redc_mp(&mut z, &field_ops.p, field_ops.mg_neg_p0_inv_mod_l).unwrap();

        // Invert z modulo p.
        let mut z_inv = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(scratch2);
        match cmpa::ct_inv_mod_odd_mp_mp(&mut z_inv, &mut z, &field_ops.p, [scratch0, scratch1]) {
            Ok(()) => (),
            Err(e) => match e {
                cmpa::CtInvModOddMpMpError::OperandsNotCoprime => {
                    return Ok(Err(curve::ProjectivePointIntoAffineError::PointIsIdentity));
                }
                _ => unreachable!(),
            },
        };

        // Divide x and y by z. Note that the Montgomery multiplication removes the
        // final remaining Montgomery radix factor still present in mg_x / mg_y.
        // That is, the multiplication brings the result implicitly back into
        // plain form.
        let (mg_x, mg_y, _) = self.get_mg_coordinates();
        cmpa::ct_montgomery_mul_mod_mp_mp(result_x, &mg_x, &z_inv, &field_ops.p, field_ops.mg_neg_p0_inv_mod_l)
            .unwrap();
        if let Some(result_y) = result_y {
            cmpa::ct_montgomery_mul_mod_mp_mp(result_y, &mg_y, &z_inv, &field_ops.p, field_ops.mg_neg_p0_inv_mod_l)
                .unwrap();
        }

        Ok(Ok(()))
    }
}

impl zeroize::ZeroizeOnDrop for ProjectivePoint {}

/// Scratch space for use by arithmetic primitives implemented at [`CurveOps`].
pub struct CurveOpsScratch {
    scratch: weierstrass_arithmetic::WeierstrassCurveOpsScratch,
}

impl CurveOpsScratch {
    fn try_new(p_len: usize) -> Result<Self, CryptoError> {
        let scratch = weierstrass_arithmetic::WeierstrassCurveOpsScratch::try_new(p_len)?;
        Ok(Self { scratch })
    }
}

/// ECC point arithmetic.
///
/// Never instantiated directly, but usually obtained through
/// [`Curve::curve_ops()`](curve::Curve::curve_ops).
pub struct CurveOps<'a> {
    curve: &'a curve::Curve,
    field_ops: CurveFieldOps,
    ops: weierstrass_arithmetic::WeierstrassCurveOps,
}

impl<'a> CurveOps<'a> {
    pub(crate) fn try_new(curve: &'a curve::Curve) -> Result<Self, CryptoError> {
        let field_ops = CurveFieldOps::try_new(curve.get_p())?;
        let (a, b) = curve.get_curve_coefficients();
        let ops = weierstrass_arithmetic::WeierstrassCurveOps::try_new(&field_ops, &a, &b)?;
        Ok(Self { curve, field_ops, ops })
    }

    /// Allocate a [`CurveOpsScratch`] instance suitable for use with this
    /// `CurveOps`.
    pub fn try_alloc_scratch(&self) -> Result<CurveOpsScratch, CryptoError> {
        CurveOpsScratch::try_new(self.curve.get_p_len())
    }

    /// Get the curve's (subgroup) generator point in [`AffinePoint`]
    /// representation.
    pub fn generator(&self) -> Result<AffinePoint, CryptoError> {
        let (g_x, g_y) = self.curve.get_generator_coordinates();
        AffinePoint::_try_from_plain_coordinates(&g_x, &g_y, &self.field_ops)
    }

    /// Get the associated curve.
    pub fn get_curve(&self) -> &curve::Curve {
        self.curve
    }

    /// Get the curve's `CurveFieldOps`.
    fn get_field_ops(&self) -> &CurveFieldOps {
        &self.field_ops
    }

    fn _point_scalar_mul<ST: cmpa::MpUIntCommon>(
        &self,
        scalar: &ST,
        point: &AffinePoint,
        scratch: &mut CurveOpsScratch,
    ) -> Result<ProjectivePoint, CryptoError> {
        // The scalar is always strictly less than the order, except for the
        // point_is_in_generator_subgroup() check.
        debug_assert!(scalar.len_is_compatible_with(self.curve.get_p_len()));
        debug_assert!(cmpa::ct_gt_mp_mp(scalar, &self.curve.get_order()).unwrap() == 0);
        self.ops.point_scalar_mul(
            scalar,
            self.curve.get_nbits().min(8 * scalar.len()),
            point,
            &self.field_ops,
            &mut scratch.scratch,
        )
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
        self.ops.point_add(op0, op1, &self.field_ops, &mut scratch.scratch)
    }

    /// Double a curve point a specified number of times.
    pub fn point_double_repeated(
        &self,
        op0: ProjectivePoint,
        repeat_count: u8,
        scratch: &mut CurveOpsScratch,
    ) -> Result<ProjectivePoint, CryptoError> {
        self.ops
            .point_double_repeated(op0, repeat_count, &self.field_ops, &mut scratch.scratch)
    }

    /// Test whether a point is on the curve.
    pub fn point_is_on_curve(
        &self,
        point: &AffinePoint,
        scratch: Option<&mut CurveOpsScratch>,
    ) -> Result<bool, CryptoError> {
        self.ops
            .point_is_on_curve(point, &self.field_ops, scratch.map(|s| &mut s.scratch))
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

        // C.f. NIST SP800-65Ar3, section 5.6.2.3.3 ("ECC Full Public-Key Validation
        // Routine") or NIST SP800-186, section D.1.1.2. ("Full Public Key
        // Validation"). If the cofactor equals one, this test could be skipped.
        // But NIST says otherwise, so do it.
        let identity = self._point_scalar_mul(&self.curve.get_order(), point, scratch)?;
        Ok(cmpa::ct_is_zero_mp(&identity.get_mg_coordinates().2).unwrap() != 0)
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
        rng: &mut dyn rng::RngCoreDispatchable,
        additional_rng_generate_input: Option<&[Option<&[u8]>]>,
    ) -> Result<key::EccKey, CryptoError> {
        // No special method defined for the backend.
        key::EccKey::generate_tcg_tpm2(self, rng, additional_rng_generate_input)
    }
}
