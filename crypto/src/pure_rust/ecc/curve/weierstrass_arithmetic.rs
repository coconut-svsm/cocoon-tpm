// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Arithmetic on Weierstrass curves.

extern crate alloc;
use alloc::vec::Vec;

use super::{AffinePoint, CurveFieldOps, ProjectivePoint};

use crate::utils_common::{
    alloc::{try_alloc_vec, try_alloc_zeroizing_vec},
    zeroize,
};
use crate::CryptoError;
use cmpa::{self, MpMutUInt as _, MpUIntCommon as _};
use core::array;

/// Scratch space for use by arithmetic primitives on Weierstrass curves.
pub struct WeierstrassCurveOpsScratch {
    pub scratch0: zeroize::Zeroizing<Vec<cmpa::LimbType>>,
    pub scratch1: zeroize::Zeroizing<Vec<cmpa::LimbType>>,
    pub scratch2: zeroize::Zeroizing<Vec<cmpa::LimbType>>,
    pub scratch3: zeroize::Zeroizing<Vec<cmpa::LimbType>>,
    pub scratch4: zeroize::Zeroizing<Vec<cmpa::LimbType>>,
    pub scratch5: zeroize::Zeroizing<Vec<cmpa::LimbType>>,
    pub scratch6: zeroize::Zeroizing<Vec<cmpa::LimbType>>,
}

impl WeierstrassCurveOpsScratch {
    pub fn try_new(p_len: usize) -> Result<Self, CryptoError> {
        let p_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(p_len);
        let mut scratch: [zeroize::Zeroizing<Vec<cmpa::LimbType>>; 7] =
            array::from_fn(|_| zeroize::Zeroizing::new(Vec::new()));
        for s in scratch.iter_mut() {
            *s = try_alloc_zeroizing_vec::<cmpa::LimbType>(p_nlimbs)?;
        }
        let [scratch0, scratch1, scratch2, scratch3, scratch4, scratch5, scratch6] = scratch;
        Ok(Self {
            scratch0,
            scratch1,
            scratch2,
            scratch3,
            scratch4,
            scratch5,
            scratch6,
        })
    }
}

impl zeroize::ZeroizeOnDrop for WeierstrassCurveOpsScratch {}

/// Arithmetic primitives on Weierstrass curves.
///
/// Implementation after "Complete addition formulas for prime order elliptic
/// curves", J. Renes , C. Costello, L. Batinak.
pub struct WeierstrassCurveOps {
    mg_a: Vec<cmpa::LimbType>,
    mg_b: Vec<cmpa::LimbType>,
}

impl WeierstrassCurveOps {
    pub fn try_new(
        field_ops: &CurveFieldOps,
        a: &cmpa::MpBigEndianUIntByteSlice,
        b: &cmpa::MpBigEndianUIntByteSlice,
    ) -> Result<Self, CryptoError> {
        let mg_a = field_ops.convert_to_mg_form(a)?;
        let mg_b = field_ops.convert_to_mg_form(b)?;

        Ok(Self { mg_a, mg_b })
    }

    /// Get the *a* coefficient in Montgomery form.
    fn get_mg_a(&self) -> cmpa::MpNativeEndianUIntLimbsSlice<'_> {
        cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&self.mg_a)
    }

    /// Get the *b* coefficient in Montgomery form.
    fn get_mg_b(&self) -> cmpa::MpNativeEndianUIntLimbsSlice<'_> {
        cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&self.mg_b)
    }

    /// Compute *3 * b* in Montgomery form.
    fn prepare_mg_b3(&self, field_ops: &CurveFieldOps) -> Result<Vec<cmpa::LimbType>, CryptoError> {
        // Compute 3 * b in Montgomery form.
        let mut mg_b3_buf =
            try_alloc_vec::<cmpa::LimbType>(cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(field_ops.p.len()))?;
        let mut mg_b3 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut mg_b3_buf);
        let mg_b = self.get_mg_b();
        mg_b3.copy_from(&mg_b);
        field_ops.add(&mut mg_b3, &mg_b);
        field_ops.add(&mut mg_b3, &mg_b);
        Ok(mg_b3_buf)
    }

    /// Implementation of point doubling.
    fn _point_double(
        result: &mut ProjectivePoint,
        op0: &ProjectivePoint,
        field_ops: &CurveFieldOps,
        mg_a: &cmpa::MpNativeEndianUIntLimbsSlice,
        mg_b3: &cmpa::MpNativeEndianUIntLimbsSlice,
        scratch: &mut WeierstrassCurveOpsScratch,
    ) {
        // Implementation after "Complete addition formulas for prime order elliptic
        // curves", J. Renes , C. Costello, L. Batinak, Algorithm 3.
        let (mg_x, mg_y, mg_z) = op0.get_mg_coordinates();
        let (mut mg_x3, mut mg_y3, mut mg_z3) = result.get_mg_coordinates_mut();

        let mut t0 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch.scratch0);
        let mut t1 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch.scratch1);
        let mut t2 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch.scratch2);
        let mut t3 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch.scratch3);
        let mut scratch = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch.scratch4);

        // Step 1.
        field_ops.mul(&mut t0, &mg_x, &mg_x);

        // Step 2.
        field_ops.mul(&mut t1, &mg_y, &mg_y);

        // Step 3.
        field_ops.mul(&mut t2, &mg_z, &mg_z);

        // Step 4.
        field_ops.mul(&mut t3, &mg_x, &mg_y);

        // Step 5.
        scratch.copy_from(&t3);
        field_ops.add(&mut t3, &scratch);

        // Step 6.
        field_ops.mul(&mut mg_z3, &mg_x, &mg_z);

        // Step 7.
        scratch.copy_from(&mg_z3);
        field_ops.add(&mut mg_z3, &scratch);

        // Step 8.
        field_ops.mul(&mut mg_x3, mg_a, &mg_z3);

        // Step 9.
        field_ops.mul(&mut mg_y3, mg_b3, &t2);

        // Step 10.
        field_ops.add(&mut mg_y3, &mg_x3);

        // Step 11.
        mg_x3.copy_from(&t1);
        field_ops.sub(&mut mg_x3, &mg_y3);

        // Step 12.
        field_ops.add(&mut mg_y3, &t1);

        // Step 13.
        scratch.copy_from(&mg_y3);
        field_ops.mul(&mut mg_y3, &mg_x3, &scratch);

        // Step 14.
        scratch.copy_from(&mg_x3);
        field_ops.mul(&mut mg_x3, &t3, &scratch);

        // Step 15.
        scratch.copy_from(&mg_z3);
        field_ops.mul(&mut mg_z3, mg_b3, &scratch);

        // Step 16.
        scratch.copy_from(&t2);
        field_ops.mul(&mut t2, mg_a, &scratch);

        // Step 17.
        t3.copy_from(&t0);
        field_ops.sub(&mut t3, &t2);

        // Step 18.
        scratch.copy_from(&t3);
        field_ops.mul(&mut t3, mg_a, &scratch);

        // Step 19.
        field_ops.add(&mut t3, &mg_z3);

        // Step 20.
        mg_z3.copy_from(&t0);
        field_ops.add(&mut mg_z3, &t0);

        // Step 21.
        field_ops.add(&mut t0, &mg_z3);

        // Step 22.
        field_ops.add(&mut t0, &t2);

        // Step 23.
        scratch.copy_from(&t0);
        field_ops.mul(&mut t0, &scratch, &t3);

        // Step 24.
        field_ops.add(&mut mg_y3, &t0);

        // Step 25.
        field_ops.mul(&mut t2, &mg_y, &mg_z);

        // Step 26.
        scratch.copy_from(&t2);
        field_ops.add(&mut t2, &scratch);

        // Step 27.
        field_ops.mul(&mut t0, &t2, &t3);

        // Step 28.
        field_ops.sub(&mut mg_x3, &t0);

        // Step 29.
        field_ops.mul(&mut mg_z3, &t2, &t1);

        // Step 30.
        scratch.copy_from(&mg_z3);
        field_ops.add(&mut mg_z3, &scratch);

        // Step 31.
        scratch.copy_from(&mg_z3);
        field_ops.add(&mut mg_z3, &scratch);
    }

    /// Implementation of point addition: projective + affine.
    #[allow(clippy::too_many_arguments)]
    fn _point_add_mixed(
        result: &mut ProjectivePoint,
        op0: &ProjectivePoint,
        op1: &AffinePoint,
        field_ops: &CurveFieldOps,
        mg_a: &cmpa::MpNativeEndianUIntLimbsSlice,
        mg_b3: &cmpa::MpNativeEndianUIntLimbsSlice,
        scratch: &mut WeierstrassCurveOpsScratch,
    ) {
        // Implementation after "Complete addition formulas for prime order elliptic
        // curves", J. Renes , C. Costello, L. Batinak, Algorithm 2.
        let (mg_x1, mg_y1, mg_z1) = op0.get_mg_coordinates();
        let (mg_x2, mg_y2) = op1.get_mg_coordinates();
        let (mut mg_x3, mut mg_y3, mut mg_z3) = result.get_mg_coordinates_mut();

        let mut t0 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch.scratch0);
        let mut t1 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch.scratch1);
        let mut t2 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch.scratch2);
        let mut t3 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch.scratch3);
        let mut t4 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch.scratch4);
        let mut t5 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch.scratch5);
        let mut scratch = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch.scratch6);

        // Step 1.
        field_ops.mul(&mut t0, &mg_x1, &mg_x2);

        // Step 2.
        field_ops.mul(&mut t1, &mg_y1, &mg_y2);

        // Step 3.
        t3.copy_from(&mg_x2);
        field_ops.add(&mut t3, &mg_y2);

        // Step 4.
        t4.copy_from(&mg_x1);
        field_ops.add(&mut t4, &mg_y1);

        // Step 5.
        scratch.copy_from(&t3);
        field_ops.mul(&mut t3, &scratch, &t4);

        // Step 6.
        t4.copy_from(&t0);
        field_ops.add(&mut t4, &t1);

        // Step 7.
        field_ops.sub(&mut t3, &t4);

        // Step 8.
        field_ops.mul(&mut t4, &mg_x2, &mg_z1);

        // Step 9.
        field_ops.add(&mut t4, &mg_x1);

        // Step 10.
        field_ops.mul(&mut t5, &mg_y2, &mg_z1);

        // Step 11.
        field_ops.add(&mut t5, &mg_y1);

        // Step 12.
        field_ops.mul(&mut mg_z3, mg_a, &t4);

        // Step 13.
        field_ops.mul(&mut mg_x3, mg_b3, &mg_z1);

        // Step 14.
        field_ops.add(&mut mg_z3, &mg_x3);

        // Step 15.
        mg_x3.copy_from(&t1);
        field_ops.sub(&mut mg_x3, &mg_z3);

        // Step 16.
        field_ops.add(&mut mg_z3, &t1);

        // Step 17.
        field_ops.mul(&mut mg_y3, &mg_x3, &mg_z3);

        // Step 18.
        t1.copy_from(&t0);
        field_ops.add(&mut t1, &t0);

        // Step 19.
        field_ops.add(&mut t1, &t0);

        // Step 20.
        field_ops.mul(&mut t2, mg_a, &mg_z1);

        // Step 21.
        scratch.copy_from(&t4);
        field_ops.mul(&mut t4, mg_b3, &scratch);

        // Step 22.
        field_ops.add(&mut t1, &t2);

        // Step 23.
        scratch.copy_from(&t2);
        t2.copy_from(&t0);
        field_ops.sub(&mut t2, &scratch);

        // Step 24.
        scratch.copy_from(&t2);
        field_ops.mul(&mut t2, mg_a, &scratch);

        // Step 25.
        field_ops.add(&mut t4, &t2);

        // Step 26.
        field_ops.mul(&mut t0, &t1, &t4);

        // Step 27.
        field_ops.add(&mut mg_y3, &t0);

        // Step 28.
        field_ops.mul(&mut t0, &t5, &t4);

        // Step 29.
        scratch.copy_from(&mg_x3);
        field_ops.mul(&mut mg_x3, &t3, &scratch);

        // Step 30.
        field_ops.sub(&mut mg_x3, &t0);

        // Step 31.
        field_ops.mul(&mut t0, &t3, &t1);

        // Step 32.
        scratch.copy_from(&mg_z3);
        field_ops.mul(&mut mg_z3, &t5, &scratch);

        // Step 33.
        field_ops.add(&mut mg_z3, &t0);
    }

    /// Implementation of point addition: projective + projective.
    #[allow(clippy::too_many_arguments)]
    fn _point_add(
        result: &mut ProjectivePoint,
        op0: &ProjectivePoint,
        op1: &ProjectivePoint,
        field_ops: &CurveFieldOps,
        mg_a: &cmpa::MpNativeEndianUIntLimbsSlice,
        mg_b3: &cmpa::MpNativeEndianUIntLimbsSlice,
        scratch: &mut WeierstrassCurveOpsScratch,
    ) {
        // Implementation after "Complete addition formulas for prime order elliptic
        // curves", J. Renes , C. Costello, L. Batinak, Algorithm 1.
        let (mg_x1, mg_y1, mg_z1) = op0.get_mg_coordinates();
        let (mg_x2, mg_y2, mg_z2) = op1.get_mg_coordinates();
        let (mut mg_x3, mut mg_y3, mut mg_z3) = result.get_mg_coordinates_mut();

        let mut t0 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch.scratch0);
        let mut t1 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch.scratch1);
        let mut t2 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch.scratch2);
        let mut t3 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch.scratch3);
        let mut t4 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch.scratch4);
        let mut t5 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch.scratch5);
        let mut scratch = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch.scratch6);

        // Step 1.
        field_ops.mul(&mut t0, &mg_x1, &mg_x2);

        // Step 2.
        field_ops.mul(&mut t1, &mg_y1, &mg_y2);

        // Step 3.
        field_ops.mul(&mut t2, &mg_z1, &mg_z2);

        // Step 4.
        t3.copy_from(&mg_x1);
        field_ops.add(&mut t3, &mg_y1);

        // Step 5.
        t4.copy_from(&mg_x2);
        field_ops.add(&mut t4, &mg_y2);

        // Step 6.
        scratch.copy_from(&t3);
        field_ops.mul(&mut t3, &scratch, &t4);

        // Step 7.
        t4.copy_from(&t0);
        field_ops.add(&mut t4, &t1);

        // Step 8.
        field_ops.sub(&mut t3, &t4);

        // Step 9.
        t4.copy_from(&mg_x1);
        field_ops.add(&mut t4, &mg_z1);

        // Step 10.
        t5.copy_from(&mg_x2);
        field_ops.add(&mut t5, &mg_z2);

        // Step 11.
        scratch.copy_from(&t4);
        field_ops.mul(&mut t4, &scratch, &t5);

        // Step 12.
        t5.copy_from(&t0);
        field_ops.add(&mut t5, &t2);

        // Step 13.
        field_ops.sub(&mut t4, &t5);

        // Step 14.
        t5.copy_from(&mg_y1);
        field_ops.add(&mut t5, &mg_z1);

        // Step 15.
        mg_x3.copy_from(&mg_y2);
        field_ops.add(&mut mg_x3, &mg_z2);

        // Step 16.
        scratch.copy_from(&t5);
        field_ops.mul(&mut t5, &scratch, &mg_x3);

        // Step 17.
        mg_x3.copy_from(&t1);
        field_ops.add(&mut mg_x3, &t2);

        // Step 18.
        field_ops.sub(&mut t5, &mg_x3);

        // Step 19.
        field_ops.mul(&mut mg_z3, mg_a, &t4);

        // Step 20.
        field_ops.mul(&mut mg_x3, mg_b3, &t2);

        // Step 21.
        field_ops.add(&mut mg_z3, &mg_x3);

        // Step 22.
        mg_x3.copy_from(&t1);
        field_ops.sub(&mut mg_x3, &mg_z3);

        // Step 23.
        field_ops.add(&mut mg_z3, &t1);

        // Step 24.
        field_ops.mul(&mut mg_y3, &mg_x3, &mg_z3);

        // Step 25.
        t1.copy_from(&t0);
        field_ops.add(&mut t1, &t0);

        // Step 26.
        field_ops.add(&mut t1, &t0);

        // Step 27.
        scratch.copy_from(&t2);
        field_ops.mul(&mut t2, mg_a, &scratch);

        // Step 28.
        scratch.copy_from(&t4);
        field_ops.mul(&mut t4, mg_b3, &scratch);

        // Step 29.
        field_ops.add(&mut t1, &t2);

        // Step 30.
        scratch.copy_from(&t2);
        t2.copy_from(&t0);
        field_ops.sub(&mut t2, &scratch);

        // Step 31.
        scratch.copy_from(&t2);
        field_ops.mul(&mut t2, mg_a, &scratch);

        // Step 32.
        field_ops.add(&mut t4, &t2);

        // Step 33.
        field_ops.mul(&mut t0, &t1, &t4);

        // Step 34.
        field_ops.add(&mut mg_y3, &t0);

        // Step 35.
        field_ops.mul(&mut t0, &t5, &t4);

        // Step 36.
        scratch.copy_from(&mg_x3);
        field_ops.mul(&mut mg_x3, &t3, &scratch);

        // Step 37.
        field_ops.sub(&mut mg_x3, &t0);

        // Step 38.
        field_ops.mul(&mut t0, &t3, &t1);

        // Step 39.
        scratch.copy_from(&mg_z3);
        field_ops.mul(&mut mg_z3, &t5, &scratch);

        // Step 40.
        field_ops.add(&mut mg_z3, &t0);
    }

    /// Multiply a curve point by a scalar.
    pub fn point_scalar_mul<ST: cmpa::MpUIntCommon>(
        &self,
        scalar: &ST,
        scalar_nbits: usize,
        point: &AffinePoint,
        field_ops: &CurveFieldOps,
        scratch: &mut WeierstrassCurveOpsScratch,
    ) -> Result<ProjectivePoint, CryptoError> {
        let mg_a = self.get_mg_a();
        let mg_b3 = self.prepare_mg_b3(field_ops)?;
        let mg_b3 = cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&mg_b3);

        let mut result = ProjectivePoint::try_new_identity(field_ops)?;
        let mut scalar_mul_scratch = ProjectivePoint::try_new(field_ops.p.len())?;
        let mut scalar_bit_pos = scalar_nbits;
        while scalar_bit_pos > 0 {
            scalar_bit_pos -= 1;

            Self::_point_double(&mut scalar_mul_scratch, &result, field_ops, &mg_a, &mg_b3, scratch);
            Self::_point_add_mixed(
                &mut result,
                &scalar_mul_scratch,
                point,
                field_ops,
                &mg_a,
                &mg_b3,
                scratch,
            );
            result.copy_from_cond(&scalar_mul_scratch, !scalar.test_bit(scalar_bit_pos));
        }

        Ok(result)
    }

    /// Add two projective points.
    pub fn point_add(
        &self,
        op0: &ProjectivePoint,
        op1: &ProjectivePoint,
        field_ops: &CurveFieldOps,
        scratch: &mut WeierstrassCurveOpsScratch,
    ) -> Result<ProjectivePoint, CryptoError> {
        let mg_a = self.get_mg_a();
        let mg_b3 = self.prepare_mg_b3(field_ops)?;
        let mg_b3 = cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&mg_b3);

        let mut result = ProjectivePoint::try_new(field_ops.p.len())?;
        Self::_point_add(&mut result, op0, op1, field_ops, &mg_a, &mg_b3, scratch);

        Ok(result)
    }

    /// Double a point a specified number of times.
    pub fn point_double_repeated(
        &self,
        mut op0: ProjectivePoint,
        repeat_count: u8,
        field_ops: &CurveFieldOps,
        scratch: &mut WeierstrassCurveOpsScratch,
    ) -> Result<ProjectivePoint, CryptoError> {
        if repeat_count == 0 {
            return Ok(op0);
        }

        let mg_a = self.get_mg_a();
        let mg_b3 = self.prepare_mg_b3(field_ops)?;
        let mg_b3 = cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&mg_b3);

        let mut result = ProjectivePoint::try_new(field_ops.p.len())?;
        for i in 0..repeat_count {
            if i != 0 {
                op0.copy_from(&result);
            }
            Self::_point_double(&mut result, &op0, field_ops, &mg_a, &mg_b3, scratch);
        }
        Ok(result)
    }

    /// Test whether a given point is on the curve.
    pub fn point_is_on_curve(
        &self,
        point: &AffinePoint,
        field_ops: &CurveFieldOps,
        scratch: Option<&mut WeierstrassCurveOpsScratch>,
    ) -> Result<bool, CryptoError> {
        // C.f. NIST SP800-56Ar3, section 5.6.2.3.4 ("ECC Partial Public-Key Validation
        // Routine") or NIST SP800-186, section D.1.1.1. ("Partial Public Key
        // Validation"). Note that the instantiation of an
        // AffinePointMontgomeryForm from plain coordinates does some bounds
        // checking already.
        let mut scratch0: zeroize::Zeroizing<Vec<cmpa::LimbType>> = zeroize::Zeroizing::from(Vec::new());
        let mut scratch1: zeroize::Zeroizing<Vec<cmpa::LimbType>> = zeroize::Zeroizing::from(Vec::new());
        let (scratch0, scratch1) = if let Some(scratch) = scratch {
            (&mut scratch.scratch0, &mut scratch.scratch1)
        } else {
            let p_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(field_ops.p.len());
            for s in [&mut scratch0, &mut scratch1].iter_mut() {
                **s = try_alloc_zeroizing_vec::<cmpa::LimbType>(p_nlimbs)?;
            }
            (&mut scratch0, &mut scratch1)
        };

        let (mg_x, mg_y) = point.get_mg_coordinates();

        // x^3
        let mut mg_x3 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(scratch0);
        let mut scratch = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(scratch1);
        field_ops.mul(&mut scratch, &mg_x, &mg_x);
        field_ops.mul(&mut mg_x3, &scratch, &mg_x);

        // a * x
        let mut mg_ax = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(scratch1);
        let mg_a = self.get_mg_a();
        field_ops.mul(&mut mg_ax, &mg_a, &mg_x);

        // x^3 + a * x
        let mut rhs = mg_x3;
        field_ops.add(&mut rhs, &mg_ax);

        // x^3 + a * x + b
        field_ops.add(&mut rhs, &self.get_mg_b());

        // y^2
        let mut lhs = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(scratch1);
        field_ops.mul(&mut lhs, &mg_y, &mg_y);

        Ok(cmpa::ct_eq_mp_mp(&lhs, &rhs).unwrap() != 0)
    }
}
