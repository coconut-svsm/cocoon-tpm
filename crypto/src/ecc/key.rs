// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

extern crate alloc;
use alloc::vec::Vec;

use super::{curve, gen_random_scalar};
use crate::{rng, CryptoError};
use crate::{
    tpm2_interface,
    utils_common::{alloc::try_alloc_zeroizing_vec, ct_cmp, zeroize},
};
use cmpa::{self, MpMutUInt as _};
use core::{convert, mem};

/// ECC public key.
///
/// Usually not instantiated directly, but obtained through `EccKey`.
pub struct EccPublicKey {
    curve_id: tpm2_interface::TpmEccCurve,
    point: curve::AffinePoint,
}

impl EccPublicKey {
    /// Get the point's associated curve id.
    pub fn get_curve_id(&self) -> tpm2_interface::TpmEccCurve {
        self.curve_id
    }

    pub fn get_point(&self) -> &curve::AffinePoint {
        &self.point
    }

    /// Convert into [`TpmsEccPoint`](tpm2_interface::TpmsEccPoint).
    ///
    /// # Arguments:
    ///
    /// * `curve_ops` - The curve's associated [`CurveOps`](curve::CurveOps),
    ///   usually obtained through
    ///   [`Curve::curve_ops()`](curve::Curve::curve_ops).
    pub fn into_tpms_ecc_point(
        self,
        curve_ops: &curve::CurveOps,
    ) -> Result<tpm2_interface::TpmsEccPoint<'static>, CryptoError> {
        let mut x_buf = try_alloc_zeroizing_vec::<u8>(curve_ops.get_curve().get_p_len())?;
        let mut x = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut x_buf);
        let mut y_buf = try_alloc_zeroizing_vec::<u8>(curve_ops.get_curve().get_p_len())?;
        let mut y = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut y_buf);
        let EccPublicKey { curve_id: _, point } = self;
        point.into_plain_coordinates(&mut x, Some(&mut y), curve_ops)?;
        let x = tpm2_interface::Tpm2bEccParameter {
            buffer: tpm2_interface::TpmBuffer::Owned(mem::take(&mut x_buf)),
        };
        let y = tpm2_interface::Tpm2bEccParameter {
            buffer: tpm2_interface::TpmBuffer::Owned(mem::take(&mut y_buf)),
        };
        Ok(tpm2_interface::TpmsEccPoint { x, y })
    }

    /// Convert to [`TpmsEccPoint`](tpm2_interface::TpmsEccPoint).
    ///
    /// If `self` is not needed any furhter, prefer to use
    /// [`into_tpms_ecc_point()`](Self::into_tpms_ecc_point) as that saves some
    /// scratch buffer allocation.
    ///
    /// # Arguments:
    ///
    /// * `curve_ops` - The curve's associated [`CurveOps`](curve::CurveOps),
    ///   usually obtained through
    ///   [`Curve::curve_ops()`](curve::Curve::curve_ops).
    pub fn to_tpms_ecc_point(
        &self,
        curve_ops: &curve::CurveOps,
    ) -> Result<tpm2_interface::TpmsEccPoint<'static>, CryptoError> {
        let mut x_buf = try_alloc_zeroizing_vec::<u8>(curve_ops.get_curve().get_p_len())?;
        let mut x = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut x_buf);
        let mut y_buf = try_alloc_zeroizing_vec::<u8>(curve_ops.get_curve().get_p_len())?;
        let mut y = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut y_buf);
        self.get_point().to_plain_coordinates(&mut x, Some(&mut y), curve_ops)?;
        let x = tpm2_interface::Tpm2bEccParameter {
            buffer: tpm2_interface::TpmBuffer::Owned(mem::take(&mut x_buf)),
        };
        let y = tpm2_interface::Tpm2bEccParameter {
            buffer: tpm2_interface::TpmBuffer::Owned(mem::take(&mut y_buf)),
        };
        Ok(tpm2_interface::TpmsEccPoint { x, y })
    }
}

impl<'a, 'b> convert::TryFrom<(&curve::CurveOps<'a>, &tpm2_interface::TpmsEccPoint<'b>)> for EccPublicKey {
    type Error = CryptoError;

    /// Load a  ECC public key from a pair of [`CurveOps`](curve::CurveOps) and
    /// the public [`TpmsEccPoint`](tpm2_interface::TpmsEccPoint)
    ///
    /// The curve's associated [`CurveOps`](curve::CurveOps), usually obtained
    /// through [`Curve::curve_ops()`](curve::Curve::curve_ops).
    fn try_from(value: (&curve::CurveOps<'a>, &tpm2_interface::TpmsEccPoint<'b>)) -> Result<Self, Self::Error> {
        // Load and validate the public key point.
        let (curve_ops, src_point) = value;
        let curve_id = curve_ops.get_curve().get_curve_id();
        let tpm2_interface::TpmsEccPoint { x: src_x, y: src_y } = &src_point;
        let point = curve::AffinePoint::try_from_plain_coordinates(
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&src_x.buffer),
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&src_y.buffer),
            curve_ops,
        )?;

        let mut curve_ops_scratch = curve_ops.try_alloc_scratch()?;
        if !curve_ops.point_is_in_generator_subgroup(&point, &mut curve_ops_scratch)? {
            return Err(CryptoError::InvalidPoint);
        }

        Ok(Self { curve_id, point })
    }
}

impl zeroize::ZeroizeOnDrop for EccPublicKey {}

/// ECC private key.
pub struct EccPrivateKey {
    d: zeroize::Zeroizing<Vec<u8>>,
}

impl EccPrivateKey {
    /// Get the private scalar.
    pub fn get_d(&self) -> cmpa::MpBigEndianUIntByteSlice<'_> {
        cmpa::MpBigEndianUIntByteSlice::from_bytes(&self.d)
    }
}

impl zeroize::ZeroizeOnDrop for EccPrivateKey {}

/// ECC key with mandatory public and optional private part.
pub struct EccKey {
    pub_key: EccPublicKey,
    priv_key: Option<EccPrivateKey>,
}

impl EccKey {
    /// Crate a `EccKey` from raw parts.
    ///
    /// <div class="warning">
    ///
    /// For internal use only, no key validation whatsoever will be conducted.
    ///
    /// </div>
    #[allow(unused)]
    pub(crate) fn new_from_raw(
        curve_id: tpm2_interface::TpmEccCurve,
        public_point: curve::AffinePoint,
        private_key: Option<zeroize::Zeroizing<Vec<u8>>>,
    ) -> Self {
        Self {
            pub_key: EccPublicKey {
                curve_id,
                point: public_point,
            },
            priv_key: private_key.map(|priv_key| EccPrivateKey { d: priv_key }),
        }
    }

    /// Generate a new random ECC key pair.
    ///
    /// The key generation method implemented by the configured implementation
    /// backend will get invoked, what is what's usually wanted to respect
    /// user choice.
    ///
    /// # See also:
    ///
    /// * [`generate_tcg_tpm2()`](Self::generate_tcg_tpm2)
    ///
    /// # Arguments:
    ///
    /// * `curve_ops` - The curve's associated [`CurveOps`](curve::CurveOps),
    ///   usually obtained through
    ///   [`Curve::curve_ops()`](curve::Curve::curve_ops).
    /// * `rng` - The random number generator to draw random bytes from. It
    ///   might not get invoked by the backend in case that draws randomness
    ///   from some alternative internal rng instance.
    /// * `additional_rng_generate_input` - Additional input to pass along to
    ///   the `rng`'s [generate()](rng::RngCore::generate) primitive.
    pub fn generate(
        curve_ops: &curve::CurveOps,
        rng: &mut dyn rng::RngCoreDispatchable,
        additional_rng_generate_input: Option<&[Option<&[u8]>]>,
    ) -> Result<Self, CryptoError> {
        curve_ops.generate_key(rng, additional_rng_generate_input)
    }

    /// Generate an ECC key pair following the procedure specified in the TCG
    /// TPM2 Library, Part 1, section C.5 ("ECC Key Generation").
    ///
    /// Note `rng` can be any [random number
    /// generator](rng::RngCoreDispatchable), but for key derivation in line
    /// with the TCG TPM2 Library spec, it is expected to be an instance of
    /// type [`TcgTpm2KdfA`](crate::kdf::tcg_tpm2_kdf_a::TcgTpm2KdfA).
    ///
    /// # See also:
    ///
    /// * [`generate()`](Self::generate)
    ///
    /// # Arguments:
    ///
    /// * `curve_ops` - The curve's associated [`CurveOps`](curve::CurveOps),
    ///   usually obtained through
    ///   [`Curve::curve_ops()`](curve::Curve::curve_ops).
    /// * `rng` - The random number generator to draw random bytes from.
    /// * `additional_rng_generate_input` - Additional input to pass along to
    ///   the `rng`'s [generate()](rng::RngCore::generate) primitive.
    pub fn generate_tcg_tpm2(
        curve_ops: &curve::CurveOps,
        rng: &mut dyn rng::RngCoreDispatchable,
        additional_rng_generate_input: Option<&[Option<&[u8]>]>,
    ) -> Result<Self, CryptoError> {
        let curve = curve_ops.get_curve();
        let mut d = try_alloc_zeroizing_vec::<u8>(curve.get_p_len())?;
        gen_random_scalar::tcg_tpm2_gen_random_ec_scalar(
            &mut d,
            &curve.get_order(),
            curve.get_nbits(),
            rng,
            additional_rng_generate_input,
        )?;

        let g = curve_ops.generator()?;
        let mut curve_ops_scratch = curve_ops.try_alloc_scratch()?;
        let point = curve_ops.point_scalar_mul(
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&d),
            &g,
            &mut curve_ops_scratch,
        )?;
        let point = match point.into_affine(curve_ops, Some(&mut curve_ops_scratch))? {
            Ok(point) => point,
            Err(curve::ProjectivePointIntoAffineError::PointIsIdentity) => {
                return Err(CryptoError::Internal);
            }
        };

        Ok(Self {
            pub_key: EccPublicKey {
                curve_id: curve.get_curve_id(),
                point,
            },
            priv_key: Some(EccPrivateKey { d }),
        })
    }

    /// Get the public key.
    pub fn pub_key(&self) -> &EccPublicKey {
        &self.pub_key
    }

    /// Get the private key.
    pub fn priv_key(&self) -> Option<&EccPrivateKey> {
        self.priv_key.as_ref()
    }

    /// Take the public key.
    pub fn take_public(self) -> EccPublicKey {
        self.pub_key
    }

    /// Convert into a pair of public
    /// [`TpmsEccPoint`](tpm2_interface::TpmsEccPoint) and
    /// private [`Tpm2bEccParameter`](tpm2_interface::Tpm2bEccParameter).
    ///
    /// # Arguments:
    ///
    /// * `curve_ops` - The curve's associated [`CurveOps`](curve::CurveOps),
    ///   usually obtained through
    ///   [`Curve::curve_ops()`](curve::Curve::curve_ops).
    pub fn into_tpms(
        self,
        curve_ops: &curve::CurveOps,
    ) -> Result<
        (
            tpm2_interface::TpmsEccPoint<'static>,
            Option<tpm2_interface::Tpm2bEccParameter<'static>>,
        ),
        CryptoError,
    > {
        let Self { pub_key, priv_key } = self;
        let pub_key = pub_key.into_tpms_ecc_point(curve_ops)?;
        let priv_key = priv_key.map(|mut priv_key| tpm2_interface::Tpm2bEccParameter {
            buffer: tpm2_interface::TpmBuffer::Owned(mem::take(&mut priv_key.d)),
        });
        Ok((pub_key, priv_key))
    }
}

impl zeroize::ZeroizeOnDrop for EccKey {}

impl<'a, 'b, 'c>
    convert::TryFrom<(
        &curve::CurveOps<'a>,
        &tpm2_interface::TpmsEccPoint<'b>,
        Option<&tpm2_interface::Tpm2bEccParameter<'c>>,
    )> for EccKey
{
    type Error = CryptoError;

    /// Load an ECC key from a triplet of [`CurveOps`](curve::CurveOps),
    /// the public [`TpmsEccPoint`](tpm2_interface::TpmsEccPoint) and
    /// optional private
    /// [`Tpm2bEccParameter`](tpm2_interface::Tpm2bEccParameter).
    ///
    /// The curve's associated [`CurveOps`](curve::CurveOps), usually obtained
    /// through [`Curve::curve_ops()`](curve::Curve::curve_ops).
    fn try_from(
        value: (
            &curve::CurveOps<'a>,
            &tpm2_interface::TpmsEccPoint<'b>,
            Option<&tpm2_interface::Tpm2bEccParameter<'c>>,
        ),
    ) -> Result<Self, Self::Error> {
        let (curve_ops, src_point, src_d) = value;
        if let Some(src_d) = src_d {
            // With private key given. Validate it and regenerate the public key from it.
            // Verify that the externally provided public key matches the
            // regenerated one.
            let curve = curve_ops.get_curve();
            let src_d = cmpa::MpBigEndianUIntByteSlice::from_bytes(&src_d.buffer);
            curve.validate_scalar(&src_d).map_err(|e| match e {
                CryptoError::InvalidPoint => CryptoError::KeyBinding,
                e => e,
            })?;

            let mut d_buf = try_alloc_zeroizing_vec::<u8>(curve.get_p_len())?;
            let mut d = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut d_buf);
            d.copy_from(&src_d);

            let g = curve_ops.generator()?;
            let mut curve_ops_scratch = curve_ops.try_alloc_scratch()?;
            let point = curve_ops.point_scalar_mul(&d, &g, &mut curve_ops_scratch)?;
            let point = match point.into_affine(curve_ops, Some(&mut curve_ops_scratch))? {
                Ok(point) => point,
                Err(curve::ProjectivePointIntoAffineError::PointIsIdentity) => {
                    return Err(CryptoError::KeyBinding);
                }
            };
            drop(curve_ops_scratch);

            // And compare with the input public key. Don't stabilize -- it won't get used
            // further henceafter anyways and equality at some point in time is
            // good enough as far as this check here is concerned.
            let mut plain_x = try_alloc_zeroizing_vec::<u8>(curve.get_p_len())?;
            let mut plain_y = try_alloc_zeroizing_vec::<u8>(curve.get_p_len())?;
            point.to_plain_coordinates(
                &mut cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut plain_x),
                Some(&mut cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut plain_y)),
                curve_ops,
            )?;

            if (ct_cmp::ct_bytes_eq(&plain_x, &src_point.x.buffer) & ct_cmp::ct_bytes_eq(&plain_y, &src_point.y.buffer))
                .unwrap()
                == 0
            {
                return Err(CryptoError::KeyBinding);
            }

            Ok(Self {
                pub_key: EccPublicKey {
                    curve_id: curve.get_curve_id(),
                    point,
                },
                priv_key: Some(EccPrivateKey { d: d_buf }),
            })
        } else {
            Ok(Self {
                pub_key: EccPublicKey::try_from((curve_ops, src_point))?,
                priv_key: None,
            })
        }
    }
}
