// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Pure Rust backend ECDSA signature scheme implementation.
//!
//! Refer to NIST FIPS 186-5, sec. 6.4.1 ("ECDSA Signature Generation
//! Algorithm")

extern crate alloc;
use alloc::vec::Vec;

use crate::utils_common::{
    alloc::{try_alloc_vec, try_alloc_zeroizing_vec},
    zeroize,
};
use crate::{
    CryptoError,
    ecc::{curve, gen_random_scalar, key},
    rng,
};
use cmpa::{self, MpMutUInt as _, MpMutUIntSlice as _, MpUIntCommon as _};
use core::array;

/// ECDSA signature creation.
///
/// # Arguments:
///
/// * `digest` - The message digest to sign.
/// * `key` - The signing key. Must have the private part available.
/// * `rng` - The [random number generator](rng::RngCore) used for generating
///   the random integer `k`. It  might not get invoked by the backend in case
///   that draws randomness from some alternative internal rng instance.
/// * `additional_rng_generate_input` - Additional input to pass along to the
///   `rng`'s [generate()](rng::RngCore::generate) primitive.
pub fn sign(
    digest: &[u8],
    key: &key::EccKey,
    rng: &mut dyn rng::RngCoreDispatchable,
    additional_rng_generate_input: Option<&[Option<&[u8]>]>,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    // Implementation according to NIST FIPS 186-5, sec. 6.4.1 ("ECDSA Signature
    // Generation Algorithm").
    let curve = curve::Curve::new(key.pub_key().get_curve_id())?;
    let curve_ops = curve.curve_ops()?;

    let order = curve.get_order();
    let order_divisor = cmpa::CtMpDivisor::new(&order, None).unwrap();
    let mg_neg_order0_inv_mod_l = cmpa::ct_montgomery_neg_n0_inv_mod_l_mp(&order).map_err(|_| CryptoError::Internal)?;
    let order_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(order.len());
    let mut mg_radix2_mod_order = try_alloc_vec::<cmpa::LimbType>(order_nlimbs)?;
    let mut mg_radix2_mod_order = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut mg_radix2_mod_order);
    cmpa::ct_montgomery_radix2_mod_n_mp(&mut mg_radix2_mod_order, &order).map_err(|_| CryptoError::Internal)?;

    const MAX_RETRIES: u32 = 16;
    let mut remaining_retries = MAX_RETRIES;
    let (r, s) = loop {
        if remaining_retries == 0 {
            return Err(CryptoError::RandomSamplingRetriesExceeded);
        }
        remaining_retries -= 1;

        // Step 3.
        let mut k_buf = try_alloc_zeroizing_vec::<u8>(order.len()).unwrap();
        gen_random_scalar::tcg_tpm2_gen_random_ec_scalar(
            &mut k_buf,
            &order,
            curve.get_nbits(),
            rng,
            additional_rng_generate_input,
        )?;
        let k = cmpa::MpBigEndianUIntByteSlice::from_bytes(&k_buf);

        // Step 5. Run it here to not have it compete memory-wise with intermediate
        // results from the preceeding steps.
        let g = curve_ops.generator()?;
        let mut curve_ops_scratch = curve_ops.try_alloc_scratch()?;
        let r = curve_ops.point_scalar_mul(&k, &g, &mut curve_ops_scratch)?;
        drop(g);

        // Steps 6-8.
        let mut r_buf = try_alloc_vec::<u8>(curve.get_p_len()).unwrap();
        let mut r_x = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut r_buf);
        if let Err(e) = r.into_affine_plain_coordinates(&mut r_x, None, &curve_ops, Some(&mut curve_ops_scratch))? {
            match e {
                curve::ProjectivePointIntoAffineError::PointIsIdentity => {
                    // This should not happen, as k is in the range 1 < k < order. But play safe and
                    // retry.
                    continue;
                }
            }
        }
        drop(curve_ops_scratch);
        let mut r = r_x; // Just a rename to align with NIST FIPS 186-5.
        cmpa::ct_mod_mp_mp(None, &mut r, &order_divisor);
        let r = r.shrink_to(order.len());

        // Step 11, test for r == 0.
        if cmpa::ct_is_zero_mp(&r).unwrap() != 0 {
            continue;
        }

        // Setup some scratch buffers for the subsequent computations.
        let mut scratch: [zeroize::Zeroizing<Vec<cmpa::LimbType>>; 4] =
            array::from_fn(|_| zeroize::Zeroizing::from(Vec::new()));
        for s in scratch.iter_mut() {
            *s = try_alloc_zeroizing_vec(order_nlimbs)?;
        }
        let [mut scratch0_buf, mut scratch1_buf, mut scratch2_buf, mut scratch3_buf] = scratch;
        let mut scratch0 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch0_buf);
        let mut scratch1 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch1_buf);

        // Step 4.
        scratch0.copy_from(&k);
        drop(k_buf);
        let k = &mut scratch0;
        let k_inv = &mut scratch1;
        if let Err(e) = cmpa::ct_inv_mod_odd_mp_mp(k_inv, k, &order, [&mut scratch2_buf, &mut scratch3_buf]) {
            match e {
                cmpa::CtInvModOddMpMpError::OperandsNotCoprime => {
                    // This should not happen as all curves' orders are primes IIRC. Play safe and
                    // retry though.
                    continue;
                }
                cmpa::CtInvModOddMpMpError::InconsistentOperandLengths
                | cmpa::CtInvModOddMpMpError::InsufficientResultSpace
                | cmpa::CtInvModOddMpMpError::InsufficientScratchSpace
                | cmpa::CtInvModOddMpMpError::InvalidModulus => {
                    return Err(CryptoError::Internal);
                }
            }
        }

        let mut scratch2 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch2_buf);
        let mut scratch3 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch3_buf);

        // Step 9.
        let mg_k_inv = &mut scratch0;
        cmpa::ct_to_montgomery_form_mp(mg_k_inv, k_inv, &order, mg_neg_order0_inv_mod_l, &mg_radix2_mod_order)
            .map_err(|_| CryptoError::Internal)?;

        // r to Montgomery form.
        let mg_r = &mut scratch2;
        scratch1.copy_from(&r);
        cmpa::ct_to_montgomery_form_mp(mg_r, &scratch1, &order, mg_neg_order0_inv_mod_l, &mg_radix2_mod_order)
            .map_err(|_| CryptoError::Internal)?;

        // d to Montgomery form.
        let mg_d = &mut scratch3;
        scratch1.copy_from(&key.priv_key().ok_or(CryptoError::NoKey)?.get_d());
        cmpa::ct_to_montgomery_form_mp(mg_d, &scratch1, &order, mg_neg_order0_inv_mod_l, &mg_radix2_mod_order)
            .map_err(|_| CryptoError::Internal)?;

        // r * d mod n
        let mg_r_d = &mut scratch1;
        cmpa::ct_montgomery_mul_mod_mp_mp(mg_r_d, mg_r, mg_d, &order, mg_neg_order0_inv_mod_l)
            .map_err(|_| CryptoError::Internal)?;

        // Detour: step 2.
        let e = &mut scratch2;
        if 8 * digest.len() <= curve.get_nbits() {
            e.copy_from(&cmpa::MpBigEndianUIntByteSlice::from_bytes(digest));
        } else {
            debug_assert!(order.len() <= digest.len());
            let (digest_head, _) = digest.split_at(order.len());
            e.copy_from(&cmpa::MpBigEndianUIntByteSlice::from_bytes(digest_head));
            cmpa::ct_rshift_mp(e, 8 * order.len() - curve.get_nbits());
        }

        // Continue with step 9.
        // e to Montgomery form.
        cmpa::ct_mod_mp_mp(None, e, &order_divisor);
        let e = e.shrink_to(order.len());
        let mg_e = &mut scratch3;
        cmpa::ct_to_montgomery_form_mp(mg_e, &e, &order, mg_neg_order0_inv_mod_l, &mg_radix2_mod_order)
            .map_err(|_| CryptoError::Internal)?;

        // e + r*d
        let mg_e_plus_r_d = mg_e; // Just a rename.
        cmpa::ct_add_mod_mp_mp(mg_e_plus_r_d, mg_r_d, &order).map_err(|_| CryptoError::Internal)?;

        // k^-1 * (e + r * d)
        let mg_s = &mut scratch1;
        cmpa::ct_montgomery_mul_mod_mp_mp(mg_s, mg_k_inv, mg_e_plus_r_d, &order, mg_neg_order0_inv_mod_l)
            .map_err(|_| CryptoError::Internal)?;

        // Step 11, test for s == 0.
        if cmpa::ct_is_zero_mp(mg_s).unwrap() != 0 {
            continue;
        }

        // Step 10 is implicit.

        // Step 12. Transform s back from Montgomery form and format it as a
        // big-endian byte buffer.
        cmpa::ct_montgomery_redc_mp(mg_s, &order, mg_neg_order0_inv_mod_l).map_err(|_| CryptoError::Internal)?;
        let s = mg_s; // Just a rename.

        drop(scratch0_buf);
        drop(scratch2_buf);
        drop(scratch3_buf);

        let mut s_buf = try_alloc_vec::<u8>(order.len())?;
        cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut s_buf).copy_from(s);
        drop(scratch1_buf);

        // Finally resize (shrink) r_buf if needed.
        let r_buf = if r_buf.len() == order.len() {
            r_buf
        } else {
            debug_assert!(order.len() < r_buf.len());
            let mut new_r_buf = try_alloc_vec::<u8>(order.len())?;
            new_r_buf.copy_from_slice(&r_buf[r_buf.len() - order.len()..]);
            new_r_buf
        };

        break (r_buf, s_buf);
    };

    Ok((r, s))
}

/// ECDSA signature verification.
///
/// # Arguments:
///
/// * `digest` - The signed message digest.
/// * `signature` - The signature to verify.
/// * `pub_key` - The verification key.
pub fn verify(digest: &[u8], signature: (&[u8], &[u8]), pub_key: &key::EccPublicKey) -> Result<(), CryptoError> {
    // Implementation according to NIST FIPS 186-5, sec. 6.4.2 ("ECDSA Signature
    // Verification Algorithm").
    let (signature_r, signature_s) = signature;
    let signature_r = cmpa::MpBigEndianUIntByteSlice::from_bytes(signature_r);
    let signature_s = cmpa::MpBigEndianUIntByteSlice::from_bytes(signature_s);

    let curve = curve::Curve::new(pub_key.get_curve_id())?;
    let order = curve.get_order();
    let order_divisor = cmpa::CtMpDivisor::new(&order, None).unwrap();
    let mg_neg_order0_inv_mod_l = cmpa::ct_montgomery_neg_n0_inv_mod_l_mp(&order).map_err(|_| CryptoError::Internal)?;
    let order_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(order.len());
    let mut mg_radix2_mod_order = try_alloc_vec::<cmpa::LimbType>(order_nlimbs)?;
    let mut mg_radix2_mod_order = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut mg_radix2_mod_order);
    cmpa::ct_montgomery_radix2_mod_n_mp(&mut mg_radix2_mod_order, &order).map_err(|_| CryptoError::Internal)?;

    // Step 1.
    if cmpa::ct_is_zero_mp(&signature_r).unwrap() != 0
        || cmpa::ct_lt_mp_mp(&signature_r, &order).unwrap() == 0
        || cmpa::ct_is_zero_mp(&signature_s).unwrap() != 0
        || cmpa::ct_lt_mp_mp(&signature_s, &order).unwrap() == 0
    {
        return Err(CryptoError::SignatureVerificationFailure);
    }

    // Setup some scratch buffers for the subsequent computations.
    let mut scratch: [Vec<cmpa::LimbType>; 4] = array::from_fn(|_| Vec::new());
    for s in scratch.iter_mut() {
        *s = try_alloc_vec(order_nlimbs)?;
    }
    let [mut scratch0_buf, mut scratch1_buf, mut scratch2_buf, mut scratch3_buf] = scratch;
    let mut scratch0 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch0_buf);
    let mut scratch1 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch1_buf);

    // Step 4.
    scratch0.copy_from(&signature_s);
    let s_inv = &mut scratch1;
    if let Err(e) = cmpa::ct_inv_mod_odd_mp_mp(s_inv, &mut scratch0, &order, [&mut scratch2_buf, &mut scratch3_buf]) {
        match e {
            cmpa::CtInvModOddMpMpError::OperandsNotCoprime => {
                return Err(CryptoError::SignatureVerificationFailure);
            }
            cmpa::CtInvModOddMpMpError::InconsistentOperandLengths
            | cmpa::CtInvModOddMpMpError::InsufficientResultSpace
            | cmpa::CtInvModOddMpMpError::InsufficientScratchSpace
            | cmpa::CtInvModOddMpMpError::InvalidModulus => {
                return Err(CryptoError::Internal);
            }
        }
    }

    // s to Montgomery form.
    let mg_s_inv = &mut scratch0;
    cmpa::ct_to_montgomery_form_mp(mg_s_inv, s_inv, &order, mg_neg_order0_inv_mod_l, &mg_radix2_mod_order)
        .map_err(|_| CryptoError::Internal)?;

    let mut scratch2 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch2_buf);
    let mut scratch3 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch3_buf);

    // Step 3.
    let e = &mut scratch2;
    if 8 * digest.len() <= curve.get_nbits() {
        e.copy_from(&cmpa::MpBigEndianUIntByteSlice::from_bytes(digest));
    } else {
        debug_assert!(order.len() <= digest.len());
        let (digest_head, _) = digest.split_at(order.len());
        e.copy_from(&cmpa::MpBigEndianUIntByteSlice::from_bytes(digest_head));
        cmpa::ct_rshift_mp(e, 8 * order.len() - curve.get_nbits());
    }

    // e to Montgomery form.
    cmpa::ct_mod_mp_mp(None, e, &order_divisor);
    let e = e.shrink_to(order.len());
    let mg_e = &mut scratch1;
    cmpa::ct_to_montgomery_form_mp(mg_e, &e, &order, mg_neg_order0_inv_mod_l, &mg_radix2_mod_order)
        .map_err(|_| CryptoError::Internal)?;

    // Step 5.
    let mg_u = &mut scratch2;
    cmpa::ct_montgomery_mul_mod_mp_mp(mg_u, mg_s_inv, mg_e, &order, mg_neg_order0_inv_mod_l)
        .map_err(|_| CryptoError::Internal)?;
    cmpa::ct_montgomery_redc_mp(mg_u, &order, mg_neg_order0_inv_mod_l).map_err(|_| CryptoError::Internal)?;
    let u = mg_u; // Just a rename.

    let mg_r = &mut scratch1;
    scratch3.copy_from(&signature_r);
    cmpa::ct_to_montgomery_form_mp(mg_r, &scratch3, &order, mg_neg_order0_inv_mod_l, &mg_radix2_mod_order)
        .map_err(|_| CryptoError::Internal)?;
    let mg_v = &mut scratch3;
    cmpa::ct_montgomery_mul_mod_mp_mp(mg_v, mg_s_inv, mg_r, &order, mg_neg_order0_inv_mod_l)
        .map_err(|_| CryptoError::Internal)?;
    cmpa::ct_montgomery_redc_mp(mg_v, &order, mg_neg_order0_inv_mod_l).map_err(|_| CryptoError::Internal)?;
    let v = mg_v; // Just a rename.

    drop(scratch0_buf);
    drop(scratch1_buf);

    // Step 6.
    let curve_ops = curve.curve_ops()?;
    let g = curve_ops.generator()?;
    let mut curve_ops_scratch = curve_ops.try_alloc_scratch()?;
    let u_g = curve_ops.point_scalar_mul(u, &g, &mut curve_ops_scratch)?;
    drop(scratch2_buf);
    let v_q = curve_ops.point_scalar_mul(v, pub_key.get_point(), &mut curve_ops_scratch)?;
    drop(scratch3_buf);
    let r1 = curve_ops.point_add(&u_g, &v_q, &mut curve_ops_scratch)?;
    drop(u_g);
    drop(v_q);

    // Steps 7-8.
    let mut r1_x = try_alloc_vec::<u8>(curve.get_p_len())?;
    let mut r1_x = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut r1_x);
    r1.into_affine_plain_coordinates(&mut r1_x, None, &curve_ops, Some(&mut curve_ops_scratch))?
        .map_err(|e| match e {
            curve::ProjectivePointIntoAffineError::PointIsIdentity => CryptoError::SignatureVerificationFailure,
        })?;
    let mut r1 = r1_x; // Just a rename to align with NIST FIPS 186-5.
    drop(curve_ops_scratch);

    // Step 9.
    cmpa::ct_mod_mp_mp(None, &mut r1, &order_divisor);
    if cmpa::ct_eq_mp_mp(&signature_r, &r1).unwrap() == 0 {
        return Err(CryptoError::SignatureVerificationFailure);
    }

    Ok(())
}
