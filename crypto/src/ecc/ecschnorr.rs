// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of the EC Schnorr signature scheme.

#[cfg(feature = "boringssl")]
compile_error!("EC Schnorr signatures not supported with BoringSSL backend");

extern crate alloc;
use alloc::vec::Vec;

use super::{curve, gen_random_scalar, key};
use crate::{CryptoError, hash, rng};
use crate::{
    tpm2_interface,
    utils_common::{
        alloc::{try_alloc_vec, try_alloc_zeroizing_vec},
        io_slices::{self, IoSlicesIterCommon as _},
        zeroize,
    },
};
use cmpa::{self, MpMutUInt as _, MpUIntCommon as _};
use core::array;

/// EC Schnorr signature creation.
///
/// # Arguments:
///
/// * `digest` - The message digest to sign.
/// * `key` - The signing key. Must have the private part available.
/// * `scheme_hash_alg` - The hash algorithm to use for the scheme.
/// * `rng` - The [random number generator](rng::RngCore) used for generating
///   the random integer `k`.
/// * `additional_rng_generate_input` - Additional input to pass along to the
///   `rng`'s [generate()](rng::RngCore::generate) primitive.
pub fn sign(
    digest: &[u8],
    key: &key::EccKey,
    scheme_hash_alg: tpm2_interface::TpmiAlgHash,
    rng: &mut dyn rng::RngCoreDispatchable,
    additional_rng_generate_input: Option<&[Option<&[u8]>]>,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    // Implementation according TCG TPM2 Library, Part 1, section C.4.3.2 ("EC
    // Schnorr Sign").
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

        // Step a.
        // The k_buf will get recycled for the returned s -- no need to zeroize it,
        // because all the other buffers storing sensitive information will get
        // zeroized. So upon error, the only information left around is a random k.
        let mut k_buf = try_alloc_vec::<u8>(order.len())?;
        gen_random_scalar::tcg_tpm2_gen_random_ec_scalar(
            &mut k_buf,
            &order,
            curve.get_nbits(),
            rng,
            additional_rng_generate_input,
        )?;
        let k = cmpa::MpBigEndianUIntByteSlice::from_bytes(&k_buf);

        // Step b.
        let g = curve_ops.generator()?;
        let mut curve_ops_scratch = curve_ops.try_alloc_scratch()?;
        let e = curve_ops.point_scalar_mul(&k, &g, &mut curve_ops_scratch)?;
        drop(g);
        let mut e_x_buf = try_alloc_zeroizing_vec::<u8>(curve.get_p_len())?;
        let mut e_x = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut e_x_buf);
        match e.into_affine_plain_coordinates(&mut e_x, None, &curve_ops, Some(&mut curve_ops_scratch))? {
            Ok(()) => (),
            Err(curve::ProjectivePointIntoAffineError::PointIsIdentity) => {
                // Step c.
                // This should not happen, as k is in the range 1 < k < order. But play safe and
                // retry.
                continue;
            }
        };
        drop(curve_ops_scratch);

        // Step d.
        let mut h = hash::HashInstance::new(scheme_hash_alg)?;
        debug_assert_eq!(e_x_buf.len(), order.len());
        h.update(io_slices::BuffersSliceIoSlicesIter::new(&[e_x_buf.as_slice(), digest]).map_infallible_err())?;
        drop(e_x_buf);
        let mut r_buf = try_alloc_vec(hash::hash_alg_digest_len(scheme_hash_alg) as usize)?;
        h.finalize_into(&mut r_buf)?;
        // r will get returned. Truncate the buffer to its final size, if needed.
        let r_buf = if r_buf.len() > order.len() {
            let mut new_r_buf = try_alloc_vec(order.len()).unwrap();
            new_r_buf.copy_from_slice(&r_buf[..order.len()]);
            drop(r_buf);
            new_r_buf
        } else {
            r_buf
        };
        let r = cmpa::MpBigEndianUIntByteSlice::from_bytes(&r_buf);

        // Step e.
        // Allocate scratch buffers first.
        let mut scratch: [zeroize::Zeroizing<Vec<cmpa::LimbType>>; 3] =
            array::from_fn(|_| zeroize::Zeroizing::from(Vec::new()));
        for s in scratch.iter_mut() {
            *s = try_alloc_zeroizing_vec(order_nlimbs)?;
        }
        let [mut scratch0_buf, mut scratch1_buf, mut scratch2_buf] = scratch;
        let mut scratch0 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch0_buf);
        let mut scratch1 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch1_buf);
        let mut scratch2 = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch2_buf);

        // r to Montgomery form.
        scratch0.copy_from(&r);
        let r = &mut scratch0;
        cmpa::ct_mod_mp_mp(None, r, &order_divisor);
        // Detour: step f.
        if cmpa::ct_is_zero_mp(r).unwrap() != 0 {
            continue;
        }
        // Continue with bringing r into Montgomery form.
        let mg_r = &mut scratch1;
        cmpa::ct_to_montgomery_form_mp(mg_r, r, &order, mg_neg_order0_inv_mod_l, &mg_radix2_mod_order)
            .map_err(|_| CryptoError::Internal)?;

        // d into Montgomery form.
        let d = &mut scratch0;
        d.copy_from(&key.priv_key().ok_or(CryptoError::NoKey)?.get_d());
        let mg_d = &mut scratch2;
        cmpa::ct_to_montgomery_form_mp(mg_d, d, &order, mg_neg_order0_inv_mod_l, &mg_radix2_mod_order)
            .map_err(|_| CryptoError::Internal)?;

        // r * d.
        let mg_r_d = &mut scratch0;
        cmpa::ct_montgomery_mul_mod_mp_mp(mg_r_d, mg_r, mg_d, &order, mg_neg_order0_inv_mod_l)
            .map_err(|_| CryptoError::Internal)?;
        // Bring the product back from Montgomery form.
        cmpa::ct_montgomery_redc_mp(mg_r_d, &order, mg_neg_order0_inv_mod_l).map_err(|_| CryptoError::Internal)?;
        let r_d = mg_r_d; // Just a rename.

        // s = k + r * d;
        let mut s_buf = k_buf; // This zero-copies k into s.
        let mut s = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut s_buf);
        cmpa::ct_add_mod_mp_mp(&mut s, r_d, &order).map_err(|_| CryptoError::Internal)?;

        // Step f., the check on r has been done above already.
        if cmpa::ct_is_zero_mp(&s).unwrap() != 0 {
            continue;
        }

        break (r_buf, s_buf);
    };

    Ok((r, s))
}

/// EC Schnorr signature verification.
///
/// # Arguments:
///
/// * `digest` - The signed message digest.
/// * `signature` - The signature to verify.
/// * `pub_key` - The verification key.
/// * `scheme_hash_alg` - The hash algorithm to use for the scheme.
pub fn verify(
    digest: &[u8],
    signature: (&[u8], &[u8]),
    pub_key: &key::EccPublicKey,
    scheme_hash_alg: tpm2_interface::TpmiAlgHash,
) -> Result<(), CryptoError> {
    // Implementation according TCG TPM2 Library, Part 1, section C.4.3.3 ("EC
    // Schnorr Validate").
    let (signature_r, signature_s) = signature;
    let signature_r = cmpa::MpBigEndianUIntByteSlice::from_bytes(signature_r);
    let signature_s = cmpa::MpBigEndianUIntByteSlice::from_bytes(signature_s);

    let curve = curve::Curve::new(pub_key.get_curve_id())?;
    let curve_ops = curve.curve_ops()?;
    let order = curve.get_order();
    let order_divisor = cmpa::CtMpDivisor::new(&order, None).unwrap();

    // Step a and length sanitization of the signature's r value range.
    if cmpa::ct_is_zero_mp(&signature_s).unwrap() != 0
        || cmpa::ct_geq_mp_mp(&signature_s, &order).unwrap() != 0
        || cmpa::ct_find_last_set_bit_mp(&signature_r).1 > 8 * order.len()
    {
        return Err(CryptoError::SignatureVerificationFailure);
    }

    // Step b.
    // Bring the signature's r into range and negate it modulo the order.
    let order_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(order.len());
    let mut neg_r_buf = try_alloc_vec::<cmpa::LimbType>(order_nlimbs)?;
    let mut neg_r = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut neg_r_buf);
    neg_r.copy_from(&signature_r);
    cmpa::ct_mod_mp_mp(None, &mut neg_r, &order_divisor);
    cmpa::ct_negate_mod_mp(&mut neg_r, &order).map_err(|_| CryptoError::Internal)?;
    let mut curve_ops_scratch = curve_ops.try_alloc_scratch()?;
    let neg_r_q = curve_ops.point_scalar_mul(&neg_r, pub_key.get_point(), &mut curve_ops_scratch)?;
    drop(neg_r_buf);
    let g = curve_ops.generator()?;
    let s_g = curve_ops.point_scalar_mul(&signature_s, &g, &mut curve_ops_scratch)?;
    drop(g);
    let e = curve_ops.point_add(&s_g, &neg_r_q, &mut curve_ops_scratch)?;
    drop(s_g);
    drop(neg_r_q);
    let mut e_x_buf = try_alloc_zeroizing_vec::<u8>(curve.get_p_len())?;
    let mut e_x = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut e_x_buf);
    match e.into_affine_plain_coordinates(&mut e_x, None, &curve_ops, Some(&mut curve_ops_scratch))? {
        Ok(()) => (),
        Err(curve::ProjectivePointIntoAffineError::PointIsIdentity) => {
            return Err(CryptoError::SignatureVerificationFailure);
        }
    };
    drop(curve_ops_scratch);

    // Step c.
    let mut h = hash::HashInstance::new(scheme_hash_alg)?;
    debug_assert_eq!(e_x_buf.len(), order.len());
    h.update(io_slices::BuffersSliceIoSlicesIter::new(&[e_x_buf.as_slice(), digest]).map_infallible_err())?;
    drop(e_x_buf);
    let mut r_buf = try_alloc_vec(hash::hash_alg_digest_len(scheme_hash_alg) as usize)?;
    h.finalize_into(&mut r_buf)?;
    let r = cmpa::MpBigEndianUIntByteSlice::from_bytes(&r_buf[..r_buf.len().min(order.len())]);

    // Step d. The numeric comparison is intentional, c.f. the note in TCG TPM2
    // Library, Part 1, section C.4.3.3 ("EC Schnorr Validate").
    if cmpa::ct_eq_mp_mp(&signature_r, &r).unwrap() == 0 {
        return Err(CryptoError::SignatureVerificationFailure);
    }

    Ok(())
}

#[test]
fn test_ecschorr() {
    use alloc::vec;

    let mut rng = rng::test_rng();
    let curve_id = curve::test_curve_id();
    let curve = curve::Curve::new(curve_id).unwrap();
    let curve_ops = curve.curve_ops().unwrap();
    let key = key::EccKey::generate(&curve_ops, &mut rng, None).unwrap();
    let test_scheme_hash_alg = hash::test_hash_alg();

    let mut test_digest = vec![0u8; 512];
    for (i, b) in test_digest.iter_mut().enumerate() {
        *b = (i % u8::MAX as usize) as u8;
    }

    let (r, s) = sign(&test_digest, &key, test_scheme_hash_alg, &mut rng, None).unwrap();
    verify(&test_digest, (&r, &s), key.pub_key(), test_scheme_hash_alg).unwrap();

    let r_len = r.len();
    let mut r_invalid = r.clone();
    r_invalid[r_len - 1] ^= 1;
    assert!(matches!(
        verify(&test_digest, (&r_invalid, &s), key.pub_key(), test_scheme_hash_alg),
        Err(CryptoError::SignatureVerificationFailure)
    ));

    let s_len = s.len();
    let mut s_invalid = s.clone();
    s_invalid[s_len - 1] ^= 1;
    assert!(matches!(
        verify(&test_digest, (&r, &s_invalid), key.pub_key(), test_scheme_hash_alg),
        Err(CryptoError::SignatureVerificationFailure)
    ));

    test_digest[0] ^= 1;
    assert!(matches!(
        verify(&test_digest, (&r, &s), key.pub_key(), test_scheme_hash_alg),
        Err(CryptoError::SignatureVerificationFailure)
    ));
}
