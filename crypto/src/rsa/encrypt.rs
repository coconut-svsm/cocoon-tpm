// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of the RSA encryption primitive.

use crate::CryptoError;
use crate::utils_common::alloc::try_alloc_zeroizing_vec;
use cmpa::{self, MpMutUInt as _, MpUIntCommon as _};

/// RSA encryption primitive.
///
/// Computes *x*<sup>*e*</sup> mod *n*, with *n* denoting the public modulus and
/// *e* the public exponent.
///
/// # Arguments:
///
/// - `x` - The plaintext to encrypt in big endian format. must be less than the
///   `modulus`, otherwise an error will be returned. The result will be written
///   to `x` upon success, also in big endian format.
/// - `modulus` - The key's public modulus.
/// - `public_exponent` - The key's public exponent.
///
/// # Errors:
///
/// - [`InvalidParams`](CryptoError::InvalidParams) - The `modulus` is invalid.
/// - [`InvalidMessageLength`](CryptoError::InvalidMessageLength) - The
///   plaintext `x` as a big endian number is not less than the `modulus` or the
///   buffer length is not consistent with it.
/// - [`MemoryAllocationFailure`](CryptoError::MemoryAllocationFailure) - Some
///   buffer allocation failed.
pub fn encrypt(
    x: &mut [u8],
    modulus: &cmpa::MpBigEndianUIntByteSlice,
    public_exponent: &cmpa::MpBigEndianUIntByteSlice,
) -> Result<(), CryptoError> {
    if modulus.test_bit(0).unwrap() == 0 {
        return Err(CryptoError::InvalidParams);
    }

    // RFC 8107, 5.1.1 RSAEP, step 1: "if the message representative is not
    // between 0 and n - 1 [...]", return an error.
    let mut x = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(x);
    if cmpa::ct_lt_mp_mp(&x, modulus).unwrap() == 0 {
        return Err(CryptoError::InvalidMessageLength);
    }

    //RFC 8107, 5.1.1 RSAEP, step 2: compute x^public_exponent modulo the modulus.
    let modulus_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(modulus.len());
    let mut result = try_alloc_zeroizing_vec::<cmpa::LimbType>(modulus_nlimbs)?;
    let mut result = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut result);
    let mut scratch = try_alloc_zeroizing_vec::<cmpa::LimbType>(modulus_nlimbs)?;

    let public_exponent_nbits = cmpa::ct_find_last_set_bit_mp(public_exponent).1;
    cmpa::ct_exp_mod_odd_mp_mp(
        &mut result,
        &mut x,
        modulus,
        public_exponent,
        public_exponent_nbits,
        &mut scratch,
    )
    .map_err(|e| match e {
        cmpa::CtExpModOddMpMpError::InvalidModulus => CryptoError::InvalidParams,
        cmpa::CtExpModOddMpMpError::InconsistentOperandLengths => CryptoError::InvalidMessageLength,
        cmpa::CtExpModOddMpMpError::InsufficientResultSpace | cmpa::CtExpModOddMpMpError::InsufficientScratchSpace => {
            CryptoError::Internal
        }
    })?;

    x.copy_from(&result);

    Ok(())
}

#[test]
fn test_encrypt() {
    use crate::utils_common::alloc::try_alloc_vec;

    // This is the modulus corresponding to the prime pair for the sha256 testcase
    // in keygen.
    let modulus: [u8; 256] = cmpa::hexstr::bytes_from_hexstr_cnst::<256>(
        "bdc4ef4fe35fe8b60f24312470a8c6e59215da963dbcf933b1eacc82b9fa7a69\
         3a4d57bd4d55e1493a70d2798ce2818d0cf9e241ae0aac40218de2abe790bffb\
         4e8f83c3d0c5704e3c79910e6cff4d7faf39965e0dcb50d2bfe32be1080dbfb8\
         9726fbfba76fd5e000d8e6b455994b26a4ae22fef5768fe74c3728db7bcd94ea\
         3d20dfafa6c37e717ca96c2e37712f0997132bf9c1c1a4f2bc903a7101eb9585\
         75dc413560bb4d3f8cd5125cb285d67938cd3613f020381617a354e655297a8a\
         aec16711b105a55a25698a45b6f34266be5657de846b37b877411e727e9df99f\
         6110efe6c61e2093922a234360773aac3b19d71d7676bbcda62b19f2085a9823",
    );
    let modulus = cmpa::MpBigEndianUIntByteSlice::from_bytes(&modulus);

    let public_exponent = super::keygen::MIN_PUBLIC_EXPONENT;
    let public_exponent = cmpa::MpBigEndianUIntByteSlice::from_bytes(public_exponent);

    let mut x_buf = try_alloc_vec::<u8>(modulus.len()).unwrap();
    // "Encrypt" a zero.
    encrypt(&mut x_buf, &modulus, &public_exponent).unwrap();
    let mut x = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut x_buf);
    assert_ne!(cmpa::ct_is_zero_mp(&x).unwrap(), 0);

    // "Encrypt" a one.
    x.store_l(0, 1);
    encrypt(&mut x_buf, &modulus, &public_exponent).unwrap();
    let mut x = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut x_buf);
    assert_ne!(cmpa::ct_is_one_mp(&x).unwrap(), 0);

    // Now encrypt something real, a three.
    x.store_l(0, 3);
    encrypt(&mut x_buf, &modulus, &public_exponent).unwrap();
    let expected: [u8; 256] = cmpa::hexstr::bytes_from_hexstr_cnst::<256>(
        "9e2256121e8e2511551e99f300a10a4a5b6403a3d6ac9a6a8c945d58a36e8ffd\
         145b027da0c80aab6ec0f7ee9a68836be36904b956784960749fbf1a52c9de75\
         682c6023b34d61c92b6068b1a546c00f95691d3b440939abf3201688b9548599\
         d8d1ebb4b2e258050ffac018dfe54e52eaab62c3e8a5bf547c4c81651fba3caf\
         28fca9a3b5a3bf2390774f6efa18ce2de2b204af140905ed4154074eace75250\
         d2f4f7a592ce808428a7511a4957224dd2ab5edc458bf3cfbc5bc0d8ed8c898a\
         953b9489a93104ef430e1fc546ed9448c74a88fec00d736087bd0fef6beda7d6\
         38266a3934415f2d84290845027f47b8f15696980139c8d9bd69261e3acc9b17",
    );
    assert_eq!(x_buf, expected);
}
