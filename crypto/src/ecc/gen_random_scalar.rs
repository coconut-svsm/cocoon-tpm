// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of random scalar generation.

#[cfg(test)]
use crate::tpm2_interface;
use crate::utils_common::io_slices::{self, IoSlicesIterCommon as _};
use crate::{CryptoError, rng};
use cmpa::{self, MpMutUInt as _, MpUIntCommon as _};
use core::mem;

/// Generate a random scalar suitable for an ECC private key.
///
/// Produce a random scalar in as specified in TCG TPM2 Library, Part 1, section
/// C.5 ("ECC Key Generation").
///
/// # Arguments:
/// * `result` - Destination buffer to receive the result.
/// * `order` - Order of the ECC subgroup.
/// * `order_nbits` - Number of significant bits in `order`.
/// * `rng` - The [random number generator](rng::RngCore) used for obtaining
/// * randomness from.
/// * `additional_rng_generate_input` - Additional input to pass along to the
///   `rng`'s [generate()](rng::RngCore::generate) primitive.
pub fn tcg_tpm2_gen_random_ec_scalar(
    result: &mut [u8],
    order: &cmpa::MpBigEndianUIntByteSlice,
    order_nbits: usize,
    rng: &mut dyn rng::RngCoreDispatchable,
    additional_rng_generate_input: Option<&[Option<&[u8]>]>,
) -> Result<(), CryptoError> {
    // Generate a random integer in the range [1..order - 1] by the method of
    // oversampling. This is also used for ECC key derivation, which must be
    // reproducible across TPMs from different vendors, and thus, must follow the
    // exact steps as specified in TCG TPM2 Library, Part 1, section C.5 ("ECC
    // Key Generation").
    if result.len() != order.len() {
        return Err(CryptoError::Internal);
    }
    debug_assert_eq!(order.len(), order_nbits.div_ceil(8));

    // Obtain order_nbits + 64 (aligned to an octet multiple) bits of randomness.
    let mut extra = [0u8; 8];
    rng::rng_dyn_dispatch_generate(
        rng,
        io_slices::BuffersSliceIoSlicesMutIter::new(&mut [extra.as_mut_slice(), result]).map_infallible_err(),
        additional_rng_generate_input,
    )?;

    let mut extra = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut extra);
    let mut result = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(result);

    // If order_nbits is not a multiple of 8, shift (extra, result), interpreted as
    // a big-endian integer, to the right so it contains exactly the first
    // order_nbits + 64 bits of randomness obtained above.
    if !order_nbits.is_multiple_of(8) {
        let rshift_distance = 8 - order_nbits % 8;
        let extra_shifted_out = cmpa::ct_rshift_mp(&mut extra, rshift_distance);
        cmpa::ct_rshift_mp(&mut result, rshift_distance);

        // The bits shifted out on the right from extra need to get shifted in on the
        // left into result. So far,
        // - rshift_distance zeroes have been shifted into the most significant part of
        //   result while
        // - the bits shifted out on the right from extra are found in the most
        //   significant bits of
        // extra_shifted_out.
        // Shift them right so that they align with the
        // zeroes shifted into result on the left.
        let result_n_high_limb_bytes = (result.len() - 1) % mem::size_of::<cmpa::LimbType>() + 1;
        let result_shift_in = extra_shifted_out >> (8 * (mem::size_of::<cmpa::LimbType>() - result_n_high_limb_bytes));

        let result_nlimbs = result.nlimbs();
        result.store_l(result_nlimbs - 1, result.load_l(result_nlimbs - 1) | result_shift_in);
    }

    let order_minus_one_divisor = cmpa::CtMpDivisor::new(order, Some(1)).unwrap();
    cmpa::ct_mod_mp_mp(Some(&mut extra), &mut result, &order_minus_one_divisor);
    cmpa::ct_add_mp_l(&mut result, 1);

    Ok(())
}

#[cfg(test)]
fn test_hashdrbg_instantiate(hash_alg: tpm2_interface::TpmiAlgHash) -> rng::HashDrbg {
    extern crate alloc;
    use alloc::vec;

    let entropy_len = rng::HashDrbg::min_seed_entropy_len(hash_alg);
    let entropy = vec![0u8; entropy_len];
    rng::HashDrbg::instantiate(hash_alg, &entropy, None, None).unwrap()
}

#[test]
fn test_gen_random_scalar() {
    // Generate a couple of random scalars for the NIST P521 curve, one
    // for each enabled hash a test HashDrbg can be instantiated from.
    const NIST_P521_N: [u8; 66] = cmpa::hexstr::bytes_from_hexstr_cnst::<66>(
        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
         fffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138\
         6409",
    );

    struct TestVec {
        drbg_hash_alg: tpm2_interface::TpmiAlgHash,
        expected: &'static [u8],
    }

    static TEST_VECS: &[TestVec] = &[
        #[cfg(feature = "sha1")]
        TestVec {
            drbg_hash_alg: tpm2_interface::TpmiAlgHash::Sha1,
            expected: &cmpa::hexstr::bytes_from_hexstr_cnst::<66>(
                "01ceed34da0db9fc4905cb21745c96a4468eb61e6e21f66cb91f9ea32cb36627\
                 f989aa3922a8ecde058861a8f495ae472b84404f5084ec4f9f6957a40c47c1bd\
                 667f",
            ),
        },
        #[cfg(feature = "sha256")]
        TestVec {
            drbg_hash_alg: tpm2_interface::TpmiAlgHash::Sha256,
            expected: &cmpa::hexstr::bytes_from_hexstr_cnst::<66>(
                "009fa70c8a6ad76f93bb250503b531508acfcc6a48c98767fd794567ba7bc252\
                 ccda9c2ee4d2bb94cd6cde2e86b3e97c5512ef326e360a5a0f87d43191e52812\
                 d847",
            ),
        },
        #[cfg(feature = "sha384")]
        TestVec {
            drbg_hash_alg: tpm2_interface::TpmiAlgHash::Sha384,
            expected: &cmpa::hexstr::bytes_from_hexstr_cnst::<66>(
                "009b55a93b4e5d85bff35d844f31afd77f8fb0eaa3b29898011d2fbf78a69550\
                 3db634ec626fd921fca2b8606f76e6c345739f4ce619db70747b18d3a6d0753d\
                 c216",
            ),
        },
        #[cfg(feature = "sha512")]
        TestVec {
            drbg_hash_alg: tpm2_interface::TpmiAlgHash::Sha512,
            expected: &cmpa::hexstr::bytes_from_hexstr_cnst::<66>(
                "01dd78ed60a9d07b9545b6d4fab5f7ceb79f6404125e669672cf8aca101b68a1\
                 41ac41e8565bd3e86ecbb0ea58575b7aabbd64e0d0caecc9e344d3c97e109ecd\
                 c9b3",
            ),
        },
        #[cfg(feature = "sha3_256")]
        TestVec {
            drbg_hash_alg: tpm2_interface::TpmiAlgHash::Sha3_256,
            expected: &cmpa::hexstr::bytes_from_hexstr_cnst::<66>(
                "0180f08745248b1435541797054f618faf25926ee1c26b218013a303b96afeb0\
                 5da5f2e20d336a7fc357e27ae7f6fe0a77a8c7c83087e05988dcd2a7ea980640\
                 c259",
            ),
        },
        #[cfg(feature = "sha3_384")]
        TestVec {
            drbg_hash_alg: tpm2_interface::TpmiAlgHash::Sha3_384,
            expected: &cmpa::hexstr::bytes_from_hexstr_cnst::<66>(
                "003c629c2d1990675787ef116d6cd01ea1e20f5c517af7a96bcc7bf48d658dd9\
                 6b7dad7a2e9181b6cb997ddc44a076768ff519e36c5e30237d745941d49880b0\
                 c595",
            ),
        },
        #[cfg(feature = "sha3_512")]
        TestVec {
            drbg_hash_alg: tpm2_interface::TpmiAlgHash::Sha3_512,
            expected: &cmpa::hexstr::bytes_from_hexstr_cnst::<66>(
                "0148aad547b6804f42b19189d77d9fe942f8129c88238f1c609ed8ea41c6d5b1\
                 b178d02986c119f3f86bc3ea3f644db2c262e02cda69a20cebd6c0ca653e4808\
                 39cf",
            ),
        },
        #[cfg(feature = "sm3_256")]
        TestVec {
            drbg_hash_alg: tpm2_interface::TpmiAlgHash::Sm3_256,
            expected: &cmpa::hexstr::bytes_from_hexstr_cnst::<66>(
                "0136baaa1fd9c0943d997cd6628ff45baba6f37ba4907bfdd14ede8af40fb47a\
                 301a4720ffe37ba515935b64468b1940737bb14754e3d62ae77bb77231f45b79\
                 c70b",
            ),
        },
    ];

    for test_vec in TEST_VECS.iter() {
        let mut drbg = test_hashdrbg_instantiate(test_vec.drbg_hash_alg);
        let mut generated = [0u8; 66];
        tcg_tpm2_gen_random_ec_scalar(
            &mut generated,
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&NIST_P521_N),
            521,
            &mut drbg,
            None,
        )
        .unwrap();
        assert_eq!(generated, test_vec.expected);
    }
}
