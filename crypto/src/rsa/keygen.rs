// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of the RSA key generation.

extern crate alloc;
use alloc::vec::Vec;

#[cfg(test)]
use crate::tpm2_interface;
use crate::utils_common::{
    alloc::try_alloc_zeroizing_vec,
    io_slices::{self, IoSlicesIterCommon as _},
    zeroize,
};
use crate::{CryptoError, rng};
use cmpa::{self, MpMutUInt as _, MpUIntCommon as _};
use core::array;

/// The minimum public exponent allowed by FIPS 186-5.
///
/// It equals *2<sup>16</sup> + 1* and is also the most commonly used one.
pub const MIN_PUBLIC_EXPONENT: &[u8; 3] = &cmpa::hexstr::bytes_from_hexstr_cnst::<3>("010001");

/// Minimum number of Miller-Rabin rounds for a specific prime bit width.
///
/// Determine the minimum number of Miller-Rabin rounds to
/// conduct on a prime candidate of length `prime_nbits`, as specified
/// in NIST FIPS 186-5, B.3.1, table B1.
///
/// # Arguments:
/// - `prime_bits` - The requested width in bits of the prime to be generated.
///   Must be >= 1024.
const fn miller_rabin_rounds(prime_nbits: usize) -> u32 {
    // This is from NIST FIPS 186-5, B.3.1, table B1.
    debug_assert!(prime_nbits >= 1024);
    if prime_nbits >= 2048 {
        2
    } else if prime_nbits >= 1536 {
        3
    } else if prime_nbits >= 1024 {
        4
    } else {
        unreachable!()
    }
}

/// Generate a prime of specified width for use in a RSA private key.
///
/// Generates a prime, in accordance with NIST FIPS 186-5, A.1.3 ("Generation of
/// Random Primes that are Probably Prime"),
/// step 4 ("Generate p"), or, equivalently, step 5 ("Generate q").
///
/// # Arguments:
///
/// - `result` - The buffer to receive the generated prime in native endian
///   format. Must have exactly the size of the request `nbits` in bytes, modulo
///   [`LimbType`](cmpa::LimbType) length alignment constaints.
/// - `nbits` - The request bit width of the prime to be generated. Must be a
///   multiple of eight.
/// - `public_exponent` - The to be generated RSA key's public exponent. Must be
///   odd and at most the requested `nbits` in length.
/// - `rng` - The [`RngCore`](rng::RngCore) instance to draw random bits from.
///   If FIPS compliance is required, it must be made sure that it's an approved
///   DRBG with a security strength compatible (i.e. strong enough) for the RSA
///   key to be generated. Refer to NIST SP 800-57, part 1, rev. 5 for details.
/// - `additional_rng_generate_input` - Additional input to pass to
///   [`RngCore::generate()`](rng::RngCore::generate) on each invocation. Note
///   that if the the `rng` instance is potentially shared, this allows for
///   exclusive consideration of the additional input data, in contrast to
///   reseeding the rng with it.
/// - `retries` - The maximum number of (odd) prime candidates to test for
///   primality before giving up.
/// - `scratch` - Array of scratch buffers to use for internal computations.
///   each must have size equal to the length of the to be generated prime,
///   modulo [`LimbType`](cmpa::LimbType) length alignment constaints just as
///   `result` itself.
///
/// # Errors:
///
/// - [`RngFailure`](CryptoError::RngFailure) - The provided `rng` instance's
///   [`generate()`](rng::RngCore::generate) returned a failure condition.
/// - [`RandomSamplingRetriesExceeded`](CryptoError::RandomSamplingRetriesExceeded) - No suitable
///   prime has been found within the limit specified by `retries` of odd
///   candidates.
/// - [`MemoryAllocationFailure`](CryptoError::MemoryAllocationFailure) - Memory
///   allocation failure.
fn gen_prime(
    result: &mut [cmpa::LimbType],
    nbits: usize,
    public_exponent: &cmpa::MpBigEndianUIntByteSlice,
    rng: &mut dyn rng::RngCoreDispatchable,
    additional_rng_generate_input: Option<&[Option<&[u8]>]>,
    retries: &mut usize,
    scratch: [&mut [cmpa::LimbType]; 5],
) -> Result<(), CryptoError> {
    debug_assert_eq!(nbits % 8, 0);
    debug_assert!(nbits > 0);
    let nbytes = nbits / 8;
    let result_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(nbytes);
    debug_assert_eq!(result.len(), result_nlimbs);
    debug_assert!(public_exponent.len() <= nbytes);
    debug_assert_ne!(public_exponent.test_bit(0).unwrap(), 0);

    let [scratch0, scratch1, scratch2, scratch3, scratch4] = scratch;
    debug_assert_eq!(scratch0.len(), result_nlimbs);
    debug_assert_eq!(scratch1.len(), result_nlimbs);
    debug_assert_eq!(scratch2.len(), result_nlimbs);
    debug_assert_eq!(scratch3.len(), result_nlimbs);
    debug_assert_eq!(scratch4.len(), result_nlimbs);

    while *retries > 0 {
        *retries -= 1;

        // FIPS 186-5, A.1.3, step 4.2: "Obtain a string p of (nlen/2) bits from a DRBG
        // [...]."
        let rng_scratch = cmpa::limb_slice_as_bytes_mut(scratch0);
        let rng_scratch = rng_scratch.split_at_mut(nbytes).0;
        rng::rng_dyn_dispatch_generate(
            rng,
            io_slices::SingletonIoSliceMut::new(rng_scratch).map_infallible_err(),
            additional_rng_generate_input,
        )
        .map_err(CryptoError::from)?;
        let rng_scratch = cmpa::MpBigEndianUIntByteSlice::from_bytes(rng_scratch);
        let mut result = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(result);
        result.copy_from(&rng_scratch);
        cmpa::clear_bits_above_mp(&mut result, nbits);

        // FIPS 186-5, A.1.3, step 4.2.1: "(Optional) The two most significant bits in p
        // may be set arbitrarily."
        //
        // Step 4.4. requires that the generated p is rejected if it's
        // less than \sqrt(2) * 2^{nbits - 1}. This is so that the product of p and q
        // does indeed has a width of 2 * nbits, i.e. value >= 2^{2*nbits - 1}.
        //
        // This requirement is effectively equivalent to the generated p being
        // >= \sqrt(2) in fixed-point, radix-2 representation shifted all the way
        // to the left so that the leading one bit aligns with the most
        // significant bit of p. In fixed-point, radix-2 representation,
        // \sqrt(2) = 1.0111001... < 1.1. So, forcing p's two most significant bits
        // to one, which is permitted by step 4.2.1, will automatically implement
        // step 4.4: the generated primes would always satisfy the constraint and
        // no candidate would ever get rejected just because of this. Note that the
        // constraint itself reduces the search space by ~1.77 bits, forcing the
        // upper two bits to a fixed value 2 bits, so it doesn't really matter.
        result.set_bit_to(nbits - 1, true);
        result.set_bit_to(nbits - 2, true);

        // FIPS 186-5, A.1.3, step 4.2.3: "if p is not odd, then p = p + 1".
        result.set_bit_to(0, true);

        // FIPS 186-5, A.1.3, step 4.5: "If (GCD(p − 1, e) = 1), then:
        // step 4.5.1: "Test p for primality [...]".
        //
        // Do not compute the GCD with the public exponent at this point.  It's not
        // exactly cheap and neither a very likely scenario, so it doesn't make
        // a good filter. But at this point, it's crucial for performance to
        // sort out a large fraction of candidates as quickly as possible.
        //
        // So start with primality testing.

        // First preselection, the most effective in terms of candidate fraction
        // filtered and also the least expensive: check if the Prime Wheel Sieve
        // would skip over the current candidate, which would prove it's a
        // composite including some small prime factors (namely those of the
        // wheel's associated primorial). Note that this is equivalent to trial
        // division of the wheel primorial's factors each, but involves only a single
        // multiprecision-by-limb division, namely in the course of the wheel
        // initialization.
        let mut sieve = cmpa::PrimeWheelSieve::start_geq_than(&result);
        let sieve_delta = sieve.produce_next_delta();
        if sieve_delta != 0 {
            continue;
        }

        // GCD with a primorial of bit width about the same order as the candidate's.
        // Also equivalent to trial division.
        if cmpa::ct_composite_test_small_prime_gcd_mp(&result, [scratch0, scratch1])
            .map_err(|_| CryptoError::Internal)?
            .unwrap()
            != 0
        {
            continue;
        }

        // Now is probably a good spot to pause primality testing and implement the
        // FIPS 186-5, A.1.3, step 4.5: "If (GCD(p − 1, e) = 1) [...]" previously
        // skipped over above.
        let mut e = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(scratch0);
        e.copy_from(public_exponent);
        let mut p_minus_one = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(scratch1);
        p_minus_one.copy_from(&result);
        p_minus_one.set_bit_to(0, false); // Minus one for an odd number.
        cmpa::ct_gcd_odd_mp_mp(&mut e, &mut p_minus_one).map_err(|_| CryptoError::Internal)?;
        if cmpa::ct_is_one_mp(&e).unwrap() == 0 {
            continue;
        }

        // Alright, continue with primality testing, do the full Miller-Rabin.
        let mut mg_radix2_mod_p = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(scratch0);
        cmpa::ct_montgomery_radix2_mod_n_mp(&mut mg_radix2_mod_p, &result).map_err(|_| CryptoError::Internal)?;
        let neg_p0_inv_mod_l = cmpa::ct_montgomery_neg_n0_inv_mod_l_mp(&result).map_err(|_| CryptoError::Internal)?;
        let mut mg_radix_mod_p = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(scratch1);
        mg_radix_mod_p.copy_from(&mg_radix2_mod_p);
        cmpa::ct_montgomery_redc_mp(&mut mg_radix_mod_p, &result, neg_p0_inv_mod_l)
            .map_err(|_| CryptoError::Internal)?;
        let rounds = miller_rabin_rounds(nbits);
        let mut is_composite = false;
        let result_div = &cmpa::CtMpDivisor::new(&result, None).map_err(|_| CryptoError::Internal)?;
        for _ in 0..rounds {
            let rng_scratch = cmpa::limb_slice_as_bytes_mut(scratch2);
            let rng_scratch = rng_scratch.split_at_mut(nbytes).0;
            rng::rng_dyn_dispatch_generate(
                rng,
                io_slices::SingletonIoSliceMut::new(rng_scratch).map_infallible_err(),
                None,
            )?;
            let rng_scratch = cmpa::MpBigEndianUIntByteSlice::from_bytes(rng_scratch);
            let mut base = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(scratch3);
            base.copy_from(&rng_scratch);
            cmpa::clear_bits_above_mp(&mut base, nbits);
            cmpa::ct_mod_mp_mp(None, &mut base, result_div);
            let mut mg_base = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(scratch2);
            cmpa::ct_to_montgomery_form_mp(&mut mg_base, &base, &result, neg_p0_inv_mod_l, &mg_radix2_mod_p)
                .map_err(|_| CryptoError::Internal)?;
            if cmpa::ct_prime_test_miller_rabin_mp(&mg_base, &result, &mg_radix_mod_p, [scratch3, scratch4])
                .map_err(|_| CryptoError::Internal)?
                .unwrap()
                == 0
            {
                is_composite = true;
                break;
            }
        }
        if is_composite {
            continue;
        }

        return Ok(());
    }

    Err(CryptoError::RandomSamplingRetriesExceeded)
}

#[cfg(test)]
struct TestVec<'a> {
    drbg_hash_alg: tpm2_interface::TpmiAlgHash,
    expected_p: &'a [u8],
    expected_q: &'a [u8],
}

#[cfg(test)]
static TEST_VECS: &[TestVec] = &[
    #[cfg(feature = "sha1")]
    TestVec {
        drbg_hash_alg: tpm2_interface::TpmiAlgHash::Sha1,
        expected_p: &cmpa::hexstr::bytes_from_hexstr_cnst::<128>(
            "d754c75d3f9c9c6d1e0d8991fc784f0cde4ba0c0108bacc784f525b14b1352ab\
             c1d93de494b227c90a32756e36b5304d44427d3a44828106b7c22929ccbf248f\
             b567965b455e8d29b05fdec19e308062fb20505fafbafcbbee8ed97c486d3b0b\
             a91755c5dc21787acd9db033926a6c5cfd49138900713f79ce557593d5f10a29",
        ),
        expected_q: &cmpa::hexstr::bytes_from_hexstr_cnst::<128>(
            "e84dc1b715821d9cc59bcf41ae4b3bad881aade1fc73cf01f4b652b247a03873\
             126ca4d2c8f2b45b6c64e66f1fd94585e57dc0d6d79862ca3fcdbbba1f0a5717\
             496116b6f3f0154c18e56f44703ce17618c358b0a74e5dfc6ed7d3f948095644\
             575a0d4a361e06cdb4a91311ad546b6991fd7aeff665bf075b3a0ed3e82ccfff",
        ),
    },
    #[cfg(feature = "sha256")]
    TestVec {
        drbg_hash_alg: tpm2_interface::TpmiAlgHash::Sha256,
        expected_p: &cmpa::hexstr::bytes_from_hexstr_cnst::<128>(
            "c13469df9fbc5ddc9b33713299d2911609ae5a772cb253a9634071639130bb47\
             4e2820a3bd859a631e660f1b28d2a03942ee2ad7fa68d94a8870ef70ba534792\
             d4b62426ae7e5b4c7c85087f358266b31b8cfebe9379744abfbbc6298f158189\
             bd503f5657dc64ea2031a6537ee24625b44c935e28c12b8b2c2b46db50c3aaa1",
        ),
        expected_q: &cmpa::hexstr::bytes_from_hexstr_cnst::<128>(
            "fb72ac78ef217f465d7f434ec4390693784e0cc53e477ec9b2635d96e0625c8c\
             15c009e6b7bd444cc6a6c90072ad48567a4126457164c1a438b9b2991f525d4e\
             692777c8057682ec2ca63da9680f12a9fe2f88aa1edbed8ed3d7c11d5988d948\
             a5ad023b2edab24674f8ef720041663e87b29d5d64774b70bef15232a46ef043",
        ),
    },
    #[cfg(feature = "sha384")]
    TestVec {
        drbg_hash_alg: tpm2_interface::TpmiAlgHash::Sha384,
        expected_p: &cmpa::hexstr::bytes_from_hexstr_cnst::<128>(
            "d10923c21464e43c5922d20c6786108142908ab542d11482046df72e838e507e\
             128133a8b6f2e958299bf1a5853db12464ef4d42decc8a793d635dcfd3526607\
             f4dd9dcbbb540cba5e729615cf8d39fe58f80fe341f123fc7c36d4e8e4d91a3d\
             294933d52ca0391cb91902118e93296de24bd903373afbb843a58de795977915",
        ),
        expected_q: &cmpa::hexstr::bytes_from_hexstr_cnst::<128>(
            "eb6e9cb54025562eaeb664469a3a0f39978282aea588f59a4932faa780e5c425\
             0e5bcc4212ff80bcb7a116c15e54bd87f36c53208fff1235207312b9f8bdd864\
             fa6ed0d8946ced8cd16b091a11e7dd6c7123e4a1035b5eb99043153836dbe9ca\
             c0e1ee8b30f77f650da6aff1a18b31580ca3e400736ceadd1c21b9b87f8047cb",
        ),
    },
    #[cfg(feature = "sha512")]
    TestVec {
        drbg_hash_alg: tpm2_interface::TpmiAlgHash::Sha512,
        expected_p: &cmpa::hexstr::bytes_from_hexstr_cnst::<128>(
            "fd3642b1ecf3e095671f4c37ab2ee6efcd9a3ccca803b9fe86f8b7958ea725b7\
             0a6cba72b272cca8ee5264dc468fecbcc811853a0b3b142c2935d7d5af3cd2ba\
             2ef7c22fbc4329da3ae821a03f0221516ea74b6b9f55e0085d8c5adb7abb407d\
             d23216ab634d26b12d8575dcd8f78d20209bae6f00cede9617c66dc8d62d5bab",
        ),
        expected_q: &cmpa::hexstr::bytes_from_hexstr_cnst::<128>(
            "ed865e02b7992f6449b24b855238d2e5ac17809be61ec6fec026b9aaff4f891f\
             7b8ae7202d5a33945366c1148aa3a075e0656f55f83853a819e4109a56f63453\
             3e57a0c30df599d50156496ebb476ee7ba3fc3f713d433b0029c4197400f88c5\
             0e71c692425234bb6acbe11e5d5020c4cdd059ea6692121ee52c6fa6379680e7",
        ),
    },
    #[cfg(feature = "sha3_256")]
    TestVec {
        drbg_hash_alg: tpm2_interface::TpmiAlgHash::Sha3_256,
        expected_p: &cmpa::hexstr::bytes_from_hexstr_cnst::<128>(
            "f5e70d18c58c2af9f776bc56b0250474a0b2d53c308acb2cf32138312a53a4aa\
             f01504de4fb61f89dca7bb89f2cae0d7bf993c75a1a649d7f3835c94d9968810\
             098e6d2cc18cb40c75257e4bd0866dc8a5e7d604e449209b3f1682a37f6f4ea5\
             5d8b136203802d5d2bd6fc4a87a283b52e2eb0f9d2e24d577b13682aee6eec0b",
        ),
        expected_q: &cmpa::hexstr::bytes_from_hexstr_cnst::<128>(
            "e16d754f8f426108cf97c6f838bfe0878aceec7cd5808b8c0869789d0b0d838a\
             175f31aacb8d24de00f8b2002fd83608473977026b70e0b6c1b963a91adbe5ea\
             28ee94ec1b3f09d69d73788a3f7f102a1404e3d6fe8452f7ed0849b2748e25e9\
             25a1481a9d6f41856630584ecbf0989de2368872249b0a147bb9e4aef207243d",
        ),
    },
    #[cfg(feature = "sha3_384")]
    TestVec {
        drbg_hash_alg: tpm2_interface::TpmiAlgHash::Sha3_384,
        expected_p: &cmpa::hexstr::bytes_from_hexstr_cnst::<128>(
            "f9598e8ba47709b0bd12509e835e17b5c050c88cf60cfdccf19f6a6e6758e2a8\
             b2738299b034c37d107b95ae0a733b92b0ba4b4fefed3c01d80654ca1d64a223\
             617637d43d61c7d869a32c50c8793a8264cc683dba60ff256147e281761ff6a6\
             2b614280cc9ea3280030d49705adb103be2a410ec34b5b38de9efcfd8ffdffb3",
        ),
        expected_q: &cmpa::hexstr::bytes_from_hexstr_cnst::<128>(
            "c983168abc5fac66c3ceb8f17cab7dec572323744274e127a27c14ea9cf535d1\
             c3ba04a38ffb0bd778f3bbce63b6a8837af99e0da580e4f543f8c3cecb532e13\
             7512b49313b4ef5c07e9134052ed05d8390cffd31fbdfc3efcc3c1afc62d7f19\
             c7eaa68f792adf35011d964fcf2450bf398f210d33b9879ebde4ab877b4cae33",
        ),
    },
    #[cfg(feature = "sha3_512")]
    TestVec {
        drbg_hash_alg: tpm2_interface::TpmiAlgHash::Sha3_512,
        expected_p: &cmpa::hexstr::bytes_from_hexstr_cnst::<128>(
            "c8f8455fe25ec3a785635bca6893d790ab35f1189992f9c47c40195bbbf5f554\
             ca7bd9e62f707a717e439ac609be83d2b8726d0de1fe5472d4c7726a547bc47c\
             83f7194b15299cd4a161d70ac3dc572caac80515b135508bb2e88cf50b8c42e1\
             033b28f132c6750d104f6457733d105fdf6fac71166f64fada00ee4efdad56a9",
        ),
        expected_q: &cmpa::hexstr::bytes_from_hexstr_cnst::<128>(
            "c17f9ebf814d30139c6e026cd7fef60835b1d5287d5e3866bab14b59936e1491\
             78ebf5e3649af1acaff837c557a52c42777e8c1904b3a05150b4304199223763\
             2faa03de1be5333b9209bb054c7a64b705cc8185ef7f6ecc70d46eff47f15587\
             75ca8bf06b7ec7b99d3744bad93df6117aaf9c8558c47d3a162159599433a477",
        ),
    },
];

#[cfg(test)]
fn test_hashdrbg_instantiate(hash_alg: tpm2_interface::TpmiAlgHash) -> rng::HashDrbg {
    use alloc::vec;

    let entropy_len = rng::HashDrbg::min_seed_entropy_len(hash_alg);
    let entropy = vec![0u8; entropy_len];
    rng::HashDrbg::instantiate(hash_alg, &entropy, None, None).unwrap()
}

#[test]
fn test_gen_prime() {
    use alloc::vec;
    for test_vec in TEST_VECS.iter() {
        let mut drbg = test_hashdrbg_instantiate(test_vec.drbg_hash_alg);

        let prime_len = test_vec.expected_p.len();
        let prime_nbits = 8 * prime_len;
        let prime_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(prime_len);
        let mut result = vec![0 as cmpa::LimbType; prime_nlimbs];
        let mut scratch0 = vec![0 as cmpa::LimbType; prime_nlimbs];
        let mut scratch1 = vec![0 as cmpa::LimbType; prime_nlimbs];
        let mut scratch2 = vec![0 as cmpa::LimbType; prime_nlimbs];
        let mut scratch3 = vec![0 as cmpa::LimbType; prime_nlimbs];
        let mut scratch4 = vec![0 as cmpa::LimbType; prime_nlimbs];
        let mut retries = 5 * prime_nbits;

        let scratch = [
            scratch0.as_mut_slice(),
            scratch1.as_mut_slice(),
            scratch2.as_mut_slice(),
            scratch3.as_mut_slice(),
            scratch4.as_mut_slice(),
        ];

        let e = cmpa::MpBigEndianUIntByteSlice::from_bytes(MIN_PUBLIC_EXPONENT);
        gen_prime(&mut result, prime_nbits, &e, &mut drbg, None, &mut retries, scratch).unwrap();

        let result = cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&result);
        let expected = cmpa::MpBigEndianUIntByteSlice::from_bytes(test_vec.expected_p);
        assert_ne!(cmpa::ct_eq_mp_mp(&result, &expected).unwrap(), 0);
    }
}

/// Validate a public exponent's value.
///
/// Verify that the specified `public_exponent` is in line with FIPS 186-5,
/// A.1.3, step 2 ("Generation of Random Primes that are Probably Prime"): it
/// should be greater than *2<sup>16</sup>*, smaller than *2<sup>256</sup>* and
/// odd.
///
/// Also see [`MIN_PUBLIC_EXPONENT`] for the minimum such value satisfying all
/// this.
///
/// # Arguments:
///
/// - `public_exponent` - The public exponent to validate.
pub fn public_exponent_is_valid(public_exponent: &cmpa::MpBigEndianUIntByteSlice) -> bool {
    cmpa::ct_geq_mp_mp(
        public_exponent,
        &cmpa::MpBigEndianUIntByteSlice::from_bytes(MIN_PUBLIC_EXPONENT),
    )
    .unwrap()
        != 0
        && public_exponent.test_bit(0).unwrap() != 0
        && cmpa::ct_find_last_set_bit_mp(public_exponent).1 <= 256
}

/// Generate a RSA private key prime pair for specified modulus width (FIPS
/// 186-5).
///
/// Generate a prime pair in accordance with NIST FIPS 186-5, A.1.3 ("Generation
/// of Random Primes that are Probably Prime"). See also
/// [`gen_prime_pair_nist_sp800_56br2()`], which enforces somewhat
/// stricter constraints on the generated pair and is built on the grounds of
/// this function here.
///
/// - `result_p` - The buffer to receive the first generated prime in native
///   endian format. Must be exactly half the size of the request
///   `modulus_nbits` in bytes, modulo [`LimbType`](cmpa::LimbType) length
///   alignment constaints.
/// - `result_q` - The buffer to receive the second generated prime in native
///   endian format. Must be exactly the half the size of the request
///   `modulus_nbits` in bytes, modulo [`LimbType`](cmpa::LimbType) length
///   alignment constaints.
/// - `modulus_nbits` - The requested bit width of the resulting public modulus.
///   Must be an even number of bytes, in units of bits. Must not be smaller
///   than 2048. Otherwise an [`InvalidParams`](CryptoError::InvalidParams) will
///   be returned.
/// - `public_exponent` - The public exponent that will be used with the
///   generated key. Must adhere to the requirements of
///   [`public_exponent_is_valid()`], otherwise an error of
///   [`InvalidParams`](CryptoError::InvalidParams) will be returned
/// - `rng` - The [`RngCore`](rng::RngCore) instance to draw random bits from.
///   If FIPS compliance is required, it must be made sure that it's an approved
///   DRBG with a security strength compatible (i.e. strong enough) for the RSA
///   key to be generated. Refer to NIST SP 800-57, part 1, rev. 5 for details.
/// - `additional_rng_generate_input` - Additional input to pass to
///   [`RngCore::generate()`](rng::RngCore::generate) on each invocation. Note
///   that if the the `rng` instance is potentially shared, this allows for
///   exclusive consideration of the additional input data, in contrast to
///   reseeding the rng with it.
///
/// # Errors:
///
/// - [`InvalidParams`](CryptoError::InvalidParams) - Invalid value of either
///   the requested `modulus_nbits` or `public_exponent`.
/// - [`RngFailure`](CryptoError::RngFailure) - The provided `rng` instance's
///   [`generate()`](rng::RngCore::generate) returned a failure condition.
/// - [`RandomSamplingRetriesExceeded`](CryptoError::RandomSamplingRetriesExceeded) - No suitable
///   prime has been found within the search limits specified by FIPS 186-5,
///   A.1.3.
/// - [`MemoryAllocationFailure`](CryptoError::MemoryAllocationFailure) - Memory
///   allocation failure.
fn gen_prime_pair_fips_186_5(
    result_p: &mut [cmpa::LimbType],
    result_q: &mut [cmpa::LimbType],
    modulus_nbits: usize,
    public_exponent: &cmpa::MpBigEndianUIntByteSlice,
    rng: &mut dyn rng::RngCoreDispatchable,
    additional_rng_generate_input: Option<&[Option<&[u8]>]>,
) -> Result<(), CryptoError> {
    // FIPS 186-5, A.1.3, step 1.
    if modulus_nbits % (2 * 8) != 0 || modulus_nbits < 2048 || public_exponent.len() > modulus_nbits / 8 {
        return Err(CryptoError::InvalidParams);
    }

    // FIPS 186-5, A.1.3, step 2.
    if !public_exponent_is_valid(public_exponent) {
        return Err(CryptoError::InvalidParams);
    }

    // FIPS 186-5, A.1.3, step 4: generate p.
    let prime_nbits = modulus_nbits / 2;
    let prime_len = prime_nbits / 8;
    let prime_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(prime_len);
    debug_assert_eq!(result_p.len(), prime_nlimbs);
    debug_assert_eq!(result_q.len(), prime_nlimbs);

    let mut scratch: [zeroize::Zeroizing<Vec<cmpa::LimbType>>; 5] =
        array::from_fn(|_| zeroize::Zeroizing::new(Vec::new()));
    for s in scratch.iter_mut() {
        *s = try_alloc_zeroizing_vec(prime_nlimbs)?;
    }

    let mut p_retries = 5 * modulus_nbits; // C.f. FIPS 186-5, A.1.3, step 4.7
    let [scratch0, scratch1, scratch2, scratch3, scratch4] = &mut scratch;
    if let Err(e) = gen_prime(
        result_p,
        prime_nbits,
        public_exponent,
        rng,
        additional_rng_generate_input,
        &mut p_retries,
        [
            scratch0.as_mut_slice(),
            scratch1.as_mut_slice(),
            scratch2.as_mut_slice(),
            scratch3.as_mut_slice(),
            scratch4.as_mut_slice(),
        ],
    ) {
        zeroize::Zeroize::zeroize(result_p);
        return Err(e);
    }

    // FIPS 186-5, A.1.3, step 5: generate q.
    let mut q_retries = 10 * modulus_nbits; // C.f. FIPS 186-5, A.1.3, step 5.8.

    // The loop terminates upon gen_prime() either upon success, or once gen_prime()
    // exceeds the q_retries.
    loop {
        if let Err(e) = gen_prime(
            result_q,
            prime_nbits,
            public_exponent,
            rng,
            additional_rng_generate_input,
            &mut q_retries,
            [
                scratch0.as_mut_slice(),
                scratch1.as_mut_slice(),
                scratch2.as_mut_slice(),
                scratch3.as_mut_slice(),
                scratch4.as_mut_slice(),
            ],
        ) {
            zeroize::Zeroize::zeroize(result_p);
            zeroize::Zeroize::zeroize(result_q);
            return Err(e);
        }

        // FIPS 186-5, A.1.3, step 5.5: if |p - q| <= 2^{prime_nbits - 100}, resume the
        // search.
        let p = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(result_p);
        let q = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(result_q);
        let mut p_q_diff = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(scratch0);
        p_q_diff.copy_from(&p);
        let is_neg = cmpa::ct_sub_mp_mp(&mut p_q_diff, &q);
        cmpa::ct_negate_cond_mp(&mut p_q_diff, cmpa::LimbChoice::from(is_neg));
        let (_, p_q_diff_width) = cmpa::ct_find_last_set_bit_mp(&p_q_diff);
        if p_q_diff_width > prime_nbits - 100 {
            // If p_q_diff_width == prime_nbits - 100 + 1, there must be at least one less
            // significant bit set. If at exactly that boundary, clear anything at and above
            // out and see if the remaining tail is non-zero.
            let need_nonzero_tail = cmpa::ct_eq_usize_usize(p_q_diff_width, prime_nbits - 100 + 1);
            cmpa::ct_clear_bits_above_mp(
                &mut p_q_diff,
                need_nonzero_tail.select_usize(prime_nbits, p_q_diff_width - 1),
            );
            if cmpa::ct_is_zero_mp(&p_q_diff).unwrap() != 0 {
                continue;
            }
        } else {
            continue;
        }
        break;
    }

    Ok(())
}

#[test]
fn test_gen_prime_pair_fips_186_5() {
    use alloc::vec;

    for test_vec in TEST_VECS.iter() {
        let mut drbg = test_hashdrbg_instantiate(test_vec.drbg_hash_alg);

        let prime_len = test_vec.expected_p.len();
        let prime_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(prime_len);
        debug_assert_eq!(prime_len, test_vec.expected_q.len());
        let modulus_len = 2 * prime_len;
        let modulus_nbits = 8 * modulus_len;
        let mut result_p = vec![0 as cmpa::LimbType; prime_nlimbs];
        let mut result_q = vec![0 as cmpa::LimbType; prime_nlimbs];

        let e = cmpa::MpBigEndianUIntByteSlice::from_bytes(MIN_PUBLIC_EXPONENT);
        gen_prime_pair_fips_186_5(&mut result_p, &mut result_q, modulus_nbits, &e, &mut drbg, None).unwrap();

        let result_p = cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&result_p);
        let result_q = cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&result_q);

        let expected_p = cmpa::MpBigEndianUIntByteSlice::from_bytes(test_vec.expected_p);
        assert_ne!(cmpa::ct_eq_mp_mp(&result_p, &expected_p).unwrap(), 0);

        let expected_q = cmpa::MpBigEndianUIntByteSlice::from_bytes(test_vec.expected_q);
        assert_ne!(cmpa::ct_eq_mp_mp(&result_q, &expected_q).unwrap(), 0);
    }
}

/// Generate a RSA private key prime pair for specified modulus width (NIST
/// SP800-56B rev. 2).
///
/// Generate a prime pair in accordance with NIST SP800-56B rev. 2
/// ("Recommendation for Pair-Wise Key Establishment Using Integer Factorization
/// Cryptography"), sec. 6.3.1 ("RSAKPG1 Family: RSA Key-Pair Generation with a
/// Fixed Public Exponent"). It is almost equivalent to
/// [`gen_prime_pair_fips_186_5()`], but imposes an additional lower bound
/// on the bit width of the resulting private exponent.
///
/// # Arguments:
///
/// Please refer to [`gen_prime_pair_fips_186_5()`].
///
/// # Errors:
///
/// Please refer to [`gen_prime_pair_fips_186_5()`].
pub fn gen_prime_pair_nist_sp800_56br2(
    result_p: &mut [cmpa::LimbType],
    result_q: &mut [cmpa::LimbType],
    modulus_nbits: usize,
    public_exponent: &cmpa::MpBigEndianUIntByteSlice,
    rng: &mut dyn rng::RngCoreDispatchable,
    additional_rng_generate_input: Option<&[Option<&[u8]>]>,
) -> Result<(), CryptoError> {
    if modulus_nbits % (2 * 8) != 0 || modulus_nbits < 2048 || public_exponent.len() > modulus_nbits / 8 {
        return Err(CryptoError::InvalidParams);
    }

    let prime_nbits = modulus_nbits / 2;
    let prime_len = prime_nbits / 8;
    let prime_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(prime_len);
    debug_assert_eq!(result_p.len(), prime_nlimbs);
    debug_assert_eq!(result_q.len(), prime_nlimbs);

    let mut retries = 2;
    while retries > 0 {
        retries -= 1;

        // NIST SP800-56B rev.2, 6.3.1.1 ("rsakpg1-basic"), step 2: "Generate the prime
        // factors p and q, as specified in FIPS 186.".
        gen_prime_pair_fips_186_5(
            result_p,
            result_q,
            modulus_nbits,
            public_exponent,
            rng,
            additional_rng_generate_input,
        )?;

        // NIST SP800-56B rev.2, 6.3.1.1 ("rsakpg1-basic"), step 3: additional
        // requirement over NIST FIPS 186-5: the private exponent, computed as d
        // = e^{-1} mod LCM(p - 1, q -1), must be greater than 2^prime_bits.
        // Calculate the LCM first.
        let p = cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(result_p);
        let q = cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(result_q);

        // Two small prime_len buffers for p - 1 and q - 1.
        let mut p_q_minus_one: [zeroize::Zeroizing<Vec<cmpa::LimbType>>; 2] =
            array::from_fn(|_| zeroize::Zeroizing::new(Vec::new()));
        for s in p_q_minus_one.iter_mut() {
            *s = match try_alloc_zeroizing_vec(prime_nlimbs) {
                Ok(buf) => buf,
                Err(e) => {
                    zeroize::Zeroize::zeroize(result_p);
                    zeroize::Zeroize::zeroize(result_q);
                    return Err(CryptoError::from(e));
                }
            };
        }

        let mut scratch: [zeroize::Zeroizing<Vec<cmpa::LimbType>>; 6] =
            array::from_fn(|_| zeroize::Zeroizing::new(Vec::new()));
        let modulus_len = modulus_nbits / 8;
        let modulus_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(modulus_len);
        // Only allocate the first two for the LCM computation.
        for s in scratch.iter_mut().take(2) {
            *s = match try_alloc_zeroizing_vec(modulus_nlimbs) {
                Ok(buf) => buf,
                Err(e) => {
                    zeroize::Zeroize::zeroize(result_p);
                    zeroize::Zeroize::zeroize(result_q);
                    return Err(CryptoError::from(e));
                }
            };
        }

        let [p_minus_one, q_minus_one] = &mut p_q_minus_one;
        let mut p_minus_one = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(p_minus_one);
        p_minus_one.copy_from(&p);
        p_minus_one.set_bit_to(0, false); // Odd integer minus one.
        let mut q_minus_one = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(q_minus_one);
        q_minus_one.copy_from(&q);
        q_minus_one.set_bit_to(0, false); // Odd integer minus one.

        let [lcm, lcm_scratch, _, _, _, _] = &mut scratch;
        let mut lcm = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(lcm);
        cmpa::ct_lcm_mp_mp(
            &mut lcm,
            &mut p_minus_one,
            prime_len,
            &mut q_minus_one,
            prime_len,
            lcm_scratch,
        )
        .map_err(|_| CryptoError::Internal)?;

        // The p/q_minus_one buffers aren't needed any longer.
        drop(p_q_minus_one);

        // Allocate the remaining four modulus_len scratch buffers for the modinv
        // computation below.
        for s in scratch.iter_mut().skip(2) {
            *s = match try_alloc_zeroizing_vec(modulus_nlimbs) {
                Ok(buf) => buf,
                Err(e) => {
                    zeroize::Zeroize::zeroize(result_p);
                    zeroize::Zeroize::zeroize(result_q);
                    return Err(CryptoError::from(e));
                }
            };
        }

        let [lcm, d, scratch0, scratch1, scratch2, scratch3] = &mut scratch;
        let mut lcm = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(lcm);
        let mut d = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(d);
        d.copy_from(public_exponent);
        // Note that the gen_prime() has already checked that the public_exponent is
        // coprime with both, p - 1 and q - 1, so the inverse does exist.
        cmpa::ct_inv_mod_mp_mp(&mut d, &mut lcm, [scratch0, scratch1, scratch2, scratch3])
            .map_err(|_| CryptoError::Internal)?;

        let (_, d_width) = cmpa::ct_find_last_set_bit_mp(&d);
        let mut d_is_in_range = false;
        if d_width > prime_nbits {
            // If d_width == prime_nbits + 1, there must be at least one less significant
            // bit set. If at exactly that boundary, clear anything at and above
            // out and see if the remaining tail is non-zero.
            let need_nonzero_tail = cmpa::ct_eq_usize_usize(d_width, prime_nbits + 1);
            cmpa::ct_clear_bits_above_mp(&mut d, need_nonzero_tail.select_usize(modulus_nbits, d_width - 1));
            d_is_in_range = cmpa::ct_is_zero_mp(&d).unwrap() == 0;
        }
        if d_is_in_range {
            return Ok(());
        }
        zeroize::Zeroize::zeroize(result_p);
        zeroize::Zeroize::zeroize(result_q);
    }

    Err(CryptoError::RandomSamplingRetriesExceeded)
}

#[test]
fn test_gen_prime_pair_nist_sp800_56br2() {
    use alloc::vec;

    for test_vec in TEST_VECS.iter() {
        let mut drbg = test_hashdrbg_instantiate(test_vec.drbg_hash_alg);

        let prime_len = test_vec.expected_p.len();
        let prime_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(prime_len);
        debug_assert_eq!(prime_len, test_vec.expected_q.len());
        let modulus_len = 2 * prime_len;
        let modulus_nbits = 8 * modulus_len;
        let mut result_p = vec![0 as cmpa::LimbType; prime_nlimbs];
        let mut result_q = vec![0 as cmpa::LimbType; prime_nlimbs];

        let e = cmpa::MpBigEndianUIntByteSlice::from_bytes(MIN_PUBLIC_EXPONENT);
        gen_prime_pair_nist_sp800_56br2(&mut result_p, &mut result_q, modulus_nbits, &e, &mut drbg, None).unwrap();

        let result_p = cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&result_p);
        let result_q = cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&result_q);

        let expected_p = cmpa::MpBigEndianUIntByteSlice::from_bytes(test_vec.expected_p);
        assert_ne!(cmpa::ct_eq_mp_mp(&result_p, &expected_p).unwrap(), 0);

        let expected_q = cmpa::MpBigEndianUIntByteSlice::from_bytes(test_vec.expected_q);
        assert_ne!(cmpa::ct_eq_mp_mp(&result_q, &expected_q).unwrap(), 0);
    }
}
