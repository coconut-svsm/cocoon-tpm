// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of the NIST SP800-90Ar1 Hash_DRBG construction.

extern crate alloc;
use alloc::vec::Vec;

use super::{ReseedableRngCore, RngCore, RngGenerateError, RngReseedError};
use crate::{
    CryptoError, hash,
    io_slices::{CryptoPeekableIoSlicesIter, CryptoWalkableIoSlicesMutIter, EmptyCryptoIoSlices},
};
use crate::{
    tpm2_interface,
    utils_common::{
        alloc::try_alloc_zeroizing_vec,
        io_slices::{self, IoSlicesIterCommon},
        zeroize,
    },
};
use cmpa;
use core::{convert, mem};

/// NIST SP800-90Ar1 Hash_DRBG [random number generator](RngCore)
/// implementation.
pub struct HashDrbg {
    /// Hash algorithm used for the construction.
    alg: tpm2_interface::TpmiAlgHash,

    /// Number of requests processed since last (re)seed
    reseed_counter: u64,

    v: zeroize::Zeroizing<Vec<u8>>,
    c: zeroize::Zeroizing<Vec<u8>>,
}

impl HashDrbg {
    const MAX_REQUESTS: u64 = 1u64 << 48;
    const MAX_REQUEST_LEN: u32 = 1u32 << 16; // 2^19 bits

    pub fn min_seed_entropy_len(alg: tpm2_interface::TpmiAlgHash) -> usize {
        // If the preimage resistance security strength is unknown/unspecified,
        // resort to the digest size.
        match hash::hash_alg_preimage_security_strength(alg) {
            Some(strength) => (strength as usize).div_ceil(8),
            None => hash::hash_alg_digest_len(alg) as usize,
        }
    }

    /// Instantiate a `HashDrbg` construction.
    ///
    /// The provided seed entropy must be at least the underlying hash
    /// algorithm's digest length in size.
    ///
    /// # Arguments:
    ///
    /// * `alg` - Underlying hash algorithm to use.
    /// * `entropy` - The seed entropy. Must be at least
    ///   [`min_seed_entropy_len()`](Self::min_seed_entropy_len) in length.
    /// * `nonce` - The `nonce` input parameter specified in NIST SP800-90Ar1.
    /// * `personalization` - The `personalization` input parameter specified in
    ///   NIST SP800-90Ar1.
    pub fn instantiate(
        alg: tpm2_interface::TpmiAlgHash,
        entropy: &[u8],
        nonce: Option<&[u8]>,
        personalization: Option<&[u8]>,
    ) -> Result<Self, CryptoError> {
        if entropy.len() < Self::min_seed_entropy_len(alg) {
            return Err(CryptoError::InsufficientSeedLength);
        }

        // NIST SP 800-90Ar1, 10.1.1.2: Hash_DRBG_Instantiate_algorithm.
        let seedlen = Self::seedlen_for_hash_alg(alg)?;
        let mut hash_instance = zeroize::ZeroizingFlat::new(hash::HashInstance::new(alg)?);
        let digest_len = hash_instance.digest_len();
        let mut digest_scratch_buf = try_alloc_zeroizing_vec::<u8>(digest_len)?;
        let mut v = try_alloc_zeroizing_vec::<u8>(seedlen)?;
        let mut c = try_alloc_zeroizing_vec::<u8>(seedlen)?;

        // Step 1.)
        let seed_material = [Some(entropy), nonce, personalization];
        let seed_material = io_slices::GenericIoSlicesIter::new(seed_material.iter().filter_map(|b| b.map(Ok)), None);
        // Step 2-3.);
        Self::hash_df::<_, EmptyCryptoIoSlices>(
            &mut hash_instance,
            seed_material,
            None,
            &mut v,
            &mut digest_scratch_buf,
        )?;
        // Step 4.);
        Self::hash_df::<_, EmptyCryptoIoSlices>(
            &mut hash_instance,
            io_slices::BuffersSliceIoSlicesIter::new([[0x00u8].as_slice(), &v].as_slice()),
            None,
            &mut c,
            &mut digest_scratch_buf,
        )?;
        // Step 5.)
        let reseed_counter = 1;

        Ok(Self {
            alg,
            reseed_counter,
            v,
            c,
        })
    }

    fn reseed<'a, AII: CryptoPeekableIoSlicesIter<'a>>(
        &mut self,
        entropy: &[u8],
        mut additional_input: Option<AII>,
    ) -> Result<(), RngReseedError> {
        if entropy.len() < Self::min_seed_entropy_len(self.alg) {
            return Err(RngReseedError::CryptoError(CryptoError::InsufficientSeedLength));
        }

        // NIST SP 800-90Ar1, 10.1.1.3: Hash_DRBG Reseed_algorithm.
        let mut hash_instance = zeroize::ZeroizingFlat::new(hash::HashInstance::new(self.alg)?);
        let digest_len = hash_instance.digest_len();
        // The code below hashes into v[] and c[], which are of size
        // seedlen_for_hash_alg() and thus, not aligned to the digest_len.
        let mut digest_scratch_buf =
            try_alloc_zeroizing_vec::<u8>(digest_len).map_err(|e| RngReseedError::CryptoError(CryptoError::from(e)))?;

        // Spare a reallocation, swap V and C. The old V, now in self.c, is getting
        // hashed into the new state below.
        mem::swap(&mut self.v, &mut self.c);
        // Step 1.)
        let seed_material = [[0x01u8].as_slice(), self.c.as_slice(), entropy];
        // Step 2-3.)
        Self::hash_df(
            &mut hash_instance,
            io_slices::BuffersSliceIoSlicesIter::new(seed_material.as_slice()),
            additional_input.as_mut(),
            &mut self.v,
            &mut digest_scratch_buf,
        )
        .map_err(RngReseedError::CryptoError)?;
        // Step 4.)
        Self::hash_df::<_, EmptyCryptoIoSlices>(
            &mut hash_instance,
            io_slices::BuffersSliceIoSlicesIter::new([[0x00u8].as_slice(), &self.v].as_slice()),
            None,
            &mut self.c,
            &mut digest_scratch_buf,
        )
        .map_err(RngReseedError::CryptoError)?;

        // Step 5.)
        self.reseed_counter = 1;

        Ok(())
    }

    fn generate<'a, 'b, OI: CryptoWalkableIoSlicesMutIter<'a>, AII: CryptoPeekableIoSlicesIter<'b>>(
        &mut self,
        mut output: OI,
        mut additional_input: Option<AII>,
    ) -> Result<(), RngGenerateError> {
        let mut hash_instance = zeroize::ZeroizingFlat::new(hash::HashInstance::new(self.alg)?);
        let digest_len = hash_instance.digest_len();

        let mut digest_scratch_buf = try_alloc_zeroizing_vec::<u8>(digest_len)
            .map_err(|e| RngGenerateError::CryptoError(CryptoError::from(e)))?;
        while !output.is_empty().map_err(RngGenerateError::CryptoError)? {
            // NIST SP 800-90Ar1, 10.1.1.4: Hash_DRBG_Generate_algorithm.
            // Step 1.)
            if self.reseed_counter > Self::MAX_REQUESTS {
                return Err(RngGenerateError::ReseedRequired);
            }

            // Step 2.)
            if let Some(additional_input) = additional_input.as_mut() {
                if !additional_input.is_empty().map_err(RngGenerateError::CryptoError)? {
                    // Step 2.1.)
                    hash_instance
                        .update(
                            io_slices::BuffersSliceIoSlicesIter::new(&[[0x02u8].as_slice(), &self.v])
                                .map_infallible_err(),
                        )
                        .map_err(RngGenerateError::CryptoError)?;
                    hash_instance
                        .update(additional_input.decoupled_borrow())
                        .map_err(RngGenerateError::CryptoError)?;
                    hash_instance.finalize_into_reset(&mut digest_scratch_buf)?;
                    // Step 2.2.)
                    let mut v = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut self.v);
                    let w = cmpa::MpBigEndianUIntByteSlice::from_bytes(&digest_scratch_buf);
                    cmpa::ct_add_mp_mp(&mut v, &w);
                }
            }

            // Step 3.)
            Self::hashgen(&mut hash_instance, &mut output, &mut self.v, &mut digest_scratch_buf)
                .map_err(RngGenerateError::CryptoError)?;

            // Step 4.)
            hash_instance
                .update(io_slices::BuffersSliceIoSlicesIter::new(&[[0x03u8].as_slice(), &self.v]).map_infallible_err())
                .map_err(RngGenerateError::CryptoError)?;
            hash_instance.finalize_into_reset(&mut digest_scratch_buf)?;
            // Step 5.)
            let h = cmpa::MpBigEndianUIntByteSlice::from_bytes(&digest_scratch_buf);
            let mut v = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut self.v);
            cmpa::ct_add_mp_mp(&mut v, &h);
            let c = cmpa::MpBigEndianUIntByteSlice::from_bytes(&self.c);
            cmpa::ct_add_mp_mp(&mut v, &c);
            let reseed_counter = self.reseed_counter.to_be_bytes();
            let reseed_counter = cmpa::MpBigEndianUIntByteSlice::from_bytes(&reseed_counter);
            cmpa::ct_add_mp_mp(&mut v, &reseed_counter);

            // Step 6.)
            self.reseed_counter += 1;
        }

        Ok(())
    }

    fn seedlen_for_hash_alg(alg: tpm2_interface::TpmiAlgHash) -> Result<usize, CryptoError> {
        // See SP 800-90Ar1, Table 2 on page 38. Strictly speaking, only values for the
        // SHA2 family of hashes are specified (SHA3 isn't even approved for the
        // Hash_DRBG construction), but simply transfer the defined seedlens to
        // SHA3 (or SM3 even) based on matching digest sizes.
        let digest_len = hash::hash_alg_digest_len(alg);
        if digest_len <= 32 {
            Ok(55)
        } else if digest_len <= 64 {
            Ok(111)
        } else {
            Err(CryptoError::UnsupportedSecurityStrength)
        }
    }

    fn hash_df<
        'a,
        'b,
        SMI: io_slices::PeekableIoSlicesIter<'a, BackendIteratorError = convert::Infallible>,
        AII: CryptoPeekableIoSlicesIter<'b>,
    >(
        hash_instance: &mut hash::HashInstance,
        input: SMI,
        mut additional_input: Option<&mut AII>,
        mut output: &mut [u8],
        digest_scratch_buf: &mut [u8],
    ) -> Result<(), CryptoError> {
        debug_assert_eq!(digest_scratch_buf.len(), hash_instance.digest_len());
        // The possible values of output.len() are limited to seedlen_for_hash_alg(),
        // the arithmetic below won't overflow.
        debug_assert!(output.len() <= u8::MAX as usize);
        let n_output_bits = u32::try_from(output.len()).map_err(|_| CryptoError::RequestTooBig)?;
        let n_output_bits = n_output_bits.checked_mul(8).ok_or(CryptoError::RequestTooBig)?;
        let digest_len = hash_instance.digest_len();

        // NIST SP 800-90Ar1, 10.1.1.4: Hash_df().
        // Preparation for step 4.2.)
        let mut input_header: [u8; 5] = [0; 5];
        input_header[1..].copy_from_slice(&n_output_bits.to_be_bytes());

        // Step 2.)
        let mut remaining = output.len();
        // Step 3.), will be incremented to one before first use below.
        let mut counter: u8 = 0;
        // Step 4.)
        while remaining > 0 {
            // Step. 3.) + 4.2.)
            counter = counter.checked_add(1).ok_or(CryptoError::RequestTooBig)?;

            // Step 4.1.) with final step 5.) fused into the loop.
            input_header[0] = counter;
            hash_instance.update(io_slices::SingletonIoSlice::new(input_header.as_slice()).map_infallible_err())?;
            hash_instance.update(input.decoupled_borrow().map_infallible_err())?;
            if let Some(additional_input) = &mut additional_input {
                hash_instance.update((*additional_input).decoupled_borrow())?;
            }

            if remaining >= digest_len {
                let cur_output_chunk;
                (cur_output_chunk, output) = output.split_at_mut(digest_len);
                hash_instance.finalize_into_reset(cur_output_chunk)?;
                remaining -= digest_len
            } else {
                hash_instance.finalize_into_reset(digest_scratch_buf)?;
                output.copy_from_slice(&digest_scratch_buf[..remaining]);
                remaining = 0;
            }
        }

        Ok(())
    }

    fn hashgen<'a>(
        hash_instance: &mut hash::HashInstance,
        output: &mut dyn CryptoWalkableIoSlicesMutIter<'a>,
        v: &mut [u8],
        digest_scratch_buf: &mut [u8],
    ) -> Result<(), CryptoError> {
        // NIST SP 800-90Ar1, 10.1.1.4: Hashgen().
        // Step 1.), in a sense.
        // In addition, enforce the maximum request length, the caller, Self::generate()
        // will loop and submit multiple "virtual" requests to hashgen() as
        // needed, interspersed with the required updates to the DRBG state.
        let digest_len = digest_scratch_buf.len();
        let max_request_len = Self::MAX_REQUEST_LEN - (Self::MAX_REQUEST_LEN % digest_len as u32);
        let requested_len = output.total_len()?;
        let mut remaining_len = usize::try_from(max_request_len)
            .unwrap_or(requested_len)
            .min(requested_len);
        if remaining_len == 0 {
            return Ok(());
        }

        // Step 2.)
        // Don't make a copy of v for performance reasons. Remember how often it had
        // been incremented and subtract that amount again when done.
        let mut v_delta = [0u8; mem::size_of::<usize>()];
        let mut v_delta = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(v_delta.as_mut_slice());
        // Step 3.) is implicit.
        // Step 4.)
        let result = loop {
            let output_slice = match output.next_slice_mut(Some(digest_len)) {
                Ok(Some(output_slice)) => output_slice,
                Ok(None) => break Ok(()),
                Err(e) => break Err(e),
            };
            let output_slice_len = output_slice.len();
            debug_assert!(remaining_len >= digest_len || remaining_len == output_slice_len + output.total_len()?);

            // Step 4.1.)
            if let Err(e) = hash_instance.update(io_slices::SingletonIoSlice::new(v).map_infallible_err()) {
                break Err(e);
            }

            // Step 4.2.) with final step 5.) fused into the loop.
            if output_slice_len == digest_len {
                if let Err(e) = hash_instance.finalize_into_reset(output_slice) {
                    break Err(CryptoError::from(e));
                }
                remaining_len -= digest_len;
            } else {
                assert_eq!(digest_scratch_buf.len(), hash_instance.digest_len());
                if let Err(e) = hash_instance.finalize_into_reset(digest_scratch_buf) {
                    break Err(CryptoError::from(e));
                }
                let digest: &[u8] = digest_scratch_buf;
                output_slice.copy_from_slice(&digest[..output_slice_len]);
                remaining_len -= output_slice_len;
                remaining_len -= match output.copy_from_iter(
                    &mut io_slices::SingletonIoSlice::new(&digest[output_slice_len..]).map_infallible_err(),
                ) {
                    Ok(copied) => copied,
                    Err(e) => break Err(e),
                };
            }

            // Stop if the (maximum) request length has been exceeded. Don't dequeue any
            // more IO slices. Don't increment V if it's been the last chunk
            // anyway.
            if remaining_len == 0 {
                break Ok(());
            }

            // Step 4.3.)
            let mut v = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(v);
            cmpa::ct_add_mp_l(&mut v, 1);
            cmpa::ct_add_mp_l(&mut v_delta, 1);
        };

        // Restore the original value of v. Don't bother subtracting the accumulated
        // v_delta again if it's still zero.
        if cmpa::ct_is_zero_mp(&v_delta).unwrap() == 0 {
            let mut v = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(v);
            cmpa::ct_sub_mp_mp(&mut v, &v_delta);
        }

        result
    }
}

impl RngCore for HashDrbg {
    fn generate<'a, 'b, OI: CryptoWalkableIoSlicesMutIter<'a>, AII: CryptoPeekableIoSlicesIter<'b>>(
        &mut self,
        output: OI,
        additional_input: Option<AII>,
    ) -> Result<(), RngGenerateError> {
        HashDrbg::generate(self, output, additional_input)
    }
}

impl ReseedableRngCore for HashDrbg {
    fn min_seed_entropy_len(&self) -> usize {
        HashDrbg::min_seed_entropy_len(self.alg)
    }

    fn reseed<'a, AII: CryptoPeekableIoSlicesIter<'a>>(
        &mut self,
        entropy: &[u8],
        additional_input: Option<AII>,
    ) -> Result<(), RngReseedError> {
        HashDrbg::reseed(self, entropy, additional_input)
    }
}

#[cfg(test)]
const TEST_HASH_DRBG_NONCE: &[u8] =
    &cmpa::hexstr::bytes_from_hexstr_cnst::<20>("746573745f686173685f647262675f6e6f6e6365");
#[cfg(test)]
const TEST_HASH_DRBG_PERSONALIZATION: &[u8] =
    &cmpa::hexstr::bytes_from_hexstr_cnst::<30>("746573745f686173685f647262675f706572736f6e616c697a6174696f6e");
#[cfg(test)]
const TEST_HASH_DRBG_ADDITIONAL_INPUT: &[u8] =
    &cmpa::hexstr::bytes_from_hexstr_cnst::<31>("746573745f686173685f647262675f6164646974696f6e616c5f696e707574");

#[cfg(test)]
struct HashDrbgTestVec<'a> {
    with_optional_inputs: bool,
    expected_outputs: [&'a [u8]; 2], // Once after instantiate, once after reseed.
}

#[cfg(test)]
fn test_hash_drbg_common(hash_alg: tpm2_interface::TpmiAlgHash, entropy: &[u8], vecs: &[HashDrbgTestVec]) {
    use alloc::vec;

    fn generate_and_compare(drbg: &mut HashDrbg, additional_input: Option<[Option<&[u8]>; 5]>, expected_output: &[u8]) {
        let output_len = expected_output.len();
        let mut output = vec![0u8; output_len];
        let output_split_at = output_len / 2;
        let (output0, output1) = output.split_at_mut(output_split_at);
        let additional_input = Some(io_slices::GenericIoSlicesIter::new(
            additional_input
                .iter()
                .flat_map(|buffers| buffers.iter())
                .filter_map(|b| b.map(Ok)),
            None,
        ));
        drbg.generate(
            io_slices::BuffersSliceIoSlicesMutIter::new(&mut [output0, &mut [0u8; 0], output1]).map_infallible_err(),
            additional_input,
        )
        .unwrap();
        assert_eq!(output, expected_output);
    }

    for v in vecs.iter() {
        let (nonce, personalization, additional_input) = if v.with_optional_inputs {
            (
                Some(TEST_HASH_DRBG_NONCE),
                Some(TEST_HASH_DRBG_PERSONALIZATION),
                Some(TEST_HASH_DRBG_ADDITIONAL_INPUT),
            )
        } else {
            (None, None, None)
        };

        let empty: [u8; 0] = [0u8; 0];
        let additional_input = additional_input.map(|s| {
            let split_at = s.len() / 2;
            let (s0, s1) = s.split_at(split_at);
            [Some(empty.as_slice()), Some(s0), None, Some(s1), Some(&empty)]
        });

        // Instantiate
        let mut drbg = HashDrbg::instantiate(hash_alg, entropy, nonce, personalization).unwrap();
        // Generate after instantiate.
        generate_and_compare(&mut drbg, additional_input, v.expected_outputs[0]);

        // Reseed.
        drbg.reseed(
            entropy,
            additional_input.as_ref().map(|additional_input| {
                io_slices::GenericIoSlicesIter::new(additional_input.iter().filter_map(|b| b.map(Ok)), None)
                    .map_infallible_err()
            }),
        )
        .unwrap();

        // And generate after reseed.
        generate_and_compare(&mut drbg, additional_input, v.expected_outputs[1]);
    }
}

#[test]
#[cfg(feature = "sha1")]
fn test_hash_drbg_sha1() {
    let entropy = &cmpa::hexstr::bytes_from_hexstr_cnst::<20>("0102030405060708090a0b0c0d0e0f1011121314");
    let vecs: [HashDrbgTestVec; 2] = [
        HashDrbgTestVec {
            with_optional_inputs: false,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<50>(
                    "0aea063927137a952e4f6308977ae7bd\
                     a66b5c6a627866886d81f5db5783aa6e\
                     72c093351d941ba7234ed4b462de71b8\
                     c175",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<9>("a696a411a4c9c2f344"),
            ],
        },
        HashDrbgTestVec {
            with_optional_inputs: true,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<50>(
                    "ba013692c69351aa8b5159371e56cb8a\
                     a7fe4eb58c43d699c75d343870f421d9\
                     41bc6266f0383d1038757f99a0644321\
                     75c0",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<9>("79043a1360b38bf8a2"),
            ],
        },
    ];

    test_hash_drbg_common(tpm2_interface::TpmiAlgHash::Sha1, entropy, &vecs);
}

#[test]
#[cfg(feature = "sha256")]
fn test_hash_drbg_sha256() {
    let entropy = &cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
        "0102030405060708090a0b0c0d0e0f10\
         1112131415161718191a1b1c1d1e1f20",
    );
    let vecs: [HashDrbgTestVec; 2] = [
        HashDrbgTestVec {
            with_optional_inputs: false,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                    "088f2cce0bef99c5388ac0742cb1b4cd\
                     ac7298deeaf397322e05c9a5b3cd9098\
                     b9708d0ee5e5dafcd6cb1ca92d7bff36\
                     4143f38f595376c92b8b2622719a4a85\
                     47173de88e6d6525b6b9ba1bbe9255c9",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<15>("46bbcc9f8c9a35586eac2400ffb8c7"),
            ],
        },
        HashDrbgTestVec {
            with_optional_inputs: true,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                    "a333be1ae7814d314e3ed203a377ca10\
                     dac6701ec2c9a1faf3b79dab0856216c\
                     5a880f18c3204ceb1f5e0eadb507231b\
                     8640627fc657f390e354e9de3d58f734\
                     89de9a141dac66b86e821ea8e6aa48e6",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<15>("e1b7638a93bc4e490219c3170dce3a"),
            ],
        },
    ];

    test_hash_drbg_common(tpm2_interface::TpmiAlgHash::Sha256, entropy, &vecs);
}

#[test]
#[cfg(feature = "sha384")]
fn test_hash_drbg_sha384() {
    let entropy = &cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
        "0102030405060708090a0b0c0d0e0f10\
         1112131415161718191a1b1c1d1e1f20\
         2122232425262728292a2b2c2d2e2f30",
    );
    let vecs: [HashDrbgTestVec; 2] = [
        HashDrbgTestVec {
            with_optional_inputs: false,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                    "6ae872085ec478b3896b1cb2c007abe3\
                     324b55233c75de1343009921896b078c\
                     bacb1827df2436eaabcfe8f5676ae058\
                     fc6afc54b4c53b151684e2e85874aa93\
                     a75d58fd270664e1ecf5415849e017e6\
                     7d36dbfab0938184789bb95b6396ea37\
                     b160692cad04a968b0b0f9aca684122b\
                     d6f0d22580e55de4",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<23>(
                    "a485fdfd9aa424984a0418501d400591\
                     bc2f4c642ef480",
                ),
            ],
        },
        HashDrbgTestVec {
            with_optional_inputs: true,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                    "1cc0474d1c0e60900c2c518400b41a37\
                     5413b331efc7524a21ba2d075940c047\
                     6e490597efd6514416de32023e6786f8\
                     08afca11e0d9bf84b89d95a1388cbb08\
                     a26024717562b7272c3cac71f3ea5676\
                     5066d66661cec91d80f146986a9e9590\
                     4c999c24dc52853a8595ca7d34cb47a6\
                     951c9a7d4bfc8249",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<23>(
                    "b4453f9972b2331d8613c6741b8d5f05\
                     a027135f802503",
                ),
            ],
        },
    ];

    test_hash_drbg_common(tpm2_interface::TpmiAlgHash::Sha384, entropy, &vecs);
}

#[test]
#[cfg(feature = "sha512")]
fn test_hash_drbg_sha512() {
    let entropy = &cmpa::hexstr::bytes_from_hexstr_cnst::<64>(
        "0102030405060708090a0b0c0d0e0f10\
         1112131415161718191a1b1c1d1e1f20\
         2122232425262728292a2b2c2d2e2f30\
         3132333435363738393a3b3c3d3e3f40",
    );
    let vecs: [HashDrbgTestVec; 2] = [
        HashDrbgTestVec {
            with_optional_inputs: false,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                    "a44129625cff6eb33e4797b25bd034a9\
                     50c4489a04f8d65a2daf80211a3801ea\
                     c4c29721f3c11eda74d58f2568838d54\
                     ffa69af5ec7621409bd867de075c4fc7\
                     f577355e3b3a2778c6f12253629eba2b\
                     93c7384a621d0fc3753442834843c242\
                     c83edd6f880e1f5bf5887d291a948ee9\
                     3e7cb956a33dd593d39b4317b880fb40\
                     9ec23b390c4e2257d9c6ca934d5f0df2\
                     65f7942cc2df74e0b1051aca53b77de0",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<31>(
                    "61656fa999bc329c5c1df90a05489a34\
                     376a097372397f6b115401749c8767",
                ),
            ],
        },
        HashDrbgTestVec {
            with_optional_inputs: true,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                    "8037acaddd4f6681adfb223cb61460a8\
                     4efabccbd268ba06650bd2232a1f5e00\
                     d3a3d5b01b324208158d00ddf8474c9d\
                     541009d41b7a5b8cb24a1d06688d2a63\
                     3a61719a655c9e36c7e9b9cf2219859e\
                     dcd831bc3e88c8dff2ca2d1e7f7f42a0\
                     b287be176d360ca448a29ffca21cc07a\
                     72207e8adf0340c701f5fbea9ede412e\
                     b69676dd464779896a9a7486ae65719e\
                     e5eb97791257d34251678956b0eabbef",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<31>(
                    "cbf4710c699a2d0f5832b5dc352d6455\
                     5a5f790c2660c83807d95e277b14de",
                ),
            ],
        },
    ];

    test_hash_drbg_common(tpm2_interface::TpmiAlgHash::Sha512, entropy, &vecs);
}

#[test]
#[cfg(feature = "sha3_256")]
fn test_hash_drbg_sha3_256() {
    let entropy = &cmpa::hexstr::bytes_from_hexstr_cnst::<32>(
        "0102030405060708090a0b0c0d0e0f10\
         1112131415161718191a1b1c1d1e1f20",
    );
    let vecs: [HashDrbgTestVec; 2] = [
        HashDrbgTestVec {
            with_optional_inputs: false,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                    "3258c702d6ecd0d210c1fe9abc96565a\
                     f756c3f8f7a57ee0c8907da6af9a203b\
                     76f62b1602f0fae934b72b3717e7f0b2\
                     147e95839ce232f20b847cd108b33dbb\
                     e50ec1b0ce47e30ac38d314e6d11085d",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<15>("bffb239be4bbc99a2b99536b5a1370"),
            ],
        },
        HashDrbgTestVec {
            with_optional_inputs: true,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
                    "ff8d286be6530db33422d8764cb18ddb\
                     50388a0c4054c30e8f58ad17a3cfa3bd\
                     7292885f0d0b7c82c7d272ff825f6d4c\
                     602a6f7b421ca4b72a2c3fb4e0533b15\
                     6bf66f1269ee26022f21c07584f06cea",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<15>("d591b2ebda3ad5c43f8fee489b24d5"),
            ],
        },
    ];

    test_hash_drbg_common(tpm2_interface::TpmiAlgHash::Sha3_256, entropy, &vecs);
}

#[test]
#[cfg(feature = "sha3_384")]
fn test_hash_drbg_sha3_384() {
    let entropy = &cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
        "0102030405060708090a0b0c0d0e0f10\
         1112131415161718191a1b1c1d1e1f20\
         2122232425262728292a2b2c2d2e2f30",
    );
    let vecs: [HashDrbgTestVec; 2] = [
        HashDrbgTestVec {
            with_optional_inputs: false,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                    "27eb240ebd3c8b68105c5134e73c6e9e\
                     9a6eece002da32fe07974e2ef93958eb\
                     bef47845384f374fdadf498dac643ce6\
                     6d574489c02b16c2a11e438aacb5dace\
                     8d2a58664ebeffb67f45c9b829e3b5f3\
                     547a097bdb35bd7560a8d7c1d5ee9e22\
                     2da3fdaa538e018d600525913917d327\
                     7a003c827e50a331",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<23>(
                    "f3b2ee64096725aa93e42993a991355e\
                     583bb209b31834",
                ),
            ],
        },
        HashDrbgTestVec {
            with_optional_inputs: true,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<120>(
                    "7f89181ba09aec19012e68574c0b4a6d\
                     76de19e5f53c7a186a58eff1c51e2dfd\
                     0db980a31e17aa52fe7304fe277a0e33\
                     1dab1ebce555277fd1f5dd7d0a53233e\
                     c91440438b00cc382440e3dcd337451b\
                     eaff9da90371e2dfcfc00fdee2af6cbb\
                     db793f854ba96c245cb6678b1ec9f5a4\
                     4ae6b9bccb259079",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<23>(
                    "752fa293a163670f148c6d406a1c92b1\
                     6613c1c2b9af21",
                ),
            ],
        },
    ];

    test_hash_drbg_common(tpm2_interface::TpmiAlgHash::Sha3_384, entropy, &vecs);
}

#[test]
#[cfg(feature = "sha3_512")]
fn test_hash_drbg_sha3_512() {
    let entropy = &cmpa::hexstr::bytes_from_hexstr_cnst::<64>(
        "0102030405060708090a0b0c0d0e0f10\
         1112131415161718191a1b1c1d1e1f20\
         2122232425262728292a2b2c2d2e2f30\
         3132333435363738393a3b3c3d3e3f40",
    );
    let vecs: [HashDrbgTestVec; 2] = [
        HashDrbgTestVec {
            with_optional_inputs: false,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                    "f05455751196861f05646c22e9914d13\
                     80b83c1ad7364afb10df3c4f3c297c6c\
                     a8a85e9b26dee9b52720a7fa895b8be5\
                     064c3b6d51927b7165b824ff6c9dfe0a\
                     8ac0a0428ef2e0d1e176a8b49c386e6e\
                     3938ef277188540eb253f57b046de4b9\
                     2cfeec142311342305a9811f9e81fdfb\
                     e3c47e6fd17cdd17787ec01a8b70c695\
                     643bc67f0e94e7c3087fb3897b904350\
                     250c5a8a105c9690b87d5a291501c74f",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<31>(
                    "9cb2fb3d56cf2d60551070d97ce4ec6c\
                     a4bcbc809c203fc6d7892098f83594",
                ),
            ],
        },
        HashDrbgTestVec {
            with_optional_inputs: true,
            expected_outputs: [
                &cmpa::hexstr::bytes_from_hexstr_cnst::<160>(
                    "3b1f0e42408926fa81d64f88b3e070eb\
                     b8921761eeebe7f50060be9c377c6a78\
                     9b2aad96e42afcf03fbb5f24988b35ed\
                     eaa757436951a0d201a44c5e4ef3b74c\
                     2fdb31795d14d72b8d0d022619ee530d\
                     a6a38dac8512ea78ae9545fad2d0c513\
                     ef3c474f270d3ab16c4d7eea765c66a8\
                     454dbebfff5d34235d5ee699600cbe17\
                     35319a78be0cedc4baceb7e3f7af1fe9\
                     6b4c42c1233832f1e0fb864ff8bc76c8",
                ),
                &cmpa::hexstr::bytes_from_hexstr_cnst::<31>(
                    "414de6dfb1628aaf79f8da757226a021\
                     e3aac077039344123001f8b985912e",
                ),
            ],
        },
    ];

    test_hash_drbg_common(tpm2_interface::TpmiAlgHash::Sha3_512, entropy, &vecs);
}
