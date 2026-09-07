// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of the RSA decryption based on the Chinese Remainder Theorem
//! (CRT).

extern crate alloc;
use alloc::vec::Vec;

use super::keygen;
use crate::CryptoError;
use crate::{
    tpm2_interface,
    utils_common::{alloc::try_alloc_zeroizing_vec, zeroize},
};
use cmpa::{self, MpMutNativeEndianUIntLimbsSlice, MpMutUInt as _, MpMutUIntSlice as _, MpUIntCommon as _};
use core::{convert, mem};

/// Representation of a RSA private key suitable for decryption based on the
/// Chinese Remainder Theorem (CRT).
///
/// For RSA, given a ciphertext *y*, a public modulus *n* = *p* * *q* and
/// private exponent *d*, with *d* being the modular inverse of the public
/// exponent *e* modulo *(p - 1) * (q - 1)*, decryption basically comes down to
/// computing *y*<sup>*d*</sup> modulo *n*, a operation cubic in the length of
/// *n*.
///
/// It is common among RSA implementations to take advantage of the Chinese
/// Remainder Theorem (CRT) and speed this up by a factor of approximately four
/// for primes *p* and *q* of equal length, i.e. the common case.  This works by
/// computing two modular exponentations modulo *p* and *q* separately each and
/// combining those into the final result modulo *n = p * q* using Garner's
/// method:
/// 1. Compute *x<sub>p</sub>=y<sup>d<sub>p</sub></sup> mod p* and
///    *x<sub>q</sub>=y<sup>d<sub>q</sub></sup> mod q*, i.e. computing two
///    modular exponentations in half the width of the full *n* only.
/// 2. Combine those into the final result by *x=x<sub>p</sub> +
///    ((x<sub>q</sub>-x<sub>p</sub>) * (p<sup>-1</sup> mod q)) * p*.
///
/// The respective private exponents are given here by
/// *d<sub>p</sub>=e<sup>-1</sup>mod (p - 1)* and analoguous for
/// *d<sub>q</sub>*. As modular inversion is quadratic in the width of the
/// modulus, these can also get computed more efficiently than the full *d*. In
/// particular, instantiating a [`RsaPrivateKeyCrt`] from a *(n, e, p)* tuple
/// received from extern makes a good check that *e* is coprime to both *p - 1*
/// and *q - 1*: otherwise the modular inversion would signal an error
/// condition.
pub struct RsaPrivateKeyCrt {
    /// The significant length of [`p`](Self::p).
    p_len: usize,
    /// The first prime, `p`, in native endian format.
    p: zeroize::Zeroizing<Vec<cmpa::LimbType>>,
    /// The significant length of [`q`](Self::q).
    q_len: usize,
    /// The second prime, `q`, in native endian format.
    q: zeroize::Zeroizing<Vec<cmpa::LimbType>>,
    /// The inverse of the public exponent modulo [`p`](Self::p) - 1, in native
    /// endian format.
    d_p: zeroize::Zeroizing<Vec<cmpa::LimbType>>,
    /// The inverse of the public exponent modulo [`q`](Self::q) - 1, in native
    /// endian format.
    d_q: zeroize::Zeroizing<Vec<cmpa::LimbType>>,
    /// The inverse of [`p`](Self::p) modulo [`q`](Self::q), in native endian
    /// format.
    p_inv_mod_q: zeroize::Zeroizing<Vec<cmpa::LimbType>>,
}

impl RsaPrivateKeyCrt {
    /// Instantiate from a single prime factor *p*.
    ///
    /// The `TPM2B_PRIVATE_KEY_RSA` structure used for transmitting a private
    /// RSA key keeps a single prime factor *p* only.
    /// [`new_from_p()`](Self::new_from_p) can be used to derive the other
    /// prime factor *q* from the given *p* and the public modulus and
    /// subsequently instantiate a [RsaPrivateKeyCrt()](Self) instance from
    /// the pair. If both, *p* and *q* are known consider
    /// using [`new_from_p_q()`](Self::new_from_p_q) directly instead.
    ///
    /// # Arguments:
    ///
    /// - `modulus` - The public modulus *n* such that *n = p * q*.
    /// - `p` - The public modulus' first prime factor *p*.
    /// - `public_exponent` - The RSA key's public exponent.
    ///
    /// # Errors:
    ///
    /// - [`InvalidParams`](CryptoError::InvalidParams) - `public_exponent` is
    ///   not in range.
    /// - [`InvalidPoint`](CryptoError::InvalidPoint) - `modulus` is not in
    ///   range.
    /// - [`KeyBinding`](CryptoError::KeyBinding)
    ///   - No *q* such that *n = p * q*exists,
    ///   - or either of `n` or `p` is not odd,
    ///   - or either of *p - 1* or *q - 1* is not coprime with
    ///     `public_exponent`,
    ///   - or p and q are not coprime.
    /// - [`MemoryAllocationFailure`](CryptoError::MemoryAllocationFailure) -
    ///   Some buffer allocation failed.
    pub fn new_from_p(
        modulus: &cmpa::MpBigEndianUIntByteSlice,
        p: &cmpa::MpBigEndianUIntByteSlice,
        public_exponent: &cmpa::MpBigEndianUIntByteSlice,
    ) -> Result<Self, CryptoError> {
        // Careful, careful here, the private key (p) is not necessarily
        // associated with the public key (modulus + public exponent):
        // it could have been handed in through e.g. TPM2_LoadExternal().
        // First sanitize the public exponent.
        if !keygen::public_exponent_is_valid(public_exponent) {
            return Err(CryptoError::InvalidParams);
        }

        if cmpa::ct_geq_mp_mp(public_exponent, modulus).unwrap() != 0 {
            return Err(CryptoError::InvalidPoint);
        }

        // Make a copy of p in native-endian order, it will be needed anyway, so it's
        // better to create it first and use that for all subsequent
        // computations.
        let p_len = p.len();
        let p_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(p_len);
        let mut p_buf = try_alloc_zeroizing_vec::<cmpa::LimbType>(p_nlimbs)?;
        let mut ne_p = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut p_buf);
        ne_p.copy_from(p);
        let p = ne_p;

        let (q_buf, q_len) = Self::compute_q(modulus, &p, p_len)?;

        Self::new_from_p_q(p_len, p_buf, q_len, q_buf, public_exponent)
    }

    /// Instantiate from known prime factors *p* and *q*.
    ///
    /// It is assumed that the cryptographic binding between the private key as
    /// represented through *(p, q)* and the public key has been established by
    /// some means already, for example because the key pair has just been
    /// generated. If not, consider using [`new_from_p()`](Self::new_from_p)
    /// instead.
    ///
    /// # Arguments:
    ///
    /// - `p_len` - The number of significant bytes in *p*, as stored in
    ///   `p_buf`.
    /// - `p_buf` - The public modulus' first prime factor *p*, in native endian
    ///   format.
    /// - `q_len` - The number of significant bytes in *q*, as stored in
    ///   `q_buf`.
    /// - `q_buf` - The public modulus' second prime factor *q*, in native
    ///   endian format.
    /// - `public_exponent` - The RSA key's public exponent.
    ///
    /// # Errors:
    ///
    /// - [`KeyBinding`](CryptoError::KeyBinding) - The following conditions are
    ///   being checked for primarily to facilitate implementation of
    ///   [new_from_p()](Self::new_from_p) using this functionality here. A key
    ///   generated by [`mod rsa`](super) itself should never fail any of these:
    ///   - Either of *p - 1* or *q - 1* is not coprime with `public_exponent`,
    ///   - or p and q are not coprime.
    /// - [`MemoryAllocationFailure`](CryptoError::MemoryAllocationFailure) -
    ///   Some buffer allocation failed.
    pub fn new_from_p_q(
        p_len: usize,
        mut p_buf: zeroize::Zeroizing<Vec<cmpa::LimbType>>,
        q_len: usize,
        mut q_buf: zeroize::Zeroizing<Vec<cmpa::LimbType>>,
        public_exponent: &cmpa::MpBigEndianUIntByteSlice,
    ) -> Result<Self, CryptoError> {
        let mut p = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut p_buf);
        let mut q = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut q_buf);

        let scratch_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(p_len.max(q_len));
        let mut scratch0 = try_alloc_zeroizing_vec::<cmpa::LimbType>(scratch_nlimbs)?;
        let mut scratch1 = try_alloc_zeroizing_vec::<cmpa::LimbType>(scratch_nlimbs)?;
        let mut scratch2 = try_alloc_zeroizing_vec::<cmpa::LimbType>(scratch_nlimbs)?;
        let mut scratch3 = try_alloc_zeroizing_vec::<cmpa::LimbType>(scratch_nlimbs)?;
        let d_p_buf = Self::compute_d_p(
            public_exponent,
            &mut p,
            [&mut scratch0, &mut scratch1, &mut scratch2, &mut scratch3],
        )?;
        let d_q_buf = Self::compute_d_p(
            public_exponent,
            &mut q,
            [&mut scratch0, &mut scratch1, &mut scratch2, &mut scratch3],
        )?;
        drop(scratch3);

        let p_inv_mod_q_buf = Self::compute_p_inv_mod_q(&p, &q, [&mut scratch0, &mut scratch1, &mut scratch2])?;

        Ok(Self {
            p_len,
            p: p_buf,
            q_len,
            q: q_buf,
            d_p: d_p_buf,
            d_q: d_q_buf,
            p_inv_mod_q: p_inv_mod_q_buf,
        })
    }

    /// Compute the factor *q* from the public modulus *n* and known *p*.
    ///
    /// Computes *q* such that *n=p * q*. On success, a pair of `(q, q_len)`
    /// is returned, with `q` in native endian format and `q_len` the number
    /// of significant bytes in it.
    ///
    /// # Arguments:
    ///
    /// * `modulus` - The public modulus.
    /// * `p` - The other prime factor of the modulus.
    /// * `p_len` - The number of significant bytes in `p`.
    ///
    /// # Errors:
    ///
    /// - [`InvalidPoint`](CryptoError::InvalidPoint) - `modulus` or `p` is not
    ///   odd.
    /// - [`InvalidPoint`](CryptoError::InvalidPoint)
    /// - [`KeyBinding`](CryptoError::KeyBinding)
    ///   - No such *q* exists,
    ///   - or either of `n` or `p` is not odd.
    /// - [`MemoryAllocationFailure`](CryptoError::MemoryAllocationFailure) -
    ///   Some buffer allocation failed.
    fn compute_q(
        modulus: &cmpa::MpBigEndianUIntByteSlice,
        p: &cmpa::MpMutNativeEndianUIntLimbsSlice,
        p_len: usize,
    ) -> Result<(zeroize::Zeroizing<Vec<cmpa::LimbType>>, usize), CryptoError> {
        // Careful, careful here, the private key (p) is not necessarily
        // associated with the public modulus -- it could have been
        // handed in through e.g. TPM2_LoadExternal().
        let modulus_len = modulus.len();
        if modulus_len == 0
            || p_len == 0
            || p_len > modulus_len
            || modulus.test_bit(0).unwrap() == 0
            || p.test_bit(0).unwrap() == 0
        {
            return Err(CryptoError::InvalidPoint);
        }

        let modulus_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(modulus_len);
        let mut modulus_scratch = try_alloc_zeroizing_vec::<cmpa::LimbType>(modulus_nlimbs)?;
        let mut modulus_scratch = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut modulus_scratch);

        let q_max_len = modulus_len - p_len + 1;
        let q_max_nlimbs = MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(q_max_len);
        let mut q_buf = try_alloc_zeroizing_vec::<cmpa::LimbType>(q_max_nlimbs)?;
        let mut q = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut q_buf);

        modulus_scratch.copy_from(modulus);
        // Cannot fail, p had been checked to have its LSB set above, so it's non-zero.
        let p = cmpa::CtMpDivisor::new(p, None).map_err(|_| CryptoError::Internal)?;
        cmpa::ct_div_mp_mp(None, &mut modulus_scratch, &p, Some(&mut q)).map_err(|_| CryptoError::Internal)?;
        if cmpa::ct_is_zero_mp(&modulus_scratch).unwrap() == 0 {
            return Err(CryptoError::KeyBinding);
        }

        let (q_is_nonzero, q_nbits) = cmpa::ct_find_last_set_bit_mp(&q);
        // Should not be possible, because modulus had initially been non-zero (odd)
        // and the remainder is zero now.
        debug_assert_ne!(q_is_nonzero.unwrap(), 0);
        if q_is_nonzero.unwrap() == 0 {
            return Err(CryptoError::KeyBinding);
        }

        let q_len = q_nbits.div_ceil(8);
        let q_nlimbs = MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(q_len);
        if q_nlimbs < q_max_nlimbs {
            // Shrink the buffer.
            let mut new_q_buf = try_alloc_zeroizing_vec::<cmpa::LimbType>(q_nlimbs)?;
            let mut new_q = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut new_q_buf);
            new_q.copy_from(&q);
            q_buf = new_q_buf;
        }

        Ok((q_buf, q_len))
    }

    /// Compute the private exponent *d<sub>p</sub>* modulo *p*.
    ///
    /// Given *p* and the public exponent *e*, compute the inverse of *e* modulo
    /// *p - 1*: *d<sub>p</sub>=e<sup>-1</sup>mod (p - 1)*. Upon success,
    /// *d<sub>p</sub>* will get returned in native endian format.
    ///
    /// # Arguments:
    ///
    /// * `public_exponent` - The public exponent *e*.
    /// * `p` - The prime factor *p*. It's to be passed as a mutable reference
    ///   and its value temporarily modified, but the original value will get
    ///   restored upon return.
    /// * `scratch` - An array of scratch buffers for internal use. Each must be
    ///   at least `p.len()` in length. Passing these buffers from the caller
    ///   enables recycling them for different purposes and avoids unncessary
    ///   reallocations.
    ///
    /// # Errors:
    ///
    /// - [`KeyBinding`](CryptoError::KeyBinding) - The public exponent *e* and
    ///   *p - 1* are not coprime.
    /// - [`MemoryAllocationFailure`](CryptoError::MemoryAllocationFailure) -
    ///   Some buffer allocation failed.
    fn compute_d_p(
        public_exponent: &cmpa::MpBigEndianUIntByteSlice,
        p: &mut cmpa::MpMutNativeEndianUIntLimbsSlice,
        scratch: [&mut [cmpa::LimbType]; 4],
    ) -> Result<zeroize::Zeroizing<Vec<cmpa::LimbType>>, CryptoError> {
        // By the time here, compute_q() and its checks have been run.
        // So it is known that modulus, p, q, are sane, in particular all odd.
        // First, reduce public_exponent mod p - 1. Re constant-time, it is assumed that
        // the width of p is not a secret.
        let mut e_mod_p_minus_one_buf = try_alloc_zeroizing_vec::<cmpa::LimbType>(
            cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(p.len().max(public_exponent.len())),
        )?;
        let mut e_mod_p_minus_one = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut e_mod_p_minus_one_buf);
        e_mod_p_minus_one.copy_from(public_exponent);
        // Temporarily make p a p - 1.
        let p_minus_one = p;
        p_minus_one.set_bit_to(0, false); // -= 1 for odd p.
        let p_minus_one_div = match cmpa::CtMpDivisor::new(p_minus_one, None) {
            Ok(d) => d,
            Err(cmpa::CtMpDivisorError::DivisorIsZero) => {
                // Restore the value of p, i.e. increment it again, before erroring out.
                p_minus_one.set_bit_to(0, true); // += 1 for even p.
                return Err(CryptoError::KeyBinding);
            }
        };
        cmpa::ct_mod_mp_mp(None, &mut e_mod_p_minus_one, &p_minus_one_div);
        // Reuse the temporary buffer used for reducing the public exponent modulo p - 1
        // for the result if its size fits. Otherwise allocate a (smaller)
        // buffer of the right size.
        let mut d_p_buf = if public_exponent.len() <= p_minus_one.len() {
            e_mod_p_minus_one_buf
        } else {
            let mut d_p_buf = match try_alloc_zeroizing_vec::<cmpa::LimbType>(
                cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(p_minus_one.len()),
            ) {
                Ok(b) => b,
                Err(e) => {
                    // Restore the value of p, i.e. increment it again, before erroring out.
                    p_minus_one.set_bit_to(0, true); // += 1 for even p.
                    return Err(CryptoError::from(e));
                }
            };
            let mut d_p = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut d_p_buf);
            d_p.copy_from(&e_mod_p_minus_one);
            drop(e_mod_p_minus_one_buf);
            d_p_buf
        };
        let mut d_p = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut d_p_buf);

        // Compute d_p = e^{-1} mod (p - 1).
        let r = cmpa::ct_inv_mod_mp_mp(&mut d_p, p_minus_one, scratch);
        // Restore the value of p, i.e. increment it again.
        p_minus_one.set_bit_to(0, true); // += 1 for even p.
        r.map_err(|e| match e {
            cmpa::CtInvModMpMpError::OperandsNotCoprime | cmpa::CtInvModMpMpError::InvalidModulus => {
                CryptoError::KeyBinding
            }
            cmpa::CtInvModMpMpError::InconsistentOperandLengths
            | cmpa::CtInvModMpMpError::InsufficientResultSpace
            | cmpa::CtInvModMpMpError::InsufficientScratchSpace => CryptoError::Internal,
        })?;

        Ok(d_p_buf)
    }

    /// Compute the modular inverse of *p* modulo *q*.
    ///
    /// Given *p* and the public exponent *q*, compute *p<sup>-1</sup>mod q*.
    /// Upon success, the result will get returned in native endian format.
    ///
    /// # Arguments:
    ///
    /// * `p` - The prime factor *p* to invert modulo *q*.
    /// * `q` - The modulus for the modular inversion, i.e. the prime factor
    ///   *q*.
    /// * `scratch` - An array of scratch buffers for internal use. The first
    ///   one must be at least the larger of `p.len()` and `q.len()` in length,
    ///   the remaining ones at least `q.len()`.
    ///
    /// # Errors:
    ///
    /// - [`KeyBinding`](CryptoError::KeyBinding) - *p* and *q* are not coprime.
    /// - [`MemoryAllocationFailure`](CryptoError::MemoryAllocationFailure) -
    ///   Some buffer allocation failed.
    fn compute_p_inv_mod_q(
        p: &cmpa::MpMutNativeEndianUIntLimbsSlice,
        q: &cmpa::MpMutNativeEndianUIntLimbsSlice,
        scratch: [&mut [cmpa::LimbType]; 3],
    ) -> Result<zeroize::Zeroizing<Vec<cmpa::LimbType>>, CryptoError> {
        let [scratch0, scratch1, scratch2] = scratch;
        // First reduce p modulo q.
        let mut p_mod_q_scratch = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(scratch0);
        p_mod_q_scratch.copy_from(p);
        cmpa::ct_mod_mp_mp(
            None,
            &mut p_mod_q_scratch,
            &cmpa::CtMpDivisor::new(q, None).map_err(|_| CryptoError::Internal)?,
        );
        let mut p_mod_q_scratch = p_mod_q_scratch.shrink_to(q.len());
        // And calculate its inverse mod q.
        let mut p_inv_mod_q_buf =
            try_alloc_zeroizing_vec(cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(q.len()))?;
        let mut p_inv_mod_q = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut p_inv_mod_q_buf);
        cmpa::ct_inv_mod_odd_mp_mp(&mut p_inv_mod_q, &mut p_mod_q_scratch, q, [scratch1, scratch2]).map_err(
            |e| match e {
                cmpa::CtInvModOddMpMpError::OperandsNotCoprime | cmpa::CtInvModOddMpMpError::InvalidModulus => {
                    CryptoError::KeyBinding
                }
                cmpa::CtInvModOddMpMpError::InconsistentOperandLengths
                | cmpa::CtInvModOddMpMpError::InsufficientResultSpace
                | cmpa::CtInvModOddMpMpError::InsufficientScratchSpace => CryptoError::Internal,
            },
        )?;

        Ok(p_inv_mod_q_buf)
    }

    /// RSA decryption primitive.
    ///
    /// Computes *y*<sup>*d*</sup> mod *n*, with *n* denoting the public
    /// modulus *n = p * q*, and *d* the private exponent, i.e. the modular
    /// inverse of the public exponent to *(p - 1) * (q - 1)*.
    ///
    ///  **No range checking whatsoever is performed on the input ciphertext
    /// `y`!** Other than that, this function implements the RFC 8017 "RSA
    /// Decryption Primitive (RSADP)".
    ///
    /// # Arguments:
    ///
    /// - `y` - The ciphertext in big endian format. Will receive the result of
    ///   the RSA decryption primitive. Must be at least of the public modulus'
    ///   length.
    ///
    /// # Errors:
    /// - [`MemoryAllocationFailure`](CryptoError::MemoryAllocationFailure) -
    ///   Some buffer allocation failed.
    pub fn decrypt(&self, y: &mut [u8]) -> Result<(), CryptoError> {
        let mut y = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(y);
        let p = self.get_p();
        let q = self.get_q();

        // Allocate a scratch buffer for ct_exp_mod_odd_mp_mp()'s internal use.
        let p_q_max_len = self.p_len.max(self.q_len);
        let scratch_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(p_q_max_len);
        let mut scratch = try_alloc_zeroizing_vec::<cmpa::LimbType>(scratch_nlimbs)?;
        // Compute y mod p.
        let mut y_mod_p_buf = try_alloc_zeroizing_vec::<cmpa::LimbType>(
            // The buffer will get recycled for use in Garner's algorithm below.
            // Make sure it's large enough to hold intermediate results.
            cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(y.len().max(p_q_max_len + self.q_len)),
        )?;
        let mut y_mod_p = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut y_mod_p_buf);
        let mut y_mod_p = y_mod_p.shrink_to(y.len().max(self.p_len));
        y_mod_p.copy_from(&y);
        cmpa::ct_mod_mp_mp(
            None,
            &mut y_mod_p,
            &cmpa::CtMpDivisor::new(&p, None).map_err(|_| CryptoError::Internal)?,
        );
        let mut y_mod_p = y_mod_p.shrink_to(self.p_len);
        // Compute x_p = y^{d_p} mod p
        let mut x_p_buf = try_alloc_zeroizing_vec::<cmpa::LimbType>(
            // Allocate the larger of p_len and q_len, this buffer will
            // get recycled for x_q below.
            cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(p_q_max_len),
        )?;
        let mut x_p = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut x_p_buf);
        let mut x_p = x_p.shrink_to(self.p_len);
        cmpa::ct_exp_mod_odd_mp_mp(
            &mut x_p,
            &mut y_mod_p,
            &p,
            &self.get_d_p(),
            8 * self.p_len,
            &mut scratch,
        )
        .map_err(|_| CryptoError::Internal)?;

        // y_mod_p contains garbage now. Reuse it for y_mod_q.
        let mut y_mod_q_buf = y_mod_p_buf;
        let mut y_mod_q = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut y_mod_q_buf);
        let mut y_mod_q = y_mod_q.shrink_to(y.len().max(self.q_len));
        y_mod_q.copy_from(&y);
        let q_div = &cmpa::CtMpDivisor::new(&q, None).map_err(|_| CryptoError::Internal)?;
        cmpa::ct_mod_mp_mp(None, &mut y_mod_q, q_div);
        let mut y_mod_q = y_mod_q.shrink_to(self.q_len);
        // Compute x_q = y^{d_q} mod q. y's contents won't be needed anymore. The x_p
        // value can get moved there and the x_p buffer then reused as the
        // destination for x_q.
        y.copy_from(&x_p);
        let mut x_q_buf = x_p_buf;
        let mut x_q = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut x_q_buf);
        let mut x_q = x_q.shrink_to(self.q_len);
        cmpa::ct_exp_mod_odd_mp_mp(
            &mut x_q,
            &mut y_mod_q,
            &q,
            &self.get_d_q(),
            8 * self.q_len,
            &mut scratch,
        )
        .map_err(|_| CryptoError::Internal)?;

        // So, now we have x_p = y^{d_p} mod p (in y[]) and x_q = y^{d_q} mod q.
        // Use Garner's algorithm to combine these into x = y^d mod (p * q),
        // with d the private exponent, d = e^{-1} mod ((p - 1)*(q - 1)):
        // x = x_p + [((x_q - x_p) * (p^{-1} mod  q)) mod q] * p.
        // The y_mod_q_buf (formerly y_mod_p_buf) has a length at least the larger of
        // y.len() and p_q_max_len + q_len (aligned for MpNativeEndianMutByteSlice), so
        // it can be used to compute the second operand to the sum above.
        drop(scratch);
        let mut scratch = y_mod_q_buf;
        let mut scratch = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut scratch);
        // scratch = (x_q - x_p) mod q. Remember, x_p is in y.
        scratch.copy_from(&x_q);
        let is_negative = cmpa::ct_sub_mp_mp(&mut scratch, &y);
        let is_negative = cmpa::LimbChoice::from(is_negative);
        cmpa::ct_negate_cond_mp(&mut scratch, is_negative);
        cmpa::ct_mod_mp_mp(None, &mut scratch, q_div);
        cmpa::ct_negate_cond_mp(&mut scratch, is_negative);
        cmpa::ct_add_cond_mp_mp(&mut scratch, &q, is_negative);

        // scratch = (scratch * (p^{-1} mod q)) mod q
        cmpa::ct_mul_trunc_mp_mp(&mut scratch, self.q_len, &self.get_p_inv_mod_q());
        cmpa::ct_mod_mp_mp(None, &mut scratch, q_div);

        // scratch = scratch * p
        cmpa::ct_mul_trunc_mp_mp(&mut scratch, self.q_len, &p);

        // x = x_p + scratch. Remember, x_p is still in y and that's where the final
        // result is supposed to go. Be careful to trim scratch[] to the y.len()
        // before the addition: it had been allocated to accomodate for the
        // maximum needed for any of the different computation step it's been
        // repurposed for above. Note that this removes only leading zeros from the
        // most signifcant end, if any.
        let scratch = scratch.shrink_to(y.len());
        cmpa::ct_add_mp_mp(&mut y, &scratch);

        Ok(())
    }

    /// Accessor to [`Self::p`](Self::p).
    ///
    /// The main purpose for having this accessor is to wrap the limbs buffer in
    /// a [MpNativeEndianUIntLimbsSlice](cmpa::MpNativeEndianUIntLimbsSlice).
    fn get_p(&self) -> cmpa::MpNativeEndianUIntLimbsSlice {
        cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&self.p)
    }

    /// Accessor to [`Self::q`](Self::q).
    ///
    /// The main purpose for having this accessor is to wrap the limbs buffer in
    /// a [MpNativeEndianUIntLimbsSlice](cmpa::MpNativeEndianUIntLimbsSlice).
    fn get_q(&self) -> cmpa::MpNativeEndianUIntLimbsSlice {
        cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&self.q)
    }

    /// Accessor to [`Self::d_p`](Self::d_p).
    ///
    /// The main purpose for having this accessor is to wrap the limbs buffer in
    /// a [MpNativeEndianUIntLimbsSlice](cmpa::MpNativeEndianUIntLimbsSlice).
    fn get_d_p(&self) -> cmpa::MpNativeEndianUIntLimbsSlice {
        cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&self.d_p)
    }

    /// Accessor to [`Self::d_q`](Self::d_q).
    ///
    /// The main purpose for having this accessor is to wrap the limbs buffer in
    /// a [MpNativeEndianUIntLimbsSlice](cmpa::MpNativeEndianUIntLimbsSlice).
    fn get_d_q(&self) -> cmpa::MpNativeEndianUIntLimbsSlice {
        cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&self.d_q)
    }

    /// Accessor to [`Self::p_inv_mod_q`](Self::p_inv_mod_q).
    ///
    /// The main purpose for having this accessor is to wrap the limbs buffer in
    /// a [MpNativeEndianUIntLimbsSlice](cmpa::MpNativeEndianUIntLimbsSlice).
    fn get_p_inv_mod_q(&self) -> cmpa::MpNativeEndianUIntLimbsSlice {
        cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&self.p_inv_mod_q)
    }
}

impl zeroize::Zeroize for RsaPrivateKeyCrt {
    fn zeroize(&mut self) {
        self.p.zeroize();
        self.q.zeroize();
        self.d_p.zeroize();
        self.d_q.zeroize();
        self.p_inv_mod_q.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for RsaPrivateKeyCrt {}

impl convert::TryFrom<&RsaPrivateKeyCrt> for tpm2_interface::Tpm2bPrivateKeyRsa<'static> {
    type Error = CryptoError;

    fn try_from(value: &RsaPrivateKeyCrt) -> Result<Self, Self::Error> {
        let mut p_buf = try_alloc_zeroizing_vec(value.p_len)?;
        let mut p = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut p_buf);
        p.copy_from(&value.get_p());
        Ok(tpm2_interface::Tpm2bPrivateKeyRsa {
            buffer: tpm2_interface::TpmBuffer::Owned(mem::take(&mut p_buf)),
        })
    }
}

// This is the modulus corresponding to the prime pair for the sha256 testcase
// in keygen.
#[cfg(test)]
const TEST_MODULUS: [u8; 256] = cmpa::hexstr::bytes_from_hexstr_cnst::<256>(
    "bdc4ef4fe35fe8b60f24312470a8c6e59215da963dbcf933b1eacc82b9fa7a69\
     3a4d57bd4d55e1493a70d2798ce2818d0cf9e241ae0aac40218de2abe790bffb\
     4e8f83c3d0c5704e3c79910e6cff4d7faf39965e0dcb50d2bfe32be1080dbfb8\
     9726fbfba76fd5e000d8e6b455994b26a4ae22fef5768fe74c3728db7bcd94ea\
     3d20dfafa6c37e717ca96c2e37712f0997132bf9c1c1a4f2bc903a7101eb9585\
     75dc413560bb4d3f8cd5125cb285d67938cd3613f020381617a354e655297a8a\
     aec16711b105a55a25698a45b6f34266be5657de846b37b877411e727e9df99f\
     6110efe6c61e2093922a234360773aac3b19d71d7676bbcda62b19f2085a9823",
);

// First prime factor of the TEST_MODULUS.
#[cfg(test)]
const TEST_P: [u8; 128] = cmpa::hexstr::bytes_from_hexstr_cnst::<128>(
    "c13469df9fbc5ddc9b33713299d2911609ae5a772cb253a9634071639130bb47\
     4e2820a3bd859a631e660f1b28d2a03942ee2ad7fa68d94a8870ef70ba534792\
     d4b62426ae7e5b4c7c85087f358266b31b8cfebe9379744abfbbc6298f158189\
     bd503f5657dc64ea2031a6537ee24625b44c935e28c12b8b2c2b46db50c3aaa1",
);

// Second prime factor of the TEST_MODULUS.
#[cfg(test)]
const TEST_Q: [u8; 128] = cmpa::hexstr::bytes_from_hexstr_cnst::<128>(
    "fb72ac78ef217f465d7f434ec4390693784e0cc53e477ec9b2635d96e0625c8c\
     15c009e6b7bd444cc6a6c90072ad48567a4126457164c1a438b9b2991f525d4e\
     692777c8057682ec2ca63da9680f12a9fe2f88aa1edbed8ed3d7c11d5988d948\
     a5ad023b2edab24674f8ef720041663e87b29d5d64774b70bef15232a46ef043",
);

#[cfg(test)]
const TEST_EXPECTED_D_P: [u8; 128] = cmpa::hexstr::bytes_from_hexstr_cnst::<128>(
    "49beaed6bb8ad3acdbd493d5839f3adfd58c265dacc2d86a244739c08e6fb25c\
     3239e0d37f089af850671647009afcab3e9fd7dc9e691cdf751ade5a01d4bdd2\
     0ebd03297c9b20501e8b4cc5f96fafb197c78688c993a74eccc66889fe627012\
     5a1f623d9bc5b503248caef6d9cc9687d7bd0ed6f6e95cac7f8c793c47249861",
);

#[cfg(test)]
const TEST_EXPECTED_D_Q: [u8; 128] = cmpa::hexstr::bytes_from_hexstr_cnst::<128>(
    "66a5dfa6d6e833cf03e82a1003a6cbfa73c8590a446c6763eb8108f9c8cc1ebf\
     c93946517b7cb65f29517908c7c7d99a03fa88a71cad6727a54899924ce910d2\
     2bb742fcd2ce18905581dff64256b4e5d4b08ef7f3f5103b985ba1a85b9eb425\
     260d44b5e860bb1a6c321b7dcc80e63e6ca30bfece3eacfb6fd79018c06bd185",
);

#[cfg(test)]
const TEST_EXPECTED_P_INV_MOD_Q: [u8; 128] = cmpa::hexstr::bytes_from_hexstr_cnst::<128>(
    "e21752b27fdceb8e2a9adb157324711685ed565ec90e03cbd02c36abcc601999\
     af1b4909006090c2b5e693ac573446337af2c8707e7b3fbfce55438fd21d7ea8\
     fc97813881750ca4cf6d2a42f6929571b29e9dc04a035d43ca167ef77893a114\
     5889f43616b21e9570cc9a7998f866d12bf81c62bf27955d5fe55135e2b7a68b",
);

#[test]
fn test_rsa_private_key_crt_new_from_p_q() {
    let test_p = cmpa::MpBigEndianUIntByteSlice::from_bytes(&TEST_P);
    let p_len = test_p.len();
    let p_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(p_len);
    let mut p_buf = try_alloc_zeroizing_vec::<cmpa::LimbType>(p_nlimbs).unwrap();
    let mut p = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut p_buf);
    p.copy_from(&test_p);

    let test_q = cmpa::MpBigEndianUIntByteSlice::from_bytes(&TEST_Q);
    let q_len = test_q.len();
    let q_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(q_len);
    let mut q_buf = try_alloc_zeroizing_vec::<cmpa::LimbType>(q_nlimbs).unwrap();
    let mut q = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut q_buf);
    q.copy_from(&test_q);

    let public_exponent = cmpa::MpBigEndianUIntByteSlice::from_bytes(super::keygen::MIN_PUBLIC_EXPONENT);

    let key = RsaPrivateKeyCrt::new_from_p_q(p_len, p_buf, q_len, q_buf, &public_exponent).unwrap();

    let test_expected_p = cmpa::MpBigEndianUIntByteSlice::from_bytes(&TEST_P);
    assert_ne!(cmpa::ct_eq_mp_mp(&key.get_p(), &test_expected_p).unwrap(), 0);
    let test_expected_q = cmpa::MpBigEndianUIntByteSlice::from_bytes(&TEST_Q);
    assert_ne!(cmpa::ct_eq_mp_mp(&key.get_q(), &test_expected_q).unwrap(), 0);
    let test_expected_d_p = cmpa::MpBigEndianUIntByteSlice::from_bytes(&TEST_EXPECTED_D_P);
    assert_ne!(cmpa::ct_eq_mp_mp(&key.get_d_p(), &test_expected_d_p).unwrap(), 0);
    let test_expected_d_q = cmpa::MpBigEndianUIntByteSlice::from_bytes(&TEST_EXPECTED_D_Q);
    assert_ne!(cmpa::ct_eq_mp_mp(&key.get_d_q(), &test_expected_d_q).unwrap(), 0);
    let test_expected_p_inv_mod_q = cmpa::MpBigEndianUIntByteSlice::from_bytes(&TEST_EXPECTED_P_INV_MOD_Q);
    assert_ne!(
        cmpa::ct_eq_mp_mp(&key.get_p_inv_mod_q(), &test_expected_p_inv_mod_q).unwrap(),
        0
    );
}

#[test]
fn test_rsa_private_key_crt_new_from_p() {
    let modulus = cmpa::MpBigEndianUIntByteSlice::from_bytes(&TEST_MODULUS);
    let p = cmpa::MpBigEndianUIntByteSlice::from_bytes(&TEST_P);
    let public_exponent = cmpa::MpBigEndianUIntByteSlice::from_bytes(super::keygen::MIN_PUBLIC_EXPONENT);

    let key = RsaPrivateKeyCrt::new_from_p(&modulus, &p, &public_exponent).unwrap();

    let test_expected_p = cmpa::MpBigEndianUIntByteSlice::from_bytes(&TEST_P);
    assert_ne!(cmpa::ct_eq_mp_mp(&key.get_p(), &test_expected_p).unwrap(), 0);
    let test_expected_q = cmpa::MpBigEndianUIntByteSlice::from_bytes(&TEST_Q);
    assert_ne!(cmpa::ct_eq_mp_mp(&key.get_q(), &test_expected_q).unwrap(), 0);
    let test_expected_d_p = cmpa::MpBigEndianUIntByteSlice::from_bytes(&TEST_EXPECTED_D_P);
    assert_ne!(cmpa::ct_eq_mp_mp(&key.get_d_p(), &test_expected_d_p).unwrap(), 0);
    let test_expected_d_q = cmpa::MpBigEndianUIntByteSlice::from_bytes(&TEST_EXPECTED_D_Q);
    assert_ne!(cmpa::ct_eq_mp_mp(&key.get_d_q(), &test_expected_d_q).unwrap(), 0);
    let test_expected_p_inv_mod_q = cmpa::MpBigEndianUIntByteSlice::from_bytes(&TEST_EXPECTED_P_INV_MOD_Q);
    assert_ne!(
        cmpa::ct_eq_mp_mp(&key.get_p_inv_mod_q(), &test_expected_p_inv_mod_q).unwrap(),
        0
    );
}

#[test]
fn test_rsa_private_key_crt_decrypt() {
    use alloc::vec;

    let test_p = cmpa::MpBigEndianUIntByteSlice::from_bytes(&TEST_P);
    let p_len = test_p.len();
    let p_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(p_len);
    let mut p_buf = try_alloc_zeroizing_vec::<cmpa::LimbType>(p_nlimbs).unwrap();
    let mut p = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut p_buf);
    p.copy_from(&test_p);

    let test_q = cmpa::MpBigEndianUIntByteSlice::from_bytes(&TEST_Q);
    let q_len = test_q.len();
    let q_nlimbs = MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(q_len);
    let mut q_buf = try_alloc_zeroizing_vec::<cmpa::LimbType>(q_nlimbs).unwrap();
    let mut q = cmpa::MpMutNativeEndianUIntLimbsSlice::from_limbs(&mut q_buf);
    q.copy_from(&test_q);

    let public_exponent = cmpa::MpBigEndianUIntByteSlice::from_bytes(super::keygen::MIN_PUBLIC_EXPONENT);

    let key = RsaPrivateKeyCrt::new_from_p_q(p_len, p_buf, q_len, q_buf, &public_exponent).unwrap();

    // Decrypt an "encrypted" zero.
    let mut y_buf = vec![0u8; TEST_MODULUS.len()];
    key.decrypt(&mut y_buf).unwrap();
    let mut y = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut y_buf);
    assert_ne!(cmpa::ct_is_zero_mp(&y).unwrap(), 0);

    // Decrypt an "encrypted" one.
    y.store_l(0, 1);
    key.decrypt(&mut y_buf).unwrap();
    let y = cmpa::MpBigEndianUIntByteSlice::from_bytes(&y_buf);
    assert_ne!(cmpa::ct_is_one_mp(&y).unwrap(), 0);

    // Alright, that works, now an encrypted three.
    let mut y_buf: [u8; 256] = cmpa::hexstr::bytes_from_hexstr_cnst::<256>(
        "9e2256121e8e2511551e99f300a10a4a5b6403a3d6ac9a6a8c945d58a36e8ffd\
         145b027da0c80aab6ec0f7ee9a68836be36904b956784960749fbf1a52c9de75\
         682c6023b34d61c92b6068b1a546c00f95691d3b440939abf3201688b9548599\
         d8d1ebb4b2e258050ffac018dfe54e52eaab62c3e8a5bf547c4c81651fba3caf\
         28fca9a3b5a3bf2390774f6efa18ce2de2b204af140905ed4154074eace75250\
         d2f4f7a592ce808428a7511a4957224dd2ab5edc458bf3cfbc5bc0d8ed8c898a\
         953b9489a93104ef430e1fc546ed9448c74a88fec00d736087bd0fef6beda7d6\
         38266a3934415f2d84290845027f47b8f15696980139c8d9bd69261e3acc9b17",
    );
    key.decrypt(&mut y_buf).unwrap();
    let y = cmpa::MpBigEndianUIntByteSlice::from_bytes(&y_buf);
    assert_ne!(cmpa::ct_leq_mp_l(&y, !0).unwrap(), 0);
    assert_eq!(y.load_l(0), 3);
}
