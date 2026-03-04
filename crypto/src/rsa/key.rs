// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! RSA key definitions and related functionality.

extern crate alloc;
use alloc::vec::Vec;

use super::{crt, encrypt, keygen};
use crate::{CryptoError, rng};
use crate::{
    tpm2_interface,
    utils_common::{
        alloc::{try_alloc_vec, try_alloc_zeroizing_vec},
        zeroize,
    },
};
use cmpa::{self, MpMutUInt, MpUIntCommon as _};
use core::{convert, mem};

pub use keygen::MIN_PUBLIC_EXPONENT;

/// Public part of a RSA key pair.
///
/// To be instantiated either through [key pair generation](RsaKey::generate) or
/// converted from (and
/// to) a [`Tpm2bPublicKeyRsa`](tpm2_interface::Tpm2bPublicKeyRsa) via
/// [`TryFrom`](convert::TryFrom).
pub struct RsaPublicKey {
    modulus: Vec<u8>,
    public_exponent: Vec<u8>,
}

impl RsaPublicKey {
    fn new(modulus: Vec<u8>, public_exponent: Vec<u8>) -> Self {
        Self {
            modulus,
            public_exponent,
        }
    }

    /// RSA encryption primitive.
    ///
    /// <div class="warning">
    ///
    /// This is only the basic encrpytion primitive. You probably don't want to
    /// use it directly for encryption. Use any of the standard schemes like
    /// OAEP or RSAES-PKCS-v1_5 instead.
    ///
    /// </div>
    ///
    /// Computes *x*<sup>*e*</sup> mod *n*, with *n* denoting the public modulus
    /// and *e* the public exponent.
    ///
    /// # Arguments:
    ///
    /// - `x` - The plaintext to encrypt in big endian format. must be less than
    ///   the `modulus`, otherwise an error will be returned. The result will be
    ///   written to `x` upon success, also in big endian format.
    ///
    /// # Errors:
    ///
    /// - [`InvalidParams`](CryptoError::InvalidParams) - The `modulus` is
    ///   invalid.
    /// - [`InvalidMessageLength`](CryptoError::InvalidMessageLength) - The
    ///   plaintext `x` as a big endian number is not less than the `modulus` or
    ///   the buffer length is not consistent with it.
    /// - [`MemoryAllocationFailure`](CryptoError::MemoryAllocationFailure) -
    ///   Some buffer allocation failed.
    pub fn encrypt(&self, x: &mut [u8]) -> Result<(), CryptoError> {
        if x.len() < self.modulus_len() {
            return Err(CryptoError::InvalidMessageLength);
        }
        encrypt::encrypt(
            x,
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&self.modulus),
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&self.public_exponent),
        )
    }

    pub fn modulus_len(&self) -> usize {
        self.modulus.len()
    }
}

impl<'a> convert::TryFrom<&'a RsaPublicKey> for (u32, tpm2_interface::Tpm2bPublicKeyRsa<'a>) {
    type Error = CryptoError;

    /// Convert a [`RsaPublicKey`] into a pair of public exponent and
    /// [`Tpm2bPublicKeyRsa`](tpm2_interface::Tpm2bPublicKeyRsa) (the modulus).
    ///
    /// # Errors:
    ///
    /// - [`Internal`](CryptoError::Internal) - Internal error.
    fn try_from(value: &'a RsaPublicKey) -> Result<Self, Self::Error> {
        let public_exponent = cmpa::MpBigEndianUIntByteSlice::from_bytes(&value.public_exponent);
        let public_exponent = public_exponent.try_into_u32().map_err(|_| CryptoError::Internal)?;

        Ok((
            public_exponent,
            tpm2_interface::Tpm2bPublicKeyRsa {
                buffer: tpm2_interface::TpmBuffer::Borrowed(&value.modulus),
            },
        ))
    }
}

impl<'a> convert::TryFrom<(u32, tpm2_interface::Tpm2bPublicKeyRsa<'a>)> for RsaPublicKey {
    type Error = CryptoError;

    /// Convert a pair of public exponent and
    /// [`Tpm2bPublicKeyRsa`](tpm2_interface::Tpm2bPublicKeyRsa) (the modulus)
    /// into a [`RsaPublicKey`].
    ///
    /// # Errors:
    ///
    /// - [`InvalidParams`](CryptoError::InvalidParams) - The public exponent is
    ///   invalid.
    /// - [`InvalidPoint`](CryptoError::InvalidPoint) - The modulus is obviously
    ///   invalid.
    /// - [`MemoryAllocationFailure`](CryptoError::MemoryAllocationFailure) -
    ///   Some buffer allocation failed.
    fn try_from(value: (u32, tpm2_interface::Tpm2bPublicKeyRsa<'a>)) -> Result<Self, Self::Error> {
        let mut public_exponent_buf = try_alloc_vec(mem::size_of::<u32>())?;
        let mut public_exponent = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut public_exponent_buf);
        public_exponent.set_to_u32(value.0);
        let public_exponent = cmpa::MpBigEndianUIntByteSlice::from_bytes(&public_exponent_buf);
        if !keygen::public_exponent_is_valid(&public_exponent) {
            return Err(CryptoError::InvalidParams);
        }
        let mut modulus_buf = try_alloc_vec(value.1.buffer.len())?;
        modulus_buf.copy_from_slice(&value.1.buffer);
        let modulus = cmpa::MpBigEndianUIntByteSlice::from_bytes(&modulus_buf);
        let (modulus_is_nonzero, modulus_last_set_bit) = cmpa::ct_find_last_set_bit_mp(&modulus);
        if modulus_is_nonzero.unwrap() == 0 || modulus_last_set_bit < 8 * modulus.len() {
            return Err(CryptoError::InvalidPoint);
        }

        Ok(Self {
            modulus: modulus_buf,
            public_exponent: public_exponent_buf,
        })
    }
}

/// Private part of a RSA key pair.
///
/// Never to be instantiated on its own, but only as part of a [`RsaKey`].
pub struct RsaPrivateKey {
    priv_key: crt::RsaPrivateKeyCrt,
}

impl RsaPrivateKey {
    fn new(privkey: crt::RsaPrivateKeyCrt) -> Self {
        Self { priv_key: privkey }
    }

    /// RSA decryption primitive ("RSADP").
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
    fn decrypt(&self, y: &mut [u8]) -> Result<(), CryptoError> {
        self.priv_key.decrypt(y)
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for RsaPrivateKey {
    fn zeroize(&mut self) {
        self.priv_key.zeroize()
    }
}

impl zeroize::ZeroizeOnDrop for RsaPrivateKey {}

impl convert::TryFrom<&RsaPrivateKey> for tpm2_interface::Tpm2bPrivateKeyRsa<'static> {
    type Error = CryptoError;

    /// Convert a [`RsaPrivateKey`] into a
    /// [`Tpm2bPrivateKeyRsa`](tpm2_interface::Tpm2bPrivateKeyRsa).
    fn try_from(value: &RsaPrivateKey) -> Result<Self, Self::Error> {
        Self::try_from(&value.priv_key)
    }
}

/// RSA key with mandatory public part and optional private part.
///
/// To be instantiated either through [key pair generation](Self::generate) or
/// converted from (and
/// to) a [`Tpm2bPublicKeyRsa`](tpm2_interface::Tpm2bPublicKeyRsa) + optional
/// [`Tpm2bPrivateKeyRsa`](tpm2_interface::Tpm2bPrivateKeyRsa) via
/// [`TryFrom`](convert::TryFrom).
pub struct RsaKey {
    pub_key: RsaPublicKey,
    priv_key: Option<RsaPrivateKey>,
}

impl RsaKey {
    /// Generate a RSA key pair.
    ///
    /// # Arguments:
    ///
    /// * `modulus_nbits` - The desired size of the modulus in bits. Must be a
    ///   multiple of 8.
    /// * `public_exponent` - The public exponent encoded in big endian format.
    ///   Commonly set to [`MIN_PUBLIC_EXPONENT`].
    ///
    /// * `rng` - The random number generator to draw random bytes from.
    /// * `additional_rng_generate_input` - Additional input to pass along to
    ///   the `rng`'s [generate()](rng::RngCore::generate) primitive.
    ///
    /// # Errors:
    /// * [`UnsupportedParams`](CryptoError::UnsupportedParams): `modulus_nbits`
    ///   is not a multiple of 8.
    /// - [`InvalidParams`](CryptoError::InvalidParams) - Invalid value of
    ///   either the requested `modulus_nbits` or `public_exponent`.
    /// - [`RngFailure`](CryptoError::RngFailure) - The provided `rng`
    ///   instance's [`generate()`](rng::RngCore::generate) returned a failure
    ///   condition.
    /// - [`RandomSamplingRetriesExceeded`](CryptoError::RandomSamplingRetriesExceeded) - No suitable
    ///   prime has been found within the search limits specified by FIPS 186-5,
    ///   A.1.3.
    /// - [`MemoryAllocationFailure`](CryptoError::MemoryAllocationFailure) -
    ///   Memory allocation failure.
    pub fn generate(
        modulus_nbits: usize,
        public_exponent: Vec<u8>,
        rng: &mut dyn rng::RngCoreDispatchable,
        additional_rng_generate_input: Option<&[Option<&[u8]>]>,
    ) -> Result<Self, CryptoError> {
        if modulus_nbits % (2 * 8) != 0 {
            return Err(CryptoError::UnsupportedParams);
        }

        // p and q will be of equal lengths.
        let p_len = modulus_nbits / (2 * 8);
        let p_nlimbs = cmpa::MpMutNativeEndianUIntLimbsSlice::nlimbs_for_len(p_len);
        let mut p_buf = try_alloc_zeroizing_vec::<cmpa::LimbType>(p_nlimbs)?;
        let mut q_buf = try_alloc_zeroizing_vec::<cmpa::LimbType>(p_nlimbs)?;

        keygen::gen_prime_pair_nist_sp800_56br2(
            &mut p_buf,
            &mut q_buf,
            modulus_nbits,
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&public_exponent),
            rng,
            additional_rng_generate_input,
        )?;

        let mut modulus_buf = try_alloc_vec::<u8>(2 * p_len)?;
        let mut modulus = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut modulus_buf);
        modulus.copy_from(&cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&p_buf));
        cmpa::ct_mul_trunc_mp_mp(
            &mut modulus,
            p_len,
            &cmpa::MpNativeEndianUIntLimbsSlice::from_limbs(&q_buf),
        );

        let priv_key = crt::RsaPrivateKeyCrt::new_from_p_q(
            p_len,
            p_buf,
            p_len,
            q_buf,
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&public_exponent),
        )?;

        let pub_key = RsaPublicKey::new(modulus_buf, public_exponent);

        Ok(Self {
            pub_key,
            priv_key: Some(RsaPrivateKey::new(priv_key)),
        })
    }

    /// Obtain a reference to the public key part.
    pub fn pub_key(&self) -> &RsaPublicKey {
        &self.pub_key
    }

    /// Obtain a reference to the private key part.
    ///
    /// Returns `None` if the private key part is not present.
    pub fn priv_key(&self) -> Option<&RsaPrivateKey> {
        self.priv_key.as_ref()
    }

    /// RSA encryption primitive.
    ///
    /// See [`RsaPublicKey::encrypt()`](RsaPublicKey::encrypt).
    pub fn encrypt(&self, x: &mut [u8]) -> Result<(), CryptoError> {
        self.pub_key.encrypt(x)
    }

    /// RSA decryption primitive ("RSADP").
    ///
    /// This provides the basic decryption primitive to used by other schemes
    /// only, it's probably not to be used directly.
    ///
    /// Computes *y*<sup>*d*</sup> mod *n*, with *n* denoting the public
    /// modulus *n = p * q*, and *d* the private exponent, i.e. the modular
    /// inverse of the public exponent to *(p - 1) * (q - 1)*.
    ///
    /// # Arguments:
    ///
    /// - `y` - The ciphertext in big endian format. Will receive the result of
    ///   the RSA decryption primitive. Must be at least of the public modulus'
    ///   length and less in value as a big endian integer.
    ///
    /// # Errors:
    /// - [`InvalidMessageLength`](CryptoError::InvalidMessageLength) - The
    ///   message `y` as a big endian number is not less than the modulus, i.e.
    ///   *y >= n*.
    /// - [`MemoryAllocationFailure`](CryptoError::MemoryAllocationFailure) -
    ///   Some buffer allocation failed.
    pub fn decrypt(&self, y: &mut [u8]) -> Result<(), CryptoError> {
        if y.len() < self.pub_key.modulus_len()
            || cmpa::ct_lt_mp_mp(
                &cmpa::MpBigEndianUIntByteSlice::from_bytes(y),
                &cmpa::MpBigEndianUIntByteSlice::from_bytes(&self.pub_key.modulus),
            )
            .unwrap()
                == 0
        {
            return Err(CryptoError::InvalidMessageLength);
        }
        self.priv_key.as_ref().ok_or(CryptoError::NoKey)?.decrypt(y)
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for RsaKey {
    fn zeroize(&mut self) {
        if let Some(k) = self.priv_key.as_mut() {
            k.zeroize();
        }
    }
}

impl zeroize::ZeroizeOnDrop for RsaKey {}

impl<'a>
    convert::TryFrom<(
        u32,
        tpm2_interface::Tpm2bPublicKeyRsa<'a>,
        Option<tpm2_interface::Tpm2bPrivateKeyRsa<'a>>,
    )> for RsaKey
{
    type Error = CryptoError;

    /// Convert a triplet of a public exponent, a
    /// [`Tpm2bPublicKeyRsa`](tpm2_interface::Tpm2bPublicKeyRsa) (the modulus) +
    /// an optional
    /// [`Tpm2bPrivateKeyRsa`](tpm2_interface::Tpm2bPrivateKeyRsa) to a
    /// [`RsaKey`].
    //
    /// # Errors:
    ///
    /// - [`InvalidParams`](CryptoError::InvalidParams) - The public exponent is
    ///   invalid.
    /// - [`InvalidPoint`](CryptoError::InvalidPoint) - The modulus is obviously
    ///   invalid.
    /// - [`KeyBinding`](CryptoError::KeyBinding) - The private key cannot be
    ///   associated with the public part or is otherwise invalid.
    /// - [`MemoryAllocationFailure`](CryptoError::MemoryAllocationFailure) -
    ///   Some buffer allocation failed.
    fn try_from(
        value: (
            u32,
            tpm2_interface::Tpm2bPublicKeyRsa<'a>,
            Option<tpm2_interface::Tpm2bPrivateKeyRsa<'a>>,
        ),
    ) -> Result<Self, Self::Error> {
        let pub_key = RsaPublicKey::try_from((value.0, value.1))?;
        let priv_key = match &value.2 {
            Some(priv_key) => {
                let priv_key = crt::RsaPrivateKeyCrt::new_from_p(
                    &cmpa::MpBigEndianUIntByteSlice::from_bytes(&pub_key.modulus),
                    &cmpa::MpBigEndianUIntByteSlice::from_bytes(&priv_key.buffer),
                    &cmpa::MpBigEndianUIntByteSlice::from_bytes(&pub_key.public_exponent),
                )?;
                Some(priv_key)
            }
            None => None,
        };
        Ok(Self {
            pub_key,
            priv_key: priv_key.map(RsaPrivateKey::new),
        })
    }
}

#[cfg(test)]
pub fn test_key() -> RsaKey {
    // This is the modulus corresponding to the prime pair for the sha256 testcase
    // in keygen.
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
    const TEST_P: [u8; 128] = cmpa::hexstr::bytes_from_hexstr_cnst::<128>(
        "c13469df9fbc5ddc9b33713299d2911609ae5a772cb253a9634071639130bb47\
         4e2820a3bd859a631e660f1b28d2a03942ee2ad7fa68d94a8870ef70ba534792\
         d4b62426ae7e5b4c7c85087f358266b31b8cfebe9379744abfbbc6298f158189\
         bd503f5657dc64ea2031a6537ee24625b44c935e28c12b8b2c2b46db50c3aaa1",
    );

    let modulus = tpm2_interface::Tpm2bPublicKeyRsa {
        buffer: tpm2_interface::TpmBuffer::Borrowed(&TEST_MODULUS),
    };
    let p = tpm2_interface::Tpm2bPrivateKeyRsa {
        buffer: tpm2_interface::TpmBuffer::Borrowed(&TEST_P),
    };
    let e = cmpa::MpBigEndianUIntByteSlice::from_bytes(keygen::MIN_PUBLIC_EXPONENT)
        .try_into_u32()
        .unwrap();
    RsaKey::try_from((e, modulus, Some(p))).unwrap()
}
