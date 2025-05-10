// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Common interface to hash algorithm implementations.
//!
//! In general, algorithms are specified in terms of a TCG
//! [`TpmiAlgHash`](tpm2_interface::TpmiAlgHash) and routed to the respective
//! implementation.


use crate::CryptoError;
use crate::tpm2_interface;

/// Determine the hash output digest length for a given hash algorithm.
///
/// # Arguments:
///
/// * `alg` - The hash algorithm.
pub const fn hash_alg_digest_len(alg: tpm2_interface::TpmiAlgHash) -> u8 {
    match alg {
        #[cfg(feature = "sha1")]
        tpm2_interface::TpmiAlgHash::Sha1 => 20u8,
        #[cfg(feature = "sha256")]
        tpm2_interface::TpmiAlgHash::Sha256 => 32u8,
        #[cfg(feature = "sha384")]
        tpm2_interface::TpmiAlgHash::Sha384 => 48u8,
        #[cfg(feature = "sha512")]
        tpm2_interface::TpmiAlgHash::Sha512 => 64u8,
        #[cfg(feature = "sha3_256")]
        tpm2_interface::TpmiAlgHash::Sha3_256 => 32u8,
        #[cfg(feature = "sha3_384")]
        tpm2_interface::TpmiAlgHash::Sha3_384 => 48u8,
        #[cfg(feature = "sha3_512")]
        tpm2_interface::TpmiAlgHash::Sha3_512 => 64u8,
        #[cfg(feature = "sm3_256")]
        tpm2_interface::TpmiAlgHash::Sm3_256 => 32u8,
    }
}

/// Determine the maximum hash output digest length among all supported hash
/// algorithms.
pub const fn max_hash_digest_len() -> u8 {
    tpm2_interface::TpmuHa::marshalled_max_size() as u8
}

/// Determine a given hash algorithm's preimage resistance security strength.
///
/// If defined, the security strength in units of bits will get returned wrapped
/// in a `Some`. If the security strength is unknown, `None` will get returned.
///
/// # Arguments:
///
/// * `alg` - The hash algorithm.
pub const fn hash_alg_preimage_security_strength(alg: tpm2_interface::TpmiAlgHash) -> Option<u16> {
    // Refer to NIST SP 800-57, part 1 for preimage resistance security strength
    // values of the SHA{1,2,3} family of hash algorithms.
    match alg {
        #[cfg(feature = "sha1")]
        tpm2_interface::TpmiAlgHash::Sha1 => {
            // Sha1 is being phased out.
            None
        }
        #[cfg(feature = "sha256")]
        tpm2_interface::TpmiAlgHash::Sha256 => Some(256u16),
        #[cfg(feature = "sha384")]
        tpm2_interface::TpmiAlgHash::Sha384 => Some(384u16),
        #[cfg(feature = "sha512")]
        tpm2_interface::TpmiAlgHash::Sha512 => Some(512u16),
        #[cfg(feature = "sha3_256")]
        tpm2_interface::TpmiAlgHash::Sha3_256 => Some(256u16),
        #[cfg(feature = "sha3_384")]
        tpm2_interface::TpmiAlgHash::Sha3_384 => Some(384u16),
        #[cfg(feature = "sha3_512")]
        tpm2_interface::TpmiAlgHash::Sha3_512 => Some(512u16),
        #[cfg(feature = "sm3_256")]
        tpm2_interface::TpmiAlgHash::Sm3_256 => {
            // Can't find an accessible document specifying the
            // preimage resistance security strength of SM3.
            None
        }
    }
}

/// Find a supported hash algorithm providing a given preimage resistance
/// security strength.
///
/// # Arguments:
///
/// * `strength` - The desired preimage resistance security strength in units of
///   bits.
/// * `minimize_length` - Whether or not a hash algorithm with minimum possible
///   output digest length shall get selected.
///
/// # Errors:
///
/// * [`UnsupportedSecurityStrength`](CryptoError::UnsupportedSecurityStrength)
///   - No suitable hash algorithm supported.
pub const fn hash_alg_select_for_preimage_security_strength(
    strength: usize,
    minimize_digest_len: bool,
) -> Result<tpm2_interface::TpmiAlgHash, CryptoError> {
    // Refer to NIST SP 800-57, part 1 for preimage resistance security strength
    // values of the SHA{1,2,3} family of hash algorithms.
    // This selection function is used primarily when there's some choice of freedom
    // for implementations, e.g. when instantiating a Hash_DRBG construction for
    // key generation. For performance reasons, favor
    // - SHA2 over SHA3, independent of minimize_digest_len,
    // - SHA2-384 over SHA2-256 if !minimize_digest_len --  the former uses 64bits
    //   internally,
    // - SHA2-512 over SHA2-384 if !minimize_digest_len -- the effort is the same,
    //   but the former yields more bits per run.
    // SHA1 is getting phased out by NIST, don't use.
    // How SM3 relates to the NIST families is unknown to me, preferring one over
    // the other probably depends on policy anyway. Furthermore, there's no
    // easily accessible document specifying the preimage resistance security
    // strength -- don't use it either for now.
    if !minimize_digest_len {
        if strength <= 512 && cfg!(feature = "sha512") {
            #[cfg(feature = "sha512")]
            return Ok(tpm2_interface::TpmiAlgHash::Sha512);
        } else if strength <= 384 && cfg!(feature = "sha384") {
            #[cfg(feature = "sha384")]
            return Ok(tpm2_interface::TpmiAlgHash::Sha384);
        }
    }

    if strength <= 256 {
        if cfg!(feature = "sha256") {
            #[cfg(feature = "sha256")]
            return Ok(tpm2_interface::TpmiAlgHash::Sha256);
        } else if cfg!(feature = "sha3_256") {
            #[cfg(feature = "sha3_256")]
            return Ok(tpm2_interface::TpmiAlgHash::Sha3_256);
        }
    }

    if strength <= 384 {
        if cfg!(feature = "sha384") {
            #[cfg(feature = "sha384")]
            return Ok(tpm2_interface::TpmiAlgHash::Sha384);
        } else if cfg!(feature = "sha3_384") {
            #[cfg(feature = "sha3_384")]
            return Ok(tpm2_interface::TpmiAlgHash::Sha3_384);
        }
    }

    if strength <= 512 {
        if cfg!(feature = "sha512") {
            #[cfg(feature = "sha512")]
            return Ok(tpm2_interface::TpmiAlgHash::Sha512);
        } else if cfg!(feature = "sha3_512") {
            #[cfg(feature = "sha3_512")]
            return Ok(tpm2_interface::TpmiAlgHash::Sha3_512);
        }
    }

    Err(CryptoError::UnsupportedSecurityStrength)
}

pub use super::backend::hash::*;

macro_rules! cfg_select_hash {
    (($f:literal, $id:ident)) => {
        #[cfg(feature = $f)]
        return tpm2_interface::TpmiAlgHash::$id;
        #[cfg(not(feature = $f))]
        {
            "Force compile error for no hash configured"
        }
    };
    (($f:literal, $id:ident), $(($f_more:literal, $id_more:ident)),+) => {
        #[cfg(feature = $f)]
        return tpm2_interface::TpmiAlgHash::$id;
        #[cfg(not(feature = $f))]
        {
            cfg_select_hash!($(($f_more, $id_more)),+)
        }
    };
}

pub const fn test_hash_alg() -> tpm2_interface::TpmiAlgHash {
    cfg_select_hash!(
        ("sha512", Sha512),
        ("sha256", Sha256),
        ("sha3_512", Sha3_512),
        ("sha3_256", Sha3_256),
        ("sha384", Sha384),
        ("sha3_384", Sha3_384),
        ("sha1", Sha1),
        ("sm3_256", Sm3_256)
    );
}
