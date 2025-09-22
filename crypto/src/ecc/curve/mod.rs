// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Low level ECC Curve definitions and arithmetic.

use crate::tpm2_interface;

#[cfg(test)]
use crate::utils_common::alloc::try_alloc_vec;
#[cfg(test)]
use cmpa::MpUIntCommon as _;

use crate::CryptoError;

#[cfg(feature = "ecc_nist_p192")]
const NIST_P192_P: [u8; 24] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<24>("fffffffffffffffffffffffffffffffeffffffffffffffff");
#[cfg(feature = "ecc_nist_p192")]
const NIST_P192_N: [u8; 24] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<24>("ffffffffffffffffffffffff99def836146bc9b1b4d22831");
#[cfg(feature = "ecc_nist_p192")]
const NIST_P192_A: [u8; 24] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<24>("fffffffffffffffffffffffffffffffefffffffffffffffc");
#[cfg(feature = "ecc_nist_p192")]
const NIST_P192_B: [u8; 24] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<24>("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1");
#[cfg(feature = "ecc_nist_p192")]
const NIST_P192_G_X: [u8; 24] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<24>("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012");
#[cfg(feature = "ecc_nist_p192")]
const NIST_P192_G_Y: [u8; 24] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<24>("07192b95ffc8da78631011ed6b24cdd573f977a11e794811");

#[cfg(feature = "ecc_nist_p224")]
const NIST_P224_P: [u8; 28] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<28>("ffffffffffffffffffffffffffffffff000000000000000000000001");
#[cfg(feature = "ecc_nist_p224")]
const NIST_P224_N: [u8; 28] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<28>("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d");
#[cfg(feature = "ecc_nist_p224")]
const NIST_P224_A: [u8; 28] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<28>("fffffffffffffffffffffffffffffffefffffffffffffffffffffffe");
#[cfg(feature = "ecc_nist_p224")]
const NIST_P224_B: [u8; 28] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<28>("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4");
#[cfg(feature = "ecc_nist_p224")]
const NIST_P224_G_X: [u8; 28] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<28>("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21");
#[cfg(feature = "ecc_nist_p224")]
const NIST_P224_G_Y: [u8; 28] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<28>("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34");

#[cfg(feature = "ecc_nist_p256")]
const NIST_P256_P: [u8; 32] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<32>("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
#[cfg(feature = "ecc_nist_p256")]
const NIST_P256_N: [u8; 32] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
#[cfg(feature = "ecc_nist_p256")]
const NIST_P256_A: [u8; 32] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<32>("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc");
#[cfg(feature = "ecc_nist_p256")]
const NIST_P256_B: [u8; 32] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<32>("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
#[cfg(feature = "ecc_nist_p256")]
const NIST_P256_G_X: [u8; 32] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<32>("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
#[cfg(feature = "ecc_nist_p256")]
const NIST_P256_G_Y: [u8; 32] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<32>("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");

#[cfg(feature = "ecc_nist_p384")]
const NIST_P384_P: [u8; 48] = cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
     ffffffff0000000000000000ffffffff",
);
#[cfg(feature = "ecc_nist_p384")]
const NIST_P384_N: [u8; 48] = cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
    "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
     581a0db248b0a77aecec196accc52973",
);
#[cfg(feature = "ecc_nist_p384")]
const NIST_P384_A: [u8; 48] = cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
     ffffffff0000000000000000fffffffc",
);
#[cfg(feature = "ecc_nist_p384")]
const NIST_P384_B: [u8; 48] = cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
    "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a\
     c656398d8a2ed19d2a85c8edd3ec2aef",
);
#[cfg(feature = "ecc_nist_p384")]
const NIST_P384_G_X: [u8; 48] = cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
    "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38\
     5502f25dbf55296c3a545e3872760ab7",
);
#[cfg(feature = "ecc_nist_p384")]
const NIST_P384_G_Y: [u8; 48] = cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
    "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0\
     0a60b1ce1d7e819d7a431d7c90ea0e5f",
);

#[cfg(feature = "ecc_nist_p521")]
const NIST_P521_P: [u8; 66] = cmpa::hexstr::bytes_from_hexstr_cnst::<66>(
    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
     ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
     ffff",
);
#[cfg(feature = "ecc_nist_p521")]
const NIST_P521_N: [u8; 66] = cmpa::hexstr::bytes_from_hexstr_cnst::<66>(
    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
     fffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138\
     6409",
);
#[cfg(feature = "ecc_nist_p521")]
const NIST_P521_A: [u8; 66] = cmpa::hexstr::bytes_from_hexstr_cnst::<66>(
    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
     ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
     fffc",
);
#[cfg(feature = "ecc_nist_p521")]
const NIST_P521_B: [u8; 66] = cmpa::hexstr::bytes_from_hexstr_cnst::<66>(
    "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef1\
     09e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b50\
     3f00",
);
#[cfg(feature = "ecc_nist_p521")]
const NIST_P521_G_X: [u8; 66] = cmpa::hexstr::bytes_from_hexstr_cnst::<66>(
    "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d\
     3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5\
     bd66",
);
#[cfg(feature = "ecc_nist_p521")]
const NIST_P521_G_Y: [u8; 66] = cmpa::hexstr::bytes_from_hexstr_cnst::<66>(
    "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e\
     662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd1\
     6650",
);

#[cfg(feature = "ecc_bn_p256")]
const BN_P256_P: [u8; 32] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<32>("fffffffffffcf0cd46e5f25eee71a49f0cdc65fb12980a82d3292ddbaed33013");
#[cfg(feature = "ecc_bn_p256")]
const BN_P256_N: [u8; 32] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<32>("fffffffffffcf0cd46e5f25eee71a49e0cdc65fb1299921af62d536cd10b500d");
#[cfg(feature = "ecc_bn_p256")]
const BN_P256_A: [u8; 0] = cmpa::hexstr::bytes_from_hexstr_cnst::<0>("");
#[cfg(feature = "ecc_bn_p256")]
const BN_P256_B: [u8; 1] = cmpa::hexstr::bytes_from_hexstr_cnst::<1>("03");
#[cfg(feature = "ecc_bn_p256")]
const BN_P256_G_X: [u8; 1] = cmpa::hexstr::bytes_from_hexstr_cnst::<1>("01");
#[cfg(feature = "ecc_bn_p256")]
const BN_P256_G_Y: [u8; 1] = cmpa::hexstr::bytes_from_hexstr_cnst::<1>("02");

#[cfg(feature = "ecc_bn_p638")]
const BN_P638_P: [u8; 80] = cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
    "23fffffdc000000d7fffffb8000001d3fffff942d000165e3fff94870000d52f\
         fffdd0e00008de55c00086520021e55bfffff51ffff4eb800000004c80015acd\
         ffffffffffffece00000000000000067",
);
#[cfg(feature = "ecc_bn_p638")]
const BN_P638_N: [u8; 80] = cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
    "23fffffdc000000d7fffffb8000001d3fffff942d000165e3fff94870000d52f\
         fffdd0e00008de55600086550021e555fffff54ffff4eac000000049800154d9\
         ffffffffffffeda00000000000000061",
);
#[cfg(feature = "ecc_bn_p638")]
const BN_P638_A: [u8; 0] = cmpa::hexstr::bytes_from_hexstr_cnst::<0>("");
#[cfg(feature = "ecc_bn_p638")]
const BN_P638_B: [u8; 2] = cmpa::hexstr::bytes_from_hexstr_cnst::<2>("0101");
#[cfg(feature = "ecc_bn_p638")]
const BN_P638_G_X: [u8; 80] = cmpa::hexstr::bytes_from_hexstr_cnst::<80>(
    "23fffffdc000000d7fffffb8000001d3fffff942d000165e3fff94870000d52f\
         fffdd0e00008de55c00086520021e55bfffff51ffff4eb800000004c80015acd\
         ffffffffffffece00000000000000066",
);
#[cfg(feature = "ecc_bn_p638")]
const BN_P638_G_Y: [u8; 1] = cmpa::hexstr::bytes_from_hexstr_cnst::<1>("10");

#[cfg(feature = "ecc_bp_p256_r1")]
const BP_P256_R1_P: [u8; 32] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<32>("a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377");
#[cfg(feature = "ecc_bp_p256_r1")]
const BP_P256_R1_N: [u8; 32] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<32>("a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7");
#[cfg(feature = "ecc_bp_p256_r1")]
const BP_P256_R1_A: [u8; 32] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<32>("7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9");
#[cfg(feature = "ecc_bp_p256_r1")]
const BP_P256_R1_B: [u8; 32] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<32>("26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6");
#[cfg(feature = "ecc_bp_p256_r1")]
const BP_P256_R1_G_X: [u8; 32] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<32>("8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262");
#[cfg(feature = "ecc_bp_p256_r1")]
const BP_P256_R1_G_Y: [u8; 32] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<32>("547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997");

#[cfg(feature = "ecc_bp_p384_r1")]
const BP_P384_R1_P: [u8; 48] = cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
    "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123\
     acd3a729901d1a71874700133107ec53",
);
#[cfg(feature = "ecc_bp_p384_r1")]
const BP_P384_R1_N: [u8; 48] = cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
    "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7\
     cf3ab6af6b7fc3103b883202e9046565",
);
#[cfg(feature = "ecc_bp_p384_r1")]
const BP_P384_R1_A: [u8; 48] = cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
    "7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f\
     8aa5814a503ad4eb04a8c7dd22ce2826",
);
#[cfg(feature = "ecc_bp_p384_r1")]
const BP_P384_R1_B: [u8; 48] = cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
    "04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d5\
     7cb4390295dbc9943ab78696fa504c11",
);
#[cfg(feature = "ecc_bp_p384_r1")]
const BP_P384_R1_G_X: [u8; 48] = cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
    "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8\
     e826e03436d646aaef87b2e247d4af1e",
);
#[cfg(feature = "ecc_bp_p384_r1")]
const BP_P384_R1_G_Y: [u8; 48] = cmpa::hexstr::bytes_from_hexstr_cnst::<48>(
    "8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff9912928\
     0e4646217791811142820341263c5315",
);

#[cfg(feature = "ecc_bp_p512_r1")]
const BP_P512_R1_P: [u8; 64] = cmpa::hexstr::bytes_from_hexstr_cnst::<64>(
    "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330871\
     7d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3",
);
#[cfg(feature = "ecc_bp_p512_r1")]
const BP_P512_R1_N: [u8; 64] = cmpa::hexstr::bytes_from_hexstr_cnst::<64>(
    "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870\
     553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069",
);
#[cfg(feature = "ecc_bp_p512_r1")]
const BP_P512_R1_A: [u8; 64] = cmpa::hexstr::bytes_from_hexstr_cnst::<64>(
    "7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc\
     2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca",
);
#[cfg(feature = "ecc_bp_p512_r1")]
const BP_P512_R1_B: [u8; 64] = cmpa::hexstr::bytes_from_hexstr_cnst::<64>(
    "3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a7\
     2bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723",
);
#[cfg(feature = "ecc_bp_p512_r1")]
const BP_P512_R1_G_X: [u8; 64] = cmpa::hexstr::bytes_from_hexstr_cnst::<64>(
    "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098e\
     ff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822",
);
#[cfg(feature = "ecc_bp_p512_r1")]
const BP_P512_R1_G_Y: [u8; 64] = cmpa::hexstr::bytes_from_hexstr_cnst::<64>(
    "7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111\
     b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892",
);

#[cfg(feature = "ecc_sm2_p256")]
const SM2_P256_P: [u8; 32] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<32>("fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff");
#[cfg(feature = "ecc_sm2_p256")]
const SM2_P256_N: [u8; 32] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<32>("fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123");
#[cfg(feature = "ecc_sm2_p256")]
const SM2_P256_A: [u8; 32] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<32>("fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc");
#[cfg(feature = "ecc_sm2_p256")]
const SM2_P256_B: [u8; 32] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<32>("28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93");
#[cfg(feature = "ecc_sm2_p256")]
const SM2_P256_G_X: [u8; 32] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<32>("32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7");
#[cfg(feature = "ecc_sm2_p256")]
const SM2_P256_G_Y: [u8; 32] =
    cmpa::hexstr::bytes_from_hexstr_cnst::<32>("bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0");

/// Provide information about an elliptic curve and provide access to
/// curve arithmetic.
pub struct Curve {
    curve_id: tpm2_interface::TpmEccCurve,
    p: &'static [u8],
    n: &'static [u8],
    cofactor_log2: u8,
    nbits: usize,
}

impl Curve {
    /// Create a new `Curve` instance.
    pub fn new(curve_id: tpm2_interface::TpmEccCurve) -> Result<Self, CryptoError> {
        let curve = match curve_id {
            tpm2_interface::TpmEccCurve::None => return Err(CryptoError::InvalidParams),
            #[cfg(feature = "ecc_nist_p192")]
            tpm2_interface::TpmEccCurve::NistP192 => Self {
                curve_id,
                p: &NIST_P192_P,
                n: &NIST_P192_N,
                cofactor_log2: 0,
                nbits: 192,
            },
            #[cfg(feature = "ecc_nist_p224")]
            tpm2_interface::TpmEccCurve::NistP224 => Self {
                curve_id,
                p: &NIST_P224_P,
                n: &NIST_P224_N,
                cofactor_log2: 0,
                nbits: 224,
            },
            #[cfg(feature = "ecc_nist_p256")]
            tpm2_interface::TpmEccCurve::NistP256 => Self {
                curve_id,
                p: &NIST_P256_P,
                n: &NIST_P256_N,
                cofactor_log2: 0,
                nbits: 256,
            },
            #[cfg(feature = "ecc_nist_p384")]
            tpm2_interface::TpmEccCurve::NistP384 => Self {
                curve_id,
                p: &NIST_P384_P,
                n: &NIST_P384_N,
                cofactor_log2: 0,
                nbits: 384,
            },
            #[cfg(feature = "ecc_nist_p521")]
            tpm2_interface::TpmEccCurve::NistP521 => Self {
                curve_id,
                p: &NIST_P521_P,
                n: &NIST_P521_N,
                cofactor_log2: 0,
                nbits: 521,
            },
            #[cfg(feature = "ecc_bn_p256")]
            tpm2_interface::TpmEccCurve::BnP256 => Self {
                curve_id,
                p: &BN_P256_P,
                n: &BN_P256_N,
                cofactor_log2: 0,
                nbits: 256,
            },
            #[cfg(feature = "ecc_bn_p638")]
            tpm2_interface::TpmEccCurve::BnP638 => Self {
                curve_id,
                p: &BN_P638_P,
                n: &BN_P638_N,
                cofactor_log2: 0,
                nbits: 638,
            },
            #[cfg(feature = "ecc_bp_p256_r1")]
            tpm2_interface::TpmEccCurve::BpP256R1 => Self {
                curve_id,
                p: &BP_P256_R1_P,
                n: &BP_P256_R1_N,
                cofactor_log2: 0,
                nbits: 256,
            },
            #[cfg(feature = "ecc_bp_p384_r1")]
            tpm2_interface::TpmEccCurve::BpP384R1 => Self {
                curve_id,
                p: &BP_P384_R1_P,
                n: &BP_P384_R1_N,
                cofactor_log2: 0,
                nbits: 384,
            },
            #[cfg(feature = "ecc_bp_p512_r1")]
            tpm2_interface::TpmEccCurve::BpP512R1 => Self {
                curve_id,
                p: &BP_P512_R1_P,
                n: &BP_P512_R1_N,
                cofactor_log2: 0,
                nbits: 512,
            },
            #[cfg(feature = "ecc_sm2_p256")]
            tpm2_interface::TpmEccCurve::Sm2P256 => Self {
                curve_id,
                p: &SM2_P256_P,
                n: &SM2_P256_N,
                cofactor_log2: 0,
                nbits: 256,
            },
        };
        Ok(curve)
    }

    /// Get the curve's TCG identifier.
    pub fn get_curve_id(&self) -> tpm2_interface::TpmEccCurve {
        self.curve_id
    }

    /// Get the curve's associated scalar field's prime.
    pub fn get_p(&self) -> cmpa::MpBigEndianUIntByteSlice<'static> {
        cmpa::MpBigEndianUIntByteSlice::from_bytes(self.p)
    }

    /// Get the length of the associated scalar field's prime in units of bytes.
    pub fn get_p_len(&self) -> usize {
        self.p.len()
    }

    /// Get curve group's order.
    pub fn get_order(&self) -> cmpa::MpBigEndianUIntByteSlice<'static> {
        cmpa::MpBigEndianUIntByteSlice::from_bytes(self.n)
    }

    /// Validate a scalar is in the curve's scalar prime field.
    pub fn validate_scalar<ST: cmpa::MpUIntCommon>(&self, scalar: &ST) -> Result<(), CryptoError> {
        let order = self.get_order();
        if scalar.len_is_compatible_with(self.get_p_len()) && cmpa::ct_geq_mp_mp(scalar, &order).unwrap() == 0 {
            Ok(())
        } else {
            Err(CryptoError::InvalidPoint)
        }
    }

    /// Get the base-2 logarithm of the cofactor.
    pub fn get_cofactor_log2(&self) -> u8 {
        self.cofactor_log2
    }

    /// Get the width in units of bits of values in the curve's associated
    /// scalar field.
    pub fn get_nbits(&self) -> usize {
        debug_assert_eq!(self.nbits.div_ceil(8), self.p.len());
        self.nbits
    }

    /// Get the `CurveOps` for the curve.
    pub fn curve_ops(&self) -> Result<CurveOps<'_>, CryptoError> {
        CurveOps::try_new(self)
    }

    /// Get the curve's coefficients.
    pub(crate) fn get_curve_coefficients(
        &self,
    ) -> (
        cmpa::MpBigEndianUIntByteSlice<'static>,
        cmpa::MpBigEndianUIntByteSlice<'static>,
    ) {
        let (a, b): (&[u8], &[u8]) = match self.curve_id {
            tpm2_interface::TpmEccCurve::None => unreachable!(),
            #[cfg(feature = "ecc_nist_p192")]
            tpm2_interface::TpmEccCurve::NistP192 => (&NIST_P192_A, &NIST_P192_B),
            #[cfg(feature = "ecc_nist_p224")]
            tpm2_interface::TpmEccCurve::NistP224 => (&NIST_P224_A, &NIST_P224_B),
            #[cfg(feature = "ecc_nist_p256")]
            tpm2_interface::TpmEccCurve::NistP256 => (&NIST_P256_A, &NIST_P256_B),
            #[cfg(feature = "ecc_nist_p384")]
            tpm2_interface::TpmEccCurve::NistP384 => (&NIST_P384_A, &NIST_P384_B),
            #[cfg(feature = "ecc_nist_p521")]
            tpm2_interface::TpmEccCurve::NistP521 => (&NIST_P521_A, &NIST_P521_B),
            #[cfg(feature = "ecc_bn_p256")]
            tpm2_interface::TpmEccCurve::BnP256 => (&BN_P256_A, &BN_P256_B),
            #[cfg(feature = "ecc_bn_p638")]
            tpm2_interface::TpmEccCurve::BnP638 => (&BN_P638_A, &BN_P638_B),
            #[cfg(feature = "ecc_bp_p256_r1")]
            tpm2_interface::TpmEccCurve::BpP256R1 => (&BP_P256_R1_A, &BP_P256_R1_B),
            #[cfg(feature = "ecc_bp_p384_r1")]
            tpm2_interface::TpmEccCurve::BpP384R1 => (&BP_P384_R1_A, &BP_P384_R1_B),
            #[cfg(feature = "ecc_bp_p512_r1")]
            tpm2_interface::TpmEccCurve::BpP512R1 => (&BP_P512_R1_A, &BP_P512_R1_B),
            #[cfg(feature = "ecc_sm2_p256")]
            tpm2_interface::TpmEccCurve::Sm2P256 => (&SM2_P256_A, &SM2_P256_B),
        };
        (
            cmpa::MpBigEndianUIntByteSlice::from_bytes(a),
            cmpa::MpBigEndianUIntByteSlice::from_bytes(b),
        )
    }

    /// Get the curve's (subgroup) generator point in affine, "plain"
    /// coordinates.
    pub(crate) fn get_generator_coordinates(
        &self,
    ) -> (
        cmpa::MpBigEndianUIntByteSlice<'static>,
        cmpa::MpBigEndianUIntByteSlice<'static>,
    ) {
        let (g_x, g_y): (&[u8], &[u8]) = match self.curve_id {
            tpm2_interface::TpmEccCurve::None => unreachable!(),
            #[cfg(feature = "ecc_nist_p192")]
            tpm2_interface::TpmEccCurve::NistP192 => (&NIST_P192_G_X, &NIST_P192_G_Y),
            #[cfg(feature = "ecc_nist_p224")]
            tpm2_interface::TpmEccCurve::NistP224 => (&NIST_P224_G_X, &NIST_P224_G_Y),
            #[cfg(feature = "ecc_nist_p256")]
            tpm2_interface::TpmEccCurve::NistP256 => (&NIST_P256_G_X, &NIST_P256_G_Y),
            #[cfg(feature = "ecc_nist_p384")]
            tpm2_interface::TpmEccCurve::NistP384 => (&NIST_P384_G_X, &NIST_P384_G_Y),
            #[cfg(feature = "ecc_nist_p521")]
            tpm2_interface::TpmEccCurve::NistP521 => (&NIST_P521_G_X, &NIST_P521_G_Y),
            #[cfg(feature = "ecc_bn_p256")]
            tpm2_interface::TpmEccCurve::BnP256 => (&BN_P256_G_X, &BN_P256_G_Y),
            #[cfg(feature = "ecc_bn_p638")]
            tpm2_interface::TpmEccCurve::BnP638 => (&BN_P638_G_X, &BN_P638_G_Y),
            #[cfg(feature = "ecc_bp_p256_r1")]
            tpm2_interface::TpmEccCurve::BpP256R1 => (&BP_P256_R1_G_X, &BP_P256_R1_G_Y),
            #[cfg(feature = "ecc_bp_p384_r1")]
            tpm2_interface::TpmEccCurve::BpP384R1 => (&BP_P384_R1_G_X, &BP_P384_R1_G_Y),
            #[cfg(feature = "ecc_bp_p512_r1")]
            tpm2_interface::TpmEccCurve::BpP512R1 => (&BP_P512_R1_G_X, &BP_P512_R1_G_Y),
            #[cfg(feature = "ecc_sm2_p256")]
            tpm2_interface::TpmEccCurve::Sm2P256 => (&SM2_P256_G_X, &SM2_P256_G_Y),
        };
        (
            cmpa::MpBigEndianUIntByteSlice::from_bytes(g_x),
            cmpa::MpBigEndianUIntByteSlice::from_bytes(g_y),
        )
    }
}

/// Error type returned by conversion from projective to affine points.
#[derive(Debug)]
pub enum ProjectivePointIntoAffineError {
    /// The projective point is the neutral element, i.e. the point at infinity.
    PointIsIdentity,
}

pub use super::super::backend::ecc::curve::*;

#[cfg(test)]
fn test_point_scalar_mul_common(curve_id: tpm2_interface::TpmEccCurve) {
    use cmpa::MpMutUInt as _;

    let curve = Curve::new(curve_id).unwrap();
    let curve_ops = curve.curve_ops().unwrap();
    let mut scratch = curve_ops.try_alloc_scratch().unwrap();
    let g = curve_ops.generator().unwrap();

    // Multiplication of generator with a zero scalar.
    let mut scalar_buf = try_alloc_vec::<u8>(curve.get_order().len()).unwrap();
    let result = curve_ops
        .point_scalar_mul(
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&scalar_buf),
            &g,
            &mut scratch,
        )
        .unwrap();
    assert!(matches!(
        result.into_affine(&curve_ops, Some(&mut scratch)).unwrap(),
        Err(ProjectivePointIntoAffineError::PointIsIdentity)
    ));

    // Multiplication of generator with a one.
    let mut scalar = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut scalar_buf);
    scalar.set_to_u8(1);
    let result = curve_ops
        .point_scalar_mul(
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&scalar_buf),
            &g,
            &mut scratch,
        )
        .unwrap();
    // Go the ProjectivePoint -> AffinePoint -> plain coordinates route
    let result = result.into_affine(&curve_ops, Some(&mut scratch)).unwrap().unwrap();
    let mut result_x_buf = try_alloc_vec::<u8>(curve.get_p().len()).unwrap();
    let mut result_x = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut result_x_buf);
    let mut result_y_buf = try_alloc_vec::<u8>(curve.get_p().len()).unwrap();
    let mut result_y = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut result_y_buf);
    result
        .into_plain_coordinates(&mut result_x, Some(&mut result_y), &curve_ops)
        .unwrap();
    let (g_x, g_y) = curve.get_generator_coordinates();
    assert_ne!(cmpa::ct_eq_mp_mp(&result_x, &g_x).unwrap(), 0);
    assert_ne!(cmpa::ct_eq_mp_mp(&result_y, &g_y).unwrap(), 0);

    // Multiplication with a scalar equal to the group order minus one. The result
    // should equal the generator again, with the y component possibly negated.
    let mut scalar = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut scalar_buf);
    scalar.copy_from(&curve.get_order());
    cmpa::ct_sub_mp_l(&mut scalar, 1);
    let result = curve_ops
        .point_scalar_mul(
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&scalar_buf),
            &g,
            &mut scratch,
        )
        .unwrap();
    // Go the direct ProjectivePoint -> plain coordinates route this time.
    let mut result_x_buf = try_alloc_vec::<u8>(curve.get_p().len()).unwrap();
    let mut result_x = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut result_x_buf);
    let mut result_y_buf = try_alloc_vec::<u8>(curve.get_p().len()).unwrap();
    let mut result_y = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut result_y_buf);
    result
        .into_affine_plain_coordinates(&mut result_x, Some(&mut result_y), &curve_ops, Some(&mut scratch))
        .unwrap()
        .unwrap();
    assert_ne!(cmpa::ct_eq_mp_mp(&result_x, &g_x).unwrap(), 0);
    let mut neg_result_y_buf = try_alloc_vec::<u8>(curve.get_p().len()).unwrap();
    let mut neg_result_y = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut neg_result_y_buf);
    neg_result_y.copy_from(&curve.get_p());
    cmpa::ct_sub_mp_mp(&mut neg_result_y, &result_y);
    assert!(cmpa::ct_eq_mp_mp(&result_y, &g_y).unwrap() != 0 || cmpa::ct_eq_mp_mp(&neg_result_y, &g_y).unwrap() != 0);
}

#[cfg(feature = "ecc_nist_p192")]
#[test]
fn test_point_scalar_mul_nist_p192() {
    test_point_scalar_mul_common(tpm2_interface::TpmEccCurve::NistP192)
}

#[cfg(feature = "ecc_nist_p224")]
#[test]
fn test_point_scalar_mul_nist_p224() {
    test_point_scalar_mul_common(tpm2_interface::TpmEccCurve::NistP224)
}

#[cfg(feature = "ecc_nist_p256")]
#[test]
fn test_point_scalar_mul_nist_p256() {
    test_point_scalar_mul_common(tpm2_interface::TpmEccCurve::NistP256)
}

#[cfg(feature = "ecc_nist_p384")]
#[test]
fn test_point_scalar_mul_nist_p384() {
    test_point_scalar_mul_common(tpm2_interface::TpmEccCurve::NistP384)
}

#[cfg(feature = "ecc_nist_p521")]
#[test]
fn test_point_scalar_mul_nist_p521() {
    test_point_scalar_mul_common(tpm2_interface::TpmEccCurve::NistP521)
}

#[cfg(feature = "ecc_bn_p256")]
#[test]
fn test_point_scalar_mul_bn_p256() {
    test_point_scalar_mul_common(tpm2_interface::TpmEccCurve::BnP256)
}

#[cfg(feature = "ecc_bn_p638")]
#[test]
fn test_point_scalar_mul_bn_p638() {
    test_point_scalar_mul_common(tpm2_interface::TpmEccCurve::BnP638)
}

#[cfg(feature = "ecc_bp_p256_r1")]
#[test]
fn test_point_scalar_mul_bp_p256_r1() {
    test_point_scalar_mul_common(tpm2_interface::TpmEccCurve::BpP256R1)
}

#[cfg(feature = "ecc_bp_p384_r1")]
#[test]
fn test_point_scalar_mul_bp_p384_r1() {
    test_point_scalar_mul_common(tpm2_interface::TpmEccCurve::BpP384R1)
}

#[cfg(feature = "ecc_bp_p512_r1")]
#[test]
fn test_point_scalar_mul_bp_p512_r1() {
    test_point_scalar_mul_common(tpm2_interface::TpmEccCurve::BpP512R1)
}

#[cfg(feature = "ecc_sm2_p256")]
#[test]
fn test_point_scalar_mul_sm2_p256() {
    test_point_scalar_mul_common(tpm2_interface::TpmEccCurve::Sm2P256)
}

#[cfg(test)]
fn test_point_add_common(curve_id: tpm2_interface::TpmEccCurve) {
    use cmpa::MpMutUInt as _;

    // Multiply the generator by three, add it independently two times to itself and
    // verify that the respective results match.
    let curve = Curve::new(curve_id).unwrap();
    let curve_ops = curve.curve_ops().unwrap();
    let mut scratch = curve_ops.try_alloc_scratch().unwrap();
    let g = curve_ops.generator().unwrap();
    assert!(curve_ops.point_is_on_curve(&g, Some(&mut scratch)).unwrap());

    // Multiply generator by three.
    let mut scalar_buf = try_alloc_vec::<u8>(curve.get_order().len()).unwrap();
    let mut scalar = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut scalar_buf);
    scalar.set_to_u8(3);
    let expected = curve_ops.point_scalar_mul(&scalar, &g, &mut scratch).unwrap();
    let expected = expected.into_affine(&curve_ops, Some(&mut scratch)).unwrap().unwrap();

    // Now add it two times to itself.
    scalar.set_to_u8(1);
    let g = g.into_projective(&curve_ops).unwrap();
    let two_g = curve_ops.point_add(&g, &g, &mut scratch).unwrap();
    let result = curve_ops.point_add(&two_g, &g, &mut scratch).unwrap();
    let result = result.into_affine(&curve_ops, Some(&mut scratch)).unwrap().unwrap();

    let mut expected_x = try_alloc_vec(curve.get_p_len()).unwrap();
    let mut expected_y = try_alloc_vec(curve.get_p_len()).unwrap();
    expected
        .into_plain_coordinates(
            &mut cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut expected_x),
            Some(&mut cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut expected_y)),
            &curve_ops,
        )
        .unwrap();
    let mut result_x = try_alloc_vec(curve.get_p_len()).unwrap();
    let mut result_y = try_alloc_vec(curve.get_p_len()).unwrap();
    result
        .into_plain_coordinates(
            &mut cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut result_x),
            Some(&mut cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut result_y)),
            &curve_ops,
        )
        .unwrap();
    assert_ne!(
        cmpa::ct_eq_mp_mp(
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&expected_x),
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&result_x)
        )
        .unwrap(),
        0
    );
    assert_ne!(
        cmpa::ct_eq_mp_mp(
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&expected_y),
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&result_y)
        )
        .unwrap(),
        0
    );
}

#[cfg(feature = "ecc_nist_p192")]
#[test]
fn test_point_add_nist_p192() {
    test_point_add_common(tpm2_interface::TpmEccCurve::NistP192)
}

#[cfg(feature = "ecc_nist_p224")]
#[test]
fn test_point_add_nist_p224() {
    test_point_add_common(tpm2_interface::TpmEccCurve::NistP224)
}

#[cfg(feature = "ecc_nist_p256")]
#[test]
fn test_point_add_nist_p256() {
    test_point_add_common(tpm2_interface::TpmEccCurve::NistP256)
}

#[cfg(feature = "ecc_nist_p384")]
#[test]
fn test_point_add_nist_p384() {
    test_point_add_common(tpm2_interface::TpmEccCurve::NistP384)
}

#[cfg(feature = "ecc_nist_p521")]
#[test]
fn test_point_add_nist_p521() {
    test_point_add_common(tpm2_interface::TpmEccCurve::NistP521)
}

#[cfg(feature = "ecc_bn_p256")]
#[test]
fn test_point_add_bn_p256() {
    test_point_add_common(tpm2_interface::TpmEccCurve::BnP256)
}

#[cfg(feature = "ecc_bn_p638")]
#[test]
fn test_point_add_bn_p638() {
    test_point_add_common(tpm2_interface::TpmEccCurve::BnP638)
}

#[cfg(feature = "ecc_bp_p256_r1")]
#[test]
fn test_point_add_bp_p256_r1() {
    test_point_add_common(tpm2_interface::TpmEccCurve::BpP256R1)
}

#[cfg(feature = "ecc_bp_p384_r1")]
#[test]
fn test_point_add_bp_p384_r1() {
    test_point_add_common(tpm2_interface::TpmEccCurve::BpP384R1)
}

#[cfg(feature = "ecc_bp_p512_r1")]
#[test]
fn test_point_add_bp_p512_r1() {
    test_point_add_common(tpm2_interface::TpmEccCurve::BpP512R1)
}

#[cfg(feature = "ecc_sm2_p256")]
#[test]
fn test_point_add_sm2_p256() {
    test_point_add_common(tpm2_interface::TpmEccCurve::Sm2P256)
}

#[cfg(test)]
fn test_point_double_repeated_common(curve_id: tpm2_interface::TpmEccCurve) {
    use cmpa::MpMutUInt as _;

    // Multiply the generator by four, double it independently twice and
    // verify that the respective results match.
    let curve = Curve::new(curve_id).unwrap();
    let curve_ops = curve.curve_ops().unwrap();
    let mut scratch = curve_ops.try_alloc_scratch().unwrap();
    let g = curve_ops.generator().unwrap();
    assert!(curve_ops.point_is_on_curve(&g, Some(&mut scratch)).unwrap());

    // Multiply generator by four.
    let mut scalar_buf = try_alloc_vec::<u8>(curve.get_order().len()).unwrap();
    let mut scalar = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut scalar_buf);
    scalar.set_to_u8(4);
    let expected = curve_ops.point_scalar_mul(&scalar, &g, &mut scratch).unwrap();
    let expected = expected.into_affine(&curve_ops, Some(&mut scratch)).unwrap().unwrap();

    // Now double the generator twice.
    let g = g.into_projective(&curve_ops).unwrap();
    let result = curve_ops.point_double_repeated(g, 2, &mut scratch).unwrap();
    let result = result.into_affine(&curve_ops, Some(&mut scratch)).unwrap().unwrap();

    let mut expected_x = try_alloc_vec(curve.get_p_len()).unwrap();
    let mut expected_y = try_alloc_vec(curve.get_p_len()).unwrap();
    expected
        .into_plain_coordinates(
            &mut cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut expected_x),
            Some(&mut cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut expected_y)),
            &curve_ops,
        )
        .unwrap();
    let mut result_x = try_alloc_vec(curve.get_p_len()).unwrap();
    let mut result_y = try_alloc_vec(curve.get_p_len()).unwrap();
    result
        .into_plain_coordinates(
            &mut cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut result_x),
            Some(&mut cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut result_y)),
            &curve_ops,
        )
        .unwrap();
    assert_ne!(
        cmpa::ct_eq_mp_mp(
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&expected_x),
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&result_x)
        )
        .unwrap(),
        0
    );
    assert_ne!(
        cmpa::ct_eq_mp_mp(
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&expected_y),
            &cmpa::MpBigEndianUIntByteSlice::from_bytes(&result_y)
        )
        .unwrap(),
        0
    );
}

#[cfg(feature = "ecc_nist_p192")]
#[test]
fn test_point_double_repeated_nist_p192() {
    test_point_double_repeated_common(tpm2_interface::TpmEccCurve::NistP192)
}

#[cfg(feature = "ecc_nist_p224")]
#[test]
fn test_point_double_repeated_nist_p224() {
    test_point_double_repeated_common(tpm2_interface::TpmEccCurve::NistP224)
}

#[cfg(feature = "ecc_nist_p256")]
#[test]
fn test_point_double_repeated_nist_p256() {
    test_point_double_repeated_common(tpm2_interface::TpmEccCurve::NistP256)
}

#[cfg(feature = "ecc_nist_p384")]
#[test]
fn test_point_double_repeated_nist_p384() {
    test_point_double_repeated_common(tpm2_interface::TpmEccCurve::NistP384)
}

#[cfg(feature = "ecc_nist_p521")]
#[test]
fn test_point_double_repeated_nist_p521() {
    test_point_double_repeated_common(tpm2_interface::TpmEccCurve::NistP521)
}

#[cfg(feature = "ecc_bn_p256")]
#[test]
fn test_point_double_repeated_bn_p256() {
    test_point_double_repeated_common(tpm2_interface::TpmEccCurve::BnP256)
}

#[cfg(feature = "ecc_bn_p638")]
#[test]
fn test_point_double_repeated_bn_p638() {
    test_point_double_repeated_common(tpm2_interface::TpmEccCurve::BnP638)
}

#[cfg(feature = "ecc_bp_p256_r1")]
#[test]
fn test_point_double_repeated_bp_p256_r1() {
    test_point_double_repeated_common(tpm2_interface::TpmEccCurve::BpP256R1)
}

#[cfg(feature = "ecc_bp_p384_r1")]
#[test]
fn test_point_double_repeated_bp_p384_r1() {
    test_point_double_repeated_common(tpm2_interface::TpmEccCurve::BpP384R1)
}

#[cfg(feature = "ecc_bp_p512_r1")]
#[test]
fn test_point_double_repeated_bp_p512_r1() {
    test_point_double_repeated_common(tpm2_interface::TpmEccCurve::BpP512R1)
}

#[cfg(feature = "ecc_sm2_p256")]
#[test]
fn test_point_double_repeated_sm2_p256() {
    test_point_double_repeated_common(tpm2_interface::TpmEccCurve::Sm2P256)
}

#[cfg(test)]
fn test_point_is_on_curve_common(curve_id: tpm2_interface::TpmEccCurve) {
    use cmpa::MpMutUInt as _;

    let curve = Curve::new(curve_id).unwrap();
    let curve_ops = curve.curve_ops().unwrap();
    let mut scratch = curve_ops.try_alloc_scratch().unwrap();
    let g = curve_ops.generator().unwrap();
    assert!(curve_ops.point_is_on_curve(&g, Some(&mut scratch)).unwrap());

    // Multiply generator by three and verify it's on the curve.
    let mut scalar_buf = try_alloc_vec::<u8>(curve.get_order().len()).unwrap();
    let mut scalar = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut scalar_buf);
    scalar.set_to_u8(3);
    let point = curve_ops.point_scalar_mul(&scalar, &g, &mut scratch).unwrap();
    let point = point.into_affine(&curve_ops, Some(&mut scratch)).unwrap().unwrap();
    assert!(curve_ops.point_is_on_curve(&point, Some(&mut scratch)).unwrap());

    // Now mess with the point a bit and verify it's correctly reported as not being
    // on the curve anymore.
    let mut point_x = try_alloc_vec(curve.get_p_len()).unwrap();
    let mut point_y = try_alloc_vec(curve.get_p_len()).unwrap();
    point
        .into_plain_coordinates(
            &mut cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut point_x),
            Some(&mut cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut point_y)),
            &curve_ops,
        )
        .unwrap();
    let mut scalar = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut scalar_buf);
    scalar.set_to_u8(1);
    cmpa::ct_add_mod_mp_mp(
        &mut cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut point_y),
        &scalar,
        &curve.get_p(),
    ).unwrap();
    // Backend implementations may or may not check at point loading
    // time whether the point is on the curve and error out if not.
    let point = match AffinePoint::try_from_plain_coordinates(
        &cmpa::MpBigEndianUIntByteSlice::from_bytes(&point_x),
        &cmpa::MpBigEndianUIntByteSlice::from_bytes(&point_y),
        &curve_ops,
    ) {
        Ok(point) => point,
        Err(CryptoError::InvalidPoint) => return,
        Err(e) => panic!("unexpected error {:?}", e),
    };
    assert!(!curve_ops.point_is_on_curve(&point, Some(&mut scratch)).unwrap());
}

#[cfg(feature = "ecc_nist_p192")]
#[test]
fn test_point_is_on_curve_nist_p192() {
    test_point_is_on_curve_common(tpm2_interface::TpmEccCurve::NistP192)
}

#[cfg(feature = "ecc_nist_p224")]
#[test]
fn test_point_is_on_curve_nist_p224() {
    test_point_is_on_curve_common(tpm2_interface::TpmEccCurve::NistP224)
}

#[cfg(feature = "ecc_nist_p256")]
#[test]
fn test_point_is_on_curve_nist_p256() {
    test_point_is_on_curve_common(tpm2_interface::TpmEccCurve::NistP256)
}

#[cfg(feature = "ecc_nist_p384")]
#[test]
fn test_point_is_on_curve_nist_p384() {
    test_point_is_on_curve_common(tpm2_interface::TpmEccCurve::NistP384)
}

#[cfg(feature = "ecc_nist_p521")]
#[test]
fn test_point_is_on_curve_nist_p521() {
    test_point_is_on_curve_common(tpm2_interface::TpmEccCurve::NistP521)
}

#[cfg(feature = "ecc_bn_p256")]
#[test]
fn test_point_is_on_curve_bn_p256() {
    test_point_is_on_curve_common(tpm2_interface::TpmEccCurve::BnP256)
}

#[cfg(feature = "ecc_bn_p638")]
#[test]
fn test_point_is_on_curve_bn_p638() {
    test_point_is_on_curve_common(tpm2_interface::TpmEccCurve::BnP638)
}

#[cfg(feature = "ecc_bp_p256_r1")]
#[test]
fn test_point_is_on_curve_bp_p256_r1() {
    test_point_is_on_curve_common(tpm2_interface::TpmEccCurve::BpP256R1)
}

#[cfg(feature = "ecc_bp_p384_r1")]
#[test]
fn test_point_is_on_curve_bp_p384_r1() {
    test_point_is_on_curve_common(tpm2_interface::TpmEccCurve::BpP384R1)
}

#[cfg(feature = "ecc_bp_p512_r1")]
#[test]
fn test_point_is_on_curve_bp_p512_r1() {
    test_point_is_on_curve_common(tpm2_interface::TpmEccCurve::BpP512R1)
}

#[cfg(feature = "ecc_sm2_p256")]
#[test]
fn test_point_is_on_curve_sm2_p256() {
    test_point_is_on_curve_common(tpm2_interface::TpmEccCurve::Sm2P256)
}

#[cfg(test)]
fn test_point_is_in_generator_subgroup_common(curve_id: tpm2_interface::TpmEccCurve) {
    use cmpa::MpMutUInt as _;

    let curve = Curve::new(curve_id).unwrap();
    let curve_ops = curve.curve_ops().unwrap();
    let mut scratch = curve_ops.try_alloc_scratch().unwrap();
    let g = curve_ops.generator().unwrap();
    assert!(curve_ops.point_is_in_generator_subgroup(&g, &mut scratch).unwrap());

    // Multiply generator by three and verify it's in the generator's subgroup.
    let mut scalar_buf = try_alloc_vec::<u8>(curve.get_order().len()).unwrap();
    let mut scalar = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut scalar_buf);
    scalar.set_to_u8(3);
    let point = curve_ops.point_scalar_mul(&scalar, &g, &mut scratch).unwrap();
    let point = point.into_affine(&curve_ops, Some(&mut scratch)).unwrap().unwrap();
    assert!(curve_ops.point_is_in_generator_subgroup(&point, &mut scratch).unwrap());

    // Now mess with the point a bit and verify it's correctly reported as not being
    // on the curve anymore.
    let mut point_x = try_alloc_vec(curve.get_p_len()).unwrap();
    let mut point_y = try_alloc_vec(curve.get_p_len()).unwrap();
    point
        .into_plain_coordinates(
            &mut cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut point_x),
            Some(&mut cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut point_y)),
            &curve_ops,
        )
        .unwrap();
    let mut scalar = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut scalar_buf);
    scalar.set_to_u8(1);
    cmpa::ct_add_mod_mp_mp(
        &mut cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut point_y),
        &scalar,
        &curve.get_p(),
    ).unwrap();
    // Backend implementations may or may not check at point loading
    // time whether the point is on the curve and error out if not.
    let point = match AffinePoint::try_from_plain_coordinates(
        &cmpa::MpBigEndianUIntByteSlice::from_bytes(&point_x),
        &cmpa::MpBigEndianUIntByteSlice::from_bytes(&point_y),
        &curve_ops,
    ) {
        Ok(point) => point,
        Err(CryptoError::InvalidPoint) => return,
        Err(e) => panic!("unexpected error {:?}", e),
    };
    assert!(!curve_ops.point_is_in_generator_subgroup(&point, &mut scratch).unwrap());
}

#[cfg(feature = "ecc_nist_p192")]
#[test]
fn test_point_is_in_generator_subgroup_nist_p192() {
    test_point_is_in_generator_subgroup_common(tpm2_interface::TpmEccCurve::NistP192)
}

#[cfg(feature = "ecc_nist_p224")]
#[test]
fn test_point_is_in_generator_subgroup_nist_p224() {
    test_point_is_in_generator_subgroup_common(tpm2_interface::TpmEccCurve::NistP224)
}

#[cfg(feature = "ecc_nist_p256")]
#[test]
fn test_point_is_in_generator_subgroup_nist_p256() {
    test_point_is_in_generator_subgroup_common(tpm2_interface::TpmEccCurve::NistP256)
}

#[cfg(feature = "ecc_nist_p384")]
#[test]
fn test_point_is_in_generator_subgroup_nist_p384() {
    test_point_is_in_generator_subgroup_common(tpm2_interface::TpmEccCurve::NistP384)
}

#[cfg(feature = "ecc_nist_p521")]
#[test]
fn test_point_is_in_generator_subgroup_nist_p521() {
    test_point_is_in_generator_subgroup_common(tpm2_interface::TpmEccCurve::NistP521)
}

#[cfg(feature = "ecc_bn_p256")]
#[test]
fn test_point_is_in_generator_subgroup_bn_p256() {
    test_point_is_in_generator_subgroup_common(tpm2_interface::TpmEccCurve::BnP256)
}

#[cfg(feature = "ecc_bn_p638")]
#[test]
fn test_point_is_in_generator_subgroup_bn_p638() {
    test_point_is_in_generator_subgroup_common(tpm2_interface::TpmEccCurve::BnP638)
}

#[cfg(feature = "ecc_bp_p256_r1")]
#[test]
fn test_point_is_in_generator_subgroup_bp_p256_r1() {
    test_point_is_in_generator_subgroup_common(tpm2_interface::TpmEccCurve::BpP256R1)
}

#[cfg(feature = "ecc_bp_p384_r1")]
#[test]
fn test_point_is_in_generator_subgroup_bp_p384_r1() {
    test_point_is_in_generator_subgroup_common(tpm2_interface::TpmEccCurve::BpP384R1)
}

#[cfg(feature = "ecc_bp_p512_r1")]
#[test]
fn test_point_is_in_generator_subgroup_bp_p512_r1() {
    test_point_is_in_generator_subgroup_common(tpm2_interface::TpmEccCurve::BpP512R1)
}

#[cfg(feature = "ecc_sm2_p256")]
#[test]
fn test_point_is_in_generator_subgroup_sm2_p256() {
    test_point_is_in_generator_subgroup_common(tpm2_interface::TpmEccCurve::Sm2P256)
}

#[cfg(test)]
macro_rules! cfg_select_curve_id {
    (($f:literal, $id:ident)) => {{
        #[cfg(feature = $f)]
        return tpm2_interface::TpmEccCurve::$id;
        #[cfg(not(feature = $f))]
        {
            "Force compile error for no ECC curve configured"
        }
    }};
    (($f:literal, $id:ident), $(($f_more:literal, $id_more:ident)),+) => {{
        #[cfg(feature = $f)]
        return tpm2_interface::TpmEccCurve::$id;
        #[cfg(not(feature = $f))]
        {
            cfg_select_curve_id!($(($f_more, $id_more)),+)
        }
    }};
}

#[cfg(test)]
pub fn test_curve_id() -> tpm2_interface::TpmEccCurve {
    cfg_select_curve_id!(
        ("ecc_nist_p192", NistP192),
        ("ecc_nist_p224", NistP224),
        ("ecc_nist_p384", NistP384),
        ("ecc_nist_p512", NistP521),
        ("ecc_bn_p256", BnP256),
        ("ecc_bn_p638", BnP638),
        ("ecc_bp_p256_r1", BpP256R1),
        ("ecc_bp_p384_r1", BpP384R1),
        ("ecc_bp_p512_r1", BpP512R1),
        ("ecc_sm2_p256", Sm2P256)
    );
}
