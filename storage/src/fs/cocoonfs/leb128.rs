// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! LEB128 integer en- and decoding.

use crate::utils_common::bitmanip::BitManip as _;

/// LEB128 decoding errors.
#[derive(Debug)]
pub enum Leb128EncodingError {
    /// The LEB128 encoding is truncated.
    TruncatedEncoding,
    /// The decoded value exceeds the range representable by the
    /// target integer type.
    DecodeOverflow,
}

/// Signed LEB128 encoding length for a given `i64` value.
///
/// # Arguments:
///
/// * `value` - The value to encode.
pub fn leb128s_i64_encoded_len(value: i64) -> usize {
    value.significant_bits().div_ceil(7) as usize
}

/// Unsigned LEB128 encoding length for a given `u64` value.
///
/// # Arguments:
///
/// * `value` - The value to encode.
pub fn leb128u_u64_encoded_len(value: u64) -> usize {
    value.significant_bits().div_ceil(7) as usize
}

/// Encode an `i64` value in signed LEB128 format.
///
/// Encode `value` into `dst` and return the remainder of `dst`.
///
/// # Arguments:
///
/// * `dst` - Destination buffer to encode into.
/// * `value` - The value to encode.
pub fn leb128s_i64_encode(dst: &mut [u8], value: i64) -> &mut [u8] {
    let significand_bits = value.significant_bits();
    let mut value = value as u64;
    let mut encoded_bits = 0;
    let mut encoded_len = 0;
    while encoded_bits < significand_bits {
        dst[encoded_len] = (value & 0x7f) as u8 | 0x80;
        value >>= 7;
        encoded_bits += 7;
        encoded_len += 1;
    }
    let last = dst[encoded_len - 1];
    let last = last.sign_extend(7 - (encoded_bits - significand_bits) - 1);
    let last = last & 0x7f;
    dst[encoded_len - 1] = last;
    &mut dst[encoded_len..]
}

#[test]
fn test_leb128s_i64_encode() {
    extern crate alloc;
    use alloc::vec;

    for value in [i64::MIN, i64::MAX] {
        let mut dst = vec![0u8; leb128s_i64_encoded_len(value)];
        leb128s_i64_encode(&mut dst, value);
        assert_eq!(leb128s_i64_decode(&dst).unwrap().0, value);
    }

    for i in 0..i64::BITS {
        let value = ((1u64 << i) - 1) as i64;
        assert!(value >= 0);
        for value in [-value, value] {
            let mut dst = vec![0u8; leb128s_i64_encoded_len(value)];
            leb128s_i64_encode(&mut dst, value);
            assert_eq!(leb128s_i64_decode(&dst).unwrap().0, value);
        }
    }
}

/// Encode an `u64` value in unsigned LEB128 format.
///
/// Encode `value` into `dst` and return the remainder of `dst`.
///
/// # Arguments:
///
/// * `dst` - Destination buffer to encode into.
/// * `value` - The value to encode.
pub fn leb128u_u64_encode(dst: &mut [u8], mut value: u64) -> &mut [u8] {
    let encoded_len = leb128u_u64_encoded_len(value);
    for dst in dst.iter_mut().take(encoded_len) {
        *dst = (value & 0x7f) as u8 | 0x80;
        value >>= 7;
    }
    dst[encoded_len - 1] ^= 0x80;
    &mut dst[encoded_len..]
}

#[test]
fn test_leb128u_u64_encode() {
    extern crate alloc;
    use alloc::vec;

    let value = u64::MAX;
    let mut dst = vec![0u8; leb128u_u64_encoded_len(value)];
    leb128u_u64_encode(&mut dst, value);
    assert_eq!(leb128u_u64_decode(&dst).unwrap().0, value);

    for i in 0..u64::BITS {
        let value = (1u64 << i) - 1;
        let mut dst = vec![0u8; leb128u_u64_encoded_len(value)];
        leb128u_u64_encode(&mut dst, value);
        assert_eq!(leb128u_u64_decode(&dst).unwrap().0, value);
    }
}

/// Decode a signed LEB128 encoding into an `i64`.
///
/// Decode from `src` and return a pair of the decoded value and the remainder
/// of `src` on success.
///
/// # Arguments:
///
/// * `src` - The source buffer to decode from.
pub fn leb128s_i64_decode(src: &[u8]) -> Result<(i64, &[u8]), Leb128EncodingError> {
    let mut encoded_len = 0usize;
    let mut value: u64 = 0;
    while encoded_len < src.len() {
        let b = src[encoded_len];
        value |= ((b & 0x7f) as u64) << (7 * encoded_len);
        encoded_len += 1;

        if encoded_len == (u64::BITS as usize).div_ceil(7) {
            // Should be done, an i64 cannot hold more. Accept overlong
            // encodings though.
            if (b ^ b.sign_extend((u64::BITS - 1) % 7)) & 0x7f != 0 {
                return Err(Leb128EncodingError::DecodeOverflow);
            }

            let sign_mask = 0u8.wrapping_sub((b >> 6) & 0x1);
            let mut b = b;
            loop {
                if b & 0x80 == 0 {
                    return Ok((value as i64, &src[encoded_len..]));
                } else if encoded_len == src.len() {
                    return Err(Leb128EncodingError::TruncatedEncoding);
                }

                b = src[encoded_len];
                encoded_len += 1;
                if (b ^ sign_mask) & 0x7f != 0 {
                    return Err(Leb128EncodingError::DecodeOverflow);
                }
            }
        } else if b & 0x80 == 0 {
            value = value.sign_extend(7 * encoded_len as u32 - 1);
            return Ok((value as i64, &src[encoded_len..]));
        }
    }

    Err(Leb128EncodingError::TruncatedEncoding)
}

#[test]
fn test_leb128s_i64_decode() {
    assert!(matches!(
        leb128s_i64_decode(&[0x80]),
        Err(Leb128EncodingError::TruncatedEncoding)
    ));
    assert_eq!(leb128s_i64_decode(&[0x00]).unwrap().0, 0);
    assert_eq!(leb128s_i64_decode(&[0x01]).unwrap().0, 1);
    assert_eq!(leb128s_i64_decode(&[0x7f]).unwrap().0, -1);
    assert_eq!(leb128s_i64_decode(&[0x3f]).unwrap().0, 63);
    assert_eq!(leb128s_i64_decode(&[0x41]).unwrap().0, -63);

    assert_eq!(
        leb128s_i64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00])
            .unwrap()
            .0,
        0x7fffffffffffffff
    );

    assert_eq!(
        leb128s_i64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00])
            .unwrap()
            .0,
        0x7fffffffffffffff
    );

    assert_eq!(
        leb128s_i64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f])
            .unwrap()
            .0,
        -1,
    );

    assert_eq!(
        leb128s_i64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f])
            .unwrap()
            .0,
        -1,
    );

    assert!(matches!(
        leb128s_i64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80]),
        Err(Leb128EncodingError::TruncatedEncoding)
    ));
    assert!(matches!(
        leb128s_i64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x80]),
        Err(Leb128EncodingError::TruncatedEncoding)
    ));
    assert!(matches!(
        leb128s_i64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        Err(Leb128EncodingError::TruncatedEncoding)
    ));
    assert!(matches!(
        leb128s_i64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        Err(Leb128EncodingError::TruncatedEncoding)
    ));

    assert!(matches!(
        leb128s_i64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]),
        Err(Leb128EncodingError::DecodeOverflow)
    ));
    assert!(matches!(
        leb128s_i64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x81, 0x00]),
        Err(Leb128EncodingError::DecodeOverflow)
    ));
    assert!(matches!(
        leb128s_i64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x01]),
        Err(Leb128EncodingError::DecodeOverflow)
    ));

    assert!(matches!(
        leb128s_i64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00]),
        Err(Leb128EncodingError::DecodeOverflow)
    ));
    assert!(matches!(
        leb128s_i64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]),
        Err(Leb128EncodingError::DecodeOverflow)
    ));
    assert!(matches!(
        leb128s_i64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f]),
        Err(Leb128EncodingError::DecodeOverflow)
    ));
    assert!(matches!(
        leb128s_i64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00]),
        Err(Leb128EncodingError::DecodeOverflow)
    ));
    assert!(matches!(
        leb128s_i64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]),
        Err(Leb128EncodingError::DecodeOverflow)
    ));
    assert!(matches!(
        leb128s_i64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f]),
        Err(Leb128EncodingError::DecodeOverflow)
    ));
}

/// Decode a unsigned LEB128 encoding into an `u64`.
///
/// Decode from `src` and return a pair of the decoded value and the remainder
/// of `src` on success.
///
/// # Arguments:
///
/// * `src` - The source buffer to decode from.
pub fn leb128u_u64_decode(src: &[u8]) -> Result<(u64, &[u8]), Leb128EncodingError> {
    let mut encoded_len = 0usize;
    let mut value: u64 = 0;
    while encoded_len < src.len() {
        let b = src[encoded_len];
        value |= ((b & 0x7f) as u64) << (7 * encoded_len);
        encoded_len += 1;

        if encoded_len == (u64::BITS as usize).div_ceil(7) {
            // Should be done, an u64 cannot hold more. Accept overlong
            // encodings though.
            if (b & 0x7f) >> (((u64::BITS - 1) % 7) + 1) != 0 {
                return Err(Leb128EncodingError::DecodeOverflow);
            }

            let mut b = b;
            loop {
                if b & 0x80 == 0 {
                    return Ok((value, &src[encoded_len..]));
                } else if encoded_len == src.len() {
                    return Err(Leb128EncodingError::TruncatedEncoding);
                }

                b = src[encoded_len];
                encoded_len += 1;
                if b & 0x7f != 0 {
                    return Err(Leb128EncodingError::DecodeOverflow);
                }
            }
        } else if b & 0x80 == 0 {
            return Ok((value, &src[encoded_len..]));
        }
    }

    Err(Leb128EncodingError::TruncatedEncoding)
}

#[test]
fn test_leb128u_u64_decode() {
    assert!(matches!(
        leb128u_u64_decode(&[0x80]),
        Err(Leb128EncodingError::TruncatedEncoding)
    ));
    assert_eq!(leb128u_u64_decode(&[0x00]).unwrap().0, 0);
    assert_eq!(leb128u_u64_decode(&[0x01]).unwrap().0, 1);
    assert_eq!(leb128u_u64_decode(&[0x7f]).unwrap().0, 127);

    assert_eq!(
        leb128u_u64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00])
            .unwrap()
            .0,
        0x7fffffffffffffff
    );

    assert_eq!(
        leb128u_u64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01])
            .unwrap()
            .0,
        0xffffffffffffffff
    );

    assert_eq!(
        leb128u_u64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x81, 0x00])
            .unwrap()
            .0,
        0xffffffffffffffff
    );

    assert!(matches!(
        leb128u_u64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80]),
        Err(Leb128EncodingError::TruncatedEncoding)
    ));
    assert!(matches!(
        leb128u_u64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x81]),
        Err(Leb128EncodingError::TruncatedEncoding)
    ));
    assert!(matches!(
        leb128u_u64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x81, 0x80]),
        Err(Leb128EncodingError::TruncatedEncoding)
    ));

    assert!(matches!(
        leb128u_u64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02]),
        Err(Leb128EncodingError::DecodeOverflow)
    ));
    assert!(matches!(
        leb128u_u64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x82, 0x00]),
        Err(Leb128EncodingError::DecodeOverflow)
    ));
    assert!(matches!(
        leb128u_u64_decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x81, 0x01]),
        Err(Leb128EncodingError::DecodeOverflow)
    ));
}
