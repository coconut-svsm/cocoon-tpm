// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! CRC-32 computation.
//!
//! The CRC polynomial used throughout is the common one with a big-endian bit
//! representation of `0x04c11db7`.
//!
//! The CRC algorithm interprets a stream of bits as coefficients of a
//! polynomial over the ring of integers modulo 2. The assumed ordering is
//! little-endian: for any of the (unsigned) Rust integer types, the "leftmost",
//! arithmetically most significant bit is associated with the poynomial term of
//! degree zero, and the "rightmost", arithmetically least significant bit
//! corresponds to the term of maximum degree. For clarity, the little-endian
//! representation of the CRC polynomial itself would be `0xedb88320u32`, which
//! is `0x04c11db7u32` bit-reversed. In a sequence of integers however, a `[u8]`
//! in particular, earlier elements correspond to terms of higher degree
//! in the combined sequence's associated polynomial than the subsequent ones.
//! For completeness: computing the CRC over some Rust integer and computing it
//! over the `[u8]` sequence representing its (arithemtic) little-endian
//! encoding produces equivalent results.
//!
//! CRCs are evenly distributed, meaning that the distribution of CRC values
//! over uniformly distributed (sufficiently long) data strings is again
//! uniform. Or to put it differently: the probability of hitting a specific
//! CRC value with some random input data is 1:2<sup>32</sup>.
//!
//! In practical applications, this probability might be too large to meet the
//! desired reliablity requirements. One solution would be to use a longer CRC
//! polynomial, e.g. CRC-64. That would come at the cost of doubling the
//! implementation's internal lookup tables' sizes though. An alternative is is
//! produce two CRC-32 values instead: one on the original data and another one
//! on the data transformed in a way such that the two CRCs are stochastically
//! independent (over uniformly distributed input data). Using the fact that the
//! CRC-32 polynomial is irreducible, hence that the ring of residue classes is
//! a field, it can be shown that swapping any two neighboring bits before
//! feeding them into the CRC computation is a suitable such transformation.
//! Convenience functions applying this transformation upfront are provided by
//! this module and suffixed with "`_snb`" for "swap neighboring bits".

/// CRC-32 lookup table by (arithmetic) low order byte half.
///
/// Adapted from Hacker's Delight, 2nd edition, chapter 14 ("Cyclic Redundancy
/// Check").
///
/// For both, the lookup index as well as for the table values, the leftmost
/// (arithmetic MSB) bit stores the coefficient to the polynomial term of degree
/// zero, the rightmost (arithmetic LSB) the one to the term of highest degree.
///
/// # See also:
///
/// * [`CRC32_LE_LUT_HN`]
const CRC32_LE_LUT_LN: [u32; 16] = [
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3, 0x0edb8832,
    0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
];

/// CRC-32 lookup table by (arithmetic) high order byte half.
///
/// Adapted from Hacker's Delight, 2nd edition, chapter 14 ("Cyclic Redundancy
/// Check").
///
/// For both, the lookup index as well as for the table values, the leftmost
/// (arithmetic MSB) bit stores the coefficient to the polynomial term of degree
/// zero, the rightmost (arithmetic LSB) the one to the term of highest degree.
///
/// # See also:
///
/// * [`CRC32_LE_LUT_LN`]
const CRC32_LE_LUT_HN: [u32; 16] = [
    0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac, 0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c, 0xedb88320,
    0xf00f9344, 0xd6d6a3e8, 0xcb61b38c, 0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c,
];

/// Swap an `u8`'s neighboring bits each.
const fn snb_u8(data: u8) -> u8 {
    // C.f. Hacker's Delight, 2nd edition, 2-20 ("Exchanging Registers").
    let t0 = (data ^ (data >> 1)) & 0x55;
    let t1 = t0 << 1;
    data ^ t0 ^ t1
}

/// Swap an `u32`'s neighboring bits each.
const fn snb_u32(data: u32) -> u32 {
    // C.f. Hacker's Delight, 2nd edition, 2-20 ("Exchanging Registers").
    let t0 = (data ^ (data >> 1)) & 0x55555555u32;
    let t1 = t0 << 1;
    data ^ t0 ^ t1
}

/// Initialize the CRC register.
pub const fn crc32le_init() -> u32 {
    !0
}

/// Finalize the CRC computation.
///
/// Return the negated residual polynomial in little-endian representation: the
/// leftmost (arithmetically most significant) bit stores the coefficient to the
/// polynomial term of degree zero, the rightmost (arithmetically least
/// significant) the one to the term of highest degree
///
/// # Arguments:
///
/// * `crc` - Value of the CRC register.
pub const fn crc32le_finish_send(crc: u32) -> u32 {
    !crc
}

/// Finalize the CRC computation and compare against an received CRC value.
///
/// Return `true` on match, `false` otherwise.
///
/// # Arguments:
///
/// * `computed_crc` - Value of the CRC register.
/// * `received_crc` - Received CRC value to compare against.
pub const fn crc32le_finish_receive(computed_crc: u32, received_crc: u32) -> bool {
    crc32le_finish_send(computed_crc) == received_crc
}

/// Update the CRC register with an `u8` data item.
///
/// Return the updated CRC register.
///
/// # Arguments:
///
/// * `crc` - Value of the CRC register.
/// * `data` - The data item to include in the checksum, interpreted as encoding
///   the coefficients of a polynomial in little-endian format: the leftmost
///   (arithmetically most significant) bit stores the coefficient to the
///   polynomial term of degree zero, the rightmost (arithmetically least
///   significant) the one to the term of highest degree.
#[allow(unused)]
pub const fn crc32le_update_u8(crc: u32, data: u8) -> u32 {
    let mut crc = crc ^ data as u32;
    crc = (crc >> 8) ^ CRC32_LE_LUT_LN[(crc & 0xf) as usize] ^ CRC32_LE_LUT_HN[((crc >> 4) & 0xf) as usize];
    crc
}

/// Swap an `u8` data item's neighboring bits each and update the CRC register
/// with the result.
///
/// Return the updated CRC register.
///
/// Equivalent to
/// `crc32le_update_u8(crc, ((data & 0x55u8) << 1) | ((data >> 1) & 0x55u8))`.
///
/// # Arguments:
///
/// * `crc` - Value of the CRC register.
/// * `data` - The data item to include in the checksum.
///
/// # See also:
///
/// * [`crc32le_update_u8()`].
#[allow(unused)]
pub const fn crc32le_update_u8_snb(crc: u32, data: u8) -> u32 {
    crc32le_update_u8(crc, snb_u8(data))
}

/// Update the CRC register with an `u32` data item.
///
/// Return the updated CRC register.
///
/// Equivalent to `crc32le_update_u8(crc, &data.to_le_bytes())`.
///
/// # Arguments:
///
/// * `crc` - Value of the CRC register.
/// * `data` - The data item to include in the checksum.
///
/// # See also:
///
/// * [`crc32le_update_u8()`].
#[allow(unused)]
pub const fn crc32le_update_u32le(crc: u32, data_from_le: u32) -> u32 {
    let mut crc = crc ^ data_from_le;
    let mut j = 4;
    while j > 0 {
        crc = (crc >> 8) ^ CRC32_LE_LUT_LN[(crc & 0xf) as usize] ^ CRC32_LE_LUT_HN[((crc >> 4) & 0xf) as usize];
        j -= 1;
    }
    crc
}

/// Swap an `u32` data item's neighboring bits each and update the CRC register
/// with the result.
///
/// Return the updated CRC register.
///
/// Equivalent to `crc32le_update_u8_snb(crc, &data.to_le_bytes())`.
///
/// # Arguments:
///
/// * `crc` - Value of the CRC register.
/// * `data` - The data item to include in the checksum.
///
/// # See also:
///
/// * [`crc32le_update_u8_snb()`].
#[allow(unused)]
pub const fn crc32le_update_u32le_snb(crc: u32, data_from_le: u32) -> u32 {
    crc32le_update_u32le(crc, snb_u32(data_from_le))
}

/// Update the CRC register with an `u64` data item.
///
/// Return the updated CRC register.
///
/// Equivalent to `crc32le_update_u8(crc, &data.to_le_bytes())`.
///
/// # Arguments:
///
/// * `crc` - Value of the CRC register.
/// * `data` - The data item to include in the checksum.
///
/// # See also:
///
/// * [`crc32le_update_u8()`].
#[allow(unused)]
pub const fn crc32le_update_u64le(crc: u32, data_from_le: u64) -> u32 {
    let crc = crc32le_update_u32le(crc, data_from_le as u32);
    crc32le_update_u32le(crc, (data_from_le >> 32) as u32)
}

/// Swap an `u64` data item's neighboring bits each and update the CRC register
/// with the result.
///
/// Return the updated CRC register.
///
/// Equivalent to `crc32le_update_u8_snb(crc, &data.to_le_bytes())`.
///
/// # Arguments:
///
/// * `data` - The data item to include in the checksum.
///
/// # See also:
///
/// * [`crc32le_update_u8_snb()`].
#[allow(unused)]
pub const fn crc32le_update_u64le_snb(crc: u32, data_from_le: u64) -> u32 {
    let crc = crc32le_update_u32le_snb(crc, data_from_le as u32);
    crc32le_update_u32le_snb(crc, (data_from_le >> 32) as u32)
}

/// Update the CRC register with an `[u8]` data slice's elements.
///
/// Return the updated CRC register.
///
/// Equivalent to a chain of successive `crc32le_update_u8()` invocations on
/// each of `data`'s elements.
///
/// # Arguments:
///
/// * `crc` - Value of the CRC register.
/// * `data` - The data item to include in the checksum.
///
/// # See also:
///
/// * [`crc32le_update_u8()`].
#[allow(unused)]
pub fn crc32le_update_data(mut crc: u32, data: &[u8]) -> u32 {
    // Split dst and mask into regions of &[u8], &[u32], &[u8] each.
    // SAEFTY: The u32 is only used for memory loads.
    let (head, middle_ne_u32, tail) = unsafe { data.align_to::<u32>() };
    for b in head.iter() {
        crc = crc32le_update_u8(crc, *b);
    }
    for v_ne in middle_ne_u32.iter() {
        let v_le = v_ne.to_le();
        crc = crc32le_update_u32le(crc, v_le);
    }
    for b in tail.iter() {
        crc = crc32le_update_u8(crc, *b);
    }

    crc
}

/// Swap each of an `[u8]` data slice's element's neighboring bits and update
/// the CRC register with the result.
///
/// Return the updated CRC register.
///
/// Equivalent to a chain of successive `crc32le_update_u8_snb()` invocations on
/// each of `data`'s elements.
///
/// # Arguments:
///
/// * `crc` - Value of the CRC register.
/// * `data` - The data item to include in the checksum.
///
/// # See also:
///
/// * [`crc32le_update_u8_snb()`].
#[allow(unused)]
pub fn crc32le_update_data_snb(mut crc: u32, data: &[u8]) -> u32 {
    // Split dst and mask into regions of &[u8], &[u32], &[u8] each.
    // SAEFTY: The u32 is only used for memory loads.
    let (head, middle_ne_u32, tail) = unsafe { data.align_to::<u32>() };
    for b in head.iter() {
        crc = crc32le_update_u8_snb(crc, *b);
    }
    for v_ne in middle_ne_u32.iter() {
        let v_le = v_ne.to_le();
        crc = crc32le_update_u32le_snb(crc, v_le);
    }
    for b in tail.iter() {
        crc = crc32le_update_u8_snb(crc, *b);
    }

    crc
}

#[test]
fn test_crc32le() {
    let send_crc = crc32le_init();
    let send_crc = crc32le_update_u32le(send_crc, 0xabbccdde);
    let send_crc = crc32le_update_u64le(send_crc, 0xabbccddeeff00112);
    let send_crc = crc32le_update_u8(send_crc, 0x23);
    let send_crc = crc32le_finish_send(send_crc);

    assert_eq!(
        crc32le_finish_send(crc32le_update_data(
            crc32le_init(),
            &[
                0xdeu8, 0xcd, 0xbc, 0xab, 0x12, 0x01, 0xf0, 0xef, 0xde, 0xcd, 0xbc, 0xab, 0x23
            ]
        )),
        send_crc
    );

    assert_ne!(
        crc32le_finish_send(crc32le_update_data(
            crc32le_init(),
            &[
                0xdeu8, 0xcd, 0xbc, 0xab, 0x12, 0x01, 0xf0, 0xef, 0xde, 0xcd, 0xbc, 0xab, 0x23, 0x00,
            ]
        )),
        send_crc
    );

    let computed_crc = crc32le_init();
    let computed_crc = crc32le_update_u8(computed_crc, 0xde);
    let computed_crc = crc32le_update_u64le(computed_crc, 0xdeeff00112abbccd);
    let computed_crc = crc32le_update_u32le(computed_crc, 0x23abbccd);
    assert!(crc32le_finish_receive(computed_crc, send_crc));
}

#[test]
fn test_crc32le_snb() {
    let send_crc = crc32le_init();
    let send_crc = crc32le_update_u32le_snb(send_crc, 0xabbccdde);
    let send_crc = crc32le_update_u64le_snb(send_crc, 0xabbccddeeff00112);
    let send_crc = crc32le_update_u8_snb(send_crc, 0x23);
    let send_crc = crc32le_finish_send(send_crc);

    assert_eq!(
        crc32le_finish_send(crc32le_update_data_snb(
            crc32le_init(),
            &[
                0xdeu8, 0xcd, 0xbc, 0xab, 0x12, 0x01, 0xf0, 0xef, 0xde, 0xcd, 0xbc, 0xab, 0x23
            ]
        )),
        send_crc
    );

    assert_ne!(
        crc32le_finish_send(crc32le_update_data_snb(
            crc32le_init(),
            &[
                0xdeu8, 0xcd, 0xbc, 0xab, 0x12, 0x01, 0xf0, 0xef, 0xde, 0xcd, 0xbc, 0xab, 0x23, 0x00,
            ]
        )),
        send_crc
    );

    let computed_crc = crc32le_init();
    let computed_crc = crc32le_update_u8_snb(computed_crc, 0xde);
    let computed_crc = crc32le_update_u64le_snb(computed_crc, 0xdeeff00112abbccd);
    let computed_crc = crc32le_update_u32le_snb(computed_crc, 0x23abbccd);
    assert!(crc32le_finish_receive(computed_crc, send_crc));
}
