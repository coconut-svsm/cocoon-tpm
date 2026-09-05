// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of common bit manipulation related primitives for native
//! integers.

macro_rules! impl_bitmanip_common {
    ($t:ty, $ut:ty, $st:ty) => {
        fn trailing_bits_mask(count: u32) -> $t {
            debug_assert!(count <= <$t>::BITS);
            let all = count / <$t>::BITS;
            let count = count % <$t>::BITS;
            (((1 as $ut) << count) - 1).wrapping_sub(all as $ut) as $t
        }

        fn is_nonzero(self) -> Self {
            let value = self as $ut;
            ((value | value.wrapping_neg()) >> (<$ut>::BITS - 1)) as $t
        }

        fn is_aligned_pow2(self, pow2_log2: u32) -> bool {
            <Self as BitManip>::abs(self) & <$ut as BitManip>::trailing_bits_mask(pow2_log2) == 0
        }
    };
}

macro_rules! impl_bitmanip_u {
    ($ut:ty, $st:ty) => {
        impl BitManip for $ut {
            type UnsignedType = $ut;

            impl_bitmanip_common!($ut, $ut, $st);

            fn abs(self) -> Self::UnsignedType {
                self
            }

            fn exp2(pow2_log2: u32) -> Self {
                debug_assert!(pow2_log2 < <$ut>::BITS);
                (1 as $ut) << pow2_log2
            }

            fn significant_bits(self) -> u32 {
                // A zero should still have one significant bit.
                let lz = (self | 1).leading_zeros();
                debug_assert!(lz < <$ut>::BITS);
                <$ut>::BITS - lz
            }

            fn sign_extend(self, sign_bit_pos: u32) -> Self {
                debug_assert!(sign_bit_pos < <$ut>::BITS);
                let leading_bits = <$ut>::BITS - sign_bit_pos - 1;
                (((self << leading_bits) as $st) >> leading_bits) as $ut
            }
        }
    };
}

macro_rules! impl_ubitmanip {
    ($ut:ty, $st:ty) => {
        impl UBitManip for $ut {
            fn round_down_pow2(self, pow2_log2: u32) -> Self {
                debug_assert!(pow2_log2 < <$ut>::BITS);
                (self >> pow2_log2) << pow2_log2
            }

            fn round_up_pow2(self, pow2_log2: u32) -> Option<Self> {
                debug_assert!(pow2_log2 < <$ut>::BITS);
                let t = ((1 as $ut) << pow2_log2) - 1;
                Some(self.checked_add(t)? & !t)
            }

            fn round_up_pow2_unchecked(self, pow2_log2: u32) -> Self {
                debug_assert!(pow2_log2 < <$ut>::BITS);
                let t = ((1 as $ut) << pow2_log2) - 1;
                self + (self.wrapping_neg() & t)
            }

            fn round_up_next_pow2(self) -> Option<Self> {
                let t = self.wrapping_sub(1);
                let lz = t.leading_zeros();
                if lz != 0 {
                    Some((1 as $ut) << (<$ut>::BITS - lz))
                } else {
                    // Is either 0 or > the largest representable power of two.
                    if self == 0 { Some(self) } else { None }
                }
            }

            fn round_down_next_pow2(self) -> Self {
                let is_zero = 1 - ((self | self.wrapping_neg()) >> (<$ut>::BITS - 1));
                ((1 as $ut) << (<$ut>::BITS - 1 - (self | is_zero).leading_zeros())) - is_zero
            }

            fn expand_from_right(self, mut mask: $ut) -> Self {
                // Refer to Hacker's Delight, 2nd ed., 7-5 ("Expand, or Generalized Insert").
                const BITS_LOG2: u32 = <$ut>::BITS.ilog2();
                let mut x = self;
                let mut a = [0 as $ut; BITS_LOG2 as usize];

                let m0 = mask;
                let mut mk = !mask << 1;

                for i in 0..BITS_LOG2 {
                    let mut mp = mk;
                    for j in 0..BITS_LOG2 {
                        mp = mp ^ (mp << (1 << j));
                    }
                    let mv = mp & mask;
                    a[i as usize] = mv;
                    mask = (mask ^ mv) | (mv >> (1 << i));
                    mk &= !mp;
                }

                let mut i = BITS_LOG2;
                while i > 0 {
                    i -= 1;
                    let mv = a[i as usize];
                    let t = x << (1 << i);
                    x = (x & !mv) | (t & mv);
                }
                return x & m0;
            }

            fn expand_from_left(self, mut mask: $ut) -> Self {
                // Refer to Hacker's Delight, 2nd ed., 7-5 ("Expand, or Generalized Insert").
                const BITS_LOG2: u32 = <$ut>::BITS.ilog2();
                let mut x = self;
                let mut a = [0 as $ut; BITS_LOG2 as usize];

                let m0 = mask;
                let mut mk = !mask >> 1;

                for i in 0..BITS_LOG2 {
                    let mut mp = mk;
                    for j in 0..BITS_LOG2 {
                        mp = mp ^ (mp >> (1 << j));
                    }
                    let mv = mp & mask;
                    a[i as usize] = mv;
                    mask = (mask ^ mv) | (mv << (1 << i));
                    mk &= !mp;
                }

                let mut i = BITS_LOG2;
                while i > 0 {
                    i -= 1;
                    let mv = a[i as usize];
                    let t = x >> (1 << i);
                    x = (x & !mv) | (t & mv);
                }
                return x & m0;
            }
        }
    };
}

macro_rules! impl_bitmanip_s {
    ($ut:ty, $st:ty) => {
        impl BitManip for $st {
            type UnsignedType = $ut;

            impl_bitmanip_common!($st, $ut, $st);

            fn abs(self) -> Self::UnsignedType {
                let neg_mask = (self >> (<$st>::BITS - 1)) as $ut;
                ((self as $ut) ^ neg_mask).wrapping_sub(neg_mask)
            }

            fn exp2(pow2_log2: u32) -> Self {
                debug_assert!(pow2_log2 < <$st>::BITS - 1);
                (1 as $st) << pow2_log2
            }

            fn significant_bits(self) -> u32 {
                let value = self as $ut;
                // Invert if negative.
                let value = value ^ (0 as $ut).wrapping_sub(value >> (<$ut>::BITS - 1));

                let lz = value.leading_zeros();
                debug_assert!(lz != 0 && lz <= <$ut>::BITS);
                <$ut>::BITS - (lz - 1)
            }

            fn sign_extend(self, sign_bit_pos: u32) -> Self {
                (self as $ut).sign_extend(sign_bit_pos) as $st
            }
        }
    };
}

pub trait BitManip: Copy {
    type UnsignedType;

    /// Create a mask with the specified number of least significant bits set.
    fn trailing_bits_mask(count: u32) -> Self;

    /// Compute the absolute value.
    fn abs(self) -> Self::UnsignedType;

    /// Test if non-zero.
    ///
    /// Returns `0` if not, `1` if yes.
    fn is_nonzero(self) -> Self;

    /// Raise two to a given power.
    ///
    /// # Arguments:
    ///
    /// * `pow2_log2` - The base-2 logarithm of the desired power of two.
    fn exp2(pow2_log2: u32) -> Self;

    /// Test whether a value is a multiple of a given power of two.
    ///
    /// # Arguments:
    ///
    /// * `pow2_log2` - The base-2 logarithm of the desired power of two.
    fn is_aligned_pow2(self, pow2_log2: u32) -> bool;

    /// Count the number of significant bits needed for representing a value.
    fn significant_bits(self) -> u32;

    /// Sign-extend from a given bit position upwards.
    ///
    /// Assume the value has its sign bit at the position specified by
    /// `sign_bit_pos` and propagate that upwards.
    fn sign_extend(self, sign_bit_pos: u32) -> Self;
}

pub trait UBitManip: Sized + BitManip<UnsignedType = Self> {
    /// Round a value down to a multiple of a given power of two.
    ///
    /// # Arguments:
    ///
    /// * `pow2_log2` - The base-2 logarithm of the desired power of two.
    fn round_down_pow2(self, pow2_log2: u32) -> Self;

    /// Round a value uo to a multiple of a given power of two.
    ///
    /// Returns `None` on overflow, otherwise the rounded value wrapped in a
    /// `Some`.
    ///
    /// # Arguments:
    ///
    /// * `pow2_log2` - The base-2 logarithm of the desired power of two.
    fn round_up_pow2(self, pow2_log2: u32) -> Option<Self>;

    /// Round a value uo to a multiple of a given power of two without checking
    /// for overflow.
    ///
    /// # Arguments:
    ///
    /// * `pow2_log2` - The base-2 logarithm of the desired power of two.
    fn round_up_pow2_unchecked(self, pow2_log2: u32) -> Self;

    /// Round a value upwards to the next power of two larger than or equal to
    /// it.
    ///
    /// Returns `None` on overflow, otherwise the rounded value wrapped in a
    /// `Some`.
    ///
    /// On input `0`, `Some(0)` is getting returned, even though that's not
    /// a power of two.
    fn round_up_next_pow2(self) -> Option<Self>;

    /// Round a value downwards to the next power of two smaller than or equal
    /// to it.
    ///
    /// On input `0`, `0` is getting returned, even though that's not a power of
    /// two.
    fn round_down_next_pow2(self) -> Self;

    /// Expand from right operation.
    ///
    /// Expand the value according to `mask`. Any bit not set in `mask` will be
    /// clear in the result. For bits set in the mask, the resulting bit
    /// value will be taken from the input value's bit at the first position
    /// not consumed yet for any previous bits in LSB-first order.
    fn expand_from_right(self, mask: Self) -> Self;

    /// Expand from left operation.
    ///
    /// Expand the value according to `mask`. Any bit not set in `mask` will be
    /// clear in the result. For bits set in the mask, the resulting bit
    /// value will be taken from the input value's bit at the first position
    /// not consumed yet for any previous bits in MSB-first order.
    fn expand_from_left(self, mask: Self) -> Self;
}

impl_bitmanip_u!(u8, i8);
impl_ubitmanip!(u8, i8);
impl_bitmanip_u!(u16, i16);
impl_ubitmanip!(u16, i16);
impl_bitmanip_u!(u32, i32);
impl_ubitmanip!(u32, i32);
impl_bitmanip_u!(u64, i64);
impl_ubitmanip!(u64, i64);
impl_bitmanip_u!(usize, isize);
impl_ubitmanip!(usize, isize);

impl_bitmanip_s!(u8, i8);
impl_bitmanip_s!(u16, i16);
impl_bitmanip_s!(u32, i32);
impl_bitmanip_s!(u64, i64);
