// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of MurmurHash3.
//!
//! MurmurHash3 has been designed by Austin Appleby, who put it in the
//! Public Domain.

/// MurmurHash3 32-bit variant hash computation state.
pub struct MurmurHash3_32 {
    h: u32,
    data_tail: [u8; 4],
    data_tail_len: u8,
    total_len: usize,
}

impl MurmurHash3_32 {
    /// Create a new MurmurHash3_32 instance.
    ///
    /// # Arguments:
    ///
    /// * `seed` - The seed.
    pub fn new(seed: u32) -> Self {
        Self {
            h: seed,
            data_tail: [0u8; 4],
            data_tail_len: 0,
            total_len: 0,
        }
    }

    /// Hash data into the instance.
    ///
    /// # Arguments:
    ///
    /// * `data` - The data to hash.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len());

        if self.data_tail_len != 0 {
            let remaining_len = self.data_tail_len as usize;
            let remaining_fillup_len = (self.data_tail.len() - remaining_len).min(data.len());
            let data_head;
            (data_head, data) = data.split_at(remaining_fillup_len);
            self.data_tail[remaining_len..remaining_len + remaining_fillup_len].copy_from_slice(data_head);
            self.data_tail_len += remaining_fillup_len as u8;
            if self.data_tail_len as usize == self.data_tail.len() {
                let k = u32::from_le_bytes(self.data_tail);
                self.h = Self::mix_key_body_word(self.h, k);
                self.data_tail_len = 0;
                self.data_tail.fill(0);
            } else {
                return;
            }
        }

        let data_words = data.chunks_exact(4);
        let data_remainder = data_words.remainder();
        if !data_remainder.is_empty() {
            self.data_tail[..data_remainder.len()].copy_from_slice(data_remainder);
            self.data_tail_len = data_remainder.len() as u8;
        }
        for k in data_words {
            let k = u32::from_le_bytes(<[u8; 4]>::try_from(k).unwrap());
            self.h = Self::mix_key_body_word(self.h, k);
        }
    }

    /// Produce the hash value.
    pub fn finalize(mut self) -> u32 {
        if self.data_tail_len != 0 {
            let k = u32::from_le_bytes(self.data_tail);
            self.h = Self::mix_key_tail_word(self.h, k);
        }

        let mut h = self.h;
        h ^= self.total_len as u32;
        h ^= h >> 16;
        h = h.wrapping_mul(0x85ebca6b);
        h ^= h >> 13;
        h = h.wrapping_mul(0xc2b2ae35);
        h ^= h >> 16;
        h
    }

    fn mix_key_body_word(mut h: u32, k: u32) -> u32 {
        h ^= Self::diffuse_key_word(k);
        h = h.rotate_left(13);
        h = 5u32.wrapping_mul(h).wrapping_add(0xe6546b64);
        h
    }

    fn mix_key_tail_word(mut h: u32, k: u32) -> u32 {
        h ^= Self::diffuse_key_word(k);
        h
    }

    fn diffuse_key_word(mut k: u32) -> u32 {
        k = k.wrapping_mul(0xcc9e2d51u32);
        k = k.rotate_left(15);
        k = k.wrapping_mul(0x1b873593u32);
        k
    }
}

#[test]
pub fn expected_values() {
    // from https://en.wikipedia.org/wiki/MurmurHash
    [
        ("", 0x00000000, 0x00000000),
        ("", 0x00000001, 0x514e28b7),
        ("", 0xffffffff, 0x81f16f39),
        ("test", 0x00000000, 0xba6bd213),
        ("test", 0x9747b28c, 0x704b81dc),
        ("Hello, world!", 0x00000000, 0xc0363e43),
        ("Hello, world!", 0x9747b28c, 0x24884cba),
        ("The quick brown fox jumps over the lazy dog", 0x00000000, 0x2e4ff723),
        ("The quick brown fox jumps over the lazy dog", 0x9747b28c, 0x2fa826cd),
    ]
    .iter()
    .for_each(|(data, seed, expected)| {
        let mut m = MurmurHash3_32::new(*seed);
        m.update(data.as_bytes());
        let hash = m.finalize();
        assert_eq!(hash, *expected);
    });
}
