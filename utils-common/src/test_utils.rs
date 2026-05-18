// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Red Hat, LLC
// Author: Oliver Steffen <osteffen@redhat.com>
//
// Simple xorshift32 PRNG — no std required.
// https://en.wikipedia.org/wiki/Xorshift

pub struct Prng {
    state: u32,
}

impl Prng {
    pub fn new() -> Self {
        Self { state: 0xdeadbeef }
    }

    pub fn get(&mut self) -> u8 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 17;
        self.state ^= self.state << 5;
        self.state as u8
    }
}
