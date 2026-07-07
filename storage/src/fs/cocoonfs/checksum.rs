// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Checksum computation and verification.
//!
//! # See also:
//!
//! * [`ChecksumInstance`].

use crate::fs::cocoonfs::crc32::{self, crc32le_finish_receive};

use core::{default, mem};

/// Length of a checksum produced by [`ChecksumInstance`].
pub const CHECKSUM_LEN: u32 = 2 * mem::size_of::<u32>() as u32;

/// Compute a checksum as defined by the CocoonFs format specification.
///
/// The semantics of the checksum are those defined by the CocoonFs format
/// specification, i.e. internally it comprises a pair of two CRC32 values: one
/// over the plain data and another of the data with neighbouring bits swapped
/// each.
///
/// Invoke [`update()`](Self::update) over the to be checksummed data one or
/// more time and call either [`finish_send()`](Self::finish_send) to obtain the
/// checksum for serialization to storage or
/// [`finish_receive`](Self::finish_receive) to verify against a checksum read
/// from storage.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ChecksumInstance {
    /// CRC32 register for checksumming the data.
    crc: u32,
    /// CRC32 register for checksumming the data with any two neighbouring bits
    /// swapped.
    crc_snb: u32,
}

impl ChecksumInstance {
    /// Create a new [`ChecksumInstance`] in initial state.
    pub const fn new() -> Self {
        Self {
            crc: crc32::crc32le_init(),
            crc_snb: crc32::crc32le_init(),
        }
    }

    /// Checksum some data portion.
    ///
    /// Update the [`ChecksumInstance`] state to account for `data`.  `update()`
    /// may get called any number of times to account for different portions
    /// of the checksummed data. The checksum eventually produced by
    /// [`finish_send()`](Self::finish_send) or
    /// [`finish_receive()`](Self::finish_receive) will be over all `data`
    /// chunks `update()` has been invoked on up to that point concatenated
    /// together.
    ///
    /// When done, invoke either [`finish_send()`](Self::finish_send) to obtain
    /// the checksum value or [`finish_receive()`](Self::finish_receive) to
    /// verify against one.
    ///
    /// # Arguments:
    ///
    /// * `data` - The data to get checksummed.
    ///
    /// # See also:
    ///
    /// * [`finish_send()`](Self::finish_send).
    /// * [`finish_receive()`](Self::finish_receive).
    pub fn update(&mut self, data: &[u8]) {
        self.crc = crc32::crc32le_update_data(self.crc, data);
        self.crc_snb = crc32::crc32le_update_data_snb(self.crc_snb, data);
    }

    /// Produce a checksum from the current [`ChecksumInstance`] state.
    ///
    /// # See also:
    ///
    /// * [`update()`](Self::update).
    /// * [`finish_receive()`](Self::finish_receive).
    pub fn finish_send(&self) -> [u8; CHECKSUM_LEN as usize] {
        let crc = crc32::crc32le_finish_send(self.crc).to_le_bytes();
        let crc_snb = crc32::crc32le_finish_send(self.crc_snb).to_le_bytes();
        let mut checksum = [0u8; CHECKSUM_LEN as usize];
        checksum[..mem::size_of::<u32>()].copy_from_slice(&crc);
        checksum[mem::size_of::<u32>()..].copy_from_slice(&crc_snb);
        checksum
    }

    /// Verify the checksum represented by the current [`ChecksumInstance`]
    /// state against an expected one.
    ///
    /// Return `true` if the checksum verification passes, `false` otherwise.
    ///
    /// # Arguments:
    ///
    /// * `expected_checksum` - The expected checksum read from storage. It must
    ///   have been previously produced by [`finish_send()`](Self::finish_send)
    ///   on some [`ChecksumInstance`] [over](Self::update) what is expected to
    ///   be the same data.
    ///
    /// # See also:
    ///
    /// * [`update()`](Self::update).
    /// * [`finish_send()`](Self::finish_send).
    pub fn finish_receive(&self, expected_checksum: &[u8]) -> bool {
        debug_assert_eq!(expected_checksum.len(), CHECKSUM_LEN as usize);
        let mut expected_crc = [0u8; mem::size_of::<u32>()];
        expected_crc.copy_from_slice(&expected_checksum[..mem::size_of::<u32>()]);
        let expected_crc = u32::from_le_bytes(expected_crc);

        let mut expected_crc_snb = [0u8; mem::size_of::<u32>()];
        expected_crc_snb.copy_from_slice(&expected_checksum[mem::size_of::<u32>()..]);
        let expected_crc_snb = u32::from_le_bytes(expected_crc_snb);

        crc32::crc32le_finish_receive(self.crc, expected_crc) && crc32le_finish_receive(self.crc_snb, expected_crc_snb)
    }
}

impl default::Default for ChecksumInstance {
    fn default() -> Self {
        Self::new()
    }
}
