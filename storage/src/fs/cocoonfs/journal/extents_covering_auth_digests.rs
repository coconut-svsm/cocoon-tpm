// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`ExtentsCoveringAuthDigests`].

extern crate alloc;
use alloc::vec::Vec;

use crate::{
    fs::cocoonfs::{FormatError, NvFsError, extents, layout, leb128},
    nvfs_err_internal,
    utils_common::{
        fixed_vec::FixedVec,
        io_slices::{self, IoSlicesIterCommon as _, IoSlicesMutIter as _, WalkableIoSlicesIter as _},
        zeroize,
    },
};
use core::ops;

#[cfg(doc)]
use layout::ImageLayout;

/// Sequence of [Authentication Tree Data
/// Block](layout::ImageLayout::auth_tree_data_block_allocation_blocks_log2)
/// digests associated with some possibly discontiguous storage extents.
///
/// Used for the journal log's
/// [`AllocBitmapFileFragmentsAuthDigests`
/// field](super::log::JournalLogFieldTag::AllocBitmapFileFragmentsAuthDigests).
pub struct ExtentsCoveringAuthDigests {
    /// Pairs of physical [Authentication Tree Data
    /// Block](layout::ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// location on storage and associated digest.
    ///
    /// Sorted by location on storage.
    auth_digests: Vec<(layout::PhysicalAllocBlockIndex, zeroize::Zeroizing<FixedVec<u8, 5>>)>,
}

impl ExtentsCoveringAuthDigests {
    /// Determine a [`ExtentsCoveringAuthDigests`]'s encoded length.
    ///
    /// # Arguments:
    ///
    /// * `covered_extents` - Storage extents to be covered by the
    ///   authentication digests, sorted by increasing storage location.
    /// * `auth_tree_data_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::auth_tree_data_block_allocation_blocks_log2`].
    /// * `auth_digest_len` - Length of a single [Authentication Tree Data
    ///   Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    ///   digest.
    pub fn encoded_len(
        covered_extents: &extents::PhysicalExtents,
        auth_tree_data_block_allocation_blocks_log2: u8,
        auth_digest_len: usize,
    ) -> Result<usize, NvFsError> {
        let auth_tree_data_block_allocation_blocks_log2 = auth_tree_data_block_allocation_blocks_log2 as u32;

        let mut total_encoded_auth_tree_data_blocks_offsets_len = 0usize;
        let mut total_auth_digests_count = 0usize;

        let auth_tree_data_blocks_allocation_blocks =
            layout::AllocBlockCount::from(1u64 << auth_tree_data_block_allocation_blocks_log2);
        let mut last_extent_allocation_blocks_end = layout::PhysicalAllocBlockIndex::from(0);
        let mut last_auth_tree_data_block_allocation_blocks_end = layout::PhysicalAllocBlockIndex::from(0);
        for covered_extent in covered_extents.iter() {
            // covered_extents is assumed to be sorted and all its extents must be
            // non-overlapping.
            if covered_extent.begin() <= last_extent_allocation_blocks_end {
                return Err(nvfs_err_internal!());
            }
            last_extent_allocation_blocks_end = covered_extent.end();

            if last_auth_tree_data_block_allocation_blocks_end >= covered_extent.end() {
                // Already covered in full.
                continue;
            }

            let mut cur_auth_tree_data_block_allocation_blocks_begin = covered_extent
                .begin()
                .align_down(auth_tree_data_block_allocation_blocks_log2)
                .max(last_auth_tree_data_block_allocation_blocks_end);
            while cur_auth_tree_data_block_allocation_blocks_begin < covered_extent.end() {
                total_encoded_auth_tree_data_blocks_offsets_len = total_encoded_auth_tree_data_blocks_offsets_len
                    .checked_add(leb128::leb128u_u64_encoded_len(
                        u64::from(
                            cur_auth_tree_data_block_allocation_blocks_begin
                                - last_auth_tree_data_block_allocation_blocks_end,
                        ) >> auth_tree_data_block_allocation_blocks_log2,
                    ))
                    .ok_or(NvFsError::DimensionsNotSupported)?;
                total_auth_digests_count += 1;

                cur_auth_tree_data_block_allocation_blocks_begin += auth_tree_data_blocks_allocation_blocks;
                last_auth_tree_data_block_allocation_blocks_end = cur_auth_tree_data_block_allocation_blocks_begin;
            }
        }

        let total_auth_digests_len = total_auth_digests_count
            .checked_mul(auth_digest_len)
            .ok_or(NvFsError::DimensionsNotSupported)?;
        total_encoded_auth_tree_data_blocks_offsets_len
            .checked_add(total_auth_digests_len)
            .ok_or(NvFsError::DimensionsNotSupported)
    }

    /// Decode a [`ExtentsCoveringAuthDigests`].
    ///
    /// # Arguments:
    ///
    /// * `src` - Source buffers to decode from. `src` will get fully consumed.
    /// * `auth_tree_data_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::auth_tree_data_block_allocation_blocks_log2`].
    /// * `allocation_block_size_128b_log2` - Verbatim value of
    ///   [`ImageLayout::allocation_block_size_128b_log2`].
    /// * `auth_digest_len` - Length of a single [Authentication Tree Data
    ///   Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    ///   digest.
    pub fn decode<'a, SI: io_slices::PeekableIoSlicesIter<'a, BackendIteratorError = NvFsError>>(
        mut src: SI,
        auth_tree_data_block_allocation_blocks_log2: u8,
        allocation_block_size_128b_log2: u8,
        auth_digest_len: usize,
    ) -> Result<Self, NvFsError> {
        let auth_tree_data_blocks_allocation_blocks =
            layout::AllocBlockCount::from(1u64 << (auth_tree_data_block_allocation_blocks_log2 as u32));
        let mut auth_digests = Vec::new();
        let mut last_auth_tree_data_block_allocation_blocks_end = layout::PhysicalAllocBlockIndex::from(0);
        while !src.is_empty()? {
            // Decode the relative Authentication Tree Data Block's beginning.
            // One leb128-encoded 64 bit integer, signed or unsigned, is at most 10 bytes
            // long.
            let mut decode_buf: [u8; 10] = [0u8; 10];
            let decode_buf_len = decode_buf.len();
            // Attempt to fill up the whole decode_buf by peeking on src.
            let mut decode_buf_io_slice = io_slices::SingletonIoSliceMut::new(&mut decode_buf);
            (&mut decode_buf_io_slice)
                .map_infallible_err()
                .copy_from_iter(&mut src.decoupled_borrow())?;
            let decode_buf_len = decode_buf_len - decode_buf_io_slice.total_len()?;
            let decode_buf = &decode_buf[..decode_buf_len];

            let (delta_auth_tree_data_blocks, decode_buf_remainder) = leb128::leb128u_u64_decode(decode_buf)
                .map_err(|_| NvFsError::from(FormatError::InvalidJournalExtentsCoveringAuthDigestsFormat))?;
            // Advance the peeked src iterator past the encoded length value.
            src.skip(decode_buf.len() - decode_buf_remainder.len())
                .map_err(|e| match e {
                    io_slices::IoSlicesIterError::BackendIteratorError(e) => e,
                    io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                        io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
                    },
                })?;
            let delta_allocation_blocks =
                delta_auth_tree_data_blocks << (auth_tree_data_block_allocation_blocks_log2 as u32);
            if delta_allocation_blocks >> (auth_tree_data_block_allocation_blocks_log2 as u32)
                != delta_auth_tree_data_blocks
            {
                return Err(NvFsError::from(
                    FormatError::InvalidJournalExtentsCoveringAuthDigestsEntry,
                ));
            }

            let cur_auth_tree_data_block_allocation_blocks_begin = layout::PhysicalAllocBlockIndex::from(
                u64::from(last_auth_tree_data_block_allocation_blocks_end)
                    .checked_add(delta_allocation_blocks)
                    .ok_or(NvFsError::from(
                        FormatError::InvalidJournalExtentsCoveringAuthDigestsEntry,
                    ))?,
            );
            if u64::from(cur_auth_tree_data_block_allocation_blocks_begin)
                >> (auth_tree_data_block_allocation_blocks_log2 as u32)
                > u64::MAX
                    >> (auth_tree_data_block_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32 + 7)
            {
                return Err(NvFsError::from(
                    FormatError::InvalidJournalExtentsCoveringAuthDigestsEntry,
                ));
            }
            last_auth_tree_data_block_allocation_blocks_end =
                cur_auth_tree_data_block_allocation_blocks_begin + auth_tree_data_blocks_allocation_blocks;

            let mut cur_auth_digest = zeroize::Zeroizing::new(FixedVec::new_with_default(auth_digest_len)?);
            io_slices::SingletonIoSliceMut::new(&mut cur_auth_digest)
                .map_infallible_err()
                .copy_from_iter(&mut (&mut src).take_exact(auth_digest_len))
                .map_err(|e| match e {
                    io_slices::IoSlicesIterError::BackendIteratorError(e) => e,
                    io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                        io_slices::IoSlicesError::BuffersExhausted => {
                            NvFsError::from(FormatError::InvalidJournalExtentsCoveringAuthDigestsFormat)
                        }
                    },
                })?;

            if let Err(e) = auth_digests.try_reserve(1) {
                return Err(NvFsError::from(e));
            }
            auth_digests.push((cur_auth_tree_data_block_allocation_blocks_begin, cur_auth_digest));
        }

        Ok(Self { auth_digests })
    }

    /// Number of [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) digest
    /// entries.
    pub fn len(&self) -> usize {
        self.auth_digests.len()
    }
}

impl ops::Index<usize> for ExtentsCoveringAuthDigests {
    type Output = (layout::PhysicalAllocBlockIndex, zeroize::Zeroizing<FixedVec<u8, 5>>);
    fn index(&self, index: usize) -> &Self::Output {
        &self.auth_digests[index]
    }
}
