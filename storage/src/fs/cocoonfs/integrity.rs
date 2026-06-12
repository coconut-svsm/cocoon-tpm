// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Functionality related to extent integrity protections.
//!
//! Refer to the CocoonFs format specification for details.
//!
//! The primary purpose of the extent integrity protection scheme is
//! is to detect torn writes to storage extents subject to the protection.
//! To that end, it is expected that writes to these extents proceed as follows:
//! 1. The extent's tail following the first [device IO
//!    Block](NvBlkDev::io_block_size_128b_log2) gets written first,
//! 2. followed by a write barrier,
//! 3. followed by the write to the extent's [device IO
//!    Block](NvBlkDev::io_block_size_128b_log2).
//!
//! Even though the integrity protections do include a [checksum] over
//! all of the extent's data, some additional protections are applied to the
//! extent's first [IO Block](ImageLayout::io_block_allocation_blocks_log2).
//! The intent is to make torn write detection for the extent's first [device IO
//! Block](NvBlkDev::io_block_size_128b_log2) more robust, as
//! [checksums](checksum) are inherently prone to collisions. The scheme
//! implemented assumes a certain hardware behavior upon torn writes, namely
//! that there would be a pivot point within the [device IO
//! Block](NvBlkDev::io_block_size_128b_log2) splitting it into all-new and
//! all-old regions respectively. A two-tier approach is followed:
//! - *Tier 0* - The extent's first 128B are transformed by a xoring them with a
//!   mask specifically chosen to make them all non-zero. Assuming that the
//!   state on storage had been all-zero before the write, any leftover zero
//!   byte encountered at verification time indicates a torn write.
//! - *Tier 1* - The extent's first [IO
//!   Block](ImageLayout::io_block_allocation_blocks_log2)'s remainder, i.e. its
//!   `128..` tail is protected by writing special write completion markers to
//!   certain checkpoint locations, namely right before all the power-of-two
//!   boundaries. Note that as the [device IO Block
//!   size](NvBlkDev::io_block_size_128b_log2) must not exceed the [filesystem's
//!   IO Block size](ImageLayout::io_block_allocation_blocks_log2), these
//!   checkpoint locations align exactly with all possible [device IO
//!   Block](NvBlkDev::io_block_size_128b_log2)' tails. Before writing the write
//!   completion marker to the respecive checkpoint locations, the original data
//!   found there will get saved away into the extent's integrity protections
//!   data area beforehand, and restored again in the course of the integrity
//!   protection verification. If any of these checkpoint locations is found to
//!   not contain the expected write completion marker value at integrity
//!   protection verification time, then a torn write has happened and the
//!   verification fails.
//!
//!   The write completion markers are not constants, but derived dynamically
//!   as "commit IDs" from the extent's [checksum]. The primary copy, i.e.
//!   the expected commit ID is always stored within the tier 0 integrity
//!   protection realm, i.e. within the extent's first 128B. As it's possible
//!   to obtain the [checksum] back from a the commit ID value, this allows
//!   for dynamic write completion marker values, i.e. commit IDs, while
//!   avoiding the need to store the commit ID and the   the [checksum]
//!   separately.
//!
//! Where exactly within an extent its collective integrity protections data is
//! stored is a property of the extent type, with the invariants that
//! - its `8 + 1` head bytes are always contained within the extent's first
//!   128B,
//! - its length is always equal to [`extent_integrity_protections_len()`],
//!   which is an invariant of the filesystem and
//! - its always contained within the extent's first [IO
//!   Block](ImageLayout::io_block_allocation_blocks_log2).
use cocoon_tpm_utils_common::io_slices::{
    IoSlicesIter, IoSlicesIterCommon, IoSlicesMutIter, MutPeekableIoSlicesMutIter, PeekableIoSlicesIter,
};

use crate::nvfs_err_internal;
use crate::utils_common::io_slices;

use crate::{
    blkdev,
    fs::{NvFsError, cocoonfs::checksum},
};

use core::{convert, mem, pin, slice, task};

#[cfg(doc)]
use crate::blkdev::NvBlkDev;
#[cfg(doc)]
use crate::fs::cocoonfs::layout::ImageLayout;

use super::layout::PhysicalAllocBlockIndex;

/// Length of the extent integrity protections data.
///
/// Note that the integrity protections data length is an invariant of the
/// filesystem.
///
/// # Arguments:
///
/// * `io_block_allocation_blocks_log2` - Verbatim value of
///   [`ImageLayout::io_block_allocation_blocks_log2`].
/// * `allocation_block_size_128b_log2` - Verbatim value of
///   [`ImageLayout::allocation_block_size_128b_log2`].
pub const fn extent_integrity_protections_len(
    io_block_allocation_blocks_log2: u8,
    allocation_block_size_128b_log2: u8,
) -> u32 {
    checksum::CHECKSUM_LEN
        + 1
        + (io_block_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32) * checksum::CHECKSUM_LEN
}

/// An extent's known tier 0 integrity protection state on storage.
///
/// In cases where more control is needed over what
/// [`extent_integrity_protections_determine_state()`] or
/// [`extent_integrity_protections_verify_and_remove()`] provide, the tier 0
/// protection may get verified and removed explicitly via
/// [`extent_tier0_integrity_protection_verify_and_remove()`] first
/// and the resulting `ExtentTier0IntegrityState` then passed onwards to either
/// of the former for that to resume at tier 1.
///
/// Examples would include a case where the `io_block_allocation_blocks_log2`
/// and `allocation_block_size_128b_log2` arguments needed as input to the full
/// [`extent_integrity_protections_determine_state()`] or
/// [`extent_integrity_protections_verify_and_remove()`] are themselves stored
/// within the tier 0 protection realm, i.e. within the extent's first 128B.
///
/// # See also:
///
/// * [`extent_tier0_integrity_protection_verify_and_remove()`].
/// * [`extent_integrity_protections_determine_state()`].
/// * [`extent_integrity_protections_verify_and_remove()`].
#[derive(Clone, Copy, Debug)]
pub struct ExtentTier0IntegrityState {
    /// Tier 1 commit ID, derived from the checksum by applying the
    /// [`xor_mask`](Self::xor_mask) to it.
    commit_id: [u8; checksum::CHECKSUM_LEN as usize],
    /// Mask applied to all bytes within the tier 0 protection realm to make
    /// them non-zero (and also, to make the [tier 1
    /// `commit_id`](Self::commit_id) to differ from previous ones).
    xor_mask: u8,
    /// Whether the tier 0 integrity protection verification passed, i.e.
    /// whether all bytes in its protection realm are non-zero.
    is_valid: bool,
    /// Whether any of the bytes within the tier 0 protection realm is non-zero.
    need_clear: bool,
}

/// Verify an extent's tier 0 integrity protections.
///
/// On success, the [`ExtentTier0IntegrityState`] is returned.
/// [`ExtentTier0IntegrityState::is_valid`] thereof represents the verification
/// outcome.
///
/// # Arguments:
///
/// * `extent` - The extent's contents. Needs to cover only the first 128B.
/// * `extent_head_skip` - Amount of head space exempt from the integrity
///   protection.
/// * `integrity_protections_offset` - Offset relative to `extent_head_skip`
///   where the integrity protections are stored within the extent.
fn extent_tier0_integrity_protection_verify<'a, E: io_slices::IoSlicesIter<'a>>(
    mut extent: E,
    extent_head_skip: usize,
    integrity_protections_offset: usize,
) -> Result<ExtentTier0IntegrityState, NvFsError>
where
    NvFsError: convert::From<E::BackendIteratorError>,
{
    // The primary commit_id + xor_mask must be into the realm of the tier 0
    // integrity protections, i.e. within the first 128B.
    if extent_head_skip > 128 - checksum::CHECKSUM_LEN as usize - 1
        || integrity_protections_offset > 128 - extent_head_skip - checksum::CHECKSUM_LEN as usize - 1
    {
        return Err(nvfs_err_internal!());
    }

    // Skip over extent_head_skip bytes, which could be a magic or similar.
    extent.skip(extent_head_skip).map_err(|e| match e {
        io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
        io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
            io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
        },
    })?;

    // Check if any of the bytes in the tier0 protection domain up to
    // integrity_protections_offset is zero and if any is non-zero.
    let mut any_zero = false;
    let mut any_nonzero = false;
    let mut region = (&mut extent).take_exact(integrity_protections_offset);
    while let Some(slice) = region.next_slice(None).map_err(|e| match e {
        io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
        io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
            io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
        },
    })? {
        debug_assert!(!slice.is_empty());
        let slice_any_zero = slice.contains(&0u8);
        any_zero |= slice_any_zero;
        let slice_all_zero = slice.iter().all(|b| *b == 0);
        any_nonzero |= !slice_all_zero;
    }

    // We're now at integrity_protections_offset. Extract the commit_id and the
    // xor_mask, which are stored at that location.
    let mut commit_id = [0u8; checksum::CHECKSUM_LEN as usize];
    io_slices::SingletonIoSliceMut::new(&mut commit_id)
        .map_infallible_err()
        .copy_from_iter(&mut (&mut extent).take_exact(checksum::CHECKSUM_LEN as usize))
        .map_err(|e| match e {
            io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
            io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
            },
        })?;
    any_zero |= commit_id.contains(&0u8);
    any_nonzero |= !commit_id.iter().all(|b| *b == 0);
    let mut xor_mask = 0u8;
    io_slices::SingletonIoSliceMut::new(slice::from_mut(&mut xor_mask))
        .map_infallible_err()
        .copy_from_iter(&mut (&mut extent).take_exact(mem::size_of::<u8>()))
        .map_err(|e| match e {
            io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
            io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
            },
        })?;
    any_zero |= xor_mask == 0;
    any_nonzero |= xor_mask != 0;

    // Finally, check if any byte in the remainder of the tier0 integrity
    // protections realm is zero or nonzero.
    let mut region = (&mut extent)
        .take_exact(128usize - extent_head_skip - integrity_protections_offset - checksum::CHECKSUM_LEN as usize - 1);
    while let Some(slice) = region.next_slice(None).map_err(|e| match e {
        io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
        io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
            io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
        },
    })? {
        debug_assert!(!slice.is_empty());
        let slice_any_zero = slice.contains(&0u8);
        any_zero |= slice_any_zero;
        let slice_all_zero = slice.iter().all(|b| *b == 0);
        any_nonzero |= !slice_all_zero;
    }

    // If any of the bytes in the tier0 integrity protection realm has been found
    // zero, this indicates a torn write -- the xor_mask is chosen such that all
    // bytes would be non-zero. If any of the bytes is non-zero, then a clear
    // before the next update of the extent's head (device) IO Block
    // will be needed.
    Ok(ExtentTier0IntegrityState {
        commit_id,
        xor_mask,
        is_valid: !any_zero,
        need_clear: any_nonzero,
    })
}

/// Verify and remove an extent's tier 0 integrity protections.
///
/// On success, a pair of a bool representing verification success and the
/// [`ExtentTier0IntegrityState`] is returned.
///
/// On verification success, the tier 0 integrity protection will get removed,
/// and the `extent`'s first 128B (outside the integrity protections data
/// region) will be at their final values.
///
/// Reasons to remove the tier 0 integrity protections explicitly first would
/// include a case where the `io_block_allocation_blocks_log2` and
/// `allocation_block_size_128b_log2` arguments needed as input to the full
/// [`extent_integrity_protections_determine_state()`] or
/// [`extent_integrity_protections_verify_and_remove()`] are themselves stored
/// within the tier 0 protection realm, i.e. within the extent's first 128B.
///
/// # Arguments:
///
/// * `extent` - The extent's contents. Needs to cover only the first 128B.
/// * `extent_head_skip` - Amount of head space exempt from the integrity
///   protection.
/// * `integrity_protections_offset` - Offset relative to `extent_head_skip`
///   where the integrity protections data is stored within the extent.
pub fn extent_tier0_integrity_protection_verify_and_remove<'a, E: io_slices::PeekableIoSlicesMutIter<'a>>(
    mut extent: E,
    extent_head_skip: usize,
    integrity_protections_offset: usize,
) -> Result<(bool, ExtentTier0IntegrityState), NvFsError>
where
    NvFsError: convert::From<E::BackendIteratorError>,
{
    // The primary commit_id + xor_mask must be into the realm of the tier 0
    // integrity protections, i.e. within the first 128B.
    if extent_head_skip > 128 - checksum::CHECKSUM_LEN as usize - 1
        || integrity_protections_offset > 128 - extent_head_skip - checksum::CHECKSUM_LEN as usize - 1
    {
        return Err(nvfs_err_internal!());
    }

    let extent_integrity_state = extent_tier0_integrity_protection_verify(
        extent.decoupled_borrow(),
        extent_head_skip,
        integrity_protections_offset,
    )?;
    if !extent_integrity_state.is_valid {
        return Ok((false, extent_integrity_state));
    }

    // Integrity check is successful. Remove the integrity protections.
    // - Xor the xor_mask into the [extent_head_skip..integrity_protections_offset]
    //   range.
    // - Clear the CHECKSUM_LEN + 1 bytes at integrity_protections_offset.
    // - Xor the xor_mask into the remainder, up to 128B.
    // Skip over extent_head_skip bytes, which could be a magic or similar.
    extent.skip(extent_head_skip).map_err(|e| match e {
        io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
        io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
            io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
        },
    })?;

    let mut region = (&mut extent).take_exact(integrity_protections_offset);
    while let Some(slice) = region.next_slice_mut(None).map_err(|e| match e {
        io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
        io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
            io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
        },
    })? {
        for b in slice.iter_mut() {
            *b ^= extent_integrity_state.xor_mask;
        }
    }

    let mut region = (&mut extent).take_exact(checksum::CHECKSUM_LEN as usize + 1);
    while let Some(slice) = region.next_slice_mut(None).map_err(|e| match e {
        io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
        io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
            io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
        },
    })? {
        slice.fill(0u8);
    }

    let mut region = (&mut extent)
        .take_exact(128 - extent_head_skip - integrity_protections_offset - checksum::CHECKSUM_LEN as usize - 1);
    while let Some(slice) = region.next_slice_mut(None).map_err(|e| match e {
        io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
        io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
            io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
        },
    })? {
        for b in slice.iter_mut() {
            *b ^= extent_integrity_state.xor_mask;
        }
    }

    Ok((true, extent_integrity_state))
}

/// Apply tier 0 integrity protection to an extent.
///
/// Apply tier 0 integrity protection to `extent`, and return a tier 1 commit
/// id derived from the `checksum`, to forward to a subsequent
/// [`extent_tier1_integrity_protection_write_checkpoint_locations_markers()`].
///
/// # Arguments:
///
/// * `extent` - The extent's buffers.  Needs to cover only the first 128B.
/// * `extent_head_skip` - Amount of head space exempt from the integrity
///   protection.
/// * `integrity_protections_offset` - Offset relative to `extent_head_skip`
///   where the integrity protections data is stored within the extent.
/// * `checksum` - Checksum over the extent's data, with the integrity
///   protections data area all zero. May be obtained from a prior call to
///   [`extent_tier1_integrity_protection_save_checkpoint_locations_data()`].
/// * `last_commit_ids_tails` - Value of
///   [`ExtentIntegrityState::last_commit_ids_tails`].
///
/// # See also:
///
/// * [`extent_tier1_integrity_protection_save_checkpoint_locations_data()`].
/// * [`extent_tier1_integrity_protection_write_checkpoint_locations_markers()`].
fn extent_tier0_integrity_protection_apply<'a, E: io_slices::MutPeekableIoSlicesMutIter<'a>>(
    mut extent: E,
    extent_head_skip: usize,
    integrity_protections_offset: usize,
    checksum: [u8; checksum::CHECKSUM_LEN as usize],
    mut last_commit_ids_tails: [[u8; 2]; 2],
) -> Result<[u8; checksum::CHECKSUM_LEN as usize], NvFsError>
where
    NvFsError: convert::From<E::BackendIteratorError>,
{
    // The primary commit_id + xor_mask must be into the realm of the tier 0
    // integrity protections, i.e. within the first 128B.
    if extent_head_skip > 128 - checksum::CHECKSUM_LEN as usize - 1
        || integrity_protections_offset > 128 - extent_head_skip - checksum::CHECKSUM_LEN as usize - 1
    {
        return Err(nvfs_err_internal!());
    }

    // Skip over extent_head_skip bytes, which could be a magic or similar.
    extent.skip(extent_head_skip).map_err(|e| match e {
        io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
        io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
            io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
        },
    })?;

    // Choose a xor_mask to get xored into the [extent_head_skip..128] region such
    // that
    // - no byte will be zero,
    // - such that the commit_id, which is the checksum xored with xor_mask, will
    //   have tail bytes different from the on in last_commit_ids_tails[].
    // Note that the commit_id and the xor_mask will subsequently get stored at
    // offset integrity_protections_offset, so ignore that that region in the
    // search for xor_mask now.
    let region0 = extent.decoupled_borrow().take_exact(integrity_protections_offset);
    let mut region1 = extent.decoupled_borrow().take_exact(128 - extent_head_skip);
    region1
        .skip(integrity_protections_offset + checksum::CHECKSUM_LEN as usize + 1)
        .map_err(|e| match e {
            io_slices::IoSlicesIterError::BackendIteratorError(io_slices::IoSlicesIterError::BackendIteratorError(
                e,
            )) => NvFsError::from(e),
            io_slices::IoSlicesIterError::IoSlicesError(e)
            | io_slices::IoSlicesIterError::BackendIteratorError(io_slices::IoSlicesIterError::IoSlicesError(e)) => {
                match e {
                    io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
                }
            }
        })?;

    last_commit_ids_tails[0][0] ^= checksum[0];
    last_commit_ids_tails[1][0] ^= checksum[0];
    last_commit_ids_tails[0][1] ^= checksum[checksum::CHECKSUM_LEN as usize - 1];
    last_commit_ids_tails[1][1] ^= checksum[checksum::CHECKSUM_LEN as usize - 1];

    let xor_mask = find_distinct_u8_value(
        region0
            .chain(region1)
            .chain(io_slices::SingletonIoSlice::new(checksum.as_slice()).map_infallible_err())
            .chain(
                io_slices::BuffersSliceIoSlicesIter::new(&[
                    last_commit_ids_tails[0].as_slice(),
                    last_commit_ids_tails[1].as_slice(),
                ])
                .map_infallible_err(),
            ),
    )
    .map_err(|e| match e {
        io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
        io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
            io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
        },
    })?;

    // Apply the xor_mask, writing the primary commit_id and the xor_mask itself to
    // their designated locations in the course.
    let mut region = (&mut extent).take_exact(integrity_protections_offset);
    while let Some(slice) = region.next_slice_mut(None).map_err(|e| match e {
        io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
        io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
            io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
        },
    })? {
        for b in slice.iter_mut() {
            *b ^= xor_mask;
        }
    }

    // The commit_id is obtained by xoring the checksum with the xor_mask.
    let mut commit_id = checksum;
    for b in commit_id.iter_mut() {
        *b ^= xor_mask;
    }
    debug_assert_ne!(commit_id[0], last_commit_ids_tails[0][0]);
    debug_assert_ne!(commit_id[0], last_commit_ids_tails[1][0]);
    debug_assert_ne!(
        commit_id[checksum::CHECKSUM_LEN as usize - 1],
        last_commit_ids_tails[0][1]
    );
    debug_assert_ne!(
        commit_id[checksum::CHECKSUM_LEN as usize - 1],
        last_commit_ids_tails[1][1]
    );
    (&mut extent)
        .take_exact(checksum::CHECKSUM_LEN as usize)
        .copy_from_iter(&mut io_slices::SingletonIoSlice::new(commit_id.as_slice()).map_infallible_err())
        .map_err(|e| match e {
            io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
            io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
            },
        })?;
    (&mut extent)
        .take_exact(mem::size_of::<u8>())
        .copy_from_iter(&mut io_slices::SingletonIoSlice::new(slice::from_ref(&xor_mask)).map_infallible_err())
        .map_err(|e| match e {
            io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
            io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
            },
        })?;

    let mut region = (&mut extent)
        .take_exact(128 - extent_head_skip - integrity_protections_offset - checksum::CHECKSUM_LEN as usize - 1);
    while let Some(slice) = region.next_slice_mut(None).map_err(|e| match e {
        io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
        io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
            io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
        },
    })? {
        for b in slice.iter_mut() {
            *b ^= xor_mask;
        }
    }

    Ok(commit_id)
}

/// Find a `u8` value disting from all others in a given set.
///
/// The returned `u8` value will be non-zero and distinct from any in `values`.
///
/// # Arguments:
///
/// * `values` - Iterator over the byte values to avoid. Must not yield more
///   than 254 distinct non-zero values.
fn find_distinct_u8_value<'a, V: io_slices::PeekableIoSlicesIter<'a>>(
    mut values: V,
) -> Result<u8, V::BackendIteratorError> {
    // For each of the 16 possible 4bit value prefixes, count the number of
    // occurences in values[]. 256 = 16 * 16 and we're going to slot strictly
    // less than 256 values, so at least one of the 16 slot will receive less
    // than 16 values.
    let mut c = [0u8; 16];
    let mut peeking_values = values.decoupled_borrow();
    while let Some(slice) = peeking_values.next_slice(None)? {
        for v in slice {
            c[(v >> 4) as usize] += 1;
        }
    }
    drop(peeking_values);

    // 256 = 16 * 16 and we've slotted less than 256 values, so
    // at least one of the 16 slots must have received less than 16 values.
    let mut h = 0u8;
    while h < 16 {
        if c[h as usize] < 16 {
            break;
        }
        h += 1;
    }
    debug_assert!(h < 16);

    // By know, it is known that one of the 16 possible values with a 4bit prefix of
    // h is not among the input values[] set. Figure out which, this time by
    // counting occurences of suffixes.
    let mut c = [0u8; 16];
    // Avoid returning a zero byte.
    if h == 0 {
        c[0] = 1;
    }
    while let Some(slice) = values.next_slice(None)? {
        for v in slice {
            if v >> 4 == h {
                c[(v & 0xfu8) as usize] += 1;
            }
        }
    }

    let mut l = 0u8;
    while l < 16 {
        if c[l as usize] == 0 {
            break;
        }
        l += 1;
    }
    debug_assert!(l < 16);

    Ok((h << 4) | l)
}

/// An extent's known integrity protections state on storage.
///
/// An `ExtentIntegrityState` instance tracks the information about a given
/// extent's storage state required to apply integrity protections to a
/// subsequent update. That is, it's required input to
/// [`extent_integrity_protections_apply()`].
///
/// Typically, the initial state on storage is determined either
/// - through [`extent_integrity_protections_determine_state()`] or
///   [`extent_integrity_protections_verify_and_remove()`], or
/// - by moving it into a well-defined state, i.e. by clearing the extent's
///   first [device IO Block](NvBlkDev::io_block_size_128b_log2) on storage, and
///   obtaining a corresponding `ExtentIntegrityState` instance from
///   [`new_clean()`](Self::new_clean).
///
/// As the extent gets subsequently written to on storage, its corresponding
/// `ExtentIntegrityState` instance may get updated accordingly to reflect the
/// changes. See e.g. [`extent_integrity_protections_apply()`],
/// [`record_clear()`](Self::record_clear) and
/// [`record_failed_write()`](Self::record_failed_write).
///
/// # See also:
///
/// * [`extent_integrity_protections_determine_state()`].
/// * [`extent_integrity_protections_verify_and_remove()`].
/// * [`extent_integrity_protections_apply()`].
#[derive(Clone, Copy, Debug)]
pub struct ExtentIntegrityState {
    /// Whether the extent's first [device IO
    /// Block](NvBlkDev::io_block_size_128b_log2) must get cleared before
    /// its next update in order to maintain torn write detection capabilities
    /// for the tier 0 integrity protection realm.
    ///
    /// `false` only if all bytes in the tier 0 integrity protection domain,
    /// i.e. within the extent's first 128B are known to be zero.
    ///
    /// `!tier0_need_clear` implies
    /// [`!need_clear_for_coherence`](Self::need_clear_for_coherence).
    tier0_need_clear: bool,

    /// Whether the extent's first [device IO
    /// Block](NvBlkDev::io_block_size_128b_log2) must get cleared before
    /// its next update in order to maintain in order to maintain torn write
    /// detection capabilities for its overlap with the tier 1 integrity
    /// protection realm.
    ///
    /// Set to `true` only, when the
    /// [`last_commit_ids_tails`](Self::last_commit_ids_tails) gets exhausted,
    /// i.e. upon invoking [`record_failed_write()`](Self::record_failed_write)
    /// when there are no more [free
    /// slots](Self::last_commit_ids_tails_has_free_slot).
    ///
    /// Note that `tier1_need_clear` implies
    /// [`need_clear_for_coherence`](Self::need_clear_for_coherence), and is
    /// redundant. However, for code comprehensibility and maintainability
    /// it's kept separate.
    tier1_need_clear: bool,

    /// Whether the extent's first [device IO
    /// Block](NvBlkDev::io_block_size_128b_log2) must get cleared before
    /// updating any of the extent's tail in order to avoid coherence
    /// issues.
    ///
    /// Is `true` whenever the first [device IO
    /// Block](NvBlkDev::io_block_size_128b_log2) contents might be in a
    /// state that could possibly pass integrity protections verification.
    ///
    /// The following invariants hold:
    /// * `need_clear_for_coherence` implies
    ///   [`tier0_need_clear`](Self::tier0_need_clear): if
    ///   `need_clear_for_coherence` is set, then all of the bytes in the tier 0
    ///   integrity protection domain could be non-zero, otherwise the first
    ///   [device IO Block](NvBlkDev::io_block_size_128b_log2) cannot possibly
    ///   pass integrity protection verification.
    ///   [`tier0_need_clear`](Self::tier0_need_clear) is set whenever any of
    ///   those bytes might be non-zero.
    /// * [`tier1_need_clear`](Self::tier1_need_clear) implies
    ///   `need_clear_for_coherence`:
    ///   [`tier1_need_clear`](Self::tier1_need_clear) is flipped to `true` only
    ///   from [`record_failed_write()`](Self::record_failed_write).
    ///   `need_clear_for_coherence` is set to `true` unconditionally there.
    need_clear_for_coherence: bool,

    /// Commit ID tail byte values on storage.
    ///
    /// Up to two commit IDs' tail byte value's are stored, if different:
    /// - the ones from the primary location, within the tier 0 integrity
    ///   protection realm,
    /// - the ones from the checkpoint location at the end of the [device IO
    ///   Block](NvBlkDev::io_block_size_128b_log2), if there is any.
    ///
    /// `last_commit_ids_tails` is used for ensuring that the commit ID
    /// generated for the next update will be different in the tail values.
    last_commit_ids_tails: [[u8; 2]; 2],
}

impl ExtentIntegrityState {
    /// Instantiate a [`ExtentIntegrityState`] in indeterminate state.
    ///
    /// The [`ExtentIntegrityState`] may subsequently moved into a determinate
    /// state by clearing the associated extent's first [device IO
    /// Block](NvBlkDev::io_block_size_128b_log2) on storage and invoking
    /// [`record_clear()`](Self::record_clear) on it.
    ///
    /// # See also:
    ///
    /// * [`new_clean`](Self::new_clean).
    /// * [`extent_integrity_protections_determine_state()`].
    /// * [`extent_integrity_protections_verify_and_remove()`].
    pub const fn new_indeterminate() -> Self {
        // Indefinite state, force Self::need_clear() to report 'true'.
        Self {
            tier0_need_clear: true,
            tier1_need_clear: true,
            need_clear_for_coherence: true,
            last_commit_ids_tails: [[u8::MAX, u8::MAX], [u8::MAX, u8::MAX]],
        }
    }

    /// Convenience helper to instantiate an [`ExtentIntegrityState`] for a
    /// storage extent known a priori to be in a clean state.
    ///
    /// Semantically equivalent to obtaining an [`ExtentIntegrityState`] from
    /// [`new_indeterminate()`](Self::new_indeterminate) and invoking
    /// [`record_clear()`](Self::record_clear) on it.
    pub const fn new_clean() -> Self {
        Self {
            tier0_need_clear: false,
            tier1_need_clear: false,
            need_clear_for_coherence: false,
            last_commit_ids_tails: [[0u8, 0u8], [0u8, 0u8]],
        }
    }

    /// Whether the extent's first [device IO
    /// Block](NvBlkDev::io_block_size_128b_log2) must get cleared before any
    /// subsequent update to extent.
    ///
    /// If `need_clear()` returns true, then the extent's first [device IO
    /// Block](NvBlkDev::io_block_size_128b_log2) must get cleared before
    /// any write to anywhere within the protected extent.
    ///
    /// `need_clear()` implies [`tier0_need_clear()`](Self::tier0_need_clear),
    /// but not vice-versa. That is, if
    /// [`extent_tier0_integrity_protection_verify_and_remove()`] could
    /// possibly be relied upon for the extent in question, then
    /// [`tier0_need_clear()`](Self::tier0_need_clear) must be used instead.
    ///
    /// # Arguments:
    ///
    /// * `_extent_head_skip` - Amount of head space exempt from the integrity
    ///   protection.
    /// * `integrity_protections_offset` - Offset relative to `extent_head_skip`
    ///   where the integrity protections are stored within the extent.
    /// * `blkdev_io_block_size_128b_log2` - Value of
    ///   [`NvBlkDev::io_block_size_128b_log2()`].
    ///
    /// # See also:
    ///
    /// * [`extent_integrity_protections_apply()`]
    /// * [`tier0_need_clear()`](Self::tier0_need_clear).
    /// * [`ExtentIntegrityProtectionsInvalidateFuture`].
    pub fn need_clear(
        &self,
        _extent_head_skip: usize,
        integrity_protections_offset: usize,
        blkdev_io_block_size_128b_log2: u32,
    ) -> bool {
        // If the first device IO Block is possibly in a state that would
        // pass integrity protections verification, then it must be cleared
        // before any subsequent update of the extent's tail in order to avoid
        // coherence issues.
        if self.need_clear_for_coherence {
            // need_clear_for_coherence implies tier0_need_clear.
            debug_assert!(self.tier0_need_clear);
            return true;
        }

        // If all of extent_head_skip..128 is zero, then the tier 0 integrity
        // protections is ready for another update.
        if !self.tier0_need_clear {
            // If all of extent_head_skip..128 is zero, then at least one
            // of the last_commit_ids slots is free.
            debug_assert!(self.last_commit_ids_tails_has_free_slot());
            return false;
        }

        // The tier 0 integrity protection domain has some non-zero bytes in it,
        // so it cannot be relied upon for protecting the next update.
        // Check if perhaps the tier 1 is sufficient.
        if self.tier1_need_clear {
            // It's not, the commit IDs recored in last_commit_ids[] don't fully reflect
            // the device IO Block's state anymore.
            return true;
        } else if blkdev_io_block_size_128b_log2 == 0 {
            // There are no tier 1 write completion checkpoint locations within the first
            // device IO Block, hence the tier 1 integrity protections are insufficient.
            return true;
        } else if integrity_protections_offset != 0 {
            // The primary commit ID (stored within the tier 0 integrity protection realm)
            // and the commit ID stored at the write checkpoint location at the
            // end of the device IO Block boundary do not cover all the
            // protected data -- there's some located before the former.
            return true;
        }

        false
    }

    /// Whether the extent's first [device IO
    /// Block](NvBlkDev::io_block_size_128b_log2) must get cleared before a
    /// subsequent update in order to maintain torn write detection capabilities
    /// for the tier 0 integrity protection realm, i.e. for the extents first
    /// 128B.
    ///
    /// `!tier0_need_clear()` implies [`!need_clear()`](Self::need_clear). That
    /// is, `tier0_need_clear()` is stricter and must be used instead if
    /// [`extent_tier0_integrity_protection_verify_and_remove()`] could possibly
    /// be relied upon for the extent in question.
    ///
    /// # See also:
    ///
    /// * [`extent_tier0_integrity_protection_verify_and_remove()`].
    /// * [`tier0_need_clear()`](Self::tier0_need_clear).
    #[allow(unused)]
    pub fn tier0_need_clear(&self) -> bool {
        // need_clear_for_coherence implies tier0_need_clear,
        // therefore, if !tier0_need_clear() implies !need_clear().
        debug_assert!(self.tier0_need_clear || !self.need_clear_for_coherence);
        self.tier0_need_clear
    }

    /// Record a clear operation.
    ///
    /// Update the `ExtentIntegrityState` to reflect that the associated
    /// extent's first [device IO Block](NvBlkDev::io_block_size_128b_log2)
    /// had been cleared on storage.
    ///
    /// # See also:
    ///
    /// * [`ExtentIntegrityProtectionsInvalidateFuture`].
    pub fn record_clear(&mut self) {
        *self = Self {
            tier0_need_clear: false,
            tier1_need_clear: false,
            need_clear_for_coherence: false,
            last_commit_ids_tails: [[0, 0], [0, 0]],
        }
    }

    /// Record a failed attempt to write to the extent.
    ///
    /// Update the [`ExtentIntegrityState`] to reflect the fact that an attempt
    /// to write to associated extent's first [device IO
    /// Block](NvBlkDev::io_block_size_128b_log2) has failed.
    ///
    /// For clarity: `record_failed_write()` is not supposed to get invoked upon
    /// failed clear operations, i.e. failed attempts to clear the
    /// associated extent's first [device IO
    /// Block](NvBlkDev::io_block_size_128b_log2) shall not be recorded in
    /// any way.
    ///
    /// # Arguments:
    ///
    /// * `torn_integrity_state` - The [`ExtentIntegrityState`] returned from
    ///   the [`extent_integrity_protections_apply()`] invocation associated
    ///   with the update.
    pub fn record_failed_write(&mut self, torn_integrity_state: &Self) {
        debug_assert!(torn_integrity_state.last_commit_ids_tails_has_free_slot());
        self.tier0_need_clear = true;
        // The first device IO Block's contents can be in any state now, including one
        // that might pass integrity protection validation.
        // To avoid coherence issues, it must be cleared before subsequently attempting
        // to write to the extent's tail.
        self.need_clear_for_coherence = true;
        // The attempt to write to the first device IO Block with an updated
        // ExtentIntegrityState of 'torn_integrity_state' failed, i.e. there had
        // been a torn write. It's unknown what the contents of the commit_id at
        // the primary locations or at the checkpoint location at the
        // device IO Block are on storage now. The exact behavior depends on the
        // hardware, but assume that there is a pivot point partitioning the
        // device IO Block into an all-new and an all-old region respectively.
        // Simply record the failed commit_id write, which might or
        // might not have been written somewhere at the free slot in
        // self.last_commit_ids. The next commit_id to be generated for a
        // subsequent update attempt will be different from either.
        if self.last_commit_ids_tails_has_free_slot() {
            self.last_commit_ids_tails[1] = torn_integrity_state.last_commit_ids_tails[0];
        } else {
            // There's no spare entry in last_commit_ids_tails[] for recording yet another
            // commit ID candidate, force a reset to bring everything back into a known
            // state.
            self.tier1_need_clear = true;
        }
    }

    /// Check if [`last_commit_ids_tails`](Self::last_commit_ids_tails) has a
    /// free slot.
    fn last_commit_ids_tails_has_free_slot(&self) -> bool {
        self.last_commit_ids_tails[1] == [0, 0]
    }
}

/// Determine an extent's tier 1 integrity protection state.
///
/// Starting out from an already determined tier 0 integrity protection state,
/// i.e. an [`ExtentTier0IntegrityState`] instance, determine the `extent`s tier
/// 1 integrity state and return the combined result as a
/// [`ExtentIntegrityState`].
///
/// The tier 0 integrity protection may or may not have been removed from
/// `extent` prior to calling this function.
///
/// # Arguments:
///
/// * `extent` - The extent's contents. Needs to cover only the first [device IO
///   Block](NvBlkDev::io_block_size_128b_log2).
/// * `extent_head_skip` - Amount of head space exempt from the integrity
///   protection.
/// * `integrity_protections_offset` - Offset relative to `extent_head_skip`
///   where the integrity protections are stored within the extent.
/// * `extent_tier0_integrity_state` - The extent's tier 0 integrity protection
///   state, as returned either directly from
///   [`extent_tier0_integrity_protection_verify()`] or from
///   [`extent_tier0_integrity_protection_verify_and_remove()`] .
/// * `io_block_allocation_blocks_log2` - Verbatim value of
///   [`ImageLayout::io_block_allocation_blocks_log2`].
/// * `allocation_block_size_128b_log2` - Verbatim value of
///   [`ImageLayout::allocation_block_size_128b_log2`].
/// * `blkdev_io_block_size_128b_log2` - Value of
///   [`NvBlkDev::io_block_size_128b_log2()`].
fn extent_tier1_integrity_protection_determine_state<'a, E: io_slices::IoSlicesIter<'a>>(
    mut extent: E,
    extent_head_skip: usize,
    integrity_protections_offset: usize,
    extent_tier0_integrity_state: &ExtentTier0IntegrityState,
    io_block_allocation_blocks_log2: u8,
    allocation_block_size_128b_log2: u8,
    blkdev_io_block_size_128b_log2: u32,
) -> Result<ExtentIntegrityState, NvFsError>
where
    NvFsError: convert::From<E::BackendIteratorError>,
{
    // The primary commit_id + xor_mask must be into the realm of the tier 0
    // integrity protections, i.e. within the first 128B.
    if extent_head_skip > 128 - checksum::CHECKSUM_LEN as usize - 1
        || integrity_protections_offset > 128 - extent_head_skip - checksum::CHECKSUM_LEN as usize - 1
    {
        return Err(nvfs_err_internal!());
    }

    // If the tier 0 protection verification would fail, then the first device IO
    // Block is invalid, and an explicit invalidation prior to future updates
    // for avoiding potential coherence issues is not needed.
    let mut extent_integrity_state = ExtentIntegrityState {
        tier0_need_clear: extent_tier0_integrity_state.need_clear,
        tier1_need_clear: false,
        need_clear_for_coherence: extent_tier0_integrity_state.is_valid,
        last_commit_ids_tails: [
            [
                extent_tier0_integrity_state.commit_id[0],
                extent_tier0_integrity_state.commit_id[checksum::CHECKSUM_LEN as usize - 1],
            ],
            [0u8, 0u8],
        ],
    };

    // The primary commit ID is stored within the tier 0 protection realm.
    debug_assert!(extent_integrity_state.last_commit_ids_tails[0] != [0, 0] || !extent_tier0_integrity_state.is_valid);

    // If the device IO Block size is > 128B, then extract the commit ID copy found
    // at its end boundary as well.
    debug_assert!(
        blkdev_io_block_size_128b_log2
            <= io_block_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32
    );
    if blkdev_io_block_size_128b_log2 != 0 {
        let mut checkpoint_location_marker = [0u8; checksum::CHECKSUM_LEN as usize];
        extent
            .skip((1usize << (blkdev_io_block_size_128b_log2 + 7)) - checksum::CHECKSUM_LEN as usize)
            .map_err(|e| match e {
                io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
                io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                    io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
                },
            })?;
        io_slices::SingletonIoSliceMut::new(&mut checkpoint_location_marker)
            .map_infallible_err()
            .copy_from_iter(&mut extent.take_exact(checksum::CHECKSUM_LEN as usize))
            .map_err(|e| match e {
                io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
                io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                    io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
                },
            })?;
        extent_integrity_state.last_commit_ids_tails[1] = [
            checkpoint_location_marker[0],
            checkpoint_location_marker[checksum::CHECKSUM_LEN as usize - 1],
        ];

        // Canonicalize.
        if extent_integrity_state.last_commit_ids_tails[0] == [0, 0] {
            debug_assert!(!extent_tier0_integrity_state.is_valid);
            debug_assert!(!extent_integrity_state.need_clear_for_coherence);
            extent_integrity_state.last_commit_ids_tails[0] = extent_integrity_state.last_commit_ids_tails[1];
            extent_integrity_state.last_commit_ids_tails[1] = [0, 0];
        } else if extent_integrity_state.last_commit_ids_tails[0] == extent_integrity_state.last_commit_ids_tails[1] {
            extent_integrity_state.last_commit_ids_tails[1] = [0, 0];
        } else {
            // The tier 1 protections would fail to verify the first device IO Block, i.e.
            // the first device IO Block is in invalid state. An explicit
            // invalidation prior to future updates for avoiding coherence
            // issues is not needed.
            extent_integrity_state.need_clear_for_coherence = false;
        }
    }

    Ok(extent_integrity_state)
}

/// Verify and remove an extent's tier 1 integrity protections.
///
/// Tier 0 integrity protections must have already been verified and removed
/// through [`extent_tier0_integrity_protection_verify_and_remove()`] upon entry
/// to this function.
///
/// On success, a pair of a bool representing verification success and the
/// [`ExtentIntegrityState`] is returned.
///
/// On verification success, the tier 1 integrity protection will get removed,
/// and the `extent`'s contents  will be at their final values. The integrity
/// protections data region within it will be all-zero.
///
/// # Arguments:
///
/// * `extent` - The extent's contents. Needs to cover only the first [IO
///   Block](ImageLayout::io_block_allocation_blocks_log2).
/// * `extent_head_skip` - Amount of head space exempt from the integrity
///   protection.
/// * `integrity_protections_offset` - Offset relative to `extent_head_skip`
///   where the integrity protections are stored within the extent.
/// * `extent_tier0_integrity_state` - The extent's tier 0 integrity protection
///   state, as returned from the prior call to
///   [`extent_tier0_integrity_protection_verify_and_remove()`].
/// * `io_block_allocation_blocks_log2` - Verbatim value of
///   [`ImageLayout::io_block_allocation_blocks_log2`].
/// * `allocation_block_size_128b_log2` - Verbatim value of
///   [`ImageLayout::allocation_block_size_128b_log2`].
/// * `blkdev_io_block_size_128b_log2` - Value of
///   [`NvBlkDev::io_block_size_128b_log2()`].
fn extent_tier1_integrity_protection_verify_and_remove<'a, E: io_slices::MutPeekableIoSlicesMutIter<'a>>(
    mut extent: E,
    extent_head_skip: usize,
    integrity_protections_offset: usize,
    extent_tier0_integrity_state: &ExtentTier0IntegrityState,
    io_block_allocation_blocks_log2: u8,
    allocation_block_size_128b_log2: u8,
    blkdev_io_block_size_128b_log2: u32,
) -> Result<(bool, ExtentIntegrityState), NvFsError>
where
    NvFsError: convert::From<E::BackendIteratorError>,
{
    // The primary commit_id + xor_mask must be into the realm of the tier 0
    // integrity protections, i.e. within the first 128B.
    if extent_head_skip > 128 - checksum::CHECKSUM_LEN as usize - 1
        || integrity_protections_offset > 128 - extent_head_skip - checksum::CHECKSUM_LEN as usize - 1
    {
        return Err(nvfs_err_internal!());
    }

    // Prepare the return value.
    let extent_integrity_state = extent_tier1_integrity_protection_determine_state(
        extent.decoupled_borrow(),
        extent_head_skip,
        integrity_protections_offset,
        extent_tier0_integrity_state,
        io_block_allocation_blocks_log2,
        allocation_block_size_128b_log2,
        blkdev_io_block_size_128b_log2,
    )?;

    // Verify the checkpoint locations markers and restore the data from the save
    // area. Clear out the save area in the course.
    let checkpoint_locations_data_save_area_begin =
        extent_head_skip + integrity_protections_offset + checksum::CHECKSUM_LEN as usize + 1;
    debug_assert!(checkpoint_locations_data_save_area_begin <= 128);
    // The IO Block size in units of Bytes is assumed to fit an usize, so the same
    // applies to the log2 applied to this value in units of 128B multiples.
    debug_assert!((io_block_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32) < usize::BITS - 7);
    let checkpoint_locations_data_save_area_len =
        (io_block_allocation_blocks_log2 + allocation_block_size_128b_log2) as usize * checksum::CHECKSUM_LEN as usize;
    // Does not overflow, checkpoint_locations_data_save_area_begin <= 128, as
    // verified above.
    let checkpoint_locations_data_save_area_end =
        checkpoint_locations_data_save_area_begin + checkpoint_locations_data_save_area_len;
    debug_assert!(
        checkpoint_locations_data_save_area_end
            <= 1usize << (io_block_allocation_blocks_log2 + allocation_block_size_128b_log2 + 7)
    );

    for i in 1..=(io_block_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32) {
        let checkpoint_locations_data_save_area_entry_begin =
            checkpoint_locations_data_save_area_begin + (checksum::CHECKSUM_LEN as usize) * ((i - 1) as usize);
        let checkpoint_location_end = 1usize << (i + 7);

        let mut peeking_extent = extent.decoupled_borrow_mut();
        // Recover the saved checkpoint location data and clear out the data save area
        // entry.
        peeking_extent
            .skip(checkpoint_locations_data_save_area_entry_begin)
            .map_err(|e| match e {
                io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
                io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                    io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
                },
            })?;
        let mut checkpoint_location_data = [0u8; checksum::CHECKSUM_LEN as usize];
        let mut checkpoint_locations_data_save_area_entry = peeking_extent
            .decoupled_borrow_mut()
            .take_exact(checksum::CHECKSUM_LEN as usize);
        io_slices::SingletonIoSliceMut::new(&mut checkpoint_location_data)
            .map_infallible_err()
            .copy_from_iter(&mut checkpoint_locations_data_save_area_entry.decoupled_borrow())
            .map_err(|e| match e {
                io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
                io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                    io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
                },
            })?;
        while let Some(slice) = checkpoint_locations_data_save_area_entry
            .next_slice_mut(None)
            .map_err(|e| match e {
                io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
                io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                    io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
                },
            })?
        {
            slice.fill(0u8);
        }
        drop(checkpoint_locations_data_save_area_entry);

        // Verify that the checkpoint location contains the commit_id marker value
        // and write the recovered data to it.
        peeking_extent
            .skip(
                checkpoint_location_end
                    - checksum::CHECKSUM_LEN as usize
                    - checkpoint_locations_data_save_area_entry_begin,
            )
            .map_err(|e| match e {
                io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
                io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                    io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
                },
            })?;
        let mut checkpoint_location_marker = [0u8; checksum::CHECKSUM_LEN as usize];
        io_slices::SingletonIoSliceMut::new(&mut checkpoint_location_marker)
            .map_infallible_err()
            .copy_from_iter(
                &mut peeking_extent
                    .decoupled_borrow()
                    .take_exact(checksum::CHECKSUM_LEN as usize),
            )
            .map_err(|e| match e {
                io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
                io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                    io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
                },
            })?;
        if checkpoint_location_marker != extent_tier0_integrity_state.commit_id {
            // Mismatch, indicating a torn write.
            return Ok((false, extent_integrity_state));
        }
        // Restore the recovered checkpoint location data.
        (&mut peeking_extent)
            .take_exact(checksum::CHECKSUM_LEN as usize)
            .copy_from_iter(&mut io_slices::SingletonIoSlice::new(&checkpoint_location_data).map_infallible_err())
            .map_err(|e| match e {
                io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
                io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                    io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
                },
            })?;
        drop(peeking_extent);
    }

    // The integrity protections have been removed and the extent is in its original
    // form.  Note that all extent_integrity_protections_len() bytes at
    // integrity_protections_offset have been set to zero now. Verify the
    // checksum in a final step. Recover the expected checksum from the
    // commit_id.
    let mut expected_checksum = extent_tier0_integrity_state.commit_id;
    for b in expected_checksum.iter_mut() {
        *b ^= extent_tier0_integrity_state.xor_mask;
    }
    let mut checksum = checksum::ChecksumInstance::new();
    while let Some(slice) = extent.next_slice(None).map_err(NvFsError::from)? {
        checksum.update(slice);
    }

    Ok((checksum.finish_receive(&expected_checksum), extent_integrity_state))
}

/// Save away the data at the tier 1 integrity protection write completion
/// checkpoints to the designated save area.
///
/// Returns the checksum over the extent's data, with the integrity
/// protections data area all zero.
///
/// Must get invoked in a first step prior to writing the commit ID, which is to
/// be derived by [`extent_tier0_integrity_protection_apply()`] from the
/// returned checksum, to the respective tier 1 integrity protection write
/// completion checkpoints in order to save away their data.
///
/// # Arguments:
///
/// * `extent` - The extent's buffers.
/// * `extent_head_skip` - Amount of head space exempt from the integrity
///   protection.
/// * `integrity_protections_offset` - Offset relative to `extent_head_skip`
///   where the integrity protections data is stored within the extent.
/// * `io_block_allocation_blocks_log2` - Verbatim value of
///   [`ImageLayout::io_block_allocation_blocks_log2`].
/// * `allocation_block_size_128b_log2` - Verbatim value of
///   [`ImageLayout::allocation_block_size_128b_log2`].
///
/// # See also:
///
/// * [`extent_tier0_integrity_protection_apply()`]
/// * [`extent_tier1_integrity_protection_write_checkpoint_locations_markers()`].
fn extent_tier1_integrity_protection_save_checkpoint_locations_data<'a, E: io_slices::MutPeekableIoSlicesMutIter<'a>>(
    mut extent: E,
    extent_head_skip: usize,
    integrity_protections_offset: usize,
    io_block_allocation_blocks_log2: u8,
    allocation_block_size_128b_log2: u8,
) -> Result<[u8; checksum::CHECKSUM_LEN as usize], NvFsError>
where
    NvFsError: convert::From<E::BackendIteratorError>,
{
    // The primary commit_id + xor_mask must be into the realm of the tier 0
    // integrity protections, i.e. within the first 128B.
    if extent_head_skip > 128 - checksum::CHECKSUM_LEN as usize - 1
        || integrity_protections_offset > 128 - extent_head_skip - checksum::CHECKSUM_LEN as usize - 1
    {
        return Err(nvfs_err_internal!());
    }

    let checkpoint_locations_data_save_area_begin =
        extent_head_skip + integrity_protections_offset + checksum::CHECKSUM_LEN as usize + 1;
    debug_assert!(checkpoint_locations_data_save_area_begin <= 128);
    // The IO Block size in units of Bytes is assumed to fit an usize, so the same
    // applies to the log2 applied to this value in units of 128B multiples.
    debug_assert!((io_block_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32) < usize::BITS - 7);
    let checkpoint_locations_data_save_area_len =
        (io_block_allocation_blocks_log2 + allocation_block_size_128b_log2) as usize * checksum::CHECKSUM_LEN as usize;
    // Does not overflow, checkpoint_locations_data_save_area_begin <= 128, as
    // verified above.
    let checkpoint_locations_data_save_area_end =
        checkpoint_locations_data_save_area_begin + checkpoint_locations_data_save_area_len;
    debug_assert!(
        checkpoint_locations_data_save_area_end
            <= 1usize << (io_block_allocation_blocks_log2 + allocation_block_size_128b_log2 + 7)
    );

    // Compute the checksum. The region storing the integrity protections
    // will all be cleared beforehand.
    let mut checksum = checksum::ChecksumInstance::new();
    let mut peeking_extent = extent.decoupled_borrow_mut();
    // First do the region up to integrity_protections_offset.
    let mut region = (&mut peeking_extent).take_exact(extent_head_skip + integrity_protections_offset);
    while let Some(slice) = region.next_slice(None).map_err(|e| match e {
        io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
        io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
            io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
        },
    })? {
        checksum.update(slice);
    }
    // Process the region storing the integrity protections.
    let mut region =
        (&mut peeking_extent).take_exact(checksum::CHECKSUM_LEN as usize + 1 + checkpoint_locations_data_save_area_len);
    while let Some(slice) = region.next_slice_mut(None).map_err(|e| match e {
        io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
        io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
            io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
        },
    })? {
        slice.fill(0u8);
        checksum.update(slice);
    }
    // And finally checksum *all* of the extent's remainder.
    while let Some(slice) = peeking_extent.next_slice(None)? {
        checksum.update(slice);
    }
    drop(peeking_extent);
    let checksum = checksum.finish_send();

    // Copy the data from the checkpoint locations to the respective checkpoint
    // locations data save area slot. Do it in reverse order, to support
    // the case that the checkpoint locations data save area overlaps with
    // one of the checkpoint locations.
    for i in (1..=(io_block_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32)).rev() {
        let checkpoint_location_end = 1usize << (i + 7);
        let mut peeking_extent = extent.decoupled_borrow();
        peeking_extent
            .skip(checkpoint_location_end - checksum::CHECKSUM_LEN as usize)
            .map_err(|e| match e {
                io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
                io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                    io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
                },
            })?;
        let mut checkpoint_location_data = [0u8; checksum::CHECKSUM_LEN as usize];
        io_slices::SingletonIoSliceMut::new(&mut checkpoint_location_data)
            .map_infallible_err()
            .copy_from_iter(&mut peeking_extent.take_exact(checksum::CHECKSUM_LEN as usize))
            .map_err(|e| match e {
                io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
                io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                    io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
                },
            })?;

        let checkpoint_locations_data_save_area_entry_begin =
            checkpoint_locations_data_save_area_begin + (checksum::CHECKSUM_LEN as usize) * ((i - 1) as usize);
        let mut peeking_extent = extent.decoupled_borrow_mut();
        peeking_extent
            .skip(checkpoint_locations_data_save_area_entry_begin)
            .map_err(|e| match e {
                io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
                io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                    io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
                },
            })?;
        peeking_extent
            .take_exact(checksum::CHECKSUM_LEN as usize)
            .copy_from_iter(&mut io_slices::SingletonIoSlice::new(&checkpoint_location_data).map_infallible_err())
            .map_err(|e| match e {
                io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
                io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                    io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
                },
            })?;
    }

    Ok(checksum)
}

/// Write the commit ID to the respective tier 1 integrity protection write
/// completion checkpoint locations.
///
/// Must get called only after the checkpoint locations' original data has been
/// saved to their designated entry in the integrity protections data area, i.e.
/// after [`extent_tier1_integrity_protection_save_checkpoint_locations_data()`].
///
/// # Arguments:
///
/// * `extent` - The extent's contents. Needs to cover only the first [IO
///   Block](ImageLayout::io_block_allocation_blocks_log2).
/// * `extent_head_skip` - Amount of head space exempt from the integrity
///   protection.
/// * `integrity_protections_offset` - Offset relative to `extent_head_skip`
///   where the integrity protections are stored within the extent.
/// * `commit_id` - The tier 1 commit ID, as obtained from
///   [`extent_tier0_integrity_protection_apply()`].
/// * `io_block_allocation_blocks_log2` - Verbatim value of
///   [`ImageLayout::io_block_allocation_blocks_log2`].
/// * `allocation_block_size_128b_log2` - Verbatim value of
///   [`ImageLayout::allocation_block_size_128b_log2`].
///
/// # See also:
///
/// * [`extent_tier1_integrity_protection_save_checkpoint_locations_data()`].
/// * [`extent_tier0_integrity_protection_apply()`].
fn extent_tier1_integrity_protection_write_checkpoint_locations_markers<'a, E: io_slices::IoSlicesMutIter<'a>>(
    mut extent: E,
    extent_head_skip: usize,
    integrity_protections_offset: usize,
    commit_id: [u8; checksum::CHECKSUM_LEN as usize],
    io_block_allocation_blocks_log2: u8,
    allocation_block_size_128b_log2: u8,
) -> Result<(), NvFsError>
where
    NvFsError: convert::From<E::BackendIteratorError>,
{
    // The primary commit_id + xor_mask must be into the realm of the tier 0
    // integrity protections, i.e. within the first 128B.
    if extent_head_skip > 128 - checksum::CHECKSUM_LEN as usize - 1
        || integrity_protections_offset > 128 - extent_head_skip - checksum::CHECKSUM_LEN as usize - 1
    {
        return Err(nvfs_err_internal!());
    }

    if io_block_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32 == 0 {
        return Ok(());
    }

    extent.skip(128).map_err(|e| match e {
        io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
        io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
            io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
        },
    })?;

    for i in 1..=(io_block_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32) {
        extent
            .skip((1usize << (i - 1 + 7)) - checksum::CHECKSUM_LEN as usize)
            .map_err(|e| match e {
                io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
                io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                    io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
                },
            })?;
        (&mut extent)
            .take_exact(checksum::CHECKSUM_LEN as usize)
            .copy_from_iter(&mut io_slices::SingletonIoSlice::new(&commit_id).map_infallible_err())
            .map_err(|e| match e {
                io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
                io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                    io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
                },
            })?;
    }

    Ok(())
}

/// Determine an extent's integrity protection state.
///
/// In cases where an extent's integrity protections are not to get verified and
/// removed, because of e.g. a mismatch of some magic stored at its beginning,
/// its [`ExtentIntegrityState`] required as input to any subsequent updates,
/// i.e. to [`extent_integrity_protections_apply()`] may still get obtained
/// through [`extent_integrity_protections_determine_state()`].
///
/// If the tier 0 integrity protections had been removed explicitly from
/// `extent` through [`extent_tier0_integrity_protection_verify_and_remove()`]
/// already, then the resulting [`ExtentTier0IntegrityState`] must get
/// passed for the `extent_tier0_integrity_state` argument.
///
/// The full [`extent_integrity_protections_verify_and_remove()`] must not have
/// been invoked on `extent` yet.
///
/// # Arguments:
///
/// * `extent` - The extent's contents. Needs to cover only the first [device IO
///   Block](NvBlkDev::io_block_size_128b_log2).
/// * `extent_head_skip` - Amount of head space exempt from the integrity
///   protection.
/// * `integrity_protections_offset` - Offset relative to `extent_head_skip`
///   where the integrity protections are stored within the extent.
/// * `extent_tier0_integrity_state` - The extent's tier 0 integrity protection
///   state, as returned from a prior
///   [`extent_tier0_integrity_protection_verify_and_remove()`], if any.
/// * `io_block_allocation_blocks_log2` - Verbatim value of
///   [`ImageLayout::io_block_allocation_blocks_log2`].
/// * `allocation_block_size_128b_log2` - Verbatim value of
///   [`ImageLayout::allocation_block_size_128b_log2`].
/// * `blkdev_io_block_size_128b_log2` - Value of
///   [`NvBlkDev::io_block_size_128b_log2()`].
///
/// # See also:
///
/// * [`extent_integrity_protections_verify_and_remove()`].
/// * [`extent_tier0_integrity_protection_verify_and_remove()`].
pub fn extent_integrity_protections_determine_state<'a, E: io_slices::PeekableIoSlicesIter<'a>>(
    extent: E,
    extent_head_skip: usize,
    integrity_protections_offset: usize,
    extent_tier0_integrity_state: Option<&ExtentTier0IntegrityState>,
    io_block_allocation_blocks_log2: u8,
    allocation_block_size_128b_log2: u8,
    blkdev_io_block_size_128b_log2: u32,
) -> Result<ExtentIntegrityState, NvFsError>
where
    NvFsError: convert::From<E::BackendIteratorError>,
{
    let extent_tier0_integrity_state = match extent_tier0_integrity_state {
        Some(extent_tier0_integrity_state) => *extent_tier0_integrity_state,
        None => extent_tier0_integrity_protection_verify(
            extent.decoupled_borrow(),
            extent_head_skip,
            integrity_protections_offset,
        )?,
    };

    extent_tier1_integrity_protection_determine_state(
        extent,
        extent_head_skip,
        integrity_protections_offset,
        &extent_tier0_integrity_state,
        io_block_allocation_blocks_log2,
        allocation_block_size_128b_log2,
        blkdev_io_block_size_128b_log2,
    )
}

/// Verify and remove an extent's integrity protections.
///
/// On success, a pair of a bool representing verification success and the
/// [`ExtentIntegrityState`] is returned.
///
/// On verification success, the integrity protection will get removed,
/// and the `extent`'s contents will be at their original values. The integrity
/// protections data region within it will be all-zero.
///
/// The tier 0 integrity protections may have been verified and removed
/// explicitly from `extent`
/// through [`extent_tier0_integrity_protection_verify_and_remove()`] already,
/// If so, then the verification must have been successful, and the resulting
/// [`ExtentTier0IntegrityState`] must get passed for the
/// `extent_tier0_integrity_state` argument.
///
/// # Arguments:
///
/// * `extent` - The extent's contents.
/// * `extent_head_skip` - Amount of head space exempt from the integrity
///   protection.
/// * `integrity_protections_offset` - Offset relative to `extent_head_skip`
///   where the integrity protections are stored within the extent.
/// * `extent_tier0_integrity_state` - The extent's tier 0 integrity protection
///   state, as returned from a prior
///   [`extent_tier0_integrity_protection_verify_and_remove()`], if any.
/// * `io_block_allocation_blocks_log2` - Verbatim value of
///   [`ImageLayout::io_block_allocation_blocks_log2`].
/// * `allocation_block_size_128b_log2` - Verbatim value of
///   [`ImageLayout::allocation_block_size_128b_log2`].
/// * `blkdev_io_block_size_128b_log2` - Value of
///   [`NvBlkDev::io_block_size_128b_log2()`].
///
/// # See also:
///
/// * [`extent_integrity_protections_determine_state()`].
/// * [`extent_tier0_integrity_protection_verify_and_remove()`].
pub fn extent_integrity_protections_verify_and_remove<'a, E: io_slices::MutPeekableIoSlicesMutIter<'a>>(
    mut extent: E,
    extent_head_skip: usize,
    integrity_protections_offset: usize,
    extent_tier0_integrity_state: Option<&ExtentTier0IntegrityState>,
    io_block_allocation_blocks_log2: u8,
    allocation_block_size_128b_log2: u8,
    blkdev_io_block_size_128b_log2: u32,
) -> Result<(bool, ExtentIntegrityState), NvFsError>
where
    NvFsError: convert::From<E::BackendIteratorError>,
{
    let extent_tier0_integrity_state = match extent_tier0_integrity_state {
        Some(extent_tier0_integrity_state) => *extent_tier0_integrity_state,
        None => {
            // extent_tier0_integrity_protection_verify_and_remove() hasn't been run by the
            // caller yet. Do it here.
            let (is_valid, extent_tier0_integrity_state) = extent_tier0_integrity_protection_verify_and_remove(
                extent.decoupled_borrow_mut(),
                extent_head_skip,
                integrity_protections_offset,
            )?;
            if !is_valid {
                let extent_integrity_state = extent_tier1_integrity_protection_determine_state(
                    extent,
                    extent_head_skip,
                    integrity_protections_offset,
                    &extent_tier0_integrity_state,
                    io_block_allocation_blocks_log2,
                    allocation_block_size_128b_log2,
                    blkdev_io_block_size_128b_log2,
                )?;
                return Ok((false, extent_integrity_state));
            }

            extent_tier0_integrity_state
        }
    };

    extent_tier1_integrity_protection_verify_and_remove(
        extent,
        extent_head_skip,
        integrity_protections_offset,
        &extent_tier0_integrity_state,
        io_block_allocation_blocks_log2,
        allocation_block_size_128b_log2,
        blkdev_io_block_size_128b_log2,
    )
}

/// Apply integrity protections to an extent.
///
/// Apply integrity protections to `extent` and return the new
/// [`ExtentIntegrityState`] the extent would have on storage after a successful
/// write.
///
/// That is, if the subsequent write to storage is successful, callers may
/// replace their copy of the `extent_integrity_state` with the value returned
/// from this function to maintain its validity. In case the subsequent write of
/// the extent's first [device IO Block](NvBlkDev::io_block_size_128b_log2)
/// fails, callers may invoke
/// [`record_failed_write()`](ExtentIntegrityState::record_failed_write) on
/// their copy of the `extent_integrity_state` in order to maintain its
/// validity.
///
/// # Arguments:
///
/// * `extent` - The extent's contents.
/// * `extent_head_skip` - Amount of head space exempt from the integrity
///   protection.
/// * `integrity_protections_offset` - Offset relative to `extent_head_skip`
///   where the integrity protections are stored within the extent.
/// * `extent_integrity_state` - The extent's current integrity protection state
///   [`need_clear()`](ExtentIntegrityState::need_clear) must evaluate to
///   `false`.
/// * `io_block_allocation_blocks_log2` - Verbatim value of
///   [`ImageLayout::io_block_allocation_blocks_log2`].
/// * `allocation_block_size_128b_log2` - Verbatim value of
///   [`ImageLayout::allocation_block_size_128b_log2`].
/// * `blkdev_io_block_size_128b_log2` - Value of
///   [`NvBlkDev::io_block_size_128b_log2()`]. Used only for diagnostic
///   purposes, i.e. for assertions. Set to a non-zero value for most relaxed
///   checks.
pub fn extent_integrity_protections_apply<'a, E: io_slices::MutPeekableIoSlicesMutIter<'a>>(
    mut extent: E,
    extent_head_skip: usize,
    integrity_protections_offset: usize,
    extent_integrity_state: &ExtentIntegrityState,
    io_block_allocation_blocks_log2: u8,
    allocation_block_size_128b_log2: u8,
    blkdev_io_block_size_128b_log2: u32,
) -> Result<ExtentIntegrityState, NvFsError>
where
    NvFsError: convert::From<E::BackendIteratorError>,
{
    debug_assert!(!extent_integrity_state.need_clear(
        extent_head_skip,
        integrity_protections_offset,
        blkdev_io_block_size_128b_log2,
    ));

    let checksum = extent_tier1_integrity_protection_save_checkpoint_locations_data(
        extent.decoupled_borrow_mut(),
        extent_head_skip,
        integrity_protections_offset,
        io_block_allocation_blocks_log2,
        allocation_block_size_128b_log2,
    )?;

    let commit_id = extent_tier0_integrity_protection_apply(
        extent.decoupled_borrow_mut(),
        extent_head_skip,
        integrity_protections_offset,
        checksum,
        extent_integrity_state.last_commit_ids_tails,
    )?;

    extent_tier1_integrity_protection_write_checkpoint_locations_markers(
        extent,
        extent_head_skip,
        integrity_protections_offset,
        commit_id,
        io_block_allocation_blocks_log2,
        allocation_block_size_128b_log2,
    )?;

    Ok(ExtentIntegrityState {
        tier0_need_clear: true,
        tier1_need_clear: false,
        need_clear_for_coherence: true,
        last_commit_ids_tails: [[commit_id[0], commit_id[checksum::CHECKSUM_LEN as usize - 1]], [0, 0]],
    })
}

/// Invalidate an extent's integrity protection by writing zeros to its first
/// [device IO Block](NvBlkDev::io_block_size_128b_log2).
///
/// The invalidation write is always followed by either a [write
/// barrier](blkdev::NvBlkDev::write_barrier), or, if the `issue_sync` argument
/// to [`new()`](Self::new) had been set to `true`, a [synchronization
/// barrier](blkdev::NvBlkDev::write_sync) even.
///
/// After the invalidation has completed successfully, users might want to
/// record that fact at an [`ExtentIntegrityState`] instance associated with the
/// invalidate extent by means of [`ExtentIntegrityState::record_clear()`].
///
/// # See also:
///
/// * [`ExtentIntegrityState::need_clear()`].
/// * [`ExtentIntegrityState::record_clear()`]
pub struct ExtentIntegrityProtectionsInvalidateFuture<B: blkdev::NvBlkDev> {
    fut_state: ExtentIntegrityProtectionsInvalidateFutureState<B>,
}

/// [`ExtentIntegrityProtectionsInvalidateFuture`] state-machine state.
enum ExtentIntegrityProtectionsInvalidateFutureState<B: blkdev::NvBlkDev> {
    Init {
        extent_begin: PhysicalAllocBlockIndex,
        allocation_block_size_128b_log2: u8,
        issue_sync: bool,
    },
    Invalidate {
        clear_fut: blkdev::helpers::NvBlkDevClearRegionFuture<B>,
        issue_sync: bool,
    },
    WriteBarrierAfterInvalidate {
        write_barrier_fut: B::WriteBarrierFuture,
    },
    WriteSyncAfterInvalidate {
        write_sync_fut: B::WriteSyncFuture,
    },
    Done,
}

impl<B: blkdev::NvBlkDev> ExtentIntegrityProtectionsInvalidateFuture<B> {
    /// Instantiate a [`ExtentIntegrityProtectionsInvalidateFuture`].
    ///
    /// # Arguments:
    ///
    /// * `extent_begin` - Location of the extent to invalidate. Must be aligned
    ///   to the [`IO Block
    ///   size`](ImageLayout::io_block_allocation_blocks_log2). As the extent's
    ///   first [device IO Block](NvBlkDev::io_block_size_128b_log2) will get
    ///   written with zeros, the extent must span at least one. However, for
    ///   the generic integrity protections in general, it is assumed that the
    ///   protected extents' boundaries are always aligned to the [`IO Block
    ///   size`](ImageLayout::io_block_allocation_blocks_log2). So both
    ///   constraints should be trivially satisfied.
    /// * `allocation_block_size_128b_log2` - Verbatim value of
    ///   [`ImageLayout::allocation_block_size_128b_log2`].
    /// * `issue_sync` - Whether to issue a [synchronization
    ///   barrier](blkdev::NvBlkDev::write_sync) after the zeroization write. If
    ///   `false`, a a [write barrier](blkdev::NvBlkDev::write_barrier)
    ///   willstill get issued.
    pub fn new(extent_begin: PhysicalAllocBlockIndex, allocation_block_size_128b_log2: u8, issue_sync: bool) -> Self {
        Self {
            fut_state: ExtentIntegrityProtectionsInvalidateFutureState::Init {
                extent_begin,
                allocation_block_size_128b_log2,
                issue_sync,
            },
        }
    }
}

impl<B: blkdev::NvBlkDev> blkdev::NvBlkDevFuture<B> for ExtentIntegrityProtectionsInvalidateFuture<B> {
    type Output = Result<(), NvFsError>;

    fn poll(self: pin::Pin<&mut Self>, blkdev: &B, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                ExtentIntegrityProtectionsInvalidateFutureState::Init {
                    extent_begin,
                    allocation_block_size_128b_log2,
                    issue_sync,
                } => {
                    let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();
                    let blkdev_io_block_allocation_blocks_log2 =
                        blkdev_io_block_size_128b_log2.saturating_sub(*allocation_block_size_128b_log2 as u32);
                    let allocation_block_blkdev_io_blocks_log2 = (*allocation_block_size_128b_log2 as u32)
                        .saturating_sub(blkdev_io_block_allocation_blocks_log2);
                    let extent_begin_blkdev_io_blocks = u64::from(*extent_begin)
                        >> blkdev_io_block_allocation_blocks_log2
                        << allocation_block_blkdev_io_blocks_log2;
                    if extent_begin_blkdev_io_blocks << blkdev_io_block_allocation_blocks_log2
                        >> allocation_block_blkdev_io_blocks_log2
                        != u64::from(*extent_begin)
                    {
                        // Either extent_begin had been unaligned, or the conversion to units of device
                        // IO Blocks overflowed.
                        this.fut_state = ExtentIntegrityProtectionsInvalidateFutureState::Done;
                        return task::Poll::Ready(Err(nvfs_err_internal!()));
                    }

                    let clear_fut = blkdev::helpers::NvBlkDevClearRegionFuture::new(
                        extent_begin_blkdev_io_blocks,
                        1,
                        blkdev_io_block_size_128b_log2 as u8,
                    );

                    this.fut_state = ExtentIntegrityProtectionsInvalidateFutureState::Invalidate {
                        clear_fut,
                        issue_sync: *issue_sync,
                    };
                }
                ExtentIntegrityProtectionsInvalidateFutureState::Invalidate { clear_fut, issue_sync } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(clear_fut), blkdev, cx) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => {
                            this.fut_state = ExtentIntegrityProtectionsInvalidateFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    if !*issue_sync {
                        let write_barrier_fut = match blkdev.write_barrier() {
                            Ok(write_barrier_fut) => write_barrier_fut,
                            Err(e) => {
                                this.fut_state = ExtentIntegrityProtectionsInvalidateFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(e)));
                            }
                        };
                        this.fut_state = ExtentIntegrityProtectionsInvalidateFutureState::WriteBarrierAfterInvalidate {
                            write_barrier_fut,
                        };
                    } else {
                        let write_sync_fut = match blkdev.write_sync() {
                            Ok(write_sync_fut) => write_sync_fut,
                            Err(e) => {
                                this.fut_state = ExtentIntegrityProtectionsInvalidateFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(e)));
                            }
                        };
                        this.fut_state = ExtentIntegrityProtectionsInvalidateFutureState::WriteSyncAfterInvalidate {
                            write_sync_fut,
                        };
                    }
                }
                ExtentIntegrityProtectionsInvalidateFutureState::WriteBarrierAfterInvalidate { write_barrier_fut } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(write_barrier_fut), blkdev, cx) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => {
                            this.fut_state = ExtentIntegrityProtectionsInvalidateFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    this.fut_state = ExtentIntegrityProtectionsInvalidateFutureState::Done;
                    return task::Poll::Ready(Ok(()));
                }
                ExtentIntegrityProtectionsInvalidateFutureState::WriteSyncAfterInvalidate { write_sync_fut } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(write_sync_fut), blkdev, cx) {
                        task::Poll::Ready(Ok(())) => (),
                        task::Poll::Ready(Err(e)) => {
                            this.fut_state = ExtentIntegrityProtectionsInvalidateFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    this.fut_state = ExtentIntegrityProtectionsInvalidateFutureState::Done;
                    return task::Poll::Ready(Ok(()));
                }
                ExtentIntegrityProtectionsInvalidateFutureState::Done => unreachable!(),
            }
        }
    }
}
