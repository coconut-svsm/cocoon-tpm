// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation [`AuxFsMetadata`] and related functionality.

extern crate alloc;
use alloc::vec::Vec;
use cocoon_tpm_utils_common::fixed_vec::FixedVec;

use crate::utils_common::{
    alloc::{TryNewError, try_alloc_vec},
    bitmanip::BitManip as _,
    io_slices::{self, IoSlicesIterCommon as _, IoSlicesMutIter as _},
};

use crate::{
    blkdev,
    fs::{
        NvFsError,
        cocoonfs::{
            FormatError, alloc_bitmap, checksum,
            extent_ptr::EncodedExtentPtr,
            extents::PhysicalExtents,
            extents_layout,
            integrity::{
                ExtentIntegrityState, extent_integrity_protections_apply, extent_integrity_protections_len,
                extent_integrity_protections_verify_and_remove, extent_tier0_integrity_protection_verify_and_remove,
            },
            layout::{AllocBlockCount, ImageLayout, PhysicalAllocBlockIndex, PhysicalAllocBlockRange},
        },
    },
    nvfs_err_internal,
};

use core::{cmp, convert, default, mem, pin, task};

#[cfg(doc)]
use crate::{
    blkdev::NvBlkDevFuture as _,
    fs::cocoonfs::{image_header, openfs::ReadFsMetadataFuture},
};

const UUID_LEN: usize = 16;

/// Integer type for encoding an [`AuxFsMetadata`] entry's data length.
type EntryDataLenType = u32;

/// [`AuxFsMetadata`] entry header length.
const ENTRY_HEADER_LEN: usize = UUID_LEN + mem::size_of::<EntryDataLenType>();

/// Error returned by [`AuxFsMetadata::add_entry()`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuxFsMetadataPushError {
    MemoryAllocationFailure,
    InvalidUuid,
    InvalidRecordLength,
    InvalidTotalLength,
    UnsupportedTotalLength,
}

/// Auxiliary CocoonFs metadata.
///
/// A CocoonFs instance may have some auxiliary filesystem metadata stored on
/// it. This auxiliary metadata is organized as a sequence of records in a TLV
/// format, with the tags being arbitrary 128 bit UUIDs. Multiple entries with
/// the same UUID are possible.
///
/// The auxiliary filesystem metadata is not protected by any cryptographic
/// means, and can be read without knowledge of the filesystem key before the
/// filesystem itself is getting opened.
///
/// The intent is to support a wide variety of key retrieval workflows where
/// some auxiliary metadata with semantics defined by the respective workflow is
/// required as input. For example, a wrapped key could get stored in a
/// `AuxFsMetadata` record and sent off to a remote attestation server in
/// order to obtain the unwrapped filesystem root key.
///
/// # See also:
///
/// * [`ReadFsMetadataFuture`].
#[derive(Debug)]
pub struct AuxFsMetadata {
    encoded: Vec<u8>,
}

impl AuxFsMetadata {
    /// Create a new, [trivial](Self::is_trivial) [`AuxFsMetadata`] instance.
    pub fn new() -> Self {
        Self { encoded: Vec::new() }
    }

    /// Try to create a copy of `self`.
    pub fn try_clone(&self) -> Result<Self, TryNewError> {
        let mut encoded = try_alloc_vec(self.encoded.len())?;
        encoded.copy_from_slice(&self.encoded);
        Ok(Self { encoded })
    }

    /// Decode a [`AuxFsMetadata`] from a single, contiguous buffer.
    ///
    /// The [`AuxFsMetadata`] contents may get stored in one or more extents on
    /// storage, each with its own checksum protections. Decode from a
    /// single, contiguous `encoded` buffer, where all the extents' payloads
    /// have been gathered into back-to-back.
    ///
    /// # Arguments:
    ///
    /// * `encoded` - The [`AuxFsMetadata`] contents, encoded in plain, with no
    ///   integrity protections.
    ///
    /// # See also:
    ///
    /// * [`ReadAuxFsMetadataFuture`].
    /// * [`ReadMkFsInfoAuxFsMetadataFuture`].
    fn decode(mut encoded: Vec<u8>) -> Result<Self, NvFsError> {
        if encoded.is_empty() {
            return Ok(Self { encoded });
        }

        // The length must be representable in an u64. It should be trivially true, but
        // make it explicit.
        if u64::try_from(encoded.len()).is_err() {
            return Err(NvFsError::from(FormatError::InvalidAuxFsMetadataSize));
        }

        // Walk the entries to confirm they match the expected format.
        let mut used_encoded_len = 0;
        let mut last_uuid = [0u8; UUID_LEN];
        loop {
            if encoded.len() - used_encoded_len < ENTRY_HEADER_LEN {
                return Err(NvFsError::from(FormatError::InvalidAuxFsMetadataFormat));
            }

            let entry_uuid = &encoded[used_encoded_len..used_encoded_len + UUID_LEN];
            used_encoded_len += UUID_LEN;

            let entry_data_len = &encoded[used_encoded_len..used_encoded_len + mem::size_of::<EntryDataLenType>()];
            used_encoded_len += mem::size_of::<EntryDataLenType>();

            let entry_data_len = usize::try_from(EntryDataLenType::from_le_bytes(
                *<&[u8; mem::size_of::<EntryDataLenType>()]>::try_from(entry_data_len)
                    .map_err(|_| nvfs_err_internal!())?,
            ))
            .map_err(|_| NvFsError::from(FormatError::InvalidAuxFsMetadataFormat))?;
            if encoded.len() - used_encoded_len < entry_data_len {
                return Err(NvFsError::from(FormatError::InvalidAuxFsMetadataFormat));
            }

            // Is it the termination record with an "UUID" of all zeros?
            if entry_uuid.iter().all(|b| *b == 0) {
                // The termination record may store an optional u64 extra modification reserve
                // property.
                if entry_data_len == mem::size_of::<u64>() {
                    // The termination record stores an offline modification extra reserve.
                    let extra_reserve = u64::from_le_bytes(
                        *<&[u8; mem::size_of::<u64>()]>::try_from(
                            &encoded[used_encoded_len..used_encoded_len + mem::size_of::<u64>()],
                        )
                        .map_err(|_| nvfs_err_internal!())?,
                    );
                    used_encoded_len += entry_data_len;
                    // The total allocated storage length, i.e. the encoded length plus the extra
                    // reserve must be representable as an u64.
                    if (u64::MAX - used_encoded_len as u64) < extra_reserve {
                        return Err(NvFsError::from(FormatError::InvalidAuxFsMetadataSize));
                    }
                } else if entry_data_len != 0 {
                    return Err(NvFsError::from(FormatError::InvalidAuxFsMetadataFormat));
                }

                break;
            } else if last_uuid.as_slice() > entry_uuid {
                // The entries must be sorted by UUID.
                return Err(NvFsError::from(FormatError::InvalidAuxFsMetadataFormat));
            }

            used_encoded_len += entry_data_len;
            last_uuid.copy_from_slice(entry_uuid);
        }

        // The excess space should have all been set to zero.
        if encoded[used_encoded_len..].iter().any(|b| *b != 0) {
            return Err(NvFsError::from(FormatError::InvalidAuxFsMetadataFormat));
        }
        encoded.truncate(used_encoded_len);

        Ok(Self { encoded })
    }

    /// Iterate over the auxiliary filesystem metadata records.
    ///
    /// The iterator will return a pair of identifying UUID and associated data
    /// for each record.
    pub fn iter(&self) -> AuxFsMetadataIter<'_> {
        AuxFsMetadataIter {
            remaining_encoded: &self.encoded,
        }
    }

    /// Set the extra reserve capacity.
    ///
    /// In order to prepare for updating the [`AuxFsMetadata`] on storage
    /// offline, i.e. without access to the filesystem root key and thus,
    /// when no reallocations or writes through the journal are possible, an
    /// optional extra reserve capacity may get allocated in advance.
    ///
    /// This extra reserve capacity, is a permanent property of the
    /// [`AuxFsMetadata`] contents on storage, and will be respected for any
    /// future reallocations.
    ///
    /// If `extra_reserve` is `None`, then no offline [`AuxFsMetadata`] updates
    /// will be possible at all, not even in case the updated contents were
    /// small enough to fit the original allocation.
    ///
    /// Otherwise, if `extra_reserve` is a `Some()`, any subsequent storage
    /// (re)allocation will include sufficient additional space required for
    /// enabling reliable offline updates robust against service
    /// interruptions. Note that this is implemented by means of a
    /// Read-Copy-Update scheme, so the preallocated storage will be at
    /// least twice as large as it had been if `extra_reserve` was set to
    /// `None`. The integer value wrapped in a `Some()` specifies the
    /// additional amount of space in Bytes over the current
    /// [`encoded_len()`](Self::encoded_len) to preallocate. It may be set
    /// to zero if it's anticipated that an offline update would perhaps
    /// become necessary in the future, but that the contents would never grow.
    /// Otherwise, if an increase in size might be possible, set to a
    /// reasonble non-zero value.
    ///
    /// # Arguments:
    ///
    /// * `extra_reserve` - The extra reserve capacity in Bytes, if any.
    ///
    /// # See also:
    ///
    /// * [`get_extra_reserve_capacity()`](Self::get_extra_reserve_capacity).
    pub fn set_extra_reserve_capacity(&mut self, extra_reserve: Option<u64>) -> Result<(), AuxFsMetadataPushError> {
        if extra_reserve.is_none() && self.encoded.is_empty() {
            return Ok(());
        }

        // Walk to the termination record and update its extra reserve info.
        let mut termination_record_begin = 0;
        for entry in self.iter() {
            termination_record_begin += ENTRY_HEADER_LEN + entry.1.len();
        }

        match extra_reserve {
            None => {
                // Reset the termination record's data length to zero.
                debug_assert!(!self.encoded.is_empty());
                self.encoded.truncate(termination_record_begin + ENTRY_HEADER_LEN);
                self.encoded[termination_record_begin + UUID_LEN..].fill(0u8);
            }
            Some(extra_reserve) => {
                debug_assert!(
                    self.encoded.is_empty() || self.encoded.len() >= termination_record_begin + ENTRY_HEADER_LEN
                );
                // termination_record_begin + ENTRY_HEADER_LEN cannot overflow an u64,
                // because, if termination_record_begin is nonzero, then that sum is within the
                // current encoding's bounds.
                let new_encoded_len = ((termination_record_begin + ENTRY_HEADER_LEN) as u64)
                    .checked_add(mem::size_of::<u64>() as u64)
                    .ok_or(AuxFsMetadataPushError::InvalidTotalLength)?;
                // The total allocated storage length must always be representable as an u64.
                if u64::MAX - new_encoded_len < extra_reserve {
                    return Err(AuxFsMetadataPushError::InvalidTotalLength);
                }
                let new_encoded_len =
                    usize::try_from(new_encoded_len).map_err(|_| AuxFsMetadataPushError::UnsupportedTotalLength)?;
                if self.encoded.len() < new_encoded_len {
                    self.encoded
                        .try_reserve(new_encoded_len - self.encoded.len())
                        .map_err(|_| AuxFsMetadataPushError::MemoryAllocationFailure)?;
                    self.encoded.resize(new_encoded_len, 0u8);
                }
                self.encoded[termination_record_begin + UUID_LEN
                    ..termination_record_begin + UUID_LEN + mem::size_of::<EntryDataLenType>()]
                    .copy_from_slice(&(mem::size_of::<u64>() as EntryDataLenType).to_le_bytes());
                self.encoded[termination_record_begin + ENTRY_HEADER_LEN
                    ..termination_record_begin + ENTRY_HEADER_LEN + mem::size_of::<u64>()]
                    .copy_from_slice(&extra_reserve.to_le_bytes());
            }
        }

        Ok(())
    }

    /// Get the [extra reserve capacity](Self::set_extra_reserve_capacity).
    ///
    /// # See also:
    ///
    /// * [`set_extra_reserve_capacity()`](Self::set_extra_reserve_capacity).
    pub fn get_extra_reserve_capacity(&self) -> Option<u64> {
        if self.encoded.is_empty() {
            return None;
        }

        // Walk to the termination record and read its extra reserve info.
        let mut termination_record_begin = 0;
        for entry in self.iter() {
            termination_record_begin += ENTRY_HEADER_LEN + entry.1.len();
        }

        let termination_record_data_len = match <&[u8; mem::size_of::<EntryDataLenType>()]>::try_from(
            &self.encoded[termination_record_begin + UUID_LEN
                ..termination_record_begin + UUID_LEN + mem::size_of::<EntryDataLenType>()],
        )
        .ok()
        {
            Some(termination_record_data_len) => EntryDataLenType::from_le_bytes(*termination_record_data_len),
            None => {
                // This cannot happen. Avoid returning an error from this function and just
                // pretend to return something.
                debug_assert!(false);
                0
            }
        };

        if termination_record_data_len == 0 {
            None
        } else {
            debug_assert_eq!(termination_record_data_len, mem::size_of::<u64>() as EntryDataLenType);
            match <&[u8; mem::size_of::<u64>()]>::try_from(
                &self.encoded[termination_record_begin + ENTRY_HEADER_LEN
                    ..termination_record_begin + ENTRY_HEADER_LEN + mem::size_of::<u64>()],
            )
            .ok()
            {
                Some(extra_reserve) => Some(u64::from_le_bytes(*extra_reserve)),
                None => {
                    // This cannot happen. Avoid returning an error from this function and just
                    // pretend to return something, i.e. a None.
                    debug_assert!(false);
                    None
                }
            }
        }
    }

    /// Add an auxiliary filesystem metadata entry.
    ///
    /// Add a new entry with an identifier of `uuid` and associated `data`.
    /// Note that multiple entries with the same UUID are possible -- if an
    /// entry with `uuid` exists already, it will *not* get replaced.
    ///
    /// # Arguments:
    ///
    /// * `uuid` - The entry's UUID, identifying it's semantics.
    /// * `data` - The entry's associated data.
    pub fn add_entry(&mut self, uuid: &[u8; UUID_LEN], data: &[u8]) -> Result<(), AuxFsMetadataPushError> {
        if uuid.iter().all(|b| *b == 0) {
            return Err(AuxFsMetadataPushError::InvalidUuid);
        }
        let entry_data_len =
            EntryDataLenType::try_from(data.len()).map_err(|_| AuxFsMetadataPushError::InvalidRecordLength)?;

        // Find the insertion position and the termination record.
        let mut used_encoded_len = 0;
        let mut insertion_pos = None;
        for entry in self.iter() {
            if uuid < entry.0 {
                insertion_pos = Some(used_encoded_len);
            }

            used_encoded_len += ENTRY_HEADER_LEN + entry.1.len();
        }
        let insertion_pos = insertion_pos.unwrap_or(used_encoded_len);

        // Account for the termination record.
        let extra_reserve = if self.encoded.is_empty() {
            // Termination record with no extra reserve info.
            used_encoded_len += ENTRY_HEADER_LEN;
            None
        } else {
            let termination_record_begin = used_encoded_len;
            let termination_record_data_len = match <&[u8; mem::size_of::<EntryDataLenType>()]>::try_from(
                &self.encoded[termination_record_begin + UUID_LEN
                    ..termination_record_begin + UUID_LEN + mem::size_of::<EntryDataLenType>()],
            )
            .ok()
            {
                Some(termination_record_data_len) => EntryDataLenType::from_le_bytes(*termination_record_data_len),
                None => {
                    // This cannot happen. Avoid introducing some variant representing an "internal"
                    // error to AuxFsMetadataPushError and just pretend to return something.
                    debug_assert!(false);
                    0
                }
            };

            used_encoded_len += ENTRY_HEADER_LEN + termination_record_data_len as usize;

            if termination_record_data_len == 0 {
                None
            } else {
                debug_assert_eq!(termination_record_data_len, mem::size_of::<u64>() as EntryDataLenType);
                match <&[u8; mem::size_of::<u64>()]>::try_from(
                    &self.encoded[termination_record_begin + ENTRY_HEADER_LEN
                        ..termination_record_begin + ENTRY_HEADER_LEN + mem::size_of::<u64>()],
                )
                .ok()
                {
                    Some(extra_reserve) => Some(u64::from_le_bytes(*extra_reserve)),
                    None => {
                        // This cannot happen. Avoid introducing some variant representing an
                        // "internal" error to AuxFsMetadataPushError and just pretend to return
                        // something, i.e. a None.
                        debug_assert!(false);
                        None
                    }
                }
            }
        };
        debug_assert!(self.encoded.is_empty() || used_encoded_len <= self.encoded.len());

        let entry_encoded_len = ENTRY_HEADER_LEN
            .checked_add(data.len())
            .ok_or(AuxFsMetadataPushError::UnsupportedTotalLength)?;
        let new_encoded_len = used_encoded_len
            .checked_add(entry_encoded_len)
            .ok_or(AuxFsMetadataPushError::UnsupportedTotalLength)?;

        // The new total allocated storage length must be representable as an u64.
        if u64::try_from(new_encoded_len)
            .ok()
            .filter(|new_encoded_len| *new_encoded_len <= u64::MAX - extra_reserve.unwrap_or(0))
            .is_none()
        {
            return Err(AuxFsMetadataPushError::InvalidTotalLength);
        }

        self.encoded
            .try_reserve(new_encoded_len - self.encoded.len())
            .map_err(|_| AuxFsMetadataPushError::MemoryAllocationFailure)?;
        // This implicity inserts a termination record (with no extra_reserve) if there
        // hadn't been one before.
        self.encoded.resize(new_encoded_len, 0u8);

        // No need to move the termination record around, the tail is all-zeros anyway.
        self.encoded
            .copy_within(insertion_pos..used_encoded_len, insertion_pos + entry_encoded_len);

        let encoded_entry = &mut self.encoded[insertion_pos..insertion_pos + entry_encoded_len];
        let (encoded_entry_uuid, remaining_encoded_entry) = encoded_entry.split_at_mut(UUID_LEN);
        encoded_entry_uuid.copy_from_slice(uuid);
        let (encoded_entry_len, encoded_entry_data) =
            remaining_encoded_entry.split_at_mut(mem::size_of::<EntryDataLenType>());
        encoded_entry_len.copy_from_slice(&entry_data_len.to_le_bytes());
        encoded_entry_data.copy_from_slice(data);

        Ok(())
    }

    /// Remove an auxiliary filesystem metadata entry.
    ///
    /// Remove the entry at position `index` within the sequence of existing
    /// entries with a UUID of `uuid`. If a matching entry is found and
    /// removed, `true` is getting returned, `false` otherwise.
    ///
    /// # Arguments:
    ///
    /// * `uuid` - The UUID of the entry to remove.
    /// * `index` - Index within the sequence of existing entries with a UUID of
    ///   `uuid`.
    pub fn remove_entry(&mut self, uuid: [u8; UUID_LEN], mut index: usize) -> bool {
        let mut found = None;
        let mut used_encoded_len = 0;
        for entry in self.iter() {
            let entry_encoded_len = ENTRY_HEADER_LEN + entry.1.len();

            if found.is_none() && uuid == *entry.0 {
                if index == 0 {
                    found = Some((used_encoded_len, entry_encoded_len));
                } else {
                    index -= 1;
                }
            }

            used_encoded_len += entry_encoded_len;
        }

        let (removal_pos, entry_encoded_len) = match found {
            Some((removal_pos, entry_encoded_len)) => (removal_pos, entry_encoded_len),
            None => return false,
        };
        debug_assert!(!self.encoded.is_empty());

        // Account for the termination record.
        // Its length is a plain ENTRY_HEADER_LEN plus the optional extra reserve stored
        // in the termination record, if any.
        used_encoded_len += ENTRY_HEADER_LEN;
        debug_assert!(used_encoded_len <= self.encoded.len());
        used_encoded_len += mem::size_of::<u64>().min(self.encoded.len() - used_encoded_len);

        self.encoded
            .copy_within(removal_pos + entry_encoded_len..used_encoded_len, removal_pos);
        self.encoded.truncate(used_encoded_len - entry_encoded_len);

        true
    }

    /// Determine whether the [`AuxFsMetadata`] instance is trivial.
    ///
    /// An [`AuxFsMetadata`] is trivial if it has no entries, and no [extra
    /// reserve capacity](Self::get_extra_reserve_capacity) set.
    pub fn is_trivial(&self) -> bool {
        // As an optimization, check whether there's only a termination record with no
        // extra reserve info.
        self.encoded.len() <= ENTRY_HEADER_LEN
            || (self.iter().next().is_none() && self.get_extra_reserve_capacity() == Some(0))
    }

    /// The [`AuxFsMetadata`]'s encoded length.
    ///
    /// The returned encoding length accounts for the bare [`AuxFsMetadata`]
    /// content encoding only, it does not include the
    /// [`get_extra_reserve_capacity()`](Self::get_extra_reserve_capacity), if
    /// any.
    ///
    /// The returned value is guaranteed to be representable as an `u64`.
    pub fn encoded_len(&self) -> usize {
        // All code-paths ensure that the result overflows neither an usize, nor an u64.
        if self.encoded.is_empty() {
            // Account for the termination record with no extra reserve info.
            ENTRY_HEADER_LEN
        } else {
            let mut used_encoded_len = 0;
            for entry in self.iter() {
                used_encoded_len += ENTRY_HEADER_LEN + entry.1.len();
            }

            let termination_record_begin = used_encoded_len;
            let termination_record_data_len = match <&[u8; mem::size_of::<EntryDataLenType>()]>::try_from(
                &self.encoded[termination_record_begin + UUID_LEN
                    ..termination_record_begin + UUID_LEN + mem::size_of::<EntryDataLenType>()],
            )
            .ok()
            {
                Some(termination_record_data_len) => EntryDataLenType::from_le_bytes(*termination_record_data_len),
                None => {
                    // This cannot happen. Avoid returning an error from this function and just
                    // pretend to return something.
                    debug_assert!(false);
                    0
                }
            };

            used_encoded_len + ENTRY_HEADER_LEN + termination_record_data_len as usize
        }
    }

    /// Determine the total storage payload length suitable for storing one
    /// [`AuxFsMetadata`] update group.
    ///
    /// The returned length is the sum of the
    /// [`encoded_len()`](Self::encoded_len) and the [extra reserve
    /// capacity](Self::get_extra_reserve_capacity).
    ///
    /// The returned value is guaranteed to be representable as an `usize`.
    ///
    /// # See also:
    ///
    /// * [`encoded_len()`](Self::encoded_len).
    /// * [`get_extra_reserve_capacity()`](Self::get_extra_reserve_capacity).
    /// * [`extents_allocation_request()`](Self::extents_allocation_request).
    fn storage_allocation_payload_length(&self) -> u64 {
        if self.encoded.is_empty() {
            // Account for the termination record with no extra reserve info.
            return ENTRY_HEADER_LEN as u64;
        }

        // All code-paths ensure that the result overflows neither an usize, nor an u64.
        // Walk to the termination record and read its extra reserve info.
        let mut used_encoded_len = 0;
        for entry in self.iter() {
            used_encoded_len += ENTRY_HEADER_LEN + entry.1.len();
        }
        let termination_record_begin = used_encoded_len;

        let termination_record_data_len = match <&[u8; mem::size_of::<EntryDataLenType>()]>::try_from(
            &self.encoded[termination_record_begin + UUID_LEN
                ..termination_record_begin + UUID_LEN + mem::size_of::<EntryDataLenType>()],
        )
        .ok()
        {
            Some(termination_record_data_len) => EntryDataLenType::from_le_bytes(*termination_record_data_len),
            None => {
                // This cannot happen. Avoid returning an error from this function and just
                // pretend to return something.
                debug_assert!(false);
                0
            }
        };

        let extra_reserve = if termination_record_data_len == 0 {
            0
        } else {
            debug_assert_eq!(termination_record_data_len, mem::size_of::<u64>() as EntryDataLenType);
            match <&[u8; mem::size_of::<u64>()]>::try_from(
                &self.encoded[termination_record_begin + ENTRY_HEADER_LEN
                    ..termination_record_begin + ENTRY_HEADER_LEN + mem::size_of::<u64>()],
            )
            .ok()
            {
                Some(extra_reserve) => u64::from_le_bytes(*extra_reserve),
                None => {
                    // This cannot happen. Avoid returning an error from this function and just
                    // pretend to return something.
                    debug_assert!(false);
                    0
                }
            }
        };

        used_encoded_len as u64 + ENTRY_HEADER_LEN as u64 + termination_record_data_len as u64 + extra_reserve
    }

    /// Obtain an [`ExtentsLayout`](extents_layout::ExtentsLayout) suitable for
    /// one update group of [`AuxFsMetadata`] extents.
    ///
    /// The returned [`ExtentsLayout`](extents_layout::ExtentsLayout) instance
    /// tracks all the constraints applying to the [`AuxFsMetadata`]
    /// extents.
    ///
    /// # Arguments:
    ///
    /// * `io_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::io_block_allocation_blocks_log2`].
    /// * `auth_tree_data_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::auth_tree_data_block_allocation_blocks_log2`].
    /// * `allocation_block_size_128b_log2` - Verbatim value of
    ///   [`ImageLayout::allocation_block_size_128b_log2`].
    ///
    /// # See also:
    ///
    /// * [`extents_allocation_request()`](Self::extents_allocation_request).
    pub(crate) fn extents_layout(
        io_block_allocation_blocks_log2: u8,
        auth_tree_data_block_allocation_blocks_log2: u8,
        allocation_block_size_128b_log2: u8,
    ) -> Result<extents_layout::ExtentsLayout, NvFsError> {
        let max_extent_allocation_blocks = AllocBlockCount::from(EncodedExtentPtr::MAX_EXTENT_ALLOCATION_BLOCKS);
        // The first extent stores the AuxFsMetadataExtentsUpdateGroupState.
        let extents_hdr_len = mem::size_of::<u8>() as u32;
        // Any extent has
        // - the integrity protections and
        // - a pair of EncodedExtentPtrs to the next and next but one extents
        //   respectively.
        let extent_hdr_len =
            extent_integrity_protections_len(io_block_allocation_blocks_log2, allocation_block_size_128b_log2)
                + AuxFsMetadataEncodedExtentsPtrsPair::encoded_len();
        extents_layout::ExtentsLayout::new(
            Some(max_extent_allocation_blocks),
            io_block_allocation_blocks_log2.max(auth_tree_data_block_allocation_blocks_log2),
            0,
            extents_hdr_len,
            extent_hdr_len,
            // No alignment constraints on the payload.
            1,
            allocation_block_size_128b_log2,
        )
    }

    /// Determine an [`AuxFsMetadata`] extent's effective payload length.
    ///
    /// The result is guaranteed to be representable as an usize.
    ///
    /// # Arguments:
    ///
    /// * `extent` - The extent whose payload length to determine. It must be
    ///   compatible with the constraints from
    ///   [`extents_layout()`](Self::extents_layout), in particular its lengths
    ///   in units of Bytes must not exceed `usize::MAX`.
    /// * `is_update_group_head` - Whether or not the extent is the first within
    ///   a update group.
    /// * `io_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::io_block_allocation_blocks_log2`].
    /// * `allocation_block_size_128b_log2` - Verbatim value of
    ///   [`ImageLayout::allocation_block_size_128b_log2`].
    fn extent_payload_len(
        extent: &PhysicalAllocBlockRange,
        is_update_group_head: bool,
        io_block_allocation_blocks_log2: u8,
        allocation_block_size_128b_log2: u8,
    ) -> u64 {
        // The first extent stores the AuxFsMetadataExtentsUpdateGroupState.
        let extents_hdr_len = mem::size_of::<u8>() as u32;
        // Any extent has
        // - the integrity protections and
        // - a pair of EncodedExtentPtrs to the next and next but one extents
        //   respectively.
        let extent_hdr_len =
            extent_integrity_protections_len(io_block_allocation_blocks_log2, allocation_block_size_128b_log2)
                + AuxFsMetadataEncodedExtentsPtrsPair::encoded_len();
        let extent_len = u64::from(extent.block_count()) << (allocation_block_size_128b_log2 as u32 + 7);
        extent_len
            - if is_update_group_head {
                extents_hdr_len as u64
            } else {
                0
            }
            - extent_hdr_len as u64
    }

    /// Create an [`ExtentsAllocationRequest`](alloc_bitmap::ExtentsAllocationRequest)
    /// for one group of [`AuxFsMetadata`] extents.
    ///
    /// # Arguments:
    ///
    /// * `io_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::io_block_allocation_blocks_log2`].
    /// * `auth_tree_data_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::auth_tree_data_block_allocation_blocks_log2`].
    /// * `allocation_block_size_128b_log2` - Verbatim value of
    ///   [`ImageLayout::allocation_block_size_128b_log2`].
    ///
    /// # See also:
    ///
    /// * [`extents_layout()`](Self::extents_layout).
    /// * [`storage_allocation_payload_length()`](Self::storage_allocation_payload_length).
    pub(crate) fn extents_allocation_request(
        &self,
        io_block_allocation_blocks_log2: u8,
        auth_tree_data_block_allocation_blocks_log2: u8,
        allocation_block_size_128b_log2: u8,
    ) -> Result<alloc_bitmap::ExtentsAllocationRequest, NvFsError> {
        Ok(alloc_bitmap::ExtentsAllocationRequest::new(
            self.storage_allocation_payload_length(),
            &Self::extents_layout(
                io_block_allocation_blocks_log2,
                auth_tree_data_block_allocation_blocks_log2,
                allocation_block_size_128b_log2,
            )?,
        ))
    }

    /// Determine the location of the [`AuxFsMetadata`] stored alongside an
    /// [`MkFsInfoHeader`](image_header::MkFsInfoHeader), if any.
    ///
    /// The returned range is guaranteed to be aligned to the [IO Block
    /// size](ImageLayout::io_block_allocation_blocks_log2).
    ///
    /// # Arguments:
    ///
    /// * `mkfsinfo_header_location` - Location of the
    ///   [`MkFsInfoHeader`](image_header::MkFsInfoHeader) on storage, i.e.
    ///   either the primary location at offset zero or
    ///   [`MkFsInfoHeader::physical_backup_location()`](image_header::MkFsInfoHeader::physical_backup_location()).
    /// * `aux_fs_metadata_len` - The value of
    ///   [`MkFsInfoHeader::aux_fs_metadata_len`](image_header::MkFsInfoHeader::aux_fs_metadata_len).
    /// * `io_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::io_block_allocation_blocks_log2`].
    /// * `allocation_block_size_128b_log2` - Verbatim value of
    ///   [`ImageLayout::allocation_block_size_128b_log2`].
    pub(crate) fn mkfsinfo_physical_location(
        mkfsinfo_header_location: &PhysicalAllocBlockRange,
        aux_fs_metadata_len: u64,
        io_block_allocation_blocks_log2: u32,
        allocation_block_size_128b_log2: u32,
    ) -> Result<Option<PhysicalAllocBlockRange>, NvFsError> {
        // If there's no AuxFsMetadata at all, then it's not stored with a
        // MkFsInfoHeader.
        if aux_fs_metadata_len == 0 {
            return Ok(None);
        }

        // Accomodate for the checksum.
        let aux_fs_metadata_io_blocks = ((aux_fs_metadata_len
            .checked_add(checksum::CHECKSUM_LEN as u64)
            .ok_or(NvFsError::DimensionsNotSupported)?
            - 1)
            >> (io_block_allocation_blocks_log2 + allocation_block_size_128b_log2 + 7))
            + 1;
        // The result has the upper 6 bits clear, as per the computation right above.
        let aux_fs_metadata_allocation_blocks =
            AllocBlockCount::from(aux_fs_metadata_io_blocks << io_block_allocation_blocks_log2);

        // If the MkFsInfoHeader is located at beginning of the image, the AuxFsMetadata
        // is placed after it. Otherwise, if it's the backup copy, the AuxFsMetadata
        // is placed before it. In either case, the storage range occupied by the
        // AuxFsMetadata is aligned to the IO Block size.
        if u64::from(mkfsinfo_header_location.begin()) == 0 {
            // Align upwards to the next IO Block boundary. Does not overflow, the
            // MkFsInfoHeader::encoded_len() is representable in an u32.
            // Aligning upwards to the next IO Block boundary results in a value with the
            // upper 7 bits clear.
            let aux_fs_metadata_allocation_blocks_begin = PhysicalAllocBlockIndex::from(
                (((u64::from(mkfsinfo_header_location.end()) - 1) >> io_block_allocation_blocks_log2) + 1)
                    << io_block_allocation_blocks_log2,
            );
            // Adding two values with the most significant bits clear cannot overflow.
            let aux_fs_metadata_location = PhysicalAllocBlockRange::from((
                aux_fs_metadata_allocation_blocks_begin,
                aux_fs_metadata_allocation_blocks,
            ));
            if u64::from(aux_fs_metadata_location.end()) > (u64::MAX >> (allocation_block_size_128b_log2 + 7)) {
                // The end converted to units of Bytes would overflow an u64.
                return Err(NvFsError::from(FormatError::InvalidAuxFsMetadataSize));
            }
            Ok(Some(aux_fs_metadata_location))
        } else {
            // The MkFsInfoHeader is stored at the backup location. Place the AuxFsMetadata
            // right before it.
            let aux_fs_metadata_allocation_blocks_end = mkfsinfo_header_location
                .begin()
                .align_down(io_block_allocation_blocks_log2);
            if u64::from(aux_fs_metadata_allocation_blocks_end) < u64::from(aux_fs_metadata_allocation_blocks) {
                return Err(NvFsError::NoSpace);
            }

            Ok(Some(PhysicalAllocBlockRange::new(
                PhysicalAllocBlockIndex::from(
                    u64::from(aux_fs_metadata_allocation_blocks_end) - u64::from(aux_fs_metadata_allocation_blocks),
                ),
                aux_fs_metadata_allocation_blocks_end,
            )))
        }
    }
}

impl default::Default for AuxFsMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl cmp::PartialEq for AuxFsMetadata {
    fn eq(&self, other: &Self) -> bool {
        Iterator::eq(self.iter(), other.iter())
            && self.get_extra_reserve_capacity() == other.get_extra_reserve_capacity()
    }
}

impl cmp::Eq for AuxFsMetadata {}

/// [`Iterator`] returned by [`AuxFsMetadata::iter()`].
pub struct AuxFsMetadataIter<'a> {
    remaining_encoded: &'a [u8],
}

impl<'a> Iterator for AuxFsMetadataIter<'a> {
    type Item = (&'a [u8; 16], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining_encoded.is_empty() {
            return None;
        }

        // AuxFsMetadata::new() has validated the encoding format already, no need to
        // redo it from here.
        let entry_uuid = &self.remaining_encoded[..UUID_LEN];
        // Avoid returning an (internal) error from here: if the try_from() failed,
        // which it wouldn't, map it to None.
        let entry_uuid = <&[u8; UUID_LEN]>::try_from(entry_uuid).ok()?;
        // Is it the termination record with an "UUID" of all zeros?
        if entry_uuid.iter().all(|b| *b == 0) {
            return None;
        }
        self.remaining_encoded = &self.remaining_encoded[UUID_LEN..];

        let entry_data_len;
        (entry_data_len, self.remaining_encoded) = self.remaining_encoded.split_at(mem::size_of::<EntryDataLenType>());
        // Avoid returning an (internal) error from here: if the try_from() failed,
        // which it wouldn't, map it to None.
        let entry_data_len = EntryDataLenType::from_le_bytes(
            *<&[u8; mem::size_of::<EntryDataLenType>()]>::try_from(entry_data_len).ok()?,
        ) as usize;

        let entry_value;
        (entry_value, self.remaining_encoded) = self.remaining_encoded.split_at(entry_data_len);

        Some((entry_uuid, entry_value))
    }
}

/// Pair of pointers to [`AuxFsMetadata`] extents.
///
/// Pairs of [`AuxFsMetadata`] extent pointers are used for two different
/// purposes.
/// * For linking to the next and next but one extents in the circular chain.
///   Storing these two pointers allows for always reconstructing the circular
///   chain even in a situation where one of the member extents is invalid, i.e.
///   doesn't pass integrity protection validations due to a torn write. For
///   this use case, neither of the two pointers is `None`.
/// * In addition to that, an `AuxFsMetadataExtentsPtrsPair` are stored in the
///   mutable image header as well as from the journal log for referring to the
///   [`AuxFsMetadata`] update groups' heads, if any. In this use case the first
///   pointer may be   `None` only if the second one is as well.
///
/// # See also:
///
/// * [`AuxFsMetadataEncodedExtentsPtrsPair`].
pub struct AuxFsMetadataExtentsPtrsPair {
    ptrs: [Option<PhysicalAllocBlockRange>; 2],
}

impl AuxFsMetadataExtentsPtrsPair {
    /// Create a [`AuxFsMetadataExtentsPtrsPair`] with both pointers set to
    /// `None`.
    pub const fn new_nil() -> Self {
        Self { ptrs: [None; 2] }
    }

    /// Create a new [`AuxFsMetadataExtentsPtrsPair`] with specified pointer
    /// targets.
    ///
    /// Initialize the [`AuxFsMetadataExtentsPtrsPair`] to point to the pair of
    /// extents specified by `ptrs`, if any.
    ///
    /// # Arguments:
    ///
    /// * `ptrs` - The extents pair to point to. Neither of the extents'
    ///   [lengths](PhysicalAllocBlockRange::block_count) shall exceed
    ///   [`EncodedExtentPtr::MAX_EXTENT_ALLOCATION_BLOCKS`], or otherwise a
    ///   subsequent  [`encode()`](Self::encode) would fail.
    pub fn new(ptrs: Option<(PhysicalAllocBlockRange, Option<PhysicalAllocBlockRange>)>) -> Self {
        Self {
            ptrs: ptrs.map(|ptrs| [Some(ptrs.0), ptrs.1]).unwrap_or([None; 2]),
        }
    }

    /// Convert to an [`AuxFsMetadataEncodedExtentsPtrsPair`].
    ///
    /// The conversion will fail if either of the extents pointed to exceed
    /// [`EncodedExtentPtr::MAX_EXTENT_ALLOCATION_BLOCKS`] in length.
    pub fn encode(&self) -> Result<AuxFsMetadataEncodedExtentsPtrsPair, NvFsError> {
        let mut encoded = AuxFsMetadataEncodedExtentsPtrsPair::new_nil();
        for i in 0..self.ptrs.len() {
            encoded.ptrs[i] = EncodedExtentPtr::encode(self.ptrs[i].as_ref(), false)?;
        }

        Ok(encoded)
    }

    /// Convert from an [`AuxFsMetadataEncodedExtentsPtrsPair`].
    ///
    /// # Arguments:
    ///
    /// * `encoded` - The [`AuxFsMetadataEncodedExtentsPtrsPair`] to convert
    ///   from.
    /// * `io_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::io_block_allocation_blocks_log2`].
    /// * `auth_tree_data_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::auth_tree_data_block_allocation_blocks_log2`].
    /// * `allocation_block_size_128b_log2` - Verbatim value of
    ///   [`ImageLayout::allocation_block_size_128b_log2`].
    fn decode(
        encoded: &AuxFsMetadataEncodedExtentsPtrsPair,
        io_block_allocation_blocks_log2: u8,
        auth_tree_data_block_allocation_blocks_log2: u8,
        allocation_block_size_128b_log2: u8,
    ) -> Result<Self, NvFsError> {
        let mut result = Self::new_nil();
        for i in 0..result.ptrs.len() {
            result.ptrs[i] = match encoded.ptrs[i]
                .decode(allocation_block_size_128b_log2 as u32)
                .map_err(|e| {
                    if e == NvFsError::from(FormatError::InvalidExtents) {
                        NvFsError::from(FormatError::InvalidAuxFsMetadataExtent)
                    } else {
                        e
                    }
                })? {
                Some((_, true)) => {
                    // Indirect extents not allowed.
                    return Err(NvFsError::from(FormatError::InvalidAuxFsMetadataExtent));
                }
                Some((extent, false)) => {
                    // The extent's boundaries must be aligned to the larger of the IO Block and the
                    // Authentication tree data block size.
                    if !(u64::from(extent.begin()) | u64::from(extent.end())).is_aligned_pow2(
                        (io_block_allocation_blocks_log2 as u32)
                            .max(auth_tree_data_block_allocation_blocks_log2 as u32),
                    ) {
                        return Err(NvFsError::from(FormatError::UnalignedAuxFsMetadataExtent));
                    }

                    Some(extent)
                }
                None => None,
            };
        }

        // The pointer pair must be in canonical form.
        if result.ptrs[0].is_none() && result.ptrs[1].is_some() {
            return Err(NvFsError::from(FormatError::InvalidAuxFsMetadataExtent));
        }

        Ok(result)
    }
}

/// Encoded [`AuxFsMetadataExtentsPtrsPair`].
///
/// Intermediate representation of an [`AuxFsMetadataExtentsPtrsPair`] which can
/// get [encoded](Self::encode) to and [decoded](Self::decode) from byte slices.
///
/// See also:
///
/// * [`AuxFsMetadataExtentsPtrsPair::encode()`]
/// * [`AuxFsMetadataExtentsPtrsPair::decode()`]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuxFsMetadataEncodedExtentsPtrsPair {
    ptrs: [EncodedExtentPtr; 2],
}

impl AuxFsMetadataEncodedExtentsPtrsPair {
    /// Create a [`AuxFsMetadataEncodedExtentsPtrsPair`] corresponding to
    /// [`AuxFsMetadataExtentsPtrsPair::new_nil()`].
    pub fn new_nil() -> Self {
        Self {
            ptrs: [EncodedExtentPtr::encode_nil(); 2],
        }
    }

    /// Encoded length of a [`AuxFsMetadataEncodedExtentsPtrsPair`].
    pub const fn encoded_len() -> u32 {
        2 * EncodedExtentPtr::ENCODED_SIZE
    }

    /// Encode to a byte buffer.
    ///
    /// # Arguments:
    ///
    /// * `dst` - The buffer to encode into. Must have at least
    ///   [`encoded_len()`](Self::encoded_len) bytes left.
    pub fn encode<'a, DI: io_slices::IoSlicesMutIter<'a>>(&self, mut dst: DI) -> Result<(), NvFsError>
    where
        NvFsError: convert::From<DI::BackendIteratorError>,
    {
        for i in 0..self.ptrs.len() {
            (&mut dst)
                .take_exact(EncodedExtentPtr::ENCODED_SIZE as usize)
                .copy_from_iter(&mut io_slices::SingletonIoSlice::new(&*self.ptrs[i]).map_infallible_err())
                .map_err(|e| match e {
                    io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                        io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
                    },
                    io_slices::IoSlicesIterError::BackendIteratorError(e) => NvFsError::from(e),
                })?;
        }
        Ok(())
    }

    /// Decode from a byte buffer.
    ///
    /// # Arguments:
    ///
    /// * `src` - The buffer to decode from. Must have at least
    ///   [`encoded_len()`](Self::encoded_len) bytes left.
    pub fn decode<'a, SI: io_slices::IoSlicesIter<'a>>(mut src: SI) -> Result<Self, NvFsError>
    where
        NvFsError: convert::From<SI::BackendIteratorError>,
    {
        let mut result = Self {
            ptrs: [EncodedExtentPtr::encode_nil(); 2],
        };
        for i in 0..result.ptrs.len() {
            let mut encoded = [0u8; EncodedExtentPtr::ENCODED_SIZE as usize];
            let mut encoded_io_slice = io_slices::SingletonIoSliceMut::new(&mut encoded);
            (&mut encoded_io_slice).map_infallible_err().copy_from_iter(&mut src)?;
            if !encoded_io_slice.is_empty().map_err(|e| {
                // Infallible.
                match e {}
            })? {
                return Err(nvfs_err_internal!());
            }

            result.ptrs[i] = EncodedExtentPtr::from(encoded);
        }

        Ok(result)
    }
}

/// [`AuxFsMetadata`] update group identifier.
///
/// In order to enable reliable offline [`AuxFsMetadata`] updates, the
/// (circular) extent list is partitioned into (up to) two groups, with at most
/// one of them being under write at any given point in time.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum AuxFsMetadataExtentsUpdateGroup {
    Group0 = 0,
    Group1 = 1,
}

/// An [`AuxFsMetadata`] update group's state encoded in its head extent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
enum AuxFsMetadataExtentsUpdateGroupState {
    /// The update group is inactive.
    Inactive = 0u8,
    /// The update group is active.
    Active = 1u8,
    /// The update group is active, but might require a storage reallocation.
    ///
    /// Set from [offline updates], i.e. updates without the filesystem key, as
    /// a hint that a reallocation is needed in order to reestablish the
    /// [extra reserve capacity](AuxFsMetadata::set_extra_reserve_capacity).
    ActiveReallocationNeeded = 2u8,
}

impl AuxFsMetadataExtentsUpdateGroupState {
    const AUX_FS_METADATA_EXTENTS_UPDATE_GROUP_STATE_INACTIVE_VALUE: u8 = Self::Inactive as u8;
    const AUX_FS_METADATA_EXTENTS_UPDATE_GROUP_STATE_ACTIVE_VALUE: u8 = Self::Active as u8;
    const AUX_FS_METADATA_EXTENTS_UPDATE_GROUP_STATE_ACTIVE_REALLOCATION_NEEDED_VALUE: u8 =
        Self::ActiveReallocationNeeded as u8;
}

impl convert::TryFrom<u8> for AuxFsMetadataExtentsUpdateGroupState {
    type Error = NvFsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            Self::AUX_FS_METADATA_EXTENTS_UPDATE_GROUP_STATE_INACTIVE_VALUE => Ok(Self::Inactive),
            Self::AUX_FS_METADATA_EXTENTS_UPDATE_GROUP_STATE_ACTIVE_VALUE => Ok(Self::Active),
            Self::AUX_FS_METADATA_EXTENTS_UPDATE_GROUP_STATE_ACTIVE_REALLOCATION_NEEDED_VALUE => {
                Ok(Self::ActiveReallocationNeeded)
            }
            _ => Err(NvFsError::from(FormatError::InvalidAuxFsMetadataExtentFormat)),
        }
    }
}

/// Internal representation of the [`AuxFsMetadata`] extents state returned by
/// [`DoReadAuxFsMetadataFuture`].
struct AuxFsMetadataExtents {
    /// The complete sequence of extents allocated to [`AuxFsMetadata`] storage.
    ///
    /// [Update group 0](AuxFsMetadataExtentsUpdateGroup::Group0)'s extents are
    /// found at the beginning in the sequence, [update group
    /// 1](AuxFsMetadataExtentsUpdateGroup::Group1), if any, starts at index
    /// [`update_group1_extents_begin`](Self::update_group1_extents_begin).
    extents: PhysicalExtents,
    /// Starting position of [update group
    /// 1](AuxFsMetadataExtentsUpdateGroup::Group1)'s extents in
    /// [`extents`](Self::extents), if any.
    update_group1_extents_begin: Option<usize>,
    /// The [update group](AuxFsMetadataExtentsUpdateGroup) currently considered
    /// active.
    ///
    /// Note that there is always an active [update
    /// group](AuxFsMetadataExtentsUpdateGroup) on storage at any given
    /// point in time. It might not be known though in case
    /// [`AuxFsMetadataExtents`] have been obtained from a
    /// [`DoReadAuxFsMetadataFuture`]
    /// [instantiated](DoReadAuxFsMetadataFuture::new()) with
    /// `find_extents_only` set and `validate_all_extents` unset.
    active_update_group: Option<AuxFsMetadataExtentsUpdateGroup>,
    /// Index of the extent in [`extents`](Self::extents) failing tier 0
    /// integrity protections verification, if any.
    ///
    /// Note that there can be at most one such extent on storage at any given
    /// point in time.
    ///
    /// If the [`AuxFsMetadataExtents`] have been obtained from a
    /// [`DoReadAuxFsMetadataFuture`]
    /// [instantiated](DoReadAuxFsMetadataFuture::new()) with
    /// `validate_all_extents` unset, then `invalid_extent_index` cannot be
    /// relied upon.
    invalid_extent_index: Option<usize>,

    /// Whether a storage reallocation might be needed.
    ///
    /// Set upon encountering a state of
    /// [`AuxFsMetadataExtentsUpdateGroupState::ActiveReallocationNeeded`] for
    /// the [`active_update_group`](Self::active_update_group).
    ///
    /// If the [`AuxFsMetadataExtents`] have been obtained from a
    /// [`DoReadAuxFsMetadataFuture`]
    /// [instantiated](DoReadAuxFsMetadataFuture::new()) with
    /// `find_extents_only` set, then `extents_reallocation_needed` cannot
    /// be relied upon.
    extents_reallocation_needed: bool,
}

impl AuxFsMetadataExtents {
    fn new() -> Self {
        Self {
            extents: PhysicalExtents::new(),
            update_group1_extents_begin: None,
            active_update_group: None,
            invalid_extent_index: None,
            extents_reallocation_needed: false,
        }
    }
}

impl default::Default for AuxFsMetadataExtents {
    fn default() -> Self {
        Self::new()
    }
}

/// Common internal [`AuxFsMetadata`] extents reading primitive.
///
/// Walk and read the circular list of [`AuxFsMetadata`] extents on a (fully
/// formatted) filesystem instance.
///
/// `DoReadAuxFsMetadataFuture` provides fine-grained control over the degree to
/// which the [`AuxFsMetadata`] extents get examined and validated.
struct DoReadAuxFsMetadataFuture<B: blkdev::NvBlkDev> {
    fut_state: DoReadAuxFsMetadataFutureState<B>,
    update_groups_heads: AuxFsMetadataExtentsPtrsPair,
    find_extents_only: bool,
    validate_all_extents: bool,
    io_block_allocation_blocks_log2: u8,
    auth_tree_data_block_allocation_blocks_log2: u8,
    allocation_block_size_128b_log2: u8,
    aux_fs_metadata_extents: AuxFsMetadataExtents,
    aux_fs_metadata: Vec<u8>,
}

/// Internal [`DoReadAuxFsMetadataFuture::poll()`] state-machine state.
enum DoReadAuxFsMetadataFutureState<B: blkdev::NvBlkDev> {
    Init {
        update_groups_heads: AuxFsMetadataEncodedExtentsPtrsPair,
    },
    ReadExtentPrepare {
        cur_update_group: AuxFsMetadataExtentsUpdateGroup,
        extent: PhysicalAllocBlockRange,
        expected_next_extent: Option<PhysicalAllocBlockRange>,
        read_full: bool,
    },
    ReadExtent {
        read_fut: blkdev::helpers::NvBlkDevReadRegionFuture<B, FixedVec<u8, 7>>,
        cur_update_group: AuxFsMetadataExtentsUpdateGroup,
        expected_next_extent: Option<PhysicalAllocBlockRange>,
    },
    DecodeAuxFsMetadata,
    Done,
}

impl<B: blkdev::NvBlkDev> DoReadAuxFsMetadataFuture<B> {
    /// Instantiate a [`DoReadAuxFsMetadataFuture`].
    ///
    /// Depending on the use case, certain actions may be skipped when
    /// examining the [`AuxFsMetadata`] extents.
    /// The returned [`AuxFsMetadataExtents::extents`] are always complete,
    /// and the [`AuxFsMetadataExtents::update_group1_extents_begin`] set to the
    /// correct position, if any. If the `find_extents_only` argument is set,
    /// only the sequence of extents storing the [`AuxFsMetadata`] will get
    /// collected and returned, but
    /// no [`AuxFsMetadata`] will actually get read and decoded. In this case
    /// the returned [`AuxFsMetadata`] instance is trivial.
    /// If the `validate_all_extents` argument is unset, the returned
    /// [`AuxFsMetadataExtents::invalid_extent_index`] is not guaranteed to
    /// be comprehensive. If `find_extents_only` is set and
    /// `validate_all_extents` is unset,
    /// [`AuxFsMetadataExtents::active_update_group`] may be `None` even if
    /// there is actually an active update group on storage.
    ///
    /// # Arguments:
    ///
    /// * `update_groups_heads` - Pointers to the respective head extents of the
    ///   two update groups within the circular extent chain on storage, if any.
    /// * `find_extents_only` - If `true`, the [`AuxFsMetadata`] contents will
    ///   not get read and decoded. A trivial, empty [`AuxFsMetadata`] instance
    ///   will get returned from [`poll()`](Self::poll) in this case.
    /// * `validate_all_extents` - If set, all extents on the circular list are
    ///   subject to [tier 0 integrity protection
    ///   verification](extent_tier0_integrity_protection_verify_and_remove).
    ///   Otherwise some extents may not get read from storage as an
    ///   optimization.
    /// * `io_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::io_block_allocation_blocks_log2`].
    /// * `auth_tree_data_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::auth_tree_data_block_allocation_blocks_log2`].
    /// * `allocation_block_size_128b_log2` - Verbatim value of
    ///   [`ImageLayout::allocation_block_size_128b_log2`].
    fn new(
        update_groups_heads: AuxFsMetadataEncodedExtentsPtrsPair,
        find_extents_only: bool,
        validate_all_extents: bool,
        io_block_allocation_blocks_log2: u8,
        auth_tree_data_block_allocation_blocks_log2: u8,
        allocation_block_size_128b_log2: u8,
    ) -> Self {
        Self {
            fut_state: DoReadAuxFsMetadataFutureState::Init { update_groups_heads },
            update_groups_heads: AuxFsMetadataExtentsPtrsPair { ptrs: [None; 2] },
            find_extents_only,
            validate_all_extents,
            io_block_allocation_blocks_log2,
            auth_tree_data_block_allocation_blocks_log2,
            allocation_block_size_128b_log2,
            aux_fs_metadata_extents: AuxFsMetadataExtents::new(),
            aux_fs_metadata: Vec::new(),
        }
    }
}

impl<B: blkdev::NvBlkDev> blkdev::NvBlkDevFuture<B> for DoReadAuxFsMetadataFuture<B> {
    type Output = Result<(AuxFsMetadataExtents, AuxFsMetadata), NvFsError>;

    fn poll(self: pin::Pin<&mut Self>, blkdev: &B, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                DoReadAuxFsMetadataFutureState::Init { update_groups_heads } => {
                    this.update_groups_heads = match AuxFsMetadataExtentsPtrsPair::decode(
                        update_groups_heads,
                        this.io_block_allocation_blocks_log2,
                        this.auth_tree_data_block_allocation_blocks_log2,
                        this.allocation_block_size_128b_log2,
                    ) {
                        Ok(update_groups_heads) => update_groups_heads,
                        Err(e) => {
                            this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };

                    match this.update_groups_heads.ptrs[0].as_ref() {
                        Some(update_group0_head) => {
                            // Validate the head extents' lengths.
                            let max_supported_extent_allocation_blocks = AllocBlockCount::from(
                                u64::try_from(usize::MAX).unwrap_or(u64::MAX)
                                    >> (this.allocation_block_size_128b_log2 as u32 + 7),
                            );
                            let min_group_head_extent_allocation_blocks = match AuxFsMetadata::extents_layout(
                                this.io_block_allocation_blocks_log2,
                                this.auth_tree_data_block_allocation_blocks_log2,
                                this.allocation_block_size_128b_log2,
                            ) {
                                Ok(extents_layout) => extents_layout.extent_payload_len_to_allocation_blocks(0, true).0,
                                Err(e) => {
                                    this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                    return task::Poll::Ready(Err(e));
                                }
                            };
                            if update_group0_head.block_count() > max_supported_extent_allocation_blocks {
                                this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::DimensionsNotSupported));
                            } else if update_group0_head.block_count() < min_group_head_extent_allocation_blocks {
                                this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(
                                    FormatError::InvalidAuxFsMetadataExtent,
                                )));
                            } else if !(u64::from(update_group0_head.begin()) | u64::from(update_group0_head.end()))
                                .is_aligned_pow2(
                                    (this.io_block_allocation_blocks_log2 as u32)
                                        .max(this.auth_tree_data_block_allocation_blocks_log2 as u32),
                                )
                            {
                                this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(
                                    FormatError::UnalignedAuxFsMetadataExtent,
                                )));
                            }

                            if let Some(update_group1_head) = this.update_groups_heads.ptrs[1].as_ref() {
                                if update_group1_head.begin() == update_group0_head.begin() {
                                    // The two group heads must be different.
                                    this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                    return task::Poll::Ready(Err(NvFsError::from(
                                        FormatError::InconsistentAuxFsMetadataExtentsChain,
                                    )));
                                } else if update_group1_head.block_count() > max_supported_extent_allocation_blocks {
                                    this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                    return task::Poll::Ready(Err(NvFsError::DimensionsNotSupported));
                                } else if update_group1_head.block_count() < min_group_head_extent_allocation_blocks {
                                    this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                    return task::Poll::Ready(Err(NvFsError::from(
                                        FormatError::InvalidAuxFsMetadataExtent,
                                    )));
                                } else if !(u64::from(update_group1_head.begin()) | u64::from(update_group1_head.end()))
                                    .is_aligned_pow2(
                                        (this.io_block_allocation_blocks_log2 as u32)
                                            .max(this.auth_tree_data_block_allocation_blocks_log2 as u32),
                                    )
                                {
                                    this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                    return task::Poll::Ready(Err(NvFsError::from(
                                        FormatError::UnalignedAuxFsMetadataExtent,
                                    )));
                                }
                            }

                            this.fut_state = DoReadAuxFsMetadataFutureState::ReadExtentPrepare {
                                cur_update_group: AuxFsMetadataExtentsUpdateGroup::Group0,
                                extent: *update_group0_head,
                                expected_next_extent: None,
                                read_full: !this.find_extents_only,
                            };
                        }
                        None => {
                            // No AuxFsMetadata, all done.
                            debug_assert!(this.update_groups_heads.ptrs[1].is_none());
                            this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                            return task::Poll::Ready(Ok((AuxFsMetadataExtents::new(), AuxFsMetadata::new())));
                        }
                    }
                }
                DoReadAuxFsMetadataFutureState::ReadExtentPrepare {
                    cur_update_group,
                    extent,
                    expected_next_extent,
                    read_full,
                } => {
                    // When here, it's been checked that
                    // - the next_extent is aligned to the larger of the IO Block and Authentication
                    //   Tree Data Block size,
                    // - and its length in units of Bytes is representable as an usize,
                    // - and its length is at least the minimum size required for the extent type
                    //   (head or tail).

                    // Check for (unexpected) loops.
                    for processed_extent in this.aux_fs_metadata_extents.extents.iter() {
                        if extent.begin() == processed_extent.begin() {
                            this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(
                                FormatError::InconsistentAuxFsMetadataExtentsChain,
                            )));
                        }
                    }

                    if let Some(insertion_pos) = this
                        .aux_fs_metadata_extents
                        .update_group1_extents_begin
                        .filter(|_| *cur_update_group == AuxFsMetadataExtentsUpdateGroup::Group0)
                    {
                        // Group 1 has been read already (update_group1_extents_begin is set), and
                        // we're currently in group 0. This can happen if the group 0 head didn't
                        // pass integrity protection validations, therefore group 1 had been read
                        // first and we cycled back into group 0. Insert the group 0 extent
                        // right before the group 1 extents.
                        debug_assert_eq!(this.aux_fs_metadata_extents.invalid_extent_index, Some(0));
                        // Re-reading the group 0 head extent already known to be invalid should not
                        // have been attempted.
                        debug_assert_ne!(insertion_pos, 0);
                        if let Err(e) = this
                            .aux_fs_metadata_extents
                            .extents
                            .insert_extent(insertion_pos, extent, true)
                        {
                            this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        debug_assert_eq!(
                            this.aux_fs_metadata_extents.extents.get_extent_range(0).begin(),
                            this.update_groups_heads.ptrs[0].as_ref().unwrap().begin()
                        );
                        this.aux_fs_metadata_extents.update_group1_extents_begin = Some(insertion_pos + 1);
                    } else {
                        // Either we're in group 0 and group 1 hasn't been
                        // entered yet or group 0 has been completed and we're
                        // in group 1.
                        if this.aux_fs_metadata_extents.update_group1_extents_begin.is_none()
                            && *cur_update_group == AuxFsMetadataExtentsUpdateGroup::Group1
                        {
                            // Just entered group 1.
                            debug_assert_eq!(
                                extent.begin(),
                                this.update_groups_heads.ptrs[1].as_ref().unwrap().begin()
                            );
                            this.aux_fs_metadata_extents.update_group1_extents_begin =
                                Some(this.aux_fs_metadata_extents.extents.len());
                        }

                        if let Err(e) = this.aux_fs_metadata_extents.extents.push_extent(extent, true) {
                            this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    }

                    let read_fut = if *read_full {
                        // See remark above, the cast to usize doesn't overflow.
                        let extent_buf = match FixedVec::new_with_default(
                            (u64::from(extent.block_count()) << (this.allocation_block_size_128b_log2 as u32 + 7))
                                as usize,
                        ) {
                            Ok(extent_buf) => extent_buf,
                            Err(e) => {
                                this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(e)));
                            }
                        };
                        blkdev::helpers::NvBlkDevReadRegionFuture::new(
                            u64::from(extent.begin()),
                            u64::from(extent.block_count()),
                            this.allocation_block_size_128b_log2,
                            extent_buf,
                            0,
                            this.io_block_allocation_blocks_log2
                                .max(this.auth_tree_data_block_allocation_blocks_log2)
                                + this.allocation_block_size_128b_log2,
                        )
                    } else {
                        // Only the first, tier0-protected 128B where the extent's chain pointers
                        // and, for group heads, the AuxFsMetadataExtentsUpdateGroupState is stored,
                        // are needed.
                        let extent_buf = match FixedVec::new_with_default(128) {
                            Ok(extent_buf) => extent_buf,
                            Err(e) => {
                                this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(e)));
                            }
                        };
                        // The shift does not overflow, EncodedExtentPtr::decode() verifies that the
                        // extent is within bounds.
                        blkdev::helpers::NvBlkDevReadRegionFuture::new(
                            u64::from(extent.begin()) << (this.allocation_block_size_128b_log2 as u32),
                            1,
                            0,
                            extent_buf,
                            0,
                            0,
                        )
                    };
                    this.fut_state = DoReadAuxFsMetadataFutureState::ReadExtent {
                        read_fut,
                        cur_update_group: *cur_update_group,
                        expected_next_extent: *expected_next_extent,
                    };
                }
                DoReadAuxFsMetadataFutureState::ReadExtent {
                    read_fut,
                    cur_update_group,
                    expected_next_extent,
                } => {
                    let mut extent_buf = match blkdev::NvBlkDevFuture::poll(pin::Pin::new(read_fut), blkdev, cx) {
                        task::Poll::Ready(Ok((extent_buf, Ok(())))) => extent_buf,
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                            this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let is_first_extent_in_update_group = match this.aux_fs_metadata_extents.update_group1_extents_begin
                    {
                        Some(update_group1_extents_begin) => match *cur_update_group {
                            AuxFsMetadataExtentsUpdateGroup::Group0 => {
                                // Group 0 gets read after group 1. This can only happen if
                                // the group 0 extent head didn't pass integrity protections
                                // and therefore group 1 had to get read first, circling back into
                                // group 0.
                                // Re-reading the group 0 head, known to be invalid, shouldn't have been
                                // attempted.
                                debug_assert!(update_group1_extents_begin > 1);
                                false
                            }
                            AuxFsMetadataExtentsUpdateGroup::Group1 => {
                                update_group1_extents_begin == this.aux_fs_metadata_extents.extents.len() - 1
                            }
                        },
                        None => {
                            debug_assert_eq!(*cur_update_group, AuxFsMetadataExtentsUpdateGroup::Group0);
                            debug_assert!(!this.aux_fs_metadata_extents.extents.is_empty());
                            this.aux_fs_metadata_extents.extents.len() == 1
                        }
                    };

                    let integrity_protections_offset = AuxFsMetadataEncodedExtentsPtrsPair::encoded_len() as usize
                        + if is_first_extent_in_update_group {
                            mem::size_of::<u8>()
                        } else {
                            0
                        };

                    // The extent's header fields, i.e. the chain pointers and, for head extents,
                    // the AuxFsMetadataExtentsUpdateGroupState are stored in the tier 0
                    // integrity protection realm.
                    let (is_coherent, tier0_integrity_state) = match extent_tier0_integrity_protection_verify_and_remove(
                        io_slices::SingletonIoSliceMut::new(&mut extent_buf),
                        0,
                        integrity_protections_offset,
                    ) {
                        Ok((is_coherent, tier0_integrity_state)) => (is_coherent, tier0_integrity_state),
                        Err(e) => {
                            this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };

                    this.fut_state = if !is_coherent {
                        // Cannot have more than one extent in incoherent state.
                        if this.aux_fs_metadata_extents.invalid_extent_index.is_some() {
                            this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(
                                FormatError::IncoherentAuxFsMetadataExtents,
                            )));
                        }

                        // No other incoherent extent so far means that if group 1 has been entered,
                        // then group 0 had been completed, and we did not
                        // circle back to it.
                        debug_assert_eq!(
                            this.aux_fs_metadata_extents.update_group1_extents_begin.is_some(),
                            *cur_update_group == AuxFsMetadataExtentsUpdateGroup::Group1,
                        );

                        this.aux_fs_metadata_extents.invalid_extent_index =
                            Some(this.aux_fs_metadata_extents.extents.len() - 1);

                        if this.aux_fs_metadata_extents.extents.len() == 1 {
                            // The group 0 head is incoherent. Switch to group 1, if any, and eventually
                            // circle back to group 0.
                            debug_assert!(this.aux_fs_metadata_extents.active_update_group.is_none());
                            debug_assert_eq!(*cur_update_group, AuxFsMetadataExtentsUpdateGroup::Group0);
                            this.aux_fs_metadata_extents.extents.remove_extent(0);
                            match this.update_groups_heads.ptrs[1].as_ref() {
                                Some(update_group1_head) => DoReadAuxFsMetadataFutureState::ReadExtentPrepare {
                                    cur_update_group: AuxFsMetadataExtentsUpdateGroup::Group1,
                                    extent: *update_group1_head,
                                    expected_next_extent: None,
                                    read_full: !this.find_extents_only,
                                },
                                None => {
                                    this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                    return task::Poll::Ready(Err(NvFsError::from(
                                        FormatError::IncoherentAuxFsMetadataExtents,
                                    )));
                                }
                            }
                        } else {
                            debug_assert!(this.aux_fs_metadata_extents.extents.len() > 1);
                            if this.aux_fs_metadata_extents.active_update_group == Some(*cur_update_group) {
                                // If a group is active, then it must not have any invalid extents.
                                this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(
                                    FormatError::IncoherentAuxFsMetadataExtents,
                                )));
                            }
                            match expected_next_extent {
                                None => {
                                    // The extent prior to the current, incoherent one had not been read (otherwise
                                    // expected_next_extent would have been set to its next-but-one chain pointer).
                                    // Step back to that and follow its next-but-one pointer to
                                    // skip over the current, incoherent one.
                                    let incoherent_extent = this
                                        .aux_fs_metadata_extents
                                        .extents
                                        .get_extent_range(this.aux_fs_metadata_extents.extents.len() - 1);
                                    this.aux_fs_metadata_extents.extents.pop_extent();
                                    if this.update_groups_heads.ptrs[1]
                                        .as_ref()
                                        .map(|update_group1_head| {
                                            update_group1_head.begin() == incoherent_extent.begin()
                                        })
                                        .unwrap_or(false)
                                    {
                                        // We're stepping back into group 0.
                                        debug_assert_eq!(*cur_update_group, AuxFsMetadataExtentsUpdateGroup::Group1);
                                        *cur_update_group = AuxFsMetadataExtentsUpdateGroup::Group0;
                                        this.aux_fs_metadata_extents.update_group1_extents_begin = None;
                                    }

                                    // Pop the last extent skipped over and to be read now. It will
                                    // get re-added from ReadExtentPrepare shortly.
                                    let skipped_extent = this
                                        .aux_fs_metadata_extents
                                        .extents
                                        .get_extent_range(this.aux_fs_metadata_extents.extents.len() - 1);
                                    if this.update_groups_heads.ptrs[1]
                                        .as_ref()
                                        .map(|update_group1_head| update_group1_head.begin() == skipped_extent.begin())
                                        .unwrap_or(false)
                                    {
                                        // The extent to be read is group 1's first extent.
                                        // Reset aux_fs_metadata_extents.update_group1_extents_begin, it will
                                        // get restored from ReadExtentPrepare shortly when the extent is to
                                        // get readded.
                                        debug_assert_eq!(*cur_update_group, AuxFsMetadataExtentsUpdateGroup::Group1);
                                        this.aux_fs_metadata_extents.update_group1_extents_begin = None;
                                    }

                                    // If the extent had been skipped over before, then it's full
                                    // contents certainly aren't needed.
                                    DoReadAuxFsMetadataFutureState::ReadExtentPrepare {
                                        cur_update_group: *cur_update_group,
                                        extent: skipped_extent,
                                        expected_next_extent: Some(incoherent_extent),
                                        read_full: false,
                                    }
                                }
                                Some(expected_next_extent) => {
                                    // The extent prior to the current, incoherent one had been read and
                                    // its next-but-one pointer is in expected_next_extent. Just skip
                                    // over the incoherent extent and read the next one instead.
                                    if this.update_groups_heads.ptrs[0]
                                        .as_ref()
                                        .map(|update_group0_head| {
                                            update_group0_head.begin() == expected_next_extent.begin()
                                        })
                                        .unwrap_or(false)
                                    {
                                        // Circling back into group 0. If there is a group 1, then
                                        // that has been processed and we're circling back from
                                        // there.
                                        debug_assert!(
                                            this.update_groups_heads.ptrs[1].is_none()
                                                || *cur_update_group == AuxFsMetadataExtentsUpdateGroup::Group1
                                        );
                                        // All done.
                                        DoReadAuxFsMetadataFutureState::DecodeAuxFsMetadata
                                    } else if this.update_groups_heads.ptrs[1]
                                        .as_ref()
                                        .map(|update_group1_head| {
                                            update_group1_head.begin() == expected_next_extent.begin()
                                        })
                                        .unwrap_or(false)
                                    {
                                        // Transitioning from group 0 into group 1.
                                        debug_assert_eq!(*cur_update_group, AuxFsMetadataExtentsUpdateGroup::Group0);
                                        // From what's been said above, because this is the first
                                        // invalid extent, we're entering group 1 for the first
                                        // time.
                                        debug_assert!(
                                            this.aux_fs_metadata_extents.update_group1_extents_begin.is_none()
                                        );
                                        // If we're entering a new group (group 1), then
                                        // chances are it's active and all its chained extents pass integrity
                                        // protections. Read it in full if it's contents might be needed.
                                        DoReadAuxFsMetadataFutureState::ReadExtentPrepare {
                                            cur_update_group: AuxFsMetadataExtentsUpdateGroup::Group1,
                                            extent: *expected_next_extent,
                                            expected_next_extent: None,
                                            read_full: !this.find_extents_only,
                                        }
                                    } else {
                                        DoReadAuxFsMetadataFutureState::ReadExtentPrepare {
                                            cur_update_group: *cur_update_group,
                                            extent: *expected_next_extent,
                                            expected_next_extent: None,
                                            read_full: false,
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        // The extent's tier 0 integrity protection have been validated.
                        // The extent's header fields are within the tier 0 integrity protection realm.
                        // Read them.
                        let chained_extents_ptrs = match AuxFsMetadataEncodedExtentsPtrsPair::decode(
                            io_slices::SingletonIoSlice::new(&extent_buf),
                        )
                        .and_then(|encoded_chained_extents_ptrs| {
                            AuxFsMetadataExtentsPtrsPair::decode(
                                &encoded_chained_extents_ptrs,
                                this.io_block_allocation_blocks_log2,
                                this.auth_tree_data_block_allocation_blocks_log2,
                                this.allocation_block_size_128b_log2,
                            )
                        }) {
                            Ok(AuxFsMetadataExtentsPtrsPair {
                                ptrs: [Some(next_extent), Some(next_next_extent)],
                            }) => [next_extent, next_next_extent],
                            Ok(_) => {
                                // The chain pointers are supposed to form a circular list,
                                // none may be NIL.
                                this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(
                                    FormatError::InconsistentAuxFsMetadataExtentsChain,
                                )));
                            }
                            Err(e) => {
                                this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                        };

                        // Validate the chained extents.
                        if let Some(expected_next_extent) = expected_next_extent {
                            if chained_extents_ptrs[0] != *expected_next_extent {
                                this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(
                                    FormatError::InconsistentAuxFsMetadataExtentsChain,
                                )));
                            }
                        }
                        let max_supported_extent_allocation_blocks = AllocBlockCount::from(
                            u64::try_from(usize::MAX).unwrap_or(u64::MAX)
                                >> (this.allocation_block_size_128b_log2 as u32 + 7),
                        );
                        let min_extent_allocation_blocks = match AuxFsMetadata::extents_layout(
                            this.io_block_allocation_blocks_log2,
                            this.auth_tree_data_block_allocation_blocks_log2,
                            this.allocation_block_size_128b_log2,
                        ) {
                            Ok(extents_layout) => {
                                extents_layout
                                    .extent_payload_len_to_allocation_blocks(
                                        if is_first_extent_in_update_group { 0 } else { 1 },
                                        is_first_extent_in_update_group,
                                    )
                                    .0
                            }
                            Err(e) => {
                                this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                        };
                        for chained_extent in chained_extents_ptrs.iter().skip(if expected_next_extent.is_some() {
                            // Next chained extent validated above already, next-but-one is remaining to do.
                            1
                        } else {
                            0
                        }) {
                            // If the chained extent is a head, then it must be an exact match.
                            match this
                                .update_groups_heads
                                .ptrs
                                .iter()
                                .flatten()
                                .find(|update_group_head| update_group_head.begin() == chained_extent.begin())
                            {
                                Some(matching_update_group_head) => {
                                    if chained_extent.end() != matching_update_group_head.end() {
                                        this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                        return task::Poll::Ready(Err(NvFsError::from(
                                            FormatError::InconsistentAuxFsMetadataExtentsChain,
                                        )));
                                    }
                                }
                                None => {
                                    if chained_extent.block_count() > max_supported_extent_allocation_blocks {
                                        this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                        return task::Poll::Ready(Err(NvFsError::DimensionsNotSupported));
                                    } else if chained_extent.block_count() < min_extent_allocation_blocks {
                                        this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                        return task::Poll::Ready(Err(NvFsError::from(
                                            FormatError::InvalidAuxFsMetadataExtent,
                                        )));
                                    } else if !(u64::from(chained_extent.begin()) | u64::from(chained_extent.end()))
                                        .is_aligned_pow2(
                                            (this.io_block_allocation_blocks_log2 as u32)
                                                .max(this.auth_tree_data_block_allocation_blocks_log2 as u32),
                                        )
                                    {
                                        this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                        return task::Poll::Ready(Err(NvFsError::from(
                                            FormatError::UnalignedAuxFsMetadataExtent,
                                        )));
                                    }
                                }
                            }
                        }

                        if is_first_extent_in_update_group {
                            let update_group_state = match AuxFsMetadataExtentsUpdateGroupState::try_from(
                                extent_buf[AuxFsMetadataEncodedExtentsPtrsPair::encoded_len() as usize],
                            ) {
                                Ok(update_group_state) => update_group_state,
                                Err(e) => {
                                    this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                    return task::Poll::Ready(Err(e));
                                }
                            };
                            debug_assert!(
                                this.aux_fs_metadata_extents.active_update_group.is_some()
                                    || this.aux_fs_metadata.is_empty()
                            );
                            // An active group 0 takes precedence over an active group 1.
                            // We did not circle back from group 1 into group 0, because the latter gets
                            // read only before the former in case the group 0 head extent is found invalid,
                            // and we're processing a head when here.
                            debug_assert_eq!(
                                this.aux_fs_metadata_extents.update_group1_extents_begin.is_some(),
                                *cur_update_group == AuxFsMetadataExtentsUpdateGroup::Group1
                            );
                            if update_group_state != AuxFsMetadataExtentsUpdateGroupState::Inactive
                                && this.aux_fs_metadata_extents.active_update_group.is_none()
                            {
                                this.aux_fs_metadata_extents.active_update_group = Some(*cur_update_group);
                                this.aux_fs_metadata_extents.extents_reallocation_needed = update_group_state
                                    == AuxFsMetadataExtentsUpdateGroupState::ActiveReallocationNeeded;
                            }
                        }

                        // Extract the encoded AuxFsMetadata payload part, if requested and in the
                        // active group.
                        if !this.find_extents_only
                            && this.aux_fs_metadata_extents.active_update_group == Some(*cur_update_group)
                        {
                            // Only tier 0 integrity protections had been validated and removed above.
                            // Validate the remainder.
                            let is_coherent = match extent_integrity_protections_verify_and_remove(
                                io_slices::SingletonIoSliceMut::new(&mut extent_buf),
                                0,
                                integrity_protections_offset,
                                Some(&tier0_integrity_state),
                                this.io_block_allocation_blocks_log2,
                                this.allocation_block_size_128b_log2,
                                blkdev.io_block_size_128b_log2(),
                            ) {
                                Ok((is_coherent, _)) => is_coherent,
                                Err(e) => {
                                    this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                    return task::Poll::Ready(Err(e));
                                }
                            };
                            if is_coherent {
                                let integrity_protections_len = extent_integrity_protections_len(
                                    this.io_block_allocation_blocks_log2,
                                    this.allocation_block_size_128b_log2,
                                );
                                // Does not overflow, as it's within extent_buf's bounds.
                                let payload_offset = integrity_protections_offset + integrity_protections_len as usize;

                                if let Err(e) = this.aux_fs_metadata.try_reserve(extent_buf.len() - payload_offset) {
                                    this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                    return task::Poll::Ready(Err(NvFsError::from(e)));
                                }
                                this.aux_fs_metadata.extend_from_slice(&extent_buf[payload_offset..]);
                            } else if !is_first_extent_in_update_group {
                                // If a group is active, then it must not have any invalid extents.
                                this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(
                                    FormatError::IncoherentAuxFsMetadataExtents,
                                )));
                            } else {
                                // This is the first extent in the group, and the group became
                                // marked as active due to its tier 0 integrity protections
                                // validation having passed just above. Undo. Don't set
                                // invalid_extent_index, as that's only relevant to the
                                // integrity of the chain, i.e. tier 0 protections.
                                this.aux_fs_metadata_extents.active_update_group = None;
                                this.aux_fs_metadata_extents.extents_reallocation_needed = false;
                            }
                        }

                        let (next_update_group, next_is_update_group_head) = if this.update_groups_heads.ptrs[0]
                            .as_ref()
                            .map(|update_group0_head| chained_extents_ptrs[0].begin() == update_group0_head.begin())
                            .unwrap_or(false)
                        {
                            (AuxFsMetadataExtentsUpdateGroup::Group0, true)
                        } else if this.update_groups_heads.ptrs[1]
                            .as_ref()
                            .map(|update_group1_head| chained_extents_ptrs[0].begin() == update_group1_head.begin())
                            .unwrap_or(false)
                        {
                            (AuxFsMetadataExtentsUpdateGroup::Group1, true)
                        } else {
                            (*cur_update_group, false)
                        };

                        let (next_next_update_group, next_next_is_update_group_head) = if this.update_groups_heads.ptrs
                            [0]
                        .as_ref()
                        .map(|update_group0_head| chained_extents_ptrs[1].begin() == update_group0_head.begin())
                        .unwrap_or(false)
                        {
                            (AuxFsMetadataExtentsUpdateGroup::Group0, true)
                        } else if this.update_groups_heads.ptrs[1]
                            .as_ref()
                            .map(|update_group1_head| chained_extents_ptrs[1].begin() == update_group1_head.begin())
                            .unwrap_or(false)
                        {
                            (AuxFsMetadataExtentsUpdateGroup::Group1, true)
                        } else {
                            (next_update_group, false)
                        };

                        // Group 1 must not circle back directly into itself without going through group
                        // 0.
                        if (*cur_update_group == AuxFsMetadataExtentsUpdateGroup::Group1
                            && next_update_group == AuxFsMetadataExtentsUpdateGroup::Group1
                            && next_is_update_group_head)
                            || (next_update_group == AuxFsMetadataExtentsUpdateGroup::Group1
                                && next_next_update_group == AuxFsMetadataExtentsUpdateGroup::Group1
                                && next_next_is_update_group_head)
                        {
                            this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(
                                FormatError::InconsistentAuxFsMetadataExtentsChain,
                            )));
                        }
                        // Likewise, if there is a group 1, then group 0 must
                        // not circle back directly into itself without going
                        // through group 1.
                        if this.update_groups_heads.ptrs[1].is_some()
                            && ((*cur_update_group == AuxFsMetadataExtentsUpdateGroup::Group0
                                && next_update_group == AuxFsMetadataExtentsUpdateGroup::Group0
                                && next_is_update_group_head)
                                || (next_update_group == AuxFsMetadataExtentsUpdateGroup::Group0
                                    && next_next_update_group == AuxFsMetadataExtentsUpdateGroup::Group0
                                    && next_next_is_update_group_head))
                        {
                            this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(
                                FormatError::InconsistentAuxFsMetadataExtentsChain,
                            )));
                        }

                        if next_is_update_group_head && next_update_group == AuxFsMetadataExtentsUpdateGroup::Group0 {
                            if this.aux_fs_metadata_extents.update_group1_extents_begin == Some(0) {
                                // If update_group1_extents_begin is set, then there must be a group 1.
                                debug_assert!(this.update_groups_heads.ptrs[1].is_some());
                                debug_assert_eq!(*cur_update_group, AuxFsMetadataExtentsUpdateGroup::Group1);
                                // The group 0 head extent had been found invalid, therefore we skipped
                                // to the group 1, have reached its end now and are about to circle
                                // back into group 0. Skip over the group 0 head extent already known to
                                // be invalid.
                                debug_assert_eq!(this.aux_fs_metadata_extents.invalid_extent_index, Some(0));
                                if let Err(e) = this.aux_fs_metadata_extents.extents.insert_extent(
                                    0,
                                    &chained_extents_ptrs[0],
                                    true,
                                ) {
                                    this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                    return task::Poll::Ready(Err(e));
                                }
                                this.aux_fs_metadata_extents.update_group1_extents_begin = Some(1);
                                if next_next_is_update_group_head {
                                    // Group 0 has only a single extent and it's the head. All done.
                                    debug_assert_eq!(next_next_update_group, AuxFsMetadataExtentsUpdateGroup::Group1);
                                    DoReadAuxFsMetadataFutureState::DecodeAuxFsMetadata
                                } else {
                                    debug_assert_eq!(next_next_update_group, AuxFsMetadataExtentsUpdateGroup::Group0);
                                    DoReadAuxFsMetadataFutureState::ReadExtentPrepare {
                                        cur_update_group: AuxFsMetadataExtentsUpdateGroup::Group0,
                                        extent: chained_extents_ptrs[1],
                                        expected_next_extent: None,
                                        read_full: false,
                                    }
                                }
                            } else {
                                // Group 0 and group 1, if any, have been processed and we're circling back into
                                // group 0. All done.
                                debug_assert_eq!(
                                    this.update_groups_heads.ptrs[1].is_some(),
                                    this.aux_fs_metadata_extents.update_group1_extents_begin.is_some()
                                );
                                debug_assert_eq!(
                                    chained_extents_ptrs[0],
                                    this.aux_fs_metadata_extents.extents.get_extent_range(0)
                                );
                                // The last extent's next-but-one chain pointer must link to the
                                // second extent, if there is one, or to the first one otherwise.
                                if chained_extents_ptrs[1]
                                    != this.aux_fs_metadata_extents.extents.get_extent_range(
                                        if this.aux_fs_metadata_extents.extents.len() >= 2 {
                                            1
                                        } else {
                                            0
                                        },
                                    )
                                {
                                    this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                    return task::Poll::Ready(Err(NvFsError::from(
                                        FormatError::InconsistentAuxFsMetadataExtentsChain,
                                    )));
                                }

                                DoReadAuxFsMetadataFutureState::DecodeAuxFsMetadata
                            }
                        } else if let Some(update_group1_extents_begin) = this
                            .aux_fs_metadata_extents
                            .update_group1_extents_begin
                            .filter(|_| next_is_update_group_head)
                        {
                            // As per the control flow logic, i.e. being here.
                            debug_assert_eq!(next_update_group, AuxFsMetadataExtentsUpdateGroup::Group1);
                            // Group 1 may not circle back into itself without going through group 0,
                            // as has been verified further above.
                            debug_assert_eq!(*cur_update_group, AuxFsMetadataExtentsUpdateGroup::Group0);
                            // Group 1 had been entered before, as per update_group1_extents_begin
                            // being Some(). This is possible only if the group 0 head had initially
                            // been found invalid, therefore we switched to group 1, traversed it,
                            // circled back from there into group 0, traversed that as well, and
                            // would now transition into group 1 once again. Terminate the walk.
                            debug_assert_eq!(this.aux_fs_metadata_extents.invalid_extent_index, Some(0));
                            // First verify that the group 0's last extent's next-but-one pointer is
                            // consistent.
                            if chained_extents_ptrs[1]
                                != this.aux_fs_metadata_extents.extents.get_extent_range(
                                    if this.aux_fs_metadata_extents.extents.len() > update_group1_extents_begin + 1 {
                                        update_group1_extents_begin + 1
                                    } else {
                                        0
                                    },
                                )
                            {
                                this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(
                                    FormatError::InconsistentAuxFsMetadataExtentsChain,
                                )));
                            }

                            DoReadAuxFsMetadataFutureState::DecodeAuxFsMetadata
                        } else {
                            // As per the control flow logic, i.e as per being here.
                            debug_assert!(
                                !next_is_update_group_head
                                    || (next_update_group == AuxFsMetadataExtentsUpdateGroup::Group1
                                        && this.aux_fs_metadata_extents.update_group1_extents_begin.is_none())
                            );
                            // The other direction also holds, because a transition from group 0
                            // to group 1 can happen only upon encountering the group 1 head.
                            debug_assert!(
                                this.aux_fs_metadata_extents.update_group1_extents_begin.is_some()
                                    || *cur_update_group == AuxFsMetadataExtentsUpdateGroup::Group0
                            );
                            debug_assert!(
                                !(next_update_group == AuxFsMetadataExtentsUpdateGroup::Group1
                                    && this.aux_fs_metadata_extents.update_group1_extents_begin.is_none())
                                    || next_is_update_group_head
                            );
                            // In summary, the next extent is a group head only if it starts group 1
                            // and group 1 hasn't been entered yet.
                            debug_assert_eq!(
                                next_is_update_group_head,
                                next_update_group == AuxFsMetadataExtentsUpdateGroup::Group1
                                    && this.aux_fs_metadata_extents.update_group1_extents_begin.is_none()
                            );
                            // And, because group 1 cannot circle back into itself without going
                            // through group 0, as has been verified further above:
                            debug_assert!(
                                !next_is_update_group_head
                                    || *cur_update_group == AuxFsMetadataExtentsUpdateGroup::Group0
                            );
                            let read_full = !this.find_extents_only
                                && (this.aux_fs_metadata_extents.active_update_group == Some(next_update_group)
                                    || (this.aux_fs_metadata_extents.active_update_group.is_none()
                                        && next_is_update_group_head));
                            let may_skip_extent = !this.validate_all_extents
                                && !read_full
                                && if this.aux_fs_metadata_extents.update_group1_extents_begin == Some(0)
                                    && next_next_is_update_group_head
                                {
                                    // The group 0 head extent had been found invalid, therefore we skipped
                                    // to the group 1, and are approaching its end now. In order to
                                    // be able to skip the invalid group 0 head when circling back,
                                    // the group 1 tail extent must not get skipped over.
                                    debug_assert_eq!(this.aux_fs_metadata_extents.invalid_extent_index, Some(0));
                                    // If update_group1_extents_begin is set, then there must be a group 1.
                                    debug_assert!(this.update_groups_heads.ptrs[1].is_some());
                                    // If update_group1_extents_begin is still at zero, none of group 0 has been
                                    // read and thus, we're still in group 1.
                                    debug_assert_eq!(*cur_update_group, AuxFsMetadataExtentsUpdateGroup::Group1);
                                    // If next_is_update_group_head had been set, then next_update_group
                                    // would necessarily have been
                                    // AuxFsMetadataExtentsUpdateGroup::Group1, as per being
                                    // here. However, we're currently in group 1, and group 1 cannot
                                    // loop back into itself without going through group 0, as
                                    // verified further above, a contradiction. Therefore
                                    // next_is_update_group_head is false.
                                    debug_assert!(!next_is_update_group_head);
                                    // If the next extent is not a group head, then it's in the same group as
                                    // the current one.
                                    debug_assert_eq!(next_update_group, AuxFsMetadataExtentsUpdateGroup::Group1);

                                    // Similar argument: the next extent is in group 1,
                                    // the next-but-one extent is a group head (as per the if-condition),
                                    // and group 1 cannot circle back into itself without going through group 0.
                                    debug_assert_eq!(next_next_update_group, AuxFsMetadataExtentsUpdateGroup::Group0);
                                    false
                                } else {
                                    true
                                };
                            if !may_skip_extent {
                                DoReadAuxFsMetadataFutureState::ReadExtentPrepare {
                                    cur_update_group: next_update_group,
                                    extent: chained_extents_ptrs[0],
                                    expected_next_extent: Some(chained_extents_ptrs[1]),
                                    read_full,
                                }
                            } else {
                                // Record the to be skipped extent.
                                if let Some(insertion_pos) = this
                                    .aux_fs_metadata_extents
                                    .update_group1_extents_begin
                                    .filter(|_| next_update_group == AuxFsMetadataExtentsUpdateGroup::Group0)
                                {
                                    // Group 1 has been read already (update_group1_extents_begin is set), and
                                    // we're currently in group 0. This can happen if the group 0 head didn't
                                    // pass integrity protection validations, therefore group 1 had been read
                                    // first and we cycled back into group 0. Insert the group 0 extent
                                    // right before the group 1 extents.
                                    debug_assert_eq!(this.aux_fs_metadata_extents.invalid_extent_index, Some(0));
                                    // When here, the next extent is not the group 0 head, as per
                                    // control flow logic, so that should have been inserted before.
                                    debug_assert!(!next_is_update_group_head);
                                    debug_assert_ne!(insertion_pos, 0);
                                    if let Err(e) = this.aux_fs_metadata_extents.extents.insert_extent(
                                        insertion_pos,
                                        &chained_extents_ptrs[0],
                                        true,
                                    ) {
                                        this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                        return task::Poll::Ready(Err(e));
                                    }
                                    debug_assert_eq!(
                                        this.aux_fs_metadata_extents.extents.get_extent_range(0).begin(),
                                        this.update_groups_heads.ptrs[0].as_ref().unwrap().begin()
                                    );
                                    this.aux_fs_metadata_extents.update_group1_extents_begin = Some(insertion_pos + 1);
                                } else {
                                    // Either we're in group 0 and group 1 hasn't been
                                    // entered yet or group 0 has been completed and we're
                                    // in group 1.
                                    if this.aux_fs_metadata_extents.update_group1_extents_begin.is_none()
                                        && next_update_group == AuxFsMetadataExtentsUpdateGroup::Group1
                                    {
                                        // Just entered group 1.
                                        debug_assert!(next_is_update_group_head);
                                        this.aux_fs_metadata_extents.update_group1_extents_begin =
                                            Some(this.aux_fs_metadata_extents.extents.len());
                                    }

                                    if let Err(e) = this
                                        .aux_fs_metadata_extents
                                        .extents
                                        .push_extent(&chained_extents_ptrs[0], true)
                                    {
                                        this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                                        return task::Poll::Ready(Err(e));
                                    }
                                }

                                // As per being here, i.e. may_skip_extent being true.
                                debug_assert!(
                                    !next_next_is_update_group_head
                                        || this.aux_fs_metadata_extents.update_group1_extents_begin != Some(0)
                                );
                                if next_next_is_update_group_head
                                    && (next_next_update_group == AuxFsMetadataExtentsUpdateGroup::Group0
                                        || this.aux_fs_metadata_extents.update_group1_extents_begin.is_some())
                                {
                                    // All done.
                                    DoReadAuxFsMetadataFutureState::DecodeAuxFsMetadata
                                } else {
                                    // As per the control flow logic.
                                    debug_assert!(
                                        !next_next_is_update_group_head
                                            || (next_next_update_group == AuxFsMetadataExtentsUpdateGroup::Group1
                                                && this.aux_fs_metadata_extents.update_group1_extents_begin.is_none())
                                    );
                                    // Group 1 cannot cycle back into itself without going though group 0, as has
                                    // been verified further above.
                                    debug_assert!(
                                        !next_next_is_update_group_head
                                            || next_update_group == AuxFsMetadataExtentsUpdateGroup::Group0
                                    );
                                    // If !find_extents_only and next_next_is_update_group_head are true, then
                                    // active_update_group is None. This follows
                                    // from may_skip_extent being true when here. In particular, active_update_group
                                    // is not equal to Some(next_update_group),
                                    // meaning with next_next_is_update_group_head being true by assumption, it's
                                    // either None or Some(Group1). But
                                    // next_next_is_update_group_head also implies
                                    // update_group1_extents_begin.is_none(), i.e. that group 1 hasn't been entered
                                    // yet, so active_update_group must be None.
                                    debug_assert!(
                                        this.find_extents_only
                                            || !next_next_is_update_group_head
                                            || this.aux_fs_metadata_extents.active_update_group.is_none()
                                                && this.aux_fs_metadata.is_empty()
                                    );

                                    let read_full = !this.find_extents_only && next_next_is_update_group_head;
                                    DoReadAuxFsMetadataFutureState::ReadExtentPrepare {
                                        cur_update_group: next_next_update_group,
                                        extent: chained_extents_ptrs[1],
                                        expected_next_extent: None,
                                        read_full,
                                    }
                                }
                            }
                        }
                    };
                }
                DoReadAuxFsMetadataFutureState::DecodeAuxFsMetadata => {
                    debug_assert!(
                        this.aux_fs_metadata_extents.active_update_group.is_some() || this.aux_fs_metadata.is_empty()
                    );
                    // There must be an active update group. If the extent walk had been such
                    // that it would have been found if one was there, bail out if there's none.
                    if (this.validate_all_extents || !this.find_extents_only)
                        && this.aux_fs_metadata_extents.active_update_group.is_none()
                    {
                        this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                        return task::Poll::Ready(Err(NvFsError::from(FormatError::IncoherentAuxFsMetadataExtents)));
                    }

                    debug_assert!(!this.find_extents_only || this.aux_fs_metadata.is_empty());
                    let aux_fs_metadata = match AuxFsMetadata::decode(mem::take(&mut this.aux_fs_metadata)) {
                        Ok(aux_fs_metadata) => aux_fs_metadata,
                        Err(e) => {
                            this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };

                    this.fut_state = DoReadAuxFsMetadataFutureState::Done;
                    return task::Poll::Ready(Ok((mem::take(&mut this.aux_fs_metadata_extents), aux_fs_metadata)));
                }
                DoReadAuxFsMetadataFutureState::Done => unreachable!(),
            }
        }
    }
}

/// Read the [`AuxFsMetadata`] from a (fully formatted) filesystem instance.
///
/// # See also:
///
/// * [`FindAuxFsMetadataExtentsFuture`].
pub struct ReadAuxFsMetadataFuture<B: blkdev::NvBlkDev> {
    read_fut: DoReadAuxFsMetadataFuture<B>,
}

impl<B: blkdev::NvBlkDev> ReadAuxFsMetadataFuture<B> {
    /// Instantiate a [`ReadAuxFsMetadataFuture`].
    ///
    /// # Arguments:
    ///
    /// * `update_groups_heads` - Pointers to the respective head extents of the
    ///   two update groups within the circular extent chain on storage, if any.
    /// * `image_layout` - The filesystem's [`ImageLayout`].
    pub fn new(update_groups_heads: AuxFsMetadataEncodedExtentsPtrsPair, image_layout: &ImageLayout) -> Self {
        Self {
            read_fut: DoReadAuxFsMetadataFuture::new(
                update_groups_heads,
                false,
                false,
                image_layout.io_block_allocation_blocks_log2,
                image_layout.auth_tree_data_block_allocation_blocks_log2,
                image_layout.allocation_block_size_128b_log2,
            ),
        }
    }
}

impl<B: blkdev::NvBlkDev> blkdev::NvBlkDevFuture<B> for ReadAuxFsMetadataFuture<B> {
    /// Output type of [`poll()`](Self::poll).
    ///
    /// On success, the locations of the [`AuxFsMetadata`]' extents on storage,
    /// a `bool` indicating whether a storage reallocation might be needed
    /// for reestablishing the [extra reserve
    /// capacity](AuxFsMetadata::set_extra_reserve_capacity), as well as the
    /// [`AuxFsMetadata`] itself will get returned.
    type Output = Result<(PhysicalExtents, bool, AuxFsMetadata), NvFsError>;

    fn poll(self: pin::Pin<&mut Self>, blkdev: &B, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        blkdev::NvBlkDevFuture::poll(pin::Pin::new(&mut this.read_fut), blkdev, cx).map(|result| {
            result.map(|(aux_fs_metadata_extents, aux_fs_metadata)| {
                (
                    aux_fs_metadata_extents.extents,
                    aux_fs_metadata_extents.extents_reallocation_needed,
                    aux_fs_metadata,
                )
            })
        })
    }
}

/// Find the [`AuxFsMetadata`] extents on a (fully formatted) filesystem
/// instance.
///
/// # See also:
///
/// * [`ReadAuxFsMetadataFuture`].
pub struct FindAuxFsMetadataExtentsFuture<B: blkdev::NvBlkDev> {
    read_fut: DoReadAuxFsMetadataFuture<B>,
}

impl<B: blkdev::NvBlkDev> FindAuxFsMetadataExtentsFuture<B> {
    /// Instantiate a [`FindAuxFsMetadataExtentsFuture`].
    ///
    /// # Arguments:
    ///
    /// * `update_groups_heads` - Pointers to the respective head extents of the
    ///   two update groups within the circular extent chain on storage, if any.
    /// * `image_layout` - The filesystem's [`ImageLayout`].
    pub fn new(update_groups_heads: AuxFsMetadataEncodedExtentsPtrsPair, image_layout: &ImageLayout) -> Self {
        Self {
            read_fut: DoReadAuxFsMetadataFuture::new(
                update_groups_heads,
                true,
                false,
                image_layout.io_block_allocation_blocks_log2,
                image_layout.auth_tree_data_block_allocation_blocks_log2,
                image_layout.allocation_block_size_128b_log2,
            ),
        }
    }
}

impl<B: blkdev::NvBlkDev> blkdev::NvBlkDevFuture<B> for FindAuxFsMetadataExtentsFuture<B> {
    /// Output type of [`poll()`](Self::poll).
    ///
    /// On success, the locations of the [`AuxFsMetadata`]' extents on
    /// storage will get returned.
    type Output = Result<PhysicalExtents, NvFsError>;

    fn poll(self: pin::Pin<&mut Self>, dev: &B, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        blkdev::NvBlkDevFuture::poll(pin::Pin::new(&mut this.read_fut), dev, cx).map(|result| {
            result.map(|(aux_fs_metadata_extents, _empty_aux_fs_metadata)| aux_fs_metadata_extents.extents)
        })
    }
}

/// Encode an [`AuxFsMetadata`] extent's chain pointers to the next and next but
/// one extents in the circular list.
///
/// # Arguments:
///
/// * `extent_buf` - The extent buffer to encode the chain pointers into. Must
///   be at least [`AuxFsMetadataEncodedExtentsPtrsPair::encoded_len()`] in
///   length.
/// * `extent_index` - Index of the extent in `aux_fs_metadata_extents`.
/// * `aux_fs_metadata_extents` - The (complete) sequence of extents allocated
///   to the [`AuxFsMetadata`] circular list.
fn aux_fs_metadata_extent_encode_chain_pointers(
    extent_buf: &mut [u8],
    extent_index: usize,
    aux_fs_metadata_extents: &PhysicalExtents,
) -> Result<(), NvFsError> {
    let mut i = extent_index + 1;
    if i == aux_fs_metadata_extents.len() {
        i = 0;
    }
    let next_chained_extent = aux_fs_metadata_extents.get_extent_range(i);
    i += 1;
    if i == aux_fs_metadata_extents.len() {
        i = 0;
    }
    let next_next_chained_extent = aux_fs_metadata_extents.get_extent_range(i);
    AuxFsMetadataExtentsPtrsPair::new(Some((next_chained_extent, Some(next_next_chained_extent))))
        .encode()
        .and_then(|chained_extents_ptrs| chained_extents_ptrs.encode(io_slices::SingletonIoSliceMut::new(extent_buf)))
}

/// Initialize some [`AuxFsMetadata`] extents from an [`AuxFsMetadata`] instance
/// without any coherence guarantees.
pub struct InitializeAuxFsMetadataExtentsFuture<B: blkdev::NvBlkDev> {
    fut_state: InitializeAuxFsMetadataExtentsFutureState<B>,
    cur_extent_index: usize,
    encoding_pos: usize,
}

/// Internal [`InitializeAuxFsMetadataExtentsFuture::poll()`] state-machine
/// state.
enum InitializeAuxFsMetadataExtentsFutureState<B: blkdev::NvBlkDev> {
    WriteExtentPrepare,
    WriteExtent {
        write_fut: blkdev::helpers::NvBlkDevWriteRegionFuture<B, FixedVec<u8, 7>>,
    },
    Done,
}

impl<B: blkdev::NvBlkDev> InitializeAuxFsMetadataExtentsFuture<B> {
    /// Instantiate a [`InitializeAuxFsMetadataExtentsFuture`].
    pub const fn new() -> Self {
        Self {
            fut_state: InitializeAuxFsMetadataExtentsFutureState::WriteExtentPrepare,
            cur_extent_index: 0,
            encoding_pos: 0,
        }
    }

    /// Poll the [`InitializeAuxFsMetadataExtentsFuture`] to completion.
    ///
    /// # Arguments:
    ///
    /// * `blkdev` - The filesystem's backing storage.
    /// * `aux_fs_metadata` - The [`AuxFsMetadata`] to initialize the storage
    ///   extents with.
    /// * `aux_fs_metadata_extents` - The [`AuxFsMetadata`] extents to
    ///   initialize on storage. The update group 0 must provide
    ///   [sufficient](AuxFsMetadata::extents_allocation_request) payload
    ///   capacity to store the `aux_fs_metadata` contents.
    /// * `update_group1_extents_begin` - Starting position of update group 1
    ///   within `aux_fs_metadata_extents`. If a group 1 is specified, it too
    ///   shall provide [sufficient](AuxFsMetadata::extents_allocation_request)
    ///   payload capacity to store the `aux_fs_metadata` contents.
    /// * `image_layout` - The filesystem's [`ImageLayout`].
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    pub fn poll(
        self: pin::Pin<&mut Self>,
        blkdev: &B,
        aux_fs_metadata: &AuxFsMetadata,
        aux_fs_metadata_extents: &PhysicalExtents,
        update_group1_extents_begin: Option<usize>,
        image_layout: &ImageLayout,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), NvFsError>> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                InitializeAuxFsMetadataExtentsFutureState::WriteExtentPrepare => {
                    if this.cur_extent_index == aux_fs_metadata_extents.len() {
                        debug_assert_eq!(this.encoding_pos, aux_fs_metadata.encoded.len());
                        this.fut_state = InitializeAuxFsMetadataExtentsFutureState::Done;
                        return task::Poll::Ready(Ok(()));
                    }

                    let extent = aux_fs_metadata_extents.get_extent_range(this.cur_extent_index);
                    // All extents are assumed to be compatible AuxFsMetadata::extents_layout(). In
                    // particular, their lengths in units of Bytes are
                    // reperesentable as an usize.
                    let extent_len = (u64::from(extent.block_count())
                        << (image_layout.allocation_block_size_128b_log2 as u32 + 7))
                        as usize;
                    let mut extent_buf = match FixedVec::new_with_default(extent_len) {
                        Ok(extent_buf) => extent_buf,
                        Err(e) => {
                            this.fut_state = InitializeAuxFsMetadataExtentsFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };

                    // Determine and encode the pointers to the chained extents.
                    if let Err(e) = aux_fs_metadata_extent_encode_chain_pointers(
                        &mut extent_buf,
                        this.cur_extent_index,
                        aux_fs_metadata_extents,
                    ) {
                        this.fut_state = InitializeAuxFsMetadataExtentsFutureState::Done;
                        return task::Poll::Ready(Err(e));
                    }

                    let mut integrity_protections_offset = AuxFsMetadataEncodedExtentsPtrsPair::encoded_len() as usize;
                    let is_update_group_head =
                        this.cur_extent_index == 0 || update_group1_extents_begin == Some(this.cur_extent_index);
                    if is_update_group_head {
                        // Add the AuxFsMetadataExtentsUpdateGroupState to the header. Initially, group
                        // 0 is active, group 1 is inactive.
                        extent_buf[integrity_protections_offset] = if this.cur_extent_index == 0 {
                            AuxFsMetadataExtentsUpdateGroupState::Active
                        } else {
                            AuxFsMetadataExtentsUpdateGroupState::Inactive
                        } as u8;
                        integrity_protections_offset += mem::size_of::<u8>();
                    }

                    // Copy the payload part if still in group 0.
                    if update_group1_extents_begin
                        .map(|update_group1_extents_begin| this.cur_extent_index < update_group1_extents_begin)
                        .unwrap_or(true)
                    {
                        let integrity_protections_len = extent_integrity_protections_len(
                            image_layout.io_block_allocation_blocks_log2,
                            image_layout.allocation_block_size_128b_log2,
                        );
                        let payload_offset = integrity_protections_offset + integrity_protections_len as usize;

                        let used_payload_len =
                            (extent_buf.len() - payload_offset).min(aux_fs_metadata.encoded.len() - this.encoding_pos);
                        extent_buf[payload_offset..payload_offset + used_payload_len].copy_from_slice(
                            &aux_fs_metadata.encoded[this.encoding_pos..this.encoding_pos + used_payload_len],
                        );
                        this.encoding_pos += used_payload_len;
                    } else {
                        debug_assert_eq!(this.encoding_pos, aux_fs_metadata.encoded.len());
                    }

                    // The extents are getting initialized and coherence is established by some
                    // external means. Pretend that the integrity state on storage is clean.
                    if let Err(e) = extent_integrity_protections_apply(
                        io_slices::SingletonIoSliceMut::new(&mut extent_buf),
                        0,
                        integrity_protections_offset,
                        &ExtentIntegrityState::new_clean(),
                        image_layout.io_block_allocation_blocks_log2,
                        image_layout.allocation_block_size_128b_log2,
                        blkdev.io_block_size_128b_log2(),
                    ) {
                        this.fut_state = InitializeAuxFsMetadataExtentsFutureState::Done;
                        return task::Poll::Ready(Err(e));
                    }

                    let write_fut = blkdev::helpers::NvBlkDevWriteRegionFuture::new(
                        u64::from(extent.begin()),
                        u64::from(extent.block_count()),
                        image_layout.allocation_block_size_128b_log2,
                        extent_buf,
                        0,
                        (image_layout.io_block_allocation_blocks_log2)
                            .max(image_layout.auth_tree_data_block_allocation_blocks_log2)
                            + image_layout.allocation_block_size_128b_log2,
                    );
                    this.fut_state = InitializeAuxFsMetadataExtentsFutureState::WriteExtent { write_fut };
                }
                InitializeAuxFsMetadataExtentsFutureState::WriteExtent { write_fut } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(write_fut), blkdev, cx) {
                        task::Poll::Ready(Ok((_extent_buf, Ok(())))) => (),
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                            this.fut_state = InitializeAuxFsMetadataExtentsFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    this.cur_extent_index += 1;
                    this.fut_state = InitializeAuxFsMetadataExtentsFutureState::WriteExtentPrepare;
                }
                InitializeAuxFsMetadataExtentsFutureState::Done => unreachable!(),
            }
        }
    }
}

/// Read the [`AuxFsMetadata`] stored alongside a
/// [`MkFsInfoHeader`](image_header::MkFsInfoHeader), if any.
pub struct ReadMkFsInfoAuxFsMetadataFuture<B: blkdev::NvBlkDev> {
    fut_state: ReadMkFsInfoAuxFsMetadataFutureState<B>,
}

enum ReadMkFsInfoAuxFsMetadataFutureState<B: blkdev::NvBlkDev> {
    Init {
        mkfsinfo_header_location: PhysicalAllocBlockRange,
        aux_fs_metadata_len: u64,
        io_block_allocation_blocks_log2: u8,
        allocation_block_size_128b_log2: u8,
    },
    Read {
        mkfsinfo_data_location: PhysicalAllocBlockRange,
        aux_fs_metadata_len: u64,
        read_fut: blkdev::helpers::NvBlkDevReadRegionFuture<B, FixedVec<u8, 7>>,
    },
    Done,
}

impl<B: blkdev::NvBlkDev> ReadMkFsInfoAuxFsMetadataFuture<B> {
    /// Instantiate a [`ReadMkFsInfoAuxFsMetadataFuture`].
    ///
    /// # Arguments:
    ///
    /// * `mkfsinfo_header_location` - Location of the
    ///   [`MkFsInfoHeader`](image_header::MkFsInfoHeader) on storage, i.e.
    ///   either the primary location at offset zero or
    ///   [`MkFsInfoHeader::physical_backup_location()`](image_header::MkFsInfoHeader::physical_backup_location()).
    /// * `aux_fs_metadata_len` - The value of
    ///   [`MkFsInfoHeader::aux_fs_metadata_len`](image_header::MkFsInfoHeader::aux_fs_metadata_len).
    /// * `io_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::io_block_allocation_blocks_log2`].
    /// * `allocation_block_size_128b_log2` - Verbatim value of
    ///   [`ImageLayout::allocation_block_size_128b_log2`].
    pub fn new(
        mkfsinfo_header_location: PhysicalAllocBlockRange,
        aux_fs_metadata_len: u64,
        io_block_allocation_blocks_log2: u8,
        allocation_block_size_128b_log2: u8,
    ) -> Self {
        Self {
            fut_state: ReadMkFsInfoAuxFsMetadataFutureState::Init {
                mkfsinfo_header_location,
                aux_fs_metadata_len,
                io_block_allocation_blocks_log2,
                allocation_block_size_128b_log2,
            },
        }
    }
}

impl<B: blkdev::NvBlkDev> blkdev::NvBlkDevFuture<B> for ReadMkFsInfoAuxFsMetadataFuture<B> {
    /// Output type of [`poll()`](Self::poll).
    ///
    /// On success, a pair of the filesystem creation info storage location and
    /// the read [`AuxFsMetadata`] gets returned.
    ///
    /// The former comprises the `mkfsinfo_header_location` initially passed to
    /// [`new()`](Self::new) as well as the [`AuxFsMetadata`] stored next to
    /// that.
    type Output = Result<(PhysicalAllocBlockRange, AuxFsMetadata), NvFsError>;

    fn poll(self: pin::Pin<&mut Self>, blkdev: &B, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                ReadMkFsInfoAuxFsMetadataFutureState::Init {
                    mkfsinfo_header_location,
                    aux_fs_metadata_len,
                    io_block_allocation_blocks_log2,
                    allocation_block_size_128b_log2,
                } => {
                    let aux_fs_metadata_location = match AuxFsMetadata::mkfsinfo_physical_location(
                        mkfsinfo_header_location,
                        *aux_fs_metadata_len,
                        *io_block_allocation_blocks_log2 as u32,
                        *allocation_block_size_128b_log2 as u32,
                    ) {
                        Ok(Some(aux_fs_metadata_location)) => aux_fs_metadata_location,
                        Ok(None) => {
                            let mkfsinfo_header_location = *mkfsinfo_header_location;
                            this.fut_state = ReadMkFsInfoAuxFsMetadataFutureState::Done;
                            return task::Poll::Ready(Ok((mkfsinfo_header_location, AuxFsMetadata::new())));
                        }
                        Err(e) => {
                            this.fut_state = ReadMkFsInfoAuxFsMetadataFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };

                    // Merge the MkFsInforHeader location with the aux_fs_metadata_location.
                    let mkfsinfo_data_location = PhysicalAllocBlockRange::new(
                        mkfsinfo_header_location.begin().min(aux_fs_metadata_location.begin()),
                        mkfsinfo_header_location.end().max(aux_fs_metadata_location.end()),
                    );

                    let aux_fs_metadata_buf_len = match usize::try_from(
                        u64::from(aux_fs_metadata_location.block_count())
                            << (*allocation_block_size_128b_log2 as u32 + 7),
                    ) {
                        Ok(aux_fs_metadata_buf_len) => aux_fs_metadata_buf_len,
                        Err(_) => {
                            this.fut_state = ReadMkFsInfoAuxFsMetadataFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::DimensionsNotSupported));
                        }
                    };
                    // AuxFsMetadata::decode() takes a Vec, but allocate a FixedVec here
                    // to avoid blkdev::helpers:::NvBlkDevReadRegionFuture instantiation bloat.
                    // The read data will get copied into a Vec later -- this code here is
                    // executed only at filesystem creation time and the performance penalty
                    // is not really a concern.
                    let aux_fs_metadata_buf = match FixedVec::new_with_default(aux_fs_metadata_buf_len) {
                        Ok(aux_fs_metadata_buf) => aux_fs_metadata_buf,
                        Err(e) => {
                            this.fut_state = ReadMkFsInfoAuxFsMetadataFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    let read_fut = blkdev::helpers::NvBlkDevReadRegionFuture::new(
                        u64::from(aux_fs_metadata_location.begin()),
                        u64::from(aux_fs_metadata_location.block_count()),
                        *allocation_block_size_128b_log2,
                        aux_fs_metadata_buf,
                        0,
                        *io_block_allocation_blocks_log2 + *allocation_block_size_128b_log2,
                    );
                    this.fut_state = ReadMkFsInfoAuxFsMetadataFutureState::Read {
                        mkfsinfo_data_location,
                        aux_fs_metadata_len: *aux_fs_metadata_len,
                        read_fut,
                    };
                }
                ReadMkFsInfoAuxFsMetadataFutureState::Read {
                    mkfsinfo_data_location,
                    aux_fs_metadata_len,
                    read_fut,
                } => {
                    let aux_fs_metadata_buf = match blkdev::NvBlkDevFuture::poll(pin::Pin::new(read_fut), blkdev, cx) {
                        task::Poll::Ready(Ok((aux_fs_metadata_buf, Ok(())))) => aux_fs_metadata_buf,
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                            this.fut_state = ReadMkFsInfoAuxFsMetadataFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    // Verify the checksum.
                    let mut checksum = checksum::ChecksumInstance::new();
                    let (expected_checksum, checksummed_part) =
                        aux_fs_metadata_buf.split_at(checksum::CHECKSUM_LEN as usize);
                    checksum.update(checksummed_part);
                    if !checksum.finish_receive(expected_checksum) {
                        // Checksum mismatch.
                        this.fut_state = ReadMkFsInfoAuxFsMetadataFutureState::Done;
                        return task::Poll::Ready(Err(NvFsError::from(FormatError::InvalidAuxFsMetadataChecksum)));
                    }

                    // By the fact that the extent is in a buffer,
                    // and extent.len() >= aux_fs_metadata_len, it's guaranteed that
                    // aux_fs_metadata_len wouldn't overflow an usize.
                    let mkfsinfo_data_location = *mkfsinfo_data_location;
                    let mut aux_fs_metadata = match try_alloc_vec(*aux_fs_metadata_len as usize) {
                        Ok(aux_fs_metadata) => aux_fs_metadata,
                        Err(e) => {
                            this.fut_state = ReadMkFsInfoAuxFsMetadataFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    aux_fs_metadata.copy_from_slice(
                        &aux_fs_metadata_buf[checksum::CHECKSUM_LEN as usize
                            ..checksum::CHECKSUM_LEN as usize + *aux_fs_metadata_len as usize],
                    );
                    drop(aux_fs_metadata_buf);
                    this.fut_state = ReadMkFsInfoAuxFsMetadataFutureState::Done;
                    return task::Poll::Ready(
                        AuxFsMetadata::decode(aux_fs_metadata)
                            .map(|aux_fs_metadata| (mkfsinfo_data_location, aux_fs_metadata)),
                    );
                }
                ReadMkFsInfoAuxFsMetadataFutureState::Done => unreachable!(),
            }
        }
    }
}

/// Write the [`AuxFsMetadata`] to be storead alongside a
/// [`MkFsInfoHeader`](image_header::MkFsInfoHeader), if any.
pub struct WriteMkFsInfoAuxFsMetadataFuture<B: blkdev::NvBlkDev> {
    fut_state: WriteMkFsInfoAuxFsMetadataFutureState<B>,
}

enum WriteMkFsInfoAuxFsMetadataFutureState<B: blkdev::NvBlkDev> {
    Init {
        mkfsinfo_header_location: PhysicalAllocBlockRange,
        io_block_allocation_blocks_log2: u8,
        allocation_block_size_128b_log2: u8,
    },
    Write {
        write_fut: blkdev::helpers::NvBlkDevWriteRegionFuture<B, FixedVec<u8, 7>>,
    },
    Done,
}

impl<B: blkdev::NvBlkDev> WriteMkFsInfoAuxFsMetadataFuture<B> {
    /// Instantiate a [`WriteMkFsInfoAuxFsMetadataFuture`].
    ///
    /// # Arguments:
    ///
    /// * `mkfsinfo_header_location` - Location of the
    ///   [`MkFsInfoHeader`](image_header::MkFsInfoHeader) on storage, i.e.
    ///   either the primary location at offset zero or
    ///   [`MkFsInfoHeader::physical_backup_location()`](image_header::MkFsInfoHeader::physical_backup_location()).
    /// * `io_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::io_block_allocation_blocks_log2`].
    /// * `allocation_block_size_128b_log2` - Verbatim value of
    ///   [`ImageLayout::allocation_block_size_128b_log2`].
    pub fn new(
        mkfsinfo_header_location: &PhysicalAllocBlockRange,
        io_block_allocation_blocks_log2: u8,
        allocation_block_size_128b_log2: u8,
    ) -> Self {
        Self {
            fut_state: WriteMkFsInfoAuxFsMetadataFutureState::Init {
                mkfsinfo_header_location: *mkfsinfo_header_location,
                io_block_allocation_blocks_log2,
                allocation_block_size_128b_log2,
            },
        }
    }

    /// Poll the [`WriteMkFsInfoAuxFsMetadataFuture`] to completion.
    ///
    /// # Arguments:
    ///
    /// * `blkdev` -  The filesystem image backing storage.
    /// * `aux_fs_metadata` - The [`AuxFsMetadata`] to write.
    /// * `cx` - - The context of the asynchronous task on whose behalf the
    ///   future is being polled.
    pub fn poll(
        self: pin::Pin<&mut Self>,
        blkdev: &B,
        aux_fs_metadata: &AuxFsMetadata,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), NvFsError>> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                WriteMkFsInfoAuxFsMetadataFutureState::Init {
                    mkfsinfo_header_location,
                    io_block_allocation_blocks_log2,
                    allocation_block_size_128b_log2,
                } => {
                    let aux_fs_metadata_len = match u64::try_from(aux_fs_metadata.encoded_len()) {
                        Ok(aux_fs_metadata_len) => aux_fs_metadata_len,
                        Err(_) => {
                            this.fut_state = WriteMkFsInfoAuxFsMetadataFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(FormatError::InvalidAuxFsMetadataSize)));
                        }
                    };
                    let aux_fs_metadata_location = match AuxFsMetadata::mkfsinfo_physical_location(
                        mkfsinfo_header_location,
                        aux_fs_metadata_len,
                        *io_block_allocation_blocks_log2 as u32,
                        *allocation_block_size_128b_log2 as u32,
                    ) {
                        Ok(Some(aux_fs_metadata_location)) => aux_fs_metadata_location,
                        Ok(None) => {
                            this.fut_state = WriteMkFsInfoAuxFsMetadataFutureState::Done;
                            return task::Poll::Ready(Ok(()));
                        }
                        Err(e) => {
                            this.fut_state = WriteMkFsInfoAuxFsMetadataFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };

                    let aux_fs_metadata_buf_len = match usize::try_from(
                        u64::from(aux_fs_metadata_location.block_count())
                            << (*allocation_block_size_128b_log2 as u32 + 7),
                    ) {
                        Ok(aux_fs_metadata_buf_len) => aux_fs_metadata_buf_len,
                        Err(_) => {
                            this.fut_state = WriteMkFsInfoAuxFsMetadataFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::DimensionsNotSupported));
                        }
                    };
                    let mut aux_fs_metadata_buf = match FixedVec::new_with_default(aux_fs_metadata_buf_len) {
                        Ok(aux_fs_metadata_buf) => aux_fs_metadata_buf,
                        Err(e) => {
                            this.fut_state = WriteMkFsInfoAuxFsMetadataFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };

                    let (expected_checksum, checksummed_part) =
                        aux_fs_metadata_buf.split_at_mut(checksum::CHECKSUM_LEN as usize);
                    debug_assert!(checksummed_part.len() >= aux_fs_metadata.encoded_len());
                    checksummed_part[..aux_fs_metadata.encoded.len()].copy_from_slice(&aux_fs_metadata.encoded);
                    let mut checksum = checksum::ChecksumInstance::new();
                    checksum.update(checksummed_part);
                    let checksum = checksum.finish_send();
                    expected_checksum.copy_from_slice(&checksum);

                    debug_assert!(
                        (u64::from(aux_fs_metadata_location.begin()) | u64::from(aux_fs_metadata_location.end()))
                            .is_aligned_pow2(*io_block_allocation_blocks_log2 as u32)
                    );
                    let write_fut = blkdev::helpers::NvBlkDevWriteRegionFuture::new(
                        u64::from(aux_fs_metadata_location.begin()),
                        u64::from(aux_fs_metadata_location.block_count()),
                        *allocation_block_size_128b_log2,
                        aux_fs_metadata_buf,
                        0,
                        *io_block_allocation_blocks_log2 + *allocation_block_size_128b_log2,
                    );
                    this.fut_state = WriteMkFsInfoAuxFsMetadataFutureState::Write { write_fut };
                }
                WriteMkFsInfoAuxFsMetadataFutureState::Write { write_fut } => {
                    match blkdev::NvBlkDevFuture::poll(pin::Pin::new(write_fut), blkdev, cx) {
                        task::Poll::Ready(Ok((aux_fs_metadata_buf, Ok(())))) => aux_fs_metadata_buf,
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                            this.fut_state = WriteMkFsInfoAuxFsMetadataFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    this.fut_state = WriteMkFsInfoAuxFsMetadataFutureState::Done;
                    return task::Poll::Ready(Ok(()));
                }
                WriteMkFsInfoAuxFsMetadataFutureState::Done => unreachable!(),
            }
        }
    }
}
