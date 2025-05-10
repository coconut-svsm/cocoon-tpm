// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

extern crate alloc;
use alloc::vec::Vec;

use crate::{
    fs::{
        cocoonfs::{
            alloc_bitmap, image_header, layout, leb128,
            transaction::auth_tree_data_blocks_update_states::{
                AuthTreeDataBlocksUpdateStates, AuthTreeDataBlocksUpdateStatesAllocationBlockIndex,
                AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange, AuthTreeDataBlocksUpdateStatesIndex,
            },
            CocoonFsFormatError,
        },
        NvFsError,
    },
    nvfs_err_internal,
    utils_common::{
        bitmanip::BitManip as _,
        io_slices::{self, IoSlicesIterCommon as _, IoSlicesMutIter as _, WalkableIoSlicesIter},
    },
};
use core::{cmp, ops};

pub struct JournalApplyWritesScriptEntry {
    target_range: layout::PhysicalAllocBlockRange,
    journal_staging_copy_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
}

impl JournalApplyWritesScriptEntry {
    pub fn get_target_range(&self) -> &layout::PhysicalAllocBlockRange {
        &self.target_range
    }

    pub fn get_journal_staging_copy_allocation_blocks_begin(&self) -> layout::PhysicalAllocBlockIndex {
        self.journal_staging_copy_allocation_blocks_begin
    }
}

pub trait JournalApplyWritesScriptIterator {
    fn next(&mut self) -> Result<Option<JournalApplyWritesScriptEntry>, NvFsError>;
}

#[derive(Clone)]
pub struct TransactionJournalApplyWritesScriptIterator<'a> {
    transaction_update_states: &'a AuthTreeDataBlocksUpdateStates,
    next_update_states_allocation_block_index: AuthTreeDataBlocksUpdateStatesAllocationBlockIndex,
    mutable_image_header_region: layout::PhysicalAllocBlockRange,
    auth_tree_data_block_allocation_blocks_log2: u8,
    io_block_allocation_blocks_log2: u8,
}

impl<'a> TransactionJournalApplyWritesScriptIterator<'a> {
    pub fn new(
        transaction_update_states: &'a AuthTreeDataBlocksUpdateStates,
        image_layout: &layout::ImageLayout,
        salt_len: u8,
    ) -> Self {
        let mutable_image_header_region = image_header::MutableImageHeader::physical_location(image_layout, salt_len);
        let auth_tree_data_block_allocation_blocks_log2 = image_layout.auth_tree_data_block_allocation_blocks_log2;
        let io_block_allocation_blocks_log2 = image_layout.io_block_allocation_blocks_log2;
        Self {
            transaction_update_states,
            next_update_states_allocation_block_index: AuthTreeDataBlocksUpdateStatesAllocationBlockIndex::from(
                AuthTreeDataBlocksUpdateStatesIndex::from(0usize),
            ),
            mutable_image_header_region,
            auth_tree_data_block_allocation_blocks_log2,
            io_block_allocation_blocks_log2,
        }
    }
}

impl<'a> JournalApplyWritesScriptIterator for TransactionJournalApplyWritesScriptIterator<'a> {
    fn next(&mut self) -> Result<Option<JournalApplyWritesScriptEntry>, NvFsError> {
        let update_states = self.transaction_update_states;

        let io_block_allocation_blocks =
            layout::AllocBlockCount::from(1u64 << (self.io_block_allocation_blocks_log2 as u32));

        // Skip over any IO blocks at the current position whose data is not modified or
        // that have been written in place. Note that the former is possible if
        // the IO block size is less than that of an Authentication Tree Data
        // Block.
        while usize::from(AuthTreeDataBlocksUpdateStatesIndex::from(
            self.next_update_states_allocation_block_index,
        )) != update_states.len()
        {
            let cur_io_block_update_states_allocation_block_end_index =
                self.next_update_states_allocation_block_index.advance(
                    io_block_allocation_blocks,
                    self.auth_tree_data_block_allocation_blocks_log2 as u32,
                );
            // All IO block alignment gaps in the update states should have been filled by
            // now.
            if usize::from(AuthTreeDataBlocksUpdateStatesIndex::from(
                cur_io_block_update_states_allocation_block_end_index,
            )) > update_states.len()
            {
                return Err(nvfs_err_internal!());
            }
            let cur_io_block_update_states_allocation_block_index_range =
                AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::new(
                    &self.next_update_states_allocation_block_index,
                    &cur_io_block_update_states_allocation_block_end_index,
                );

            // All IO block alignment gaps in the update states should have been filled by
            // now.
            if !update_states.is_contiguous_aligned_allocation_blocks_region(
                &cur_io_block_update_states_allocation_block_index_range,
                self.io_block_allocation_blocks_log2 as u32,
            ) {
                return Err(nvfs_err_internal!());
            }

            let auth_tree_data_block_update_state = &update_states
                [AuthTreeDataBlocksUpdateStatesIndex::from(self.next_update_states_allocation_block_index)];
            if let Some(journal_staging_copy_allocation_blocks_begin) =
                auth_tree_data_block_update_state.get_journal_staging_copy_allocation_blocks_begin()
            {
                // The data modification had been written in place, skip over it.
                // Note that a contiguous journal staging copy gets assigned to an
                // IO- or Authentication Tree Data Block, whichever is larger.
                if journal_staging_copy_allocation_blocks_begin
                    == auth_tree_data_block_update_state.get_target_allocation_blocks_begin()
                {
                    if self.io_block_allocation_blocks_log2 >= self.auth_tree_data_block_allocation_blocks_log2 {
                        self.next_update_states_allocation_block_index =
                            cur_io_block_update_states_allocation_block_end_index;
                    } else {
                        self.next_update_states_allocation_block_index =
                            AuthTreeDataBlocksUpdateStatesAllocationBlockIndex::from(
                                AuthTreeDataBlocksUpdateStatesIndex::from(
                                    self.next_update_states_allocation_block_index,
                                )
                                .step(),
                            );
                    }
                    continue;
                }
            } else {
                // All update states should have been written by now and have a journal staging
                // copy area allocated to them.
                return Err(nvfs_err_internal!());
            }

            // The mutable image header is always assumed to get updated, even though no
            // updates might have been actually staged yet at that point.
            let cur_io_block_allocation_blocks_begin =
                update_states.get_allocation_block_target(&self.next_update_states_allocation_block_index);
            if cur_io_block_allocation_blocks_begin < self.mutable_image_header_region.end()
                && cur_io_block_allocation_blocks_begin >= self.mutable_image_header_region.begin()
            {
                break;
            }

            let cur_io_block_any_modified = cur_io_block_update_states_allocation_block_index_range
                .iter(self.auth_tree_data_block_allocation_blocks_log2 as u32)
                .any(|cur_update_states_allocation_block_index| {
                    update_states[cur_update_states_allocation_block_index].has_modified_data()
                });

            if cur_io_block_any_modified {
                break;
            } else {
                // Unneeded update states entries should have been pruned by now.
                if self.io_block_allocation_blocks_log2 >= self.auth_tree_data_block_allocation_blocks_log2 {
                    return Err(nvfs_err_internal!());
                }
                self.next_update_states_allocation_block_index = cur_io_block_update_states_allocation_block_end_index;
            }
        }

        if usize::from(AuthTreeDataBlocksUpdateStatesIndex::from(
            self.next_update_states_allocation_block_index,
        )) == update_states.len()
        {
            return Ok(None);
        }

        let region_target_allocation_blocks_begin =
            update_states.get_allocation_block_target(&self.next_update_states_allocation_block_index);
        if !u64::from(region_target_allocation_blocks_begin)
            .is_aligned_pow2(self.io_block_allocation_blocks_log2 as u32)
        {
            return Err(nvfs_err_internal!());
        }
        // All modified update states should have been written by now, meaning they have
        // a Journal Staging Copy area allocated to them.
        let region_journal_staging_copy_allocation_blocks_begin = update_states
            .get_allocation_block_journal_staging_copy(&self.next_update_states_allocation_block_index)
            .ok_or_else(|| nvfs_err_internal!())?;
        if !u64::from(region_journal_staging_copy_allocation_blocks_begin)
            .is_aligned_pow2(self.io_block_allocation_blocks_log2 as u32)
        {
            return Err(nvfs_err_internal!());
        }
        let mut region_allocation_blocks = io_block_allocation_blocks;

        let mut last_io_block_target_allocation_blocks_begin = region_target_allocation_blocks_begin;
        let mut last_io_block_journal_staging_copy_allocation_blocks_begin =
            region_journal_staging_copy_allocation_blocks_begin;
        self.next_update_states_allocation_block_index = self.next_update_states_allocation_block_index.advance(
            io_block_allocation_blocks,
            self.auth_tree_data_block_allocation_blocks_log2 as u32,
        );

        // Extend the range until there's a discontinuity in the target or journal
        // copying area regions, or an unmodified IO block is being encountered, or
        // an IO Block had been written in-place.
        while usize::from(AuthTreeDataBlocksUpdateStatesIndex::from(
            self.next_update_states_allocation_block_index,
        )) != update_states.len()
        {
            let cur_io_block_target_allocation_blocks_begin =
                update_states.get_allocation_block_target(&self.next_update_states_allocation_block_index);
            if last_io_block_target_allocation_blocks_begin > cur_io_block_target_allocation_blocks_begin
                || cur_io_block_target_allocation_blocks_begin - last_io_block_target_allocation_blocks_begin
                    != io_block_allocation_blocks
            {
                break;
            }
            last_io_block_target_allocation_blocks_begin = cur_io_block_target_allocation_blocks_begin;
            let cur_io_block_journal_staging_copy_allocation_blocks_begin = match update_states
                .get_allocation_block_journal_staging_copy(&self.next_update_states_allocation_block_index)
            {
                Some(cur_io_block_journal_staging_copy_allocation_blocks_begin) => {
                    cur_io_block_journal_staging_copy_allocation_blocks_begin
                }
                None => {
                    // All modified update states should have been written by now, meaning they have
                    // a Journal Staging Copy area allocated to them.
                    return Err(nvfs_err_internal!());
                }
            };
            if last_io_block_journal_staging_copy_allocation_blocks_begin
                > cur_io_block_journal_staging_copy_allocation_blocks_begin
                || cur_io_block_journal_staging_copy_allocation_blocks_begin
                    - last_io_block_journal_staging_copy_allocation_blocks_begin
                    != io_block_allocation_blocks
            {
                break;
            }
            last_io_block_journal_staging_copy_allocation_blocks_begin =
                cur_io_block_journal_staging_copy_allocation_blocks_begin;

            let cur_io_block_update_states_allocation_block_end_index =
                self.next_update_states_allocation_block_index.advance(
                    io_block_allocation_blocks,
                    self.auth_tree_data_block_allocation_blocks_log2 as u32,
                );
            if usize::from(AuthTreeDataBlocksUpdateStatesIndex::from(
                cur_io_block_update_states_allocation_block_end_index,
            )) > update_states.len()
            {
                return Err(nvfs_err_internal!());
            }
            let cur_io_block_update_states_allocation_block_index_range =
                AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::new(
                    &self.next_update_states_allocation_block_index,
                    &cur_io_block_update_states_allocation_block_end_index,
                );

            // All IO block alignment gaps in the update states should have been filled by
            // now.
            if !update_states.is_contiguous_aligned_allocation_blocks_region(
                &cur_io_block_update_states_allocation_block_index_range,
                self.io_block_allocation_blocks_log2 as u32,
            ) {
                return Err(nvfs_err_internal!());
            }

            if cur_io_block_journal_staging_copy_allocation_blocks_begin == cur_io_block_target_allocation_blocks_begin
            {
                // The IO block had been written in place. Skip over it and stop.
                // Note that a contiguous journal staging copy gets assigned to an
                // IO- or Authentication Tree Data Block, whichever is larger.
                if self.io_block_allocation_blocks_log2 >= self.auth_tree_data_block_allocation_blocks_log2 {
                    self.next_update_states_allocation_block_index =
                        cur_io_block_update_states_allocation_block_end_index;
                } else {
                    self.next_update_states_allocation_block_index =
                        AuthTreeDataBlocksUpdateStatesAllocationBlockIndex::from(
                            AuthTreeDataBlocksUpdateStatesIndex::from(self.next_update_states_allocation_block_index)
                                .step(),
                        );
                }
                break;
            }

            self.next_update_states_allocation_block_index = cur_io_block_update_states_allocation_block_end_index;

            // The mutable image header is always assumed to get updated, even though no
            // updates might have been actually staged yet at that point.
            let cur_io_block_any_modified = (cur_io_block_target_allocation_blocks_begin
                < self.mutable_image_header_region.end()
                && cur_io_block_target_allocation_blocks_begin >= self.mutable_image_header_region.begin())
                || cur_io_block_update_states_allocation_block_index_range
                    .iter(self.auth_tree_data_block_allocation_blocks_log2 as u32)
                    .any(|cur_update_states_allocation_block_index| {
                        update_states[cur_update_states_allocation_block_index].has_modified_data()
                    });
            if !cur_io_block_any_modified {
                // Unneeded update states entries should have been pruned by now.
                if self.io_block_allocation_blocks_log2 >= self.auth_tree_data_block_allocation_blocks_log2 {
                    return Err(nvfs_err_internal!());
                }
                break;
            }

            region_allocation_blocks = region_allocation_blocks + io_block_allocation_blocks;
        }

        let target_range =
            layout::PhysicalAllocBlockRange::from((region_target_allocation_blocks_begin, region_allocation_blocks));
        Ok(Some(JournalApplyWritesScriptEntry {
            target_range,
            journal_staging_copy_allocation_blocks_begin: region_journal_staging_copy_allocation_blocks_begin,
        }))
    }
}

pub struct JournalApplyWritesScript {
    script: Vec<JournalApplyWritesScriptEntry>,
}

impl JournalApplyWritesScript {
    pub fn encoded_len<I: JournalApplyWritesScriptIterator>(
        mut script_entry_iter: I,
        io_block_allocation_blocks_log2: u32,
    ) -> Result<usize, NvFsError> {
        let mut encoded_len = 0usize;
        let mut last_entry_target_allocation_blocks_end = layout::PhysicalAllocBlockIndex::from(0);
        let mut last_entry_journal_staging_copy_allocation_blocks_end = layout::PhysicalAllocBlockIndex::from(0);
        while let Some(script_entry) = script_entry_iter.next()? {
            let target_delta_encoded_len = leb128::leb128u_u64_encoded_len(
                u64::from(script_entry.target_range.begin() - last_entry_target_allocation_blocks_end)
                    >> io_block_allocation_blocks_log2,
            );
            // Note: the cast to i64 is well-defined in Rust's two's complement
            // representation.
            let journal_staging_copy_delta_encoded_len = leb128::leb128s_i64_encoded_len(
                u64::from(script_entry.journal_staging_copy_allocation_blocks_begin)
                    .wrapping_sub(u64::from(last_entry_journal_staging_copy_allocation_blocks_end))
                    as i64
                    >> io_block_allocation_blocks_log2,
            );
            let block_count_encoded_len = leb128::leb128u_u64_encoded_len(
                u64::from(script_entry.target_range.block_count()) >> io_block_allocation_blocks_log2,
            );
            encoded_len = encoded_len
                .checked_add(
                    target_delta_encoded_len + journal_staging_copy_delta_encoded_len + block_count_encoded_len,
                )
                .ok_or(NvFsError::DimensionsNotSupported)?;
            last_entry_target_allocation_blocks_end = script_entry.target_range.end();
            last_entry_journal_staging_copy_allocation_blocks_end =
                script_entry.journal_staging_copy_allocation_blocks_begin + script_entry.target_range.block_count();
        }

        // The script will be terminated with three consecutive zeroes.
        encoded_len.checked_add(3).ok_or(NvFsError::DimensionsNotSupported)
    }

    pub fn encode<I: Clone + JournalApplyWritesScriptIterator>(
        mut buf: &mut [u8],
        mut script_entry_iter: I,
        io_block_allocation_blocks_log2: u32,
    ) -> Result<&mut [u8], NvFsError> {
        debug_assert!(buf.len() >= Self::encoded_len(script_entry_iter.clone(), io_block_allocation_blocks_log2)?);

        let mut last_entry_target_allocation_blocks_end = layout::PhysicalAllocBlockIndex::from(0);
        let mut last_entry_journal_staging_copy_allocation_blocks_end = layout::PhysicalAllocBlockIndex::from(0);
        while let Some(script_entry) = script_entry_iter.next()? {
            buf = leb128::leb128u_u64_encode(
                buf,
                u64::from(script_entry.target_range.begin() - last_entry_target_allocation_blocks_end)
                    >> io_block_allocation_blocks_log2,
            );
            // Note: the cast to i64 is well-defined in Rust's two's complement
            // representation.
            buf = leb128::leb128s_i64_encode(
                buf,
                u64::from(script_entry.journal_staging_copy_allocation_blocks_begin)
                    .wrapping_sub(u64::from(last_entry_journal_staging_copy_allocation_blocks_end))
                    as i64
                    >> io_block_allocation_blocks_log2,
            );
            buf = leb128::leb128u_u64_encode(
                buf,
                u64::from(script_entry.target_range.block_count()) >> io_block_allocation_blocks_log2,
            );
            last_entry_target_allocation_blocks_end = script_entry.target_range.end();
            last_entry_journal_staging_copy_allocation_blocks_end =
                script_entry.journal_staging_copy_allocation_blocks_begin + script_entry.target_range.block_count();
        }

        // Encode the termination record as three consecutive zeroes.
        buf[0] = 0;
        buf[1] = 0;
        buf[2] = 0;
        Ok(&mut buf[3..])
    }

    pub fn decode<'a, SI: io_slices::PeekableIoSlicesIter<'a, BackendIteratorError = NvFsError>>(
        mut src: SI,
        io_block_allocation_blocks_log2: u32,
        allocation_block_size128b_log2: u32,
    ) -> Result<Self, NvFsError> {
        let mut script = Vec::new();
        // One leb128-encoded 64 bit integer, signed or unsigned, is at most 10 bytes
        // long.
        let mut decode_buf: [u8; 30] = [0u8; 30];
        let mut decode_buf_len = 0;
        let mut peeking_src = src.decoupled_borrow();
        let mut remaining_src_len = src.total_len()?;
        let mut total_consumed_src_len = 0;
        let mut last_entry_target_allocation_blocks_end = 0u64;
        let mut last_entry_journal_staging_copy_allocation_blocks_end = 0u64;
        loop {
            // Refill the decode buffer.
            debug_assert_eq!(peeking_src.total_len()?, remaining_src_len);
            let decode_buf_refill_len = (decode_buf.len() - decode_buf_len).min(remaining_src_len);
            io_slices::SingletonIoSliceMut::new(
                &mut decode_buf[decode_buf_len..decode_buf_len + decode_buf_refill_len],
            )
            .map_infallible_err()
            .copy_from_iter(&mut peeking_src)?;
            decode_buf_len += decode_buf_refill_len;
            remaining_src_len -= decode_buf_refill_len;

            // There must be enough space for the three zero bytes of the termination
            // record.
            if decode_buf_len < 3 {
                return Err(NvFsError::from(
                    CocoonFsFormatError::InvalidJournalApplyWritesScriptFormat,
                ));
            }

            // Decode the triplet of (target delta, journal copy area begin, length).
            let mut remaining_decode_buf = &decode_buf[..decode_buf_len];
            let target_delta_io_blocks;
            (target_delta_io_blocks, remaining_decode_buf) = leb128::leb128u_u64_decode(remaining_decode_buf)
                .map_err(|_| NvFsError::from(CocoonFsFormatError::InvalidJournalApplyWritesScriptFormat))?;

            let journal_staging_copy_delta_io_blocks;
            (journal_staging_copy_delta_io_blocks, remaining_decode_buf) =
                leb128::leb128s_i64_decode(remaining_decode_buf)
                    .map_err(|_| NvFsError::from(CocoonFsFormatError::InvalidJournalApplyWritesScriptFormat))?;
            let io_blocks_count;
            (io_blocks_count, remaining_decode_buf) = leb128::leb128u_u64_decode(remaining_decode_buf)
                .map_err(|_| NvFsError::from(CocoonFsFormatError::InvalidJournalApplyWritesScriptFormat))?;

            // Move the remaining bytes in decode_buf to the front.
            let consumed = decode_buf_len - remaining_decode_buf.len();
            total_consumed_src_len += consumed;
            decode_buf_len -= consumed;
            decode_buf.copy_within(consumed..consumed + decode_buf_len, 0);

            // Check for the termination record.
            if target_delta_io_blocks == 0 && journal_staging_copy_delta_io_blocks == 0 && io_blocks_count == 0 {
                break;
            } else if io_blocks_count == 0 {
                // Invalid value.
                return Err(NvFsError::from(
                    CocoonFsFormatError::InvalidJournalApplyWritesScriptEntry,
                ));
            }

            let target_delta_allocation_blocks = target_delta_io_blocks << io_block_allocation_blocks_log2;
            if target_delta_allocation_blocks >> io_block_allocation_blocks_log2 != target_delta_io_blocks {
                return Err(NvFsError::from(
                    CocoonFsFormatError::InvalidJournalApplyWritesScriptFormat,
                ));
            }
            let entry_target_allocation_blocks_begin = last_entry_target_allocation_blocks_end
                .checked_add(target_delta_allocation_blocks)
                .ok_or(NvFsError::from(
                    CocoonFsFormatError::InvalidJournalApplyWritesScriptEntry,
                ))?;

            let journal_staging_copy_delta_allocation_blocks =
                journal_staging_copy_delta_io_blocks << io_block_allocation_blocks_log2;
            if journal_staging_copy_delta_allocation_blocks >> io_block_allocation_blocks_log2
                != journal_staging_copy_delta_io_blocks
            {
                return Err(NvFsError::from(
                    CocoonFsFormatError::InvalidJournalApplyWritesScriptFormat,
                ));
            }
            // Convert the delta encoded as signed leb128 to u64 in
            // two's complement and add with wraparound  -- this way the full
            // possible u64 range can be covered).
            let entry_journal_staging_copy_allocation_blocks_begin =
                last_entry_journal_staging_copy_allocation_blocks_end
                    .wrapping_add(journal_staging_copy_delta_allocation_blocks as u64);

            let allocation_blocks_count = io_blocks_count << io_block_allocation_blocks_log2;
            if allocation_blocks_count >> io_block_allocation_blocks_log2 != io_blocks_count {
                return Err(NvFsError::from(
                    CocoonFsFormatError::InvalidJournalApplyWritesScriptFormat,
                ));
            }

            let entry_target_allocation_blocks_end = entry_target_allocation_blocks_begin
                .checked_add(allocation_blocks_count)
                .ok_or(NvFsError::from(
                    CocoonFsFormatError::InvalidJournalApplyWritesScriptEntry,
                ))?;
            if entry_target_allocation_blocks_end > u64::MAX >> (allocation_block_size128b_log2 + 7) {
                return Err(NvFsError::from(
                    CocoonFsFormatError::InvalidJournalApplyWritesScriptFormat,
                ));
            }
            let entry_journal_staging_copy_allocation_blocks_end = entry_journal_staging_copy_allocation_blocks_begin
                .checked_add(allocation_blocks_count)
                .ok_or(NvFsError::from(
                    CocoonFsFormatError::InvalidJournalApplyWritesScriptEntry,
                ))?;
            if entry_journal_staging_copy_allocation_blocks_end > u64::MAX >> (allocation_block_size128b_log2 + 7) {
                return Err(NvFsError::from(
                    CocoonFsFormatError::InvalidJournalApplyWritesScriptFormat,
                ));
            }

            last_entry_target_allocation_blocks_end = entry_target_allocation_blocks_end;
            last_entry_journal_staging_copy_allocation_blocks_end = entry_journal_staging_copy_allocation_blocks_end;

            script.try_reserve(1)?;
            script.push(JournalApplyWritesScriptEntry {
                target_range: layout::PhysicalAllocBlockRange::new(
                    layout::PhysicalAllocBlockIndex::from(entry_target_allocation_blocks_begin),
                    layout::PhysicalAllocBlockIndex::from(entry_target_allocation_blocks_end),
                ),
                journal_staging_copy_allocation_blocks_begin: layout::PhysicalAllocBlockIndex::from(
                    entry_journal_staging_copy_allocation_blocks_begin,
                ),
            });
        }

        drop(peeking_src);
        src.skip(total_consumed_src_len).map_err(|e| match e {
            io_slices::IoSlicesIterError::BackendIteratorError(e) => e,
            io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
            },
        })?;

        Ok(Self { script })
    }

    pub fn len(&self) -> usize {
        self.script.len()
    }

    pub fn lookup(&self, target_allocation_block_index: layout::PhysicalAllocBlockIndex) -> Result<usize, usize> {
        self.script.binary_search_by(
            |entry| match entry.target_range.end().cmp(&target_allocation_block_index) {
                cmp::Ordering::Less | cmp::Ordering::Equal => cmp::Ordering::Less,
                cmp::Ordering::Greater => match entry.target_range.end().cmp(&target_allocation_block_index) {
                    cmp::Ordering::Less | cmp::Ordering::Equal => cmp::Ordering::Equal,
                    cmp::Ordering::Greater => cmp::Ordering::Greater,
                },
            },
        )
    }
}

impl ops::Index<usize> for JournalApplyWritesScript {
    type Output = JournalApplyWritesScriptEntry;

    fn index(&self, index: usize) -> &Self::Output {
        &self.script[index]
    }
}

pub struct JournalUpdateAuthDigestsScriptEntry {
    target_range: layout::PhysicalAllocBlockRange,
}

impl JournalUpdateAuthDigestsScriptEntry {
    pub fn new(target_range: &layout::PhysicalAllocBlockRange) -> Self {
        Self {
            target_range: *target_range,
        }
    }

    pub fn get_target_range(&self) -> &layout::PhysicalAllocBlockRange {
        &self.target_range
    }
}

pub trait JournalUpdateAuthDigestsScriptIterator {
    fn next(&mut self) -> Result<Option<JournalUpdateAuthDigestsScriptEntry>, NvFsError>;
}

pub struct JournalUpdateAuthDigestsScript {
    script: Vec<JournalUpdateAuthDigestsScriptEntry>,
}

impl JournalUpdateAuthDigestsScript {
    pub fn encoded_len<I: JournalUpdateAuthDigestsScriptIterator>(
        mut script_entry_iter: I,
        auth_tree_data_blocks_allocation_blocks_log2: u32,
    ) -> Result<usize, NvFsError> {
        let mut encoded_len = 0usize;
        let mut last_entry_target_allocation_blocks_end = layout::PhysicalAllocBlockIndex::from(0);
        while let Some(script_entry) = script_entry_iter.next()? {
            let target_delta_encoded_len = leb128::leb128u_u64_encoded_len(
                u64::from(script_entry.target_range.begin() - last_entry_target_allocation_blocks_end)
                    >> auth_tree_data_blocks_allocation_blocks_log2,
            );
            let block_count_encoded_len = leb128::leb128u_u64_encoded_len(
                u64::from(script_entry.target_range.block_count()) >> auth_tree_data_blocks_allocation_blocks_log2,
            );
            encoded_len = encoded_len
                .checked_add(target_delta_encoded_len + block_count_encoded_len)
                .ok_or(NvFsError::DimensionsNotSupported)?;
            last_entry_target_allocation_blocks_end = script_entry.target_range.end();
        }

        // The script will be terminated with two consecutive zeroes.
        encoded_len.checked_add(2).ok_or(NvFsError::DimensionsNotSupported)
    }

    pub fn encode<I: Clone + JournalUpdateAuthDigestsScriptIterator>(
        mut buf: &mut [u8],
        mut script_entry_iter: I,
        auth_tree_data_blocks_allocation_blocks_log2: u32,
    ) -> Result<&mut [u8], NvFsError> {
        debug_assert!(
            buf.len() >= Self::encoded_len(script_entry_iter.clone(), auth_tree_data_blocks_allocation_blocks_log2)?
        );

        let mut last_entry_target_allocation_blocks_end = layout::PhysicalAllocBlockIndex::from(0);
        while let Some(script_entry) = script_entry_iter.next()? {
            buf = leb128::leb128u_u64_encode(
                buf,
                u64::from(script_entry.target_range.begin() - last_entry_target_allocation_blocks_end)
                    >> auth_tree_data_blocks_allocation_blocks_log2,
            );
            buf = leb128::leb128u_u64_encode(
                buf,
                u64::from(script_entry.target_range.block_count()) >> auth_tree_data_blocks_allocation_blocks_log2,
            );
            last_entry_target_allocation_blocks_end = script_entry.target_range.end();
        }

        // Encode the termination record as a pair of two zeroes.
        buf[0] = 0;
        buf[1] = 0;
        Ok(&mut buf[2..])
    }

    pub fn decode<'a, SI: io_slices::PeekableIoSlicesIter<'a, BackendIteratorError = NvFsError>>(
        mut src: SI,
        auth_tree_data_blocks_allocation_blocks_log2: u32,
        allocation_block_size128b_log2: u32,
    ) -> Result<Self, NvFsError> {
        let mut script = Vec::new();
        // One leb128-encoded 64 bit integer, signed or unsigned, is at most 10 bytes
        // long.
        let mut decode_buf: [u8; 20] = [0u8; 20];
        let mut decode_buf_len = 0;
        let mut peeking_src = src.decoupled_borrow();
        let mut remaining_src_len = src.total_len()?;
        let mut total_consumed_src_len = 0;
        let mut last_entry_target_allocation_blocks_end = 0u64;
        loop {
            // Refill the decode buffer.
            debug_assert_eq!(peeking_src.total_len()?, remaining_src_len);
            let decode_buf_refill_len = (decode_buf.len() - decode_buf_len).min(remaining_src_len);
            io_slices::SingletonIoSliceMut::new(
                &mut decode_buf[decode_buf_len..decode_buf_len + decode_buf_refill_len],
            )
            .map_infallible_err()
            .copy_from_iter(&mut peeking_src)?;
            decode_buf_len += decode_buf_refill_len;
            remaining_src_len -= decode_buf_refill_len;

            // There must be enough space for the two zero bytes of the termination
            // record.
            if decode_buf_len < 2 {
                return Err(NvFsError::from(
                    CocoonFsFormatError::InvalidJournalUpdateAuthDigestsScriptFormat,
                ));
            }

            // Decode the pair of (target delta, length).
            let mut remaining_decode_buf = &decode_buf[..decode_buf_len];
            let target_delta_auth_tree_data_blocks;
            (target_delta_auth_tree_data_blocks, remaining_decode_buf) =
                leb128::leb128u_u64_decode(remaining_decode_buf)
                    .map_err(|_| NvFsError::from(CocoonFsFormatError::InvalidJournalUpdateAuthDigestsScriptFormat))?;
            let auth_tree_data_blocks_count;
            (auth_tree_data_blocks_count, remaining_decode_buf) = leb128::leb128u_u64_decode(remaining_decode_buf)
                .map_err(|_| NvFsError::from(CocoonFsFormatError::InvalidJournalUpdateAuthDigestsScriptFormat))?;

            // Move the remaining bytes in decode_buf to the front.
            let consumed = decode_buf_len - remaining_decode_buf.len();
            total_consumed_src_len += consumed;
            decode_buf_len -= consumed;
            decode_buf.copy_within(consumed..consumed + decode_buf_len, 0);

            // Check for the termination record.
            if target_delta_auth_tree_data_blocks == 0 && auth_tree_data_blocks_count == 0 {
                break;
            } else if auth_tree_data_blocks_count == 0 {
                // Invalid value.
                return Err(NvFsError::from(
                    CocoonFsFormatError::InvalidJournalUpdateAuthDigestsScriptEntry,
                ));
            }

            let target_delta_allocation_blocks =
                target_delta_auth_tree_data_blocks << auth_tree_data_blocks_allocation_blocks_log2;
            if target_delta_allocation_blocks >> auth_tree_data_blocks_allocation_blocks_log2
                != target_delta_auth_tree_data_blocks
            {
                return Err(NvFsError::from(
                    CocoonFsFormatError::InvalidJournalUpdateAuthDigestsScriptEntry,
                ));
            }
            let entry_target_allocation_blocks_begin = last_entry_target_allocation_blocks_end
                .checked_add(target_delta_allocation_blocks)
                .ok_or(NvFsError::from(
                    CocoonFsFormatError::InvalidJournalUpdateAuthDigestsScriptEntry,
                ))?;

            let allocation_blocks_count = auth_tree_data_blocks_count << auth_tree_data_blocks_allocation_blocks_log2;
            if allocation_blocks_count >> auth_tree_data_blocks_allocation_blocks_log2 != auth_tree_data_blocks_count {
                return Err(NvFsError::from(
                    CocoonFsFormatError::InvalidJournalUpdateAuthDigestsScriptEntry,
                ));
            }

            let entry_target_allocation_blocks_end = entry_target_allocation_blocks_begin
                .checked_add(allocation_blocks_count)
                .ok_or(NvFsError::from(
                    CocoonFsFormatError::InvalidJournalUpdateAuthDigestsScriptEntry,
                ))?;
            if entry_target_allocation_blocks_end > u64::MAX >> (allocation_block_size128b_log2 + 7) {
                return Err(NvFsError::from(
                    CocoonFsFormatError::InvalidJournalUpdateAuthDigestsScriptEntry,
                ));
            }

            last_entry_target_allocation_blocks_end = entry_target_allocation_blocks_end;

            script.try_reserve(1)?;
            script.push(JournalUpdateAuthDigestsScriptEntry {
                target_range: layout::PhysicalAllocBlockRange::new(
                    layout::PhysicalAllocBlockIndex::from(entry_target_allocation_blocks_begin),
                    layout::PhysicalAllocBlockIndex::from(entry_target_allocation_blocks_end),
                ),
            });
        }

        drop(peeking_src);
        src.skip(total_consumed_src_len).map_err(|e| match e {
            io_slices::IoSlicesIterError::BackendIteratorError(e) => e,
            io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
            },
        })?;

        Ok(Self { script })
    }

    pub fn is_empty(&self) -> bool {
        self.script.is_empty()
    }

    pub fn len(&self) -> usize {
        self.script.len()
    }
}

impl ops::Index<usize> for JournalUpdateAuthDigestsScript {
    type Output = JournalUpdateAuthDigestsScriptEntry;

    fn index(&self, index: usize) -> &Self::Output {
        &self.script[index]
    }
}

pub struct JournalTrimsScriptEntry {
    target_range: layout::PhysicalAllocBlockRange,
}

impl JournalTrimsScriptEntry {
    pub fn get_target_range(&self) -> &layout::PhysicalAllocBlockRange {
        &self.target_range
    }
}

pub trait JournalTrimsScriptIterator {
    fn next(&mut self) -> Result<Option<JournalTrimsScriptEntry>, NvFsError>;
}

#[derive(Clone)]
pub struct TransactionJournalTrimsScriptIterator<'a> {
    alloc_bitmap: &'a alloc_bitmap::AllocBitmap,
    transaction_pending_frees_iter: alloc_bitmap::SparseAllocBitmapBlockIterator<'a>,
    next_pending_free: Option<(layout::PhysicalAllocBlockIndex, alloc_bitmap::BitmapWord)>,
    io_block_allocation_blocks_log2: u8,
}

impl<'a> TransactionJournalTrimsScriptIterator<'a> {
    pub fn new(
        fs_sync_state_alloc_bitmap: &'a alloc_bitmap::AllocBitmap,
        transaction_pending_frees: &'a alloc_bitmap::SparseAllocBitmap,
        io_block_allocation_blocks_log2: u8,
    ) -> Self {
        let mut transaction_pending_frees_iter =
            transaction_pending_frees.block_iter(io_block_allocation_blocks_log2 as u32);
        let next_pending_free = transaction_pending_frees_iter.next();
        Self {
            alloc_bitmap: fs_sync_state_alloc_bitmap,
            transaction_pending_frees_iter,
            next_pending_free,
            io_block_allocation_blocks_log2,
        }
    }
}

impl<'a> JournalTrimsScriptIterator for TransactionJournalTrimsScriptIterator<'a> {
    fn next(&mut self) -> Result<Option<JournalTrimsScriptEntry>, NvFsError> {
        let io_block_allocation_blocks_log2 = self.io_block_allocation_blocks_log2 as u32;
        let io_block_allocation_blocks = 1u32 << io_block_allocation_blocks_log2;

        // Find the next IO block that becomes fully free due to deallocations from the
        // transaction.
        let empty_sparse_alloc_bitmap = alloc_bitmap::SparseAllocBitmapUnion::new(&[]);
        let (region_allocation_blocks_begin, mut alloc_bitmap_io_block_iter) = loop {
            match self.next_pending_free.take() {
                Some(next_pending_free) => {
                    let mut alloc_bitmap_io_block_iter = self.alloc_bitmap.iter_chunked_at_allocation_block(
                        &empty_sparse_alloc_bitmap,
                        &empty_sparse_alloc_bitmap,
                        next_pending_free.0,
                        io_block_allocation_blocks,
                    );
                    let io_block_alloc_bitmap_word = alloc_bitmap_io_block_iter.next().unwrap_or(0);
                    if io_block_alloc_bitmap_word & !next_pending_free.1 == 0 {
                        // The complete IO block became free.
                        break (next_pending_free.0, alloc_bitmap_io_block_iter);
                    }
                    self.next_pending_free = self.transaction_pending_frees_iter.next();
                }
                None => return Ok(None),
            }
        };

        // Extend the region until there's a gap.
        let mut region_allocation_blocks = io_block_allocation_blocks as u64;
        let mut last_io_block_allocation_blocks_begin = region_allocation_blocks_begin;
        self.next_pending_free = self.transaction_pending_frees_iter.next();
        while let Some(next_pending_free) = self.next_pending_free.as_ref() {
            if next_pending_free.0 - last_io_block_allocation_blocks_begin
                != layout::AllocBlockCount::from(io_block_allocation_blocks as u64)
            {
                break;
            }
            let io_block_alloc_bitmap_word = alloc_bitmap_io_block_iter.next().unwrap_or(0);
            if io_block_alloc_bitmap_word & !next_pending_free.1 != 0 {
                // Skip over the current pending free entry so that the next invocation won't
                // reexamine it.
                self.next_pending_free = self.transaction_pending_frees_iter.next();
                break;
            }

            region_allocation_blocks += io_block_allocation_blocks as u64;
            last_io_block_allocation_blocks_begin = next_pending_free.0;
            self.next_pending_free = self.transaction_pending_frees_iter.next();
        }

        Ok(Some(JournalTrimsScriptEntry {
            target_range: layout::PhysicalAllocBlockRange::from((
                region_allocation_blocks_begin,
                layout::AllocBlockCount::from(region_allocation_blocks),
            )),
        }))
    }
}

pub struct JournalTrimsScript {
    script: Vec<JournalTrimsScriptEntry>,
}

impl JournalTrimsScript {
    pub fn encoded_len<I: JournalTrimsScriptIterator>(
        mut script_entry_iter: I,
        io_block_allocation_blocks_log2: u32,
    ) -> Result<usize, NvFsError> {
        let mut encoded_len = 0usize;
        let mut last_entry_target_allocation_blocks_end = layout::PhysicalAllocBlockIndex::from(0);
        while let Some(script_entry) = script_entry_iter.next()? {
            let target_delta_encoded_len = leb128::leb128u_u64_encoded_len(
                u64::from(script_entry.target_range.begin() - last_entry_target_allocation_blocks_end)
                    >> io_block_allocation_blocks_log2,
            );
            let block_count_encoded_len = leb128::leb128u_u64_encoded_len(
                u64::from(script_entry.target_range.block_count()) >> io_block_allocation_blocks_log2,
            );
            encoded_len = encoded_len
                .checked_add(target_delta_encoded_len + block_count_encoded_len)
                .ok_or(NvFsError::DimensionsNotSupported)?;
            last_entry_target_allocation_blocks_end = script_entry.target_range.end();
        }

        // The script will be terminated with two consecutive zeroes.
        encoded_len.checked_add(2).ok_or(NvFsError::DimensionsNotSupported)
    }

    pub fn encode<I: Clone + JournalTrimsScriptIterator>(
        mut buf: &mut [u8],
        mut script_entry_iter: I,
        io_block_allocation_blocks_log2: u32,
    ) -> Result<&mut [u8], NvFsError> {
        debug_assert!(buf.len() >= Self::encoded_len(script_entry_iter.clone(), io_block_allocation_blocks_log2)?);

        let mut last_entry_target_allocation_blocks_end = layout::PhysicalAllocBlockIndex::from(0);
        while let Some(script_entry) = script_entry_iter.next()? {
            buf = leb128::leb128u_u64_encode(
                buf,
                u64::from(script_entry.target_range.begin() - last_entry_target_allocation_blocks_end)
                    >> io_block_allocation_blocks_log2,
            );
            buf = leb128::leb128u_u64_encode(
                buf,
                u64::from(script_entry.target_range.block_count()) >> io_block_allocation_blocks_log2,
            );
            last_entry_target_allocation_blocks_end = script_entry.target_range.end();
        }

        // Encode the termination record as a pair of two zeroes.
        buf[0] = 0;
        buf[1] = 0;
        Ok(&mut buf[2..])
    }

    pub fn decode<'a, SI: io_slices::PeekableIoSlicesIter<'a, BackendIteratorError = NvFsError>>(
        mut src: SI,
        io_block_allocation_blocks_log2: u32,
        allocation_block_size_128b_log2: u32,
    ) -> Result<Self, NvFsError> {
        let mut script = Vec::new();
        // One leb128-encoded 64 bit integer, signed or unsigned, is at most 10 bytes
        // long.
        let mut decode_buf: [u8; 20] = [0u8; 20];
        let mut decode_buf_len = 0;
        let mut peeking_src = src.decoupled_borrow();
        let mut remaining_src_len = src.total_len()?;
        let mut total_consumed_src_len = 0;
        let mut last_entry_target_allocation_blocks_end = 0u64;
        loop {
            // Refill the decode buffer.
            debug_assert_eq!(peeking_src.total_len()?, remaining_src_len);
            let decode_buf_refill_len = (decode_buf.len() - decode_buf_len).min(remaining_src_len);
            io_slices::SingletonIoSliceMut::new(
                &mut decode_buf[decode_buf_len..decode_buf_len + decode_buf_refill_len],
            )
            .map_infallible_err()
            .copy_from_iter(&mut peeking_src)?;
            decode_buf_len += decode_buf_refill_len;
            remaining_src_len -= decode_buf_refill_len;

            // There must be enough space for the two zero bytes of the termination
            // record.
            if decode_buf_len < 2 {
                return Err(NvFsError::from(CocoonFsFormatError::InvalidJournalTrimsScriptFormat));
            }

            // Decode the pair of (target delta, length).
            let mut remaining_decode_buf = &decode_buf[..decode_buf_len];
            let target_delta_io_blocks;
            (target_delta_io_blocks, remaining_decode_buf) = leb128::leb128u_u64_decode(remaining_decode_buf)
                .map_err(|_| NvFsError::from(CocoonFsFormatError::InvalidJournalTrimsScriptFormat))?;
            let io_blocks_count;
            (io_blocks_count, remaining_decode_buf) = leb128::leb128u_u64_decode(remaining_decode_buf)
                .map_err(|_| NvFsError::from(CocoonFsFormatError::InvalidJournalTrimsScriptFormat))?;

            // Move the remaining bytes in decode_buf to the front.
            let consumed = decode_buf_len - remaining_decode_buf.len();
            total_consumed_src_len += consumed;
            decode_buf_len -= consumed;
            decode_buf.copy_within(consumed..consumed + decode_buf_len, 0);

            // Check for the termination record.
            if target_delta_io_blocks == 0 && io_blocks_count == 0 {
                break;
            } else if io_blocks_count == 0 {
                // Invalid value.
                return Err(NvFsError::from(CocoonFsFormatError::InvalidJournalTrimsScriptEntry));
            }

            let target_delta_allocation_blocks = target_delta_io_blocks << io_block_allocation_blocks_log2;
            if target_delta_allocation_blocks >> io_block_allocation_blocks_log2 != target_delta_io_blocks {
                return Err(NvFsError::from(CocoonFsFormatError::InvalidJournalTrimsScriptEntry));
            }
            let entry_target_allocation_blocks_begin = last_entry_target_allocation_blocks_end
                .checked_add(target_delta_allocation_blocks)
                .ok_or(NvFsError::from(CocoonFsFormatError::InvalidJournalTrimsScriptEntry))?;

            let allocation_blocks_count = io_blocks_count << io_block_allocation_blocks_log2;
            if allocation_blocks_count >> io_block_allocation_blocks_log2 != io_blocks_count {
                return Err(NvFsError::from(CocoonFsFormatError::InvalidJournalTrimsScriptEntry));
            }
            let entry_target_allocation_blocks_end = entry_target_allocation_blocks_begin
                .checked_add(allocation_blocks_count)
                .ok_or(NvFsError::from(CocoonFsFormatError::InvalidJournalTrimsScriptEntry))?;
            if entry_target_allocation_blocks_end > u64::MAX >> (allocation_block_size_128b_log2 + 7) {
                return Err(NvFsError::from(CocoonFsFormatError::InvalidJournalTrimsScriptEntry));
            }

            last_entry_target_allocation_blocks_end = entry_target_allocation_blocks_end;

            script.try_reserve(1)?;
            script.push(JournalTrimsScriptEntry {
                target_range: layout::PhysicalAllocBlockRange::new(
                    layout::PhysicalAllocBlockIndex::from(entry_target_allocation_blocks_begin),
                    layout::PhysicalAllocBlockIndex::from(entry_target_allocation_blocks_end),
                ),
            });
        }

        drop(peeking_src);
        src.skip(total_consumed_src_len).map_err(|e| match e {
            io_slices::IoSlicesIterError::BackendIteratorError(e) => e,
            io_slices::IoSlicesIterError::IoSlicesError(e) => match e {
                io_slices::IoSlicesError::BuffersExhausted => nvfs_err_internal!(),
            },
        })?;

        Ok(Self { script })
    }

    pub fn len(&self) -> usize {
        self.script.len()
    }
}

impl ops::Index<usize> for JournalTrimsScript {
    type Output = JournalTrimsScriptEntry;

    fn index(&self, index: usize) -> &Self::Output {
        &self.script[index]
    }
}
