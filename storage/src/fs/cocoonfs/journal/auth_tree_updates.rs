// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

extern crate alloc;
use alloc::vec::Vec;

use crate::{
    fs::{
        NvFsError,
        cocoonfs::{
            CocoonFsFormatError, alloc_bitmap, auth_tree, extents,
            journal::apply_script::JournalUpdateAuthDigestsScriptIterator, layout,
        },
    },
    nvfs_err_internal,
};
use core::cmp;

pub fn collect_alloc_bitmap_blocks_for_auth_tree_reconstruction<UI: JournalUpdateAuthDigestsScriptIterator>(
    mut update_auth_digests_script_iter: UI,
    alloc_bitmap_file: &alloc_bitmap::AllocBitmapFile,
    auth_tree_config: &auth_tree::AuthTreeConfig,
    auth_tree_data_block_allocation_blocks_log2: u8,
) -> Result<Vec<u64>, NvFsError> {
    let auth_tree_data_block_allocation_blocks_log2 = auth_tree_data_block_allocation_blocks_log2 as u32;
    let mut alloc_bitmap_file_block_indices = Vec::<u64>::new();

    let mut covered_physical_allocation_blocks_end = layout::PhysicalAllocBlockIndex::from(0u64);
    while let Some(update_auth_digests_script_entry) = update_auth_digests_script_iter.next()? {
        let updated_physical_allocation_blocks_range = update_auth_digests_script_entry.get_target_range();
        if updated_physical_allocation_blocks_range.end() <= covered_physical_allocation_blocks_end {
            continue;
        }

        // The update script entries' associated target regions are aligned to the
        // Authentication Tree Data Block size.
        if updated_physical_allocation_blocks_range
            .begin()
            .align_down(auth_tree_data_block_allocation_blocks_log2)
            != updated_physical_allocation_blocks_range.begin()
            || updated_physical_allocation_blocks_range
                .end()
                .align_down(auth_tree_data_block_allocation_blocks_log2)
                != updated_physical_allocation_blocks_range.end()
        {
            return Err(nvfs_err_internal!());
        }

        let updated_physical_allocation_blocks_range = layout::PhysicalAllocBlockRange::new(
            updated_physical_allocation_blocks_range
                .begin()
                .max(covered_physical_allocation_blocks_end)
                .align_down(auth_tree_data_block_allocation_blocks_log2),
            updated_physical_allocation_blocks_range.end(),
        );

        // Translate to a (contiguous) range in the Authentication Tree Data domain.
        let first_updated_auth_tree_data_block_index =
            auth_tree_config.translate_physical_to_data_block_index(updated_physical_allocation_blocks_range.begin());
        let last_updated_auth_tree_data_block_index = auth_tree_config.translate_physical_to_data_block_index(
            layout::PhysicalAllocBlockIndex::from(u64::from(updated_physical_allocation_blocks_range.end()) - 1)
                .align_down(auth_tree_data_block_allocation_blocks_log2),
        );

        // As leaf nodes must be assumed partially written during the Journal
        // replay, they need to get reconstructed in full. Extend the
        // data range to the full (logical) range covered by these.
        let needed_auth_tree_data_blocks_begin = auth_tree_config
            .covering_leaf_node_id(first_updated_auth_tree_data_block_index)
            .first_covered_data_block();
        let last_needed_auth_tree_data_block_index = auth_tree_config
            .covering_leaf_node_id(last_updated_auth_tree_data_block_index)
            .last_covered_data_block();
        let needed_auth_tree_data_blocks_end =
            last_needed_auth_tree_data_block_index + auth_tree::AuthTreeDataBlockCount::from(1u64);
        // Map the logical Authentication Tree Data Range back to a list of contiguous
        // physical extents, possibly interspersed with the extents for the
        // Authentication Tree itself on storage.
        for needed_auth_tree_data_physical_segment in
            auth_tree_config.translate_data_block_range_to_physical(&auth_tree::AuthTreeDataBlockRange::new(
                needed_auth_tree_data_blocks_begin,
                needed_auth_tree_data_blocks_end,
            ))
        {
            let needed_physical_allocation_blocks_range = layout::PhysicalAllocBlockRange::from((
                needed_auth_tree_data_physical_segment.1,
                needed_auth_tree_data_physical_segment.0.block_count(),
            ));
            if needed_physical_allocation_blocks_range.end() <= covered_physical_allocation_blocks_end {
                continue;
            }

            // And collect all allocation bitmap file blocks tracking any Allocation Block
            // within the current physical data range.
            covered_physical_allocation_blocks_end =
                covered_physical_allocation_blocks_end.max(needed_physical_allocation_blocks_range.begin());
            while covered_physical_allocation_blocks_end < needed_physical_allocation_blocks_range.end() {
                let alloc_bitmap_file_block_index = alloc_bitmap_file.bitmap_word_index_to_file_block_index(
                    u64::from(covered_physical_allocation_blocks_end) >> alloc_bitmap::BITMAP_WORD_BITS_LOG2,
                )?;
                debug_assert!(
                    alloc_bitmap_file_block_indices
                        .last()
                        .map(|l| *l < alloc_bitmap_file_block_index)
                        .unwrap_or(true)
                );
                alloc_bitmap_file_block_indices.try_reserve(1)?;
                alloc_bitmap_file_block_indices.push(alloc_bitmap_file_block_index);

                covered_physical_allocation_blocks_end = layout::PhysicalAllocBlockIndex::from(
                    (alloc_bitmap_file_block_index + 1)
                        .checked_mul(
                            alloc_bitmap_file.get_bitmap_words_per_file_block() << alloc_bitmap::BITMAP_WORD_BITS_LOG2,
                        )
                        .unwrap_or(u64::MAX),
                );
            }
        }
    }

    Ok(alloc_bitmap_file_block_indices)
}

pub fn alloc_bitmap_file_block_indices_to_physical_extents(
    alloc_bitmap_file_block_indices: &[u64],
    alloc_bitmap_file_extents: &extents::LogicalExtents,
    image_layout: &layout::ImageLayout,
) -> Result<extents::PhysicalExtents, NvFsError> {
    debug_assert!(alloc_bitmap_file_block_indices.is_sorted());

    let mut physical_extents = extents::PhysicalExtents::new();

    let alloc_bitmap_file_block_allocation_blocks_log2 =
        image_layout.allocation_bitmap_file_block_allocation_blocks_log2 as u32;
    let alloc_bitmap_file_block_allocation_blocks =
        layout::AllocBlockCount::from(1u64 << alloc_bitmap_file_block_allocation_blocks_log2);
    let mut i = 0;
    while i < alloc_bitmap_file_block_indices.len() {
        let cur_alloc_bitmap_file_block_logical_allocation_blocks_begin = layout::LogicalAllocBlockIndex::from(
            alloc_bitmap_file_block_indices[i] << alloc_bitmap_file_block_allocation_blocks_log2,
        );
        i += 1;
        let containing_logical_alloc_bitmap_file_extent = alloc_bitmap_file_extents
            .lookup(cur_alloc_bitmap_file_block_logical_allocation_blocks_begin)
            .ok_or_else(|| nvfs_err_internal!())?;
        if containing_logical_alloc_bitmap_file_extent
            .logical_range()
            .block_count()
            < alloc_bitmap_file_block_allocation_blocks
        {
            return Err(NvFsError::from(
                CocoonFsFormatError::UnalignedAllocationBitmapFileExtents,
            ));
        }

        let mut alloc_file_blocks_run_physical_allocation_blocks_begin =
            containing_logical_alloc_bitmap_file_extent.physical_range().begin();
        let mut alloc_file_blocks_run_physical_allocation_blocks_end =
            alloc_file_blocks_run_physical_allocation_blocks_begin + alloc_bitmap_file_block_allocation_blocks;

        // In order to avoid lookups in the allocation bitmap file's extent for every
        // single file block in the list, consume as much from the found extent
        // as possible.
        while i < alloc_bitmap_file_block_indices.len() {
            let cur_alloc_bitmap_file_block_logical_allocation_blocks_begin = layout::LogicalAllocBlockIndex::from(
                alloc_bitmap_file_block_indices[i] << alloc_bitmap_file_block_allocation_blocks_log2,
            );
            if cur_alloc_bitmap_file_block_logical_allocation_blocks_begin
                >= containing_logical_alloc_bitmap_file_extent.logical_range().end()
            {
                break;
            }

            if containing_logical_alloc_bitmap_file_extent.logical_range().end()
                - cur_alloc_bitmap_file_block_logical_allocation_blocks_begin
                < alloc_bitmap_file_block_allocation_blocks
            {
                return Err(NvFsError::from(
                    CocoonFsFormatError::UnalignedAllocationBitmapFileExtents,
                ));
            }

            if alloc_bitmap_file_block_indices[i] != alloc_bitmap_file_block_indices[i - 1] + 1 {
                // There's a gap. Add what's been found so far and continue with the next
                // contiguous run still contained in the current allocation file
                // extent.
                physical_extents.push_extent(
                    &layout::PhysicalAllocBlockRange::new(
                        alloc_file_blocks_run_physical_allocation_blocks_begin,
                        alloc_file_blocks_run_physical_allocation_blocks_end,
                    ),
                    false,
                )?;
                alloc_file_blocks_run_physical_allocation_blocks_begin =
                    alloc_file_blocks_run_physical_allocation_blocks_end
                        + layout::AllocBlockCount::from(
                            (alloc_bitmap_file_block_indices[i] - alloc_bitmap_file_block_indices[i - 1])
                                << alloc_bitmap_file_block_allocation_blocks_log2,
                        );
                alloc_file_blocks_run_physical_allocation_blocks_end =
                    alloc_file_blocks_run_physical_allocation_blocks_begin;
            }
            i += 1;
            alloc_file_blocks_run_physical_allocation_blocks_end += alloc_bitmap_file_block_allocation_blocks;
        }

        physical_extents.push_extent(
            &layout::PhysicalAllocBlockRange::new(
                alloc_file_blocks_run_physical_allocation_blocks_begin,
                alloc_file_blocks_run_physical_allocation_blocks_end,
            ),
            false,
        )?;
    }

    // Finally, sort and merge the found physical extents.
    let physical_extents_len = physical_extents.len();
    physical_extents.sort_extents_by(
        0..physical_extents_len,
        |e0, e1| match e0.end().cmp(&e1.begin()) {
            cmp::Ordering::Less => cmp::Ordering::Less,
            cmp::Ordering::Equal => cmp::Ordering::Less,
            cmp::Ordering::Greater => {
                // There are no overlaps.
                debug_assert!(e0.begin() >= e1.end());
                cmp::Ordering::Greater
            }
        },
        false,
    );

    Ok(physical_extents)
}
