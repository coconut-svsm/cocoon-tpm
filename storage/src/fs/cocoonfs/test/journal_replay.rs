// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

extern crate alloc;
use alloc::vec::Vec;

use super::{
    cocoonfs_test_commit_transaction_op_helper, cocoonfs_test_enumerate_inodes_op_collect,
    cocoonfs_test_fs_instance_into_chip_helper, cocoonfs_test_mkfs_op_helper, cocoonfs_test_openfs_op_helper,
    cocoonfs_test_read_inode_op_helper, cocoonfs_test_start_transaction_op_helper,
    cocoonfs_test_unlink_inodes_op_uncond, cocoonfs_test_write_inode_op_helper, CocoonFsTestConfigs,
};
use crate::fs::cocoonfs::extent_ptr;

#[test]
fn write_read_one_small() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let fs_instance = cocoonfs_test_mkfs_op_helper(&test_config, 3usize << 18, enable_trimming).unwrap();

            let transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            let inode_write_data = b"Hello CocoonFs";
            let transaction =
                cocoonfs_test_write_inode_op_helper(&fs_instance, transaction, 0x10, inode_write_data).unwrap();

            // Now commit with failure to apply the journal, thereby leaving it in place.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, true).unwrap();

            // Close the FS, open and try to read the file.
            let chip = cocoonfs_test_fs_instance_into_chip_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(chip).unwrap();

            let (_read_context, inode_read_data) =
                cocoonfs_test_read_inode_op_helper(&fs_instance, None, 0x10).unwrap();
            assert_eq!(inode_write_data.as_slice(), inode_read_data.unwrap().as_slice());
        }
    }
}

#[test]
fn write_read_one_large() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let allocation_block_size_128b_log2 = test_config.layout.allocation_block_size_128b_log2 as u32;
            let fs_instance = cocoonfs_test_mkfs_op_helper(
                &test_config,
                3usize << (18 + allocation_block_size_128b_log2),
                enable_trimming,
            )
            .unwrap();

            let transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            // Make the inode larger than what could be encoded as a direct extent in the
            // Inode Index, i.e. an indirect Inode Extents List will be needed.
            let inode_data_size = ((extent_ptr::EncodedExtentPtr::MAX_EXTENT_ALLOCATION_BLOCKS as usize + 1)
                << (allocation_block_size_128b_log2 + 7))
                + (7usize << (allocation_block_size_128b_log2 + 7 - 1) << (allocation_block_size_128b_log2 + 7));

            let mut inode_write_data = Vec::new();
            inode_write_data.resize(inode_data_size, 0x55u8);

            let transaction = cocoonfs_test_write_inode_op_helper(
                &fs_instance,
                transaction,
                0x10,
                &inode_write_data[..inode_data_size],
            )
            .unwrap();

            // Now commit with failure to apply the journal, thereby leaving it in place.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, true).unwrap();

            // Close the FS, open and try to read again.
            let chip = cocoonfs_test_fs_instance_into_chip_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(chip).unwrap();

            let (_read_context, inode_read_data) =
                cocoonfs_test_read_inode_op_helper(&fs_instance, None, 0x10).unwrap();
            assert_eq!(inode_write_data.as_slice(), inode_read_data.unwrap().as_slice());
        }
    }
}

#[test]
fn write_read_two_large_interleaved_growth() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let allocation_block_size_128b_log2 = test_config.layout.allocation_block_size_128b_log2 as u32;
            let fs_instance = cocoonfs_test_mkfs_op_helper(
                &test_config,
                3usize << (18 + allocation_block_size_128b_log2),
                enable_trimming,
            )
            .unwrap();

            let transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            // Make the inode larger than what could be encoded as a direct extent in the
            // Inode Index, i.e. an indirect Inode Extents List will be needed.
            let inode_data_initial_size = (extent_ptr::EncodedExtentPtr::MAX_EXTENT_ALLOCATION_BLOCKS as usize + 1)
                << (allocation_block_size_128b_log2 + 7);
            let inode_data_final_size = inode_data_initial_size
                + (3usize << (allocation_block_size_128b_log2 + 7 - 1) << (allocation_block_size_128b_log2 + 7));

            let mut inode0_write_data = Vec::new();
            inode0_write_data.resize(inode_data_final_size, 0x55u8);
            let mut inode1_write_data = Vec::new();
            inode1_write_data.resize(inode_data_final_size, 0xaau8);

            let transaction = cocoonfs_test_write_inode_op_helper(
                &fs_instance,
                transaction,
                0x10,
                &inode0_write_data[..inode_data_initial_size],
            )
            .unwrap();
            let mut transaction = cocoonfs_test_write_inode_op_helper(
                &fs_instance,
                transaction,
                0x11,
                &inode1_write_data[..inode_data_initial_size],
            )
            .unwrap();

            let mut inode_data_cur_size = inode_data_initial_size;
            while inode_data_cur_size < inode_data_final_size {
                inode_data_cur_size += 1usize << (allocation_block_size_128b_log2 + 7);

                transaction = cocoonfs_test_write_inode_op_helper(
                    &fs_instance,
                    transaction,
                    0x10,
                    &inode0_write_data[..inode_data_cur_size],
                )
                .unwrap();
                transaction = cocoonfs_test_write_inode_op_helper(
                    &fs_instance,
                    transaction,
                    0x11,
                    &inode1_write_data[..inode_data_cur_size],
                )
                .unwrap();
            }

            // Now commit with failure to apply the journal, thereby leaving it in place.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, true).unwrap();

            // Close the FS, open and try to read again.
            let chip = cocoonfs_test_fs_instance_into_chip_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(chip).unwrap();

            let (_read_context, inode0_read_data) =
                cocoonfs_test_read_inode_op_helper(&fs_instance, None, 0x10).unwrap();
            assert_eq!(inode0_write_data.as_slice(), inode0_read_data.unwrap().as_slice());

            let (_read_context, inode1_read_data) =
                cocoonfs_test_read_inode_op_helper(&fs_instance, None, 0x11).unwrap();
            assert_eq!(inode1_write_data.as_slice(), inode1_read_data.unwrap().as_slice());
        }
    }
}

#[test]
fn write_update_two_large_interleaved_growth() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let allocation_block_size_128b_log2 = test_config.layout.allocation_block_size_128b_log2 as u32;
            let fs_instance = cocoonfs_test_mkfs_op_helper(
                &test_config,
                3usize << (18 + allocation_block_size_128b_log2),
                enable_trimming,
            )
            .unwrap();

            let transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            // Make the inode larger than what could be encoded as a direct extent in the
            // Inode Index, i.e. an indirect Inode Extents List will be needed.
            let inode_data_initial_size = (extent_ptr::EncodedExtentPtr::MAX_EXTENT_ALLOCATION_BLOCKS as usize + 1)
                << (allocation_block_size_128b_log2 + 7);
            let inode_data_final_size = inode_data_initial_size
                + (3usize << (allocation_block_size_128b_log2 + 7 - 1) << (allocation_block_size_128b_log2 + 7));

            let mut inode0_write_data = Vec::new();
            inode0_write_data.resize(inode_data_final_size, 0x55u8);
            let mut inode1_write_data = Vec::new();
            inode1_write_data.resize(inode_data_final_size, 0xaau8);

            let transaction = cocoonfs_test_write_inode_op_helper(
                &fs_instance,
                transaction,
                0x10,
                &inode0_write_data[..inode_data_initial_size],
            )
            .unwrap();
            let mut transaction = cocoonfs_test_write_inode_op_helper(
                &fs_instance,
                transaction,
                0x11,
                &inode1_write_data[..inode_data_initial_size],
            )
            .unwrap();

            let mut inode_data_cur_size = inode_data_initial_size;
            while inode_data_cur_size < inode_data_final_size {
                inode_data_cur_size += 1usize << (allocation_block_size_128b_log2 + 7);

                transaction = cocoonfs_test_write_inode_op_helper(
                    &fs_instance,
                    transaction,
                    0x10,
                    &inode0_write_data[..inode_data_cur_size],
                )
                .unwrap();
                transaction = cocoonfs_test_write_inode_op_helper(
                    &fs_instance,
                    transaction,
                    0x11,
                    &inode1_write_data[..inode_data_cur_size],
                )
                .unwrap();
            }

            // Commit
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            // Update the first inode.
            let transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();
            let mut inode0_write_data = Vec::new();
            inode0_write_data.resize(inode_data_final_size, 0x56u8);

            let transaction =
                cocoonfs_test_write_inode_op_helper(&fs_instance, transaction, 0x10, &inode0_write_data).unwrap();

            // Commit with failure to apply the journal, thereby leaving it in place.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, true).unwrap();

            // Close the FS, open and try to read again.
            let chip = cocoonfs_test_fs_instance_into_chip_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(chip).unwrap();

            let (_read_context, inode0_read_data) =
                cocoonfs_test_read_inode_op_helper(&fs_instance, None, 0x10).unwrap();
            assert_eq!(inode0_write_data.as_slice(), inode0_read_data.unwrap().as_slice());

            let (_read_context, inode1_read_data) =
                cocoonfs_test_read_inode_op_helper(&fs_instance, None, 0x11).unwrap();
            assert_eq!(inode1_write_data.as_slice(), inode1_read_data.unwrap().as_slice());

            // Update the second inode.
            let transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();
            let mut inode1_write_data = Vec::new();
            inode1_write_data.resize(inode_data_final_size, 0xabu8);

            let transaction =
                cocoonfs_test_write_inode_op_helper(&fs_instance, transaction, 0x11, &inode1_write_data).unwrap();

            // Commit with failure to apply the journal, thereby leaving it in place.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, true).unwrap();

            // Close the FS, open and try to read again.
            let chip = cocoonfs_test_fs_instance_into_chip_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(chip).unwrap();

            let (_read_context, inode0_read_data) =
                cocoonfs_test_read_inode_op_helper(&fs_instance, None, 0x10).unwrap();
            assert_eq!(inode0_write_data.as_slice(), inode0_read_data.unwrap().as_slice());

            let (_read_context, inode1_read_data) =
                cocoonfs_test_read_inode_op_helper(&fs_instance, None, 0x11).unwrap();
            assert_eq!(inode1_write_data.as_slice(), inode1_read_data.unwrap().as_slice());
        }
    }
}

#[test]
fn write_unlink_two_large_interleaved_growth() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let allocation_block_size_128b_log2 = test_config.layout.allocation_block_size_128b_log2 as u32;
            let fs_instance = cocoonfs_test_mkfs_op_helper(
                &test_config,
                3usize << (18 + allocation_block_size_128b_log2),
                enable_trimming,
            )
            .unwrap();

            let transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            // Make the inode larger than what could be encoded as a direct extent in the
            // Inode Index, i.e. an indirect Inode Extents List will be needed.
            let inode_data_initial_size = (extent_ptr::EncodedExtentPtr::MAX_EXTENT_ALLOCATION_BLOCKS as usize + 1)
                << (allocation_block_size_128b_log2 + 7);
            let inode_data_final_size = inode_data_initial_size
                + (3usize << (allocation_block_size_128b_log2 + 7 - 1) << (allocation_block_size_128b_log2 + 7));

            let mut inode0_write_data = Vec::new();
            inode0_write_data.resize(inode_data_final_size, 0x55u8);
            let mut inode1_write_data = Vec::new();
            inode1_write_data.resize(inode_data_final_size, 0xaau8);

            let transaction = cocoonfs_test_write_inode_op_helper(
                &fs_instance,
                transaction,
                0x10,
                &inode0_write_data[..inode_data_initial_size],
            )
            .unwrap();
            let mut transaction = cocoonfs_test_write_inode_op_helper(
                &fs_instance,
                transaction,
                0x11,
                &inode1_write_data[..inode_data_initial_size],
            )
            .unwrap();

            let mut inode_data_cur_size = inode_data_initial_size;
            while inode_data_cur_size < inode_data_final_size {
                inode_data_cur_size += 1usize << (allocation_block_size_128b_log2 + 7);

                transaction = cocoonfs_test_write_inode_op_helper(
                    &fs_instance,
                    transaction,
                    0x10,
                    &inode0_write_data[..inode_data_cur_size],
                )
                .unwrap();
                transaction = cocoonfs_test_write_inode_op_helper(
                    &fs_instance,
                    transaction,
                    0x11,
                    &inode1_write_data[..inode_data_cur_size],
                )
                .unwrap();
            }

            // Commit
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            // Unlink the first inode.
            let transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();
            let transaction = cocoonfs_test_unlink_inodes_op_uncond(&fs_instance, transaction, 0x10..=0x10).unwrap();

            // Commit with failure to apply the journal, thereby leaving it in place.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, true).unwrap();

            // Close the FS, open, verify that the unlinked inode is gone and read the
            // other's data.
            let chip = cocoonfs_test_fs_instance_into_chip_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(chip).unwrap();

            assert_eq!(
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x10..=0x11)
                    .unwrap()
                    .1,
                [0x11]
            );
            let (_read_context, inode1_read_data) =
                cocoonfs_test_read_inode_op_helper(&fs_instance, None, 0x11).unwrap();
            assert_eq!(inode1_write_data.as_slice(), inode1_read_data.unwrap().as_slice());

            // Unlink the second inode.
            let transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();
            let transaction = cocoonfs_test_unlink_inodes_op_uncond(&fs_instance, transaction, 0x11..=0x11).unwrap();

            // Commit with failure to apply the journal, thereby leaving it in place.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, true).unwrap();

            // Close the FS, open and verify both inodes are gone now.
            let chip = cocoonfs_test_fs_instance_into_chip_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(chip).unwrap();

            assert_eq!(
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x10..=0x11)
                    .unwrap()
                    .1,
                []
            );
        }
    }
}
