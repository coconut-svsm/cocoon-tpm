// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

extern crate alloc;
use alloc::vec::Vec;

use super::{
    CocoonFsTestConfigs, cocoonfs_test_commit_transaction_op_helper, cocoonfs_test_fs_instance_into_chip_helper,
    cocoonfs_test_mkfs_op_helper, cocoonfs_test_openfs_op_helper, cocoonfs_test_read_inode_op_helper,
    cocoonfs_test_start_transaction_op_helper, cocoonfs_test_write_inode_op_helper,
};
use crate::fs::{self, cocoonfs::extent_ptr};

#[test]
fn write_read_one_small() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let fs_instance = cocoonfs_test_mkfs_op_helper(&test_config, 3usize << 18, enable_trimming).unwrap();

            let transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            let inode_write_data = b"Hello CocoonFs";
            let transaction =
                cocoonfs_test_write_inode_op_helper(&fs_instance, transaction, 0x10, inode_write_data).unwrap();

            // Read through the uncommitted transaction
            let (read_context, inode_read_data) = cocoonfs_test_read_inode_op_helper(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x10,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert_eq!(inode_write_data.as_slice(), inode_read_data.unwrap().as_slice());

            // Now commit and read from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            let (_read_context, inode_read_data) =
                cocoonfs_test_read_inode_op_helper(&fs_instance, None, 0x10).unwrap();
            assert_eq!(inode_write_data.as_slice(), inode_read_data.unwrap().as_slice());

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
fn write_read_one_small_uncommitted_overwrite() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let fs_instance = cocoonfs_test_mkfs_op_helper(&test_config, 3usize << 18, enable_trimming).unwrap();

            let transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            // First write.
            let inode_write_data = b"Hello CocoonFs";
            let transaction =
                cocoonfs_test_write_inode_op_helper(&fs_instance, transaction, 0x10, inode_write_data).unwrap();

            // Read through the uncommitted transaction
            let (read_context, inode_read_data) = cocoonfs_test_read_inode_op_helper(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x10,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert_eq!(inode_write_data.as_slice(), inode_read_data.unwrap().as_slice());

            // Second write, overwrite what's staged at the transaction.
            let inode_write_data = b"Sup CocoonFs";
            let transaction =
                cocoonfs_test_write_inode_op_helper(&fs_instance, transaction, 0x10, inode_write_data).unwrap();

            // Read again through the uncommitted transaction
            let (read_context, inode_read_data) = cocoonfs_test_read_inode_op_helper(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x10,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert_eq!(inode_write_data.as_slice(), inode_read_data.unwrap().as_slice());

            // Now commit and read from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            let (_read_context, inode_read_data) =
                cocoonfs_test_read_inode_op_helper(&fs_instance, None, 0x10).unwrap();
            assert_eq!(inode_write_data.as_slice(), inode_read_data.unwrap().as_slice());

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
fn write_read_one_small_committed_overwrite() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let fs_instance = cocoonfs_test_mkfs_op_helper(&test_config, 3usize << 18, enable_trimming).unwrap();

            let transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            // First write.
            let inode_write_data = b"Hello CocoonFs";
            let transaction =
                cocoonfs_test_write_inode_op_helper(&fs_instance, transaction, 0x10, inode_write_data).unwrap();

            // Read through the uncommitted transaction
            let (read_context, inode_read_data) = cocoonfs_test_read_inode_op_helper(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x10,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert_eq!(inode_write_data.as_slice(), inode_read_data.unwrap().as_slice());

            // Now commit and read from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            let (_read_context, inode_read_data) =
                cocoonfs_test_read_inode_op_helper(&fs_instance, None, 0x10).unwrap();
            assert_eq!(inode_write_data.as_slice(), inode_read_data.unwrap().as_slice());

            // Close the FS, open and try to read again.
            let chip = cocoonfs_test_fs_instance_into_chip_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(chip).unwrap();

            let (_read_context, inode_read_data) =
                cocoonfs_test_read_inode_op_helper(&fs_instance, None, 0x10).unwrap();
            assert_eq!(inode_write_data.as_slice(), inode_read_data.unwrap().as_slice());

            // Second write, overwrite the committed data.
            let transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            let inode_write_data = b"Sup CocoonFs";
            let transaction =
                cocoonfs_test_write_inode_op_helper(&fs_instance, transaction, 0x10, inode_write_data).unwrap();

            // Read again through the uncommitted transaction
            let (read_context, inode_read_data) = cocoonfs_test_read_inode_op_helper(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x10,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert_eq!(inode_write_data.as_slice(), inode_read_data.unwrap().as_slice());

            // Now commit and read from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            let (_read_context, inode_read_data) =
                cocoonfs_test_read_inode_op_helper(&fs_instance, None, 0x10).unwrap();
            assert_eq!(inode_write_data.as_slice(), inode_read_data.unwrap().as_slice());

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
fn write_read_one_medium() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let fs_instance = cocoonfs_test_mkfs_op_helper(&test_config, 3usize << 18, enable_trimming).unwrap();

            let transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            let allocation_block_size_128b_log2 = test_config.layout.allocation_block_size_128b_log2 as u32;
            // Make the inode larger than what could be encoded as a direct extent in the
            // Inode Index, i.e. an indirect Inode Extents List will be needed.
            let inode_data_size = (extent_ptr::EncodedExtentPtr::MAX_EXTENT_ALLOCATION_BLOCKS as usize + 1)
                << (allocation_block_size_128b_log2 + 7);
            let mut inode_write_data = Vec::new();
            inode_write_data.resize(inode_data_size, 0x55u8);

            let transaction =
                cocoonfs_test_write_inode_op_helper(&fs_instance, transaction, 0x10, &inode_write_data).unwrap();

            // Read through the uncommitted transaction
            let (read_context, inode_read_data) = cocoonfs_test_read_inode_op_helper(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x10,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert_eq!(inode_write_data.as_slice(), inode_read_data.unwrap().as_slice());

            // Now commit and read from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            let (_read_context, inode_read_data) =
                cocoonfs_test_read_inode_op_helper(&fs_instance, None, 0x10).unwrap();
            assert_eq!(inode_write_data.as_slice(), inode_read_data.unwrap().as_slice());

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

            // Read through the uncommitted transaction
            let (read_context, inode0_read_data) = cocoonfs_test_read_inode_op_helper(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x10,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert_eq!(inode0_write_data.as_slice(), inode0_read_data.unwrap().as_slice());

            let (read_context, inode1_read_data) = cocoonfs_test_read_inode_op_helper(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x11,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert_eq!(inode1_write_data.as_slice(), inode1_read_data.unwrap().as_slice());

            // Now commit and read from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            let (_read_context, inode0_read_data) =
                cocoonfs_test_read_inode_op_helper(&fs_instance, None, 0x10).unwrap();
            assert_eq!(inode0_write_data.as_slice(), inode0_read_data.unwrap().as_slice());

            let (_read_context, inode1_read_data) =
                cocoonfs_test_read_inode_op_helper(&fs_instance, None, 0x11).unwrap();
            assert_eq!(inode1_write_data.as_slice(), inode1_read_data.unwrap().as_slice());

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
