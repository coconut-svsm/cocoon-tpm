// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

extern crate alloc;

use super::{
    CocoonFsTestConfigs, cocoonfs_test_commit_transaction_op_helper, cocoonfs_test_enumerate_inodes_op_collect,
    cocoonfs_test_fs_instance_into_blkdev_helper, cocoonfs_test_mkfs_op_helper, cocoonfs_test_openfs_op_helper,
    cocoonfs_test_read_inode_op_helper, cocoonfs_test_start_transaction_op_helper,
    cocoonfs_test_unlink_inodes_op_uncond, cocoonfs_test_write_inode_op_helper,
};
use crate::fs;

#[test]
fn enumerate_inodes() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let fs_instance = cocoonfs_test_mkfs_op_helper(&test_config, 3usize << 18, enable_trimming).unwrap();

            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            for inode in 0x10..=0x19 {
                transaction = cocoonfs_test_write_inode_op_helper(&fs_instance, transaction, inode, &[]).unwrap();
            }

            // Enumerate the full range through the uncommitted transaction
            let (read_context, inodes) = cocoonfs_test_enumerate_inodes_op_collect(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x0..=u32::MAX,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert!(inodes.iter().copied().eq(0x10u32..=0x19));

            // Enumerate the exact range through the uncommitted transaction
            let (read_context, inodes) = cocoonfs_test_enumerate_inodes_op_collect(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x10u32..=0x19,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert!(inodes.iter().copied().eq(0x10u32..=0x19));

            // Enumerate a subrange through the uncommitted transaction
            let (read_context, inodes) = cocoonfs_test_enumerate_inodes_op_collect(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x11u32..=0x18,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert!(inodes.iter().copied().eq(0x11u32..=0x18));

            // Now commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            // Enumerate the full range.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10u32..=0x19));

            // Enumerate the exact range.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x10..=0x19).unwrap();
            assert!(inodes.iter().copied().eq(0x10u32..=0x19));

            // Enumerate a subrange.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x11..=0x18).unwrap();
            assert!(inodes.iter().copied().eq(0x11u32..=0x18));

            // Close the FS, open and try to enumerate again.
            let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(blkdev).unwrap();

            // Enumerate the full range.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10u32..=0x19));

            // Enumerate the exact range.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x10..=0x19).unwrap();
            assert!(inodes.iter().copied().eq(0x10u32..=0x19));

            // Enumerate a subrange.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x11..=0x18).unwrap();
            assert!(inodes.iter().copied().eq(0x11u32..=0x18));
        }
    }
}

#[test]
fn create_many_inodes_forward() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let allocation_block_size_128b_log2 = test_config.layout.allocation_block_size_128b_log2 as u32;
            let fs_instance = cocoonfs_test_mkfs_op_helper(
                &test_config,
                3usize << (19 + allocation_block_size_128b_log2),
                enable_trimming,
            )
            .unwrap();

            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            for inode in 0x10..0x1010 {
                transaction = cocoonfs_test_write_inode_op_helper(
                    &fs_instance,
                    transaction,
                    inode,
                    inode.to_le_bytes().as_slice(),
                )
                .unwrap();
            }

            // Enumerate through the uncommitted transaction and verify all created inodes
            // are there.
            let (read_context, inodes) = cocoonfs_test_enumerate_inodes_op_collect(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x0..=u32::MAX,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Now commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            // Enumerate to verify the inodes are still there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Read all inode's contents and verify they match expectations. This verifies
            // all inodes can get looked up and that the respective inodes'
            // entries point to the expected data.
            for inode in 0x10..0x1010 {
                let (_read_context, inode_data) =
                    cocoonfs_test_read_inode_op_helper(&fs_instance, None, inode).unwrap();
                let inode_data = inode_data.unwrap();
                assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());
            }

            // Close the FS, open and try to enumerate + read again.
            let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(blkdev).unwrap();

            // Enumerate to verify the inodes are still there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Read all inode's contents and verify they match expectations.
            for inode in 0x10..0x1010 {
                let (_read_context, inode_data) =
                    cocoonfs_test_read_inode_op_helper(&fs_instance, None, inode).unwrap();
                let inode_data = inode_data.unwrap();
                assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());
            }
        }
    }
}

#[test]
fn create_many_inodes_forward_sliced() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let allocation_block_size_128b_log2 = test_config.layout.allocation_block_size_128b_log2 as u32;
            let fs_instance = cocoonfs_test_mkfs_op_helper(
                &test_config,
                3usize << (19 + allocation_block_size_128b_log2),
                enable_trimming,
            )
            .unwrap();

            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            for inode in (0x10..0x1010).step_by(2) {
                transaction = cocoonfs_test_write_inode_op_helper(
                    &fs_instance,
                    transaction,
                    inode,
                    inode.to_le_bytes().as_slice(),
                )
                .unwrap();
            }
            for inode in (0x10..0x1010).step_by(2) {
                let inode = inode + 1;
                transaction = cocoonfs_test_write_inode_op_helper(
                    &fs_instance,
                    transaction,
                    inode,
                    inode.to_le_bytes().as_slice(),
                )
                .unwrap();
            }

            // Enumerate through the uncommitted transaction and verify all created inodes
            // are there.
            let (read_context, inodes) = cocoonfs_test_enumerate_inodes_op_collect(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x0..=u32::MAX,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Now commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            // Enumerate to verify the inodes are still there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Read all inode's contents and verify they match expectations. This verifies
            // all inodes can get looked up and that the respective inodes'
            // entries point to the expected data.
            for inode in 0x10..0x1010 {
                let (_read_context, inode_data) =
                    cocoonfs_test_read_inode_op_helper(&fs_instance, None, inode).unwrap();
                let inode_data = inode_data.unwrap();
                assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());
            }

            // Close the FS, open and try to enumerate + read again.
            let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(blkdev).unwrap();

            // Enumerate to verify the inodes are still there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Read all inode's contents and verify they match expectations.
            for inode in 0x10..0x1010 {
                let (_read_context, inode_data) =
                    cocoonfs_test_read_inode_op_helper(&fs_instance, None, inode).unwrap();
                let inode_data = inode_data.unwrap();
                assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());
            }
        }
    }
}

#[test]
fn create_many_inodes_backward() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let allocation_block_size_128b_log2 = test_config.layout.allocation_block_size_128b_log2 as u32;
            let fs_instance = cocoonfs_test_mkfs_op_helper(
                &test_config,
                3usize << (19 + allocation_block_size_128b_log2),
                enable_trimming,
            )
            .unwrap();

            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            for inode in (0x10..0x1010).rev() {
                transaction = cocoonfs_test_write_inode_op_helper(
                    &fs_instance,
                    transaction,
                    inode,
                    inode.to_le_bytes().as_slice(),
                )
                .unwrap();
            }

            // Enumerate through the uncommitted transaction and verify all created inodes
            // are there.
            let (read_context, inodes) = cocoonfs_test_enumerate_inodes_op_collect(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x0..=u32::MAX,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Now commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            // Enumerate to verify the inodes are still there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Read all inode's contents and verify they match expectations. This verifies
            // all inodes can get looked up and that the respective inodes'
            // entries point to the expected data.
            for inode in 0x10..0x1010 {
                let (_read_context, inode_data) =
                    cocoonfs_test_read_inode_op_helper(&fs_instance, None, inode).unwrap();
                let inode_data = inode_data.unwrap();
                assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());
            }

            // Close the FS, open and try to enumerate + read again.
            let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(blkdev).unwrap();

            // Enumerate to verify the inodes are still there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Read all inode's contents and verify they match expectations.
            for inode in 0x10..0x1010 {
                let (_read_context, inode_data) =
                    cocoonfs_test_read_inode_op_helper(&fs_instance, None, inode).unwrap();
                let inode_data = inode_data.unwrap();
                assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());
            }
        }
    }
}

#[test]
fn create_many_inodes_backward_sliced() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let allocation_block_size_128b_log2 = test_config.layout.allocation_block_size_128b_log2 as u32;
            let fs_instance = cocoonfs_test_mkfs_op_helper(
                &test_config,
                3usize << (19 + allocation_block_size_128b_log2),
                enable_trimming,
            )
            .unwrap();

            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            for inode in (0x10..0x1010).step_by(2).rev() {
                let inode = inode + 1;
                transaction = cocoonfs_test_write_inode_op_helper(
                    &fs_instance,
                    transaction,
                    inode,
                    inode.to_le_bytes().as_slice(),
                )
                .unwrap();
            }
            for inode in (0x10..0x1010).step_by(2).rev() {
                transaction = cocoonfs_test_write_inode_op_helper(
                    &fs_instance,
                    transaction,
                    inode,
                    inode.to_le_bytes().as_slice(),
                )
                .unwrap();
            }

            // Enumerate through the uncommitted transaction and verify all created inodes
            // are there.
            let (read_context, inodes) = cocoonfs_test_enumerate_inodes_op_collect(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x0..=u32::MAX,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Now commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            // Enumerate to verify the inodes are still there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Read all inode's contents and verify they match expectations. This verifies
            // all inodes can get looked up and that the respective inodes'
            // entries point to the expected data.
            for inode in 0x10..0x1010 {
                let (_read_context, inode_data) =
                    cocoonfs_test_read_inode_op_helper(&fs_instance, None, inode).unwrap();
                let inode_data = inode_data.unwrap();
                assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());
            }

            // Close the FS, open and try to enumerate + read again.
            let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(blkdev).unwrap();

            // Enumerate to verify the inodes are still there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Read all inode's contents and verify they match expectations.
            for inode in 0x10..0x1010 {
                let (_read_context, inode_data) =
                    cocoonfs_test_read_inode_op_helper(&fs_instance, None, inode).unwrap();
                let inode_data = inode_data.unwrap();
                assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());
            }
        }
    }
}

#[test]
fn create_many_inodes_inner_to_outer() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let allocation_block_size_128b_log2 = test_config.layout.allocation_block_size_128b_log2 as u32;
            let fs_instance = cocoonfs_test_mkfs_op_helper(
                &test_config,
                3usize << (19 + allocation_block_size_128b_log2),
                enable_trimming,
            )
            .unwrap();

            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            for i in 0x0..0x0800 {
                for inode in [0x10 + 0x800 - i - 1, 0x10 + 0x800 + i] {
                    transaction = cocoonfs_test_write_inode_op_helper(
                        &fs_instance,
                        transaction,
                        inode,
                        inode.to_le_bytes().as_slice(),
                    )
                    .unwrap();
                }
            }

            // Enumerate through the uncommitted transaction and verify all created inodes
            // are there.
            let (read_context, inodes) = cocoonfs_test_enumerate_inodes_op_collect(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x0..=u32::MAX,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Now commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            // Enumerate to verify the inodes are still there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Read all inode's contents and verify they match expectations. This verifies
            // all inodes can get looked up and that the respective inodes'
            // entries point to the expected data.
            for inode in 0x10..0x1010 {
                let (_read_context, inode_data) =
                    cocoonfs_test_read_inode_op_helper(&fs_instance, None, inode).unwrap();
                let inode_data = inode_data.unwrap();
                assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());
            }

            // Close the FS, open and try to enumerate + read again.
            let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(blkdev).unwrap();

            // Enumerate to verify the inodes are still there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Read all inode's contents and verify they match expectations.
            for inode in 0x10..0x1010 {
                let (_read_context, inode_data) =
                    cocoonfs_test_read_inode_op_helper(&fs_instance, None, inode).unwrap();
                let inode_data = inode_data.unwrap();
                assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());
            }
        }
    }
}

#[test]
fn create_many_inodes_inner_to_outer_sliced() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let allocation_block_size_128b_log2 = test_config.layout.allocation_block_size_128b_log2 as u32;
            let fs_instance = cocoonfs_test_mkfs_op_helper(
                &test_config,
                3usize << (19 + allocation_block_size_128b_log2),
                enable_trimming,
            )
            .unwrap();

            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            for i in (0x0..0x0800).step_by(2) {
                for inode in [0x10 + 0x800 - i - 1, 0x10 + 0x800 + i] {
                    transaction = cocoonfs_test_write_inode_op_helper(
                        &fs_instance,
                        transaction,
                        inode,
                        inode.to_le_bytes().as_slice(),
                    )
                    .unwrap();
                }
            }
            for i in (0x0..0x0800).step_by(2) {
                for inode in [0x10 + 0x800 - i - 2, 0x10 + 0x800 + i + 1] {
                    transaction = cocoonfs_test_write_inode_op_helper(
                        &fs_instance,
                        transaction,
                        inode,
                        inode.to_le_bytes().as_slice(),
                    )
                    .unwrap();
                }
            }

            // Enumerate through the uncommitted transaction and verify all created inodes
            // are there.
            let (read_context, inodes) = cocoonfs_test_enumerate_inodes_op_collect(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x0..=u32::MAX,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Now commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            // Enumerate to verify the inodes are still there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Read all inode's contents and verify they match expectations. This verifies
            // all inodes can get looked up and that the respective inodes'
            // entries point to the expected data.
            for inode in 0x10..0x1010 {
                let (_read_context, inode_data) =
                    cocoonfs_test_read_inode_op_helper(&fs_instance, None, inode).unwrap();
                let inode_data = inode_data.unwrap();
                assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());
            }

            // Close the FS, open and try to enumerate + read again.
            let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(blkdev).unwrap();

            // Enumerate to verify the inodes are still there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Read all inode's contents and verify they match expectations.
            for inode in 0x10..0x1010 {
                let (_read_context, inode_data) =
                    cocoonfs_test_read_inode_op_helper(&fs_instance, None, inode).unwrap();
                let inode_data = inode_data.unwrap();
                assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());
            }
        }
    }
}

#[test]
fn create_many_inodes_outer_to_inner() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let allocation_block_size_128b_log2 = test_config.layout.allocation_block_size_128b_log2 as u32;
            let fs_instance = cocoonfs_test_mkfs_op_helper(
                &test_config,
                3usize << (19 + allocation_block_size_128b_log2),
                enable_trimming,
            )
            .unwrap();

            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            for i in (0x0..0x0800).rev() {
                for inode in [0x10 + 0x800 - i - 1, 0x10 + 0x800 + i] {
                    transaction = cocoonfs_test_write_inode_op_helper(
                        &fs_instance,
                        transaction,
                        inode,
                        inode.to_le_bytes().as_slice(),
                    )
                    .unwrap();
                }
            }

            // Enumerate through the uncommitted transaction and verify all created inodes
            // are there.
            let (read_context, inodes) = cocoonfs_test_enumerate_inodes_op_collect(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x0..=u32::MAX,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Now commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            // Enumerate to verify the inodes are still there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Read all inode's contents and verify they match expectations. This verifies
            // all inodes can get looked up and that the respective inodes'
            // entries point to the expected data.
            for inode in 0x10..0x1010 {
                let (_read_context, inode_data) =
                    cocoonfs_test_read_inode_op_helper(&fs_instance, None, inode).unwrap();
                let inode_data = inode_data.unwrap();
                assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());
            }

            // Close the FS, open and try to enumerate + read again.
            let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(blkdev).unwrap();

            // Enumerate to verify the inodes are still there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Read all inode's contents and verify they match expectations.
            for inode in 0x10..0x1010 {
                let (_read_context, inode_data) =
                    cocoonfs_test_read_inode_op_helper(&fs_instance, None, inode).unwrap();
                let inode_data = inode_data.unwrap();
                assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());
            }
        }
    }
}

#[test]
fn create_many_inodes_outer_to_inner_sliced() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let allocation_block_size_128b_log2 = test_config.layout.allocation_block_size_128b_log2 as u32;
            let fs_instance = cocoonfs_test_mkfs_op_helper(
                &test_config,
                3usize << (19 + allocation_block_size_128b_log2),
                enable_trimming,
            )
            .unwrap();

            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            for i in (0x0..0x0800).step_by(2).rev() {
                for inode in [0x10 + 0x800 - i - 2, 0x10 + 0x800 + i + 1] {
                    transaction = cocoonfs_test_write_inode_op_helper(
                        &fs_instance,
                        transaction,
                        inode,
                        inode.to_le_bytes().as_slice(),
                    )
                    .unwrap();
                }
            }
            for i in (0x0..0x0800).step_by(2).rev() {
                for inode in [0x10 + 0x800 - i - 1, 0x10 + 0x800 + i] {
                    transaction = cocoonfs_test_write_inode_op_helper(
                        &fs_instance,
                        transaction,
                        inode,
                        inode.to_le_bytes().as_slice(),
                    )
                    .unwrap();
                }
            }

            // Enumerate through the uncommitted transaction and verify all created inodes
            // are there.
            let (read_context, inodes) = cocoonfs_test_enumerate_inodes_op_collect(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x0..=u32::MAX,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Now commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            // Enumerate to verify the inodes are still there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Read all inode's contents and verify they match expectations. This verifies
            // all inodes can get looked up and that the respective inodes'
            // entries point to the expected data.
            for inode in 0x10..0x1010 {
                let (_read_context, inode_data) =
                    cocoonfs_test_read_inode_op_helper(&fs_instance, None, inode).unwrap();
                let inode_data = inode_data.unwrap();
                assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());
            }

            // Close the FS, open and try to enumerate + read again.
            let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(blkdev).unwrap();

            // Enumerate to verify the inodes are still there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Read all inode's contents and verify they match expectations.
            for inode in 0x10..0x1010 {
                let (_read_context, inode_data) =
                    cocoonfs_test_read_inode_op_helper(&fs_instance, None, inode).unwrap();
                let inode_data = inode_data.unwrap();
                assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());
            }
        }
    }
}

#[test]
fn unlink_uncommitted_inodes() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let fs_instance = cocoonfs_test_mkfs_op_helper(&test_config, 3usize << 18, enable_trimming).unwrap();

            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            for inode in 0x10..=0x19 {
                transaction = cocoonfs_test_write_inode_op_helper(&fs_instance, transaction, inode, &[]).unwrap();
            }

            // Enumerate through the uncommitted transaction
            let (read_context, inodes) = cocoonfs_test_enumerate_inodes_op_collect(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x0..=u32::MAX,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert!(inodes.iter().copied().eq(0x10u32..=0x19));

            // Now unlink.
            let transaction = cocoonfs_test_unlink_inodes_op_uncond(&fs_instance, transaction, 0x10u32..=0x19).unwrap();

            // Verify they're gone.
            let (read_context, inodes) = cocoonfs_test_enumerate_inodes_op_collect(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x0..=u32::MAX,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert!(inodes.is_empty());

            // Now commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.is_empty());

            // Close the FS, open and try to enumerate again.
            let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(blkdev).unwrap();

            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.is_empty());
        }
    }
}

#[test]
fn unlink_committed_inodes() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let fs_instance = cocoonfs_test_mkfs_op_helper(&test_config, 3usize << 18, enable_trimming).unwrap();

            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            for inode in 0x10..=0x19 {
                transaction = cocoonfs_test_write_inode_op_helper(&fs_instance, transaction, inode, &[]).unwrap();
            }

            // Now commit.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            // Verify the inodes are there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10u32..=0x19));

            // Now unlink.
            let transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();
            let transaction = cocoonfs_test_unlink_inodes_op_uncond(&fs_instance, transaction, 0x10u32..=0x19).unwrap();

            // Verify they're gone when enumerated through the transaction.
            let (read_context, inodes) = cocoonfs_test_enumerate_inodes_op_collect(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x0..=u32::MAX,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert!(inodes.is_empty());

            // Now commit.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            // Verify the inodes are gone.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.is_empty());

            // Close the FS, open and try to enumerate again.
            let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(blkdev).unwrap();

            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.is_empty());
        }
    }
}

#[test]
fn unlink_many_inodes_forward() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let allocation_block_size_128b_log2 = test_config.layout.allocation_block_size_128b_log2 as u32;
            let fs_instance = cocoonfs_test_mkfs_op_helper(
                &test_config,
                3usize << (19 + allocation_block_size_128b_log2),
                enable_trimming,
            )
            .unwrap();

            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            for inode in 0x10..0x1010 {
                transaction = cocoonfs_test_write_inode_op_helper(
                    &fs_instance,
                    transaction,
                    inode,
                    inode.to_le_bytes().as_slice(),
                )
                .unwrap();
            }

            // Commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            // Verify all inodes are there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Unlink all inodes.
            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();
            for inode in 0x10u32..0x1010 {
                // Verify that the inode points still points at its data after all the
                // unlinking.
                let (read_context, inode_data) = cocoonfs_test_read_inode_op_helper(
                    &fs_instance,
                    Some(fs::NvFsReadContext::Transaction { transaction }),
                    inode,
                )
                .unwrap();
                transaction = match read_context {
                    fs::NvFsReadContext::Transaction { transaction } => transaction,
                    _ => panic!("Transaction read context not returned back."),
                };
                let inode_data = inode_data.unwrap();
                assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());

                // And unlink.
                transaction = cocoonfs_test_unlink_inodes_op_uncond(&fs_instance, transaction, inode..=inode).unwrap();
            }

            // Enumerate throught the transaction and verify the inodes are gone..
            let (read_context, inodes) = cocoonfs_test_enumerate_inodes_op_collect(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x0..=u32::MAX,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert!(inodes.is_empty());

            // Now commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.is_empty());

            // Close the FS, open and try to enumerate again.
            let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(blkdev).unwrap();

            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.is_empty());
        }
    }
}

#[test]
fn unlink_many_inodes_forward_sliced() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let allocation_block_size_128b_log2 = test_config.layout.allocation_block_size_128b_log2 as u32;
            let fs_instance = cocoonfs_test_mkfs_op_helper(
                &test_config,
                3usize << (19 + allocation_block_size_128b_log2),
                enable_trimming,
            )
            .unwrap();

            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            for inode in 0x10..0x1010 {
                transaction = cocoonfs_test_write_inode_op_helper(
                    &fs_instance,
                    transaction,
                    inode,
                    inode.to_le_bytes().as_slice(),
                )
                .unwrap();
            }

            // Commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            // Verify all inodes are there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Unlink all inodes.
            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();
            for inode in (0x10..0x1010).step_by(2) {
                // Verify that the inode points still points at its data after all the
                // unlinking.
                let (read_context, inode_data) = cocoonfs_test_read_inode_op_helper(
                    &fs_instance,
                    Some(fs::NvFsReadContext::Transaction { transaction }),
                    inode,
                )
                .unwrap();
                transaction = match read_context {
                    fs::NvFsReadContext::Transaction { transaction } => transaction,
                    _ => panic!("Transaction read context not returned back."),
                };
                let inode_data = inode_data.unwrap();
                assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());

                // And unlink.
                transaction = cocoonfs_test_unlink_inodes_op_uncond(&fs_instance, transaction, inode..=inode).unwrap();
            }
            for inode in (0x10..0x1010).step_by(2) {
                let inode = inode + 1;

                // Verify that the inode points still points at its data after all the
                // unlinking.
                let (read_context, inode_data) = cocoonfs_test_read_inode_op_helper(
                    &fs_instance,
                    Some(fs::NvFsReadContext::Transaction { transaction }),
                    inode,
                )
                .unwrap();
                transaction = match read_context {
                    fs::NvFsReadContext::Transaction { transaction } => transaction,
                    _ => panic!("Transaction read context not returned back."),
                };
                let inode_data = inode_data.unwrap();
                assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());

                // And unlink.
                transaction = cocoonfs_test_unlink_inodes_op_uncond(&fs_instance, transaction, inode..=inode).unwrap();
            }

            // Enumerate through the transaction and verify the inodes are gone..
            let (read_context, inodes) = cocoonfs_test_enumerate_inodes_op_collect(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x0..=u32::MAX,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert!(inodes.is_empty());

            // Now commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.is_empty());

            // Close the FS, open and try to enumerate again.
            let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(blkdev).unwrap();

            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.is_empty());
        }
    }
}

#[test]
fn unlink_many_inodes_backward() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let allocation_block_size_128b_log2 = test_config.layout.allocation_block_size_128b_log2 as u32;
            let fs_instance = cocoonfs_test_mkfs_op_helper(
                &test_config,
                3usize << (19 + allocation_block_size_128b_log2),
                enable_trimming,
            )
            .unwrap();

            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            for inode in 0x10..0x1010 {
                transaction = cocoonfs_test_write_inode_op_helper(
                    &fs_instance,
                    transaction,
                    inode,
                    inode.to_le_bytes().as_slice(),
                )
                .unwrap();
            }

            // Commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            // Verify all inodes are there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Unlink all inodes.
            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();
            for inode in (0x10..0x1010).rev() {
                // Verify that the inode points still points at its data after all the
                // unlinking.
                let (read_context, inode_data) = cocoonfs_test_read_inode_op_helper(
                    &fs_instance,
                    Some(fs::NvFsReadContext::Transaction { transaction }),
                    inode,
                )
                .unwrap();
                transaction = match read_context {
                    fs::NvFsReadContext::Transaction { transaction } => transaction,
                    _ => panic!("Transaction read context not returned back."),
                };
                let inode_data = inode_data.unwrap();
                assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());

                // And unlink.
                transaction = cocoonfs_test_unlink_inodes_op_uncond(&fs_instance, transaction, inode..=inode).unwrap();
            }

            // Enumerate throught the transaction and verify the inodes are gone..
            let (read_context, inodes) = cocoonfs_test_enumerate_inodes_op_collect(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x0..=u32::MAX,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert!(inodes.is_empty());

            // Now commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.is_empty());

            // Close the FS, open and try to enumerate again.
            let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(blkdev).unwrap();

            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.is_empty());
        }
    }
}

#[test]
fn unlink_many_inodes_backward_sliced() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let allocation_block_size_128b_log2 = test_config.layout.allocation_block_size_128b_log2 as u32;
            let fs_instance = cocoonfs_test_mkfs_op_helper(
                &test_config,
                3usize << (19 + allocation_block_size_128b_log2),
                enable_trimming,
            )
            .unwrap();

            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            for inode in 0x10..0x1010 {
                transaction = cocoonfs_test_write_inode_op_helper(
                    &fs_instance,
                    transaction,
                    inode,
                    inode.to_le_bytes().as_slice(),
                )
                .unwrap();
            }

            // Commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            // Verify all inodes are there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Unlink all inodes.
            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();
            for inode in (0x10..0x1010).step_by(2).rev() {
                let inode = inode + 1;

                // Verify that the inode points still points at its data after all the
                // unlinking.
                let (read_context, inode_data) = cocoonfs_test_read_inode_op_helper(
                    &fs_instance,
                    Some(fs::NvFsReadContext::Transaction { transaction }),
                    inode,
                )
                .unwrap();
                transaction = match read_context {
                    fs::NvFsReadContext::Transaction { transaction } => transaction,
                    _ => panic!("Transaction read context not returned back."),
                };
                let inode_data = inode_data.unwrap();
                assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());

                // And unlink.
                transaction = cocoonfs_test_unlink_inodes_op_uncond(&fs_instance, transaction, inode..=inode).unwrap();
            }
            for inode in (0x10..0x1010).step_by(2).rev() {
                // Verify that the inode points still points at its data after all the
                // unlinking.
                let (read_context, inode_data) = cocoonfs_test_read_inode_op_helper(
                    &fs_instance,
                    Some(fs::NvFsReadContext::Transaction { transaction }),
                    inode,
                )
                .unwrap();
                transaction = match read_context {
                    fs::NvFsReadContext::Transaction { transaction } => transaction,
                    _ => panic!("Transaction read context not returned back."),
                };
                let inode_data = inode_data.unwrap();
                assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());

                // And unlink.
                transaction = cocoonfs_test_unlink_inodes_op_uncond(&fs_instance, transaction, inode..=inode).unwrap();
            }

            // Enumerate throught the transaction and verify the inodes are gone..
            let (read_context, inodes) = cocoonfs_test_enumerate_inodes_op_collect(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x0..=u32::MAX,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert!(inodes.is_empty());

            // Now commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.is_empty());

            // Close the FS, open and try to enumerate again.
            let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(blkdev).unwrap();

            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.is_empty());
        }
    }
}

#[test]
fn unlink_many_inodes_inner_to_outer() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let allocation_block_size_128b_log2 = test_config.layout.allocation_block_size_128b_log2 as u32;
            let fs_instance = cocoonfs_test_mkfs_op_helper(
                &test_config,
                3usize << (19 + allocation_block_size_128b_log2),
                enable_trimming,
            )
            .unwrap();

            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            for inode in 0x10..0x1010 {
                transaction = cocoonfs_test_write_inode_op_helper(
                    &fs_instance,
                    transaction,
                    inode,
                    inode.to_le_bytes().as_slice(),
                )
                .unwrap();
            }

            // Commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            // Verify all inodes are there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Unlink all inodes.
            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();
            for i in 0x0..0x0800 {
                for inode in [0x10 + 0x800 - i - 1, 0x10 + 0x800 + i] {
                    // Verify that the inode points still points at its data after all the
                    // unlinking.
                    let (read_context, inode_data) = cocoonfs_test_read_inode_op_helper(
                        &fs_instance,
                        Some(fs::NvFsReadContext::Transaction { transaction }),
                        inode,
                    )
                    .unwrap();
                    transaction = match read_context {
                        fs::NvFsReadContext::Transaction { transaction } => transaction,
                        _ => panic!("Transaction read context not returned back."),
                    };
                    let inode_data = inode_data.unwrap();
                    assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());

                    // And unlink.
                    transaction =
                        cocoonfs_test_unlink_inodes_op_uncond(&fs_instance, transaction, inode..=inode).unwrap();
                }
            }

            // Enumerate throught the transaction and verify the inodes are gone..
            let (read_context, inodes) = cocoonfs_test_enumerate_inodes_op_collect(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x0..=u32::MAX,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert!(inodes.is_empty());

            // Now commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.is_empty());

            // Close the FS, open and try to enumerate again.
            let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(blkdev).unwrap();

            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.is_empty());
        }
    }
}

#[test]
fn unlink_many_inodes_inner_to_outer_sliced() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let allocation_block_size_128b_log2 = test_config.layout.allocation_block_size_128b_log2 as u32;
            let fs_instance = cocoonfs_test_mkfs_op_helper(
                &test_config,
                3usize << (19 + allocation_block_size_128b_log2),
                enable_trimming,
            )
            .unwrap();

            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            for inode in 0x10..0x1010 {
                transaction = cocoonfs_test_write_inode_op_helper(
                    &fs_instance,
                    transaction,
                    inode,
                    inode.to_le_bytes().as_slice(),
                )
                .unwrap();
            }

            // Commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            // Verify all inodes are there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Unlink all inodes.
            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();
            for i in (0x0..0x0800).step_by(2) {
                for inode in [0x10 + 0x800 - i - 1, 0x10 + 0x800 + i] {
                    // Verify that the inode points still points at its data after all the
                    // unlinking.
                    let (read_context, inode_data) = cocoonfs_test_read_inode_op_helper(
                        &fs_instance,
                        Some(fs::NvFsReadContext::Transaction { transaction }),
                        inode,
                    )
                    .unwrap();
                    transaction = match read_context {
                        fs::NvFsReadContext::Transaction { transaction } => transaction,
                        _ => panic!("Transaction read context not returned back."),
                    };
                    let inode_data = inode_data.unwrap();
                    assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());

                    // And unlink.
                    transaction =
                        cocoonfs_test_unlink_inodes_op_uncond(&fs_instance, transaction, inode..=inode).unwrap();
                }
            }
            for i in (0x0..0x0800).step_by(2) {
                for inode in [0x10 + 0x800 - i - 2, 0x10 + 0x800 + i + 1] {
                    // Verify that the inode points still points at its data after all the
                    // unlinking.
                    let (read_context, inode_data) = cocoonfs_test_read_inode_op_helper(
                        &fs_instance,
                        Some(fs::NvFsReadContext::Transaction { transaction }),
                        inode,
                    )
                    .unwrap();
                    transaction = match read_context {
                        fs::NvFsReadContext::Transaction { transaction } => transaction,
                        _ => panic!("Transaction read context not returned back."),
                    };
                    let inode_data = inode_data.unwrap();
                    assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());

                    // And unlink.
                    transaction =
                        cocoonfs_test_unlink_inodes_op_uncond(&fs_instance, transaction, inode..=inode).unwrap();
                }
            }

            // Enumerate throught the transaction and verify the inodes are gone..
            let (read_context, inodes) = cocoonfs_test_enumerate_inodes_op_collect(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x0..=u32::MAX,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert!(inodes.is_empty());

            // Now commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.is_empty());

            // Close the FS, open and try to enumerate again.
            let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(blkdev).unwrap();

            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.is_empty());
        }
    }
}

#[test]
fn unlink_many_inodes_outer_to_inner() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let allocation_block_size_128b_log2 = test_config.layout.allocation_block_size_128b_log2 as u32;
            let fs_instance = cocoonfs_test_mkfs_op_helper(
                &test_config,
                3usize << (19 + allocation_block_size_128b_log2),
                enable_trimming,
            )
            .unwrap();

            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            for inode in 0x10..0x1010 {
                transaction = cocoonfs_test_write_inode_op_helper(
                    &fs_instance,
                    transaction,
                    inode,
                    inode.to_le_bytes().as_slice(),
                )
                .unwrap();
            }

            // Commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            // Verify all inodes are there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Unlink all inodes.
            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();
            for i in (0x0..0x0800).rev() {
                for inode in [0x10 + 0x800 - i - 1, 0x10 + 0x800 + i] {
                    // Verify that the inode points still points at its data after all the
                    // unlinking.
                    let (read_context, inode_data) = cocoonfs_test_read_inode_op_helper(
                        &fs_instance,
                        Some(fs::NvFsReadContext::Transaction { transaction }),
                        inode,
                    )
                    .unwrap();
                    transaction = match read_context {
                        fs::NvFsReadContext::Transaction { transaction } => transaction,
                        _ => panic!("Transaction read context not returned back."),
                    };
                    let inode_data = inode_data.unwrap();
                    assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());

                    // And unlink.
                    transaction =
                        cocoonfs_test_unlink_inodes_op_uncond(&fs_instance, transaction, inode..=inode).unwrap();
                }
            }

            // Enumerate throught the transaction and verify the inodes are gone..
            let (read_context, inodes) = cocoonfs_test_enumerate_inodes_op_collect(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x0..=u32::MAX,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert!(inodes.is_empty());

            // Now commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.is_empty());

            // Close the FS, open and try to enumerate again.
            let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(blkdev).unwrap();

            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.is_empty());
        }
    }
}

#[test]
fn unlink_many_inodes_outer_to_inner_sliced() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let allocation_block_size_128b_log2 = test_config.layout.allocation_block_size_128b_log2 as u32;
            let fs_instance = cocoonfs_test_mkfs_op_helper(
                &test_config,
                3usize << (19 + allocation_block_size_128b_log2),
                enable_trimming,
            )
            .unwrap();

            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();

            for inode in 0x10..0x1010 {
                transaction = cocoonfs_test_write_inode_op_helper(
                    &fs_instance,
                    transaction,
                    inode,
                    inode.to_le_bytes().as_slice(),
                )
                .unwrap();
            }

            // Commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            // Verify all inodes are there.
            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.iter().copied().eq(0x10..0x1010));

            // Unlink all inodes.
            let mut transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();
            for i in (0x0..0x0800).step_by(2).rev() {
                for inode in [0x10 + 0x800 - i - 2, 0x10 + 0x800 + i + 1] {
                    // Verify that the inode points still points at its data after all the
                    // unlinking.
                    let (read_context, inode_data) = cocoonfs_test_read_inode_op_helper(
                        &fs_instance,
                        Some(fs::NvFsReadContext::Transaction { transaction }),
                        inode,
                    )
                    .unwrap();
                    transaction = match read_context {
                        fs::NvFsReadContext::Transaction { transaction } => transaction,
                        _ => panic!("Transaction read context not returned back."),
                    };
                    let inode_data = inode_data.unwrap();
                    assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());

                    // And unlink.
                    transaction =
                        cocoonfs_test_unlink_inodes_op_uncond(&fs_instance, transaction, inode..=inode).unwrap();
                }
            }
            for i in (0x0..0x0800).step_by(2).rev() {
                for inode in [0x10 + 0x800 - i - 1, 0x10 + 0x800 + i] {
                    // Verify that the inode points still points at its data after all the
                    // unlinking.
                    let (read_context, inode_data) = cocoonfs_test_read_inode_op_helper(
                        &fs_instance,
                        Some(fs::NvFsReadContext::Transaction { transaction }),
                        inode,
                    )
                    .unwrap();
                    transaction = match read_context {
                        fs::NvFsReadContext::Transaction { transaction } => transaction,
                        _ => panic!("Transaction read context not returned back."),
                    };
                    let inode_data = inode_data.unwrap();
                    assert_eq!(inode_data.as_slice(), inode.to_le_bytes().as_slice());

                    // And unlink.
                    transaction =
                        cocoonfs_test_unlink_inodes_op_uncond(&fs_instance, transaction, inode..=inode).unwrap();
                }
            }

            // Enumerate throught the transaction and verify the inodes are gone..
            let (read_context, inodes) = cocoonfs_test_enumerate_inodes_op_collect(
                &fs_instance,
                Some(fs::NvFsReadContext::Transaction { transaction }),
                0x0..=u32::MAX,
            )
            .unwrap();
            let transaction = match read_context {
                fs::NvFsReadContext::Transaction { transaction } => transaction,
                _ => panic!("Transaction read context not returned back."),
            };
            assert!(inodes.is_empty());

            // Now commit and enumerate from the FS.
            cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.is_empty());

            // Close the FS, open and try to enumerate again.
            let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
            let fs_instance = cocoonfs_test_openfs_op_helper(blkdev).unwrap();

            let (_read_context, inodes) =
                cocoonfs_test_enumerate_inodes_op_collect(&fs_instance, None, 0x0..=u32::MAX).unwrap();
            assert!(inodes.is_empty());
        }
    }
}
