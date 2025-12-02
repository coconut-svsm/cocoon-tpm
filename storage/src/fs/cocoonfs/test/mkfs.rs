// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use super::{
    CocoonFsTestConfigs, cocoonfs_test_commit_transaction_op_helper, cocoonfs_test_fs_instance_into_blkdev_helper,
    cocoonfs_test_mkfs_op_helper, cocoonfs_test_openfs_fail_mkfsinfo_header_application_op_helper,
    cocoonfs_test_openfs_op_helper, cocoonfs_test_read_inode_op_helper, cocoonfs_test_start_transaction_op_helper,
    cocoonfs_test_write_inode_op_helper, cocoonfs_test_write_mkfsinfo_header_op_helper,
};

#[test]
fn mkfs_openfs() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let fs_instance = cocoonfs_test_mkfs_op_helper(&test_config, 3usize << 18, enable_trimming).unwrap();

            // Close and open.
            let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
            cocoonfs_test_openfs_op_helper(blkdev).unwrap();
        }
    }
}

#[test]
fn write_mkfsinfo_header_openfs() {
    for test_config in CocoonFsTestConfigs::new() {
        // Write the filesystem creation info header.
        let blkdev = cocoonfs_test_write_mkfsinfo_header_op_helper(&test_config, 3usize << 18).unwrap();

        // And open to actually run the filesystem creation.
        let fs_instance = cocoonfs_test_openfs_op_helper(blkdev).unwrap();

        // Leave a marker inode there to verify that the next openfs op would not just
        // invoke mkfs once again.
        let transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();
        let inode_write_data = b"Hello CocoonFs";
        let transaction =
            cocoonfs_test_write_inode_op_helper(&fs_instance, transaction, 0x10, inode_write_data).unwrap();
        cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

        // Close and open the freshly formatted filesystem.
        let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
        let fs_instance = cocoonfs_test_openfs_op_helper(blkdev).unwrap();

        // Verify the marker inode is still there.
        let (_read_context, inode_read_data) = cocoonfs_test_read_inode_op_helper(&fs_instance, None, 0x10).unwrap();
        assert_eq!(inode_write_data.as_slice(), inode_read_data.unwrap().as_slice());
    }
}

#[test]
fn write_mkfsinfo_header_openfs_fail_retry() {
    for test_config in CocoonFsTestConfigs::new() {
        // Write the filesystem creation info header.
        let blkdev = cocoonfs_test_write_mkfsinfo_header_op_helper(&test_config, 3usize << 18).unwrap();

        // And open to attempt a filesystem creation, but simulate IO failure at the
        // point of writing the regular filesystem header, so that only the
        // backup mkfsinfo header remains intact.
        let blkdev = cocoonfs_test_openfs_fail_mkfsinfo_header_application_op_helper(blkdev).unwrap();

        // Open once more, now let the filesystem creation succeed.
        let fs_instance = cocoonfs_test_openfs_op_helper(blkdev).unwrap();

        // Leave a marker inode there to verify that the next openfs op would not just
        // invoke mkfs once again.
        let transaction = cocoonfs_test_start_transaction_op_helper(&fs_instance, None).unwrap();
        let inode_write_data = b"Hello CocoonFs";
        let transaction =
            cocoonfs_test_write_inode_op_helper(&fs_instance, transaction, 0x10, inode_write_data).unwrap();
        cocoonfs_test_commit_transaction_op_helper(&fs_instance, transaction, false).unwrap();

        // Close and open the freshly formatted filesystem.
        let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
        let fs_instance = cocoonfs_test_openfs_op_helper(blkdev).unwrap();

        // Verify the marker inode is still there.
        let (_read_context, inode_read_data) = cocoonfs_test_read_inode_op_helper(&fs_instance, None, 0x10).unwrap();
        assert_eq!(inode_write_data.as_slice(), inode_read_data.unwrap().as_slice());
    }
}
