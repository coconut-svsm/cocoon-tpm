// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use super::{
    CocoonFsTestConfigs, cocoonfs_test_fs_instance_into_blkdev_helper, cocoonfs_test_mkfs_op_helper,
    cocoonfs_test_read_fs_metadata_helper, cocoonfs_test_write_mkfsinfo_header_op_helper,
};
use crate::fs::cocoonfs::AuxFsMetadata;

const fn mk_test_uuid(i: u8) -> [u8; 16] {
    let mut uuid = [0u8; 16];
    uuid[15] = i;
    uuid
}

#[test]
fn mkfs_init_without_extra_reserve() {
    let mut aux_fs_metadata = AuxFsMetadata::new();
    aux_fs_metadata.add_entry(&mk_test_uuid(1), &[1, 2, 3, 4]).unwrap();

    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let fs_instance = cocoonfs_test_mkfs_op_helper(
                &test_config,
                Some(aux_fs_metadata.try_clone().unwrap()),
                3usize << 18,
                enable_trimming,
            )
            .unwrap();
            // Close and read the FsMetadata.
            let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
            let (_blkdev, fs_metadata) = cocoonfs_test_read_fs_metadata_helper(blkdev).unwrap();
            assert_eq!(&aux_fs_metadata, fs_metadata.get_aux());
        }
    }
}

#[test]
fn mkfs_init_with_extra_reserve() {
    let mut aux_fs_metadata = AuxFsMetadata::new();
    aux_fs_metadata.add_entry(&mk_test_uuid(1), &[1, 2, 3, 4]).unwrap();

    for test_config in CocoonFsTestConfigs::new() {
        let mut aux_fs_metadata = aux_fs_metadata.try_clone().unwrap();
        // One Allocation Block more than what could get linked from a EncodedExtentPtr.
        aux_fs_metadata
            .set_extra_reserve_capacity(Some(
                65 << (test_config.layout.allocation_block_size_128b_log2 as u32 + 7),
            ))
            .unwrap();

        for enable_trimming in [false, true] {
            let fs_instance = cocoonfs_test_mkfs_op_helper(
                &test_config,
                Some(aux_fs_metadata.try_clone().unwrap()),
                3usize << 18,
                enable_trimming,
            )
            .unwrap();
            // Close and read the FsMetadata.
            let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
            let (_blkdev, fs_metadata) = cocoonfs_test_read_fs_metadata_helper(blkdev).unwrap();
            assert_eq!(&aux_fs_metadata, fs_metadata.get_aux());
        }
    }
}

#[test]
fn mkfsinfo_init_without_extra_reserve() {
    let mut aux_fs_metadata = AuxFsMetadata::new();
    aux_fs_metadata.add_entry(&mk_test_uuid(1), &[1, 2, 3, 4]).unwrap();

    for test_config in CocoonFsTestConfigs::new() {
        let blkdev = cocoonfs_test_write_mkfsinfo_header_op_helper(
            &test_config,
            Some(aux_fs_metadata.try_clone().unwrap()),
            3usize << 18,
        )
        .unwrap();
        // Read the FsMetadata.
        let (_blkdev, fs_metadata) = cocoonfs_test_read_fs_metadata_helper(blkdev).unwrap();
        assert_eq!(&aux_fs_metadata, fs_metadata.get_aux());
    }
}
