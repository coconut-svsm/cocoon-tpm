// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

extern crate alloc;
use alloc::vec::Vec;

use super::{
    CocoonFsTestConfigs, cocoonfs_test_fs_instance_into_blkdev_helper, cocoonfs_test_mkfs_op_helper,
    cocoonfs_test_openfs_fail_mkfsinfo_header_application_op_helper, cocoonfs_test_read_fs_metadata_helper,
    cocoonfs_test_write_aux_fs_metadata_offline_helper, cocoonfs_test_write_mkfsinfo_header_op_helper,
};
use crate::fs::{
    NvFsError, NvFsIoError,
    cocoonfs::{AuxFsMetadata, FsMetadata, layout},
};

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

#[test]
fn write_offline_formatted() {
    let mut initial_aux_fs_metadata = AuxFsMetadata::new();
    initial_aux_fs_metadata
        .add_entry(&mk_test_uuid(1), &[1, 2, 3, 4])
        .unwrap();
    initial_aux_fs_metadata.set_extra_reserve_capacity(Some(0)).unwrap();

    let mut updated_aux_fs_metadata = AuxFsMetadata::new();
    updated_aux_fs_metadata
        .add_entry(&mk_test_uuid(1), &[5, 6, 7, 8])
        .unwrap();

    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let fs_instance = cocoonfs_test_mkfs_op_helper(
                &test_config,
                Some(initial_aux_fs_metadata.try_clone().unwrap()),
                3usize << 18,
                enable_trimming,
            )
            .unwrap();
            // Close and read the FsMetadata.
            let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
            let (blkdev, fs_metadata) = cocoonfs_test_read_fs_metadata_helper(blkdev).unwrap();
            assert_eq!(&initial_aux_fs_metadata, fs_metadata.get_aux());
            // Update the AuxFsMetadata.
            let (blkdev, result) = cocoonfs_test_write_aux_fs_metadata_offline_helper(
                blkdev,
                fs_metadata,
                updated_aux_fs_metadata.try_clone().unwrap(),
                false,
                false,
            );
            result.unwrap();
            // Read back from storage.
            let (_blkdev, fs_metadata) = cocoonfs_test_read_fs_metadata_helper(blkdev).unwrap();
            assert_eq!(&updated_aux_fs_metadata, fs_metadata.get_aux());
        }
    }
}

#[test]
fn write_offline_formatted_fail_final_write() {
    let mut initial_aux_fs_metadata = AuxFsMetadata::new();
    initial_aux_fs_metadata
        .add_entry(&mk_test_uuid(1), &[1, 2, 3, 4])
        .unwrap();
    initial_aux_fs_metadata.set_extra_reserve_capacity(Some(0)).unwrap();

    let mut updated_aux_fs_metadata = AuxFsMetadata::new();
    updated_aux_fs_metadata
        .add_entry(&mk_test_uuid(1), &[5, 6, 7, 8])
        .unwrap();

    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let fs_instance = cocoonfs_test_mkfs_op_helper(
                &test_config,
                Some(initial_aux_fs_metadata.try_clone().unwrap()),
                3usize << 18,
                enable_trimming,
            )
            .unwrap();
            // Close and read the FsMetadata.
            let blkdev = cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance);
            let (blkdev, fs_metadata) = cocoonfs_test_read_fs_metadata_helper(blkdev).unwrap();
            assert_eq!(&initial_aux_fs_metadata, fs_metadata.get_aux());
            // Attempt to update the AuxFsMetadata, but fail at the final write.
            let (blkdev, result) = cocoonfs_test_write_aux_fs_metadata_offline_helper(
                blkdev,
                fs_metadata,
                updated_aux_fs_metadata.try_clone().unwrap(),
                false,
                true,
            );
            match result {
                Ok(_) => assert!(false),
                Err(e) => assert_eq!(e, NvFsError::IoError(NvFsIoError::IoFailure)),
            };
            // Read back from storage.
            let (blkdev, fs_metadata) = cocoonfs_test_read_fs_metadata_helper(blkdev).unwrap();
            assert_eq!(&initial_aux_fs_metadata, fs_metadata.get_aux());
            // Try again, don't fault this time.
            let (blkdev, result) = cocoonfs_test_write_aux_fs_metadata_offline_helper(
                blkdev,
                fs_metadata,
                updated_aux_fs_metadata.try_clone().unwrap(),
                false,
                false,
            );
            result.unwrap();
            // Read back from storage.
            let (_blkdev, fs_metadata) = cocoonfs_test_read_fs_metadata_helper(blkdev).unwrap();
            assert_eq!(&updated_aux_fs_metadata, fs_metadata.get_aux());
        }
    }
}

#[test]
fn write_offline_mkfsinfo_fail_final_write() {
    let mut initial_aux_fs_metadata = AuxFsMetadata::new();
    initial_aux_fs_metadata
        .add_entry(&mk_test_uuid(1), &[1, 2, 3, 4])
        .unwrap();
    initial_aux_fs_metadata.set_extra_reserve_capacity(Some(0)).unwrap();

    let mut updated_aux_fs_metadata = AuxFsMetadata::new();
    updated_aux_fs_metadata
        .add_entry(&mk_test_uuid(1), &[5, 6, 7, 8])
        .unwrap();

    for test_config in CocoonFsTestConfigs::new() {
        let blkdev = cocoonfs_test_write_mkfsinfo_header_op_helper(
            &test_config,
            Some(initial_aux_fs_metadata.try_clone().unwrap()),
            3usize << 18,
        )
        .unwrap();
        let (blkdev, fs_metadata) = cocoonfs_test_read_fs_metadata_helper(blkdev).unwrap();
        assert_eq!(&initial_aux_fs_metadata, fs_metadata.get_aux());
        // Attempt to update the AuxFsMetadata, but fail at the final write.
        let (blkdev, result) = cocoonfs_test_write_aux_fs_metadata_offline_helper(
            blkdev,
            fs_metadata,
            updated_aux_fs_metadata.try_clone().unwrap(),
            false,
            true,
        );
        match result {
            Ok(_) => assert!(false),
            Err(e) => assert_eq!(e, NvFsError::IoError(NvFsIoError::IoFailure)),
        };
        // Read back from storage.
        let (blkdev, fs_metadata) = cocoonfs_test_read_fs_metadata_helper(blkdev).unwrap();
        assert_eq!(&initial_aux_fs_metadata, fs_metadata.get_aux());
        match &fs_metadata {
            FsMetadata::MkFsInfo(fs_metadata) => {
                // The effective mkfsinfo data should be at the backup location after the failed
                // final write to the primary location.
                assert_ne!(u64::from(fs_metadata.mkfsinfo_data_location.begin()), 0);
            }
            FsMetadata::Formatted(_) => assert!(false),
        };
        // Try again, don't fault this time.
        let (blkdev, result) = cocoonfs_test_write_aux_fs_metadata_offline_helper(
            blkdev,
            fs_metadata,
            updated_aux_fs_metadata.try_clone().unwrap(),
            false,
            false,
        );
        result.unwrap();
        // Read back from storage.
        let (_blkdev, fs_metadata) = cocoonfs_test_read_fs_metadata_helper(blkdev).unwrap();
        assert_eq!(&updated_aux_fs_metadata, fs_metadata.get_aux());
    }
}

#[test]
fn write_offline_mkfsinfo_fail_final_write_and_mkfs_fail_final_write() {
    let mut initial_aux_fs_metadata = AuxFsMetadata::new();
    initial_aux_fs_metadata
        .add_entry(&mk_test_uuid(1), &[1, 2, 3, 4])
        .unwrap();
    initial_aux_fs_metadata.set_extra_reserve_capacity(Some(0)).unwrap();

    let mut updated_aux_fs_metadata = AuxFsMetadata::new();
    updated_aux_fs_metadata
        .add_entry(&mk_test_uuid(1), &[5, 6, 7, 8])
        .unwrap();

    for test_config in CocoonFsTestConfigs::new() {
        let blkdev = cocoonfs_test_write_mkfsinfo_header_op_helper(
            &test_config,
            Some(initial_aux_fs_metadata.try_clone().unwrap()),
            3usize << 18,
        )
        .unwrap();
        let (blkdev, fs_metadata) = cocoonfs_test_read_fs_metadata_helper(blkdev).unwrap();
        assert_eq!(&initial_aux_fs_metadata, fs_metadata.get_aux());
        // Attempt to update the AuxFsMetadata, but fail at the final write. This leaves
        // only the backup copy of the mkfsinfo data in place.
        let (blkdev, result) = cocoonfs_test_write_aux_fs_metadata_offline_helper(
            blkdev,
            fs_metadata,
            updated_aux_fs_metadata.try_clone().unwrap(),
            false,
            true,
        );
        match result {
            Ok(_) => assert!(false),
            Err(e) => assert_eq!(e, NvFsError::IoError(NvFsIoError::IoFailure)),
        };
        // Read back from storage.
        let (blkdev, fs_metadata) = cocoonfs_test_read_fs_metadata_helper(blkdev).unwrap();
        assert_eq!(&initial_aux_fs_metadata, fs_metadata.get_aux());
        let backup_mkfsinfo_begin = match &fs_metadata {
            FsMetadata::MkFsInfo(fs_metadata) => {
                // The effective mkfsinfo data should be at the backup location after the failed
                // final write to the primary location.
                let backup_mkfsinfo_begin = fs_metadata.mkfsinfo_data_location.begin();
                assert_ne!(u64::from(backup_mkfsinfo_begin), 0);
                backup_mkfsinfo_begin
            }
            FsMetadata::Formatted(_) => {
                assert!(false);
                layout::PhysicalAllocBlockIndex::from(u64::MAX)
            }
        };

        // Now run a mkfs operation. That would inevitably have to relocate the backup
        // mkfsinfo before the block device resize operation. Fail its final
        // write to see it indeed works as expected.
        let blkdev = cocoonfs_test_openfs_fail_mkfsinfo_header_application_op_helper(blkdev).unwrap();

        // Read the (relocated) FsMetadata.
        let (_blkdev, fs_metadata) = cocoonfs_test_read_fs_metadata_helper(blkdev).unwrap();
        assert_eq!(&initial_aux_fs_metadata, fs_metadata.get_aux());
        match &fs_metadata {
            FsMetadata::MkFsInfo(fs_metadata) => {
                // The effective mkfsinfo data should be at the backup location after the failed
                // final write to the primary location.
                let relocated_backup_mkfsinfo_begin = fs_metadata.mkfsinfo_data_location.begin();
                assert!(relocated_backup_mkfsinfo_begin > backup_mkfsinfo_begin);
            }
            FsMetadata::Formatted(_) => assert!(false),
        };
    }
}

#[test]
fn write_offline_mkfsinfo_fail_final_write_and_retry_fail_resize() {
    let mut initial_aux_fs_metadata = AuxFsMetadata::new();
    initial_aux_fs_metadata
        .add_entry(&mk_test_uuid(1), &[1, 2, 3, 4])
        .unwrap();
    initial_aux_fs_metadata.set_extra_reserve_capacity(Some(0)).unwrap();

    let mut updated_aux_fs_metadata = AuxFsMetadata::new();
    updated_aux_fs_metadata
        .add_entry(&mk_test_uuid(1), &[5, 6, 7, 8])
        .unwrap();

    for test_config in CocoonFsTestConfigs::new() {
        let blkdev = cocoonfs_test_write_mkfsinfo_header_op_helper(
            &test_config,
            Some(initial_aux_fs_metadata.try_clone().unwrap()),
            3usize << 18,
        )
        .unwrap();
        let (blkdev, fs_metadata) = cocoonfs_test_read_fs_metadata_helper(blkdev).unwrap();
        assert_eq!(&initial_aux_fs_metadata, fs_metadata.get_aux());
        // Attempt to update the AuxFsMetadata, but fail at the final write. This leaves
        // only the backup copy of the mkfsinfo data in place.
        let (blkdev, result) = cocoonfs_test_write_aux_fs_metadata_offline_helper(
            blkdev,
            fs_metadata,
            updated_aux_fs_metadata.try_clone().unwrap(),
            false,
            true,
        );
        match result {
            Ok(_) => assert!(false),
            Err(e) => assert_eq!(e, NvFsError::IoError(NvFsIoError::IoFailure)),
        };
        // Read back from storage.
        let (blkdev, fs_metadata) = cocoonfs_test_read_fs_metadata_helper(blkdev).unwrap();
        assert_eq!(&initial_aux_fs_metadata, fs_metadata.get_aux());
        match &fs_metadata {
            FsMetadata::MkFsInfo(fs_metadata) => {
                // The effective mkfsinfo data should be at the backup location after the failed
                // final write to the primary location.
                let backup_mkfsinfo_begin = fs_metadata.mkfsinfo_data_location.begin();
                assert_ne!(u64::from(backup_mkfsinfo_begin), 0);
            }
            FsMetadata::Formatted(_) => {
                assert!(false);
            }
        };

        // Now retry, with a much larger AuxFsMetadata, forcing a resize, but fail that.
        // There should have been a relocation of the original backup mkfsinfo to the
        // primary location prior to the resizing.
        let mut updated_aux_fs_metadata = AuxFsMetadata::new();
        let mut data = Vec::new();
        data.resize(
            16usize
                << ((test_config.layout.io_block_allocation_blocks_log2 as u32
                    + test_config.layout.allocation_block_size_128b_log2 as u32)
                    .max(2)
                    + 7),
            0u8,
        );
        updated_aux_fs_metadata.add_entry(&mk_test_uuid(1), &data).unwrap();
        let (blkdev, result) = cocoonfs_test_write_aux_fs_metadata_offline_helper(
            blkdev,
            fs_metadata,
            updated_aux_fs_metadata.try_clone().unwrap(),
            true,
            false,
        );
        match result {
            Ok(_) => assert!(false),
            Err(e) => assert_eq!(e, NvFsError::IoError(NvFsIoError::IoFailure)),
        };

        // Read the (relocated) FsMetadata.
        let (_blkdev, fs_metadata) = cocoonfs_test_read_fs_metadata_helper(blkdev).unwrap();
        assert_eq!(&initial_aux_fs_metadata, fs_metadata.get_aux());
        match &fs_metadata {
            FsMetadata::MkFsInfo(fs_metadata) => {
                // The effective mkfsinfo data should be at the primary
                // location after the failed resizing operation.
                let relocated_backup_mkfsinfo_begin = fs_metadata.mkfsinfo_data_location.begin();
                assert_eq!(u64::from(relocated_backup_mkfsinfo_begin), 0);
            }
            FsMetadata::Formatted(_) => assert!(false),
        };
    }
}
