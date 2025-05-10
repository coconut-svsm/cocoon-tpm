// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use super::{
    cocoonfs_test_fs_instance_into_chip_helper, cocoonfs_test_mkfs_op_helper, cocoonfs_test_openfs_op_helper,
    CocoonFsTestConfigs,
};

#[test]
fn mkfs_openfs() {
    for test_config in CocoonFsTestConfigs::new() {
        for enable_trimming in [false, true] {
            let fs_instance = cocoonfs_test_mkfs_op_helper(&test_config, 3usize << 18, enable_trimming).unwrap();

            // Close and open.
            let chip = cocoonfs_test_fs_instance_into_chip_helper(fs_instance);
            cocoonfs_test_openfs_op_helper(chip).unwrap();
        }
    }
}
