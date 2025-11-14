// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

use crate::{
    blkdev::test::TestNvBlkDev,
    crypto::{hash, rng, symcipher},
    fs::{
        self,
        cocoonfs::{CocoonFs, CocoonFsMkFsFuture, CocoonFsOpenFsFuture, CocoonFsWriteMkfsInfoHeaderFuture, layout},
    },
    nvfs_err_internal, tpm2_interface,
    utils_async::{
        sync_types,
        test::{TestAsyncExecutor, TestNopSyncTypes},
    },
    utils_common::{fixed_vec::FixedVec, zeroize},
};
use core::{marker, ops, pin, slice, task};

struct CocoonFsTestLayoutConfig {
    blkdev_io_block_size_128b_log2: u8,
    preferred_blkdev_io_blocks_bulk_log2: u8,

    allocation_block_size_128b_log2: u8,
    io_block_allocation_blocks_log2: u8,
    auth_tree_node_io_blocks_log2: u8,
    auth_tree_data_block_allocation_blocks_log2: u8,
    allocation_bitmap_file_block_allocation_blocks_log2: u8,
    index_tree_node_allocation_blocks_log2: u8,

    salt_len: u8,
}

const COCOONFS_TEST_LAYOUT_CONFIGS: [CocoonFsTestLayoutConfig; 5] = [
    // Base.
    CocoonFsTestLayoutConfig {
        blkdev_io_block_size_128b_log2: 0,
        preferred_blkdev_io_blocks_bulk_log2: 2,
        allocation_block_size_128b_log2: 0,
        io_block_allocation_blocks_log2: 0,
        auth_tree_node_io_blocks_log2: 0,
        auth_tree_data_block_allocation_blocks_log2: 0,
        allocation_bitmap_file_block_allocation_blocks_log2: 0,
        index_tree_node_allocation_blocks_log2: 0,
        salt_len: 0,
    },
    // Device IO Block size > Authentication Tree Data Block.
    CocoonFsTestLayoutConfig {
        blkdev_io_block_size_128b_log2: 4,
        preferred_blkdev_io_blocks_bulk_log2: 0,
        allocation_block_size_128b_log2: 0,
        io_block_allocation_blocks_log2: 4,
        auth_tree_node_io_blocks_log2: 0,
        auth_tree_data_block_allocation_blocks_log2: 2,
        allocation_bitmap_file_block_allocation_blocks_log2: 0,
        index_tree_node_allocation_blocks_log2: 0,
        salt_len: 0,
    },
    // Device IO Block size < Authentication Tree Data Block.
    CocoonFsTestLayoutConfig {
        blkdev_io_block_size_128b_log2: 2,
        preferred_blkdev_io_blocks_bulk_log2: 0,
        allocation_block_size_128b_log2: 0,
        io_block_allocation_blocks_log2: 2,
        auth_tree_node_io_blocks_log2: 0,
        auth_tree_data_block_allocation_blocks_log2: 4,
        allocation_bitmap_file_block_allocation_blocks_log2: 0,
        index_tree_node_allocation_blocks_log2: 0,
        salt_len: 0,
    },
    // Device IO Block size < Allocation Block.
    CocoonFsTestLayoutConfig {
        blkdev_io_block_size_128b_log2: 0,
        preferred_blkdev_io_blocks_bulk_log2: 0,
        allocation_block_size_128b_log2: 2,
        io_block_allocation_blocks_log2: 0,
        auth_tree_node_io_blocks_log2: 0,
        auth_tree_data_block_allocation_blocks_log2: 0,
        allocation_bitmap_file_block_allocation_blocks_log2: 0,
        index_tree_node_allocation_blocks_log2: 0,
        salt_len: 0,
    },
    // Realistic.
    CocoonFsTestLayoutConfig {
        blkdev_io_block_size_128b_log2: 2,                      //  512B
        preferred_blkdev_io_blocks_bulk_log2: 3,                // 4096B
        allocation_block_size_128b_log2: 0,                     //  128B
        io_block_allocation_blocks_log2: 2,                     //  512B
        auth_tree_node_io_blocks_log2: 1,                       // 1024B
        auth_tree_data_block_allocation_blocks_log2: 2,         //  512B
        allocation_bitmap_file_block_allocation_blocks_log2: 0, //  128B
        index_tree_node_allocation_blocks_log2: 0,              //  128B
        salt_len: 0,
    },
];

struct CocoonFsTestCryptoConfig {
    auth_tree_node_hash_alg: tpm2_interface::TpmiAlgHash,
    auth_tree_data_hmac_hash_alg: tpm2_interface::TpmiAlgHash,
    auth_tree_root_hmac_hash_alg: tpm2_interface::TpmiAlgHash,
    preauth_cca_protection_hmac_hash_alg: tpm2_interface::TpmiAlgHash,
    block_cipher_alg: symcipher::SymBlockCipherAlg,
}

const COCOONFS_TEST_CRTYPTO_CONFIGS: [CocoonFsTestCryptoConfig; 1] = [CocoonFsTestCryptoConfig {
    auth_tree_data_hmac_hash_alg: cocoonfs_test_hash_alg(),
    auth_tree_node_hash_alg: cocoonfs_test_hash_alg(),
    auth_tree_root_hmac_hash_alg: cocoonfs_test_hash_alg(),
    preauth_cca_protection_hmac_hash_alg: cocoonfs_test_hash_alg(),
    block_cipher_alg: cocoonfs_test_block_cipher_alg(),
}];

const fn cocoonfs_test_hash_alg() -> tpm2_interface::TpmiAlgHash {
    hash::test_hash_alg()
}

const fn cocoonfs_test_block_cipher_alg() -> symcipher::SymBlockCipherAlg {
    symcipher::test_block_cipher_alg()
}

struct CocoonFsTestConfig<'a> {
    layout: &'a CocoonFsTestLayoutConfig,
    crypto: &'a CocoonFsTestCryptoConfig,
}

impl<'a> CocoonFsTestConfig<'a> {
    fn instantiate(&self, image_size: usize) -> (TestNvBlkDev, layout::ImageLayout, FixedVec<u8, 4>) {
        let image_layout = layout::ImageLayout::new(
            self.layout.allocation_block_size_128b_log2,
            self.layout.io_block_allocation_blocks_log2,
            self.layout.auth_tree_node_io_blocks_log2,
            self.layout.auth_tree_data_block_allocation_blocks_log2,
            self.layout.allocation_bitmap_file_block_allocation_blocks_log2,
            self.layout.index_tree_node_allocation_blocks_log2,
            self.crypto.auth_tree_node_hash_alg,
            self.crypto.auth_tree_data_hmac_hash_alg,
            self.crypto.auth_tree_root_hmac_hash_alg,
            self.crypto.preauth_cca_protection_hmac_hash_alg,
            cocoonfs_test_hash_alg(),
            self.crypto.block_cipher_alg,
        )
        .unwrap();

        let image_blkdev_io_blocks_count =
            u64::try_from(image_size).unwrap() >> (self.layout.blkdev_io_block_size_128b_log2 as u32 + 7);
        let blkdev = TestNvBlkDev::new(
            self.layout.blkdev_io_block_size_128b_log2 as u32,
            image_blkdev_io_blocks_count,
            self.layout.preferred_blkdev_io_blocks_bulk_log2 as u32,
        );

        let mut salt = FixedVec::new_with_default(self.layout.salt_len as usize).unwrap();
        let mut salt_chunks = salt.chunks_exact_mut(4);
        while let Some(salt_chunk) = salt_chunks.next() {
            salt_chunk.copy_from_slice(b"SALT");
        }
        for s in salt_chunks.into_remainder().iter_mut().enumerate() {
            *s.1 = b"SALT"[s.0];
        }

        (blkdev, image_layout, salt)
    }
}

struct CocoonFsTestConfigs {
    layout_iter: slice::Iter<'static, CocoonFsTestLayoutConfig>,
    next_layout: Option<&'static CocoonFsTestLayoutConfig>,
    crypto_iter: slice::Iter<'static, CocoonFsTestCryptoConfig>,
}

impl CocoonFsTestConfigs {
    fn new() -> Self {
        Self {
            layout_iter: COCOONFS_TEST_LAYOUT_CONFIGS.iter(),
            next_layout: None,
            crypto_iter: COCOONFS_TEST_CRTYPTO_CONFIGS.iter(),
        }
    }
}

impl Iterator for CocoonFsTestConfigs {
    type Item = CocoonFsTestConfig<'static>;

    fn next(&mut self) -> Option<Self::Item> {
        let crypto = match self.crypto_iter.next() {
            Some(crypto) => crypto,
            None => {
                self.next_layout = None;
                self.crypto_iter = COCOONFS_TEST_CRTYPTO_CONFIGS.iter();
                self.crypto_iter.next()?
            }
        };
        let layout = match self.next_layout.as_ref() {
            Some(next_layout) => next_layout,
            None => self.next_layout.insert(self.layout_iter.next()?),
        };
        Some(CocoonFsTestConfig { layout, crypto })
    }
}

type TestCocoonFs = CocoonFs<TestNopSyncTypes, TestNvBlkDev>;

fn cocoonfs_test_mk_fs_instance_ref<'a>(
    fs_instance: &'a <TestCocoonFs as fs::NvFs>::SyncRcPtr,
) -> <TestCocoonFs as fs::NvFs>::SyncRcPtrRef<'a> {
    type CocoonFsTestSyncRcPtr = <TestCocoonFs as fs::NvFs>::SyncRcPtr;
    <CocoonFsTestSyncRcPtr as sync_types::SyncRcPtr<_>>::as_ref(&fs_instance)
}

fn cocoonfs_test_fs_instance_into_blkdev_helper(fs_instance: <TestCocoonFs as fs::NvFs>::SyncRcPtr) -> TestNvBlkDev {
    let blkdev = fs_instance.blkdev.snapshot();
    blkdev
}

fn cocoonfs_test_mkfs_op_helper(
    test_config: &CocoonFsTestConfig,
    image_size: usize,
    enable_trimming: bool,
) -> Result<<TestCocoonFs as fs::NvFs>::SyncRcPtr, fs::NvFsError> {
    let rng = Box::new(rng::test_rng());
    let (blkdev, image_layout, salt) = test_config.instantiate(image_size);
    let mkfs_fut = CocoonFsMkFsFuture::<TestNopSyncTypes, _>::new(
        blkdev,
        &image_layout,
        salt,
        None,
        &[0u8; 0],
        enable_trimming,
        rng,
    )
    .map_err(|(_blkdev, _rng, e)| e)
    .unwrap();

    let executor = TestAsyncExecutor::new();
    let mkfs_waiter = TestAsyncExecutor::spawn(&executor, mkfs_fut);
    TestAsyncExecutor::run_to_completion(&executor);
    let mkfs_result = mkfs_waiter.take().unwrap();
    let (_rng, mkfs_result) = mkfs_result.unwrap();
    mkfs_result.map_err(|(_blkdev, e)| e)
}

fn cocoonfs_test_write_mkfsinfo_header_op_helper(
    test_config: &CocoonFsTestConfig,
    image_size: usize,
) -> Result<TestNvBlkDev, fs::NvFsError> {
    let (blkdev, image_layout, salt) = test_config.instantiate(0);
    let image_size = image_size as u64;
    let write_mkfsinfo_header_fut =
        CocoonFsWriteMkfsInfoHeaderFuture::new(blkdev, &image_layout, salt, Some(image_size), false)
            .map_err(|(_blkdev, e)| e)?;

    let executor = TestAsyncExecutor::new();
    let write_mkfsinfo_header_waiter = TestAsyncExecutor::spawn(&executor, write_mkfsinfo_header_fut);
    TestAsyncExecutor::run_to_completion(&executor);
    let write_mkfsinfo_header_result = write_mkfsinfo_header_waiter.take().unwrap();
    let (blkdev, result) = write_mkfsinfo_header_result.unwrap();
    match result {
        Ok(()) => Ok(blkdev),
        Err(e) => Err(e),
    }
}

fn cocoonfs_test_openfs_op_helper(
    blkdev: TestNvBlkDev,
) -> Result<<TestCocoonFs as fs::NvFs>::SyncRcPtr, fs::NvFsError> {
    let rng = Box::new(rng::test_rng());
    let root_key = zeroize::Zeroizing::new([0u8; 0].iter().map(|b| *b).collect::<Vec<u8>>());
    let openfs_fut = CocoonFsOpenFsFuture::<TestNopSyncTypes, _>::new(blkdev, root_key, false, rng)
        .map_err(|(_blkdev, _root_key, _rng, e)| e)
        .unwrap();
    let executor = TestAsyncExecutor::new();
    let openfs_waiter = TestAsyncExecutor::spawn(&executor, openfs_fut);
    TestAsyncExecutor::run_to_completion(&executor);
    let openfs_result = openfs_waiter.take().unwrap();
    let (_rng, openfs_result) = openfs_result.unwrap();
    openfs_result.map_err(|(_blkdev, _root_key, e)| e)
}

fn cocoonfs_test_openfs_fail_mkfsinfo_header_application_op_helper(
    blkdev: TestNvBlkDev,
) -> Result<TestNvBlkDev, fs::NvFsError> {
    let rng = Box::new(rng::test_rng());
    let root_key = zeroize::Zeroizing::new([0u8; 0].iter().map(|b| *b).collect::<Vec<u8>>());
    let mut openfs_fut = CocoonFsOpenFsFuture::<TestNopSyncTypes, _>::new(blkdev, root_key, false, rng)
        .map_err(|(_blkdev, _root_key, _rng, e)| e)
        .unwrap();
    // Simulate IO failure when writing the regular static image header.
    openfs_fut.test_fail_apply_mkfsinfo_header = true;
    let executor = TestAsyncExecutor::new();
    let openfs_waiter = TestAsyncExecutor::spawn(&executor, openfs_fut);
    TestAsyncExecutor::run_to_completion(&executor);
    let openfs_result = openfs_waiter.take().unwrap();
    let (_rng, openfs_result) = openfs_result.unwrap();
    match openfs_result {
        Ok(_fs_instance) => {
            // The test is supposed to fail application of the mkfsinfo header. But there
            // was none, presumably because the test is buggy.
            Err(nvfs_err_internal!())
        }
        Err((blkdev, _root_key, fs::NvFsError::IoError(fs::NvFsIoError::IoFailure))) => Ok(blkdev),
        Err((_blkdev, _root_key, e)) => Err(e),
    }
}

#[allow(unused)]
fn cocoonfs_test_start_read_sequence_op_helper(
    fs_instance: &<TestCocoonFs as fs::NvFs>::SyncRcPtr,
) -> Result<<TestCocoonFs as fs::NvFs>::ConsistentReadSequence, fs::NvFsError> {
    let rng = Box::new(rng::test_rng());
    let start_read_sequence_fut = <CocoonFs<TestNopSyncTypes, _> as fs::NvFs>::start_read_sequence(
        &cocoonfs_test_mk_fs_instance_ref(&fs_instance),
    );
    let executor = TestAsyncExecutor::new();
    let start_read_sequence_fut = TestAsyncExecutor::spawn(
        &executor,
        fs::NvFsFutureAsCoreFuture::<TestCocoonFs, _>::new(fs_instance.clone(), start_read_sequence_fut, rng),
    );
    TestAsyncExecutor::run_to_completion(&executor);
    start_read_sequence_fut.take().unwrap().unwrap().1
}

fn cocoonfs_test_start_transaction_op_helper(
    fs_instance: &<TestCocoonFs as fs::NvFs>::SyncRcPtr,
    continued_read_sequence: Option<&<TestCocoonFs as fs::NvFs>::ConsistentReadSequence>,
) -> Result<<TestCocoonFs as fs::NvFs>::Transaction, fs::NvFsError> {
    let rng = Box::new(rng::test_rng());
    let start_transaction_fut = <CocoonFs<TestNopSyncTypes, _> as fs::NvFs>::start_transaction(
        &cocoonfs_test_mk_fs_instance_ref(&fs_instance),
        continued_read_sequence,
    );
    let executor = TestAsyncExecutor::new();
    let start_transaction_waiter = TestAsyncExecutor::spawn(
        &executor,
        fs::NvFsFutureAsCoreFuture::<TestCocoonFs, _>::new(fs_instance.clone(), start_transaction_fut, rng),
    );
    TestAsyncExecutor::run_to_completion(&executor);
    start_transaction_waiter.take().unwrap().unwrap().1
}

fn cocoonfs_test_commit_transaction_op_helper(
    fs_instance: &<TestCocoonFs as fs::NvFs>::SyncRcPtr,
    mut transaction: <TestCocoonFs as fs::NvFs>::Transaction,
    fail_apply_journal: bool,
) -> Result<(), fs::TransactionCommitError> {
    let rng = Box::new(rng::test_rng());
    if fail_apply_journal {
        transaction.test_set_fail_apply_journal();
    }
    let commit_transaction_fut = <TestCocoonFs as fs::NvFs>::commit_transaction(
        &cocoonfs_test_mk_fs_instance_ref(&fs_instance),
        transaction,
        None,
        None,
        true,
    );
    let executor = TestAsyncExecutor::new();
    let commit_transaction_waiter = TestAsyncExecutor::spawn(
        &executor,
        fs::NvFsFutureAsCoreFuture::<TestCocoonFs, _>::new(fs_instance.clone(), commit_transaction_fut, rng),
    );
    TestAsyncExecutor::run_to_completion(&executor);
    let commit_transaction_result = commit_transaction_waiter.take().unwrap().unwrap().1;
    commit_transaction_result
}

fn cocoonfs_test_write_inode_op_helper(
    fs_instance: &<TestCocoonFs as fs::NvFs>::SyncRcPtr,
    transaction: <TestCocoonFs as fs::NvFs>::Transaction,
    inode: u32,
    data: &[u8],
) -> Result<<TestCocoonFs as fs::NvFs>::Transaction, fs::NvFsError> {
    let rng = Box::new(rng::test_rng());
    let data = data.iter().copied().collect::<Vec<u8>>();
    let write_inode_fut = <TestCocoonFs as fs::NvFs>::write_inode(
        &cocoonfs_test_mk_fs_instance_ref(&fs_instance),
        transaction,
        inode,
        zeroize::Zeroizing::new(data),
    );
    let executor = TestAsyncExecutor::new();
    let write_inode_waiter = TestAsyncExecutor::spawn(
        &executor,
        fs::NvFsFutureAsCoreFuture::<CocoonFs<TestNopSyncTypes, _>, _>::new(fs_instance.clone(), write_inode_fut, rng),
    );
    TestAsyncExecutor::run_to_completion(&executor);
    let write_inode_result = write_inode_waiter.take().unwrap().unwrap().1;
    write_inode_result
        .and_then(|(transaction, _write_inode_data, write_inode_result)| write_inode_result.map(|_| transaction))
}

fn cocoonfs_test_read_inode_op_helper(
    fs_instance: &<TestCocoonFs as fs::NvFs>::SyncRcPtr,
    read_context: Option<fs::NvFsReadContext<TestCocoonFs>>,
    inode: u32,
) -> Result<(fs::NvFsReadContext<TestCocoonFs>, Option<zeroize::Zeroizing<Vec<u8>>>), fs::NvFsError> {
    let rng = Box::new(rng::test_rng());
    let read_inode_fut =
        <TestCocoonFs as fs::NvFs>::read_inode(&cocoonfs_test_mk_fs_instance_ref(&fs_instance), read_context, inode);
    let executor = TestAsyncExecutor::new();
    let read_inode_waiter = TestAsyncExecutor::spawn(
        &executor,
        fs::NvFsFutureAsCoreFuture::<CocoonFs<TestNopSyncTypes, _>, _>::new(fs_instance.clone(), read_inode_fut, rng),
    );
    TestAsyncExecutor::run_to_completion(&executor);
    let read_inode_result = read_inode_waiter.take().unwrap().unwrap().1;
    read_inode_result.and_then(|(read_context, read_inode_result)| read_inode_result.map(|data| (read_context, data)))
}

fn cocoonfs_test_enumerate_inodes_op_collect(
    fs_instance: &<TestCocoonFs as fs::NvFs>::SyncRcPtr,
    read_context: Option<fs::NvFsReadContext<TestCocoonFs>>,
    inodes_enumerate_range: ops::RangeInclusive<u32>,
) -> Result<(fs::NvFsReadContext<TestCocoonFs>, Vec<u32>), fs::NvFsError> {
    struct CollectInodesCallback {
        collected_inodes: Vec<u32>,
    }

    impl CocoonFsTestEnumerateInodesFutureCallback for CollectInodesCallback {
        fn call(&mut self, inode: u32, _inode_data: zeroize::Zeroizing<Vec<u8>>) -> Result<(), fs::NvFsError> {
            self.collected_inodes.push(inode);
            Ok(())
        }
    }

    let (read_context, callback) = cocoonfs_test_enumerate_inodes_op_cb(
        fs_instance,
        read_context,
        inodes_enumerate_range,
        CollectInodesCallback {
            collected_inodes: Vec::new(),
        },
    )?;
    let CollectInodesCallback { collected_inodes } = callback;
    Ok((read_context, collected_inodes))
}

fn cocoonfs_test_enumerate_inodes_op_cb<CB: CocoonFsTestEnumerateInodesFutureCallback>(
    fs_instance: &<TestCocoonFs as fs::NvFs>::SyncRcPtr,
    read_context: Option<fs::NvFsReadContext<TestCocoonFs>>,
    inodes_enumerate_range: ops::RangeInclusive<u32>,
    callback: CB,
) -> Result<(fs::NvFsReadContext<TestCocoonFs>, CB), fs::NvFsError> {
    let rng = Box::new(rng::test_rng());
    let enumerate_inodes_fut =
        CocoonFsTestEnumerateInodesFuture::new(fs_instance, read_context, inodes_enumerate_range, callback)?;
    let executor = TestAsyncExecutor::new();
    let enumerate_inodes_waiter = TestAsyncExecutor::spawn(
        &executor,
        fs::NvFsFutureAsCoreFuture::<CocoonFs<TestNopSyncTypes, _>, _>::new(
            fs_instance.clone(),
            enumerate_inodes_fut,
            rng,
        ),
    );
    TestAsyncExecutor::run_to_completion(&executor);
    let enumerate_inodes_result = enumerate_inodes_waiter.take().unwrap().unwrap().1;
    enumerate_inodes_result
}

trait CocoonFsTestEnumerateInodesFutureCallback: 'static + marker::Unpin + marker::Send {
    fn call(&mut self, inode: u32, inode_data: zeroize::Zeroizing<Vec<u8>>) -> Result<(), fs::NvFsError>;
}

struct CocoonFsTestEnumerateInodesFuture<CB: CocoonFsTestEnumerateInodesFutureCallback> {
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self.
    callback: Option<CB>,
    fut_state: CocoonFsTestEnumerateInodesFutureState,
}

enum CocoonFsTestEnumerateInodesFutureState {
    StartReadSequence {
        start_read_sequence_fut: <TestCocoonFs as fs::NvFs>::StartReadSequenceFut,
        inodes_enumerate_range: ops::RangeInclusive<u32>,
    },
    CreateEnumerateCursor {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
        // Self.
        read_context: Option<fs::NvFsReadContext<TestCocoonFs>>,
        inodes_enumerate_range: ops::RangeInclusive<u32>,
    },
    Next {
        next_fut: <<TestCocoonFs as fs::NvFs>::EnumerateCursor as fs::NvFsEnumerateCursor<TestCocoonFs>>::NextFut,
    },
    ReadCurrentInodeData {
        inode: u32,
        read_fut:
            <<TestCocoonFs as fs::NvFs>::EnumerateCursor as fs::NvFsEnumerateCursor<TestCocoonFs>>::ReadInodeDataFut,
    },
    Done,
}

impl<CB: CocoonFsTestEnumerateInodesFutureCallback> CocoonFsTestEnumerateInodesFuture<CB> {
    fn new(
        fs_instance: &<TestCocoonFs as fs::NvFs>::SyncRcPtr,
        read_context: Option<fs::NvFsReadContext<TestCocoonFs>>,
        inodes_enumerate_range: ops::RangeInclusive<u32>,
        callback: CB,
    ) -> Result<Self, fs::NvFsError> {
        let fut_state = match read_context {
            Some(read_context) => CocoonFsTestEnumerateInodesFutureState::CreateEnumerateCursor {
                read_context: Some(read_context),
                inodes_enumerate_range,
            },
            None => {
                let start_read_sequence_fut =
                    <TestCocoonFs as fs::NvFs>::start_read_sequence(&cocoonfs_test_mk_fs_instance_ref(&fs_instance));
                CocoonFsTestEnumerateInodesFutureState::StartReadSequence {
                    start_read_sequence_fut,
                    inodes_enumerate_range,
                }
            }
        };
        Ok(Self {
            callback: Some(callback),
            fut_state,
        })
    }
}

impl<CB: CocoonFsTestEnumerateInodesFutureCallback> fs::NvFsFuture<TestCocoonFs>
    for CocoonFsTestEnumerateInodesFuture<CB>
{
    type Output = Result<(fs::NvFsReadContext<TestCocoonFs>, CB), fs::NvFsError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        fs_instance: &<TestCocoonFs as fs::NvFs>::SyncRcPtrRef<'_>,
        rng: &mut dyn rng::RngCoreDispatchable,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                CocoonFsTestEnumerateInodesFutureState::StartReadSequence {
                    start_read_sequence_fut,
                    inodes_enumerate_range,
                } => {
                    let read_sequence =
                        match fs::NvFsFuture::poll(pin::Pin::new(start_read_sequence_fut), fs_instance, rng, cx) {
                            task::Poll::Ready(Ok(read_sequence)) => read_sequence,
                            task::Poll::Ready(Err(e)) => {
                                this.fut_state = CocoonFsTestEnumerateInodesFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                            task::Poll::Pending => return task::Poll::Pending,
                        };
                    this.fut_state = CocoonFsTestEnumerateInodesFutureState::CreateEnumerateCursor {
                        read_context: Some(fs::NvFsReadContext::Committed { seq: read_sequence }),
                        inodes_enumerate_range: inodes_enumerate_range.clone(),
                    };
                }
                CocoonFsTestEnumerateInodesFutureState::CreateEnumerateCursor {
                    read_context,
                    inodes_enumerate_range,
                } => {
                    let read_context = match read_context.take() {
                        Some(read_context) => read_context,
                        None => {
                            this.fut_state = CocoonFsTestEnumerateInodesFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    let enumerate_cursor = match <TestCocoonFs as fs::NvFs>::enumerate_cursor(
                        fs_instance,
                        read_context,
                        inodes_enumerate_range.clone(),
                    )
                    .and_then(|result| result.map_err(|(_read_context, e)| e))
                    {
                        Ok(enumerate_cursor) => enumerate_cursor,
                        Err(e) => {
                            this.fut_state = CocoonFsTestEnumerateInodesFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };

                    let next_fut = fs::NvFsEnumerateCursor::next(enumerate_cursor);
                    this.fut_state = CocoonFsTestEnumerateInodesFutureState::Next { next_fut };
                }
                CocoonFsTestEnumerateInodesFutureState::Next { next_fut } => {
                    let (enumerate_cursor, inode) =
                        match fs::NvFsFuture::poll(pin::Pin::new(next_fut), fs_instance, rng, cx) {
                            task::Poll::Ready(result) => {
                                match result.and_then(|(enumerate_cursor, result)| {
                                    result.map(|inode| (enumerate_cursor, inode))
                                }) {
                                    Ok((enumerate_cursor, inode)) => (enumerate_cursor, inode),
                                    Err(e) => {
                                        this.fut_state = CocoonFsTestEnumerateInodesFutureState::Done;
                                        return task::Poll::Ready(Err(e));
                                    }
                                }
                            }
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    match inode {
                        Some(inode) => {
                            let read_fut = fs::NvFsEnumerateCursor::read_current_inode_data(enumerate_cursor);
                            this.fut_state =
                                CocoonFsTestEnumerateInodesFutureState::ReadCurrentInodeData { inode, read_fut };
                        }
                        None => {
                            this.fut_state = CocoonFsTestEnumerateInodesFutureState::Done;
                            let read_context = match fs::NvFsEnumerateCursor::into_context(enumerate_cursor) {
                                Ok(read_context) => read_context,
                                Err(e) => {
                                    return task::Poll::Ready(Err(e));
                                }
                            };

                            let callback = match this.callback.take() {
                                Some(callback) => callback,
                                None => {
                                    return task::Poll::Ready(Err(nvfs_err_internal!()));
                                }
                            };

                            return task::Poll::Ready(Ok((read_context, callback)));
                        }
                    };
                }
                CocoonFsTestEnumerateInodesFutureState::ReadCurrentInodeData { inode, read_fut } => {
                    let (enumerate_cursor, inode_data) =
                        match fs::NvFsFuture::poll(pin::Pin::new(read_fut), fs_instance, rng, cx) {
                            task::Poll::Ready(result) => {
                                match result.and_then(|(enumerate_cursor, result)| {
                                    result.map(|inode_data| (enumerate_cursor, inode_data))
                                }) {
                                    Ok((enumerate_cursor, inode_data)) => (enumerate_cursor, inode_data),
                                    Err(e) => {
                                        this.fut_state = CocoonFsTestEnumerateInodesFutureState::Done;
                                        return task::Poll::Ready(Err(e));
                                    }
                                }
                            }
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    let callback = match this.callback.as_mut() {
                        Some(callback) => callback,
                        None => {
                            this.fut_state = CocoonFsTestEnumerateInodesFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    if let Err(e) = CocoonFsTestEnumerateInodesFutureCallback::call(callback, *inode, inode_data) {
                        this.fut_state = CocoonFsTestEnumerateInodesFutureState::Done;
                        return task::Poll::Ready(Err(e));
                    }

                    let next_fut = fs::NvFsEnumerateCursor::next(enumerate_cursor);
                    this.fut_state = CocoonFsTestEnumerateInodesFutureState::Next { next_fut };
                }
                CocoonFsTestEnumerateInodesFutureState::Done => unreachable!(),
            }
        }
    }
}

fn cocoonfs_test_unlink_inodes_op_uncond(
    fs_instance: &<TestCocoonFs as fs::NvFs>::SyncRcPtr,
    transaction: <TestCocoonFs as fs::NvFs>::Transaction,
    inodes_unlink_range: ops::RangeInclusive<u32>,
) -> Result<<TestCocoonFs as fs::NvFs>::Transaction, fs::NvFsError> {
    cocoonfs_test_unlink_inodes_op_fnmut_cb(fs_instance, transaction, inodes_unlink_range, |_inode, _inode_data| {
        Ok(true)
    })
    .map(|(transaction, _callback)| transaction)
}

fn cocoonfs_test_unlink_inodes_op_fnmut_cb<
    CB: 'static + FnMut(u32, &[u8]) -> Result<bool, fs::NvFsError> + marker::Send + marker::Unpin,
>(
    fs_instance: &<TestCocoonFs as fs::NvFs>::SyncRcPtr,
    transaction: <TestCocoonFs as fs::NvFs>::Transaction,
    inodes_unlink_range: ops::RangeInclusive<u32>,
    callback: CB,
) -> Result<(<TestCocoonFs as fs::NvFs>::Transaction, CB), fs::NvFsError> {
    struct UnlinkInodesCallback<
        CB: 'static + FnMut(u32, &[u8]) -> Result<bool, fs::NvFsError> + marker::Send + marker::Unpin,
    > {
        callback: CB,
    }

    impl<CB: 'static + FnMut(u32, &[u8]) -> Result<bool, fs::NvFsError> + marker::Send + marker::Unpin>
        CocoonFsTestUnlinkInodesFutureCallback for UnlinkInodesCallback<CB>
    {
        fn call(&mut self, inode: u32, inode_data: zeroize::Zeroizing<Vec<u8>>) -> Result<bool, fs::NvFsError> {
            (&mut self.callback)(inode, inode_data.as_slice())
        }
    }

    let (transaction, callback) = cocoonfs_test_unlink_inodes_op_cb(
        fs_instance,
        transaction,
        inodes_unlink_range,
        UnlinkInodesCallback { callback },
    )?;
    let UnlinkInodesCallback { callback } = callback;
    Ok((transaction, callback))
}

fn cocoonfs_test_unlink_inodes_op_cb<CB: CocoonFsTestUnlinkInodesFutureCallback>(
    fs_instance: &<TestCocoonFs as fs::NvFs>::SyncRcPtr,
    transaction: <TestCocoonFs as fs::NvFs>::Transaction,
    inodes_unlink_range: ops::RangeInclusive<u32>,
    callback: CB,
) -> Result<(<TestCocoonFs as fs::NvFs>::Transaction, CB), fs::NvFsError> {
    let rng = Box::new(rng::test_rng());
    let unlink_inodes_fut =
        CocoonFsTestUnlinkInodesFuture::new(fs_instance, transaction, inodes_unlink_range, callback)?;
    let executor = TestAsyncExecutor::new();
    let unlink_inodes_waiter = TestAsyncExecutor::spawn(
        &executor,
        fs::NvFsFutureAsCoreFuture::<CocoonFs<TestNopSyncTypes, _>, _>::new(
            fs_instance.clone(),
            unlink_inodes_fut,
            rng,
        ),
    );
    TestAsyncExecutor::run_to_completion(&executor);
    let unlink_inodes_result = unlink_inodes_waiter.take().unwrap().unwrap().1;
    unlink_inodes_result
}

trait CocoonFsTestUnlinkInodesFutureCallback: 'static + marker::Unpin + marker::Send {
    fn call(&mut self, inode: u32, inode_data: zeroize::Zeroizing<Vec<u8>>) -> Result<bool, fs::NvFsError>;
}

struct CocoonFsTestUnlinkInodesFuture<CB: CocoonFsTestUnlinkInodesFutureCallback> {
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self.
    callback: Option<CB>,
    fut_state: CocoonFsTestUnlinkInodesFutureState,
}

enum CocoonFsTestUnlinkInodesFutureState {
    Next {
        next_fut: <<TestCocoonFs as fs::NvFs>::UnlinkCursor as fs::NvFsUnlinkCursor<TestCocoonFs>>::NextFut,
    },
    ReadCurrentInodeData {
        inode: u32,
        read_fut: <<TestCocoonFs as fs::NvFs>::UnlinkCursor as fs::NvFsUnlinkCursor<TestCocoonFs>>::ReadInodeDataFut,
    },
    UnlinkCurrentInode {
        unlink_fut: <<TestCocoonFs as fs::NvFs>::UnlinkCursor as fs::NvFsUnlinkCursor<TestCocoonFs>>::UnlinkInodeFut,
    },
    Done,
}

impl<CB: CocoonFsTestUnlinkInodesFutureCallback> CocoonFsTestUnlinkInodesFuture<CB> {
    fn new(
        fs_instance: &<TestCocoonFs as fs::NvFs>::SyncRcPtr,
        transaction: <TestCocoonFs as fs::NvFs>::Transaction,
        inodes_unlink_range: ops::RangeInclusive<u32>,
        callback: CB,
    ) -> Result<Self, fs::NvFsError> {
        let unlink_cursor = <TestCocoonFs as fs::NvFs>::unlink_cursor(
            &cocoonfs_test_mk_fs_instance_ref(&fs_instance),
            transaction,
            inodes_unlink_range,
        )
        .and_then(|result| result.map_err(|(_transaction, e)| e))?;
        let next_fut = fs::NvFsUnlinkCursor::next(unlink_cursor);
        Ok(Self {
            callback: Some(callback),
            fut_state: CocoonFsTestUnlinkInodesFutureState::Next { next_fut },
        })
    }
}

impl<CB: CocoonFsTestUnlinkInodesFutureCallback> fs::NvFsFuture<TestCocoonFs> for CocoonFsTestUnlinkInodesFuture<CB> {
    type Output = Result<(<TestCocoonFs as fs::NvFs>::Transaction, CB), fs::NvFsError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        fs_instance: &<TestCocoonFs as fs::NvFs>::SyncRcPtrRef<'_>,
        rng: &mut dyn rng::RngCoreDispatchable,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                CocoonFsTestUnlinkInodesFutureState::Next { next_fut } => {
                    let (unlink_cursor, inode) =
                        match fs::NvFsFuture::poll(pin::Pin::new(next_fut), fs_instance, rng, cx) {
                            task::Poll::Ready(result) => {
                                match result
                                    .and_then(|(unlink_cursor, result)| result.map(|inode| (unlink_cursor, inode)))
                                {
                                    Ok((unlink_cursor, inode)) => (unlink_cursor, inode),
                                    Err(e) => {
                                        this.fut_state = CocoonFsTestUnlinkInodesFutureState::Done;
                                        return task::Poll::Ready(Err(e));
                                    }
                                }
                            }
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    match inode {
                        Some(inode) => {
                            let read_fut = fs::NvFsUnlinkCursor::read_current_inode_data(unlink_cursor);
                            this.fut_state =
                                CocoonFsTestUnlinkInodesFutureState::ReadCurrentInodeData { inode, read_fut };
                        }
                        None => {
                            this.fut_state = CocoonFsTestUnlinkInodesFutureState::Done;
                            let transaction = match fs::NvFsUnlinkCursor::into_transaction(unlink_cursor) {
                                Ok(transaction) => transaction,
                                Err(e) => {
                                    return task::Poll::Ready(Err(e));
                                }
                            };

                            let callback = match this.callback.take() {
                                Some(callback) => callback,
                                None => {
                                    return task::Poll::Ready(Err(nvfs_err_internal!()));
                                }
                            };

                            return task::Poll::Ready(Ok((transaction, callback)));
                        }
                    };
                }
                CocoonFsTestUnlinkInodesFutureState::ReadCurrentInodeData { inode, read_fut } => {
                    let (unlink_cursor, inode_data) =
                        match fs::NvFsFuture::poll(pin::Pin::new(read_fut), fs_instance, rng, cx) {
                            task::Poll::Ready(result) => {
                                match result.and_then(|(unlink_cursor, result)| {
                                    result.map(|inode_data| (unlink_cursor, inode_data))
                                }) {
                                    Ok((unlink_cursor, inode_data)) => (unlink_cursor, inode_data),
                                    Err(e) => {
                                        this.fut_state = CocoonFsTestUnlinkInodesFutureState::Done;
                                        return task::Poll::Ready(Err(e));
                                    }
                                }
                            }
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    let callback = match this.callback.as_mut() {
                        Some(callback) => callback,
                        None => {
                            this.fut_state = CocoonFsTestUnlinkInodesFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    match CocoonFsTestUnlinkInodesFutureCallback::call(callback, *inode, inode_data) {
                        Ok(unlink_cur_inode) => {
                            if unlink_cur_inode {
                                let unlink_fut = fs::NvFsUnlinkCursor::unlink_current_inode(unlink_cursor);
                                this.fut_state = CocoonFsTestUnlinkInodesFutureState::UnlinkCurrentInode { unlink_fut };
                            } else {
                                let next_fut = fs::NvFsUnlinkCursor::next(unlink_cursor);
                                this.fut_state = CocoonFsTestUnlinkInodesFutureState::Next { next_fut };
                            }
                        }
                        Err(e) => {
                            this.fut_state = CocoonFsTestUnlinkInodesFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                }
                CocoonFsTestUnlinkInodesFutureState::UnlinkCurrentInode { unlink_fut } => {
                    let unlink_cursor = match fs::NvFsFuture::poll(pin::Pin::new(unlink_fut), fs_instance, rng, cx) {
                        task::Poll::Ready(result) => {
                            match result.and_then(|(unlink_cursor, result)| result.map(|_| unlink_cursor)) {
                                Ok(unlink_cursor) => unlink_cursor,
                                Err(e) => {
                                    this.fut_state = CocoonFsTestUnlinkInodesFutureState::Done;
                                    return task::Poll::Ready(Err(e));
                                }
                            }
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    let next_fut = fs::NvFsUnlinkCursor::next(unlink_cursor);
                    this.fut_state = CocoonFsTestUnlinkInodesFutureState::Next { next_fut };
                }
                CocoonFsTestUnlinkInodesFutureState::Done => unreachable!(),
            }
        }
    }
}

mod inode_index;
mod journal_replay;
mod mkfs;
mod write_read;
