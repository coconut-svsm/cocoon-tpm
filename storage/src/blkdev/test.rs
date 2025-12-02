// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`TestNvBlkDev`].

extern crate alloc;
use alloc::vec::Vec;

use crate::blkdev::{self, ChunkedIoRegion, NvBlkDevIoError};
use crate::utils_async::{
    sync_types::{Lock as _, SyncTypes},
    test::TestNopSyncTypes,
};
use crate::utils_common::fixed_vec::FixedVec;
use core::{mem, ops, pin, task};
use ops::{Deref as _, DerefMut as _};

/// In-memory [`NvBlkDev`](blkdev::NvBlkDev) emulation for use with testing.
pub struct TestNvBlkDev {
    io_blocks: <TestNopSyncTypes as SyncTypes>::Lock<Vec<Option<FixedVec<u8, 7>>>>,
    io_block_size_128b_log2: u32,
    preferred_io_blocks_bulk_log2: u32,
}

impl TestNvBlkDev {
    /// Create a new `TestNvBlkDev` instance.
    ///
    /// # Arguments:
    ///
    /// * `io_block_size_128b_log2` - The desired size of a [`Device IO
    ///   Block`](blkdev::NvBlkDev::io_block_size_128b_log2).
    /// * `io_blocks_count` - The desired size of the emulated storage in units
    ///   of Device IO Blocks.
    /// * `preferred_io_blocks_bulk_log2` - [Optimum IO request
    ///   size]((blkdev::NvBlkDev::preferred_io_blocks_bulk_log2).
    pub fn new(io_block_size_128b_log2: u32, io_blocks_count: u64, preferred_io_blocks_bulk_log2: u32) -> Self {
        let mut io_blocks = Vec::new();
        let io_blocks_count = usize::try_from(io_blocks_count).unwrap();
        io_blocks.resize(io_blocks_count, None);
        Self {
            io_blocks: <TestNopSyncTypes as SyncTypes>::Lock::from(io_blocks),
            io_block_size_128b_log2,
            preferred_io_blocks_bulk_log2,
        }
    }

    /// Create a snapshot clone.
    pub fn snapshot(&self) -> Self {
        let io_blocks = self.io_blocks.lock();
        let cloned_io_blocks = io_blocks.clone();
        drop(io_blocks);
        Self {
            io_blocks: <TestNopSyncTypes as SyncTypes>::Lock::from(cloned_io_blocks),
            io_block_size_128b_log2: self.io_block_size_128b_log2,
            preferred_io_blocks_bulk_log2: self.preferred_io_blocks_bulk_log2,
        }
    }

    fn _read_chunked_io_region(
        &self,
        request: &mut dyn blkdev::NvBlkDevReadRequest,
        io_region: ChunkedIoRegion,
        io_blocks_bulk_log2: u32,
    ) -> Result<(), NvBlkDevIoError> {
        let io_blocks = self.io_blocks.lock();
        for (physical_bulk_index, bulk_chunks) in io_region
            .aligned_blocks_iter(io_blocks_bulk_log2 + self.io_block_size_128b_log2)
            .unwrap()
        {
            let bulk_first_io_block_index = match physical_bulk_index.checked_shl(io_blocks_bulk_log2) {
                Some(io_block_index) => io_block_index,
                None => return Err(NvBlkDevIoError::IoBlockOutOfRange),
            };
            let bulk_first_io_block_index = match usize::try_from(bulk_first_io_block_index) {
                Ok(io_block_index) => io_block_index,
                Err(_) => return Err(NvBlkDevIoError::IoBlockOutOfRange),
            };

            for (offset_in_bulk_128b, bulk_chunk_range) in bulk_chunks {
                let dst_bulk_chunk_slice = match request.get_destination_buffer(&bulk_chunk_range)? {
                    Some(dst_bulk_chunk_slice) => dst_bulk_chunk_slice,
                    None => continue,
                };
                let offset_in_bulk_128b = usize::try_from(offset_in_bulk_128b).unwrap();
                let io_block_index_in_bulk = offset_in_bulk_128b >> self.io_block_size_128b_log2;
                let mut io_block_index = match bulk_first_io_block_index.checked_add(io_block_index_in_bulk) {
                    Some(io_block_index) => io_block_index,
                    None => return Err(NvBlkDevIoError::IoBlockOutOfRange),
                };

                let io_block_size_128b = 1usize << self.io_block_size_128b_log2;
                let io_block_size = io_block_size_128b << 7;
                let offset_in_io_block_128b = offset_in_bulk_128b & (io_block_size_128b - 1);
                let mut offset_in_io_block = offset_in_io_block_128b << 7;
                debug_assert!(dst_bulk_chunk_slice.len() <= io_block_size << io_blocks_bulk_log2);
                debug_assert!(
                    dst_bulk_chunk_slice.len() < io_block_size
                        || (dst_bulk_chunk_slice.len() % io_block_size == 0 && offset_in_io_block == 0)
                );
                let mut bytes_copied = 0;
                while bytes_copied < dst_bulk_chunk_slice.len() {
                    if io_block_index >= io_blocks.len() {
                        return Err(NvBlkDevIoError::IoBlockOutOfRange);
                    }
                    let io_block = match io_blocks[io_block_index].as_ref() {
                        Some(io_block) => io_block,
                        None => return Err(NvBlkDevIoError::IoBlockNotMapped),
                    };

                    let bytes_remaining = dst_bulk_chunk_slice.len() - bytes_copied;
                    let bytes_to_copy = bytes_remaining.min(io_block_size - offset_in_io_block);

                    dst_bulk_chunk_slice[bytes_copied..bytes_copied + bytes_to_copy]
                        .copy_from_slice(&io_block[offset_in_io_block..offset_in_io_block + bytes_to_copy]);
                    io_block_index += 1;
                    offset_in_io_block = 0;
                    bytes_copied += bytes_to_copy;
                }
            }
        }
        Ok(())
    }

    fn process_read_request(&self, request: &mut dyn blkdev::NvBlkDevReadRequest) -> Result<(), NvBlkDevIoError> {
        let io_range = request.region();
        let (unaligned_head, aligned_tail) =
            io_range.align_to(self.preferred_io_blocks_bulk_log2 + self.io_block_size_128b_log2);
        self._read_chunked_io_region(request, unaligned_head, 0)?;
        if let Some((aligned, unaligned_tail)) = aligned_tail {
            self._read_chunked_io_region(request, aligned, self.preferred_io_blocks_bulk_log2)?;
            self._read_chunked_io_region(request, unaligned_tail, 0)?;
        }
        Ok(())
    }

    fn _write_chunked_io_region(
        &self,
        request: &dyn blkdev::NvBlkDevWriteRequest,
        io_region: ChunkedIoRegion,
        io_blocks_bulk_log2: u32,
    ) -> Result<(), NvBlkDevIoError> {
        let mut io_blocks = self.io_blocks.lock();
        for (physical_bulk_index, bulk_chunks) in io_region
            .aligned_blocks_iter(io_blocks_bulk_log2 + self.io_block_size_128b_log2)
            .unwrap()
        {
            let bulk_first_io_block_index = match physical_bulk_index.checked_shl(io_blocks_bulk_log2) {
                Some(io_block_index) => io_block_index,
                None => return Err(NvBlkDevIoError::IoBlockOutOfRange),
            };
            let bulk_first_io_block_index = match usize::try_from(bulk_first_io_block_index) {
                Ok(io_block_index) => io_block_index,
                Err(_) => return Err(NvBlkDevIoError::IoBlockOutOfRange),
            };

            for (offset_in_bulk_128b, bulk_chunk_range) in bulk_chunks {
                let src_bulk_chunk_slice = request.get_source_buffer(&bulk_chunk_range)?;
                let offset_in_bulk_128b = usize::try_from(offset_in_bulk_128b).unwrap();
                let io_block_index_in_bulk = offset_in_bulk_128b >> self.io_block_size_128b_log2;
                let mut io_block_index = match bulk_first_io_block_index.checked_add(io_block_index_in_bulk) {
                    Some(io_block_index) => io_block_index,
                    None => return Err(NvBlkDevIoError::IoBlockOutOfRange),
                };

                let io_block_size_128b = 1usize << self.io_block_size_128b_log2;
                let io_block_size = io_block_size_128b << 7;
                let offset_in_io_block_128b = offset_in_bulk_128b & (io_block_size_128b - 1);
                let mut offset_in_io_block = offset_in_io_block_128b << 7;
                debug_assert!(src_bulk_chunk_slice.len() <= io_block_size << io_blocks_bulk_log2);
                debug_assert!(
                    src_bulk_chunk_slice.len() < io_block_size
                        || (src_bulk_chunk_slice.len() % io_block_size == 0 && offset_in_io_block == 0)
                );
                let mut bytes_copied = 0;
                while bytes_copied < src_bulk_chunk_slice.len() {
                    if io_block_index >= io_blocks.len() {
                        return Err(NvBlkDevIoError::IoBlockOutOfRange);
                    }

                    if io_blocks[io_block_index].is_none() {
                        let block_buf = FixedVec::new_with_default(io_block_size).unwrap();
                        io_blocks[io_block_index] = Some(block_buf);
                    }
                    let io_block = io_blocks[io_block_index].as_mut().unwrap();

                    let bytes_remaining = src_bulk_chunk_slice.len() - bytes_copied;
                    let bytes_to_copy = bytes_remaining.min(io_block_size - offset_in_io_block);

                    io_block[offset_in_io_block..offset_in_io_block + bytes_to_copy]
                        .copy_from_slice(&src_bulk_chunk_slice[bytes_copied..bytes_copied + bytes_to_copy]);
                    io_block_index += 1;
                    offset_in_io_block = 0;
                    bytes_copied += bytes_to_copy;
                }
            }
        }
        Ok(())
    }

    fn process_write_request(&self, request: &dyn blkdev::NvBlkDevWriteRequest) -> Result<(), NvBlkDevIoError> {
        let io_range = request.region();
        let (unaligned_head, aligned_tail) =
            io_range.align_to(self.preferred_io_blocks_bulk_log2 + self.io_block_size_128b_log2);
        self._write_chunked_io_region(request, unaligned_head, 0)?;
        if let Some((aligned, unaligned_tail)) = aligned_tail {
            self._write_chunked_io_region(request, aligned, self.preferred_io_blocks_bulk_log2)?;
            self._write_chunked_io_region(request, unaligned_tail, 0)?;
        }
        Ok(())
    }
}

impl blkdev::NvBlkDev for TestNvBlkDev {
    fn io_block_size_128b_log2(&self) -> u32 {
        self.io_block_size_128b_log2
    }

    fn io_blocks(&self) -> u64 {
        u64::try_from(self.io_blocks.lock().len()).unwrap()
    }

    fn preferred_io_blocks_bulk_log2(&self) -> u32 {
        self.preferred_io_blocks_bulk_log2
    }

    type ResizeFuture = TestNvBlkDevResizeFuture;
    fn resize(&self, io_blocks_count: u64) -> Result<Self::ResizeFuture, NvBlkDevIoError> {
        Ok(TestNvBlkDevResizeFuture::Init { io_blocks_count })
    }

    type ReadFuture<R: blkdev::NvBlkDevReadRequest> = TestNvBlkDevReadFuture<R>;
    fn read<R: blkdev::NvBlkDevReadRequest>(
        &self,
        request: R,
    ) -> Result<Result<Self::ReadFuture<R>, (R, NvBlkDevIoError)>, NvBlkDevIoError> {
        Ok(Ok(TestNvBlkDevReadFuture::Init { request }))
    }

    type WriteFuture<R: blkdev::NvBlkDevWriteRequest> = TestNvBlkDevWriteFuture<R>;
    fn write<R: blkdev::NvBlkDevWriteRequest>(
        &self,
        request: R,
    ) -> Result<Result<Self::WriteFuture<R>, (R, NvBlkDevIoError)>, NvBlkDevIoError> {
        Ok(Ok(TestNvBlkDevWriteFuture::Init { request }))
    }

    type WriteBarrierFuture = TestNvBlkDevWriteSyncFuture;
    fn write_barrier(&self) -> Result<Self::WriteBarrierFuture, NvBlkDevIoError> {
        Ok(TestNvBlkDevWriteSyncFuture::Init)
    }

    type WriteSyncFuture = TestNvBlkDevWriteSyncFuture;
    fn write_sync(&self) -> Result<Self::WriteSyncFuture, NvBlkDevIoError> {
        Ok(TestNvBlkDevWriteSyncFuture::Init)
    }

    type TrimFuture = TestNvBlkDevTrimFuture;
    fn trim(&self, io_block_index: u64, io_blocks_count: u64) -> Result<Self::TrimFuture, NvBlkDevIoError> {
        let io_blocks_count = usize::try_from(io_blocks_count).map_err(|_| NvBlkDevIoError::IoBlockOutOfRange)?;
        Ok(TestNvBlkDevTrimFuture::Init {
            io_block_index,
            io_blocks_count,
        })
    }
}

/// [`NvBlkDev::ResizeFuture`](blkdev::NvBlkDev::ResizeFuture) type for the
/// [`TestNvBlkDev`] implementation.
pub enum TestNvBlkDevResizeFuture {
    Init { io_blocks_count: u64 },
    PolledOnce { io_blocks_count: u64 },
    Done,
}

impl Unpin for TestNvBlkDevResizeFuture {}

impl blkdev::NvBlkDevFuture<TestNvBlkDev> for TestNvBlkDevResizeFuture {
    type Output = Result<(), NvBlkDevIoError>;

    fn poll(mut self: pin::Pin<&mut Self>, dev: &TestNvBlkDev, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        match self.deref_mut() {
            Self::Init { io_blocks_count } => {
                *self = Self::PolledOnce {
                    io_blocks_count: *io_blocks_count,
                };
                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
            Self::PolledOnce { io_blocks_count } => {
                let mut io_blocks = dev.io_blocks.lock();
                let io_blocks_count = usize::try_from(*io_blocks_count).unwrap();
                io_blocks.resize(io_blocks_count, None);
                drop(io_blocks);
                *self = Self::Done;
                task::Poll::Ready(Ok(()))
            }
            Self::Done => {
                unreachable!("Attempt to poll completed future.")
            }
        }
    }
}

/// [`NvBlkDev::ReadFuture`](blkdev::NvBlkDev::ReadFuture) type for the
/// [`TestNvBlkDev`] implementation.
pub enum TestNvBlkDevReadFuture<R: blkdev::NvBlkDevReadRequest> {
    Init { request: R },
    PolledOnce { request: R },
    Done,
}

impl<R: blkdev::NvBlkDevReadRequest> Unpin for TestNvBlkDevReadFuture<R> {}

impl<R: blkdev::NvBlkDevReadRequest> blkdev::NvBlkDevFuture<TestNvBlkDev> for TestNvBlkDevReadFuture<R> {
    type Output = Result<(R, Result<(), NvBlkDevIoError>), NvBlkDevIoError>;

    fn poll(mut self: pin::Pin<&mut Self>, dev: &TestNvBlkDev, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = mem::replace(self.deref_mut(), Self::Done);
        match this {
            Self::Init { request } => {
                *self = Self::PolledOnce { request };
                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
            Self::PolledOnce { mut request } => {
                let result = dev.process_read_request(&mut request);
                task::Poll::Ready(Ok((request, result)))
            }
            Self::Done => {
                unreachable!("Attempt to poll completed future.")
            }
        }
    }
}

/// [`NvBlkDev::WriteFuture`](blkdev::NvBlkDev::WriteFuture) type for the
/// [`TestNvBlkDev`] implementation.
pub enum TestNvBlkDevWriteFuture<R: blkdev::NvBlkDevWriteRequest> {
    Init { request: R },
    PolledOnce { request: R },
    Done,
}

impl<R: blkdev::NvBlkDevWriteRequest> Unpin for TestNvBlkDevWriteFuture<R> {}

impl<R: blkdev::NvBlkDevWriteRequest> blkdev::NvBlkDevFuture<TestNvBlkDev> for TestNvBlkDevWriteFuture<R> {
    type Output = Result<(R, Result<(), NvBlkDevIoError>), NvBlkDevIoError>;

    fn poll(mut self: pin::Pin<&mut Self>, dev: &TestNvBlkDev, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = mem::replace(self.deref_mut(), Self::Done);
        match this {
            Self::Init { request } => {
                *self = Self::PolledOnce { request };
                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
            Self::PolledOnce { request } => {
                let result = dev.process_write_request(&request);
                task::Poll::Ready(Ok((request, result)))
            }
            Self::Done => {
                unreachable!("Attempt to poll completed future.")
            }
        }
    }
}

/// [`NvBlkDev::WriteSyncFuture`](blkdev::NvBlkDev::WriteSyncFuture) type for
/// the [`TestNvBlkDev`] implementation.
pub enum TestNvBlkDevWriteSyncFuture {
    Init,
    PolledOnce,
    Done,
}

impl Unpin for TestNvBlkDevWriteSyncFuture {}

impl blkdev::NvBlkDevFuture<TestNvBlkDev> for TestNvBlkDevWriteSyncFuture {
    type Output = Result<(), NvBlkDevIoError>;

    fn poll(
        mut self: pin::Pin<&mut Self>,
        _dev: &TestNvBlkDev,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        match self.deref() {
            Self::Init => {
                *self = Self::PolledOnce;
                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
            Self::PolledOnce => {
                *self = Self::Done;
                task::Poll::Ready(Ok(()))
            }
            Self::Done => {
                unreachable!("Attempt to poll completed future.")
            }
        }
    }
}

/// [`NvBlkDev::TrimFuture`](blkdev::NvBlkDev::TrimFuture) type for the
/// [`TestNvBlkDev`] implementation.
pub enum TestNvBlkDevTrimFuture {
    Init {
        io_block_index: u64,
        io_blocks_count: usize,
    },
    PolledOnce {
        io_block_index: u64,
        io_blocks_count: usize,
    },
    Done,
}

impl Unpin for TestNvBlkDevTrimFuture {}

impl blkdev::NvBlkDevFuture<TestNvBlkDev> for TestNvBlkDevTrimFuture {
    type Output = Result<(), NvBlkDevIoError>;

    fn poll(mut self: pin::Pin<&mut Self>, dev: &TestNvBlkDev, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        match self.deref_mut() {
            Self::Init {
                io_block_index,
                io_blocks_count,
            } => {
                *self = Self::PolledOnce {
                    io_block_index: *io_block_index,
                    io_blocks_count: *io_blocks_count,
                };
                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
            Self::PolledOnce {
                io_block_index,
                io_blocks_count,
            } => {
                let io_block_index = usize::try_from(*io_block_index).unwrap();
                let end_io_block_index = io_block_index.checked_add(*io_blocks_count).unwrap();
                let mut io_blocks = dev.io_blocks.lock();
                if io_blocks.len() < end_io_block_index {
                    return task::Poll::Ready(Err(NvBlkDevIoError::IoBlockOutOfRange));
                }
                for block in io_blocks.iter_mut().skip(io_block_index).take(*io_blocks_count) {
                    *block = None;
                }
                drop(io_blocks);
                *self = Self::Done;
                task::Poll::Ready(Ok(()))
            }
            Self::Done => {
                unreachable!("Attempt to poll completed future.")
            }
        }
    }
}

#[cfg(test)]
use crate::utils_async::sync_types;
#[cfg(test)]
use core::future;

#[cfg(test)]
type TestSyncRcPtrFactory = <TestNopSyncTypes as sync_types::SyncTypes>::SyncRcPtrFactory;

#[cfg(test)]
type TestNvBlkDevSyncRcPtr = <TestSyncRcPtrFactory as sync_types::SyncRcPtrFactory>::SyncRcPtr<TestNvBlkDev>;

#[cfg(test)]
struct TestNvBlkDevFuture<F: blkdev::NvBlkDevFuture<TestNvBlkDev>> {
    dev: TestNvBlkDevSyncRcPtr,
    dev_fut: F,
}

#[cfg(test)]
impl<F: blkdev::NvBlkDevFuture<TestNvBlkDev>> TestNvBlkDevFuture<F> {
    fn new(dev: TestNvBlkDevSyncRcPtr, dev_fut: F) -> Self {
        Self { dev, dev_fut }
    }
}

#[cfg(test)]
impl<F: blkdev::NvBlkDevFuture<TestNvBlkDev>> future::Future for TestNvBlkDevFuture<F> {
    type Output = F::Output;

    fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        // Safe, inner_fut will get projection-pinned right below.
        let this = unsafe { pin::Pin::into_inner_unchecked(self) };
        // Safe, it's a projection pin.
        let dev_fut = unsafe { pin::Pin::new_unchecked(&mut this.dev_fut) };
        F::poll(dev_fut, &this.dev, cx)
    }
}

#[test]
fn test_nv_blkdev_rw() {
    use crate::blkdev::ChunkedIoRegionChunkRange;

    #[derive(PartialEq, Eq, Debug)]
    struct TestRwRequest {
        region: ChunkedIoRegion,
        level0_child_count_log2: u32,
        level1_child_count_log2: u32,
        buffers: FixedVec<FixedVec<FixedVec<FixedVec<u8, 7>, 0>, 0>, 0>,
    }

    impl TestRwRequest {
        fn new(
            chunk_size_128b_log2: u32,
            level0_child_count_log2: u32,
            level1_child_count_log2: u32,
            level2_child_count: usize,
            physical_begin_chunk: u64,
        ) -> Self {
            let physical_begin_128b = physical_begin_chunk << chunk_size_128b_log2;
            let region_size_128b =
                level2_child_count << (chunk_size_128b_log2 + level0_child_count_log2 + level1_child_count_log2);
            let physical_end_128b = physical_begin_128b + region_size_128b as u64;
            let region = ChunkedIoRegion::new(physical_begin_128b, physical_end_128b, chunk_size_128b_log2).unwrap();
            let mut buffers = FixedVec::new_with_default(level2_child_count).unwrap();
            for l2_child in buffers.iter_mut() {
                let mut level1_childs = FixedVec::new_with_default(1usize << level1_child_count_log2).unwrap();
                for l1_child in level1_childs.iter_mut() {
                    let mut level0_childs = FixedVec::new_with_default(1usize << level0_child_count_log2).unwrap();
                    for l0_child in level0_childs.iter_mut() {
                        *l0_child = FixedVec::new_with_default(1usize << (chunk_size_128b_log2 + 7)).unwrap();
                    }
                    *l1_child = level0_childs;
                }
                *l2_child = level1_childs;
            }

            Self {
                region,
                level0_child_count_log2,
                level1_child_count_log2,
                buffers,
            }
        }

        fn fill_buffers_with<F: FnMut() -> u32>(&mut self, fill_fn: &mut F) {
            for l2 in 0..self.buffers.len() {
                for l1 in 0..(1usize << self.level1_child_count_log2) {
                    for l0 in 0..(1usize << self.level0_child_count_log2) {
                        let chunk = &mut self.buffers[l2][l1][l0];
                        for v in chunk.chunks_mut(4) {
                            let fill_value = fill_fn();
                            v.copy_from_slice(&fill_value.to_le_bytes());
                        }
                    }
                }
            }
        }
    }

    impl blkdev::NvBlkDevReadRequest for TestRwRequest {
        fn region(&self) -> &ChunkedIoRegion {
            &self.region
        }

        fn get_destination_buffer(
            &mut self,
            range: &ChunkedIoRegionChunkRange,
        ) -> Result<Option<&mut [u8]>, NvBlkDevIoError> {
            let chunk = range.chunk();
            let (l2, [l1, l0]) =
                chunk.decompose_to_hierarchic_indices([self.level1_child_count_log2, self.level0_child_count_log2]);
            Ok(Some(&mut self.buffers[l2][l1][l0][range.range_in_chunk().clone()]))
        }
    }

    impl blkdev::NvBlkDevWriteRequest for TestRwRequest {
        fn region(&self) -> &ChunkedIoRegion {
            &self.region
        }

        fn get_source_buffer(&self, range: &ChunkedIoRegionChunkRange) -> Result<&[u8], NvBlkDevIoError> {
            let chunk = range.chunk();
            let (l2, [l1, l0]) =
                chunk.decompose_to_hierarchic_indices([self.level1_child_count_log2, self.level0_child_count_log2]);
            Ok(&self.buffers[l2][l1][l0][range.range_in_chunk().clone()])
        }
    }

    fn test_one(
        io_block_size_128b_log2: u32,
        preferred_io_blocks_bulk_log2: u32,
        request_chunk_size_128b_log2: u32,
        request_level0_child_count_log2: u32,
        request_level1_child_count_log2: u32,
        request_level2_child_count: usize,
    ) {
        use crate::utils_async::test::TestAsyncExecutor;
        use blkdev::NvBlkDev as _;

        let request_physical_begin_chunk =
            1 << (io_block_size_128b_log2 - request_chunk_size_128b_log2.min(io_block_size_128b_log2));
        let request_size_128b = (request_level2_child_count as u64)
            << (request_chunk_size_128b_log2 + request_level0_child_count_log2 + request_level1_child_count_log2);
        let physical_end_128b = (request_physical_begin_chunk << request_chunk_size_128b_log2) + request_size_128b;
        let io_block_size_128b = 1 << io_block_size_128b_log2;
        let io_blocks_count = (physical_end_128b + (io_block_size_128b - 1)) >> io_block_size_128b_log2;
        let dev = <TestSyncRcPtrFactory as sync_types::SyncRcPtrFactory>::try_new(TestNvBlkDev::new(
            io_block_size_128b_log2,
            io_blocks_count,
            preferred_io_blocks_bulk_log2,
        ))
        .unwrap();

        let mut write_request = TestRwRequest::new(
            request_chunk_size_128b_log2,
            request_level0_child_count_log2,
            request_level1_child_count_log2,
            request_level2_child_count,
            request_physical_begin_chunk,
        );
        let mut fill_value: u32 = 0;
        write_request.fill_buffers_with(&mut || {
            fill_value += 1;
            fill_value
        });

        let e = TestAsyncExecutor::new();
        let write_task = TestAsyncExecutor::spawn(
            &e,
            TestNvBlkDevFuture::new(
                dev.clone(),
                dev.write(write_request).and_then(|r| r.map_err(|(_, e)| e)).unwrap(),
            ),
        );
        TestAsyncExecutor::run_to_completion(&e);
        let (write_request, result) = write_task.take().unwrap().unwrap();
        result.unwrap();

        let read_request = TestRwRequest::new(
            request_chunk_size_128b_log2,
            request_level0_child_count_log2,
            request_level1_child_count_log2,
            request_level2_child_count,
            request_physical_begin_chunk,
        );
        let read_task = TestAsyncExecutor::spawn(
            &e,
            TestNvBlkDevFuture::new(
                dev.clone(),
                dev.read(read_request).and_then(|r| r.map_err(|(_, e)| e)).unwrap(),
            ),
        );
        TestAsyncExecutor::run_to_completion(&e);
        let (read_request, result) = read_task.take().unwrap().unwrap();
        result.unwrap();

        assert_eq!(read_request, write_request);
    }

    test_one(0, 0, 0, 0, 0, 1);
    test_one(0, 0, 1, 0, 0, 1);

    test_one(0, 0, 0, 1, 1, 3);
    test_one(0, 0, 1, 1, 1, 3);
    test_one(0, 1, 0, 1, 1, 3);
    test_one(0, 1, 1, 1, 1, 3);
    test_one(0, 1, 2, 1, 1, 3);
    test_one(0, 2, 1, 1, 1, 3);

    test_one(0, 0, 0, 0, 1, 2 * 3);
    test_one(0, 0, 1, 0, 1, 2 * 3);
    test_one(0, 1, 0, 0, 1, 2 * 3);
    test_one(0, 1, 1, 0, 1, 2 * 3);
    test_one(0, 1, 2, 0, 1, 2 * 3);
    test_one(0, 2, 1, 0, 1, 2 * 3);

    test_one(0, 0, 0, 1, 0, 2 * 3);
    test_one(0, 0, 1, 1, 0, 2 * 3);
    test_one(0, 1, 0, 1, 0, 2 * 3);
    test_one(0, 1, 1, 1, 0, 2 * 3);
    test_one(0, 1, 2, 1, 0, 2 * 3);
    test_one(0, 2, 1, 1, 0, 2 * 3);

    test_one(0, 0, 0, 0, 0, 2 * 2 * 3);
    test_one(0, 0, 1, 0, 0, 2 * 2 * 3);
    test_one(0, 1, 0, 0, 0, 2 * 2 * 3);
    test_one(0, 1, 1, 0, 0, 2 * 2 * 3);
    test_one(0, 1, 2, 0, 0, 2 * 2 * 3);
    test_one(0, 2, 1, 0, 0, 2 * 2 * 3);

    test_one(0, 0, 0, 2, 0, 3);
    test_one(0, 0, 1, 2, 0, 3);
    test_one(0, 1, 0, 2, 0, 3);
    test_one(0, 1, 1, 2, 0, 3);
    test_one(0, 1, 2, 2, 0, 3);
    test_one(0, 2, 1, 2, 0, 3);

    test_one(0, 0, 0, 0, 2, 3);
    test_one(0, 0, 1, 0, 2, 3);
    test_one(0, 1, 0, 0, 2, 3);
    test_one(0, 1, 1, 0, 2, 3);
    test_one(0, 1, 2, 0, 2, 3);
    test_one(0, 2, 1, 0, 2, 3);

    test_one(1, 0, 0, 0, 0, 2);
    test_one(1, 0, 0, 1, 1, 3);
    test_one(1, 1, 0, 1, 1, 3);
    test_one(1, 2, 0, 1, 1, 3);
}
