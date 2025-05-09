// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`TestNvChip`].

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::chip::{self, ChunkedIoRegion, NvChipIoError};
use crate::utils_async::{
    sync_types::{Lock as _, SyncTypes},
    test::TestNopSyncTypes,
};
use core::{mem, ops, pin, task};
use ops::{Deref as _, DerefMut as _};

/// In-memory [`NvChip`](chip::NvChip) emulation for use with testing.
pub struct TestNvChip {
    chip_io_blocks: <TestNopSyncTypes as SyncTypes>::Lock<Vec<Option<Vec<u8>>>>,
    chip_io_block_size_128b_log2: u32,
    preferred_chip_io_blocks_bulk_log2: u32,
}

impl TestNvChip {
    /// Create a new `TestNvChip` instance.
    ///
    /// # Arguments:
    ///
    /// * `chip_io_block_size_128b_log2`: The desired size of a [`Chip IO
    ///   Block`](chip::NvChip::chip_io_block_size_128b_log2).
    /// * `chip_io_blocks_count`: The desired size of the emulated storage in
    ///   units of Chip IO Blocks.
    /// * `preferred_chip_io_blocks_bulk_log2` - [Optimum IO request
    ///   size]((chip::NvChip::preferred_chip_io_blocks_bulk_log2).
    pub fn new(
        chip_io_block_size_128b_log2: u32,
        chip_io_blocks_count: u64,
        preferred_chip_io_blocks_bulk_log2: u32,
    ) -> Self {
        let mut chip_io_blocks = Vec::new();
        let chip_io_blocks_count = usize::try_from(chip_io_blocks_count).unwrap();
        chip_io_blocks.resize(chip_io_blocks_count, None);
        Self {
            chip_io_blocks: <TestNopSyncTypes as SyncTypes>::Lock::from(chip_io_blocks),
            chip_io_block_size_128b_log2,
            preferred_chip_io_blocks_bulk_log2,
        }
    }

    /// Create a snapshot clone.
    pub fn snapshot(&self) -> Self {
        let chip_io_blocks = self.chip_io_blocks.lock();
        let cloned_chip_io_blocks = chip_io_blocks.clone();
        drop(chip_io_blocks);
        Self {
            chip_io_blocks: <TestNopSyncTypes as SyncTypes>::Lock::from(cloned_chip_io_blocks),
            chip_io_block_size_128b_log2: self.chip_io_block_size_128b_log2,
            preferred_chip_io_blocks_bulk_log2: self.preferred_chip_io_blocks_bulk_log2,
        }
    }

    fn _read_chunked_io_region(
        &self,
        request: &mut dyn chip::NvChipReadRequest,
        io_region: ChunkedIoRegion,
        chip_io_blocks_bulk_log2: u32,
    ) -> Result<(), NvChipIoError> {
        let chip_io_blocks = self.chip_io_blocks.lock();
        for (physical_bulk_index, bulk_chunks) in io_region
            .aligned_blocks_iter(chip_io_blocks_bulk_log2 + self.chip_io_block_size_128b_log2)
            .unwrap()
        {
            let bulk_first_chip_io_block_index = match physical_bulk_index.checked_shl(chip_io_blocks_bulk_log2) {
                Some(chip_io_block_index) => chip_io_block_index,
                None => return Err(NvChipIoError::IoBlockOutOfRange),
            };
            let bulk_first_chip_io_block_index = match usize::try_from(bulk_first_chip_io_block_index) {
                Ok(chip_io_block_index) => chip_io_block_index,
                Err(_) => return Err(NvChipIoError::IoBlockOutOfRange),
            };

            for (offset_in_bulk_128b, bulk_chunk_range) in bulk_chunks {
                let dst_bulk_chunk_slice = match request.get_destination_buffer(&bulk_chunk_range)? {
                    Some(dst_bulk_chunk_slice) => dst_bulk_chunk_slice,
                    None => continue,
                };
                let offset_in_bulk_128b = usize::try_from(offset_in_bulk_128b).unwrap();
                let chip_io_block_index_in_bulk = offset_in_bulk_128b >> self.chip_io_block_size_128b_log2;
                let mut chip_io_block_index =
                    match bulk_first_chip_io_block_index.checked_add(chip_io_block_index_in_bulk) {
                        Some(chip_io_block_index) => chip_io_block_index,
                        None => return Err(NvChipIoError::IoBlockOutOfRange),
                    };

                let chip_io_block_size_128b = 1usize << self.chip_io_block_size_128b_log2;
                let chip_io_block_size = chip_io_block_size_128b << 7;
                let offset_in_chip_io_block_128b = offset_in_bulk_128b & (chip_io_block_size_128b - 1);
                let mut offset_in_chip_io_block = offset_in_chip_io_block_128b << 7;
                debug_assert!(dst_bulk_chunk_slice.len() <= chip_io_block_size << chip_io_blocks_bulk_log2);
                debug_assert!(
                    dst_bulk_chunk_slice.len() < chip_io_block_size
                        || (dst_bulk_chunk_slice.len() % chip_io_block_size == 0 && offset_in_chip_io_block == 0)
                );
                let mut bytes_copied = 0;
                while bytes_copied < dst_bulk_chunk_slice.len() {
                    if chip_io_block_index >= chip_io_blocks.len() {
                        return Err(NvChipIoError::IoBlockOutOfRange);
                    }
                    let chip_io_block = match chip_io_blocks[chip_io_block_index].as_ref() {
                        Some(chip_io_block) => chip_io_block,
                        None => return Err(NvChipIoError::IoBlockNotMapped),
                    };

                    let bytes_remaining = dst_bulk_chunk_slice.len() - bytes_copied;
                    let bytes_to_copy = bytes_remaining.min(chip_io_block_size - offset_in_chip_io_block);

                    dst_bulk_chunk_slice[bytes_copied..bytes_copied + bytes_to_copy].copy_from_slice(
                        &chip_io_block[offset_in_chip_io_block..offset_in_chip_io_block + bytes_to_copy],
                    );
                    chip_io_block_index += 1;
                    offset_in_chip_io_block = 0;
                    bytes_copied += bytes_to_copy;
                }
            }
        }
        Ok(())
    }

    fn process_read_request(&self, request: &mut dyn chip::NvChipReadRequest) -> Result<(), NvChipIoError> {
        let io_range = request.region();
        let (unaligned_head, aligned_tail) =
            io_range.align_to(self.preferred_chip_io_blocks_bulk_log2 + self.chip_io_block_size_128b_log2);
        self._read_chunked_io_region(request, unaligned_head, 0)?;
        if let Some((aligned, unaligned_tail)) = aligned_tail {
            self._read_chunked_io_region(request, aligned, self.preferred_chip_io_blocks_bulk_log2)?;
            self._read_chunked_io_region(request, unaligned_tail, 0)?;
        }
        Ok(())
    }

    fn _write_chunked_io_region(
        &self,
        request: &dyn chip::NvChipWriteRequest,
        io_region: ChunkedIoRegion,
        chip_io_blocks_bulk_log2: u32,
    ) -> Result<(), NvChipIoError> {
        let mut chip_io_blocks = self.chip_io_blocks.lock();
        for (physical_bulk_index, bulk_chunks) in io_region
            .aligned_blocks_iter(chip_io_blocks_bulk_log2 + self.chip_io_block_size_128b_log2)
            .unwrap()
        {
            let bulk_first_chip_io_block_index = match physical_bulk_index.checked_shl(chip_io_blocks_bulk_log2) {
                Some(chip_io_block_index) => chip_io_block_index,
                None => return Err(NvChipIoError::IoBlockOutOfRange),
            };
            let bulk_first_chip_io_block_index = match usize::try_from(bulk_first_chip_io_block_index) {
                Ok(chip_io_block_index) => chip_io_block_index,
                Err(_) => return Err(NvChipIoError::IoBlockOutOfRange),
            };

            for (offset_in_bulk_128b, bulk_chunk_range) in bulk_chunks {
                let src_bulk_chunk_slice = request.get_source_buffer(&bulk_chunk_range)?;
                let offset_in_bulk_128b = usize::try_from(offset_in_bulk_128b).unwrap();
                let chip_io_block_index_in_bulk = offset_in_bulk_128b >> self.chip_io_block_size_128b_log2;
                let mut chip_io_block_index =
                    match bulk_first_chip_io_block_index.checked_add(chip_io_block_index_in_bulk) {
                        Some(chip_io_block_index) => chip_io_block_index,
                        None => return Err(NvChipIoError::IoBlockOutOfRange),
                    };

                let chip_io_block_size_128b = 1usize << self.chip_io_block_size_128b_log2;
                let chip_io_block_size = chip_io_block_size_128b << 7;
                let offset_in_chip_io_block_128b = offset_in_bulk_128b & (chip_io_block_size_128b - 1);
                let mut offset_in_chip_io_block = offset_in_chip_io_block_128b << 7;
                debug_assert!(src_bulk_chunk_slice.len() <= chip_io_block_size << chip_io_blocks_bulk_log2);
                debug_assert!(
                    src_bulk_chunk_slice.len() < chip_io_block_size
                        || (src_bulk_chunk_slice.len() % chip_io_block_size == 0 && offset_in_chip_io_block == 0)
                );
                let mut bytes_copied = 0;
                while bytes_copied < src_bulk_chunk_slice.len() {
                    if chip_io_block_index >= chip_io_blocks.len() {
                        return Err(NvChipIoError::IoBlockOutOfRange);
                    }

                    if chip_io_blocks[chip_io_block_index].is_none() {
                        let block_buf = vec![0; chip_io_block_size];
                        chip_io_blocks[chip_io_block_index] = Some(block_buf);
                    }
                    let chip_io_block = chip_io_blocks[chip_io_block_index].as_mut().unwrap();

                    let bytes_remaining = src_bulk_chunk_slice.len() - bytes_copied;
                    let bytes_to_copy = bytes_remaining.min(chip_io_block_size - offset_in_chip_io_block);

                    chip_io_block[offset_in_chip_io_block..offset_in_chip_io_block + bytes_to_copy]
                        .copy_from_slice(&src_bulk_chunk_slice[bytes_copied..bytes_copied + bytes_to_copy]);
                    chip_io_block_index += 1;
                    offset_in_chip_io_block = 0;
                    bytes_copied += bytes_to_copy;
                }
            }
        }
        Ok(())
    }

    fn process_write_request(&self, request: &dyn chip::NvChipWriteRequest) -> Result<(), NvChipIoError> {
        let io_range = request.region();
        let (unaligned_head, aligned_tail) =
            io_range.align_to(self.preferred_chip_io_blocks_bulk_log2 + self.chip_io_block_size_128b_log2);
        self._write_chunked_io_region(request, unaligned_head, 0)?;
        if let Some((aligned, unaligned_tail)) = aligned_tail {
            self._write_chunked_io_region(request, aligned, self.preferred_chip_io_blocks_bulk_log2)?;
            self._write_chunked_io_region(request, unaligned_tail, 0)?;
        }
        Ok(())
    }
}

impl chip::NvChip for TestNvChip {
    fn chip_io_block_size_128b_log2(&self) -> u32 {
        self.chip_io_block_size_128b_log2
    }

    fn chip_io_blocks(&self) -> u64 {
        u64::try_from(self.chip_io_blocks.lock().len()).unwrap()
    }

    fn preferred_chip_io_blocks_bulk_log2(&self) -> u32 {
        self.preferred_chip_io_blocks_bulk_log2
    }

    type ResizeFuture = TestNvChipResizeFuture;
    fn resize(&self, chip_io_blocks_count: u64) -> Result<Self::ResizeFuture, NvChipIoError> {
        Ok(TestNvChipResizeFuture::Init { chip_io_blocks_count })
    }

    type ReadFuture<R: chip::NvChipReadRequest> = TestNvChipReadFuture<R>;
    fn read<R: chip::NvChipReadRequest>(
        &self,
        request: R,
    ) -> Result<Result<Self::ReadFuture<R>, (R, NvChipIoError)>, NvChipIoError> {
        Ok(Ok(TestNvChipReadFuture::Init { request }))
    }

    type WriteFuture<R: chip::NvChipWriteRequest> = TestNvChipWriteFuture<R>;
    fn write<R: chip::NvChipWriteRequest>(
        &self,
        request: R,
    ) -> Result<Result<Self::WriteFuture<R>, (R, NvChipIoError)>, NvChipIoError> {
        Ok(Ok(TestNvChipWriteFuture::Init { request }))
    }

    type WriteBarrierFuture = TestNvChipWriteSyncFuture;
    fn write_barrier(&self) -> Result<Self::WriteBarrierFuture, NvChipIoError> {
        Ok(TestNvChipWriteSyncFuture::Init)
    }

    type WriteSyncFuture = TestNvChipWriteSyncFuture;
    fn write_sync(&self) -> Result<Self::WriteSyncFuture, NvChipIoError> {
        Ok(TestNvChipWriteSyncFuture::Init)
    }

    type TrimFuture = TestNvChipTrimFuture;
    fn trim(&self, chip_io_block_index: u64, chip_io_blocks_count: u64) -> Result<Self::TrimFuture, NvChipIoError> {
        let chip_io_blocks_count =
            usize::try_from(chip_io_blocks_count).map_err(|_| NvChipIoError::IoBlockOutOfRange)?;
        Ok(TestNvChipTrimFuture::Init {
            chip_io_block_index,
            chip_io_blocks_count,
        })
    }
}

/// [`NvChip::ResizeFuture`](chip::NvChip::ResizeFuture) type for the
/// [`TestNvChip`] implementation.
pub enum TestNvChipResizeFuture {
    Init { chip_io_blocks_count: u64 },
    PolledOnce { chip_io_blocks_count: u64 },
    Done,
}

impl Unpin for TestNvChipResizeFuture {}

impl chip::NvChipFuture<TestNvChip> for TestNvChipResizeFuture {
    type Output = Result<(), NvChipIoError>;

    fn poll(mut self: pin::Pin<&mut Self>, chip: &TestNvChip, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        match self.deref_mut() {
            Self::Init { chip_io_blocks_count } => {
                *self = Self::PolledOnce {
                    chip_io_blocks_count: *chip_io_blocks_count,
                };
                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
            Self::PolledOnce { chip_io_blocks_count } => {
                let mut chip_io_blocks = chip.chip_io_blocks.lock();
                let chip_io_blocks_count = usize::try_from(*chip_io_blocks_count).unwrap();
                chip_io_blocks.resize(chip_io_blocks_count, None);
                drop(chip_io_blocks);
                *self = Self::Done;
                task::Poll::Ready(Ok(()))
            }
            Self::Done => {
                unreachable!("Attempt to poll completed future.")
            }
        }
    }
}

/// [`NvChip::ReadFuture`](chip::NvChip::ReadFuture) type for the [`TestNvChip`]
/// implementation.
pub enum TestNvChipReadFuture<R: chip::NvChipReadRequest> {
    Init { request: R },
    PolledOnce { request: R },
    Done,
}

impl<R: chip::NvChipReadRequest> Unpin for TestNvChipReadFuture<R> {}

impl<R: chip::NvChipReadRequest> chip::NvChipFuture<TestNvChip> for TestNvChipReadFuture<R> {
    type Output = Result<(R, Result<(), NvChipIoError>), NvChipIoError>;

    fn poll(mut self: pin::Pin<&mut Self>, chip: &TestNvChip, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = mem::replace(self.deref_mut(), Self::Done);
        match this {
            Self::Init { request } => {
                *self = Self::PolledOnce { request };
                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
            Self::PolledOnce { mut request } => {
                let result = chip.process_read_request(&mut request);
                task::Poll::Ready(Ok((request, result)))
            }
            Self::Done => {
                unreachable!("Attempt to poll completed future.")
            }
        }
    }
}

/// [`NvChip::WriteFuture`](chip::NvChip::WriteFuture) type for the
/// [`TestNvChip`] implementation.
pub enum TestNvChipWriteFuture<R: chip::NvChipWriteRequest> {
    Init { request: R },
    PolledOnce { request: R },
    Done,
}

impl<R: chip::NvChipWriteRequest> Unpin for TestNvChipWriteFuture<R> {}

impl<R: chip::NvChipWriteRequest> chip::NvChipFuture<TestNvChip> for TestNvChipWriteFuture<R> {
    type Output = Result<(R, Result<(), NvChipIoError>), NvChipIoError>;

    fn poll(mut self: pin::Pin<&mut Self>, chip: &TestNvChip, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = mem::replace(self.deref_mut(), Self::Done);
        match this {
            Self::Init { request } => {
                *self = Self::PolledOnce { request };
                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
            Self::PolledOnce { request } => {
                let result = chip.process_write_request(&request);
                task::Poll::Ready(Ok((request, result)))
            }
            Self::Done => {
                unreachable!("Attempt to poll completed future.")
            }
        }
    }
}

/// [`NvChip::WriteSyncFuture`](chip::NvChip::WriteSyncFuture) type for the
/// [`TestNvChip`] implementation.
pub enum TestNvChipWriteSyncFuture {
    Init,
    PolledOnce,
    Done,
}

impl Unpin for TestNvChipWriteSyncFuture {}

impl chip::NvChipFuture<TestNvChip> for TestNvChipWriteSyncFuture {
    type Output = Result<(), NvChipIoError>;

    fn poll(mut self: pin::Pin<&mut Self>, _chip: &TestNvChip, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
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

/// [`NvChip::TrimFuture`](chip::NvChip::TrimFuture) type for the [`TestNvChip`]
/// implementation.
pub enum TestNvChipTrimFuture {
    Init {
        chip_io_block_index: u64,
        chip_io_blocks_count: usize,
    },
    PolledOnce {
        chip_io_block_index: u64,
        chip_io_blocks_count: usize,
    },
    Done,
}

impl Unpin for TestNvChipTrimFuture {}

impl chip::NvChipFuture<TestNvChip> for TestNvChipTrimFuture {
    type Output = Result<(), NvChipIoError>;

    fn poll(mut self: pin::Pin<&mut Self>, chip: &TestNvChip, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        match self.deref_mut() {
            Self::Init {
                chip_io_block_index,
                chip_io_blocks_count,
            } => {
                *self = Self::PolledOnce {
                    chip_io_block_index: *chip_io_block_index,
                    chip_io_blocks_count: *chip_io_blocks_count,
                };
                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
            Self::PolledOnce {
                chip_io_block_index,
                chip_io_blocks_count,
            } => {
                let chip_io_block_index = usize::try_from(*chip_io_block_index).unwrap();
                let end_block_index = chip_io_block_index.checked_add(*chip_io_blocks_count).unwrap();
                let mut chip_io_blocks = chip.chip_io_blocks.lock();
                if chip_io_blocks.len() < end_block_index {
                    return task::Poll::Ready(Err(NvChipIoError::IoBlockOutOfRange));
                }
                for block in chip_io_blocks
                    .iter_mut()
                    .skip(chip_io_block_index)
                    .take(*chip_io_blocks_count)
                {
                    *block = None;
                }
                drop(chip_io_blocks);
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
type TestNvChipSyncRcPtr = <TestSyncRcPtrFactory as sync_types::SyncRcPtrFactory>::SyncRcPtr<TestNvChip>;

#[cfg(test)]
struct TestNvChipFuture<F: chip::NvChipFuture<TestNvChip>> {
    chip: TestNvChipSyncRcPtr,
    chip_fut: F,
}

#[cfg(test)]
impl<F: chip::NvChipFuture<TestNvChip>> TestNvChipFuture<F> {
    fn new(chip: TestNvChipSyncRcPtr, chip_fut: F) -> Self {
        Self { chip, chip_fut }
    }
}

#[cfg(test)]
impl<F: chip::NvChipFuture<TestNvChip>> future::Future for TestNvChipFuture<F> {
    type Output = F::Output;

    fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        // Safe, inner_fut will get projection-pinned right below.
        let this = unsafe { pin::Pin::into_inner_unchecked(self) };
        // Safe, it's a projection pin.
        let chip_fut = unsafe { pin::Pin::new_unchecked(&mut this.chip_fut) };
        F::poll(chip_fut, &this.chip, cx)
    }
}

#[test]
fn test_nv_chip_rw() {
    use crate::chip::ChunkedIoRegionChunkRange;

    #[derive(PartialEq, Eq, Debug)]
    struct TestRwRequest {
        region: ChunkedIoRegion,
        level0_child_count_log2: u32,
        level1_child_count_log2: u32,
        buffers: Vec<Vec<Vec<Vec<u8>>>>,
    }

    impl TestRwRequest {
        fn new(
            chunk_size_128b_log2: u32,
            level0_child_count_log2: u32,
            level1_child_count_log2: u32,
            level2_child_count: usize,
            physical_begin_chunk: u64,
        ) -> Self {
            // For vec![].
            use alloc::vec;

            let physical_begin_128b = physical_begin_chunk << chunk_size_128b_log2;
            let region_size_128b =
                level2_child_count << (chunk_size_128b_log2 + level0_child_count_log2 + level1_child_count_log2);
            let physical_end_128b = physical_begin_128b + region_size_128b as u64;
            let region = ChunkedIoRegion::new(physical_begin_128b, physical_end_128b, chunk_size_128b_log2).unwrap();
            let mut buffers = Vec::new();
            for _l2 in 0..level2_child_count {
                let mut level1_childs = Vec::new();
                for _l1 in 0..(1usize << level1_child_count_log2) {
                    let mut level0_childs = Vec::new();
                    for _l0 in 0..(1usize << level0_child_count_log2) {
                        let chunk = vec![0; 1usize << (chunk_size_128b_log2 + 7)];
                        level0_childs.push(chunk);
                    }
                    level1_childs.push(level0_childs);
                }
                buffers.push(level1_childs);
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

    impl chip::NvChipReadRequest for TestRwRequest {
        fn region(&self) -> &ChunkedIoRegion {
            &self.region
        }

        fn get_destination_buffer(
            &mut self,
            range: &ChunkedIoRegionChunkRange,
        ) -> Result<Option<&mut [u8]>, NvChipIoError> {
            let chunk = range.chunk();
            let (l2, [l1, l0]) =
                chunk.decompose_to_hierarchic_indices([self.level1_child_count_log2, self.level0_child_count_log2]);
            Ok(Some(&mut self.buffers[l2][l1][l0][range.range_in_chunk().clone()]))
        }
    }

    impl chip::NvChipWriteRequest for TestRwRequest {
        fn region(&self) -> &ChunkedIoRegion {
            &self.region
        }

        fn get_source_buffer(&self, range: &ChunkedIoRegionChunkRange) -> Result<&[u8], NvChipIoError> {
            let chunk = range.chunk();
            let (l2, [l1, l0]) =
                chunk.decompose_to_hierarchic_indices([self.level1_child_count_log2, self.level0_child_count_log2]);
            Ok(&self.buffers[l2][l1][l0][range.range_in_chunk().clone()])
        }
    }

    fn test_one(
        chip_io_block_size_128b_log2: u32,
        preferred_chip_io_blocks_bulk_log2: u32,
        request_chunk_size_128b_log2: u32,
        request_level0_child_count_log2: u32,
        request_level1_child_count_log2: u32,
        request_level2_child_count: usize,
    ) {
        use crate::utils_async::test::TestAsyncExecutor;
        use chip::NvChip as _;

        let request_physical_begin_chunk =
            1 << (chip_io_block_size_128b_log2 - request_chunk_size_128b_log2.min(chip_io_block_size_128b_log2));
        let request_size_128b = (request_level2_child_count as u64)
            << (request_chunk_size_128b_log2 + request_level0_child_count_log2 + request_level1_child_count_log2);
        let physical_end_128b = (request_physical_begin_chunk << request_chunk_size_128b_log2) + request_size_128b;
        let chip_io_block_size_128b = 1 << chip_io_block_size_128b_log2;
        let chip_io_blocks_count = (physical_end_128b + (chip_io_block_size_128b - 1)) >> chip_io_block_size_128b_log2;
        let chip = <TestSyncRcPtrFactory as sync_types::SyncRcPtrFactory>::try_new(TestNvChip::new(
            chip_io_block_size_128b_log2,
            chip_io_blocks_count,
            preferred_chip_io_blocks_bulk_log2,
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
            TestNvChipFuture::new(
                chip.clone(),
                chip.write(write_request).and_then(|r| r.map_err(|(_, e)| e)).unwrap(),
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
            TestNvChipFuture::new(
                chip.clone(),
                chip.read(read_request).and_then(|r| r.map_err(|(_, e)| e)).unwrap(),
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
