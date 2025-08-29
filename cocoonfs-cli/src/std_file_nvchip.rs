// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`StdFileNvChip`], a [`NvChip`](chip::NvChip) trait
//! implementation based on Rust `std` [`File`] IO primitives.

use cocoon_tpm_storage::{chip::NvChipIoError, nvchip_err_internal};
use cocoon_tpm_utils_async::sync_types::Lock;

use super::std_sync_types::StdLock;
use crate::{storage::chip, utils_common::fixed_vec::FixedVec};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    pin, task,
};

/// Inner state of [`StdFileNvChip`], to be wrapped in a [`Lock`](StdLock).
struct StdFileNvChipInner {
    /// The backend filesystem storage volume image [`File`].
    volume_file: File,
    /// The [`Chip IO Block size`](chip::NvChip::chip_io_block_size_128b_log2).
    chip_io_block_size_128b_log2: u32,
    /// Number of [Chip IO Blocks](Self::chip_io_block_size_128b_log2) provided
    /// by the [`volume_file`](Self::volume_file).
    chip_io_blocks: u64,
    /// Bounce buffer for IO.
    ///
    /// One [Chip IO Block](Self::chip_io_block_size_128b_log2) in size.
    chip_io_block_bounce_buffer: FixedVec<u8, 7>,
    /// Whether the [`StdFileNvChipInner`] is considered to have entered failed
    /// state.
    ///
    /// The failed state is typically entered once a query for
    /// [`volume_file`](Self::volume_size) fails, and the value in
    /// [`chip_io_blocks`](Self::chip_io_blocks) has therefore become stale.
    failed: bool,
}

impl StdFileNvChipInner {
    /// The [preferred bulk IO
    /// size](chip::NvChip::preferred_chip_io_blocks_bulk_log2).
    fn preferred_chip_io_blocks_bulk_log2(&self) -> u32 {
        // 16kB
        (14u32 - 7).saturating_sub(self.chip_io_block_size_128b_log2)
    }
}

/// [`NvChip`](chip::NvChip) trait implementation based on
///  Rust `std` [`File`] IO primitives.
pub struct StdFileNvChip {
    inner: Box<StdLock<StdFileNvChipInner>>,
}

impl chip::NvChip for StdFileNvChip {
    fn chip_io_block_size_128b_log2(&self) -> u32 {
        self.inner.lock().chip_io_block_size_128b_log2
    }

    fn chip_io_blocks(&self) -> u64 {
        self.inner.lock().chip_io_blocks
    }

    fn preferred_chip_io_blocks_bulk_log2(&self) -> u32 {
        self.inner.lock().preferred_chip_io_blocks_bulk_log2()
    }

    type ResizeFuture = StdFileNvChipResizeFuture;

    fn resize(&self, chip_io_blocks_count: u64) -> Result<Self::ResizeFuture, chip::NvChipIoError> {
        if chip_io_blocks_count > u64::MAX >> (self.chip_io_block_size_128b_log2() + 7) {
            return Err(chip::NvChipIoError::IoBlockOutOfRange);
        }

        Ok(Self::ResizeFuture {
            new_chip_io_blocks: chip_io_blocks_count,
        })
    }

    type ReadFuture<R: chip::NvChipReadRequest> = StdFileNvChipReadFuture<R>;

    fn read<R: chip::NvChipReadRequest>(
        &self,
        request: R,
    ) -> Result<Result<Self::ReadFuture<R>, (R, chip::NvChipIoError)>, chip::NvChipIoError> {
        Ok(Ok(Self::ReadFuture::<R> { request: Some(request) }))
    }

    type WriteFuture<R: chip::NvChipWriteRequest> = StdFileNvChipWriteFuture<R>;

    fn write<R: chip::NvChipWriteRequest>(
        &self,
        request: R,
    ) -> Result<Result<Self::WriteFuture<R>, (R, chip::NvChipIoError)>, chip::NvChipIoError> {
        Ok(Ok(Self::WriteFuture::<R> { request: Some(request) }))
    }

    type WriteBarrierFuture = Self::WriteSyncFuture;

    fn write_barrier(&self) -> Result<Self::WriteBarrierFuture, chip::NvChipIoError> {
        self.write_sync()
    }

    type WriteSyncFuture = StdFileNvChipWriteSyncFuture;

    fn write_sync(&self) -> Result<Self::WriteSyncFuture, chip::NvChipIoError> {
        Ok(StdFileNvChipWriteSyncFuture)
    }

    type TrimFuture = StdFileNvChipTrimFuture;

    fn trim(
        &self,
        chip_io_block_index: u64,
        chip_io_blocks_count: u64,
    ) -> Result<Self::TrimFuture, chip::NvChipIoError> {
        Ok(Self::TrimFuture {
            chip_io_block_index,
            chip_io_blocks_count,
        })
    }
}

impl StdFileNvChip {
    /// Instantiate a [`StdFileNvChip`].
    ///
    /// # Arguments:
    ///
    /// * `volume_file` - The filesystem image volume [`File`] to operate on.
    /// * `max_io_block_size_128b_log2` - Upper limit to impose on the
    ///   [`StdFileNvChip`] instance's [`Chip IO
    ///   Block`](chip::NvChip::chip_io_block_size_128b_log2) size, if any. If
    ///   specified, the block size reported by the operating system for
    ///   `volume_file` will be capped at `max_io_block_size_128b_log2`.
    pub fn new(volume_file: File, max_io_block_size_128b_log2: Option<u32>) -> Result<Self, chip::NvChipIoError> {
        let meta = match volume_file.metadata() {
            Ok(meta) => meta,
            Err(e) => {
                eprintln!("error: volume stat failed: error={}", e);
                return Err(std_io_error_to_chip_io_error(e));
            }
        };

        #[cfg(unix)]
        let file_block_size = meta.blksize();
        #[cfg(not(unix))]
        let file_block_size = 512;

        let file_block_size_128b_log2 = if file_block_size == 0 {
            0
        } else {
            file_block_size.ilog2() - 7
        };

        let chip_io_block_size_128b_log2 = max_io_block_size_128b_log2
            .map(|max_io_block_size_128b_log2| max_io_block_size_128b_log2.min(file_block_size_128b_log2))
            .unwrap_or(file_block_size_128b_log2);

        if chip_io_block_size_128b_log2 >= usize::BITS - 7 {
            eprintln!("error: volume block size unsupported: {}B", file_block_size);
            return Err(chip::NvChipIoError::OperationNotSupported);
        }

        let chip_io_blocks = meta.len() >> (chip_io_block_size_128b_log2 + 7);

        let chip_io_block_bounce_buffer = FixedVec::new_with_default(1usize << (chip_io_block_size_128b_log2 + 7))?;

        Ok(Self {
            inner: Box::new(StdLock::from(StdFileNvChipInner {
                volume_file,
                chip_io_block_size_128b_log2,
                chip_io_blocks,
                chip_io_block_bounce_buffer,
                failed: false,
            })),
        })
    }
}

/// Convert a [`std::io::Error`] to a [`NvChipIoError`](chip::NvChipIoError).
fn std_io_error_to_chip_io_error(e: io::Error) -> chip::NvChipIoError {
    match e.kind() {
        io::ErrorKind::Unsupported | io::ErrorKind::NotSeekable => chip::NvChipIoError::OperationNotSupported,
        io::ErrorKind::FileTooLarge | io::ErrorKind::UnexpectedEof => chip::NvChipIoError::IoBlockOutOfRange,
        io::ErrorKind::OutOfMemory => chip::NvChipIoError::MemoryAllocationFailure,
        _ => chip::NvChipIoError::IoFailure,
    }
}

/// [`NvChip::ResizeFuture`](chip::NvChip::ResizeFuture) implementation for
/// [`StdFileNvChip`].
pub struct StdFileNvChipResizeFuture {
    new_chip_io_blocks: u64,
}

impl chip::NvChipFuture<StdFileNvChip> for StdFileNvChipResizeFuture {
    type Output = Result<(), chip::NvChipIoError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        chip: &StdFileNvChip,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        let mut inner = chip.inner.lock();
        let result = match inner
            .volume_file
            .set_len(self.new_chip_io_blocks << (inner.chip_io_block_size_128b_log2 + 7))
        {
            Ok(()) => {
                inner.chip_io_blocks = self.new_chip_io_blocks;
                Ok(())
            }
            Err(e) => {
                // Try to figure out what the volume size is now.
                if let Ok(meta) = inner.volume_file.metadata() {
                    inner.chip_io_blocks = meta.len() >> (inner.chip_io_block_size_128b_log2 + 7);
                    if self.new_chip_io_blocks > inner.chip_io_blocks {
                        eprintln!(
                            "error: volume resize failed: error={}, target={}, current={}",
                            e,
                            self.new_chip_io_blocks << (inner.chip_io_block_size_128b_log2 + 7),
                            inner.chip_io_blocks << (inner.chip_io_block_size_128b_log2 + 7)
                        );
                    }
                } else {
                    inner.failed = true;
                }
                Err(std_io_error_to_chip_io_error(e))
            }
        };
        task::Poll::Ready(result)
    }
}

/// [`NvChip::ReadFuture`](chip::NvChip::ReadFuture) implementation for
/// [`StdFileNvChip`].
pub struct StdFileNvChipReadFuture<R: chip::NvChipReadRequest> {
    request: Option<R>,
}

impl<R: chip::NvChipReadRequest> chip::NvChipFuture<StdFileNvChip> for StdFileNvChipReadFuture<R> {
    type Output = Result<(R, Result<(), chip::NvChipIoError>), chip::NvChipIoError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        chip: &StdFileNvChip,
        _cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let mut inner = chip.inner.lock();
        let preferred_chip_io_blocks_bulk_log2 = inner.preferred_chip_io_blocks_bulk_log2();
        let StdFileNvChipInner {
            volume_file,
            chip_io_block_size_128b_log2,
            chip_io_blocks,
            chip_io_block_bounce_buffer,
            failed,
        } = &mut *inner;

        let this = pin::Pin::into_inner(self);
        let mut request = match this.request.take() {
            Some(request) => request,
            None => return task::Poll::Ready(Err(nvchip_err_internal!())),
        };

        if *failed {
            return task::Poll::Ready(Err(chip::NvChipIoError::IoFailure));
        }

        let region = request.region().clone();
        if region.chunk_size_128b_log2() >= *chip_io_block_size_128b_log2 {
            // The buffers are all larger than (by a fixed power of two multiple of) the
            // volume block size. No bounce buffer needed.
            let block_size_128b_log2 = if region.is_aligned(region.chunk_size_128b_log2()) {
                region.chunk_size_128b_log2()
            } else if region.chunk_size_128b_log2()
                >= preferred_chip_io_blocks_bulk_log2 + *chip_io_block_size_128b_log2
                && region.is_aligned(preferred_chip_io_blocks_bulk_log2 + *chip_io_block_size_128b_log2)
            {
                preferred_chip_io_blocks_bulk_log2 + *chip_io_block_size_128b_log2
            } else {
                debug_assert!(region.is_aligned(*chip_io_block_size_128b_log2));
                *chip_io_block_size_128b_log2
            };
            let blocks_iter = match region.aligned_blocks_iter(block_size_128b_log2) {
                Ok(blocks_iter) => blocks_iter,
                Err(_) => return task::Poll::Ready(Ok((request, Err(nvchip_err_internal!())))),
            };
            let mut need_seek = true;
            for (physical_block_index, block_chunks) in blocks_iter {
                let block_begin_128b = physical_block_index << block_size_128b_log2;
                if block_begin_128b >= *chip_io_blocks << *chip_io_block_size_128b_log2
                    || ((*chip_io_blocks << *chip_io_block_size_128b_log2) - block_begin_128b) >> block_size_128b_log2
                        == 0
                {
                    return task::Poll::Ready(Ok((request, Err(chip::NvChipIoError::IoBlockOutOfRange))));
                }
                for (offset_in_block_128b, chunk_range) in block_chunks {
                    // The buffer size is >= the iteration block size.
                    debug_assert_eq!(offset_in_block_128b, 0);
                    if need_seek {
                        if let Err(e) =
                            volume_file.seek(SeekFrom::Start((block_begin_128b + offset_in_block_128b) << 7))
                        {
                            eprintln!(
                                "error: volume seek for read failed: error={}, position={}",
                                e,
                                (block_begin_128b + offset_in_block_128b) << 7
                            );
                            return task::Poll::Ready(Ok((request, Err(std_io_error_to_chip_io_error(e)))));
                        }
                        need_seek = false;
                    }

                    let buf = match request.get_destination_buffer(&chunk_range) {
                        Ok(buf) => buf,
                        Err(e) => return task::Poll::Ready(Ok((request, Err(e)))),
                    };
                    let buf = match buf {
                        Some(buf) => buf,
                        None => {
                            need_seek = true;
                            continue;
                        }
                    };

                    if let Err(e) = volume_file.read_exact(buf) {
                        eprintln!(
                            "error: volume read failed: error={}, position={}, size={}",
                            e,
                            (block_begin_128b + offset_in_block_128b) << 7,
                            1u64 << (block_size_128b_log2 + 7)
                        );
                        return task::Poll::Ready(Ok((request, Err(std_io_error_to_chip_io_error(e)))));
                    }
                }
            }
        } else {
            // The buffers are smaller than the volume block size, going through the bounce
            // buffer is necessary.
            let block_size_128b_log2 = *chip_io_block_size_128b_log2;
            let blocks_iter = match region.aligned_blocks_iter(block_size_128b_log2) {
                Ok(blocks_iter) => blocks_iter,
                Err(_) => return task::Poll::Ready(Ok((request, Err(nvchip_err_internal!())))),
            };
            let mut need_seek = true;
            for (physical_block_index, block_chunks) in blocks_iter {
                let block_begin_128b = physical_block_index << block_size_128b_log2;
                if block_begin_128b >= *chip_io_blocks << *chip_io_block_size_128b_log2
                    || ((*chip_io_blocks << *chip_io_block_size_128b_log2) - block_begin_128b) >> block_size_128b_log2
                        == 0
                {
                    return task::Poll::Ready(Ok((request, Err(chip::NvChipIoError::IoBlockOutOfRange))));
                }

                if need_seek {
                    if let Err(e) = volume_file.seek(SeekFrom::Start(block_begin_128b << 7)) {
                        eprintln!(
                            "error: volume seek for read failed: error={}, position={}",
                            e,
                            block_begin_128b << 7
                        );
                        return task::Poll::Ready(Ok((request, Err(std_io_error_to_chip_io_error(e)))));
                    }
                    need_seek = false;
                }

                if let Err(e) = volume_file.read_exact(chip_io_block_bounce_buffer) {
                    eprintln!(
                        "error: volume read failed: error={}, position={}, size={}",
                        e,
                        block_begin_128b << 7,
                        1u64 << (block_size_128b_log2 + 7)
                    );
                    return task::Poll::Ready(Ok((request, Err(std_io_error_to_chip_io_error(e)))));
                }

                for (offset_in_block_128b, chunk_range) in block_chunks {
                    let buf = match request.get_destination_buffer(&chunk_range) {
                        Ok(buf) => buf,
                        Err(e) => return task::Poll::Ready(Ok((request, Err(e)))),
                    };
                    let buf = match buf {
                        Some(buf) => buf,
                        None => continue,
                    };

                    let buf_len = buf.len();
                    debug_assert_eq!(buf_len, 1usize << (region.chunk_size_128b_log2() + 7));
                    let offset_in_block = (offset_in_block_128b << 7) as usize;
                    buf.copy_from_slice(&chip_io_block_bounce_buffer[offset_in_block..offset_in_block + buf_len]);
                }
            }
        }

        task::Poll::Ready(Ok((request, Ok(()))))
    }
}

/// [`NvChip::WriteFuture`](chip::NvChip::WriteFuture) implementation for
/// [`StdFileNvChip`].
pub struct StdFileNvChipWriteFuture<R: chip::NvChipWriteRequest> {
    request: Option<R>,
}

impl<R: chip::NvChipWriteRequest> chip::NvChipFuture<StdFileNvChip> for StdFileNvChipWriteFuture<R> {
    type Output = Result<(R, Result<(), chip::NvChipIoError>), chip::NvChipIoError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        chip: &StdFileNvChip,
        _cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let mut inner = chip.inner.lock();
        let preferred_chip_io_blocks_bulk_log2 = inner.preferred_chip_io_blocks_bulk_log2();
        let StdFileNvChipInner {
            volume_file,
            chip_io_block_size_128b_log2,
            chip_io_blocks,
            chip_io_block_bounce_buffer,
            failed,
        } = &mut *inner;

        let this = pin::Pin::into_inner(self);
        let request = match this.request.take() {
            Some(request) => request,
            None => return task::Poll::Ready(Err(nvchip_err_internal!())),
        };

        if *failed {
            return task::Poll::Ready(Err(chip::NvChipIoError::IoFailure));
        }

        let region = request.region().clone();
        if region.chunk_size_128b_log2() >= *chip_io_block_size_128b_log2 {
            // The buffers are all larger than (by a fixed power of two multiple of) the
            // volume block size. No bounce buffer needed.
            let block_size_128b_log2 = if region.is_aligned(region.chunk_size_128b_log2()) {
                region.chunk_size_128b_log2()
            } else if region.chunk_size_128b_log2()
                >= preferred_chip_io_blocks_bulk_log2 + *chip_io_block_size_128b_log2
                && region.is_aligned(preferred_chip_io_blocks_bulk_log2 + *chip_io_block_size_128b_log2)
            {
                preferred_chip_io_blocks_bulk_log2 + *chip_io_block_size_128b_log2
            } else {
                debug_assert!(region.is_aligned(*chip_io_block_size_128b_log2));
                *chip_io_block_size_128b_log2
            };
            let blocks_iter = match region.aligned_blocks_iter(block_size_128b_log2) {
                Ok(blocks_iter) => blocks_iter,
                Err(_) => return task::Poll::Ready(Ok((request, Err(nvchip_err_internal!())))),
            };
            let mut need_seek = true;
            for (physical_block_index, block_chunks) in blocks_iter {
                let block_begin_128b = physical_block_index << block_size_128b_log2;
                if block_begin_128b >= *chip_io_blocks << *chip_io_block_size_128b_log2
                    || ((*chip_io_blocks << *chip_io_block_size_128b_log2) - block_begin_128b) >> block_size_128b_log2
                        == 0
                {
                    return task::Poll::Ready(Ok((request, Err(chip::NvChipIoError::IoBlockOutOfRange))));
                }

                if need_seek {
                    if let Err(e) = volume_file.seek(SeekFrom::Start(block_begin_128b << 7)) {
                        eprintln!(
                            "error: volume seek for write failed: error={}, position={}",
                            e,
                            block_begin_128b << 7
                        );
                        return task::Poll::Ready(Ok((request, Err(std_io_error_to_chip_io_error(e)))));
                    }
                    need_seek = false;
                }

                for (offset_in_block_128b, chunk_range) in block_chunks {
                    // The buffer size is >= the iteration block size.
                    debug_assert_eq!(offset_in_block_128b, 0);
                    let buf = match request.get_source_buffer(&chunk_range) {
                        Ok(buf) => buf,
                        Err(e) => return task::Poll::Ready(Ok((request, Err(e)))),
                    };

                    if let Err(e) = volume_file.write_all(buf) {
                        eprintln!(
                            "error: volume write failed: error={}, position={}, size={}",
                            e,
                            (block_begin_128b + offset_in_block_128b) << 7,
                            1u64 << (block_size_128b_log2 + 7)
                        );
                        return task::Poll::Ready(Ok((request, Err(std_io_error_to_chip_io_error(e)))));
                    }
                }
            }
        } else {
            // The buffers are smaller than the volume block size, going through the bounce
            // buffer is necessary.
            let block_size_128b_log2 = *chip_io_block_size_128b_log2;
            let blocks_iter = match region.aligned_blocks_iter(block_size_128b_log2) {
                Ok(blocks_iter) => blocks_iter,
                Err(_) => return task::Poll::Ready(Ok((request, Err(nvchip_err_internal!())))),
            };
            let mut need_seek = true;
            for (physical_block_index, block_chunks) in blocks_iter {
                let block_begin_128b = physical_block_index << block_size_128b_log2;
                if block_begin_128b >= *chip_io_blocks << *chip_io_block_size_128b_log2
                    || ((*chip_io_blocks << *chip_io_block_size_128b_log2) - block_begin_128b) >> block_size_128b_log2
                        == 0
                {
                    return task::Poll::Ready(Ok((request, Err(chip::NvChipIoError::IoBlockOutOfRange))));
                }

                if need_seek {
                    if let Err(e) = volume_file.seek(SeekFrom::Start(block_begin_128b << 7)) {
                        eprintln!(
                            "error: volume seek for write failed: error={}, position={}",
                            e,
                            block_begin_128b << 7
                        );
                        return task::Poll::Ready(Ok((request, Err(std_io_error_to_chip_io_error(e)))));
                    }
                    need_seek = false;
                }

                for (offset_in_block_128b, chunk_range) in block_chunks {
                    let buf = match request.get_source_buffer(&chunk_range) {
                        Ok(buf) => buf,
                        Err(e) => return task::Poll::Ready(Ok((request, Err(e)))),
                    };

                    let buf_len = buf.len();
                    debug_assert_eq!(buf_len, 1usize << (region.chunk_size_128b_log2() + 7));
                    let offset_in_block = (offset_in_block_128b << 7) as usize;
                    chip_io_block_bounce_buffer[offset_in_block..offset_in_block + buf_len].copy_from_slice(buf);
                }

                if let Err(e) = volume_file.write_all(chip_io_block_bounce_buffer) {
                    eprintln!(
                        "error: volume write failed: error={}, position={}, size={}",
                        e,
                        block_begin_128b << 7,
                        1u64 << (block_size_128b_log2 + 7)
                    );
                    return task::Poll::Ready(Ok((request, Err(std_io_error_to_chip_io_error(e)))));
                }
            }
        }

        if let Err(e) = inner.volume_file.flush() {
            eprintln!("error: volume writes flushing failed: error={}", e);
            return task::Poll::Ready(Ok((request, Err(std_io_error_to_chip_io_error(e)))));
        }

        task::Poll::Ready(Ok((request, Ok(()))))
    }
}

/// [`NvChip::WriteSyncFuture`](chip::NvChip::WriteSyncFuture) implementation
/// for [`StdFileNvChip`].
///
/// Also used for the
/// [`NvChip::WriteBarrierFuture`](chip::NvChip::WriteBarrierFuture).
pub struct StdFileNvChipWriteSyncFuture;

impl chip::NvChipFuture<StdFileNvChip> for StdFileNvChipWriteSyncFuture {
    type Output = Result<(), chip::NvChipIoError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        chip: &StdFileNvChip,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        let mut inner = chip.inner.lock();
        if let Err(e) = inner.volume_file.flush() {
            eprintln!("error: volume writes flushing failed: error={}", e);
            return task::Poll::Ready(Err(std_io_error_to_chip_io_error(e)));
        }

        if let Err(e) = inner.volume_file.sync_data() {
            eprintln!("error: volume sync request failed: error={}", e);
            return task::Poll::Ready(Err(std_io_error_to_chip_io_error(e)));
        }

        task::Poll::Ready(Ok(()))
    }
}

/// [`NvChip::TrimFuture`](chip::NvChip::TrimFuture) implementation for
/// [`StdFileNvChip`].
pub struct StdFileNvChipTrimFuture {
    chip_io_block_index: u64,
    chip_io_blocks_count: u64,
}

impl chip::NvChipFuture<StdFileNvChip> for StdFileNvChipTrimFuture {
    type Output = Result<(), chip::NvChipIoError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        chip: &StdFileNvChip,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        let mut inner = chip.inner.lock();
        let StdFileNvChipInner {
            volume_file,
            chip_io_block_size_128b_log2,
            chip_io_blocks,
            chip_io_block_bounce_buffer,
            failed,
        } = &mut *inner;

        // No access to fallocate from std Rust. Write zeroes as a fallback alternative,
        // external tools might be able to do something with it.
        if self.chip_io_blocks_count == 0 {
            return task::Poll::Ready(Ok(()));
        } else if *failed {
            return task::Poll::Ready(Err(chip::NvChipIoError::IoFailure));
        } else if self.chip_io_block_index > *chip_io_blocks
            || *chip_io_blocks - self.chip_io_block_index < self.chip_io_blocks_count
        {
            return task::Poll::Ready(Err(NvChipIoError::IoBlockOutOfRange));
        }

        if let Err(e) = volume_file.seek(SeekFrom::Start(
            self.chip_io_block_index << (*chip_io_block_size_128b_log2 + 7),
        )) {
            eprintln!(
                "error: volume seek for write failed: error={}, position={}",
                e,
                self.chip_io_block_index << (*chip_io_block_size_128b_log2 + 7),
            );
            return task::Poll::Ready(Err(std_io_error_to_chip_io_error(e)));
        }

        chip_io_block_bounce_buffer.fill(0u8);
        for i in 0..self.chip_io_blocks_count {
            if let Err(e) = volume_file.write_all(chip_io_block_bounce_buffer) {
                eprintln!(
                    "error: volume write for trim failed: error={}, position={}, size={}",
                    e,
                    (self.chip_io_block_index + i) << (*chip_io_block_size_128b_log2 + 7),
                    chip_io_block_bounce_buffer.len()
                );
                return task::Poll::Ready(Err(std_io_error_to_chip_io_error(e)));
            }
        }

        if let Err(e) = inner.volume_file.flush() {
            eprintln!("error: volume writes flushing failed: error={}", e);
            return task::Poll::Ready(Err(std_io_error_to_chip_io_error(e)));
        }

        task::Poll::Ready(Ok(()))
    }
}
