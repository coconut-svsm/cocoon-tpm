// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`StdFileNvBlkDev`], a [`NvBlkDev`](blkdev::NvBlkDev)
//! trait implementation based on Rust `std` [`File`] IO primitives.

use super::std_sync_types::StdLock;
use crate::{
    storage::{blkdev, nvblkdev_err_internal},
    utils_async::sync_types::Lock as _,
    utils_common::fixed_vec::FixedVec,
};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    pin, task,
};

/// Inner state of [`StdFileNvBlkDev`], to be wrapped in a [`Lock`](StdLock).
struct StdFileNvBlkDevInner {
    /// The backend filesystem storage volume image [`File`].
    volume_file: File,
    /// The [`Device IO Block size`](blkdev::NvBlkDev::io_block_size_128b_log2).
    io_block_size_128b_log2: u32,
    /// Number of [Device IO Blocks](Self::io_block_size_128b_log2) provided by
    /// the [`volume_file`](Self::volume_file).
    io_blocks: u64,
    /// Bounce buffer for IO.
    ///
    /// One [Device IO Block](Self::io_block_size_128b_log2) in size.
    io_block_bounce_buffer: FixedVec<u8, 7>,
    /// Whether the [`StdFileNvBlkDevInner`] is considered to have entered
    /// failed state.
    ///
    /// The failed state is typically entered once a query for
    /// [`volume_file`](Self::volume_size) fails, and the value in
    /// [`io_blocks`](Self::io_blocks) has therefore become stale.
    failed: bool,
}

impl StdFileNvBlkDevInner {
    /// The [preferred bulk IO
    /// size](blkdev::NvBlkDev::preferred_io_blocks_bulk_log2).
    fn preferred_io_blocks_bulk_log2(&self) -> u32 {
        // 16kB
        (14u32 - 7).saturating_sub(self.io_block_size_128b_log2)
    }
}

/// [`NvBlkDev`](blkdev::NvBlkDev) trait implementation based on
///  Rust `std` [`File`] IO primitives.
pub struct StdFileNvBlkDev {
    inner: Box<StdLock<StdFileNvBlkDevInner>>,
}

impl blkdev::NvBlkDev for StdFileNvBlkDev {
    fn io_block_size_128b_log2(&self) -> u32 {
        self.inner.lock().io_block_size_128b_log2
    }

    fn io_blocks(&self) -> u64 {
        self.inner.lock().io_blocks
    }

    fn preferred_io_blocks_bulk_log2(&self) -> u32 {
        self.inner.lock().preferred_io_blocks_bulk_log2()
    }

    type ResizeFuture = StdFileNvBlkDevResizeFuture;

    fn resize(&self, io_blocks: u64) -> Result<Self::ResizeFuture, blkdev::NvBlkDevIoError> {
        if io_blocks > u64::MAX >> (self.io_block_size_128b_log2() + 7) {
            return Err(blkdev::NvBlkDevIoError::IoBlockOutOfRange);
        }

        Ok(Self::ResizeFuture {
            new_io_blocks: io_blocks,
        })
    }

    type ReadFuture<R: blkdev::NvBlkDevReadRequest> = StdFileNvBlkDevReadFuture<R>;

    fn read<R: blkdev::NvBlkDevReadRequest>(
        &self,
        request: R,
    ) -> Result<Result<Self::ReadFuture<R>, (R, blkdev::NvBlkDevIoError)>, blkdev::NvBlkDevIoError> {
        Ok(Ok(Self::ReadFuture::<R> { request: Some(request) }))
    }

    type WriteFuture<R: blkdev::NvBlkDevWriteRequest> = StdFileNvBlkDevWriteFuture<R>;

    fn write<R: blkdev::NvBlkDevWriteRequest>(
        &self,
        request: R,
    ) -> Result<Result<Self::WriteFuture<R>, (R, blkdev::NvBlkDevIoError)>, blkdev::NvBlkDevIoError> {
        Ok(Ok(Self::WriteFuture::<R> { request: Some(request) }))
    }

    type WriteBarrierFuture = Self::WriteSyncFuture;

    fn write_barrier(&self) -> Result<Self::WriteBarrierFuture, blkdev::NvBlkDevIoError> {
        self.write_sync()
    }

    type WriteSyncFuture = StdFileNvBlkDevWriteSyncFuture;

    fn write_sync(&self) -> Result<Self::WriteSyncFuture, blkdev::NvBlkDevIoError> {
        Ok(StdFileNvBlkDevWriteSyncFuture)
    }

    type TrimFuture = StdFileNvBlkDevTrimFuture;

    fn trim(&self, io_block_index: u64, io_blocks: u64) -> Result<Self::TrimFuture, blkdev::NvBlkDevIoError> {
        Ok(Self::TrimFuture {
            io_block_index,
            io_blocks,
        })
    }
}

impl StdFileNvBlkDev {
    /// Instantiate a [`StdFileNvBlkDev`].
    ///
    /// # Arguments:
    ///
    /// * `volume_file` - The filesystem image volume [`File`] to operate on.
    /// * `max_io_block_size_128b_log2` - Upper limit to impose on the
    ///   [`StdFileNvBlkDev`] instance's [`Device IO
    ///   Block`](blkdev::NvBlkDev::io_block_size_128b_log2) size, if any. If
    ///   specified, the block size reported by the operating system for
    ///   `volume_file` will be capped at `max_io_block_size_128b_log2`.
    pub fn new(volume_file: File, max_io_block_size_128b_log2: Option<u32>) -> Result<Self, blkdev::NvBlkDevIoError> {
        let meta = match volume_file.metadata() {
            Ok(meta) => meta,
            Err(e) => {
                eprintln!("error: volume stat failed: error={}", e);
                return Err(std_io_error_to_blkdev_io_error(e));
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

        let io_block_size_128b_log2 = max_io_block_size_128b_log2
            .map(|max_io_block_size_128b_log2| max_io_block_size_128b_log2.min(file_block_size_128b_log2))
            .unwrap_or(file_block_size_128b_log2);

        if io_block_size_128b_log2 >= usize::BITS - 7 {
            eprintln!("error: volume block size unsupported: {}B", file_block_size);
            return Err(blkdev::NvBlkDevIoError::OperationNotSupported);
        }

        let io_blocks = meta.len() >> (io_block_size_128b_log2 + 7);

        let io_block_bounce_buffer = FixedVec::new_with_default(1usize << (io_block_size_128b_log2 + 7))?;

        Ok(Self {
            inner: Box::new(StdLock::from(StdFileNvBlkDevInner {
                volume_file,
                io_block_size_128b_log2,
                io_blocks,
                io_block_bounce_buffer,
                failed: false,
            })),
        })
    }
}

/// Convert a [`std::io::Error`] to a
/// [`NvBlkDevIoError`](blkdev::NvBlkDevIoError).
fn std_io_error_to_blkdev_io_error(e: io::Error) -> blkdev::NvBlkDevIoError {
    match e.kind() {
        io::ErrorKind::Unsupported | io::ErrorKind::NotSeekable => blkdev::NvBlkDevIoError::OperationNotSupported,
        io::ErrorKind::FileTooLarge | io::ErrorKind::UnexpectedEof => blkdev::NvBlkDevIoError::IoBlockOutOfRange,
        io::ErrorKind::OutOfMemory => blkdev::NvBlkDevIoError::MemoryAllocationFailure,
        _ => blkdev::NvBlkDevIoError::IoFailure,
    }
}

/// [`NvBlkDev::ResizeFuture`](blkdev::NvBlkDev::ResizeFuture) implementation
/// for [`StdFileNvBlkDev`].
pub struct StdFileNvBlkDevResizeFuture {
    new_io_blocks: u64,
}

impl blkdev::NvBlkDevFuture<StdFileNvBlkDev> for StdFileNvBlkDevResizeFuture {
    type Output = Result<(), blkdev::NvBlkDevIoError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        dev: &StdFileNvBlkDev,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        let mut inner = dev.inner.lock();
        let result = match inner
            .volume_file
            .set_len(self.new_io_blocks << (inner.io_block_size_128b_log2 + 7))
        {
            Ok(()) => {
                inner.io_blocks = self.new_io_blocks;
                Ok(())
            }
            Err(e) => {
                // Try to figure out what the volume size is now.
                if let Ok(meta) = inner.volume_file.metadata() {
                    inner.io_blocks = meta.len() >> (inner.io_block_size_128b_log2 + 7);
                    if self.new_io_blocks > inner.io_blocks {
                        eprintln!(
                            "error: volume resize failed: error={}, target={}, current={}",
                            e,
                            self.new_io_blocks << (inner.io_block_size_128b_log2 + 7),
                            inner.io_blocks << (inner.io_block_size_128b_log2 + 7)
                        );
                    }
                } else {
                    inner.failed = true;
                }
                Err(std_io_error_to_blkdev_io_error(e))
            }
        };
        task::Poll::Ready(result)
    }
}

/// [`NvBlkDev::ReadFuture`](blkdev::NvBlkDev::ReadFuture) implementation for
/// [`StdFileNvBlkDev`].
pub struct StdFileNvBlkDevReadFuture<R: blkdev::NvBlkDevReadRequest> {
    request: Option<R>,
}

impl<R: blkdev::NvBlkDevReadRequest> blkdev::NvBlkDevFuture<StdFileNvBlkDev> for StdFileNvBlkDevReadFuture<R> {
    type Output = Result<(R, Result<(), blkdev::NvBlkDevIoError>), blkdev::NvBlkDevIoError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        dev: &StdFileNvBlkDev,
        _cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let mut inner = dev.inner.lock();
        let preferred_io_blocks_bulk_log2 = inner.preferred_io_blocks_bulk_log2();
        let StdFileNvBlkDevInner {
            volume_file,
            io_block_size_128b_log2,
            io_blocks,
            io_block_bounce_buffer,
            failed,
        } = &mut *inner;

        let this = pin::Pin::into_inner(self);
        let mut request = match this.request.take() {
            Some(request) => request,
            None => return task::Poll::Ready(Err(nvblkdev_err_internal!())),
        };

        if *failed {
            return task::Poll::Ready(Err(blkdev::NvBlkDevIoError::IoFailure));
        }

        let region = request.region().clone();
        if region.chunk_size_128b_log2() >= *io_block_size_128b_log2 {
            // The buffers are all larger than (by a fixed power of two multiple of) the
            // volume block size. No bounce buffer needed.
            let block_size_128b_log2 = if region.is_aligned(region.chunk_size_128b_log2()) {
                region.chunk_size_128b_log2()
            } else if region.chunk_size_128b_log2() >= preferred_io_blocks_bulk_log2 + *io_block_size_128b_log2
                && region.is_aligned(preferred_io_blocks_bulk_log2 + *io_block_size_128b_log2)
            {
                preferred_io_blocks_bulk_log2 + *io_block_size_128b_log2
            } else {
                debug_assert!(region.is_aligned(*io_block_size_128b_log2));
                *io_block_size_128b_log2
            };
            let blocks_iter = match region.aligned_blocks_iter(block_size_128b_log2) {
                Ok(blocks_iter) => blocks_iter,
                Err(_) => return task::Poll::Ready(Ok((request, Err(nvblkdev_err_internal!())))),
            };
            let mut need_seek = true;
            for (physical_block_index, block_chunks) in blocks_iter {
                let block_begin_128b = physical_block_index << block_size_128b_log2;
                if block_begin_128b >= *io_blocks << *io_block_size_128b_log2
                    || ((*io_blocks << *io_block_size_128b_log2) - block_begin_128b) >> block_size_128b_log2 == 0
                {
                    return task::Poll::Ready(Ok((request, Err(blkdev::NvBlkDevIoError::IoBlockOutOfRange))));
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
                            return task::Poll::Ready(Ok((request, Err(std_io_error_to_blkdev_io_error(e)))));
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
                        return task::Poll::Ready(Ok((request, Err(std_io_error_to_blkdev_io_error(e)))));
                    }
                }
            }
        } else {
            // The buffers are smaller than the volume block size, going through the bounce
            // buffer is necessary.
            let block_size_128b_log2 = *io_block_size_128b_log2;
            let blocks_iter = match region.aligned_blocks_iter(block_size_128b_log2) {
                Ok(blocks_iter) => blocks_iter,
                Err(_) => return task::Poll::Ready(Ok((request, Err(nvblkdev_err_internal!())))),
            };
            let mut need_seek = true;
            for (physical_block_index, block_chunks) in blocks_iter {
                let block_begin_128b = physical_block_index << block_size_128b_log2;
                if block_begin_128b >= *io_blocks << *io_block_size_128b_log2
                    || ((*io_blocks << *io_block_size_128b_log2) - block_begin_128b) >> block_size_128b_log2 == 0
                {
                    return task::Poll::Ready(Ok((request, Err(blkdev::NvBlkDevIoError::IoBlockOutOfRange))));
                }

                if need_seek {
                    if let Err(e) = volume_file.seek(SeekFrom::Start(block_begin_128b << 7)) {
                        eprintln!(
                            "error: volume seek for read failed: error={}, position={}",
                            e,
                            block_begin_128b << 7
                        );
                        return task::Poll::Ready(Ok((request, Err(std_io_error_to_blkdev_io_error(e)))));
                    }
                    need_seek = false;
                }

                if let Err(e) = volume_file.read_exact(io_block_bounce_buffer) {
                    eprintln!(
                        "error: volume read failed: error={}, position={}, size={}",
                        e,
                        block_begin_128b << 7,
                        1u64 << (block_size_128b_log2 + 7)
                    );
                    return task::Poll::Ready(Ok((request, Err(std_io_error_to_blkdev_io_error(e)))));
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
                    buf.copy_from_slice(&io_block_bounce_buffer[offset_in_block..offset_in_block + buf_len]);
                }
            }
        }

        task::Poll::Ready(Ok((request, Ok(()))))
    }
}

/// [`NvBlkDev::WriteFuture`](blkdev::NvBlkDev::WriteFuture) implementation for
/// [`StdFileNvBlkDev`].
pub struct StdFileNvBlkDevWriteFuture<R: blkdev::NvBlkDevWriteRequest> {
    request: Option<R>,
}

impl<R: blkdev::NvBlkDevWriteRequest> blkdev::NvBlkDevFuture<StdFileNvBlkDev> for StdFileNvBlkDevWriteFuture<R> {
    type Output = Result<(R, Result<(), blkdev::NvBlkDevIoError>), blkdev::NvBlkDevIoError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        dev: &StdFileNvBlkDev,
        _cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let mut inner = dev.inner.lock();
        let preferred_io_blocks_bulk_log2 = inner.preferred_io_blocks_bulk_log2();
        let StdFileNvBlkDevInner {
            volume_file,
            io_block_size_128b_log2,
            io_blocks,
            io_block_bounce_buffer,
            failed,
        } = &mut *inner;

        let this = pin::Pin::into_inner(self);
        let request = match this.request.take() {
            Some(request) => request,
            None => return task::Poll::Ready(Err(nvblkdev_err_internal!())),
        };

        if *failed {
            return task::Poll::Ready(Err(blkdev::NvBlkDevIoError::IoFailure));
        }

        let region = request.region().clone();
        if region.chunk_size_128b_log2() >= *io_block_size_128b_log2 {
            // The buffers are all larger than (by a fixed power of two multiple of) the
            // volume block size. No bounce buffer needed.
            let block_size_128b_log2 = if region.is_aligned(region.chunk_size_128b_log2()) {
                region.chunk_size_128b_log2()
            } else if region.chunk_size_128b_log2() >= preferred_io_blocks_bulk_log2 + *io_block_size_128b_log2
                && region.is_aligned(preferred_io_blocks_bulk_log2 + *io_block_size_128b_log2)
            {
                preferred_io_blocks_bulk_log2 + *io_block_size_128b_log2
            } else {
                debug_assert!(region.is_aligned(*io_block_size_128b_log2));
                *io_block_size_128b_log2
            };
            let blocks_iter = match region.aligned_blocks_iter(block_size_128b_log2) {
                Ok(blocks_iter) => blocks_iter,
                Err(_) => return task::Poll::Ready(Ok((request, Err(nvblkdev_err_internal!())))),
            };
            let mut need_seek = true;
            for (physical_block_index, block_chunks) in blocks_iter {
                let block_begin_128b = physical_block_index << block_size_128b_log2;
                if block_begin_128b >= *io_blocks << *io_block_size_128b_log2
                    || ((*io_blocks << *io_block_size_128b_log2) - block_begin_128b) >> block_size_128b_log2 == 0
                {
                    return task::Poll::Ready(Ok((request, Err(blkdev::NvBlkDevIoError::IoBlockOutOfRange))));
                }

                if need_seek {
                    if let Err(e) = volume_file.seek(SeekFrom::Start(block_begin_128b << 7)) {
                        eprintln!(
                            "error: volume seek for write failed: error={}, position={}",
                            e,
                            block_begin_128b << 7
                        );
                        return task::Poll::Ready(Ok((request, Err(std_io_error_to_blkdev_io_error(e)))));
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
                        return task::Poll::Ready(Ok((request, Err(std_io_error_to_blkdev_io_error(e)))));
                    }
                }
            }
        } else {
            // The buffers are smaller than the volume block size, going through the bounce
            // buffer is necessary.
            let block_size_128b_log2 = *io_block_size_128b_log2;
            let blocks_iter = match region.aligned_blocks_iter(block_size_128b_log2) {
                Ok(blocks_iter) => blocks_iter,
                Err(_) => return task::Poll::Ready(Ok((request, Err(nvblkdev_err_internal!())))),
            };
            let mut need_seek = true;
            for (physical_block_index, block_chunks) in blocks_iter {
                let block_begin_128b = physical_block_index << block_size_128b_log2;
                if block_begin_128b >= *io_blocks << *io_block_size_128b_log2
                    || ((*io_blocks << *io_block_size_128b_log2) - block_begin_128b) >> block_size_128b_log2 == 0
                {
                    return task::Poll::Ready(Ok((request, Err(blkdev::NvBlkDevIoError::IoBlockOutOfRange))));
                }

                if need_seek {
                    if let Err(e) = volume_file.seek(SeekFrom::Start(block_begin_128b << 7)) {
                        eprintln!(
                            "error: volume seek for write failed: error={}, position={}",
                            e,
                            block_begin_128b << 7
                        );
                        return task::Poll::Ready(Ok((request, Err(std_io_error_to_blkdev_io_error(e)))));
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
                    io_block_bounce_buffer[offset_in_block..offset_in_block + buf_len].copy_from_slice(buf);
                }

                if let Err(e) = volume_file.write_all(io_block_bounce_buffer) {
                    eprintln!(
                        "error: volume write failed: error={}, position={}, size={}",
                        e,
                        block_begin_128b << 7,
                        1u64 << (block_size_128b_log2 + 7)
                    );
                    return task::Poll::Ready(Ok((request, Err(std_io_error_to_blkdev_io_error(e)))));
                }
            }
        }

        if let Err(e) = inner.volume_file.flush() {
            eprintln!("error: volume writes flushing failed: error={}", e);
            return task::Poll::Ready(Ok((request, Err(std_io_error_to_blkdev_io_error(e)))));
        }

        task::Poll::Ready(Ok((request, Ok(()))))
    }
}

/// [`NvBlkDev::WriteSyncFuture`](blkdev::NvBlkDev::WriteSyncFuture)
/// implementation for [`StdFileNvBlkDev`].
///
/// Also used for the
/// [`NvBlkDev::WriteBarrierFuture`](blkdev::NvBlkDev::WriteBarrierFuture).
pub struct StdFileNvBlkDevWriteSyncFuture;

impl blkdev::NvBlkDevFuture<StdFileNvBlkDev> for StdFileNvBlkDevWriteSyncFuture {
    type Output = Result<(), blkdev::NvBlkDevIoError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        dev: &StdFileNvBlkDev,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        let mut inner = dev.inner.lock();
        if let Err(e) = inner.volume_file.flush() {
            eprintln!("error: volume writes flushing failed: error={}", e);
            return task::Poll::Ready(Err(std_io_error_to_blkdev_io_error(e)));
        }

        if let Err(e) = inner.volume_file.sync_data() {
            eprintln!("error: volume sync request failed: error={}", e);
            return task::Poll::Ready(Err(std_io_error_to_blkdev_io_error(e)));
        }

        task::Poll::Ready(Ok(()))
    }
}

/// [`NvBlkDev::TrimFuture`](blkdev::NvBlkDev::TrimFuture) implementation for
/// [`StdFileNvBlkDev`].
pub struct StdFileNvBlkDevTrimFuture {
    io_block_index: u64,
    io_blocks: u64,
}

impl blkdev::NvBlkDevFuture<StdFileNvBlkDev> for StdFileNvBlkDevTrimFuture {
    type Output = Result<(), blkdev::NvBlkDevIoError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        dev: &StdFileNvBlkDev,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        let mut inner = dev.inner.lock();
        let StdFileNvBlkDevInner {
            volume_file,
            io_block_size_128b_log2,
            io_blocks,
            io_block_bounce_buffer,
            failed,
        } = &mut *inner;

        // No access to fallocate from std Rust. Write zeroes as a fallback alternative,
        // external tools might be able to do something with it.
        if self.io_blocks == 0 {
            return task::Poll::Ready(Ok(()));
        } else if *failed {
            return task::Poll::Ready(Err(blkdev::NvBlkDevIoError::IoFailure));
        } else if self.io_block_index > *io_blocks || *io_blocks - self.io_block_index < self.io_blocks {
            return task::Poll::Ready(Err(blkdev::NvBlkDevIoError::IoBlockOutOfRange));
        }

        if let Err(e) = volume_file.seek(SeekFrom::Start(self.io_block_index << (*io_block_size_128b_log2 + 7))) {
            eprintln!(
                "error: volume seek for write failed: error={}, position={}",
                e,
                self.io_block_index << (*io_block_size_128b_log2 + 7),
            );
            return task::Poll::Ready(Err(std_io_error_to_blkdev_io_error(e)));
        }

        io_block_bounce_buffer.fill(0u8);
        for i in 0..self.io_blocks {
            if let Err(e) = volume_file.write_all(io_block_bounce_buffer) {
                eprintln!(
                    "error: volume write for trim failed: error={}, position={}, size={}",
                    e,
                    (self.io_block_index + i) << (*io_block_size_128b_log2 + 7),
                    io_block_bounce_buffer.len()
                );
                return task::Poll::Ready(Err(std_io_error_to_blkdev_io_error(e)));
            }
        }

        if let Err(e) = inner.volume_file.flush() {
            eprintln!("error: volume writes flushing failed: error={}", e);
            return task::Poll::Ready(Err(std_io_error_to_blkdev_io_error(e)));
        }

        task::Poll::Ready(Ok(()))
    }
}
