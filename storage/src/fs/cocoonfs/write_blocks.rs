// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`WriteBlocksFuture`].

extern crate alloc;
use alloc::vec::Vec;

use crate::{
    chip::{self, ChunkedIoRegion, ChunkedIoRegionChunkRange, ChunkedIoRegionError},
    fs::{cocoonfs::layout, NvFsError, NvFsIoError},
    nvfs_err_internal,
    utils_common::bitmanip::BitManip as _,
};
use core::{mem, pin, task};

pub struct WriteBlocksFuture<C: chip::NvChip> {
    fut_state: WriteBlocksFutureState<C>,
}

enum WriteBlocksFutureState<C: chip::NvChip> {
    Init {
        extent: layout::PhysicalAllocBlockRange,
        src_io_blocks: Vec<Vec<u8>>,
        src_block_allocation_blocks_log2: u8,
        chip_io_block_allocation_blocks_log2: u8,
        allocation_block_size_128b_log2: u8,
    },
    Write {
        write_fut: C::WriteFuture<WriteBlocksNvChipRequest>,
    },
    Done,
}

impl<C: chip::NvChip> WriteBlocksFuture<C> {
    pub fn new(
        extent: &layout::PhysicalAllocBlockRange,
        src_io_blocks: Vec<Vec<u8>>,
        src_block_allocation_blocks_log2: u8,
        chip_io_block_allocation_blocks_log2: u8,
        allocation_block_size_128b_log2: u8,
    ) -> Self {
        Self {
            fut_state: WriteBlocksFutureState::Init {
                extent: *extent,
                src_io_blocks,
                src_block_allocation_blocks_log2,
                chip_io_block_allocation_blocks_log2,
                allocation_block_size_128b_log2,
            },
        }
    }
}

impl<C: chip::NvChip> chip::NvChipFuture<C> for WriteBlocksFuture<C> {
    type Output = Result<(Vec<Vec<u8>>, Result<(), NvFsError>), NvFsError>;

    fn poll(self: pin::Pin<&mut Self>, chip: &C, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                WriteBlocksFutureState::Init {
                    extent,
                    src_io_blocks,
                    src_block_allocation_blocks_log2,
                    chip_io_block_allocation_blocks_log2,
                    allocation_block_size_128b_log2,
                } => {
                    let write_request = match WriteBlocksNvChipRequest::new(
                        extent,
                        mem::take(src_io_blocks),
                        *src_block_allocation_blocks_log2 as u32,
                        *chip_io_block_allocation_blocks_log2 as u32,
                        *allocation_block_size_128b_log2 as u32,
                    ) {
                        Ok(write_request) => write_request,
                        Err((src_io_blocks, e)) => {
                            this.fut_state = WriteBlocksFutureState::Done;
                            return task::Poll::Ready(Ok((src_io_blocks, Err(e))));
                        }
                    };
                    let write_fut = match chip.write(write_request) {
                        Ok(Ok(write_fut)) => write_fut,
                        Ok(Err((write_request, e))) => {
                            this.fut_state = WriteBlocksFutureState::Done;
                            let WriteBlocksNvChipRequest {
                                region: _,
                                src_blocks: src_io_blocks,
                            } = write_request;
                            return task::Poll::Ready(Ok((src_io_blocks, Err(NvFsError::from(e)))));
                        }
                        Err(e) => {
                            this.fut_state = WriteBlocksFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    this.fut_state = WriteBlocksFutureState::Write { write_fut }
                }
                WriteBlocksFutureState::Write { write_fut } => {
                    match chip::NvChipFuture::poll(pin::Pin::new(write_fut), chip, cx) {
                        task::Poll::Ready(Ok((write_request, result))) => {
                            this.fut_state = WriteBlocksFutureState::Done;
                            let WriteBlocksNvChipRequest {
                                region: _,
                                src_blocks: src_io_blocks,
                            } = write_request;
                            return task::Poll::Ready(Ok((src_io_blocks, result.map_err(NvFsError::from))));
                        }
                        task::Poll::Ready(Err(e)) => {
                            this.fut_state = WriteBlocksFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    }
                }
                WriteBlocksFutureState::Done => unreachable!(),
            }
        }
    }
}

struct WriteBlocksNvChipRequest {
    region: ChunkedIoRegion,
    src_blocks: Vec<Vec<u8>>,
}

impl WriteBlocksNvChipRequest {
    fn new(
        extent: &layout::PhysicalAllocBlockRange,
        src_blocks: Vec<Vec<u8>>,
        src_block_allocation_blocks_log2: u32,
        chip_io_block_allocation_blocks_log2: u32,
        allocation_block_size_128b_log2: u32,
    ) -> Result<Self, (Vec<Vec<u8>>, NvFsError)> {
        // The target range must be aligned to the Chip IO block size and its length
        // must be a multiple of the source block size.
        if !(u64::from(extent.begin()) | u64::from(extent.end())).is_aligned_pow2(chip_io_block_allocation_blocks_log2)
            || src_block_allocation_blocks_log2 >= u64::BITS
            || !u64::from(extent.block_count()).is_aligned_pow2(src_block_allocation_blocks_log2)
        {
            return Err((src_blocks, nvfs_err_internal!()));
        }

        let extent_src_blocks_count =
            match usize::try_from(u64::from(extent.block_count()) >> src_block_allocation_blocks_log2) {
                Ok(io_blocks) => io_blocks,
                Err(_) => return Err((src_blocks, NvFsError::DimensionsNotSupported)),
            };
        // Unused excess buffers in src_io_blocks are explicitly allowed: this enabled
        // callers to allocate the Vec of source block buffers only once with maximum
        // needed length and resuse for different write requests.
        if extent_src_blocks_count > src_blocks.len() {
            return Err((src_blocks, nvfs_err_internal!()));
        }

        let physical_begin_128b = u64::from(extent.begin()) << allocation_block_size_128b_log2;
        let physical_end_128b = u64::from(extent.end()) << allocation_block_size_128b_log2;
        if physical_end_128b >> allocation_block_size_128b_log2 != u64::from(extent.end()) {
            return Err((src_blocks, NvFsError::IoError(NvFsIoError::RegionOutOfRange)));
        }
        let region = match ChunkedIoRegion::new(
            physical_begin_128b,
            physical_end_128b,
            src_block_allocation_blocks_log2 + allocation_block_size_128b_log2,
        ) {
            Ok(region) => region,
            Err(ChunkedIoRegionError::ChunkSizeOverflow) => {
                return Err((src_blocks, NvFsError::DimensionsNotSupported));
            }
            Err(ChunkedIoRegionError::InvalidBounds) => {
                return Err((src_blocks, nvfs_err_internal!()));
            }
            Err(ChunkedIoRegionError::ChunkIndexOverflow) => {
                // It's been checked above the the number of chunks, i.e. of source blocks,
                // fits an usize.
                debug_assert!(chip_io_block_allocation_blocks_log2 < src_block_allocation_blocks_log2);
                return Err((src_blocks, NvFsError::DimensionsNotSupported));
            }
            Err(ChunkedIoRegionError::RegionUnaligned) => {
                // It's been checked above that the extent's length is aligned to the source
                // block size size.
                return Err((src_blocks, nvfs_err_internal!()));
            }
        };

        Ok(Self { region, src_blocks })
    }
}

impl chip::NvChipWriteRequest for WriteBlocksNvChipRequest {
    fn region(&self) -> &ChunkedIoRegion {
        &self.region
    }

    fn get_source_buffer(&self, range: &ChunkedIoRegionChunkRange) -> Result<&[u8], chip::NvChipIoError> {
        let src_block_index = range.chunk().decompose_to_hierarchic_indices([]).0;
        Ok(&self.src_blocks[src_block_index][range.range_in_chunk().clone()])
    }
}
