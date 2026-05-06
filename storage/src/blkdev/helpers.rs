// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Convenience helpers for reading from and writing to a [`NvBlkDev`].

use crate::utils_common::{bitmanip::BitManip as _, fixed_vec::FixedVec};

use core::{convert, marker, ops, pin, task};

use super::{
    ChunkedIoRegion, ChunkedIoRegionChunkRange, ChunkedIoRegionError, NvBlkDev, NvBlkDevFuture, NvBlkDevIoError,
    NvBlkDevReadRequest, NvBlkDevWriteRequest,
};
use crate::nvblkdev_err_internal;

/// Write data gathered from equal, power-of-two sized buffers to a [`NvBlkDev`]
/// region.
///
/// # See also:
///
/// * [`NvBlkDevWriteRegionFuture`].
/// * [`NvBlkDevClearRegionFuture`].
/// * [`SplitBlocksBuffers`].
pub struct NvBlkDevWriteRegionBlocksGatherFuture<
    B: NvBlkDev,
    S: ops::Index<usize, Output: convert::AsRef<[u8]>> + marker::Unpin + marker::Send,
> {
    fut_state: NvBlkDevWriteRegionBlocksGatherFutureState<B, S>,
}

/// [`NvBlkDevWriteRegionBlocksGatherFuture`] state-machine state.
enum NvBlkDevWriteRegionBlocksGatherFutureState<
    B: NvBlkDev,
    S: ops::Index<usize, Output: convert::AsRef<[u8]>> + marker::Unpin + marker::Send,
> {
    Init {
        write_region_begin_dst_blocks: u64,
        write_region_dst_blocks: u64,
        dst_block_size_128b_log2: u8,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable self.
        src_blocks: Option<S>,
        src_blocks_index_offset: usize,
        src_block_size_128b_log2: u8,
    },
    Write {
        write_fut: B::WriteFuture<WriteRegionBlocksGatherNvBlkDevRequest<S>>,
    },
    Done,
}

impl<B: NvBlkDev, S: ops::Index<usize, Output: convert::AsRef<[u8]>> + marker::Unpin + marker::Send>
    NvBlkDevWriteRegionBlocksGatherFuture<B, S>
{
    /// Instantiate a [`NvBlkDevWriteRegionBlocksGatherFuture`].
    ///
    ///
    /// Instantiate a [`NvBlkDevWriteRegionBlocksGatherFuture`] for writing data
    /// gathered from the `src_blocks` sequence of source block buffers, each of
    /// length as specified by `src_block_size_128b_log2`, to a contiguous
    /// [`NvBlkDev`] region.
    ///
    /// The destination [`NvBlkDev`] region is given by the pair of
    /// `write_region_begin_dst_blocks` and `write_region_dst_blocks`, both
    /// in units of the destination block size as specified by
    /// `dst_block_size_128b_log2`. It must be aligned to the [Device IO Block
    /// size](NvBlkDev::io_block_size_128b_log2).
    ///
    /// The [`NvBlkDevWriteRegionBlocksGatherFuture`] assumes owership of the
    /// `src_blocks` buffers for the duration of the operation. They will
    /// eventually get returned from [`poll()`](Self::poll) upon completion.
    ///
    /// # Arguments:
    ///
    /// * `write_region_begin_dst_blocks` - Beginning of the write destination
    ///   on the [`NvBlkDev`], in units of the destination block size as
    ///   specified by `dst_block_size_128b_log2`. Must be aligned to the
    ///   [Device IO Block size](NvBlkDev::io_block_size_128b_log2) given by
    ///   `blkdev_io_block_size_128b_log2`.
    /// * `write_region_dst_blocks` - Number of destination blocks of size as as
    ///   specified by `dst_block_size_128b_log2` to write out. Must be aligned
    ///   to the [Device IO Block size](NvBlkDev::io_block_size_128b_log2) given
    ///   by `blkdev_io_block_size_128b_log2`. The write region's length in
    ///   units of Bytes must be reperesentable as an `u64` as well as an
    ///   `usize`.
    /// * `dst_block_size_128b_log2` - Base-2 logarithm of the destination block
    ///   size in units of 128B multiples. The write destination region's bounds
    ///   are specified in units of the destination block size.
    /// * `src_blocks` - The source buffers. Must have at least the number of
    ///   buffer entries following the `src_blocks_index_offset` position as is
    ///   required to accomodate for the `write_region_dst_blocks` destination
    ///   blocks, of size as specified by `dst_block_size_128b_log2`, with each
    ///   buffer's length being equal to the source block size as specified by
    ///   `src_block_size_128b_log2`.
    /// * `src_blocks_index_offset` - Offset to add to `src_blocks` buffer entry
    ///   indices. That is, the first `src_blocks_index_offset` entries in
    ///   `src_blocks` will be skipped over.
    /// * `src_block_size_128b_log2` - Base-2 logarithm of the source block size
    ///   in units of 128B multiples. Each buffer entry in `src_blocks` is
    ///   exactly one such source block in length. The total write region's
    ///   length must be evenly divisible by the source block size.
    pub fn new(
        write_region_begin_dst_blocks: u64,
        write_region_dst_blocks: u64,
        dst_block_size_128b_log2: u8,
        src_blocks: S,
        src_blocks_index_offset: usize,
        src_block_size_128b_log2: u8,
    ) -> Self {
        Self {
            fut_state: NvBlkDevWriteRegionBlocksGatherFutureState::Init {
                write_region_begin_dst_blocks,
                write_region_dst_blocks,
                dst_block_size_128b_log2,
                src_blocks: Some(src_blocks),
                src_blocks_index_offset,
                src_block_size_128b_log2,
            },
        }
    }
}

impl<B: NvBlkDev, S: ops::Index<usize, Output: convert::AsRef<[u8]>> + marker::Unpin + marker::Send> NvBlkDevFuture<B>
    for NvBlkDevWriteRegionBlocksGatherFuture<B, S>
{
    /// Output type of [`poll()`](Self::poll).
    ///
    /// A two-level [`Result`] is returned upon [future](NvBlkDevFuture)
    /// completion.
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering an internal error and the input data buffers are lost.
    /// * `Ok((src_blocks, ...))` - Otherwise the outer level [`Result`] is set
    ///   to [`Ok`] and a pair of the input data buffers, `src_blocks`, and the
    ///   operation result will get returned within:
    ///     * `Ok((src_blocks, Err(e)))` - In case of an error, the error reason
    ///       `e` is returned in an [`Err`].
    ///     * `Ok((src_blocks, Ok(())))` -  Otherwise, `Ok(())` will get
    ///       returned for the operation result on success.
    type Output = Result<(S, Result<(), NvBlkDevIoError>), NvBlkDevIoError>;

    fn poll(self: core::pin::Pin<&mut Self>, blkdev: &B, cx: &mut core::task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                NvBlkDevWriteRegionBlocksGatherFutureState::Init {
                    write_region_begin_dst_blocks,
                    write_region_dst_blocks,
                    dst_block_size_128b_log2,
                    src_blocks,
                    src_blocks_index_offset,
                    src_block_size_128b_log2,
                } => {
                    let src_blocks = match src_blocks.take() {
                        Some(src_blocks) => src_blocks,
                        None => {
                            this.fut_state = NvBlkDevWriteRegionBlocksGatherFutureState::Done;
                            return task::Poll::Ready(Err(nvblkdev_err_internal!()));
                        }
                    };

                    if *write_region_dst_blocks == 0 {
                        this.fut_state = NvBlkDevWriteRegionBlocksGatherFutureState::Done;
                        return task::Poll::Ready(Ok((src_blocks, Ok(()))));
                    }

                    let write_request = match WriteRegionBlocksGatherNvBlkDevRequest::new(
                        *write_region_begin_dst_blocks,
                        *write_region_dst_blocks,
                        *dst_block_size_128b_log2,
                        src_blocks,
                        *src_blocks_index_offset,
                        *src_block_size_128b_log2,
                        blkdev.io_blocks(),
                        blkdev.io_block_size_128b_log2(),
                    ) {
                        Ok(write_request) => write_request,
                        Err((src_blocks, e)) => {
                            this.fut_state = NvBlkDevWriteRegionBlocksGatherFutureState::Done;
                            return task::Poll::Ready(Ok((src_blocks, Err(e))));
                        }
                    };
                    let write_fut = match blkdev.write(write_request) {
                        Ok(Ok(write_fut)) => write_fut,
                        Ok(Err((write_request, e))) => {
                            this.fut_state = NvBlkDevWriteRegionBlocksGatherFutureState::Done;
                            return task::Poll::Ready(Ok((write_request.src_blocks, Err(e))));
                        }
                        Err(e) => {
                            this.fut_state = NvBlkDevWriteRegionBlocksGatherFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };

                    this.fut_state = NvBlkDevWriteRegionBlocksGatherFutureState::Write { write_fut };
                }
                NvBlkDevWriteRegionBlocksGatherFutureState::Write { write_fut } => {
                    match NvBlkDevFuture::poll(pin::Pin::new(write_fut), blkdev, cx) {
                        task::Poll::Ready(result) => {
                            this.fut_state = NvBlkDevWriteRegionBlocksGatherFutureState::Done;
                            return task::Poll::Ready(
                                result.map(|(write_request, result)| (write_request.src_blocks, result)),
                            );
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    }
                }
                NvBlkDevWriteRegionBlocksGatherFutureState::Done => unreachable!(),
            }
        }
    }
}

/// [`NvBlkDevWriteRequest`] implementation used internally by
/// [`NvBlkDevWriteRegionBlocksGatherFuture`].
struct WriteRegionBlocksGatherNvBlkDevRequest<
    S: ops::Index<usize, Output: convert::AsRef<[u8]>> + marker::Unpin + marker::Send,
> {
    region: ChunkedIoRegion,
    src_blocks: S,
    src_blocks_index_offset: usize,
}

impl<S: ops::Index<usize, Output: convert::AsRef<[u8]>> + marker::Unpin + marker::Send>
    WriteRegionBlocksGatherNvBlkDevRequest<S>
{
    /// Instantiate a [`WriteRegionBlocksGatherNvBlkDevRequest`].
    ///
    /// # Arguments:
    ///
    /// * `write_region_begin_dst_blocks` - Beginning of the write destination
    ///   on the [`NvBlkDev`], in units of the destination block size as
    ///   specified by `dst_block_size_128b_log2`. Must be aligned to the
    ///   [Device IO Block size](NvBlkDev::io_block_size_128b_log2) given by
    ///   `blkdev_io_block_size_128b_log2`.
    /// * `write_region_dst_blocks` - Number of destination blocks of size as as
    ///   specified by `dst_block_size_128b_log2` to write out. Must be non-zero
    ///   and aligned to the [Device IO Block
    ///   size](NvBlkDev::io_block_size_128b_log2) given by
    ///   `blkdev_io_block_size_128b_log2`. The write region's length in units
    ///   of Bytes must be reperesentable as an `u64` as well as an `usize`.
    /// * `dst_block_size_128b_log2` - Base-2 logarithm of the destination block
    ///   size in units of 128B multiples. The write destination region's bounds
    ///   are specified in units of the destination block size.
    /// * `src_blocks` - The source buffers. Must have at least the number of
    ///   buffer entries following the `src_blocks_index_offset` position as is
    ///   required to accomodate for the `write_region_dst_blocks` destination
    ///   blocks, of size as specified by `dst_block_size_128b_log2`, with each
    ///   buffer's length being equal to the source block size as specified by
    ///   `src_block_size_128b_log2`.
    /// * `src_blocks_index_offset` - Offset to add to `src_blocks` buffer entry
    ///   indices. That is, the first `src_blocks_index_offset` entries in
    ///   `src_blocks` will be skipped over.
    /// * `src_block_size_128b_log2` - Base-2 logarithm of the source block size
    ///   in units of 128B multiples. Each buffer entry in `src_blocks` is
    ///   exactly one such source block in length. The total write region's
    ///   length must be evenly divisible by the source block size.
    /// * `blkdev_io_blocks` - Value of [`NvBlkDev::io_blocks()`].
    /// * `blkdev_io_block_size_128b_log2` - Value of
    ///   [`NvBlkDev::io_block_size_128b_log2()`].
    #[allow(clippy::too_many_arguments)]
    fn new(
        write_region_begin_dst_blocks: u64,
        write_region_dst_blocks: u64,
        dst_block_size_128b_log2: u8,
        src_blocks: S,
        src_blocks_index_offset: usize,
        src_block_size_128b_log2: u8,
        blkdev_io_blocks: u64,
        blkdev_io_block_size_128b_log2: u32,
    ) -> Result<Self, (S, NvBlkDevIoError)> {
        let dst_block_size_128b_log2 = dst_block_size_128b_log2 as u32;
        let src_block_size_128b_log2 = src_block_size_128b_log2 as u32;

        debug_assert_ne!(write_region_dst_blocks, 0);

        if blkdev_io_block_size_128b_log2 >= u64::BITS - 7 {
            // If the device IO Block size is larger than what can get represented in an
            // u64, then the total write region's length cannot be evenly
            // divisible by it.
            return Err((src_blocks, nvblkdev_err_internal!()));
        } else if dst_block_size_128b_log2 >= u64::BITS - 7 {
            // If a single destination block exceeds u64::MAX in length, then the total
            // request length cannot get represented as an u64.
            return Err((src_blocks, NvBlkDevIoError::IoBlockOutOfRange));
        } else if src_block_size_128b_log2 >= {
            #[allow(clippy::unnecessary_min_or_max)]
            u64::BITS.min(usize::BITS)
        } - 7
        {
            // If the source block size is larger than what can get represented in an u64,
            // then the total write region's length cannot be evenly divisible by it.
            return Err((src_blocks, nvblkdev_err_internal!()));
        }

        if write_region_dst_blocks
            > ({
                #[allow(clippy::unnecessary_min_or_max)]
                u64::try_from(usize::MAX).unwrap_or(u64::MAX).min(u64::MAX)
            } >> (dst_block_size_128b_log2 + 7))
        {
            // The request's total length in units of Bytes cannot get represented as an u64
            // or usize.
            return Err((src_blocks, NvBlkDevIoError::IoBlockOutOfRange));
        }

        let write_region_src_blocks = if dst_block_size_128b_log2 >= src_block_size_128b_log2 {
            write_region_dst_blocks << (dst_block_size_128b_log2 - src_block_size_128b_log2)
        } else {
            let src_block_dst_blocks_log2 = src_block_size_128b_log2 - dst_block_size_128b_log2;
            let write_region_src_blocks = write_region_dst_blocks >> src_block_dst_blocks_log2;
            if write_region_src_blocks << src_block_dst_blocks_log2 != write_region_dst_blocks {
                // The write region's length is not an even multiple of the source block
                // size.
                return Err((src_blocks, nvblkdev_err_internal!()));
            }
            write_region_src_blocks
        };
        debug_assert!((0..usize::try_from(write_region_src_blocks).unwrap()).all(|i| {
            let src_block = src_blocks[src_blocks_index_offset + i].as_ref();
            src_block.len() == 1usize << (src_block_size_128b_log2 + 7)
        }));

        let (write_region_begin_blkdev_io_blocks, write_region_blkdev_io_blocks) = if blkdev_io_block_size_128b_log2
            > dst_block_size_128b_log2
        {
            let blkdev_io_block_dst_blocks_log2 = blkdev_io_block_size_128b_log2 - dst_block_size_128b_log2;
            let write_region_begin_blkdev_io_blocks = write_region_begin_dst_blocks >> blkdev_io_block_dst_blocks_log2;
            if write_region_begin_blkdev_io_blocks << blkdev_io_block_dst_blocks_log2 != write_region_begin_dst_blocks {
                // The write region's beginning is not aligned to the device IO Block size.
                return Err((src_blocks, nvblkdev_err_internal!()));
            }
            let write_region_blkdev_io_blocks = write_region_dst_blocks >> blkdev_io_block_dst_blocks_log2;
            if write_region_blkdev_io_blocks << blkdev_io_block_dst_blocks_log2 != write_region_dst_blocks {
                // The write region's length/end is not aligned to the device IO Block size.
                return Err((src_blocks, nvblkdev_err_internal!()));
            }
            (write_region_begin_blkdev_io_blocks, write_region_blkdev_io_blocks)
        } else {
            let dst_block_blkdev_io_blocks_log2 = dst_block_size_128b_log2 - blkdev_io_block_size_128b_log2;
            let write_region_begin_blkdev_io_blocks = write_region_begin_dst_blocks << dst_block_blkdev_io_blocks_log2;
            if write_region_begin_blkdev_io_blocks >> dst_block_blkdev_io_blocks_log2 != write_region_begin_dst_blocks {
                // The write region's beginning in units of device IO Blocks overflows an u64.
                return Err((src_blocks, NvBlkDevIoError::IoBlockOutOfRange));
            }
            let write_region_blkdev_io_blocks = write_region_dst_blocks << dst_block_blkdev_io_blocks_log2;
            if write_region_blkdev_io_blocks >> dst_block_blkdev_io_blocks_log2 != write_region_dst_blocks {
                // The write region's length in units of device IO Blocks overflows an u64.
                return Err((src_blocks, NvBlkDevIoError::IoBlockOutOfRange));
            }
            (write_region_begin_blkdev_io_blocks, write_region_blkdev_io_blocks)
        };

        let write_region_end_blkdev_io_blocks =
            match write_region_begin_blkdev_io_blocks.checked_add(write_region_blkdev_io_blocks) {
                Some(write_region_end_blkdev_io_blocks) => write_region_end_blkdev_io_blocks,
                None => return Err((src_blocks, NvBlkDevIoError::IoBlockOutOfRange)),
            };
        if write_region_end_blkdev_io_blocks > blkdev_io_blocks {
            return Err((src_blocks, NvBlkDevIoError::IoBlockOutOfRange));
        }

        let write_region_end_128b = write_region_end_blkdev_io_blocks << blkdev_io_block_size_128b_log2;
        if (write_region_end_128b << 7) >> (blkdev_io_block_size_128b_log2 + 7) != write_region_end_blkdev_io_blocks {
            // The write region's end in units of Bytes is not representable as an u64.
            return Err((src_blocks, NvBlkDevIoError::IoBlockOutOfRange));
        }

        let region = match ChunkedIoRegion::new(
            write_region_begin_blkdev_io_blocks << blkdev_io_block_size_128b_log2,
            write_region_end_128b,
            src_block_size_128b_log2,
        ) {
            Ok(region) => region,
            Err(e) => {
                return Err((
                    src_blocks,
                    match e {
                        ChunkedIoRegionError::ChunkSizeOverflow => {
                            // Cannot happen, the source block size fits an usize, as verified at function
                            // entry.
                            nvblkdev_err_internal!()
                        }
                        ChunkedIoRegionError::ChunkIndexOverflow => {
                            // Cannot happen, the write region's total length fits an usize, as
                            // verified above.
                            nvblkdev_err_internal!()
                        }
                        ChunkedIoRegionError::RegionUnaligned => {
                            // Cannot happen, the write region's length is a multiple of the source block
                            // size, as specified by src_block_size_128b_log2.
                            nvblkdev_err_internal!()
                        }
                        ChunkedIoRegionError::InvalidBounds => {
                            // The region's end is not before its beginning by construction.
                            nvblkdev_err_internal!()
                        }
                    },
                ));
            }
        };

        Ok(Self {
            region,
            src_blocks,
            src_blocks_index_offset,
        })
    }
}

impl<S: ops::Index<usize, Output: convert::AsRef<[u8]>> + marker::Unpin + marker::Send> NvBlkDevWriteRequest
    for WriteRegionBlocksGatherNvBlkDevRequest<S>
{
    fn region(&self) -> &ChunkedIoRegion {
        &self.region
    }

    fn get_source_buffer(&self, range: &ChunkedIoRegionChunkRange) -> Result<&[u8], NvBlkDevIoError> {
        let src_block_index = self.src_blocks_index_offset + range.chunk().decompose_to_hierarchic_indices([]).0;
        Ok(&self.src_blocks[src_block_index].as_ref()[range.range_in_chunk().clone()])
    }
}

/// Read from a [`NvBlkDev`] region and scatter into equal, power-of-two sized
/// buffers.
///
/// # See also:
///
/// * [`NvBlkDevReadRegionFuture`].
/// * [`SplitBlocksBuffers`].
pub struct NvBlkDevReadRegionBlocksScatterFuture<
    B: NvBlkDev,
    D: ops::IndexMut<usize, Output: convert::AsMut<[u8]>> + marker::Unpin + marker::Send,
> {
    fut_state: NvBlkDevReadRegionBlocksScatterFutureState<B, D>,
}

/// [`NvBlkDevReadRegionBlocksScatterFuture`] state-machine state.
enum NvBlkDevReadRegionBlocksScatterFutureState<
    B: NvBlkDev,
    D: ops::IndexMut<usize, Output: convert::AsMut<[u8]>> + marker::Unpin + marker::Send,
> {
    Init {
        read_region_begin_src_blocks: u64,
        read_region_src_blocks: u64,
        src_block_size_128b_log2: u8,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable self.
        dst_blocks: Option<D>,
        dst_blocks_index_offset: usize,
        dst_block_size_128b_log2: u8,
    },
    Read {
        read_fut: B::ReadFuture<ReadRegionBlocksScatterNvBlkDevRequest<D>>,
    },
    Done,
}

impl<B: NvBlkDev, D: ops::IndexMut<usize, Output: convert::AsMut<[u8]>> + marker::Unpin + marker::Send>
    NvBlkDevReadRegionBlocksScatterFuture<B, D>
{
    /// Instantiate a [`NvBlkDevReadRegionBlocksScatterFuture`].
    ///
    /// Instantiate a [`NvBlkDevReadRegionBlocksScatterFuture`] for reading from
    /// a contiguous [`NvBlkDev`] region into the `dst_blocks` sequence of
    /// destination block buffers, each of length as specified by
    /// `dst_block_size_128b_log2`.
    ///
    /// The source [`NvBlkDev`] region is given by the pair of
    /// `read_region_begin_src_blocks` and `read_region_src_blocks`, both in
    /// units of the source block size as specified by
    /// `src_block_size_128b_log2`. Unlike it's the case with
    /// [`NvBlkDevWriteRegionBlocksGatherFuture`], the read region doesn't need
    /// to be aligned to the [Device IO Block
    /// size](NvBlkDev::io_block_size_128b_log2).
    ///
    /// The [`NvBlkDevReadRegionBlocksScatterFuture`] assumes owership of the
    /// `dst_blocks` buffers for the duration of the operation. They will
    /// eventually get returned from [`poll()`](Self::poll) upon completion.
    ///
    /// # Arguments:
    ///
    /// * `read_region_begin_src_blocks` - Beginning of the read region the on
    ///   the [`NvBlkDev`], in units of the source block size as specified by
    ///   `src_block_size_128b_log2`.
    /// * `read_region_src_blocks` - Number of blocks of size as as specified by
    ///   `src_block_size_128b_log2` to read. Must be non-zero. The read
    ///   region's length in units of Bytes must be reperesentable as an `u64`
    ///   as well as an `usize`.
    /// * `src_block_size_128b_log2` - Base-2 logarithm of the source block size
    ///   in units of 128B multiples. The read region's bounds are specified in
    ///   units of the source block size.
    /// * `dst_blocks` - The destination buffers. Must have at least the number
    ///   of buffer entries following the `dst_blocks_index_offset` position as
    ///   is required to accomodate for the `read_region_src_blocks` source
    ///   blocks, of size as specified by `src_block_size_128b_log2`, with each
    ///   buffer's length being equal to the destination block size as specified
    ///   by `dst_block_size_128b_log2`.
    /// * `dst_blocks_index_offset` - Offset to add to `dst_blocks` buffer entry
    ///   indices. That is, the first `dst_blocks_index_offset` entries in
    ///   `dst_blocks` will be skipped over.
    /// * `dst_block_size_128b_log2` - Base-2 logarithm of the destination block
    ///   size in units of 128B multiples. Each buffer entry in `dst_blocks` is
    ///   exactly one such destination block in length. The total read region's
    ///   length must be evenly divisible by the destination block size.
    pub fn new(
        read_region_begin_src_blocks: u64,
        read_region_src_blocks: u64,
        src_block_size_128b_log2: u8,
        dst_blocks: D,
        dst_blocks_index_offset: usize,
        dst_block_size_128b_log2: u8,
    ) -> Self {
        Self {
            fut_state: NvBlkDevReadRegionBlocksScatterFutureState::Init {
                read_region_begin_src_blocks,
                read_region_src_blocks,
                src_block_size_128b_log2,
                dst_blocks: Some(dst_blocks),
                dst_blocks_index_offset,
                dst_block_size_128b_log2,
            },
        }
    }
}

impl<B: NvBlkDev, D: ops::IndexMut<usize, Output: convert::AsMut<[u8]>> + marker::Unpin + marker::Send>
    NvBlkDevFuture<B> for NvBlkDevReadRegionBlocksScatterFuture<B, D>
{
    /// Output type of [`poll()`](Self::poll).
    ///
    /// A two-level [`Result`] is returned upon [future](NvBlkDevFuture)
    /// completion.
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering an internal error and the input data buffers are lost.
    /// * `Ok((dst_blocks, ...))` - Otherwise the outer level [`Result`] is set
    ///   to [`Ok`] and a pair of the input data buffers, `dst_blocks`, and the
    ///   operation result will get returned within:
    ///     * `Ok((dst_blocks, Err(e)))` - In case of an error, the error reason
    ///       `e` is returned in an [`Err`].
    ///     * `Ok((dst_blocks, Ok(())))` -  Otherwise, `Ok(())` will get
    ///       returned for the operation result on success.
    type Output = Result<(D, Result<(), NvBlkDevIoError>), NvBlkDevIoError>;

    fn poll(self: core::pin::Pin<&mut Self>, blkdev: &B, cx: &mut core::task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                NvBlkDevReadRegionBlocksScatterFutureState::Init {
                    read_region_begin_src_blocks,
                    read_region_src_blocks,
                    src_block_size_128b_log2,
                    dst_blocks,
                    dst_blocks_index_offset,
                    dst_block_size_128b_log2,
                } => {
                    let dst_blocks = match dst_blocks.take() {
                        Some(dst_blocks) => dst_blocks,
                        None => {
                            this.fut_state = NvBlkDevReadRegionBlocksScatterFutureState::Done;
                            return task::Poll::Ready(Err(nvblkdev_err_internal!()));
                        }
                    };

                    if *read_region_src_blocks == 0 {
                        // Empty read request.
                        this.fut_state = NvBlkDevReadRegionBlocksScatterFutureState::Done;
                        return task::Poll::Ready(Ok((dst_blocks, Ok(()))));
                    }

                    let read_request = match ReadRegionBlocksScatterNvBlkDevRequest::new(
                        *read_region_begin_src_blocks,
                        *read_region_src_blocks,
                        *src_block_size_128b_log2,
                        dst_blocks,
                        *dst_blocks_index_offset,
                        *dst_block_size_128b_log2,
                        blkdev.io_blocks(),
                        blkdev.io_block_size_128b_log2(),
                    ) {
                        Ok(read_request) => read_request,
                        Err((dst_blocks, e)) => {
                            this.fut_state = NvBlkDevReadRegionBlocksScatterFutureState::Done;
                            return task::Poll::Ready(Ok((dst_blocks, Err(e))));
                        }
                    };
                    let read_fut = match blkdev.read(read_request) {
                        Ok(Ok(read_fut)) => read_fut,
                        Ok(Err((read_request, e))) => {
                            this.fut_state = NvBlkDevReadRegionBlocksScatterFutureState::Done;
                            return task::Poll::Ready(Ok((read_request.dst_blocks, Err(e))));
                        }
                        Err(e) => {
                            this.fut_state = NvBlkDevReadRegionBlocksScatterFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };

                    this.fut_state = NvBlkDevReadRegionBlocksScatterFutureState::Read { read_fut };
                }
                NvBlkDevReadRegionBlocksScatterFutureState::Read { read_fut } => {
                    match NvBlkDevFuture::poll(pin::Pin::new(read_fut), blkdev, cx) {
                        task::Poll::Ready(result) => {
                            this.fut_state = NvBlkDevReadRegionBlocksScatterFutureState::Done;
                            return task::Poll::Ready(
                                result.map(|(read_request, result)| (read_request.dst_blocks, result)),
                            );
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    }
                }
                NvBlkDevReadRegionBlocksScatterFutureState::Done => unreachable!(),
            }
        }
    }
}

/// [`NvBlkDevReadRequest`] implementation used internally by
/// [`NvBlkDevReadRegionBlocksScatterFuture`].
struct ReadRegionBlocksScatterNvBlkDevRequest<
    D: ops::IndexMut<usize, Output: convert::AsMut<[u8]>> + marker::Unpin + marker::Send,
> {
    region: ChunkedIoRegion,
    dst_blocks: D,
    dst_blocks_index_offset: usize,
    aligned_read_region_head_padding_request_dst_blocks: u64,
    read_region_request_dst_blocks: u64,
    dst_block_size_128b_log2: u8,
}

impl<D: ops::IndexMut<usize, Output: convert::AsMut<[u8]>> + marker::Unpin + marker::Send>
    ReadRegionBlocksScatterNvBlkDevRequest<D>
{
    /// Instantiate a [`ReadRegionBlocksScatterNvBlkDevRequest`].
    ///
    /// # Arguments:
    ///
    /// * `read_region_begin_src_blocks` - Beginning of the read region the on
    ///   the [`NvBlkDev`], in units of the source block size as specified by
    ///   `src_block_size_128b_log2`.
    /// * `read_region_src_blocks` - Number of blocks of size as as specified by
    ///   `src_block_size_128b_log2` to read. Must be non-zero. The read
    ///   region's length in units of Bytes must be reperesentable as an `u64`
    ///   as well as an `usize`.
    /// * `src_block_size_128b_log2` - Base-2 logarithm of the source block size
    ///   in units of 128B multiples. The read region's bounds are specified in
    ///   units of the source block size.
    /// * `dst_blocks` - The destination buffers. Must have at least the number
    ///   of buffer entries following the `dst_blocks_index_offset` position as
    ///   is required to accomodate for the `read_region_src_blocks` source
    ///   blocks, of size as specified by `src_block_size_128b_log2`, with each
    ///   buffer's length being equal to the destination block size as specified
    ///   by `dst_block_size_128b_log2`.
    /// * `dst_blocks_index_offset` - Offset to add to `dst_blocks` buffer entry
    ///   indices. That is, the first `dst_blocks_index_offset` entries in
    ///   `dst_blocks` will be skipped over.
    /// * `dst_block_size_128b_log2` - Base-2 logarithm of the destination block
    ///   size in units of 128B multiples. Each buffer entry in `dst_blocks` is
    ///   exactly one such destination block in length. The total read region's
    ///   length must be evenly divisible by the destination block size.
    /// * `blkdev_io_blocks` - Value of [`NvBlkDev::io_blocks()`].
    /// * `blkdev_io_block_size_128b_log2` - Value of
    ///   [`NvBlkDev::io_block_size_128b_log2()`].
    #[allow(clippy::too_many_arguments)]
    fn new(
        read_region_begin_src_blocks: u64,
        read_region_src_blocks: u64,
        src_block_size_128b_log2: u8,
        mut dst_blocks: D,
        dst_blocks_index_offset: usize,
        dst_block_size_128b_log2: u8,
        blkdev_io_blocks: u64,
        blkdev_io_block_size_128b_log2: u32,
    ) -> Result<Self, (D, NvBlkDevIoError)> {
        debug_assert_ne!(read_region_src_blocks, 0);

        if blkdev_io_block_size_128b_log2 >= u64::BITS {
            return Err((dst_blocks, nvblkdev_err_internal!()));
        } else if blkdev_io_block_size_128b_log2
            >= usize::BITS - 1 + (src_block_size_128b_log2 as u32).min(dst_block_size_128b_log2 as u32)
        {
            // Bail out, the alignment of the read region to the Device IO Block size in
            // units of source blocks or destination blocks could overflow an
            // usize.
            return Err((dst_blocks, NvBlkDevIoError::OperationNotSupported));
        } else if src_block_size_128b_log2 as u32 >= u64::BITS - 7 {
            // If a single source block exceeds u64::MAX in length, then the total request
            // length cannot get represented as an u64.
            return Err((dst_blocks, NvBlkDevIoError::IoBlockOutOfRange));
        } else if dst_block_size_128b_log2 as u32 >= {
            #[allow(clippy::unnecessary_min_or_max)]
            u64::BITS.min(usize::BITS)
        } - 7
        {
            // If the destination block size is larger than what can get represented in an
            // u64, then the total read region's length cannot be evenly
            // divisible by it.
            return Err((dst_blocks, nvblkdev_err_internal!()));
        }

        if read_region_src_blocks
            > ({
                #[allow(clippy::unnecessary_min_or_max)]
                u64::try_from(usize::MAX).unwrap_or(u64::MAX).min(u64::MAX)
            } >> (src_block_size_128b_log2 as u32 + 7))
        {
            // The request's total length in units of Bytes cannot get represented as an u64
            // or usize.
            return Err((dst_blocks, NvBlkDevIoError::IoBlockOutOfRange));
        }

        let read_region_dst_blocks = if src_block_size_128b_log2 as u32 >= dst_block_size_128b_log2 as u32 {
            read_region_src_blocks << (src_block_size_128b_log2 as u32 - dst_block_size_128b_log2 as u32)
        } else {
            let dst_block_src_blocks_log2 = dst_block_size_128b_log2 as u32 - src_block_size_128b_log2 as u32;
            let read_region_dst_blocks = read_region_src_blocks >> dst_block_src_blocks_log2;
            if read_region_dst_blocks << dst_block_src_blocks_log2 != read_region_src_blocks {
                // The read region's length is not an even multiple of the destination block
                // size.
                return Err((dst_blocks, nvblkdev_err_internal!()));
            }
            read_region_dst_blocks
        };
        debug_assert!((0..usize::try_from(read_region_dst_blocks).unwrap()).all(|i| {
            let dst_block = dst_blocks[dst_blocks_index_offset + i].as_mut();
            dst_block.is_empty() || dst_block.len() == 1usize << (dst_block_size_128b_log2 as u32 + 7)
        }));

        let (
            aligned_read_region_begin_blkdev_io_blocks,
            aligned_read_region_blkdev_io_blocks,
            request_dst_block_size_128b_log,
            aligned_read_region_head_padding_request_dst_blocks,
            read_region_request_dst_blocks,
        ) = if blkdev_io_block_size_128b_log2 > src_block_size_128b_log2 as u32 {
            // Align the read region to a multiple of the Device IO Block size.
            let blkdev_io_block_src_blocks_log2 = blkdev_io_block_size_128b_log2 - src_block_size_128b_log2 as u32;
            let aligned_read_region_begin_blkdev_io_blocks =
                read_region_begin_src_blocks >> blkdev_io_block_src_blocks_log2;
            let aligned_read_region_head_padding_src_blocks = read_region_begin_src_blocks
                - (aligned_read_region_begin_blkdev_io_blocks << blkdev_io_block_src_blocks_log2);
            // The addition does not overflow: read_region_src_blocks is known to have the
            // upper 7 bits clear,
            // and aligned_read_region_head_padding_src_blocks is strictly less than a
            // Device IO Block, so has the MSB clear as well.
            let aligned_read_region_blkdev_io_blocks =
                ((aligned_read_region_head_padding_src_blocks + read_region_src_blocks - 1)
                    >> blkdev_io_block_src_blocks_log2)
                    + 1;
            let (
                request_dst_block_size_128b_log,
                aligned_read_region_head_padding_request_dst_blocks,
                read_region_request_dst_blocks,
            ) = if dst_block_size_128b_log2 as u32 <= src_block_size_128b_log2 as u32 {
                let src_block_dst_blocks_log2 = src_block_size_128b_log2 as u32 - dst_block_size_128b_log2 as u32;
                (
                    dst_block_size_128b_log2,
                    aligned_read_region_head_padding_src_blocks << src_block_dst_blocks_log2,
                    read_region_dst_blocks,
                )
            } else {
                let dst_block_src_blocks_log2 = dst_block_size_128b_log2 as u32 - src_block_size_128b_log2 as u32;
                let aligned_read_region_head_padding_dst_blocks =
                    aligned_read_region_head_padding_src_blocks >> dst_block_src_blocks_log2;
                if aligned_read_region_head_padding_dst_blocks << dst_block_src_blocks_log2
                    == aligned_read_region_head_padding_src_blocks
                {
                    // The head padding happens to be a multiple of the destination block size.
                    // Retain the larger dst_block_size_128b_log2 buffer chunk size for the request.
                    (
                        dst_block_size_128b_log2,
                        aligned_read_region_head_padding_dst_blocks,
                        read_region_dst_blocks,
                    )
                } else {
                    // The head padding is not a multiple of the destination block size,
                    // but, by construction, of the smaller source block size. Lower
                    // the request buffer chunk size to src_block_size_128b_log2.
                    (
                        src_block_size_128b_log2,
                        aligned_read_region_head_padding_src_blocks,
                        read_region_src_blocks,
                    )
                }
            };
            (
                aligned_read_region_begin_blkdev_io_blocks,
                aligned_read_region_blkdev_io_blocks,
                request_dst_block_size_128b_log,
                aligned_read_region_head_padding_request_dst_blocks,
                read_region_request_dst_blocks,
            )
        } else {
            let src_block_blkdev_io_blocks_log2 = src_block_size_128b_log2 as u32 - blkdev_io_block_size_128b_log2;
            let read_region_begin_blkdev_io_blocks = read_region_begin_src_blocks << src_block_blkdev_io_blocks_log2;
            if read_region_begin_blkdev_io_blocks >> src_block_blkdev_io_blocks_log2 != read_region_begin_src_blocks {
                // The read region's beginning in units of device IO Blocks overflows an u64.
                return Err((dst_blocks, NvBlkDevIoError::IoBlockOutOfRange));
            }
            let read_region_blkdev_io_blocks = read_region_src_blocks << src_block_blkdev_io_blocks_log2;
            if read_region_blkdev_io_blocks >> src_block_blkdev_io_blocks_log2 != read_region_src_blocks {
                // The read region's length in units of device IO Blocks overflows an u64.
                return Err((dst_blocks, NvBlkDevIoError::IoBlockOutOfRange));
            }
            (
                read_region_begin_blkdev_io_blocks,
                read_region_blkdev_io_blocks,
                dst_block_size_128b_log2,
                0,
                read_region_dst_blocks,
            )
        };

        let aligned_read_region_end_blkdev_io_blocks =
            match aligned_read_region_begin_blkdev_io_blocks.checked_add(aligned_read_region_blkdev_io_blocks) {
                Some(read_region_end_blkdev_io_blocks) => read_region_end_blkdev_io_blocks,
                None => return Err((dst_blocks, NvBlkDevIoError::IoBlockOutOfRange)),
            };
        if aligned_read_region_end_blkdev_io_blocks > blkdev_io_blocks {
            return Err((dst_blocks, NvBlkDevIoError::IoBlockOutOfRange));
        }

        let read_region_end_128b = aligned_read_region_end_blkdev_io_blocks << blkdev_io_block_size_128b_log2;
        if read_region_end_128b >> blkdev_io_block_size_128b_log2 != aligned_read_region_end_blkdev_io_blocks {
            return Err((dst_blocks, NvBlkDevIoError::IoBlockOutOfRange));
        }

        let region = match ChunkedIoRegion::new(
            aligned_read_region_begin_blkdev_io_blocks << blkdev_io_block_size_128b_log2,
            read_region_end_128b,
            request_dst_block_size_128b_log as u32,
        ) {
            Ok(region) => region,
            Err(e) => {
                return Err((
                    dst_blocks,
                    match e {
                        ChunkedIoRegionError::ChunkSizeOverflow => {
                            // Cannot happen, the source block size fits an usize, as verified at
                            // function entry, and request_dst_block_size_128b_log <=
                            // dst_block_size_128b_log2.
                            nvblkdev_err_internal!()
                        }
                        ChunkedIoRegionError::ChunkIndexOverflow => {
                            // The requested read region's total length in units of Bytes fits as usize,
                            // as has been checked above. The alignment to the device IO Block size
                            // might have increased the length, but the device IO Block size had
                            // been bounded at function entry so that the aligned read region's length
                            // in units of either the source or the destination block size wouldn't
                            // overflow an usize. So we cannot end up here.
                            nvblkdev_err_internal!()
                        }
                        ChunkedIoRegionError::RegionUnaligned => {
                            // Cannot happen, the read region's length is a multiple of the destination
                            // block size as verified above, and
                            // request_dst_block_size_128b_log <= dst_block_size_128b_log2.
                            nvblkdev_err_internal!()
                        }
                        ChunkedIoRegionError::InvalidBounds => {
                            // The region's end is not before its beginning by construction.
                            nvblkdev_err_internal!()
                        }
                    },
                ));
            }
        };

        Ok(Self {
            region,
            dst_blocks,
            dst_blocks_index_offset,
            aligned_read_region_head_padding_request_dst_blocks,
            read_region_request_dst_blocks,
            dst_block_size_128b_log2,
        })
    }
}

impl<D: ops::IndexMut<usize, Output: convert::AsMut<[u8]>> + marker::Unpin + marker::Send> NvBlkDevReadRequest
    for ReadRegionBlocksScatterNvBlkDevRequest<D>
{
    fn region(&self) -> &ChunkedIoRegion {
        &self.region
    }

    fn get_destination_buffer(
        &mut self,
        range: &ChunkedIoRegionChunkRange,
    ) -> Result<Option<&mut [u8]>, NvBlkDevIoError> {
        let request_dst_block_index_in_aligned_read_region = range.chunk().decompose_to_hierarchic_indices([]).0;
        if u64::try_from(request_dst_block_index_in_aligned_read_region)
            .ok()
            .map(|request_dst_block_index_in_aligned_read_region| {
                request_dst_block_index_in_aligned_read_region
                    < self.aligned_read_region_head_padding_request_dst_blocks
            })
            .unwrap_or(false)
        {
            // Within head padding to align the requested read region with the Device IO
            // Block size.
            return Ok(None);
        }
        // As per the comparison above,
        // aligned_read_region_head_padding_request_dst_blocks
        // <=  request_dst_block_index_in_aligned_read_region and the latter is an
        // usize, hence casting the former to an usize can't overflow.
        let request_dst_block_index_in_read_region = request_dst_block_index_in_aligned_read_region
            - self.aligned_read_region_head_padding_request_dst_blocks as usize;
        if usize::try_from(self.read_region_request_dst_blocks)
            .map(|read_region_request_dst_blocks| {
                request_dst_block_index_in_read_region >= read_region_request_dst_blocks
            })
            .unwrap_or(false)
        {
            // Within tail paddding to align the requested read region with the Device IO
            // Block size.
            return Ok(None);
        }

        let request_dst_block_size_128b_log2 = self.region.chunk_size_128b_log2();
        let dst_block_request_dst_blocks_log2 = self.dst_block_size_128b_log2 as u32 - request_dst_block_size_128b_log2;
        let dst_block_index_in_read_region =
            request_dst_block_index_in_read_region >> dst_block_request_dst_blocks_log2;
        let dst_block = self.dst_blocks[self.dst_blocks_index_offset + dst_block_index_in_read_region].as_mut();
        if !dst_block.is_empty() {
            let request_dst_block_index_in_dst_block =
                request_dst_block_index_in_read_region & usize::trailing_bits_mask(dst_block_request_dst_blocks_log2);
            let request_dst_block_in_dst_block_begin =
                request_dst_block_index_in_dst_block << (request_dst_block_size_128b_log2 + 7);
            let request_dst_block_in_dst_block_end =
                (request_dst_block_index_in_dst_block + 1) << (request_dst_block_size_128b_log2 + 7);
            let request_dst_block =
                &mut dst_block[request_dst_block_in_dst_block_begin..request_dst_block_in_dst_block_end];
            Ok(Some(&mut request_dst_block[range.range_in_chunk().clone()]))
        } else {
            Ok(None)
        }
    }
}

/// Write data from a single, linear buffer to a [`NvBlkDev`] region.
///
/// # See also:
///
/// * [`NvBlkDevWriteRegionBlocksGatherFuture`].
/// * [`NvBlkDevClearRegionFuture`].
pub struct NvBlkDevWriteRegionFuture<B: NvBlkDev, S: convert::AsRef<[u8]> + marker::Unpin + marker::Send> {
    write_fut: NvBlkDevWriteRegionBlocksGatherFuture<B, SingletonBufferAsBlocksBuffers<S>>,
}

impl<B: NvBlkDev, S: convert::AsRef<[u8]> + marker::Unpin + marker::Send> NvBlkDevWriteRegionFuture<B, S> {
    /// Instantiate a [`NvBlkDevWriteRegionFuture`].
    ///
    /// Instantiate a [`NvBlkDevWriteRegionFuture`] for writing data provided in
    /// a single, linear `src` buffer to a contiguous [`NvBlkDev`] region.
    ///
    /// The destination [`NvBlkDev`] region is given by the pair of
    /// `write_region_begin_dst_blocks` and `write_region_dst_blocks`, both
    /// in units of the destination block size as specified by
    /// `dst_block_size_128b_log2`. It must be aligned to the [Device IO Block
    /// size](NvBlkDev::io_block_size_128b_log2).
    ///
    /// Even though the `src` buffer is linear, it is assumed to be partitioned
    /// into logical source blocks, of size as specified by
    /// `src_block_size_128b_log2`. The significance is that
    /// `src_blocks_index_offset` is relative to that block size, and also, that
    /// larger buffer length alignments may potentially foster a more efficient
    /// processing at the [`NvBlkDev`] implementation side.
    ///
    /// The [`NvBlkDevWriteRegionFuture`] assumes owership of the `src` buffer
    /// for the duration of the operation. It will eventually get returned
    /// from [`poll()`](Self::poll) upon completion.
    ///
    /// # Arguments:
    ///
    /// * `write_region_begin_dst_blocks` - Beginning of the write destination
    ///   on the [`NvBlkDev`], in units of the destination block size as
    ///   specified by `dst_block_size_128b_log2`. Must be aligned to the
    ///   [Device IO Block size](NvBlkDev::io_block_size_128b_log2) given by
    ///   `blkdev_io_block_size_128b_log2`.
    /// * `write_region_dst_blocks` - Number of destination blocks of size as as
    ///   specified by `dst_block_size_128b_log2` to write out. Must be aligned
    ///   to the [Device IO Block size](NvBlkDev::io_block_size_128b_log2) given
    ///   by `blkdev_io_block_size_128b_log2`.
    /// * `dst_block_size_128b_log2` - Base-2 logarithm of the destination block
    ///   size in units of 128B multiples. The write destination region's bounds
    ///   are specified in units of the destination block size.
    /// * `src` - The source buffer. Its length must be large enough to
    ///   accomodate for `src_block_index_offset` source blocks of size as
    ///   specified by `src_block_size_128b_log2`, followed by
    ///   `write_region_dst_blocks` destination blocks of size as specified by
    ///   `dst_block_size_128b_log2`.
    /// * `src_blocks_index_offset` - Offset into the `src` buffer in units of
    ///   source blocks of size as specified by `src_block_size_128b_log2`. That
    ///   is, the first `src_blocks_index_offset << (src_block_size_128b_log2 +
    ///   7)` bytes will be skipped over.
    /// * `src_block_size_128b_log2` - Base-2 logarithm of the source block size
    ///   in units of 128B multiples. The total write region's length must be
    ///   evenly divisible by the source block size.
    pub fn new(
        write_region_begin_dst_blocks: u64,
        write_region_dst_blocks: u64,
        dst_block_size_128b_log2: u8,
        src: S,
        src_blocks_index_offset: usize,
        src_block_size_128b_log2: u8,
    ) -> Self {
        Self {
            write_fut: NvBlkDevWriteRegionBlocksGatherFuture::new(
                write_region_begin_dst_blocks,
                write_region_dst_blocks,
                dst_block_size_128b_log2,
                SingletonBufferAsBlocksBuffers {
                    buffer: src,
                    block_size_128b_log2: src_block_size_128b_log2,
                },
                src_blocks_index_offset,
                src_block_size_128b_log2,
            ),
        }
    }
}

impl<B: NvBlkDev, S: convert::AsRef<[u8]> + marker::Unpin + marker::Send> NvBlkDevFuture<B>
    for NvBlkDevWriteRegionFuture<B, S>
{
    /// Output type of [`poll()`](Self::poll).
    ///
    /// A two-level [`Result`] is returned upon [future](NvBlkDevFuture)
    /// completion.
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering an internal error and the input data buffers are lost.
    /// * `Ok((src, ...))` - Otherwise the outer level [`Result`] is set to
    ///   [`Ok`] and a pair of the input data buffer, `src`, and the operation
    ///   result will get returned within:
    ///     * `Ok((src, Err(e)))` - In case of an error, the error reason `e` is
    ///       returned in an [`Err`].
    ///     * `Ok((src, Ok(())))` -  Otherwise, `Ok(())` will get returned for
    ///       the operation result on success.
    type Output = Result<(S, Result<(), NvBlkDevIoError>), NvBlkDevIoError>;

    fn poll(self: pin::Pin<&mut Self>, blkdev: &B, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        NvBlkDevFuture::poll(pin::Pin::new(&mut this.write_fut), blkdev, cx)
            .map(|result| result.map(|(src_blocks, result)| (src_blocks.buffer, result)))
    }
}

/// Write zeros to a [`NvBlkDev`] region.
pub struct NvBlkDevClearRegionFuture<B: NvBlkDev> {
    fut_state: NvBlkDevClearRegionFutureState<B>,
}

/// [`NvBlkDevClearRegionFuture`] state-machine state.
enum NvBlkDevClearRegionFutureState<B: NvBlkDev> {
    Init {
        write_region_begin_dst_blocks: u64,
        write_region_dst_blocks: u64,
        dst_block_size_128b_log2: u8,
    },
    Write {
        write_fut: B::WriteFuture<ClearRegionNvBlkDevRequest>,
    },
    Done,
}

impl<B: NvBlkDev> NvBlkDevClearRegionFuture<B> {
    /// Instantiate a [`NvBlkDevClearRegionFuture`].
    ///
    /// Instantiate a [`NvBlkDevClearRegionFuture`] for writing zeros to a
    /// contiguous [`NvBlkDev`] region.
    ///
    /// The destination [`NvBlkDev`] region is given by the pair of
    /// `write_region_begin_dst_blocks` and `write_region_dst_blocks`, both
    /// in units of the destination block size as specified by
    /// `dst_block_size_128b_log2`. It must be aligned to the [Device IO Block
    /// size](NvBlkDev::io_block_size_128b_log2).
    ///
    /// # Arguments:
    ///
    /// * `write_region_begin_dst_blocks` - Beginning of the write destination
    ///   on the [`NvBlkDev`], in units of the destination block size as
    ///   specified by `dst_block_size_128b_log2`. Must be aligned to the
    ///   [Device IO Block size](NvBlkDev::io_block_size_128b_log2) given by
    ///   `blkdev_io_block_size_128b_log2`.
    /// * `write_region_dst_blocks` - Number of destination blocks of size as as
    ///   specified by `dst_block_size_128b_log2` to write out. Must be aligned
    ///   to the [Device IO Block size](NvBlkDev::io_block_size_128b_log2) given
    ///   by `blkdev_io_block_size_128b_log2`. The write region's length in
    ///   units of Bytes must be reperesentable as an `u64` as well as an
    ///   `usize`.
    /// * `dst_block_size_128b_log2` - Base-2 logarithm of the destination block
    ///   size in units of 128B multiples. The write destination region's bounds
    ///   are specified in units of the destination block size.
    pub fn new(write_region_begin_dst_blocks: u64, write_region_dst_blocks: u64, dst_block_size_128b_log2: u8) -> Self {
        Self {
            fut_state: NvBlkDevClearRegionFutureState::Init {
                write_region_begin_dst_blocks,
                write_region_dst_blocks,
                dst_block_size_128b_log2,
            },
        }
    }
}

impl<B: NvBlkDev> NvBlkDevFuture<B> for NvBlkDevClearRegionFuture<B> {
    type Output = Result<(), NvBlkDevIoError>;

    fn poll(self: pin::Pin<&mut Self>, blkdev: &B, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                NvBlkDevClearRegionFutureState::Init {
                    write_region_begin_dst_blocks,
                    write_region_dst_blocks,
                    dst_block_size_128b_log2,
                } => {
                    if *write_region_dst_blocks == 0 {
                        this.fut_state = NvBlkDevClearRegionFutureState::Done;
                        return task::Poll::Ready(Ok(()));
                    }

                    let blkdev_io_blocks = blkdev.io_blocks();
                    let blkdev_io_block_size_128b_log2 = blkdev.io_block_size_128b_log2();
                    if blkdev_io_block_size_128b_log2 >= u64::BITS - 7 {
                        // If the device IO Block size is larger than what can get represented in an
                        // u64, then the total write region's length cannot be evenly
                        // divisible by it.
                        this.fut_state = NvBlkDevClearRegionFutureState::Done;
                        return task::Poll::Ready(Err(nvblkdev_err_internal!()));
                    } else if *dst_block_size_128b_log2 as u32 >= u64::BITS - 7 {
                        // If a single destination block exceeds u64::MAX in length, then the total
                        // request length cannot get represented as an u64.
                        this.fut_state = NvBlkDevClearRegionFutureState::Done;
                        return task::Poll::Ready(Err(NvBlkDevIoError::IoBlockOutOfRange));
                    } else if *write_region_dst_blocks
                        > ({
                            #[allow(clippy::unnecessary_min_or_max)]
                            u64::try_from(usize::MAX).unwrap_or(u64::MAX).min(u64::MAX)
                        } >> (*dst_block_size_128b_log2 as u32 + 7))
                    {
                        // The request's total length in units of Bytes cannot get represented as an u64
                        // or usize.
                        this.fut_state = NvBlkDevClearRegionFutureState::Done;
                        return task::Poll::Ready(Err(NvBlkDevIoError::IoBlockOutOfRange));
                    }

                    let (write_region_begin_blkdev_io_blocks, write_region_blkdev_io_blocks) =
                        if blkdev_io_block_size_128b_log2 > *dst_block_size_128b_log2 as u32 {
                            let blkdev_io_block_dst_blocks_log2 =
                                blkdev_io_block_size_128b_log2 - *dst_block_size_128b_log2 as u32;
                            let write_region_begin_blkdev_io_blocks =
                                *write_region_begin_dst_blocks >> blkdev_io_block_dst_blocks_log2;
                            if write_region_begin_blkdev_io_blocks << blkdev_io_block_dst_blocks_log2
                                != *write_region_begin_dst_blocks
                            {
                                // The write region's beginning is not aligned to the device IO Block size.
                                this.fut_state = NvBlkDevClearRegionFutureState::Done;
                                return task::Poll::Ready(Err(nvblkdev_err_internal!()));
                            }
                            let write_region_blkdev_io_blocks =
                                *write_region_dst_blocks >> blkdev_io_block_dst_blocks_log2;
                            if write_region_blkdev_io_blocks << blkdev_io_block_dst_blocks_log2
                                != *write_region_dst_blocks
                            {
                                // The write region's length/end is not aligned to the device IO Block size.
                                this.fut_state = NvBlkDevClearRegionFutureState::Done;
                                return task::Poll::Ready(Err(nvblkdev_err_internal!()));
                            }
                            (write_region_begin_blkdev_io_blocks, write_region_blkdev_io_blocks)
                        } else {
                            let dst_block_blkdev_io_blocks_log2 =
                                *dst_block_size_128b_log2 as u32 - blkdev_io_block_size_128b_log2;
                            let write_region_begin_blkdev_io_blocks =
                                *write_region_begin_dst_blocks << dst_block_blkdev_io_blocks_log2;
                            if write_region_begin_blkdev_io_blocks >> dst_block_blkdev_io_blocks_log2
                                != *write_region_begin_dst_blocks
                            {
                                // The write region's beginning in units of device IO Blocks overflows an u64.
                                this.fut_state = NvBlkDevClearRegionFutureState::Done;
                                return task::Poll::Ready(Err(NvBlkDevIoError::IoBlockOutOfRange));
                            }
                            let write_region_blkdev_io_blocks =
                                *write_region_dst_blocks << dst_block_blkdev_io_blocks_log2;
                            if write_region_blkdev_io_blocks >> dst_block_blkdev_io_blocks_log2
                                != *write_region_dst_blocks
                            {
                                // The write region's length in units of device IO Blocks overflows an u64.
                                this.fut_state = NvBlkDevClearRegionFutureState::Done;
                                return task::Poll::Ready(Err(NvBlkDevIoError::IoBlockOutOfRange));
                            }
                            (write_region_begin_blkdev_io_blocks, write_region_blkdev_io_blocks)
                        };

                    let write_region_end_blkdev_io_blocks =
                        match write_region_begin_blkdev_io_blocks.checked_add(write_region_blkdev_io_blocks) {
                            Some(write_region_end_blkdev_io_blocks) => write_region_end_blkdev_io_blocks,
                            None => {
                                this.fut_state = NvBlkDevClearRegionFutureState::Done;
                                return task::Poll::Ready(Err(NvBlkDevIoError::IoBlockOutOfRange));
                            }
                        };
                    if write_region_end_blkdev_io_blocks > blkdev_io_blocks {
                        this.fut_state = NvBlkDevClearRegionFutureState::Done;
                        return task::Poll::Ready(Err(NvBlkDevIoError::IoBlockOutOfRange));
                    }

                    let write_region_end_128b = write_region_end_blkdev_io_blocks << blkdev_io_block_size_128b_log2;
                    if (write_region_end_128b << 7) >> (blkdev_io_block_size_128b_log2 + 7)
                        != write_region_end_blkdev_io_blocks
                    {
                        // The write region's end in units of Bytes is not representable as an u64.
                        this.fut_state = NvBlkDevClearRegionFutureState::Done;
                        return task::Poll::Ready(Err(NvBlkDevIoError::IoBlockOutOfRange));
                    }

                    let write_request = match ClearRegionNvBlkDevRequest::new(
                        write_region_begin_blkdev_io_blocks << blkdev_io_block_size_128b_log2,
                        write_region_end_128b,
                    ) {
                        Ok(write_request) => write_request,
                        Err(e) => {
                            this.fut_state = NvBlkDevClearRegionFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    let write_fut = match blkdev.write(write_request) {
                        Ok(Ok(write_fut)) => write_fut,
                        Ok(Err((_, e))) | Err(e) => {
                            this.fut_state = NvBlkDevClearRegionFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    this.fut_state = NvBlkDevClearRegionFutureState::Write { write_fut };
                }
                NvBlkDevClearRegionFutureState::Write { write_fut } => {
                    match NvBlkDevFuture::poll(pin::Pin::new(write_fut), blkdev, cx) {
                        task::Poll::Ready(result) => {
                            this.fut_state = NvBlkDevClearRegionFutureState::Done;
                            return task::Poll::Ready(result.and_then(|(_, result)| result));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    }
                }
                NvBlkDevClearRegionFutureState::Done => unreachable!(),
            }
        }
    }
}

/// [`NvBlkDevWriteRequest`] implementation used internally by
/// [`NvBlkDevClearRegionFuture`].
struct ClearRegionNvBlkDevRequest {
    region: ChunkedIoRegion,
    zeros_buf: FixedVec<u8, 7>,
}

impl ClearRegionNvBlkDevRequest {
    fn new(write_region_begin_128b: u64, write_region_end_128b: u64) -> Result<Self, NvBlkDevIoError> {
        // Allocate a buffer of the minimum length filled with zeroes. 128 Bytes is the
        // minimum chunk size.
        let zeros_buf = FixedVec::new_with_default(128)?;

        let region = ChunkedIoRegion::new(write_region_begin_128b, write_region_end_128b, 0).map_err(|e| match e {
            ChunkedIoRegionError::ChunkSizeOverflow => {
                // Cannot happen, the source block size is 128B and fits an usize.
                nvblkdev_err_internal!()
            }
            ChunkedIoRegionError::ChunkIndexOverflow => {
                // Cannot happen, the write region's total length fits an usize, as verified by
                // NvBlkDevClearRegionFuture.
                nvblkdev_err_internal!()
            }
            ChunkedIoRegionError::RegionUnaligned => {
                // Cannot happen, the chunk size is at the minimum of 128B, therefore the write
                // region is always aligned.
                nvblkdev_err_internal!()
            }
            ChunkedIoRegionError::InvalidBounds => {
                // The region's end is not before its beginning by construction in
                // NvBlkDevClearRegionFuture.
                nvblkdev_err_internal!()
            }
        })?;

        Ok(Self { region, zeros_buf })
    }
}

impl NvBlkDevWriteRequest for ClearRegionNvBlkDevRequest {
    fn region(&self) -> &ChunkedIoRegion {
        &self.region
    }

    fn get_source_buffer(&self, range: &ChunkedIoRegionChunkRange) -> Result<&[u8], NvBlkDevIoError> {
        // The chunk size is 128 Bytes, i.e. the size of zeros_buf. Ignore the chunk
        // index and provide the corresponding region from zero-filled
        // zero_buf.
        Ok(&self.zeros_buf[range.range_in_chunk().clone()])
    }
}

/// Read data from a a [`NvBlkDev`] region into a single, linear buffer.
///
/// # See also:
///
/// * [`NvBlkDevReadRegionBlocksScatterFuture`].
pub struct NvBlkDevReadRegionFuture<
    B: NvBlkDev,
    S: convert::AsRef<[u8]> + convert::AsMut<[u8]> + marker::Unpin + marker::Send,
> {
    read_fut: NvBlkDevReadRegionBlocksScatterFuture<B, SingletonBufferAsBlocksBuffers<S>>,
}

impl<B: NvBlkDev, D: convert::AsRef<[u8]> + convert::AsMut<[u8]> + marker::Unpin + marker::Send>
    NvBlkDevReadRegionFuture<B, D>
{
    /// Instantiate a [`NvBlkDevReadRegionFuture`].
    ///
    /// Instantiate a [`NvBlkDevReadRegionFuture`] for reading data from a
    /// contiguous [`NvBlkDev`] region into a single, linear `dst` buffer.
    ///
    /// The source [`NvBlkDev`] region is given by the pair of
    /// `read_region_begin_src_blocks` and `read_region_src_blocks`, both in
    /// units of the source block size as specified by
    /// `src_block_size_128b_log2`. Unlike it's the case with
    /// [`NvBlkDevWriteRegionBlocksGatherFuture`], the read region doesn't need
    /// to be aligned to the [Device IO Block
    /// size](NvBlkDev::io_block_size_128b_log2).
    ///
    /// Even though the `dst` buffer is linear, it is assumed to be partitioned
    /// into logical destination blocks, of size as specified by
    /// `dst_block_size_128b_log2`. The significance is that
    /// `dst_blocks_index_offset` is relative to that block size, and also, that
    /// larger buffer length alignments may potentially foster a more efficient
    /// processing at the [`NvBlkDev`] implementation side.
    ///
    /// The [`NvBlkDevReadRegionFuture`] assumes owership of the `dst` buffer
    /// for the duration of the operation. It will eventually get returned
    /// from [`poll()`](Self::poll) upon completion.
    ///
    /// # Arguments:
    ///
    /// * `read_region_begin_src_blocks` - Beginning of the read region the on
    ///   the [`NvBlkDev`], in units of the source block size as specified by
    ///   `src_block_size_128b_log2`.
    /// * `read_region_src_blocks` - Number of blocks of size as as specified by
    ///   `src_block_size_128b_log2` to read. Must be non-zero. The read
    ///   region's length in units of Bytes must be reperesentable as an `u64`
    ///   as well as an `usize`.
    /// * `src_block_size_128b_log2` - Base-2 logarithm of the source block size
    ///   in units of 128B multiples. The read region's bounds are specified in
    ///   units of the source block size.
    /// * `dst` - The destination buffer. Its length must be large enough to
    ///   accomodate for `dst_block_index_offset` destination blocks of size as
    ///   specified by `dst_block_size_128b_log2, followed by
    ///   `read_region_src_blocks` source blocks of size as specified by
    ///   `src_block_size_128b_log2`.
    /// * `dst_blocks_index_offset` - Offset to add to `dst_blocks` buffer entry
    ///   indices. That is, the first `dst_blocks_index_offset <<
    ///   (dst_block_size_128b_log2 + 7)` bytes will be skipped over.
    /// * `dst_block_size_128b_log2` - Base-2 logarithm of the destination block
    ///   size in units of 128B multiples. The total read region's length must
    ///   be evenly divisible by the destination block size.
    pub fn new(
        read_region_begin_src_blocks: u64,
        read_region_src_blocks: u64,
        src_block_size_128b_log2: u8,
        dst: D,
        dst_blocks_index_offset: usize,
        dst_block_size_128b_log2: u8,
    ) -> Self {
        Self {
            read_fut: NvBlkDevReadRegionBlocksScatterFuture::new(
                read_region_begin_src_blocks,
                read_region_src_blocks,
                src_block_size_128b_log2,
                SingletonBufferAsBlocksBuffers {
                    buffer: dst,
                    block_size_128b_log2: dst_block_size_128b_log2,
                },
                dst_blocks_index_offset,
                dst_block_size_128b_log2,
            ),
        }
    }
}

impl<B: NvBlkDev, D: convert::AsRef<[u8]> + convert::AsMut<[u8]> + marker::Unpin + marker::Send> NvBlkDevFuture<B>
    for NvBlkDevReadRegionFuture<B, D>
{
    /// Output type of [`poll()`](Self::poll).
    ///
    /// A two-level [`Result`] is returned upon [future](NvBlkDevFuture)
    /// completion.
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering an internal error and the input data buffers are lost.
    /// * `Ok((src, ...))` - Otherwise the outer level [`Result`] is set to
    ///   [`Ok`] and a pair of the input data buffer, `dst`, and the operation
    ///   result will get returned within:
    ///     * `Ok((dst, Err(e)))` - In case of an error, the error reason `e` is
    ///       returned in an [`Err`].
    ///     * `Ok((dst, Ok(())))` -  Otherwise, `Ok(())` will get returned for
    ///       the operation result on success.
    type Output = Result<(D, Result<(), NvBlkDevIoError>), NvBlkDevIoError>;

    fn poll(self: pin::Pin<&mut Self>, blkdev: &B, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        NvBlkDevFuture::poll(pin::Pin::new(&mut this.read_fut), blkdev, cx)
            .map(|result| result.map(|(dst_blocks, result)| (dst_blocks.buffer, result)))
    }
}

/// Implementation helper presenting a single linear buffer as an (indexable)
/// sequence of block sized buffers.
struct SingletonBufferAsBlocksBuffers<V> {
    buffer: V,
    block_size_128b_log2: u8,
}

impl<V: convert::AsRef<[u8]>> ops::Index<usize> for SingletonBufferAsBlocksBuffers<V> {
    type Output = [u8];

    fn index(&self, index: usize) -> &Self::Output {
        &self.buffer.as_ref()
            [index << (self.block_size_128b_log2 as u32 + 7)..(index + 1) << (self.block_size_128b_log2 as u32 + 7)]
    }
}

impl<V: convert::AsRef<[u8]> + convert::AsMut<[u8]>> ops::IndexMut<usize> for SingletonBufferAsBlocksBuffers<V> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.buffer.as_mut()
            [index << (self.block_size_128b_log2 as u32 + 7)..(index + 1) << (self.block_size_128b_log2 as u32 + 7)]
    }
}

/// View on a sequence of block buffers as a partition of (potentially) smaller
/// blocks.
///
/// Assuming that `V` is an indexable sequence of buffers, all equal to the same
/// power-of-two in in length, provide a view as an indexable sequence of
/// buffers again, all equal to the same, potentially smaller power-of-two in
/// length.
///
/// # See also:
///
/// * [`NvBlkDevReadRegionBlocksScatterFuture`].
/// * [`NvBlkDevWriteRegionBlocksGatherFuture`].
pub struct SplitBlocksBuffers<V> {
    buffers: V,
    buffer_block_size_128b_log2: u8,
    split_block_size_128b_log2: u8,
}

impl<V> SplitBlocksBuffers<V> {
    /// Instantiate a [`SplitBlocksBuffers`].
    ///
    /// Assuming that `buffers` is a sequence of block buffers, all of size as
    /// specified by `buffer_block_size_128b_log2`, provide a view as s
    /// sequence of block buffers again, but all of size as specified by the
    /// potentially smaller `split_block_size_128b_log2`.
    ///
    /// Note that `buffer_block_size_128b_log2` is merely used for index
    /// computations into `buffers` and if some `buffers` entry effectively
    /// isn't ever accessed, its actual length may be arbitrary.
    ///
    /// # Arguments:
    ///
    /// * `buffers` - The sequence of block buffers to provide a view on. As far
    ///   as index computations are concerned, every entry is assumed to have a
    ///   length as specified by `buffer_block_size_128b_log2`.
    /// * `buffer_block_size_128b_log2` - Base-2 logarithm of a `buffers` entry
    ///   length in units of 128B multiples.
    /// * `split_block_size_128b_log2` - Base-2 logarithm of the length of a
    ///   buffer entry in the resulting [`SplitBlocksBuffers`] view in units of
    ///   128B multiples . Must not exceed `buffer_block_size_128b_log2`.
    pub fn new(buffers: V, buffer_block_size_128b_log2: u8, split_block_size_128b_log2: u8) -> Self {
        debug_assert!(buffer_block_size_128b_log2 >= split_block_size_128b_log2);
        Self {
            buffers,
            buffer_block_size_128b_log2,
            split_block_size_128b_log2,
        }
    }

    /// Obtain the inner buffers back.
    ///
    /// Obtain the buffers initially passed to [`new()`](Self::new) back.
    pub fn into_buffers(self) -> V {
        self.buffers
    }
}

impl<V: ops::Index<usize, Output: convert::AsRef<[u8]>>> ops::Index<usize> for SplitBlocksBuffers<V> {
    type Output = [u8];

    fn index(&self, index: usize) -> &Self::Output {
        let buffer_block_split_blocks_log2 =
            self.buffer_block_size_128b_log2 as u32 - self.split_block_size_128b_log2 as u32;
        let buffer_block_index = index >> buffer_block_split_blocks_log2;
        let split_block_in_buffer_block_index = index & usize::trailing_bits_mask(buffer_block_split_blocks_log2);
        let split_block_in_buffer_block_begin =
            split_block_in_buffer_block_index << (self.split_block_size_128b_log2 as u32 + 7);
        let split_block_in_buffer_block_end =
            (split_block_in_buffer_block_index + 1) << (self.split_block_size_128b_log2 as u32 + 7);
        &self.buffers[buffer_block_index].as_ref()[split_block_in_buffer_block_begin..split_block_in_buffer_block_end]
    }
}

impl<V: ops::IndexMut<usize, Output: convert::AsRef<[u8]> + convert::AsMut<[u8]>>> ops::IndexMut<usize>
    for SplitBlocksBuffers<V>
{
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        let buffer_block_split_blocks_log2 =
            self.buffer_block_size_128b_log2 as u32 - self.split_block_size_128b_log2 as u32;
        let buffer_block_index = index >> buffer_block_split_blocks_log2;
        let split_block_in_buffer_block_index = index & usize::trailing_bits_mask(buffer_block_split_blocks_log2);
        let split_block_in_buffer_block_begin =
            split_block_in_buffer_block_index << (self.split_block_size_128b_log2 as u32 + 7);
        let split_block_in_buffer_block_end =
            (split_block_in_buffer_block_index + 1) << (self.split_block_size_128b_log2 as u32 + 7);
        &mut self.buffers[buffer_block_index].as_mut()
            [split_block_in_buffer_block_begin..split_block_in_buffer_block_end]
    }
}

#[test]
fn test_write_gather_read_scatter() {
    fn test_one(
        blkdev_io_block_size_128b_log2: u32,
        write_src_block_size_128b_log2: u32,
        read_dst_block_size_128b_log2: u32,
    ) {
        extern crate alloc;
        use alloc::vec::Vec;

        use crate::blkdev::test::{TestNvBlkDev, TestNvBlkDevFuture};
        use crate::utils_async::{
            sync_types,
            test::{TestAsyncExecutor, TestNopSyncTypes},
        };

        type TestSyncRcPtrFactory = <TestNopSyncTypes as sync_types::SyncTypes>::SyncRcPtrFactory;

        let max_block_size_128b_log2 = blkdev_io_block_size_128b_log2
            .max(write_src_block_size_128b_log2)
            .max(read_dst_block_size_128b_log2);
        let min_block_size_128b_log2 = blkdev_io_block_size_128b_log2
            .min(write_src_block_size_128b_log2)
            .min(read_dst_block_size_128b_log2);

        let write_region_length_128b_log2 = 2 + max_block_size_128b_log2;
        let mut write_buffers = Vec::new();
        write_buffers.push(Vec::new());
        for _ in 0..(1u64 << (write_region_length_128b_log2 - write_src_block_size_128b_log2)) {
            let mut buffer = Vec::new();
            buffer.resize(1usize << (write_src_block_size_128b_log2 + 7), 0u8);
            write_buffers.push(buffer);
        }
        let mut write_buffers = SplitBlocksBuffers::new(
            write_buffers,
            write_src_block_size_128b_log2 as u8,
            min_block_size_128b_log2 as u8,
        );
        for i in 0..(1usize << (write_region_length_128b_log2 - min_block_size_128b_log2)) {
            let value = (i + 1) as u8;
            // Skip over the first write_src_buffers[] entry, which will get skipped over
            // below when writing.
            let i = i + (1usize << (write_src_block_size_128b_log2 - min_block_size_128b_log2));
            write_buffers[i].fill(value);
        }
        let write_buffers = write_buffers.into_buffers();

        let write_region_blkdev_io_blocks = 1u64 << (write_region_length_128b_log2 - blkdev_io_block_size_128b_log2);
        let dev = <TestSyncRcPtrFactory as sync_types::SyncRcPtrFactory>::try_new(TestNvBlkDev::new(
            blkdev_io_block_size_128b_log2,
            1 + write_region_blkdev_io_blocks,
            0,
        ))
        .unwrap();

        let e = TestAsyncExecutor::new();
        let write_task = TestAsyncExecutor::spawn(
            &e,
            TestNvBlkDevFuture::new(
                dev.clone(),
                NvBlkDevWriteRegionBlocksGatherFuture::new(
                    1u64 << (blkdev_io_block_size_128b_log2 - min_block_size_128b_log2),
                    write_region_blkdev_io_blocks << (blkdev_io_block_size_128b_log2 - min_block_size_128b_log2),
                    min_block_size_128b_log2 as u8,
                    write_buffers,
                    1,
                    write_src_block_size_128b_log2 as u8,
                ),
            ),
        );
        TestAsyncExecutor::run_to_completion(&e);
        let (_write_buffers, result) = write_task.take().unwrap().unwrap();
        result.unwrap();

        // Unaligned read: skip one source block at the head and tail each.
        let read_region_dst_blocks = (1u64 << (write_region_length_128b_log2 - read_dst_block_size_128b_log2)) - 2;
        let mut read_buffers = Vec::new();
        read_buffers.push(Vec::new());
        for _ in 0..read_region_dst_blocks {
            let mut buffer = Vec::new();
            buffer.resize(1usize << (read_dst_block_size_128b_log2 + 7), 0u8);
            read_buffers.push(buffer);
        }
        let read_task = TestAsyncExecutor::spawn(
            &e,
            TestNvBlkDevFuture::new(
                dev.clone(),
                NvBlkDevReadRegionBlocksScatterFuture::new(
                    (1u64 << (blkdev_io_block_size_128b_log2 - min_block_size_128b_log2))
                        + (1u64 << (read_dst_block_size_128b_log2 - min_block_size_128b_log2)),
                    read_region_dst_blocks << (read_dst_block_size_128b_log2 - min_block_size_128b_log2),
                    min_block_size_128b_log2 as u8,
                    read_buffers,
                    1,
                    read_dst_block_size_128b_log2 as u8,
                ),
            ),
        );
        TestAsyncExecutor::run_to_completion(&e);
        let (read_buffers, result) = read_task.take().unwrap().unwrap();
        result.unwrap();
        let read_buffers = SplitBlocksBuffers::new(
            read_buffers,
            read_dst_block_size_128b_log2 as u8,
            min_block_size_128b_log2 as u8,
        );
        for i in 0..((read_region_dst_blocks as usize) << (read_dst_block_size_128b_log2 - min_block_size_128b_log2)) {
            // One read_dst_block_size_128b_log2 sized block written out at the head had not
            // been read back.
            let expected_value_offset = 1usize << (read_dst_block_size_128b_log2 - min_block_size_128b_log2);
            let expected_value = (expected_value_offset + i + 1) as u8;

            // The first read_dst_buffers[] entry had been skipped over.
            let i = i + (1usize << (read_dst_block_size_128b_log2 - min_block_size_128b_log2));

            assert!(read_buffers[i].iter().all(|b| *b == expected_value));
        }
    }

    test_one(0, 0, 0);
    test_one(0, 0, 1);
    test_one(0, 1, 0);
    test_one(0, 1, 1);
    test_one(1, 0, 0);
    test_one(1, 0, 1);
    test_one(1, 1, 0);
    test_one(1, 1, 1);
    test_one(2, 0, 0);
    test_one(2, 0, 1);
    test_one(2, 1, 0);
    test_one(2, 1, 1);
}
