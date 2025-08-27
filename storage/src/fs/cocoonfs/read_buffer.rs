// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`ReadBuffer`] and the related
//! [`BufferedReadAuthenticateDataFuture`].

extern crate alloc;

use crate::{
    chip::{self, ChunkedIoRegion, ChunkedIoRegionChunkRange, ChunkedIoRegionError},
    fs::{
        NvFsError,
        cocoonfs::{CocoonFsFormatError, alloc_bitmap, auth_tree, layout},
    },
    nvchip_err_internal, nvfs_err_internal,
    utils_async::sync_types::{self, ConstructibleLock as _, Lock as _},
    utils_common::{bitmanip::BitManip as _, fixed_vec::FixedVec},
};
use core::{mem, pin, sync::atomic, task};

#[cfg(doc)]
use layout::ImageLayout;

/// Buffered [Allocation Block](ImageLayout::allocation_block_size_128b_log2)
/// update specification.
pub enum ReadBufferAllocationBlockUpdate {
    /// The [Allocation Block](ImageLayout::allocation_block_size_128b_log2) is
    /// known to be unallocated.
    Unallocated,
    /// Invalidate any state buffered for the [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2).
    Invalidate,
    /// Retain what's buffered for the [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2).
    Retain,
    /// Update the [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2)'s buffered data.
    Update {
        /// The updated data.
        ///
        /// Must match the size as determined by
        /// [`ImageLayout::allocation_block_size_128b_log2`].
        data: FixedVec<u8, 7>,
    },
}

/// Buffer for some power-of-two size block's individual [Allocation
/// Blocks](ImageLayout::allocation_block_size_128b_log2).
///
/// The [`ReadBuffer`] maintains one [`BlockAllocationBlocksReadBuffer`] for the
/// most recently read [Authentication Tree Data
/// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) as well as
/// [Chip IO Block](chip::NvChip::chip_io_block_size_128b_log2) respectively
/// each.
struct BlockAllocationBlocksReadBuffer {
    /// Beginning of the currently buffered block on storage, if any.
    buffered_block_allocation_blocks_begin: Option<layout::PhysicalAllocBlockIndex>,
    /// Buffered Allocation Blocks.
    ///
    /// - `None` means the Allocation Block has been consumed,
    /// - an empty `FixedVec` means the Allocation Block has not been consumed,
    ///   but is unallocated.
    buffered_allocation_blocks: FixedVec<Option<FixedVec<u8, 7>>, 0>,
}

impl BlockAllocationBlocksReadBuffer {
    /// Instantiate a new [`BlockAllocationBlocksReadBuffer`].
    ///
    /// # Arguments:
    ///
    /// `block_allocation_blocks_log2` - Base-2 logarithm of the buffered
    /// block's size in units of [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2).
    fn new(block_allocation_blocks_log2: u32) -> Result<Self, NvFsError> {
        if block_allocation_blocks_log2 >= usize::BITS {
            return Err(NvFsError::DimensionsNotSupported);
        }

        let buffered_allocation_blocks = FixedVec::new_with_default(1usize << block_allocation_blocks_log2)?;
        Ok(Self {
            buffered_block_allocation_blocks_begin: None,
            buffered_allocation_blocks,
        })
    }

    /// Take a contiguous sequence of buffered [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2).
    ///
    /// Transfer any of the buffered block's [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2) starting
    /// at index `take_begin` to the corresponding entry from
    /// `dst_allocation_blocks_bufs`. For any Allocation Block
    /// buffered as unallocated, the `FixedVec` from the corresponding
    /// `dst_allocation_blocks_bufs` entry will get reset to zero length.
    /// Any entry from `dst_allocation_blocks_bufs`, for which no [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) is
    /// found in the buffer anymore, will be left unmodified.
    ///
    /// A pair of two `bool`s is returned:
    /// * The first entry is set to `true` if and only if all entries from
    ///   `dst_allocation_blocks_bufs` received an assignment from the buffer.
    /// * The second entry is set to `true` if no more entries are remaining in
    ///   the buffer after the transfer.
    ///
    /// # Arguments:
    ///
    /// * `take_begin` - Index of the first [Allocation
    ///   Block](ImageLayout::allocation_block_size_128b_log2) in the buffered
    ///   block to transfer (if present).
    /// * `dst_allocation_blocks_bufs` - Iterator over `&mut FixedVec` items to
    ///   transfer the respective [Allocation
    ///   Block](ImageLayout::allocation_block_size_128b_log2) buffers to.
    fn take_buffers<'a, DI: Iterator<Item = &'a mut FixedVec<u8, 7>>>(
        &mut self,
        take_begin: usize,
        dst_allocation_blocks_bufs: DI,
    ) -> (bool, bool) {
        let mut any_missing = false;
        // Cast to usize does not overflow, as per the above it is known that
        // range_begin is in range.
        let mut i = take_begin;
        for dst_allocation_block_buf in dst_allocation_blocks_bufs {
            if i == self.buffered_allocation_blocks.len() {
                any_missing = true;
                break;
            }
            match self.buffered_allocation_blocks[i].take() {
                Some(buffered_allocation_block) => {
                    *dst_allocation_block_buf = buffered_allocation_block;
                }
                None => {
                    any_missing = true;
                }
            };

            i += 1;
        }

        let any_remaining = self.buffered_allocation_blocks[..take_begin]
            .iter()
            .chain(self.buffered_allocation_blocks[i..].iter())
            .any(|buffered_allocation_block| buffered_allocation_block.is_some());

        if !any_remaining {
            self.buffered_block_allocation_blocks_begin = None;
        }

        (!any_missing, !any_remaining)
    }

    /// Clear the buffer.
    fn clear(&mut self) {
        for buffered_allocation_block in &mut self.buffered_allocation_blocks {
            *buffered_allocation_block = None;
        }
        self.buffered_block_allocation_blocks_begin = None;
    }

    /// Insert a contiguous sequence of [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) buffers.
    ///
    /// Reset any existing [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) buffer
    /// entries and transfer the ones from `src_allocation_blocks_bufs` into the
    /// buffer. The first entry from `src_allocation_blocks_bufs`
    /// corresponds to the storage location specified by
    /// `src_allocation_blocks_begin`.
    ///
    /// If an entry from `src_allocation_blocks_bufs` is `None`, then the
    /// [Allocation Block](ImageLayout::allocation_block_size_128b_log2)
    /// will get tracked as unavailable. Otherwise, if the `FixedVec` is empty,
    /// it get buffered as unallocated. Otherwise the [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) will
    /// get buffered with the data from the `FixedVec` taken.
    ///
    /// On success, the location of the buffer's first buffered [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) will get
    /// returned, if any.
    ///
    /// # Arguments:
    ///
    /// * `src_allocation_blocks_begin` - Location of the first entry from
    ///   `src_allocation_blocks_bufs` on storage.
    /// * `src_allocation_blocks_bufs` - Iterator over the [Allocation
    ///   Block](ImageLayout::allocation_block_size_128b_log2) buffers to
    ///   insert.
    fn insert_buffers<'a, SI: Iterator<Item = Option<&'a mut FixedVec<u8, 7>>>>(
        &mut self,
        src_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        src_allocation_blocks_bufs: SI,
    ) -> Option<layout::PhysicalAllocBlockIndex> {
        debug_assert!(self.buffered_allocation_blocks.len().is_pow2());
        let buffered_block_allocation_blocks_begin = layout::PhysicalAllocBlockIndex::from(
            u64::from(src_allocation_blocks_begin) & !(self.buffered_allocation_blocks.len() as u64 - 1),
        );
        self.buffered_block_allocation_blocks_begin = Some(buffered_block_allocation_blocks_begin);

        // Does not overflow, the subtrahend is the minuend aligned downwards by an
        // usize above.
        let i = u64::from(src_allocation_blocks_begin - buffered_block_allocation_blocks_begin) as usize;
        debug_assert!(i < self.buffered_allocation_blocks.len());
        let mut j = i;
        let mut any_inserted = false;
        for src_allocation_block_buf in src_allocation_blocks_bufs.take(self.buffered_allocation_blocks.len() - i) {
            if let Some(src_allocation_block_buf) = src_allocation_block_buf {
                any_inserted = true;
                self.buffered_allocation_blocks[j] = Some(mem::take(src_allocation_block_buf));
            } else {
                self.buffered_allocation_blocks[j] = None;
            }
            j += 1;
            if j == self.buffered_allocation_blocks.len() {
                break;
            }
        }

        self.buffered_allocation_blocks[..i].fill(None);
        self.buffered_allocation_blocks[j..].fill(None);

        if !any_inserted {
            self.buffered_block_allocation_blocks_begin = None;
        }

        self.buffered_block_allocation_blocks_begin
    }

    /// Update buffered [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2).
    ///
    /// Update [Allocation Block](ImageLayout::allocation_block_size_128b_log2)
    /// buffer entries as specified by `src_allocation_block_bufs`. The
    /// first entry from `src_allocation_blocks_bufs` corresponds to the
    /// storage location specified by `src_allocation_blocks_begin`. Existing
    /// entries not in range of the `src_allocation_blocks_bufs` will be left
    /// unmodified.
    ///
    /// On success, the location of the buffer's first buffered [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) will get returned,
    /// if any.
    ///
    /// # Arguments:
    ///
    /// * `src_allocation_blocks_begin` - Location of the first entry from
    ///   `src_allocation_blocks_bufs` on storage.
    /// * `src_allocation_blocks_bufs` - Iterator over the [Allocation
    ///   Block](ImageLayout::allocation_block_size_128b_log2) buffer update
    ///   specifications.
    fn update_buffers<SI: Iterator<Item = ReadBufferAllocationBlockUpdate>>(
        &mut self,
        mut src_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        mut src_allocation_blocks_bufs: SI,
    ) -> Option<layout::PhysicalAllocBlockIndex> {
        // If no block is currently being buffered, return.
        let buffered_block_allocation_blocks_begin = self.buffered_block_allocation_blocks_begin?;
        debug_assert!(self.buffered_allocation_blocks.len().is_pow2());
        if (u64::from(src_allocation_blocks_begin) ^ u64::from(buffered_block_allocation_blocks_begin))
            & !(self.buffered_allocation_blocks.len() as u64 - 1)
            != 0
        {
            // The src_allocation_blocks_begin and the buffer_allocation_blocks_begin are in
            // different blocks.
            if src_allocation_blocks_begin > buffered_block_allocation_blocks_begin {
                return Some(buffered_block_allocation_blocks_begin);
            }

            // Advance the source to the beginning of the buffered block.
            while src_allocation_blocks_begin != buffered_block_allocation_blocks_begin {
                if src_allocation_blocks_bufs.next().is_none() {
                    return Some(buffered_block_allocation_blocks_begin);
                }
                src_allocation_blocks_begin += layout::AllocBlockCount::from(1);
            }
        }

        // Does not overflow, the subtrahend is the minuend aligned downwards by an
        // usize.
        let i = u64::from(src_allocation_blocks_begin - buffered_block_allocation_blocks_begin) as usize;
        debug_assert!(i < self.buffered_allocation_blocks.len());
        let mut j = i;
        let mut any_remaining = false;
        for allocation_block_update in src_allocation_blocks_bufs.take(self.buffered_allocation_blocks.len() - i) {
            match allocation_block_update {
                ReadBufferAllocationBlockUpdate::Unallocated => {
                    // An empty FixedVec represents an unallocated Allocation Block.
                    self.buffered_allocation_blocks[j] = Some(FixedVec::new_empty());
                    any_remaining = true;
                }
                ReadBufferAllocationBlockUpdate::Invalidate => {
                    self.buffered_allocation_blocks[j] = None;
                }
                ReadBufferAllocationBlockUpdate::Retain => {
                    any_remaining |= self.buffered_allocation_blocks[j].is_some();
                }
                ReadBufferAllocationBlockUpdate::Update { data } => {
                    self.buffered_allocation_blocks[j] = Some(data);
                    any_remaining = true;
                }
            }
            j += 1;
            if j == self.buffered_allocation_blocks.len() {
                break;
            }
        }

        any_remaining |= self.buffered_allocation_blocks[..i]
            .iter()
            .any(|buffered_allocation_block| buffered_allocation_block.is_some());
        any_remaining |= self.buffered_allocation_blocks[j..]
            .iter()
            .any(|buffered_allocation_block| buffered_allocation_block.is_some());

        if !any_remaining {
            self.buffered_block_allocation_blocks_begin = None;
        }

        self.buffered_block_allocation_blocks_begin
    }
}

/// A [`ReadBuffer`]'s buffered data.
struct ReadBufferBufferedData {
    /// Unauthenticated data buffered from most recently read [Chip IO
    /// block](chip::NvChip::chip_io_block_size_128b_log2).
    min_io_block_buf: BlockAllocationBlocksReadBuffer,
    /// Authenticated data buffered from the most recently read and
    /// authenticated [Authentication
    /// Tree Data Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2).
    auth_tree_data_block_buf: BlockAllocationBlocksReadBuffer,
}

impl ReadBufferBufferedData {
    /// Instantiate a [`ReadBufferBufferedData`].
    ///
    /// # Arguments:
    ///
    /// * `min_io_block_allocation_blocks_log2` - Base-2 logarithm of the [Chip
    ///   IO Block](chip::NvChip::chip_io_block_size_128b_log2) size in units of
    ///   [Allocation Blocks](ImageLayout::allocation_block_size_128b_log2).
    /// * `auth_tree_data_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::auth_tree_data_block_allocation_blocks_log2`].
    fn new(
        min_io_block_allocation_blocks_log2: u32,
        auth_tree_data_block_allocation_blocks_log2: u32,
    ) -> Result<Self, NvFsError> {
        Ok(Self {
            min_io_block_buf: BlockAllocationBlocksReadBuffer::new(min_io_block_allocation_blocks_log2)?,
            auth_tree_data_block_buf: BlockAllocationBlocksReadBuffer::new(
                auth_tree_data_block_allocation_blocks_log2,
            )?,
        })
    }
}

/// Data read buffer.
///
/// In general, read requests don't align with [Chip IO
/// Block](chip::NvChip::chip_io_block_size_128b_log2) or [Authentication Tree
/// Data Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
/// boundaries, yet reads from physical storage must get processed at a
/// granularity of the former, and authentication at that of the latter.
///
/// In order to exploit spatial locality, a `ReadBuffer` buffers the unused
/// portions from prior reads for potential consumption from subsequent ones.
///
/// More specifically, it maintains a buffer of [Allocation
/// Blocks](ImageLayout::allocation_block_size_128b_log2) authenticated in the
/// course of proecessing a prior read request but not consumed yet.
/// Furthermore, if the [Chip IO
/// Block](chip::NvChip::chip_io_block_size_128b_log2) happens to exceed the
/// [Authentication Tree
/// Data Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) size,
/// then it also buffers not yet authenticated [Allocation
/// Blocks](ImageLayout::allocation_block_size_128b_log2) read in as a byproduct
/// in the course of processing a prior read request.
///
/// No data is ever inserted directly into a `ReadBuffer` nor consumed from it,
/// that's all handled transparently through the
/// [`BufferedReadAuthenticateDataFuture`]. Interfaces are provided to supersede
/// or invalidate buffered data at
/// [`Transaction`](super::transaction::Transaction) commit though.
///
/// # See also:
///
/// * [`BufferedReadAuthenticateDataFuture`].
pub struct ReadBuffer<ST: sync_types::SyncTypes> {
    /// Verbatim copy of
    /// [`ImageLayout::allocation_block_size_128b_log2`].
    allocation_block_size_128b_log2: u8,
    /// Value of [`NvChip::chip_io_block_size_128b_log2`](chip::NvChip::chip_io_block_size_128b_log2) converted to units
    /// of [Allocation Blocks](ImageLayout::allocation_block_size_128b_log2).
    min_io_block_allocation_blocks_log2: u8,
    /// Verbatim copy of
    /// [`ImageLayout::auth_tree_data_block_allocation_blocks_log2`].
    auth_tree_data_block_allocation_blocks_log2: u8,

    /// The buffered data.
    buf: ST::Lock<ReadBufferBufferedData>,

    /// Copy of the
    /// [`buffered_block_allocation_blocks_begin`](BlockAllocationBlocksReadBuffer::buffered_block_allocation_blocks_begin)
    /// value from [`buf`](Self::buf)'s
    /// [`min_io_block_buf`](ReadBufferBufferedData::min_io_block_buf).
    ///
    /// A value of `None` is mapped to `u64::MAX`.
    /// Modified only under the [`Lock`](sync_types::Lock) wrapping
    /// [`buf`](Self::buf).
    buffered_min_io_block_allocation_blocks_begin: atomic::AtomicU64,
    /// Copy of the
    /// [`buffered_block_allocation_blocks_begin`](BlockAllocationBlocksReadBuffer::buffered_block_allocation_blocks_begin)
    /// value from [`buf`](Self::buf)'s
    /// [`auth_tree_data_block_buf`](ReadBufferBufferedData::auth_tree_data_block_buf).
    ///
    /// A value of `None` is mapped to `u64::MAX`.
    /// Modified only under the [`Lock`](sync_types::Lock) wrapping
    /// [`buf`](Self::buf).
    buffered_auth_tree_data_block_allocation_blocks_begin: atomic::AtomicU64,
}

impl<ST: sync_types::SyncTypes> ReadBuffer<ST> {
    /// Instantiate a [`ReadBuffer`].
    ///
    /// # Arguments:
    ///
    /// * `image_layout` - The filesystem's [`ImageLayout`].
    /// * `chip` - The filesystem image backing storage.
    pub fn new<C: chip::NvChip>(image_layout: &layout::ImageLayout, chip: &C) -> Result<Self, NvFsError> {
        let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2;

        let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();
        let min_io_block_allocation_blocks_log2 =
            chip_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2 as u32);
        let min_io_block_allocation_blocks_log2 =
            u8::try_from(min_io_block_allocation_blocks_log2).map_err(|_| nvfs_err_internal!())?;

        let auth_tree_data_block_allocation_blocks_log2 = image_layout.auth_tree_data_block_allocation_blocks_log2;

        Ok(Self {
            allocation_block_size_128b_log2,
            min_io_block_allocation_blocks_log2,
            auth_tree_data_block_allocation_blocks_log2,
            buf: ST::Lock::from(ReadBufferBufferedData::new(
                min_io_block_allocation_blocks_log2 as u32,
                auth_tree_data_block_allocation_blocks_log2 as u32,
            )?),
            buffered_min_io_block_allocation_blocks_begin: atomic::AtomicU64::new(u64::MAX),
            buffered_auth_tree_data_block_allocation_blocks_begin: atomic::AtomicU64::new(u64::MAX),
        })
    }

    /// Take a contiguous sequence of buffered authenticated [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2), if any.
    ///
    /// Transfer any of the buffered authenticated [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2) to the
    /// corresponding entry from `dst_allocation_blocks_bufs`. For any
    /// Allocation Block buffered as unallocated, the `FixedVec`
    /// from the corresponding `dst_allocation_blocks_bufs` entry will get reset
    /// to zero length. Any entry from `dst_allocation_blocks_bufs`, for
    /// which no [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) is found in the
    /// buffer anymore, will be left unmodified.
    ///
    /// If no [Allocation Block](ImageLayout::allocation_block_size_128b_log2)
    /// in the requested `range` was buffered, `None` will get returned.
    /// Otherwise, a pair of the subrange of `range` possibly populated with
    /// data from the buffer and a bool indicating whether buffered data for
    /// all of that subrange was transferred is returned, wrapped in a `Some`.
    ///
    /// # Arguments:
    ///
    /// * `range`  - The requested storage range.
    /// * `dst_allocation_blocks_bufs` - Iterator over `&mut FixedVec` items to
    ///   transfer the respective [Allocation
    ///   Block](ImageLayout::allocation_block_size_128b_log2) buffers to. Must
    ///   yield one entry for each Allocation Block in `range`.
    fn take_authenticated_buffers<'a, DI: Iterator<Item = &'a mut FixedVec<u8, 7>>>(
        &self,
        range: &layout::PhysicalAllocBlockRange,
        dst_allocation_blocks_bufs: DI,
    ) -> Option<(layout::PhysicalAllocBlockRange, bool)> {
        let auth_tree_data_block_allocation_blocks_log2 = self.auth_tree_data_block_allocation_blocks_log2 as u32;

        if !self.auth_tree_blocks_are_buffered()
            || !Self::range_overlaps_block(
                range,
                layout::PhysicalAllocBlockIndex::from(
                    self.buffered_auth_tree_data_block_allocation_blocks_begin
                        .load(atomic::Ordering::Relaxed),
                ),
                auth_tree_data_block_allocation_blocks_log2,
            )
        {
            return None;
        }

        let mut locked_buf = self.buf.lock();
        if let Some((buffered_subrange, take_buffered_allocation_blocks_begin)) = locked_buf
            .auth_tree_data_block_buf
            .buffered_block_allocation_blocks_begin
            .as_ref()
            .and_then(|buffered_block_allocation_blocks_begin| {
                Self::trim_range_to_block(
                    range,
                    *buffered_block_allocation_blocks_begin,
                    auth_tree_data_block_allocation_blocks_log2,
                )
                .map(|buffered_subrange| {
                    (
                        buffered_subrange,
                        // Does not overflow, it's been checked above that the complete
                        // range's allocation block count
                        // fits an usize.
                        u64::from(buffered_subrange.begin() - *buffered_block_allocation_blocks_begin) as usize,
                    )
                })
            })
        {
            // Does not overflow, it's been checked above that the complete range's
            // allocation block count fits an usize.
            let dst_allocation_blocks_bufs_begin = u64::from(buffered_subrange.begin() - range.begin()) as usize;
            let dst_allocation_blocks_bufs_end =
                dst_allocation_blocks_bufs_begin + u64::from(buffered_subrange.block_count()) as usize;

            let (all_in_subrange_found, buf_emptied) = locked_buf.auth_tree_data_block_buf.take_buffers(
                take_buffered_allocation_blocks_begin,
                dst_allocation_blocks_bufs
                    .skip(dst_allocation_blocks_bufs_begin)
                    .take(dst_allocation_blocks_bufs_end - dst_allocation_blocks_bufs_begin),
            );
            if buf_emptied {
                self.buffered_auth_tree_data_block_allocation_blocks_begin
                    .store(u64::MAX, atomic::Ordering::Relaxed);
            }

            return Some((buffered_subrange, all_in_subrange_found));
        }

        None
    }

    /// Take a contiguous sequence of buffered unauthenticated [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2), if any.
    ///
    /// Transfer any of the buffered unauthenticated [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2) to the
    /// corresponding entry from `dst_allocation_blocks_bufs`. For any
    /// Allocation Block buffered as unallocated, the `FixedVec`
    /// from the corresponding `dst_allocation_blocks_bufs` entry will get reset
    /// to zero length. Any entry from `dst_allocation_blocks_bufs`, for
    /// which no [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) is found in the
    /// buffer anymore, will be left unmodified.
    ///
    /// If no [Allocation Block](ImageLayout::allocation_block_size_128b_log2)
    /// in the requested `range` was buffered, `None` will get returned.
    /// Otherwise, a pair of the subrange of `range` possibly populated with
    /// data from the buffer and a bool indicating whether buffered data for
    /// all of that subrange was transferred is returned, wrapped in a `Some`.
    ///
    /// # Arguments:
    ///
    /// * `range`  - The requested storage range.
    /// * `dst_allocation_blocks_bufs` - Iterator over `&mut FixedVec` items to
    ///   transfer the respective [Allocation
    ///   Block](ImageLayout::allocation_block_size_128b_log2) buffers to. Must
    ///   yield one entry for each Allocation Block in `range`.
    fn take_unauthenticated_buffers<'a, DI: Iterator<Item = &'a mut FixedVec<u8, 7>>>(
        &self,
        range: &layout::PhysicalAllocBlockRange,
        dst_allocation_blocks_bufs: DI,
    ) -> Option<(layout::PhysicalAllocBlockRange, bool)> {
        let min_io_block_allocation_blocks_log2 = self.min_io_block_allocation_blocks_log2 as u32;

        if !self.min_io_blocks_are_buffered()
            || !Self::range_overlaps_block(
                range,
                layout::PhysicalAllocBlockIndex::from(
                    self.buffered_min_io_block_allocation_blocks_begin
                        .load(atomic::Ordering::Relaxed),
                ),
                min_io_block_allocation_blocks_log2,
            )
        {
            return None;
        }

        let mut locked_buf = self.buf.lock();
        if let Some((buffered_subrange, take_buffered_allocation_blocks_begin)) = locked_buf
            .min_io_block_buf
            .buffered_block_allocation_blocks_begin
            .as_ref()
            .and_then(|buffered_block_allocation_blocks_begin| {
                Self::trim_range_to_block(
                    range,
                    *buffered_block_allocation_blocks_begin,
                    min_io_block_allocation_blocks_log2,
                )
                .map(|buffered_subrange| {
                    (
                        buffered_subrange,
                        // Does not overflow, it's been checked above that the complete
                        // range's allocation block count
                        // fits an usize.
                        u64::from(buffered_subrange.begin() - *buffered_block_allocation_blocks_begin) as usize,
                    )
                })
            })
        {
            // Does not overflow, it's been checked above that the complete range's
            // allocation block count fits an usize.
            let dst_allocation_blocks_bufs_begin = u64::from(buffered_subrange.begin() - range.begin()) as usize;
            let dst_allocation_blocks_bufs_end =
                dst_allocation_blocks_bufs_begin + u64::from(buffered_subrange.block_count()) as usize;

            let (all_in_subrange_found, buf_emptied) = locked_buf.min_io_block_buf.take_buffers(
                take_buffered_allocation_blocks_begin,
                dst_allocation_blocks_bufs
                    .skip(dst_allocation_blocks_bufs_begin)
                    .take(dst_allocation_blocks_bufs_end - dst_allocation_blocks_bufs_begin),
            );
            if buf_emptied {
                self.buffered_min_io_block_allocation_blocks_begin
                    .store(u64::MAX, atomic::Ordering::Relaxed);
            }

            return Some((buffered_subrange, all_in_subrange_found));
        }

        None
    }

    /// Insert a contiguous sequence of authenticated [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) buffers.
    ///
    /// Reset any existing authenticated [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) buffer entries and
    /// transfer the ones from `src_allocation_blocks_bufs` into the buffer.
    /// The first entry from `src_allocation_blocks_bufs` corresponds to the
    /// storage location specified by `src_allocation_blocks_begin`.
    ///
    /// If an entry from `src_allocation_blocks_bufs` is `None`, then the
    /// [Allocation Block](ImageLayout::allocation_block_size_128b_log2)
    /// will get tracked as unavailable. Otherwise, if the `FixedVec` is empty,
    /// it get buffered as unallocated. Otherwise the [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) will get buffered
    /// with the data from the `FixedVec` taken.
    ///
    /// # Arguments:
    ///
    /// * `src_allocation_blocks_begin` - Location of the first entry from
    ///   `src_allocation_blocks_bufs` on storage.
    /// * `src_allocation_blocks_bufs` - Iterator over the [Allocation
    ///   Block](ImageLayout::allocation_block_size_128b_log2) buffers to
    ///   insert. The buffers must all have been authenticated!
    fn insert_authenticated_buffers<'a, SI: Iterator<Item = Option<&'a mut FixedVec<u8, 7>>>>(
        &self,
        src_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        src_allocation_blocks_bufs: SI,
    ) {
        if !self.auth_tree_blocks_are_buffered() {
            return;
        }

        let mut locked_buf = self.buf.lock();
        self.buffered_auth_tree_data_block_allocation_blocks_begin.store(
            locked_buf
                .auth_tree_data_block_buf
                .insert_buffers(src_allocation_blocks_begin, src_allocation_blocks_bufs)
                .map(u64::from)
                .unwrap_or(u64::MAX),
            atomic::Ordering::Relaxed,
        );
    }

    /// Insert a contiguous sequence of unauthenticated [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) buffers.
    ///
    /// Reset any existing unauthenticated [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) buffer entries and
    /// transfer the ones from `src_allocation_blocks_bufs` into the buffer.
    /// The first entry from `src_allocation_blocks_bufs` corresponds to the
    /// storage location specified by `src_allocation_blocks_begin`.
    ///
    /// If an entry from `src_allocation_blocks_bufs` is `None`, then the
    /// [Allocation Block](ImageLayout::allocation_block_size_128b_log2)
    /// will get tracked as unavailable. Otherwise, if the `FixedVec` is empty,
    /// it get buffered as unallocated. Otherwise the [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) will get buffered
    /// with the data from the `FixedVec` taken.
    ///
    /// # Arguments:
    ///
    /// * `src_allocation_blocks_begin` - Location of the first entry from
    ///   `src_allocation_blocks_bufs` on storage.
    /// * `src_allocation_blocks_bufs` - Iterator over the [Allocation
    ///   Block](ImageLayout::allocation_block_size_128b_log2) buffers to
    ///   insert.
    fn insert_unauthenticated_buffers<'a, SI: Iterator<Item = Option<&'a mut FixedVec<u8, 7>>>>(
        &self,
        src_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        src_allocation_blocks_bufs: SI,
    ) {
        if !self.min_io_blocks_are_buffered() {
            return;
        }

        let mut locked_buf = self.buf.lock();
        self.buffered_min_io_block_allocation_blocks_begin.store(
            locked_buf
                .min_io_block_buf
                .insert_buffers(src_allocation_blocks_begin, src_allocation_blocks_bufs)
                .map(u64::from)
                .unwrap_or(u64::MAX),
            atomic::Ordering::Relaxed,
        );
    }

    /// Get the current storage range window spanning all possibly buffered
    /// authenticated [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2), if any.
    pub fn get_buffered_authenticated_range(&self) -> Option<layout::PhysicalAllocBlockRange> {
        if !self.auth_tree_blocks_are_buffered() {
            return None;
        }

        let buffered_auth_tree_data_block_allocation_blocks_begin = self
            .buffered_auth_tree_data_block_allocation_blocks_begin
            .load(atomic::Ordering::Relaxed);
        if buffered_auth_tree_data_block_allocation_blocks_begin == u64::MAX {
            return None;
        }
        let buffered_auth_tree_data_block_allocation_blocks_begin =
            layout::PhysicalAllocBlockIndex::from(buffered_auth_tree_data_block_allocation_blocks_begin);
        let auth_tree_data_block_allocation_blocks =
            layout::AllocBlockCount::from(1u64 << (self.auth_tree_data_block_allocation_blocks_log2 as u32));
        Some(layout::PhysicalAllocBlockRange::from((
            buffered_auth_tree_data_block_allocation_blocks_begin,
            auth_tree_data_block_allocation_blocks,
        )))
    }

    /// Get the current storage range window spanning all possibly buffered
    /// unauthenticated [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2), if any.
    pub fn get_buffered_unauthenticated_range(&self) -> Option<layout::PhysicalAllocBlockRange> {
        if !self.min_io_blocks_are_buffered() {
            return None;
        }

        let buffered_min_io_block_allocation_blocks_begin = self
            .buffered_min_io_block_allocation_blocks_begin
            .load(atomic::Ordering::Relaxed);
        if buffered_min_io_block_allocation_blocks_begin == u64::MAX {
            return None;
        }
        let buffered_min_block_allocation_blocks_begin =
            layout::PhysicalAllocBlockIndex::from(buffered_min_io_block_allocation_blocks_begin);
        let min_io_block_allocation_blocks =
            layout::AllocBlockCount::from(1u64 << (self.min_io_block_allocation_blocks_log2 as u32));
        Some(layout::PhysicalAllocBlockRange::from((
            buffered_min_block_allocation_blocks_begin,
            min_io_block_allocation_blocks,
        )))
    }

    /// Update buffered authenticated [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2).
    ///
    /// Update authenticated [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) buffer
    /// entries as specified by `src_allocation_block_bufs`. The first entry
    /// from `src_allocation_blocks_bufs` corresponds to the storage
    /// location specified by `src_allocation_blocks_begin`. Existing
    /// entries not in range of the `src_allocation_blocks_bufs` will be
    /// left unmodified.
    ///
    /// # Arguments:
    ///
    /// * `src_allocation_blocks_begin` - Location of the first entry from
    ///   `src_allocation_blocks_bufs` on storage.
    /// * `src_allocation_blocks_bufs` - Iterator over the [Allocation
    ///   Block](ImageLayout::allocation_block_size_128b_log2) buffer update
    ///   specifications. Except for the
    ///   [`Invalidate`](ReadBufferAllocationBlockUpdate::Invalidate) case, all
    ///   update entries must be authenticated!
    pub fn update_authenticated_buffers<SI: Iterator<Item = ReadBufferAllocationBlockUpdate>>(
        &mut self,
        src_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        src_allocation_blocks_bufs: SI,
    ) {
        if !self.auth_tree_blocks_are_buffered() {
            return;
        }

        self.buffered_auth_tree_data_block_allocation_blocks_begin.store(
            self.buf
                .get_mut()
                .auth_tree_data_block_buf
                .update_buffers(src_allocation_blocks_begin, src_allocation_blocks_bufs)
                .map(u64::from)
                .unwrap_or(u64::MAX),
            atomic::Ordering::Relaxed,
        );
    }

    /// Update buffered unauthenticated [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2).
    ///
    /// Update unauthenticated [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) buffer entries
    /// as specified by `src_allocation_block_bufs`. The first entry from
    /// `src_allocation_blocks_bufs` corresponds to the storage location
    /// specified by `src_allocation_blocks_begin`. Existing entries not in
    /// range of the `src_allocation_blocks_bufs` will be left unmodified.
    ///
    /// # Arguments:
    ///
    /// * `src_allocation_blocks_begin` - Location of the first entry from
    ///   `src_allocation_blocks_bufs` on storage.
    /// * `src_allocation_blocks_bufs` - Iterator over the [Allocation
    ///   Block](ImageLayout::allocation_block_size_128b_log2) buffer update
    ///   specifications.
    pub fn update_unauthenticated_buffers<SI: Iterator<Item = ReadBufferAllocationBlockUpdate>>(
        &mut self,
        src_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        src_allocation_blocks_bufs: SI,
    ) {
        if !self.min_io_blocks_are_buffered() {
            return;
        }

        self.buffered_min_io_block_allocation_blocks_begin.store(
            self.buf
                .get_mut()
                .min_io_block_buf
                .update_buffers(src_allocation_blocks_begin, src_allocation_blocks_bufs)
                .map(u64::from)
                .unwrap_or(u64::MAX),
            atomic::Ordering::Relaxed,
        );
    }

    /// Clear all buffered data.
    pub fn clear_caches(&self) {
        let mut locked_buf = self.buf.lock();
        locked_buf.auth_tree_data_block_buf.clear();
        self.buffered_auth_tree_data_block_allocation_blocks_begin
            .store(u64::MAX, atomic::Ordering::Relaxed);
        locked_buf.min_io_block_buf.clear();
        self.buffered_min_io_block_allocation_blocks_begin
            .store(u64::MAX, atomic::Ordering::Relaxed);
    }

    /// Determine whether unauthenticated data from read
    /// [Chip IO Blocks](chip::NvChip::chip_io_block_size_128b_log2) reads is to
    /// be buffered.
    fn min_io_blocks_are_buffered(&self) -> bool {
        self.min_io_block_allocation_blocks_log2 > self.auth_tree_data_block_allocation_blocks_log2
    }

    /// Determine whether data from authenticated [Authentication Tree Data
    /// Blocks](ImageLayout::auth_tree_data_block_allocation_blocks_log2) is to
    /// be buffered.
    fn auth_tree_blocks_are_buffered(&self) -> bool {
        self.auth_tree_data_block_allocation_blocks_log2 != 0
    }

    /// Test if a given storage range overlaps with some aligned, power-of-two
    /// sized block.
    ///
    /// # Arguments:
    ///
    /// * `range` - The extent on storage to test for an overlap with the block.
    /// * `block_allocation_blocks_begin` - The block's beginning on storage.
    ///   Must be aligned to the size as determined by
    ///   `block_allocation_blocks_log2`.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block's size
    ///   in units of [Allocation
    ///   Blocks](ImageLayout::allocation_block_size_128b_log2).
    fn range_overlaps_block(
        range: &layout::PhysicalAllocBlockRange,
        block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        block_allocation_blocks_log2: u32,
    ) -> bool {
        if range.end() <= block_allocation_blocks_begin {
            return false;
        }

        if range.begin() > block_allocation_blocks_begin
            && (u64::from(range.begin()) ^ u64::from(block_allocation_blocks_begin)) >> block_allocation_blocks_log2
                != 0
        {
            // range comes after the block's beginning and there's a block boundary crossing
            // inbetween.
            return false;
        }

        true
    }

    /// Trim a given storage range to its overlap with some aligned,
    /// power-of-two sized block, if any.
    ///
    /// If the `range` doesn't overlap with the block, return `None`. Otherwise
    /// return the overlapping subrange wrapped in a `Some`.
    ///
    /// # Arguments:
    ///
    /// * `range` - The extent on storage to trim to overlap with the block.
    /// * `block_allocation_blocks_begin` - The block's beginning on storage.
    ///   Must be aligned to the size as determined by
    ///   `block_allocation_blocks_log2`.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block's size
    ///   in units of [Allocation
    ///   Blocks](ImageLayout::allocation_block_size_128b_log2).
    fn trim_range_to_block(
        range: &layout::PhysicalAllocBlockRange,
        block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        block_allocation_blocks_log2: u32,
    ) -> Option<layout::PhysicalAllocBlockRange> {
        if !Self::range_overlaps_block(range, block_allocation_blocks_begin, block_allocation_blocks_log2) {
            return None;
        }

        let trimmed_range_begin = range.begin().max(block_allocation_blocks_begin);
        let trimmed_range_end =
            if (u64::from(range.end()) ^ u64::from(block_allocation_blocks_begin)) >> block_allocation_blocks_log2 == 0
            {
                range.end()
            } else {
                // Cannot overflow, it is known that range.end() comes after or at the block's
                // end, which means the latter is representable.
                block_allocation_blocks_begin + layout::AllocBlockCount::from(1u64 << block_allocation_blocks_log2)
            };

        Some(layout::PhysicalAllocBlockRange::new(
            trimmed_range_begin,
            trimmed_range_end,
        ))
    }
}

/// Read and authenticate committed data through a [`ReadBuffer`].
pub struct BufferedReadAuthenticateDataFuture<C: chip::NvChip> {
    /// All other data bundled together to allow for independenr borrowing from
    /// [`fut_state`](Self::fut_state).
    d: BufferedReadAuthenticatedDataFutureData,
    fut_state: BufferedReadAuthenticateDataFutureState<C>,
}

/// Internal [`BufferedReadAuthenticateDataFuture`] state.
struct BufferedReadAuthenticatedDataFutureData {
    request_range: layout::PhysicalAllocBlockRange,

    /// The request region aligned to the [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) size.
    auth_tree_data_block_aligned_request_range: layout::PhysicalAllocBlockRange,

    /// The beginning of the `auth_tree_data_block_aligned_request_range`
    /// as represented in the Authentication Tree Data domain.
    request_range_auth_tree_data_allocation_blocks_begin: auth_tree::AuthTreeDataAllocBlockIndex,

    /// The request range aligned to the larger of a [Chip IO
    /// Block](chip::NvChip::chip_io_block_size_128b_log2)) and an
    /// [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2).
    ///
    /// This is the area of operation.
    aligned_request_range: layout::PhysicalAllocBlockRange,

    /// Destination buffers for the `request_range`, one for each [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2).
    dst_allocation_blocks_bufs: FixedVec<FixedVec<u8, 7>, 0>,

    /// Head and tail portions of the scratch Allocation Block buffers needed to
    /// fill up the [`request_range`](Self::request_range) to
    /// [`aligned_request_range`](Self::aligned_request_range) fused together in
    /// a single array.
    alignment_scratch_allocation_blocks_bufs: FixedVec<FixedVec<u8, 7>, 0>,

    /// Subrange of [`request_range`](Self::request_range) for which
    /// authenticated data has been obtained from the [`ReadBuffer`].
    authenticated_subrange_from_read_buf: Option<layout::PhysicalAllocBlockRange>,
    /// Subrange of
    /// [`auth_tree_data_block_aligned_request_range`](Self::auth_tree_data_block_aligned_request_range)
    /// for which unauthenticated data has been obtained from the
    /// [`ReadBuffer`].
    unauthenticated_subrange_from_read_buf: Option<layout::PhysicalAllocBlockRange>,

    /// End of the
    /// [`auth_tree_data_block_aligned_request_range`](Self::auth_tree_data_block_aligned_request_range)
    /// head subrange authenticated so far.
    authenticated_allocation_blocks_end: layout::PhysicalAllocBlockIndex,

    /// [Chip IO Block](chip::NvChip::chip_io_block_size_128b_log2) in units of
    /// [Allocation Blocks](ImageLayout::allocation_block_size_128b_log2).
    min_io_block_allocation_blocks_log2: u8,
    /// [Preferred Chip IO bulk
    /// size](chip::NvChip::preferred_chip_io_blocks_bulk_log2) in units of
    /// [Allocation Blocks](ImageLayout::allocation_block_size_128b_log2).
    preferred_chip_io_bulk_allocation_blocks_log2: u8,
    /// Verbatim value of
    /// [`ImageLayout::auth_tree_data_block_allocation_blocks_log2`].
    auth_tree_data_block_allocation_blocks_log2: u8,
    /// Verbatim value of [`ImageLayout::allocation_block_size_128b_log2`].
    allocation_block_size_128b_log2: u8,
}

impl<C: chip::NvChip> BufferedReadAuthenticateDataFuture<C> {
    /// Instantiate a [`BufferedReadAuthenticateDataFuture`].
    ///
    /// # Arguments:
    ///
    /// * `request_range` - The data storage range to read and authenticate.
    ///   Must all be allocated.
    /// * `image_layout` - The filesystem's [`ImageLayout`].
    /// * `auth_tree_config` - The filesystem's
    ///   [`AuthTreeConfig`](auth_tree::AuthTreeConfig).
    /// * `chip` - The filesystem image backing storage.
    pub fn new(
        request_range: &layout::PhysicalAllocBlockRange,
        image_layout: &layout::ImageLayout,
        auth_tree_config: &auth_tree::AuthTreeConfig,
        chip: &C,
    ) -> Result<Self, NvFsError> {
        let request_range_allocation_blocks = match usize::try_from(u64::from(request_range.block_count())) {
            Ok(request_range_allocation_blocks) => request_range_allocation_blocks,
            Err(_) => return Err(NvFsError::DimensionsNotSupported),
        };

        let auth_tree_data_block_allocation_blocks_log2 = image_layout.auth_tree_data_block_allocation_blocks_log2;
        let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2;
        let chip_io_block_size_128b = chip.chip_io_block_size_128b_log2();
        let preferred_chip_io_blocks_bulk_log2 = chip.preferred_chip_io_blocks_bulk_log2();

        let min_io_block_allocation_blocks_log2 =
            u8::try_from(chip_io_block_size_128b.saturating_sub(allocation_block_size_128b_log2 as u32))
                .map_err(|_| nvfs_err_internal!())?;
        // Determine the preferred Chip IO request block size in units of Allocation
        // Blocks. Possibly ramp it up to some reasonable value to the reduce
        // the overall number of IO requests.
        let preferred_chip_io_bulk_allocation_blocks_log2 = preferred_chip_io_blocks_bulk_log2
            .saturating_add(chip_io_block_size_128b)
            .min(usize::BITS - 1 + allocation_block_size_128b_log2 as u32)
            .saturating_sub(allocation_block_size_128b_log2 as u32)
            .max(auth_tree_data_block_allocation_blocks_log2 as u32)
            as u8;

        let auth_tree_data_block_aligned_request_range =
            match request_range.align(auth_tree_data_block_allocation_blocks_log2 as u32) {
                Some(auth_tree_data_block_aligned_request_range) => auth_tree_data_block_aligned_request_range,
                None => {
                    return Err(NvFsError::from(CocoonFsFormatError::BlockOutOfRange));
                }
            };

        let request_range_auth_tree_data_allocation_blocks_begin =
            auth_tree::AuthTreeDataAllocBlockIndex::new_from_data_block_index(
                auth_tree_config
                    .translate_physical_to_data_block_index(auth_tree_data_block_aligned_request_range.begin()),
                auth_tree_data_block_allocation_blocks_log2 as u32,
            );

        // The request range aligned to the larger of the Chip IO Block and
        // Authenication Tree Data Block size, this is the area of operation.
        let aligned_request_range =
            match auth_tree_data_block_aligned_request_range.align(min_io_block_allocation_blocks_log2 as u32) {
                Some(min_io_block_aligned_request_range) => min_io_block_aligned_request_range,
                None => {
                    return Err(NvFsError::from(CocoonFsFormatError::BlockOutOfRange));
                }
            };

        // Check that the total IO range's length in units of Allocation Blocks fits an
        // usize, the rest of the code relies on that without conducting any
        // further checks.
        if usize::try_from(u64::from(aligned_request_range.block_count())).is_err() {
            return Err(NvFsError::DimensionsNotSupported);
        }

        let dst_allocation_blocks_bufs = FixedVec::new_with_default(request_range_allocation_blocks)?;

        // Will get allocated lazily if needed.
        let alignment_scratch_allocation_blocks_bufs = FixedVec::new_empty();

        Ok(Self {
            d: BufferedReadAuthenticatedDataFutureData {
                request_range: *request_range,
                auth_tree_data_block_aligned_request_range,
                request_range_auth_tree_data_allocation_blocks_begin,
                aligned_request_range,
                dst_allocation_blocks_bufs,
                alignment_scratch_allocation_blocks_bufs,
                authenticated_subrange_from_read_buf: None,
                unauthenticated_subrange_from_read_buf: None,
                authenticated_allocation_blocks_end: auth_tree_data_block_aligned_request_range.begin(),
                min_io_block_allocation_blocks_log2,
                preferred_chip_io_bulk_allocation_blocks_log2,
                auth_tree_data_block_allocation_blocks_log2,
                allocation_block_size_128b_log2,
            },
            fut_state: BufferedReadAuthenticateDataFutureState::Init,
        })
    }

    /// Poll the [`BufferedReadAuthenticateDataFuture`] to completion.
    ///
    /// On successful completion, a `FixedVec` of buffers is being returned, one
    /// for each [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) in the requested
    /// read range.
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `image_layout` - The filesystem's [`ImageLayout`].
    /// * `image_header_end` - [End of the filesystem image header on
    ///   storage](super::image_header::MutableImageHeader::physical_location).
    /// * `fs_sync_state_alloc_bitmap` - The [filesystem instance's allocation
    ///   bitmap](super::fs::CocoonFsSyncState::alloc_bitmap).
    /// * `fs_sync_state_auth_tree` - The [filesystem instance's authentication
    ///   tree](super::fs::CocoonFsSyncState::auth_tree).
    /// * `fs_sync_state_read_buffer` - The [filesystem instance's read
    ///   buffer](super::fs::CocoonFsSyncState::read_buffer).
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    #[allow(clippy::too_many_arguments)]
    pub fn poll<ST: sync_types::SyncTypes>(
        self: pin::Pin<&mut Self>,
        chip: &C,
        image_layout: &layout::ImageLayout,
        image_header_end: layout::PhysicalAllocBlockIndex,
        fs_sync_state_alloc_bitmap: &alloc_bitmap::AllocBitmap,
        fs_sync_state_auth_tree: &mut auth_tree::AuthTreeRef<'_, ST>,
        fs_sync_state_read_buffer: &ReadBuffer<ST>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<FixedVec<FixedVec<u8, 7>, 0>, NvFsError>> {
        let this = pin::Pin::into_inner(self);
        {
            debug_assert_eq!(
                (
                    this.d.min_io_block_allocation_blocks_log2,
                    this.d.auth_tree_data_block_allocation_blocks_log2,
                    this.d.allocation_block_size_128b_log2
                ),
                (
                    fs_sync_state_read_buffer.min_io_block_allocation_blocks_log2,
                    fs_sync_state_read_buffer.auth_tree_data_block_allocation_blocks_log2,
                    fs_sync_state_read_buffer.allocation_block_size_128b_log2
                )
            );
        }
        let min_io_block_allocation_blocks_log2 = this.d.min_io_block_allocation_blocks_log2 as u32;
        let auth_tree_data_block_allocation_blocks_log2 = this.d.auth_tree_data_block_allocation_blocks_log2 as u32;
        let allocation_block_size_128b_log2 = this.d.allocation_block_size_128b_log2 as u32;

        loop {
            match &mut this.fut_state {
                BufferedReadAuthenticateDataFutureState::Init => {
                    // First try to obtain anything already authenticated from the read buffer.
                    if let Some((found_subrange, auth_tree_data_block_complete)) = fs_sync_state_read_buffer
                        .take_authenticated_buffers(&this.d.request_range, this.d.dst_allocation_blocks_bufs.iter_mut())
                    {
                        if !auth_tree_data_block_complete {
                            // Some authenticated allocation blocks had been found in the read
                            // buffer, but some from the containing Authentication Tree Data Block
                            // which fall within the request range had been missing. Partial
                            // Authentication Tree Data Blocks don't help, because the
                            // authentication of the containing Authentication Tree Data Block needs
                            // to be re-done anyway. Clear the range again to simplify matters
                            // everywhere else.
                            this.d.dst_allocation_blocks_bufs[u64::from(
                                found_subrange.begin() - this.d.request_range.begin(),
                            ) as usize
                                ..u64::from(found_subrange.end() - this.d.request_range.begin()) as usize]
                                .fill(FixedVec::new_empty());
                        } else {
                            if found_subrange == this.d.request_range {
                                // All found authenticated in the read buffer -> done.
                                this.fut_state = BufferedReadAuthenticateDataFutureState::Done;
                                return task::Poll::Ready(Ok(mem::take(&mut this.d.dst_allocation_blocks_bufs)));
                            }
                            this.d.authenticated_subrange_from_read_buf = Some(found_subrange);
                        }
                    }

                    // Now it is known that the alignment scratch buffers will probably be
                    // needed. Allocate them (not the buffers themselves yet, but the FixedVec
                    // holding the buffer FixedVecs).
                    this.d.allocate_alignment_scratch_allocation_blocks_buf()?;

                    // Try to obtain unauthenticated data overlapping with the request range from
                    // the read buffer. Note that in practice this is relevant only
                    // - if the Chip IO Block size is larger than an Authentication Tree Data Block
                    //   and
                    // - only for the range's head and tail regions, as it is (almost) impossible to
                    //   find a complete Chip IO block still in the read buffer -- in the common
                    //   case, parts of it would have been consumed already at insertion time.
                    // So try to gather any unauthenticated data for the
                    // auth_tree_data_block_aligned_request_range, which in general is not aligned
                    // to the Chip IO Block size.
                    let (
                        head_auth_tree_data_block_alignment_scratch_allocation_blocks_bufs,
                        tail_auth_tree_data_block_alignment_scratch_allocation_blocks_bufs,
                    ) = BufferedReadAuthenticatedDataFutureData
                            ::get_auth_tree_data_block_alignment_scratch_allocation_blocks_bufs(
                        &mut this.d.alignment_scratch_allocation_blocks_bufs,
                        &this.d.request_range,
                        &this.d.auth_tree_data_block_aligned_request_range,
                        &this.d.aligned_request_range,
                    );

                    if let Some((found_subrange, min_io_block_complete)) = fs_sync_state_read_buffer
                        .take_unauthenticated_buffers(
                            &this.d.auth_tree_data_block_aligned_request_range,
                            head_auth_tree_data_block_alignment_scratch_allocation_blocks_bufs
                                .iter_mut()
                                .chain(this.d.dst_allocation_blocks_bufs.iter_mut())
                                .chain(tail_auth_tree_data_block_alignment_scratch_allocation_blocks_bufs),
                        )
                    {
                        // Some unauthenticated Allocation Blocks from a certain Chip IO Block
                        // overlapping with the request range had been found in the read buffer.
                        // Note that this implies that the Minimum IO Block size is larger than the
                        // Authentication Tree Data Block size, because otherwise unauthenticated
                        // allocation blocks would not have been kept in the read buffer.
                        if !min_io_block_complete {
                            // There are some Allocation Blocks missing in some of the containing
                            // Minimum IO Block's Authentication Tree Data Blocks overlapping with
                            // the request_range. That means that the containing Minimum IO Block
                            // needs to get re-read anyway, and what has just been obtained from the
                            // read buffer will be of no value. Clear that out again in order to
                            // simplify the logic.
                            this.d
                                .alignment_scratch_allocation_blocks_bufs
                                .fill(FixedVec::new_empty());
                            this.d.dst_allocation_blocks_bufs.fill(FixedVec::new_empty());
                        } else {
                            this.d.unauthenticated_subrange_from_read_buf = Some(found_subrange);
                        }

                        // In the highly unlikely event that the unauthenticated buffers just
                        // retrieved alias with any authenticated ones obtained above, invalidate
                        // the authentication status -- the authenticated buffers would have been
                        // overwritten with unauthenticated ones then.
                        if this
                            .d
                            .authenticated_subrange_from_read_buf
                            .map(|authenticated_subrange_from_read_buf| {
                                authenticated_subrange_from_read_buf.overlaps_with(&found_subrange)
                            })
                            .unwrap_or(false)
                        {
                            this.d.authenticated_subrange_from_read_buf = None;
                        }

                        if this
                            .d
                            .unauthenticated_subrange_from_read_buf
                            .as_ref()
                            .map(|unauthenticated_subrange_from_read_buf| {
                                unauthenticated_subrange_from_read_buf
                                    == &this.d.auth_tree_data_block_aligned_request_range
                            })
                            .unwrap_or(false)
                        {
                            // All the data is there, proceed to the authentication.
                            this.fut_state = BufferedReadAuthenticateDataFutureState::AuthenticateSubrange {
                                auth_subrange_fut_state: BufferedReadAuthenticateDataFutureAuthenticateState::Init,
                            };
                            continue;
                        }
                    }

                    // Finally allocate Allocation Block destination buffers for anything not
                    // obtained from the read buffer.
                    let (head_alignment_scratch_allocation_blocks_bufs, tail_alignment_scratch_allocation_blocks_bufs) =
                        BufferedReadAuthenticatedDataFutureData::get_alignment_scratch_allocation_blocks_bufs(
                            &mut this.d.alignment_scratch_allocation_blocks_bufs,
                            &this.d.request_range,
                            &this.d.aligned_request_range,
                        );

                    let ((unused_head_alignment_scratch_allocation_blocks_bufs,
                          used_head_alignment_scratch_allocation_blocks_bufs),
                         (used_tail_alignment_scratch_allocation_blocks_bufs,
                          _unused_tail_alignment_scratch_allocation_blocks_bufs)) =
                         BufferedReadAuthenticatedDataFutureData
                        ::split_off_unused_alignment_scratch_allocation_blocks_bufs(
                            head_alignment_scratch_allocation_blocks_bufs,
                            tail_alignment_scratch_allocation_blocks_bufs,
                            &this.d.request_range,
                            &this.d.auth_tree_data_block_aligned_request_range,
                            this.d.authenticated_subrange_from_read_buf.as_ref(),
                            this.d.unauthenticated_subrange_from_read_buf.as_ref(),
                            min_io_block_allocation_blocks_log2
                        );

                    let mut cur_allocation_block_index = this.d.aligned_request_range.begin()
                        + layout::AllocBlockCount::from(
                            unused_head_alignment_scratch_allocation_blocks_bufs.len() as u64
                        );
                    debug_assert!(
                        cur_allocation_block_index == this.d.aligned_request_range.begin()
                            || cur_allocation_block_index == this.d.request_range.begin()
                    );
                    debug_assert!(cur_allocation_block_index < this.d.auth_tree_data_block_aligned_request_range.end());

                    let allocation_block_size = 1usize << (image_layout.allocation_block_size_128b_log2 as u32 + 7);
                    let empty_sparse_alloc_bitmap = alloc_bitmap::SparseAllocBitmapUnion::new(&[]);
                    let mut alloc_bitmap_iter = fs_sync_state_alloc_bitmap.iter_at_allocation_block(
                        &empty_sparse_alloc_bitmap,
                        &empty_sparse_alloc_bitmap,
                        cur_allocation_block_index,
                    );

                    for allocation_block_buf in used_head_alignment_scratch_allocation_blocks_bufs
                        .iter_mut()
                        .chain(this.d.dst_allocation_blocks_bufs.iter_mut())
                        .chain(used_tail_alignment_scratch_allocation_blocks_bufs.iter_mut())
                    {
                        debug_assert!(cur_allocation_block_index < this.d.aligned_request_range.end());
                        let allocation_block_is_allocated = alloc_bitmap_iter.next().unwrap_or(false);
                        // All Allocation Blocks in the requested range are assumed to be allocated.
                        debug_assert!(
                            cur_allocation_block_index < this.d.request_range.begin()
                                || cur_allocation_block_index >= this.d.request_range.end()
                                || allocation_block_is_allocated
                        );
                        if allocation_block_is_allocated && allocation_block_buf.is_empty() {
                            *allocation_block_buf = match FixedVec::new_with_default(allocation_block_size) {
                                Ok(allocation_block_buf) => allocation_block_buf,
                                Err(e) => {
                                    this.fut_state = BufferedReadAuthenticateDataFutureState::Done;
                                    return task::Poll::Ready(Err(NvFsError::from(e)));
                                }
                            };
                        }

                        cur_allocation_block_index += layout::AllocBlockCount::from(1u64);
                    }

                    this.fut_state = BufferedReadAuthenticateDataFutureState::PrepareNextSubrangeDataRead {
                        read_subrange_allocation_blocks_begin: this.d.authenticated_allocation_blocks_end,
                    };
                }
                BufferedReadAuthenticateDataFutureState::PrepareNextSubrangeDataRead {
                    read_subrange_allocation_blocks_begin,
                } => {
                    let auth_tree_config = fs_sync_state_auth_tree.get_config();
                    let read_range = match this
                        .d
                        .determine_next_read_region(*read_subrange_allocation_blocks_begin, auth_tree_config)
                    {
                        Ok(next_read_range) => next_read_range,
                        Err(e) => {
                            this.fut_state = BufferedReadAuthenticateDataFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };

                    // If a batch worth authenticating has been read to this point,
                    // determine_next_read_region() from above returns None, otherwise the next
                    // physical region to read in.
                    let read_range = match read_range {
                        Some(read_range) => read_range,
                        None => {
                            // Everything needed for authenticating a batch of data is there.
                            this.fut_state = BufferedReadAuthenticateDataFutureState::AuthenticateSubrange {
                                auth_subrange_fut_state: BufferedReadAuthenticateDataFutureAuthenticateState::Init,
                            };
                            continue;
                        }
                    };

                    let read_request_io_region = ChunkedIoRegion::new(
                        u64::from(read_range.begin()) << allocation_block_size_128b_log2,
                        u64::from(read_range.end()) << allocation_block_size_128b_log2,
                        allocation_block_size_128b_log2,
                    )
                    .map_err(|e| match e {
                        ChunkedIoRegionError::ChunkSizeOverflow | ChunkedIoRegionError::ChunkIndexOverflow => {
                            NvFsError::DimensionsNotSupported
                        }
                        ChunkedIoRegionError::InvalidBounds | ChunkedIoRegionError::RegionUnaligned => {
                            nvfs_err_internal!()
                        }
                    })?;

                    // The read request assumes ownership of all IO buffers for the duration it's
                    // pending.  hey'll get returned upon completion.
                    let read_request = BufferedReadAuthenticateDataFutureNvChipReadRequest {
                        aligned_request_range_allocation_blocks_begin: this.d.aligned_request_range.begin(),
                        dst_allocation_blocks_bufs: mem::take(&mut this.d.dst_allocation_blocks_bufs),
                        alignment_scratch_allocation_blocks_bufs: mem::take(
                            &mut this.d.alignment_scratch_allocation_blocks_bufs,
                        ),
                        head_alignment_scratch_allocation_blocks: u64::from(
                            this.d.request_range.begin() - this.d.aligned_request_range.begin(),
                        ) as usize,
                        authenticated_subrange_from_read_buf: this.d.authenticated_subrange_from_read_buf,
                        read_request_allocation_blocks_begin: read_range.begin(),
                        read_request_io_region,
                    };

                    let read_fut = match chip.read(read_request).and_then(|r| r.map_err(|(_, e)| e)) {
                        Ok(read_fut) => read_fut,
                        Err(e) => {
                            this.fut_state = BufferedReadAuthenticateDataFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    this.fut_state = BufferedReadAuthenticateDataFutureState::ReadSubrangeData { read_range, read_fut };
                }
                BufferedReadAuthenticateDataFutureState::ReadSubrangeData { read_range, read_fut } => {
                    match chip::NvChipFuture::poll(pin::Pin::new(read_fut), chip, cx) {
                        task::Poll::Pending => return task::Poll::Pending,
                        task::Poll::Ready(Ok((mut completed_read_request, Ok(())))) => {
                            // Return IO buffer ownership back from the request.
                            this.d.dst_allocation_blocks_bufs =
                                mem::take(&mut completed_read_request.dst_allocation_blocks_bufs);
                            this.d.alignment_scratch_allocation_blocks_bufs =
                                mem::take(&mut completed_read_request.alignment_scratch_allocation_blocks_bufs);
                            this.fut_state = BufferedReadAuthenticateDataFutureState::PrepareNextSubrangeDataRead {
                                read_subrange_allocation_blocks_begin: read_range.end(),
                            };
                        }
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                            this.fut_state = BufferedReadAuthenticateDataFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    }
                }
                BufferedReadAuthenticateDataFutureState::AuthenticateSubrange {
                    auth_subrange_fut_state,
                } => {
                    let auth_tree_config = fs_sync_state_auth_tree.get_config();
                    let auth_tree_covered_data_blocks_per_leaf_node_log2 =
                        auth_tree_config.covered_data_blocks_per_leaf_node_log2() as u32;
                    let auth_tree_covered_allocation_blocks_per_leaf_node_log2 =
                        auth_tree_covered_data_blocks_per_leaf_node_log2 + auth_tree_data_block_allocation_blocks_log2;

                    match auth_subrange_fut_state {
                        BufferedReadAuthenticateDataFutureAuthenticateState::Init => {
                            debug_assert!(this.d.authenticated_allocation_blocks_end < this.d.request_range.end());
                            if let Some(authenticated_subrange_from_read_buf) =
                                this.d.authenticated_subrange_from_read_buf.as_ref()
                            {
                                // An authenticated subrange initially obtained from the read buffer
                                // aligning to the left boundary of the request range is not
                                // necessarily aligned to the Authentication Tree Data Block size,
                                // check for this case explictly.
                                if this.d.authenticated_allocation_blocks_end
                                    == authenticated_subrange_from_read_buf.begin()
                                    || (this.d.authenticated_allocation_blocks_end
                                        == this.d.auth_tree_data_block_aligned_request_range.begin()
                                        && authenticated_subrange_from_read_buf.begin() == this.d.request_range.begin())
                                {
                                    this.d.authenticated_allocation_blocks_end =
                                        authenticated_subrange_from_read_buf.end();
                                    if this.d.authenticated_allocation_blocks_end >= this.d.request_range.end() {
                                        this.fut_state = BufferedReadAuthenticateDataFutureState::Finish;
                                        continue;
                                    } else if (u64::from(
                                        this.d.translate_physical_to_auth_tree_data_allocation_block_index(
                                            authenticated_subrange_from_read_buf.begin(),
                                        ),
                                    ) ^ u64::from(
                                        this.d.translate_physical_to_auth_tree_data_allocation_block_index(
                                            authenticated_subrange_from_read_buf.end(),
                                        ),
                                    )) >> auth_tree_covered_allocation_blocks_per_leaf_node_log2
                                        != 0
                                    {
                                        // Exhausted the region covered by a single Authentication
                                        // Tree Leaf Node, read the next one, if any.
                                        this.fut_state =
                                            BufferedReadAuthenticateDataFutureState::PrepareNextSubrangeDataRead {
                                                read_subrange_allocation_blocks_begin: this
                                                    .d
                                                    .authenticated_allocation_blocks_end,
                                            };
                                        continue;
                                    }
                                }
                            }
                            debug_assert_eq!(
                                this.d
                                    .authenticated_allocation_blocks_end
                                    .align_down(auth_tree_data_block_allocation_blocks_log2),
                                this.d.authenticated_allocation_blocks_end
                            );

                            if this.d.authenticated_allocation_blocks_end
                                == this.d.auth_tree_data_block_aligned_request_range.end()
                            {
                                this.fut_state = BufferedReadAuthenticateDataFutureState::Finish;
                                continue;
                            }

                            let auth_tree_data_block_index = auth_tree_config
                                .translate_physical_to_data_block_index(this.d.authenticated_allocation_blocks_end);
                            let auth_tree_leaf_node_id =
                                auth_tree_config.covering_leaf_node_id(auth_tree_data_block_index);
                            let auth_tree_leaf_node_load_fut =
                                auth_tree::AuthTreeNodeLoadFuture::new(auth_tree_leaf_node_id);
                            *auth_subrange_fut_state =
                                BufferedReadAuthenticateDataFutureAuthenticateState::LoadAuthTreeLeafNode {
                                    auth_tree_data_block_index,
                                    auth_tree_leaf_node_load_fut,
                                };
                        }
                        BufferedReadAuthenticateDataFutureAuthenticateState::LoadAuthTreeLeafNode {
                            auth_tree_data_block_index,
                            auth_tree_leaf_node_load_fut,
                        } => {
                            let (auth_tree_config, auth_tree_root_hmac_digest, mut auth_tree_node_cache) =
                                fs_sync_state_auth_tree.destructure_borrow();
                            let leaf_node = match auth_tree::AuthTreeNodeLoadFuture::poll(
                                pin::Pin::new(auth_tree_leaf_node_load_fut),
                                chip,
                                auth_tree_config,
                                auth_tree_root_hmac_digest,
                                &mut auth_tree_node_cache,
                                cx,
                            ) {
                                task::Poll::Ready(Ok(leaf_node)) => leaf_node,
                                task::Poll::Ready(Err(e)) => {
                                    this.fut_state = BufferedReadAuthenticateDataFutureState::Done;
                                    return task::Poll::Ready(Err(e));
                                }
                                task::Poll::Pending => return task::Poll::Pending,
                            };

                            // We've got the Authentication Tree Leaf node and all data covered by
                            // it has been read in by now, as per the logic of
                            // determine_next_read_region() and the PrepareNextSubrangeDataRead
                            // state handling. Authenticate it. Note that the request region is
                            // contiguous on physical storage, hence not interspersed by the
                            // Authenication Tree Nodes themselves and thus, the Authentication Tree
                            // Data Block indices, i.e. those obtained from he
                            // AuthTreeConfig::translate_physical_data_block(), corresponding to the
                            // request region are contiguous as well.
                            loop {
                                debug_assert!({
                                    let cur_auth_tree_data_block_index = auth_tree_config
                                        .translate_physical_to_data_block_index(
                                            this.d.authenticated_allocation_blocks_end,
                                        );
                                    let leaf_node_id = leaf_node.get_node_id();
                                    *auth_tree_data_block_index == cur_auth_tree_data_block_index
                                        && cur_auth_tree_data_block_index >= leaf_node_id.first_covered_data_block()
                                        && cur_auth_tree_data_block_index <= leaf_node_id.last_covered_data_block()
                                });

                                let (
                                    head_alignment_scratch_allocation_blocks,
                                    tail_alignment_scratch_allocation_blocks_bufs,
                                ) = BufferedReadAuthenticatedDataFutureData
                                        ::get_auth_tree_data_block_alignment_scratch_allocation_blocks_bufs(
                                    &mut this.d.alignment_scratch_allocation_blocks_bufs,
                                    &this.d.request_range,
                                    &this.d.auth_tree_data_block_aligned_request_range,
                                    &this.d.aligned_request_range,
                                );

                                // Prepare an iterator over the current Authentication Tree Data
                                // Block's individual Allocation Blocks' buffers. No usize overflows
                                // possible here, the whole aligned_range in units of Allocation
                                // Blocks fits an usize.
                                let cur_auth_tree_data_block_allocation_blocks_iter =
                                    head_alignment_scratch_allocation_blocks
                                        .iter()
                                        .chain(this.d.dst_allocation_blocks_bufs.iter())
                                        .chain(tail_alignment_scratch_allocation_blocks_bufs.iter())
                                        .skip(u64::from(
                                            this.d.authenticated_allocation_blocks_end
                                                - this.d.auth_tree_data_block_aligned_request_range.begin(),
                                        ) as usize)
                                        .take(1usize << auth_tree_data_block_allocation_blocks_log2)
                                        .map(|allocation_block_buf| {
                                            Ok((!allocation_block_buf.is_empty())
                                                .then_some(allocation_block_buf.as_slice()))
                                        });

                                if let Err(e) = auth_tree_config.authenticate_data_block_from_tree(
                                    &leaf_node,
                                    *auth_tree_data_block_index,
                                    cur_auth_tree_data_block_allocation_blocks_iter,
                                    image_header_end,
                                ) {
                                    this.fut_state = BufferedReadAuthenticateDataFutureState::Done;
                                    return task::Poll::Ready(Err(e));
                                }

                                // Advance the current position.
                                debug_assert_eq!(
                                    this.d
                                        .authenticated_allocation_blocks_end
                                        .align_down(auth_tree_data_block_allocation_blocks_log2),
                                    this.d.authenticated_allocation_blocks_end
                                );
                                this.d.authenticated_allocation_blocks_end +=
                                    layout::AllocBlockCount::from(1u64 << auth_tree_data_block_allocation_blocks_log2);
                                *auth_tree_data_block_index += auth_tree::AuthTreeDataBlockCount::from(1);

                                // Skip over the authenticated region at point initially obtained from the
                                // read buffer, if any.
                                if let Some(authenticated_subrange_from_read_buf) =
                                    this.d.authenticated_subrange_from_read_buf.as_ref()
                                {
                                    if this.d.authenticated_allocation_blocks_end
                                        == authenticated_subrange_from_read_buf.begin()
                                    {
                                        this.d.authenticated_allocation_blocks_end =
                                            authenticated_subrange_from_read_buf.end();
                                        // If the request is not complete yet,
                                        // authenticated_allocation_blocks_end is still aligned to
                                        // a Authentication Tree Data Block boundary.
                                        debug_assert!(
                                            this.d.authenticated_allocation_blocks_end >= this.d.request_range.end()
                                                || this
                                                    .d
                                                    .authenticated_allocation_blocks_end
                                                    .align_down(auth_tree_data_block_allocation_blocks_log2)
                                                    == this.d.authenticated_allocation_blocks_end
                                        );
                                        // Advance the auth_tree_data_block_index position needed
                                        // for authentication accordingly. The authenticated range
                                        // initially obtained from the read buffer spans one
                                        // Autehntication Tree Data Block at most.
                                        debug_assert!(
                                            u64::from(
                                                authenticated_subrange_from_read_buf.end()
                                                    - authenticated_subrange_from_read_buf.begin()
                                            ) >> auth_tree_data_block_allocation_blocks_log2
                                                <= 1
                                        );
                                        *auth_tree_data_block_index += auth_tree::AuthTreeDataBlockCount::from(1);
                                    }
                                }

                                if this.d.authenticated_allocation_blocks_end >= this.d.request_range.end() {
                                    break;
                                }
                                let leaf_node_id = leaf_node.get_node_id();
                                if *auth_tree_data_block_index < leaf_node_id.first_covered_data_block()
                                    || *auth_tree_data_block_index > leaf_node_id.last_covered_data_block()
                                {
                                    // Exhausted the region covered by a single Authentication
                                    // Tree leaf node.  Stop authenticating for now and proceeed
                                    // with reading data for the next one.
                                    break;
                                }
                            }

                            if this.d.authenticated_allocation_blocks_end >= this.d.request_range.end() {
                                this.fut_state = BufferedReadAuthenticateDataFutureState::Finish;
                            } else {
                                this.fut_state = BufferedReadAuthenticateDataFutureState::PrepareNextSubrangeDataRead {
                                    read_subrange_allocation_blocks_begin: this.d.authenticated_allocation_blocks_end,
                                };
                            }
                        }
                    }
                }
                BufferedReadAuthenticateDataFutureState::Finish => {
                    // All done. Insert anything from the alignment scratch buffers, i.e. everything
                    // not needed for fulfilling the request_range, into the read buffer for
                    // consumption in future requests.
                    // First do any Allocation Buffers not in the original request range
                    // authenticated as a by-product.
                    let (
                        authenticated_head_alignment_scratch_allocation_blocks_bufs,
                        authenticated_tail_alignment_scratch_allocation_blocks_bufs,
                    ) = BufferedReadAuthenticatedDataFutureData
                            ::get_auth_tree_data_block_alignment_scratch_allocation_blocks_bufs(
                        &mut this.d.alignment_scratch_allocation_blocks_bufs,
                        &this.d.request_range,
                        &this.d.auth_tree_data_block_aligned_request_range,
                        &this.d.aligned_request_range,
                    );
                    // Careful, careful, the alignment scratch buffers at either end might not have
                    // been authenticated if an authenticated region aligning with the original left
                    // or right end had initially been obtained from the read buffer.
                    let (head_is_authenticated, tail_is_authenticated) = this
                        .d
                        .authenticated_subrange_from_read_buf
                        .as_ref()
                        .map(|authenticated_subrange_from_read_buf| {
                            (
                                authenticated_subrange_from_read_buf.begin() != this.d.request_range.begin(),
                                authenticated_subrange_from_read_buf.end() != this.d.request_range.end(),
                            )
                        })
                        .unwrap_or((true, true));
                    let mut authenticated_head_alignment_scratch_allocation_blocks_bufs_taken = false;
                    let mut authenticated_tail_alignment_scratch_allocation_blocks_bufs_taken = false;
                    if (!authenticated_head_alignment_scratch_allocation_blocks_bufs.is_empty()
                        && head_is_authenticated)
                        || (!authenticated_tail_alignment_scratch_allocation_blocks_bufs.is_empty()
                            && tail_is_authenticated)
                    {
                        if u64::from(
                            this.d.auth_tree_data_block_aligned_request_range.end()
                                - this.d.auth_tree_data_block_aligned_request_range.begin(),
                        ) >> auth_tree_data_block_allocation_blocks_log2
                            == 1
                        {
                            // The head and tail are contained in the same Authentication Tree Data
                            // Block, insert them together at once.
                            fs_sync_state_read_buffer.insert_authenticated_buffers(
                                this.d.auth_tree_data_block_aligned_request_range.begin(),
                                (authenticated_head_alignment_scratch_allocation_blocks_bufs
                                    .iter_mut()
                                    .map(|allocation_block_buf| head_is_authenticated.then_some(allocation_block_buf)))
                                .chain(this.d.dst_allocation_blocks_bufs.iter().map(|_| None))
                                .chain(
                                    authenticated_tail_alignment_scratch_allocation_blocks_bufs
                                        .iter_mut()
                                        .map(|allocation_block_buf| {
                                            tail_is_authenticated.then_some(allocation_block_buf)
                                        }),
                                ),
                            );
                            authenticated_head_alignment_scratch_allocation_blocks_bufs_taken |= head_is_authenticated;
                            authenticated_tail_alignment_scratch_allocation_blocks_bufs_taken |= tail_is_authenticated;
                        } else if !authenticated_tail_alignment_scratch_allocation_blocks_bufs.is_empty()
                            && tail_is_authenticated
                        {
                            fs_sync_state_read_buffer.insert_authenticated_buffers(
                                this.d.request_range.end(),
                                authenticated_tail_alignment_scratch_allocation_blocks_bufs
                                    .iter_mut()
                                    .map(Some),
                            );
                            authenticated_head_alignment_scratch_allocation_blocks_bufs_taken = true;
                        } else if !authenticated_head_alignment_scratch_allocation_blocks_bufs.is_empty()
                            && head_is_authenticated
                        {
                            fs_sync_state_read_buffer.insert_authenticated_buffers(
                                this.d.auth_tree_data_block_aligned_request_range.begin(),
                                authenticated_head_alignment_scratch_allocation_blocks_bufs
                                    .iter_mut()
                                    .map(Some),
                            );
                            authenticated_tail_alignment_scratch_allocation_blocks_bufs_taken = true;
                        }
                    }

                    // And insert the remaining alignment scratch Allocation Blocks read but not
                    // authenticated into the read buffer. Don't bother inserting if all are
                    // unallocated.
                    if fs_sync_state_read_buffer.min_io_blocks_are_buffered() {
                        let (
                            head_alignment_scratch_allocation_blocks_bufs,
                            tail_alignment_scratch_allocation_blocks_bufs,
                        ) = BufferedReadAuthenticatedDataFutureData::get_alignment_scratch_allocation_blocks_bufs(
                            &mut this.d.alignment_scratch_allocation_blocks_bufs,
                            &this.d.request_range,
                            &this.d.aligned_request_range,
                        );
                        let (
                            (unused_head_alignment_scratch_allocation_blocks_bufs,
                             used_head_alignment_scratch_allocation_blocks_bufs),
                             (used_tail_alignment_scratch_allocation_blocks_bufs,
                              _unused_tail_alignment_scratch_allocation_blocks_bufs)
                        ) = BufferedReadAuthenticatedDataFutureData
                                ::split_off_unused_alignment_scratch_allocation_blocks_bufs(
                                    head_alignment_scratch_allocation_blocks_bufs,
                                    tail_alignment_scratch_allocation_blocks_bufs,
                                    &this.d.request_range,
                                    &this.d.auth_tree_data_block_aligned_request_range,
                                    this.d.authenticated_subrange_from_read_buf.as_ref(),
                                    this.d.unauthenticated_subrange_from_read_buf.as_ref(),
                                    min_io_block_allocation_blocks_log2
                                );
                        let any_allocated_at_head = used_head_alignment_scratch_allocation_blocks_bufs
                            .iter()
                            .any(|allocation_block_buf| !allocation_block_buf.is_empty());
                        let any_allocated_at_tail = used_tail_alignment_scratch_allocation_blocks_bufs
                            .iter()
                            .any(|allocation_block_buf| !allocation_block_buf.is_empty());
                        if any_allocated_at_head || any_allocated_at_tail {
                            // If any of the authenticated Allocation Block buffers had been taken
                            // and inserted above, they are empty buffers now. Be careful not to
                            // insert those as such, but as None, because otherwise the entry in the
                            // read buffer might  errorneously be mistaken as to representing an
                            // unallocated Allocation Block in the future.
                            let (
                                remaining_head_alignment_scratch_allocation_blocks_bufs,
                                taken_head_alignment_scratch_allocation_blocks_bufs,
                            ) = if authenticated_head_alignment_scratch_allocation_blocks_bufs_taken {
                                used_head_alignment_scratch_allocation_blocks_bufs.split_at_mut(u64::from(
                                    this.d.auth_tree_data_block_aligned_request_range.begin()
                                        - this.d.aligned_request_range.begin(),
                                )
                                    as usize)
                            } else {
                                used_head_alignment_scratch_allocation_blocks_bufs
                                    .split_at_mut(used_head_alignment_scratch_allocation_blocks_bufs.len())
                            };
                            let (
                                taken_tail_alignment_scratch_allocation_blocks_bufs,
                                remaining_tail_alignment_scratch_allocation_blocks_bufs,
                            ) = if authenticated_tail_alignment_scratch_allocation_blocks_bufs_taken {
                                used_tail_alignment_scratch_allocation_blocks_bufs.split_at_mut(u64::from(
                                    this.d.auth_tree_data_block_aligned_request_range.end()
                                        - this.d.request_range.end(),
                                )
                                    as usize)
                            } else {
                                used_tail_alignment_scratch_allocation_blocks_bufs.split_at_mut(0)
                            };

                            if u64::from(this.d.aligned_request_range.end() - this.d.aligned_request_range.begin())
                                >> min_io_block_allocation_blocks_log2
                                == 1
                            {
                                // The head and tail are contained in the same Authentication Tree Data
                                // Block, insert them together at once.
                                fs_sync_state_read_buffer.insert_unauthenticated_buffers(
                                    this.d.aligned_request_range.begin(),
                                    (unused_head_alignment_scratch_allocation_blocks_bufs
                                        .iter()
                                        .map(|_| None))
                                    .chain(
                                        remaining_head_alignment_scratch_allocation_blocks_bufs
                                            .iter_mut()
                                            .map(Some),
                                    )
                                    .chain(taken_head_alignment_scratch_allocation_blocks_bufs.iter().map(|_| None))
                                    .chain(this.d.dst_allocation_blocks_bufs.iter().map(|_| None))
                                    .chain(taken_tail_alignment_scratch_allocation_blocks_bufs.iter().map(|_| None))
                                    .chain(
                                        remaining_tail_alignment_scratch_allocation_blocks_bufs
                                            .iter_mut()
                                            .map(Some),
                                    ),
                                );
                            } else if any_allocated_at_tail {
                                fs_sync_state_read_buffer.insert_unauthenticated_buffers(
                                    this.d.request_range.end(),
                                    taken_tail_alignment_scratch_allocation_blocks_bufs
                                        .iter()
                                        .map(|_| None)
                                        .chain(
                                            remaining_tail_alignment_scratch_allocation_blocks_bufs
                                                .iter_mut()
                                                .map(Some),
                                        ),
                                );
                            } else if any_allocated_at_head {
                                fs_sync_state_read_buffer.insert_authenticated_buffers(
                                    this.d.aligned_request_range.begin(),
                                    (unused_head_alignment_scratch_allocation_blocks_bufs
                                        .iter()
                                        .map(|_| None))
                                    .chain(
                                        remaining_head_alignment_scratch_allocation_blocks_bufs
                                            .iter_mut()
                                            .map(Some),
                                    ),
                                );
                            }
                        }
                    }

                    let dst_allocation_blocks_bufs = mem::take(&mut this.d.dst_allocation_blocks_bufs);
                    this.fut_state = BufferedReadAuthenticateDataFutureState::Done;
                    return task::Poll::Ready(Ok(dst_allocation_blocks_bufs));
                }
                BufferedReadAuthenticateDataFutureState::Done => unreachable!(),
            }
        }
    }
}

impl BufferedReadAuthenticatedDataFutureData {
    /// Convenience wrapper to
    /// [`_translate_physical_to_auth_tree_data_allocation_block_index()`](Self::_translate_physical_to_auth_tree_data_allocation_block_index).
    ///
    /// Translate the `request_range_allocation_block_index`
    /// [`PhysicalAllocBlockIndex`](layout::PhysicalAllocBlockIndex)
    /// within the (aligned) request range into the
    /// [`AuthTreeDataAllocBlockIndex`](auth_tree::AuthTreeDataAllocBlockIndex)
    /// domain.
    ///
    /// # Arguments:
    ///
    /// * `request_range_allocation_block_index` - The
    ///   [`PhysicalAllocBlockIndex`](layout::PhysicalAllocBlockIndex) to
    ///   translate. Must be within the [Authentication Tree Data
    ///   Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    ///   aligned request range.
    fn translate_physical_to_auth_tree_data_allocation_block_index(
        &self,
        request_range_allocation_block_index: layout::PhysicalAllocBlockIndex,
    ) -> auth_tree::AuthTreeDataAllocBlockIndex {
        Self::_translate_physical_to_auth_tree_data_allocation_block_index(
            request_range_allocation_block_index,
            self.request_range_auth_tree_data_allocation_blocks_begin,
            &self.auth_tree_data_block_aligned_request_range,
        )
    }

    /// Translate a [`PhysicalAllocBlockIndex`](layout::PhysicalAllocBlockIndex)
    /// within the (aligned) request range into the
    /// [`AuthTreeDataAllocBlockIndex`](auth_tree::AuthTreeDataAllocBlockIndex)
    /// domain.
    ///
    /// # Arguments:
    ///
    /// * `request_range_allocation_block_index` - The
    ///   [`PhysicalAllocBlockIndex`](layout::PhysicalAllocBlockIndex) to
    ///   translate. Must be within the bounds of
    ///   `auth_tree_data_block_aligned_request_range`.
    /// * `request_range_auth_tree_data_allocation_blocks_begin` - The
    ///   [`AuthTreeDataAllocBlockIndex`](auth_tree::AuthTreeDataAllocBlockIndex)
    ///   corresponding to the beginning of the
    ///   `auth_tree_data_block_aligned_request_range`.
    /// * `auth_tree_data_block_aligned_request_range` - The [Authentication
    ///   Tree Data Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    ///   aligned request range.
    fn _translate_physical_to_auth_tree_data_allocation_block_index(
        request_range_allocation_block_index: layout::PhysicalAllocBlockIndex,
        request_range_auth_tree_data_allocation_blocks_begin: auth_tree::AuthTreeDataAllocBlockIndex,
        auth_tree_data_block_aligned_request_range: &layout::PhysicalAllocBlockRange,
    ) -> auth_tree::AuthTreeDataAllocBlockIndex {
        // The request extent is contiguous on physical storage, hence not interspersed
        // with extents from the Authentication Tree and the mapping from
        // physical to the Authentication Tree Data domain is linear.
        debug_assert!(
            request_range_allocation_block_index >= auth_tree_data_block_aligned_request_range.begin()
                && request_range_allocation_block_index <= auth_tree_data_block_aligned_request_range.end()
        );
        request_range_auth_tree_data_allocation_blocks_begin
            + (request_range_allocation_block_index - auth_tree_data_block_aligned_request_range.begin())
    }

    /// Allocate the [`Self::alignment_scratch_allocation_blocks_bufs`].
    fn allocate_alignment_scratch_allocation_blocks_buf(&mut self) -> Result<(), NvFsError> {
        debug_assert!(
            self.aligned_request_range
                .contains(&self.auth_tree_data_block_aligned_request_range)
        );
        // Does not overflow, it's been checked in Self::new() that the whole
        // aligned_request_range's Allocation Block Count fits an usize.
        let head_alignment_scratch_allocation_blocks =
            u64::from(self.request_range.begin() - self.aligned_request_range.begin()) as usize;
        let tail_alignment_scratch_allocation_blocks =
            u64::from(self.aligned_request_range.end() - self.request_range.end()) as usize;
        let alignment_scratch_allocation_blocks =
            head_alignment_scratch_allocation_blocks + tail_alignment_scratch_allocation_blocks;
        self.alignment_scratch_allocation_blocks_bufs =
            FixedVec::new_with_default(alignment_scratch_allocation_blocks)?;
        Ok(())
    }

    /// Get the alignment padding scratch buffers.
    ///
    /// Return the head and tail scratch buffers corresponding to the
    /// head and tail alignment padding from the
    /// [`aligned_request_range`](Self::aligned_request_range).
    ///
    /// # Arguments:
    ///
    /// * `alignment_scratch_allocation_blocks_bufs` - `mut` reference to
    ///   [`Self::alignment_scratch_allocation_blocks_bufs`].
    /// * `request_range` - Reference to [`Self::request_range`].
    /// * `aligned_request_range` - Reference to
    ///   [`Self::aligned_request_range`].
    fn get_alignment_scratch_allocation_blocks_bufs<'a>(
        alignment_scratch_allocation_blocks_bufs: &'a mut [FixedVec<u8, 7>],
        request_range: &layout::PhysicalAllocBlockRange,
        aligned_request_range: &layout::PhysicalAllocBlockRange,
    ) -> (&'a mut [FixedVec<u8, 7>], &'a mut [FixedVec<u8, 7>]) {
        // The aligned_request_range is the request_range aligned to the larger of the
        // Chip IO Block and the Authentication Tree Data Block size. Return the
        // head and tail scratch buffer portions needed for aligning to the
        // larger of the two.
        // Note that the complete aligned_request_range length in units of Allocation
        // Blocks is guaranteed to fit an usize.
        debug_assert!(aligned_request_range.contains(request_range));
        let head_alignment_scratch_allocation_blocks =
            u64::from(request_range.begin() - aligned_request_range.begin()) as usize;
        let tail_alignment_scratch_allocation_blocks =
            u64::from(aligned_request_range.end() - request_range.end()) as usize;
        debug_assert_eq!(
            head_alignment_scratch_allocation_blocks + tail_alignment_scratch_allocation_blocks,
            alignment_scratch_allocation_blocks_bufs.len()
        );
        let (head_alignment_scratch_allocation_blocks_bufs, tail_alignment_scratch_allocation_blocks_bufs) =
            alignment_scratch_allocation_blocks_bufs.split_at_mut(head_alignment_scratch_allocation_blocks);
        (
            head_alignment_scratch_allocation_blocks_bufs,
            tail_alignment_scratch_allocation_blocks_bufs,
        )
    }

    /// Split off the unused parts of the alignment padding scratch buffers.
    ///
    /// In some specific constellations of data obtained from the [`ReadBuffer`]
    /// it is known that certain parts of the alignment padding scratch
    /// buffers wouldn't ever get accessed. Split these parts off.
    /// More specifically, return a quadruplet of buffers,
    /// with the outer entries corresponding to the unused, and the inner two
    /// entries to the used parts of the head and tail padding scratch
    /// buffers respectively.
    ///
    /// # Arguments:
    /// * `head_alignment_scratch_allocation_blocks_bufs` - Head part obtained
    ///   from [`get_alignment_scratch_allocation_blocks_bufs()`](Self::get_alignment_scratch_allocation_blocks_bufs).
    /// * `tail_alignment_scratch_allocation_blocks_bufs` - Tail part obtained
    ///   from [`get_alignment_scratch_allocation_blocks_bufs()`](Self::get_alignment_scratch_allocation_blocks_bufs).
    /// * `request_range` - Reference to [`Self::request_range`].
    /// * `auth_tree_data_block_aligned_request_range` - Reference to
    ///   [`Self::auth_tree_data_block_aligned_request_range`].
    /// * `authenticated_subrange_from_read_buf` - Reference to
    ///   [`Self::authenticated_subrange_from_read_buf`].
    /// * `unauthenticated_subrange_from_read_buf` - Reference to
    ///   [`Self::unauthenticated_subrange_from_read_buf`].
    /// * `min_io_block_allocation_blocks_log2` - Value of
    ///   [`Self::min_io_block_allocation_blocks_log2`].
    #[allow(clippy::type_complexity)]
    fn split_off_unused_alignment_scratch_allocation_blocks_bufs<'a>(
        head_alignment_scratch_allocation_blocks_bufs: &'a mut [FixedVec<u8, 7>],
        tail_alignment_scratch_allocation_blocks_bufs: &'a mut [FixedVec<u8, 7>],
        request_range: &layout::PhysicalAllocBlockRange,
        auth_tree_data_block_aligned_request_range: &layout::PhysicalAllocBlockRange,
        authenticated_subrange_from_read_buf: Option<&layout::PhysicalAllocBlockRange>,
        unauthenticated_subrange_from_read_buf: Option<&layout::PhysicalAllocBlockRange>,
        min_io_block_allocation_blocks_log2: u32,
    ) -> (
        (&'a mut [FixedVec<u8, 7>], &'a mut [FixedVec<u8, 7>]),
        (&'a mut [FixedVec<u8, 7>], &'a mut [FixedVec<u8, 7>]),
    ) {
        debug_assert!(
            authenticated_subrange_from_read_buf
                .map(|authenticated_subrange_from_read_buf| authenticated_subrange_from_read_buf != request_range)
                .unwrap_or(true)
        );

        // If some unauthenticated data had been obtained from the read buffer and that
        // range aligns to the left or right of the
        // auth_tree_data_block_aligned_request_range, then the
        // alignment scratch buffers won't be needed for that end -- note that
        // unauthenticated data is buffered only if the Minimum IO block size is
        // > the Authentication Tree Data Block size, so an unauthenticated
        // region at the head or tail, if any, always extends up to some
        // boundary which is both, Minimum IO Block as well as Authentication
        // Tree Data Block aligned within the original request region.
        let (head_scratch_is_unused, tail_scratch_is_unused) = unauthenticated_subrange_from_read_buf
            .map(|unauthenticated_subrange_from_read_buf| {
                debug_assert!(
                    authenticated_subrange_from_read_buf
                        .as_ref()
                        .map(|authenticated_subrange_from_read_buf| {
                            !authenticated_subrange_from_read_buf.overlaps_with(unauthenticated_subrange_from_read_buf)
                        })
                        .unwrap_or(true)
                );
                (
                    unauthenticated_subrange_from_read_buf.begin()
                        == auth_tree_data_block_aligned_request_range.begin(),
                    unauthenticated_subrange_from_read_buf.end() == auth_tree_data_block_aligned_request_range.end(),
                )
            })
            .unwrap_or((false, false));

        // Likewise, if some authenticated data had been obtained from the read buffer
        // and that authenticated range aligns to either the beginning or the
        // end of the request range, and that range's boundary within the
        // interior of the request range happens to be aligned to the Chip IO
        // Block size, then the alignment scratch buffers for that end will not
        // be neeeded either.
        let (head_scratch_is_unused, tail_scratch_is_unused) = authenticated_subrange_from_read_buf
            .map(|authenticated_subrange_from_read_buf| {
                (
                    head_scratch_is_unused
                        || (authenticated_subrange_from_read_buf.begin() == request_range.begin()
                            && authenticated_subrange_from_read_buf
                                .end()
                                .align_down(min_io_block_allocation_blocks_log2)
                                == authenticated_subrange_from_read_buf.end()),
                    tail_scratch_is_unused
                        || (authenticated_subrange_from_read_buf.end() == request_range.end()
                            && authenticated_subrange_from_read_buf
                                .begin()
                                .align_down(min_io_block_allocation_blocks_log2)
                                == authenticated_subrange_from_read_buf.begin()),
                )
            })
            .unwrap_or((head_scratch_is_unused, tail_scratch_is_unused));

        let head_alignment_scratch_allocation_blocks_bufs_len = head_alignment_scratch_allocation_blocks_bufs.len();
        let tail_alignment_scratch_allocation_blocks_bufs_len = tail_alignment_scratch_allocation_blocks_bufs.len();

        (
            head_alignment_scratch_allocation_blocks_bufs.split_at_mut(if head_scratch_is_unused {
                head_alignment_scratch_allocation_blocks_bufs_len
            } else {
                0
            }),
            tail_alignment_scratch_allocation_blocks_bufs.split_at_mut(if tail_scratch_is_unused {
                0
            } else {
                tail_alignment_scratch_allocation_blocks_bufs_len
            }),
        )
    }

    /// Get the [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// alignment padding scratch buffers.
    ///
    /// Return the head and tail scratch buffers corresponding to the
    /// head and tail alignment padding from the
    /// [`auth_tree_data_block_aligned_request_range`](Self::auth_tree_data_block_aligned_request_range).
    ///
    /// # Arguments:
    ///
    /// * `alignment_scratch_allocation_blocks_bufs` - `mut` reference to
    ///   [`Self::alignment_scratch_allocation_blocks_bufs`].
    /// * `request_range` - Reference to [`Self::request_range`].
    /// * `auth_tree_data_block_aligned_request_range` - Reference to
    ///   [`Self::auth_tree_data_block_aligned_request_range`].
    /// * `aligned_request_range` - Reference to
    ///   [`Self::aligned_request_range`].
    fn get_auth_tree_data_block_alignment_scratch_allocation_blocks_bufs<'a>(
        alignment_scratch_allocation_blocks_bufs: &'a mut [FixedVec<u8, 7>],
        request_range: &layout::PhysicalAllocBlockRange,
        auth_tree_data_block_aligned_request_range: &layout::PhysicalAllocBlockRange,
        aligned_request_range: &layout::PhysicalAllocBlockRange,
    ) -> (&'a mut [FixedVec<u8, 7>], &'a mut [FixedVec<u8, 7>]) {
        // The aligned_request_range is the request_range aligned to the larger of the
        // Chip IO Block and the Authentication Tree Data Block size. Obtain
        // only the head and tail portions needed to align the request_range to
        // the Authentication Tree Data Block size.
        // Note that the complete aligned_request_range length in units of Allocation
        // Blocks is guaranteed to fit an usize.
        debug_assert!(aligned_request_range.contains(auth_tree_data_block_aligned_request_range));
        debug_assert!(auth_tree_data_block_aligned_request_range.contains(request_range));
        let (head_alignment_scratch_allocation_blocks_bufs, tail_alignment_scratch_allocation_blocks_bufs) =
            Self::get_alignment_scratch_allocation_blocks_bufs(
                alignment_scratch_allocation_blocks_bufs,
                request_range,
                aligned_request_range,
            );

        let (_, head_auth_tree_data_block_alignment_scratch_allocation_blocks_bufs) =
            head_alignment_scratch_allocation_blocks_bufs.split_at_mut(u64::from(
                auth_tree_data_block_aligned_request_range.begin() - aligned_request_range.begin(),
            ) as usize);
        let (tail_auth_tree_data_block_alignment_scratch_allocation_blocks_bufs, _) =
            tail_alignment_scratch_allocation_blocks_bufs.split_at_mut(u64::from(
                auth_tree_data_block_aligned_request_range.end() - request_range.end(),
            ) as usize);

        (
            head_auth_tree_data_block_alignment_scratch_allocation_blocks_bufs,
            tail_auth_tree_data_block_alignment_scratch_allocation_blocks_bufs,
        )
    }

    /// Determine the next region to read from physical storage.
    ///
    /// Depending on the current progress, return the next region to read in
    /// from storage. If `None` is returned, the caller is supposed to
    /// authenticate the currently accumulated batch read in so far but not
    /// authenticated yet and invoke `determine_next_read_region()` again
    /// afterwards in case the the request hasn't been completed by then.
    /// Otherwise the caller will proceed to read the returned range from
    /// storage and invoke `determine_next_read_region()` again.
    ///
    /// # Arguments:
    ///
    /// * `cur_request_allocation_block_index` - Current read position in the
    ///   [`Self::aligned_request_range`].
    /// * `auth_tree_config` - The filesystem's
    ///   [`AuthTreeConfig`](auth_tree::AuthTreeConfig).
    fn determine_next_read_region(
        &mut self,
        mut cur_request_allocation_block_index: layout::PhysicalAllocBlockIndex,
        auth_tree_config: &auth_tree::AuthTreeConfig,
    ) -> Result<Option<layout::PhysicalAllocBlockRange>, NvFsError> {
        debug_assert!(cur_request_allocation_block_index >= self.authenticated_allocation_blocks_end);
        debug_assert!(self.authenticated_allocation_blocks_end < self.auth_tree_data_block_aligned_request_range.end());
        if cur_request_allocation_block_index >= self.auth_tree_data_block_aligned_request_range.end() {
            // All data has been read by now. Let the caller proceed with authenticating
            // that and be done.
            return Ok(None);
        }
        debug_assert!(
            cur_request_allocation_block_index >= self.auth_tree_data_block_aligned_request_range.begin()
                && cur_request_allocation_block_index < self.auth_tree_data_block_aligned_request_range.end()
        );

        let min_io_block_allocation_blocks_log2 = self.min_io_block_allocation_blocks_log2 as u32;
        let preferred_chip_io_bulk_allocation_blocks_log2 = self.preferred_chip_io_bulk_allocation_blocks_log2 as u32;
        let auth_tree_data_block_allocation_blocks_log2 = self.auth_tree_data_block_allocation_blocks_log2 as u32;

        let auth_tree_covered_data_blocks_per_leaf_node_log2 =
            auth_tree_config.covered_data_blocks_per_leaf_node_log2() as u32;
        let auth_tree_covered_allocation_blocks_per_leaf_node_log2 =
            auth_tree_covered_data_blocks_per_leaf_node_log2 + self.auth_tree_data_block_allocation_blocks_log2 as u32;

        if (u64::from(
            self.translate_physical_to_auth_tree_data_allocation_block_index(cur_request_allocation_block_index),
        ) ^ u64::from(
            self.translate_physical_to_auth_tree_data_allocation_block_index(self.authenticated_allocation_blocks_end),
        )) >> auth_tree_covered_allocation_blocks_per_leaf_node_log2
            != 0
        {
            // The current read position would advance past the region of what's covered by
            // a single Authentication Tree Leaf node. Return and let the caller
            // authenticate what's there.
            return Ok(None);
        }

        // Start by skipping over regions which
        // - correspond to fully unallocated Chip IO Blocks, possible only if the Chip
        //   IO Block size is less than that of an Authentication Tree Data Block,
        // - over the head alignment scratch if unneeded (because an authenticated area
        //   whose end aligns with Chip IO Block size had been retrieved from the read
        //   buffer),
        // - over any authenticated or unauthenticated regions initially retrieved from
        //   the read buffer.
        let (head_alignment_scratch_allocation_blocks_bufs, tail_alignment_scratch_allocation_blocks_bufs) =
            Self::get_alignment_scratch_allocation_blocks_bufs(
                &mut self.alignment_scratch_allocation_blocks_bufs,
                &self.request_range,
                &self.aligned_request_range,
            );
        let allocation_blocks_bufs = head_alignment_scratch_allocation_blocks_bufs
            .iter()
            .chain(self.dst_allocation_blocks_bufs.iter())
            .chain(tail_alignment_scratch_allocation_blocks_bufs.iter());
        // Advance the allocation_blocks_bufs iterator to the position corresponding to
        // cur_request_allocation_block_index. The usize does not overflow, the whole
        // aligned_request_range's length in units of Allocation Blocks fits an usize,
        // as per the check in Self::new(). Unfortunately,
        // Iterator::advance_by() is unstable.
        let mut allocation_blocks_bufs = allocation_blocks_bufs
            .skip(u64::from(cur_request_allocation_block_index - self.aligned_request_range.begin()) as usize);
        while cur_request_allocation_block_index != self.auth_tree_data_block_aligned_request_range.end() {
            // Clippy does not undestand the allocation_blocks_bufs iterator cannot get
            // cosumed here.
            #[allow(clippy::while_let_on_iterator)]
            while let Some(allocation_block_buf) = allocation_blocks_bufs.next() {
                if !allocation_block_buf.is_empty() {
                    break;
                } else {
                    cur_request_allocation_block_index += layout::AllocBlockCount::from(1);
                    if cur_request_allocation_block_index == self.auth_tree_data_block_aligned_request_range.end() {
                        break;
                    }
                }
            }
            if let Some(authenticated_subrange_from_read_buf) = self.authenticated_subrange_from_read_buf.as_ref() {
                if cur_request_allocation_block_index >= authenticated_subrange_from_read_buf.begin()
                    && cur_request_allocation_block_index < authenticated_subrange_from_read_buf.end()
                {
                    // If at the request end, or at the end of what's covered by a single
                    // Authentication Tree Leaf node, return and let the caller proceed with
                    // authenticating what has been read so far.
                    if authenticated_subrange_from_read_buf.end() == self.request_range.end()
                        || (u64::from(Self::_translate_physical_to_auth_tree_data_allocation_block_index(
                            cur_request_allocation_block_index,
                            self.request_range_auth_tree_data_allocation_blocks_begin,
                            &self.auth_tree_data_block_aligned_request_range,
                        )) ^ u64::from(Self::_translate_physical_to_auth_tree_data_allocation_block_index(
                            authenticated_subrange_from_read_buf.end(),
                            self.request_range_auth_tree_data_allocation_blocks_begin,
                            &self.auth_tree_data_block_aligned_request_range,
                        ))) >> auth_tree_covered_allocation_blocks_per_leaf_node_log2
                            != 0
                    {
                        debug_assert!(
                            authenticated_subrange_from_read_buf.end() == self.request_range.end()
                                || u64::from(cur_request_allocation_block_index)
                                    .is_aligned_pow2(auth_tree_data_block_allocation_blocks_log2)
                        );
                        return Ok(None);
                    }
                    // Otherwise advance the iterator over the found region.
                    // Iterator::advance_by() is unstable.
                    // The allocation_blocks_buf has already been iterated past the element pointed
                    // to by current cur_request_allocation_block_index.
                    cur_request_allocation_block_index += layout::AllocBlockCount::from(1);
                    while cur_request_allocation_block_index != authenticated_subrange_from_read_buf.end() {
                        allocation_blocks_bufs.next().ok_or_else(|| nvfs_err_internal!())?;
                        cur_request_allocation_block_index += layout::AllocBlockCount::from(1);
                    }
                    continue;
                }
            } else if let Some(unauthenticated_subrange_from_read_buf) =
                self.unauthenticated_subrange_from_read_buf.as_ref()
            {
                // The read buffer retains unauthenticated data only if the Chip IO Block size
                // exceeds that of an Authentication Tree Data Block.
                debug_assert!(min_io_block_allocation_blocks_log2 > auth_tree_data_block_allocation_blocks_log2);
                debug_assert!(
                    unauthenticated_subrange_from_read_buf.begin()
                        >= self.auth_tree_data_block_aligned_request_range.begin()
                        && unauthenticated_subrange_from_read_buf.end()
                            <= self.auth_tree_data_block_aligned_request_range.end()
                );
                debug_assert!(
                    unauthenticated_subrange_from_read_buf.begin()
                        == self.auth_tree_data_block_aligned_request_range.begin()
                        || unauthenticated_subrange_from_read_buf
                            .begin()
                            .align_down(min_io_block_allocation_blocks_log2)
                            == unauthenticated_subrange_from_read_buf.begin()
                );
                debug_assert!(
                    unauthenticated_subrange_from_read_buf.end()
                        == self.auth_tree_data_block_aligned_request_range.end()
                        || unauthenticated_subrange_from_read_buf
                            .end()
                            .align_down(min_io_block_allocation_blocks_log2)
                            == unauthenticated_subrange_from_read_buf.end()
                );
                if cur_request_allocation_block_index >= unauthenticated_subrange_from_read_buf.begin()
                    && cur_request_allocation_block_index < unauthenticated_subrange_from_read_buf.end()
                {
                    if (u64::from(Self::_translate_physical_to_auth_tree_data_allocation_block_index(
                        cur_request_allocation_block_index,
                        self.request_range_auth_tree_data_allocation_blocks_begin,
                        &self.auth_tree_data_block_aligned_request_range,
                    )) ^ u64::from(Self::_translate_physical_to_auth_tree_data_allocation_block_index(
                        unauthenticated_subrange_from_read_buf.end(),
                        self.request_range_auth_tree_data_allocation_blocks_begin,
                        &self.auth_tree_data_block_aligned_request_range,
                    ))) >> auth_tree_covered_allocation_blocks_per_leaf_node_log2
                        != 0
                        || unauthenticated_subrange_from_read_buf.end()
                            == self.auth_tree_data_block_aligned_request_range.end()
                    {
                        // Either crossing the boundary of an Authentication Tree Data Block's
                        // covered range or everything needed for authenticating the original
                        // request range is available, return and let the caller proceed with
                        // authenticating what's there.
                        return Ok(None);
                    }
                    // Otherwise advance the iterator over the found region.
                    // Iterator::advance_by() is unstable.
                    // The allocation_blocks_buf has already been iterated past the element pointed
                    // to by current cur_request_allocation_block_index.
                    cur_request_allocation_block_index += layout::AllocBlockCount::from(1);
                    while cur_request_allocation_block_index != unauthenticated_subrange_from_read_buf.end() {
                        allocation_blocks_bufs.next().ok_or_else(|| nvfs_err_internal!())?;
                        cur_request_allocation_block_index += layout::AllocBlockCount::from(1);
                    }
                    debug_assert_eq!(
                        cur_request_allocation_block_index.align_down(min_io_block_allocation_blocks_log2),
                        cur_request_allocation_block_index
                    );
                    continue;
                }
            }
            break;
        }

        debug_assert!(cur_request_allocation_block_index <= self.auth_tree_data_block_aligned_request_range.end());
        if cur_request_allocation_block_index == self.auth_tree_data_block_aligned_request_range.end() {
            debug_assert!(allocation_blocks_bufs.all(|allocation_block_buf| allocation_block_buf.is_empty()));
            return Ok(None);
        }
        debug_assert_eq!(
            (u64::from(Self::_translate_physical_to_auth_tree_data_allocation_block_index(
                cur_request_allocation_block_index,
                self.request_range_auth_tree_data_allocation_blocks_begin,
                &self.auth_tree_data_block_aligned_request_range,
            )) ^ u64::from(Self::_translate_physical_to_auth_tree_data_allocation_block_index(
                self.authenticated_allocation_blocks_end,
                self.request_range_auth_tree_data_allocation_blocks_begin,
                &self.auth_tree_data_block_aligned_request_range,
            ))) >> auth_tree_covered_allocation_blocks_per_leaf_node_log2,
            0
        );

        // It is known that the Chip IO block cur_request_allocation_block_index points
        // into needs a read by now.
        let read_range_allocation_blocks_begin =
            cur_request_allocation_block_index.align_down(min_io_block_allocation_blocks_log2);
        // Be extra cautious to never ever invalidate any authentication status by
        // re-reading from storage.
        if self.authenticated_allocation_blocks_end != self.auth_tree_data_block_aligned_request_range.begin()
            && self.authenticated_allocation_blocks_end > read_range_allocation_blocks_begin
        {
            return Err(nvfs_err_internal!());
        }
        debug_assert!(
            self.unauthenticated_subrange_from_read_buf
                .as_ref()
                .map(
                    |unauthenticated_subrange_from_read_buf| read_range_allocation_blocks_begin
                        < unauthenticated_subrange_from_read_buf.begin()
                        || read_range_allocation_blocks_begin >= unauthenticated_subrange_from_read_buf.end()
                )
                .unwrap_or(true)
        );
        // Search for the read range's end. Advance the current position to past the
        // first Chip IO Block.
        cur_request_allocation_block_index = read_range_allocation_blocks_begin
            + layout::AllocBlockCount::from(1u64 << (min_io_block_allocation_blocks_log2));
        debug_assert!(cur_request_allocation_block_index <= self.aligned_request_range.end());
        debug_assert!(
            self.unauthenticated_subrange_from_read_buf
                .as_ref()
                .map(
                    |unauthenticated_subrange_from_read_buf| cur_request_allocation_block_index
                        <= unauthenticated_subrange_from_read_buf.begin()
                        || cur_request_allocation_block_index > unauthenticated_subrange_from_read_buf.end()
                )
                .unwrap_or(true)
        );
        if cur_request_allocation_block_index == self.aligned_request_range.end() {
            return Ok(Some(layout::PhysicalAllocBlockRange::new(
                read_range_allocation_blocks_begin,
                cur_request_allocation_block_index,
            )));
        }
        let mut read_range_allocation_blocks_end = cur_request_allocation_block_index;
        // Reset the allocation_blocks_bufs iterator to the current position.
        let allocation_blocks_bufs = head_alignment_scratch_allocation_blocks_bufs
            .iter()
            .chain(self.dst_allocation_blocks_bufs.iter())
            .chain(tail_alignment_scratch_allocation_blocks_bufs.iter());
        // Advance the allocation_blocks_bufs iterator to the position corresponding to
        // cur_request_allocation_block_index. The usize does not overflow, the whole
        // aligned_request_range's length in units of Allocation Blocks fits an usize,
        // as per the check in Self::new(). Unfortunately,
        // Iterator::advance_by() is unstable.
        let mut allocation_blocks_bufs = allocation_blocks_bufs
            .skip(u64::from(cur_request_allocation_block_index - self.aligned_request_range.begin()) as usize);

        while cur_request_allocation_block_index != self.aligned_request_range.end() {
            if (u64::from(Self::_translate_physical_to_auth_tree_data_allocation_block_index(
                read_range_allocation_blocks_end,
                self.request_range_auth_tree_data_allocation_blocks_begin,
                &self.auth_tree_data_block_aligned_request_range,
            )) ^ u64::from(Self::_translate_physical_to_auth_tree_data_allocation_block_index(
                self.authenticated_allocation_blocks_end,
                self.request_range_auth_tree_data_allocation_blocks_begin,
                &self.auth_tree_data_block_aligned_request_range,
            ))) >> auth_tree_covered_allocation_blocks_per_leaf_node_log2
                != 0
                || (u64::from(read_range_allocation_blocks_end) ^ u64::from(read_range_allocation_blocks_begin))
                    >> preferred_chip_io_bulk_allocation_blocks_log2
                    != 0
            {
                // Don't cross preferred bulk IO block boundaries or leave a region covered by a
                // single Authentication Tree Leaf Block. Stop and let the caller process what's
                // been found so far.
                break;
            }

            if let Some(unauthenticated_subrange_from_read_buf) = self.unauthenticated_subrange_from_read_buf.as_ref() {
                if cur_request_allocation_block_index == unauthenticated_subrange_from_read_buf.begin() {
                    // Data had been initially retrieved from the read buffer, don't re-read it
                    // then. Let the caller read what's missing up to the current position.
                    debug_assert_eq!(
                        cur_request_allocation_block_index.align_down(min_io_block_allocation_blocks_log2),
                        cur_request_allocation_block_index
                    );
                    return Ok(Some(layout::PhysicalAllocBlockRange::new(
                        read_range_allocation_blocks_begin,
                        read_range_allocation_blocks_end,
                    )));
                }
                debug_assert!(
                    cur_request_allocation_block_index < unauthenticated_subrange_from_read_buf.begin()
                        || cur_request_allocation_block_index >= unauthenticated_subrange_from_read_buf.end()
                )
            }

            let cur_min_io_block_allocation_blocks_end = cur_request_allocation_block_index
                + layout::AllocBlockCount::from(1u64 << min_io_block_allocation_blocks_log2);
            while cur_request_allocation_block_index != cur_min_io_block_allocation_blocks_end {
                if let Some(authenticated_subrange_from_read_buf) = self.authenticated_subrange_from_read_buf.as_ref() {
                    if authenticated_subrange_from_read_buf.begin() == cur_request_allocation_block_index {
                        if authenticated_subrange_from_read_buf.end() >= cur_min_io_block_allocation_blocks_end {
                            break;
                        }
                        while cur_request_allocation_block_index != authenticated_subrange_from_read_buf.end() {
                            // Iterator::advance_by() is unstable.
                            allocation_blocks_bufs.next().ok_or_else(|| nvfs_err_internal!())?;
                            cur_request_allocation_block_index += layout::AllocBlockCount::from(1);
                        }
                        continue;
                    }
                    debug_assert!(
                        cur_request_allocation_block_index < authenticated_subrange_from_read_buf.begin()
                            || cur_request_allocation_block_index >= authenticated_subrange_from_read_buf.end()
                    );
                }
                let allocation_block_buf = allocation_blocks_bufs.next().ok_or_else(|| nvfs_err_internal!())?;
                if !allocation_block_buf.is_empty() {
                    // The Allocation Block destination buffer is not empty, meaning the Allocation
                    // Block is allocated and needs a read.
                    read_range_allocation_blocks_end = cur_min_io_block_allocation_blocks_end;
                    // Advance the allocation_blocks_bufs iterator to past the current Chip IO
                    // block. One entry has already been popped right above.
                    cur_request_allocation_block_index += layout::AllocBlockCount::from(1);
                    // Iterator::advance_by() is unstable.
                    while cur_request_allocation_block_index != cur_min_io_block_allocation_blocks_end {
                        allocation_blocks_bufs.next().ok_or_else(|| nvfs_err_internal!())?;
                        cur_request_allocation_block_index += layout::AllocBlockCount::from(1);
                    }
                    break;
                }
                cur_request_allocation_block_index += layout::AllocBlockCount::from(1);
            }
            if read_range_allocation_blocks_end != cur_min_io_block_allocation_blocks_end {
                // The current Chip IO block doesn't need a read, stop and let the caller read
                // what's missing up the current point.
                break;
            }
        }

        Ok(Some(layout::PhysicalAllocBlockRange::new(
            read_range_allocation_blocks_begin,
            read_range_allocation_blocks_end,
        )))
    }
}

/// [`BufferedReadAuthenticateDataFuture`] state-machine state.
enum BufferedReadAuthenticateDataFutureState<C: chip::NvChip> {
    Init,
    PrepareNextSubrangeDataRead {
        read_subrange_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
    },
    ReadSubrangeData {
        read_range: layout::PhysicalAllocBlockRange,
        read_fut: C::ReadFuture<BufferedReadAuthenticateDataFutureNvChipReadRequest>,
    },
    AuthenticateSubrange {
        auth_subrange_fut_state: BufferedReadAuthenticateDataFutureAuthenticateState<C>,
    },
    Finish,
    Done,
}

/// [`BufferedReadAuthenticateDataFutureState::AuthenticateSubrange`]
/// sub-state-machine state.
enum BufferedReadAuthenticateDataFutureAuthenticateState<C: chip::NvChip> {
    Init,
    LoadAuthTreeLeafNode {
        auth_tree_data_block_index: auth_tree::AuthTreeDataBlockIndex,
        auth_tree_leaf_node_load_fut: auth_tree::AuthTreeNodeLoadFuture<C>,
    },
}

/// [`NvChipReadRequest`](chip::NvChipReadRequest) implementation used
/// internally by [`BufferedReadAuthenticateDataFuture`].
struct BufferedReadAuthenticateDataFutureNvChipReadRequest {
    aligned_request_range_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
    dst_allocation_blocks_bufs: FixedVec<FixedVec<u8, 7>, 0>,
    alignment_scratch_allocation_blocks_bufs: FixedVec<FixedVec<u8, 7>, 0>,
    head_alignment_scratch_allocation_blocks: usize,
    authenticated_subrange_from_read_buf: Option<layout::PhysicalAllocBlockRange>,

    read_request_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
    read_request_io_region: ChunkedIoRegion,
}

impl chip::NvChipReadRequest for BufferedReadAuthenticateDataFutureNvChipReadRequest {
    fn region(&self) -> &ChunkedIoRegion {
        &self.read_request_io_region
    }

    fn get_destination_buffer(
        &mut self,
        range: &ChunkedIoRegionChunkRange,
    ) -> Result<Option<&mut [u8]>, chip::NvChipIoError> {
        let (allocation_block_index, _) = range.chunk().decompose_to_hierarchic_indices([]);
        let allocation_block_index =
            self.read_request_allocation_blocks_begin + layout::AllocBlockCount::from(allocation_block_index as u64);

        // Do not overwrite already authenticated allocation blocks initially obtained
        // from the read buffer.
        if self
            .authenticated_subrange_from_read_buf
            .map(|authenticated_subrange_from_read_buf| {
                allocation_block_index >= authenticated_subrange_from_read_buf.begin()
                    && allocation_block_index < authenticated_subrange_from_read_buf.end()
            })
            .unwrap_or(false)
        {
            return Ok(None);
        }

        // Does not overflow an usize, the full aligned_request_range length in units of
        // Allocation Blocks fits an usize, as per the check in
        // BufferedReadAuthenticateDataFuture::new().
        let allocation_block_index_in_aligned_request_range =
            u64::from(allocation_block_index - self.aligned_request_range_allocation_blocks_begin) as usize;
        let (head_alignment_scratch_allocation_blocks_bufs, tail_alignment_scratch_allocation_blocks_bufs) = self
            .alignment_scratch_allocation_blocks_bufs
            .split_at_mut(self.head_alignment_scratch_allocation_blocks);
        let head_alignment_scratch_allocation_blocks = head_alignment_scratch_allocation_blocks_bufs.len();
        let tail_alignment_scratch_allocation_blocks = tail_alignment_scratch_allocation_blocks_bufs.len();
        let dst_allocation_blocks_bufs = &mut self.dst_allocation_blocks_bufs;
        let dst_allocation_blocks = dst_allocation_blocks_bufs.len();
        let allocation_block_buf =
            if allocation_block_index_in_aligned_request_range < head_alignment_scratch_allocation_blocks {
                head_alignment_scratch_allocation_blocks_bufs[allocation_block_index_in_aligned_request_range]
                    .as_mut_slice()
            } else if allocation_block_index_in_aligned_request_range
                < head_alignment_scratch_allocation_blocks + dst_allocation_blocks
            {
                dst_allocation_blocks_bufs
                    [allocation_block_index_in_aligned_request_range - head_alignment_scratch_allocation_blocks]
                    .as_mut_slice()
            } else if allocation_block_index_in_aligned_request_range
                < head_alignment_scratch_allocation_blocks
                    + dst_allocation_blocks
                    + tail_alignment_scratch_allocation_blocks
            {
                tail_alignment_scratch_allocation_blocks_bufs[allocation_block_index_in_aligned_request_range
                    - dst_allocation_blocks
                    - head_alignment_scratch_allocation_blocks]
                    .as_mut_slice()
            } else {
                return Err(nvchip_err_internal!());
            };

        if allocation_block_buf.is_empty() {
            // The Allocation Block is unallocated and its contents are not needed.
            return Ok(None);
        }

        Ok(Some(&mut allocation_block_buf[range.range_in_chunk().clone()]))
    }
}
