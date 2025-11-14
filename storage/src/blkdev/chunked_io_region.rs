// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`ChunkedIoRegion`].

use crate::utils_common::bitmanip::{BitManip as _, UBitManip as _};
use core::ops;

/// Error type returned by [`ChunkedIoRegion`] and related functionality.
#[derive(Debug)]
pub enum ChunkedIoRegionError {
    /// The chunk size cannot be represented in an `usize`.
    ChunkSizeOverflow,
    /// Invalid region bounds or some chunk index is out of bounds.
    InvalidBounds,
    /// The number of chunks in a physical region cannot be represented in an
    /// `usize`.
    ChunkIndexOverflow,
    /// The physical region's length is not a multiple of the chunk size.
    RegionUnaligned,
}

/// Mapping between IO request buffers and a contiguous range of physical
/// storage.
///
/// In general the size of logical entities to read or write from an IO request
/// doesn't match the physical unit of IO, i.e. a [Device IO
/// Block](super::NvBlkDev::io_block_size_128b_log2) -- the former may be a
/// multiple of the former and vice-versa.
///
/// A [`ChunkedIoRegion`] provides a means to track the association between a
/// set of buffers used to hold the former, so called "chunks", and a contiguous
/// range of physical NV storage, as well as facilities to translate between the
/// two. In this context it is noteworthy that the exact semantics of what a
/// [`ChunkedIoRegion`]'s chunk comprises is completely opaque to the API itself
/// and up to its users to define, but it is expected that they would map to
/// memory buffers or subslices thereof somehow.
///
/// Even though not required by the [`ChunkedIoRegion`] implementation itself,
/// it is assumed that the beginning and extents of the physical region would be
/// commonly [aligned](Self::is_aligned) to the [Device IO
/// Block](super::NvBlkDev::io_block_size_128b_log2) size so that
/// [`super::NvBlkDev`] implementations can
/// [iterate](Self::aligned_blocks_iter) over the region in steps of that unit.
///
/// The "chunks" however must all be of equal size, which is in turn constrained
/// to equal some power of two.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ChunkedIoRegion {
    /// The region's beginning on physical storage, specified in multiples of
    /// 128 Bytes.
    physical_begin_128b: u64,
    /// The region's end on physical storage, specified in multiples of 128
    /// Bytes.
    physical_end_128b: u64,
    /// Base-2 logarithm of the chunk size, as specified in multiples of 128
    /// Bytes.
    chunk_size_128b_log2: u32,
    /// If this instance is a subregion of some larger region, it tracks the
    /// offset within the sequence of all chunks.
    chunk_index_offset: usize,
}

impl ChunkedIoRegion {
    /// Instantiate a new [`ChunkedIoRegion`].
    ///
    /// The region's length must be aligned to a multiple of the chunk size,
    /// as specified through `chunk_size_128b`.
    ///
    /// # Arguments:
    ///
    /// * `physical_begin_128b` - The region's beginning on physical storage,
    ///   specified in multiples of 128 Bytes.
    /// * `physical_end_128b` - The region's end on physical storage, specified
    ///   in multiples of 128 Bytes.
    /// * `chunk_size_128b_log2` - Base-2 logarithm of the chunk size, as
    ///   specified in multiples of 128 Bytes. The resulting chunk size in units
    ///   of Bytes must fit an [`usize`].
    ///
    /// # Errors:
    ///
    /// * [`ChunkSizeOverflow`](ChunkedIoRegionError::ChunkSizeOverflow) - The
    ///   chunk size in units of Bytes doesn't fit an [`usize`].
    /// * [`ChunkIndexOverflow`](ChunkedIoRegionError::ChunkIndexOverflow) - The
    ///   total number of chunks in the region does not fit an [`usize`].
    /// * [`RegionUnaligned`](ChunkedIoRegionError::RegionUnaligned) - The
    ///   physical storage region's length is not aligned to the chunk size.
    /// * [`InvalidBounds`](ChunkedIoRegionError::InvalidBounds) - The end of
    ///   the region on physical storage is located before the beginning.
    pub fn new(
        physical_begin_128b: u64,
        physical_end_128b: u64,
        chunk_size_128b_log2: u32,
    ) -> Result<Self, ChunkedIoRegionError> {
        if chunk_size_128b_log2 >= usize::BITS - 7 || chunk_size_128b_log2 >= u64::BITS {
            Err(ChunkedIoRegionError::ChunkSizeOverflow)
        } else if physical_end_128b < physical_begin_128b {
            Err(ChunkedIoRegionError::InvalidBounds)
        } else if usize::try_from((physical_end_128b - physical_begin_128b) >> chunk_size_128b_log2).is_err() {
            Err(ChunkedIoRegionError::ChunkIndexOverflow)
        } else if !(physical_end_128b - physical_begin_128b).is_aligned_pow2(chunk_size_128b_log2) {
            Err(ChunkedIoRegionError::RegionUnaligned)
        } else {
            Ok(Self {
                physical_begin_128b,
                physical_end_128b,
                chunk_size_128b_log2,
                chunk_index_offset: 0,
            })
        }
    }

    /// Test whether the region on physical storage is aligned to a given
    /// power of two.
    ///
    /// If and only if the region os aligned to the value specified through
    /// `alignment_128b_log2`,
    /// it can be [iterated](Self::aligned_blocks_iter) over in units of that
    /// size.
    ///
    /// # Arguments:
    ///
    /// * `alignment_128b_log2` - Exponent of the power of two value to the the
    ///   region alignment against.
    pub fn is_aligned(&self, alignment_128b_log2: u32) -> bool {
        if alignment_128b_log2 >= u64::BITS {
            false
        } else {
            self.physical_begin_128b.is_aligned_pow2(alignment_128b_log2)
                && self.physical_end_128b.is_aligned_pow2(alignment_128b_log2)
        }
    }

    pub fn max_aligned_128b_log2(&self) -> u32 {
        (self.physical_begin_128b | self.physical_end_128b)
            .trailing_zeros()
            .min(u64::BITS - 1)
    }

    /// Split the region into a body subregion of specified alignment, alongside
    /// unaligned head and tail parts.
    ///
    /// The result is returned as a pair of the (potentially empty) unaligned
    /// head subregion and an optional pair of the aligned body part together
    /// with the unaligned tail. `None` will get returned for that second
    /// entry in case alignment is not possible for the region.
    ///
    /// # Arguments:
    ///
    /// * `alignment_128b_log2` - Base-2 logarithm of the desired alignment as
    ///   specified in multiples of 128 Bytes.
    pub fn align_to(&self, alignment_128b_log2: u32) -> (Self, Option<(Self, Self)>) {
        if alignment_128b_log2 >= u64::BITS {
            return (self.clone(), None);
        }
        // Round physical_end_128b down to a multiple of the desired alignment.
        let aligned_physical_end_128b = self.physical_end_128b.round_down_pow2(alignment_128b_log2);
        // Round physical_begin_128b up to a multiple of the desired alignment.
        let aligned_physical_begin_128b = self
            .physical_begin_128b
            .round_up_pow2(alignment_128b_log2)
            .unwrap_or(aligned_physical_end_128b);
        if aligned_physical_end_128b <= aligned_physical_begin_128b {
            return (self.clone(), None);
        }

        let chunk_index_offset = self.chunk_index_offset;
        let unaligned_head = Self {
            physical_begin_128b: self.physical_begin_128b,
            physical_end_128b: aligned_physical_begin_128b,
            chunk_size_128b_log2: self.chunk_size_128b_log2,
            chunk_index_offset,
        };

        let chunk_index_offset = chunk_index_offset + unaligned_head.chunks_count();
        let aligned = Self {
            physical_begin_128b: aligned_physical_begin_128b,
            physical_end_128b: aligned_physical_end_128b,
            chunk_size_128b_log2: self.chunk_size_128b_log2,
            chunk_index_offset,
        };

        let chunk_index_offset = chunk_index_offset + aligned.chunks_count();
        let unaligned_tail = Self {
            physical_begin_128b: aligned_physical_end_128b,
            physical_end_128b: self.physical_end_128b,
            chunk_size_128b_log2: self.chunk_size_128b_log2,
            chunk_index_offset,
        };

        (unaligned_head, Some((aligned, unaligned_tail)))
    }

    /// Split the region at a specified chunk boundary.
    ///
    /// Split the region at a specified chunk boundary point while
    /// [maintaining](Self::chunks_index_offset) the association to the
    /// original region's chunks.
    ///
    /// # Arguments:
    ///
    /// * `split_pos_chunk_offset` - The split point within the region, relative
    ///   to the initial [`ChunkedIoRegion`]'s chunks.
    ///
    /// # Errors:
    ///
    /// * [`InvalidBounds`](ChunkedIoRegionError::InvalidBounds) -
    ///   `split_pos_chunk_offset` is not within the bounds of the region.
    pub fn split_at(&self, split_pos_chunk_offset: usize) -> Result<(Self, Self), ChunkedIoRegionError> {
        let chunk_index_offset = self.chunk_index_offset;
        if split_pos_chunk_offset < chunk_index_offset
            || split_pos_chunk_offset - chunk_index_offset > self.chunks_count()
        {
            return Err(ChunkedIoRegionError::InvalidBounds);
        }
        let physical_split_pos_128b = self.physical_begin_128b
            + (((split_pos_chunk_offset - chunk_index_offset) as u64) << self.chunk_size_128b_log2);
        let head = Self {
            physical_begin_128b: self.physical_begin_128b,
            physical_end_128b: physical_split_pos_128b,
            chunk_size_128b_log2: self.chunk_size_128b_log2,
            chunk_index_offset,
        };
        debug_assert_eq!(head.chunks_count(), split_pos_chunk_offset - chunk_index_offset);
        let tail = Self {
            physical_begin_128b: physical_split_pos_128b,
            physical_end_128b: self.physical_end_128b,
            chunk_size_128b_log2: self.chunk_size_128b_log2,
            chunk_index_offset: split_pos_chunk_offset,
        };
        Ok((head, tail))
    }

    /// Test whether the [`ChunkedIoRegion`] spans an empty range.
    pub fn is_empty(&self) -> bool {
        self.physical_end_128b == self.physical_begin_128b
    }

    /// Offset of this region's first chunk relative to the initial
    /// [`ChunkedIoRegion`]'s `self` has been derived from, if any, either by
    /// [aligning](Self::align_to) or by [splitting](Self::split_at).
    pub fn chunks_index_offset(&self) -> usize {
        self.chunk_index_offset
    }

    /// Total number of chunks in the region.
    pub fn chunks_count(&self) -> usize {
        let chunks = (self.physical_end_128b - self.physical_begin_128b) >> self.chunk_size_128b_log2;
        // The number of chunks is guaranteed to fit an usize, c.f. Self::new().
        usize::try_from(chunks).unwrap()
    }

    /// Base-2 logarithm of the underlying chunk size, as specified in multiples
    /// of 128 Bytes.
    pub fn chunk_size_128b_log2(&self) -> u32 {
        self.chunk_size_128b_log2
    }

    /// Iterate over the [`ChunkedIoRegion`] in blocks of specified size.
    ///
    /// The region must be [aligned](Self::is_aligned) to the desired iteration
    /// block size or the call will fail.
    ///
    /// In general, it is possible that the region's underlying chunk size is
    /// either not smaller or that it is smaller than the desired iteration
    /// block size. In the former case, a single chunk would fit of one or
    /// more iteration blocks, in the latter case it is the other way
    /// around.
    ///
    /// To support either configuration, the iterator returned is in fact a two
    /// level iterator:
    /// - The [first level iterator](ChunkedIoRegionAlignedBlocksIterator),
    ///   returned from this function here, iterates over logical iteration
    ///   blocks of the size requested.
    /// - The first level iterator would yield [second level
    ///   iterators](ChunkedIoRegionAlignedBlockChunksRangesIterator), which can
    ///   then be used to obtain all the region's chunks (sub)ranges
    ///   intersecting with the current iteration block.
    ///
    ///  For further clarification:
    ///   - In the first case described above, i.e. that the chunk size is
    ///     larger or equal to the iteration block size, those second level
    ///     iterators would only yield a single chunk (sub)range each.
    ///   - In the second case, they would yield ranges covering complete
    ///     chunks, as many as are needed to fill the iteration block size.
    ///
    /// # Arguments:
    ///
    /// * `block_size_128b_log2` - Base-2 logarithm of the desired iteration
    ///   block size, as specified in multiples of 128 Bytes.
    ///
    /// # Errors:
    ///
    /// * [`RegionUnaligned`](ChunkedIoRegionError::RegionUnaligned) - The
    ///   physical storage region is not aligned to the specified iteration
    ///   block size.
    pub fn aligned_blocks_iter(
        &self,
        block_size_128b_log2: u32,
    ) -> Result<ChunkedIoRegionAlignedBlocksIterator<'_>, ChunkedIoRegionError> {
        if !self.is_aligned(block_size_128b_log2) {
            return Err(ChunkedIoRegionError::RegionUnaligned);
        }

        Ok(ChunkedIoRegionAlignedBlocksIterator {
            region: self,
            block_size_128b_log2,
            physical_pos_128b: self.physical_begin_128b,
        })
    }
}

/// Index into a [`ChunkedIoRegion`]'s sequence of chunks.
#[derive(Clone, Copy)]
pub struct ChunkedIoRegionChunkIndex {
    chunk_index: usize,
}

impl ChunkedIoRegionChunkIndex {
    /// Convenience helper to decompose a chunk index into a user-defined
    /// hierarchy of indices.
    ///
    /// For the common case where a fixed number of multiple consecutive chunks
    /// are semantically related by some kind of "group relationship", this
    /// convenience helper provides a means to decompose the
    /// [`ChunkedIoRegionChunkIndex`] into indices to such groups (and into
    /// groups of groups and so on).
    ///
    /// The only limitation is that the the number of members in each group
    /// must be a (fixed) power of two at each level.
    ///
    /// The group hierarchy layout is specified by means of the
    /// `hierarchy_children_log2` array containing the group member
    /// counts at each level, specified as base-2 logarithms, with the
    /// innermost, or "leaf", group entry at its tail end.
    ///
    /// The decomposed index will get returned as array of indices into the
    /// respective groups at each level, in addition to an "outermost" index
    /// in units of top level groups.
    pub fn decompose_to_hierarchic_indices<const N: usize>(
        &self,
        hierarchy_children_log2: [u32; N],
    ) -> (usize, [usize; N]) {
        let mut hierarchic_indices = [0usize; N];
        let mut index = self.chunk_index;
        for i in (0..N).rev() {
            let children_log2 = hierarchy_children_log2[i];
            if children_log2 >= usize::BITS {
                hierarchic_indices[i] = index;
                return (0, hierarchic_indices);
            }
            let mask = usize::trailing_bits_mask(children_log2);
            hierarchic_indices[i] = index & mask;
            index >>= children_log2;
        }

        (index, hierarchic_indices)
    }
}

/// A contiguous range contained in full within a [`ChunkedIoRegion`]'s chunk.
#[derive(Clone)]
pub struct ChunkedIoRegionChunkRange {
    /// Index to the chunk.
    chunk: ChunkedIoRegionChunkIndex,
    /// Range within the chunk.
    range: ops::Range<usize>,
}

impl ChunkedIoRegionChunkRange {
    /// Index to the chunk containing the range.
    pub fn chunk(&self) -> ChunkedIoRegionChunkIndex {
        self.chunk
    }

    /// The range within the chunk.
    pub fn range_in_chunk(&self) -> &ops::Range<usize> {
        &self.range
    }
}

/// First-level iterator returned by [`ChunkedIoRegion::aligned_blocks_iter()`]
/// for iterating the region in blocks of specified size.
pub struct ChunkedIoRegionAlignedBlocksIterator<'a> {
    region: &'a ChunkedIoRegion,
    block_size_128b_log2: u32,
    physical_pos_128b: u64,
}

impl<'a> Iterator for ChunkedIoRegionAlignedBlocksIterator<'a> {
    type Item = (u64, ChunkedIoRegionAlignedBlockChunksRangesIterator<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.physical_pos_128b == self.region.physical_end_128b {
            None
        } else {
            let cur_physical_pos_128b = self.physical_pos_128b;
            // Will not oveflow, both the range's begin and end are guaranteed
            // to be aligned to the block size, c.f. ChunkedIoRegion::aligned_blocks_iter().
            self.physical_pos_128b += u64::exp2(self.block_size_128b_log2);
            let physical_block_index = cur_physical_pos_128b >> self.block_size_128b_log2;
            Some((
                physical_block_index,
                ChunkedIoRegionAlignedBlockChunksRangesIterator {
                    region: self.region,
                    block_size_128b_log2: self.block_size_128b_log2,
                    physical_pos_128b: Some(cur_physical_pos_128b),
                },
            ))
        }
    }
}

/// Second-level iterator yieleded by [`ChunkedIoRegionAlignedBlocksIterator`]
/// for iterating the chunks' (sub)ranges making up the given "iteration
/// block".
pub struct ChunkedIoRegionAlignedBlockChunksRangesIterator<'a> {
    region: &'a ChunkedIoRegion,
    block_size_128b_log2: u32,
    physical_pos_128b: Option<u64>,
}

impl<'a> Iterator for ChunkedIoRegionAlignedBlockChunksRangesIterator<'a> {
    type Item = (u64, ChunkedIoRegionChunkRange);

    fn next(&mut self) -> Option<Self::Item> {
        let cur_physical_pos_128b = self.physical_pos_128b?;

        let block_chunk_range_size_128b_log2 = self.block_size_128b_log2.min(self.region.chunk_size_128b_log2);
        let block_chunk_range_size_128b = u64::exp2(block_chunk_range_size_128b_log2);
        // Will never overflow -- the ChunkedIoRegion's bounds are both guaranteed to be
        // aligned to the iterator's block size, c.f.
        // ChunkedIoRegion::aligned_blocks_iter().
        debug_assert!(self.block_size_128b_log2 < u64::BITS);
        let next_pos_128b = cur_physical_pos_128b + block_chunk_range_size_128b;
        let offset_in_block_mask_128b = u64::trailing_bits_mask(self.block_size_128b_log2);
        self.physical_pos_128b = if next_pos_128b & offset_in_block_mask_128b != 0 {
            Some(next_pos_128b)
        } else {
            None
        };

        let offset_in_block_128b = cur_physical_pos_128b & offset_in_block_mask_128b;
        let chunk_index = (cur_physical_pos_128b - self.region.physical_begin_128b) >> self.region.chunk_size_128b_log2;
        // The region's length in units of chunks is guaranteed to fit an usize, c.f
        // ChunkedIoRegion::new().
        let chunk_index = usize::try_from(chunk_index).unwrap() + self.region.chunk_index_offset;
        let block_chunk_range_begin_128b = (cur_physical_pos_128b - self.region.physical_begin_128b)
            & u64::trailing_bits_mask(self.region.chunk_size_128b_log2);
        let block_chunk_range_end_128b = block_chunk_range_begin_128b + block_chunk_range_size_128b;
        debug_assert!(block_chunk_range_end_128b <= u64::exp2(self.region.chunk_size_128b_log2));
        // The region's underlying chunk size (in units of bytes) is guaranteed to fit
        // an usize, c.f ChunkedIoRegion::new().
        let block_chunk_range_begin_128b = usize::try_from(block_chunk_range_begin_128b).unwrap();
        let block_chunk_range_end_128b = usize::try_from(block_chunk_range_end_128b).unwrap();
        let block_chunk_range_begin = block_chunk_range_begin_128b.checked_shl(7).unwrap();
        let block_chunk_range_end = block_chunk_range_end_128b.checked_shl(7).unwrap();
        let block_chunk_range = block_chunk_range_begin..block_chunk_range_end;

        Some((
            offset_in_block_128b,
            ChunkedIoRegionChunkRange {
                chunk: ChunkedIoRegionChunkIndex { chunk_index },
                range: block_chunk_range,
            },
        ))
    }
}
