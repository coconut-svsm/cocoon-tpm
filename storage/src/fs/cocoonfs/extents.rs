// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`PhysicalExtents`] and [`LogicalExtents`].

extern crate alloc;
use alloc::vec::Vec;

use crate::fs::{
    NvFsError,
    cocoonfs::layout::{self, LogicalAllocBlockRange, PhysicalAllocBlockRange},
};
use core::{cmp, ops, slice};

/// Ordered sequence of [`PhysicalAllocBlockRange`]s.
#[derive(Default)]
pub struct PhysicalExtents {
    /// Extents stored as `(physical_begin, block_count)`, in units of
    /// allocation blocks.
    extents: Vec<(u64, u64)>,
}

impl PhysicalExtents {
    /// Create an empty [`PhysicalExtents`] instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Test if the [`PhysicalExtents`] instance contains any extents.
    pub fn is_empty(&self) -> bool {
        self.extents.is_empty()
    }

    /// Get the number of extents in the [`PhysicalExtents`] instance.
    pub fn len(&self) -> usize {
        self.extents.len()
    }

    /// Try to clone the [`PhysicalExtents`].
    pub fn try_clone(&self) -> Result<Self, NvFsError> {
        let mut extents = Vec::new();
        extents.try_reserve_exact(self.extents.len())?;
        extents.extend_from_slice(&self.extents);
        Ok(Self { extents })
    }

    /// Unpack an entry from [`Self::extents`] into a
    /// [`PhysicalAllocBlockRange`].
    fn unpack_entry(entry: &(u64, u64)) -> layout::PhysicalAllocBlockRange {
        layout::PhysicalAllocBlockRange::from((
            layout::PhysicalAllocBlockIndex::from(entry.0),
            layout::AllocBlockCount::from(entry.1),
        ))
    }

    /// Get the extent at a specified index.
    ///
    /// # Arguments:
    ///
    /// * `i` - index of the extent entry.
    pub fn get_extent_range(&self, i: usize) -> layout::PhysicalAllocBlockRange {
        Self::unpack_entry(&self.extents[i])
    }

    /// Insert an extent at a specified position.
    ///
    /// # Arguments:
    ///
    /// * `pos` - Index position to insert the extent at.
    /// * `range` - The extent to insert.
    /// * `no_merge` - Whether or not to attempt to merge `range` with its
    ///   preexisting neighboring extents.
    pub fn insert_extent(
        &mut self,
        pos: usize,
        range: &layout::PhysicalAllocBlockRange,
        no_merge: bool,
    ) -> Result<(), NvFsError> {
        debug_assert!(pos <= self.len());
        if u64::from(range.block_count()) == 0 {
            return Ok(());
        }
        debug_assert!(!(0..self.len()).any(|i| self.get_extent_range(i).overlaps_with(range)));
        if !no_merge {
            if pos > 0 && self.get_extent_range(pos - 1).end() == range.begin() {
                self.extents[pos - 1].1 += u64::from(range.block_count());
                if pos < self.len() && self.get_extent_range(pos - 1).end() == self.get_extent_range(pos).begin() {
                    self.extents[pos - 1].1 += self.extents[pos].1;
                    self.extents.remove(pos);
                }
                return Ok(());
            } else if pos < self.len() && range.end() == self.get_extent_range(pos).begin() {
                self.extents[pos].0 = u64::from(range.begin());
                self.extents[pos].1 += u64::from(range.block_count());
                return Ok(());
            }
        }

        if self.extents.capacity() == self.extents.len() {
            self.extents
                .try_reserve_exact(1)
                .map_err(|_| NvFsError::MemoryAllocationFailure)?;
        }
        self.extents
            .insert(pos, (u64::from(range.begin()), u64::from(range.block_count())));
        Ok(())
    }

    /// Append an extent to the sequence.
    ///
    /// # Arguments:
    ///
    /// * `pos` - Index position to insert the extent at.
    /// * `range` - The extent to insert.
    /// * `no_merge` - Whether or not to attempt to merge `range` with its
    ///   preexisting predecessor.
    pub fn push_extent(&mut self, range: &layout::PhysicalAllocBlockRange, no_merge: bool) -> Result<(), NvFsError> {
        self.insert_extent(self.len(), range, no_merge)
    }

    /// Remove the extent at the sequence's back.
    ///
    /// # Arguments:
    ///
    /// * `pos` - Index position to insert the extent at.
    /// * `range` - The extent to insert.
    /// * `no_merge` - Whether or not to attempt to merge `range` with its
    ///   preexisting predecessor.
    pub fn pop_extent(&mut self) {
        self.extents.pop();
    }

    /// Remove an extent at a specified index
    ///
    /// # Arguments:
    ///
    /// * `i` - Index of the extent in the sequence to remove.
    pub fn remove_extent(&mut self, i: usize) {
        self.extents.remove(i);
    }

    /// Append all extents from another [`PhysicalExtents`] sequence.
    ///
    /// # Arguments:
    /// * `extents` - The extents to append to `self`.
    /// * `no_merge` - Whether or not to attempt to merge the last extent from
    ///   `self` with the first extent from `extents`.
    pub fn append_extents(&mut self, extents: &Self, no_merge: bool) -> Result<(), NvFsError> {
        if extents.extents.is_empty() {
            return Ok(());
        } else if self.extents.is_empty() {
            *self = extents.try_clone()?;
            return Ok(());
        }

        if no_merge || self.get_extent_range(self.len() - 1).end() != extents.get_extent_range(0).begin() {
            self.extents.try_reserve_exact(extents.extents.len())?;
            self.extents.extend_from_slice(&extents.extents);
        } else {
            self.extents.try_reserve_exact(extents.extents.len() - 1)?;
            let original_extents_len = self.len();
            self.extents[original_extents_len - 1].1 += extents.extents[0].1;
            self.extents.extend_from_slice(&extents.extents[1..]);
        }
        Ok(())
    }

    /// Split the [`PhysicalExtents`] sequence at a specified position.
    ///
    /// # Arguments:
    ///
    /// * `i` - Index of the extent containing the pivot point.
    /// * `offset_in_extent` - Position within the `i`th extent to split at.
    pub fn split(
        mut self,
        mut i: usize,
        mut offset_in_extent: layout::AllocBlockCount,
    ) -> Result<(Self, Self), NvFsError> {
        if i < self.extents.len() && offset_in_extent == self.get_extent_range(i).block_count() {
            i += 1;
            offset_in_extent = layout::AllocBlockCount::from(0);
        }
        if i == self.extents.len() {
            return Ok((self, Self::new()));
        }

        let mut split_off_extents = Vec::<(u64, u64)>::new();
        split_off_extents.try_reserve_exact(self.extents.len() - i)?;
        split_off_extents.extend(&self.extents[i..]);
        split_off_extents[0].0 += u64::from(offset_in_extent);
        split_off_extents[0].1 -= u64::from(offset_in_extent);

        if u64::from(offset_in_extent) != 0 {
            self.extents[i].1 = u64::from(offset_in_extent);
            i += 1;
        }
        self.extents.drain(i..);

        Ok((
            self,
            Self {
                extents: split_off_extents,
            },
        ))
    }

    /// Shrink an extent at a given index by a specified amount.
    ///
    /// # Arguments:
    ///
    /// * `i` - Index of the extent to shrink.
    /// * `allocation_blocks` - Amount to shrink the `i`th extent by.
    pub fn shrink_extent_by(&mut self, i: usize, allocation_blocks: layout::AllocBlockCount) -> bool {
        let allocation_blocks = u64::from(allocation_blocks);
        debug_assert!(allocation_blocks <= self.extents[i].1);
        if allocation_blocks == self.extents[i].1 {
            self.remove_extent(i);
            true
        } else {
            self.extents[i].1 -= allocation_blocks;
            false
        }
    }

    /// Sort the extents by a specified comparison predicate.
    ///
    /// # Arguments:
    ///
    /// * `range` - Index range specifying the extents to sort.
    /// * `compare` - The comparison predicate.
    /// * `no_merge` - Whether or not to attempt to merge neighboring extents
    ///   after the sort.
    pub fn sort_extents_by<F>(&mut self, mut range: ops::Range<usize>, mut compare: F, no_merge: bool)
    where
        F: FnMut(&layout::PhysicalAllocBlockRange, &layout::PhysicalAllocBlockRange) -> cmp::Ordering,
    {
        self.extents[range.clone()].sort_by(|e0, e1| {
            let r0 = Self::unpack_entry(e0);
            let r1 = Self::unpack_entry(e1);
            compare(&r0, &r1)
        });

        if !no_merge {
            if range.start == 0 {
                range.start = 1;
            }
            if range.end < self.extents.len() {
                range.end += 1;
            }
            for pos in range.rev() {
                if self.get_extent_range(pos - 1).end() == self.get_extent_range(pos).begin() {
                    self.extents[pos - 1].1 += self.extents[pos].1;
                    self.extents.remove(pos);
                }
            }
        }
    }

    /// Swap to extents in the [`PhysicalExtents`] sequence.
    ///
    /// # Arguements:
    ///
    /// * `i` - Index of the first extent to swap.
    /// * `j` - Index of the second extent to swap.
    pub fn swap_extents(&mut self, i: usize, j: usize) {
        self.extents.swap(i, j)
    }

    /// Iterate over the extents in the sequence.
    pub fn iter(&self) -> PhysicalExtentsIterator<'_> {
        PhysicalExtentsIterator {
            extents_iter: self.extents.iter(),
        }
    }
}

impl From<LogicalExtents> for PhysicalExtents {
    fn from(value: LogicalExtents) -> Self {
        let mut extents = value.extents;
        let mut last_logical_end = layout::LogicalAllocBlockIndex::from(0);
        for entry in extents.iter_mut() {
            let logical_end = layout::LogicalAllocBlockIndex::from(entry.1);
            entry.1 = (logical_end - last_logical_end).into();
            last_logical_end = logical_end;
        }
        Self { extents }
    }
}

/// [`Iterator`] returned by [`PhysicalExtents::iter()`].
#[derive(Clone)]
pub struct PhysicalExtentsIterator<'a> {
    extents_iter: slice::Iter<'a, (u64, u64)>,
}

impl<'a> Iterator for PhysicalExtentsIterator<'a> {
    type Item = PhysicalAllocBlockRange;

    fn next(&mut self) -> Option<Self::Item> {
        self.extents_iter.next().map(|(physical_begin, block_count)| {
            layout::PhysicalAllocBlockRange::from((
                layout::PhysicalAllocBlockIndex::from(*physical_begin),
                layout::AllocBlockCount::from(*block_count),
            ))
        })
    }
}

/// Unordered set of disjunct [`PhysicalAllocBlockRange`]s.
pub struct PhysicalExtentsSet {
    /// Sorted extents stored as `(physical_begin, physical_end)`, in units of
    /// allocation blocks.
    extents: Vec<(u64, u64)>,
}

impl PhysicalExtentsSet {
    /// Get the extent at a specified index.
    ///
    /// # Arguments:
    ///
    /// * `i` - index of the extent entry.
    fn entry_physical_range(&self, index: usize) -> layout::PhysicalAllocBlockRange {
        let entry = &self.extents[index];
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(entry.0),
            layout::PhysicalAllocBlockIndex::from(entry.1),
        )
    }

    /// Iterate over extents from the [`PhysicalExtentsSet`] overlapping with a
    /// given query extent.
    ///
    /// The returned iterator will yield any extent from the set overlapping
    /// with `query_range`, cropped to that range.
    ///
    /// # Arguments:
    ///
    /// * `query_range` - The query extent whose overlapping extents from the
    ///   set to iterate over.
    #[allow(dead_code)]
    pub fn overlaps(&self, query_range: layout::PhysicalAllocBlockRange) -> PhysicalExtentsSetOverlapsIterator<'_> {
        let (index_begin, index_end) = self._overlaps(&query_range);
        PhysicalExtentsSetOverlapsIterator {
            extents: self,
            query_range,
            index_begin,
            index_end,
        }
    }

    /// Insert a new extent to the set.
    ///
    /// The inserted extent will get merged with any overlapping preexisting
    /// extent in the set.
    ///
    /// # Arguments:
    ///
    /// * `insertion_range` - The extent to add to the set.
    #[allow(dead_code)]
    pub fn insert(&mut self, insertion_range: layout::PhysicalAllocBlockRange) -> Result<(), NvFsError> {
        let (mut overlap_begin, mut overlap_end) = self._overlaps(&insertion_range);
        if overlap_begin != 0 && self.entry_physical_range(overlap_begin - 1).end() == insertion_range.begin() {
            overlap_begin -= 1;
        }
        if overlap_end < self.extents.len() && self.entry_physical_range(overlap_end).begin() == insertion_range.end() {
            overlap_end += 1;
        }

        debug_assert!(
            overlap_begin == 0 || self.entry_physical_range(overlap_begin - 1).end() < insertion_range.begin()
        );
        debug_assert!(
            overlap_end == self.extents.len() || self.entry_physical_range(overlap_end).begin() > insertion_range.end()
        );

        if overlap_begin == overlap_end {
            self.extents
                .try_reserve(1)
                .map_err(|_| NvFsError::MemoryAllocationFailure)?;
            self.extents.insert(
                overlap_begin,
                (insertion_range.begin().into(), insertion_range.end().into()),
            );
        } else {
            self.extents[overlap_begin].0 = self
                .entry_physical_range(overlap_begin)
                .begin()
                .min(insertion_range.begin())
                .into();
            self.extents[overlap_begin].1 = self
                .entry_physical_range(overlap_end - 1)
                .end()
                .max(insertion_range.end())
                .into();
            self.extents.drain(overlap_begin + 1..overlap_end);
        }
        Ok(())
    }

    /// Remove an extent from the set.
    ///
    /// # Arguments:
    ///
    /// * `removal_range` - The extent to remove. Any existing extent
    ///   overlapping with it will get cropped by the overlap.
    #[allow(dead_code)]
    pub fn remove(&mut self, removal_range: &layout::PhysicalAllocBlockRange) -> Result<(), NvFsError> {
        let (mut overlap_begin, mut overlap_end) = self._overlaps(removal_range);

        if overlap_begin == overlap_end {
            return Ok(());
        }

        if overlap_begin + 1 == overlap_end
            && self.entry_physical_range(overlap_begin).begin() < removal_range.begin()
            && self.entry_physical_range(overlap_begin).end() > removal_range.end()
        {
            self.extents
                .try_reserve(1)
                .map_err(|_| NvFsError::MemoryAllocationFailure)?;
            self.extents.insert(
                overlap_begin + 1,
                (
                    removal_range.end().into(),
                    self.entry_physical_range(overlap_begin).end().into(),
                ),
            );
            self.extents[overlap_begin].1 = removal_range.begin().into();
        } else {
            if self.entry_physical_range(overlap_begin).begin() < removal_range.begin() {
                self.extents[overlap_begin].1 = removal_range.begin().into();
                overlap_begin += 1;
            }
            if self.entry_physical_range(overlap_end - 1).end() > removal_range.end() {
                self.extents[overlap_end - 1].0 = removal_range.end().into();
                overlap_end -= 1;
            }
            self.extents.drain(overlap_begin..overlap_end);
        }

        Ok(())
    }

    /// Find the index range within (sorted) [`Self::extents`] of extents
    /// overlapping with a given query extent.
    ///
    ///
    /// Return a pair of indices: the first one points to the first entry with
    /// its end strictly greater than `query_range.begin()`, the second one
    /// points past the last entry with its begin strictly less than
    ///  `query_range.end()`, if any.
    ///
    /// # Arguments:
    ///
    /// * `query_range` - The extents to find overlaps with.
    fn _overlaps(&self, query_range: &layout::PhysicalAllocBlockRange) -> (usize, usize) {
        if self.extents.is_empty() || self.entry_physical_range(0).begin() >= query_range.end() {
            // Return an empty interval located at the beginning.
            return (0, 0);
        } else if self.entry_physical_range(self.extents.len() - 1).end() <= query_range.begin() {
            // Return an empty interval located at the end.
            return (self.extents.len(), self.extents.len());
        }

        let mut l = 0;
        let mut u = self.extents.len() - 1;
        let mut l_index_last = 0;
        let mut u_index_last = self.extents.len() - 1;
        let index_first = loop {
            if l == u {
                debug_assert!(query_range.begin() < self.entry_physical_range(u).end());
                debug_assert!(u == 0 || query_range.begin() >= self.entry_physical_range(u - 1).end());
                break u;
            }

            // Compute m = (l + u) / 2 w/o overflow, c.f. Hacker's Delight, section 2-5.
            let i = (l & u) + ((l ^ u) >> 1);
            debug_assert_ne!(i, u);
            let entry_range = self.entry_physical_range(i);
            if query_range.begin() < entry_range.end() {
                u = i;
                if query_range.end() <= entry_range.begin() {
                    u_index_last = u - 1;
                }
            } else if query_range.begin() >= entry_range.end() {
                l = i + 1;
                l_index_last = i;
            }
        };

        let mut l = l_index_last;
        let mut u = u_index_last;
        let index_last = loop {
            if l == u {
                debug_assert!(query_range.end() > self.entry_physical_range(l).begin());
                debug_assert!(
                    l == self.extents.len() - 1 || query_range.end() <= self.entry_physical_range(l + 1).begin()
                );
                break l;
            }

            // Compute m = (l + u + 1) / 2 w/o overflow, c.f. Hacker's Delight, section 2-5.
            debug_assert!(l < u); // l + 1 won't overflow.
            let i = ((l + 1) & u) + (((l + 1) ^ u) >> 1);
            debug_assert_ne!(i, l);
            let entry_range = self.entry_physical_range(i);
            if query_range.end() <= entry_range.begin() {
                u = i - 1;
            } else if query_range.end() > entry_range.begin() {
                l = i;
            }
        };

        let index_begin = index_first;
        let index_end = index_last + 1;
        debug_assert!(index_begin <= index_end);
        (index_begin, index_end)
    }
}

impl From<PhysicalExtents> for PhysicalExtentsSet {
    fn from(value: PhysicalExtents) -> Self {
        let mut extents = value.extents;
        extents.sort_by_key(|entry| layout::PhysicalAllocBlockIndex::from(entry.0));
        for entry in extents.iter_mut() {
            entry.1 = (layout::PhysicalAllocBlockIndex::from(entry.0) + layout::AllocBlockCount::from(entry.1)).into();
        }
        Self { extents }
    }
}

/// Iterator returned by [`PhysicalExtentsSet::overlaps()`].
pub struct PhysicalExtentsSetOverlapsIterator<'a> {
    extents: &'a PhysicalExtentsSet,
    query_range: layout::PhysicalAllocBlockRange,
    index_begin: usize,
    index_end: usize,
}

impl<'a> Iterator for PhysicalExtentsSetOverlapsIterator<'a> {
    type Item = layout::PhysicalAllocBlockRange;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index_begin < self.index_end {
            let index = self.index_begin;
            self.index_begin += 1;

            let entry_range = self.extents.entry_physical_range(index);

            Some(layout::PhysicalAllocBlockRange::new(
                entry_range.begin().max(self.query_range.begin()),
                entry_range.end().min(self.query_range.end()),
            ))
        } else {
            None
        }
    }
}

#[test]
fn test_physical_extents_set_overlaps() {
    let extents_set = PhysicalExtentsSet::from(PhysicalExtents {
        extents: Vec::from([(6, 2), (4, 1), (1, 2)]),
    });

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(0),
        layout::PhysicalAllocBlockIndex::from(1),
    ));
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(0),
        layout::PhysicalAllocBlockIndex::from(2),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(2),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(1),
        layout::PhysicalAllocBlockIndex::from(2),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(2),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(0),
        layout::PhysicalAllocBlockIndex::from(3),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(1),
        layout::PhysicalAllocBlockIndex::from(3),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(2),
        layout::PhysicalAllocBlockIndex::from(3),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(2),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(0),
        layout::PhysicalAllocBlockIndex::from(4),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(1),
        layout::PhysicalAllocBlockIndex::from(4),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(2),
        layout::PhysicalAllocBlockIndex::from(4),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(2),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(3),
        layout::PhysicalAllocBlockIndex::from(4),
    ));
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(0),
        layout::PhysicalAllocBlockIndex::from(5),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(1),
        layout::PhysicalAllocBlockIndex::from(5),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(2),
        layout::PhysicalAllocBlockIndex::from(5),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(2),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(3),
        layout::PhysicalAllocBlockIndex::from(5),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(4),
        layout::PhysicalAllocBlockIndex::from(5),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(0),
        layout::PhysicalAllocBlockIndex::from(6),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(1),
        layout::PhysicalAllocBlockIndex::from(6),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(2),
        layout::PhysicalAllocBlockIndex::from(6),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(2),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(3),
        layout::PhysicalAllocBlockIndex::from(6),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(4),
        layout::PhysicalAllocBlockIndex::from(6),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(5),
        layout::PhysicalAllocBlockIndex::from(6),
    ));
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(0),
        layout::PhysicalAllocBlockIndex::from(7),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(7),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(1),
        layout::PhysicalAllocBlockIndex::from(7),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(7),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(2),
        layout::PhysicalAllocBlockIndex::from(7),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(2),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(7),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(3),
        layout::PhysicalAllocBlockIndex::from(7),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(7),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(4),
        layout::PhysicalAllocBlockIndex::from(7),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(7),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(5),
        layout::PhysicalAllocBlockIndex::from(7),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(7),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(6),
        layout::PhysicalAllocBlockIndex::from(7),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(7),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(0),
        layout::PhysicalAllocBlockIndex::from(8),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(1),
        layout::PhysicalAllocBlockIndex::from(8),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(2),
        layout::PhysicalAllocBlockIndex::from(8),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(2),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(3),
        layout::PhysicalAllocBlockIndex::from(8),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(4),
        layout::PhysicalAllocBlockIndex::from(8),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(5),
        layout::PhysicalAllocBlockIndex::from(8),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(6),
        layout::PhysicalAllocBlockIndex::from(8),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(7),
        layout::PhysicalAllocBlockIndex::from(8),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(7),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(0),
        layout::PhysicalAllocBlockIndex::from(9),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(1),
        layout::PhysicalAllocBlockIndex::from(9),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(1),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(2),
        layout::PhysicalAllocBlockIndex::from(9),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(2),
            layout::PhysicalAllocBlockIndex::from(3),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(3),
        layout::PhysicalAllocBlockIndex::from(9),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(4),
        layout::PhysicalAllocBlockIndex::from(9),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(4),
            layout::PhysicalAllocBlockIndex::from(5),
        )
    );
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(5),
        layout::PhysicalAllocBlockIndex::from(9),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(6),
        layout::PhysicalAllocBlockIndex::from(9),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(6),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(7),
        layout::PhysicalAllocBlockIndex::from(9),
    ));
    assert_eq!(
        overlaps.next().unwrap(),
        layout::PhysicalAllocBlockRange::new(
            layout::PhysicalAllocBlockIndex::from(7),
            layout::PhysicalAllocBlockIndex::from(8),
        )
    );
    assert!(overlaps.next().is_none());

    let mut overlaps = extents_set.overlaps(layout::PhysicalAllocBlockRange::new(
        layout::PhysicalAllocBlockIndex::from(8),
        layout::PhysicalAllocBlockIndex::from(9),
    ));
    assert!(overlaps.next().is_none());
}

/// Mapping of a filesystem entity's contiguously stored logical extents to
/// physical backing storage.
///
/// In general, a filesystem entity such as the authentication tree or the
/// allocation bitmap file is stored across multiple [physical
/// extents](layout::PhysicalAllocBlockRange), in arbitrary order.
///
/// `LogicalExtents` provides a means to map from [logial
/// positions](layout::LogicalAllocBlockIndex) relative to the entity's data to
/// the associated physical storage locations.
#[derive(Default)]
pub struct LogicalExtents {
    /// Extents stored as `(physical_begin, logical_end)`, in units of
    /// allocation blocks. The virtual `logical_begin` is implicitly equal
    /// to the previous entry's `logical_end`, if any, zero otherwise.
    extents: Vec<(u64, u64)>,
}

impl LogicalExtents {
    /// Create an empty [`LogicalExtents`] instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Test if the [`LogicalExtents`] instance contains any extents.
    pub fn is_empty(&self) -> bool {
        self.extents.is_empty()
    }

    /// Number of [physical extents](layout::PhysicalAllocBlockRange) in the
    /// [`LogicalExtents`] instance.
    pub fn len(&self) -> usize {
        self.extents.len()
    }

    /// Collective size of the [`LogicalExtents`] in units of [Allocation
    /// Blocks](layout::ImageLayout::allocation_block_size_128b_log2).
    pub fn allocation_block_count(&self) -> layout::AllocBlockCount {
        layout::AllocBlockCount::from(self.extents.last().map(|e| e.1).unwrap_or(0))
    }

    /// Append a [physical extent](layout::PhysicalAllocBlockRange) to the back.
    ///
    /// # Arguments:
    ///
    /// * `physical_extent` - The extent to append.
    pub fn extend_by_physical(&mut self, physical_extent: layout::PhysicalAllocBlockRange) -> Result<(), NvFsError> {
        if self.extents.capacity() == self.extents.len() {
            self.extents
                .try_reserve_exact(1)
                .map_err(|_| NvFsError::MemoryAllocationFailure)?;
        }
        let logical_end = self.allocation_block_count() + physical_extent.block_count();
        self.extents
            .push((u64::from(physical_extent.begin()), u64::from(logical_end)));
        Ok(())
    }

    /// Get the extent at a specified index.
    ///
    /// # Arguments:
    ///
    /// * `i` - index of the extent entry.
    pub fn get_extent(&self, i: usize) -> LogicalExtent {
        let logical_range = self.entry_logical_range(i);
        let physical_begin = layout::PhysicalAllocBlockIndex::from(self.extents[i].0);

        LogicalExtent {
            logical_begin: logical_range.begin(),
            physical_begin,
            allocation_block_count: logical_range.block_count(),
        }
    }

    /// Iterate over the [`LogicalExtents`]s' contiguously stored extents.
    pub fn iter(&self) -> LogicalExtentsRangeIterator<'_> {
        if !self.extents.is_empty() {
            let index_last = self.extents.len() - 1;
            let end_in_last = self.entry_logical_range(index_last).block_count();
            let range = LogicalExtentsRange {
                index_first: 0,
                index_last,
                offset_in_first: layout::AllocBlockCount::from(0),
                end_in_last,
            };
            LogicalExtentsRangeIterator {
                extents: self,
                range: Some(range),
                index: 0,
            }
        } else {
            LogicalExtentsRangeIterator {
                extents: self,
                range: None,
                index: 0,
            }
        }
    }

    /// Iterate over the [`LogicalExtents`]s' contiguously stored extents
    /// overlapping with a given query [`LogicalAllocBlockRange`].
    ///
    /// If `query_range` is out of the range covered by the [`LogicalExtents`],
    /// even only partially, then `None` is returned. Otherwise an [iterator
    /// over its comprising contiguous extents](LogicalExtentsRangeIterator)
    /// wrapped in a `Some` is returned. The iterator will yield
    /// [`LogicalExtent`] entries cropped to the `query_range`.
    ///
    /// # Arguments:
    ///
    /// * `query_range` - The query extent whose overlapping extents from the
    ///   [`LogicalExtents`] to iterate over.
    pub fn iter_range(&self, query_range: &LogicalAllocBlockRange) -> Option<LogicalExtentsRangeIterator<'_>> {
        self.lookup_range(query_range)
            .map(|range| LogicalExtentsRangeIterator::new(self, &range))
    }

    /// Get an entry's associated [`LogicalAllocBlockRange`].
    ///
    /// # Arguments:
    ///
    /// * `index` - Index of the entry.
    fn entry_logical_range(&self, index: usize) -> layout::LogicalAllocBlockRange {
        layout::LogicalAllocBlockRange::new(
            if index != 0 {
                layout::LogicalAllocBlockIndex::from(self.extents[index - 1].1)
            } else {
                layout::LogicalAllocBlockIndex::from(0)
            },
            layout::LogicalAllocBlockIndex::from(self.extents[index].1),
        )
    }

    /// Map a [`LogicalAllocBlockIndex`](layout::LogicalAllocBlockIndex) to its
    /// physical storage location.
    ///
    /// If not in range, `None` will get returned. Otherwise a
    /// [`LogicalExtent`] starting at the position specified by
    /// `query_logical_allocation_block_index` and extending up to the end
    /// of the contiguously stored extent will get returned wrapped in a `Some`.
    ///
    /// # Arguments:
    ///
    /// * `query_logical_allocation_block_index` - The logical position to map.
    pub fn lookup(
        &self,
        query_logical_allocation_block_index: layout::LogicalAllocBlockIndex,
    ) -> Option<LogicalExtent> {
        let index = self
            .extents
            .partition_point(|extent| extent.1 <= u64::from(query_logical_allocation_block_index));
        if index == self.extents.len() {
            return None;
        }

        let logical_range = self.entry_logical_range(index);
        let mut logical_begin = logical_range.begin();
        let logical_end = logical_range.end();
        let mut physical_begin = layout::PhysicalAllocBlockIndex::from(self.extents[index].0);
        let offset_in_extent = query_logical_allocation_block_index - logical_begin;
        logical_begin += offset_in_extent;
        physical_begin += offset_in_extent;

        Some(LogicalExtent {
            logical_begin,
            physical_begin,
            allocation_block_count: logical_end - logical_begin,
        })
    }

    /// Map a [`LogicalAllocBlockRange`] to a [range](`LogicalExtentsRange`) in
    /// the [`LogicalExtents`].
    ///
    /// If `query_range` is out of the range covered by the [`LogicalExtents`],
    /// even only partially, then `None` is returned. Otherwise an
    /// [`LogicalExtentsRange`] spanning its comprising extents wrapped in a
    /// `Some` is returned.
    ///
    /// # Arguments:
    ///
    /// * `query_range` - The logical query range to map.
    fn lookup_range(&self, query_range: &LogicalAllocBlockRange) -> Option<LogicalExtentsRange> {
        debug_assert!(query_range.begin() < query_range.end());
        debug_assert!(!self.extents.is_empty());
        debug_assert!(query_range.end() <= self.entry_logical_range(self.extents.len() - 1).end());

        let mut l = 0;
        let mut u = self.extents.len() - 1;
        let mut u_index_last = self.extents.len() - 1;
        let index_first = loop {
            // Compute m = (l + u) / 2 w/o overflow, c.f. Hacker's Delight, section 2-5.
            let i = (l & u) + ((l ^ u) >> 1);
            let entry_range = self.entry_logical_range(i);
            if query_range.begin() < entry_range.begin() {
                u = i - 1;
                if query_range.end() <= entry_range.begin() {
                    u_index_last = u;
                }
            } else if query_range.begin() >= entry_range.end() {
                l = i + 1;
            } else {
                break i;
            }
            if u < l {
                return None;
            }
        };

        let mut l = index_first;
        let mut u = u_index_last;
        let index_last = loop {
            // Compute m = (l + u) / 2 w/o overflow, c.f. Hacker's Delight, section 2-5.
            let i = (l & u) + ((l ^ u) >> 1);
            let entry_range = self.entry_logical_range(i);
            if query_range.end() <= entry_range.begin() {
                u = i - 1;
            } else if query_range.end() > entry_range.end() {
                l = i + 1;
            } else {
                break i;
            }
            if u < l {
                return None;
            }
        };

        let offset_in_first = query_range.begin() - self.entry_logical_range(index_first).begin();
        let end_in_last = query_range.end() - self.entry_logical_range(index_last).begin();

        Some(LogicalExtentsRange {
            index_first,
            index_last,
            offset_in_first,
            end_in_last,
        })
    }
}

#[test]
fn test_logical_extents_lookup_range() {
    let extents = LogicalExtents::from(PhysicalExtents {
        extents: Vec::from([(6, 2), (4, 1), (0, 2)]),
    });

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(0),
                layout::LogicalAllocBlockIndex::from(1)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 0,
            index_last: 0,
            offset_in_first: layout::AllocBlockCount::from(0),
            end_in_last: layout::AllocBlockCount::from(1),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(0),
                layout::LogicalAllocBlockIndex::from(2)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 0,
            index_last: 0,
            offset_in_first: layout::AllocBlockCount::from(0),
            end_in_last: layout::AllocBlockCount::from(2),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(1),
                layout::LogicalAllocBlockIndex::from(2)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 0,
            index_last: 0,
            offset_in_first: layout::AllocBlockCount::from(1),
            end_in_last: layout::AllocBlockCount::from(2),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(0),
                layout::LogicalAllocBlockIndex::from(3)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 0,
            index_last: 1,
            offset_in_first: layout::AllocBlockCount::from(0),
            end_in_last: layout::AllocBlockCount::from(1),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(1),
                layout::LogicalAllocBlockIndex::from(3)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 0,
            index_last: 1,
            offset_in_first: layout::AllocBlockCount::from(1),
            end_in_last: layout::AllocBlockCount::from(1),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(2),
                layout::LogicalAllocBlockIndex::from(3)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 1,
            index_last: 1,
            offset_in_first: layout::AllocBlockCount::from(0),
            end_in_last: layout::AllocBlockCount::from(1),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(0),
                layout::LogicalAllocBlockIndex::from(4)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 0,
            index_last: 2,
            offset_in_first: layout::AllocBlockCount::from(0),
            end_in_last: layout::AllocBlockCount::from(1),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(1),
                layout::LogicalAllocBlockIndex::from(4)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 0,
            index_last: 2,
            offset_in_first: layout::AllocBlockCount::from(1),
            end_in_last: layout::AllocBlockCount::from(1),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(2),
                layout::LogicalAllocBlockIndex::from(4)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 1,
            index_last: 2,
            offset_in_first: layout::AllocBlockCount::from(0),
            end_in_last: layout::AllocBlockCount::from(1),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(3),
                layout::LogicalAllocBlockIndex::from(4)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 2,
            index_last: 2,
            offset_in_first: layout::AllocBlockCount::from(0),
            end_in_last: layout::AllocBlockCount::from(1),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(0),
                layout::LogicalAllocBlockIndex::from(5)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 0,
            index_last: 2,
            offset_in_first: layout::AllocBlockCount::from(0),
            end_in_last: layout::AllocBlockCount::from(2),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(1),
                layout::LogicalAllocBlockIndex::from(5)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 0,
            index_last: 2,
            offset_in_first: layout::AllocBlockCount::from(1),
            end_in_last: layout::AllocBlockCount::from(2),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(2),
                layout::LogicalAllocBlockIndex::from(5)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 1,
            index_last: 2,
            offset_in_first: layout::AllocBlockCount::from(0),
            end_in_last: layout::AllocBlockCount::from(2),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(3),
                layout::LogicalAllocBlockIndex::from(5)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 2,
            index_last: 2,
            offset_in_first: layout::AllocBlockCount::from(0),
            end_in_last: layout::AllocBlockCount::from(2),
        }
    );

    assert_eq!(
        extents
            .lookup_range(&layout::LogicalAllocBlockRange::new(
                layout::LogicalAllocBlockIndex::from(4),
                layout::LogicalAllocBlockIndex::from(5)
            ))
            .unwrap(),
        LogicalExtentsRange {
            index_first: 2,
            index_last: 2,
            offset_in_first: layout::AllocBlockCount::from(1),
            end_in_last: layout::AllocBlockCount::from(2),
        }
    );
}

impl From<PhysicalExtents> for LogicalExtents {
    fn from(value: PhysicalExtents) -> Self {
        let mut extents = value.extents;
        let mut logical_end = 0;
        for entry in extents.iter_mut() {
            logical_end += entry.1;
            entry.1 = logical_end;
        }
        Self { extents }
    }
}

/// Range in [`LogicalExtents`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalExtentsRange {
    index_first: usize,
    index_last: usize,
    offset_in_first: layout::AllocBlockCount,
    end_in_last: layout::AllocBlockCount,
}

/// Entry in [`LogicalExtents`].
pub struct LogicalExtent {
    logical_begin: layout::LogicalAllocBlockIndex,
    physical_begin: layout::PhysicalAllocBlockIndex,
    allocation_block_count: layout::AllocBlockCount,
}

impl LogicalExtent {
    /// Get the associated range in the filesystem entity's data domain.
    pub fn logical_range(&self) -> layout::LogicalAllocBlockRange {
        let logical_end = self.logical_begin + self.allocation_block_count;
        layout::LogicalAllocBlockRange::new(self.logical_begin, logical_end)
    }

    /// Get the associated range on physical storage.
    pub fn physical_range(&self) -> layout::PhysicalAllocBlockRange {
        let physical_end = self.physical_begin + self.allocation_block_count;
        layout::PhysicalAllocBlockRange::new(self.physical_begin, physical_end)
    }
}

/// [`Iterator`] returned by [`LogicalExtents::iter()`] and
/// [`LogicalExtents::iter_range()`].
#[derive(Clone)]
pub struct LogicalExtentsRangeIterator<'a> {
    extents: &'a LogicalExtents,
    range: Option<LogicalExtentsRange>,
    index: usize,
}

impl<'a> LogicalExtentsRangeIterator<'a> {
    pub fn new(extents: &'a LogicalExtents, range: &LogicalExtentsRange) -> Self {
        Self {
            extents,
            range: Some(range.clone()),
            index: 0,
        }
    }
}

impl<'a> Iterator for LogicalExtentsRangeIterator<'a> {
    type Item = LogicalExtent;

    fn next(&mut self) -> Option<Self::Item> {
        let range = self.range.as_ref()?;
        let index = self.index;
        if index == range.index_last + 1 {
            return None;
        }
        self.index += 1;

        let logical_range = self.extents.entry_logical_range(index);
        let mut logical_begin = logical_range.begin();
        let mut physical_begin = layout::PhysicalAllocBlockIndex::from(self.extents.extents[index].0);
        if index == range.index_first {
            logical_begin += range.offset_in_first;
            physical_begin += range.offset_in_first;
        }

        let logical_end = if index != range.index_last {
            logical_range.end()
        } else {
            logical_range.begin() + range.end_in_last
        };

        Some(LogicalExtent {
            logical_begin,
            physical_begin,
            allocation_block_count: logical_end - logical_begin,
        })
    }
}
