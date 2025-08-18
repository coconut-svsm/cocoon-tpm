// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Functionality related to the authentication tree.

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

use crate::{
    chip,
    crypto::hash,
    fs::{
        NvFsError, NvFsIoError,
        cocoonfs::{
            CocoonFsFormatError,
            alloc_bitmap::{AllocBitmap, SparseAllocBitmapUnion},
            auth_subject_ids::AuthSubjectDataSuffix,
            extent_ptr, extents,
            fs::{CocoonFsConfig, CocoonFsSyncStateMemberRef, CocoonFsSyncStateReadFuture},
            inode_extents_list, inode_index,
            journal::apply_script::JournalUpdateAuthDigestsScript,
            keys,
            layout::{self, BlockIndex},
            set_assoc_cache,
        },
    },
    nvfs_err_internal, tpm2_interface,
    utils_async::sync_types::{self, RwLock as _},
    utils_common::{
        alloc::box_try_new,
        bitmanip::{BitManip as _, UBitManip as _},
        ct_cmp,
        fixed_vec::FixedVec,
        io_slices::{self, IoSlicesIterCommon as _},
        zeroize,
    },
};
use core::{cmp, convert, iter, marker, mem, ops, pin, task};
use ops::{Deref as _, DerefMut as _};

#[cfg(doc)]
use crate::chip::NvChipFuture as _;
#[cfg(doc)]
use crate::fs::cocoonfs::image_header::MutableImageHeader;
#[cfg(doc)]
use layout::ImageLayout;

/// [Allocation Block](ImageLayout::allocation_block_size_128b_log2)
/// index in the authentication tree's authenticated data domain.
///
/// The data authenticated by an authentication tree comprises all of the
/// filesystem's image without the extents storing the tree itself. An
/// `AuthTreeDataAllocBlockIndex` refers to an [Allocation
/// Block](ImageLayout::allocation_block_size_128b_log2) in that domain.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct AuthTreeDataAllocBlockIndex {
    index: u64,
}

impl AuthTreeDataAllocBlockIndex {
    /// Convert from a [`AuthTreeDataBlockIndex`].
    ///
    /// The returned [`AuthTreeDataAllocBlockIndex`] will refer to the first
    /// [Allocation Block](ImageLayout::allocation_block_size_128b_log2)
    /// in the [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// identified by `data_block_index`.
    ///
    /// # Arguments:
    ///
    /// * `data_block_index` - The [`AuthTreeDataBlockIndex`] to convert from.
    /// * `data_block_allocation_blocks_log2` - Base-2 logarithm of the
    ///   [Authentication Tree Data
    ///   Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) in
    ///   units of [Allocation
    ///   Blocks](ImageLayout::allocation_block_size_128b_log2).
    pub fn new_from_data_block_index(
        data_block_index: AuthTreeDataBlockIndex,
        data_block_allocation_blocks_log2: u32,
    ) -> Self {
        Self {
            index: u64::from(data_block_index) << data_block_allocation_blocks_log2,
        }
    }
}

impl convert::From<u64> for AuthTreeDataAllocBlockIndex {
    fn from(value: u64) -> Self {
        Self { index: value }
    }
}

impl convert::From<AuthTreeDataAllocBlockIndex> for u64 {
    fn from(value: AuthTreeDataAllocBlockIndex) -> Self {
        value.index
    }
}

impl ops::Add<layout::AllocBlockCount> for AuthTreeDataAllocBlockIndex {
    type Output = Self;

    fn add(self, rhs: layout::AllocBlockCount) -> Self::Output {
        Self {
            index: self.index.checked_add(u64::from(rhs)).unwrap(),
        }
    }
}

impl ops::AddAssign<layout::AllocBlockCount> for AuthTreeDataAllocBlockIndex {
    fn add_assign(&mut self, rhs: layout::AllocBlockCount) {
        self.index = self.index.checked_add(u64::from(rhs)).unwrap();
    }
}

impl ops::Sub<Self> for AuthTreeDataAllocBlockIndex {
    type Output = layout::AllocBlockCount;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::Output::from(self.index.checked_sub(rhs.index).unwrap())
    }
}

impl layout::BlockIndex<layout::AllocBlockCount> for AuthTreeDataAllocBlockIndex {
    fn align_down(&self, align_log2: u32) -> Self {
        Self::from(self.index.round_down_pow2(align_log2))
    }

    fn align_up(&self, align_log2: u32) -> Option<Self> {
        Some(Self::from(self.index.round_up_pow2(align_log2)?))
    }
}

/// [`AuthTreeDataAllocBlockIndex`] range.
type AuthTreeDataAllocBlockRange = layout::BlockRange<AuthTreeDataAllocBlockIndex, layout::AllocBlockCount>;

/// [Authentication Tree Data
/// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
/// count.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AuthTreeDataBlockCount {
    count: u64,
}

impl convert::From<u64> for AuthTreeDataBlockCount {
    fn from(value: u64) -> Self {
        Self { count: value }
    }
}

impl convert::From<AuthTreeDataBlockCount> for u64 {
    fn from(value: AuthTreeDataBlockCount) -> Self {
        value.count
    }
}

impl ops::Add<AuthTreeDataBlockCount> for AuthTreeDataBlockCount {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            count: self.count.checked_add(rhs.count).unwrap(),
        }
    }
}

impl ops::Sub<Self> for AuthTreeDataBlockCount {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::Output::from(self.count.checked_sub(rhs.count).unwrap())
    }
}

impl layout::BlockCount for AuthTreeDataBlockCount {
    fn align_down(&self, align_log2: u32) -> Self {
        Self::from(self.count.round_down_pow2(align_log2))
    }

    fn align_up(&self, align_log2: u32) -> Option<Self> {
        self.count.round_up_pow2(align_log2).map(Self::from)
    }
}

/// [Authentication Tree Data
/// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
/// index in the authentication tree's authenticated data domain.
///
/// The data authenticated by an authentication tree comprises all of the
/// filesystem's image without the extents storing the tree itself. An
/// `AuthTreeDataBlockIndex` refers to an [Authentication Tree Data
/// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) in
/// that domain.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct AuthTreeDataBlockIndex {
    index: u64,
}

impl AuthTreeDataBlockIndex {
    /// Convert from a [`AuthTreeDataAllocBlockIndex`].
    ///
    /// The returned [`AuthTreeDataBlockIndex`] will refer to the
    /// [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// containing the [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) identified
    /// by `data_allocation_block_index`.
    ///
    /// # Arguments:
    ///
    /// * `data_allocation_block_index` - The [`AuthTreeDataAllocBlockIndex`] to
    ///   convert from.
    /// * `data_block_allocation_blocks_log2` - Base-2 logarithm of the
    ///   [Authentication Tree Data
    ///   Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) in
    ///   units of [Allocation
    ///   Blocks](ImageLayout::allocation_block_size_128b_log2).
    fn new_from_data_allocation_block_index(
        data_allocation_block_index: AuthTreeDataAllocBlockIndex,
        data_block_allocation_blocks_log2: u32,
    ) -> Self {
        Self {
            index: u64::from(data_allocation_block_index) >> data_block_allocation_blocks_log2,
        }
    }
}

impl convert::From<u64> for AuthTreeDataBlockIndex {
    fn from(value: u64) -> Self {
        Self { index: value }
    }
}

impl convert::From<AuthTreeDataBlockIndex> for u64 {
    fn from(value: AuthTreeDataBlockIndex) -> Self {
        value.index
    }
}

impl ops::Add<AuthTreeDataBlockCount> for AuthTreeDataBlockIndex {
    type Output = Self;

    fn add(self, rhs: AuthTreeDataBlockCount) -> Self::Output {
        Self {
            index: self.index.checked_add(u64::from(rhs)).unwrap(),
        }
    }
}

impl ops::AddAssign<AuthTreeDataBlockCount> for AuthTreeDataBlockIndex {
    fn add_assign(&mut self, rhs: AuthTreeDataBlockCount) {
        self.index = self.index.checked_add(u64::from(rhs)).unwrap();
    }
}

impl ops::Sub<Self> for AuthTreeDataBlockIndex {
    type Output = AuthTreeDataBlockCount;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::Output::from(self.index.checked_sub(rhs.index).unwrap())
    }
}

impl layout::BlockIndex<AuthTreeDataBlockCount> for AuthTreeDataBlockIndex {
    fn align_down(&self, align_log2: u32) -> Self {
        Self::from(self.index.round_down_pow2(align_log2))
    }

    fn align_up(&self, align_log2: u32) -> Option<Self> {
        Some(Self::from(self.index.round_up_pow2(align_log2)?))
    }
}

/// [`AuthTreeDataBlockIndex`] range.
pub type AuthTreeDataBlockRange = layout::BlockRange<AuthTreeDataBlockIndex, AuthTreeDataBlockCount>;

/// Authentication tree node identifier.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuthTreeNodeId {
    /// First Authentication Tree Data block authenticated by the node's
    /// leftmost leaf descandant.
    covered_data_blocks_begin: AuthTreeDataBlockIndex,
    /// Node level, counted zero-based from bottom.
    level: u8,
    /// Copied verbatim from the associated
    /// [`AuthTreeConfig::node_digests_per_node_log2`].
    node_digests_per_node_log2: u8,
    /// Copied verbatim from the associated
    /// [`AuthTreeConfig::data_digests_per_node_log2`].
    data_digests_per_node_log2: u8,
}

impl AuthTreeNodeId {
    /// Create a new [`AuthTreeNodeId`] instance.
    ///
    /// # Arguments:
    ///
    /// * `covered_data_blocks_index` - Index of some [Authentication Tree Data
    ///   Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    ///   within the data range covered by the subtree rooted at the node.
    /// * `level` - The node level, counted zero-based from bottom, i.e. from
    ///   the leaves.
    /// * `node_digests_per_node_log2` - The value of
    ///   [`AuthTreeConfig::node_digests_per_node_log2`] verbatim.
    /// * `data_digests_per_node_log2` - The value of
    ///   [`AuthTreeConfig::data_digests_per_node_log2`] verbatim.
    fn new(
        covered_data_block_index: AuthTreeDataBlockIndex,
        level: u8,
        node_digests_per_node_log2: u8,
        data_digests_per_node_log2: u8,
    ) -> Self {
        let level_covered_data_block_index_bits = Self::level_covered_data_block_index_bits(
            level as u32,
            node_digests_per_node_log2 as u32,
            data_digests_per_node_log2 as u32,
        );
        let covered_data_blocks_begin = if level_covered_data_block_index_bits < u64::BITS {
            u64::from(covered_data_block_index) & !u64::trailing_bits_mask(level_covered_data_block_index_bits)
        } else {
            0
        };
        Self {
            covered_data_blocks_begin: AuthTreeDataBlockIndex::from(covered_data_blocks_begin),
            level,
            node_digests_per_node_log2,
            data_digests_per_node_log2,
        }
    }

    /// Number of least significant [`AuthTreeDataBlockIndex`] bits covered by
    /// the (possibly virtual) complete subtree rooted at a node at given level.
    ///
    /// This effectively computes the base-2 logarithm of the number of leaf
    /// entries in a complete subtree of height `level + 1`.
    ///
    /// # Arguments:
    ///
    /// * `level` - Level of the subtree root, counted zero-based from bottom,
    ///   i.e. from the leaves.
    /// * `node_digests_per_node_log2` - The value of
    ///   [`AuthTreeConfig::node_digests_per_node_log2`] verbatim.
    /// * `data_digests_per_node_log2` - The value of
    ///   [`AuthTreeConfig::data_digests_per_node_log2`] verbatim.
    fn level_covered_data_block_index_bits(
        level: u32,
        node_digests_per_node_log2: u32,
        data_digests_per_node_log2: u32,
    ) -> u32 {
        level * node_digests_per_node_log2 + data_digests_per_node_log2
    }

    /// Index of the parent node digest entry the node gets digested into.
    fn index_in_parent(&self) -> usize {
        let level_covered_data_block_index_bits = Self::level_covered_data_block_index_bits(
            self.level as u32,
            self.node_digests_per_node_log2 as u32,
            self.data_digests_per_node_log2 as u32,
        );
        debug_assert!(level_covered_data_block_index_bits < u64::BITS);
        ((u64::from(self.covered_data_blocks_begin) >> level_covered_data_block_index_bits)
            & u64::trailing_bits_mask(self.node_digests_per_node_log2 as u32)) as usize
    }

    /// Index of the first [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// covered by the (possibly virtual) subtree rooted at the node.
    pub fn first_covered_data_block(&self) -> AuthTreeDataBlockIndex {
        self.covered_data_blocks_begin
    }

    /// Index of the last [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// covered by a (possibly virtual) complete subtree rooted at the node.
    ///
    /// Note that it is possible in certain configurations that the index of the
    /// (virtual) last covered [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// is not representable as an `u64`, in which case `u64::MAX` would get
    /// returned.
    pub fn last_covered_data_block(&self) -> AuthTreeDataBlockIndex {
        let level_covered_data_block_index_bits = Self::level_covered_data_block_index_bits(
            self.level as u32,
            self.node_digests_per_node_log2 as u32,
            self.data_digests_per_node_log2 as u32,
        );
        let last_covered_data_block = if level_covered_data_block_index_bits < u64::BITS {
            let level_covered_index_mask = u64::trailing_bits_mask(level_covered_data_block_index_bits);
            debug_assert_eq!(u64::from(self.covered_data_blocks_begin) & level_covered_index_mask, 0);
            u64::from(self.covered_data_blocks_begin) | level_covered_index_mask
        } else {
            u64::MAX
        };
        AuthTreeDataBlockIndex::from(last_covered_data_block)
    }

    /// Index of the first [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// covered by the (possibly virtual) subtree rooted at the node's last
    /// possible child.
    ///
    /// Used primarily as a proxy to identify the node in authentication
    /// contexts HMACced alongside the node's data itself.
    ///
    /// The resuly may only be used for non-virtual nodes, i.e. nodes for which
    /// the respective subtrees rooted at them do actually cover some
    /// non-empty range on the filesystem's image.
    ///
    /// Note that it is possible in certain configurations that the resulting
    /// index value for the root node overflows an `u64`, in which case it's
    /// taken to modulo two to the power of `u64::BITS` would get returned.
    /// Note that the root node's value would still be unique among all nodes in
    /// this case: the number of least significant consecutive zero bits is
    /// uniquely determined by the node's level and there is only one node
    /// at the root node's level.
    fn last_entry_covered_data_blocks_begin(&self) -> AuthTreeDataBlockIndex {
        if self.level != 0 {
            let level_covered_data_block_index_bits = Self::level_covered_data_block_index_bits(
                self.level as u32,
                self.node_digests_per_node_log2 as u32,
                self.data_digests_per_node_log2 as u32,
            );
            debug_assert!((level_covered_data_block_index_bits - self.node_digests_per_node_log2 as u32) < u64::BITS);
            AuthTreeDataBlockIndex::from(
                u64::from(self.covered_data_blocks_begin)
                    | (u64::trailing_bits_mask(self.node_digests_per_node_log2 as u32)
                        << (level_covered_data_block_index_bits - self.node_digests_per_node_log2 as u32)),
            )
        } else {
            debug_assert_eq!(
                u64::from(self.covered_data_blocks_begin)
                    & u64::trailing_bits_mask(self.data_digests_per_node_log2 as u32),
                0
            );
            AuthTreeDataBlockIndex::from(
                u64::from(self.covered_data_blocks_begin)
                    | u64::trailing_bits_mask(self.data_digests_per_node_log2 as u32),
            )
        }
    }
}

impl cmp::PartialOrd<Self> for AuthTreeNodeId {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl cmp::Ord for AuthTreeNodeId {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        // Implement DFS pre order.
        let max_level = self.level.max(other.level);
        if (u64::from(self.covered_data_blocks_begin) ^ u64::from(other.covered_data_blocks_begin))
            >> (max_level * self.node_digests_per_node_log2 + self.data_digests_per_node_log2)
            == 0
        {
            // One is the parent of the other, the child compares as greater.
            return match self.level.cmp(&other.level) {
                cmp::Ordering::Less => cmp::Ordering::Greater,
                cmp::Ordering::Equal => {
                    debug_assert_eq!(self.covered_data_blocks_begin, other.covered_data_blocks_begin);
                    cmp::Ordering::Equal
                }
                cmp::Ordering::Greater => cmp::Ordering::Less,
            };
        }

        debug_assert_ne!(self.covered_data_blocks_begin, other.covered_data_blocks_begin);
        self.covered_data_blocks_begin.cmp(&other.covered_data_blocks_begin)
    }
}

/// An authentication tree node's data.
pub struct AuthTreeNode {
    data: FixedVec<u8, 7>,
}

impl AuthTreeNode {
    /// Immutable access to some digest entry stored in the node.
    ///
    /// # Arguments:
    ///
    /// * `index` - Index of the digest entry within the node.
    /// * `digest_len` - Length of any digest entry stored in the node.
    fn get_digest(&self, index: usize, digest_len: usize) -> &[u8] {
        let digest_begin = index * digest_len;
        let digest_end = digest_begin + digest_len;
        &self.data[digest_begin..digest_end]
    }

    /// Mutable access to some digest entry stored in the node.
    ///
    /// # Arguments:
    ///
    /// * `index` - Index of the digest entry within the node.
    /// * `digest_len` - Length of any digest entry stored in the node.
    fn get_digest_mut(&mut self, index: usize, digest_len: usize) -> &mut [u8] {
        let digest_begin = index * digest_len;
        let digest_end = digest_begin + digest_len;
        &mut self.data[digest_begin..digest_end]
    }
}

/// Map physical [Allocation
/// Blocks](ImageLayout::allocation_block_size_128b_log2) indices into the
/// [Authentication Tree Data Block index domain](AuthTreeDataAllocBlockIndex)
/// and vice versa.
///
/// The authentication trees don't verify their own storage, therefore the
/// authenticated data is not contiguous on the physical storage, but
/// interspersed with authentication tree node storage extents. The
/// `AuthTreeDataAllocationBlocksMap` provides a means for translating
/// between physical addresses of [Allocation
/// Blocks](ImageLayout::allocation_block_size_128b_log2) subject to
/// authentication and contiguous [Authentication Tree Data domain
/// indices](AuthTreeDataAllocBlockIndex).
struct AuthTreeDataAllocationBlocksMap {
    /// Authentication tree storage extents represented as
    /// `(physical_end, accumulated_block_count)`, in units of [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2), ordered
    /// by `physical_end`, with `accumulated_block_count` being equal to the
    /// sum of all Allocation Blocks allocated to the authentication tree
    /// node storage up to `physical_end`.
    auth_tree_storage_physical_extents: Vec<(u64, u64)>,
}

impl AuthTreeDataAllocationBlocksMap {
    /// Instntiate a new `AuthTreeDataAllocationBlocksMap`.
    ///
    /// # Arguments:
    ///
    /// * `logical_auth_tree_extents` - The extents storing the authentication
    ///   tree's nodes.
    fn new(logical_auth_tree_extents: &extents::LogicalExtents) -> Result<Self, NvFsError> {
        let mut auth_tree_storage_physical_extents = Vec::new();
        auth_tree_storage_physical_extents.try_reserve_exact(logical_auth_tree_extents.len())?;
        for logical_extent in logical_auth_tree_extents.iter() {
            let physical_range = logical_extent.physical_range();
            // Temporarily add in unsorted order and with this
            // entry's block count only, the list will be sorted and the latter subsequently
            // accumulated below.
            auth_tree_storage_physical_extents
                .push((u64::from(physical_range.end()), u64::from(physical_range.block_count())));
        }
        auth_tree_storage_physical_extents.sort_unstable_by_key(|e| e.0);

        if auth_tree_storage_physical_extents.is_empty() {
            return Ok(Self {
                auth_tree_storage_physical_extents,
            });
        }

        // Transform the entries so that their second tuple field contains the
        // accumulated extent block count up to and including the current
        // position and merge extents together if possible.
        let (mut last_extent_physical_allocation_blocks_end, mut accumulated_block_count) =
            auth_tree_storage_physical_extents[0];
        let mut i = 1;
        while i < auth_tree_storage_physical_extents.len() {
            let e = &mut auth_tree_storage_physical_extents[i];
            accumulated_block_count += e.1;
            let cur_extent_physical_allocation_blocks_end = e.0;
            let cur_extent_physical_allocation_blocks_begin = cur_extent_physical_allocation_blocks_end - e.1;
            e.1 = accumulated_block_count;
            if cur_extent_physical_allocation_blocks_begin != last_extent_physical_allocation_blocks_end {
                i += 1;
            } else {
                auth_tree_storage_physical_extents.remove(i - 1);
            }
            last_extent_physical_allocation_blocks_end = cur_extent_physical_allocation_blocks_end;
        }

        Ok(Self {
            auth_tree_storage_physical_extents,
        })
    }

    /// Map a contiguous
    /// [`PhysicalAllocBlockRange`](layout::PhysicalAllocBlockRange) into the
    /// [Authentication Tree Data Block index
    /// domain](AuthTreeDataAllocBlockIndex).
    ///
    /// # Arguments:
    ///
    /// * `physical_range` - The
    ///   [`PhysicalAllocBlockRange`](layout::PhysicalAllocBlockRange) to map.
    ///   Must not overlap with any of the authentication tree nodes storage
    ///   extents.
    fn map_physical_to_data_allocation_blocks(
        &self,
        physical_range: &layout::PhysicalAllocBlockRange,
    ) -> AuthTreeDataAllocBlockRange {
        // Convert the physical Allocation Block index to an Authentication Tree Data
        // one by subtracting from the former the space occupied by any
        // authentication tree nodes located before it in the image.
        let i = self
            .auth_tree_storage_physical_extents
            .partition_point(|e| e.0 <= u64::from(physical_range.begin()));
        let auth_tree_storage_accumulated_block_count = if i != 0 {
            self.auth_tree_storage_physical_extents[i - 1].1
        } else {
            0
        };
        // The physical allocation block range shall not intersect with any
        // authentication tree nodes.
        if i < self.auth_tree_storage_physical_extents.len() {
            let next = self.auth_tree_storage_physical_extents[i];
            let next_begin = next.0 - (next.1 - auth_tree_storage_accumulated_block_count);
            let next_begin = layout::PhysicalAllocBlockIndex::from(next_begin);
            debug_assert!(next_begin >= physical_range.end());
        }
        AuthTreeDataAllocBlockRange::from((
            AuthTreeDataAllocBlockIndex::from(
                u64::from(physical_range.begin()) - auth_tree_storage_accumulated_block_count,
            ),
            physical_range.block_count(),
        ))
    }

    /// Map an [`AuthTreeDataAllocBlockIndex`] to the associated
    /// [`PhysicalAllocBlockIndex`](layout::PhysicalAllocBlockIndex).
    ///
    /// Note that the numeric value of an [`AuthTreeDataAllocBlockIndex`] is
    /// always `<=` the one of the corresponding
    /// [`PhysicalAllocBlockIndex`](layout::PhysicalAllocBlockIndex) and the two
    /// differ by at most the total number of [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2) occupied
    /// by the authentication tree storage. If `data_allocation_block_index` is
    /// within the maximum possible numerical range, which is bounded by
    /// `u64::MAX` bytes converted to units of [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2), then the
    /// conversion will not cause an integer overflow. However, in case
    /// `data_allocation_block_index` refers to a location beyond the
    /// filesystem image's actual authenticated data range, then it's not
    /// guaranteed that the resulting
    /// [`PhysicalAllocBlockIndex`](layout::PhysicalAllocBlockIndex) would also
    /// stay within these maximum possible numerical bounds.
    ///
    /// # Arguments:
    ///
    /// * `data_allocation_block_index` - The [`AuthTreeDataAllocBlockIndex`] to
    ///   map to its associated
    ///   [`PhysicalAllocBlockIndex`](layout::PhysicalAllocBlockIndex).
    fn map_data_to_physical_allocation_block(
        &self,
        data_allocation_block_index: AuthTreeDataAllocBlockIndex,
    ) -> layout::PhysicalAllocBlockIndex {
        let map_index = self
            .auth_tree_storage_physical_extents
            .partition_point(|e| e.0 - e.1 <= u64::from(data_allocation_block_index));
        if map_index != 0 {
            layout::PhysicalAllocBlockIndex::from(
                u64::from(data_allocation_block_index) + self.auth_tree_storage_physical_extents[map_index].1,
            )
        } else {
            layout::PhysicalAllocBlockIndex::from(u64::from(data_allocation_block_index))
        }
    }

    /// Map a contiguous range in the [Authentication Tree Data Block index
    /// domain](AuthTreeDataAllocBlockIndex) to an associated sequence of
    /// [`PhysicalAllocBlockRange`](layout::PhysicalAllocBlockRange)s.
    ///
    /// Note that while a single contiguous
    /// [`PhysicalAllocBlockRange`](layout::PhysicalAllocBlockRange) (not
    /// overlapping with any of the authentication tree's storage extents)
    /// always maps to a unique contiguous [`AuthTreeDataAllocBlockRange`],
    /// the converse is not true: a single contiguous
    /// [`AuthTreeDataAllocBlockRange`] can correspond to a sequence of more
    /// than one
    /// [`PhysicalAllocBlockRange`](layout::PhysicalAllocBlockRange), all
    /// interspersed with some authentication tree node storage extents on
    /// physical storage. That is, its mapping is piecewise linear and
    /// strictly monotonic increasing.
    ///
    /// Return an iterator over that mapping's linear pieces. More specifically,
    /// the iterator will yield pairs of [`AuthTreeDataAllocBlockRange`] and
    /// an associated
    /// [`PhysicalAllocBlockIndex`](layout::PhysicalAllocBlockIndex) each, where
    /// the former specifies an element of a `data_range` partition and the
    /// latter the beginning of the corresponding contiguous region on
    /// physical storage.
    ///
    /// `data_range` may extend into (or even be located entirely within) a
    /// region beyond the filesystem image's actual authenticated data
    /// range, but will be capped internally so that none of its (logically)
    /// associated
    /// [`PhysicalAllocBlockRange`](layout::PhysicalAllocBlockRange)s
    /// would ever exceed the upper bound of
    /// `u64::MAX` bytes converted to [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2).
    ///
    /// # Arguments:
    ///
    /// * `data_range` - The contiguous range in the [Authentication Tree Data
    ///   Block index domain](AuthTreeDataAllocBlockIndex) to map to its
    ///   associated
    ///   [`PhysicalAllocBlockRange`](layout::PhysicalAllocBlockRange)s.
    fn iter_data_range_mapping(
        &self,
        data_range: &AuthTreeDataAllocBlockRange,
    ) -> AuthTreeDataAllocationBlocksMapIterator<'_> {
        // Make sure that the last physical range emitted would not overflow an u64.
        let max_data_range_allocation_blocks_end =
            AuthTreeDataAllocBlockIndex::from(u64::MAX - u64::from(self.total_auth_tree_extents_allocation_blocks()));
        let data_range_allocation_blocks_begin = data_range.begin().min(max_data_range_allocation_blocks_end);
        let data_range_allocation_blocks_end = data_range.end().min(max_data_range_allocation_blocks_end);

        let map_index = self
            .auth_tree_storage_physical_extents
            .partition_point(|e| e.0 - e.1 <= u64::from(data_range_allocation_blocks_begin));
        AuthTreeDataAllocationBlocksMapIterator {
            map: self,
            map_index,
            next_data_allocation_block: data_range_allocation_blocks_begin,
            data_allocation_blocks_end: data_range_allocation_blocks_end,
        }
    }

    /// Return the total number of [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2) occupied
    /// by the authentication tree storage extents.
    fn total_auth_tree_extents_allocation_blocks(&self) -> layout::AllocBlockCount {
        layout::AllocBlockCount::from(self.auth_tree_storage_physical_extents.last().map(|e| e.1).unwrap_or(0))
    }
}

/// [`Iterator`] over the linear pieces of a given's
/// [`AuthTreeDataAllocBlockRange`]'s mapping into the
/// [`PhysicalAllocBlockIndex`](layout::PhysicalAllocBlockIndex) domain.
///
/// In general, single contiguous
/// [`AuthTreeDataAllocBlockRange`] can correspond to a sequence of more
/// than one
/// [`PhysicalAllocBlockRange`](layout::PhysicalAllocBlockRange), all
/// interspersed with some authentication tree node storage extents on
/// physical storage. That is, its mapping is piecewise linear and
/// strictly monotonic increasing.
///
/// `AuthTreeDataAllocationBlocksMapIterator` implements an [`Iterator`] over
/// that mapping's pieces. More specifically, it yield pairs of
/// [`AuthTreeDataAllocBlockRange`] and an associated
/// [`PhysicalAllocBlockIndex`](layout::PhysicalAllocBlockIndex) each, where the
/// former specifies an element of a partition of the original
/// [`AuthTreeDataAllocBlockRange`] and the latter the beginning of the
/// associated contiguous region on physical storage.
pub struct AuthTreeDataAllocationBlocksMapIterator<'a> {
    map: &'a AuthTreeDataAllocationBlocksMap,
    map_index: usize,
    next_data_allocation_block: AuthTreeDataAllocBlockIndex,
    data_allocation_blocks_end: AuthTreeDataAllocBlockIndex,
}

impl<'a> Iterator for AuthTreeDataAllocationBlocksMapIterator<'a> {
    type Item = (AuthTreeDataAllocBlockRange, layout::PhysicalAllocBlockIndex);

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_data_allocation_block == self.data_allocation_blocks_end {
            return None;
        }

        let data_allocation_blocks_begin = u64::from(self.next_data_allocation_block);
        let auth_tree_storage_accumulated_block_count = if self.map_index > 0 {
            let e = &self.map.auth_tree_storage_physical_extents[self.map_index - 1];
            debug_assert!(e.0 - e.1 <= data_allocation_blocks_begin);
            e.1
        } else {
            0
        };
        let data_allocation_blocks_end = if self.map_index < self.map.auth_tree_storage_physical_extents.len() {
            let e = self.map.auth_tree_storage_physical_extents[self.map_index];
            if e.0 - e.1 < u64::from(self.data_allocation_blocks_end) {
                self.map_index += 1;
                e.0 - e.1
            } else {
                u64::from(self.data_allocation_blocks_end)
            }
        } else {
            u64::from(self.data_allocation_blocks_end)
        };
        self.next_data_allocation_block = AuthTreeDataAllocBlockIndex::from(data_allocation_blocks_end);

        let physical_allocation_blocks_begin = data_allocation_blocks_begin + auth_tree_storage_accumulated_block_count;

        Some((
            AuthTreeDataAllocBlockRange::new(
                AuthTreeDataAllocBlockIndex::from(data_allocation_blocks_begin),
                self.next_data_allocation_block,
            ),
            layout::PhysicalAllocBlockIndex::from(physical_allocation_blocks_begin),
        ))
    }
}

#[test]
fn test_auth_tree_data_allocation_blocks_map_from_phys() {
    let mut logical_auth_tree_extents = extents::LogicalExtents::new();
    logical_auth_tree_extents
        .extend_by_physical(layout::PhysicalAllocBlockRange::from((
            layout::PhysicalAllocBlockIndex::from(1),
            layout::AllocBlockCount::from(1),
        )))
        .unwrap();
    logical_auth_tree_extents
        .extend_by_physical(layout::PhysicalAllocBlockRange::from((
            layout::PhysicalAllocBlockIndex::from(4),
            layout::AllocBlockCount::from(1),
        )))
        .unwrap();
    let map = AuthTreeDataAllocationBlocksMap::new(&logical_auth_tree_extents).unwrap();

    let auth_tree_data_range = map.map_physical_to_data_allocation_blocks(&layout::PhysicalAllocBlockRange::from((
        layout::PhysicalAllocBlockIndex::from(0),
        layout::AllocBlockCount::from(1),
    )));
    assert_eq!(u64::from(auth_tree_data_range.begin()), 0);
    assert_eq!(u64::from(auth_tree_data_range.end()), 1);

    let auth_tree_data_range = map.map_physical_to_data_allocation_blocks(&layout::PhysicalAllocBlockRange::from((
        layout::PhysicalAllocBlockIndex::from(2),
        layout::AllocBlockCount::from(1),
    )));
    assert_eq!(u64::from(auth_tree_data_range.begin()), 1);
    assert_eq!(u64::from(auth_tree_data_range.end()), 2);

    let auth_tree_data_range = map.map_physical_to_data_allocation_blocks(&layout::PhysicalAllocBlockRange::from((
        layout::PhysicalAllocBlockIndex::from(3),
        layout::AllocBlockCount::from(1),
    )));
    assert_eq!(u64::from(auth_tree_data_range.begin()), 2);
    assert_eq!(u64::from(auth_tree_data_range.end()), 3);

    let auth_tree_data_range = map.map_physical_to_data_allocation_blocks(&layout::PhysicalAllocBlockRange::from((
        layout::PhysicalAllocBlockIndex::from(2),
        layout::AllocBlockCount::from(2),
    )));
    assert_eq!(u64::from(auth_tree_data_range.begin()), 1);
    assert_eq!(u64::from(auth_tree_data_range.end()), 3);

    let auth_tree_data_range = map.map_physical_to_data_allocation_blocks(&layout::PhysicalAllocBlockRange::from((
        layout::PhysicalAllocBlockIndex::from(5),
        layout::AllocBlockCount::from(1),
    )));
    assert_eq!(u64::from(auth_tree_data_range.begin()), 3);
    assert_eq!(u64::from(auth_tree_data_range.end()), 4);

    let auth_tree_data_range = map.map_physical_to_data_allocation_blocks(&layout::PhysicalAllocBlockRange::from((
        layout::PhysicalAllocBlockIndex::from(6),
        layout::AllocBlockCount::from(1),
    )));
    assert_eq!(u64::from(auth_tree_data_range.begin()), 4);
    assert_eq!(u64::from(auth_tree_data_range.end()), 5);
}

#[test]
fn test_auth_tree_data_allocation_blocks_map_to_phys() {
    let mut logical_auth_tree_extents = extents::LogicalExtents::new();
    logical_auth_tree_extents
        .extend_by_physical(layout::PhysicalAllocBlockRange::from((
            layout::PhysicalAllocBlockIndex::from(1),
            layout::AllocBlockCount::from(1),
        )))
        .unwrap();
    logical_auth_tree_extents
        .extend_by_physical(layout::PhysicalAllocBlockRange::from((
            layout::PhysicalAllocBlockIndex::from(4),
            layout::AllocBlockCount::from(1),
        )))
        .unwrap();
    let map = AuthTreeDataAllocationBlocksMap::new(&logical_auth_tree_extents).unwrap();

    let mut mapped_auth_tree_data_range = map.iter_data_range_mapping(&AuthTreeDataAllocBlockRange::from((
        AuthTreeDataAllocBlockIndex::from(0),
        layout::AllocBlockCount::from(1),
    )));
    assert_eq!(
        mapped_auth_tree_data_range.next(),
        Some((
            AuthTreeDataAllocBlockRange::from(
                (AuthTreeDataAllocBlockIndex::from(0), layout::AllocBlockCount::from(1),)
            ),
            layout::PhysicalAllocBlockIndex::from(0)
        ))
    );
    assert!(mapped_auth_tree_data_range.next().is_none());

    let mut mapped_auth_tree_data_range = map.iter_data_range_mapping(&AuthTreeDataAllocBlockRange::from((
        AuthTreeDataAllocBlockIndex::from(0),
        layout::AllocBlockCount::from(2),
    )));
    assert_eq!(
        mapped_auth_tree_data_range.next(),
        Some((
            AuthTreeDataAllocBlockRange::from(
                (AuthTreeDataAllocBlockIndex::from(0), layout::AllocBlockCount::from(1),)
            ),
            layout::PhysicalAllocBlockIndex::from(0)
        ))
    );
    assert_eq!(
        mapped_auth_tree_data_range.next(),
        Some((
            AuthTreeDataAllocBlockRange::from(
                (AuthTreeDataAllocBlockIndex::from(1), layout::AllocBlockCount::from(1),)
            ),
            layout::PhysicalAllocBlockIndex::from(2)
        ))
    );
    assert!(mapped_auth_tree_data_range.next().is_none());

    let mut mapped_auth_tree_data_range = map.iter_data_range_mapping(&AuthTreeDataAllocBlockRange::from((
        AuthTreeDataAllocBlockIndex::from(1),
        layout::AllocBlockCount::from(2),
    )));
    assert_eq!(
        mapped_auth_tree_data_range.next(),
        Some((
            AuthTreeDataAllocBlockRange::from(
                (AuthTreeDataAllocBlockIndex::from(1), layout::AllocBlockCount::from(2),)
            ),
            layout::PhysicalAllocBlockIndex::from(2)
        ))
    );
    assert!(mapped_auth_tree_data_range.next().is_none());

    let mut mapped_auth_tree_data_range = map.iter_data_range_mapping(&AuthTreeDataAllocBlockRange::from((
        AuthTreeDataAllocBlockIndex::from(1),
        layout::AllocBlockCount::from(4),
    )));
    assert_eq!(
        mapped_auth_tree_data_range.next(),
        Some((
            AuthTreeDataAllocBlockRange::from(
                (AuthTreeDataAllocBlockIndex::from(1), layout::AllocBlockCount::from(2),)
            ),
            layout::PhysicalAllocBlockIndex::from(2)
        ))
    );
    assert_eq!(
        mapped_auth_tree_data_range.next(),
        Some((
            AuthTreeDataAllocBlockRange::from(
                (AuthTreeDataAllocBlockIndex::from(3), layout::AllocBlockCount::from(2),)
            ),
            layout::PhysicalAllocBlockIndex::from(5)
        ))
    );
    assert!(mapped_auth_tree_data_range.next().is_none());

    let mut mapped_auth_tree_data_range = map.iter_data_range_mapping(&AuthTreeDataAllocBlockRange::from((
        AuthTreeDataAllocBlockIndex::from(3),
        layout::AllocBlockCount::from(1),
    )));
    assert_eq!(
        mapped_auth_tree_data_range.next(),
        Some((
            AuthTreeDataAllocBlockRange::from(
                (AuthTreeDataAllocBlockIndex::from(3), layout::AllocBlockCount::from(1),)
            ),
            layout::PhysicalAllocBlockIndex::from(5)
        ))
    );
    assert!(mapped_auth_tree_data_range.next().is_none());

    let mut mapped_auth_tree_data_range = map.iter_data_range_mapping(&AuthTreeDataAllocBlockRange::from((
        AuthTreeDataAllocBlockIndex::from(4),
        layout::AllocBlockCount::from(1),
    )));
    assert_eq!(
        mapped_auth_tree_data_range.next(),
        Some((
            AuthTreeDataAllocBlockRange::from(
                (AuthTreeDataAllocBlockIndex::from(4), layout::AllocBlockCount::from(1),)
            ),
            layout::PhysicalAllocBlockIndex::from(6)
        ))
    );
    assert!(mapped_auth_tree_data_range.next().is_none());
}

/// Cache for an authentication tree's authenticated [nodes](AuthTreeNode).
///
/// Nodes in the cache are identified by their respective [`AuthTreeNodeId`].
pub struct AuthTreeNodeCache {
    cache: set_assoc_cache::SetAssocCache<AuthTreeNodeId, AuthTreeNode, AuthTreeNodeCacheMapNodeIdToSetAssocCacheSet>,
}

impl AuthTreeNodeCache {
    /// Instantiate an [`AuthTreeNodeCache`].
    pub fn new(tree_config: &AuthTreeConfig) -> Result<Self, NvFsError> {
        // Provide each level with ~2 cache entries, on average. Bin two levels together
        // each -- note that adding a child will need access to the parent for
        // authenticaton, and thus, LRU-refresh the latter.
        let auth_tree_levels = tree_config.auth_tree_levels as u32;
        let cache_sets_count = (2 * auth_tree_levels).div_ceil(4);
        let map_node_id_to_cache_set =
            AuthTreeNodeCacheMapNodeIdToSetAssocCacheSet::new(auth_tree_levels, cache_sets_count);
        let cache =
            set_assoc_cache::SetAssocCache::new(map_node_id_to_cache_set, iter::repeat_n(4, cache_sets_count as usize))
                .map_err(|e| match e {
                    set_assoc_cache::SetAssocCacheConfigureError::MemoryAllocationFailure => {
                        NvFsError::MemoryAllocationFailure
                    }
                })?;
        Ok(Self { cache })
    }

    /// Lookup a cache entry by [`AuthTreeNodeId`].
    ///
    /// Return the [cache entry index](AuthTreeNodeCacheIndex) of the entry
    /// storing the node with the specified `node_id` wrapped in a `Some`, if
    /// any, or `None` otherwise.
    fn lookup(&self, node_id: &AuthTreeNodeId) -> Option<AuthTreeNodeCacheIndex> {
        self.cache.lookup(node_id).map(|index| AuthTreeNodeCacheIndex { index })
    }

    /// Immutable access to a cache entry by its
    /// [index](AuthTreeNodeCacheIndex).
    ///
    /// Returns a pair of the specified cache entry's stored node's
    /// [`AuthTreeNodeId`] and an immutable reference to the node itself,
    /// collectively wrapped in a `Some`, if any, or `None` otherwise.
    fn get_entry(&self, index: AuthTreeNodeCacheIndex) -> Option<(&AuthTreeNodeId, &AuthTreeNode)> {
        self.cache.get_entry(index.index)
    }

    /// Mutable access to a cache entry by its
    /// [index](AuthTreeNodeCacheIndex).
    ///
    /// Returns a pair of the specified cache entry's stored node's
    /// [`AuthTreeNodeId`] and a mutable reference to the node itself,
    /// collectively wrapped in a `Some`, if any, or `None` otherwise.
    fn get_entry_mut(&mut self, index: AuthTreeNodeCacheIndex) -> Option<(&AuthTreeNodeId, &mut AuthTreeNode)> {
        self.cache.get_entry_mut(index.index)
    }

    /// Retrieve a cache entry's stored node's [`AuthTreeNodeId`], if any.
    fn get_entry_node_id(&self, index: AuthTreeNodeCacheIndex) -> Option<&AuthTreeNodeId> {
        self.cache.get_entry_key(index.index)
    }

    /// Insert a new entry in the cache.
    ///
    /// Upon success, the cache entry's associated [`AuthTreeNodeCacheIndex`]
    /// will get returned.
    ///
    /// # Arguments:
    ///
    /// * `node_id` - the node's id.
    /// * `node` - the **authenticated** node data.
    fn insert(&mut self, node_id: AuthTreeNodeId, node: AuthTreeNode) -> Result<AuthTreeNodeCacheIndex, NvFsError> {
        let index = match self.cache.insert(node_id, node) {
            set_assoc_cache::SetAssocCacheInsertionResult::Inserted { index, evicted: _ } => index,
            set_assoc_cache::SetAssocCacheInsertionResult::Uncacheable { .. } => {
                // All nodes are cached as per the key to set map.
                return Err(nvfs_err_internal!());
            }
        };
        Ok(AuthTreeNodeCacheIndex { index })
    }

    /// Clear the cache.
    fn clear(&mut self) {
        self.cache.prune_all();
    }
}

/// Index to an entry in the [`AuthTreeNodeCache`].
#[derive(Clone, Copy)]
struct AuthTreeNodeCacheIndex {
    index: set_assoc_cache::SetAssocCacheIndex,
}

/// [`SetAssocCacheMapKeyToSet`](set_assoc_cache::SetAssocCacheMapKeyToSet)
/// implementation controlling the layout of the
/// [`SetAssocCache`](set_assoc_cache::SetAssocCache) used internally by
/// [`AuthTreeNodeCache`].
struct AuthTreeNodeCacheMapNodeIdToSetAssocCacheSet {
    cache_sets_count: u8,
    auth_tree_levels_inv_multiplier: u32,
    auth_tree_levels_inv_shift: u32,
}

impl AuthTreeNodeCacheMapNodeIdToSetAssocCacheSet {
    fn new(auth_tree_levels: u32, cache_sets_count: u32) -> Self {
        debug_assert!(auth_tree_levels != 0);

        // With (auth_tree_levels - 1) * cache_sets_count being < 2^15, the
        // "divison by multiplication + shift" method can get implemented
        // completely in 32-bit arithmetic. For reference, c.f.  Hacker's Delight, 2nd
        // edition, 10-13 ("INTEGER DIVISION BY CONSTANTS - Similar Methods").
        debug_assert!(auth_tree_levels <= 64);
        debug_assert!(cache_sets_count <= 64);

        // Logarithm by two, rounded up.
        let auth_tree_levels_log2 = auth_tree_levels.ilog2() + !auth_tree_levels.is_pow2() as u32;
        let auth_tree_levels_inv_shift = 16 + auth_tree_levels_log2;
        let auth_tree_levels_inv_multiplier = (1u32 << auth_tree_levels_inv_shift).div_ceil(auth_tree_levels);
        debug_assert!(auth_tree_levels_inv_multiplier < 1u32 << (16 + 1));

        Self {
            cache_sets_count: cache_sets_count as u8,
            auth_tree_levels_inv_multiplier,
            auth_tree_levels_inv_shift,
        }
    }
}

impl set_assoc_cache::SetAssocCacheMapKeyToSet<AuthTreeNodeId> for AuthTreeNodeCacheMapNodeIdToSetAssocCacheSet {
    fn map_key(&self, key: &AuthTreeNodeId) -> Option<usize> {
        // Nodes are mapped to cache sets based on their level only, and the mapping is
        // affine.
        let level = key.level as u32;
        Some(
            ((level * self.cache_sets_count as u32 * self.auth_tree_levels_inv_multiplier)
                >> self.auth_tree_levels_inv_shift) as usize,
        )
    }
}

/// Reference to an [`AuthTreeNodeCache`] instance wrapped in a
/// [`RwLock`](sync_types::RwLock).
///
/// Instances of [`AuthTreeNodeCache`] are expected to get wrapped in a
/// [`RwLock`](sync_types::RwLock). `AuthTreeNodeCacheRef` can represent either
/// immutable references to the containing [`RwLock`](sync_types::RwLock) or
/// a mutable reference to the inner [`AuthTreeNodeCache`].
///
/// API functions needing access to an [`AuthTreeNodeCache`] usually take it as
/// an argument of type `AuthTreeNodeCacheRef`, thereby potentially alleviating
/// the need to take the lock in case the caller can provide exclusive access
/// already.
///
/// # See also:
///
/// * [`AuthTreeRef::destructure_borrow()`].
pub enum AuthTreeNodeCacheRef<'a, ST: sync_types::SyncTypes> {
    /// Immutable reference to the [`RwLock`](sync_types::RwLock) wrapping the
    /// [`AuthTreeNodeCache`].
    ///
    /// Accessing the wrapped [`AuthTreeNodeCache`] requires locking the
    /// protecting [`RwLock`](sync_types::RwLock).
    Ref { cache: &'a ST::RwLock<AuthTreeNodeCache> },
    /// Direct mutable reference to the [`AuthTreeNodeCache`].
    ///
    /// Accessing the referenced [`AuthTreeNodeCache`] does not involve any
    /// locking operation.
    MutRef { cache: &'a mut AuthTreeNodeCache },
}

impl<'a, ST: sync_types::SyncTypes> AuthTreeNodeCacheRef<'a, ST> {
    /// Reborrow the reference.
    ///
    /// [`AuthTreeNodeCacheRef`] is not covariant over its lifetime parameter.
    /// `make_borrow()` enables reborrowing with a shorter lifetime if
    /// needed.
    fn make_borrow(&mut self) -> AuthTreeNodeCacheRef<'_, ST> {
        match self {
            Self::Ref { cache } => AuthTreeNodeCacheRef::Ref { cache },
            Self::MutRef { cache } => AuthTreeNodeCacheRef::MutRef { cache },
        }
    }
}

impl<'a, ST: sync_types::SyncTypes> convert::From<AuthTreeNodeCacheReadGuard<'a, ST>> for AuthTreeNodeCacheRef<'a, ST> {
    fn from(value: AuthTreeNodeCacheReadGuard<'a, ST>) -> Self {
        match value {
            AuthTreeNodeCacheReadGuard::ReadGuard { cache, guard: _ } => Self::Ref { cache },
            AuthTreeNodeCacheReadGuard::WriteGuard { guard } => Self::from(guard),
        }
    }
}

impl<'a, ST: sync_types::SyncTypes> convert::From<AuthTreeNodeCacheWriteGuard<'a, ST>>
    for AuthTreeNodeCacheRef<'a, ST>
{
    fn from(value: AuthTreeNodeCacheWriteGuard<'a, ST>) -> Self {
        match value {
            AuthTreeNodeCacheWriteGuard::WriteGuard { cache, guard: _ } => Self::Ref { cache },
            AuthTreeNodeCacheWriteGuard::MutRef { cache } => Self::MutRef { cache },
        }
    }
}

impl<'a, 'b, ST: sync_types::SyncTypes> convert::From<&'a mut AuthTreeRef<'b, ST>> for AuthTreeNodeCacheRef<'a, ST> {
    fn from(value: &'a mut AuthTreeRef<'b, ST>) -> Self {
        match value {
            AuthTreeRef::Ref { tree } => Self::Ref {
                cache: &tree.node_cache,
            },
            AuthTreeRef::MutRef { tree } => Self::MutRef {
                cache: tree.node_cache.get_mut(),
            },
        }
    }
}

/// Read guard for an [`AuthTreeNodeCache`] wrapped in a
/// [`RwLock`](sync_types::RwLock).
///
/// Usually obtained from an [`AuthTreeNodeCacheRef`] via [`From`] or
/// constructed explicitly from an [`AuthTreeNodeCacheWriteGuard`].
enum AuthTreeNodeCacheReadGuard<'a, ST: sync_types::SyncTypes>
where
    <ST as sync_types::SyncTypes>::RwLock<AuthTreeNodeCache>: 'a,
{
    /// The `AuthTreeNodeCacheReadGuard` instance is realized by an actual
    /// [`RwLock::ReadGuard`](sync_types::RwLock::ReadGuard).
    ///
    /// Usually spawned off from a [`AuthTreeNodeCacheRef::Ref`].
    ReadGuard {
        cache: &'a ST::RwLock<AuthTreeNodeCache>,
        guard: <ST::RwLock<AuthTreeNodeCache> as sync_types::RwLock<AuthTreeNodeCache>>::ReadGuard<'a>,
    },
    /// The `AuthTreeNodeCacheReadGuard` instance is realized by an
    /// [`AuthTreeNodeCacheWriteGuard`].
    WriteGuard { guard: AuthTreeNodeCacheWriteGuard<'a, ST> },
}

impl<'a, ST: sync_types::SyncTypes> ops::Deref for AuthTreeNodeCacheReadGuard<'a, ST> {
    type Target = AuthTreeNodeCache;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::ReadGuard { cache: _, guard } => guard,
            Self::WriteGuard { guard } => guard,
        }
    }
}

impl<'a, ST: sync_types::SyncTypes> convert::From<AuthTreeNodeCacheRef<'a, ST>> for AuthTreeNodeCacheReadGuard<'a, ST> {
    fn from(value: AuthTreeNodeCacheRef<'a, ST>) -> Self {
        match value {
            AuthTreeNodeCacheRef::Ref { cache } => Self::ReadGuard {
                cache,
                guard: cache.read(),
            },
            AuthTreeNodeCacheRef::MutRef { cache } => Self::WriteGuard {
                guard: AuthTreeNodeCacheWriteGuard::MutRef { cache },
            },
        }
    }
}

/// Write guard for an [`AuthTreeNodeCache`] wrapped in a
/// [`RwLock`](sync_types::RwLock).
enum AuthTreeNodeCacheWriteGuard<'a, ST: sync_types::SyncTypes>
where
    <ST as sync_types::SyncTypes>::RwLock<AuthTreeNodeCache>: 'a,
{
    /// The `AuthTreeNodeCacheWriteGuard` instance is realized by an actual
    /// [`RwLock::WriteGuard`](sync_types::RwLock::WriteGuard).
    ///
    /// Usually spawned off from a [`AuthTreeNodeCacheRef::Ref`].
    WriteGuard {
        cache: &'a ST::RwLock<AuthTreeNodeCache>,
        guard: <ST::RwLock<AuthTreeNodeCache> as sync_types::RwLock<AuthTreeNodeCache>>::WriteGuard<'a>,
    },
    /// The `AuthTreeNodeCacheWriteGuard` instance is realized by a mutable
    /// reference to the [`AuthTreeNodeCache`].
    ///
    /// Usually spawned off by borrowing from a
    /// [`AuthTreeNodeCacheRef::MutRef`].
    MutRef { cache: &'a mut AuthTreeNodeCache },
}

impl<'a, ST: sync_types::SyncTypes> ops::Deref for AuthTreeNodeCacheWriteGuard<'a, ST> {
    type Target = AuthTreeNodeCache;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::WriteGuard { cache: _, guard } => guard,
            Self::MutRef { cache } => cache,
        }
    }
}

impl<'a, ST: sync_types::SyncTypes> ops::DerefMut for AuthTreeNodeCacheWriteGuard<'a, ST> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::WriteGuard { cache: _, guard } => guard.deref_mut(),
            Self::MutRef { cache } => cache,
        }
    }
}

impl<'a, ST: sync_types::SyncTypes> convert::From<AuthTreeNodeCacheRef<'a, ST>>
    for AuthTreeNodeCacheWriteGuard<'a, ST>
{
    fn from(value: AuthTreeNodeCacheRef<'a, ST>) -> Self {
        match value {
            AuthTreeNodeCacheRef::Ref { cache } => Self::WriteGuard {
                cache,
                guard: cache.write(),
            },
            AuthTreeNodeCacheRef::MutRef { cache } => Self::MutRef { cache },
        }
    }
}

/// Reference to an entry in an [`AuthTreeNodeCache`].
pub struct AuthTreeNodeCacheEntryRef<'a, ST: sync_types::SyncTypes> {
    cache: AuthTreeNodeCacheReadGuard<'a, ST>,
    entry_index: AuthTreeNodeCacheIndex,
}

impl<'a, ST: sync_types::SyncTypes> AuthTreeNodeCacheEntryRef<'a, ST> {
    pub fn get_node_id(&self) -> &AuthTreeNodeId {
        self.cache.get_entry_node_id(self.entry_index).unwrap()
    }
}

impl<'a, ST: sync_types::SyncTypes> convert::From<AuthTreeNodeCacheEntryRef<'a, ST>>
    for AuthTreeNodeCacheReadGuard<'a, ST>
{
    fn from(value: AuthTreeNodeCacheEntryRef<'a, ST>) -> Self {
        value.cache
    }
}

impl<'a, ST: sync_types::SyncTypes> ops::Deref for AuthTreeNodeCacheEntryRef<'a, ST> {
    type Target = AuthTreeNode;

    fn deref(&self) -> &Self::Target {
        self.cache.get_entry(self.entry_index).unwrap().1
    }
}

/// Authentication tree configuration parameters and related functionality.
pub struct AuthTreeConfig {
    /// Location of the authentication tree's node storage on physical storage.
    auth_tree_extents: extents::LogicalExtents,
    /// Translation map between the [physical](layout::PhysicalAllocBlockIndex)
    /// and the [Authentication Tree Data Block](AuthTreeDataAllocBlockIndex)
    /// index domains.
    auth_tree_data_allocation_blocks_map: AuthTreeDataAllocationBlocksMap,

    /// Base-2 logarithm of the number of digests in a non-leaf node.
    ///
    /// Determines the number of digests of type
    /// [`node_hash_alg`](Self::node_hash_alg) that fit
    /// into an authentication tree node, rounded down to the next power of two.
    node_digests_per_node_log2: u8,
    /// Inverse of `(1 << node_digests_per_node_log2) - 1` modulo
    /// 2<sup>64</sup>, c.f. [`digests_per_node_minus_one_inv_mod_u64()`].
    node_digests_per_node_minus_one_inv_mod_u64: u64,
    /// Base-2 logarithm of the number of digests in a leaf node.
    ///
    /// Determines the number of digests of type
    /// [`data_hmac_hash_alg`](Self::data_hmac_hash_alg) that fit
    /// into an authentication tree node, rounded down to the next power of two.
    data_digests_per_node_log2: u8,

    /// Height of the authentication tree.
    auth_tree_levels: u8,
    /// Maximum number of [Authentication Tree Data
    /// Blocks](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// authenticated by the authentication tree.
    max_covered_data_block_count: u64,

    /// Copied verbatim from [`ImageLayout::auth_tree_node_hash_alg`].
    node_hash_alg: tpm2_interface::TpmiAlgHash,
    /// Length of a digest of type [`node_hash_alg`](Self::node_hash_alg).
    node_digest_len: u8,

    /// Copied verbatim from [`ImageLayout::auth_tree_data_hmac_hash_alg`].
    data_hmac_hash_alg: tpm2_interface::TpmiAlgHash,
    /// HMAC key used for forming digests over [Authentication Tree Data
    /// Blocks](ImageLayout::auth_tree_data_block_allocation_blocks_log2) with
    /// [`data_hmac_hash_alg`](Self::data_hmac_hash_alg)
    data_hmac_key: zeroize::Zeroizing<FixedVec<u8, 4>>,
    /// Length of a digest of type
    /// [`data_hmac_hash_alg`](Self::data_hmac_hash_alg).
    data_digest_len: u8,

    /// Copied verbatim from [`ImageLayout::auth_tree_root_hmac_hash_alg`].
    root_hmac_hash_alg: tpm2_interface::TpmiAlgHash,
    /// HMAC key used for forming authentication tree root digests with
    /// [`root_hmac_hash_alg`](Self::root_hmac_hash_alg).
    root_hmac_key: zeroize::Zeroizing<FixedVec<u8, 4>>,

    /// Copied verbatim from [`ImageLayout::allocation_block_size_128b_log2`].
    allocation_block_size_128b_log2: u8,
    /// Derived from from [`ImageLayout::auth_tree_node_io_blocks_log2`].
    node_allocation_blocks_log2: u8,
    /// Copied verbatim from
    /// [`ImageLayout::auth_tree_data_block_allocation_blocks_log2`].
    data_block_allocation_blocks_log2: u8,

    /// Digest over image context data to be included in the final root digest.
    image_context_digest: FixedVec<u8, 5>,
}

impl AuthTreeConfig {
    /// Instantiate a new `AuthTreeConfig`.
    ///
    /// # Arguments:
    ///
    /// * `root_key` - The filesystem's root key.
    /// * `image_layout` - The filesystem's [`ImageLayout`].
    /// * `inode_index_entry_leaf_node_block_ptr` -  The inode index entry leaf
    ///   node pointer as found in the filesystem's
    ///   [`MutableImageHeader::inode_index_entry_leaf_node_block_ptr`].
    /// * `image_size` - The filesystem image size as found in the filesystem's
    ///   [`MutableImageHeader::image_size`].
    /// * `auth_tree_extents` - Storage extents of the authentication tree.
    /// * `allocation_bitmap_extents` - Storage extents of the allocation bitmap
    ///   file.
    pub fn new(
        root_key: &keys::RootKey,
        image_layout: &layout::ImageLayout,
        inode_index_entry_leaf_node_block_ptr: &extent_ptr::EncodedBlockPtr,
        image_size: layout::AllocBlockCount,
        auth_tree_extents: extents::LogicalExtents,
        allocation_bitmap_extents: &extents::PhysicalExtents,
    ) -> Result<Self, NvFsError> {
        let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2;
        let node_allocation_blocks_log2 = image_layout
            .auth_tree_node_io_blocks_log2
            .checked_add(image_layout.io_block_allocation_blocks_log2)
            .ok_or(CocoonFsFormatError::InvalidAuthTreeConfig)?;
        // An Authentication Tree Node's size must fit an usize as well as an
        // u64.
        let node_size_128b_log2 = node_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32;
        let node_size_log2 = node_size_128b_log2 + 7;
        if node_size_log2 >= u64::BITS {
            return Err(CocoonFsFormatError::InvalidAuthTreeConfig.into());
        } else if node_size_log2 >= usize::BITS {
            return Err(CocoonFsFormatError::UnsupportedAuthTreeConfig.into());
        }

        let data_block_allocation_blocks_log2 = image_layout.auth_tree_data_block_allocation_blocks_log2 as u32;
        // A Data Block's Allocation Blocks must be representable in an u64 bitmap (for
        // a Data Block HMAC's authentication context).
        if data_block_allocation_blocks_log2 >= u32::BITS || 1u32 << data_block_allocation_blocks_log2 > u64::BITS {
            return Err(CocoonFsFormatError::InvalidAuthTreeConfig.into());
        }

        let node_hash_alg = image_layout.auth_tree_node_hash_alg;
        let node_digest_len = hash::hash_alg_digest_len(node_hash_alg);
        let node_digest_len_log2 = (node_digest_len as u32).round_up_next_pow2().unwrap().ilog2();
        if node_size_log2 <= node_digest_len_log2 {
            return Err(CocoonFsFormatError::InvalidAuthTreeConfig.into());
        }
        let node_digests_per_node_log2 = (node_size_log2 - node_digest_len_log2) as u8;

        let data_hmac_hash_alg = image_layout.auth_tree_data_hmac_hash_alg;
        let data_digest_len = hash::hash_alg_digest_len(data_hmac_hash_alg);
        let data_digest_len_log2 = (data_digest_len as u32).round_up_next_pow2().unwrap().ilog2();
        if node_size_log2 <= data_digest_len_log2 {
            return Err(CocoonFsFormatError::InvalidAuthTreeConfig.into());
        }
        let data_digests_per_node_log2 = (node_size_log2 - data_digest_len_log2) as u8;
        let data_hmac_key = root_key.derive_key(&keys::KeyId::new(
            inode_index::SpecialInode::AuthTree as u32,
            0,
            keys::KeyPurpose::AuthenticationData,
        ))?;

        // Verify that all the Authentication Tree's extents are aligned to the larger
        // of
        // - the IO block size,
        // - the Authentication Tree Data Block size
        // and that each extent contains an integral multiple of Authentication Tree
        // nodes.
        let io_block_allocation_blocks_log2 = image_layout.io_block_allocation_blocks_log2 as u32;
        let auth_tree_extents_min_alignment_allocation_blocks_log2 =
            io_block_allocation_blocks_log2.max(data_block_allocation_blocks_log2);
        for extent in auth_tree_extents.iter() {
            let physical_range = extent.physical_range();
            if !(u64::from(physical_range.begin()) | u64::from(physical_range.end()))
                .is_aligned_pow2(auth_tree_extents_min_alignment_allocation_blocks_log2)
                || !u64::from(physical_range.block_count()).is_aligned_pow2(io_block_allocation_blocks_log2)
            {
                return Err(CocoonFsFormatError::UnalignedAuthTreeExtents.into());
            }
        }
        let auth_tree_nodes_allocation_block_count = auth_tree_extents.allocation_block_count();
        if u64::from(auth_tree_extents.allocation_block_count()) == 0 {
            return Err(CocoonFsFormatError::InvalidAuthTreeDimensions.into());
        }
        if image_size < auth_tree_nodes_allocation_block_count {
            return Err(CocoonFsFormatError::InvalidAuthTreeDimensions.into());
        }

        let auth_tree_data_allocation_blocks_map = AuthTreeDataAllocationBlocksMap::new(&auth_tree_extents)?;

        // Deduce the Authentication Tree dimensions from the node count.
        let auth_tree_node_count = u64::from(auth_tree_nodes_allocation_block_count) >> node_allocation_blocks_log2;
        let auth_tree_levels = auth_tree_node_count_to_auth_tree_levels(
            auth_tree_node_count,
            node_digests_per_node_log2 as u32,
            data_digests_per_node_log2 as u32,
            data_block_allocation_blocks_log2,
        )?;
        let node_digests_per_node_minus_one_inv_mod_u64 =
            digests_per_node_minus_one_inv_mod_u64(node_digests_per_node_log2 as u32);
        // Verify that the extents of the covered data can be deduced. This validates
        // the tree shape as well (e.g. no dangling interior nodes without any
        // descendants).
        let mut max_covered_data_block_count = auth_tree_node_count_to_max_covered_data_block_count(
            auth_tree_node_count,
            auth_tree_levels,
            node_digests_per_node_log2 as u32,
            node_digests_per_node_minus_one_inv_mod_u64,
            data_digests_per_node_log2 as u32,
            data_block_allocation_blocks_log2,
        )?;
        max_covered_data_block_count = max_covered_data_block_count.min(u64::MAX >> data_block_allocation_blocks_log2);

        let image_data_allocation_blocks = image_size - auth_tree_nodes_allocation_block_count;
        let mut image_data_blocks = u64::from(image_data_allocation_blocks) >> data_block_allocation_blocks_log2;
        if image_data_blocks << data_block_allocation_blocks_log2 != u64::from(image_data_allocation_blocks) {
            image_data_blocks += 1;
        }
        if image_data_blocks > max_covered_data_block_count {
            return Err(CocoonFsFormatError::InvalidAuthTreeDimensions.into());
        }

        let root_hmac_hash_alg = image_layout.auth_tree_root_hmac_hash_alg;
        let root_hmac_key = root_key.derive_key(&keys::KeyId::new(
            inode_index::SpecialInode::AuthTree as u32,
            0,
            keys::KeyPurpose::AuthenticationRoot,
        ))?;

        let image_context_digest_len = hash::hash_alg_digest_len(root_hmac_hash_alg) as usize;
        let mut image_context_digest = FixedVec::new_with_default(image_context_digest_len)?;
        Self::digest_image_context_into(
            &mut image_context_digest,
            root_hmac_hash_alg,
            &root_hmac_key,
            image_layout,
            inode_index_entry_leaf_node_block_ptr,
            image_size,
            &auth_tree_extents,
            allocation_bitmap_extents,
        )?;

        Ok(Self {
            auth_tree_extents,
            auth_tree_data_allocation_blocks_map,
            node_digests_per_node_log2,
            node_digests_per_node_minus_one_inv_mod_u64,
            data_digests_per_node_log2,
            auth_tree_levels,
            max_covered_data_block_count,
            node_hash_alg,
            node_digest_len,
            data_hmac_hash_alg,
            data_hmac_key,
            data_digest_len,
            root_hmac_hash_alg,
            root_hmac_key,
            allocation_block_size_128b_log2,
            node_allocation_blocks_log2,
            data_block_allocation_blocks_log2: image_layout.auth_tree_data_block_allocation_blocks_log2,
            image_context_digest,
        })
    }

    /// Deduce suitable authentication tree dimensions from the total filesystem
    /// image size.
    ///
    /// To be used at filesystem creation ("mkfs") time to fit the
    /// authentication tree's dimensions to a given filesystem image size.
    /// The authentication tree size is determined as the minimum such that
    /// the storage needed for the tree itself plus the data range possibly
    /// authenticated by it together span as much of the filesystem image size
    /// as possible.
    ///
    /// The result will be returned as a pair of authentication tree node count
    /// and the size of any filesystem image remainder space, which is
    /// beyond the data range possibly authenticated by the tree of found
    /// dimensions, hence cannot be used by the filesystem.
    ///
    /// # Arguments:
    ///
    /// * `image_layout` - The filesystem's [`ImageLayout`].
    /// * `image_allocation_blocks` - The desired filesystem image size.
    pub fn image_allocation_blocks_to_auth_tree_node_count(
        image_layout: &layout::ImageLayout,
        image_allocation_blocks: layout::AllocBlockCount,
    ) -> Result<(u64, layout::AllocBlockCount), NvFsError> {
        let allocation_block_size_128b_log2 = image_layout.allocation_block_size_128b_log2 as u32;
        let node_allocation_blocks_log2 =
            image_layout.auth_tree_node_io_blocks_log2 as u32 + image_layout.io_block_allocation_blocks_log2 as u32;
        // An Authentication Tree Node's size must fit an usize as well as an
        // u64.
        let node_size_128b_log2 = node_allocation_blocks_log2 + allocation_block_size_128b_log2;
        let node_size_log2 = node_size_128b_log2 + 7;
        if node_size_log2 >= u64::BITS {
            return Err(CocoonFsFormatError::InvalidAuthTreeConfig.into());
        } else if node_size_log2 >= usize::BITS {
            return Err(CocoonFsFormatError::UnsupportedAuthTreeConfig.into());
        }

        let data_block_allocation_blocks_log2 = image_layout.auth_tree_data_block_allocation_blocks_log2 as u32;
        // A Data Block's Allocation Blocks must be representable in an u64 bitmap (for
        // a Data Block HMAC's authentication context).
        if data_block_allocation_blocks_log2 >= u32::BITS || 1u32 << data_block_allocation_blocks_log2 > u64::BITS {
            return Err(CocoonFsFormatError::InvalidAuthTreeConfig.into());
        }

        let node_hash_alg = image_layout.auth_tree_node_hash_alg;
        let node_digest_len = hash::hash_alg_digest_len(node_hash_alg);
        let node_digest_len_log2 = (node_digest_len as u32).round_up_next_pow2().unwrap().ilog2();
        if node_size_log2 <= node_digest_len_log2 {
            return Err(CocoonFsFormatError::InvalidAuthTreeConfig.into());
        }
        let node_digests_per_node_log2 = node_size_log2 - node_digest_len_log2;
        let node_digests_per_node_minus_one_inv_mod_u64 =
            digests_per_node_minus_one_inv_mod_u64(node_digests_per_node_log2);

        let data_hmac_hash_alg = image_layout.auth_tree_data_hmac_hash_alg;
        let data_digest_len = hash::hash_alg_digest_len(data_hmac_hash_alg);
        let data_digest_len_log2 = (data_digest_len as u32).round_up_next_pow2().unwrap().ilog2();
        if node_size_log2 <= data_digest_len_log2 {
            return Err(CocoonFsFormatError::InvalidAuthTreeConfig.into());
        }
        let data_digests_per_node_log2 = node_size_log2 - data_digest_len_log2;

        let auth_tree_levels = image_allocation_blocks_to_auth_tree_levels(
            image_allocation_blocks,
            node_digests_per_node_log2,
            node_digests_per_node_minus_one_inv_mod_u64,
            data_digests_per_node_log2,
            node_allocation_blocks_log2,
            image_layout.auth_tree_data_block_allocation_blocks_log2 as u32,
        )?;

        Ok(image_allocation_blocks_to_auth_tree_node_count(
            image_allocation_blocks,
            auth_tree_levels,
            node_digests_per_node_log2,
            node_digests_per_node_minus_one_inv_mod_u64,
            data_digests_per_node_log2,
            node_allocation_blocks_log2,
            image_layout.auth_tree_data_block_allocation_blocks_log2 as u32,
        ))
    }

    /// Form the image context digest to be included in the final root node
    /// digest.
    ///
    /// # Arguments:
    ///
    /// * `dst` - Destination buffer to write the digest to. Its length must
    ///   match that of [`root_hmac_hash_alg`](Self::root_hmac_hash_alg) digests
    ///   exactly.
    /// * `root_hmac_hash_alg` - Verbatim copy of
    ///   [`root_hmac_hash_alg`](Self::root_hmac_hash_alg).
    /// * `root_hmac_key` -  Reference to the
    ///   [`root_hmac_key`](Self::root_hmac_key) or equivalent.
    /// * `image_layout` - The filesystem's [`ImageLayout`].
    /// * `inode_index_entry_leaf_node_block_ptr` -  The inode index entry leaf
    ///   node pointer as found in the filesystem's
    ///   [`MutableImageHeader::inode_index_entry_leaf_node_block_ptr`].
    /// * `image_size` - The filesystem image size as found in the filesystem's
    ///   [`MutableImageHeader::image_size`].
    /// * `auth_tree_extents` - Storage extents of the authentication tree.
    /// * `allocation_bitmap_extents` - Storage extents of the allocation bitmap
    ///   file.
    #[allow(clippy::too_many_arguments)]
    fn digest_image_context_into(
        dst: &mut [u8],
        root_hmac_hash_alg: tpm2_interface::TpmiAlgHash,
        root_hmac_key: &[u8],
        image_layout: &layout::ImageLayout,
        inode_index_entry_leaf_node_block_ptr: &extent_ptr::EncodedBlockPtr,
        image_size: layout::AllocBlockCount,
        auth_tree_extents: &extents::LogicalExtents,
        allocation_bitmap_extents: &extents::PhysicalExtents,
    ) -> Result<(), NvFsError> {
        if dst.len() != hash::hash_alg_digest_len(root_hmac_hash_alg) as usize {
            return Err(nvfs_err_internal!());
        }
        // Note: the digest gets HMACced again when forming the root digest. The HMAC
        // operation is done here only to be consistent with the hash
        // algorithm's intended usage -- otherwise a mere plain hash would work
        // just as well.
        let mut h = hash::HmacInstance::new(root_hmac_hash_alg, root_hmac_key)?;

        let auth_context_subject_id_suffix = [
            0u8, // Version of the authenticated data's format.
            AuthSubjectDataSuffix::ImageContext as u8,
        ];

        // Make the authentication tree's extents part of the context in order to fix
        // the mapping of physical indices into the authentication tree data
        // block index domain.
        let auth_tree_extents = inode_extents_list::indirect_extents_list_encode(
            auth_tree_extents.iter().map(|e| e.physical_range()),
            None,
        )?;

        // Make the allocation bitmap special file's extents part of the context in
        // order to enable bootstrapping: the allocation bitmap's contents will
        // get authenticated through the authentication tree, but for CCA
        // protection, it needs also get verified that the authenticated
        // contents are actually from the allocation bitmap.
        let allocation_bitmap_extents =
            inode_extents_list::indirect_extents_list_encode(allocation_bitmap_extents.iter(), None)?;
        h.update(
            io_slices::BuffersSliceIoSlicesIter::new(&[
                b"COCOONFS".as_slice(),
                0u8.to_le_bytes().as_slice(),
                image_layout.encode()?.as_slice(),
                inode_index_entry_leaf_node_block_ptr.deref().as_slice(),
                u64::from(image_size).to_le_bytes().as_slice(),
                &auth_tree_extents,
                &allocation_bitmap_extents,
                &auth_context_subject_id_suffix,
            ])
            .map_infallible_err(),
        )?;

        h.finalize_into(dst)?;
        Ok(())
    }

    /// Get authentication tree's storage extents.
    pub fn get_auth_tree_extents(&self) -> &extents::LogicalExtents {
        &self.auth_tree_extents
    }

    /// Map a [`PhysicalAllocBlockIndex`](layout::PhysicalAllocBlockIndex) into
    /// the [Authentication Tree Data Block index
    /// domain](AuthTreeDataBlockIndex).
    ///
    /// Return the [`AuthTreeDataBlockIndex`] for the [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// containing the specified `physical_allocation_block_index`.
    ///
    /// # Arguments:
    ///
    /// * `physical_allocation_block_index` - The physical location to map into
    ///   the [Authentication Tree Data Block index
    ///   domain](AuthTreeDataBlockIndex). Must be strictly within the interior
    ///   of the authentication tree's covered data range.
    pub fn translate_physical_to_data_block_index(
        &self,
        physical_allocation_block_index: layout::PhysicalAllocBlockIndex,
    ) -> AuthTreeDataBlockIndex {
        let physical_data_block_allocation_blocks_begin =
            physical_allocation_block_index.align_down(self.data_block_allocation_blocks_log2 as u32);
        let physical_data_block_allocation_blocks_range = layout::PhysicalAllocBlockRange::from((
            physical_data_block_allocation_blocks_begin,
            layout::AllocBlockCount::from(1u64 << self.data_block_allocation_blocks_log2),
        ));
        AuthTreeDataBlockIndex::new_from_data_allocation_block_index(
            self.auth_tree_data_allocation_blocks_map
                .map_physical_to_data_allocation_blocks(&physical_data_block_allocation_blocks_range)
                .begin(),
            self.data_block_allocation_blocks_log2 as u32,
        )
    }

    /// Map a [`AuthTreeDataBlockIndex`] to the associated physical location.
    ///
    /// Return the [`PhysicalAllocBlockIndex`](layout::PhysicalAllocBlockIndex)
    /// of the first [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2) within the
    /// physical [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// associated with the specified `data_block_index`.
    ///
    /// # Arguments:
    ///
    /// * `data_block_index` - The [`AuthTreeDataBlockIndex`] to map to its
    ///   associated physical location. Must be within the bounds of the
    ///   authentication tree's covered data range (with that range's end being
    ///   inclusive).
    pub fn translate_data_block_index_to_physical(
        &self,
        data_block_index: AuthTreeDataBlockIndex,
    ) -> layout::PhysicalAllocBlockIndex {
        self.auth_tree_data_allocation_blocks_map
            .map_data_to_physical_allocation_block(AuthTreeDataAllocBlockIndex::new_from_data_block_index(
                data_block_index,
                self.data_block_allocation_blocks_log2 as u32,
            ))
    }

    /// Map a [`AuthTreeDataBlockRange`] to one or more associated physical
    /// regions.
    ///
    /// Note that while a single contiguous
    /// [`PhysicalAllocBlockRange`](layout::PhysicalAllocBlockRange) (not
    /// overlapping with any of the authentication tree's storage extents)
    /// always maps to a unique contiguous [`AuthTreeDataAllocBlockRange`],
    /// the converse is not true: a single contiguous
    /// [`AuthTreeDataAllocBlockRange`] or [`AuthTreeDataBlockRange`] can
    /// correspond to a sequence of more than one
    /// [`PhysicalAllocBlockRange`](layout::PhysicalAllocBlockRange), all
    /// interspersed with some authentication tree node storage extents on
    /// physical storage. That is, its mapping is piecewise linear and
    /// strictly monotonic increasing.
    ///
    /// Return an iterator over that mapping's linear pieces. More specifically,
    /// the iterator will yield pairs of [`AuthTreeDataAllocBlockRange`] and
    /// an associated
    /// [`PhysicalAllocBlockIndex`](layout::PhysicalAllocBlockIndex) each, where
    /// the former specifies an element of a `data_range` partition and the
    /// latter the beginning of the corresponding contiguous region on
    /// physical storage.
    ///
    /// `data_range` may extend into (or even be located entirely within) a
    /// region beyond the filesystem image's actual authenticated data
    /// range, but will be capped internally so that none of its (logically)
    /// associated
    /// [`PhysicalAllocBlockRange`](layout::PhysicalAllocBlockRange)s would ever
    /// exceed the upper bound of `u64::MAX` bytes converted to [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2).
    ///
    /// # Arguments:
    ///
    /// * `data_range` - The contiguous range in the [Authentication Tree Data
    ///   Block index domain](AuthTreeDataBlockIndex) to map to its associated
    ///   [`PhysicalAllocBlockRange`](layout::PhysicalAllocBlockRange)s.
    pub fn translate_data_block_range_to_physical(
        &self,
        data_range: &AuthTreeDataBlockRange,
    ) -> AuthTreeDataAllocationBlocksMapIterator<'_> {
        let data_allocation_blocks_range = AuthTreeDataAllocBlockRange::new(
            AuthTreeDataAllocBlockIndex::new_from_data_block_index(
                data_range.begin(),
                self.data_block_allocation_blocks_log2 as u32,
            ),
            AuthTreeDataAllocBlockIndex::new_from_data_block_index(
                data_range.end(),
                self.data_block_allocation_blocks_log2 as u32,
            ),
        );
        self.auth_tree_data_allocation_blocks_map
            .iter_data_range_mapping(&data_allocation_blocks_range)
    }

    /// Determine the leaf authentication tree node authenticating a given
    /// [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2).
    ///
    /// Return the [`AuthTreeNodeId`] identifying the leaf node storing the
    /// digest of the [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// specified by `data_block_index`.
    ///
    /// # Arguments:
    ///
    /// * `data_block_index` - The [Authentication Tree Data Block index domain
    ///   index](AuthTreeDataBlockIndex) of the [Authentication Tree Data
    ///   Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) to
    ///   determine the authenticating leaf node of. Must be strictly within the
    ///   interior of the authentication tree's covered data range.
    pub fn covering_leaf_node_id(&self, data_block_index: AuthTreeDataBlockIndex) -> AuthTreeNodeId {
        AuthTreeNodeId::new(
            data_block_index,
            0,
            self.node_digests_per_node_log2,
            self.data_digests_per_node_log2,
        )
    }

    /// Determine the storage location of a given authentication tree node.
    ///
    /// Determine the storage location within the filesystem image of the
    /// authentication tree node identified by `node_id`. Note that the
    /// resulting region's bounds are always aligned to the larger of
    /// the [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// or [IO Block](ImageLayout::io_block_allocation_blocks_log2)
    /// size.
    ///
    /// # Arguments:
    ///
    /// * `node_id` - The [`AuthTreeNodeId`] identifying the node whose storage
    ///   location to determine.
    fn node_io_region(&self, node_id: &AuthTreeNodeId) -> Result<chip::ChunkedIoRegion, NvFsError> {
        debug_assert!(node_id.level < self.auth_tree_levels);
        if u64::from(node_id.covered_data_blocks_begin) >= self.max_covered_data_block_count {
            return Err(CocoonFsFormatError::BlockOutOfRange.into());
        }
        let dfs_pre_node_index = auth_tree_node_dfs_pre_index(
            node_id.covered_data_blocks_begin,
            node_id.level,
            self.auth_tree_levels,
            self.node_digests_per_node_log2 as u32,
            self.node_digests_per_node_minus_one_inv_mod_u64,
            self.data_digests_per_node_log2 as u32,
        )
        .0;
        let logical_begin =
            layout::LogicalAllocBlockIndex::from(dfs_pre_node_index << self.node_allocation_blocks_log2);
        let logical_end = logical_begin + layout::AllocBlockCount::from(1u64 << self.node_allocation_blocks_log2);
        let logical_range = layout::LogicalAllocBlockRange::new(logical_begin, logical_end);
        let mut extents_range_iter = self
            .auth_tree_extents
            .iter_range(&logical_range)
            .ok_or_else(|| nvfs_err_internal!())?;
        let extent = extents_range_iter.next().ok_or_else(|| nvfs_err_internal!())?;
        if extents_range_iter.next().is_some() {
            return Err(nvfs_err_internal!());
        }
        let physical_range = extent.physical_range();
        chip::ChunkedIoRegion::new(
            u64::from(physical_range.begin()) << self.allocation_block_size_128b_log2,
            u64::from(physical_range.end()) << self.allocation_block_size_128b_log2,
            (self.node_allocation_blocks_log2 + self.allocation_block_size_128b_log2) as u32,
        )
        .map_err(|_| nvfs_err_internal!())
    }

    /// Get the size of an authentication tree node in units of bytes.
    fn node_size(&self) -> usize {
        1usize << (self.node_allocation_blocks_log2 + self.allocation_block_size_128b_log2 + 7)
    }

    /// Compute the authentication tree root digest into a preallocated buffer.
    ///
    /// # Arguments:
    ///
    /// * `root_hmac_digest_dst` - Buffer receiving the computed digest. Its
    ///   size must match the digest length of
    ///   [`root_hmac_hash_alg`](Self::root_hmac_hash_alg) exactly.
    /// * `root_node_id` - The [`AuthTreeNodeId`] identifying the tree's root
    ///   node.
    /// * `digest_entries_iterator` - [`Iterator`] over the digests stored in
    ///   the root node, any unused excess entries set to constant zero
    ///   included.
    fn hmac_root_node_into<'a, DEI: Iterator<Item = &'a [u8]>>(
        &self,
        root_hmac_digest_dst: &mut [u8],
        root_node_id: &AuthTreeNodeId,
        digest_entries_iterator: DEI,
    ) -> Result<(), NvFsError> {
        debug_assert_eq!(
            root_hmac_digest_dst.len(),
            hash::hash_alg_digest_len(self.root_hmac_hash_alg) as usize
        );
        let mut h = hash::HmacInstance::new(self.root_hmac_hash_alg, &self.root_hmac_key)?;
        for digest_entry in digest_entries_iterator {
            h.update(io_slices::SingletonIoSlice::new(digest_entry).map_infallible_err())?;
        }

        let auth_context_subject_id_suffix = [
            0u8, // Version of the authenticated data's format.
            AuthSubjectDataSuffix::AuthTreeRootNode as u8,
        ];
        // Note: this uniquely encodes the node's position within the tree. In
        // particular, it encodes the tree's depth. As an alternative, the tree
        // depth could get represented directly, but be consistent with how
        // internal nodes are getting authenticated.
        let node_id = u64::from(root_node_id.last_entry_covered_data_blocks_begin()).to_le_bytes();
        h.update(
            io_slices::BuffersSliceIoSlicesIter::new(&[
                node_id.as_slice(),
                self.image_context_digest.as_slice(),
                auth_context_subject_id_suffix.as_slice(),
            ])
            .map_infallible_err(),
        )?;
        h.finalize_into(root_hmac_digest_dst)?;
        Ok(())
    }

    /// Compute the authentication tree root digest into a newly allocated
    /// buffer.
    ///
    /// # Arguments:
    ///
    /// * `root_node_id` - The [`AuthTreeNodeId`] identifying the tree's root
    ///   node.
    /// * `digest_entries_iterator` - [`Iterator`] over the digests stored in
    ///   the root node, any unused excess entries set to constant zero
    ///   included.
    fn hmac_root_node<'a, DEI: Iterator<Item = &'a [u8]>>(
        &self,
        root_node_id: &AuthTreeNodeId,
        digest_entries_iterator: DEI,
    ) -> Result<zeroize::Zeroizing<FixedVec<u8, 5>>, NvFsError> {
        let root_hmac_digest_len = hash::hash_alg_digest_len(self.root_hmac_hash_alg) as usize;
        let mut root_hmac_digest = zeroize::Zeroizing::new(FixedVec::new_with_default(root_hmac_digest_len)?);
        self.hmac_root_node_into(&mut root_hmac_digest, root_node_id, digest_entries_iterator)?;
        Ok(root_hmac_digest)
    }

    /// Authenticate the tree root node's contents against an expected root
    /// digest.
    ///
    /// # Arguments:
    ///
    /// * `expected_root_hmac_digest` - Buffer containing the expected digest,
    ///   as usually stored in [`MutableImageHeader::root_hmac_digest`].  Its
    ///   size must match the digest length of
    ///   [`root_hmac_hash_alg`](Self::root_hmac_hash_alg) exactly.
    /// * `root_node_id` - The [`AuthTreeNodeId`] identifying the tree's root
    ///   node.
    /// * `node_data` - Buffer containing the raw root node data to get
    ///   authenticated. Must be exactly [`node_size()`](Self::node_size) in
    ///   length.
    fn authenticate_root_node(
        &self,
        expected_root_hmac_digest: &[u8],
        root_node_id: &AuthTreeNodeId,
        node_data: &[u8],
    ) -> Result<(), NvFsError> {
        debug_assert_eq!(
            expected_root_hmac_digest.len(),
            hash::hash_alg_digest_len(self.root_hmac_hash_alg) as usize
        );
        let (digest_entry_len, digest_entries_in_node_log2) = if root_node_id.level > 0 {
            (self.node_digest_len as usize, self.node_digests_per_node_log2)
        } else {
            (self.data_digest_len as usize, self.data_digests_per_node_log2)
        };
        debug_assert!(node_data.len() >= digest_entry_len << digest_entries_in_node_log2);
        let root_hmac_digest = self.hmac_root_node(
            root_node_id,
            node_data
                .chunks_exact(digest_entry_len)
                .take(1usize << digest_entries_in_node_log2),
        )?;
        if ct_cmp::ct_bytes_eq(&root_hmac_digest, expected_root_hmac_digest).unwrap() != 0 {
            Ok(())
        } else {
            Err(NvFsError::AuthenticationFailure)
        }
    }

    /// Compute the digest over a non-root authentication tree node into a
    /// preallocated buffer.
    ///
    /// # Arguments:
    ///
    /// * `node_digest_dst` - Buffer receiving the computed digest. Its size
    ///   must match the digest length of [`node_hash_alg`](Self::node_hash_alg)
    ///   exactly.
    /// * `node_id` - The [`AuthTreeNodeId`] identifying the to be digested
    ///   node.
    /// * `digest_entries_iterator` - [`Iterator`] over the digests stored in
    ///   the node, any unused excess entries set to constant zero included.
    fn digest_descendant_node_into<'a, DEI: Iterator<Item = &'a [u8]>>(
        &self,
        node_digest_dst: &mut [u8],
        node_id: &AuthTreeNodeId,
        digest_entries_iterator: DEI,
    ) -> Result<(), NvFsError> {
        debug_assert_eq!(node_digest_dst.len(), self.node_digest_len as usize);
        let mut h = hash::HashInstance::new(self.node_hash_alg)?;
        for digest_entry in digest_entries_iterator {
            h.update(io_slices::SingletonIoSlice::new(digest_entry).map_infallible_err())?;
        }

        let auth_context_subject_id_suffix = [
            0u8, // Version of the authenticated data's format.
            AuthSubjectDataSuffix::AuthTreeDescendantNode as u8,
        ];
        // Note: this uniquely encodes the node's position within the tree.
        let node_id = u64::from(node_id.last_entry_covered_data_blocks_begin()).to_le_bytes();
        h.update(
            io_slices::BuffersSliceIoSlicesIter::new(&[node_id.as_slice(), auth_context_subject_id_suffix.as_slice()])
                .map_infallible_err(),
        )?;

        h.finalize_into(node_digest_dst)?;
        Ok(())
    }

    /// Compute the digest over a non-root authentication tree node into a newly
    /// allocated buffer.
    ///
    /// # Arguments:
    ///
    /// * `node_id` - The [`AuthTreeNodeId`] identifying the to be digested
    ///   node.
    /// * `digest_entries_iterator` - [`Iterator`] over the digests stored in
    ///   the node, any unused excess entries set to constant zero included.
    fn digest_descendant_node<'a, DEI: Iterator<Item = &'a [u8]>>(
        &self,
        node_id: &AuthTreeNodeId,
        digest_entries_iterator: DEI,
    ) -> Result<FixedVec<u8, 5>, NvFsError> {
        let node_digest_len = self.node_digest_len as usize;
        let mut node_digest = FixedVec::new_with_default(node_digest_len)?;
        self.digest_descendant_node_into(&mut node_digest, node_id, digest_entries_iterator)?;
        Ok(node_digest)
    }

    /// Authenticate a non-root node's contents against an expected node
    /// digest.
    ///
    /// # Arguments:
    ///
    /// * `expected_node_digest` - Buffer containing the node's expected digest,
    ///   as usually found in its (already authenticated) parent node. Its size
    ///   must match the digest length of [`node_hash_alg`](Self::node_hash_alg)
    ///   exactly.
    /// * `node_id` - The [`AuthTreeNodeId`] identifying the to be authenticated
    ///   node.
    /// * `node_data` - Buffer containing the raw node data to get
    ///   authenticated. Must be exactly [`node_size()`](Self::node_size) in
    ///   length.
    fn authenticate_descendant_node(
        &self,
        expected_node_digest: &[u8],
        node_id: &AuthTreeNodeId,
        node_data: &[u8],
    ) -> Result<(), NvFsError> {
        debug_assert_eq!(expected_node_digest.len(), self.node_digest_len as usize);

        let (digest_entry_len, digest_entries_in_node_log2) = if node_id.level != 0 {
            (self.node_digest_len as usize, self.node_digests_per_node_log2)
        } else {
            (self.data_digest_len as usize, self.data_digests_per_node_log2)
        };
        debug_assert!(node_data.len() >= digest_entry_len << self.node_digests_per_node_log2);
        let node_digest = self.digest_descendant_node(
            node_id,
            node_data
                .chunks_exact(digest_entry_len)
                .take(1usize << digest_entries_in_node_log2),
        )?;
        if ct_cmp::ct_bytes_eq(&node_digest, expected_node_digest).unwrap() != 0 {
            Ok(())
        } else {
            Err(NvFsError::AuthenticationFailure)
        }
    }

    /// Compute a digest over an [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// into a newly allocated buffer.
    ///
    /// # Arguments:
    ///
    /// * `data_block_index` - The [Authentication Tree Data Block index domain
    ///   index](AuthTreeDataBlockIndex) of the to be digested [Authentication
    ///   Tree Data Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2).
    /// * `data_block_allocation_blocks_iter` - [`Iterator`] over the the
    ///   [Authentication Tree Data
    ///   Block's](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    ///   individual [Allocation
    ///   Blocks](ImageLayout::allocation_block_size_128b_log2). The iterator
    ///   must yield one entry for each of the [Allocation
    ///   Blocks](ImageLayout::allocation_block_size_128b_log2) as follows:
    ///
    ///   * `Err(e)` - The iterator's implementation encountered some error `e`.
    ///     The iteration will be cancelled at this point and the error `e`
    ///     propagated back.
    ///   * `Ok(allocation_block_data)`, with `allocation_block_data` either
    ///      * `None` if the [Allocation
    ///        Block](ImageLayout::allocation_block_size_128b_log2) is
    ///        unallocated or
    ///      * a buffer containing the [Allocation
    ///        Block's](ImageLayout::allocation_block_size_128b_log2) data
    ///        wrapped in a `Some`.
    /// * `image_header_end` - [End of the filesystem image header on
    ///   storage](MutableImageHeader::physical_location).
    ///
    /// # See also:
    ///
    /// * [`AuthTreeDigestDataBlockContext`].
    pub fn digest_data_block<'a, ABI: Iterator<Item = Result<Option<&'a [u8]>, NvFsError>>>(
        &self,
        data_block_index: AuthTreeDataBlockIndex,
        mut data_block_allocation_blocks_iter: ABI,
        image_header_end: layout::PhysicalAllocBlockIndex,
    ) -> Result<FixedVec<u8, 5>, NvFsError> {
        let data_digest_len = self.data_digest_len as usize;
        let mut data_block_digest = FixedVec::new_with_default(data_digest_len)?;

        let mut digest_data_block_context = AuthTreeDigestDataBlockContext::new(
            hash::HmacInstance::new(self.data_hmac_hash_alg, &self.data_hmac_key)?,
            self.data_block_allocation_blocks_log2,
            self.allocation_block_size_128b_log2,
        );

        // The image header's Allocation Blocks don't get authenticated. Enforce this.
        // Note that for the image header, the mapping from physical to logical
        // Authentication Tree Data Block is 1:1.
        if u64::from(image_header_end) > u64::from(data_block_index) << self.data_block_allocation_blocks_log2 {
            for _ in 0..(u64::from(image_header_end)
                - (u64::from(data_block_index) << self.data_block_allocation_blocks_log2))
                .min(1u64 << self.data_block_allocation_blocks_log2)
            {
                // Consume whatever the Iterator over the Authentication Tree Data Block's
                // Allocation Blocks returns.
                match data_block_allocation_blocks_iter.next() {
                    Some(Ok(_)) => (),
                    Some(Err(e)) => return Err(e),
                    None => return Err(nvfs_err_internal!()),
                }
                digest_data_block_context.update(None)?;
            }
        }

        for allocation_block in data_block_allocation_blocks_iter {
            match allocation_block {
                Ok(allocation_block) => {
                    digest_data_block_context.update(allocation_block)?;
                }
                Err(e) => return Err(e),
            }
        }

        digest_data_block_context.finalize_into(&mut data_block_digest, data_block_index)?;

        Ok(data_block_digest)
    }

    /// Authenticate an [Authentication Tree Data
    /// Block's](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// contents against an expected digest.
    ///
    /// # Arguments:
    ///
    /// * `expected_data_block_digest` - The expected [Authentication Tree Data
    ///   Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    ///   digest. Its length must match the
    ///   [`data_hmac_hash_alg`](Self::data_hmac_hash_alg) digest length
    ///   exactly.
    /// * `data_block_index` - The [Authentication Tree Data Block index domain
    ///   index](AuthTreeDataBlockIndex) of the to be digested [Authentication
    ///   Tree Data Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2).
    /// * `data_block_allocation_blocks_iter` - [`Iterator`] over the the
    ///   [Authentication Tree Data
    ///   Block's](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    ///   individual [Allocation
    ///   Blocks](ImageLayout::allocation_block_size_128b_log2). The iterator
    ///   must yield one entry for each of the [Allocation
    ///   Blocks](ImageLayout::allocation_block_size_128b_log2) as follows:
    ///
    ///   * `Err(e)` - The iterator's implementation encountered some error `e`.
    ///     The iteration will be cancelled at this point and the error `e`
    ///     propagated back.
    ///   * `Ok(allocation_block_data)`, with `allocation_block_data` either
    ///      * `None` if the [Allocation
    ///        Block](ImageLayout::allocation_block_size_128b_log2) is
    ///        unallocated or
    ///      * a buffer containing the [Allocation
    ///        Block's](ImageLayout::allocation_block_size_128b_log2) data
    ///        wrapped in a `Some`.
    /// * `image_header_end` - [End of the filesystem image header on
    ///   storage](MutableImageHeader::physical_location).
    pub fn authenticate_data_block<'a, ABI: Iterator<Item = Result<Option<&'a [u8]>, NvFsError>>>(
        &self,
        expected_data_block_digest: &[u8],
        data_block_index: AuthTreeDataBlockIndex,
        data_block_allocation_blocks_iter: ABI,
        image_header_end: layout::PhysicalAllocBlockIndex,
    ) -> Result<(), NvFsError> {
        debug_assert_eq!(expected_data_block_digest.len(), self.data_digest_len as usize);
        let data_block_digest =
            self.digest_data_block(data_block_index, data_block_allocation_blocks_iter, image_header_end)?;
        if ct_cmp::ct_bytes_eq(&data_block_digest, expected_data_block_digest).unwrap() != 0 {
            Ok(())
        } else {
            Err(NvFsError::AuthenticationFailure)
        }
    }

    /// Access a given [Authentication Tree Data
    /// Block's](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// digest stored in its authenticating leaf node.
    ///
    /// # Arguments
    ///
    /// * `leaf_node` - [`AuthTreeNodeCache`] entry storing the leaf node
    ///   covering the [Authentication Tree Data
    ///   Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    ///   identified by `data_block_index`.
    /// * `data_block_index` - Index in the [Authentication Tree Data Block
    ///   index domain](AuthTreeDataBlockIndex) of the [Authentication Tree Data
    ///   Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) to
    ///   access the associated digest of.
    pub fn get_data_block_digest_entry_from_tree<'a, 'b, ST: sync_types::SyncTypes>(
        &self,
        leaf_node: &'a AuthTreeNodeCacheEntryRef<'b, ST>,
        data_block_index: AuthTreeDataBlockIndex,
    ) -> Result<&'a [u8], NvFsError> {
        let leaf_node_id = leaf_node.get_node_id();
        if leaf_node_id
            != &AuthTreeNodeId::new(
                data_block_index,
                0,
                self.node_digests_per_node_log2,
                self.data_digests_per_node_log2,
            )
        {
            return Err(nvfs_err_internal!());
        }
        let data_block_entry_in_leaf_node =
            (u64::from(data_block_index) & u64::trailing_bits_mask(self.data_digests_per_node_log2 as u32)) as usize;
        Ok(leaf_node.get_digest(data_block_entry_in_leaf_node, self.data_digest_len as usize))
    }

    /// Authenticate an [Authentication Tree Data Block index
    /// domain](AuthTreeDataAllocBlockIndex) against the digest
    /// stored in its (already authenticated) covering leaf node.
    ///
    /// # Arguments
    ///
    /// * `leaf_node` - [`AuthTreeNodeCache`] entry storing the leaf node
    ///   covering the [Authentication Tree Data
    ///   Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    ///   identified by `data_block_index`.
    /// * `data_block_index` - Index in the [Authentication Tree Data Block
    ///   index domain](AuthTreeDataBlockIndex) of the to be authenticated
    ///   [Authentication Tree Data
    ///   Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2).
    /// * `data_block_allocation_blocks_iter` - [`Iterator`] over the the
    ///   [Authentication Tree Data
    ///   Block's](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    ///   individual [Allocation
    ///   Blocks](ImageLayout::allocation_block_size_128b_log2). The iterator
    ///   must yield one entry for each of the [Allocation
    ///   Blocks](ImageLayout::allocation_block_size_128b_log2) as follows:
    ///
    ///   * `Err(e)` - The iterator's implementation encountered some error `e`.
    ///     The iteration will be cancelled at this point and the error `e`
    ///     propagated back.
    ///   * `Ok(allocation_block_data)`, with `allocation_block_data` either
    ///      * `None` if the [Allocation
    ///        Block](ImageLayout::allocation_block_size_128b_log2) is to be
    ///        considered unallocated for the authentication or
    ///      * a buffer containing the [Allocation
    ///        Block's](ImageLayout::allocation_block_size_128b_log2) to be
    ///        authenticated data wrapped in a `Some`.
    /// * `image_header_end` - [End of the filesystem image header on
    ///   storage](MutableImageHeader::physical_location).
    pub fn authenticate_data_block_from_tree<
        'a,
        ST: sync_types::SyncTypes,
        ABI: Iterator<Item = Result<Option<&'a [u8]>, NvFsError>>,
    >(
        &self,
        leaf_node: &AuthTreeNodeCacheEntryRef<'_, ST>,
        data_block_index: AuthTreeDataBlockIndex,
        data_block_allocation_blocks_iter: ABI,
        image_header_end: layout::PhysicalAllocBlockIndex,
    ) -> Result<(), NvFsError> {
        let leaf_node_id = leaf_node.get_node_id();
        if leaf_node_id
            != &AuthTreeNodeId::new(
                data_block_index,
                0,
                self.node_digests_per_node_log2,
                self.data_digests_per_node_log2,
            )
        {
            return Err(nvfs_err_internal!());
        }
        let expected_data_block_digest = self.get_data_block_digest_entry_from_tree(leaf_node, data_block_index)?;
        self.authenticate_data_block(
            expected_data_block_digest,
            data_block_index,
            data_block_allocation_blocks_iter,
            image_header_end,
        )
    }

    /// Determine the number of [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// authenticated by a single authentication tree leaf node.
    pub fn covered_data_blocks_per_leaf_node_log2(&self) -> u8 {
        self.data_digests_per_node_log2
    }
}

/// Compute a digest over an [Authentication Tree Data
/// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
/// incrementally.
///
/// When not all of an [Authentication Tree Data
/// Block's](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
/// data is available at once, `AuthTreeDigestDataBlockContext` may be used to
/// compute its digest incrementally.  Users are supposed to call
/// [`update()`](Self::update) for each of the [Authentication Tree Data
/// Block's](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
/// [Allocation Blocks](ImageLayout::allocation_block_size_128b_log2),
/// allocated or not, and eventually
/// invoke [`finalize_into()`](Self::finalize_into) to obtain the digest.
struct AuthTreeDigestDataBlockContext {
    /// A [`HmacInstance`](hash::HmacInstance) instantiated
    /// with [`data_hmac_hash_alg`](AuthTreeConfig::data_hmac_hash_alg)
    /// and the [`data_hmac_key`](AuthTreeConfig::data_hmac_key) to be used for
    /// digesting [Authentication Tree
    /// Data Blocks](ImageLayout::auth_tree_data_block_allocation_blocks_log2).
    data_block_hmac_instance: hash::HmacInstance,
    /// Bitmap tracking which of the [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2) in the
    /// to be digested [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// are considered allocated.
    data_block_alloc_bitmap: u64,
    /// Current position within the [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// being digested in units of [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2).
    allocation_block_in_data_block_index: u32,
    /// Verbatim copy of [`AuthTreeConfig::data_block_allocation_blocks_log2`].
    data_block_allocation_blocks_log2: u8,
    /// Verbatim copy of [`ImageLayout::allocation_block_size_128b_log2`].
    allocation_block_size_128b_log2: u8,
}

impl AuthTreeDigestDataBlockContext {
    /// Instantiate a new [`AuthTreeDigestDataBlockContext`].
    ///
    /// # Arguments:
    ///
    /// * `data_block_hmac_instance` - A [`HmacInstance`](hash::HmacInstance)
    ///   instantiated with
    ///   [`data_hmac_hash_alg`](AuthTreeConfig::data_hmac_hash_alg) and the
    ///   [`data_hmac_key`](AuthTreeConfig::data_hmac_key) to be used for
    ///   digesting [Authentication Tree
    /// * `data_block_allocation_blocks_log2` - Verbatim copy of
    ///   [`AuthTreeConfig::data_block_allocation_blocks_log2`].
    /// * `allocation_block_size_128b_log2` - Verbatim copy of
    ///   [`ImageLayout::allocation_block_size_128b_log2`].
    fn new(
        data_block_hmac_instance: hash::HmacInstance,
        data_block_allocation_blocks_log2: u8,
        allocation_block_size_128b_log2: u8,
    ) -> Self {
        Self {
            data_block_hmac_instance,
            data_block_alloc_bitmap: 0,
            allocation_block_in_data_block_index: 0,
            data_block_allocation_blocks_log2,
            allocation_block_size_128b_log2,
        }
    }

    /// Update the [`AuthTreeDigestDataBlockContext`] with the [Authentication
    /// Tree Data
    /// Block's](ImageLayout::auth_tree_data_block_allocation_blocks_log2) next
    /// [Allocation Block's](ImageLayout::allocation_block_size_128b_log2)
    /// data.
    ///
    /// Must get invoked for each of the [Authentication Tree Data
    /// Block's](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// individual [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2) before
    /// [`finalize_into()`](Self::finalize_into) may eventually get invoked.
    ///
    /// # Arguments:
    ///
    /// * `allocation_block_data` - either
    ///   * `None` if the [Allocation
    ///     Block](ImageLayout::allocation_block_size_128b_log2) is unallocated
    ///     or
    ///   * a buffer containing the [Allocation
    ///     Block's](ImageLayout::allocation_block_size_128b_log2) data wrapped
    ///     in a `Some`.
    fn update(&mut self, allocation_block_data: Option<&[u8]>) -> Result<(), NvFsError> {
        // As per AuthTreeConfig::new() it is known that the number of Allocation Blocks
        // in an Authentication Tree Data Block is <= 64, so the shift is
        // well-defined.
        if self.allocation_block_in_data_block_index >> (self.data_block_allocation_blocks_log2 as u32) != 0 {
            return Err(nvfs_err_internal!());
        }
        if let Some(allocation_block_data) = allocation_block_data {
            if allocation_block_data.len() != 1usize << (self.allocation_block_size_128b_log2 + 7) {
                return Err(nvfs_err_internal!());
            }
            self.data_block_hmac_instance
                .update(io_slices::SingletonIoSlice::new(allocation_block_data).map_infallible_err())?;
            self.data_block_alloc_bitmap |= 1u64 << self.allocation_block_in_data_block_index;
        }
        self.allocation_block_in_data_block_index += 1;
        Ok(())
    }

    /// Obtain the final [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// digest.
    ///
    /// Must get invoked only after [`update()`](Self::update) had been called
    /// on each of the [Authentication Tree Data
    /// Block's](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// individual [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2).
    ///
    /// # Arguments:
    ///
    /// * `data_block_digest` - Destination buffer receiving the digest. Its
    ///   size must match the
    ///   [`data_hmac_hash_alg`](AuthTreeConfig::data_hmac_hash_alg) digest
    ///   length exactly.
    /// * `data_block_index` - The [Authentication Tree Data Block index domain
    ///   index](AuthTreeDataBlockIndex) of the [Authentication Tree Data
    ///   Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) being
    ///   digested.
    fn finalize_into(
        mut self,
        data_block_digest: &mut [u8],
        data_block_index: AuthTreeDataBlockIndex,
    ) -> Result<(), NvFsError> {
        debug_assert_eq!(data_block_digest.len(), self.data_block_hmac_instance.digest_len());

        // As per AuthTreeConfig::new() it is known that the number of Allocation Blocks
        // in an Authentication Tree Data Block is <= 64, so the shift is
        // well-defined.
        if self.allocation_block_in_data_block_index != (1u32 << (self.data_block_allocation_blocks_log2 as u32)) {
            return Err(nvfs_err_internal!());
        }

        let auth_context_subject_id_suffix = [
            0u8, // Version of the authenticated data's format.
            AuthSubjectDataSuffix::AuthTreeDataBlock as u8,
        ];
        self.data_block_hmac_instance.update(
            io_slices::BuffersSliceIoSlicesIter::new(&[
                self.data_block_alloc_bitmap.to_le_bytes().as_slice(),
                u64::from(data_block_index).to_le_bytes().as_slice(),
                auth_context_subject_id_suffix.as_slice(),
            ])
            .map_infallible_err(),
        )?;
        self.data_block_hmac_instance.finalize_into(data_block_digest)?;
        Ok(())
    }
}

/// A filesystem's fully operational authentication tree.
pub struct AuthTree<ST: sync_types::SyncTypes> {
    config: AuthTreeConfig,
    root_hmac_digest: FixedVec<u8, 5>,
    node_cache: ST::RwLock<AuthTreeNodeCache>,
}

impl<ST: sync_types::SyncTypes> AuthTree<ST> {
    /// Instantiate a new [`AuthTree`] instance.
    ///
    /// # Arguments:
    ///
    /// * `root_key` - The filesystem's root key.
    /// * `image_layout` - The filesystem's [`ImageLayout`].
    /// * `inode_index_entry_leaf_node_block_ptr` -  The inode index entry leaf
    ///   node pointer as found in the filesystem's
    ///   [`MutableImageHeader::inode_index_entry_leaf_node_block_ptr`].
    /// * `image_size` - The filesystem image size as found in the filesystem's
    ///   [`MutableImageHeader::image_size`].
    /// * `auth_tree_extents` - Storage extents of the authentication tree.
    /// * `allocation_bitmap_extents` - Storage extents of the allocation bitmap
    ///   file.
    /// * `root_hmac_digest` - The filesystem's root digest, as found in
    ///   [`MutableImageHeader::root_hmac_digest`].
    pub fn new(
        root_key: &keys::RootKey,
        image_layout: &layout::ImageLayout,
        inode_index_entry_leaf_node_block_ptr: &extent_ptr::EncodedBlockPtr,
        image_size: layout::AllocBlockCount,
        auth_tree_extents: extents::LogicalExtents,
        allocation_bitmap_extents: &extents::PhysicalExtents,
        root_hmac_digest: FixedVec<u8, 5>,
    ) -> Result<Self, NvFsError> {
        let config = AuthTreeConfig::new(
            root_key,
            image_layout,
            inode_index_entry_leaf_node_block_ptr,
            image_size,
            auth_tree_extents,
            allocation_bitmap_extents,
        )?;
        if root_hmac_digest.len() != hash::hash_alg_digest_len(config.root_hmac_hash_alg) as usize {
            return Err(CocoonFsFormatError::InvalidDigestLength.into());
        }

        let node_cache = ST::RwLock::from(AuthTreeNodeCache::new(&config)?);

        Ok(Self {
            config,
            root_hmac_digest,
            node_cache,
        })
    }

    /// Instantiate a [`AuthTree`] from its parts.
    ///
    /// # Arguments:
    ///
    /// * `config` - The [`AuthTree`]'s assoicated [`AuthTreeConfig`].
    /// * `root_hmac_digest` - The filesystem's root digest, as found in
    ///   [`MutableImageHeader::root_hmac_digest`].
    /// * `node_cache` - The authentication tree node cached, possibly
    ///   containing some (authenticated) nodes already.
    pub fn new_from_parts(
        config: AuthTreeConfig,
        root_hmac_digest: FixedVec<u8, 5>,
        node_cache: AuthTreeNodeCache,
    ) -> Self {
        Self {
            config,
            root_hmac_digest,
            node_cache: ST::RwLock::from(node_cache),
        }
    }

    /// Access the [`AuthTreeConfig`].
    pub fn get_config(&self) -> &AuthTreeConfig {
        &self.config
    }

    /// Access the authentication tree's current root HMAC digest.
    pub fn get_root_hmac_digest(&self) -> &[u8] {
        &self.root_hmac_digest
    }

    /// Clear all caches.
    pub fn clear_caches(&self) {
        self.node_cache.write().clear();
    }
}

/// Multiplexer for shared or `mut` [`AuthTree`] references.
///
/// Whenever a caller of the authentication tree related APIs is capable of
/// providing an exclusive `mut` [`AuthTree`] reference, e.g. at transaction
/// commit time, taking certain internal locks can be avoided as an
/// optimization.
///
/// In order to support either case through common interfaces, define
/// [`AuthTreeRef`] as a wrapper to either shared or `mut` [`AuthTree`]
/// references.
pub enum AuthTreeRef<'a, ST: sync_types::SyncTypes> {
    /// Shared reference to an [`AuthTree`].
    Ref { tree: &'a AuthTree<ST> },
    /// Exclusive reference to an [`AuthTree`].
    MutRef { tree: &'a mut AuthTree<ST> },
}

impl<'a, ST: sync_types::SyncTypes> AuthTreeRef<'a, ST> {
    /// Reborrow the reference.
    ///
    /// [`AuthTreeRef`] is not covariant over its lifetime parameter.
    /// `make_borrow()` enables reborrowing with a shorter lifetime if
    /// needed.
    #[allow(dead_code)]
    fn make_borrow(&mut self) -> AuthTreeRef<'_, ST> {
        match self {
            Self::Ref { tree } => AuthTreeRef::Ref { tree },
            Self::MutRef { tree } => AuthTreeRef::MutRef { tree },
        }
    }

    /// Destructure into references to the [`AuthTree`]'s constituent
    /// components.
    pub fn destructure_borrow<'b>(&'b mut self) -> (&'b AuthTreeConfig, &'b [u8], AuthTreeNodeCacheRef<'b, ST>) {
        match self {
            Self::Ref { tree } => (
                &tree.config,
                &tree.root_hmac_digest,
                AuthTreeNodeCacheRef::Ref {
                    cache: &tree.node_cache,
                },
            ),
            Self::MutRef { tree } => (
                &tree.config,
                &tree.root_hmac_digest,
                AuthTreeNodeCacheRef::MutRef {
                    cache: tree.node_cache.get_mut(),
                },
            ),
        }
    }
}

impl<'a, ST: sync_types::SyncTypes> ops::Deref for AuthTreeRef<'a, ST> {
    type Target = AuthTree<ST>;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Ref { tree } => tree,
            Self::MutRef { tree } => tree,
        }
    }
}

/// A path from some node in the tree to the root.
#[derive(Clone, Copy)]
struct AuthTreeRootPath {
    /// The [`AuthTreeNodeId`] of the path's start node.
    node_id: AuthTreeNodeId,
    /// Verbatim copy of [`AuthTreeConfig::auth_tree_levels`].
    auth_tree_levels: u8,
    /// Verbatim copy of [`AuthTreeConfig::node_digests_per_node_log2`].
    node_digests_per_node_log2: u8,
    /// Verbatim copy of [`AuthTreeConfig::data_digests_per_node_log2`].
    data_digests_per_node_log2: u8,
}

impl AuthTreeRootPath {
    /// Instantiate a new [`AuthTreeRootPath`].
    ///
    /// # Arguments:
    ///
    /// * `node_id` - The [`AuthTreeNodeId`] of the path's start node.
    /// * `tree_config` - The filesystem's [`AuthTreeConfig`].
    fn new(node_id: AuthTreeNodeId, tree_config: &AuthTreeConfig) -> Self {
        Self {
            node_id,
            auth_tree_levels: tree_config.auth_tree_levels,
            node_digests_per_node_log2: tree_config.node_digests_per_node_log2,
            data_digests_per_node_log2: tree_config.data_digests_per_node_log2,
        }
    }

    /// Iterate over nodes on the path, from the start node to the root.
    fn iter(&self) -> AuthTreePathNodesIterator<'_> {
        AuthTreePathNodesIterator {
            path: self,
            level: self.node_id.level,
        }
    }
}

/// [`Iterator`] returned by [`AuthTreeRootPath::iter()`].
#[derive(Clone, Copy)]
struct AuthTreePathNodesIterator<'a> {
    path: &'a AuthTreeRootPath,
    level: u8,
}

impl<'a> Iterator for AuthTreePathNodesIterator<'a> {
    type Item = AuthTreeNodeId;

    fn next(&mut self) -> Option<Self::Item> {
        if self.level == self.path.auth_tree_levels {
            return None;
        }
        let level = self.level;
        self.level += 1;

        Some(AuthTreeNodeId::new(
            self.path.node_id.covered_data_blocks_begin,
            level,
            self.path.node_digests_per_node_log2,
            self.path.data_digests_per_node_log2,
        ))
    }
}

/// Read an authentication tree node from storage.
struct AuthTreeNodeReadFuture<C: chip::NvChip> {
    read_fut: C::ReadFuture<AuthTreeNodeReadNvChipRequest>,
}

impl<C: chip::NvChip> AuthTreeNodeReadFuture<C> {
    /// Instantiate an [`AuthTreeNodeReadFuture`].
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `tree_config` - The filesystem's [`AuthTreeConfig`].
    /// * `node_id` - The [`AuthTreeNodeId`] identifying the node to read.
    fn new(chip: &C, tree_config: &AuthTreeConfig, node_id: &AuthTreeNodeId) -> Result<Self, NvFsError> {
        Self::new_with_buf(chip, tree_config, node_id, FixedVec::new_empty())
    }

    /// Instantiate an [`AuthTreeNodeReadFuture`] with destination buffer
    /// recycling.
    ///
    /// May be used instead of [`new()`](Self::new) if a buffer is already
    /// available to save some allocations.
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `tree_config` - The filesystem's [`AuthTreeConfig`].
    /// * `node_id` - The [`AuthTreeNodeId`] identifying the node to read.
    /// * `dst_buf` - The node data destination buffer to get repurposed.
    fn new_with_buf(
        chip: &C,
        tree_config: &AuthTreeConfig,
        node_id: &AuthTreeNodeId,
        mut dst_buf: FixedVec<u8, 7>,
    ) -> Result<Self, NvFsError> {
        let node_size = tree_config.node_size();
        if dst_buf.len() != node_size {
            dst_buf = FixedVec::new_with_default(node_size)?;
        }

        let io_region = tree_config.node_io_region(node_id)?;
        let request = AuthTreeNodeReadNvChipRequest { dst_buf, io_region };
        let read_fut = chip
            .read(request)
            .and_then(|r| r.map_err(|(_, e)| e))
            .map_err(NvFsError::from)?;
        Ok(Self { read_fut })
    }
}

impl<C: chip::NvChip> chip::NvChipFuture<C> for AuthTreeNodeReadFuture<C> {
    type Output = Result<FixedVec<u8, 7>, NvFsError>;

    fn poll(self: pin::Pin<&mut Self>, chip: &C, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        match chip::NvChipFuture::poll(pin::Pin::new(&mut this.read_fut), chip, cx) {
            task::Poll::Ready(Ok((request, Ok(())))) => {
                let AuthTreeNodeReadNvChipRequest { dst_buf, .. } = request;
                task::Poll::Ready(Ok(dst_buf))
            }
            task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => task::Poll::Ready(Err(NvFsError::from(e))),
            task::Poll::Pending => task::Poll::Pending,
        }
    }
}

/// [`NvChipReadRequest`](chip::NvChipReadRequest) implementation used
/// internally by [`AuthTreeNodeReadFuture`].
struct AuthTreeNodeReadNvChipRequest {
    dst_buf: FixedVec<u8, 7>,
    io_region: chip::ChunkedIoRegion,
}

impl chip::NvChipReadRequest for AuthTreeNodeReadNvChipRequest {
    fn region(&self) -> &chip::ChunkedIoRegion {
        &self.io_region
    }

    fn get_destination_buffer(
        &mut self,
        range: &chip::ChunkedIoRegionChunkRange,
    ) -> Result<Option<&mut [u8]>, chip::NvChipIoError> {
        debug_assert_eq!(range.chunk().decompose_to_hierarchic_indices::<0>([]).0, 0);
        Ok(Some(&mut self.dst_buf[range.range_in_chunk().clone()]))
    }
}

/// Write an authentication tree node to storage.
struct AuthTreeNodeWriteFuture<C: chip::NvChip> {
    write_fut: C::WriteFuture<AuthTreeNodeWriteNvChipRequest>,
}

impl<C: chip::NvChip> AuthTreeNodeWriteFuture<C> {
    /// Instantiate an [`AuthTreeNodeWriteFuture`].
    ///
    /// The [`AuthTreeNodeWriteFuture`] assumes ownership of the `src_buf` for
    /// the duration of the write operation, and eventually returns it back
    /// upon [future](chip::NvChipFuture) completion.
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `tree_config` - The filesystem's [`AuthTreeConfig`].
    /// * `node_id` - The [`AuthTreeNodeId`] identifying the node to write.
    /// * `src_buf` - The node data to get written. Its length must match the
    ///   [`node size`](AuthTreeConfig::node_size) exactly. Returned back from
    ///   [`poll()`](Self::poll) upon future completion.
    fn new(
        chip: &C,
        tree_config: &AuthTreeConfig,
        node_id: &AuthTreeNodeId,
        src_buf: FixedVec<u8, 7>,
    ) -> Result<Result<Self, (FixedVec<u8, 7>, NvFsError)>, NvFsError> {
        if src_buf.len() != tree_config.node_size() {
            return Err(nvfs_err_internal!());
        }

        let io_region = tree_config.node_io_region(node_id)?;
        let request = AuthTreeNodeWriteNvChipRequest { src_buf, io_region };
        let write_fut = match chip.write(request).map_err(NvFsError::from)? {
            Ok(write_fut) => write_fut,
            Err((request, e)) => return Ok(Err((request.src_buf, NvFsError::from(e)))),
        };
        Ok(Ok(Self { write_fut }))
    }
}

impl<C: chip::NvChip> chip::NvChipFuture<C> for AuthTreeNodeWriteFuture<C> {
    /// Output type of [`poll()`](Self::poll).
    ///
    /// A two-level [`Result`] is returned upon [future](chip::NvChipFuture)
    /// completion.
    /// * `Err(e)` -  The outer level [`Result`] is set to [`Err`] upon
    ///   encountering an internal error causing the input buffer to get lost.
    /// * `Ok((src_buf, ...))` - Otherwise the outer level [`Result`] is set to
    ///   [`Ok`] and a pair of the input `src_buf` and the operation result will
    ///   get returned within:
    ///     * `Ok((`src_buf`, Err(e)))` - In case of an error, the error reason
    ///       `e` is returned in an [`Err`].
    ///     * `Ok((`src_buf`, Ok(())))` - Otherwise, `Ok(())` will get returned
    ///       for the operation result on success.
    type Output = Result<(FixedVec<u8, 7>, Result<(), NvFsError>), NvFsError>;

    fn poll(self: pin::Pin<&mut Self>, chip: &C, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        match chip::NvChipFuture::poll(pin::Pin::new(&mut this.write_fut), chip, cx) {
            task::Poll::Ready(Ok((request, result))) => {
                let AuthTreeNodeWriteNvChipRequest { src_buf, .. } = request;
                task::Poll::Ready(Ok((src_buf, result.map_err(NvFsError::from))))
            }
            task::Poll::Ready(Err(e)) => task::Poll::Ready(Err(NvFsError::from(e))),
            task::Poll::Pending => task::Poll::Pending,
        }
    }
}

/// [`NvChipWriteRequest`](chip::NvChipWriteRequest) implementation used
/// internally by [`AuthTreeNodeWriteFuture`].
struct AuthTreeNodeWriteNvChipRequest {
    src_buf: FixedVec<u8, 7>,
    io_region: chip::ChunkedIoRegion,
}

impl chip::NvChipWriteRequest for AuthTreeNodeWriteNvChipRequest {
    fn region(&self) -> &chip::ChunkedIoRegion {
        &self.io_region
    }

    fn get_source_buffer(&self, range: &chip::ChunkedIoRegionChunkRange) -> Result<&[u8], chip::NvChipIoError> {
        debug_assert_eq!(range.chunk().decompose_to_hierarchic_indices::<0>([]).0, 0);
        Ok(&self.src_buf[range.range_in_chunk().clone()])
    }
}

/// Read and authenticate an authentication tree node.
///
/// Read and authenticate an authentication tree node. Note that this involves
/// reading and authenticating any node on the path to the nearest ancestor
/// possibly already in the [`AuthTreeNodeCache`], if any, or on the path to the
/// root if none. The originally requested node (and possibly any nodes
/// processed in the course) will eventually get placed in the
/// [`AuthTreeNodeCache`] and a reference to the entry returned upon future
/// completion.
pub struct AuthTreeNodeLoadFuture<C: chip::NvChip> {
    fut_state: AuthTreeNodeLoadFutureState<C>,
}

/// Internal [`AuthTreeNodeLoadFuture::poll()`] state-machine state.
enum AuthTreeNodeLoadFutureState<C: chip::NvChip> {
    Init {
        request_node_id: AuthTreeNodeId,
    },
    LoadRootPathNodePrepare {
        request_node_id: AuthTreeNodeId,
        cur_node_id: AuthTreeNodeId,
        cur_node_expected_digest: FixedVec<u8, 5>,
    },
    LoadRootPathNode {
        request_node_id: AuthTreeNodeId,
        cur_node_id: AuthTreeNodeId,
        cur_node_expected_digest: FixedVec<u8, 5>,
        node_read_fut: AuthTreeNodeReadFuture<C>,
    },
    Done,
}

impl<C: chip::NvChip> AuthTreeNodeLoadFuture<C> {
    /// Instantiate a new [`AuthTreeNodeLoadFuture`].
    ///
    /// # Arguments:
    ///
    /// * `request_node_id` - The [`AuthTreeNodeId`] of the node to read and
    ///   authenticate.
    pub fn new(request_node_id: AuthTreeNodeId) -> Self {
        Self {
            fut_state: AuthTreeNodeLoadFutureState::Init { request_node_id },
        }
    }

    /// Poll the [`AuthTreeNodeLoadFuture`] to completion.
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `tree_config` - The filesystem's [`AuthTree`]'s [`AuthTreeConfig`].
    /// * `root_hmac_digest` - The filesystem's [`AuthTree`]'s root digest.
    /// * `node_cache` - The filesystem's [`AuthTree`]'s [`AuthTreeNodeCache`].
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    pub fn poll<'a, 'b, ST: sync_types::SyncTypes>(
        mut self: pin::Pin<&mut Self>,
        chip: &C,
        tree_config: &AuthTreeConfig,
        root_hmac_digest: &[u8],
        node_cache: &'a mut AuthTreeNodeCacheRef<'b, ST>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<AuthTreeNodeCacheEntryRef<'a, ST>, NvFsError>> {
        let mut node_cache = node_cache.make_borrow();
        let this = self.deref_mut();
        'load_next_node: loop {
            match &mut this.fut_state {
                AuthTreeNodeLoadFutureState::Init { request_node_id } => {
                    // Check the cache for the first ancestor of the requested node on the path to
                    // the root. If the requested node is found, return right away. Otherwise,
                    // continue with loading the missing descendant of the found cached node, if
                    // any, or the root node.
                    // First, allocate the digest buffer outside the lock, even though
                    // it would not be needed on a cache hit.
                    let mut child_node_expected_digest =
                        match FixedVec::new_with_default(tree_config.node_digest_len as usize) {
                            Ok(child_node_expected_digest) => child_node_expected_digest,
                            Err(e) => {
                                this.fut_state = AuthTreeNodeLoadFutureState::Done;
                                return task::Poll::Ready(Err(NvFsError::from(e)));
                            }
                        };

                    let root_path = AuthTreeRootPath::new(*request_node_id, tree_config);
                    let node_cache_guard = AuthTreeNodeCacheReadGuard::from(node_cache);
                    for node_id in root_path.iter() {
                        if let Some(cache_entry_index) = node_cache_guard.deref().lookup(&node_id) {
                            if node_id == *request_node_id {
                                return task::Poll::Ready(Ok(AuthTreeNodeCacheEntryRef {
                                    cache: node_cache_guard,
                                    entry_index: cache_entry_index,
                                }));
                            }

                            let child_node_level = node_id.level - 1;
                            let child_node_id = AuthTreeNodeId::new(
                                request_node_id.covered_data_blocks_begin,
                                child_node_level,
                                tree_config.node_digests_per_node_log2,
                                tree_config.data_digests_per_node_log2,
                            );
                            let parent_node = node_cache_guard.get_entry(cache_entry_index).unwrap().1;
                            child_node_expected_digest.copy_from_slice(
                                parent_node
                                    .get_digest(child_node_id.index_in_parent(), tree_config.node_digest_len as usize),
                            );
                            node_cache = AuthTreeNodeCacheRef::from(node_cache_guard);

                            this.fut_state = AuthTreeNodeLoadFutureState::LoadRootPathNodePrepare {
                                request_node_id: *request_node_id,
                                cur_node_id: child_node_id,
                                cur_node_expected_digest: child_node_expected_digest,
                            };

                            continue 'load_next_node;
                        }
                    }
                    node_cache = AuthTreeNodeCacheRef::from(node_cache_guard);

                    // No ancestor node found in the cache. Load the root.
                    let root_node_id = AuthTreeNodeId::new(
                        request_node_id.covered_data_blocks_begin,
                        tree_config.auth_tree_levels - 1,
                        tree_config.node_digests_per_node_log2,
                        tree_config.data_digests_per_node_log2,
                    );

                    this.fut_state = AuthTreeNodeLoadFutureState::LoadRootPathNodePrepare {
                        request_node_id: *request_node_id,
                        cur_node_id: root_node_id,
                        cur_node_expected_digest: child_node_expected_digest,
                    };
                }
                AuthTreeNodeLoadFutureState::LoadRootPathNodePrepare {
                    request_node_id,
                    cur_node_id,
                    cur_node_expected_digest,
                } => {
                    let node_read_fut = match AuthTreeNodeReadFuture::new(chip, tree_config, cur_node_id) {
                        Ok(node_read_fut) => node_read_fut,
                        Err(e) => {
                            this.fut_state = AuthTreeNodeLoadFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    this.fut_state = AuthTreeNodeLoadFutureState::LoadRootPathNode {
                        request_node_id: *request_node_id,
                        cur_node_id: *cur_node_id,
                        cur_node_expected_digest: mem::take(cur_node_expected_digest),
                        node_read_fut,
                    };
                }
                AuthTreeNodeLoadFutureState::LoadRootPathNode {
                    request_node_id,
                    cur_node_id,
                    cur_node_expected_digest,
                    node_read_fut,
                } => {
                    let cur_node_data = match chip::NvChipFuture::poll(pin::Pin::new(node_read_fut), chip, cx) {
                        task::Poll::Pending => return task::Poll::Pending,
                        task::Poll::Ready(Ok(cur_node_data)) => cur_node_data,
                        task::Poll::Ready(Err(e)) => {
                            this.fut_state = AuthTreeNodeLoadFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };

                    // Authenticate what has just been read.
                    if let Err(e) = if cur_node_id.level != tree_config.auth_tree_levels - 1 {
                        tree_config.authenticate_descendant_node(cur_node_expected_digest, cur_node_id, &cur_node_data)
                    } else {
                        // It is the root node.
                        tree_config.authenticate_root_node(root_hmac_digest, cur_node_id, &cur_node_data)
                    } {
                        this.fut_state = AuthTreeNodeLoadFutureState::Done;
                        return task::Poll::Ready(Err(e));
                    }

                    let cur_node = AuthTreeNode { data: cur_node_data };
                    let mut node_cache_guard = AuthTreeNodeCacheWriteGuard::from(node_cache);
                    if cur_node_id == request_node_id {
                        // Done. Add to the node cache and return a reference.
                        let cur_node_id = *cur_node_id;
                        this.fut_state = AuthTreeNodeLoadFutureState::Done;
                        let cache_entry_index = match node_cache_guard.deref_mut().insert(cur_node_id, cur_node) {
                            Ok(cache_entry_index) => cache_entry_index,
                            Err(e) => return task::Poll::Ready(Err(e)),
                        };
                        return task::Poll::Ready(Ok(AuthTreeNodeCacheEntryRef {
                            cache: AuthTreeNodeCacheReadGuard::WriteGuard {
                                guard: node_cache_guard,
                            },
                            entry_index: cache_entry_index,
                        }));
                    }

                    // Continue the authentication path down to the requested node. First check
                    // whether some descendant node had been added concurrently to the cache in the
                    // meanwhile. If so, don't thrash the cache any further and continue with the
                    // found one instead.
                    let next_parent_node_cache_entry_index = {
                        let root_path = AuthTreeRootPath::new(*request_node_id, tree_config);
                        let mut found_descendant_node_cache_entry_index = None;
                        for descendant_node_id in root_path.iter() {
                            if descendant_node_id == *cur_node_id {
                                break;
                            }
                            if let Some(cache_entry_index) = node_cache_guard.deref().lookup(&descendant_node_id) {
                                if descendant_node_id == *request_node_id {
                                    return task::Poll::Ready(Ok(AuthTreeNodeCacheEntryRef {
                                        cache: AuthTreeNodeCacheReadGuard::WriteGuard {
                                            guard: node_cache_guard,
                                        },
                                        entry_index: cache_entry_index,
                                    }));
                                }

                                // Continue with the found descendant node instead of the recently
                                // loaded one.
                                *cur_node_id = descendant_node_id;
                                found_descendant_node_cache_entry_index = Some(cache_entry_index);
                                break;
                            }
                        }

                        match found_descendant_node_cache_entry_index {
                            Some(found_descendant_node_cache_entry_index) => found_descendant_node_cache_entry_index,
                            None => match node_cache_guard.deref_mut().insert(*cur_node_id, cur_node) {
                                Ok(cache_entry_index) => cache_entry_index,
                                Err(e) => {
                                    this.fut_state = AuthTreeNodeLoadFutureState::Done;
                                    return task::Poll::Ready(Err(e));
                                }
                            },
                        }
                    };

                    // And setup everything to read and authenticate the next node
                    // down the path to the requested node in the next iteration.
                    let child_node_level = cur_node_id.level - 1;
                    let child_node_id = AuthTreeNodeId::new(
                        request_node_id.covered_data_blocks_begin,
                        child_node_level,
                        tree_config.node_digests_per_node_log2,
                        tree_config.data_digests_per_node_log2,
                    );
                    let parent_node = node_cache_guard
                        .get_entry(next_parent_node_cache_entry_index)
                        .unwrap()
                        .1;
                    cur_node_expected_digest.copy_from_slice(
                        parent_node.get_digest(child_node_id.index_in_parent(), tree_config.node_digest_len as usize),
                    );

                    node_cache = AuthTreeNodeCacheRef::from(node_cache_guard);

                    this.fut_state = AuthTreeNodeLoadFutureState::LoadRootPathNodePrepare {
                        request_node_id: *request_node_id,
                        cur_node_id: child_node_id,
                        cur_node_expected_digest: mem::take(cur_node_expected_digest),
                    };
                }
                AuthTreeNodeLoadFutureState::Done => unreachable!(),
            }
        }
    }
}

/// Digest entry update record in [`AuthTreePendingNodeUpdates`].
struct AuthTreePendingNodeEntryUpdate {
    /// Index of the to be updated digest entry within the node.
    entry_index_in_node: usize,
    /// Updated digest entry value.
    updated_digest: FixedVec<u8, 5>,
}

/// Pending updates to an authentication tree node.
struct AuthTreePendingNodeUpdates {
    /// [`AuthTreeNodeId`] of the to be updated node.
    node_id: AuthTreeNodeId,
    /// Pending digest entry updates.
    updated_entries: Vec<AuthTreePendingNodeEntryUpdate>,
}

/// Pending authentication tree updates.
///
/// Updating the authentication tree at transaction commit time is a two-step
/// process:
///
/// 1. First all updates to the tree are collected into a
///    `AuthTreePendingNodeUpdates` in-memory representation before writing any
///    of the journal by means of [`AuthTreePrepareUpdatesFuture`] and the new
///    root digest will eventually get computed.
/// 2. After the journal has been written, including the new root digest, the
///    changes recorded at the `AuthTreePendingNodesUpdates` will eventually get
///    applied via [`AuthTreeApplyUpdatesFuture`].
///
/// Note that the [`AuthTreeDataBlocksUpdatesIterator`] trait implementation
/// used for collecting updated [Authentication Tree Data
/// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
/// digests through [`AuthTreePrepareUpdatesFuture`] may steal those digests
/// from e.g. a [`Transaction`](super::transaction::Transaction) instance and
/// transfer them over to the `AuthTreePendingNodesUpdates` instance.
/// [`AuthTreePendingNodesUpdates::into_updated_data_blocks()`] may be used
/// to obtain them back e.g. upon encountering some error.
#[derive(Default)]
pub struct AuthTreePendingNodesUpdates {
    /// Pending updates to the individual authentication tree nodes, stored in
    /// DFS pre order.
    nodes_updates: Vec<AuthTreePendingNodeUpdates>,
}

impl AuthTreePendingNodesUpdates {
    /// Create an empty [`AuthTreePendingNodesUpdates`] instance.
    pub fn new() -> Self {
        Self {
            nodes_updates: Vec::new(),
        }
    }

    /// Obtain the leaf-level [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// digests back.
    pub fn into_updated_data_blocks(
        self,
        tree_config: &AuthTreeConfig,
    ) -> AuthTreePendingNodesUpdatesIntoDataUpdatesIter<'_> {
        AuthTreePendingNodesUpdatesIntoDataUpdatesIter::new(self.nodes_updates, tree_config)
    }
}

/// [`Iterator`] returned by
/// [`AuthTreePendingNodesUpdates::into_updated_data_blocks()`].
pub struct AuthTreePendingNodesUpdatesIntoDataUpdatesIter<'a> {
    /// The [`AuthTreePendingNodeUpdates`] instance to obtain the
    /// [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// digests back from.
    nodes_updates: Vec<AuthTreePendingNodeUpdates>,
    /// [Authentication Tree Data Block index domain
    /// index](AuthTreeDataBlockIndex) of the last [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// level entry in `nodes_updates`.
    nodes_updates_last_data_block_index: AuthTreeDataBlockIndex,
    /// Position within `nodes_updates`.
    next_updated_node_index: usize,
    /// Position within the current (leaf level) node entry in `nodes_updates`.
    next_updated_node_entry_index: usize,
    /// The filesystem's [`AuthTreeConfig`].
    tree_config: &'a AuthTreeConfig,
    /// Iterator for mapping the [Authentication Tree Data Block index domain
    /// indices](AuthTreeDataBlockIndex) tracked in the `node_updates`'
    /// entries back to physical positions.
    remaining_data_range_physical_segments: Option<AuthTreeDataAllocationBlocksMapIterator<'a>>,
    /// The current entry yielded from the
    /// `remaining_data_range_physical_segments` iterator.
    cur_remaining_data_range_physical_segment: Option<(AuthTreeDataAllocBlockRange, layout::PhysicalAllocBlockIndex)>,
}
impl<'a> AuthTreePendingNodesUpdatesIntoDataUpdatesIter<'a> {
    fn new(nodes_updates: Vec<AuthTreePendingNodeUpdates>, auth_tree_config: &'a AuthTreeConfig) -> Self {
        // When translating logical to physical ranges, the maximum will be used for the
        // end in the lookup.
        let nodes_updates_last_data_block_index = nodes_updates
            .iter()
            .rev()
            .find(|updated_node| updated_node.node_id.level == 0)
            .map(|last_node| {
                last_node.node_id.first_covered_data_block()
                    + AuthTreeDataBlockCount::from(
                        last_node
                            .updated_entries
                            .last()
                            .map(|last_node_last_entry| last_node_last_entry.entry_index_in_node)
                            .unwrap_or(0) as u64,
                    )
            })
            .unwrap_or(AuthTreeDataBlockIndex::from(0u64));
        let next_updated_node_index = nodes_updates
            .iter()
            .enumerate()
            .find(|(_, updated_node)| updated_node.node_id.level == 0 && !updated_node.updated_entries.is_empty())
            .map(|(i, _)| i)
            .unwrap_or(nodes_updates.len());
        Self {
            nodes_updates,
            nodes_updates_last_data_block_index,
            next_updated_node_index,
            next_updated_node_entry_index: 0,
            tree_config: auth_tree_config,
            remaining_data_range_physical_segments: None,
            cur_remaining_data_range_physical_segment: None,
        }
    }
}

impl<'a> iter::Iterator for AuthTreePendingNodesUpdatesIntoDataUpdatesIter<'a> {
    type Item = Result<PhysicalAuthTreeDataBlockUpdate, NvFsError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_updated_node_index == self.nodes_updates.len() {
            return None;
        }

        let updated_node = &mut self.nodes_updates[self.next_updated_node_index];
        debug_assert!(self.next_updated_node_entry_index < updated_node.updated_entries.len());
        debug_assert_eq!(
            self.cur_remaining_data_range_physical_segment.is_none(),
            self.remaining_data_range_physical_segments.is_none()
        );

        let node_covered_auth_tree_data_blocks_begin = updated_node.node_id.first_covered_data_block();
        let remaining_data_range_physical_segments = match self.remaining_data_range_physical_segments.as_mut() {
            Some(remaining_data_range_physical_segments) => remaining_data_range_physical_segments,
            None => {
                debug_assert_eq!(self.next_updated_node_entry_index, 0);
                let remaining_auth_tree_data_blocks_range = AuthTreeDataBlockRange::new(
                    node_covered_auth_tree_data_blocks_begin
                        + AuthTreeDataBlockCount::from(updated_node.updated_entries[0].entry_index_in_node as u64),
                    self.nodes_updates_last_data_block_index + AuthTreeDataBlockCount::from(1u64),
                );
                let remaining_data_range_physical_segments = self.remaining_data_range_physical_segments.insert(
                    self.tree_config
                        .translate_data_block_range_to_physical(&remaining_auth_tree_data_blocks_range),
                );
                self.cur_remaining_data_range_physical_segment = remaining_data_range_physical_segments.next();
                remaining_data_range_physical_segments
            }
        };

        let cur_entry_auth_tree_data_block_index = node_covered_auth_tree_data_blocks_begin
            + AuthTreeDataBlockCount::from(
                updated_node.updated_entries[self.next_updated_node_entry_index].entry_index_in_node as u64,
            );
        let cur_entry_auth_tree_data_block_allocation_blocks_begin =
            AuthTreeDataAllocBlockIndex::new_from_data_block_index(
                cur_entry_auth_tree_data_block_index,
                self.tree_config.data_block_allocation_blocks_log2 as u32,
            );

        let cur_remaining_data_range_physical_segment = loop {
            let cur_remaining_data_range_physical_segment =
                match self.cur_remaining_data_range_physical_segment.as_ref() {
                    Some(cur_remaining_data_range_physical_segment) => cur_remaining_data_range_physical_segment,
                    None => return Some(Err(nvfs_err_internal!())),
                };
            debug_assert!(
                cur_entry_auth_tree_data_block_allocation_blocks_begin
                    >= cur_remaining_data_range_physical_segment.0.begin()
            );
            if cur_entry_auth_tree_data_block_allocation_blocks_begin
                >= cur_remaining_data_range_physical_segment.0.end()
            {
                self.cur_remaining_data_range_physical_segment = remaining_data_range_physical_segments.next();
                continue;
            }
            break cur_remaining_data_range_physical_segment;
        };

        let cur_entry_auth_tree_data_block_physical_allocation_blocks_begin = cur_remaining_data_range_physical_segment
            .1
            + (cur_entry_auth_tree_data_block_allocation_blocks_begin
                - cur_remaining_data_range_physical_segment.0.begin());
        let cur_entry_data_block_digest =
            mem::take(&mut updated_node.updated_entries[self.next_updated_node_entry_index].updated_digest);

        self.next_updated_node_entry_index += 1;
        if self.next_updated_node_entry_index == updated_node.updated_entries.len() {
            self.next_updated_node_entry_index = 0;
            loop {
                self.next_updated_node_index += 1;
                if self.next_updated_node_index == self.nodes_updates.len()
                    || (self.nodes_updates[self.next_updated_node_index].node_id.level == 0
                        && !self.nodes_updates[self.next_updated_node_index]
                            .updated_entries
                            .is_empty())
                {
                    break;
                }
            }
            if self.next_updated_node_index != self.nodes_updates.len()
                && AuthTreeDataAllocBlockIndex::new_from_data_block_index(
                    self.nodes_updates[self.next_updated_node_index]
                        .node_id
                        .first_covered_data_block(),
                    self.tree_config.data_block_allocation_blocks_log2 as u32,
                ) > cur_remaining_data_range_physical_segment.0.end()
            {
                // The next node's associated range is too far ahead, force a new lookup.
                self.remaining_data_range_physical_segments = None;
                self.cur_remaining_data_range_physical_segment = None;
            }
        }

        Some(Ok(PhysicalAuthTreeDataBlockUpdate {
            data_block_allocation_blocks_begin: cur_entry_auth_tree_data_block_physical_allocation_blocks_begin,
            data_block_digest: cur_entry_data_block_digest,
        }))
    }
}

/// [Authentication Tree Data
/// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
/// digest update in the [Authentication Tree Data Block index
/// domain](AuthTreeDataBlockIndex).
struct LogicalAuthTreeDataBlockUpdate {
    /// [Authentication Tree Data Block index domain
    /// index](AuthTreeDataAllocBlockIndex) of the [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// the updated `data_block_digest` is associated with.
    data_block_index: AuthTreeDataBlockIndex,
    /// The updated [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// digest.
    data_block_digest: FixedVec<u8, 5>,
}

/// [Authentication Tree Data
/// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
/// digest update in the [physical index
/// domain](layout::PhysicalAllocBlockIndex).
pub struct PhysicalAuthTreeDataBlockUpdate {
    /// Beginning of the [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// on physical storage the updated `data_block_digest` is associated
    /// with.
    pub data_block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
    /// The updated [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// digest.
    pub data_block_digest: FixedVec<u8, 5>,
}

/// Pollable iterator trait supplying [Authentication Tree Data
/// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
/// level digest updates to an [`AuthTreePrepareUpdatesFuture`].
///
/// Obtaining the next updated [Authentication Tree Data
/// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
/// digest may involve some non-trivial operations including IO, like is e.g.
/// the authentication of its retained [Allocation
/// Blocks](ImageLayout::allocation_block_size_128b_log2)'s data.
///
/// For this reason, the primitive for obtaining the next iterator item,
/// [`poll_for_next()`](Self::poll_for_next), implements
/// [`Future::poll()`](core::future::Future::poll)-like semantics.
pub trait AuthTreeDataBlocksUpdatesIterator<ST: sync_types::SyncTypes, C: chip::NvChip> {
    /// Poll the iterator for the next [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// level digest update.
    ///
    /// # Arguments:
    ///
    /// * `fs_instance_sync_state` - Reference to the filesystem instance's
    ///   [`CocoonFsSyncState`](super::fs::CocoonFsSyncState).
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    fn poll_for_next(
        self: pin::Pin<&mut Self>,
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, C>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<Option<PhysicalAuthTreeDataBlockUpdate>, NvFsError>>;

    /// Invoked upon error from [`AuthTreePrepareUpdatesFuture`] for
    /// transferring any possibly stolen [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// level digests back.
    ///
    /// # Arguments:
    ///
    /// * `fs_config` - The filesystem instance's [`CocoonFsConfig`].
    /// * `returned_updates` -
    ///   [`AuthTreePendingNodesUpdatesIntoDataUpdatesIter`] iterator over the
    ///   [Authentication Tree Data
    ///   Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) level
    ///   digests previously obtained from
    ///   [`poll_for_next()`](Self::poll_for_next).
    fn return_digests_on_error(
        &mut self,
        fs_config: &CocoonFsConfig,
        returned_updates: AuthTreePendingNodesUpdatesIntoDataUpdatesIter,
    ) -> Result<(), NvFsError>;

    /// Invoked upon error from [`AuthTreePrepareUpdatesFuture`] for
    /// transferring a single possibly stolen [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// level digests back.
    ///
    /// # Arguments:
    ///
    /// * `fs_config` - The filesystem instance's [`CocoonFsConfig`].
    /// * `returned_update` - The [Authentication Tree Data
    ///   Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) level
    ///   digest previously obtained from
    ///   [`poll_for_next()`](Self::poll_for_next).
    fn return_digest_on_error(
        &mut self,
        fs_config: &CocoonFsConfig,
        returned_update: PhysicalAuthTreeDataBlockUpdate,
    ) -> Result<(), NvFsError>;
}

/// Collect authentication tree updates into a new
/// [`AuthTreePendingNodeUpdates`] and eventually compute the updated
/// root digest.
///
/// The updated [Authentication Tree Data
/// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
/// level digests are to be supplied from extern by means of some
/// [`AuthTreeDataBlocksUpdatesIterator`] implementation. The
/// `AuthTreePrepareUpdatesFuture` assumes ownership on it for the duration of
/// the operation and eventually returns it back when done.
pub struct AuthTreePrepareUpdatesFuture<
    ST: sync_types::SyncTypes,
    C: chip::NvChip,
    DUI: AuthTreeDataBlocksUpdatesIterator<ST, C> + marker::Unpin,
> {
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
    // reference on Self.
    data_block_updates_iter: Option<DUI>,
    pending_nodes_updates: AuthTreePendingNodesUpdates,
    /// Current position in the tree, represented as a sequence of indicies into
    /// [`pending_nodes_updates`](Self::pending_nodes_updates), sorted by
    /// distance from the root.
    cursor: Vec<usize>,
    fut_state: AuthTreePrepareUpdatesFutureState<C>,
    _phantom: marker::PhantomData<fn() -> *const ST>,
}

/// Internal [`AuthTreePrepareUpdatesFuture::poll()`] state-machine state.
enum AuthTreePrepareUpdatesFutureState<C: chip::NvChip> {
    Init,
    ObtainNextUpdatedDataBlock,
    AdvanceCursor {
        next_updated_data_block: Option<LogicalAuthTreeDataBlockUpdate>,
    },
    LoadAuthTreeNode {
        load_original_node_fut: AuthTreeNodeLoadFuture<C>,
        next_updated_data_block: Option<LogicalAuthTreeDataBlockUpdate>,
        node_digest_dst: FixedVec<u8, 5>,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip, DUI: AuthTreeDataBlocksUpdatesIterator<ST, C> + marker::Unpin>
    AuthTreePrepareUpdatesFuture<ST, C, DUI>
{
    /// Instantiate a new [`AuthTreePrepareUpdatesFuture`].
    ///
    /// # Arguments:
    ///
    /// * `data_block_updates_iter` - The [`AuthTreeDataBlocksUpdatesIterator`]
    ///   over the [Authentication Tree Data
    ///   Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    ///   updates. Will get returned back from [`poll()`](Self::poll) upon
    ///   future completion.
    pub fn new(data_block_updates_iter: DUI) -> Self {
        Self {
            data_block_updates_iter: Some(data_block_updates_iter),
            pending_nodes_updates: AuthTreePendingNodesUpdates::new(),
            cursor: Vec::new(),
            fut_state: AuthTreePrepareUpdatesFutureState::Init,
            _phantom: marker::PhantomData,
        }
    }

    fn push_cursor_to_leaf(
        &mut self,
        data_block_index: AuthTreeDataBlockIndex,
        node_digests_per_node_log2: u8,
        data_digests_per_node_log2: u8,
        auth_tree_levels: u8,
    ) -> Result<(), NvFsError> {
        let mut level = match self.cursor.last() {
            Some(bottom) => {
                debug_assert!(
                    self.pending_nodes_updates.nodes_updates[*bottom]
                        .node_id
                        .last_covered_data_block()
                        >= data_block_index
                );
                debug_assert!(self.pending_nodes_updates.nodes_updates[*bottom].node_id.level > 0);
                self.pending_nodes_updates.nodes_updates[*bottom].node_id.level
            }
            None => auth_tree_levels,
        };
        if self.cursor.capacity() < auth_tree_levels as usize {
            self.cursor
                .try_reserve_exact(auth_tree_levels as usize - self.cursor.capacity())
                .map_err(|_| NvFsError::MemoryAllocationFailure)?;
        }
        self.pending_nodes_updates
            .nodes_updates
            .try_reserve_exact(level as usize)
            .map_err(|_| NvFsError::MemoryAllocationFailure)?;
        while level > 0 {
            level -= 1;
            self.cursor.push(self.pending_nodes_updates.nodes_updates.len());
            self.pending_nodes_updates
                .nodes_updates
                .push(AuthTreePendingNodeUpdates {
                    node_id: AuthTreeNodeId::new(
                        data_block_index,
                        level,
                        node_digests_per_node_log2,
                        data_digests_per_node_log2,
                    ),
                    updated_entries: Vec::new(),
                });
        }

        Ok(())
    }

    fn pending_bottom_node_updates_push(
        &mut self,
        child_covered_data_blocks_begin: AuthTreeDataBlockIndex,
        mut child_digest: FixedVec<u8, 5>,
        node_digests_per_node_log2: u8,
        data_digests_per_node_log2: u8,
    ) -> Result<(), (NvFsError, FixedVec<u8, 5>)> {
        let bottom = self.cursor.last().unwrap();
        let bottom_node_pending_updates = &mut self.pending_nodes_updates.nodes_updates[*bottom];
        debug_assert!(bottom_node_pending_updates.node_id.covered_data_blocks_begin <= child_covered_data_blocks_begin);
        debug_assert!(bottom_node_pending_updates.node_id.last_covered_data_block() >= child_covered_data_blocks_begin);
        let level = bottom_node_pending_updates.node_id.level;
        let entry_index_in_node = if level != 0 {
            (u64::from(child_covered_data_blocks_begin)
                >> ((level - 1) * node_digests_per_node_log2 + data_digests_per_node_log2))
                & u64::trailing_bits_mask(node_digests_per_node_log2 as u32)
        } else {
            u64::from(child_covered_data_blocks_begin) & u64::trailing_bits_mask(data_digests_per_node_log2 as u32)
        } as usize;
        bottom_node_pending_updates
            .updated_entries
            .try_reserve_exact(1)
            .map_err(|_| (NvFsError::MemoryAllocationFailure, mem::take(&mut child_digest)))?;
        bottom_node_pending_updates
            .updated_entries
            .push(AuthTreePendingNodeEntryUpdate {
                entry_index_in_node,
                updated_digest: child_digest,
            });
        Ok(())
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip, DUI: AuthTreeDataBlocksUpdatesIterator<ST, C> + marker::Unpin>
    CocoonFsSyncStateReadFuture<ST, C> for AuthTreePrepareUpdatesFuture<ST, C, DUI>
{
    /// Output type of [`poll()`](Self::poll).
    ///
    /// A two-level [`Result`] is returned upon
    /// [future](CocoonFsSyncStateReadFuture) completion:
    /// * `Err(e)` -  The outer level [`Result`] is set to [`Err`] upon
    ///   encountering an internal error causing the
    ///   [`AuthTreeDataBlocksUpdatesIterator`] to get lost.
    /// * `Ok((data_block_updates_iter, ...))` - Otherwise the outer level
    ///   [`Result`] is set to [`Ok`] and a pair of the input
    ///   `data_block_updates_iter` and the operation result will get returned
    ///   within:
    ///     * `Ok((data_block_updates_iter, Err(e)))` - In case of an error, the
    ///       error reason `e` is returned in an [`Err`].
    ///     * `Ok((data_block_updates_iter, Ok((root_hmac_digest,
    ///       pending_nodes_updates))))` - Otherwise, a pair of the updated root
    ///       digest and the [`AuthTreePendingNodesUpdates`] instance will get
    ///       returned wrapped in an `Ok`.
    type Output = Result<(DUI, Result<(FixedVec<u8, 5>, AuthTreePendingNodesUpdates), NvFsError>), NvFsError>;
    type AuxPollData<'a> = ();

    fn poll<'a>(
        self: pin::Pin<&mut Self>,
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, C>,
        _aux_data: &mut Self::AuxPollData<'a>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        let result = 'outer: loop {
            match &mut this.fut_state {
                AuthTreePrepareUpdatesFutureState::Init => {
                    this.fut_state = AuthTreePrepareUpdatesFutureState::ObtainNextUpdatedDataBlock;
                }
                AuthTreePrepareUpdatesFutureState::ObtainNextUpdatedDataBlock => {
                    let data_block_updates_iter = match this.data_block_updates_iter.as_mut() {
                        Some(data_block_updates_iter) => data_block_updates_iter,
                        None => {
                            break Err((nvfs_err_internal!(), None));
                        }
                    };
                    let next_updated_data_block = match AuthTreeDataBlocksUpdatesIterator::poll_for_next(
                        pin::Pin::new(data_block_updates_iter),
                        fs_instance_sync_state,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(next_updated_data_block)) => next_updated_data_block,
                        task::Poll::Ready(Err(e)) => break Err((e, None)),
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    let tree_config = fs_instance_sync_state.auth_tree.get_config();
                    let next_updated_data_block =
                        next_updated_data_block.map(|next_updated_data_block| LogicalAuthTreeDataBlockUpdate {
                            data_block_index: tree_config.translate_physical_to_data_block_index(
                                next_updated_data_block.data_block_allocation_blocks_begin,
                            ),
                            data_block_digest: next_updated_data_block.data_block_digest,
                        });
                    this.fut_state = AuthTreePrepareUpdatesFutureState::AdvanceCursor {
                        next_updated_data_block,
                    };
                }
                AuthTreePrepareUpdatesFutureState::AdvanceCursor {
                    next_updated_data_block,
                } => {
                    let tree_config = fs_instance_sync_state.auth_tree.get_config();
                    let mut next_updated_data_block = next_updated_data_block.take();
                    if this.cursor.is_empty() {
                        // This is the first update, if any.
                        debug_assert!(this.pending_nodes_updates.nodes_updates.is_empty());
                        match next_updated_data_block
                            .as_ref()
                            .map(|next_updated_data_block| next_updated_data_block.data_block_index)
                        {
                            Some(next_updated_data_block_index) => {
                                // There is an update. Push the cursor to the covering leaf, so that
                                // it's never empty for what follows.
                                if let Err(e) = this.push_cursor_to_leaf(
                                    next_updated_data_block_index,
                                    tree_config.node_digests_per_node_log2,
                                    tree_config.data_digests_per_node_log2,
                                    tree_config.auth_tree_levels,
                                ) {
                                    break Err((e, next_updated_data_block));
                                }
                            }
                            None => {
                                // There is no change at all, copy the existing root hmac and
                                // return.
                                let root_hmac_digest = &fs_instance_sync_state.auth_tree.root_hmac_digest;
                                let mut root_hmac_copy = match FixedVec::new_with_default(root_hmac_digest.len()) {
                                    Ok(root_hmac_copy) => root_hmac_copy,
                                    Err(e) => break Err((NvFsError::from(e), None)),
                                };
                                root_hmac_copy.copy_from_slice(root_hmac_digest);
                                break Ok(root_hmac_copy);
                            }
                        };
                    }

                    // Figure out what to do next, based on next_updated_data_block,
                    // the cursor position and the bottom node's covered data range:
                    // - if next_updated_data_block is None, all that is left to do is to move the
                    //   cursor all the way up to the root, digesting child nodes into their
                    //   associated parent entries in the course.
                    // - if the next_updated_data_block is located past the cursor's bottom node's
                    //   covered data range, the cursor needs to get moved up until
                    //   next_updated_data_block is in range again, digesting child nodes into
                    //   parent entries on the go,
                    // - if the next_updated_data_block is in the cursor's bottom node's covered
                    //   range, the cursor will get moved down all the way to level 0, and the
                    //   next_updated_data_block's associated digest recorded in the corresponding
                    //   leaf slot.
                    loop {
                        let bottom = *this.cursor.last().unwrap();
                        let bottom_node_pending_updates = &this.pending_nodes_updates.nodes_updates[bottom];
                        if let Some(mut next_updated_data_block_in_range) =
                            next_updated_data_block.take_if(|next_updated_data_block| {
                                next_updated_data_block.data_block_index
                                    <= bottom_node_pending_updates.node_id.last_covered_data_block()
                            })
                        {
                            // next_updated_data_block is in the cursor's bottom node's covered
                            // range. Record its digest in the
                            // corresponding leaf node, potentially after
                            // moving the cursor all the way down to level 0.
                            if this.cursor.len() != tree_config.auth_tree_levels as usize {
                                if let Err(e) = this.push_cursor_to_leaf(
                                    next_updated_data_block_in_range.data_block_index,
                                    tree_config.node_digests_per_node_log2,
                                    tree_config.data_digests_per_node_log2,
                                    tree_config.auth_tree_levels,
                                ) {
                                    break 'outer Err((e, Some(next_updated_data_block_in_range)));
                                }
                            }
                            if let Err((e, returned_data_block_digest)) = this.pending_bottom_node_updates_push(
                                next_updated_data_block_in_range.data_block_index,
                                mem::take(&mut next_updated_data_block_in_range.data_block_digest),
                                tree_config.node_digests_per_node_log2,
                                tree_config.data_digests_per_node_log2,
                            ) {
                                next_updated_data_block_in_range.data_block_digest = returned_data_block_digest;
                                break 'outer Err((e, Some(next_updated_data_block_in_range)));
                            }

                            // Obtain the next updated data block location and digest.
                            this.fut_state = AuthTreePrepareUpdatesFutureState::ObtainNextUpdatedDataBlock;
                            break;
                        } else {
                            // At this point, next_updated_data_block is either None or past the
                            // cursor's bottom node's covered range. In either
                            // case, the cursor needs to get moved up, digesting
                            // nodes into their associated parent entries, if any, in the
                            // course.
                            let (digest_entry_in_node_len, digest_entries_in_node_log2) =
                                if bottom_node_pending_updates.node_id.level != 0 {
                                    (tree_config.node_digest_len, tree_config.node_digests_per_node_log2)
                                } else {
                                    (tree_config.data_digest_len, tree_config.data_digests_per_node_log2)
                                };
                            if bottom_node_pending_updates.updated_entries.len()
                                == 1usize << digest_entries_in_node_log2
                            {
                                // All of the node's entries got updated, its original contents
                                // won't be needed for computing the
                                // updated digest.
                                let popped = bottom;
                                this.cursor.pop();
                                let popped_node_pending_updates = &this.pending_nodes_updates.nodes_updates[popped];
                                let popped_node_updated_digests = AuthTreeNodeUpdatedDigestsIterator::new(
                                    None,
                                    &popped_node_pending_updates.updated_entries,
                                    digest_entry_in_node_len,
                                    digest_entries_in_node_log2,
                                );

                                if !this.cursor.is_empty() {
                                    // At a descendant node, compute the digest and record it at the
                                    // associated parent entry.
                                    let popped_node_id = popped_node_pending_updates.node_id;
                                    let node_digest = match tree_config
                                        .digest_descendant_node(&popped_node_id, popped_node_updated_digests)
                                    {
                                        Ok(node_digest) => node_digest,
                                        Err(e) => {
                                            break 'outer Err((e, next_updated_data_block));
                                        }
                                    };
                                    if let Err((e, _)) = this.pending_bottom_node_updates_push(
                                        popped_node_id.covered_data_blocks_begin,
                                        node_digest,
                                        tree_config.node_digests_per_node_log2,
                                        tree_config.data_digests_per_node_log2,
                                    ) {
                                        break 'outer Err((e, next_updated_data_block));
                                    }
                                } else {
                                    // At the root, compute the HMAC over the root node and be done.
                                    match tree_config.hmac_root_node(
                                        &popped_node_pending_updates.node_id,
                                        popped_node_updated_digests,
                                    ) {
                                        Ok(mut root_hmac) => {
                                            break 'outer Ok(mem::take(&mut root_hmac));
                                        }
                                        Err(e) => {
                                            break 'outer Err((e, next_updated_data_block));
                                        }
                                    };
                                }
                            } else {
                                // Only part of the node's entries got updated, its original
                                // contents will be needed for computing the updated digest. Load
                                // and authenticate the node's original contents.
                                let load_tree_node_fut =
                                    AuthTreeNodeLoadFuture::new(bottom_node_pending_updates.node_id);
                                // The AuthTreeNodeLoadFuture will return with the cache locked,
                                // allocate the destination for the digest in advance outside that
                                // lock.
                                let node_digest_len =
                                    if bottom_node_pending_updates.node_id.level != tree_config.auth_tree_levels - 1 {
                                        // A node descendant from the root.
                                        tree_config.node_digest_len as usize
                                    } else {
                                        // The root node.
                                        hash::hash_alg_digest_len(tree_config.root_hmac_hash_alg) as usize
                                    };
                                let node_digest_dst = match FixedVec::new_with_default(node_digest_len) {
                                    Ok(node_digest_dst) => node_digest_dst,
                                    Err(e) => break 'outer Err((NvFsError::from(e), next_updated_data_block)),
                                };
                                this.fut_state = AuthTreePrepareUpdatesFutureState::LoadAuthTreeNode {
                                    load_original_node_fut: load_tree_node_fut,
                                    next_updated_data_block,
                                    node_digest_dst,
                                };
                                break;
                            }
                        }
                    }
                }
                AuthTreePrepareUpdatesFutureState::LoadAuthTreeNode {
                    load_original_node_fut,
                    next_updated_data_block,
                    node_digest_dst,
                } => {
                    // The cursor is currently being moved up (because the next_updated_data_block
                    // is past the bottom node's covered range) and the original contents of the
                    // current bottom node, which hasn't got all of its entries updated, are in the
                    // process of getting loaded and authenticated. When done, pop it and digest it
                    // into the associated parent entry, if any.
                    let (
                        fs_instance,
                        _fs_sync_state_image_size,
                        _fs_sync_state_alloc_bitmap,
                        _fs_sync_state_alloc_bitmap_file,
                        mut fs_sync_state_auth_tree,
                        _fs_sync_state_inode_index,
                        _fs_sync_state_read_buffer,
                        _fs_sync_state_keys_cache,
                    ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();
                    let (auth_tree_config, auth_tree_root_hmac_digest, mut auth_tree_node_cache) =
                        fs_sync_state_auth_tree.destructure_borrow();
                    let popped_node_original = match AuthTreeNodeLoadFuture::poll(
                        pin::Pin::new(load_original_node_fut),
                        &fs_instance.chip,
                        auth_tree_config,
                        auth_tree_root_hmac_digest,
                        &mut auth_tree_node_cache,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(node)) => node,
                        task::Poll::Ready(Err(e)) => break Err((e, next_updated_data_block.take())),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let next_updated_data_block = next_updated_data_block.take();
                    // Take the pre-allocated digest destination buffer.
                    let mut popped_node_digest_dst = mem::take(node_digest_dst);
                    let popped = this.cursor.pop().unwrap();
                    let popped_is_root = this.cursor.is_empty();
                    let popped_node_pending_updates = &mut this.pending_nodes_updates.nodes_updates[popped];
                    let (digest_entry_in_node_len, digest_entries_in_node_log2) =
                        if popped_node_pending_updates.node_id.level != 0 {
                            (
                                auth_tree_config.node_digest_len,
                                auth_tree_config.node_digests_per_node_log2,
                            )
                        } else {
                            (
                                auth_tree_config.data_digest_len,
                                auth_tree_config.data_digests_per_node_log2,
                            )
                        };
                    let popped_node_updated_digests = AuthTreeNodeUpdatedDigestsIterator::new(
                        Some(&popped_node_original.data),
                        &popped_node_pending_updates.updated_entries,
                        digest_entry_in_node_len,
                        digest_entries_in_node_log2,
                    );
                    if !popped_is_root {
                        // Popped node is not the root, digest its updated contents into the
                        // associated parent entry.
                        let popped_node_id = popped_node_pending_updates.node_id;
                        auth_tree_config.digest_descendant_node_into(
                            &mut popped_node_digest_dst,
                            &popped_node_id,
                            popped_node_updated_digests,
                        )?;
                        drop(popped_node_original); // Drop the locks before doing the memory allocation below.
                        if let Err((e, _)) = this.pending_bottom_node_updates_push(
                            popped_node_id.covered_data_blocks_begin,
                            popped_node_digest_dst,
                            auth_tree_config.node_digests_per_node_log2,
                            auth_tree_config.data_digests_per_node_log2,
                        ) {
                            break Err((e, next_updated_data_block));
                        }
                        this.fut_state = AuthTreePrepareUpdatesFutureState::AdvanceCursor {
                            next_updated_data_block,
                        };
                    } else {
                        // Popped node is the root, HMAC its updated contents and be done.
                        debug_assert!(next_updated_data_block.is_none());
                        if let Err(e) = auth_tree_config.hmac_root_node_into(
                            &mut popped_node_digest_dst,
                            &popped_node_pending_updates.node_id,
                            popped_node_updated_digests,
                        ) {
                            break Err((e, next_updated_data_block));
                        };
                        break Ok(popped_node_digest_dst);
                    }
                }
                AuthTreePrepareUpdatesFutureState::Done => unreachable!(),
            }
        };

        this.fut_state = AuthTreePrepareUpdatesFutureState::Done;
        match result {
            Ok(root_hmac) => match this.data_block_updates_iter.take() {
                Some(data_block_updates_iter) => task::Poll::Ready(Ok((
                    data_block_updates_iter,
                    Ok((root_hmac, mem::take(&mut this.pending_nodes_updates))),
                ))),
                None => task::Poll::Ready(Err(nvfs_err_internal!())),
            },
            Err((e, next_updated_data_block)) => {
                // Return all data block digests back to the iterator, to enable it to return
                // (its backend, i.e. the transaction) to a consistent state.
                // Consume it if that fails.
                let tree_config = fs_instance_sync_state.auth_tree.get_config();
                let mut data_block_updates_iter = match this.data_block_updates_iter.take() {
                    Some(data_block_updates_iter) => data_block_updates_iter,
                    None => return task::Poll::Ready(Err(nvfs_err_internal!())),
                };
                let fs_instance = fs_instance_sync_state.get_fs_ref();
                let fs_config = &fs_instance.fs_config;
                if data_block_updates_iter
                    .return_digests_on_error(
                        fs_config,
                        mem::take(&mut this.pending_nodes_updates).into_updated_data_blocks(tree_config),
                    )
                    .is_err()
                {
                    return task::Poll::Ready(Err(e));
                }

                if let Some(mut next_updated_data_block) = next_updated_data_block {
                    if data_block_updates_iter
                        .return_digest_on_error(
                            fs_config,
                            PhysicalAuthTreeDataBlockUpdate {
                                data_block_allocation_blocks_begin: tree_config
                                    .translate_data_block_index_to_physical(next_updated_data_block.data_block_index),
                                data_block_digest: mem::take(&mut next_updated_data_block.data_block_digest),
                            },
                        )
                        .is_err()
                    {
                        return task::Poll::Ready(Err(e));
                    }
                }

                task::Poll::Ready(Ok((data_block_updates_iter, Err(e))))
            }
        }
    }
}

/// [`Iterator`] over an authentication tree node's digests, merging updated
/// with retained digests.
struct AuthTreeNodeUpdatedDigestsIterator<'a> {
    original_node_data: Option<&'a [u8]>,
    updated_entries: &'a [AuthTreePendingNodeEntryUpdate],
    next_entry_index_in_node: usize,
    next_updated_entries_index: usize,
    digest_len: u8,
    digests_per_node_log2: u8,
}

impl<'a> AuthTreeNodeUpdatedDigestsIterator<'a> {
    /// Instantiate a new [`AuthTreeNodeUpdatedDigestsIterator`].
    ///
    /// # Arguments:
    ///
    /// * `original_node_data` - The nodes original data. May be `None` of all
    ///   of the node's digests have updates pending to them.
    /// * `updated_entries` - The node's updated digest entries.
    /// * `digest_len` - Length of a single digest entry stored in the node.
    /// * `digests_per_node_log2` - Base-2 logarithm of the number of digest
    ///   entries in the node.
    fn new(
        original_node_data: Option<&'a [u8]>,
        updated_entries: &'a [AuthTreePendingNodeEntryUpdate],
        digest_len: u8,
        digests_per_node_log2: u8,
    ) -> Self {
        match original_node_data {
            Some(original_node_data) => {
                debug_assert!(original_node_data.len() >= (digest_len as usize) << digests_per_node_log2);
            }
            None => {
                debug_assert_eq!(updated_entries.len(), 1usize << digests_per_node_log2);
            }
        }

        Self {
            original_node_data,
            updated_entries,
            next_entry_index_in_node: 0,
            next_updated_entries_index: 0,
            digest_len,
            digests_per_node_log2,
        }
    }
}

impl<'a> Iterator for AuthTreeNodeUpdatedDigestsIterator<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_entry_index_in_node == 1usize << self.digests_per_node_log2 {
            return None;
        }

        let entry_index_in_node = self.next_entry_index_in_node;
        self.next_entry_index_in_node += 1;
        if self.next_updated_entries_index < self.updated_entries.len()
            && entry_index_in_node == self.updated_entries[self.next_updated_entries_index].entry_index_in_node
        {
            let updated_entry_index = self.next_updated_entries_index;
            self.next_updated_entries_index += 1;
            Some(&self.updated_entries[updated_entry_index].updated_digest)
        } else {
            Some(
                self.original_node_data
                    .unwrap()
                    .chunks(self.digest_len as usize)
                    .nth(entry_index_in_node)
                    .unwrap(),
            )
        }
    }
}

/// Apply authentication tree updates from an [`AuthTreePendingNodeUpdates`].
///
/// Write the updates to storage and also, update the caches as appropriate.
pub struct AuthTreeApplyUpdatesFuture<C: chip::NvChip> {
    pending_nodes_updates: AuthTreePendingNodesUpdates,
    cur_pending_nodes_updates_index: usize,
    fut_state: AuthTreeApplyUpdatesFutureState<C>,
}

/// Internal [`AuthTreeApplyUpdatesFuture::poll()`] state-machine state.
enum AuthTreeApplyUpdatesFutureState<C: chip::NvChip> {
    Init { node_data_buf: FixedVec<u8, 7> },
    ReadUnmodifiedNode { read_node_fut: AuthTreeNodeReadFuture<C> },
    WriteUpdatedNodePrepare { updated_node_data: FixedVec<u8, 7> },
    WriteUpdatedNode { write_node_fut: AuthTreeNodeWriteFuture<C> },
    Done,
}

impl<C: chip::NvChip> AuthTreeApplyUpdatesFuture<C> {
    /// Instantiate a new [`AuthTreeApplyUpdatesFuture`].
    ///
    /// # Arguments:
    ///
    /// * `pending_nodes_updates` - The updates to apply.
    pub fn new(pending_nodes_updates: AuthTreePendingNodesUpdates) -> Self {
        Self {
            pending_nodes_updates,
            cur_pending_nodes_updates_index: 0,
            fut_state: AuthTreeApplyUpdatesFutureState::Init {
                node_data_buf: FixedVec::new_empty(),
            },
        }
    }

    /// Poll the [`AuthTreeApplyUpdatesFuture`] to completion.
    ///
    /// Upon future completion, a pair of the input
    /// [`AuthTreePendingNodesUpdates`] and the operation's result will get
    /// returned.
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `tree` - Exclusive reference to the filesystem's [`AuthTree`]
    ///   instance.
    /// * `updated_root_hmac_digest` - The updated root digest.
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    pub fn poll<ST: sync_types::SyncTypes>(
        self: pin::Pin<&mut Self>,
        chip: &C,
        tree: &mut AuthTree<ST>,
        updated_root_hmac_digest: &[u8],
        cx: &mut task::Context<'_>,
    ) -> task::Poll<(AuthTreePendingNodesUpdates, Result<(), NvFsError>)> {
        let this = pin::Pin::into_inner(self);
        let result = loop {
            match &mut this.fut_state {
                AuthTreeApplyUpdatesFutureState::Init { node_data_buf } => {
                    if this.cur_pending_nodes_updates_index == this.pending_nodes_updates.nodes_updates.len() {
                        tree.root_hmac_digest.copy_from_slice(updated_root_hmac_digest);
                        break Ok(());
                    }

                    if node_data_buf.is_empty() {
                        *node_data_buf = match FixedVec::new_with_default(tree.config.node_size()) {
                            Ok(node_data_buf) => node_data_buf,
                            Err(e) => break Err(NvFsError::from(e)),
                        };
                    }

                    let cur_pending_node_updates =
                        &this.pending_nodes_updates.nodes_updates[this.cur_pending_nodes_updates_index];
                    let (digest_entry_len, digest_entries_in_node_log2) = if cur_pending_node_updates.node_id.level > 0
                    {
                        (
                            tree.config.node_digest_len as usize,
                            tree.config.node_digests_per_node_log2,
                        )
                    } else {
                        (
                            tree.config.data_digest_len as usize,
                            tree.config.data_digests_per_node_log2,
                        )
                    };
                    debug_assert!(node_data_buf.len() >= digest_entry_len << digest_entries_in_node_log2);

                    if let Some(node_cache_entry) = tree.node_cache.get_mut().lookup(&cur_pending_node_updates.node_id)
                    {
                        // The node is in the node cache, update the cache entry and copy the
                        // node data to write out from there.
                        let cached_node = match tree.node_cache.get_mut().get_entry_mut(node_cache_entry) {
                            Some((_, cached_node)) => cached_node,
                            None => break Err(nvfs_err_internal!()),
                        };
                        Self::apply_pending_node_updates_to_buf(
                            cur_pending_node_updates,
                            &mut cached_node.data,
                            &tree.config,
                        );
                        node_data_buf.as_mut_slice().copy_from_slice(&cached_node.data);
                        this.fut_state = AuthTreeApplyUpdatesFutureState::WriteUpdatedNodePrepare {
                            updated_node_data: mem::take(node_data_buf),
                        };
                    } else if cur_pending_node_updates.updated_entries.len() == 1usize << digest_entries_in_node_log2 {
                        // All the node's digests will get updated, no parts of the unmodified one
                        // will be needed.
                        Self::apply_pending_node_updates_to_buf(cur_pending_node_updates, node_data_buf, &tree.config);
                        this.fut_state = AuthTreeApplyUpdatesFutureState::WriteUpdatedNodePrepare {
                            updated_node_data: mem::take(node_data_buf),
                        };
                    } else {
                        // Some of the nodes' entries are retained unmodified. Read the original
                        // node data to fill in the pending updates into.
                        let read_node_fut = match AuthTreeNodeReadFuture::new_with_buf(
                            chip,
                            &tree.config,
                            &cur_pending_node_updates.node_id,
                            mem::take(node_data_buf),
                        ) {
                            Ok(read_node_fut) => read_node_fut,
                            Err(e) => break Err(e),
                        };
                        this.fut_state = AuthTreeApplyUpdatesFutureState::ReadUnmodifiedNode { read_node_fut };
                    }
                }
                AuthTreeApplyUpdatesFutureState::ReadUnmodifiedNode { read_node_fut } => {
                    let mut node_data = match chip::NvChipFuture::poll(pin::Pin::new(read_node_fut), chip, cx) {
                        task::Poll::Ready(Ok(unmodified_node_data)) => unmodified_node_data,
                        task::Poll::Ready(Err(e)) => break Err(e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    // Fill in the updated entries' digests into the unmodified node data just read.
                    let cur_pending_node_updates =
                        &this.pending_nodes_updates.nodes_updates[this.cur_pending_nodes_updates_index];
                    Self::apply_pending_node_updates_to_buf(cur_pending_node_updates, &mut node_data, &tree.config);

                    this.fut_state = AuthTreeApplyUpdatesFutureState::WriteUpdatedNodePrepare {
                        updated_node_data: node_data,
                    };
                }
                AuthTreeApplyUpdatesFutureState::WriteUpdatedNodePrepare { updated_node_data } => {
                    let cur_pending_node_updates =
                        &this.pending_nodes_updates.nodes_updates[this.cur_pending_nodes_updates_index];
                    let write_node_fut = match AuthTreeNodeWriteFuture::new(
                        chip,
                        &tree.config,
                        &cur_pending_node_updates.node_id,
                        mem::take(updated_node_data),
                    )
                    .and_then(|result| result.map_err(|(_, e)| e))
                    {
                        Ok(write_node_fut) => write_node_fut,
                        Err(e) => break Err(e),
                    };
                    this.fut_state = AuthTreeApplyUpdatesFutureState::WriteUpdatedNode { write_node_fut };
                }
                AuthTreeApplyUpdatesFutureState::WriteUpdatedNode { write_node_fut } => {
                    let node_data_buf = match chip::NvChipFuture::poll(pin::Pin::new(write_node_fut), chip, cx) {
                        task::Poll::Ready(Ok((node_data_buf, Ok(())))) => node_data_buf,
                        task::Poll::Ready(Err(e) | Ok((_, Err(e)))) => break Err(e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    this.cur_pending_nodes_updates_index += 1;
                    this.fut_state = AuthTreeApplyUpdatesFutureState::Init { node_data_buf };
                }
                AuthTreeApplyUpdatesFutureState::Done => unreachable!(),
            }
        };

        this.fut_state = AuthTreeApplyUpdatesFutureState::Done;
        task::Poll::Ready((mem::take(&mut this.pending_nodes_updates), result))
    }

    fn apply_pending_node_updates_to_buf(
        pending_node_updates: &AuthTreePendingNodeUpdates,
        node_data: &mut [u8],
        tree_config: &AuthTreeConfig,
    ) {
        let (digest_entry_len, digest_entries_in_node_log2) = if pending_node_updates.node_id.level > 0 {
            (
                tree_config.node_digest_len as usize,
                tree_config.node_digests_per_node_log2,
            )
        } else {
            (
                tree_config.data_digest_len as usize,
                tree_config.data_digests_per_node_log2,
            )
        };
        debug_assert!(node_data.len() >= digest_entry_len << digest_entries_in_node_log2);

        for node_entry_update in pending_node_updates.updated_entries.iter() {
            debug_assert!(node_entry_update.entry_index_in_node < 1usize << digest_entries_in_node_log2);
            debug_assert_eq!(digest_entry_len, node_entry_update.updated_digest.len());
            let entry_digest_begin_in_node = node_entry_update.entry_index_in_node * digest_entry_len;
            let entry_digest_end_in_node = entry_digest_begin_in_node + node_entry_update.updated_digest.len();
            node_data[entry_digest_begin_in_node..entry_digest_end_in_node]
                .copy_from_slice(&node_entry_update.updated_digest);
        }
    }
}

/// Compute the number of nodes in an (assumed) complete subtree.
///
/// # Arguments:
///
/// * `subtree_root_level` - The subtree root's level, counted zero-based from
///   the leaves.
/// * `auth_tree_levels` - Total height of the containing tree.
/// * `node_digests_per_node_log2` - The value of
///   [`AuthTreeConfig::node_digests_per_node_log2`] verbatim.
/// * `node_digests_per_node_minus_one_inv_mod_u64` - Inverse of `(1 <<
///   node_digests_per_node_log2) - 1` modulo 2<sup>64</sup>, c.f.
///   [`digests_per_node_minus_one_inv_mod_u64()`].
fn auth_subtree_node_count(
    subtree_root_level: u8,
    auth_tree_levels: u8,
    node_digests_per_node_log2: u32,
    node_digests_per_node_minus_one_inv_mod_u64: u64,
) -> u64 {
    debug_assert!(auth_tree_levels >= 1);
    debug_assert!(subtree_root_level < auth_tree_levels);
    debug_assert_eq!(
        u64::trailing_bits_mask(node_digests_per_node_log2).wrapping_mul(node_digests_per_node_minus_one_inv_mod_u64),
        1
    );
    // The node count can be easily computed as a geometric sum,
    // which evaluates to
    // (2^((subtree_root_level + 1) * node_digest_per_node_block_log2) - 1) /
    // (2^node_digest_per_node_block_log2 - 1).
    // The divisior happens to equal the child node entry index mask, for
    // which the inverse modulo 2^64 is in
    // node_digests_per_node_minus_one_inv_mod_u64.
    //
    // But be careful: for unrealistically large values of
    // node_digests_per_node_block_log2, and large values of the
    // image_allocation_blocks (hence levels), the intermediate dividend value in
    // the equation above can overflow an u64 if the node count of the whole tree is
    // to be computed, i.e. if subtree_root_level == auth_tree_levels - 1.
    // It cannot overflow for proper subtrees, i.e. for
    // subtree_root_level < auth_tree_levels - 1 though (see below).
    // Also, the final result for the whole tree will fit an u64, and can get
    // computed recursively from its subtrees by
    // 2^c * S(L - 2) + 1,
    // with c := node_digests_per_node_block_log2, L:= auth_tree_levels,
    // and S(l) := auth_subtree_node_count(l) for brevity.
    //
    // To see that this fits an u64, observe first that
    // S(L - 2) <= (2^(W - 1) - 1) / (2^c - 1), with W == u64::BITS here,
    // because always L <= (W + c - 1) / c, c.f.
    // image_allocation_blocks_to_auth_tree_levels():
    // Observe that _minimizing_ L such that
    // 2^(c * (L - 1)) >= (u * image_allocation_blocks + b) / v
    // means that in particular
    // 2^(c * (L - 1)) < 2^c * (u * image_allocation_blocks + b) / v
    // (because if not, then one level less would have sufficed).
    // Set image_allocation_blocks = 2^W - 1.
    // Set v' = 2^c * b < v and therefore,
    // 2^(c * (L - 1)) < 2^c * (u * image_allocation_blocks + b) / v'
    // holds as well.
    // Expand the definitions of u and v'.
    // Note that certainly the block size b >= 2^c.
    // To eventually arrive at 2^(c*(L - 1)) < 2^W or c*(L - 1) < W,
    // c * L <= W + c - 1, therefore L <= (W + c - 1) / c.
    //
    // Note also that auth_tree_node_count_to_auth_tree_levels() enforces that upper
    // limit on the tree height.
    //
    // From that, it follows directly that (2^c - 1) * S(L - 2) <= 2^(W - 1) - 1,
    // or, via doubling, that 2 * (2^c - 1) * S(L - 2) <= 2^W - 2.
    // As 2^c >= 2, we finally obtain
    // 2^c * S(L - 2) <= 2^W - 2 or
    // 2^c * S(L - 2) + 1 <= 2^W - 1 respectively.
    //
    // So, for proper subtrees, i.e. for subtree_root_level <= auth_tree_levels - 2,
    // compute the number of nodes directly, and use a recursive approach
    // for the whole tree, subtree_root_level == auth_tree_levels - 1.
    if auth_tree_levels >= 2 && subtree_root_level == auth_tree_levels - 1 {
        return auth_subtree_node_count(
            auth_tree_levels - 2,
            auth_tree_levels,
            node_digests_per_node_log2,
            node_digests_per_node_minus_one_inv_mod_u64,
        ) * (1u64 << node_digests_per_node_log2)
            + 1;
    }

    debug_assert!(((subtree_root_level + 1) as u32) * node_digests_per_node_log2 <= 64);
    u64::trailing_bits_mask((subtree_root_level + 1) as u32 * node_digests_per_node_log2)
        .wrapping_mul(node_digests_per_node_minus_one_inv_mod_u64)
}

#[test]
fn test_auth_subtree_node_count() {
    for node_digests_per_node_log2 in 1..=64 {
        let node_digests_per_node_minus_one_inv_mod_u64 =
            digests_per_node_minus_one_inv_mod_u64(node_digests_per_node_log2);
        let auth_tree_levels = ((u64::BITS - 1) / node_digests_per_node_log2 + 1) as u8;
        let mut expected = 0u64;
        for subtree_root_level in 0..auth_tree_levels {
            if node_digests_per_node_log2 < 64 {
                let digests_per_node = 1u64 << node_digests_per_node_log2;
                expected = expected.checked_mul(digests_per_node).unwrap().checked_add(1).unwrap();
            } else {
                expected = 1;
            }
            assert_eq!(
                expected,
                auth_subtree_node_count(
                    subtree_root_level,
                    auth_tree_levels,
                    node_digests_per_node_log2,
                    node_digests_per_node_minus_one_inv_mod_u64
                )
            );
        }
    }
}

/// Compute the inverse of `(1 << digests_per_node_log2) - 1` modulo
/// 2<sup>64</sup>.
///
/// `(1 << digests_per_node_log2) - 1` is odd, hence has no common factors with
/// 2 to any power, and therefore has a unique inverse modulo any such a power.
/// That unique inverse can get computed efficiently via a Hensel lifting.
///
/// As the inverse is unique, numerators known to be divisible evenly by `(1 <<
/// digests_per_node_log2) - 1`, as is e.g. the case in the evaluation of some
/// geometric sums, can be divided efficiently my multiplying with the inverse
/// and taking the result modulo the given power of two, 2<sup>64</sup> here.
fn digests_per_node_minus_one_inv_mod_u64(digests_per_node_log2: u32) -> u64 {
    let digests_per_node_minus_one = u64::trailing_bits_mask(digests_per_node_log2);
    // (2^digests_per_node_log2 - 1) is its own inverse modulo
    // 2^digests_per_node_log2 ...
    debug_assert_eq!(
        digests_per_node_minus_one.wrapping_mul(digests_per_node_minus_one) & digests_per_node_minus_one,
        1
    );
    // ... lift it to a inverse modulo 2^64 via Hensel lifting.
    let mut e = digests_per_node_log2;
    let mut digests_per_node_minus_one_inv = digests_per_node_minus_one;
    while e < u64::BITS {
        digests_per_node_minus_one_inv = (digests_per_node_minus_one_inv << 1).wrapping_sub(
            digests_per_node_minus_one
                .wrapping_mul(digests_per_node_minus_one_inv)
                .wrapping_mul(digests_per_node_minus_one_inv),
        );
        e *= 2;
    }
    debug_assert_eq!(
        digests_per_node_minus_one_inv.wrapping_mul(digests_per_node_minus_one),
        1
    );
    digests_per_node_minus_one_inv
}

#[test]
fn test_digests_per_node_minus_one_inv_mod_u64() {
    for digests_per_node_log2 in 1u32..=64 {
        let digests_per_node_minus_one = u64::trailing_bits_mask(digests_per_node_log2 as u32);
        assert_eq!(
            digests_per_node_minus_one.wrapping_mul(digests_per_node_minus_one_inv_mod_u64(digests_per_node_log2)),
            1
        );
    }
}

/// Deduce a suitable minimum authentication tree height from the total
/// filesystem image size.
///
/// To be used at filesystem creation ("mkfs") time to fit the authentication
/// tree's dimensions to a given filesystem image size.  The authentication tree
/// height is determined as the minimum such that the storage needed for the an
/// assumed complete tree of that height itself plus the data range
/// possibly authenticated by it together span the filesystem image size at
/// least.
///
/// # Arguments:
///
/// * `image_allocation_blocks` - The desired filesystem image size.
/// * `node_digests_per_node_log2` - Base-2 logarithm of the number of digests
///   in a non-leaf node, c.f. [`AuthTreeConfig::node_digests_per_node_log2`].
/// * `node_digests_per_node_minus_one_inv_mod_u64` - Inverse of `(1 <<
///   node_digests_per_node_log2) - 1` modulo 2<sup>64</sup>, c.f.
///   [`digests_per_node_minus_one_inv_mod_u64()`].
/// * `data_digests_per_node_log2` - Base-2 logarithm of the number of digests
///   in a leaf node, c.f. [`AuthTreeConfig::data_digests_per_node_log2`].
/// * `node_allocation_blocks_log2` - The size of an authentication tree node,
///   c.f. [`AuthTreeConfig::node_allocation_blocks_log2`].
/// * `data_block_allocation_blocks_log2` - The size of an [Authentication Tree
///   Data Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2).
fn image_allocation_blocks_to_auth_tree_levels(
    image_allocation_blocks: layout::AllocBlockCount,
    node_digests_per_node_log2: u32,
    node_digests_per_node_minus_one_inv_mod_u64: u64,
    data_digests_per_node_log2: u32,
    node_allocation_blocks_log2: u32,
    data_block_allocation_blocks_log2: u32,
) -> Result<u8, NvFsError> {
    let image_allocation_blocks = u64::from(image_allocation_blocks);
    let node_digests_per_node = 1u64 << node_digests_per_node_log2;
    let node_allocation_blocks = 1u64 << node_allocation_blocks_log2;

    if image_allocation_blocks < node_allocation_blocks {
        return Err(NvFsError::from(CocoonFsFormatError::InvalidAuthTreeDimensions));
    }

    // Let t(l) denote the collective size in units of allocation blocks occupied by
    // a complete tree of height l as well as of the maximum data range covered by
    // it. Find the least l such that t(l) >= image_allocation_blocks.
    // For that, write t(l) = n(l) * b + d(l), with
    // b    := the authentication tree node size in units of allocation blocks,
    // n(l) := the number of nodes in a complete tree of height l,
    // d(l) := the maximum data range covered by a complete tree of height l in
    // units of allocation blocks.
    // The following relations hold:
    // n(l) = (2^(c*l) - 1) / (2^c - 1),
    // d(l) = 2^(c * (l - 1)) * f * s,
    // with 2^c := the number of each inner node's children,
    // f := the number of (data) digests in a leaf node and
    // s := the size of an authentication tree data block in units of allocation
    // blocks. It follows that the constraint image_allocation_blocks <= t(l) is
    // equivalent to
    // (2^c - 1) * image_allocation_blocks
    //   <= (2^c - 1) * t(l) = (2^c * b + (2^c - 1) * f * s) * 2^(c*(l - 1)) - b
    // and must be solved for minimum l.
    // Rewrite to
    // 2^(c*(l - 1)) >= (u * image_allocation_blocks + b) / v,
    // with u := 2^c - 1 and v = 2^c * b + u * f * s.
    // Because u < v and b < v, the right hand value does not overflow, but care
    // must be taken that intermediate values, the dividend to be more specific,
    // won't overflow either. So interleave the computations of the division by
    // v and the computation of the dividend, reducing intermediate values in
    // the course.
    // Handle extreme cases first:
    if node_allocation_blocks > image_allocation_blocks / 2 {
        // There won't be enough space for more than one tree node.
        return Ok(1);
    } else if u64::BITS <= data_digests_per_node_log2 + data_block_allocation_blocks_log2 {
        // A single tree node would be capable of covering all of the maximum possible
        // image_allocation_blocks.
        return Ok(1);
    } else if image_allocation_blocks - node_allocation_blocks
        <= 1u64 << (data_digests_per_node_log2 + data_block_allocation_blocks_log2)
    {
        // A single tree node would be cabable of covering all of the remaining
        // space in image_allocation_blocks, after accounting for the space the
        // node itself would consume.
        return Ok(1);
    } else if image_allocation_blocks >> node_allocation_blocks_log2 <= (1u64 << node_digests_per_node_log2) {
        // There's not enough space for two full levels worth of tree nodes.
        return Ok(2);
    } else if u64::BITS <= node_digests_per_node_log2 + data_digests_per_node_log2 + data_block_allocation_blocks_log2 {
        // Two levels would be capable of covering all of the maximum possible
        // image_allocation_blocks.
        return Ok(2);
    } else if image_allocation_blocks - (1u64 << (node_digests_per_node_log2 + node_allocation_blocks_log2))
        <= (1u64 << (node_digests_per_node_log2 + data_digests_per_node_log2 + data_block_allocation_blocks_log2))
    {
        // Two levels would be capable of covering all of the remaining space in
        // image_allocation_blocks, after accounting for the space the nodes
        // themselves would consume.
        return Ok(2);
    }

    // Remember from above, the goal is to compute
    // (u * image_allocation_blocks + b) / v.
    let u = node_digests_per_node - 1;
    let v = (1u64 << (node_digests_per_node_log2 + node_allocation_blocks_log2))
        + (u << (data_digests_per_node_log2 + data_block_allocation_blocks_log2));
    debug_assert!(u < v); // u / v = 0, u % v = u
    // First step: compute image_allocation_blocks / v.
    let mut q = image_allocation_blocks / v;
    debug_assert_ne!(q, 0);
    // Second step: compute u * image_allocation_blocks / v. Handle the intermediate
    // q and r from above separately.
    let r = image_allocation_blocks - v * q;
    q *= u; // Will not overflow, because u < v.
    // Compute u * r / v. Recall that u = 2^node_digests_per_node_log2 - 1.
    debug_assert!(r <= u64::MAX >> 1);
    let mut q_ur = 0;
    let mut r_ur = r;
    for _ in 1..node_digests_per_node_log2 {
        q_ur <<= 1;
        if r_ur >= v - r_ur {
            q_ur += 1;
            r_ur -= v - r_ur;
        } else {
            r_ur <<= 1;
        }
        if r >= v - r_ur {
            q_ur += 1;
            r_ur = r - (v - r_ur);
        } else {
            r_ur += r;
        }
    }
    q += q_ur;
    let r = if node_allocation_blocks >= v - r_ur {
        q += 1;
        node_allocation_blocks - (v - r_ur)
    } else {
        r_ur + node_allocation_blocks
    };
    if r != 0 {
        q += 1;
    }

    // Base-2 logarithm of q, rounded up.
    let q_log2 = if q != 1 { (q - 1).ilog2() + 1 } else { 0 };
    let auth_tree_levels = q_log2.div_ceil(node_digests_per_node_log2) as u8 + 1;

    // Now, t(l) >= image_allocation_blocks for the complete tree, but the final
    // tree will be a partial one truncated to make it fit
    // image_allocation_blocks. If that partial tree would have only a single
    // child at the root node, reduce the level by one. This would be the case
    // if a single subtree descendant from the root, t(l - 1), together with a
    // path tree path from top to bottom, l * b, would exceed the
    // image_allocation_blocks.
    if auth_tree_levels > 1 {
        let root_entry_subtree_node_count = auth_subtree_node_count(
            auth_tree_levels - 2,
            auth_tree_levels - 1,
            node_digests_per_node_log2,
            node_digests_per_node_minus_one_inv_mod_u64,
        );
        let root_entry_subtree_data_allocation_blocks = 1u64
            << ((auth_tree_levels - 2) as u32 * node_digests_per_node_log2
                + data_digests_per_node_log2
                + data_block_allocation_blocks_log2);
        let root_entry_subtree_total_allocation_blocks =
            (root_entry_subtree_node_count << node_allocation_blocks_log2) + root_entry_subtree_data_allocation_blocks;
        debug_assert!(root_entry_subtree_total_allocation_blocks < image_allocation_blocks);
        if image_allocation_blocks - root_entry_subtree_total_allocation_blocks
            < (auth_tree_levels as u64) << node_allocation_blocks_log2
        {
            return Ok(auth_tree_levels - 1);
        }
    }

    Ok(auth_tree_levels)
}

#[test]
fn test_image_allocation_blocks_to_auth_tree_levels() {
    assert_eq!(
        image_allocation_blocks_to_auth_tree_levels(layout::AllocBlockCount::from(0), 1, 1, 1, 0, 0),
        Err(NvFsError::from(CocoonFsFormatError::InvalidAuthTreeDimensions))
    );
    for image_allocation_blocks in 1..4 {
        assert_eq!(
            image_allocation_blocks_to_auth_tree_levels(
                layout::AllocBlockCount::from(image_allocation_blocks),
                1,
                digests_per_node_minus_one_inv_mod_u64(1),
                1,
                0,
                0
            )
            .unwrap(),
            1
        );
    }
    for image_allocation_blocks in 4..10 {
        assert_eq!(
            image_allocation_blocks_to_auth_tree_levels(
                layout::AllocBlockCount::from(image_allocation_blocks),
                1,
                digests_per_node_minus_one_inv_mod_u64(1),
                1,
                0,
                0
            )
            .unwrap(),
            2
        );
    }
    assert_eq!(
        image_allocation_blocks_to_auth_tree_levels(
            layout::AllocBlockCount::from(10),
            1,
            digests_per_node_minus_one_inv_mod_u64(1),
            1,
            0,
            0
        )
        .unwrap(),
        3
    );

    for image_allocation_blocks in [1u64 << 8, 1u64 << 11, 1u64 << 16, 1u64 << 17, 1u64 << 63, !0u64] {
        for node_allocation_blocks_log2 in (0..17).chain([63]) {
            for node_digests_per_node_log2 in [1u32, node_allocation_blocks_log2 + 1, node_allocation_blocks_log2 + 2] {
                if node_digests_per_node_log2 >= u64::BITS {
                    break;
                }
                let data_digests_per_node_log2 = node_digests_per_node_log2;
                let digests_per_node_minus_one_inv_mod_u64 =
                    digests_per_node_minus_one_inv_mod_u64(node_digests_per_node_log2);
                for data_block_allocation_blocks_log2 in 0..(64 - node_digests_per_node_log2) {
                    if image_allocation_blocks < (1u64 << node_allocation_blocks_log2) {
                        assert_eq!(
                            image_allocation_blocks_to_auth_tree_levels(
                                layout::AllocBlockCount::from(image_allocation_blocks),
                                node_digests_per_node_log2,
                                digests_per_node_minus_one_inv_mod_u64,
                                data_digests_per_node_log2,
                                node_allocation_blocks_log2,
                                data_block_allocation_blocks_log2,
                            ),
                            Err(NvFsError::from(CocoonFsFormatError::InvalidAuthTreeDimensions))
                        );
                        continue;
                    }
                    let auth_tree_levels = image_allocation_blocks_to_auth_tree_levels(
                        layout::AllocBlockCount::from(image_allocation_blocks),
                        node_digests_per_node_log2,
                        digests_per_node_minus_one_inv_mod_u64,
                        data_digests_per_node_log2,
                        node_allocation_blocks_log2,
                        data_block_allocation_blocks_log2,
                    )
                    .unwrap();
                    assert!(auth_tree_levels != 0);

                    // Verify: The space occupied by a complete tree should, together with the range
                    // covered by it, be >= the image size.
                    let auth_tree_node_count = auth_subtree_node_count(
                        auth_tree_levels - 1,
                        auth_tree_levels,
                        node_digests_per_node_log2,
                        digests_per_node_minus_one_inv_mod_u64,
                    );

                    // A tree with one level less should not be sufficient to cover all
                    // of the available space.
                    if auth_tree_levels > 1 {
                        assert!(
                            (((auth_tree_node_count - 1) >> node_digests_per_node_log2) << node_allocation_blocks_log2)
                                + (1u64
                                    << ((auth_tree_levels - 2) as u32 * node_digests_per_node_log2
                                        + data_digests_per_node_log2
                                        + data_block_allocation_blocks_log2))
                                < image_allocation_blocks
                        );
                    }

                    if (auth_tree_levels - 1) as u32 * node_digests_per_node_log2
                        + data_digests_per_node_log2
                        + data_block_allocation_blocks_log2
                        >= u64::BITS
                    {
                        // The data range covered exceeds an u64, so it's definitely larger than
                        // image_allocation_blocks.
                        continue;
                    }
                    let max_covered_data_allocation_blocks = 1u64
                        << ((auth_tree_levels - 1) as u32 * node_digests_per_node_log2
                            + data_digests_per_node_log2
                            + data_block_allocation_blocks_log2);
                    if u64::MAX - max_covered_data_allocation_blocks
                        < (auth_tree_node_count << node_allocation_blocks_log2)
                    {
                        // Collective tree nodes size plus covered data range
                        // exceeds an u64, so also definitely greater than
                        // image_allocation_blocks.
                        continue;
                    }
                    let t = (auth_tree_node_count << node_allocation_blocks_log2) + max_covered_data_allocation_blocks;
                    // There might be some excess space not allowing for an additional full path
                    // from the root all the way to the bottom in a tree with one more level.
                    let incomplete_path_allocation_blocks = (auth_tree_levels as u64) << node_allocation_blocks_log2;
                    assert!(
                        u64::MAX - t < incomplete_path_allocation_blocks
                            || t + incomplete_path_allocation_blocks >= image_allocation_blocks
                    );
                }
            }
        }
    }
}

/// Deduce suitable authentication tree dimensions from the total filesystem
/// image size.
///
/// To be used at filesystem creation ("mkfs") time to fit the authentication
/// tree's dimensions to a given filesystem image size. Crop an assumed full
/// authentication tree of height `auth_tree_levels` to a partial tree of
/// minimum size such that the storage needed for the tree itself plus the data
/// range possibly authenticated by it together still span as much of the
/// filesystem image size as possible.
///
/// The result will be returned as a pair of authentication tree node count
/// and the size of any filesystem image remainder space, which is
/// beyond the data range possibly authenticated by the tree of found
/// dimensions, hence cannot be used by the filesystem.
///
/// * `image_allocation_blocks` - The desired filesystem image size.
/// * `auth_tree_levels` - Height of the authentication tree as determined by
///   [`image_allocation_blocks_to_auth_tree_levels()`].
/// * `node_digests_per_node_log2` - Base-2 logarithm of the number of digests
///   in a non-leaf node, c.f. [`AuthTreeConfig::node_digests_per_node_log2`].
/// * `node_digests_per_node_minus_one_inv_mod_u64` - Inverse of
///   `node_digests_per_node_log2 - 1` modulo 2<sup>64</sup>, c.f.
///   [`digests_per_node_minus_one_inv_mod_u64()`].
/// * `data_digests_per_node_log2` - Base-2 logarithm of the number of digests
///   in a leaf node, c.f. [`AuthTreeConfig::data_digests_per_node_log2`].
/// * `node_allocation_blocks_log2` - The size of an authentication tree node,
///   c.f. [`AuthTreeConfig::node_allocation_blocks_log2`].
/// * `data_block_allocation_blocks_log2` - The size of an [Authentication Tree
///   Data Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2).
fn image_allocation_blocks_to_auth_tree_node_count(
    image_allocation_blocks: layout::AllocBlockCount,
    auth_tree_levels: u8,
    node_digests_per_node_log2: u32,
    node_digests_per_node_minus_one_inv_mod_u64: u64,
    data_digests_per_node_log2: u32,
    node_allocation_blocks_log2: u32,
    data_block_allocation_blocks_log2: u32,
) -> (u64, layout::AllocBlockCount) {
    let mut image_allocation_blocks = u64::from(image_allocation_blocks);

    // Truncate a (virtual) complete authentication tree of height auth_tree_levels
    // such that it and the data covered by it will fit image_allocation_blocks.
    // Proceed from top to bottom: at each node account for the complete descendant
    // subtrees emerging from it and descend into the partial one, if any.
    let node_allocation_blocks = 1u64 << node_allocation_blocks_log2;
    if image_allocation_blocks < node_allocation_blocks {
        return (0, layout::AllocBlockCount::from(image_allocation_blocks));
    }

    // Number of nodes in a complete subtree emerging from a node at the current
    // level and data range covered by a complete subtree emerging from a node
    // at the current level.
    let (mut entry_subtree_node_count, mut entry_subtree_data_allocation_blocks) = if auth_tree_levels >= 2 {
        (
            auth_subtree_node_count(
                auth_tree_levels - 2,
                auth_tree_levels - 1,
                node_digests_per_node_log2,
                node_digests_per_node_minus_one_inv_mod_u64,
            ),
            1u64 << ((auth_tree_levels - 2) as u32 * node_digests_per_node_log2
                + data_digests_per_node_log2
                + data_block_allocation_blocks_log2),
        )
    } else {
        (
            0,
            1u64 << (data_digests_per_node_log2 + data_block_allocation_blocks_log2),
        )
    };

    let mut auth_tree_node_count = 0;
    let mut level = auth_tree_levels;
    while level > 0 {
        level -= 1;

        let entry_subtree_total_allocation_blocks =
            (entry_subtree_node_count << node_allocation_blocks_log2) + entry_subtree_data_allocation_blocks;

        // Account for the current root node itself.
        image_allocation_blocks -= node_allocation_blocks;
        auth_tree_node_count += 1;
        // Complete subtrees descendant of the current root node.
        let full_subtree_count = image_allocation_blocks / entry_subtree_total_allocation_blocks;
        image_allocation_blocks -= full_subtree_count * entry_subtree_total_allocation_blocks;
        auth_tree_node_count += full_subtree_count * entry_subtree_node_count;

        if image_allocation_blocks < (level as u64) << node_allocation_blocks_log2 {
            // Not enough space left for even a single tree path down to the bottom.
            break;
        }

        if level != 0 {
            // Update for the next iteration.
            entry_subtree_node_count = (entry_subtree_node_count - 1) >> node_digests_per_node_log2;
            entry_subtree_data_allocation_blocks >>= node_digests_per_node_log2;
        }
    }

    debug_assert!(level != 0 || image_allocation_blocks < (1u64 << data_block_allocation_blocks_log2));

    (
        auth_tree_node_count,
        layout::AllocBlockCount::from(image_allocation_blocks),
    )
}

/// Infer the authentication tree height from its node count.
///
/// Find the minimum tree height such that an (assumed) complete tree of that
/// height would have `auth_tree_node_count` nodes at least.
///
/// # Arguments:
///
/// * `auth_tree_node_count` - The tree's total node count, as deduced from e.g.
///   the storage size occupied by it.
/// * `node_digests_per_node_log2` - Base-2 logarithm of the number of digests
///   in a non-leaf node, c.f. [`AuthTreeConfig::node_digests_per_node_log2`].
/// * `data_digests_per_node_log2` - Base-2 logarithm of the number of digests
///   in a leaf node, c.f. [`AuthTreeConfig::data_digests_per_node_log2`].
/// * `data_block_allocation_blocks_log2` - The size of an [Authentication Tree
///   Data Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2).
fn auth_tree_node_count_to_auth_tree_levels(
    auth_tree_node_count: u64,
    node_digests_per_node_log2: u32,
    data_digests_per_node_log2: u32,
    data_block_allocation_blocks_log2: u32,
) -> Result<u8, NvFsError> {
    if auth_tree_node_count == 0 {
        return Err(CocoonFsFormatError::InvalidAuthTreeDimensions.into());
    }
    debug_assert!(0 < node_digests_per_node_log2 && node_digests_per_node_log2 <= u64::BITS);

    // When deducing the Authentication Tree shape from the size of its extents,
    // i.e. the node count, it may happen that the extent padding (to align with
    // the Authentication Tree Data Block size) would add another level to
    // what's originally been computed by
    // image_allocation_blocks_to_auth_tree_levels().
    // Furthermore, attackers might attempt to present large Authentication Tree
    // extents to cause integer overflows.
    //
    // Limit the tree height such that
    // a.) The number of nodes in a complete tree of that height would still fit an
    //     u64.
    // b.) The data range covered by any proper subtree in units of
    //     Allocation Blocks is <= 2^63 in length.
    //
    // Both are possible without ever dropping to below the value originally
    // computed by image_allocation_blocks_to_auth_tree_levels(), therefore the
    // height capping really only ever splits off padding nodes, if any.
    //
    // For what follows, denote W = u64::BITS, c = node_digests_per_node_log2,
    // d = data_digests_per_node_log2, a = data_block_allocation_blocks_log2.
    //
    // For a.), the upper limit is L <= (W + c - 1) / c, c.f. the discussion in
    // auth_subtree_node_count().
    //
    // For b.) note that if L >= (W - d - a + c - 1) / c + 1,
    // then a complete Authentication Tree of L levels covers at least 2^W
    // Allocation Blocks. However, at the same time, if L is less or equal than
    // that value, which happens to equal (W - 1 - d - a) / c + 2, then a
    // subtree of height strictly less than L would cover <= 2^(W - 1)
    // Allocation Blocks. Thus, capping L at that value achieves the desired
    // property without limiting the Authentication Tree's covered data region
    // in practice.
    let max_auth_tree_levels = u64::BITS
        .min(u64::BITS - data_digests_per_node_log2 - data_block_allocation_blocks_log2 + node_digests_per_node_log2)
        .div_ceil(node_digests_per_node_log2) as u8;

    let t = if node_digests_per_node_log2 != u64::BITS {
        auth_tree_node_count - ((auth_tree_node_count - 1) >> node_digests_per_node_log2)
    } else {
        auth_tree_node_count
    };
    debug_assert_ne!(t, 0);
    let t = match t.round_up_next_pow2() {
        Some(t) => t,
        None => return Ok(max_auth_tree_levels),
    };
    let levels_minus_one = t.ilog2().div_ceil(node_digests_per_node_log2) as u8;
    Ok((levels_minus_one + 1).min(max_auth_tree_levels))
}

#[test]
fn test_auth_tree_node_count_to_auth_tree_levels() {
    for node_digests_per_node_log2 in 1u32..=64 {
        for auth_tree_levels in 1..=u64::BITS.div_ceil(node_digests_per_node_log2) as u8 {
            let auth_tree_node_count = auth_subtree_node_count(
                auth_tree_levels - 1,
                auth_tree_levels,
                node_digests_per_node_log2,
                digests_per_node_minus_one_inv_mod_u64(node_digests_per_node_log2),
            );
            assert_eq!(
                auth_tree_levels,
                auth_tree_node_count_to_auth_tree_levels(auth_tree_node_count, node_digests_per_node_log2, 0, 0)
                    .unwrap()
            );
            if auth_tree_node_count != 1 {
                assert_eq!(
                    auth_tree_levels,
                    auth_tree_node_count_to_auth_tree_levels(
                        auth_tree_node_count - 1,
                        node_digests_per_node_log2,
                        0,
                        0
                    )
                    .unwrap()
                );
            }
            if (auth_tree_levels as u32) * node_digests_per_node_log2 < 64 {
                assert_eq!(
                    auth_tree_levels + 1,
                    auth_tree_node_count_to_auth_tree_levels(
                        auth_tree_node_count + 1,
                        node_digests_per_node_log2,
                        0,
                        0
                    )
                    .unwrap()
                );
            } else if auth_tree_node_count != u64::MAX {
                assert_eq!(
                    auth_tree_node_count_to_auth_tree_levels(
                        auth_tree_node_count + 1,
                        node_digests_per_node_log2,
                        0,
                        0
                    )
                    .unwrap(),
                    auth_tree_levels
                );
            }
        }
    }
}

/// Infer the maximum possible data range authenticated by some authentication
/// tree from its node count.
///
/// # Arguments:
///
/// * `auth_tree_node_count` - The tree's total node count, as deduced from e.g.
///   the storage size occupied by it.
/// * auth_tree_levels` - The authentication tree's height as computed via
///   [`auth_tree_node_count_to_auth_tree_levels()`].
/// * `node_digests_per_node_log2` - Base-2 logarithm of the number of digests
///   in a non-leaf node, c.f. [`AuthTreeConfig::node_digests_per_node_log2`].
/// * `node_digests_per_node_minus_one_inv_mod_u64` - Inverse of
///   `node_digests_per_node_log2 - 1` modulo 2<sup>64</sup>, c.f.
///   [`digests_per_node_minus_one_inv_mod_u64()`].
/// * `data_digests_per_node_log2` - Base-2 logarithm of the number of digests
///   in a leaf node, c.f. [`AuthTreeConfig::data_digests_per_node_log2`].
/// * `data_block_allocation_blocks_log2` - The size of an [Authentication Tree
///   Data Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2).
fn auth_tree_node_count_to_max_covered_data_block_count(
    mut auth_tree_node_count: u64,
    auth_tree_levels: u8,
    node_digests_per_node_log2: u32,
    node_digests_per_node_minus_one_inv_mod_u64: u64,
    data_digests_per_node_log2: u32,
    data_block_allocation_blocks_log2: u32,
) -> Result<u64, NvFsError> {
    if auth_tree_node_count == 0 {
        return Err(CocoonFsFormatError::InvalidAuthTreeDimensions.into());
    }
    debug_assert!(0 < node_digests_per_node_log2 && node_digests_per_node_log2 < u64::BITS);
    debug_assert!(0 < data_digests_per_node_log2 && data_digests_per_node_log2 < u64::BITS);
    debug_assert_eq!(
        auth_tree_levels,
        auth_tree_node_count_to_auth_tree_levels(
            auth_tree_node_count,
            node_digests_per_node_log2,
            data_digests_per_node_log2,
            data_block_allocation_blocks_log2
        )
        .unwrap()
    );

    if auth_tree_levels == 1 {
        debug_assert_eq!(auth_tree_node_count, 1);
        return Ok(1u64 << data_digests_per_node_log2);
    }

    // Traverse the tree from top to bottom, at each level account for the
    // Authentication Tree data block range covered by the complete subtrees rooted
    // at the current node's entries and descend into the partial one, if any.
    let mut max_covered_data_block_count = 0u64;
    let mut level = auth_tree_levels;
    // The number of nodes in a complete tree is guaranteed to fit an u64,
    // c.f. auth_tree_node_count_to_auth_tree_levels().
    let mut entry_subtree_node_count = auth_subtree_node_count(
        auth_tree_levels - 1,
        auth_tree_levels,
        node_digests_per_node_log2,
        node_digests_per_node_minus_one_inv_mod_u64,
    );
    while level > 1 && auth_tree_node_count != 0 {
        if auth_tree_node_count < level as u64 {
            // No complete path from the current node down to the bottom
            // left, meaning the current node is padding.
            auth_tree_node_count = 0;
            break;
        }
        level -= 1;
        // Remove the current node.
        auth_tree_node_count -= 1;
        // Recursively calculate the new subtree node count for one level less.
        entry_subtree_node_count = (entry_subtree_node_count - 1) >> node_digests_per_node_log2;
        // Remove all complete subtrees rooted at entries from the current node.
        let full_entries_in_node = auth_tree_node_count / entry_subtree_node_count;
        debug_assert!(full_entries_in_node <= 1u64 << node_digests_per_node_log2);
        auth_tree_node_count -= full_entries_in_node * entry_subtree_node_count;
        // And account for the Authentication Tree Data Block ranges covered by those.
        // The range covered by a single, proper subtree is guaranteed to fit an u64,
        // c.f. auth_tree_node_count_to_auth_tree_levels().
        debug_assert!(((level - 1) as u32 * node_digests_per_node_log2 + data_digests_per_node_log2 < u64::BITS));
        if level == auth_tree_levels - 1 {
            // The root node's full entries could collectively cover a wider range
            // than would be representable in an u64. Note that this can happen if the
            // originally truncated tree
            // (image_allocation_blocks_to_auth_tree_node_count()) gets extended by padding
            // nodes.
            if full_entries_in_node
                >= 1u64 << (u64::BITS - ((level - 1) as u32 * node_digests_per_node_log2 + data_digests_per_node_log2))
            {
                return Ok(u64::MAX);
            }
        } else {
            // When in a subtree known to be partial, then at least one of the descendant
            // subtrees rooted at the current subtree root must be partial.
            debug_assert!(full_entries_in_node < 1u64 << node_digests_per_node_log2);
        }
        let full_subtrees_covered_data_blocks_count =
            full_entries_in_node << ((level - 1) as u32 * node_digests_per_node_log2 + data_digests_per_node_log2);
        max_covered_data_block_count =
            match max_covered_data_block_count.checked_add(full_subtrees_covered_data_blocks_count) {
                Some(max_covered_data_block_count) => max_covered_data_block_count,
                None => {
                    // The range covered by a single, proper subtree is guaranteed to fit an u64,
                    // c.f. auth_tree_node_count_to_auth_tree_levels() and is a power of two. Hence
                    // overflows (to zero) can only occur when adding full entries at the
                    // root node level. The root level case had been checked above.
                    return Err(nvfs_err_internal!());
                }
            };
    }
    debug_assert_eq!(auth_tree_node_count, 0);
    Ok(max_covered_data_block_count)
}

#[test]
fn test_auth_tree_node_count_to_max_covered_data_block_count() {
    for node_digests_per_node_log2 in 1..17 {
        let node_digests_per_node_minus_one_inv_mod_u64 =
            digests_per_node_minus_one_inv_mod_u64(node_digests_per_node_log2);
        let data_digests_per_node_log2 = node_digests_per_node_log2;
        assert_eq!(
            auth_tree_node_count_to_max_covered_data_block_count(
                1,
                1,
                node_digests_per_node_log2,
                node_digests_per_node_minus_one_inv_mod_u64,
                data_digests_per_node_log2,
                0,
            )
            .unwrap(),
            1u64 << node_digests_per_node_log2
        );

        for auth_tree_levels in 2u8..(((u64::BITS - data_digests_per_node_log2) + node_digests_per_node_log2 - 1)
                / node_digests_per_node_log2) as u8
                + 1 // For the leaf level.
                + 1
        // For making the iteration boundary inclusive.
        {
            let root_entry_subtree_node_count = auth_subtree_node_count(
                auth_tree_levels - 2,
                auth_tree_levels,
                node_digests_per_node_log2,
                node_digests_per_node_minus_one_inv_mod_u64,
            );
            for full_entries_in_root in 1..(1u64 << node_digests_per_node_log2) {
                // Incomplete paths from top to bottom in partial root entry.
                if auth_tree_levels > 2 {
                    for p in 1..auth_tree_levels - 1 {
                        assert_eq!(
                            auth_tree_node_count_to_max_covered_data_block_count(
                                full_entries_in_root * root_entry_subtree_node_count + 1 + p as u64,
                                auth_tree_levels,
                                node_digests_per_node_log2,
                                node_digests_per_node_minus_one_inv_mod_u64,
                                data_digests_per_node_log2,
                                0,
                            )
                            .unwrap(),
                            full_entries_in_root
                                << ((auth_tree_levels - 2) as u32 * node_digests_per_node_log2
                                    + data_digests_per_node_log2)
                        );
                    }
                }

                // Complete subtrees + a single path down from the root all the way to the
                // bottom.
                assert_eq!(
                    auth_tree_node_count_to_max_covered_data_block_count(
                        full_entries_in_root * root_entry_subtree_node_count + auth_tree_levels as u64,
                        auth_tree_levels,
                        node_digests_per_node_log2,
                        node_digests_per_node_minus_one_inv_mod_u64,
                        data_digests_per_node_log2,
                        0,
                    )
                    .unwrap(),
                    (full_entries_in_root
                        << ((auth_tree_levels - 2) as u32 * node_digests_per_node_log2 + data_digests_per_node_log2))
                        + (1u64 << data_digests_per_node_log2)
                );

                // Only complete subtrees emerging from the root.
                if u64::MAX
                    - (full_entries_in_root
                        << ((auth_tree_levels - 2) as u32 * node_digests_per_node_log2 + data_digests_per_node_log2))
                    < 1u64 << ((auth_tree_levels - 2) as u32 * node_digests_per_node_log2 + data_digests_per_node_log2)
                {
                    // The data range covered by one more complete tree entry would exceed an u64.
                    break;
                }
                assert_eq!(
                    auth_tree_node_count_to_max_covered_data_block_count(
                        1 + (full_entries_in_root + 1) * root_entry_subtree_node_count,
                        auth_tree_levels,
                        node_digests_per_node_log2,
                        node_digests_per_node_minus_one_inv_mod_u64,
                        data_digests_per_node_log2,
                        0,
                    )
                    .unwrap(),
                    (full_entries_in_root + 1)
                        << ((auth_tree_levels - 2) as u32 * node_digests_per_node_log2 + data_digests_per_node_log2)
                );
            }
        }
    }
}

/// Compute an authentication tree node's DFS pre index.
///
/// The node whose DFS pre index within the tree to compute is identified by the
/// pair of `covered_data_block_index` and `level`.
///
/// # Arguments:
///
/// * `covered_data_block_index` - [Authentication Tree Data Block index domain
///   index](AuthTreeDataBlockIndex) of some [Authentication Tree Data
///   Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
///   authenticated by the subtree rooted at the node in question.
/// * `level` - Level of the node within the the tree, counted zero-based from
///   the leaves.
/// * auth_tree_levels` - The authentication tree's height.
/// * `node_digests_per_node_log2` - Base-2 logarithm of the number of digests
///   in a non-leaf node, c.f. [`AuthTreeConfig::node_digests_per_node_log2`].
/// * `node_digests_per_node_minus_one_inv_mod_u64` - Inverse of
///   `node_digests_per_node_log2 - 1` modulo 2<sup>64</sup>, c.f.
///   [`digests_per_node_minus_one_inv_mod_u64()`].
/// * `data_digests_per_node_log2` - Base-2 logarithm of the number of digests
///   in a leaf node, c.f. [`AuthTreeConfig::data_digests_per_node_log2`].
fn auth_tree_node_dfs_pre_index(
    covered_data_block_index: AuthTreeDataBlockIndex,
    level: u8,
    auth_tree_levels: u8,
    node_digests_per_node_log2: u32,
    node_digests_per_node_minus_one_inv_mod_u64: u64,
    data_digests_per_node_log2: u32,
) -> (u64, usize) {
    debug_assert!(auth_tree_levels > 0);
    debug_assert!(level < auth_tree_levels);

    let child_entry_index_mask = u64::trailing_bits_mask(node_digests_per_node_log2);
    let (mut index, entry_in_node_index) = if level != 0 {
        let index = u64::from(covered_data_block_index)
            >> ((level - 1) as u32 * node_digests_per_node_log2 + data_digests_per_node_log2);
        (index >> node_digests_per_node_log2, index & child_entry_index_mask)
    } else {
        let index = u64::from(covered_data_block_index);
        (
            index >> data_digests_per_node_log2,
            index & u64::trailing_bits_mask(data_digests_per_node_log2),
        )
    };
    let entry_in_node_index = entry_in_node_index as usize;
    if level + 1 == auth_tree_levels {
        return (0, entry_in_node_index);
    }

    // Calculate the DFS PRE index of the Authentication Tree node at the requested
    // level on the path to the given data block: traverse the tree from bottom
    // to top, at each (parent) node account for the complete subtrees rooted at the
    // preceeding sibling entries each as well as for the parent node itself and
    // move further up.
    // The Authentication Tree's total node count will always fit an u64, c.f.
    // the reasoning in auth_subtree_node_count(). Thus, the computation of
    // node_dfs_pre_index, which is strictly less than that, won't overflow either.
    let mut node_dfs_pre_index = 0;
    // The size of each subtree rooted right below the current parent node level.
    let mut entry_subtree_node_count = auth_subtree_node_count(
        level,
        auth_tree_levels,
        node_digests_per_node_log2,
        node_digests_per_node_minus_one_inv_mod_u64,
    );
    for _parent_level in level + 1..auth_tree_levels {
        let entry_in_parent_node = index & child_entry_index_mask;
        index >>= node_digests_per_node_log2;

        // Skip all the preceeding siblings' subtree nodes.
        node_dfs_pre_index += entry_subtree_node_count * entry_in_parent_node;
        // And account for the current parent node itself.
        node_dfs_pre_index += 1;

        // Calculate the next round's subtree node count recursively.
        // In the very last round, this can overflow but won't get used.
        entry_subtree_node_count = (entry_subtree_node_count << node_digests_per_node_log2).wrapping_add(1);
    }
    (node_dfs_pre_index, entry_in_node_index)
}

/// Initialize the authentication tree at filesystem creation ("mkfs") time.
///
/// The authentication tree's contents are initialized by a single pass over all
/// of its authenticated data range. Initially allocated data regions' contents
/// are supposed to get recorded via [`update()`](Self::update), while unused
/// regions initially in unallocated state must get skipped over by advancing
/// the `AuthTreeInitializationCursor` past them
/// via [`advance_to()`](Self::advance_to). Note that this scheme enables
/// interleaving of the actual data initialization writes with the corresponding
/// authentication tree updates.
///
/// When done, i.e. after the cursor has eventually been moved all the way to
/// the filesystem image's end, [`finalize_into()`](Self::finalize_into) is to
/// get invoked in order to obtain the initial authentication tree's root
/// digest.
pub struct AuthTreeInitializationCursor {
    root_path_nodes: Vec<AuthTreeNode>,
    image_header_end: layout::PhysicalAllocBlockIndex,
    image_size: layout::AllocBlockCount,
    aligned_image_size: layout::AllocBlockCount,
    data_block_hmac_instance_init: hash::HmacInstance,
    digest_cur_data_block_context: AuthTreeDigestDataBlockContext,
    cur_physical_allocation_block_index: layout::PhysicalAllocBlockIndex,
    cur_data_block_index: AuthTreeDataBlockIndex,
    cur_contiguous_data_blocks_range_end: AuthTreeDataBlockIndex,
}

impl AuthTreeInitializationCursor {
    /// Create a new [`AuthTreeInitializationCursor`].
    ///
    /// # Arguments:
    ///
    /// * `tree_config` - The to be created filesystem's [`AuthTreeConfig`].
    /// * `image_header_end` - [End of the filesystem image header on
    ///   storage](MutableImageHeader::physical_location).
    /// * `image_size` - The to be created filesystem's image size.
    pub fn new(
        tree_config: &AuthTreeConfig,
        image_header_end: layout::PhysicalAllocBlockIndex,
        image_size: layout::AllocBlockCount,
    ) -> Result<Box<Self>, NvFsError> {
        let aligned_image_size = layout::AllocBlockCount::from(
            u64::from(image_size)
                .round_up_pow2(tree_config.data_block_allocation_blocks_log2 as u32)
                .ok_or_else(|| nvfs_err_internal!())?,
        );

        let mut root_path_nodes = Vec::new();
        root_path_nodes.try_reserve_exact(tree_config.auth_tree_levels as usize)?;
        let node_size = tree_config.node_size();
        for _ in 0..tree_config.auth_tree_levels {
            let data = FixedVec::new_with_default(node_size)?;
            root_path_nodes.push(AuthTreeNode { data });
        }

        let data_block_hmac_instance_init =
            hash::HmacInstance::new(tree_config.data_hmac_hash_alg, &tree_config.data_hmac_key)?;
        let digest_cur_data_block_context = AuthTreeDigestDataBlockContext::new(
            data_block_hmac_instance_init.try_clone()?,
            tree_config.data_block_allocation_blocks_log2,
            tree_config.allocation_block_size_128b_log2,
        );

        // Determine the first contiguous range of data covered by the Authentication
        // Tree.
        let (cur_physical_allocation_block_index, cur_contiguous_data_blocks_range_end) = match tree_config
            .auth_tree_data_allocation_blocks_map
            .iter_data_range_mapping(&AuthTreeDataAllocBlockRange::new(
                AuthTreeDataAllocBlockIndex::from(0u64),
                AuthTreeDataAllocBlockIndex::from(u64::MAX >> (tree_config.allocation_block_size_128b_log2 as u32 + 7)),
            ))
            .next()
        {
            Some((cur_contiguous_data_allocation_blocks_range, cur_physical_allocation_block_index)) => (
                cur_physical_allocation_block_index,
                AuthTreeDataBlockIndex::new_from_data_allocation_block_index(
                    cur_contiguous_data_allocation_blocks_range.end(),
                    tree_config.data_block_allocation_blocks_log2 as u32,
                ),
            ),
            None => {
                return Err(NvFsError::from(CocoonFsFormatError::InvalidAuthTreeDimensions));
            }
        };

        box_try_new(Self {
            root_path_nodes,
            image_header_end,
            image_size,
            aligned_image_size,
            data_block_hmac_instance_init,
            digest_cur_data_block_context,
            cur_physical_allocation_block_index,
            cur_data_block_index: AuthTreeDataBlockIndex::from(0u64),
            cur_contiguous_data_blocks_range_end,
        })
        .map_err(NvFsError::from)
    }

    /// Get the cursor's current position.
    pub fn next_physical_allocation_block_index(&self) -> layout::PhysicalAllocBlockIndex {
        self.cur_physical_allocation_block_index
    }

    /// Advance the cursor to a specified position.
    ///
    /// Advance the cursor to the specified position at
    /// `to_physical_allocation_block_index`, recording any [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) skipped
    /// over as unallocated. The returned
    /// [`AuthTreeInitializationCursorAdvanceFuture`] assumes ownership of the
    /// cursor and must get polled to completion in order to  fill in any
    /// incomplete subtrees before the point, write those out and to
    /// eventually obtain the (advanced) cursor back.
    ///
    /// On error, a pair of the input cursor and the error reason wrapped in an
    /// `Err` is returned back.
    ///
    /// # Arguments:
    ///
    /// * `to_physical_allocation_block_index` - Target position to advance the
    ///   cursor to.
    pub fn advance_to<C: chip::NvChip>(
        self: Box<Self>,
        to_physical_allocation_block_index: layout::PhysicalAllocBlockIndex,
    ) -> Result<AuthTreeInitializationCursorAdvanceFuture<C>, (Box<Self>, NvFsError)> {
        AuthTreeInitializationCursorAdvanceFuture::new(self, to_physical_allocation_block_index)
    }

    /// Record some [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) data at the
    /// cursor's current position.
    ///
    /// Record the `allocation_block_data` at the cursor's current position and
    /// advance the cursor past it. Depending of whether moving the cursor
    /// past the current [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) results
    /// in some subtrees having become completed, either
    /// * [`AuthTreeInitializationCursorUpdateResult::NeedAuthTreePartWrite`]
    ///   wrapping a [future](AuthTreeInitializationCursorWritePartFuture) for
    ///   writing out any completed parts gets returned -- polling it to
    ///   completion will eventually yield the cursor back.
    /// * Otherwise the cursor is returned directly, wrapped in a
    ///   [`AuthTreeInitializationCursorUpdateResult::Done`].
    pub fn update<C: chip::NvChip>(
        mut self: Box<Self>,
        tree_config: &AuthTreeConfig,
        allocation_block_data: &[u8],
    ) -> Result<AuthTreeInitializationCursorUpdateResult<C>, NvFsError> {
        if self.cur_physical_allocation_block_index >= layout::PhysicalAllocBlockIndex::from(0u64) + self.image_size {
            return Err(nvfs_err_internal!());
        }

        // The image header is not authenticated, enforce that.
        self.digest_cur_data_block_context.update(
            (self.image_header_end <= self.cur_physical_allocation_block_index).then_some(allocation_block_data),
        )?;
        self.cur_physical_allocation_block_index += layout::AllocBlockCount::from(1u64);

        let at_image_end =
            self.cur_physical_allocation_block_index == layout::PhysicalAllocBlockIndex::from(0u64) + self.image_size;
        if at_image_end
            || u64::from(self.cur_physical_allocation_block_index)
                .is_aligned_pow2(tree_config.data_block_allocation_blocks_log2 as u32)
        {
            // If within the image's last Authentication Tree Data Block, complete it with
            // unallocated Allocation Blocks.
            if at_image_end {
                for _ in 0..u64::from(self.aligned_image_size - self.image_size) {
                    self.digest_cur_data_block_context.update(None)?;
                    self.cur_physical_allocation_block_index += layout::AllocBlockCount::from(1u64);
                }
            }

            let data_block_entry_in_leaf_node = (u64::from(self.cur_data_block_index)
                & u64::trailing_bits_mask(tree_config.data_digests_per_node_log2 as u32))
                as usize;
            let digest_cur_data_block_context = mem::replace(
                &mut self.digest_cur_data_block_context,
                AuthTreeDigestDataBlockContext::new(
                    self.data_block_hmac_instance_init.try_clone()?,
                    tree_config.data_block_allocation_blocks_log2,
                    tree_config.allocation_block_size_128b_log2,
                ),
            );
            digest_cur_data_block_context.finalize_into(
                self.root_path_nodes[0]
                    .get_digest_mut(data_block_entry_in_leaf_node, tree_config.data_digest_len as usize),
                self.cur_data_block_index,
            )?;

            self.cur_auth_tree_data_block_index_step(tree_config)?;
            // What to do next depends on whether an Authentication Tree Node boundary has
            // been crossed: if so, make the caller to write out. Also, if the end of the
            // image has been reached, let it write the remainder out (with
            // zeroes filled in for the nodes' excess digest entries).
            if !at_image_end
                && u64::from(self.cur_data_block_index)
                    & u64::trailing_bits_mask(tree_config.data_digests_per_node_log2 as u32)
                    != 0
            {
                Ok(AuthTreeInitializationCursorUpdateResult::Done { cursor: self })
            } else {
                Ok(AuthTreeInitializationCursorUpdateResult::NeedAuthTreePartWrite {
                    write_fut: AuthTreeInitializationCursorWritePartFuture::new(self, at_image_end),
                })
            }
        } else {
            Ok(AuthTreeInitializationCursorUpdateResult::Done { cursor: self })
        }
    }

    /// Obtain the final authentication tree root digest.
    ///
    /// Must get called only after the cursor has been moved to the filesystem
    /// image's end.
    ///
    /// # Arguments:
    ///
    /// * `root_hmac_digest_dst` - Destination buffer for the root digest. Its
    ///   size must match the
    ///   [`root_hmac_hash_alg`](AuthTreeConfig::root_hmac_hash_alg) digest
    ///   length exactly.
    /// * `tree_config` - The to be created filesystem's [`AuthTreeConfig`].
    /// * `node_cache` - An [`AuthTreeNodeCache`] instance to store the root
    ///   node into.
    #[allow(clippy::boxed_local)]
    pub fn finalize_into(
        mut self: Box<Self>,
        root_hmac_digest_dst: &mut [u8],
        tree_config: &AuthTreeConfig,
        node_cache: Option<&mut AuthTreeNodeCache>,
    ) -> Result<(), NvFsError> {
        if self.cur_physical_allocation_block_index
            != layout::PhysicalAllocBlockIndex::from(0u64) + self.aligned_image_size
            || root_hmac_digest_dst.len() != hash::hash_alg_digest_len(tree_config.root_hmac_hash_alg) as usize
        {
            return Err(nvfs_err_internal!());
        }

        let root_node_id = AuthTreeNodeId::new(
            AuthTreeDataBlockIndex::from(0u64),
            tree_config.auth_tree_levels - 1,
            tree_config.node_digests_per_node_log2,
            tree_config.data_digests_per_node_log2,
        );

        let root_node = self.root_path_nodes.pop().ok_or_else(|| nvfs_err_internal!())?;

        let (digest_entry_in_root_node_len, digest_entries_in_root_node_log2) = if tree_config.auth_tree_levels != 1 {
            (tree_config.node_digest_len, tree_config.node_digests_per_node_log2)
        } else {
            (tree_config.data_digest_len, tree_config.data_digests_per_node_log2)
        };

        tree_config.hmac_root_node_into(
            root_hmac_digest_dst,
            &root_node_id,
            (0..(1usize << (digest_entries_in_root_node_log2 as u32)))
                .map(|i| root_node.get_digest(i, digest_entry_in_root_node_len as usize)),
        )?;

        // Finally add the root node to the cache, if any.
        if let Some(node_cache) = node_cache {
            node_cache.insert(root_node_id, root_node)?;
        }

        Ok(())
    }

    /// Adance the cursor's current position by a single [Authentication Tree
    /// Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2).
    fn cur_auth_tree_data_block_index_step(&mut self, tree_config: &AuthTreeConfig) -> Result<(), NvFsError> {
        // Advance the cursor's Authentication Tree Data Block index by one block.
        self.cur_data_block_index += AuthTreeDataBlockCount::from(1u64);
        if self.cur_data_block_index == self.cur_contiguous_data_blocks_range_end {
            // End of contiguous data range, i.e. the cur_physical_allocation_block_index is
            // at the beginning of an Authentication Tree extent. Skip over that.
            let (cur_physical_allocation_block_index, cur_contiguous_auth_tree_data_block_range_end) = match tree_config
                .auth_tree_data_allocation_blocks_map
                .iter_data_range_mapping(&AuthTreeDataAllocBlockRange::new(
                    AuthTreeDataAllocBlockIndex::new_from_data_block_index(
                        self.cur_data_block_index,
                        tree_config.data_block_allocation_blocks_log2 as u32,
                    ),
                    AuthTreeDataAllocBlockIndex::from(
                        u64::MAX >> (tree_config.allocation_block_size_128b_log2 as u32 + 7),
                    ),
                ))
                .next()
            {
                Some((cur_contiguous_auth_tree_data_alloc_block_range, cur_physical_allocation_block_index)) => (
                    cur_physical_allocation_block_index,
                    AuthTreeDataBlockIndex::new_from_data_allocation_block_index(
                        cur_contiguous_auth_tree_data_alloc_block_range.end(),
                        tree_config.data_block_allocation_blocks_log2 as u32,
                    ),
                ),
                None => {
                    // At the maximum end possible, we should be done by now.
                    if self.cur_physical_allocation_block_index
                        < layout::PhysicalAllocBlockIndex::from(0u64) + self.aligned_image_size
                    {
                        return Err(nvfs_err_internal!());
                    }
                    (self.cur_physical_allocation_block_index, self.cur_data_block_index)
                }
            };
            self.cur_physical_allocation_block_index = cur_physical_allocation_block_index;
            self.cur_contiguous_data_blocks_range_end = cur_contiguous_auth_tree_data_block_range_end;
            if self.cur_physical_allocation_block_index
                > layout::PhysicalAllocBlockIndex::from(0u64) + self.aligned_image_size
            {
                return Err(nvfs_err_internal!());
            }
        }
        Ok(())
    }
}

/// Return value of [`AuthTreeInitializationCursor::update()`].
pub enum AuthTreeInitializationCursorUpdateResult<C: chip::NvChip> {
    /// No subtree got completed and the [`AuthTreeInitializationCursor`] is
    /// returned back directly.
    Done { cursor: Box<AuthTreeInitializationCursor> },
    /// Some completed parts of the authentication tree need to get written,
    /// implemented by polling `write_fut` to completion.
    NeedAuthTreePartWrite {
        write_fut: AuthTreeInitializationCursorWritePartFuture<C>,
    },
}

/// Future returned by [`AuthTreeInitializationCursor::advance_to()`].
pub struct AuthTreeInitializationCursorAdvanceFuture<C: chip::NvChip> {
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self.
    cursor: Option<Box<AuthTreeInitializationCursor>>,
    to_physical_allocation_block_index: layout::PhysicalAllocBlockIndex,
    fut_state: AuthTreeInitializationCursorAdvanceFutureState<C>,
}

/// Internal [`AuthTreeInitializationCursorAdvanceFuture::poll()`] state-machine
/// state.
enum AuthTreeInitializationCursorAdvanceFutureState<C: chip::NvChip> {
    Init,
    SkipCurAuthTreeDataBlockRemainder,
    WriteAuthTreePart {
        write_fut: AuthTreeInitializationCursorWritePartFuture<C>,
    },
    Done,
}

impl<C: chip::NvChip> AuthTreeInitializationCursorAdvanceFuture<C> {
    /// Instantiate a [`AuthTreeInitializationCursorAdvanceFuture`].
    ///
    /// On error, a pair of the input `cursor` and the error reason wrapped in
    /// an `Err` is returned back.
    ///
    /// # Arguments:
    ///
    /// * `cursor` - The [`AuthTreeInitializationCursor`] to advance.
    /// * `to_physical_allocation_block_index` - Target position to advance the
    ///   cursor to.
    fn new(
        cursor: Box<AuthTreeInitializationCursor>,
        mut to_physical_allocation_block_index: layout::PhysicalAllocBlockIndex,
    ) -> Result<Self, (Box<AuthTreeInitializationCursor>, NvFsError)> {
        if to_physical_allocation_block_index != layout::PhysicalAllocBlockIndex::from(0u64) + cursor.image_size {
            if cursor.cur_physical_allocation_block_index > to_physical_allocation_block_index
                || to_physical_allocation_block_index > layout::PhysicalAllocBlockIndex::from(0u64) + cursor.image_size
            {
                return Err((cursor, nvfs_err_internal!()));
            }
        } else {
            // If seeking to the image end, make sure to fill up the last, possibly partial,
            // Authentication Tree Data Block.
            to_physical_allocation_block_index =
                layout::PhysicalAllocBlockIndex::from(0u64) + cursor.aligned_image_size;
        }

        Ok(Self {
            cursor: Some(cursor),
            to_physical_allocation_block_index,
            fut_state: AuthTreeInitializationCursorAdvanceFutureState::Init,
        })
    }

    /// Poll the [`AuthTreeInitializationCursorAdvanceFuture`] to completion.
    ///
    /// Upon successful [`AuthTreeInitializationCursorAdvanceFuture`]
    /// completion, the [`AuthTreeInitializationCursor`] will eventually get
    /// returned back for further use.
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `tree_config` - The to be created filesystem's [`AuthTreeConfig`].
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    pub fn poll(
        self: pin::Pin<&mut Self>,
        chip: &C,
        tree_config: &AuthTreeConfig,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<Box<AuthTreeInitializationCursor>, NvFsError>> {
        let this = pin::Pin::into_inner(self);

        let data_block_allocation_blocks_log2 = tree_config.data_block_allocation_blocks_log2 as u32;

        loop {
            match &mut this.fut_state {
                AuthTreeInitializationCursorAdvanceFutureState::Init => {
                    let cursor = match this.cursor.as_mut() {
                        Some(cursor) => cursor,
                        None => {
                            this.fut_state = AuthTreeInitializationCursorAdvanceFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    if this.to_physical_allocation_block_index == cursor.cur_physical_allocation_block_index {
                        this.fut_state = AuthTreeInitializationCursorAdvanceFutureState::Done;
                        return task::Poll::Ready(this.cursor.take().ok_or_else(|| nvfs_err_internal!()));
                    }

                    if (u64::from(this.to_physical_allocation_block_index)
                        ^ u64::from(cursor.cur_physical_allocation_block_index))
                        >> data_block_allocation_blocks_log2
                        == 0
                    {
                        // The current and target locations are in the same
                        // Authentication Tree Data Block.
                        // Digest unallocated Allocation Blocks inbetween and be
                        // done.
                        while cursor.cur_physical_allocation_block_index != this.to_physical_allocation_block_index {
                            if let Err(e) = cursor.digest_cur_data_block_context.update(None) {
                                this.fut_state = AuthTreeInitializationCursorAdvanceFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                            cursor.cur_physical_allocation_block_index += layout::AllocBlockCount::from(1u64);
                        }

                        // aligned_image_size is aligned to the Authentication Tree Data Block size
                        // while to_physical_allocation_block_index is not, by
                        // virtue of being here.
                        debug_assert_ne!(
                            cursor.cur_physical_allocation_block_index,
                            layout::PhysicalAllocBlockIndex::from(0u64) + cursor.aligned_image_size
                        );
                        this.fut_state = AuthTreeInitializationCursorAdvanceFutureState::Done;
                        return task::Poll::Ready(this.cursor.take().ok_or_else(|| nvfs_err_internal!()));
                    } else {
                        this.fut_state =
                            AuthTreeInitializationCursorAdvanceFutureState::SkipCurAuthTreeDataBlockRemainder;
                    }
                }
                AuthTreeInitializationCursorAdvanceFutureState::SkipCurAuthTreeDataBlockRemainder => {
                    let cursor = match this.cursor.as_mut() {
                        Some(cursor) => cursor,
                        None => {
                            this.fut_state = AuthTreeInitializationCursorAdvanceFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    loop {
                        if let Err(e) = cursor.digest_cur_data_block_context.update(None) {
                            this.fut_state = AuthTreeInitializationCursorAdvanceFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        cursor.cur_physical_allocation_block_index += layout::AllocBlockCount::from(1);
                        if u64::from(cursor.cur_physical_allocation_block_index)
                            .is_aligned_pow2(tree_config.data_block_allocation_blocks_log2 as u32)
                        {
                            break;
                        }
                    }

                    // Complete the digest and store in the corrsponding leaf node entry.
                    let data_block_entry_in_leaf_node = (u64::from(cursor.cur_data_block_index)
                        & u64::trailing_bits_mask(tree_config.data_digests_per_node_log2 as u32))
                        as usize;
                    let data_block_hmac_instance = match cursor.data_block_hmac_instance_init.try_clone() {
                        Ok(data_block_hmac_instance) => data_block_hmac_instance,
                        Err(e) => {
                            this.fut_state = AuthTreeInitializationCursorAdvanceFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(e)));
                        }
                    };
                    let digest_cur_data_block_context = mem::replace(
                        &mut cursor.digest_cur_data_block_context,
                        AuthTreeDigestDataBlockContext::new(
                            data_block_hmac_instance,
                            tree_config.data_block_allocation_blocks_log2,
                            tree_config.allocation_block_size_128b_log2,
                        ),
                    );
                    if let Err(e) = digest_cur_data_block_context.finalize_into(
                        cursor.root_path_nodes[0]
                            .get_digest_mut(data_block_entry_in_leaf_node, tree_config.data_digest_len as usize),
                        cursor.cur_data_block_index,
                    ) {
                        this.fut_state = AuthTreeInitializationCursorAdvanceFutureState::Done;
                        return task::Poll::Ready(Err(e));
                    }

                    // Advance the cursor's Authentication Tree Data Block index.
                    if let Err(e) = cursor.cur_auth_tree_data_block_index_step(tree_config) {
                        this.fut_state = AuthTreeInitializationCursorAdvanceFutureState::Done;
                        return task::Poll::Ready(Err(e));
                    }
                    if cursor.cur_physical_allocation_block_index > this.to_physical_allocation_block_index {
                        // to_physical_allocation_block_index points into some Authentication Tree
                        // extent.
                        this.fut_state = AuthTreeInitializationCursorAdvanceFutureState::Done;
                        return task::Poll::Ready(Err(nvfs_err_internal!()));
                    }

                    // What to do next depends on whether an Authentication Tree Node boundary has
                    // been crossed. If so, write out, otherwise go back to Init and let it figure
                    // what to do. Also, if the end of the image has been reached, write the
                    // remainder out (with zeroes filled in for the nodes' excess digest entries).
                    let at_image_end = cursor.cur_physical_allocation_block_index
                        == layout::PhysicalAllocBlockIndex::from(0u64) + cursor.aligned_image_size;
                    if !at_image_end
                        && u64::from(cursor.cur_data_block_index)
                            & u64::trailing_bits_mask(tree_config.data_digests_per_node_log2 as u32)
                            != 0
                    {
                        this.fut_state = AuthTreeInitializationCursorAdvanceFutureState::Init;
                    } else {
                        let cursor = match this.cursor.take() {
                            Some(cursor) => cursor,
                            None => {
                                this.fut_state = AuthTreeInitializationCursorAdvanceFutureState::Done;
                                return task::Poll::Ready(Err(nvfs_err_internal!()));
                            }
                        };
                        this.fut_state = AuthTreeInitializationCursorAdvanceFutureState::WriteAuthTreePart {
                            write_fut: AuthTreeInitializationCursorWritePartFuture::new(cursor, at_image_end),
                        }
                    }
                }
                AuthTreeInitializationCursorAdvanceFutureState::WriteAuthTreePart { write_fut } => {
                    let cursor = match AuthTreeInitializationCursorWritePartFuture::poll(
                        pin::Pin::new(write_fut),
                        chip,
                        tree_config,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(cursor)) => cursor,
                        task::Poll::Ready(Err(e)) => {
                            this.fut_state = AuthTreeInitializationCursorAdvanceFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    this.cursor = Some(cursor);
                    this.fut_state = AuthTreeInitializationCursorAdvanceFutureState::Init;
                }
                AuthTreeInitializationCursorAdvanceFutureState::Done => unreachable!(),
            }
        }
    }
}

/// Future returned by [`AuthTreeInitializationCursor::update()`] in the
/// [`AuthTreeInitializationCursorUpdateResult::NeedAuthTreePartWrite`] case.
///
/// Write out any completed subtrees' remaining parts and return the
/// [`AuthTreeInitializationCursor`] back.
pub struct AuthTreeInitializationCursorWritePartFuture<C: chip::NvChip> {
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self.
    cursor: Option<Box<AuthTreeInitializationCursor>>,
    to_data_block_index: AuthTreeDataBlockIndex,
    write_full_path: bool,
    cur_level: u8,
    fut_state: AuthTreeInitializationCursorWritePartFutureState<C>,
}

/// Internal [`AuthTreeInitializationCursorWritePartFuture::poll()`]
/// state-machine state.
enum AuthTreeInitializationCursorWritePartFutureState<C: chip::NvChip> {
    Init,
    WriteNode { write_fut: AuthTreeNodeWriteFuture<C> },
    Done,
}

impl<C: chip::NvChip> AuthTreeInitializationCursorWritePartFuture<C> {
    /// Instantiate a [`AuthTreeInitializationCursorWritePartFuture`].
    ///
    /// # Arguments:
    ///
    /// * `cursor` - The [`AuthTreeInitializationCursor`].
    /// * `write_full_path` - Whether or not to write out the full path to the
    ///   tree's root (inclusive), or only up to the nearest node covering the
    ///   cursor's current position (exclusive). Set to `true` only when finally
    ///   moving to the filesystem image's end.
    fn new(cursor: Box<AuthTreeInitializationCursor>, write_full_path: bool) -> Self {
        let to_data_block_index = cursor.cur_data_block_index;
        Self {
            cursor: Some(cursor),
            to_data_block_index,
            write_full_path,
            cur_level: 0,
            fut_state: AuthTreeInitializationCursorWritePartFutureState::Init,
        }
    }

    /// Poll the [`AuthTreeInitializationCursorWritePartFuture`] to completion.
    ///
    /// Upon successful completion, the [`AuthTreeInitializationCursor`] will
    /// get returned back.
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `tree_config` - The to be created filesystem's [`AuthTreeConfig`].
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    pub fn poll(
        self: pin::Pin<&mut Self>,
        chip: &C,
        tree_config: &AuthTreeConfig,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<Box<AuthTreeInitializationCursor>, NvFsError>> {
        let this = pin::Pin::into_inner(self);

        let cursor = match this.cursor.as_mut() {
            Some(cursor) => cursor,
            None => {
                this.fut_state = AuthTreeInitializationCursorWritePartFutureState::Done;
                return task::Poll::Ready(Err(nvfs_err_internal!()));
            }
        };

        loop {
            match &mut this.fut_state {
                AuthTreeInitializationCursorWritePartFutureState::Init => {
                    if this.cur_level == tree_config.auth_tree_levels || u64::from(this.to_data_block_index) == 0 {
                        this.fut_state = AuthTreeInitializationCursorWritePartFutureState::Done;
                        return task::Poll::Ready(this.cursor.take().ok_or_else(|| nvfs_err_internal!()));
                    }

                    let last_data_block_index = AuthTreeDataBlockIndex::from(u64::from(this.to_data_block_index) - 1);
                    let cur_node_id = AuthTreeNodeId::new(
                        last_data_block_index,
                        this.cur_level,
                        tree_config.node_digests_per_node_log2,
                        tree_config.data_digests_per_node_log2,
                    );
                    if !this.write_full_path && cur_node_id.last_covered_data_block() != last_data_block_index {
                        this.fut_state = AuthTreeInitializationCursorWritePartFutureState::Done;
                        return task::Poll::Ready(this.cursor.take().ok_or_else(|| nvfs_err_internal!()));
                    }

                    let cur_node_data = mem::take(&mut cursor.root_path_nodes[this.cur_level as usize].data);

                    // Digest the node into the parent's corresponding entry.
                    let cur_node_data = if this.cur_level != tree_config.auth_tree_levels - 1 {
                        let cur_node = AuthTreeNode { data: cur_node_data };
                        let (digest_entry_in_node_len, digest_entries_in_node_log2) = if this.cur_level != 0 {
                            (tree_config.node_digest_len, tree_config.node_digests_per_node_log2)
                        } else {
                            (tree_config.data_digest_len, tree_config.data_digests_per_node_log2)
                        };

                        if let Err(e) = tree_config.digest_descendant_node_into(
                            cursor.root_path_nodes[this.cur_level as usize + 1]
                                .get_digest_mut(cur_node_id.index_in_parent(), tree_config.node_digest_len as usize),
                            &cur_node_id,
                            (0..(1usize << (digest_entries_in_node_log2 as u32)))
                                .map(|i| cur_node.get_digest(i, digest_entry_in_node_len as usize)),
                        ) {
                            this.fut_state = AuthTreeInitializationCursorWritePartFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        let AuthTreeNode { data: cur_node_data } = cur_node;
                        cur_node_data
                    } else {
                        cur_node_data
                    };

                    // And write it out.
                    let write_fut = match AuthTreeNodeWriteFuture::new(chip, tree_config, &cur_node_id, cur_node_data) {
                        Ok(Ok(write_fut)) => write_fut,
                        Ok(Err((_, e))) | Err(e) => {
                            this.fut_state = AuthTreeInitializationCursorWritePartFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    this.fut_state = AuthTreeInitializationCursorWritePartFutureState::WriteNode { write_fut };
                }
                AuthTreeInitializationCursorWritePartFutureState::WriteNode { write_fut } => {
                    let mut cur_node_data = match chip::NvChipFuture::poll(pin::Pin::new(write_fut), chip, cx) {
                        task::Poll::Ready(Ok((cur_node_data, Ok(())))) => cur_node_data,
                        task::Poll::Ready(Ok((_, Err(e))) | Err(e)) => {
                            this.fut_state = AuthTreeInitializationCursorWritePartFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    // Clear out if not the root node (the root node data is needed for creating the
                    // root digest). Note that this is needed to zero out excess node entries near
                    // the end which do not correspond to any actual storage. When writing out the
                    // full path to the root, we're at the end and a reinitialization is not needed.
                    if !this.write_full_path && this.cur_level != tree_config.auth_tree_levels - 1 {
                        cur_node_data.fill(0u8);
                    }
                    // Return the buffer back.
                    cursor.root_path_nodes[this.cur_level as usize].data = cur_node_data;
                    this.cur_level += 1;
                    this.fut_state = AuthTreeInitializationCursorWritePartFutureState::Init;
                }
                AuthTreeInitializationCursorWritePartFutureState::Done => unreachable!(),
            }
        }
    }
}

/// Reconstruct the authentication tree during journal replay.
///
/// Reconstruct the modified authentication tree's nodes according to a
/// journal's [`JournalUpdateAuthDigestsScript`].
///
/// The authentication tree's contents are reconstructed by a single pass over
/// all of its authenticated data range. Modified data contents are supposed to
/// get recorded via [`update()`](Self::update), while unmodified regions must
/// get skipped over by advancing the `AuthTreeReplayJournalUpdateScriptCursor`
/// past them via [`advance_to()`](Self::advance_to). Authentication tree
/// updates recorded in the [`JournalUpdateAuthDigestsScript`] with no
/// corresponding entry in the journal's
/// [`JournalApplyWritesScript`](super::journal::apply_script::JournalApplyWritesScript),
/// i.e. authentication tree updates for in-place writes or due to
/// deallocations, are applied transparently in the course of advancing the
/// cursor over the respective regions. Note that this scheme enables
/// interleaving of the actual data update writes themselves with the
/// corresponding authentication tree updates.
pub struct AuthTreeReplayJournalUpdateScriptCursor {
    image_size: layout::AllocBlockCount,
    aligned_image_size: layout::AllocBlockCount,
    alloc_bitmap_journal_fragments: AllocBitmap,
    journal_update_script: JournalUpdateAuthDigestsScript,
    journal_update_script_index: usize,
    data_block_hmac_instance_init: hash::HmacInstance,
    root_path_nodes: Vec<AuthTreeNode>,
    digest_cur_data_block_context: Option<AuthTreeDigestDataBlockContext>,
    cur_physical_allocation_block_index: layout::PhysicalAllocBlockIndex,
    cur_data_allocation_block_index: AuthTreeDataAllocBlockIndex,
    cur_contiguous_data_allocation_blocks_range_end: AuthTreeDataAllocBlockIndex,
    at_end: bool,
}

impl AuthTreeReplayJournalUpdateScriptCursor {
    /// Instantiate a [`AuthTreeReplayJournalUpdateScriptCursor`].
    ///
    /// # Arguments:
    ///
    /// * `image_layout` - The filesystem's [`ImageLayout`].
    /// * `tree_config` - The filesystem's [`AuthTreeConfig`].
    /// * `image_header_end` - [End of the filesystem image header on
    ///   storage](MutableImageHeader::physical_location).
    /// * `journal_log_head_extent` - [Location of the journal log head
    ///   extent](super::journal::log::JournalLog::head_extent_physical_location).
    /// * `image_size` - The filesystem image size as found in the filesystem's
    ///   (possibly updated) [`MutableImageHeader::image_size`].
    /// * `alloc_bitmap_journal_fragments` - [Allocation bitmap](AllocBitmap)
    ///   needed for the authentication tree reconstruction, i.e. the updated
    ///   [`AllocBitmap`] with valid entries for any range covered by some
    ///   modified leaf node. C.f.
    ///   [`AllocBitmapFileReadJournalFragmentsFuture`](super::alloc_bitmap::AllocBitmapFileReadJournalFragmentsFuture).
    /// * `journal_update_script` - The [`JournalUpdateAuthDigestsScript`]
    ///   decoded from the journal log to apply to the tree.
    pub fn new(
        image_layout: &layout::ImageLayout,
        tree_config: &AuthTreeConfig,
        image_header_end: layout::PhysicalAllocBlockIndex,
        journal_log_head_extent: &layout::PhysicalAllocBlockRange,
        image_size: layout::AllocBlockCount,
        mut alloc_bitmap_journal_fragments: AllocBitmap,
        journal_update_script: JournalUpdateAuthDigestsScript,
    ) -> Result<Box<Self>, NvFsError> {
        // The image_size should be aligned to the IO Block size, so that
        // aligned_image_size would as well.
        if !u64::from(image_size).is_aligned_pow2(image_layout.io_block_allocation_blocks_log2 as u32) {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidImageSize));
        }
        let aligned_image_size = layout::AllocBlockCount::from(
            u64::from(image_size)
                .round_up_pow2(tree_config.data_block_allocation_blocks_log2 as u32)
                .ok_or_else(|| nvfs_err_internal!())?,
        );

        // The leaf node digests reconstruction code relies on the fact that a leaf node
        // (whose size is aligned to the IO Block size, as is any node) covers
        // at least an IO Block. Note that this is trivially true, because
        // a digest length is less than 128 Bytes, i.e. less than an Allocation Block in
        // size, but make it explicit.
        if image_layout.io_block_allocation_blocks_log2 as u32
            > tree_config.data_digests_per_node_log2 as u32 + tree_config.data_block_allocation_blocks_log2 as u32
        {
            return Err(NvFsError::from(CocoonFsFormatError::UnsupportedAuthTreeConfig));
        }

        // The image header and the Journal Log head extent are tracked as allocated in
        // the Allocation Bitmap, but authenticated as if unallocated. As
        // alloc_bitmap is owned and being used exclusively for authentication,
        // simply clear the corresponding bits here.
        alloc_bitmap_journal_fragments.set_in_range(
            &layout::PhysicalAllocBlockRange::new(layout::PhysicalAllocBlockIndex::from(0), image_header_end),
            false,
        )?;
        alloc_bitmap_journal_fragments.set_in_range(journal_log_head_extent, false)?;

        let data_block_hmac_instance_init =
            hash::HmacInstance::new(tree_config.data_hmac_hash_alg, &tree_config.data_hmac_key)?;

        let mut root_path_nodes = Vec::new();
        root_path_nodes.try_reserve(tree_config.auth_tree_levels as usize)?;

        box_try_new(Self {
            image_size,
            aligned_image_size,
            alloc_bitmap_journal_fragments,
            journal_update_script,
            journal_update_script_index: 0,
            data_block_hmac_instance_init,
            root_path_nodes,
            digest_cur_data_block_context: None,
            cur_physical_allocation_block_index: layout::PhysicalAllocBlockIndex::from(0u64),
            cur_data_allocation_block_index: AuthTreeDataAllocBlockIndex::from(0u64),
            cur_contiguous_data_allocation_blocks_range_end: AuthTreeDataAllocBlockIndex::from(0u64),
            at_end: false,
        })
        .map_err(NvFsError::from)
    }

    /// Advance the cursor to a specified position.
    ///
    /// Advance the cursor to the specified position at
    /// `to_physical_allocation_block_index`, assuming any [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2)s' data
    /// skipped over as unmodified by the journal. The returned
    /// [`AuthTreeReplayJournalUpdateScriptCursorAdvanceFuture`] assumes
    /// ownership of the cursor and must get polled to completion in order
    /// to transparently reconstruct any intermediate parts as needed, write
    /// completed subtrees out and to eventually obtain the (advanced)
    /// cursor back.
    ///
    /// # Arguments:
    ///
    /// * `to_physical_allocation_block_index` - Target position to advance the
    ///   cursor to.
    pub fn advance_to<C: chip::NvChip>(
        self: Box<Self>,
        chip: &C,
        to_physical_allocation_block_index: layout::PhysicalAllocBlockIndex,
        tree_config: &AuthTreeConfig,
    ) -> Result<AuthTreeReplayJournalUpdateScriptCursorAdvanceFuture<C>, NvFsError> {
        AuthTreeReplayJournalUpdateScriptCursorAdvanceFuture::new(
            chip,
            self,
            to_physical_allocation_block_index,
            tree_config,
        )
    }

    /// Record some modified [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) data at the
    /// cursor's current position.
    ///
    /// Record the modified `allocation_block_data` at the cursor's current
    /// position and advance the cursor past it. Depending of whether moving
    /// the cursor past the current [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) results in
    /// some subtrees having become completed, either
    /// * [`AuthTreeReplayJournalUpdateScriptCursorUpdateResult::NeedAuthTreePartWrite`] wrapping a
    ///   [future](AuthTreeReplayJournalUpdateScriptCursorWritePartFuture) for writing out any
    ///   completed parts gets returned -- polling it to completion will eventually yield the cursor
    ///   back.
    /// * Otherwise the cursor is returned directly, wrapped in a
    ///   [`AuthTreeReplayJournalUpdateScriptCursorUpdateResult::Done`].
    pub fn update<C: chip::NvChip>(
        mut self: Box<Self>,
        tree_config: &AuthTreeConfig,
        allocation_block_data: &[u8],
    ) -> Result<AuthTreeReplayJournalUpdateScriptCursorUpdateResult<C>, NvFsError> {
        if self.cur_data_allocation_block_index >= self.cur_contiguous_data_allocation_blocks_range_end {
            self.update_physical_position(tree_config)?;
        }
        if self.cur_physical_allocation_block_index >= layout::PhysicalAllocBlockIndex::from(0u64) + self.image_size {
            return Err(nvfs_err_internal!());
        }

        // Push missing nodes all the way to the bottom.
        while self.root_path_nodes.len() != tree_config.auth_tree_levels as usize {
            let node = FixedVec::new_with_default(tree_config.node_size())?;
            self.root_path_nodes.push(AuthTreeNode { data: node });
            debug_assert!(u64::from(self.cur_data_allocation_block_index).is_aligned_pow2(
                AuthTreeNodeId::level_covered_data_block_index_bits(
                    (tree_config.auth_tree_levels as usize - self.root_path_nodes.len()) as u32,
                    tree_config.node_digests_per_node_log2 as u32,
                    tree_config.data_digests_per_node_log2 as u32
                )
            ));
        }

        let digest_cur_data_block_context = match self.digest_cur_data_block_context.as_mut() {
            Some(digest_cur_data_block_context) => digest_cur_data_block_context,
            None => {
                let data_block_hmac_instance = self.data_block_hmac_instance_init.try_clone()?;
                self.digest_cur_data_block_context
                    .insert(AuthTreeDigestDataBlockContext::new(
                        data_block_hmac_instance,
                        tree_config.data_block_allocation_blocks_log2,
                        tree_config.allocation_block_size_128b_log2,
                    ))
            }
        };

        let empty_pending_allocs = SparseAllocBitmapUnion::new(&[]);
        let empty_pending_frees = SparseAllocBitmapUnion::new(&[]);
        digest_cur_data_block_context.update(
            self.alloc_bitmap_journal_fragments
                .iter_at_allocation_block(
                    &empty_pending_allocs,
                    &empty_pending_frees,
                    self.cur_physical_allocation_block_index,
                )
                .next()
                .unwrap_or(false)
                .then_some(allocation_block_data),
        )?;

        self.cur_physical_allocation_block_index += layout::AllocBlockCount::from(1);
        while self.journal_update_script_index != self.journal_update_script.len()
            && self.journal_update_script[self.journal_update_script_index]
                .get_target_range()
                .end()
                <= self.cur_physical_allocation_block_index
        {
            self.journal_update_script_index += 1;
        }
        self.cur_data_allocation_block_index += layout::AllocBlockCount::from(1);
        let data_block_allocation_blocks_log2 = tree_config.data_block_allocation_blocks_log2 as u32;
        if u64::from(self.cur_physical_allocation_block_index).is_aligned_pow2(data_block_allocation_blocks_log2) {
            let digest_cur_data_block_context = self
                .digest_cur_data_block_context
                .take()
                .ok_or_else(|| nvfs_err_internal!())?;

            let cur_data_block_index = AuthTreeDataBlockIndex::new_from_data_allocation_block_index(
                AuthTreeDataAllocBlockIndex::from(u64::from(self.cur_data_allocation_block_index) - 1),
                data_block_allocation_blocks_log2,
            );
            let leaf_node = &mut self.root_path_nodes[tree_config.auth_tree_levels as usize - 1];
            let leaf_node_digest_entry = leaf_node.get_digest_mut(
                (u64::from(cur_data_block_index)
                    & u64::trailing_bits_mask(tree_config.data_digests_per_node_log2 as u32)) as usize,
                tree_config.data_digest_len as usize,
            );
            digest_cur_data_block_context.finalize_into(leaf_node_digest_entry, cur_data_block_index)?;

            if u64::from(self.cur_data_allocation_block_index)
                .is_aligned_pow2(tree_config.data_digests_per_node_log2 as u32 + data_block_allocation_blocks_log2)
            {
                // End of current leaf node reached, a write-out is needed.
                return Ok(
                    AuthTreeReplayJournalUpdateScriptCursorUpdateResult::NeedAuthTreePartWrite {
                        write_fut: AuthTreeReplayJournalUpdateScriptCursorWritePartFuture::new(self),
                    },
                );
            }
        }

        Ok(AuthTreeReplayJournalUpdateScriptCursorUpdateResult::Done { cursor: self })
    }

    /// Update [`Self::cur_physical_allocation_block_index`] to match
    /// [`Self::cur_data_allocation_block_index`].
    ///
    /// The mapping from the [Authentication Tree Data Block index
    /// domain](AuthTreeDataAllocBlockIndex) to [physical
    /// locations](layout::PhysicalAllocBlockIndex) is piecewise linear.
    /// Once [`Self::cur_data_allocation_block_index`] has been advanced past
    /// [`Self::cur_contiguous_data_allocation_blocks_range_end`], i.e. when
    /// the mapping's current linear piece is left, the value
    /// of [`Self::cur_physical_allocation_block_index`] needs to get adjusted
    /// by a discontiguous jump. `update_physical_position()` does that.
    ///
    /// `update_physical_position()` must get invoked only while
    /// [`Self::cur_data_allocation_block_index`] is within the filesystem
    /// image's bounds, or an error of [`NvFsIoError::RegionOutOfRange`] will
    /// get returned.
    fn update_physical_position(&mut self, tree_config: &AuthTreeConfig) -> Result<(), NvFsError> {
        match tree_config
            .auth_tree_data_allocation_blocks_map
            .iter_data_range_mapping(&AuthTreeDataAllocBlockRange::new(
                self.cur_data_allocation_block_index,
                AuthTreeDataAllocBlockIndex::from(u64::MAX >> (tree_config.allocation_block_size_128b_log2 as u32 + 7)),
            ))
            .next()
        {
            Some((cur_contiguous_data_allocation_blocks_range, cur_physical_allocation_block_index)) => {
                // The cur_physical_allocation_block_index only ever gets moved in the forward
                // direction. More specifically whenever crossing an
                // Authentication Tree extent, that extent's length gets added.
                debug_assert!(cur_physical_allocation_block_index >= self.cur_physical_allocation_block_index);
                if cur_physical_allocation_block_index
                    <= layout::PhysicalAllocBlockIndex::from(0u64) + self.aligned_image_size
                {
                    self.cur_physical_allocation_block_index = cur_physical_allocation_block_index;
                    self.cur_contiguous_data_allocation_blocks_range_end =
                        cur_contiguous_data_allocation_blocks_range.end();
                    Ok(())
                } else {
                    Err(NvFsError::IoError(NvFsIoError::RegionOutOfRange))
                }
            }
            None => Err(NvFsError::IoError(NvFsIoError::RegionOutOfRange)),
        }
    }
}

/// Return value of [`AuthTreeReplayJournalUpdateScriptCursor::update()`].
pub enum AuthTreeReplayJournalUpdateScriptCursorUpdateResult<C: chip::NvChip> {
    /// No subtree got completed and the
    /// [`AuthTreeReplayJournalUpdateScriptCursor`] is returned back
    /// directly.
    Done {
        cursor: Box<AuthTreeReplayJournalUpdateScriptCursor>,
    },
    /// Some completed parts of the authentication tree need to get written,
    /// implemented by polling `write_fut` to completion.
    NeedAuthTreePartWrite {
        write_fut: AuthTreeReplayJournalUpdateScriptCursorWritePartFuture<C>,
    },
}

/// Future returned by
/// [`AuthTreeReplayJournalUpdateScriptCursor::advance_to()`].
pub struct AuthTreeReplayJournalUpdateScriptCursorAdvanceFuture<C: chip::NvChip> {
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self.
    cursor: Option<Box<AuthTreeReplayJournalUpdateScriptCursor>>,
    fut_state: AuthTreeReplayJournalUpdateScriptCursorAdvanceFutureState<C>,
    to_physical_allocation_block_index: layout::PhysicalAllocBlockIndex,
    to_data_allocation_block_index: AuthTreeDataAllocBlockIndex,
    node_read_buf: FixedVec<u8, 7>,
}

/// Internal [`AuthTreeReplayJournalUpdateScriptCursorAdvanceFuture::poll()`]
/// state-machine state.
enum AuthTreeReplayJournalUpdateScriptCursorAdvanceFutureState<C: chip::NvChip> {
    Init,
    WriteNode {
        node_id: AuthTreeNodeId,
        write_fut: AuthTreeNodeWriteFuture<C>,
    },
    ReconstructLeafNodePart {
        reconstruct_node_part_fut: AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsFuture<C>,
    },
    ReconstructInternalNodePart {
        reconstruct_node_part_fut: AuthTreeReplayJournalUpdateScriptCursorReconstructInternalDigestsFuture<C>,
    },
    Done,
}

impl<C: chip::NvChip> AuthTreeReplayJournalUpdateScriptCursorAdvanceFuture<C> {
    /// Instantiate a [`AuthTreeReplayJournalUpdateScriptCursorAdvanceFuture`].
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `cursor` - The [`AuthTreeReplayJournalUpdateScriptCursor`] to advance.
    /// * `to_physical_allocation_block_index` - Target position to advance the
    ///   cursor to.
    /// * `tree_config` - The filesystem's [`AuthTreeConfig`].
    fn new(
        chip: &C,
        cursor: Box<AuthTreeReplayJournalUpdateScriptCursor>,
        mut to_physical_allocation_block_index: layout::PhysicalAllocBlockIndex,
        tree_config: &AuthTreeConfig,
    ) -> Result<Self, NvFsError> {
        let chip_io_block_allocation_blocks_log2 = chip
            .chip_io_block_size_128b_log2()
            .saturating_sub(tree_config.allocation_block_size_128b_log2 as u32);
        if !u64::from(to_physical_allocation_block_index).is_aligned_pow2(chip_io_block_allocation_blocks_log2) {
            return Err(nvfs_err_internal!());
        }
        let to_data_allocation_block_index =
            if to_physical_allocation_block_index >= layout::PhysicalAllocBlockIndex::from(0u64) + cursor.image_size {
                to_physical_allocation_block_index =
                    layout::PhysicalAllocBlockIndex::from(0u64) + cursor.aligned_image_size;
                let image_data_allocation_blocks = layout::AllocBlockCount::from(u64::from(
                    cursor.aligned_image_size
                        - tree_config
                            .auth_tree_data_allocation_blocks_map
                            .total_auth_tree_extents_allocation_blocks(),
                ));
                AuthTreeDataAllocBlockIndex::from(0u64) + image_data_allocation_blocks
            } else {
                AuthTreeDataAllocBlockIndex::new_from_data_block_index(
                    tree_config.translate_physical_to_data_block_index(to_physical_allocation_block_index),
                    tree_config.data_block_allocation_blocks_log2 as u32,
                ) + layout::AllocBlockCount::from(
                    u64::from(to_physical_allocation_block_index)
                        & u64::trailing_bits_mask(tree_config.data_block_allocation_blocks_log2 as u32),
                )
            };
        Ok(Self {
            cursor: Some(cursor),
            fut_state: AuthTreeReplayJournalUpdateScriptCursorAdvanceFutureState::Init,
            to_physical_allocation_block_index,
            to_data_allocation_block_index,
            node_read_buf: FixedVec::new_empty(),
        })
    }

    /// Poll the [`AuthTreeReplayJournalUpdateScriptCursorAdvanceFuture`] to
    /// completion.
    ///
    /// Upon successful completion, the
    /// [`AuthTreeReplayJournalUpdateScriptCursor`] will get returned back.
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `tree_config` - The filesystem's [`AuthTree`]'s [`AuthTreeConfig`].
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    pub fn poll(
        self: pin::Pin<&mut Self>,
        chip: &C,
        tree_config: &AuthTreeConfig,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<Box<AuthTreeReplayJournalUpdateScriptCursor>, NvFsError>> {
        let this = pin::Pin::into_inner(self);

        let result = 'outer: loop {
            match &mut this.fut_state {
                AuthTreeReplayJournalUpdateScriptCursorAdvanceFutureState::Init => {
                    let cursor = match this.cursor.as_mut() {
                        Some(cursor) => cursor,
                        None => {
                            this.fut_state = AuthTreeReplayJournalUpdateScriptCursorAdvanceFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    let data_block_allocation_blocks_log2 = tree_config.data_block_allocation_blocks_log2 as u32;
                    let mut cur_node_level =
                        (tree_config.auth_tree_levels as usize - cursor.root_path_nodes.len()) as u8;
                    let image_data_allocation_blocks = layout::AllocBlockCount::from(u64::from(
                        cursor.aligned_image_size
                            - tree_config
                                .auth_tree_data_allocation_blocks_map
                                .total_auth_tree_extents_allocation_blocks(),
                    ));

                    // When at the image end (which is covered by the rightmost, possibly partial
                    // subtree descendant from the root), then that should have
                    // been the target for the advance operation.
                    debug_assert!(
                        cursor.cur_data_allocation_block_index
                            < AuthTreeDataAllocBlockIndex::from(0u64) + image_data_allocation_blocks
                            || this.to_physical_allocation_block_index
                                >= layout::PhysicalAllocBlockIndex::from(0u64) + cursor.image_size
                    );
                    if !cursor.root_path_nodes.is_empty()
                        && (u64::from(cursor.cur_data_allocation_block_index).is_aligned_pow2(
                            AuthTreeNodeId::level_covered_data_block_index_bits(
                                cur_node_level as u32,
                                tree_config.node_digests_per_node_log2 as u32,
                                tree_config.data_digests_per_node_log2 as u32,
                            ) + data_block_allocation_blocks_log2,
                        ) || cursor.cur_data_allocation_block_index
                            >= AuthTreeDataAllocBlockIndex::from(0u64) + image_data_allocation_blocks)
                    {
                        // Reached the end of the current node at the tip of the root path.
                        // Note that the cur_data_allocation_block_index might have wrapped around to
                        // zero at the very end: proper (full) subtrees are guaranteed to cover a
                        // data range which is a power of two <= 2^63 in length, but accumulating
                        // multiple thereof at the root node can wrap.
                        let node_id = AuthTreeNodeId::new(
                            AuthTreeDataBlockIndex::new_from_data_allocation_block_index(
                                AuthTreeDataAllocBlockIndex::from(
                                    u64::from(cursor.cur_data_allocation_block_index).wrapping_sub(1),
                                ),
                                data_block_allocation_blocks_log2,
                            ),
                            cur_node_level,
                            tree_config.node_digests_per_node_log2,
                            tree_config.data_digests_per_node_log2,
                        );
                        let root_path_nodes_len = cursor.root_path_nodes.len();
                        let AuthTreeNode { data: node } = mem::replace(
                            &mut cursor.root_path_nodes[root_path_nodes_len - 1],
                            AuthTreeNode {
                                data: FixedVec::new_empty(),
                            },
                        );
                        cursor.root_path_nodes.truncate(root_path_nodes_len - 1);
                        let write_fut = match AuthTreeNodeWriteFuture::new(chip, tree_config, &node_id, node) {
                            Ok(Ok(write_fut)) => write_fut,
                            Err(e) | Ok(Err((_, e))) => break Err(e),
                        };
                        this.fut_state =
                            AuthTreeReplayJournalUpdateScriptCursorAdvanceFutureState::WriteNode { node_id, write_fut };
                        continue;
                    }

                    // If cur_data_allocation_block_index had wrapped to zero, then it's aligned to
                    // any node's covered region's end and the node would have been popped and
                    // written above. If the cursor is in its initial state, then
                    // cur_data_block_allocation_block_index is zero and the root_path_nodes is
                    // also empty.
                    debug_assert!(
                        u64::from(cursor.cur_data_allocation_block_index) != 0 || cursor.root_path_nodes.is_empty()
                    );
                    debug_assert!(!cursor.at_end || cursor.root_path_nodes.is_empty());
                    if cursor.at_end {
                        // Attempting to advance the cursor to the end while already there.
                        debug_assert!(
                            u64::from(cursor.cur_data_allocation_block_index) == 0
                                || cursor.cur_data_allocation_block_index
                                    >= AuthTreeDataAllocBlockIndex::from(0u64) + image_data_allocation_blocks
                        );
                        break Ok(());
                    }

                    // If done, complete the future. Note that it is intentional not to descend into
                    // (push) desendant nodes whose beginning aligns with
                    // to_physical_allocation_block_index -- this avoids any ambiguity on whether
                    // cur_data_allocation_block_index is at the beginning or end of the current
                    // node: if it aligns with a node boundary, then it's always at its end.
                    if cursor.cur_data_allocation_block_index == this.to_data_allocation_block_index {
                        break Ok(());
                    }

                    let move_to_end = this.to_physical_allocation_block_index
                        == layout::PhysicalAllocBlockIndex::from(0u64) + cursor.aligned_image_size
                        && cursor.journal_update_script_index == cursor.journal_update_script.len();
                    if move_to_end {
                        // Advance all the way to the end.
                        // Complete all nodes currently on root_path_nodes.
                        if cursor.root_path_nodes.is_empty() {
                            // The root_path_nodes had not been fully unwound above,
                            // yet it's empty (at_end is false), meaning the cursor is in its initial state
                            // and there's nothing to do.
                            debug_assert_eq!(u64::from(cursor.cur_data_allocation_block_index), 0);
                            debug_assert!(cursor.journal_update_script.is_empty());
                            break Ok(());
                        }

                        // The node had not been unwound above, meaning
                        // cur_data_allocation_block_index does not align with its end and it needs
                        // to get completed.
                        debug_assert!(
                            cursor.cur_data_allocation_block_index
                                < AuthTreeDataAllocBlockIndex::from(0u64) + image_data_allocation_blocks
                        );
                        let cur_node_level_covered_data_block_index_bits =
                            AuthTreeNodeId::level_covered_data_block_index_bits(
                                cur_node_level as u32,
                                tree_config.node_digests_per_node_log2 as u32,
                                tree_config.data_digests_per_node_log2 as u32,
                            );
                        let cur_node_level_covered_data_allocation_block_index_bits =
                            cur_node_level_covered_data_block_index_bits + data_block_allocation_blocks_log2;

                        // If the current position as well as the image end are both
                        // covered by the current node, then it's only partially filled one.
                        let cur_node_is_partial = (u64::from(cursor.cur_data_allocation_block_index)
                            ^ u64::from(AuthTreeDataAllocBlockIndex::from(0u64) + image_data_allocation_blocks))
                            >> cur_node_level_covered_data_allocation_block_index_bits
                            == 0;
                        if cur_node_level == 0 {
                            let reconstruct_to_data_allocation_block_index = if cur_node_is_partial {
                                AuthTreeDataAllocBlockIndex::from(0u64) + image_data_allocation_blocks
                            } else {
                                match cursor
                                    .cur_data_allocation_block_index
                                    .align_up(cur_node_level_covered_data_allocation_block_index_bits)
                                {
                                    Some(reconstruct_to_data_allocation_block_index) => {
                                        reconstruct_to_data_allocation_block_index
                                    }
                                    None => {
                                        // It's already known that the current position is covered
                                        // by a leaf node different (and before) the one covering
                                        // the image end.
                                        break Err(nvfs_err_internal!());
                                    }
                                }
                            };
                            let cursor = match this.cursor.take() {
                                Some(cursor) => cursor,
                                None => break Err(nvfs_err_internal!()),
                            };
                            let reconstruct_node_part_fut =
                                match AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsFuture::new(
                                    chip,
                                    cursor,
                                    reconstruct_to_data_allocation_block_index,
                                    tree_config,
                                ) {
                                    Ok(reconstruct_node_part_fut) => reconstruct_node_part_fut,
                                    Err(e) => break Err(e),
                                };
                            this.fut_state =
                                AuthTreeReplayJournalUpdateScriptCursorAdvanceFutureState::ReconstructLeafNodePart {
                                    reconstruct_node_part_fut,
                                };
                        } else {
                            let reconstruct_to_data_allocation_block_index = if cur_node_is_partial {
                                let cur_node_entry_covered_data_block_index_bits =
                                    cur_node_level_covered_data_block_index_bits
                                        - tree_config.node_digests_per_node_log2 as u32;
                                let cur_node_entry_covered_data_allocation_block_index_bits =
                                    cur_node_entry_covered_data_block_index_bits + data_block_allocation_blocks_log2;
                                (AuthTreeDataAllocBlockIndex::from(0u64) + image_data_allocation_blocks)
                                    .align_up(cur_node_entry_covered_data_allocation_block_index_bits)
                                    .unwrap_or(AuthTreeDataAllocBlockIndex::from(0u64))
                            } else {
                                cursor
                                    .cur_data_allocation_block_index
                                    .align_up(cur_node_level_covered_data_allocation_block_index_bits)
                                    .unwrap_or(AuthTreeDataAllocBlockIndex::from(0u64))
                            };
                            let cursor = match this.cursor.take() {
                                Some(cursor) => cursor,
                                None => break Err(nvfs_err_internal!()),
                            };
                            let reconstruct_node_part_fut =
                                AuthTreeReplayJournalUpdateScriptCursorReconstructInternalDigestsFuture::new(
                                    cursor,
                                    reconstruct_to_data_allocation_block_index,
                                    mem::take(&mut this.node_read_buf),
                                    tree_config,
                                );
                            this.fut_state =
                                AuthTreeReplayJournalUpdateScriptCursorAdvanceFutureState::ReconstructInternalNodePart {
                                    reconstruct_node_part_fut
                                };
                        }

                        continue;
                    }

                    let next_stop_data_allocation_block_index = {
                        if cursor.journal_update_script_index != cursor.journal_update_script.len() {
                            let journal_update_script_entry_range =
                                *cursor.journal_update_script[cursor.journal_update_script_index].get_target_range();
                            let chip_io_block_allocation_blocks_log2 = chip
                                .chip_io_block_size_128b_log2()
                                .saturating_sub(tree_config.allocation_block_size_128b_log2 as u32);
                            let journal_update_script_entry_range_begin = journal_update_script_entry_range
                                .begin()
                                .align_down(chip_io_block_allocation_blocks_log2);

                            if this.to_physical_allocation_block_index <= journal_update_script_entry_range_begin {
                                this.to_data_allocation_block_index
                            } else {
                                if cursor.cur_data_allocation_block_index
                                    >= cursor.cur_contiguous_data_allocation_blocks_range_end
                                {
                                    if let Err(e) = cursor.update_physical_position(tree_config) {
                                        break Err(e);
                                    }
                                }
                                debug_assert!(
                                    cursor.cur_physical_allocation_block_index
                                        < journal_update_script_entry_range.end()
                                );
                                if cursor.cur_physical_allocation_block_index < journal_update_script_entry_range_begin
                                {
                                    AuthTreeDataAllocBlockIndex::new_from_data_block_index(
                                        tree_config.translate_physical_to_data_block_index(
                                            journal_update_script_entry_range_begin,
                                        ),
                                        tree_config.data_block_allocation_blocks_log2 as u32,
                                    ) + layout::AllocBlockCount::from(
                                        u64::from(journal_update_script_entry_range_begin)
                                            & u64::trailing_bits_mask(data_block_allocation_blocks_log2),
                                    )
                                } else {
                                    // The current position is at the beginning or the interior of
                                    // the current journal_update_script_entry. The region needs to
                                    // get reconstructed as a whole from the data without any
                                    // skipping. Do it up to the next leaf node boundary, the
                                    // to_data_allocation_block_index or the
                                    // journal_update_script_entry's end, whichever comes first.
                                    let next_stop_data_allocation_block_index = if this
                                        .to_physical_allocation_block_index
                                        <= journal_update_script_entry_range.end()
                                    {
                                        this.to_data_allocation_block_index
                                    } else {
                                        let journal_update_script_entry_range_end =
                                            match journal_update_script_entry_range
                                                .end()
                                                .align_up(chip_io_block_allocation_blocks_log2)
                                            {
                                                Some(journal_update_script_entry_end) => {
                                                    journal_update_script_entry_end
                                                }
                                                None => {
                                                    // The aligned_image_size is aligned to the Chip IO Block size,
                                                    // therefore the update script entry's end must be larger than that,
                                                    // thus it's invalid.
                                                    break Err(NvFsError::from(
                                                        CocoonFsFormatError::InvalidJournalUpdateAuthDigestsScriptEntry,
                                                    ));
                                                }
                                            };
                                        AuthTreeDataAllocBlockIndex::new_from_data_block_index(
                                            tree_config.translate_physical_to_data_block_index(
                                                journal_update_script_entry_range_end,
                                            ),
                                            tree_config.data_block_allocation_blocks_log2 as u32,
                                        ) + layout::AllocBlockCount::from(
                                            u64::from(journal_update_script_entry_range_end)
                                                & u64::trailing_bits_mask(
                                                    tree_config.data_block_allocation_blocks_log2 as u32,
                                                ),
                                        )
                                    };
                                    // Limit to the end of the current leaf node's covered region.
                                    let next_stop_data_allocation_block_index = cursor.cur_data_allocation_block_index
                                        + (next_stop_data_allocation_block_index
                                            - cursor.cur_data_allocation_block_index)
                                            .min(layout::AllocBlockCount::from(
                                                (1u64
                                                    << (tree_config.data_digests_per_node_log2 as u32
                                                        + data_block_allocation_blocks_log2))
                                                    - (u64::from(cursor.cur_data_allocation_block_index)
                                                        & u64::trailing_bits_mask(
                                                            tree_config.data_digests_per_node_log2 as u32
                                                                + data_block_allocation_blocks_log2,
                                                        )),
                                            ));
                                    while cursor.root_path_nodes.len() != tree_config.auth_tree_levels as usize {
                                        let node = match FixedVec::new_with_default(tree_config.node_size()) {
                                            Ok(node) => node,
                                            Err(e) => break 'outer Err(NvFsError::from(e)),
                                        };
                                        cursor.root_path_nodes.push(AuthTreeNode { data: node });
                                    }
                                    let cursor = match this.cursor.take() {
                                        Some(cursor) => cursor,
                                        None => break Err(nvfs_err_internal!()),
                                    };
                                    let reconstruct_node_part_fut =
                                        match AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsFuture::new(
                                            chip,
                                            cursor,
                                            next_stop_data_allocation_block_index,
                                            tree_config,
                                        ) {
                                            Ok(reconstruct_node_part_fut) => reconstruct_node_part_fut,
                                            Err(e) => break Err(e),
                                        };
                                    this.fut_state =
                                        AuthTreeReplayJournalUpdateScriptCursorAdvanceFutureState::
                                    ReconstructLeafNodePart {
                                        reconstruct_node_part_fut,
                                    };
                                    continue;
                                }
                            }
                        } else {
                            this.to_data_allocation_block_index
                        }
                    };

                    // Move to the next stop, which is either to_data_allocation_block_index or the
                    // next journal_update_script entry's beginning, whichever comes first. We may
                    // skip over intermediate data regions by reconstructing the
                    // corresponding node parts at the upper levels.
                    // It is known by now that cur_data_allocation_block_index !=
                    // next_stop_data_allocation_block_index, hence the latter cannot be 0.
                    debug_assert_ne!(u64::from(next_stop_data_allocation_block_index), 0);
                    // First check whether the current node's covered data range includes the next
                    // stop.
                    if !cursor.root_path_nodes.is_empty() {
                        let cur_node_level_covered_data_block_index_bits =
                            AuthTreeNodeId::level_covered_data_block_index_bits(
                                cur_node_level as u32,
                                tree_config.node_digests_per_node_log2 as u32,
                                tree_config.data_digests_per_node_log2 as u32,
                            );
                        let cur_node_level_covered_data_allocation_block_index_bits =
                            cur_node_level_covered_data_block_index_bits + data_block_allocation_blocks_log2;
                        if (u64::from(cursor.cur_data_allocation_block_index)
                            ^ u64::from(next_stop_data_allocation_block_index))
                            >> cur_node_level_covered_data_allocation_block_index_bits
                            != 0
                        {
                            // The current node's covered data region does not include
                            // next_stop_data_allocation_block_index. Complete the
                            // current node and write it out in a subsequent iteration.
                            let reconstruct_to_data_allocation_block_index = match cursor
                                .cur_data_allocation_block_index
                                .align_up(cur_node_level_covered_data_allocation_block_index_bits)
                            {
                                Some(reconstruct_to_data_allocation_block_index) => {
                                    reconstruct_to_data_allocation_block_index
                                }
                                None => {
                                    // As per being here, the current node's covered data region ends
                                    // before or at the next stop, hence before the image end.
                                    break Err(nvfs_err_internal!());
                                }
                            };
                            let cursor = match this.cursor.take() {
                                Some(cursor) => cursor,
                                None => break Err(nvfs_err_internal!()),
                            };
                            if cur_node_level == 0 {
                                let reconstruct_node_part_fut =
                                    match AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsFuture::new(
                                        chip,
                                        cursor,
                                        reconstruct_to_data_allocation_block_index,
                                        tree_config,
                                    ) {
                                        Ok(reconstruct_node_part_fut) => reconstruct_node_part_fut,
                                        Err(e) => break Err(e),
                                    };
                                this.fut_state =
                                AuthTreeReplayJournalUpdateScriptCursorAdvanceFutureState::ReconstructLeafNodePart {
                                    reconstruct_node_part_fut,
                                };
                            } else {
                                let reconstruct_node_part_fut =
                                    AuthTreeReplayJournalUpdateScriptCursorReconstructInternalDigestsFuture::new(
                                        cursor,
                                        reconstruct_to_data_allocation_block_index,
                                        mem::take(&mut this.node_read_buf),
                                        tree_config,
                                    );
                                this.fut_state =
                                AuthTreeReplayJournalUpdateScriptCursorAdvanceFutureState::ReconstructInternalNodePart {
                                    reconstruct_node_part_fut
                                };
                            }

                            continue;
                        }
                    }

                    // The current node's covered data region includes the next stop. Possibly
                    // descend and complete the then current node up to the next stop's
                    // corresponding position. Note that a subsequent iteration might repeat that
                    // process if necessary.
                    if cursor.root_path_nodes.is_empty() {
                        debug_assert_eq!(u64::from(cursor.cur_data_allocation_block_index), 0);
                        let root_node = match FixedVec::new_with_default(tree_config.node_size()) {
                            Ok(root_node) => root_node,
                            Err(e) => break Err(NvFsError::from(e)),
                        };
                        cursor.root_path_nodes.push(AuthTreeNode { data: root_node });
                        cur_node_level = tree_config.auth_tree_levels - 1;
                    }
                    // Descend as long as the current entry in the current node covers both,
                    // cur_data_allocation_block_index
                    // and next_stop_data_allocation_block_index.
                    let cur_node_level_covered_data_block_index_bits =
                        AuthTreeNodeId::level_covered_data_block_index_bits(
                            cur_node_level as u32,
                            tree_config.node_digests_per_node_log2 as u32,
                            tree_config.data_digests_per_node_log2 as u32,
                        );
                    let mut cur_node_level_covered_data_allocation_block_index_bits =
                        cur_node_level_covered_data_block_index_bits + data_block_allocation_blocks_log2;
                    while cur_node_level != 0 {
                        let cur_node_entry_covered_data_allocation_block_index_bits =
                            cur_node_level_covered_data_allocation_block_index_bits
                                - tree_config.node_digests_per_node_log2 as u32;
                        debug_assert!(
                            u64::from(cursor.cur_data_allocation_block_index)
                                .is_aligned_pow2(cur_node_entry_covered_data_allocation_block_index_bits)
                        );
                        if (u64::from(cursor.cur_data_allocation_block_index)
                            ^ u64::from(next_stop_data_allocation_block_index))
                            >> cur_node_entry_covered_data_allocation_block_index_bits
                            != 0
                        {
                            break;
                        }

                        let node = match FixedVec::new_with_default(tree_config.node_size()) {
                            Ok(node) => node,
                            Err(e) => break 'outer Err(NvFsError::from(e)),
                        };
                        cursor.root_path_nodes.push(AuthTreeNode { data: node });

                        cur_node_level -= 1;
                        cur_node_level_covered_data_allocation_block_index_bits =
                            cur_node_entry_covered_data_allocation_block_index_bits;
                    }

                    // And reconstruct the current node's part corresponding to
                    // the region between cur_data_allocation_block_index and
                    // next_stop_data_allocation_block_index.
                    if cur_node_level == 0 {
                        let reconstruct_to_data_allocation_block_index = next_stop_data_allocation_block_index;
                        debug_assert_ne!(
                            cursor.cur_data_allocation_block_index,
                            reconstruct_to_data_allocation_block_index
                        );
                        let cursor = match this.cursor.take() {
                            Some(cursor) => cursor,
                            None => break Err(nvfs_err_internal!()),
                        };
                        let reconstruct_node_part_fut =
                            match AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsFuture::new(
                                chip,
                                cursor,
                                reconstruct_to_data_allocation_block_index,
                                tree_config,
                            ) {
                                Ok(reconstruct_node_part_fut) => reconstruct_node_part_fut,
                                Err(e) => break Err(e),
                            };
                        this.fut_state =
                            AuthTreeReplayJournalUpdateScriptCursorAdvanceFutureState::ReconstructLeafNodePart {
                                reconstruct_node_part_fut,
                            };
                    } else {
                        let cur_node_entry_covered_data_allocation_block_index_bits =
                            cur_node_level_covered_data_allocation_block_index_bits
                                - tree_config.node_digests_per_node_log2 as u32;
                        let reconstruct_to_data_allocation_block_index = next_stop_data_allocation_block_index
                            .align_down(cur_node_entry_covered_data_allocation_block_index_bits);
                        debug_assert_ne!(
                            cursor.cur_data_allocation_block_index,
                            reconstruct_to_data_allocation_block_index
                        );
                        let cursor = match this.cursor.take() {
                            Some(cursor) => cursor,
                            None => break Err(nvfs_err_internal!()),
                        };
                        let reconstruct_node_part_fut =
                            AuthTreeReplayJournalUpdateScriptCursorReconstructInternalDigestsFuture::new(
                                cursor,
                                reconstruct_to_data_allocation_block_index,
                                mem::take(&mut this.node_read_buf),
                                tree_config,
                            );
                        this.fut_state =
                            AuthTreeReplayJournalUpdateScriptCursorAdvanceFutureState::ReconstructInternalNodePart {
                                reconstruct_node_part_fut,
                            };
                    }
                }
                AuthTreeReplayJournalUpdateScriptCursorAdvanceFutureState::WriteNode { node_id, write_fut } => {
                    let node = match chip::NvChipFuture::poll(pin::Pin::new(write_fut), chip, cx) {
                        task::Poll::Ready(Ok((node, Ok(())))) => node,
                        task::Poll::Ready(Err(e) | Ok((_, Err(e)))) => break Err(e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    let node = AuthTreeNode { data: node };

                    let cursor = match this.cursor.as_mut() {
                        Some(cursor) => cursor,
                        None => {
                            this.fut_state = AuthTreeReplayJournalUpdateScriptCursorAdvanceFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    if let Some(parent_node) = cursor.root_path_nodes.last_mut() {
                        let (digest_entry_in_child_node_len, digest_entries_in_child_node_log2) = if node_id.level != 0
                        {
                            (tree_config.node_digest_len, tree_config.node_digests_per_node_log2)
                        } else {
                            (tree_config.data_digest_len, tree_config.data_digests_per_node_log2)
                        };
                        if let Err(e) = tree_config.digest_descendant_node_into(
                            parent_node.get_digest_mut(node_id.index_in_parent(), tree_config.node_digest_len as usize),
                            node_id,
                            (0..(1usize << (digest_entries_in_child_node_log2 as u32)))
                                .map(|i| node.get_digest(i, digest_entry_in_child_node_len as usize)),
                        ) {
                            break Err(e);
                        }
                    } else {
                        // Just wrote out the root node, all done.
                        debug_assert!(
                            this.to_physical_allocation_block_index
                                >= layout::PhysicalAllocBlockIndex::from(0u64) + cursor.image_size
                        );
                        cursor.at_end = true;
                        break Ok(());
                    }
                    this.fut_state = AuthTreeReplayJournalUpdateScriptCursorAdvanceFutureState::Init;
                }
                AuthTreeReplayJournalUpdateScriptCursorAdvanceFutureState::ReconstructLeafNodePart {
                    reconstruct_node_part_fut,
                } => {
                    let cursor = match AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsFuture::poll(
                        pin::Pin::new(reconstruct_node_part_fut),
                        chip,
                        tree_config,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(cursor)) => cursor,
                        task::Poll::Ready(Err(e)) => break Err(e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    this.cursor = Some(cursor);
                    this.fut_state = AuthTreeReplayJournalUpdateScriptCursorAdvanceFutureState::Init;
                }
                AuthTreeReplayJournalUpdateScriptCursorAdvanceFutureState::ReconstructInternalNodePart {
                    reconstruct_node_part_fut,
                } => {
                    let (cursor, node_read_buf) =
                        match AuthTreeReplayJournalUpdateScriptCursorReconstructInternalDigestsFuture::poll(
                            pin::Pin::new(reconstruct_node_part_fut),
                            chip,
                            tree_config,
                            cx,
                        ) {
                            task::Poll::Ready(Ok(cursor)) => cursor,
                            task::Poll::Ready(Err(e)) => break Err(e),
                            task::Poll::Pending => return task::Poll::Pending,
                        };
                    this.cursor = Some(cursor);
                    this.node_read_buf = node_read_buf;
                    this.fut_state = AuthTreeReplayJournalUpdateScriptCursorAdvanceFutureState::Init;
                }
                AuthTreeReplayJournalUpdateScriptCursorAdvanceFutureState::Done => unreachable!(),
            }
        };

        this.fut_state = AuthTreeReplayJournalUpdateScriptCursorAdvanceFutureState::Done;
        task::Poll::Ready(result.and_then(|_| this.cursor.take().ok_or_else(|| nvfs_err_internal!())))
    }
}

/// Reconstruct some contiguous (sub)sequence of a leaf node'sdigest entries in
/// the course of
/// [advancing](AuthTreeReplayJournalUpdateScriptCursorAdvanceFuture) a
/// [`AuthTreeReplayJournalUpdateScriptCursor`].
struct AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsFuture<C: chip::NvChip> {
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self.
    cursor: Option<Box<AuthTreeReplayJournalUpdateScriptCursor>>,
    fut_state: AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsFutureState<C>,
    to_data_allocation_block_index: AuthTreeDataAllocBlockIndex,
    read_buffers: FixedVec<FixedVec<u8, 7>, 0>,
    preferred_chip_io_bulk_allocation_blocks_log2: u8,
}

/// Internal [`AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsFuture::poll()`] state-machine state.
enum AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsFutureState<C: chip::NvChip> {
    PrepareReadData,
    ReadData {
        read_fut: C::ReadFuture<AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsReadDataRequest>,
        read_region_physical_allocation_blocks_end: layout::PhysicalAllocBlockIndex,
    },
    Done,
}

impl<C: chip::NvChip> AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsFuture<C> {
    /// Instantiate a new
    /// [`AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsFuture`]
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `cursor` - The [`AuthTreeReplayJournalUpdateScriptCursor`] to advance.
    /// * `to_data_allocation_block_index` - Target position to advance the
    ///   cursor to. Must be located at some [Authentication Tree Data
    ///   Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    ///   boundary covered by the `cursor`'s current bottom node, which must be
    ///   a leaf.
    /// * `tree_config` - The filesystem's [`AuthTreeConfig`].
    fn new(
        chip: &C,
        cursor: Box<AuthTreeReplayJournalUpdateScriptCursor>,
        to_data_allocation_block_index: AuthTreeDataAllocBlockIndex,
        tree_config: &AuthTreeConfig,
    ) -> Result<Self, NvFsError> {
        let allocation_block_size_128b_log2 = tree_config.allocation_block_size_128b_log2 as u32;
        let chip_io_block_allocation_blocks_log2 = chip
            .chip_io_block_size_128b_log2()
            .saturating_sub(allocation_block_size_128b_log2);
        let data_block_allocation_blocks_log2 = tree_config.data_block_allocation_blocks_log2 as u32;

        let image_data_allocation_blocks = layout::AllocBlockCount::from(u64::from(
            cursor.aligned_image_size
                - tree_config
                    .auth_tree_data_allocation_blocks_map
                    .total_auth_tree_extents_allocation_blocks(),
        ));
        debug_assert!(
            to_data_allocation_block_index <= AuthTreeDataAllocBlockIndex::from(0u64) + image_data_allocation_blocks
        );

        // The current root path extends all the way down to a leaf node.
        debug_assert_eq!(cursor.root_path_nodes.len(), tree_config.auth_tree_levels as usize);
        // Updates + cursor advancements always happen in units of the IO Block size.
        debug_assert!(
            cursor.cur_data_allocation_block_index >= cursor.cur_contiguous_data_allocation_blocks_range_end
                || u64::from(cursor.cur_physical_allocation_block_index)
                    .is_aligned_pow2(chip_io_block_allocation_blocks_log2)
        );
        // The Authentication Tree extents are aligned to the larger of the IO Block and
        // Authentication Tree Data Block size. Thus, any physical index alignment
        // constraints <= than that translate to the Authentication Tree data index
        // domain.
        debug_assert!(
            u64::from(cursor.cur_data_allocation_block_index).is_aligned_pow2(chip_io_block_allocation_blocks_log2)
        );
        debug_assert!(u64::from(to_data_allocation_block_index).is_aligned_pow2(chip_io_block_allocation_blocks_log2));
        debug_assert!(to_data_allocation_block_index >= cursor.cur_data_allocation_block_index);
        debug_assert!(
            u64::from(to_data_allocation_block_index)
                <= tree_config.max_covered_data_block_count << data_block_allocation_blocks_log2
        );
        // There's a pending Authentication Tree Data Block update context only if
        // not at a Authentication Tree Data Block boundary.
        debug_assert!(
            !u64::from(cursor.cur_data_allocation_block_index).is_aligned_pow2(data_block_allocation_blocks_log2)
                || cursor.digest_cur_data_block_context.is_none()
        );
        // The current and target positions should be within the range covered
        // by a single Authentication Tree Leaf node.
        let leaf_node_covered_data_allocation_block_index_bits =
            tree_config.data_digests_per_node_log2 as u32 + data_block_allocation_blocks_log2;
        debug_assert!(
            (1u64 << leaf_node_covered_data_allocation_block_index_bits)
                >= u64::from(
                    to_data_allocation_block_index
                        - cursor
                            .cur_data_allocation_block_index
                            .align_down(leaf_node_covered_data_allocation_block_index_bits)
                )
        );

        let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();
        let chip_io_block_allocations_blocks_log2 =
            chip_io_block_size_128b_log2.saturating_sub(allocation_block_size_128b_log2);
        let preferred_chip_io_bulk_allocation_blocks_log2 = (chip.preferred_chip_io_blocks_bulk_log2()
            + chip_io_block_size_128b_log2)
            .saturating_sub(allocation_block_size_128b_log2)
            .max(chip_io_block_allocation_blocks_log2)
            .min(usize::BITS - 1 + chip_io_block_allocations_blocks_log2);

        // Allocate read buffers with one entry for each Chip IO Block in the preferred
        // bulk range. However, if the total range to read is less than that, allocate
        // only what's needed for reading it all at once.
        let read_buffers_len =
            (1usize << (preferred_chip_io_bulk_allocation_blocks_log2 - chip_io_block_allocations_blocks_log2)).min(
                usize::try_from(
                    u64::from(to_data_allocation_block_index - cursor.cur_data_allocation_block_index)
                        >> chip_io_block_allocations_blocks_log2,
                )
                .unwrap_or(usize::MAX),
            );
        let mut read_buffers = FixedVec::new_with_default(read_buffers_len)?;
        for read_buffer in read_buffers.iter_mut() {
            *read_buffer = FixedVec::new_with_default(
                1usize << (chip_io_block_allocations_blocks_log2 + allocation_block_size_128b_log2 + 7),
            )?;
        }

        Ok(Self {
            cursor: Some(cursor),
            fut_state: AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsFutureState::PrepareReadData,
            to_data_allocation_block_index,
            read_buffers,
            preferred_chip_io_bulk_allocation_blocks_log2: preferred_chip_io_bulk_allocation_blocks_log2 as u8,
        })
    }

    /// Poll the [`AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsFuture`] to completion.
    ///
    /// Upon successful completion, the
    /// [`AuthTreeReplayJournalUpdateScriptCursor`] will get returned back.
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `tree_config` - The filesystem's [`AuthTree`]'s [`AuthTreeConfig`].
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    fn poll(
        self: pin::Pin<&mut Self>,
        chip: &C,
        tree_config: &AuthTreeConfig,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<Box<AuthTreeReplayJournalUpdateScriptCursor>, NvFsError>> {
        let this = pin::Pin::into_inner(self);

        let cursor = match this.cursor.as_mut() {
            Some(cursor) => cursor,
            None => {
                this.fut_state = AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsFutureState::Done;
                return task::Poll::Ready(Err(nvfs_err_internal!()));
            }
        };

        let result = 'outer: loop {
            match &mut this.fut_state {
                AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsFutureState::PrepareReadData => {
                    // Digest the leading sequence of completely unallocated Chip IO Blocks at the
                    // current position, if any, as such. Then determine the maximum possible
                    // sequence of Chip IO Blocks with some allocations within them to read.
                    let allocation_block_size_128b_log2 = tree_config.allocation_block_size_128b_log2 as u32;
                    let data_block_allocation_blocks_log2 = tree_config.data_block_allocation_blocks_log2 as u32;
                    let chip_io_block_allocations_blocks_log2 = chip
                        .chip_io_block_size_128b_log2()
                        .saturating_sub(allocation_block_size_128b_log2);
                    debug_assert!(
                        u64::from(cursor.cur_data_allocation_block_index)
                            .is_aligned_pow2(chip_io_block_allocations_blocks_log2)
                    );

                    if cursor.cur_data_allocation_block_index == this.to_data_allocation_block_index {
                        break Ok(());
                    }

                    if cursor.cur_data_allocation_block_index >= cursor.cur_contiguous_data_allocation_blocks_range_end
                    {
                        if let Err(e) = cursor.update_physical_position(tree_config) {
                            break Err(e);
                        }
                    }

                    let empty_pending_allocs = SparseAllocBitmapUnion::new(&[]);
                    let empty_pending_frees = SparseAllocBitmapUnion::new(&[]);
                    let mut chip_io_block_chunked_alloc_bitmap_iter =
                        cursor.alloc_bitmap_journal_fragments.iter_chunked_at_allocation_block(
                            &empty_pending_allocs,
                            &empty_pending_frees,
                            cursor.cur_physical_allocation_block_index,
                            1u32 << chip_io_block_allocations_blocks_log2,
                        );
                    loop {
                        debug_assert_eq!(
                            u64::from(cursor.cur_data_allocation_block_index)
                                .is_aligned_pow2(data_block_allocation_blocks_log2),
                            cursor.digest_cur_data_block_context.is_none()
                        );

                        let cur_chip_io_block_alloc_bitmap =
                            chip_io_block_chunked_alloc_bitmap_iter.next().unwrap_or(0);
                        if cur_chip_io_block_alloc_bitmap != 0 {
                            // Some of the Chip IO Block's Allocation Blocks are allocated and the Chip IO
                            // block needs to get read.
                            break;
                        }

                        for _ in 0..1u64 << chip_io_block_allocations_blocks_log2 {
                            let digest_cur_data_block_context = match cursor.digest_cur_data_block_context.as_mut() {
                                Some(digest_cur_data_block_context) => digest_cur_data_block_context,
                                None => {
                                    let data_block_hmac_instance =
                                        match cursor.data_block_hmac_instance_init.try_clone() {
                                            Ok(data_block_hmac_instance) => data_block_hmac_instance,
                                            Err(e) => break 'outer Err(NvFsError::from(e)),
                                        };
                                    cursor
                                        .digest_cur_data_block_context
                                        .insert(AuthTreeDigestDataBlockContext::new(
                                            data_block_hmac_instance,
                                            tree_config.data_block_allocation_blocks_log2,
                                            tree_config.allocation_block_size_128b_log2,
                                        ))
                                }
                            };

                            if let Err(e) = digest_cur_data_block_context.update(None) {
                                break 'outer Err(e);
                            }

                            cursor.cur_physical_allocation_block_index += layout::AllocBlockCount::from(1);
                            while cursor.journal_update_script_index != cursor.journal_update_script.len()
                                && cursor.journal_update_script[cursor.journal_update_script_index]
                                    .get_target_range()
                                    .end()
                                    <= cursor.cur_physical_allocation_block_index
                            {
                                cursor.journal_update_script_index += 1;
                            }
                            cursor.cur_data_allocation_block_index += layout::AllocBlockCount::from(1);
                            if u64::from(cursor.cur_physical_allocation_block_index)
                                .is_aligned_pow2(data_block_allocation_blocks_log2)
                            {
                                let digest_cur_data_block_context = match cursor.digest_cur_data_block_context.take() {
                                    Some(digest_cur_data_block_context) => digest_cur_data_block_context,
                                    None => break 'outer Err(nvfs_err_internal!()),
                                };

                                let cur_data_block_index = AuthTreeDataBlockIndex::new_from_data_allocation_block_index(
                                    AuthTreeDataAllocBlockIndex::from(
                                        u64::from(cursor.cur_data_allocation_block_index) - 1,
                                    ),
                                    data_block_allocation_blocks_log2,
                                );
                                let leaf_node = &mut cursor.root_path_nodes[tree_config.auth_tree_levels as usize - 1];
                                let leaf_node_digest_entry = leaf_node.get_digest_mut(
                                    (u64::from(cur_data_block_index)
                                        & u64::trailing_bits_mask(tree_config.data_digests_per_node_log2 as u32))
                                        as usize,
                                    tree_config.data_digest_len as usize,
                                );
                                if let Err(e) = digest_cur_data_block_context
                                    .finalize_into(leaf_node_digest_entry, cur_data_block_index)
                                {
                                    break 'outer Err(e);
                                }

                                if cursor.cur_physical_allocation_block_index
                                    == layout::PhysicalAllocBlockIndex::from(0u64) + cursor.aligned_image_size
                                {
                                    // Any excess digests are filled with zeroes.
                                    // Advancing to beyond the image end is only being done for
                                    // the final cursor unwind.
                                    debug_assert!(
                                        u64::from(this.to_data_allocation_block_index)
                                            .is_aligned_pow2(data_block_allocation_blocks_log2)
                                    );
                                    break 'outer Ok(());
                                }
                            }
                        }

                        if cursor.cur_data_allocation_block_index == this.to_data_allocation_block_index {
                            break 'outer Ok(());
                        }

                        if cursor.cur_data_allocation_block_index
                            >= cursor.cur_contiguous_data_allocation_blocks_range_end
                        {
                            // The Authentication Tree's extents are aligned to the Authentication Tree Data
                            // Block size, so the same applies to the data regions
                            // inbetween.
                            debug_assert!(
                                u64::from(cursor.cur_physical_allocation_block_index)
                                    .is_aligned_pow2(data_block_allocation_blocks_log2)
                            );
                            if let Err(e) = cursor.update_physical_position(tree_config) {
                                break 'outer Err(e);
                            }

                            chip_io_block_chunked_alloc_bitmap_iter =
                                cursor.alloc_bitmap_journal_fragments.iter_chunked_at_allocation_block(
                                    &empty_pending_allocs,
                                    &empty_pending_frees,
                                    cursor.cur_physical_allocation_block_index,
                                    1u32 << chip_io_block_allocations_blocks_log2,
                                );
                        }
                    }

                    debug_assert_ne!(
                        cursor.cur_data_allocation_block_index,
                        this.to_data_allocation_block_index
                    );
                    debug_assert_ne!(
                        cursor.cur_physical_allocation_block_index,
                        layout::PhysicalAllocBlockIndex::from(0u64) + cursor.aligned_image_size
                    );
                    // All Allocation Blocks beyond the image_size are considered unallocated,
                    // hence, once at the image end, the cursor would have been advanced all the way
                    // to the aligned end above.
                    debug_assert!(
                        cursor.cur_physical_allocation_block_index
                            < layout::PhysicalAllocBlockIndex::from(0u64) + cursor.image_size
                    );
                    let read_region_physical_allocation_blocks_begin = cursor.cur_physical_allocation_block_index;
                    let mut read_region_physical_allocation_blocks_end = read_region_physical_allocation_blocks_begin
                        + layout::AllocBlockCount::from(1u64 << chip_io_block_allocations_blocks_log2);
                    let mut cur_data_allocation_block_index = cursor.cur_data_allocation_block_index
                        + layout::AllocBlockCount::from(1u64 << chip_io_block_allocations_blocks_log2);
                    while cur_data_allocation_block_index != this.to_data_allocation_block_index
                        && cur_data_allocation_block_index != cursor.cur_contiguous_data_allocation_blocks_range_end
                    {
                        // If crossing a preferred Chip IO boundary, stop.
                        if (u64::from(read_region_physical_allocation_blocks_begin)
                            ^ u64::from(read_region_physical_allocation_blocks_end))
                            >> (this.preferred_chip_io_bulk_allocation_blocks_log2 as u32)
                            != 0
                        {
                            break;
                        }

                        // If all of the next Chip IO block's Allocation Blocks are unallocated, it
                        // doesn't need to get read. Stop then.
                        let cur_chip_io_block_alloc_bitmap =
                            chip_io_block_chunked_alloc_bitmap_iter.next().unwrap_or(0);
                        if cur_chip_io_block_alloc_bitmap == 0 {
                            break;
                        }

                        read_region_physical_allocation_blocks_end +=
                            layout::AllocBlockCount::from(1u64 << chip_io_block_allocations_blocks_log2);
                        cur_data_allocation_block_index +=
                            layout::AllocBlockCount::from(1u64 << chip_io_block_allocations_blocks_log2);
                    }

                    let read_request_region = match chip::ChunkedIoRegion::new(
                        u64::from(read_region_physical_allocation_blocks_begin) << allocation_block_size_128b_log2,
                        u64::from(read_region_physical_allocation_blocks_end) << allocation_block_size_128b_log2,
                        chip_io_block_allocations_blocks_log2 + allocation_block_size_128b_log2,
                    ) {
                        Ok(read_request_region) => read_request_region,
                        Err(e) => {
                            break Err(match e {
                                chip::ChunkedIoRegionError::ChunkSizeOverflow => {
                                    // The Chip IO block size fits an usize.
                                    nvfs_err_internal!()
                                }
                                chip::ChunkedIoRegionError::InvalidBounds => {
                                    nvfs_err_internal!()
                                }
                                chip::ChunkedIoRegionError::ChunkIndexOverflow => {
                                    // No more that the preferred Chip IO block size is ever read at once and
                                    // that in units of Chip IO Blocks has been capped to fit an usize.
                                    nvfs_err_internal!()
                                }
                                chip::ChunkedIoRegionError::RegionUnaligned => nvfs_err_internal!(),
                            });
                        }
                    };
                    let read_request = AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsReadDataRequest {
                        region: read_request_region,
                        read_buffers: mem::take(&mut this.read_buffers),
                    };
                    let read_fut = match chip.read(read_request) {
                        Ok(Ok(read_fut)) => read_fut,
                        Err(e) | Ok(Err((_, e))) => break Err(NvFsError::from(e)),
                    };
                    this.fut_state =
                        AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsFutureState::ReadData {
                            read_fut,
                            read_region_physical_allocation_blocks_end,
                        };
                }
                AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsFutureState::ReadData {
                    read_fut,
                    read_region_physical_allocation_blocks_end,
                } => {
                    let allocation_block_size_128b_log2 = tree_config.allocation_block_size_128b_log2 as u32;
                    let data_block_allocation_blocks_log2 = tree_config.data_block_allocation_blocks_log2 as u32;
                    let chip_io_block_allocations_blocks_log2 = chip
                        .chip_io_block_size_128b_log2()
                        .saturating_sub(allocation_block_size_128b_log2);

                    let read_request = match chip::NvChipFuture::poll(pin::Pin::new(read_fut), chip, cx) {
                        task::Poll::Ready(Ok((read_request, Ok(())))) => read_request,
                        task::Poll::Ready(Err(e) | Ok((_, Err(e)))) => break Err(NvFsError::from(e)),
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    let AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsReadDataRequest {
                        read_buffers,
                        ..
                    } = read_request;
                    this.read_buffers = read_buffers;

                    let empty_pending_allocs = SparseAllocBitmapUnion::new(&[]);
                    let empty_pending_frees = SparseAllocBitmapUnion::new(&[]);
                    let mut chip_io_block_chunked_alloc_bitmap_iter =
                        cursor.alloc_bitmap_journal_fragments.iter_chunked_at_allocation_block(
                            &empty_pending_allocs,
                            &empty_pending_frees,
                            cursor.cur_physical_allocation_block_index,
                            1u32 << chip_io_block_allocations_blocks_log2,
                        );

                    let mut chip_io_block_index = 0;
                    while cursor.cur_physical_allocation_block_index != *read_region_physical_allocation_blocks_end {
                        let chip_io_block = &this.read_buffers[chip_io_block_index];
                        let mut cur_chip_io_block_alloc_bitmap =
                            chip_io_block_chunked_alloc_bitmap_iter.next().unwrap_or(0);
                        for allocation_block_in_chip_io_block_index in
                            0..1usize << chip_io_block_allocations_blocks_log2
                        {
                            let digest_cur_data_block_context = match cursor.digest_cur_data_block_context.as_mut() {
                                Some(digest_cur_data_block_context) => digest_cur_data_block_context,
                                None => {
                                    let data_block_hmac_instance =
                                        match cursor.data_block_hmac_instance_init.try_clone() {
                                            Ok(data_block_hmac_instance) => data_block_hmac_instance,
                                            Err(e) => break 'outer Err(NvFsError::from(e)),
                                        };
                                    cursor
                                        .digest_cur_data_block_context
                                        .insert(AuthTreeDigestDataBlockContext::new(
                                            data_block_hmac_instance,
                                            tree_config.data_block_allocation_blocks_log2,
                                            tree_config.allocation_block_size_128b_log2,
                                        ))
                                }
                            };

                            let allocation_block = &chip_io_block[allocation_block_in_chip_io_block_index
                                << (allocation_block_size_128b_log2 + 7)
                                ..(allocation_block_in_chip_io_block_index + 1)
                                    << (allocation_block_size_128b_log2 + 7)];
                            if let Err(e) = digest_cur_data_block_context
                                .update((cur_chip_io_block_alloc_bitmap & 1 != 0).then_some(allocation_block))
                            {
                                break 'outer Err(e);
                            }

                            cur_chip_io_block_alloc_bitmap >>= 1;
                            cursor.cur_physical_allocation_block_index += layout::AllocBlockCount::from(1);
                            while cursor.journal_update_script_index != cursor.journal_update_script.len()
                                && cursor.journal_update_script[cursor.journal_update_script_index]
                                    .get_target_range()
                                    .end()
                                    <= cursor.cur_physical_allocation_block_index
                            {
                                cursor.journal_update_script_index += 1;
                            }
                            cursor.cur_data_allocation_block_index += layout::AllocBlockCount::from(1);
                            if u64::from(cursor.cur_physical_allocation_block_index)
                                .is_aligned_pow2(data_block_allocation_blocks_log2)
                            {
                                let digest_cur_data_block_context = match cursor.digest_cur_data_block_context.take() {
                                    Some(digest_cur_data_block_context) => digest_cur_data_block_context,
                                    None => break 'outer Err(nvfs_err_internal!()),
                                };

                                let cur_data_block_index = AuthTreeDataBlockIndex::new_from_data_allocation_block_index(
                                    AuthTreeDataAllocBlockIndex::from(
                                        u64::from(cursor.cur_data_allocation_block_index) - 1,
                                    ),
                                    data_block_allocation_blocks_log2,
                                );
                                let leaf_node = &mut cursor.root_path_nodes[tree_config.auth_tree_levels as usize - 1];
                                let leaf_node_digest_entry = leaf_node.get_digest_mut(
                                    (u64::from(cur_data_block_index)
                                        & u64::trailing_bits_mask(tree_config.data_digests_per_node_log2 as u32))
                                        as usize,
                                    tree_config.data_digest_len as usize,
                                );
                                if let Err(e) = digest_cur_data_block_context
                                    .finalize_into(leaf_node_digest_entry, cur_data_block_index)
                                {
                                    break 'outer Err(e);
                                }
                            }
                        }

                        chip_io_block_index += 1;
                    }
                    this.fut_state =
                        AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsFutureState::PrepareReadData;
                }
                AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsFutureState::Done => unreachable!(),
            }
        };

        this.fut_state = AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsFutureState::Done;
        task::Poll::Ready(result.and_then(|_| this.cursor.take().ok_or_else(|| nvfs_err_internal!())))
    }
}

/// [`NvChipReadRequest`](chip::NvChipReadRequest) implementation used
/// internally by
/// [`AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsFuture`].
struct AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsReadDataRequest {
    region: chip::ChunkedIoRegion,
    read_buffers: FixedVec<FixedVec<u8, 7>, 0>,
}

impl chip::NvChipReadRequest for AuthTreeReplayJournalUpdateScriptCursorReconstructLeafDigestsReadDataRequest {
    fn region(&self) -> &chip::ChunkedIoRegion {
        &self.region
    }
    fn get_destination_buffer(
        &mut self,
        range: &chip::ChunkedIoRegionChunkRange,
    ) -> Result<Option<&mut [u8]>, chip::NvChipIoError> {
        let (read_buffer_index, _) = range.chunk().decompose_to_hierarchic_indices([]);
        Ok(Some(
            &mut self.read_buffers[read_buffer_index][range.range_in_chunk().clone()],
        ))
    }
}

/// Reconstruct some contiguous (sub)sequence of a non-leaf node's digest
/// entries in the course of
/// [advancing](AuthTreeReplayJournalUpdateScriptCursorAdvanceFuture) a
/// [`AuthTreeReplayJournalUpdateScriptCursor`].
struct AuthTreeReplayJournalUpdateScriptCursorReconstructInternalDigestsFuture<C: chip::NvChip> {
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self.
    cursor: Option<Box<AuthTreeReplayJournalUpdateScriptCursor>>,
    fut_state: AuthTreeReplayJournalUpdateScriptCursorReconstructInternalDigestsFutureState<C>,
    to_data_allocation_block_index: AuthTreeDataAllocBlockIndex,
    node_read_buf: FixedVec<u8, 7>,
}

/// Internal [`AuthTreeReplayJournalUpdateScriptCursorReconstructInternalDigestsFuture::poll()`] state-machine state.
enum AuthTreeReplayJournalUpdateScriptCursorReconstructInternalDigestsFutureState<C: chip::NvChip> {
    PrepareReadChildNode,
    ReadChildNode {
        child_node_id: AuthTreeNodeId,
        read_fut: AuthTreeNodeReadFuture<C>,
    },
    Done,
}

impl<C: chip::NvChip> AuthTreeReplayJournalUpdateScriptCursorReconstructInternalDigestsFuture<C> {
    /// Instantiate a new
    /// [`AuthTreeReplayJournalUpdateScriptCursorReconstructInternalDigestsFuture`]
    ///
    /// # Arguments:
    ///
    /// * `cursor` - The [`AuthTreeReplayJournalUpdateScriptCursor`] to advance.
    /// * `to_data_allocation_block_index` - Target position to advance the
    ///   cursor to. Must be located at the boundary of a region covered by some
    ///   digest entry in the `cursor`'s current bottom node, which must be a
    ///   non-leaf.
    /// * `node_read_buf` - Possily recycled buffer for reading child nodes. May
    ///   be of any size. Will get returned back upon successful
    ///   [`poll()`](Self::poll) completion.
    /// * `tree_config` - The filesystem's [`AuthTreeConfig`].
    fn new(
        cursor: Box<AuthTreeReplayJournalUpdateScriptCursor>,
        to_data_allocation_block_index: AuthTreeDataAllocBlockIndex,
        node_read_buf: FixedVec<u8, 7>,
        tree_config: &AuthTreeConfig,
    ) -> Self {
        debug_assert!(!cursor.root_path_nodes.is_empty());
        // The current node at the root path's bottom to update should be an internal
        // one.
        debug_assert!(cursor.root_path_nodes.len() < tree_config.auth_tree_levels as usize);
        let cur_node_level = (tree_config.auth_tree_levels as usize - cursor.root_path_nodes.len()) as u8;
        let data_block_allocation_blocks_log2 = tree_config.data_block_allocation_blocks_log2 as u32;
        let node_digests_per_node_log2 = tree_config.node_digests_per_node_log2 as u32;
        let entry_covered_data_block_index_bits = AuthTreeNodeId::level_covered_data_block_index_bits(
            cur_node_level as u32 - 1,
            node_digests_per_node_log2,
            tree_config.data_digests_per_node_log2 as u32,
        );
        let entry_covered_data_allocation_block_index_bits =
            entry_covered_data_block_index_bits + data_block_allocation_blocks_log2;
        // Proper subtrees always cover <= 2^(u64::BITS - 1) Authentication Tree Data
        // Blocks, c.f. auth_tree_node_count_to_auth_tree_levels().
        debug_assert!(entry_covered_data_block_index_bits < u64::BITS);
        // The current and target position should be aligned to the current node's
        // entries' respective covered data range each.
        debug_assert!(
            u64::from(cursor.cur_data_allocation_block_index)
                .is_aligned_pow2(entry_covered_data_allocation_block_index_bits)
        );
        debug_assert!(
            u64::from(to_data_allocation_block_index).is_aligned_pow2(entry_covered_data_allocation_block_index_bits)
        );
        // And the range inbetween should be covered by the current node.  Note that if
        // to_data_allocation_block_index points to right after an integral (power of
        // two) of what's covered by complete subtrees descendant from the root,
        // then it might have wrapped to zero.
        debug_assert!(
            cursor.cur_data_allocation_block_index <= to_data_allocation_block_index
                || u64::from(to_data_allocation_block_index) == 0
        );
        // The range from the current position up to to_auth_tree_data_block_index
        // should all be covered by the current node. First verify this is true
        // for the case that to_data_allocation_block_index did not wrap to
        // zero.
        debug_assert!(
            cursor.cur_data_allocation_block_index > to_data_allocation_block_index
                || 1u64 << node_digests_per_node_log2
                    >= (u64::from(to_data_allocation_block_index) >> entry_covered_data_allocation_block_index_bits)
                        - (u64::from(cursor.cur_data_allocation_block_index)
                            >> entry_covered_data_allocation_block_index_bits)
                            .round_down_pow2(node_digests_per_node_log2)
        );
        // If to_data_allocation_block_index had wrapped to zero, then stepping
        // cur_data_allocation_block_index to the end of the region covered by the
        // current node (or, for the root node, past the last entry in range)
        // should as well.
        debug_assert!(
            cursor.cur_data_allocation_block_index <= to_data_allocation_block_index
                || u64::from(cursor.cur_data_allocation_block_index).wrapping_neg()
                    >> entry_covered_data_allocation_block_index_bits
                    <= 1u64 << node_digests_per_node_log2
        );

        Self {
            cursor: Some(cursor),
            fut_state:
                AuthTreeReplayJournalUpdateScriptCursorReconstructInternalDigestsFutureState::PrepareReadChildNode,
            to_data_allocation_block_index,
            node_read_buf,
        }
    }

    /// Poll the [`AuthTreeReplayJournalUpdateScriptCursorReconstructInternalDigestsFuture`] to completion.
    ///
    /// Upon successful completion, a pair of the
    /// [`AuthTreeReplayJournalUpdateScriptCursor`] and the child node read
    /// buffer initially passed to [`new()`](Self::new) will get returned
    /// back.
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `tree_config` - The filesystem's [`AuthTree`]'s [`AuthTreeConfig`].
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    #[allow(clippy::type_complexity)]
    fn poll(
        self: pin::Pin<&mut Self>,
        chip: &C,
        tree_config: &AuthTreeConfig,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(Box<AuthTreeReplayJournalUpdateScriptCursor>, FixedVec<u8, 7>), NvFsError>> {
        let this = pin::Pin::into_inner(self);

        let cursor = match this.cursor.as_mut() {
            Some(cursor) => cursor,
            None => {
                this.fut_state = AuthTreeReplayJournalUpdateScriptCursorReconstructInternalDigestsFutureState::Done;
                return task::Poll::Ready(Err(nvfs_err_internal!()));
            }
        };

        let result =
            loop {
                match &mut this.fut_state {
                AuthTreeReplayJournalUpdateScriptCursorReconstructInternalDigestsFutureState::PrepareReadChildNode => {
                    if cursor.cur_data_allocation_block_index == this.to_data_allocation_block_index {
                        break Ok(());
                    }

                    let cur_node_level = (tree_config.auth_tree_levels as usize - cursor.root_path_nodes.len()) as u8;
                    let cur_child_node_id = AuthTreeNodeId::new(
                        AuthTreeDataBlockIndex::new_from_data_allocation_block_index(
                            cursor.cur_data_allocation_block_index,
                            tree_config.data_block_allocation_blocks_log2 as u32,
                        ),
                        cur_node_level - 1,
                        tree_config.node_digests_per_node_log2,
                        tree_config.data_digests_per_node_log2,
                    );
                    let read_fut = match AuthTreeNodeReadFuture::new_with_buf(
                        chip,
                        tree_config,
                        &cur_child_node_id,
                        mem::take(&mut this.node_read_buf),
                    ) {
                        Ok(read_fut) => read_fut,
                        Err(e) => break Err(e),
                    };
                    this.fut_state =
                        AuthTreeReplayJournalUpdateScriptCursorReconstructInternalDigestsFutureState::ReadChildNode {
                            child_node_id: cur_child_node_id,
                            read_fut,
                        };
                }
                AuthTreeReplayJournalUpdateScriptCursorReconstructInternalDigestsFutureState::ReadChildNode {
                    child_node_id,
                    read_fut,
                } => {
                    let child_node_data = match chip::NvChipFuture::poll(pin::Pin::new(read_fut), chip, cx) {
                        task::Poll::Ready(Ok(child_node)) => child_node,
                        task::Poll::Ready(Err(e)) => break Err(e),
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    let child_node = AuthTreeNode { data: child_node_data };

                    let root_path_nodes_len = cursor.root_path_nodes.len();
                    let cur_node = &mut cursor.root_path_nodes[root_path_nodes_len - 1];

                    let (digest_entry_in_child_node_len, digest_entries_in_child_node_log2) =
                        if child_node_id.level != 0 {
                            (tree_config.node_digest_len, tree_config.node_digests_per_node_log2)
                        } else {
                            (tree_config.data_digest_len, tree_config.data_digests_per_node_log2)
                        };
                    if let Err(e) = tree_config.digest_descendant_node_into(
                        cur_node.get_digest_mut(child_node_id.index_in_parent(), tree_config.node_digest_len as usize),
                        child_node_id,
                        (0..(1usize << (digest_entries_in_child_node_log2 as u32)))
                            .map(|i| child_node.get_digest(i, digest_entry_in_child_node_len as usize)),
                    ) {
                        break Err(e);
                    }

                    AuthTreeNode {
                        data: this.node_read_buf,
                    } = child_node;

                    let cur_node_level = (tree_config.auth_tree_levels as usize - cursor.root_path_nodes.len()) as u8;
                    let entry_covered_data_block_index_bits = AuthTreeNodeId::level_covered_data_block_index_bits(
                        cur_node_level as u32 - 1,
                        tree_config.node_digests_per_node_log2 as u32,
                        tree_config.data_digests_per_node_log2 as u32,
                    );
                    let entry_covered_data_allocation_block_index_bits =
                        entry_covered_data_block_index_bits + tree_config.data_block_allocation_blocks_log2 as u32;
                    // When moving to the end of the region covered by a complete subtree descendant
                    // from the root, the position might wrap to zero.
                    debug_assert!(u64::from(cursor.cur_data_allocation_block_index)
                        .is_aligned_pow2(entry_covered_data_allocation_block_index_bits));
                    cursor.cur_data_allocation_block_index = AuthTreeDataAllocBlockIndex::from(
                        u64::from(cursor.cur_data_allocation_block_index)
                            .wrapping_add(1u64 << entry_covered_data_allocation_block_index_bits),
                    );
                    debug_assert!(
                        u64::from(cursor.cur_data_allocation_block_index) != 0
                            || u64::from(this.to_data_allocation_block_index) == 0
                    );

                    if u64::from(cursor.cur_data_allocation_block_index) != 0
                        && cursor.cur_data_allocation_block_index
                            < cursor.cur_contiguous_data_allocation_blocks_range_end
                    {
                        cursor.cur_physical_allocation_block_index +=
                            layout::AllocBlockCount::from(1u64 << entry_covered_data_allocation_block_index_bits);

                        // We're never skipping over a journal_update_script entry by advancing at
                        // non-leaf level.
                        debug_assert!(
                            cursor.journal_update_script_index == cursor.journal_update_script.len()
                                || cursor.cur_physical_allocation_block_index
                                    <= cursor.journal_update_script[cursor.journal_update_script_index]
                                        .get_target_range()
                                        .begin()
                        );
                    }

                    this.fut_state = AuthTreeReplayJournalUpdateScriptCursorReconstructInternalDigestsFutureState::
                                        PrepareReadChildNode;
                }

                AuthTreeReplayJournalUpdateScriptCursorReconstructInternalDigestsFutureState::Done => unreachable!(),
            }
            };

        this.fut_state = AuthTreeReplayJournalUpdateScriptCursorReconstructInternalDigestsFutureState::Done;
        task::Poll::Ready(result.and_then(|_| {
            this.cursor
                .take()
                .ok_or_else(|| nvfs_err_internal!())
                .map(|cursor| (cursor, mem::take(&mut this.node_read_buf)))
        }))
    }
}

/// Future returned by [`AuthTreeReplayJournalUpdateScriptCursor::update()`] in
/// the
/// [`AuthTreeReplayJournalUpdateScriptCursorUpdateResult::NeedAuthTreePartWrite`] case.
///
/// Write out any completed subtrees' remaining parts and return the
/// [`AuthTreeReplayJournalUpdateScriptCursor`] back.
pub struct AuthTreeReplayJournalUpdateScriptCursorWritePartFuture<C: chip::NvChip> {
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable reference on
    // Self.
    cursor: Option<Box<AuthTreeReplayJournalUpdateScriptCursor>>,
    fut_state: AuthTreeReplayJournalUpdateScriptCursorWritePartFutureState<C>,
}

/// Internal [`AuthTreeReplayJournalUpdateScriptCursorWritePartFuture::poll()`]
/// state-machine state.
enum AuthTreeReplayJournalUpdateScriptCursorWritePartFutureState<C: chip::NvChip> {
    Init,
    WriteNode {
        node_id: AuthTreeNodeId,
        write_fut: AuthTreeNodeWriteFuture<C>,
    },
    Done,
}

impl<C: chip::NvChip> AuthTreeReplayJournalUpdateScriptCursorWritePartFuture<C> {
    /// Instantiate a
    /// [`AuthTreeReplayJournalUpdateScriptCursorWritePartFuture`].
    ///
    /// # Arguments:
    ///
    /// * `cursor` - The [`AuthTreeReplayJournalUpdateScriptCursor`].
    fn new(cursor: Box<AuthTreeReplayJournalUpdateScriptCursor>) -> Self {
        debug_assert!(cursor.digest_cur_data_block_context.is_none());
        Self {
            cursor: Some(cursor),
            fut_state: AuthTreeReplayJournalUpdateScriptCursorWritePartFutureState::Init,
        }
    }

    /// Poll the [`AuthTreeReplayJournalUpdateScriptCursorWritePartFuture`] to
    /// completion.
    ///
    /// Upon successful completion, the [`AuthTreeInitializationCursor`] will
    /// get returned back.
    ///
    /// # Arguments:
    ///
    /// * `chip` - The filesystem image backing storage.
    /// * `tree_config` - The to be created filesystem's [`AuthTreeConfig`].
    /// * `cx` - The context of the asynchronous task on whose behalf the future
    ///   is being polled.
    pub fn poll(
        self: pin::Pin<&mut Self>,
        chip: &C,
        tree_config: &AuthTreeConfig,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<Box<AuthTreeReplayJournalUpdateScriptCursor>, NvFsError>> {
        let this = pin::Pin::into_inner(self);

        let cursor = match this.cursor.as_mut() {
            Some(cursor) => cursor,
            None => {
                this.fut_state = AuthTreeReplayJournalUpdateScriptCursorWritePartFutureState::Done;
                return task::Poll::Ready(Err(nvfs_err_internal!()));
            }
        };

        loop {
            match &mut this.fut_state {
                AuthTreeReplayJournalUpdateScriptCursorWritePartFutureState::Init => {
                    debug_assert!(!cursor.root_path_nodes.is_empty());

                    let data_block_allocation_blocks_log2 = tree_config.data_block_allocation_blocks_log2 as u32;
                    let cur_node_level = (tree_config.auth_tree_levels as usize - cursor.root_path_nodes.len()) as u8;
                    if !u64::from(cursor.cur_data_allocation_block_index).is_aligned_pow2(
                        AuthTreeNodeId::level_covered_data_block_index_bits(
                            cur_node_level as u32,
                            tree_config.node_digests_per_node_log2 as u32,
                            tree_config.data_digests_per_node_log2 as u32,
                        ) + data_block_allocation_blocks_log2,
                    ) {
                        // The current position is not at the end of the region covered by the current
                        // node, all done.
                        this.fut_state = AuthTreeReplayJournalUpdateScriptCursorWritePartFutureState::Done;
                        let cursor = match this.cursor.take() {
                            Some(cursor) => cursor,
                            None => {
                                return task::Poll::Ready(Err(nvfs_err_internal!()));
                            }
                        };
                        return task::Poll::Ready(Ok(cursor));
                    }

                    // The current position aligns with the end of the current
                    // node at the tip of the root path.
                    // Note that the cur_data_allocation_block_index might have
                    // wrapped around to zero at the very end: proper (full)
                    // subtrees are guaranteed to cover a
                    // data range which is a power of two <= 2^63 in length, but
                    // accumulating multiple thereof at the root node can wrap.
                    let node_id = AuthTreeNodeId::new(
                        AuthTreeDataBlockIndex::new_from_data_allocation_block_index(
                            AuthTreeDataAllocBlockIndex::from(
                                u64::from(cursor.cur_data_allocation_block_index).wrapping_sub(1),
                            ),
                            data_block_allocation_blocks_log2,
                        ),
                        cur_node_level,
                        tree_config.node_digests_per_node_log2,
                        tree_config.data_digests_per_node_log2,
                    );
                    let root_path_nodes_len = cursor.root_path_nodes.len();
                    let AuthTreeNode { data: node } = mem::replace(
                        &mut cursor.root_path_nodes[root_path_nodes_len - 1],
                        AuthTreeNode {
                            data: FixedVec::new_empty(),
                        },
                    );
                    cursor.root_path_nodes.truncate(root_path_nodes_len - 1);
                    let write_fut = match AuthTreeNodeWriteFuture::new(chip, tree_config, &node_id, node) {
                        Ok(Ok(write_fut)) => write_fut,
                        Err(e) | Ok(Err((_, e))) => {
                            this.fut_state = AuthTreeReplayJournalUpdateScriptCursorWritePartFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    this.fut_state =
                        AuthTreeReplayJournalUpdateScriptCursorWritePartFutureState::WriteNode { node_id, write_fut };
                }
                AuthTreeReplayJournalUpdateScriptCursorWritePartFutureState::WriteNode { node_id, write_fut } => {
                    let node = match chip::NvChipFuture::poll(pin::Pin::new(write_fut), chip, cx) {
                        task::Poll::Ready(Ok((node, Ok(())))) => node,
                        task::Poll::Ready(Err(e) | Ok((_, Err(e)))) => {
                            this.fut_state = AuthTreeReplayJournalUpdateScriptCursorWritePartFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    let node = AuthTreeNode { data: node };

                    if let Some(parent_node) = cursor.root_path_nodes.last_mut() {
                        let (digest_entry_in_child_node_len, digest_entries_in_child_node_log2) = if node_id.level != 0
                        {
                            (tree_config.node_digest_len, tree_config.node_digests_per_node_log2)
                        } else {
                            (tree_config.data_digest_len, tree_config.data_digests_per_node_log2)
                        };
                        if let Err(e) = tree_config.digest_descendant_node_into(
                            parent_node.get_digest_mut(node_id.index_in_parent(), tree_config.node_digest_len as usize),
                            node_id,
                            (0..(1usize << (digest_entries_in_child_node_log2 as u32)))
                                .map(|i| node.get_digest(i, digest_entry_in_child_node_len as usize)),
                        ) {
                            this.fut_state = AuthTreeReplayJournalUpdateScriptCursorWritePartFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    } else {
                        // Just wrote out the root node, all done.
                        this.fut_state = AuthTreeReplayJournalUpdateScriptCursorWritePartFutureState::Done;
                        let mut cursor = match this.cursor.take() {
                            Some(cursor) => cursor,
                            None => {
                                return task::Poll::Ready(Err(nvfs_err_internal!()));
                            }
                        };
                        cursor.at_end = true;
                        return task::Poll::Ready(Ok(cursor));
                    }
                    this.fut_state = AuthTreeReplayJournalUpdateScriptCursorWritePartFutureState::Init;
                }
                AuthTreeReplayJournalUpdateScriptCursorWritePartFutureState::Done => unreachable!(),
            }
        }
    }
}
