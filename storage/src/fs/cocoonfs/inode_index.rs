// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Functionality related to the inode index B+-tree.

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

use crate::{
    chip,
    crypto::{self, hash, rng, symcipher},
    fs::{
        cocoonfs::{
            alloc_bitmap, auth_subject_ids, auth_tree, encryption_entities,
            extent_ptr::{self, EncodedBlockPtr, EncodedExtentPtr},
            extents,
            fs::{
                CocoonFsAllocateBlockFuture, CocoonFsAllocateBlocksFuture, CocoonFsConfig, CocoonFsSyncStateMemberRef,
                CocoonFsSyncStateReadFuture,
            },
            inode_extents_list::{InodeExtentsListPendingUpdate, InodeExtentsListReadFuture},
            inode_index, keys, layout,
            read_authenticate_extent::ReadAuthenticateExtentFutureResult,
            read_buffer::{self, BufferedReadAuthenticateDataFuture},
            read_inode_data::ReadInodeDataFuture,
            read_preauth,
            transaction::{
                self, auth_tree_data_blocks_update_states::AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
                read_authenticate_data::TransactionReadAuthenticateDataFuture,
            },
            write_inode_data::InodeExtentsPendingReallocation,
            CocoonFsFormatError,
        },
        NvFsError,
    },
    nvfs_err_internal, tpm2_interface,
    utils_async::sync_types::{self, RwLock as _},
    utils_common::{
        alloc::{box_try_new, try_alloc_vec},
        ct_cmp, index_permutation,
        io_slices::{self, IoSlicesIterCommon as _},
        zeroize,
    },
};
use core::{array, cmp, convert, marker, mem, ops, pin, task};

/// Special inodes reserved for internal filesystem use.
#[repr(u32)]
pub enum SpecialInode {
    #[allow(dead_code)]
    NoInode = 0,
    AuthTree = 1,
    AllocBitmap = 2,
    IndexRoot = 3,
    #[allow(dead_code)]
    Reserved = 4,
    JournalLog = 5, // Virtual inode used for key derivation.
}

pub const SPECIAL_INODE_MAX: u32 = SpecialInode::JournalLog as u32;

/// Subdomain identifiers used for key derivation in the context of some inode.
#[repr(u32)]
pub enum InodeKeySubdomain {
    InodeExtentsList = 1,
    InodeData = 2,
}

pub type InodeIndexKeyType = u32;
type EncodedInodeIndexKeyType = [u8; mem::size_of::<InodeIndexKeyType>()];

fn encode_key(key: InodeIndexKeyType) -> EncodedInodeIndexKeyType {
    key.to_le_bytes()
}

fn decode_key(encoded_key: EncodedInodeIndexKeyType) -> InodeIndexKeyType {
    InodeIndexKeyType::from_le_bytes(encoded_key)
}

fn read_encoded_keys_entry(index: usize, encoded_keys: &[u8]) -> Result<EncodedInodeIndexKeyType, NvFsError> {
    let entry_begin = index * mem::size_of::<EncodedInodeIndexKeyType>();
    let entry_end = entry_begin + mem::size_of::<EncodedInodeIndexKeyType>();

    if entry_end > encoded_keys.len() {
        return Err(nvfs_err_internal!());
    }

    Ok(
        *<&EncodedInodeIndexKeyType>::try_from(&encoded_keys[entry_begin..entry_end])
            .map_err(|_| nvfs_err_internal!())?,
    )
}

fn lookup_key(
    key: InodeIndexKeyType,
    encoded_keys: &[u8],
    encoded_keys_entries: usize,
) -> Result<Result<usize, usize>, NvFsError> {
    if encoded_keys.len() < encoded_keys_entries * mem::size_of::<EncodedInodeIndexKeyType>() {
        return Err(nvfs_err_internal!());
    }

    if encoded_keys_entries == 0 {
        return Ok(Err(0));
    }

    let mut l = 0;
    let mut u = encoded_keys_entries - 1;
    while l <= u {
        let m = (l + u) / 2;
        let entry = decode_key(read_encoded_keys_entry(m, encoded_keys)?);
        match key.cmp(&entry) {
            cmp::Ordering::Equal => {
                return Ok(Ok(m));
            }
            cmp::Ordering::Less => {
                if m == 0 {
                    return Ok(Err(m));
                }
                u = m - 1;
            }
            cmp::Ordering::Greater => {
                l = m + 1;
            }
        }
    }

    Ok(Err(l))
}

/// Layout information about the inode index B+-tree.
#[derive(Clone)]
pub struct InodeIndexTreeLayout {
    node_encrypted_block_layout: encryption_entities::EncryptedBlockLayout,

    max_internal_node_entries: usize,
    min_internal_node_entries: usize,
    max_leaf_node_entries: usize,
    min_leaf_node_entries: usize,
    encoded_node_len: usize,
}

impl InodeIndexTreeLayout {
    fn new(node_encrypted_block_layout: encryption_entities::EncryptedBlockLayout) -> Result<Self, NvFsError> {
        // The root node gets referenced from the InodeIndex' SpecialInode::IndexRoot
        // inode entry, with an EncodedExtentPtr which must be direct.
        if 1u64 << node_encrypted_block_layout.get_block_allocation_blocks_log2()
            > extent_ptr::EncodedExtentPtr::MAX_EXTENT_ALLOCATION_BLOCKS
        {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidIndexConfig));
        }

        let block_len = node_encrypted_block_layout.effective_payload_len()?;

        // The format is (in logical order)
        // - four bytes to encode the node level in the B+-tree, counted 1-based from
        //   leaf nodes upwards,
        // - a sequence of EncodedBlockPtrs to the children, (logically) interspersed
        //   with separating keys, i.e. 32 bit inode numbers.
        let max_internal_node_entries = (block_len - 4 - EncodedBlockPtr::ENCODED_SIZE as usize)
            / (mem::size_of::<EncodedInodeIndexKeyType>() + EncodedBlockPtr::ENCODED_SIZE as usize);

        // This is needed for preemptive node splitting of full nodes to be feasible: 1
        // entry would remain at the two child nodes each, 1, gets moved into
        // the parent.
        if max_internal_node_entries < 3 {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidIndexConfig));
        }

        let min_internal_node_entries = max_internal_node_entries / 2;
        // For enabling preemptive splitting of full nodes down the path from the root
        // in the course of insertions, it is generally assumed that
        // max_internal_node_entries is odd: even after the median key had been
        // moved to the parent, the remaining entries would still form two valid
        // B+-tree nodes, as far as the lower entry count threshold is concerned, which
        // is defined to equal half the max_internal_node_entries value rounded
        // down. A similar reasoning applies to preemptive merging of minimally
        // filled nodes down the root path for deletions: two such blocks plus
        // the separator key from the parent moved down still fit
        // into the maximum entry count.  However, rather than unconditionally wasting
        // space by actually forcing max_internal_node_entries to odd (by
        // decreasing it by one if even), only decrease the lower threshold as
        // if it had been.
        let min_internal_node_entries = min_internal_node_entries - (1 - (max_internal_node_entries & 1));
        debug_assert!(min_internal_node_entries >= 1);
        // Preemptive splitting is possible.
        debug_assert!(2 * min_internal_node_entries < max_internal_node_entries);
        // As is preemptive merging.
        debug_assert!((max_internal_node_entries - 1) / 2 >= min_internal_node_entries);

        let encoded_internal_node_len = 4
            + EncodedBlockPtr::ENCODED_SIZE as usize
            + max_internal_node_entries
                * (mem::size_of::<EncodedInodeIndexKeyType>() + EncodedBlockPtr::ENCODED_SIZE as usize);

        // The format is (in logical order)
        // - four bytes to encode the node level in the B+-tree, counted 1-based from
        //   leaf nodes upwards,
        // - a sequence of EncodedExtentPtrs to the inodes' extents each, (logically)
        //   logically associated with, a key each, i.e. a 32 bit inode number,
        // - a single block pointer to the next leaf node in symmetric order.
        let max_leaf_node_entries = (block_len - 4 - EncodedBlockPtr::ENCODED_SIZE as usize)
            / (mem::size_of::<EncodedInodeIndexKeyType>() + EncodedExtentPtr::ENCODED_SIZE as usize);
        let min_leaf_node_entries = max_leaf_node_entries.div_ceil(2);
        // Cannot happen, but make it explicit.
        if min_leaf_node_entries < 4 {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidIndexConfig));
        }

        let encoded_leaf_node_len = 4
            + EncodedBlockPtr::ENCODED_SIZE as usize
            + max_leaf_node_entries
                * (mem::size_of::<EncodedInodeIndexKeyType>() + EncodedExtentPtr::ENCODED_SIZE as usize);

        // By coincidence, the formats of the internal and leaf nodes come to the same
        // total size, so the max() is effectively a no-op as far as the result is
        // concerned.
        let encoded_node_len = encoded_internal_node_len.max(encoded_leaf_node_len);

        Ok(Self {
            node_encrypted_block_layout,
            max_internal_node_entries,
            min_internal_node_entries,
            max_leaf_node_entries,
            min_leaf_node_entries,
            encoded_node_len,
        })
    }

    fn encoded_node_len(&self) -> usize {
        self.encoded_node_len
    }
}

/// Inode index B+-tree leaf node.
pub struct InodeIndexTreeLeafNode {
    /// Encoded node in plaintext.
    encoded_node: Vec<u8>,
    /// Number of entries used in the node.
    entries: usize,
    /// Location of the node on storage.
    node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
}

impl InodeIndexTreeLeafNode {
    fn new_empty(
        node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        layout: &InodeIndexTreeLayout,
    ) -> Result<Self, NvFsError> {
        // By initializing the Vec with zeroes, the ->encoded_keys[] are is implicitly
        // initialized to SpecialInode::NoInode, as it should be.
        let encoded_node = try_alloc_vec(layout.encoded_node_len)?;
        let mut n = Self {
            encoded_node,
            entries: 0,
            node_allocation_blocks_begin,
        };

        // Encoded node levels are 1-based.
        *n.encoded_node_level_mut(layout)? = 1u32.to_le_bytes();
        *n.encoded_next_leaf_node_ptr_mut(layout)? = *EncodedBlockPtr::encode_nil();

        // Initialize all child pointers.
        for vacant_extent_ptr in n
            .encoded_entries_extent_ptrs_mut(layout)
            .chunks_exact_mut(EncodedExtentPtr::ENCODED_SIZE as usize)
        {
            *<&mut [u8; EncodedBlockPtr::ENCODED_SIZE as usize]>::try_from(vacant_extent_ptr)
                .map_err(|_| nvfs_err_internal!())? = *EncodedExtentPtr::encode_nil();
        }

        Ok(n)
    }

    fn decode(
        node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        encoded_node: Vec<u8>,
        layout: &InodeIndexTreeLayout,
    ) -> Result<Self, NvFsError> {
        if encoded_node.len() != layout.encoded_node_len {
            return Err(nvfs_err_internal!());
        }

        let mut n = Self {
            encoded_node,
            entries: 0,
            node_allocation_blocks_begin,
        };

        // Encoded node levels are 1-based.
        if *n.encoded_node_level(layout)? != 1u32.to_le_bytes() {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidIndexNode));
        }

        let mut last_key: Option<InodeIndexKeyType> = None;
        let mut entries = 0;
        let keys = n.encoded_keys(layout);
        for encoded_key in keys.chunks_exact(mem::size_of::<EncodedInodeIndexKeyType>()) {
            let key =
                decode_key(*<&EncodedInodeIndexKeyType>::try_from(encoded_key).map_err(|_| nvfs_err_internal!())?);
            if key == 0 {
                break;
            }

            if last_key.as_ref().map(|last_key| *last_key >= key).unwrap_or(false) {
                return Err(NvFsError::from(CocoonFsFormatError::InvalidIndexNode));
            }
            entries += 1;
            last_key = Some(key);
        }
        if keys[entries * mem::size_of::<EncodedInodeIndexKeyType>()..]
            .iter()
            .any(|b| *b != 0)
        {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidIndexNode));
        }
        n.entries = entries;

        let allocated_extent_ptrs_end = n.entries * EncodedExtentPtr::ENCODED_SIZE as usize;
        let extent_ptrs = n.encoded_entries_extent_ptrs(layout);
        for encoded_extent_ptr in
            extent_ptrs[..allocated_extent_ptrs_end].chunks_exact(EncodedExtentPtr::ENCODED_SIZE as usize)
        {
            if EncodedExtentPtr::from(
                *<&[u8; EncodedExtentPtr::ENCODED_SIZE as usize]>::try_from(encoded_extent_ptr)
                    .map_err(|_| nvfs_err_internal!())?,
            )
            .decode(layout.node_encrypted_block_layout.get_allocation_block_size_128b_log2() as u32)?
            .is_none()
            {
                return Err(NvFsError::from(CocoonFsFormatError::InvalidIndexNode));
            }
        }
        for encoded_extent_ptr in
            extent_ptrs[allocated_extent_ptrs_end..].chunks_exact(EncodedExtentPtr::ENCODED_SIZE as usize)
        {
            if EncodedExtentPtr::from(
                *<&[u8; EncodedExtentPtr::ENCODED_SIZE as usize]>::try_from(encoded_extent_ptr)
                    .map_err(|_| nvfs_err_internal!())?,
            )
            .decode(layout.node_encrypted_block_layout.get_allocation_block_size_128b_log2() as u32)?
            .is_some()
            {
                return Err(NvFsError::from(CocoonFsFormatError::InvalidIndexNode));
            }
        }

        Ok(n)
    }

    pub fn lookup(
        &self,
        key: InodeIndexKeyType,
        layout: &InodeIndexTreeLayout,
    ) -> Result<Result<usize, usize>, NvFsError> {
        lookup_key(key, self.encoded_keys(layout), self.entries)
    }

    fn entry_inode(&self, entry_index: usize, layout: &InodeIndexTreeLayout) -> Result<InodeIndexKeyType, NvFsError> {
        Ok(decode_key(read_encoded_keys_entry(
            entry_index,
            self.encoded_keys(layout),
        )?))
    }

    pub fn entry_extent_ptr(
        &self,
        entry_index: usize,
        layout: &InodeIndexTreeLayout,
    ) -> Result<EncodedExtentPtr, NvFsError> {
        Ok(EncodedExtentPtr::from(
            *self.encoded_entry_extent_ptr(entry_index, layout)?,
        ))
    }

    fn insert(
        &mut self,
        key: InodeIndexKeyType,
        extent_ptr: EncodedExtentPtr,
        insertion_pos: Option<Result<usize, usize>>,
        layout: &InodeIndexTreeLayout,
    ) -> Result<(), NvFsError> {
        let insertion_pos = match insertion_pos {
            Some(insertion_pos) => insertion_pos,
            None => self.lookup(key, layout)?,
        };
        let insertion_pos = match insertion_pos {
            Ok(existing_pos) => {
                *self.encoded_entry_extent_ptr_mut(existing_pos, layout)? = *extent_ptr;
                return Ok(());
            }
            Err(insertion_pos) => insertion_pos,
        };

        if self.entries == layout.max_leaf_node_entries {
            return Err(nvfs_err_internal!());
        }

        let keys_insertion_pos = insertion_pos * mem::size_of::<EncodedInodeIndexKeyType>();
        let moved_keys_begin = keys_insertion_pos;
        let moved_keys_end = self.entries * mem::size_of::<EncodedInodeIndexKeyType>();
        let keys = self.encoded_keys_mut(layout);
        keys.copy_within(
            moved_keys_begin..moved_keys_end,
            moved_keys_begin + mem::size_of::<EncodedInodeIndexKeyType>(),
        );
        *<&mut EncodedInodeIndexKeyType>::try_from(
            &mut keys[keys_insertion_pos..keys_insertion_pos + mem::size_of::<EncodedInodeIndexKeyType>()],
        )
        .map_err(|_| nvfs_err_internal!())? = encode_key(key);

        let extent_ptrs_insertion_pos = insertion_pos * EncodedExtentPtr::ENCODED_SIZE as usize;
        let moved_extent_ptrs_begin = extent_ptrs_insertion_pos;
        let moved_extent_ptrs_end = self.entries * EncodedExtentPtr::ENCODED_SIZE as usize;
        let extent_ptrs = self.encoded_entries_extent_ptrs_mut(layout);
        extent_ptrs.copy_within(
            moved_extent_ptrs_begin..moved_extent_ptrs_end,
            moved_extent_ptrs_begin + EncodedExtentPtr::ENCODED_SIZE as usize,
        );
        *<&mut [u8; EncodedExtentPtr::ENCODED_SIZE as usize]>::try_from(
            &mut extent_ptrs
                [extent_ptrs_insertion_pos..extent_ptrs_insertion_pos + EncodedExtentPtr::ENCODED_SIZE as usize],
        )
        .map_err(|_| nvfs_err_internal!())? = *extent_ptr;

        self.entries += 1;

        Ok(())
    }

    fn remove(&mut self, removal_pos: usize, layout: &InodeIndexTreeLayout) -> Result<(), NvFsError> {
        if self.entries == 0 {
            return Err(nvfs_err_internal!());
        }

        let keys_removal_pos = removal_pos * mem::size_of::<EncodedInodeIndexKeyType>();
        let moved_keys_begin = keys_removal_pos + mem::size_of::<EncodedInodeIndexKeyType>();
        let moved_keys_end = self.entries * mem::size_of::<EncodedInodeIndexKeyType>();
        let keys = self.encoded_keys_mut(layout);
        keys.copy_within(moved_keys_begin..moved_keys_end, keys_removal_pos);
        // Fill the newly vacant key slot at the tail with a value of
        // SpecialInode::NoInode.
        keys[moved_keys_end - mem::size_of::<EncodedInodeIndexKeyType>()..moved_keys_end].fill(0u8);

        let extent_ptrs_removal_pos = removal_pos * EncodedExtentPtr::ENCODED_SIZE as usize;
        let moved_extent_ptrs_begin = extent_ptrs_removal_pos + EncodedExtentPtr::ENCODED_SIZE as usize;
        let moved_extent_ptrs_end = self.entries * EncodedExtentPtr::ENCODED_SIZE as usize;
        let extent_ptrs = self.encoded_entries_extent_ptrs_mut(layout);
        extent_ptrs.copy_within(moved_extent_ptrs_begin..moved_extent_ptrs_end, extent_ptrs_removal_pos);
        // Clear the newly vacant extent pointer entry at the tail.
        *<&mut [u8; EncodedExtentPtr::ENCODED_SIZE as usize]>::try_from(
            &mut extent_ptrs[moved_extent_ptrs_end - EncodedExtentPtr::ENCODED_SIZE as usize..moved_extent_ptrs_end],
        )
        .map_err(|_| nvfs_err_internal!())? = *EncodedExtentPtr::encode_nil();

        self.entries -= 1;

        Ok(())
    }

    fn spill_left(
        &mut self,
        right: &mut Self,
        count: usize,
        layout: &InodeIndexTreeLayout,
    ) -> Result<EncodedInodeIndexKeyType, NvFsError> {
        let left = self;
        if left.entries + count > layout.max_leaf_node_entries
            || right.entries < count
            || right.entries - count < layout.min_leaf_node_entries
        {
            return Err(nvfs_err_internal!());
        }

        let original_src_entries = right.entries;
        let keys_spill_len = count * mem::size_of::<EncodedInodeIndexKeyType>();
        let dst_keys_spill_begin = left.entries * mem::size_of::<EncodedInodeIndexKeyType>();
        let dst_keys_spill_end = dst_keys_spill_begin + keys_spill_len;
        let src_keys_spill_end = keys_spill_len;
        let src_keys = right.encoded_keys_mut(layout);
        // Spill count keys from right to left.
        left.encoded_keys_mut(layout)[dst_keys_spill_begin..dst_keys_spill_end]
            .copy_from_slice(&src_keys[..src_keys_spill_end]);
        // Memmove the right node's remaining keys to the front and clear out the tail
        // accordingly.
        let src_original_keys_end = original_src_entries * mem::size_of::<EncodedInodeIndexKeyType>();
        src_keys.copy_within(src_keys_spill_end..src_original_keys_end, 0);
        src_keys[src_original_keys_end - keys_spill_len..src_original_keys_end].fill(0);
        // The new parent separator key is the one now found at the right node's head.
        let new_parent_separator_key =
            *<&EncodedInodeIndexKeyType>::try_from(&src_keys[..mem::size_of::<EncodedInodeIndexKeyType>()])
                .map_err(|_| nvfs_err_internal!())?;

        let extent_ptrs_spill_len = count * EncodedExtentPtr::ENCODED_SIZE as usize;
        let dst_extent_ptrs_spill_begin = left.entries * EncodedExtentPtr::ENCODED_SIZE as usize;
        let dst_extent_ptrs_spill_end = dst_extent_ptrs_spill_begin + extent_ptrs_spill_len;
        let src_extent_ptrs_spill_end = extent_ptrs_spill_len;
        let src_extent_ptrs = right.encoded_entries_extent_ptrs_mut(layout);
        // Spill count extent pointers from right to left.
        left.encoded_entries_extent_ptrs_mut(layout)[dst_extent_ptrs_spill_begin..dst_extent_ptrs_spill_end]
            .copy_from_slice(&src_extent_ptrs[..src_extent_ptrs_spill_end]);
        // Memmove the right node's remaining extent pointers to the front and clear out
        // the tail accordingly.
        let src_original_extent_ptrs_end = original_src_entries * EncodedExtentPtr::ENCODED_SIZE as usize;
        src_extent_ptrs.copy_within(src_extent_ptrs_spill_end..src_original_extent_ptrs_end, 0);
        for vacant_src_extent_ptr in src_extent_ptrs
            [src_original_extent_ptrs_end - extent_ptrs_spill_len..src_original_extent_ptrs_end]
            .chunks_exact_mut(EncodedExtentPtr::ENCODED_SIZE as usize)
        {
            *<&mut [u8; EncodedExtentPtr::ENCODED_SIZE as usize]>::try_from(vacant_src_extent_ptr)
                .map_err(|_| nvfs_err_internal!())? = *EncodedExtentPtr::encode_nil();
        }

        left.entries += count;
        right.entries -= count;
        Ok(new_parent_separator_key)
    }

    fn spill_right(
        &mut self,
        right: &mut Self,
        count: usize,
        layout: &InodeIndexTreeLayout,
    ) -> Result<EncodedInodeIndexKeyType, NvFsError> {
        let left = self;
        if right.entries + count > layout.max_leaf_node_entries
            || left.entries < count
            || left.entries - count < layout.min_leaf_node_entries
        {
            return Err(nvfs_err_internal!());
        }

        let original_src_entries = left.entries;
        let original_dst_entries = right.entries;

        let keys_spill_len = count * mem::size_of::<EncodedInodeIndexKeyType>();
        let src_keys_spill_end = original_src_entries * mem::size_of::<EncodedInodeIndexKeyType>();
        let src_keys_spill_begin = src_keys_spill_end - keys_spill_len;
        let dst_keys_spill_end = keys_spill_len;
        let dst_keys = right.encoded_keys_mut(layout);
        let src_keys = left.encoded_keys_mut(layout);
        // Make room for count new keys at the right node's head by memmoving the
        // existing ones towards the tail.
        let dst_original_keys_end = original_dst_entries * mem::size_of::<EncodedInodeIndexKeyType>();
        dst_keys.copy_within(..dst_original_keys_end, dst_keys_spill_end);
        // Spill count keys from left to right.
        dst_keys[..dst_keys_spill_end].copy_from_slice(&src_keys[src_keys_spill_begin..src_keys_spill_end]);
        // Encode SpecialInode::NoInode in little endian at the src' newly vacant tail
        // key entries.
        src_keys[src_keys_spill_begin..src_keys_spill_end].fill(0u8);
        // The new parent separator key is the one now found at the right node's head.
        let new_parent_separator_key =
            *<&EncodedInodeIndexKeyType>::try_from(&dst_keys[..mem::size_of::<EncodedInodeIndexKeyType>()])
                .map_err(|_| nvfs_err_internal!())?;

        let extent_ptrs_spill_len = count * EncodedExtentPtr::ENCODED_SIZE as usize;
        let src_extent_ptrs_spill_end = original_src_entries * EncodedExtentPtr::ENCODED_SIZE as usize;
        let src_extent_ptrs_spill_begin = src_extent_ptrs_spill_end - extent_ptrs_spill_len;
        let dst_extent_ptrs_spill_end = extent_ptrs_spill_len;
        let dst_extent_ptrs = right.encoded_entries_extent_ptrs_mut(layout);
        let src_extent_ptrs = left.encoded_entries_extent_ptrs_mut(layout);
        // Make room for count new extent pointers at the right node's head by memmoving
        // the existing ones towards the tail.
        let dst_original_extent_ptrs_end = original_dst_entries * EncodedExtentPtr::ENCODED_SIZE as usize;
        dst_extent_ptrs.copy_within(..dst_original_extent_ptrs_end, dst_extent_ptrs_spill_end);
        // Spill count extent pointers from left to right.
        dst_extent_ptrs[..dst_extent_ptrs_spill_end]
            .copy_from_slice(&src_extent_ptrs[src_extent_ptrs_spill_begin..src_extent_ptrs_spill_end]);
        // And clear out all extent pointers which became vacant at the src' tail.
        for vacant_src_extent_ptr in src_extent_ptrs[src_extent_ptrs_spill_begin..src_extent_ptrs_spill_end]
            .chunks_exact_mut(EncodedExtentPtr::ENCODED_SIZE as usize)
        {
            *<&mut [u8; EncodedExtentPtr::ENCODED_SIZE as usize]>::try_from(vacant_src_extent_ptr)
                .map_err(|_| nvfs_err_internal!())? = *EncodedExtentPtr::encode_nil();
        }

        left.entries -= count;
        right.entries += count;
        Ok(new_parent_separator_key)
    }

    fn split_insert(
        &mut self,
        key: InodeIndexKeyType,
        extent_ptr: EncodedExtentPtr,
        insertion_pos: usize,
        new_node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        layout: &InodeIndexTreeLayout,
    ) -> Result<(Self, EncodedInodeIndexKeyType), NvFsError> {
        let insert_in_left = insertion_pos <= self.entries / 2;
        // If the number of exisiting entries is odd, and the new entry is to get
        // inserted into the left node after the splitting, spill one more entry
        // into the right node and vice-versa.
        let spill_count = (self.entries + insert_in_left as usize) / 2;
        if spill_count + (1 - insert_in_left as usize) < layout.min_leaf_node_entries
            || self.entries - spill_count + (insert_in_left as usize) < layout.min_leaf_node_entries
        {
            return Err(nvfs_err_internal!());
        }

        let new_encoded_node = try_alloc_vec(layout.encoded_node_len)?;
        let mut new_node = Self {
            encoded_node: new_encoded_node,
            entries: spill_count + (1 - insert_in_left as usize),
            node_allocation_blocks_begin: new_node_allocation_blocks_begin,
        };
        *new_node.encoded_node_level_mut(layout)? = 1u32.to_le_bytes();

        let original_src_entries = self.entries;
        let keys_spill_len = spill_count * mem::size_of::<EncodedInodeIndexKeyType>();
        let src_keys_spill_end = original_src_entries * mem::size_of::<EncodedInodeIndexKeyType>();
        let src_keys_spill_begin = src_keys_spill_end - keys_spill_len;
        let extent_ptrs_spill_len = spill_count * EncodedExtentPtr::ENCODED_SIZE as usize;
        let src_extent_ptrs_spill_end = original_src_entries * EncodedExtentPtr::ENCODED_SIZE as usize;
        let src_extent_ptrs_spill_begin = src_extent_ptrs_spill_end - extent_ptrs_spill_len;
        let src_keys = self.encoded_keys(layout);
        let src_extent_ptrs = self.encoded_entries_extent_ptrs(layout);
        if insert_in_left {
            let dst_keys_spill_end = keys_spill_len;
            let dst_keys = new_node.encoded_keys_mut(layout);
            dst_keys[..dst_keys_spill_end].copy_from_slice(&src_keys[src_keys_spill_begin..src_keys_spill_end]);

            let dst_extent_ptrs_spill_end = extent_ptrs_spill_len;
            let dst_extent_ptrs = new_node.encoded_entries_extent_ptrs_mut(layout);
            dst_extent_ptrs[..dst_extent_ptrs_spill_end]
                .copy_from_slice(&src_extent_ptrs[src_extent_ptrs_spill_begin..src_extent_ptrs_spill_end]);
            self.entries -= spill_count;
            self.insert(key, extent_ptr, Some(Err(insertion_pos)), layout)?;
        } else {
            // Determine the insertion position relative to the right node.
            let insertion_pos = insertion_pos - (original_src_entries - spill_count);

            let keys_batch1_len = insertion_pos * mem::size_of::<EncodedInodeIndexKeyType>();
            let keys_batch2_len = keys_spill_len - keys_batch1_len;
            let src_keys_spill_batch1_begin = src_keys_spill_begin;
            let src_keys_spill_batch1_end = src_keys_spill_batch1_begin + keys_batch1_len;
            let src_keys_spill_batch2_begin = src_keys_spill_batch1_end;
            let src_keys_spill_batch2_end = src_keys_spill_end;
            let dst_keys_spill_batch1_end = keys_batch1_len;
            // Skip over one slot for the insertion.
            let dst_keys_spill_batch2_begin = dst_keys_spill_batch1_end + mem::size_of::<EncodedInodeIndexKeyType>();
            let dst_keys_spill_batch2_end = dst_keys_spill_batch2_begin + keys_batch2_len;
            let dst_keys = new_node.encoded_keys_mut(layout);
            // Spill first batch.
            dst_keys[..dst_keys_spill_batch1_end]
                .copy_from_slice(&src_keys[src_keys_spill_batch1_begin..src_keys_spill_batch1_end]);
            // Insert the new key at the target position inbetween the two spill batches.
            *<&mut EncodedInodeIndexKeyType>::try_from(
                &mut dst_keys[dst_keys_spill_batch1_end..dst_keys_spill_batch2_begin],
            )
            .map_err(|_| nvfs_err_internal!())? = encode_key(key);
            // Spill second batch.
            dst_keys[dst_keys_spill_batch2_begin..dst_keys_spill_batch2_end]
                .copy_from_slice(&src_keys[src_keys_spill_batch2_begin..src_keys_spill_batch2_end]);

            let extent_ptrs_batch1_len = insertion_pos * EncodedExtentPtr::ENCODED_SIZE as usize;
            let extent_ptrs_batch2_len = extent_ptrs_spill_len - extent_ptrs_batch1_len;
            let src_extent_ptrs_spill_batch1_begin = src_extent_ptrs_spill_begin;
            let src_extent_ptrs_spill_batch1_end = src_extent_ptrs_spill_batch1_begin + extent_ptrs_batch1_len;
            let src_extent_ptrs_spill_batch2_begin = src_extent_ptrs_spill_batch1_end;
            let src_extent_ptrs_spill_batch2_end = src_extent_ptrs_spill_end;
            let dst_extent_ptrs_spill_batch1_end = extent_ptrs_batch1_len;
            // Skip over one slot for the insertion.
            let dst_extent_ptrs_spill_batch2_begin =
                dst_extent_ptrs_spill_batch1_end + EncodedExtentPtr::ENCODED_SIZE as usize;
            let dst_extent_ptrs_spill_batch2_end = dst_extent_ptrs_spill_batch2_begin + extent_ptrs_batch2_len;
            let dst_extent_ptrs = new_node.encoded_entries_extent_ptrs_mut(layout);
            // Spill first batch.
            dst_extent_ptrs[..dst_extent_ptrs_spill_batch1_end].copy_from_slice(
                &src_extent_ptrs[src_extent_ptrs_spill_batch1_begin..src_extent_ptrs_spill_batch1_end],
            );
            // Insert the new extent pointer at the target position inbetween the two spill
            // batches.
            *<&mut [u8; EncodedExtentPtr::ENCODED_SIZE as usize]>::try_from(
                &mut dst_extent_ptrs[dst_extent_ptrs_spill_batch1_end..dst_extent_ptrs_spill_batch2_begin],
            )
            .map_err(|_| nvfs_err_internal!())? = *extent_ptr;
            // Spill second batch.
            dst_extent_ptrs[dst_extent_ptrs_spill_batch2_begin..dst_extent_ptrs_spill_batch2_end].copy_from_slice(
                &src_extent_ptrs[src_extent_ptrs_spill_batch2_begin..src_extent_ptrs_spill_batch2_end],
            );

            self.entries -= spill_count;
        }

        // The remainder of dst_keys is initialized to all-zeroes, i.e. to
        // SpecialInode::NoInode, by the Vec allocation above already. Take care
        // of the keys removed from self.
        let src_keys_clear_begin = self.entries * mem::size_of::<EncodedInodeIndexKeyType>();
        let src_keys_clear_end = original_src_entries * mem::size_of::<EncodedInodeIndexKeyType>();
        let src_keys = self.encoded_keys_mut(layout);
        src_keys[src_keys_clear_begin..src_keys_clear_end].fill(0u8);
        let src_extent_ptrs_clear_begin = self.entries * EncodedExtentPtr::ENCODED_SIZE as usize;
        let src_extent_ptrs_clear_end = original_src_entries * EncodedExtentPtr::ENCODED_SIZE as usize;
        let src_extent_ptrs = self.encoded_entries_extent_ptrs_mut(layout);
        for vacant_src_extent_ptr in src_extent_ptrs[src_extent_ptrs_clear_begin..src_extent_ptrs_clear_end]
            .chunks_exact_mut(EncodedExtentPtr::ENCODED_SIZE as usize)
        {
            *<&mut [u8; EncodedExtentPtr::ENCODED_SIZE as usize]>::try_from(vacant_src_extent_ptr)
                .map_err(|_| nvfs_err_internal!())? = *EncodedExtentPtr::encode_nil();
        }
        let dst_extent_ptrs_clear_begin = new_node.entries * EncodedExtentPtr::ENCODED_SIZE as usize;
        let dst_extent_ptrs = new_node.encoded_entries_extent_ptrs_mut(layout);
        for vacant_dst_extent_ptr in
            dst_extent_ptrs[dst_extent_ptrs_clear_begin..].chunks_exact_mut(EncodedExtentPtr::ENCODED_SIZE as usize)
        {
            *<&mut [u8; EncodedExtentPtr::ENCODED_SIZE as usize]>::try_from(vacant_dst_extent_ptr)
                .map_err(|_| nvfs_err_internal!())? = *EncodedExtentPtr::encode_nil();
        }

        // The new parent separator key is the one now found at the right node's head.
        let dst_keys = new_node.encoded_keys(layout);
        let parent_separator_key =
            *<&EncodedInodeIndexKeyType>::try_from(&dst_keys[..mem::size_of::<EncodedInodeIndexKeyType>()])
                .map_err(|_| nvfs_err_internal!())?;

        let left_next_leaf_node_ptr = self.encoded_next_leaf_node_ptr_mut(layout)?;
        *new_node.encoded_next_leaf_node_ptr_mut(layout)? = *left_next_leaf_node_ptr;
        *left_next_leaf_node_ptr = *EncodedBlockPtr::encode(Some(new_node_allocation_blocks_begin))?;

        Ok((new_node, parent_separator_key))
    }

    fn merge_remove(
        &mut self,
        right: &Self,
        removal_pos_after_merge: usize,
        layout: &InodeIndexTreeLayout,
    ) -> Result<(), NvFsError> {
        let left = self;
        if left.entries + right.entries - 1 > layout.max_leaf_node_entries {
            return Err(nvfs_err_internal!());
        }

        let remove_from_left = removal_pos_after_merge < left.entries;
        if remove_from_left {
            left.remove(removal_pos_after_merge, layout)?;

            let keys_spill_len = right.entries * mem::size_of::<EncodedInodeIndexKeyType>();
            let dst_keys_spill_begin = left.entries * mem::size_of::<EncodedInodeIndexKeyType>();
            let dst_keys_spill_end = dst_keys_spill_begin + keys_spill_len;
            let src_keys_spill_end = keys_spill_len;
            let src_keys = right.encoded_keys(layout);
            // Spill all keys from right to left.
            left.encoded_keys_mut(layout)[dst_keys_spill_begin..dst_keys_spill_end]
                .copy_from_slice(&src_keys[..src_keys_spill_end]);

            let extent_ptrs_spill_len = right.entries * EncodedExtentPtr::ENCODED_SIZE as usize;
            let dst_extent_ptrs_spill_begin = left.entries * EncodedExtentPtr::ENCODED_SIZE as usize;
            let dst_extent_ptrs_spill_end = dst_extent_ptrs_spill_begin + extent_ptrs_spill_len;
            let src_extent_ptrs_spill_end = extent_ptrs_spill_len;
            let src_extent_ptrs = right.encoded_entries_extent_ptrs(layout);
            // Spill all extent pointers from right to left.
            left.encoded_entries_extent_ptrs_mut(layout)[dst_extent_ptrs_spill_begin..dst_extent_ptrs_spill_end]
                .copy_from_slice(&src_extent_ptrs[..src_extent_ptrs_spill_end]);

            left.entries += right.entries;
        } else {
            // Determine the removal position relative to the right node.
            let removal_pos = removal_pos_after_merge - left.entries;

            let keys_spill_batch1_len = removal_pos * mem::size_of::<EncodedInodeIndexKeyType>();
            let keys_spill_batch2_len = (right.entries - removal_pos - 1) * mem::size_of::<EncodedInodeIndexKeyType>();
            let dst_keys_spill_batch1_begin = left.entries * mem::size_of::<EncodedInodeIndexKeyType>();
            let dst_keys_spill_batch1_end = dst_keys_spill_batch1_begin + keys_spill_batch1_len;
            let dst_keys_spill_batch2_begin = dst_keys_spill_batch1_end;
            let dst_keys_spill_batch2_end = dst_keys_spill_batch2_begin + keys_spill_batch2_len;
            let src_keys_spill_batch1_end = keys_spill_batch1_len;
            // Skip over one slot for the removal.
            let src_keys_spill_batch2_begin = src_keys_spill_batch1_end + mem::size_of::<EncodedInodeIndexKeyType>();
            let src_keys_spill_batch2_end = src_keys_spill_batch2_begin + keys_spill_batch2_len;
            let dst_keys = left.encoded_keys_mut(layout);
            let src_keys = right.encoded_keys(layout);
            // Spill first batch.
            dst_keys[dst_keys_spill_batch1_begin..dst_keys_spill_batch1_end]
                .copy_from_slice(&src_keys[..src_keys_spill_batch1_end]);
            // Spill second batch.
            dst_keys[dst_keys_spill_batch2_begin..dst_keys_spill_batch2_end]
                .copy_from_slice(&src_keys[src_keys_spill_batch2_begin..src_keys_spill_batch2_end]);

            let extent_ptrs_spill_batch1_len = removal_pos * EncodedExtentPtr::ENCODED_SIZE as usize;
            let extent_ptrs_spill_batch2_len =
                (right.entries - removal_pos - 1) * EncodedExtentPtr::ENCODED_SIZE as usize;
            let dst_extent_ptrs_spill_batch1_begin = left.entries * EncodedExtentPtr::ENCODED_SIZE as usize;
            let dst_extent_ptrs_spill_batch1_end = dst_extent_ptrs_spill_batch1_begin + extent_ptrs_spill_batch1_len;
            let dst_extent_ptrs_spill_batch2_begin = dst_extent_ptrs_spill_batch1_end;
            let dst_extent_ptrs_spill_batch2_end = dst_extent_ptrs_spill_batch2_begin + extent_ptrs_spill_batch2_len;
            let src_extent_ptrs_spill_batch1_end = extent_ptrs_spill_batch1_len;
            // Skip over one slot for the removal.
            let src_extent_ptrs_spill_batch2_begin =
                src_extent_ptrs_spill_batch1_end + EncodedExtentPtr::ENCODED_SIZE as usize;
            let src_extent_ptrs_spill_batch2_end = src_extent_ptrs_spill_batch2_begin + extent_ptrs_spill_batch2_len;
            let dst_extent_ptrs = left.encoded_entries_extent_ptrs_mut(layout);
            let src_extent_ptrs = right.encoded_entries_extent_ptrs(layout);
            // Spill first batch.
            dst_extent_ptrs[dst_extent_ptrs_spill_batch1_begin..dst_extent_ptrs_spill_batch1_end]
                .copy_from_slice(&src_extent_ptrs[..src_extent_ptrs_spill_batch1_end]);
            // Spill second batch.
            dst_extent_ptrs[dst_extent_ptrs_spill_batch2_begin..dst_extent_ptrs_spill_batch2_end].copy_from_slice(
                &src_extent_ptrs[src_extent_ptrs_spill_batch2_begin..src_extent_ptrs_spill_batch2_end],
            );

            left.entries += right.entries - 1;
        }

        *left.encoded_next_leaf_node_ptr_mut(layout)? = *right.encoded_next_leaf_node_ptr(layout)?;

        Ok(())
    }

    fn encoded_next_leaf_node_ptr(
        &self,
        _layout: &InodeIndexTreeLayout,
    ) -> Result<&[u8; EncodedBlockPtr::ENCODED_SIZE as usize], NvFsError> {
        let encoded_next_leaf_node_ptr_begin = 0;
        let encoded_next_leaf_node_ptr_end = encoded_next_leaf_node_ptr_begin + EncodedBlockPtr::ENCODED_SIZE as usize;
        <&[u8; EncodedBlockPtr::ENCODED_SIZE as usize]>::try_from(
            &self.encoded_node[encoded_next_leaf_node_ptr_begin..encoded_next_leaf_node_ptr_end],
        )
        .map_err(|_| nvfs_err_internal!())
    }

    fn encoded_next_leaf_node_ptr_mut(
        &mut self,
        _layout: &InodeIndexTreeLayout,
    ) -> Result<&mut [u8; EncodedBlockPtr::ENCODED_SIZE as usize], NvFsError> {
        let encoded_next_leaf_node_ptr_begin = 0;
        let encoded_next_leaf_node_ptr_end = encoded_next_leaf_node_ptr_begin + EncodedBlockPtr::ENCODED_SIZE as usize;
        <&mut [u8; EncodedBlockPtr::ENCODED_SIZE as usize]>::try_from(
            &mut self.encoded_node[encoded_next_leaf_node_ptr_begin..encoded_next_leaf_node_ptr_end],
        )
        .map_err(|_| nvfs_err_internal!())
    }

    fn encoded_entries_extent_ptrs(&self, layout: &InodeIndexTreeLayout) -> &[u8] {
        let encoded_entries_extent_ptrs_begin = EncodedBlockPtr::ENCODED_SIZE as usize;
        let encoded_entries_extent_ptrs_end =
            encoded_entries_extent_ptrs_begin + layout.max_leaf_node_entries * EncodedExtentPtr::ENCODED_SIZE as usize;
        &self.encoded_node[encoded_entries_extent_ptrs_begin..encoded_entries_extent_ptrs_end]
    }

    fn encoded_entries_extent_ptrs_mut(&mut self, layout: &InodeIndexTreeLayout) -> &mut [u8] {
        let encoded_entries_extent_ptrs_begin = EncodedBlockPtr::ENCODED_SIZE as usize;
        let encoded_entries_extent_ptrs_end =
            encoded_entries_extent_ptrs_begin + layout.max_leaf_node_entries * EncodedExtentPtr::ENCODED_SIZE as usize;
        &mut self.encoded_node[encoded_entries_extent_ptrs_begin..encoded_entries_extent_ptrs_end]
    }

    fn encoded_keys(&self, layout: &InodeIndexTreeLayout) -> &[u8] {
        let encoded_keys_begin = EncodedBlockPtr::ENCODED_SIZE as usize
            + layout.max_leaf_node_entries * EncodedExtentPtr::ENCODED_SIZE as usize;
        let encoded_keys_end =
            encoded_keys_begin + layout.max_leaf_node_entries * mem::size_of::<EncodedInodeIndexKeyType>();
        &self.encoded_node[encoded_keys_begin..encoded_keys_end]
    }

    fn encoded_keys_mut(&mut self, layout: &InodeIndexTreeLayout) -> &mut [u8] {
        let encoded_keys_begin = EncodedBlockPtr::ENCODED_SIZE as usize
            + layout.max_leaf_node_entries * EncodedExtentPtr::ENCODED_SIZE as usize;
        let encoded_keys_end =
            encoded_keys_begin + layout.max_leaf_node_entries * mem::size_of::<EncodedInodeIndexKeyType>();
        &mut self.encoded_node[encoded_keys_begin..encoded_keys_end]
    }

    fn encoded_node_level(&self, layout: &InodeIndexTreeLayout) -> Result<&[u8; mem::size_of::<u32>()], NvFsError> {
        <&[u8; mem::size_of::<u32>()]>::try_from(&self.encoded_node[layout.encoded_node_len - mem::size_of::<u32>()..])
            .map_err(|_| nvfs_err_internal!())
    }

    fn encoded_node_level_mut(
        &mut self,
        layout: &InodeIndexTreeLayout,
    ) -> Result<&mut [u8; mem::size_of::<u32>()], NvFsError> {
        <&mut [u8; mem::size_of::<u32>()]>::try_from(
            &mut self.encoded_node[layout.encoded_node_len - mem::size_of::<u32>()..],
        )
        .map_err(|_| nvfs_err_internal!())
    }

    fn encoded_entry_extent_ptr(
        &self,
        index: usize,
        layout: &InodeIndexTreeLayout,
    ) -> Result<&[u8; EncodedExtentPtr::ENCODED_SIZE as usize], NvFsError> {
        let entry_begin = index * EncodedExtentPtr::ENCODED_SIZE as usize;
        let entry_end = entry_begin + EncodedExtentPtr::ENCODED_SIZE as usize;
        let encoded_extent_ptrs = self.encoded_entries_extent_ptrs(layout);
        if encoded_extent_ptrs.len() < entry_end {
            return Err(nvfs_err_internal!());
        }
        <&[u8; EncodedExtentPtr::ENCODED_SIZE as usize]>::try_from(&encoded_extent_ptrs[entry_begin..entry_end])
            .map_err(|_| nvfs_err_internal!())
    }

    fn encoded_entry_extent_ptr_mut(
        &mut self,
        index: usize,
        layout: &InodeIndexTreeLayout,
    ) -> Result<&mut [u8; EncodedExtentPtr::ENCODED_SIZE as usize], NvFsError> {
        let entry_begin = index * EncodedExtentPtr::ENCODED_SIZE as usize;
        let entry_end = entry_begin + EncodedExtentPtr::ENCODED_SIZE as usize;
        let encoded_extent_ptrs = self.encoded_entries_extent_ptrs_mut(layout);
        if encoded_extent_ptrs.len() < entry_end {
            return Err(nvfs_err_internal!());
        }
        <&mut [u8; EncodedExtentPtr::ENCODED_SIZE as usize]>::try_from(&mut encoded_extent_ptrs[entry_begin..entry_end])
            .map_err(|_| nvfs_err_internal!())
    }
}

/// Inode index B+-tree internal node.
struct InodeIndexTreeInternalNode {
    /// Encoded node in plaintext.
    encoded_node: Vec<u8>,
    /// Number of separator keys in the node.
    ///
    /// The number of children is always one more.
    entries: usize,
    /// Location of the node on storage.
    node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
}

impl InodeIndexTreeInternalNode {
    fn new_empty_root(
        node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        root_node_level: u32,
        layout: &InodeIndexTreeLayout,
    ) -> Result<Self, NvFsError> {
        if root_node_level == 0 {
            return Err(nvfs_err_internal!());
        }

        // By initializing the Vec with zeroes, the ->encoded_keys[] are is implicitly
        // initialized to SpecialInode::NoInode, as it should be.
        let encoded_node = try_alloc_vec(layout.encoded_node_len)?;
        let mut n = Self {
            encoded_node,
            entries: 0,
            node_allocation_blocks_begin,
        };
        // Encoded node levels are 1-based.
        *n.encoded_node_level_mut(layout)? = (root_node_level + 1).to_le_bytes();

        // Initialize all child pointers.
        for child_ptr in n
            .encoded_child_ptrs_mut(layout)
            .chunks_exact_mut(EncodedBlockPtr::ENCODED_SIZE as usize)
        {
            *<&mut [u8; EncodedBlockPtr::ENCODED_SIZE as usize]>::try_from(child_ptr)
                .map_err(|_| nvfs_err_internal!())? = *EncodedBlockPtr::encode_nil();
        }

        Ok(n)
    }

    fn init_empty_root(
        &mut self,
        left_child_ptr: EncodedBlockPtr,
        right_child_ptr: EncodedBlockPtr,
        separator_key: EncodedInodeIndexKeyType,
        layout: &InodeIndexTreeLayout,
    ) -> Result<(), NvFsError> {
        if !self.entries == 0 {
            return Err(nvfs_err_internal!());
        }

        self.entries = 1;

        self.update_separator_key(0, separator_key, layout)?;

        let child_ptrs = self.encoded_child_ptrs_mut(layout);
        *<&mut [u8; EncodedBlockPtr::ENCODED_SIZE as usize]>::try_from(
            &mut child_ptrs[..EncodedBlockPtr::ENCODED_SIZE as usize],
        )
        .map_err(|_| nvfs_err_internal!())? = *left_child_ptr;
        *<&mut [u8; EncodedBlockPtr::ENCODED_SIZE as usize]>::try_from(
            &mut child_ptrs[EncodedBlockPtr::ENCODED_SIZE as usize..2 * EncodedBlockPtr::ENCODED_SIZE as usize],
        )
        .map_err(|_| nvfs_err_internal!())? = *right_child_ptr;

        Ok(())
    }

    fn decode(
        node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        encoded_node: Vec<u8>,
        layout: &InodeIndexTreeLayout,
    ) -> Result<Self, NvFsError> {
        if encoded_node.len() != layout.encoded_node_len {
            return Err(nvfs_err_internal!());
        }

        let mut n = Self {
            encoded_node,
            entries: 0,
            node_allocation_blocks_begin,
        };

        // Encoded node levels are 1-based, counted from leaf nodes upwards.
        if u32::from_le_bytes(*n.encoded_node_level(layout)?) <= 1 {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidIndexNode));
        }

        let mut last_key: Option<InodeIndexKeyType> = None;
        let mut entries = 0;
        let keys = n.encoded_keys(layout);
        for encoded_key in keys.chunks_exact(mem::size_of::<EncodedInodeIndexKeyType>()) {
            let key =
                decode_key(*<&EncodedInodeIndexKeyType>::try_from(encoded_key).map_err(|_| nvfs_err_internal!())?);
            if key == 0 {
                break;
            }

            if last_key.as_ref().map(|last_key| *last_key >= key).unwrap_or(false) {
                return Err(NvFsError::from(CocoonFsFormatError::InvalidIndexNode));
            }
            entries += 1;
            last_key = Some(key);
        }
        if keys[entries * mem::size_of::<EncodedInodeIndexKeyType>()..]
            .iter()
            .any(|b| *b != 0)
        {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidIndexNode));
        }
        n.entries = entries;

        let allocated_child_ptrs_end = (n.entries + 1) * EncodedBlockPtr::ENCODED_SIZE as usize;
        let child_ptrs = n.encoded_child_ptrs(layout);
        for encoded_child_ptr in
            child_ptrs[..allocated_child_ptrs_end].chunks_exact(EncodedBlockPtr::ENCODED_SIZE as usize)
        {
            if EncodedBlockPtr::from(
                *<&[u8; EncodedBlockPtr::ENCODED_SIZE as usize]>::try_from(encoded_child_ptr)
                    .map_err(|_| nvfs_err_internal!())?,
            )
            .decode(layout.node_encrypted_block_layout.get_allocation_block_size_128b_log2() as u32)?
            .is_none()
            {
                return Err(NvFsError::from(CocoonFsFormatError::InvalidIndexNode));
            }
        }
        for encoded_child_ptr in
            child_ptrs[allocated_child_ptrs_end..].chunks_exact(EncodedBlockPtr::ENCODED_SIZE as usize)
        {
            if EncodedBlockPtr::from(
                *<&[u8; EncodedBlockPtr::ENCODED_SIZE as usize]>::try_from(encoded_child_ptr)
                    .map_err(|_| nvfs_err_internal!())?,
            )
            .decode(layout.node_encrypted_block_layout.get_allocation_block_size_128b_log2() as u32)?
            .is_some()
            {
                return Err(NvFsError::from(CocoonFsFormatError::InvalidIndexNode));
            }
        }

        Ok(n)
    }

    fn node_level(&self, layout: &InodeIndexTreeLayout) -> Result<u32, NvFsError> {
        // Encoded node levels are 1-based.
        Ok(u32::from_le_bytes(*self.encoded_node_level(layout)?) - 1)
    }

    fn lookup_child(&self, key: InodeIndexKeyType, layout: &InodeIndexTreeLayout) -> Result<usize, NvFsError> {
        Ok(match lookup_key(key, self.encoded_keys(layout), self.entries)? {
            Ok(eq_key_index) => eq_key_index + 1,
            Err(gt_key_index) => gt_key_index,
        })
    }

    fn entry_child_ptr(&self, child_index: usize, layout: &InodeIndexTreeLayout) -> Result<EncodedBlockPtr, NvFsError> {
        Ok(EncodedBlockPtr::from(
            *self.encoded_entry_child_ptr(child_index, layout)?,
        ))
    }

    fn get_separator_key(
        &self,
        left_child_index: usize,
        layout: &InodeIndexTreeLayout,
    ) -> Result<EncodedInodeIndexKeyType, NvFsError> {
        let separator_key_index = left_child_index;
        let keys_separator_key_pos = separator_key_index * mem::size_of::<EncodedInodeIndexKeyType>();
        let keys = self.encoded_keys(layout);
        Ok(*<&EncodedInodeIndexKeyType>::try_from(
            &keys[keys_separator_key_pos..keys_separator_key_pos + mem::size_of::<EncodedInodeIndexKeyType>()],
        )
        .map_err(|_| nvfs_err_internal!())?)
    }

    fn update_separator_key(
        &mut self,
        left_child_index: usize,
        separator_key: EncodedInodeIndexKeyType,
        layout: &InodeIndexTreeLayout,
    ) -> Result<(), NvFsError> {
        let separator_key_index = left_child_index;
        let keys_separator_key_pos = separator_key_index * mem::size_of::<EncodedInodeIndexKeyType>();
        let keys = self.encoded_keys_mut(layout);
        *<&mut EncodedInodeIndexKeyType>::try_from(
            &mut keys[keys_separator_key_pos..keys_separator_key_pos + mem::size_of::<EncodedInodeIndexKeyType>()],
        )
        .map_err(|_| nvfs_err_internal!())? = separator_key;
        Ok(())
    }

    fn insert(
        &mut self,
        insertion_pos_left_child_index: usize,
        separator_key: EncodedInodeIndexKeyType,
        right_child_ptr: EncodedBlockPtr,
        layout: &InodeIndexTreeLayout,
    ) -> Result<(), NvFsError> {
        if self.entries == layout.max_internal_node_entries {
            return Err(nvfs_err_internal!());
        }

        let insertion_pos_separator_key_index = insertion_pos_left_child_index;
        let insertion_pos_right_child_index = insertion_pos_left_child_index + 1;

        let keys_insertion_pos = insertion_pos_separator_key_index * mem::size_of::<EncodedInodeIndexKeyType>();
        let moved_keys_begin = keys_insertion_pos;
        let moved_keys_end = self.entries * mem::size_of::<EncodedInodeIndexKeyType>();
        let keys = self.encoded_keys_mut(layout);
        keys.copy_within(
            moved_keys_begin..moved_keys_end,
            moved_keys_begin + mem::size_of::<EncodedInodeIndexKeyType>(),
        );
        *<&mut EncodedInodeIndexKeyType>::try_from(
            &mut keys[keys_insertion_pos..keys_insertion_pos + mem::size_of::<EncodedInodeIndexKeyType>()],
        )
        .map_err(|_| nvfs_err_internal!())? = separator_key;

        let child_ptrs_insertion_pos = insertion_pos_right_child_index * EncodedBlockPtr::ENCODED_SIZE as usize;
        let moved_child_ptrs_begin = child_ptrs_insertion_pos;
        let moved_child_ptrs_end = (self.entries + 1) * EncodedBlockPtr::ENCODED_SIZE as usize;
        let child_ptrs = self.encoded_child_ptrs_mut(layout);
        child_ptrs.copy_within(
            moved_child_ptrs_begin..moved_child_ptrs_end,
            moved_child_ptrs_begin + EncodedBlockPtr::ENCODED_SIZE as usize,
        );
        *<&mut [u8; EncodedBlockPtr::ENCODED_SIZE as usize]>::try_from(
            &mut child_ptrs
                [child_ptrs_insertion_pos..child_ptrs_insertion_pos + EncodedBlockPtr::ENCODED_SIZE as usize],
        )
        .map_err(|_| nvfs_err_internal!())? = *right_child_ptr;

        self.entries += 1;

        Ok(())
    }

    fn remove(&mut self, removal_pos_right_child_index: usize, layout: &InodeIndexTreeLayout) -> Result<(), NvFsError> {
        if removal_pos_right_child_index == 0 {
            return Err(nvfs_err_internal!());
        }

        let removal_pos_separator_key_index = removal_pos_right_child_index - 1;

        let keys_removal_pos = removal_pos_separator_key_index * mem::size_of::<EncodedInodeIndexKeyType>();
        let moved_keys_begin = keys_removal_pos + mem::size_of::<EncodedInodeIndexKeyType>();
        let moved_keys_end = self.entries * mem::size_of::<EncodedInodeIndexKeyType>();
        let keys = self.encoded_keys_mut(layout);
        keys.copy_within(moved_keys_begin..moved_keys_end, keys_removal_pos);
        // Fill the newly vacant key slot at the tail with a value of
        // SpecialInode::NoInode.
        keys[moved_keys_end - mem::size_of::<EncodedInodeIndexKeyType>()..moved_keys_end].fill(0u8);

        let child_ptrs_removal_pos = removal_pos_right_child_index * EncodedBlockPtr::ENCODED_SIZE as usize;
        let moved_child_ptrs_begin = child_ptrs_removal_pos + EncodedBlockPtr::ENCODED_SIZE as usize;
        let moved_child_ptrs_end = (self.entries + 1) * EncodedBlockPtr::ENCODED_SIZE as usize;
        let child_ptrs = self.encoded_child_ptrs_mut(layout);
        child_ptrs.copy_within(moved_child_ptrs_begin..moved_child_ptrs_end, child_ptrs_removal_pos);
        // Clear the newly vacant child pointer entry at the tail.
        *<&mut [u8; EncodedBlockPtr::ENCODED_SIZE as usize]>::try_from(
            &mut child_ptrs[moved_child_ptrs_end - EncodedBlockPtr::ENCODED_SIZE as usize..moved_child_ptrs_end],
        )
        .map_err(|_| nvfs_err_internal!())? = *EncodedBlockPtr::encode_nil();

        self.entries -= 1;

        Ok(())
    }

    fn rotate_left(
        &mut self,
        right: &mut Self,
        count: usize,
        parent_separator_key: EncodedInodeIndexKeyType,
        layout: &InodeIndexTreeLayout,
    ) -> Result<EncodedInodeIndexKeyType, NvFsError> {
        if count == 0 {
            return Ok(parent_separator_key);
        }

        let left = self;
        if left.entries + count > layout.max_internal_node_entries
            || right.entries < count
            || right.entries - count < layout.min_internal_node_entries
        {
            return Err(nvfs_err_internal!());
        }

        let original_src_entries = right.entries;
        let keys_spill_len = count * mem::size_of::<EncodedInodeIndexKeyType>();
        let dst_keys_spill_begin = left.entries * mem::size_of::<EncodedInodeIndexKeyType>();
        let dst_keys_spill_end = dst_keys_spill_begin + keys_spill_len;
        let src_keys_spill_end = keys_spill_len;
        let dst_keys = left.encoded_keys_mut(layout);
        let src_keys = right.encoded_keys_mut(layout);
        // Append parent separator to the left node.
        *<&mut EncodedInodeIndexKeyType>::try_from(
            &mut dst_keys[dst_keys_spill_begin..dst_keys_spill_begin + mem::size_of::<EncodedInodeIndexKeyType>()],
        )
        .map_err(|_| nvfs_err_internal!())? = parent_separator_key;
        // Spill count - 1 keys from right to left.
        left.encoded_keys_mut(layout)
            [dst_keys_spill_begin + mem::size_of::<EncodedInodeIndexKeyType>()..dst_keys_spill_end]
            .copy_from_slice(&src_keys[..src_keys_spill_end - mem::size_of::<EncodedInodeIndexKeyType>()]);
        // The new parent separator key is the next one popped off the head of the right
        // node.
        let new_parent_separator_key = *<&EncodedInodeIndexKeyType>::try_from(
            &src_keys[src_keys_spill_end - mem::size_of::<EncodedInodeIndexKeyType>()..src_keys_spill_end],
        )
        .map_err(|_| nvfs_err_internal!())?;
        // Memmove the right node's remaining keys to the front and clear out the tail
        // accordingly.
        let src_original_keys_end = original_src_entries * mem::size_of::<EncodedInodeIndexKeyType>();
        src_keys.copy_within(src_keys_spill_end..src_original_keys_end, 0);
        // Encode SpecialInode::NoInode in little endian at the src' newly vacant tail
        // key entries.
        src_keys[src_original_keys_end - keys_spill_len..src_original_keys_end].fill(0);

        let child_ptrs_spill_len = count * EncodedBlockPtr::ENCODED_SIZE as usize;
        let dst_child_ptrs_spill_begin = (left.entries + 1) * EncodedBlockPtr::ENCODED_SIZE as usize;
        let dst_child_ptrs_spill_end = dst_child_ptrs_spill_begin + child_ptrs_spill_len;
        let src_child_ptrs_spill_end = child_ptrs_spill_len;
        let src_child_ptrs = right.encoded_child_ptrs_mut(layout);
        // Spill count child pointers from right to left.
        left.encoded_child_ptrs_mut(layout)[dst_child_ptrs_spill_begin..dst_child_ptrs_spill_end]
            .copy_from_slice(&src_child_ptrs[..src_child_ptrs_spill_end]);
        // Memmove the right node's remaining child pointers to the front and clear out
        // the tail accordingly.
        let src_original_child_ptrs_end = (original_src_entries + 1) * EncodedBlockPtr::ENCODED_SIZE as usize;
        src_child_ptrs.copy_within(src_child_ptrs_spill_end..src_original_child_ptrs_end, 0);
        for vacant_src_child_ptr in src_child_ptrs
            [src_original_child_ptrs_end - child_ptrs_spill_len..src_original_child_ptrs_end]
            .chunks_exact_mut(EncodedBlockPtr::ENCODED_SIZE as usize)
        {
            *<&mut [u8; EncodedBlockPtr::ENCODED_SIZE as usize]>::try_from(vacant_src_child_ptr)
                .map_err(|_| nvfs_err_internal!())? = *EncodedBlockPtr::encode_nil();
        }

        left.entries += count;
        right.entries -= count;
        Ok(new_parent_separator_key)
    }

    fn rotate_right(
        &mut self,
        right: &mut Self,
        count: usize,
        parent_separator_key: EncodedInodeIndexKeyType,
        layout: &InodeIndexTreeLayout,
    ) -> Result<EncodedInodeIndexKeyType, NvFsError> {
        if count == 0 {
            return Ok(parent_separator_key);
        }

        let left = self;
        if right.entries + count > layout.max_internal_node_entries
            || left.entries < count
            || left.entries - count < layout.min_internal_node_entries
        {
            return Err(nvfs_err_internal!());
        }

        let original_src_entries = left.entries;
        let original_dst_entries = right.entries;
        let keys_spill_len = count * mem::size_of::<EncodedInodeIndexKeyType>();
        let src_keys_spill_end = original_src_entries * mem::size_of::<EncodedInodeIndexKeyType>();
        let src_keys_spill_begin = src_keys_spill_end - keys_spill_len;
        let dst_keys_spill_end = keys_spill_len;
        let dst_keys = right.encoded_keys_mut(layout);
        let src_keys = left.encoded_keys_mut(layout);
        // Make room for count new keys at the right node's head by memmoving the
        // existing ones towards the tail.
        let dst_original_keys_end = original_dst_entries * mem::size_of::<EncodedInodeIndexKeyType>();
        dst_keys.copy_within(..dst_original_keys_end, dst_keys_spill_end);
        // Prepend the parent separator key to the right node.
        *<&mut EncodedInodeIndexKeyType>::try_from(
            &mut dst_keys[dst_keys_spill_end - mem::size_of::<EncodedInodeIndexKeyType>()..dst_keys_spill_end],
        )
        .map_err(|_| nvfs_err_internal!())? = parent_separator_key;
        // Spill count - 1 keys from left to right.
        dst_keys[..dst_keys_spill_end - mem::size_of::<EncodedInodeIndexKeyType>()].copy_from_slice(
            &src_keys[src_keys_spill_begin + mem::size_of::<EncodedInodeIndexKeyType>()..src_keys_spill_end],
        );
        // The new parent separator key is the next one popped off the tail of the left
        // node.
        let new_parent_separator_key = *<&EncodedInodeIndexKeyType>::try_from(
            &src_keys[src_keys_spill_begin..src_keys_spill_begin + mem::size_of::<EncodedInodeIndexKeyType>()],
        )
        .map_err(|_| nvfs_err_internal!())?;
        // Encode SpecialInode::NoInode in little endian at the src' newly vacant tail
        // key entries.
        src_keys[src_keys_spill_begin..src_keys_spill_end].fill(0u8);

        let child_ptrs_spill_len = count * EncodedBlockPtr::ENCODED_SIZE as usize;
        let src_child_ptrs_spill_end = (original_src_entries + 1) * EncodedBlockPtr::ENCODED_SIZE as usize;
        let src_child_ptrs_spill_begin = src_child_ptrs_spill_end - child_ptrs_spill_len;
        let dst_child_ptrs_spill_end = child_ptrs_spill_len;
        let dst_child_ptrs = right.encoded_child_ptrs_mut(layout);
        let src_child_ptrs = left.encoded_child_ptrs_mut(layout);
        // Make room for count new child pointers at the right node's head by memmoving
        // the existing ones towards the tail.
        let dst_original_child_ptrs_end = (original_dst_entries + 1) * EncodedBlockPtr::ENCODED_SIZE as usize;
        dst_child_ptrs.copy_within(..dst_original_child_ptrs_end, dst_child_ptrs_spill_end);
        // Spill count child pointers from left to right.
        dst_child_ptrs[..dst_child_ptrs_spill_end]
            .copy_from_slice(&src_child_ptrs[src_child_ptrs_spill_begin..src_child_ptrs_spill_end]);
        // And clear out all child pointers which became vacant at the src' tail.
        for vacant_src_child_ptr in src_child_ptrs[src_child_ptrs_spill_begin..src_child_ptrs_spill_end]
            .chunks_exact_mut(EncodedBlockPtr::ENCODED_SIZE as usize)
        {
            *<&mut [u8; EncodedBlockPtr::ENCODED_SIZE as usize]>::try_from(vacant_src_child_ptr)
                .map_err(|_| nvfs_err_internal!())? = *EncodedBlockPtr::encode_nil();
        }

        left.entries -= count;
        right.entries += count;
        Ok(new_parent_separator_key)
    }

    fn split(
        &mut self,
        new_node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        layout: &InodeIndexTreeLayout,
    ) -> Result<(Self, EncodedInodeIndexKeyType), NvFsError> {
        // If the current number of keys is odd, there will be one more key
        // in the left node than in the right after spilling. However, the last
        // remaining key in the left node will get moved to the parent as a
        // separator. So in either case, after the splitting is complete, both
        // nodes will have their entry count >= the lower threshold.
        let new_node_entries = self.entries / 2;
        if new_node_entries < layout.min_internal_node_entries
            || self.entries - new_node_entries - 1 < layout.min_internal_node_entries
        {
            return Err(nvfs_err_internal!());
        }

        let new_encoded_node = try_alloc_vec(layout.encoded_node_len)?;
        let mut new_node = Self {
            encoded_node: new_encoded_node,
            entries: new_node_entries,
            node_allocation_blocks_begin: new_node_allocation_blocks_begin,
        };
        *new_node.encoded_node_level_mut(layout)? = *self.encoded_node_level(layout)?;

        let original_src_entries = self.entries;
        let keys_spill_len = new_node_entries * mem::size_of::<EncodedInodeIndexKeyType>();
        let src_keys_spill_end = original_src_entries * mem::size_of::<EncodedInodeIndexKeyType>();
        let src_keys_spill_begin = src_keys_spill_end - keys_spill_len;
        let dst_keys_spill_end = keys_spill_len;
        let dst_keys = new_node.encoded_keys_mut(layout);
        let src_keys = self.encoded_keys_mut(layout);
        dst_keys[..dst_keys_spill_end].copy_from_slice(&src_keys[src_keys_spill_begin..src_keys_spill_end]);
        // The remainder of dst_keys is initialized to all-zeroes, i.e. to
        // SpecialInode::NoInode, by the Vec allocation above already. Take care
        // of the keys removed from self.
        src_keys[src_keys_spill_begin..src_keys_spill_end].fill(0u8);
        // Extract the new separator key to insert at the parent and zeroize that as
        // well.
        let parent_separator_key = *<&EncodedInodeIndexKeyType>::try_from(
            &src_keys[src_keys_spill_begin - mem::size_of::<EncodedInodeIndexKeyType>()..src_keys_spill_begin],
        )
        .map_err(|_| nvfs_err_internal!())?;
        src_keys[src_keys_spill_begin - mem::size_of::<EncodedInodeIndexKeyType>()..src_keys_spill_begin].fill(0);

        let child_ptrs_spill_len = (new_node_entries + 1) * EncodedBlockPtr::ENCODED_SIZE as usize;
        let src_child_ptrs_spill_end = (original_src_entries + 1) * EncodedBlockPtr::ENCODED_SIZE as usize;
        let src_child_ptrs_spill_begin = src_child_ptrs_spill_end - child_ptrs_spill_len;
        let dst_child_ptrs_spill_end = child_ptrs_spill_len;
        let dst_child_ptrs = new_node.encoded_child_ptrs_mut(layout);
        let src_child_ptrs = self.encoded_child_ptrs_mut(layout);
        dst_child_ptrs[..dst_child_ptrs_spill_end]
            .copy_from_slice(&src_child_ptrs[src_child_ptrs_spill_begin..src_child_ptrs_spill_end]);
        // Clear out the child pointers which became vacant at the left node's tail.
        for vacant_src_child_ptr in src_child_ptrs[src_child_ptrs_spill_begin..src_child_ptrs_spill_end]
            .chunks_exact_mut(EncodedBlockPtr::ENCODED_SIZE as usize)
        {
            *<&mut [u8; EncodedBlockPtr::ENCODED_SIZE as usize]>::try_from(vacant_src_child_ptr)
                .map_err(|_| nvfs_err_internal!())? = *EncodedBlockPtr::encode_nil();
        }
        // And initialize the unoccupied child pointer slots at the right node's tail.
        for vacant_dst_child_ptr in
            dst_child_ptrs[dst_child_ptrs_spill_end..].chunks_exact_mut(EncodedBlockPtr::ENCODED_SIZE as usize)
        {
            *<&mut [u8; EncodedBlockPtr::ENCODED_SIZE as usize]>::try_from(vacant_dst_child_ptr)
                .map_err(|_| nvfs_err_internal!())? = *EncodedBlockPtr::encode_nil();
        }

        self.entries -= new_node_entries + 1;

        Ok((new_node, parent_separator_key))
    }

    fn merge(
        &mut self,
        right: &Self,
        parent_separator_key: EncodedInodeIndexKeyType,
        layout: &InodeIndexTreeLayout,
    ) -> Result<(), NvFsError> {
        let left = self;
        if left.entries + 1 + right.entries > layout.max_leaf_node_entries {
            return Err(nvfs_err_internal!());
        }
        let keys_spill_len = right.entries * mem::size_of::<EncodedInodeIndexKeyType>();
        let dst_keys_spill_begin = (left.entries + 1) * mem::size_of::<EncodedInodeIndexKeyType>();
        let dst_keys_spill_end = dst_keys_spill_begin + keys_spill_len;
        let src_keys_spill_end = keys_spill_len;
        let src_keys = right.encoded_keys(layout);
        let dst_keys = left.encoded_keys_mut(layout);
        // Append the parent separator key to the left node.
        *<&mut EncodedInodeIndexKeyType>::try_from(
            &mut dst_keys[dst_keys_spill_begin - mem::size_of::<EncodedInodeIndexKeyType>()..dst_keys_spill_begin],
        )
        .map_err(|_| nvfs_err_internal!())? = parent_separator_key;
        // Spill all keys from right to left.
        dst_keys[dst_keys_spill_begin..dst_keys_spill_end].copy_from_slice(&src_keys[..src_keys_spill_end]);

        let child_ptrs_spill_len = (right.entries + 1) * EncodedBlockPtr::ENCODED_SIZE as usize;
        let dst_child_ptrs_spill_begin = (left.entries + 1) * EncodedBlockPtr::ENCODED_SIZE as usize;
        let dst_child_ptrs_spill_end = dst_child_ptrs_spill_begin + child_ptrs_spill_len;
        let src_child_ptrs_spill_end = child_ptrs_spill_len;
        let src_child_ptrs = right.encoded_child_ptrs(layout);
        // Spill all child pointers from right to left.
        left.encoded_child_ptrs_mut(layout)[dst_child_ptrs_spill_begin..dst_child_ptrs_spill_end]
            .copy_from_slice(&src_child_ptrs[..src_child_ptrs_spill_end]);

        left.entries += right.entries + 1;

        Ok(())
    }

    fn encoded_child_ptrs(&self, layout: &InodeIndexTreeLayout) -> &[u8] {
        let encoded_child_ptrs_begin = 0;
        let encoded_child_ptrs_end =
            encoded_child_ptrs_begin + (layout.max_leaf_node_entries + 1) * EncodedBlockPtr::ENCODED_SIZE as usize;
        &self.encoded_node[encoded_child_ptrs_begin..encoded_child_ptrs_end]
    }

    fn encoded_child_ptrs_mut(&mut self, layout: &InodeIndexTreeLayout) -> &mut [u8] {
        let encoded_child_ptrs_begin = 0;
        let encoded_child_ptrs_end =
            encoded_child_ptrs_begin + (layout.max_leaf_node_entries + 1) * EncodedBlockPtr::ENCODED_SIZE as usize;
        &mut self.encoded_node[encoded_child_ptrs_begin..encoded_child_ptrs_end]
    }

    fn encoded_keys(&self, layout: &InodeIndexTreeLayout) -> &[u8] {
        let encoded_keys_begin = (layout.max_leaf_node_entries + 1) * EncodedBlockPtr::ENCODED_SIZE as usize;
        let encoded_keys_end =
            encoded_keys_begin + layout.max_leaf_node_entries * mem::size_of::<EncodedInodeIndexKeyType>();
        &self.encoded_node[encoded_keys_begin..encoded_keys_end]
    }

    fn encoded_keys_mut(&mut self, layout: &InodeIndexTreeLayout) -> &mut [u8] {
        let encoded_keys_begin = (layout.max_leaf_node_entries + 1) * EncodedBlockPtr::ENCODED_SIZE as usize;
        let encoded_keys_end =
            encoded_keys_begin + layout.max_leaf_node_entries * mem::size_of::<EncodedInodeIndexKeyType>();
        &mut self.encoded_node[encoded_keys_begin..encoded_keys_end]
    }

    fn encoded_node_level(&self, layout: &InodeIndexTreeLayout) -> Result<&[u8; mem::size_of::<u32>()], NvFsError> {
        <&[u8; mem::size_of::<u32>()]>::try_from(&self.encoded_node[layout.encoded_node_len - mem::size_of::<u32>()..])
            .map_err(|_| nvfs_err_internal!())
    }

    fn encoded_node_level_mut(
        &mut self,
        layout: &InodeIndexTreeLayout,
    ) -> Result<&mut [u8; mem::size_of::<u32>()], NvFsError> {
        <&mut [u8; mem::size_of::<u32>()]>::try_from(
            &mut self.encoded_node[layout.encoded_node_len - mem::size_of::<u32>()..],
        )
        .map_err(|_| nvfs_err_internal!())
    }

    fn encoded_entry_child_ptr(
        &self,
        child_index: usize,
        layout: &InodeIndexTreeLayout,
    ) -> Result<&[u8; EncodedExtentPtr::ENCODED_SIZE as usize], NvFsError> {
        let entry_begin = child_index * EncodedBlockPtr::ENCODED_SIZE as usize;
        let entry_end = entry_begin + EncodedBlockPtr::ENCODED_SIZE as usize;
        let encoded_child_ptrs = self.encoded_child_ptrs(layout);
        if encoded_child_ptrs.len() < entry_end {
            return Err(nvfs_err_internal!());
        }
        <&[u8; EncodedBlockPtr::ENCODED_SIZE as usize]>::try_from(&encoded_child_ptrs[entry_begin..entry_end])
            .map_err(|_| nvfs_err_internal!())
    }
}

/// Arbitrary node in the inode index B+-tree, i.e. either a leaf or an internal one.
enum InodeIndexTreeNode {
    /// Internal node.
    Internal(InodeIndexTreeInternalNode),
    /// Leaf node.
    Leaf(InodeIndexTreeLeafNode),
}

impl InodeIndexTreeNode {
    fn decode(
        node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        encoded_node: Vec<u8>,
        layout: &InodeIndexTreeLayout,
    ) -> Result<Self, NvFsError> {
        if encoded_node.len() != layout.encoded_node_len {
            return Err(nvfs_err_internal!());
        }

        // Encoded node levels are 1-based, counted from leaf nodes upwards.
        match u32::from_le_bytes(
            *<&[u8; mem::size_of::<u32>()]>::try_from(&encoded_node[layout.encoded_node_len - mem::size_of::<u32>()..])
                .map_err(|_| nvfs_err_internal!())?,
        ) {
            0u32 => Err(NvFsError::from(CocoonFsFormatError::InvalidIndexNode)),
            1u32 => Ok(Self::Leaf(InodeIndexTreeLeafNode::decode(
                node_allocation_blocks_begin,
                encoded_node,
                layout,
            )?)),
            _ => Ok(Self::Internal(InodeIndexTreeInternalNode::decode(
                node_allocation_blocks_begin,
                encoded_node,
                layout,
            )?)),
        }
    }

    fn node_allocation_blocks_begin(&self) -> layout::PhysicalAllocBlockIndex {
        match self {
            Self::Internal(internal_node) => internal_node.node_allocation_blocks_begin,
            Self::Leaf(leaf_node) => leaf_node.node_allocation_blocks_begin,
        }
    }

    fn clone_with_preallocated_buf(&self, mut preallocated_encoded_node: Vec<u8>) -> Self {
        match self {
            Self::Internal(InodeIndexTreeInternalNode {
                encoded_node,
                entries,
                node_allocation_blocks_begin,
            }) => {
                preallocated_encoded_node.copy_from_slice(encoded_node);
                Self::Internal(InodeIndexTreeInternalNode {
                    encoded_node: preallocated_encoded_node,
                    entries: *entries,
                    node_allocation_blocks_begin: *node_allocation_blocks_begin,
                })
            }
            Self::Leaf(InodeIndexTreeLeafNode {
                encoded_node,
                entries,
                node_allocation_blocks_begin,
            }) => {
                preallocated_encoded_node.copy_from_slice(encoded_node);
                Self::Leaf(InodeIndexTreeLeafNode {
                    encoded_node: preallocated_encoded_node,
                    entries: *entries,
                    node_allocation_blocks_begin: *node_allocation_blocks_begin,
                })
            }
        }
    }
}

/// Entry in [`InodeIndexTreeNodeCache`].
struct InodeIndexTreeNodeCacheEntry {
    node_level: u32,
    node: InodeIndexTreeNode,
}

/// Inode index B+-tree node cache.
pub struct InodeIndexTreeNodeCache {
    cached_nodes: Vec<InodeIndexTreeNodeCacheEntry>,
    cached_nodes_capacity: usize,
    index_tree_levels: u32,
}

impl InodeIndexTreeNodeCache {
    fn new(layout: &InodeIndexTreeLayout, index_tree_levels: u32) -> Self {
        // Cache the two topmost levels' nodes.
        let cached_nodes_capacity = 1 + layout.max_internal_node_entries.max(layout.max_leaf_node_entries);
        Self {
            cached_nodes: Vec::new(),
            cached_nodes_capacity,
            index_tree_levels,
        }
    }

    fn clear(&mut self) {
        self.cached_nodes = Vec::new();
    }

    fn prune_cond<C: FnMut(layout::PhysicalAllocBlockIndex, u32) -> bool>(&mut self, mut cond: C) {
        let mut i = 0;
        while i < self.cached_nodes.len() {
            let entry = &self.cached_nodes[i];
            if cond(entry.node.node_allocation_blocks_begin(), entry.node_level) {
                self.cached_nodes.remove(i);
            } else {
                i += 1;
            }
        }
    }

    fn prune_node_at(&mut self, node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex) {
        if let Ok(entry_index) = self._lookup_entry_index(node_allocation_blocks_begin) {
            self.cached_nodes.remove(entry_index.index);
        }
    }

    fn reconfigure(&mut self, index_tree_levels: u32) {
        if self.index_tree_levels == index_tree_levels {
            return;
        }

        // Only the two topmost levels' nodes are getting cached, evict the ones which
        // don't qualify anymore.
        self.prune_cond(|_, cache_entry_node_level| {
            cache_entry_node_level >= index_tree_levels || cache_entry_node_level + 2 < index_tree_levels
        });
        self.index_tree_levels = index_tree_levels;
    }

    fn insert_entries_from(&mut self, other: &mut Self) {
        if self.index_tree_levels != other.index_tree_levels {
            return;
        }

        if !other.cached_nodes.is_empty() && !self.try_reserve_cached_nodes() {
            other.clear();
            return;
        }

        let mut i = 0;
        for new_node in other.cached_nodes.drain(..) {
            let new_node_allocation_blocks_begin = new_node.node.node_allocation_blocks_begin();
            let mut found_match = false;
            while i < self.cached_nodes.len() {
                match self.cached_nodes[i]
                    .node
                    .node_allocation_blocks_begin()
                    .cmp(&new_node_allocation_blocks_begin)
                {
                    cmp::Ordering::Less => (),
                    cmp::Ordering::Equal => {
                        found_match = true;
                        break;
                    }
                    cmp::Ordering::Greater => break,
                };
                i += 1;
            }
            if found_match {
                self.cached_nodes[i] = new_node;
            } else {
                self.cached_nodes.insert(i, new_node);
            }
            i += 1;
        }
        other.cached_nodes = Vec::new();
    }

    fn insert(&mut self, node_level: u32, node: InodeIndexTreeNode) -> InodeIndexTreeNodeCacheInsertionResult {
        match self.lookup_entry_index(node.node_allocation_blocks_begin(), Some(node_level)) {
            None => InodeIndexTreeNodeCacheInsertionResult::Uncacheable { node },
            Some(Ok(index)) => {
                self.cached_nodes[index.index].node = node;
                InodeIndexTreeNodeCacheInsertionResult::Inserted { index }
            }
            Some(Err(index)) => {
                if self.try_reserve_cached_nodes() {
                    debug_assert!(self.cached_nodes.capacity() > self.cached_nodes.len());
                    self.cached_nodes
                        .insert(usize::from(index), InodeIndexTreeNodeCacheEntry { node_level, node });
                    InodeIndexTreeNodeCacheInsertionResult::Inserted { index }
                } else {
                    InodeIndexTreeNodeCacheInsertionResult::Uncacheable { node }
                }
            }
        }
    }

    fn remove(&mut self, index: InodeIndexTreeNodeCacheIndex) -> InodeIndexTreeNode {
        self.cached_nodes.remove(index.index).node
    }

    fn lookup(
        &self,
        node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        node_level: Option<u32>,
    ) -> Option<InodeIndexTreeNodeCacheIndex> {
        self.lookup_entry_index(node_allocation_blocks_begin, node_level)?.ok()
    }

    fn get_entry_node(&self, index: InodeIndexTreeNodeCacheIndex) -> &InodeIndexTreeNode {
        &self.cached_nodes[index.index].node
    }

    fn get_entry_node_level(&self, index: InodeIndexTreeNodeCacheIndex) -> u32 {
        self.cached_nodes[index.index].node_level
    }

    fn try_reserve_cached_nodes(&mut self) -> bool {
        if self.cached_nodes.capacity() != 0 {
            debug_assert!(self.cached_nodes.capacity() >= self.cached_nodes_capacity);
            true
        } else {
            // Failure to allocate is non-fatal for a cache.
            self.cached_nodes.try_reserve_exact(self.cached_nodes_capacity).is_ok()
        }
    }

    fn lookup_entry_index(
        &self,
        node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        node_level: Option<u32>,
    ) -> Option<Result<InodeIndexTreeNodeCacheIndex, InodeIndexTreeNodeCacheIndex>> {
        // Only the two topmost levels' nodes are getting cached.
        if let Some(node_level) = node_level {
            if node_level >= self.index_tree_levels || node_level + 2 < self.index_tree_levels {
                return None;
            }
        }

        Some(self._lookup_entry_index(node_allocation_blocks_begin))
    }

    fn _lookup_entry_index(
        &self,
        node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
    ) -> Result<InodeIndexTreeNodeCacheIndex, InodeIndexTreeNodeCacheIndex> {
        self.cached_nodes
            .as_slice()
            .binary_search_by(|cache_entry| {
                cache_entry
                    .node
                    .node_allocation_blocks_begin()
                    .cmp(&node_allocation_blocks_begin)
            })
            .map(InodeIndexTreeNodeCacheIndex::from)
            .map_err(InodeIndexTreeNodeCacheIndex::from)
    }
}

/// Index into the [`InodeIndexTreeNodeCache`].
#[derive(Clone, Copy)]
struct InodeIndexTreeNodeCacheIndex {
    index: usize,
}

impl convert::From<usize> for InodeIndexTreeNodeCacheIndex {
    fn from(value: usize) -> Self {
        Self { index: value }
    }
}

impl convert::From<InodeIndexTreeNodeCacheIndex> for usize {
    fn from(value: InodeIndexTreeNodeCacheIndex) -> Self {
        value.index
    }
}

/// Result of inserting a node into the [`InodeIndexTreeNodeCache`].
enum InodeIndexTreeNodeCacheInsertionResult {
    /// The node has been inserted.
    Inserted { index: InodeIndexTreeNodeCacheIndex },
    /// The node does not qualify for caching, or a memory allocation failure has been encountered
    /// when attempting to insert it.
    Uncacheable { node: InodeIndexTreeNode },
}

/// The inode index.
pub struct InodeIndex<ST: sync_types::SyncTypes> {
    layout: InodeIndexTreeLayout,
    entry_leaf_node_preauth_cca_protection_digest: Vec<u8>,
    index_tree_levels: u32,
    tree_nodes_cache: ST::RwLock<InodeIndexTreeNodeCache>,
    root_node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
    tree_node_encryption_instance: encryption_entities::EncryptedBlockEncryptionInstance,
    tree_node_decryption_instance: encryption_entities::EncryptedBlockDecryptionInstance,
}

impl<ST: sync_types::SyncTypes> InodeIndex<ST> {
    pub fn initialize(
        entry_leaf_node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        auth_tree_inode_entry_extent_ptr: extent_ptr::EncodedExtentPtr,
        alloc_bitmap_inode_entry_extent_ptr: extent_ptr::EncodedExtentPtr,
        image_layout: &layout::ImageLayout,
        root_key: &keys::RootKey,
        keys_cache: &mut keys::KeyCacheRef<ST>,
        rng: &mut dyn rng::RngCoreDispatchable,
    ) -> Result<(Self, Vec<u8>), NvFsError> {
        let tree_node_encrypted_block_layout = encryption_entities::EncryptedBlockLayout::new(
            image_layout.block_cipher_alg,
            image_layout.index_tree_node_allocation_blocks_log2,
            image_layout.allocation_block_size_128b_log2,
        )?;
        let tree_node_encryption_key = keys::KeyCache::get_key(
            keys_cache,
            root_key,
            &keys::KeyId::new(
                SpecialInode::IndexRoot as u32,
                InodeKeySubdomain::InodeData as u32,
                keys::KeyPurpose::Encryption,
            ),
        )?;
        let tree_node_encryption_block_cipher_instance = symcipher::SymBlockCipherModeEncryptionInstance::new(
            tpm2_interface::TpmiAlgCipherMode::Cbc,
            &image_layout.block_cipher_alg,
            &tree_node_encryption_key,
        )?;
        let tree_node_decryption_block_cipher_instance = symcipher::SymBlockCipherModeDecryptionInstance::new(
            tpm2_interface::TpmiAlgCipherMode::Cbc,
            &image_layout.block_cipher_alg,
            &tree_node_encryption_key,
        )?;
        drop(tree_node_encryption_key);
        let tree_node_encryption_instance = encryption_entities::EncryptedBlockEncryptionInstance::new(
            tree_node_encrypted_block_layout.clone(),
            tree_node_encryption_block_cipher_instance,
        )?;
        let tree_node_decryption_instance = encryption_entities::EncryptedBlockDecryptionInstance::new(
            tree_node_encrypted_block_layout.clone(),
            tree_node_decryption_block_cipher_instance,
        )?;
        let layout = InodeIndexTreeLayout::new(tree_node_encrypted_block_layout)?;

        let mut entry_leaf_node = InodeIndexTreeLeafNode::new_empty(entry_leaf_node_allocation_blocks_begin, &layout)?;
        entry_leaf_node.insert(
            SpecialInode::AuthTree as InodeIndexKeyType,
            auth_tree_inode_entry_extent_ptr,
            None,
            &layout,
        )?;
        entry_leaf_node.insert(
            SpecialInode::AllocBitmap as InodeIndexKeyType,
            alloc_bitmap_inode_entry_extent_ptr,
            None,
            &layout,
        )?;
        // Initially the entry leaf node is the root.
        let index_root_inode_entry_extent_ptr = extent_ptr::EncodedExtentPtr::encode(
            Some(&layout::PhysicalAllocBlockRange::from((
                entry_leaf_node_allocation_blocks_begin,
                layout::AllocBlockCount::from(1u64 << (image_layout.index_tree_node_allocation_blocks_log2 as u32)),
            ))),
            false,
        )?;
        entry_leaf_node.insert(
            SpecialInode::IndexRoot as InodeIndexKeyType,
            index_root_inode_entry_extent_ptr,
            None,
            &layout,
        )?;

        let tree_node_block_size = 1usize
            << (image_layout.index_tree_node_allocation_blocks_log2 as u32
                + image_layout.allocation_block_size_128b_log2 as u32
                + 7);
        let mut encrypted_entry_leaf_node = try_alloc_vec(tree_node_block_size)?;
        tree_node_encryption_instance.encrypt_one_block(
            io_slices::SingletonIoSliceMut::new(&mut encrypted_entry_leaf_node).map_infallible_err(),
            io_slices::SingletonIoSlice::new(&entry_leaf_node.encoded_node).map_infallible_err(),
            rng,
        )?;

        let preauth_cca_protection_hmac_digest_len =
            hash::hash_alg_digest_len(image_layout.preauth_cca_protection_hmac_hash_alg) as usize;
        let mut entry_leaf_node_preauth_cca_protection_digest = try_alloc_vec(preauth_cca_protection_hmac_digest_len)?;
        entry_leaf_node_preautch_cca_hmac(
            &mut entry_leaf_node_preauth_cca_protection_digest,
            io_slices::SingletonIoSlice::new(&encrypted_entry_leaf_node).map_infallible_err(),
            image_layout,
            root_key,
            keys_cache,
        )?;

        let mut tree_nodes_cache = InodeIndexTreeNodeCache::new(&layout, 1);
        tree_nodes_cache.insert(0, InodeIndexTreeNode::Leaf(entry_leaf_node));

        Ok((
            Self {
                layout,
                entry_leaf_node_preauth_cca_protection_digest,
                index_tree_levels: 1,
                tree_nodes_cache: ST::RwLock::from(tree_nodes_cache),
                root_node_allocation_blocks_begin: entry_leaf_node_allocation_blocks_begin,
                tree_node_encryption_instance,
                tree_node_decryption_instance,
            },
            encrypted_entry_leaf_node,
        ))
    }

    pub fn get_entry_leaf_node_preauth_cca_protection_digest(&self) -> &[u8] {
        &self.entry_leaf_node_preauth_cca_protection_digest
    }

    pub fn apply_updates<IM: FnMut(&layout::PhysicalAllocBlockRange) -> bool>(
        &mut self,
        updates: &mut TransactionInodeIndexUpdates,
        mut is_range_modified: IM,
    ) {
        if let Some(updated_entry_leaf_node_preauth_cca_protection_digest) =
            updates.get_updated_entry_leaf_node_preauth_cca_protection_digest()
        {
            self.entry_leaf_node_preauth_cca_protection_digest
                .copy_from_slice(updated_entry_leaf_node_preauth_cca_protection_digest);
        }

        self.root_node_allocation_blocks_begin = updates.root_node_allocation_blocks_begin;
        self.index_tree_levels = updates.index_tree_levels;

        self.tree_nodes_cache.get_mut().reconfigure(updates.index_tree_levels);
        let tree_node_allocation_blocks_log2 = self
            .layout
            .node_encrypted_block_layout
            .get_block_allocation_blocks_log2();
        let tree_node_allocation_blocks = layout::AllocBlockCount::from(1u64 << tree_node_allocation_blocks_log2);
        self.tree_nodes_cache
            .get_mut()
            .prune_cond(|tree_node_allocation_blocks_begin, _tree_node_level| {
                is_range_modified(&layout::PhysicalAllocBlockRange::from((
                    tree_node_allocation_blocks_begin,
                    tree_node_allocation_blocks,
                )))
            });
        for removed_node_allocation_blocks_begin in updates.removed_nodes.iter() {
            self.tree_nodes_cache
                .get_mut()
                .prune_node_at(*removed_node_allocation_blocks_begin);
        }
        self.tree_nodes_cache
            .get_mut()
            .insert_entries_from(&mut updates.updated_tree_nodes_cache);
    }

    pub fn clear_caches(&self) {
        self.tree_nodes_cache.write().clear();
    }
}

/// Locking guard for [`InodeIndex::tree_nodes_cache`].
enum InodeIndexTreeNodeCacheGuard<'a, ST: sync_types::SyncTypes> {
    ReadGuard {
        guard: <ST::RwLock<InodeIndexTreeNodeCache> as sync_types::RwLock<InodeIndexTreeNodeCache>>::ReadGuard<'a>,
    },
    WriteGuard {
        guard: <ST::RwLock<InodeIndexTreeNodeCache> as sync_types::RwLock<InodeIndexTreeNodeCache>>::WriteGuard<'a>,
    },
}

impl<'a, ST: sync_types::SyncTypes> ops::Deref for InodeIndexTreeNodeCacheGuard<'a, ST> {
    type Target = InodeIndexTreeNodeCache;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::ReadGuard { guard } => guard,
            Self::WriteGuard { guard } => guard,
        }
    }
}

/// Entry in [`TransactionInodeIndexUpdates::tree_nodes_staged_updates`]
struct TransactionInodeIndexUpdatesStagedTreeNode {
    /// The level of the updated node.
    node_level: u32,
    /// The updated node.
    node: InodeIndexTreeNode,
}

/// State of a [`Transaction`](transaction::Transaction) specific to inode index updates.
pub struct TransactionInodeIndexUpdates {
    /// Staging area for inode index node updates.
    ///
    /// The [`Transaction`](transaction::Transaction) view of the inode index must be kept
    /// consistent at all times, even in case of e.g. failure to encrypt some node after having
    /// modified it.
    ///
    /// Nodes staged in clear in the `tree_nodes_staged_updates` take precedence over any
    /// (encrypted) data modifications recorded at the
    /// [`Transaction::auth_tree_data_blocks_update_states`](transaction::Transaction::auth_tree_data_blocks_update_states)
    /// for their resp. storage locations, which in turn take precedence over any data stored at
    /// those locations, i.e.  from before the [`Transaction`](transaction::Transaction) had been
    /// started.
    tree_nodes_staged_updates: [Option<TransactionInodeIndexUpdatesStagedTreeNode>; 5],
    /// Cache of modified nodes removed from
    /// [`tree_nodes_staged_updates`](Self::tree_nodes_staged_updates) and succesfully encrypted to
    /// [`Transaction::auth_tree_data_blocks_update_states`](transaction::Transaction::auth_tree_data_blocks_update_states).
    updated_tree_nodes_cache: InodeIndexTreeNodeCache,
    /// Locations of removed nodes.
    removed_nodes: Vec<layout::PhysicalAllocBlockIndex>,
    /// Height of the updated inode index B+-tree.
    index_tree_levels: u32,
    /// Location of th updated inode index B+-tree's root node.
    root_node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
    /// Whether or not the inode index inode pointing to the root node still needs to get updated.
    root_node_inode_needs_update: bool,
    /// Updated preauthentication CCA protection digest of the inode index entry leaf node.
    ///
    /// Empty if the inode index entry leaf node has not changed or the update node has not been
    /// removed from [`tree_nodes_staged_updates`](Self::tree_nodes_staged_updates) yet.
    entry_leaf_node_preauth_cca_protection_digest: Vec<u8>,
}

impl TransactionInodeIndexUpdates {
    pub fn new<ST: sync_types::SyncTypes>(inode_index: &InodeIndex<ST>) -> Self {
        let index_tree_levels = inode_index.index_tree_levels;
        Self {
            tree_nodes_staged_updates: array::from_fn(|_| None),
            updated_tree_nodes_cache: InodeIndexTreeNodeCache::new(&inode_index.layout, index_tree_levels),
            removed_nodes: Vec::new(),
            index_tree_levels,
            root_node_allocation_blocks_begin: inode_index.root_node_allocation_blocks_begin,
            root_node_inode_needs_update: false,
            entry_leaf_node_preauth_cca_protection_digest: Vec::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_all_tree_nodes_staged_updates<ST: sync_types::SyncTypes>(
        &mut self,
        transaction_allocs: &mut transaction::TransactionAllocations,
        transaction_updates_states: &mut transaction::AuthTreeDataBlocksUpdateStates,
        rng: &mut dyn rng::RngCoreDispatchable,
        fs_config: &CocoonFsConfig,
        fs_sync_state_alloc_bitmap: &alloc_bitmap::AllocBitmap,
        fs_sync_state_inode_index: &InodeIndex<ST>,
        fs_sync_state_keys_cache: &mut keys::KeyCacheRef<'_, ST>,
    ) -> Result<(), NvFsError> {
        for staged_update_slot in 0..self.tree_nodes_staged_updates.len() {
            self.apply_tree_node_staged_update(
                staged_update_slot,
                transaction_allocs,
                transaction_updates_states,
                rng,
                fs_config,
                fs_sync_state_alloc_bitmap,
                fs_sync_state_inode_index,
                fs_sync_state_keys_cache,
            )?;
            self.tree_nodes_staged_updates[staged_update_slot] = None;
        }
        Ok(())
    }

    pub fn get_updated_entry_leaf_node_preauth_cca_protection_digest(&self) -> Option<&[u8]> {
        (!self.entry_leaf_node_preauth_cca_protection_digest.is_empty())
            .then_some(&self.entry_leaf_node_preauth_cca_protection_digest)
    }

    pub fn clear_caches(&mut self) {
        self.updated_tree_nodes_cache.clear();
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_tree_node_staged_update<ST: sync_types::SyncTypes>(
        &mut self,
        staged_update_slot: usize,
        transaction_allocs: &mut transaction::TransactionAllocations,
        transaction_updates_states: &mut transaction::AuthTreeDataBlocksUpdateStates,
        rng: &mut dyn rng::RngCoreDispatchable,
        fs_config: &CocoonFsConfig,
        fs_sync_state_alloc_bitmap: &alloc_bitmap::AllocBitmap,
        fs_sync_state_inode_index: &InodeIndex<ST>,
        fs_sync_state_keys_cache: &mut keys::KeyCacheRef<'_, ST>,
    ) -> Result<(), NvFsError> {
        let staged_node_update = match self.tree_nodes_staged_updates[staged_update_slot].as_mut() {
            Some(staged_node_update) => staged_node_update,
            None => return Ok(()),
        };

        // If this is the entry leaf node and there's a pending update to the special
        // index tree root node inode to get written, do it now.
        let is_entry_leaf_node = if let InodeIndexTreeNode::Leaf(leaf_node) = &mut staged_node_update.node {
            let entry_leaf_node_allocation_blocks_begin = match fs_config
                .inode_index_entry_leaf_node_block_ptr
                .decode(fs_config.image_layout.allocation_block_size_128b_log2 as u32)
            {
                Ok(Some(entry_leaf_node_allocation_blocks_begin)) => entry_leaf_node_allocation_blocks_begin,
                Ok(None) => return Err(nvfs_err_internal!()),
                Err(e) => return Err(e),
            };
            if leaf_node.node_allocation_blocks_begin == entry_leaf_node_allocation_blocks_begin {
                if self.root_node_inode_needs_update {
                    Self::update_index_root_node_inode(
                        leaf_node,
                        self.root_node_allocation_blocks_begin,
                        &fs_sync_state_inode_index.layout,
                        fs_config.image_layout.index_tree_node_allocation_blocks_log2 as u32,
                    )?;
                    self.root_node_inode_needs_update = false;
                }

                true
            } else {
                false
            }
        } else {
            false
        };

        let node_range = layout::PhysicalAllocBlockRange::from((
            staged_node_update.node.node_allocation_blocks_begin(),
            layout::AllocBlockCount::from(
                1u64 << (fs_config.image_layout.index_tree_node_allocation_blocks_log2 as u32),
            ),
        ));

        let update_states_allocation_blocks_range = transaction_updates_states
            .insert_missing_in_range(
                node_range,
                fs_sync_state_alloc_bitmap,
                &transaction_allocs.pending_frees,
                None,
            )
            .map_err(|(e, _)| e)?
            .0;

        transaction_updates_states.allocate_allocation_blocks_update_staging_bufs(
            &update_states_allocation_blocks_range,
            fs_config.image_layout.allocation_block_size_128b_log2 as u32,
        )?;
        let encoded_node_buf = match &staged_node_update.node {
            InodeIndexTreeNode::Internal(internal_node) => internal_node.encoded_node.as_slice(),
            InodeIndexTreeNode::Leaf(leaf_node) => leaf_node.encoded_node.as_slice(),
        };
        if let Err(e) = fs_sync_state_inode_index
            .tree_node_encryption_instance
            .encrypt_one_block(
                transaction_updates_states
                    .iter_allocation_blocks_update_staging_bufs_mut(&update_states_allocation_blocks_range)?,
                io_slices::SingletonIoSlice::new(encoded_node_buf).map_infallible_err(),
                rng,
            )
        {
            // The Allocation Block's allocated for the Index Tree Nodes in the node update
            // staging slot will not get freed or repurposed for anything else,
            // the only way to make forward-progress for the transaction is to
            // retry eventually. Simply reset the that Allocation Block's staged
            // update states for good measure and to free up some memory now.
            transaction_updates_states.reset_allocation_blocks_staged_updates(&update_states_allocation_blocks_range);
            return Err(e);
        }

        // If this is the entry leaf node, then recompute the pre-auth CCA protection
        // digest.
        if is_entry_leaf_node {
            let preauth_cca_protection_hmac_hash_alg = fs_config.image_layout.preauth_cca_protection_hmac_hash_alg;
            if self.entry_leaf_node_preauth_cca_protection_digest.is_empty() {
                self.entry_leaf_node_preauth_cca_protection_digest =
                    try_alloc_vec(hash::hash_alg_digest_len(preauth_cca_protection_hmac_hash_alg) as usize)?;
            }

            entry_leaf_node_preautch_cca_hmac(
                &mut self.entry_leaf_node_preauth_cca_protection_digest,
                transaction_updates_states
                    .iter_allocation_blocks_update_staging_bufs_mut(&update_states_allocation_blocks_range)?,
                &fs_config.image_layout,
                &fs_config.root_key,
                fs_sync_state_keys_cache,
            )?;
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn reserve_tree_node_update_staging_slot<ST: sync_types::SyncTypes>(
        &mut self,
        tree_node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        preserved_slots_set: &[Option<usize>],
        transaction_allocs: &mut transaction::TransactionAllocations,
        transaction_updates_states: &mut transaction::AuthTreeDataBlocksUpdateStates,
        rng: &mut dyn rng::RngCoreDispatchable,
        fs_config: &CocoonFsConfig,
        fs_sync_state_alloc_bitmap: &alloc_bitmap::AllocBitmap,
        fs_sync_state_inode_index: &InodeIndex<ST>,
        fs_sync_state_keys_cache: &mut keys::KeyCacheRef<'_, ST>,
    ) -> Result<usize, NvFsError> {
        if preserved_slots_set.len() >= self.tree_nodes_staged_updates.len() {
            return Err(nvfs_err_internal!());
        }

        // If there's some occupied slot already holding the node to get inserted,
        // return that.
        if let Some(staged_update_slot) = self.tree_nodes_staged_updates.iter().position(|slot| {
            slot.as_ref()
                .map(|staged_node_update| {
                    staged_node_update.node.node_allocation_blocks_begin() == tree_node_allocation_blocks_begin
                })
                .unwrap_or(false)
        }) {
            return Ok(staged_update_slot);
        };

        // Otherwise, if there's an unoccupied slot, return that.
        if let Some(staged_update_slot) =
            self.tree_nodes_staged_updates
                .iter()
                .enumerate()
                .position(|(slot_index, slot)| {
                    slot.is_none()
                        & !preserved_slots_set.iter().any(|preserved_slot_index| {
                            preserved_slot_index
                                .as_ref()
                                .map(|preserved_slot_index| *preserved_slot_index == slot_index)
                                .unwrap_or(false)
                        })
                })
        {
            return Ok(staged_update_slot);
        };

        // Otherwise free up a slot which is not in the
        // preserved_slots_set.
        let staged_update_slot =
            match self
                .tree_nodes_staged_updates
                .iter()
                .enumerate()
                .position(|(slot_index, _slot)| {
                    !preserved_slots_set.iter().any(|preserved_slot_index| {
                        preserved_slot_index
                            .as_ref()
                            .map(|preserved_slot_index| *preserved_slot_index == slot_index)
                            .unwrap_or(false)
                    })
                }) {
                Some(staged_update_slot) => staged_update_slot,
                None => return Err(nvfs_err_internal!()),
            };

        // Encrypt the node's contents into the transaction's per-Allocation Block
        // Staged Updates buffers. Note: if that fails, the staged node update
        // slot is left as-is, and that takes precedence over everything else
        // when reading nodes. So in case of error, the metadata, from the POV
        // of the transaction, will remain intact in either case.
        self.apply_tree_node_staged_update(
            staged_update_slot,
            transaction_allocs,
            transaction_updates_states,
            rng,
            fs_config,
            fs_sync_state_alloc_bitmap,
            fs_sync_state_inode_index,
            fs_sync_state_keys_cache,
        )?;

        // Move the plaintext node from the staged update slot to the transaction's
        // index tree node cache.
        if let Some(TransactionInodeIndexUpdatesStagedTreeNode { node_level, node }) =
            self.tree_nodes_staged_updates[staged_update_slot].take()
        {
            self.updated_tree_nodes_cache.insert(node_level, node);
        }

        Ok(staged_update_slot)
    }

    fn get_tree_nodes_staged_updates_slot(
        tree_nodes_staged_updates: &[Option<TransactionInodeIndexUpdatesStagedTreeNode>; 5],
        index: usize,
    ) -> Result<&TransactionInodeIndexUpdatesStagedTreeNode, NvFsError> {
        tree_nodes_staged_updates[index]
            .as_ref()
            .ok_or_else(|| nvfs_err_internal!())
    }

    fn get_tree_nodes_staged_updates_slots_mut<const N: usize>(
        tree_nodes_staged_updates: &mut [Option<TransactionInodeIndexUpdatesStagedTreeNode>; 5],
        mut indices: [usize; N],
    ) -> Result<[&mut TransactionInodeIndexUpdatesStagedTreeNode; N], NvFsError> {
        let mut index_perm: [usize; N] = array::from_fn(|i| i);
        index_perm.sort_by(|i0, i1| indices[*i0].cmp(&indices[*i1]));
        // Afterwards, indices are sorted in ascending order and
        // index_perm contains the inverse permutation to undo the sorting.
        index_permutation::apply_and_invert_index_perm(&mut index_perm, &mut indices);
        debug_assert!(indices.is_sorted());

        let mut slots_iter = tree_nodes_staged_updates.iter_mut().enumerate();
        // array::try_from_fn() is unstable. Until that's available, extract into an
        // array of Options first, check that and unwrap afterwards.
        let mut result: [Option<&mut TransactionInodeIndexUpdatesStagedTreeNode>; N] = array::from_fn(|i| {
            let i = indices[i];
            // Clippy doesn't understand we cannot consume the slots_iter here.
            #[allow(clippy::while_let_on_iterator)]
            while let Some((slot_index, slot)) = slots_iter.next() {
                if slot_index == i {
                    return slot.as_mut();
                }
            }
            None
        });
        if result.iter().any(|node| node.is_none()) {
            return Err(nvfs_err_internal!());
        }

        let mut result: [&mut TransactionInodeIndexUpdatesStagedTreeNode; N] =
            array::from_fn(|i| result[i].take().unwrap());
        // Bring the result into the original order of the input indices.
        index_permutation::apply_index_perm(&mut index_perm, &mut result);

        Ok(result)
    }

    fn update_index_root_node_inode(
        entry_leaf_node: &mut InodeIndexTreeLeafNode,
        root_node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        layout: &InodeIndexTreeLayout,
        index_tree_node_allocation_blocks_log2: u32,
    ) -> Result<(), NvFsError> {
        let root_inode_entry_pos_in_node = match entry_leaf_node.lookup(SpecialInode::IndexRoot as u32, layout)? {
            Ok(root_inode_entry_pos_in_node) => root_inode_entry_pos_in_node,
            Err(_insertion_pos) => {
                // The index root inode must be always there.
                return Err(nvfs_err_internal!());
            }
        };
        let root_node_extent_ptr = extent_ptr::EncodedExtentPtr::encode(
            Some(&layout::PhysicalAllocBlockRange::from((
                root_node_allocation_blocks_begin,
                layout::AllocBlockCount::from(1u64 << index_tree_node_allocation_blocks_log2),
            ))),
            false,
        )?;
        entry_leaf_node.insert(
            SpecialInode::IndexRoot as u32,
            root_node_extent_ptr,
            Some(Ok(root_inode_entry_pos_in_node)),
            layout,
        )
    }
}

fn entry_leaf_node_preautch_cca_hmac<'a, ST: sync_types::SyncTypes, SI: crypto::CryptoIoSlicesIter<'a>>(
    dst: &mut [u8],
    encrypted_node_data: SI,
    image_layout: &layout::ImageLayout,
    root_key: &keys::RootKey,
    keys_cache: &mut keys::KeyCacheRef<ST>,
) -> Result<(), NvFsError> {
    let preauth_cca_protection_hmac_hash_alg = image_layout.preauth_cca_protection_hmac_hash_alg;
    if dst.len() != hash::hash_alg_digest_len(preauth_cca_protection_hmac_hash_alg) as usize {
        return Err(nvfs_err_internal!());
    }
    // For the key domain: it's the entry leaf that gets digested, not the root, so
    // beware that the naming might be misleading --
    // SpecialInode::IndexRoot is considered to represent
    // the inode index as a whole in this context here.
    let preauth_cca_protection_hmac_key = keys::KeyCache::get_key(
        keys_cache,
        root_key,
        &keys::KeyId::new(
            SpecialInode::IndexRoot as u32,
            InodeKeySubdomain::InodeData as u32,
            keys::KeyPurpose::PreAuthCcaProtectionAuthentication,
        ),
    )?;
    let mut preauth_cca_protection_hmac_instance =
        hash::HmacInstance::new(preauth_cca_protection_hmac_hash_alg, &preauth_cca_protection_hmac_key)?;

    preauth_cca_protection_hmac_instance.update(encrypted_node_data)?;

    let auth_context_subject_id_suffix = [
        0u8, // Version of the authenticated data's format.
        auth_subject_ids::AuthSubjectDataSuffix::InodeIndexNode as u8,
    ];
    let auth_context_enc_params = {
        let (block_cipher_alg_id, block_cipher_key_size) =
            <(tpm2_interface::TpmiAlgSymObject, u16)>::from(&image_layout.block_cipher_alg);
        let mut auth_context_enc_params =
            [0u8; tpm2_interface::TpmiAlgSymObject::marshalled_size() as usize + mem::size_of::<u16>()];
        let context_buf = block_cipher_alg_id
            .marshal(&mut auth_context_enc_params)
            .map_err(|_| nvfs_err_internal!())?;
        tpm2_interface::marshal_u16(context_buf, block_cipher_key_size).map_err(|_| nvfs_err_internal!())?;
        auth_context_enc_params
    };
    preauth_cca_protection_hmac_instance.update(
        io_slices::BuffersSliceIoSlicesIter::new(&[
            auth_context_enc_params.as_slice(),
            auth_context_subject_id_suffix.as_slice(),
        ])
        .map_infallible_err(),
    )?;

    preauth_cca_protection_hmac_instance.finalize_into(dst)?;
    Ok(())
}

/// Reference to an inode index tree node, possibly at the state as last modified by some pending
/// [`Transaction`](transaction::Transaction).
enum InodeIndexTreeNodeRef<'a, ST: sync_types::SyncTypes> {
    /// Owned node data.
    Owned {
        node: InodeIndexTreeNode,
        is_modified_by_transaction: bool,
    },
    /// Reference to an entry in [`InodeIndex::tree_nodes_cache`]
    CacheEntryRef {
        cache_guard: InodeIndexTreeNodeCacheGuard<'a, ST>,
        cache_entry_index: InodeIndexTreeNodeCacheIndex,
    },
    /// Reference to an entry in [`TransactionInodeIndexUpdates::tree_nodes_staged_updates`].
    TransactionStagedUpdatesNodeRef {
        transaction: Box<transaction::Transaction>,
        nodes_staged_updates_slot_index: usize,
    },
    /// Reference to an entry in [`TransactionInodeIndexUpdates::updated_tree_nodes_cache`].
    TransactionUpdatedNodesCacheEntryRef {
        transaction: Box<transaction::Transaction>,
        cache_entry_index: InodeIndexTreeNodeCacheIndex,
    },
}

impl<'a, ST: sync_types::SyncTypes> InodeIndexTreeNodeRef<'a, ST> {
    fn get_node(&self) -> Result<&InodeIndexTreeNode, NvFsError> {
        match self {
            Self::Owned {
                node,
                is_modified_by_transaction: _,
            } => Ok(node),
            Self::CacheEntryRef {
                cache_guard,
                cache_entry_index,
            } => Ok(cache_guard.get_entry_node(*cache_entry_index)),
            Self::TransactionStagedUpdatesNodeRef {
                transaction,
                nodes_staged_updates_slot_index,
            } => transaction.inode_index_updates.tree_nodes_staged_updates[*nodes_staged_updates_slot_index]
                .as_ref()
                .map(|staged_node| &staged_node.node)
                .ok_or_else(|| nvfs_err_internal!()),
            Self::TransactionUpdatedNodesCacheEntryRef {
                transaction,
                cache_entry_index,
            } => Ok(transaction
                .inode_index_updates
                .updated_tree_nodes_cache
                .get_entry_node(*cache_entry_index)),
        }
    }

    fn into_transaction(self) -> Option<Box<transaction::Transaction>> {
        match self {
            Self::Owned { .. } | Self::CacheEntryRef { .. } => None,
            Self::TransactionStagedUpdatesNodeRef { transaction, .. }
            | Self::TransactionUpdatedNodesCacheEntryRef { transaction, .. } => Some(transaction),
        }
    }
}

/// Read, authenticate and decrypt an inode index B+-tree node, possibly at the state as last
/// modified by some pending [`Transaction`](transaction::Transaction).
struct InodeIndexReadTreeNodeFuture<C: chip::NvChip> {
    fut_state: InodeIndexReadTreeNodeFutureState<C>,
    node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
    expected_node_level: Option<u32>,
    encoded_node_buf: Vec<u8>,
    read_for_update: bool,
}

enum InodeIndexReadTreeNodeFutureState<C: chip::NvChip> {
    Init {
        transaction: Option<Box<transaction::Transaction>>,
    },
    ReadNodeCommitted {
        returned_transaction: Option<Box<transaction::Transaction>>,
        read_fut: BufferedReadAuthenticateDataFuture<C>,
    },
    ReadNodeUncommitted {
        update_states_allocation_blocks_range: AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        read_fut: TransactionReadAuthenticateDataFuture<C>,
    },
    DecryptNode {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        encrypted_node: Option<ReadAuthenticateExtentFutureResult>,
        is_modified_by_transaction: bool,
    },
    Done,
}

impl<C: chip::NvChip> InodeIndexReadTreeNodeFuture<C> {
    fn new(
        transaction: Option<Box<transaction::Transaction>>,
        node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        expected_node_level: Option<u32>,
        read_for_update: bool,
    ) -> Self {
        Self {
            fut_state: InodeIndexReadTreeNodeFutureState::Init { transaction },
            node_allocation_blocks_begin,
            expected_node_level,
            encoded_node_buf: Vec::new(),
            read_for_update,
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    fn poll<'a, ST: sync_types::SyncTypes>(
        self: pin::Pin<&mut Self>,
        chip: &C,
        fs_config: &CocoonFsConfig,
        fs_sync_state_alloc_bitmap: &alloc_bitmap::AllocBitmap,
        fs_sync_state_auth_tree: &mut auth_tree::AuthTreeRef<'_, ST>,
        fs_sync_state_inode_index_tree_layout: &InodeIndexTreeLayout,
        fs_sync_state_inode_index_tree_nodes_cache: &'a ST::RwLock<InodeIndexTreeNodeCache>,
        fs_sync_state_inode_index_tree_node_decryption_instance: &encryption_entities::EncryptedBlockDecryptionInstance,
        fs_sync_state_read_buffer: &read_buffer::ReadBuffer<ST>,
        cx: &mut core::task::Context<'_>,
    ) -> task::Poll<(
        Option<Box<transaction::Transaction>>,
        Result<InodeIndexTreeNodeRef<'a, ST>, NvFsError>,
    )> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                InodeIndexReadTreeNodeFutureState::Init {
                    transaction: fut_transaction,
                } => {
                    let node_allocation_blocks_begin = this.node_allocation_blocks_begin;
                    let expected_node_level = this.expected_node_level;
                    let image_layout = &fs_config.image_layout;
                    let node_range = layout::PhysicalAllocBlockRange::from((
                        node_allocation_blocks_begin,
                        layout::AllocBlockCount::from(
                            1u64 << (image_layout.index_tree_node_allocation_blocks_log2 as u32),
                        ),
                    ));

                    if let Some(mut transaction) = fut_transaction.take() {
                        // If the node is among the nodes staged for update from the supplied
                        // transaction, then return a reference to that.
                        for (nodes_staged_updates_slot_index, nodes_staged_updates_slot) in transaction
                            .inode_index_updates
                            .tree_nodes_staged_updates
                            .iter()
                            .enumerate()
                        {
                            if let Some(entry) = nodes_staged_updates_slot.as_ref() {
                                if entry.node.node_allocation_blocks_begin() == node_allocation_blocks_begin {
                                    // Check that the node level matches expectations.
                                    if expected_node_level
                                        .map(|expected_node_level| entry.node_level != expected_node_level)
                                        .unwrap_or(false)
                                    {
                                        this.fut_state = InodeIndexReadTreeNodeFutureState::Done;
                                        return task::Poll::Ready((
                                            Some(transaction),
                                            Err(NvFsError::from(CocoonFsFormatError::InvalidIndexNode)),
                                        ));
                                    }
                                    return task::Poll::Ready((
                                        None,
                                        Ok(InodeIndexTreeNodeRef::TransactionStagedUpdatesNodeRef {
                                            transaction,
                                            nodes_staged_updates_slot_index,
                                        }),
                                    ));
                                }
                            }
                        }

                        // Otherwise, if the node is among the supplied transaction's cached updated
                        // nodes, return a reference to that.
                        if let Some(cache_entry_index) = transaction
                            .inode_index_updates
                            .updated_tree_nodes_cache
                            .lookup(node_allocation_blocks_begin, expected_node_level)
                        {
                            // Check that the node level matches expectations.
                            if expected_node_level
                                .map(|expected_node_level| {
                                    transaction
                                        .inode_index_updates
                                        .updated_tree_nodes_cache
                                        .get_entry_node_level(cache_entry_index)
                                        != expected_node_level
                                })
                                .unwrap_or(false)
                            {
                                this.fut_state = InodeIndexReadTreeNodeFutureState::Done;
                                return task::Poll::Ready((
                                    Some(transaction),
                                    Err(NvFsError::from(CocoonFsFormatError::InvalidIndexNode)),
                                ));
                            }
                            if this.read_for_update {
                                // The transaction wants to modify a node which is in its
                                // cache. Remove the node from the cache and return it as owned.
                                let node = transaction
                                    .inode_index_updates
                                    .updated_tree_nodes_cache
                                    .remove(cache_entry_index);
                                this.fut_state = InodeIndexReadTreeNodeFutureState::Done;
                                return task::Poll::Ready((
                                    Some(transaction),
                                    Ok(InodeIndexTreeNodeRef::Owned {
                                        node,
                                        is_modified_by_transaction: true,
                                    }),
                                ));
                            } else {
                                this.fut_state = InodeIndexReadTreeNodeFutureState::Done;
                                return task::Poll::Ready((
                                    None,
                                    Ok(InodeIndexTreeNodeRef::TransactionUpdatedNodesCacheEntryRef {
                                        transaction,
                                        cache_entry_index,
                                    }),
                                ));
                            }
                        }

                        // Otherwise, if the node is within a storage area updated by the supplied
                        // transaction (meaning the node has been modified, but is not in any of the
                        // caches), then read from there.
                        let transaction_update_states = &transaction.auth_tree_data_blocks_update_states;
                        if let Ok(update_states_allocation_blocks_range) =
                            transaction_update_states.lookup_allocation_blocks_update_states_index_range(&node_range)
                        {
                            let all_allocation_block_update_states_present = transaction_update_states
                                .is_contiguous_allocation_blocks_region(&update_states_allocation_blocks_range);
                            let mut any_has_modified_data = false;
                            let mut all_have_modified_data = all_allocation_block_update_states_present;
                            let mut all_have_data_loaded = all_allocation_block_update_states_present;
                            let mut all_loaded_data_is_authenticated = true;
                            for allocation_block_update_state in transaction_update_states
                                .iter_allocation_blocks(Some(&update_states_allocation_blocks_range))
                            {
                                let has_modified_data = allocation_block_update_state.1.has_modified_data();
                                any_has_modified_data |= has_modified_data;
                                all_have_modified_data &= has_modified_data;
                                match allocation_block_update_state.1.has_encrypted_data_loaded() {
                                    Some(loaded_encrypted_data_is_authenticated) => {
                                        all_loaded_data_is_authenticated &= loaded_encrypted_data_is_authenticated;
                                    }
                                    None => {
                                        all_have_data_loaded = false;
                                    }
                                }
                            }

                            // If any Allocation Block had been modified, then all should be.
                            if any_has_modified_data != all_have_modified_data {
                                this.fut_state = InodeIndexReadTreeNodeFutureState::Done;
                                return task::Poll::Ready((Some(transaction), Err(nvfs_err_internal!())));
                            } else if all_have_data_loaded && all_loaded_data_is_authenticated {
                                this.fut_state = InodeIndexReadTreeNodeFutureState::DecryptNode {
                                    encrypted_node: Some(
                                        ReadAuthenticateExtentFutureResult::PendingTransactionUpdatesRef {
                                            transaction,
                                            update_states_allocation_blocks_range,
                                        },
                                    ),
                                    is_modified_by_transaction: true,
                                };
                                continue;
                            } else if any_has_modified_data {
                                let read_fut = TransactionReadAuthenticateDataFuture::new(
                                    transaction,
                                    &update_states_allocation_blocks_range,
                                    true,
                                    true,
                                );
                                this.fut_state = InodeIndexReadTreeNodeFutureState::ReadNodeUncommitted {
                                    update_states_allocation_blocks_range,
                                    read_fut,
                                };
                                continue;
                            }
                        }

                        // Return the transaction back and continue with reading from committed data
                        // instead.
                        *fut_transaction = Some(transaction);
                    }

                    // Try the shared cache of (unmodified) index tree nodes.
                    // If the node is to be cloned, allocate a suitable buffer before taking the
                    // cache lock.
                    if this.read_for_update {
                        let tree_layout = fs_sync_state_inode_index_tree_layout;
                        this.encoded_node_buf = match try_alloc_vec(tree_layout.encoded_node_len) {
                            Ok(encoded_node_buf) => encoded_node_buf,
                            Err(e) => {
                                let transaction = fut_transaction.take();
                                this.fut_state = InodeIndexReadTreeNodeFutureState::Done;
                                return task::Poll::Ready((transaction, Err(NvFsError::from(e))));
                            }
                        };
                    }

                    let nodes_cache_guard = fs_sync_state_inode_index_tree_nodes_cache.read();
                    if let Some(cache_entry_index) =
                        nodes_cache_guard.lookup(node_allocation_blocks_begin, expected_node_level)
                    {
                        // Check that the node level matches expectations.
                        if expected_node_level
                            .map(|expected_node_level| {
                                nodes_cache_guard.get_entry_node_level(cache_entry_index) != expected_node_level
                            })
                            .unwrap_or(false)
                        {
                            let transaction = fut_transaction.take();
                            this.fut_state = InodeIndexReadTreeNodeFutureState::Done;
                            return task::Poll::Ready((
                                transaction,
                                Err(NvFsError::from(CocoonFsFormatError::InvalidIndexNode)),
                            ));
                        }
                        if this.read_for_update {
                            let node = nodes_cache_guard
                                .get_entry_node(cache_entry_index)
                                .clone_with_preallocated_buf(mem::take(&mut this.encoded_node_buf));
                            let transaction = fut_transaction.take();
                            this.fut_state = InodeIndexReadTreeNodeFutureState::Done;
                            return task::Poll::Ready((
                                transaction,
                                Ok(InodeIndexTreeNodeRef::Owned {
                                    node,
                                    is_modified_by_transaction: false,
                                }),
                            ));
                        } else {
                            let transaction = fut_transaction.take();
                            this.fut_state = InodeIndexReadTreeNodeFutureState::Done;
                            return task::Poll::Ready((
                                transaction,
                                Ok(InodeIndexTreeNodeRef::CacheEntryRef {
                                    cache_guard: InodeIndexTreeNodeCacheGuard::ReadGuard {
                                        guard: nodes_cache_guard,
                                    },
                                    cache_entry_index,
                                }),
                            ));
                        }
                    }
                    drop(nodes_cache_guard);

                    // Otherwise read the node from storage.
                    let read_fut = match BufferedReadAuthenticateDataFuture::new(
                        &node_range,
                        &fs_config.image_layout,
                        fs_sync_state_auth_tree.get_config(),
                        chip,
                    ) {
                        Ok(read_fut) => read_fut,
                        Err(e) => {
                            let transaction = fut_transaction.take();
                            this.fut_state = InodeIndexReadTreeNodeFutureState::Done;
                            return task::Poll::Ready((transaction, Err(e)));
                        }
                    };
                    this.fut_state = InodeIndexReadTreeNodeFutureState::ReadNodeCommitted {
                        returned_transaction: fut_transaction.take(),
                        read_fut,
                    };
                }
                InodeIndexReadTreeNodeFutureState::ReadNodeCommitted {
                    returned_transaction,
                    read_fut,
                } => {
                    match BufferedReadAuthenticateDataFuture::poll(
                        pin::Pin::new(read_fut),
                        chip,
                        &fs_config.image_layout,
                        fs_config.image_header_end,
                        fs_sync_state_alloc_bitmap,
                        fs_sync_state_auth_tree,
                        fs_sync_state_read_buffer,
                        cx,
                    ) {
                        task::Poll::Ready(Ok(allocation_blocks_bufs)) => {
                            let returned_transaction = returned_transaction.take();
                            this.fut_state = InodeIndexReadTreeNodeFutureState::DecryptNode {
                                encrypted_node: Some(ReadAuthenticateExtentFutureResult::Owned {
                                    returned_transaction,
                                    allocation_blocks_bufs,
                                }),
                                is_modified_by_transaction: false,
                            };
                        }
                        task::Poll::Ready(Err(e)) => {
                            let returned_transaction = returned_transaction.take();
                            this.fut_state = InodeIndexReadTreeNodeFutureState::Done;
                            return task::Poll::Ready((returned_transaction, Err(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    }
                }
                InodeIndexReadTreeNodeFutureState::ReadNodeUncommitted {
                    update_states_allocation_blocks_range,
                    read_fut,
                } => {
                    match TransactionReadAuthenticateDataFuture::poll(
                        pin::Pin::new(read_fut),
                        chip,
                        fs_config,
                        fs_sync_state_alloc_bitmap,
                        fs_sync_state_auth_tree,
                        cx,
                    ) {
                        task::Poll::Ready(Ok((
                            transaction,
                            update_states_allocation_blocks_range_index_offsets,
                            result,
                        ))) => {
                            let mut update_states_allocation_blocks_range =
                                update_states_allocation_blocks_range.clone();

                            if let Err(e) = result {
                                this.fut_state = InodeIndexReadTreeNodeFutureState::Done;
                                return task::Poll::Ready((Some(transaction), Err(e)));
                            }

                            if let Some(update_states_allocation_blocks_range_index_offsets) =
                                update_states_allocation_blocks_range_index_offsets
                            {
                                update_states_allocation_blocks_range = update_states_allocation_blocks_range
                                    .apply_states_insertions_offsets(
                                        update_states_allocation_blocks_range_index_offsets
                                            .inserted_states_before_range_count,
                                        update_states_allocation_blocks_range_index_offsets
                                            .inserted_states_within_range_count,
                                    );
                            }

                            this.fut_state = InodeIndexReadTreeNodeFutureState::DecryptNode {
                                encrypted_node: Some(
                                    ReadAuthenticateExtentFutureResult::PendingTransactionUpdatesRef {
                                        transaction,
                                        update_states_allocation_blocks_range,
                                    },
                                ),
                                is_modified_by_transaction: true,
                            };
                        }
                        task::Poll::Ready(Err(e)) => {
                            this.fut_state = InodeIndexReadTreeNodeFutureState::Done;
                            return task::Poll::Ready((None, Err(e)));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    }
                }
                InodeIndexReadTreeNodeFutureState::DecryptNode {
                    encrypted_node,
                    is_modified_by_transaction,
                } => {
                    let encrypted_node = match encrypted_node.take() {
                        Some(encrypted_node) => encrypted_node,
                        None => {
                            this.fut_state = InodeIndexReadTreeNodeFutureState::Done;
                            return task::Poll::Ready((None, Err(nvfs_err_internal!())));
                        }
                    };
                    let is_modified_by_transaction = *is_modified_by_transaction;
                    this.fut_state = InodeIndexReadTreeNodeFutureState::Done;

                    // Allocate the decryption target buffer if that has not happened yet.
                    let tree_layout = fs_sync_state_inode_index_tree_layout;
                    let mut encoded_node_buf = mem::take(&mut this.encoded_node_buf);
                    if encoded_node_buf.is_empty() {
                        encoded_node_buf = match try_alloc_vec(tree_layout.encoded_node_len) {
                            Ok(encoded_node_buf) => encoded_node_buf,
                            Err(e) => {
                                let transaction = encrypted_node.into_transaction();
                                return task::Poll::Ready((transaction, Err(NvFsError::from(e))));
                            }
                        };
                    }
                    if let Err(e) = fs_sync_state_inode_index_tree_node_decryption_instance.decrypt_one_block(
                        io_slices::SingletonIoSliceMut::new(&mut encoded_node_buf).map_infallible_err(),
                        io_slices::GenericIoSlicesIter::new(encrypted_node.iter_allocation_blocks_bufs(), None),
                    ) {
                        return task::Poll::Ready((encrypted_node.into_transaction(), Err(e)));
                    }

                    let transaction = encrypted_node.into_transaction();
                    let node = match InodeIndexTreeNode::decode(
                        this.node_allocation_blocks_begin,
                        encoded_node_buf,
                        tree_layout,
                    ) {
                        Ok(node) => node,
                        Err(e) => {
                            return task::Poll::Ready((transaction, Err(e)));
                        }
                    };

                    let node_level = match &node {
                        InodeIndexTreeNode::Internal(internal_node) => match internal_node.node_level(tree_layout) {
                            Ok(node_level) => node_level,
                            Err(e) => return task::Poll::Ready((transaction, Err(e))),
                        },
                        InodeIndexTreeNode::Leaf(_) => 0,
                    };
                    if this
                        .expected_node_level
                        .map(|expected_node_level| node_level != expected_node_level)
                        .unwrap_or(false)
                    {
                        return task::Poll::Ready((
                            transaction,
                            Err(NvFsError::from(CocoonFsFormatError::InvalidIndexNode)),
                        ));
                    }

                    return task::Poll::Ready(if !this.read_for_update {
                        if is_modified_by_transaction {
                            let mut transaction = match transaction {
                                Some(transaction) => transaction,
                                None => {
                                    return task::Poll::Ready((None, Err(nvfs_err_internal!())));
                                }
                            };
                            match transaction
                                .inode_index_updates
                                .updated_tree_nodes_cache
                                .insert(node_level, node)
                            {
                                InodeIndexTreeNodeCacheInsertionResult::Inserted { index } => (
                                    None,
                                    Ok(InodeIndexTreeNodeRef::TransactionUpdatedNodesCacheEntryRef {
                                        transaction,
                                        cache_entry_index: index,
                                    }),
                                ),
                                InodeIndexTreeNodeCacheInsertionResult::Uncacheable { node } => (
                                    Some(transaction),
                                    Ok(InodeIndexTreeNodeRef::Owned {
                                        node,
                                        is_modified_by_transaction,
                                    }),
                                ),
                            }
                        } else {
                            let mut nodes_cache_guard = fs_sync_state_inode_index_tree_nodes_cache.write();
                            match nodes_cache_guard.insert(node_level, node) {
                                InodeIndexTreeNodeCacheInsertionResult::Inserted { index } => (
                                    transaction,
                                    Ok(InodeIndexTreeNodeRef::CacheEntryRef {
                                        cache_guard: InodeIndexTreeNodeCacheGuard::WriteGuard {
                                            guard: nodes_cache_guard,
                                        },
                                        cache_entry_index: index,
                                    }),
                                ),
                                InodeIndexTreeNodeCacheInsertionResult::Uncacheable { node } => (
                                    transaction,
                                    Ok(InodeIndexTreeNodeRef::Owned {
                                        node,
                                        is_modified_by_transaction,
                                    }),
                                ),
                            }
                        }
                    } else {
                        (
                            transaction,
                            Ok(InodeIndexTreeNodeRef::Owned {
                                node,
                                is_modified_by_transaction,
                            }),
                        )
                    });
                }
                InodeIndexReadTreeNodeFutureState::Done => unreachable!(),
            }
        }
    }
}

/// Lookup some inode in the inode index, possibly at the state as last modified by some
/// [`Transaction`](transaction::Transaction).
pub struct InodeIndexLookupFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    inode: InodeIndexKeyType,
    fut_state: InodeIndexLookupFutureState<C>,
    _phantom: marker::PhantomData<fn() -> *const ST>,
}

#[allow(clippy::large_enum_variant)]
enum InodeIndexLookupFutureState<C: chip::NvChip> {
    Init {
        transaction: Option<Box<transaction::Transaction>>,
    },
    ReadTreeNode {
        read_fut: InodeIndexReadTreeNodeFuture<C>,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> InodeIndexLookupFuture<ST, C> {
    pub fn new(transaction: Option<Box<transaction::Transaction>>, inode: InodeIndexKeyType) -> Self {
        Self {
            inode,
            fut_state: InodeIndexLookupFutureState::Init { transaction },
            _phantom: marker::PhantomData,
        }
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsSyncStateReadFuture<ST, C> for InodeIndexLookupFuture<ST, C> {
    type Output = (
        Option<Box<transaction::Transaction>>,
        Result<Option<extent_ptr::EncodedExtentPtr>, NvFsError>,
    );

    type AuxPollData<'a> = ();

    fn poll(
        self: pin::Pin<&mut Self>,
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, C>,
        _aux_data: &mut Self::AuxPollData<'_>,
        cx: &mut core::task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        let (
            fs_instance,
            _fs_sync_state_image_size,
            fs_sync_state_alloc_bitmap,
            _fs_sync_state_alloc_bitmap_file,
            mut fs_sync_state_auth_tree,
            fs_sync_state_inode_index,
            fs_sync_state_read_buffer,
            _fs_sync_state_keys_cache,
        ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();

        let (returned_transaction, e) = loop {
            match &mut this.fut_state {
                InodeIndexLookupFutureState::Init { transaction } => {
                    let (root_node_allocation_blocks_begin, root_node_level) = match transaction.as_ref() {
                        Some(transaction) => (
                            transaction.inode_index_updates.root_node_allocation_blocks_begin,
                            transaction.inode_index_updates.index_tree_levels - 1,
                        ),
                        None => (
                            fs_sync_state_inode_index.root_node_allocation_blocks_begin,
                            fs_sync_state_inode_index.index_tree_levels - 1,
                        ),
                    };
                    let read_fut = InodeIndexReadTreeNodeFuture::new(
                        transaction.take(),
                        root_node_allocation_blocks_begin,
                        Some(root_node_level),
                        false,
                    );
                    this.fut_state = InodeIndexLookupFutureState::ReadTreeNode { read_fut };
                }
                InodeIndexLookupFutureState::ReadTreeNode { read_fut } => {
                    let (returned_transaction, node_ref) = match InodeIndexReadTreeNodeFuture::poll(
                        pin::Pin::new(read_fut),
                        &fs_instance.chip,
                        &fs_instance.fs_config,
                        fs_sync_state_alloc_bitmap,
                        &mut fs_sync_state_auth_tree,
                        &fs_sync_state_inode_index.layout,
                        &fs_sync_state_inode_index.tree_nodes_cache,
                        &fs_sync_state_inode_index.tree_node_decryption_instance,
                        fs_sync_state_read_buffer,
                        cx,
                    ) {
                        task::Poll::Ready((returned_transaction, Ok(node_ref))) => (returned_transaction, node_ref),
                        task::Poll::Ready((returned_transaction, Err(e))) => {
                            break (returned_transaction, e);
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    match node_ref.get_node() {
                        Ok(InodeIndexTreeNode::Internal(internal_node)) => {
                            let tree_layout = &fs_sync_state_inode_index.layout;
                            let node_level = match internal_node.node_level(tree_layout) {
                                Ok(node_level) => node_level,
                                Err(e) => break (returned_transaction.or(node_ref.into_transaction()), e),
                            };

                            let next_child_index = match internal_node.lookup_child(this.inode, tree_layout) {
                                Ok(next_child_index) => next_child_index,
                                Err(e) => {
                                    break (returned_transaction.or(node_ref.into_transaction()), e);
                                }
                            };

                            let next_child_ptr = match internal_node.entry_child_ptr(next_child_index, tree_layout) {
                                Ok(next_child_ptr) => next_child_ptr,
                                Err(e) => {
                                    break (returned_transaction.or(node_ref.into_transaction()), e);
                                }
                            };

                            let transaction = returned_transaction.or(node_ref.into_transaction());

                            let next_child_node_allocation_blocks_begin = match next_child_ptr.decode(
                                tree_layout
                                    .node_encrypted_block_layout
                                    .get_allocation_block_size_128b_log2() as u32,
                            ) {
                                Ok(next_child_node_allocation_blocks_begin) => {
                                    match next_child_node_allocation_blocks_begin {
                                        Some(next_child_node_allocation_blocks_begin) => {
                                            next_child_node_allocation_blocks_begin
                                        }
                                        None => {
                                            break (
                                                transaction,
                                                NvFsError::from(CocoonFsFormatError::InvalidIndexNode),
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    break (transaction, e);
                                }
                            };

                            let next_child_node_level = node_level - 1;
                            let read_fut = InodeIndexReadTreeNodeFuture::new(
                                transaction,
                                next_child_node_allocation_blocks_begin,
                                Some(next_child_node_level),
                                false,
                            );
                            this.fut_state = InodeIndexLookupFutureState::ReadTreeNode { read_fut };
                        }
                        Ok(InodeIndexTreeNode::Leaf(leaf_node)) => {
                            let tree_layout = &fs_sync_state_inode_index.layout;
                            let entry_index = match leaf_node.lookup(this.inode, tree_layout) {
                                Ok(entry_index) => entry_index,
                                Err(e) => {
                                    break (returned_transaction.or(node_ref.into_transaction()), e);
                                }
                            };
                            let entry_extent_ptr = match entry_index {
                                Ok(entry_index) => match leaf_node.encoded_entry_extent_ptr(entry_index, tree_layout) {
                                    Ok(entry_extent_ptr) => Some(EncodedExtentPtr::from(*entry_extent_ptr)),
                                    Err(e) => {
                                        break (returned_transaction.or(node_ref.into_transaction()), e);
                                    }
                                },
                                Err(_) => None,
                            };

                            // Done, return the result.
                            this.fut_state = InodeIndexLookupFutureState::Done;
                            return task::Poll::Ready((
                                returned_transaction.or(node_ref.into_transaction()),
                                Ok(entry_extent_ptr),
                            ));
                        }
                        Err(e) => {
                            break (returned_transaction.or(node_ref.into_transaction()), e);
                        }
                    }
                }
                InodeIndexLookupFutureState::Done => unreachable!(),
            }
        };

        this.fut_state = InodeIndexLookupFutureState::Done;
        task::Poll::Ready((returned_transaction, Err(e)))
    }
}

/// Cursor for enumerating inodes within a specified range in the inode index, possibly at the state
/// as last modified by some [`Transaction`](transaction::Transaction).
pub struct InodeIndexEnumerateCursor<ST: sync_types::SyncTypes, C: chip::NvChip> {
    inodes_enumerate_range: ops::RangeInclusive<InodeIndexKeyType>,
    transaction: Option<Box<transaction::Transaction>>,
    tree_position: Option<InodeIndexEnumerateCursorTreePosition>,
    at_end: bool,
    _phantom: marker::PhantomData<fn() -> (ST, C)>,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> InodeIndexEnumerateCursor<ST, C> {
    pub fn new(
        transaction: Option<Box<transaction::Transaction>>,
        inodes_enumer_range: ops::RangeInclusive<InodeIndexKeyType>,
    ) -> Result<Box<Self>, (Option<Box<transaction::Transaction>>, NvFsError)> {
        let inodes_enumerate_range = ops::RangeInclusive::new(
            (*inodes_enumer_range.start()).max(SPECIAL_INODE_MAX),
            *inodes_enumer_range.end(),
        );

        let mut cursor = match box_try_new(Self {
            inodes_enumerate_range,
            transaction: None,
            tree_position: None,
            at_end: false,
            _phantom: marker::PhantomData,
        }) {
            Ok(cursor) => cursor,
            Err(e) => {
                return Err((transaction, NvFsError::from(e)));
            }
        };
        cursor.transaction = transaction;

        Ok(cursor)
    }

    pub fn into_transaction(self) -> Option<Box<transaction::Transaction>> {
        self.transaction
    }

    pub fn next(self: Box<Self>) -> InodeIndexEnumerateCursorNextFuture<ST, C> {
        InodeIndexEnumerateCursorNextFuture {
            fut_state: InodeIndexEnumerateCursorNextFutureState::Init { cursor: Some(self) },
        }
    }

    pub fn read_inode_data(self: Box<Self>) -> InodeIndexEnumerateCursorReadInodeDataFuture<ST, C> {
        debug_assert!(self.tree_position.is_some());
        InodeIndexEnumerateCursorReadInodeDataFuture {
            fut_state: InodeIndexEnumerateCursorReadInodeDataFutureState::Init { cursor: Some(self) },
        }
    }
}

struct InodeIndexEnumerateCursorTreePosition {
    leaf_node: InodeIndexTreeNodeRefForUpdate,
    entry_index_in_leaf_node: usize,
}

impl InodeIndexEnumerateCursorTreePosition {
    fn get_leaf_node<'a>(
        &'a self,
        transaction: Option<&'a transaction::Transaction>,
    ) -> Result<&'a InodeIndexTreeNode, NvFsError> {
        match transaction {
            Some(transaction) => self.leaf_node.get_node(transaction),
            None => match &self.leaf_node {
                InodeIndexTreeNodeRefForUpdate::Owned { node, .. } => Ok(node),
                InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef { .. } => {
                    // If there's no transaction to begin with, the node reference cannot refer to
                    // some update staged in one.
                    Err(nvfs_err_internal!())
                }
            },
        }
    }
}

/// Advance an [`InodeIndexEnumerateCursor`].
pub struct InodeIndexEnumerateCursorNextFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    fut_state: InodeIndexEnumerateCursorNextFutureState<ST, C>,
}

enum InodeIndexEnumerateCursorNextFutureState<ST: sync_types::SyncTypes, C: chip::NvChip> {
    Init {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        cursor: Option<Box<InodeIndexEnumerateCursor<ST, C>>>,
    },
    LookupNextInodeWalkReadTreeNode {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self. Has its transaction moved temporarily into read_fut.
        cursor: Option<Box<InodeIndexEnumerateCursor<ST, C>>>,
        next_inode: InodeIndexKeyType,
        read_fut: InodeIndexReadTreeNodeFuture<C>,
    },
    ReadNextTreeLeafNode {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.  Has its transaction moved temporarily into read_fut.
        cursor: Option<Box<InodeIndexEnumerateCursor<ST, C>>>,
        read_fut: InodeIndexReadTreeNodeFuture<C>,
    },
    InodesRangeExhausted {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        cursor: Option<Box<InodeIndexEnumerateCursor<ST, C>>>,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsSyncStateReadFuture<ST, C>
    for InodeIndexEnumerateCursorNextFuture<ST, C>
{
    type Output = Result<
        (
            Box<InodeIndexEnumerateCursor<ST, C>>,
            Result<Option<InodeIndexKeyType>, NvFsError>,
        ),
        NvFsError,
    >;

    type AuxPollData<'a> = ();

    fn poll<'a>(
        self: pin::Pin<&mut Self>,
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, C>,
        _aux_data: &mut Self::AuxPollData<'a>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        let (cursor, transaction, e) = loop {
            match &mut this.fut_state {
                InodeIndexEnumerateCursorNextFutureState::Init { cursor } => {
                    let mut cursor = match cursor.take() {
                        Some(cursor) => cursor,
                        None => break (None, None, nvfs_err_internal!()),
                    };

                    let tree_layout = &fs_instance_sync_state.inode_index.layout;
                    match &mut cursor.tree_position {
                        None => {
                            // First time to retrieve the next inode on this cursor.
                            debug_assert!(!cursor.at_end);
                            if cursor.inodes_enumerate_range.is_empty() {
                                this.fut_state = InodeIndexEnumerateCursorNextFutureState::InodesRangeExhausted {
                                    cursor: Some(cursor),
                                };
                                continue;
                            }
                            let (root_node_allocation_blocks_begin, root_node_level) = cursor
                                .transaction
                                .as_ref()
                                .map(|transaction| {
                                    (
                                        transaction.inode_index_updates.root_node_allocation_blocks_begin,
                                        transaction.inode_index_updates.index_tree_levels - 1,
                                    )
                                })
                                .unwrap_or((
                                    fs_instance_sync_state.inode_index.root_node_allocation_blocks_begin,
                                    fs_instance_sync_state.inode_index.index_tree_levels - 1,
                                ));
                            let read_fut = InodeIndexReadTreeNodeFuture::new(
                                cursor.transaction.take(),
                                root_node_allocation_blocks_begin,
                                Some(root_node_level),
                                root_node_level == 0,
                            );
                            let next_inode = *cursor.inodes_enumerate_range.start();
                            this.fut_state =
                                InodeIndexEnumerateCursorNextFutureState::LookupNextInodeWalkReadTreeNode {
                                    cursor: Some(cursor),
                                    next_inode,
                                    read_fut,
                                };
                        }
                        Some(tree_position) => {
                            if cursor.at_end {
                                // Don't even bother with potentially reading another index tree node.
                                this.fut_state = InodeIndexEnumerateCursorNextFutureState::InodesRangeExhausted {
                                    cursor: Some(cursor),
                                };
                                continue;
                            }

                            tree_position.entry_index_in_leaf_node += 1;

                            let leaf_node = match tree_position.get_leaf_node(cursor.transaction.as_deref()) {
                                Ok(InodeIndexTreeNode::Leaf(leaf_node)) => leaf_node,
                                Ok(InodeIndexTreeNode::Internal(_)) => {
                                    break (Some(cursor), None, nvfs_err_internal!())
                                }
                                Err(e) => break (Some(cursor), None, e),
                            };

                            if tree_position.entry_index_in_leaf_node < leaf_node.entries {
                                let inode = match leaf_node.entry_inode(
                                    tree_position.entry_index_in_leaf_node,
                                    &fs_instance_sync_state.inode_index.layout,
                                ) {
                                    Ok(inode) => inode,
                                    Err(e) => break (Some(cursor), None, e),
                                };
                                if inode > *cursor.inodes_enumerate_range.end() {
                                    this.fut_state = InodeIndexEnumerateCursorNextFutureState::InodesRangeExhausted {
                                        cursor: Some(cursor),
                                    };
                                    continue;
                                }
                                if inode == *cursor.inodes_enumerate_range.end() {
                                    cursor.at_end = true;
                                }
                                this.fut_state = InodeIndexEnumerateCursorNextFutureState::Done;
                                return task::Poll::Ready(Ok((cursor, Ok(Some(inode)))));
                            }

                            // The current leaf node has been exhausted, move to the next one, if
                            // any.
                            let next_leaf_node_allocation_blocks_begin = match leaf_node
                                .encoded_next_leaf_node_ptr(&fs_instance_sync_state.inode_index.layout)
                                .and_then(|next_leaf_ptr| {
                                    EncodedBlockPtr::from(*next_leaf_ptr).decode(
                                        tree_layout
                                            .node_encrypted_block_layout
                                            .get_allocation_block_size_128b_log2()
                                            as u32,
                                    )
                                }) {
                                Ok(next_leaf_node_allocation_blocks_begin) => next_leaf_node_allocation_blocks_begin,
                                Err(e) => break (Some(cursor), None, e),
                            };
                            let next_leaf_node_allocation_blocks_begin = match next_leaf_node_allocation_blocks_begin {
                                Some(next_leaf_node_allocation_blocks_begin) => next_leaf_node_allocation_blocks_begin,
                                None => {
                                    this.fut_state = InodeIndexEnumerateCursorNextFutureState::InodesRangeExhausted {
                                        cursor: Some(cursor),
                                    };
                                    continue;
                                }
                            };

                            let read_fut = InodeIndexReadTreeNodeFuture::new(
                                cursor.transaction.take(),
                                next_leaf_node_allocation_blocks_begin,
                                Some(0),
                                true,
                            );
                            this.fut_state = InodeIndexEnumerateCursorNextFutureState::ReadNextTreeLeafNode {
                                cursor: Some(cursor),
                                read_fut,
                            };
                        }
                    }
                }
                InodeIndexEnumerateCursorNextFutureState::LookupNextInodeWalkReadTreeNode {
                    cursor: fut_cursor,
                    next_inode,
                    read_fut,
                } => {
                    let (
                        fs_instance,
                        _fs_sync_state_image_size,
                        fs_sync_state_alloc_bitmap,
                        _fs_sync_state_alloc_bitmap_file,
                        mut fs_sync_state_auth_tree,
                        fs_sync_state_inode_index,
                        fs_sync_state_read_buffer,
                        _fs_sync_state_keys_cache,
                    ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();

                    let (returned_transaction, node_ref) = match InodeIndexReadTreeNodeFuture::poll(
                        pin::Pin::new(read_fut),
                        &fs_instance.chip,
                        &fs_instance.fs_config,
                        fs_sync_state_alloc_bitmap,
                        &mut fs_sync_state_auth_tree,
                        &fs_sync_state_inode_index.layout,
                        &fs_sync_state_inode_index.tree_nodes_cache,
                        &fs_sync_state_inode_index.tree_node_decryption_instance,
                        fs_sync_state_read_buffer,
                        cx,
                    ) {
                        task::Poll::Ready((returned_transaction, Ok(node_ref))) => (returned_transaction, node_ref),
                        task::Poll::Ready((returned_transaction, Err(e))) => {
                            break (fut_cursor.take(), returned_transaction, e);
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let mut cursor = match fut_cursor.take() {
                        Some(cursor) => cursor,
                        None => break (None, None, nvfs_err_internal!()),
                    };

                    match node_ref.get_node() {
                        Ok(InodeIndexTreeNode::Internal(internal_node)) => {
                            let tree_layout = &fs_sync_state_inode_index.layout;
                            let node_level = match internal_node.node_level(tree_layout) {
                                Ok(internal_node_level) => internal_node_level,
                                Err(e) => {
                                    break (Some(cursor), returned_transaction, e);
                                }
                            };

                            let next_child_index = match internal_node.lookup_child(*next_inode, tree_layout) {
                                Ok(next_child_index) => next_child_index,
                                Err(e) => {
                                    break (Some(cursor), returned_transaction, e);
                                }
                            };

                            let next_child_node_allocation_blocks_begin = match internal_node
                                .entry_child_ptr(next_child_index, tree_layout)
                                .and_then(|next_child_ptr| {
                                    next_child_ptr.decode(
                                        tree_layout
                                            .node_encrypted_block_layout
                                            .get_allocation_block_size_128b_log2()
                                            as u32,
                                    )
                                }) {
                                Ok(next_child_node_allocation_blocks_begin) => next_child_node_allocation_blocks_begin,
                                Err(e) => {
                                    break (Some(cursor), returned_transaction, e);
                                }
                            };
                            let next_child_node_allocation_blocks_begin = match next_child_node_allocation_blocks_begin
                            {
                                Some(next_child_node_allocation_blocks_begin) => {
                                    next_child_node_allocation_blocks_begin
                                }
                                None => {
                                    break (
                                        Some(cursor),
                                        returned_transaction.or(node_ref.into_transaction()),
                                        NvFsError::from(CocoonFsFormatError::InvalidIndexNode),
                                    );
                                }
                            };

                            *fut_cursor = Some(cursor);
                            let transaction = returned_transaction.or(node_ref.into_transaction());
                            let next_child_node_level = node_level - 1;
                            *read_fut = InodeIndexReadTreeNodeFuture::new(
                                transaction,
                                next_child_node_allocation_blocks_begin,
                                Some(next_child_node_level),
                                next_child_node_level == 0,
                            );
                        }
                        Ok(InodeIndexTreeNode::Leaf(leaf_node)) => {
                            let tree_layout = &fs_sync_state_inode_index.layout;
                            let entry_index_in_leaf_node = match leaf_node.lookup(*next_inode, tree_layout) {
                                Ok(Ok(entry_index_in_leaf_node)) => entry_index_in_leaf_node,
                                Ok(Err(entry_index_in_leaf_node)) => {
                                    if entry_index_in_leaf_node == leaf_node.entries {
                                        // No inodes in range. Still update the cursor's tree_position so
                                        // that the nodes will perhaps get added to the caches as
                                        // appropriate upon return.
                                        let (transaction, node_ref) =
                                            InodeIndexTreeNodeRefForUpdate::try_from_node_ref(node_ref);
                                        cursor.transaction = transaction.or(returned_transaction);
                                        let node_ref = match node_ref {
                                            Ok(node_ref) => node_ref,
                                            Err(e) => {
                                                break (Some(cursor), None, e);
                                            }
                                        };
                                        cursor.tree_position = Some(InodeIndexEnumerateCursorTreePosition {
                                            leaf_node: node_ref,
                                            entry_index_in_leaf_node,
                                        });
                                        this.fut_state =
                                            InodeIndexEnumerateCursorNextFutureState::InodesRangeExhausted {
                                                cursor: Some(cursor),
                                            };
                                        continue;
                                    }
                                    entry_index_in_leaf_node
                                }
                                Err(e) => {
                                    break (Some(cursor), returned_transaction.or(node_ref.into_transaction()), e)
                                }
                            };

                            let inode = match leaf_node.entry_inode(entry_index_in_leaf_node, tree_layout) {
                                Ok(inode) => inode,
                                Err(e) => {
                                    break (Some(cursor), returned_transaction.or(node_ref.into_transaction()), e)
                                }
                            };

                            let (transaction, node_ref) = InodeIndexTreeNodeRefForUpdate::try_from_node_ref(node_ref);
                            cursor.transaction = transaction.or(returned_transaction);
                            let node_ref = match node_ref {
                                Ok(node_ref) => node_ref,
                                Err(e) => {
                                    break (Some(cursor), None, e);
                                }
                            };
                            let tree_position = InodeIndexEnumerateCursorTreePosition {
                                leaf_node: node_ref,
                                entry_index_in_leaf_node,
                            };

                            if inode > *cursor.inodes_enumerate_range.end() {
                                // No more inodes in range. Still update the cursor's
                                // tree_position so that the nodes will perhaps get added to the
                                // caches as appropriate upon return.
                                cursor.tree_position = Some(tree_position);
                                this.fut_state = InodeIndexEnumerateCursorNextFutureState::InodesRangeExhausted {
                                    cursor: Some(cursor),
                                };
                                continue;
                            }
                            if inode == *cursor.inodes_enumerate_range.end() {
                                cursor.at_end = true;
                            }

                            cursor.tree_position = Some(tree_position);
                            this.fut_state = InodeIndexEnumerateCursorNextFutureState::Done;
                            return task::Poll::Ready(Ok((cursor, Ok(Some(inode)))));
                        }
                        Err(e) => break (Some(cursor), returned_transaction.or(node_ref.into_transaction()), e),
                    }
                }
                InodeIndexEnumerateCursorNextFutureState::ReadNextTreeLeafNode { cursor, read_fut } => {
                    let (
                        fs_instance,
                        _fs_sync_state_image_size,
                        fs_sync_state_alloc_bitmap,
                        _fs_sync_state_alloc_bitmap_file,
                        mut fs_sync_state_auth_tree,
                        fs_sync_state_inode_index,
                        fs_sync_state_read_buffer,
                        _fs_sync_state_keys_cache,
                    ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();

                    let (returned_transaction, node_ref) = match InodeIndexReadTreeNodeFuture::poll(
                        pin::Pin::new(read_fut),
                        &fs_instance.chip,
                        &fs_instance.fs_config,
                        fs_sync_state_alloc_bitmap,
                        &mut fs_sync_state_auth_tree,
                        &fs_sync_state_inode_index.layout,
                        &fs_sync_state_inode_index.tree_nodes_cache,
                        &fs_sync_state_inode_index.tree_node_decryption_instance,
                        fs_sync_state_read_buffer,
                        cx,
                    ) {
                        task::Poll::Ready((returned_transaction, Ok(node_ref))) => (returned_transaction, node_ref),
                        task::Poll::Ready((returned_transaction, Err(e))) => {
                            break (cursor.take(), returned_transaction, e);
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let mut cursor = match cursor.take() {
                        Some(cursor) => cursor,
                        None => break (None, None, nvfs_err_internal!()),
                    };

                    let (transaction, node_ref) = InodeIndexTreeNodeRefForUpdate::try_from_node_ref(node_ref);
                    cursor.transaction = transaction.or(returned_transaction);
                    let node_ref = match node_ref {
                        Ok(node_ref) => node_ref,
                        Err(e) => {
                            break (Some(cursor), None, e);
                        }
                    };

                    let tree_position = match cursor.tree_position.as_mut() {
                        Some(tree_position) => {
                            let prev_leaf_node = mem::replace(&mut tree_position.leaf_node, node_ref);
                            tree_position.entry_index_in_leaf_node = 0;

                            // Add the previous leaf node to a cache as appropriate.
                            if let InodeIndexTreeNodeRefForUpdate::Owned {
                                node: prev_leaf_node,
                                is_modified_by_transaction: prev_leaf_node_is_modified_by_transaction,
                            } = prev_leaf_node
                            {
                                if prev_leaf_node_is_modified_by_transaction {
                                    match cursor.transaction.as_mut() {
                                        Some(transaction) => transaction
                                            .inode_index_updates
                                            .updated_tree_nodes_cache
                                            .insert(0, prev_leaf_node),
                                        None => {
                                            // How can it have been modified by a transaction if there is none?
                                            break (Some(cursor), None, nvfs_err_internal!());
                                        }
                                    };
                                } else {
                                    let mut tree_nodes_cache_guard = fs_sync_state_inode_index.tree_nodes_cache.write();
                                    tree_nodes_cache_guard.insert(0, prev_leaf_node);
                                }
                            }

                            tree_position
                        }
                        None => cursor.tree_position.insert(InodeIndexEnumerateCursorTreePosition {
                            leaf_node: node_ref,
                            entry_index_in_leaf_node: 0,
                        }),
                    };

                    let leaf_node = match tree_position.get_leaf_node(cursor.transaction.as_deref()) {
                        Ok(InodeIndexTreeNode::Leaf(leaf_node)) => leaf_node,
                        Ok(InodeIndexTreeNode::Internal(_)) => {
                            break (
                                Some(cursor),
                                None,
                                NvFsError::from(CocoonFsFormatError::InvalidIndexNode),
                            );
                        }
                        Err(e) => break (Some(cursor), None, e),
                    };

                    if leaf_node.entries == 0 {
                        break (
                            Some(cursor),
                            None,
                            NvFsError::from(CocoonFsFormatError::InvalidIndexNode),
                        );
                    }
                    let inode = match leaf_node.entry_inode(0, &fs_sync_state_inode_index.layout) {
                        Ok(inode) => inode,
                        Err(e) => break (Some(cursor), None, e),
                    };

                    if inode < *cursor.inodes_enumerate_range.end() {
                        this.fut_state = InodeIndexEnumerateCursorNextFutureState::Done;
                        return task::Poll::Ready(Ok((cursor, Ok(Some(inode)))));
                    } else {
                        this.fut_state =
                            InodeIndexEnumerateCursorNextFutureState::InodesRangeExhausted { cursor: Some(cursor) };
                    }
                }
                InodeIndexEnumerateCursorNextFutureState::InodesRangeExhausted { cursor } => {
                    let mut cursor = match cursor.take() {
                        Some(cursor) => cursor,
                        None => break (None, None, nvfs_err_internal!()),
                    };

                    cursor.at_end = true;
                    // Add the nodes owned by the cursor's tree_position into the caches as
                    // appropriate.
                    if let Some(tree_position) = cursor.tree_position.take() {
                        let InodeIndexEnumerateCursorTreePosition {
                            leaf_node,
                            entry_index_in_leaf_node: _,
                        } = tree_position;

                        if let InodeIndexTreeNodeRefForUpdate::Owned {
                            node: leaf_node,
                            is_modified_by_transaction: leaf_node_is_modified_by_transaction,
                        } = leaf_node
                        {
                            if leaf_node_is_modified_by_transaction {
                                match cursor.transaction.as_mut() {
                                    Some(transaction) => transaction
                                        .inode_index_updates
                                        .updated_tree_nodes_cache
                                        .insert(0, leaf_node),
                                    None => {
                                        // How can it have been modified by a transaction if there is none?
                                        break (Some(cursor), None, nvfs_err_internal!());
                                    }
                                };
                            } else {
                                let mut tree_nodes_cache_guard =
                                    fs_instance_sync_state.inode_index.tree_nodes_cache.write();
                                tree_nodes_cache_guard.insert(0, leaf_node);
                            }
                        }
                    }
                    this.fut_state = InodeIndexEnumerateCursorNextFutureState::Done;
                    return task::Poll::Ready(Ok((cursor, Ok(None))));
                }
                InodeIndexEnumerateCursorNextFutureState::Done => unreachable!(),
            }
        };

        this.fut_state = InodeIndexEnumerateCursorNextFutureState::Done;
        task::Poll::Ready(match cursor {
            Some(mut cursor) => {
                cursor.transaction = cursor.transaction.take().or(transaction);
                Ok((cursor, Err(e)))
            }
            None => Err(nvfs_err_internal!()),
        })
    }
}

/// Read the data of the inode an [`InodeIndexEnumerateCursor`] currently points at.
pub struct InodeIndexEnumerateCursorReadInodeDataFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    fut_state: InodeIndexEnumerateCursorReadInodeDataFutureState<ST, C>,
}

enum InodeIndexEnumerateCursorReadInodeDataFutureState<ST: sync_types::SyncTypes, C: chip::NvChip> {
    Init {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        cursor: Option<Box<InodeIndexEnumerateCursor<ST, C>>>,
    },
    ReadInodeExtentsList {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self. Has its transaction moved temporarily into read_inode_extents_list_fut.
        cursor: Option<Box<InodeIndexEnumerateCursor<ST, C>>>,
        inode: InodeIndexKeyType,
        read_inode_extents_list_fut: InodeExtentsListReadFuture<ST, C>,
    },
    ReadInodeData {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self. Has its transaction moved temporarily into read_inode_data_fut.
        cursor: Option<Box<InodeIndexEnumerateCursor<ST, C>>>,
        read_inode_data_fut: ReadInodeDataFuture<ST, C>,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsSyncStateReadFuture<ST, C>
    for InodeIndexEnumerateCursorReadInodeDataFuture<ST, C>
{
    type Output = Result<
        (
            Box<InodeIndexEnumerateCursor<ST, C>>,
            Result<zeroize::Zeroizing<Vec<u8>>, NvFsError>,
        ),
        NvFsError,
    >;

    type AuxPollData<'a> = ();

    fn poll<'a>(
        self: pin::Pin<&mut Self>,
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, C>,
        _aux_data: &mut Self::AuxPollData<'a>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        let (cursor, transaction, e) = loop {
            match &mut this.fut_state {
                InodeIndexEnumerateCursorReadInodeDataFutureState::Init { cursor } => {
                    let mut cursor = match cursor.take() {
                        Some(cursor) => cursor,
                        None => break (None, None, nvfs_err_internal!()),
                    };
                    let tree_position = match cursor.tree_position.as_mut() {
                        Some(tree_position) => tree_position,
                        None => break (Some(cursor), None, nvfs_err_internal!()),
                    };

                    let leaf_node = match tree_position.get_leaf_node(cursor.transaction.as_deref()) {
                        Ok(InodeIndexTreeNode::Leaf(leaf_node)) => leaf_node,
                        Ok(InodeIndexTreeNode::Internal(_)) => {
                            break (
                                Some(cursor),
                                None,
                                NvFsError::from(CocoonFsFormatError::InvalidIndexNode),
                            );
                        }
                        Err(e) => break (Some(cursor), None, e),
                    };

                    let inode = match leaf_node.entry_inode(
                        tree_position.entry_index_in_leaf_node,
                        &fs_instance_sync_state.inode_index.layout,
                    ) {
                        Ok(inode) => inode,
                        Err(e) => break (Some(cursor), None, e),
                    };
                    let inode_index_entry_extent_ptr = match leaf_node.entry_extent_ptr(
                        tree_position.entry_index_in_leaf_node,
                        &fs_instance_sync_state.inode_index.layout,
                    ) {
                        Ok(inode_index_entry_extent_ptr) => inode_index_entry_extent_ptr,
                        Err(e) => break (Some(cursor), None, e),
                    };
                    let allocation_block_size_128b_log2 = fs_instance_sync_state
                        .get_fs_ref()
                        .fs_config
                        .image_layout
                        .allocation_block_size_128b_log2
                        as u32;
                    match inode_index_entry_extent_ptr.decode(allocation_block_size_128b_log2) {
                        Ok(Some((inode_extent, false))) => {
                            let mut inode_extents = extents::PhysicalExtents::new();
                            if let Err(e) = inode_extents.push_extent(&inode_extent, true) {
                                break (Some(cursor), None, e);
                            }
                            let read_inode_data_fut = ReadInodeDataFuture::new_with_inode_extents(
                                cursor.transaction.take(),
                                inode,
                                inode_extents,
                            );
                            this.fut_state = InodeIndexEnumerateCursorReadInodeDataFutureState::ReadInodeData {
                                cursor: Some(cursor),
                                read_inode_data_fut,
                            };
                        }
                        Ok(Some((_first_inode_extents_list_extent, true))) => {
                            let (
                                fs_instance,
                                _fs_sync_state_image_size,
                                _fs_sync_state_alloc_bitmap,
                                _fs_sync_state_alloc_bitmap_file,
                                _fs_sync_state_auth_tree,
                                _fs_sync_state_inode_index,
                                _fs_sync_state_read_buffer,
                                mut fs_sync_state_keys_cache,
                            ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();

                            let read_inode_extents_list_fut = match InodeExtentsListReadFuture::new(
                                cursor.transaction.take(),
                                inode,
                                &inode_index_entry_extent_ptr,
                                &fs_instance.fs_config.root_key,
                                &mut fs_sync_state_keys_cache,
                                &fs_instance.fs_config.image_layout,
                            ) {
                                Ok(read_inode_extents_list_fut) => read_inode_extents_list_fut,
                                Err((returned_transaction, e)) => break (Some(cursor), returned_transaction, e),
                            };
                            this.fut_state = InodeIndexEnumerateCursorReadInodeDataFutureState::ReadInodeExtentsList {
                                cursor: Some(cursor),
                                inode,
                                read_inode_extents_list_fut,
                            };
                        }
                        Ok(None) => break (Some(cursor), None, NvFsError::from(CocoonFsFormatError::InvalidExtents)),
                        Err(e) => break (Some(cursor), None, e),
                    }
                }
                InodeIndexEnumerateCursorReadInodeDataFutureState::ReadInodeExtentsList {
                    cursor,
                    inode,
                    read_inode_extents_list_fut,
                } => {
                    let (returned_transaction, _inode_extents_list_extents, inode_extents) =
                        match CocoonFsSyncStateReadFuture::poll(
                            pin::Pin::new(read_inode_extents_list_fut),
                            fs_instance_sync_state,
                            &mut (),
                            cx,
                        ) {
                            task::Poll::Ready((
                                returned_transaction,
                                Ok((inode_extents_list_extents, inode_extents)),
                            )) => (returned_transaction, inode_extents_list_extents, inode_extents),
                            task::Poll::Ready((returned_transaction, Err(e))) => {
                                break (cursor.take(), returned_transaction, e)
                            }
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    let cursor = match cursor.take() {
                        Some(cursor) => cursor,
                        None => break (None, returned_transaction, nvfs_err_internal!()),
                    };

                    let read_inode_data_fut =
                        ReadInodeDataFuture::new_with_inode_extents(returned_transaction, *inode, inode_extents);
                    this.fut_state = InodeIndexEnumerateCursorReadInodeDataFutureState::ReadInodeData {
                        cursor: Some(cursor),
                        read_inode_data_fut,
                    };
                }
                InodeIndexEnumerateCursorReadInodeDataFutureState::ReadInodeData {
                    cursor,
                    read_inode_data_fut,
                } => {
                    let (returned_transaction, inode_data) = match CocoonFsSyncStateReadFuture::poll(
                        pin::Pin::new(read_inode_data_fut),
                        fs_instance_sync_state,
                        &mut (),
                        cx,
                    ) {
                        task::Poll::Ready((returned_transaction, Ok(inode_data))) => (returned_transaction, inode_data),
                        task::Poll::Ready((returned_transaction, Err(e))) => {
                            break (cursor.take(), returned_transaction, e);
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let mut cursor = match cursor.take() {
                        Some(cursor) => cursor,
                        None => break (None, returned_transaction, nvfs_err_internal!()),
                    };
                    cursor.transaction = returned_transaction;

                    // When here from the InodeIndexEnumerateCursor, it is known that the inode
                    // exists.
                    let inode_data = match inode_data {
                        Some(inode_data) => inode_data,
                        None => break (Some(cursor), None, nvfs_err_internal!()),
                    };

                    this.fut_state = InodeIndexEnumerateCursorReadInodeDataFutureState::Done;
                    return task::Poll::Ready(Ok((cursor, Ok(inode_data))));
                }
                InodeIndexEnumerateCursorReadInodeDataFutureState::Done => unreachable!(),
            }
        };

        this.fut_state = InodeIndexEnumerateCursorReadInodeDataFutureState::Done;
        task::Poll::Ready(match cursor {
            Some(mut cursor) => {
                cursor.transaction = cursor.transaction.take().or(transaction);
                if cursor.transaction.is_none() {
                    Err(e)
                } else {
                    Ok((cursor, Err(e)))
                }
            }
            None => Err(e),
        })
    }
}

/// Reference to an inode index B+-tree node read for update on behalf of some
/// [`Transaction`](transaction::Transaction).
enum InodeIndexTreeNodeRefForUpdate {
    /// The node data is owned.
    Owned {
        node: InodeIndexTreeNode,
        is_modified_by_transaction: bool,
    },
    /// The node is already staged at [`TransactionInodeIndexUpdates::tree_nodes_staged_updates`].
    TransactionStagedUpdatesNodeRef {
        nodes_staged_updates_slot_index: usize,
    },
}

impl InodeIndexTreeNodeRefForUpdate {
    fn get_nodes_staged_updates_slot_index(&self) -> Option<usize> {
        match self {
            Self::Owned { .. } => None,
            Self::TransactionStagedUpdatesNodeRef {
                nodes_staged_updates_slot_index,
            } => Some(*nodes_staged_updates_slot_index),
        }
    }
}

impl InodeIndexTreeNodeRefForUpdate {
    fn get_node<'a>(&'a self, transaction: &'a transaction::Transaction) -> Result<&'a InodeIndexTreeNode, NvFsError> {
        match self {
            Self::Owned { node, .. } => Ok(node),
            Self::TransactionStagedUpdatesNodeRef {
                nodes_staged_updates_slot_index,
            } => transaction.inode_index_updates.tree_nodes_staged_updates[*nodes_staged_updates_slot_index]
                .as_ref()
                .map(|staged_node| &staged_node.node)
                .ok_or_else(|| nvfs_err_internal!()),
        }
    }

    fn try_from_node_ref<ST: sync_types::SyncTypes>(
        r: InodeIndexTreeNodeRef<'_, ST>,
    ) -> (Option<Box<transaction::Transaction>>, Result<Self, NvFsError>) {
        match r {
            InodeIndexTreeNodeRef::Owned {
                node,
                is_modified_by_transaction,
            } => (
                None,
                Ok(Self::Owned {
                    node,
                    is_modified_by_transaction,
                }),
            ),
            InodeIndexTreeNodeRef::CacheEntryRef { .. } => (None, Err(nvfs_err_internal!())),
            InodeIndexTreeNodeRef::TransactionStagedUpdatesNodeRef {
                transaction,
                nodes_staged_updates_slot_index,
            } => (
                Some(transaction),
                Ok(Self::TransactionStagedUpdatesNodeRef {
                    nodes_staged_updates_slot_index,
                }),
            ),
            InodeIndexTreeNodeRef::TransactionUpdatedNodesCacheEntryRef { transaction, .. } => {
                (Some(transaction), Err(nvfs_err_internal!()))
            }
        }
    }
}

/// Result of looking up an inode for insertion.
pub struct InodeIndexLookupForInsertResult {
    inode: InodeIndexKeyType,
    preexisting_entry_extent_ptr: Option<EncodedExtentPtr>,
    leaf_node: InodeIndexTreeNodeRefForUpdate,
    leaf_parent_node: Option<InodeIndexTreeNodeRefForUpdate>,
}

impl InodeIndexLookupForInsertResult {
    pub fn get_preexisting_extent_ptr(&self) -> Option<EncodedExtentPtr> {
        self.preexisting_entry_extent_ptr
    }
}

/// Look up an inode for insertion.
pub struct InodeIndexLookupForInsertFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    inode: InodeIndexKeyType,
    found_leaf_parent_node: Option<InodeIndexTreeNodeRefForUpdate>,
    fut_state: InodeIndexLookupForInsertFutureState<C>,
    _phantom: marker::PhantomData<fn() -> *const ST>,
}

#[allow(clippy::large_enum_variant)]
enum InodeIndexLookupForInsertFutureState<C: chip::NvChip> {
    Init {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<transaction::Transaction>>,
    },
    ReadTreeNode {
        read_fut: InodeIndexReadTreeNodeFuture<C>,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> InodeIndexLookupForInsertFuture<ST, C> {
    pub fn new(transaction: Box<transaction::Transaction>, inode: InodeIndexKeyType) -> Self {
        Self {
            inode,
            found_leaf_parent_node: None,
            fut_state: InodeIndexLookupForInsertFutureState::Init {
                transaction: Some(transaction),
            },
            _phantom: marker::PhantomData,
        }
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsSyncStateReadFuture<ST, C>
    for InodeIndexLookupForInsertFuture<ST, C>
{
    type Output = Result<
        (
            Box<transaction::Transaction>,
            Result<InodeIndexLookupForInsertResult, NvFsError>,
        ),
        NvFsError,
    >;

    type AuxPollData<'a> = ();

    fn poll(
        self: pin::Pin<&mut Self>,
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, C>,
        _aux_data: &mut Self::AuxPollData<'_>,
        cx: &mut core::task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        let (
            fs_instance,
            _fs_sync_state_image_size,
            fs_sync_state_alloc_bitmap,
            _fs_sync_state_alloc_bitmap_file,
            mut fs_sync_state_auth_tree,
            fs_sync_state_inode_index,
            fs_sync_state_read_buffer,
            _fs_sync_state_keys_cache,
        ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();

        let (returned_transaction, e) = loop {
            match &mut this.fut_state {
                InodeIndexLookupForInsertFutureState::Init { transaction } => {
                    let transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => {
                            break (None, nvfs_err_internal!());
                        }
                    };
                    let root_node_allocation_blocks_begin =
                        transaction.inode_index_updates.root_node_allocation_blocks_begin;
                    let root_node_level = transaction.inode_index_updates.index_tree_levels - 1;
                    let read_fut = InodeIndexReadTreeNodeFuture::new(
                        Some(transaction),
                        root_node_allocation_blocks_begin,
                        Some(root_node_level),
                        root_node_level <= 1,
                    );
                    this.fut_state = InodeIndexLookupForInsertFutureState::ReadTreeNode { read_fut };
                }
                InodeIndexLookupForInsertFutureState::ReadTreeNode { read_fut } => {
                    let (returned_transaction, node_ref) = match InodeIndexReadTreeNodeFuture::poll(
                        pin::Pin::new(read_fut),
                        &fs_instance.chip,
                        &fs_instance.fs_config,
                        fs_sync_state_alloc_bitmap,
                        &mut fs_sync_state_auth_tree,
                        &fs_sync_state_inode_index.layout,
                        &fs_sync_state_inode_index.tree_nodes_cache,
                        &fs_sync_state_inode_index.tree_node_decryption_instance,
                        fs_sync_state_read_buffer,
                        cx,
                    ) {
                        task::Poll::Ready((returned_transaction, Ok(node_ref))) => (returned_transaction, node_ref),
                        task::Poll::Ready((returned_transaction, Err(e))) => {
                            break (returned_transaction, e);
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    match node_ref.get_node() {
                        Ok(InodeIndexTreeNode::Internal(internal_node)) => {
                            let tree_layout = &fs_sync_state_inode_index.layout;
                            let node_level = match internal_node.node_level(tree_layout) {
                                Ok(internal_node_level) => internal_node_level,
                                Err(e) => {
                                    break (returned_transaction.or(node_ref.into_transaction()), e);
                                }
                            };

                            let next_child_index = match internal_node.lookup_child(this.inode, tree_layout) {
                                Ok(next_child_index) => next_child_index,
                                Err(e) => {
                                    break (returned_transaction.or(node_ref.into_transaction()), e);
                                }
                            };

                            let next_child_ptr = match internal_node.entry_child_ptr(next_child_index, tree_layout) {
                                Ok(next_child_ptr) => next_child_ptr,
                                Err(e) => {
                                    break (returned_transaction.or(node_ref.into_transaction()), e);
                                }
                            };

                            let next_child_node_allocation_blocks_begin = match next_child_ptr.decode(
                                tree_layout
                                    .node_encrypted_block_layout
                                    .get_allocation_block_size_128b_log2() as u32,
                            ) {
                                Ok(next_child_node_allocation_blocks_begin) => {
                                    match next_child_node_allocation_blocks_begin {
                                        Some(next_child_node_allocation_blocks_begin) => {
                                            next_child_node_allocation_blocks_begin
                                        }
                                        None => {
                                            break (
                                                returned_transaction.or(node_ref.into_transaction()),
                                                NvFsError::from(CocoonFsFormatError::InvalidIndexNode),
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    break (returned_transaction.or(node_ref.into_transaction()), e);
                                }
                            };

                            let transaction = if node_level == 1 {
                                // The bottom internal node had been read for update.
                                // Turn the node_ref into a InodeIndexTreeNodeRefForUpdate, obtain
                                // the transaction back, and store the node in Self::found_leaf_parent_node.
                                let (transaction, node_ref) =
                                    InodeIndexTreeNodeRefForUpdate::try_from_node_ref(node_ref);
                                let transaction = transaction.or(returned_transaction);
                                let node_ref = match node_ref {
                                    Ok(node_ref) => node_ref,
                                    Err(e) => {
                                        break (transaction, e);
                                    }
                                };
                                let transaction = match transaction {
                                    Some(transaction) => transaction,
                                    None => {
                                        break (None, nvfs_err_internal!());
                                    }
                                };

                                this.found_leaf_parent_node = Some(node_ref);

                                transaction
                            } else {
                                match returned_transaction.or(node_ref.into_transaction()) {
                                    Some(transaction) => transaction,
                                    None => break (None, nvfs_err_internal!()),
                                }
                            };

                            let next_child_node_level = node_level - 1;
                            let read_fut = InodeIndexReadTreeNodeFuture::new(
                                Some(transaction),
                                next_child_node_allocation_blocks_begin,
                                Some(next_child_node_level),
                                next_child_node_level <= 1,
                            );
                            this.fut_state = InodeIndexLookupForInsertFutureState::ReadTreeNode { read_fut };
                        }
                        Ok(InodeIndexTreeNode::Leaf(leaf_node)) => {
                            let tree_layout = &fs_sync_state_inode_index.layout;
                            let preexisting_entry_index = match leaf_node.lookup(this.inode, tree_layout) {
                                Ok(preexisting_entry_index) => preexisting_entry_index,
                                Err(e) => {
                                    break (returned_transaction.or(node_ref.into_transaction()), e);
                                }
                            };
                            let preexisting_entry_extent_ptr = match preexisting_entry_index {
                                Ok(preexisting_entry_index) => {
                                    match leaf_node.encoded_entry_extent_ptr(preexisting_entry_index, tree_layout) {
                                        Ok(preexisting_entry_extent_ptr) => {
                                            Some(EncodedExtentPtr::from(*preexisting_entry_extent_ptr))
                                        }
                                        Err(e) => {
                                            break (returned_transaction.or(node_ref.into_transaction()), e);
                                        }
                                    }
                                }
                                Err(_) => None,
                            };

                            // The leaf node had been read for update.
                            // Turn the node_ref into a InodeIndexTreeNodeRefForUpdate and obtain
                            // the transaction back.
                            let leaf_node_entries = leaf_node.entries;
                            let (transaction, node_ref) = InodeIndexTreeNodeRefForUpdate::try_from_node_ref(node_ref);
                            let transaction = transaction.or(returned_transaction);
                            let node_ref = match node_ref {
                                Ok(node_ref) => node_ref,
                                Err(e) => {
                                    break (transaction, e);
                                }
                            };
                            let mut transaction = match transaction {
                                Some(transaction) => transaction,
                                None => {
                                    break (None, nvfs_err_internal!());
                                }
                            };

                            // If no entry will have to get inserted, or there's enough room in the
                            // node, then the parent will not be needed. Don't carry it around then,
                            // dismiss it from here and possibly move into a cache as appropriate.
                            if preexisting_entry_extent_ptr.is_some()
                                || leaf_node_entries < tree_layout.max_leaf_node_entries
                            {
                                if let Some(InodeIndexTreeNodeRefForUpdate::Owned {
                                    node: parent_node,
                                    is_modified_by_transaction: parent_node_is_modified_by_transaction,
                                }) = this.found_leaf_parent_node.take()
                                {
                                    if parent_node_is_modified_by_transaction {
                                        transaction
                                            .inode_index_updates
                                            .updated_tree_nodes_cache
                                            .insert(1, parent_node);
                                    } else {
                                        let mut tree_nodes_cache_guard =
                                            fs_sync_state_inode_index.tree_nodes_cache.write();
                                        tree_nodes_cache_guard.insert(1, parent_node);
                                    }
                                }
                            }

                            // Done, return the result.
                            this.fut_state = InodeIndexLookupForInsertFutureState::Done;
                            return task::Poll::Ready(Ok((
                                transaction,
                                Ok(InodeIndexLookupForInsertResult {
                                    inode: this.inode,
                                    preexisting_entry_extent_ptr,
                                    leaf_node: node_ref,
                                    leaf_parent_node: this.found_leaf_parent_node.take(),
                                }),
                            )));
                        }
                        Err(e) => {
                            break (returned_transaction.or(node_ref.into_transaction()), e);
                        }
                    }
                }
                InodeIndexLookupForInsertFutureState::Done => unreachable!(),
            }
        };

        this.fut_state = InodeIndexLookupForInsertFutureState::Done;
        if let Some(returned_transaction) = returned_transaction {
            task::Poll::Ready(Ok((returned_transaction, Err(e))))
        } else {
            task::Poll::Ready(Err(e))
        }
    }
}

/// Insert or update an inode entry.
pub struct InodeIndexInsertEntryFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    lookup_result: InodeIndexLookupForInsertResult,
    pending_inode_extents_reallocation: InodeExtentsPendingReallocation,
    pending_inode_extents_list_update: InodeExtentsListPendingUpdate,
    fut_state: InodeIndexInsertEntryFutureState<ST, C>,
}

enum InodeIndexInsertEntryFutureState<ST: sync_types::SyncTypes, C: chip::NvChip> {
    Init {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<transaction::Transaction>>,
    },
    TryRotatePrepare {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<transaction::Transaction>>,
        nodes_staged_updates_parent_slot_index: usize,
        nodes_staged_updates_child_slot_index: usize,
    },
    TryRotate {
        nodes_staged_updates_parent_slot_index: usize,
        nodes_staged_updates_child_slot_index: usize,
        child_index_in_parent: usize,
        read_sibling_fut: InodeIndexReadTreeNodeFuture<C>,
        at_left_sibling: bool,
    },
    SplitRootNode {
        nodes_staged_updates_old_root_slot_index: usize,
        allocate_fut: CocoonFsAllocateBlocksFuture<ST, C>,
    },
    SplitNode {
        nodes_staged_updates_parent_slot_index: usize,
        nodes_staged_updates_child_slot_index: usize,
        child_index_in_parent: usize,
        allocate_fut: CocoonFsAllocateBlockFuture<ST, C>,
    },
    PreemptiveRotateSplitWalkLoadRoot {
        read_root_fut: InodeIndexReadTreeNodeFuture<C>,
    },
    PreemptiveRotateSplitWalkLoadChildPrepare {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<transaction::Transaction>>,
        parent_node_ref: InodeIndexTreeNodeRefForUpdate,
    },
    PreemptiveRotateSplitWalkLoadChild {
        parent_node_ref: InodeIndexTreeNodeRefForUpdate,
        read_child_fut: InodeIndexReadTreeNodeFuture<C>,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> InodeIndexInsertEntryFuture<ST, C> {
    pub fn new(
        transaction: Box<transaction::Transaction>,
        lookup_result: InodeIndexLookupForInsertResult,
        pending_inode_extents_reallocation: InodeExtentsPendingReallocation,
        pending_inode_extents_list_update: InodeExtentsListPendingUpdate,
    ) -> Self {
        Self {
            lookup_result,
            pending_inode_extents_reallocation,
            pending_inode_extents_list_update,
            fut_state: InodeIndexInsertEntryFutureState::Init {
                transaction: Some(transaction),
            },
        }
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsSyncStateReadFuture<ST, C>
    for InodeIndexInsertEntryFuture<ST, C>
{
    type Output = Result<
        (
            Box<transaction::Transaction>,
            Result<
                (),
                (
                    InodeExtentsPendingReallocation,
                    InodeExtentsListPendingUpdate,
                    NvFsError,
                ),
            >,
        ),
        NvFsError,
    >;
    type AuxPollData<'a> = ();

    fn poll<'a>(
        self: pin::Pin<&mut Self>,
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, C>,
        _aux_data: &mut Self::AuxPollData<'a>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        let (returned_transaction, result) = loop {
            match &mut this.fut_state {
                InodeIndexInsertEntryFutureState::Init { transaction } => {
                    let mut transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => break (None, Err(nvfs_err_internal!())),
                    };

                    if let Some(lookup_result_preexisting_extent_ptr) =
                        this.lookup_result.preexisting_entry_extent_ptr.as_ref()
                    {
                        if *lookup_result_preexisting_extent_ptr
                            == this
                                .pending_inode_extents_list_update
                                .get_inode_index_entry_extent_ptr()
                        {
                            // The inode entry is already up-to-date and we're almost done. Now that
                            // it is known that no non-revertable allocations will be made for index
                            // tree, it is safe to free the extents to be released on behalf of the
                            // invoking operation.
                            if let Err(e) = this
                                .pending_inode_extents_reallocation
                                .free_excess_preexisting_inode_extents(
                                    &mut transaction.allocs,
                                    &mut transaction.auth_tree_data_blocks_update_states,
                                )
                            {
                                break (Some(transaction), Err(e));
                            }
                            if let Err(e) = this
                                .pending_inode_extents_list_update
                                .free_excess_preexisting_inode_extents_list_extents(
                                    &mut transaction.allocs,
                                    &mut transaction.auth_tree_data_blocks_update_states,
                                )
                            {
                                break match this
                                    .pending_inode_extents_reallocation
                                    .rollback_excess_preexisting_inode_extents_free(
                                        transaction,
                                        &fs_instance_sync_state.alloc_bitmap,
                                    ) {
                                    Ok(transaction) => (Some(transaction), Err(e)),
                                    Err(e) => (None, Err(e)),
                                };
                            }

                            break (Some(transaction), Ok(()));
                        }
                    }

                    // Stage the previously found and loaded leaf node for an update.
                    let lookup_result_leaf_node = mem::replace(
                        &mut this.lookup_result.leaf_node,
                        InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                            nodes_staged_updates_slot_index: usize::MAX,
                        },
                    );
                    let nodes_staged_updates_leaf_slot_index = match lookup_result_leaf_node {
                        InodeIndexTreeNodeRefForUpdate::Owned {
                            node: leaf_node,
                            is_modified_by_transaction: leaf_is_modified_by_transaction,
                        } => {
                            let (
                                fs_instance,
                                _fs_sync_state_image_size,
                                fs_sync_state_alloc_bitmap,
                                _fs_sync_state_alloc_bitmap_file,
                                _fs_sync_state_auth_tree,
                                fs_sync_state_inode_index,
                                _fs_sync_state_read_buffer,
                                mut fs_sync_state_keys_cache,
                            ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();
                            let nodes_staged_updates_leaf_slot_index =
                                match transaction.inode_index_updates.reserve_tree_node_update_staging_slot(
                                    leaf_node.node_allocation_blocks_begin(),
                                    &[this
                                        .lookup_result
                                        .leaf_parent_node
                                        .as_ref()
                                        .and_then(|leaf_parent_node| {
                                            leaf_parent_node.get_nodes_staged_updates_slot_index()
                                        })],
                                    &mut transaction.allocs,
                                    &mut transaction.auth_tree_data_blocks_update_states,
                                    transaction.rng.as_mut(),
                                    &fs_instance.fs_config,
                                    fs_sync_state_alloc_bitmap,
                                    fs_sync_state_inode_index,
                                    &mut fs_sync_state_keys_cache,
                                ) {
                                    Ok(nodes_staged_updates_leaf_slot_index) => nodes_staged_updates_leaf_slot_index,
                                    Err(e) => {
                                        // Restore the lookup_result to its previous state.
                                        this.lookup_result.leaf_node = InodeIndexTreeNodeRefForUpdate::Owned {
                                            node: leaf_node,
                                            is_modified_by_transaction: leaf_is_modified_by_transaction,
                                        };

                                        break (Some(transaction), Err(e));
                                    }
                                };

                            transaction.inode_index_updates.tree_nodes_staged_updates
                                [nodes_staged_updates_leaf_slot_index] =
                                Some(TransactionInodeIndexUpdatesStagedTreeNode {
                                    node_level: 0,
                                    node: leaf_node,
                                });

                            this.lookup_result.leaf_node =
                                InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                    nodes_staged_updates_slot_index: nodes_staged_updates_leaf_slot_index,
                                };

                            nodes_staged_updates_leaf_slot_index
                        }
                        InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                            nodes_staged_updates_slot_index,
                        } => {
                            this.lookup_result.leaf_node =
                                InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                    nodes_staged_updates_slot_index,
                                };
                            nodes_staged_updates_slot_index
                        }
                    };

                    // Try to update the leaf node directly, which is possible if either there's a
                    // preexisting entry for the inode or already or the node has enough capacity
                    // left.
                    let [nodes_staged_updates_leaf_slot] =
                        match TransactionInodeIndexUpdates::get_tree_nodes_staged_updates_slots_mut(
                            &mut transaction.inode_index_updates.tree_nodes_staged_updates,
                            [nodes_staged_updates_leaf_slot_index],
                        ) {
                            Ok(nodes_staged_updates_leaf_slot) => nodes_staged_updates_leaf_slot,
                            Err(e) => break (Some(transaction), Err(e)),
                        };

                    let staged_update_leaf_node = match &mut nodes_staged_updates_leaf_slot.node {
                        InodeIndexTreeNode::Internal(_) => break (Some(transaction), Err(nvfs_err_internal!())),
                        InodeIndexTreeNode::Leaf(leaf_node) => leaf_node,
                    };

                    let tree_layout = &fs_instance_sync_state.inode_index.layout;
                    if this.lookup_result.preexisting_entry_extent_ptr.is_some()
                        || staged_update_leaf_node.entries < tree_layout.max_leaf_node_entries
                    {
                        // Now that it is known that no non-revertable allocations will be made for
                        // the index tree, it is safe to free the extents to be released on behalf
                        // of the invoking operation.
                        if let Err(e) = this
                            .pending_inode_extents_reallocation
                            .free_excess_preexisting_inode_extents(
                                &mut transaction.allocs,
                                &mut transaction.auth_tree_data_blocks_update_states,
                            )
                        {
                            break (Some(transaction), Err(e));
                        }
                        if let Err(e) = this
                            .pending_inode_extents_list_update
                            .free_excess_preexisting_inode_extents_list_extents(
                                &mut transaction.allocs,
                                &mut transaction.auth_tree_data_blocks_update_states,
                            )
                        {
                            break match this
                                .pending_inode_extents_reallocation
                                .rollback_excess_preexisting_inode_extents_free(
                                    transaction,
                                    &fs_instance_sync_state.alloc_bitmap,
                                ) {
                                Ok(transaction) => (Some(transaction), Err(e)),
                                Err(e) => (None, Err(e)),
                            };
                        }

                        if let Err(e) = staged_update_leaf_node.insert(
                            this.lookup_result.inode,
                            this.pending_inode_extents_list_update
                                .get_inode_index_entry_extent_ptr(),
                            None,
                            tree_layout,
                        ) {
                            let transaction = match this
                                .pending_inode_extents_list_update
                                .rollback_excess_preexisting_inode_extents_list_extents_free(
                                    transaction,
                                    &fs_instance_sync_state.alloc_bitmap,
                                ) {
                                Ok(transaction) => transaction,
                                Err(e) => break (None, Err(e)),
                            };

                            break match this
                                .pending_inode_extents_list_update
                                .rollback_excess_preexisting_inode_extents_list_extents_free(
                                    transaction,
                                    &fs_instance_sync_state.alloc_bitmap,
                                ) {
                                Ok(transaction) => (Some(transaction), Err(e)),
                                Err(e) => (None, Err(e)),
                            };
                        }

                        break (Some(transaction), Ok(()));
                    }

                    // Otherwise the leaf node is full, now it's a good time to load its parent, if
                    // any, into an update slot.
                    if let Some(leaf_parent_node) = this.lookup_result.leaf_parent_node.take() {
                        let nodes_staged_updates_leaf_parent_slot_index = match leaf_parent_node {
                            InodeIndexTreeNodeRefForUpdate::Owned {
                                node: leaf_parent_node,
                                is_modified_by_transaction: leaf_parent_is_modified_by_transaction,
                            } => {
                                let (
                                    fs_instance,
                                    _fs_sync_state_image_size,
                                    fs_sync_state_alloc_bitmap,
                                    _fs_sync_state_alloc_bitmap_file,
                                    _fs_sync_state_auth_tree,
                                    fs_sync_state_inode_index,
                                    _fs_sync_state_read_buffer,
                                    mut fs_sync_state_keys_cache,
                                ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();
                                let nodes_staged_updates_leaf_parent_slot_index =
                                    match transaction.inode_index_updates.reserve_tree_node_update_staging_slot(
                                        leaf_parent_node.node_allocation_blocks_begin(),
                                        &[Some(nodes_staged_updates_leaf_slot_index)],
                                        &mut transaction.allocs,
                                        &mut transaction.auth_tree_data_blocks_update_states,
                                        transaction.rng.as_mut(),
                                        &fs_instance.fs_config,
                                        fs_sync_state_alloc_bitmap,
                                        fs_sync_state_inode_index,
                                        &mut fs_sync_state_keys_cache,
                                    ) {
                                        Ok(nodes_staged_updates_leaf_parent_slot_index) => {
                                            nodes_staged_updates_leaf_parent_slot_index
                                        }
                                        Err(e) => {
                                            // Restore the lookup_result to its previous state.
                                            this.lookup_result.leaf_parent_node =
                                                Some(InodeIndexTreeNodeRefForUpdate::Owned {
                                                    node: leaf_parent_node,
                                                    is_modified_by_transaction: leaf_parent_is_modified_by_transaction,
                                                });

                                            break (Some(transaction), Err(e));
                                        }
                                    };

                                transaction.inode_index_updates.tree_nodes_staged_updates
                                    [nodes_staged_updates_leaf_parent_slot_index] =
                                    Some(TransactionInodeIndexUpdatesStagedTreeNode {
                                        node_level: 1,
                                        node: leaf_parent_node,
                                    });

                                this.lookup_result.leaf_parent_node =
                                    Some(InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                        nodes_staged_updates_slot_index: nodes_staged_updates_leaf_parent_slot_index,
                                    });

                                nodes_staged_updates_leaf_parent_slot_index
                            }
                            InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                nodes_staged_updates_slot_index,
                            } => {
                                this.lookup_result.leaf_parent_node =
                                    Some(InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                        nodes_staged_updates_slot_index,
                                    });
                                nodes_staged_updates_slot_index
                            }
                        };

                        this.fut_state = InodeIndexInsertEntryFutureState::TryRotatePrepare {
                            transaction: Some(transaction),
                            nodes_staged_updates_parent_slot_index: nodes_staged_updates_leaf_parent_slot_index,
                            nodes_staged_updates_child_slot_index: nodes_staged_updates_leaf_slot_index,
                        };
                    } else {
                        // A full leaf with no parent recorded in the lookup_result means the leaf
                        // is the root, so it must get split.
                        debug_assert_eq!(transaction.inode_index_updates.index_tree_levels, 1);
                        let fs_instance = fs_instance_sync_state.get_fs_ref();
                        let image_layout = &fs_instance.fs_config.image_layout;
                        let allocate_fut = match CocoonFsAllocateBlocksFuture::<ST, C>::new(
                            &fs_instance,
                            transaction,
                            image_layout.index_tree_node_allocation_blocks_log2 as u32,
                            2,
                            false,
                        ) {
                            Ok(allocate_fut) => allocate_fut,
                            Err((transaction, e)) => break (transaction, Err(e)),
                        };

                        this.fut_state = InodeIndexInsertEntryFutureState::SplitRootNode {
                            nodes_staged_updates_old_root_slot_index: nodes_staged_updates_leaf_slot_index,
                            allocate_fut,
                        };
                    }
                }
                InodeIndexInsertEntryFutureState::TryRotatePrepare {
                    transaction,
                    nodes_staged_updates_parent_slot_index,
                    nodes_staged_updates_child_slot_index,
                } => {
                    let transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => break (None, Err(nvfs_err_internal!())),
                    };

                    let nodes_staged_updates_parent_slot =
                        match TransactionInodeIndexUpdates::get_tree_nodes_staged_updates_slot(
                            &transaction.inode_index_updates.tree_nodes_staged_updates,
                            *nodes_staged_updates_parent_slot_index,
                        ) {
                            Ok(nodes_staged_updates_parent_slot) => nodes_staged_updates_parent_slot,
                            Err(e) => break (Some(transaction), Err(e)),
                        };

                    let parent_node = match &nodes_staged_updates_parent_slot.node {
                        InodeIndexTreeNode::Internal(internal_node) => internal_node,
                        InodeIndexTreeNode::Leaf(_) => break (Some(transaction), Err(nvfs_err_internal!())),
                    };

                    // Any internal node, including the root, should have at least two childs,
                    // i.e. at least one separator key.
                    if parent_node.entries == 0 {
                        break (
                            Some(transaction),
                            Err(NvFsError::from(CocoonFsFormatError::InvalidIndexNode)),
                        );
                    }

                    let tree_layout = &fs_instance_sync_state.inode_index.layout;
                    let child_index_in_parent = match parent_node.lookup_child(this.lookup_result.inode, tree_layout) {
                        Ok(child_index_in_parent) => child_index_in_parent,
                        Err(e) => break (Some(transaction), Err(e)),
                    };

                    let (at_left_sibling, sibling_child_index_in_parent) = if child_index_in_parent != 0 {
                        (true, child_index_in_parent - 1)
                    } else {
                        (false, child_index_in_parent + 1)
                    };

                    let sibling_child_node_allocation_blocks_begin = match parent_node
                        .encoded_entry_child_ptr(sibling_child_index_in_parent, tree_layout)
                        .and_then(|sibling_child_ptr| {
                            EncodedBlockPtr::from(*sibling_child_ptr).decode(
                                tree_layout
                                    .node_encrypted_block_layout
                                    .get_allocation_block_size_128b_log2() as u32,
                            )
                        })
                        .and_then(|sibling_child_node_allocation_blocks_begin| {
                            sibling_child_node_allocation_blocks_begin
                                .ok_or(NvFsError::from(CocoonFsFormatError::InvalidIndexNode))
                        }) {
                        Ok(sibling_child_node_allocation_blocks_begin) => sibling_child_node_allocation_blocks_begin,
                        Err(e) => break (Some(transaction), Err(e)),
                    };

                    let child_node_level = match parent_node.node_level(tree_layout) {
                        Ok(parent_node_level) => parent_node_level - 1,
                        Err(e) => break (Some(transaction), Err(e)),
                    };
                    let read_sibling_fut = InodeIndexReadTreeNodeFuture::new(
                        Some(transaction),
                        sibling_child_node_allocation_blocks_begin,
                        Some(child_node_level),
                        true,
                    );

                    this.fut_state = InodeIndexInsertEntryFutureState::TryRotate {
                        nodes_staged_updates_parent_slot_index: *nodes_staged_updates_parent_slot_index,
                        nodes_staged_updates_child_slot_index: *nodes_staged_updates_child_slot_index,
                        child_index_in_parent,
                        read_sibling_fut,
                        at_left_sibling,
                    }
                }
                InodeIndexInsertEntryFutureState::TryRotate {
                    nodes_staged_updates_parent_slot_index,
                    nodes_staged_updates_child_slot_index,
                    child_index_in_parent,
                    read_sibling_fut,
                    at_left_sibling,
                } => {
                    let (
                        fs_instance,
                        _fs_sync_state_image_size,
                        fs_sync_state_alloc_bitmap,
                        _fs_sync_state_alloc_bitmap_file,
                        mut fs_sync_state_auth_tree,
                        fs_sync_state_inode_index,
                        fs_sync_state_read_buffer,
                        mut fs_sync_state_keys_cache,
                    ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();

                    let (returned_transaction, sibling_child_node_ref) = match InodeIndexReadTreeNodeFuture::poll(
                        pin::Pin::new(read_sibling_fut),
                        &fs_instance.chip,
                        &fs_instance.fs_config,
                        fs_sync_state_alloc_bitmap,
                        &mut fs_sync_state_auth_tree,
                        &fs_sync_state_inode_index.layout,
                        &fs_sync_state_inode_index.tree_nodes_cache,
                        &fs_sync_state_inode_index.tree_node_decryption_instance,
                        fs_sync_state_read_buffer,
                        cx,
                    ) {
                        task::Poll::Ready((returned_transaction, Ok(sibling_child_node_ref))) => {
                            (returned_transaction, sibling_child_node_ref)
                        }
                        task::Poll::Ready((returned_transaction, Err(e))) => break (returned_transaction, Err(e)),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let tree_layout = &fs_sync_state_inode_index.layout;
                    if match sibling_child_node_ref.get_node() {
                        Ok(InodeIndexTreeNode::Internal(internal_node)) => {
                            // After a rotation, both sibling nodes should have one spare entry available.
                            internal_node.entries >= tree_layout.max_internal_node_entries - 1
                        }
                        Ok(InodeIndexTreeNode::Leaf(leaf_node)) => {
                            // After a rotation, both sibling nodes should have one spare entry available.
                            leaf_node.entries >= tree_layout.max_leaf_node_entries - 1
                        }
                        Err(e) => {
                            break (
                                returned_transaction.or(sibling_child_node_ref.into_transaction()),
                                Err(e),
                            )
                        }
                    } {
                        // The sibling is full, a rotation is not possible.
                        // Insert the unmodified sibling into a cache as appropriate and obtain the
                        // transaction back.
                        let transaction = match sibling_child_node_ref {
                            InodeIndexTreeNodeRef::Owned {
                                node: sibling_child_node,
                                is_modified_by_transaction: sibling_child_node_is_modified_by_transaction,
                            } => {
                                let mut transaction = match returned_transaction {
                                    Some(transaction) => transaction,
                                    None => break (None, Err(nvfs_err_internal!())),
                                };

                                let nodes_staged_updates_parent_slot =
                                    match TransactionInodeIndexUpdates::get_tree_nodes_staged_updates_slot(
                                        &transaction.inode_index_updates.tree_nodes_staged_updates,
                                        *nodes_staged_updates_parent_slot_index,
                                    ) {
                                        Ok(nodes_staged_updates_parent_slot) => nodes_staged_updates_parent_slot,
                                        Err(e) => break (Some(transaction), Err(e)),
                                    };
                                let parent_node = match &nodes_staged_updates_parent_slot.node {
                                    InodeIndexTreeNode::Internal(internal_node) => internal_node,
                                    InodeIndexTreeNode::Leaf(_) => {
                                        break (Some(transaction), Err(nvfs_err_internal!()))
                                    }
                                };
                                let child_node_level = match parent_node.node_level(tree_layout) {
                                    Ok(parent_node_level) => parent_node_level - 1,
                                    Err(e) => break (Some(transaction), Err(e)),
                                };

                                if sibling_child_node_is_modified_by_transaction {
                                    transaction
                                        .inode_index_updates
                                        .updated_tree_nodes_cache
                                        .insert(child_node_level, sibling_child_node);
                                } else {
                                    let mut tree_nodes_cache_guard = fs_sync_state_inode_index.tree_nodes_cache.write();
                                    tree_nodes_cache_guard.insert(child_node_level, sibling_child_node);
                                }

                                transaction
                            }
                            InodeIndexTreeNodeRef::CacheEntryRef { .. } => match returned_transaction {
                                Some(transaction) => transaction,
                                None => break (None, Err(nvfs_err_internal!())),
                            },
                            InodeIndexTreeNodeRef::TransactionStagedUpdatesNodeRef { transaction, .. }
                            | InodeIndexTreeNodeRef::TransactionUpdatedNodesCacheEntryRef { transaction, .. } => {
                                transaction
                            }
                        };

                        let nodes_staged_updates_parent_slot =
                            match TransactionInodeIndexUpdates::get_tree_nodes_staged_updates_slot(
                                &transaction.inode_index_updates.tree_nodes_staged_updates,
                                *nodes_staged_updates_parent_slot_index,
                            ) {
                                Ok(nodes_staged_updates_parent_slot) => nodes_staged_updates_parent_slot,
                                Err(e) => break (Some(transaction), Err(e)),
                            };
                        let parent_node = match &nodes_staged_updates_parent_slot.node {
                            InodeIndexTreeNode::Internal(internal_node) => internal_node,
                            InodeIndexTreeNode::Leaf(_) => break (Some(transaction), Err(nvfs_err_internal!())),
                        };
                        let parent_node_level = match parent_node.node_level(tree_layout) {
                            Ok(parent_node_level) => parent_node_level,
                            Err(e) => break (Some(transaction), Err(e)),
                        };

                        if !*at_left_sibling || *child_index_in_parent == parent_node.entries {
                            // No right sibling or it has just been tried with negative outcome. If
                            // the child is not the leaf, then we're in a preemptive split-rotate
                            // walk from the root and splitting the child is always
                            // possible. Otherwise it depends on whether the leaf's parent is full
                            // -- if it is, resort to a preemptive split-rotate walk from the root.
                            debug_assert!(
                                parent_node_level == 1 || parent_node.entries != tree_layout.max_internal_node_entries
                            );
                            if parent_node_level != 1 || parent_node.entries != tree_layout.max_internal_node_entries {
                                let image_layout = &fs_instance.fs_config.image_layout;
                                let allocate_fut = match CocoonFsAllocateBlockFuture::new(
                                    &fs_instance,
                                    transaction,
                                    image_layout.index_tree_node_allocation_blocks_log2 as u32,
                                    false,
                                ) {
                                    Ok(allocate_fut) => allocate_fut,
                                    Err((transaction, e)) => break (transaction, Err(e)),
                                };
                                this.fut_state = InodeIndexInsertEntryFutureState::SplitNode {
                                    nodes_staged_updates_parent_slot_index: *nodes_staged_updates_parent_slot_index,
                                    nodes_staged_updates_child_slot_index: *nodes_staged_updates_child_slot_index,
                                    child_index_in_parent: *child_index_in_parent,
                                    allocate_fut,
                                };
                            } else {
                                let root_node_allocation_blocks_begin =
                                    transaction.inode_index_updates.root_node_allocation_blocks_begin;
                                let root_node_level = transaction.inode_index_updates.index_tree_levels - 1;
                                let read_root_fut = InodeIndexReadTreeNodeFuture::new(
                                    Some(transaction),
                                    root_node_allocation_blocks_begin,
                                    Some(root_node_level),
                                    true,
                                );
                                this.fut_state = InodeIndexInsertEntryFutureState::PreemptiveRotateSplitWalkLoadRoot {
                                    read_root_fut,
                                };
                            }
                        } else {
                            // Try the right sibling instead.
                            let right_sibling_child_index = *child_index_in_parent + 1;
                            let right_sibling_child_node_allocation_blocks_begin = match parent_node
                                .encoded_entry_child_ptr(right_sibling_child_index, tree_layout)
                                .and_then(|sibling_child_ptr| {
                                    EncodedBlockPtr::from(*sibling_child_ptr).decode(
                                        tree_layout
                                            .node_encrypted_block_layout
                                            .get_allocation_block_size_128b_log2()
                                            as u32,
                                    )
                                })
                                .and_then(|sibling_child_node_allocation_blocks_begin| {
                                    sibling_child_node_allocation_blocks_begin
                                        .ok_or(NvFsError::from(CocoonFsFormatError::InvalidIndexNode))
                                }) {
                                Ok(sibling_child_node_allocation_blocks_begin) => {
                                    sibling_child_node_allocation_blocks_begin
                                }
                                Err(e) => break (Some(transaction), Err(e)),
                            };
                            let child_node_level = parent_node_level - 1;
                            let read_right_sibling_fut = InodeIndexReadTreeNodeFuture::new(
                                Some(transaction),
                                right_sibling_child_node_allocation_blocks_begin,
                                Some(child_node_level),
                                true,
                            );

                            *read_sibling_fut = read_right_sibling_fut;
                            *at_left_sibling = false;
                        }
                        continue;
                    }

                    // Alright, the nodes can get rotated.
                    // First get the sibling a update staging slot.
                    let (transaction, sibling_child_node_ref) =
                        InodeIndexTreeNodeRefForUpdate::try_from_node_ref(sibling_child_node_ref);
                    let transaction = transaction.or(returned_transaction);
                    let sibling_child_node_ref = match sibling_child_node_ref {
                        Ok(node_ref) => node_ref,
                        Err(e) => {
                            break (transaction, Err(e));
                        }
                    };
                    let mut transaction = match transaction {
                        Some(transaction) => transaction,
                        None => {
                            break (None, Err(nvfs_err_internal!()));
                        }
                    };

                    let nodes_staged_updates_sibling_child_slot_index = match sibling_child_node_ref {
                        InodeIndexTreeNodeRefForUpdate::Owned {
                            node: sibling_child_node,
                            ..
                        } => {
                            let nodes_staged_updates_sibling_child_slot_index =
                                match transaction.inode_index_updates.reserve_tree_node_update_staging_slot(
                                    sibling_child_node.node_allocation_blocks_begin(),
                                    &[
                                        this.lookup_result.leaf_node.get_nodes_staged_updates_slot_index(),
                                        this.lookup_result
                                            .leaf_parent_node
                                            .as_ref()
                                            .and_then(|leaf_parent_node| {
                                                leaf_parent_node.get_nodes_staged_updates_slot_index()
                                            }),
                                        Some(*nodes_staged_updates_parent_slot_index),
                                        Some(*nodes_staged_updates_child_slot_index),
                                    ],
                                    &mut transaction.allocs,
                                    &mut transaction.auth_tree_data_blocks_update_states,
                                    transaction.rng.as_mut(),
                                    &fs_instance.fs_config,
                                    fs_sync_state_alloc_bitmap,
                                    fs_sync_state_inode_index,
                                    &mut fs_sync_state_keys_cache,
                                ) {
                                    Ok(nodes_staged_updates_sibling_child_slot_index) => {
                                        nodes_staged_updates_sibling_child_slot_index
                                    }
                                    Err(e) => break (Some(transaction), Err(e)),
                                };

                            let sibling_child_node_level = match &sibling_child_node {
                                InodeIndexTreeNode::Internal(sibling_child_node) => {
                                    match sibling_child_node.node_level(tree_layout) {
                                        Ok(sibling_child_node_level) => sibling_child_node_level,
                                        Err(e) => break (Some(transaction), Err(e)),
                                    }
                                }
                                InodeIndexTreeNode::Leaf(_) => 0,
                            };

                            transaction.inode_index_updates.tree_nodes_staged_updates
                                [nodes_staged_updates_sibling_child_slot_index] =
                                Some(TransactionInodeIndexUpdatesStagedTreeNode {
                                    node_level: sibling_child_node_level,
                                    node: sibling_child_node,
                                });
                            nodes_staged_updates_sibling_child_slot_index
                        }
                        InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                            nodes_staged_updates_slot_index,
                        } => nodes_staged_updates_slot_index,
                    };

                    let [nodes_staged_updates_parent_slot, nodes_staged_updates_child_slot, nodes_staged_updates_sibling_child_slot] =
                        match TransactionInodeIndexUpdates::get_tree_nodes_staged_updates_slots_mut(
                            &mut transaction.inode_index_updates.tree_nodes_staged_updates,
                            [
                                *nodes_staged_updates_parent_slot_index,
                                *nodes_staged_updates_child_slot_index,
                                nodes_staged_updates_sibling_child_slot_index,
                            ],
                        ) {
                            Ok(slots) => slots,
                            Err(e) => break (Some(transaction), Err(e)),
                        };

                    let parent_node = match &mut nodes_staged_updates_parent_slot.node {
                        InodeIndexTreeNode::Internal(internal_node) => internal_node,
                        InodeIndexTreeNode::Leaf(_) => break (Some(transaction), Err(nvfs_err_internal!())),
                    };

                    match &mut nodes_staged_updates_child_slot.node {
                        InodeIndexTreeNode::Internal(child_node) => {
                            let sibling_child_node = match &mut nodes_staged_updates_sibling_child_slot.node {
                                InodeIndexTreeNode::Internal(sibling_child_node) => sibling_child_node,
                                InodeIndexTreeNode::Leaf(_) => {
                                    break (
                                        Some(transaction),
                                        Err(NvFsError::from(CocoonFsFormatError::InvalidIndexNode)),
                                    );
                                }
                            };

                            debug_assert_eq!(
                                child_node.entries,
                                fs_sync_state_inode_index.layout.max_internal_node_entries
                            );
                            let rotate_count = (child_node.entries - sibling_child_node.entries).div_ceil(2);
                            debug_assert!(
                                rotate_count >= 1
                                    && (sibling_child_node.entries + rotate_count)
                                        < fs_sync_state_inode_index.layout.max_internal_node_entries
                            );
                            let follow_sibling = if *at_left_sibling {
                                // Rotate left.
                                debug_assert!(*child_index_in_parent >= 1);
                                let parent_separator_key =
                                    match parent_node.get_separator_key(*child_index_in_parent - 1, tree_layout) {
                                        Ok(parent_separator_key) => parent_separator_key,
                                        Err(e) => break (Some(transaction), Err(e)),
                                    };
                                let new_parent_separator_key = match sibling_child_node.rotate_left(
                                    child_node,
                                    rotate_count,
                                    parent_separator_key,
                                    tree_layout,
                                ) {
                                    Ok(new_parent_separator_key) => new_parent_separator_key,
                                    Err(e) => {
                                        // If the rotation failed (due to an internal error), then
                                        // the transaction's view on the metadata is inconsistent.
                                        // Eat it.
                                        break (None, Err(e));
                                    }
                                };
                                if let Err(e) = parent_node.update_separator_key(
                                    *child_index_in_parent - 1,
                                    new_parent_separator_key,
                                    tree_layout,
                                ) {
                                    // Likewise.
                                    break (None, Err(e));
                                }
                                this.lookup_result.inode < InodeIndexKeyType::from_le_bytes(new_parent_separator_key)
                            } else {
                                // Rotate right.
                                let parent_separator_key =
                                    match parent_node.get_separator_key(*child_index_in_parent, tree_layout) {
                                        Ok(parent_separator_key) => parent_separator_key,
                                        Err(e) => break (Some(transaction), Err(e)),
                                    };
                                let new_parent_separator_key = match child_node.rotate_right(
                                    sibling_child_node,
                                    rotate_count,
                                    parent_separator_key,
                                    tree_layout,
                                ) {
                                    Ok(new_parent_separator_key) => new_parent_separator_key,
                                    Err(e) => {
                                        // If the rotation failed (due to an internal error), then
                                        // the transaction's view on the metadata is inconsistent.
                                        // Eat it.
                                        break (None, Err(e));
                                    }
                                };
                                if let Err(e) = parent_node.update_separator_key(
                                    *child_index_in_parent,
                                    new_parent_separator_key,
                                    tree_layout,
                                ) {
                                    // Likewise.
                                    break (None, Err(e));
                                }
                                this.lookup_result.inode >= InodeIndexKeyType::from_le_bytes(new_parent_separator_key)
                            };

                            // After having rotated now, descend and continue the preemptive rotate-split
                            // walk.
                            let nodes_staged_updates_next_parent_slot_index = if follow_sibling {
                                nodes_staged_updates_sibling_child_slot_index
                            } else {
                                *nodes_staged_updates_child_slot_index
                            };
                            this.fut_state =
                                InodeIndexInsertEntryFutureState::PreemptiveRotateSplitWalkLoadChildPrepare {
                                    transaction: Some(transaction),
                                    parent_node_ref: InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                        nodes_staged_updates_slot_index: nodes_staged_updates_next_parent_slot_index,
                                    },
                                };
                        }
                        InodeIndexTreeNode::Leaf(child_node) => {
                            let sibling_child_node = match &mut nodes_staged_updates_sibling_child_slot.node {
                                InodeIndexTreeNode::Leaf(sibling_child_node) => sibling_child_node,
                                InodeIndexTreeNode::Internal(_) => {
                                    break (
                                        Some(transaction),
                                        Err(NvFsError::from(CocoonFsFormatError::InvalidIndexNode)),
                                    );
                                }
                            };

                            debug_assert_eq!(
                                child_node.entries,
                                fs_sync_state_inode_index.layout.max_leaf_node_entries
                            );
                            let spill_count = (child_node.entries - sibling_child_node.entries).div_ceil(2);
                            debug_assert!(
                                spill_count >= 1
                                    && (sibling_child_node.entries + spill_count)
                                        < fs_sync_state_inode_index.layout.max_leaf_node_entries
                            );
                            let insert_into_sibling = if *at_left_sibling {
                                // Spill left.
                                debug_assert!(*child_index_in_parent >= 1);
                                let new_parent_separator_key =
                                    match sibling_child_node.spill_left(child_node, spill_count, tree_layout) {
                                        Ok(new_parent_separator_key) => new_parent_separator_key,
                                        Err(e) => {
                                            // If the spilling failed (due to an internal error), then
                                            // the transaction's view on the metadata is inconsistent.
                                            // Eat it.
                                            break (None, Err(e));
                                        }
                                    };
                                if let Err(e) = parent_node.update_separator_key(
                                    *child_index_in_parent - 1,
                                    new_parent_separator_key,
                                    tree_layout,
                                ) {
                                    // Likewise.
                                    break (None, Err(e));
                                }
                                this.lookup_result.inode < InodeIndexKeyType::from_le_bytes(new_parent_separator_key)
                            } else {
                                // Spill right.
                                let new_parent_separator_key =
                                    match child_node.spill_right(sibling_child_node, spill_count, tree_layout) {
                                        Ok(new_parent_separator_key) => new_parent_separator_key,
                                        Err(e) => {
                                            // If the spilling failed (due to an internal error), then
                                            // the transaction's view on the metadata is inconsistent.
                                            // Eat it.
                                            break (None, Err(e));
                                        }
                                    };
                                if let Err(e) = parent_node.update_separator_key(
                                    *child_index_in_parent,
                                    new_parent_separator_key,
                                    tree_layout,
                                ) {
                                    // Likewise.
                                    break (None, Err(e));
                                }
                                this.lookup_result.inode >= InodeIndexKeyType::from_le_bytes(new_parent_separator_key)
                            };

                            // Now that it is known that no non-revertable allocations will be made
                            // for the index tree, it is safe to free the blocks to be released on
                            // behalf of the invoking operation.
                            if let Err(e) = this
                                .pending_inode_extents_reallocation
                                .free_excess_preexisting_inode_extents(
                                    &mut transaction.allocs,
                                    &mut transaction.auth_tree_data_blocks_update_states,
                                )
                            {
                                break (Some(transaction), Err(e));
                            }
                            if let Err(e) = this
                                .pending_inode_extents_list_update
                                .free_excess_preexisting_inode_extents_list_extents(
                                    &mut transaction.allocs,
                                    &mut transaction.auth_tree_data_blocks_update_states,
                                )
                            {
                                break match this
                                    .pending_inode_extents_reallocation
                                    .rollback_excess_preexisting_inode_extents_free(
                                        transaction,
                                        fs_sync_state_alloc_bitmap,
                                    ) {
                                    Ok(transaction) => (Some(transaction), Err(e)),
                                    Err(e) => (None, Err(e)),
                                };
                            }

                            let leaf_node = if insert_into_sibling {
                                sibling_child_node
                            } else {
                                child_node
                            };

                            if let Err(e) = leaf_node.insert(
                                this.lookup_result.inode,
                                this.pending_inode_extents_list_update
                                    .get_inode_index_entry_extent_ptr(),
                                None,
                                tree_layout,
                            ) {
                                // If the insertion failed (due to an internal error), then the
                                // transaction's view on the metadata is inconsistent. Eat it.
                                break (None, Err(e));
                            }
                            break (Some(transaction), Ok(()));
                        }
                    }
                }
                InodeIndexInsertEntryFutureState::SplitRootNode {
                    nodes_staged_updates_old_root_slot_index,
                    allocate_fut,
                } => {
                    let (mut transaction, allocated_nodes_blocks) = match CocoonFsSyncStateReadFuture::poll(
                        pin::Pin::new(allocate_fut),
                        fs_instance_sync_state,
                        &mut (),
                        cx,
                    ) {
                        task::Poll::Ready(Ok((transaction, Ok(allocated_nodes_blocks)))) => {
                            (transaction, allocated_nodes_blocks)
                        }
                        task::Poll::Ready(Ok((transaction, Err(e)))) => break (Some(transaction), Err(e)),
                        task::Poll::Ready(Err(e)) => break (None, Err(e)),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let (
                        fs_instance,
                        _fs_sync_state_image_size,
                        fs_sync_state_alloc_bitmap,
                        _fs_sync_state_alloc_bitmap_file,
                        _fs_sync_state_auth_tree,
                        fs_sync_state_inode_index,
                        _fs_sync_state_read_buffer,
                        mut fs_sync_state_keys_cache,
                    ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();

                    let image_layout = &fs_instance.fs_config.image_layout;

                    let rollback_nodes_blocks_allocation =
                        |transaction: Box<transaction::Transaction>,
                         allocated_nodes_blocks: &[layout::PhysicalAllocBlockIndex]| {
                            transaction.rollback_blocks_allocation(
                                allocated_nodes_blocks.iter().copied(),
                                image_layout.index_tree_node_allocation_blocks_log2 as u32,
                                fs_sync_state_alloc_bitmap,
                            )
                        };

                    // Get the two new nodes some update staging blocks. Do it before the actual
                    // split (which is a point of no return), because the reservation can fail.
                    let nodes_staged_updates_new_root_slot_index =
                        match transaction.inode_index_updates.reserve_tree_node_update_staging_slot(
                            allocated_nodes_blocks[0],
                            &[
                                this.lookup_result.leaf_node.get_nodes_staged_updates_slot_index(),
                                this.lookup_result
                                    .leaf_parent_node
                                    .as_ref()
                                    .and_then(|leaf_parent_node| {
                                        leaf_parent_node.get_nodes_staged_updates_slot_index()
                                    }),
                                Some(*nodes_staged_updates_old_root_slot_index),
                            ],
                            &mut transaction.allocs,
                            &mut transaction.auth_tree_data_blocks_update_states,
                            transaction.rng.as_mut(),
                            &fs_instance.fs_config,
                            fs_sync_state_alloc_bitmap,
                            fs_sync_state_inode_index,
                            &mut fs_sync_state_keys_cache,
                        ) {
                            Ok(nodes_staged_updates_new_root_slot_index) => nodes_staged_updates_new_root_slot_index,
                            Err(e) => {
                                break match rollback_nodes_blocks_allocation(transaction, &allocated_nodes_blocks) {
                                    Ok(transaction) => (Some(transaction), Err(e)),
                                    Err(e) => (None, Err(e)),
                                };
                            }
                        };

                    // Allocate a new root before the split, as the memory allocation could fail.
                    let new_root_node_level = transaction.inode_index_updates.index_tree_levels;
                    let tree_layout = &fs_sync_state_inode_index.layout;
                    let mut new_empty_root_node = match InodeIndexTreeInternalNode::new_empty_root(
                        allocated_nodes_blocks[0],
                        new_root_node_level,
                        tree_layout,
                    ) {
                        Ok(new_empty_root_node) => new_empty_root_node,
                        Err(e) => {
                            break match rollback_nodes_blocks_allocation(transaction, &allocated_nodes_blocks) {
                                Ok(transaction) => (Some(transaction), Err(e)),
                                Err(e) => (None, Err(e)),
                            };
                        }
                    };

                    let nodes_staged_updates_new_sibling_slot_index = match transaction
                        .inode_index_updates
                        .reserve_tree_node_update_staging_slot(
                            allocated_nodes_blocks[1],
                            &[
                                this.lookup_result.leaf_node.get_nodes_staged_updates_slot_index(),
                                this.lookup_result
                                    .leaf_parent_node
                                    .as_ref()
                                    .and_then(|leaf_parent_node| {
                                        leaf_parent_node.get_nodes_staged_updates_slot_index()
                                    }),
                                Some(*nodes_staged_updates_old_root_slot_index),
                                Some(nodes_staged_updates_new_root_slot_index),
                            ],
                            &mut transaction.allocs,
                            &mut transaction.auth_tree_data_blocks_update_states,
                            transaction.rng.as_mut(),
                            &fs_instance.fs_config,
                            fs_sync_state_alloc_bitmap,
                            fs_sync_state_inode_index,
                            &mut fs_sync_state_keys_cache,
                        ) {
                        Ok(nodes_staged_updates_new_sibling_slot_index) => nodes_staged_updates_new_sibling_slot_index,
                        Err(e) => {
                            break match rollback_nodes_blocks_allocation(transaction, &allocated_nodes_blocks) {
                                Ok(transaction) => (Some(transaction), Err(e)),
                                Err(e) => (None, Err(e)),
                            };
                        }
                    };

                    let [nodes_staged_updates_old_root_slot] =
                        match TransactionInodeIndexUpdates::get_tree_nodes_staged_updates_slots_mut(
                            &mut transaction.inode_index_updates.tree_nodes_staged_updates,
                            [*nodes_staged_updates_old_root_slot_index],
                        ) {
                            Ok(nodes_staged_updates_old_root_slot) => nodes_staged_updates_old_root_slot,
                            Err(e) => {
                                break match rollback_nodes_blocks_allocation(transaction, &allocated_nodes_blocks) {
                                    Ok(transaction) => (Some(transaction), Err(e)),
                                    Err(e) => (None, Err(e)),
                                };
                            }
                        };

                    // Do the actual split.
                    let (new_sibling_node, parent_separator_key, old_root_node_allocation_blocks_begin) =
                        match &mut nodes_staged_updates_old_root_slot.node {
                            InodeIndexTreeNode::Internal(old_root_node) => {
                                match old_root_node.split(allocated_nodes_blocks[1], tree_layout) {
                                    Ok((new_sibling_node, parent_separator_key)) => (
                                        InodeIndexTreeNode::Internal(new_sibling_node),
                                        parent_separator_key,
                                        old_root_node.node_allocation_blocks_begin,
                                    ),
                                    Err(e) => {
                                        if !matches!(e, NvFsError::MemoryAllocationFailure) {
                                            // The transaction's view of the metadata is
                                            // inconsistent, consume the transaction.
                                            break (None, Err(e));
                                        } else {
                                            break match rollback_nodes_blocks_allocation(
                                                transaction,
                                                &allocated_nodes_blocks,
                                            ) {
                                                Ok(transaction) => (Some(transaction), Err(e)),
                                                Err(e) => (None, Err(e)),
                                            };
                                        }
                                    }
                                }
                            }
                            InodeIndexTreeNode::Leaf(old_root_node) => {
                                let insertion_pos = match old_root_node.lookup(this.lookup_result.inode, tree_layout) {
                                    Ok(Err(insertion_pos)) => insertion_pos,
                                    Ok(Ok(_)) => {
                                        // It is known at this point that the entry does not exist yet.
                                        break match rollback_nodes_blocks_allocation(
                                            transaction,
                                            &allocated_nodes_blocks,
                                        ) {
                                            Ok(transaction) => (Some(transaction), Err(nvfs_err_internal!())),
                                            Err(e) => (None, Err(e)),
                                        };
                                    }
                                    Err(e) => {
                                        break match rollback_nodes_blocks_allocation(
                                            transaction,
                                            &allocated_nodes_blocks,
                                        ) {
                                            Ok(transaction) => (Some(transaction), Err(e)),
                                            Err(e) => (None, Err(e)),
                                        };
                                    }
                                };

                                // Now that it is known that no more non-revertable allocations will be done
                                // for the index tree, it is safe to free the blocks to be released from
                                // the invoking operation.
                                if let Err(e) = this
                                    .pending_inode_extents_reallocation
                                    .free_excess_preexisting_inode_extents(
                                        &mut transaction.allocs,
                                        &mut transaction.auth_tree_data_blocks_update_states,
                                    )
                                {
                                    break (Some(transaction), Err(e));
                                }
                                if let Err(e) = this
                                    .pending_inode_extents_list_update
                                    .free_excess_preexisting_inode_extents_list_extents(
                                        &mut transaction.allocs,
                                        &mut transaction.auth_tree_data_blocks_update_states,
                                    )
                                {
                                    break match this
                                        .pending_inode_extents_reallocation
                                        .rollback_excess_preexisting_inode_extents_free(
                                            transaction,
                                            fs_sync_state_alloc_bitmap,
                                        ) {
                                        Ok(transaction) => (Some(transaction), Err(e)),
                                        Err(e) => (None, Err(e)),
                                    };
                                }

                                match old_root_node.split_insert(
                                    this.lookup_result.inode,
                                    this.pending_inode_extents_list_update
                                        .get_inode_index_entry_extent_ptr(),
                                    insertion_pos,
                                    allocated_nodes_blocks[1],
                                    tree_layout,
                                ) {
                                    Ok((new_sibling_node, parent_separator_key)) => (
                                        InodeIndexTreeNode::Leaf(new_sibling_node),
                                        parent_separator_key,
                                        old_root_node.node_allocation_blocks_begin,
                                    ),
                                    Err(e) => {
                                        if !matches!(e, NvFsError::MemoryAllocationFailure) {
                                            // The transaction's view of the metadata is
                                            // inconsistent, consume the transaction.
                                            break (None, Err(e));
                                        }

                                        let transaction = match this
                                            .pending_inode_extents_list_update
                                            .rollback_excess_preexisting_inode_extents_list_extents_free(
                                                transaction,
                                                fs_sync_state_alloc_bitmap,
                                            ) {
                                            Ok(transaction) => transaction,
                                            Err(e) => break (None, Err(e)),
                                        };
                                        let transaction = match this
                                            .pending_inode_extents_reallocation
                                            .rollback_excess_preexisting_inode_extents_free(
                                                transaction,
                                                fs_sync_state_alloc_bitmap,
                                            ) {
                                            Ok(transaction) => transaction,
                                            Err(e) => break (None, Err(e)),
                                        };

                                        break match rollback_nodes_blocks_allocation(
                                            transaction,
                                            &allocated_nodes_blocks,
                                        ) {
                                            Ok(transaction) => (Some(transaction), Err(e)),
                                            Err(e) => (None, Err(e)),
                                        };
                                    }
                                }
                            }
                        };

                    let left_child_ptr = match EncodedBlockPtr::encode(Some(old_root_node_allocation_blocks_begin)) {
                        Ok(left_child_ptr) => left_child_ptr,
                        Err(e) => {
                            // The transaction's view of the metadata is inconsistent,
                            // consume the transaction.
                            break (None, Err(e));
                        }
                    };
                    let right_child_ptr = match EncodedBlockPtr::encode(Some(allocated_nodes_blocks[1])) {
                        Ok(right_child_ptr) => right_child_ptr,
                        Err(e) => {
                            // The transaction's view of the metadata is inconsistent,
                            // consume the transaction.
                            break (None, Err(e));
                        }
                    };
                    if let Err(e) = new_empty_root_node.init_empty_root(
                        left_child_ptr,
                        right_child_ptr,
                        parent_separator_key,
                        tree_layout,
                    ) {
                        // The transaction's view of the metadata is inconsistent,
                        // consume the transaction.
                        break (None, Err(e));
                    };

                    transaction.inode_index_updates.tree_nodes_staged_updates
                        [nodes_staged_updates_new_root_slot_index] = Some(TransactionInodeIndexUpdatesStagedTreeNode {
                        node_level: new_root_node_level,
                        node: InodeIndexTreeNode::Internal(new_empty_root_node),
                    });
                    transaction.inode_index_updates.tree_nodes_staged_updates
                        [nodes_staged_updates_new_sibling_slot_index] =
                        Some(TransactionInodeIndexUpdatesStagedTreeNode {
                            node_level: new_root_node_level - 1,
                            node: new_sibling_node,
                        });

                    transaction.inode_index_updates.index_tree_levels = new_root_node_level + 1;
                    transaction
                        .inode_index_updates
                        .updated_tree_nodes_cache
                        .reconfigure(transaction.inode_index_updates.index_tree_levels);
                    transaction.inode_index_updates.root_node_allocation_blocks_begin = allocated_nodes_blocks[0];
                    transaction.inode_index_updates.root_node_inode_needs_update = true;

                    // Determine what to do next. This is a reborrow, it cannot really fail. If it
                    // still does, consume the transaction to avoid rolling back the inode extents
                    // reallocations + updated extents lists potentially being referenced now from
                    // the leaf entry updated above.
                    let nodes_staged_updates_old_root_slot =
                        match TransactionInodeIndexUpdates::get_tree_nodes_staged_updates_slot(
                            &transaction.inode_index_updates.tree_nodes_staged_updates,
                            *nodes_staged_updates_old_root_slot_index,
                        ) {
                            Ok(nodes_staged_updates_old_root_slot) => nodes_staged_updates_old_root_slot,
                            Err(e) => break (None, Err(e)),
                        };
                    match &nodes_staged_updates_old_root_slot.node {
                        InodeIndexTreeNode::Internal(_) => {
                            let follow_sibling =
                                this.lookup_result.inode >= InodeIndexKeyType::from_le_bytes(parent_separator_key);
                            let next_parent_node_ref =
                                InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                    nodes_staged_updates_slot_index: if follow_sibling {
                                        nodes_staged_updates_new_sibling_slot_index
                                    } else {
                                        *nodes_staged_updates_old_root_slot_index
                                    },
                                };
                            this.fut_state =
                                InodeIndexInsertEntryFutureState::PreemptiveRotateSplitWalkLoadChildPrepare {
                                    transaction: Some(transaction),
                                    parent_node_ref: next_parent_node_ref,
                                };
                        }
                        InodeIndexTreeNode::Leaf(_) => {
                            // All done.
                            break (Some(transaction), Ok(()));
                        }
                    }
                }
                InodeIndexInsertEntryFutureState::SplitNode {
                    nodes_staged_updates_parent_slot_index,
                    nodes_staged_updates_child_slot_index,
                    child_index_in_parent,
                    allocate_fut,
                } => {
                    let (mut transaction, allocated_node_block) = match CocoonFsSyncStateReadFuture::poll(
                        pin::Pin::new(allocate_fut),
                        fs_instance_sync_state,
                        &mut (),
                        cx,
                    ) {
                        task::Poll::Ready(Ok((transaction, Ok(allocated_node_block)))) => {
                            (transaction, allocated_node_block)
                        }
                        task::Poll::Ready(Ok((transaction, Err(e)))) => break (Some(transaction), Err(e)),
                        task::Poll::Ready(Err(e)) => break (None, Err(e)),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let (
                        fs_instance,
                        _fs_sync_state_image_size,
                        fs_sync_state_alloc_bitmap,
                        _fs_sync_state_alloc_bitmap_file,
                        _fs_sync_state_auth_tree,
                        fs_sync_state_inode_index,
                        _fs_sync_state_read_buffer,
                        mut fs_sync_state_keys_cache,
                    ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();

                    let image_layout = &fs_instance.fs_config.image_layout;

                    let rollback_node_block_allocation =
                        |transaction: Box<transaction::Transaction>,
                         allocated_node_block: layout::PhysicalAllocBlockIndex| {
                            transaction.rollback_block_allocation(
                                allocated_node_block,
                                image_layout.index_tree_node_allocation_blocks_log2 as u32,
                                fs_sync_state_alloc_bitmap,
                            )
                        };

                    // Get the new node some update staging block. Do it before the actual
                    // split (which is a point of no return), because the reservation can fail.
                    let nodes_staged_updates_new_child_sibling_slot_index =
                        match transaction.inode_index_updates.reserve_tree_node_update_staging_slot(
                            allocated_node_block,
                            &[
                                this.lookup_result.leaf_node.get_nodes_staged_updates_slot_index(),
                                this.lookup_result
                                    .leaf_parent_node
                                    .as_ref()
                                    .and_then(|leaf_parent_node| {
                                        leaf_parent_node.get_nodes_staged_updates_slot_index()
                                    }),
                                Some(*nodes_staged_updates_parent_slot_index),
                                Some(*nodes_staged_updates_child_slot_index),
                            ],
                            &mut transaction.allocs,
                            &mut transaction.auth_tree_data_blocks_update_states,
                            transaction.rng.as_mut(),
                            &fs_instance.fs_config,
                            fs_sync_state_alloc_bitmap,
                            fs_sync_state_inode_index,
                            &mut fs_sync_state_keys_cache,
                        ) {
                            Ok(nodes_staged_updates_new_child_sibling_slot_index) => {
                                nodes_staged_updates_new_child_sibling_slot_index
                            }
                            Err(e) => {
                                break match rollback_node_block_allocation(transaction, allocated_node_block) {
                                    Ok(transaction) => (Some(transaction), Err(e)),
                                    Err(e) => (None, Err(e)),
                                };
                            }
                        };

                    let [nodes_staged_updates_parent_slot, nodes_staged_updates_child_slot] =
                        match TransactionInodeIndexUpdates::get_tree_nodes_staged_updates_slots_mut(
                            &mut transaction.inode_index_updates.tree_nodes_staged_updates,
                            [
                                *nodes_staged_updates_parent_slot_index,
                                *nodes_staged_updates_child_slot_index,
                            ],
                        ) {
                            Ok(slots) => slots,
                            Err(e) => {
                                break match rollback_node_block_allocation(transaction, allocated_node_block) {
                                    Ok(transaction) => (Some(transaction), Err(e)),
                                    Err(e) => (None, Err(e)),
                                };
                            }
                        };

                    let parent_node = match &mut nodes_staged_updates_parent_slot.node {
                        InodeIndexTreeNode::Internal(parent_node) => parent_node,
                        InodeIndexTreeNode::Leaf(_) => {
                            break match rollback_node_block_allocation(transaction, allocated_node_block) {
                                Ok(transaction) => (Some(transaction), Err(nvfs_err_internal!())),
                                Err(e) => (None, Err(e)),
                            };
                        }
                    };

                    // Do the actual split.
                    let tree_layout = &fs_sync_state_inode_index.layout;
                    let (new_child_sibling_node, parent_separator_key) = match &mut nodes_staged_updates_child_slot.node
                    {
                        InodeIndexTreeNode::Internal(child_node) => {
                            match child_node.split(allocated_node_block, tree_layout) {
                                Ok((new_child_sibling_node, parent_separator_key)) => (
                                    InodeIndexTreeNode::Internal(new_child_sibling_node),
                                    parent_separator_key,
                                ),
                                Err(e) => {
                                    if !matches!(e, NvFsError::MemoryAllocationFailure) {
                                        // The transaction's view of the metadata is
                                        // inconsistent, consume the transaction.
                                        break (None, Err(e));
                                    } else {
                                        break match rollback_node_block_allocation(transaction, allocated_node_block) {
                                            Ok(transaction) => (Some(transaction), Err(e)),
                                            Err(e) => (None, Err(e)),
                                        };
                                    }
                                }
                            }
                        }
                        InodeIndexTreeNode::Leaf(child_node) => {
                            let insertion_pos = match child_node.lookup(this.lookup_result.inode, tree_layout) {
                                Ok(Err(insertion_pos)) => insertion_pos,
                                Ok(Ok(_)) => {
                                    // It is known at this point that the entry does not exist yet.
                                    // Reset the staged update slot initialized above with the new root.
                                    break match rollback_node_block_allocation(transaction, allocated_node_block) {
                                        Ok(transaction) => (Some(transaction), Err(nvfs_err_internal!())),
                                        Err(e) => (None, Err(e)),
                                    };
                                }
                                Err(e) => {
                                    break match rollback_node_block_allocation(transaction, allocated_node_block) {
                                        Ok(transaction) => (Some(transaction), Err(e)),
                                        Err(e) => (None, Err(e)),
                                    };
                                }
                            };

                            // Now that it is known that no more non-revertable allocations will be done
                            // for the index tree, it is safe to free the blocks to be released from
                            // the invoking operation.
                            if let Err(e) = this
                                .pending_inode_extents_reallocation
                                .free_excess_preexisting_inode_extents(
                                    &mut transaction.allocs,
                                    &mut transaction.auth_tree_data_blocks_update_states,
                                )
                            {
                                break (Some(transaction), Err(e));
                            }
                            if let Err(e) = this
                                .pending_inode_extents_list_update
                                .free_excess_preexisting_inode_extents_list_extents(
                                    &mut transaction.allocs,
                                    &mut transaction.auth_tree_data_blocks_update_states,
                                )
                            {
                                break match this
                                    .pending_inode_extents_reallocation
                                    .rollback_excess_preexisting_inode_extents_free(
                                        transaction,
                                        fs_sync_state_alloc_bitmap,
                                    ) {
                                    Ok(transaction) => (Some(transaction), Err(e)),
                                    Err(e) => (None, Err(e)),
                                };
                            }

                            match child_node.split_insert(
                                this.lookup_result.inode,
                                this.pending_inode_extents_list_update
                                    .get_inode_index_entry_extent_ptr(),
                                insertion_pos,
                                allocated_node_block,
                                tree_layout,
                            ) {
                                Ok((new_sibling_node, parent_separator_key)) => {
                                    (InodeIndexTreeNode::Leaf(new_sibling_node), parent_separator_key)
                                }
                                Err(e) => {
                                    if !matches!(e, NvFsError::MemoryAllocationFailure) {
                                        // The transaction's view of the metadata is
                                        // inconsistent, consume the transaction.
                                        break (None, Err(e));
                                    }

                                    let transaction = match this
                                        .pending_inode_extents_list_update
                                        .rollback_excess_preexisting_inode_extents_list_extents_free(
                                            transaction,
                                            fs_sync_state_alloc_bitmap,
                                        ) {
                                        Ok(transaction) => transaction,
                                        Err(e) => break (None, Err(e)),
                                    };
                                    let transaction = match this
                                        .pending_inode_extents_reallocation
                                        .rollback_excess_preexisting_inode_extents_free(
                                            transaction,
                                            fs_sync_state_alloc_bitmap,
                                        ) {
                                        Ok(transaction) => transaction,
                                        Err(e) => break (None, Err(e)),
                                    };

                                    break match rollback_node_block_allocation(transaction, allocated_node_block) {
                                        Ok(transaction) => (Some(transaction), Err(e)),
                                        Err(e) => (None, Err(e)),
                                    };
                                }
                            }
                        }
                    };

                    // Update the parent.
                    let right_child_ptr = match EncodedBlockPtr::encode(Some(allocated_node_block)) {
                        Ok(right_child_ptr) => right_child_ptr,
                        Err(e) => {
                            // The transaction's view of the metadata is inconsistent,
                            // consume the transaction.
                            break (None, Err(e));
                        }
                    };
                    if let Err(e) = parent_node.insert(
                        *child_index_in_parent,
                        parent_separator_key,
                        right_child_ptr,
                        tree_layout,
                    ) {
                        // The transaction's view of the metadata is inconsistent,
                        // consume the transaction.
                        break (None, Err(e));
                    }

                    let parent_node_level = match parent_node.node_level(tree_layout) {
                        Ok(parent_node_level) => parent_node_level,
                        Err(e) => {
                            // The transaction's view of the metadata is inconsistent,
                            // consume the transaction.
                            break (None, Err(e));
                        }
                    };

                    transaction.inode_index_updates.tree_nodes_staged_updates
                        [nodes_staged_updates_new_child_sibling_slot_index] =
                        Some(TransactionInodeIndexUpdatesStagedTreeNode {
                            node_level: parent_node_level - 1,
                            node: new_child_sibling_node,
                        });

                    // Determine what to do next.  This is a reborrow, it cannot really fail. If it
                    // still does, consume the transaction to avoid rolling back the inode extents
                    // reallocations + updated extents lists potentially being referenced now from
                    // the leaf entry updated above.
                    let nodes_staged_updates_child_slot =
                        match TransactionInodeIndexUpdates::get_tree_nodes_staged_updates_slot(
                            &transaction.inode_index_updates.tree_nodes_staged_updates,
                            *nodes_staged_updates_child_slot_index,
                        ) {
                            Ok(nodes_staged_updates_child_slot) => nodes_staged_updates_child_slot,
                            Err(e) => break (None, Err(e)),
                        };
                    match &nodes_staged_updates_child_slot.node {
                        InodeIndexTreeNode::Internal(_) => {
                            let follow_sibling =
                                this.lookup_result.inode >= InodeIndexKeyType::from_le_bytes(parent_separator_key);
                            let next_parent_node_ref =
                                InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                    nodes_staged_updates_slot_index: if follow_sibling {
                                        nodes_staged_updates_new_child_sibling_slot_index
                                    } else {
                                        *nodes_staged_updates_child_slot_index
                                    },
                                };
                            this.fut_state =
                                InodeIndexInsertEntryFutureState::PreemptiveRotateSplitWalkLoadChildPrepare {
                                    transaction: Some(transaction),
                                    parent_node_ref: next_parent_node_ref,
                                };
                        }
                        InodeIndexTreeNode::Leaf(_) => {
                            // All done.
                            break (Some(transaction), Ok(()));
                        }
                    }
                }
                InodeIndexInsertEntryFutureState::PreemptiveRotateSplitWalkLoadRoot { read_root_fut } => {
                    let (
                        fs_instance,
                        _fs_sync_state_image_size,
                        fs_sync_state_alloc_bitmap,
                        _fs_sync_state_alloc_bitmap_file,
                        mut fs_sync_state_auth_tree,
                        fs_sync_state_inode_index,
                        fs_sync_state_read_buffer,
                        mut fs_sync_state_keys_cache,
                    ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();

                    let (returned_transaction, root_node_ref) = match InodeIndexReadTreeNodeFuture::poll(
                        pin::Pin::new(read_root_fut),
                        &fs_instance.chip,
                        &fs_instance.fs_config,
                        fs_sync_state_alloc_bitmap,
                        &mut fs_sync_state_auth_tree,
                        &fs_sync_state_inode_index.layout,
                        &fs_sync_state_inode_index.tree_nodes_cache,
                        &fs_sync_state_inode_index.tree_node_decryption_instance,
                        fs_sync_state_read_buffer,
                        cx,
                    ) {
                        task::Poll::Ready((returned_transaction, Ok(sibling_child_node_ref))) => {
                            (returned_transaction, sibling_child_node_ref)
                        }
                        task::Poll::Ready((returned_transaction, Err(e))) => break (returned_transaction, Err(e)),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let (transaction, root_node_ref) = InodeIndexTreeNodeRefForUpdate::try_from_node_ref(root_node_ref);
                    let transaction = transaction.or(returned_transaction);
                    let root_node_ref = match root_node_ref {
                        Ok(node_ref) => node_ref,
                        Err(e) => {
                            break (transaction, Err(e));
                        }
                    };
                    let mut transaction = match transaction {
                        Some(transaction) => transaction,
                        None => {
                            break (None, Err(nvfs_err_internal!()));
                        }
                    };

                    let root_node = match root_node_ref.get_node(&transaction) {
                        Ok(root_node) => root_node,
                        Err(e) => break (Some(transaction), Err(e)),
                    };
                    let root_node = match root_node {
                        InodeIndexTreeNode::Internal(root_node) => root_node,
                        InodeIndexTreeNode::Leaf(_) => {
                            // A full leaf node at the root would have been
                            // split up right away.
                            break (Some(transaction), Err(nvfs_err_internal!()));
                        }
                    };

                    let tree_layout = &fs_sync_state_inode_index.layout;
                    let image_layout = &fs_instance.fs_config.image_layout;
                    if root_node.entries == tree_layout.max_internal_node_entries {
                        // Root node is full, split it preemptively.
                        // Get the root node an update staging slot.
                        let nodes_staged_updates_root_slot_index = match root_node_ref {
                            InodeIndexTreeNodeRefForUpdate::Owned { node: root_node, .. } => {
                                let nodes_staged_updates_root_slot_index = match transaction
                                    .inode_index_updates
                                    .reserve_tree_node_update_staging_slot(
                                        root_node.node_allocation_blocks_begin(),
                                        &[
                                            this.lookup_result.leaf_node.get_nodes_staged_updates_slot_index(),
                                            this.lookup_result
                                                .leaf_parent_node
                                                .as_ref()
                                                .and_then(|leaf_parent_node| {
                                                    leaf_parent_node.get_nodes_staged_updates_slot_index()
                                                }),
                                        ],
                                        &mut transaction.allocs,
                                        &mut transaction.auth_tree_data_blocks_update_states,
                                        transaction.rng.as_mut(),
                                        &fs_instance.fs_config,
                                        fs_sync_state_alloc_bitmap,
                                        fs_sync_state_inode_index,
                                        &mut fs_sync_state_keys_cache,
                                    ) {
                                    Ok(nodes_staged_updates_root_slot_index) => nodes_staged_updates_root_slot_index,
                                    Err(e) => break (Some(transaction), Err(e)),
                                };

                                transaction.inode_index_updates.tree_nodes_staged_updates
                                    [nodes_staged_updates_root_slot_index] =
                                    Some(TransactionInodeIndexUpdatesStagedTreeNode {
                                        node_level: transaction.inode_index_updates.index_tree_levels - 1,
                                        node: root_node,
                                    });

                                nodes_staged_updates_root_slot_index
                            }
                            InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                nodes_staged_updates_slot_index,
                            } => nodes_staged_updates_slot_index,
                        };

                        let allocate_fut = match CocoonFsAllocateBlocksFuture::<ST, C>::new(
                            &fs_instance,
                            transaction,
                            image_layout.index_tree_node_allocation_blocks_log2 as u32,
                            2,
                            false,
                        ) {
                            Ok(allocate_fut) => allocate_fut,
                            Err((transaction, e)) => break (transaction, Err(e)),
                        };

                        this.fut_state = InodeIndexInsertEntryFutureState::SplitRootNode {
                            nodes_staged_updates_old_root_slot_index: nodes_staged_updates_root_slot_index,
                            allocate_fut,
                        }
                    } else {
                        // Root node is not full, continue the preemptive
                        // rotate-split walk downwards.
                        this.fut_state = InodeIndexInsertEntryFutureState::PreemptiveRotateSplitWalkLoadChildPrepare {
                            transaction: Some(transaction),
                            parent_node_ref: root_node_ref,
                        };
                    }
                }
                InodeIndexInsertEntryFutureState::PreemptiveRotateSplitWalkLoadChildPrepare {
                    transaction,
                    parent_node_ref,
                } => {
                    let mut transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => break (None, Err(nvfs_err_internal!())),
                    };
                    // Detemine what to do next. If at level 1, then the leaf node beneath
                    // can get split right away (when here, it's known that it is full and
                    // cannot get rotated) and we're done aftewards. Otherwise, continue with the
                    // rotate-split walk.
                    let parent_node = match parent_node_ref.get_node(&transaction) {
                        Ok(parent_node) => parent_node,
                        Err(e) => break (Some(transaction), Err(e)),
                    };
                    let parent_node = match parent_node {
                        InodeIndexTreeNode::Internal(parent_node) => parent_node,
                        InodeIndexTreeNode::Leaf(_) => break (Some(transaction), Err(nvfs_err_internal!())),
                    };

                    let tree_layout = &fs_instance_sync_state.inode_index.layout;
                    let child_index_in_parent = match parent_node.lookup_child(this.lookup_result.inode, tree_layout) {
                        Ok(child_index_in_parent) => child_index_in_parent,
                        Err(e) => break (Some(transaction), Err(e)),
                    };
                    let parent_node_level = match parent_node.node_level(tree_layout) {
                        Ok(parent_node_level) => parent_node_level,
                        Err(e) => break (Some(transaction), Err(e)),
                    };

                    if parent_node_level == 1 {
                        // Get the parent an update staging slot for the splitting.
                        let (
                            fs_instance,
                            _fs_sync_state_image_size,
                            fs_sync_state_alloc_bitmap,
                            _fs_sync_state_alloc_bitmap_file,
                            _fs_sync_state_auth_tree,
                            fs_sync_state_inode_index,
                            _fs_sync_state_read_buffer,
                            mut fs_sync_state_keys_cache,
                        ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();
                        let image_layout = &fs_instance.fs_config.image_layout;
                        let nodes_staged_updates_leaf_parent_slot_index = match mem::replace(
                            parent_node_ref,
                            InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                nodes_staged_updates_slot_index: usize::MAX,
                            },
                        ) {
                            InodeIndexTreeNodeRefForUpdate::Owned {
                                node: leaf_parent_node, ..
                            } => {
                                let nodes_staged_updates_leaf_parent_slot_index =
                                    match transaction.inode_index_updates.reserve_tree_node_update_staging_slot(
                                        leaf_parent_node.node_allocation_blocks_begin(),
                                        &[this.lookup_result.leaf_node.get_nodes_staged_updates_slot_index()],
                                        &mut transaction.allocs,
                                        &mut transaction.auth_tree_data_blocks_update_states,
                                        transaction.rng.as_mut(),
                                        &fs_instance.fs_config,
                                        fs_sync_state_alloc_bitmap,
                                        fs_sync_state_inode_index,
                                        &mut fs_sync_state_keys_cache,
                                    ) {
                                        Ok(nodes_staged_updates_leaf_parent_slot_index) => {
                                            nodes_staged_updates_leaf_parent_slot_index
                                        }
                                        Err(e) => break (Some(transaction), Err(e)),
                                    };
                                transaction.inode_index_updates.tree_nodes_staged_updates
                                    [nodes_staged_updates_leaf_parent_slot_index] =
                                    Some(TransactionInodeIndexUpdatesStagedTreeNode {
                                        node_level: 1,
                                        node: leaf_parent_node,
                                    });
                                nodes_staged_updates_leaf_parent_slot_index
                            }
                            InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                nodes_staged_updates_slot_index,
                            } => nodes_staged_updates_slot_index,
                        };
                        // Update the lookup_result's leaf_parent_node to the current parent node.
                        this.lookup_result.leaf_parent_node =
                            Some(InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                nodes_staged_updates_slot_index: nodes_staged_updates_leaf_parent_slot_index,
                            });

                        let nodes_staged_updates_leaf_slot_index = match &this.lookup_result.leaf_node {
                            InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                nodes_staged_updates_slot_index,
                            } => *nodes_staged_updates_slot_index,
                            _ => break (Some(transaction), Err(nvfs_err_internal!())),
                        };

                        let allocate_fut = match CocoonFsAllocateBlockFuture::new(
                            &fs_instance,
                            transaction,
                            image_layout.index_tree_node_allocation_blocks_log2 as u32,
                            false,
                        ) {
                            Ok(allocate_fut) => allocate_fut,
                            Err((transaction, e)) => break (transaction, Err(e)),
                        };

                        this.fut_state = InodeIndexInsertEntryFutureState::SplitNode {
                            nodes_staged_updates_parent_slot_index: nodes_staged_updates_leaf_parent_slot_index,
                            nodes_staged_updates_child_slot_index: nodes_staged_updates_leaf_slot_index,
                            child_index_in_parent,
                            allocate_fut,
                        };
                    } else {
                        let child_node_allocation_blocks_begin = match parent_node
                            .entry_child_ptr(child_index_in_parent, tree_layout)
                            .and_then(|child_ptr| {
                                EncodedBlockPtr::from(*child_ptr).decode(
                                    tree_layout
                                        .node_encrypted_block_layout
                                        .get_allocation_block_size_128b_log2()
                                        as u32,
                                )
                            })
                            .and_then(|child_node_allocation_blocks_begin| {
                                child_node_allocation_blocks_begin
                                    .ok_or(NvFsError::from(CocoonFsFormatError::InvalidIndexNode))
                            }) {
                            Ok(child_node_allocation_blocks_begin) => child_node_allocation_blocks_begin,
                            Err(e) => break (Some(transaction), Err(e)),
                        };

                        let read_child_fut = InodeIndexReadTreeNodeFuture::new(
                            Some(transaction),
                            child_node_allocation_blocks_begin,
                            Some(parent_node_level - 1),
                            true,
                        );
                        this.fut_state = InodeIndexInsertEntryFutureState::PreemptiveRotateSplitWalkLoadChild {
                            parent_node_ref: mem::replace(
                                parent_node_ref,
                                InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                    nodes_staged_updates_slot_index: usize::MAX,
                                },
                            ),
                            read_child_fut,
                        };
                    }
                }
                InodeIndexInsertEntryFutureState::PreemptiveRotateSplitWalkLoadChild {
                    parent_node_ref,
                    read_child_fut,
                } => {
                    let (
                        fs_instance,
                        _fs_sync_state_image_size,
                        fs_sync_state_alloc_bitmap,
                        _fs_sync_state_alloc_bitmap_file,
                        mut fs_sync_state_auth_tree,
                        fs_sync_state_inode_index,
                        fs_sync_state_read_buffer,
                        mut fs_sync_state_keys_cache,
                    ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();

                    let (returned_transaction, child_node_ref) = match InodeIndexReadTreeNodeFuture::poll(
                        pin::Pin::new(read_child_fut),
                        &fs_instance.chip,
                        &fs_instance.fs_config,
                        fs_sync_state_alloc_bitmap,
                        &mut fs_sync_state_auth_tree,
                        &fs_sync_state_inode_index.layout,
                        &fs_sync_state_inode_index.tree_nodes_cache,
                        &fs_sync_state_inode_index.tree_node_decryption_instance,
                        fs_sync_state_read_buffer,
                        cx,
                    ) {
                        task::Poll::Ready((returned_transaction, Ok(sibling_child_node_ref))) => {
                            (returned_transaction, sibling_child_node_ref)
                        }
                        task::Poll::Ready((returned_transaction, Err(e))) => break (returned_transaction, Err(e)),
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let (transaction, child_node_ref) =
                        InodeIndexTreeNodeRefForUpdate::try_from_node_ref(child_node_ref);
                    let transaction = transaction.or(returned_transaction);
                    let child_node_ref = match child_node_ref {
                        Ok(node_ref) => node_ref,
                        Err(e) => {
                            break (transaction, Err(e));
                        }
                    };
                    let mut transaction = match transaction {
                        Some(transaction) => transaction,
                        None => {
                            break (None, Err(nvfs_err_internal!()));
                        }
                    };

                    let child_node = match child_node_ref.get_node(&transaction) {
                        Ok(child_node) => child_node,
                        Err(e) => break (Some(transaction), Err(e)),
                    };
                    let child_node = match child_node {
                        InodeIndexTreeNode::Internal(child_node) => child_node,
                        InodeIndexTreeNode::Leaf(_) => {
                            // The rotate-split walk is not getting continued to the parent: once
                            // the bottom internal nodes have been reached, the leaf is getting
                            // split up directly.
                            break (Some(transaction), Err(nvfs_err_internal!()));
                        }
                    };

                    let tree_layout = &fs_sync_state_inode_index.layout;
                    let parent_node_level =
                        match parent_node_ref
                            .get_node(&transaction)
                            .and_then(|parent_node| match parent_node {
                                InodeIndexTreeNode::Internal(parent_node) => parent_node.node_level(tree_layout),
                                InodeIndexTreeNode::Leaf(_) => Err(nvfs_err_internal!()),
                            }) {
                            Ok(parent_node_level) => parent_node_level,
                            Err(e) => break (Some(transaction), Err(e)),
                        };

                    if child_node.entries == tree_layout.max_internal_node_entries {
                        // The child is full, try to rotate.
                        // Reserve update staging slots for the parent and child each in preparation
                        // of that.
                        let child_node_level = match child_node.node_level(tree_layout) {
                            Ok(child_node_level) => child_node_level,
                            Err(e) => break (Some(transaction), Err(e)),
                        };

                        let nodes_staged_updates_parent_slot_index = match mem::replace(
                            parent_node_ref,
                            InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                nodes_staged_updates_slot_index: usize::MAX,
                            },
                        ) {
                            InodeIndexTreeNodeRefForUpdate::Owned { node: parent_node, .. } => {
                                let nodes_staged_updates_parent_slot_index = match transaction
                                    .inode_index_updates
                                    .reserve_tree_node_update_staging_slot(
                                        parent_node.node_allocation_blocks_begin(),
                                        &[
                                            this.lookup_result.leaf_node.get_nodes_staged_updates_slot_index(),
                                            this.lookup_result
                                                .leaf_parent_node
                                                .as_ref()
                                                .and_then(|leaf_parent_node| {
                                                    leaf_parent_node.get_nodes_staged_updates_slot_index()
                                                }),
                                            child_node_ref.get_nodes_staged_updates_slot_index(),
                                        ],
                                        &mut transaction.allocs,
                                        &mut transaction.auth_tree_data_blocks_update_states,
                                        transaction.rng.as_mut(),
                                        &fs_instance.fs_config,
                                        fs_sync_state_alloc_bitmap,
                                        fs_sync_state_inode_index,
                                        &mut fs_sync_state_keys_cache,
                                    ) {
                                    Ok(nodes_staged_updates_root_slot_index) => nodes_staged_updates_root_slot_index,
                                    Err(e) => break (Some(transaction), Err(e)),
                                };
                                transaction.inode_index_updates.tree_nodes_staged_updates
                                    [nodes_staged_updates_parent_slot_index] =
                                    Some(TransactionInodeIndexUpdatesStagedTreeNode {
                                        node_level: parent_node_level,
                                        node: parent_node,
                                    });
                                nodes_staged_updates_parent_slot_index
                            }
                            InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                nodes_staged_updates_slot_index,
                            } => nodes_staged_updates_slot_index,
                        };

                        let nodes_staged_updates_child_slot_index = match child_node_ref {
                            InodeIndexTreeNodeRefForUpdate::Owned { node: child_node, .. } => {
                                let nodes_staged_updates_child_slot_index = match transaction
                                    .inode_index_updates
                                    .reserve_tree_node_update_staging_slot(
                                        child_node.node_allocation_blocks_begin(),
                                        &[
                                            this.lookup_result.leaf_node.get_nodes_staged_updates_slot_index(),
                                            this.lookup_result
                                                .leaf_parent_node
                                                .as_ref()
                                                .and_then(|leaf_parent_node| {
                                                    leaf_parent_node.get_nodes_staged_updates_slot_index()
                                                }),
                                            Some(nodes_staged_updates_parent_slot_index),
                                        ],
                                        &mut transaction.allocs,
                                        &mut transaction.auth_tree_data_blocks_update_states,
                                        transaction.rng.as_mut(),
                                        &fs_instance.fs_config,
                                        fs_sync_state_alloc_bitmap,
                                        fs_sync_state_inode_index,
                                        &mut fs_sync_state_keys_cache,
                                    ) {
                                    Ok(nodes_staged_updates_root_slot_index) => nodes_staged_updates_root_slot_index,
                                    Err(e) => break (Some(transaction), Err(e)),
                                };
                                transaction.inode_index_updates.tree_nodes_staged_updates
                                    [nodes_staged_updates_child_slot_index] =
                                    Some(TransactionInodeIndexUpdatesStagedTreeNode {
                                        node_level: child_node_level,
                                        node: child_node,
                                    });
                                nodes_staged_updates_child_slot_index
                            }
                            InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                nodes_staged_updates_slot_index,
                            } => nodes_staged_updates_slot_index,
                        };

                        this.fut_state = InodeIndexInsertEntryFutureState::TryRotatePrepare {
                            transaction: Some(transaction),
                            nodes_staged_updates_parent_slot_index,
                            nodes_staged_updates_child_slot_index,
                        };
                    } else {
                        // The child node is not full, continue the rotate-split walk downwards.
                        // Possibly insert the parent into the caches before that, it won't be
                        // needed for modification here.
                        if let InodeIndexTreeNodeRefForUpdate::Owned {
                            node: parent_node,
                            is_modified_by_transaction: parent_node_is_modified_by_transaction,
                        } = mem::replace(
                            parent_node_ref,
                            InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                nodes_staged_updates_slot_index: usize::MAX,
                            },
                        ) {
                            if parent_node_is_modified_by_transaction {
                                transaction
                                    .inode_index_updates
                                    .updated_tree_nodes_cache
                                    .insert(parent_node_level, parent_node);
                            } else {
                                let mut tree_nodes_cache_guard = fs_sync_state_inode_index.tree_nodes_cache.write();
                                tree_nodes_cache_guard.insert(parent_node_level, parent_node);
                            }
                        }

                        this.fut_state = InodeIndexInsertEntryFutureState::PreemptiveRotateSplitWalkLoadChildPrepare {
                            transaction: Some(transaction),
                            parent_node_ref: child_node_ref,
                        };
                    }
                }
                InodeIndexInsertEntryFutureState::Done => unreachable!(),
            }
        };

        this.fut_state = InodeIndexInsertEntryFutureState::Done;
        if let Some(mut transaction) = returned_transaction {
            // Move the (up to) two nodes from Self::lookup_result into the caches if still
            // owned by the future.
            if let InodeIndexTreeNodeRefForUpdate::Owned {
                node,
                is_modified_by_transaction,
            } = mem::replace(
                &mut this.lookup_result.leaf_node,
                InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                    nodes_staged_updates_slot_index: usize::MAX,
                },
            ) {
                if is_modified_by_transaction {
                    transaction.inode_index_updates.updated_tree_nodes_cache.insert(0, node);
                } else {
                    let mut tree_nodes_cache_guard = fs_instance_sync_state.inode_index.tree_nodes_cache.write();
                    tree_nodes_cache_guard.insert(0, node);
                }
            }
            if let Some(InodeIndexTreeNodeRefForUpdate::Owned {
                node: parent_node,
                is_modified_by_transaction: parent_node_is_modified_by_transaction,
            }) = this.lookup_result.leaf_parent_node.take()
            {
                if parent_node_is_modified_by_transaction {
                    transaction
                        .inode_index_updates
                        .updated_tree_nodes_cache
                        .insert(1, parent_node);
                } else {
                    let mut tree_nodes_cache_guard = fs_instance_sync_state.inode_index.tree_nodes_cache.write();
                    tree_nodes_cache_guard.insert(1, parent_node);
                }
            }
            task::Poll::Ready(match result {
                Ok(()) => Ok((transaction, Ok(()))),
                Err(e) => Ok((
                    transaction,
                    Err((
                        mem::take(&mut this.pending_inode_extents_reallocation),
                        mem::take(&mut this.pending_inode_extents_list_update),
                        e,
                    )),
                )),
            })
        } else {
            match result {
                Ok(()) => task::Poll::Ready(Err(nvfs_err_internal!())),
                Err(e) => task::Poll::Ready(Err(e)),
            }
        }
    }
}

/// Cursor for conditionally unlinking inodes in a given range.
pub struct InodeIndexUnlinkCursor<ST: sync_types::SyncTypes, C: chip::NvChip> {
    inodes_unlink_range: ops::RangeInclusive<InodeIndexKeyType>,
    // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
    // reference on Self.
    transaction: Option<Box<transaction::Transaction>>,
    tree_position: Option<InodeIndexUnlinkCursorTreePosition>,
    at_end: bool,
    _phantom: marker::PhantomData<fn() -> (ST, C)>,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> InodeIndexUnlinkCursor<ST, C> {
    pub fn new(
        transaction: Box<transaction::Transaction>,
        inodes_unlink_range: ops::RangeInclusive<InodeIndexKeyType>,
    ) -> Result<Box<Self>, (Box<transaction::Transaction>, NvFsError)> {
        let inodes_unlink_range = ops::RangeInclusive::new(
            (*inodes_unlink_range.start()).max(SPECIAL_INODE_MAX),
            *inodes_unlink_range.end(),
        );

        let mut cursor = match box_try_new(Self {
            inodes_unlink_range,
            transaction: None,
            tree_position: None,
            at_end: false,
            _phantom: marker::PhantomData,
        }) {
            Ok(cursor) => cursor,
            Err(e) => {
                return Err((transaction, NvFsError::from(e)));
            }
        };
        cursor.transaction = Some(transaction);

        Ok(cursor)
    }

    pub fn into_transaction(self) -> Result<Box<transaction::Transaction>, NvFsError> {
        self.transaction.ok_or_else(|| nvfs_err_internal!())
    }

    pub fn next(self: Box<Self>) -> InodeIndexUnlinkCursorNextFuture<ST, C> {
        InodeIndexUnlinkCursorNextFuture {
            fut_state: InodeIndexUnlinkCursorNextFutureState::Init { cursor: Some(self) },
        }
    }

    pub fn unlink_inode(self: Box<Self>) -> InodeIndexUnlinkCursorUnlinkInodeFuture<ST, C> {
        debug_assert!(self
            .tree_position
            .as_ref()
            .and_then(|tree_position| tree_position.inode.as_ref())
            .is_some());
        InodeIndexUnlinkCursorUnlinkInodeFuture {
            fut_state: InodeIndexUnlinkCursorUnlinkInodeFutureState::Init { cursor: Some(self) },
        }
    }

    pub fn read_inode_data(self: Box<Self>) -> InodeIndexUnlinkCursorReadInodeDataFuture<ST, C> {
        debug_assert!(self
            .tree_position
            .as_ref()
            .and_then(|tree_position| tree_position.inode.as_ref())
            .is_some());
        InodeIndexUnlinkCursorReadInodeDataFuture {
            fut_state: InodeIndexUnlinkCursorReadInodeDataFutureState::Init { cursor: Some(self) },
        }
    }
}

struct InodeIndexUnlinkCursorTreePosition {
    leaf_node: InodeIndexTreeNodeRefForUpdate,
    leaf_parent_node: Option<InodeIndexTreeNodeRefForUpdate>,
    entry_index_in_leaf_node: usize,
    inode: Option<InodeIndexUnlinkCursorTreePositionInodeEntry>,
}

struct InodeIndexUnlinkCursorTreePositionInodeEntry {
    inode: InodeIndexKeyType,
    inode_extents: Option<InodeIndexUnlinkCursorTreePositionInodeEntryExtents>,
}

struct InodeIndexUnlinkCursorTreePositionInodeEntryExtents {
    inode_extents_list_extents: Option<extents::PhysicalExtents>,
    inode_extents: extents::PhysicalExtents,
}

/// Advance an [`InodeIndexUnlinkCursor`] to the next position.
pub struct InodeIndexUnlinkCursorNextFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    fut_state: InodeIndexUnlinkCursorNextFutureState<ST, C>,
}

enum InodeIndexUnlinkCursorNextFutureState<ST: sync_types::SyncTypes, C: chip::NvChip> {
    Init {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        cursor: Option<Box<InodeIndexUnlinkCursor<ST, C>>>,
    },
    LookupNextInodeWalkReadTreeNode {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self. Has its transaction moved temporarily into read_fut.
        cursor: Option<Box<InodeIndexUnlinkCursor<ST, C>>>,
        next_inode: InodeIndexKeyType,
        found_leaf_parent_node: Option<InodeIndexTreeNodeRefForUpdate>,
        read_fut: InodeIndexReadTreeNodeFuture<C>,
    },
    ReadNextTreeLeafNode {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.  Has its transaction moved temporarily into read_fut.
        cursor: Option<Box<InodeIndexUnlinkCursor<ST, C>>>,
        read_fut: InodeIndexReadTreeNodeFuture<C>,
    },
    InodesRangeExhausted {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        cursor: Option<Box<InodeIndexUnlinkCursor<ST, C>>>,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsSyncStateReadFuture<ST, C>
    for InodeIndexUnlinkCursorNextFuture<ST, C>
{
    type Output = Result<
        (
            Box<InodeIndexUnlinkCursor<ST, C>>,
            Result<Option<InodeIndexKeyType>, NvFsError>,
        ),
        NvFsError,
    >;

    type AuxPollData<'a> = ();

    fn poll<'a>(
        self: pin::Pin<&mut Self>,
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, C>,
        _aux_data: &mut Self::AuxPollData<'a>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        let (cursor, transaction, e) = loop {
            match &mut this.fut_state {
                InodeIndexUnlinkCursorNextFutureState::Init { cursor } => {
                    let mut cursor = match cursor.take() {
                        Some(cursor) => cursor,
                        None => break (None, None, nvfs_err_internal!()),
                    };

                    let mut transaction = match cursor.transaction.take() {
                        Some(transaction) => transaction,
                        None => break (Some(cursor), None, nvfs_err_internal!()),
                    };

                    let tree_layout = &fs_instance_sync_state.inode_index.layout;
                    match &mut cursor.tree_position {
                        None => {
                            // First time to retrieve the next inode on this cursor.
                            debug_assert!(!cursor.at_end);
                            if cursor.inodes_unlink_range.is_empty() {
                                cursor.transaction = Some(transaction);
                                this.fut_state = InodeIndexUnlinkCursorNextFutureState::InodesRangeExhausted {
                                    cursor: Some(cursor),
                                };
                                continue;
                            }
                            let root_node_allocation_blocks_begin =
                                transaction.inode_index_updates.root_node_allocation_blocks_begin;
                            let root_node_level = transaction.inode_index_updates.index_tree_levels - 1;
                            let read_fut = InodeIndexReadTreeNodeFuture::new(
                                Some(transaction),
                                root_node_allocation_blocks_begin,
                                Some(root_node_level),
                                root_node_level <= 1,
                            );
                            let next_inode = *cursor.inodes_unlink_range.start();
                            this.fut_state = InodeIndexUnlinkCursorNextFutureState::LookupNextInodeWalkReadTreeNode {
                                cursor: Some(cursor),
                                next_inode,
                                found_leaf_parent_node: None,
                                read_fut,
                            };
                        }
                        Some(tree_position) => {
                            if cursor.at_end {
                                // Don't even bother with potentially reading another index tree node.
                                cursor.transaction = Some(transaction);
                                this.fut_state = InodeIndexUnlinkCursorNextFutureState::InodesRangeExhausted {
                                    cursor: Some(cursor),
                                };
                                continue;
                            }

                            tree_position.entry_index_in_leaf_node = if tree_position.inode.is_some() {
                                // The last inode did not get unlinked, skip
                                // over it.
                                tree_position.entry_index_in_leaf_node + 1
                            } else {
                                // The last inode got unliked, the
                                // entry_index_in_leaf_node is
                                // pointing at the next entry already, if any.
                                tree_position.entry_index_in_leaf_node
                            };
                            tree_position.inode = None;

                            let leaf_node = match tree_position.leaf_node.get_node(&transaction) {
                                Ok(InodeIndexTreeNode::Leaf(leaf_node)) => leaf_node,
                                Ok(InodeIndexTreeNode::Internal(_)) => {
                                    break (Some(cursor), Some(transaction), nvfs_err_internal!())
                                }
                                Err(e) => break (Some(cursor), Some(transaction), e),
                            };

                            if tree_position.entry_index_in_leaf_node < leaf_node.entries {
                                let inode = match leaf_node.entry_inode(
                                    tree_position.entry_index_in_leaf_node,
                                    &fs_instance_sync_state.inode_index.layout,
                                ) {
                                    Ok(inode) => inode,
                                    Err(e) => break (Some(cursor), Some(transaction), e),
                                };
                                if inode > *cursor.inodes_unlink_range.end() {
                                    cursor.transaction = Some(transaction);
                                    this.fut_state = InodeIndexUnlinkCursorNextFutureState::InodesRangeExhausted {
                                        cursor: Some(cursor),
                                    };
                                    continue;
                                }
                                if inode == *cursor.inodes_unlink_range.end() {
                                    cursor.at_end = true;
                                }
                                tree_position.inode = Some(InodeIndexUnlinkCursorTreePositionInodeEntry {
                                    inode,
                                    inode_extents: None,
                                });
                                cursor.transaction = Some(transaction);
                                this.fut_state = InodeIndexUnlinkCursorNextFutureState::Done;
                                return task::Poll::Ready(Ok((cursor, Ok(Some(inode)))));
                            }

                            // The current leaf node has been exhausted, move to the next one, if
                            // any.
                            let next_leaf_node_allocation_blocks_begin = match leaf_node
                                .encoded_next_leaf_node_ptr(&fs_instance_sync_state.inode_index.layout)
                                .and_then(|next_leaf_ptr| {
                                    EncodedBlockPtr::from(*next_leaf_ptr).decode(
                                        tree_layout
                                            .node_encrypted_block_layout
                                            .get_allocation_block_size_128b_log2()
                                            as u32,
                                    )
                                }) {
                                Ok(next_leaf_node_allocation_blocks_begin) => next_leaf_node_allocation_blocks_begin,
                                Err(e) => break (Some(cursor), Some(transaction), e),
                            };
                            let next_leaf_node_allocation_blocks_begin = match next_leaf_node_allocation_blocks_begin {
                                Some(next_leaf_node_allocation_blocks_begin) => next_leaf_node_allocation_blocks_begin,
                                None => {
                                    cursor.transaction = Some(transaction);
                                    this.fut_state = InodeIndexUnlinkCursorNextFutureState::InodesRangeExhausted {
                                        cursor: Some(cursor),
                                    };
                                    continue;
                                }
                            };

                            // If there's a leaf parent node cached, try to keep that if the next leaf
                            // is also among its children.
                            if let Some(leaf_parent_node) = tree_position.leaf_parent_node.as_ref() {
                                let leaf_parent_node = match leaf_parent_node.get_node(&transaction) {
                                    Ok(InodeIndexTreeNode::Internal(leaf_parent_node)) => leaf_parent_node,
                                    Ok(InodeIndexTreeNode::Leaf(_)) => {
                                        break (Some(cursor), Some(transaction), nvfs_err_internal!())
                                    }
                                    Err(e) => break (Some(cursor), Some(transaction), e),
                                };
                                // By the fact we're following to the next leaf node means that the
                                // former one is not the root, hence has some entries in it.
                                if leaf_node.entries == 0 {
                                    break (
                                        Some(cursor),
                                        Some(transaction),
                                        NvFsError::from(CocoonFsFormatError::InvalidIndexNode),
                                    );
                                }
                                let tree_layout = &fs_instance_sync_state.inode_index.layout;
                                let leaf_node_last_entry_inode =
                                    match leaf_node.entry_inode(leaf_node.entries - 1, tree_layout) {
                                        Ok(leaf_node_last_entry_inode) => leaf_node_last_entry_inode,
                                        Err(e) => break (Some(cursor), Some(transaction), e),
                                    };
                                let leaf_node_child_entry_in_parent = match leaf_parent_node.lookup_child(
                                    leaf_node_last_entry_inode,
                                    &fs_instance_sync_state.inode_index.layout,
                                ) {
                                    Ok(child_entry_index) => child_entry_index,
                                    Err(e) => break (Some(cursor), Some(transaction), e),
                                };
                                if leaf_node_child_entry_in_parent == leaf_parent_node.entries {
                                    // The previous child node had been the last one, reset the parent.
                                    if let Some(InodeIndexTreeNodeRefForUpdate::Owned {
                                        node: leaf_parent_node,
                                        is_modified_by_transaction: leaf_parent_node_is_modified_by_transaction,
                                    }) = tree_position.leaf_parent_node.take()
                                    {
                                        if leaf_parent_node_is_modified_by_transaction {
                                            transaction
                                                .inode_index_updates
                                                .updated_tree_nodes_cache
                                                .insert(1, leaf_parent_node);
                                        } else {
                                            let mut tree_nodes_cache_guard =
                                                fs_instance_sync_state.inode_index.tree_nodes_cache.write();
                                            tree_nodes_cache_guard.insert(1, leaf_parent_node);
                                        }
                                    }
                                } else {
                                    // Consistency check: the parent's next child pointer should match
                                    // what's been found through the leaf's next link above.
                                    let next_child_node_allocation_blocks_begin = match leaf_parent_node
                                        .entry_child_ptr(leaf_node_child_entry_in_parent + 1, tree_layout)
                                        .and_then(|child_ptr| {
                                            EncodedBlockPtr::from(*child_ptr).decode(
                                                tree_layout
                                                    .node_encrypted_block_layout
                                                    .get_allocation_block_size_128b_log2()
                                                    as u32,
                                            )
                                        }) {
                                        Ok(next_child_node_allocation_blocks_begin) => {
                                            next_child_node_allocation_blocks_begin
                                        }
                                        Err(e) => break (Some(cursor), Some(transaction), e),
                                    };
                                    match next_child_node_allocation_blocks_begin {
                                        Some(next_child_node_allocation_blocks_begin) => {
                                            if next_child_node_allocation_blocks_begin
                                                != next_leaf_node_allocation_blocks_begin
                                            {
                                                break (
                                                    Some(cursor),
                                                    Some(transaction),
                                                    NvFsError::from(CocoonFsFormatError::InvalidIndexNode),
                                                );
                                            }
                                        }
                                        None => {
                                            break (
                                                Some(cursor),
                                                Some(transaction),
                                                NvFsError::from(CocoonFsFormatError::InvalidIndexNode),
                                            )
                                        }
                                    };

                                    // If the separator key in the parent happens to be past the
                                    // specified inode range already, then don't bother loading the
                                    // next leaf and stop right now..
                                    let separator_key = match leaf_parent_node
                                        .get_separator_key(leaf_node_child_entry_in_parent, tree_layout)
                                    {
                                        Ok(separator_key) => decode_key(separator_key),
                                        Err(e) => break (Some(cursor), Some(transaction), e),
                                    };
                                    if separator_key > *cursor.inodes_unlink_range.end() {
                                        cursor.transaction = Some(transaction);
                                        this.fut_state = InodeIndexUnlinkCursorNextFutureState::InodesRangeExhausted {
                                            cursor: Some(cursor),
                                        };
                                        continue;
                                    }
                                }
                            }

                            let read_fut = InodeIndexReadTreeNodeFuture::new(
                                Some(transaction),
                                next_leaf_node_allocation_blocks_begin,
                                Some(0),
                                true,
                            );
                            this.fut_state = InodeIndexUnlinkCursorNextFutureState::ReadNextTreeLeafNode {
                                cursor: Some(cursor),
                                read_fut,
                            };
                        }
                    }
                }
                InodeIndexUnlinkCursorNextFutureState::LookupNextInodeWalkReadTreeNode {
                    cursor: fut_cursor,
                    next_inode,
                    found_leaf_parent_node,
                    read_fut,
                } => {
                    let (
                        fs_instance,
                        _fs_sync_state_image_size,
                        fs_sync_state_alloc_bitmap,
                        _fs_sync_state_alloc_bitmap_file,
                        mut fs_sync_state_auth_tree,
                        fs_sync_state_inode_index,
                        fs_sync_state_read_buffer,
                        _fs_sync_state_keys_cache,
                    ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();

                    let (returned_transaction, node_ref) = match InodeIndexReadTreeNodeFuture::poll(
                        pin::Pin::new(read_fut),
                        &fs_instance.chip,
                        &fs_instance.fs_config,
                        fs_sync_state_alloc_bitmap,
                        &mut fs_sync_state_auth_tree,
                        &fs_sync_state_inode_index.layout,
                        &fs_sync_state_inode_index.tree_nodes_cache,
                        &fs_sync_state_inode_index.tree_node_decryption_instance,
                        fs_sync_state_read_buffer,
                        cx,
                    ) {
                        task::Poll::Ready((returned_transaction, Ok(node_ref))) => (returned_transaction, node_ref),
                        task::Poll::Ready((returned_transaction, Err(e))) => {
                            break (fut_cursor.take(), returned_transaction, e);
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let mut cursor = match fut_cursor.take() {
                        Some(cursor) => cursor,
                        None => break (None, None, nvfs_err_internal!()),
                    };

                    match node_ref.get_node() {
                        Ok(InodeIndexTreeNode::Internal(internal_node)) => {
                            let tree_layout = &fs_sync_state_inode_index.layout;
                            let node_level = match internal_node.node_level(tree_layout) {
                                Ok(internal_node_level) => internal_node_level,
                                Err(e) => {
                                    break (Some(cursor), returned_transaction.or(node_ref.into_transaction()), e);
                                }
                            };

                            let next_child_index = match internal_node.lookup_child(*next_inode, tree_layout) {
                                Ok(next_child_index) => next_child_index,
                                Err(e) => {
                                    break (Some(cursor), returned_transaction.or(node_ref.into_transaction()), e);
                                }
                            };

                            let next_child_node_allocation_blocks_begin = match internal_node
                                .entry_child_ptr(next_child_index, tree_layout)
                                .and_then(|next_child_ptr| {
                                    next_child_ptr.decode(
                                        tree_layout
                                            .node_encrypted_block_layout
                                            .get_allocation_block_size_128b_log2()
                                            as u32,
                                    )
                                }) {
                                Ok(next_child_node_allocation_blocks_begin) => next_child_node_allocation_blocks_begin,
                                Err(e) => {
                                    break (Some(cursor), returned_transaction.or(node_ref.into_transaction()), e);
                                }
                            };
                            let next_child_node_allocation_blocks_begin = match next_child_node_allocation_blocks_begin
                            {
                                Some(next_child_node_allocation_blocks_begin) => {
                                    next_child_node_allocation_blocks_begin
                                }
                                None => {
                                    break (
                                        Some(cursor),
                                        returned_transaction.or(node_ref.into_transaction()),
                                        NvFsError::from(CocoonFsFormatError::InvalidIndexNode),
                                    );
                                }
                            };

                            let transaction = if node_level == 1 {
                                // The bottom internal node had been read for update.
                                // Turn the node_ref into a InodeIndexTreeNodeRefForUpdate, obtain
                                // the transaction back, and store the node in Self::found_leaf_parent_node.
                                let (transaction, node_ref) =
                                    InodeIndexTreeNodeRefForUpdate::try_from_node_ref(node_ref);
                                let transaction = transaction.or(returned_transaction);
                                let node_ref = match node_ref {
                                    Ok(node_ref) => node_ref,
                                    Err(e) => {
                                        break (Some(cursor), transaction, e);
                                    }
                                };
                                let transaction = match transaction {
                                    Some(transaction) => transaction,
                                    None => {
                                        break (None, None, nvfs_err_internal!());
                                    }
                                };

                                *found_leaf_parent_node = Some(node_ref);

                                transaction
                            } else {
                                match returned_transaction.or(node_ref.into_transaction()) {
                                    Some(transaction) => transaction,
                                    None => break (None, None, nvfs_err_internal!()),
                                }
                            };

                            *fut_cursor = Some(cursor);
                            let next_child_node_level = node_level - 1;
                            *read_fut = InodeIndexReadTreeNodeFuture::new(
                                Some(transaction),
                                next_child_node_allocation_blocks_begin,
                                Some(next_child_node_level),
                                next_child_node_level <= 1,
                            );
                        }
                        Ok(InodeIndexTreeNode::Leaf(leaf_node)) => {
                            let tree_layout = &fs_sync_state_inode_index.layout;
                            let entry_index_in_leaf_node = match leaf_node.lookup(*next_inode, tree_layout) {
                                Ok(Ok(entry_index_in_leaf_node)) => entry_index_in_leaf_node,
                                Ok(Err(entry_index_in_leaf_node)) => {
                                    if entry_index_in_leaf_node == leaf_node.entries {
                                        // No inodes in range. Still update the cursor's tree_position so
                                        // that the nodes will perhaps get added to the caches as
                                        // appropriate upon return.
                                        let (transaction, node_ref) =
                                            InodeIndexTreeNodeRefForUpdate::try_from_node_ref(node_ref);
                                        let transaction = transaction.or(returned_transaction);
                                        let node_ref = match node_ref {
                                            Ok(node_ref) => node_ref,
                                            Err(e) => {
                                                break (Some(cursor), transaction, e);
                                            }
                                        };
                                        cursor.transaction = Some(match transaction {
                                            Some(transaction) => transaction,
                                            None => {
                                                break (None, None, nvfs_err_internal!());
                                            }
                                        });
                                        cursor.tree_position = Some(InodeIndexUnlinkCursorTreePosition {
                                            leaf_node: node_ref,
                                            leaf_parent_node: found_leaf_parent_node.take(),
                                            entry_index_in_leaf_node,
                                            inode: None,
                                        });
                                        this.fut_state = InodeIndexUnlinkCursorNextFutureState::InodesRangeExhausted {
                                            cursor: Some(cursor),
                                        };
                                        continue;
                                    }
                                    entry_index_in_leaf_node
                                }
                                Err(e) => {
                                    break (Some(cursor), returned_transaction.or(node_ref.into_transaction()), e)
                                }
                            };

                            let inode = match leaf_node.entry_inode(entry_index_in_leaf_node, tree_layout) {
                                Ok(inode) => inode,
                                Err(e) => {
                                    break (Some(cursor), returned_transaction.or(node_ref.into_transaction()), e)
                                }
                            };

                            let (transaction, node_ref) = InodeIndexTreeNodeRefForUpdate::try_from_node_ref(node_ref);
                            let transaction = transaction.or(returned_transaction);
                            let node_ref = match node_ref {
                                Ok(node_ref) => node_ref,
                                Err(e) => {
                                    break (Some(cursor), transaction, e);
                                }
                            };
                            cursor.transaction = Some(match transaction {
                                Some(transaction) => transaction,
                                None => {
                                    break (None, None, nvfs_err_internal!());
                                }
                            });
                            let mut tree_position = InodeIndexUnlinkCursorTreePosition {
                                leaf_node: node_ref,
                                leaf_parent_node: found_leaf_parent_node.take(),
                                entry_index_in_leaf_node,
                                inode: None,
                            };

                            if inode > *cursor.inodes_unlink_range.end() {
                                // No more inodes in range. Still update the cursor's
                                // tree_position so that the nodes will perhaps get added to the
                                // caches as appropriate upon return.
                                cursor.tree_position = Some(tree_position);
                                this.fut_state = InodeIndexUnlinkCursorNextFutureState::InodesRangeExhausted {
                                    cursor: Some(cursor),
                                };
                                continue;
                            }
                            if inode == *cursor.inodes_unlink_range.end() {
                                cursor.at_end = true;
                            }

                            tree_position.inode = Some(InodeIndexUnlinkCursorTreePositionInodeEntry {
                                inode,
                                inode_extents: None,
                            });
                            cursor.tree_position = Some(tree_position);
                            this.fut_state = InodeIndexUnlinkCursorNextFutureState::Done;
                            return task::Poll::Ready(Ok((cursor, Ok(Some(inode)))));
                        }
                        Err(e) => break (Some(cursor), returned_transaction.or(node_ref.into_transaction()), e),
                    }
                }
                InodeIndexUnlinkCursorNextFutureState::ReadNextTreeLeafNode { cursor, read_fut } => {
                    let (
                        fs_instance,
                        _fs_sync_state_image_size,
                        fs_sync_state_alloc_bitmap,
                        _fs_sync_state_alloc_bitmap_file,
                        mut fs_sync_state_auth_tree,
                        fs_sync_state_inode_index,
                        fs_sync_state_read_buffer,
                        _fs_sync_state_keys_cache,
                    ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();

                    let (returned_transaction, node_ref) = match InodeIndexReadTreeNodeFuture::poll(
                        pin::Pin::new(read_fut),
                        &fs_instance.chip,
                        &fs_instance.fs_config,
                        fs_sync_state_alloc_bitmap,
                        &mut fs_sync_state_auth_tree,
                        &fs_sync_state_inode_index.layout,
                        &fs_sync_state_inode_index.tree_nodes_cache,
                        &fs_sync_state_inode_index.tree_node_decryption_instance,
                        fs_sync_state_read_buffer,
                        cx,
                    ) {
                        task::Poll::Ready((returned_transaction, Ok(node_ref))) => (returned_transaction, node_ref),
                        task::Poll::Ready((returned_transaction, Err(e))) => {
                            break (cursor.take(), returned_transaction, e);
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let mut cursor = match cursor.take() {
                        Some(cursor) => cursor,
                        None => break (None, None, nvfs_err_internal!()),
                    };

                    let (transaction, node_ref) = InodeIndexTreeNodeRefForUpdate::try_from_node_ref(node_ref);
                    let transaction = transaction.or(returned_transaction);
                    let node_ref = match node_ref {
                        Ok(node_ref) => node_ref,
                        Err(e) => {
                            break (Some(cursor), transaction, e);
                        }
                    };
                    let mut transaction = match transaction {
                        Some(transaction) => transaction,
                        None => {
                            break (None, None, nvfs_err_internal!());
                        }
                    };

                    let tree_position = match cursor.tree_position.as_mut() {
                        Some(tree_position) => {
                            let prev_leaf_node = mem::replace(&mut tree_position.leaf_node, node_ref);
                            // For completeness: retain the leaf parent, if any. If it would not
                            // have been a parent of the current leaf node too, then it would have
                            // been reset.
                            tree_position.entry_index_in_leaf_node = 0;
                            tree_position.inode = None;

                            // Add the previous leaf node to a cache as appropriate.
                            if let InodeIndexTreeNodeRefForUpdate::Owned {
                                node: prev_leaf_node,
                                is_modified_by_transaction: prev_leaf_node_is_modified_by_transaction,
                            } = prev_leaf_node
                            {
                                if prev_leaf_node_is_modified_by_transaction {
                                    transaction
                                        .inode_index_updates
                                        .updated_tree_nodes_cache
                                        .insert(0, prev_leaf_node);
                                } else {
                                    let mut tree_nodes_cache_guard = fs_sync_state_inode_index.tree_nodes_cache.write();
                                    tree_nodes_cache_guard.insert(0, prev_leaf_node);
                                }
                            }

                            tree_position
                        }
                        None => cursor.tree_position.insert(InodeIndexUnlinkCursorTreePosition {
                            leaf_node: node_ref,
                            leaf_parent_node: None,
                            entry_index_in_leaf_node: 0,
                            inode: None,
                        }),
                    };

                    let leaf_node = match tree_position.leaf_node.get_node(&transaction) {
                        Ok(InodeIndexTreeNode::Leaf(leaf_node)) => leaf_node,
                        Ok(InodeIndexTreeNode::Internal(_)) => {
                            break (
                                Some(cursor),
                                Some(transaction),
                                NvFsError::from(CocoonFsFormatError::InvalidIndexNode),
                            );
                        }
                        Err(e) => break (Some(cursor), Some(transaction), e),
                    };

                    if leaf_node.entries == 0 {
                        break (
                            Some(cursor),
                            Some(transaction),
                            NvFsError::from(CocoonFsFormatError::InvalidIndexNode),
                        );
                    }
                    let inode = match leaf_node.entry_inode(0, &fs_sync_state_inode_index.layout) {
                        Ok(inode) => inode,
                        Err(e) => break (Some(cursor), Some(transaction), e),
                    };

                    cursor.transaction = Some(transaction);

                    if inode < *cursor.inodes_unlink_range.end() {
                        tree_position.inode = Some(InodeIndexUnlinkCursorTreePositionInodeEntry {
                            inode,
                            inode_extents: None,
                        });
                        this.fut_state = InodeIndexUnlinkCursorNextFutureState::Done;
                        return task::Poll::Ready(Ok((cursor, Ok(Some(inode)))));
                    } else {
                        this.fut_state =
                            InodeIndexUnlinkCursorNextFutureState::InodesRangeExhausted { cursor: Some(cursor) };
                    }
                }
                InodeIndexUnlinkCursorNextFutureState::InodesRangeExhausted { cursor } => {
                    let mut cursor = match cursor.take() {
                        Some(cursor) => cursor,
                        None => break (None, None, nvfs_err_internal!()),
                    };
                    let mut transaction = match cursor.transaction.take() {
                        Some(transaction) => transaction,
                        None => break (Some(cursor), None, nvfs_err_internal!()),
                    };

                    cursor.at_end = true;
                    // Add the nodes owned by the cursor's tree_position into the caches as
                    // appropriate.
                    if let Some(tree_position) = cursor.tree_position.take() {
                        let InodeIndexUnlinkCursorTreePosition {
                            leaf_node,
                            mut leaf_parent_node,
                            entry_index_in_leaf_node: _,
                            inode: _,
                        } = tree_position;

                        if let InodeIndexTreeNodeRefForUpdate::Owned {
                            node: leaf_node,
                            is_modified_by_transaction: leaf_node_is_modified_by_transaction,
                        } = leaf_node
                        {
                            if leaf_node_is_modified_by_transaction {
                                transaction
                                    .inode_index_updates
                                    .updated_tree_nodes_cache
                                    .insert(0, leaf_node);
                            } else {
                                let mut tree_nodes_cache_guard =
                                    fs_instance_sync_state.inode_index.tree_nodes_cache.write();
                                tree_nodes_cache_guard.insert(0, leaf_node);
                            }
                        }
                        if let Some(InodeIndexTreeNodeRefForUpdate::Owned {
                            node: leaf_parent_node,
                            is_modified_by_transaction: leaf_parent_node_is_modified_by_transaction,
                        }) = leaf_parent_node.take()
                        {
                            if leaf_parent_node_is_modified_by_transaction {
                                transaction
                                    .inode_index_updates
                                    .updated_tree_nodes_cache
                                    .insert(1, leaf_parent_node);
                            } else {
                                let mut tree_nodes_cache_guard =
                                    fs_instance_sync_state.inode_index.tree_nodes_cache.write();
                                tree_nodes_cache_guard.insert(1, leaf_parent_node);
                            }
                        }
                    }
                    cursor.transaction = Some(transaction);
                    this.fut_state = InodeIndexUnlinkCursorNextFutureState::Done;
                    return task::Poll::Ready(Ok((cursor, Ok(None))));
                }
                InodeIndexUnlinkCursorNextFutureState::Done => unreachable!(),
            }
        };

        this.fut_state = InodeIndexUnlinkCursorNextFutureState::Done;
        task::Poll::Ready(match cursor {
            Some(mut cursor) => {
                cursor.transaction = cursor.transaction.take().or(transaction);
                if cursor.transaction.is_none() {
                    Err(nvfs_err_internal!())
                } else {
                    Ok((cursor, Err(e)))
                }
            }
            None => Err(nvfs_err_internal!()),
        })
    }
}

/// Unlink the inode an [`InodeIndexUnlinkCursor`] currently points at.
pub struct InodeIndexUnlinkCursorUnlinkInodeFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    fut_state: InodeIndexUnlinkCursorUnlinkInodeFutureState<ST, C>,
}

#[allow(clippy::large_enum_variant)]
enum InodeIndexUnlinkCursorUnlinkInodeFutureState<ST: sync_types::SyncTypes, C: chip::NvChip> {
    Init {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        cursor: Option<Box<InodeIndexUnlinkCursor<ST, C>>>,
    },
    ReadInodeExtentsList {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self. Has its transaction moved temporarily into read_inode_extents_list_fut.
        cursor: Option<Box<InodeIndexUnlinkCursor<ST, C>>>,
        read_inode_extents_list_fut: InodeExtentsListReadFuture<ST, C>,
    },
    ApplyInodeExtentsListStagedUpdatesPrepare {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        cursor: Option<Box<InodeIndexUnlinkCursor<ST, C>>>,
        next_inode_extents_list_extent_index: usize,
    },
    ApplyInodeExtentsListStagedUpdates {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self. Has its transaction moved temporarily into prepare_staged_updates_application_fut.
        cursor: Option<Box<InodeIndexUnlinkCursor<ST, C>>>,
        cur_inode_extents_list_extent_index: usize,
        cur_update_states_allocation_blocks_range: AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        prepare_staged_updates_application_fut: transaction::TransactionPrepareStagedUpdatesApplicationFuture<ST, C>,
    },
    UnlinkPrepare {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        cursor: Option<Box<InodeIndexUnlinkCursor<ST, C>>>,
    },
    TryMergePrepare {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        cursor: Option<Box<InodeIndexUnlinkCursor<ST, C>>>,
        nodes_staged_updates_parent_slot_index: usize,
        nodes_staged_updates_child_slot_index: usize,
    },
    TryMerge {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self. Has its transaction moved temporarily into read_sibling_fut.
        cursor: Option<Box<InodeIndexUnlinkCursor<ST, C>>>,
        nodes_staged_updates_parent_slot_index: usize,
        nodes_staged_updates_child_slot_index: usize,
        child_index_in_parent: usize,
        read_sibling_fut: InodeIndexReadTreeNodeFuture<C>,
        at_left_sibling: bool,
        has_right_sibling: bool,
    },
    PreemptiveMergeRotateWalkLoadRoot {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self. Has its transaction moved temporarily into read_root_fut.
        cursor: Option<Box<InodeIndexUnlinkCursor<ST, C>>>,
        read_root_fut: InodeIndexReadTreeNodeFuture<C>,
    },
    PreemptiveMergeRotateWalkLoadChildPrepare {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        cursor: Option<Box<InodeIndexUnlinkCursor<ST, C>>>,
        parent_node_ref: InodeIndexTreeNodeRefForUpdate,
    },
    PreemptiveMergeRotateWalkLoadChild {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self. Has its transaction moved temporarily into read_child_fut.
        cursor: Option<Box<InodeIndexUnlinkCursor<ST, C>>>,
        parent_node_ref: InodeIndexTreeNodeRefForUpdate,
        read_child_fut: InodeIndexReadTreeNodeFuture<C>,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsSyncStateReadFuture<ST, C>
    for InodeIndexUnlinkCursorUnlinkInodeFuture<ST, C>
{
    type Output = Result<(Box<InodeIndexUnlinkCursor<ST, C>>, Result<(), NvFsError>), NvFsError>;

    type AuxPollData<'a> = ();

    fn poll<'a>(
        self: pin::Pin<&mut Self>,
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, C>,
        _aux_data: &mut Self::AuxPollData<'a>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        let (cursor, transaction, e) = 'outer: loop {
            match &mut this.fut_state {
                InodeIndexUnlinkCursorUnlinkInodeFutureState::Init { cursor } => {
                    let mut cursor = match cursor.take() {
                        Some(cursor) => cursor,
                        None => break (None, None, nvfs_err_internal!()),
                    };
                    let tree_position = match cursor.tree_position.as_mut() {
                        Some(tree_position) => tree_position,
                        None => break (Some(cursor), None, nvfs_err_internal!()),
                    };
                    let inode = match tree_position.inode.as_mut() {
                        Some(inode) => inode,
                        None => {
                            // Inode at cursor position got unlinked already.
                            break (Some(cursor), None, nvfs_err_internal!());
                        }
                    };
                    let mut transaction = match cursor.transaction.take() {
                        Some(transaction) => transaction,
                        None => break (Some(cursor), None, nvfs_err_internal!()),
                    };
                    // Start out in a clean rollback state.
                    transaction.allocs.reset_rollback();

                    if let Some(inode_extents) = inode.inode_extents.as_ref() {
                        // The inode's data had previously been read through the cursor and its extents
                        // list is available.
                        cursor.transaction = Some(transaction);
                        if inode_extents.inode_extents_list_extents.is_some() {
                            // Before freeing the inode extents list's extents, apply any staged updates so
                            // that the free can get rolled back while maintaing a consistent metadata state
                            // for the transaction.
                            this.fut_state =
                                InodeIndexUnlinkCursorUnlinkInodeFutureState::ApplyInodeExtentsListStagedUpdatesPrepare {
                                    cursor: Some(cursor),
                                    next_inode_extents_list_extent_index: 0,
                                };
                        } else {
                            this.fut_state =
                                InodeIndexUnlinkCursorUnlinkInodeFutureState::UnlinkPrepare { cursor: Some(cursor) };
                        }
                        continue;
                    }

                    let leaf_node = match tree_position.leaf_node.get_node(&transaction) {
                        Ok(InodeIndexTreeNode::Leaf(leaf_node)) => leaf_node,
                        Ok(InodeIndexTreeNode::Internal(_)) => {
                            break (Some(cursor), Some(transaction), nvfs_err_internal!())
                        }
                        Err(e) => break (Some(cursor), Some(transaction), e),
                    };
                    let inode_index_entry_extent_ptr = match leaf_node.entry_extent_ptr(
                        tree_position.entry_index_in_leaf_node,
                        &fs_instance_sync_state.inode_index.layout,
                    ) {
                        Ok(inode_index_entry_extent_ptr) => inode_index_entry_extent_ptr,
                        Err(e) => break (Some(cursor), Some(transaction), e),
                    };
                    let allocation_block_size_128b_log2 = fs_instance_sync_state
                        .get_fs_ref()
                        .fs_config
                        .image_layout
                        .allocation_block_size_128b_log2
                        as u32;
                    match inode_index_entry_extent_ptr.decode(allocation_block_size_128b_log2) {
                        Ok(Some((inode_extent, false))) => {
                            let mut inode_extents = extents::PhysicalExtents::new();
                            if let Err(e) = inode_extents.push_extent(&inode_extent, true) {
                                break (Some(cursor), Some(transaction), e);
                            }
                            inode.inode_extents = Some(InodeIndexUnlinkCursorTreePositionInodeEntryExtents {
                                inode_extents_list_extents: None,
                                inode_extents,
                            });
                            cursor.transaction = Some(transaction);
                            this.fut_state =
                                InodeIndexUnlinkCursorUnlinkInodeFutureState::UnlinkPrepare { cursor: Some(cursor) };
                        }
                        Ok(Some((_first_inode_extents_list_extent, true))) => {
                            let (
                                fs_instance,
                                _fs_sync_state_image_size,
                                _fs_sync_state_alloc_bitmap,
                                _fs_sync_state_alloc_bitmap_file,
                                _fs_sync_state_auth_tree,
                                _fs_sync_state_inode_index,
                                _fs_sync_state_read_buffer,
                                mut fs_sync_state_keys_cache,
                            ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();

                            let inode = inode.inode;
                            let read_inode_extents_list_fut = match InodeExtentsListReadFuture::new(
                                Some(transaction),
                                inode,
                                &inode_index_entry_extent_ptr,
                                &fs_instance.fs_config.root_key,
                                &mut fs_sync_state_keys_cache,
                                &fs_instance.fs_config.image_layout,
                            ) {
                                Ok(read_inode_extents_list_fut) => read_inode_extents_list_fut,
                                Err((returned_transaction, e)) => break (Some(cursor), returned_transaction, e),
                            };
                            this.fut_state = InodeIndexUnlinkCursorUnlinkInodeFutureState::ReadInodeExtentsList {
                                cursor: Some(cursor),
                                read_inode_extents_list_fut,
                            };
                        }
                        Ok(None) => {
                            break (
                                Some(cursor),
                                Some(transaction),
                                NvFsError::from(CocoonFsFormatError::InvalidExtents),
                            )
                        }
                        Err(e) => break (Some(cursor), Some(transaction), e),
                    }
                }
                InodeIndexUnlinkCursorUnlinkInodeFutureState::ReadInodeExtentsList {
                    cursor,
                    read_inode_extents_list_fut,
                } => {
                    let (returned_transaction, inode_extents_list_extents, inode_extents) =
                        match CocoonFsSyncStateReadFuture::poll(
                            pin::Pin::new(read_inode_extents_list_fut),
                            fs_instance_sync_state,
                            &mut (),
                            cx,
                        ) {
                            task::Poll::Ready((
                                returned_transaction,
                                Ok((inode_extents_list_extents, inode_extents)),
                            )) => (returned_transaction, inode_extents_list_extents, inode_extents),
                            task::Poll::Ready((returned_transaction, Err(e))) => {
                                break (cursor.take(), returned_transaction, e)
                            }
                            task::Poll::Pending => return task::Poll::Pending,
                        };
                    let transaction = match returned_transaction {
                        Some(transaction) => transaction,
                        None => break (cursor.take(), None, nvfs_err_internal!()),
                    };
                    let mut cursor = match cursor.take() {
                        Some(cursor) => cursor,
                        None => break (None, Some(transaction), nvfs_err_internal!()),
                    };
                    cursor.transaction = Some(transaction);

                    let tree_position_inode = match cursor
                        .tree_position
                        .as_mut()
                        .and_then(|tree_position| tree_position.inode.as_mut())
                    {
                        Some(tree_position_inode) => tree_position_inode,
                        None => break (Some(cursor), None, nvfs_err_internal!()),
                    };
                    tree_position_inode.inode_extents = Some(InodeIndexUnlinkCursorTreePositionInodeEntryExtents {
                        inode_extents_list_extents: Some(inode_extents_list_extents),
                        inode_extents,
                    });

                    // Before freeing the inode extents list's extents, apply any staged updates so
                    // that the free can get rolled back while maintaing a consistent metadata state
                    // for the transaction.
                    this.fut_state =
                        InodeIndexUnlinkCursorUnlinkInodeFutureState::ApplyInodeExtentsListStagedUpdatesPrepare {
                            cursor: Some(cursor),
                            next_inode_extents_list_extent_index: 0,
                        };
                }
                InodeIndexUnlinkCursorUnlinkInodeFutureState::ApplyInodeExtentsListStagedUpdatesPrepare {
                    cursor,
                    next_inode_extents_list_extent_index,
                } => {
                    let mut cursor = match cursor.take() {
                        Some(cursor) => cursor,
                        None => break (None, None, nvfs_err_internal!()),
                    };
                    let transaction = match cursor.transaction.take() {
                        Some(transaction) => transaction,
                        None => break (Some(cursor), None, nvfs_err_internal!()),
                    };

                    let inode_extents_list_extents = match cursor
                        .tree_position
                        .as_ref()
                        .and_then(|tree_position| tree_position.inode.as_ref())
                        .and_then(|inode| inode.inode_extents.as_ref())
                        .and_then(|inode_extents| inode_extents.inode_extents_list_extents.as_ref())
                    {
                        Some(inode_extents_list_extents) => inode_extents_list_extents,
                        None => break (Some(cursor), Some(transaction), nvfs_err_internal!()),
                    };
                    while *next_inode_extents_list_extent_index < inode_extents_list_extents.len() {
                        let cur_update_states_allocation_blocks_range = match transaction
                            .auth_tree_data_blocks_update_states
                            .lookup_allocation_blocks_update_states_index_range(
                                &inode_extents_list_extents.get_extent_range(*next_inode_extents_list_extent_index),
                            ) {
                            Ok(cur_update_states_allocation_blocks_range) => cur_update_states_allocation_blocks_range,
                            Err(_) => {
                                *next_inode_extents_list_extent_index += 1;
                                continue;
                            }
                        };

                        let prepare_staged_updates_application_fut =
                            transaction::TransactionPrepareStagedUpdatesApplicationFuture::new(
                                transaction,
                                cur_update_states_allocation_blocks_range.clone(),
                            );
                        this.fut_state =
                            InodeIndexUnlinkCursorUnlinkInodeFutureState::ApplyInodeExtentsListStagedUpdates {
                                cursor: Some(cursor),
                                cur_inode_extents_list_extent_index: *next_inode_extents_list_extent_index,
                                cur_update_states_allocation_blocks_range,
                                prepare_staged_updates_application_fut,
                            };
                        continue 'outer;
                    }

                    // No more updates staged for the preexisting inode extents list's
                    // extents. Jump to the unlink phase.
                    cursor.transaction = Some(transaction);
                    this.fut_state =
                        InodeIndexUnlinkCursorUnlinkInodeFutureState::UnlinkPrepare { cursor: Some(cursor) };
                }
                InodeIndexUnlinkCursorUnlinkInodeFutureState::ApplyInodeExtentsListStagedUpdates {
                    cursor,
                    cur_inode_extents_list_extent_index,
                    cur_update_states_allocation_blocks_range,
                    prepare_staged_updates_application_fut,
                } => {
                    let (mut transaction, cur_update_states_allocation_blocks_range_offsets) =
                        match CocoonFsSyncStateReadFuture::poll(
                            pin::Pin::new(prepare_staged_updates_application_fut),
                            fs_instance_sync_state,
                            &mut (),
                            cx,
                        ) {
                            task::Poll::Ready(Ok((
                                transaction,
                                cur_update_states_allocation_blocks_range_offsets,
                                Ok(()),
                            ))) => (transaction, cur_update_states_allocation_blocks_range_offsets),
                            task::Poll::Ready(Ok((transaction, _, Err(e)))) => {
                                break (cursor.take(), Some(transaction), e);
                            }
                            task::Poll::Ready(Err(e)) => break (cursor.take(), None, e),
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    if let Some(cur_update_states_allocation_blocks_range_offsets) =
                        cur_update_states_allocation_blocks_range_offsets
                    {
                        *cur_update_states_allocation_blocks_range = cur_update_states_allocation_blocks_range
                            .apply_states_insertions_offsets(
                                cur_update_states_allocation_blocks_range_offsets.inserted_states_before_range_count,
                                cur_update_states_allocation_blocks_range_offsets.inserted_states_within_range_count,
                            );
                    }

                    transaction
                        .auth_tree_data_blocks_update_states
                        .apply_allocation_blocks_staged_updates(
                            Some(cur_update_states_allocation_blocks_range),
                            &fs_instance_sync_state.alloc_bitmap,
                        );

                    let mut cursor = match cursor.take() {
                        Some(cursor) => cursor,
                        None => break (None, Some(transaction), nvfs_err_internal!()),
                    };
                    cursor.transaction = Some(transaction);
                    this.fut_state =
                        InodeIndexUnlinkCursorUnlinkInodeFutureState::ApplyInodeExtentsListStagedUpdatesPrepare {
                            cursor: Some(cursor),
                            next_inode_extents_list_extent_index: *cur_inode_extents_list_extent_index + 1,
                        };
                }
                InodeIndexUnlinkCursorUnlinkInodeFutureState::UnlinkPrepare { cursor } => {
                    let mut cursor = match cursor.take() {
                        Some(cursor) => cursor,
                        None => break (None, None, nvfs_err_internal!()),
                    };
                    let mut transaction = match cursor.transaction.take() {
                        Some(transaction) => transaction,
                        None => break (Some(cursor), None, nvfs_err_internal!()),
                    };
                    let tree_position = match cursor.tree_position.as_mut() {
                        Some(tree_position) => tree_position,
                        None => break (Some(cursor), Some(transaction), nvfs_err_internal!()),
                    };

                    // Get the leaf node an update staging slot.
                    let tree_position_leaf_node = mem::replace(
                        &mut tree_position.leaf_node,
                        InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                            nodes_staged_updates_slot_index: usize::MAX,
                        },
                    );
                    let nodes_staged_updates_leaf_slot_index = match tree_position_leaf_node {
                        InodeIndexTreeNodeRefForUpdate::Owned {
                            node: leaf_node,
                            is_modified_by_transaction: leaf_is_modified_by_transaction,
                        } => {
                            let (
                                fs_instance,
                                _fs_sync_state_image_size,
                                fs_sync_state_alloc_bitmap,
                                _fs_sync_state_alloc_bitmap_file,
                                _fs_sync_state_auth_tree,
                                fs_sync_state_inode_index,
                                _fs_sync_state_read_buffer,
                                mut fs_sync_state_keys_cache,
                            ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();
                            let nodes_staged_updates_leaf_slot_index =
                                match transaction.inode_index_updates.reserve_tree_node_update_staging_slot(
                                    leaf_node.node_allocation_blocks_begin(),
                                    &[tree_position.leaf_parent_node.as_ref().and_then(|leaf_parent_node| {
                                        leaf_parent_node.get_nodes_staged_updates_slot_index()
                                    })],
                                    &mut transaction.allocs,
                                    &mut transaction.auth_tree_data_blocks_update_states,
                                    transaction.rng.as_mut(),
                                    &fs_instance.fs_config,
                                    fs_sync_state_alloc_bitmap,
                                    fs_sync_state_inode_index,
                                    &mut fs_sync_state_keys_cache,
                                ) {
                                    Ok(nodes_staged_updates_leaf_slot_index) => nodes_staged_updates_leaf_slot_index,
                                    Err(e) => {
                                        // Restore the lookup_result to its previous state.
                                        tree_position.leaf_node = InodeIndexTreeNodeRefForUpdate::Owned {
                                            node: leaf_node,
                                            is_modified_by_transaction: leaf_is_modified_by_transaction,
                                        };

                                        break (Some(cursor), Some(transaction), e);
                                    }
                                };

                            transaction.inode_index_updates.tree_nodes_staged_updates
                                [nodes_staged_updates_leaf_slot_index] =
                                Some(TransactionInodeIndexUpdatesStagedTreeNode {
                                    node_level: 0,
                                    node: leaf_node,
                                });

                            tree_position.leaf_node = InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                nodes_staged_updates_slot_index: nodes_staged_updates_leaf_slot_index,
                            };

                            nodes_staged_updates_leaf_slot_index
                        }
                        InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                            nodes_staged_updates_slot_index,
                        } => {
                            tree_position.leaf_node = InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                nodes_staged_updates_slot_index,
                            };
                            nodes_staged_updates_slot_index
                        }
                    };

                    let index_tree_levels = transaction.inode_index_updates.index_tree_levels;
                    let [nodes_staged_updates_leaf_slot] =
                        match TransactionInodeIndexUpdates::get_tree_nodes_staged_updates_slots_mut(
                            &mut transaction.inode_index_updates.tree_nodes_staged_updates,
                            [nodes_staged_updates_leaf_slot_index],
                        ) {
                            Ok(nodes_staged_updates_leaf_slot) => nodes_staged_updates_leaf_slot,
                            Err(e) => break (Some(cursor), Some(transaction), e),
                        };
                    let staged_update_leaf_node = match &mut nodes_staged_updates_leaf_slot.node {
                        InodeIndexTreeNode::Internal(_) => {
                            break (Some(cursor), Some(transaction), nvfs_err_internal!())
                        }
                        InodeIndexTreeNode::Leaf(leaf_node) => leaf_node,
                    };

                    // See if the leaf node has enough entries left so that the current one can get
                    // removed directly.
                    let tree_layout = &fs_instance_sync_state.inode_index.layout;
                    if staged_update_leaf_node.entries > tree_layout.min_leaf_node_entries || index_tree_levels == 1 {
                        // It has, free the inode's extents and remove its entry from the index
                        // tree.
                        let inode_extents = match tree_position
                            .inode
                            .as_ref()
                            .and_then(|inode| inode.inode_extents.as_ref())
                        {
                            Some(inode_extents) => inode_extents,
                            None => break (Some(cursor), Some(transaction), nvfs_err_internal!()),
                        };
                        if let Err(e) = transaction::Transaction::free_extents(
                            &mut transaction.allocs,
                            &mut transaction.auth_tree_data_blocks_update_states,
                            inode_extents.inode_extents.iter(),
                        ) {
                            break (Some(cursor), Some(transaction), e);
                        }
                        if let Some(inode_extents_list_extents) = inode_extents.inode_extents_list_extents.as_ref() {
                            if let Err(e) = transaction::Transaction::free_extents(
                                &mut transaction.allocs,
                                &mut transaction.auth_tree_data_blocks_update_states,
                                inode_extents_list_extents.iter(),
                            ) {
                                let transaction = match transaction.rollback_extents_free(
                                    inode_extents.inode_extents.iter(),
                                    &fs_instance_sync_state.alloc_bitmap,
                                    true,
                                ) {
                                    Ok(transaction) => transaction,
                                    Err(e) => break (Some(cursor), None, e),
                                };
                                break (Some(cursor), Some(transaction), e);
                            }
                        }
                        if let Err(e) =
                            staged_update_leaf_node.remove(tree_position.entry_index_in_leaf_node, tree_layout)
                        {
                            let transaction = if let Some(inode_extents_list_extents) =
                                inode_extents.inode_extents_list_extents.as_ref()
                            {
                                match transaction.rollback_extents_free(
                                    inode_extents_list_extents.iter(),
                                    &fs_instance_sync_state.alloc_bitmap,
                                    false,
                                ) {
                                    Ok(transaction) => transaction,
                                    Err(e) => break (Some(cursor), None, e),
                                }
                            } else {
                                transaction
                            };
                            let transaction = match transaction.rollback_extents_free(
                                inode_extents.inode_extents.iter(),
                                &fs_instance_sync_state.alloc_bitmap,
                                true,
                            ) {
                                Ok(transaction) => transaction,
                                Err(e) => break (Some(cursor), None, e),
                            };
                            break (Some(cursor), Some(transaction), e);
                        }

                        if tree_position
                            .inode
                            .as_ref()
                            .map(|inode| inode.inode == *cursor.inodes_unlink_range.end())
                            .unwrap_or(false)
                        {
                            cursor.at_end = true;
                        }
                        tree_position.inode = None;
                        this.fut_state = InodeIndexUnlinkCursorUnlinkInodeFutureState::Done;
                        transaction.allocs.reset_rollback();
                        cursor.transaction = Some(transaction);
                        return task::Poll::Ready(Ok((cursor, Ok(()))));
                    }

                    // The leaf is at its minimum fill level and is not the
                    // root. If the leaf's parent node is available, get it a
                    // node update staging slot now.
                    if let Some(tree_position_leaf_parent_node) = tree_position.leaf_parent_node.as_mut() {
                        let tree_position_leaf_parent_node = mem::replace(
                            tree_position_leaf_parent_node,
                            InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                nodes_staged_updates_slot_index: usize::MAX,
                            },
                        );
                        let nodes_staged_updates_leaf_parent_slot_index = match tree_position_leaf_parent_node {
                            InodeIndexTreeNodeRefForUpdate::Owned {
                                node: leaf_parent_node,
                                is_modified_by_transaction: leaf_parent_is_modified_by_transaction,
                            } => {
                                let (
                                    fs_instance,
                                    _fs_sync_state_image_size,
                                    fs_sync_state_alloc_bitmap,
                                    _fs_sync_state_alloc_bitmap_file,
                                    _fs_sync_state_auth_tree,
                                    fs_sync_state_inode_index,
                                    _fs_sync_state_read_buffer,
                                    mut fs_sync_state_keys_cache,
                                ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();
                                let nodes_staged_updates_leaf_parent_slot_index = match transaction
                                    .inode_index_updates
                                    .reserve_tree_node_update_staging_slot(
                                        leaf_parent_node.node_allocation_blocks_begin(),
                                        &[Some(nodes_staged_updates_leaf_slot_index)],
                                        &mut transaction.allocs,
                                        &mut transaction.auth_tree_data_blocks_update_states,
                                        transaction.rng.as_mut(),
                                        &fs_instance.fs_config,
                                        fs_sync_state_alloc_bitmap,
                                        fs_sync_state_inode_index,
                                        &mut fs_sync_state_keys_cache,
                                    ) {
                                    Ok(nodes_staged_updates_leaf_parent_slot_index) => {
                                        nodes_staged_updates_leaf_parent_slot_index
                                    }
                                    Err(e) => {
                                        // Restore the lookup_result to its previous state.
                                        tree_position.leaf_parent_node = Some(InodeIndexTreeNodeRefForUpdate::Owned {
                                            node: leaf_parent_node,
                                            is_modified_by_transaction: leaf_parent_is_modified_by_transaction,
                                        });

                                        break (Some(cursor), Some(transaction), e);
                                    }
                                };

                                transaction.inode_index_updates.tree_nodes_staged_updates
                                    [nodes_staged_updates_leaf_parent_slot_index] =
                                    Some(TransactionInodeIndexUpdatesStagedTreeNode {
                                        node_level: 1,
                                        node: leaf_parent_node,
                                    });

                                tree_position.leaf_parent_node =
                                    Some(InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                        nodes_staged_updates_slot_index: nodes_staged_updates_leaf_parent_slot_index,
                                    });

                                nodes_staged_updates_leaf_parent_slot_index
                            }
                            InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                nodes_staged_updates_slot_index,
                            } => {
                                tree_position.leaf_parent_node =
                                    Some(InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                        nodes_staged_updates_slot_index,
                                    });
                                nodes_staged_updates_slot_index
                            }
                        };

                        let nodes_staged_updates_leaf_parent_slot =
                            match TransactionInodeIndexUpdates::get_tree_nodes_staged_updates_slot(
                                &transaction.inode_index_updates.tree_nodes_staged_updates,
                                nodes_staged_updates_leaf_parent_slot_index,
                            ) {
                                Ok(nodes_staged_updates_leaf_parent_slot) => nodes_staged_updates_leaf_parent_slot,
                                Err(e) => break (Some(cursor), Some(transaction), e),
                            };
                        let staged_update_leaf_parent_node = match &nodes_staged_updates_leaf_parent_slot.node {
                            InodeIndexTreeNode::Internal(leaf_parent_node) => leaf_parent_node,
                            InodeIndexTreeNode::Leaf(_) => {
                                break (Some(cursor), Some(transaction), nvfs_err_internal!())
                            }
                        };

                        let tree_layout = &fs_instance_sync_state.inode_index.layout;
                        if staged_update_leaf_parent_node.entries > tree_layout.min_internal_node_entries
                            || transaction.inode_index_updates.index_tree_levels == 2
                        {
                            cursor.transaction = Some(transaction);
                            this.fut_state = InodeIndexUnlinkCursorUnlinkInodeFutureState::TryMergePrepare {
                                cursor: Some(cursor),
                                nodes_staged_updates_parent_slot_index: nodes_staged_updates_leaf_parent_slot_index,
                                nodes_staged_updates_child_slot_index: nodes_staged_updates_leaf_slot_index,
                            };
                            continue;
                        }
                    }

                    let root_node_allocation_blocks_begin =
                        transaction.inode_index_updates.root_node_allocation_blocks_begin;
                    let root_node_level = transaction.inode_index_updates.index_tree_levels - 1;
                    let read_root_fut = InodeIndexReadTreeNodeFuture::new(
                        Some(transaction),
                        root_node_allocation_blocks_begin,
                        Some(root_node_level),
                        true,
                    );
                    this.fut_state = InodeIndexUnlinkCursorUnlinkInodeFutureState::PreemptiveMergeRotateWalkLoadRoot {
                        cursor: Some(cursor),
                        read_root_fut,
                    };
                }
                InodeIndexUnlinkCursorUnlinkInodeFutureState::TryMergePrepare {
                    cursor,
                    nodes_staged_updates_parent_slot_index,
                    nodes_staged_updates_child_slot_index,
                } => {
                    let mut cursor = match cursor.take() {
                        Some(cursor) => cursor,
                        None => break (None, None, nvfs_err_internal!()),
                    };
                    let transaction = match cursor.transaction.take() {
                        Some(transaction) => transaction,
                        None => break (Some(cursor), None, nvfs_err_internal!()),
                    };

                    let tree_position_inode = match cursor
                        .tree_position
                        .as_ref()
                        .and_then(|tree_position| tree_position.inode.as_ref())
                    {
                        Some(tree_position_inode) => tree_position_inode,
                        None => break (Some(cursor), Some(transaction), nvfs_err_internal!()),
                    };

                    let nodes_staged_updates_parent_slot =
                        match TransactionInodeIndexUpdates::get_tree_nodes_staged_updates_slot(
                            &transaction.inode_index_updates.tree_nodes_staged_updates,
                            *nodes_staged_updates_parent_slot_index,
                        ) {
                            Ok(nodes_staged_updates_parent_slot) => nodes_staged_updates_parent_slot,
                            Err(e) => break (Some(cursor), Some(transaction), e),
                        };

                    let parent_node = match &nodes_staged_updates_parent_slot.node {
                        InodeIndexTreeNode::Internal(internal_node) => internal_node,
                        InodeIndexTreeNode::Leaf(_) => break (Some(cursor), Some(transaction), nvfs_err_internal!()),
                    };

                    // Any internal node, including the root, should have at least two childs,
                    // i.e. at least one separator key.
                    if parent_node.entries == 0 {
                        break (
                            Some(cursor),
                            Some(transaction),
                            NvFsError::from(CocoonFsFormatError::InvalidIndexNode),
                        );
                    }

                    let tree_layout = &fs_instance_sync_state.inode_index.layout;
                    let child_index_in_parent = match parent_node.lookup_child(tree_position_inode.inode, tree_layout) {
                        Ok(leaf_child_index_in_parent) => leaf_child_index_in_parent,
                        Err(e) => break (Some(cursor), Some(transaction), e),
                    };

                    let (at_left_sibling, sibling_child_index_in_parent) = if child_index_in_parent != 0 {
                        (true, child_index_in_parent - 1)
                    } else {
                        (false, child_index_in_parent + 1)
                    };
                    let has_right_sibling = child_index_in_parent < parent_node.entries;

                    let sibling_child_node_allocation_blocks_begin = match parent_node
                        .encoded_entry_child_ptr(sibling_child_index_in_parent, tree_layout)
                        .and_then(|sibling_child_ptr| {
                            EncodedBlockPtr::from(*sibling_child_ptr).decode(
                                tree_layout
                                    .node_encrypted_block_layout
                                    .get_allocation_block_size_128b_log2() as u32,
                            )
                        })
                        .and_then(|sibling_child_node_allocation_blocks_begin| {
                            sibling_child_node_allocation_blocks_begin
                                .ok_or(NvFsError::from(CocoonFsFormatError::InvalidIndexNode))
                        }) {
                        Ok(sibling_child_node_allocation_blocks_begin) => sibling_child_node_allocation_blocks_begin,
                        Err(e) => break (Some(cursor), Some(transaction), e),
                    };

                    let child_node_level = match parent_node.node_level(tree_layout) {
                        Ok(parent_node_level) => parent_node_level - 1,
                        Err(e) => break (Some(cursor), Some(transaction), e),
                    };
                    let read_sibling_fut = InodeIndexReadTreeNodeFuture::new(
                        Some(transaction),
                        sibling_child_node_allocation_blocks_begin,
                        Some(child_node_level),
                        true,
                    );

                    this.fut_state = InodeIndexUnlinkCursorUnlinkInodeFutureState::TryMerge {
                        cursor: Some(cursor),
                        nodes_staged_updates_parent_slot_index: *nodes_staged_updates_parent_slot_index,
                        nodes_staged_updates_child_slot_index: *nodes_staged_updates_child_slot_index,
                        child_index_in_parent,
                        read_sibling_fut,
                        at_left_sibling,
                        has_right_sibling,
                    }
                }
                InodeIndexUnlinkCursorUnlinkInodeFutureState::TryMerge {
                    cursor: fut_cursor,
                    nodes_staged_updates_parent_slot_index,
                    nodes_staged_updates_child_slot_index,
                    child_index_in_parent,
                    read_sibling_fut,
                    at_left_sibling,
                    has_right_sibling,
                } => {
                    let (
                        fs_instance,
                        _fs_sync_state_image_size,
                        fs_sync_state_alloc_bitmap,
                        _fs_sync_state_alloc_bitmap_file,
                        mut fs_sync_state_auth_tree,
                        fs_sync_state_inode_index,
                        fs_sync_state_read_buffer,
                        mut fs_sync_state_keys_cache,
                    ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();

                    let (returned_transaction, sibling_child_node_ref) = match InodeIndexReadTreeNodeFuture::poll(
                        pin::Pin::new(read_sibling_fut),
                        &fs_instance.chip,
                        &fs_instance.fs_config,
                        fs_sync_state_alloc_bitmap,
                        &mut fs_sync_state_auth_tree,
                        &fs_sync_state_inode_index.layout,
                        &fs_sync_state_inode_index.tree_nodes_cache,
                        &fs_sync_state_inode_index.tree_node_decryption_instance,
                        fs_sync_state_read_buffer,
                        cx,
                    ) {
                        task::Poll::Ready((returned_transaction, Ok(sibling_child_node_ref))) => {
                            (returned_transaction, sibling_child_node_ref)
                        }
                        task::Poll::Ready((returned_transaction, Err(e))) => {
                            break (fut_cursor.take(), returned_transaction, e)
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let mut cursor = match fut_cursor.take() {
                        Some(cursor) => cursor,
                        None => break (None, None, nvfs_err_internal!()),
                    };

                    let tree_layout = &fs_sync_state_inode_index.layout;
                    if *at_left_sibling
                        && *has_right_sibling
                        && match sibling_child_node_ref.get_node() {
                            Ok(InodeIndexTreeNode::Internal(internal_node)) => {
                                internal_node.entries > tree_layout.min_internal_node_entries
                            }
                            Ok(InodeIndexTreeNode::Leaf(leaf_node)) => {
                                leaf_node.entries > tree_layout.min_leaf_node_entries
                            }
                            Err(e) => {
                                break (
                                    Some(cursor),
                                    returned_transaction.or(sibling_child_node_ref.into_transaction()),
                                    e,
                                )
                            }
                        }
                    {
                        // A merge with the left sibling is not possible and there's a right
                        // sibling. Insert the unmodified left sibling into a cache as appropriate and
                        // try the right sibling afterwards.
                        let transaction = match sibling_child_node_ref {
                            InodeIndexTreeNodeRef::Owned {
                                node: sibling_child_node,
                                is_modified_by_transaction: sibling_child_node_is_modified_by_transaction,
                            } => {
                                let mut transaction = match returned_transaction {
                                    Some(transaction) => transaction,
                                    None => break (Some(cursor), None, nvfs_err_internal!()),
                                };

                                let nodes_staged_updates_parent_slot =
                                    match TransactionInodeIndexUpdates::get_tree_nodes_staged_updates_slot(
                                        &transaction.inode_index_updates.tree_nodes_staged_updates,
                                        *nodes_staged_updates_parent_slot_index,
                                    ) {
                                        Ok(nodes_staged_updates_parent_slot) => nodes_staged_updates_parent_slot,
                                        Err(e) => break (Some(cursor), Some(transaction), e),
                                    };
                                let parent_node = match &nodes_staged_updates_parent_slot.node {
                                    InodeIndexTreeNode::Internal(internal_node) => internal_node,
                                    InodeIndexTreeNode::Leaf(_) => {
                                        break (Some(cursor), Some(transaction), nvfs_err_internal!())
                                    }
                                };
                                let child_node_level = match parent_node.node_level(tree_layout) {
                                    Ok(parent_node_level) => parent_node_level - 1,
                                    Err(e) => break (Some(cursor), Some(transaction), e),
                                };

                                if sibling_child_node_is_modified_by_transaction {
                                    transaction
                                        .inode_index_updates
                                        .updated_tree_nodes_cache
                                        .insert(child_node_level, sibling_child_node);
                                } else {
                                    let mut tree_nodes_cache_guard = fs_sync_state_inode_index.tree_nodes_cache.write();
                                    tree_nodes_cache_guard.insert(child_node_level, sibling_child_node);
                                }

                                transaction
                            }
                            InodeIndexTreeNodeRef::CacheEntryRef { .. } => match returned_transaction {
                                Some(transaction) => transaction,
                                None => break (Some(cursor), None, nvfs_err_internal!()),
                            },
                            InodeIndexTreeNodeRef::TransactionStagedUpdatesNodeRef { transaction, .. }
                            | InodeIndexTreeNodeRef::TransactionUpdatedNodesCacheEntryRef { transaction, .. } => {
                                transaction
                            }
                        };

                        let nodes_staged_updates_parent_slot =
                            match TransactionInodeIndexUpdates::get_tree_nodes_staged_updates_slot(
                                &transaction.inode_index_updates.tree_nodes_staged_updates,
                                *nodes_staged_updates_parent_slot_index,
                            ) {
                                Ok(nodes_staged_updates_parent_slot) => nodes_staged_updates_parent_slot,
                                Err(e) => break (Some(cursor), Some(transaction), e),
                            };
                        let parent_node = match &nodes_staged_updates_parent_slot.node {
                            InodeIndexTreeNode::Internal(internal_node) => internal_node,
                            InodeIndexTreeNode::Leaf(_) => {
                                break (Some(cursor), Some(transaction), nvfs_err_internal!())
                            }
                        };
                        let parent_node_level = match parent_node.node_level(tree_layout) {
                            Ok(parent_node_level) => parent_node_level,
                            Err(e) => break (Some(cursor), Some(transaction), e),
                        };

                        let right_sibling_child_index = *child_index_in_parent + 1;
                        let right_sibling_child_node_allocation_blocks_begin = match parent_node
                            .encoded_entry_child_ptr(right_sibling_child_index, tree_layout)
                            .and_then(|sibling_child_ptr| {
                                EncodedBlockPtr::from(*sibling_child_ptr).decode(
                                    tree_layout
                                        .node_encrypted_block_layout
                                        .get_allocation_block_size_128b_log2()
                                        as u32,
                                )
                            })
                            .and_then(|sibling_child_node_allocation_blocks_begin| {
                                sibling_child_node_allocation_blocks_begin
                                    .ok_or(NvFsError::from(CocoonFsFormatError::InvalidIndexNode))
                            }) {
                            Ok(sibling_child_node_allocation_blocks_begin) => {
                                sibling_child_node_allocation_blocks_begin
                            }
                            Err(e) => break (Some(cursor), Some(transaction), e),
                        };
                        let child_node_level = parent_node_level - 1;
                        let read_right_sibling_fut = InodeIndexReadTreeNodeFuture::new(
                            Some(transaction),
                            right_sibling_child_node_allocation_blocks_begin,
                            Some(child_node_level),
                            true,
                        );

                        *fut_cursor = Some(cursor);
                        *read_sibling_fut = read_right_sibling_fut;
                        *at_left_sibling = false;

                        continue;
                    }

                    // Get the sibling a node update staging slot.
                    let (transaction, sibling_child_node_ref) =
                        InodeIndexTreeNodeRefForUpdate::try_from_node_ref(sibling_child_node_ref);
                    let transaction = transaction.or(returned_transaction);
                    let sibling_child_node_ref = match sibling_child_node_ref {
                        Ok(node_ref) => node_ref,
                        Err(e) => {
                            break (Some(cursor), transaction, e);
                        }
                    };
                    let mut transaction = match transaction {
                        Some(transaction) => transaction,
                        None => break (Some(cursor), None, nvfs_err_internal!()),
                    };

                    let tree_position = match cursor.tree_position.as_mut() {
                        Some(tree_position) => tree_position,
                        None => break (Some(cursor), Some(transaction), nvfs_err_internal!()),
                    };
                    let nodes_staged_updates_sibling_child_slot_index = match sibling_child_node_ref {
                        InodeIndexTreeNodeRefForUpdate::Owned {
                            node: sibling_child_node,
                            ..
                        } => {
                            let nodes_staged_updates_sibling_child_slot_index =
                                match transaction.inode_index_updates.reserve_tree_node_update_staging_slot(
                                    sibling_child_node.node_allocation_blocks_begin(),
                                    &[
                                        tree_position.leaf_node.get_nodes_staged_updates_slot_index(),
                                        tree_position.leaf_parent_node.as_ref().and_then(|leaf_parent_node| {
                                            leaf_parent_node.get_nodes_staged_updates_slot_index()
                                        }),
                                        Some(*nodes_staged_updates_parent_slot_index),
                                        Some(*nodes_staged_updates_child_slot_index),
                                    ],
                                    &mut transaction.allocs,
                                    &mut transaction.auth_tree_data_blocks_update_states,
                                    transaction.rng.as_mut(),
                                    &fs_instance.fs_config,
                                    fs_sync_state_alloc_bitmap,
                                    fs_sync_state_inode_index,
                                    &mut fs_sync_state_keys_cache,
                                ) {
                                    Ok(nodes_staged_updates_sibling_child_slot_index) => {
                                        nodes_staged_updates_sibling_child_slot_index
                                    }
                                    Err(e) => break (Some(cursor), Some(transaction), e),
                                };

                            let sibling_child_node_level = match &sibling_child_node {
                                InodeIndexTreeNode::Internal(sibling_child_node) => {
                                    match sibling_child_node.node_level(tree_layout) {
                                        Ok(sibling_child_node_level) => sibling_child_node_level,
                                        Err(e) => break (Some(cursor), Some(transaction), e),
                                    }
                                }
                                InodeIndexTreeNode::Leaf(_) => 0,
                            };

                            transaction.inode_index_updates.tree_nodes_staged_updates
                                [nodes_staged_updates_sibling_child_slot_index] =
                                Some(TransactionInodeIndexUpdatesStagedTreeNode {
                                    node_level: sibling_child_node_level,
                                    node: sibling_child_node,
                                });
                            nodes_staged_updates_sibling_child_slot_index
                        }
                        InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                            nodes_staged_updates_slot_index,
                        } => nodes_staged_updates_slot_index,
                    };

                    // Now either merge (preferred) or rotate the child and the sibling.
                    let index_tree_levels = transaction.inode_index_updates.index_tree_levels;
                    let [nodes_staged_updates_parent_slot, nodes_staged_updates_child_slot, nodes_staged_updates_sibling_child_slot] =
                        match TransactionInodeIndexUpdates::get_tree_nodes_staged_updates_slots_mut(
                            &mut transaction.inode_index_updates.tree_nodes_staged_updates,
                            [
                                *nodes_staged_updates_parent_slot_index,
                                *nodes_staged_updates_child_slot_index,
                                nodes_staged_updates_sibling_child_slot_index,
                            ],
                        ) {
                            Ok(slots) => slots,
                            Err(e) => break (Some(cursor), Some(transaction), e),
                        };

                    let parent_node = match &mut nodes_staged_updates_parent_slot.node {
                        InodeIndexTreeNode::Internal(internal_node) => internal_node,
                        InodeIndexTreeNode::Leaf(_) => break (Some(cursor), Some(transaction), nvfs_err_internal!()),
                    };

                    match &mut nodes_staged_updates_child_slot.node {
                        InodeIndexTreeNode::Internal(child_node) => {
                            let sibling_child_node = match &mut nodes_staged_updates_sibling_child_slot.node {
                                InodeIndexTreeNode::Internal(sibling_child_node) => sibling_child_node,
                                InodeIndexTreeNode::Leaf(_) => {
                                    break (
                                        Some(cursor),
                                        Some(transaction),
                                        NvFsError::from(CocoonFsFormatError::InvalidIndexNode),
                                    );
                                }
                            };

                            // See if preemptive merging is possible. Note that the parent separator
                            // key would get moved down, resulting in an additional entry in the
                            // combined node.
                            if child_node.entries + sibling_child_node.entries < tree_layout.max_internal_node_entries {
                                // A merge is possible.
                                let (
                                    nodes_staged_updates_left_child_slot_index,
                                    nodes_staged_updates_right_child_slot_index,
                                    left_child_node,
                                    right_child_node,
                                    right_child_index_in_parent,
                                ) = if *at_left_sibling {
                                    (
                                        nodes_staged_updates_sibling_child_slot_index,
                                        *nodes_staged_updates_child_slot_index,
                                        sibling_child_node,
                                        child_node,
                                        *child_index_in_parent,
                                    )
                                } else {
                                    (
                                        *nodes_staged_updates_child_slot_index,
                                        nodes_staged_updates_sibling_child_slot_index,
                                        child_node,
                                        sibling_child_node,
                                        *child_index_in_parent + 1,
                                    )
                                };

                                let parent_separator_key =
                                    match parent_node.get_separator_key(right_child_index_in_parent - 1, tree_layout) {
                                        Ok(parent_separator_key) => parent_separator_key,
                                        Err(e) => break (Some(cursor), Some(transaction), e),
                                    };

                                // Free up the right node's backing Allocation Blocks now before the
                                // point of no return, as the associated memory allocation can fail.
                                let index_tree_node_allocation_blocks_log2 = fs_instance
                                    .fs_config
                                    .image_layout
                                    .index_tree_node_allocation_blocks_log2
                                    as u32;
                                if let Err(e) = transaction::Transaction::free_block(
                                    &mut transaction.allocs,
                                    &mut transaction.auth_tree_data_blocks_update_states,
                                    right_child_node.node_allocation_blocks_begin,
                                    index_tree_node_allocation_blocks_log2,
                                ) {
                                    break (Some(cursor), Some(transaction), e);
                                }

                                // If the parent is the root, and would have
                                // only a single child after the merge, free it now before the point
                                // of now return, as the associated memory allocation can fail.
                                let parent_node_level = match parent_node.node_level(tree_layout) {
                                    Ok(parent_node_level) => parent_node_level,
                                    Err(e) => break (Some(cursor), Some(transaction), e),
                                };
                                if parent_node_level + 1 == index_tree_levels && parent_node.entries == 1 {
                                    if let Err(e) = transaction.inode_index_updates.removed_nodes.try_reserve(1) {
                                        let right_child_node_node_allocation_blocks_begin =
                                            right_child_node.node_allocation_blocks_begin;
                                        let transaction = match transaction.rollback_block_free(
                                            right_child_node_node_allocation_blocks_begin,
                                            index_tree_node_allocation_blocks_log2,
                                            fs_sync_state_alloc_bitmap,
                                        ) {
                                            Ok(transaction) => transaction,
                                            Err(e) => break (Some(cursor), None, e),
                                        };
                                        break (Some(cursor), Some(transaction), NvFsError::from(e));
                                    }
                                    if let Err(e) = transaction::Transaction::free_block(
                                        &mut transaction.allocs,
                                        &mut transaction.auth_tree_data_blocks_update_states,
                                        parent_node.node_allocation_blocks_begin,
                                        index_tree_node_allocation_blocks_log2,
                                    ) {
                                        let right_child_node_node_allocation_blocks_begin =
                                            right_child_node.node_allocation_blocks_begin;
                                        let transaction = match transaction.rollback_block_free(
                                            right_child_node_node_allocation_blocks_begin,
                                            index_tree_node_allocation_blocks_log2,
                                            fs_sync_state_alloc_bitmap,
                                        ) {
                                            Ok(transaction) => transaction,
                                            Err(e) => break (Some(cursor), None, e),
                                        };
                                        break (Some(cursor), Some(transaction), e);
                                    }
                                    transaction
                                        .inode_index_updates
                                        .removed_nodes
                                        .push(parent_node.node_allocation_blocks_begin);
                                }

                                if let Err(e) =
                                    left_child_node.merge(right_child_node, parent_separator_key, tree_layout)
                                {
                                    // The transaction's view on the metadata is inconsistent in
                                    // case some (internal) error has occured. Consume it.
                                    break (Some(cursor), None, e);
                                }
                                if parent_node_level + 1 == index_tree_levels && parent_node.entries == 1 {
                                    // The root would become trivial after removal of the right child, pop it.
                                    let new_root_node_allocation_blocks_begin =
                                        left_child_node.node_allocation_blocks_begin;
                                    transaction.inode_index_updates.tree_nodes_staged_updates
                                        [*nodes_staged_updates_parent_slot_index] = None;
                                    transaction.inode_index_updates.root_node_allocation_blocks_begin =
                                        new_root_node_allocation_blocks_begin;
                                    transaction.inode_index_updates.root_node_inode_needs_update = true;
                                    transaction.inode_index_updates.index_tree_levels -= 1;
                                    transaction
                                        .inode_index_updates
                                        .updated_tree_nodes_cache
                                        .reconfigure(transaction.inode_index_updates.index_tree_levels);
                                } else {
                                    // Otherwise remove the right child from the parent.
                                    if let Err(e) = parent_node.remove(right_child_index_in_parent, tree_layout) {
                                        // The transaction's view on the metadata is inconsistent in
                                        // case some (internal) error has occured.  Consume it.
                                        break (Some(cursor), None, e);
                                    }
                                }

                                transaction.inode_index_updates.tree_nodes_staged_updates
                                    [nodes_staged_updates_right_child_slot_index] = None;
                                // The walk is continued below. Make sure it uses the new slot index for the
                                // child.
                                *nodes_staged_updates_child_slot_index = nodes_staged_updates_left_child_slot_index;

                                // In case the tree_position's leaf_parent_node was referencing the
                                // right node, redirect it to the left one it got merged into.
                                if tree_position
                                    .leaf_parent_node
                                    .as_ref()
                                    .and_then(|leaf_parent_node| leaf_parent_node.get_nodes_staged_updates_slot_index())
                                    .map(|nodes_staged_updates_leaf_parent_slot_index| {
                                        nodes_staged_updates_leaf_parent_slot_index
                                            == nodes_staged_updates_right_child_slot_index
                                    })
                                    .unwrap_or(false)
                                {
                                    tree_position.leaf_parent_node =
                                        Some(InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                            nodes_staged_updates_slot_index: nodes_staged_updates_left_child_slot_index,
                                        });
                                }
                            } else {
                                // Otherwise rotate (which is always possible if
                                // merging is not).
                                debug_assert!(sibling_child_node.entries > child_node.entries);
                                let rotate_count = (sibling_child_node.entries - child_node.entries).div_ceil(2);
                                if *at_left_sibling {
                                    let parent_separator_key =
                                        match parent_node.get_separator_key(*child_index_in_parent - 1, tree_layout) {
                                            Ok(parent_separator_key) => parent_separator_key,
                                            Err(e) => break (Some(cursor), Some(transaction), e),
                                        };
                                    let new_parent_separator_key = match sibling_child_node.rotate_right(
                                        child_node,
                                        rotate_count,
                                        parent_separator_key,
                                        tree_layout,
                                    ) {
                                        Ok(new_parent_separator_key) => new_parent_separator_key,
                                        Err(e) => {
                                            // In case the rotation failed (with an internal error),
                                            // the transaction's view on the metadata is
                                            // inconsistent. Consume it.
                                            break (Some(cursor), None, e);
                                        }
                                    };
                                    if let Err(e) = parent_node.update_separator_key(
                                        *child_index_in_parent - 1,
                                        new_parent_separator_key,
                                        tree_layout,
                                    ) {
                                        // In case the separator key update failed (with an internal
                                        // error), the transaction's view on the metadata is
                                        // inconsistent. Consume it.
                                        break (Some(cursor), None, e);
                                    }
                                } else {
                                    let parent_separator_key =
                                        match parent_node.get_separator_key(*child_index_in_parent, tree_layout) {
                                            Ok(parent_separator_key) => parent_separator_key,
                                            Err(e) => break (Some(cursor), Some(transaction), e),
                                        };
                                    let new_parent_separator_key = match child_node.rotate_left(
                                        sibling_child_node,
                                        rotate_count,
                                        parent_separator_key,
                                        tree_layout,
                                    ) {
                                        Ok(new_parent_separator_key) => new_parent_separator_key,
                                        Err(e) => {
                                            // In case the rotation failed (with an internal error),
                                            // the transaction's view on the metadata is
                                            // inconsistent. Consume it.
                                            break (Some(cursor), None, e);
                                        }
                                    };
                                    if let Err(e) = parent_node.update_separator_key(
                                        *child_index_in_parent,
                                        new_parent_separator_key,
                                        tree_layout,
                                    ) {
                                        // In case the separator key update failed (with an internal
                                        // error), the transaction's view on the metadata is
                                        // inconsistent. Consume it.
                                        break (Some(cursor), None, e);
                                    }
                                }
                            }

                            // Continue the merge-rotate walk.
                            cursor.transaction = Some(transaction);
                            this.fut_state =
                                InodeIndexUnlinkCursorUnlinkInodeFutureState::PreemptiveMergeRotateWalkLoadChildPrepare {
                                    cursor: Some(cursor),
                                    parent_node_ref: InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                        nodes_staged_updates_slot_index: *nodes_staged_updates_child_slot_index,
                                    },
                                };
                        }
                        InodeIndexTreeNode::Leaf(child_node) => {
                            let sibling_child_node = match &mut nodes_staged_updates_sibling_child_slot.node {
                                InodeIndexTreeNode::Leaf(sibling_child_node) => sibling_child_node,
                                InodeIndexTreeNode::Internal(_) => {
                                    break (
                                        Some(cursor),
                                        Some(transaction),
                                        NvFsError::from(CocoonFsFormatError::InvalidIndexNode),
                                    );
                                }
                            };

                            let inode_extents = match tree_position
                                .inode
                                .as_ref()
                                .and_then(|inode| inode.inode_extents.as_ref())
                            {
                                Some(inode_extents) => inode_extents,
                                None => break (Some(cursor), Some(transaction), nvfs_err_internal!()),
                            };

                            // Deallocate the inode's extents now before the point of no return, as
                            // the associated memory allocation could fail.
                            if let Err(e) = transaction::Transaction::free_extents(
                                &mut transaction.allocs,
                                &mut transaction.auth_tree_data_blocks_update_states,
                                inode_extents.inode_extents.iter(),
                            ) {
                                break (Some(cursor), Some(transaction), e);
                            }
                            if let Some(inode_extents_list_extents) = inode_extents.inode_extents_list_extents.as_ref()
                            {
                                if let Err(e) = transaction::Transaction::free_extents(
                                    &mut transaction.allocs,
                                    &mut transaction.auth_tree_data_blocks_update_states,
                                    inode_extents_list_extents.iter(),
                                ) {
                                    let transaction = match transaction.rollback_extents_free(
                                        inode_extents.inode_extents.iter(),
                                        fs_sync_state_alloc_bitmap,
                                        true,
                                    ) {
                                        Ok(transaction) => transaction,
                                        Err(e) => break (Some(cursor), None, e),
                                    };
                                    break (Some(cursor), Some(transaction), e);
                                }
                            }

                            let rollback_inode_extents_deallocation = |mut transaction: Box<
                                transaction::Transaction,
                            >|
                             -> Result<
                                Box<transaction::Transaction>,
                                NvFsError,
                            > {
                                if let Some(inode_extents_list_extents) =
                                    inode_extents.inode_extents_list_extents.as_ref()
                                {
                                    // Any staged updates to the inode extents list got applied in
                                    // preparation of the unlinking, so the rollback of the
                                    // deallocation will return it to a consistent state.
                                    transaction = transaction.rollback_extents_free(
                                        inode_extents_list_extents.iter(),
                                        fs_sync_state_alloc_bitmap,
                                        false,
                                    )?;
                                }

                                // The deallocation moved the inode's contents into an indeterminate
                                // state, because any prior pending updates had not been applied.
                                transaction = transaction.rollback_extents_free(
                                    inode_extents.inode_extents.iter(),
                                    fs_sync_state_alloc_bitmap,
                                    true,
                                )?;

                                Ok(transaction)
                            };

                            if child_node.entries - 1 + sibling_child_node.entries <= tree_layout.max_leaf_node_entries
                            {
                                // A merge is possible.
                                let (
                                    nodes_staged_updates_left_child_slot_index,
                                    nodes_staged_updates_right_child_slot_index,
                                    left_child_node,
                                    right_child_node,
                                    right_child_index_in_parent,
                                    entry_index_in_leaf_node,
                                ) = if *at_left_sibling {
                                    let entry_index_in_leaf_node =
                                        sibling_child_node.entries + tree_position.entry_index_in_leaf_node;
                                    (
                                        nodes_staged_updates_sibling_child_slot_index,
                                        *nodes_staged_updates_child_slot_index,
                                        sibling_child_node,
                                        child_node,
                                        *child_index_in_parent,
                                        entry_index_in_leaf_node,
                                    )
                                } else {
                                    (
                                        *nodes_staged_updates_child_slot_index,
                                        nodes_staged_updates_sibling_child_slot_index,
                                        child_node,
                                        sibling_child_node,
                                        *child_index_in_parent + 1,
                                        tree_position.entry_index_in_leaf_node,
                                    )
                                };

                                // Free up the right node's backing Allocation Blocks now before the
                                // point of no return, as the associated memory allocation can fail.
                                let index_tree_node_allocation_blocks_log2 = fs_instance
                                    .fs_config
                                    .image_layout
                                    .index_tree_node_allocation_blocks_log2
                                    as u32;
                                if let Err(e) = transaction::Transaction::free_block(
                                    &mut transaction.allocs,
                                    &mut transaction.auth_tree_data_blocks_update_states,
                                    right_child_node.node_allocation_blocks_begin,
                                    index_tree_node_allocation_blocks_log2,
                                ) {
                                    let transaction = match rollback_inode_extents_deallocation(transaction) {
                                        Ok(transaction) => transaction,
                                        Err(e) => break (Some(cursor), None, e),
                                    };
                                    break (Some(cursor), Some(transaction), e);
                                }

                                // If the parent is the root, and would have only a single child
                                // after the merge, free it now before the point of now return, as
                                // the associated memory allocation can fail.
                                if index_tree_levels == 2 && parent_node.entries == 1 {
                                    if let Err(e) = transaction.inode_index_updates.removed_nodes.try_reserve(1) {
                                        let right_child_node_node_allocation_blocks_begin =
                                            right_child_node.node_allocation_blocks_begin;
                                        let transaction = match transaction.rollback_block_free(
                                            right_child_node_node_allocation_blocks_begin,
                                            index_tree_node_allocation_blocks_log2,
                                            fs_sync_state_alloc_bitmap,
                                        ) {
                                            Ok(transaction) => transaction,
                                            Err(e) => break (Some(cursor), None, e),
                                        };
                                        let transaction = match rollback_inode_extents_deallocation(transaction) {
                                            Ok(transaction) => transaction,
                                            Err(e) => break (Some(cursor), None, e),
                                        };
                                        break (Some(cursor), Some(transaction), NvFsError::from(e));
                                    }
                                    if let Err(e) = transaction::Transaction::free_block(
                                        &mut transaction.allocs,
                                        &mut transaction.auth_tree_data_blocks_update_states,
                                        parent_node.node_allocation_blocks_begin,
                                        index_tree_node_allocation_blocks_log2,
                                    ) {
                                        let right_child_node_node_allocation_blocks_begin =
                                            right_child_node.node_allocation_blocks_begin;
                                        let transaction = match transaction.rollback_block_free(
                                            right_child_node_node_allocation_blocks_begin,
                                            index_tree_node_allocation_blocks_log2,
                                            fs_sync_state_alloc_bitmap,
                                        ) {
                                            Ok(transaction) => transaction,
                                            Err(e) => break (Some(cursor), None, e),
                                        };
                                        let transaction = match rollback_inode_extents_deallocation(transaction) {
                                            Ok(transaction) => transaction,
                                            Err(e) => break (Some(cursor), None, e),
                                        };
                                        break (Some(cursor), Some(transaction), e);
                                    }
                                    transaction
                                        .inode_index_updates
                                        .removed_nodes
                                        .push(parent_node.node_allocation_blocks_begin);
                                }

                                if let Err(e) = left_child_node.merge_remove(
                                    right_child_node,
                                    entry_index_in_leaf_node,
                                    tree_layout,
                                ) {
                                    // The merge failed (with internal error) and the transaction's view on the
                                    // metadata is inconsistent. Consume it.
                                    break (Some(cursor), None, e);
                                }
                                if index_tree_levels == 2 && parent_node.entries == 1 {
                                    // The root would become trivial after removal of the right child, pop it.
                                    let new_root_node_allocation_blocks_begin =
                                        left_child_node.node_allocation_blocks_begin;
                                    transaction.inode_index_updates.tree_nodes_staged_updates
                                        [*nodes_staged_updates_parent_slot_index] = None;
                                    transaction.inode_index_updates.root_node_allocation_blocks_begin =
                                        new_root_node_allocation_blocks_begin;
                                    transaction.inode_index_updates.root_node_inode_needs_update = true;
                                    transaction.inode_index_updates.index_tree_levels -= 1;
                                    transaction
                                        .inode_index_updates
                                        .updated_tree_nodes_cache
                                        .reconfigure(transaction.inode_index_updates.index_tree_levels);
                                    tree_position.leaf_parent_node = None;
                                } else {
                                    // Otherwise remove the right child from the parent.
                                    if let Err(e) = parent_node.remove(right_child_index_in_parent, tree_layout) {
                                        // The transaction's view on the metadata is inconsistent in
                                        // case some (internal) error has occured.  Consume it.
                                        break (Some(cursor), None, e);
                                    }
                                }

                                transaction.inode_index_updates.tree_nodes_staged_updates
                                    [nodes_staged_updates_right_child_slot_index] = None;

                                // Update the cursor's tree_position to account for the leaf node
                                // merge.
                                tree_position.leaf_node =
                                    InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                        nodes_staged_updates_slot_index: nodes_staged_updates_left_child_slot_index,
                                    };
                                tree_position.entry_index_in_leaf_node = entry_index_in_leaf_node;
                            } else {
                                // Otherwise rotate (which is always possible if merging is not).
                                debug_assert!(sibling_child_node.entries > child_node.entries);
                                let rotate_count = (sibling_child_node.entries - child_node.entries).div_ceil(2);
                                if *at_left_sibling {
                                    let new_parent_separator_key =
                                        match sibling_child_node.spill_right(child_node, rotate_count, tree_layout) {
                                            Ok(new_parent_separator_key) => new_parent_separator_key,
                                            Err(e) => {
                                                // In case the rotation failed (with an internal error),
                                                // the transaction's view on the metadata is
                                                // inconsistent. Consume it.
                                                break (Some(cursor), None, e);
                                            }
                                        };
                                    if let Err(e) = parent_node.update_separator_key(
                                        *child_index_in_parent - 1,
                                        new_parent_separator_key,
                                        tree_layout,
                                    ) {
                                        // In case the separator key update failed (with an internal
                                        // error), the transaction's view on the metadata is
                                        // inconsistent. Consume it.
                                        break (Some(cursor), None, e);
                                    }
                                    tree_position.entry_index_in_leaf_node += rotate_count;
                                } else {
                                    let new_parent_separator_key =
                                        match child_node.spill_left(sibling_child_node, rotate_count, tree_layout) {
                                            Ok(new_parent_separator_key) => new_parent_separator_key,
                                            Err(e) => {
                                                // In case the rotation failed (with an internal error),
                                                // the transaction's view on the metadata is
                                                // inconsistent. Consume it.
                                                break (Some(cursor), None, e);
                                            }
                                        };
                                    if let Err(e) = parent_node.update_separator_key(
                                        *child_index_in_parent,
                                        new_parent_separator_key,
                                        tree_layout,
                                    ) {
                                        // In case the separator key update failed (with an internal
                                        // error), the transaction's view on the metadata is
                                        // inconsistent. Consume it.
                                        break (Some(cursor), None, e);
                                    }
                                }

                                if let Err(e) = child_node.remove(tree_position.entry_index_in_leaf_node, tree_layout) {
                                    // In case the entry removal failed (with an internal error),
                                    // the transaction's view on the metadata is inconsistent. Consume it.
                                    break (Some(cursor), None, e);
                                }
                            }

                            // The inode got unlinked from the leaf node one way or the other now.
                            if tree_position
                                .inode
                                .as_ref()
                                .map(|inode| inode.inode == *cursor.inodes_unlink_range.end())
                                .unwrap_or(false)
                            {
                                cursor.at_end = true;
                            }
                            tree_position.inode = None;
                            this.fut_state = InodeIndexUnlinkCursorUnlinkInodeFutureState::Done;
                            transaction.allocs.reset_rollback();
                            cursor.transaction = Some(transaction);
                            return task::Poll::Ready(Ok((cursor, Ok(()))));
                        }
                    }
                }
                InodeIndexUnlinkCursorUnlinkInodeFutureState::PreemptiveMergeRotateWalkLoadRoot {
                    cursor,
                    read_root_fut,
                } => {
                    let (
                        fs_instance,
                        _fs_sync_state_image_size,
                        fs_sync_state_alloc_bitmap,
                        _fs_sync_state_alloc_bitmap_file,
                        mut fs_sync_state_auth_tree,
                        fs_sync_state_inode_index,
                        fs_sync_state_read_buffer,
                        _fs_sync_state_keys_cache,
                    ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();

                    let (returned_transaction, root_node_ref) = match InodeIndexReadTreeNodeFuture::poll(
                        pin::Pin::new(read_root_fut),
                        &fs_instance.chip,
                        &fs_instance.fs_config,
                        fs_sync_state_alloc_bitmap,
                        &mut fs_sync_state_auth_tree,
                        &fs_sync_state_inode_index.layout,
                        &fs_sync_state_inode_index.tree_nodes_cache,
                        &fs_sync_state_inode_index.tree_node_decryption_instance,
                        fs_sync_state_read_buffer,
                        cx,
                    ) {
                        task::Poll::Ready((returned_transaction, Ok(root_node_ref))) => {
                            (returned_transaction, root_node_ref)
                        }
                        task::Poll::Ready((returned_transaction, Err(e))) => {
                            break (cursor.take(), returned_transaction, e)
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let (transaction, root_node_ref) =
                        match InodeIndexTreeNodeRefForUpdate::try_from_node_ref(root_node_ref) {
                            (transaction, Ok(root_node_ref)) => (transaction, root_node_ref),
                            (transaction, Err(e)) => break (cursor.take(), returned_transaction.or(transaction), e),
                        };

                    let transaction = match returned_transaction.or(transaction) {
                        Some(transaction) => transaction,
                        None => break (cursor.take(), None, nvfs_err_internal!()),
                    };

                    let mut cursor = match cursor.take() {
                        Some(cursor) => cursor,
                        None => break (None, Some(transaction), nvfs_err_internal!()),
                    };

                    cursor.transaction = Some(transaction);
                    this.fut_state =
                        InodeIndexUnlinkCursorUnlinkInodeFutureState::PreemptiveMergeRotateWalkLoadChildPrepare {
                            cursor: Some(cursor),
                            parent_node_ref: root_node_ref,
                        };
                }
                InodeIndexUnlinkCursorUnlinkInodeFutureState::PreemptiveMergeRotateWalkLoadChildPrepare {
                    cursor,
                    parent_node_ref,
                } => {
                    let mut cursor = match cursor.take() {
                        Some(cursor) => cursor,
                        None => break (None, None, nvfs_err_internal!()),
                    };

                    let transaction = match cursor.transaction.take() {
                        Some(transaction) => transaction,
                        None => break (Some(cursor), None, nvfs_err_internal!()),
                    };

                    let tree_position_inode = match cursor
                        .tree_position
                        .as_ref()
                        .and_then(|tree_position| tree_position.inode.as_ref())
                    {
                        Some(tree_position_inode) => tree_position_inode,
                        None => break (Some(cursor), Some(transaction), nvfs_err_internal!()),
                    };

                    let parent_node = match parent_node_ref.get_node(&transaction) {
                        Ok(InodeIndexTreeNode::Internal(parent_node)) => parent_node,
                        Ok(InodeIndexTreeNode::Leaf(_)) => {
                            // When here, it is already known that the tree height is > 1 and that
                            // the parent node is an internal one.
                            break (Some(cursor), Some(transaction), nvfs_err_internal!());
                        }
                        Err(e) => break (Some(cursor), Some(transaction), e),
                    };
                    let tree_layout = &fs_instance_sync_state.inode_index.layout;
                    let parent_node_level = match parent_node.node_level(tree_layout) {
                        Ok(parent_node_level) => parent_node_level,
                        Err(e) => break (Some(cursor), Some(transaction), e),
                    };
                    let child_index_in_parent = match parent_node.lookup_child(tree_position_inode.inode, tree_layout) {
                        Ok(child_index_in_parent) => child_index_in_parent,
                        Err(e) => break (Some(cursor), Some(transaction), e),
                    };
                    let child_node_allocation_blocks_begin = match parent_node
                        .entry_child_ptr(child_index_in_parent, tree_layout)
                        .and_then(|child_ptr| {
                            EncodedBlockPtr::from(*child_ptr).decode(
                                tree_layout
                                    .node_encrypted_block_layout
                                    .get_allocation_block_size_128b_log2() as u32,
                            )
                        })
                        .and_then(|child_node_allocation_blocks_begin| {
                            child_node_allocation_blocks_begin
                                .ok_or(NvFsError::from(CocoonFsFormatError::InvalidIndexNode))
                        }) {
                        Ok(child_node_allocation_blocks_begin) => child_node_allocation_blocks_begin,
                        Err(e) => break (Some(cursor), Some(transaction), e),
                    };

                    let read_child_fut = InodeIndexReadTreeNodeFuture::new(
                        Some(transaction),
                        child_node_allocation_blocks_begin,
                        Some(parent_node_level - 1),
                        true,
                    );

                    this.fut_state = InodeIndexUnlinkCursorUnlinkInodeFutureState::PreemptiveMergeRotateWalkLoadChild {
                        cursor: Some(cursor),
                        parent_node_ref: mem::replace(
                            parent_node_ref,
                            InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                nodes_staged_updates_slot_index: usize::MAX,
                            },
                        ),
                        read_child_fut,
                    };
                }
                InodeIndexUnlinkCursorUnlinkInodeFutureState::PreemptiveMergeRotateWalkLoadChild {
                    cursor,
                    parent_node_ref,
                    read_child_fut,
                } => {
                    let (
                        fs_instance,
                        _fs_sync_state_image_size,
                        fs_sync_state_alloc_bitmap,
                        _fs_sync_state_alloc_bitmap_file,
                        mut fs_sync_state_auth_tree,
                        fs_sync_state_inode_index,
                        fs_sync_state_read_buffer,
                        mut fs_sync_state_keys_cache,
                    ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();

                    let (returned_transaction, child_node_ref) = match InodeIndexReadTreeNodeFuture::poll(
                        pin::Pin::new(read_child_fut),
                        &fs_instance.chip,
                        &fs_instance.fs_config,
                        fs_sync_state_alloc_bitmap,
                        &mut fs_sync_state_auth_tree,
                        &fs_sync_state_inode_index.layout,
                        &fs_sync_state_inode_index.tree_nodes_cache,
                        &fs_sync_state_inode_index.tree_node_decryption_instance,
                        fs_sync_state_read_buffer,
                        cx,
                    ) {
                        task::Poll::Ready((returned_transaction, Ok(root_node_ref))) => {
                            (returned_transaction, root_node_ref)
                        }
                        task::Poll::Ready((returned_transaction, Err(e))) => {
                            break (cursor.take(), returned_transaction, e)
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let (transaction, child_node_ref) =
                        match InodeIndexTreeNodeRefForUpdate::try_from_node_ref(child_node_ref) {
                            (transaction, Ok(root_node_ref)) => (transaction, root_node_ref),
                            (transaction, Err(e)) => break (cursor.take(), returned_transaction.or(transaction), e),
                        };

                    let mut transaction = match returned_transaction.or(transaction) {
                        Some(transaction) => transaction,
                        None => break (cursor.take(), None, nvfs_err_internal!()),
                    };

                    let mut cursor = match cursor.take() {
                        Some(cursor) => cursor,
                        None => break (None, Some(transaction), nvfs_err_internal!()),
                    };

                    let child_node = match child_node_ref.get_node(&transaction) {
                        Ok(child_node) => child_node,
                        Err(e) => break (Some(cursor), Some(transaction), e),
                    };
                    let (child_node_at_min_threshold, child_node_level) = match child_node {
                        InodeIndexTreeNode::Leaf(_) => (true, 0),
                        InodeIndexTreeNode::Internal(internal_child_node) => {
                            let child_node_level =
                                match internal_child_node.node_level(&fs_sync_state_inode_index.layout) {
                                    Ok(child_node_level) => child_node_level,
                                    Err(e) => break (Some(cursor), Some(transaction), e),
                                };
                            (
                                internal_child_node.entries
                                    == fs_sync_state_inode_index.layout.min_internal_node_entries,
                                child_node_level,
                            )
                        }
                    };
                    let parent_node_level = child_node_level + 1;
                    if child_node_at_min_threshold {
                        // Get the parent and child a node update staging slot
                        // each and continue with merge/rotate.
                        let tree_position = match cursor.tree_position.as_mut() {
                            Some(tree_position) => tree_position,
                            None => break (Some(cursor), Some(transaction), nvfs_err_internal!()),
                        };
                        let nodes_staged_updates_parent_slot_index = match mem::replace(
                            parent_node_ref,
                            InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                nodes_staged_updates_slot_index: usize::MAX,
                            },
                        ) {
                            InodeIndexTreeNodeRefForUpdate::Owned {
                                node: parent_node,
                                is_modified_by_transaction: _,
                            } => {
                                let nodes_staged_updates_parent_slot_index =
                                    match transaction.inode_index_updates.reserve_tree_node_update_staging_slot(
                                        parent_node.node_allocation_blocks_begin(),
                                        &[
                                            tree_position.leaf_node.get_nodes_staged_updates_slot_index(),
                                            tree_position.leaf_parent_node.as_ref().and_then(|leaf_parent_node| {
                                                leaf_parent_node.get_nodes_staged_updates_slot_index()
                                            }),
                                            child_node_ref.get_nodes_staged_updates_slot_index(),
                                        ],
                                        &mut transaction.allocs,
                                        &mut transaction.auth_tree_data_blocks_update_states,
                                        transaction.rng.as_mut(),
                                        &fs_instance.fs_config,
                                        fs_sync_state_alloc_bitmap,
                                        fs_sync_state_inode_index,
                                        &mut fs_sync_state_keys_cache,
                                    ) {
                                        Ok(nodes_staged_updates_parent_slot_index) => {
                                            nodes_staged_updates_parent_slot_index
                                        }
                                        Err(e) => break (Some(cursor), Some(transaction), e),
                                    };

                                transaction.inode_index_updates.tree_nodes_staged_updates
                                    [nodes_staged_updates_parent_slot_index] =
                                    Some(TransactionInodeIndexUpdatesStagedTreeNode {
                                        node_level: parent_node_level,
                                        node: parent_node,
                                    });

                                nodes_staged_updates_parent_slot_index
                            }
                            InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                nodes_staged_updates_slot_index,
                            } => nodes_staged_updates_slot_index,
                        };
                        if parent_node_level == 1 {
                            tree_position.leaf_parent_node =
                                Some(InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                    nodes_staged_updates_slot_index: nodes_staged_updates_parent_slot_index,
                                });
                        }

                        let nodes_staged_updates_child_slot_index = match child_node_ref {
                            InodeIndexTreeNodeRefForUpdate::Owned {
                                node: child_node,
                                is_modified_by_transaction: _,
                            } => {
                                let nodes_staged_updates_child_slot_index = match transaction
                                    .inode_index_updates
                                    .reserve_tree_node_update_staging_slot(
                                        child_node.node_allocation_blocks_begin(),
                                        &[
                                            tree_position.leaf_node.get_nodes_staged_updates_slot_index(),
                                            tree_position.leaf_parent_node.as_ref().and_then(|leaf_parent_node| {
                                                leaf_parent_node.get_nodes_staged_updates_slot_index()
                                            }),
                                            Some(nodes_staged_updates_parent_slot_index),
                                        ],
                                        &mut transaction.allocs,
                                        &mut transaction.auth_tree_data_blocks_update_states,
                                        transaction.rng.as_mut(),
                                        &fs_instance.fs_config,
                                        fs_sync_state_alloc_bitmap,
                                        fs_sync_state_inode_index,
                                        &mut fs_sync_state_keys_cache,
                                    ) {
                                    Ok(nodes_staged_updates_child_slot_index) => nodes_staged_updates_child_slot_index,
                                    Err(e) => break (Some(cursor), Some(transaction), e),
                                };

                                transaction.inode_index_updates.tree_nodes_staged_updates
                                    [nodes_staged_updates_child_slot_index] =
                                    Some(TransactionInodeIndexUpdatesStagedTreeNode {
                                        node_level: child_node_level,
                                        node: child_node,
                                    });

                                nodes_staged_updates_child_slot_index
                            }
                            InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                nodes_staged_updates_slot_index,
                            } => nodes_staged_updates_slot_index,
                        };

                        cursor.transaction = Some(transaction);
                        this.fut_state = InodeIndexUnlinkCursorUnlinkInodeFutureState::TryMergePrepare {
                            cursor: Some(cursor),
                            nodes_staged_updates_parent_slot_index,
                            nodes_staged_updates_child_slot_index,
                        };
                    } else {
                        // The (internal) child is good, continue the preemptive merge-rotate walk.
                        debug_assert!(parent_node_level >= 2); // The child is not a leaf.

                        // First add the unneeded parent into caches as appropriate.
                        if let InodeIndexTreeNodeRefForUpdate::Owned {
                            node: parent_node,
                            is_modified_by_transaction: parent_node_is_modified_by_transaction,
                        } = mem::replace(
                            parent_node_ref,
                            InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                                nodes_staged_updates_slot_index: usize::MAX,
                            },
                        ) {
                            if parent_node_is_modified_by_transaction {
                                transaction
                                    .inode_index_updates
                                    .updated_tree_nodes_cache
                                    .insert(parent_node_level, parent_node);
                            } else {
                                let mut tree_nodes_cache_guard = fs_sync_state_inode_index.tree_nodes_cache.write();
                                tree_nodes_cache_guard.insert(parent_node_level, parent_node);
                            }
                        }

                        cursor.transaction = Some(transaction);
                        this.fut_state =
                            InodeIndexUnlinkCursorUnlinkInodeFutureState::PreemptiveMergeRotateWalkLoadChildPrepare {
                                cursor: Some(cursor),
                                parent_node_ref: child_node_ref,
                            };
                    }
                }
                InodeIndexUnlinkCursorUnlinkInodeFutureState::Done => unreachable!(),
            }
        };

        this.fut_state = InodeIndexUnlinkCursorUnlinkInodeFutureState::Done;
        task::Poll::Ready(match cursor {
            Some(mut cursor) => {
                cursor.transaction = cursor.transaction.take().or(transaction);
                if let Some(transaction) = cursor.transaction.as_mut() {
                    transaction.allocs.reset_rollback();
                    Ok((cursor, Err(e)))
                } else {
                    Err(e)
                }
            }
            None => Err(e),
        })
    }
}

/// Read the data of the inode an [`InodeIndexUnlinkCursor`] currently points at.
pub struct InodeIndexUnlinkCursorReadInodeDataFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    fut_state: InodeIndexUnlinkCursorReadInodeDataFutureState<ST, C>,
}

enum InodeIndexUnlinkCursorReadInodeDataFutureState<ST: sync_types::SyncTypes, C: chip::NvChip> {
    Init {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        cursor: Option<Box<InodeIndexUnlinkCursor<ST, C>>>,
    },
    ReadInodeExtentsList {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self. Has its transaction moved temporarily into read_inode_extents_list_fut.
        cursor: Option<Box<InodeIndexUnlinkCursor<ST, C>>>,
        read_inode_extents_list_fut: InodeExtentsListReadFuture<ST, C>,
    },
    ReadInodeData {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self. Has its transaction moved temporarily into read_inode_data_fut.
        cursor: Option<Box<InodeIndexUnlinkCursor<ST, C>>>,
        read_inode_data_fut: ReadInodeDataFuture<ST, C>,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsSyncStateReadFuture<ST, C>
    for InodeIndexUnlinkCursorReadInodeDataFuture<ST, C>
{
    type Output = Result<
        (
            Box<InodeIndexUnlinkCursor<ST, C>>,
            Result<zeroize::Zeroizing<Vec<u8>>, NvFsError>,
        ),
        NvFsError,
    >;

    type AuxPollData<'a> = ();

    fn poll<'a>(
        self: pin::Pin<&mut Self>,
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, C>,
        _aux_data: &mut Self::AuxPollData<'a>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        let (cursor, transaction, e) = loop {
            match &mut this.fut_state {
                InodeIndexUnlinkCursorReadInodeDataFutureState::Init { cursor } => {
                    let mut cursor = match cursor.take() {
                        Some(cursor) => cursor,
                        None => break (None, None, nvfs_err_internal!()),
                    };
                    let transaction = match cursor.transaction.take() {
                        Some(transaction) => transaction,
                        None => break (Some(cursor), None, nvfs_err_internal!()),
                    };
                    let tree_position = match cursor.tree_position.as_mut() {
                        Some(tree_position) => tree_position,
                        None => break (Some(cursor), Some(transaction), nvfs_err_internal!()),
                    };
                    let tree_position_inode = match tree_position.inode.as_mut() {
                        Some(tree_position_inode) => tree_position_inode,
                        None => {
                            // Inode at cursor position got unlinked already.
                            break (Some(cursor), Some(transaction), nvfs_err_internal!());
                        }
                    };

                    if let Some(inode_extents) = tree_position_inode.inode_extents.as_ref() {
                        // The inode's data had previously been read through the cursor and its extents
                        // list is available.
                        let inode_extents = match inode_extents.inode_extents.try_clone() {
                            Ok(inode_extents) => inode_extents,
                            Err(e) => break (Some(cursor), Some(transaction), e),
                        };
                        let read_inode_data_fut = ReadInodeDataFuture::new_with_inode_extents(
                            Some(transaction),
                            tree_position_inode.inode,
                            inode_extents,
                        );
                        this.fut_state = InodeIndexUnlinkCursorReadInodeDataFutureState::ReadInodeData {
                            cursor: Some(cursor),
                            read_inode_data_fut,
                        };
                        continue;
                    }

                    let leaf_node = match tree_position.leaf_node.get_node(&transaction) {
                        Ok(InodeIndexTreeNode::Leaf(leaf_node)) => leaf_node,
                        Ok(InodeIndexTreeNode::Internal(_)) => {
                            break (Some(cursor), Some(transaction), nvfs_err_internal!())
                        }
                        Err(e) => break (Some(cursor), Some(transaction), e),
                    };
                    let inode_index_entry_extent_ptr = match leaf_node.entry_extent_ptr(
                        tree_position.entry_index_in_leaf_node,
                        &fs_instance_sync_state.inode_index.layout,
                    ) {
                        Ok(inode_index_entry_extent_ptr) => inode_index_entry_extent_ptr,
                        Err(e) => break (Some(cursor), Some(transaction), e),
                    };
                    let allocation_block_size_128b_log2 = fs_instance_sync_state
                        .get_fs_ref()
                        .fs_config
                        .image_layout
                        .allocation_block_size_128b_log2
                        as u32;
                    match inode_index_entry_extent_ptr.decode(allocation_block_size_128b_log2) {
                        Ok(Some((inode_extent, false))) => {
                            let mut inode_extents = extents::PhysicalExtents::new();
                            if let Err(e) = inode_extents.push_extent(&inode_extent, true) {
                                break (Some(cursor), Some(transaction), e);
                            }
                            tree_position_inode.inode_extents = match inode_extents.try_clone() {
                                Ok(inode_extents) => Some(InodeIndexUnlinkCursorTreePositionInodeEntryExtents {
                                    inode_extents_list_extents: None,
                                    inode_extents,
                                }),
                                Err(e) => break (Some(cursor), Some(transaction), e),
                            };
                            let read_inode_data_fut = ReadInodeDataFuture::new_with_inode_extents(
                                Some(transaction),
                                tree_position_inode.inode,
                                inode_extents,
                            );
                            this.fut_state = InodeIndexUnlinkCursorReadInodeDataFutureState::ReadInodeData {
                                cursor: Some(cursor),
                                read_inode_data_fut,
                            };
                        }
                        Ok(Some((_first_inode_extents_list_extent, true))) => {
                            let (
                                fs_instance,
                                _fs_sync_state_image_size,
                                _fs_sync_state_alloc_bitmap,
                                _fs_sync_state_alloc_bitmap_file,
                                _fs_sync_state_auth_tree,
                                _fs_sync_state_inode_index,
                                _fs_sync_state_read_buffer,
                                mut fs_sync_state_keys_cache,
                            ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();

                            let inode = tree_position_inode.inode;
                            let read_inode_extents_list_fut = match InodeExtentsListReadFuture::new(
                                Some(transaction),
                                inode,
                                &inode_index_entry_extent_ptr,
                                &fs_instance.fs_config.root_key,
                                &mut fs_sync_state_keys_cache,
                                &fs_instance.fs_config.image_layout,
                            ) {
                                Ok(read_inode_extents_list_fut) => read_inode_extents_list_fut,
                                Err((returned_transaction, e)) => break (Some(cursor), returned_transaction, e),
                            };
                            this.fut_state = InodeIndexUnlinkCursorReadInodeDataFutureState::ReadInodeExtentsList {
                                cursor: Some(cursor),
                                read_inode_extents_list_fut,
                            };
                        }
                        Ok(None) => {
                            break (
                                Some(cursor),
                                Some(transaction),
                                NvFsError::from(CocoonFsFormatError::InvalidExtents),
                            )
                        }
                        Err(e) => break (Some(cursor), Some(transaction), e),
                    }
                }
                InodeIndexUnlinkCursorReadInodeDataFutureState::ReadInodeExtentsList {
                    cursor,
                    read_inode_extents_list_fut,
                } => {
                    let (returned_transaction, inode_extents_list_extents, inode_extents) =
                        match CocoonFsSyncStateReadFuture::poll(
                            pin::Pin::new(read_inode_extents_list_fut),
                            fs_instance_sync_state,
                            &mut (),
                            cx,
                        ) {
                            task::Poll::Ready((
                                returned_transaction,
                                Ok((inode_extents_list_extents, inode_extents)),
                            )) => (returned_transaction, inode_extents_list_extents, inode_extents),
                            task::Poll::Ready((returned_transaction, Err(e))) => {
                                break (cursor.take(), returned_transaction, e)
                            }
                            task::Poll::Pending => return task::Poll::Pending,
                        };
                    let transaction = match returned_transaction {
                        Some(transaction) => transaction,
                        None => break (cursor.take(), None, nvfs_err_internal!()),
                    };
                    let mut cursor = match cursor.take() {
                        Some(cursor) => cursor,
                        None => break (None, Some(transaction), nvfs_err_internal!()),
                    };

                    let tree_position_inode = match cursor
                        .tree_position
                        .as_mut()
                        .and_then(|tree_position| tree_position.inode.as_mut())
                    {
                        Some(tree_position_inode) => tree_position_inode,
                        None => break (Some(cursor), Some(transaction), nvfs_err_internal!()),
                    };
                    tree_position_inode.inode_extents = match inode_extents.try_clone() {
                        Ok(inode_extents) => Some(InodeIndexUnlinkCursorTreePositionInodeEntryExtents {
                            inode_extents_list_extents: Some(inode_extents_list_extents),
                            inode_extents,
                        }),
                        Err(e) => break (Some(cursor), Some(transaction), e),
                    };
                    let read_inode_data_fut = ReadInodeDataFuture::new_with_inode_extents(
                        Some(transaction),
                        tree_position_inode.inode,
                        inode_extents,
                    );
                    this.fut_state = InodeIndexUnlinkCursorReadInodeDataFutureState::ReadInodeData {
                        cursor: Some(cursor),
                        read_inode_data_fut,
                    };
                }
                InodeIndexUnlinkCursorReadInodeDataFutureState::ReadInodeData {
                    cursor,
                    read_inode_data_fut,
                } => {
                    let (returned_transaction, inode_data) = match CocoonFsSyncStateReadFuture::poll(
                        pin::Pin::new(read_inode_data_fut),
                        fs_instance_sync_state,
                        &mut (),
                        cx,
                    ) {
                        task::Poll::Ready((returned_transaction, Ok(inode_data))) => (returned_transaction, inode_data),
                        task::Poll::Ready((returned_transaction, Err(e))) => {
                            break (cursor.take(), returned_transaction, e);
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let transaction = match returned_transaction {
                        Some(transaction) => transaction,
                        None => break (cursor.take(), None, nvfs_err_internal!()),
                    };

                    let mut cursor = match cursor.take() {
                        Some(cursor) => cursor,
                        None => break (None, Some(transaction), nvfs_err_internal!()),
                    };

                    // When here from the InodeIndexUnlinkCursor, it is known that the inode exists.
                    let inode_data = match inode_data {
                        Some(inode_data) => inode_data,
                        None => break (Some(cursor), Some(transaction), nvfs_err_internal!()),
                    };

                    cursor.transaction = Some(transaction);
                    this.fut_state = InodeIndexUnlinkCursorReadInodeDataFutureState::Done;
                    return task::Poll::Ready(Ok((cursor, Ok(inode_data))));
                }
                InodeIndexUnlinkCursorReadInodeDataFutureState::Done => unreachable!(),
            }
        };

        this.fut_state = InodeIndexUnlinkCursorReadInodeDataFutureState::Done;
        task::Poll::Ready(match cursor {
            Some(mut cursor) => {
                cursor.transaction = cursor.transaction.take().or(transaction);
                if cursor.transaction.is_none() {
                    Err(e)
                } else {
                    Ok((cursor, Err(e)))
                }
            }
            None => Err(e),
        })
    }
}

/// Update the root inode entry in the inode index entry leaf node.
pub struct InodeIndexUpdateRootNodeInodeFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    fut_state: InodeIndexUpdateRootNodeInodeFutureState<C>,
    _phantom: marker::PhantomData<fn() -> *const ST>,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> InodeIndexUpdateRootNodeInodeFuture<ST, C> {
    pub fn new(transaction: Box<transaction::Transaction>) -> Self {
        Self {
            fut_state: InodeIndexUpdateRootNodeInodeFutureState::Init {
                transaction: Some(transaction),
            },
            _phantom: marker::PhantomData,
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum InodeIndexUpdateRootNodeInodeFutureState<C: chip::NvChip> {
    Init {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<transaction::Transaction>>,
    },
    ReadEntryLeafTreeNode {
        read_fut: InodeIndexReadTreeNodeFuture<C>,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsSyncStateReadFuture<ST, C>
    for InodeIndexUpdateRootNodeInodeFuture<ST, C>
{
    type Output = Result<(Box<transaction::Transaction>, Result<(), NvFsError>), NvFsError>;
    type AuxPollData<'a> = ();

    fn poll<'a>(
        self: pin::Pin<&mut Self>,
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, C>,
        _aux_data: &mut Self::AuxPollData<'a>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                InodeIndexUpdateRootNodeInodeFutureState::Init { transaction } => {
                    let transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => {
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    if !transaction.inode_index_updates.root_node_inode_needs_update {
                        this.fut_state = InodeIndexUpdateRootNodeInodeFutureState::Done;
                        return task::Poll::Ready(Ok((transaction, Ok(()))));
                    }

                    let fs_config = &fs_instance_sync_state.get_fs_ref().fs_config;
                    let entry_leaf_node_allocation_blocks_begin = match fs_config
                        .inode_index_entry_leaf_node_block_ptr
                        .decode(fs_config.image_layout.allocation_block_size_128b_log2 as u32)
                    {
                        Ok(Some(entry_leaf_node_allocation_blocks_begin)) => entry_leaf_node_allocation_blocks_begin,
                        Ok(None) => {
                            this.fut_state = InodeIndexUpdateRootNodeInodeFutureState::Done;
                            return task::Poll::Ready(Ok((
                                transaction,
                                Err(NvFsError::from(CocoonFsFormatError::InvalidExtents)),
                            )));
                        }
                        Err(e) => {
                            this.fut_state = InodeIndexUpdateRootNodeInodeFutureState::Done;
                            return task::Poll::Ready(Ok((transaction, Err(e))));
                        }
                    };

                    let read_fut = InodeIndexReadTreeNodeFuture::new(
                        Some(transaction),
                        entry_leaf_node_allocation_blocks_begin,
                        Some(0),
                        true,
                    );
                    this.fut_state = InodeIndexUpdateRootNodeInodeFutureState::ReadEntryLeafTreeNode { read_fut };
                }
                InodeIndexUpdateRootNodeInodeFutureState::ReadEntryLeafTreeNode { read_fut } => {
                    let (
                        fs_instance,
                        _fs_sync_state_image_size,
                        fs_sync_state_alloc_bitmap,
                        _fs_sync_state_alloc_bitmap_file,
                        mut fs_sync_state_auth_tree,
                        fs_sync_state_inode_index,
                        fs_sync_state_read_buffer,
                        mut fs_sync_state_keys_cache,
                    ) = fs_instance_sync_state.fs_instance_and_destructure_borrow();

                    let (returned_transaction, entry_leaf_node_ref) = match InodeIndexReadTreeNodeFuture::poll(
                        pin::Pin::new(read_fut),
                        &fs_instance.chip,
                        &fs_instance.fs_config,
                        fs_sync_state_alloc_bitmap,
                        &mut fs_sync_state_auth_tree,
                        &fs_sync_state_inode_index.layout,
                        &fs_sync_state_inode_index.tree_nodes_cache,
                        &fs_sync_state_inode_index.tree_node_decryption_instance,
                        fs_sync_state_read_buffer,
                        cx,
                    ) {
                        task::Poll::Ready((returned_transaction, Ok(node_ref))) => (returned_transaction, node_ref),
                        task::Poll::Ready((returned_transaction, Err(e))) => {
                            this.fut_state = InodeIndexUpdateRootNodeInodeFutureState::Done;
                            return task::Poll::Ready(match returned_transaction {
                                Some(transaction) => Ok((transaction, Err(e))),
                                None => Err(e),
                            });
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let (transaction, entry_leaf_node_ref) =
                        InodeIndexTreeNodeRefForUpdate::try_from_node_ref(entry_leaf_node_ref);
                    let transaction = transaction.or(returned_transaction);
                    let entry_leaf_node_ref = match entry_leaf_node_ref {
                        Ok(node_ref) => node_ref,
                        Err(e) => {
                            this.fut_state = InodeIndexUpdateRootNodeInodeFutureState::Done;
                            return task::Poll::Ready(match transaction {
                                Some(transaction) => Ok((transaction, Err(e))),
                                None => Err(e),
                            });
                        }
                    };
                    let mut transaction = match transaction {
                        Some(transaction) => transaction,
                        None => {
                            this.fut_state = InodeIndexUpdateRootNodeInodeFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    let root_node_allocation_blocks_begin =
                        transaction.inode_index_updates.root_node_allocation_blocks_begin;
                    // Get the entry leaf node an update staging slot.
                    let nodes_staged_updates_entry_leaf_slot_index = match entry_leaf_node_ref {
                        InodeIndexTreeNodeRefForUpdate::Owned {
                            node: entry_leaf_node, ..
                        } => {
                            let nodes_staged_updates_entry_leaf_slot_index =
                                match transaction.inode_index_updates.reserve_tree_node_update_staging_slot(
                                    entry_leaf_node.node_allocation_blocks_begin(),
                                    &[],
                                    &mut transaction.allocs,
                                    &mut transaction.auth_tree_data_blocks_update_states,
                                    transaction.rng.as_mut(),
                                    &fs_instance.fs_config,
                                    fs_sync_state_alloc_bitmap,
                                    fs_sync_state_inode_index,
                                    &mut fs_sync_state_keys_cache,
                                ) {
                                    Ok(nodes_staged_updates_entry_leaf_slot_index) => {
                                        nodes_staged_updates_entry_leaf_slot_index
                                    }
                                    Err(e) => {
                                        this.fut_state = InodeIndexUpdateRootNodeInodeFutureState::Done;
                                        return task::Poll::Ready(Ok((transaction, Err(e))));
                                    }
                                };

                            transaction.inode_index_updates.tree_nodes_staged_updates
                                [nodes_staged_updates_entry_leaf_slot_index] =
                                Some(TransactionInodeIndexUpdatesStagedTreeNode {
                                    node_level: 0,
                                    node: entry_leaf_node,
                                });
                            nodes_staged_updates_entry_leaf_slot_index
                        }
                        InodeIndexTreeNodeRefForUpdate::TransactionStagedUpdatesNodeRef {
                            nodes_staged_updates_slot_index,
                        } => nodes_staged_updates_slot_index,
                    };

                    let [nodes_staged_updates_entry_leaf_slot] =
                        match TransactionInodeIndexUpdates::get_tree_nodes_staged_updates_slots_mut(
                            &mut transaction.inode_index_updates.tree_nodes_staged_updates,
                            [nodes_staged_updates_entry_leaf_slot_index],
                        ) {
                            Ok(slots) => slots,
                            Err(e) => {
                                this.fut_state = InodeIndexUpdateRootNodeInodeFutureState::Done;
                                return task::Poll::Ready(Ok((transaction, Err(e))));
                            }
                        };
                    let entry_leaf_node = match &mut nodes_staged_updates_entry_leaf_slot.node {
                        InodeIndexTreeNode::Leaf(leaf_node) => leaf_node,
                        InodeIndexTreeNode::Internal(_) => {
                            this.fut_state = InodeIndexUpdateRootNodeInodeFutureState::Done;
                            return task::Poll::Ready(Ok((transaction, Err(nvfs_err_internal!()))));
                        }
                    };
                    if let Err(e) = TransactionInodeIndexUpdates::update_index_root_node_inode(
                        entry_leaf_node,
                        root_node_allocation_blocks_begin,
                        &fs_sync_state_inode_index.layout,
                        fs_instance
                            .fs_config
                            .image_layout
                            .index_tree_node_allocation_blocks_log2 as u32,
                    ) {
                        this.fut_state = InodeIndexUpdateRootNodeInodeFutureState::Done;
                        return task::Poll::Ready(Ok((transaction, Err(e))));
                    }
                    transaction.inode_index_updates.root_node_inode_needs_update = false;

                    this.fut_state = InodeIndexUpdateRootNodeInodeFutureState::Done;
                    return task::Poll::Ready(Ok((transaction, Ok(()))));
                }
                InodeIndexUpdateRootNodeInodeFutureState::Done => unreachable!(),
            }
        }
    }
}

/// Read, authenticate and decrypt the inode index entry leaf node entry before the authentication
/// tree based authentication is available.
///
/// Authentication is done by means of the preauthentication CCA protection digest over the inode
/// index entry leaf node stored in the mutable image header.
pub struct InodeIndexReadEntryLeafTreeNodePreauthCcaProtectedFuture<C: chip::NvChip> {
    entry_leaf_node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
    fut_state: InodeIndexReadEntryLeafTreeNodePreauthCcaProtectedFutureState<C>,
}

enum InodeIndexReadEntryLeafTreeNodePreauthCcaProtectedFutureState<C: chip::NvChip> {
    Init,
    ReadEntryLeafNode {
        read_entry_leaf_node_fut: read_preauth::ReadExtentUnauthenticatedFuture<C>,
    },
    Done,
}

impl<C: chip::NvChip> InodeIndexReadEntryLeafTreeNodePreauthCcaProtectedFuture<C> {
    pub fn new(entry_leaf_node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex) -> Self {
        Self {
            entry_leaf_node_allocation_blocks_begin,
            fut_state: InodeIndexReadEntryLeafTreeNodePreauthCcaProtectedFutureState::Init,
        }
    }

    pub fn poll<ST: sync_types::SyncTypes>(
        self: pin::Pin<&mut Self>,
        chip: &C,
        expected_entry_leaf_node_preauth_cca_protection_digest: &[u8],
        image_layout: &layout::ImageLayout,
        root_key: &keys::RootKey,
        keys_cache: &mut keys::KeyCacheRef<ST>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(InodeIndexTreeLeafNode, InodeIndexTreeLayout), NvFsError>> {
        let this = pin::Pin::into_inner(self);

        let result = loop {
            match &mut this.fut_state {
                InodeIndexReadEntryLeafTreeNodePreauthCcaProtectedFutureState::Init => {
                    let node_allocation_blocks = layout::AllocBlockCount::from(
                        1u64 << (image_layout.index_tree_node_allocation_blocks_log2 as u32),
                    );
                    // The addition does not overflow, both addends have the upper seven bits clear.
                    let entry_leaf_node_extent = layout::PhysicalAllocBlockRange::new(
                        this.entry_leaf_node_allocation_blocks_begin,
                        this.entry_leaf_node_allocation_blocks_begin + node_allocation_blocks,
                    );

                    let read_entry_leaf_node_fut = read_preauth::ReadExtentUnauthenticatedFuture::new(
                        &entry_leaf_node_extent,
                        image_layout.allocation_block_size_128b_log2,
                    );
                    this.fut_state = InodeIndexReadEntryLeafTreeNodePreauthCcaProtectedFutureState::ReadEntryLeafNode {
                        read_entry_leaf_node_fut,
                    };
                }
                InodeIndexReadEntryLeafTreeNodePreauthCcaProtectedFutureState::ReadEntryLeafNode {
                    read_entry_leaf_node_fut,
                } => {
                    let encrypted_entry_leaf_node =
                        match chip::NvChipFuture::poll(pin::Pin::new(read_entry_leaf_node_fut), chip, cx) {
                            task::Poll::Ready(Ok(encrypted_entry_leaf_node)) => encrypted_entry_leaf_node,
                            task::Poll::Ready(Err(e)) => break Err(e),
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    // Before decrypting, verify the preauth CCA protection HMAC.
                    let preauth_cca_protection_digest_len =
                        hash::hash_alg_digest_len(image_layout.preauth_cca_protection_hmac_hash_alg) as usize;
                    let mut preauth_cca_protection_digest = match try_alloc_vec(preauth_cca_protection_digest_len) {
                        Ok(preauth_cca_protection_digest) => preauth_cca_protection_digest,
                        Err(e) => break Err(NvFsError::from(e)),
                    };

                    if let Err(e) = entry_leaf_node_preautch_cca_hmac(
                        &mut preauth_cca_protection_digest,
                        io_slices::SingletonIoSlice::new(&encrypted_entry_leaf_node).map_infallible_err(),
                        image_layout,
                        root_key,
                        keys_cache,
                    ) {
                        break Err(e);
                    }
                    if ct_cmp::ct_bytes_eq(
                        &preauth_cca_protection_digest,
                        expected_entry_leaf_node_preauth_cca_protection_digest,
                    )
                    .unwrap()
                        == 0
                    {
                        break Err(NvFsError::AuthenticationFailure);
                    }

                    // Ok, decrypt.  For the key domain, note that SpecialInode::IndexRoot is
                    // considered to represent the inode index as a whole in this context here.
                    let tree_node_encrypted_block_layout = match encryption_entities::EncryptedBlockLayout::new(
                        image_layout.block_cipher_alg,
                        image_layout.index_tree_node_allocation_blocks_log2,
                        image_layout.allocation_block_size_128b_log2,
                    ) {
                        Ok(inode_index_tree_node_encryption_block_layout) => {
                            inode_index_tree_node_encryption_block_layout
                        }
                        Err(e) => break Err(e),
                    };
                    let tree_node_encryption_key = match keys::KeyCache::get_key(
                        keys_cache,
                        root_key,
                        &keys::KeyId::new(
                            SpecialInode::IndexRoot as u32,
                            InodeKeySubdomain::InodeData as u32,
                            keys::KeyPurpose::Encryption,
                        ),
                    ) {
                        Ok(inode_index_node_encryption_key) => inode_index_node_encryption_key,
                        Err(e) => break Err(e),
                    };
                    let tree_node_decryption_block_cipher_instance =
                        match symcipher::SymBlockCipherModeDecryptionInstance::new(
                            tpm2_interface::TpmiAlgCipherMode::Cbc,
                            &image_layout.block_cipher_alg,
                            &tree_node_encryption_key,
                        ) {
                            Ok(tree_node_decryption_block_cipher_instance) => {
                                tree_node_decryption_block_cipher_instance
                            }
                            Err(e) => break Err(NvFsError::from(e)),
                        };
                    drop(tree_node_encryption_key);
                    let tree_node_decryption_instance = match encryption_entities::EncryptedBlockDecryptionInstance::new(
                        tree_node_encrypted_block_layout.clone(),
                        tree_node_decryption_block_cipher_instance,
                    ) {
                        Ok(tree_node_decryption_instance) => tree_node_decryption_instance,
                        Err(e) => break Err(e),
                    };
                    let tree_layout = match inode_index::InodeIndexTreeLayout::new(tree_node_encrypted_block_layout) {
                        Ok(inode_index_tree_layout) => inode_index_tree_layout,
                        Err(e) => break Err(e),
                    };
                    let tree_node_encoded_len = tree_layout.encoded_node_len();
                    let mut decrypted_entry_leaf_node = match try_alloc_vec(tree_node_encoded_len) {
                        Ok(decrypted_entry_leaf_node) => decrypted_entry_leaf_node,
                        Err(e) => break Err(NvFsError::from(e)),
                    };
                    if let Err(e) = tree_node_decryption_instance.decrypt_one_block(
                        io_slices::SingletonIoSliceMut::new(&mut decrypted_entry_leaf_node).map_infallible_err(),
                        io_slices::SingletonIoSlice::new(&encrypted_entry_leaf_node).map_infallible_err(),
                    ) {
                        break Err(e);
                    }
                    drop(encrypted_entry_leaf_node);
                    drop(tree_node_decryption_instance);

                    // Decode.
                    let entry_leaf_node = match inode_index::InodeIndexTreeLeafNode::decode(
                        this.entry_leaf_node_allocation_blocks_begin,
                        decrypted_entry_leaf_node,
                        &tree_layout,
                    ) {
                        Ok(inode_index_entry_leaf_node) => inode_index_entry_leaf_node,
                        Err(e) => break Err(e),
                    };

                    break Ok((entry_leaf_node, tree_layout));
                }
                InodeIndexReadEntryLeafTreeNodePreauthCcaProtectedFutureState::Done => unreachable!(),
            }
        };

        this.fut_state = InodeIndexReadEntryLeafTreeNodePreauthCcaProtectedFutureState::Done;
        task::Poll::Ready(result)
    }
}

/// Bootstrap the [`InodeIndex`] at filesystem opening time, after the authentication tree based
/// authentication has become available.
pub struct InodeIndexBootstrapFuture<ST: sync_types::SyncTypes, C: chip::NvChip>
where
    ST::RwLock<InodeIndexTreeNodeCache>: marker::Unpin,
{
    entry_leaf_node_preauth_cca_protection_digest: Vec<u8>,
    tree_layout: InodeIndexTreeLayout,
    tree_node_encryption_instance: Option<encryption_entities::EncryptedBlockEncryptionInstance>,
    tree_node_decryption_instance: Option<encryption_entities::EncryptedBlockDecryptionInstance>,
    tree_nodes_cache: ST::RwLock<InodeIndexTreeNodeCache>,
    fut_state: InodeIndexBootstrapFutureState<C>,
}

enum InodeIndexBootstrapFutureState<C: chip::NvChip> {
    Init {
        entry_leaf_node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
    },
    ReadEntryLeafNode {
        entry_leaf_node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        read_fut: InodeIndexReadTreeNodeFuture<C>,
    },
    ReadRootNode {
        root_node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        read_fut: InodeIndexReadTreeNodeFuture<C>,
    },
    Finalize {
        root_node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        root_node_level: u32,
    },
    Done,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> InodeIndexBootstrapFuture<ST, C>
where
    ST::RwLock<InodeIndexTreeNodeCache>: marker::Unpin,
{
    pub fn new(
        entry_leaf_node_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        entry_leaf_node_preauth_cca_protection_digest: Vec<u8>,
        image_layout: &layout::ImageLayout,
        root_key: &keys::RootKey,
        keys_cache: &mut keys::KeyCacheRef<ST>,
    ) -> Result<Self, NvFsError> {
        let tree_node_encrypted_block_layout = encryption_entities::EncryptedBlockLayout::new(
            image_layout.block_cipher_alg,
            image_layout.index_tree_node_allocation_blocks_log2,
            image_layout.allocation_block_size_128b_log2,
        )?;
        let tree_node_encryption_key = keys::KeyCache::get_key(
            keys_cache,
            root_key,
            &keys::KeyId::new(
                SpecialInode::IndexRoot as u32,
                InodeKeySubdomain::InodeData as u32,
                keys::KeyPurpose::Encryption,
            ),
        )?;
        let tree_node_encryption_block_cipher_instance = symcipher::SymBlockCipherModeEncryptionInstance::new(
            tpm2_interface::TpmiAlgCipherMode::Cbc,
            &image_layout.block_cipher_alg,
            &tree_node_encryption_key,
        )?;
        let tree_node_decryption_block_cipher_instance = symcipher::SymBlockCipherModeDecryptionInstance::new(
            tpm2_interface::TpmiAlgCipherMode::Cbc,
            &image_layout.block_cipher_alg,
            &tree_node_encryption_key,
        )?;
        drop(tree_node_encryption_key);
        let tree_node_encryption_instance = encryption_entities::EncryptedBlockEncryptionInstance::new(
            tree_node_encrypted_block_layout.clone(),
            tree_node_encryption_block_cipher_instance,
        )?;
        let tree_node_decryption_instance = encryption_entities::EncryptedBlockDecryptionInstance::new(
            tree_node_encrypted_block_layout.clone(),
            tree_node_decryption_block_cipher_instance,
        )?;

        let tree_layout = InodeIndexTreeLayout::new(tree_node_encrypted_block_layout)?;
        let tree_nodes_cache = InodeIndexTreeNodeCache::new(&tree_layout, 1);

        Ok(Self {
            entry_leaf_node_preauth_cca_protection_digest,
            tree_layout,
            tree_node_encryption_instance: Some(tree_node_encryption_instance),
            tree_node_decryption_instance: Some(tree_node_decryption_instance),
            tree_nodes_cache: ST::RwLock::from(tree_nodes_cache),
            fut_state: InodeIndexBootstrapFutureState::Init {
                entry_leaf_node_allocation_blocks_begin,
            },
        })
    }

    pub fn poll(
        self: pin::Pin<&mut Self>,
        chip: &C,
        fs_config: &CocoonFsConfig,
        alloc_bitmap: &alloc_bitmap::AllocBitmap,
        auth_tree: &mut auth_tree::AuthTreeRef<'_, ST>,
        read_buffer: &read_buffer::ReadBuffer<ST>,
        cx: &mut core::task::Context<'_>,
    ) -> task::Poll<Result<InodeIndex<ST>, NvFsError>> {
        let this = pin::Pin::into_inner(self);

        loop {
            match &mut this.fut_state {
                InodeIndexBootstrapFutureState::Init {
                    entry_leaf_node_allocation_blocks_begin,
                } => {
                    // Note: the entry leaf node had been read before, but only with preauth CCA
                    // protection (to get the Authentication Tree's + Alloc Bitmap File's extents).
                    // Read again, now with full authentication through the Authentication Tree.
                    let read_fut = InodeIndexReadTreeNodeFuture::new(
                        None,
                        *entry_leaf_node_allocation_blocks_begin,
                        Some(0),
                        false,
                    );
                    this.fut_state = InodeIndexBootstrapFutureState::ReadEntryLeafNode {
                        entry_leaf_node_allocation_blocks_begin: *entry_leaf_node_allocation_blocks_begin,
                        read_fut,
                    };
                }
                InodeIndexBootstrapFutureState::ReadEntryLeafNode {
                    entry_leaf_node_allocation_blocks_begin,
                    read_fut,
                } => {
                    let tree_node_decryption_instance = match this.tree_node_decryption_instance.as_ref() {
                        Some(tree_node_decryption_instance) => tree_node_decryption_instance,
                        None => {
                            this.fut_state = InodeIndexBootstrapFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    let entry_leaf_node_ref = match InodeIndexReadTreeNodeFuture::poll(
                        pin::Pin::new(read_fut),
                        chip,
                        fs_config,
                        alloc_bitmap,
                        auth_tree,
                        &this.tree_layout,
                        &this.tree_nodes_cache,
                        tree_node_decryption_instance,
                        read_buffer,
                        cx,
                    ) {
                        task::Poll::Ready((_, Ok(node_ref))) => node_ref,
                        task::Poll::Ready((_, Err(e))) => {
                            this.fut_state = InodeIndexBootstrapFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let entry_leaf_node = match entry_leaf_node_ref.get_node() {
                        Ok(entry_leaf_node) => entry_leaf_node,
                        Err(e) => {
                            this.fut_state = InodeIndexBootstrapFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    let entry_leaf_node = match entry_leaf_node {
                        InodeIndexTreeNode::Leaf(entry_leaf_node) => entry_leaf_node,
                        InodeIndexTreeNode::Internal(_) => {
                            this.fut_state = InodeIndexBootstrapFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    let index_root_inode_entry_index = match entry_leaf_node
                        .lookup(SpecialInode::IndexRoot as u32, &this.tree_layout)
                    {
                        Ok(Ok(index_root_inode_entry_index)) => index_root_inode_entry_index,
                        Ok(Err(_)) => {
                            this.fut_state = InodeIndexBootstrapFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(CocoonFsFormatError::SpecialInodeMissing)));
                        }
                        Err(e) => {
                            this.fut_state = InodeIndexBootstrapFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    let root_node_extent_ptr = match entry_leaf_node
                        .encoded_entry_extent_ptr(index_root_inode_entry_index, &this.tree_layout)
                    {
                        Ok(root_node_extent_ptr) => *root_node_extent_ptr,
                        Err(e) => {
                            this.fut_state = InodeIndexBootstrapFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    drop(entry_leaf_node_ref);

                    let root_node_extent = match extent_ptr::EncodedExtentPtr::from(root_node_extent_ptr)
                        .decode(fs_config.image_layout.allocation_block_size_128b_log2 as u32)
                    {
                        Ok(Some((root_node_extent, false))) => root_node_extent,
                        Ok(Some((_, true))) => {
                            // Indirect extent. Not allowed for the index root node.
                            this.fut_state = InodeIndexBootstrapFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(
                                CocoonFsFormatError::InvalidIndexRootExtents,
                            )));
                        }
                        Ok(None) => {
                            // The inode exists, but the extents reference is nil, which is invalid.
                            this.fut_state = InodeIndexBootstrapFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(CocoonFsFormatError::InvalidExtents)));
                        }
                        Err(e) => {
                            this.fut_state = InodeIndexBootstrapFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    if root_node_extent.block_count()
                        != layout::AllocBlockCount::from(
                            1u64 << (this
                                .tree_layout
                                .node_encrypted_block_layout
                                .get_block_allocation_blocks_log2() as u32),
                        )
                    {
                        // The encoded root node extent's length must match the tree node size.
                        this.fut_state = InodeIndexBootstrapFutureState::Done;
                        return task::Poll::Ready(Err(NvFsError::from(CocoonFsFormatError::InvalidIndexRootExtents)));
                    }

                    if root_node_extent.begin() == *entry_leaf_node_allocation_blocks_begin {
                        // The entry leaf node is the root, all done.
                        this.fut_state = InodeIndexBootstrapFutureState::Finalize {
                            root_node_allocation_blocks_begin: *entry_leaf_node_allocation_blocks_begin,
                            root_node_level: 0,
                        };
                    } else {
                        // Read the tree root node in order to determine the tree depth.
                        let read_fut = InodeIndexReadTreeNodeFuture::new(None, root_node_extent.begin(), None, false);
                        this.fut_state = InodeIndexBootstrapFutureState::ReadRootNode {
                            root_node_allocation_blocks_begin: root_node_extent.begin(),
                            read_fut,
                        };
                    }
                }
                InodeIndexBootstrapFutureState::ReadRootNode {
                    root_node_allocation_blocks_begin,
                    read_fut,
                } => {
                    let tree_node_decryption_instance = match this.tree_node_decryption_instance.as_ref() {
                        Some(tree_node_decryption_instance) => tree_node_decryption_instance,
                        None => {
                            this.fut_state = InodeIndexBootstrapFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    let root_node_ref = match InodeIndexReadTreeNodeFuture::poll(
                        pin::Pin::new(read_fut),
                        chip,
                        fs_config,
                        alloc_bitmap,
                        auth_tree,
                        &this.tree_layout,
                        &this.tree_nodes_cache,
                        tree_node_decryption_instance,
                        read_buffer,
                        cx,
                    ) {
                        task::Poll::Ready((_, Ok(root_node_ref))) => root_node_ref,
                        task::Poll::Ready((_, Err(e))) => {
                            this.fut_state = InodeIndexBootstrapFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };

                    let root_node = match root_node_ref.get_node() {
                        Ok(root_node) => root_node,
                        Err(e) => {
                            this.fut_state = InodeIndexBootstrapFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };
                    let root_node = match root_node {
                        InodeIndexTreeNode::Internal(root_node) => root_node,
                        InodeIndexTreeNode::Leaf(_) => {
                            // It's already know that the entry leaf node is not the root, hence the
                            // root cannot be a leaf.
                            this.fut_state = InodeIndexBootstrapFutureState::Done;
                            return task::Poll::Ready(Err(NvFsError::from(CocoonFsFormatError::InvalidIndexNode)));
                        }
                    };
                    let root_node_level = match root_node.node_level(&this.tree_layout) {
                        Ok(root_node_level) => root_node_level,
                        Err(e) => {
                            this.fut_state = InodeIndexBootstrapFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };

                    // Insert the root node into the cache.
                    match root_node_ref {
                        InodeIndexTreeNodeRef::Owned {
                            node: root_node,
                            is_modified_by_transaction,
                        } => {
                            if is_modified_by_transaction {
                                this.fut_state = InodeIndexBootstrapFutureState::Done;
                                return task::Poll::Ready(Err(nvfs_err_internal!()));
                            }
                            // RwLock::get_mut() would be better, but the borrow checker does not
                            // understand the cache borrow can get cancelled here in this
                            // destructureing.
                            let mut tree_nodes_cache = this.tree_nodes_cache.write();
                            tree_nodes_cache.reconfigure(root_node_level + 1);
                            tree_nodes_cache.insert(root_node_level, root_node);
                        }
                        InodeIndexTreeNodeRef::CacheEntryRef {
                            cache_guard,
                            cache_entry_index: _,
                        } => {
                            // The cache had initially been configured for a tree depth of one, so
                            // the root node should not have been inserted there.
                            debug_assert!(false);
                            drop(cache_guard);
                            // RwLock::get_mut() would be better, but the borrow checker does not
                            // understand the cache borrow can get cancelled here in this
                            // destructureing.
                            let mut tree_nodes_cache = this.tree_nodes_cache.write();
                            tree_nodes_cache.reconfigure(root_node_level + 1);
                        }
                        InodeIndexTreeNodeRef::TransactionStagedUpdatesNodeRef { .. }
                        | InodeIndexTreeNodeRef::TransactionUpdatedNodesCacheEntryRef { .. } => {
                            // The node had not been read through a transaction.
                            this.fut_state = InodeIndexBootstrapFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    this.fut_state = InodeIndexBootstrapFutureState::Finalize {
                        root_node_allocation_blocks_begin: *root_node_allocation_blocks_begin,
                        root_node_level,
                    };
                }
                InodeIndexBootstrapFutureState::Finalize {
                    root_node_allocation_blocks_begin,
                    root_node_level,
                } => {
                    let tree_node_encryption_instance = match this.tree_node_encryption_instance.take() {
                        Some(tree_node_encryption_instance) => tree_node_encryption_instance,
                        None => {
                            this.fut_state = InodeIndexBootstrapFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };
                    let tree_node_decryption_instance = match this.tree_node_decryption_instance.take() {
                        Some(tree_node_decryption_instance) => tree_node_decryption_instance,
                        None => {
                            this.fut_state = InodeIndexBootstrapFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };
                    let inode_index = InodeIndex {
                        layout: this.tree_layout.clone(),
                        entry_leaf_node_preauth_cca_protection_digest: mem::take(
                            &mut this.entry_leaf_node_preauth_cca_protection_digest,
                        ),
                        index_tree_levels: *root_node_level + 1,
                        tree_nodes_cache: mem::replace(
                            &mut this.tree_nodes_cache,
                            ST::RwLock::from(InodeIndexTreeNodeCache::new(&this.tree_layout, 0)),
                        ),
                        root_node_allocation_blocks_begin: *root_node_allocation_blocks_begin,
                        tree_node_encryption_instance,
                        tree_node_decryption_instance,
                    };
                    this.fut_state = InodeIndexBootstrapFutureState::Done;
                    return task::Poll::Ready(Ok(inode_index));
                }
                InodeIndexBootstrapFutureState::Done => unreachable!(),
            }
        }
    }
}
