// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`AuthTreeDataBlocksUpdateStates`] for managing a
//! [`Transaction`](super::Transaction)'s associated data updates.

extern crate alloc;
use alloc::vec::Vec;

use crate::{
    crypto::CryptoError,
    fs::{
        NvFsError,
        cocoonfs::{alloc_bitmap, auth_tree, layout},
    },
    nvfs_err_internal,
    utils_common::{
        bitmanip::{BitManip as _, UBitManip as _},
        fixed_vec::FixedVec,
        io_slices::{self, IoSlicesIter as _, IoSlicesMutIter as _},
    },
};
use core::{convert, mem, ops, slice};

#[cfg(doc)]
use super::journal_allocations::TransactionAllocateJournalStagingCopiesFuture;
#[cfg(doc)]
use super::prepare_staged_updates_application::TransactionPrepareStagedUpdatesApplicationFuture;
#[cfg(doc)]
use layout::ImageLayout;

/// Cached [Allocation Block](ImageLayout::allocation_block_size_128b_log2)
/// data.
///
/// The cached data itself is amended by a flag whether or not its
/// authenticated.
pub(super) struct CachedEncryptedAllocationBlockData {
    /// The [Allocation Block's](ImageLayout::allocation_block_size_128b_log2)
    /// encrypted data.
    encrypted_data: FixedVec<u8, 7>,
    /// Whether or not `encrypted_data` is authenticated.
    authenticated: bool,
}

impl CachedEncryptedAllocationBlockData {
    /// Instantiate a [`CachedEncryptedAllocationBlockData`].
    ///
    /// The `encrypted_data` is initially tracked as unauthenticated.
    ///
    /// # Arguments:
    ///
    /// * `encrypted_data` - The [Allocation
    ///   Block](ImageLayout::allocation_block_size_128b_log2) data to cache.
    pub fn new(encrypted_data: FixedVec<u8, 7>) -> Self {
        debug_assert!(!encrypted_data.is_empty());
        Self {
            encrypted_data,
            authenticated: false,
        }
    }

    /// Get the cached data.
    pub fn get_encrypted_data(&self) -> &[u8] {
        &self.encrypted_data
    }

    /// Whether or not the cached data is authenticated.
    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// Mark the cached data as authenticated.
    pub fn set_authenticated(&mut self) {
        self.authenticated = true;
    }

    /// Obtain the cached data back.
    pub fn into_encrypted_data(self) -> FixedVec<u8, 7> {
        self.encrypted_data
    }
}

/// Details specific to the
/// [`AllocationBlockUpdateNvSyncStateAllocated::Unmodified`] state.
pub(super) struct AllocationBlockUpdateNvSyncStateAllocatedUnmodified {
    /// Cached [Allocation Block](ImageLayout::allocation_block_size_128b_log2)
    /// data, if any.
    pub cached_encrypted_data: Option<CachedEncryptedAllocationBlockData>,

    /// Whether or not the unmodifed data has been copied over to the [Journal
    /// Staging
    /// Copy](AuthTreeDataBlockUpdateState::get_journal_staging_copy_allocation_blocks_begin) already.
    ///
    /// All of a [Device IO
    /// block's](crate::blkdev::NvBlkDev::io_block_size_128b_log2) [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2) are homogenous in
    /// that regard.
    pub copied_to_journal: bool,
}

/// Details specific to the
/// [`AllocationBlockUpdateNvSyncStateAllocated::Modified`] state.
pub(super) enum AllocationBlockUpdateNvSyncStateAllocatedModified {
    /// The most recently applied [staged
    /// update](AllocationBlockUpdateStagedUpdate) has not been written out
    /// to the [Journal Staging
    /// Copy](AuthTreeDataBlockUpdateState::get_journal_staging_copy_allocation_blocks_begin) yet.
    ///
    /// The updated contents are considered for the reproduction of the
    /// containing [Authentication Tree Data Block'
    /// s](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// [authentication digest](AuthTreeDataBlockUpdateState::auth_digest),
    /// if any and if needed. The main motivation for having this
    /// intermediate state is the ability to selectively write out
    /// updates or e.g.  discard unmodified buffers at a [Device IO
    /// block](crate::blkdev::NvBlkDev::io_block_size_128b_log2) granularity in
    /// case a single [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// comprises several such ones.
    JournalDirty {
        /// The encrypted data as applied from a [staged
        /// update](AllocationBlockUpdateStagedUpdate).
        ///
        /// As the data is not coming from extern storage, it's always
        /// considered genuine.
        authenticated_encrypted_data: FixedVec<u8, 7>,
    },

    /// The most recently applied [staged
    /// update](AllocationBlockUpdateStagedUpdate) has been written out to
    /// the [Journal Staging
    /// Copy](AuthTreeDataBlockUpdateState::get_journal_staging_copy_allocation_blocks_begin).
    JournalClean {
        /// Cached [Allocation
        /// Block](ImageLayout::allocation_block_size_128b_log2) data, if any.
        cached_encrypted_data: Option<CachedEncryptedAllocationBlockData>,
    },
}

/// Details specific to the [`AllocationBlockUpdateNvSyncState::Allocated`]
/// state.
pub(super) enum AllocationBlockUpdateNvSyncStateAllocated {
    /// No [staged update](AllocationBlockUpdateStagedUpdate) has been applied
    /// to the [Allocation
    /// Block's](ImageLayout::allocation_block_size_128b_log2) associated
    /// [storage tracking state](AllocationBlockUpdateNvSyncState) yet.
    Unmodified(AllocationBlockUpdateNvSyncStateAllocatedUnmodified),

    /// Some [staged update](AllocationBlockUpdateStagedUpdate) has been applied
    /// to the [Allocation
    /// Block's](ImageLayout::allocation_block_size_128b_log2) associated
    /// [storage tracking state](AllocationBlockUpdateNvSyncState).
    ///
    /// Note that this does *not* necessarily imply that the change has actually
    /// been written out to storage, as it could still be in the
    /// [`JournalDirty`](AllocationBlockUpdateNvSyncStateAllocatedModified::JournalDirty) state.
    Modified(AllocationBlockUpdateNvSyncStateAllocatedModified),
}

/// Representation of
/// [`AllocationBlockUpdateNvSyncStateUnallocated::target_state`].
pub(super) enum AllocationBlockUpdateNvSyncStateUnallocatedTargetState {
    /// The target [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) had been
    /// unallocated before the transaction, and remains so.
    ///
    /// `is_initialized` is set to true if the target [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) can be considered
    /// to have been filled with essentially random data, which is relevant
    /// when trimming is disabled and will be true if some other Allocation
    /// Block of the containing [IO
    /// Block](ImageLayout::io_block_allocation_blocks_log2) had been allocated.
    Unallocated { is_initialized: bool },

    /// The target Allocation Block had been allocated before the transaction,
    /// but got deallocated in the course.
    Allocated,
}

impl AllocationBlockUpdateNvSyncStateUnallocatedTargetState {
    /// Determine whether the target [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) can be considered
    /// to have been filled with essentially random data.
    pub fn is_initialized(&self) -> bool {
        match self {
            Self::Unallocated { is_initialized } => *is_initialized,
            Self::Allocated => true,
        }
    }
}

/// Details specific to the [`AllocationBlockUpdateNvSyncState::Unallocated`]
/// state.
pub(super) struct AllocationBlockUpdateNvSyncStateUnallocated {
    /// (Essentially) random data to write to the unallocated [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2).
    pub(super) random_fillup: Option<FixedVec<u8, 7>>,

    /// Whether or not some essentially random data has been writen to the
    /// [Journal Staging
    /// Copy](AuthTreeDataBlockUpdateState::get_journal_staging_copy_allocation_blocks_begin)
    /// already.
    pub(super) copied_to_journal: bool,

    /// Details about the target [Allocation
    /// Block's](ImageLayout::allocation_block_size_128b_log2) state from
    /// before the transaction.
    pub(super) target_state: AllocationBlockUpdateNvSyncStateUnallocatedTargetState,
}

/// Representation of the [`AllocationBlockUpdateState::nv_sync_state`] field.
pub(super) enum AllocationBlockUpdateNvSyncState {
    /// The [Allocation Block](ImageLayout::allocation_block_size_128b_log2) is
    /// allocated.
    Allocated(AllocationBlockUpdateNvSyncStateAllocated),

    /// The [Allocation Block](ImageLayout::allocation_block_size_128b_log2)
    /// is unallocated.
    Unallocated(AllocationBlockUpdateNvSyncStateUnallocated),
}

/// Representation of the [`AllocationBlockUpdateState::staged_update`] field.
pub(super) enum AllocationBlockUpdateStagedUpdate {
    /// No update staged.
    None,

    /// The [Allocation Block](ImageLayout::allocation_block_size_128b_log2) is
    /// to get deallocated.
    Deallocate,

    /// The [Allocation Block's](ImageLayout::allocation_block_size_128b_log2)
    /// contents are to get overwritten with `encrypted_data`.
    Update { encrypted_data: FixedVec<u8, 7> },

    /// A previous update to either the [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) itself or some
    /// other in a logical sequence it's a member of failed and the contents
    /// are to be considered indeterminate.
    ///
    /// A subsequent update staging operation may move the state out of
    /// `FailedUpdate` again.
    FailedUpdate,
}

/// Update status of a single [`Allocation
/// Block`](ImageLayout::allocation_block_size_128b_log2).
///
/// Managed exclusively at
/// [AuthTreeDataBlockUpdateState::allocation_blocks_states].
pub struct AllocationBlockUpdateState {
    /// The [Allocation Block's](ImageLayout::allocation_block_size_128b_log2)
    /// update status on storage.
    ///
    /// Most importantly, next to dirtiness, this provides the authorative
    /// source of information on how to reconstruct the containing
    /// [Authentication Tree Data
    /// Block's](ImageLayout::auth_tree_data_block_allocation_blocks_log2) most
    /// recent [`AuthTreeDataBlockUpdateState::auth_digest`] value, if any,
    /// which becomes important when some Allocation Block data buffers of
    /// the containing Authentication Tree Data Block had previously been
    /// discarded, but need to get reloaded.
    pub(super) nv_sync_state: AllocationBlockUpdateNvSyncState,

    /// The update staged for application to the [Allocation
    /// Block's](ImageLayout::allocation_block_size_128b_log2) [storage tracking
    /// state](AllocationBlockUpdateNvSyncState), if any.
    ///
    /// The purpose of staging updates separately is to foster a potential
    /// accumulation of updates to several different Allocation Blocks in a
    /// containing [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) before
    /// applying them collectively to their associated [storage tracking
    /// state](AllocationBlockUpdateNvSyncState) each, which potentially
    /// alleviates the need to authenticate the formers' contents.
    pub(super) staged_update: AllocationBlockUpdateStagedUpdate,
}

impl AllocationBlockUpdateState {
    /// Determine whether the [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) is
    /// allocated and has its data updated by the transaction.
    pub fn has_modified_data(&self) -> bool {
        // Consider a failed update as a modification so that any attempt to
        // subsequently read it will report an error as appropriate.
        matches!(
            self.staged_update,
            AllocationBlockUpdateStagedUpdate::Update { .. } | AllocationBlockUpdateStagedUpdate::FailedUpdate
        ) || matches!(
            self.nv_sync_state,
            AllocationBlockUpdateNvSyncState::Allocated(AllocationBlockUpdateNvSyncStateAllocated::Modified(..))
        )
    }

    /// Determine whether the [`AllocationBlockUpdateState`] has the [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) data loaded and
    /// authenticated.
    pub fn has_encrypted_data_loaded(&self) -> Option<bool> {
        match &self.staged_update {
            AllocationBlockUpdateStagedUpdate::None => (),
            AllocationBlockUpdateStagedUpdate::Update { .. } => {
                return Some(true);
            }
            AllocationBlockUpdateStagedUpdate::Deallocate => {
                return None;
            }
            AllocationBlockUpdateStagedUpdate::FailedUpdate => {
                // The Allocation Block's contents are indeterminate. Return a fake indication
                // that the data is loaded, so that it will not be attempted to
                // get read from storage and an error will get reported upon
                // subsequently accessing it.
                return Some(true);
            }
        }

        match &self.nv_sync_state {
            AllocationBlockUpdateNvSyncState::Unallocated(..) => None,
            AllocationBlockUpdateNvSyncState::Allocated(allocated_state) => match allocated_state {
                AllocationBlockUpdateNvSyncStateAllocated::Unmodified(unmodified_state) => unmodified_state
                    .cached_encrypted_data
                    .as_ref()
                    .map(|cached_encrypted_data| cached_encrypted_data.is_authenticated()),
                AllocationBlockUpdateNvSyncStateAllocated::Modified(modified_state) => match modified_state {
                    AllocationBlockUpdateNvSyncStateAllocatedModified::JournalClean { cached_encrypted_data } => {
                        cached_encrypted_data
                            .as_ref()
                            .map(|cached_encrypted_data| cached_encrypted_data.is_authenticated())
                    }
                    AllocationBlockUpdateNvSyncStateAllocatedModified::JournalDirty { .. } => Some(true),
                },
            },
        }
    }

    /// Access the [Allocation
    /// Block's](ImageLayout::allocation_block_size_128b_log2) authenticated
    /// encrypted data.
    ///
    /// Must get called only if
    /// [`has_encrypted_data_loaded()`](Self::has_encrypted_data_loaded) returns
    /// true.
    pub fn get_authenticated_encrypted_data(&self) -> Result<&[u8], NvFsError> {
        match &self.staged_update {
            AllocationBlockUpdateStagedUpdate::None => (),
            AllocationBlockUpdateStagedUpdate::Update { encrypted_data } => {
                return Ok(encrypted_data.as_slice());
            }
            AllocationBlockUpdateStagedUpdate::Deallocate => {
                return Err(nvfs_err_internal!());
            }
            AllocationBlockUpdateStagedUpdate::FailedUpdate => (),
        }

        match &self.nv_sync_state {
            AllocationBlockUpdateNvSyncState::Unallocated(..) => Err(nvfs_err_internal!()),
            AllocationBlockUpdateNvSyncState::Allocated(allocated_state) => match allocated_state {
                AllocationBlockUpdateNvSyncStateAllocated::Unmodified(unmodified_state) => {
                    match unmodified_state.cached_encrypted_data.as_ref() {
                        Some(cached_encrypted_data) => {
                            if cached_encrypted_data.is_authenticated() {
                                Ok(cached_encrypted_data.get_encrypted_data())
                            } else {
                                Err(nvfs_err_internal!())
                            }
                        }
                        None => Err(nvfs_err_internal!()),
                    }
                }
                AllocationBlockUpdateNvSyncStateAllocated::Modified(modified_state) => match modified_state {
                    AllocationBlockUpdateNvSyncStateAllocatedModified::JournalClean { cached_encrypted_data } => {
                        match cached_encrypted_data {
                            Some(cached_encrypted_data) => {
                                if cached_encrypted_data.is_authenticated() {
                                    Ok(cached_encrypted_data.get_encrypted_data())
                                } else {
                                    Err(nvfs_err_internal!())
                                }
                            }
                            None => Err(nvfs_err_internal!()),
                        }
                    }
                    AllocationBlockUpdateNvSyncStateAllocatedModified::JournalDirty {
                        authenticated_encrypted_data,
                    } => Ok(authenticated_encrypted_data),
                },
            },
        }
    }
}

/// Track a [transaction's](super::Transaction) accumulated data updates to a
/// given [Authentication
/// Tree Data Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2).
///
/// Note that even though perhaps completely unrelated otherwise, all of an
/// Authentication Tree Data Block's indivdual [Allocation
/// Blocks](ImageLayout::allocation_block_size_128b_log2) contribute
/// to its authentication digest, hence are managed together.
///
/// Instances are exclusively stored and managed in the containing
/// [`AuthTreeDataBlocksUpdateStates::states`].
pub struct AuthTreeDataBlockUpdateState {
    /// Location of the [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// associated with and tracked by this instance.
    target_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,

    /// Location of the associated Journal Staging Copy, if any.
    ///
    /// For details, refer to the description of
    /// [`Self::get_journal_staging_copy_allocation_blocks_begin()`].
    journal_staging_copy_allocation_blocks_begin: Option<layout::PhysicalAllocBlockIndex>,

    /// Update states of the [Authentication Tree Data
    /// Block's](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// individual [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2).
    allocation_blocks_states: FixedVec<AllocationBlockUpdateState, 0>,

    /// The updated authentication digest, if any.
    ///
    /// All information needed for its reproduction (except possibly the data
    /// itself), can be collectively found in the
    /// [`allocation_blocks_states`'s](Self::allocation_blocks_states)
    /// [`nv_sync_state`s](AllocationBlockUpdateState::nv_sync_state).
    ///
    /// The following invariant holds: if there is any modification to the
    /// [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) and any
    /// of the `allocation_blocks_states` entries (corresponding to
    /// allocated [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2)) does not have the
    /// data [loaded and
    /// authenticated](AllocationBlockUpdateState::has_encrypted_data_loaded),
    /// then there will always be an `auth_digest`.
    ///
    /// In principle it would be possible to authenticate the missing data
    /// without an `auth_digest` from the authentication tree if the
    /// corresponding [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2) all happened to be
    /// unmodified, but this case is currently not supported as it's
    /// probably not worth the extra complexity.
    auth_digest: Option<FixedVec<u8, 5>>,
}

impl AuthTreeDataBlockUpdateState {
    /// Location of the [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// associated with and tracked by this instance.
    pub fn get_target_allocation_blocks_begin(&self) -> layout::PhysicalAllocBlockIndex {
        self.target_allocation_blocks_begin
    }

    /// Obain the location of the associated Journal Staging Copy, if any.
    ///
    /// In general, data updates are not written directly to their target
    /// location, but to a "Journal Staging Copy" first (and only applied to
    /// the final destination once all of the Journal is in place). This
    /// returns the location of the Journal Staging Area, if any has been
    /// allocated for the given [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// already.
    ///
    /// In some special cases it is possible that data writes are made directly
    /// to their target locations "in-place" without going through a journal
    /// staging copy first. In this case the location returned by
    /// `get_journal_staging_copy_allocation_blocks_begin()` matches that of
    /// [`get_target_allocation_blocks_begin()`](Self::get_target_allocation_blocks_begin).
    ///
    /// If no Journal Staging Copy area has been allocated yet, `None` is being
    /// returned.
    ///
    /// If the [IO Block size](ImageLayout::io_block_allocation_blocks_log2)
    /// happens to be larger than that of an Authentication Tree Data Block,
    /// then all of the IO Block needs to get copied to a Journal Staging
    /// Area, even if some of the Authentication Tree Data Blocks contained
    /// therein are unmodified. The individual Authentication Tree Data Blocks'
    /// offsets in that staging copy IO Block match their position within
    /// the [destination](Self::get_target_allocation_blocks_begin) IO Block
    /// each in this case.
    ///
    /// If on the other hand a single Authentication Tree Data Block comprises
    /// several IO Blocks, then only the IO Blocks with updates in them need
    /// to get copied to a Journal Staging Area, and in principle it would
    /// be possible to write them to arbitrary locations, independent of
    /// each other. However, even though unmodified IO Blocks are indeed not
    /// getting copied, the ones which are retain their relative positions
    /// for their Journal Staging Copies in order to simplify the
    /// implementation. That is, a single block the size of an Authentication
    /// Tree Data Block is being allocated for the IO Blocks' staging copies
    /// and those being actually written out retain their relative position
    /// (including distances) therein.
    ///
    /// # See also:
    ///
    /// * [`TransactionAllocateJournalStagingCopiesFuture`].
    pub fn get_journal_staging_copy_allocation_blocks_begin(&self) -> Option<layout::PhysicalAllocBlockIndex> {
        self.journal_staging_copy_allocation_blocks_begin
    }

    /// Get the [Authentication Tree Data
    /// Block's](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// updated authentication digest, if any.
    pub fn get_auth_digest(&self) -> Option<&[u8]> {
        self.auth_digest.as_deref()
    }

    /// Steal the [Authentication Tree Data
    /// Block's](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// updated authentication digest, if any.
    pub fn steal_auth_digest(&mut self) -> Option<FixedVec<u8, 5>> {
        self.auth_digest.take()
    }

    /// Set the [Authentication Tree Data
    /// Block's](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// updated authentication digest, if any.
    pub fn set_auth_digest(&mut self, auth_digest: FixedVec<u8, 5>) {
        self.auth_digest = Some(auth_digest);
    }

    /// Iterate over the [Authentication Tree Data
    /// Block's](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// individual [Allocation
    /// Block's](ImageLayout::allocation_block_size_128b_log2)
    /// [`AllocationBlockUpdateState`]s.
    pub fn iter_allocation_blocks(&self) -> slice::Iter<'_, AllocationBlockUpdateState> {
        self.allocation_blocks_states.iter()
    }

    /// Iterate over the [Authentication Tree Data
    /// Block's](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// individual [Allocation
    /// Block's](ImageLayout::allocation_block_size_128b_log2)
    /// [`AllocationBlockUpdateState`]s with `mut` access.
    pub fn iter_allocation_blocks_mut(&mut self) -> slice::IterMut<'_, AllocationBlockUpdateState> {
        self.allocation_blocks_states.iter_mut()
    }

    /// Iterate over the [Authentication Tree Data
    /// Block's](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// individual [Allocation
    /// Blocks](ImageLayout::allocation_block_size_128b_log2) for the purpose of
    /// [computing the authentication
    /// digest](auth_tree::AuthTreeConfig::digest_data_block).
    ///
    /// # Arguments:
    ///
    /// * `image_header_end` - [End of the filesystem image header on
    ///   storage](crate::fs::cocoonfs::image_header::MutableImageHeader::physical_location).
    /// * `expect_authenticated_data` - If true, verify in the course of the
    ///   iteration that all of the Authentication Tree Data
    ///   Block's](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    ///   individual [Allocation
    ///   Block's](ImageLayout::allocation_block_size_128b_log2)
    ///   [`AllocationBlockUpdateState`]s have their data available as
    ///   authenticated.
    pub(super) fn iter_auth_digest_allocation_blocks(
        &self,
        image_header_end: layout::PhysicalAllocBlockIndex,
        expect_authenticated_data: bool,
    ) -> AuthTreeDataBlockUpdateStateAuthDigestAllocationBlocksIter<'_> {
        AuthTreeDataBlockUpdateStateAuthDigestAllocationBlocksIter::new(
            self,
            image_header_end,
            expect_authenticated_data,
        )
    }
}

impl ops::Index<usize> for AuthTreeDataBlockUpdateState {
    type Output = AllocationBlockUpdateState;

    fn index(&self, index: usize) -> &Self::Output {
        &self.allocation_blocks_states[index]
    }
}

/// Iterator returned by
/// [`AuthTreeDataBlockUpdateState::iter_auth_digest_allocation_blocks`].
pub(super) struct AuthTreeDataBlockUpdateStateAuthDigestAllocationBlocksIter<'a> {
    auth_tree_block_allocation_blocks_states_iter: slice::Iter<'a, AllocationBlockUpdateState>,
    skip_count: usize,
    expect_authenticated_data: bool,
}

impl<'a> AuthTreeDataBlockUpdateStateAuthDigestAllocationBlocksIter<'a> {
    /// Instantiate a
    /// [`AuthTreeDataBlockUpdateStateAuthDigestAllocationBlocksIter`].
    ///
    /// # Arguments:
    ///
    /// * `auth_tree_data_block_update_state` - The
    ///   [`AuthTreeDataBlockUpdateState`] to create an iterator over.
    /// * `image_header_end` - [End of the filesystem image header on
    ///   storage](crate:
    ///   fs::cocoonfs::image_header::MutableImageHeader::physical_location).
    /// * `expect_authenticated_data` - If true, verify in the course of the
    ///   iteration that all of the Authentication Tree Data
    ///   Block's](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    ///   individual [Allocation
    ///   Block's](ImageLayout::allocation_block_size_128b_log2)
    ///   [`AllocationBlockUpdateState`]s have their data available as
    ///   authenticated.
    fn new(
        auth_tree_data_block_update_state: &'a AuthTreeDataBlockUpdateState,
        image_header_end: layout::PhysicalAllocBlockIndex,
        expect_authenticated_data: bool,
    ) -> Self {
        // The image header is always unauthenticated. If the current Authentication
        // Tree Data Block is overlapping with it, skip over the corresponding
        // head region.
        let skip_count = if image_header_end <= auth_tree_data_block_update_state.get_target_allocation_blocks_begin() {
            0
        } else {
            usize::try_from(u64::from(
                image_header_end - auth_tree_data_block_update_state.get_target_allocation_blocks_begin(),
            ))
            .unwrap_or(usize::MAX)
            .min(auth_tree_data_block_update_state.allocation_blocks_states.len())
        };
        Self {
            auth_tree_block_allocation_blocks_states_iter: auth_tree_data_block_update_state
                .allocation_blocks_states
                .iter(),
            skip_count,
            expect_authenticated_data,
        }
    }
}

impl<'a> Iterator for AuthTreeDataBlockUpdateStateAuthDigestAllocationBlocksIter<'a> {
    type Item = Result<Option<&'a [u8]>, NvFsError>;

    fn next(&mut self) -> Option<Self::Item> {
        // If in the image header region, which is always unauthenticated, return None.
        if self.skip_count != 0 {
            self.skip_count -= 1;
            self.auth_tree_block_allocation_blocks_states_iter.next();
            return Some(Ok(None));
        }

        self.auth_tree_block_allocation_blocks_states_iter
            .next()
            .map(|allocation_block_state| match &allocation_block_state.nv_sync_state {
                AllocationBlockUpdateNvSyncState::Unallocated(_) => Ok(None),
                AllocationBlockUpdateNvSyncState::Allocated(allocated_state) => match allocated_state {
                    AllocationBlockUpdateNvSyncStateAllocated::Unmodified(unmodified_state) => {
                        match unmodified_state.cached_encrypted_data.as_ref() {
                            Some(cached_encrypted_data) => {
                                if self.expect_authenticated_data && !cached_encrypted_data.is_authenticated() {
                                    return Err(nvfs_err_internal!());
                                }
                                Ok(Some(cached_encrypted_data.get_encrypted_data()))
                            }
                            None => Err(nvfs_err_internal!()),
                        }
                    }
                    AllocationBlockUpdateNvSyncStateAllocated::Modified(modified_state) => match modified_state {
                        AllocationBlockUpdateNvSyncStateAllocatedModified::JournalDirty {
                            authenticated_encrypted_data,
                        } => Ok(Some(authenticated_encrypted_data.as_slice())),
                        AllocationBlockUpdateNvSyncStateAllocatedModified::JournalClean { cached_encrypted_data } => {
                            match cached_encrypted_data {
                                Some(cached_encrypted_data) => {
                                    if self.expect_authenticated_data && !cached_encrypted_data.is_authenticated() {
                                        return Err(nvfs_err_internal!());
                                    }
                                    Ok(Some(cached_encrypted_data.get_encrypted_data()))
                                }
                                None => Err(nvfs_err_internal!()),
                            }
                        }
                    },
                },
            })
    }
}

/// Track all of a [transaction's](super::Transaction) accumulated data updates
/// at [Authentication
/// Tree Data Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
/// granularity.
///
/// Note that even though perhaps completely unrelated otherwise, all of an
/// [Authentication Tree
/// Data Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
/// indivdual [Allocation Blocks](ImageLayout::allocation_block_size_128b_log2)
/// contribute to its authentication digest, hence are managed together in an
/// [`AuthTreeDataBlockUpdateState`] instance each.
///
/// The collection is sparse, in general only
/// - [Authentication Tree Data
///   Blocks](ImageLayout::auth_tree_data_block_allocation_blocks_log2) with
///   modifications in them and
/// - possibly unmodified [Authentication Tree Data
///   Blocks](ImageLayout::auth_tree_data_block_allocation_blocks_log2) part of
///   a larger modified [IO Block](ImageLayout::io_block_allocation_blocks_log2)
///   or [Device IO Block](crate::blkdev::NvBlkDev::io_block_size_128b_log2) have
///   associated entries.
///
/// For each [Allocation Block level entry](AllocationBlockUpdateState), the
/// current [state as already written or to be written to
/// storage](AllocationBlockUpdateNvSyncState) is tracked.  In addition to that,
/// there's an [update staging](AllocationBlockUpdateStagedUpdate) layer. Its
/// main purpose is to enable the accumulation of multiple independent updates
/// to a containing [Authentication Tree Data
/// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) individual
/// [Allocation Blocks](ImageLayout::allocation_block_size_128b_log2), thereby
/// potentially alleviating the need to read in and authenticate the
/// [Authentication Tree Data
/// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) in case
/// none of its original [Allocation
/// Blocks](ImageLayout::allocation_block_size_128b_log2) are retained.
/// Furthermore, staged updates may get reset, which provides a mechanism to
/// revert them for graceful error handling.
///
/// In general, the application of data update writes takes the following steps:
/// 1. The states corresponding to the updated storage range are
///    [inserted](Self::insert_missing_in_range).
/// 2. The update staging buffers are
///    [allocated](Self::allocate_allocation_blocks_update_staging_bufs) and the
///    updated data [written to
///    those](Self::iter_allocation_blocks_update_staging_bufs_mut).
/// 3. Eventually, once one or more data updates have been staged, they're
///    getting prepared for application to the storage tracking state via
///    [`TransactionPrepareStagedUpdatesApplicationFuture`].  This will read in
///    and authenticate any retained data in the containing [Authentication Tree
///    Data Blocks](ImageLayout::auth_tree_data_block_allocation_blocks_log2).
/// 4. The staged updates are then getting [applied to the storage tracking
///    state](Self::apply_allocation_blocks_staged_updates), tracked as
///    [dirty](AllocationBlockUpdateNvSyncStateAllocatedModified::JournalDirty).
/// 5. Somewhen later, the updates may get written to storage, possibly to a
///    [journal staging
///    copy](AuthTreeDataBlockUpdateState::get_journal_staging_copy_allocation_blocks_begin)
///    as appropriate, by means of a
///    [`TransactionWriteDirtyDataFuture`](super::write_dirty_data::TransactionWriteDirtyDataFuture).
pub struct AuthTreeDataBlocksUpdateStates {
    /// State of data updates at [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)
    /// granularity, with one entry for each modified such block.
    ///
    /// Ordered by the associated Authentication Tree Data Blocks' [location on
    /// storage](AuthTreeDataBlockUpdateState::get_target_allocation_blocks_begin).
    states: Vec<AuthTreeDataBlockUpdateState>,

    /// Copied verbatim from
    /// [`ImageLayout`](ImageLayout::io_block_allocation_blocks_log2).
    io_block_allocation_blocks_log2: u8,

    /// Copied verbatim from
    /// [`ImageLayout`](ImageLayout::auth_tree_data_block_allocation_blocks_log2).
    auth_tree_data_block_allocation_blocks_log2: u8,

    /// Copied verbatim from
    /// [`ImageLayout`](ImageLayout::allocation_block_size_128b_log2).
    allocation_block_size_128b_log2: u8,
}

impl AuthTreeDataBlocksUpdateStates {
    /// Create a new [`AuthTreeDataBlocksUpdateStates`] instance.
    ///
    /// # Arguments:
    ///
    /// * `io_block_allocation_blocks_log2` - Value of
    ///   [`ImageLayout::io_block_allocation_blocks_log2`].
    /// * `auth_tree_data_block_allocation_blocks_log2` - Value of
    ///   [`ImageLayout::auth_tree_data_block_allocation_blocks_log2`].
    /// * `allocation_block_size_128_log2` - Value of
    ///   [`ImageLayout::allocation_block_size_128b_log2`].
    pub fn new(
        io_block_allocation_blocks_log2: u8,
        auth_tree_data_block_allocation_blocks_log2: u8,
        allocation_block_size_128b_log2: u8,
    ) -> Self {
        AuthTreeDataBlocksUpdateStates {
            states: Vec::new(),
            io_block_allocation_blocks_log2,
            auth_tree_data_block_allocation_blocks_log2,
            allocation_block_size_128b_log2,
        }
    }

    /// Number of [`AuthTreeDataBlockUpdateState`] entries.
    pub fn len(&self) -> usize {
        self.states.len()
    }

    /// Clear.
    pub fn clear(&mut self) {
        self.states = Vec::new();
    }

    /// Lookup an
    /// [Authentication Tree Data Block level entry
    /// index](AuthTreeDataBlocksUpdateStatesIndex) by [location on
    /// storage](AuthTreeDataBlockUpdateState::get_target_allocation_blocks_begin).
    ///
    /// Returns the index wrapped in a result, in an [`Ok`] if a match was
    /// found, in an [`Err`] otherwise. In the latter error case, the index
    /// returned may serve as an insertion hint to
    /// [`insert_missing_in_range`](Self::insert_missing_in_range).
    ///
    /// # Arguments:
    ///
    /// * `target_auth_tree_data_block_allocation_blocks_begin` - storage
    ///   location to lookup an entry for. Must be aligned to a multiple of the
    ///   Authentication Tree Data Block size.
    pub fn lookup_auth_tree_data_block_update_state_index(
        &self,
        target_auth_tree_data_block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
    ) -> Result<AuthTreeDataBlocksUpdateStatesIndex, AuthTreeDataBlocksUpdateStatesIndex> {
        debug_assert_eq!(
            target_auth_tree_data_block_allocation_blocks_begin
                .align_down(self.auth_tree_data_block_allocation_blocks_log2 as u32),
            target_auth_tree_data_block_allocation_blocks_begin
        );
        self.states
            .binary_search_by(|s| {
                s.target_allocation_blocks_begin
                    .cmp(&target_auth_tree_data_block_allocation_blocks_begin)
            })
            .map(AuthTreeDataBlocksUpdateStatesIndex::from)
            .map_err(AuthTreeDataBlocksUpdateStatesIndex::from)
    }

    /// Lookup an [Allocation Block level index
    /// range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange)
    /// tracking a given [storage
    /// region]((AuthTreeDataBlockUpdateState::get_target_allocation_blocks_begin).
    ///
    ///
    /// Returns the index range wrapped in an [`Ok`] if some overlapping update
    /// tracking states had been found, or an insertion position index
    /// wrapped in an [`Err`] otherwise.
    ///
    /// # Arguments:
    ///
    /// * `target_allocation_blocks_range` - The storage region to search for.
    pub fn lookup_allocation_blocks_update_states_index_range(
        &self,
        target_allocation_blocks_range: &layout::PhysicalAllocBlockRange,
    ) -> Result<AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange, AuthTreeDataBlocksUpdateStatesIndex> {
        let auth_tree_data_block_allocation_blocks_log2 = self.auth_tree_data_block_allocation_blocks_log2 as u32;
        let first_states_index = self.lookup_auth_tree_data_block_update_state_index(
            target_allocation_blocks_range
                .begin()
                .align_down(auth_tree_data_block_allocation_blocks_log2),
        );
        let (first_states_index, states_allocation_blocks_range_begin) = match first_states_index {
            Ok(first_states_index) => (
                first_states_index,
                AuthTreeDataBlocksUpdateStatesAllocationBlockIndex::new(
                    first_states_index,
                    u64::from(
                        target_allocation_blocks_range.begin()
                            - self[first_states_index].get_target_allocation_blocks_begin(),
                    ) as usize,
                ),
            ),
            Err(first_states_index) => {
                if first_states_index.index >= self.states.len()
                    || self[first_states_index].get_target_allocation_blocks_begin()
                        >= target_allocation_blocks_range.end()
                {
                    return Err(first_states_index);
                }
                (
                    first_states_index,
                    AuthTreeDataBlocksUpdateStatesAllocationBlockIndex::from(first_states_index),
                )
            }
        };

        let states_allocation_blocks_range_end = if self[first_states_index].get_target_allocation_blocks_begin()
            == target_allocation_blocks_range
                .end()
                .align_down(auth_tree_data_block_allocation_blocks_log2)
        {
            AuthTreeDataBlocksUpdateStatesAllocationBlockIndex::new(
                first_states_index,
                u64::from(
                    target_allocation_blocks_range.end()
                        - self[first_states_index].get_target_allocation_blocks_begin(),
                ) as usize,
            )
        } else {
            match self.lookup_auth_tree_data_block_update_state_index(
                target_allocation_blocks_range
                    .end()
                    .align_down(auth_tree_data_block_allocation_blocks_log2),
            ) {
                Ok(last_states_index) => AuthTreeDataBlocksUpdateStatesAllocationBlockIndex::new(
                    last_states_index,
                    u64::from(
                        target_allocation_blocks_range.end()
                            - self[last_states_index].get_target_allocation_blocks_begin(),
                    ) as usize,
                ),
                Err(last_states_index) => AuthTreeDataBlocksUpdateStatesAllocationBlockIndex::from(last_states_index),
            }
        };

        Ok(AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::new(
            &states_allocation_blocks_range_begin,
            &states_allocation_blocks_range_end,
        ))
    }

    /// Iterate over the [`AuthTreeDataBlockUpdateState`] entries.
    ///
    /// If `range` is specified, restrict the iteration to it, otherwise iterate
    /// over all entries.
    ///
    /// # Arguments:
    ///
    /// * `range` - [Authentication Tree Data Block level entry index
    ///   range](AuthTreeDataBlocksUpdateStatesIndexRange) to restrict the
    ///   iteration to, if any.
    pub fn iter_auth_tree_data_blocks<'a>(
        &'a self,
        range: Option<&'a AuthTreeDataBlocksUpdateStatesIndexRange>,
    ) -> slice::Iter<'a, AuthTreeDataBlockUpdateState> {
        match range {
            Some(range) => self.states[usize::from(range.begin)..usize::from(range.end)].iter(),
            None => self.states.iter(),
        }
    }

    /// Iterate over the [`AllocationBlockUpdateState`] entries.
    ///
    /// If `range` is specified, restrict the iteration to it, otherwise iterate
    /// over all entries.
    ///
    /// # Arguments:
    ///
    /// * `range` - [Allocation Block level entry index
    ///   range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange) to
    ///   restrict the iteration to, if any.
    pub fn iter_allocation_blocks(
        &self,
        states_allocation_blocks_range: Option<&AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange>,
    ) -> AuthTreeDataBlocksUpdateStatesAllocationBlocksIter<'_> {
        AuthTreeDataBlocksUpdateStatesAllocationBlocksIter::new(self, states_allocation_blocks_range)
    }

    /// Iterate over the [`AllocationBlockUpdateState`] entries with `mut`
    /// access.
    ///
    /// If `range` is specified, restrict the iteration to it, otherwise iterate
    /// over all entries.
    ///
    /// # Arguments:
    ///
    /// * `range` - [Allocation Block level entry index
    ///   range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange) to
    ///   restrict the iteration to, if any.
    pub fn iter_allocation_blocks_mut(
        &mut self,
        states_allocation_blocks_range: Option<&AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange>,
    ) -> AuthTreeDataBlocksUpdateStatesAllocationBlocksIterMut<'_> {
        AuthTreeDataBlocksUpdateStatesAllocationBlocksIterMut::new(self, states_allocation_blocks_range)
    }

    /// Insert missing states for a given [storage
    /// region](AuthTreeDataBlockUpdateState::get_target_allocation_blocks_begin).
    ///
    /// Inserted states start out in an unmodified state, with their allocation
    /// and [initialization
    /// status](AllocationBlockUpdateNvSyncStateUnallocatedTargetState::is_initialized)
    /// deduced from the provided allocation bitmap information.
    ///
    /// Returns the [`[Allocation Block level index
    /// range`](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange)
    /// corresponding to the physical input `target_range` on success or an
    /// error otherwise.
    ///
    /// In either case, error or not, the number of states inserted is getting
    /// returned unconditionally. If non-zero, all pre-existing update
    /// tracking state indices obtained before the call are invalidated.
    ///
    /// # Arguments:
    ///
    /// * `target_range` - The range to populate missing states for.
    /// * `alloc_bitmap` - Reference to the [Allocation
    ///   Bitmap](alloc_bitmap::AllocBitmap) in its state from before the
    ///   transaction owning `self` has started.
    /// * `pending_frees` - Deallocations from the owning transaction to
    ///   logically apply on top of `alloc_bitmap`.
    /// * `states_insertion_index_hint` - Optional insertion hint, if specified,
    ///   must correspond to the result of
    ///   [`lookup_auth_tree_data_block_update_state_index()`](Self::lookup_auth_tree_data_block_update_state_index)
    ///   on `target_range.begin()`.
    pub fn insert_missing_in_range(
        &mut self,
        target_range: layout::PhysicalAllocBlockRange,
        alloc_bitmap: &alloc_bitmap::AllocBitmap,
        pending_frees: &alloc_bitmap::SparseAllocBitmap,
        states_insertion_index_hint: Option<AuthTreeDataBlocksUpdateStatesIndex>,
    ) -> Result<(AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange, usize), (NvFsError, usize)> {
        let auth_tree_data_block_allocation_blocks_log2 = self.auth_tree_data_block_allocation_blocks_log2 as u32;
        let io_block_allocation_blocks_log2 = self.io_block_allocation_blocks_log2 as u32;
        let aligned_target_range = target_range
            .align(auth_tree_data_block_allocation_blocks_log2)
            .ok_or_else(|| nvfs_err_internal!())
            .map_err(|e| (e, 0))?;
        let auth_tree_data_blocks_count = usize::try_from(
            u64::from(aligned_target_range.block_count()) >> self.auth_tree_data_block_allocation_blocks_log2,
        )
        .map_err(|_| NvFsError::MemoryAllocationFailure)
        .map_err(|e| (e, 0))?;
        debug_assert!(auth_tree_data_blocks_count >= 1);

        // Consider the insertion position hint, if given, or lookup the target_range
        // otherwise.
        let states_index_range_begin = match states_insertion_index_hint {
            Some(states_insertion_index_hint) => {
                debug_assert!(states_insertion_index_hint.index <= self.states.len());
                debug_assert!(
                    states_insertion_index_hint.index == 0
                        || self.states[states_insertion_index_hint.index - 1].target_allocation_blocks_begin
                            < aligned_target_range.begin()
                );
                if states_insertion_index_hint.index == self.states.len() {
                    Err(states_insertion_index_hint)
                } else if self.states[states_insertion_index_hint.index].target_allocation_blocks_begin
                    == aligned_target_range.begin()
                {
                    Ok(states_insertion_index_hint)
                } else {
                    debug_assert!(
                        self.states[states_insertion_index_hint.index].target_allocation_blocks_begin
                            > aligned_target_range.begin()
                    );
                    Err(states_insertion_index_hint)
                }
            }
            None => self.lookup_auth_tree_data_block_update_state_index(aligned_target_range.begin()),
        };

        // Check if everything is there already, otherwise unpack the result from the
        // lookup.
        let states_index_range_begin = match states_index_range_begin {
            Ok(states_index_range_begin) => {
                if auth_tree_data_blocks_count == 1
                    || self.states.len() - states_index_range_begin.index >= auth_tree_data_blocks_count
                        && self.states[states_index_range_begin.index + auth_tree_data_blocks_count - 1]
                            .target_allocation_blocks_begin
                            == aligned_target_range.begin()
                                + layout::AllocBlockCount::from(
                                    (auth_tree_data_blocks_count as u64 - 1)
                                        << auth_tree_data_block_allocation_blocks_log2,
                                )
                {
                    let begin = AuthTreeDataBlocksUpdateStatesAllocationBlockIndex::from(states_index_range_begin)
                        .advance(
                            target_range.begin() - aligned_target_range.begin(),
                            auth_tree_data_block_allocation_blocks_log2,
                        );
                    let end = begin.advance(target_range.block_count(), auth_tree_data_block_allocation_blocks_log2);
                    return Ok((
                        AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange { begin, end },
                        0,
                    ));
                }

                states_index_range_begin
            }

            Err(states_index_range_begin) => states_index_range_begin,
        };

        // Count how many Authentication Tree Data Blocks are missing.
        let missing_auth_tree_data_blocks_count =
            if auth_tree_data_blocks_count != 1 && states_index_range_begin.index < self.states.len() {
                let mut missing_auth_tree_data_blocks_count = auth_tree_data_blocks_count;
                for s in &self.states[states_index_range_begin.index..] {
                    if s.target_allocation_blocks_begin >= aligned_target_range.end() {
                        break;
                    }
                    missing_auth_tree_data_blocks_count -= 1;
                }
                missing_auth_tree_data_blocks_count
            } else {
                auth_tree_data_blocks_count
            };

        self.states
            .try_reserve_exact(missing_auth_tree_data_blocks_count)
            .map_err(|_| NvFsError::MemoryAllocationFailure)
            .map_err(|e| (e, 0))?;
        let mut total_inserted_states_count = 0;
        let mut cur_states_insertion_index = states_index_range_begin.index;
        let mut cur_target_allocation_blocks_begin = aligned_target_range.begin();
        let empty_sparse_alloc_bitmap = alloc_bitmap::SparseAllocBitmapUnion::new(&[]);
        let mut io_block_chunked_alloc_bitmap_iter = alloc_bitmap.iter_chunked_at_allocation_block(
            &empty_sparse_alloc_bitmap,
            &empty_sparse_alloc_bitmap,
            cur_target_allocation_blocks_begin.align_down(io_block_allocation_blocks_log2),
            1u32 << self.io_block_allocation_blocks_log2,
        );
        let mut cur_io_block_alloc_bitmap = io_block_chunked_alloc_bitmap_iter.next().unwrap_or(0);
        let mut pending_frees_iter = pending_frees.iter_at(cur_target_allocation_blocks_begin);
        let mut cur_pending_frees = pending_frees_iter.next();
        while cur_target_allocation_blocks_begin < aligned_target_range.end() {
            let cur_gap_target_allocation_blocks_end = if cur_states_insertion_index < self.states.len() {
                let next_state_target_allocation_blocks_begin =
                    self.states[cur_states_insertion_index].target_allocation_blocks_begin;
                if next_state_target_allocation_blocks_begin == cur_target_allocation_blocks_begin {
                    // There's already an entry corresponding to the current Authentication Tree
                    // Data Block, skip past it.
                    cur_states_insertion_index += 1;
                    let last_io_block_index =
                        u64::from(cur_target_allocation_blocks_begin) >> io_block_allocation_blocks_log2;
                    cur_target_allocation_blocks_begin +=
                        layout::AllocBlockCount::from(1u64 << self.auth_tree_data_block_allocation_blocks_log2);
                    let cur_io_block_index =
                        u64::from(cur_target_allocation_blocks_begin) >> io_block_allocation_blocks_log2;
                    for _ in 0..cur_io_block_index - last_io_block_index {
                        cur_io_block_alloc_bitmap = io_block_chunked_alloc_bitmap_iter.next().unwrap_or(0);
                    }
                    continue;
                }

                debug_assert!(next_state_target_allocation_blocks_begin > cur_target_allocation_blocks_begin);
                next_state_target_allocation_blocks_begin.min(aligned_target_range.end())
            } else {
                aligned_target_range.end()
            };

            let cur_gap_auth_tree_data_blocks_count =
                (u64::from(cur_gap_target_allocation_blocks_end - cur_target_allocation_blocks_begin)
                    >> auth_tree_data_block_allocation_blocks_log2) as usize;
            // Track the number of inserted states[] entries for rollback on error.
            let mut cur_gap_inserted_states_count = 0;
            while cur_target_allocation_blocks_begin < cur_gap_target_allocation_blocks_end {
                // Figure out whether the already existant neighbours from the same target IO
                // block, if any, already have a region within some Journal IO block allocated
                // to them. If so, piggy_back on it.
                let cur_journal_staging_copy_allocation_blocks_begin =
                    if self.io_block_allocation_blocks_log2 > self.auth_tree_data_block_allocation_blocks_log2 {
                        let containing_target_io_block_allocation_blocks_begin =
                            cur_target_allocation_blocks_begin.align_down(self.io_block_allocation_blocks_log2 as u32);
                        if cur_states_insertion_index > 0
                            && self.states[cur_states_insertion_index - 1]
                                .target_allocation_blocks_begin
                                .align_down(self.io_block_allocation_blocks_log2 as u32)
                                == containing_target_io_block_allocation_blocks_begin
                        {
                            self.states[cur_states_insertion_index - 1]
                                .journal_staging_copy_allocation_blocks_begin
                                .map(|j| {
                                    j.align_down(self.io_block_allocation_blocks_log2 as u32)
                                        + (cur_target_allocation_blocks_begin
                                            - containing_target_io_block_allocation_blocks_begin)
                                })
                        } else if cur_states_insertion_index < self.states.len()
                            && self.states[cur_states_insertion_index]
                                .target_allocation_blocks_begin
                                .align_down(self.io_block_allocation_blocks_log2 as u32)
                                == containing_target_io_block_allocation_blocks_begin
                        {
                            self.states[cur_states_insertion_index]
                                .journal_staging_copy_allocation_blocks_begin
                                .map(|j| {
                                    j.align_down(self.io_block_allocation_blocks_log2 as u32)
                                        + (cur_target_allocation_blocks_begin
                                            - containing_target_io_block_allocation_blocks_begin)
                                })
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                // To save some Vec element moves due to repeated insertions, append the new one
                // to the end of states[] and rotate afterwards.
                let s = if cur_gap_auth_tree_data_blocks_count != 1 {
                    self.states.push(AuthTreeDataBlockUpdateState {
                        target_allocation_blocks_begin: cur_target_allocation_blocks_begin,
                        journal_staging_copy_allocation_blocks_begin: cur_journal_staging_copy_allocation_blocks_begin,
                        allocation_blocks_states: FixedVec::new_empty(),
                        auth_digest: None,
                    });
                    let states_len = self.states.len();
                    &mut self.states[states_len - 1]
                } else {
                    self.states.insert(
                        cur_states_insertion_index,
                        AuthTreeDataBlockUpdateState {
                            target_allocation_blocks_begin: cur_target_allocation_blocks_begin,
                            journal_staging_copy_allocation_blocks_begin:
                                cur_journal_staging_copy_allocation_blocks_begin,
                            allocation_blocks_states: FixedVec::new_empty(),
                            auth_digest: None,
                        },
                    );
                    &mut self.states[cur_states_insertion_index]
                };
                cur_gap_inserted_states_count += 1;

                let mut cur_target_allocation_block_index = cur_target_allocation_blocks_begin;
                s.allocation_blocks_states = match FixedVec::new_from_fn(
                    1usize << auth_tree_data_block_allocation_blocks_log2,
                    |_| -> Result<AllocationBlockUpdateState, convert::Infallible> {
                        // Initialize the individual Authentication Tree Data Block's Allocation Blocks'
                        // states according to whether the containing IO Block indicates they had been
                        // initialized with something before and also, to whether they'll get freed by
                        // the transaction.
                        let cur_allocation_block_in_io_block_index = u64::from(cur_target_allocation_block_index)
                            & u64::trailing_bits_mask(io_block_allocation_blocks_log2);
                        let allocation_block_state = if (cur_io_block_alloc_bitmap
                            >> cur_allocation_block_in_io_block_index)
                            & 1
                            != 0
                        {
                            // The Allocation Block had been allocated before the transaction started.
                            // If a free is pending for the current Allocation Block, then record that
                            // fact at its state accordingly.
                            let is_free_pending = match &cur_pending_frees {
                                Some((cur_pending_frees_target_allocation_blocks_begin, cur_pending_frees_bitmap)) => {
                                    if *cur_pending_frees_target_allocation_blocks_begin
                                        > cur_target_allocation_block_index
                                    {
                                        // The current pending frees entry is ahead, so this is not one.
                                        false
                                    } else {
                                        // The current pending frees entry is at or before the current
                                        // position. If the former, examine,
                                        // if the latter, advance the pending frees to
                                        // the next one.
                                        if cur_target_allocation_block_index
                                            - *cur_pending_frees_target_allocation_blocks_begin
                                            < layout::AllocBlockCount::from(alloc_bitmap::BitmapWord::BITS as u64)
                                        {
                                            (*cur_pending_frees_bitmap
                                                >> u64::from(
                                                    cur_target_allocation_block_index
                                                        - *cur_pending_frees_target_allocation_blocks_begin,
                                                ))
                                                & 1
                                                != 0
                                        } else {
                                            // Advance to the next pending frees entry and examine if
                                            // now in range.
                                            pending_frees_iter.skip_to(cur_target_allocation_block_index);
                                            cur_pending_frees = pending_frees_iter.next();
                                            cur_pending_frees
                                                .as_ref()
                                                .map(
                                                    |(
                                                        cur_pending_frees_target_allocation_blocks_begin,
                                                        cur_pending_frees_bitmap,
                                                    )| {
                                                        if *cur_pending_frees_target_allocation_blocks_begin
                                                            <= cur_target_allocation_block_index
                                                        {
                                                            (*cur_pending_frees_bitmap
                                                            >> u64::from(
                                                                cur_target_allocation_block_index
                                                                    - *cur_pending_frees_target_allocation_blocks_begin,
                                                            ))
                                                            & 1
                                                            != 0
                                                        } else {
                                                            false
                                                        }
                                                    },
                                                )
                                                .unwrap_or(false)
                                        }
                                    }
                                }
                                None => false,
                            };
                            let staged_update = if is_free_pending {
                                AllocationBlockUpdateStagedUpdate::Deallocate
                            } else {
                                AllocationBlockUpdateStagedUpdate::None
                            };

                            AllocationBlockUpdateState {
                                nv_sync_state: AllocationBlockUpdateNvSyncState::Allocated(
                                    AllocationBlockUpdateNvSyncStateAllocated::Unmodified(
                                        AllocationBlockUpdateNvSyncStateAllocatedUnmodified {
                                            cached_encrypted_data: None,
                                            copied_to_journal: false,
                                        },
                                    ),
                                ),
                                staged_update,
                            }
                        } else {
                            // The Allocation Block had been unallocated before the transaction.
                            // If any Allocation Block from the containing IO Block, if any, had been
                            // allocated by a previous transaction already, then all the remaining
                            // unallocated ones will have been initialized alongside.
                            let target_is_initialized = cur_io_block_alloc_bitmap != 0;
                            AllocationBlockUpdateState {
                                nv_sync_state: AllocationBlockUpdateNvSyncState::Unallocated(
                                    AllocationBlockUpdateNvSyncStateUnallocated {
                                        random_fillup: None,
                                        copied_to_journal: false,
                                        target_state:
                                            AllocationBlockUpdateNvSyncStateUnallocatedTargetState::Unallocated {
                                                is_initialized: target_is_initialized,
                                            },
                                    },
                                ),
                                staged_update: AllocationBlockUpdateStagedUpdate::None,
                            }
                        };

                        cur_target_allocation_block_index += layout::AllocBlockCount::from(1);
                        if cur_target_allocation_block_index.align_down(io_block_allocation_blocks_log2)
                            == cur_target_allocation_block_index
                        {
                            cur_io_block_alloc_bitmap = io_block_chunked_alloc_bitmap_iter.next().unwrap_or(0);
                        }

                        Ok(allocation_block_state)
                    },
                ) {
                    Ok(allocation_blocks_states) => allocation_blocks_states,
                    Err(e) => {
                        // Rollback the partial insertions to leave the states in a clean state.
                        if cur_gap_auth_tree_data_blocks_count != 1 {
                            let states_len = self.states.len();
                            self.states.truncate(states_len - cur_gap_inserted_states_count);
                        } else {
                            self.states.remove(cur_states_insertion_index);
                        }
                        return Err((NvFsError::from(e), total_inserted_states_count));
                    }
                };

                cur_target_allocation_blocks_begin = cur_target_allocation_block_index;
            }
            debug_assert_eq!(cur_target_allocation_blocks_begin, cur_gap_target_allocation_blocks_end);

            debug_assert_eq!(cur_gap_inserted_states_count, cur_gap_auth_tree_data_blocks_count);
            // Do the rotation to move the elements just added temporarily at the end to
            // their actual position.
            if cur_gap_auth_tree_data_blocks_count != 1 {
                self.states[cur_states_insertion_index..].rotate_right(cur_gap_auth_tree_data_blocks_count);
            }
            cur_states_insertion_index += cur_gap_auth_tree_data_blocks_count;
            total_inserted_states_count += cur_gap_auth_tree_data_blocks_count;
        }

        debug_assert_eq!(
            cur_states_insertion_index - usize::from(states_index_range_begin),
            auth_tree_data_blocks_count
        );

        let begin = AuthTreeDataBlocksUpdateStatesAllocationBlockIndex::from(states_index_range_begin).advance(
            target_range.begin() - aligned_target_range.begin(),
            auth_tree_data_block_allocation_blocks_log2,
        );
        let end = begin.advance(target_range.block_count(), auth_tree_data_block_allocation_blocks_log2);
        Ok((
            AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange { begin, end },
            total_inserted_states_count,
        ))
    }

    /// Populate missing entries in an [Authentication Tree Data Block level
    /// index range](AuthTreeDataBlocksUpdateStatesIndexRange) to fill
    /// alignment gaps.
    ///
    /// Populate missing states in the `states_index_range` to make all existing
    /// subranges corresponding to maximally contiguous regions of [storage
    /// locations](AuthTreeDataBlockUpdateState::get_target_allocation_blocks_begin) aligned to the
    /// block size as specified by `target_allocation_blocks_alignment_log2`.
    ///
    /// Gaps of size and alignment of the specified alignment block size are
    /// being skipped over and hence, retained.  The update tracking states
    /// index range returned upon success covers all of
    /// the input `states_index_range`, plus any additional padding states
    /// inserted at the head or tail.
    ///
    /// Any newly inserted states start out in an unmodified state, with their
    /// allocation and [initialization
    /// status](AllocationBlockUpdateNvSyncStateUnallocatedTargetState::is_initialized) deduced from
    /// the provided allocation bitmap information.
    ///
    /// If any new entries have been inserted, any previously obtained update
    /// tracking states index range, including the input
    /// `states_index_range` is invalidated. However, it is possible to
    /// apply correction offsets to such pre-existing index range to account
    /// for the insertions. If new states had been inserted, then the
    /// [offsets](AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets)
    /// applicable to the input `states_index_range` are returned
    /// unconditionally, independent of success. Note that these offsets may
    /// get transformed to apply to other index ranges by
    /// means of [`AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsetsTransformToAfter`] or
    /// [`AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsetsTransformToContaining`] to be setup
    /// before the invocation of this function.
    fn fill_states_index_range_regions_alignment_gaps(
        &mut self,
        states_index_range: &AuthTreeDataBlocksUpdateStatesIndexRange,
        target_allocation_blocks_alignment_log2: u32,
        alloc_bitmap: &alloc_bitmap::AllocBitmap,
        pending_frees: &alloc_bitmap::SparseAllocBitmap,
    ) -> (
        Result<AuthTreeDataBlocksUpdateStatesIndexRange, NvFsError>,
        Option<AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets>,
    ) {
        debug_assert!(usize::from(states_index_range.end) <= self.states.len());
        debug_assert!(target_allocation_blocks_alignment_log2 < usize::BITS);
        let auth_tree_data_block_allocation_blocks_log2 = self.auth_tree_data_block_allocation_blocks_log2 as u32;
        if auth_tree_data_block_allocation_blocks_log2 >= target_allocation_blocks_alignment_log2 {
            // Requested alignment is guaranteed by design.
            return (Ok(states_index_range.clone()), None);
        }

        // Extend the given index range to include missing parts in front or after it
        // within the bounds of the specified alignment's range, if any.
        let mut aligned_states_index_range = self.extend_states_index_range_within_alignment(
            states_index_range.clone(),
            target_allocation_blocks_alignment_log2,
        );

        // Return early if the index range covers a single contiguous, aligned region
        // already.
        if self.is_contiguous_aligned_region(&aligned_states_index_range, target_allocation_blocks_alignment_log2) {
            return (Ok(aligned_states_index_range), None);
        }

        // For returning the info about newly inserted states, compute the number of
        // states to be inserted before the input states_index_range as the
        // difference of the distance to the next downward alignment boundary
        // and the number of states already present in that area.
        let range_target_allocation_blocks_begin =
            self.states[states_index_range.begin.index].target_allocation_blocks_begin;
        // Distance to the alignment boundary, in units of Authentication Tree Data
        // Blocks.
        let alignment_auth_tree_data_blocks_distance_before = (u64::from(range_target_allocation_blocks_begin)
            & u64::trailing_bits_mask(target_allocation_blocks_alignment_log2))
            >> auth_tree_data_block_allocation_blocks_log2;
        let total_missing_states_before_count = alignment_auth_tree_data_blocks_distance_before
            - (states_index_range.begin.index - aligned_states_index_range.begin.index) as u64;

        // And do it analogously for the number of states to be inserted after the input
        // states_index_range.
        let range_last_auth_tree_data_block_target_allocation_blocks_begin =
            self.states[states_index_range.end.index - 1].target_allocation_blocks_begin;
        // Determine the distance to the next alignment boundary, also in units of
        // Authentication Tree Data Blocks, c.f. Hacker's Delight, 2nd edition,
        // 3-1 ("Rounding Up/Down to a Multiple of a Known Power of 2").
        let alignment_auth_tree_data_blocks_distance_after =
            (u64::from(range_last_auth_tree_data_block_target_allocation_blocks_begin)
                .wrapping_add(1u64 << auth_tree_data_block_allocation_blocks_log2)
                .wrapping_neg()
                & u64::trailing_bits_mask(target_allocation_blocks_alignment_log2))
                >> auth_tree_data_block_allocation_blocks_log2;
        let total_missing_states_after_count = alignment_auth_tree_data_blocks_distance_after
            - (aligned_states_index_range.end.index - states_index_range.end.index) as u64;

        let mut total_inserted_states_count = 0usize;
        let mut cur_states_index = aligned_states_index_range.begin;
        while cur_states_index != aligned_states_index_range.end {
            debug_assert!(cur_states_index.index < self.states.len());
            let cur_region_states_index_range = AuthTreeDataBlocksUpdateStatesIndexRange::new(
                cur_states_index,
                self.find_aligned_gap_after(cur_states_index, target_allocation_blocks_alignment_log2)
                    .min(aligned_states_index_range.end),
            );
            if !self
                .is_contiguous_aligned_region(&cur_region_states_index_range, target_allocation_blocks_alignment_log2)
            {
                let cur_region_aligned_target_allocation_blocks_begin = self.states
                    [cur_region_states_index_range.begin.index]
                    .target_allocation_blocks_begin
                    .align_down(target_allocation_blocks_alignment_log2);
                let cur_region_aligned_target_allocation_blocks_end = self.states
                    [cur_region_states_index_range.end.index - 1]
                    .target_allocation_blocks_begin
                    .align_down(target_allocation_blocks_alignment_log2)
                    + layout::AllocBlockCount::from(1u64 << target_allocation_blocks_alignment_log2);
                let (cur_completed_region_states_index_range, cur_inserted_states_count) = match self
                    .insert_missing_in_range(
                        layout::PhysicalAllocBlockRange::new(
                            cur_region_aligned_target_allocation_blocks_begin,
                            cur_region_aligned_target_allocation_blocks_end,
                        ),
                        alloc_bitmap,
                        pending_frees,
                        Some(cur_states_index),
                    ) {
                    Ok((cur_completed_region_states_allocation_blocks_index_range, cur_inserted_states_count)) => {
                        // The states to be inserted before the original input range for
                        // alignment will all be inserted at once.
                        debug_assert!(
                            total_inserted_states_count != 0
                                || cur_inserted_states_count >= total_missing_states_before_count as usize
                        );
                        (
                            AuthTreeDataBlocksUpdateStatesIndexRange::from(
                                cur_completed_region_states_allocation_blocks_index_range,
                            ),
                            cur_inserted_states_count,
                        )
                    }
                    Err((e, cur_inserted_states_count)) => {
                        let inserted_states_after_range_count =
                            if cur_region_states_index_range.end() == aligned_states_index_range.end() {
                                // It's the last iteration. Note that the states to be
                                // inserted after the input range, if any, would all get
                                // inserted in the course of the last loop iteration at
                                // once.  The insertion operation might have failed midways
                                // though, but it would always populate the new states in
                                // order from the front towards the back. For returning the
                                // info about insertions, determine to what extent the
                                // missing states in the region right after the input
                                // states_index_range have been filled.
                                //
                                // The maximum number of states that have been inserted before the
                                // position corresponding to the states_index_range's end is the
                                // total number of states that had been missing within the current
                                // region region minus the number of states missing after the
                                // states_index_range's end. The remainder from
                                // cur_inserted_states_count,
                                // if any, is the desired number of new states populated after
                                // the states_index_range's end.
                                let cur_region_missing_states_count = {
                                    // The number of states that had been missing in the current
                                    // region is the difference
                                    // of the spanned Authentication Tree Data Blocks
                                    // and the number of states that had already been there.
                                    let cur_region_aligned_auth_tree_data_blocks_count = u64::from(
                                        cur_region_aligned_target_allocation_blocks_end
                                            - cur_region_aligned_target_allocation_blocks_begin,
                                    )
                                        >> auth_tree_data_block_allocation_blocks_log2;
                                    debug_assert!(
                                        cur_region_states_index_range.len() as u64
                                            <= cur_region_aligned_auth_tree_data_blocks_count
                                    );
                                    cur_region_aligned_auth_tree_data_blocks_count
                                        - cur_region_states_index_range.len() as u64
                                };
                                debug_assert!(cur_region_missing_states_count >= total_missing_states_after_count);
                                (cur_inserted_states_count as u64)
                                    .saturating_sub(cur_region_missing_states_count - total_missing_states_after_count)
                            } else {
                                0u64
                            };

                        total_inserted_states_count += cur_inserted_states_count;

                        let states_index_range_offsets = if total_inserted_states_count != 0 {
                            debug_assert!(
                                total_inserted_states_count as u64
                                    >= total_missing_states_before_count + total_missing_states_after_count
                            );
                            Some(AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets {
                                inserted_states_before_range_count: total_missing_states_before_count as usize,
                                inserted_states_within_range_count: total_inserted_states_count
                                    - (total_missing_states_before_count + inserted_states_after_range_count) as usize,
                                inserted_states_after_range_count: inserted_states_after_range_count as usize,
                                max_target_allocations_blocks_alignment_log2: target_allocation_blocks_alignment_log2,
                            })
                        } else {
                            None
                        };

                        return (Err(e), states_index_range_offsets);
                    }
                };

                debug_assert_eq!(
                    cur_region_states_index_range.begin,
                    cur_completed_region_states_index_range.begin
                );
                debug_assert!(
                    cur_region_states_index_range.end.index < cur_completed_region_states_index_range.end.index
                );
                debug_assert_eq!(
                    cur_completed_region_states_index_range.end.index,
                    cur_region_states_index_range.end.index + cur_inserted_states_count
                );
                aligned_states_index_range.end.index += cur_inserted_states_count;
                total_inserted_states_count += cur_inserted_states_count;
                cur_states_index = cur_completed_region_states_index_range.end;
            } else {
                cur_states_index = cur_region_states_index_range.end;
            }
        }

        let states_index_range_offsets = if total_inserted_states_count != 0 {
            debug_assert!(
                total_inserted_states_count as u64
                    >= total_missing_states_before_count + total_missing_states_after_count
            );
            Some(AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets {
                inserted_states_before_range_count: total_missing_states_before_count as usize,
                inserted_states_within_range_count: total_inserted_states_count
                    - (total_missing_states_before_count + total_missing_states_after_count) as usize,
                inserted_states_after_range_count: total_missing_states_after_count as usize,
                max_target_allocations_blocks_alignment_log2: target_allocation_blocks_alignment_log2,
            })
        } else {
            None
        };

        (Ok(aligned_states_index_range), states_index_range_offsets)
    }

    /// Populate missing entries in an [Allocation Block level
    /// index range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange)
    /// to fill alignment gaps.
    ///
    /// Convenience function wrapping
    /// [`fill_states_index_range_regions_alignment_gaps()`](Self::fill_states_index_range_regions_alignment_gaps)
    /// to handle the Allocation Block level index domain case.
    pub fn fill_states_allocation_blocks_index_range_regions_alignment_gaps(
        &mut self,
        states_allocation_blocks_index_range: &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        target_allocation_blocks_alignment_log2: u32,
        alloc_bitmap: &alloc_bitmap::AllocBitmap,
        pending_frees: &alloc_bitmap::SparseAllocBitmap,
    ) -> (
        Result<AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange, NvFsError>,
        Option<AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets>,
    ) {
        let auth_tree_data_block_allocation_blocks_log2 = self.auth_tree_data_block_allocation_blocks_log2 as u32;
        if target_allocation_blocks_alignment_log2 >= auth_tree_data_block_allocation_blocks_log2 {
            // The requested alignment is a multiple of the Authentication Tree Data Block
            // size. Fill the containg AuthTreeDataBlocksUpdateStatesIndexRange's region
            // gaps accordingly.
            let states_index_range =
                AuthTreeDataBlocksUpdateStatesIndexRange::from(states_allocation_blocks_index_range.clone());
            let (aligned_states_index_range, states_index_range_offsets) = self
                .fill_states_index_range_regions_alignment_gaps(
                    &states_index_range,
                    target_allocation_blocks_alignment_log2,
                    alloc_bitmap,
                    pending_frees,
                );
            (
                aligned_states_index_range.map(AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::from),
                states_index_range_offsets,
            )
        } else {
            // All contiguous regions intersecting with the specified range are aligned to
            // the Authentication Tree Data Block size by design, which is larger
            // than the requested alignment. All that is left to do is to
            // possibly extend the states_allocation_blocks_index_range's bounds
            // in order to make them aligned.
            (
                Ok(self.extend_states_allocation_blocks_index_range_within_alignment(
                    states_allocation_blocks_index_range,
                    target_allocation_blocks_alignment_log2,
                )),
                None,
            )
        }
    }

    /// Prune [`AuthTreeDataBlockUpdateState`] entries not overlapping with an
    /// [IO Block](ImageLayout::io_block_allocation_blocks_log2) with
    /// pending data updates.
    ///
    /// # Arguments:
    ///
    /// * `abandoned_journal_staging_copy_blocks` - Destination for collecting
    ///   abandoned journal staging copy blocks. Entries will point to the
    ///   beginning of abandoned blocks, all equal to the larger of an
    ///   [Authentication Tree Data
    ///   Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) and
    ///   an [IO Block](layout::ImageLayout::io_block_allocation_blocks_log2) in
    ///   size.
    /// * `image_header_end` - [End of the filesystem image header on
    ///   storage](crate::fs::cocoonfs::image_header::MutableImageHeader::physical_location).
    pub fn prune_unmodified(
        &mut self,
        abandoned_journal_staging_copy_blocks: &mut Vec<layout::PhysicalAllocBlockIndex>,
        image_header_end: layout::PhysicalAllocBlockIndex,
    ) -> Result<(), NvFsError> {
        let io_block_allocation_blocks_log2 = self.io_block_allocation_blocks_log2 as u32;
        let auth_tree_data_block_allocation_blocks_log2 = self.auth_tree_data_block_allocation_blocks_log2 as u32;
        let journal_block_allocation_blocks_log2 =
            io_block_allocation_blocks_log2.max(auth_tree_data_block_allocation_blocks_log2);

        let mut prune_states_range = |this: &mut Self, range_begin: usize, range_end: usize| -> Result<(), NvFsError> {
            // Count how many Journal Staging Blocks will get abandoned and reserve the
            // additional capacity only once.
            let mut abandoned_journal_staging_copy_blocks_in_range = 1usize;
            let mut last_journal_staging_copy_allocation_blocks_begin: Option<layout::PhysicalAllocBlockIndex> = None;
            for i in range_begin..range_end {
                if let Some(cur_journal_staging_copy_allocation_blocks_begin) =
                    this.states[i].get_journal_staging_copy_allocation_blocks_begin()
                {
                    if last_journal_staging_copy_allocation_blocks_begin
                        .map(|last_journal_staging_copy_allocation_blocks_begin| {
                            (u64::from(last_journal_staging_copy_allocation_blocks_begin)
                                ^ u64::from(cur_journal_staging_copy_allocation_blocks_begin))
                                >> journal_block_allocation_blocks_log2
                                != 0
                        })
                        .unwrap_or(true)
                    {
                        abandoned_journal_staging_copy_blocks_in_range += 1;
                    }
                    last_journal_staging_copy_allocation_blocks_begin =
                        Some(cur_journal_staging_copy_allocation_blocks_begin);
                }
            }
            abandoned_journal_staging_copy_blocks.try_reserve(abandoned_journal_staging_copy_blocks_in_range)?;

            // Now add all abandoned Journal Staging Blocks.
            let mut last_journal_staging_copy_allocation_blocks_begin: Option<layout::PhysicalAllocBlockIndex> = None;
            for i in range_begin..range_end {
                if let Some(cur_journal_staging_copy_allocation_blocks_begin) =
                    this.states[i].get_journal_staging_copy_allocation_blocks_begin()
                {
                    if last_journal_staging_copy_allocation_blocks_begin
                        .map(|last_journal_staging_copy_allocation_blocks_begin| {
                            (u64::from(last_journal_staging_copy_allocation_blocks_begin)
                                ^ u64::from(cur_journal_staging_copy_allocation_blocks_begin))
                                >> journal_block_allocation_blocks_log2
                                != 0
                        })
                        .unwrap_or(true)
                    {
                        abandoned_journal_staging_copy_blocks.push(
                            cur_journal_staging_copy_allocation_blocks_begin
                                .align_down(journal_block_allocation_blocks_log2),
                        );
                    }
                    last_journal_staging_copy_allocation_blocks_begin =
                        Some(cur_journal_staging_copy_allocation_blocks_begin);
                }
            }

            // And finally remove the states in the specified range.
            this.states.drain(range_begin..range_end);
            Ok(())
        };

        let mut prune_range_begin: Option<usize> = None;
        let mut cur_states_index = 0usize;
        while cur_states_index < self.states.len() {
            let first_auth_tree_data_block_update_state_in_io_block = &self.states[cur_states_index];
            let mut any_modified = first_auth_tree_data_block_update_state_in_io_block
                .iter_allocation_blocks()
                .any(|allocation_block_update_state| allocation_block_update_state.has_modified_data());

            // The Allocation Blocks from the image header will always get updated at
            // transaction commit, because the root HMAC is being stored there.
            // Don't purge.
            if first_auth_tree_data_block_update_state_in_io_block.get_target_allocation_blocks_begin()
                < image_header_end
            {
                any_modified = true;
            }

            // If the IO Block size is larger than an Authentication Tree Data Block, prune
            // only if all Authentication Tree Data Blocks in the same
            // containing IO Block don't have any data modifications.
            let mut auth_tree_data_block_update_state_in_io_block_index = 1usize;
            while cur_states_index + auth_tree_data_block_update_state_in_io_block_index != self.states.len() {
                let cur_auth_tree_data_block_update_state =
                    &self.states[cur_states_index + auth_tree_data_block_update_state_in_io_block_index];
                if (u64::from(cur_auth_tree_data_block_update_state.get_target_allocation_blocks_begin())
                    ^ u64::from(
                        first_auth_tree_data_block_update_state_in_io_block.get_target_allocation_blocks_begin(),
                    ))
                    >> io_block_allocation_blocks_log2
                    != 0
                {
                    // The Authentication Tree Data Block is in a different IO Block.
                    break;
                }

                any_modified |= cur_auth_tree_data_block_update_state
                    .iter_allocation_blocks()
                    .any(|allocation_block_update_state| allocation_block_update_state.has_modified_data());

                auth_tree_data_block_update_state_in_io_block_index += 1;
            }

            if any_modified {
                if let Some(prune_range_begin) = prune_range_begin.take() {
                    prune_states_range(self, prune_range_begin, cur_states_index)?;
                    cur_states_index = prune_range_begin;
                }
            } else if prune_range_begin.is_none() {
                prune_range_begin = Some(cur_states_index);
            }
            cur_states_index += auth_tree_data_block_update_state_in_io_block_index;
        }

        if let Some(prune_range_begin) = prune_range_begin.take() {
            prune_states_range(self, prune_range_begin, self.states.len())?;
        }
        Ok(())
    }

    /// Test whether the [storage
    /// locations](AuthTreeDataBlockUpdateState::get_target_allocation_blocks_begin) associated with
    /// a given [Authentication Tree Data Block level update tracking state
    /// index range](AuthTreeDataBlocksUpdateStatesIndexRange) form a
    /// contiguous region.
    pub fn is_contiguous_region(&self, states_index_range: &AuthTreeDataBlocksUpdateStatesIndexRange) -> bool {
        debug_assert!(states_index_range.end.index <= self.states.len());
        if states_index_range.is_empty() {
            return true;
        }
        let auth_tree_data_block_allocation_blocks_log2 = self.auth_tree_data_block_allocation_blocks_log2;
        let spanned_auth_tree_data_blocks_range = (u64::from(
            self.states[states_index_range.end.index - 1].target_allocation_blocks_begin
                - self.states[states_index_range.begin.index].target_allocation_blocks_begin,
        ) >> auth_tree_data_block_allocation_blocks_log2)
            + 1;
        debug_assert!(u64::try_from(states_index_range.len()).unwrap() <= spanned_auth_tree_data_blocks_range);
        states_index_range.len() as u64 == spanned_auth_tree_data_blocks_range
    }

    /// Test whether the [storage
    /// locations](AuthTreeDataBlockUpdateState::get_target_allocation_blocks_begin) associated with
    /// a given [Authentication Tree Data Block level update tracking state
    /// index range](AuthTreeDataBlocksUpdateStatesIndexRange) form a
    /// contiguous region aligned to a specified block size
    fn is_contiguous_aligned_region(
        &self,
        states_index_range: &AuthTreeDataBlocksUpdateStatesIndexRange,
        target_allocation_blocks_alignment_log2: u32,
    ) -> bool {
        debug_assert!(states_index_range.end.index <= self.states.len());
        debug_assert!(target_allocation_blocks_alignment_log2 < usize::BITS);
        if states_index_range.is_empty() {
            return true;
        }

        let auth_tree_data_block_allocation_blocks_log2 = self.auth_tree_data_block_allocation_blocks_log2 as u32;
        if auth_tree_data_block_allocation_blocks_log2 >= target_allocation_blocks_alignment_log2 {
            return self.is_contiguous_region(states_index_range);
        }

        // First check if the range's first entry's target beginning is aligned.
        let first_target_allocation_blocks_begin =
            self.states[states_index_range.begin.index].target_allocation_blocks_begin;
        let first_aligned_target_allocation_blocks_begin =
            first_target_allocation_blocks_begin.align_down(target_allocation_blocks_alignment_log2);
        if first_aligned_target_allocation_blocks_begin != first_target_allocation_blocks_begin {
            return false;
        }

        // Now verify that the number of Authentication Tree Data Block Update entries
        // matches what would be expected for the aligned covered target range: if there
        // was a gap, that number would be too small.
        let last_first_aligned_target_allocation_blocks_begin = self.states[states_index_range.end.index - 1]
            .target_allocation_blocks_begin
            .align_down(target_allocation_blocks_alignment_log2);
        (u64::from(last_first_aligned_target_allocation_blocks_begin - first_aligned_target_allocation_blocks_begin)
            >> target_allocation_blocks_alignment_log2)
            + 1
            == (states_index_range.len()
                >> (target_allocation_blocks_alignment_log2 - auth_tree_data_block_allocation_blocks_log2))
                as u64
    }

    /// Test whether the [storage
    /// locations](AuthTreeDataBlockUpdateState::get_target_allocation_blocks_begin) associated with
    /// a given [Allocation Block level update tracking state
    /// index range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange)
    /// form a contiguous region.
    pub fn is_contiguous_allocation_blocks_region(
        &self,
        states_allocation_blocks_index_range: &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    ) -> bool {
        self.is_contiguous_region(&AuthTreeDataBlocksUpdateStatesIndexRange::from(
            states_allocation_blocks_index_range.clone(),
        ))
    }

    /// Test whether the [storage
    /// locations](AuthTreeDataBlockUpdateState::get_target_allocation_blocks_begin) associated with
    /// a given [Allocation Block level update tracking state
    /// index range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange)
    /// form a contiguous region aligned to a specified block size.
    pub fn is_contiguous_aligned_allocation_blocks_region(
        &self,
        states_allocation_blocks_index_range: &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        target_allocation_blocks_alignment_log2: u32,
    ) -> bool {
        if !self.is_contiguous_aligned_region(
            &AuthTreeDataBlocksUpdateStatesIndexRange::from(states_allocation_blocks_index_range.clone()),
            target_allocation_blocks_alignment_log2,
        ) {
            return false;
        }

        if target_allocation_blocks_alignment_log2 >= self.auth_tree_data_block_allocation_blocks_log2 as u32 {
            states_allocation_blocks_index_range
                .begin
                .allocation_block_index_in_auth_tree_data_block
                == 0
                && states_allocation_blocks_index_range
                    .end
                    .allocation_block_index_in_auth_tree_data_block
                    == 0
        } else {
            debug_assert!(target_allocation_blocks_alignment_log2 < usize::BITS);
            (states_allocation_blocks_index_range
                .begin
                .allocation_block_index_in_auth_tree_data_block
                | states_allocation_blocks_index_range
                    .end
                    .allocation_block_index_in_auth_tree_data_block)
                & usize::trailing_bits_mask(target_allocation_blocks_alignment_log2)
                == 0
        }
    }

    /// Find an [Allocation Block level update tracking state index
    /// range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange)'s
    /// maximal leading subrange with a contiguous associated [storage
    /// locations](AuthTreeDataBlockUpdateState::get_target_allocation_blocks_begin).
    pub fn allocation_blocks_range_contiguous_head_subrange(
        &self,
        states_allocation_blocks_index_range: &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    ) -> AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange {
        let mut cur_auth_tree_data_block_update_states_index = states_allocation_blocks_index_range
            .begin
            .auth_tree_data_blocks_update_states_index;
        if cur_auth_tree_data_block_update_states_index
            == states_allocation_blocks_index_range
                .end
                .auth_tree_data_blocks_update_states_index
        {
            // The range spans less than a single Authentication Tree Data Block, hence is
            // contiguous.
            return states_allocation_blocks_index_range.clone();
        }

        let auth_tree_data_block_allocation_blocks_log2 = self.auth_tree_data_block_allocation_blocks_log2 as u32;
        let last_auth_tree_data_block_target_allocation_blocks_begin =
            self.states[cur_auth_tree_data_block_update_states_index.index].target_allocation_blocks_begin;
        cur_auth_tree_data_block_update_states_index = cur_auth_tree_data_block_update_states_index.step();
        while cur_auth_tree_data_block_update_states_index
            < states_allocation_blocks_index_range
                .end
                .auth_tree_data_blocks_update_states_index
        {
            let cur_auth_tree_data_block_target_allocation_blocks_begin =
                self.states[cur_auth_tree_data_block_update_states_index.index].target_allocation_blocks_begin;
            if u64::from(
                cur_auth_tree_data_block_target_allocation_blocks_begin
                    - last_auth_tree_data_block_target_allocation_blocks_begin,
            ) >> auth_tree_data_block_allocation_blocks_log2
                != 1
            {
                return AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::new(
                    &states_allocation_blocks_index_range.begin,
                    &AuthTreeDataBlocksUpdateStatesAllocationBlockIndex::from(
                        cur_auth_tree_data_block_update_states_index,
                    ),
                );
            }
            cur_auth_tree_data_block_update_states_index = cur_auth_tree_data_block_update_states_index.step();
        }
        debug_assert_eq!(
            cur_auth_tree_data_block_update_states_index,
            states_allocation_blocks_index_range
                .end
                .auth_tree_data_blocks_update_states_index
        );

        if states_allocation_blocks_index_range
            .end
            .allocation_block_index_in_auth_tree_data_block
            != 0
            && u64::from(
                self.states[cur_auth_tree_data_block_update_states_index.index].target_allocation_blocks_begin
                    - last_auth_tree_data_block_target_allocation_blocks_begin,
            ) >> auth_tree_data_block_allocation_blocks_log2
                == 1
        {
            states_allocation_blocks_index_range.clone()
        } else {
            AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::new(
                &states_allocation_blocks_index_range.begin,
                &AuthTreeDataBlocksUpdateStatesAllocationBlockIndex::from(cur_auth_tree_data_block_update_states_index),
            )
        }
    }

    /// Find the next discontinuity of tracked [storage
    /// location](AuthTreeDataBlockUpdateState::get_target_allocation_blocks_begin)
    /// ranges.
    ///
    /// Returns the [Authentication Tree Data Block level
    /// index](AuthTreeDataBlocksUpdateStatesIndex) of the next gap found or
    /// the past-the-end position if none.
    ///
    /// # Arguments:
    ///
    /// * `index` - search start position.
    pub fn find_gap_after(&self, index: AuthTreeDataBlocksUpdateStatesIndex) -> AuthTreeDataBlocksUpdateStatesIndex {
        debug_assert!(index.index < self.states.len());
        let auth_tree_data_block_allocation_blocks_log2 = self.auth_tree_data_block_allocation_blocks_log2 as u32;
        let mut last_target_allocations_blocks_begin = self.states[index.index].target_allocation_blocks_begin;
        let mut gap_index = index.index + 1;
        while gap_index < self.states.len() {
            let cur_target_allocation_blocks_begin = self.states[gap_index].target_allocation_blocks_begin;
            if u64::from(cur_target_allocation_blocks_begin - last_target_allocations_blocks_begin)
                >> auth_tree_data_block_allocation_blocks_log2
                != 1
            {
                break;
            }

            last_target_allocations_blocks_begin = cur_target_allocation_blocks_begin;
            gap_index += 1;
        }
        let gap_index = AuthTreeDataBlocksUpdateStatesIndex { index: gap_index };
        debug_assert!(self.is_contiguous_region(&AuthTreeDataBlocksUpdateStatesIndexRange::new(index, gap_index)));
        gap_index
    }

    /// Find the next discontinuity of tracked [storage
    /// location](AuthTreeDataBlockUpdateState::get_target_allocation_blocks_begin) ranges with
    /// minimum specified alignment and size.
    ///
    /// Returns the [Authentication Tree Data Block level
    /// index](AuthTreeDataBlocksUpdateStatesIndex) of the next aligned gap
    /// found or the past-the-end position if none. Gaps which don't cover
    /// at least one aligned block of size as specified by
    /// `target_allocation_blocks_alignment_log2` are getting skipped over in
    /// the search.
    ///
    /// This is commonly used for finding stop-gaps when preparing potentially
    /// sparsely populated ranges for subsequent processing in units of a
    /// certain block size, such as that of [Device IO
    /// blocks](crate::blkdev::NvBlkDev::io_block_size_128b_log2).
    ///
    /// # Arguments:
    ///
    /// * `index` - search start position.
    /// * `target_allocation_blocks_alignment_log2` - The desired gap block
    ///   alignment and size to search for.
    pub fn find_aligned_gap_after(
        &self,
        index: AuthTreeDataBlocksUpdateStatesIndex,
        target_allocation_blocks_alignment_log2: u32,
    ) -> AuthTreeDataBlocksUpdateStatesIndex {
        debug_assert!(index.index < self.states.len());
        let auth_tree_data_block_allocation_blocks_log2 = self.auth_tree_data_block_allocation_blocks_log2 as u32;
        if auth_tree_data_block_allocation_blocks_log2 >= target_allocation_blocks_alignment_log2 {
            return self.find_gap_after(index);
        }
        let mut last_aligned_target_allocation_blocks_begin = self.states[index.index]
            .target_allocation_blocks_begin
            .align_down(target_allocation_blocks_alignment_log2);
        let mut gap_index = index.index + 1;
        while gap_index != self.states.len() {
            let cur_aligned_target_allocation_blocks_begin = self.states[gap_index]
                .target_allocation_blocks_begin
                .align_down(target_allocation_blocks_alignment_log2);
            if u64::from(cur_aligned_target_allocation_blocks_begin - last_aligned_target_allocation_blocks_begin)
                >> target_allocation_blocks_alignment_log2
                > 1
            {
                break;
            }
            last_aligned_target_allocation_blocks_begin = cur_aligned_target_allocation_blocks_begin;
            gap_index += 1;
        }

        AuthTreeDataBlocksUpdateStatesIndex { index: gap_index }
    }

    /// Extend an [Authentication Tree Data Block level index
    /// range](AuthTreeDataBlocksUpdateStatesIndexRange) to include all present
    /// states within a specified alignment's reach.
    ///
    /// Extend the given `states_index_range` at both ends to include present
    /// neighbour states without crossing an [storage
    /// location](AuthTreeDataBlockUpdateState::get_target_allocation_blocks_begin) alignment
    /// boundary as specified by `target_allocation_blocks_alignment_log2`.
    ///
    /// # Arguments:
    ///
    /// * `states_index_range` - The index range to extend within the alignment
    ///   constraints.
    /// * `target_allocation_blocks_alignment_log2` - The alignment to extend
    ///   the range within.
    fn extend_states_index_range_within_alignment(
        &self,
        mut states_index_range: AuthTreeDataBlocksUpdateStatesIndexRange,
        target_allocation_blocks_alignment_log2: u32,
    ) -> AuthTreeDataBlocksUpdateStatesIndexRange {
        debug_assert!(states_index_range.end.index <= self.states.len());
        if states_index_range.is_empty()
            || self.auth_tree_data_block_allocation_blocks_log2 as u32 >= target_allocation_blocks_alignment_log2
        {
            return states_index_range;
        }

        let first_aligned_target_allocation_blocks_begin = self.states[states_index_range.begin.index]
            .target_allocation_blocks_begin
            .align_down(target_allocation_blocks_alignment_log2);
        while states_index_range.begin.index > 0 {
            if self.states[states_index_range.begin.index - 1]
                .target_allocation_blocks_begin
                .align_down(target_allocation_blocks_alignment_log2)
                < first_aligned_target_allocation_blocks_begin
            {
                break;
            }
            states_index_range.begin.index -= 1;
        }

        let last_first_aligned_target_allocation_blocks_begin = self.states[states_index_range.end.index - 1]
            .target_allocation_blocks_begin
            .align_down(target_allocation_blocks_alignment_log2);
        while states_index_range.end.index < self.states.len() {
            if self.states[states_index_range.end.index]
                .target_allocation_blocks_begin
                .align_down(target_allocation_blocks_alignment_log2)
                != last_first_aligned_target_allocation_blocks_begin
            {
                break;
            }
            states_index_range.end.index += 1;
        }

        states_index_range
    }

    /// Extend an [Allocation Block level
    /// range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange) to
    /// include all present states within a specified alignment's reach.
    ///
    /// Extend the given `states_index_range` at both ends to include present
    /// neighbour states without crossing an [storage
    /// location](AuthTreeDataBlockUpdateState::get_target_allocation_blocks_begin) alignment
    /// boundary as specified by `target_allocation_blocks_alignment_log2`.
    ///
    /// # Arguments:
    ///
    /// * `states_index_range` - The index range to extend within the alignment
    ///   constraints.
    /// * `target_allocation_blocks_alignment_log2` - The alignment to extend
    ///   the range within.
    pub fn extend_states_allocation_blocks_index_range_within_alignment(
        &self,
        states_allocation_blocks_index_range: &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        target_allocation_blocks_alignment_log2: u32,
    ) -> AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange {
        let auth_tree_data_block_allocation_blocks_log2 = self.auth_tree_data_block_allocation_blocks_log2 as u32;
        if target_allocation_blocks_alignment_log2 >= auth_tree_data_block_allocation_blocks_log2 {
            AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::from(
                self.extend_states_index_range_within_alignment(
                    AuthTreeDataBlocksUpdateStatesIndexRange::from(states_allocation_blocks_index_range.clone()),
                    target_allocation_blocks_alignment_log2,
                ),
            )
        } else {
            // All contiguous regions intersecting with the specified range are aligned to
            // the Authentication Tree Data Block size by design, which is larger
            // than the requested alignment. Simply extend the
            // states_allocation_blocks_index_range's bounds within
            // their containing respective Authentication Tree Data Blocks in order to make
            // them aligned.
            let mut aligned_states_allocation_blocks_index_range = states_allocation_blocks_index_range.clone();
            // Align the beginning downwards.
            aligned_states_allocation_blocks_index_range
                .begin
                .allocation_block_index_in_auth_tree_data_block = aligned_states_allocation_blocks_index_range
                .begin
                .allocation_block_index_in_auth_tree_data_block
                .round_down_pow2(target_allocation_blocks_alignment_log2);
            // Align the end upwards.
            debug_assert!(auth_tree_data_block_allocation_blocks_log2 < usize::BITS);
            debug_assert!(target_allocation_blocks_alignment_log2 < usize::BITS - 1);
            debug_assert!(
                aligned_states_allocation_blocks_index_range
                    .end
                    .allocation_block_index_in_auth_tree_data_block
                    < 1usize << auth_tree_data_block_allocation_blocks_log2
            );
            // Determine the distance to the next alignment boundary, c.f. Hacker's Delight,
            // 2nd edition, 3-1 ("Rounding Up/Down to a Multiple of a Known
            // Power of 2").
            let end_align_up_padding = aligned_states_allocation_blocks_index_range
                .end
                .allocation_block_index_in_auth_tree_data_block
                .wrapping_neg()
                & ((1usize << target_allocation_blocks_alignment_log2) - 1);
            aligned_states_allocation_blocks_index_range.end =
                aligned_states_allocation_blocks_index_range.end.advance(
                    layout::AllocBlockCount::from(end_align_up_padding as u64),
                    auth_tree_data_block_allocation_blocks_log2,
                );

            aligned_states_allocation_blocks_index_range
        }
    }

    /// Determine an [Allocation Block
    /// level](AuthTreeDataBlocksUpdateStatesAllocationBlockIndex) update
    /// tracking state's associated [location on
    /// storage](AuthTreeDataBlockUpdateState::get_target_allocation_blocks_begin).
    pub fn get_allocation_block_target(
        &self,
        states_allocation_block_index: &AuthTreeDataBlocksUpdateStatesAllocationBlockIndex,
    ) -> layout::PhysicalAllocBlockIndex {
        self[AuthTreeDataBlocksUpdateStatesIndex::from(*states_allocation_block_index)].target_allocation_blocks_begin
            + layout::AllocBlockCount::from(
                states_allocation_block_index.allocation_block_index_in_auth_tree_data_block as u64,
            )
    }

    /// Determine the maximal contiguous [storage
    /// location](AuthTreeDataBlockUpdateState::get_target_allocation_blocks_begin)
    /// range spanned by a given  [Allocation Block
    /// level index
    /// range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange).
    ///
    /// Any yet untracked gaps between the two ends are included.
    pub fn get_contiguous_region_target_range(
        &self,
        states_allocation_blocks_index_range: &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    ) -> layout::PhysicalAllocBlockRange {
        debug_assert!(
            self.is_contiguous_region(&AuthTreeDataBlocksUpdateStatesIndexRange::from(
                states_allocation_blocks_index_range.clone()
            ))
        );
        let target_allocation_blocks_begin =
            self.get_allocation_block_target(&states_allocation_blocks_index_range.begin);
        let target_allocation_blocks_end =
            if states_allocation_blocks_index_range.begin != states_allocation_blocks_index_range.end {
                let last_states_allocation_block_index = states_allocation_blocks_index_range
                    .end
                    .step_back(self.auth_tree_data_block_allocation_blocks_log2 as u32)
                    .unwrap();
                self.get_allocation_block_target(&last_states_allocation_block_index) + layout::AllocBlockCount::from(1)
            } else {
                target_allocation_blocks_begin
            };
        layout::PhysicalAllocBlockRange::new(target_allocation_blocks_begin, target_allocation_blocks_end)
    }

    /// Determine an [Allocation Block
    /// level](AuthTreeDataBlocksUpdateStatesAllocationBlockIndex) update
    /// tracking state's associated [Journal Staging
    /// Copy](AuthTreeDataBlockUpdateState::get_journal_staging_copy_allocation_blocks_begin)
    /// location on storage, if any.
    ///
    /// If the containing IO Block qualifies for in-place writes, the target
    /// Allocation Block address is being returned.
    pub fn get_allocation_block_journal_staging_copy(
        &self,
        states_allocation_block_index: &AuthTreeDataBlocksUpdateStatesAllocationBlockIndex,
    ) -> Option<layout::PhysicalAllocBlockIndex> {
        self[AuthTreeDataBlocksUpdateStatesIndex::from(*states_allocation_block_index)]
            .journal_staging_copy_allocation_blocks_begin
            .map(|auth_tree_data_block_journal_staging_copy_allocation_blocks_begin| {
                auth_tree_data_block_journal_staging_copy_allocation_blocks_begin
                    + layout::AllocBlockCount::from(
                        states_allocation_block_index.allocation_block_index_in_auth_tree_data_block as u64,
                    )
            })
    }

    /// Determine an [Allocation Block level update state index
    /// range's](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange)
    /// associated [Journal Staging
    /// Copy](AuthTreeDataBlockUpdateState::get_journal_staging_copy_allocation_blocks_begin)
    /// location area on storage, if any and contiguous.
    ///
    /// Note that the current implementation always assigns a contiguous Journal
    /// Staging Copy area to all Allocation Blocks contained within a common
    /// block of size the larger of an [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) and
    /// and an [IO Block](ImageLayout::io_block_allocation_blocks_log2). See
    /// also the reasoning
    /// [here](AuthTreeDataBlockUpdateState::get_journal_staging_copy_allocation_blocks_begin).
    pub fn get_contiguous_region_journal_staging_copy_range(
        &self,
        states_allocation_blocks_index_range: &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    ) -> Option<layout::PhysicalAllocBlockRange> {
        debug_assert!(
            self.is_contiguous_region(&AuthTreeDataBlocksUpdateStatesIndexRange::from(
                states_allocation_blocks_index_range.clone()
            ))
        );
        let journal_staging_copy_allocation_blocks_begin =
            self.get_allocation_block_journal_staging_copy(&states_allocation_blocks_index_range.begin)?;
        let journal_staging_copy_allocation_blocks_end =
            if states_allocation_blocks_index_range.begin != states_allocation_blocks_index_range.end {
                // A states range qualifying as a contiguous region implies only that
                // the associated _target_ region is contiguous. Verify that the same
                // holds for the associated Journal Data Staging Copy, if any.
                let mut last_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin = self
                    [AuthTreeDataBlocksUpdateStatesIndex::from(states_allocation_blocks_index_range.begin)]
                .journal_staging_copy_allocation_blocks_begin?;
                for i in AuthTreeDataBlocksUpdateStatesIndexRange::from(states_allocation_blocks_index_range.clone())
                    .iter()
                    .skip(1)
                {
                    let cur_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin =
                        self[i].journal_staging_copy_allocation_blocks_begin?;
                    if cur_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin
                        < last_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin
                        || cur_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin
                            - last_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin
                            != layout::AllocBlockCount::from(1u64 << self.auth_tree_data_block_allocation_blocks_log2)
                    {
                        return None;
                    }
                    last_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin =
                        cur_auth_tree_data_block_journal_staging_copy_allocation_blocks_begin;
                }

                // Ok, determine the Journal Data Staging Copy position past the range's last
                // Allocation Block.
                let last_states_allocation_block_index = states_allocation_blocks_index_range
                    .end
                    .step_back(self.auth_tree_data_block_allocation_blocks_log2 as u32)
                    .unwrap();
                self.get_allocation_block_journal_staging_copy(&last_states_allocation_block_index)
                    .unwrap()
                    + layout::AllocBlockCount::from(1)
            } else {
                journal_staging_copy_allocation_blocks_begin
            };

        Some(layout::PhysicalAllocBlockRange::new(
            journal_staging_copy_allocation_blocks_begin,
            journal_staging_copy_allocation_blocks_end,
        ))
    }

    /// Assign an allocated [Journal Staging
    /// Copy](AuthTreeDataBlockUpdateState::get_journal_staging_copy_allocation_blocks_begin)
    /// block to a given range of [Authentication Tree Data Block level
    /// update states](AuthTreeDataBlocksUpdateStatesIndexRange).
    ///
    /// The provided Journal Staging Copy block must be the size of and aligned
    /// to the larger of [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) and
    /// and an [IO Block](ImageLayout::io_block_allocation_blocks_log2). The
    /// same applies to the update states' [associated covered region on
    /// storage](Self::get_contiguous_region_target_range). Relative offsets
    /// will be preserved when assigning portions of the provided Journal
    /// Staging Copy block to individual Authentication Tree Data Block
    /// level update tracking states in the range.
    ///
    /// The specified `states_index_range` may have missing states, i.e. gaps.
    /// When populated later on, these will automatically inherit their portion
    /// within the Journal Staging Copy area from the neighbours.
    ///
    /// # Arguments:
    ///
    /// * `states_index_range` - The states to assign the Journal Staging Copy
    ///   block to.
    /// * `journal_staging_copy_allocation_blocks_begin` - Beginning of the
    ///   allocated Journal Staging Copy block to assign.
    pub fn assign_journal_staging_copy_block(
        &mut self,
        states_index_range_begin: AuthTreeDataBlocksUpdateStatesIndex,
        journal_staging_copy_block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
    ) -> Result<(), NvFsError> {
        let auth_tree_data_block_allocation_blocks_log2 = self.auth_tree_data_block_allocation_blocks_log2 as u32;
        let io_block_allocation_blocks_log2 = self.io_block_allocation_blocks_log2 as u32;

        debug_assert!(usize::from(states_index_range_begin) < self.states.len());
        let journal_staging_copy_block_allocation_blocks_log2 =
            auth_tree_data_block_allocation_blocks_log2.max(io_block_allocation_blocks_log2);
        debug_assert_eq!(
            journal_staging_copy_block_allocation_blocks_begin
                .align_down(journal_staging_copy_block_allocation_blocks_log2),
            journal_staging_copy_block_allocation_blocks_begin
        );

        let states_index_range = self.extend_states_index_range_within_alignment(
            AuthTreeDataBlocksUpdateStatesIndexRange {
                begin: states_index_range_begin,
                end: states_index_range_begin.step(),
            },
            journal_staging_copy_block_allocation_blocks_log2,
        );

        for i in states_index_range.iter() {
            if self[i].journal_staging_copy_allocation_blocks_begin.is_some() {
                return Err(nvfs_err_internal!());
            }
        }

        for i in states_index_range.iter() {
            let cur_journal_staging_copy_block_allocation_blocks_offset = layout::AllocBlockCount::from(
                u64::from(self[i].target_allocation_blocks_begin)
                    & u64::trailing_bits_mask(journal_staging_copy_block_allocation_blocks_log2),
            );
            self[i].journal_staging_copy_allocation_blocks_begin = Some(
                journal_staging_copy_block_allocation_blocks_begin
                    + cur_journal_staging_copy_block_allocation_blocks_offset,
            )
        }
        Ok(())
    }

    /// Allocate [data update
    /// staging](AllocationBlockUpdateStagedUpdate) buffers for a
    /// given [Allocation Block level index
    /// range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange).
    ///
    /// Move all the [`AllocationBlockUpdateState::staged_update`] in
    /// `states_allocation_blocks_range` to the
    /// [`AllocationBlockUpdateStagedUpdate::Update`] state
    /// with an allocated [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) sized
    /// data buffer each.
    ///
    /// Once the data update staging buffers have been allocated, they may get
    /// populated by encrypting directly into them by means of a
    /// [`MutPeekableIoSlicesMutIter`](io_slices::MutPeekableIoSlicesMutIter)
    /// instantiated via
    /// [`iter_allocation_blocks_update_staging_bufs_mut()`](Self::iter_allocation_blocks_update_staging_bufs_mut).
    ///
    /// # Arguments:
    ///
    /// * `states_allocation_blocks_range` - [Allocation Block level entry index
    ///   range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange) to
    ///   allocate data update staging buffers in.
    /// * `allocation_block_size_128b_log2` - Verbatim value of
    ///   [`ImageLayout::allocation_block_size_128b_log2`].
    ///
    /// # See also:
    ///
    /// * [`iter_allocation_blocks_update_staging_bufs_mut()`](Self::iter_allocation_blocks_update_staging_bufs_mut).
    pub fn allocate_allocation_blocks_update_staging_bufs(
        &mut self,
        states_allocation_blocks_range: &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        allocation_block_size_128b_log2: u32,
    ) -> Result<(), NvFsError> {
        for (_, allocation_block_update_state) in self.iter_allocation_blocks_mut(Some(states_allocation_blocks_range))
        {
            if let AllocationBlockUpdateStagedUpdate::Update { encrypted_data } =
                &allocation_block_update_state.staged_update
            {
                if !encrypted_data.is_empty() {
                    continue;
                }
            }
            let allocation_block_size = 1usize << (allocation_block_size_128b_log2 + 7);
            let encrypted_data = FixedVec::new_with_default(allocation_block_size)?;
            allocation_block_update_state.staged_update = AllocationBlockUpdateStagedUpdate::Update { encrypted_data }
        }
        Ok(())
    }

    /// Create a [`MutPeekableIoSlicesMutIter`](io_slices::MutPeekableIoSlicesMutIter) for the
    /// combined [data update
    /// staging](AllocationBlockUpdateStagedUpdate) buffers in a given
    /// [Allocation Block level index
    /// range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange).
    ///
    /// The data update staging buffers must have been allocated before via
    /// [`allocate_allocation_blocks_update_staging_bufs()`](Self::allocate_allocation_blocks_update_staging_bufs).
    ///
    /// * `states_allocation_blocks_range` - [Allocation Block level entry index
    ///   range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange) to
    ///   create a [`MutPeekableIoSlicesMutIter`](io_slices::MutPeekableIoSlicesMutIter)
    ///   for.
    pub fn iter_allocation_blocks_update_staging_bufs_mut(
        &mut self,
        states_allocation_blocks_range: &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    ) -> Result<AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIterMut<'_>, NvFsError> {
        let allocation_block_size_128b_log2 = self.allocation_block_size_128b_log2;
        AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIterMut::new(
            self.iter_allocation_blocks_mut(Some(states_allocation_blocks_range)),
            allocation_block_size_128b_log2,
        )
    }

    /// Reset the [staged updates](AllocationBlockUpdateStagedUpdate) in
    /// a given [Allocation Block level index
    /// range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange).
    ///
    /// The staged updates will all get reset to
    /// [`AllocationBlockUpdateStagedUpdate::None`].
    ///
    /// # Arguments:
    ///
    /// * `states_allocation_blocks_range` - [Allocation Block level entry index
    ///   range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange) to
    ///   reset any staged updates in.
    pub fn reset_allocation_blocks_staged_updates(
        &mut self,
        states_allocation_blocks_range: &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    ) {
        for (_, allocation_block_update_state) in self.iter_allocation_blocks_mut(Some(states_allocation_blocks_range))
        {
            allocation_block_update_state.staged_update = AllocationBlockUpdateStagedUpdate::None;
        }
    }

    /// Move the [staged updates](AllocationBlockUpdateStagedUpdate) in
    /// a given [Allocation Block level index
    /// range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange) to the
    /// [`FailedUpdate`]( AllocationBlockUpdateStagedUpdate::FailedUpdate)
    /// state.
    ///
    /// # Arguments:
    ///
    /// * `states_allocation_blocks_range` - [Allocation Block level entry index
    ///   range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange) to
    ///   reset any staged updates in.
    pub fn reset_allocation_blocks_staged_updates_to_failed(
        &mut self,
        states_allocation_blocks_range: &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    ) {
        for (_, allocation_block_update_state) in self.iter_allocation_blocks_mut(Some(states_allocation_blocks_range))
        {
            allocation_block_update_state.staged_update = AllocationBlockUpdateStagedUpdate::FailedUpdate;
        }
    }

    /// Reset some power-of-two sized block's [staged
    /// updates](AllocationBlockUpdateStagedUpdate).
    ///
    /// Reset all updates staged for the block starting at
    /// `target_block_allocation_blocks_begin` on storage with size as
    /// determined by `block_allocation_blocks_log2` to the
    /// [`AllocationBlockUpdateStagedUpdate::None`] state.
    ///
    /// # Arguments:
    ///
    /// * `target_block_allocation_blocks_begin` - Beginning of the block on
    ///   storage.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size in
    ///   units of [Allocation
    ///   Blocks](ImageLayout::allocation_block_size_128b_log2).
    pub fn reset_staged_block_updates(
        &mut self,
        target_block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        block_allocation_blocks_log2: u32,
    ) {
        self.reset_staged_extent_updates(&layout::PhysicalAllocBlockRange::from((
            target_block_allocation_blocks_begin,
            layout::AllocBlockCount::from(1u64 << block_allocation_blocks_log2),
        )));
    }

    /// Reset some power-of-two sized blocks' [staged
    /// updates](AllocationBlockUpdateStagedUpdate).
    ///
    /// Reset all updates staged for the blocks starting at the respective
    /// locations obtained from the `target_blocks_allocation_blocks_begin_iter`
    /// with sizes as determined by `block_allocation_blocks_log2` each to
    /// the [`AllocationBlockUpdateStagedUpdate::None`] state.
    ///
    /// # Arguments:
    ///
    /// * `target_blocks_allocation_blocks_begin_iter` - Iterator over the
    ///   respective blocks' beginning on storage.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size in
    ///   units of [Allocation
    ///   Blocks](ImageLayout::allocation_block_size_128b_log2).
    #[allow(dead_code)]
    pub fn reset_staged_blocks_updates<BI: Iterator<Item = layout::PhysicalAllocBlockIndex>>(
        &mut self,
        target_blocks_allocation_blocks_begin_iter: BI,
        block_allocation_blocks_log2: u32,
    ) {
        for target_block_allocation_blocks_begin in target_blocks_allocation_blocks_begin_iter {
            self.reset_staged_block_updates(target_block_allocation_blocks_begin, block_allocation_blocks_log2);
        }
    }

    /// Reset some storage extent's [staged
    /// updates](AllocationBlockUpdateStagedUpdate).
    ///
    /// Reset all updates staged for the `target_extent` to the
    /// [`AllocationBlockUpdateStagedUpdate::None`] state.
    ///
    /// # Arguments:
    ///
    /// * `target_extent` - The storage extent to reset any staged updates for.
    pub fn reset_staged_extent_updates(&mut self, target_extent: &layout::PhysicalAllocBlockRange) {
        let states_allocation_blocks_range =
            match self.lookup_allocation_blocks_update_states_index_range(target_extent) {
                Ok(states_allocation_blocks_range) => states_allocation_blocks_range,
                Err(_) => return,
            };
        self.reset_allocation_blocks_staged_updates(&states_allocation_blocks_range);
    }

    /// Reset some storage extents' [staged
    /// updates](AllocationBlockUpdateStagedUpdate).
    ///
    /// Reset all updates staged for the storage extents obtained from
    /// `target_extents_iter` to the
    /// [`AllocationBlockUpdateStagedUpdate::None`] state.
    ///
    /// # Arguments:
    ///
    /// * `target_extents_iter` - Iterator over the storage extents to reset any
    ///   staged updates for.
    pub fn reset_staged_extents_updates<EI: Iterator<Item = layout::PhysicalAllocBlockRange>>(
        &mut self,
        target_extents_iter: EI,
    ) {
        for target_extent in target_extents_iter {
            self.reset_staged_extent_updates(&target_extent);
        }
    }

    /// Reset some storage extent's [staged
    /// updates](AllocationBlockUpdateStagedUpdate) to the to the
    /// [`FailedUpdate`]( AllocationBlockUpdateStagedUpdate::FailedUpdate)
    /// state.
    ///
    /// # Arguments:
    ///
    /// * `target_extent` - The storage extent to reset any staged updates for.
    pub fn reset_staged_extent_updates_to_failed(&mut self, target_extent: &layout::PhysicalAllocBlockRange) {
        let states_allocation_blocks_range =
            match self.lookup_allocation_blocks_update_states_index_range(target_extent) {
                Ok(states_allocation_blocks_range) => states_allocation_blocks_range,
                Err(_) => return,
            };
        self.reset_allocation_blocks_staged_updates_to_failed(&states_allocation_blocks_range);
    }

    /// Reset some storage extents' [staged
    /// updates](AllocationBlockUpdateStagedUpdate) to the
    /// [`FailedUpdate`]( AllocationBlockUpdateStagedUpdate::FailedUpdate)
    /// state.
    ///
    /// Reset all staged updates for the storage extents obtained from
    /// `target_extents_iter` to the
    /// [`AllocationBlockUpdateStagedUpdate::FailedUpdate`] state.
    ///
    /// # Arguments:
    ///
    /// * `target_extents_iter` - Iterator over the storage extents to reset any
    ///   staged updates for.
    pub fn reset_staged_extents_updates_to_failed<EI: Iterator<Item = layout::PhysicalAllocBlockRange>>(
        &mut self,
        target_extents_iter: EI,
    ) {
        for target_extent in target_extents_iter {
            self.reset_staged_extent_updates_to_failed(&target_extent);
        }
    }

    /// Apply the [staged updates](AllocationBlockUpdateStagedUpdate) to
    /// the [storage tracking
    /// states](AllocationBlockUpdateNvSyncState).
    ///
    /// If `states_allocation_blocks_range` is specified, only updates staged in
    /// that range are applied. Any applied staged updates are getting moved
    /// to the [`AllocationBlockUpdateStagedUpdate::None`] state afterwards.
    ///
    /// Any [`AuthTreeDataBlockUpdateState`] in the
    /// `states_allocation_blocks_range` with updates staged to it must have
    /// all of its retained [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2)s' data loaded and
    /// authenticated before the staged updates may get applied.
    /// [`TransactionPrepareStagedUpdatesApplicationFuture`] may be used for
    /// preparation.
    ///
    /// # Arguments:
    ///
    /// * `states_allocation_blocks_range` - Optional [Allocation Block level
    ///   entry index
    ///   range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange) to
    ///   restrict the staged updates application to.
    /// * `alloc_bitmap` - The filesystem's
    ///   [`AllocBitmap`](alloc_bitmap::AllocBitmap) in the state from before
    ///   the transaction.
    ///
    /// # See also:
    ///
    /// * [`TransactionPrepareStagedUpdatesApplicationFuture`].
    pub fn apply_allocation_blocks_staged_updates(
        &mut self,
        states_allocation_blocks_range: Option<&AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange>,
        alloc_bitmap: &alloc_bitmap::AllocBitmap,
    ) {
        if self.states.is_empty() {
            debug_assert!(
                states_allocation_blocks_range
                    .map(|states_allocation_blocks_range| states_allocation_blocks_range.is_empty())
                    .unwrap_or(true)
            );
            return;
        }
        let (mut cur_states_index, mut first_allocation_block_index_in_auth_tree_data_block, states_range_end) =
            match states_allocation_blocks_range.as_ref() {
                Some(states_allocation_blocks_range) => {
                    if states_allocation_blocks_range.is_empty() {
                        return;
                    }
                    (
                        states_allocation_blocks_range
                            .begin
                            .auth_tree_data_blocks_update_states_index,
                        states_allocation_blocks_range
                            .begin
                            .allocation_block_index_in_auth_tree_data_block,
                        AuthTreeDataBlocksUpdateStatesIndexRange::from((*states_allocation_blocks_range).clone()).end,
                    )
                }
                None => (
                    AuthTreeDataBlocksUpdateStatesIndex::from(0),
                    0,
                    AuthTreeDataBlocksUpdateStatesIndex::from(self.states.len()),
                ),
            };

        let io_block_allocation_blocks_log2 = self.io_block_allocation_blocks_log2 as u32;
        let auth_tree_data_block_allocation_blocks_log2 = self.auth_tree_data_block_allocation_blocks_log2 as u32;
        let empty_sparse_alloc_bitmap = alloc_bitmap::SparseAllocBitmapUnion::new(&[]);
        let mut cur_io_block_target_allocation_blocks_begin = self
            .get_allocation_block_target(&AuthTreeDataBlocksUpdateStatesAllocationBlockIndex {
                auth_tree_data_blocks_update_states_index: cur_states_index,
                allocation_block_index_in_auth_tree_data_block: first_allocation_block_index_in_auth_tree_data_block,
            })
            .align_down(io_block_allocation_blocks_log2);
        let mut io_block_chunked_alloc_bitmap_iter = alloc_bitmap.iter_chunked_at_allocation_block(
            &empty_sparse_alloc_bitmap,
            &empty_sparse_alloc_bitmap,
            cur_io_block_target_allocation_blocks_begin,
            1u32 << io_block_allocation_blocks_log2,
        );
        let mut cur_io_block_alloc_bitmap = io_block_chunked_alloc_bitmap_iter.next().unwrap_or(0);

        while cur_states_index != states_range_end {
            let cur_auth_tree_data_block_state = &mut self[cur_states_index];
            let cur_auth_tree_data_block_target_allocation_blocks_begin =
                cur_auth_tree_data_block_state.get_target_allocation_blocks_begin();
            if first_allocation_block_index_in_auth_tree_data_block == 0
                && u64::from(
                    cur_auth_tree_data_block_target_allocation_blocks_begin
                        - cur_io_block_target_allocation_blocks_begin,
                ) >> io_block_allocation_blocks_log2
                    > 1
            {
                // There is a gap in the states and it crosses an IO block
                // boundary. Reset the io_block_chunked_alloc_bitmap_iter to the new position.
                cur_io_block_target_allocation_blocks_begin =
                    cur_auth_tree_data_block_target_allocation_blocks_begin.align_down(io_block_allocation_blocks_log2);
                io_block_chunked_alloc_bitmap_iter.goto(cur_io_block_target_allocation_blocks_begin);
                cur_io_block_alloc_bitmap = io_block_chunked_alloc_bitmap_iter.next().unwrap_or(0);
            }

            let allocation_blocks_in_auth_tree_data_block_end = states_allocation_blocks_range
                .as_ref()
                .and_then(|states_allocation_blocks_range| {
                    (states_allocation_blocks_range
                        .end
                        .auth_tree_data_blocks_update_states_index
                        == cur_states_index)
                        .then_some(
                            states_allocation_blocks_range
                                .end
                                .allocation_block_index_in_auth_tree_data_block,
                        )
                })
                .unwrap_or(1usize << auth_tree_data_block_allocation_blocks_log2);
            let mut any_allocation_block_state_updated = false;
            for cur_allocation_block_index_in_auth_tree_data_block in
                first_allocation_block_index_in_auth_tree_data_block..allocation_blocks_in_auth_tree_data_block_end
            {
                let cur_allocation_block_state = &mut cur_auth_tree_data_block_state.allocation_blocks_states
                    [cur_allocation_block_index_in_auth_tree_data_block];
                let cur_target_allocation_block = cur_auth_tree_data_block_target_allocation_blocks_begin
                    + layout::AllocBlockCount::from(cur_allocation_block_index_in_auth_tree_data_block as u64);
                if (u64::from(cur_target_allocation_block) ^ u64::from(cur_io_block_target_allocation_blocks_begin))
                    >> io_block_allocation_blocks_log2
                    != 0
                {
                    debug_assert_eq!(
                        cur_target_allocation_block - cur_io_block_target_allocation_blocks_begin,
                        layout::AllocBlockCount::from(1u64 << io_block_allocation_blocks_log2)
                    );
                    cur_io_block_alloc_bitmap = io_block_chunked_alloc_bitmap_iter.next().unwrap_or(0);
                    cur_io_block_target_allocation_blocks_begin = cur_target_allocation_block;
                }

                match &mut cur_allocation_block_state.staged_update {
                    AllocationBlockUpdateStagedUpdate::None => (),
                    AllocationBlockUpdateStagedUpdate::Update { encrypted_data } => {
                        any_allocation_block_state_updated = true;
                        cur_allocation_block_state.nv_sync_state = AllocationBlockUpdateNvSyncState::Allocated(
                            AllocationBlockUpdateNvSyncStateAllocated::Modified(
                                AllocationBlockUpdateNvSyncStateAllocatedModified::JournalDirty {
                                    authenticated_encrypted_data: mem::take(encrypted_data),
                                },
                            ),
                        );
                        cur_allocation_block_state.staged_update = AllocationBlockUpdateStagedUpdate::None;
                    }
                    AllocationBlockUpdateStagedUpdate::Deallocate => {
                        match &mut cur_allocation_block_state.nv_sync_state {
                            AllocationBlockUpdateNvSyncState::Unallocated(_) => (),
                            AllocationBlockUpdateNvSyncState::Allocated(allocated_state) => {
                                any_allocation_block_state_updated = true;
                                let unallocated_state = match allocated_state {
                                    AllocationBlockUpdateNvSyncStateAllocated::Unmodified(unmodified_state) => {
                                        // Repurpose the essentially random data previously at that location.
                                        let random_fillup = unmodified_state
                                            .cached_encrypted_data
                                            .take()
                                            .map(|cached_encrypted_data| cached_encrypted_data.encrypted_data);
                                        AllocationBlockUpdateNvSyncStateUnallocated {
                                            random_fillup,
                                            copied_to_journal: unmodified_state.copied_to_journal,
                                            target_state:
                                                AllocationBlockUpdateNvSyncStateUnallocatedTargetState::Allocated,
                                        }
                                    }
                                    AllocationBlockUpdateNvSyncStateAllocated::Modified(modified_state) => {
                                        let target_io_block_is_initialized = cur_io_block_alloc_bitmap != 0;
                                        let target_allocation_block_was_allocated = (cur_io_block_alloc_bitmap
                                            >> (u64::from(
                                                cur_target_allocation_block
                                                    - cur_io_block_target_allocation_blocks_begin,
                                            ) as u32))
                                            & 1
                                            != 0;
                                        let target_state = if target_allocation_block_was_allocated {
                                            // The Allocation Block had originally been allocated before the
                                            // transaction.
                                            AllocationBlockUpdateNvSyncStateUnallocatedTargetState::Allocated
                                        } else {
                                            // If any Allocation Block from the containing IO Block is initialized,
                                            // then all are.
                                            AllocationBlockUpdateNvSyncStateUnallocatedTargetState::Unallocated {
                                                is_initialized: target_io_block_is_initialized,
                                            }
                                        };
                                        // Repurpose essentially random data previously at that location, if any.
                                        let (random_fillup, copied_to_journal) = match modified_state {
                                            AllocationBlockUpdateNvSyncStateAllocatedModified::JournalClean {
                                                cached_encrypted_data,
                                            } => {
                                                let random_fillup = cached_encrypted_data
                                                    .take()
                                                    .map(|cached_encrypted_data| cached_encrypted_data.encrypted_data);
                                                (random_fillup, true)
                                            }
                                            AllocationBlockUpdateNvSyncStateAllocatedModified::JournalDirty {
                                                authenticated_encrypted_data,
                                            } => {
                                                // There might or might not have been something
                                                // copied to the journal before -- it's unknown at
                                                // this point. Note though that if a state is in
                                                // JournalDirty, then all other non-modified and
                                                // allocated states in the containing Authentication
                                                // Tree Data Block have their data loaded and
                                                // authenticated. Initialize random_fillup to
                                                // potentially save another read just for this
                                                // deallocated Allocation Block here. Also, don't
                                                // invoke the rng, encrypted data is considered
                                                // essentially random.
                                                let random_fillup = mem::take(authenticated_encrypted_data);
                                                (Some(random_fillup), false)
                                            }
                                        };
                                        AllocationBlockUpdateNvSyncStateUnallocated {
                                            random_fillup,
                                            copied_to_journal,
                                            target_state,
                                        }
                                    }
                                };
                                cur_allocation_block_state.nv_sync_state =
                                    AllocationBlockUpdateNvSyncState::Unallocated(unallocated_state)
                            }
                        }
                        cur_allocation_block_state.staged_update = AllocationBlockUpdateStagedUpdate::None;
                    }
                    AllocationBlockUpdateStagedUpdate::FailedUpdate => {
                        // A previous update staging attempt failed. Don't do
                        // anything and keep the
                        // error state.
                    }
                };
            }

            // The application of an update renders the auth_digest invalid. It is expected
            // that all retained Allocation Blocks' states from the containing
            // Authentication Tree Data Block have their data loaded and
            // authenticated.
            if any_allocation_block_state_updated {
                cur_auth_tree_data_block_state.auth_digest = None;
            }

            first_allocation_block_index_in_auth_tree_data_block = 0;
            cur_states_index = cur_states_index.step();
        }
    }

    /// Stage [`Deallocate`](AllocationBlockUpdateStagedUpdate::Deallocate)
    /// updates for some power-of-two sized block.
    ///
    /// Move all existing [`AllocationBlockUpdateStagedUpdate`] entries
    /// associated with the block starting at
    /// `deallocated_target_block_allocation_blocks_begin` on storage with size
    /// as determined by `block_allocation_blocks_log2` to the
    /// [`AllocationBlockUpdateStagedUpdate::Deallocate`] state.
    ///
    /// # Arguments:
    ///
    /// * `deallocated_target_block_allocation_blocks_begin` - Beginning of the
    ///   block on storage.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size in
    ///   units of [Allocation
    ///   Blocks](ImageLayout::allocation_block_size_128b_log2).
    pub fn stage_block_deallocation_updates(
        &mut self,
        deallocated_target_block_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
        block_allocation_blocks_log2: u32,
    ) {
        self.stage_extent_deallocation_updates(&layout::PhysicalAllocBlockRange::from((
            deallocated_target_block_allocation_blocks_begin,
            layout::AllocBlockCount::from(1u64 << block_allocation_blocks_log2),
        )));
    }

    /// Stage [`Deallocate`](AllocationBlockUpdateStagedUpdate::Deallocate)
    /// updates for some power-of-two sized blocks.
    ///
    /// Move all existing [`AllocationBlockUpdateStagedUpdate`] entries
    /// associated with the blocks starting at the respective locations
    /// obtained from the
    /// `deallocated_target_blocks_allocation_blocks_begin_iter` with
    /// sizes as determined by `block_allocation_blocks_log2` each to the
    /// [`AllocationBlockUpdateStagedUpdate::Deallocate`] state.
    ///
    /// # Arguments:
    ///
    /// * `deallocated_target_blocks_allocation_blocks_begin_iter` - Iterator
    ///   over the respective blocks' beginning on storage.
    /// * `block_allocation_blocks_log2` - Base-2 logarithm of the block size in
    ///   units of [Allocation
    ///   Blocks](ImageLayout::allocation_block_size_128b_log2).
    pub fn stage_blocks_deallocation_updates<BI: Iterator<Item = layout::PhysicalAllocBlockIndex>>(
        &mut self,
        deallocated_target_blocks_allocation_blocks_begin_iter: BI,
        block_allocation_blocks_log2: u32,
    ) {
        for deallocated_target_block_allocation_blocks_begin in deallocated_target_blocks_allocation_blocks_begin_iter {
            self.stage_block_deallocation_updates(
                deallocated_target_block_allocation_blocks_begin,
                block_allocation_blocks_log2,
            );
        }
    }

    /// Stage [`Deallocate`](AllocationBlockUpdateStagedUpdate::Deallocate)
    /// updates for some extent.
    ///
    /// Move all existing [`AllocationBlockUpdateStagedUpdate`] entries
    /// associated with `deallocated_target_extent` to the
    /// [`AllocationBlockUpdateStagedUpdate::Deallocate`] state.
    ///
    /// # Arguments:
    ///
    /// * `deallocated_target_extent` - The storage extent to stage
    ///   [`Deallocate`](AllocationBlockUpdateStagedUpdate::Deallocate) updates
    ///   for.
    pub fn stage_extent_deallocation_updates(&mut self, deallocated_target_extent: &layout::PhysicalAllocBlockRange) {
        let auth_tree_data_block_allocation_blocks_log2 = self.auth_tree_data_block_allocation_blocks_log2 as u32;
        let mut cur_states_allocation_block_index = match self.lookup_auth_tree_data_block_update_state_index(
            deallocated_target_extent
                .begin()
                .align_down(auth_tree_data_block_allocation_blocks_log2),
        ) {
            Ok(auth_tree_data_blocks_update_states_index) => AuthTreeDataBlocksUpdateStatesAllocationBlockIndex {
                auth_tree_data_blocks_update_states_index,
                allocation_block_index_in_auth_tree_data_block: u64::from(
                    deallocated_target_extent.begin()
                        - self[auth_tree_data_blocks_update_states_index].target_allocation_blocks_begin,
                ) as usize,
            },
            Err(auth_tree_data_blocks_update_states_index) => {
                AuthTreeDataBlocksUpdateStatesAllocationBlockIndex::from(auth_tree_data_blocks_update_states_index)
            }
        };
        while usize::from(AuthTreeDataBlocksUpdateStatesIndex::from(
            cur_states_allocation_block_index,
        )) != self.states.len()
            && self.get_allocation_block_target(&cur_states_allocation_block_index) < deallocated_target_extent.end()
        {
            let allocation_block_state = &mut self[cur_states_allocation_block_index];
            // In case the NV sync status is already in unallocated state, only reset any
            // currently staged update not yet applied to the NV sync state, if
            // any.
            allocation_block_state.staged_update = if !matches!(
                allocation_block_state.nv_sync_state,
                AllocationBlockUpdateNvSyncState::Unallocated(_)
            ) {
                AllocationBlockUpdateStagedUpdate::Deallocate
            } else {
                AllocationBlockUpdateStagedUpdate::None
            };
            cur_states_allocation_block_index =
                cur_states_allocation_block_index.step(auth_tree_data_block_allocation_blocks_log2);
        }
    }

    /// Stage [`Deallocate`](AllocationBlockUpdateStagedUpdate::Deallocate)
    /// updates for some extents.
    ///
    /// Move all existing [`AllocationBlockUpdateStagedUpdate`] entries
    /// associated with the storage extents obtained from
    /// `deallocated_target_extents_iter` to the
    /// [`AllocationBlockUpdateStagedUpdate::Deallocate`] state.
    ///
    /// # Arguments:
    ///
    /// # Arguments:
    ///
    /// * `deallocated_target_extents_iter` - Iterator over the storage extents
    ///   to stage [`Deallocate`](AllocationBlockUpdateStagedUpdate::Deallocate)
    ///   updates for.
    pub fn stage_extents_deallocation_updates<EI: Iterator<Item = layout::PhysicalAllocBlockRange>>(
        &mut self,
        deallocated_target_extents_iter: EI,
    ) {
        for deallocated_target_extent in deallocated_target_extents_iter {
            self.stage_extent_deallocation_updates(&deallocated_target_extent);
        }
    }

    /// Mark all [`AllocationBlockUpdateNvSyncState`]s in a given [Allocation
    /// Block level entry
    /// index range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange)
    /// as clean.
    ///
    /// Mark all [`AllocationBlockUpdateNvSyncState`] in
    /// `states_allocation_blocks_range` as having been written to
    /// the journal staging copy.
    ///
    /// # Arguments:
    ///
    /// * `states_allocation_blocks_range` - [Allocation Block level entry index
    ///   range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange) to
    ///   mark as clean.
    pub fn mark_states_clean(
        &mut self,
        states_allocation_blocks_range: &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    ) {
        for (_, allocation_block_update_state) in self.iter_allocation_blocks_mut(Some(states_allocation_blocks_range))
        {
            match &mut allocation_block_update_state.nv_sync_state {
                AllocationBlockUpdateNvSyncState::Unallocated(unallocated_state) => {
                    unallocated_state.copied_to_journal = true;
                }
                AllocationBlockUpdateNvSyncState::Allocated(allocated_state) => match allocated_state {
                    AllocationBlockUpdateNvSyncStateAllocated::Unmodified(unmodified_state) => {
                        unmodified_state.copied_to_journal = true;
                    }
                    AllocationBlockUpdateNvSyncStateAllocated::Modified(modified_state) => match modified_state {
                        AllocationBlockUpdateNvSyncStateAllocatedModified::JournalClean {
                            cached_encrypted_data: _,
                        } => (),
                        AllocationBlockUpdateNvSyncStateAllocatedModified::JournalDirty {
                            authenticated_encrypted_data,
                        } => {
                            let authenticated_encrypted_data = mem::take(authenticated_encrypted_data);
                            let cached_encrypted_data = Some(CachedEncryptedAllocationBlockData {
                                encrypted_data: authenticated_encrypted_data,
                                authenticated: true,
                            });
                            allocation_block_update_state.nv_sync_state = AllocationBlockUpdateNvSyncState::Allocated(
                                AllocationBlockUpdateNvSyncStateAllocated::Modified(
                                    AllocationBlockUpdateNvSyncStateAllocatedModified::JournalClean {
                                        cached_encrypted_data,
                                    },
                                ),
                            );
                        }
                    },
                },
            }
        }
    }

    /// Compute authentication digests for some
    /// [`AuthTreeDataBlockUpdateState`]s.
    ///
    /// Update the [`AuthTreeDataBlockUpdateState::auth_digest`] for all entries
    /// if `states_index_range` is `None`, or only for those in the
    /// specified range.
    ///
    /// All [`AllocationBlockUpdateState`]s for any
    /// [`AuthTreeDataBlockUpdateState`] whose authentication digest is to
    /// get computed must have [Allocation
    /// Block](ImageLayout::allocation_block_size_128b_log2) [loaded and
    /// authenticated](AllocationBlockUpdateState::has_encrypted_data_loaded).
    ///
    /// # Arguments:
    ///
    /// * `states_index_range` - Optional entry range to restrict the operation
    ///   to.
    /// * `auth_tree_config` - The fileystem's
    ///   [`AuthTreeConfig`](auth_tree::AuthTreeConfig).
    /// * `image_header_end` - [End of the filesystem image header on
    ///   storage](crate::fs::cocoonfs::image_header::MutableImageHeader::physical_location).
    pub fn update_auth_digests(
        &mut self,
        states_index_range: Option<&AuthTreeDataBlocksUpdateStatesIndexRange>,
        auth_tree_config: &auth_tree::AuthTreeConfig,
        image_header_end: layout::PhysicalAllocBlockIndex,
    ) -> Result<(), NvFsError> {
        let (mut cur_states_index, states_index_range_end) = match states_index_range {
            Some(states_index_range) => (states_index_range.begin(), states_index_range.end()),
            None => (
                AuthTreeDataBlocksUpdateStatesIndex::from(0),
                AuthTreeDataBlocksUpdateStatesIndex::from(self.states.len()),
            ),
        };

        // Note that this is guaranteed to fit an usize, so the cast below would not
        // overflow.
        let auth_tree_data_block_allocation_blocks = 1u64 << (self.auth_tree_data_block_allocation_blocks_log2 as u32);

        while cur_states_index != states_index_range_end {
            let cur_update_state = &mut self[cur_states_index];
            if cur_update_state.auth_digest.is_some() {
                cur_states_index = cur_states_index.step();
                continue;
            }

            let cur_auth_tree_data_block_allocation_blocks_begin =
                cur_update_state.get_target_allocation_blocks_begin();
            // If there are no data modifications in the current Authentication Tree Data
            // Block, then don't recompute the digest.
            if !cur_update_state
                .iter_allocation_blocks()
                .skip(
                    u64::from(image_header_end)
                        .saturating_sub(u64::from(cur_auth_tree_data_block_allocation_blocks_begin))
                        .min(auth_tree_data_block_allocation_blocks) as usize,
                )
                .any(|allocation_block_update_state| allocation_block_update_state.has_modified_data())
            {
                cur_states_index = cur_states_index.step();
                continue;
            }

            let cur_auth_tree_data_block_index = auth_tree_config
                .translate_physical_to_data_block_index(cur_auth_tree_data_block_allocation_blocks_begin);
            cur_update_state.auth_digest = Some(auth_tree_config.digest_data_block(
                cur_auth_tree_data_block_index,
                cur_update_state.iter_auth_digest_allocation_blocks(image_header_end, true),
                image_header_end,
            )?);

            cur_states_index = cur_states_index.step();
        }

        Ok(())
    }
}

impl ops::Index<AuthTreeDataBlocksUpdateStatesIndex> for AuthTreeDataBlocksUpdateStates {
    type Output = AuthTreeDataBlockUpdateState;

    fn index(&self, index: AuthTreeDataBlocksUpdateStatesIndex) -> &Self::Output {
        debug_assert!(index.index < self.states.len());
        &self.states[index.index]
    }
}

impl ops::IndexMut<AuthTreeDataBlocksUpdateStatesIndex> for AuthTreeDataBlocksUpdateStates {
    fn index_mut(&mut self, index: AuthTreeDataBlocksUpdateStatesIndex) -> &mut Self::Output {
        debug_assert!(index.index < self.states.len());
        &mut self.states[index.index]
    }
}

impl ops::Index<AuthTreeDataBlocksUpdateStatesAllocationBlockIndex> for AuthTreeDataBlocksUpdateStates {
    type Output = AllocationBlockUpdateState;

    fn index(&self, index: AuthTreeDataBlocksUpdateStatesAllocationBlockIndex) -> &Self::Output {
        debug_assert!(
            index.allocation_block_index_in_auth_tree_data_block
                < 1usize << self.auth_tree_data_block_allocation_blocks_log2
        );
        &self[index.auth_tree_data_blocks_update_states_index].allocation_blocks_states
            [index.allocation_block_index_in_auth_tree_data_block]
    }
}

impl ops::IndexMut<AuthTreeDataBlocksUpdateStatesAllocationBlockIndex> for AuthTreeDataBlocksUpdateStates {
    fn index_mut(&mut self, index: AuthTreeDataBlocksUpdateStatesAllocationBlockIndex) -> &mut Self::Output {
        debug_assert!(
            index.allocation_block_index_in_auth_tree_data_block
                < 1usize << self.auth_tree_data_block_allocation_blocks_log2
        );
        &mut self[index.auth_tree_data_blocks_update_states_index].allocation_blocks_states
            [index.allocation_block_index_in_auth_tree_data_block]
    }
}

/// Index into [`AuthTreeDataBlocksUpdateStates`] referring to a single
/// [Authentication Tree Data
/// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) level
/// entry.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct AuthTreeDataBlocksUpdateStatesIndex {
    index: usize,
}

impl AuthTreeDataBlocksUpdateStatesIndex {
    /// Increment the index.
    pub fn step(&self) -> Self {
        Self { index: self.index + 1 }
    }

    /// Decrement the index.
    ///
    /// Return `None` if already at the beginning.
    pub fn step_back(&self) -> Option<Self> {
        self.index.checked_sub(1).map(|index| Self { index })
    }
}

impl convert::From<usize> for AuthTreeDataBlocksUpdateStatesIndex {
    fn from(value: usize) -> Self {
        Self { index: value }
    }
}

impl convert::From<AuthTreeDataBlocksUpdateStatesIndex> for usize {
    fn from(value: AuthTreeDataBlocksUpdateStatesIndex) -> Self {
        value.index
    }
}

impl convert::From<AuthTreeDataBlocksUpdateStatesAllocationBlockIndex> for AuthTreeDataBlocksUpdateStatesIndex {
    fn from(value: AuthTreeDataBlocksUpdateStatesAllocationBlockIndex) -> Self {
        value.auth_tree_data_blocks_update_states_index
    }
}

/// [Index](AuthTreeDataBlocksUpdateStatesIndex) range of [Authentication Tree
/// Data Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) level
/// entries managed in an [`AuthTreeDataBlocksUpdateStates`] instance.
///
/// Note that the Authentication Tree Data Blocks described by such an index
/// range are ordered by their [location on
/// storage](AuthTreeDataBlockUpdateState::get_target_allocation_blocks_begin),
/// but not necessarily contiguous because there might be some entries missing
/// in the associated [`AuthTreeDataBlocksUpdateStates`] instance.
#[derive(Clone)]
pub struct AuthTreeDataBlocksUpdateStatesIndexRange {
    begin: AuthTreeDataBlocksUpdateStatesIndex,
    end: AuthTreeDataBlocksUpdateStatesIndex,
}

impl AuthTreeDataBlocksUpdateStatesIndexRange {
    /// Instantiate a new [`AuthTreeDataBlocksUpdateStatesIndexRange`].
    ///
    /// # Arguments:
    ///
    /// * `begin` - Beginning of the range.
    /// * `end` - End of the range.
    pub fn new(begin: AuthTreeDataBlocksUpdateStatesIndex, end: AuthTreeDataBlocksUpdateStatesIndex) -> Self {
        debug_assert!(begin <= end);
        Self { begin, end }
    }

    /// Number of [`AuthTreeDataBlockUpdateState`] entries in the range.
    pub fn len(&self) -> usize {
        self.end.index - self.begin.index
    }

    /// Whether or not the range is entry.
    pub fn is_empty(&self) -> bool {
        self.end.index == self.begin.index
    }

    /// Get the range's beginning.
    pub fn begin(&self) -> AuthTreeDataBlocksUpdateStatesIndex {
        self.begin
    }

    /// Get the range's end.
    pub fn end(&self) -> AuthTreeDataBlocksUpdateStatesIndex {
        self.end
    }

    /// Iterate over the indices in the range.
    pub fn iter(&self) -> AuthTreeDataBlocksUpdateStatesIndexRangeIter {
        AuthTreeDataBlocksUpdateStatesIndexRangeIter {
            next_index: self.begin,
            end: self.end,
        }
    }

    /// Apply correction offsets to account for [`AuthTreeDataBlockUpdateState`]
    /// entry insertions.
    ///
    /// # Arguments:
    ///
    /// * `states_inserted_before_count` - Number of new entries inserted before
    ///   the range.
    /// * `states_inserted_within_count` - Number of new entries inserted within
    ///   the range.
    pub fn apply_states_insertions_offsets(
        &self,
        states_inserted_before_count: usize,
        states_inserted_within_count: usize,
    ) -> Self {
        Self {
            begin: AuthTreeDataBlocksUpdateStatesIndex {
                index: self.begin.index + states_inserted_before_count,
            },
            end: AuthTreeDataBlocksUpdateStatesIndex {
                index: self.end.index + states_inserted_before_count + states_inserted_within_count,
            },
        }
    }
}

impl convert::From<AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange>
    for AuthTreeDataBlocksUpdateStatesIndexRange
{
    fn from(value: AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange) -> Self {
        let end = if value.end.allocation_block_index_in_auth_tree_data_block == 0 {
            value.end.auth_tree_data_blocks_update_states_index
        } else {
            AuthTreeDataBlocksUpdateStatesIndex::from(
                usize::from(value.end.auth_tree_data_blocks_update_states_index) + 1,
            )
        };

        Self {
            begin: value.begin.auth_tree_data_blocks_update_states_index,
            end,
        }
    }
}

/// Iterator over the individual [Authentication Tree Data Block level
/// indices](AuthTreeDataBlocksUpdateStatesIndex) in an
/// [`AuthTreeDataBlocksUpdateStatesIndexRange`].
///
/// # See also:
///
/// * [`AuthTreeDataBlocksUpdateStatesIndexRange::iter()`].
pub struct AuthTreeDataBlocksUpdateStatesIndexRangeIter {
    next_index: AuthTreeDataBlocksUpdateStatesIndex,
    end: AuthTreeDataBlocksUpdateStatesIndex,
}

impl Iterator for AuthTreeDataBlocksUpdateStatesIndexRangeIter {
    type Item = AuthTreeDataBlocksUpdateStatesIndex;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_index == self.end {
            None
        } else {
            let cur_index = self.next_index;
            self.next_index.index += 1;
            Some(cur_index)
        }
    }
}

/// Index into [`AuthTreeDataBlocksUpdateStates`] referring to a single
/// [Allocation Block](ImageLayout::allocation_block_size_128b_log2) level
/// entry.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct AuthTreeDataBlocksUpdateStatesAllocationBlockIndex {
    auth_tree_data_blocks_update_states_index: AuthTreeDataBlocksUpdateStatesIndex,
    allocation_block_index_in_auth_tree_data_block: usize,
}

impl AuthTreeDataBlocksUpdateStatesAllocationBlockIndex {
    /// Instantiate a [`AuthTreeDataBlocksUpdateStatesAllocationBlockIndex`].
    ///
    /// # Arguments:
    ///
    /// * `auth_tree_data_blocks_update_states_index` - Index identifying the
    ///   containing [Authentication Tree Data
    ///   Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2)'s
    ///   associated [`AuthTreeDataBlockUpdateState`] entry.
    /// * `allocation_block_index_in_auth_tree_data_block` - Index of the
    ///   [Allocation Block](ImageLayout::allocation_block_size_128b_log2)
    ///   within the containing [Authentication Tree Data
    ///   Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2). Must
    ///   not point past the [Authentication Tree Data
    ///   Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2).
    pub fn new(
        auth_tree_data_blocks_update_states_index: AuthTreeDataBlocksUpdateStatesIndex,
        allocation_block_index_in_auth_tree_data_block: usize,
    ) -> Self {
        Self {
            auth_tree_data_blocks_update_states_index,
            allocation_block_index_in_auth_tree_data_block,
        }
    }

    /// Increment the index.
    ///
    /// # Arguments:
    ///
    /// * `auth_tree_data_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::auth_tree_data_block_allocation_blocks_log2`].
    pub fn step(&self, auth_tree_data_block_allocation_blocks_log2: u32) -> Self {
        self.advance(
            layout::AllocBlockCount::from(1),
            auth_tree_data_block_allocation_blocks_log2,
        )
    }

    /// Decrement the index.
    ///
    /// # Arguments:
    ///
    /// * `auth_tree_data_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::auth_tree_data_block_allocation_blocks_log2`].
    pub fn step_back(&self, auth_tree_data_block_allocation_blocks_log2: u32) -> Option<Self> {
        if self.allocation_block_index_in_auth_tree_data_block == 0 {
            if usize::from(self.auth_tree_data_blocks_update_states_index) == 0 {
                None
            } else {
                Some(Self {
                    auth_tree_data_blocks_update_states_index: AuthTreeDataBlocksUpdateStatesIndex::from(
                        usize::from(self.auth_tree_data_blocks_update_states_index) - 1,
                    ),
                    allocation_block_index_in_auth_tree_data_block: usize::trailing_bits_mask(
                        auth_tree_data_block_allocation_blocks_log2,
                    ),
                })
            }
        } else {
            Some(Self {
                auth_tree_data_blocks_update_states_index: self.auth_tree_data_blocks_update_states_index,
                allocation_block_index_in_auth_tree_data_block: self.allocation_block_index_in_auth_tree_data_block - 1,
            })
        }
    }

    /// Advance the index by a specified distance.
    ///
    /// # Arguments:
    ///
    /// * `distance` - Number of [Allocation
    ///   Block](ImageLayout::allocation_block_size_128b_log2) entries to
    ///   advance the index by.
    /// * `auth_tree_data_block_allocation_blocks_log2` - Verbatim value of
    ///   [`ImageLayout::auth_tree_data_block_allocation_blocks_log2`].
    pub fn advance(&self, distance: layout::AllocBlockCount, auth_tree_data_block_allocation_blocks_log2: u32) -> Self {
        // Cannot overflow: the total number of Allocation Blocks always fits an u64.
        let mut allocation_block_index_in_auth_tree_data_block =
            self.allocation_block_index_in_auth_tree_data_block as u64 + u64::from(distance);
        let distance_auth_tree_data_blocks =
            allocation_block_index_in_auth_tree_data_block >> auth_tree_data_block_allocation_blocks_log2;
        allocation_block_index_in_auth_tree_data_block ^=
            distance_auth_tree_data_blocks << auth_tree_data_block_allocation_blocks_log2;
        // The usize arithmetic cannot overflow: all indices refer to offsets into
        // AuthTreeDataBlocksUpdateStates::states[].
        let auth_tree_data_blocks_update_states_index = AuthTreeDataBlocksUpdateStatesIndex::from(
            usize::from(self.auth_tree_data_blocks_update_states_index) + distance_auth_tree_data_blocks as usize,
        );
        Self {
            auth_tree_data_blocks_update_states_index,
            allocation_block_index_in_auth_tree_data_block: allocation_block_index_in_auth_tree_data_block as usize,
        }
    }
}

impl convert::From<AuthTreeDataBlocksUpdateStatesIndex> for AuthTreeDataBlocksUpdateStatesAllocationBlockIndex {
    fn from(value: AuthTreeDataBlocksUpdateStatesIndex) -> Self {
        Self {
            auth_tree_data_blocks_update_states_index: value,
            allocation_block_index_in_auth_tree_data_block: 0,
        }
    }
}

/// [Index](AuthTreeDataBlocksUpdateStatesAllocationBlockIndex) range of
/// [Allocation Block](ImageLayout::allocation_block_size_128b_log2) level
/// entries managed in an [`AuthTreeDataBlocksUpdateStates`] instance.
///
/// Note that the Allocation Blocks described by such an index range are ordered
/// by their [location
/// on storage](AuthTreeDataBlockUpdateState::get_target_allocation_blocks_begin), but not
/// necessarily contiguous because there might be some [Authentication Tree Data
/// Blocks](ImageLayout::auth_tree_data_block_allocation_blocks_log2) sized
/// entries missing in the associated [`AuthTreeDataBlocksUpdateStates`]
/// instance.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange {
    begin: AuthTreeDataBlocksUpdateStatesAllocationBlockIndex,
    end: AuthTreeDataBlocksUpdateStatesAllocationBlockIndex,
}

impl AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange {
    /// Instantiate a new
    /// [`AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange`].
    ///
    /// # Arguments:
    ///
    /// * `begin` - Beginning of the range.
    /// * `end` - End of the range.
    pub fn new(
        begin: &AuthTreeDataBlocksUpdateStatesAllocationBlockIndex,
        end: &AuthTreeDataBlocksUpdateStatesAllocationBlockIndex,
    ) -> Self {
        debug_assert!(begin <= end);
        Self {
            begin: *begin,
            end: *end,
        }
    }

    /// Whether or not the range is entry.
    pub fn is_empty(&self) -> bool {
        self.begin == self.end
    }

    /// Get the range's beginning.
    pub fn begin(&self) -> &AuthTreeDataBlocksUpdateStatesAllocationBlockIndex {
        &self.begin
    }

    /// Get the range's end.
    pub fn end(&self) -> &AuthTreeDataBlocksUpdateStatesAllocationBlockIndex {
        &self.end
    }

    /// Iterate over the indices in the range.
    pub fn iter(
        &self,
        auth_tree_data_block_allocation_blocks_log2: u32,
    ) -> AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRangeIter {
        AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRangeIter {
            next_index: self.begin,
            end: self.end,
            auth_tree_data_block_allocation_blocks_log2,
        }
    }

    /// Apply correction offsets to account for [`AuthTreeDataBlockUpdateState`]
    /// entry insertions.
    ///
    /// # Arguments:
    ///
    /// * `states_inserted_before_count` - Number of new
    ///   [`AuthTreeDataBlockUpdateState`] entries inserted before the range.
    /// * `states_inserted_within_count` - Number of new
    ///   [`AuthTreeDataBlockUpdateState`] entries inserted within the range.
    pub fn apply_states_insertions_offsets(
        &self,
        states_inserted_before_count: usize,
        states_inserted_within_count: usize,
    ) -> Self {
        Self {
            begin: AuthTreeDataBlocksUpdateStatesAllocationBlockIndex {
                auth_tree_data_blocks_update_states_index: AuthTreeDataBlocksUpdateStatesIndex {
                    index: self.begin.auth_tree_data_blocks_update_states_index.index + states_inserted_before_count,
                },
                allocation_block_index_in_auth_tree_data_block: self
                    .begin
                    .allocation_block_index_in_auth_tree_data_block,
            },

            end: AuthTreeDataBlocksUpdateStatesAllocationBlockIndex {
                auth_tree_data_blocks_update_states_index: AuthTreeDataBlocksUpdateStatesIndex {
                    index: self.end.auth_tree_data_blocks_update_states_index.index
                        + states_inserted_before_count
                        + states_inserted_within_count,
                },
                allocation_block_index_in_auth_tree_data_block: self.end.allocation_block_index_in_auth_tree_data_block,
            },
        }
    }
}

impl convert::From<AuthTreeDataBlocksUpdateStatesIndexRange>
    for AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange
{
    fn from(value: AuthTreeDataBlocksUpdateStatesIndexRange) -> Self {
        Self {
            begin: AuthTreeDataBlocksUpdateStatesAllocationBlockIndex {
                auth_tree_data_blocks_update_states_index: value.begin,
                allocation_block_index_in_auth_tree_data_block: 0,
            },
            end: AuthTreeDataBlocksUpdateStatesAllocationBlockIndex {
                auth_tree_data_blocks_update_states_index: value.end,
                allocation_block_index_in_auth_tree_data_block: 0,
            },
        }
    }
}

/// Iterator over the individual [Allocation Block level
/// indices](AuthTreeDataBlocksUpdateStatesAllocationBlockIndex) in an
/// [`AuthTreeDataBlocksUpdateStatesIndexRange`].
///
/// # See also:
///
/// * [`AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::iter()`].
pub struct AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRangeIter {
    next_index: AuthTreeDataBlocksUpdateStatesAllocationBlockIndex,
    end: AuthTreeDataBlocksUpdateStatesAllocationBlockIndex,
    auth_tree_data_block_allocation_blocks_log2: u32,
}

impl Iterator for AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRangeIter {
    type Item = AuthTreeDataBlocksUpdateStatesAllocationBlockIndex;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_index == self.end {
            None
        } else {
            let cur_index = self.next_index;
            self.next_index = cur_index.step(self.auth_tree_data_block_allocation_blocks_log2);
            Some(cur_index)
        }
    }
}

/// Offsets to apply to an [`AuthTreeDataBlocksUpdateStatesIndexRange`] to
/// account for insertion of additional [`AuthTreeDataBlockUpdateState`] entries
/// from
/// [`fill_states_index_range_regions_alignment_gaps()`](AuthTreeDataBlocksUpdateStates::fill_states_index_range_regions_alignment_gaps).
///
/// Without further action, states insertions invalidate any pre-existing index
/// ranges, the offsets provide a means to account for such insertions and keep
/// index ranges alive across such insertion operations.
///
/// The offsets instance is always specific to a single specific index range
/// only, but may be transformed to others by means of
/// [`AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsetsTransformToAfter`]
/// or
/// [`AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsetsTransformToContaining`].
pub struct AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets {
    /// Number of [`AuthTreeDataBlockUpdateState`] entries that had been
    /// inserted before the associated
    /// [`AuthTreeDataBlocksUpdateStatesIndexRange`].
    pub inserted_states_before_range_count: usize,
    /// Number of [`AuthTreeDataBlockUpdateState`] entries that had been
    /// inserted in the interior of the associated
    /// [`AuthTreeDataBlocksUpdateStatesIndexRange`].
    pub inserted_states_within_range_count: usize,
    /// Number of [`AuthTreeDataBlockUpdateState`] entries that had been
    /// inserted after the associated
    /// [`AuthTreeDataBlocksUpdateStatesIndexRange`]. Needed for transforming
    /// the offsets from one range to another.
    pub inserted_states_after_range_count: usize,
    /// Maximum alignment fillup ever applied to the associated
    /// [`AuthTreeDataBlocksUpdateStatesIndexRange`] in the course of some
    /// operation. Needed for transforming the offsets from one range to
    /// another.
    pub max_target_allocations_blocks_alignment_log2: u32,
}

impl AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets {
    /// Get the total number of inserted [`AuthTreeDataBlockUpdateState`]
    /// entries.
    pub fn total_inserted_states_count(&self) -> usize {
        self.inserted_states_before_range_count
            + self.inserted_states_within_range_count
            + self.inserted_states_after_range_count
    }

    /// Merge two [`AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets`] instances by accumulation.
    pub fn accumulate(&self, other: &Self) -> Self {
        Self {
            inserted_states_before_range_count: self.inserted_states_before_range_count
                + other.inserted_states_before_range_count,
            inserted_states_within_range_count: self.inserted_states_within_range_count
                + other.inserted_states_within_range_count,
            inserted_states_after_range_count: self.inserted_states_after_range_count
                + other.inserted_states_after_range_count,
            max_target_allocations_blocks_alignment_log2: self
                .max_target_allocations_blocks_alignment_log2
                .max(other.max_target_allocations_blocks_alignment_log2),
        }
    }
}

/// Transform [states insertion
/// offsets](AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets)
/// specific to one [Authentication Tree Data Block level
/// index range](AuthTreeDataBlocksUpdateStatesIndexRange) to another located
/// after it.
pub struct AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsetsTransformToAfter {
    from_range_end_to_range_begin_target_allocation_blocks_xor: u64,
    from_range_end_to_to_range_begin_missing_states_count: u64,
    from_range_end_to_range_end_target_allocation_blocks_xor: u64,
    from_range_end_to_to_range_end_missing_states_count: u64,
}

impl AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsetsTransformToAfter {
    /// Setup a index range offsets transform instance.
    ///
    /// Must get invoked before the actual states insertion operation with the
    /// original index ranges.
    ///
    /// # Arguments:
    ///
    /// * `from_states_index_range` - The index range associated with the
    ///   offsets to get later transformed to apply to `to_states_index_range`.
    /// * `to_states_index_range` - The index range to later obtain insertion
    ///   offsets for.
    /// * `states` - The [`AuthTreeDataBlocksUpdateStates`] instance both
    ///   `from_states_index_range` and `to_states_index_range` refer into.
    pub fn new(
        from_states_index_range: &AuthTreeDataBlocksUpdateStatesIndexRange,
        to_states_index_range: &AuthTreeDataBlocksUpdateStatesIndexRange,
        states: &AuthTreeDataBlocksUpdateStates,
    ) -> Self {
        // If the range to transform from is empty, it has no well-defined position
        // within the physical target range, which could serve as an anchor
        // point. The same is true for the range to transform to, but as it's
        // located after the range to get transformed from, it is simply assumed
        // that what is significant is what is located before its end.
        debug_assert!(!from_states_index_range.is_empty());
        debug_assert!(from_states_index_range.end() <= to_states_index_range.begin());

        let auth_tree_data_block_allocation_blocks_log2 = states.auth_tree_data_block_allocation_blocks_log2 as u32;

        if from_states_index_range.end() == to_states_index_range.end() {
            return Self {
                from_range_end_to_range_begin_target_allocation_blocks_xor: 0,
                from_range_end_to_to_range_begin_missing_states_count: 0,
                from_range_end_to_range_end_target_allocation_blocks_xor: 0,
                from_range_end_to_to_range_end_missing_states_count: 0,
            };
        }

        let from_range_last_auth_tree_data_block_target_allocation_blocks_begin =
            states[from_states_index_range.end().step_back().unwrap()].get_target_allocation_blocks_begin();
        // If to_states_range.is_empty(), this is not really the last one,
        // but the last one before the range. Oherwise it is the last one in range.
        let to_range_last_auth_tree_data_block_target_allocation_blocks_begin =
            states[to_states_index_range.end().step_back().unwrap()].get_target_allocation_blocks_begin();

        // The number of missing states is the difference of the number of
        // Authentication Tree Data Blocks spanned and what's already there.
        let from_range_end_to_to_range_end_missing_states_count = (u64::from(
            to_range_last_auth_tree_data_block_target_allocation_blocks_begin
                - from_range_last_auth_tree_data_block_target_allocation_blocks_begin,
        ) >> auth_tree_data_block_allocation_blocks_log2)
            - AuthTreeDataBlocksUpdateStatesIndexRange::new(from_states_index_range.end(), to_states_index_range.end())
                .len() as u64;

        let from_range_end_to_range_end_target_allocation_blocks_xor =
            u64::from(from_range_last_auth_tree_data_block_target_allocation_blocks_begin)
                .wrapping_add(1u64 << auth_tree_data_block_allocation_blocks_log2)
                ^ u64::from(to_range_last_auth_tree_data_block_target_allocation_blocks_begin)
                    .wrapping_add(1u64 << auth_tree_data_block_allocation_blocks_log2);

        let (
            from_range_end_to_range_begin_target_allocation_blocks_xor,
            from_range_end_to_to_range_begin_missing_states_count,
        ) = if !to_states_index_range.is_empty() {
            let from_range_target_allocation_blocks_end =
                from_range_last_auth_tree_data_block_target_allocation_blocks_begin
                    + layout::AllocBlockCount::from(1u64 << auth_tree_data_block_allocation_blocks_log2);
            let to_range_target_allocation_blocks_begin =
                states[to_states_index_range.begin()].get_target_allocation_blocks_begin();

            // The number of missing states is the difference of the number of
            // Authentication Tree Data Blocks spanned and what's already there.
            let from_range_end_to_to_range_begin_missing_states_count =
                (u64::from(to_range_target_allocation_blocks_begin - from_range_target_allocation_blocks_end)
                    >> auth_tree_data_block_allocation_blocks_log2)
                    - AuthTreeDataBlocksUpdateStatesIndexRange::new(
                        from_states_index_range.end(),
                        to_states_index_range.begin(),
                    )
                    .len() as u64;

            let from_range_end_to_range_begin_target_allocation_blocks_xor =
                u64::from(from_range_target_allocation_blocks_end) ^ u64::from(to_range_target_allocation_blocks_begin);

            (
                from_range_end_to_range_begin_target_allocation_blocks_xor,
                from_range_end_to_to_range_begin_missing_states_count,
            )
        } else {
            (
                from_range_end_to_range_end_target_allocation_blocks_xor,
                from_range_end_to_to_range_end_missing_states_count,
            )
        };

        Self {
            from_range_end_to_range_begin_target_allocation_blocks_xor,
            from_range_end_to_to_range_begin_missing_states_count,
            from_range_end_to_range_end_target_allocation_blocks_xor,
            from_range_end_to_to_range_end_missing_states_count,
        }
    }

    /// Obtain transformed index range offsets after the states insertion
    /// operation has completed.
    ///
    /// Transform the `from_range_offsets` specific to the initial
    /// `from_states_index_range` passed to [`new()`](Self::new) to be
    /// applicable to the `to_states_index_range`, also as passed to
    /// [`new()`](Self::new).
    ///
    /// # Arguments:
    ///
    /// * `from_range_offsets` - The offsets specific to the
    ///   `from_states_index_range` initially passed to [`new()`](Self::new), as
    ///   returned back from the states insertion primitive.
    /// * `alignment_fillup_maybe_failed` - Whether the states insertion might
    ///   have failed halfways, i.e. whether the insertion primitive returned an
    ///   error.
    pub fn apply(
        &self,
        from_range_offsets: &AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets,
    ) -> AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets {
        // If the end of the range to be transformed from and the one of the range to be
        // transformed to are not separated by an alignment block, then states
        // filled after the former might extend to after the latter.
        let inserted_states_after_to_range_count = if self.from_range_end_to_range_end_target_allocation_blocks_xor
            >> from_range_offsets.max_target_allocations_blocks_alignment_log2
            != 0
        {
            0
        } else {
            // States get populated from left to right, so this is correct even if
            // an error occured midways.
            (from_range_offsets.inserted_states_after_range_count as u64)
                .saturating_sub(self.from_range_end_to_to_range_end_missing_states_count) as usize
        };
        let remaining_inserted_states_after_from_range_count =
            from_range_offsets.inserted_states_after_range_count - inserted_states_after_to_range_count;

        // If the end of the range to be transformed from and the beginning of the range
        // to be transformed to are not separated by an alignment block, then
        // states filled after the former might extend to after the latter.
        let inserted_states_within_to_range_count = if self.from_range_end_to_range_begin_target_allocation_blocks_xor
            >> from_range_offsets.max_target_allocations_blocks_alignment_log2
            != 0
        {
            0
        } else {
            // States get populated from left to right, so this is correct even if
            // an error occured midways.
            (remaining_inserted_states_after_from_range_count as u64)
                .saturating_sub(self.from_range_end_to_to_range_begin_missing_states_count) as usize
        };

        // The remainder got all inserted before the range to transform to.
        let inserted_states_before_to_range_count = from_range_offsets.total_inserted_states_count()
            - inserted_states_after_to_range_count
            - inserted_states_within_to_range_count;

        AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets {
            inserted_states_before_range_count: inserted_states_before_to_range_count,
            inserted_states_within_range_count: inserted_states_within_to_range_count,
            inserted_states_after_range_count: inserted_states_after_to_range_count,
            max_target_allocations_blocks_alignment_log2: from_range_offsets
                .max_target_allocations_blocks_alignment_log2,
        }
    }
}

/// Transform [states insertion
/// offsets](AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets)
/// specific to one [Authentication Tree Data Block level index
/// range](AuthTreeDataBlocksUpdateStatesIndexRange) to another containing it.
pub struct AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsetsTransformToContaining {
    to_range_begin_from_range_begin_target_allocation_blocks_xor: u64,
    to_range_begin_to_from_range_begin_missing_states_count: u64,
    to_range_target_allocation_blocks_begin: layout::PhysicalAllocBlockIndex,
    from_range_end_to_range_end_target_allocation_blocks_xor: u64,
    from_range_end_to_to_range_end_missing_states_count: u64,
}

impl AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsetsTransformToContaining {
    /// Setup a index range offsets transform instance.
    ///
    /// Must get invoked before the actual states insertion operation with the
    /// original index ranges.
    ///
    /// # Arguments:
    ///
    /// * `from_states_index_range` - The index range associated with the
    ///   offsets to get later transformed to apply to `to_states_index_range`.
    /// * `to_states_index_range` - The index range to later obtain insertion
    ///   offsets for.
    /// * `states` - The [`AuthTreeDataBlocksUpdateStates`] instance both
    ///   `from_states_index_range` and `to_states_index_range` refer into.
    pub fn new(
        from_states_index_range: &AuthTreeDataBlocksUpdateStatesIndexRange,
        to_states_index_range: &AuthTreeDataBlocksUpdateStatesIndexRange,
        states: &AuthTreeDataBlocksUpdateStates,
    ) -> Self {
        // If the range to transform from is empty, it has no well-defined position
        // within the physical target range, which could serve as an anchor
        // point.
        debug_assert!(!from_states_index_range.is_empty());
        // The range to transform to contains the range to transform from by assumption.
        debug_assert!(
            to_states_index_range.begin() <= from_states_index_range.begin()
                && from_states_index_range.end() <= to_states_index_range.end()
        );

        let auth_tree_data_block_allocation_blocks_log2 = states.auth_tree_data_block_allocation_blocks_log2 as u32;

        let to_range_target_allocation_blocks_begin =
            states[to_states_index_range.begin()].get_target_allocation_blocks_begin();
        let from_range_target_allocation_blocks_begin =
            states[from_states_index_range.begin()].get_target_allocation_blocks_begin();

        // The number of missing states is the difference of the number of
        // Authentication Tree Data Blocks spanned and what's already there.
        let to_range_begin_to_from_range_begin_missing_states_count =
            (u64::from(from_range_target_allocation_blocks_begin - to_range_target_allocation_blocks_begin)
                >> auth_tree_data_block_allocation_blocks_log2)
                - AuthTreeDataBlocksUpdateStatesIndexRange::new(
                    to_states_index_range.begin(),
                    from_states_index_range.begin(),
                )
                .len() as u64;

        let to_range_begin_from_range_begin_target_allocation_blocks_xor =
            u64::from(to_range_target_allocation_blocks_begin) ^ u64::from(from_range_target_allocation_blocks_begin);

        let from_range_last_auth_tree_data_block_target_allocation_blocks_begin =
            states[from_states_index_range.end().step_back().unwrap()].get_target_allocation_blocks_begin();
        let to_range_last_auth_tree_data_block_target_allocation_blocks_begin =
            states[to_states_index_range.end().step_back().unwrap()].get_target_allocation_blocks_begin();

        // The number of missing states is the difference of the number of
        // Authentication Tree Data Blocks spanned and what's already there.
        let from_range_end_to_to_range_end_missing_states_count = (u64::from(
            to_range_last_auth_tree_data_block_target_allocation_blocks_begin
                - from_range_last_auth_tree_data_block_target_allocation_blocks_begin,
        ) >> auth_tree_data_block_allocation_blocks_log2)
            - AuthTreeDataBlocksUpdateStatesIndexRange::new(from_states_index_range.end(), to_states_index_range.end())
                .len() as u64;

        let from_range_end_to_range_end_target_allocation_blocks_xor =
            u64::from(from_range_last_auth_tree_data_block_target_allocation_blocks_begin)
                .wrapping_add(1u64 << auth_tree_data_block_allocation_blocks_log2)
                ^ u64::from(to_range_last_auth_tree_data_block_target_allocation_blocks_begin)
                    .wrapping_add(1u64 << auth_tree_data_block_allocation_blocks_log2);

        Self {
            to_range_begin_from_range_begin_target_allocation_blocks_xor,
            to_range_begin_to_from_range_begin_missing_states_count,
            to_range_target_allocation_blocks_begin,
            from_range_end_to_range_end_target_allocation_blocks_xor,
            from_range_end_to_to_range_end_missing_states_count,
        }
    }

    /// Obtain transformed index range offsets after the states insertion
    /// operation has completed.
    ///
    /// Transform the `from_range_offsets` specific to the initial
    /// `from_states_index_range` passed to [`new()`](Self::new) to be
    /// applicable to the `to_states_index_range`, also as passed to
    /// [`new()`](Self::new).
    ///
    /// # Arguments:
    ///
    /// * `from_range_offsets` - The offsets specific to the
    ///   `from_states_index_range` initially passed to [`new()`](Self::new), as
    ///   returned back from the states insertion primitive.
    /// * `alignment_fillup_maybe_failed` - Whether the states insertion might
    ///   have failed halfways, i.e. whether the insertion primitive returned an
    ///   error.
    pub fn apply(
        &self,
        from_range_offsets: &AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets,
        alignment_fillup_maybe_failed: Option<&AuthTreeDataBlocksUpdateStates>,
    ) -> AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets {
        // If the beginning of the range to be transformed from and the one of the range
        // to be transformed to are not separated by an alignment block, then
        // states filled before the former might extend to before the latter.
        let inserted_states_before_to_range_count = if self.to_range_begin_from_range_begin_target_allocation_blocks_xor
            >> from_range_offsets.max_target_allocations_blocks_alignment_log2
            != 0
        {
            0
        } else {
            // In the (rare) event that the left-to-right alignment gap fillup might have
            // failed somewhere midways when populating states before the
            // beginning of the range to get transformed from, it cannot be
            // assumed that all missing states between the range to transform to
            // and the latter have been filled up and we have to resort to a search.
            let alignment_fillup_maybe_failed = if from_range_offsets.inserted_states_within_range_count != 0
                || from_range_offsets.inserted_states_after_range_count != 0
            {
                // The fillup already made it past the beginning of the range to transform from.
                None
            } else {
                alignment_fillup_maybe_failed
            };
            match alignment_fillup_maybe_failed {
                None => {
                    // States get populated from left to right, so this is correct *only if*
                    // no error occured midways while populating any states before the range
                    // to be transformed from, i.e. in the common case.
                    debug_assert!(
                        from_range_offsets.inserted_states_before_range_count
                            >= self.to_range_begin_to_from_range_begin_missing_states_count as usize
                    );
                    from_range_offsets.inserted_states_before_range_count
                        - self.to_range_begin_to_from_range_begin_missing_states_count as usize
                }
                Some(states) => {
                    let auth_tree_data_block_allocation_blocks_log2 =
                        states.auth_tree_data_block_allocation_blocks_log2 as u32;

                    // Recover the beginning target allocation block of the range to transform from
                    // from the xor.
                    let from_range_target_allocation_blocks_begin = layout::PhysicalAllocBlockIndex::from(
                        u64::from(self.to_range_target_allocation_blocks_begin)
                            ^ self.to_range_begin_from_range_begin_target_allocation_blocks_xor,
                    );

                    let adjusted_to_states_index_range_begin = states
                        .lookup_auth_tree_data_block_update_state_index(self.to_range_target_allocation_blocks_begin)
                        .unwrap();
                    let adjusted_from_states_index_range_begin = states
                        .lookup_auth_tree_data_block_update_state_index(from_range_target_allocation_blocks_begin)
                        .unwrap();

                    // The number of missing states is the difference of the number of
                    // Authentication Tree Data Blocks spanned and what's actually there.
                    let adjusted_to_range_begin_to_from_range_begin_missing_states_count = (u64::from(
                        from_range_target_allocation_blocks_begin - self.to_range_target_allocation_blocks_begin,
                    )
                        >> auth_tree_data_block_allocation_blocks_log2)
                        - AuthTreeDataBlocksUpdateStatesIndexRange::new(
                            adjusted_to_states_index_range_begin,
                            adjusted_from_states_index_range_begin,
                        )
                        .len() as u64;
                    debug_assert!(
                        adjusted_to_range_begin_to_from_range_begin_missing_states_count
                            <= self.to_range_begin_to_from_range_begin_missing_states_count
                    );
                    let inserted_states_within_to_range_count = self
                        .to_range_begin_to_from_range_begin_missing_states_count
                        - adjusted_to_range_begin_to_from_range_begin_missing_states_count;
                    debug_assert!(
                        inserted_states_within_to_range_count as usize
                            <= from_range_offsets.inserted_states_before_range_count
                    );
                    from_range_offsets.inserted_states_before_range_count
                        - inserted_states_within_to_range_count as usize
                }
            }
        };

        // If the end of the range to be transformed from and the one of the range to be
        // transformed to are not separated by an alignment block, then states
        // filled after the former might extend to after the latter.
        let inserted_states_after_to_range_count = if self.from_range_end_to_range_end_target_allocation_blocks_xor
            >> from_range_offsets.max_target_allocations_blocks_alignment_log2
            != 0
        {
            0
        } else {
            // States get populated from left to right, so this is correct even if
            // an error occured midways.
            (from_range_offsets.inserted_states_after_range_count as u64)
                .saturating_sub(self.from_range_end_to_to_range_end_missing_states_count) as usize
        };

        // The remainder all went to within the range's bounds.
        let inserted_states_within_to_range_count = from_range_offsets.total_inserted_states_count()
            - inserted_states_before_to_range_count
            - inserted_states_after_to_range_count;

        AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets {
            inserted_states_before_range_count: inserted_states_before_to_range_count,
            inserted_states_within_range_count: inserted_states_within_to_range_count,
            inserted_states_after_range_count: inserted_states_after_to_range_count,
            max_target_allocations_blocks_alignment_log2: from_range_offsets
                .max_target_allocations_blocks_alignment_log2,
        }
    }
}

/// Iterator returned by
/// [`AuthTreeDataBlocksUpdateStates::iter_allocation_blocks()`].
#[derive(Clone)]
pub struct AuthTreeDataBlocksUpdateStatesAllocationBlocksIter<'a> {
    // Until slice::take() has been stabilized, remaining_states needs to live in an
    // Option: apparently Rust would not allow moving temporarily out of it,
    // splitting it and moving the result back in again, it would infect
    // the splitted result with &mut self's lifetime.
    remaining_states: Option<&'a [AuthTreeDataBlockUpdateState]>,
    cur_auth_tree_data_block_allocation_blocks_iter: Option<(
        layout::PhysicalAllocBlockIndex,
        slice::Iter<'a, AllocationBlockUpdateState>,
    )>,
    auth_tree_data_block_allocation_blocks_log2: u8,
    next_states_allocation_blocks_index: AuthTreeDataBlocksUpdateStatesAllocationBlockIndex,
    states_allocation_blocks_range_end: Option<AuthTreeDataBlocksUpdateStatesAllocationBlockIndex>,
}

impl<'a> AuthTreeDataBlocksUpdateStatesAllocationBlocksIter<'a> {
    /// Instantiate a [`AuthTreeDataBlocksUpdateStatesAllocationBlocksIter`].
    ///
    /// # Arguments:
    ///
    /// * `states` - The [`AuthTreeDataBlocksUpdateStates`] to iterate over.
    /// * `states_allocation_blocks_range` - [Allocation Block level entry index
    ///   range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange) to
    ///   restrict the iteration to, if any.
    fn new(
        states: &'a AuthTreeDataBlocksUpdateStates,
        states_allocation_blocks_range: Option<&AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange>,
    ) -> Self {
        let auth_tree_data_block_allocation_blocks_log2 = states.auth_tree_data_block_allocation_blocks_log2;
        let mut remaining_states = states.states.as_slice();
        let (
            cur_auth_tree_data_block_allocation_blocks_iter,
            next_states_allocation_blocks_index,
            states_allocation_blocks_range_end,
        ) = match states_allocation_blocks_range {
            Some(states_allocation_blocks_range) => {
                remaining_states = remaining_states
                    .split_at(usize::from(AuthTreeDataBlocksUpdateStatesIndex::from(
                        *states_allocation_blocks_range.begin(),
                    )))
                    .1;

                let first_allocation_block_index_in_auth_tree_data_block = states_allocation_blocks_range
                    .begin()
                    .allocation_block_index_in_auth_tree_data_block;
                let cur_auth_tree_data_block_allocation_blocks_iter = if states_allocation_blocks_range.begin()
                    != states_allocation_blocks_range.end()
                    && first_allocation_block_index_in_auth_tree_data_block != 0
                {
                    let first_auth_tree_data_block_state;
                    (first_auth_tree_data_block_state, remaining_states) = remaining_states.split_at(1);
                    let first_auth_tree_data_block_state = &first_auth_tree_data_block_state[0];
                    let first_target_allocation_block_index = first_auth_tree_data_block_state
                        .get_target_allocation_blocks_begin()
                        + layout::AllocBlockCount::from(first_allocation_block_index_in_auth_tree_data_block as u64);
                    let remaining_allocation_blocks_states = first_auth_tree_data_block_state
                        .allocation_blocks_states
                        .split_at(first_allocation_block_index_in_auth_tree_data_block)
                        .1;
                    Some((
                        first_target_allocation_block_index,
                        remaining_allocation_blocks_states.iter(),
                    ))
                } else {
                    None
                };
                (
                    cur_auth_tree_data_block_allocation_blocks_iter,
                    *states_allocation_blocks_range.begin(),
                    Some(*states_allocation_blocks_range.end()),
                )
            }
            None => (
                None,
                AuthTreeDataBlocksUpdateStatesAllocationBlockIndex::from(AuthTreeDataBlocksUpdateStatesIndex::from(
                    0usize,
                )),
                None,
            ),
        };

        Self {
            remaining_states: Some(remaining_states),
            cur_auth_tree_data_block_allocation_blocks_iter,
            auth_tree_data_block_allocation_blocks_log2,
            next_states_allocation_blocks_index,
            states_allocation_blocks_range_end,
        }
    }
}

impl<'a> Iterator for AuthTreeDataBlocksUpdateStatesAllocationBlocksIter<'a> {
    /// The type of the elements being iterated over.
    ///
    /// The iterator yields pairs of the [`AllocationBlockUpdateState`]s
    /// associated target storage location and a reference to the
    /// [`AllocationBlockUpdateState`]s themselves each.
    type Item = (layout::PhysicalAllocBlockIndex, &'a AllocationBlockUpdateState);

    fn next(&mut self) -> Option<Self::Item> {
        if self
            .states_allocation_blocks_range_end
            .as_ref()
            .map(|states_allocation_blocks_range_end| {
                self.next_states_allocation_blocks_index == *states_allocation_blocks_range_end
            })
            .unwrap_or(false)
        {
            return None;
        }

        match self.cur_auth_tree_data_block_allocation_blocks_iter.as_mut().and_then(
            |(next_target_allocation_block_index, cur_auth_tree_data_block_allocation_blocks_iter)| {
                cur_auth_tree_data_block_allocation_blocks_iter
                    .next()
                    .map(|cur_allocation_block_update_state| {
                        (next_target_allocation_block_index, cur_allocation_block_update_state)
                    })
            },
        ) {
            Some((next_target_allocation_block_index, cur_allocation_block_update_state)) => {
                let cur_target_allocation_block_index = *next_target_allocation_block_index;
                *next_target_allocation_block_index =
                    cur_target_allocation_block_index + layout::AllocBlockCount::from(1);
                self.next_states_allocation_blocks_index = self
                    .next_states_allocation_blocks_index
                    .step(self.auth_tree_data_block_allocation_blocks_log2 as u32);
                Some((cur_target_allocation_block_index, cur_allocation_block_update_state))
            }
            None => {
                self.cur_auth_tree_data_block_allocation_blocks_iter = None;
                let remaining_states = self.remaining_states.take()?;
                if remaining_states.is_empty() {
                    return None;
                }
                let (cur_auth_tree_data_block_state, remaining_states) = remaining_states.split_at(1);
                self.remaining_states = Some(remaining_states);
                let cur_auth_tree_data_block_state = &cur_auth_tree_data_block_state[0];
                let cur_target_allocation_block_index =
                    cur_auth_tree_data_block_state.get_target_allocation_blocks_begin();
                debug_assert_eq!(
                    cur_auth_tree_data_block_state.allocation_blocks_states.len(),
                    1usize << self.auth_tree_data_block_allocation_blocks_log2
                );
                let (cur_allocation_block_state, remaining_allocation_blocks_states) =
                    cur_auth_tree_data_block_state.allocation_blocks_states.split_at(1);
                let cur_allocation_block_state = &cur_allocation_block_state[0];
                let next_target_allocation_block_index =
                    cur_target_allocation_block_index + layout::AllocBlockCount::from(1);
                self.cur_auth_tree_data_block_allocation_blocks_iter = Some((
                    next_target_allocation_block_index,
                    remaining_allocation_blocks_states.iter(),
                ));
                self.next_states_allocation_blocks_index = self
                    .next_states_allocation_blocks_index
                    .step(self.auth_tree_data_block_allocation_blocks_log2 as u32);
                Some((cur_target_allocation_block_index, cur_allocation_block_state))
            }
        }
    }
}

/// Iterator returned by
/// [`AuthTreeDataBlocksUpdateStates::iter_allocation_blocks_mut()`].
pub struct AuthTreeDataBlocksUpdateStatesAllocationBlocksIterMut<'a> {
    // Until slice::take() has been stabilized, remaining_states needs to live in an
    // Option: apparently Rust would not allow moving temporarily out of it,
    // splitting it and moving the result back in again, it would infect
    // the splitted result with &mut self's lifetime.
    remaining_states: Option<&'a mut [AuthTreeDataBlockUpdateState]>,
    cur_auth_tree_data_block_allocation_blocks_iter: Option<(
        layout::PhysicalAllocBlockIndex,
        // Remaining Allocation Block states in the current Authentication Tree Data Block.
        // Would have been nice to use slice::IterMut<'a, _> here, but as_mut_slice(), needed for
        // Self::peek_mut(), is unstable.
        &'a mut [AllocationBlockUpdateState],
    )>,
    auth_tree_data_block_allocation_blocks_log2: u8,
    next_states_allocation_blocks_index: AuthTreeDataBlocksUpdateStatesAllocationBlockIndex,
    states_allocation_blocks_range_end: Option<AuthTreeDataBlocksUpdateStatesAllocationBlockIndex>,
}

impl<'a> AuthTreeDataBlocksUpdateStatesAllocationBlocksIterMut<'a> {
    /// Instantiate a [`AuthTreeDataBlocksUpdateStatesAllocationBlocksIterMut`].
    ///
    /// # Arguments:
    ///
    /// * `states` - The [`AuthTreeDataBlocksUpdateStates`] to iterate over.
    /// * `states_allocation_blocks_range` - [Allocation Block level entry index
    ///   range](AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange) to
    ///   restrict the iteration to, if any.
    fn new(
        states: &'a mut AuthTreeDataBlocksUpdateStates,
        states_allocation_blocks_range: Option<&AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange>,
    ) -> Self {
        let auth_tree_data_block_allocation_blocks_log2 = states.auth_tree_data_block_allocation_blocks_log2;
        let mut remaining_states = states.states.as_mut_slice();
        let (
            cur_auth_tree_data_block_allocation_blocks_iter,
            next_states_allocation_blocks_index,
            states_allocation_blocks_range_end,
        ) = match states_allocation_blocks_range {
            Some(states_allocation_blocks_range) => {
                remaining_states = remaining_states
                    .split_at_mut(usize::from(AuthTreeDataBlocksUpdateStatesIndex::from(
                        *states_allocation_blocks_range.begin(),
                    )))
                    .1;

                let first_allocation_block_index_in_auth_tree_data_block = states_allocation_blocks_range
                    .begin()
                    .allocation_block_index_in_auth_tree_data_block;
                let cur_auth_tree_data_block_allocation_blocks_iter = if states_allocation_blocks_range.begin()
                    != states_allocation_blocks_range.end()
                    && first_allocation_block_index_in_auth_tree_data_block != 0
                {
                    let first_auth_tree_data_block_state;
                    (first_auth_tree_data_block_state, remaining_states) = remaining_states.split_at_mut(1);
                    let first_auth_tree_data_block_state = &mut first_auth_tree_data_block_state[0];
                    let first_target_allocation_block_index = first_auth_tree_data_block_state
                        .get_target_allocation_blocks_begin()
                        + layout::AllocBlockCount::from(first_allocation_block_index_in_auth_tree_data_block as u64);
                    let remaining_allocation_blocks_states = first_auth_tree_data_block_state
                        .allocation_blocks_states
                        .split_at_mut(first_allocation_block_index_in_auth_tree_data_block)
                        .1;
                    debug_assert!(!remaining_allocation_blocks_states.is_empty());
                    Some((first_target_allocation_block_index, remaining_allocation_blocks_states))
                } else {
                    None
                };
                (
                    cur_auth_tree_data_block_allocation_blocks_iter,
                    *states_allocation_blocks_range.begin(),
                    Some(*states_allocation_blocks_range.end()),
                )
            }
            None => (
                None,
                AuthTreeDataBlocksUpdateStatesAllocationBlockIndex::from(AuthTreeDataBlocksUpdateStatesIndex::from(
                    0usize,
                )),
                None,
            ),
        };

        Self {
            remaining_states: Some(remaining_states),
            cur_auth_tree_data_block_allocation_blocks_iter,
            auth_tree_data_block_allocation_blocks_log2,
            next_states_allocation_blocks_index,
            states_allocation_blocks_range_end,
        }
    }

    /// Spawn off a [`AuthTreeDataBlocksUpdateStatesAllocationBlocksIter`] from
    /// `self`'s current state.
    fn peek(&self) -> AuthTreeDataBlocksUpdateStatesAllocationBlocksIter<'_> {
        AuthTreeDataBlocksUpdateStatesAllocationBlocksIter {
            remaining_states: self.remaining_states.as_deref(),
            cur_auth_tree_data_block_allocation_blocks_iter: {
                self.cur_auth_tree_data_block_allocation_blocks_iter.as_ref().map(
                    |(next_target_allocation_block_index, cur_auth_tree_data_block_allocation_blocks_iter)| {
                        (
                            *next_target_allocation_block_index,
                            cur_auth_tree_data_block_allocation_blocks_iter.iter(),
                        )
                    },
                )
            },
            auth_tree_data_block_allocation_blocks_log2: self.auth_tree_data_block_allocation_blocks_log2,
            next_states_allocation_blocks_index: self.next_states_allocation_blocks_index,
            states_allocation_blocks_range_end: self.states_allocation_blocks_range_end,
        }
    }

    /// Spawn off a [`AuthTreeDataBlocksUpdateStatesAllocationBlocksIterMut`]
    /// from `self`'s current state.
    fn peek_mut(&mut self) -> AuthTreeDataBlocksUpdateStatesAllocationBlocksIterMut<'_> {
        AuthTreeDataBlocksUpdateStatesAllocationBlocksIterMut {
            remaining_states: self.remaining_states.as_deref_mut(),
            cur_auth_tree_data_block_allocation_blocks_iter: {
                self.cur_auth_tree_data_block_allocation_blocks_iter.as_mut().map(
                    |(next_target_allocation_block_index, cur_auth_tree_data_block_allocation_blocks_iter)| {
                        (
                            *next_target_allocation_block_index,
                            &mut **cur_auth_tree_data_block_allocation_blocks_iter,
                        )
                    },
                )
            },
            auth_tree_data_block_allocation_blocks_log2: self.auth_tree_data_block_allocation_blocks_log2,
            next_states_allocation_blocks_index: self.next_states_allocation_blocks_index,
            states_allocation_blocks_range_end: self.states_allocation_blocks_range_end,
        }
    }
}

impl<'a> Iterator for AuthTreeDataBlocksUpdateStatesAllocationBlocksIterMut<'a> {
    /// The type of the elements being iterated over.
    ///
    /// The iterator yields pairs of the [`AllocationBlockUpdateState`]s
    /// associated target storage location and a `mut` reference to the
    /// [`AllocationBlockUpdateState`]s themselves each.
    type Item = (layout::PhysicalAllocBlockIndex, &'a mut AllocationBlockUpdateState);

    fn next(&mut self) -> Option<Self::Item> {
        if self
            .states_allocation_blocks_range_end
            .as_ref()
            .map(|states_allocation_blocks_range_end| {
                self.next_states_allocation_blocks_index == *states_allocation_blocks_range_end
            })
            .unwrap_or(false)
        {
            return None;
        }

        match self.cur_auth_tree_data_block_allocation_blocks_iter.take() {
            Some((next_target_allocation_block_index, remaining_allocation_blocks_states)) => {
                debug_assert!(!remaining_allocation_blocks_states.is_empty());
                let (cur_allocation_block_update_state, remaining_allocation_blocks_states) =
                    remaining_allocation_blocks_states.split_at_mut(1);
                let cur_allocation_block_update_state = &mut cur_allocation_block_update_state[0];
                let cur_target_allocation_block_index = next_target_allocation_block_index;
                if !remaining_allocation_blocks_states.is_empty() {
                    self.cur_auth_tree_data_block_allocation_blocks_iter = Some((
                        cur_target_allocation_block_index + layout::AllocBlockCount::from(1),
                        remaining_allocation_blocks_states,
                    ));
                }
                self.next_states_allocation_blocks_index = self
                    .next_states_allocation_blocks_index
                    .step(self.auth_tree_data_block_allocation_blocks_log2 as u32);
                Some((cur_target_allocation_block_index, cur_allocation_block_update_state))
            }
            None => {
                let remaining_states = self.remaining_states.take()?;
                if remaining_states.is_empty() {
                    return None;
                }
                let (cur_auth_tree_data_block_state, remaining_states) = remaining_states.split_at_mut(1);
                self.remaining_states = Some(remaining_states);
                let cur_auth_tree_data_block_state = &mut cur_auth_tree_data_block_state[0];
                let cur_target_allocation_block_index =
                    cur_auth_tree_data_block_state.get_target_allocation_blocks_begin();
                debug_assert_eq!(
                    cur_auth_tree_data_block_state.allocation_blocks_states.len(),
                    1usize << self.auth_tree_data_block_allocation_blocks_log2
                );
                let (cur_allocation_block_state, remaining_allocation_blocks_states) =
                    cur_auth_tree_data_block_state.allocation_blocks_states.split_at_mut(1);
                let cur_allocation_block_state = &mut cur_allocation_block_state[0];
                if !remaining_allocation_blocks_states.is_empty() {
                    let next_target_allocation_block_index =
                        cur_target_allocation_block_index + layout::AllocBlockCount::from(1);
                    self.cur_auth_tree_data_block_allocation_blocks_iter =
                        Some((next_target_allocation_block_index, remaining_allocation_blocks_states));
                }
                self.next_states_allocation_blocks_index = self
                    .next_states_allocation_blocks_index
                    .step(self.auth_tree_data_block_allocation_blocks_log2 as u32);
                Some((cur_target_allocation_block_index, cur_allocation_block_state))
            }
        }
    }
}

/// [`PeekableIoSlicesIter`](io_slices::PeekableIoSlicesIter) over some
/// [`AllocationBlockUpdateStagedUpdate`] entries' combined buffers.
///
/// Provided primarily for supporting the
/// [`MutPeekableIoSlicesMutIter`](io_slices::MutPeekableIoSlicesMutIter)
/// implementation for
/// [`AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIterMut`].
pub struct AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIter<'a> {
    update_states_allocation_blocks_iter: AuthTreeDataBlocksUpdateStatesAllocationBlocksIter<'a>,
    head: Option<&'a [u8]>,
    allocation_block_size_128b_log2: u8,
}

impl<'a> AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIter<'a> {
    /// Instantiate a
    /// [`AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIter`].
    ///
    ///
    /// # Arguments:
    ///
    /// * `update_states_allocation_blocks_iter` - Iterator over the
    ///   [`AllocationBlockUpdateState`] entries whose update staging buffers to
    ///   combine.
    /// * `allocation_block_size_128b_log2` - Verbatim value of
    ///   [`ImageLayout::allocation_block_size_128b_log2`].
    #[allow(dead_code)]
    fn new(
        mut update_states_allocation_blocks_iter: AuthTreeDataBlocksUpdateStatesAllocationBlocksIter<'a>,
        allocation_block_size_128b_log2: u8,
    ) -> Result<Self, NvFsError> {
        let head = match update_states_allocation_blocks_iter.next() {
            Some((_, first_allocation_block_update_state)) => {
                match &first_allocation_block_update_state.staged_update {
                    AllocationBlockUpdateStagedUpdate::Update { encrypted_data } => {
                        if encrypted_data.is_empty() {
                            return Err(nvfs_err_internal!());
                        }
                        Some(encrypted_data.as_slice())
                    }
                    _ => return Err(nvfs_err_internal!()),
                }
            }
            None => None,
        };
        Ok(Self {
            update_states_allocation_blocks_iter,
            head,
            allocation_block_size_128b_log2,
        })
    }
}

impl<'a> io_slices::IoSlicesIterCommon for AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIter<'a> {
    type BackendIteratorError = CryptoError;

    fn next_slice_len(&mut self) -> Result<usize, Self::BackendIteratorError> {
        Ok(self.head.as_ref().map(|slice| slice.len()).unwrap_or(0))
    }
}

impl<'a> io_slices::IoSlicesIter<'a> for AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIter<'a> {
    fn next_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        let head_slice = match self.head.take() {
            Some(head_slice) => head_slice,
            None => return Ok(None),
        };

        let max_len = max_len
            .map(|max_len| max_len.min(head_slice.len()))
            .unwrap_or(head_slice.len());
        if max_len < head_slice.len() {
            let (head_slice, remaining_slice) = head_slice.split_at(max_len);
            self.head = Some(remaining_slice);
            Ok(Some(head_slice))
        } else {
            self.head = match self.update_states_allocation_blocks_iter.next() {
                Some((_, next_allocation_block_update_state)) => {
                    match &next_allocation_block_update_state.staged_update {
                        AllocationBlockUpdateStagedUpdate::Update { encrypted_data } => {
                            if encrypted_data.is_empty() {
                                return Err(CryptoError::Internal);
                            }
                            Some(encrypted_data.as_slice())
                        }
                        AllocationBlockUpdateStagedUpdate::FailedUpdate => {
                            return Err(CryptoError::BufferStateIndeterminate);
                        }
                        _ => return Err(CryptoError::Internal),
                    }
                }
                None => None,
            };
            Ok(Some(head_slice))
        }
    }
}

impl<'a> io_slices::WalkableIoSlicesIter<'a>
    for AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIter<'a>
{
    fn for_each(&self, cb: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), Self::BackendIteratorError> {
        let mut iter = io_slices::PeekableIoSlicesIter::decoupled_borrow(self);
        while let Some(slice) = iter.next_slice(None)? {
            if !cb(slice) {
                break;
            }
        }
        Ok(())
    }

    fn all_aligned_to(&self, alignment: usize) -> Result<bool, Self::BackendIteratorError> {
        if alignment.is_pow2() && alignment <= (1usize << (self.allocation_block_size_128b_log2 as u32 + 7)) {
            // All Allocation Blocks are aligned. Check the head.
            Ok(self
                .head
                .as_ref()
                .map(|slice| slice.len() & (alignment - 1) == 0)
                .unwrap_or(true))
        } else {
            let mut all_aligned = true;
            if alignment.is_pow2() {
                self.for_each(&mut |slice| {
                    all_aligned &= slice.len() & (alignment - 1) == 0;
                    all_aligned
                })?;
            } else {
                self.for_each(&mut |slice| {
                    all_aligned &= slice.len() % alignment == 0;
                    all_aligned
                })?;
            }
            Ok(all_aligned)
        }
    }
}

impl<'a> io_slices::PeekableIoSlicesIter<'a>
    for AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIter<'a>
{
    type DecoupledBorrowIterType<'b>
        = AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIter<'b>
    where
        Self: 'b;

    fn decoupled_borrow<'b>(&'b self) -> Self::DecoupledBorrowIterType<'b> {
        AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIter {
            update_states_allocation_blocks_iter: self.update_states_allocation_blocks_iter.clone(),
            head: self.head,
            allocation_block_size_128b_log2: self.allocation_block_size_128b_log2,
        }
    }
}

/// [`MutPeekableIoSlicesMutIter`](io_slices::MutPeekableIoSlicesMutIter)
/// returned by
/// [`AuthTreeDataBlocksUpdateStates::iter_allocation_blocks_update_staging_bufs_mut()`].
pub struct AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIterMut<'a> {
    update_states_allocation_blocks_iter: AuthTreeDataBlocksUpdateStatesAllocationBlocksIterMut<'a>,
    head: Option<&'a mut [u8]>,
    allocation_block_size_128b_log2: u8,
}

impl<'a> AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIterMut<'a> {
    /// Instantiate a
    /// [`AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIterMut`].
    ///
    ///
    /// # Arguments:
    ///
    /// * `update_states_allocation_blocks_iter` - Iterator over the
    ///   [`AllocationBlockUpdateState`] entries whose update staging buffers to
    ///   combine.
    /// * `allocation_block_size_128b_log2` - Verbatim value of
    ///   [`ImageLayout::allocation_block_size_128b_log2`].
    fn new(
        mut update_states_allocation_blocks_iter: AuthTreeDataBlocksUpdateStatesAllocationBlocksIterMut<'a>,
        allocation_block_size_128b_log2: u8,
    ) -> Result<Self, NvFsError> {
        let head = match update_states_allocation_blocks_iter.next() {
            Some((_, first_allocation_block_update_state)) => {
                match &mut first_allocation_block_update_state.staged_update {
                    AllocationBlockUpdateStagedUpdate::Update { encrypted_data } => {
                        if encrypted_data.is_empty() {
                            return Err(nvfs_err_internal!());
                        }
                        Some(encrypted_data.as_mut_slice())
                    }
                    _ => return Err(nvfs_err_internal!()),
                }
            }
            None => None,
        };
        Ok(Self {
            update_states_allocation_blocks_iter,
            head,
            allocation_block_size_128b_log2,
        })
    }
}

impl<'a> io_slices::IoSlicesIterCommon for AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIterMut<'a> {
    type BackendIteratorError = CryptoError;

    fn next_slice_len(&mut self) -> Result<usize, Self::BackendIteratorError> {
        Ok(self.head.as_ref().map(|slice| slice.len()).unwrap_or(0))
    }
}

impl<'a> io_slices::IoSlicesIter<'a> for AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIterMut<'a> {
    fn next_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        self.next_slice_mut(max_len).map(|slice| slice.map(|slice| &*slice))
    }
}

impl<'a> io_slices::IoSlicesMutIter<'a> for AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIterMut<'a> {
    fn next_slice_mut(&mut self, max_len: Option<usize>) -> Result<Option<&'a mut [u8]>, Self::BackendIteratorError> {
        let head_slice = match self.head.take() {
            Some(head_slice) => head_slice,
            None => return Ok(None),
        };

        let max_len = max_len
            .map(|max_len| max_len.min(head_slice.len()))
            .unwrap_or(head_slice.len());
        if max_len < head_slice.len() {
            let (head_slice, remaining_slice) = head_slice.split_at_mut(max_len);
            self.head = Some(remaining_slice);
            Ok(Some(head_slice))
        } else {
            self.head = match self.update_states_allocation_blocks_iter.next() {
                Some((_, next_allocation_block_update_state)) => {
                    match &mut next_allocation_block_update_state.staged_update {
                        AllocationBlockUpdateStagedUpdate::Update { encrypted_data } => {
                            if encrypted_data.is_empty() {
                                return Err(CryptoError::Internal);
                            }
                            Some(encrypted_data.as_mut_slice())
                        }
                        AllocationBlockUpdateStagedUpdate::FailedUpdate => {
                            return Err(CryptoError::BufferStateIndeterminate);
                        }
                        _ => return Err(CryptoError::Internal),
                    }
                }
                None => None,
            };
            Ok(Some(head_slice))
        }
    }
}

impl<'a> io_slices::WalkableIoSlicesIter<'a>
    for AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIterMut<'a>
{
    fn for_each(&self, cb: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), Self::BackendIteratorError> {
        let mut iter = io_slices::PeekableIoSlicesIter::decoupled_borrow(self);
        while let Some(slice) = iter.next_slice(None)? {
            if !cb(slice) {
                break;
            }
        }
        Ok(())
    }

    fn all_aligned_to(&self, alignment: usize) -> Result<bool, Self::BackendIteratorError> {
        if alignment.is_pow2() && alignment <= (1usize << (self.allocation_block_size_128b_log2 as u32 + 7)) {
            // All Allocation Blocks are aligned. Check the head.
            Ok(self
                .head
                .as_ref()
                .map(|slice| slice.len() & (alignment - 1) == 0)
                .unwrap_or(true))
        } else {
            let mut all_aligned = true;
            if alignment.is_pow2() {
                self.for_each(&mut |slice| {
                    all_aligned &= slice.len() & (alignment - 1) == 0;
                    all_aligned
                })?;
            } else {
                self.for_each(&mut |slice| {
                    all_aligned &= slice.len() % alignment == 0;
                    all_aligned
                })?;
            }
            Ok(all_aligned)
        }
    }
}

impl<'a> io_slices::PeekableIoSlicesIter<'a>
    for AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIterMut<'a>
{
    type DecoupledBorrowIterType<'b>
        = AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIter<'b>
    where
        Self: 'b;

    fn decoupled_borrow<'b>(&'b self) -> Self::DecoupledBorrowIterType<'b> {
        AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIter {
            update_states_allocation_blocks_iter: self.update_states_allocation_blocks_iter.peek(),
            head: self.head.as_deref(),
            allocation_block_size_128b_log2: self.allocation_block_size_128b_log2,
        }
    }
}

impl<'a> io_slices::MutPeekableIoSlicesMutIter<'a>
    for AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIterMut<'a>
{
    type DecoupledBorrowMutIterType<'b>
        = AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIterMut<'b>
    where
        Self: 'b;

    fn decoupled_borrow_mut<'b>(&'b mut self) -> Self::DecoupledBorrowMutIterType<'b> {
        AuthTreeDataBlocksUpdateStatesAllocationBlocksStagedUpdateBufsIterMut {
            update_states_allocation_blocks_iter: self.update_states_allocation_blocks_iter.peek_mut(),
            head: self.head.as_deref_mut(),
            allocation_block_size_128b_log2: self.allocation_block_size_128b_log2,
        }
    }
}
