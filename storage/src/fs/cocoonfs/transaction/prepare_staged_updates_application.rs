// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`TransactionPrepareStagedUpdatesApplicationFuture`].

extern crate alloc;
use alloc::boxed::Box;

use super::{
    auth_tree_data_blocks_update_states::{
        AllocationBlockUpdateNvSyncState, AllocationBlockUpdateNvSyncStateAllocated,
        AllocationBlockUpdateNvSyncStateAllocatedModified, AllocationBlockUpdateStagedUpdate,
        AuthTreeDataBlocksUpdateStatesAllocationBlockIndex, AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets,
        AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsetsTransformToAfter,
        AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsetsTransformToContaining,
        AuthTreeDataBlocksUpdateStatesIndexRange,
    },
    read_authenticate_data::TransactionReadAuthenticateDataFuture,
    read_missing_data::TransactionReadMissingDataFuture,
    Transaction,
};
use crate::{
    chip,
    fs::cocoonfs::{
        fs::{CocoonFsSyncStateMemberRef, CocoonFsSyncStateReadFuture},
        layout, NvFsError,
    },
    nvfs_err_internal,
    utils_async::sync_types,
};
use core::{marker, pin, task};

pub struct TransactionPrepareStagedUpdatesApplicationFuture<ST: sync_types::SyncTypes, C: chip::NvChip> {
    request_states_allocation_blocks_index_range: AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    request_states_range_offsets: Option<AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets>,
    remaining_states_index_range: AuthTreeDataBlocksUpdateStatesIndexRange,
    fut_state: TransactionPrepareStagedUpdatesApplicationFutureState<C>,
    _phantom: marker::PhantomData<fn() -> *const ST>,
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> TransactionPrepareStagedUpdatesApplicationFuture<ST, C> {
    pub fn new(
        transaction: Box<Transaction>,
        request_states_allocation_blocks_index_range: AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    ) -> Self {
        let remaining_states_index_range =
            AuthTreeDataBlocksUpdateStatesIndexRange::from(request_states_allocation_blocks_index_range.clone());
        Self {
            request_states_allocation_blocks_index_range,
            request_states_range_offsets: None,
            remaining_states_index_range,
            fut_state: TransactionPrepareStagedUpdatesApplicationFutureState::Init {
                transaction: Some(transaction),
            },
            _phantom: marker::PhantomData,
        }
    }

    fn determine_next_prepare_subrange(
        transaction: &Transaction,
        image_header_end: layout::PhysicalAllocBlockIndex,
        request_states_allocation_blocks_range: &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        remaining_states_index_range: &AuthTreeDataBlocksUpdateStatesIndexRange,
    ) -> (
        Option<AuthTreeDataBlocksUpdateStatesIndexRange>,
        AuthTreeDataBlocksUpdateStatesIndexRange,
    ) {
        let allocation_block_size_128b_log2 = transaction.allocation_block_size_128b_log2 as u32;
        let auth_tree_data_block_allocation_blocks_log2 =
            transaction.auth_tree_data_block_allocation_blocks_log2 as u32;
        let chip_io_block_size_128b_log2 = transaction.chip_io_block_size_128b_log2;
        let preferred_chip_io_blocks_bulk_log2 = transaction.preferred_chip_io_blocks_bulk_log2;
        let preferred_read_block_allocation_blocks_log2 =
            TransactionReadMissingDataFuture::<C>::preferred_read_block_allocation_blocks_log2(
                chip_io_block_size_128b_log2,
                preferred_chip_io_blocks_bulk_log2,
                allocation_block_size_128b_log2,
                auth_tree_data_block_allocation_blocks_log2,
            );

        let states = &transaction.auth_tree_data_blocks_update_states;
        let mut remaining_states_index_range = remaining_states_index_range.clone();
        if remaining_states_index_range.is_empty() {
            return (None, remaining_states_index_range);
        }
        let mut last_physical_auth_tree_data_block_allocation_blocks_begin =
            states[remaining_states_index_range.begin()].get_target_allocation_blocks_begin();
        let mut subrange_needing_authentication_states_index_range_end = None;
        let mut cur_states_index = remaining_states_index_range.begin();
        while cur_states_index != remaining_states_index_range.end() {
            let cur_auth_tree_data_block_state = &states[cur_states_index];
            let cur_physical_auth_tree_data_block_allocation_blocks_begin =
                cur_auth_tree_data_block_state.get_target_allocation_blocks_begin();
            if subrange_needing_authentication_states_index_range_end.is_some() {
                // Something's been found by now. If there's a gap, stop.  Also, in order to
                // avoid having unboundedly long subsequences needing no
                // preparation at all somewhere in the returned range's
                // interior, stop upon crossing a preferred IO block boundary.
                if u64::from(
                    cur_physical_auth_tree_data_block_allocation_blocks_begin
                        - last_physical_auth_tree_data_block_allocation_blocks_begin,
                ) >> auth_tree_data_block_allocation_blocks_log2
                    > 1
                    || cur_physical_auth_tree_data_block_allocation_blocks_begin
                        .align_down(preferred_read_block_allocation_blocks_log2)
                        != last_physical_auth_tree_data_block_allocation_blocks_begin
                            .align_down(preferred_read_block_allocation_blocks_log2)
                {
                    break;
                }
            }

            let mut cur_auth_tree_data_block_any_unapplied_update_in_request_range = false;
            let mut cur_auth_tree_data_block_any_retained_with_unauthenticated_data = false;
            let mut cur_auth_tree_data_block_any_unauthenticated = false;
            for cur_allocation_block_index_in_auth_tree_data_block in
                0usize..1usize << auth_tree_data_block_allocation_blocks_log2
            {
                // Allocation blocks in the image header are not considered for the
                // authentication digest and are getting updated frequently,
                // i.e. at every transaction commit, because the root HMAC is
                // being stored there. Avoid unnecessarily authenticating
                // the possibly non-empty remainder of the last overlapping Authentication Tree
                // Data Block, if possible.
                let cur_allocation_block_is_in_image_header = cur_physical_auth_tree_data_block_allocation_blocks_begin
                    < image_header_end
                    && u64::from(image_header_end - cur_physical_auth_tree_data_block_allocation_blocks_begin)
                        > cur_allocation_block_index_in_auth_tree_data_block as u64;
                if cur_allocation_block_is_in_image_header {
                    continue;
                }

                let cur_allocation_block_state =
                    &cur_auth_tree_data_block_state[cur_allocation_block_index_in_auth_tree_data_block];
                if !matches!(
                    cur_allocation_block_state.staged_update,
                    AllocationBlockUpdateStagedUpdate::None | AllocationBlockUpdateStagedUpdate::FailedUpdate
                ) {
                    let cur_states_allocation_block_index = AuthTreeDataBlocksUpdateStatesAllocationBlockIndex::new(
                        cur_states_index,
                        cur_allocation_block_index_in_auth_tree_data_block,
                    );
                    let cur_allocation_block_is_in_request_range = *request_states_allocation_blocks_range.begin()
                        <= cur_states_allocation_block_index
                        && cur_states_allocation_block_index < *request_states_allocation_blocks_range.end();
                    if cur_allocation_block_is_in_request_range {
                        cur_auth_tree_data_block_any_unapplied_update_in_request_range |= true;
                    }
                }

                match &cur_allocation_block_state.nv_sync_state {
                    AllocationBlockUpdateNvSyncState::Unallocated(_unallocated_state) => (),
                    AllocationBlockUpdateNvSyncState::Allocated(allocated_state) => {
                        match allocated_state {
                            AllocationBlockUpdateNvSyncStateAllocated::Unmodified(unmodified_state) => {
                                // Missing data implies unauthenticated.
                                let is_unauthenticated = unmodified_state
                                    .cached_encrypted_data
                                    .as_ref()
                                    .map(|cached_encrypted_data| !cached_encrypted_data.is_authenticated())
                                    .unwrap_or(true);
                                cur_auth_tree_data_block_any_retained_with_unauthenticated_data |= matches!(
                                    cur_allocation_block_state.staged_update,
                                    AllocationBlockUpdateStagedUpdate::None
                                )
                                    & is_unauthenticated;
                                cur_auth_tree_data_block_any_unauthenticated |= is_unauthenticated;
                            }
                            AllocationBlockUpdateNvSyncStateAllocated::Modified(modified_state) => {
                                match modified_state {
                                    AllocationBlockUpdateNvSyncStateAllocatedModified::JournalClean {
                                        cached_encrypted_data,
                                    } => {
                                        // Missing data implies unauthenticated.
                                        let is_unauthenticated = cached_encrypted_data
                                            .as_ref()
                                            .map(|cached_encrypted_data| !cached_encrypted_data.is_authenticated())
                                            .unwrap_or(true);
                                        cur_auth_tree_data_block_any_retained_with_unauthenticated_data |= matches!(
                                            cur_allocation_block_state.staged_update,
                                            AllocationBlockUpdateStagedUpdate::None
                                        )
                                            & is_unauthenticated;
                                        cur_auth_tree_data_block_any_unauthenticated |= is_unauthenticated;
                                    }
                                    AllocationBlockUpdateNvSyncStateAllocatedModified::JournalDirty { .. } => {}
                                }
                            }
                        }
                    }
                }
            }
            let cur_auth_tree_data_block_needs_authentication =
                cur_auth_tree_data_block_any_unapplied_update_in_request_range
                    & cur_auth_tree_data_block_any_retained_with_unauthenticated_data;

            cur_states_index = cur_states_index.step();
            if cur_auth_tree_data_block_needs_authentication {
                subrange_needing_authentication_states_index_range_end = Some(cur_states_index);
            } else if subrange_needing_authentication_states_index_range_end.is_some() {
                if cur_auth_tree_data_block_any_unauthenticated {
                    // Something needing prepation has been found before, the current
                    // Authentication Tree Data Block does not need any
                    // authentication, and unnecessarily doing it
                    // nevertheless would incur a non-trivial cost. Stop for now.
                    break;
                }
            } else {
                // Nothing's been found before and the current Authentication Tree Data Block
                // doesn't need any preparation either. Advance the
                // remaining range's beginning past the current position.
                remaining_states_index_range =
                    AuthTreeDataBlocksUpdateStatesIndexRange::new(cur_states_index, remaining_states_index_range.end());
            }
            last_physical_auth_tree_data_block_allocation_blocks_begin =
                cur_physical_auth_tree_data_block_allocation_blocks_begin;
        }

        if let Some(subrange_needing_authentication_states_index_range_end) =
            subrange_needing_authentication_states_index_range_end
        {
            let subrange_states_index_range = AuthTreeDataBlocksUpdateStatesIndexRange::new(
                remaining_states_index_range.begin(),
                subrange_needing_authentication_states_index_range_end,
            );
            remaining_states_index_range =
                AuthTreeDataBlocksUpdateStatesIndexRange::new(cur_states_index, remaining_states_index_range.end());
            (Some(subrange_states_index_range), remaining_states_index_range)
        } else {
            debug_assert!(remaining_states_index_range.is_empty());
            (None, remaining_states_index_range)
        }
    }
}

impl<ST: sync_types::SyncTypes, C: chip::NvChip> CocoonFsSyncStateReadFuture<ST, C>
    for TransactionPrepareStagedUpdatesApplicationFuture<ST, C>
{
    type Output = Result<
        (
            Box<Transaction>,
            Option<AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets>,
            Result<(), NvFsError>,
        ),
        NvFsError,
    >;

    type AuxPollData<'a> = ();

    fn poll<'a>(
        self: pin::Pin<&mut Self>,
        fs_instance_sync_state: &mut CocoonFsSyncStateMemberRef<'_, ST, C>,
        _aux_poll_data: &mut Self::AuxPollData<'a>,
        cx: &mut core::task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let this = pin::Pin::into_inner(self);
        loop {
            match &mut this.fut_state {
                TransactionPrepareStagedUpdatesApplicationFutureState::Init { transaction } => {
                    let transaction = transaction.take().ok_or_else(|| nvfs_err_internal!())?;

                    let next_subrange_states_index_range;
                    (next_subrange_states_index_range, this.remaining_states_index_range) =
                        Self::determine_next_prepare_subrange(
                            &transaction,
                            fs_instance_sync_state.get_fs_ref().fs_config.image_header_end,
                            &this.request_states_allocation_blocks_index_range,
                            &this.remaining_states_index_range,
                        );
                    if let Some(next_subrange_states_index_range) = next_subrange_states_index_range {
                        let states = &transaction.auth_tree_data_blocks_update_states;
                        let request_states_index_range_offsets_transform =
                            AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsetsTransformToContaining::new(
                                &next_subrange_states_index_range,
                                &AuthTreeDataBlocksUpdateStatesIndexRange::from(
                                    this.request_states_allocation_blocks_index_range.clone(),
                                ),
                                states,
                            );
                        let remaining_states_index_range_offsets_transform =
                            AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsetsTransformToAfter::new(
                                &next_subrange_states_index_range,
                                &this.remaining_states_index_range,
                                states,
                            );
                        let read_authenticate_data_fut = TransactionReadAuthenticateDataFuture::new(
                            transaction,
                            &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::from(
                                next_subrange_states_index_range.clone(),
                            ),
                            false,
                            true,
                        );
                        this.fut_state =
                            TransactionPrepareStagedUpdatesApplicationFutureState::ReadAuthenticateSubrange {
                                request_states_index_range_offsets_transform,
                                remaining_states_index_range_offsets_transform,
                                read_authenticate_data_fut,
                            };
                    } else {
                        // All done.
                        return task::Poll::Ready(Ok((transaction, this.request_states_range_offsets.take(), Ok(()))));
                    }
                }
                TransactionPrepareStagedUpdatesApplicationFutureState::ReadAuthenticateSubrange {
                    request_states_index_range_offsets_transform,
                    remaining_states_index_range_offsets_transform,
                    read_authenticate_data_fut,
                } => {
                    let (fs_instance, _, fs_sync_state_alloc_bitmap, _, mut fs_sync_state_auth_tree, _, _, _) =
                        fs_instance_sync_state.fs_instance_and_destructure_borrow();
                    let (transaction, subrange_states_index_range_offsets, result) =
                        match TransactionReadAuthenticateDataFuture::poll(
                            pin::Pin::new(read_authenticate_data_fut),
                            &fs_instance.chip,
                            &fs_instance.fs_config,
                            fs_sync_state_alloc_bitmap,
                            &mut fs_sync_state_auth_tree,
                            cx,
                        ) {
                            task::Poll::Ready(Ok((transcation, subrange_states_index_range_offsets, result))) => {
                                (transcation, subrange_states_index_range_offsets, result)
                            }
                            task::Poll::Ready(Err(e)) => return task::Poll::Ready(Err(e)),
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    // Before evaluating the result and potentially return on error,
                    // apply all states array index offset adjustments to account for
                    // alignment insertions.
                    if let Some(subrange_states_index_range_offsets) = subrange_states_index_range_offsets {
                        let alignment_fillup_maybe_failed = if result.is_err() {
                            Some(&transaction.auth_tree_data_blocks_update_states)
                        } else {
                            None
                        };
                        let cur_request_states_index_range_offsets = request_states_index_range_offsets_transform
                            .apply(&subrange_states_index_range_offsets, alignment_fillup_maybe_failed);
                        this.request_states_allocation_blocks_index_range = this
                            .request_states_allocation_blocks_index_range
                            .apply_states_insertions_offsets(
                                cur_request_states_index_range_offsets.inserted_states_before_range_count,
                                cur_request_states_index_range_offsets.inserted_states_within_range_count,
                            );
                        this.request_states_range_offsets = this
                            .request_states_range_offsets
                            .as_ref()
                            .map(|prev| prev.accumulate(&cur_request_states_index_range_offsets))
                            .or(Some(cur_request_states_index_range_offsets));

                        let remaining_states_index_range_offsets =
                            remaining_states_index_range_offsets_transform.apply(&subrange_states_index_range_offsets);
                        this.remaining_states_index_range =
                            this.remaining_states_index_range.apply_states_insertions_offsets(
                                remaining_states_index_range_offsets.inserted_states_before_range_count,
                                remaining_states_index_range_offsets.inserted_states_within_range_count,
                            );
                    }

                    if let Err(e) = result {
                        this.fut_state = TransactionPrepareStagedUpdatesApplicationFutureState::Done;
                        return task::Poll::Ready(Ok((transaction, this.request_states_range_offsets.take(), Err(e))));
                    }

                    // Proceed to the next subrange, if any.
                    this.fut_state = TransactionPrepareStagedUpdatesApplicationFutureState::Init {
                        transaction: Some(transaction),
                    };
                }
                TransactionPrepareStagedUpdatesApplicationFutureState::Done => unreachable!(),
            }
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum TransactionPrepareStagedUpdatesApplicationFutureState<C: chip::NvChip> {
    Init {
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable
        // reference on Self.
        transaction: Option<Box<Transaction>>,
    },
    ReadAuthenticateSubrange {
        request_states_index_range_offsets_transform:
            AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsetsTransformToContaining,
        remaining_states_index_range_offsets_transform:
            AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsetsTransformToAfter,
        read_authenticate_data_fut: TransactionReadAuthenticateDataFuture<C>,
    },
    Done,
}
