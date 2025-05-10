// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`TransactionReadAuthenticateDataFuture`].

extern crate alloc;
use alloc::boxed::Box;

use super::{
    Transaction,
    auth_tree_data_blocks_update_states::{
        AllocationBlockUpdateNvSyncState, AllocationBlockUpdateNvSyncStateAllocated,
        AllocationBlockUpdateNvSyncStateAllocatedModified, AllocationBlockUpdateNvSyncStateUnallocated,
        AllocationBlockUpdateNvSyncStateUnallocatedTargetState, AllocationBlockUpdateStagedUpdate,
        AuthTreeDataBlockUpdateState, AuthTreeDataBlocksUpdateStatesAllocationBlockIndex,
        AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets,
        AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsetsTransformToAfter,
        AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsetsTransformToContaining,
        AuthTreeDataBlocksUpdateStatesIndexRange,
    },
    read_missing_data::TransactionReadMissingDataFuture,
};
use crate::{
    chip,
    fs::{
        NvFsError,
        cocoonfs::{alloc_bitmap, auth_tree, fs::CocoonFsConfig, layout},
    },
    nvfs_err_internal,
    utils_async::sync_types,
};
use core::{pin, task};

/// Read and authenticate data from storage.
///
/// Read and authenticate all missing data from storage into a specified range's
/// [Allocation Blocks'](layout::ImageLayout::allocation_block_size_128b_log2)
/// associated
/// [`nv_sync_state`s](super::auth_tree_data_blocks_update_states::AllocationBlockUpdateState::nv_sync_state)
/// buffers as appropriate.
///
/// Note that the data loaded for a particular [Allocation
/// Block](layout::ImageLayout::allocation_block_size_128b_log2) might perhaps
/// have been superseded logically by
/// [`staged_update`s](super::auth_tree_data_blocks_update_states::AllocationBlockUpdateState::staged_update),
/// but could still be needed to form an authentication digest over the
/// containing [Authentication
/// Tree Data Block](layout::ImageLayout::auth_tree_data_block_allocation_blocks_log2).
pub(in super::super) struct TransactionReadAuthenticateDataFuture<C: chip::NvChip> {
    request_states_allocation_blocks_index_range: AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
    request_states_range_offsets: Option<AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets>,
    remaining_states_index_range: AuthTreeDataBlocksUpdateStatesIndexRange,
    remaining_auth_tree_data_blocks_head_skip_mask: alloc_bitmap::BitmapWord,
    fut_state: TransactionReadAuthenticateDataFutureState<C>,
    consider_staged_updates: bool,
    only_allocated: bool,
}

impl<C: chip::NvChip> TransactionReadAuthenticateDataFuture<C> {
    pub fn new(
        transaction: Box<Transaction>,
        request_states_allocation_blocks_index_range: &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        consider_staged_updates: bool,
        only_allocated: bool,
    ) -> Self {
        let remaining_states_index_range =
            AuthTreeDataBlocksUpdateStatesIndexRange::from(request_states_allocation_blocks_index_range.clone());
        let remaining_auth_tree_data_blocks_head_skip_mask =
            Self::create_remaining_auth_tree_data_blocks_head_skip_mask(&transaction, &remaining_states_index_range);
        Self {
            request_states_allocation_blocks_index_range: request_states_allocation_blocks_index_range.clone(),
            request_states_range_offsets: None,
            remaining_states_index_range,
            remaining_auth_tree_data_blocks_head_skip_mask,
            fut_state: TransactionReadAuthenticateDataFutureState::Init {
                transaction: Some(transaction),
            },
            consider_staged_updates,
            only_allocated,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn poll<ST: sync_types::SyncTypes>(
        self: pin::Pin<&mut Self>,
        chip: &C,
        fs_config: &CocoonFsConfig,
        fs_sync_state_alloc_bitmap: &alloc_bitmap::AllocBitmap,
        fs_sync_state_auth_tree: &mut auth_tree::AuthTreeRef<'_, ST>,
        cx: &mut core::task::Context<'_>,
    ) -> task::Poll<
        Result<
            (
                Box<Transaction>,
                Option<AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsets>,
                Result<(), NvFsError>,
            ),
            NvFsError,
        >,
    > {
        let this = pin::Pin::into_inner(self);
        loop {
            match &mut this.fut_state {
                TransactionReadAuthenticateDataFutureState::Init { transaction } => {
                    let transaction = transaction.take().ok_or_else(|| nvfs_err_internal!())?;
                    this.fut_state = TransactionReadAuthenticateDataFutureState::Done;

                    let next_subrange;
                    (
                        next_subrange,
                        this.remaining_states_index_range,
                        this.remaining_auth_tree_data_blocks_head_skip_mask,
                    ) = Self::determine_next_read_authenticate_subrange(
                        &transaction,
                        fs_config.image_header_end,
                        &this.request_states_allocation_blocks_index_range,
                        &this.remaining_states_index_range,
                        this.remaining_auth_tree_data_blocks_head_skip_mask,
                        this.consider_staged_updates,
                        this.only_allocated,
                    )?;

                    if let Some((
                        next_subrange_states_index_range,
                        next_subrange_auth_tree_data_blocks_skip_mask,
                        next_subrange_has_any_missing_data,
                    )) = next_subrange
                    {
                        // Update the skip mask for new states shifted "into reach" before
                        // potentially filling up missing states in the
                        // course of a read operation.
                        this.remaining_auth_tree_data_blocks_head_skip_mask |=
                            Self::create_remaining_auth_tree_data_blocks_head_skip_mask(
                                &transaction,
                                &this.remaining_states_index_range,
                            );
                        // Depending on whether or not the next subrange has any missing data,
                        // proceed either with a read or directly with the
                        // data authentication.
                        if next_subrange_has_any_missing_data {
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
                            let read_missing_data_fut = match TransactionReadMissingDataFuture::new(
                                transaction,
                                &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange::from(
                                    next_subrange_states_index_range.clone(),
                                ),
                            ) {
                                Ok(read_missing_data_fut) => read_missing_data_fut,
                                Err((transaction, e)) => {
                                    return task::Poll::Ready(Ok((
                                        transaction,
                                        this.request_states_range_offsets.take(),
                                        Err(e),
                                    )));
                                }
                            };
                            this.fut_state = TransactionReadAuthenticateDataFutureState::ReadMissingSubrangeData {
                                read_subrange_states_index_range: next_subrange_states_index_range,
                                read_subrange_auth_tree_data_blocks_skip_mask:
                                    next_subrange_auth_tree_data_blocks_skip_mask,
                                request_states_index_range_offsets_transform,
                                remaining_states_index_range_offsets_transform,
                                read_missing_data_fut,
                            };
                        } else {
                            this.fut_state = TransactionReadAuthenticateDataFutureState::AuthenticateSubrange {
                                transaction: Some(transaction),
                                auth_subrange_states_index_range: next_subrange_states_index_range,
                                auth_subrange_auth_tree_data_blocks_skip_mask:
                                    next_subrange_auth_tree_data_blocks_skip_mask,
                                last_physical_auth_tree_data_block: None,
                                auth_subrange_fut_state:
                                    TransactionReadAuthenticateDataFutureAuthenticateSubrangeState
                                        ::AuthenticateNextDataBlock { saved_auth_tree_data_block_index: None },
                            }
                        }
                    } else {
                        // All done.
                        return task::Poll::Ready(Ok((transaction, this.request_states_range_offsets.take(), Ok(()))));
                    }
                }
                TransactionReadAuthenticateDataFutureState::ReadMissingSubrangeData {
                    read_subrange_states_index_range,
                    read_subrange_auth_tree_data_blocks_skip_mask,
                    request_states_index_range_offsets_transform,
                    remaining_states_index_range_offsets_transform,
                    read_missing_data_fut,
                } => {
                    let (transaction, read_subrange_states_index_range_offsets, result) =
                        match TransactionReadMissingDataFuture::poll(
                            pin::Pin::new(read_missing_data_fut),
                            chip,
                            fs_sync_state_alloc_bitmap,
                            cx,
                        ) {
                            task::Poll::Ready(Ok((transcation, read_subrange_states_index_range_offsets, result))) => {
                                (transcation, read_subrange_states_index_range_offsets, result)
                            }
                            task::Poll::Ready(Err(e)) => {
                                return task::Poll::Ready(Err(e));
                            }
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    // Before evaluating the result and potentially return on error,
                    // apply all states array index offset adjustments to account for
                    // alignment insertions.
                    if let Some(read_subrange_states_index_range_offsets) = read_subrange_states_index_range_offsets {
                        *read_subrange_states_index_range = read_subrange_states_index_range
                            .apply_states_insertions_offsets(
                                read_subrange_states_index_range_offsets.inserted_states_before_range_count,
                                read_subrange_states_index_range_offsets.inserted_states_within_range_count,
                            );

                        let alignment_fillup_maybe_failed = if result.is_err() {
                            Some(&transaction.auth_tree_data_blocks_update_states)
                        } else {
                            None
                        };
                        let cur_request_states_index_range_offsets = request_states_index_range_offsets_transform
                            .apply(&read_subrange_states_index_range_offsets, alignment_fillup_maybe_failed);
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

                        let remaining_states_index_range_offsets = remaining_states_index_range_offsets_transform
                            .apply(&read_subrange_states_index_range_offsets);
                        this.remaining_states_index_range =
                            this.remaining_states_index_range.apply_states_insertions_offsets(
                                remaining_states_index_range_offsets.inserted_states_before_range_count,
                                remaining_states_index_range_offsets.inserted_states_within_range_count,
                            );
                    }

                    if let Err(e) = result {
                        return task::Poll::Ready(Ok((transaction, this.request_states_range_offsets.take(), Err(e))));
                    }

                    // After having read in any missing data within the current subrange, proceed
                    // with the authentication.
                    this.fut_state = TransactionReadAuthenticateDataFutureState::AuthenticateSubrange {
                        transaction: Some(transaction),
                        auth_subrange_states_index_range: read_subrange_states_index_range.clone(),
                        auth_subrange_auth_tree_data_blocks_skip_mask: *read_subrange_auth_tree_data_blocks_skip_mask,
                        last_physical_auth_tree_data_block: None,
                        auth_subrange_fut_state:
                            TransactionReadAuthenticateDataFutureAuthenticateSubrangeState::AuthenticateNextDataBlock {
                                saved_auth_tree_data_block_index: None,
                            },
                    };
                    // The future will get polled in the next loop iteration.
                }
                TransactionReadAuthenticateDataFutureState::AuthenticateSubrange {
                    transaction: fut_transaction,
                    auth_subrange_states_index_range,
                    auth_subrange_auth_tree_data_blocks_skip_mask,
                    last_physical_auth_tree_data_block,
                    auth_subrange_fut_state,
                } => {
                    let transaction = fut_transaction.as_mut().ok_or_else(|| nvfs_err_internal!())?;
                    let auth_tree_data_block_allocation_blocks_log2 =
                        transaction.auth_tree_data_block_allocation_blocks_log2;
                    let states = &mut transaction.auth_tree_data_blocks_update_states;

                    let mut last_physical_auth_tree_data_block = match last_physical_auth_tree_data_block {
                        Some(last_physical_auth_tree_data_block) => {
                            // Re-entered from the LoadAuthTreeLeafNode substate.
                            *last_physical_auth_tree_data_block
                        }
                        None => {
                            // First time state entry for the current subrange.
                            if !auth_subrange_states_index_range.is_empty() {
                                u64::from(
                                    states[auth_subrange_states_index_range.begin()]
                                        .get_target_allocation_blocks_begin(),
                                ) >> auth_tree_data_block_allocation_blocks_log2
                            } else {
                                // All of the current subrange authenticated, proceed to the
                                // next, if any.
                                this.fut_state = TransactionReadAuthenticateDataFutureState::Init {
                                    transaction: fut_transaction.take(),
                                };
                                continue;
                            }
                        }
                    };

                    while !auth_subrange_states_index_range.is_empty() {
                        match auth_subrange_fut_state {
                            TransactionReadAuthenticateDataFutureAuthenticateSubrangeState
                                ::AuthenticateNextDataBlock { saved_auth_tree_data_block_index } => {
                                let cur_states_index = auth_subrange_states_index_range.begin();
                                let cur_auth_tree_block_state = &mut states[cur_states_index];
                                let cur_physical_auth_tree_data_block_allocation_blocks_begin =
                                    cur_auth_tree_block_state.get_target_allocation_blocks_begin();

                                // Advance the skip bitmask to the current position and test it.
                                let cur_physical_auth_tree_data_block = u64::from(
                                    cur_physical_auth_tree_data_block_allocation_blocks_begin
                                ) >> auth_tree_data_block_allocation_blocks_log2;
                                debug_assert!(
                                    cur_physical_auth_tree_data_block - last_physical_auth_tree_data_block
                                        < alloc_bitmap::BitmapWord::BITS as u64
                                );
                                *auth_subrange_auth_tree_data_blocks_skip_mask >>=
                                    cur_physical_auth_tree_data_block - last_physical_auth_tree_data_block;
                                last_physical_auth_tree_data_block = cur_physical_auth_tree_data_block;
                                if *auth_subrange_auth_tree_data_blocks_skip_mask & 1 != 0 {
                                    *auth_subrange_states_index_range =
                                        AuthTreeDataBlocksUpdateStatesIndexRange::new(
                                            auth_subrange_states_index_range.begin().step(),
                                            auth_subrange_states_index_range.end()
                                        );
                                    continue;
                                }

                                let auth_tree_config = fs_sync_state_auth_tree.get_config();
                                let cur_auth_tree_data_block_index =
                                    saved_auth_tree_data_block_index.unwrap_or_else(|| {
                                        auth_tree_config.translate_physical_to_data_block_index(
                                            cur_physical_auth_tree_data_block_allocation_blocks_begin
                                        )
                                    });
                                if let Some(cur_expected_auth_tree_data_block_digest) =
                                        cur_auth_tree_block_state.get_auth_digest() {
                                    let image_header_end = fs_config.image_header_end;
                                    if let Err(e) = auth_tree_config.authenticate_data_block(
                                        cur_expected_auth_tree_data_block_digest,
                                        cur_auth_tree_data_block_index,
                                        cur_auth_tree_block_state.iter_auth_digest_allocation_blocks(image_header_end,
                                                                                                     false),
                                        image_header_end,
                                    ) {
                                        return task::Poll::Ready(Ok((
                                            fut_transaction.take().ok_or_else(|| nvfs_err_internal!())?,
                                            this.request_states_range_offsets.take(),
                                            Err(e),
                                        )));
                                    }

                                    Self::mark_auth_tree_block_allocation_blocks_states_authenticated(
                                        cur_auth_tree_block_state,
                                        image_header_end,
                                    );

                                    *auth_subrange_states_index_range =
                                        AuthTreeDataBlocksUpdateStatesIndexRange::new(
                                            auth_subrange_states_index_range.begin().step(),
                                            auth_subrange_states_index_range.end()
                                        );

                                } else {
                                    // Authenticate with the authentication tree.
                                    debug_assert!(!cur_auth_tree_block_state.iter_allocation_blocks().any(
                                        |allocate_block_update_state| {
                                            matches!(&allocate_block_update_state.nv_sync_state,
                                                     AllocationBlockUpdateNvSyncState::Allocated(
                                                         AllocationBlockUpdateNvSyncStateAllocated::Modified(_)
                                                     ) |
                                                     AllocationBlockUpdateNvSyncState::Unallocated(
                                                         AllocationBlockUpdateNvSyncStateUnallocated {
                                                             target_state:
                                                             AllocationBlockUpdateNvSyncStateUnallocatedTargetState
                                                                 ::Allocated,
                                                             ..
                                                         }))
                                        }));

                                    let auth_tree_leaf_node_id =
                                        auth_tree_config.covering_leaf_node_id(cur_auth_tree_data_block_index);
                                    let auth_tree_leaf_node_load_fut =
                                        auth_tree::AuthTreeNodeLoadFuture::new(auth_tree_leaf_node_id);
                                    *auth_subrange_fut_state =
                                        TransactionReadAuthenticateDataFutureAuthenticateSubrangeState
                                        ::LoadAuthTreeLeafNode {
                                            auth_tree_data_block_index: cur_auth_tree_data_block_index,
                                            auth_tree_leaf_node_load_fut,
                                        };
                                    continue;
                                }
                            },
                            TransactionReadAuthenticateDataFutureAuthenticateSubrangeState::LoadAuthTreeLeafNode {
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
                                    &mut auth_tree_node_cache, cx
                                ) {
                                    task::Poll::Ready(Ok(leaf_node)) => leaf_node,
                                    task::Poll::Ready(Err(e)) => {
                                        return task::Poll::Ready(Ok((
                                            fut_transaction.take().ok_or_else(|| nvfs_err_internal!())?,
                                            this.request_states_range_offsets.take(),
                                            Err(e),
                                        )));
                                    },
                                    task::Poll::Pending => return task::Poll::Pending,
                                };


                                let mut cur_auth_tree_data_block_index = *auth_tree_data_block_index;
                                let mut cur_states_index = auth_subrange_states_index_range.begin();
                                let mut authenticated_all_in_leaf_node_range = true;
                                loop {
                                    let image_header_end = fs_config.image_header_end;
                                    let cur_auth_tree_block_state = &mut states[cur_states_index];
                                    if let Err(e) = auth_tree_config.authenticate_data_block_from_tree(
                                        &leaf_node,
                                        cur_auth_tree_data_block_index,
                                        cur_auth_tree_block_state.iter_auth_digest_allocation_blocks(image_header_end,
                                                                                                     false),
                                        image_header_end,
                                    ) {
                                        return task::Poll::Ready(Ok((
                                            fut_transaction.take().ok_or_else(|| nvfs_err_internal!())?,
                                            this.request_states_range_offsets.take(),
                                            Err(e),
                                        )));
                                    }

                                    Self::mark_auth_tree_block_allocation_blocks_states_authenticated(
                                        cur_auth_tree_block_state,
                                        image_header_end,
                                    );

                                    // Set the corresponding bit in the skip mask so that the
                                    // current Authentication Tree Data Block would not get
                                    // authenticated (over and over) again in case the region cannot
                                    // get advanced past the leaf node's covered range.
                                    let cur_physical_auth_tree_data_block_allocation_blocks_begin =
                                        cur_auth_tree_block_state.get_target_allocation_blocks_begin();
                                    let cur_physical_auth_tree_data_block = u64::from(
                                        cur_physical_auth_tree_data_block_allocation_blocks_begin
                                    ) >> auth_tree_data_block_allocation_blocks_log2;
                                    debug_assert!(
                                        cur_physical_auth_tree_data_block - last_physical_auth_tree_data_block
                                            < alloc_bitmap::BitmapWord::BITS as u64
                                    );
                                    let skip_mask_pos =
                                        cur_physical_auth_tree_data_block - last_physical_auth_tree_data_block;
                                    *auth_subrange_auth_tree_data_blocks_skip_mask |= 1u64 << skip_mask_pos;

                                    // See if some more of the Authentication Tree Data Blocks in
                                    // the current request range can get authenticated with the
                                    // recently loaded authentication tree leaf node.
                                    cur_states_index = cur_states_index.step();
                                    // Skip over states having their correspondig bit set in the
                                    // skip bitmask, or which cannot get authenticated through the
                                    // Authentication Tree anymore..
                                    while cur_states_index != auth_subrange_states_index_range.end() {
                                        let cur_auth_tree_block_state = &mut states[cur_states_index];
                                        let cur_physical_auth_tree_data_block_allocation_blocks_begin =
                                            cur_auth_tree_block_state.get_target_allocation_blocks_begin();

                                        let cur_physical_auth_tree_data_block = u64::from(
                                            cur_physical_auth_tree_data_block_allocation_blocks_begin
                                        ) >> auth_tree_data_block_allocation_blocks_log2;
                                        debug_assert!(
                                            cur_physical_auth_tree_data_block - last_physical_auth_tree_data_block
                                                < alloc_bitmap::BitmapWord::BITS as u64
                                        );
                                        let skip_mask_pos =
                                            cur_physical_auth_tree_data_block - last_physical_auth_tree_data_block;
                                        if *auth_subrange_auth_tree_data_blocks_skip_mask &
                                            (1u64 << skip_mask_pos) == 0 {
                                            if cur_auth_tree_block_state.get_auth_digest().is_none() {
                                                break;
                                            } else {
                                                // If the Authentication Tree Data Block's
                                                // associated update state has an Authentication
                                                // Digest stored, then that is more current than
                                                // what is in the Authentication Tree and must be
                                                // used instead.
                                                authenticated_all_in_leaf_node_range = false;
                                            }
                                        }
                                        cur_states_index = cur_states_index.step();
                                    }

                                    if cur_states_index == auth_subrange_states_index_range.end() {
                                        break;
                                    }

                                    // Finally check whether the next Authentication Tree Data Block
                                    // needing authentication through the Authentication Tree is
                                    // still in the current leaf node's covered range.
                                    let cur_auth_tree_block_state = &mut states[cur_states_index];
                                    let cur_physical_auth_tree_data_block_allocation_blocks_begin =
                                        cur_auth_tree_block_state.get_target_allocation_blocks_begin();
                                    // Update for check below and also, it will be needed for the next iteration,
                                    // if any.
                                    cur_auth_tree_data_block_index =
                                        auth_tree_config.translate_physical_to_data_block_index(
                                            cur_physical_auth_tree_data_block_allocation_blocks_begin
                                        );
                                    let leaf_node_id = leaf_node.get_node_id();
                                    if cur_auth_tree_data_block_index < leaf_node_id.first_covered_data_block() ||
                                       cur_auth_tree_data_block_index > leaf_node_id.last_covered_data_block() {
                                            break;
                                       }
                                }

                                let (
                                    remaining_auth_subrange_states_index_range_begin,
                                    saved_auth_tree_data_block_index
                                ) = if authenticated_all_in_leaf_node_range {
                                    (cur_states_index, Some(cur_auth_tree_data_block_index))
                                } else {
                                    // Some states in the range
                                    // auth_subrange_states_index_range.begin()..cur_states_index
                                    // still need authentication.
                                    (auth_subrange_states_index_range.begin().step(), None)
                                };
                                *auth_subrange_states_index_range =
                                    AuthTreeDataBlocksUpdateStatesIndexRange::new(
                                        remaining_auth_subrange_states_index_range_begin,
                                        auth_subrange_states_index_range.end()
                                    );
                                *auth_subrange_fut_state =
                                    TransactionReadAuthenticateDataFutureAuthenticateSubrangeState
                                    ::AuthenticateNextDataBlock { saved_auth_tree_data_block_index };
                            },
                        }
                    }

                    // All of the current subrange authenticated, proceed to the next, if any.
                    this.fut_state = TransactionReadAuthenticateDataFutureState::Init {
                        transaction: fut_transaction.take(),
                    };
                }
                TransactionReadAuthenticateDataFutureState::Done => unreachable!(),
            }
        }
    }

    fn create_remaining_auth_tree_data_blocks_head_skip_mask(
        transaction: &Transaction,
        remaining_states_index_range: &AuthTreeDataBlocksUpdateStatesIndexRange,
    ) -> alloc_bitmap::BitmapWord {
        // When reading in missing data, gaps in the states array might get populated
        // for alignment in the course. This might introduce new states the
        // original requestor had not been interested in at all. In order to
        // avoid authenticating these even though not needed, maintain a bitmap
        // of states missing before submitting the read of missing data. Note that
        // this is only an optimization, as authenticating these additional, unrelated
        // states' data should be possible and not cause any harm with respect
        // to correctness.
        if remaining_states_index_range.is_empty() {
            return 0;
        }

        let auth_tree_data_block_allocation_blocks_log2 =
            transaction.auth_tree_data_block_allocation_blocks_log2 as u32;
        let states = &transaction.auth_tree_data_blocks_update_states;

        let mut skip_mask = 0;
        let mut i = 1;
        let mut last_physical_auth_tree_data_block =
            u64::from(states[remaining_states_index_range.begin()].get_target_allocation_blocks_begin())
                >> auth_tree_data_block_allocation_blocks_log2;
        let mut cur_states_index = remaining_states_index_range.begin().step();
        while i < alloc_bitmap::BitmapWord::BITS && cur_states_index != remaining_states_index_range.end() {
            let cur_physical_auth_tree_data_block =
                u64::from(states[cur_states_index].get_target_allocation_blocks_begin())
                    >> auth_tree_data_block_allocation_blocks_log2;
            let gap_auth_tree_data_blocks_count =
                cur_physical_auth_tree_data_block - last_physical_auth_tree_data_block - 1;
            last_physical_auth_tree_data_block = cur_physical_auth_tree_data_block;
            let gap_auth_tree_data_blocks_count =
                gap_auth_tree_data_blocks_count.min((alloc_bitmap::BitmapWord::BITS - i) as u64) as u32;
            debug_assert!(gap_auth_tree_data_blocks_count < alloc_bitmap::BitmapWord::BITS);
            skip_mask |= (((1 as alloc_bitmap::BitmapWord) << gap_auth_tree_data_blocks_count) - 1) << i;
            i += gap_auth_tree_data_blocks_count + 1;
            cur_states_index = cur_states_index.step();
        }

        skip_mask
    }

    #[allow(clippy::type_complexity)]
    fn determine_next_read_authenticate_subrange(
        transaction: &Transaction,
        image_header_end: layout::PhysicalAllocBlockIndex,
        request_states_allocation_blocks_range: &AuthTreeDataBlocksUpdateStatesAllocationBlocksIndexRange,
        remaining_states_index_range: &AuthTreeDataBlocksUpdateStatesIndexRange,
        mut remaining_auth_tree_data_blocks_head_skip_mask: alloc_bitmap::BitmapWord,
        consider_staged_updates: bool,
        only_allocated: bool,
    ) -> Result<
        (
            Option<(AuthTreeDataBlocksUpdateStatesIndexRange, alloc_bitmap::BitmapWord, bool)>,
            AuthTreeDataBlocksUpdateStatesIndexRange,
            alloc_bitmap::BitmapWord,
        ),
        NvFsError,
    > {
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
            return Ok((
                None,
                remaining_states_index_range,
                remaining_auth_tree_data_blocks_head_skip_mask,
            ));
        }

        let mut last_physical_auth_tree_data_block_allocation_blocks_begin =
            states[remaining_states_index_range.begin()].get_target_allocation_blocks_begin();
        let mut subrange_physical_auth_tree_data_blocks_begin =
            u64::from(last_physical_auth_tree_data_block_allocation_blocks_begin)
                >> auth_tree_data_block_allocation_blocks_log2;
        let mut subrange_auth_tree_data_blocks_skip_mask = 0;
        let mut subrange_has_any_missing_data = false;
        let mut cur_states_index = remaining_states_index_range.begin();
        while cur_states_index != remaining_states_index_range.end() {
            let cur_physical_auth_tree_data_block_allocation_blocks_begin =
                states[cur_states_index].get_target_allocation_blocks_begin();
            let cur_physical_auth_tree_data_block_index =
                u64::from(cur_physical_auth_tree_data_block_allocation_blocks_begin)
                    >> auth_tree_data_block_allocation_blocks_log2;
            // If there are any bits set in the skip mask, advance (shift) it so  that its
            // least significant bit corresponds to the current position and
            // examine that.
            if remaining_auth_tree_data_blocks_head_skip_mask != 0 {
                let last_physical_auth_tree_data_block_index =
                    u64::from(last_physical_auth_tree_data_block_allocation_blocks_begin)
                        >> auth_tree_data_block_allocation_blocks_log2;
                let auth_tree_data_blocks_distance_to_last =
                    cur_physical_auth_tree_data_block_index - last_physical_auth_tree_data_block_index;
                if auth_tree_data_blocks_distance_to_last < alloc_bitmap::BitmapWord::BITS as u64 {
                    remaining_auth_tree_data_blocks_head_skip_mask >>= auth_tree_data_blocks_distance_to_last;
                } else {
                    remaining_auth_tree_data_blocks_head_skip_mask = 0
                }
                let skip_cur_auth_tree_data_block = remaining_auth_tree_data_blocks_head_skip_mask & 1 != 0;
                if skip_cur_auth_tree_data_block {
                    // Clear the bit to perhaps make the whole bitmask zero and enable the next loop
                    // iteration to skip its evaluation then. It's also strictly needed to force
                    // remaining_auth_tree_data_blocks_head_skip_mask == 0 once the loop conditions
                    // becomes false (and thus, remaining_auth_tree_data_blocks_head_skip_mask won't
                    // get shifted anymore).
                    remaining_auth_tree_data_blocks_head_skip_mask ^= 1;
                    let next_states_index = cur_states_index.step();
                    debug_assert!(
                        next_states_index != remaining_states_index_range.end()
                            || remaining_auth_tree_data_blocks_head_skip_mask == 0
                    );
                    // If nothing's been found yet, advance the remaining range's beginning past
                    // the current position.
                    if cur_states_index == remaining_states_index_range.begin() {
                        remaining_states_index_range = AuthTreeDataBlocksUpdateStatesIndexRange::new(
                            next_states_index,
                            remaining_states_index_range.end(),
                        );
                    }
                    cur_states_index = next_states_index;
                    last_physical_auth_tree_data_block_allocation_blocks_begin =
                        cur_physical_auth_tree_data_block_allocation_blocks_begin;
                    continue;
                }
            }

            if cur_states_index != remaining_states_index_range.begin() {
                // Something's been found by now. Stop if the subrange's spanned target region
                // is getting too long to get tracked in the skip bitmask word.
                // To align with the backing storage's preferred IO block size,
                // stop also upon crossing a preferred IO block boundary.
                if cur_physical_auth_tree_data_block_index - subrange_physical_auth_tree_data_blocks_begin
                    >= alloc_bitmap::BitmapWord::BITS as u64
                    || cur_physical_auth_tree_data_block_allocation_blocks_begin
                        .align_down(preferred_read_block_allocation_blocks_log2)
                        != last_physical_auth_tree_data_block_allocation_blocks_begin
                            .align_down(preferred_read_block_allocation_blocks_log2)
                {
                    break;
                }
            } else {
                // Nothing's been found yet, update the subrange's skip mask (as inherited from
                // the remaining range), accordingly to make it correspond to
                // the current position.
                subrange_auth_tree_data_blocks_skip_mask = remaining_auth_tree_data_blocks_head_skip_mask;
                // Also, move the subrange's beginning (in units of Authentication Tree Data
                // Blocks) ahead accordingly.
                subrange_physical_auth_tree_data_blocks_begin = cur_physical_auth_tree_data_block_index;
            }

            // Now examine the current Authentication Tree Data Block's NV sync state.
            // While iterating over the individual Allocation blocks, keep track of:
            // - Whether data needed for authenticating anything within the current
            //   Authentication Tree Data block's contents is missing.
            let mut cur_auth_tree_data_block_any_missing_auth_data = false;
            // - Whether unallocated (but initialized) data within request range is missing.
            let mut cur_auth_tree_data_block_any_unallocated_missing_req_data = false;
            // - Whether any allocated data within request range is unauthenticated (or
            //   missing alltogether).
            let mut cur_auth_tree_data_block_any_unauthenticated_req_data = false;
            // - Whether or not any Allocation Block is in Modified Clean state, i.e. its
            //   data exists in a Journal Staging Copy. Used only for consistency checking
            //   of the internal state.
            let mut cur_auth_tree_data_block_any_modified_journal_clean = false;
            // - Whether or not any Allocation Block is in Modified Dirty state, i.e. its
            //   data exists exclusively in memory. Used only for consistency checking of
            //   the internal state.
            let mut cur_auth_tree_data_block_any_modified_journal_dirty = false;
            let cur_auth_tree_data_block_state = &states[cur_states_index];
            for cur_allocation_block_index_in_auth_tree_data_block in
                0usize..1usize << auth_tree_data_block_allocation_blocks_log2
            {
                let cur_states_allocation_block_index = AuthTreeDataBlocksUpdateStatesAllocationBlockIndex::new(
                    cur_states_index,
                    cur_allocation_block_index_in_auth_tree_data_block,
                );
                let cur_allocation_block_is_in_request_range = *request_states_allocation_blocks_range.begin()
                    <= cur_states_allocation_block_index
                    && cur_states_allocation_block_index < *request_states_allocation_blocks_range.end();
                let cur_allocation_block_state =
                    &cur_auth_tree_data_block_state[cur_allocation_block_index_in_auth_tree_data_block];
                if consider_staged_updates
                    && !matches!(
                        cur_allocation_block_state.staged_update,
                        AllocationBlockUpdateStagedUpdate::None
                    )
                {
                    // Even though the staged update takes precedence, the data from storage
                    // superseded by it could still be needed for authenticating other Allocation
                    // Blocks from the same containing Authentication Tree Data Block.
                    cur_auth_tree_data_block_any_missing_auth_data |= match &cur_allocation_block_state.nv_sync_state {
                        AllocationBlockUpdateNvSyncState::Unallocated(..) => false,
                        AllocationBlockUpdateNvSyncState::Allocated(allocated_state) => {
                            match allocated_state {
                                AllocationBlockUpdateNvSyncStateAllocated::Unmodified(unmodified_state) => {
                                    unmodified_state.cached_encrypted_data.is_none()
                                }
                                AllocationBlockUpdateNvSyncStateAllocated::Modified(modified_state) => {
                                    match modified_state {
                                        AllocationBlockUpdateNvSyncStateAllocatedModified::JournalClean {
                                            cached_encrypted_data,
                                        } => cached_encrypted_data.is_none(),
                                        AllocationBlockUpdateNvSyncStateAllocatedModified::JournalDirty { .. } => {
                                            // JournalDirty states always have the
                                            // data loaded in memory.
                                            false
                                        }
                                    }
                                }
                            }
                        }
                    };

                    match &cur_allocation_block_state.staged_update {
                        AllocationBlockUpdateStagedUpdate::None => {
                            // Unreachable, as per the if-condition above.
                            debug_assert!(false);
                        }
                        AllocationBlockUpdateStagedUpdate::Update { .. } => {
                            // Encrypted data staged to get applied is
                            // considered present and
                            // authenticated, as it's not coming from extern.
                        }
                        AllocationBlockUpdateStagedUpdate::Deallocate => {
                            // If a request for !only_allocated, attempt to repurpose any
                            // essentially random data previously at that location.
                            cur_auth_tree_data_block_any_unallocated_missing_req_data |=
                                cur_allocation_block_is_in_request_range
                                    && match &cur_allocation_block_state.nv_sync_state {
                                        AllocationBlockUpdateNvSyncState::Unallocated(unallocated_state) => {
                                            unallocated_state.random_fillup.is_none()
                                                && (unallocated_state.target_state.is_initialized()
                                                    || unallocated_state.copied_to_journal)
                                        }
                                        AllocationBlockUpdateNvSyncState::Allocated(allocated_state) => {
                                            match allocated_state {
                                                AllocationBlockUpdateNvSyncStateAllocated::Unmodified(
                                                    unmodified_state,
                                                ) => unmodified_state.cached_encrypted_data.is_none(),
                                                AllocationBlockUpdateNvSyncStateAllocated::Modified(modified_state) => {
                                                    match modified_state {
                                                        AllocationBlockUpdateNvSyncStateAllocatedModified
                                                            ::JournalClean {
                                                            cached_encrypted_data,
                                                        } => {
                                                            cached_encrypted_data.is_none()
                                                        },
                                                        AllocationBlockUpdateNvSyncStateAllocatedModified
                                                            ::JournalDirty { .. } => {
                                                            // JournalDirty states always have the
                                                            // data loaded in memory.
                                                            false
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    };
                        }
                        AllocationBlockUpdateStagedUpdate::FailedUpdate => {
                            // Attempt to read from a staged update in indeterminate state.
                            if cur_allocation_block_is_in_request_range {
                                return Err(NvFsError::FailedDataUpdateRead);
                            }
                        }
                    }
                } else {
                    match &cur_allocation_block_state.nv_sync_state {
                        AllocationBlockUpdateNvSyncState::Unallocated(unallocated_state) => {
                            if unallocated_state.target_state.is_initialized() || unallocated_state.copied_to_journal {
                                cur_auth_tree_data_block_any_unallocated_missing_req_data |=
                                    unallocated_state.random_fillup.is_none()
                                        && cur_allocation_block_is_in_request_range;
                            }
                        }
                        AllocationBlockUpdateNvSyncState::Allocated(allocated_state) => {
                            match allocated_state {
                                AllocationBlockUpdateNvSyncStateAllocated::Unmodified(unmodified_state) => {
                                    if let Some(cached_encrypted_data) = unmodified_state.cached_encrypted_data.as_ref()
                                    {
                                        cur_auth_tree_data_block_any_unauthenticated_req_data |=
                                            cur_allocation_block_is_in_request_range
                                                & !cached_encrypted_data.is_authenticated();
                                    } else {
                                        // Missing implies unauthenticated.
                                        cur_auth_tree_data_block_any_unauthenticated_req_data |=
                                            cur_allocation_block_is_in_request_range;
                                        cur_auth_tree_data_block_any_missing_auth_data = true;
                                    }
                                }
                                AllocationBlockUpdateNvSyncStateAllocated::Modified(modified_state) => {
                                    match modified_state {
                                        AllocationBlockUpdateNvSyncStateAllocatedModified::JournalClean {
                                            cached_encrypted_data,
                                        } => {
                                            // Allocation Blocks in the image header are not getting
                                            // authenticated and updates thereto might have been
                                            // flushed to the journal without computing and
                                            // memorizing a containing Authentication Tree Data
                                            // Block's
                                            // AuthTreeDataBlockUpdateState::auth_digest. Don't
                                            // consider them in the internal state consistency check
                                            // below.
                                            let cur_allocation_block_is_in_image_header =
                                                cur_physical_auth_tree_data_block_allocation_blocks_begin
                                                    < image_header_end
                                                    && u64::from(
                                                        image_header_end
                                                            - cur_physical_auth_tree_data_block_allocation_blocks_begin,
                                                    ) > cur_allocation_block_index_in_auth_tree_data_block as u64;
                                            if let Some(cached_encrypted_data) = cached_encrypted_data.as_ref() {
                                                cur_auth_tree_data_block_any_unauthenticated_req_data |=
                                                    cur_allocation_block_is_in_request_range
                                                        & !cached_encrypted_data.is_authenticated();
                                            } else {
                                                // Missing implies unauthenticated.
                                                cur_auth_tree_data_block_any_unauthenticated_req_data |=
                                                    cur_allocation_block_is_in_request_range;
                                                cur_auth_tree_data_block_any_missing_auth_data = true;
                                                debug_assert!(
                                                    cur_allocation_block_is_in_image_header
                                                        || cur_auth_tree_data_block_state.get_auth_digest().is_some()
                                                );
                                            }
                                            cur_auth_tree_data_block_any_modified_journal_clean |=
                                                !cur_allocation_block_is_in_image_header;
                                        }
                                        AllocationBlockUpdateNvSyncStateAllocatedModified::JournalDirty { .. } => {
                                            // Allocation Blocks in the image header are not getting
                                            // authenticated and updates thereto migh have been
                                            // flushed to the journal without computing and
                                            // memorizing a containing Authentication Tree Data
                                            // Block's
                                            // AuthTreeDataBlockUpdateState::auth_digest. Don't
                                            // consider them in the internal state consistency check
                                            // below.
                                            let cur_allocation_block_is_in_image_header =
                                                cur_physical_auth_tree_data_block_allocation_blocks_begin
                                                    < image_header_end
                                                    && u64::from(
                                                        image_header_end
                                                            - cur_physical_auth_tree_data_block_allocation_blocks_begin,
                                                    ) > cur_allocation_block_index_in_auth_tree_data_block as u64;
                                            cur_auth_tree_data_block_any_modified_journal_dirty |=
                                                !cur_allocation_block_is_in_image_header;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // If there's any modification as well as any unauthenticated Allocation Block
            // (possibly a different, unmodified one), then it must be possible
            // to authenticate by means of an accordingly updated HMAC. (Note
            // that it would in principle still be possible to authenticate if
            // the unauthenticated Allocation Blocks happened to be all unmodified,
            // but it's not supported because it's probably not worth the additional
            // complexity.)
            if cur_auth_tree_data_block_any_unauthenticated_req_data
                && (cur_auth_tree_data_block_any_modified_journal_clean
                    || cur_auth_tree_data_block_any_modified_journal_dirty)
                && cur_auth_tree_data_block_state.get_auth_digest().is_none()
            {
                return Err(nvfs_err_internal!());
            }

            let cur_auth_tree_data_block_has_any_missing_data = (cur_auth_tree_data_block_any_unauthenticated_req_data
                && cur_auth_tree_data_block_any_missing_auth_data)
                || (cur_auth_tree_data_block_any_unallocated_missing_req_data && !only_allocated);

            // If no unauthenticated data, i.e. everything within the current Authentication
            // Tree Block is either in unallocated state or everything is
            // authenticated, set a bit to skip the authentication alltogether
            // at a later stage. Assume that the current Authentication Tree
            // Data Block will be contained in the subrange to be returned, i.e.
            // it's located somewhere after another one which does need some processing.
            // Note that in the latter case, i.e. that everything in the current
            // Authentication Tree Block is in authenticated state already,
            // which implies the data is there in the first place, all of the
            // subrange returned will have its data loaded as well, c.f. the stop
            // condition upon different requirements with respect to data reads below. This
            // implies that the caller would not attempt to read any data, jump
            // right ahead to the authentication phase and efficiently skip over
            // the current block as per the bitmask. Thus, there will be no harm
            // performance-wise in potentially returning a subrange comprising a
            // tail of Authentication Tree Data Blocks not needing any
            // processing at all.
            if !cur_auth_tree_data_block_any_unauthenticated_req_data {
                subrange_auth_tree_data_blocks_skip_mask |= (1 as alloc_bitmap::BitmapWord)
                    << (cur_physical_auth_tree_data_block_index - subrange_physical_auth_tree_data_blocks_begin)
            }

            let next_states_index = cur_states_index.step();
            debug_assert!(
                next_states_index != remaining_states_index_range.end()
                    || remaining_auth_tree_data_blocks_head_skip_mask == 0
            );
            if cur_states_index != remaining_states_index_range.begin() {
                // Already found something to process before. If the requirements with respect
                // to data reads are different, stop.
                if cur_auth_tree_data_block_has_any_missing_data ^ subrange_has_any_missing_data {
                    break;
                }
            } else {
                // Nothing's been found so far, if the current Authentication Tree Data Block
                // doesn't need any handling either, move the remaining subrange's beginning
                // past it.
                if !cur_auth_tree_data_block_any_unauthenticated_req_data
                    && !cur_auth_tree_data_block_has_any_missing_data
                {
                    remaining_states_index_range = AuthTreeDataBlocksUpdateStatesIndexRange::new(
                        next_states_index,
                        remaining_states_index_range.end(),
                    );
                }
            }
            subrange_has_any_missing_data |= cur_auth_tree_data_block_has_any_missing_data;
            cur_states_index = next_states_index;
            last_physical_auth_tree_data_block_allocation_blocks_begin =
                cur_physical_auth_tree_data_block_allocation_blocks_begin;
        }

        debug_assert!(!remaining_states_index_range.is_empty() || remaining_auth_tree_data_blocks_head_skip_mask == 0);
        if cur_states_index != remaining_states_index_range.begin() {
            let subrange_states_index_range =
                AuthTreeDataBlocksUpdateStatesIndexRange::new(remaining_states_index_range.begin(), cur_states_index);
            remaining_states_index_range =
                AuthTreeDataBlocksUpdateStatesIndexRange::new(cur_states_index, remaining_states_index_range.end());
            Ok((
                Some((
                    subrange_states_index_range,
                    subrange_auth_tree_data_blocks_skip_mask,
                    subrange_has_any_missing_data,
                )),
                remaining_states_index_range,
                remaining_auth_tree_data_blocks_head_skip_mask,
            ))
        } else {
            debug_assert!(remaining_states_index_range.is_empty());
            Ok((
                None,
                remaining_states_index_range,
                remaining_auth_tree_data_blocks_head_skip_mask,
            ))
        }
    }

    fn mark_auth_tree_block_allocation_blocks_states_authenticated(
        state: &mut AuthTreeDataBlockUpdateState,
        image_header_end: layout::PhysicalAllocBlockIndex,
    ) {
        // The Allocation Blocks from the image header are not included in the
        // containing Authentication Tree Data Block's digest content-wise.
        // Don't mark those as authenticated then.
        let auth_tree_data_block_allocation_blocks_begin = state.get_target_allocation_blocks_begin();
        let skip_count = if auth_tree_data_block_allocation_blocks_begin >= image_header_end {
            0usize
        } else {
            // The number of Allocation Blocks in an Authentication Tree Data Block always
            // fits an usize.
            usize::try_from(u64::from(image_header_end - state.get_target_allocation_blocks_begin()))
                .unwrap_or(usize::MAX)
        };
        for allocation_block_state in state.iter_allocation_blocks_mut().skip(skip_count) {
            match &mut allocation_block_state.nv_sync_state {
                AllocationBlockUpdateNvSyncState::Unallocated(_) => (),
                AllocationBlockUpdateNvSyncState::Allocated(allocated_state) => match allocated_state {
                    AllocationBlockUpdateNvSyncStateAllocated::Unmodified(unmodified_state) => {
                        if let Some(cached_encrypted_data) = &mut unmodified_state.cached_encrypted_data {
                            cached_encrypted_data.set_authenticated();
                        }
                    }
                    AllocationBlockUpdateNvSyncStateAllocated::Modified(modified_state) => match modified_state {
                        AllocationBlockUpdateNvSyncStateAllocatedModified::JournalDirty { .. } => (),
                        AllocationBlockUpdateNvSyncStateAllocatedModified::JournalClean { cached_encrypted_data } => {
                            if let Some(cached_encrypted_data) = cached_encrypted_data {
                                cached_encrypted_data.set_authenticated();
                            }
                        }
                    },
                },
            }
        }
    }
}

enum TransactionReadAuthenticateDataFutureState<C: chip::NvChip> {
    Init {
        transaction: Option<Box<Transaction>>,
    },
    ReadMissingSubrangeData {
        read_subrange_states_index_range: AuthTreeDataBlocksUpdateStatesIndexRange,
        read_subrange_auth_tree_data_blocks_skip_mask: alloc_bitmap::BitmapWord,
        request_states_index_range_offsets_transform:
            AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsetsTransformToContaining,
        remaining_states_index_range_offsets_transform:
            AuthTreeDataBlocksUpdateStatesFillAlignmentGapsRangeOffsetsTransformToAfter,
        read_missing_data_fut: TransactionReadMissingDataFuture<C>,
    },
    AuthenticateSubrange {
        transaction: Option<Box<Transaction>>,
        auth_subrange_states_index_range: AuthTreeDataBlocksUpdateStatesIndexRange,
        auth_subrange_auth_tree_data_blocks_skip_mask: alloc_bitmap::BitmapWord,
        last_physical_auth_tree_data_block: Option<u64>,
        auth_subrange_fut_state: TransactionReadAuthenticateDataFutureAuthenticateSubrangeState<C>,
    },
    Done,
}

enum TransactionReadAuthenticateDataFutureAuthenticateSubrangeState<C: chip::NvChip> {
    AuthenticateNextDataBlock {
        saved_auth_tree_data_block_index: Option<auth_tree::AuthTreeDataBlockIndex>,
    },
    LoadAuthTreeLeafNode {
        auth_tree_data_block_index: auth_tree::AuthTreeDataBlockIndex,
        auth_tree_leaf_node_load_fut: auth_tree::AuthTreeNodeLoadFuture<C>,
    },
}
