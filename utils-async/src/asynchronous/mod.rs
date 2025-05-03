// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Rust `async` related [`Future`] adaptors.

mod broadcast_waker;
use broadcast_waker::{BroadcastWakerError, BroadcastWakerSubscriptionId, BroadcastWakerSubscriptions};
