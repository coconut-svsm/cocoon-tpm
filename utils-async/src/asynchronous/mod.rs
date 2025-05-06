// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Rust `async` related [`Future`] adaptors.

mod broadcast_future;
pub use broadcast_future::{BroadcastFuture, BroadcastFutureError, BroadcastFutureSubscription};
mod broadcast_waker;
use broadcast_waker::{BroadcastWakerError, BroadcastWakerSubscriptionId, BroadcastWakerSubscriptions};
mod future_queue;
pub use future_queue::{EnqueuedFutureSubscription, FutureQueue, FutureQueueError, QueuedFuture};
mod rwlock;
pub use rwlock::{
    AsyncRwLock, AsyncRwLockError, AsyncRwLockReadFuture, AsyncRwLockReadGuard, AsyncRwLockReadGuardForInner,
    AsyncRwLockReadWeakGuard, AsyncRwLockReadWeakGuardForInner, AsyncRwLockWriteFuture, AsyncRwLockWriteGuard,
    AsyncRwLockWriteWeakGuard,
};
mod semaphore;
pub use semaphore::{
    AsyncSemaphore, AsyncSemaphoreError, AsyncSemaphoreExclusiveAllFuture, AsyncSemaphoreExclusiveAllGuard,
    AsyncSemaphoreExclusiveAllWeakGuard, AsyncSemaphoreLeasesFuture, AsyncSemaphoreLeasesGuard,
    AsyncSemaphoreLeasesWeakGuard,
};
