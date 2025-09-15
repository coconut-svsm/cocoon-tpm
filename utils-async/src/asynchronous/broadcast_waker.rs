// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of a broadcast [`Waker`](task::Waker).
//!
//! A broadcast [`Waker`](task::Waker) instantiated from a
//! [`BroadcastWakerSubscriptions`] instance will broadcast any received wake
//! events to all previously subscribed wakers.
//!
//! # See also:
//!
//! * [`BroadcastWakerSubscriptions`]
extern crate alloc;

use crate::alloc::{SyncVec, SyncVecError};
use crate::sync_types::{self, Lock as _, WeakSyncRcPtr as _};
use core::{convert, marker, mem, num, ops, sync, task};
use ops::Deref as _;
use sync::atomic;

/// Error returned by
/// [`BroadcastWakerSubscriptions::subscribe()`](BroadcastWakerSubscriptions::subscribe).
#[derive(Clone, Copy, Debug)]
pub enum BroadcastWakerError {
    /// A memory allocation failed.
    MemoryAllocationFailure,
}

impl convert::From<SyncVecError> for BroadcastWakerError {
    fn from(value: SyncVecError) -> Self {
        match value {
            SyncVecError::MemoryAllocationFailure => BroadcastWakerError::MemoryAllocationFailure,
        }
    }
}

/// Subscriptions to a ([to be instantiated](Self::waker)) broadcast
/// [`Waker`](task::Waker).
///
/// A broadcast waker instantiated trough the BroadcastWakerSubscriptions
/// instance's [`waker()`](Self::waker) will collectively wake all previously
/// subscribed wakers.
///
/// To register a given [`Waker`](task::Waker) for receiving broadcast wakes, a
/// subscription must first get allocated through
/// [`subscribe()`](Self::subscribe). A waker may then get installed and
/// also, subsequently updated, for the subscription with
/// [`set_subscription_waker()`](Self::set_subscription_waker).
pub struct BroadcastWakerSubscriptions<ST: sync_types::SyncTypes> {
    /// The subscriptions.
    state: ST::Lock<BroadcastWakerSubscriptionsState>,
    /// Wake generation, incremented upon each broadcast wake event.
    wake_gen: atomic::AtomicU64,
}

impl<ST: sync_types::SyncTypes> BroadcastWakerSubscriptions<ST> {
    /// Create a new `BroadcastWakerSubscriptions` instance.
    ///
    /// Note that callers must wrap the returned instance in some
    /// [`SyncRcPtr`](sync_types::SyncRcPtr) to actually [create a
    /// waker](Self::waker) from it.
    pub fn new() -> Self {
        Self {
            state: ST::Lock::from(BroadcastWakerSubscriptionsState {
                subscribers: SyncVec::new(),
                last_subscription_id: 0,
            }),
            wake_gen: atomic::AtomicU64::new(0),
        }
    }

    /// Allocate a subscription.
    ///
    /// On success, a unique [`id`](BroadcastWakerSubscriptionId) identifying
    /// the allocated subscription will get returned. No
    /// [`Waker`](task::Waker) is installed at the newly
    /// allocated subscription yet. A [`Waker`](task::Waker) may get
    /// subsequently installed via
    /// [`set_subscription_waker()`](Self::set_subscription_waker).
    ///
    /// May sleep for a memory allocation, must not be called with any spinlock
    /// type [`Lock`](sync_types::Lock) held.
    pub fn subscribe(&self) -> Result<BroadcastWakerSubscriptionId, BroadcastWakerError> {
        let mut state_guard = self.state.lock();
        state_guard.last_subscription_id += 1;
        let subscription_id = num::NonZeroU64::new(state_guard.last_subscription_id).unwrap();

        let subscribers_lock =
            sync_types::LockForInner::<'_, _, _, BroadcastWakerSubscriptionsStateDerefInnerSubscribersTag>::from_outer(
                &self.state,
            );
        let mut subscribers_guard = sync_types::LockForInnerGuard::<
            '_,
            _,
            _,
            BroadcastWakerSubscriptionsStateDerefInnerSubscribersTag,
        >::from_outer(state_guard);
        let result;
        (subscribers_guard, result) = SyncVec::try_reserve_exact(&subscribers_lock, subscribers_guard, 1);
        if let Err(e) = result {
            return Err(BroadcastWakerError::from(e));
        }

        subscribers_guard.push((subscription_id, None));
        Ok(BroadcastWakerSubscriptionId { subscription_id })
    }

    /// Cancel a subscription.
    ///
    /// The associated subscription gets deallocated and the currently installed
    /// waker, if any, won't receive any further broadcast events. If
    /// `wake_remaining` is `true`, all other remaining subscribed
    /// [`Waker`](task::Waker)s will get woken.
    ///
    /// Does not sleep, may get called with some spinlock type
    /// [`Lock`](sync_types::Lock) held.
    ///
    /// # Arguments:
    ///
    /// * `subscription_id` - The subscription to terminate.
    /// * `wake_remaining` - If true, all remaining subscribed
    ///   [`Waker`](task::Waker)s will get woken.
    pub fn unsubscribe(
        &self,
        subscription_id: BroadcastWakerSubscriptionId,
        wake_remaining: bool,
    ) -> Option<Option<task::Waker>> {
        let mut state_guard = self.state.lock();
        let removed_waker = match state_guard
            .subscribers
            .iter()
            .position(|(entry_subscription_id, _)| subscription_id.subscription_id == *entry_subscription_id)
        {
            Some(index) => Some(state_guard.subscribers.remove(index).1),
            None => None,
        };

        if wake_remaining {
            self.wake_impl(&state_guard);
        }

        removed_waker
    }

    /// Update a subscription's associated [`Waker`](task::Waker).
    ///
    /// A subscription's associated [`Waker`](task::Waker) may get updated an
    /// arbitrary number of times, each time replacing the previously
    /// associated one, if any.
    ///
    /// Does not sleep, may get called with some spinlock type
    /// [`Lock`](sync_types::Lock) held.
    ///
    /// # Arguments:
    ///
    /// * `subscription_id` - The subscription whose associated
    ///   [`Waker`](task::Waker) to update.
    /// * `waker` - The [`Waker`](task::Waker) to associate with the
    ///   subscription identified by `subscription_id`.
    pub fn set_subscription_waker(&self, subscription_id: BroadcastWakerSubscriptionId, waker: task::Waker) {
        let mut state_guard = self.state.lock();
        if let Some(subscription_entry) = state_guard
            .subscribers
            .iter_mut()
            .find(|(entry_subscription_id, _)| subscription_id.subscription_id == *entry_subscription_id)
        {
            subscription_entry.1 = Some(waker);
        }
    }

    /// Obtain the wake generation, a number incremented upon each broadcast
    /// wake event.
    ///
    /// To be used for figuring whether a broadcast wake event has possibly
    /// happened between two points in time.
    ///
    /// # Memory ordering semantics:
    ///
    /// * A `wake_gen()` sequenced before a `set_subscriptions_waker()` from the
    ///   current thread, happening before a broadcast wakeup event issued from
    ///   any thread is guaranteed to read the old (or rather not the new)
    ///   generation value.
    /// * A `wake_gen()` sequenced after a `set_subscriptions_waker()` from the
    ///   current thread, happening after a broadcast wakeup event issued from
    ///   any thread is guaranteed to read the new (or rather not an old)
    ///   generation value.
    /// * A wakeup through
    ///   [`BroadcastWakerSubscriptions::waker()`](BroadcastWakerSubscriptions::waker)
    ///   has [`Release`](atomic::Ordering::Release) semantics on the wakeup
    ///   generation value whereas `wake_gen()` has
    ///   [`Acquire`](atomic::Ordering::Acquire) semantics. That means that
    ///   memory writes sequenced before the wake-up will happen before any
    ///   memory reads sequenced after a loading a current generation value from
    ///   any thread.
    /// * A `wake_gen()` sequenced after the load of some atomic variable, at
    ///   any memory order, including [`Relaxed`](atomic::Ordering::Relaxed),
    ///   reading a value stored by any thread, at any memory order, including
    ///   [`Relaxed`](atomic::Ordering::Relaxed), after a broadcast wake event
    ///   had been issued from that thread, is guaranteed to read the new (or
    ///   rather not an old) generation value. Note that this includes stores to
    ///   some common atomic variable issued in the course of invoking some
    ///   subscribed waker's callback from the thread issuing the broadcast
    ///   event. This means in particular that threads woken due to receiving a
    ///   broadcast event will read a recent generation value.
    ///
    /// **Provisions must be made as appropriate by users of the API in order to
    /// obtain any additional guarantees beyond the ones listed above!**
    pub fn wake_gen(&self) -> u64 {
        // Pairs with the fence in Self::wake_impl() (if called from a woken thread).
        // Make sure a woken thread sees a recent wake generation value.
        atomic::fence(atomic::Ordering::Acquire);
        // Reading the wake generation value has Acquire semantics.
        self.wake_gen.load(atomic::Ordering::Acquire)
    }

    /// Instantiate a broadcast waker which, when woken, would collectively wake
    /// all subscribed wakers.
    ///
    /// # Arguments:
    ///
    /// * `this` - A [`SyncRcPtrRef`](sync_types::SyncRcPtrRef) referring to the
    ///   [`SyncRcPtr`](sync_types::SyncRcPtr) the `BroadcastWakerSubscriptions`
    ///   had been wrapped in, c.f. [`Self::new()`](Self::new).
    pub fn waker<'a, SP: 'a + sync_types::SyncRcPtr<Self>, SR: sync_types::SyncRcPtrRef<'a, Self, SP>>(
        this: &SR,
    ) -> task::Waker {
        let raw_waker = broadcast_raw_waker_new(this);
        unsafe { task::Waker::from_raw(raw_waker) }
    }

    /// Wake all subscribed wakers.
    fn wake(&self) {
        self.wake_impl(&self.state.lock());
    }

    /// Broadcast a wake event.
    fn wake_impl(&self, state: &BroadcastWakerSubscriptionsState) {
        // Storing the generation value has Release semantics.
        self.wake_gen.fetch_add(1, atomic::Ordering::Release);
        // It is anticipated that waking would involve some sort of atomic store at
        // least. The fence ensures the woken threads doing a corresponding
        // Acquire would see the updated wake_gen (as well as any updated state
        // they'll be woken up for in the first place).
        atomic::fence(atomic::Ordering::Release);
        for subscriber in state.subscribers.iter() {
            if let Some(waker) = subscriber.1.as_ref() {
                waker.wake_by_ref()
            }
        }
    }
}

impl<ST: sync_types::SyncTypes> Default for BroadcastWakerSubscriptions<ST> {
    fn default() -> Self {
        Self::new()
    }
}

/// State of [`BroadcastWakerSubscriptions::state`].
struct BroadcastWakerSubscriptionsState {
    /// The subscriptions.
    ///
    /// Pair of (subscription id, installed [`Waker`](task::Waker), if any).
    subscribers: SyncVec<(num::NonZeroU64, Option<task::Waker>)>,
    /// Last allocated subscription id.
    last_subscription_id: u64,
}

/// [`DerefInnerByTag`](sync_types::DerefInnerByTag) `TAG` for derefencing
/// `BroadcastWakerSubscriptionsState::subscriptions`.
///
/// Enables presenting the [`Lock`](sync_types::Lock) of the
/// [`BroadcastWakerSubscriptions::state`] member as one
/// for the inner, contained [`BroadcastWakerSubscriptionsState::subscribers`]
/// via the [`LockForInner`](sync_types::LockForInner) mechanism.
struct BroadcastWakerSubscriptionsStateDerefInnerSubscribersTag;

impl sync_types::DerefInnerByTag<BroadcastWakerSubscriptionsStateDerefInnerSubscribersTag>
    for BroadcastWakerSubscriptionsState
{
    crate::impl_deref_inner_by_tag!(subscribers, SyncVec<(num::NonZeroU64, Option<task::Waker>)>);
}

impl sync_types::DerefMutInnerByTag<BroadcastWakerSubscriptionsStateDerefInnerSubscribersTag>
    for BroadcastWakerSubscriptionsState
{
    crate::impl_deref_mut_inner_by_tag!(subscribers);
}

/// ID identifying a subscription to a [`BroadcastWakerSubscriptions`] instance.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BroadcastWakerSubscriptionId {
    subscription_id: num::NonZeroU64,
}

/// Container struct for the ]`const RAW_WAKER_VTABLE`](Self::RAW_WAKER_VTABLE).
struct BroadcastRawWakerVTable<ST: sync_types::SyncTypes, SP: sync_types::SyncRcPtr<BroadcastWakerSubscriptions<ST>>> {
    _phantom: marker::PhantomData<fn() -> (*const ST, *const SP)>,
}

impl<ST: sync_types::SyncTypes, SP: sync_types::SyncRcPtr<BroadcastWakerSubscriptions<ST>>>
    BroadcastRawWakerVTable<ST, SP>
{
    /// [`RawWakerVTable`](task::RawWakerVTable) for a broadcast waker
    /// instantiated
    /// from [`BroadcastWakerSubscriptions::waker()`](BroadcastWakerSubscriptions::waker).
    const RAW_WAKER_VTABLE: task::RawWakerVTable = task::RawWakerVTable::new(
        broadcast_raw_waker_clone::<ST, SP>,
        broadcast_raw_waker_wake::<ST, SP>,
        broadcast_raw_waker_wake_by_ref::<ST, SP>,
        broadcast_raw_waker_drop::<ST, SP>,
    );
}

/// Construct a new [`RawWaker`](task::RawWaker) to get returned by
/// [`BroadcastWakerSubscriptions::waker()`](BroadcastWakerSubscriptions::waker).
fn broadcast_raw_waker_new<
    'a,
    ST: sync_types::SyncTypes,
    SP: 'a + sync_types::SyncRcPtr<BroadcastWakerSubscriptions<ST>>,
    SR: sync_types::SyncRcPtrRef<'a, BroadcastWakerSubscriptions<ST>, SP>,
>(
    subscriptions: &SR,
) -> task::RawWaker {
    let subscriptions = subscriptions.make_weak_clone();
    let data: *const BroadcastWakerSubscriptions<ST> = SP::WeakSyncRcPtr::into_raw(subscriptions);
    task::RawWaker::new(data as *const (), &BroadcastRawWakerVTable::<ST, SP>::RAW_WAKER_VTABLE)
}

/// `clone` entry of the [`BroadcastRawWakerVTable::RAW_WAKER_VTABLE`].
unsafe fn broadcast_raw_waker_clone<
    ST: sync_types::SyncTypes,
    SP: sync_types::SyncRcPtr<BroadcastWakerSubscriptions<ST>>,
>(
    data: *const (),
) -> task::RawWaker {
    let data = data as *const BroadcastWakerSubscriptions<ST>;
    let subscriptions = mem::ManuallyDrop::new(unsafe { SP::WeakSyncRcPtr::from_raw(data) });
    let data: *const BroadcastWakerSubscriptions<ST> = SP::WeakSyncRcPtr::into_raw(subscriptions.deref().clone());
    task::RawWaker::new(data as *const (), &BroadcastRawWakerVTable::<ST, SP>::RAW_WAKER_VTABLE)
}

/// `drop` entry of the [`BroadcastRawWakerVTable::RAW_WAKER_VTABLE`].
unsafe fn broadcast_raw_waker_drop<
    ST: sync_types::SyncTypes,
    SP: sync_types::SyncRcPtr<BroadcastWakerSubscriptions<ST>>,
>(
    data: *const (),
) {
    let data = data as *const BroadcastWakerSubscriptions<ST>;
    let subscriptions = unsafe { SP::WeakSyncRcPtr::from_raw(data) };
    drop(subscriptions)
}

/// `wake` entry of the [`BroadcastRawWakerVTable::RAW_WAKER_VTABLE`].
unsafe fn broadcast_raw_waker_wake<
    ST: sync_types::SyncTypes,
    SP: sync_types::SyncRcPtr<BroadcastWakerSubscriptions<ST>>,
>(
    data: *const (),
) {
    let data = data as *const BroadcastWakerSubscriptions<ST>;
    let subscriptions = unsafe { SP::WeakSyncRcPtr::from_raw(data) };
    if let Some(subscriptions) = subscriptions.upgrade() {
        subscriptions.deref().wake();
    }
}

/// `wake_by_ref` entry of the [`BroadcastRawWakerVTable::RAW_WAKER_VTABLE`].
unsafe fn broadcast_raw_waker_wake_by_ref<
    ST: sync_types::SyncTypes,
    SP: sync_types::SyncRcPtr<BroadcastWakerSubscriptions<ST>>,
>(
    data: *const (),
) {
    let data = data as *const BroadcastWakerSubscriptions<ST>;
    let subscriptions = mem::ManuallyDrop::new(unsafe { SP::WeakSyncRcPtr::from_raw(data) });
    if let Some(subscriptions) = subscriptions.upgrade() {
        subscriptions.deref().wake();
    }
}
