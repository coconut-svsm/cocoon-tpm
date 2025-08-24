// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`BroadcastFuture`].

extern crate alloc;
use super::{BroadcastWakerError, BroadcastWakerSubscriptionId, BroadcastWakerSubscriptions};
use crate::sync_types::{self, Lock as _, SyncRcPtrRef};
use core::{cell, convert, future, marker, pin, sync::atomic, task};

#[derive(Clone, Copy, Debug)]
/// Error returned by
/// [`BroadcastFuture::subscribe`](BroadcastFuture::subscribe).
pub enum BroadcastFutureError {
    /// A memory allocation failed.
    MemoryAllocationFailure,
}

impl convert::From<BroadcastWakerError> for BroadcastFutureError {
    fn from(value: BroadcastWakerError) -> Self {
        match value {
            BroadcastWakerError::MemoryAllocationFailure => BroadcastFutureError::MemoryAllocationFailure,
        }
    }
}

/// [`Future`]-like type to get wrapped in a [`BroadcastFuture`].
///
/// The standard Rust [`Future::poll()`](future::Future::poll) signature is
/// extended to enable access to some auxiliary data provided through **any**
/// `BroadcastFutureSubscription::poll()`](BroadcastFutureSubscription::poll).
pub trait BroadcastedFuture {
    /// The type of value produced on completion.
    type Output: Clone + marker::Send;

    /// Type of the auxiliary argument provided to [`poll()`](Self::poll).
    type AuxPollData<'a>;

    /// The extended `poll()` being provided access to some `aux_data`.
    ///
    /// # Arguments:
    ///
    /// * `aux_data` - Auxiliary data passed onwards from **some unspecified**
    ///   [`BroadcastFutureSubscription::poll()`](BroadcastFutureSubscription::poll).
    /// * `cx` - Asynchronous task context providing access to a
    ///   [`Waker`](task::Waker).
    fn poll<'a>(
        self: pin::Pin<&mut Self>,
        aux_data: &mut Self::AuxPollData<'a>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output>;
}

/// Future adaptor enabling collective polling on a wrapped
/// [`BroadcastedFuture`], replicating the result to all subscribers.
///
/// A `BroadcastFuture` wraps a given inner [`BrodacastedFuture`] and allows for
/// collective polling from one or more subscribers instantiated via
/// [`subscribe()`](Self::subscribe).
///
/// Once the inner future completes, the result will be made available
/// ("broadcasted") as a [`Clone`] to all subscribers upon their respective next
/// `poll()` invocation, if any. This holds true even for subscriptions made
/// after the inner [`Future`] has completed.
///
/// The `BroadcastFuture` implementation is robust against threads "loosing
/// interest", e.g. abandoned tasks never polled again: whenever at least one
/// subscribed thread is still getting polled, wakeups always do get processed
/// and the wrapped [`BroadcastedFuture`] is guaranteed to make progress. This
/// comes at the cost of an (intentional) thundering-herd style wake-up scheme:
/// whenever the inner [`BroadcastedFuture`] is woken, the wake-up gets
/// broadcasted to all subscribers.
pub struct BroadcastFuture<ST: sync_types::SyncTypes, F: BroadcastedFuture> {
    /// The subscriptions to the `BroadcastFuture`.
    subscriptions: BroadcastWakerSubscriptions<ST>,
    /// Concurrent polling state for the `inner_fut`. Used to ensure only
    /// one thread is polling the `inner_fut` at a time.
    polling_state: ST::Lock<BroadcastFuturePollingState>,
    /// The inner [`BroadcastedFuture`].
    inner_fut: cell::UnsafeCell<BroadcastFutureInnerFuture<F>>,
}

unsafe impl<ST: sync_types::SyncTypes, F: BroadcastedFuture> marker::Send for BroadcastFuture<ST, F> {}

unsafe impl<ST: sync_types::SyncTypes, F: BroadcastedFuture> marker::Sync for BroadcastFuture<ST, F> {}

impl<ST: sync_types::SyncTypes, F: BroadcastedFuture> BroadcastFuture<ST, F> {
    /// Wrap a given [`BroadcastedFuture`] in a `BroadcastFuture`.
    ///
    /// Note that the caller is supposed to move the returned `BroadcastFuture`
    /// into a pinned [`SyncRcPtr`](sync_types::SyncRcPtr) -- the other parts of
    /// the API expect that.
    ///
    /// # Arguments:
    ///
    /// * `inner` - The [`BroadcastedFuture`] to get wrapped, collectively
    ///   polled and whose result is to get eventually broadcasted to all
    ///   [subscriptions](Self::subscribe).
    pub fn new(inner: F) -> Self {
        Self {
            subscriptions: BroadcastWakerSubscriptions::new(),
            polling_state: ST::Lock::from(BroadcastFuturePollingState::Idle),
            inner_fut: cell::UnsafeCell::new(BroadcastFutureInnerFuture::Pending { inner }),
        }
    }

    /// Unwrap the inner future.
    ///
    /// Returns the inner [`BroadcastedFuture`] in case it's still
    /// [`Pending`](task::Poll::Pending), `None` otherwise.
    pub fn into_inner(self) -> Option<F> {
        match self.inner_fut.into_inner() {
            BroadcastFutureInnerFuture::Pending { inner } => Some(inner),
            BroadcastFutureInnerFuture::Ready(_) => None,
        }
    }

    /// Subscribe to the given `BroadcastFuture` instance.
    ///
    /// On success, a [`BroadcastFutureSubscription`] [`BrodacastedFuture`] will
    /// get returned, which can then subsequently get polled to drive
    /// progress on the wrapped future forward and to eventually obtain the
    /// broadcasted result.
    ///
    /// # Errors:
    ///
    /// * [`BroadcastFutureError::MemoryAllocationFailure`] - Memory allocation
    ///   failure.
    pub fn subscribe<'a, BP: 'a + sync_types::SyncRcPtr<Self>, BR: sync_types::SyncRcPtrRef<'a, Self, BP>>(
        this: pin::Pin<BR>,
    ) -> Result<BroadcastFutureSubscription<ST, F, BP>, BroadcastFutureError> {
        let subscription_id = this.subscriptions.subscribe()?;
        let broadcast_future = this.make_clone();
        Ok(BroadcastFutureSubscription::new(broadcast_future, subscription_id))
    }

    /// Cancel a subscription.
    ///
    /// # Arguments:
    ///
    /// * subscription_id` - The id associated with the subscription.
    fn cancel_subscription(&self, subscription_id: BroadcastWakerSubscriptionId) {
        self.subscriptions.unsubscribe(subscription_id, false);
    }

    /// Poll on behalf of a subscription.
    ///
    /// # Arguments:
    ///
    /// * `this` - A [`Pin<SyncRcPtrRef<Self>>`](sync_types::SyncRcPtrRef)
    ///   referring to the [`Pin<SyncRcPtr<Self>>`](sync_types::SyncRcPtr) the
    ///   `BroadcastFuture` had been wrapped in, c.f.
    ///   [`Self::new()`](Self::new).
    /// * subscription_id` - The id associated with the subscription on whose
    ///   behalf to poll from.
    /// * `aux_poll_data` - The auxiliary argument to provide when
    ///   [polling](BroadcastedFuture::poll) the wrapped [`BroadcastedFuture`].
    ///   Note that the inner [`BroadcastedFuture::poll()`] will get invoked
    ///   with the `aux_poll_data` passed on behalf of some unspecified
    ///   subscription, so they must all be functionally equivalent!
    /// * `cx` - Asynchronous task context providing access to a
    ///   [`Waker`](task::Waker).
    fn poll_from_subscription<
        'a,
        'b,
        BP: 'a + sync_types::SyncRcPtr<Self>,
        BR: 'a + sync_types::SyncRcPtrRef<'a, Self, BP>,
    >(
        this: pin::Pin<BR>,
        subscription_id: BroadcastWakerSubscriptionId,
        aux_poll_data: &mut F::AuxPollData<'b>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<F::Output>
    where
        Self: 'a,
    {
        // Only one subscriber thread -- the first to come -- ever polls the inner
        // Future. That thread sets and owns the
        // BroadcastFuturePollingState::InPoll state for the duration of
        // the poll. All other threads entering poll_from_subscription() and seeing the
        // InPoll state will immediately return with a status of Pending and
        // wait for the polling thread to complete its work and wake up all the
        // others again. For robustness against the currently polling thread
        // "loosing interest", i.e. never getting polled again after propagating a
        // Pending from the inner Future back to the caller, it is important to not let
        // it escape from here if any other thread receives a wake-up while
        // InPoll is set.  In particular, the fact that the polling thread gets
        // woken itself and would return from here in a "runnable" state does
        // not suffice -- as said, it might not get polled again for some reason.

        // This is safe, the Pin only concerns the currently polled inner future and
        // that will get rewrapped below.
        let this = unsafe { pin::Pin::into_inner_unchecked(this) };

        let mut polling_state_guard = this.polling_state.lock();

        // If polling in reaction to a received wake event, then we're seeing an updated
        // broadcast wake_gen in this thread, c.f. the documentation of
        // BroadcastWakerSubscriptions::wake_gen(). It is important to obtain the
        // wake_gen here in case of an early return just below. The release
        // semantics of the polling_state_guard drop synchronizes with a
        // subsequent reacquire from the currently polling task further below,
        // hence the latter will also observe the updated wake_gen value and loop over.
        //
        // If the current thread become the polling thread, and happens to see the
        // latest, update of wake_gen here (so that it will not loop over
        // below), then it also sees all prior updates to any state the inner
        // Future depends on. Meaning that the inner Future would already
        // have access to its latest state updates when polled below. See the
        // documentation of BroadcastWakerSubscriptions::wake_gen() memory
        // ordering semantics.
        let mut wake_gen = this.subscriptions.wake_gen();

        if *polling_state_guard == BroadcastFuturePollingState::InPoll {
            this.subscriptions
                .set_subscription_waker(subscription_id, cx.waker().clone());
            return task::Poll::Pending;
        }
        // If the ->polling_state is Idle, the contents of the Cell are consistent,
        // memory ordering considerations included. If not, it can be anything
        // and the compiler reordering accesses to before the check above would
        // be UB.
        atomic::compiler_fence(atomic::Ordering::Acquire);

        // Safe, access is exclusive as per holding the lock and ->polling_state
        // being Idle.
        let inner_fut = this.inner_fut.get();
        let inner_fut = unsafe { &mut *inner_fut };
        let f = match inner_fut {
            BroadcastFutureInnerFuture::Pending { inner } => inner,
            BroadcastFutureInnerFuture::Ready(result) => {
                // Don't clone under the lock. Note that once the inner future has completed and
                // the result installed here, it's stable.
                drop(polling_state_guard);
                this.subscriptions.unsubscribe(subscription_id, false);
                return task::Poll::Ready(result.clone());
            }
        };

        let waker = BroadcastWakerSubscriptions::waker(&sync_types::SyncRcPtrRefForInner::<
            '_,
            _,
            _,
            _,
            BroadcastFutureDerefInnerSubscriptionsTag,
        >::new(&this));

        let mut task_waker_updated = false;
        loop {
            // From now on, exclusive access to the inner_fut is granted to the current
            // task, even after the polling_state_guard is getting unlocked below.
            // Note that besides setting ->polling_state to InPoll, this drops the
            // polling_state_guard lock, so that the poll below is not being done
            // with the lock held.
            let in_poll_guard = BroadcastFutureInPollGuard::new(&this, polling_state_guard);

            // Safe, it's a projection repin.
            let f = unsafe { pin::Pin::new_unchecked(&mut *f) };

            let result = BroadcastedFuture::poll(f, aux_poll_data, &mut task::Context::from_waker(&waker));

            // At this point the (broadcast) waker might wake other tasks, they'd see
            // ->polling_state == InPoll and put themselves immediately back to sleep. In
            // case a wake-up happened, as indicated by a change of wake_gen,
            // loop over to enforce another poll(). As a side-effect, this
            // scheme allows us to install the current task's waker lazily only
            // when needed.
            match result {
                task::Poll::Ready(result) => {
                    *inner_fut = BroadcastFutureInnerFuture::Ready(result.clone());
                    // Reacquire the ->polling_state lock and reset to Idle.
                    polling_state_guard = in_poll_guard.release();
                    drop(polling_state_guard);
                    // Unsubscribe and wake the others to grab their copy of the result.
                    this.subscriptions.unsubscribe(subscription_id, true);
                    return task::Poll::Ready(result);
                }
                task::Poll::Pending => {
                    // Not completed, update the waker associated with the current subscription.
                    if !task_waker_updated {
                        this.subscriptions
                            .set_subscription_waker(subscription_id, cx.waker().clone());
                        task_waker_updated = true;
                    }

                    // Reacquire the ->polling_state lock and reset to Idle.
                    polling_state_guard = in_poll_guard.release();
                    // See the documentation of BroadcastFuturePollingState::wake_gen():
                    // if a wakeup event happened before the set_subscription_waker() above,
                    // then we're guaranteed to read an updated wake generation value. Otherwise the
                    // updated waker has been woken.
                    let cur_wake_gen = this.subscriptions.wake_gen();
                    if wake_gen != cur_wake_gen {
                        // As outlined above, enforce another poll() if a wake-up has happened in
                        // the meanwhile.
                        wake_gen = cur_wake_gen;
                    } else {
                        return task::Poll::Pending;
                    }
                }
            }
        }
    }
}

/// [`DerefInnerByTag`](sync_types::DerefInnerByTag) `TAG` for derefencing
/// `BroadcastFuture::subscriptions`.
///
/// Enables presenting the [`SyncRcPtr`](sync_types::SyncRcPtr) of the
/// [`BroadcastFuture`] as one for its [`BroadcastFuture::subscriptions`] member
/// via the [`SyncRcPtrForInner`](sync_types::SyncRcPtrForInner) mechanism.
struct BroadcastFutureDerefInnerSubscriptionsTag;

impl<ST: sync_types::SyncTypes, F: BroadcastedFuture>
    sync_types::DerefInnerByTag<BroadcastFutureDerefInnerSubscriptionsTag> for BroadcastFuture<ST, F>
{
    crate::impl_deref_inner_by_tag!(subscriptions, BroadcastWakerSubscriptions<ST>);
}

impl<ST: sync_types::SyncTypes, F: BroadcastedFuture>
    sync_types::DerefMutInnerByTag<BroadcastFutureDerefInnerSubscriptionsTag> for BroadcastFuture<ST, F>
{
    crate::impl_deref_mut_inner_by_tag!(subscriptions);
}

/// Polling progress of a [`BroadcastFuture`]'s inner [`BroadcastedFuture`].
enum BroadcastFutureInnerFuture<F: BroadcastedFuture> {
    /// The inner [`BroadcastedFuture`] is not [`Ready`](task::Poll::Ready)
    /// yet and must get polled further.
    Pending {
        /// The inner future to get collectively polled for.
        inner: F,
    },
    /// The inner [`BroadcastedFuture`] is [`Ready`](task::Poll::Ready),
    /// with the resulting [`Output`][`Future::Output`].
    Ready(F::Output),
}

/// Concurrent polling state of the [`BroadcastFuture`]'s inner
/// [`BroadcastedFuture`], tracked at [`BroadcastFuture::polling_state`].
///
/// Used for managing exclusive access to the inner [`BroadcastedFuture`]
/// without holding a [`Lock`](sync_types::Lock), which is possibly of the
/// spinlock kind, over [`Future::poll()`](Future::poll) invocations.
///
/// Note that updates to the [`BroadcastFuture::polling_state`] are done under
/// the protection of a [`Lock`](sync_types::Lock), but that's getting dropped
/// inbetween while the [`BroadcastedFuture`] is being polled.
///
/// # See also:
///
/// * [`BroadcastFutureInPollGuard`]
#[derive(PartialEq, Eq, Debug)]
enum BroadcastFuturePollingState {
    /// No thread is currently polling the inner [`BroadcastedFuture`].
    Idle,
    /// A thread is currently exclusively polling the inner
    /// [`BroadcastedFuture`] and that thread owns a
    /// [`BroadcastFutureInPollGuard`].
    InPoll,
}

/// Guard for [`BroadcastFuture::polling_state`]'s
/// [`InPoll`](BroadcastFuturePollingState::InPoll) state.
///
/// Held exclusively by the thread currently polling the [`BroadcastFuture`]'s
/// inner [`BroadcastedFuture`].
struct BroadcastFutureInPollGuard<'a, ST: sync_types::SyncTypes, F: BroadcastedFuture> {
    broadcast_future: &'a BroadcastFuture<ST, F>,
    locked_in_poll: bool,
}

impl<'a, ST: sync_types::SyncTypes, F: BroadcastedFuture> BroadcastFutureInPollGuard<'a, ST, F> {
    /// Transition the [`BroadcastFuture::polling_state`] from
    /// [`Idle`](BroadcastFuturePollingState::Idle) to
    /// [`InPoll`](BroadcastFuturePollingState::InPoll) and return a
    /// `BroadcastFutureInPollGuard` for it.
    ///
    /// Upon entry, `*polling_state_guard` must be
    /// [`Idle`](BroadcastFuturePollingState::Idle).
    /// Assign [`InPoll`](BroadcastFuturePollingState::InPoll)and release the
    /// `polling_state_guard` [`Lock`](sync_types::Lock).
    ///
    /// # Arguments:
    ///
    /// * `broadcast_future` - The [`BroadcastFuture`] to lock for polling from
    ///   the current thread.
    /// * `polling_state_guard` - [Locking guard](sync_types::Lock::Guard) for
    ///   `broadcast_future.polling_state`.
    fn new<'b>(
        broadcast_future: &'a BroadcastFuture<ST, F>,
        mut polling_state_guard: <ST::Lock<BroadcastFuturePollingState> as sync_types::Lock<
            BroadcastFuturePollingState,
        >>::Guard<'b>,
    ) -> Self {
        debug_assert_eq!(*polling_state_guard, BroadcastFuturePollingState::Idle);
        *polling_state_guard = BroadcastFuturePollingState::InPoll;
        Self {
            broadcast_future,
            locked_in_poll: true,
        }
    }

    /// Release the guarded [`BroadcastFuture::polling_state`]'s
    /// [`InPoll`](BroadcastFuturePollingState::InPoll) state.
    ///
    /// Reacquire the  [`BroadcastFuture::polling_state`]
    /// [`Lock`](sync_types::Lock), switch the value back to
    /// [`Idle`](BroadcastFuturePollingState::Idle) and return the
    /// [`BroadcastFuture::polling_state`]
    /// [`Lock::Guard`](sync_types::Lock::Guard).
    ///
    /// As long as the returned [`Lock::Guard`](sync_types::Lock::Guard) is
    /// being held, the [`BroadcastFuture::polling_state`] value is guaranteed
    /// to remain at [`Idle`](BroadcastFuturePollingState::Idle) and no
    /// other thread can become the polling thread.
    fn release(
        mut self,
    ) -> <ST::Lock<BroadcastFuturePollingState> as sync_types::Lock<BroadcastFuturePollingState>>::Guard<'a> {
        let mut polling_state_guard = self.broadcast_future.polling_state.lock();
        *polling_state_guard = BroadcastFuturePollingState::Idle;
        self.locked_in_poll = false;
        polling_state_guard
    }
}

impl<'a, ST: sync_types::SyncTypes, F: BroadcastedFuture> Drop for BroadcastFutureInPollGuard<'a, ST, F> {
    fn drop(&mut self) {
        if self.locked_in_poll {
            *self.broadcast_future.polling_state.lock() = BroadcastFuturePollingState::Idle;
            self.locked_in_poll = false;
        }
    }
}

/// Subscription to a [`BroadcastFuture`].
///
/// [`BroadcastFutureSubscription`], instantiated through
/// [`BroadcastFuture::subscribe()`], implements [`poll()`](Self::poll) itself
/// and is to be used to poll on the wrapped inner future and to eventually
/// obtain its broadcasted result once completed.
///
/// It should be obvious, but it is explictly permitted to concurrently poll on
/// the same [`BroadcastFuture`] instance from multiple associated
/// subscriptions.
///
/// The wrapped future can only make progress upon polling on the subscriptions.
/// Once the inner future gets woken, the wake-up is guaranteed to get
/// broadcasted to all registered subscribers.
pub struct BroadcastFutureSubscription<
    ST: sync_types::SyncTypes,
    F: BroadcastedFuture,
    BP: sync_types::SyncRcPtr<BroadcastFuture<ST, F>>,
> {
    state: BroadcastFutureSubscriptionState<ST, F, BP>,
}

impl<ST: sync_types::SyncTypes, F: BroadcastedFuture, BP: sync_types::SyncRcPtr<BroadcastFuture<ST, F>>>
    BroadcastFutureSubscription<ST, F, BP>
{
    /// Instantiate a [`BroadcastFutureSubscription`] bound to some
    /// [`BroadcastFuture`].
    ///
    /// # Arguments:
    ///
    /// * `broadcast_future` - The [`BroadcastFuture`] the to be insantiated
    ///   [`BroadcastFutureSubscription`] will be associated with.
    /// * `subscription_id` - The subscription id obtained from
    ///   [`BroadcastFuture::subscriptions`].
    fn new(broadcast_future: pin::Pin<BP>, subscription_id: BroadcastWakerSubscriptionId) -> Self {
        Self {
            state: BroadcastFutureSubscriptionState::Pending {
                broadcast_future,
                subscription_id,
                _phantom: marker::PhantomData,
            },
        }
    }

    /// Poll on behalf of the subscription.
    ///
    /// # Arguments:
    ///
    /// * `aux_poll_data` - The auxiliary argument to provide when
    ///   [polling](BroadcastedFuture::poll) the wrapped [`BroadcastedFuture`].
    ///   Note that the inner [`BroadcastedFuture::poll()`] will get invoked
    ///   with the `aux_poll_data` passed on behalf of some unspecified
    ///   subscription, so they must all be functionally equivalent!
    /// * `cx` - Asynchronous task context providing access to a
    ///   [`Waker`](task::Waker).
    pub fn poll<'a>(
        self: pin::Pin<&mut Self>,
        aux_poll_data: &mut F::AuxPollData<'a>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<F::Output> {
        let this = self.get_mut();
        match &this.state {
            BroadcastFutureSubscriptionState::Pending {
                broadcast_future,
                subscription_id,
                _phantom,
            } => {
                let result = BroadcastFuture::poll_from_subscription(
                    sync_types::SyncRcPtr::as_ref(broadcast_future),
                    *subscription_id,
                    aux_poll_data,
                    cx,
                );
                if matches!(result, task::Poll::Ready(_)) {
                    this.state = BroadcastFutureSubscriptionState::Done;
                }
                result
            }
            BroadcastFutureSubscriptionState::Done => unreachable!(),
        }
    }
}

impl<ST: sync_types::SyncTypes, F: BroadcastedFuture, BP: sync_types::SyncRcPtr<BroadcastFuture<ST, F>>> Drop
    for BroadcastFutureSubscription<ST, F, BP>
{
    fn drop(&mut self) {
        match &self.state {
            BroadcastFutureSubscriptionState::Pending {
                broadcast_future,
                subscription_id,
                _phantom,
            } => {
                broadcast_future.cancel_subscription(*subscription_id);
                self.state = BroadcastFutureSubscriptionState::Done;
            }
            BroadcastFutureSubscriptionState::Done => (),
        }
    }
}

impl<
    'a,
    ST: sync_types::SyncTypes,
    F: BroadcastedFuture<AuxPollData<'a> = ()>,
    BP: sync_types::SyncRcPtr<BroadcastFuture<ST, F>>,
> future::Future for BroadcastFutureSubscription<ST, F, BP>
{
    type Output = F::Output;

    fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        BroadcastFutureSubscription::poll(self, &mut (), cx)
    }
}

/// Private state of [`BroadcastFutureSubscription`].
enum BroadcastFutureSubscriptionState<
    ST: sync_types::SyncTypes,
    F: BroadcastedFuture,
    BP: sync_types::SyncRcPtr<BroadcastFuture<ST, F>>,
> {
    /// The [`BroadcastFutureSubscription`] [`BroadcastedFuture`] has not been
    /// polled to completion yet.
    Pending {
        /// The [`BroadcastFuture`] the subscription is to.
        broadcast_future: pin::Pin<BP>,
        /// The id associated with the subscription.
        subscription_id: BroadcastWakerSubscriptionId,
        _phantom: marker::PhantomData<fn() -> (*const ST, *const F)>,
    },
    /// The [`BroadcastFutureSubscription`] [`BroadcastedFuture`] has been
    /// polled to completion and the broadcasted result returned.
    Done,
}

#[test]
fn test_broadcast_future_single() {
    use crate::test::{TestAsyncExecutor, TestNopSyncTypes};

    struct TestBroadcastedFuture {}

    impl BroadcastedFuture for TestBroadcastedFuture {
        type Output = u32;
        type AuxPollData<'a> = ();

        fn poll<'a>(
            self: pin::Pin<&mut Self>,
            _aux_data: &mut Self::AuxPollData<'a>,
            _cx: &mut task::Context<'_>,
        ) -> task::Poll<Self::Output> {
            task::Poll::Ready(1u32)
        }
    }

    let broadcast_future =
        <<TestNopSyncTypes as sync_types::SyncTypes>::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>::try_new(
            BroadcastFuture::<TestNopSyncTypes, TestBroadcastedFuture>::new(TestBroadcastedFuture {}),
        )
        .unwrap();
    let broadcast_future = unsafe { pin::Pin::new_unchecked(broadcast_future) };

    let subscription = BroadcastFuture::subscribe(sync_types::SyncRcPtr::as_ref(&broadcast_future)).unwrap();

    let e = TestAsyncExecutor::new();
    let w = TestAsyncExecutor::spawn(&e, subscription);
    TestAsyncExecutor::run_to_completion(&e);
    assert_eq!(w.take().unwrap(), 1u32);
}

#[test]
fn test_broadcast_future_broadcast() {
    use crate::test::{TestAsyncExecutor, TestNopSyncTypes};

    struct TestBroadcastedFuture {
        polled_once: bool,
    }

    impl BroadcastedFuture for TestBroadcastedFuture {
        type Output = u32;
        type AuxPollData<'a> = ();

        fn poll<'a>(
            self: pin::Pin<&mut Self>,
            _aux_data: &mut Self::AuxPollData<'a>,
            _cx: &mut task::Context<'_>,
        ) -> task::Poll<Self::Output> {
            if self.polled_once == false {
                self.get_mut().polled_once = true;
                task::Poll::Pending
            } else {
                task::Poll::Ready(1u32)
            }
        }
    }

    let broadcast_future =
        <<TestNopSyncTypes as sync_types::SyncTypes>::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>::try_new(
            BroadcastFuture::<TestNopSyncTypes, TestBroadcastedFuture>::new(TestBroadcastedFuture {
                polled_once: false,
            }),
        )
        .unwrap();
    let broadcast_future = unsafe { pin::Pin::new_unchecked(broadcast_future) };

    let subscription0 = BroadcastFuture::subscribe(sync_types::SyncRcPtr::as_ref(&broadcast_future)).unwrap();
    let subscription1 = BroadcastFuture::subscribe(sync_types::SyncRcPtr::as_ref(&broadcast_future)).unwrap();

    let e = TestAsyncExecutor::new();
    let w0 = TestAsyncExecutor::spawn(&e, subscription0);
    let w1 = TestAsyncExecutor::spawn(&e, subscription1);
    TestAsyncExecutor::run_to_completion(&e);
    assert_eq!(w0.take().unwrap(), 1u32);
    assert_eq!(w1.take().unwrap(), 1u32);
}

#[test]
fn test_broadcast_future_post_completion_subscribe() {
    use crate::test::{TestAsyncExecutor, TestNopSyncTypes};

    struct TestBroadcastedFuture {
        done: bool,
    }

    impl BroadcastedFuture for TestBroadcastedFuture {
        type Output = u32;
        type AuxPollData<'a> = ();

        fn poll<'a>(
            self: pin::Pin<&mut Self>,
            _aux_data: &mut Self::AuxPollData<'a>,
            _cx: &mut task::Context<'_>,
        ) -> task::Poll<Self::Output> {
            assert!(!self.done);
            self.get_mut().done = true;
            task::Poll::Ready(1u32)
        }
    }

    let broadcast_future =
        <<TestNopSyncTypes as sync_types::SyncTypes>::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>::try_new(
            BroadcastFuture::<TestNopSyncTypes, TestBroadcastedFuture>::new(TestBroadcastedFuture { done: false }),
        )
        .unwrap();
    let broadcast_future = unsafe { pin::Pin::new_unchecked(broadcast_future) };

    let subscription0 = BroadcastFuture::subscribe(sync_types::SyncRcPtr::as_ref(&broadcast_future)).unwrap();

    let e = TestAsyncExecutor::new();
    let w0 = TestAsyncExecutor::spawn(&e, subscription0);
    TestAsyncExecutor::run_to_completion(&e);
    assert_eq!(w0.take().unwrap(), 1u32);

    let subscription1 = BroadcastFuture::subscribe(sync_types::SyncRcPtr::as_ref(&broadcast_future)).unwrap();
    let w1 = TestAsyncExecutor::spawn(&e, subscription1);
    TestAsyncExecutor::run_to_completion(&e);
    assert_eq!(w1.take().unwrap(), 1u32);
}

#[test]
fn test_broadcast_future_cancel_subscription() {
    use crate::test::{TestAsyncExecutor, TestNopSyncTypes};

    struct TestBroadcastedFuture {}

    impl BroadcastedFuture for TestBroadcastedFuture {
        type Output = u32;
        type AuxPollData<'a> = ();

        fn poll<'a>(
            self: pin::Pin<&mut Self>,
            _aux_data: &mut Self::AuxPollData<'a>,
            _cx: &mut task::Context<'_>,
        ) -> task::Poll<Self::Output> {
            task::Poll::Ready(1u32)
        }
    }

    let broadcast_future =
        <<TestNopSyncTypes as sync_types::SyncTypes>::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>::try_new(
            BroadcastFuture::<TestNopSyncTypes, TestBroadcastedFuture>::new(TestBroadcastedFuture {}),
        )
        .unwrap();
    let broadcast_future = unsafe { pin::Pin::new_unchecked(broadcast_future) };

    let subscription0 = BroadcastFuture::subscribe(sync_types::SyncRcPtr::as_ref(&broadcast_future)).unwrap();
    let subscription1 = BroadcastFuture::subscribe(sync_types::SyncRcPtr::as_ref(&broadcast_future)).unwrap();
    let e = TestAsyncExecutor::new();
    let w1 = TestAsyncExecutor::spawn(&e, subscription1);
    drop(subscription0);
    TestAsyncExecutor::run_to_completion(&e);
    assert_eq!(w1.take().unwrap(), 1u32);
}
