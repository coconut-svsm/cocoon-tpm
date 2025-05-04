// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`FutureQueue`].

extern crate alloc;
use super::broadcast_waker;
use crate::{
    alloc::{SyncVec, SyncVecError},
    sync_types::{self, Lock as _},
};
use core::{cell, convert, marker, pin, sync::atomic, task};

/// Trait for futures to be processed by a [`FutureQueue`].
///
/// As the whole point of the [`FutureQueue`] concept is to arbitrate
/// access to some shared value, the standard [`Future::poll()`](Future::poll)
/// signature is being extended to provide exclusive access to that shared
/// value.
pub trait QueuedFuture<T> {
    type Output;
    type AuxPollData<'a>;

    /// The extended `poll()` with access to the [`FutureQueue`]'s arbitrated
    /// ressource.
    ///
    /// # Arguements:
    ///
    /// * `arbitrated_ressource` - A `mut` reference to the [`FutureQueue`]'s
    ///   arbitrated ressource. As a [`FutureQueue`] processes queued futures in
    ///   order, no other future will be given access inbetween any two `poll()`
    ///   invocations on this instance..
    /// * `aux_data` - Auxiliary data passed onwards from **any**
    ///   [`EnqueuedFutureSubscription::poll()`](EnqueuedFutureSubscription::poll).
    /// * `cx` - Asynchronous task context providing access to a
    ///   [`Waker`](task::Waker).
    fn poll<'a>(
        self: pin::Pin<&mut Self>,
        arbitrated_ressource: &mut T,
        aux_data: &mut Self::AuxPollData<'a>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output>;
}

/// Error returned by [`FutureQueue::enqueue`](FutureQueue::enqueue).
#[derive(Clone, Copy, Debug)]
pub enum FutureQueueError {
    /// A memory allocation failed.
    MemoryAllocationFailure,
}

impl convert::From<broadcast_waker::BroadcastWakerError> for FutureQueueError {
    fn from(value: broadcast_waker::BroadcastWakerError) -> Self {
        match value {
            broadcast_waker::BroadcastWakerError::MemoryAllocationFailure => FutureQueueError::MemoryAllocationFailure,
        }
    }
}

impl convert::From<SyncVecError> for FutureQueueError {
    fn from(value: SyncVecError) -> Self {
        match value {
            SyncVecError::MemoryAllocationFailure => FutureQueueError::MemoryAllocationFailure,
        }
    }
}

/// Process futures one after another, providing each exclusive access to some
/// "arbitrated ressource".
///
/// From a functionality perspective, a `FutureQueue` is very similar to an
/// asynchronous lock, where the lock is typically to be locked via polling and
/// the owner can then subsequently keep it for an indefinite amount of time,
/// e.g. across multiple [`poll()`](core::future::Future::poll) invocations on
/// some other [`Future`]s, until eventually releasing the lock again and waking
/// other waiters. However, this asynchronous lock scheme has the drawback that
/// it is not robust against threads "loosing interest", e.g. tasks abandoned
/// for some reason: if the execution environment happens to not poll some lock
/// owning task any further, all other waiting tasks would end up stuck for
/// forever.
///
/// A `FutureQueue` solves this problem by assuming ownership of any future
/// needing access to the protected ressource and providing that (exclusively)
/// to its [`poll()`](QueuedFuture::poll) once it becomes first in line. The
/// important point is that any [`poll()`](EnqueuedFutureSubscription::poll) on
/// an enqueued future's [associated subscriptions](EnqueuedFutureSubscription)
/// will always drive progress for any other enqueued futures ahead in line,
/// even if their original submitters ceased the polling. That way, any thread
/// polling on its enqueued future's [associated
/// subscription](EnqueuedFutureSubscription) is guaranteed that its future will
/// eventually get processed.
///
/// As the enqueued future's [`poll()`](QueuedFuture::poll) had to get extended
/// in order to provide access to the `FutureQueue` arbitrated ressource, a new
/// trait [`QueuedFuture`], otherwise resembling that of a standard Rust
/// [`Future`] is being defined. Users may enqueue implementations thereof via
/// [`FutureQueue::enqueue()`](FutureQueue::enqueue) and subsequently
/// [poll](EnqueuedFutureSubscription::poll) on the resulting
/// [`EnqueuedFutureSubscription`] to drive their respective enqueued future's
/// progress forward and eventually retrieve its result once
/// [`Ready`](task::Poll::Ready).
pub struct FutureQueue<ST: sync_types::SyncTypes, T, F: QueuedFuture<T>> {
    /// Broadcast waker subscriptions.
    ///
    /// There's a 1:1 correspondence between FutureQueue subscription and
    /// broadcast `waker` subscriptions. On every [poll from some
    /// subscription](EnqueuedFutureSubscription::poll), the passed
    /// [`Waker`](task::Waker) will get installed for the corresponding
    /// broadcast `waker` subscription.
    wakers: broadcast_waker::BroadcastWakerSubscriptions<ST>,
    /// [`Lock`](sync_types::Lock) protected state.
    state: ST::Lock<FutureQueueState<T, F>>,
    /// The currently active [`QueuedFuture`].
    ///
    /// Moved here for maintaining [`Pin`](pin::Pin) guarantees.
    /// Access is serialized via [`FutureQueueState::polling_state`].
    /// The associated subscription id is in
    /// [`FutureQueueState::active_queue_entry_id`].
    active_fut: cell::UnsafeCell<Option<F>>,
    /// The `FutureQueue`'s arbitrated ressource.
    ///
    /// Only the currently `active_fut` is given access through its
    /// [`poll()`](QueuedFuture::poll).
    arbitrated_ressource: cell::UnsafeCell<T>,
}

unsafe impl<ST: sync_types::SyncTypes, T, F: QueuedFuture<T>> marker::Send for FutureQueue<ST, T, F> {}
unsafe impl<ST: sync_types::SyncTypes, T, F: QueuedFuture<T>> marker::Sync for FutureQueue<ST, T, F> {}

impl<ST: sync_types::SyncTypes, T, F: QueuedFuture<T>> FutureQueue<ST, T, F> {
    /// Crate a new [`FutureQueue`] instance.
    ///
    /// Note that the caller is supposed to move the returned `BroadcastFuture`
    /// into a pinned [`SyncRcPtr`](sync_types::SyncRcPtr) -- the other parts of
    /// the API expect that.
    ///
    /// # Arguments:
    ///
    /// * `arbitrated_ressource` - The value to serialize access to. Provided as
    ///   a `mut` reference to enqueued future's [`poll()`](QueuedFuture::poll).
    pub fn new(arbitrated_ressource: T) -> Self {
        Self {
            wakers: broadcast_waker::BroadcastWakerSubscriptions::new(),
            state: ST::Lock::from(FutureQueueState::new()),
            active_fut: cell::UnsafeCell::new(None),
            arbitrated_ressource: cell::UnsafeCell::new(arbitrated_ressource),
        }
    }

    /// Access the wrapped arbitrated ressource through a `mut` reference on
    /// `Self`.
    pub fn get_arbitrated_ressource_mut(&mut self) -> &mut T {
        self.arbitrated_ressource.get_mut()
    }

    /// Enqueue a [future](QueuedFuture).
    ///
    /// On success, a [`EnqueuedFutureSubscription`] will get returned, which
    /// may get [`poll()`](EnqueuedFutureSubscription::poll)ed to
    /// drive the future's progress forward and to eventually obtain its result.
    ///
    /// On error, the future instance will get returned back to the caller
    /// alongside some error information. Note that returning the future back
    /// enables the caller to recover objects whose ownership had been
    /// passed temporarily into the future.
    ///
    /// # Arguments:
    /// * `this` - A [`Pin<SyncRcPtr<Self>>`](sync_types::SyncRcPtr) the
    ///   `FutureQueue` had been wrapped in, c.f. [`Self::new()`](Self::new).
    /// * `fut` - The future to enqueue.
    pub fn enqueue<QP: sync_types::SyncRcPtr<FutureQueue<ST, T, F>>>(
        this: pin::Pin<QP>,
        fut: F,
    ) -> Result<EnqueuedFutureSubscription<ST, T, F, QP>, (F, FutureQueueError)> {
        let queue_entry_id = match this.wakers.subscribe() {
            Ok(queue_entry_id) => queue_entry_id,
            Err(e) => return Err((fut, FutureQueueError::from(e))),
        };

        let state_guard = this.state.lock();
        let completion_queue_lock =
            sync_types::LockForInner::<'_, _, _, FutureQueueStateDerefInnerCompletionQueueTag>::from_outer(&this.state);
        let mut completion_queue_guard =
            sync_types::LockForInnerGuard::<'_, _, _, FutureQueueStateDerefInnerCompletionQueueTag>::from_outer(
                state_guard,
            );
        let result;
        (completion_queue_guard, result) =
            SyncVec::try_reserve_exact(&completion_queue_lock, completion_queue_guard, 1);
        if let Err(e) = result {
            this.wakers.unsubscribe(queue_entry_id, false);
            return Err((fut, FutureQueueError::from(e)));
        }
        // Push a None placeholder, so that the capacity just allocated won't get
        // repurposed until when it's needed at future completion.
        completion_queue_guard.push(None);
        let state_guard = completion_queue_guard.into_outer();

        let submission_queue_lock =
            sync_types::LockForInner::<'_, _, _, FutureQueueStateDerefInnerSubmissionQueueTag>::from_outer(&this.state);
        let mut submission_queue_guard =
            sync_types::LockForInnerGuard::<'_, _, _, FutureQueueStateDerefInnerSubmissionQueueTag>::from_outer(
                state_guard,
            );
        let result;
        (submission_queue_guard, result) =
            SyncVec::try_reserve_exact(&submission_queue_lock, submission_queue_guard, 1);
        if let Err(e) = result {
            let mut state_guard = submission_queue_guard.into_outer();
            let popped_cqe = state_guard.completion_queue.pop();
            debug_assert!(matches!(popped_cqe, Some(None)));
            this.wakers.unsubscribe(queue_entry_id, false);
            return Err((fut, FutureQueueError::from(e)));
        }
        submission_queue_guard.push((queue_entry_id, fut));
        drop(submission_queue_guard);

        Ok(EnqueuedFutureSubscription::new(this, queue_entry_id))
    }

    /// Cancel a queued future.
    ///
    /// # Arguments:
    ///
    /// * `queue_entry_id` - The associated subscription id.
    fn cancel_queued(&self, queue_entry_id: broadcast_waker::BroadcastWakerSubscriptionId) {
        self.wakers.unsubscribe(queue_entry_id, false);

        let mut state_guard = self.state.lock();
        if let Some(sqe_index) = state_guard
            .submission_queue
            .iter()
            .position(|sqe| sqe.0 == queue_entry_id)
        {
            state_guard.submission_queue.remove(sqe_index);

            debug_assert!(!state_guard
                .completion_queue
                .iter()
                .any(|cqe| cqe.as_ref().map(|cqe| cqe.0 == queue_entry_id).unwrap_or(false)));
            let popped_cqe = state_guard.completion_queue.pop();
            debug_assert!(matches!(popped_cqe, Some(None)));
        } else if state_guard
            .active_queue_entry_id
            .map(|active_queue_entry_id| active_queue_entry_id == queue_entry_id)
            .unwrap_or(false)
        {
            // The cancelled entry is currently active. Setting ->active_queue_entry_id to
            // None indicates a request for cancellation. If no poll is
            // currently ongoing, even clear out the ->active_fut entry in order
            // to free any associated ressources now. Otherwise
            // the task actively polling will see the request for cancellation and do it
            // soon.
            state_guard.active_queue_entry_id = None;
            if state_guard.polling_state == FutureQueuePollingState::Idle {
                let active_fut = self.active_fut.get();
                // Safe, access is exclusive as per ->polling_state.
                let active_fut = unsafe { &mut *active_fut };
                *active_fut = None;
            }

            debug_assert!(!state_guard
                .completion_queue
                .iter()
                .any(|cqe| cqe.as_ref().map(|cqe| cqe.0 == queue_entry_id).unwrap_or(false)));
            let popped_cqe = state_guard.completion_queue.pop();
            debug_assert!(matches!(popped_cqe, Some(None)));
        } else {
            // Entry is not queued for polling anymore, it must have been completed then, if
            // anything.
            if let Some(cqe_index) = state_guard
                .completion_queue
                .iter()
                .position(|cqe| cqe.as_ref().map(|cqe| cqe.0 == queue_entry_id).unwrap_or(false))
            {
                state_guard.completion_queue.remove(cqe_index);
            }
        }
    }

    /// Poll the enqueued futures on behalf of an
    /// [`EnqueuedFutureSubscription`], until the one associated with the
    /// subscription has completed.
    ///
    /// # Arguments:
    ///
    /// * `this` - A [`Pin<SyncRcPtrRef<Self>>`](sync_types::SyncRcPtrRef)
    ///   referring to the [`Pin<SyncRcPtr<Self>>`](sync_types::SyncRcPtr) the
    ///   `FutureQueue` had been wrapped in, c.f. [`Self::new()`](Self::new).
    /// * `queue_entry_id` - The id associated with the
    ///   [`EnqueuedFutureSubscription`] on whose behalf to poll.
    /// * `aux_poll_data` - Auxiliary polling data to pass along to **any**
    ///   polled [`QueuedFuture::poll()`](QueuedFuture::poll).
    /// * `cx` - Asynchronous task context providing access to a
    ///   [`Waker`](task::Waker).
    fn poll_from_queue_entry_owner<
        'a,
        QP: 'a + sync_types::SyncRcPtr<Self>,
        QR: 'a + sync_types::SyncRcPtrRef<'a, Self, QP>,
    >(
        this: pin::Pin<QR>,
        queue_entry_id: broadcast_waker::BroadcastWakerSubscriptionId,
        aux_poll_data: &mut F::AuxPollData<'_>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<F::Output>
    where
        Self: 'a,
    {
        // Only one subscriber thread -- the first to come -- ever polls the inner
        // futures. That thread sets and owns the
        // FutureQueuePollingState::InPoll state for the duration of the
        // poll. All other threads entering poll_from_queue_entry_owner() and seeing the
        // InPoll state will immediately return with a status of Pending and
        // wait for the polling thread to complete its work and wake up the
        // others again. For robustness against the currently polling thread
        // "loosing interest", i.e. never getting polled again after propagating a
        // Pending from the active queued future back to the caller, it is important to
        // not let it escape from here if any other thread receives a wake-up
        // while InPoll is set.  In particular, the fact that the polling thread
        // gets woken itself and would return from here in a "runnable" state
        // does not suffice -- as said, it might not get polled again for some
        // reason.

        // This is safe, the Pin only concerns the currently polled inner future and
        // that will get rewrapped below.
        let this = unsafe { pin::Pin::into_inner_unchecked(this) };

        let mut state_guard = this.state.lock();

        // First check the completion queue, some other task might have completed our
        // enqueued future.
        for (cqe_index, cqe) in state_guard.completion_queue.iter().enumerate() {
            match cqe {
                Some(cqe) => {
                    if cqe.0 == queue_entry_id {
                        // take_if() is unstable.
                        let cqe = state_guard.completion_queue.remove(cqe_index).unwrap();
                        return task::Poll::Ready(cqe.1);
                    }
                }
                None => {
                    // Tail of None's reached.
                    break;
                }
            }
        }

        // Not completed, update the associated waker.
        this.wakers.set_subscription_waker(queue_entry_id, cx.waker().clone());

        // If polling in reaction to a received (broadcasted) wake event for the
        // active_fut, then we're seeing an updated broadcast wake_gen in this
        // thread, c.f. the documentation of
        // BroadcastWakerSubscriptions::wake_gen(). It is important to obtain
        // the wake_gen here in case of an early return just below. The release
        // semantics of state_guard drop synchronizes with a subsequent
        // reacquire from the currently polling task further below,
        // hence the latter will also observe the updated wake_gen value and loop over.
        //
        // If the current thread become the polling thread, and happens to see the
        // latest, update of wake_gen here (so that it will not loop over
        // below), then it also sees all prior updates to any state the currently
        // active_fut depends on. Meaning that the currently active future would
        // already have access to its latest state updates when polled below.
        // See the documentation of BroadcastWakerSubscriptions::wake_gen()
        // memory ordering semantics.
        let mut wake_gen = this.wakers.wake_gen();

        if state_guard.polling_state == FutureQueuePollingState::InPoll {
            // Someone else is currently polling already.
            return task::Poll::Pending;
        }
        // If the ->polling_state is Idle, the contents of the Cell are consistent,
        // memory ordering considerations included. If not, it can be anything
        // and the compiler reordering accesses to before the check above would
        // be UB. Note that the CPU doing _speculative_ reorderings is fine.
        atomic::compiler_fence(atomic::Ordering::Acquire);

        // Constructing the broadcast waker to register at the inner futures is not
        // necessarily to be done under the state lock, it's done here only to
        // avoid the instantiation if not needed.
        let waker = broadcast_waker::BroadcastWakerSubscriptions::waker(&sync_types::SyncRcPtrRefForInner::<
            '_,
            _,
            _,
            _,
            FutureQueueDerefInnerWakersTag,
        >::new(&this));

        loop {
            let active_fut = this.active_fut.get();
            // Safe, access is exclusive as per holding the state lock and ->polling_state
            // begin Idle.
            let active_fut = unsafe { &mut *active_fut };
            let active_fut_entry = if state_guard.active_queue_entry_id.is_some() {
                active_fut.as_mut().unwrap()
            } else {
                // ->active_queue_entry_id being None might indicate a request for cancellation.
                *active_fut = None;
                // The fact we're polling on behalf of a not yet completed owner means
                // there are some queued futures left to process.
                debug_assert!(!state_guard.submission_queue.is_empty());
                let head_sqe = state_guard.submission_queue.remove(0);
                state_guard.active_queue_entry_id = Some(head_sqe.0);
                active_fut.insert(head_sqe.1)
            };

            // From now on, exclusive access to the currently active future as well as to
            // the aribtrated ressource is granted to the current task, even after
            // the state_guard is getting unlocked below. Note that besides
            // setting -> polling_state to InPoll, this drops the state_guard lock,
            // so that the poll below is not being done with the lock held.
            let in_poll_guard = FutureQueueInPollGuard::new(&this, state_guard);

            // Safe, it's a projection repin.
            let f = unsafe { pin::Pin::new_unchecked(active_fut_entry) };
            let arbitrated_ressource = this.arbitrated_ressource.get();
            // Safe, access is exclusive as per ->polling_state.
            let arbitrated_ressource = unsafe { &mut *arbitrated_ressource };

            let result = QueuedFuture::poll(
                f,
                arbitrated_ressource,
                aux_poll_data,
                &mut task::Context::from_waker(&waker),
            );

            // At this point the (broadcast) waker might wake other tasks, they'd see
            // ->polling_state == InPoll and put themselves immediately back to sleep. In
            // principle, the event will not get missed as the current task will
            // also receive a wake-up and either get rescheduled and poll again
            // (if the current future is not associated with it), or wake up the
            // other tasks once again in case it unsubscribes. However, in case
            // the current tasks' rescheduling is not considered, i.e. the current task is
            // abandonned for some reason, the future would stall. Thus, in case a wake-up
            // happened, as indicated by a change of wake_gen, loop over to
            // enforce another poll().

            // Reacquire the ->state lock and reset ->polling_state to Idle.
            state_guard = in_poll_guard.release();

            let completed_queue_entry_id = match state_guard.active_queue_entry_id {
                Some(active_queue_entry_id) => active_queue_entry_id,
                None => {
                    // The enqueued entry got cancelled concurrently while getting polled.
                    *active_fut = None;
                    // Forward the wake_gen for the next iteration.
                    wake_gen = this.wakers.wake_gen();
                    continue;
                }
            };

            match result {
                task::Poll::Ready(result) => {
                    state_guard.active_queue_entry_id = None;
                    *active_fut = None;
                    if completed_queue_entry_id == queue_entry_id {
                        // The currently polling task is the owner of the future just completed,
                        // return the result directly (rather than enqueueing it in the completion
                        // queue).
                        let popped_cqe = state_guard.completion_queue.pop();
                        debug_assert!(matches!(popped_cqe, Some(None)));
                        drop(state_guard);
                        // Unsubscribe and wake the others, if any, in order to have them take over.
                        this.wakers.unsubscribe(queue_entry_id, true);
                        return task::Poll::Ready(result);
                    } else {
                        let cqe = state_guard
                            .completion_queue
                            .iter_mut()
                            .find(|cqe| cqe.is_none())
                            .unwrap();
                        *cqe = Some((completed_queue_entry_id, result));
                        let completed_waker = this.wakers.unsubscribe(completed_queue_entry_id, false).flatten();
                        if let Some(completed_waker) = completed_waker {
                            completed_waker.wake();
                        }
                        // Forward the wake_gen for the next iteration.
                        wake_gen = this.wakers.wake_gen();
                    }
                }
                task::Poll::Pending => {
                    let cur_wake_gen = this.wakers.wake_gen();
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

/// [`DerefInnerByTag`](sync_types::DerefInnerByTag) `TAG` for dereferencing
/// [`FutureQueue::wakers`].
///
/// Enables presenting the [`SyncRcPtr`](sync_types::SyncRcPtr) of the
/// [`FutureQueue`] as one for its [`FutureQueue::wakers`] member
/// via the [`SyncRcPtrForInner`](sync_types::SyncRcPtrForInner) mechanism.
struct FutureQueueDerefInnerWakersTag {}

impl<ST: sync_types::SyncTypes, T, F: QueuedFuture<T>> sync_types::DerefInnerByTag<FutureQueueDerefInnerWakersTag>
    for FutureQueue<ST, T, F>
{
    crate::impl_deref_inner_by_tag!(wakers, broadcast_waker::BroadcastWakerSubscriptions<ST>);
}

impl<ST: sync_types::SyncTypes, T, F: QueuedFuture<T>> sync_types::DerefMutInnerByTag<FutureQueueDerefInnerWakersTag>
    for FutureQueue<ST, T, F>
{
    crate::impl_deref_mut_inner_by_tag!(wakers);
}

/// [`Lock`](sync_types::Lock) protected internal [`FutureQueue::state`].
struct FutureQueueState<T, F: QueuedFuture<T>> {
    polling_state: FutureQueuePollingState,
    /// Submission queue.
    ///
    /// Pairs of submission id and enqueued future.
    submission_queue: SyncVec<(broadcast_waker::BroadcastWakerSubscriptionId, F)>,
    /// Completion queue.
    ///
    /// `Option` Pairs of submission id and result.
    /// At future enqueueing time, a `None` placeholder gets pushed. Upon future
    /// completion, the first available `None` entry gets replaced with thr
    /// result.
    completion_queue: SyncVec<Option<(broadcast_waker::BroadcastWakerSubscriptionId, F::Output)>>,
    /// The subscription id associated with the currently active future, i.e.
    /// the one which had been moved into
    /// [`FutureQueue::active_fut`].
    ///
    /// Set to `None` if no future is active or if the currently active one is
    /// to be cancelled.
    active_queue_entry_id: Option<broadcast_waker::BroadcastWakerSubscriptionId>,
}

impl<T, F: QueuedFuture<T>> FutureQueueState<T, F> {
    fn new() -> Self {
        Self {
            polling_state: FutureQueuePollingState::Idle,
            submission_queue: SyncVec::new(),
            completion_queue: SyncVec::new(),
            active_queue_entry_id: None,
        }
    }
}

/// Concurrent polling state of the [`FutureQueue`]'s
/// enqueued[futures](QueuedFuture) tracked at
/// [`FutureQueueState::polling_state`].
///
/// Used for managing exclusive access to the [enqueued futures](QueuedFuture)
/// without holding a [`Lock`](sync_types::Lock), which is possibly of the
/// spinlock kind, over [`QueuedFuture::poll()`](QueuedFuture::poll)
/// invocations.
///
/// Note that updates to the [`FutureQueueState::polling_state`] are done under
/// the protection of a [`Lock`](sync_types::Lock), but that's getting dropped
/// inbetween while a [`QueuedFuture`] is being polled.
///
/// # See also:
///
/// * [`FutureQueueInPollGuard`]
#[derive(PartialEq, Eq)]
enum FutureQueuePollingState {
    /// No thread is currently polling an [enqueued future](QueuedFuture).
    Idle,
    /// A thread is currently exclusively polling the [enqueued
    /// futures](QueuedFuture) and that thread owns a
    /// [`FutureQueueInPollGuard`].
    InPoll,
}

/// Guard for [`FutureQueueState::polling_state`]'s
/// [`InPoll`](FutureQueuePollingState::InPoll) state.
///
/// Held exclusively by the thread currently polling the the [enqueued
/// futures](QueuedFuture).
struct FutureQueueInPollGuard<'a, ST: sync_types::SyncTypes, T, F: QueuedFuture<T>> {
    queue: &'a FutureQueue<ST, T, F>,
    locked_in_poll: bool,
}

impl<'a, ST: sync_types::SyncTypes, T, F: QueuedFuture<T>> FutureQueueInPollGuard<'a, ST, T, F> {
    /// Transition the [`FutureQueueState::polling_state`] from
    /// [`Idle`](FutureQueuePollingState::Idle) to
    /// [`InPoll`](FutureQueuePollingState::InPoll) and return a
    /// `FutureQueueInPollGuard` for it.
    ///
    /// Upon entry, `*state_guard.polling_state` must be
    /// [`Idle`](FutureQueuePollingState::Idle).
    /// Assign [`InPoll`](FutureQueuePollingState::InPoll) and release the
    /// `state_guard` [`Lock`](sync_types::Lock).
    ///
    /// # Arguments:
    ///
    /// * `queue` - The [`FutureQueue`] to lock for polling from the current
    ///   thread.
    /// * `state_guard` - [Locking guard](sync_types::Lock::Guard) for
    ///   `queue.state`.
    fn new<'b>(
        queue: &'a FutureQueue<ST, T, F>,
        mut state_guard: <ST::Lock<FutureQueueState<T, F>> as sync_types::Lock<FutureQueueState<T, F>>>::Guard<'b>,
    ) -> Self {
        state_guard.polling_state = FutureQueuePollingState::InPoll;
        Self {
            queue,
            locked_in_poll: true,
        }
    }

    /// Release the guarded [`FutureQueueState::polling_state`]'s
    /// [`InPoll`](FutureQueuePollingState::InPoll) state.
    ///
    /// Reacquire the  [`FutureQueue::state`]
    /// [`Lock`](sync_types::Lock), switch the `state.polling_state` value back
    /// to [`Idle`](FutureQueuePollingState::Idle) and return the
    /// [`FutureQueue::state`]
    /// [`Lock::Guard`](sync_types::Lock::Guard).
    ///
    /// As long as the returned [`Lock::Guard`](sync_types::Lock::Guard) is
    /// being held, the [`FutureQueueState::polling_state`] value is guaranteed
    /// to remain at [`Idle`](FutureQueuePollingState::Idle) and no
    /// other thread can become the polling thread.
    fn release(mut self) -> <ST::Lock<FutureQueueState<T, F>> as sync_types::Lock<FutureQueueState<T, F>>>::Guard<'a> {
        let mut state_guard = self.queue.state.lock();
        state_guard.polling_state = FutureQueuePollingState::Idle;
        self.locked_in_poll = false;
        state_guard
    }
}

impl<'a, ST: sync_types::SyncTypes, T, F: QueuedFuture<T>> Drop for FutureQueueInPollGuard<'a, ST, T, F> {
    fn drop(&mut self) {
        if self.locked_in_poll {
            self.queue.state.lock().polling_state = FutureQueuePollingState::Idle;
            self.locked_in_poll = false;
        }
    }
}

/// [`DerefInnerByTag`](sync_types::DerefInnerByTag) `TAG` for dereferencing
/// [`FutureQueueState::submission_queue`].
///
/// Enables presenting the [`Lock`](sync_types::Lock) of the
/// [`FutureQueue::state`] member as one
/// for the inner, contained [`FutureQueueState::submission_queue`]
/// via the [`LockForInner`](sync_types::LockForInner) mechanism.
struct FutureQueueStateDerefInnerSubmissionQueueTag;

impl<T, F: QueuedFuture<T>> sync_types::DerefInnerByTag<FutureQueueStateDerefInnerSubmissionQueueTag>
    for FutureQueueState<T, F>
{
    crate::impl_deref_inner_by_tag!(
        submission_queue,
        SyncVec<(broadcast_waker::BroadcastWakerSubscriptionId, F)>
    );
}

impl<T, F: QueuedFuture<T>> sync_types::DerefMutInnerByTag<FutureQueueStateDerefInnerSubmissionQueueTag>
    for FutureQueueState<T, F>
{
    crate::impl_deref_mut_inner_by_tag!(submission_queue);
}

/// [`DerefInnerByTag`](sync_types::DerefInnerByTag) `TAG` for dereferencing
/// [`FutureQueueState::completion_queue`].
///
/// Enables presenting the [`Lock`](sync_types::Lock) of the
/// [`FutureQueue::state`] member as one
/// for the inner, contained [`FutureQueueState::completion_queue`]
/// via the [`LockForInner`](sync_types::LockForInner) mechanism.
struct FutureQueueStateDerefInnerCompletionQueueTag;

impl<T, F: QueuedFuture<T>> sync_types::DerefInnerByTag<FutureQueueStateDerefInnerCompletionQueueTag>
    for FutureQueueState<T, F>
{
    crate::impl_deref_inner_by_tag!(
        completion_queue,
        SyncVec<Option<(broadcast_waker::BroadcastWakerSubscriptionId, F::Output,)>>
    );
}

impl<T, F: QueuedFuture<T>> sync_types::DerefMutInnerByTag<FutureQueueStateDerefInnerCompletionQueueTag>
    for FutureQueueState<T, F>
{
    crate::impl_deref_mut_inner_by_tag!(completion_queue);
}

/// Subscription associated with a [future](QueuedFuture)
/// [`enqueued`](FutureQueue::enqueue) to a [`FutureQueue`].
///
/// An [`EnqueuedFutureSubscription`], instantiated via
/// [`FutureQueue::enqueue()`](FutureQueue::enqueue), is to be used to
/// [`poll()`](Self::poll) for the enqueued [future](QueuedFuture).
///
/// It should be obvious, but it is explictly permitted to concurrently poll on
/// the same [`FutureQueue`] instance from multiple associated subscriptions.
pub struct EnqueuedFutureSubscription<
    ST: sync_types::SyncTypes,
    T,
    F: QueuedFuture<T>,
    QP: sync_types::SyncRcPtr<FutureQueue<ST, T, F>>,
> {
    state: EnqueuedFutureSubscriptionState<ST, T, F, QP>,
}

impl<ST: sync_types::SyncTypes, T, F: QueuedFuture<T>, QP: sync_types::SyncRcPtr<FutureQueue<ST, T, F>>>
    EnqueuedFutureSubscription<ST, T, F, QP>
{
    /// Instantiate a new `EnqueuedFutureSubscription`.
    ///
    /// # Arguments:
    ///
    /// * `queue` - The [`FutureQueue`] the subscription is to.
    /// * `queue_entry_id` - The id associated with the subscription.
    fn new(queue: pin::Pin<QP>, queue_entry_id: broadcast_waker::BroadcastWakerSubscriptionId) -> Self {
        Self {
            state: EnqueuedFutureSubscriptionState::Pending {
                queue,
                queue_entry_id,
                _phantom: marker::PhantomData,
            },
        }
    }

    /// Poll for the associated [enqueued](FutureQueue::enqueue)
    /// [future](QueuedFuture).
    ///
    /// Note that this may drive other futures enqueued ahead in line to
    /// completion first. Wake-up events issued for any future ahead in line
    /// will get broadcasted to the [`Waker`](task::Waker) associated with
    /// `cx`.
    ///
    /// Once the associated future completes with a
    /// [`poll()`](QueuedFuture::poll) return status of
    /// [`Ready`](task::Poll::Ready), the result will get propagated back from
    /// here accordingly (including if the future had in fact been completed by
    /// polling on a different subscription).
    ///
    /// # Arguments:
    ///
    /// * `aux_poll_data` - The reference to pass along for the `aux_data`
    ///   argument of [`QueuedFuture::poll()`](QueuedFuture::poll), for **any
    ///   future polled**, including ones ahead in line not associated with this
    ///   subscription.
    /// * `cx` - Asynchronous task context providing access to a
    ///   [`Waker`](task::Waker).
    pub fn poll(
        &mut self,
        aux_poll_data: &mut F::AuxPollData<'_>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<F::Output> {
        match &self.state {
            EnqueuedFutureSubscriptionState::Pending {
                queue,
                queue_entry_id,
                _phantom,
            } => {
                let result = FutureQueue::poll_from_queue_entry_owner(
                    sync_types::SyncRcPtr::as_ref(queue),
                    *queue_entry_id,
                    aux_poll_data,
                    cx,
                );
                if matches!(result, task::Poll::Ready(_)) {
                    self.state = EnqueuedFutureSubscriptionState::Done;
                }
                result
            }
            EnqueuedFutureSubscriptionState::Done => unreachable!(),
        }
    }
}

impl<ST: sync_types::SyncTypes, T, F: QueuedFuture<T>, QP: sync_types::SyncRcPtr<FutureQueue<ST, T, F>>> Drop
    for EnqueuedFutureSubscription<ST, T, F, QP>
{
    fn drop(&mut self) {
        match &self.state {
            EnqueuedFutureSubscriptionState::Pending {
                queue,
                queue_entry_id,
                _phantom,
            } => {
                queue.cancel_queued(*queue_entry_id);
                self.state = EnqueuedFutureSubscriptionState::Done;
            }
            EnqueuedFutureSubscriptionState::Done => (),
        }
    }
}

/// Private state of [`EnqueuedFutureSubscription`].
enum EnqueuedFutureSubscriptionState<
    ST: sync_types::SyncTypes,
    T,
    F: QueuedFuture<T>,
    QP: sync_types::SyncRcPtr<FutureQueue<ST, T, F>>,
> {
    /// The associated [enqueued future](QueuedFuture) has not been polled to
    /// completion yet.
    Pending {
        /// The [`FutureQueue`] the subscription is to.
        queue: pin::Pin<QP>,
        /// The id associated with the subscription.
        queue_entry_id: broadcast_waker::BroadcastWakerSubscriptionId,
        #[allow(clippy::type_complexity)]
        _phantom: marker::PhantomData<fn() -> (*const ST, *const T, *const F)>,
    },
    Done,
}

#[test]
fn test_future_queue_poll_in_order() {
    use crate::test::{TestAsyncExecutor, TestNopSyncTypes};
    use core::future;

    type TestFutureQueueArbitratedRessourceType = u32;

    struct TestQueuedFuture {}

    impl QueuedFuture<TestFutureQueueArbitratedRessourceType> for TestQueuedFuture {
        type Output = u32;
        type AuxPollData<'a> = ();

        fn poll<'a>(
            self: pin::Pin<&mut Self>,
            arbitrated_ressource: &mut TestFutureQueueArbitratedRessourceType,
            _aux_data: &mut Self::AuxPollData<'a>,
            _cx: &mut task::Context<'_>,
        ) -> task::Poll<Self::Output> {
            *arbitrated_ressource += 1;
            task::Poll::Ready(*arbitrated_ressource)
        }
    }

    type TestFutureQueue = FutureQueue<TestNopSyncTypes, TestFutureQueueArbitratedRessourceType, TestQueuedFuture>;
    type TestFutureQueueSyncRcPtr =
        <<TestNopSyncTypes as sync_types::SyncTypes>::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>::SyncRcPtr<
            TestFutureQueue,
        >;
    type TestEnqueuedFutureSubscription = EnqueuedFutureSubscription<
        TestNopSyncTypes,
        TestFutureQueueArbitratedRessourceType,
        TestQueuedFuture,
        TestFutureQueueSyncRcPtr,
    >;

    struct TestWrapEnqueuedFuture {
        enqueued_future: TestEnqueuedFutureSubscription,
    }

    impl future::Future for TestWrapEnqueuedFuture {
        type Output = <TestQueuedFuture as QueuedFuture<TestFutureQueueArbitratedRessourceType>>::Output;

        fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
            self.get_mut().enqueued_future.poll(&mut (), cx)
        }
    }

    let queue =
        <<TestNopSyncTypes as sync_types::SyncTypes>::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>::try_new(
            FutureQueue::<TestNopSyncTypes, u32, TestQueuedFuture>::new(0),
        )
        .unwrap();
    let queue = unsafe { pin::Pin::new_unchecked(queue) };

    let enqueued0 = FutureQueue::enqueue(queue.clone(), TestQueuedFuture {})
        .map_err(|(_f, e)| e)
        .unwrap();
    let enqueued1 = FutureQueue::enqueue(queue.clone(), TestQueuedFuture {})
        .map_err(|(_f, e)| e)
        .unwrap();
    let enqueued2 = FutureQueue::enqueue(queue.clone(), TestQueuedFuture {})
        .map_err(|(_f, e)| e)
        .unwrap();

    let e = TestAsyncExecutor::new();
    let w0 = TestAsyncExecutor::spawn(
        &e,
        TestWrapEnqueuedFuture {
            enqueued_future: enqueued0,
        },
    );
    let w1 = TestAsyncExecutor::spawn(
        &e,
        TestWrapEnqueuedFuture {
            enqueued_future: enqueued1,
        },
    );
    let w2 = TestAsyncExecutor::spawn(
        &e,
        TestWrapEnqueuedFuture {
            enqueued_future: enqueued2,
        },
    );
    TestAsyncExecutor::run_to_completion(&e);

    assert_eq!(w0.take().unwrap(), 1);
    assert_eq!(w1.take().unwrap(), 2);
    assert_eq!(w2.take().unwrap(), 3);
}

#[test]
fn test_future_queue_poll_in_reverse_order() {
    use crate::test::{TestAsyncExecutor, TestNopSyncTypes};
    use core::future;

    type TestFutureQueueArbitratedRessourceType = u32;

    struct TestQueuedFuture {}

    impl QueuedFuture<TestFutureQueueArbitratedRessourceType> for TestQueuedFuture {
        type Output = u32;
        type AuxPollData<'a> = ();

        fn poll<'a>(
            self: pin::Pin<&mut Self>,
            arbitrated_ressource: &mut TestFutureQueueArbitratedRessourceType,
            _aux_data: &mut Self::AuxPollData<'a>,
            _cx: &mut task::Context<'_>,
        ) -> task::Poll<Self::Output> {
            *arbitrated_ressource += 1;
            task::Poll::Ready(*arbitrated_ressource)
        }
    }

    type TestFutureQueue = FutureQueue<TestNopSyncTypes, TestFutureQueueArbitratedRessourceType, TestQueuedFuture>;
    type TestFutureQueueSyncRcPtr =
        <<TestNopSyncTypes as sync_types::SyncTypes>::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>::SyncRcPtr<
            TestFutureQueue,
        >;
    type TestEnqueuedFutureSubscription = EnqueuedFutureSubscription<
        TestNopSyncTypes,
        TestFutureQueueArbitratedRessourceType,
        TestQueuedFuture,
        TestFutureQueueSyncRcPtr,
    >;

    struct TestWrapEnqueuedFuture {
        enqueued_future: TestEnqueuedFutureSubscription,
    }

    impl future::Future for TestWrapEnqueuedFuture {
        type Output = <TestQueuedFuture as QueuedFuture<TestFutureQueueArbitratedRessourceType>>::Output;

        fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
            self.get_mut().enqueued_future.poll(&mut (), cx)
        }
    }

    let queue =
        <<TestNopSyncTypes as sync_types::SyncTypes>::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>::try_new(
            FutureQueue::<TestNopSyncTypes, u32, TestQueuedFuture>::new(0),
        )
        .unwrap();
    let queue = unsafe { pin::Pin::new_unchecked(queue) };

    let enqueued0 = FutureQueue::enqueue(queue.clone(), TestQueuedFuture {})
        .map_err(|(_f, e)| e)
        .unwrap();
    let enqueued1 = FutureQueue::enqueue(queue.clone(), TestQueuedFuture {})
        .map_err(|(_f, e)| e)
        .unwrap();
    let enqueued2 = FutureQueue::enqueue(queue.clone(), TestQueuedFuture {})
        .map_err(|(_f, e)| e)
        .unwrap();

    let e = TestAsyncExecutor::new();
    let w2 = TestAsyncExecutor::spawn(
        &e,
        TestWrapEnqueuedFuture {
            enqueued_future: enqueued2,
        },
    );
    TestAsyncExecutor::run_to_completion(&e);
    assert_eq!(w2.take().unwrap(), 3);

    let w1 = TestAsyncExecutor::spawn(
        &e,
        TestWrapEnqueuedFuture {
            enqueued_future: enqueued1,
        },
    );
    TestAsyncExecutor::run_to_completion(&e);
    assert_eq!(w1.take().unwrap(), 2);

    let w0 = TestAsyncExecutor::spawn(
        &e,
        TestWrapEnqueuedFuture {
            enqueued_future: enqueued0,
        },
    );
    TestAsyncExecutor::run_to_completion(&e);
    assert_eq!(w0.take().unwrap(), 1);
}

#[test]
fn test_future_queue_cancel_queued() {
    use crate::test::{TestAsyncExecutor, TestNopSyncTypes};
    use core::future;

    type TestFutureQueueArbitratedRessourceType = u32;

    struct TestQueuedFuture {}

    impl QueuedFuture<TestFutureQueueArbitratedRessourceType> for TestQueuedFuture {
        type Output = u32;
        type AuxPollData<'a> = ();

        fn poll<'a>(
            self: pin::Pin<&mut Self>,
            arbitrated_ressource: &mut TestFutureQueueArbitratedRessourceType,
            _aux_data: &mut Self::AuxPollData<'a>,
            _cx: &mut task::Context<'_>,
        ) -> task::Poll<Self::Output> {
            *arbitrated_ressource += 1;
            task::Poll::Ready(*arbitrated_ressource)
        }
    }

    type TestFutureQueue = FutureQueue<TestNopSyncTypes, TestFutureQueueArbitratedRessourceType, TestQueuedFuture>;
    type TestFutureQueueSyncRcPtr =
        <<TestNopSyncTypes as sync_types::SyncTypes>::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>::SyncRcPtr<
            TestFutureQueue,
        >;
    type TestEnqueuedFutureSubscription = EnqueuedFutureSubscription<
        TestNopSyncTypes,
        TestFutureQueueArbitratedRessourceType,
        TestQueuedFuture,
        TestFutureQueueSyncRcPtr,
    >;

    struct TestCancelQueuedFuture {
        enqueued0: TestEnqueuedFutureSubscription,
        enqueued1: Option<TestEnqueuedFutureSubscription>,
        enqueued2: TestEnqueuedFutureSubscription,
    }

    impl future::Future for TestCancelQueuedFuture {
        type Output = ();

        fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<()> {
            let this = self.get_mut();
            drop(this.enqueued1.take());
            assert_eq!(this.enqueued2.poll(&mut (), cx), task::Poll::Ready(2));
            assert_eq!(this.enqueued0.poll(&mut (), cx), task::Poll::Ready(1));
            task::Poll::Ready(())
        }
    }

    let queue =
        <<TestNopSyncTypes as sync_types::SyncTypes>::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>::try_new(
            FutureQueue::<TestNopSyncTypes, u32, TestQueuedFuture>::new(0),
        )
        .unwrap();
    let queue = unsafe { pin::Pin::new_unchecked(queue) };

    let enqueued0 = FutureQueue::enqueue(queue.clone(), TestQueuedFuture {})
        .map_err(|(_f, e)| e)
        .unwrap();
    let enqueued1 = FutureQueue::enqueue(queue.clone(), TestQueuedFuture {})
        .map_err(|(_f, e)| e)
        .unwrap();
    let enqueued2 = FutureQueue::enqueue(queue.clone(), TestQueuedFuture {})
        .map_err(|(_f, e)| e)
        .unwrap();

    let e = TestAsyncExecutor::new();
    let w = TestAsyncExecutor::spawn(
        &e,
        TestCancelQueuedFuture {
            enqueued0,
            enqueued1: Some(enqueued1),
            enqueued2,
        },
    );
    TestAsyncExecutor::run_to_completion(&e);
    w.take().unwrap();
}

#[test]
fn test_future_queue_cancel_active() {
    use crate::test::{TestAsyncExecutor, TestNopSyncTypes};
    use core::future;

    type TestFutureQueueArbitratedRessourceType = u32;

    struct TestQueuedFuture {
        stall_forever: bool,
    }

    impl QueuedFuture<TestFutureQueueArbitratedRessourceType> for TestQueuedFuture {
        type Output = u32;
        type AuxPollData<'a> = ();

        fn poll<'a>(
            self: pin::Pin<&mut Self>,
            arbitrated_ressource: &mut TestFutureQueueArbitratedRessourceType,
            _aux_data: &mut Self::AuxPollData<'a>,
            _cx: &mut task::Context<'_>,
        ) -> task::Poll<Self::Output> {
            if self.stall_forever {
                return task::Poll::Pending;
            }
            *arbitrated_ressource += 1;
            task::Poll::Ready(*arbitrated_ressource)
        }
    }

    type TestFutureQueue = FutureQueue<TestNopSyncTypes, TestFutureQueueArbitratedRessourceType, TestQueuedFuture>;
    type TestFutureQueueSyncRcPtr =
        <<TestNopSyncTypes as sync_types::SyncTypes>::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>::SyncRcPtr<
            TestFutureQueue,
        >;
    type TestEnqueuedFutureSubscription = EnqueuedFutureSubscription<
        TestNopSyncTypes,
        TestFutureQueueArbitratedRessourceType,
        TestQueuedFuture,
        TestFutureQueueSyncRcPtr,
    >;

    struct TestCancelQueuedFuture {
        enqueued0: Option<TestEnqueuedFutureSubscription>,
        enqueued1: TestEnqueuedFutureSubscription,
        enqueued2: TestEnqueuedFutureSubscription,
    }

    impl future::Future for TestCancelQueuedFuture {
        type Output = ();

        fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<()> {
            let this = self.get_mut();
            assert_eq!(this.enqueued0.as_mut().unwrap().poll(&mut (), cx), task::Poll::Pending);
            assert_eq!(this.enqueued1.poll(&mut (), cx), task::Poll::Pending);
            assert_eq!(this.enqueued2.poll(&mut (), cx), task::Poll::Pending);
            drop(this.enqueued0.take());
            assert_eq!(this.enqueued2.poll(&mut (), cx), task::Poll::Ready(2));
            assert_eq!(this.enqueued1.poll(&mut (), cx), task::Poll::Ready(1));
            task::Poll::Ready(())
        }
    }

    let queue =
        <<TestNopSyncTypes as sync_types::SyncTypes>::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>::try_new(
            FutureQueue::<TestNopSyncTypes, u32, TestQueuedFuture>::new(0),
        )
        .unwrap();
    let queue = unsafe { pin::Pin::new_unchecked(queue) };

    let enqueued0 = FutureQueue::enqueue(queue.clone(), TestQueuedFuture { stall_forever: true })
        .map_err(|(_f, e)| e)
        .unwrap();
    let enqueued1 = FutureQueue::enqueue(queue.clone(), TestQueuedFuture { stall_forever: false })
        .map_err(|(_f, e)| e)
        .unwrap();
    let enqueued2 = FutureQueue::enqueue(queue.clone(), TestQueuedFuture { stall_forever: false })
        .map_err(|(_f, e)| e)
        .unwrap();

    let e = TestAsyncExecutor::new();
    let w = TestAsyncExecutor::spawn(
        &e,
        TestCancelQueuedFuture {
            enqueued0: Some(enqueued0),
            enqueued1,
            enqueued2,
        },
    );
    TestAsyncExecutor::run_to_completion(&e);
    w.take().unwrap();
}
