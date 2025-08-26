// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Testing [`TestNopSyncTypes`] and a [`Future`] [test
//! exector](TestAsyncExecutor) implementations.

extern crate alloc;
use alloc::{boxed::Box, sync};

use crate::{
    alloc::SyncVec,
    sync_types::{self, Lock as _},
};
use core::{cell, convert, future, marker, ops, pin, sync::atomic, task};

/// Dummy [`Lock`](sync_types::Lock) for testing purposes.
///
/// Any attempt to lock an already locked `TestNopLock` will panic.
pub struct TestNopLock<T: marker::Send> {
    locked: atomic::AtomicBool,
    v: cell::UnsafeCell<T>,
}

impl<T: marker::Send> convert::From<T> for TestNopLock<T> {
    fn from(value: T) -> Self {
        Self {
            locked: atomic::AtomicBool::new(false),
            v: cell::UnsafeCell::new(value),
        }
    }
}

unsafe impl<T: marker::Send> marker::Send for TestNopLock<T> {}
unsafe impl<T: marker::Send> marker::Sync for TestNopLock<T> {}

impl<T: marker::Send> sync_types::Lock<T> for TestNopLock<T> {
    type Guard<'a>
        = TestNopLockGuard<'a, T>
    where
        Self: 'a;

    fn lock(&self) -> Self::Guard<'_> {
        assert_eq!(
            self.locked
                .compare_exchange(false, true, atomic::Ordering::Acquire, atomic::Ordering::Relaxed),
            Ok(false),
            "Testing TestNopLocks are not expected to ever be contended."
        );
        TestNopLockGuard { lock: self }
    }
}

impl<T: marker::Send> sync_types::ConstructibleLock<T> for TestNopLock<T> {
    fn get_mut(&mut self) -> &mut T {
        assert!(!self.locked.load(atomic::Ordering::Relaxed));
        let p = self.v.get();
        unsafe { &mut *p }
    }
}

/// The [locking guard](sync_types::Lock::Guard) associated with
/// [`TestNopLock`].
pub struct TestNopLockGuard<'a, T: marker::Send> {
    lock: &'a TestNopLock<T>,
}

impl<'a, T: marker::Send> Drop for TestNopLockGuard<'a, T> {
    fn drop(&mut self) {
        assert_eq!(
            self.lock
                .locked
                .compare_exchange(true, false, atomic::Ordering::Acquire, atomic::Ordering::Relaxed),
            Ok(true),
            "Testing TestNopLock with active lock guard found unlocked."
        );
    }
}

impl<'a, T: marker::Send> ops::Deref for TestNopLockGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        let p = self.lock.v.get();
        // Safety: the very purpose of a Lock is exclusive access, so no aliasing.
        unsafe { &*p }
    }
}

impl<'a, T: marker::Send> ops::DerefMut for TestNopLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let p = self.lock.v.get();
        // Safety: the very purpose of a Lock is exclusive access, so no aliasing.
        unsafe { &mut *p }
    }
}

/// Dummy [`RwLock`](sync_types::RwLock) for testing purposes.
///
/// Any attempt to lock a read-locked `TestNopLock` for write or vice versa will
/// panic.
pub struct TestNopRwLock<T: marker::Send + marker::Sync> {
    locked: atomic::AtomicIsize,
    v: cell::UnsafeCell<T>,
}

impl<T: marker::Send + marker::Sync> convert::From<T> for TestNopRwLock<T> {
    fn from(value: T) -> Self {
        Self {
            locked: atomic::AtomicIsize::new(0),
            v: cell::UnsafeCell::new(value),
        }
    }
}

unsafe impl<T: marker::Send + marker::Sync> marker::Send for TestNopRwLock<T> {}
unsafe impl<T: marker::Send + marker::Sync> marker::Sync for TestNopRwLock<T> {}

impl<T: marker::Send + marker::Sync> sync_types::RwLock<T> for TestNopRwLock<T> {
    type ReadGuard<'a>
        = TestNopRwLockReadGuard<'a, T>
    where
        Self: 'a;
    type WriteGuard<'a>
        = TestNopRwLockWriteGuard<'a, T>
    where
        Self: 'a;

    fn read(&self) -> Self::ReadGuard<'_> {
        assert!(
            self.locked.fetch_add(1, atomic::Ordering::Acquire) >= 0,
            "Testing TestNopRwLocks are not expected to ever be contended."
        );
        TestNopRwLockReadGuard { lock: self }
    }

    fn write(&self) -> Self::WriteGuard<'_> {
        assert_eq!(
            self.locked.fetch_sub(1, atomic::Ordering::Acquire),
            0,
            "Testing TestNopRwLocks are not expected to ever be contended."
        );
        TestNopRwLockWriteGuard { lock: self }
    }

    fn get_mut(&mut self) -> &mut T {
        assert_eq!(self.locked.load(atomic::Ordering::Relaxed), 0);
        let p = self.v.get();
        unsafe { &mut *p }
    }
}

/// The [read lock guard](sync_types::RwLock::ReadGuard) associated with
/// [`TestNopRwLock`].
pub struct TestNopRwLockReadGuard<'a, T: marker::Send + marker::Sync> {
    lock: &'a TestNopRwLock<T>,
}

impl<'a, T: marker::Send + marker::Sync> Drop for TestNopRwLockReadGuard<'a, T> {
    fn drop(&mut self) {
        assert!(
            self.lock.locked.fetch_sub(1, atomic::Ordering::Release) > 0,
            "Testing TestNopRwLock with active read guard found unlocked or write locked."
        );
    }
}

impl<'a, T: marker::Send + marker::Sync> ops::Deref for TestNopRwLockReadGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        let p = self.lock.v.get();
        // Safety: the very purpose of a RwLock is exclusive Writers, so no
        // aliasing with mutable references.
        unsafe { &*p }
    }
}

/// The [write lock guard](sync_types::RwLock::WriteGuard) associated with
/// [`TestNopRwLock`].
pub struct TestNopRwLockWriteGuard<'a, T: marker::Send + marker::Sync> {
    lock: &'a TestNopRwLock<T>,
}

impl<'a, T: marker::Send + marker::Sync> Drop for TestNopRwLockWriteGuard<'a, T> {
    fn drop(&mut self) {
        assert_eq!(
            self.lock.locked.fetch_add(1, atomic::Ordering::Release),
            -1,
            "Testing TestNopRwLock with active lock write guard found unlocked or read locked."
        );
    }
}

impl<'a, T: marker::Send + marker::Sync> ops::Deref for TestNopRwLockWriteGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        let p = self.lock.v.get();
        // Safety: the very purpose of a RwLock is exclusive Writers, so no
        // aliasing with mutable references.
        unsafe { &*p }
    }
}

impl<'a, T: marker::Send + marker::Sync> ops::DerefMut for TestNopRwLockWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let p = self.lock.v.get();
        // Safety: the very purpose of a RwLock is exclusive Writers, so no
        // aliasing with mutable references.
        unsafe { &mut *p }
    }
}

/// Dummy [`SyncTypes`](sync_types::SyncTypes) collection for testing purposes.
pub struct TestNopSyncTypes;

impl sync_types::SyncTypes for TestNopSyncTypes {
    type Lock<T: marker::Send> = TestNopLock<T>;
    type RwLock<T: marker::Send + marker::Sync> = TestNopRwLock<T>;
    type SyncRcPtrFactory = sync_types::GenericArcFactory;
}

/// Dyn dispatcher trait to a [`Future`] enqueued at [`TestAsyncExecutor`].
///
/// # See also:
///
/// * [`QueuedTask`]
trait QueuedTaskDispatch: marker::Send {
    /// Poll the wrapped [`Future`].
    ///
    /// Return true once the wrapped [`Future`]'s
    /// [`poll()`](future::Future::poll) returns
    /// [`Ready`](task::Poll::Ready), `false` otherwise.
    fn poll_pinned(&mut self, cx: &mut task::Context<'_>) -> bool;
}

/// Dyn dispatcher to a [`Future`] enqueued at [`TestAsyncExecutor`].
///
/// As the individual enqueued [`Future`]s can all have different
/// [`Output`](future::Future::Output) types, it is not possible to store them
/// as `dyn` objects and dispatch to their [`poll()`](future::Future::poll)
/// implementations directly, hence the indirection.
struct QueuedTask<F: future::Future + Send>
where
    F::Output: Send + 'static,
{
    /// The queued [`Future`].
    f: F,
    /// The result, stored once `f`'s [`poll()`](future::Future::poll) returns
    /// [`Ready`](task::Poll::Ready).
    ///
    /// The `result` is shared with and can get stolen by the task's associated
    /// [`TestAsyncExecutorTaskWaiter`].
    result: sync_types::GenericArc<TestNopLock<Option<F::Output>>>,
}

impl<F: future::Future + Send> QueuedTaskDispatch for QueuedTask<F>
where
    F::Output: Send + 'static,
{
    fn poll_pinned(&mut self, cx: &mut task::Context<'_>) -> bool {
        // Safety: always called with actually pinned &mut self, as part of the
        // contract.
        let f = unsafe { pin::Pin::new_unchecked(&mut self.f) };
        match future::Future::poll(f, cx) {
            task::Poll::Ready(result) => {
                *self.result.lock() = Some(result);
                true
            }
            task::Poll::Pending => false,
        }
    }
}

/// Runnable status of a [`TaskQueueEntry`] enqueued at [`TestAsyncExecutor`].
enum TaskStatus {
    /// The task is blocked, i.e. the associated [`Future`]'s
    /// [`poll()`](future::Future::poll)
    /// returned [`Pending`](task::Poll::Pending) and the task has not been
    /// woken yet.
    Blocked,
    /// The task is runnable and can be polled, i.e. it's either been freshly
    /// enqueued or woken.
    Runnable,
}

/// State for top-level [`Future`] entry [enqueued](TestAsyncExecutor::spawn) at
/// a [`TestAsyncExecutor`].
struct TaskQueueEntry {
    /// The task id assigned to the associated enqueued top-level [`Future`]
    /// by the containing [executor](TestAsyncExecutor).
    id: u64,
    /// Runnable status of the top-level [`Future`].
    status: TaskStatus,
    /// The enqueued top-level [`Future`].
    task: Option<pin::Pin<Box<dyn QueuedTaskDispatch>>>,
    /// [`Waker`](task::Waker) installed on behalf of the
    /// [`TestAsyncExecutorTaskWaiter`]'s
    /// [`Future::poll()`](future::Future::poll) implementation, if any.
    waiter_waker: Option<task::Waker>,
}

/// A [`Waker`](task::Waker) for the [`TestAsyncExecutor`].
struct Waker {
    task_id: u64,
    executor: sync_types::GenericArc<TestAsyncExecutor>,
}

impl alloc::task::Wake for Waker {
    fn wake(self: sync::Arc<Self>) {
        let executor = &self.executor;
        let mut tasks = executor.tasks.lock();
        for t in tasks.iter_mut() {
            if t.id == self.task_id && matches!(t.status, TaskStatus::Blocked) {
                t.status = TaskStatus::Runnable
            }
        }
    }
}

enum TaskWaiterState<T: marker::Send> {
    Pending {
        /// Executor the associated top-level [`Future`] had been enqueued to.
        executor: sync_types::GenericArc<TestAsyncExecutor>,
        /// The task id assigned to the associated enqueued top-level [`Future`]
        /// by the `executor`.
        task_id: u64,
        /// Pointer to the [`Future::Output`] slot shared with
        /// [`QueuedTask::result`]
        result: sync_types::GenericArc<TestNopLock<Option<T>>>,
    },
    Done,
}

/// Waiter to be returned for top level [`Future`]s via
/// [`TestAsyncExecutor::spawn()`](TestAsyncExecutor::spawn).
///
/// A `TestAsyncExecutorTaskWaiter` provides a means to obtain the
/// [`Output`](future::Future::Output) of the associated enqueued [`Future`]
/// when [`Ready`](task::Poll::Ready).
///
/// Note that a [`TestAsyncExecutorTaskWaiter`] implements [`Future`] itself, so
/// it can get enqueued to the [`TestAsyncExecutor`] or polled from another
/// owning [`Future`].
pub struct TestAsyncExecutorTaskWaiter<T: marker::Send> {
    state: TaskWaiterState<T>,
}

impl<T: marker::Send> TestAsyncExecutorTaskWaiter<T> {
    /// Take the associated enqueued [`Future`]'s
    /// [`Output`](future::Future::Output) if [`Ready`](task::Poll::Ready).
    ///
    /// Returns `None` if the (future::Future::Output) is not
    /// [`Ready`](task::Poll::Ready) yet or the result has already been
    /// taken, including through [`Self::poll()`](Self::poll).
    pub fn take(mut self) -> Option<T> {
        match &mut self.state {
            TaskWaiterState::Pending {
                executor: _,
                task_id: _,
                result,
            } => {
                let result = result.lock().take();
                self.state = TaskWaiterState::Done;
                result
            }
            TaskWaiterState::Done => None,
        }
    }
}

impl<T: marker::Send> Drop for TestAsyncExecutorTaskWaiter<T> {
    fn drop(&mut self) {
        match &self.state {
            TaskWaiterState::Pending {
                executor,
                task_id,
                result,
            } => {
                if !result.lock().is_some() {
                    executor.remove_task(*task_id);
                }
            }
            TaskWaiterState::Done => (),
        }
    }
}

impl<T: marker::Send> Unpin for TestAsyncExecutorTaskWaiter<T> {}

impl<T: marker::Send> future::Future for TestAsyncExecutorTaskWaiter<T> {
    type Output = T;

    fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.get_mut();
        match &this.state {
            TaskWaiterState::Pending {
                executor,
                task_id,
                result,
            } => {
                let mut locked_result = result.lock();
                if let Some(result) = locked_result.take() {
                    drop(locked_result);
                    this.state = TaskWaiterState::Done;
                    task::Poll::Ready(result)
                } else {
                    let mut tasks = executor.tasks.lock();
                    let task = tasks.iter_mut().find(|task| task.id == *task_id).unwrap();
                    task.waiter_waker = Some(cx.waker().clone());
                    task::Poll::Pending
                }
            }
            TaskWaiterState::Done => unreachable!(),
        }
    }
}

/// Single-threaded [`Future`] task executor for testing purposes.
///
/// Enqueue top-level [`Future`]s via [`spawn()`](Self::spawn) and
/// poll all currently enqueued ones to completion via
/// [`run_to_completion()`](Self::run_to_completion).
///
/// Enqueued [`Future`]s may [enqueue](Self::spawn) further ones from their
/// [`Future::poll()`](future::Future::poll) and poll on the resulting
/// [`TestAsyncExecutorTaskWaiter`].
pub struct TestAsyncExecutor {
    /// All enqueued top-level [`Future`]s.
    tasks: TestNopLock<SyncVec<TaskQueueEntry>>,
    /// The task id to assign to the next [`Future`] to get
    /// [enqueued](Self::spawn).
    next_id: atomic::AtomicU64,
}

impl TestAsyncExecutor {
    /// Create a new [`TestAsyncExecutor`] instance.
    pub fn new() -> sync_types::GenericArc<Self> {
        <sync_types::GenericArcFactory as sync_types::SyncRcPtrFactory>::try_new(Self {
            tasks: TestNopLock::from(SyncVec::new()),
            next_id: atomic::AtomicU64::new(0),
        })
        .unwrap()
    }

    /// Enqueue a top-level [`Future`] for polling from a subsequent
    /// [`run_to_completion()`](Self::run_to_completion) invocation.
    ///
    /// # See also:
    /// * [`TestAsyncExecutorTaskWaiter`]
    /// * [`run_to_completion()`](Self::run_to_completion)
    pub fn spawn<F: future::Future + Send + 'static>(
        this: &sync_types::GenericArc<Self>,
        f: F,
    ) -> TestAsyncExecutorTaskWaiter<F::Output>
    where
        F::Output: Send + 'static,
    {
        let id = this.next_id.fetch_add(1, atomic::Ordering::Relaxed);

        let result =
            <sync_types::GenericArcFactory as sync_types::SyncRcPtrFactory>::try_new(TestNopLock::from(None)).unwrap();
        let waiter = TestAsyncExecutorTaskWaiter {
            state: TaskWaiterState::Pending {
                executor: this.clone(),
                task_id: id,
                result: result.clone(),
            },
        };

        let task = Box::pin(QueuedTask { f, result }) as pin::Pin<Box<dyn QueuedTaskDispatch>>;
        let tasks = this.tasks.lock();
        let (mut tasks, r) = SyncVec::try_reserve_exact(&this.tasks, tasks, 1);
        r.unwrap();
        tasks.push(TaskQueueEntry {
            id,
            status: TaskStatus::Runnable,
            task: Some(task),
            waiter_waker: None,
        });

        waiter
    }

    fn remove_task(&self, id: u64) {
        let mut tasks = self.tasks.lock();
        if let Some(index) = tasks.iter().position(|task| task.id == id) {
            // Removing/Dropping the task might drop further TaskWaiter instances held by
            // that task, which would in turn invoke this function and try to
            // get self.tasks for writing.
            let entry = tasks.remove(index);
            drop(tasks);
            drop(entry);
        };
    }

    /// Poll all currently [enqueued](Self::spawn) [`Future`]s to completion.
    ///
    /// A [`Future`] is in "runnable" state right after it has been
    /// [`enqueued`](Self::spawn) and ceases to once its
    /// [`Future::poll()`](future::Future::poll) returns a status of
    /// [`Pending`](task::Poll::Pending). A non-runnable [`Future`] becomes
    /// runnable again when [woken](task::Waker::wake). There must always be at
    /// least one runnable [`Future`] left, or the executor will become
    /// stuck and report the fact via a panic.
    ///
    /// `run_to_completion()` polls the runnable enqueued [`Future`] in a
    /// round-robin fashion, in the order of their enqueueing. That is, if
    /// futures `[a, b, c]` are enqueued, with `a` non-runnable and `b` and
    /// `c` runnable, and the cursor is at `a` or `b`, then `b` will get polled
    /// first, followed by `c`, followed by `a` if that became runnable in the
    /// course of polling `b` or `c`.
    pub fn run_to_completion(this: &sync_types::GenericArc<Self>) {
        let mut last_polled: Option<(usize, u64)> = None;
        loop {
            let mut tasks = this.tasks.lock();
            if tasks.is_empty() {
                break;
            }

            // Determine the next task to examine: either the one with the next larger task
            // id, if any, or wrap around to the beginning.
            let mut search_begin = match last_polled {
                Some((last_index, last_task_id)) => {
                    // The saved index is only an approximate hint, because self.tasks might have
                    // changed when its lock was released. Search downwards for
                    // the last entry before index with a task id <= the last
                    // one, and search upward from there for the one with the next higher id.
                    let last_index = last_index.min(tasks.len());
                    let last_before_leq = tasks[..last_index]
                        .iter()
                        .rposition(|entry| entry.id <= last_task_id)
                        .unwrap_or(0);
                    match tasks
                        .iter()
                        .enumerate()
                        .skip(last_before_leq)
                        .find(|(_, entry)| entry.id > last_task_id)
                    {
                        Some((index, _)) => index,
                        None => {
                            // No task with a higher id than the last one. Wrap around.
                            0
                        }
                    }
                }
                None => 0,
            };
            let index = loop {
                match tasks
                    .iter()
                    .enumerate()
                    .skip(search_begin)
                    .find(|(_, entry)| matches!(entry.status, TaskStatus::Runnable))
                {
                    Some((index, _)) => break Some(index),
                    None => {
                        // Wrap around if the search hasn't started from the beginning already.
                        if search_begin == 0 {
                            break None;
                        }
                        search_begin = 0;
                    }
                }
            };
            let index = index.expect("TestAsyncExecutor stuck with no runnable task.");

            let entry = &mut tasks[index];
            let task_id = entry.id;
            last_polled = Some((index, task_id));
            // Temporarily steal the QueueTask for invoking it below with self.tasks[]
            // unlocked.
            let mut task = match entry.task.take() {
                Some(task) => task,
                None => {
                    continue;
                }
            };
            // Set the status to blocked now, so that any wake-ups from wakers
            // won't get missed.
            entry.status = TaskStatus::Blocked;
            // Drop the tasks lock for the duration of polling the task --
            // it might want to spawn more tasks or drop some TaskWaiters.
            drop(tasks);

            let waker = task::Waker::from(sync::Arc::new(Waker {
                task_id,
                executor: this.clone(),
            }));
            let mut cx = task::Context::from_waker(&waker);
            // Safety: poll_pinned() immediately repins it.
            let done = unsafe { task.as_mut().get_unchecked_mut() }.poll_pinned(&mut cx);

            let task = if done {
                // Dropping the task might drop further TaskWaiter instances held by
                // that task, which would invoke Self::remove_task() and try to
                // get self.tasks for writing. Do it here outside the self.tasks lock.
                drop(task);
                None
            } else {
                Some(task)
            };

            let mut tasks = this.tasks.lock();
            // While the lock had been released, self.tasks[] could potentially have
            // been mutated. Find the index corresponding to the task_id saved away above.
            let updated_index = if index < tasks.len() && tasks[index].id == task_id {
                // Position is unchanged.
                index
            } else {
                match tasks.iter().position(|entry| entry.id == task_id) {
                    Some(updated_index) => updated_index,
                    None => {
                        // The task has gone, presumably because its associated TaskWaiter had
                        // been dropped.
                        continue;
                    }
                }
            };
            last_polled = Some((updated_index, task_id));

            if done {
                let waiter_waker = tasks[updated_index].waiter_waker.take();
                tasks.remove(updated_index);
                if let Some(waiter_waker) = waiter_waker {
                    drop(tasks);
                    waiter_waker.wake();
                }
            } else {
                let entry = &mut tasks[updated_index];
                // Restore the pointer to the QueuedTask, which had temporarily
                // been taken before the poll() invocation above.
                entry.task = task;
            }
        }
    }
}

#[test]
fn test_test_async_executor_simple() {
    struct SimpleTask {}

    impl future::Future for SimpleTask {
        type Output = u32;

        fn poll(self: pin::Pin<&mut Self>, _cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
            task::Poll::Ready(42)
        }
    }

    let executor = TestAsyncExecutor::new();
    let waiter = TestAsyncExecutor::spawn(&executor, SimpleTask {});
    TestAsyncExecutor::run_to_completion(&executor);
    assert_eq!(waiter.take().unwrap(), 42);
    assert_eq!(sync_types::GenericArc::strong_count(&executor), 1);
    assert_eq!(sync_types::GenericArc::weak_count(&executor), 0);

    let waiter = TestAsyncExecutor::spawn(&executor, async { async { 42 }.await });
    TestAsyncExecutor::run_to_completion(&executor);
    assert_eq!(waiter.take().unwrap(), 42);
    assert_eq!(sync_types::GenericArc::strong_count(&executor), 1);
    assert_eq!(sync_types::GenericArc::weak_count(&executor), 0);
}

#[test]
fn test_test_async_executor_chained_waiters() {
    struct SimpleTask {}

    impl future::Future for SimpleTask {
        type Output = u32;

        fn poll(self: pin::Pin<&mut Self>, _cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
            task::Poll::Ready(42)
        }
    }

    let executor = TestAsyncExecutor::new();
    let waiter = TestAsyncExecutor::spawn(&executor, SimpleTask {});
    let waiter = TestAsyncExecutor::spawn(&executor, waiter);
    let waiter = TestAsyncExecutor::spawn(&executor, waiter);
    TestAsyncExecutor::run_to_completion(&executor);
    assert_eq!(waiter.take().unwrap(), 42);
    assert_eq!(sync_types::GenericArc::strong_count(&executor), 1);
    assert_eq!(sync_types::GenericArc::weak_count(&executor), 0);
}

#[test]
fn test_test_async_executor_recursive_spawning() {
    use ops::DerefMut as _;

    enum SpawningTask {
        Init {
            executor: sync_types::GenericArc<TestAsyncExecutor>,
            n: u32,
        },
        WaitingForSpawn {
            waiter: TestAsyncExecutorTaskWaiter<u32>,
        },
    }

    impl Unpin for SpawningTask {}

    impl future::Future for SpawningTask {
        type Output = u32;

        fn poll(mut self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
            match self.deref_mut() {
                Self::Init { executor, n } => {
                    if *n == 0 {
                        task::Poll::Ready(0)
                    } else {
                        let mut waiter = TestAsyncExecutor::spawn(
                            executor,
                            SpawningTask::Init {
                                executor: executor.clone(),
                                n: *n - 1,
                            },
                        );
                        match future::Future::poll(pin::Pin::new(&mut waiter), cx) {
                            task::Poll::Ready(_) => {
                                // The task associated with the waiter did not have a chance to run
                                // yet.
                                unreachable!();
                            }
                            task::Poll::Pending => {
                                *self.deref_mut() = Self::WaitingForSpawn { waiter };
                                task::Poll::Pending
                            }
                        }
                    }
                }
                Self::WaitingForSpawn { waiter } => {
                    match future::Future::poll(pin::Pin::new(waiter), cx) {
                        task::Poll::Ready(n) => task::Poll::Ready(n + 1),
                        task::Poll::Pending => {
                            // This future's task should have been woken only once
                            // the waiter has become ready.
                            unreachable!();
                        }
                    }
                }
            }
        }
    }

    let executor = TestAsyncExecutor::new();
    let waiter = TestAsyncExecutor::spawn(
        &executor,
        SpawningTask::Init {
            executor: executor.clone(),
            n: 42,
        },
    );
    TestAsyncExecutor::run_to_completion(&executor);
    assert_eq!(waiter.take().unwrap(), 42);
    assert_eq!(sync_types::GenericArc::strong_count(&executor), 1);
    assert_eq!(sync_types::GenericArc::weak_count(&executor), 0);
}

#[test]
fn test_test_async_executor_wake_self() {
    use ops::Deref as _;

    enum SelfWakingTask {
        Unpolled,
        PolledOnce,
    }

    impl Unpin for SelfWakingTask {}

    impl future::Future for SelfWakingTask {
        type Output = u32;

        fn poll(mut self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
            match self.deref() {
                Self::Unpolled => {
                    cx.waker().wake_by_ref();
                    *self = Self::PolledOnce;
                    task::Poll::Pending
                }
                Self::PolledOnce => task::Poll::Ready(42),
            }
        }
    }

    let executor = TestAsyncExecutor::new();
    let waiter = TestAsyncExecutor::spawn(&executor, SelfWakingTask::Unpolled);
    let waiter = TestAsyncExecutor::spawn(&executor, waiter);
    TestAsyncExecutor::run_to_completion(&executor);
    assert_eq!(waiter.take().unwrap(), 42);
    assert_eq!(sync_types::GenericArc::strong_count(&executor), 1);
    assert_eq!(sync_types::GenericArc::weak_count(&executor), 0);
}
