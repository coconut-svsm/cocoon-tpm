// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`AsyncRwLock`]

extern crate alloc;
use super::semaphore;
use crate::sync_types;
use core::ptr;
use core::{convert, future, marker, ops, pin, task};

/// Error information returned by the [`AsyncRwLock`] API.
#[derive(Clone, Copy, Debug)]
pub enum AsyncRwLockError {
    /// A pending operation's associated [`AsyncRwLock`] has been
    /// dropped.
    StaleRwLock,

    /// Memory allocation failure.
    MemoryAllocationFailure,

    /// Internal error.
    Internal,
}

impl convert::From<semaphore::AsyncSemaphoreError> for AsyncRwLockError {
    fn from(value: semaphore::AsyncSemaphoreError) -> Self {
        match value {
            semaphore::AsyncSemaphoreError::RequestExceedsSemaphoreCapacity => AsyncRwLockError::Internal,
            semaphore::AsyncSemaphoreError::StaleSemaphore => AsyncRwLockError::StaleRwLock,
            semaphore::AsyncSemaphoreError::MemoryAllocationFailure => AsyncRwLockError::MemoryAllocationFailure,
            semaphore::AsyncSemaphoreError::Internal => AsyncRwLockError::Internal,
        }
    }
}

/// A Read-Write Lock which can be waited asynchronously for.
///
/// The locking operations [`read()`](Self::read) and [`write()`](Self::write)
/// return [`Future`]s which can subsequently get polled to eventually obtain
/// the lock.
///
/// [`AsyncRwLock`] follows the common Read-Write Lock semantics: locking for
/// writes is mutually exclusive, with either locking type whereas any number of
/// read lockings can be granted at a time.
///
/// `AsyncRwlock` is **not** robust against threads "loosing interest", e.g.
/// because the execution environment somehow abandoned them: any lock waiting
/// [`Future`] acquired from [`read()`](Self::read) or [`write()`](Self::write)
/// must either get polled to completion or dropped, otherwise it might block
/// other waiters for forever. Similar reasoning applies to the lock grant
/// guards themselves: [`AsyncRwLockReadGuard`] and [`AsyncRwLockWriteGuard`]
/// instances may always block other waiters, so it must be made sure that
/// progress is always driven forward for a lock holder until the respective
/// locking guard gets eventually dropped again.
pub struct AsyncRwLock<ST: sync_types::SyncTypes, T> {
    sem: semaphore::AsyncSemaphore<ST, T>,
}

impl<ST: sync_types::SyncTypes, T> AsyncRwLock<ST, T> {
    /// Instantiate a new [`AsyncRwLock`]
    ///
    /// Note that the caller is supposed to move the returned `AsyncSemaphore`
    /// into a [`SyncRcPtr`](sync_types::SyncRcPtr) -- the other parts of
    /// the API expect that.
    ///
    /// # Arguments:
    ///
    /// * `data` - the data to wrap in the the lock.
    pub fn new(data: T) -> Self {
        Self {
            sem: semaphore::AsyncSemaphore::new(0, data),
        }
    }

    /// Asynchronous, non-exclusive locking for read semantics.
    ///
    /// Instantiate a [`AsyncRwLockReadFuture`] for taking the lock
    /// asynchronously for read semantics.
    ///
    /// The returned future will not become ready as long as an exlusive write
    /// locking, i.e. an [`AsyncRwLockWriteGuard`] is active, or some waiter
    /// for an exclusive write locking is ahead in line.
    ///
    /// Note that the mere existence of a [`AsyncRwLockReadFuture`]
    /// returned from this function may block other waiters -- it **must**
    /// always get either polled to completion or dropped again.
    ///
    /// # Errors:
    ///
    /// * [`AsyncRwLockError::MemoryAllocationFailure`] - Memory allocation
    ///   failure.
    pub fn read<'a, LP: 'a + sync_types::SyncRcPtr<Self>, LR: 'a + sync_types::SyncRcPtrRef<'a, Self, LP>>(
        this: &LR,
    ) -> Result<AsyncRwLockReadFuture<ST, T, LP>, AsyncRwLockError>
    where
        Self: 'a,
    {
        let this_sem = sync_types::SyncRcPtrRefForInner::<'_, _, _, _, AsyncRwLockIndexInnerSemTag>::new(this);
        let sem_trivial_lease_fut = semaphore::AsyncSemaphore::acquire_leases(&this_sem, 0)?;
        Ok(AsyncRwLockReadFuture { sem_trivial_lease_fut })
    }

    /// Asynchronous, exclusive locking for write semantics.
    ///
    /// Instantiate a [`AsyncRwLockWriteFuture`] for taking the lock
    /// asynchronously for write semantics.
    ///
    /// The returned future will not become ready as long as some locking of any
    /// type, i.e. an [`AsyncRwLockWriteGuard`] or [`AsyncRwLockReadGuard`]
    /// is active, or some other waiter is ahead in line.
    ///
    /// Note that the mere existence of a [`AsyncRwLockWriteFuture`]
    /// returned from this function may block other waiters -- it **must**
    /// always get either polled to completion or dropped again.
    ///
    /// # Errors:
    ///
    /// * [`AsyncRwLockError::MemoryAllocationFailure`] - Memory allocation
    ///   failure.
    pub fn write<'a, LP: 'a + sync_types::SyncRcPtr<Self>, LR: 'a + sync_types::SyncRcPtrRef<'a, Self, LP>>(
        this: &LR,
    ) -> Result<AsyncRwLockWriteFuture<ST, T, LP>, AsyncRwLockError>
    where
        Self: 'a,
    {
        let this_sem = sync_types::SyncRcPtrRefForInner::<'_, _, _, _, AsyncRwLockIndexInnerSemTag>::new(this);
        let sem_exclusive_all_fut = semaphore::AsyncSemaphore::acquire_exclusive_all(&this_sem)?;
        Ok(AsyncRwLockWriteFuture { sem_exclusive_all_fut })
    }

    /// Try to synchronously acquire lock non-exclusively for read semantics.
    ///
    /// The operation will only succeed and return a [`AsyncRwLockReadGuard`] if
    /// no exclusive locking is active or waited for to become available.
    /// Otherwise [`None`] will get returned.
    pub fn try_read<'a, LP: 'a + sync_types::SyncRcPtr<Self>, LR: 'a + sync_types::SyncRcPtrRef<'a, Self, LP>>(
        this: &LR,
    ) -> Option<AsyncRwLockReadGuard<ST, T, LP>>
    where
        Self: 'a,
    {
        let this_sem = sync_types::SyncRcPtrRefForInner::<'_, _, _, _, AsyncRwLockIndexInnerSemTag>::new(this);
        semaphore::AsyncSemaphore::try_acquire_leases(&this_sem, 0)
            .unwrap()
            .map(|sem_trivial_lease_guard| AsyncRwLockReadGuard {
                sem_trivial_lease_guard,
            })
    }

    /// Try to synchronously acquire lock exclusively for write semantics.
    ///
    /// The operation will only succeed and return a [`AsyncRwLockWriteGuard`]
    /// if no locking is active or waited for to become available.
    /// Otherwise [`None`] will get returned.
    pub fn try_write<'a, LP: 'a + sync_types::SyncRcPtr<Self>, LR: 'a + sync_types::SyncRcPtrRef<'a, Self, LP>>(
        this: &LR,
    ) -> Option<AsyncRwLockWriteGuard<ST, T, LP>>
    where
        Self: 'a,
    {
        let this_sem = sync_types::SyncRcPtrRefForInner::<'_, _, _, _, AsyncRwLockIndexInnerSemTag>::new(this);
        semaphore::AsyncSemaphore::try_acquire_exclusive_all(&this_sem).map(|sem_exclusive_all_guard| {
            AsyncRwLockWriteGuard {
                sem_exclusive_all_guard,
            }
        })
    }
}

/// [`DerefInnerByTag`](sync_types::DerefInnerByTag) `TAG` for dereferencing
/// [`AsyncRwLock::sem`].
///
/// Enables presenting the [`SyncRcPtr`](sync_types::SyncRcPtr) of the
/// [`AsyncRwLock`] as one for its [`AsyncRwLock::sem`] member
/// via the [`SyncRcPtrForInner`](sync_types::SyncRcPtrForInner) mechanism.
struct AsyncRwLockIndexInnerSemTag;

impl<ST: sync_types::SyncTypes, T> sync_types::DerefInnerByTag<AsyncRwLockIndexInnerSemTag> for AsyncRwLock<ST, T> {
    crate::impl_deref_inner_by_tag!(sem, semaphore::AsyncSemaphore<ST, T>);
}

/// Asynchronous wait for non-exclusive locking of an [`AsyncRwLock`].
///
/// To be obtained through [`AsyncRwLock::read()`].
///
/// # Note on lifetime management
///
/// An [`AsyncRwLockReadFuture`] instance will only maintain a weak reference
/// (i.e. a [`WeakSyncRcPtr`](sync_types::WeakSyncRcPtr)) to the associated
/// [`AsyncRwLock`] instance and thus, would not hinder its deallocation. In
/// case the lock gets dropped before the future had a chance to acquire it, its
/// `poll()` would return [`AsyncRwLockError::StaleRwLock`].
pub struct AsyncRwLockReadFuture<ST: sync_types::SyncTypes, T, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, T>>> {
    sem_trivial_lease_fut: semaphore::AsyncSemaphoreLeasesFuture<
        ST,
        T,
        sync_types::SyncRcPtrForInner<AsyncRwLock<ST, T>, LP, AsyncRwLockIndexInnerSemTag>,
    >,
}

impl<ST: sync_types::SyncTypes, T, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, T>>> AsyncRwLockReadFuture<ST, T, LP> {
    /// Obtain the associated [`AsyncRwLock`].
    ///
    /// Return the associated [`AsyncRwLock`] wrapped in `Some` if still
    /// alive, `None` otherwise.
    pub fn get_rwlock(&self) -> Option<LP> {
        self.sem_trivial_lease_fut
            .get_semaphore()
            .map(|sem| sem.into_container())
    }
}

impl<ST: sync_types::SyncTypes, T, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, T>>> marker::Unpin
    for AsyncRwLockReadFuture<ST, T, LP>
{
}

impl<ST: sync_types::SyncTypes, T, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, T>>> future::Future
    for AsyncRwLockReadFuture<ST, T, LP>
{
    type Output = Result<AsyncRwLockReadGuard<ST, T, LP>, AsyncRwLockError>;

    /// Poll for a locking grant of the associated [`AsyncRwLock`].
    ///
    /// Upon future completion, either a [`AsyncRwLockReadGuard`] is returned
    /// or, if the associated [`AsyncRwLock`] had been dropped in the
    /// meanwhile, an error of [`AsyncRwLockError::StaleRwLock`].
    ///
    /// The future must not get polled any further once completed.
    fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        future::Future::poll(pin::Pin::new(&mut self.get_mut().sem_trivial_lease_fut), cx)
            .map_ok(|sem_trivial_lease_guard| AsyncRwLockReadGuard {
                sem_trivial_lease_guard,
            })
            .map_err(AsyncRwLockError::from)
    }
}

/// Non-exclusive locking grant on an [`AsyncRwLock`].
///
/// Besides the common functionality one would expect from a locking guard, it's
/// noteworthy that a `AsyncRwLockReadGuard` instance can get presented as a
/// [`SyncRcPtr`](sync_types) for the [`AsyncRwLock`]'s inner value (or any of
/// its members) via [`AsyncRwLockReadGuardForInner`] to APIs that expect such
/// one.
pub struct AsyncRwLockReadGuard<ST: sync_types::SyncTypes, T, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, T>>> {
    sem_trivial_lease_guard: semaphore::AsyncSemaphoreLeasesGuard<
        ST,
        T,
        sync_types::SyncRcPtrForInner<AsyncRwLock<ST, T>, LP, AsyncRwLockIndexInnerSemTag>,
    >,
}

impl<ST: sync_types::SyncTypes, T, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, T>>> AsyncRwLockReadGuard<ST, T, LP> {
    /// Obtain the associated [`AsyncRwLock`].
    pub fn get_rwlock(&self) -> LP::SyncRcPtrRef<'_> {
        self.sem_trivial_lease_guard.get_semaphore().get_container().clone()
    }

    /// Release the lock and return the associated [`AsyncRwLock`].
    pub fn into_rwlock(self) -> LP {
        self.sem_trivial_lease_guard.into_semaphore().into_container()
    }

    /// Convert into an [`AsyncRwLockReadWeakGuard`] not hindering
    /// destruction of the associated [`AsyncRwLock`].
    pub fn into_weak(self) -> AsyncRwLockReadWeakGuard<ST, T, LP> {
        AsyncRwLockReadWeakGuard {
            sem_trivial_lease_guard: Some(self.sem_trivial_lease_guard.into_weak()),
        }
    }

    /// Convert into a raw pointer to the protected inner value.
    ///
    /// Must eventually get converted back with [`from_raw()`](Self::from_raw)
    /// or the locking grant will be leaked forever.
    fn into_raw(this: Self) -> *const T {
        let (ptr, leases_granted) = this.sem_trivial_lease_guard.into_raw();
        debug_assert_eq!(leases_granted, 0);
        ptr
    }

    /// Convert back from a raw pointer to the protected value obtained from
    /// [`from_raw()`](Self::from_raw).
    ///
    /// # Safety
    ///
    /// The raw pointer to the protected value must have been previously
    /// obtained from [`from_raw()`](Self::from_raw).
    unsafe fn from_raw(ptr: *const T) -> Self {
        let sem_trivial_lease_guard = unsafe { semaphore::AsyncSemaphoreLeasesGuard::from_raw(ptr, 0) };
        Self {
            sem_trivial_lease_guard,
        }
    }
}

impl<ST: sync_types::SyncTypes, T, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, T>>> ops::Deref
    for AsyncRwLockReadGuard<ST, T, LP>
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.sem_trivial_lease_guard
    }
}

impl<ST: sync_types::SyncTypes, T, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, T>>> Clone
    for AsyncRwLockReadGuard<ST, T, LP>
{
    fn clone(&self) -> Self {
        let sem_trivial_lease_guard = self.sem_trivial_lease_guard.spawn_trivial_lease();
        Self {
            sem_trivial_lease_guard,
        }
    }
}

/// Weak variant of [`AsyncRwLockReadGuard`] not hindering destruction of the
/// associated [`AsyncRwLock`].
///
/// In cases were it's desired that long-living locking grants don't prevent a
/// destruction of the associated [`AsyncRwLock`], or to break cycles, a
/// `AsyncRwLockReadWeakGuard` may be used. To be obtained via
/// [`AsyncRwLockReadGuard::into_weak()`].
///
/// An `AsyncRwLockReadWeakGuard` may get converted back into a full
/// [`AsyncRwLockReadGuard`] via [`upgrade()`](Self::upgrade).
pub struct AsyncRwLockReadWeakGuard<ST: sync_types::SyncTypes, T, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, T>>> {
    #[allow(clippy::type_complexity)]
    sem_trivial_lease_guard: Option<
        semaphore::AsyncSemaphoreLeasesWeakGuard<
            ST,
            T,
            sync_types::SyncRcPtrForInner<AsyncRwLock<ST, T>, LP, AsyncRwLockIndexInnerSemTag>,
        >,
    >,
}

impl<ST: sync_types::SyncTypes, T, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, T>>> AsyncRwLockReadWeakGuard<ST, T, LP> {
    /// Attempt to convert back into an [`AsyncRwLockReadGuard`].
    ///
    /// Returns the [`AsyncRwLockReadGuard`] wrapped in `Some` if the
    /// associated [`AsyncRwLock`] is still alive, `None otherwise.
    pub fn upgrade(self) -> Option<AsyncRwLockReadGuard<ST, T, LP>> {
        self.sem_trivial_lease_guard
            .and_then(|sem_trivial_lease_guard| sem_trivial_lease_guard.upgrade())
            .map(|sem_trivial_lease_guard| AsyncRwLockReadGuard {
                sem_trivial_lease_guard,
            })
    }

    /// Attempt to convert back into an [`AsyncRwLockReadGuard`] by reference.
    ///
    /// Returns the [`AsyncRwLockReadGuard`] wrapped in `Some` if the
    /// associated [`AsyncRwLock`] is still alive, `None otherwise.
    fn upgrade_by_ref(&self) -> Option<AsyncRwLockReadGuard<ST, T, LP>> {
        self.sem_trivial_lease_guard
            .as_ref()
            .and_then(|sem_trivial_lease_guard| sem_trivial_lease_guard.try_spawn_trivial_lease())
            .map(|sem_trivial_lease_guard| AsyncRwLockReadGuard {
                sem_trivial_lease_guard,
            })
    }

    /// Convert into a raw pointer to the protected inner value.
    ///
    /// Must eventually get converted back with [`from_raw()`](Self::from_raw)
    /// or the locking grant will be leaked forever.
    ///
    /// The returned raw pointer **must not** be used for anything except for
    /// passing it back to [`from_raw()`](Self::from_raw). In particular it
    /// must not get dereferenced, as the associated [`AsyncRwLock`], and
    /// hence its wrapped value, might have been dropped already.
    fn into_raw(mut this: Self) -> *const T {
        this.sem_trivial_lease_guard
            .take()
            .map(|sem_trivial_lease_guard| {
                let (ptr, leases_granted) = sem_trivial_lease_guard.into_raw();
                debug_assert_eq!(leases_granted, 0);
                ptr
            })
            .unwrap_or(ptr::null())
    }

    /// Convert back from a raw pointer to the protected value obtained from
    /// [`from_raw()`](Self::from_raw).
    ///
    /// # Safety
    ///
    /// The raw pointer to the protected value must have been previously
    /// obtained from [`from_raw()`](Self::from_raw).
    unsafe fn from_raw(ptr: *const T) -> Self {
        if !ptr.is_null() {
            let sem_trivial_lease_guard = unsafe { semaphore::AsyncSemaphoreLeasesWeakGuard::from_raw(ptr, 0) };
            Self {
                sem_trivial_lease_guard: Some(sem_trivial_lease_guard),
            }
        } else {
            Self {
                sem_trivial_lease_guard: None,
            }
        }
    }
}

impl<ST: sync_types::SyncTypes, T, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, T>>> Clone
    for AsyncRwLockReadWeakGuard<ST, T, LP>
{
    fn clone(&self) -> Self {
        let sem_trivial_lease_guard = self
            .sem_trivial_lease_guard
            .as_ref()
            .and_then(|sem_trivial_lease_guard| sem_trivial_lease_guard.try_spawn_trivial_lease())
            .map(|sem_trivial_lease_guard| sem_trivial_lease_guard.into_weak());
        Self {
            sem_trivial_lease_guard,
        }
    }
}

/// Present a `AsyncRwLockReadGuard` instance as a [`SyncRcPtr`](sync_types) for
/// the [`AsyncRwLock`]'s inner value (or any of its members).
///
/// Useful for presenting APIs with a [`SyncRcPtr`](sync_types::SyncRcPtr) to
/// the [`AsyncRwLock`]'s wrapped value or any of its members if needed.
///
/// Users are supposed to implement
/// [`DerefInnerByTag`](sync_types::DerefInnerByTag) the [`AsyncRwLock`]'s
/// wrapped value's type, for a `TAG` routing either to the [`AsyncRwLock`]'s
/// wrapped value itself or to one of its members.
///
/// Note that the [`AsyncRwLockReadGuardForInner`] (as well its cloning spawns)
/// own a read lock on the associated [`AsyncRwLock`] for its whole lifetime. In
/// particular it blocks other tasks waiting to acquire a write lock.
pub struct AsyncRwLockReadGuardForInner<
    ST: sync_types::SyncTypes,
    OT,
    LP: sync_types::SyncRcPtr<AsyncRwLock<ST, OT>>,
    TAG,
> where
    OT: sync_types::DerefInnerByTag<TAG>,
{
    guard_for_outer: AsyncRwLockReadGuard<ST, OT, LP>,
    _phantom: marker::PhantomData<fn() -> TAG>,
}

impl<ST: sync_types::SyncTypes, OT, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, OT>>, TAG> Clone
    for AsyncRwLockReadGuardForInner<ST, OT, LP, TAG>
where
    OT: sync_types::DerefInnerByTag<TAG>,
{
    fn clone(&self) -> Self {
        Self {
            guard_for_outer: self.guard_for_outer.clone(),
            _phantom: marker::PhantomData,
        }
    }
}

impl<ST: sync_types::SyncTypes, OT, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, OT>>, TAG>
    convert::From<AsyncRwLockReadGuard<ST, OT, LP>> for AsyncRwLockReadGuardForInner<ST, OT, LP, TAG>
where
    OT: sync_types::DerefInnerByTag<TAG>,
{
    fn from(value: AsyncRwLockReadGuard<ST, OT, LP>) -> Self {
        Self {
            guard_for_outer: value,
            _phantom: marker::PhantomData,
        }
    }
}

impl<ST: sync_types::SyncTypes, OT, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, OT>>, TAG> ops::Deref
    for AsyncRwLockReadGuardForInner<ST, OT, LP, TAG>
where
    OT: sync_types::DerefInnerByTag<TAG>,
{
    type Target = <OT as sync_types::DerefInnerByTag<TAG>>::Output;

    fn deref(&self) -> &Self::Target {
        <OT as sync_types::DerefInnerByTag<TAG>>::deref_inner(&self.guard_for_outer)
    }
}

impl<ST: sync_types::SyncTypes, OT, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, OT>>, TAG>
    sync_types::SyncRcPtr<<OT as sync_types::DerefInnerByTag<TAG>>::Output>
    for AsyncRwLockReadGuardForInner<ST, OT, LP, TAG>
where
    OT: sync_types::DerefInnerByTag<TAG>,
    <OT as sync_types::DerefInnerByTag<TAG>>::Output: marker::Send + marker::Sync,
{
    type WeakSyncRcPtr = AsyncRwLockReadWeakGuardForInner<ST, OT, LP, TAG>;

    type SyncRcPtrRef<'a>
        = sync_types::GenericSyncRcPtrRef<'a, <OT as sync_types::DerefInnerByTag<TAG>>::Output, Self>
    where
        Self: 'a;

    fn downgrade(&self) -> Self::WeakSyncRcPtr {
        Self::WeakSyncRcPtr::from(self.guard_for_outer.clone().into_weak())
    }

    fn into_raw(this: Self) -> *const <OT as sync_types::DerefInnerByTag<TAG>>::Output {
        let ptr_to_outer = AsyncRwLockReadGuard::into_raw(this.guard_for_outer);
        <OT as sync_types::DerefInnerByTag<TAG>>::to_inner_ptr(ptr_to_outer)
    }

    unsafe fn from_raw(ptr: *const <OT as sync_types::DerefInnerByTag<TAG>>::Output) -> Self {
        let ptr_to_outer = unsafe { <OT as sync_types::DerefInnerByTag<TAG>>::container_of(ptr) };
        let guard_for_outer = unsafe { AsyncRwLockReadGuard::from_raw(ptr_to_outer) };
        Self {
            guard_for_outer,
            _phantom: marker::PhantomData,
        }
    }
}

/// Weak variant of [`AsyncRwLockReadGuardForInner`] not hindering destruction
/// of the associated [`AsyncRwLock`].
///
/// Implements [`WeakSyncRcPtr`](sync_types::WeakSyncRcPtr) and is to be
/// obtained from an [`AsyncRwLockReadGuardForInner`] through the
/// [`SyncRcPtr`](sync_types::SyncRcPtr) API,
/// i.e. via [`SyncRcPtr::downgrade`](sync_types::SyncRcPtr::downgrade).
pub struct AsyncRwLockReadWeakGuardForInner<
    ST: sync_types::SyncTypes,
    OT,
    LP: sync_types::SyncRcPtr<AsyncRwLock<ST, OT>>,
    TAG,
> where
    OT: sync_types::DerefInnerByTag<TAG>,
{
    guard_for_outer: AsyncRwLockReadWeakGuard<ST, OT, LP>,
    _phantom: marker::PhantomData<fn() -> TAG>,
}

impl<ST: sync_types::SyncTypes, OT, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, OT>>, TAG> Clone
    for AsyncRwLockReadWeakGuardForInner<ST, OT, LP, TAG>
where
    OT: sync_types::DerefInnerByTag<TAG>,
{
    fn clone(&self) -> Self {
        Self {
            guard_for_outer: self.guard_for_outer.clone(),
            _phantom: marker::PhantomData,
        }
    }
}

impl<ST: sync_types::SyncTypes, OT, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, OT>>, TAG>
    convert::From<AsyncRwLockReadWeakGuard<ST, OT, LP>> for AsyncRwLockReadWeakGuardForInner<ST, OT, LP, TAG>
where
    OT: sync_types::DerefInnerByTag<TAG>,
{
    fn from(value: AsyncRwLockReadWeakGuard<ST, OT, LP>) -> Self {
        Self {
            guard_for_outer: value,
            _phantom: marker::PhantomData,
        }
    }
}

impl<ST: sync_types::SyncTypes, OT, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, OT>>, TAG>
    sync_types::WeakSyncRcPtr<
        <OT as sync_types::DerefInnerByTag<TAG>>::Output,
        AsyncRwLockReadGuardForInner<ST, OT, LP, TAG>,
    > for AsyncRwLockReadWeakGuardForInner<ST, OT, LP, TAG>
where
    OT: sync_types::DerefInnerByTag<TAG>,
    <OT as sync_types::DerefInnerByTag<TAG>>::Output: marker::Send + marker::Sync,
{
    fn upgrade(&self) -> Option<AsyncRwLockReadGuardForInner<ST, OT, LP, TAG>> {
        self.guard_for_outer
            .upgrade_by_ref()
            .map(|guard_for_outer| AsyncRwLockReadGuardForInner {
                guard_for_outer,
                _phantom: marker::PhantomData,
            })
    }

    fn into_raw(this: Self) -> *const <OT as sync_types::DerefInnerByTag<TAG>>::Output {
        let ptr_to_outer = AsyncRwLockReadWeakGuard::into_raw(this.guard_for_outer);
        <OT as sync_types::DerefInnerByTag<TAG>>::to_inner_ptr(ptr_to_outer)
    }

    unsafe fn from_raw(ptr: *const <OT as sync_types::DerefInnerByTag<TAG>>::Output) -> Self {
        let ptr_to_outer = unsafe { <OT as sync_types::DerefInnerByTag<TAG>>::container_of(ptr) };
        let guard_for_outer = unsafe { AsyncRwLockReadWeakGuard::from_raw(ptr_to_outer) };
        Self {
            guard_for_outer,
            _phantom: marker::PhantomData,
        }
    }
}

/// Asynchronous wait for exclusive locking of an [`AsyncRwLock`].
///
/// To be obtained through [`AsyncRwLock::write()`].
///
/// # Note on lifetime management
///
/// An [`AsyncRwLockWriteFuture`] instance will only maintain a weak reference
/// (i.e. a [`WeakSyncRcPtr`](sync_types::WeakSyncRcPtr)) to the associated
/// [`AsyncRwLock`] instance and thus, would not hinder its deallocation. In
/// case the lock gets dropped before the future had a chance to acquire it, its
/// `poll()` would return [`AsyncRwLockError::StaleRwLock`].
pub struct AsyncRwLockWriteFuture<ST: sync_types::SyncTypes, T, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, T>>> {
    sem_exclusive_all_fut: semaphore::AsyncSemaphoreExclusiveAllFuture<
        ST,
        T,
        sync_types::SyncRcPtrForInner<AsyncRwLock<ST, T>, LP, AsyncRwLockIndexInnerSemTag>,
    >,
}

impl<ST: sync_types::SyncTypes, T, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, T>>> AsyncRwLockWriteFuture<ST, T, LP> {
    pub fn get_rwlock(&self) -> Option<LP> {
        self.sem_exclusive_all_fut
            .get_semaphore()
            .map(|sem| sem.into_container())
    }
}

impl<ST: sync_types::SyncTypes, T, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, T>>> marker::Unpin
    for AsyncRwLockWriteFuture<ST, T, LP>
{
}

impl<ST: sync_types::SyncTypes, T, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, T>>> future::Future
    for AsyncRwLockWriteFuture<ST, T, LP>
{
    type Output = Result<AsyncRwLockWriteGuard<ST, T, LP>, AsyncRwLockError>;

    /// Poll for a locking grant of the associated [`AsyncRwLock`].
    ///
    /// Upon future completion, either a [`AsyncRwLockWriteGuard`] is returned
    /// or, if the associated [`AsyncRwLock`] had been dropped in the
    /// meanwhile, an error of [`AsyncRwLockError::StaleRwLock`].
    ///
    /// The future must not get polled any further once completed.
    fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        future::Future::poll(pin::Pin::new(&mut self.get_mut().sem_exclusive_all_fut), cx)
            .map_ok(|sem_exclusive_all_guard| AsyncRwLockWriteGuard {
                sem_exclusive_all_guard,
            })
            .map_err(AsyncRwLockError::from)
    }
}

/// Exclusive locking grant on an [`AsyncRwLock`].
pub struct AsyncRwLockWriteGuard<ST: sync_types::SyncTypes, T, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, T>>> {
    sem_exclusive_all_guard: semaphore::AsyncSemaphoreExclusiveAllGuard<
        ST,
        T,
        sync_types::SyncRcPtrForInner<AsyncRwLock<ST, T>, LP, AsyncRwLockIndexInnerSemTag>,
    >,
}

impl<ST: sync_types::SyncTypes, T, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, T>>> AsyncRwLockWriteGuard<ST, T, LP> {
    /// Obtain the associated [`AsyncRwLock`].
    pub fn get_rwlock(&self) -> LP::SyncRcPtrRef<'_> {
        self.sem_exclusive_all_guard.get_semaphore().get_container().clone()
    }

    /// Release the lock and return the associated [`AsyncRwLock`].
    pub fn into_rwlock(self) -> LP {
        self.sem_exclusive_all_guard.into_semaphore().into_container()
    }

    /// Convert into an [`AsyncRwLockWriteWeakGuard`] not hindering
    /// destruction of the associated [`AsyncRwLock`].
    pub fn into_weak(self) -> AsyncRwLockWriteWeakGuard<ST, T, LP> {
        AsyncRwLockWriteWeakGuard {
            sem_exclusive_all_guard: self.sem_exclusive_all_guard.into_weak(),
        }
    }

    /// Simultaneously obtain an immutable reference to the associated
    /// [`AsyncRwLock`] as well as a mutable one to its wrapped inner value.
    ///
    /// Mutably dereferencing the [`AsyncRwLockWriteGuard`] to obtain a `mut`
    /// reference on the protected value would result in a borrow on `self`
    /// and thus, prohibits any use of [`get_rwlock()`](Self::get_rwlock)
    /// over the course of the reference's lifetime.
    ///
    /// However, due to the [`AsyncRwLockWriteGuard`]'s locking semantics, there
    /// isn't anything problematic about immutably referencing the
    /// associated [`AsyncRwLock`] at the same time. It's useful in e.g.
    /// situations where the lock lives in some zero-overhead
    /// [`SyncRcPtrForInner`](sync_types::SyncRcPtrForInner) and one seeks to
    /// obtain a reference to the container starting out from the lock
    /// guard.
    pub fn borrow_outer_inner_mut<'a>(&'a mut self) -> (LP::SyncRcPtrRef<'a>, &'a mut T) {
        let (sem, v) = self.sem_exclusive_all_guard.borrow_outer_inner_mut();
        (sem.get_container().clone(), v)
    }
}

impl<ST: sync_types::SyncTypes, T, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, T>>> ops::Deref
    for AsyncRwLockWriteGuard<ST, T, LP>
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.sem_exclusive_all_guard
    }
}

impl<ST: sync_types::SyncTypes, T, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, T>>> ops::DerefMut
    for AsyncRwLockWriteGuard<ST, T, LP>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.sem_exclusive_all_guard
    }
}

/// Weak variant of [`AsyncRwLockWriteGuard`] not hindering destruction of the
/// associated [`AsyncRwLock`].
///
/// In cases were it's desired that long-living locking grants don't prevent a
/// destruction of the associated [`AsyncRwLock`], or to break cycles, a
/// `AsyncRwLockWriteWeakGuard` may be used. To be obtained via
/// [`AsyncRwLockWriteGuard::into_weak()`].
///
/// An `AsyncRwLockWriteWeakGuard` may get converted back into a full
/// [`AsyncRwLockWriteGuard`] via [`upgrade()`](Self::upgrade).
pub struct AsyncRwLockWriteWeakGuard<ST: sync_types::SyncTypes, T, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, T>>> {
    sem_exclusive_all_guard: semaphore::AsyncSemaphoreExclusiveAllWeakGuard<
        ST,
        T,
        sync_types::SyncRcPtrForInner<AsyncRwLock<ST, T>, LP, AsyncRwLockIndexInnerSemTag>,
    >,
}

impl<ST: sync_types::SyncTypes, T, LP: sync_types::SyncRcPtr<AsyncRwLock<ST, T>>> AsyncRwLockWriteWeakGuard<ST, T, LP> {
    /// Attempt to convert back into an [`AsyncRwLockWriteGuard`].
    ///
    /// Returns the [`AsyncRwLockWriteGuard`] wrapped in `Some` if the
    /// associated [`AsyncRwLock`] is still alive, `None otherwise.
    pub fn upgrade(self) -> Option<AsyncRwLockWriteGuard<ST, T, LP>> {
        self.sem_exclusive_all_guard
            .upgrade()
            .map(|sem_exclusive_all_guard| AsyncRwLockWriteGuard {
                sem_exclusive_all_guard,
            })
    }
}
