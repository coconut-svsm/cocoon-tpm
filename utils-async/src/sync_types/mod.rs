// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Lock and `Arc` abstraction traits as well as related functionality.
//!
//! # Execution environment agnostic sync type abstractions
//!
//! In `[no_std]` environments, the `std::sync::Mutex` or `std::sync::RwLock`
//! are unavailable and the exact semantics of a provided lock implementation
//! depend heavily on the target execution environment -- it could be anything
//! ranging from a simple spinlock up to a full blown mutex with scheduling
//! semantics. In order to facilitate integrations into any possible
//! environment, define abstraction traits for locks and `Arc`s that the rest of
//! the code can be made generic over: [`ConstructibleLock`], [`RwLock`] and
//! [`SyncRcPtr`]/[`SyncRcPtrFactory`]. For limiting the amount of generic
//! parameters to get specified all over the place, group them together as
//! associated types of the [`SyncTypes`] trait expected to get implemented for
//! a target execution environment. Execution environments might want to
//! consider using the provided [`GenericArcFactory`] for their
//! [`SyncRcPtrFactory`].
//!
//! # Elimination of [`Lock`] or [`SyncRcPtr`] nesting in data structures
//!
//! It is a common scenario for [`Lock`]s and [`SyncRcPtr`]s to nest in the
//! following way: a structure protected by a [`Lock`] could contain a member
//! for which some API operating on that expects the member itself to be wrapped
//! in [`Lock`] and similar for [`SyncRcPtr`]s. In such scenarios the inner
//! member would have to get wrapped in a [`Lock`] or [`SyncRcPtr`] exclusively
//! for the reason of complying with the API's expectations -- after all, a lock
//! on the containing `struct` grants exclusive access to the inner member as
//! well and analogous for [`SyncRcPtr`]s. As atomic operations typically have
//! some performace cost, it's desirable to eliminate the need for wrapping the
//! member in an extra [`Lock`] or [`SyncRcPtr`]. For such scenarios the
//! [`LockForInner`] and [`SyncRcPtrForInner`] implementations are provided.

// Lifetimes are not obvious at first sight here, make them explicit.
#![allow(clippy::needless_lifetimes)]

extern crate alloc;
use core::{clone, convert, marker, mem, ops, pin};

/// Execution environment agnostic lock abstraction.
///
/// Users of the `Lock` must assume that the implementation is of the spinlock
/// type and **must not** block while holding the lock or execute otherwise
/// long-running work. This includes IO in particular, but also memory
/// allocations.
pub trait Lock<T: ?Sized>: marker::Send + marker::Sync {
    /// Lock guard type returned by [`lock()`](Self::lock).
    type Guard<'a>: ops::Deref<Target = T> + ops::DerefMut
    where
        Self: 'a;

    /// Lock the lock.
    ///
    /// Users of the `Lock` **must not** block or execute otherwise long-running
    /// work while holding the lock.
    fn lock(&self) -> Self::Guard<'_>;
}

/// Constructible [`Lock`].
///
/// A [`Lock`] is not necessarily constructible by wrapping the to be protected
/// value.  A counter-example is [`LockForInner`], which is obtained from a lock
/// wrapping a containing data structure. The [`ConstructibleLock`] trait is
/// implemented by [`Lock`] types which *are* constructible by wrapping a value.
pub trait ConstructibleLock<T>: Lock<T> + convert::From<T> {
    /// Access the wrapped value.
    ///
    /// Access the wrapped value through a mutable reference on `Self` without
    /// going through a locking operation. Note that the existence of the
    /// `mut` reference on `Self` implies that it cannot have been locked
    /// concurrently and that access is exclusive.
    fn get_mut(&mut self) -> &mut T;
}

/// Virtual zero-cost [`Lock`] implementation for members of a
/// [`Lock`]-protected `struct`.
///
/// In scenarios where a containing `struct OT` is protected by a [`Lock`]
/// already, but some API operating on one of its members is expecting that
/// member to be wrapped in a [`Lock`] by itself, it is desirable to not store
/// the member in another actual [`Lock`] within the containing `struct OT` just
/// for the sake of adhering to the API -- the atomic operations typically
/// involved in locking can be expensive, whereas a lock on the outer `struct
/// OT` does provide exclusive access to the inner member as well already.
///
/// `LockForInner` may be used to present a [`Lock`] wrapping the outer `struct
/// OT` as a one wrapping the inner member to APIs at zero cost. The member in
/// question is identified by a `TAG` type and the containing `struct OT` is
/// expected to implement [`DerefMutInnerByTag<TAG>`](DerefMutInnerByTag) for
/// translating references to the outer type to ones for the member.
pub struct LockForInner<'a, OT, OL, TAG>
where
    OT: 'a + ?Sized + DerefMutInnerByTag<TAG>,
    OL: 'a + Lock<OT>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send,
{
    lock_for_outer: &'a OL,
    _phantom: marker::PhantomData<fn() -> (*const OT, *const TAG)>,
}

impl<'a, OT, OL, TAG> LockForInner<'a, OT, OL, TAG>
where
    OT: ?Sized + DerefMutInnerByTag<TAG>,
    OL: 'a + Lock<OT>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send,
{
    /// Instantiate a [`LockForInner`] from a [`Lock`] wrapping the containing
    /// struct.
    ///
    /// # Arguments:
    ///
    /// * `lock_for_outer` - Reference to the [`Lock`] wrapping the containing
    ///   `struct OT`.
    pub fn from_outer(lock_for_outer: &'a OL) -> Self {
        Self {
            lock_for_outer,
            _phantom: marker::PhantomData,
        }
    }
}

impl<'a, OT, OL, TAG> Lock<<OT as DerefInnerByTag<TAG>>::Output> for LockForInner<'a, OT, OL, TAG>
where
    OT: ?Sized + DerefMutInnerByTag<TAG>,
    OL: 'a + Lock<OT>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send,
{
    type Guard<'b>
        = LockForInnerGuard<'b, OT, OL, TAG>
    where
        Self: 'b;

    fn lock(&self) -> Self::Guard<'_> {
        let guard_for_outer = self.lock_for_outer.lock();
        LockForInnerGuard {
            guard_for_outer,
            _phantom_tag: marker::PhantomData,
        }
    }
}

/// Locking guard obtained from [`LockForInner::lock()`](LockForInner::lock).
///
/// Alternatively, an exising guard for the [`Lock`] wrapping the outer `OT` may
/// get converted directly [to](Self::from_outer) and [back
/// from](Self::into_outer) a `LockForInnerGuard` instance.
pub struct LockForInnerGuard<'a, OT, OL, TAG>
where
    OT: ?Sized + DerefMutInnerByTag<TAG>,
    OL: 'a + Lock<OT>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send,
{
    guard_for_outer: OL::Guard<'a>,
    _phantom_tag: marker::PhantomData<fn() -> *const TAG>,
}

impl<'a, OT, OL, TAG> LockForInnerGuard<'a, OT, OL, TAG>
where
    OT: ?Sized + DerefMutInnerByTag<TAG>,
    OL: 'a + Lock<OT>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send,
{
    /// Convert an existing guard for the [`Lock`] wrapping the outer `OT` to a
    /// `LockForInnerGuard`.
    pub fn from_outer(guard_for_outer: OL::Guard<'a>) -> Self {
        Self {
            guard_for_outer,
            _phantom_tag: marker::PhantomData,
        }
    }

    /// Convert a `LockForInnerGuard` instance back to a guard for the [`Lock`]
    /// wrapping the outer `OT`.
    pub fn into_outer(self) -> OL::Guard<'a> {
        self.guard_for_outer
    }
}

impl<'a, OT, OL, TAG> ops::Deref for LockForInnerGuard<'a, OT, OL, TAG>
where
    OT: ?Sized + DerefMutInnerByTag<TAG>,
    OL: 'a + Lock<OT>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send,
{
    type Target = <OT as DerefInnerByTag<TAG>>::Output;

    fn deref(&self) -> &Self::Target {
        <OT as DerefInnerByTag<TAG>>::deref_inner(self.guard_for_outer.deref())
    }
}

impl<'a, OT, OL, TAG> ops::DerefMut for LockForInnerGuard<'a, OT, OL, TAG>
where
    OT: ?Sized + DerefMutInnerByTag<TAG>,
    OL: 'a + Lock<OT>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        <OT as DerefMutInnerByTag<TAG>>::deref_mut_inner(self.guard_for_outer.deref_mut())
    }
}

/// Execution environment agnostic read-write-lock abstraction.
///
/// A read-write-lock:
/// * A [`ReadGuard`](Self::ReadGuard) provides read-only access to the wrapped
///   value and there can be multiple concurrent ones at a given point in time.
/// * A [`WriteGuard`](Self::WriteGuard) is exclusive with both, itself and any
///   [`ReadGuards`](Self::ReadGuard) and provides write access.
///
/// Users of the `RwLock` must assume that the implementation is of the spinlock
/// type and **must not** block while holding the lock or execute otherwise
/// long-running work. This includes IO in particular, but also memory
/// allocations.
pub trait RwLock<T>: marker::Send + marker::Sync + convert::From<T> {
    /// Read lock guard type returned by [`read()`](Self::read).
    type ReadGuard<'a>: ops::Deref<Target = T>
    where
        Self: 'a;

    /// Write lock guard type returned by [`write()`](Self::write).
    type WriteGuard<'a>: ops::Deref<Target = T> + ops::DerefMut
    where
        Self: 'a;

    /// Lock the `RwLock` non-exclusively for reading.
    ///
    /// Users of the `RwLock` **must not** block or execute otherwise
    /// long-running work while holding the lock.
    fn read(&self) -> Self::ReadGuard<'_>;

    /// Lock the `RwLock` exclusively for writing.
    ///
    /// Users of the `RwLock` **must not** block or execute otherwise
    /// long-running work while holding the lock.
    fn write(&self) -> Self::WriteGuard<'_>;

    fn get_mut(&mut self) -> &mut T;
}

/// Execution environment agnostic [`sync::Arc`](alloc::sync::Arc) abstraction.
///
/// Just as `sync::Arc`, a SyncRcPtr is a [`Sync`]-safe reference counting
/// pointer to a shared, wrapped value.  The wrapped value will only get dropped
/// once the last cloning spawn of the original [`SyncRcPtr`] goes out of life.
///
/// To break cycles or to otherwise not hinder destruction of the inner value
/// due to long-lived strong reference count leases,
/// [`WeakSyncRcPtr`](Self::WeakSyncRcPtr) may be stored instead of `SyncRcPtr`
/// instances themselves.
pub trait SyncRcPtr<T: ?Sized>: Clone + ops::Deref<Target = T> + marker::Send + marker::Sync + marker::Unpin {
    /// Weak pointer type returned by [downgrade()](Self::downgrade).
    type WeakSyncRcPtr: WeakSyncRcPtr<T, Self>;

    /// Pointer reference type returned by [ref()](Self::as_ref).
    ///
    /// Implementations generic over some `SyncRcPtr<T>` should prefer accepting
    /// a `SyncRcPtr<T>::SyncRcPtrRef` over `&SyncRcPtr<T>` whenever
    /// possible. Refer to the documentation of [`SyncRcPtrRef`] for more
    /// details.
    type SyncRcPtrRef<'a>: SyncRcPtrRef<'a, T, Self>
    where
        Self: 'a;

    /// Downgrade to a [`WeakSyncRcPtr`].
    fn downgrade(&self) -> Self::WeakSyncRcPtr;

    /// Create a reference to the pointer.
    ///
    /// The `SyncRcPtrRef` indirection exists primarily to enable the creation
    /// of zero-cost [`SyncRcPtrRefForInner`] instances from a
    /// [`SyncRcPtrRef`] to the outer, containing type without going through
    /// a [`SyncRcPtrForInner`], i.e. without obtaining a temporary strong
    /// reference count lease on the outer `SyncRcPtr`.
    fn as_ref(&self) -> Self::SyncRcPtrRef<'_> {
        Self::SyncRcPtrRef::new(self)
    }

    /// Convert a `SyncRcPtr` into a raw pointer.
    ///
    /// Convert into a raw pointer without releasing the owned reference count
    /// lease. The raw pointer may eventually get converted back into a
    /// `SyncRcPtr` by means of [`from_raw()`](Self::from_raw). If that does
    /// not happen, the owned lease will be leaked.
    fn into_raw(this: Self) -> *const T;

    /// Convert a raw pointer previously obtained from
    /// [`into_raw()`](Self::into_raw) back into a `SyncRcPtr`.
    ///
    /// # Safety
    ///
    /// The raw `ptr` *must* have previously been obtained from
    /// [`SyncRcPtr<U>::into_raw()`](Self::into_raw) where
    /// * the `SyncRcPtr<U>` refers to the same `SyncRcPtr` implementation as
    ///   `Self`, with generic parameter `U` in place of the `T` from `Self`,
    ///   and
    /// * if `U` is sized, it must have the same size and alignment as `T` or
    /// * if `U` is unsized, its data pointer must have the same size and
    ///   alignment as `T`.
    unsafe fn from_raw(ptr: *const T) -> Self;
}

/// Execution environment agnostic [`sync::Weak`](alloc::sync::Weak)
/// abstraction.
///
/// Obtained either through [`SyncRcPtr::downgrade()`](SyncRcPtr::downgrade) or
/// [`SyncRcPtrRef::make_weak_clone()`](SyncRcPtrRef::make_weak_clone).
///
/// A `WeakSyncRcPtr` instance does not hinder destruction of the original
/// [`SyncRcPtr`]'s wrapped value. Note that this concerns only the
/// [`drop()`](Drop::drop) -- the backing memory mat get deallocated only once
/// the last `WeakSyncRcPtr` is gone.
pub trait WeakSyncRcPtr<T: ?Sized, P: SyncRcPtr<T>>: Clone + marker::Send + marker::Unpin {
    /// Convert a `WeakSyncRcPtr` back to a [`SyncRcPtr`].
    ///
    /// This will be successful only if at least one [`SyncRcPtr`] cloning spawn
    /// of the original [`SyncRcPtr`] instance is still around somewhere,
    /// otherwise the wrapped value had been destructed already and `None`
    /// will get returned.
    fn upgrade(&self) -> Option<P>;

    /// Convert a `WeakSyncRcPtr` into a raw pointer.
    ///
    /// Convert into a raw pointer without releasing the owned weak reference
    /// count lease. The raw pointer may eventually get converted back into
    /// a `WeakSyncRcPtr` by means of [`from_raw()`](Self::from_raw). If
    /// that does not happen, the owned lease will be leaked.
    fn into_raw(this: Self) -> *const T;

    /// Convert a raw pointer previously obtained from
    /// [`into_raw()`](Self::into_raw) back into a `WeakSyncRcPtr`.
    ///
    /// # Safety
    ///
    /// The raw `ptr` *must* have previously been obtained from
    /// [`WeakSyncRcPtr<U>::into_raw()`](Self::into_raw) where
    /// * the `WeakSyncRcPtr<U>` refers to the same `SyncRcPtr` implementation
    ///   as `Self`, with generic parameter `U` in place of the `T` from `Self`,
    ///   and
    /// * if `U` is sized, it must have the same size and alignment as `T` or
    /// * if `U` is unsized, its data pointer must have the same size and
    ///   alignment as `T`.
    unsafe fn from_raw(ptr: *const T) -> Self;
}

/// Error type returned by
/// [`SyncRcPtrFactory::try_new()`](SyncRcPtrFactory::try_new) and
/// [`SyncRcPtrFactory::try_new_recoverable()`](SyncRcPtrFactory::try_new_recoverable).
#[derive(Debug)]
pub enum SyncRcPtrTryNewError {
    /// Memory alocation failure.
    AllocationFailure,
}

/// Error type returned by
/// [`SyncRcPtrFactory::try_new_with()`](SyncRcPtrFactory::try_new_with).
pub enum SyncRcPtrTryNewWithError<E> {
    /// Failure to allocate a new [`SyncRcPtr`].
    TryNewError(SyncRcPtrTryNewError),
    /// The provided initalization callback returned an error indication.
    WithError(E),
}

/// Factory for the creation of [`SyncRcPtr`] instances.
pub trait SyncRcPtrFactory {
    type SyncRcPtr<T>: SyncRcPtr<T>
    where
        T: marker::Send + marker::Sync;

    /// Try to allocate a new [`SyncRcPtr`] instance.
    ///
    /// # Arguments:
    ///
    /// * `value` - The initialization value.
    fn try_new<T>(value: T) -> Result<Self::SyncRcPtr<T>, SyncRcPtrTryNewError>
    where
        T: marker::Send + marker::Sync;

    /// Try to allocate a new [`SyncRcPtr`] instance, returning the
    /// initialization value back upon allocation failure.
    ///
    /// With the conventional [`try_new()`](Self::try_new), the initialization
    /// `value` will still get consumed and is effectively lost upon
    /// allocation failure. The `try_new_recoverable()` on the other hands
    /// returns the `value` back to the caller alongside an error code in this
    /// case.
    ///
    /// # Arguments:
    ///
    /// * `value` - The initialization value, will get returned back to the
    ///   caller upon failure.
    fn try_new_recoverable<T>(value: T) -> Result<Self::SyncRcPtr<T>, (T, SyncRcPtrTryNewError)>
    where
        T: marker::Send + marker::Sync,
    {
        // Try to allocate a MaybeUninit SyncRcPtr and copy the supplied value into the
        // destination only when that has succeeded, otherwise return the value
        // back to the caller.
        let uninit = match Self::try_new::<mem::MaybeUninit<T>>(mem::MaybeUninit::uninit()) {
            Ok(uninit) => uninit,
            Err(e) => return Err((value, e)),
        };

        let p: *const mem::MaybeUninit<T> = SyncRcPtr::into_raw(uninit);
        // This is safe, it's the only pointer around.
        let p = p as *mut mem::MaybeUninit<T>;
        unsafe { &mut *p }.write(value);

        // {into,from}_raw() must work across transmutable type pairs and
        // MaybeUninit<T> <-> T is such one.
        let p = p as *const T;
        let p = unsafe { Self::SyncRcPtr::<T>::from_raw(p) };
        Ok(p)
    }

    /// Try to allocate a new [`SyncRcPtr`] and initialize with a user provided
    /// callback.
    ///
    /// The provided callback `new` will get invoked only after all allocation
    /// have succeeded and it is known that the construction of the
    /// receiving [`SyncRcPtr`] instance will not fail. `new` itself may
    /// still return an error though, in which case the error is propagated back
    /// to the caller.
    ///
    /// `try_new_with()` is intended for "value stealing" scenarios, where the
    /// initialization value is only to get stolen at a point where it is
    /// known that the [`SyncRcPtr`] allocation cannot fail anymore.
    ///
    /// Furthermore, writing the initialization value returned by `new` directly
    /// into the destination memory may enable certain compiler
    /// optimizations and safe copy over the stack.
    fn try_new_with<T, R, E, N>(new: N) -> Result<(Self::SyncRcPtr<T>, R), SyncRcPtrTryNewWithError<E>>
    where
        T: marker::Send + marker::Sync,
        N: ops::FnOnce() -> Result<(T, R), E>,
    {
        // Try to allocate a MaybeUninit SyncRcPtr and obtain the value from the
        // callback only when successful.
        let uninit = match Self::try_new::<mem::MaybeUninit<T>>(mem::MaybeUninit::uninit()) {
            Ok(uninit) => uninit,
            Err(e) => return Err(SyncRcPtrTryNewWithError::TryNewError(e)),
        };

        let (value, new_res) = match new() {
            Ok(r) => r,
            Err(e) => return Err(SyncRcPtrTryNewWithError::WithError(e)),
        };

        let p: *const mem::MaybeUninit<T> = SyncRcPtr::into_raw(uninit);
        // This is safe, it's the only pointer around.
        let p = p as *mut mem::MaybeUninit<T>;
        unsafe { &mut *p }.write(value);

        // {into,from}_raw() must work across transmutable type pairs and
        // MaybeUninit<T> <-> T is such one.
        let p = p as *const T;
        let p = unsafe { Self::SyncRcPtr::<T>::from_raw(p) };
        Ok((p, new_res))
    }
}

/// A reference to a [`SyncRcPtr`].
///
/// Implementations generic over some [`SyncRcPtr<T>`](SyncRcPtr) should prefer
/// accepting a `SyncRcPtrRef<T>` over a `&SyncRcPtr<T>` whenever possible.
///
/// Doing so enables callers to potentially safe an atomic operation
/// just for creating an intermediate [`SyncRcPtr<T>`] in cases where that
/// happens to be a derived [`SyncRcPtrForInner`], referring to some member of
/// type `T` contained in an outer `struct OT` managed by a
/// [`SyncRcPtr<OT>`](SyncRcPtr):
/// * obtaining a [`SyncRcPtrForInner`] from a [`&SyncRcPtr<OT>`](SyncRcPtr) for
///   the outer type would always involve an atomic reference count increment,
///   whereas
/// * a [`SyncRcPtrRef<OT>`](SyncRcPtrRef) can get converted to a
///   [`SyncRcPtrRefForInner`] at zero cost.
pub trait SyncRcPtrRef<'a, T: ?Sized, P: 'a + SyncRcPtr<T>>: Clone + ops::Deref<Target = T> {
    /// Create a new `SyncRcPtrRef` referencing the specified [`SyncRcPtr`]
    /// instance.
    fn new(p: &'a P) -> Self;

    /// Obtain an owned [`SyncRcPtr`] instance from the reference.
    fn make_clone(&self) -> P;

    /// Obtain a [`WeakSyncRcPtr`] from the reference [`SyncRcPtr`].
    fn make_weak_clone(&self) -> P::WeakSyncRcPtr;
}

/// [`WeakSyncRcPtr`] associated with a `Pin<SyncRcPtr<T>>`.
///
/// An of [`SyncRcPtr`] for `Pin<SyncRcPtr<T>>` is provided and
/// `PinnedWeakSyncRcPtr` is its associated [`WeakSyncRcPtr`] type returned by
/// the implementation of
/// [`Pin<SyncRcPtr<T>>::downgrade()`](SyncRcPtr::downgrade).
///
/// Note that it is not possible to simply use `Pin<SyncRcPtr<T>::WeakSyncRcPtr`
/// for that, as [`Pin`](pin::Pin) requires the wrapped pointer to be
/// dereferencable.
pub struct PinnedWeakSyncRcPtr<T: ?Sized, P: SyncRcPtr<T>> {
    weak_ptr: P::WeakSyncRcPtr,
}

impl<T: ?Sized, P: SyncRcPtr<T>> PinnedWeakSyncRcPtr<T, P> {
    /// Obtain a `PinnedWeakSyncRcPtr` from a `Pin<SyncRcPtr<T>>`.
    fn downgrade<'a, R: SyncRcPtrRef<'a, T, P>>(ptr_ref: &pin::Pin<R>) -> Self
    where
        P: 'a,
    {
        // This is safe, unwrap the ptr from the Pin for internal storage, it will
        // always get rewrapped when passed to the outside again.
        let ptr_ref = unsafe { pin::Pin::into_inner_unchecked(ptr_ref.clone()) };
        Self {
            weak_ptr: ptr_ref.make_weak_clone(),
        }
    }
}

impl<T: ?Sized, P: SyncRcPtr<T>> Clone for PinnedWeakSyncRcPtr<T, P> {
    fn clone(&self) -> Self {
        Self {
            weak_ptr: self.weak_ptr.clone(),
        }
    }
}

impl<T: ?Sized, P: SyncRcPtr<T>> WeakSyncRcPtr<T, pin::Pin<P>> for PinnedWeakSyncRcPtr<T, P> {
    fn upgrade(&self) -> Option<pin::Pin<P>> {
        self.weak_ptr.upgrade().map(|ptr| {
            // This is safe, it's merely a rewrap: the internally stored weak_ptr had
            // been unwrapped from a Pin before.
            unsafe { pin::Pin::new_unchecked(ptr) }
        })
    }

    fn into_raw(this: Self) -> *const T {
        P::WeakSyncRcPtr::into_raw(this.weak_ptr)
    }

    unsafe fn from_raw(ptr: *const T) -> Self {
        let weak_ptr = unsafe { P::WeakSyncRcPtr::from_raw(ptr) };
        Self { weak_ptr }
    }
}

impl<T: ?Sized, P: SyncRcPtr<T>> SyncRcPtr<T> for pin::Pin<P> {
    type SyncRcPtrRef<'a>
        = pin::Pin<P::SyncRcPtrRef<'a>>
    where
        P: 'a;
    type WeakSyncRcPtr = PinnedWeakSyncRcPtr<T, P>;

    fn downgrade(&self) -> Self::WeakSyncRcPtr {
        PinnedWeakSyncRcPtr::downgrade(&<Self as SyncRcPtr<T>>::as_ref(self))
    }

    fn as_ref(&self) -> Self::SyncRcPtrRef<'_> {
        <Self::SyncRcPtrRef<'_> as SyncRcPtrRef<'_, T, Self>>::new(self)
    }

    fn into_raw(this: Self) -> *const T {
        // This is safe: the returned pointer is const, so would require
        // an unsafe {} operation to move out from.
        let this = unsafe { pin::Pin::into_inner_unchecked(this) };
        P::into_raw(this)
    }

    unsafe fn from_raw(ptr: *const T) -> Self {
        unsafe {
            let p = P::from_raw(ptr);
            pin::Pin::new_unchecked(p)
        }
    }
}

impl<'a, T: ?Sized, P: SyncRcPtr<T>, R: SyncRcPtrRef<'a, T, P>> SyncRcPtrRef<'a, T, pin::Pin<P>> for pin::Pin<R>
where
    P: 'a,
{
    fn new(p: &'a pin::Pin<P>) -> Self {
        // Pin is [repr(transparent)]
        let p = p as *const pin::Pin<P> as *const P;
        let p: &'a P = unsafe { &*p };
        let r = R::new(p);
        // This is safe: rewrap in a Pin.
        unsafe { pin::Pin::new_unchecked(r) }
    }

    fn make_clone(&self) -> pin::Pin<P> {
        // This is safe: unwrap and rewrap in a Pin.
        unsafe { pin::Pin::new_unchecked(pin::Pin::into_inner_unchecked(self.clone()).make_clone()) }
    }

    fn make_weak_clone(&self) -> <pin::Pin<P> as SyncRcPtr<T>>::WeakSyncRcPtr {
        PinnedWeakSyncRcPtr::downgrade(self)
    }
}

/// Implementation helper for [`SyncRcPtrRef`].
///
/// As explained in the documentation to [`SyncRcPtrRef`], it exists primarily
/// to enable certain optimizations in the context of [`SyncRcPtrForInner`]. For
/// [`SyncRcPtr`] with no special requirements, implementations may choose to
/// use `GenericSyncRcPtrRef` for their associated [`SyncRcPtr::SyncRcPtrRef`]
/// type.
pub struct GenericSyncRcPtrRef<'a, T: ?Sized, P: SyncRcPtr<T>> {
    r: &'a P,
    _phantom: marker::PhantomData<fn() -> *const T>,
}

impl<'a, T: ?Sized, P: SyncRcPtr<T>> Clone for GenericSyncRcPtrRef<'a, T, P> {
    fn clone(&self) -> Self {
        Self {
            r: self.r,
            _phantom: marker::PhantomData,
        }
    }
}

impl<'a, T: ?Sized, P: SyncRcPtr<T>> ops::Deref for GenericSyncRcPtrRef<'a, T, P> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.r.deref()
    }
}

impl<'a, T: ?Sized, P: SyncRcPtr<T>> SyncRcPtrRef<'a, T, P> for GenericSyncRcPtrRef<'a, T, P> {
    fn new(p: &'a P) -> Self {
        Self {
            r: p,
            _phantom: marker::PhantomData,
        }
    }
    fn make_clone(&self) -> P {
        self.r.clone()
    }

    fn make_weak_clone(&self) -> P::WeakSyncRcPtr {
        self.r.downgrade()
    }
}

/// Translate a reference to a containing compound type to a reference to a
/// contained data item.
///
/// Intended to be used with [`LockForInner`] and [`SyncRcPtrForInner`].
///
/// `DerefInnerByTag` is to be implemented on the containing compound type,
/// typically a `struct`, and is supposed to translate a reference to that outer
/// type to some contained data item identified by the `TAG` type, typically a
/// `struct` member.
///
/// Users should not implement this trait by themselves, but use the
/// [`impl_deref_inner_by_tag!()`](crate::impl_deref_inner_by_tag) macro.
///
/// # Example:
///
/// ```
/// struct Outer {
///     inner0: (),
///     inner1: u32,
/// }
///
/// struct OuterDerefInner0Tag {}
///
/// struct OuterDerefInner1Tag {}
///
/// impl DerefInnerByTag<OuterDerefInner0Tag> for Outer {
///     impl_deref_inner_by_tag!(inner0, ())
/// }
///
/// impl DerefInnerByTag<OuterDerefInner1Tag> for Outer {
///     impl_deref_inner_by_tag!(inner1, u32)
/// }
/// ```
pub trait DerefInnerByTag<TAG> {
    type Output: ?Sized;

    /// Translate a reference to the containing type to the member.
    fn deref_inner(&self) -> &Self::Output;

    /// Translate a pointer to the containing type to the member.
    fn to_inner_ptr(outer: *const Self) -> *const Self::Output;

    /// Translate a pointer to the member back to the containing type.
    ///
    /// # Safety
    ///
    /// The `inner` pointer must have previously been obtained from
    /// [`to_inner_ptr()`](Self::to_inner_ptr) or by a cast of the the reference
    /// obtained from [`deref_inner()`](Self::deref_inner) to pointer type.
    unsafe fn container_of(inner: *const Self::Output) -> *const Self;
}

/// Helper macro for implementing the [`DerefInnerByTag`] trait.
#[macro_export]
macro_rules! impl_deref_inner_by_tag {
    ($field:ident, $field_type:path) => {
        type Output = $field_type;

        fn deref_inner(&self) -> &Self::Output {
            &self.$field
        }

        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        fn to_inner_ptr(outer: *const Self) -> *const Self::Output {
            use core::ptr;
            // This is safe, even if outer does not point to initialized memory: the usage
            // pattern is among the explicitly documented examples for addr_of!().
            unsafe { ptr::addr_of!((*outer).$field) }
        }

        unsafe fn container_of(inner: *const Self::Output) -> *const Self {
            use core::mem;
            unsafe {
                inner
                    .cast::<u8>()
                    .sub(mem::offset_of!(Self, $field))
                    .cast::<Self>()
            }
        }
    };
}

/// Translate a `mut` reference to a containing compound type to a `mut`
/// reference to a contained data item.
///
/// Intended to be used with [`LockForInner`].
///
/// `DerefMutInnerByTag` is to be implemented on the containing compound type,
/// typically a `struct`, and is supposed to translate a `mut` reference to that
/// outer type to some contained data item identified by the `TAG` type,
/// typically a `struct` member.
///
/// Users should not implement this trait by themselves, but use the
/// [`impl_deref_mut inner_by_tag!()`](crate::impl_deref_mut inner_by_tag)
/// macro.
///
/// # Example:
///
/// ```
/// struct Outer {
///     inner: (),
/// }
///
/// struct OuterDerefInnerTag {}
///
/// impl DerefInnerByTag<OuterDerefInnerTag> for Outer {
///     impl_deref_inner_by_tag!(inner, ())
/// }
///
/// impl DerefMutInnerByTag<OuterDerefInnerTag> for Outer {
///     impl_deref_mut_inner_by_tag!(inner, ())
/// }
/// ```
pub trait DerefMutInnerByTag<TAG>: DerefInnerByTag<TAG> {
    fn deref_mut_inner(&mut self) -> &mut Self::Output;
}

/// Helper macro for implementing the [`DerefMutInnerByTag`] trait.
#[macro_export]
macro_rules! impl_deref_mut_inner_by_tag {
    ($field:ident) => {
        fn deref_mut_inner(&mut self) -> &mut Self::Output {
            &mut self.$field
        }
    };
}

/// Virtual zero-cost [`SyncRcPtr`] implementation for members of a
/// [`SyncRcPtr`]-managed `struct`.
///
/// In scenarios where a containing `struct OT` is managed by a [`SyncRcPtr`]
/// already, but some API operating on one of its members is expecting that
/// member to be wrapped in a [`SyncRcPtr`] by itself, it is desirable to not
/// store the member in another actual full-blown [`SyncRcPtr`] within the
/// containing `struct OT` just for the sake of adhering to the API:
/// * the extra heap allocation for the member fragments the heap and also
///   reduces locality relative to the containing `struct`,
/// * the atomic operations typically involved with cloning and destruction of
///   [`SyncRcPtr`] can be expensive -- the more instances there are and the
///   more cachelines the different atomic reference counts are scattered over
///   the worse it tends to get,
/// * whereas the inner member's wrapping [`SyncRcPtr`] instance would be
///   completely superfluous from a lifetime management perspective, because the
///   outer one always implicitly owns a reference count lease on the inner one.
///
/// `SyncRcPtrForInner` may be used to present a [`SyncRcPtr`] wrapping the
/// outer `struct OT` as a one wrapping the inner member to APIs at zero
/// additional cost. The member in question is identified by a `TAG` type and
/// the containing `struct OT` is expected to implement
/// [`DerefInnerByTag<TAG>`](DerefInnerByTag) for translating references to the
/// outer type to ones for the member.
pub struct SyncRcPtrForInner<OT, OP, TAG>
where
    OT: ?Sized + DerefInnerByTag<TAG>,
    OP: SyncRcPtr<OT>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send + marker::Sync,
{
    ptr_to_outer: OP,
    _phantom: marker::PhantomData<fn() -> (*const OT, *const TAG)>,
}

impl<OT, OP, TAG> SyncRcPtrForInner<OT, OP, TAG>
where
    OT: ?Sized + DerefInnerByTag<TAG>,
    OP: SyncRcPtr<OT>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send + marker::Sync,
{
    /// Convert a [`SyncRcPtr`] for the containing type to an
    /// `SyncRcPtrForInner` for the inner member.
    ///
    /// # Arguments:
    ///
    /// * `ptr_to_outer` - The `SyncRcPtr<OT>` for the outer containing
    ///   `struct`.
    pub fn new(ptr_to_outer: OP) -> Self {
        Self {
            ptr_to_outer,
            _phantom: marker::PhantomData,
        }
    }

    /// Translate a `SyncRcPtrForInner` for a `struct` member back to a
    /// `SyncRcPtr` for the containing outer type.
    ///
    /// Note that this involves a cloning of the `SyncRcPtr<OT>`, i.e. a
    /// reference count increment. For a consuming alternative, see
    /// [`into_container()`](Self::into_container).
    ///
    /// # See also:
    ///
    /// * [`into_container()`](Self::into_container)
    pub fn get_container(&self) -> OP::SyncRcPtrRef<'_> {
        self.ptr_to_outer.as_ref()
    }

    /// Translate a `SyncRcPtrForInner` for a `struct` member back into a
    /// `SyncRcPtr` for the containing outer type.
    pub fn into_container(self) -> OP {
        self.ptr_to_outer
    }
}

impl<OT, OP, TAG> SyncRcPtrForInner<OT, pin::Pin<OP>, TAG>
where
    OT: ?Sized + DerefInnerByTag<TAG>,
    OP: SyncRcPtr<OT>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send + marker::Sync,
{
    /// Projection-pin a `Pin<SyncRcPtr>` for an outer containing type
    /// structurally to a `Pin<SyncRcPtrForInner>` for a member.
    ///
    /// For a general discussion of [`Pin`](pin::Pin) projections, refer to the
    /// core [`pin`] module documentation.
    ///
    /// # Safety
    ///
    /// The general projection pinning documented for the core [`pin`] module
    /// apply.
    pub unsafe fn new_projection_pin(ptr_to_outer: pin::Pin<OP>) -> pin::Pin<Self> {
        // If the inner data is an ordinary member or alike of the outer type, then this
        // is sound, the ptr_to_outer is pinned, and it remains so, which means
        // that the inner is also pinned.
        unsafe {
            pin::Pin::new_unchecked(Self {
                ptr_to_outer,
                _phantom: marker::PhantomData,
            })
        }
    }
}

impl<OT, OP, TAG> convert::From<OP> for SyncRcPtrForInner<OT, OP, TAG>
where
    OT: ?Sized + DerefInnerByTag<TAG>,
    OP: SyncRcPtr<OT>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send + marker::Sync,
{
    fn from(value: OP) -> Self {
        Self::new(value)
    }
}

impl<OT, OP, TAG> clone::Clone for SyncRcPtrForInner<OT, OP, TAG>
where
    OT: ?Sized + DerefInnerByTag<TAG>,
    OP: SyncRcPtr<OT>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send + marker::Sync,
{
    fn clone(&self) -> Self {
        Self {
            ptr_to_outer: self.ptr_to_outer.clone(),
            _phantom: marker::PhantomData,
        }
    }
}

impl<OT, OP, TAG> ops::Deref for SyncRcPtrForInner<OT, OP, TAG>
where
    OT: ?Sized + DerefInnerByTag<TAG>,
    OP: SyncRcPtr<OT>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send + marker::Sync,
{
    type Target = <OT as DerefInnerByTag<TAG>>::Output;

    fn deref(&self) -> &Self::Target {
        DerefInnerByTag::<TAG>::deref_inner(self.ptr_to_outer.deref())
    }
}

impl<OT, OP, TAG> marker::Unpin for SyncRcPtrForInner<OT, OP, TAG>
where
    OT: ?Sized + DerefInnerByTag<TAG>,
    OP: SyncRcPtr<OT>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send + marker::Sync,
{
}

impl<OT, OP, TAG> SyncRcPtr<<OT as DerefInnerByTag<TAG>>::Output> for SyncRcPtrForInner<OT, OP, TAG>
where
    OT: ?Sized + DerefInnerByTag<TAG>,
    OP: SyncRcPtr<OT>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send + marker::Sync,
{
    type WeakSyncRcPtr = WeakSyncRcPtrForInner<OT, OP, TAG>;
    type SyncRcPtrRef<'a>
        = SyncRcPtrRefForInner<'a, OT, OP, OP::SyncRcPtrRef<'a>, TAG>
    where
        OP: 'a,
        OT: 'a,
        TAG: 'a;

    fn downgrade(&self) -> Self::WeakSyncRcPtr {
        WeakSyncRcPtrForInner {
            weak_ptr_to_outer: self.ptr_to_outer.downgrade(),
            _phantom: marker::PhantomData,
        }
    }

    fn into_raw(this: Self) -> *const <OT as DerefInnerByTag<TAG>>::Output {
        let outer = OP::into_raw(this.ptr_to_outer);
        <OT as DerefInnerByTag<TAG>>::to_inner_ptr(outer)
    }

    unsafe fn from_raw(ptr: *const <OT as DerefInnerByTag<TAG>>::Output) -> Self {
        // This is safe, part of the contract is that ptr_to_inner originated from
        // Self::into_raw().
        let ptr_to_outer = unsafe { <OT as DerefInnerByTag<TAG>>::container_of(ptr) };
        let ptr_to_outer = unsafe { OP::from_raw(ptr_to_outer) };
        Self {
            ptr_to_outer,
            _phantom: marker::PhantomData,
        }
    }
}

/// [`WeakSyncRcPtr`] implementation associated with [`SyncRcPtrForInner`].
pub struct WeakSyncRcPtrForInner<OT, OP, TAG>
where
    OT: ?Sized + DerefInnerByTag<TAG>,
    OP: SyncRcPtr<OT>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send + marker::Sync,
{
    weak_ptr_to_outer: OP::WeakSyncRcPtr,
    _phantom: marker::PhantomData<fn() -> (*const OT, *const TAG)>,
}

impl<OT, OP, TAG> clone::Clone for WeakSyncRcPtrForInner<OT, OP, TAG>
where
    OT: ?Sized + DerefInnerByTag<TAG>,
    OP: SyncRcPtr<OT>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send + marker::Sync,
{
    fn clone(&self) -> Self {
        Self {
            weak_ptr_to_outer: self.weak_ptr_to_outer.clone(),
            _phantom: marker::PhantomData,
        }
    }
}

impl<OT, OP, TAG> marker::Unpin for WeakSyncRcPtrForInner<OT, OP, TAG>
where
    OT: ?Sized + DerefInnerByTag<TAG>,
    OP: SyncRcPtr<OT>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send + marker::Sync,
{
}

impl<OT, OP, TAG> WeakSyncRcPtr<<OT as DerefInnerByTag<TAG>>::Output, SyncRcPtrForInner<OT, OP, TAG>>
    for WeakSyncRcPtrForInner<OT, OP, TAG>
where
    OT: ?Sized + DerefInnerByTag<TAG>,
    OP: SyncRcPtr<OT>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send + marker::Sync,
{
    fn upgrade(&self) -> Option<SyncRcPtrForInner<OT, OP, TAG>> {
        self.weak_ptr_to_outer
            .upgrade()
            .map(|ptr_to_outer| SyncRcPtrForInner::<OT, OP, TAG> {
                ptr_to_outer,
                _phantom: marker::PhantomData,
            })
    }

    fn into_raw(this: Self) -> *const <OT as DerefInnerByTag<TAG>>::Output {
        let outer = OP::WeakSyncRcPtr::into_raw(this.weak_ptr_to_outer);
        <OT as DerefInnerByTag<TAG>>::to_inner_ptr(outer)
    }

    unsafe fn from_raw(ptr: *const <OT as DerefInnerByTag<TAG>>::Output) -> Self {
        // This is safe, part of the contract is that ptr_to_inner originated from
        // Self::into_raw().
        let ptr_to_outer = unsafe { <OT as DerefInnerByTag<TAG>>::container_of(ptr) };
        let weak_ptr_to_outer = unsafe { OP::WeakSyncRcPtr::from_raw(ptr_to_outer) };
        Self {
            weak_ptr_to_outer,
            _phantom: marker::PhantomData,
        }
    }
}

/// [`SyncRcPtrRef`] implementation associated with [`SyncRcPtrForInner`].
///
/// As outlined in the documentation to [`SyncRcPtrRef`], translating a
/// [`SyncRcPtrRef`] for the outer containing `struct` to a
/// `SyncRcPtrRefForInner` for the member is a zero cost operation, wheras going
/// from a [`SyncRcPtr`] for the outer `struct` to a [`SyncRcPtrForInner`] for
/// the member is not.
pub struct SyncRcPtrRefForInner<'a, OT, OP, OR, TAG>
where
    OT: ?Sized + DerefInnerByTag<TAG>,
    OP: 'a + SyncRcPtr<OT>,
    OR: SyncRcPtrRef<'a, OT, OP>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send + marker::Sync,
    TAG: 'a,
{
    ptr_to_outer_ref: OR,
    #[allow(clippy::type_complexity)]
    _phantom: marker::PhantomData<fn() -> (&'a (), *const OT, *const OP, *const TAG)>,
}

impl<'a, OT, OP, OR, TAG> SyncRcPtrRefForInner<'a, OT, OP, OR, TAG>
where
    OT: ?Sized + DerefInnerByTag<TAG>,
    OP: 'a + SyncRcPtr<OT>,
    OR: SyncRcPtrRef<'a, OT, OP>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send + marker::Sync,
    TAG: 'a,
{
    pub fn new(ptr_to_outer_ref: &OR) -> Self {
        Self {
            ptr_to_outer_ref: ptr_to_outer_ref.clone(),
            _phantom: marker::PhantomData,
        }
    }

    /// Translate a `SyncRcPtrRefForInner` for a `struct` member back to a
    /// `SyncRcPtrRef` for the containing outer type.
    pub fn get_container(&self) -> &OR {
        &self.ptr_to_outer_ref
    }
}

impl<'a, OT, OP, OR, TAG> SyncRcPtrRefForInner<'a, OT, pin::Pin<OP>, OR, TAG>
where
    OT: ?Sized + DerefInnerByTag<TAG>,
    OP: SyncRcPtr<OT>,
    OR: SyncRcPtrRef<'a, OT, pin::Pin<OP>>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send + marker::Sync,
{
    /// Projection-pin a `Pin<SyncRcPtrRef>` for an outer containing type
    /// structurally to a `Pin<SyncRcPtrRefForInner>` for a member.
    ///
    /// For a general discussion of [`Pin`](pin::Pin) projections, refer to the
    /// core [`pin`] module documentation.
    ///
    /// # Safety
    ///
    /// The general projection pinning documented for the core [`pin`] module
    /// apply.
    pub unsafe fn new_projection_pin(ptr_to_outer_ref: &OR) -> pin::Pin<Self> {
        // If the inner data is an ordinary member or alike of the outer type, then this
        // is sound, the ptr_to_outer is pinned, and it remains so, which means
        // that the inner is also pinned.
        unsafe {
            pin::Pin::new_unchecked(Self {
                ptr_to_outer_ref: ptr_to_outer_ref.clone(),
                _phantom: marker::PhantomData,
            })
        }
    }
}

impl<'a, OT, OP, OR, TAG> Clone for SyncRcPtrRefForInner<'a, OT, OP, OR, TAG>
where
    OT: ?Sized + DerefInnerByTag<TAG>,
    OP: 'a + SyncRcPtr<OT>,
    OR: SyncRcPtrRef<'a, OT, OP>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send + marker::Sync,
    TAG: 'a,
{
    fn clone(&self) -> Self {
        Self {
            ptr_to_outer_ref: self.ptr_to_outer_ref.clone(),
            _phantom: marker::PhantomData,
        }
    }
}

impl<'a, OT, OP, OR, TAG> ops::Deref for SyncRcPtrRefForInner<'a, OT, OP, OR, TAG>
where
    OT: ?Sized + DerefInnerByTag<TAG>,
    OP: 'a + SyncRcPtr<OT>,
    OR: SyncRcPtrRef<'a, OT, OP>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send + marker::Sync,
    TAG: 'a,
{
    type Target = <OT as DerefInnerByTag<TAG>>::Output;

    fn deref(&self) -> &Self::Target {
        DerefInnerByTag::<TAG>::deref_inner(self.ptr_to_outer_ref.deref())
    }
}

impl<'a, OT, OP, OR, TAG> SyncRcPtrRef<'a, <OT as DerefInnerByTag<TAG>>::Output, SyncRcPtrForInner<OT, OP, TAG>>
    for SyncRcPtrRefForInner<'a, OT, OP, OR, TAG>
where
    OT: 'a + ?Sized + DerefInnerByTag<TAG>,
    OP: 'a + SyncRcPtr<OT>,
    OR: SyncRcPtrRef<'a, OT, OP>,
    <OT as DerefInnerByTag<TAG>>::Output: marker::Send + marker::Sync,
    TAG: 'a,
{
    fn new(p: &'a SyncRcPtrForInner<OT, OP, TAG>) -> Self {
        Self::new(&OR::new(&p.ptr_to_outer))
    }

    fn make_clone(&self) -> SyncRcPtrForInner<OT, OP, TAG> {
        SyncRcPtrForInner::<OT, OP, TAG> {
            ptr_to_outer: self.ptr_to_outer_ref.make_clone(),
            _phantom: marker::PhantomData,
        }
    }

    fn make_weak_clone(
        &self,
    ) -> <SyncRcPtrForInner<OT, OP, TAG> as SyncRcPtr<<OT as DerefInnerByTag<TAG>>::Output>>::WeakSyncRcPtr {
        WeakSyncRcPtrForInner::<OT, OP, TAG> {
            weak_ptr_to_outer: self.ptr_to_outer_ref.make_weak_clone(),
            _phantom: marker::PhantomData,
        }
    }
}

/// Convenience grouping of an execution environment's synchronization related
/// trait implementations.
///
/// For limiting the amount of generic parameters to get specified all over the
/// place, group them together as associated types of the [`SyncTypes`] trait
/// expected to get implemented for a target execution environment.
pub trait SyncTypes: marker::Unpin + 'static {
    /// The execution environment's implementation of the [`ConstructibleLock`]
    /// trait.
    type Lock<T: marker::Send>: ConstructibleLock<T>;
    /// The execution environment's implementation of the [`RwLock`] trait.
    type RwLock<T: marker::Send + marker::Sync>: RwLock<T>;
    /// The execution environment's implementation of the [`SyncRcPtrFactory`]
    /// trait. Execution environments might want to consider using the
    /// provided [`GenericArcFactory`] for their [`SyncRcPtrFactory`].
    type SyncRcPtrFactory: SyncRcPtrFactory;
}

mod generic_arc;
pub use generic_arc::{GenericArc, GenericArcFactory, GenericWeak};
