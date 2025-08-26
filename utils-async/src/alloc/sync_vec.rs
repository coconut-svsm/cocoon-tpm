extern crate alloc;
use alloc::vec::Vec;

use crate::sync_types;
use core::{marker, ops};

/// Error returned by [`SyncVec::try_reserve()`] and
/// [`SyncVec::try_reserve_exact()`].
#[derive(Debug)]
pub enum SyncVecError {
    /// The memory allocation has failed.
    MemoryAllocationFailure,
}

/// [`Lock`](sync_types::Lock)-protectable [`Vec`] proxy with support for
/// unlocked reallocations.
///
/// As an execution environment's [`Lock`](sync_types::Lock) implementation
/// might be of the spinlock kind, memory allocations under such a lock are to
/// be avoided. `SyncVec` implements a common "Read-Copy-Update" style pattern
/// for resizing a Rust core [`Vec`]: the lock will get dropped for a
/// memory allocation, reacquired afterwards and the original [`Vec`] replaced
/// with the resized one under the reacquired lock.
///
/// Note that in order to support [`LockForInner`](sync_types::LockForInner)
/// scenarios, `SyncVec` does not wrap the managed [`Vec`] in
/// [`Lock`](sync_types::Lock) by itself: it is expected that users of `SyncVec`
/// wrap it or an ancestor in the data structure hiearchy in one.
///
/// Even though the inner [`Vec`] is fully exposed via
/// [`DerefMut`](ops::DerefMut), users should refrain from using
/// [`Vec::try_reserve()`](Vec::try_reserve) or
/// [`Vec::try_reserve_exact()`](Vec::try_reserve_exact) directly through a
/// [`locking guard`](sync_types::Lock::Guard), either explictly or implicitly
/// through e.g. a [`Vec::resize()`](Vec::resize) on a [`Vec`] with insufficient
/// capcacity.
pub struct SyncVec<T: marker::Send> {
    /// The managed [`Vec`] instance.
    v: Vec<T>,
    /// Sum of the requested additional capacities of all currently pending
    /// concurrent [`try_reserve_impl()`](Self::try_reserve_impl) requests.
    pending_reservations_additional_capacity: usize,
}

impl<T: marker::Send> SyncVec<T> {
    /// Create a new empty `SyncVec`.
    pub fn new() -> Self {
        Self {
            v: Vec::new(),
            pending_reservations_additional_capacity: 0,
        }
    }

    /// Wrapper to [`Vec::try_reserve_exact()`](Vec::try_reserve_exact) with
    /// lock management support.
    ///
    /// To be called with the protecting [`Lock`](sync_types::Lock) locked.  The
    /// corresponding locking `guard` is to be handed over by the caller and
    /// will get returned back. ** Note that the `guard` may get dropped and
    /// reacquired in the course, so any state protected by the
    /// [`Lock`](sync_types::Lock) must get reread and reevaluated by the
    /// caller!**. Moreover, the capacity reservation is valid only for the
    /// lifetime of the returned guard. Details follow.
    ///
    /// If the underlying `Vec`'s capacity is already sufficient, nothing is to
    /// be done and the original `guard` would simply get returned back.
    /// Otherwise
    /// * the guard will get dropped,
    /// * memory of size sufficient to hold a [`Vec`] with the additional
    ///   requested capacity allocated outside the lock and
    /// * the lock gets reacquired,
    /// * if the memory allocation was successful, the original [`Vec`]'s
    ///   elements get moved into the new memory,
    /// * the guard for the *reacquired* lock gets returned back to the caller.
    ///
    /// Furthermore, there are provisions to handle multiple concurrent
    /// reservations correctly.
    ///
    /// # Arguments:
    ///
    /// * `this` - The [`Lock`](sync_types::Lock) rotecting the `SyncVec`
    ///   instance.
    /// * `guard` - [`Locking guard`](sync_types::Lock::Guard) for `this`. Will
    ///   get returned back to the caller on success, **but might have been
    ///   dropped and reacquired in the course**.
    /// * `additional_capacity` - The additional capacity to reserve. On
    ///   success, the underlying `Vec` is guaranteed to have storage sufficient
    ///   to hold that many additional elements without any reallocation, as
    ///   long as the [`Locking guard`](sync_types::Lock::Guard) is alive.
    pub fn try_reserve_exact<'a, L: sync_types::Lock<Self>>(
        this: &'a L,
        guard: L::Guard<'a>,
        additional_capacity: usize,
    ) -> (L::Guard<'a>, Result<(), SyncVecError>) {
        Self::try_reserve_impl(this, guard, additional_capacity, true)
    }

    /// Wrapper to [`Vec::try_reserve()`](Vec::try_reserve) with lock management
    /// support.
    ///
    /// To be called with the protecting [`Lock`](sync_types::Lock) locked.  The
    /// corresponding locking `guard` is to be handed over by the caller and
    /// will get returned back. ** Note that the `guard` may get dropped and
    /// reacquired in the course, so any state protected by the
    /// [`Lock`](sync_types::Lock) must get reread and reevaluated by the
    /// caller!**. Moreover, the capacity reservation is valid only for the
    /// lifetime of the returned guard. Details follow.
    ///
    /// If the underlying `Vec`'s capacity is already sufficient, nothing is to
    /// be done and the original `guard` would simply get returned back.
    /// Otherwise
    /// * the guard will get dropped,
    /// * memory of size sufficient to hold a [`Vec`] with the additional
    ///   requested capacity allocated outside the lock and
    /// * the lock gets reacquired,
    /// * if the memory allocation was successful, the original [`Vec`]'s
    ///   elements get moved into the new memory,
    /// * the guard for the *reacquired* lock gets returned back to the caller.
    ///
    /// Furthermore, there are provisions to handle multiple concurrent
    /// reservations correctly.
    ///
    /// # Arguments:
    ///
    /// * `this` - The [`Lock`](sync_types::Lock) rotecting the `SyncVec`
    ///   instance.
    /// * `guard` - [`Locking guard`](sync_types::Lock::Guard) for `this`. Will
    ///   get returned back to the caller on success, **but might have been
    ///   dropped and reacquired in the course**.
    /// * `additional_capacity` - The additional capacity to reserve. On
    ///   success, the underlying `Vec` is guaranteed to have storage sufficient
    ///   to hold that many additional elements without any reallocation, as
    ///   long as the [`Locking guard`](sync_types::Lock::Guard) is alive.
    pub fn try_reserve<'a, L: sync_types::Lock<Self>>(
        this: &'a L,
        guard: L::Guard<'a>,
        additional_capacity: usize,
    ) -> (L::Guard<'a>, Result<(), SyncVecError>) {
        Self::try_reserve_impl(this, guard, additional_capacity, false)
    }

    /// The implementation common to [`try_reserve()`](Self::try_reserve) and
    /// [`try_reserve_exact()`](Self::try_reserve_exact).
    fn try_reserve_impl<'a, L: sync_types::Lock<Self>>(
        this: &'a L,
        mut guard: L::Guard<'a>,
        additional_capacity: usize,
        exact: bool,
    ) -> (L::Guard<'a>, Result<(), SyncVecError>) {
        // Don't allocate under the lock. If there's enough capacity and no concurrent
        // pending reallocations, just return. Otherwise announce
        // the pending allocation (i.e. the additional capacity required), drop
        // the lock, allocate, and install the reallocated Vec.
        let reallocated_capacity = match guard
            .v
            .len()
            .checked_add(guard.pending_reservations_additional_capacity)
            .and_then(|c| c.checked_add(additional_capacity))
        {
            Some(reallocated_capacity) => reallocated_capacity,
            None => return (guard, Err(SyncVecError::MemoryAllocationFailure)),
        };

        if guard.v.capacity() >= reallocated_capacity {
            return (guard, Ok(()));
        };
        // Announce the pending reallocation. From now on, after releasing the lock,
        // any subsequent concurrent reallocation will include the requested
        // number of spare entries for us.
        guard.pending_reservations_additional_capacity += additional_capacity;
        drop(guard);

        let mut reallocated_v = Vec::new();
        let allocation_failed = if exact {
            reallocated_v.try_reserve_exact(reallocated_capacity).is_err()
        } else {
            reallocated_v.try_reserve(reallocated_capacity).is_err()
        };
        if allocation_failed {
            let mut guard = this.lock();
            guard.pending_reservations_additional_capacity -= additional_capacity;
            return (guard, Err(SyncVecError::MemoryAllocationFailure));
        }

        let mut guard = this.lock();
        if guard.v.capacity()
            >= reallocated_capacity.min(guard.v.len() + guard.pending_reservations_additional_capacity)
        {
            // Someone else came in and did the allocation already, including
            // the entries for us.
            guard.pending_reservations_additional_capacity -= additional_capacity;
            return (guard, Ok(()));
        }

        debug_assert!(reallocated_capacity > guard.v.len());
        reallocated_v.append(&mut guard.v);
        guard.v = reallocated_v;
        guard.pending_reservations_additional_capacity -= additional_capacity;

        (guard, Ok(()))
    }
}

impl<T: marker::Send> ops::Deref for SyncVec<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.v
    }
}

impl<T: marker::Send> ops::DerefMut for SyncVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.v
    }
}

impl<T: marker::Send> Default for SyncVec<T> {
    fn default() -> Self {
        Self::new()
    }
}
