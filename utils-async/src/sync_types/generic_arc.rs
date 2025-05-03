// SPDX-License-Identifier: Apache-2.0
// Copyright The Rust Project Developers (see https://thanks.rust-lang.org)
// Copyright 2025 SUSE LLC
//
// Implementation is based heavily on Rust's core Arc. Copyrights and licenses
// apply accordingly.
//
// Simplifications made relative to the original Arc implementation from the
// Rust project:
// - only support Sized T (otherwise implementation is not possible with stable
//   Rust)
// - trimmed all unneeded functionality, noteworthy in particular:
// - no get_mut()/is_unique(), hence no locking of the weak reference count, and
//   also weaker memory ordering in Arc::downgrade(),
// - no new_cyclic(), hence no uninitialized memory at birth, which allows for
//   weaker memory ordering Weak::upgrade().

//! Implementaion of [`GenericArc`].
//!
//! Based heavily on a trimmed version of Rust's core [`Arc`](alloc::sync::Arc).

extern crate alloc;
use alloc::boxed::Box;

use super::{GenericSyncRcPtrRef, SyncRcPtr, SyncRcPtrFactory, SyncRcPtrRef, SyncRcPtrTryNewError, WeakSyncRcPtr};
use crate::utils_common::alloc::{box_try_new, TryNewError};
use core::{
    marker::{self, PhantomData},
    mem::{self, ManuallyDrop},
    ops::Deref,
    ptr::{self, NonNull},
    sync::atomic,
};

const MAX_REFCOUNT: usize = (isize::MAX) as usize;

/// The error in case either counter reaches above `MAX_REFCOUNT`, and we can
/// `panic` safely.
const INTERNAL_OVERFLOW_ERROR: &str = "Arc counter overflow";

/// Trimmed reimplementation of Rust's core [`Arc`](alloc::sync::Arc).
struct Arc<T> {
    ptr: NonNull<ArcInner<T>>,
    phantom: PhantomData<ArcInner<T>>,
}

unsafe impl<T: Sync + Send> Send for Arc<T> {}
unsafe impl<T: Sync + Send> Sync for Arc<T> {}

impl<T: Sized> Arc<T> {
    unsafe fn from_inner(ptr: NonNull<ArcInner<T>>) -> Self {
        Self {
            ptr,
            phantom: PhantomData,
        }
    }

    unsafe fn from_ptr(ptr: *mut ArcInner<T>) -> Self {
        unsafe { Self::from_inner(NonNull::new_unchecked(ptr)) }
    }
}

/// Trimmed reimplementation of Rust's core [`Weak`](alloc::sync::Weak
struct Weak<T> {
    ptr: NonNull<ArcInner<T>>,
}

unsafe impl<T: Sync + Send> Send for Weak<T> {}
unsafe impl<T: Sync + Send> Sync for Weak<T> {}

// This is repr(C) to future-proof against possible field-reordering, which
// would interfere with otherwise safe [into|from]_raw() of transmutable
// inner types.
#[repr(C)]
struct ArcInner<T> {
    strong: atomic::AtomicUsize,
    weak: atomic::AtomicUsize,
    data: mem::MaybeUninit<T>,
}

unsafe impl<T: Sync + Send> Send for ArcInner<T> {}
unsafe impl<T: Sync + Send> Sync for ArcInner<T> {}

impl<T> Arc<T> {
    #[inline]
    pub fn try_new(data: T) -> Result<Arc<T>, TryNewError> {
        // Start the weak pointer count as 1 which is the weak pointer that's
        // held by all the strong pointers (kinda), see std/rc.rs for more info
        let mut x: Box<_> = box_try_new(ArcInner {
            strong: atomic::AtomicUsize::new(1),
            weak: atomic::AtomicUsize::new(1),
            data: mem::MaybeUninit::uninit(),
        })?;
        x.data.write(data);
        unsafe { Ok(Self::from_inner(Box::leak(x).into())) }
    }
}

impl<T> Arc<T> {
    /// Constructs an `Arc<T>` from a raw pointer.
    #[inline]
    pub unsafe fn from_raw(ptr: *const T) -> Self {
        unsafe {
            let offset = data_offset::<T>();

            // Reverse the offset to find the original ArcInner.
            let arc_ptr = ptr.byte_sub(offset) as *mut ArcInner<T>;

            Self::from_ptr(arc_ptr)
        }
    }
}

impl<T> Arc<T> {
    /// Consumes the `Arc`, returning the wrapped pointer.
    #[inline]
    pub fn into_raw(this: Self) -> *const T {
        let this = ManuallyDrop::new(this);
        Self::as_ptr(&*this)
    }

    /// Provides a raw pointer to the data.
    fn as_ptr(this: &Self) -> *const T {
        let ptr: *mut ArcInner<T> = NonNull::as_ptr(this.ptr);
        unsafe { &*ptr }.data.as_ptr()
    }

    /// Creates a new [`Weak`] pointer to this allocation.
    pub fn downgrade(this: &Self) -> Weak<T> {
        let mut cur = this.inner().weak.load(atomic::Ordering::Relaxed);

        loop {
            // We can't allow the refcount to increase much past `MAX_REFCOUNT`.
            assert!(cur <= MAX_REFCOUNT, "{}", INTERNAL_OVERFLOW_ERROR);
            match this.inner().weak.compare_exchange_weak(
                cur,
                cur + 1,
                atomic::Ordering::Relaxed,
                atomic::Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Weak { ptr: this.ptr };
                }
                Err(old) => cur = old,
            }
        }
    }

    #[inline]
    fn inner(&self) -> &ArcInner<T> {
        // This unsafety is ok because while this arc is alive we're guaranteed
        // that the inner pointer is valid. Furthermore, we know that the
        // `ArcInner` structure itself is `Sync` because the inner data is
        // `Sync` as well, so we're ok loaning out an immutable pointer to these
        // contents.
        unsafe { self.ptr.as_ref() }
    }

    // Non-inlined part of `drop`.
    #[inline(never)]
    unsafe fn drop_slow(&mut self) {
        // Drop the weak ref collectively held by all strong references when this
        // variable goes out of scope. This ensures that the memory is deallocated
        // even if the destructor of `T` panics.
        let _weak = Weak { ptr: self.ptr };

        // Destroy the data at this time, even though we must not free the box
        // allocation itself (there might still be weak pointers lying around).
        // We cannot use `get_mut_unchecked` here, because `self.alloc` is borrowed.
        unsafe { ptr::drop_in_place((*self.ptr.as_ptr()).data.as_mut_ptr()) };
    }
}

impl<T> Clone for Arc<T> {
    /// Makes a clone of the `Arc` pointer.
    #[inline]
    fn clone(&self) -> Arc<T> {
        // Using a relaxed ordering is alright here, as knowledge of the
        // original reference prevents other threads from erroneously deleting
        // the object.
        //
        // As explained in the [Boost documentation][1], Increasing the
        // reference counter can always be done with memory_order_relaxed: New
        // references to an object can only be formed from an existing
        // reference, and passing an existing reference from one thread to
        // another must already provide any required synchronization.
        //
        // [1]: (www.boost.org/doc/libs/1_55_0/doc/html/atomic/usage_examples.html)
        let old_size = self.inner().strong.fetch_add(1, atomic::Ordering::Relaxed);

        // However we need to guard against massive refcounts in case someone is
        // `mem::forget`ing Arcs. If we don't do this the count can overflow and
        // users will use-after free. This branch will never be taken in any
        // realistic program. We abort because such a program is incredibly
        // degenerate, and we don't care to support it.
        //
        // This check is not 100% water-proof: we error when the refcount grows beyond
        // `isize::MAX`. But we do that check *after* having done the increment,
        // so there is a chance here that the worst already happened and we
        // actually do overflow the `usize` counter. However, that requires the
        // counter to grow from `isize::MAX` to `usize::MAX` between the increment
        // above and the `abort` below, which seems exceedingly unlikely.
        //
        // This is a global invariant, and also applies when using a compare-exchange
        // loop to increment counters in other methods.
        // Otherwise, the counter could be brought to an almost-overflow using a
        // compare-exchange loop, and then overflow using a few `fetch_add`s.
        assert!(old_size <= MAX_REFCOUNT, "{}", INTERNAL_OVERFLOW_ERROR);

        unsafe { Self::from_inner(self.ptr) }
    }
}

impl<T> Deref for Arc<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        unsafe { self.inner().data.assume_init_ref() }
    }
}

impl<T> Drop for Arc<T> {
    /// Drops the `Arc`.
    #[inline]
    fn drop(&mut self) {
        // Because `fetch_sub` is already atomic, we do not need to synchronize
        // with other threads unless we are going to delete the object. This
        // same logic applies to the below `fetch_sub` to the `weak` count.
        if self.inner().strong.fetch_sub(1, atomic::Ordering::Release) != 1 {
            return;
        }

        // This fence is needed to prevent reordering of use of the data and
        // deletion of the data. Because it is marked `Release`, the decreasing
        // of the reference count synchronizes with this `Acquire` fence. This
        // means that use of the data happens before decreasing the reference
        // count, which happens before this fence, which happens before the
        // deletion of the data.
        //
        // As explained in the [Boost documentation][1],
        //
        // > It is important to enforce any possible access to the object in one
        // > thread (through an existing reference) to *happen before* deleting
        // > the object in a different thread. This is achieved by a "release"
        // > operation after dropping a reference (any access to the object
        // > through this reference must obviously happened before), and an
        // > "acquire" operation before deleting the object.
        //
        // In particular, while the contents of an Arc are usually immutable, it's
        // possible to have interior writes to something like a Mutex<T>. Since a
        // Mutex is not acquired when it is deleted, we can't rely on its
        // synchronization logic to make writes in thread A visible to a destructor
        // running in thread B.
        //
        // Also note that the Acquire fence here could probably be replaced with an
        // Acquire load, which could improve performance in highly-contended
        // situations. See [2].
        //
        // [1]: (www.boost.org/doc/libs/1_55_0/doc/html/atomic/usage_examples.html)
        // [2]: (https://github.com/rust-lang/rust/pull/41714)
        atomic::fence(atomic::Ordering::Acquire);

        unsafe {
            self.drop_slow();
        }
    }
}

/// Helper type to allow accessing the reference counts without
/// making any assertions about the data field.
struct WeakInner<'a> {
    weak: &'a atomic::AtomicUsize,
    strong: &'a atomic::AtomicUsize,
}

impl<T> Weak<T> {
    /// Converts a raw pointer previously created by
    /// [`into_raw()`](Self::into_raw) back into `Weak<T>`.
    #[inline]
    pub unsafe fn from_raw(ptr: *const T) -> Self {
        // See Weak::as_ptr for context on how the input pointer is derived.

        let ptr = {
            // SAFETY: data_offset is safe to call, as ptr references a real (potentially
            // dropped) T.
            let offset = data_offset::<T>();
            // Thus, we reverse the offset to get the whole RcInner.
            // SAFETY: the pointer originated from a Weak, so this offset is safe.
            unsafe { ptr.byte_sub(offset) as *mut ArcInner<T> }
        };

        // SAFETY: we now have recovered the original Weak pointer, so can create the
        // Weak.
        Weak {
            ptr: unsafe { NonNull::new_unchecked(ptr) },
        }
    }
}

impl<T> Weak<T> {
    /// Returns a raw pointer to the object `T` pointed to by this `Weak<T>`.
    fn as_ptr(&self) -> *const T {
        let ptr: *mut ArcInner<T> = NonNull::as_ptr(self.ptr);
        unsafe { (*ptr).data.as_ptr() }
    }

    /// Consumes the `Weak<T>` and turns it into a raw pointer.
    pub fn into_raw(self) -> *const T {
        ManuallyDrop::new(self).as_ptr()
    }
}

impl<T> Weak<T> {
    /// Attempts to upgrade the `Weak` pointer to an [`Arc`], delaying
    /// dropping of the inner value if successful.
    pub fn upgrade(&self) -> Option<Arc<T>> {
        #[inline]
        fn checked_increment(n: usize) -> Option<usize> {
            // Any write of 0 we can observe leaves the field in permanently zero state.
            if n == 0 {
                return None;
            }
            // See comments in `Arc::clone` for why we do this (for `mem::forget`).
            assert!(n <= MAX_REFCOUNT, "{}", INTERNAL_OVERFLOW_ERROR);
            Some(n + 1)
        }

        // We use a CAS loop to increment the strong count instead of a
        // fetch_add as this function should never take the reference count
        // from zero to one.
        if self
            .inner()
            .strong
            .fetch_update(atomic::Ordering::Relaxed, atomic::Ordering::Relaxed, checked_increment)
            .is_ok()
        {
            // SAFETY: pointer is not null, verified in checked_increment
            unsafe { Some(Arc::from_inner(self.ptr)) }
        } else {
            None
        }
    }

    /// Returns `None` when the pointer is dangling and there is no allocated
    /// `ArcInner`, (i.e., when this `Weak` was created by `Weak::new`).
    #[inline]
    fn inner(&self) -> WeakInner<'_> {
        let ptr = self.ptr.as_ptr();
        // We are careful to *not* create a reference covering the "data" field, as the
        // field may be mutated concurrently (for example, if the last `Arc` is
        // dropped, the data field will be dropped in-place).
        unsafe {
            WeakInner {
                strong: &(*ptr).strong,
                weak: &(*ptr).weak,
            }
        }
    }
}

impl<T> Clone for Weak<T> {
    /// Makes a clone of the `Weak` pointer that points to the same allocation.
    #[inline]
    fn clone(&self) -> Weak<T> {
        // See comments in Arc::clone() for why this is relaxed. This can use a
        // fetch_add (ignoring the lock) because the weak count is only locked
        // where are *no other* weak pointers in existence. (So we can't be
        // running this code in that case).
        let old_size = self.inner().weak.fetch_add(1, atomic::Ordering::Relaxed);

        // See comments in Arc::clone() for why we do this (for mem::forget).
        assert!(old_size <= MAX_REFCOUNT, "{}", INTERNAL_OVERFLOW_ERROR);

        Weak { ptr: self.ptr }
    }
}

impl<T> Drop for Weak<T> {
    /// Drops the `Weak` pointer.
    fn drop(&mut self) {
        if self.inner().weak.fetch_sub(1, atomic::Ordering::Release) == 1 {
            atomic::fence(atomic::Ordering::Acquire);
            let _box = unsafe { Box::from_raw(self.ptr.as_ptr()) };
        }
    }
}

impl<T> Unpin for Arc<T> {}

/// Gets the offset within an `ArcInner` for the payload.
const fn data_offset<T>() -> usize {
    mem::offset_of!(ArcInner<T>, data)
}

/// Generic [`SyncRcPtr`] implementation based on Rust's core
/// [`Arc`](alloc::sync::Arc).
///
/// # See also:
/// * [`GenericArcFactory`]
/// * [`GenericWeak`]
pub struct GenericArc<T> {
    ptr: Arc<T>,
}

impl<T> Deref for GenericArc<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.ptr
    }
}

impl<T> Clone for GenericArc<T> {
    fn clone(&self) -> Self {
        Self { ptr: self.ptr.clone() }
    }
}

impl<T: marker::Send + marker::Sync> SyncRcPtr<T> for GenericArc<T> {
    type WeakSyncRcPtr = GenericWeak<T>;

    type SyncRcPtrRef<'a>
        = GenericSyncRcPtrRef<'a, T, Self>
    where
        Self: 'a;

    fn as_ref(&self) -> Self::SyncRcPtrRef<'_> {
        <Self::SyncRcPtrRef<'_> as SyncRcPtrRef<'_, _, Self>>::new(self)
    }

    fn downgrade(&self) -> Self::WeakSyncRcPtr {
        Self::WeakSyncRcPtr {
            ptr: Arc::downgrade(&self.ptr),
        }
    }

    fn into_raw(this: Self) -> *const T {
        Arc::into_raw(this.ptr)
    }

    unsafe fn from_raw(ptr: *const T) -> Self {
        Self {
            ptr: unsafe { Arc::from_raw(ptr) },
        }
    }
}

/// [`WeakSyncRcPtr`] implementation associated with [`GenericArc`].
pub struct GenericWeak<T> {
    ptr: Weak<T>,
}

impl<T> Clone for GenericWeak<T> {
    fn clone(&self) -> Self {
        Self { ptr: self.ptr.clone() }
    }
}

impl<T: marker::Send + marker::Sync> WeakSyncRcPtr<T, GenericArc<T>> for GenericWeak<T> {
    fn upgrade(&self) -> Option<GenericArc<T>> {
        self.ptr.upgrade().map(|ptr| GenericArc { ptr })
    }

    fn into_raw(this: Self) -> *const T {
        this.ptr.into_raw()
    }

    unsafe fn from_raw(ptr: *const T) -> Self {
        Self {
            ptr: unsafe { Weak::from_raw(ptr) },
        }
    }
}

/// [`SyncRcPtrFactory`] implementation for [`GenericArc`].
pub struct GenericArcFactory;

impl SyncRcPtrFactory for GenericArcFactory {
    type SyncRcPtr<T>
        = GenericArc<T>
    where
        T: Sized + marker::Send + marker::Sync;

    fn try_new<T>(value: T) -> Result<Self::SyncRcPtr<T>, SyncRcPtrTryNewError>
    where
        T: marker::Send + marker::Sync,
    {
        Ok(GenericArc {
            ptr: Arc::try_new(value).map_err(|e| match e {
                TryNewError::MemoryAllocationFailure => SyncRcPtrTryNewError::AllocationFailure,
            })?,
        })
    }
}
