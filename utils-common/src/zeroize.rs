// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Configuration dependent, transparent aliases as well as some utilities
//! related to the [`Zeroize`](https://docs.rs/zeroize/latest/zeroize/trait.Zeroize.html) crate.
//!
//! Depending on whether or not the `zeroize` Cargo feature is enabled,
//! [`Zeroize`], [`ZeroizeOnDrop`] and [`Zeroizing`] are either defined as
//! aliases to the actual definitions from the [`zeroize crate`](https://docs.rs/zeroize/latest/zeroize/index.html) or to trivial
//! drop-in substitutes.
//!
//! In addition to that, zeroization related helpers like [`ZeroizingFlat`] are
//! being provided.

extern crate alloc;
use alloc::boxed::Box;

use core::{clone::Clone, convert, mem, ops};

#[cfg(feature = "zeroize")]
use zeroize;

#[cfg(feature = "zeroize")]
#[doc(hidden)]
mod cfg {
    pub use zeroize::Zeroize;
    pub use zeroize::ZeroizeOnDrop;
    pub use zeroize::Zeroizing;
}

#[cfg(not(feature = "zeroize"))]
#[doc(hidden)]
mod cfg {
    use core::ops;

    pub trait Zeroize {
        fn zeroize(&mut self);
    }

    impl<T> Zeroize for T {
        fn zeroize(&mut self) {}
    }

    pub trait ZeroizeOnDrop {}

    #[derive(Clone, Copy)]
    #[repr(transparent)]
    pub struct Zeroizing<T>(T);

    impl<T> core::ops::Deref for Zeroizing<T> {
        type Target = T;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl<T> ops::DerefMut for Zeroizing<T> {
        fn deref_mut(&mut self) -> &mut <Self as ops::Deref>::Target {
            &mut self.0
        }
    }

    impl<T> From<T> for Zeroizing<T> {
        fn from(value: T) -> Self {
            Self(value)
        }
    }
}

/// Configuration abstraction alias definition for
/// [`zeroize::Zeroize`](https://docs.rs/zeroize/latest/zeroize/trait.Zeroize.html).
///
/// Depending on whether or the Cargo feature `zeroize` is enabled, this is
/// either an alias to the real [`zeroize::Zeroize`](https://docs.rs/zeroize/latest/zeroize/trait.Zeroize.html) or to some
/// API compatible drop-in substitute implemented trivially for any type.
pub use cfg::Zeroize;

/// Configuration abstraction alias definition for
/// [`zeroize::ZeroizeOnDrop`](https://docs.rs/zeroize/latest/zeroize/trait.ZeroizeOnDrop.html).
///
/// Depending on whether or the Cargo feature `zeroize` is enabled, this is
/// either an alias to the real [`zeroize::ZeroizeOnDrop`](https://docs.rs/zeroize/latest/zeroize/trait.ZeroizeOnDrop.html)
/// or to some API compatible drop-in substitute.
pub use cfg::ZeroizeOnDrop;

/// Configuration abstraction alias definition for
/// [`zeroize::Zeroizing`](https://docs.rs/zeroize/latest/zeroize/struct.Zeroizing.html).
///
/// Depending on whether or the Cargo feature `zeroize` is enabled, this is
/// either an alias to the real [`zeroize::Zeroizing`](https://docs.rs/zeroize/latest/zeroize/struct.Zeroizing.html) or to
/// some trivial, API compatible drop-in substitute.
pub use cfg::Zeroizing;

/// Zeroize a flat type/struct on `drop`.
///
/// For external types not implementing `Zeroize`, this can be used to still
/// clear its memory after it has been dropped.
///
/// Only the flat memory backing `T` itself is getting cleared, but **not** any
/// heap allocations the value itself possibly owns, like e.g. some managed
/// through `Vec`s, `Box`es or alike.
///
/// <div class="warning">
///
/// Works reliably only once `Box`ed and only for the memory owned by the `Box`,
/// no guarantees are being made for temporary copies emitted by the compiler
/// during construction or unpeeling through [`take_with()`](Self::take_with),
/// [`take_boxed_with()`](Self::take_boxed_with) or
/// [`into_inner()`](Self::into_inner) -- it all depends on compiler
/// optimizations then
///
/// </div>
///
/// If the `zeroize` Cargo feature is off, `ZeroizingFlat` becomes a trivial
/// wrapper.
#[repr(transparent)]
pub struct ZeroizingFlat<T> {
    value: mem::MaybeUninit<T>,
}

impl<T> ZeroizingFlat<T> {
    /// Wrap a value for zeroization at drop.
    ///
    /// <div class="warning">
    ///
    /// Even when constructed from rvalues, it all depends on compiler
    /// optimizations whether or not the value will effectively get
    /// constructed in place or non-zeroized intermediate copies will
    /// be made on the stack.
    ///
    /// </div>
    ///
    /// # Arguments:
    ///
    /// * `value` - The value to wrap.
    pub fn new(value: T) -> Self {
        Self {
            value: mem::MaybeUninit::new(value),
        }
    }

    /// Take the wrapped value and invoke a callback on it.
    ///
    /// Functionally equivalent to
    /// ```ignore
    /// f(self.into_inner())
    /// ```
    /// Compared to the code above, `take_with()` fosters certain compiler
    /// optimizations for copy elisions because it makes it possible to
    /// invoke `f()` directly on the original memory backing the wrapped value
    /// instead of on a temporary stack copy thereof.
    ///
    /// <div class="warning">
    ///
    /// There are no guarantees regarding whether such an optimization will
    /// actually be made by the compiler. In particular, the compiler might
    /// create non-zeroized temporary copies of the wrapped data on the
    /// stack.
    ///
    /// </div>
    ///
    /// # Arguments:
    ///
    /// * `f` - The callback to invoke on the unwrapped value. The return value
    ///   gets propagated back.
    #[allow(unused_mut)]
    pub fn take_with<R, F: FnOnce(T) -> R>(mut self, f: F) -> R {
        // Enable the compiler to call f() on the original data without preparing a
        // temporary copy on the stack. Whether or not this works out depends on
        // compiler optimizations though.
        let inner = unsafe { self.value.assume_init_read() };
        let r = f(inner);
        #[cfg(feature = "zeroize")]
        {
            let p_value = &raw mut self.value;
            unsafe { zeroize::zeroize_flat_type(p_value) };
        }
        // Don't invoke drop, the wrapped value was moved into f() above.
        mem::forget(self);
        r
    }

    /// Take the wrapped value.
    ///
    /// <div class="warning">
    ///
    /// Once unwrapped, no zeroization guarantees will apply to the unwrapped
    /// value anymore, even in the following example:
    /// ```ignore
    /// let secret: ZeroizingFlat<T>;
    /// let secret = ZeroizingFlat::new(secret.into_inner());
    /// ```
    ///
    /// </div>
    pub fn into_inner(self) -> T {
        self.take_with(|value| value)
    }

    /// Take the wrapped value from a `Box<Self>` and invoke a callback on it.
    ///
    /// Functionally equivalent to
    /// ```ignore
    /// Box::into_inner(self).take_with(f)
    /// ```
    /// with `Box::into_inner()` being unstable at the time of writing.
    ///
    /// Note that in the code snippet above, the `Box::into_inner()` to be more
    /// specific, would almost certainly move `Self` into a temporary
    /// location on the stack, and that stack copy would then eventually get
    /// zeroized, **not** the memory previously owned by the `Box`.
    /// `take_boxed_with()` on the other hand guarantees that the memory owned
    /// by the `Box` will get zeroized.
    ///
    /// Furthermore, `take_boxed_with()` fosters certain compiler
    /// optimizations for copy elisions because it makes it possible to
    /// invoke `f()` directly on the original memory managed by the `Box`
    /// instead of on a temporary stack copy thereof.
    ///
    /// <div class="warning">
    ///
    /// There are no guarantees regarding whether such an optimization will
    /// actually be made by the compiler. In particular, the compiler might
    /// create non-zeroized temporary copies of the wrapped data on the
    /// stack.
    ///
    /// </div>
    ///
    /// # Arguments:
    ///
    /// * `f` - The callback to invoke on the unwrapped value. The return value
    ///   gets propagated back.
    pub fn take_boxed_with<R, F: FnOnce(T) -> R>(self: Box<Self>, f: F) -> R {
        // Transform the Box<Self> to Box<ManuallyDrop<Self>> in order to avoid double
        // frees upon drop of Self on unwind from f() -- the ownership of the
        // wrapped value gets moved into f() and it ought to get dropped from
        // there only.
        let p_this = Box::into_raw(self) as *mut mem::ManuallyDrop<Self>;
        let this = unsafe { Box::from_raw(p_this) };

        // Enable the compiler to call f() on the original data owned by the Box without
        // preparing a temporary copy on the stack. Whether or not this works
        // out depends on compiler optimizations though.
        let inner = unsafe { this.value.assume_init_read() };
        let r = f(inner);

        // Now zeroize the memory and deallocate.
        let p_this = Box::into_raw(this) as *mut Self;
        #[cfg(feature = "zeroize")]
        {
            let p_value = &raw mut unsafe { &mut *p_this }.value;
            unsafe { zeroize::zeroize_flat_type(p_value) }
        };
        // Don't drop upon deallocation, the value had been moved into f() above.
        let p_this = p_this as *mut mem::ManuallyDrop<Self>;
        drop(unsafe { Box::from_raw(p_this) });

        r
    }

    /// Replace the wrapped value with a new one.
    ///
    /// Compared to mere reassignment of Self, this avoids a redundant
    /// zeroization pass between dropping the old and assigning the new
    /// value.
    ///
    /// <div class="warning">
    ///
    /// The compiler might emit temorary copies of `value` on the stack not
    /// covered by any zeroization.
    ///
    /// </div>
    ///
    /// # Arguments:
    ///
    /// * `value` - The new value to wrap.
    pub fn replace(&mut self, value: T) {
        unsafe { self.value.assume_init_drop() };
        self.value = mem::MaybeUninit::new(value);
    }

    /// Replace the value wrapped in a `Box`ed `Self`.
    ///
    ///
    /// Compared to [`replace`](Self::replace), `replace_boxed_with()` fosters
    /// certain compiler optimizations for copy elisions because it makes it
    /// possible to place the new value directly into the memory backing the
    /// originally wrapped value instead of into an intermediate stack
    /// copy first.
    ///
    /// <div class="warning">
    ///
    /// There are no guarantees regarding whether such an optimization will
    /// actually be made by the compiler. In particular, the compiler might
    /// create non-zeroized temporary copies of the wrapped data on the stack.
    ///
    /// </div>
    ///
    /// `replace_boxed_with()` takes a `Box<Self>` and a callback for obtaining
    /// the new replacement for the wrapped value, invokes `f()` to obtain
    /// the replacement, wraps it in `self` and returns the `Box<Self>`
    /// back. No memory reallocation will be made in the course.
    ///
    /// # Arguments:
    ///
    /// * `f` - The callback to obtain the replacement for the wrapped value
    ///   from.
    pub fn replace_boxed_with<F: FnOnce() -> T>(mut self: Box<Self>, f: F) -> Box<Self> {
        unsafe { self.value.assume_init_drop() };
        // Temporarily turn the Box<Self> into a Box<ManuallyDrop<Self>> to avoid double
        // frees upon unwinding from f() -- the formerly wapped valued has just
        // been dropped, don't do it again.
        let p_this = Box::into_raw(self) as *mut mem::ManuallyDrop<Self>;
        let mut this = unsafe { Box::from_raw(p_this) };
        this.value = mem::MaybeUninit::new(f());
        let p_this = Box::into_raw(this) as *mut Self;
        unsafe { Box::from_raw(p_this) }
    }
}

impl<T> Drop for ZeroizingFlat<T> {
    fn drop(&mut self) {
        unsafe { mem::MaybeUninit::assume_init_drop(&mut self.value) };
        #[cfg(feature = "zeroize")]
        unsafe {
            zeroize::zeroize_flat_type(&raw mut self.value)
        };
    }
}

impl<T> convert::From<T> for ZeroizingFlat<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T> ops::Deref for ZeroizingFlat<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { self.value.assume_init_ref() }
    }
}

impl<T> ops::DerefMut for ZeroizingFlat<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.value.assume_init_mut() }
    }
}

impl<T: Clone> Clone for ZeroizingFlat<T> {
    fn clone(&self) -> Self {
        Self {
            value: mem::MaybeUninit::new(unsafe { self.value.assume_init_ref() }.clone()),
        }
    }
}
