// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Scatter-gather lists for byte slices.
//!
//! The destination and/or source byte buffers for certain operations like
//! copying, encryption etc. can be organized very differently for each use-case
//! and represented e.g. as
//! - a single byte slice,
//! - a slice of byte slices,
//! - a [`Iterator`] over several byte slices.
//!
//! Define *IO slice iterator* traits for abstracting the different capabilities
//! of these, and provide implementations for the common cases listed above.

// Lifetimes are not obvious at first sight here, make them explicit.
#![allow(clippy::needless_lifetimes)]

use crate::{bitmanip::BitManip as _, ct_cmp, xor};
use core::{convert, fmt, iter, marker};

/// Error information for [`IoSlicesIterError::IoSlicesError`].
#[derive(PartialEq, Eq, Debug)]
pub enum IoSlicesError {
    BuffersExhausted,
}

/// Error returned by various primitives operating on
/// [*IO slice iterators*](IoSlicesIterCommon).
#[derive(Debug)]
pub enum IoSlicesIterError<BackendIteratorError> {
    /// The underlying [*IO slice iterator*](IoSlicesIterCommon) returned an
    /// error.
    BackendIteratorError(BackendIteratorError),
    /// The operation itself encountered an error, e.g. an unexpected premature
    /// buffer end.
    IoSlicesError(IoSlicesError),
}

/// Base trait implemented by all *IO slice iterators*.
///
/// A *IO slice iterator* represents a sequence of byte slices, implementing
/// operations for iterating over these one by one, examining the remainder
/// etc..
pub trait IoSlicesIterCommon {
    /// Associated type defining the error type possibly returned by the
    /// iterator on error.
    ///
    /// Most commonly this will be either [`Infallible`](convert::Infallible) or
    /// some error representing an internal logic error.
    type BackendIteratorError: Sized + fmt::Debug;

    /// The next head byte slice's length.
    ///
    /// The returned value defines a guaranteed lower bound on the byte slice
    /// length obtainable from the next invocation of
    /// [`next_slice()`](IoSlicesIter::next_slice) or
    /// [`next_slice_mut()`](IoSlicesMutIter::next_slice_mut).
    ///
    /// # Errors:
    ///
    /// * [`BackendIteratorError`](Self::BackendIteratorError) - Error specific
    ///   to the trait implementation.
    fn next_slice_len(&mut self) -> Result<usize, Self::BackendIteratorError>;

    /// Test whether there are any more byte slices left.
    ///
    /// # Errors:
    ///
    /// * [`BackendIteratorError`](Self::BackendIteratorError) - Error specific
    ///   to the trait implementation.
    fn is_empty(&mut self) -> Result<bool, Self::BackendIteratorError> {
        Ok(self.next_slice_len()? == 0)
    }

    /// Map the iterator's [`BackendIteratorError`](Self::BackendIteratorError)
    fn map_err<F, E>(self, f: F) -> IoSlicesIterMapErr<Self, F, E>
    where
        Self: Sized,
        F: Fn(Self::BackendIteratorError) -> E,
        E: Sized + fmt::Debug,
    {
        IoSlicesIterMapErr { iter: self, f }
    }

    /// Convenience helper to map an [`Infallible`](convert::Infallible)
    /// [`BackendIteratorError`](Self::BackendIteratorError) to some other error
    /// time.
    fn map_infallible_err<E>(self) -> IoSlicesIterMapErr<Self, fn(convert::Infallible) -> E, E>
    where
        Self: Sized,
        Self: IoSlicesIterCommon<BackendIteratorError = convert::Infallible>,
        E: Sized + fmt::Debug,
    {
        IoSlicesIterMapErr {
            iter: self,
            f: |e: convert::Infallible| -> E { match e {} },
        }
    }

    /// Create a reference *IO slice iterator* adaptor.
    ///
    /// Advancing the reference will advance the original. This helper exists
    /// only to work around limitations with lifetimes on `mut` references.
    fn as_ref<'a, 'b>(&'a mut self) -> CovariantIoSlicesIterRef<'a, 'b, Self>
    where
        Self: Sized,
    {
        CovariantIoSlicesIterRef::new(self)
    }

    /// Create a *IO slice iterator* adaptor covering exactly the specified
    /// number of head bytes from `self`.
    ///
    /// A [`BuffersExhausted`](IoSlicesError::BuffersExhausted) error will get
    /// returned during iteration if the underlying iterator, i.e. `self`,
    /// yields less than `n` bytes.
    ///
    /// # Arguments:
    ///
    /// * `n` - The number of head bytes to yield from the resulting *IO slice
    ///   iterator* adaptor.
    fn take_exact(self, n: usize) -> IoSlicesIterTakeExact<Self>
    where
        Self: Sized,
    {
        IoSlicesIterTakeExact::new(self, n)
    }

    /// Chain two *IO slice iterators* back to back.
    ///
    /// The created *IO slice iterator* adaptor will first exhaust `self`, and
    /// then proceed to iterate `other`.
    ///
    /// # Arguments:
    ///
    /// * `other` - The second *IO slice iterator* to chain after `self`.
    fn chain<I1>(self, other: I1) -> IoSlicesIterChain<Self, I1>
    where
        Self: Sized,
        I1: Sized + IoSlicesIterCommon<BackendIteratorError = Self::BackendIteratorError>,
    {
        IoSlicesIterChain::new(self, other)
    }
}

impl<I: ?Sized + IoSlicesIterCommon> IoSlicesIterCommon for &mut I {
    type BackendIteratorError = I::BackendIteratorError;

    fn next_slice_len(&mut self) -> Result<usize, Self::BackendIteratorError> {
        I::next_slice_len(*self)
    }
}

/// *IO slice iterator* returning readable, non-`mut` byte slices.
pub trait IoSlicesIter<'a>: IoSlicesIterCommon {
    /// Obtain the next byte slice from the front.
    ///
    /// If the *IO slice iterator* is exhausted, it will signal the fact by
    /// returning `Ok(None)`. Otherwise a `Ok(&[u8])` will get returned.
    ///
    /// If `max_len` is not `None`, it defines the maximum length of the slice
    /// to get returned. That is, the implementation might have a longer
    /// byte slice available at its head, but would split that up into two
    /// parts as appropriate then and return the remainder in the subsequent
    /// iteration only.
    ///
    /// # Arguments:
    ///
    /// * `max_len` - Upper bound on the returned byte slice's length, if any.
    ///
    /// # Errors:
    ///
    /// * [`BackendIteratorError`](IoSlicesIterCommon::BackendIteratorError) -
    ///   Error specific to the trait implementation.
    fn next_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError>;

    /// Skip over a specified number of bytes.
    ///
    /// # Arguments:
    ///
    /// * `distance` - The number of bytes to skip over at the head.
    ///
    /// # Errors:
    ///
    /// * [`BackendIteratorError`](IoSlicesIterError::BackendIteratorError) -
    ///   Error specific to the trait implementation.
    /// * [`IoSlicesError`](IoSlicesIterError::BackendIteratorError) - The
    ///   iterator had less than `distance` bytes left.
    fn skip(&mut self, mut distance: usize) -> Result<(), IoSlicesIterError<Self::BackendIteratorError>> {
        while distance != 0 {
            match self.next_slice(Some(distance)) {
                Ok(Some(consumed)) => {
                    distance -= consumed.len();
                }
                Ok(None) => {
                    return Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted));
                }
                Err(e) => return Err(IoSlicesIterError::BackendIteratorError(e)),
            };
        }
        Ok(())
    }

    /// Compare two *IO slice iterators* for equality in constant time.
    ///
    /// # Arguments:
    ///
    /// * `other` - The *IO slice iterator* to compare `self` against.
    ///
    /// # Errors:
    ///
    /// * [`BackendIteratorError`](IoSlicesIterCommon::BackendIteratorError) -
    ///   Error specific to the trait implementation.
    fn ct_eq_with_iter<'b, OI: Sized + IoSlicesIter<'b, BackendIteratorError = Self::BackendIteratorError>>(
        mut self,
        mut other: OI,
    ) -> Result<cmpa::LimbChoice, Self::BackendIteratorError>
    where
        Self: Sized,
    {
        let mut is_eq = cmpa::LimbChoice::from(1);
        loop {
            let cur_slice_len = self.next_slice_len()?.min(other.next_slice_len()?);
            let cur_self_slice = match self.next_slice(Some(cur_slice_len))? {
                Some(dst) => dst,
                None => {
                    break;
                }
            };
            let cur_other_slice = match other.next_slice(Some(cur_slice_len))? {
                Some(src) => src,
                None => {
                    return Ok(cmpa::LimbChoice::from(0));
                }
            };
            is_eq &= ct_cmp::ct_bytes_eq(cur_self_slice, cur_other_slice);
        }
        return Ok(is_eq & cmpa::LimbChoice::from(other.next_slice(None)?.is_none() as cmpa::LimbType));
    }
}

impl<'a, 'b: 'a, I: ?Sized + IoSlicesIter<'b>> IoSlicesIter<'a> for &'a mut I {
    fn next_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        I::next_slice(*self, max_len)
    }
}

/// *IO slice iterator* returning writeable, `mut` byte slices.
pub trait IoSlicesMutIter<'a>: IoSlicesIter<'a> {
    /// Obtain the next byte slice from the front.
    ///
    /// If the *IO slice iterator* is exhausted, it will signal the fact by
    /// returning `Ok(None)`. Otherwise a `Ok(&mut [u8])` will get returned.
    ///
    /// If `max_len` is not `None`, it defines the maximum length of the slice
    /// to get returned. That is, the implementation might have a longer
    /// byte slice available at its head, but would split that up into two
    /// parts as appropriate then and return the remainder in the subsequent
    /// iteration only.
    ///
    /// # Arguments:
    ///
    /// * `max_len` - Upper bound on the returned byte slice's length, if any.
    ///
    /// # Errors:
    ///
    /// * [`BackendIteratorError`](IoSlicesIterCommon::BackendIteratorError) -
    ///   Error specific to the trait implementation.
    fn next_slice_mut(&mut self, max_len: Option<usize>) -> Result<Option<&'a mut [u8]>, Self::BackendIteratorError>;

    /// Copy bytes from another *IO slice iterator*.
    ///
    /// Bytes will get copied and the *IO slice iterators* advanced until either
    /// the destination or source iterator has been exhausted.
    ///
    /// # Arguments:
    ///
    /// * `src_iter` - The source *IO slice iterator* to copy bytes from.
    ///
    /// # Errors:
    ///
    /// * [`BackendIteratorError`](IoSlicesIterCommon::BackendIteratorError) -
    ///   Error specific to the trait implementation.
    fn copy_from_iter<'b>(
        &mut self,
        src_iter: &mut dyn IoSlicesIter<'b, BackendIteratorError = Self::BackendIteratorError>,
    ) -> Result<usize, Self::BackendIteratorError> {
        let mut copied = 0usize;
        loop {
            let cur_slice_len = self.next_slice_len()?.min(src_iter.next_slice_len()?);
            let dst = match self.next_slice_mut(Some(cur_slice_len))? {
                Some(dst) => dst,
                None => {
                    return Ok(copied);
                }
            };
            let src = match src_iter.next_slice(Some(cur_slice_len))? {
                Some(src) => src,
                None => {
                    return Ok(copied);
                }
            };
            dst.copy_from_slice(src);
            copied += cur_slice_len;
        }
    }

    /// Copy bytes from another *IO slice iterator*.
    ///
    /// # Arguments:
    ///
    /// * `src_iter` - The source *IO slice iterator* to copy bytes from.
    ///
    /// # Errors:
    ///
    /// * [`BackendIteratorError`](IoSlicesIterError::BackendIteratorError) -
    ///   Error specific to the trait implementation.
    /// * [`IoSlicesError`](IoSlicesIterError::BackendIteratorError) - The
    ///   number of bytes covered by the destination and source *IO slice
    ///   iterators* was different.
    fn copy_from_iter_exhaustive<'b, SI: Sized + IoSlicesIter<'b, BackendIteratorError = Self::BackendIteratorError>>(
        mut self,
        mut src_iter: SI,
    ) -> Result<(), IoSlicesIterError<Self::BackendIteratorError>>
    where
        Self: Sized,
    {
        self.copy_from_iter(&mut src_iter)
            .map_err(IoSlicesIterError::BackendIteratorError)?;
        if !self.is_empty().map_err(IoSlicesIterError::BackendIteratorError)?
            || !src_iter.is_empty().map_err(IoSlicesIterError::BackendIteratorError)?
        {
            return Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted));
        }
        Ok(())
    }

    /// Xor with bytes from another *IO slice iterator*.
    ///
    /// Bytes will get xored and the *IO slice iterators* advanced until either
    /// the destination or source iterator has been exhausted.
    /// # Arguments:
    ///
    /// * `src_iter` - The source *IO slice iterator* to xor bytes from into
    ///   `self`.
    ///
    /// # Errors:
    ///
    /// * [`BackendIteratorError`](IoSlicesIterCommon::BackendIteratorError) -
    ///   Error specific to the trait implementation.
    fn xor_from_iter<'b>(
        &mut self,
        src_iter: &mut dyn IoSlicesIter<'b, BackendIteratorError = Self::BackendIteratorError>,
    ) -> Result<usize, Self::BackendIteratorError> {
        let mut copied = 0usize;
        loop {
            let cur_slice_len = self.next_slice_len()?.min(src_iter.next_slice_len()?);
            let dst = match self.next_slice_mut(Some(cur_slice_len))? {
                Some(dst) => dst,
                None => {
                    return Ok(copied);
                }
            };
            let src = match src_iter.next_slice(Some(cur_slice_len))? {
                Some(src) => src,
                None => {
                    return Ok(copied);
                }
            };
            xor::xor_bytes(dst, src);
            copied += cur_slice_len;
        }
    }

    /// Fill all of an *IO slice iterator's* bytes with a fixed value.
    ///
    /// # Arguments:
    ///
    /// * `value` - The fill byte value.
    ///
    /// # Errors:
    ///
    /// * [`BackendIteratorError`](IoSlicesIterCommon::BackendIteratorError) -
    ///   Error specific to the trait implementation.
    fn fill(mut self, value: u8) -> Result<(), Self::BackendIteratorError>
    where
        Self: Sized,
    {
        while let Some(dst) = self.next_slice_mut(None)? {
            dst.fill(value)
        }
        Ok(())
    }
}

impl<'a, 'b: 'a, I: ?Sized + IoSlicesMutIter<'b>> IoSlicesMutIter<'a> for &'a mut I {
    fn next_slice_mut(&mut self, max_len: Option<usize>) -> Result<Option<&'a mut [u8]>, Self::BackendIteratorError> {
        I::next_slice_mut(*self, max_len)
    }
}

/// *IO slice iterator* from which readable, non-`mut` byte slices can get
/// consumed from either end.
pub trait DoubleEndedIoSlicesIter<'a>: IoSlicesIter<'a> {
    /// Obtain the next byte slice from the back.
    ///
    /// If the *IO slice iterator* is exhausted, it will signal the fact by
    /// returning `Ok(None)`. Otherwise a `Ok(&[u8])` will get returned.
    ///
    /// If `max_len` is not `None`, it defines the maximum length of the slice
    /// to get returned. That is, the implementation might have a longer
    /// byte slice available at its tail, but would split that up into two
    /// parts as appropriate then and return the remainder in the subsequent
    /// iteration only.
    ///
    /// # Arguments:
    ///
    /// * `max_len` - Upper bound on the returned byte slice's length, if any.
    ///
    /// # Errors:
    ///
    /// * [`BackendIteratorError`](IoSlicesIterCommon::BackendIteratorError) -
    ///   Error specific to the trait implementation.
    fn next_back_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError>;

    /// Skip over a specified number of bytes at the back.
    ///
    /// # Arguments:
    ///
    /// * `distance` - The number of bytes to skip over at the back.
    ///
    /// # Errors:
    ///
    /// * [`BackendIteratorError`](IoSlicesIterError::BackendIteratorError) -
    ///   Error specific to the trait implementation.
    /// * [`IoSlicesError`](IoSlicesIterError::BackendIteratorError) - The
    ///   iterator had less than `distance` bytes left.
    fn skip_back(&mut self, mut distance: usize) -> Result<(), IoSlicesIterError<Self::BackendIteratorError>> {
        while distance != 0 {
            match self.next_back_slice(Some(distance)) {
                Ok(Some(consumed)) => {
                    distance -= consumed.len();
                }
                Ok(None) => {
                    return Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted));
                }
                Err(e) => return Err(IoSlicesIterError::BackendIteratorError(e)),
            };
        }
        Ok(())
    }
}

impl<'a, 'b: 'a, I: ?Sized + DoubleEndedIoSlicesIter<'b>> DoubleEndedIoSlicesIter<'a> for &'a mut I {
    fn next_back_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        I::next_back_slice(*self, max_len)
    }
}

/// *IO slice iterator* from which writeable, `mut` byte slices can get consumed
/// from either end..
pub trait DoubleEndedIoSlicesMutIter<'a>: IoSlicesMutIter<'a> + DoubleEndedIoSlicesIter<'a> {
    /// Obtain the next byte slice from the back.
    ///
    /// If the *IO slice iterator* is exhausted, it will signal the fact by
    /// returning `Ok(None)`. Otherwise a `Ok(&[u8])` will get returned.
    ///
    /// If `max_len` is not `None`, it defines the maximum length of the slice
    /// to get returned. That is, the implementation might have a longer
    /// byte slice available at its tail, but would split that up into two
    /// parts as appropriate then and return the remainder in the subsequent
    /// iteration only.
    ///
    /// # Arguments:
    ///
    /// * `max_len` - Upper bound on the returned byte slice's length, if any.
    ///
    /// # Errors:
    ///
    /// * [`BackendIteratorError`](IoSlicesIterCommon::BackendIteratorError) -
    ///   Error specific to the trait implementation.
    fn next_back_slice_mut(
        &mut self,
        max_len: Option<usize>,
    ) -> Result<Option<&'a mut [u8]>, Self::BackendIteratorError>;
}

impl<'a, 'b: 'a, I: ?Sized + DoubleEndedIoSlicesMutIter<'b>> DoubleEndedIoSlicesMutIter<'a> for &'a mut I {
    fn next_back_slice_mut(
        &mut self,
        max_len: Option<usize>,
    ) -> Result<Option<&'a mut [u8]>, Self::BackendIteratorError> {
        I::next_back_slice_mut(*self, max_len)
    }
}

/// *IO slice iterator* whose byte slices can get visited with a callback.
///
/// This is intended for tasks like accumulating the total number of bytes
/// or testing whether all of an *IO slice iterator's* byte slices have a given
/// alignment.
///
/// Note that a [`PeekableIoSlicesIter`] can always be made a
/// [`WalkableIoSlicesIter`], but the latter qualifies as a `dyn` compatible
/// trait whereas the former does not.
pub trait WalkableIoSlicesIter<'a>: IoSlicesIter<'a> {
    /// Visit all byte slices with a callback.
    ///
    /// Stop the walk once `cb` returns `false`, otherwise keep going.
    ///
    /// # Arguments:
    ///
    ///  * `cb` - The callback to invoke on each slice.
    ///
    /// # Errors:
    ///
    /// * [`BackendIteratorError`](IoSlicesIterCommon::BackendIteratorError) -
    ///   Error specific to the trait implementation.
    fn for_each(&self, cb: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), Self::BackendIteratorError>;

    /// Total remaining bytes in the *IO slice iterator*.
    ///
    /// # Errors:
    ///
    /// * [`BackendIteratorError`](IoSlicesIterCommon::BackendIteratorError) -
    ///   Error specific to the trait implementation.
    fn total_len(&self) -> Result<usize, Self::BackendIteratorError> {
        let mut l = 0;
        self.for_each(&mut |slice| {
            l += slice.len();
            true
        })?;
        Ok(l)
    }

    /// Test whether all of an *IO slice iterator's* byte slice's length have a
    /// given alignment.
    ///
    /// # Arguments:
    ///
    /// * `alignment` - The desired alignment.
    ///
    /// # Errors:
    ///
    /// * [`BackendIteratorError`](IoSlicesIterCommon::BackendIteratorError) -
    ///   Error specific to the trait implementation.
    fn all_lengths_multiple_of(&self, alignment: usize) -> Result<bool, Self::BackendIteratorError> {
        let mut all_multiple_of = true;
        if alignment.is_pow2() {
            self.for_each(&mut |slice| {
                all_multiple_of &= slice.len() & (alignment - 1) == 0;
                all_multiple_of
            })?;
        } else {
            self.for_each(&mut |slice| {
                all_multiple_of &= slice.len() % alignment == 0;
                all_multiple_of
            })?;
        }
        Ok(all_multiple_of)
    }
}

impl<'a, 'b: 'a, I: ?Sized + WalkableIoSlicesIter<'b>> WalkableIoSlicesIter<'a> for &'a mut I {
    fn for_each(&self, cb: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), Self::BackendIteratorError> {
        I::for_each(*self, cb)
    }
}

/// Convenience trait for requiring bounds on [`IoSlicesMutIter`] and
/// [`WalkableIoSlicesIter`].
pub trait WalkableIoSlicesMutIter<'a>: IoSlicesMutIter<'a> + WalkableIoSlicesIter<'a> {}

impl<'a, I: IoSlicesMutIter<'a> + WalkableIoSlicesIter<'a>> WalkableIoSlicesMutIter<'a> for I {}

/// A multipass *IO slice iterator* returning readable, non-`mut` byte slices.
pub trait PeekableIoSlicesIter<'a>: WalkableIoSlicesIter<'a> {
    /// The iterator type returned by
    /// [`decoupled_borrow()`](Self::decoupled_borrow).
    type DecoupledBorrowIterType<'b>: PeekableIoSlicesIter<'b, BackendIteratorError = Self::BackendIteratorError>
    where
        Self: 'b;

    /// Spawn an independent *IO slice iterator* over `self`'s data.
    ///
    /// Operations on the spawn don't affect any of `self`'s state.
    fn decoupled_borrow<'b>(&'b self) -> Self::DecoupledBorrowIterType<'b>;
}

// Rust would not allow different ("unconstrained") lifetimes for I and the
// reference here.  That's the reason why CovariantIoSlicesIterRef exists.
impl<'a, I: ?Sized + PeekableIoSlicesIter<'a>> PeekableIoSlicesIter<'a> for &'a mut I {
    type DecoupledBorrowIterType<'c>
        = I::DecoupledBorrowIterType<'c>
    where
        Self: 'c;

    fn decoupled_borrow<'c>(&'c self) -> Self::DecoupledBorrowIterType<'c> {
        I::decoupled_borrow(*self)
    }
}

/// Convenience trait for requiring bounds on [`IoSlicesMutIter`] and
/// [`PeekableIoSlicesIter`].
pub trait PeekableIoSlicesMutIter<'a>: IoSlicesMutIter<'a> + PeekableIoSlicesIter<'a> {}

impl<'a, I: IoSlicesMutIter<'a> + PeekableIoSlicesIter<'a>> PeekableIoSlicesMutIter<'a> for I {}

/// A multipass *IO slice iterator* returning writeable, `mut` byte slices.
pub trait MutPeekableIoSlicesMutIter<'a>: IoSlicesMutIter<'a> + PeekableIoSlicesIter<'a> {
    /// The iterator type returned by
    /// [`decoupled_borrow_mut()`](Self::decoupled_borrow_mut).
    type DecoupledBorrowMutIterType<'b>: MutPeekableIoSlicesMutIter<'b, BackendIteratorError = Self::BackendIteratorError>
    where
        Self: 'b;

    /// Spawn an independent *IO slice iterator* over `self`'s data.
    ///
    /// Operations on the spawn don't affect any of `self`'s state other than
    /// that data written to the spawn will later be visible by reads
    /// through `self`.
    fn decoupled_borrow_mut<'b>(&'b mut self) -> Self::DecoupledBorrowMutIterType<'b>;
}

// Rust would not allow different ("unconstrained") lifetimes for I and the
// reference here.  That's the reason why CovariantIoSlicesIterRef exists.
impl<'a, I: ?Sized + MutPeekableIoSlicesMutIter<'a>> MutPeekableIoSlicesMutIter<'a> for &'a mut I {
    type DecoupledBorrowMutIterType<'c>
        = I::DecoupledBorrowMutIterType<'c>
    where
        Self: 'c;

    fn decoupled_borrow_mut<'c>(&'c mut self) -> Self::DecoupledBorrowMutIterType<'c> {
        I::decoupled_borrow_mut(*self)
    }
}

/// Adaptor implementing [`IoSlicesIter`] for a generic wrapped
/// [`Iterator<Item=Result<&u8, E>`](Iterator).
///
/// The rules for transforming the `Option<Result<&u8, E>>` returned from the
/// [`Iterator::next()`](Iterator::next) into a `Result<Option<&u8>, E>` as is
/// required for [`IoSlicesIter::next_slice()`](IoSlicesIter::next_slice) follow
/// [`Option::transpose()`](Option::transpose).
#[derive(Clone)]
pub struct GenericIoSlicesIter<
    'a,
    I: Iterator<Item = Result<&'a [u8], BackendIteratorError>>,
    BackendIteratorError: fmt::Debug,
> {
    iter: I,
    head: Option<&'a [u8]>,
    tail: Option<&'a [u8]>,
    iter_done: bool,
}

impl<'a, I: Iterator<Item = Result<&'a [u8], BackendIteratorError>>, BackendIteratorError: fmt::Debug>
    GenericIoSlicesIter<'a, I, BackendIteratorError>
{
    /// Wrap a generic [`Iterator`] in a `GenericIoSlicesIter`.
    ///
    /// # Arguments:
    ///
    /// * `iter` - The [`Iterator`] to wrap.
    /// * `head` - An optional byte slice to emit first before starting to
    ///   dequeue further slices from `iter`.
    pub fn new(iter: I, head: Option<&'a [u8]>) -> Self {
        Self {
            iter,
            head: head.filter(|head| !head.is_empty()),
            tail: None,
            iter_done: false,
        }
    }

    fn refill_head(&mut self) -> Result<Option<&[u8]>, BackendIteratorError> {
        while !self.iter_done {
            match self.iter.next() {
                Some(Ok(head)) => {
                    if head.is_empty() {
                        // Skip over empty buffer.
                        continue;
                    }
                    self.head = Some(head);
                    return Ok(self.head);
                }
                Some(Err(e)) => {
                    self.iter_done = true;
                    return Err(e);
                }
                None => {
                    self.iter_done = true;
                }
            }
        }

        self.head = self.tail.take();
        Ok(self.head)
    }

    fn maybe_refill_head(&mut self) -> Result<Option<&[u8]>, BackendIteratorError> {
        if self.head.is_none() {
            return self.refill_head();
        }
        Ok(self.head)
    }
}
impl<'a, I: Iterator<Item = Result<&'a [u8], BackendIteratorError>>, BackendIteratorError: fmt::Debug>
    IoSlicesIterCommon for GenericIoSlicesIter<'a, I, BackendIteratorError>
{
    type BackendIteratorError = BackendIteratorError;

    fn next_slice_len(&mut self) -> Result<usize, BackendIteratorError> {
        Ok(self.maybe_refill_head()?.map(|head| head.len()).unwrap_or(0))
    }
}

impl<'a, 'b: 'a, I: Iterator<Item = Result<&'b [u8], BackendIteratorError>>, BackendIteratorError: fmt::Debug>
    IoSlicesIter<'a> for GenericIoSlicesIter<'b, I, BackendIteratorError>
{
    fn next_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        self.maybe_refill_head()?;

        let max_len = if let Some(max_len) = max_len {
            max_len
        } else {
            return Ok(self.head.take());
        };

        let consumed = match self.head.take() {
            Some(head) => {
                let max_len = max_len.min(head.len());
                let (consumed, remaining) = head.split_at(max_len);
                self.head = (!remaining.is_empty()).then_some(remaining);
                Some(consumed)
            }
            None => None,
        };
        Ok(consumed)
    }
}

impl<
    'a,
    'b: 'a,
    I: DoubleEndedIterator<Item = Result<&'b [u8], BackendIteratorError>>,
    BackendIteratorError: fmt::Debug,
> DoubleEndedIoSlicesIter<'a> for GenericIoSlicesIter<'b, I, BackendIteratorError>
{
    fn next_back_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        if self.tail.is_none() {
            while !self.iter_done {
                match self.iter.next_back() {
                    Some(Ok(tail)) => {
                        if tail.is_empty() {
                            // Skip over empty buffer.
                            continue;
                        }
                        self.tail = Some(tail);
                        break;
                    }
                    Some(Err(e)) => {
                        self.iter_done = true;
                        return Err(e);
                    }
                    None => {
                        self.iter_done = true;
                    }
                }
            }

            if self.tail.is_none() {
                self.tail = self.head.take();
            }
        }

        let max_len = if let Some(max_len) = max_len {
            max_len
        } else {
            return Ok(self.tail.take());
        };

        let consumed = match self.tail.take() {
            Some(tail) => {
                let max_len = max_len.min(tail.len());
                let (remaining, consumed) = tail.split_at(tail.len() - max_len);
                self.tail = (!remaining.is_empty()).then_some(remaining);
                Some(consumed)
            }
            None => None,
        };

        Ok(consumed)
    }
}

impl<'a, 'b: 'a, I: Iterator<Item = Result<&'b [u8], BackendIteratorError>> + Clone, BackendIteratorError: fmt::Debug>
    WalkableIoSlicesIter<'a> for GenericIoSlicesIter<'b, I, BackendIteratorError>
{
    fn for_each(&self, cb: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), Self::BackendIteratorError> {
        let mut iter = self.decoupled_borrow();
        while let Some(slice) = iter.next_slice(None)? {
            if !cb(slice) {
                break;
            }
        }
        Ok(())
    }
}

impl<'a, 'b: 'a, I: Iterator<Item = Result<&'b [u8], BackendIteratorError>> + Clone, BackendIteratorError: fmt::Debug>
    PeekableIoSlicesIter<'a> for GenericIoSlicesIter<'b, I, BackendIteratorError>
{
    type DecoupledBorrowIterType<'c>
        = GenericIoSlicesIter<
        'c,
        iter::Map<I, fn(Result<&'b [u8], BackendIteratorError>) -> Result<&'c [u8], BackendIteratorError>>,
        BackendIteratorError,
    >
    where
        Self: 'c;

    fn decoupled_borrow<'c>(&'c self) -> Self::DecoupledBorrowIterType<'c> {
        GenericIoSlicesIter::new(
            self.iter.clone().map(|s: Result<&'b [u8], BackendIteratorError>| s),
            self.head,
        )
    }
}

/// Adaptor implementing [`IoSlicesMutIter`] for a generic wrapped
/// [`Iterator<Item=Result<&mut u8, E>`](Iterator).
///
/// The rules for transforming the `Option<Result<&mut u8, E>>` returned from
/// the [`Iterator::next()`](Iterator::next) into a `Result<Option<&mut u8>, E>`
/// as is required for
/// [`IoSlicesMutIter::next_slice_mut()`](IoSlicesMutIter::next_slice_mut)
/// follow [`Option::transpose()`](Option::transpose).
pub struct GenericIoSlicesMutIter<
    'a,
    I: Iterator<Item = Result<&'a mut [u8], BackendIteratorError>>,
    BackendIteratorError: fmt::Debug,
> {
    iter: I,
    head: Option<&'a mut [u8]>,
    iter_done: bool,
}

impl<'a, I: Iterator<Item = Result<&'a mut [u8], BackendIteratorError>>, BackendIteratorError: fmt::Debug>
    GenericIoSlicesMutIter<'a, I, BackendIteratorError>
{
    /// Wrap a generic [`Iterator`] in a `GenericIoSlicesMutIter`.
    ///
    /// # Arguments:
    ///
    /// * `iter` - The [`Iterator`] to wrap.
    /// * `head` - An optional byte slice to emit first before starting to
    ///   dequeue further slices from `iter`.
    pub fn new(iter: I, head: Option<&'a mut [u8]>) -> Self {
        Self {
            iter,
            head: head.filter(|head| !head.is_empty()),
            iter_done: false,
        }
    }

    fn refill_head(&mut self) -> Result<Option<&mut [u8]>, BackendIteratorError> {
        while !self.iter_done {
            match self.iter.next() {
                Some(Ok(head)) => {
                    if head.is_empty() {
                        // Skip over empty buffer.
                        continue;
                    }
                    self.head = Some(head);
                    return Ok(self.head.as_deref_mut());
                }
                Some(Err(e)) => {
                    self.iter_done = true;
                    return Err(e);
                }
                None => {
                    self.iter_done = true;
                }
            }
        }

        Ok(None)
    }

    fn maybe_refill_head(&mut self) -> Result<Option<&mut [u8]>, BackendIteratorError> {
        if self.head.is_none() {
            return self.refill_head();
        }
        Ok(self.head.as_deref_mut())
    }
}

impl<'a, I: Iterator<Item = Result<&'a mut [u8], BackendIteratorError>>, BackendIteratorError: fmt::Debug>
    IoSlicesIterCommon for GenericIoSlicesMutIter<'a, I, BackendIteratorError>
{
    type BackendIteratorError = BackendIteratorError;

    fn next_slice_len(&mut self) -> Result<usize, BackendIteratorError> {
        Ok(self.maybe_refill_head()?.map(|head| head.len()).unwrap_or(0))
    }
}

impl<'a, 'b: 'a, I: Iterator<Item = Result<&'b mut [u8], BackendIteratorError>>, BackendIteratorError: fmt::Debug>
    IoSlicesIter<'a> for GenericIoSlicesMutIter<'b, I, BackendIteratorError>
{
    fn next_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        self.next_slice_mut(max_len)
            .map(|mut slice| slice.take().map(|slice| &*slice))
    }
}

impl<'a, 'b: 'a, I: Iterator<Item = Result<&'b mut [u8], BackendIteratorError>>, BackendIteratorError: fmt::Debug>
    IoSlicesMutIter<'a> for GenericIoSlicesMutIter<'b, I, BackendIteratorError>
{
    fn next_slice_mut(&mut self, max_len: Option<usize>) -> Result<Option<&'a mut [u8]>, Self::BackendIteratorError> {
        self.maybe_refill_head()?;

        let max_len = if let Some(max_len) = max_len {
            max_len
        } else {
            return Ok(self.head.take());
        };

        let consumed = match self.head.take() {
            Some(head) => {
                let max_len = max_len.min(head.len());
                let (consumed, remaining) = head.split_at_mut(max_len);
                self.head = (!remaining.is_empty()).then_some(remaining);
                Some(consumed)
            }
            None => None,
        };
        Ok(consumed)
    }
}

/// Wrapper implementing [`IoSlicesIter`] for a slice of byte slices.
///
/// The byte slices from the wrapped slice will get dequeued in order.
pub struct BuffersSliceIoSlicesIter<'a, B: convert::AsRef<[u8]>> {
    buffers_slice: &'a [B],
    head: Option<&'a [u8]>,
    tail: Option<&'a [u8]>,
}

impl<'a, B: convert::AsRef<[u8]>> BuffersSliceIoSlicesIter<'a, B> {
    /// Wrap a slice of byte slices in a `BuffersSliceIoSlicesIter`.
    ///
    /// # Arguments:
    ///
    /// * `buffers_slice` - The slice of byte slices to wrap.
    pub fn new(buffers_slice: &'a [B]) -> Self {
        Self {
            buffers_slice,
            head: None,
            tail: None,
        }
    }

    fn refill_head(&mut self) -> Option<&[u8]> {
        while !self.buffers_slice.is_empty() {
            let head;
            (head, self.buffers_slice) = self.buffers_slice.split_at(1);
            let head = *self.head.insert(head[0].as_ref());
            if head.is_empty() {
                // Skip over empty buffer.
                continue;
            }
            return Some(head);
        }
        self.head = self.tail.take();
        self.head
    }

    fn maybe_refill_head(&mut self) -> Option<&[u8]> {
        match self.head.as_ref() {
            Some(head) => Some(*head),
            None => self.refill_head(),
        }
    }
}

impl<'a, B: convert::AsRef<[u8]>> IoSlicesIterCommon for BuffersSliceIoSlicesIter<'a, B> {
    type BackendIteratorError = convert::Infallible;

    fn next_slice_len(&mut self) -> Result<usize, Self::BackendIteratorError> {
        Ok(self.maybe_refill_head().map(|head| head.len()).unwrap_or(0))
    }
}

impl<'a, 'b: 'a, B: convert::AsRef<[u8]>> IoSlicesIter<'a> for BuffersSliceIoSlicesIter<'b, B> {
    fn next_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        self.maybe_refill_head();

        let max_len = if let Some(max_len) = max_len {
            max_len
        } else {
            return Ok(self.head.take());
        };

        let consumed = match self.head.take() {
            Some(head) => {
                let max_len = max_len.min(head.len());
                let (consumed, remaining) = head.split_at(max_len);
                self.head = (!remaining.is_empty()).then_some(remaining);
                Some(consumed)
            }
            None => None,
        };
        Ok(consumed)
    }
}

impl<'a, 'b: 'a, B: convert::AsRef<[u8]>> DoubleEndedIoSlicesIter<'a> for BuffersSliceIoSlicesIter<'b, B> {
    fn next_back_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        if self.tail.is_none() {
            while !self.buffers_slice.is_empty() {
                let tail;
                (self.buffers_slice, tail) = self.buffers_slice.split_at(self.buffers_slice.len() - 1);
                let tail = tail[0].as_ref();
                if tail.is_empty() {
                    // Skip over empty buffer.
                    continue;
                }
                self.tail = Some(tail);
                break;
            }

            if self.tail.is_none() {
                self.tail = self.head.take();
            }
        }

        let max_len = if let Some(max_len) = max_len {
            max_len
        } else {
            return Ok(self.tail.take());
        };

        let consumed = match self.tail.take() {
            Some(tail) => {
                let max_len = max_len.min(tail.len());
                let (remaining, consumed) = tail.split_at(tail.len() - max_len);
                self.tail = (!remaining.is_empty()).then_some(remaining);
                Some(consumed)
            }
            None => None,
        };

        Ok(consumed)
    }
}

impl<'a, 'b: 'a, B: convert::AsRef<[u8]>> WalkableIoSlicesIter<'a> for BuffersSliceIoSlicesIter<'b, B> {
    fn for_each(&self, cb: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), Self::BackendIteratorError> {
        for slice in self
            .head
            .iter()
            .copied()
            .chain(self.buffers_slice.iter().map(|slice| slice.as_ref()))
            .chain(self.tail.iter().copied())
            .filter(|slice| !slice.is_empty())
        {
            if !cb(slice) {
                break;
            }
        }
        Ok(())
    }
}

impl<'a, 'b: 'a, B: convert::AsRef<[u8]>> PeekableIoSlicesIter<'a> for BuffersSliceIoSlicesIter<'b, B> {
    type DecoupledBorrowIterType<'c>
        = BuffersSliceIoSlicesIter<'c, B>
    where
        Self: 'c;

    fn decoupled_borrow<'c>(&'c self) -> Self::DecoupledBorrowIterType<'c> {
        BuffersSliceIoSlicesIter {
            buffers_slice: self.buffers_slice,
            head: self.head,
            tail: self.tail,
        }
    }
}

impl<'a, B: convert::AsRef<[u8]>> Iterator for BuffersSliceIoSlicesIter<'a, B> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_slice(None) {
            Ok(slice) => slice,
            Err(e) => match e {},
        }
    }
}

#[test]
fn test_buffers_slice_io_slices_iter() {
    let a = [1u8, 2u8];
    let b: [u8; 0] = [0u8; 0];
    let c = [3u8, 4u8];
    let d: [u8; 0] = [0u8; 0];
    let slices = [a.as_slice(), b.as_slice(), c.as_slice(), d.as_slice()];
    let mut slices = BuffersSliceIoSlicesIter::new(&slices);
    assert_eq!(slices.decoupled_borrow().count(), 2);
    assert_eq!(slices.total_len().unwrap(), 4);
    assert_eq!(slices.decoupled_borrow().next_slice(Some(1)).unwrap().unwrap()[0], 1);
    assert_eq!(slices.next_slice(Some(1)).unwrap().unwrap()[0], 1);
    assert_eq!(slices.decoupled_borrow().count(), 2);
    assert_eq!(slices.total_len().unwrap(), 3);
    assert_eq!(slices.decoupled_borrow().next_slice(Some(1)).unwrap().unwrap()[0], 2);
    assert_eq!(slices.next_slice(Some(1)).unwrap().unwrap()[0], 2);
    assert_eq!(slices.decoupled_borrow().count(), 1);
    assert_eq!(slices.total_len().unwrap(), 2);
    assert_eq!(slices.decoupled_borrow().next_slice(Some(1)).unwrap().unwrap()[0], 3);
    assert_eq!(slices.next_slice(Some(1)).unwrap().unwrap()[0], 3);
    assert_eq!(slices.decoupled_borrow().count(), 1);
    assert_eq!(slices.total_len().unwrap(), 1);
    assert_eq!(slices.decoupled_borrow().next_slice(Some(1)).unwrap().unwrap()[0], 4);
    assert_eq!(slices.next_slice(Some(1)).unwrap().unwrap()[0], 4);
    assert_eq!(slices.decoupled_borrow().count(), 0);
    assert_eq!(slices.total_len().unwrap(), 0);
    assert!(slices.is_empty().unwrap());
    assert_eq!(a, [1, 2]);
    assert_eq!(c, [3, 4]);

    let a = [4u8, 3u8];
    let b: [u8; 0] = [0u8; 0];
    let c = [2u8, 1u8];
    let d: [u8; 0] = [0u8; 0];
    let slices = [a.as_slice(), b.as_slice(), c.as_slice(), d.as_slice()];
    let mut slices = BuffersSliceIoSlicesIter::new(&slices);
    assert_eq!(slices.decoupled_borrow().count(), 2);
    assert_eq!(slices.total_len().unwrap(), 4);
    assert_eq!(
        slices.decoupled_borrow().next_back_slice(Some(1)).unwrap().unwrap()[0],
        1
    );
    assert_eq!(slices.next_back_slice(Some(1)).unwrap().unwrap()[0], 1);
    assert_eq!(slices.decoupled_borrow().count(), 2);
    assert_eq!(slices.total_len().unwrap(), 3);
    assert_eq!(
        slices.decoupled_borrow().next_back_slice(Some(1)).unwrap().unwrap()[0],
        2
    );
    assert_eq!(slices.next_back_slice(Some(1)).unwrap().unwrap()[0], 2);
    assert_eq!(slices.decoupled_borrow().count(), 1);
    assert_eq!(slices.total_len().unwrap(), 2);
    assert_eq!(
        slices.decoupled_borrow().next_back_slice(Some(1)).unwrap().unwrap()[0],
        3
    );
    assert_eq!(slices.next_back_slice(Some(1)).unwrap().unwrap()[0], 3);
    assert_eq!(slices.decoupled_borrow().count(), 1);
    assert_eq!(slices.total_len().unwrap(), 1);
    assert_eq!(
        slices.decoupled_borrow().next_back_slice(Some(1)).unwrap().unwrap()[0],
        4
    );
    assert_eq!(slices.next_back_slice(Some(1)).unwrap().unwrap()[0], 4);
    assert_eq!(slices.decoupled_borrow().count(), 0);
    assert_eq!(slices.total_len().unwrap(), 0);
    assert!(slices.is_empty().unwrap());
    assert_eq!(a, [4, 3]);
    assert_eq!(c, [2, 1]);

    let a = [1u8, 2u8];
    let b: [u8; 0] = [0u8; 0];
    let c = [3u8, 4u8];
    let d: [u8; 0] = [0u8; 0];
    let slices = [a.as_slice(), b.as_slice(), c.as_slice(), d.as_slice()];
    let mut slices = BuffersSliceIoSlicesIter::new(&slices);
    assert_eq!(slices.decoupled_borrow().count(), 2);
    let s = slices.decoupled_borrow().next_slice(None).unwrap().unwrap();
    assert_eq!(s, [1, 2]);
    assert_eq!(slices.decoupled_borrow().count(), 2);
    let s = slices.next_slice(None).unwrap().unwrap();
    assert_eq!(s, [1, 2]);
    assert_eq!(slices.decoupled_borrow().count(), 1);
    let s = slices.decoupled_borrow().next_slice(None).unwrap().unwrap();
    assert_eq!(s, [3, 4]);
    assert_eq!(slices.decoupled_borrow().count(), 1);
    let s = slices.next_slice(None).unwrap().unwrap();
    assert_eq!(s, [3, 4]);
    assert_eq!(slices.decoupled_borrow().count(), 0);
    assert!(slices.next_slice(None).unwrap().is_none());

    let a = [4u8, 3u8];
    let b: [u8; 0] = [0u8; 0];
    let c = [2u8, 1u8];
    let d: [u8; 0] = [0u8; 0];
    let slices = [a.as_slice(), b.as_slice(), c.as_slice(), d.as_slice()];
    let mut slices = BuffersSliceIoSlicesIter::new(&slices);
    assert_eq!(slices.decoupled_borrow().count(), 2);
    let s = slices.decoupled_borrow().next_back_slice(None).unwrap().unwrap();
    assert_eq!(s, [2, 1]);
    assert_eq!(slices.decoupled_borrow().count(), 2);
    let s = slices.next_back_slice(None).unwrap().unwrap();
    assert_eq!(s, [2, 1]);
    assert_eq!(slices.decoupled_borrow().count(), 1);
    let s = slices.decoupled_borrow().next_back_slice(None).unwrap().unwrap();
    assert_eq!(s, [4, 3]);
    assert_eq!(slices.decoupled_borrow().count(), 1);
    let s = slices.next_back_slice(None).unwrap().unwrap();
    assert_eq!(s, [4, 3]);
    assert_eq!(slices.decoupled_borrow().count(), 0);
    assert!(slices.next_back_slice(None).unwrap().is_none());
}

/// Wrapper implementing [`IoSlicesMutIter`] for a slice of byte slices.
///
/// The byte slices from the wrapped slice will get dequeued in order.
pub struct BuffersSliceIoSlicesMutIter<'a, B: convert::AsMut<[u8]>> {
    // slice::take_first_mut() is unstable,  buffers_slice
    // needs to live an Option until that has stabilized.
    buffers_slice: Option<&'a mut [B]>,
    head: Option<&'a mut [u8]>,
    tail: Option<&'a mut [u8]>,
}

impl<'a, B: convert::AsMut<[u8]>> BuffersSliceIoSlicesMutIter<'a, B> {
    /// Wrap a slice of byte slices in a `BuffersSliceIoSlicesMutIter`.
    ///
    /// # Arguments:
    ///
    /// * `buffers_slice` - The slice of byte slices to wrap.
    pub fn new(buffers_slice: &'a mut [B]) -> Self {
        Self {
            buffers_slice: Some(buffers_slice),
            head: None,
            tail: None,
        }
    }

    fn refill_head(&mut self) -> Option<&mut [u8]> {
        if let Some(mut buffers_slice) = self.buffers_slice.take() {
            while !buffers_slice.is_empty() {
                let head;
                (head, buffers_slice) = buffers_slice.split_at_mut(1);
                let head: &'a mut [u8] = head[0].as_mut();
                if head.is_empty() {
                    // Skip over empty buffer.
                    continue;
                }
                self.buffers_slice = Some(buffers_slice);
                self.head = Some(head);
                return self.head.as_deref_mut();
            }
            self.buffers_slice = Some(buffers_slice);
        }
        self.head = self.tail.take();
        self.head.as_deref_mut()
    }

    fn maybe_refill_head(&mut self) -> Option<&mut [u8]> {
        if self.head.is_none() {
            self.refill_head();
        }
        self.head.as_deref_mut()
    }
}

impl<'a, B: convert::AsMut<[u8]>> IoSlicesIterCommon for BuffersSliceIoSlicesMutIter<'a, B> {
    type BackendIteratorError = convert::Infallible;

    fn next_slice_len(&mut self) -> Result<usize, Self::BackendIteratorError> {
        Ok(self.maybe_refill_head().map(|head| head.len()).unwrap_or(0))
    }
}

impl<'a, 'b: 'a, B: convert::AsMut<[u8]>> IoSlicesIter<'a> for BuffersSliceIoSlicesMutIter<'b, B> {
    fn next_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        self.maybe_refill_head();

        let max_len = if let Some(max_len) = max_len {
            max_len
        } else {
            return Ok(self.head.take().map(|s| &*s));
        };

        let consumed = match self.head.take() {
            Some(head) => {
                let max_len = max_len.min(head.len());
                let (consumed, remaining) = head.split_at_mut(max_len);
                self.head = (!remaining.is_empty()).then_some(remaining);
                Some(&*consumed)
            }
            None => None,
        };
        Ok(consumed)
    }
}

impl<'a, 'b: 'a, B: convert::AsMut<[u8]>> IoSlicesMutIter<'a> for BuffersSliceIoSlicesMutIter<'b, B> {
    fn next_slice_mut(&mut self, max_len: Option<usize>) -> Result<Option<&'a mut [u8]>, Self::BackendIteratorError> {
        self.maybe_refill_head();

        let max_len = if let Some(max_len) = max_len {
            max_len
        } else {
            return Ok(self.head.take());
        };

        let consumed = match self.head.take() {
            Some(head) => {
                let max_len = max_len.min(head.len());
                let (consumed, remaining) = head.split_at_mut(max_len);
                self.head = (!remaining.is_empty()).then_some(remaining);
                Some(consumed)
            }
            None => None,
        };
        Ok(consumed)
    }
}

impl<'a, 'b: 'a, B: convert::AsMut<[u8]>> DoubleEndedIoSlicesIter<'a> for BuffersSliceIoSlicesMutIter<'b, B> {
    fn next_back_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        if self.tail.is_none() {
            if let Some(mut buffers_slice) = self.buffers_slice.take() {
                while !buffers_slice.is_empty() {
                    let buffers_slice_len = buffers_slice.len();
                    let tail;
                    (buffers_slice, tail) = buffers_slice.split_at_mut(buffers_slice_len - 1);
                    let tail = tail[0].as_mut();
                    if tail.is_empty() {
                        // Skip over empty buffer.
                        continue;
                    }
                    self.tail = Some(tail);
                    break;
                }
                self.buffers_slice = Some(buffers_slice);
            }

            if self.tail.is_none() {
                self.tail = self.head.take();
            }
        }

        let max_len = if let Some(max_len) = max_len {
            max_len
        } else {
            return Ok(self.tail.take().map(|s| &*s));
        };

        let consumed = match self.tail.take() {
            Some(tail) => {
                let max_len = max_len.min(tail.len());
                let (remaining, consumed) = tail.split_at_mut(tail.len() - max_len);
                self.tail = (!remaining.is_empty()).then_some(remaining);
                Some(&*consumed)
            }
            None => None,
        };

        Ok(consumed)
    }
}

impl<'a, 'b: 'a, B: convert::AsMut<[u8]>> DoubleEndedIoSlicesMutIter<'a> for BuffersSliceIoSlicesMutIter<'b, B> {
    fn next_back_slice_mut(
        &mut self,
        max_len: Option<usize>,
    ) -> Result<Option<&'a mut [u8]>, Self::BackendIteratorError> {
        if self.tail.is_none() {
            if let Some(mut buffers_slice) = self.buffers_slice.take() {
                while !buffers_slice.is_empty() {
                    let buffers_slice_len = buffers_slice.len();
                    let tail;
                    (buffers_slice, tail) = buffers_slice.split_at_mut(buffers_slice_len - 1);
                    let tail = tail[0].as_mut();
                    if tail.is_empty() {
                        // Skip over empty buffer.
                        continue;
                    }
                    self.tail = Some(tail);
                    break;
                }
                self.buffers_slice = Some(buffers_slice);
            }

            if self.tail.is_none() {
                self.tail = self.head.take();
            }
        }

        let max_len = if let Some(max_len) = max_len {
            max_len
        } else {
            return Ok(self.tail.take());
        };

        let consumed = match self.tail.take() {
            Some(tail) => {
                let max_len = max_len.min(tail.len());
                let (remaining, consumed) = tail.split_at_mut(tail.len() - max_len);
                self.tail = (!remaining.is_empty()).then_some(remaining);
                Some(consumed)
            }
            None => None,
        };

        Ok(consumed)
    }
}

impl<'a, 'b: 'a, B: convert::AsMut<[u8]> + convert::AsRef<[u8]>> WalkableIoSlicesIter<'a>
    for BuffersSliceIoSlicesMutIter<'b, B>
{
    fn for_each(&self, cb: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), Self::BackendIteratorError> {
        for slice in self
            .head
            .iter()
            .map(|slice| &**slice)
            .chain(
                self.buffers_slice
                    .iter()
                    .flat_map(|buffers_slice| buffers_slice.iter())
                    .map(|slice| slice.as_ref()),
            )
            .chain(self.tail.iter().map(|slice| &**slice))
            .filter(|slice| !slice.is_empty())
        {
            if !cb(slice) {
                break;
            }
        }
        Ok(())
    }
}

impl<'a, 'b: 'a, B: convert::AsMut<[u8]> + convert::AsRef<[u8]>> PeekableIoSlicesIter<'a>
    for BuffersSliceIoSlicesMutIter<'b, B>
{
    type DecoupledBorrowIterType<'c>
        = BuffersSliceIoSlicesIter<'c, B>
    where
        Self: 'c;

    fn decoupled_borrow<'c>(&'c self) -> Self::DecoupledBorrowIterType<'c> {
        BuffersSliceIoSlicesIter {
            buffers_slice: self.buffers_slice.as_deref().unwrap(),
            head: self.head.as_deref(),
            tail: self.tail.as_deref(),
        }
    }
}

impl<'a, 'b: 'a, B: convert::AsMut<[u8]> + convert::AsRef<[u8]>> MutPeekableIoSlicesMutIter<'a>
    for BuffersSliceIoSlicesMutIter<'b, B>
{
    type DecoupledBorrowMutIterType<'c>
        = BuffersSliceIoSlicesMutIter<'c, B>
    where
        Self: 'c;

    fn decoupled_borrow_mut<'c>(&'c mut self) -> Self::DecoupledBorrowMutIterType<'c> {
        BuffersSliceIoSlicesMutIter {
            buffers_slice: self.buffers_slice.as_deref_mut(),
            head: self.head.as_deref_mut(),
            tail: self.tail.as_deref_mut(),
        }
    }
}

impl<'a, B: convert::AsMut<[u8]>> Iterator for BuffersSliceIoSlicesMutIter<'a, B> {
    type Item = &'a mut [u8];

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_slice_mut(None) {
            Ok(slice) => slice,
            Err(e) => match e {},
        }
    }
}

#[test]
fn test_buffers_slice_io_slices_mut_iter() {
    let mut a = [0u8, 0u8];
    let mut b: [u8; 0] = [0u8; 0];
    let mut c = [0u8, 0u8];
    let mut d: [u8; 0] = [0u8; 0];
    let mut slices = [a.as_mut_slice(), b.as_mut_slice(), c.as_mut_slice(), d.as_mut_slice()];
    let mut slices = BuffersSliceIoSlicesMutIter::new(&mut slices);
    assert_eq!(slices.decoupled_borrow().count(), 2);
    assert_eq!(slices.total_len().unwrap(), 4);
    assert_eq!(slices.decoupled_borrow().next_slice(Some(1)).unwrap().unwrap()[0], 0);
    slices.decoupled_borrow_mut().next_slice_mut(Some(1)).unwrap().unwrap()[0] = 0xcc;
    let s = slices.next_slice_mut(Some(1)).unwrap().unwrap();
    assert_eq!(s[0], 0xcc);
    s[0] = 1;
    assert_eq!(slices.decoupled_borrow().count(), 2);
    assert_eq!(slices.total_len().unwrap(), 3);
    assert_eq!(slices.decoupled_borrow().next_slice(Some(1)).unwrap().unwrap()[0], 0);
    slices.decoupled_borrow_mut().next_slice_mut(Some(1)).unwrap().unwrap()[0] = 0xcc;
    let s = slices.next_slice_mut(Some(1)).unwrap().unwrap();
    assert_eq!(s[0], 0xcc);
    s[0] = 2;
    assert_eq!(slices.decoupled_borrow().count(), 1);
    assert_eq!(slices.total_len().unwrap(), 2);
    assert_eq!(slices.decoupled_borrow().next_slice(Some(1)).unwrap().unwrap()[0], 0);
    slices.decoupled_borrow_mut().next_slice_mut(Some(1)).unwrap().unwrap()[0] = 0xcc;
    let s = slices.next_slice_mut(Some(1)).unwrap().unwrap();
    assert_eq!(s[0], 0xcc);
    s[0] = 3;
    assert_eq!(slices.decoupled_borrow().count(), 1);
    assert_eq!(slices.total_len().unwrap(), 1);
    assert_eq!(slices.decoupled_borrow().next_slice(Some(1)).unwrap().unwrap()[0], 0);
    slices.decoupled_borrow_mut().next_slice_mut(Some(1)).unwrap().unwrap()[0] = 0xcc;
    let s = slices.next_slice_mut(Some(1)).unwrap().unwrap();
    assert_eq!(s[0], 0xcc);
    s[0] = 4;
    assert_eq!(slices.decoupled_borrow().count(), 0);
    assert_eq!(slices.total_len().unwrap(), 0);
    assert!(slices.is_empty().unwrap());
    assert_eq!(a, [1, 2]);
    assert_eq!(c, [3, 4]);

    let mut a = [0u8, 0u8];
    let mut b: [u8; 0] = [0u8; 0];
    let mut c = [0u8, 0u8];
    let mut d: [u8; 0] = [0u8; 0];
    let mut slices = [a.as_mut_slice(), b.as_mut_slice(), c.as_mut_slice(), d.as_mut_slice()];
    let mut slices = BuffersSliceIoSlicesMutIter::new(&mut slices);
    assert_eq!(slices.decoupled_borrow().count(), 2);
    assert_eq!(slices.total_len().unwrap(), 4);
    assert_eq!(
        slices.decoupled_borrow().next_back_slice(Some(1)).unwrap().unwrap()[0],
        0
    );
    slices
        .decoupled_borrow_mut()
        .next_back_slice_mut(Some(1))
        .unwrap()
        .unwrap()[0] = 0xcc;
    let s = slices.next_back_slice_mut(Some(1)).unwrap().unwrap();
    assert_eq!(s[0], 0xcc);
    s[0] = 1;
    assert_eq!(slices.decoupled_borrow().count(), 2);
    assert_eq!(slices.total_len().unwrap(), 3);
    assert_eq!(
        slices.decoupled_borrow().next_back_slice(Some(1)).unwrap().unwrap()[0],
        0
    );
    slices
        .decoupled_borrow_mut()
        .next_back_slice_mut(Some(1))
        .unwrap()
        .unwrap()[0] = 0xcc;
    let s = slices.next_back_slice_mut(Some(1)).unwrap().unwrap();
    assert_eq!(s[0], 0xcc);
    s[0] = 2;
    assert_eq!(slices.decoupled_borrow().count(), 1);
    assert_eq!(slices.total_len().unwrap(), 2);
    assert_eq!(
        slices.decoupled_borrow().next_back_slice(Some(1)).unwrap().unwrap()[0],
        0
    );
    slices
        .decoupled_borrow_mut()
        .next_back_slice_mut(Some(1))
        .unwrap()
        .unwrap()[0] = 0xcc;
    let s = slices.next_back_slice_mut(Some(1)).unwrap().unwrap();
    assert_eq!(s[0], 0xcc);
    s[0] = 3;
    assert_eq!(slices.decoupled_borrow().count(), 1);
    assert_eq!(slices.total_len().unwrap(), 1);
    assert_eq!(
        slices.decoupled_borrow().next_back_slice(Some(1)).unwrap().unwrap()[0],
        0
    );
    slices
        .decoupled_borrow_mut()
        .next_back_slice_mut(Some(1))
        .unwrap()
        .unwrap()[0] = 0xcc;
    let s = slices.next_back_slice_mut(Some(1)).unwrap().unwrap();
    assert_eq!(s[0], 0xcc);
    s[0] = 4;
    assert_eq!(slices.decoupled_borrow().count(), 0);
    assert_eq!(slices.total_len().unwrap(), 0);
    assert!(slices.is_empty().unwrap());
    assert_eq!(a, [4, 3]);
    assert_eq!(c, [2, 1]);

    let mut a = [0u8, 0u8];
    let mut b: [u8; 0] = [0u8; 0];
    let mut c = [0u8, 0u8];
    let mut d: [u8; 0] = [0u8; 0];
    let mut slices = [a.as_mut_slice(), b.as_mut_slice(), c.as_mut_slice(), d.as_mut_slice()];
    let mut slices = BuffersSliceIoSlicesMutIter::new(&mut slices);
    assert_eq!(slices.decoupled_borrow().count(), 2);
    let s = slices.decoupled_borrow_mut().next_slice_mut(None).unwrap().unwrap();
    assert_eq!(s.len(), 2);
    s[0] = 0xcc;
    s[1] = 0x55;
    let s = slices.next_slice_mut(None).unwrap().unwrap();
    assert_eq!(s.len(), 2);
    assert_eq!(s[0], 0xcc);
    assert_eq!(s[1], 0x55);
    s[0] = 1;
    s[1] = 2;
    assert_eq!(slices.decoupled_borrow().count(), 1);
    let s = slices.decoupled_borrow_mut().next_slice_mut(None).unwrap().unwrap();
    assert_eq!(s.len(), 2);
    s[0] = 0xcc;
    s[1] = 0x55;
    let s = slices.next_slice_mut(None).unwrap().unwrap();
    assert_eq!(s.len(), 2);
    assert_eq!(s[0], 0xcc);
    assert_eq!(s[1], 0x55);
    s[0] = 3;
    s[1] = 4;
    assert_eq!(slices.decoupled_borrow().count(), 0);
    assert!(slices.next_slice_mut(None).unwrap().is_none());
    assert_eq!(a, [1, 2]);
    assert_eq!(c, [3, 4]);

    let mut a = [0u8, 0u8];
    let mut b: [u8; 0] = [0u8; 0];
    let mut c = [0u8, 0u8];
    let mut d: [u8; 0] = [0u8; 0];
    let mut slices = [a.as_mut_slice(), b.as_mut_slice(), c.as_mut_slice(), d.as_mut_slice()];
    let mut slices = BuffersSliceIoSlicesMutIter::new(&mut slices);
    assert_eq!(slices.decoupled_borrow().count(), 2);
    let s = slices
        .decoupled_borrow_mut()
        .next_back_slice_mut(None)
        .unwrap()
        .unwrap();
    assert_eq!(s.len(), 2);
    s[0] = 0xcc;
    s[1] = 0x55;
    let s = slices.next_back_slice_mut(None).unwrap().unwrap();
    assert_eq!(s.len(), 2);
    assert_eq!(s[0], 0xcc);
    assert_eq!(s[1], 0x55);
    s[0] = 2;
    s[1] = 1;
    assert_eq!(slices.decoupled_borrow().count(), 1);
    let s = slices
        .decoupled_borrow_mut()
        .next_back_slice_mut(None)
        .unwrap()
        .unwrap();
    assert_eq!(s.len(), 2);
    s[0] = 0xcc;
    s[1] = 0x55;
    let s = slices.next_back_slice_mut(None).unwrap().unwrap();
    assert_eq!(s.len(), 2);
    assert_eq!(s[0], 0xcc);
    assert_eq!(s[1], 0x55);
    s[0] = 4;
    s[1] = 3;
    assert_eq!(slices.decoupled_borrow().count(), 0);
    assert!(slices.next_back_slice_mut(None).unwrap().is_none());
    assert_eq!(a, [4, 3]);
    assert_eq!(c, [2, 1]);
}

/// Wrapper implementing [`IoSlicesIter`] for a single byte slice.
pub struct SingletonIoSlice<'a> {
    // Lives in an Option only because it has to for the SingletonIoSliceMut variant.
    slice: Option<&'a [u8]>,
}

impl<'a> SingletonIoSlice<'a> {
    /// Wrap a byte slice in a `SingletonIoSlice`.
    ///
    /// # Arguments:
    ///
    /// * `slice` - The byte slice to wrap.
    pub fn new(slice: &'a [u8]) -> Self {
        Self { slice: Some(slice) }
    }
}

impl<'a> IoSlicesIterCommon for SingletonIoSlice<'a> {
    type BackendIteratorError = convert::Infallible;

    fn next_slice_len(&mut self) -> Result<usize, Self::BackendIteratorError> {
        Ok(self.slice.as_ref().map(|slice| slice.len()).unwrap_or(0))
    }
}

impl<'a, 'b: 'a> IoSlicesIter<'a> for SingletonIoSlice<'b> {
    fn next_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        let slice = match self.slice.take() {
            Some(slice) => slice,
            None => return Ok(None),
        };
        if slice.is_empty() {
            return Ok(None);
        }
        let head_slice_len = max_len.map(|max_len| max_len.min(slice.len())).unwrap_or(slice.len());
        let (head, slice) = slice.split_at(head_slice_len);
        self.slice = Some(slice);
        Ok(Some(head))
    }
}

impl<'a, 'b: 'a> DoubleEndedIoSlicesIter<'a> for SingletonIoSlice<'b> {
    fn next_back_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        let slice = match self.slice.take() {
            Some(slice) => slice,
            None => return Ok(None),
        };
        if slice.is_empty() {
            return Ok(None);
        }
        let tail_slice_len = max_len.map(|max_len| max_len.min(slice.len())).unwrap_or(slice.len());
        let (slice, tail) = slice.split_at(slice.len() - tail_slice_len);
        self.slice = Some(slice);
        Ok(Some(tail))
    }
}

impl<'a, 'b: 'a> WalkableIoSlicesIter<'a> for SingletonIoSlice<'b> {
    fn for_each(&self, cb: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), Self::BackendIteratorError> {
        if let Some(slice) = self.slice {
            if !slice.is_empty() {
                cb(slice);
            }
        }
        Ok(())
    }
}

impl<'a, 'b: 'a> PeekableIoSlicesIter<'a> for SingletonIoSlice<'b> {
    type DecoupledBorrowIterType<'c>
        = SingletonIoSlice<'c>
    where
        Self: 'c;

    fn decoupled_borrow<'c>(&'c self) -> Self::DecoupledBorrowIterType<'c> {
        SingletonIoSlice { slice: self.slice }
    }
}

/// Wrapper implementing [`IoSlicesMutIter`] for a single byte slice.
pub struct SingletonIoSliceMut<'a> {
    slice: Option<&'a mut [u8]>,
}

impl<'a> SingletonIoSliceMut<'a> {
    /// Wrap a byte slice in a `SingletonIoSliceMut`.
    ///
    /// # Arguments:
    ///
    /// * `slice` - The byte slice to wrap.
    pub fn new(slice: &'a mut [u8]) -> Self {
        Self { slice: Some(slice) }
    }
}
impl<'a> IoSlicesIterCommon for SingletonIoSliceMut<'a> {
    type BackendIteratorError = convert::Infallible;

    fn next_slice_len(&mut self) -> Result<usize, Self::BackendIteratorError> {
        Ok(self.slice.as_ref().map(|slice| slice.len()).unwrap_or(0))
    }
}

impl<'a, 'b: 'a> IoSlicesIter<'a> for SingletonIoSliceMut<'b> {
    fn next_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        self.next_slice_mut(max_len)
            .map(|mut slice| slice.take().map(|slice| &*slice))
    }
}

impl<'a, 'b: 'a> IoSlicesMutIter<'a> for SingletonIoSliceMut<'b> {
    fn next_slice_mut(&mut self, max_len: Option<usize>) -> Result<Option<&'a mut [u8]>, Self::BackendIteratorError> {
        let slice = match self.slice.take() {
            Some(slice) => slice,
            None => return Ok(None),
        };
        if slice.is_empty() {
            return Ok(None);
        }
        let head_slice_len = max_len.map(|max_len| max_len.min(slice.len())).unwrap_or(slice.len());
        let (head, slice) = slice.split_at_mut(head_slice_len);
        self.slice = Some(slice);
        Ok(Some(head))
    }
}

impl<'a, 'b: 'a> DoubleEndedIoSlicesIter<'a> for SingletonIoSliceMut<'b> {
    fn next_back_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        self.next_back_slice_mut(max_len)
            .map(|mut slice| slice.take().map(|slice| &*slice))
    }
}

impl<'a, 'b: 'a> DoubleEndedIoSlicesMutIter<'a> for SingletonIoSliceMut<'b> {
    fn next_back_slice_mut(
        &mut self,
        max_len: Option<usize>,
    ) -> Result<Option<&'a mut [u8]>, Self::BackendIteratorError> {
        let slice = match self.slice.take() {
            Some(slice) => slice,
            None => return Ok(None),
        };
        if slice.is_empty() {
            return Ok(None);
        }
        let tail_slice_len = max_len.map(|max_len| max_len.min(slice.len())).unwrap_or(slice.len());
        let (slice, tail) = slice.split_at_mut(slice.len() - tail_slice_len);
        self.slice = Some(slice);
        Ok(Some(tail))
    }
}

impl<'a, 'b: 'a> WalkableIoSlicesIter<'a> for SingletonIoSliceMut<'b> {
    fn for_each(&self, cb: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), Self::BackendIteratorError> {
        if let Some(slice) = self.slice.as_deref() {
            if !slice.is_empty() {
                cb(slice);
            }
        }
        Ok(())
    }
}

impl<'a, 'b: 'a> PeekableIoSlicesIter<'a> for SingletonIoSliceMut<'b> {
    type DecoupledBorrowIterType<'c>
        = SingletonIoSlice<'c>
    where
        Self: 'c;

    fn decoupled_borrow<'c>(&'c self) -> Self::DecoupledBorrowIterType<'c> {
        SingletonIoSlice {
            slice: self.slice.as_deref(),
        }
    }
}

impl<'a, 'b: 'a> MutPeekableIoSlicesMutIter<'a> for SingletonIoSliceMut<'b> {
    type DecoupledBorrowMutIterType<'c>
        = SingletonIoSliceMut<'c>
    where
        Self: 'c;

    fn decoupled_borrow_mut<'c>(&'c mut self) -> Self::DecoupledBorrowMutIterType<'c> {
        SingletonIoSliceMut {
            slice: self.slice.as_deref_mut(),
        }
    }
}

/// Trivial [*IO slice iterator*](IoSlicesIterCommon) implementation returning
/// no byte slice.
#[derive(Default)]
pub struct EmptyIoSlices {}

impl IoSlicesIterCommon for EmptyIoSlices {
    type BackendIteratorError = convert::Infallible;

    fn next_slice_len(&mut self) -> Result<usize, Self::BackendIteratorError> {
        Ok(0)
    }
}

impl<'a> IoSlicesIter<'a> for EmptyIoSlices {
    fn next_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        self.next_slice_mut(max_len)
            .map(|mut slice| slice.take().map(|slice| &*slice))
    }
}

impl<'a> IoSlicesMutIter<'a> for EmptyIoSlices {
    fn next_slice_mut(&mut self, _max_len: Option<usize>) -> Result<Option<&'a mut [u8]>, Self::BackendIteratorError> {
        Ok(None)
    }
}

impl<'a> DoubleEndedIoSlicesIter<'a> for EmptyIoSlices {
    fn next_back_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        self.next_back_slice_mut(max_len)
            .map(|mut slice| slice.take().map(|slice| &*slice))
    }
}

impl<'a> DoubleEndedIoSlicesMutIter<'a> for EmptyIoSlices {
    fn next_back_slice_mut(
        &mut self,
        _max_len: Option<usize>,
    ) -> Result<Option<&'a mut [u8]>, Self::BackendIteratorError> {
        Ok(None)
    }
}

impl<'a> WalkableIoSlicesIter<'a> for EmptyIoSlices {
    fn for_each(&self, _cb: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), Self::BackendIteratorError> {
        Ok(())
    }

    fn total_len(&self) -> Result<usize, Self::BackendIteratorError> {
        Ok(0)
    }

    fn all_lengths_multiple_of(&self, _alignment: usize) -> Result<bool, Self::BackendIteratorError> {
        Ok(true)
    }
}

impl<'a> PeekableIoSlicesIter<'a> for EmptyIoSlices {
    type DecoupledBorrowIterType<'b>
        = Self
    where
        Self: 'b;

    fn decoupled_borrow<'b>(&'b self) -> Self::DecoupledBorrowIterType<'b> {
        Self {}
    }
}

impl<'a> MutPeekableIoSlicesMutIter<'a> for EmptyIoSlices {
    type DecoupledBorrowMutIterType<'b>
        = Self
    where
        Self: 'b;

    fn decoupled_borrow_mut<'b>(&'b mut self) -> Self::DecoupledBorrowMutIterType<'b> {
        Self {}
    }
}

/// [*IO slice iterator*](IoSlicesIterCommon) adaptor returned by
/// [`IoSlicesIterCommon::map_err()`](IoSlicesIterCommon::map_err).
pub struct IoSlicesIterMapErr<I, F, E>
where
    I: IoSlicesIterCommon,
    F: Fn(I::BackendIteratorError) -> E,
    E: Sized + fmt::Debug,
{
    iter: I,
    f: F,
}

impl<I, F, E> IoSlicesIterCommon for IoSlicesIterMapErr<I, F, E>
where
    I: IoSlicesIterCommon,
    F: Fn(I::BackendIteratorError) -> E,
    E: Sized + fmt::Debug,
{
    type BackendIteratorError = E;

    fn next_slice_len(&mut self) -> Result<usize, Self::BackendIteratorError> {
        self.iter.next_slice_len().map_err(|e| (self.f)(e))
    }

    fn is_empty(&mut self) -> Result<bool, Self::BackendIteratorError> {
        self.iter.is_empty().map_err(|e| (self.f)(e))
    }
}

impl<'a, I, F, E> IoSlicesIter<'a> for IoSlicesIterMapErr<I, F, E>
where
    I: IoSlicesIter<'a>,
    F: Fn(I::BackendIteratorError) -> E,
    E: Sized + fmt::Debug,
{
    fn next_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        self.iter.next_slice(max_len).map_err(|e| (self.f)(e))
    }
}

impl<'a, I, F, E> IoSlicesMutIter<'a> for IoSlicesIterMapErr<I, F, E>
where
    I: IoSlicesMutIter<'a>,
    F: Fn(I::BackendIteratorError) -> E,
    E: Sized + fmt::Debug,
{
    fn next_slice_mut(&mut self, max_len: Option<usize>) -> Result<Option<&'a mut [u8]>, Self::BackendIteratorError> {
        self.iter.next_slice_mut(max_len).map_err(|e| (self.f)(e))
    }
}

impl<'a, I, F, E> DoubleEndedIoSlicesIter<'a> for IoSlicesIterMapErr<I, F, E>
where
    I: DoubleEndedIoSlicesIter<'a>,
    F: Fn(I::BackendIteratorError) -> E,
    E: Sized + fmt::Debug,
{
    fn next_back_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        self.iter.next_back_slice(max_len).map_err(|e| (self.f)(e))
    }
}

impl<'a, I, F, E> DoubleEndedIoSlicesMutIter<'a> for IoSlicesIterMapErr<I, F, E>
where
    I: DoubleEndedIoSlicesMutIter<'a>,
    F: Fn(I::BackendIteratorError) -> E,
    E: Sized + fmt::Debug,
{
    fn next_back_slice_mut(
        &mut self,
        max_len: Option<usize>,
    ) -> Result<Option<&'a mut [u8]>, Self::BackendIteratorError> {
        self.iter.next_back_slice_mut(max_len).map_err(|e| (self.f)(e))
    }
}

impl<'a, I, F, E> WalkableIoSlicesIter<'a> for IoSlicesIterMapErr<I, F, E>
where
    I: WalkableIoSlicesIter<'a>,
    F: Fn(I::BackendIteratorError) -> E,
    E: Sized + fmt::Debug,
{
    fn for_each(&self, cb: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), Self::BackendIteratorError> {
        self.iter.for_each(cb).map_err(|e| (self.f)(e))
    }

    fn total_len(&self) -> Result<usize, Self::BackendIteratorError> {
        self.iter.total_len().map_err(|e| (self.f)(e))
    }

    fn all_lengths_multiple_of(&self, alignment: usize) -> Result<bool, Self::BackendIteratorError> {
        self.iter.all_lengths_multiple_of(alignment).map_err(|e| (self.f)(e))
    }
}

impl<'a, I, F, E> PeekableIoSlicesIter<'a> for IoSlicesIterMapErr<I, F, E>
where
    I: PeekableIoSlicesIter<'a>,
    F: Fn(I::BackendIteratorError) -> E,
    E: Sized + fmt::Debug,
{
    type DecoupledBorrowIterType<'b>
        = IoSlicesIterMapErr<I::DecoupledBorrowIterType<'b>, &'b F, E>
    where
        Self: 'b;

    fn decoupled_borrow<'b>(&'b self) -> Self::DecoupledBorrowIterType<'b> {
        IoSlicesIterMapErr {
            iter: self.iter.decoupled_borrow(),
            f: &self.f,
        }
    }
}

impl<'a, I, F, E> MutPeekableIoSlicesMutIter<'a> for IoSlicesIterMapErr<I, F, E>
where
    I: MutPeekableIoSlicesMutIter<'a>,
    F: Fn(I::BackendIteratorError) -> E,
    E: Sized + fmt::Debug,
{
    type DecoupledBorrowMutIterType<'b>
        = IoSlicesIterMapErr<I::DecoupledBorrowMutIterType<'b>, &'b F, E>
    where
        Self: 'b;

    fn decoupled_borrow_mut<'b>(&'b mut self) -> Self::DecoupledBorrowMutIterType<'b> {
        IoSlicesIterMapErr {
            iter: self.iter.decoupled_borrow_mut(),
            f: &self.f,
        }
    }
}

/// [*IO slice iterator*](IoSlicesIterCommon) adaptor returned by
/// [`IoSlicesIterCommon::as_ref()`](IoSlicesIterCommon::as_ref).
pub struct CovariantIoSlicesIterRef<'a, 'b: 'a, I: ?Sized + IoSlicesIterCommon> {
    iter: &'a mut I,
    _phantom: marker::PhantomData<fn() -> &'b ()>,
}

impl<'a, 'b: 'a, I: ?Sized + IoSlicesIterCommon> CovariantIoSlicesIterRef<'a, 'b, I> {
    fn new(iter: &'a mut I) -> Self {
        Self {
            iter,
            _phantom: marker::PhantomData,
        }
    }
}

impl<'a, 'b: 'a, I: ?Sized + IoSlicesIterCommon> IoSlicesIterCommon for CovariantIoSlicesIterRef<'a, 'b, I> {
    type BackendIteratorError = I::BackendIteratorError;

    fn next_slice_len(&mut self) -> Result<usize, Self::BackendIteratorError> {
        self.iter.next_slice_len()
    }

    fn is_empty(&mut self) -> Result<bool, Self::BackendIteratorError> {
        self.iter.is_empty()
    }
}

impl<'a, 'b: 'a, I: ?Sized + IoSlicesIter<'b>> IoSlicesIter<'a> for CovariantIoSlicesIterRef<'a, 'b, I> {
    fn next_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        self.iter.next_slice(max_len)
    }
}

impl<'a, 'b: 'a, I: ?Sized + IoSlicesMutIter<'b>> IoSlicesMutIter<'a> for CovariantIoSlicesIterRef<'a, 'b, I> {
    fn next_slice_mut(&mut self, max_len: Option<usize>) -> Result<Option<&'a mut [u8]>, Self::BackendIteratorError> {
        self.iter.next_slice_mut(max_len)
    }
}

impl<'a, 'b: 'a, I: ?Sized + DoubleEndedIoSlicesIter<'b>> DoubleEndedIoSlicesIter<'a>
    for CovariantIoSlicesIterRef<'a, 'b, I>
{
    fn next_back_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        self.iter.next_back_slice(max_len)
    }
}

impl<'a, 'b: 'a, I: ?Sized + DoubleEndedIoSlicesMutIter<'b>> DoubleEndedIoSlicesMutIter<'a>
    for CovariantIoSlicesIterRef<'a, 'b, I>
{
    fn next_back_slice_mut(
        &mut self,
        max_len: Option<usize>,
    ) -> Result<Option<&'a mut [u8]>, Self::BackendIteratorError> {
        self.iter.next_back_slice_mut(max_len)
    }
}

impl<'a, 'b: 'a, I: ?Sized + WalkableIoSlicesIter<'b>> WalkableIoSlicesIter<'a>
    for CovariantIoSlicesIterRef<'a, 'b, I>
{
    fn for_each(&self, cb: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), Self::BackendIteratorError> {
        (*self.iter).for_each(cb)
    }

    fn total_len(&self) -> Result<usize, Self::BackendIteratorError> {
        (*self.iter).total_len()
    }

    fn all_lengths_multiple_of(&self, alignment: usize) -> Result<bool, Self::BackendIteratorError> {
        (*self.iter).all_lengths_multiple_of(alignment)
    }
}

impl<'a, 'b: 'a, I: ?Sized + PeekableIoSlicesIter<'b>> PeekableIoSlicesIter<'a>
    for CovariantIoSlicesIterRef<'a, 'b, I>
{
    type DecoupledBorrowIterType<'c>
        = I::DecoupledBorrowIterType<'c>
    where
        Self: 'c;

    fn decoupled_borrow<'c>(&'c self) -> Self::DecoupledBorrowIterType<'c> {
        (*self.iter).decoupled_borrow()
    }
}

impl<'a, 'b: 'a, I: ?Sized + MutPeekableIoSlicesMutIter<'b>> MutPeekableIoSlicesMutIter<'a>
    for CovariantIoSlicesIterRef<'a, 'b, I>
{
    type DecoupledBorrowMutIterType<'c>
        = I::DecoupledBorrowMutIterType<'c>
    where
        Self: 'c;

    fn decoupled_borrow_mut<'c>(&'c mut self) -> Self::DecoupledBorrowMutIterType<'c> {
        self.iter.decoupled_borrow_mut()
    }
}

/// [*IO slice iterator*](IoSlicesIterCommon) adaptor returned by
/// [`IoSlicesIterCommon::take_exact()`](IoSlicesIterCommon::take_exact).
pub struct IoSlicesIterTakeExact<I>
where
    I: IoSlicesIterCommon,
{
    iter: I,
    remaining: usize,
}

impl<I> IoSlicesIterTakeExact<I>
where
    I: IoSlicesIterCommon,
{
    fn new(iter: I, n: usize) -> Self {
        Self { iter, remaining: n }
    }
}

impl<I> IoSlicesIterCommon for IoSlicesIterTakeExact<I>
where
    I: IoSlicesIterCommon,
{
    type BackendIteratorError = IoSlicesIterError<I::BackendIteratorError>;

    fn next_slice_len(&mut self) -> Result<usize, Self::BackendIteratorError> {
        self.iter
            .next_slice_len()
            .map(|slice_len| slice_len.min(self.remaining))
            .map_err(IoSlicesIterError::BackendIteratorError)
    }

    fn is_empty(&mut self) -> Result<bool, Self::BackendIteratorError> {
        Ok(self.remaining == 0)
    }
}

impl<'a, I> IoSlicesIter<'a> for IoSlicesIterTakeExact<I>
where
    I: IoSlicesIter<'a>,
{
    fn next_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let max_len = max_len
            .map(|max_len| max_len.min(self.remaining))
            .unwrap_or(self.remaining);
        let slice = self
            .iter
            .next_slice(Some(max_len))
            .map_err(IoSlicesIterError::BackendIteratorError)?;
        match slice {
            Some(slice) => self.remaining -= slice.len(),
            None => return Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted)),
        }
        Ok(slice)
    }
}

impl<'a, I> IoSlicesMutIter<'a> for IoSlicesIterTakeExact<I>
where
    I: IoSlicesMutIter<'a>,
{
    fn next_slice_mut(&mut self, max_len: Option<usize>) -> Result<Option<&'a mut [u8]>, Self::BackendIteratorError> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let max_len = max_len
            .map(|max_len| max_len.min(self.remaining))
            .unwrap_or(self.remaining);
        let slice = self
            .iter
            .next_slice_mut(Some(max_len))
            .map_err(IoSlicesIterError::BackendIteratorError)?;
        match slice.as_ref() {
            Some(slice) => self.remaining -= slice.len(),
            None => return Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted)),
        }
        Ok(slice)
    }
}

impl<'a, I> WalkableIoSlicesIter<'a> for IoSlicesIterTakeExact<I>
where
    I: WalkableIoSlicesIter<'a>,
{
    fn for_each(&self, cb: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), Self::BackendIteratorError> {
        let mut remaining = self.remaining;
        let mut buffers_exhausted = false;
        self.iter
            .for_each(&mut |slice| {
                if remaining == 0 {
                    return false;
                }

                let slice_len = remaining.min(slice.len());
                if slice_len == 0 {
                    buffers_exhausted = true;
                    return false;
                }
                remaining -= slice_len;
                cb(&slice[..slice_len])
            })
            .map_err(IoSlicesIterError::BackendIteratorError)?;

        if !buffers_exhausted {
            Ok(())
        } else {
            Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted))
        }
    }

    fn total_len(&self) -> Result<usize, Self::BackendIteratorError> {
        Ok(self.remaining)
    }
}

impl<'a, I> PeekableIoSlicesIter<'a> for IoSlicesIterTakeExact<I>
where
    I: PeekableIoSlicesIter<'a>,
{
    type DecoupledBorrowIterType<'b>
        = IoSlicesIterTakeExact<I::DecoupledBorrowIterType<'b>>
    where
        Self: 'b;

    fn decoupled_borrow<'b>(&'b self) -> Self::DecoupledBorrowIterType<'b> {
        IoSlicesIterTakeExact {
            iter: self.iter.decoupled_borrow(),
            remaining: self.remaining,
        }
    }
}

impl<'a, I> MutPeekableIoSlicesMutIter<'a> for IoSlicesIterTakeExact<I>
where
    I: MutPeekableIoSlicesMutIter<'a>,
{
    type DecoupledBorrowMutIterType<'b>
        = IoSlicesIterTakeExact<I::DecoupledBorrowMutIterType<'b>>
    where
        Self: 'b;

    fn decoupled_borrow_mut<'b>(&'b mut self) -> Self::DecoupledBorrowMutIterType<'b> {
        IoSlicesIterTakeExact {
            iter: self.iter.decoupled_borrow_mut(),
            remaining: self.remaining,
        }
    }
}

/// [*IO slice iterator*](IoSlicesIterCommon) adaptor returned by
/// [`IoSlicesIterCommon::chain()`](IoSlicesIterCommon::chain).
pub struct IoSlicesIterChain<I0, I1>
where
    I0: IoSlicesIterCommon,
    I1: IoSlicesIterCommon<BackendIteratorError = I0::BackendIteratorError>,
{
    iter0: Option<I0>,
    iter1: Option<I1>,
}

impl<I0, I1> IoSlicesIterChain<I0, I1>
where
    I0: IoSlicesIterCommon,
    I1: IoSlicesIterCommon<BackendIteratorError = I0::BackendIteratorError>,
{
    fn new(iter0: I0, iter1: I1) -> Self {
        Self {
            iter0: Some(iter0),
            iter1: Some(iter1),
        }
    }
}

impl<I0, I1> IoSlicesIterCommon for IoSlicesIterChain<I0, I1>
where
    I0: IoSlicesIterCommon,
    I1: IoSlicesIterCommon<BackendIteratorError = I0::BackendIteratorError>,
{
    type BackendIteratorError = I0::BackendIteratorError;

    fn next_slice_len(&mut self) -> Result<usize, Self::BackendIteratorError> {
        self.iter0
            .as_mut()
            .map(|iter0| iter0.next_slice_len())
            .or_else(|| self.iter1.as_mut().map(|iter1| iter1.next_slice_len()))
            .unwrap_or(Ok(0))
    }

    fn is_empty(&mut self) -> Result<bool, Self::BackendIteratorError> {
        Ok(self
            .iter0
            .as_mut()
            .map(|iter0| iter0.is_empty())
            .transpose()?
            .unwrap_or(true)
            && self
                .iter1
                .as_mut()
                .map(|iter1| iter1.is_empty())
                .transpose()?
                .unwrap_or(true))
    }
}

impl<'a, I0, I1> IoSlicesIter<'a> for IoSlicesIterChain<I0, I1>
where
    I0: IoSlicesIter<'a>,
    I1: IoSlicesIter<'a, BackendIteratorError = I0::BackendIteratorError>,
{
    fn next_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        if let Some(iter0) = self.iter0.as_mut() {
            match iter0.next_slice(max_len)? {
                Some(slice) => return Ok(Some(slice)),
                None => self.iter0 = None,
            }
        }
        if let Some(iter1) = self.iter1.as_mut() {
            let slice = iter1.next_slice(max_len)?;
            if slice.is_none() {
                self.iter1 = None;
            }
            return Ok(slice);
        }
        Ok(None)
    }
}

impl<'a, I0, I1> IoSlicesMutIter<'a> for IoSlicesIterChain<I0, I1>
where
    I0: IoSlicesMutIter<'a>,
    I1: IoSlicesMutIter<'a, BackendIteratorError = I0::BackendIteratorError>,
{
    fn next_slice_mut(&mut self, max_len: Option<usize>) -> Result<Option<&'a mut [u8]>, Self::BackendIteratorError> {
        if let Some(iter0) = self.iter0.as_mut() {
            match iter0.next_slice_mut(max_len)? {
                Some(slice) => return Ok(Some(slice)),
                None => self.iter0 = None,
            }
        }
        if let Some(iter1) = self.iter1.as_mut() {
            let slice = iter1.next_slice_mut(max_len)?;
            if slice.is_none() {
                self.iter1 = None;
            }
            return Ok(slice);
        }
        Ok(None)
    }
}

impl<'a, I0, I1> DoubleEndedIoSlicesIter<'a> for IoSlicesIterChain<I0, I1>
where
    I0: DoubleEndedIoSlicesIter<'a>,
    I1: DoubleEndedIoSlicesIter<'a, BackendIteratorError = I0::BackendIteratorError>,
{
    fn next_back_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        if let Some(iter1) = self.iter1.as_mut() {
            match iter1.next_back_slice(max_len)? {
                Some(slice) => return Ok(Some(slice)),
                None => self.iter1 = None,
            }
        }
        if let Some(iter0) = self.iter0.as_mut() {
            let slice = iter0.next_back_slice(max_len)?;
            if slice.is_none() {
                self.iter0 = None;
            }
            return Ok(slice);
        }
        Ok(None)
    }
}

impl<'a, I0, I1> DoubleEndedIoSlicesMutIter<'a> for IoSlicesIterChain<I0, I1>
where
    I0: DoubleEndedIoSlicesMutIter<'a>,
    I1: DoubleEndedIoSlicesMutIter<'a, BackendIteratorError = I0::BackendIteratorError>,
{
    fn next_back_slice_mut(
        &mut self,
        max_len: Option<usize>,
    ) -> Result<Option<&'a mut [u8]>, Self::BackendIteratorError> {
        if let Some(iter1) = self.iter1.as_mut() {
            match iter1.next_back_slice_mut(max_len)? {
                Some(slice) => return Ok(Some(slice)),
                None => self.iter1 = None,
            }
        }
        if let Some(iter0) = self.iter0.as_mut() {
            let slice = iter0.next_back_slice_mut(max_len)?;
            if slice.is_none() {
                self.iter0 = None;
            }
            return Ok(slice);
        }
        Ok(None)
    }
}
impl<'a, I0, I1> WalkableIoSlicesIter<'a> for IoSlicesIterChain<I0, I1>
where
    I0: WalkableIoSlicesIter<'a>,
    I1: WalkableIoSlicesIter<'a, BackendIteratorError = I0::BackendIteratorError>,
{
    fn for_each(&self, cb: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), Self::BackendIteratorError> {
        let mut done = false;
        self.iter0
            .as_ref()
            .map(|iter0| {
                iter0.for_each(&mut |slice| {
                    done |= !cb(slice);
                    !done
                })
            })
            .transpose()?;
        if done {
            return Ok(());
        }

        self.iter0.as_ref().map(|iter0| iter0.for_each(cb)).transpose()?;
        Ok(())
    }

    fn total_len(&self) -> Result<usize, Self::BackendIteratorError> {
        Ok(self.iter0.as_ref().map(|iter0| iter0.total_len()).unwrap_or(Ok(0))?
            + self.iter1.as_ref().map(|iter1| iter1.total_len()).unwrap_or(Ok(0))?)
    }

    fn all_lengths_multiple_of(&self, alignment: usize) -> Result<bool, Self::BackendIteratorError> {
        Ok(self
            .iter0
            .as_ref()
            .map(|iter0| iter0.all_lengths_multiple_of(alignment))
            .transpose()?
            .unwrap_or(true)
            && self
                .iter1
                .as_ref()
                .map(|iter1| iter1.all_lengths_multiple_of(alignment))
                .transpose()?
                .unwrap_or(true))
    }
}

impl<'a, I0, I1> PeekableIoSlicesIter<'a> for IoSlicesIterChain<I0, I1>
where
    I0: PeekableIoSlicesIter<'a>,
    I1: PeekableIoSlicesIter<'a, BackendIteratorError = I0::BackendIteratorError>,
{
    type DecoupledBorrowIterType<'b>
        = IoSlicesIterChain<I0::DecoupledBorrowIterType<'b>, I1::DecoupledBorrowIterType<'b>>
    where
        Self: 'b;

    fn decoupled_borrow<'b>(&'b self) -> Self::DecoupledBorrowIterType<'b> {
        IoSlicesIterChain {
            iter0: self.iter0.as_ref().map(|iter0| iter0.decoupled_borrow()),
            iter1: self.iter1.as_ref().map(|iter1| iter1.decoupled_borrow()),
        }
    }
}

impl<'a, I0, I1> MutPeekableIoSlicesMutIter<'a> for IoSlicesIterChain<I0, I1>
where
    I0: MutPeekableIoSlicesMutIter<'a>,
    I1: MutPeekableIoSlicesMutIter<'a, BackendIteratorError = I0::BackendIteratorError>,
{
    type DecoupledBorrowMutIterType<'b>
        = IoSlicesIterChain<I0::DecoupledBorrowMutIterType<'b>, I1::DecoupledBorrowMutIterType<'b>>
    where
        Self: 'b;

    fn decoupled_borrow_mut<'b>(&'b mut self) -> Self::DecoupledBorrowMutIterType<'b> {
        IoSlicesIterChain {
            iter0: self.iter0.as_mut().map(|iter0| iter0.decoupled_borrow_mut()),
            iter1: self.iter1.as_mut().map(|iter1| iter1.decoupled_borrow_mut()),
        }
    }
}

/// [`IoSlicesIter`] implementation yielding a specified number of zero bytes.
pub struct ZeroFilledIoSlices {
    remaining: usize,
}

impl ZeroFilledIoSlices {
    pub const CHUNK_SIZE: usize = 16;
    const ZEROES_BUFFER: [u8; Self::CHUNK_SIZE] = [0u8; Self::CHUNK_SIZE];

    /// Instantiate a `ZeroFilledIoSlices`.
    ///
    /// # Arguments:
    ///
    /// * `n` - The number of zero bytes to yield.
    pub fn new(n: usize) -> Self {
        Self { remaining: n }
    }
}

impl IoSlicesIterCommon for ZeroFilledIoSlices {
    type BackendIteratorError = convert::Infallible;

    fn next_slice_len(&mut self) -> Result<usize, Self::BackendIteratorError> {
        Ok(self.remaining.min(Self::ZEROES_BUFFER.len()))
    }

    fn is_empty(&mut self) -> Result<bool, Self::BackendIteratorError> {
        Ok(self.remaining == 0)
    }
}

impl<'a> IoSlicesIter<'a> for ZeroFilledIoSlices {
    fn next_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let mut len = self.remaining.min(Self::ZEROES_BUFFER.len());
        len = max_len.map(|max_len| max_len.min(len)).unwrap_or(len);
        self.remaining -= len;

        Ok(Some(&Self::ZEROES_BUFFER[..len]))
    }
}

impl<'a> WalkableIoSlicesIter<'a> for ZeroFilledIoSlices {
    fn for_each(&self, cb: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), Self::BackendIteratorError> {
        let mut remaining = self.remaining;

        while remaining != 0 {
            let slice_len = remaining.min(Self::ZEROES_BUFFER.len());
            remaining -= slice_len;
            if !cb(&Self::ZEROES_BUFFER[..slice_len]) {
                break;
            }
        }
        Ok(())
    }

    fn total_len(&self) -> Result<usize, Self::BackendIteratorError> {
        Ok(self.remaining)
    }

    fn all_lengths_multiple_of(&self, alignment: usize) -> Result<bool, Self::BackendIteratorError> {
        if alignment.is_pow2() {
            Ok(self.remaining & (alignment - 1) == 0)
        } else {
            Ok(self.remaining.is_multiple_of(alignment))
        }
    }
}

impl<'a> PeekableIoSlicesIter<'a> for ZeroFilledIoSlices {
    type DecoupledBorrowIterType<'b> = Self;

    fn decoupled_borrow<'b>(&'b self) -> Self::DecoupledBorrowIterType<'b> {
        Self {
            remaining: self.remaining,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod walkable_io_slices_iter {
        use super::*;

        #[test]
        fn empty_io_slices() {
            let io_slice = EmptyIoSlices::default();
            {
                // total len
                assert_eq!(io_slice.total_len().unwrap(), 0);
            }

            {
                // for each
                io_slice
                    .for_each(&mut |_| {
                        assert!(false, "This should never be called");
                        true
                    })
                    .unwrap();
            }

            {
                // all_lengths_multiple_of
                assert!(io_slice.all_lengths_multiple_of(5).unwrap());
                assert!(io_slice.all_lengths_multiple_of(1).unwrap());
                assert!(io_slice.all_lengths_multiple_of(4223).unwrap());
            }
        }

        #[test]
        fn io_slices_iter_chain() {
            let buffer1 = [0u8, 1, 2, 3, 4];
            let slices1 = [buffer1.as_slice()];
            let buffer2 = [5u8, 6, 7];
            let slices2 = [buffer2.as_slice()];
            let buffer3 = [5u8, 6, 7, 8, 9];
            let slices3 = [buffer3.as_slice()];

            {
                // total len
                let chain = IoSlicesIterChain::new(
                    BuffersSliceIoSlicesIter::new(&slices1),
                    BuffersSliceIoSlicesIter::new(&slices2),
                );

                assert_eq!(chain.total_len().unwrap(), buffer1.len() + buffer2.len());
            }

            {
                // for each
                let chain = IoSlicesIterChain::new(
                    BuffersSliceIoSlicesIter::new(&slices1),
                    BuffersSliceIoSlicesIter::new(&slices2),
                );
                let all_slices = [buffer1.as_slice(), buffer2.as_slice()];
                let mut i = all_slices.iter();

                chain
                    .for_each(&mut |v| {
                        assert_eq!(v, *i.next().unwrap());
                        true
                    })
                    .unwrap();
                assert!(i.next().is_none());
            }

            {
                // all_lengths_multiple_of
                {
                    let chain_same_length = IoSlicesIterChain::new(
                        BuffersSliceIoSlicesIter::new(&slices1),
                        BuffersSliceIoSlicesIter::new(&slices3),
                    );
                    assert!(chain_same_length.all_lengths_multiple_of(5).unwrap());
                }
                {
                    let chain_different_length = IoSlicesIterChain::new(
                        BuffersSliceIoSlicesIter::new(&slices1),
                        BuffersSliceIoSlicesIter::new(&slices2),
                    );
                    assert!(!chain_different_length.all_lengths_multiple_of(5).unwrap());
                }
            }
        }
    }
}
