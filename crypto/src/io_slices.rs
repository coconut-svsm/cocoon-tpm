// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Convience traits fixing the various [*IO slice iterator* traits](io_slices)'
//! associated
//! [`BackendIteratorError`](io_slices::IoSlicesIterCommon::BackendIteratorError) fixed to
//! [`CryptoError`].

// Lifetimes are not obvious at first sight here, make the explicit.
#![allow(clippy::needless_lifetimes)]

use crate::CryptoError;
use crate::utils_common::io_slices::{self, IoSlicesIterCommon as _};
use core::convert;

/// [`IoSlicesIter`](io_slices::IoSlicesIter) with the associated
/// [`BackendIteratorError`](io_slices::IoSlicesIterCommon::BackendIteratorError) fixed to
/// [`CryptoError`].
pub trait CryptoIoSlicesIter<'a>: io_slices::IoSlicesIter<'a, BackendIteratorError = CryptoError> {}

impl<'a, I> CryptoIoSlicesIter<'a> for I where I: io_slices::IoSlicesIter<'a, BackendIteratorError = CryptoError> {}

/// [`IoSlicesMutIter`](io_slices::IoSlicesMutIter) with the associated
/// [`BackendIteratorError`](io_slices::IoSlicesIterCommon::BackendIteratorError) fixed to
/// [`CryptoError`].
pub trait CryptoIoSlicesMutIter<'a>: io_slices::IoSlicesMutIter<'a, BackendIteratorError = CryptoError> {}

impl<'a, I> CryptoIoSlicesMutIter<'a> for I where I: io_slices::IoSlicesMutIter<'a, BackendIteratorError = CryptoError> {}

/// [`DoubleEndedIoSlicesIter`](io_slices::DoubleEndedIoSlicesIter) with the
/// associated
/// [`BackendIteratorError`](io_slices::IoSlicesIterCommon::BackendIteratorError) fixed to
/// [`CryptoError`].
pub trait CryptoDoubleEndedIoSlicesIter<'a>:
    io_slices::DoubleEndedIoSlicesIter<'a, BackendIteratorError = CryptoError>
{
}

impl<'a, I> CryptoDoubleEndedIoSlicesIter<'a> for I where
    I: io_slices::DoubleEndedIoSlicesIter<'a, BackendIteratorError = CryptoError>
{
}

/// [`DoubleEndedIoSlicesMutIter`](io_slices::DoubleEndedIoSlicesMutIter) with
/// the associated
/// [`BackendIteratorError`](io_slices::IoSlicesIterCommon::BackendIteratorError) fixed to
/// [`CryptoError`].
pub trait CryptoDoubleEndedIoSlicesMutIter<'a>:
    io_slices::DoubleEndedIoSlicesMutIter<'a, BackendIteratorError = CryptoError>
{
}

impl<'a, I> CryptoDoubleEndedIoSlicesMutIter<'a> for I where
    I: io_slices::DoubleEndedIoSlicesMutIter<'a, BackendIteratorError = CryptoError>
{
}

/// [`WalkableIoSlicesIter`](io_slices::WalkableIoSlicesIter) with the
/// associated
/// [`BackendIteratorError`](io_slices::IoSlicesIterCommon::BackendIteratorError) fixed to
/// [`CryptoError`].
pub trait CryptoWalkableIoSlicesIter<'a>:
    io_slices::WalkableIoSlicesIter<'a, BackendIteratorError = CryptoError>
{
}

impl<'a, I> CryptoWalkableIoSlicesIter<'a> for I where
    I: io_slices::WalkableIoSlicesIter<'a, BackendIteratorError = CryptoError>
{
}

/// [`WalkableIoSlicesMutIter`](io_slices::WalkableIoSlicesMutIter) with the
/// associated
/// [`BackendIteratorError`](io_slices::IoSlicesIterCommon::BackendIteratorError) fixed to
/// [`CryptoError`].
pub trait CryptoWalkableIoSlicesMutIter<'a>:
    io_slices::WalkableIoSlicesMutIter<'a, BackendIteratorError = CryptoError>
{
}

impl<'a, I> CryptoWalkableIoSlicesMutIter<'a> for I where
    I: io_slices::WalkableIoSlicesMutIter<'a, BackendIteratorError = CryptoError>
{
}

/// [`PeekableIoSlicesIter`](io_slices::PeekableIoSlicesIter) with the
/// associated
/// [`BackendIteratorError`](io_slices::IoSlicesIterCommon::BackendIteratorError) fixed to
/// [`CryptoError`].
pub trait CryptoPeekableIoSlicesIter<'a>:
    io_slices::PeekableIoSlicesIter<'a, BackendIteratorError = CryptoError>
{
}

impl<'a, I> CryptoPeekableIoSlicesIter<'a> for I where
    I: io_slices::PeekableIoSlicesIter<'a, BackendIteratorError = CryptoError>
{
}

/// [`PeekableIoSlicesMutIter`](io_slices::PeekableIoSlicesMutIter) with the
/// associated
/// [`BackendIteratorError`](io_slices::IoSlicesIterCommon::BackendIteratorError) fixed to
/// [`CryptoError`].
pub trait CryptoPeekableIoSlicesMutIter<'a>:
    io_slices::PeekableIoSlicesMutIter<'a, BackendIteratorError = CryptoError>
{
}

impl<'a, I> CryptoPeekableIoSlicesMutIter<'a> for I where
    I: io_slices::PeekableIoSlicesMutIter<'a, BackendIteratorError = CryptoError>
{
}

/// [`MutPeekableIoSlicesMutIter`](io_slices::MutPeekableIoSlicesMutIter) with
/// the associated
/// [`BackendIteratorError`](io_slices::IoSlicesIterCommon::BackendIteratorError) fixed to
/// [`CryptoError`].
pub trait CryptoMutPeekableIoSlicesMutIter<'a>:
    io_slices::MutPeekableIoSlicesMutIter<'a, BackendIteratorError = CryptoError>
{
}

impl<'a, I> CryptoMutPeekableIoSlicesMutIter<'a> for I where
    I: io_slices::MutPeekableIoSlicesMutIter<'a, BackendIteratorError = CryptoError>
{
}

type EmptyCryptoIoSlicesIterMapErrType =
    io_slices::IoSlicesIterMapErr<io_slices::EmptyIoSlices, fn(convert::Infallible) -> CryptoError, CryptoError>;

/// [`EmptyIoSlices`](io_slices::EmptyIoSlices) with the associated
/// [`Infallible`](convert::Infallible)
/// [`BackendIteratorError`](io_slices::IoSlicesIterCommon::BackendIteratorError) mapped
/// [`CryptoError`].
pub struct EmptyCryptoIoSlices {
    iter: EmptyCryptoIoSlicesIterMapErrType,
}

impl Default for EmptyCryptoIoSlices {
    fn default() -> Self {
        Self {
            iter: io_slices::EmptyIoSlices::default().map_infallible_err(),
        }
    }
}

impl io_slices::IoSlicesIterCommon for EmptyCryptoIoSlices {
    type BackendIteratorError = CryptoError;

    fn next_slice_len(&mut self) -> Result<usize, Self::BackendIteratorError> {
        self.iter.next_slice_len()
    }
}

impl<'a> io_slices::IoSlicesIter<'a> for EmptyCryptoIoSlices {
    fn next_slice(&mut self, max_len: Option<usize>) -> Result<Option<&'a [u8]>, Self::BackendIteratorError> {
        self.iter.next_slice(max_len)
    }
}

impl<'a> io_slices::IoSlicesMutIter<'a> for EmptyCryptoIoSlices {
    fn next_slice_mut(&mut self, max_len: Option<usize>) -> Result<Option<&'a mut [u8]>, Self::BackendIteratorError> {
        self.iter.next_slice_mut(max_len)
    }
}

impl<'a> io_slices::WalkableIoSlicesIter<'a> for EmptyCryptoIoSlices {
    fn for_each(&self, cb: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), Self::BackendIteratorError> {
        self.iter.for_each(cb)
    }

    fn total_len(&self) -> Result<usize, Self::BackendIteratorError> {
        self.iter.total_len()
    }

    fn all_aligned_to(&self, alignment: usize) -> Result<bool, Self::BackendIteratorError> {
        self.iter.all_aligned_to(alignment)
    }
}

impl<'a> io_slices::PeekableIoSlicesIter<'a> for EmptyCryptoIoSlices {
    type DecoupledBorrowIterType<'b>
        = Self
    where
        Self: 'b;

    fn decoupled_borrow<'b>(&'b self) -> Self::DecoupledBorrowIterType<'b> {
        Self::default()
    }
}

impl<'a> io_slices::MutPeekableIoSlicesMutIter<'a> for EmptyCryptoIoSlices {
    type DecoupledBorrowMutIterType<'b>
        = Self
    where
        Self: 'b;

    fn decoupled_borrow_mut<'b>(&'b mut self) -> Self::DecoupledBorrowMutIterType<'b> {
        Self::default()
    }
}
