// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Storage backend filesystem traits and definitions.
//!
//! Storage backends define a [`NvFs`] implementation for other components to
//! store sensitive data to. For a secure filesystem implemention suitable for
//! deployments in untrusted environments see [`cocoonfs`].

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

use crate::chip;
use crate::crypto;
use crate::utils_async::sync_types::{self, SyncRcPtrRef as _};
use crate::utils_common::{self, zeroize};
use core::{convert, future, marker, ops, pin, task};

pub mod cocoonfs;

/// [`NvFsError::IoError`] details.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum NvFsIoError {
    /// Read or write region out of the underlying physical storage's bounds.
    RegionOutOfRange,
    /// Read from a region never written to before or which had been trimmed
    /// since.
    RegionNotMapped,
    /// Unspecified IO failure.
    IoFailure,
}

/// Error type returned by [`NvFs`] primitives.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum NvFsError {
    /// Logic error.
    Internal,

    /// Permanent internal failure.
    ///
    /// Some internal logic error led to a condition rendering the [`NvFs`]
    /// instance unusuable for forever.
    PermanentInternalFailure,

    /// A memory allocation has failed.
    MemoryAllocationFailure,

    /// Stale consistent read sequence.
    ///
    /// A [`ConsistentReadSequence`](NvFs::ConsistentReadSequence) or the read
    /// sequence implicit to a [`Transaction`](NvFs::Transaction) became
    /// stale because some other [`Transaction`](NvFs::Transaction) had been
    /// [committed](NvFs::commit_transaction) in the meanwhile.
    Retry,

    /// The operation is not supported.
    OperationNotSupported,

    /// IO error.
    IoError(NvFsIoError),

    /// Some cryptographic primitive failed.
    CryptoError(crypto::CryptoError),

    /// Filesystem format error.
    ///
    /// Details are provided as a filesystem implementation specific error code.
    FsFormatError(isize),

    /// The size of some entity exceeds the bounds supported by the [`NvFs`]
    /// implementation.
    DimensionsNotSupported,

    /// Authentication failure.
    ///
    /// The filesystem implements some form of authentication and verification
    /// failed.
    AuthenticationFailure,

    /// Insufficient free space left on the storage.
    NoSpace,

    /// Attempted to read back some inode's data for which a prior update
    /// operation failed.
    ///
    /// Attempted to read an inode's data through a
    /// [`Transaction`](NvFs::Transaction),
    /// but the inode's data is in indeterminate state in the context of that
    /// transaction, because a prior [write](NvFs::write_inode) or
    /// [unlinking operation](NvFs::unlink_cursor) operation failed.
    FailedDataUpdateRead,

    /// Attempted to read from, write to or unlink a reserved inode.
    InodeReserved,
}

impl convert::From<convert::Infallible> for NvFsError {
    fn from(value: convert::Infallible) -> Self {
        match value {}
    }
}

impl convert::From<utils_common::alloc::TryNewError> for NvFsError {
    fn from(value: utils_common::alloc::TryNewError) -> Self {
        match value {
            utils_common::alloc::TryNewError::MemoryAllocationFailure => Self::MemoryAllocationFailure,
        }
    }
}

impl convert::From<utils_common::fixed_vec::FixedVecMemoryAllocationFailure> for NvFsError {
    fn from(_value: utils_common::fixed_vec::FixedVecMemoryAllocationFailure) -> Self {
        Self::MemoryAllocationFailure
    }
}

impl convert::From<utils_common::fixed_vec::FixedVecNewFromFnError<NvFsError>> for NvFsError {
    fn from(value: utils_common::fixed_vec::FixedVecNewFromFnError<NvFsError>) -> Self {
        match value {
            utils_common::fixed_vec::FixedVecNewFromFnError::MemoryAllocationFailure => Self::MemoryAllocationFailure,
            utils_common::fixed_vec::FixedVecNewFromFnError::FnError(e) => e,
        }
    }
}

impl convert::From<utils_common::fixed_vec::FixedVecNewFromFnError<convert::Infallible>> for NvFsError {
    fn from(value: utils_common::fixed_vec::FixedVecNewFromFnError<convert::Infallible>) -> Self {
        Self::from(utils_common::fixed_vec::FixedVecMemoryAllocationFailure::from(value))
    }
}

impl convert::From<alloc::collections::TryReserveError> for NvFsError {
    fn from(_value: alloc::collections::TryReserveError) -> Self {
        Self::MemoryAllocationFailure
    }
}

impl convert::From<chip::NvChipIoError> for NvFsError {
    fn from(value: chip::NvChipIoError) -> Self {
        match value {
            chip::NvChipIoError::Internal => Self::Internal,
            chip::NvChipIoError::MemoryAllocationFailure => Self::MemoryAllocationFailure,
            chip::NvChipIoError::OperationNotSupported => Self::OperationNotSupported,
            chip::NvChipIoError::IoBlockOutOfRange => Self::IoError(NvFsIoError::RegionOutOfRange),
            chip::NvChipIoError::IoBlockNotMapped => Self::IoError(NvFsIoError::RegionNotMapped),
            chip::NvChipIoError::IoFailure => Self::IoError(NvFsIoError::IoFailure),
        }
    }
}

impl convert::From<crypto::CryptoError> for NvFsError {
    fn from(value: crypto::CryptoError) -> Self {
        match value.anonymize_any_sensitive(crypto::CryptoError::UnspecifiedFailure) {
            crypto::CryptoError::MemoryAllocationFailure => Self::MemoryAllocationFailure,
            crypto::CryptoError::BufferStateIndeterminate => {
                // The only possible cause for a crypto io_slices reporting an indeterminate
                // buffer state is a prior inode data update that failed
                // midway.
                Self::FailedDataUpdateRead
            }
            e => Self::CryptoError(e),
        }
    }
}

impl convert::From<crypto::rng::RngGenerateError> for NvFsError {
    fn from(value: crypto::rng::RngGenerateError) -> Self {
        match value {
            crypto::rng::RngGenerateError::CryptoError(e) => Self::from(e),
            crypto::rng::RngGenerateError::ReseedRequired => Self::from(crypto::CryptoError::RngFailure),
        }
    }
}

/// Debugging friendly helper for [`NvFs`] implementations to instantiate
/// [`NvFsError::Internal`].
///
/// Panics if `cfg!(debug_assertions)` is on, to allow for debugger examination
/// at the point the logic error has happened. Otherwise a
/// [`NvFsError::Internal`] is returned.
#[macro_export]
macro_rules! nvfs_err_internal {
    () => {{
        if cfg!(debug_assertions) {
            panic!("NvFsError::Internal");
        } else {
            $crate::fs::NvFsError::Internal
        }
    }};
}

/// [`NvFs`] read context.
///
/// Passed to any [`NvFs`] read primitive for specifying whether to
/// read the state as committed to storage or, alternatively, through some
/// [`Transaction`](NvFs::Transaction).
pub enum NvFsReadContext<FS: NvFs> {
    /// Read the state as last committed to storage.
    ///
    /// Read the state as found committed to storage at the point the `seq`
    /// [`ConsistentReadSequence`](NvFs::ConsistentReadSequence)
    /// had been [`started`](NvFs::start_read_sequence).
    ///
    /// The respective `NvFs` read primitives will return an error of
    /// [`Retry`](NvFsError::Retry) in case the `seq`
    /// [`ConsistentReadSequence`](NvFs::ConsistentReadSequence) became
    /// stale, i.e. when a [`Transaction`](NvFs::Transaction) got
    /// [committed](NvFs::commit_transaction)
    /// after the [`NvFs::start_read_sequence()`] `seq` had been obtained from.
    Committed { seq: FS::ConsistentReadSequence },

    /// Read the state through a [`Transaction`](NvFs::Transaction).
    ///
    /// Read the state as if `transaction` had been
    /// [`committed`](NvFs::commit_transaction) to storage.
    ///
    /// The respective `NvFs` read primitives will return an error of
    /// [`Retry`](NvFsError::Retry) in case the consistent read sequence
    /// implict to `transaction` became stale, i.e. when
    /// another [`Transaction`](NvFs::Transaction) got
    /// [committed](NvFs::commit_transaction) after
    /// the [`NvFs::start_transaction()`] the `transaction` had been obtained
    /// from.
    ///
    /// The `NvFsReadContext` assumes exclusive ownership of `transaction`. The
    /// respective `NvFs` read primitives all return the `NvFsReadContext`
    /// instance back when finished, from which the `transaction` may then
    /// get recovered.
    Transaction { transaction: FS::Transaction },
}

impl<FS: NvFs> NvFsReadContext<FS> {
    pub fn as_seq(&self) -> FS::ConsistentReadSequence {
        match self {
            Self::Committed { seq } => seq.clone(),
            Self::Transaction { transaction } => FS::ConsistentReadSequence::from(transaction),
        }
    }
}

/// Type for a user specified pre-transaction-commit callback.
///
/// The pre-commit callback will only get invoked if the
/// [`Transaction`](NvFs::Transaction) is still eligible for commit, i.e. if it
/// hasn't been superseded by committing another one since it got
/// [started](NvFs::start_transaction) in the meanwhile.
///
/// Returning an error from the pre-commit callback will cause a cancellation of
/// the associated [`Transaction`](NvFs::Transaction) commit process and make it
/// fail with that error.  In this case -- and only in this case -- the call
/// will not be paired with one to the corresponding [post-commit
/// callback](PostCommitCallbackType).
///
/// # See also:
///
/// * [`NvFs::commit_transaction()`]
pub type PreCommitValidateCallbackType = Box<dyn FnOnce() -> Result<(), NvFsError> + marker::Send>;

/// Type for a user specified post-transaction-commit callback.
///
/// The invocation of the post-commit callback is always paired with a prior
/// invocation of the [pre-commit](PreCommitValidateCallbackType) that returned
/// success.
///
/// The result of the [`Transaction`](NvFs::Transaction) commit is made
/// available as an argument to the callback.
///
/// # See also:
///
/// * [`NvFs::commit_transaction()`]
pub type PostCommitCallbackType = Box<dyn FnOnce(Result<(), TransactionCommitError>) + marker::Send>;

/// Error information returned for [`Transaction`](NvFs::Transaction)
/// [commit](NvFs::commit_transaction) failures.
#[derive(Debug)]
pub enum TransactionCommitError {
    /// The transaction commit failed and the actual state stored on the backend
    /// is equivalent to what it had been before the failed transaction
    /// commit attempt.
    LogStateClean { reason: NvFsError },

    /// The commit operation failed at some point, but it is unknown what the
    /// actual state on the storage backend is: it could be either in the
    /// original state from before the transaction or it might also have got
    /// the transaction applied insofar as the changes would become effective
    /// after a remount, e.g. due to some journal replay mechanism.  However, in
    /// the latter case, any subsequent operation, including [starting
    /// consistent read sequences](NvFs::start_read_sequence), on the still
    /// mounted image is guaranteed to commence only after the state was
    /// successfully moved back to what it had been before the failed
    /// transaction commit attempt. For explicitly returning to a clean state,
    /// the convenience [`NvFs::try_cleanup_indeterminate_commit_log()`]
    /// helper is provided.
    LogStateIndeterminate { reason: NvFsError },
}

/// Future trait implemented by all [`NvFs`] related futures.
///
/// `NvFsFuture` differs from the standard [Rust `Future`](future::Future) only
/// in that it takes an additional `fs_instance` argument, thereby potentially
/// avoiding the need of creating and storing additional
/// [`SyncRcPtr`](sync_types::SyncRcPtr) clones for the fs instance. In cases
/// where a proper Rust [`Future`] is needed, [`NvFsFuture`] implementation
/// instances can get wrapped in a [`NvFsFutureAsCoreFuture`].
///
/// # See also:
///
/// * [`NvFsFutureAsCoreFuture`]
pub trait NvFsFuture<FS: NvFs>: 'static {
    type Output;

    /// Poll on a [`NvFsFuture`].
    ///
    /// Completely analogous to the standard [Rust
    /// `Future::poll()`](future::Future::poll), except for the additional
    /// `fs_instance` argument.
    ///
    /// # Arguments:
    ///
    /// * `fs_instance` - A [`SyncRcPtrRef<NvFs>`](sync_types::SyncRcPtrRef)
    ///   referring to the [`SyncRcPtr<NvFs>`](sync_types::SyncRcPtr) managing
    ///   the `NvFs` instance the [`NvFsFuture`] had been obtained from.
    /// * `cx` - The context of an asynchronous task.
    fn poll(
        self: pin::Pin<&mut Self>,
        fs_instance: &FS::SyncRcPtrRef<'_>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output>;
}

/// Storage backend filesystem interface.
///
/// Trait `NvFs` defines an interface to a storage backend filesystem
/// implementation for the other components to store sensitive data on.
///
/// # Filesystem model
///
/// In contrast to common general-purpose filesystems, it is not assumed that
/// arbitrary filenames or any sort of hierarchic directory structure is
/// supported: inodes are identified and referred to directly by `u32` integers.
///
/// Moreover, it is expected that individual files are generally small and that
/// it's affordable to always read or write them as a whole -- partial reads or
/// updates (and seeks accordingly) are not supported. This limitation enables
/// implementations to use fresh random encryption block cipher mode IVs for
/// each file update, thereby achieving stronger security properties than what's
/// provided by common block layer based encryption scheme like e.g. XTS or
/// CBC-ESSIV.
///
/// # Execution model
///
/// In order to enable integration with a wide range of different execution
/// environments with different characteristics, the `NvFs` API is defined in
/// terms of Rust's `async` [`Future`] concept. Note that this does not mandate
/// a target execution environment to implement any actual asynchronous
/// processing semantics -- all `NvFs` [`Future`]s could just as well get polled
/// synchronously to completion by some minimal `async` executor like e.g.
/// [`Pollster`](https://docs.rs/pollster/latest/pollster/) or similar if desired.
///
/// `NvFs` [`Future`]s are never anonymous -- i.e. what one would get out of
/// Rust's `async` keyword -- so that they can get stored in a [`Box`] on the
/// heap or in some other dependendant [`Future`]. The possibility of moving
/// execution state away from the stack and storing it on the heap might be
/// advantageous for stack constrained environments like kernels.
///
/// The `NvFs` methods don't in fact return [`Future`]s, but [`NvFsFuture`]s.
/// The latter differ from the former only in that they take an additional
/// `fs_instance` argument, thereby potentially avoiding the need of creating
/// and storing additional [`SyncRcPtr`](sync_types::SyncRcPtr) clones for the
/// fs instance. In cases where a proper Rust [`Future`] is needed,
/// [`NvFsFuture`] implementation instances can get wrapped in a
/// [`NvFsFutureAsCoreFuture`].
///
/// # Transactions and Consistent Read Sequences
///
/// Any updates, both to metadata and to file data, are to be accumulated at a
/// [`Transaction`](Self::Transaction), started via
/// [`start_transaction()`](Self::start_transaction), which may eventually get
/// [committed](Self::commit_transaction) for the changes to take effect on the
/// backing storage atomically. Conceptually, the preparation of a
/// [`Transaction`](Self::Transaction) in its
/// pre-[commit](Self::commit_transaction) phase is considered a sequence of
/// mere read-only operations.
///
/// Due to the nature of the asynchronous execution model, it's always possible
/// that a sequence of read operations from one thread runs concurrently to a
/// [`Transaction`](Self::Transaction) [commit](Self::commit_transaction) from
/// another one, which might render some of the prior reads obsolete. As
/// (external) locking schemes are inherently susceptible to lock holding
/// threads "loosing interest" and not making any further progress, which might
/// or might not be an actual issue for a given target execution environment, a
/// retry mechanism in the form of "consistent read sequences" is implemented
/// instead.
///
/// Users of the `NvFs` API seeking to maintain consistency across multiple read
/// operations would initiate a
/// [`ConsistentReadSequence`](Self::ConsistentReadSequence)
/// via [`start_read_sequence()`](Self::start_read_sequence) and pass the
/// obtained handle to any subsequent read primitive to be included in the
/// consistency chain. If some [`Transaction`](Self::Transaction) gets
/// [committed](Self::commit_transaction) concurrently after the
/// [`ConsistentReadSequence`](Self::ConsistentReadSequence) had been started,
/// the read sequence will become "stale". Once that happens, any pending
/// or future `NvFs` read primitive operating on the now broken
/// [`ConsistentReadSequence`](Self::ConsistentReadSequence) will return an
/// error of [`NvFsError::Retry`].
///
/// A [`Transaction`](Self::Transaction) in its
/// pre-[commit](Self::commit_transaction) preparation phase is implicitly
/// considered a "consistent read sequence" itself: it either begins at the
/// corresponding [`start_transaction()`](Self::start_transaction) or may even
/// extend further back by continuing on a previously created
/// [`ConsistentReadSequence`](Self::ConsistentReadSequence) specified to the
/// [`start_transaction()`](Self::start_transaction). In particular, a
/// [`Transaction`](Self::Transaction) [commit](Self::commit_transaction) would
/// always invalidate all other pending [`Transaction`](Self::Transaction)s
/// currently still in their pre-commit preparation phase. For clarity: this
/// means that only one out of a set of concurrently prepared
/// [`Transaction`](Self::Transaction)s
/// can get [committed](Self::commit_transaction) successfully, all other would
/// fail with [`NvFsError::Retry`] at some point.
///
/// For any `NvFs` read primitive, it is possible to read either the state as
/// last committed to storage, or, alternatively, through a
/// [`Transaction`](Self::Transaction) still under preparation for reading the
/// state as if that transaction had been committed at the current point. Users
/// specify the desired context to the respective read primitive by passing a
/// [`NvFsReadContext`]. For the [`Transaction`](Self::Transaction) case,
/// the read primitives assume exclusive ownership of the
/// [`Transaction`](Self::Transaction), as wrapped in a [`NvFsReadContext`].
/// On completion, the [`NvFsReadContext`] instance will get returned back,
/// from which the [`Transaction`](Self::Transaction) may then get recovered.
///
/// ## Robustness against abandoned [committing](Self::commit_transaction) tasks
///
/// For some `async` execution environments it might, depending on their task
/// model, be possible that a task gets abandoned at some point and never polled
/// again. This is potentially problematic for tasks that issued a
/// [`Transaction`](Self::Transaction) [commit](Self::commit_transaction),
/// but cease to drive progress on the associated
/// [`CommitTransactionFut`](Self::CommitTransactionFut) through
/// [polling](NvFsFuture::poll) at some point: as that could prohibit the
/// initiation of any further
/// [`ConsistentReadSequence`](Self::ConsistentReadSequence) or
/// [`Transaction`](Self::Transaction), it would effectively render the `NvFs`
/// instance  unusable for forever.
///
/// Any `NvFs` implementation possibly deployed in such an `async` execution
/// environment must have provisisons in place so that this scenario cannot
/// happen. A possible solution is to let
/// [`StartReadSequenceFut`](Self::StartReadSequenceFut) and
/// [`StartTransactionFut`](Self::StartTransactionFut) "help out" behind the
/// scenes and collectively take over the polling of a currently pending
/// [`CommitTransactionFut`](Self::CommitTransactionFut), if any.
///
/// ## Write failure tolerance
///
/// Writes to the underlying storage can fail at any time. For example, if the
/// physical storage is attached over a network, it might become temporarily
/// unreachable. Note that this would become particularly relevant if the
/// underlying `NvFs` implementation happened to rely on some external trusted
/// party for rollback protection measures.
///
/// In general there are only two feasible options for a `NvFs` implementation
/// to handle write failures: report an error back to the application or retry
/// the write operation in the hope it will eventually succeed. Which action to
/// take will depend on [`Transaction`](Self::Transaction)
/// [commit](Self::commit_transaction) stage a write failure is being
/// encountered in.
///
/// It is anticipated that a `NvFs` implementation's
/// [`Transaction`](Self::Transaction) [commit](Self::commit_transaction)
/// resembles the following process:
/// 1. Journal setup
///     1. Some kind of journal is written to storage by the `NvFs`
///        implementation. This would involve writing copies of the updated data
///        to some otherwise unused storage locations and setting up some
///        metadata describing the updates.
///     2. Some flag indicating the journal is complete and to be considered
///        effective is written.
/// 2. The journal is then subsequently getting applied, i.e. all data updates
///    applied to their target location on storage.
/// 3. The journal is possibly getting cleaned up again.
///
/// ### Write failures during journal setup
///
/// Failures encountered during 1.1 are non-critical: as long as the "journal is
/// ready" flag from step 1.2 has not been written yet, any updates staged to
/// the journal wouldn't take effect after a possible power cut. Thus, for any
/// error encountered during that phase, the transaction commit can simply get
/// cancelled and the error reported back for the
/// [committer](Self::commit_transaction) to take action as appropriate, e.g. to
/// fail the associated user request and dismiss any pending updates to the
/// application state.
///
/// Failures encountered during the "journal is ready" flag write in step 1.2 on
/// the other hand are very much critical as far as consistency is concerned. If
/// that happens, the storage state is indeterminate: depending on whether the
/// flag update made it to physical storage or not, the journal could either be
/// found as being complete and thus, applicable, after a power cut or it could
/// be found in a partially written state. In the former case, the associated
/// data updates would be considered effective while in the latter case the
/// journal would get cancelled and any staged data updates dismissed.
///
/// *In either case, it is important that the application's state or the user's
/// view does not become inconsistent with what's effective on storage --
/// especially as adversaries might be able to actively provoke storage service
/// interruptions or power cuts in certain execution environments.*
///
/// There are basically two options for `NvFs` implementations to handle a write
/// failure encountered during 1.2:
/// 1. Retry until success and complete the corresponding
///    [`CommitTransactionFut`](Self::CommitTransactionFut) only afterwards.
/// 2. Attempt to cancel the journal on storage and report the
///    [`CommitTransactionFut`](Self::CommitTransactionFut) as failed to the
///    issuing application.
///
/// As it is completely unpredictable how much time it will take for the
/// underlying hardware to recover, if ever at all, it is generally favorable to
/// go with the second option, because that allows for a timely completion of
/// the [`CommitTransactionFut`](Self::CommitTransactionFut) with an error and
/// enables the issuing application to move on.
///
/// More specifically, upon encountering  a write error during step 1.2, a
/// `NvFs` implementation may choose to
/// * complete the associated
///   [`CommitTransactionFut`](Self::CommitTransactionFut) with an error,
///   informing the issuing application about the
///   [`TransactionCommitError::LogStateIndeterminate`] condition and
/// * let subsequently initiated
///   [`StartReadSequenceFut`](Self::StartReadSequenceFut)s or
///   [`StartTransactionFut`](Self::StartTransactionFut)s, if any, attempt to
///   bring the storage into a determinate state again by cancelling the journal
///   on it before proceeding any further. Note that these cannot complete
///   anyway before the storage has been brought back into a determinate state,
///   so they serve as natural entry points for journal cancellation retries --
///   chances are that enough time has passed in the meanwhile for the
///   underlying hardware to recover.
///
/// With that, the application
/// * can safely dismiss any pending updates to its internal state right away,
/// * map the [`TransactionCommitError::LogStateIndeterminate`] to some
///   application specific error code to present to the user, perhaps indicating
///   that the staged updates might possibly still become effective after a
///   potential power cut happening with no further (successful) reads or writes
///   before it,
/// * continue to use the `NvFs` functionality as usual, with any
///   [`StartReadSequenceFut`](Self::StartReadSequenceFut)s or
///   [`StartTransactionFut`](Self::StartTransactionFut)s simply failing as long
///   as the journal cancellation has not succeeded yet.
///
/// In particular, applications having a need for explictly determining the
/// underlying storage state may start "probing" [`read
/// sequences`](Self::start_read_sequence), which will succeed only once the
/// journal has been cancelled. As an alternative,
/// the convenience [`NvFs::try_cleanup_indeterminate_commit_log()`] is
/// provided.
///
/// ### Write failures during journal application
///
/// When in stage 2. or later, the updates are considered effective. A `NvFs`
/// implementation **must not** report any write failures encountered at this
/// stage back *while leaving the journal in place*, because the data updates
/// would still take effect after a power cut, thereby causing an inconsistent
/// view for the user who would have previously observed an error. As chances
/// are that a cancellation of the journal wouldn't succeed either at this
/// point, the best option a `NvFs` implementation has is to retry the journal
/// application until it succeeds. A `NvFs` implementation may choose to either
/// * keep the corresponding
///   [`CommitTransactionFut`](Self::CommitTransactionFut) pending and complete
///   it only once the journal application has eventually succeeded,
/// * or to complete it immediately with success and let subsequently initiated
///   [`StartReadSequenceFut`](Self::StartReadSequenceFut)s or
///   [`StartTransactionFut`](Self::StartTransactionFut)s, if any, take over and
///   continue with further attempts to apply the journal.
///
/// The second option is almost always preferable, because
/// * from the application's point of view the storage update has succeeded --
///   it would be perfectly fine to update any application state and continue
///   serving user requests at this point already,
/// * any subsequent [`StartReadSequenceFut`](Self::StartReadSequenceFut)s or
///   [`StartTransactionFut`](Self::StartTransactionFut)s cannot complete anyway
///   before the pending journal has been applied, so they serve as natural
///   entry points for retrying the journal application -- chances are that
///   enough time has passed in the meanwhile for the underlying storage
///   hardware to recover.
pub trait NvFs: Sized + marker::Send + marker::Sync + 'static {
    /// The [`SyncRcPtr`](sync_types::SyncRcPtr) implementation any instance of
    /// the `NvFs` implementation lives in.
    ///
    /// The concrete [`SyncRcPtr`](sync_types::SyncRcPtr) type to use is
    /// typically specified as a generic parameter to the respective `NvFs`
    /// implementation.
    type SyncRcPtr: sync_types::SyncRcPtr<Self>;

    /// Alias to [`SyncRcPtr::SyncRcPtrRef`](sync_types::SyncRcPtr::SyncRcPtrRef).
    type SyncRcPtrRef<'a>: sync_types::SyncRcPtrRef<'a, Self, Self::SyncRcPtr>;

    /// `NvFs` implementation specific type for the representation of a
    /// consistent read sequence.
    ///
    /// A `ConsistentReadSequence`, obtained from the
    /// [future](Self::StartReadSequenceFut) returned by
    /// [start_read_sequence()](Self::start_read_sequence), is used for
    /// maintaining read consistency across one or more of the `NvFs` read
    /// primitive's invocations. It enters a "stale" state once some
    /// [`Transaction`](Self::Transaction) gets
    /// [committed](Self::commit_transaction), from when on any `NvFs` read
    /// primitives operating on the `ConsistentReadSequence` would henceforth
    /// fail with an error of [`Retry`](NvFsError::Retry).
    ///
    /// Implements [`Clone`], so an arbitrary number of spawns all referring to
    /// the same consistent read sequence may be created.
    type ConsistentReadSequence: Clone + for<'a> convert::From<&'a Self::Transaction>;

    /// `NvFs` implementation specific type for representing a transaction
    /// during its preparation phase.
    ///
    /// A `Transaction`, obtained from the
    /// [future](Self::StartTransactionFut) returned by
    /// [start_transaction()](Self::start_transaction), is passed to the
    /// `NvFs`' respective write primitives for staging any desired update
    /// and eventually [committed](Self::commit_transaction) in order to
    /// take effect.
    ///
    /// A `Transaction` is implicitly considered a
    /// [`ConsistentReadSequence`](Self::ConsistentReadSequence) itself, meaning
    /// it would become obsolete once any other `Transaction` happens to get
    /// [committed](Self::commit_transaction) concurrently during its
    /// preparation phase -- any subsequent attempt to use it would fail with
    /// [`Retry`](NvFsError::Retry) in this case.
    ///
    /// Note that it is possible to request from any of the `NvFs` read
    /// primitives to read at the state the filesystem would have if a given
    /// `Transaction` had already been committed, by means of specifying it
    /// for the [`NvFsReadContext`].
    type Transaction;

    /// `NvFs` implementation specific [future](NvFsFuture) type instantiated
    /// through [`start_read_sequence()`](Self::start_read_sequence).
    type StartReadSequenceFut: NvFsFuture<Self, Output = Result<Self::ConsistentReadSequence, NvFsError>>;

    /// Start a [`ConsistentReadSequence`](Self::ConsistentReadSequence).
    ///
    /// `start_read_sequence()` returns a [future](Self::StartReadSequenceFut),
    /// which must get [polled](NvFsFuture::poll) to eventually obtain the
    /// desired [`ConsistentReadSequence`](Self::ConsistentReadSequence)
    /// instance.
    ///
    /// # Arguments:
    ///
    /// * `this` - A [`SyncRcPtrRef<Self>`](sync_types::SyncRcPtrRef) referring
    ///   to the [`SyncRcPtr<Self>`](sync_types::SyncRcPtr) managing the `NvFs`
    ///   instance.
    fn start_read_sequence(this: &Self::SyncRcPtrRef<'_>) -> Self::StartReadSequenceFut;

    /// `NvFs` implementation specific [future](NvFsFuture) type instantiated
    /// through [`start_transaction()`](Self::start_transaction).
    type StartTransactionFut: NvFsFuture<Self, Output = Result<Self::Transaction, NvFsError>>;

    /// Start a [`Transaction`](Self::Transaction).
    ///
    /// `start_transaction()` returns a [future](Self::StartTransactionFut),
    /// which must get [polled](NvFsFuture::poll) to eventually obtain the
    /// desired [`Transaction`](Self::Transaction) instance.
    ///
    /// # Arguments:
    ///
    /// * `this` - A [`SyncRcPtrRef<Self>`](sync_types::SyncRcPtrRef) referring
    ///   to the [`SyncRcPtr<Self>`](sync_types::SyncRcPtr) managing the `NvFs`
    ///   instance.
    fn start_transaction(
        this: &Self::SyncRcPtrRef<'_>,
        continued_read_sequence: Option<&Self::ConsistentReadSequence>,
        rng: Box<dyn crypto::rng::RngCoreDispatchable + marker::Send>,
    ) -> Self::StartTransactionFut;

    /// `NvFs` implementation specific [future](NvFsFuture) type instantiated
    /// through [`commit_transaction()`](Self::commit_transaction).
    type CommitTransactionFut: NvFsFuture<Self, Output = Result<(), TransactionCommitError>>;

    /// Commit a [`Transaction`](Self::Transaction).
    ///
    /// `commit_transaction()` returns a [future](Self::CommitTransactionFut),
    /// which must get [polled](NvFsFuture::poll) to eventually commit
    /// the given [`Transaction`](Self::Transaction).
    ///
    /// The operation will fail if it has been superseded by a commit of another
    /// concurrent [`Transaction`](Self::Transaction) commit since the time
    /// `transaction` was created via
    /// [`start_transaction()`](Self::start_transaction).
    ///
    /// Otherwise the specified `pre_commit_validate_cb()` callback, if any,
    /// will get invoked and the operation continued only if no error is
    /// getting returned from there. Note that the subsequent transaction
    /// commit operation can still fail, the only guarantee made is that if a
    /// commit is attempted, then `pre_commit_validate_cb()` will have been
    /// called. The intended use is to validate -- and perhaps stabilize --
    /// some application state associated with the transaction.
    ///
    /// After the `transaction` has either been successfully committed to
    /// storage or upon failure, the specified `post_commit_cb()` will get
    /// invoked with the commit result passed as an argument. Invocations of
    /// `pre_commit_validate_cb()` and `post_commit_cb()` are always
    /// symmetric, except if the former returned an error to signal
    /// cancellation. It is guaranteed that no other transaction commit
    /// *from the invoking application* will commence before completion of
    /// the `post_commit_cb()` callback. The intended use is to atomically
    /// update application state associated with the transaction on success
    /// or to "unfreeze" it on failure.
    ///
    /// If `issue_sync` is specified as `true`, the commit will not be
    /// considered complete until after a write synchronization issued on
    /// the backing storage has completed, meaning the changes have been
    /// physically written. Otherwise write order coherence is guaranteed.
    ///
    /// # Arguments:
    ///
    /// * `this` - A [`SyncRcPtrRef<Self>`](sync_types::SyncRcPtrRef) referring
    ///   to the [`SyncRcPtr<Self>`](sync_types::SyncRcPtr) managing the `NvFs`
    ///   instance.
    /// * `transaction` - The [`Transaction`](Self::Transaction) to commit.
    /// * `pre_commit_validate_cb` - The pre-commit validation to invoke if the
    ///   to be committed `transaction` is still eligible for commit, i.e. had
    ///   not been superseded by another concurrent commit in the meanwhile. May
    ///   return an error to cancel the commit process. For the `Ok` case, it is
    ///   guaranteed to be paired with a subsequent `post_commit_cb()`
    ///   invocation.
    /// * `post_commit_cb` - The post-commit callback to invoke. Always paired
    ///   with a prior `pre_commit_validate_cb()` returning success. Gets
    ///   invoked for both, successful commits as well as for failures.
    /// * `issue_sync` - Whether or not to issue a sync request to the
    ///   underlying physical storage after the commit.
    fn commit_transaction(
        this: &Self::SyncRcPtrRef<'_>,
        transaction: Self::Transaction,
        pre_commit_validate_cb: Option<PreCommitValidateCallbackType>,
        post_commit_cb: Option<PostCommitCallbackType>,
        issue_sync: bool,
    ) -> Self::CommitTransactionFut;

    /// `NvFs` implementation specific [future](NvFsFuture) type instantiated
    /// through
    /// [`try_cleanup_indeterminate_commit_log()`](Self::try_cleanup_indeterminate_commit_log).
    type TryCleanupIndeterminateCommitLogFut: NvFsFuture<Self, Output = Result<(), NvFsError>>;

    /// Convenience helper for trying to recover from a
    /// [`TransactionCommitError::LogStateIndeterminate`] failure.
    ///
    /// If a [`Transaction`](Self::Transaction) commit fails with
    /// [`TransactionCommitError::LogStateIndeterminate`], the state on
    /// physical storage is indeterminate -- it could either be the one from
    /// before the transaction or the updates staged at the transaction
    /// could possibly take effect after a remount.
    ///
    /// No further operation on the `NvFs` instance, including
    /// [starting read sequences](Self::start_read_sequence), will succeed then,
    /// until the `NvFs` implementation manages to move the filesystem back
    /// into a determinate state again, namely to the one from before the
    /// transaction.
    ///
    /// Applications may invoke the `try_cleanup_indeterminate_commit_log()`
    /// convenience function to make this process explicit.
    ///
    ///
    /// `try_cleanup_indeterminate_commit_log()` returns a
    /// [future](Self::TryCleanupIndeterminateCommitLogFut), which must get
    /// [polled](NvFsFuture::poll) to eventually return the filesystem into
    /// a determinate state if possible..
    ///
    /// # Arguments:
    ///
    /// * `this` - A [`SyncRcPtrRef<Self>`](sync_types::SyncRcPtrRef) referring
    ///   to the [`SyncRcPtr<Self>`](sync_types::SyncRcPtr) managing the `NvFs`
    ///   instance.
    fn try_cleanup_indeterminate_commit_log(this: &Self::SyncRcPtrRef<'_>)
    -> Self::TryCleanupIndeterminateCommitLogFut;

    /// `NvFs` implementation specific [future](NvFsFuture) type instantiated
    /// through [`read_inode()`](Self::read_inode).
    ///
    /// A two-level [`Result`] is returned upon [future](NvFsFuture) completion.
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering either an internal error or if the consistent read
    ///   sequence associated with the input [`NvFsReadContext`] has become
    ///   stale, in which case an error `e` of [`Retry`](NvFsError::Retry) will
    ///   be returned. The [`NvFsReadContext`] originally provided to
    ///   [`read_inode()`](Self::read_inode) is lost.
    /// * `Ok((read_context, ...))` - Otherwise the outer level [`Result`] is
    ///   set to [`Ok`] and a pair of the input [`NvFsReadContext`],
    ///   `read_context`,  and the operation result will get returned within:
    ///     * `Ok((read_context, Err(e)))` - In case of an error, the error
    ///       reason `e` is returned in an [`Err`].
    ///     * `Ok((read_context, Ok(...)))` - Otherwise an [`Option`] wrapped in
    ///       [`Ok`] is returned:
    ///         * `Ok((read_context, Ok(None)))` - The inode attempted to read
    ///           does not exist.
    ///         * `Ok((read_context, Ok(Some(data))))` - The inode exists and
    ///           its data is available as `data`.
    type ReadInodeFut: NvFsFuture<
            Self,
            Output = Result<
                (
                    NvFsReadContext<Self>,
                    Result<Option<zeroize::Zeroizing<Vec<u8>>>, NvFsError>,
                ),
                NvFsError,
            >,
        >;

    /// Read an inode's data.
    ///
    /// `read_inode()` returns a [future](Self::ReadInodeFut), which must get
    /// [polled](NvFsFuture::poll) to read and eventually return the inode's
    /// data.
    ///
    /// An optional [`NvFsReadContext`] is accepted for the `context` argument.
    /// It may be set to `Some` for specifying either a
    /// [ConsistentReadSequence](NvFsReadContext::Committed) to continue on
    /// or to some [`Transaction`](NvFsReadContext::Transaction) to read
    /// through. If `None`, a new
    /// [`ConsistentReadSequence`](Self::ConsistentReadSequence)
    /// will get [started](Self::start_read_sequence) implicitly as part of the
    /// call.
    ///
    /// # Arguments:
    ///
    /// * `this` - A [`SyncRcPtrRef<Self>`](sync_types::SyncRcPtrRef) referring
    ///   to the [`SyncRcPtr<Self>`](sync_types::SyncRcPtr) managing the `NvFs`
    ///   instance.
    /// * `context` - The optional [`NvFsReadContext`]. If `None`, a
    ///   [`ConsistentReadSequence`](Self::ConsistentReadSequence) will be
    ///   [started](Self::start_read_sequence) implicitly as part of the
    ///   operation.
    /// * `inode` - The inode whose data to read.
    fn read_inode(
        this: &Self::SyncRcPtrRef<'_>,
        context: Option<NvFsReadContext<Self>>,
        inode: u32,
    ) -> Self::ReadInodeFut;

    /// `NvFs` implementation specific [future](NvFsFuture) type instantiated
    /// through [`write_inode()`](Self::write_inode).
    ///
    /// A two-level [`Result`] is returned upon [future](NvFsFuture) completion.
    /// * `Err(e)` -  The outer level [`Result`] is set to [`Err`] upon
    ///   encountering either an internal error or if the consistent read
    ///   sequence implicit to the [`Transaction`](Self::Transaction) has become
    ///   stale, in which case an error `e` of [`Retry`](NvFsError::Retry) will
    ///   be returned. The [`Transaction`](Self::Transaction) originally
    ///   provided to [`write_inode()`](Self::write_inode) is lost.
    /// * `Ok((transaction, data, ...))` - Otherwise the outer level [`Result`]
    ///   is set to [`Ok`] and a triplet of the input
    ///   [`Transaction`](Self::Transaction), the input data buffer and the
    ///   operation result will get returned within:
    ///     * `Ok((transaction, data, Err(e)))` - In case of an error, the error
    ///       reason `e` is returned in an [`Err`].
    ///     * `Ok((transaction, data, Ok(())))` - Otherwise, `Ok(())` will get
    ///       returned for the operation result on success.
    type WriteInodeFut: NvFsFuture<
            Self,
            Output = Result<(Self::Transaction, zeroize::Zeroizing<Vec<u8>>, Result<(), NvFsError>), NvFsError>,
        >;

    /// Write an inode's data.
    ///
    /// Stage an update to `inode`'s data at `transaction`.
    ///
    /// `write_inode()` returns a [future](Self::WriteInodeFut), which must get
    /// [polled](NvFsFuture::poll) to stage the data update at `transaction` and
    /// eventually return the operation's result.
    ///
    /// If the returned [`future`](Self::WriteInodeFut) completes successfully,
    /// `inode`s data will be overwritten with `data` once `transaction`
    /// gets [committed](Self::commit_transaction). If `inode` does not
    /// exist, it will be created.
    ///
    /// Upon failure of the returned [`future`](Self::WriteInodeFut), the
    /// `inode`'s data becomes indeterminate in the context of
    /// `transaction`. Subsequent attempts to [read it through
    /// `transaction`](NvFsReadContext::Transaction) or to
    /// [commit](Self::commit_transaction) would either
    /// * result in *some* unspecified version of the `inode` data previously
    ///   written successfully, which includes prior writes staged at
    ///   `transaction` or the data as it had been committed to storage before
    ///   `transaction` was [started](Self::start_transaction),
    /// * return an error of
    ///   [`FailedDataUpdateRead`](NvFsError::FailedDataUpdateRead).
    ///
    /// Which of the two options is taken is **not** and invariant of the `NvFs`
    /// implementation, it may depend on `transaction`'s modification
    /// history and its current internal state.
    ///
    /// A subsequent successful write to or [deletion](Self::unlink_cursor) of
    /// `inode` via `transaction` will return its data back into a
    /// determinate state.
    fn write_inode(
        this: &Self::SyncRcPtrRef<'_>,
        transaction: Self::Transaction,
        inode: u32,
        data: zeroize::Zeroizing<Vec<u8>>,
    ) -> Self::WriteInodeFut;

    /// `NvFs` implementation specific [`NvFsEnumerateCursor`] type returned by
    /// [`enumerate_cursor()`](Self::enumerate_cursor).
    type EnumerateCursor: NvFsEnumerateCursor<Self>;

    /// Enumerate existing inodes within a specified range.
    ///
    /// Instantiate a [`NvFsEnumerateCursor`] for enumerating existing inodes
    /// within the (inclusive) `inodes_enumerate_range`.
    ///
    /// A [`NvFsReadContext`] is expected for the `context` argument.  It may
    /// specify either a
    /// [ConsistentReadSequence](NvFsReadContext::Committed) to continue on or
    /// to some [`Transaction`](NvFsReadContext::Transaction) to read
    /// through. On success, the returned [`NvFsEnumerateCursor`] assumes
    /// ownership of the `context`, use
    /// [`NvFsEnumerateCursor::into_context()`] to eventually obtain it back.
    ///
    /// # Arguments:
    ///
    /// * `this` - A [`SyncRcPtrRef<Self>`](sync_types::SyncRcPtrRef) referring
    ///   to the [`SyncRcPtr<Self>`](sync_types::SyncRcPtr) managing the `NvFs`
    ///   instance.
    /// * `context` - The [`NvFsReadContext`].
    /// * `inodes_enumerate_range` - The (inclusive) range to enumerate any
    ///   existing inodes in.
    ///
    /// # Return value:
    ///
    /// A two-level [`Result`] is returned.
    /// * `Err(e)` -  The outer level [`Result`] is set to [`Err`] upon
    ///   encountering either an internal error or if the consistent read
    ///   sequence associated with `context` has become stale, in which case an
    ///   error `e` of [`Retry`](NvFsError::Retry) will be returned. The
    ///   provided `context` is lost.
    /// * `Ok(...)` - Otherwise the outer level [`Result`] is set to [`Ok`]:
    ///     * `Ok(Ok(cursor))` - In case of success, the desired
    ///       [`NvFsEnumerateCursor`] instance is returned.
    ///     * `Ok(Err(context, e))` - Otherwise, a pair of the input `context`
    ///       and an error code `e` is returned.
    #[allow(clippy::type_complexity)]
    fn enumerate_cursor(
        this: &Self::SyncRcPtrRef<'_>,
        context: NvFsReadContext<Self>,
        inodes_enumerate_range: ops::RangeInclusive<u32>,
    ) -> Result<Result<Self::EnumerateCursor, (NvFsReadContext<Self>, NvFsError)>, NvFsError>;

    /// `NvFs` implementation specific [`NvFsUnlinkCursor`] type returned by
    /// [`unlink_cursor()`](Self::unlink_cursor).
    type UnlinkCursor: NvFsUnlinkCursor<Self>;

    /// Conditionally delete inodes within a specified range.
    ///
    /// Instantiate a [`NvFsUnlinkCursor`] for conditionally unlinking inodes
    /// within the (inclusive) `inodes_unlink_range`.
    ///
    /// `unlink_cursor()` does not delete any inodes by itself, that's
    /// controlled through the returned [`NvFsUnlinkCursor`].
    ///
    /// On success, the returned [`NvFsUnlinkCursor`] assumes ownership of the
    /// `transaction` for the purpose of staging the requested inode
    /// deletions to it, use [`NvFsUnlinkCursor::into_transaction()`] to
    /// eventually obtain it back.
    ///
    /// # Arguments:
    ///
    /// * `this` - A [`SyncRcPtrRef<Self>`](sync_types::SyncRcPtrRef) referring
    ///   to the [`SyncRcPtr<Self>`](sync_types::SyncRcPtr) managing the `NvFs`
    ///   instance.
    /// * `transaction` - The [`Transaction`](Self::Transaction) to stage inode
    ///   removals to.
    /// * `inodes_unlink_range` - The (inclusive) range to conditionally unlink
    ///   inodes in.
    ///
    /// # Return value:
    ///
    /// A two-level [`Result`] is returned.
    /// * `Err(e)` -  The outer level [`Result`] is set to [`Err`] upon
    ///   encountering either an internal error or if the consistent read
    ///   sequence implicit to `transaction` has become stale, in which case an
    ///   error `e` of [`Retry`](NvFsError::Retry) will be returned. The
    ///   provided `context` is lost.
    /// * `Ok(...)` - Otherwise the outer level [`Result`] is set to [`Ok`]:
    ///     * `Ok(Ok(cursor))` - In case of success, the desired
    ///       [`NvFsUnlinkCursor`] instance is returned.
    ///     * `Ok(Err(transaction, e))` - Otherwise, a pair of the input
    ///       `transaction` and an error code `e` is returned.
    #[allow(clippy::type_complexity)]
    fn unlink_cursor(
        this: &Self::SyncRcPtrRef<'_>,
        transaction: Self::Transaction,
        inodes_unlink_range: ops::RangeInclusive<u32>,
    ) -> Result<Result<Self::UnlinkCursor, (Self::Transaction, NvFsError)>, NvFsError>;
}

/// Inode enumeration cursor interface.
///
/// [`NvFs`] implementation specific instances of `NvFsEnumerateCursor` to be
/// obtained from [`NvFs::enumerate_cursor()`].
///
/// Initially the cursor points to no inode. It may be moved to the first inode
/// existing in the requested enumeration range, and subsequently to the next
/// following one each, by means of the [future](Self::NextFut) returned from
/// [`next()`](Self::next).
///
/// The current inode at point, if any, may be read through
/// [`read_current_inode_data()`](Self::read_current_inode_data). When
/// enumerating through a [`Transaction`](NvFsReadContext::Transaction),
/// there is no alternative, as the cursor assumes exclusive ownership on it for
/// the duration of its lifetime. When reading the state as committed to
/// storage, i.e. through a
/// [`ConsistentReadSequence`](NvFsReadContext::Committed), preferring
/// [`read_current_inode_data()`](Self::read_current_inode_data) over
/// [`NvFs::read_inode()`] is still advisable, as it may safe some metadata
/// lookups.
///
/// The future returned from [`next()`](Self::next) as well as the one from
/// [`read_current_inode_data(`)](Self::read_current_inode_data`) both assume
/// ownership of the cursor for the duration of the operation and eventually
/// return it back when done.
pub trait NvFsEnumerateCursor<FS: NvFs>: Sized {
    /// Obtain the [`NvFsReadContext`] back.
    ///
    /// Obtain the `context` originally passed to [`NvFs::enumerate_cursor()`]
    /// back. In particular this can be used for recovering a
    /// [`Transaction`](NvFs::Transaction) when reading through one.
    fn into_context(self) -> Result<NvFsReadContext<FS>, NvFsError>;

    /// `NvFs` implementation specific [future](NvFsFuture) type instantiated
    /// through [`next()`](Self::next).
    ///
    /// A two-level [`Result`] is returned upon [future](NvFsFuture) completion.
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering either an internal error or if the consistent read
    ///   sequence associated with the [`NvFsEnumerateCursor`]'s
    ///   [`NvFsReadContext`] has become stale, in which case an error `e` of
    ///   [`Retry`](NvFsError::Retry) will be returned. The
    ///   [`NvFsEnumerateCursor`], and hence the[`NvFsReadContext`] originally
    ///   provided to [`NvFs::enumerate_cursor()`] is lost.
    /// * `Ok((cursor, ...))` - Otherwise the outer level [`Result`] is set to
    ///   [`Ok`] and a pair of the input [`NvFsEnumerateCursor`], `cursor`,  and
    ///   the operation result will get returned within:
    ///     * `Ok((cursor, Err(e)))` - In case of an error, the error reason `e`
    ///       is returned in an [`Err`].
    ///     * `Ok((cursor, Ok(...)))` - Otherwise an [`Option`] wrapped in
    ///       [`Ok`] is returned:
    ///         * `Ok((cursor, Ok(None)))` - No further inodes exist in the
    ///           specified enumeration range.
    ///         * `Ok((cursor, Ok(Some(inode))))` - The next inode existing in
    ///           the specified enumeration range has number `inode`.
    type NextFut: NvFsFuture<FS, Output = Result<(Self, Result<Option<u32>, NvFsError>), NvFsError>>;

    /// Move the cursor to the next existing inode in the enumeration range.
    ///
    /// The returned [future](Self::NextFut) must get polled in order to obtain
    /// the next inode existing in the enumeration range. It assumes
    /// ownership of the cursor for the duration of the operation and
    /// eventually returns it back when done.
    fn next(self) -> Self::NextFut;

    /// `NvFs` implementation specific [future](NvFsFuture) type instantiated
    /// through [`read_current_inode_data()`](Self::read_current_inode_data).
    ///
    /// A two-level [`Result`] is returned upon [future](NvFsFuture) completion.
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering either an internal error or if the consistent read
    ///   sequence associated with the [`NvFsEnumerateCursor`]'s
    ///   [`NvFsReadContext`] has become stale, in which case an error `e` of
    ///   [`Retry`](NvFsError::Retry) will be returned. The
    ///   [`NvFsEnumerateCursor`], and hence the[`NvFsReadContext`] originally
    ///   provided to [`NvFs::enumerate_cursor()`] is lost.
    /// * `Ok((cursor, ...))` - Otherwise the outer level [`Result`] is set to
    ///   [`Ok`] and a pair of the input [`NvFsEnumerateCursor`], `cursor`,  and
    ///   the operation result will get returned within:
    ///     * `Ok((cursor, Err(e)))` - In case of an error, the error reason `e`
    ///       is returned in an [`Err`].
    ///     * `Ok((cursor, Ok(data)))` - Otherwise the inode `data` is returned.
    type ReadInodeDataFut: NvFsFuture<FS, Output = Result<(Self, Result<zeroize::Zeroizing<Vec<u8>>, NvFsError>), NvFsError>>;

    /// Read the inode at point.
    ///
    /// The returned [future](Self::ReadInodeDataFut) must get polled in order
    /// to obtain the inode data. It assumes ownership of the cursor for the
    /// duration of the operation and eventually returns it back when done.
    ///
    /// The cursor must currently point to some inode, i.e.
    /// [`next()`](Self::next) must have been invoked at least once
    /// and its most recent invocation did succeed with a result of `Some`.
    fn read_current_inode_data(self) -> Self::ReadInodeDataFut;
}

/// Inode deletion cursor interface.
///
/// [`NvFs`] implementation specific instances of `NvFsUnlinkCursor` to be
/// obtained from [`NvFs::unlink_cursor()`].
///
/// Initially the cursor points to no inode. It may be moved to the first inode
/// existing in the requested unlinking range, and subsequently to the next
/// following one each, by means of the [future](Self::NextFut) returned from
/// [`next()`](Self::next).
///
/// The inode at point may get staged for unlinking at the associated
/// [`Transaction`](NvFs::Transaction) via
/// [`unlink_current_inode()`](Self::unlink_current_inode). Once completed with
/// success, the `NvFsUnlinkCursor` doesn't point to any inode anymore, but may
/// be moved to the one subsequent to the just unlinked inode within the
/// unlinking range, if any, with [next()](Self::next).
///
/// For deciding whether or not to unlink the current inode at point, an
/// examination of its data may be necessary, which may get read through
/// [`read_current_inode_data()`](Self::read_current_inode_data).
///
/// Once all desired inode unlinking operations have been staged, the associated
/// [`Transaction`](NvFs::Transaction) may get obtained back via
/// [`into_transaction`](Self::into_transaction) for accumulating further
/// modifications or [`commit`](NvFs::commit_transaction).
///
/// The futures returned from [`next()`](Self::next),
/// [`unlink_current_inode()`](Self::unlink_current_inode) as well as from
/// [`read_current_inode_data`()](Self::read_current_inode_data) all assume
/// ownership of the cursor for the duration of the operation and eventually
/// return it back when done.
pub trait NvFsUnlinkCursor<FS: NvFs>: Sized {
    /// Obtain the [`Transaction`](NvFs::Transaction) back.
    ///
    /// Obtain the `transaction` originally passed to [`NvFs::unlink_cursor()`]
    /// back.
    fn into_transaction(self) -> Result<FS::Transaction, NvFsError>;

    /// `NvFs` implementation specific [future](NvFsFuture) type instantiated
    /// through [`next()`](Self::next).
    ///
    /// A two-level [`Result`] is returned upon [future](NvFsFuture) completion.
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering either an internal error or if the consistent read
    ///   sequence implicit to the [`NvFsUnlinkCursor`]'s
    ///   [`Transaction`](NvFs::Transaction) has become stale, in which case an
    ///   error `e` of [`Retry`](NvFsError::Retry) will be returned. The
    ///   [`NvFsUnlinkCursor`], and hence the [`Transaction`](NvFs::Transaction)
    ///   originally provided to [`NvFs::unlink_cursor()`] is lost.
    /// * `Ok((cursor, ...))` - Otherwise the outer level [`Result`] is set to
    ///   [`Ok`] and a pair of the input [`NvFsUnlinkCursor`], `cursor`,  and
    ///   the operation result will get returned within:
    ///     * `Ok((cursor, Err(e)))` - In case of an error, the error reason `e`
    ///       is returned in an [`Err`].
    ///     * `Ok((cursor, Ok(...)))` - Otherwise an [`Option`] wrapped in
    ///       [`Ok`] is returned:
    ///         * `Ok((cursor, Ok(None)))` - No further inodes exist in the
    ///           specified unlinking range.
    ///         * `Ok((cursor, Ok(Some(inode))))` - The next inode existing in
    ///           the specified unlinking range has number `inode`.
    type NextFut: NvFsFuture<FS, Output = Result<(Self, Result<Option<u32>, NvFsError>), NvFsError>>;

    /// Move the cursor to the next existing inode in the unlinking range.
    ///
    /// The returned [future](Self::NextFut) must get polled in order to obtain
    /// the next inode existing in the enumeration range. It assumes
    /// ownership of the cursor for the duration of the operation and
    /// eventually returns it back when done.
    fn next(self) -> Self::NextFut;

    /// `NvFs` implementation specific [future](NvFsFuture) type instantiated
    /// through [`unlink_current_inode()`](Self::unlink_current_inode).
    ///
    /// A two-level [`Result`] is returned upon [future](NvFsFuture) completion.
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering either an internal error or if the consistent read
    ///   sequence implicit to the [`NvFsUnlinkCursor`]'s
    ///   [`Transaction`](NvFs::Transaction) has become stale, in which case an
    ///   error `e` of [`Retry`](NvFsError::Retry) will be returned. The
    ///   [`NvFsUnlinkCursor`], and hence the [`Transaction`](NvFs::Transaction)
    ///   originally provided to [`NvFs::unlink_cursor()`] is lost.
    /// * `Ok((cursor, ...))` - Otherwise the outer level [`Result`] is set to
    ///   [`Ok`] and a pair of the input [`NvFsUnlinkCursor`], `cursor`,  and
    ///   the operation result will get returned within:
    ///     * `Ok((cursor, Err(e)))` - In case of an error, the error reason `e`
    ///       is returned in an [`Err`].
    ///     * `Ok((cursor, Ok(())))` - Otherwise the inode had been staged
    ///       successfully for deletion at the `cursor`'s associated
    ///       [`Transaction`](NvFs::Transaction).
    type UnlinkInodeFut: NvFsFuture<FS, Output = Result<(Self, Result<(), NvFsError>), NvFsError>>;

    /// Unlink the inode at point.
    ///
    /// Stage the inode at point for unlinking at the cursor's associated
    /// [`Transaction`](NvFs::Transaction).
    ///
    /// The returned [future](Self::UnlinkInodeFut) must get polled in order
    /// to stage the unlinking operation. It assumes ownership of the cursor for
    /// the duration of the operation and eventually returns it back when
    /// done.
    ///
    /// The cursor must currently point to some inode, i.e.
    /// [`next()`](Self::next) must have been invoked at least once with no
    /// intermediate (successful)
    /// [`unlink_current_inode()`](Self::unlink_current_inode) since and its
    /// most recent invocation did succeed with a result of `Some`.
    ///
    /// In case the returned [future](Self::UnlinkInodeFut) happens to fail, the
    /// inode's data state becomes indeterminate in the context of the
    /// cursor's associated [`Transaction`](NvFs::Transaction). Subsequent
    /// attempts to [read it through the
    /// transaction](NvFsReadContext::Transaction)
    /// or to [commit](NvFs::commit_transaction) would either
    /// * result in *some* unspecified version of the `inode` data previously
    ///   written successfully, which includes prior writes staged at that
    ///   transaction or the data as it had been committed to storage before the
    ///   transaction was [started](NvFs::start_transaction),
    /// * return an error of
    ///   [`FailedDataUpdateRead`](NvFsError::FailedDataUpdateRead).
    ///
    /// A subsequent successful [write](NvFs::write_inode) to or deletion of the
    /// inode via the transaction currently associated with the cursor will
    /// return its data back into a determinate state.
    fn unlink_current_inode(self) -> Self::UnlinkInodeFut;

    /// `NvFs` implementation specific [future](NvFsFuture) type instantiated
    /// through [`read_current_inode_data()`](Self::read_current_inode_data).
    ///
    /// A two-level [`Result`] is returned upon [future](NvFsFuture) completion.
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering either an internal error or if the consistent read
    ///   sequence implicit to the [`NvFsUnlinkCursor`]'s
    ///   [`Transaction`](NvFs::Transaction) has become stale, in which case an
    ///   error `e` of [`Retry`](NvFsError::Retry) will be returned. The
    ///   [`NvFsUnlinkCursor`], and hence the [`Transaction`](NvFs::Transaction)
    ///   originally provided to [`NvFs::unlink_cursor()`] is lost.
    /// * `Ok((cursor, ...))` - Otherwise the outer level [`Result`] is set to
    ///   [`Ok`] and a pair of the input [`NvFsUnlinkCursor`], `cursor`,  and
    ///   the operation result will get returned within:
    ///     * `Ok((cursor, Err(e)))` - In case of an error, the error reason `e`
    ///       is returned in an [`Err`].
    ///     * `Ok((cursor, Ok(data)))` - Otherwise the inode `data` is returned.
    type ReadInodeDataFut: NvFsFuture<FS, Output = Result<(Self, Result<zeroize::Zeroizing<Vec<u8>>, NvFsError>), NvFsError>>;

    /// Read the inode at point.
    ///
    /// The returned [future](Self::ReadInodeDataFut) must get polled in order
    /// to obtain the inode data. It assumes ownership of the cursor for the
    /// duration of the operation and eventually returns it back when done.
    ///
    /// The cursor must currently point to some inode, i.e.
    /// [`next()`](Self::next) must have been invoked at least once with no
    /// intermediate (successful)
    /// [`unlink_current_inode()`](Self::unlink_current_inode) since and its
    /// most recent invocation did succeed with a result of `Some`.
    fn read_current_inode_data(self) -> Self::ReadInodeDataFut;
}

/// [`NvFsFuture`] adaptor implementing the standard [Rust
/// `Future`](future::Future) trait.
pub struct NvFsFutureAsCoreFuture<FS: NvFs, F: NvFsFuture<FS>> {
    fs_instance: FS::SyncRcPtr,
    fut: F,
}

impl<FS: NvFs, F: NvFsFuture<FS>> NvFsFutureAsCoreFuture<FS, F> {
    /// Wrap a [`NvFsFuture`] in a new [`NvFsFutureAsCoreFuture`].
    ///
    /// # Arguments:
    ///
    /// * `fs_instance` - The [`NvFs`] instance the [`NvFsFuture`] `fut` had
    ///   been obtained from.
    /// * `fut` - The [`NvFsFuture`] to wrap.
    pub fn new(fs_instance: FS::SyncRcPtr, fut: F) -> Self {
        Self { fs_instance, fut }
    }
}

impl<FS: NvFs, F: NvFsFuture<FS>> future::Future for NvFsFutureAsCoreFuture<FS, F> {
    type Output = F::Output;

    fn poll(self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        // Safe, it's just a projection pin.
        let this = unsafe { pin::Pin::into_inner_unchecked(self) };
        let fut = unsafe { pin::Pin::new_unchecked(&mut this.fut) };
        NvFsFuture::poll(fut, &FS::SyncRcPtrRef::new(&this.fs_instance), cx)
    }
}
