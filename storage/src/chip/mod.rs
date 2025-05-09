// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Definition of the [`NvChip`] trait, a block device abstraction for
//! [`NvFs`](super::fs::NvFs) implementations to build on.

mod chunked_io_region;
pub use chunked_io_region::{
    ChunkedIoRegion, ChunkedIoRegionAlignedBlockChunksRangesIterator, ChunkedIoRegionAlignedBlocksIterator,
    ChunkedIoRegionChunkIndex, ChunkedIoRegionChunkRange, ChunkedIoRegionError,
};

use core::{marker, pin, task};

/// Error type returned by [`NvChip`] primitives.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NvChipIoError {
    /// Logic error.
    Internal,

    /// A memory allocation has failed.
    MemoryAllocationFailure,

    /// Some requested operation is not supported.
    OperationNotSupported,

    /// Read or write region out of the underlying physical storage's bounds.
    IoBlockOutOfRange,

    /// Read from a region never written to before or which had been trimmed
    /// since.
    IoBlockNotMapped,

    /// Unspecified IO failure.
    IoFailure,
}

/// Future trait implemented by all [`NvChip`] related futures.
///
/// `NvChipFuture` differs from the standard [Rust
/// `Future`](core::future::Future) only in that it takes an additional `chip`
/// argument, thereby potentially avoiding the need of creating and
/// storing additional [`SyncRcPtr`](crate::utils_async::sync_types::SyncRcPtr)
/// clones for the [`NvChip`] instance.
pub trait NvChipFuture<C: ?Sized + NvChip> {
    type Output;

    /// Poll on a [`NvChipFuture`].
    ///
    /// Completely analogous to the standard [Rust
    /// `Future::poll()`](core::future::Future::poll), except for the
    /// additional `chip` argument.
    ///
    /// # Arguments:
    ///
    /// * `chip` -The [`NvChip`] instance the [`NvChipFuture`] had been obtained
    ///   from.
    /// * `cx` - The context of an asynchronous task.
    fn poll(self: pin::Pin<&mut Self>, chip: &C, cx: &mut task::Context<'_>) -> task::Poll<Self::Output>;
}

/// Trait defining an interface to block device like storage backends for
/// [`NvFs`](super::fs::NvFs) implementations to build on.
///
/// Define primitives for querying a physical storage backend about its
/// dimensions and characteristics, as well as for reading, writing and trimming
/// contiguous, [block](Self::chip_io_block_size_128b_log2) aligned regions.
///
/// Most of the API is specified in terms of Rust `async` [`Future`] concept in
/// order to enable dependant [`NvFs`](super::fs::NvFs) implementations to
/// target a wide range of possible execution environments with different
/// characteristics.
///
/// In general, a storage backend `NvChip` implementation is tightly coupled to
/// the target `async` execution environment by nature though. `NvChip`
/// implementations may therefore assume a specific `async` executor
/// implementation to be deployed with. For example, if targetting some minimal
/// executor like [`Pollster`](https://docs.rs/pollster/latest/pollster/), it would be
/// absolutely legitimate to block the current's thread's execution for IO.
///
/// The `NvChip` methods don't in fact return [`Future`]s, but
/// [`NvChipFuture`]s. The latter differ from the former only in that they take
/// an additional `chip` argument, thereby potentially avoiding the need of
/// creating and storing additional
/// [`SyncRcPtr`](crate::utils_async::sync_types::SyncRcPtr) clones
/// for the `NvChip` instance.
///
/// # Coherence considerations
/// ## Intra-power-cycle coherence
///
/// By the very nature of the `async` execution model, there can be concurrent
/// reads and writes to overlapping regions on storage. In what follows, it is
/// assumed there's a total order on all points in time where some IO operation
/// is initiated or [polled](NvChipFuture::poll) to completion.
/// The following coherence rules apply for any sequence of operations initiated
/// from the same power cycle, in order of their priority:
///
/// * *Superseding pending writes* - Polling a [write
///   barrier](Self::WriteBarrierFuture) to completion implicitly completes all
///   pending [write](Self::WriteBarrierFuture) or [trim](Self::TrimFuture)
///   operations initiated prior to it with unspecified result. Note that this
///   only affects the aforementioned total order within a power-cycle for the
///   rules that follow, no promises are being made regarding the state of the
///   physical backing storage. Polling further on a [write](Self::WriteFuture)
///   or [trim](Self::TrimFuture) future implicitly completed this way results
///   in implementation defined behavior -- that is, it's an `unreachable()`
///   condition.
/// * *Conflicting writes* - In the absence of any [write
///   barriers](Self::write_barrier), [initiating a write](Self::write) to a
///   region overlapping with an already pending
///   [write](Self::WriteBarrierFuture) or [trim](Self::TrimFuture) not yet
///   polled to completion results in implementation defined behavior. That is,
///   it's an `unreachable()` condition.
/// * *Read-write conflicts* - Further polling on a [read
///   future](Self::ReadFuture) after a [write](Self::write) or
///   [trim](Self::trim) to some region overlapping with it has been initiated
///   results in implementation defined behavior. That is, it's an
///   `unreachable()` condition.
/// * *Write-read conflicts* - [Initiating a read](Self::read) from a region
///   overlapping with a pending [write](Self::WriteFuture) or
///   [trim](Self::TrimFuture) not yet polled to completion results in
///   implementation defined behavior. That is, it's an `unreachable()`
///   condition.
/// * *Reading from failed writes or trimmed regions* - [Initiating a
///   read](Self::read) from a region overlapping with a prior
///   [write](Self::WriteFuture) that had been completed with error, or with a
///   [trim](Self::TrimFuture) completed with either status, neither of which
///   had been superseded by a subsequent successfully completed write since,
///   results in implementation defined behavior. That is, it's an
///   `unreachable()` condition.
/// * *Cache coherence* - Reading from a region overlapping with a previous
///   [write](Self::WriteFuture) from a future polled to *successful* completion
///   by the time the read operation started, and which had not been superseded
///   by a later write to or trim of that region overlap, must return the
///   updated data from the most recent write for the overlap.
///
/// ## Inter-power-cycle coherence
///
/// Inter-power-cycle coherence concerns the order in which writes become
/// effective on physical storage. More specifically how reads after a power
/// cycling event relate to writes and trims somewhen before it.
///
/// It is assumed that the minimum unit of IO,
/// i.e. a ["Chip IO Block"](Self::chip_io_block_size_128b_log2), has the
/// following semantics:
/// * [Writes](Self::write) to or [trims](Self::trim) of one ["Chip IO
///   Block"](Self::chip_io_block_size_128b_log2) do not affect any other [Chip
///   IO Blocks](Self::chip_io_block_size_128b_log2).
/// * [Writes](Self::write) to a single [Chip IO
///   Block](Self::chip_io_block_size_128b_log2) are not necessarily atomic, but
///   -- assuming the absence of any power cycling events -- there is a point in
///   time when its physical state fully reflects the to be written state. It is
///   said that "a write becomes effective on physical storage" at that point in
///   time. Starting from when a write was initiatied up to when it possibly
///   becomes effective on physical storage, the [Chip IO
///   Block](Self::chip_io_block_size_128b_log2) "is under write". In
///   particular, if a [Chip IO Block](Self::chip_io_block_size_128b_log2) is
///   under write at the time a power cycle event happens, it remains so until
///   eventually overwritten again (or trimmed) in a later power cycle.
/// * [Trim](Self::trim) requests are at some point getting transmitted to the
///   physical storage backend, from when on they're said to have "commenced".
/// * For a single given [Chip IO Block](Self::chip_io_block_size_128b_log2),
///   there is a total order on the writes and trims. That is a given [Chip IO
///   Block](Self::chip_io_block_size_128b_log2) can be either under write, a
///   write to it may have become effective on physical storage or a trim may
///   have commenced.
/// * Reading from a [Chip IO Block](Self::chip_io_block_size_128b_log2) under
///   write results in arbitrary data to be returned.
/// * Reading from a [Chip IO Block](Self::chip_io_block_size_128b_log2) for
///   which a trim has commenced results in implementation defined behavior.
///   That is, it's an `unreachable()` condition.
/// * Power cycle events behave as if a virtual [write
///   barrier](Self::write_barrier) had been issued and polled to completion at
///   that point.
/// * A [write sync](Self::write_sync) operation has implicit write barrier
///   semantics. Furthermore, once the corresponding
///   [future](Self::WriteSyncFuture) has been polled to a successful
///   completion, it is guaranteed that any writes initiated prior to it have
///   become effective on physical storage.
/// * In the absence of any [write barrier](Self::write_barrier), writes to and
///   trims of *different* [Chip IO Block](Self::chip_io_block_size_128b_log2)
///   may become effective on physical storage or commence respectively in any
///   order.
///   - [Writes](Self::write) issued after a [write
///     barrier](Self::WriteBarrierFuture) has been polled to completion must
///     not become effective on physical storage before any
///     [writes](Self::WriteFuture) polled to completion before the [write
///     barrier request](Self::write_barrier) had been issued.
///   - [Trims](Self::trim) issued after a [write
///     barrier](Self::WriteBarrierFuture) has been polled to completion must
///     not commence before any [writes](Self::WriteFuture) polled to completion
///     before the [write barrier request](Self::write_barrier) became effective
///     on physical storage.
pub trait NvChip: marker::Unpin + marker::Send + marker::Sync + 'static {
    /// The minium IO unit guaranteed not to affect neighbouring blocks
    ///
    /// Referred to in this documentation as "Chip IO Block" size. To be
    /// returned as the base-2 logarithm of that minimum Chip IO Block size as
    /// given in units of 128 Byte multiples.
    ///
    /// In order to avoid any TOCTOU issues, an implementation must always
    /// consistently return the same value for a given [`NvChip`] instance.
    fn chip_io_block_size_128b_log2(&self) -> u32;

    /// The current size of the backing NV memory in units of [Chip IO
    /// Blocks](Self::chip_io_block_size_128b_log2).
    fn chip_io_blocks(&self) -> u64;

    /// Optimum number of [Chip IO
    /// Blocks](Self::chip_io_block_size_128b_log2) to process at
    /// once.
    ///
    /// To be returned as a base-2 logarithm of the value in units of [Chip IO
    /// blocks](Self::chip_io_block_size_128b_log2. For example, a memory-backed
    /// implementation might guarantee that writes to individual 128 Byte
    /// allocation units won't affect neighbouring data, but prefer IO to
    /// processed in units of 4K pages for performance reasons.
    ///
    /// In order to avoid any TOCTOU issues, an implementation must always
    /// consistently return the same value for a given [`NvChip`] instance.
    fn preferred_chip_io_blocks_bulk_log2(&self) -> u32;

    /// `NvChip` implementation specific [future](NvChipFuture) type
    /// instantiated through [`resize()`](Self::resize).
    type ResizeFuture: NvChipFuture<Self, Output = Result<(), NvChipIoError>>;

    /// Attempt to resize, i.e. grow or shrink, the backing storage.
    ///
    /// If unsupported, an error of [`NvChipIoError::OperationNotSupported`]
    /// shall get returned.
    ///
    /// # Arguments:
    ///
    /// * chip_io_blocks_count` - The new size, in units of [Chip IO
    ///   Blocks](Self::chip_io_block_size_128b_log2).
    fn resize(&self, chip_io_blocks_count: u64) -> Result<Self::ResizeFuture, NvChipIoError>;

    /// `NvChip` implementation specific [future](NvChipFuture) type
    /// instantiated through [`read()`](Self::read).
    ///
    /// A two-level [`Result`] is returned upon [future](NvChipFuture)
    /// completion.
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering an internal error `e`. The [`request`](NvChipReadRequest)
    ///   originally provided to [`read()`](Self::read) is lost.
    /// * `Ok((request, ...))` - Otherwise the outer level [`Result`] is set to
    ///   [`Ok`] and a pair of the input [`request`](NvChipReadRequest) and the
    ///   operation result will get returned within:
    ///     * `Ok((request, Err(e)))` - In case of an error, the error reason
    ///       `e` is returned in an [`Err`].
    ///     * `Ok((request, Ok(())))` - Otherwise, `Ok(())` will get returned
    ///       for the operation result on success.
    type ReadFuture<R: NvChipReadRequest>: NvChipFuture<Self, Output = Result<(R, Result<(), NvChipIoError>), NvChipIoError>>
        + marker::Unpin;

    /// Read data from physical storage.
    ///
    /// In order to avoid extensive allocations and data copies, the source
    /// buffer ownership is getting transferred to the
    /// [`ReadFuture`](Self::ReadFuture) in the form of a
    /// [`NvChipReadRequest`] for the duration of the operation and eventually
    /// returned back.
    ///
    /// The API interface does in principle allow for consuming the `request`,
    /// but implementations should **only ever** do so on internal error
    /// when they would have to panic otherwise: not returning the request
    /// can ultimately lead to situations where the upper layers cannot
    /// proceed any further and would have to drop into a permanent failure.
    ///
    /// # Arguments:
    ///
    /// * `request` - The [`NvChipReadRequest`] describing where to read from as
    ///   well as providing access to the destination buffers receiving the
    ///   result. The associated range is guaranteed to be
    ///   [aligned](ChunkedIoRegion::is_aligned) to [Chip IO
    ///   Blocks](Self::chip_io_block_size_128b_log2).
    #[allow(clippy::type_complexity)]
    fn read<R: NvChipReadRequest>(
        &self,
        request: R,
    ) -> Result<Result<Self::ReadFuture<R>, (R, NvChipIoError)>, NvChipIoError>;

    /// `NvChip` implementation specific [future](NvChipFuture) type
    /// instantiated through [`write()`](Self::write).
    ///
    /// A two-level [`Result`] is returned upon [future](NvChipFuture)
    /// completion.
    /// * `Err(e)` - The outer level [`Result`] is set to [`Err`] upon
    ///   encountering an internal error `e`. The
    ///   [`request`](NvChipWriteRequest) originally provided to
    ///   [`read()`](Self::read) is lost.
    /// * `Ok((request, ...))` - Otherwise the outer level [`Result`] is set to
    ///   [`Ok`] and a pair of the input [`request`](NvChipWriteRequest) and the
    ///   operation result will get returned within:
    ///     * `Ok((request, Err(e)))` - In case of an error, the error reason
    ///       `e` is returned in an [`Err`].
    ///     * `Ok((request, Ok(())))` - Otherwise, `Ok(())` will get returned
    ///       for the operation result on success.
    type WriteFuture<R: NvChipWriteRequest>: NvChipFuture<Self, Output = Result<(R, Result<(), NvChipIoError>), NvChipIoError>>
        + marker::Unpin;

    /// Write data to physical storage.
    ///
    /// In order to avoid extensive allocations and data copies, the source
    /// buffer ownership is getting transferred to the
    /// [`WriteFuture`](Self::WriteFuture) in the form of a
    /// [`NvChipWriteRequest`] for the duration of the operation and eventually
    /// returned back.
    ///
    /// The API interface does in principle allow for consuming the `request`,
    /// but implementations should **only ever** do so on internal error
    /// when they would have to panic otherwise: not returning the request
    /// can ultimately lead to situations where the upper layers cannot
    /// proceed any further and would have to drop into a permanent failure.
    ///
    /// # Arguments:
    ///
    /// * `request` - The [`NvChipWriteRequest`] describing where to write to as
    ///   well as providing access to the source buffers to take the data from.
    ///   The associated range is guaranteed to be
    ///   [aligned](ChunkedIoRegion::is_aligned) to [Chip IO
    ///   Blocks](Self::chip_io_block_size_128b_log2).
    #[allow(clippy::type_complexity)]
    fn write<R: NvChipWriteRequest>(
        &self,
        request: R,
    ) -> Result<Result<Self::WriteFuture<R>, (R, NvChipIoError)>, NvChipIoError>;

    /// `NvChip` implementation specific [future](NvChipFuture) type
    /// instantiated through [`write_barrier()`](Self::write_barrier).
    type WriteBarrierFuture: NvChipFuture<Self, Output = Result<(), NvChipIoError>> + marker::Unpin;

    /// Issue a reordering barrier for any pending writes and trims to
    /// subsequently issued ones.
    fn write_barrier(&self) -> Result<Self::WriteBarrierFuture, NvChipIoError>;

    /// `NvChip` implementation specific [future](NvChipFuture) type
    /// instantiated through [`write_sync()`](Self::write_sync).
    type WriteSyncFuture: NvChipFuture<Self, Output = Result<(), NvChipIoError>> + marker::Unpin;

    /// Sync all pending writes to the backing storage.
    fn write_sync(&self) -> Result<Self::WriteSyncFuture, NvChipIoError>;

    /// `NvChip` implementation specific [future](NvChipFuture) type
    /// instantiated through [`trim()`](Self::trim).
    type TrimFuture: NvChipFuture<Self, Output = Result<(), NvChipIoError>> + marker::Unpin;

    /// Discard a given range on physical storage.
    ///
    /// This is a hint issued by the [`NvFs`](super::fs::NvFs) implementation
    /// informing the storage device that the specified range is considered
    /// being unused from now and will never be read again without a prior
    /// write. Implementations may return
    /// [`NvChipIoError::OperationNotSupported`].
    ///
    /// # Arguments:
    ///
    /// * `chip_io_block_index` - Index of the first [Chip IO
    ///   Block](Self::chip_io_block_size_128b_log2) to discard.
    /// * `chip_io_blocks_count` - The number of [Chip IO
    ///   Blocks](Self::chip_io_block_size_128b_log2) to discard.
    fn trim(&self, chip_io_block_index: u64, chip_io_blocks_count: u64) -> Result<Self::TrimFuture, NvChipIoError>;
}

/// Trait defining the common interface to [`NvChip`] write requests to be
/// submitted to [`write()`](NvChip::write).
///
/// The `NvChipWriteRequest` interface is intended to provide a means to obtain
/// all required information about the write destination location as well as
/// access to the source data buffers in a generic way. Note that the
/// [`NvChipWriteRequest`] instance is always getting returned again one way or
/// the other out of [`write()`](NvChip::write) or the associated
/// [`WriteFuture`](NvChip::WriteFuture) respectively, enabling temporary
/// ownership transfers of any required ressources, like e.g. the source
/// buffers, for the duration of the write request.
///
/// The write request source data may be split across equally sized buffers,
/// so-called "chunks", whose layout is described alongside the physical write
/// destination location by means of the [`ChunkedIoRegion`] returned by
/// [`region()`](Self::region). The region is required to be
/// [aligned](ChunkedIoRegion::is_aligned) to the [Chip IO
/// Block](NvChip::chip_io_block_size_128b_log2) size.
///
/// Access to the chunked source buffers is provided by making the
/// [`NvChipWriteRequest`] instance indexable with [`ChunkedIoRegionChunkRange`]
/// "indices" emitted by the aforementioned
/// [`ChunkedIoRegion`]'s iterators.
pub trait NvChipWriteRequest {
    /// Return a [`ChunkedIoRegion`] describing the buffer layout as well as the
    /// physical destination of the write request.
    /// [`ChunkedIoRegionChunkRange`]s obtained from its iterators will be
    /// used to index `Self`, thereby getting access to the individual
    /// source buffers.
    fn region(&self) -> &ChunkedIoRegion;

    /// Get access to the destination buffer slice associated with a
    /// [`ChunkedIoRegionChunkRange`].
    fn get_source_buffer(&self, range: &ChunkedIoRegionChunkRange) -> Result<&[u8], NvChipIoError>;
}

/// Trait defining the common interface to [`NvChip`] read requests to be
/// submitted to [`read()`](NvChip::read).
///
/// The `NvChipReadRequest` interface is intended to provide a means to obtain
/// all required information about the read source location as well as access to
/// the destination data buffers in a generic way. Note that the
/// [`NvChipReadRequest`] instance is always getting returned again one way or
/// the other out of [`read()`](NvChip::read) or the associated
/// [`ReadFuture`](NvChip::ReadFuture) respectively, enabling temporary
/// ownership transfers of any required ressources, like e.g. the source
/// buffers, for the duration of the read request.
///
/// The read request destination memory may be split across equally sized
/// buffers, so-called "chunks", whose layout is described alongside the
/// physical read source location by means of the [`ChunkedIoRegion`] returned
/// by [`region()`](Self::region). The region is required to be
/// [aligned](ChunkedIoRegion::is_aligned) to the [Chip IO
/// Block](NvChip::chip_io_block_size_128b_log2) size.
///
/// Access to the chunked destination buffers is provided by making the
/// [`NvChipReadRequest`] instance indexable with [`ChunkedIoRegionChunkRange`]
/// "indices" emitted by the aforementioned
/// [`ChunkedIoRegion`]'s iterators.
pub trait NvChipReadRequest {
    /// Return a [`ChunkedIoRegion`] describing the buffer layout as well as the
    /// physical source of the read request.
    /// [`ChunkedIoRegionChunkRange`]s obtained from its iterators will be
    /// used to index `Self`, thereby getting access to the individual
    /// destination buffers.
    fn region(&self) -> &ChunkedIoRegion;

    /// Get access to the destination buffer slice associated with a
    /// [`ChunkedIoRegionChunkRange`].
    ///
    /// Return `None` if the read result for the `range` is to be dismissed.
    fn get_destination_buffer(&mut self, range: &ChunkedIoRegionChunkRange)
        -> Result<Option<&mut [u8]>, NvChipIoError>;
}
