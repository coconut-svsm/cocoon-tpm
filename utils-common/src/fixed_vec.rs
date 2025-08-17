// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! [`FixedVec`] -- non-resizeable heap allocations with efficient memory
//! footprint.

#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

#[cfg(feature = "zeroize")]
use zeroize;

use core::{cmp, convert, fmt, iter, marker, mem, ops, ptr, slice};

#[cfg(doc)]
use alloc::vec::Vec;

/// Error type returned for [`FixedVec`] allocation failures.
#[derive(Clone, Copy, Debug)]
pub struct FixedVecMemoryAllocationFailure;

/// Error type returned by [`FixedVec::new_from_fn()`].
#[derive(Clone, Copy, Debug)]
pub enum FixedVecNewFromFnError<E: Sized> {
    /// Memory allocation failure.
    MemoryAllocationFailure,
    /// The provided initialization function returned the wrapped error.
    FnError(E),
}

impl<E: Sized> From<FixedVecMemoryAllocationFailure> for FixedVecNewFromFnError<E> {
    fn from(_value: FixedVecMemoryAllocationFailure) -> Self {
        Self::MemoryAllocationFailure
    }
}

impl From<FixedVecNewFromFnError<convert::Infallible>> for FixedVecMemoryAllocationFailure {
    fn from(value: FixedVecNewFromFnError<convert::Infallible>) -> Self {
        match value {
            FixedVecNewFromFnError::MemoryAllocationFailure => FixedVecMemoryAllocationFailure,
            FixedVecNewFromFnError::FnError(e) => match e {
                // Infallible.
            },
        }
    }
}

/// Number of least significant "tag" bits in a [`FixedVec`] heap allocation
/// pointer value reserved for encoding the length, if possible.
const PTR_TAG_BITS: u32 = 3;
/// Mask for the least significant [`PTR_TAG_BITS`] bits.
const PTR_TAG_MASK: usize = (1usize << PTR_TAG_BITS) - 1;

/// Manage heap allocations for the case that the [`FixedVec`]'s length is not
/// stored within the allocated memory.
///
/// The heap allocation's internal format differs slightly between the cases
/// that the [`FixedVec`]'s length is encoded in its pointer's tag bits or
/// within the allocated memory respectively.
///
/// `FixedVecDataWithoutLen` implements functionality related to handling the
/// former. The heap allocation simply comprises the [`FixedVec`]'s sequence of
/// `T` elements.
///
/// # See also:
///
/// * [`FixedVecDataWithLen`].
struct FixedVecDataWithoutLen<T: Sized> {
    _phantom: marker::PhantomData<fn() -> *const T>,
}

impl<T: Sized> FixedVecDataWithoutLen<T> {
    /// Allocate memory suitable for storing a sequence of `T` elements of
    /// specified length.
    ///
    /// On success, a pointer to the allocation is returned. Use
    /// [`data_ptr()`](Self::data_ptr) to obtain a pointer to the sequence
    /// of `T` elements.
    ///
    /// # Arguments:
    ///
    /// * `len` - Number of `T` elements to be stored in the [`FixedVec`].
    ///
    /// # Safety:
    ///
    /// * `T` must not be a ZST and `len` must not be zero.
    /// * On success, it's guaranteed that `len * size_of::<T>()` will not
    ///   exceed [`isize::MAX`].
    unsafe fn try_allocate(len: usize) -> Result<ptr::NonNull<u8>, FixedVecMemoryAllocationFailure> {
        debug_assert!(mem::size_of::<T>() != 0);
        debug_assert!(len != 0);
        let size = len
            .checked_mul(mem::size_of::<T>())
            .ok_or(FixedVecMemoryAllocationFailure)?;
        let align = (1usize << PTR_TAG_BITS).max(mem::align_of::<T>());
        // Note: this fails if the aligned size exceeds isize::MAX.
        let layout = alloc::alloc::Layout::from_size_align(size, align).map_err(|_| FixedVecMemoryAllocationFailure)?;
        // SAFETY: T is not a ZST and len is not zero, hence the layout has non-zero
        // size.
        let allocation_ptr = unsafe { alloc::alloc::alloc(layout) };
        if allocation_ptr.is_null() {
            return Err(FixedVecMemoryAllocationFailure);
        }
        // SAFETY: it's been checked above that the pointer is non-null.
        Ok(unsafe { ptr::NonNull::new_unchecked(allocation_ptr) })
    }

    /// Deallocate the memory.
    ///
    /// # Arguments:
    ///
    /// * `allocation_ptr` - Pointer to the memory previously obtained from
    ///   [`try_allocate()`](Self::try_allocate).
    ///
    /// # Safety:
    ///
    /// `allocation_ptr` must have been allocated by [`Self::try_allocate()`]
    /// with matching `len` and not been deallocated already.
    unsafe fn deallocate(allocation_ptr: ptr::NonNull<u8>, len: usize) {
        // No overflow checks here, they've already been passed
        // in Self::try_allocate().
        let size = len * mem::size_of::<T>();
        let align = (1usize << PTR_TAG_BITS).max(mem::align_of::<T>());
        // SAFETY: this reconstructs the very same Layout already instantiated from
        // Self::try_allocate().
        let layout = unsafe { alloc::alloc::Layout::from_size_align_unchecked(size, align) };
        // SAFETY: The reconstructed layout matches that used by Self::try_allocate()
        // when allocating the memory referenced by allocation_ptr.
        unsafe { alloc::alloc::dealloc(allocation_ptr.as_ptr(), layout) };
    }

    /// Obtain a pointer to the sequence of `T` elements within the heap
    /// allocation.
    ///
    /// # Arguments:
    ///
    /// * `allocation_ptr` - Pointer to the memory previously obtained from
    ///   [`try_allocate()`](Self::try_allocate).
    ///
    /// # Safety:
    ///
    /// * `allocation_ptr` must have been allocated by [`Self::try_allocate()`]
    ///   and not been [deallocated](Self::deallocate) yet.
    /// * The returned pointer points to the beginning of contiguously
    ///   allocated, properly aligned sequence of memory slots suitable for
    ///   storing a `T` each, of number as requested for the `len` argument
    ///   initially passed to [`Self::try_allocate()`]. The backing memory's
    ///   total size does not exceed `isize::MAX`, as per the prior
    ///   [`Self::try_allocate()`] having been successful.
    unsafe fn data_ptr(allocation_ptr: ptr::NonNull<u8>) -> ptr::NonNull<T> {
        let data_ptr = allocation_ptr.as_ptr() as *mut T;
        // SAFETY: the pointer had been NonNull on input, and still is.
        unsafe { ptr::NonNull::new_unchecked(data_ptr) }
    }
}

/// Manage heap allocations for the case that the [`FixedVec`]'s length is
/// stored within the allocated memory.
///
/// The heap allocation's internal format differs slightly between the cases
/// that the [`FixedVec`]'s length is encoded in its pointer's tag bits or
/// within the allocated memory respectively.
///
/// `FixedVecDataWithLen` implements functionality related to handling the
/// latter. The [`FixedVec`]'s length is stored first, followed by its (aligned)
/// sequence of `T` elements.
///
/// # See also:
///
/// * [`FixedVecDataWithoutLen`].
struct FixedVecDataWithLen<T: Sized> {
    _phantom: marker::PhantomData<fn() -> *const T>,
}

impl<T: Sized> FixedVecDataWithLen<T> {
    /// Allocate memory suitable for storing a sequence of `T` elements of
    /// specified length.
    ///
    /// On success, a pointer to the allocation is returned. Use
    /// [`data_ptr()`](Self::data_ptr) to obtain a pointer to the sequence
    /// of `T` elements.
    ///
    /// # Arguments:
    ///
    /// * `len` - Number of `T` elements to be stored in the [`FixedVec`].
    ///
    /// # Safety:
    ///
    /// * `T` must not be a ZST and `len` must not be zero.
    /// * On success, it's guaranteed that `len * size_of::<T>()` will not
    ///   exceed [`isize::MAX`].
    unsafe fn try_allocate(len: usize) -> Result<ptr::NonNull<u8>, FixedVecMemoryAllocationFailure> {
        debug_assert!(mem::size_of::<T>() != 0);
        debug_assert!(len != 0);
        let size = len
            .checked_mul(mem::size_of::<T>())
            .and_then(|size| size.checked_add(Self::data_offset()))
            .ok_or(FixedVecMemoryAllocationFailure)?;
        let align = (1usize << PTR_TAG_BITS)
            .max(mem::align_of::<usize>())
            .max(mem::align_of::<T>());
        // Note: this fails if the aligned size exceeds isize::MAX.
        let layout = alloc::alloc::Layout::from_size_align(size, align).map_err(|_| FixedVecMemoryAllocationFailure)?;
        // SAFETY: T is not a ZST and len is not zero, hence the layout has non-zero
        // size.
        let allocation_ptr = unsafe { alloc::alloc::alloc(layout) };
        if allocation_ptr.is_null() {
            return Err(FixedVecMemoryAllocationFailure);
        }
        // SAFETY: the memory has been layout such that there's a properly aligned usize
        // at the head.
        unsafe { (allocation_ptr as *mut usize).write(len) };
        // SAFETY: it's been checked above that the pointer is non-null.
        Ok(unsafe { ptr::NonNull::new_unchecked(allocation_ptr) })
    }

    /// Deallocate the memory.
    ///
    /// # Arguments:
    ///
    /// * `allocation_ptr` - Pointer to the memory previously obtained from
    ///   [`try_allocate()`](Self::try_allocate).
    ///
    /// # Safety:
    ///
    /// `allocation_ptr` must have been allocated by [`Self::try_allocate()`]
    /// with matching `len` and not been deallocated already.
    unsafe fn deallocate(allocation_ptr: ptr::NonNull<u8>, len: usize) {
        // No overflow checks here, they've already been passed
        // in Self::try_allocate().
        let size = len * mem::size_of::<T>() + Self::data_offset();
        let align = (1usize << PTR_TAG_BITS)
            .max(mem::align_of::<usize>())
            .max(mem::align_of::<T>());
        // SAFETY: this reconstructs the very same Layout already instantiated from
        // Self::try_allocate().
        let layout = unsafe { alloc::alloc::Layout::from_size_align_unchecked(size, align) };
        // SAFETY: The reconstructed layout matches that used by Self::try_allocate()
        // when allocating the memory referenced by allocation_ptr.
        unsafe { alloc::alloc::dealloc(allocation_ptr.as_ptr(), layout) };
    }

    /// Retrieve the [`FixedVec`] length stored within the heap allocation.
    ///
    /// # Arguments:
    ///
    /// * `allocation_ptr` - Pointer to the memory previously obtained from
    ///   [`try_allocate()`](Self::try_allocate).
    ///
    /// # Safety:
    ///
    /// `allocation_ptr` must have been allocated by [`Self::try_allocate()`]
    /// and not been [deallocated](Self::deallocate) yet.
    unsafe fn data_len(allocation_ptr: ptr::NonNull<u8>) -> usize {
        let ptr_to_len = allocation_ptr.as_ptr() as *const usize;
        // SAFETY: The allocation_ptr obtained from Self::try_allocate() points at an
        // usize at the head and has been initialized with the length value
        // there.
        unsafe { *ptr_to_len }
    }

    /// Offset of the sequence of `T` elements within the heap allocation.
    const fn data_offset() -> usize {
        assert!(mem::align_of::<T>().is_power_of_two());
        mem::size_of::<usize>() + (mem::size_of::<usize>().wrapping_neg() & (mem::align_of::<T>() - 1))
    }

    /// Obtain a pointer to the sequence of `T` elements within the heap
    /// allocation.
    ///
    /// # Arguments:
    ///
    /// * `allocation_ptr` - Pointer to the memory previously obtained from
    ///   [`try_allocate()`](Self::try_allocate).
    ///
    /// # Safety:
    ///
    /// * `allocation_ptr` must have been allocated by [`Self::try_allocate()`]
    ///   and not been [deallocated](Self::deallocate) yet.
    /// * The returned pointer points to the beginning of a contiguously
    ///   allocated, properly aligned sequence of memory slots suitable for
    ///   storing a `T` each, of number as requested for the `len` argument
    ///   initially passed to [`Self::try_allocate()`]. The backing memory's
    ///   total size does not exceed `isize::MAX`, as per the prior
    ///   [`Self::try_allocate()`] having been successful.
    unsafe fn data_ptr(allocation_ptr: ptr::NonNull<u8>) -> ptr::NonNull<T> {
        // SAFETY: stays in the bounds of the allocation, as per the layout construction
        // in Self::try_allocate().
        let data_ptr = (unsafe { allocation_ptr.as_ptr().add(Self::data_offset()) }) as *mut T;
        // SAFETY: the pointer had been NonNull on input, and still is.
        unsafe { ptr::NonNull::new_unchecked(data_ptr) }
    }
}

/// Representation of [`FixedVec::tagged_ptr`].
union FixedVecTaggedPtr {
    /// Tagged pointer to the data for non-ZST element types.
    ///
    /// If a [null pointer](ptr::null_mut), then the [`FixedVec`] is empty and
    /// no memory is allocated. Otherwise, `non_zst_tagged_ptr` is a tagged
    /// pointer, storing the tag in the least significant [`PTR_TAG_BITS`]:
    /// * If the least significant [`PTR_TAG_BITS`] are equal to
    ///   [`PTR_TAG_MASK`], i.e. the maximum possible encodable value, then the
    ///   pointer points to a memory in the [`FixedVecDataWithLen`] format, i.e.
    ///   the [`FixedVec`]'s length is stored in front of the data in the memory
    ///   allocation.
    /// * Otherwise the [`FixedVec`]'s length is a power of two, and the tag
    ///   encodes the base-2 logarithm thereof, relative to the [`FixedVec`]'s
    ///   `BASE_LEN_LOG2` generic parameter.
    non_zst_tagged_ptr: *mut u8,
    /// The [`FixedVec`] length for ZST element types.
    ///
    /// For ZST element types, no memory is ever allocated and
    /// the tagged pointer always stores the [`FixedVec`] length.
    zst_data_len: usize,
}

/// Non-resizeable heap allocations with efficient memory footprint.
///
/// In order to support resizing operations, a standard Rust [`struct Vec`](Vec)
/// is relatively large: it comprises a pointer to the heap allocation itself,
/// alongsize two [`usize`]s for the [`Vec`]'s [length](Vec::len) and
/// [capacity](Vec::capacity) each. In situations where there are many instances
/// thereof, and resizing is generally not needed, such that as for IO buffers,
/// this can incur quite some unnecessary overhead.
///
/// `FixedVec` provides a more memory efficient alternative. Resizing operations
/// are not supported, and therefore there is no notion of a capacity.
/// The `FixedVec` length `usize` is stored externally within the heap
/// allocation, except for some special values of particular relevance to the
/// intended use-cases:
/// * Either if the length is zero,
/// * or if it is a power of two, with a base-2 logarithm greater or equal to
///   the `BASE_LEN_LOG2` generic parameter, and less than some fixed bound
///   internal to the implementation, then it will get encoded into (the least
///   significant bits of) the heap pointer value.
///
/// In either case, the memory occupied by a `struct FixedVec` is always that of
/// a (thin) pointer, and by dimensioning the `BASE_LEN_LOG2` parameter properly
/// in accordance with the expected usecase, even the `FixedVec`'s length usize
/// often doesn't need to get accomodated for within the heap allocation.
pub struct FixedVec<T: Sized, const BASE_LEN_LOG2: u32> {
    /// The tagged pointer.
    ///
    /// If T is a ZST, then [`FixedVecTaggedPtr::zst_data_len`] is active.
    /// Otherwise [`FixedVecTaggedPtr::non_zst_tagged_ptr`], i.e. a tagged
    /// pointer to the heap allocation, if any, is active.
    tagged_ptr: FixedVecTaggedPtr,
    _phantom: marker::PhantomData<fn() -> *const T>,
}

impl<T: Sized, const BASE_LEN_LOG2: u32> FixedVec<T, BASE_LEN_LOG2> {
    /// Instantitate a new empty [`FixedVec`].
    pub const fn new_empty() -> Self {
        if mem::size_of::<T>() == 0 {
            Self {
                tagged_ptr: FixedVecTaggedPtr {
                    // For ZST T, the tagged_ptr's zst_data_len union field is active.
                    zst_data_len: 0,
                },
                _phantom: marker::PhantomData,
            }
        } else {
            Self {
                tagged_ptr: FixedVecTaggedPtr {
                    // For non-ZST T, the tagged_ptr's non_zst_tagged_ptr union field is active.
                    non_zst_tagged_ptr: ptr::null_mut(),
                },
                _phantom: marker::PhantomData,
            }
        }
    }

    /// Instantiate a [`FixedVec`] of specified length and initialize its
    /// elements with values produced by a provided function.
    ///
    /// Instantiate a [`FixedVec`] of length `len`, and initialize its elements
    /// with the values produced by invoking `f` with the respective element
    /// index. `f` may return an error, in which case its propagated back by
    /// means of an [`FixedVecNewFromFnError::FnError`]. Otherwise, on
    /// success of `f`, the associated [`FixedVec`] element is initialized
    /// with the returned value.
    ///
    /// # Arguments:
    ///
    /// * `len` - The number of elements the instantiated [`FixedVec`] shall
    ///   contain.
    /// * `f` - The provided element initialization function.
    pub fn new_from_fn<E: Sized, F: FnMut(usize) -> Result<T, E>>(
        len: usize,
        mut f: F,
    ) -> Result<Self, FixedVecNewFromFnError<E>> {
        let (v, data_ptr) = if mem::size_of::<T>() == 0 {
            let v = Self {
                tagged_ptr: FixedVecTaggedPtr {
                    // For ZST T, the tagged_ptr's zst_data_len union field is active.
                    zst_data_len: len,
                },
                _phantom: marker::PhantomData,
            };
            if len == 0 {
                return Ok(v);
            }
            // Don't invoke Self::drop() until all elements have been initialized.
            (mem::ManuallyDrop::new(v), ptr::NonNull::dangling())
        } else if len == 0 {
            let v = Self {
                tagged_ptr: FixedVecTaggedPtr {
                    // For non-ZST T, the tagged_ptr's non_zst_tagged_ptr union field is active.
                    non_zst_tagged_ptr: ptr::null_mut(),
                },
                _phantom: marker::PhantomData,
            };
            return Ok(v);
        } else if BASE_LEN_LOG2 < usize::BITS
            && len.is_power_of_two()
            && len >> BASE_LEN_LOG2 != 0
            && len >> BASE_LEN_LOG2 < (1usize << PTR_TAG_MASK)
        {
            // The len value qualifies for encoding in the tagged_ptr's tag.
            let ptr_tag = (len.ilog2() - BASE_LEN_LOG2) as usize;
            // SAFETY: T is not a ZST and len iz not zero.
            let untagged_ptr = unsafe { FixedVecDataWithoutLen::<T>::try_allocate(len)? };
            // SAFETY: untagged_ptr has just been obtained from
            // FixedVecDataWithoutLen::try_allocate().
            let data_ptr = unsafe { FixedVecDataWithoutLen::<T>::data_ptr(untagged_ptr) };
            let v = Self {
                tagged_ptr: FixedVecTaggedPtr {
                    // For non-ZST T, the tagged_ptr's non_zst_tagged_ptr union field is active.
                    non_zst_tagged_ptr: untagged_ptr.as_ptr().map_addr(|untagged_ptr| untagged_ptr | ptr_tag),
                },
                _phantom: marker::PhantomData,
            };
            // Don't invoke Self::drop() until all elements have been initialized.
            (mem::ManuallyDrop::new(v), data_ptr)
        } else {
            // The len value does not qualify for encoding in the tagged_ptr's tag. It must
            // get stored at the allocated memory's head.
            let ptr_tag = PTR_TAG_MASK;
            // SAFETY: T is not a ZST and len iz not zero.
            let untagged_ptr = unsafe { FixedVecDataWithLen::<T>::try_allocate(len)? };
            // SAFETY: untagged_ptr has just been obtained from
            // FixedVecDataWithLen::try_allocate().
            let data_ptr = unsafe { FixedVecDataWithLen::data_ptr(untagged_ptr) };
            let v = Self {
                // For non-ZST T, the tagged_ptr's non_zst_tagged_ptr union field is active.
                tagged_ptr: FixedVecTaggedPtr {
                    non_zst_tagged_ptr: untagged_ptr.as_ptr().map_addr(|untagged_ptr| untagged_ptr | ptr_tag),
                },
                _phantom: marker::PhantomData,
            };
            // Don't invoke Self::drop() until all elements have been initialized.
            (mem::ManuallyDrop::new(v), data_ptr)
        };

        let mut element_ptr = data_ptr;
        for i in 0..len {
            let value = match f(i) {
                Ok(value) => value,
                Err(e) => {
                    // Drop the elements initialized so far.
                    let mut element_ptr = data_ptr;
                    for _ in 0..i {
                        // SAFETY:
                        // - If T is a ZST, then data_ptr and hence element_ptr is ptr::dangling_mut(),
                        //   hence properly aligned and non-null.
                        // - Otherwise data_ptr has been obtained from either
                        //   FixedVecDataWithoutLen::data_ptr() or FixedVecDataWithLen::data_ptr() on an
                        //   allocation obtained from a prior successful
                        //   FixedVecDataWithoutLen::try_allocate() or
                        //   FixedVecDataWithLen::try_allocate() invoked with len respectively. Thus,
                        //   considering the loop bounds, element_ptr is valid for reads and writes, is
                        //   aligned and points at an initialized T.
                        unsafe { element_ptr.drop_in_place() };
                        // SAFETY: Either T is a ZST, or element_ptr never moves past the end of the
                        // allocation, as per the loop bounds.
                        element_ptr = unsafe { element_ptr.add(1) };
                    }
                    // Deallocate again.
                    if mem::size_of::<T>() != 0 {
                        // SAFETY: For non-ZST T, the tagged_ptr's non_zst_tagged_ptr union field is
                        // active.
                        let tagged_ptr = unsafe { v.tagged_ptr.non_zst_tagged_ptr };
                        let tag = tagged_ptr.addr() & PTR_TAG_MASK;
                        let untagged_ptr = tagged_ptr.map_addr(|tagged_ptr| tagged_ptr & !PTR_TAG_MASK);
                        // SAFETY: untagged_ptr is non-null as T is not a ZST and len is != 0 when here.
                        let untagged_ptr = unsafe { ptr::NonNull::new_unchecked(untagged_ptr) };
                        if tag != PTR_TAG_MASK {
                            // SAFETY: untagged_ptr has previously been obtained above from
                            // FixedVecDataWithoutLen::try_allocate() as per the tag value and not
                            // been deallocated since.
                            unsafe { FixedVecDataWithoutLen::<T>::deallocate(untagged_ptr, len) };
                        } else {
                            // SAFETY: untagged_ptr has previously been obtained above from
                            // FixedVecDataWithLen::try_allocate() as per the tag value and not been
                            // deallocated since.
                            unsafe { FixedVecDataWithLen::<T>::deallocate(untagged_ptr, len) };
                        }
                    }

                    return Err(FixedVecNewFromFnError::FnError(e));
                }
            };
            // SAFETY:
            // - If T is a ZST, then data_ptr and hence element_ptr is ptr::dangling_mut(),
            //   hence properly aligned and non-null.
            // - Otherwise data_ptr has been obtained from either
            //   FixedVecDataWithoutLen::data_ptr() or FixedVecDataWithLen::data_ptr() on an
            //   allocation obtained from a prior successful
            //   FixedVecDataWithoutLen::try_allocate() or
            //   FixedVecDataWithLen::try_allocate() invoked with len respectively. Thus,
            //   considering the loop bounds, element_ptr is valid for reads and writes and
            //   is aligned.
            unsafe { element_ptr.write(value) };
            // SAFETY: Either T is a ZST, or element_ptr never moves past the end of the
            // allocation, as per the loop bounds.
            element_ptr = unsafe { element_ptr.add(1) };
        }

        Ok(mem::ManuallyDrop::into_inner(v))
    }

    /// Returns true if the [`FixedVec`] contains no elements.
    pub fn is_empty(&self) -> bool {
        if mem::size_of::<T>() == 0 {
            // SAFETY: For ZST T, the tagged_ptr's zst_data_len union field is active.
            (unsafe { self.tagged_ptr.zst_data_len }) == 0
        } else {
            // SAFETY: For non-ZST T, the tagged_ptr's non_zst_tagged_ptr union field is
            // active.
            (unsafe { self.tagged_ptr.non_zst_tagged_ptr }).is_null()
        }
    }

    /// Returns the number of elements in the [`FixedVec`].
    pub fn len(&self) -> usize {
        if mem::size_of::<T>() == 0 {
            // SAFETY: For ZST T, the tagged_ptr's zst_data_len union field is active.
            unsafe { self.tagged_ptr.zst_data_len }
        } else {
            // SAFETY: For non-ZST T, the tagged_ptr's non_zst_tagged_ptr union field is
            // active.
            let tagged_ptr = unsafe { self.tagged_ptr.non_zst_tagged_ptr };
            if tagged_ptr.is_null() {
                0
            } else {
                let tag = tagged_ptr.addr() & PTR_TAG_MASK;
                if tag != PTR_TAG_MASK {
                    // The tag encodes the length.
                    1usize << (BASE_LEN_LOG2 + tag as u32)
                } else {
                    // The length is stored at the allocated memory's head.
                    let untagged_ptr = tagged_ptr.map_addr(|tagged_ptr| tagged_ptr & !PTR_TAG_MASK);
                    // SAFETY: If the FixedVec had been empty, then tagged_ptr would have been null
                    // in the branch condition above. As the FixedVec isn't empty, some memory must
                    // have been allocated for it, and untagged_ptr points at that.
                    let untagged_ptr = unsafe { ptr::NonNull::new_unchecked(untagged_ptr) };
                    // SAFETY: untagged_ptr has previously been obtained from
                    // FixedVecDataWithLen::try_allocate() as per the tag value and not deallocated
                    // yet because self is still alive.
                    unsafe { FixedVecDataWithLen::<T>::data_len(untagged_ptr) }
                }
            }
        }
    }

    /// Extracts a slice containing the entire [`FixedVec`].
    ///
    /// Equivalent to `&s[..]`.
    pub fn as_slice(&self) -> &[T] {
        let (data_ptr, len) = if mem::size_of::<T>() == 0 {
            // SAFETY: For ZST T, the tagged_ptr's zst_data_len union field is active.
            let len = unsafe { self.tagged_ptr.zst_data_len };
            (ptr::NonNull::dangling(), len)
        } else {
            // SAFETY: xFor non-ZST T, the tagged_ptr's non_zst_tagged_ptr union field is
            // active.
            let tagged_ptr = unsafe { self.tagged_ptr.non_zst_tagged_ptr };
            if tagged_ptr.is_null() {
                (ptr::NonNull::dangling(), 0)
            } else {
                let tag = tagged_ptr.addr() & PTR_TAG_MASK;
                let untagged_ptr = tagged_ptr.map_addr(|tagged_ptr| tagged_ptr & !PTR_TAG_MASK);
                // SAFETY: If the FixedVec had been empty, then tagged_ptr would have been null
                // in the branch condition above. As the FixedVec isn't empty,
                // some memory must have been allocated for it, and untagged_ptr
                // points at that.
                let untagged_ptr = unsafe { ptr::NonNull::new_unchecked(untagged_ptr) };
                if tag != PTR_TAG_MASK {
                    // The tag encodes the length and the memory contains only the data elements.
                    let len = 1usize << (BASE_LEN_LOG2 + tag as u32);
                    // SAFETY: untagged_ptr has previously been obtained from
                    // FixedVecDataWithoutLen::try_allocate() as per the tag value and not been
                    // deallocated yet because self is still alive.
                    let data_ptr = unsafe { FixedVecDataWithoutLen::data_ptr(untagged_ptr) };
                    (data_ptr, len)
                } else {
                    // SAFETY: untagged_ptr has previously been obtained from
                    // FixedVecDataWithLen::try_allocate() as per the tag value and not been
                    // deallocated yet because self is still alive.
                    let len = unsafe { FixedVecDataWithLen::<T>::data_len(untagged_ptr) };
                    // SAFETY: likewise.
                    let data_ptr = unsafe { FixedVecDataWithLen::data_ptr(untagged_ptr) };
                    (data_ptr, len)
                }
            }
        };

        // SAFETY:
        // - If T is a ZST or the FixedVec is empty, the data_ptr is
        //   ptr::dangling_mut().
        // - Otherwise it's been obtained from either FixedVecDataWithoutLen::data_ptr()
        //   or FixedVecDataWithLen::data_ptr() on an allocation obtained from a prior
        //   successful FixedVecDataWithoutLen::try_allocate() or
        //   FixedVecDataWithLen::try_allocate() invoked with len respectively,
        //   therefore points at the to the beginning of a contiguously allocated
        //   sequence of len properly aligned memory slots suitable for storing a `T`
        //   each, and the total memory size does not exceed `isize::MAX`. All Ts have
        //   been initialized.
        // In either case, while the constructed slice is alive, it carries a borrow on
        // self, hence is exclusive with any writes.
        unsafe { slice::from_raw_parts(data_ptr.as_ptr(), len) }
    }

    /// Extracts a mutable slice of the entire vector.
    ///
    /// Equivalent to `&mut s[..]`.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        let (data_ptr, len) = if mem::size_of::<T>() == 0 {
            // SAFETY: For ZST T, the tagged_ptr's zst_data_len union field is active.
            let len = unsafe { self.tagged_ptr.zst_data_len };
            (ptr::NonNull::dangling(), len)
        } else {
            // SAFETY: For non-ZST T, the tagged_ptr's non_zst_tagged_ptr union field is
            // active.
            let tagged_ptr = unsafe { self.tagged_ptr.non_zst_tagged_ptr };
            if tagged_ptr.is_null() {
                (ptr::NonNull::dangling(), 0)
            } else {
                let tag = tagged_ptr.addr() & PTR_TAG_MASK;
                let untagged_ptr = tagged_ptr.map_addr(|tagged_ptr| tagged_ptr & !PTR_TAG_MASK);
                // SAFETY: If the FixedVec had been empty, then tagged_ptr would have been null
                // in the branch condition above. As the FixedVec isn't empty,
                // some memory must have been allocated for it, and untagged_ptr
                // points at that.
                let untagged_ptr = unsafe { ptr::NonNull::new_unchecked(untagged_ptr) };
                if tag != PTR_TAG_MASK {
                    // The tag encodes the length and the memory contains only the data elements.
                    let len = 1usize << (BASE_LEN_LOG2 + tag as u32);
                    // SAFETY: untagged_ptr has previously been obtained from
                    // FixedVecDataWithoutLen::try_allocate() as per the tag value and not been
                    // deallocated yet because self is still alive.
                    let data_ptr = unsafe { FixedVecDataWithoutLen::data_ptr(untagged_ptr) };
                    (data_ptr, len)
                } else {
                    // SAFETY: untagged_ptr has previously been obtained from
                    // FixedVecDataWithLen::try_allocate() as per the tag value and not been
                    // deallocated yet because self is still alive.
                    let len = unsafe { FixedVecDataWithLen::<T>::data_len(untagged_ptr) };
                    // SAFETY: likewise.
                    let data_ptr = unsafe { FixedVecDataWithLen::data_ptr(untagged_ptr) };
                    (data_ptr, len)
                }
            }
        };

        // SAFETY:
        // - If T is a ZST or the FixedVec is empty, the data_ptr is
        //   ptr::dangling_mut().
        // - Otherwise it's been obtained from either FixedVecDataWithoutLen::data_ptr()
        //   or FixedVecDataWithLen::data_ptr() on an allocation obtained from a prior
        //   successful FixedVecDataWithoutLen::try_allocate() or
        //   FixedVecDataWithLen::try_allocate() invoked with len respectively,
        //   therefore points at the to the beginning of a contiguously allocated
        //   sequence of len properly aligned memory slots suitable for storing a `T`
        //   each, and the total memory size does not exceed `isize::MAX`. All Ts have
        //   been initialized.
        // In either case, while the constructed slice is alive, all accesses to the
        // backing memory will be made exclusively through it, because it
        // carries a borrow on self.
        unsafe { slice::from_raw_parts_mut(data_ptr.as_ptr(), len) }
    }
}

impl<T: Sized, const BASE_LEN_LOG2: u32> Drop for FixedVec<T, BASE_LEN_LOG2> {
    fn drop(&mut self) {
        if mem::size_of::<T>() == 0 {
            // SAFETY: For ZST T, the tagged_ptr's zst_data_len union field is active.
            let len = unsafe { self.tagged_ptr.zst_data_len };
            let data_ptr = ptr::dangling_mut::<T>();
            let mut element_ptr = data_ptr;
            for _ in 0..len {
                // SAFETY: T is a ZST, and element_ptr is ptr::dangling_mut(), so aligned and
                // non-null.
                unsafe { element_ptr.drop_in_place() };
                // SAFETY: T is a ZST, so this is a nop.
                element_ptr = unsafe { element_ptr.add(1) };
            }
        } else {
            // SAFETY: For non-ZST T, the tagged_ptr's non_zst_tagged_ptr union field is
            // active.
            let tagged_ptr = unsafe { self.tagged_ptr.non_zst_tagged_ptr };
            if !tagged_ptr.is_null() {
                let tag = tagged_ptr.addr() & PTR_TAG_MASK;
                let untagged_ptr = tagged_ptr.map_addr(|tagged_ptr| tagged_ptr & !PTR_TAG_MASK);
                // SAFETY: If the FixedVec had been empty, then tagged_ptr would have been null
                // in the branch condition above. As the FixedVec isn't empty,
                // some memory must have been allocated for it, and untagged_ptr
                // points at that.
                let untagged_ptr = unsafe { ptr::NonNull::new_unchecked(untagged_ptr) };
                let (data_ptr, len) = if tag != PTR_TAG_MASK {
                    // The tag encodes the length and the memory contains only the data elements.
                    let len = 1usize << (BASE_LEN_LOG2 + tag as u32);
                    // SAFETY: untagged_ptr has previously been obtained from
                    // FixedVecDataWithoutLen::try_allocate() as per the tag value and not been
                    // deallocated already because self is only about to get dropped now.
                    let data_ptr = unsafe { FixedVecDataWithoutLen::<T>::data_ptr(untagged_ptr) };
                    (data_ptr, len)
                } else {
                    // SAFETY: untagged_ptr has previously been obtained from
                    // FixedVecDataWithLen::try_allocate() as per the tag value and not been
                    // deallocated already because self is only about to get dropped now.
                    let len = unsafe { FixedVecDataWithLen::<T>::data_len(untagged_ptr) };
                    // SAFETY: likewise.
                    let data_ptr = unsafe { FixedVecDataWithLen::<T>::data_ptr(untagged_ptr) };
                    (data_ptr, len)
                };

                let mut element_ptr = data_ptr;
                for _ in 0..len {
                    // - SAFETY: data_ptr has been obtained from either
                    //   FixedVecDataWithoutLen::data_ptr() or FixedVecDataWithLen::data_ptr() on an
                    //   allocation obtained from a prior successful
                    //   FixedVecDataWithoutLen::try_allocate() or
                    //   FixedVecDataWithLen::try_allocate() invoked with len respectively. Thus,
                    //   considering the loop bounds, element_ptr is valid for reads and writes, is
                    //   aligned and points at an initialized T.
                    unsafe { element_ptr.drop_in_place() };
                    // SAFETY: element_ptr never moves past the end of the allocation,
                    // as per the loop bounds.
                    element_ptr = unsafe { element_ptr.add(1) };
                }

                if tag != PTR_TAG_MASK {
                    // SAFETY: untagged_ptr has previously been obtained from
                    // FixedVecDataWithoutLen::try_allocate() as per the tag value and not been
                    // deallocated already because self is only about to get dropped now.
                    unsafe { FixedVecDataWithoutLen::<T>::deallocate(untagged_ptr, len) };
                } else {
                    // SAFETY: untagged_ptr has previously been obtained from
                    // FixedVecDataWithLen::try_allocate() as per the tag value and not been
                    // deallocated already because self is only about to get dropped now.
                    unsafe { FixedVecDataWithLen::<T>::deallocate(untagged_ptr, len) };
                }
            }
        }
    }
}

impl<T: Sized + Default, const BASE_LEN_LOG2: u32> FixedVec<T, BASE_LEN_LOG2> {
    /// Instantiate a [`FixedVec`] of specified length and default-initialize
    /// its elements.
    ///
    /// Instantiate a [`FixedVec`] of length `len`, and initialize all its
    /// elements with `T::default()`.
    ///
    /// # Arguments:
    ///
    /// * `len` - The number of elements the instantiated [`FixedVec`] shall
    ///   contain.
    pub fn new_with_default(len: usize) -> Result<Self, FixedVecMemoryAllocationFailure> {
        Self::new_from_fn(len, |_| -> Result<T, convert::Infallible> { Ok(T::default()) })
            .map_err(FixedVecMemoryAllocationFailure::from)
    }
}

impl<T: Sized + Clone, const BASE_LEN_LOG2: u32> FixedVec<T, BASE_LEN_LOG2> {
    /// Instantiate a [`FixedVec`] of specified length and initialize all its
    /// elements with a given value.
    ///
    /// Instantiate a [`FixedVec`] of length `len`, and initialize its elements
    /// with `value`.
    ///
    /// # Arguments:
    ///
    /// * `len` - The number of elements the instantiated [`FixedVec`] shall
    ///   contain.
    /// * `value` - The element initialization value.
    pub fn new_with_value(len: usize, value: T) -> Result<Self, FixedVecMemoryAllocationFailure> {
        Self::new_from_fn(len, |_| -> Result<T, convert::Infallible> { Ok(value.clone()) })
            .map_err(FixedVecMemoryAllocationFailure::from)
    }
}

impl<T: Sized, const BASE_LEN_LOG2: u32> ops::Deref for FixedVec<T, BASE_LEN_LOG2> {
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<T: Sized, const BASE_LEN_LOG2: u32> ops::DerefMut for FixedVec<T, BASE_LEN_LOG2> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl<T: Sized, const BASE_LEN_LOG2: u32> convert::AsRef<[T]> for FixedVec<T, BASE_LEN_LOG2> {
    fn as_ref(&self) -> &[T] {
        self
    }
}

impl<T: Sized, const BASE_LEN_LOG2: u32> convert::AsMut<[T]> for FixedVec<T, BASE_LEN_LOG2> {
    fn as_mut(&mut self) -> &mut [T] {
        self
    }
}

impl<T: Sized, const BASE_LEN_LOG2: u32> Default for FixedVec<T, BASE_LEN_LOG2> {
    fn default() -> Self {
        Self::new_empty()
    }
}

impl<T: Sized + Clone, const BASE_LEN_LOG2: u32> Clone for FixedVec<T, BASE_LEN_LOG2> {
    fn clone(&self) -> Self {
        Self::new_from_fn(self.len(), |i| -> Result<T, convert::Infallible> {
            Ok((*self)[i].clone())
        })
        .unwrap()
    }
}

impl<'a, T: Sized + Clone, const BASE_LEN_LOG2: u32> iter::IntoIterator for &'a FixedVec<T, BASE_LEN_LOG2> {
    type Item = &'a T;
    type IntoIter = slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        (**self).iter()
    }
}

impl<'a, T: Sized + Clone, const BASE_LEN_LOG2: u32> iter::IntoIterator for &'a mut FixedVec<T, BASE_LEN_LOG2> {
    type Item = &'a mut T;
    type IntoIter = slice::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        (**self).iter_mut()
    }
}

impl<T: Sized + cmp::PartialEq, const BASE_LEN_LOG2: u32> cmp::PartialEq for FixedVec<T, BASE_LEN_LOG2> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice().eq(other.as_slice())
    }
}

impl<T: Sized + cmp::Eq, const BASE_LEN_LOG2: u32> cmp::Eq for FixedVec<T, BASE_LEN_LOG2> {}

// SAFETY: if T is Send, then so is the FixedVec.
unsafe impl<T: Sized + marker::Send, const BASE_LEN_LOG2: u32> marker::Send for FixedVec<T, BASE_LEN_LOG2> {}

// SAFETY: if T is Sync, then so is the FixedVec.
unsafe impl<T: Sized + marker::Sync, const BASE_LEN_LOG2: u32> marker::Sync for FixedVec<T, BASE_LEN_LOG2> {}

impl<T: Sized + fmt::Debug, const BASE_LEN_LOG2: u32> fmt::Debug for FixedVec<T, BASE_LEN_LOG2> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

#[cfg(feature = "zeroize")]
impl<T: Sized + zeroize::Zeroize, const BASE_LEN_LOG2: u32> zeroize::Zeroize for FixedVec<T, BASE_LEN_LOG2> {
    fn zeroize(&mut self) {
        for element in self.iter_mut() {
            element.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl<T: Sized + zeroize::ZeroizeOnDrop, const BASE_LEN_LOG2: u32> zeroize::ZeroizeOnDrop
    for FixedVec<T, BASE_LEN_LOG2>
{
}

#[cfg(test)]
fn test_one<T: Sized + Default + Clone + cmp::Eq + fmt::Debug, const BASE_LEN_LOG2: u32>(test_value: T) {
    let mut v_empty = FixedVec::<T, BASE_LEN_LOG2>::new_empty();
    assert!(v_empty.is_empty());
    assert_eq!(v_empty.len(), 0);
    assert_eq!(v_empty.iter().count(), 0);
    assert_eq!(v_empty.iter_mut().count(), 0);

    for len in [
        0usize,
        (1usize << BASE_LEN_LOG2) - 1,
        (1usize << BASE_LEN_LOG2),
        (1usize << BASE_LEN_LOG2) + 1,
        1usize << (BASE_LEN_LOG2 + PTR_TAG_MASK as u32 - 1),
        1usize << (BASE_LEN_LOG2 + PTR_TAG_MASK as u32),
        1usize << (BASE_LEN_LOG2 + PTR_TAG_MASK as u32 + 1),
    ] {
        let mut v0 = FixedVec::<T, BASE_LEN_LOG2>::new_with_default(len).unwrap();
        assert_eq!(v0.is_empty(), len == 0);
        assert_eq!(v0.len(), len);
        assert_eq!(v0.iter().count(), len);
        assert_eq!(v0.iter_mut().count(), len);
        for element in v0.iter() {
            assert_eq!(*element, T::default());
        }
        for element in v0.iter_mut() {
            *element = test_value.clone();
        }

        let mut v1 = FixedVec::<T, BASE_LEN_LOG2>::new_with_value(len, test_value.clone()).unwrap();
        assert_eq!(v1.is_empty(), len == 0);
        assert_eq!(v1.len(), len);
        assert_eq!(v1.iter().count(), len);
        assert_eq!(v1.iter_mut().count(), len);
        for element in v1.iter() {
            assert_eq!(*element, test_value.clone());
        }

        assert_eq!(v0.as_slice(), v1.as_slice());

        assert!(
            len == 0
                || matches!(
                    FixedVec::<T, BASE_LEN_LOG2>::new_from_fn(len, |i| {
                        if i != len - 1 { Ok(T::default()) } else { Err(()) }
                    },),
                    Err(FixedVecNewFromFnError::FnError(()))
                )
        );
    }
}

#[test]
fn fixed_vec_u32_0() {
    test_one::<u32, 0>(42);
}

#[test]
fn fixed_vec_u32_2() {
    test_one::<u32, 2>(42);
}

#[cfg(test)]
use core::sync;

#[cfg(test)]
static TEST_ZST_INSTANCES: sync::atomic::AtomicUsize = sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
struct TestZST;

#[cfg(test)]
impl Default for TestZST {
    fn default() -> Self {
        TEST_ZST_INSTANCES.fetch_add(1, sync::atomic::Ordering::Relaxed);
        TestZST
    }
}

#[cfg(test)]
impl Clone for TestZST {
    fn clone(&self) -> Self {
        Self::default()
    }
}

#[cfg(test)]
impl Drop for TestZST {
    fn drop(&mut self) {
        TEST_ZST_INSTANCES.fetch_sub(1, sync::atomic::Ordering::Relaxed);
    }
}

#[test]
fn fixed_vec_zst() {
    fn _fixed_vec_zst() {
        test_one::<TestZST, 0>(TestZST::default());
        test_one::<TestZST, 2>(TestZST::default());
    }
    _fixed_vec_zst();
    assert_eq!(TEST_ZST_INSTANCES.load(sync::atomic::Ordering::Relaxed), 0);
}
