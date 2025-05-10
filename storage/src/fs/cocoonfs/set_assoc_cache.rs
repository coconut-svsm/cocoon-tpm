// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`SetAssocCache`].

extern crate alloc;
use alloc::vec::Vec;

use crate::utils_common::bitmanip::BitManip as _;
use core::{array, borrow, cmp, default, sync::atomic};

/// Internal per-set state for [`SetAssocCache::reconfigure()`].
///
/// Stored inline in [`SetAssocCacheSet`] as
/// [`reconfigure_state`](SetAssocCacheSet::reconfigure_state).
#[derive(Default)]
struct SetAssocCacheReconfigureSetState {
    /// Number of remaining occupied slots not yet distributed.
    remaining_to_redistribute: u8,
    /// Number of unoccupied slots in the set.
    unoccupied_slots: u8,
    /// Whether or not the set had been visited in a given entry redistribution
    /// walk.
    visited: bool,
}

/// Cache set in a [`SetAssocCache`].
struct SetAssocCacheSet<K: cmp::Ord, T> {
    /// LRU reference matrix packed into 64 bit.
    ///
    /// For a description of the packed LRU reference matrix scheme, refer to
    /// Hacker's Delight, 2nd edition, 7-9 ("An LRU Algorithm").
    ///
    /// Unallocated slots have their corresponding 8 bit subword's bits all set.
    lru_reference_matrix: atomic::AtomicU64,
    /// Fixed number of slots storing the cache set's cached entries.
    slots: [Option<(K, T)>; 8],
    /// Permutation of the (occupied) [`slots'`](Self::slots) indices specifying
    /// entry key order.
    ///
    /// Represented as 1-based 4 bit indices packed into a 32 bit word. Unused 4
    /// bit subwords at the tail are set to zero.
    ordered_slots: u32,
    /// The set's capacity.
    ///
    /// The maximum possible set capacity is 8, but a set's capacity may be
    /// configured to be less than that.
    capacity: u8,
    /// Reconfigure state used internally by [`SetAssocCache::reconfigure()`].
    ///
    /// Storing the reconfigure state here in the unused padding area avoids
    /// some allocation at reconfigure time.
    reconfigure_state: SetAssocCacheReconfigureSetState,
}

impl<K: cmp::Ord, T> default::Default for SetAssocCacheSet<K, T> {
    fn default() -> Self {
        Self {
            lru_reference_matrix: atomic::AtomicU64::default(),
            slots: array::from_fn(|_| None),
            ordered_slots: 0,
            capacity: 0,
            reconfigure_state: SetAssocCacheReconfigureSetState::default(),
        }
    }
}

impl<K: cmp::Ord, T> SetAssocCacheSet<K, T> {
    const MAX_ASSOCIATIVITY: u32 = 8;

    /// Generate 64 bit mask with every 8th bit set, starting from the LSB.
    const fn subwords8_mask_lsb() -> u64 {
        let mut m = 0x01u64;
        m |= m << 8;
        m |= m << 16;
        m |= m << 32;
        m
    }

    /// Generate 64 bit mask with every 4th bit set, starting from the LSB.
    const fn subwords4_mask_lsb() -> u32 {
        let mut m = 0x01u32;
        m |= m << 4;
        m |= m << 8;
        m |= m << 16;
        m
    }

    /// Determine the set of zero 8-bit subwords.
    ///
    /// Return a mask with each 8-bit subword's MSB set iff the corresponding
    /// 8 bit subword in the input value equals zero.
    fn subwords8_mask_is_zero_msb(x: u64) -> u64 {
        // C.f. Hacker's Delight, 2nd edition, 6-1 ("Find First 0-Byte").
        let subwords8_mask_msb_inv = !(Self::subwords8_mask_lsb() << 7);
        let y = (x & subwords8_mask_msb_inv) + subwords8_mask_msb_inv;
        !(y | x | subwords8_mask_msb_inv)
    }

    /// Find the index of the least significant 8 bit subword with all bits
    /// unset.
    fn find_least_significant_zero_byte(x: u64) -> u32 {
        Self::subwords8_mask_is_zero_msb(x).trailing_zeros() >> 3
    }

    /// Determine the set of zero 4-bit subwords.
    ///
    /// Return a mask with each 4-bit subword's MSB set iff the corresponding
    /// 4 bit subword in the input value equals zero.
    fn subwords4_mask_is_zero_msb(x: u32) -> u32 {
        // C.f. Hacker's Delight, 2nd edition, 6-1 ("Find First 0-Byte").
        let subwords4_mask_msb_inv = !(Self::subwords4_mask_lsb() << 3);
        let y = (x & subwords4_mask_msb_inv) + subwords4_mask_msb_inv;
        !(y | x | subwords4_mask_msb_inv)
    }

    /// Find the index of the least significant 4 bit subword with all bits
    /// unset.
    fn find_least_significant_zero_nibble(x: u32) -> u32 {
        Self::subwords4_mask_is_zero_msb(x).trailing_zeros() >> 2
    }

    /// Compress 8 bit subwords individually.
    ///
    /// Compress each 8 bit subword in `x` as specified by the mask `m`. For
    /// each set bit in `m`, the bit at the corresponding position in `x`
    /// gets extracted and the set of bits extracted in each 8 bit subword
    /// get compressed to its right, i.e. towards the least significant
    /// position, back to back.
    ///
    /// For a discussion of bit compression, refer to Hacker's Delight, 2nd
    /// edition, sec. 7-4 ("Compress, or Generalized Extract").
    const fn subwords8_compress(mut x: u64, mut m: u64) -> u64 {
        // Adapted from Hacker's Delight, 2nd edition, 7-4 ("Compress, or Generalized
        // Extract") to compress within each of an u64's 8-bit subword
        // individually.
        let subwords8_mask_lsb = Self::subwords8_mask_lsb();
        x &= m;
        let mut mk = (!m << 1) & !subwords8_mask_lsb;
        let mut i = 0u32;
        while i < 3 {
            let mut subwords8_mask_psxor_shift_clear = subwords8_mask_lsb;
            let mut mp = mk ^ ((mk << 1) & !subwords8_mask_psxor_shift_clear);
            subwords8_mask_psxor_shift_clear |= subwords8_mask_psxor_shift_clear << 1;
            mp ^= (mp << 2) & !subwords8_mask_psxor_shift_clear;
            subwords8_mask_psxor_shift_clear |= subwords8_mask_psxor_shift_clear << 2;
            mp ^= (mp << 4) & !subwords8_mask_psxor_shift_clear;

            let mv = mp & m;
            m = (m ^ mv) | (mv >> (1 << i));
            let t = x & mv;
            x = (x ^ t) | (t >> (1 << i));

            mk &= !mp;
            i += 1;
        }

        x
    }

    /// Examine each 8 bit subword whether all of its bits are set.
    ///
    /// A 8 bit subword's least significant bit is set in the result iff the
    /// corresponding subword from the input had all its bits set.
    fn subwords8_mask_all_set_lsb(mut x: u64) -> u64 {
        let subwords8_mask_lsb = Self::subwords8_mask_lsb();
        x &= x >> 1;
        x &= x >> 2;
        x &= x >> 4;
        x & subwords8_mask_lsb
    }

    /// Retain bits only from 8 bit subwords which have all their bits set.
    fn subwords8_mask_all_set(x: u64) -> u64 {
        let subwords8_mask_all_set_lsb = Self::subwords8_mask_all_set_lsb(x);
        let subwords8_mask_all_set_msb = subwords8_mask_all_set_lsb << 7;
        subwords8_mask_all_set_msb | (subwords8_mask_all_set_msb - subwords8_mask_all_set_lsb)
    }

    /// Reset a slot's LRU age through a shared reference.
    ///
    /// Mark the slot identified by `slot` as most recently accessed.
    ///
    /// The `lru_reference_slot_sync()` variant involves some read-modify-write
    /// atomic operations. If a mutable reference to `Self` is available,
    /// consider using
    /// [`lru_reference_slot_locked()`](Self::lru_reference_slot_locked)
    /// instead.
    ///
    /// # Arguments:
    ///
    /// * `lru_reference_matrix` - Shared reference to
    ///   [`Self::lru_reference_matrix`].
    /// * `capacity` - Copied value of [`Self::capacity`].
    /// * `slot` - The index of the slot, relative to [`Self::slots`], whose LRU
    ///   age to reset.
    fn lru_reference_slot_sync(lru_reference_matrix: &atomic::AtomicU64, capacity: u32, slot: u32) {
        // There will be no new concurrent slot allocations without a lock, so
        // the set of unoccupied slots computed below is stable.
        let lru_reference_matrix_mask_referenced_slot = ((1u64 << capacity) - 1) << (8 * slot);
        let lru_reference_matrix_val =
            lru_reference_matrix.fetch_or(lru_reference_matrix_mask_referenced_slot, atomic::Ordering::Relaxed);
        // Don't age unoccupied slots, they shall continue to have all bits set in the
        // lru_reference_matrix.
        let lru_reference_matrix_mask_unoccupied_slots = Self::subwords8_mask_all_set(lru_reference_matrix_val);
        lru_reference_matrix.fetch_and(
            !(Self::subwords8_mask_lsb() << slot) | lru_reference_matrix_mask_unoccupied_slots,
            atomic::Ordering::Relaxed,
        );
    }

    /// Reset a slot's LRU age through an exclusive reference.
    ///
    /// Mark the slot identified by `slot` as most recently accessed.
    ///
    /// # Arguments:
    ///
    /// * `lru_reference_matrix` - Exclusive reference to
    ///   [`Self::lru_reference_matrix`].
    /// * `capacity` - Copied value of [`Self::capacity`].
    /// * `slot` - The index of the slot, relative to [`Self::slots`], whose LRU
    ///   age to reset.
    fn lru_reference_slot_locked(lru_reference_matrix: &mut atomic::AtomicU64, capacity: u32, slot: u32) {
        let mut lru_reference_matrix_val = lru_reference_matrix.load(atomic::Ordering::Relaxed);
        // The slot might have been unoccupied before. If so, clear the all-ones mask
        // encoding that.
        lru_reference_matrix_val &= !(0xff << (8 * slot));
        // Compute the set of unocuppied slots _before_ renewing the slot just further
        // down below: if the capacity is at max, it the updated slot's
        // lru_reference_matrix entry would temporarily alias with the special
        // value used for identifying  unoccpuied slots.
        let lru_reference_matrix_mask_unoccupied_slots = Self::subwords8_mask_all_set(lru_reference_matrix_val);
        // Set all bits (within the capacity) to mark the slot as the most recently used
        // one.
        let lru_reference_matrix_mask_referenced_slot = ((1u64 << capacity) - 1) << (8 * slot);
        lru_reference_matrix_val |= lru_reference_matrix_mask_referenced_slot;
        // Don't age unoccupied slots, they shall continue to have all bits set in the
        // lru_reference_matrix.
        lru_reference_matrix_val &= !(Self::subwords8_mask_lsb() << slot) | lru_reference_matrix_mask_unoccupied_slots;
        lru_reference_matrix.store(lru_reference_matrix_val, atomic::Ordering::Relaxed);
    }

    /// Mark a slot as unoccpuied in the LRU reference matrix.
    ///
    /// # Arguments:
    ///
    /// * `lru_reference_matrix` - Reference to [`Self::lru_reference_matrix`].
    /// * `slot` - The index of the slot, relative to [`Self::slots`], whose LRU
    ///   age to reset.
    fn lru_remove_slot_locked(lru_reference_matrix: &mut atomic::AtomicU64, slot: u32) {
        let mut updated_lru_reference_matrix = lru_reference_matrix.load(atomic::Ordering::Relaxed);
        // The special value of all bits set in the lru_reference_matrix identifies an
        // unoccupied slot.
        updated_lru_reference_matrix |= 0xff << (8 * slot);
        lru_reference_matrix.store(updated_lru_reference_matrix, atomic::Ordering::Relaxed);
    }

    /// Map an index into [`ordered_slots`](Self::ordered_slots) to one in
    /// [`slots`](Self::slots).
    ///
    /// If `ordered_slots_index` is not mapped, i.e. not less than
    /// [`occupied_slots_count()`](Self::occupied_slots_count), `None` is
    /// returned, otherwise the associated index into [`slots`](Self::slots)
    /// wrapped in a `Some`.
    ///
    /// # Arguments:
    ///
    /// * `ordered_slots_index` - Index into
    ///   [`ordered_slots`](Self::ordered_slots).
    fn get_ordered_slot(&self, ordered_slots_index: u32) -> Option<u32> {
        let slot = (self.ordered_slots >> (4 * ordered_slots_index)) & 0xf;
        (slot != 0).then(|| slot - 1)
    }

    /// Determine the number of slots occupied by entries in the set.
    fn occupied_slots_count(&self) -> u32 {
        Self::find_least_significant_zero_nibble(self.ordered_slots)
    }

    /// Lookup an [`ordered_slots`](Self::ordered_slots) entry by key.
    ///
    /// Determine the position within the [`ordered_slots`](Self::ordered_slots)
    /// associated with `key`. If the key associated with the entry at that
    /// point matches the queried `key` exactly, then the result is wrapped
    /// in an `Ok`, otherwise in an `Err`. In the latter case, the returned
    /// position specifies the insertion point for the `key` to be passed to
    /// [`insert_ordered_slots_entry()](Self::insert_ordered_slots_entry) if
    /// desired.
    fn lookup_ordered_slots_index<Q: borrow::Borrow<K>>(&self, key: &Q) -> Result<u32, u32> {
        let key = <Q as borrow::Borrow<K>>::borrow(key);
        if self.ordered_slots == 0 {
            return Err(0);
        }
        // Not sure a binary search on small arrays makes much sense, but well...
        let mut l = 0u32;
        let mut u = self.capacity as u32 - 1;
        while l <= u {
            let m = (l + u) / 2;
            let slot = match self.get_ordered_slot(m) {
                Some(slot) => slot,
                None => {
                    debug_assert_ne!(u, 0);
                    u = m - 1;
                    continue;
                }
            };
            match key.cmp(&self.slots[slot as usize].as_ref().unwrap().0) {
                cmp::Ordering::Equal => {
                    return Ok(m);
                }
                cmp::Ordering::Less => {
                    if m == 0 {
                        return Err(m);
                    }
                    u = m - 1;
                }
                cmp::Ordering::Greater => {
                    l = m + 1;
                }
            }
        }
        Err(l)
    }

    /// Insert an entry into the [`ordered_slots`](Self::ordered_slots) map.
    ///
    /// # Arguments:
    ///
    /// * `insertion_index` - Insertion point in
    ///   [`ordered_slots`](Self::ordered_slots).
    /// * `slot` - The index into [`slots`](Self::slots) to reference from newly
    ///   inserted [`ordered_slots`](Self::ordered_slots) entry.
    fn insert_ordered_slots_entry(ordered_slots: &mut u32, insertion_index: u32, slot: u32) {
        debug_assert!(slot < Self::MAX_ASSOCIATIVITY);
        debug_assert!(insertion_index < Self::MAX_ASSOCIATIVITY);
        *ordered_slots = ((((*ordered_slots >> (4 * insertion_index)) << 4) | (slot + 1)) << (4 * insertion_index))
            | (*ordered_slots & ((1 << (4 * insertion_index)) - 1));
    }

    /// Remove an entry from the [`ordered_slots`](Self::ordered_slots) map.
    ///
    /// # Arguments:
    ///
    /// * `removal_index` - Index of the entry in
    ///   [`ordered_slots`](Self::ordered_slots) to remove.
    fn remove_ordered_slots_entry(ordered_slots: &mut u32, removal_index: u32) {
        *ordered_slots = (((*ordered_slots >> (4 * removal_index)) >> 4) << (4 * removal_index))
            | (*ordered_slots & ((1 << (4 * removal_index)) - 1));
    }

    /// Find the entry in [`ordered_slots`](Self::ordered_slots) mapping to a
    /// given entry in [`slots`](Self::slots).
    fn reverse_lookup_ordered_slots_index(ordered_slots: u32, slot: u32) -> Option<u32> {
        debug_assert!(slot < Self::MAX_ASSOCIATIVITY);
        let subwords4_mask_lsb = Self::subwords4_mask_lsb();
        let ordered_slots_index =
            Self::find_least_significant_zero_nibble(ordered_slots ^ ((slot + 1) * subwords4_mask_lsb));
        (ordered_slots_index != Self::MAX_ASSOCIATIVITY).then_some(ordered_slots_index)
    }

    /// Lookup a cache set entry by key.
    ///
    /// Returns the index into [`slots`](Self::slots) wrapped in `Some` if
    /// there's a match or `None` otherwise.
    fn lookup_key<Q: borrow::Borrow<K>>(&self, key: &Q) -> Option<SetAssocCacheSetSlotIndex> {
        let key = <Q as borrow::Borrow<K>>::borrow(key);
        let ordered_slots_index = match self.lookup_ordered_slots_index(&key) {
            Ok(existing_ordered_index) => existing_ordered_index,
            Err(_) => return None,
        };

        let slot = self.get_ordered_slot(ordered_slots_index).unwrap();
        Some(SetAssocCacheSetSlotIndex { slot: slot as u8 })
    }

    /// Insert an entry into the cache set.
    ///
    /// If an entry matching `key` exists in the set already, then the existing
    /// entry's associated value is replaced with `value`. Otherwise a new
    /// entry for the combination of `key` and `value` gets inserted.
    ///
    /// In either case, the [`slots`](Self::slots) index of the entry for `key`
    /// gets returned in the first component of the returned pair.
    ///
    /// In case some other entry with a different associated key had to get
    /// evicted in order to free up a slot in the cache set for the new one,
    /// then that evicted entry will get returned in the second component of
    /// the returned value.
    fn insert(&mut self, key: K, value: T) -> (SetAssocCacheSetSlotIndex, Option<(K, T)>) {
        let mut ordered_slots_insertion_index = match self.lookup_ordered_slots_index(&key) {
            Ok(existing_ordered_slots_index) => {
                let slot = self.get_ordered_slot(existing_ordered_slots_index).unwrap();
                self.slots[slot as usize] = Some((key, value));
                return (SetAssocCacheSetSlotIndex { slot: slot as u8 }, None);
            }
            Err(ordered_slots_insertion_index) => ordered_slots_insertion_index,
        };

        let (slot, slot_is_unoccupied) = {
            let lru_reference_matrix = self.lru_reference_matrix.load(atomic::Ordering::Relaxed);
            let lru_reference_matrix_mask_unoccupied_slots_lsb = Self::subwords8_mask_all_set_lsb(lru_reference_matrix);
            if lru_reference_matrix_mask_unoccupied_slots_lsb != 0 {
                (
                    lru_reference_matrix_mask_unoccupied_slots_lsb.trailing_zeros() >> 3,
                    true,
                )
            } else {
                (Self::find_least_significant_zero_byte(lru_reference_matrix), false)
            }
        };
        debug_assert!(slot < self.capacity as u32);
        Self::lru_reference_slot_locked(&mut self.lru_reference_matrix, self.capacity as u32, slot);

        if !slot_is_unoccupied {
            let ordered_slots_evicted_index =
                Self::reverse_lookup_ordered_slots_index(self.ordered_slots, slot).unwrap();
            Self::remove_ordered_slots_entry(&mut self.ordered_slots, ordered_slots_evicted_index);
            if ordered_slots_insertion_index > ordered_slots_evicted_index {
                ordered_slots_insertion_index -= 1;
            }
        }
        Self::insert_ordered_slots_entry(&mut self.ordered_slots, ordered_slots_insertion_index, slot);

        let evicted = self.slots[slot as usize].replace((key, value));
        debug_assert!(slot_is_unoccupied != evicted.is_some());
        (SetAssocCacheSetSlotIndex { slot: slot as u8 }, evicted)
    }

    /// Remove a cache set entry by key.
    ///
    /// Remove the cache set entry identified by `key`, if any. If there was
    /// some, return the removed entry wrapped in a `Some`, otherwise `None`
    /// gets returned.
    fn remove_by_key<Q: borrow::Borrow<K>>(&mut self, key: &Q) -> Option<(K, T)> {
        let key = <Q as borrow::Borrow<K>>::borrow(key);
        let ordered_slots_index = match self.lookup_ordered_slots_index(&key) {
            Ok(existing_ordered_index) => existing_ordered_index,
            Err(_) => return None,
        };

        let slot = self.get_ordered_slot(ordered_slots_index).unwrap();
        Self::lru_remove_slot_locked(&mut self.lru_reference_matrix, slot);
        Self::remove_ordered_slots_entry(&mut self.ordered_slots, ordered_slots_index);
        self.slots[slot as usize].take()
    }

    /// Remove a cache set entry indentified by an index into the
    /// [`slots`](Self::slots).
    ///
    /// The `slot`'s associated [`ordered_slots`](Self::ordered_slots) index may
    /// optionally be supplied via `ordered_slots_index` if known. If not
    /// given, i.e. `None` a reverse lookup will be performed.
    ///
    /// If the cache entry set `slot` had been occupied, then the removed entry
    /// will get returned wrapped in a `Some`, `None` otherwise.
    ///
    /// # Arguments:
    ///
    /// * `slot` - Index into [`slots`](Self::slots) indentifying the entry to
    ///   remove.
    /// * `ordered_slots_index` - Optionally supplied index specifying the
    ///   [`ordered_slots`](Self::ordered_slots) entry that maps to `slot`.
    fn remove_by_slot(&mut self, slot: SetAssocCacheSetSlotIndex, ordered_slots_index: Option<u32>) -> Option<(K, T)> {
        let slot = slot.slot as u32;
        let subwords4_mask_lsb = Self::subwords4_mask_lsb();
        let ordered_slots_index = ordered_slots_index.unwrap_or_else(|| {
            Self::find_least_significant_zero_nibble(self.ordered_slots ^ ((slot + 1) * subwords4_mask_lsb))
        });
        if ordered_slots_index == Self::MAX_ASSOCIATIVITY {
            debug_assert!(self.slots[slot as usize].is_none());
            return None;
        }
        Self::lru_remove_slot_locked(&mut self.lru_reference_matrix, slot);
        Self::remove_ordered_slots_entry(&mut self.ordered_slots, ordered_slots_index);
        let removed = self.slots[slot as usize].take();
        debug_assert!(removed.is_some());
        removed
    }

    /// Shrink the cache set's [`capacity`](Self::capacity).
    ///
    /// Shrink the cache set's [`capacity`](Self::capacity) to `new_capacity`,
    /// evicting entries as needed.
    fn shrink_capacity(&mut self, new_capacity: u32) {
        debug_assert!(new_capacity <= Self::MAX_ASSOCIATIVITY);
        debug_assert!(new_capacity < self.capacity as u32);
        let subwords8_mask_lsb = Self::subwords8_mask_lsb();
        let mut lru_reference_matrix = self.lru_reference_matrix.load(atomic::Ordering::Relaxed);

        // First figure determine the least recently used slots to evict to make room.
        // Keep track of what has been marked for eviction in
        // - subwords4_mask_slot_is_evicted: the LSB is set in each niblle iff the
        //   corresponding slot is marked for eviction.
        // - subwords8_mask_all_evicted: maintain (identical) bitmasks in every of the
        //   eight 8-bit subwords with bits set therein also corresponding to to be
        //   evicted slots. This kind of reduandant mask's purpose is to  facilitate
        //   compression of the lru_reference_matrix in order to account for the evicted
        //   slots below.
        let mut subwords8_mask_all_evicted = 0;
        let mut subwords4_mask_slot_is_evicted = 0u32;
        // First "evict" the unoccuped slots.
        let mut lru_reference_matrix_mask_unoccupied_slots = Self::subwords8_mask_all_set(lru_reference_matrix);
        while self.capacity as u32 > new_capacity {
            let evicted_slot = if lru_reference_matrix_mask_unoccupied_slots != 0 {
                let unoccupied_slot = lru_reference_matrix_mask_unoccupied_slots.trailing_zeros();
                lru_reference_matrix_mask_unoccupied_slots ^= 0xffu64 << unoccupied_slot;
                unoccupied_slot >> 3
            } else {
                Self::find_least_significant_zero_byte(lru_reference_matrix)
            };
            debug_assert!(evicted_slot < Self::MAX_ASSOCIATIVITY);
            // Remember for later.
            subwords4_mask_slot_is_evicted |= 1 << (4 * evicted_slot);
            subwords8_mask_all_evicted |= subwords8_mask_lsb << evicted_slot;

            // Age the remaining slots in order to get an eviction candidate for the next
            // round, if any.
            lru_reference_matrix &= !subwords8_mask_all_evicted;
            // Temporarily set all bits to not evict again. Over the course of subsequent
            // iterations some will get cleared, but never all.
            lru_reference_matrix |= 0xff << (8 * evicted_slot);

            self.capacity -= 1;
        }
        // In each field of the LRU reference matrix retain only those bits
        // corresponding to slots not removed. Compress those to the right of
        // the 8-bit subwords each.
        lru_reference_matrix = Self::subwords8_compress(lru_reference_matrix, !subwords8_mask_all_evicted);
        // But retained unoccupied slots shall remain unoccupied. Restore their special
        // identifiation value of all-ones.
        lru_reference_matrix |= lru_reference_matrix_mask_unoccupied_slots;

        // For adjusting slot indices in order to account for the removed slots, compute
        // for each slot how many slots with a numerically smaller index are to
        // be evicted. The computation below builds on the "parallel suffix"
        // ("ps") method for accumulating the number of numerically less or
        // equal slots removed for each slot.
        let mut slots_evicted_ps_le_count = subwords4_mask_slot_is_evicted;
        slots_evicted_ps_le_count += slots_evicted_ps_le_count << 4;
        slots_evicted_ps_le_count += slots_evicted_ps_le_count << 8;
        slots_evicted_ps_le_count += slots_evicted_ps_le_count << 16;

        // Actually evict the slots, removed them from the (packed)
        // ordered_slots and lru_reference_matrix arrays, as well as drop their
        // contents. For retained slots, move their contents to the new
        // position, if any.
        let mut remaining_slots_evicted_ps_le_count = slots_evicted_ps_le_count;
        for slot in 0..Self::MAX_ASSOCIATIVITY {
            let slots_evicted_le_count = remaining_slots_evicted_ps_le_count & 0xf;
            if (subwords4_mask_slot_is_evicted & 0xf) == 0 {
                // Some slots with a numerically smaller index might have been removed.
                // Account for that and move the contents to the new position.
                self.slots[(slot - slots_evicted_le_count) as usize] = self.slots[slot as usize].take();
            } else {
                self.slots[slot as usize] = None;

                if let Some(ordered_slots_index) = Self::reverse_lookup_ordered_slots_index(self.ordered_slots, slot) {
                    Self::remove_ordered_slots_entry(&mut self.ordered_slots, ordered_slots_index);
                }

                let slot = slot + 1 - slots_evicted_le_count;
                lru_reference_matrix = (((lru_reference_matrix >> (8 * slot)) >> 8) << (8 * slot))
                    | (lru_reference_matrix & ((1 << (8 * slot)) - 1));
            }
            subwords4_mask_slot_is_evicted >>= 4;
            remaining_slots_evicted_ps_le_count >>= 4;
        }

        debug_assert_eq!(lru_reference_matrix & !u64::trailing_bits_mask(8 * new_capacity), 0);
        self.lru_reference_matrix
            .store(lru_reference_matrix, atomic::Ordering::Relaxed);

        // Adjust the slot indices in the (packed) ordered_slots array in order to
        // account for the removed slots. Rearrange the
        // slots_evicted_ps_le_count computed above to match the order
        // of the ordered_slots and apply it.
        let mut ordered_slots_evicted_le_count = 0;
        let mut i = Self::find_least_significant_zero_nibble(self.ordered_slots);
        while i > 0 {
            i -= 1;
            let ordered_slots_entry = self.get_ordered_slot(i).unwrap();
            ordered_slots_evicted_le_count <<= 4;
            ordered_slots_evicted_le_count |= (slots_evicted_ps_le_count >> (4 * ordered_slots_entry)) & 0xf;
        }
        // Apply the adjustments to each 4-bit subword.
        self.ordered_slots -= ordered_slots_evicted_le_count;

        self.capacity = new_capacity as u8;
    }

    /// Increase the cache set's [`capacity`](Self::capacity).
    ///
    /// Increase the cache set's [`capacity`](Self::capacity) to `new_capacity`.
    fn grow_capacity(&mut self, new_capacity: u32) {
        debug_assert!(new_capacity <= Self::MAX_ASSOCIATIVITY);
        debug_assert!(new_capacity > self.capacity as u32);

        // Mark the newly added slots as unoccpuied by flipping all their bits to one.
        let added_capacity = new_capacity - self.capacity as u32;
        let mut lru_reference_matrix = self.lru_reference_matrix.load(atomic::Ordering::Relaxed);
        lru_reference_matrix |= u64::trailing_bits_mask(8 * added_capacity) << (8 * self.capacity);
        self.lru_reference_matrix
            .store(lru_reference_matrix, atomic::Ordering::Relaxed);

        self.capacity = new_capacity as u8;
    }

    /// Change the cache set's [`capacity`](Self::capacity).
    ///
    /// Increase or decrease the cache set's [`capacity`](Self::capacity) to
    /// `new_capacity`. In case the capacity gets shrunken, some entries
    /// might get evicted in the course.
    fn set_capacity(&mut self, new_capacity: u32) {
        match new_capacity.cmp(&(self.capacity as u32)) {
            cmp::Ordering::Less => {
                self.shrink_capacity(new_capacity);
            }
            cmp::Ordering::Greater => {
                self.grow_capacity(new_capacity);
            }
            cmp::Ordering::Equal => (),
        }
    }

    /// Find the least recently used cache set slot.
    ///
    /// Return the [`slots`](Self::slots) index of the least recently used slot,
    /// if any. Unoccpuied slots are not considered in the search. If no
    /// slot is occupied, then `None` will get returned, otherwise the index
    /// of the least recently used slot.
    fn least_recently_used_occupied_slot(&self) -> Option<SetAssocCacheSetSlotIndex> {
        let subwords8_mask_lsb = Self::subwords8_mask_lsb();

        // The least recently used occupied slot will be the one with the fewest set
        // bits in its associated lru_reference_matrix value. Note that
        // unoccupied ones will have all their bits set, while unoccupied ones
        // will have at least one clear (the one corresponding to themselves).
        // Compress all bits to the right in each 8-bit subword.
        let lru_reference_matrix = self.lru_reference_matrix.load(atomic::Ordering::Relaxed);
        let compressed_lru_reference_matrix = Self::subwords8_compress(!0, lru_reference_matrix);

        // Now determine the shortest compressed lru_reference_matrix value, ignoring
        // the zeros.
        let mut shortest_compressed = compressed_lru_reference_matrix;
        shortest_compressed &= shortest_compressed >> 8;
        shortest_compressed &= shortest_compressed >> 16;
        shortest_compressed &= shortest_compressed >> 32;
        shortest_compressed &= 0xff;
        if shortest_compressed == 0xff {
            // All bits set for all slots, meaning all are unoccupied.
            return None;
        }

        // And find its index.
        let slot = Self::find_least_significant_zero_byte(
            compressed_lru_reference_matrix ^ (shortest_compressed * subwords8_mask_lsb),
        );
        debug_assert!(slot < Self::MAX_ASSOCIATIVITY);
        // It's unique.
        debug_assert_eq!(
            Self::find_least_significant_zero_byte(
                ((compressed_lru_reference_matrix | !u64::trailing_bits_mask(8 * (self.capacity as u32)))
                    ^ (shortest_compressed * subwords8_mask_lsb))
                    | (1u64 << (8 * slot))
            ),
            Self::MAX_ASSOCIATIVITY
        );

        Some(SetAssocCacheSetSlotIndex { slot: slot as u8 })
    }

    /// Find the cache set slot of a specific LRU age.
    ///
    /// Return the [`slots`](Self::slots) index of the slot having a specified
    /// `age`, if any. An `age` value of `0` will yield the most recently
    /// used (occupied) slot, if any , whereas an `age` value of `capacity -
    /// 1` corresponds to the maximum age the least recently used (occupied)
    /// slot could possibly have.
    ///
    /// If an occuplied slot of LRU age `age` exists, then its index will get
    /// returned wrapped in a `Some`. Otherwise, i.e. if `age` is not less
    /// than [`occupied_slots_count()`](Self::occupied_slots_count), then
    /// `None` gets returned.
    fn slot_with_age(&self, age: u32) -> Option<SetAssocCacheSetSlotIndex> {
        debug_assert!(age < Self::MAX_ASSOCIATIVITY);
        if age >= self.capacity as u32 {
            return None;
        }

        let subwords8_mask_lsb = Self::subwords8_mask_lsb();
        // The number of bits set in the lru_reference_matrix corresponds to the
        // respective associated slot entries' ages: the number of bits
        // set equals capacity - 1 - age.
        // Compress the lru_reference_matrix 8-bit-subword-wise, and
        // subsequently search for the entry with the expected number of
        // bits set.
        let lru_reference_matrix = self.lru_reference_matrix.load(atomic::Ordering::Relaxed);
        let compressed_lru_reference_matrix = Self::subwords8_compress(!0, lru_reference_matrix);
        let slot = Self::find_least_significant_zero_byte(
            compressed_lru_reference_matrix
                ^ ((subwords8_mask_lsb << (self.capacity as u32 - 1 - age)) - subwords8_mask_lsb),
        );
        // The age is unique, there should be no more than one match.
        debug_assert!(
            slot == self.capacity as u32
                || Self::find_least_significant_zero_byte(
                    (compressed_lru_reference_matrix
                        ^ ((subwords8_mask_lsb << (self.capacity as u32 - 1 - age)) - subwords8_mask_lsb))
                        | (1u64 << (8 * slot))
                ) == self.capacity as u32
        );

        (slot < self.capacity as u32).then_some(SetAssocCacheSetSlotIndex { slot: slot as u8 })
    }

    /// Evict all entries in the cache set.
    fn prune_all(&mut self) {
        for slot in self.slots.iter_mut() {
            *slot = None;
        }
        self.lru_reference_matrix.store(
            u64::trailing_bits_mask(8 * self.capacity as u32),
            atomic::Ordering::Relaxed,
        );
        self.ordered_slots = 0;
    }

    /// Conditionally evict entries from the cache set.
    ///
    /// Invoke the `cond` predicate callback on every entry in the cache set and
    /// evict those for which it returns `true`.
    fn prune_cond<C: FnMut(&K, &T) -> bool>(&mut self, cond: &mut C) {
        let mut ordered_slots_index = 0;
        while ordered_slots_index < Self::MAX_ASSOCIATIVITY {
            let ordered_slot = match self.get_ordered_slot(ordered_slots_index) {
                Some(ordered_slot) => ordered_slot,
                None => break,
            };

            let (k, v) = self.slots[ordered_slot as usize].as_ref().unwrap();
            if cond(k, v) {
                self.remove_by_slot(
                    SetAssocCacheSetSlotIndex {
                        slot: ordered_slot as u8,
                    },
                    Some(ordered_slots_index),
                );
            } else {
                ordered_slots_index += 1;
            }
        }
    }

    /// Immutable access to a cache set slot.
    ///
    /// If the supplied [`slots`](Self::slots) index refers to an unoccupied
    /// slot, return `None`. Otherwise reset the slot's LRU age and return
    /// a shared reference to its contents wrapped in `Some`.
    fn get_slot(&self, index: SetAssocCacheSetSlotIndex) -> Option<(&K, &T)> {
        let slot = index.slot as u32;
        let entry = self.slots[slot as usize].as_ref().map(|(k, v)| (k, v))?;
        Self::lru_reference_slot_sync(&self.lru_reference_matrix, self.capacity as u32, slot);
        Some(entry)
    }

    /// Mutable access to a cache set slot.
    ///
    /// If the supplied [`slots`](Self::slots) index refers to an unoccupied
    /// slot, return `None`. Otherwise reset the slot's LRU age and return
    /// a pair of a shared reference to the entry' key and a `mut` reference to
    /// the associated value.
    fn get_slot_mut(&mut self, index: SetAssocCacheSetSlotIndex) -> Option<(&K, &mut T)> {
        let slot = index.slot as u32;
        let entry = self.slots[slot as usize].as_mut().map(|(k, v)| (&*k, v))?;
        Self::lru_reference_slot_locked(&mut self.lru_reference_matrix, self.capacity as u32, slot);
        Some(entry)
    }

    /// Access a cache slot's associated key.
    ///
    /// If the supplied [`slots`](Self::slots) index refers to an unoccupied
    /// slot, return `None`. Otherwise return a reference to the cached
    /// entry's associated key.
    fn get_slot_key(&self, index: SetAssocCacheSetSlotIndex) -> Option<&K> {
        let slot = index.slot as u32;
        self.slots[slot as usize].as_ref().map(|(k, _v)| k)
    }
}

/// Typed index into [`SetAssocCacheSet::slots`].
#[derive(Clone, Copy)]
struct SetAssocCacheSetSlotIndex {
    slot: u8,
}

/// Trait for [`SetAssocCache`] maps mapping keys to their associated cache
/// sets, if any.
pub trait SetAssocCacheMapKeyToSet<K> {
    /// Map a key to a cache set to store any entry with that key in.
    ///
    /// If entries with the given `key` qualify for insertion into the cache,
    /// the associated cache set's index gets returned as wrapped in a
    /// `Some`. Otherwise, i.e. if entry's with that `key` shall not get
    /// cached, a `None` is returned.
    fn map_key(&self, key: &K) -> Option<usize>;
}

/// Error returned by [`SetAssocCache::new()`] and
/// [`SetAssocCache::reconfigure()`].
#[derive(Debug)]
pub enum SetAssocCacheConfigureError {
    /// Memory allocation failure.
    MemoryAllocationFailure,
}

/// Set-associative cache.
///
/// A [`SetAssocCache`] stores key-value-pairs in a fixed, preallocated set of
/// slots.
///
/// The set of all available slots is partitioned into groups referred to as the
/// "cache sets". Any possible key maps to (at most) one cache set and an entry
/// with that key will get stored in one the associated set's slots only. In
/// particular, entries whose keys are associated with the same
/// cache set contend for the fixed number of slots in that set. Within a set,
/// existing entries are evicted in least recently used (LRU) order as needed in
/// order to make room for new entries to get inserted.
///
/// The total number of sets, the capacity of each individual set (within the
/// bounds of [`MAX_SET_ASSOCIATIVITY`](Self::MAX_SET_ASSOCIATIVITY)) as well as
/// the [map from keys to cache sets](SetAssocCacheMapKeyToSet) are specified at
/// [instantiation](Self::new) time, and can get
/// [reconfigured](Self::reconfigure) later. Note that the support for
/// non-uniform cache set capacities in combination with arbitrary maps allows
/// for tuning the cache configuration to any expected entry key access
/// probablity distribution.
pub struct SetAssocCache<K: cmp::Ord, T, M: SetAssocCacheMapKeyToSet<K>> {
    /// The cache sets.
    sets: Vec<SetAssocCacheSet<K, T>>,
    /// The installed [map from keys to associated cache
    /// sets](SetAssocCacheMapKeyToSet).
    map_key_to_set: M,
}

impl<K: cmp::Ord, T, M: SetAssocCacheMapKeyToSet<K>> SetAssocCache<K, T, M> {
    /// Maximum possible cache set capacity.
    ///
    /// The maximum possible number of slots any given single cache set can
    /// provide.
    pub const MAX_SET_ASSOCIATIVITY: u32 = SetAssocCacheSet::<K, T>::MAX_ASSOCIATIVITY;

    /// Instantiate a new [`SetAssocCache`].
    ///
    /// The number and capacity of each of the cache's cache set will be as
    /// determined by the `set_capacities` iterator: for each capacity
    /// returned from it, a set of that capacity will get created. For the
    /// purpose of the `map_key_to_set`, which defines the association of keys
    /// with cache sets, the cache set indexing order is defined to the
    /// `sets_capacities` iteration order.
    ///
    /// Note that it is possible to change the [`SetAssocCache`] configuration
    /// again later on via [`reconfigure()`](Self::reconfigure).
    ///
    /// # Arguments:
    ///
    /// * `map_key_to_set` - The map establishing the association between keys
    ///   and cache sets.
    /// * `sets_capacities` - Iterator defining the total number and individual
    ///   capacities of the cache sets.
    pub fn new<SCI: Iterator<Item = u32> + Clone>(
        map_key_to_set: M,
        sets_capacities: SCI,
    ) -> Result<Self, SetAssocCacheConfigureError> {
        let sets_count = sets_capacities.clone().count();
        let mut sets = Vec::new();
        sets.try_reserve_exact(sets_count)
            .map_err(|_| SetAssocCacheConfigureError::MemoryAllocationFailure)?;
        sets.resize_with(sets_count, SetAssocCacheSet::default);

        for (i, set_capacity) in sets_capacities.enumerate() {
            sets[i].set_capacity(set_capacity);
        }

        Ok(Self { sets, map_key_to_set })
    }

    /// Reconfigure a [`SetAssocCache`].
    ///
    /// Reconfigure the existing [`SetAssocCache`] instances's cache sets' total
    /// number and individual dimensions as determined by `sets_capacities`
    /// and install a new `map_key_to_set` for associating keys with sets.
    ///
    /// The reconfiguration process attempts to retain the existing cache
    /// entries to the extent possible, redistributing them according to the
    /// new `map_key_to_set` binning. Note that a least-recently-used (LRU)
    /// ordering is maintained only within a cache set each, so entries
    /// redistributed from different cache sets into a common one have no
    /// defined LRU relationship. The redistribution algorithm attempts to
    /// establish an approximate one for entries binned together, roughly by the
    /// two entries' respective LRU age positions within their original
    /// containing cache sets.
    ///
    /// # Arguments:
    ///
    /// * `map_key_to_set` - The new map establishing the association between
    ///   keys and cache sets.
    /// * `sets_capacities` - Iterator defining the new total number and
    ///   individual capacities of the cache sets.
    #[allow(dead_code)]
    pub fn reconfigure<SCI: Iterator<Item = u32> + Clone>(
        &mut self,
        map_key_to_set: M,
        sets_capacities: SCI,
    ) -> Result<(), SetAssocCacheConfigureError> {
        for s in self.sets.iter_mut() {
            let occupied_slots = s.occupied_slots_count() as u8;
            let unoccupied_slots = s.capacity - occupied_slots;
            s.reconfigure_state = SetAssocCacheReconfigureSetState {
                remaining_to_redistribute: occupied_slots,
                unoccupied_slots,
                visited: false,
            }
        }

        let new_sets_count = sets_capacities.clone().count();
        if new_sets_count > self.sets.len() {
            self.sets
                .try_reserve_exact(new_sets_count - self.sets.len())
                .map_err(|_| SetAssocCacheConfigureError::MemoryAllocationFailure)?;
            self.sets.resize_with(new_sets_count, SetAssocCacheSet::default)
        }

        // Before redistributing the entries across the cache sets, temporarily grow
        // each set to the maximum in order to not unnecessarily evict any entries
        // during redistribution. Note that this won't consume any additional memory.
        for s in self.sets.iter_mut() {
            let old_capacity = s.capacity;
            if old_capacity as u32 != Self::MAX_SET_ASSOCIATIVITY {
                s.grow_capacity(Self::MAX_SET_ASSOCIATIVITY);
                s.reconfigure_state.unoccupied_slots += Self::MAX_SET_ASSOCIATIVITY as u8 - old_capacity;
            }
        }

        let mut redistribution_path_start_set_search_begin_index = 0;
        loop {
            let mut found_redistribution_path_start_set: Option<(usize, u8, u8)> = None;
            let mut i = redistribution_path_start_set_search_begin_index;
            // Find the set with maximum number of remaining entries to distribute, or, on
            // ties, with the minimum number of unoccupied slots.
            loop {
                let s = &self.sets[i];
                if s.reconfigure_state.remaining_to_redistribute != 0 {
                    match found_redistribution_path_start_set {
                        Some((_, found_remaining_to_distribute, found_unoccupied_slots)) => {
                            if found_remaining_to_distribute < s.reconfigure_state.remaining_to_redistribute
                                || (found_remaining_to_distribute == s.reconfigure_state.remaining_to_redistribute
                                    && found_unoccupied_slots > s.reconfigure_state.unoccupied_slots)
                            {
                                found_redistribution_path_start_set = Some((
                                    i,
                                    s.reconfigure_state.remaining_to_redistribute,
                                    s.reconfigure_state.unoccupied_slots,
                                ));
                            }
                        }
                        None => {
                            found_redistribution_path_start_set = Some((
                                i,
                                s.reconfigure_state.remaining_to_redistribute,
                                s.reconfigure_state.unoccupied_slots,
                            ));
                        }
                    }
                }
                i += 1;
                if i == self.sets.len() {
                    i = 0;
                }
                if i == redistribution_path_start_set_search_begin_index {
                    break;
                }
            }
            let redistribution_path_start_set_index = match found_redistribution_path_start_set {
                Some((found_start_set_index, _, _)) => {
                    // In the next iteration, start the search after the current found set in order
                    // to give everyone a fair chance.
                    redistribution_path_start_set_search_begin_index = found_start_set_index + 1;
                    if redistribution_path_start_set_search_begin_index == self.sets.len() {
                        redistribution_path_start_set_search_begin_index = 0;
                    }

                    found_start_set_index
                }
                None => break,
            };

            let redistribution_path_start_set = &mut self.sets[redistribution_path_start_set_index];
            let redistribution_path_start_set_least_recently_used_slot = redistribution_path_start_set
                .least_recently_used_occupied_slot()
                .unwrap();
            let new_destination_set_index = match map_key_to_set.map_key(
                &redistribution_path_start_set.slots
                    [redistribution_path_start_set_least_recently_used_slot.slot as usize]
                    .as_ref()
                    .unwrap()
                    .0,
            ) {
                Some(new_destination_set_index) => new_destination_set_index,
                None => {
                    // The entry shall not get cached anymore, just remove it.
                    redistribution_path_start_set
                        .remove_by_slot(redistribution_path_start_set_least_recently_used_slot, None);
                    redistribution_path_start_set.reconfigure_state.unoccupied_slots += 1;
                    redistribution_path_start_set
                        .reconfigure_state
                        .remaining_to_redistribute -= 1;
                    continue;
                }
            };

            // If in the same set, just refresh the LRU age.
            if new_destination_set_index == redistribution_path_start_set_index {
                SetAssocCacheSet::<K, T>::lru_reference_slot_locked(
                    &mut redistribution_path_start_set.lru_reference_matrix,
                    redistribution_path_start_set.capacity as u32,
                    redistribution_path_start_set_least_recently_used_slot.slot as u32,
                );
                redistribution_path_start_set
                    .reconfigure_state
                    .remaining_to_redistribute -= 1;
                continue;
            }

            let mut last_evicted = redistribution_path_start_set
                .remove_by_slot(redistribution_path_start_set_least_recently_used_slot, None)
                .map(|last_evicted| (last_evicted, new_destination_set_index));
            debug_assert!(last_evicted.is_some());
            redistribution_path_start_set.reconfigure_state.unoccupied_slots += 1;
            redistribution_path_start_set
                .reconfigure_state
                .remaining_to_redistribute -= 1;
            // Clear all visited flags.
            for s in self.sets.iter_mut() {
                s.reconfigure_state.visited = false;
            }
            // Superfluous, because the starting set has unoccupied_slots > 0 and a path
            // would get terminated there anyway, but be consistent.
            let start_set = &mut self.sets[redistribution_path_start_set_index];
            start_set.reconfigure_state.visited = true;

            while let Some((cur_to_redistribute, cur_to_redistribute_new_destination_set_index)) = last_evicted.take() {
                let cur_destination_set = &mut self.sets[cur_to_redistribute_new_destination_set_index];
                if cur_destination_set.reconfigure_state.unoccupied_slots == 0 {
                    // The path' starting set has at least one unoccupied slot: after all,
                    // one (the oldest) entry had been removed to start the path.
                    debug_assert_ne!(
                        cur_to_redistribute_new_destination_set_index,
                        redistribution_path_start_set_index
                    );
                    if cur_destination_set.reconfigure_state.remaining_to_redistribute != 0 {
                        // The set is full and the one currently marked as oldest in the LRU
                        // tracking will need to still get redistributed as well. So, push in the
                        // last evicted entry, and continue the redistribution path with the one
                        // that falls out from below, i.e. the least recently used entry from the
                        // set not redistributed yet. However, (as a heuristic) avoid short -- or
                        // any for that matter -- cycles involving only a small subset of the cache
                        // sets over and over again: otherwise anything which would get pushed into
                        // them in a subsequent outer loop iteration, even though potentially much
                        // older in reality, would cut the line with respect to the LRU tracking.
                        let cur_destination_set = &mut self.sets[cur_to_redistribute_new_destination_set_index];

                        if cur_destination_set.reconfigure_state.visited {
                            // Been here, and the cycle shall be stopped. This means that some entry
                            // will necessarily end up getting evicted. Choose the oldest one,
                            // which, during the redistribution process, is the oldest one among the
                            // already redistributed entries from the set. Note that such one
                            // exists, because the set had been visited before.
                            debug_assert!(
                                cur_destination_set.reconfigure_state.remaining_to_redistribute
                                    < cur_destination_set.capacity
                            );
                            let least_recently_used_redistributed_slot_age = cur_destination_set.capacity
                                - cur_destination_set.reconfigure_state.remaining_to_redistribute
                                - 1;
                            let least_recently_used_redistributed_slot = cur_destination_set
                                .slot_with_age(least_recently_used_redistributed_slot_age as u32)
                                .unwrap();
                            cur_destination_set.remove_by_slot(least_recently_used_redistributed_slot, None);
                            cur_destination_set.insert(cur_to_redistribute.0, cur_to_redistribute.1);
                        } else {
                            // Not been here yet, let the path continue.
                            cur_destination_set.reconfigure_state.visited = true;

                            // The to be evicted entry is among the ones to redistribute, update the
                            // accounting accordingly.
                            cur_destination_set.reconfigure_state.remaining_to_redistribute -= 1;
                            let evicted = cur_destination_set
                                .insert(cur_to_redistribute.0, cur_to_redistribute.1)
                                .1;
                            debug_assert!(evicted.is_some());
                            last_evicted = evicted.and_then(|evicted| {
                                map_key_to_set
                                    .map_key(&evicted.0)
                                    .map(|evicted_new_destination_set_index| {
                                        (evicted, evicted_new_destination_set_index)
                                    })
                            });
                        }
                    } else {
                        // The set is full, but all occupied slots had been redistributed into
                        // it before. One must get evicted, loosing its contents from the cache.
                        cur_destination_set.insert(cur_to_redistribute.0, cur_to_redistribute.1);
                    }
                } else {
                    // There are unoccupied slots in the set, inserting one will not evict any.
                    cur_destination_set.reconfigure_state.unoccupied_slots -= 1;
                    cur_destination_set.insert(cur_to_redistribute.0, cur_to_redistribute.1);
                }
            }
        }

        for (i, new_set_capacity) in sets_capacities.enumerate() {
            self.sets[i].set_capacity(new_set_capacity);
        }
        self.sets.truncate(new_sets_count);

        self.map_key_to_set = map_key_to_set;

        Ok(())
    }

    /// Lookup a cache entry by key.
    ///
    /// If an entry matching `key` is currently being cached, its
    /// [index](SetAssocCacheIndex) is being returned, wrapped in a `Some`.
    /// Otherwise `None` is returned.
    pub fn lookup<Q: borrow::Borrow<K>>(&self, key: &Q) -> Option<SetAssocCacheIndex> {
        let key = <Q as borrow::Borrow<K>>::borrow(key);
        let set_index = self.map_key_to_set.map_key(key)?;
        let slot = self.sets[set_index].lookup_key(key);
        slot.map(|slot| SetAssocCacheIndex { set_index, slot })
    }

    /// Access a cached entry by [index](SetAssocCacheIndex) for immutable
    /// access.
    ///
    /// If the `index` refers to a valid cache entry slot, its LRU age is reset
    /// and the entry's contents are returned as a pair of shared references
    /// to the key and associated value. Otherwise `None` is returned
    pub fn get_entry(&self, index: SetAssocCacheIndex) -> Option<(&K, &T)> {
        self.sets[index.set_index].get_slot(index.slot)
    }

    /// Access a cached entry by [index](SetAssocCacheIndex) for mutable access.
    ///
    /// If the `index` refers to a valid cache entry slot, its LRU age is reset
    /// and the entry's contents are returned as a pair of a shared reference to
    /// the entry' key and a `mut` reference to the associated value.
    /// Otherwise `None` is returned
    pub fn get_entry_mut(&mut self, index: SetAssocCacheIndex) -> Option<(&K, &mut T)> {
        self.sets[index.set_index].get_slot_mut(index.slot)
    }

    pub fn get_entry_key(&self, index: SetAssocCacheIndex) -> Option<&K> {
        self.sets[index.set_index].get_slot_key(index.slot)
    }

    /// Access a cached entry by key for immutable access.
    ///
    /// Lookup a cached entry by `key`. If no match is being found, return
    /// `None`. Otherwise reset the the entry's LRU age and provide access
    /// to the associated value by means of a shared reference wrapped in a
    /// `Some`.
    #[allow(dead_code)]
    pub fn get<Q: borrow::Borrow<K>>(&self, key: &Q) -> Option<&T> {
        self.lookup(key)
            .and_then(|index| self.get_entry(index).map(|(_k, v)| v))
    }

    /// Insert an entry into the cache.
    ///
    /// Attempt to insert an entry for `value` associated with `key`.
    ///
    /// If the `key` does not qualify for caching, as per
    /// [`SetAssocCacheMapKeyToSet::map_key()`] returning `None`,
    /// the input `value` gets returned back via
    /// [`SetAssocCacheInsertionResult::Uncacheable`].
    ///
    /// Otherwise the `value` gets inserted into the cache and associated with
    /// `key` and the resulting entry's [index](SetAssocCacheIndex)
    /// returned as part of [`SetAssocCacheInsertionResult::Inserted`].
    ///
    /// If an entry with `key` exists already, the associated value is replaced.
    /// If some other entry had to get evicted in order to make room for
    /// the one, its contents will get returned as part of
    /// [`SetAssocCacheInsertionResult::Inserted`].
    pub fn insert(&mut self, key: K, value: T) -> SetAssocCacheInsertionResult<K, T> {
        let set_index = match self.map_key_to_set.map_key(&key) {
            Some(set_index) => set_index,
            None => return SetAssocCacheInsertionResult::Uncacheable { value },
        };
        let (slot, evicted) = self.sets[set_index].insert(key, value);
        SetAssocCacheInsertionResult::Inserted {
            index: SetAssocCacheIndex { set_index, slot },
            evicted,
        }
    }

    /// Remove an entry by [index](SetAssocCacheIndex).
    ///
    /// If the `index` refers to a valid cache entry slot, it gets removed from
    /// the cache and its contents are returned as a pair of key and
    /// associated value. Otherwise `None` is returned
    #[allow(dead_code)]
    pub fn remove_entry(&mut self, index: SetAssocCacheIndex) -> Option<(K, T)> {
        self.sets[index.set_index].remove_by_slot(index.slot, None)
    }

    /// Remove an entry by key.
    ///
    /// If an entry for `key` is found in the cache, it gets removed from and
    /// its contents are returned as a pair of key and associated value.
    /// Otherwise `None` is returned
    #[allow(dead_code)]
    pub fn remove<Q: borrow::Borrow<K>>(&mut self, key: &Q) -> Option<(K, T)> {
        let key = <Q as borrow::Borrow<K>>::borrow(key);
        let set_index = self.map_key_to_set.map_key(key)?;
        self.sets[set_index].remove_by_key(key)
    }

    /// Evict all entries in the cache.
    pub fn prune_all(&mut self) {
        for s in self.sets.iter_mut() {
            s.prune_all();
        }
    }

    /// Conditionally evict entries from the cache.
    ///
    /// Invoke the `cond` predicate callback on every entry in the cache and
    /// evict those for which it returns `true`.
    #[allow(dead_code)]
    pub fn prune_cond<C: FnMut(&K, &T) -> bool>(&mut self, mut cond: C) {
        for s in self.sets.iter_mut() {
            s.prune_cond(&mut cond);
        }
    }

    /// Iterate over the cached entries in key order, providing mutable access
    /// to the associated values each.
    #[allow(dead_code)]
    pub fn iter_ordered_mut(
        &mut self,
    ) -> Result<SetAssocCacheOrderedMutIter<'_, K, T, M>, SetAssocCacheOrderedIterNewError> {
        SetAssocCacheOrderedMutIter::new(self)
    }

    /// Iterate over the cached entries in key order.
    #[allow(dead_code)]
    pub fn iter_ordered(&self) -> Result<SetAssocCacheOrderedIter<'_, K, T, M>, SetAssocCacheOrderedIterNewError> {
        SetAssocCacheOrderedIter::new(self)
    }

    #[allow(dead_code)]
    pub fn get_map_key_to_set(&self) -> &M {
        &self.map_key_to_set
    }
}

/// Result returned by [`SetAssocCache::insert()`].
pub enum SetAssocCacheInsertionResult<K, T> {
    /// The entry has been been inserted into the cache.
    Inserted {
        /// [Index](SetAssocCacheIndex) of the newly entry.
        index: SetAssocCacheIndex,
        /// Entry evicted in order to make some room for the newly inserted
        /// entry, if any.
        #[allow(dead_code)]
        evicted: Option<(K, T)>,
    },
    /// The entry did not qualify for insertion into the cache.
    ///
    /// The [`SetAssocCache`]'s [`SetAssocCacheMapKeyToSet::map_key()]` returned
    /// `None`, indicating the entry shall not get cached.
    Uncacheable {
        /// The input value passed to [`SetAssocCache::insert()`], returned back
        /// verbatim.
        #[allow(dead_code)]
        value: T,
    },
}

/// Index of a cached entry in a [`SetAssocCache`].
#[derive(Clone, Copy)]
pub struct SetAssocCacheIndex {
    set_index: usize,
    slot: SetAssocCacheSetSlotIndex,
}

/// Error returned by [`SetAssocCacheOrderedCursor::new()`].
enum SetAssocCacheOrderedCursorNewError {
    /// Memory allocation failure.
    MemoryAllocationFailure,
}

/// Cursor into [`SetAssocCache`] for iterating over its entries in key order.
struct SetAssocCacheOrderedCursor {
    /// Current positions within each cache set.
    ///
    /// Represented as a sequence of packed indices into
    /// [`SetAssocCacheSet::ordered_slots`], each represented as a 4 bit nibble.
    packed_sets_next_ordered_slots_index: Vec<u32>,
    /// Indices to the next cache entries, sorted by key order.
    ///
    /// Index entries are valid from
    /// [`next_ordered_batch_begin`](Self::next_ordered_batch_begin) through the
    /// end. Indices into the cache are represented as pairs of cache set
    /// index and slot index within the specified cache set.
    next_ordered_batch: [(usize, u8); 4],
    /// Beginning of valid, unconsumed entries in
    /// [`next_ordered_batch`](Self::next_ordered_batch).
    next_ordered_batch_begin: u8,
}

impl SetAssocCacheOrderedCursor {
    /// Instantiate a [`SetAssocCacheOrderedCursor`].
    fn new<K: cmp::Ord, T>(sets: &[SetAssocCacheSet<K, T>]) -> Result<Self, SetAssocCacheOrderedCursorNewError> {
        let packed_sets_next_ordered_slots_index_len = (sets.len() >> 3) + if sets.len() & 0x7 != 0 { 1 } else { 0 };
        let mut packed_sets_next_ordered_slots_index = Vec::new();
        packed_sets_next_ordered_slots_index
            .try_reserve_exact(packed_sets_next_ordered_slots_index_len)
            .map_err(|_| SetAssocCacheOrderedCursorNewError::MemoryAllocationFailure)?;
        packed_sets_next_ordered_slots_index.resize(packed_sets_next_ordered_slots_index_len, 0);
        let next_ordered_batch = [(0, 0); 4];
        let next_ordered_batch_begin = next_ordered_batch.len() as u8;
        Ok(Self {
            packed_sets_next_ordered_slots_index,
            next_ordered_batch,
            next_ordered_batch_begin,
        })
    }

    /// Set a given 4 bit subword's value within a packed integer.
    ///
    /// # Arguments:
    ///
    /// * `x` - The packed integer's original value, containing eight 4 bit
    ///   subwords.
    /// * `i` - The index of the 4 bit subword within `x` to alter.
    /// * `value` - The new value to set the `i`'th subword in `x` to.
    fn subwords4_set_one(x: u32, i: u32, value: u32) -> u32 {
        debug_assert!(i < 8);
        debug_assert!(value < 0x10);
        (x & !(0xf << (4 * i))) | (value << (4 * i))
    }

    /// Advance the cursor.
    ///
    /// A pair of cache set index and slot within that set referring to the next
    /// cached entry in global key order will get returned wrapped in `Some`, if
    /// any. If there aren't any more, `None` is returned.
    fn next<K: cmp::Ord, T>(&mut self, sets: &[SetAssocCacheSet<K, T>]) -> Option<(usize, u32)> {
        if self.next_ordered_batch_begin as usize == self.next_ordered_batch.len() {
            self.refill_next_ordered_batch(sets);
            if self.next_ordered_batch_begin as usize == self.next_ordered_batch.len() {
                return None;
            }
        }

        let dequeued_index = self.next_ordered_batch[self.next_ordered_batch_begin as usize];
        self.next_ordered_batch_begin += 1;
        let dequeued_index = (dequeued_index.0, dequeued_index.1 as u32);
        let dequeued_set_index = dequeued_index.0;

        // Increment the next ordered_slots' index associated with the dequeued set.
        let i = dequeued_set_index >> 3;
        let j = (dequeued_set_index & 0x7) as u32;
        let dequeued_set_next_ordered_slots_index =
            ((self.packed_sets_next_ordered_slots_index[i] >> (4 * j)) & 0xf) + 1;
        self.packed_sets_next_ordered_slots_index[i] = Self::subwords4_set_one(
            self.packed_sets_next_ordered_slots_index[i],
            j,
            dequeued_set_next_ordered_slots_index,
        );

        // If the dequeued next slot's key is smaller than what's currently batched, if
        // anything, batch it.
        if dequeued_set_next_ordered_slots_index == SetAssocCacheSet::<K, T>::MAX_ASSOCIATIVITY
            || self.next_ordered_batch_begin as usize == self.next_ordered_batch.len()
        {
            return Some(dequeued_index);
        }
        let dequeued_set_next_ordered_slot =
            match sets[dequeued_set_index].get_ordered_slot(dequeued_set_next_ordered_slots_index) {
                Some(dequeued_set_next_ordered_slot) => dequeued_set_next_ordered_slot,
                None => {
                    return Some(dequeued_index);
                }
            };

        let dequeued_set_next_ordered_slot_key = &sets[dequeued_set_index].slots
            [dequeued_set_next_ordered_slot as usize]
            .as_ref()
            .unwrap()
            .0;
        let next_ordered_batch_insertion_pos =
            self.find_next_ordered_batch_insertion_pos(sets, dequeued_set_next_ordered_slot_key);
        if next_ordered_batch_insertion_pos != self.next_ordered_batch.len() {
            self.next_ordered_batch_insert_at(
                next_ordered_batch_insertion_pos,
                (dequeued_set_index, dequeued_set_next_ordered_slot as u8),
            );
        }

        Some(dequeued_index)
    }

    /// Refill [`next_ordered_batch`](Self::next_ordered_batch).
    ///
    /// Refill [`next_ordered_batch`](Self::next_ordered_batch) by comparing all
    /// the cache sets respective [next
    /// entries](Self::packed_sets_next_ordered_slots_index) in key order with
    /// each other.
    fn refill_next_ordered_batch<K: cmp::Ord, T>(&mut self, sets: &[SetAssocCacheSet<K, T>]) {
        debug_assert_eq!(self.next_ordered_batch_begin as usize, self.next_ordered_batch.len());
        for i in 0..self.packed_sets_next_ordered_slots_index.len() {
            let mut packed_sets_next_ordered_slots_index = self.packed_sets_next_ordered_slots_index[i];
            for j in 0..8 {
                let cur_set_index = 8 * i + j;
                if cur_set_index >= sets.len() {
                    break;
                }
                let cur_set_next_ordered_slots_index = packed_sets_next_ordered_slots_index & 0xf;
                packed_sets_next_ordered_slots_index >>= 4;
                if cur_set_next_ordered_slots_index == SetAssocCacheSet::<K, T>::MAX_ASSOCIATIVITY {
                    continue;
                }
                let cur_set_next_ordered_slot =
                    match sets[cur_set_index].get_ordered_slot(cur_set_next_ordered_slots_index) {
                        Some(cur_set_next_ordered_slot) => cur_set_next_ordered_slot,
                        None => {
                            continue;
                        }
                    };
                let cur_set_next_ordered_slot_key = &sets[cur_set_index].slots[cur_set_next_ordered_slot as usize]
                    .as_ref()
                    .unwrap()
                    .0;
                let next_ordered_batch_insertion_pos =
                    self.find_next_ordered_batch_insertion_pos(sets, cur_set_next_ordered_slot_key);
                if self.next_ordered_batch_begin != 0
                    || next_ordered_batch_insertion_pos != self.next_ordered_batch.len()
                {
                    self.next_ordered_batch_insert_at(
                        next_ordered_batch_insertion_pos,
                        (cur_set_index, cur_set_next_ordered_slot as u8),
                    );
                }
            }
        }
    }

    /// Determine the insertion position in
    /// [`next_ordered_batch`](Self::next_ordered_batch) corresponding
    /// to a specified cache entry key.
    fn find_next_ordered_batch_insertion_pos<K: cmp::Ord, T>(&self, sets: &[SetAssocCacheSet<K, T>], key: &K) -> usize {
        let mut next_ordered_batch_insertion_pos = self.next_ordered_batch.len();
        while next_ordered_batch_insertion_pos > self.next_ordered_batch_begin as usize {
            let existing_next_ordered_batch_entry = &self.next_ordered_batch[next_ordered_batch_insertion_pos - 1];
            match key.cmp(
                &sets[existing_next_ordered_batch_entry.0].slots[existing_next_ordered_batch_entry.1 as usize]
                    .as_ref()
                    .unwrap()
                    .0,
            ) {
                cmp::Ordering::Greater => break,
                cmp::Ordering::Less => {
                    next_ordered_batch_insertion_pos -= 1;
                }
                cmp::Ordering::Equal => unreachable!(),
            }
        }
        next_ordered_batch_insertion_pos
    }

    /// Insert an entry into [`next_ordered_batch`](Self::next_ordered_batch) at
    /// a specified position.
    ///
    /// Insert the pair of `(set_index, set_next_ordered_slot)` into
    /// [`next_ordered_batch`](Self::next_ordered_batch) at the position
    /// specified by `next_ordered_batch_insertion_pos`.
    ///
    /// If [`next_ordered_batch`](Self::next_ordered_batch) is not full yet,
    /// i.e. [`next_ordered_batch_begin`](Self::next_ordered_batch_begin) is not
    /// zero, then existing entries are moved towards the front as
    /// appropriate in order to make some room for the new entry.
    /// Otherwise existing entries are moved towards the end as appropriate,
    /// shifting out the last one of them in the course.
    fn next_ordered_batch_insert_at(
        &mut self,
        mut next_ordered_batch_insertion_pos: usize,
        (set_index, set_next_ordered_slot): (usize, u8),
    ) {
        debug_assert!(next_ordered_batch_insertion_pos >= self.next_ordered_batch_begin as usize);
        debug_assert!(next_ordered_batch_insertion_pos <= self.next_ordered_batch.len());
        debug_assert!(
            next_ordered_batch_insertion_pos != self.next_ordered_batch.len() || self.next_ordered_batch_begin != 0
        );
        if self.next_ordered_batch_begin == 0 {
            // All batch entries used, kick out the last one.
            let next_ordered_batch_len = self.next_ordered_batch.len();
            self.next_ordered_batch.copy_within(
                next_ordered_batch_insertion_pos..next_ordered_batch_len - 1,
                next_ordered_batch_insertion_pos + 1,
            );
        } else {
            // Spare batch entries available, extend towards the unused entries at the head.
            self.next_ordered_batch.copy_within(
                self.next_ordered_batch_begin as usize..next_ordered_batch_insertion_pos,
                self.next_ordered_batch_begin as usize - 1,
            );
            self.next_ordered_batch_begin -= 1;
            next_ordered_batch_insertion_pos -= 1;
        }
        self.next_ordered_batch[next_ordered_batch_insertion_pos] = (set_index, set_next_ordered_slot);
    }
}

/// Error information returned from [`SetAssocCache::iter_ordered()`] and
/// [`SetAssocCache::iter_ordered_mut()`].
#[derive(Debug)]
pub enum SetAssocCacheOrderedIterNewError {
    /// Memory allocation failure.
    MemoryAllocationFailure,
}

/// Iterator type returned by [`SetAssocCache::iter_ordered_mut()`].
///
/// Note that `SetAssocCacheOrderedMutIter` *does not* implement the standard
/// [`Iterator`] trait, as returning `mut` references of the iterator instances
/// lifetime each would have required some `unsafe` operations.
pub struct SetAssocCacheOrderedMutIter<'a, K: cmp::Ord, T, M: SetAssocCacheMapKeyToSet<K>> {
    /// The [`SetAssocCache`] the iterator is associated with.
    cache: &'a mut SetAssocCache<K, T, M>,
    /// Cursor tracking the current position within `cache` in entry key order.
    cursor: SetAssocCacheOrderedCursor,
}

impl<'a, K: cmp::Ord, T, M: SetAssocCacheMapKeyToSet<K>> SetAssocCacheOrderedMutIter<'a, K, T, M> {
    /// Instantiate a [`SetAssocCacheOrderedMutIter`] on a [`SetAssocCache`].
    fn new(cache: &'a mut SetAssocCache<K, T, M>) -> Result<Self, SetAssocCacheOrderedIterNewError> {
        let cursor = SetAssocCacheOrderedCursor::new(&cache.sets).map_err(|e| match e {
            SetAssocCacheOrderedCursorNewError::MemoryAllocationFailure => {
                SetAssocCacheOrderedIterNewError::MemoryAllocationFailure
            }
        })?;
        Ok(Self { cache, cursor })
    }

    /// Advance the iterator and obtain the next cached entry in key order, if
    /// any.
    ///
    /// Advance the iterator to the next cached entry in key order, of any.  If
    /// there's some, its contents are returned as a pair of a shared
    /// reference to the entry' key and a `mut` reference to the associated
    /// value. Otherwise `None` is returned
    #[allow(dead_code)]
    pub fn next(&mut self) -> Option<(&K, &mut T)> {
        let (next_set_index, next_set_next_ordered_slot) = self.cursor.next(&self.cache.sets)?;
        self.cache.sets[next_set_index].slots[next_set_next_ordered_slot as usize]
            .as_mut()
            .map(|(k, v)| (&*k, v))
    }
}

/// [`Iterator`] type returned by [`SetAssocCache::iter_ordered()`].
pub struct SetAssocCacheOrderedIter<'a, K: cmp::Ord, T, M: SetAssocCacheMapKeyToSet<K>> {
    /// The [`SetAssocCache`] the iterator is associated with.
    cache: &'a SetAssocCache<K, T, M>,
    /// Cursor tracking the current position within `cache` in entry key order.
    cursor: SetAssocCacheOrderedCursor,
}

impl<'a, K: cmp::Ord, T, M: SetAssocCacheMapKeyToSet<K>> SetAssocCacheOrderedIter<'a, K, T, M> {
    /// Instantiate a [`SetAssocCacheOrderedIter`] on a [`SetAssocCache`].
    fn new(cache: &'a SetAssocCache<K, T, M>) -> Result<Self, SetAssocCacheOrderedIterNewError> {
        let cursor = SetAssocCacheOrderedCursor::new(&cache.sets).map_err(|e| match e {
            SetAssocCacheOrderedCursorNewError::MemoryAllocationFailure => {
                SetAssocCacheOrderedIterNewError::MemoryAllocationFailure
            }
        })?;
        Ok(Self { cache, cursor })
    }
}

impl<'a, K: cmp::Ord, T, M: SetAssocCacheMapKeyToSet<K>> Iterator for SetAssocCacheOrderedIter<'a, K, T, M> {
    type Item = (&'a K, &'a T);

    fn next(&mut self) -> Option<Self::Item> {
        let (next_set_index, next_set_next_ordered_slot) = self.cursor.next(&self.cache.sets)?;
        self.cache.sets[next_set_index].slots[next_set_next_ordered_slot as usize]
            .as_ref()
            .map(|(k, v)| (k, v))
    }
}

#[test]
fn test_set_assoc_cache_single_set_lru_insert() {
    use core::iter;

    struct TrivialMapSetToKey {}

    impl SetAssocCacheMapKeyToSet<u32> for TrivialMapSetToKey {
        fn map_key(&self, _key: &u32) -> Option<usize> {
            Some(0)
        }
    }

    for capacity in 1..SetAssocCacheSet::<u32, u32>::MAX_ASSOCIATIVITY + 1 {
        let mut cache = SetAssocCache::<u32, u32, _>::new(TrivialMapSetToKey {}, iter::once(capacity as u32)).unwrap();

        for i in 0u32..capacity {
            cache.insert(2 * i, 2 * i);
        }
        assert_eq!(
            cache
                .iter_ordered()
                .unwrap()
                .map(|(k, v)| (*k, *v))
                .collect::<Vec<(u32, u32)>>(),
            (0..capacity).map(|i| (2 * i, 2 * i)).collect::<Vec<(u32, u32)>>()
        );

        for j in 0u32..capacity {
            let i = capacity + j;
            cache.insert(2 * i, 2 * i);

            assert_eq!(
                cache
                    .iter_ordered()
                    .unwrap()
                    .map(|(k, v)| (*k, *v))
                    .collect::<Vec<(u32, u32)>>(),
                (j + 1..capacity + j + 1)
                    .map(|i| (2 * i, 2 * i))
                    .collect::<Vec<(u32, u32)>>()
            );
        }
    }
}

#[test]
fn test_set_assoc_cache_single_set_lru_mark_access() {
    use core::iter;

    struct TrivialMapSetToKey {}

    impl SetAssocCacheMapKeyToSet<u32> for TrivialMapSetToKey {
        fn map_key(&self, _key: &u32) -> Option<usize> {
            Some(0)
        }
    }

    for capacity in 2..SetAssocCacheSet::<u32, u32>::MAX_ASSOCIATIVITY + 1 {
        let mut cache = SetAssocCache::<u32, u32, _>::new(TrivialMapSetToKey {}, iter::once(capacity as u32)).unwrap();

        for i in 0u32..capacity {
            cache.insert(2 * i, 2 * i);
        }

        assert_eq!(*cache.get_entry(cache.lookup(&0).unwrap()).unwrap().0, 0);
        cache.insert(2 * capacity, 2 * capacity);

        assert_eq!(
            cache
                .iter_ordered()
                .unwrap()
                .map(|(k, v)| (*k, *v))
                .collect::<Vec<(u32, u32)>>(),
            iter::once(0)
                .chain(2..capacity + 1)
                .map(|i| (2 * i, 2 * i))
                .collect::<Vec<(u32, u32)>>()
        );
    }
}

#[test]
fn test_set_assoc_cache_single_set_lru_remove() {
    use core::iter;

    struct TrivialMapSetToKey {}

    impl SetAssocCacheMapKeyToSet<u32> for TrivialMapSetToKey {
        fn map_key(&self, _key: &u32) -> Option<usize> {
            Some(0)
        }
    }

    for capacity in [4, 8].iter() {
        let mut cache = SetAssocCache::<u32, u32, _>::new(TrivialMapSetToKey {}, iter::once(*capacity as u32)).unwrap();

        for i in 0u32..*capacity {
            cache.insert(2 * i, 2 * i);
        }
        assert_eq!(
            cache
                .iter_ordered()
                .unwrap()
                .map(|(k, v)| (*k, *v))
                .collect::<Vec<(u32, u32)>>(),
            (0..*capacity).map(|i| (2 * i, 2 * i)).collect::<Vec<(u32, u32)>>()
        );

        for i in 0u32..*capacity {
            cache.remove(&(2 * i + 1));
        }
        assert_eq!(
            cache
                .iter_ordered()
                .unwrap()
                .map(|(k, v)| (*k, *v))
                .collect::<Vec<(u32, u32)>>(),
            (0..*capacity).map(|i| (2 * i, 2 * i)).collect::<Vec<(u32, u32)>>()
        );

        for i in 0u32..*capacity / 2 {
            cache.remove(&(4 * i));
        }
        assert_eq!(
            cache
                .iter_ordered()
                .unwrap()
                .map(|(k, v)| (*k, *v))
                .collect::<Vec<(u32, u32)>>(),
            (0..*capacity / 2)
                .map(|i| (4 * i + 2, 4 * i + 2))
                .collect::<Vec<(u32, u32)>>()
        );

        for i in 0u32..*capacity / 2 {
            cache.insert(4 * i, 4 * i);
        }
        assert_eq!(
            cache
                .iter_ordered()
                .unwrap()
                .map(|(k, v)| (*k, *v))
                .collect::<Vec<(u32, u32)>>(),
            (0..*capacity).map(|i| (2 * i, 2 * i)).collect::<Vec<(u32, u32)>>()
        );

        cache.insert(2 * *capacity, 2 * *capacity);
        assert_eq!(
            cache
                .iter_ordered()
                .unwrap()
                .map(|(k, v)| (*k, *v))
                .collect::<Vec<(u32, u32)>>(),
            iter::once(0)
                .chain(2..*capacity + 1)
                .map(|i| (2 * i, 2 * i))
                .collect::<Vec<(u32, u32)>>()
        );
    }
}

#[test]
fn test_set_assoc_cache_iter_ordered() {
    use core::iter;

    struct Mod3MapSetToKey {}

    impl SetAssocCacheMapKeyToSet<u32> for Mod3MapSetToKey {
        fn map_key(&self, key: &u32) -> Option<usize> {
            Some((*key % 3) as usize)
        }
    }

    for set_capacity in 1..SetAssocCacheSet::<u32, u32>::MAX_ASSOCIATIVITY + 1 {
        let mut cache =
            SetAssocCache::<u32, u32, _>::new(Mod3MapSetToKey {}, iter::repeat(set_capacity as u32).take(3)).unwrap();

        for i in 0..3 * set_capacity {
            cache.insert(i, i);
            assert_eq!(
                cache
                    .iter_ordered()
                    .unwrap()
                    .map(|(k, v)| (*k, *v))
                    .collect::<Vec<(u32, u32)>>(),
                (0..i + 1).map(|j| (j, j)).collect::<Vec<(u32, u32)>>()
            );
        }
    }

    for set_capacity in 1..9 {
        let mut cache =
            SetAssocCache::<u32, u32, _>::new(Mod3MapSetToKey {}, iter::repeat(set_capacity as u32).take(3)).unwrap();

        for i in (0..3 * set_capacity).rev() {
            cache.insert(i, i);
            assert_eq!(
                cache
                    .iter_ordered()
                    .unwrap()
                    .map(|(k, v)| (*k, *v))
                    .collect::<Vec<(u32, u32)>>(),
                (i..3 * set_capacity).map(|j| (j, j)).collect::<Vec<(u32, u32)>>()
            );
        }
    }
}

#[test]
fn test_set_assoc_cache_reconfigure_single_set_shrink() {
    use core::iter;

    struct TrivialMapSetToKey {}

    impl SetAssocCacheMapKeyToSet<u32> for TrivialMapSetToKey {
        fn map_key(&self, _key: &u32) -> Option<usize> {
            Some(0)
        }
    }

    for capacity in 1u32..SetAssocCacheSet::<u32, u32>::MAX_ASSOCIATIVITY + 1 {
        for new_capacity in 0..capacity {
            let removed = capacity - new_capacity;
            for unoccupied in 0..(removed + 1).min(capacity) + 1 {
                let mut cache =
                    SetAssocCache::<u32, u32, _>::new(TrivialMapSetToKey {}, iter::once(capacity as u32)).unwrap();

                for i in 0u32..capacity - unoccupied {
                    cache.insert(i, i);
                }
                cache
                    .reconfigure(TrivialMapSetToKey {}, iter::once(new_capacity as u32))
                    .unwrap();
                let retained_end = capacity - unoccupied;
                let retained_begin = removed.saturating_sub(unoccupied).min(retained_end);
                assert_eq!(
                    cache
                        .iter_ordered()
                        .unwrap()
                        .map(|(k, v)| (*k, *v))
                        .collect::<Vec<(u32, u32)>>(),
                    (retained_begin..retained_end)
                        .map(|i| (i, i))
                        .collect::<Vec<(u32, u32)>>()
                );

                let new_unoccupied = new_capacity - (retained_end - retained_begin);
                for i in retained_end..retained_end + new_unoccupied {
                    cache.insert(i, i);
                }
                assert_eq!(
                    cache
                        .iter_ordered()
                        .unwrap()
                        .map(|(k, v)| (*k, *v))
                        .collect::<Vec<(u32, u32)>>(),
                    (retained_begin..retained_end + new_unoccupied)
                        .map(|i| (i, i))
                        .collect::<Vec<(u32, u32)>>()
                );

                for i in 0..new_capacity {
                    cache.insert(retained_end + new_unoccupied + i, retained_end + new_unoccupied + i);
                    assert_eq!(
                        cache
                            .iter_ordered()
                            .unwrap()
                            .map(|(k, v)| (*k, *v))
                            .collect::<Vec<(u32, u32)>>(),
                        (retained_begin + i + 1..retained_end + new_unoccupied + i + 1)
                            .map(|j| (j, j))
                            .collect::<Vec<(u32, u32)>>()
                    );
                }
            }
        }
    }
}

#[test]
fn test_set_assoc_cache_reconfigure_single_set_grow() {
    use core::iter;

    struct TrivialMapSetToKey {}

    impl SetAssocCacheMapKeyToSet<u32> for TrivialMapSetToKey {
        fn map_key(&self, _key: &u32) -> Option<usize> {
            Some(0)
        }
    }

    for capacity in 0u32..SetAssocCacheSet::<u32, u32>::MAX_ASSOCIATIVITY - 1 {
        for new_capacity in capacity..SetAssocCacheSet::<u32, u32>::MAX_ASSOCIATIVITY + 1 {
            for unoccupied in 0..capacity.min(capacity) + 1 {
                let mut cache =
                    SetAssocCache::<u32, u32, _>::new(TrivialMapSetToKey {}, iter::once(capacity as u32)).unwrap();

                for i in 0u32..capacity - unoccupied {
                    cache.insert(i, i);
                }
                cache
                    .reconfigure(TrivialMapSetToKey {}, iter::once(new_capacity as u32))
                    .unwrap();
                assert_eq!(
                    cache
                        .iter_ordered()
                        .unwrap()
                        .map(|(k, v)| (*k, *v))
                        .collect::<Vec<(u32, u32)>>(),
                    (0..capacity - unoccupied).map(|i| (i, i)).collect::<Vec<(u32, u32)>>()
                );

                for i in capacity - unoccupied..new_capacity {
                    cache.insert(i, i);
                }
                assert_eq!(
                    cache
                        .iter_ordered()
                        .unwrap()
                        .map(|(k, v)| (*k, *v))
                        .collect::<Vec<(u32, u32)>>(),
                    (0..new_capacity).map(|i| (i, i)).collect::<Vec<(u32, u32)>>()
                );

                for i in 0..new_capacity {
                    cache.insert(new_capacity + i, new_capacity + i);
                    assert_eq!(
                        cache
                            .iter_ordered()
                            .unwrap()
                            .map(|(k, v)| (*k, *v))
                            .collect::<Vec<(u32, u32)>>(),
                        (i + 1..new_capacity + i + 1)
                            .map(|j| (j, j))
                            .collect::<Vec<(u32, u32)>>()
                    );
                }
            }
        }
    }
}

#[test]
fn test_set_assoc_cache_reconfigure_permutate_sets() {
    use core::iter;

    struct ModMapSetToKey {
        n: u32,
        offset: u32,
    }

    impl SetAssocCacheMapKeyToSet<u32> for ModMapSetToKey {
        fn map_key(&self, key: &u32) -> Option<usize> {
            Some(((*key + self.offset) % self.n) as usize)
        }
    }

    for sets_count in 1..5 {
        for set_capacity in 1..SetAssocCacheSet::<u32, u32>::MAX_ASSOCIATIVITY + 1 {
            for unoccupied in 0..sets_count + 1 {
                let mut cache = SetAssocCache::<u32, u32, _>::new(
                    ModMapSetToKey {
                        n: sets_count,
                        offset: 0,
                    },
                    iter::repeat(set_capacity as u32).take(sets_count as usize),
                )
                .unwrap();
                for i in 0u32..sets_count * set_capacity - unoccupied {
                    cache.insert(i, i);
                }
                assert_eq!(
                    cache
                        .iter_ordered()
                        .unwrap()
                        .map(|(k, v)| (*k, *v))
                        .collect::<Vec<(u32, u32)>>(),
                    (0..sets_count * set_capacity - unoccupied)
                        .map(|i| (i, i))
                        .collect::<Vec<(u32, u32)>>()
                );

                cache
                    .reconfigure(
                        ModMapSetToKey {
                            n: sets_count,
                            offset: 1,
                        },
                        iter::repeat(set_capacity as u32).take(sets_count as usize),
                    )
                    .unwrap();
                assert_eq!(
                    cache
                        .iter_ordered()
                        .unwrap()
                        .map(|(k, v)| (*k, *v))
                        .collect::<Vec<(u32, u32)>>(),
                    (0..sets_count * set_capacity - unoccupied)
                        .map(|i| (i, i))
                        .collect::<Vec<(u32, u32)>>()
                );

                for i in sets_count * set_capacity - unoccupied..sets_count * set_capacity {
                    cache.insert(i, i);
                }
                assert_eq!(
                    cache
                        .iter_ordered()
                        .unwrap()
                        .map(|(k, v)| (*k, *v))
                        .collect::<Vec<(u32, u32)>>(),
                    (0..sets_count * set_capacity)
                        .map(|i| (i, i))
                        .collect::<Vec<(u32, u32)>>()
                );

                for i in 0u32..sets_count * set_capacity {
                    cache.insert(sets_count * set_capacity + i, sets_count * set_capacity + i);
                    assert_eq!(
                        cache
                            .iter_ordered()
                            .unwrap()
                            .map(|(k, v)| (*k, *v))
                            .collect::<Vec<(u32, u32)>>(),
                        (i + 1..sets_count * set_capacity + i + 1)
                            .map(|i| (i, i))
                            .collect::<Vec<(u32, u32)>>()
                    );
                }
            }
        }
    }
}

#[test]
fn test_set_assoc_cache_reconfigure_merge_sets() {
    use core::iter;

    struct ModMapSetToKey {
        n: u32,
        offset: u32,
    }

    impl SetAssocCacheMapKeyToSet<u32> for ModMapSetToKey {
        fn map_key(&self, key: &u32) -> Option<usize> {
            Some(((*key % self.n) + self.offset) as usize)
        }
    }

    for set_capacity in 1..SetAssocCacheSet::<u32, u32>::MAX_ASSOCIATIVITY + 1 {
        for mod_map_offset in [0, 1].iter() {
            let mut cache = SetAssocCache::<u32, u32, _>::new(
                ModMapSetToKey { n: 2, offset: 0 },
                iter::repeat(set_capacity as u32).take(2),
            )
            .unwrap();
            for i in 0u32..2 * set_capacity {
                cache.insert(i, i);
            }
            assert_eq!(
                cache
                    .iter_ordered()
                    .unwrap()
                    .map(|(k, v)| (*k, *v))
                    .collect::<Vec<(u32, u32)>>(),
                (0..2 * set_capacity).map(|i| (i, i)).collect::<Vec<(u32, u32)>>()
            );

            cache
                .reconfigure(
                    ModMapSetToKey {
                        n: 1,
                        offset: *mod_map_offset,
                    },
                    iter::repeat(set_capacity as u32).take(2),
                )
                .unwrap();

            // Expect a perfect shuffle. If the number of elements is odd, it is not really
            // well-defined by "LRU age" which of the two merged sets the first
            // element is being taken from.
            let retained = cache
                .iter_ordered()
                .unwrap()
                .map(|(k, v)| (*k, *v))
                .collect::<Vec<(u32, u32)>>();
            let expected = (set_capacity..2 * set_capacity)
                .map(|i| (i, i))
                .collect::<Vec<(u32, u32)>>();
            if set_capacity % 2 == 0 {
                assert_eq!(retained, expected);
            } else {
                assert!(set_capacity - retained[0].0 <= 1);
                assert_eq!(retained[1..], expected[1..]);
            }

            if set_capacity >= 2 {
                // Verify LRU order is roughly maintained, i.e. that the entries merged from one
                // set alternate with the one from the other, age-wise. Note
                // that for two such neighbouring elements from different source
                // sets, it is not really well-defined which one is supposed to
                // be newer than the other, so skip the first two elements
                // in the comparison below.
                for i in 0..set_capacity {
                    cache.insert(2 * set_capacity + i, 2 * set_capacity + i);
                    assert_eq!(
                        cache
                            .iter_ordered()
                            .unwrap()
                            .map(|(k, v)| (*k, *v))
                            .collect::<Vec<(u32, u32)>>()[2..],
                        (set_capacity + i + 1..2 * set_capacity + i + 1)
                            .map(|j| (j, j))
                            .collect::<Vec<(u32, u32)>>()[2..]
                    );
                }
            }
        }
    }
}
