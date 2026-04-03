// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Apply index permutations to slices.

/// Apply an index permutation to a slice and invert the permutation in place.
///
/// This is equivalent to `result[i] = apply_to[index_perm[i]]` without requiring
/// a separate intermediate buffer.
///
/// # Arguments
/// * `index_perm` - The index permutation to apply and subsequently invert in
///   place. After the function returns, `index_perm` will contain the inverse
///   of the original permutation. Its length must be less or equal than
///   `usize::MAX / 2` for implementation reasons.
///   The permutation has to be valid: all indices up to `apply_to.len()` have to appear
///   exactly once.
/// * `apply_to` - The slice to apply the index permutation to. Its length must
///   match the one from `index_perm`.
pub fn apply_and_invert_index_perm<T>(index_perm: &mut [usize], apply_to: &mut [T]) {
    assert_eq!(index_perm.len(), apply_to.len());

    // Process the permutation's cycles individually to enable O(n) in-place
    // processing without any memory allocations. To track which indices in
    // index_perm[] belong to any cycle already processed, handled_offsets gets
    // added to those.
    let handled_offset = 1usize << (usize::BITS - 1);
    debug_assert!(index_perm.len() < handled_offset);
    let is_handled = |i: usize| (i & handled_offset) != 0;

    let mut cycle_search_start = 0;
    while let Some((cycle_start, _)) = index_perm.iter().enumerate().skip(cycle_search_start).find(|(_, i)| {
        // Don't process any element twice and, as an optimization, don't process
        // trivial cycles consisting of only a single element.
        let i = **i;
        !is_handled(i) && i != index_perm[i]
    }) {
        let mut from = cycle_start;
        let mut to = index_perm[from];
        loop {
            debug_assert!(!is_handled(index_perm[to]));
            let next_to = index_perm[to];
            index_perm[to] = from | handled_offset;

            if to != cycle_start {
                // After the swap,
                // - apply_to[from] contains the final result of applying the original
                //   permutation before the inversion.
                // - apply_to[to] contains the element initially stored at apply_to[cycle_start]
                //   before applying any of the permutation. It will trickle all the way up to
                //   its final location in the course of processing the current permutation
                //   cycle.
                apply_to.swap(from, to);
            } else {
                debug_assert_eq!(index_perm[next_to], cycle_start | handled_offset);
                break;
            }
            from = to;
            to = next_to;
        }
        cycle_search_start = cycle_start + 1;
    }

    // Verify that the permutation was valid: every entry must have been visited
    // (handled) or be a genuine fixed point.
    debug_assert!(index_perm.iter().enumerate().all(|(i, &v)| is_handled(v) || v == i));

    // Finally, clear the handle_offset markers
    for i in index_perm.iter_mut() {
        *i &= !handled_offset;
    }
}

/// Apply an index permutation to a slice.
///
/// This is equivalent to `result[i] = apply_to[index_perm[i]]` without requiring
/// a separate intermediate buffer.
///
/// # Arguments:
///
/// * `index_perm` - The index permutation to apply. It is taken as a
///   mutable reference (and is getting modified internally for tracking
///   progress), its contents will be set to the identity permutation when the
///   function returns. Its length must be less or equal than `usize::MAX / 2`
///   for implementation reasons.
///   The permutation has to be valid: all indices up to `apply_to.len()` have to appear
///   exactly once.
/// * `apply_to` - The slice to apply the index permutation to. Its length must
///   match the one from `index_perm`.
pub fn apply_index_perm<T>(index_perm: &mut [usize], apply_to: &mut [T]) {
    assert_eq!(index_perm.len(), apply_to.len());

    // Process the permutation's cycles individually to enable O(n) in-place
    // processing without any memory allocations. To track which indices in
    // index_perm[] belong to any cycle already processed, handled_offsets gets
    // added to those.
    let handled_offset = 1usize << (usize::BITS - 1);
    debug_assert!(index_perm.len() < handled_offset);
    let is_handled = |i: usize| (i & handled_offset) != 0;

    let mut cycle_search_start = 0;
    while let Some((cycle_start, _)) = index_perm.iter().enumerate().skip(cycle_search_start).find(|(_, i)| {
        // Don't process any element twice and, as an optimization, don't process
        // trivial cycles consisting of only a single element.
        let i = **i;
        !is_handled(i) && i != index_perm[i]
    }) {
        let mut from = cycle_start;
        let mut to = index_perm[from];
        loop {
            debug_assert!(!is_handled(index_perm[to]));
            let next_to = index_perm[to];
            index_perm[to] = to | handled_offset;

            if to != cycle_start {
                // After the swap,
                // - apply_to[from] contains the final result of applying the permutation.
                // - apply_to[to] contains the element initially stored at apply_to[cycle_start]
                //   before applying any of the permutation. It will trickle all the way up to
                //   its final location in the course of processing the current permutation
                //   cycle.
                apply_to.swap(from, to);
            } else {
                debug_assert!(is_handled(index_perm[next_to]));
                break;
            }
            from = to;
            to = next_to;
        }
        cycle_search_start = cycle_start + 1;
    }

    // Verify that the permutation was valid: every entry must have been visited
    // (handled) or be a genuine fixed point.
    debug_assert!(index_perm.iter().enumerate().all(|(i, &v)| is_handled(v) || v == i));

    // Finally, clear the handle_offset markers
    for i in index_perm.iter_mut() {
        *i &= !handled_offset;
    }
}
