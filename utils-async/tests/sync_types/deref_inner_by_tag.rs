// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Red Hat, LLC
// Author: Oliver Steffen <osteffen@redhat.com>

use cocoon_tpm_utils_async::sync_types::{DerefInnerByTag, DerefMutInnerByTag};
use cocoon_tpm_utils_async::{impl_deref_inner_by_tag, impl_deref_mut_inner_by_tag};

struct Outer {
    field_a: u32,
    field_b: [u64; 1],
}

struct TagA;
struct TagB;

impl DerefInnerByTag<TagA> for Outer {
    impl_deref_inner_by_tag!(field_a, u32);
}

impl DerefMutInnerByTag<TagA> for Outer {
    impl_deref_mut_inner_by_tag!(field_a);
}

impl DerefInnerByTag<TagB> for Outer {
    impl_deref_inner_by_tag!(field_b, [u64; 1]);
}

impl DerefMutInnerByTag<TagB> for Outer {
    impl_deref_mut_inner_by_tag!(field_b);
}

#[test]
fn deref_inner_field_a() {
    let outer = Outer {
        field_a: 42,
        field_b: [100],
    };
    assert_eq!(*DerefInnerByTag::<TagA>::deref_inner(&outer), 42);
}

#[test]
fn deref_inner_field_b() {
    let outer = Outer {
        field_a: 0,
        field_b: [999],
    };
    assert_eq!(*DerefInnerByTag::<TagB>::deref_inner(&outer), [999]);
}

#[test]
fn deref_mut_inner() {
    let mut outer = Outer {
        field_a: 0,
        field_b: [0],
    };
    *DerefMutInnerByTag::<TagA>::deref_mut_inner(&mut outer) = 99;
    assert_eq!(outer.field_a, 99);

    *DerefMutInnerByTag::<TagB>::deref_mut_inner(&mut outer) = [200];
    assert_eq!(outer.field_b, [200]);
}

#[test]
fn to_inner_ptr_container_of_round_trip_a() {
    let outer = Outer {
        field_a: 42,
        field_b: [0],
    };
    let outer_ptr: *const Outer = &outer;
    let inner_ptr = <Outer as DerefInnerByTag<TagA>>::to_inner_ptr(outer_ptr);
    assert_eq!(unsafe { *inner_ptr }, 42);

    let recovered = unsafe { <Outer as DerefInnerByTag<TagA>>::container_of(inner_ptr) };
    assert_eq!(recovered, outer_ptr);
}

#[test]
fn to_inner_ptr_container_of_round_trip_b() {
    let outer = Outer {
        field_a: 0,
        field_b: [12345],
    };
    let outer_ptr: *const Outer = &outer;
    let inner_ptr = <Outer as DerefInnerByTag<TagB>>::to_inner_ptr(outer_ptr);
    assert_eq!(unsafe { *inner_ptr }, [12345]);

    let recovered = unsafe { <Outer as DerefInnerByTag<TagB>>::container_of(inner_ptr) };
    assert_eq!(recovered, outer_ptr);
}
