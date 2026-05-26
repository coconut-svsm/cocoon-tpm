// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Red Hat, LLC
// Author: Oliver Steffen <osteffen@redhat.com>

use cocoon_tpm_utils_async::sync_types::{DerefInnerByTag, DerefMutInnerByTag, Lock, LockForInner, LockForInnerGuard};
use cocoon_tpm_utils_async::test::TestNopLock;
use cocoon_tpm_utils_async::{impl_deref_inner_by_tag, impl_deref_mut_inner_by_tag};
use core::ops::{Deref, DerefMut};

// Note: field types are limited to path types (u32, u64, etc.) because
// impl_deref_inner_by_tag! uses $field_type:path. Array types like [u8; 4]
// are rejected with "no rules expected this token in macro call".
struct Outer {
    value: u32,
    data: u64,
}

struct ValueTag;
struct DataTag;

impl DerefInnerByTag<ValueTag> for Outer {
    impl_deref_inner_by_tag!(value, u32);
}

impl DerefMutInnerByTag<ValueTag> for Outer {
    impl_deref_mut_inner_by_tag!(value);
}

impl DerefInnerByTag<DataTag> for Outer {
    impl_deref_inner_by_tag!(data, u64);
}

impl DerefMutInnerByTag<DataTag> for Outer {
    impl_deref_mut_inner_by_tag!(data);
}

fn assert_value_lock(value: &impl Lock<u32>, expected: u32) {
    let guard = value.lock();
    assert_eq!(*guard, expected);
}

fn assert_data_lock(data: &impl Lock<u64>, expected: u64) {
    let guard = data.lock();
    assert_eq!(*guard, expected);
}

#[test]
fn lock_for_inner_read() {
    let outer_lock = TestNopLock::from(Outer { value: 42, data: 100 });
    let inner_lock: LockForInner<Outer, TestNopLock<Outer>, ValueTag> = LockForInner::from_outer(&outer_lock);

    assert_value_lock(&inner_lock, 42);
}

#[test]
fn lock_for_inner_write() {
    let outer_lock = TestNopLock::from(Outer { value: 0, data: 0 });
    let inner_lock: LockForInner<Outer, TestNopLock<Outer>, ValueTag> = LockForInner::from_outer(&outer_lock);

    {
        let mut guard = inner_lock.lock();
        *guard = 99;
    }

    let guard = outer_lock.lock();
    assert_eq!(guard.deref().value, 99);
}

#[test]
fn lock_for_inner_different_tags() {
    let outer_lock = TestNopLock::from(Outer { value: 10, data: 200 });

    let value_lock: LockForInner<Outer, TestNopLock<Outer>, ValueTag> = LockForInner::from_outer(&outer_lock);
    let data_lock: LockForInner<Outer, TestNopLock<Outer>, DataTag> = LockForInner::from_outer(&outer_lock);

    assert_value_lock(&value_lock, 10);
    assert_data_lock(&data_lock, 200);
}

#[test]
fn lock_for_inner_guard_from_outer() {
    let outer_lock = TestNopLock::from(Outer { value: 42, data: 0 });

    let outer_guard = outer_lock.lock();
    let inner_guard = LockForInnerGuard::<Outer, TestNopLock<Outer>, ValueTag>::from_outer(outer_guard);
    assert_eq!(*inner_guard, 42);
}

#[test]
fn lock_for_inner_guard_into_outer() {
    let outer_lock = TestNopLock::from(Outer { value: 42, data: 100 });

    let outer_guard = outer_lock.lock();
    let inner_guard = LockForInnerGuard::<Outer, TestNopLock<Outer>, ValueTag>::from_outer(outer_guard);
    let recovered_outer_guard = inner_guard.into_outer();
    assert_eq!(recovered_outer_guard.deref().value, 42);
    assert_eq!(recovered_outer_guard.deref().data, 100);
}

#[test]
fn lock_for_inner_guard_deref_mut() {
    let outer_lock = TestNopLock::from(Outer { value: 0, data: 0 });

    let outer_guard = outer_lock.lock();
    let mut inner_guard = LockForInnerGuard::<Outer, TestNopLock<Outer>, DataTag>::from_outer(outer_guard);
    *inner_guard.deref_mut() = 0xff;
    let recovered = inner_guard.into_outer();
    assert_eq!(recovered.deref().data, 0xff);
}

#[test]
fn lock_for_inner_write_visible_through_outer() {
    let outer_lock = TestNopLock::from(Outer { value: 0, data: 0 });

    {
        let inner_lock: LockForInner<Outer, TestNopLock<Outer>, ValueTag> = LockForInner::from_outer(&outer_lock);
        let mut guard = inner_lock.lock();
        *guard = 123;
    }

    {
        let inner_lock: LockForInner<Outer, TestNopLock<Outer>, DataTag> = LockForInner::from_outer(&outer_lock);
        let mut guard = inner_lock.lock();
        *guard = 456;
    }

    let guard = outer_lock.lock();
    assert_eq!(guard.deref().value, 123);
    assert_eq!(guard.deref().data, 456);
}
