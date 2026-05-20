// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Red Hat, LLC
// Author: Oliver Steffen <osteffen@redhat.com>

use cocoon_tpm_utils_async::impl_deref_inner_by_tag;
use cocoon_tpm_utils_async::sync_types::{
    DerefInnerByTag, GenericArc, GenericArcFactory, SyncRcPtr, SyncRcPtrFactory, SyncRcPtrForInner, SyncRcPtrRef,
    WeakSyncRcPtr,
};
use core::ops::Deref;
use core::sync::atomic::{AtomicU32, Ordering};

struct Outer {
    value: AtomicU32,
    extra: [u64; 1],
}

struct ValueTag;
struct ExtraTag;

impl DerefInnerByTag<ValueTag> for Outer {
    impl_deref_inner_by_tag!(value, AtomicU32);
}

impl DerefInnerByTag<ExtraTag> for Outer {
    impl_deref_inner_by_tag!(extra, [u64; 1]);
}

fn make_outer_arc() -> GenericArc<Outer> {
    GenericArcFactory::try_new(Outer {
        value: AtomicU32::new(42),
        extra: [100],
    })
    .unwrap()
}

type InnerValuePtr = SyncRcPtrForInner<Outer, GenericArc<Outer>, ValueTag>;
type InnerExtraPtr = SyncRcPtrForInner<Outer, GenericArc<Outer>, ExtraTag>;

#[test]
fn new_and_deref() {
    let arc = make_outer_arc();
    let inner: InnerValuePtr = SyncRcPtrForInner::new(arc);
    assert_eq!(inner.load(Ordering::Relaxed), 42);
}

#[test]
fn deref_different_tags() {
    let arc = make_outer_arc();
    let value_ptr: InnerValuePtr = SyncRcPtrForInner::new(arc.clone());
    let extra_ptr: InnerExtraPtr = SyncRcPtrForInner::new(arc);
    assert_eq!(value_ptr.load(Ordering::Relaxed), 42);
    assert_eq!(*extra_ptr, [100]);

    value_ptr.store(99, Ordering::Relaxed);
    assert_eq!(value_ptr.load(Ordering::Relaxed), 99);
    assert_eq!(*extra_ptr, [100]);
}

#[test]
fn from_conversion() {
    let arc = make_outer_arc();
    let inner: InnerValuePtr = arc.into();
    assert_eq!(inner.load(Ordering::Relaxed), 42);
}

#[test]
fn clone_keeps_value_alive() {
    let arc = make_outer_arc();
    let inner: InnerValuePtr = SyncRcPtrForInner::new(arc);
    let inner2 = inner.clone();

    inner.store(99, Ordering::Relaxed);
    assert_eq!(inner2.load(Ordering::Relaxed), 99);

    drop(inner);
    assert_eq!(inner2.load(Ordering::Relaxed), 99);
}

#[test]
fn get_container() {
    let arc = make_outer_arc();
    let inner: InnerValuePtr = SyncRcPtrForInner::new(arc);

    inner.store(99, Ordering::Relaxed);

    let container_ref = inner.get_container();
    assert_eq!(container_ref.deref().value.load(Ordering::Relaxed), 99);
    assert_eq!(container_ref.deref().extra, [100]);
}

#[test]
fn into_container() {
    let arc = make_outer_arc();
    let inner: InnerValuePtr = SyncRcPtrForInner::new(arc);

    inner.store(99, Ordering::Relaxed);

    let recovered_arc = inner.into_container();
    assert_eq!(recovered_arc.value.load(Ordering::Relaxed), 99);
    assert_eq!(recovered_arc.extra, [100]);
}

#[test]
fn downgrade_upgrade() {
    let arc = make_outer_arc();
    let inner: InnerValuePtr = SyncRcPtrForInner::new(arc);

    let weak = inner.downgrade();
    inner.store(99, Ordering::Relaxed);

    let upgraded = weak.upgrade().unwrap();
    assert_eq!(upgraded.load(Ordering::Relaxed), 99);
}

#[test]
fn inner_survives_outer_drop() {
    let arc = make_outer_arc();
    let inner: InnerValuePtr = SyncRcPtrForInner::new(arc.clone());

    arc.value.store(99, Ordering::Relaxed);
    assert_eq!(inner.load(Ordering::Relaxed), 99);

    drop(arc);
    assert_eq!(inner.load(Ordering::Relaxed), 99);

    inner.store(200, Ordering::Relaxed);
    assert_eq!(inner.load(Ordering::Relaxed), 200);
}

#[test]
fn weak_inner_survives_outer_drop() {
    let arc = make_outer_arc();
    let inner: InnerValuePtr = SyncRcPtrForInner::new(arc.clone());
    let weak = inner.downgrade();

    arc.value.store(99, Ordering::Relaxed);
    drop(arc);

    let upgraded = weak.upgrade().unwrap();
    assert_eq!(upgraded.load(Ordering::Relaxed), 99);
}

#[test]
fn weak_inner_fails_after_all_strong_dropped() {
    let arc = make_outer_arc();
    let inner: InnerValuePtr = SyncRcPtrForInner::new(arc.clone());
    let weak = inner.downgrade();

    drop(arc);
    drop(inner);
    assert!(weak.upgrade().is_none());
}

#[test]
fn weak_upgrade_fails_after_drop() {
    let arc = make_outer_arc();
    let inner: InnerValuePtr = SyncRcPtrForInner::new(arc);
    let weak = inner.downgrade();

    drop(inner);
    assert!(weak.upgrade().is_none());
}

#[test]
fn weak_clone() {
    let arc = make_outer_arc();
    let inner: InnerValuePtr = SyncRcPtrForInner::new(arc);
    let weak1 = inner.downgrade();
    let weak2 = weak1.clone();

    inner.store(99, Ordering::Relaxed);

    let upgraded1 = weak1.upgrade().unwrap();
    let upgraded2 = weak2.upgrade().unwrap();
    assert_eq!(upgraded1.load(Ordering::Relaxed), 99);
    assert_eq!(upgraded2.load(Ordering::Relaxed), 99);
}

#[test]
fn into_raw_from_raw_round_trip() {
    let arc = make_outer_arc();
    let inner: InnerValuePtr = SyncRcPtrForInner::new(arc);
    let inner2 = inner.clone();

    let raw = InnerValuePtr::into_raw(inner);
    assert_eq!(unsafe { &*raw }.load(Ordering::Relaxed), 42);

    inner2.store(99, Ordering::Relaxed);
    assert_eq!(unsafe { &*raw }.load(Ordering::Relaxed), 99);

    let recovered = unsafe { InnerValuePtr::from_raw(raw) };
    assert_eq!(recovered.load(Ordering::Relaxed), 99);

    recovered.store(200, Ordering::Relaxed);
    assert_eq!(inner2.load(Ordering::Relaxed), 200);
}

#[test]
fn weak_into_raw_from_raw_round_trip() {
    let arc = make_outer_arc();
    let inner: InnerValuePtr = SyncRcPtrForInner::new(arc);
    let weak = inner.downgrade();

    let raw = <InnerValuePtr as SyncRcPtr<AtomicU32>>::WeakSyncRcPtr::into_raw(weak);

    inner.store(99, Ordering::Relaxed);

    let recovered = unsafe { <InnerValuePtr as SyncRcPtr<AtomicU32>>::WeakSyncRcPtr::from_raw(raw) };
    let upgraded = recovered.upgrade().unwrap();
    assert_eq!(upgraded.load(Ordering::Relaxed), 99);
}

#[test]
fn sync_rc_ptr_ref_for_inner_make_clone() {
    let arc = make_outer_arc();
    let inner: InnerValuePtr = SyncRcPtrForInner::new(arc);

    inner.store(99, Ordering::Relaxed);

    let inner_ref = <InnerValuePtr as SyncRcPtr<AtomicU32>>::as_ref(&inner);
    assert_eq!(inner_ref.load(Ordering::Relaxed), 99);

    let cloned = inner_ref.make_clone();
    assert_eq!(cloned.load(Ordering::Relaxed), 99);

    inner.store(200, Ordering::Relaxed);
    assert_eq!(cloned.load(Ordering::Relaxed), 200);
}

#[test]
fn sync_rc_ptr_ref_for_inner_make_weak_clone() {
    let arc = make_outer_arc();
    let inner: InnerValuePtr = SyncRcPtrForInner::new(arc);

    inner.store(99, Ordering::Relaxed);

    let inner_ref = <InnerValuePtr as SyncRcPtr<AtomicU32>>::as_ref(&inner);
    let weak = inner_ref.make_weak_clone();

    let upgraded = weak.upgrade().unwrap();
    assert_eq!(upgraded.load(Ordering::Relaxed), 99);
}

#[test]
fn sync_rc_ptr_ref_for_inner_get_container() {
    let arc = make_outer_arc();
    let inner: InnerValuePtr = SyncRcPtrForInner::new(arc);

    inner.store(99, Ordering::Relaxed);

    let inner_ref = <InnerValuePtr as SyncRcPtr<AtomicU32>>::as_ref(&inner);
    let container = inner_ref.get_container();
    assert_eq!(container.deref().value.load(Ordering::Relaxed), 99);
    assert_eq!(container.deref().extra, [100]);
}
