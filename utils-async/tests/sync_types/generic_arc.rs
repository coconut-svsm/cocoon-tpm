// SPDX-License-Identifier: Apache-2.0
// Copyright The Rust Project Developers (see https://thanks.rust-lang.org)
// Copyright 2026 Red Hat, LLC
// Author: Oliver Steffen <osteffen@redhat.com>

use cocoon_tpm_utils_async::sync_types::{
    GenericArc, GenericArcFactory, GenericWeak, SyncRcPtr, SyncRcPtrFactory, SyncRcPtrTryNewWithError, WeakSyncRcPtr,
};
use core::ops::Deref;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

struct DropCanary(*mut AtomicUsize);

// SAFETY: only used in single-threaded tests.
unsafe impl Send for DropCanary {}
unsafe impl Sync for DropCanary {}

impl Drop for DropCanary {
    fn drop(&mut self) {
        unsafe { (*self.0).fetch_add(1, Ordering::SeqCst) };
    }
}

#[test]
fn try_new() {
    let arc = GenericArcFactory::try_new(42u32).unwrap();
    assert_eq!(*arc, 42);
}

#[test]
fn clone_and_deref() {
    let arc = GenericArcFactory::try_new(AtomicU32::new(42)).unwrap();
    let arc2 = arc.clone();
    assert_eq!(arc2.load(Ordering::Relaxed), 42);

    arc.store(99, Ordering::Relaxed);
    assert_eq!(arc2.load(Ordering::Relaxed), 99);

    drop(arc2);
    assert_eq!(arc.load(Ordering::Relaxed), 99);
}

#[test]
fn downgrade_upgrade() {
    let arc = GenericArcFactory::try_new(AtomicU32::new(42)).unwrap();
    let weak = arc.downgrade();

    arc.store(99, Ordering::Relaxed);

    let upgraded = weak.upgrade().unwrap();
    assert_eq!(upgraded.load(Ordering::Relaxed), 99);
}

#[test]
fn upgrade_fails_after_all_strong_dropped() {
    let arc = GenericArcFactory::try_new(42u32).unwrap();
    let weak = arc.downgrade();

    drop(arc);
    assert!(weak.upgrade().is_none());
}

#[test]
fn weak_clone() {
    let arc = GenericArcFactory::try_new(AtomicU32::new(42)).unwrap();
    let weak1 = arc.downgrade();
    let weak2 = weak1.clone();

    arc.store(99, Ordering::Relaxed);

    let upgraded = weak2.upgrade().unwrap();
    assert_eq!(upgraded.load(Ordering::Relaxed), 99);

    drop(weak1);
    arc.store(200, Ordering::Relaxed);
    let upgraded2 = weak2.upgrade().unwrap();
    assert_eq!(upgraded2.load(Ordering::Relaxed), 200);
}

#[test]
fn into_raw_from_raw_round_trip() {
    let arc = GenericArcFactory::try_new(AtomicU32::new(42)).unwrap();
    let arc2 = arc.clone();

    let raw = GenericArc::into_raw(arc);
    assert_eq!(unsafe { &*raw }.load(Ordering::Relaxed), 42);

    arc2.store(99, Ordering::Relaxed);
    assert_eq!(unsafe { &*raw }.load(Ordering::Relaxed), 99);

    let recovered = unsafe { GenericArc::<AtomicU32>::from_raw(raw) };
    assert_eq!(recovered.load(Ordering::Relaxed), 99);

    recovered.store(200, Ordering::Relaxed);
    assert_eq!(arc2.load(Ordering::Relaxed), 200);

    drop(arc2);
    assert_eq!(recovered.load(Ordering::Relaxed), 200);
}

#[test]
fn weak_into_raw_from_raw_round_trip() {
    let arc = GenericArcFactory::try_new(AtomicU32::new(42)).unwrap();
    let weak = arc.downgrade();

    let raw = GenericWeak::<AtomicU32>::into_raw(weak);

    arc.store(99, Ordering::Relaxed);

    let recovered = unsafe { GenericWeak::<AtomicU32>::from_raw(raw) };
    let upgraded = recovered.upgrade().unwrap();
    assert_eq!(upgraded.load(Ordering::Relaxed), 99);
}

#[test]
fn try_new_recoverable_success() {
    let result = GenericArcFactory::try_new_recoverable(42u32);
    let arc = result.unwrap();
    assert_eq!(*arc, 42);
}

#[test]
fn try_new_with_success() {
    let result = GenericArcFactory::try_new_with::<u32, &str, (), _>(|| Ok((42, "side-result")));
    let (arc, side) = result.unwrap();
    assert_eq!(*arc, 42);
    assert_eq!(side, "side-result");
}

#[test]
fn try_new_with_callback_error() {
    let result = GenericArcFactory::try_new_with::<u32, (), &str, _>(|| Err("callback failed"));
    match result {
        Err(SyncRcPtrTryNewWithError::WithError(msg)) => assert_eq!(msg, "callback failed"),
        _ => panic!("expected WithError"),
    }
}

#[test]
fn deref_access() {
    let arc = GenericArcFactory::try_new((1u32, 2u32)).unwrap();
    assert_eq!(arc.deref().0, 1);
    assert_eq!(arc.deref().1, 2);
}

#[test]
fn multiple_weak_all_fail_after_strong_drop() {
    let arc = GenericArcFactory::try_new(42u32).unwrap();
    let weak1 = arc.downgrade();
    let weak2 = arc.downgrade();
    let weak3 = weak1.clone();

    drop(arc);
    assert!(weak1.upgrade().is_none());
    assert!(weak2.upgrade().is_none());
    assert!(weak3.upgrade().is_none());
}

#[test]
fn drop_order_strong_then_weak() {
    let arc = GenericArcFactory::try_new(AtomicU32::new(42)).unwrap();
    let weak = arc.downgrade();
    let arc2 = arc.clone();

    arc.store(99, Ordering::Relaxed);
    let upgraded = weak.upgrade().unwrap();
    assert_eq!(upgraded.load(Ordering::Relaxed), 99);
    drop(upgraded);

    drop(arc);
    let upgraded = weak.upgrade().unwrap();
    assert_eq!(upgraded.load(Ordering::Relaxed), 99);
    drop(upgraded);

    arc2.store(200, Ordering::Relaxed);
    let upgraded = weak.upgrade().unwrap();
    assert_eq!(upgraded.load(Ordering::Relaxed), 200);
    drop(upgraded);

    drop(arc2);
    assert!(weak.upgrade().is_none());
}

#[test]
fn drop_arc() {
    let mut canary = AtomicUsize::new(0);
    let arc = GenericArcFactory::try_new(DropCanary(&mut canary as *mut AtomicUsize)).unwrap();
    drop(arc);
    assert_eq!(canary.load(Ordering::Acquire), 1);
}

#[test]
fn drop_arc_weak() {
    let mut canary = AtomicUsize::new(0);
    let arc = GenericArcFactory::try_new(DropCanary(&mut canary as *mut AtomicUsize)).unwrap();
    let weak = arc.downgrade();
    assert_eq!(canary.load(Ordering::Acquire), 0);
    drop(arc);
    assert_eq!(canary.load(Ordering::Acquire), 1);
    drop(weak);
}
