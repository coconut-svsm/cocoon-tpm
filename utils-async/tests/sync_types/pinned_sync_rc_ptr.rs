// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Red Hat, LLC
// Author: Oliver Steffen <osteffen@redhat.com>

use cocoon_tpm_utils_async::sync_types::{
    GenericArc, GenericArcFactory, SyncRcPtr, SyncRcPtrFactory, SyncRcPtrRef, WeakSyncRcPtr,
};
use core::pin::Pin;
use core::sync::atomic::{AtomicU32, Ordering};

type PinnedArc = Pin<GenericArc<AtomicU32>>;

fn make_pinned_arc(val: u32) -> PinnedArc {
    let arc = GenericArcFactory::try_new(AtomicU32::new(val)).unwrap();
    Pin::new(arc)
}

#[test]
fn pinned_deref() {
    let pinned = make_pinned_arc(42);
    assert_eq!(pinned.load(Ordering::Relaxed), 42);
}

#[test]
fn pinned_clone() {
    let pinned = make_pinned_arc(42);
    let pinned2 = pinned.clone();
    assert_eq!(pinned2.load(Ordering::Relaxed), 42);

    pinned.store(99, Ordering::Relaxed);
    assert_eq!(pinned2.load(Ordering::Relaxed), 99);
}

#[test]
fn pinned_downgrade_upgrade() {
    let pinned = make_pinned_arc(42);
    let weak = <PinnedArc as SyncRcPtr<AtomicU32>>::downgrade(&pinned);

    pinned.store(99, Ordering::Relaxed);

    let upgraded = weak.upgrade().unwrap();
    assert_eq!(upgraded.load(Ordering::Relaxed), 99);
}

#[test]
fn pinned_weak_upgrade_fails_after_drop() {
    let pinned = make_pinned_arc(42);
    let weak = <PinnedArc as SyncRcPtr<AtomicU32>>::downgrade(&pinned);

    drop(pinned);
    assert!(weak.upgrade().is_none());
}

#[test]
fn pinned_weak_clone() {
    let pinned = make_pinned_arc(42);
    let weak1 = <PinnedArc as SyncRcPtr<AtomicU32>>::downgrade(&pinned);
    let weak2 = weak1.clone();

    pinned.store(99, Ordering::Relaxed);

    let upgraded1 = weak1.upgrade().unwrap();
    let upgraded2 = weak2.upgrade().unwrap();
    assert_eq!(upgraded1.load(Ordering::Relaxed), 99);
    assert_eq!(upgraded2.load(Ordering::Relaxed), 99);
}

#[test]
fn pinned_into_raw_from_raw() {
    let pinned = make_pinned_arc(42);
    let pinned2 = pinned.clone();

    let raw = <PinnedArc as SyncRcPtr<AtomicU32>>::into_raw(pinned);
    assert_eq!(unsafe { &*raw }.load(Ordering::Relaxed), 42);

    pinned2.store(99, Ordering::Relaxed);
    assert_eq!(unsafe { &*raw }.load(Ordering::Relaxed), 99);

    let recovered = unsafe { <PinnedArc as SyncRcPtr<AtomicU32>>::from_raw(raw) };
    assert_eq!(recovered.load(Ordering::Relaxed), 99);

    recovered.store(200, Ordering::Relaxed);
    assert_eq!(pinned2.load(Ordering::Relaxed), 200);

    drop(pinned2);
}

#[test]
fn pinned_weak_into_raw_from_raw() {
    let pinned = make_pinned_arc(42);
    let weak = <PinnedArc as SyncRcPtr<AtomicU32>>::downgrade(&pinned);

    type PinnedWeak = <PinnedArc as SyncRcPtr<AtomicU32>>::WeakSyncRcPtr;

    let raw = PinnedWeak::into_raw(weak);

    pinned.store(99, Ordering::Relaxed);

    let recovered = unsafe { PinnedWeak::from_raw(raw) };
    let upgraded = recovered.upgrade().unwrap();
    assert_eq!(upgraded.load(Ordering::Relaxed), 99);
}

#[test]
fn pinned_as_ref_make_clone() {
    let pinned = make_pinned_arc(42);

    pinned.store(99, Ordering::Relaxed);

    let pinned_ref = <PinnedArc as SyncRcPtr<AtomicU32>>::as_ref(&pinned);
    assert_eq!(pinned_ref.load(Ordering::Relaxed), 99);

    let cloned = pinned_ref.make_clone();
    assert_eq!(cloned.load(Ordering::Relaxed), 99);

    pinned.store(200, Ordering::Relaxed);
    assert_eq!(cloned.load(Ordering::Relaxed), 200);
}

#[test]
fn pinned_as_ref_make_weak_clone() {
    let pinned = make_pinned_arc(42);

    pinned.store(99, Ordering::Relaxed);

    let pinned_ref = <PinnedArc as SyncRcPtr<AtomicU32>>::as_ref(&pinned);
    let weak = pinned_ref.make_weak_clone();

    let upgraded = weak.upgrade().unwrap();
    assert_eq!(upgraded.load(Ordering::Relaxed), 99);
}
