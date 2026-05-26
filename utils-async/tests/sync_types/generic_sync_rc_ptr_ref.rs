// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Red Hat, LLC
// Author: Oliver Steffen <osteffen@redhat.com>

use cocoon_tpm_utils_async::sync_types::{
    GenericArc, GenericArcFactory, GenericSyncRcPtrRef, SyncRcPtr, SyncRcPtrFactory, SyncRcPtrRef, WeakSyncRcPtr,
};
use core::ops::Deref;
use core::sync::atomic::{AtomicU32, Ordering};

#[test]
fn new_and_deref() {
    let arc = GenericArcFactory::try_new(AtomicU32::new(42)).unwrap();
    let ptr_ref = GenericSyncRcPtrRef::new(&arc);
    assert_eq!(ptr_ref.load(Ordering::Relaxed), 42);
}

#[test]
fn clone() {
    let arc = GenericArcFactory::try_new(AtomicU32::new(42)).unwrap();
    let ptr_ref = GenericSyncRcPtrRef::new(&arc);
    let ptr_ref2 = ptr_ref.clone();

    arc.store(99, Ordering::Relaxed);
    assert_eq!(ptr_ref.load(Ordering::Relaxed), 99);
    assert_eq!(ptr_ref2.load(Ordering::Relaxed), 99);
}

#[test]
fn make_clone() {
    let arc = GenericArcFactory::try_new(AtomicU32::new(42)).unwrap();
    let ptr_ref = GenericSyncRcPtrRef::new(&arc);
    let cloned: GenericArc<AtomicU32> = ptr_ref.make_clone();

    arc.store(99, Ordering::Relaxed);
    assert_eq!(cloned.load(Ordering::Relaxed), 99);

    drop(arc);
    assert_eq!(cloned.load(Ordering::Relaxed), 99);

    cloned.store(200, Ordering::Relaxed);
    assert_eq!(cloned.load(Ordering::Relaxed), 200);
}

#[test]
fn make_weak_clone() {
    let arc = GenericArcFactory::try_new(AtomicU32::new(42)).unwrap();
    let ptr_ref = GenericSyncRcPtrRef::new(&arc);

    let weak = ptr_ref.make_weak_clone();

    arc.store(99, Ordering::Relaxed);

    let upgraded = weak.upgrade().unwrap();
    assert_eq!(upgraded.load(Ordering::Relaxed), 99);
}

#[test]
fn make_weak_clone_fails_after_strong_drop() {
    let arc = GenericArcFactory::try_new(AtomicU32::new(42)).unwrap();
    let weak = {
        let ptr_ref = GenericSyncRcPtrRef::new(&arc);
        ptr_ref.make_weak_clone()
    };
    drop(arc);
    assert!(weak.upgrade().is_none());
}

#[test]
fn as_ref_returns_generic_ref() {
    let arc = GenericArcFactory::try_new(AtomicU32::new(42)).unwrap();
    let ptr_ref = arc.as_ref();

    arc.store(99, Ordering::Relaxed);
    assert_eq!(ptr_ref.deref().load(Ordering::Relaxed), 99);

    let cloned = ptr_ref.make_clone();
    assert_eq!(cloned.load(Ordering::Relaxed), 99);

    arc.store(200, Ordering::Relaxed);
    assert_eq!(cloned.load(Ordering::Relaxed), 200);
}
