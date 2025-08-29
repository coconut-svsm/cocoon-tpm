// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`sync_types::SyncTypes`] for the
//! locking types provided by Rust `std`.

use crate::utils_async::sync_types;
use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::{convert, marker};

/// [`Lock`](sync_types::SyncTypes:::Lock) trait implementation built on Rust
/// `std` [`Mutex`](std::sync::Mutex).
pub struct StdLock<T: marker::Send> {
    mtx: Mutex<T>,
}

impl<T: marker::Send> sync_types::Lock<T> for StdLock<T> {
    type Guard<'a>
        = MutexGuard<'a, T>
    where
        T: 'a;

    fn lock(&self) -> Self::Guard<'_> {
        self.mtx.lock().unwrap()
    }
}

impl<T: marker::Send> sync_types::ConstructibleLock<T> for StdLock<T> {
    fn get_mut(&mut self) -> &mut T {
        self.mtx.get_mut().unwrap()
    }
}

impl<T: marker::Send> convert::From<T> for StdLock<T> {
    fn from(value: T) -> Self {
        Self { mtx: Mutex::new(value) }
    }
}

/// [`RwLock`](sync_types::SyncTypes:::Lock) trait implementation built on Rust
/// `std` [`RwLock`](std::sync::rwLock).
pub struct StdRwLock<T: marker::Send + marker::Sync> {
    rwlock: RwLock<T>,
}

impl<T: marker::Send + marker::Sync> sync_types::RwLock<T> for StdRwLock<T> {
    type ReadGuard<'a>
        = RwLockReadGuard<'a, T>
    where
        T: 'a;
    type WriteGuard<'a>
        = RwLockWriteGuard<'a, T>
    where
        T: 'a;

    fn get_mut(&mut self) -> &mut T {
        self.rwlock.get_mut().unwrap()
    }

    fn read(&self) -> Self::ReadGuard<'_> {
        self.rwlock.read().unwrap()
    }

    fn write(&self) -> Self::WriteGuard<'_> {
        self.rwlock.write().unwrap()
    }
}

impl<T: marker::Send + marker::Sync> convert::From<T> for StdRwLock<T> {
    fn from(value: T) -> Self {
        Self {
            rwlock: RwLock::new(value),
        }
    }
}

/// [`SyncTypes`](sync_types::SyncTypes) trait implementation based on
/// on Rust [`std::sync`].
pub struct StdSyncTypes {}

impl sync_types::SyncTypes for StdSyncTypes {
    type Lock<T: marker::Send> = StdLock<T>;
    type RwLock<T: marker::Send + marker::Sync> = StdRwLock<T>;
    type SyncRcPtrFactory = sync_types::GenericArcFactory;
}
