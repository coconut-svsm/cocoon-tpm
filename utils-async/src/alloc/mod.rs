// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Concurrency related memory allocation utilities.

mod sync_vec;
pub use sync_vec::{SyncVec, SyncVecError};
