// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

#![no_std]

// Lifetimes are not always obvious at first sight, allow for making them explicit even if
// redundant.
#![allow(clippy::needless_lifetimes)]

use cocoon_tpm_crypto as crypto;
use cocoon_tpm_tpm2_interface as tpm2_interface;
use cocoon_tpm_utils_async as utils_async;
use cocoon_tpm_utils_common as utils_common;

pub mod chip;
pub mod fs;
