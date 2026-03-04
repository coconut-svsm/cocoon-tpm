// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! RSA implementation.

#[cfg(feature = "boringssl")]
compile_error!("RSA not supported with BoringSSL backend");

mod crt;
mod encrypt;
#[cfg(feature = "rsaes")]
pub mod es_pkcs1_v1_5;
mod key;
mod keygen;
#[cfg(feature = "oaep")]
pub mod oaep;
#[cfg(feature = "rsapss")]
pub mod pss;
#[cfg(feature = "rsassa")]
pub mod ssa_pkcs1_v1_5;

pub use key::*;
