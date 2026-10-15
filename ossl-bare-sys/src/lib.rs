// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Red Hat
// Author: Oliver Steffen <osteffen@redhat.com>

//! Bare OpenSSL FFI bindings (`libcrypto`).
//!
//! Builds OpenSSL from source, generates Rust FFI bindings via bindgen,
//! and links `libcrypto.a`. Build configuration (compiler flags, OpenSSL
//! configure options) is supplied by a target-integration crate via
//! Cargo `links` metadata (`links = "ossl"`).
//!
//! # Build metadata consumed
//!
//! From `cocoon-tpm-ossl-bare-sys-target-integration`
//! (`links = "ossl-bare-sys-target-integration"`):
//!
//! | Env var                                                     | Required | Usage                                        |
//! |-------------------------------------------------------------|----------|----------------------------------------------|
//! | `DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_CONFIGURE_CONFIG_FILE`| no       | Custom OpenSSL target configuration file      |
//! | `DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_CONFIGURE_TARGET`     | no       | OpenSSL `Configure` target name               |
//! | `DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_CONFIGURE_ARGS`       | no       | Extra arguments to OpenSSL `Configure`        |
//! | `DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_CPPFLAGS`             | no       | C preprocessor flags for OpenSSL and shim     |
//! | `DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_CFLAGS`               | no       | C compiler flags for OpenSSL and shim         |
//! | `DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_BINDGEN_CFLAGS`       | no       | Extra clang flags for bindgen                 |
//! | `DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_LINK_SEARCH`          | no       | Additional library search path                |
//! | `DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_LINK_LIB`             | no       | Additional library to link                    |
//!
//! # Build metadata provided
//!
//! | Key                 | Env var consumed as           | Description                                      |
//! |---------------------|-------------------------------|--------------------------------------------------|
//! | `OSSL_INCLUDE_DIR`  | `DEP_OSSL_OSSL_INCLUDE_DIR`   | Path to generated OpenSSL headers (build output) |
//! | `OSSL_SRC_INCLUDE_DIR`| `DEP_OSSL_OSSL_SRC_INCLUDE_DIR`| Path to OpenSSL source headers                 |
//! | `OSSL_LIB_DIR`      | `DEP_OSSL_OSSL_LIB_DIR`       | Path to the compiled `libcrypto.a`              |

#![no_std]
#![allow(warnings)]

// Explicit dependency against the ossl_bare_sys_target_integration crate, so that we'll include its
// link-lib, if any, here.
use cocoon_tpm_ossl_bare_sys_target_integration as _;

include!(env!("OSSL_BARE_SYS_BINDGEN_WRAPPER_RS"));
