// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

fn main() {
    // See bssl-bare-sys' build.rs for a list and meaning of metadata variables recognized.
    // println!("cargo::metadata=CPPFLAGS=");
    // println!("cargo::metadata=BINDGEN_CFLAGS=");
    // println!("cargo::metadata=CFLAGS=");
    // println!("cargo::metadata=CXXFLAGS=");
    // println!("cargo::metadata=LINK_SEARCH={}", ...);
    // println!("cargo::metadata=LINK_LIB={}", ...);

    // Set the CMAKE_SYSTEM_NAME for embedded/standalone builds
    // println!("cargo::metadata=CMAKE_SYSTEM_NAME=Generic");

    // BoringSSL contains C++ code. This default integration stub targets a
    // regular host environment, so link libstdc++. Embedded projects should
    // replace this crate (via Cargo's [patch] mechanism) and provide
    // whatever C++ runtime is appropriate for their environment.
    println!("cargo::rustc-link-lib=stdc++");
}
