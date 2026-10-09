// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Red Hat
// Author: Oliver Steffen <osteffen@redhat.com>

fn main() {
    // See ossl-bare-sys' build.rs for a list and meaning of metadata variables
    // recognized.
    // println!("cargo::metadata=CPPFLAGS=");
    // println!("cargo::metadata=BINDGEN_CFLAGS=");
    // println!("cargo::metadata=CFLAGS=");
    // println!("cargo::metadata=CONFIGURE_ARGS=");
    // println!("cargo::metadata=LINK_SEARCH={}", ...);
    // println!("cargo::metadata=LINK_LIB={}", ...);

    // OpenSSL is pure C, so no C++ runtime is needed (unlike BoringSSL).
}
