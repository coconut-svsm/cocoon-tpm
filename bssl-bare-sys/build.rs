// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const LINK_NAME_SYM_PREFIX: &str = "bssl_a52a4823_";

#[derive(Debug)]
struct BindgenPrefixLinkNames {}

impl bindgen::callbacks::ParseCallbacks for BindgenPrefixLinkNames {
    fn generated_link_name_override(&self, item_info: bindgen::callbacks::ItemInfo<'_>) -> Option<String> {
        Some(String::from(LINK_NAME_SYM_PREFIX) + item_info.name)
    }
}

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_path = PathBuf::from(out_dir.clone());

    // Remove the libcrypto.a from a previous run, if any -- the symbol renaming
    // further below is not idempotent.
    let bssl_libcrypto = out_path.join("build").join("libcrypto.a");
    let _ = std::fs::remove_file(bssl_libcrypto);

    let mut integration_cppflags = None;
    let mut integration_cflags = None;
    let mut integration_cxxflags = None;
    let mut integration_asflags = None;
    let mut integration_bindgen_cflags = None;
    if cfg!(feature = "target-integration") {
        integration_cppflags = env::var("DEP_BSSL_BARE_SYS_TARGET_INTEGRATION_CPPFLAGS").ok();
        integration_cflags = env::var("DEP_BSSL_BARE_SYS_TARGET_INTEGRATION_CFLAGS").ok();
        integration_cxxflags = env::var("DEP_BSSL_BARE_SYS_TARGET_INTEGRATION_CXXFLAGS").ok();
        integration_asflags = env::var("DEP_BSSL_BARE_SYS_TARGET_INTEGRATION_ASFLAGS").ok();
        integration_bindgen_cflags = env::var("DEP_BSSL_BARE_SYS_TARGET_INTEGRATION_BINDGEN_CFLAGS").ok();
    }

    // Build openssl.
    let bssl_src_dir = "third-party/boringssl";
    println!("cargo::rerun-if-changed={}", bssl_src_dir);
    let mut cmake_config = cmake::Config::new(bssl_src_dir);
    if let Some(integration_cppflags) = integration_cppflags.as_ref() {
        cmake_config.asmflag(integration_cppflags);
        cmake_config.cflag(integration_cppflags);
        cmake_config.cxxflag(integration_cppflags);
    }
    if let Some(integration_cflags) = integration_cflags.as_ref() {
        cmake_config.cflag(integration_cflags);
    }
    if let Some(integration_cxxflags) = integration_cxxflags.as_ref() {
        cmake_config.cxxflag(integration_cxxflags);
    }
    if let Some(integration_asflags) = integration_asflags.as_ref() {
        cmake_config.asmflag(integration_asflags);
    }
    if cfg!(feature = "target-integration") {
        cmake_config.configure_arg("-DCMAKE_SYSTEM_NAME=Generic");
    }
    cmake_config.build_target("crypto");
    let bssl_dst_path = cmake_config.build();
    let bssl_build_path = bssl_dst_path.join("build");

    // Prefix all symbols to avoid name collisions.
    let bssl_libcrypto = bssl_build_path
        .join("libcrypto.a")
        .into_os_string()
        .into_string()
        .unwrap();
    let status = Command::new("objcopy")
        .arg(format!("--prefix-symbols={}", LINK_NAME_SYM_PREFIX))
        .arg(&bssl_libcrypto)
        .arg(&bssl_libcrypto)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .unwrap();
    assert!(status.success());
    // And rename the undefined references back.
    let mut cmd = Command::new("objcopy");
    for sym in [
        "_GLOBAL_OFFSET_TABLE_",
        "__assert_fail",
        "__errno_location",
        "__isoc23_sscanf",
        "abort",
        "bsearch",
        "calloc",
        "errno",
        "fclose",
        "feof",
        "ferror",
        "fflush",
        "fgets",
        "fopen",
        "fopen64",
        "fprintf",
        "fputc",
        "fputs",
        "fread",
        "free",
        "fseek",
        "ftell",
        "fwrite",
        "getauxval",
        "getentropy",
        "getenv",
        "madvise",
        "malloc",
        "memchr",
        "memcmp",
        "memcpy",
        "memmove",
        "memset",
        "mmap",
        "munmap",
        "open",
        "perror",
        "pthread_getspecific",
        "pthread_key_create",
        "pthread_mutex_lock",
        "pthread_mutex_unlock",
        "pthread_once",
        "pthread_rwlock_destroy",
        "pthread_rwlock_init",
        "pthread_rwlock_rdlock",
        "pthread_rwlock_unlock",
        "pthread_rwlock_wrlock",
        "pthread_setspecific",
        "read",
        "qsort",
        "realloc",
        "snprintf",
        "sscanf",
        "stderr",
        "strchr",
        "strcmp",
        "strerror",
        "strlen",
        "strncmp",
        "syscall",
        "sysconf",
        "time",
        "vsnprintf",
    ] {
        cmd.arg("--redefine-sym")
            .arg(format!("{}{}={}", LINK_NAME_SYM_PREFIX, sym, sym));
    }
    let status = cmd
        .arg(&bssl_libcrypto)
        .arg(&bssl_libcrypto)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .unwrap();
    assert!(status.success());

    // Generate the binding.
    // Essentially translated verbatim from boringssl/rust/bssl-sys/CMakeLists.txt.
    let bssl_src_path = PathBuf::from(bssl_src_dir);
    let bssl_src_rust_bssl_sys_bindgen_hdr = PathBuf::from("third-party")
        .join("wrapper.h")
        .into_os_string()
        .into_string()
        .unwrap();
    let bssl_src_include_path = bssl_src_path.join("include");
    let bssl_src_include_dir = bssl_src_include_path.clone().into_os_string().into_string().unwrap();
    let bindgen_wrapper_rs_out_path = out_path.join("wrapper.rs");
    // wrap_static_fns(true) is not possible unfortunately, as it would ignore
    // functions with a link_name_override(), which includes all for some
    // reason.
    let mut bindings = bindgen::Builder::default()
        .header(&bssl_src_rust_bssl_sys_bindgen_hdr)
        .allowlist_file(bssl_src_rust_bssl_sys_bindgen_hdr)
        .allowlist_file(format!(
            "{}.*\\.h",
            bssl_src_include_path
                .join("openssl")
                .into_os_string()
                .into_string()
                .unwrap()
        ))
        .enable_function_attribute_detection()
        .use_core()
        .default_macro_constant_type(bindgen::MacroTypeVariation::Signed)
        .rustified_enum("point_conversion_form_t")
        .parse_callbacks(Box::new(BindgenPrefixLinkNames {}))
        .clang_arg(format!("-I{}", bssl_src_include_dir));
    if let Some(integration_bindgen_cflags) = integration_bindgen_cflags.as_ref() {
        bindings = bindings.clang_args(integration_bindgen_cflags.split_ascii_whitespace());
    }
    bindings
        .generate()
        .expect("Failed to generate bssl bindings")
        .write_to_file(bindgen_wrapper_rs_out_path.clone())
        .expect("Failed to write bssl bindings");

    // Included from lib.rs by means of this environment variable.
    println!(
        "cargo::rustc-env=BSSL_BARE_SYS_BINDGEN_WRAPPER_RS={}",
        bindgen_wrapper_rs_out_path.into_os_string().into_string().unwrap()
    );

    println!(
        "cargo::rustc-link-search={}",
        bssl_build_path.as_os_str().to_os_string().into_string().unwrap()
    );
    // Add the generated objects to the link.
    println!("cargo::rustc-link-lib=crypto");
}
