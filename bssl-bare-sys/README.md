# Cocoon TPM project - `bssl-bare-sys` crate

`bssl-bare-sys` is a packaging crate providing a BoringSSL FFI
interface to the `cocoon-tpm-crypto` crate.

Most notably, a copy of BoringSSL -- its libcrypto to be more specific
-- will get compiled as part of the build process and a Rust FFI
binding generated for it.

**Note that the copy of BoringSSL is distributed as a git submodule
under the `bssl-bare-sys` crate, it must get initialized first!**

External build requirements are `cmake` and `objcopy` from binutils.

All symbols from BoringSSL will get renamed to have a prefix of
`bssl_a52a4823_` in order to avoid name collisions with other copies
of BoringSSL or OpenSSL in your project, if any. Note that the process
of renaming is a bit fragile, because all symbols have to get prefixed
in a first step, and the set of known undefined symbols to be provided
by the environment, i.e. `libc`, will have to get renamed back to the
original. In case you're seeing `unresolved reference` linker error,
chances are the list in `build.rs` is incomplete and must get amended.

## Integration
The `bssl-bare-sys` supports customizing the integration into
freestanding/embedded-like environments.

`bssl-bare-sys` depends on a `bssl-bare-sys-target-integration` crate
that controls the BoringSSL build from its `build.rs` via the
[`cargo::metadata=KEY=VALUE`](https://doc.rust-lang.org/cargo/reference/build-scripts.html#the-links-manifest-key)
mechanism. A default stub is provided that links `libstdc++` for
regular host (Linux) environments.

For embedded or freestanding builds, you're supposed to provide a
substitute for the `bssl-bare-sys-target-integration` crate via e.g.
Cargo's
[`[patch.'<URL>']`](https://doc.rust-lang.org/cargo/reference/overriding-dependencies.html)
mechanism.

The `bssl-bare-sys-target-integration` must have
`links = "bssl-bare-sys-target-integration"` in its `Cargo.toml` and
may set any of the following `cargo::metadata` keys:

* `CPPFLAGS` - C preprocessor flags for the BoringSSL build.
* `CFLAGS` - C compiler flags for the BoringSSL build.
* `CXXFLAGS` - C++ compiler flags for the BoringSSL build.
* `ASFLAGS` - Assembler flags for the BoringSSL build.
* `BINDGEN_CFLAGS` - Flags to be passed to clang for the bindgen FFI
  generation.
* `CMAKE_SYSTEM_NAME` - If set, passed to CMake as
  `-DCMAKE_SYSTEM_NAME=<value>`. Use `Generic` for freestanding/embedded
  targets.

Furthermore, the `bssl-bare-sys-target-integration` may add any
library to get linked for resolving BoringSSL's undefined references
via the usual
[`cargo::rust-link-lib`](https://doc.rust-lang.org/cargo/reference/build-scripts.html#rustc-link-lib)
and specify library search paths by means of
[`cargo::rust-link-search`](https://doc.rust-lang.org/cargo/reference/build-scripts.html#rustc-link-search).

The default `bssl-bare-sys-target-integration` stub links `libstdc++`
(since BoringSSL contains C++ code). An embedded replacement would
typically omit this and instead provide whatever C++ runtime (if any)
is appropriate for the target environment.
