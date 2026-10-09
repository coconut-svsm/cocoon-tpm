# Cocoon TPM project - `ossl-bare-sys` crate

`ossl-bare-sys` is a packaging crate providing a OpenSSL FFI
interface to the `cocoon-tpm-crypto` crate.

Most notably, a copy of OpenSSL -- its libcrypto to be more specific
-- will get compiled as part of the build process and a Rust FFI
binding generated for it.

**Note that the copy of OpenSSL is distributed as a git submodule
under the `ossl-bare-sys` crate, it must get initialized first!**

External build requirements are `perl`, `make` and `objcopy` from binutils.

All symbols from OpenSSL can optionally be renamed to have a prefix of
`ossl_a52a4823_` in order to avoid name collisions with other copies of OpenSSL
in your project, if any. To trigger this activate the `prefix-symbols` feature.
Note that the process of renaming is a bit fragile, because all symbols have to
get prefixed in a first step, and the set of known undefined symbols to be
provided by the environment, i.e. `libc`, will have to get renamed back to the
original. In case you're seeing `unresolved reference` linker error, chances
are the list in `build.rs` is incomplete and must get amended.

## Integration

The `ossl-bare-sys` supports customizing the integration into
freestanding/embedded-like environments.

`ossl-bare-sys` depends on a `ossl-bare-sys-target-integration` crate
that controls the OpenSSL build from its `build.rs` via the
[`cargo::metadata=KEY=VALUE`](https://doc.rust-lang.org/cargo/reference/build-scripts.html#the-links-manifest-key)
mechanism. A default empty stub is provided for regular host (Linux)
environments.
