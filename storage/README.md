# Cocoon TPM project - `cocoon-tpm-storage` crate

This `[no_std]` crate provides secure persistent storage functionality.

Most importantly, it defines the `NvFs` trait as a common interface to
filesystem functionality required by other crates in the project, and
an implementation for the CocoonFs filesystem format thereof.

CocoonFs is a special purpose filesystem format designed to meet the
security demands for protecting sensitive data, like TPM state or UEFI
variables, when stored outside the security boundary of e.g. a TEE.

For full details about the CocoonFs format, please refer to its
specification to be found at `src/fs/cooonfs/cocoonfs-format.md`, a
HTML rendered version is available
[here](https://nicst.de/cocoonfs-format.html).
