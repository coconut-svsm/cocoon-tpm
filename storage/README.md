# Cocoon TPM project - `cocoon-tpm-storage` crate

This `[no_std]` crate provides secure persistent storage functionality.

Most importantly, it defines the `NvFs` trait as a common interface to
filesystem functionality required by other crates in the project, and
an implementation for the CocoonFs filesystem format thereof.

CocoonFs is a special purpose filesystem format designed for the
secure storage of sensitive data in e.g. a TEE setting. In addition to
its primary design focus on strong security properties, the format
implements support for some features of particular relevance to the
intended use-case, such as support for keyless storage volume
provisiong and robustness against service interruptions by means of a
journal.

For the format specification, refer to file `cocoonfs-format.md`
distributed with the code, see
[here](https://coconut-svsm.github.io/cocoon-tpm/cocoonfs/cocoonfs-format.html)
for a rendered version.
