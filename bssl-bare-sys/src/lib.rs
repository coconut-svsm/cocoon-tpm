#![no_std]
#![allow(warnings)]

// Explicit dependency against the bssl_bare_sys_target_integration crate, so that we'll include its
// link-lib, if any, here.
#[cfg(feature = "target-integration")]
use cocoon_tpm_bssl_bare_sys_target_integration as _;

include!(env!("BSSL_BARE_SYS_BINDGEN_WRAPPER_RS"));
