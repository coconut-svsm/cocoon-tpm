// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of a x86_64 `rdseed` based [Random number
//! generator](RngCore).

#![cfg(all(feature = "enable_x86_64_rdseed", target_arch = "x86_64"))]

use crate::utils_common::zeroize;
use crate::{
    CryptoError,
    io_slices::{CryptoPeekableIoSlicesIter, CryptoWalkableIoSlicesMutIter},
    rng::{RngCore, RngGenerateError},
};
use core::{arch::asm, convert, mem};

#[derive(Debug)]
enum RdSeedError {
    MaxRetriesExhausted,
}

impl convert::From<RdSeedError> for CryptoError {
    fn from(value: RdSeedError) -> Self {
        match value {
            RdSeedError::MaxRetriesExhausted => CryptoError::RngFailure,
        }
    }
}

const MAX_RDSEED_RETRIES: u8 = 5;

#[inline(never)]
fn rdseed() -> Result<u64, RdSeedError> {
    let mut retries = 0;
    let result = loop {
        let result: u64;
        let success: u8;
        unsafe {
            asm!(
                "rdseed {result:r};\n\
                 setc {success};\n\
                 ",
                result = out(reg) result,
                success = out(reg_byte) success,
            );
        }

        if success != 1 {
            retries += 1;
            if retries >= MAX_RDSEED_RETRIES {
                return Err(RdSeedError::MaxRetriesExhausted);
            }
            continue;
        }
        break result;
    };
    Ok(result)
}

fn cpuid(mut eax: u32, mut ecx: u32) -> (u32, u32, u32, u32) {
    let rbx: u64;
    let edx: u32;

    unsafe {
        // rustc complains that LLVM uses "%bx" internally,
        // so it cannot be specified directly.
        asm!("mov {rbx:r}, rbx;\n\
              cpuid;\n\
              xchg {rbx:r}, rbx;\n\
              ",
             inout("ax") eax,
             rbx = out(reg) rbx,
             inout("cx") ecx,
             out("dx") edx
        );
    }
    (eax, rbx as u32, ecx, edx)
}

fn cpuid_max_function() -> u32 {
    let (eax, _, _, _) = cpuid(0x0000_0000u32, 0);
    eax
}

fn cpu_has_rdseed() -> bool {
    if cpuid_max_function() < 0x0000_0007u32 {
        return false;
    }

    let (_, ebx, _, _) = cpuid(0x0000_0007u32, 0);
    ebx & (1u32 << 18) != 0
}

/// Error type returned by
/// [`X86RdSeedRng::instantiate()`](X86RdSeedRng::instantiate).
#[derive(Debug)]
pub enum X86RdSeedRngInstantiateError {
    /// No CPU support for the `rdseed` instruction.
    RdSeedInsnUnsupported,
}

/// x86_64 `rdseed` based [Random number generator](RngCore).
///
/// May serve as a primary source of entropy in constrained execution
/// environments where no other sources are available. Otherwise
/// you might consider drawing entropy from the operating system's random number
/// generation primitives, like `/dev/random`.
///
/// <div class="warning">
///
/// The `X86RdSeedRng` is not intended to be used directly for [randomness
/// generation](RngCore::generate), but rather to serve as a seeding parent in
/// e.g. a [chained](crate::rng::ChainedRng) construction.
///
/// </div>
pub struct X86RdSeedRng {}

impl X86RdSeedRng {
    /// Instantiate a `X86RdSeedRng`.
    pub fn instantiate() -> Result<Self, X86RdSeedRngInstantiateError> {
        if !cpu_has_rdseed() {
            return Err(X86RdSeedRngInstantiateError::RdSeedInsnUnsupported);
        }
        Ok(Self {})
    }
}

impl RngCore for X86RdSeedRng {
    fn generate<'a, 'b, OI: CryptoWalkableIoSlicesMutIter<'a>, AII: CryptoPeekableIoSlicesIter<'b>>(
        &mut self,
        mut output: OI,
        _additional_input: Option<AII>,
    ) -> Result<(), RngGenerateError> {
        let mut rdseed_output_buf: zeroize::Zeroizing<[u8; mem::size_of::<u64>()]> =
            [0u8; mem::size_of::<u64>()].into();
        while let Some(output_slice) = output
            .next_slice_mut(Some(rdseed_output_buf.len()))
            .map_err(RngGenerateError::CryptoError)?
        {
            let r = match rdseed() {
                Ok(r) => r,
                Err(e) => {
                    return Err(RngGenerateError::CryptoError(CryptoError::from(e)));
                }
            };
            *rdseed_output_buf = r.to_ne_bytes();
            let output_slice_len = output_slice.len();
            output_slice.copy_from_slice(&rdseed_output_buf[..output_slice_len]);
        }
        Ok(())
    }
}
