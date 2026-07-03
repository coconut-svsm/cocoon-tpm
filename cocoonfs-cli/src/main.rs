// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use cocoon_tpm_crypto as crypto;
use cocoon_tpm_storage as storage;
use cocoon_tpm_tpm2_interface as tpm2_interface;
use cocoon_tpm_utils_async::{self as utils_async};
use cocoon_tpm_utils_common as utils_common;

use crypto::{
    rng,
    symcipher::{self, SymBlockCipherAlg},
};
use storage::fs::{
    NvFs, NvFsEnumerateCursor as _, NvFsFutureAsCoreFuture, NvFsReadContext, NvFsUnlinkCursor as _,
    cocoonfs::{
        AuxFsMetadata, CocoonFs, FsMetadata, ImageLayout, MkFsFuture, OpenFsFuture, ReadFsMetadataFuture,
        WriteAuxFsMetadataOfflineFuture, WriteMkFsInfoHeaderFuture,
    },
};
use tpm2_interface::TpmiAlgHash;
use utils_async::sync_types;
use utils_common::{fixed_vec::FixedVec, zeroize};

mod std_sync_types;
use std_sync_types::StdSyncTypes;
mod std_file_nvblkdev;
use std_file_nvblkdev::StdFileNvBlkDev;

use clap::{self, CommandFactory as _, Parser as _};
use pollster::FutureExt as _;
use std::{
    ffi, fmt, fs,
    io::{self, Read, Write},
    iter,
    path::PathBuf,
    pin::Pin,
};

type CocoonFsType = CocoonFs<StdSyncTypes, StdFileNvBlkDev>;

fn cocoonfs_mk_fs_instance_ref(
    fs_instance: &<CocoonFsType as NvFs>::SyncRcPtr,
) -> <CocoonFsType as NvFs>::SyncRcPtrRef<'_> {
    type CocoonFsSyncRcPtr = <CocoonFsType as NvFs>::SyncRcPtr;
    <CocoonFsSyncRcPtr as sync_types::SyncRcPtr<_>>::as_ref(fs_instance)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CliSizeValue {
    size: u64,
}

impl From<CliSizeValue> for u64 {
    fn from(value: CliSizeValue) -> Self {
        value.size
    }
}

impl fmt::Display for CliSizeValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (shift, unit) = if self.size >> 30 << 30 == self.size {
            (30u32, 'G')
        } else if self.size >> 20 << 20 == self.size {
            (20, 'M')
        } else if self.size >> 10 << 10 == self.size {
            (10, 'K')
        } else {
            (0, 'B')
        };

        write!(f, "{}{}", self.size >> shift, unit)
    }
}

impl clap::builder::ValueParserFactory for CliSizeValue {
    type Parser = CliSizeValueParser;

    fn value_parser() -> Self::Parser {
        Self::Parser {}
    }
}

#[derive(Clone, Copy)]
struct CliSizeValueParser {}

impl clap::builder::TypedValueParser for CliSizeValueParser {
    type Value = CliSizeValue;
    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let value = value.to_str().ok_or_else(|| {
            let mut err = clap::Error::new(clap::error::ErrorKind::InvalidUtf8).with_cmd(cmd);
            if let Some(arg) = arg {
                err.insert(
                    clap::error::ContextKind::InvalidArg,
                    clap::error::ContextValue::String(arg.to_string()),
                );
            }
            err
        })?;

        let value = value.trim_start();
        let unit_pos = value.char_indices().find(|(_pos, c)| !c.is_ascii_digit());
        let (value, unit_shift) = match unit_pos {
            Some((unit_pos, _)) => {
                let unit = &value[unit_pos..].trim();
                if unit.is_empty() || *unit == "B" {
                    (&value[..unit_pos], 0u32)
                } else if *unit == "K" {
                    (&value[..unit_pos], 10)
                } else if *unit == "M" {
                    (&value[..unit_pos], 20)
                } else if *unit == "G" {
                    (&value[..unit_pos], 30)
                } else {
                    let mut err = clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd);
                    if let Some(arg) = arg {
                        err.insert(
                            clap::error::ContextKind::InvalidArg,
                            clap::error::ContextValue::String(arg.to_string()),
                        );
                    }
                    err.insert(
                        clap::error::ContextKind::InvalidValue,
                        clap::error::ContextValue::String(value.to_string()),
                    );
                    // clap currently doesn't convey this to the user, unfortunately. Still add a
                    // meaningful message in hope it would some day.
                    err.insert(
                        clap::error::ContextKind::Custom,
                        clap::error::ContextValue::String("recognized units: [B|K|M|G], default: B".to_string()),
                    );
                    return Err(err);
                }
            }
            None => (value.trim_end(), 1),
        };

        let value = clap::value_parser!(u64).parse_ref(cmd, arg, value.as_ref())?;

        if value << unit_shift >> unit_shift != value {
            let mut err = clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd);
            if let Some(arg) = arg {
                err.insert(
                    clap::error::ContextKind::InvalidArg,
                    clap::error::ContextValue::String(arg.to_string()),
                );
            }
            err.insert(
                clap::error::ContextKind::InvalidValue,
                clap::error::ContextValue::String(value.to_string()),
            );
            // clap currently doesn't convey this to the user, unfortunately. Still add a
            // meaningful message in hope it would some day.
            err.insert(
                clap::error::ContextKind::Custom,
                clap::error::ContextValue::String("value too large".to_string()),
            );
            return Err(err);
        }

        Ok(CliSizeValue {
            size: value << unit_shift,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CliPowerOfTwoSizeValue<const MIN_VALUE_LOG2: u32> {
    size_log2: u32,
}

impl<const MIN_VALUE_LOG2: u32> From<CliPowerOfTwoSizeValue<MIN_VALUE_LOG2>> for u32 {
    fn from(value: CliPowerOfTwoSizeValue<MIN_VALUE_LOG2>) -> Self {
        value.size_log2
    }
}

impl<const MIN_VALUE_LOG2: u32> From<CliPowerOfTwoSizeValue<MIN_VALUE_LOG2>> for CliSizeValue {
    fn from(value: CliPowerOfTwoSizeValue<MIN_VALUE_LOG2>) -> Self {
        CliSizeValue {
            size: 1u64 << value.size_log2,
        }
    }
}

impl<const MIN_VALUE_LOG2: u32> fmt::Display for CliPowerOfTwoSizeValue<MIN_VALUE_LOG2> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        CliSizeValue::from(*self).fmt(f)
    }
}

impl<const MIN_VALUE_LOG2: u32> clap::builder::ValueParserFactory for CliPowerOfTwoSizeValue<MIN_VALUE_LOG2> {
    type Parser = CliPowerOfTwoSizeValueParser<MIN_VALUE_LOG2>;

    fn value_parser() -> Self::Parser {
        CliPowerOfTwoSizeValueParser::<MIN_VALUE_LOG2> {}
    }
}

#[derive(Clone, Copy)]
struct CliPowerOfTwoSizeValueParser<const MIN_VALUE_LOG2: u32> {}

impl<const MIN_VALUE_LOG2: u32> clap::builder::TypedValueParser for CliPowerOfTwoSizeValueParser<MIN_VALUE_LOG2> {
    type Value = CliPowerOfTwoSizeValue<MIN_VALUE_LOG2>;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let size = clap::value_parser!(CliSizeValue).parse_ref(cmd, arg, value)?;

        let min_size = CliSizeValue::from(CliPowerOfTwoSizeValue::<MIN_VALUE_LOG2> {
            size_log2: MIN_VALUE_LOG2,
        });
        if size < min_size {
            let mut err = clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd);
            if let Some(arg) = arg {
                err.insert(
                    clap::error::ContextKind::InvalidArg,
                    clap::error::ContextValue::String(arg.to_string()),
                );
            }
            err.insert(
                clap::error::ContextKind::InvalidValue,
                clap::error::ContextValue::String(size.to_string()),
            );
            // clap currently doesn't convey this to the user, unfortunately. Still add a
            // meaningful message in hope it would some day.
            err.insert(
                clap::error::ContextKind::Custom,
                clap::error::ContextValue::String(format!("minimum value: {min_size}")),
            );
        } else if !size.size.is_power_of_two() {
            let mut err = clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd);
            if let Some(arg) = arg {
                err.insert(
                    clap::error::ContextKind::InvalidArg,
                    clap::error::ContextValue::String(arg.to_string()),
                );
            }
            err.insert(
                clap::error::ContextKind::InvalidValue,
                clap::error::ContextValue::String(size.to_string()),
            );
            // clap currently doesn't convey this to the user, unfortunately. Still add a
            // meaningful message in hope it would some day.
            err.insert(
                clap::error::ContextKind::Custom,
                clap::error::ContextValue::String("value must be a power of two".to_string()),
            );
        }

        Ok(CliPowerOfTwoSizeValue {
            size_log2: size.size.ilog2(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
enum ByteFromHexError {
    InvalidDigit,
}
fn nibble_from_hex(hexchar: u8) -> Result<u8, ByteFromHexError> {
    Ok(hexchar
        - match hexchar {
            b'0'..=b'9' => b'0',
            b'a'..=b'f' => b'a' - 0xa,
            b'A'..=b'F' => b'A' - 0xa,
            _ => {
                return Err(ByteFromHexError::InvalidDigit);
            }
        })
}

fn byte_from_hex(hexstr: &[u8; 2]) -> Result<u8, ByteFromHexError> {
    let mut result = 0u8;
    for hexchar in hexstr {
        let nibble = nibble_from_hex(*hexchar)?;
        result = result << 4 | nibble;
    }
    Ok(result)
}

#[derive(Clone, Copy)]
struct CliHexStringValueParser {}

impl clap::builder::TypedValueParser for CliHexStringValueParser {
    type Value = FixedVec<u8, 4>;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let value = value.to_str().ok_or_else(|| {
            let mut err = clap::Error::new(clap::error::ErrorKind::InvalidUtf8).with_cmd(cmd);
            if let Some(arg) = arg {
                err.insert(
                    clap::error::ContextKind::InvalidArg,
                    clap::error::ContextValue::String(arg.to_string()),
                );
            }
            err
        })?;

        let value = value.trim();
        let len = value.len().div_ceil(2);
        let mut result = FixedVec::new_with_default(len).unwrap();
        let src = value.as_bytes();
        let (src, dst) = if !value.len().is_multiple_of(2) {
            // Pad with a zero nibble at the head.
            result[0] = nibble_from_hex(src[0]).map_err(|e| {
                match e {
                    ByteFromHexError::InvalidDigit => {
                        let mut err = clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd);
                        if let Some(arg) = arg {
                            err.insert(
                                clap::error::ContextKind::InvalidArg,
                                clap::error::ContextValue::String(arg.to_string()),
                            );
                        }
                        err.insert(
                            clap::error::ContextKind::InvalidValue,
                            clap::error::ContextValue::String(value.to_string()),
                        );
                        // clap currently doesn't convey this to the user, unfortunately. Still add a
                        // meaningful message in hope it would some day.
                        err.insert(
                            clap::error::ContextKind::Custom,
                            clap::error::ContextValue::String("invalid hexadecimal digit".to_string()),
                        );

                        err
                    }
                }
            })?;
            (&src[1..], &mut result[1..])
        } else {
            (src, &mut *result)
        };

        for (i, hexdigit_pair) in src.chunks_exact(2).enumerate() {
            let hexdigit_pair = <&[u8; 2]>::try_from(hexdigit_pair).unwrap();
            dst[i] = byte_from_hex(hexdigit_pair).map_err(|e| match e {
                ByteFromHexError::InvalidDigit => {
                    let mut err = clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd);
                    if let Some(arg) = arg {
                        err.insert(
                            clap::error::ContextKind::InvalidArg,
                            clap::error::ContextValue::String(arg.to_string()),
                        );
                    }
                    err.insert(
                        clap::error::ContextKind::InvalidValue,
                        clap::error::ContextValue::String(value.to_string()),
                    );
                    // clap currently doesn't convey this to the user, unfortunately. Still add a
                    // meaningful message in hope it would some day.
                    err.insert(
                        clap::error::ContextKind::Custom,
                        clap::error::ContextValue::String("invalid hexadecimal digit".to_string()),
                    );

                    err
                }
            })?;
        }

        Ok(result)
    }
}

const UUID_LEN: usize = 16;
// (Binary) component lengths for the common 8-4-4-4-12 format.
const UUID_COMPONENTS_LENS: [usize; 5] = [4, 2, 2, 2, 6];

#[derive(Clone, Copy, Debug)]
struct CliUuidValue {
    uuid: [u8; UUID_LEN],
}

impl fmt::Display for CliUuidValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut i = 0;
        for component_len in UUID_COMPONENTS_LENS {
            for _ in 0..component_len {
                write!(f, "{:02x}", self.uuid[i])?;
                i += 1;
            }
            if i != UUID_LEN {
                write!(f, "-")?;
            }
        }
        Ok(())
    }
}

impl clap::builder::ValueParserFactory for CliUuidValue {
    type Parser = CliUuidValueParser;

    fn value_parser() -> Self::Parser {
        Self::Parser {}
    }
}

#[derive(Clone, Copy)]
struct CliUuidValueParser {}

impl clap::builder::TypedValueParser for CliUuidValueParser {
    type Value = CliUuidValue;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let value = value.to_str().ok_or_else(|| {
            let mut err = clap::Error::new(clap::error::ErrorKind::InvalidUtf8).with_cmd(cmd);
            if let Some(arg) = arg {
                err.insert(
                    clap::error::ContextKind::InvalidArg,
                    clap::error::ContextValue::String(arg.to_string()),
                );
            }
            err
        })?;

        let value = value.trim();
        let src = value.as_bytes();

        if src.iter().filter(|c| **c == b'-').count() != UUID_COMPONENTS_LENS.len() - 1 {
            let mut err = clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd);
            if let Some(arg) = arg {
                err.insert(
                    clap::error::ContextKind::InvalidArg,
                    clap::error::ContextValue::String(arg.to_string()),
                );
            }
            err.insert(
                clap::error::ContextKind::InvalidValue,
                clap::error::ContextValue::String(value.to_string()),
            );
            // clap currently doesn't convey this to the user, unfortunately. Still add a
            // meaningful message in hope it would some day.
            err.insert(
                clap::error::ContextKind::Custom,
                clap::error::ContextValue::String(
                    "invalid number of components in UUID string (expected format is 8-4-4-4-12)".to_string(),
                ),
            );
            return Err(err);
        }

        let mut expected_component_end_pos = 0;
        for (component_index, found_component_end_pos) in src
            .iter()
            .enumerate()
            .filter_map(|(pos, c)| if *c == b'-' { Some(pos) } else { None })
            .chain(iter::once(src.len()))
            .enumerate()
        {
            expected_component_end_pos += 2 * UUID_COMPONENTS_LENS[component_index];
            if found_component_end_pos != expected_component_end_pos {
                let mut err = clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd);
                if let Some(arg) = arg {
                    err.insert(
                        clap::error::ContextKind::InvalidArg,
                        clap::error::ContextValue::String(arg.to_string()),
                    );
                }
                err.insert(
                    clap::error::ContextKind::InvalidValue,
                    clap::error::ContextValue::String(value.to_string()),
                );
                // clap currently doesn't convey this to the user, unfortunately. Still add a
                // meaningful message in hope it would some day.
                err.insert(
                    clap::error::ContextKind::Custom,
                    clap::error::ContextValue::String(
                        "invalid component length in UUID string (expected format is 8-4-4-4-12)".to_string(),
                    ),
                );
                return Err(err);
            }
            // Account for the separator.
            expected_component_end_pos += 1;
        }

        let mut uuid = [0u8; UUID_LEN];
        let mut i = 0;
        let mut j = 0;
        for component_len in UUID_COMPONENTS_LENS.iter() {
            for _ in 0..*component_len {
                let hexdigit_pair = <&[u8; 2]>::try_from(&src[j..j + 2]).unwrap();
                j += 2;
                uuid[i] = byte_from_hex(hexdigit_pair).map_err(|e| match e {
                    ByteFromHexError::InvalidDigit => {
                        let mut err = clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd);
                        if let Some(arg) = arg {
                            err.insert(
                                clap::error::ContextKind::InvalidArg,
                                clap::error::ContextValue::String(arg.to_string()),
                            );
                        }
                        err.insert(
                            clap::error::ContextKind::InvalidValue,
                            clap::error::ContextValue::String(value.to_string()),
                        );
                        // clap currently doesn't convey this to the user, unfortunately. Still add a
                        // meaningful message in hope it would some day.
                        err.insert(
                            clap::error::ContextKind::Custom,
                            clap::error::ContextValue::String("invalid hexadecimal digit in UUID".to_string()),
                        );

                        err
                    }
                })?;
                i += 1;
            }
            // Skip over the separator.
            j += 1;
        }

        Ok(CliUuidValue { uuid })
    }
}

#[derive(Clone)]
struct CliAuxFsMetadataExtraReserveCapacityValue {
    capacity: Option<u64>,
}

impl fmt::Display for CliAuxFsMetadataExtraReserveCapacityValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.capacity.as_ref() {
            Some(capacity) => write!(f, "{}", CliSizeValue { size: *capacity }),
            None => write!(f, "disabled"),
        }
    }
}

impl clap::builder::ValueParserFactory for CliAuxFsMetadataExtraReserveCapacityValue {
    type Parser = CliAuxFsMetadataExtraReserveCapacityValueParser;

    fn value_parser() -> Self::Parser {
        Self::Parser {}
    }
}

#[derive(Clone)]
struct CliAuxFsMetadataExtraReserveCapacityValueParser {}

impl clap::builder::TypedValueParser for CliAuxFsMetadataExtraReserveCapacityValueParser {
    type Value = CliAuxFsMetadataExtraReserveCapacityValue;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        if value == "disabled" {
            Ok(CliAuxFsMetadataExtraReserveCapacityValue { capacity: None })
        } else {
            Ok(CliAuxFsMetadataExtraReserveCapacityValue {
                capacity: Some(clap::value_parser!(CliSizeValue).parse_ref(cmd, arg, value)?.size),
            })
        }
    }
}

#[derive(clap::Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Filesystem image volume file.
    #[arg(name = "image", short, long, value_name = "FILE")]
    volume_file_path: PathBuf,

    /// Ignore the filesystem image volume file backing storage's IO block size.
    ///
    /// May be used for accessing filesystem with a maximum supported IO block
    /// size smaller than the host's. Can lead to data loss in the event of
    /// a power cut or similar.
    #[arg(name = "force-ignore-volume-storage-block-size", short = 'f', long)]
    ignore_volume_file_io_block_size: bool,

    #[command(subcommand)]
    command: CliCommand,
}

#[derive(clap::Subcommand)]
enum CliCommand {
    /// Format the filesystem.
    Mkfs(CliMkFsArgs),
    /// Write a filesystem creation info header.
    ///
    /// A filesystem creation info header can get written without access to the
    /// key and stores all configuration parameters required for actually
    /// creating the filesystem. The filesystem will get created transparently
    /// when first accessed.
    WriteMkfsInfoHeader(CliWriteMkFsInfoHeaderArgs),

    /// Show and manipulate auxiliary filesystem metadata.
    #[command(subcommand)]
    AuxFsMetadata(CliAuxFsMetadataCommand),

    /// Write to a file in the filesystem image.
    WriteFile(CliWriteFileArgs),

    /// Read from a file in the filesystem image.
    ReadFile(CliReadFileArgs),

    /// List all files in the filesystem image.
    ListFiles(CliListFilesArgs),

    /// Remove a file from the filesystem image.
    RemoveFile(CliRemoveFile),
}

#[derive(clap::Args)]
struct CliMkFsArgs {
    #[command(flatten)]
    key: CliKeySource,

    #[command(flatten)]
    mkfsinfo: CliMkfsInfo,

    /// Don't randomize unallocated storage regions.
    #[arg(name = "no-randomize-unallocated", long, short = 'n')]
    enable_trimming: bool,
}

#[derive(clap::Args)]
struct CliWriteMkFsInfoHeaderArgs {
    #[command(flatten)]
    mkfsinfo: CliMkfsInfo,

    /// Trim the filesystem volume image file to the header.
    ///
    /// The resulting file contains only the bare header and may get written to
    /// the beginning of a storage volume.
    #[arg(name = "trim-volume-file-to-header", long, short = 'T')]
    trim_volume_file_to_header: bool,
}

#[derive(clap::Subcommand)]
enum CliAuxFsMetadataCommand {
    /// List all entries.
    ListEntries,
    /// Read a selected entry's data.
    ReadEntry(CliAuxFsMetadataReadEntryArgs),
    /// Edit the auxiliary filesystem metadata.
    Edit(CliAuxFsMetadataEditArgs),
}

#[derive(clap::Args)]
struct CliAuxFsMetadataReadEntryArgs {
    /// UUID of the entry to read.
    uuid: CliUuidValue,
    /// Selection index within the sequence of all entries with matching UUIDs.
    #[arg(default_value_t = 0)]
    index: usize,
    /// Output file to write the read data to [default: standard output].
    #[arg(name = "output-file", short, long, value_name = "FILE")]
    out_file_path: Option<PathBuf>,
}

#[derive(clap::Args)]
struct CliAuxFsMetadataEditArgs {
    #[command(flatten)]
    key: CliKeySourceOpt,

    /// Don't randomize unallocated storage regions.
    #[arg(name = "no-randomize-unallocated", long, short = 'n')]
    enable_trimming: bool,

    #[command(subcommand)]
    command: CliAuxFsMetadataEditCommand,
}

#[derive(clap::Subcommand)]
enum CliAuxFsMetadataEditCommand {
    /// Change the preallocated extra reserve capacity for enabling offline
    /// updates.
    SetExtraReserveCapacity(CliAuxFsMetadataSetExtraReserveCapacityArgs),
    /// Add an entry.
    AddEntry(CliAuxFsMetadataAddEntryArgs),
    /// Remove an entry
    RemoveEntry(CliAuxFsMetadataRemoveEntryArgs),
}

#[derive(clap::Args)]
struct CliAuxFsMetadataSetExtraReserveCapacityArgs {
    /// The extra reserve capacity to preallocate.
    ///
    /// The preallocated extra reserve capacity determines whether offline
    /// auxiliary filesystem metadata updates, i.e. when the key is
    /// inaccessible, will be possible. If set to "disabled", no offline
    /// updates will be possible.  Otherwise offline updates will be enabled,
    /// with a total size increase up to the preallocated extra SIZE.
    #[arg(value_name = "disabled|SIZE")]
    extra_reserve_capacity: CliAuxFsMetadataExtraReserveCapacityValue,
}

#[derive(clap::Args)]
struct CliAuxFsMetadataAddEntryArgs {
    /// UUID of the entry to add.
    uuid: CliUuidValue,
    /// Input file providing the data to write [default: standard input].
    #[arg(name = "input-file", short, long, value_name = "FILE")]
    in_file_path: Option<PathBuf>,
}

#[derive(clap::Args)]
struct CliAuxFsMetadataRemoveEntryArgs {
    /// UUID of the entry to remove.
    uuid: CliUuidValue,
    /// Selection index within the sequence of all entries with matching UUIDs.
    #[arg(default_value_t = 0)]
    index: usize,
}

#[derive(clap::Args)]
struct CliWriteFileArgs {
    #[command(flatten)]
    key: CliKeySource,

    /// Input file providing the data to write [default: standard input].
    #[arg(name = "input-file", short, long, value_name = "FILE")]
    in_file_path: Option<PathBuf>,

    /// Don't randomize unallocated storage regions.
    #[arg(name = "no-randomize-unallocated", long, short = 'n')]
    enable_trimming: bool,

    /// Inode number of the file to write to.
    #[arg(value_name="INODE-NUMBER", value_parser = clap::value_parser!(u64).range(6..))]
    inode: u64,

    /// Flags value to set for the inode.
    #[arg(value_name="INODE-FLAGS", value_parser = clap::value_parser!(u8), default_value_t = 0)]
    inode_flags: u8,
}

#[derive(clap::Args)]
struct CliReadFileArgs {
    #[command(flatten)]
    key: CliKeySource,

    /// Output file to write the read data to [default: standard output].
    #[arg(name = "output-file", short, long, value_name = "FILE")]
    out_file_path: Option<PathBuf>,

    /// Don't randomize unallocated storage regions.
    #[arg(name = "no-randomize-unallocated", long, short = 'n')]
    enable_trimming: bool,

    /// Inode number of the file to read from.
    #[arg(value_name="INODE-NUMBER", value_parser = clap::value_parser!(u64).range(6..))]
    inode: u64,
}

#[derive(clap::Args)]
struct CliListFilesArgs {
    #[command(flatten)]
    key: CliKeySource,

    /// Don't randomize unallocated storage regions.
    #[arg(name = "no-randomize-unallocated", long, short = 'n')]
    enable_trimming: bool,
}

#[derive(clap::Args)]
struct CliRemoveFile {
    #[command(flatten)]
    key: CliKeySource,

    /// Don't randomize unallocated storage regions.
    #[arg(name = "no-randomize-unallocated", long, short = 'n')]
    enable_trimming: bool,

    /// Inode number to delete.
    #[arg(value_name="INODE-NUMBER", value_parser = clap::value_parser!(u64).range(6..))]
    inode: u64,
}

#[derive(clap::Args)]
struct CliMkfsInfo {
    /// Hash algorithm familiy to use for filesystem authentication.
    ///
    /// Hash algorithms from the given family will get selected for various
    /// purposes as suitable for the specified target security strength.
    #[arg(name = "hash-family", short = 'H', long, value_name = "HASH-FAMILY")]
    hash_familiy: CliHashFamiliy,

    /// Block cipher algorithm to use for filesystem encryption.
    ///
    /// The key size will get chosen as appropriate such that the specified
    /// target security strength is met.
    #[arg(name = "cipher", short = 'C', long, value_name = "CIPHER")]
    block_cipher: CliBlockCipher,

    /// Target security strength in bits
    #[arg(name = "target-security-strength", short, long, value_name = "BITS")]
    target_security_strength: CliSecurityStrength,

    #[command(flatten)]
    salt: CliSaltSource,

    /// Filesystem image size [default: backing file's size, if available].
    #[arg(name = "image-size", long, short = 's', value_name = "SIZE")]
    image_size: Option<CliSizeValue>,

    /// Initial allocated auxiliary filesystem metadata extra reserve capacity.
    ///
    /// The preallocated extra reserve capacity determines whether offline
    /// auxiliary filesystem metadata updates, i.e. when the key is
    /// inaccessible, will be possible. If set to "disabled", no offline
    /// updates will be possible.  Otherwise offline updates will be enabled,
    /// with a total size increase up to the preallocated extra SIZE.
    #[arg(long, value_name = "disabled|SIZE", default_value = "1K")]
    aux_fs_metadata_extra_reserve_capacity: CliAuxFsMetadataExtraReserveCapacityValue,

    /// Allocation Block size.
    ///
    /// Unit of allocation. Must be a power of two >= 128B.
    #[arg(long, value_name = "SIZE", default_value = "128B")]
    allocation_block_size: CliPowerOfTwoSizeValue<7>,

    /// IO Block size [default: max of 512B and Allocation Block size].
    ///
    /// Upper bound on the supported storage hardware's native IO size. Must be
    /// a power of two multiple <= 64 of the Allocation Block size.
    #[arg(long, value_name = "SIZE")]
    io_block_size: Option<CliPowerOfTwoSizeValue<7>>,

    /// Authentication Tree Data Block size [default: IO Block size].
    ///
    /// Unit of data authentication, controlling the fan-out at the
    /// authentication tree leaf nodes: larger values decrease the
    /// authentication tree height, but at the cost of making data
    /// authentication more coarse grained. Must be a power of two multiple <=
    /// 64 of the Allocation Block size.
    #[arg(long, value_name = "SIZE")]
    auth_tree_data_block_size: Option<CliPowerOfTwoSizeValue<7>>,

    /// Authentication Tree node size [default: max of 1024B and IO Block size].
    ///
    /// Size of an authentication tree node, controlling the tree's branching
    /// factor: larger values decrease the authentication tree height, but
    /// at the cost of having to process larger nodes. Must be a power of
    /// two >= the IO Block size.
    #[arg(long, value_name = "SIZE")]
    auth_tree_node_size: Option<CliPowerOfTwoSizeValue<7>>,

    /// Inode index B+-tree leaf node size [default: Allocation Block size].
    ///
    /// Size of a leaf node in the inode index B+-tree, controlling the number
    /// of inode entries that can be stored in a leaf node. Must be a power of
    /// two multiple <= 64 of the Allocation Block size.
    #[arg(long, value_name = "SIZE")]
    inode_index_tree_leaf_node_size: Option<CliPowerOfTwoSizeValue<7>>,

    /// Inode index B+-tree internal node size [default: Allocation Block size].
    ///
    /// Size of a internal node in the inode index B+-tree, controlling the
    /// tree's branching factor. Must be a power of two multiple <= 64 of the
    /// Allocation Block size.
    #[arg(long, value_name = "SIZE")]
    inode_index_tree_internal_node_size: Option<CliPowerOfTwoSizeValue<7>>,

    /// Allocation bitmap block size [default: max of 512B and the
    /// Authentication Tree Data Block size].
    ///
    /// Encryption granularity of the Allocation bitmap. Each unit stores an IV,
    /// so larger values reduce the overhead, but increase the update
    /// granularity. Must be a power of two >= the Allocation Block size.
    #[arg(long, value_name = "SIZE")]
    allocation_bitmap_file_block_size: Option<CliPowerOfTwoSizeValue<7>>,
}

#[derive(Clone, clap::ValueEnum)]
enum CliHashFamiliy {
    #[cfg(feature = "sha2")]
    Sha2,
    #[cfg(feature = "sha3")]
    Sha3,
    #[cfg(feature = "sm3")]
    Sm3,
}

#[derive(Clone, clap::ValueEnum)]
enum CliBlockCipher {
    #[cfg(feature = "aes")]
    Aes,
    #[cfg(feature = "camellia")]
    Camellia,
    #[cfg(feature = "sm4")]
    Sm4,
}

#[derive(Clone, clap::ValueEnum)]
enum CliSecurityStrength {
    #[value(name = "128")]
    S128,
    #[value(name = "192")]
    S192,
    #[value(name = "256")]
    S256,
}

#[derive(clap::Args)]
#[group(required = true, multiple = false)]
struct CliKeySource {
    /// File containing the filesystem key.
    #[arg(name = "key-file", short = 'k', long, value_name = "FILE")]
    key_file_path: Option<PathBuf>,
    /// Filesystem key provided as a hexadecimal string.
    #[arg(name = "key", short = 'K', long, value_name = "HEX", value_parser = CliHexStringValueParser{})]
    key: Option<FixedVec<u8, 4>>,
}

#[derive(clap::Args)]
#[group(multiple = false)]
struct CliKeySourceOpt {
    /// File containing the filesystem key.
    #[arg(name = "key-file", short = 'k', long, value_name = "FILE")]
    key_file_path: Option<PathBuf>,
    /// Filesystem key provided as a hexadecimal string.
    #[arg(name = "key", short = 'K', long, value_name = "HEX", value_parser = CliHexStringValueParser{})]
    key: Option<FixedVec<u8, 4>>,
}

struct CliKeySourceRef<'a> {
    key_file_path: Option<&'a PathBuf>,
    key: Option<&'a FixedVec<u8, 4>>,
}

impl<'a> From<&'a CliKeySource> for CliKeySourceRef<'a> {
    fn from(value: &'a CliKeySource) -> Self {
        debug_assert!(value.key_file_path.is_some() || value.key.is_some());
        Self {
            key_file_path: value.key_file_path.as_ref(),
            key: value.key.as_ref(),
        }
    }
}

impl<'a> From<&'a CliKeySourceOpt> for Option<CliKeySourceRef<'a>> {
    fn from(value: &'a CliKeySourceOpt) -> Self {
        if value.key_file_path.is_none() && value.key.is_none() {
            None
        } else {
            Some(CliKeySourceRef {
                key_file_path: value.key_file_path.as_ref(),
                key: value.key.as_ref(),
            })
        }
    }
}

#[derive(clap::Args)]
#[group(required = true, multiple = false)]
struct CliSaltSource {
    /// File containing the filesystem salt/id.
    ///
    /// The salt will be stored in the filesystem image header and may
    /// be used filesystem image identification purposes. The salt's length
    /// must not exceed 255B.
    #[arg(name = "salt-file", short = 'i', long, value_name = "FILE")]
    salt_file_path: Option<PathBuf>,
    /// Filesystem salt/id provided as a hexadecimal string.
    ///
    /// The salt will be stored in the filesystem image header and may
    /// be used filesystem image identification purposes. The salt's length
    /// must not exceed 255B.
    #[arg(name = "salt", long, short = 'I', value_name = "HEX", value_parser = CliHexStringValueParser{})]
    salt: Option<FixedVec<u8, 4>>,
}

fn cli_mkfs_to_image_layout(cli: &CliMkfsInfo) -> ImageLayout {
    let allocation_block_size_128b_log2 = cli.allocation_block_size.size_log2 - 7;

    let io_block_allocation_blocks_log2 = if let Some(io_block_size) = cli.io_block_size {
        let io_block_size_128b_log2 = io_block_size.size_log2 - 7;
        if io_block_size_128b_log2 < allocation_block_size_128b_log2
            || io_block_size_128b_log2 - allocation_block_size_128b_log2 > 6
        {
            let mut cmd = Cli::command();
            cmd.error(
                clap::error::ErrorKind::ArgumentConflict,
                "IO Block size not a multiple of the Allocation Block size between 0 and 64",
            )
            .exit()
        }
        io_block_size_128b_log2 - allocation_block_size_128b_log2
    } else {
        (9u32 - 7).saturating_sub(allocation_block_size_128b_log2)
    };

    let auth_tree_data_block_allocation_blocks_log2 =
        if let Some(auth_tree_data_block_size) = cli.auth_tree_data_block_size {
            let auth_tree_data_block_size_128b_log2 = auth_tree_data_block_size.size_log2 - 7;
            if auth_tree_data_block_size_128b_log2 < allocation_block_size_128b_log2
                || auth_tree_data_block_size_128b_log2 - allocation_block_size_128b_log2 > 6
            {
                let mut cmd = Cli::command();
                cmd.error(
                    clap::error::ErrorKind::ArgumentConflict,
                    "Authentication Tree Data Block size not a multiple of the Allocation Block size between 0 and 64",
                )
                .exit()
            }
            auth_tree_data_block_size_128b_log2 - allocation_block_size_128b_log2
        } else {
            io_block_allocation_blocks_log2
        };

    let auth_tree_node_io_blocks_log2 = if let Some(auth_tree_node_size) = cli.auth_tree_node_size {
        let auth_tree_node_size_128b_log2 = auth_tree_node_size.size_log2 - 7;
        if auth_tree_node_size_128b_log2 < io_block_allocation_blocks_log2 + allocation_block_size_128b_log2 {
            let mut cmd = Cli::command();
            cmd.error(
                clap::error::ErrorKind::ArgumentConflict,
                "authentication tree node size size not a multiple of the IO Block size",
            )
            .exit()
        }
        auth_tree_node_size_128b_log2 - io_block_allocation_blocks_log2 - allocation_block_size_128b_log2
    } else {
        (10u32 - 7).saturating_sub(io_block_allocation_blocks_log2 + allocation_block_size_128b_log2)
    };

    let inode_index_tree_leaf_node_allocation_blocks_log2 =
        if let Some(inode_index_tree_leaf_node_size) = cli.inode_index_tree_leaf_node_size {
            let inode_index_tree_leaf_node_size_128b_log2 = inode_index_tree_leaf_node_size.size_log2 - 7;
            if inode_index_tree_leaf_node_size_128b_log2 < allocation_block_size_128b_log2
                || inode_index_tree_leaf_node_size_128b_log2 - allocation_block_size_128b_log2 > 6
            {
                let mut cmd = Cli::command();
                cmd.error(
                    clap::error::ErrorKind::ArgumentConflict,
                    "inode index tree leaf node size not a multiple of the Allocation Block size between 0 and 64",
                )
                .exit()
            }
            inode_index_tree_leaf_node_size_128b_log2 - allocation_block_size_128b_log2
        } else {
            0u32
        };

    let inode_index_tree_internal_node_allocation_blocks_log2 =
        if let Some(inode_index_tree_internal_node_size) = cli.inode_index_tree_internal_node_size {
            let inode_index_tree_internal_node_size_128b_log2 = inode_index_tree_internal_node_size.size_log2 - 7;
            if inode_index_tree_internal_node_size_128b_log2 < allocation_block_size_128b_log2
                || inode_index_tree_internal_node_size_128b_log2 - allocation_block_size_128b_log2 > 6
            {
                let mut cmd = Cli::command();
                cmd.error(
                    clap::error::ErrorKind::ArgumentConflict,
                    "inode index tree internal node size not a multiple of the Allocation Block size between 0 and 64",
                )
                .exit()
            }
            inode_index_tree_internal_node_size_128b_log2 - allocation_block_size_128b_log2
        } else {
            0u32
        };

    let allocation_bitmap_file_block_allocation_blocks_log2 =
        if let Some(allocation_bitmap_file_block_size) = cli.allocation_bitmap_file_block_size {
            let allocation_bitmap_file_block_size_128b_log2 = allocation_bitmap_file_block_size.size_log2 - 7;
            if allocation_bitmap_file_block_size_128b_log2 < allocation_block_size_128b_log2 {
                let mut cmd = Cli::command();
                cmd.error(
                    clap::error::ErrorKind::ArgumentConflict,
                    "allocation bitmap block size not a multiple of the Allocation Block size",
                )
                .exit()
            }
            allocation_bitmap_file_block_size_128b_log2 - allocation_block_size_128b_log2
        } else {
            (9u32 - 7)
                .saturating_sub(allocation_block_size_128b_log2)
                .max(auth_tree_data_block_allocation_blocks_log2)
        };

    let (preimage_resistant_hash, collision_resistant_hash) = match cli.hash_familiy {
        #[cfg(feature = "sha2")]
        CliHashFamiliy::Sha2 => match cli.target_security_strength {
            CliSecurityStrength::S128 => (TpmiAlgHash::Sha256, TpmiAlgHash::Sha256),
            CliSecurityStrength::S192 => (TpmiAlgHash::Sha256, TpmiAlgHash::Sha384),
            CliSecurityStrength::S256 => (TpmiAlgHash::Sha256, TpmiAlgHash::Sha512),
        },
        #[cfg(feature = "sha3")]
        CliHashFamiliy::Sha3 => match cli.target_security_strength {
            CliSecurityStrength::S128 => (TpmiAlgHash::Sha3_256, TpmiAlgHash::Sha3_256),
            CliSecurityStrength::S192 => (TpmiAlgHash::Sha3_256, TpmiAlgHash::Sha3_384),
            CliSecurityStrength::S256 => (TpmiAlgHash::Sha3_256, TpmiAlgHash::Sha3_512),
        },
        #[cfg(feature = "sm3")]
        CliHashFamiliy::Sm3 => match cli.target_security_strength {
            CliSecurityStrength::S128 => (TpmiAlgHash::Sm3_256, TpmiAlgHash::Sm3_256),
            CliSecurityStrength::S192 | CliSecurityStrength::S256 => {
                let mut cmd = Cli::command();
                cmd.error(
                    clap::error::ErrorKind::ArgumentConflict,
                    "hash family sm3 doesn't support specified target security strength",
                )
                .exit();
            }
        },
    };

    let block_cipher_alg = match cli.block_cipher {
        #[cfg(feature = "aes")]
        CliBlockCipher::Aes => SymBlockCipherAlg::Aes(match cli.target_security_strength {
            CliSecurityStrength::S128 => symcipher::SymBlockCipherAesKeySize::Aes128,
            CliSecurityStrength::S192 => symcipher::SymBlockCipherAesKeySize::Aes192,
            CliSecurityStrength::S256 => symcipher::SymBlockCipherAesKeySize::Aes256,
        }),
        #[cfg(feature = "camellia")]
        CliBlockCipher::Camellia => SymBlockCipherAlg::Camellia(match cli.target_security_strength {
            CliSecurityStrength::S128 => symcipher::SymBlockCipherCamelliaKeySize::Camellia128,
            CliSecurityStrength::S192 => symcipher::SymBlockCipherCamelliaKeySize::Camellia192,
            CliSecurityStrength::S256 => symcipher::SymBlockCipherCamelliaKeySize::Camellia256,
        }),
        #[cfg(feature = "sm4")]
        CliBlockCipher::Sm4 => SymBlockCipherAlg::Sm4(match cli.target_security_strength {
            CliSecurityStrength::S128 => symcipher::SymBlockCipherSm4KeySize::Sm4_128,
            CliSecurityStrength::S192 | CliSecurityStrength::S256 => {
                let mut cmd = Cli::command();
                cmd.error(
                    clap::error::ErrorKind::ArgumentConflict,
                    "block cipher sm4 doesn't support specified target security strength",
                )
                .exit();
            }
        }),
    };

    match ImageLayout::new(
        allocation_block_size_128b_log2 as u8,
        io_block_allocation_blocks_log2 as u8,
        auth_tree_node_io_blocks_log2 as u8,
        auth_tree_data_block_allocation_blocks_log2 as u8,
        allocation_bitmap_file_block_allocation_blocks_log2 as u8,
        inode_index_tree_leaf_node_allocation_blocks_log2 as u8,
        inode_index_tree_internal_node_allocation_blocks_log2 as u8,
        collision_resistant_hash, // auth_tree_node_hash_alg
        collision_resistant_hash, // auth_tree_data_hmac_hash_alg
        preimage_resistant_hash,  // auth_tree_root_hmac_hash_alg
        preimage_resistant_hash,  // preauth_cca_protection_hmac_hash_alg
        preimage_resistant_hash,  // kdf_hash_alg
        block_cipher_alg,
    ) {
        Ok(image_layout) => image_layout,
        Err(e) => {
            eprintln!("error: invalid filesystem configuration parameters: {e:?}");
            std::process::exit(3);
        }
    }
}

fn load_key(key_source: CliKeySourceRef<'_>) -> FixedVec<u8, 4> {
    if let Some(src_key) = key_source.key {
        let mut key = FixedVec::new_with_default(src_key.len()).unwrap();
        key.copy_from_slice(src_key);
        key
    } else if let Some(key_file_path) = key_source.key_file_path {
        let src_key = match fs::read(key_file_path) {
            Ok(src_key) => src_key,
            Err(e) => {
                eprintln!("error: failed to read key file: error={e}");
                std::process::exit(4);
            }
        };
        let mut key = FixedVec::new_with_default(src_key.len()).unwrap();
        key.copy_from_slice(&src_key);
        key
    } else {
        // The CLI parser ensures there's either of the two.
        debug_assert!(false);
        eprintln!("error: no key source specified on command line");
        std::process::exit(2);
    }
}

fn load_salt(salt_source: &CliSaltSource) -> FixedVec<u8, 4> {
    if let Some(src_salt) = salt_source.salt.as_ref() {
        let mut salt = FixedVec::new_with_default(src_salt.len()).unwrap();
        salt.copy_from_slice(src_salt);
        salt
    } else if let Some(salt_file_path) = salt_source.salt_file_path.as_ref() {
        let src_salt = match fs::read(salt_file_path) {
            Ok(src_salt) => src_salt,
            Err(e) => {
                eprintln!("error: failed to read salt file: error={e}");
                std::process::exit(4);
            }
        };
        let mut salt = FixedVec::new_with_default(src_salt.len()).unwrap();
        salt.copy_from_slice(&src_salt);
        salt
    } else {
        // The CLI parser ensures there's either of the two.
        debug_assert!(false);
        eprintln!("error: no salt source specified on command line");
        std::process::exit(2);
    }
}

const fn rng_hash_drbg_hash() -> TpmiAlgHash {
    let candidates: &[TpmiAlgHash] = &[
        #[cfg(feature = "sha2")]
        TpmiAlgHash::Sha512,
        #[cfg(feature = "sha3")]
        TpmiAlgHash::Sha3_512,
        #[cfg(feature = "sm3")]
        TpmiAlgHash::Sm3_256,
    ];
    candidates[0]
}

fn instantiate_rng() -> Box<rng::HashDrbg> {
    let drbg_hash = rng_hash_drbg_hash();
    let seed_len = rng::HashDrbg::min_seed_entropy_len(drbg_hash);
    let mut seed = FixedVec::<u8, 5>::new_with_default(seed_len).unwrap();
    if let Err(e) = getrandom::fill(&mut seed) {
        eprintln!("failed to obtain entropy for RNG seeding: error={e}");
        std::process::exit(4);
    }
    match rng::HashDrbg::instantiate(drbg_hash, &seed, None, Some(b"cocoonfs-cli")) {
        Ok(rng) => Box::new(rng),
        Err(e) => {
            eprintln!("failed to instantiate RNG: error={e:?}");
            std::process::exit(4);
        }
    }
}

fn open_volume_file_for_mkfs(
    volume_file_path: &PathBuf,
    image_size: Option<u64>,
    max_io_block_size_128b_log2: Option<u32>,
) -> StdFileNvBlkDev {
    let mut open_flags = fs::OpenOptions::new();
    // We also want O_DIRECT, but standard Rust doesn't make it available.
    open_flags.read(true).write(true);
    if image_size.is_some() {
        // A pre-existing file isn't needed for determining the desired image size.
        open_flags.create(true);
    }
    let volume_file = match open_flags.open(volume_file_path) {
        Ok(volume_file) => volume_file,
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound && image_size.is_none() {
                eprintln!("error: filesystem image volume file doen't exist and no filesystem image size specified");
                std::process::exit(4);
            } else {
                eprintln!("error: failed to open filesystem image volume file: error={e}");
                std::process::exit(4);
            }
        }
    };

    // Truncate, ignore errors.
    match volume_file.set_len(0) {
        Ok(()) | Err(_) => (),
    };

    match StdFileNvBlkDev::new(volume_file, max_io_block_size_128b_log2) {
        Ok(blkdev) => blkdev,
        Err(_) => std::process::exit(5),
    }
}

fn open_blkdev(volume_file_path: &PathBuf, max_io_block_size_128b_log2: Option<u32>) -> StdFileNvBlkDev {
    let mut open_flags = fs::OpenOptions::new();
    // We also want O_DIRECT, but standard Rust doesn't make it available.
    open_flags.read(true).write(true);
    let volume_file = match open_flags.open(volume_file_path) {
        Ok(volume_file) => volume_file,
        Err(e) => {
            eprintln!("error: failed to open filesystem image volume file: error={e}");
            std::process::exit(4);
        }
    };

    match StdFileNvBlkDev::new(volume_file, max_io_block_size_128b_log2) {
        Ok(blkdev) => blkdev,
        Err(_) => std::process::exit(5),
    }
}

#[allow(clippy::type_complexity)]
fn open_filesystem(
    blkdev: StdFileNvBlkDev,
    key: &[u8],
    enable_trimming: bool,
) -> (
    Pin<
        <<StdSyncTypes as sync_types::SyncTypes>::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>::SyncRcPtr<
            CocoonFsType,
        >,
    >,
    Box<dyn rng::RngCoreDispatchable + Send>,
) {
    let rng = instantiate_rng();
    let key = zeroize::Zeroizing::new(key.to_vec());
    let openfs_fut = match OpenFsFuture::<StdSyncTypes, StdFileNvBlkDev>::new(blkdev, None, key, enable_trimming, rng) {
        Ok(openfs_fut) => openfs_fut,
        Err((_blkdev, _key, _rng, e)) => {
            eprintln!("error: failed to initiate CocoonFS filesystem opening operation: error={e:?}");
            std::process::exit(6);
        }
    };
    match openfs_fut.block_on() {
        Ok((rng, Ok(fs_instance))) => (fs_instance, rng),
        Ok((_, Err((_, _, e)))) | Err(e) => {
            eprintln!("error: failed to open CocoonFS filesystem: error={e:?}");
            std::process::exit(6);
        }
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        CliCommand::Mkfs(cli_mkfs_args) => {
            let image_layout = cli_mkfs_to_image_layout(&cli_mkfs_args.mkfsinfo);
            let key = load_key(CliKeySourceRef::from(&cli_mkfs_args.key));
            let salt = load_salt(&cli_mkfs_args.mkfsinfo.salt);
            let mut aux_fs_metadata = AuxFsMetadata::new();
            if let Err(e) = aux_fs_metadata
                .set_extra_reserve_capacity(cli_mkfs_args.mkfsinfo.aux_fs_metadata_extra_reserve_capacity.capacity)
            {
                eprintln!("error: failed to set auxiliary filesystem metadata extra reserve capacity: error={e:?}");
                std::process::exit(6);
            }

            let rng = instantiate_rng();
            let blkdev = open_volume_file_for_mkfs(
                &cli.volume_file_path,
                cli_mkfs_args.mkfsinfo.image_size.map(u64::from),
                (cli.ignore_volume_file_io_block_size).then_some(
                    image_layout.io_block_allocation_blocks_log2 as u32
                        + image_layout.allocation_block_size_128b_log2 as u32,
                ),
            );
            let mkfs_fut = match MkFsFuture::<StdSyncTypes, StdFileNvBlkDev>::new(
                blkdev,
                &image_layout,
                salt,
                aux_fs_metadata,
                cli_mkfs_args.mkfsinfo.image_size.map(u64::from),
                &key,
                cli_mkfs_args.enable_trimming,
                rng,
            ) {
                Ok(mkfs_fut) => mkfs_fut,
                Err((_blkdev, _rng, e)) => {
                    eprintln!("error: failed to initiate CocoonFS mkfs operation: error={e:?}");
                    std::process::exit(6);
                }
            };
            match mkfs_fut.block_on() {
                Ok((_rng, Ok(_fs_instance))) => (),
                Ok((_, Err((_, e)))) | Err(e) => {
                    eprintln!("error: CocoonFS mkfs operation failed: error={e:?}");
                    std::process::exit(6);
                }
            }
        }
        CliCommand::WriteMkfsInfoHeader(cli_write_mkfsinfo_header_args) => {
            let image_layout = cli_mkfs_to_image_layout(&cli_write_mkfsinfo_header_args.mkfsinfo);
            let salt = load_salt(&cli_write_mkfsinfo_header_args.mkfsinfo.salt);
            let mut aux_fs_metadata = AuxFsMetadata::new();
            if let Err(e) = aux_fs_metadata.set_extra_reserve_capacity(
                cli_write_mkfsinfo_header_args
                    .mkfsinfo
                    .aux_fs_metadata_extra_reserve_capacity
                    .capacity,
            ) {
                eprintln!("error: failed to set auxiliary filesystem metadata extra reserve capacity: error={e:?}");
                std::process::exit(6);
            }

            let blkdev = open_volume_file_for_mkfs(
                &cli.volume_file_path,
                cli_write_mkfsinfo_header_args.mkfsinfo.image_size.map(u64::from),
                (cli.ignore_volume_file_io_block_size).then_some(
                    image_layout.io_block_allocation_blocks_log2 as u32
                        + image_layout.allocation_block_size_128b_log2 as u32,
                ),
            );
            let write_mkfsinfo_header_fut = match WriteMkFsInfoHeaderFuture::new(
                blkdev,
                &image_layout,
                salt,
                aux_fs_metadata,
                cli_write_mkfsinfo_header_args.mkfsinfo.image_size.map(u64::from),
                !cli_write_mkfsinfo_header_args.trim_volume_file_to_header,
            ) {
                Ok(write_mkfsinfo_header_fut) => write_mkfsinfo_header_fut,
                Err((_blkdev, e)) => {
                    eprintln!("error: failed to initiate CocoonFS mkfsinfo header write operation: error={e:?}");
                    std::process::exit(6);
                }
            };
            match write_mkfsinfo_header_fut.block_on() {
                Ok((_blkdev, Ok(()))) => (),
                Ok((_, Err(e))) | Err(e) => {
                    eprintln!("error: CocoonFS mkfsinfo header write operation failed: error={e:?}");
                    std::process::exit(6);
                }
            }
        }
        CliCommand::AuxFsMetadata(cli_aux_fs_metdata_command) => {
            let blkdev = open_blkdev(&cli.volume_file_path, cli.ignore_volume_file_io_block_size.then_some(0));
            let read_fs_metadata_fut = match ReadFsMetadataFuture::new(blkdev) {
                Ok(read_fs_metadata_fut) => read_fs_metadata_fut,
                Err((_blkdev, e)) => {
                    eprintln!("error: failed to initiate CocoonFS metadata read operation: error={e:?}");
                    std::process::exit(6);
                }
            };
            let (blkdev, fs_metadata) = match read_fs_metadata_fut.block_on() {
                Ok((blkdev, Ok(fs_metadata))) => (blkdev, fs_metadata),
                Ok((_, Err(e))) | Err(e) => {
                    eprintln!("error: failed to read CocoonFS metadata: error={e:?}");
                    std::process::exit(6);
                }
            };

            match cli_aux_fs_metdata_command {
                CliAuxFsMetadataCommand::ListEntries => {
                    for entry in fs_metadata.get_aux().iter() {
                        println!("{}", CliUuidValue { uuid: *entry.0 });
                    }
                }
                CliAuxFsMetadataCommand::ReadEntry(cli_read_entry_args) => {
                    let mut index = cli_read_entry_args.index;
                    let mut found_entry = None;
                    for entry in fs_metadata.get_aux().iter() {
                        if *entry.0 == cli_read_entry_args.uuid.uuid {
                            if index == 0 {
                                found_entry = Some(entry);
                                break;
                            } else {
                                index -= 1;
                            }
                        }
                    }

                    let data = match found_entry {
                        Some(found_entry) => found_entry.1,
                        None => {
                            eprintln!("error: auxiliary filesystem metadata entry does not exist");
                            std::process::exit(6);
                        }
                    };

                    match cli_read_entry_args.out_file_path {
                        Some(out_file_path) => {
                            if let Err(e) = fs::write(out_file_path, data) {
                                eprintln!("error: failed to write data to output file: error={e}");
                                std::process::exit(4);
                            }
                        }
                        None => {
                            if let Err(e) = io::stdout().write_all(data) {
                                eprintln!("error: failed to write data to standard output: error={e}");
                                std::process::exit(4);
                            }
                        }
                    };
                }
                CliAuxFsMetadataCommand::Edit(cli_edit_args) => {
                    let mut updated_aux_fs_metadata = fs_metadata.get_aux().try_clone().unwrap();
                    match cli_edit_args.command {
                        CliAuxFsMetadataEditCommand::SetExtraReserveCapacity(cli_set_reserve_capacity_args) => {
                            if let Err(e) = updated_aux_fs_metadata.set_extra_reserve_capacity(
                                cli_set_reserve_capacity_args.extra_reserve_capacity.capacity,
                            ) {
                                eprintln!(
                                    "error: failed to set auxiliary filesystem metadata extra reserve capacity: error={e:?}"
                                );
                                std::process::exit(6);
                            }
                        }
                        CliAuxFsMetadataEditCommand::AddEntry(cli_add_entry_args) => {
                            let mut data = Vec::new();
                            match cli_add_entry_args.in_file_path.as_ref() {
                                Some(in_file_path) => match fs::read(in_file_path) {
                                    Ok(result) => data = result,
                                    Err(e) => {
                                        eprintln!("error: failed to read data from input file: error={e}");
                                        std::process::exit(4);
                                    }
                                },
                                None => {
                                    if let Err(e) = io::stdin().read_to_end(&mut data) {
                                        eprintln!("error: failed to read data from standard input: error={e}");
                                        std::process::exit(4);
                                    }
                                }
                            };

                            if let Err(e) = updated_aux_fs_metadata.add_entry(&cli_add_entry_args.uuid.uuid, &data) {
                                eprintln!("error: failed to add auxiliary filesystem metadata entry: error={e:?}");
                                std::process::exit(6);
                            }
                        }
                        CliAuxFsMetadataEditCommand::RemoveEntry(cli_remove_entry_args) => {
                            if !updated_aux_fs_metadata
                                .remove_entry(cli_remove_entry_args.uuid.uuid, cli_remove_entry_args.index)
                            {
                                eprintln!("error: auxiliary filesystem metadata entry does not exist");
                                std::process::exit(6);
                            }
                        }
                    }

                    // If there's a filesystem creation info header, then don't format the
                    // filesystem and do an offline update.
                    match Option::<CliKeySourceRef>::from(&cli_edit_args.key)
                        .filter(|_| matches!(&fs_metadata, FsMetadata::Formatted(_)))
                    {
                        Some(key_source) => {
                            let key = load_key(key_source);
                            // The filesystem is formatted and a key has been provided, open the
                            // filesystem and apply the update through a transaction.
                            let (fs_instance, rng) = open_filesystem(blkdev, &key, cli_edit_args.enable_trimming);
                            let (transaction, rng) = match NvFsFutureAsCoreFuture::new(
                                fs_instance.clone(),
                                <CocoonFsType as NvFs>::start_transaction(
                                    &cocoonfs_mk_fs_instance_ref(&fs_instance),
                                    None,
                                ),
                                rng,
                            )
                            .block_on()
                            {
                                Ok((rng, Ok(transaction))) => (transaction, rng),
                                Ok((_, Err(e))) | Err(e) => {
                                    eprintln!("error: failed to start CocoonFS transaction: error={e:?}");
                                    std::process::exit(6);
                                }
                            };

                            let (transaction, rng) = match NvFsFutureAsCoreFuture::new(
                                fs_instance.clone(),
                                CocoonFsType::write_aux_fs_metadata(
                                    &cocoonfs_mk_fs_instance_ref(&fs_instance),
                                    transaction,
                                    updated_aux_fs_metadata,
                                ),
                                rng,
                            )
                            .block_on()
                            {
                                Ok((rng, (_updated_aux_fs_metadata, Ok((transaction, Ok(())))))) => (transaction, rng),
                                Ok((_, (_, Ok((_, Err(e)))))) | Ok((_, (_, Err(e)))) | Err(e) => {
                                    eprintln!(
                                        "error: failed to stage auxiliary fileystem metadata update at CocoonFS transaction: error={e:?}"
                                    );
                                    std::process::exit(6);
                                }
                            };

                            match NvFsFutureAsCoreFuture::new(
                                fs_instance.clone(),
                                <CocoonFsType as NvFs>::commit_transaction(
                                    &cocoonfs_mk_fs_instance_ref(&fs_instance),
                                    transaction,
                                    None,
                                    None,
                                    true,
                                ),
                                rng,
                            )
                            .block_on()
                            {
                                Ok((_rng, Ok(()))) => (),
                                Ok((_rng, Err(e))) => {
                                    eprintln!("error: failed to commit CocoonFS transaction: error={e:?}");
                                    std::process::exit(6);
                                }
                                Err(e) => {
                                    eprintln!("error: failed to commit CocoonFS transaction: error={e:?}");
                                    std::process::exit(6);
                                }
                            }
                        }
                        None => {
                            // There's only a filesystem creation info header of the key wasn't
                            // provided, apply through an offline update.
                            match WriteAuxFsMetadataOfflineFuture::new(blkdev, fs_metadata, updated_aux_fs_metadata)
                                .block_on()
                            {
                                Ok((_blkdev, Ok(_updated_aux_fs_metadata))) => (),
                                Ok((_, Err(e))) | Err(e) => {
                                    eprintln!(
                                        "error: failed to write auxiliary fileystem metadata update: error={e:?}"
                                    );
                                    std::process::exit(6);
                                }
                            }
                        }
                    }
                }
            }
        }
        CliCommand::WriteFile(cli_write_file_args) => {
            let mut data = Vec::new();
            match cli_write_file_args.in_file_path.as_ref() {
                Some(in_file_path) => match fs::read(in_file_path) {
                    Ok(result) => data = result,
                    Err(e) => {
                        eprintln!("error: failed to read data from input file: error={e}");
                        std::process::exit(4);
                    }
                },
                None => {
                    if let Err(e) = io::stdin().read_to_end(&mut data) {
                        eprintln!("error: failed to read data from standard input: error={e}");
                        std::process::exit(4);
                    }
                }
            };

            let key = load_key(CliKeySourceRef::from(&cli_write_file_args.key));

            // If the volume file's block size is to be ignored, the it would be best to
            // resort to using the IO block size recorded in the filesystem
            // header. But that's not known as it currently stands, so use the
            // minimum possible then.
            let blkdev = open_blkdev(&cli.volume_file_path, cli.ignore_volume_file_io_block_size.then_some(0));
            let (fs_instance, rng) = open_filesystem(blkdev, &key, cli_write_file_args.enable_trimming);

            let (transaction, rng) = match NvFsFutureAsCoreFuture::new(
                fs_instance.clone(),
                <CocoonFsType as NvFs>::start_transaction(&cocoonfs_mk_fs_instance_ref(&fs_instance), None),
                rng,
            )
            .block_on()
            {
                Ok((rng, Ok(transaction))) => (transaction, rng),
                Ok((_, Err(e))) | Err(e) => {
                    eprintln!("error: failed to start CocoonFS transaction: error={e:?}");
                    std::process::exit(6);
                }
            };

            let (transaction, rng) = match NvFsFutureAsCoreFuture::new(
                fs_instance.clone(),
                <CocoonFsType as NvFs>::write_inode(
                    &cocoonfs_mk_fs_instance_ref(&fs_instance),
                    transaction,
                    cli_write_file_args.inode,
                    cli_write_file_args.inode_flags,
                    0xffu8,
                    zeroize::Zeroizing::new(data),
                ),
                rng,
            )
            .block_on()
            {
                Ok((rng, (_data, Ok((transaction, Ok(())))))) => (transaction, rng),
                Ok((_, (_, Ok((_, Err(e)))))) | Ok((_, (_, Err(e)))) | Err(e) => {
                    eprintln!("error: failed to stage file write at CocoonFS transaction: error={e:?}");
                    std::process::exit(6);
                }
            };

            match NvFsFutureAsCoreFuture::new(
                fs_instance.clone(),
                <CocoonFsType as NvFs>::commit_transaction(
                    &cocoonfs_mk_fs_instance_ref(&fs_instance),
                    transaction,
                    None,
                    None,
                    true,
                ),
                rng,
            )
            .block_on()
            {
                Ok((_rng, Ok(()))) => (),
                Ok((_rng, Err(e))) => {
                    eprintln!("error: failed to commit CocoonFS transaction: error={e:?}");
                    std::process::exit(6);
                }
                Err(e) => {
                    eprintln!("error: failed to commit CocoonFS transaction: error={e:?}");
                    std::process::exit(6);
                }
            }
        }
        CliCommand::ReadFile(cli_read_file_args) => {
            let key = load_key(CliKeySourceRef::from(&cli_read_file_args.key));

            // If the volume file's block size is to be ignored, the it would be best to
            // resort to using the IO block size recorded in the filesystem
            // header. But that's not known as it currently stands, so use the
            // minimum possible then.
            let blkdev = open_blkdev(&cli.volume_file_path, cli.ignore_volume_file_io_block_size.then_some(0));
            let (fs_instance, rng) = open_filesystem(blkdev, &key, cli_read_file_args.enable_trimming);

            let result = match NvFsFutureAsCoreFuture::new(
                fs_instance.clone(),
                <CocoonFsType as NvFs>::read_inode(
                    &cocoonfs_mk_fs_instance_ref(&fs_instance),
                    None,
                    cli_read_file_args.inode,
                ),
                rng,
            )
            .block_on()
            {
                Ok((_rng, Ok((_read_seq, Ok(result))))) => result,
                Ok((_, Ok((_, Err(e))))) | Ok((_, Err(e))) | Err(e) => {
                    eprintln!("error: failed to read CocoonFS inode data: error={e:?}");
                    std::process::exit(6);
                }
            };

            let data = match result {
                Some(result) => result.1,
                None => {
                    eprintln!("error: CocoonFS inode doesn't exist");
                    std::process::exit(6);
                }
            };

            match cli_read_file_args.out_file_path {
                Some(out_file_path) => {
                    if let Err(e) = fs::write(out_file_path, &data) {
                        eprintln!("error: failed to write data to output file: error={e}");
                        std::process::exit(4);
                    }
                }
                None => {
                    if let Err(e) = io::stdout().write_all(&data) {
                        eprintln!("error: failed to write data to standard output: error={e}");
                        std::process::exit(4);
                    }
                }
            };
        }
        CliCommand::ListFiles(cli_list_files_args) => {
            let key = load_key(CliKeySourceRef::from(&cli_list_files_args.key));

            // If the volume file's block size is to be ignored, the it would be best to
            // resort to using the IO block size recorded in the filesystem
            // header. But that's not known as it currently stands, so use the
            // minimum possible then.
            let blkdev = open_blkdev(&cli.volume_file_path, cli.ignore_volume_file_io_block_size.then_some(0));
            let (fs_instance, rng) = open_filesystem(blkdev, &key, cli_list_files_args.enable_trimming);

            let (consistent_read_sequence, mut rng) = match NvFsFutureAsCoreFuture::new(
                fs_instance.clone(),
                <CocoonFsType as NvFs>::start_read_sequence(&cocoonfs_mk_fs_instance_ref(&fs_instance)),
                rng,
            )
            .block_on()
            {
                Ok((rng, Ok(consistent_read_sequence))) => (consistent_read_sequence, rng),
                Ok((_, Err(e))) | Err(e) => {
                    eprintln!("error: failed to start consistent CocoonFS read sequence: error={e:?}");
                    std::process::exit(6);
                }
            };

            let mut enumerate_cursor = match <CocoonFsType as NvFs>::enumerate_cursor(
                &cocoonfs_mk_fs_instance_ref(&fs_instance),
                NvFsReadContext::Committed {
                    seq: consistent_read_sequence,
                },
                6..=u64::MAX,
            ) {
                Ok(Ok(enumerate_cursor)) => enumerate_cursor,
                Ok(Err((_, e))) | Err(e) => {
                    eprintln!("error: failed to instantiate CocoonFS enumeration cursor: error={e:?}");
                    std::process::exit(6);
                }
            };

            loop {
                let inode;
                (enumerate_cursor, rng, inode) =
                    match NvFsFutureAsCoreFuture::new(fs_instance.clone(), enumerate_cursor.next(), rng).block_on() {
                        Ok((rng, Ok((enumerate_cursor, Ok(inode))))) => (enumerate_cursor, rng, inode),
                        Ok((_, Ok((_, Err(e))))) | Ok((_, Err(e))) | Err(e) => {
                            eprintln!("error: failed to advance CocoonFS enumeration cursor: error={e:?}");
                            std::process::exit(6);
                        }
                    };

                match inode {
                    Some(inode) => {
                        let (inode, inode_flags) = inode;
                        println!("{inode} {inode_flags:#04x}")
                    }
                    None => break,
                };
            }
        }
        CliCommand::RemoveFile(cli_remove_file_args) => {
            let key = load_key(CliKeySourceRef::from(&cli_remove_file_args.key));

            // If the volume file's block size is to be ignored, the it would be best to
            // resort to using the IO block size recorded in the filesystem
            // header. But that's not known as it currently stands, so use the
            // minimum possible then.
            let blkdev = open_blkdev(&cli.volume_file_path, cli.ignore_volume_file_io_block_size.then_some(0));
            let (fs_instance, rng) = open_filesystem(blkdev, &key, cli_remove_file_args.enable_trimming);

            let (transaction, mut rng) = match NvFsFutureAsCoreFuture::new(
                fs_instance.clone(),
                <CocoonFsType as NvFs>::start_transaction(&cocoonfs_mk_fs_instance_ref(&fs_instance), None),
                rng,
            )
            .block_on()
            {
                Ok((rng, Ok(transaction))) => (transaction, rng),
                Ok((_, Err(e))) | Err(e) => {
                    eprintln!("error: failed to start CocoonFS transaction: error={e:?}");
                    std::process::exit(6);
                }
            };

            let mut unlink_cursor = match <CocoonFsType as NvFs>::unlink_cursor(
                &cocoonfs_mk_fs_instance_ref(&fs_instance),
                transaction,
                cli_remove_file_args.inode..=cli_remove_file_args.inode,
            ) {
                Ok(Ok(unlink_cursor)) => unlink_cursor,
                Ok(Err((_, e))) | Err(e) => {
                    eprintln!("error: failed to instantiate CocoonFS unlink cursor: error={e:?}");
                    std::process::exit(6);
                }
            };

            loop {
                let inode;
                (unlink_cursor, rng, inode) =
                    match NvFsFutureAsCoreFuture::new(fs_instance.clone(), unlink_cursor.next(), rng).block_on() {
                        Ok((rng, Ok((unlink_cursor, Ok(inode))))) => (unlink_cursor, rng, inode),
                        Ok((_, Ok((_, Err(e))))) | Ok((_, Err(e))) | Err(e) => {
                            eprintln!("error: failed to advance CocoonFS unlink cursor: error={e:?}");
                            std::process::exit(6);
                        }
                    };

                if inode.is_none() {
                    break;
                }

                (unlink_cursor, rng) =
                    match NvFsFutureAsCoreFuture::new(fs_instance.clone(), unlink_cursor.unlink_current_inode(), rng)
                        .block_on()
                    {
                        Ok((rng, Ok((unlink_cursor, Ok(()))))) => (unlink_cursor, rng),
                        Ok((_, Ok((_, Err(e))))) | Ok((_, Err(e))) | Err(e) => {
                            eprintln!("error: failed to stage inode removal at CocoonFS transaction: error={e:?}");
                            std::process::exit(6);
                        }
                    };
            }

            let transaction = match unlink_cursor.into_transaction() {
                Ok(transaction) => transaction,
                Err(e) => {
                    eprintln!("error: failed to retrieve transaction from CocoonFS unlink cursor: error={e:?}");
                    std::process::exit(6);
                }
            };

            match NvFsFutureAsCoreFuture::new(
                fs_instance.clone(),
                <CocoonFsType as NvFs>::commit_transaction(
                    &cocoonfs_mk_fs_instance_ref(&fs_instance),
                    transaction,
                    None,
                    None,
                    true,
                ),
                rng,
            )
            .block_on()
            {
                Ok((_rng, Ok(()))) => (),
                Ok((_rng, Err(e))) => {
                    eprintln!("error: failed to commit CocoonFS transaction: error={e:?}");
                    std::process::exit(6);
                }
                Err(e) => {
                    eprintln!("error: failed to commit CocoonFS transaction: error={e:?}");
                    std::process::exit(6);
                }
            }
        }
    }
}
