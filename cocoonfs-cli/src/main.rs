// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
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
        CocoonFs, CocoonFsImageLayout, CocoonFsMkFsFuture, CocoonFsOpenFsFuture, CocoonFsWriteMkfsInfoHeaderFuture,
    },
};
use tpm2_interface::TpmiAlgHash;
use utils_async::sync_types;
use utils_common::{fixed_vec::FixedVec, zeroize};

mod std_sync_types;
use std_sync_types::StdSyncTypes;
mod std_file_nvchip;
use std_file_nvchip::StdFileNvChip;

use clap::{self, CommandFactory as _, Parser as _};
use pollster::FutureExt as _;
use std::{
    fs,
    io::{self, Read, Write},
    path::PathBuf,
    pin::Pin,
};

type CocoonFsType = CocoonFs<StdSyncTypes, StdFileNvChip>;

fn cocoonfs_mk_fs_instance_ref(
    fs_instance: &<CocoonFsType as NvFs>::SyncRcPtr,
) -> <CocoonFsType as NvFs>::SyncRcPtrRef<'_> {
    type CocoonFsSyncRcPtr = <CocoonFsType as NvFs>::SyncRcPtr;
    <CocoonFsSyncRcPtr as sync_types::SyncRcPtr<_>>::as_ref(fs_instance)
}

fn cli_parse_size(arg: &str) -> Result<u64, clap::error::Error> {
    let arg = arg.trim_start();
    let unit_pos = arg.char_indices().find(|(_pos, c)| !c.is_ascii_digit());
    let (value, unit) = match unit_pos {
        Some((unit_pos, _)) => {
            let unit = &arg[unit_pos..].trim();
            if unit.is_empty() || *unit == "B" {
                (&arg[..unit_pos], 1u64)
            } else if *unit == "K" {
                (&arg[..unit_pos], 1024u64)
            } else if *unit == "M" {
                (&arg[..unit_pos], 1024u64 * 1024)
            } else if *unit == "G" {
                (&arg[..unit_pos], 1024u64 * 1024 * 1024)
            } else {
                return Err(clap::Error::raw(
                    clap::error::ErrorKind::ValueValidation,
                    "unrecognized unit, possible values: none|B, K, M, G",
                ));
            }
        }
        None => (arg.trim_end(), 1),
    };

    let value = match value.parse::<u64>() {
        Ok(value) => value,
        Err(_) => {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::ValueValidation,
                "value too large",
            ));
        }
    };

    value
        .checked_mul(unit)
        .ok_or_else(|| clap::Error::raw(clap::error::ErrorKind::ValueValidation, "value too large"))
}

fn cli_parse_power_of_two_size_log2<const MIN_VALUE_LOG2: u32>(arg: &str) -> Result<u32, clap::error::Error> {
    let size = cli_parse_size(arg)?;
    if !size.is_power_of_two() {
        Err(clap::Error::raw(
            clap::error::ErrorKind::ValueValidation,
            "value must be a power of two",
        ))
    } else if size >> MIN_VALUE_LOG2 == 0 {
        Err(clap::Error::raw(
            clap::error::ErrorKind::ValueValidation,
            format!("value must be >= {}", 1u64 << MIN_VALUE_LOG2,),
        ))
    } else {
        Ok(size.ilog2())
    }
}

fn cli_parse_hexstr(arg: &str) -> Result<FixedVec<u8, 4>, clap::error::Error> {
    fn nibble_from_hex(hexchar: u8) -> Result<u8, clap::error::Error> {
        Ok(hexchar
            - match hexchar {
                b'0'..=b'9' => b'0',
                b'a'..=b'f' => b'a' - 0xa,
                b'A'..=b'F' => b'A' - 0xa,
                _ => {
                    return Err(clap::Error::raw(
                        clap::error::ErrorKind::ValueValidation,
                        "invalid digit in hexadecimal string",
                    ));
                }
            })
    }

    fn byte_from_hex(hexstr: &[u8; 2]) -> Result<u8, clap::error::Error> {
        let mut result = 0u8;
        for hexchar in hexstr {
            let nibble = nibble_from_hex(*hexchar)?;
            result = result << 4 | nibble;
        }
        Ok(result)
    }

    let arg = arg.trim();
    let arg = arg.as_bytes();
    let len = arg.len().div_ceil(2);
    let mut result = FixedVec::new_with_default(len).unwrap();

    let (src, dst) = if arg.len() % 2 != 0 {
        // Pad with a zero nibble at the head.
        result[0] = nibble_from_hex(arg[0])?;
        (&arg[1..], &mut result[1..])
    } else {
        (arg, &mut *result)
    };

    for (i, hexdigit_pair) in src.chunks_exact(2).enumerate() {
        let hexdigit_pair = <&[u8; 2]>::try_from(hexdigit_pair).unwrap();
        dst[i] = byte_from_hex(hexdigit_pair)?;
    }

    Ok(result)
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
    #[arg(value_name="INODE-NUMBER", value_parser = clap::value_parser!(u32).range(6..))]
    inode: u32,
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
    #[arg(value_name="INODE-NUMBER", value_parser = clap::value_parser!(u32).range(6..))]
    inode: u32,
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
    #[arg(value_name="INODE-NUMBER", value_parser = clap::value_parser!(u32).range(6..))]
    inode: u32,
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
    #[arg(name = "image-size", long, short = 's', value_name = "SIZE", value_parser = cli_parse_size)]
    image_size: Option<u64>,

    /// Allocation Block size [default: 128B]
    ///
    /// Unit of allocation. Must be a power of two >= 128B.
    #[arg(
        name = "allocation-block-size",
        long,
        value_name = "SIZE",
        value_parser = cli_parse_power_of_two_size_log2::<7>
    )]
    allocation_block_size_log2: Option<u32>,

    /// IO Block size [default: max of 512B and Allocation Block size].
    ///
    /// Upper bound on the supported storage hardware's native IO size. Must be
    /// a power of two multiple <= 64 of the Allocation Block size.
    #[arg(name = "io-block-size", long, value_name = "SIZE", value_parser = cli_parse_power_of_two_size_log2::<7>)]
    io_block_size_log2: Option<u32>,

    /// Authentication Tree Data Block size [default: IO Block size].
    ///
    /// Unit of data authentication, controlling the fan-out at the
    /// authentication tree leaf nodes: larger values decrease the
    /// authentication tree height, but at the cost of making data
    /// authentication more coarse grained. Must be a power of two multiple <=
    /// 64 of the Allocation Block size.
    #[arg(
        name = "auth-tree-data-block-size",
        long,
        value_name = "SIZE",
        value_parser = cli_parse_power_of_two_size_log2::<7>
    )]
    auth_tree_data_block_size_log2: Option<u32>,

    /// Authentication Tree node size [default: max of 1024B and IO Block size].
    ///
    /// Size of an authentication tree node, controlling the tree's branching
    /// factor: larger values decrease the authentication tree height, but
    /// at the cost of having to process larger nodes. Must be a power of
    /// two >= the IO Block size.
    #[arg(
        name = "auth-tree-node-size",
        long,
        value_name = "SIZE",
        value_parser = cli_parse_power_of_two_size_log2::<7>
    )]
    auth_tree_node_size_log2: Option<u32>,

    /// Inode index B+-tree node size [default: Allocation Block size].
    ///
    /// Size of a node in the inode index B+-tree, controlling the tree's
    /// branching factor. Must be a power of two multiple <= 64 of the
    /// Allocation Block size.
    #[arg(
        name = "inode-index-tree-node-size",
        long,
        value_name = "SIZE",
        value_parser = cli_parse_power_of_two_size_log2::<7>
    )]
    inode_index_tree_node_size_log2: Option<u32>,

    /// Allocation bitmap block size [default: max of 512B and the
    /// Authentication Tree Data Block size].
    ///
    /// Encryption granularity of the Allocation bitmap. Each unit stores an IV,
    /// so larger values reduce the overhead, but increase the update
    /// granularity. Must be a power of two >= the Allocation Block size.
    #[arg(
        name = "allocation-bitmap-block-size",
        long,
        value_name = "SIZE",
        value_parser = cli_parse_power_of_two_size_log2::<7>
    )]
    allocation_bitmap_file_block_size_log2: Option<u32>,
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
    #[arg(name = "key", short = 'K', long, value_name = "HEX", value_parser = cli_parse_hexstr)]
    key: Option<FixedVec<u8, 4>>,
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
    #[arg(name = "salt", long, short = 'I', value_name = "HEX", value_parser = cli_parse_hexstr)]
    salt: Option<FixedVec<u8, 4>>,
}

fn cli_mkfs_to_cocoonfs_image_layout(cli: &CliMkfsInfo) -> CocoonFsImageLayout {
    let allocation_block_size_128b_log2 = cli
        .allocation_block_size_log2
        .map(|allocation_block_size_log2| allocation_block_size_log2 - 7)
        .unwrap_or(0);

    let io_block_allocation_blocks_log2 = if let Some(io_block_size_log2) = cli.io_block_size_log2 {
        let io_block_size_128b_log2 = io_block_size_log2 - 7;
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
        if let Some(auth_tree_data_block_size_log2) = cli.auth_tree_data_block_size_log2 {
            let auth_tree_data_block_size_128b_log2 = auth_tree_data_block_size_log2 - 7;
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

    let auth_tree_node_io_blocks_log2 = if let Some(auth_tree_node_size_log2) = cli.auth_tree_node_size_log2 {
        let auth_tree_node_size_128b_log2 = auth_tree_node_size_log2 - 7;
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

    let inode_index_tree_node_allocation_blocks_log2 =
        if let Some(inode_index_tree_node_size_log2) = cli.inode_index_tree_node_size_log2 {
            let inode_index_tree_node_size_128b_log2 = inode_index_tree_node_size_log2 - 7;
            if inode_index_tree_node_size_128b_log2 < allocation_block_size_128b_log2
                || inode_index_tree_node_size_128b_log2 - allocation_block_size_128b_log2 > 6
            {
                let mut cmd = Cli::command();
                cmd.error(
                    clap::error::ErrorKind::ArgumentConflict,
                    "inode index tree node size not a multiple of the Allocation Block size between 0 and 64",
                )
                .exit()
            }
            inode_index_tree_node_size_128b_log2 - allocation_block_size_128b_log2
        } else {
            0u32
        };

    let allocation_bitmap_file_block_allocation_blocks_log2 =
        if let Some(allocation_bitmap_file_block_size_log2) = cli.allocation_bitmap_file_block_size_log2 {
            let allocation_bitmap_file_block_size_128b_log2 = allocation_bitmap_file_block_size_log2 - 7;
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

    match CocoonFsImageLayout::new(
        allocation_block_size_128b_log2 as u8,
        io_block_allocation_blocks_log2 as u8,
        auth_tree_node_io_blocks_log2 as u8,
        auth_tree_data_block_allocation_blocks_log2 as u8,
        allocation_bitmap_file_block_allocation_blocks_log2 as u8,
        inode_index_tree_node_allocation_blocks_log2 as u8,
        collision_resistant_hash, // auth_tree_node_hash_alg
        collision_resistant_hash, // auth_tree_data_hmac_hash_alg
        preimage_resistant_hash,  // auth_tree_root_hmac_hash_alg
        preimage_resistant_hash,  // preauth_cca_protection_hmac_hash_alg
        preimage_resistant_hash,  // kdf_hash_alg
        block_cipher_alg,
    ) {
        Ok(image_layout) => image_layout,
        Err(e) => {
            eprintln!("error: invalid filesystem configuration parameters: {:?}", e);
            std::process::exit(3);
        }
    }
}

fn load_key(key_source: &CliKeySource) -> FixedVec<u8, 4> {
    if let Some(src_key) = key_source.key.as_ref() {
        let mut key = FixedVec::new_with_default(src_key.len()).unwrap();
        key.copy_from_slice(src_key);
        key
    } else if let Some(key_file_path) = key_source.key_file_path.as_ref() {
        let src_key = match fs::read(key_file_path) {
            Ok(src_key) => src_key,
            Err(e) => {
                eprintln!("error: failed to read key file: error={}", e);
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
                eprintln!("error: failed to read salt file: error={}", e);
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
        eprintln!("failed to obtain entropy for RNG seeding: error={}", e);
        std::process::exit(4);
    }
    match rng::HashDrbg::instantiate(drbg_hash, &seed, None, Some(b"cocoonfs-cli")) {
        Ok(rng) => Box::new(rng),
        Err(e) => {
            eprintln!("failed to instantiate RNG: error={:?}", e);
            std::process::exit(4);
        }
    }
}

fn open_volume_file_for_mkfs(
    volume_file_path: &PathBuf,
    image_size: Option<u64>,
    max_io_block_size_128b_log2: Option<u32>,
) -> StdFileNvChip {
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
                eprintln!("error: failed to open filesystem image volume file: error={}", e);
                std::process::exit(4);
            }
        }
    };

    // Truncate, ignore errors.
    match volume_file.set_len(0) {
        Ok(()) | Err(_) => (),
    };

    match StdFileNvChip::new(volume_file, max_io_block_size_128b_log2) {
        Ok(chip) => chip,
        Err(_) => std::process::exit(5),
    }
}

#[allow(clippy::type_complexity)]
fn open_filesystem(
    volume_file_path: &PathBuf,
    key: &[u8],
    max_io_block_size_128b_log2: Option<u32>,
    enable_trimming: bool,
) -> (
    Pin<
        <<StdSyncTypes as sync_types::SyncTypes>::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>::SyncRcPtr<
            CocoonFsType,
        >,
    >,
    Box<dyn rng::RngCoreDispatchable + Send>,
) {
    let mut open_flags = fs::OpenOptions::new();
    // We also want O_DIRECT, but standard Rust doesn't make it available.
    open_flags.read(true).write(true);
    let volume_file = match open_flags.open(volume_file_path) {
        Ok(volume_file) => volume_file,
        Err(e) => {
            eprintln!("error: failed to open filesystem image volume file: error={}", e);
            std::process::exit(4);
        }
    };

    let chip = match StdFileNvChip::new(volume_file, max_io_block_size_128b_log2) {
        Ok(chip) => chip,
        Err(_) => std::process::exit(5),
    };
    let rng = instantiate_rng();
    let key = zeroize::Zeroizing::new(key.to_vec());
    let openfs_fut = match CocoonFsOpenFsFuture::<StdSyncTypes, StdFileNvChip>::new(chip, key, enable_trimming, rng) {
        Ok(openfs_fut) => openfs_fut,
        Err((_chip, _key, _rng, e)) => {
            eprintln!(
                "error: failed to initiate CocoonFS filesystem opening operation: error={:?}",
                e
            );
            std::process::exit(6);
        }
    };
    match openfs_fut.block_on() {
        Ok((rng, Ok(fs_instance))) => (fs_instance, rng),
        Ok((_, Err((_, _, e)))) | Err(e) => {
            eprintln!("error: failed to open CocoonFS filesystem: error={:?}", e);
            std::process::exit(6);
        }
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        CliCommand::Mkfs(cli_mkfs_args) => {
            let image_layout = cli_mkfs_to_cocoonfs_image_layout(&cli_mkfs_args.mkfsinfo);
            let key = load_key(&cli_mkfs_args.key);
            let salt = load_salt(&cli_mkfs_args.mkfsinfo.salt);

            let rng = instantiate_rng();
            let chip = open_volume_file_for_mkfs(
                &cli.volume_file_path,
                cli_mkfs_args.mkfsinfo.image_size,
                (cli.ignore_volume_file_io_block_size).then_some(
                    image_layout.io_block_allocation_blocks_log2 as u32
                        + image_layout.allocation_block_size_128b_log2 as u32,
                ),
            );
            let mkfs_fut = match CocoonFsMkFsFuture::<StdSyncTypes, StdFileNvChip>::new(
                chip,
                &image_layout,
                salt,
                cli_mkfs_args.mkfsinfo.image_size,
                &key,
                cli_mkfs_args.enable_trimming,
                rng,
            ) {
                Ok(mkfs_fut) => mkfs_fut,
                Err((_chip, _rng, e)) => {
                    eprintln!("error: failed to initiate CocoonFS mkfs operation: error={:?}", e);
                    std::process::exit(6);
                }
            };
            match mkfs_fut.block_on() {
                Ok((_rng, Ok(_fs_instance))) => (),
                Ok((_, Err((_, e)))) | Err(e) => {
                    eprintln!("error: CocoonFS mkfs operation failed: error={:?}", e);
                    std::process::exit(6);
                }
            }
        }
        CliCommand::WriteMkfsInfoHeader(cli_write_mkfsinfo_header_args) => {
            let image_layout = cli_mkfs_to_cocoonfs_image_layout(&cli_write_mkfsinfo_header_args.mkfsinfo);
            let salt = load_salt(&cli_write_mkfsinfo_header_args.mkfsinfo.salt);

            let chip = open_volume_file_for_mkfs(
                &cli.volume_file_path,
                cli_write_mkfsinfo_header_args.mkfsinfo.image_size,
                (cli.ignore_volume_file_io_block_size).then_some(
                    image_layout.io_block_allocation_blocks_log2 as u32
                        + image_layout.allocation_block_size_128b_log2 as u32,
                ),
            );
            let write_mkfsinfo_header_fut = match CocoonFsWriteMkfsInfoHeaderFuture::new(
                chip,
                &image_layout,
                salt,
                cli_write_mkfsinfo_header_args.mkfsinfo.image_size,
                !cli_write_mkfsinfo_header_args.trim_volume_file_to_header,
            ) {
                Ok(write_mkfsinfo_header_fut) => write_mkfsinfo_header_fut,
                Err((_chip, e)) => {
                    eprintln!(
                        "error: failed to initiate CocoonFS mkfsinfo header write operation: error={:?}",
                        e
                    );
                    std::process::exit(6);
                }
            };
            match write_mkfsinfo_header_fut.block_on() {
                Ok((_chip, Ok(()))) => (),
                Ok((_, Err(e))) | Err(e) => {
                    eprintln!("error: CocoonFS mkfsinfo header write operation failed: error={:?}", e);
                    std::process::exit(6);
                }
            }
        }
        CliCommand::WriteFile(cli_write_file_args) => {
            let mut data = Vec::new();
            match cli_write_file_args.in_file_path.as_ref() {
                Some(in_file_path) => match fs::read(in_file_path) {
                    Ok(result) => data = result,
                    Err(e) => {
                        eprintln!("error: failed to read data from input file: error={}", e);
                        std::process::exit(4);
                    }
                },
                None => {
                    if let Err(e) = io::stdin().read_to_end(&mut data) {
                        eprintln!("error: failed to read data from standard input: error={}", e);
                        std::process::exit(4);
                    }
                }
            };

            let key = load_key(&cli_write_file_args.key);

            // If the volume file's block size is to be ignored, the it would be best to
            // resort to using the IO block size recorded in the filesystem
            // header. But that's not known as it currently stands, so use the
            // minimum possible then.
            let (fs_instance, rng) = open_filesystem(
                &cli.volume_file_path,
                &key,
                cli.ignore_volume_file_io_block_size.then_some(0),
                cli_write_file_args.enable_trimming,
            );

            let (transaction, rng) = match NvFsFutureAsCoreFuture::new(
                fs_instance.clone(),
                <CocoonFsType as NvFs>::start_transaction(&cocoonfs_mk_fs_instance_ref(&fs_instance), None),
                rng,
            )
            .block_on()
            {
                Ok((rng, Ok(transaction))) => (transaction, rng),
                Ok((_, Err(e))) | Err(e) => {
                    eprintln!("error: failed to start CocoonFS transaction: error={:?}", e);
                    std::process::exit(6);
                }
            };

            let (transaction, rng) = match NvFsFutureAsCoreFuture::new(
                fs_instance.clone(),
                <CocoonFsType as NvFs>::write_inode(
                    &cocoonfs_mk_fs_instance_ref(&fs_instance),
                    transaction,
                    cli_write_file_args.inode,
                    zeroize::Zeroizing::new(data),
                ),
                rng,
            )
            .block_on()
            {
                Ok((rng, Ok((transaction, _data, Ok(()))))) => (transaction, rng),
                Ok((_, Ok((_, _, Err(e))))) | Ok((_, Err(e))) | Err(e) => {
                    eprintln!(
                        "error: failed to stage file write at CocoonFS transaction: error={:?}",
                        e
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
                    eprintln!("error: failed to commit CocoonFS transaction: error={:?}", e);
                    std::process::exit(6);
                }
                Err(e) => {
                    eprintln!("error: failed to commit CocoonFS transaction: error={:?}", e);
                    std::process::exit(6);
                }
            }
        }
        CliCommand::ReadFile(cli_read_file_args) => {
            let key = load_key(&cli_read_file_args.key);

            // If the volume file's block size is to be ignored, the it would be best to
            // resort to using the IO block size recorded in the filesystem
            // header. But that's not known as it currently stands, so use the
            // minimum possible then.
            let (fs_instance, rng) = open_filesystem(
                &cli.volume_file_path,
                &key,
                cli.ignore_volume_file_io_block_size.then_some(0),
                cli_read_file_args.enable_trimming,
            );

            let data = match NvFsFutureAsCoreFuture::new(
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
                Ok((_rng, Ok((_read_seq, Ok(data))))) => data,
                Ok((_, Ok((_, Err(e))))) | Ok((_, Err(e))) | Err(e) => {
                    eprintln!("error: failed to read CocoonFS inode data: error={:?}", e);
                    std::process::exit(6);
                }
            };

            let data = match data {
                Some(data) => data,
                None => {
                    eprintln!("error: CocoonFS inode doesn't exist");
                    std::process::exit(6);
                }
            };

            match cli_read_file_args.out_file_path {
                Some(out_file_path) => {
                    if let Err(e) = fs::write(out_file_path, &data) {
                        eprintln!("error: failed to write data to output file: error={}", e);
                        std::process::exit(4);
                    }
                }
                None => {
                    if let Err(e) = io::stdout().write_all(&data) {
                        eprintln!("error: failed to write data to standard output: error={}", e);
                        std::process::exit(4);
                    }
                }
            };
        }
        CliCommand::ListFiles(cli_list_files_args) => {
            let key = load_key(&cli_list_files_args.key);

            // If the volume file's block size is to be ignored, the it would be best to
            // resort to using the IO block size recorded in the filesystem
            // header. But that's not known as it currently stands, so use the
            // minimum possible then.
            let (fs_instance, rng) = open_filesystem(
                &cli.volume_file_path,
                &key,
                cli.ignore_volume_file_io_block_size.then_some(0),
                cli_list_files_args.enable_trimming,
            );

            let (consistent_read_sequence, mut rng) = match NvFsFutureAsCoreFuture::new(
                fs_instance.clone(),
                <CocoonFsType as NvFs>::start_read_sequence(&cocoonfs_mk_fs_instance_ref(&fs_instance)),
                rng,
            )
            .block_on()
            {
                Ok((rng, Ok(consistent_read_sequence))) => (consistent_read_sequence, rng),
                Ok((_, Err(e))) | Err(e) => {
                    eprintln!(
                        "error: failed to start consistent CocoonFS read sequence: error={:?}",
                        e
                    );
                    std::process::exit(6);
                }
            };

            let mut enumerate_cursor = match <CocoonFsType as NvFs>::enumerate_cursor(
                &cocoonfs_mk_fs_instance_ref(&fs_instance),
                NvFsReadContext::Committed {
                    seq: consistent_read_sequence,
                },
                6..=u32::MAX,
            ) {
                Ok(Ok(enumerate_cursor)) => enumerate_cursor,
                Ok(Err((_, e))) | Err(e) => {
                    eprintln!(
                        "error: failed to instantiate CocoonFS enumeration cursor: error={:?}",
                        e
                    );
                    std::process::exit(6);
                }
            };

            loop {
                let inode;
                (enumerate_cursor, rng, inode) =
                    match NvFsFutureAsCoreFuture::new(fs_instance.clone(), enumerate_cursor.next(), rng).block_on() {
                        Ok((rng, Ok((enumerate_cursor, Ok(inode))))) => (enumerate_cursor, rng, inode),
                        Ok((_, Ok((_, Err(e))))) | Ok((_, Err(e))) | Err(e) => {
                            eprintln!("error: failed to advance CocoonFS enumeration cursor: error={:?}", e);
                            std::process::exit(6);
                        }
                    };

                match inode {
                    Some(inode) => {
                        println!("{}", inode)
                    }
                    None => break,
                };
            }
        }
        CliCommand::RemoveFile(cli_remove_file_args) => {
            let key = load_key(&cli_remove_file_args.key);

            // If the volume file's block size is to be ignored, the it would be best to
            // resort to using the IO block size recorded in the filesystem
            // header. But that's not known as it currently stands, so use the
            // minimum possible then.
            let (fs_instance, rng) = open_filesystem(
                &cli.volume_file_path,
                &key,
                cli.ignore_volume_file_io_block_size.then_some(0),
                cli_remove_file_args.enable_trimming,
            );

            let (transaction, mut rng) = match NvFsFutureAsCoreFuture::new(
                fs_instance.clone(),
                <CocoonFsType as NvFs>::start_transaction(&cocoonfs_mk_fs_instance_ref(&fs_instance), None),
                rng,
            )
            .block_on()
            {
                Ok((rng, Ok(transaction))) => (transaction, rng),
                Ok((_, Err(e))) | Err(e) => {
                    eprintln!("error: failed to start CocoonFS transaction: error={:?}", e);
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
                    eprintln!("error: failed to instantiate CocoonFS unlink cursor: error={:?}", e);
                    std::process::exit(6);
                }
            };

            loop {
                let inode;
                (unlink_cursor, rng, inode) =
                    match NvFsFutureAsCoreFuture::new(fs_instance.clone(), unlink_cursor.next(), rng).block_on() {
                        Ok((rng, Ok((unlink_cursor, Ok(inode))))) => (unlink_cursor, rng, inode),
                        Ok((_, Ok((_, Err(e))))) | Ok((_, Err(e))) | Err(e) => {
                            eprintln!("error: failed to advance CocoonFS unlink cursor: error={:?}", e);
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
                            eprintln!(
                                "error: failed to stage inode removal at CocoonFS transaction: error={:?}",
                                e
                            );
                            std::process::exit(6);
                        }
                    };
            }

            let transaction = match unlink_cursor.into_transaction() {
                Ok(transaction) => transaction,
                Err(e) => {
                    eprintln!(
                        "error: failed to retrieve transaction from CocoonFS unlink cursor: error={:?}",
                        e
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
                    eprintln!("error: failed to commit CocoonFS transaction: error={:?}", e);
                    std::process::exit(6);
                }
                Err(e) => {
                    eprintln!("error: failed to commit CocoonFS transaction: error={:?}", e);
                    std::process::exit(6);
                }
            }
        }
    }
}
