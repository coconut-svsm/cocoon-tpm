// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Functionality related to root- and subkey derivations.

extern crate alloc;
use alloc::vec::Vec;

use crate::{
    crypto::{
        hash,
        kdf::{self, Kdf as _},
        symcipher,
    },
    fs::{NvFsError, cocoonfs::set_assoc_cache},
    nvfs_err_internal, tpm2_interface,
    utils_async::sync_types::{self, RwLock as _},
    utils_common::{
        alloc::try_alloc_zeroizing_vec,
        io_slices::{self, IoSlicesIterCommon as _},
        murmurhash3, zeroize,
    },
};
use core::{convert, iter, mem, ops, slice};

#[cfg(doc)]
use crate::fs::cocoonfs::layout::ImageLayout;

/// Intended cryptographic purpose of a derived key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum KeyPurpose {
    /// Subkey derivation.
    ///
    /// The KDF used is [`TcgTpm2KdfA`](kdf::tcg_tpm2_kdf_a::TcgTpm2KdfA) with a
    /// hash algorithm of [`ImageLayout::kdf_hash_alg`].
    Derivation = 1,
    /// Computation of the authentication tree root HMAC.
    ///
    /// The hash algorithm used for the HMAC is
    /// [`ImageLayout::auth_tree_root_hmac_hash_alg`].
    AuthenticationRoot = 2,
    /// Computation of [Authentication Tree Data
    /// Block](ImageLayout::auth_tree_data_block_allocation_blocks_log2) HMACs.
    ///
    /// The hash algorithm used for the HMACs is
    /// [`ImageLayout::auth_tree_data_hmac_hash_alg`].
    AuthenticationData = 3,
    /// Computation of HMACs stored inline for CCA protection before the
    /// authentication tree is available at filesystem opening time.
    ///
    /// The hash algorithm used for the HMACs is
    /// [`ImageLayout::preauth_cca_protection_hmac_hash_alg`].
    PreAuthCcaProtectionAuthentication = 4,
    /// Encryption.
    ///
    /// The block cipher to be used for encryption is
    /// [`ImageLayout::block_cipher_alg`] in CBC mode.
    Encryption = 5,
}

/// Key identifier for the purpose of subkey derivation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyId {
    /// Domain, usually an inode number.
    domain: u32,
    /// Subdomain identifier further specifying the scope of the key within the
    /// given [`domain`](Self::domain).
    subdomain: u32,
    /// The cryptographic purpose the key is to be used for.
    purpose: KeyPurpose,
}

impl KeyId {
    /// Instantiate a [`KeyId`].
    ///
    /// # Arguments:
    ///
    /// * `domain` - The key's domain, usually an inode number.
    /// * `subdomain` - Subdomain identifier further specifying the scope of the
    ///   key within the given `domain`.
    /// * `purpose` - The cryptographic purpose the key is to be used for.
    pub fn new(domain: u32, subdomain: u32, purpose: KeyPurpose) -> Self {
        Self {
            domain,
            subdomain,
            purpose,
        }
    }
}

/// Cache of derived subkeys.
///
/// A `KeyCache` is always associated with a single, unique [`RootKey`], and
/// stores subkeys derived therefrom.
///
/// <div class="warning">
///
/// The associated [`RootKey`] is not stored with the `KeyCache` instance
/// itself. Be careful to always pass the same one to
/// [`get_key()`](Self::get_key).
///
/// </div>
pub struct KeyCache {
    cache: set_assoc_cache::SetAssocCache<KeyId, zeroize::Zeroizing<Vec<u8>>, KeyCacheMapKeyIdToSetAssocCacheSet>,
}

impl KeyCache {
    /// Instantiate a [`KeyCache`].
    pub fn new() -> Result<Self, NvFsError> {
        // Create a cache of two full sets, i.e. 16 slots in total.
        let cache =
            set_assoc_cache::SetAssocCache::new(
                KeyCacheMapKeyIdToSetAssocCacheSet { cache_sets_count: 2 },
                iter::repeat_n(
                    set_assoc_cache::SetAssocCache::<
                        KeyId,
                        zeroize::Zeroizing<Vec<u8>>,
                        KeyCacheMapKeyIdToSetAssocCacheSet,
                    >::MAX_SET_ASSOCIATIVITY,
                    2,
                ),
            )
            .map_err(|e| match e {
                set_assoc_cache::SetAssocCacheConfigureError::MemoryAllocationFailure => {
                    NvFsError::MemoryAllocationFailure
                }
            })?;

        Ok(Self { cache })
    }

    /// Obtain a subkey from the cache or derive if not present.
    ///
    /// Lookup the subkey identified by `key_id` in the cache. If it doesn't
    /// exist yet, derive it and insert it into the cache.
    ///
    /// On success, a reference to the subkey's cache entry is returned as
    /// a [`KeyCacheEntryRef`].
    ///
    /// # Arguments:
    ///
    /// * `this` - [`KeyCacheRef`] to `self`.
    /// * `root_key` - The [`RootKey`] associated with `self`.
    /// * `key_id` - [`KeyId`] of the subkey to obtain.
    pub fn get_key<'a, ST: sync_types::SyncTypes>(
        this: &'a mut KeyCacheRef<'_, ST>,
        root_key: &RootKey,
        key_id: &KeyId,
    ) -> Result<KeyCacheEntryRef<'a, ST>, NvFsError> {
        let read_guard = KeyCacheReadGuard::from(this.make_borrow());
        if let Some(cache_entry_index) = read_guard.cache.lookup(key_id) {
            return Ok(KeyCacheEntryRef {
                cache: read_guard,
                cache_entry_index,
            });
        }
        let this = KeyCacheRef::from(read_guard);

        // Key not found in cache, instantiate it.
        let key = root_key.derive_key(key_id)?;
        let mut write_guard = KeyCacheWriteGuard::from(this);
        let cache_entry_index = match write_guard.cache.insert(*key_id, key) {
            set_assoc_cache::SetAssocCacheInsertionResult::Inserted { index, evicted: _ } => index,
            set_assoc_cache::SetAssocCacheInsertionResult::Uncacheable { value: _ } => {
                // All keys are to get cached, as per the key to cache set map.
                return Err(nvfs_err_internal!());
            }
        };
        Ok(KeyCacheEntryRef {
            cache: KeyCacheReadGuard::WriteGuard { guard: write_guard },
            cache_entry_index,
        })
    }

    /// Prune all cache entries.
    pub fn clear(&mut self) {
        self.cache.prune_all();
    }
}

/// Reference to [`KeyCache`] wrapped in a [`RwLock`](sync_types::RwLock).
///
/// Instances of [`KeyCache`] are expected to get wrapped in a
/// [`RwLock`](sync_types::RwLock). `KeyCacheRef` can represent either
/// immutable references to the containing [`RwLock`](sync_types::RwLock) or
/// a mutable reference to the inner [`KeyCache`].
///
/// API functions needing access to an [`KeyCache`] usually take it as
/// an argument of type `KeyCacheRef`, thereby potentially alleviating
/// the need to take the lock in case the caller can provide exclusive access
/// already.
pub enum KeyCacheRef<'a, ST: sync_types::SyncTypes> {
    /// Immutable reference to the [`RwLock`](sync_types::RwLock) wrapping the
    /// [`KeyCache`].
    ///
    /// Accessing the wrapped [`KeyCache`] requires locking the
    /// protecting [`RwLock`](sync_types::RwLock).
    Ref { cache: &'a ST::RwLock<KeyCache> },
    /// Direct mutable reference to the [`KeyCache`].
    ///
    /// Accessing the referenced [`KeyCache`] does not involve any
    /// locking operation.
    MutRef { cache: &'a mut KeyCache },
}

impl<'a, ST: sync_types::SyncTypes> KeyCacheRef<'a, ST> {
    /// Instantiate a [`KeyCacheRef`] from a `mut` [`KeyCache`] reference.
    ///
    /// # Arguments:
    ///
    /// * `cache` - The [`KeyCache`] `mut` reference to wrap.
    pub fn new_mut(cache: &'a mut KeyCache) -> Self {
        Self::MutRef { cache }
    }

    /// Reborrow the reference.
    ///
    /// [`KeyCacheRef`] is not covariant over its lifetime parameter.
    /// `make_borrow()` enables reborrowing with a shorter lifetime if
    /// needed.
    fn make_borrow(&mut self) -> KeyCacheRef<'_, ST> {
        match self {
            Self::Ref { cache } => KeyCacheRef::Ref { cache },
            Self::MutRef { cache } => KeyCacheRef::MutRef { cache },
        }
    }
}

impl<'a, ST: sync_types::SyncTypes> convert::From<KeyCacheReadGuard<'a, ST>> for KeyCacheRef<'a, ST> {
    fn from(value: KeyCacheReadGuard<'a, ST>) -> Self {
        match value {
            KeyCacheReadGuard::ReadGuard { cache, guard: _ } => Self::Ref { cache },
            KeyCacheReadGuard::WriteGuard { guard } => Self::from(guard),
        }
    }
}

impl<'a, ST: sync_types::SyncTypes> convert::From<KeyCacheWriteGuard<'a, ST>> for KeyCacheRef<'a, ST> {
    fn from(value: KeyCacheWriteGuard<'a, ST>) -> Self {
        match value {
            KeyCacheWriteGuard::WriteGuard { cache, guard: _ } => Self::Ref { cache },
            KeyCacheWriteGuard::MutRef { cache } => Self::MutRef { cache },
        }
    }
}

/// Read lock guard for a [`KeyCache`] wrapped in a
/// [`RwLock`](sync_types::RwLock).
///
/// Usually obtained from an [`KeyCacheRef`] via [`From`] or constructed
/// explicitly from an [`KeyCacheWriteGuard`].
enum KeyCacheReadGuard<'a, ST: sync_types::SyncTypes>
where
    <ST as sync_types::SyncTypes>::RwLock<KeyCache>: 'a,
{
    /// The `KeyReadGuard` instance is realized by an actual
    /// [`RwLock::ReadGuard`](sync_types::RwLock::ReadGuard).
    ///
    /// Usually spawned off from a [`KeyCacheRef::Ref`].
    ReadGuard {
        cache: &'a ST::RwLock<KeyCache>,
        guard: <ST::RwLock<KeyCache> as sync_types::RwLock<KeyCache>>::ReadGuard<'a>,
    },
    /// The `KeyCacheReadGuard` instance is realized by an
    /// [`KeyCacheWriteGuard`].
    WriteGuard { guard: KeyCacheWriteGuard<'a, ST> },
}

impl<'a, ST: sync_types::SyncTypes> ops::Deref for KeyCacheReadGuard<'a, ST> {
    type Target = KeyCache;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::ReadGuard { cache: _, guard } => guard,
            Self::WriteGuard { guard } => guard,
        }
    }
}

impl<'a, ST: sync_types::SyncTypes> convert::From<KeyCacheRef<'a, ST>> for KeyCacheReadGuard<'a, ST> {
    fn from(value: KeyCacheRef<'a, ST>) -> Self {
        match value {
            KeyCacheRef::Ref { cache } => Self::ReadGuard {
                cache,
                guard: cache.read(),
            },
            KeyCacheRef::MutRef { cache } => Self::WriteGuard {
                guard: KeyCacheWriteGuard::MutRef { cache },
            },
        }
    }
}

/// Write guard for a [`KeyCache`] wrapped in a [`RwLock`](sync_types::RwLock).
enum KeyCacheWriteGuard<'a, ST: sync_types::SyncTypes>
where
    <ST as sync_types::SyncTypes>::RwLock<KeyCache>: 'a,
{
    /// The `KeyCacheWriteGuard` instance is realized by an actual
    /// [`RwLock::WriteGuard`](sync_types::RwLock::WriteGuard).
    ///
    /// Usually spawned off from a [`KeyCacheRef::Ref`].
    WriteGuard {
        cache: &'a ST::RwLock<KeyCache>,
        guard: <ST::RwLock<KeyCache> as sync_types::RwLock<KeyCache>>::WriteGuard<'a>,
    },
    /// The `KeyCacheWriteGuard` instance is realized by a mutable reference to
    /// the [`KeyCache`].
    ///
    /// Usually spawned off by borrowing from a [`KeyCacheRef::MutRef`].
    MutRef { cache: &'a mut KeyCache },
}

impl<'a, ST: sync_types::SyncTypes> ops::Deref for KeyCacheWriteGuard<'a, ST> {
    type Target = KeyCache;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::WriteGuard { cache: _, guard } => guard,
            Self::MutRef { cache } => cache,
        }
    }
}

impl<'a, ST: sync_types::SyncTypes> ops::DerefMut for KeyCacheWriteGuard<'a, ST> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::WriteGuard { cache: _, guard } => guard.deref_mut(),
            Self::MutRef { cache } => cache,
        }
    }
}

impl<'a, ST: sync_types::SyncTypes> convert::From<KeyCacheRef<'a, ST>> for KeyCacheWriteGuard<'a, ST> {
    fn from(value: KeyCacheRef<'a, ST>) -> Self {
        match value {
            KeyCacheRef::Ref { cache } => Self::WriteGuard {
                cache,
                guard: cache.write(),
            },
            KeyCacheRef::MutRef { cache } => Self::MutRef { cache },
        }
    }
}

/// Reference to an entry in a [`KeyCache`] wrapped in a
/// [`RwLock`](sync_types::RwLock).
pub struct KeyCacheEntryRef<'a, ST: sync_types::SyncTypes> {
    /// Read guard on the [`KeyCache`].
    cache: KeyCacheReadGuard<'a, ST>,
    /// Cache entry index into [`KeyCache::cache`].
    cache_entry_index: set_assoc_cache::SetAssocCacheIndex,
}

impl<'a, ST: sync_types::SyncTypes> ops::Deref for KeyCacheEntryRef<'a, ST> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.cache.deref().cache.get_entry(self.cache_entry_index).unwrap().1
    }
}

/// [`SetAssocCacheMapKeyToSet`](set_assoc_cache::SetAssocCacheMapKeyToSet)
/// implementation controlling the layout of the
/// [`SetAssocCache`](set_assoc_cache::SetAssocCache) used internally by
/// [`KeyCache`].
struct KeyCacheMapKeyIdToSetAssocCacheSet {
    cache_sets_count: u32,
}

impl set_assoc_cache::SetAssocCacheMapKeyToSet<KeyId> for KeyCacheMapKeyIdToSetAssocCacheSet {
    fn map_key(&self, key: &KeyId) -> Option<usize> {
        let mut h = murmurhash3::MurmurHash3_32::new(0);
        h.update(&key.domain.to_ne_bytes());
        h.update(&key.subdomain.to_ne_bytes());
        h.update(slice::from_ref(&(key.purpose as u8)));
        let h: u32 = h.finalize();
        // Multiply high, i.e. u32::carrying_mul() is unstable.
        Some((((h as u64) * (self.cache_sets_count as u64)) >> 32) as usize)
    }
}

/// Filesystem root key derived from externally supplied key material.
pub struct RootKey {
    /// [`TcgTpm2KdfA`](kdf::tcg_tpm2_kdf_a::TcgTpm2KdfA) input parent key
    /// material to be used for subkey derivation.
    root_key: zeroize::Zeroizing<Vec<u8>>,

    /// The hash algorithm to use with
    /// [`TcgTpm2KdfA`](kdf::tcg_tpm2_kdf_a::TcgTpm2KdfA).
    kdf_hash_alg: tpm2_interface::TpmiAlgHash,

    /// Length of subkeys to be derived for [`KeyPurpose::AuthenticationRoot`].
    auth_tree_root_hmac_key_len: usize,
    /// Length of subkeys to be derived for [`KeyPurpose::AuthenticationData`].
    auth_tree_data_hmac_key_len: usize,
    /// Length of subkeys to be derived for
    /// [`KeyPurpose::PreAuthCcaProtectionAuthentication`].
    preauth_cca_protection_hmac_key_len: usize,
    /// Length of subkeys to be derived for [`KeyPurpose::Encryption`].
    block_cipher_key_len: usize,
}

impl RootKey {
    /// Instantiate a [`RootKey`] from externally supplied key material.
    ///
    /// # Arguments:
    ///
    /// * `key` - The externally supplied raw key material.
    /// * `salt` - Root key derivation salt as found in the
    ///   [`StaticImageHeader::salt`](super::image_header::StaticImageHeader::salt).
    /// * `kdf_hash_alg` - The hash algorithm to be used with
    ///   [`TcgTpm2KdfA`](kdf::tcg_tpm2_kdf_a::TcgTpm2KdfA) for subkey
    ///   derivation, i.e. the value of [`ImageLayout::kdf_hash_alg`].
    /// * `auth_tree_root_hmac_hash_alg` - The HMAC hash algorithm to be used
    ///   with subkeys derived for [`KeyPurpose::AuthenticationRoot`], i.e. the
    ///   value of [`ImageLayout::auth_tree_root_hmac_hash_alg`].
    /// * `auth_tree_node_hash_alg``  The hash algorithm to be used for forming
    ///   digests over authentication tree nodes, i.e. the value of
    ///   [`ImageLayout::auth_tree_node_hash_alg`].
    /// * `auth_tree_data_hmac_hash_alg` - The HMAC hash algorithm to be used
    ///   with subkeys derived for [`KeyPurpose::AuthenticationData`], i.e. the
    ///   value of [`ImageLayout::auth_tree_data_hmac_hash_alg`].
    /// * `preauth_cca_protection_hmac_hash_alg` - The HMAC hash algorithm to be
    ///   used with subkeys derived for
    ///   [`KeyPurpose::PreAuthCcaProtectionAuthentication`], i.e. the value of
    ///   [`ImageLayout::preauth_cca_protection_hmac_hash_alg`].
    /// * `block_cipher_alg` - The block cipher algorithm to be used with
    ///   subkeys derived for [`KeyPurpose::Encryption`], i.e. the value of
    ///   [`ImageLayout::block_cipher_alg`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: &[u8],
        salt: &[u8],
        kdf_hash_alg: tpm2_interface::TpmiAlgHash,
        auth_tree_root_hmac_hash_alg: tpm2_interface::TpmiAlgHash,
        auth_tree_node_hash_alg: tpm2_interface::TpmiAlgHash,
        auth_tree_data_hmac_hash_alg: tpm2_interface::TpmiAlgHash,
        preauth_cca_protection_hmac_hash_alg: tpm2_interface::TpmiAlgHash,
        block_cipher_alg: &symcipher::SymBlockCipherAlg,
    ) -> Result<Self, NvFsError> {
        // Don't take the externally supplied key as the root key directly, but run it
        // through a KDF: the root key KDF's underlying hash algorithm is
        // mandatorily fixed to one with maximum supported security strength in
        // order to mitigate against downgrade attacks on the rest of the
        // parameter set. That is, downgrading any of the other parameters will yield
        // what is effectively a random root key, unrelated to the real one. The
        // security strength of the toplevel root key KDF would (hopefully) put
        // a barrier on any attempt to infer information about the externally
        // provided input key from knowledge gained about subkeys derived using
        // potentially weak methods.
        //
        // The context passed to KDFa for derivation of the root_key will be, in this
        // order,
        // - The magic 'COCOONFS', without a null terminator.
        // - the image format version, as an u8, fixed to zero for now,
        // - the kdf_hash_alg, as a u16,
        // - the auth_tree_root_hmac_hash_alg, as a u16,
        // - the auth_tree_node_hash_alg, as a u16,
        // - the auth_tree_data_hmac_hash_alg, as a u16,
        // - preauth_cca_protection_hmac_hash_alg, as a u16,
        // - the encryption parameters:
        //   - mode identifier as an u16, fixed to TpmiAlgCipherMode::Cbc for now,
        //     included for future extensibility,
        //   - block_cipher_alg, encoded as a (TpmiAlgSymObject, u16) pair, the block
        //     cipher identifier and key size, both encoded as u16s.
        // - The salt length, encoded as an u8.
        // - The salt itself.
        const CONTEXT_HEAD_LEN: usize = 8 + 1 + 2 + 2 + 2 + 2 + 2 + 2 + 2 + 2 + 1;
        let mut context_head = [0u8; CONTEXT_HEAD_LEN];
        let salt_len = u8::try_from(salt.len()).unwrap_or(u8::MAX);
        let context_tail = &salt[..salt_len as usize];
        let buf = context_head.as_mut_slice();
        buf[..8].copy_from_slice(b"COCOONFS");
        let buf = &mut buf[8..];
        let buf = tpm2_interface::marshal_u8(buf, 0).map_err(|_| nvfs_err_internal!())?;
        let buf = kdf_hash_alg.marshal(buf).map_err(|_| nvfs_err_internal!())?;
        let buf = auth_tree_root_hmac_hash_alg
            .marshal(buf)
            .map_err(|_| nvfs_err_internal!())?;
        let buf = auth_tree_node_hash_alg.marshal(buf).map_err(|_| nvfs_err_internal!())?;
        let buf = auth_tree_data_hmac_hash_alg
            .marshal(buf)
            .map_err(|_| nvfs_err_internal!())?;
        let buf = preauth_cca_protection_hmac_hash_alg
            .marshal(buf)
            .map_err(|_| nvfs_err_internal!())?;
        let buf = tpm2_interface::TpmiAlgCipherMode::Cbc
            .marshal(buf)
            .map_err(|_| nvfs_err_internal!())?;
        let (block_cipher_alg_id, block_cipher_key_size) =
            <(tpm2_interface::TpmiAlgSymObject, u16)>::from(block_cipher_alg);
        let buf = block_cipher_alg_id.marshal(buf).map_err(|_| nvfs_err_internal!())?;
        let buf = tpm2_interface::marshal_u16(buf, block_cipher_key_size).map_err(|_| nvfs_err_internal!())?;
        let buf = tpm2_interface::marshal_u8(buf, salt_len).map_err(|_| nvfs_err_internal!())?;
        debug_assert!(buf.is_empty());

        let root_key_len = hash::hash_alg_digest_len(kdf_hash_alg);
        let mut root_key = try_alloc_zeroizing_vec::<u8>(root_key_len as usize)?;
        kdf::tcg_tpm2_kdf_a::TcgTpm2KdfA::new(
            tpm2_interface::TpmiAlgHash::Sha512,
            key,
            &[KeyPurpose::Derivation as u8],
            Some(&context_head),
            Some(context_tail),
            8 * (root_key_len as u32),
        )
        .and_then(|kdf| kdf.generate(io_slices::SingletonIoSliceMut::new(&mut root_key).map_infallible_err()))
        .map_err(NvFsError::from)?;

        let auth_tree_root_hmac_key_len = hash::hash_alg_digest_len(auth_tree_root_hmac_hash_alg) as usize;
        let auth_tree_data_hmac_key_len = hash::hash_alg_digest_len(auth_tree_data_hmac_hash_alg) as usize;
        let preauth_cca_protection_hmac_key_len =
            hash::hash_alg_digest_len(preauth_cca_protection_hmac_hash_alg) as usize;
        let block_cipher_key_len = block_cipher_alg.key_len();

        Ok(Self {
            root_key,
            kdf_hash_alg,
            auth_tree_root_hmac_key_len,
            auth_tree_data_hmac_key_len,
            preauth_cca_protection_hmac_key_len,
            block_cipher_key_len,
        })
    }

    /// Derive a subkey from the [`RootKey`].
    ///
    /// # Arguments:
    ///
    /// * `key_id` - [`KeyId`] of the subkey to derive.
    pub fn derive_key(&self, key_id: &KeyId) -> Result<zeroize::Zeroizing<Vec<u8>>, NvFsError> {
        let key_len = match key_id.purpose {
            KeyPurpose::Derivation => hash::hash_alg_digest_len(self.kdf_hash_alg) as usize,
            KeyPurpose::AuthenticationRoot => self.auth_tree_root_hmac_key_len,
            KeyPurpose::AuthenticationData => self.auth_tree_data_hmac_key_len,
            KeyPurpose::PreAuthCcaProtectionAuthentication => self.preauth_cca_protection_hmac_key_len,
            KeyPurpose::Encryption => self.block_cipher_key_len,
        };
        let mut key = try_alloc_zeroizing_vec(key_len)?;
        let mut full_domain = [0u8; 2 * mem::size_of::<u32>()];
        // split_array_mut() is unstable.
        *<&mut [u8; mem::size_of::<u32>()]>::try_from(&mut full_domain[..mem::size_of::<u32>()])
            .map_err(|_| nvfs_err_internal!())? = key_id.domain.to_le_bytes();
        *<&mut [u8; mem::size_of::<u32>()]>::try_from(&mut full_domain[mem::size_of::<u32>()..])
            .map_err(|_| nvfs_err_internal!())? = key_id.subdomain.to_le_bytes();
        kdf::tcg_tpm2_kdf_a::TcgTpm2KdfA::new(
            self.kdf_hash_alg,
            &self.root_key,
            &[key_id.purpose as u8],
            Some(&full_domain),
            None,
            8 * (key_len as u32),
        )
        .and_then(|kdf| kdf.generate(io_slices::SingletonIoSliceMut::new(&mut key).map_infallible_err()))
        .map_err(NvFsError::from)?;
        Ok(key)
    }
}
