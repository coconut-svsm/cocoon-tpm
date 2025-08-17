// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of [`ImageLayout`], [`PhysicalAllocBlockIndex`] and
//! [`PhysicalAllocBlockRange`], [`LogicalAllocBlockIndex`] and
//! [`LogicalAllocBlockRange`].

use crate::{
    crypto::{CryptoError, symcipher},
    fs::{
        NvFsError,
        cocoonfs::{CocoonFsFormatError, alloc_bitmap, extent_ptr},
    },
    nvfs_err_internal, tpm2_interface,
    utils_common::bitmanip::UBitManip as _,
};
use core::{cmp, convert, marker, ops};

/// Trait defining functionality common to types representing block counts.
pub trait BlockCount: Copy + ops::Add<Self, Output = Self> + ops::Sub<Self, Output = Self> {
    fn align_down(&self, align_log2: u32) -> Self;
    fn align_up(&self, align_log2: u32) -> Option<Self>;
}

/// Trait defining functionality common to types representing block indices.
pub trait BlockIndex<C: BlockCount>: Copy + cmp::Ord + ops::Add<C, Output = Self> + ops::Sub<Self, Output = C> {
    fn align_down(&self, align_log2: u32) -> Self;
    fn align_up(&self, align_log2: u32) -> Option<Self>;
}

/// [Allocation Block](ImageLayout::allocation_block_size_128b_log2) count.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct AllocBlockCount {
    count: u64,
}

impl convert::From<u64> for AllocBlockCount {
    fn from(value: u64) -> Self {
        Self { count: value }
    }
}

impl convert::From<AllocBlockCount> for u64 {
    fn from(value: AllocBlockCount) -> Self {
        value.count
    }
}

impl ops::Add<AllocBlockCount> for AllocBlockCount {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            count: self.count.checked_add(rhs.count).unwrap(),
        }
    }
}

impl ops::Sub<AllocBlockCount> for AllocBlockCount {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            count: self.count.checked_sub(rhs.count).unwrap(),
        }
    }
}

impl BlockCount for AllocBlockCount {
    fn align_down(&self, align_log2: u32) -> Self {
        Self::from(self.count.round_down_pow2(align_log2))
    }

    fn align_up(&self, align_log2: u32) -> Option<Self> {
        self.count.round_up_pow2(align_log2).map(Self::from)
    }
}

/// [Allocation Block](ImageLayout::allocation_block_size_128b_log2) index on
/// physical storage.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct PhysicalAllocBlockIndex {
    index: u64,
}

impl PhysicalAllocBlockIndex {
    pub fn align_down(&self, align_allocation_blocks_log2: u32) -> Self {
        Self::from((u64::from(*self) >> align_allocation_blocks_log2) << align_allocation_blocks_log2)
    }
}

impl convert::From<u64> for PhysicalAllocBlockIndex {
    fn from(value: u64) -> Self {
        Self { index: value }
    }
}

impl convert::From<PhysicalAllocBlockIndex> for u64 {
    fn from(value: PhysicalAllocBlockIndex) -> Self {
        value.index
    }
}

impl ops::Add<AllocBlockCount> for PhysicalAllocBlockIndex {
    type Output = Self;

    fn add(self, rhs: AllocBlockCount) -> Self::Output {
        Self {
            index: self.index.checked_add(rhs.count).unwrap(),
        }
    }
}

impl ops::AddAssign<AllocBlockCount> for PhysicalAllocBlockIndex {
    fn add_assign(&mut self, rhs: AllocBlockCount) {
        self.index = self.index.checked_add(rhs.count).unwrap();
    }
}

impl ops::Sub<Self> for PhysicalAllocBlockIndex {
    type Output = AllocBlockCount;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::Output {
            count: self.index.checked_sub(rhs.index).unwrap(),
        }
    }
}

impl BlockIndex<AllocBlockCount> for PhysicalAllocBlockIndex {
    fn align_down(&self, align_log2: u32) -> Self {
        Self::from(self.index.round_down_pow2(align_log2))
    }

    fn align_up(&self, align_log2: u32) -> Option<Self> {
        Some(Self::from(self.index.round_up_pow2(align_log2)?))
    }
}

/// [Allocation Block](ImageLayout::allocation_block_size_128b_log2) index
/// within some logical filesystem entity's data.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct LogicalAllocBlockIndex {
    index: u64,
}

impl convert::From<u64> for LogicalAllocBlockIndex {
    fn from(value: u64) -> Self {
        Self { index: value }
    }
}

impl convert::From<LogicalAllocBlockIndex> for u64 {
    fn from(value: LogicalAllocBlockIndex) -> Self {
        value.index
    }
}

impl ops::Add<AllocBlockCount> for LogicalAllocBlockIndex {
    type Output = Self;

    fn add(self, rhs: AllocBlockCount) -> Self::Output {
        Self {
            index: self.index.checked_add(rhs.count).unwrap(),
        }
    }
}

impl ops::AddAssign<AllocBlockCount> for LogicalAllocBlockIndex {
    fn add_assign(&mut self, rhs: AllocBlockCount) {
        self.index = self.index.checked_add(rhs.count).unwrap();
    }
}

impl ops::Sub<Self> for LogicalAllocBlockIndex {
    type Output = AllocBlockCount;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::Output {
            count: self.index.checked_sub(rhs.index).unwrap(),
        }
    }
}

impl BlockIndex<AllocBlockCount> for LogicalAllocBlockIndex {
    fn align_down(&self, align_log2: u32) -> Self {
        Self::from(self.index.round_down_pow2(align_log2))
    }

    fn align_up(&self, align_log2: u32) -> Option<Self> {
        Some(Self::from(self.index.round_up_pow2(align_log2)?))
    }
}

/// Range of blocks of a certain type.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BlockRange<I: BlockIndex<C>, C: BlockCount> {
    b: I,
    e: I,
    _phantom_c: marker::PhantomData<C>,
}

impl<I: BlockIndex<C>, C: BlockCount> BlockRange<I, C> {
    pub fn new(b: I, e: I) -> Self {
        debug_assert!(b < e);
        Self {
            b,
            e,
            _phantom_c: marker::PhantomData,
        }
    }

    pub fn begin(&self) -> I {
        self.b
    }

    pub fn end(&self) -> I {
        self.e
    }

    pub fn block_count(&self) -> C {
        self.e - self.b
    }

    pub fn overlaps_with(&self, other: &Self) -> bool {
        self.end() > other.begin() && self.begin() < other.end()
    }

    pub fn contains(&self, other: &Self) -> bool {
        self.begin() <= other.begin() && other.end() <= self.end()
    }

    pub fn align(&self, align_log2: u32) -> Option<Self> {
        let aligned_b = self.b.align_down(align_log2);
        let aligned_e = self.e.align_up(align_log2)?;
        Some(Self::new(aligned_b, aligned_e))
    }

    pub fn max_aligned_subrange(&self, align_log2: u32) -> Option<Self> {
        let aligned_e = self.e.align_down(align_log2);
        let aligned_b = self.b.align_up(align_log2)?;
        if aligned_b >= aligned_e {
            return None;
        }

        Some(Self {
            b: aligned_b,
            e: aligned_e,
            _phantom_c: marker::PhantomData,
        })
    }
}

impl<I: BlockIndex<C>, C: BlockCount> convert::From<(I, C)> for BlockRange<I, C> {
    fn from(value: (I, C)) -> Self {
        Self {
            b: value.0,
            e: value.0 + value.1,
            _phantom_c: marker::PhantomData,
        }
    }
}

/// Range of [Allocation Blocks](ImageLayout::allocation_block_size_128b_log2)
/// on physical storage.
pub type PhysicalAllocBlockRange = BlockRange<PhysicalAllocBlockIndex, AllocBlockCount>;

/// Range of [Allocation Blocks](ImageLayout::allocation_block_size_128b_log2)
/// within some logical filesystem entity.
pub type LogicalAllocBlockRange = BlockRange<LogicalAllocBlockIndex, AllocBlockCount>;

/// Core filesystem configuration parameters.
#[derive(Clone)]
pub struct ImageLayout {
    /// Base-2 logarithm of the "Allocation Block" size, specified in units of
    /// 128B multiples.
    ///
    /// Allocation Blocks are the basic units of block allocations, all other
    /// sizes are specified in terms of Allocation Blocks.
    pub allocation_block_size_128b_log2: u8,

    /// Base-2 logarithm of the "IO Block" size, specified in units of
    /// [Allocation Blocks](Self::allocation_block_size_128b_log2).
    ///
    /// The "IO Block" is defined to be equal the minimum unit of backend IO
    /// assumed not to ever clobber unrelated IO Blocks in the course of
    /// writing.
    pub io_block_allocation_blocks_log2: u8,

    /// Base-2 logarithm of the authentication tree node size as specified in
    /// units of [IO Blocks](Self::io_block_allocation_blocks_log2).
    ///
    /// Authentication tree, i.e. Merkle Tree, nodes store digests over their
    /// child nodes back to back. Increasing the node size increases the
    /// inner-tree fanout ratio, at the cost of increasing the efforts for
    /// (re-)hashing a single child node for validation or update respectively.
    pub auth_tree_node_io_blocks_log2: u8,

    /// Base-2 logarithm of the range covered by a single authentication tree
    /// leaf node digest entry, i.e. a "Authentication Tree Data Block", as
    /// specified in units of [Allocation
    /// Blocks](Self::allocation_block_size_128b_log2).
    ///
    /// Note that the allocation bitmap is managed in blocks of that size, so
    /// that an authentication tree leaf node digest entry authenticating the
    /// bitmap always would authenticate it exclusively and nothing else.
    /// This is crucial for bootstrapping the authentication in a
    /// CCA-defensive manner, because in the general case an examination of the
    /// allocation bitmap itself would be needed for validating an
    /// authentication tree leaf digest entry (for handling unallocated
    /// allocation blocks in the to be authenticated range properly when
    /// calcualting the digest). This constraint breaks the cycle and enables
    /// the bootstrapping code to authenticate the allocation bitmap's contents
    /// **before** decrypting it.
    pub auth_tree_data_block_allocation_blocks_log2: u8,

    /// Base-2 logarithm of an "Allocation Bitmap File Block"'s size as
    /// specified in units of [Allocation
    /// Blocks](Self::allocation_block_size_128b_log2).
    ///
    /// The Allocation Bitmap File Block size determines the granularity at
    /// which changes to the allocation bitmap are getting encrypted.
    /// Smaller block sizes reduce the work incurred with re-encrypting
    /// unmodified neigbouring parts. However, as each individual block stores
    /// an IV, smaller block sizes also imply a larger relative storage
    /// overhead.
    pub allocation_bitmap_file_block_allocation_blocks_log2: u8,

    /// Base-2 logarithm of the Index B-Tree node size as specified in units of
    /// [Allocation Blocks](Self::allocation_block_size_128b_log2).
    ///
    /// Must be >= the IV size + 4 + 8 + 7 * 12 so that the first node (in
    /// symmetric order) is guaranteed to always store the first four
    /// special file entries needed for bootstrapping, as per the minimum
    /// B-Tree node fill level.
    pub index_tree_node_allocation_blocks_log2: u8,

    /// The Hash algorithm to use for non-root authentication tree node
    /// authentication.
    ///
    /// Overall authentication security strength is determined by the security
    /// strength in regard to collision resistance (c.f. NIST SP 800-57,
    /// part 1, rev. 57, table 3) of the
    /// [`auth_tree_node_hash_alg`](Self::auth_tree_node_hash_alg) and
    /// [`auth_tree_data_hmac_hash_alg`](Self::auth_tree_data_hmac_hash_alg)
    /// hash functions, as well as by the security strength of the HMAC
    /// construction specified by means of
    /// [`auth_tree_root_hmac_hash_alg`](Self::auth_tree_root_hmac_hash_alg).
    ///
    /// As a rule of thumb, the
    /// [`auth_tree_node_hash_alg`](Self::auth_tree_node_hash_alg) digest
    /// size in bits should be no less than twice the targeted overall security
    /// strength.
    pub auth_tree_node_hash_alg: tpm2_interface::TpmiAlgHash,

    /// The HMAC hash algorithm to use for data authentication.
    ///
    /// Overall authentication security strength is determined by the security
    /// strength in regard to collision resistance (c.f. NIST SP 800-57,
    /// part 1, rev. 57, table 3) of the
    /// [`auth_tree_node_hash_alg`](Self::auth_tree_node_hash_alg) and
    /// [`auth_tree_data_hmac_hash_alg`](Self::auth_tree_data_hmac_hash_alg)
    /// hash functions, as well as by the security strength of the HMAC
    /// construction specified by means of
    /// [`auth_tree_root_hmac_hash_alg`](Self::auth_tree_root_hmac_hash_alg).
    ///
    /// As a rule of thumb, the
    /// [`auth_tree_data_hmac_hash_alg`](Self::auth_tree_data_hmac_hash_alg)
    /// digest size in bits should be no less than twice the targeted overall
    /// security strength.
    pub auth_tree_data_hmac_hash_alg: tpm2_interface::TpmiAlgHash,

    /// The HMAC hash algorithm to use for authentication tree root node
    /// authentication.
    ///
    /// Overall authentication security strength is determined by the security
    /// strength in regard to collision resistance (c.f. NIST SP 800-57,
    /// part 1, rev. 57, table 3) of the
    /// [`auth_tree_node_hash_alg`](Self::auth_tree_node_hash_alg) and
    /// [`auth_tree_data_hmac_hash_alg`](Self::auth_tree_data_hmac_hash_alg)
    /// hash functions, as well as by the security strength of the HMAC
    /// construction specified by means of
    /// [`auth_tree_root_hmac_hash_alg`](Self::auth_tree_root_hmac_hash_alg).
    ///
    /// As a rule of thumb, the digest size of the hash used for the HMACs
    /// should be no less than the targeted overall security strength.
    pub auth_tree_root_hmac_hash_alg: tpm2_interface::TpmiAlgHash,

    /// Hash algorithm to use for CCA-protection HMACs.
    ///
    /// For defending against Chosen Ciphertext Attacks (CCA) at an early stage
    /// when still bootstrapping the "full" authentication, HMACs are used
    /// in various places, namely for
    /// - the contents of the first (in symmetric order) index B-Tree node,
    /// - the extents lists and, if needed for the journal, contents of the
    ///   allocation bitmap file,
    /// - the extents lists of the authentication tree file,
    /// - the extents of the journal file.
    ///
    /// For clarification, it should be stressed that the sole purpose of these
    /// HMACs is to restrict an attacker in his ability to craft arbitrary
    /// ciphertexts and inject them to the filesystem code for decryption, by
    /// rejecting (with overwhelming probability) those that had not been
    /// created by the filesystem respectively someone with knowledge of the
    /// root key somewhen before. They do not, in any way, provide any sort
    /// of image content authentication.
    ///
    /// For the time being, it's recommended to set
    /// [`preauth_cca_protection_hmac_hash_alg`](Self::preauth_cca_protection_hmac_hash_alg) to
    /// [`auth_root_hmac_hash_alg`](Self::auth_tree_root_hmac_hash_alg) for
    /// maximum security. However, as the CCA protection HMACs are stored
    /// inline with the protected data structures and might consume a
    /// significant portion of space, and given that that the CCA
    /// model might not be of actual or limited concern for every real world
    /// application use case, this recommendation might get reviewed in the
    /// future. Even more so as domain specific encryption keys are being
    /// used for the CCA-protected entities, the latter of which, by
    /// themselves, might be of limited value if revealed.
    pub preauth_cca_protection_hmac_hash_alg: tpm2_interface::TpmiAlgHash,

    /// Hash algorithm to be used for the subkey KDF.
    pub kdf_hash_alg: tpm2_interface::TpmiAlgHash,

    /// Block cipher to use in CBC mode for encryption throughout.
    pub block_cipher_alg: symcipher::SymBlockCipherAlg,
}

impl ImageLayout {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        allocation_block_size_128b_log2: u8,
        io_block_allocation_blocks_log2: u8,
        auth_tree_node_io_blocks_log2: u8,
        auth_tree_data_block_allocation_blocks_log2: u8,
        allocation_bitmap_file_block_allocation_blocks_log2: u8,
        index_tree_node_allocation_blocks_log2: u8,
        auth_tree_node_hash_alg: tpm2_interface::TpmiAlgHash,
        auth_tree_data_hmac_hash_alg: tpm2_interface::TpmiAlgHash,
        auth_tree_root_hmac_hash_alg: tpm2_interface::TpmiAlgHash,
        preauth_cca_protection_hmac_hash_alg: tpm2_interface::TpmiAlgHash,
        kdf_hash_alg: tpm2_interface::TpmiAlgHash,
        block_cipher_alg: symcipher::SymBlockCipherAlg,
    ) -> Result<Self, NvFsError> {
        if allocation_block_size_128b_log2 as u32 + 7 >= u64::BITS {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidImageLayoutConfig));
        }
        if allocation_block_size_128b_log2 as u32 + 7 >= usize::BITS {
            return Err(NvFsError::DimensionsNotSupported);
        }

        if io_block_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32 + 7 >= u64::BITS {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidImageLayoutConfig));
        }
        if io_block_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32 + 7 >= usize::BITS {
            return Err(NvFsError::DimensionsNotSupported);
        }

        if auth_tree_node_io_blocks_log2 as u32
            + io_block_allocation_blocks_log2 as u32
            + allocation_block_size_128b_log2 as u32
            + 7
            >= u64::BITS
        {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidImageLayoutConfig));
        }
        if auth_tree_node_io_blocks_log2 as u32
            + io_block_allocation_blocks_log2 as u32
            + allocation_block_size_128b_log2 as u32
            + 7
            >= usize::BITS
        {
            return Err(NvFsError::DimensionsNotSupported);
        }

        if auth_tree_data_block_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32 + 7 >= u64::BITS
        {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidImageLayoutConfig));
        }
        if auth_tree_data_block_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32 + 7
            >= usize::BITS
        {
            return Err(NvFsError::DimensionsNotSupported);
        }

        // A Journal IO Block, which is the larger of an IO Block and an Authentication
        // Tree Data Block, must fit into the region covered by a single
        // allocation bitmap word.
        if 1u64 << io_block_allocation_blocks_log2.max(auth_tree_data_block_allocation_blocks_log2)
            > alloc_bitmap::BitmapWord::BITS as u64
        {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidImageLayoutConfig));
        }

        if allocation_bitmap_file_block_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32 + 7
            >= u64::BITS
        {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidImageLayoutConfig));
        }
        if allocation_bitmap_file_block_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32 + 7
            >= usize::BITS
        {
            return Err(NvFsError::DimensionsNotSupported);
        }

        if index_tree_node_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32 + 7 >= u64::BITS {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidImageLayoutConfig));
        }
        if index_tree_node_allocation_blocks_log2 as u32 + allocation_block_size_128b_log2 as u32 + 7 >= usize::BITS {
            return Err(NvFsError::DimensionsNotSupported);
        }

        // An index tree node block must fit into the region covered by a single
        // allocation bitmap word.
        if 1u64 << index_tree_node_allocation_blocks_log2 > alloc_bitmap::BitmapWord::BITS as u64 {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidImageLayoutConfig));
        }
        // Also, an index tree node must be encodable as a direct extent pointer,
        // because the special index root node inode is encoded that way.
        if 1u64 << index_tree_node_allocation_blocks_log2 > extent_ptr::EncodedExtentPtr::MAX_EXTENT_ALLOCATION_BLOCKS {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidImageLayoutConfig));
        }

        Ok(Self {
            allocation_block_size_128b_log2,
            io_block_allocation_blocks_log2,
            auth_tree_node_io_blocks_log2,
            auth_tree_data_block_allocation_blocks_log2,
            allocation_bitmap_file_block_allocation_blocks_log2,
            index_tree_node_allocation_blocks_log2,
            auth_tree_node_hash_alg,
            auth_tree_data_hmac_hash_alg,
            auth_tree_root_hmac_hash_alg,
            preauth_cca_protection_hmac_hash_alg,
            kdf_hash_alg,
            block_cipher_alg,
        })
    }

    pub const fn encoded_len() -> u8 {
        1u8 + 1
            + 1
            + 1
            + 1
            + 1
            + 5 * (tpm2_interface::TpmiAlgHash::marshalled_size() as u8)
            + tpm2_interface::TpmiAlgSymObject::marshalled_size() as u8
            + 2
    }

    pub fn encode(&self) -> Result<[u8; Self::encoded_len() as usize], NvFsError> {
        let mut result = [0u8; Self::encoded_len() as usize];

        result[0] = self.allocation_block_size_128b_log2;
        result[1] = self.io_block_allocation_blocks_log2;
        result[2] = self.auth_tree_node_io_blocks_log2;
        result[3] = self.auth_tree_data_block_allocation_blocks_log2;
        result[4] = self.allocation_bitmap_file_block_allocation_blocks_log2;
        result[5] = self.index_tree_node_allocation_blocks_log2;
        let mut buf = &mut result[6..];
        buf = self
            .auth_tree_node_hash_alg
            .marshal(buf)
            .map_err(|_| nvfs_err_internal!())?;
        buf = self
            .auth_tree_data_hmac_hash_alg
            .marshal(buf)
            .map_err(|_| nvfs_err_internal!())?;
        buf = self
            .auth_tree_root_hmac_hash_alg
            .marshal(buf)
            .map_err(|_| nvfs_err_internal!())?;
        buf = self
            .preauth_cca_protection_hmac_hash_alg
            .marshal(buf)
            .map_err(|_| nvfs_err_internal!())?;
        buf = self.kdf_hash_alg.marshal(buf).map_err(|_| nvfs_err_internal!())?;
        let (block_cipher_alg_id, block_cipher_key_size) =
            <(tpm2_interface::TpmiAlgSymObject, u16)>::from(&self.block_cipher_alg);
        buf = block_cipher_alg_id.marshal(buf).map_err(|_| nvfs_err_internal!())?;
        buf = tpm2_interface::marshal_u16(buf, block_cipher_key_size).map_err(|_| nvfs_err_internal!())?;
        debug_assert!(buf.is_empty());

        Ok(result)
    }

    pub fn decode(buf: &[u8]) -> Result<Self, NvFsError> {
        if buf.len() != Self::encoded_len() as usize {
            return Err(NvFsError::from(CocoonFsFormatError::InvalidImageHeaderFormat));
        }
        let allocation_block_size_128b_log2 = buf[0];
        let io_block_allocation_blocks_log2 = buf[1];
        let auth_tree_node_io_blocks_log2 = buf[2];
        let auth_tree_data_block_allocation_blocks_log2 = buf[3];
        let allocation_bitmap_file_block_allocation_blocks_log2 = buf[4];
        let index_tree_node_allocation_blocks_log2 = buf[5];

        let mut buf = &buf[6..];
        let auth_tree_node_hash_alg;
        (buf, auth_tree_node_hash_alg) = tpm2_interface::TpmiAlgHash::unmarshal(buf).map_err(|e| match e {
            tpm2_interface::TpmErr::Rc(tpm2_interface::TpmRc::HASH) => {
                NvFsError::from(CocoonFsFormatError::UnsupportedCryptoAlgorithm)
            }
            _ => nvfs_err_internal!(),
        })?;

        let auth_tree_data_hmac_hash_alg;
        (buf, auth_tree_data_hmac_hash_alg) = tpm2_interface::TpmiAlgHash::unmarshal(buf).map_err(|e| match e {
            tpm2_interface::TpmErr::Rc(tpm2_interface::TpmRc::HASH) => {
                NvFsError::from(CocoonFsFormatError::UnsupportedCryptoAlgorithm)
            }
            _ => nvfs_err_internal!(),
        })?;

        let auth_tree_root_hmac_hash_alg;
        (buf, auth_tree_root_hmac_hash_alg) = tpm2_interface::TpmiAlgHash::unmarshal(buf).map_err(|e| match e {
            tpm2_interface::TpmErr::Rc(tpm2_interface::TpmRc::HASH) => {
                NvFsError::from(CocoonFsFormatError::UnsupportedCryptoAlgorithm)
            }
            _ => nvfs_err_internal!(),
        })?;

        let preauth_cca_protection_hmac_hash_alg;
        (buf, preauth_cca_protection_hmac_hash_alg) =
            tpm2_interface::TpmiAlgHash::unmarshal(buf).map_err(|e| match e {
                tpm2_interface::TpmErr::Rc(tpm2_interface::TpmRc::HASH) => {
                    NvFsError::from(CocoonFsFormatError::UnsupportedCryptoAlgorithm)
                }
                _ => nvfs_err_internal!(),
            })?;

        let kdf_hash_alg;
        (buf, kdf_hash_alg) = tpm2_interface::TpmiAlgHash::unmarshal(buf).map_err(|e| match e {
            tpm2_interface::TpmErr::Rc(tpm2_interface::TpmRc::HASH) => {
                NvFsError::from(CocoonFsFormatError::UnsupportedCryptoAlgorithm)
            }
            _ => nvfs_err_internal!(),
        })?;

        let block_cipher_alg_id;
        (buf, block_cipher_alg_id) = tpm2_interface::TpmiAlgSymObject::unmarshal(buf).map_err(|e| match e {
            tpm2_interface::TpmErr::Rc(tpm2_interface::TpmRc::SYMMETRIC) => {
                NvFsError::from(CocoonFsFormatError::UnsupportedCryptoAlgorithm)
            }
            _ => nvfs_err_internal!(),
        })?;
        let block_cipher_key_size;
        (buf, block_cipher_key_size) = tpm2_interface::unmarshal_u16(buf).map_err(|_| nvfs_err_internal!())?;
        debug_assert!(buf.is_empty());
        let block_cipher_alg = symcipher::SymBlockCipherAlg::try_from((block_cipher_alg_id, block_cipher_key_size))
            .map_err(|e| match e {
                CryptoError::InvalidParams => NvFsError::from(CocoonFsFormatError::UnsupportedCryptoAlgorithm),
                _ => nvfs_err_internal!(),
            })?;

        Ok(Self {
            allocation_block_size_128b_log2,
            io_block_allocation_blocks_log2,
            auth_tree_node_io_blocks_log2,
            auth_tree_data_block_allocation_blocks_log2,
            allocation_bitmap_file_block_allocation_blocks_log2,
            index_tree_node_allocation_blocks_log2,
            auth_tree_node_hash_alg,
            auth_tree_data_hmac_hash_alg,
            auth_tree_root_hmac_hash_alg,
            preauth_cca_protection_hmac_hash_alg,
            kdf_hash_alg,
            block_cipher_alg,
        })
    }
}
