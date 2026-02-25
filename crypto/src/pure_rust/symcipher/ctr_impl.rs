// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use cipher::{
    Block, BlockBackend, BlockCipher, BlockClosure, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, InnerIvInit, Iv,
    IvState, ParBlocksSizeUser,
    consts::U1,
    crypto_common::{InnerUser, IvSizeUser},
    generic_array::{ArrayLength, GenericArray},
    inout::InOut,
};
#[cfg(feature = "zeroize")]
use zeroize::Zeroize as _;

pub struct Encryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    cipher: C,
    iv: Block<C>,
    enc_iv_scratch: Block<C>,
}

impl<C> BlockSizeUser for Encryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    type BlockSize = C::BlockSize;
}

impl<C> BlockEncryptMut for Encryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    fn encrypt_with_backend_mut(&mut self, outer_closure: impl BlockClosure<BlockSize = Self::BlockSize>) {
        let Self {
            cipher,
            iv,
            enc_iv_scratch,
        } = self;
        cipher.encrypt_with_backend_mut(Closure {
            iv,
            enc_iv_scratch,
            outer_closure,
        })
    }
}

impl<C> InnerUser for Encryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    type Inner = C;
}

impl<C> IvSizeUser for Encryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    type IvSize = C::BlockSize;
}

impl<C> InnerIvInit for Encryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
            enc_iv_scratch: Block::<C>::default(),
        }
    }
}

impl<C> IvState for Encryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    #[inline]
    fn iv_state(&self) -> Iv<Self> {
        self.iv.clone()
    }
}

#[cfg(feature = "zeroize")]
impl<C: BlockEncryptMut + BlockCipher> Drop for Encryptor<C> {
    fn drop(&mut self) {
        self.iv.zeroize();
        self.enc_iv_scratch.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<C: BlockEncryptMut + BlockCipher + zeroize::ZeroizeOnDrop> zeroize::ZeroizeOnDrop for Encryptor<C> {}

pub struct Decryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    cipher: C,
    iv: Block<C>,
    enc_iv_scratch: Block<C>,
}

impl<C> BlockSizeUser for Decryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    type BlockSize = C::BlockSize;
}

impl<C> BlockDecryptMut for Decryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    fn decrypt_with_backend_mut(&mut self, outer_closure: impl BlockClosure<BlockSize = Self::BlockSize>) {
        let Self {
            cipher,
            iv,
            enc_iv_scratch,
        } = self;
        cipher.encrypt_with_backend_mut(Closure {
            iv,
            enc_iv_scratch,
            outer_closure,
        })
    }
}

impl<C> InnerUser for Decryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    type Inner = C;
}

impl<C> IvSizeUser for Decryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    type IvSize = C::BlockSize;
}

impl<C> InnerIvInit for Decryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
            enc_iv_scratch: Block::<C>::default(),
        }
    }
}

impl<C> IvState for Decryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    #[inline]
    fn iv_state(&self) -> Iv<Self> {
        self.iv.clone()
    }
}

#[cfg(feature = "zeroize")]
impl<C: BlockEncryptMut + BlockCipher> Drop for Decryptor<C> {
    fn drop(&mut self) {
        self.iv.zeroize();
        self.enc_iv_scratch.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<C: BlockEncryptMut + BlockCipher + zeroize::ZeroizeOnDrop> zeroize::ZeroizeOnDrop for Decryptor<C> {}

struct Closure<'a, BS, BC>
where
    BS: ArrayLength<u8>,
    BC: BlockClosure<BlockSize = BS>,
{
    iv: &'a mut GenericArray<u8, BS>,
    enc_iv_scratch: &'a mut GenericArray<u8, BS>,
    outer_closure: BC,
}

impl<BS, BC> BlockSizeUser for Closure<'_, BS, BC>
where
    BS: ArrayLength<u8>,
    BC: BlockClosure<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<BS, BC> BlockClosure for Closure<'_, BS, BC>
where
    BS: ArrayLength<u8>,
    BC: BlockClosure<BlockSize = BS>,
{
    #[inline(always)]
    fn call<B: BlockBackend<BlockSize = Self::BlockSize>>(self, inner_backend: &mut B) {
        let Self {
            iv,
            enc_iv_scratch,
            outer_closure,
        } = self;
        outer_closure.call(&mut Backend {
            iv,
            enc_iv_scratch,
            inner_backend,
        });
    }
}

struct Backend<'a, BS, BK>
where
    BS: ArrayLength<u8>,
    BK: BlockBackend<BlockSize = BS>,
{
    iv: &'a mut GenericArray<u8, BS>,
    enc_iv_scratch: &'a mut GenericArray<u8, BS>,
    inner_backend: &'a mut BK,
}

impl<BS, BK> BlockSizeUser for Backend<'_, BS, BK>
where
    BS: ArrayLength<u8>,
    BK: BlockBackend<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<BS, BK> ParBlocksSizeUser for Backend<'_, BS, BK>
where
    BS: ArrayLength<u8>,
    BK: BlockBackend<BlockSize = BS>,
{
    type ParBlocksSize = U1;
}

impl<BS, BK> BlockBackend for Backend<'_, BS, BK>
where
    BS: ArrayLength<u8>,
    BK: BlockBackend<BlockSize = BS>,
{
    #[inline(always)]
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        self.inner_backend
            .proc_block(InOut::from((&*self.iv, &mut *self.enc_iv_scratch)));
        block.xor_in2out(self.enc_iv_scratch);
        cmpa::ct_add_mp_l(
            &mut cmpa::MpMutBigEndianUIntByteSlice::from_bytes(self.iv.as_mut_slice()),
            1,
        );
    }
}
