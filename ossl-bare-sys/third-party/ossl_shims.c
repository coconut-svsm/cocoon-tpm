/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Red Hat
 * Author: Oliver Steffen <osteffen@redhat.com>
 */

/* Suppress OpenSSL 3.0 deprecation warnings for the legacy HMAC API. */
#define OPENSSL_SUPPRESS_DEPRECATED

#include "ossl_shims.h"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/modes.h>
#include <string.h>

unsigned ossl_shim_BN_num_bytes(const BIGNUM *bn)
{
	return (unsigned)BN_num_bytes(bn);
}

int ossl_shim_BN_bn2bin_padded(unsigned char *out, size_t len, const BIGNUM *in)
{
	/* OpenSSL's BN_bn2binpad takes int len, returns int (len on success, -1 on error).
	 * BoringSSL's BN_bn2bin_padded takes size_t len, returns 1/0. */
	if (len > (size_t)INT_MAX)
		return 0;
	int ret = BN_bn2binpad(in, out, (int)len);
	return ret >= 0 ? 1 : 0;
}

int ossl_shim_EVP_MD_size(const EVP_MD *md)
{
	return EVP_MD_get_size(md);
}

int ossl_shim_EVP_MD_CTX_size(const EVP_MD_CTX *ctx)
{
	return EVP_MD_CTX_get_size(ctx);
}

void ossl_shim_EVP_MD_CTX_cleanse(EVP_MD_CTX *ctx)
{
	/* BoringSSL zeros the digest state then cleans up.
	 * OpenSSL doesn't expose the internal state for zeroing, so we just reset. */
	EVP_MD_CTX_reset(ctx);
}

void ossl_shim_HMAC_CTX_init(HMAC_CTX *ctx)
{
	HMAC_CTX_reset(ctx);
}

void ossl_shim_HMAC_CTX_cleanup(HMAC_CTX *ctx)
{
	HMAC_CTX_reset(ctx);
}

int ossl_shim_HMAC_CTX_copy_ex(HMAC_CTX *dest, const HMAC_CTX *src)
{
	return HMAC_CTX_copy(dest, (HMAC_CTX *)src);
}

const EVP_MD *ossl_shim_HMAC_CTX_get_md(const HMAC_CTX *ctx)
{
	return HMAC_CTX_get_md(ctx);
}

size_t ossl_shim_HMAC_size(const HMAC_CTX *ctx)
{
	return HMAC_size(ctx);
}

/* Block encrypt callback for CRYPTO_ctr128_encrypt. */
static void aes_block128_f(const unsigned char in[16], unsigned char out[16],
                            const void *key)
{
	AES_encrypt(in, out, (const AES_KEY *)key);
}

void ossl_shim_AES_ctr128_encrypt(const unsigned char *in, unsigned char *out,
                                   size_t len, const AES_KEY *key,
                                   unsigned char ivec[16],
                                   unsigned char ecount_buf[16],
                                   unsigned int *num)
{
	CRYPTO_ctr128_encrypt(in, out, len, key, ivec, ecount_buf, num,
	                      aes_block128_f);
}

int ossl_shim_ERR_GET_LIB(unsigned long e)
{
	return ERR_GET_LIB(e);
}

int ossl_shim_ERR_GET_REASON(unsigned long e)
{
	return ERR_GET_REASON(e);
}
