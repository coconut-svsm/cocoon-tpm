/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Red Hat
 * Author: Oliver Steffen <osteffen@redhat.com>
 *
 * Compatibility shims providing BoringSSL-like API on top of OpenSSL.
 * These are thin wrappers around OpenSSL functions or re-implementations
 * of BoringSSL-specific functions. Macros that bindgen cannot see are
 * also wrapped as real functions here.
 */

#ifndef OSSL_SHIMS_H
#define OSSL_SHIMS_H

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <stddef.h>

/*
 * BN_num_bytes is a macro in OpenSSL. Provide as a function for bindgen.
 */
unsigned ossl_shim_BN_num_bytes(const BIGNUM *bn);

/*
 * BN_bn2bin_padded: BoringSSL-specific (size_t len).
 * OpenSSL has BN_bn2binpad (int len, returns int len or -1).
 * This shim matches the BoringSSL signature: returns 1 on success, 0 on failure.
 */
int ossl_shim_BN_bn2bin_padded(unsigned char *out, size_t len, const BIGNUM *in);

/*
 * EVP_MD_size is a macro in OpenSSL (maps to EVP_MD_get_size).
 * Provide as a function for bindgen.
 */
int ossl_shim_EVP_MD_size(const EVP_MD *md);

/*
 * EVP_MD_CTX_size is a macro in OpenSSL (maps to EVP_MD_CTX_get_size_ex).
 * Provide as a function for bindgen.
 */
int ossl_shim_EVP_MD_CTX_size(const EVP_MD_CTX *ctx);

/*
 * EVP_MD_CTX_cleanse: BoringSSL-specific. Zeros digest state, then cleans up.
 * We approximate with EVP_MD_CTX_reset.
 */
void ossl_shim_EVP_MD_CTX_cleanse(EVP_MD_CTX *ctx);

/*
 * HMAC_CTX_init: BoringSSL-specific (for stack-allocated contexts).
 * Map to HMAC_CTX_reset in OpenSSL.
 */
void ossl_shim_HMAC_CTX_init(HMAC_CTX *ctx);

/*
 * HMAC_CTX_cleanup: BoringSSL-specific (free internals, not the ctx itself).
 * Map to HMAC_CTX_reset in OpenSSL.
 */
void ossl_shim_HMAC_CTX_cleanup(HMAC_CTX *ctx);

/*
 * HMAC_CTX_copy_ex: BoringSSL-specific. Like HMAC_CTX_copy but dest must
 * already be initialized.
 * Map to HMAC_CTX_copy in OpenSSL (which handles this case).
 */
int ossl_shim_HMAC_CTX_copy_ex(HMAC_CTX *dest, const HMAC_CTX *src);

/*
 * HMAC_CTX_get_md: deprecated in OpenSSL 3.0 but still available.
 * Provide a shim to avoid deprecation warnings.
 */
const EVP_MD *ossl_shim_HMAC_CTX_get_md(const HMAC_CTX *ctx);

/*
 * HMAC_size: deprecated in OpenSSL 3.0.
 * Provide a shim to avoid deprecation warnings.
 */
size_t ossl_shim_HMAC_size(const HMAC_CTX *ctx);

/*
 * AES_ctr128_encrypt: available in BoringSSL but not directly in OpenSSL's
 * public AES API. Implemented using CRYPTO_ctr128_encrypt + AES_encrypt.
 */
void ossl_shim_AES_ctr128_encrypt(const unsigned char *in, unsigned char *out,
                                   size_t len, const AES_KEY *key,
                                   unsigned char ivec[16],
                                   unsigned char ecount_buf[16],
                                   unsigned int *num);

/*
 * ERR_GET_LIB / ERR_GET_REASON are macros in OpenSSL.
 * Provide as functions for bindgen so the Rust side doesn't
 * need to reimplement the bit layout.
 */
int ossl_shim_ERR_GET_LIB(unsigned long e);
int ossl_shim_ERR_GET_REASON(unsigned long e);

#endif /* OSSL_SHIMS_H */
