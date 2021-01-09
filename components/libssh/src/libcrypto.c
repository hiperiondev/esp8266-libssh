/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 by Aris Adamantiadis
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/crypto.h"
#include "libssh/wrapper.h"
#include "libssh/libcrypto.h"
#if defined(HAVE_OPENSSL_EVP_CHACHA20) && defined(HAVE_OPENSSL_EVP_POLY1305)
#include "libssh/bytearray.h"
#include "libssh/chacha20-poly1305-common.h"
#endif

#ifdef HAVE_LIBCRYPTO

#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/engine.h>

#include "libcrypto-compat.h"

#ifdef HAVE_OPENSSL_AES_H
#define HAS_AES
#include <openssl/aes.h>
#endif
#ifdef HAVE_OPENSSL_DES_H
#define HAS_DES
#include <openssl/des.h>
#endif

#if (defined(HAVE_VALGRIND_VALGRIND_H) && defined(HAVE_OPENSSL_IA32CAP_LOC))
#include <valgrind/valgrind.h>
#define CAN_DISABLE_AESNI
#endif

#include "libssh/crypto.h"

#ifdef HAVE_OPENSSL_EVP_KDF_CTX_NEW_ID
#include <openssl/kdf.h>
#endif

#ifdef HAVE_OPENSSL_CRYPTO_CTR128_ENCRYPT
#include <openssl/modes.h>
#endif

#include "libssh/crypto.h"

static int libcrypto_initialized = 0;

void ssh_reseed(void){
#ifndef _WIN32
    struct timeval tv;
    gettimeofday(&tv, NULL);
    RAND_add(&tv, sizeof(tv), 0.0);
#endif
}

/**
 * @brief Get random bytes
 *
 * Make sure to always check the return code of this function!
 *
 * @param[in]  where    The buffer to fill with random bytes
 *
 * @param[in]  len      The size of the buffer to fill.
 *
 * @param[in]  strong   Use a strong or private RNG source.
 *
 * @return 1 on success, 0 on error.
 */
int ssh_get_random(void *where, int len, int strong)
{
#ifdef HAVE_OPENSSL_RAND_PRIV_BYTES
    if (strong) {
        /* Returns -1 when not supported, 0 on error, 1 on success */
        return !!RAND_priv_bytes(where, len);
    }
#else
    (void)strong;
#endif /* HAVE_RAND_PRIV_BYTES */

    /* Returns -1 when not supported, 0 on error, 1 on success */
    return !!RAND_bytes(where, len);
}

SHACTX sha1_init(void)
{
    int rc;
    SHACTX c = EVP_MD_CTX_create();
    if (c == NULL) {
        return NULL;
    }
    EVP_MD_CTX_init(c);
    rc = EVP_DigestInit_ex(c, EVP_sha1(), NULL);
    if (rc == 0) {
        EVP_MD_CTX_destroy(c);
        c = NULL;
    }
    return c;
}

void sha1_update(SHACTX c, const void *data, unsigned long len)
{
    EVP_DigestUpdate(c, data, len);
}

void sha1_final(unsigned char *md, SHACTX c)
{
    unsigned int mdlen = 0;

    EVP_DigestFinal(c, md, &mdlen);
    EVP_MD_CTX_destroy(c);
}

void sha1(const unsigned char *digest, int len, unsigned char *hash)
{
    SHACTX c = sha1_init();
    if (c != NULL) {
        sha1_update(c, digest, len);
        sha1_final(hash, c);
    }
}

#ifdef HAVE_OPENSSL_ECC
static const EVP_MD *nid_to_evpmd(int nid)
{
    switch (nid) {
        case NID_X9_62_prime256v1:
            return EVP_sha256();
        case NID_secp384r1:
            return EVP_sha384();
        case NID_secp521r1:
            return EVP_sha512();
        default:
            return NULL;
    }

    return NULL;
}

void evp(int nid, unsigned char *digest, int len, unsigned char *hash, unsigned int *hlen)
{
    const EVP_MD *evp_md = nid_to_evpmd(nid);
    EVP_MD_CTX *md = EVP_MD_CTX_new();

    EVP_DigestInit(md, evp_md);
    EVP_DigestUpdate(md, digest, len);
    EVP_DigestFinal(md, hash, hlen);
    EVP_MD_CTX_free(md);
}

EVPCTX evp_init(int nid)
{
    const EVP_MD *evp_md = nid_to_evpmd(nid);

    EVPCTX ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return NULL;
    }

    EVP_DigestInit(ctx, evp_md);

    return ctx;
}

void evp_update(EVPCTX ctx, const void *data, unsigned long len)
{
    EVP_DigestUpdate(ctx, data, len);
}

void evp_final(EVPCTX ctx, unsigned char *md, unsigned int *mdlen)
{
    EVP_DigestFinal(ctx, md, mdlen);
    EVP_MD_CTX_free(ctx);
}
#endif

SHA256CTX sha256_init(void)
{
    int rc;
    SHA256CTX c = EVP_MD_CTX_create();
    if (c == NULL) {
        return NULL;
    }
    EVP_MD_CTX_init(c);
    rc = EVP_DigestInit_ex(c, EVP_sha256(), NULL);
    if (rc == 0) {
        EVP_MD_CTX_destroy(c);
        c = NULL;
    }
    return c;
}

void sha256_update(SHA256CTX c, const void *data, unsigned long len)
{
    EVP_DigestUpdate(c, data, len);
}

void sha256_final(unsigned char *md, SHA256CTX c)
{
    unsigned int mdlen = 0;

    EVP_DigestFinal(c, md, &mdlen);
    EVP_MD_CTX_destroy(c);
}

void sha256(const unsigned char *digest, int len, unsigned char *hash)
{
    SHA256CTX c = sha256_init();
    if (c != NULL) {
        sha256_update(c, digest, len);
        sha256_final(hash, c);
    }
}

SHA384CTX sha384_init(void)
{
    int rc;
    SHA384CTX c = EVP_MD_CTX_create();
    if (c == NULL) {
        return NULL;
    }
    EVP_MD_CTX_init(c);
    rc = EVP_DigestInit_ex(c, EVP_sha384(), NULL);
    if (rc == 0) {
        EVP_MD_CTX_destroy(c);
        c = NULL;
    }
    return c;
}

void sha384_update(SHA384CTX c, const void *data, unsigned long len)
{
    EVP_DigestUpdate(c, data, len);
}

void sha384_final(unsigned char *md, SHA384CTX c)
{
    unsigned int mdlen = 0;

    EVP_DigestFinal(c, md, &mdlen);
    EVP_MD_CTX_destroy(c);
}

void sha384(const unsigned char *digest, int len, unsigned char *hash)
{
    SHA384CTX c = sha384_init();
    if (c != NULL) {
        sha384_update(c, digest, len);
        sha384_final(hash, c);
    }
}

SHA512CTX sha512_init(void)
{
    int rc = 0;
    SHA512CTX c = EVP_MD_CTX_create();
    if (c == NULL) {
        return NULL;
    }
    EVP_MD_CTX_init(c);
    rc = EVP_DigestInit_ex(c, EVP_sha512(), NULL);
    if (rc == 0) {
        EVP_MD_CTX_destroy(c);
        c = NULL;
    }
    return c;
}

void sha512_update(SHA512CTX c, const void *data, unsigned long len)
{
    EVP_DigestUpdate(c, data, len);
}

void sha512_final(unsigned char *md, SHA512CTX c)
{
    unsigned int mdlen = 0;

    EVP_DigestFinal(c, md, &mdlen);
    EVP_MD_CTX_destroy(c);
}

void sha512(const unsigned char *digest, int len, unsigned char *hash)
{
    SHA512CTX c = sha512_init();
    if (c != NULL) {
        sha512_update(c, digest, len);
        sha512_final(hash, c);
    }
}

MD5CTX md5_init(void)
{
    int rc;
    MD5CTX c = EVP_MD_CTX_create();
    if (c == NULL) {
        return NULL;
    }
    EVP_MD_CTX_init(c);
    rc = EVP_DigestInit_ex(c, EVP_md5(), NULL);
    if(rc == 0) {
        EVP_MD_CTX_destroy(c);
        c = NULL;
    }
    return c;
}

void md5_update(MD5CTX c, const void *data, unsigned long len)
{
    EVP_DigestUpdate(c, data, len);
}

void md5_final(unsigned char *md, MD5CTX c)
{
    unsigned int mdlen = 0;

    EVP_DigestFinal(c, md, &mdlen);
    EVP_MD_CTX_destroy(c);
}

#ifdef HAVE_OPENSSL_EVP_KDF_CTX_NEW_ID
static const EVP_MD *sshkdf_digest_to_md(enum ssh_kdf_digest digest_type)
{
    switch (digest_type) {
    case SSH_KDF_SHA1:
        return EVP_sha1();
    case SSH_KDF_SHA256:
        return EVP_sha256();
    case SSH_KDF_SHA384:
        return EVP_sha384();
    case SSH_KDF_SHA512:
        return EVP_sha512();
    }
    return NULL;
}

int ssh_kdf(struct ssh_crypto_struct *crypto,
            unsigned char *key, size_t key_len,
            int key_type, unsigned char *output,
            size_t requested_len)
{
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new_id(EVP_KDF_SSHKDF);
    int rc;

    if (ctx == NULL) {
        return -1;
    }

    rc = EVP_KDF_ctrl(ctx, EVP_KDF_CTRL_SET_MD,
                      sshkdf_digest_to_md(crypto->digest_type));
    if (rc != 1) {
        goto out;
    }
    rc = EVP_KDF_ctrl(ctx, EVP_KDF_CTRL_SET_KEY, key, key_len);
    if (rc != 1) {
        goto out;
    }
    rc = EVP_KDF_ctrl(ctx, EVP_KDF_CTRL_SET_SSHKDF_XCGHASH,
                      crypto->secret_hash, crypto->digest_len);
    if (rc != 1) {
        goto out;
    }
    rc = EVP_KDF_ctrl(ctx, EVP_KDF_CTRL_SET_SSHKDF_TYPE, key_type);
    if (rc != 1) {
        goto out;
    }
    rc = EVP_KDF_ctrl(ctx, EVP_KDF_CTRL_SET_SSHKDF_SESSION_ID,
                      crypto->session_id, crypto->digest_len);
    if (rc != 1) {
        goto out;
    }
    rc = EVP_KDF_derive(ctx, output, requested_len);
    if (rc != 1) {
        goto out;
    }

out:
    EVP_KDF_CTX_free(ctx);
    if (rc < 0) {
        return rc;
    }
    return 0;
}

#else
int ssh_kdf(struct ssh_crypto_struct *crypto,
            unsigned char *key, size_t key_len,
            int key_type, unsigned char *output,
            size_t requested_len)
{
    return sshkdf_derive_key(crypto, key, key_len,
                             key_type, output, requested_len);
}
#endif

HMACCTX hmac_init(const void *key, int len, enum ssh_hmac_e type) {
  HMACCTX ctx = NULL;

  ctx = HMAC_CTX_new();
  if (ctx == NULL) {
    return NULL;
  }


  switch(type) {
    case SSH_HMAC_SHA1:
      HMAC_Init_ex(ctx, key, len, EVP_sha1(), NULL);
      break;
    case SSH_HMAC_SHA256:
      HMAC_Init_ex(ctx, key, len, EVP_sha256(), NULL);
      break;
    case SSH_HMAC_SHA512:
      HMAC_Init_ex(ctx, key, len, EVP_sha512(), NULL);
      break;
    case SSH_HMAC_MD5:
      HMAC_Init_ex(ctx, key, len, EVP_md5(), NULL);
      break;
    default:
      HMAC_CTX_free(ctx);
      ctx = NULL;
  }

  return ctx;
}

void hmac_update(HMACCTX ctx, const void *data, unsigned long len) {
  HMAC_Update(ctx, data, len);
}

void hmac_final(HMACCTX ctx, unsigned char *hashmacbuf, unsigned int *len) {
  HMAC_Final(ctx,hashmacbuf,len);

#if OPENSSL_VERSION_NUMBER > 0x10100000L
  HMAC_CTX_free(ctx);
  ctx = NULL;
#else
  HMAC_cleanup(ctx);
  SAFE_FREE(ctx);
  ctx = NULL;
#endif
}

static void evp_cipher_init(struct ssh_cipher_struct *cipher) {
    if (cipher->ctx == NULL) {
        cipher->ctx = EVP_CIPHER_CTX_new();
    }

    switch(cipher->ciphertype){
    case SSH_AES128_CBC:
        cipher->cipher = EVP_aes_128_cbc();
        break;
    case SSH_AES192_CBC:
        cipher->cipher = EVP_aes_192_cbc();
        break;
    case SSH_AES256_CBC:
        cipher->cipher = EVP_aes_256_cbc();
        break;
#ifdef HAVE_OPENSSL_EVP_AES_CTR
    case SSH_AES128_CTR:
        cipher->cipher = EVP_aes_128_ctr();
        break;
    case SSH_AES192_CTR:
        cipher->cipher = EVP_aes_192_ctr();
        break;
    case SSH_AES256_CTR:
        cipher->cipher = EVP_aes_256_ctr();
        break;
#else
    case SSH_AES128_CTR:
    case SSH_AES192_CTR:
    case SSH_AES256_CTR:
        SSH_LOG(SSH_LOG_WARNING, "This cipher is not available in evp_cipher_init");
        break;
#endif
#ifdef HAVE_OPENSSL_EVP_AES_GCM
    case SSH_AEAD_AES128_GCM:
        cipher->cipher = EVP_aes_128_gcm();
        break;
    case SSH_AEAD_AES256_GCM:
        cipher->cipher = EVP_aes_256_gcm();
        break;
#else
    case SSH_AEAD_AES128_GCM:
    case SSH_AEAD_AES256_GCM:
        SSH_LOG(SSH_LOG_WARNING, "This cipher is not available in evp_cipher_init");
        break;
#endif /* HAVE_OPENSSL_EVP_AES_GCM */
    case SSH_3DES_CBC:
        cipher->cipher = EVP_des_ede3_cbc();
        break;
#ifdef WITH_BLOWFISH_CIPHER
    case SSH_BLOWFISH_CBC:
        cipher->cipher = EVP_bf_cbc();
        break;
        /* ciphers not using EVP */
#endif
    case SSH_AEAD_CHACHA20_POLY1305:
        SSH_LOG(SSH_LOG_WARNING, "The ChaCha cipher cannot be handled here");
        break;
    case SSH_NO_CIPHER:
        SSH_LOG(SSH_LOG_WARNING, "No valid ciphertype found");
        break;
    }
}

static int evp_cipher_set_encrypt_key(struct ssh_cipher_struct *cipher,
            void *key, void *IV)
{
    int rc;

    evp_cipher_init(cipher);
    EVP_CIPHER_CTX_reset(cipher->ctx);

    rc = EVP_EncryptInit_ex(cipher->ctx, cipher->cipher, NULL, key, IV);
    if (rc != 1){
        SSH_LOG(SSH_LOG_WARNING, "EVP_EncryptInit_ex failed");
        return SSH_ERROR;
    }

#ifdef HAVE_OPENSSL_EVP_AES_GCM
    /* For AES-GCM we need to set IV in specific way */
    if (cipher->ciphertype == SSH_AEAD_AES128_GCM ||
        cipher->ciphertype == SSH_AEAD_AES256_GCM) {
        rc = EVP_CIPHER_CTX_ctrl(cipher->ctx,
                                 EVP_CTRL_GCM_SET_IV_FIXED,
                                 -1,
                                 (uint8_t *)IV);
        if (rc != 1) {
            SSH_LOG(SSH_LOG_WARNING, "EVP_CTRL_GCM_SET_IV_FIXED failed");
            return SSH_ERROR;
        }
    }
#endif /* HAVE_OPENSSL_EVP_AES_GCM */

    EVP_CIPHER_CTX_set_padding(cipher->ctx, 0);

    return SSH_OK;
}

static int evp_cipher_set_decrypt_key(struct ssh_cipher_struct *cipher,
            void *key, void *IV) {
    int rc;

    evp_cipher_init(cipher);
    EVP_CIPHER_CTX_reset(cipher->ctx);

    rc = EVP_DecryptInit_ex(cipher->ctx, cipher->cipher, NULL, key, IV);
    if (rc != 1){
        SSH_LOG(SSH_LOG_WARNING, "EVP_DecryptInit_ex failed");
        return SSH_ERROR;
    }

#ifdef HAVE_OPENSSL_EVP_AES_GCM
    /* For AES-GCM we need to set IV in specific way */
    if (cipher->ciphertype == SSH_AEAD_AES128_GCM ||
        cipher->ciphertype == SSH_AEAD_AES256_GCM) {
        rc = EVP_CIPHER_CTX_ctrl(cipher->ctx,
                                 EVP_CTRL_GCM_SET_IV_FIXED,
                                 -1,
                                 (uint8_t *)IV);
        if (rc != 1) {
            SSH_LOG(SSH_LOG_WARNING, "EVP_CTRL_GCM_SET_IV_FIXED failed");
            return SSH_ERROR;
        }
    }
#endif /* HAVE_OPENSSL_EVP_AES_GCM */

    EVP_CIPHER_CTX_set_padding(cipher->ctx, 0);

    return SSH_OK;
}

/* EVP wrapper function for encrypt/decrypt */
static void evp_cipher_encrypt(struct ssh_cipher_struct *cipher,
                               void *in,
                               void *out,
                               size_t len)
{
    int outlen = 0;
    int rc = 0;

    rc = EVP_EncryptUpdate(cipher->ctx,
                           (unsigned char *)out,
                           &outlen,
                           (unsigned char *)in,
                           (int)len);
    if (rc != 1){
        SSH_LOG(SSH_LOG_WARNING, "EVP_EncryptUpdate failed");
        return;
    }
    if (outlen != (int)len){
        SSH_LOG(SSH_LOG_WARNING,
                "EVP_EncryptUpdate: output size %d for %zu in",
                outlen,
                len);
        return;
    }
}

static void evp_cipher_decrypt(struct ssh_cipher_struct *cipher,
                               void *in,
                               void *out,
                               size_t len)
{
    int outlen = 0;
    int rc = 0;

    rc = EVP_DecryptUpdate(cipher->ctx,
                           (unsigned char *)out,
                           &outlen,
                           (unsigned char *)in,
                           (int)len);
    if (rc != 1){
        SSH_LOG(SSH_LOG_WARNING, "EVP_DecryptUpdate failed");
        return;
    }
    if (outlen != (int)len){
        SSH_LOG(SSH_LOG_WARNING,
                "EVP_DecryptUpdate: output size %d for %zu in",
                outlen,
                len);
        return;
    }
}

static void evp_cipher_cleanup(struct ssh_cipher_struct *cipher) {
    if (cipher->ctx != NULL) {
        EVP_CIPHER_CTX_free(cipher->ctx);
    }
}

#ifndef HAVE_OPENSSL_EVP_AES_CTR
/* Some OS (osx, OpenIndiana, ...) have no support for CTR ciphers in EVP_aes */

struct ssh_aes_key_schedule {
    AES_KEY key;
    uint8_t IV[AES_BLOCK_SIZE];
};

static int aes_ctr_set_key(struct ssh_cipher_struct *cipher, void *key,
    void *IV) {
    int rc;

    if (cipher->aes_key == NULL) {
        cipher->aes_key = malloc(sizeof (struct ssh_aes_key_schedule));
    }
    if (cipher->aes_key == NULL) {
        return SSH_ERROR;
    }
    ZERO_STRUCTP(cipher->aes_key);
    /* CTR doesn't need a decryption key */
    rc = AES_set_encrypt_key(key, cipher->keysize, &cipher->aes_key->key);
    if (rc < 0) {
        SAFE_FREE(cipher->aes_key);
        return SSH_ERROR;
    }
    memcpy(cipher->aes_key->IV, IV, AES_BLOCK_SIZE);
    return SSH_OK;
}

static void
aes_ctr_encrypt(struct ssh_cipher_struct *cipher,
                void *in,
                void *out,
                size_t len)
{
  unsigned char tmp_buffer[AES_BLOCK_SIZE];
  unsigned int num=0;
  /* Some things are special with ctr128 :
   * In this case, tmp_buffer is not being used, because it is used to store temporary data
   * when an encryption is made on lengths that are not multiple of blocksize.
   * Same for num, which is being used to store the current offset in blocksize in CTR
   * function.
   */
#ifdef HAVE_OPENSSL_CRYPTO_CTR128_ENCRYPT
  CRYPTO_ctr128_encrypt(in, out, len, &cipher->aes_key->key, cipher->aes_key->IV, tmp_buffer, &num, (block128_f)AES_encrypt);
#else
  AES_ctr128_encrypt(in, out, len, &cipher->aes_key->key, cipher->aes_key->IV, tmp_buffer, &num);
#endif /* HAVE_OPENSSL_CRYPTO_CTR128_ENCRYPT */
}

static void aes_ctr_cleanup(struct ssh_cipher_struct *cipher){
    if (cipher != NULL) {
        if (cipher->aes_key != NULL) {
            explicit_bzero(cipher->aes_key, sizeof(*cipher->aes_key));
        }
        SAFE_FREE(cipher->aes_key);
    }
}

#endif /* HAVE_OPENSSL_EVP_AES_CTR */

#ifdef HAVE_OPENSSL_EVP_AES_GCM
static int
evp_cipher_aead_get_length(struct ssh_cipher_struct *cipher,
                           void *in,
                           uint8_t *out,
                           size_t len,
                           uint64_t seq)
{
    (void)cipher;
    (void)seq;

    /* The length is not encrypted: Copy it to the result buffer */
    memcpy(out, in, len);

    return SSH_OK;
}

static void
evp_cipher_aead_encrypt(struct ssh_cipher_struct *cipher,
                        void *in,
                        void *out,
                        size_t len,
                        uint8_t *tag,
                        uint64_t seq)
{
    size_t authlen, aadlen;
    uint8_t lastiv[1];
    int tmplen = 0;
    size_t outlen;
    int rc;

    (void) seq;

    aadlen = cipher->lenfield_blocksize;
    authlen = cipher->tag_size;

    /* increment IV */
    rc = EVP_CIPHER_CTX_ctrl(cipher->ctx,
                             EVP_CTRL_GCM_IV_GEN,
                             1,
                             lastiv);
    if (rc == 0) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_CTRL_GCM_IV_GEN failed");
        return;
    }

    /* Pass over the authenticated data (not encrypted) */
    rc = EVP_EncryptUpdate(cipher->ctx,
                           NULL,
                           &tmplen,
                           (unsigned char *)in,
                           (int)aadlen);
    outlen = tmplen;
    if (rc == 0 || outlen != aadlen) {
        SSH_LOG(SSH_LOG_WARNING, "Failed to pass authenticated data");
        return;
    }
    memcpy(out, in, aadlen);

    /* Encrypt the rest of the data */
    rc = EVP_EncryptUpdate(cipher->ctx,
                           (unsigned char *)out + aadlen,
                           &tmplen,
                           (unsigned char *)in + aadlen,
                           (int)len - aadlen);
    outlen = tmplen;
    if (rc != 1 || outlen != (int)len - aadlen) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_EncryptUpdate failed");
        return;
    }

    /* compute tag */
    rc = EVP_EncryptFinal(cipher->ctx,
                          NULL,
                          &tmplen);
    if (rc < 0) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_EncryptFinal failed: Failed to create a tag");
        return;
    }

    rc = EVP_CIPHER_CTX_ctrl(cipher->ctx,
                             EVP_CTRL_GCM_GET_TAG,
                             authlen,
                             (unsigned char *)tag);
    if (rc != 1) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_CTRL_GCM_GET_TAG failed");
        return;
    }
}

static int
evp_cipher_aead_decrypt(struct ssh_cipher_struct *cipher,
                        void *complete_packet,
                        uint8_t *out,
                        size_t encrypted_size,
                        uint64_t seq)
{
    size_t authlen, aadlen;
    uint8_t lastiv[1];
    int outlen = 0;
    int rc = 0;

    (void)seq;

    aadlen = cipher->lenfield_blocksize;
    authlen = cipher->tag_size;

    /* increment IV */
    rc = EVP_CIPHER_CTX_ctrl(cipher->ctx,
                             EVP_CTRL_GCM_IV_GEN,
                             1,
                             lastiv);
    if (rc == 0) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_CTRL_GCM_IV_GEN failed");
        return SSH_ERROR;
    }

    /* set tag for authentication */
    rc = EVP_CIPHER_CTX_ctrl(cipher->ctx,
                             EVP_CTRL_GCM_SET_TAG,
                             authlen,
                             (unsigned char *)complete_packet + aadlen + encrypted_size);
    if (rc == 0) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_CTRL_GCM_SET_TAG failed");
        return SSH_ERROR;
    }

    /* Pass over the authenticated data (not encrypted) */
    rc = EVP_DecryptUpdate(cipher->ctx,
                           NULL,
                           &outlen,
                           (unsigned char *)complete_packet,
                           (int)aadlen);
    if (rc == 0) {
        SSH_LOG(SSH_LOG_WARNING, "Failed to pass authenticated data");
        return SSH_ERROR;
    }
    /* Do not copy the length to the target buffer, because it is already processed */
    //memcpy(out, complete_packet, aadlen);

    /* Decrypt the rest of the data */
    rc = EVP_DecryptUpdate(cipher->ctx,
                           (unsigned char *)out,
                           &outlen,
                           (unsigned char *)complete_packet + aadlen,
                           encrypted_size /* already substracted aadlen*/);
    if (rc != 1) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_DecryptUpdate failed");
        return SSH_ERROR;
    }

    if (outlen != (int)encrypted_size) {
        SSH_LOG(SSH_LOG_WARNING,
                "EVP_DecryptUpdate: output size %d for %zd in",
                outlen,
                encrypted_size);
        return SSH_ERROR;
    }

    /* verify tag */
    rc = EVP_DecryptFinal(cipher->ctx,
                          NULL,
                          &outlen);
    if (rc < 0) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_DecryptFinal failed: Failed authentication");
        return SSH_ERROR;
    }

    return SSH_OK;
}

#endif /* HAVE_OPENSSL_EVP_AES_GCM */

#if defined(HAVE_OPENSSL_EVP_CHACHA20) && defined(HAVE_OPENSSL_EVP_POLY1305)

struct chacha20_poly1305_keysched {
    /* cipher handle used for encrypting the packets */
    EVP_CIPHER_CTX *main_evp;
    /* cipher handle used for encrypting the length field */
    EVP_CIPHER_CTX *header_evp;
    /* mac handle used for authenticating the packets */
    EVP_PKEY_CTX *pctx;
    /* Poly1305 key */
    EVP_PKEY *key;
    /* MD context for digesting data in poly1305 */
    EVP_MD_CTX *mctx;
};

static void
chacha20_poly1305_cleanup(struct ssh_cipher_struct *cipher)
{
    struct chacha20_poly1305_keysched *ctx = NULL;

    if (cipher->chacha20_schedule == NULL) {
        return;
    }

    ctx = cipher->chacha20_schedule;

    EVP_CIPHER_CTX_free(ctx->main_evp);
    ctx->main_evp  = NULL;
    EVP_CIPHER_CTX_free(ctx->header_evp);
    ctx->header_evp = NULL;
    /* ctx->pctx is freed as part of MD context */
    EVP_PKEY_free(ctx->key);
    ctx->key = NULL;
    EVP_MD_CTX_free(ctx->mctx);
    ctx->mctx = NULL;

    SAFE_FREE(cipher->chacha20_schedule);
}

static int
chacha20_poly1305_set_key(struct ssh_cipher_struct *cipher,
                          void *key,
                          UNUSED_PARAM(void *IV))
{
    struct chacha20_poly1305_keysched *ctx = NULL;
    uint8_t *u8key = key;
    int ret = SSH_ERROR, rv;

    if (cipher->chacha20_schedule == NULL) {
        ctx = calloc(1, sizeof(*ctx));
        if (ctx == NULL) {
            return -1;
        }
        cipher->chacha20_schedule = ctx;
    } else {
        ctx = cipher->chacha20_schedule;
    }

    /* ChaCha20 initialization */
    /* K2 uses the first half of the key */
    ctx->main_evp = EVP_CIPHER_CTX_new();
    if (ctx->main_evp == NULL) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_CIPHER_CTX_new failed");
        goto out;
    }
    rv = EVP_EncryptInit_ex(ctx->main_evp, EVP_chacha20(), NULL, u8key, NULL);
    if (rv != 1) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_CipherInit failed");
        goto out;
    }
    /* K1 uses the second half of the key */
    ctx->header_evp = EVP_CIPHER_CTX_new();
    if (ctx->header_evp == NULL) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_CIPHER_CTX_new failed");
        goto out;
    }
    ret = EVP_EncryptInit_ex(ctx->header_evp, EVP_chacha20(), NULL,
                             u8key + CHACHA20_KEYLEN, NULL);
    if (ret != 1) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_CipherInit failed");
        goto out;
    }

    /* The Poly1305 key initialization is delayed to the time we know
     * the actual key for packet so we do not need to create a bogus keys
     */
    ctx->mctx = EVP_MD_CTX_new();
    if (ctx->mctx == NULL) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_MD_CTX_new failed");
        return SSH_ERROR;
    }

    ret = SSH_OK;
out:
    if (ret != SSH_OK) {
        chacha20_poly1305_cleanup(cipher);
    }
    return ret;
}

static const uint8_t zero_block[CHACHA20_BLOCKSIZE] = {0};

static int
chacha20_poly1305_set_iv(struct ssh_cipher_struct *cipher,
                         uint64_t seq,
                         int do_encrypt)
{
    struct chacha20_poly1305_keysched *ctx = cipher->chacha20_schedule;
    uint8_t seqbuf[16] = {0};
    int ret;

    /* Prepare the IV for OpenSSL -- it needs to be 128 b long. First 32 b is
     * counter the rest is nonce. The memory is initialized to zeros
     * (counter starts from 0) and we set the sequence number in the second half
     */
    PUSH_BE_U64(seqbuf, 8, seq);
#ifdef DEBUG_CRYPTO
    ssh_log_hexdump("seqbuf (chacha20 IV)", seqbuf, sizeof(seqbuf));
#endif /* DEBUG_CRYPTO */

    ret = EVP_CipherInit_ex(ctx->header_evp, NULL, NULL, NULL, seqbuf, do_encrypt);
    if (ret != 1) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_CipherInit_ex(header_evp) failed");
        return SSH_ERROR;
    }

    ret = EVP_CipherInit_ex(ctx->main_evp, NULL, NULL, NULL, seqbuf, do_encrypt);
    if (ret != 1) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_CipherInit_ex(main_evp) failed");
        return SSH_ERROR;
    }

    return SSH_OK;
}

static int
chacha20_poly1305_packet_setup(struct ssh_cipher_struct *cipher,
                               uint64_t seq,
                               int do_encrypt)
{
    struct chacha20_poly1305_keysched *ctx = cipher->chacha20_schedule;
    uint8_t poly_key[CHACHA20_BLOCKSIZE];
    int ret = SSH_ERROR, len, rv;

    /* The initialization for decrypt was already done with the length block */
    if (do_encrypt) {
        rv = chacha20_poly1305_set_iv(cipher, seq, do_encrypt);
        if (rv != SSH_OK) {
            return SSH_ERROR;
        }
    }

    /* Output full ChaCha block so that counter increases by one for
     * next step. */
    rv = EVP_CipherUpdate(ctx->main_evp, poly_key, &len,
                           (unsigned char *)zero_block, sizeof(zero_block));
    if (rv != 1 || len != CHACHA20_BLOCKSIZE) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_EncryptUpdate failed");
        goto out;
    }
#ifdef DEBUG_CRYPTO
    ssh_log_hexdump("poly_key", poly_key, POLY1305_KEYLEN);
#endif /* DEBUG_CRYPTO */

    /* Set the Poly1305 key */
    if (ctx->key == NULL) {
        /* Poly1305 Initialization needs to know the actual key */
        ctx->key = EVP_PKEY_new_mac_key(EVP_PKEY_POLY1305, NULL,
                                        poly_key, POLY1305_KEYLEN);
        if (ctx->key == NULL) {
            SSH_LOG(SSH_LOG_WARNING, "EVP_PKEY_new_mac_key failed");
            goto out;
        }
        rv = EVP_DigestSignInit(ctx->mctx, &ctx->pctx, NULL, NULL, ctx->key);
        if (rv != 1) {
            SSH_LOG(SSH_LOG_WARNING, "EVP_DigestSignInit failed");
            goto out;
        }
    } else {
        /* Updating the key is easier but less obvious */
        rv = EVP_PKEY_CTX_ctrl(ctx->pctx, -1, EVP_PKEY_OP_SIGNCTX,
                                EVP_PKEY_CTRL_SET_MAC_KEY,
                                POLY1305_KEYLEN, (void *)poly_key);
        if (rv <= 0) {
            SSH_LOG(SSH_LOG_WARNING, "EVP_PKEY_CTX_ctrl failed");
            goto out;
        }
    }

    ret = SSH_OK;
out:
    explicit_bzero(poly_key, sizeof(poly_key));
    return ret;
}

static int
chacha20_poly1305_aead_decrypt_length(struct ssh_cipher_struct *cipher,
                                      void *in,
                                      uint8_t *out,
                                      size_t len,
                                      uint64_t seq)
{
    struct chacha20_poly1305_keysched *ctx = cipher->chacha20_schedule;
    int rv, outlen;

    if (len < sizeof(uint32_t)) {
        return SSH_ERROR;
    }

#ifdef DEBUG_CRYPTO
    ssh_log_hexdump("encrypted length", (uint8_t *)in, sizeof(uint32_t));
#endif /* DEBUG_CRYPTO */

    /* Set IV for the header EVP */
    rv = chacha20_poly1305_set_iv(cipher, seq, 0);
    if (rv != SSH_OK) {
        return SSH_ERROR;
    }

    rv = EVP_CipherUpdate(ctx->header_evp, out, &outlen, in, len);
    if (rv != 1 || outlen != sizeof(uint32_t)) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_CipherUpdate failed");
        return SSH_ERROR;
    }

#ifdef DEBUG_CRYPTO
    ssh_log_hexdump("deciphered length", out, sizeof(uint32_t));
#endif /* DEBUG_CRYPTO */

    rv = EVP_CipherFinal_ex(ctx->header_evp, out + outlen, &outlen);
    if (rv != 1 || outlen != 0) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_CipherFinal_ex failed");
        return SSH_ERROR;
    }

    return SSH_OK;
}

static int
chacha20_poly1305_aead_decrypt(struct ssh_cipher_struct *cipher,
                               void *complete_packet,
                               uint8_t *out,
                               size_t encrypted_size,
                               uint64_t seq)
{
    struct chacha20_poly1305_keysched *ctx = cipher->chacha20_schedule;
    uint8_t *mac = (uint8_t *)complete_packet + sizeof(uint32_t) +
                   encrypted_size;
    uint8_t tag[POLY1305_TAGLEN] = {0};
    int ret = SSH_ERROR;
    int rv, cmp, len = 0;
    size_t taglen = POLY1305_TAGLEN;

    /* Prepare the Poly1305 key */
    rv = chacha20_poly1305_packet_setup(cipher, seq, 0);
    if (rv != SSH_OK) {
        SSH_LOG(SSH_LOG_WARNING, "Failed to setup packet");
        goto out;
    }

#ifdef DEBUG_CRYPTO
    ssh_log_hexdump("received mac", mac, POLY1305_TAGLEN);
#endif /* DEBUG_CRYPTO */

    /* Calculate MAC of received data */
    rv = EVP_DigestSignUpdate(ctx->mctx, complete_packet,
                              encrypted_size + sizeof(uint32_t));
    if (rv != 1) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_DigestSignUpdate failed");
        goto out;
    }

    rv = EVP_DigestSignFinal(ctx->mctx, tag, &taglen);
    if (rv != 1) {
        SSH_LOG(SSH_LOG_WARNING, "poly1305 verify error");
        goto out;
    }

#ifdef DEBUG_CRYPTO
    ssh_log_hexdump("calculated mac", tag, POLY1305_TAGLEN);
#endif /* DEBUG_CRYPTO */

    /* Verify the calculated MAC matches the attached MAC */
    cmp = memcmp(tag, mac, POLY1305_TAGLEN);
    if (cmp != 0) {
        /* mac error */
        SSH_LOG(SSH_LOG_PACKET, "poly1305 verify error");
        return SSH_ERROR;
    }

    /* Decrypt the message */
    rv = EVP_CipherUpdate(ctx->main_evp, out, &len,
                          (uint8_t *)complete_packet + sizeof(uint32_t),
                          encrypted_size);
    if (rv != 1) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_CipherUpdate failed");
        goto out;
    }

    rv = EVP_CipherFinal_ex(ctx->main_evp, out + len, &len);
    if (rv != 1 || len != 0) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_CipherFinal_ex failed");
        goto out;
    }

    ret = SSH_OK;
out:
    return ret;
}

static void
chacha20_poly1305_aead_encrypt(struct ssh_cipher_struct *cipher,
                               void *in,
                               void *out,
                               size_t len,
                               uint8_t *tag,
                               uint64_t seq)
{
    struct ssh_packet_header *in_packet = in, *out_packet = out;
    struct chacha20_poly1305_keysched *ctx = cipher->chacha20_schedule;
    size_t taglen = POLY1305_TAGLEN;
    int ret, outlen = 0;

    /* Prepare the Poly1305 key */
    ret = chacha20_poly1305_packet_setup(cipher, seq, 1);
    if (ret != SSH_OK) {
        SSH_LOG(SSH_LOG_WARNING, "Failed to setup packet");
        return;
    }

#ifdef DEBUG_CRYPTO
    ssh_log_hexdump("plaintext length",
                    (unsigned char *)&in_packet->length, sizeof(uint32_t));
#endif /* DEBUG_CRYPTO */
    /* step 2, encrypt length field */
    ret = EVP_CipherUpdate(ctx->header_evp,
                           (unsigned char *)&out_packet->length,
                           &outlen,
                           (unsigned char *)&in_packet->length,
                           sizeof(uint32_t));
    if (ret != 1 || outlen != sizeof(uint32_t)) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_CipherUpdate failed");
        return;
    }
#ifdef DEBUG_CRYPTO
    ssh_log_hexdump("encrypted length",
                    (unsigned char *)&out_packet->length, outlen);
#endif /* DEBUG_CRYPTO */
    ret = EVP_CipherFinal_ex(ctx->header_evp, (uint8_t *)out + outlen, &outlen);
    if (ret != 1 || outlen != 0) {
        SSH_LOG(SSH_LOG_PACKET, "EVP_EncryptFinal_ex failed");
        return;
    }

    /* step 3, encrypt packet payload (main_evp counter == 1) */
    /* We already did encrypt one block so the counter should be in the correct position */
    ret = EVP_CipherUpdate(ctx->main_evp,
                           out_packet->payload,
                           &outlen,
                           in_packet->payload,
                           len - sizeof(uint32_t));
    if (ret != 1) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_CipherUpdate failed");
        return;
    }

    /* step 4, compute the MAC */
    ret = EVP_DigestSignUpdate(ctx->mctx, out_packet, len);
    if (ret <= 0) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_DigestSignUpdate failed");
        return;
    }
    ret = EVP_DigestSignFinal(ctx->mctx, tag, &taglen);
    if (ret <= 0) {
        SSH_LOG(SSH_LOG_WARNING, "EVP_DigestSignFinal failed");
        return;
    }
}
#endif /* defined(HAVE_OPENSSL_EVP_CHACHA20) && defined(HAVE_OPENSSL_EVP_POLY1305) */

#ifdef WITH_INSECURE_NONE
static void
none_crypt(UNUSED_PARAM(struct ssh_cipher_struct *cipher),
           void *in,
           void *out,
           size_t len)
{
    memcpy(out, in, len);
}
#endif /* WITH_INSECURE_NONE */

/*
 * The table of supported ciphers
 */
static struct ssh_cipher_struct ssh_ciphertab[] = {
#ifdef WITH_BLOWFISH_CIPHER
  {
    .name = "blowfish-cbc",
    .blocksize = 8,
    .ciphertype = SSH_BLOWFISH_CBC,
    .keysize = 128,
    .set_encrypt_key = evp_cipher_set_encrypt_key,
    .set_decrypt_key = evp_cipher_set_decrypt_key,
    .encrypt = evp_cipher_encrypt,
    .decrypt = evp_cipher_decrypt,
    .cleanup = evp_cipher_cleanup
  },
#endif
#ifdef HAS_AES
#ifdef HAVE_OPENSSL_EVP_AES_CTR
  {
    .name = "aes128-ctr",
    .blocksize = AES_BLOCK_SIZE,
    .ciphertype = SSH_AES128_CTR,
    .keysize = 128,
    .set_encrypt_key = evp_cipher_set_encrypt_key,
    .set_decrypt_key = evp_cipher_set_decrypt_key,
    .encrypt = evp_cipher_encrypt,
    .decrypt = evp_cipher_decrypt,
    .cleanup = evp_cipher_cleanup
  },
  {
    .name = "aes192-ctr",
    .blocksize = AES_BLOCK_SIZE,
    .ciphertype = SSH_AES192_CTR,
    .keysize = 192,
    .set_encrypt_key = evp_cipher_set_encrypt_key,
    .set_decrypt_key = evp_cipher_set_decrypt_key,
    .encrypt = evp_cipher_encrypt,
    .decrypt = evp_cipher_decrypt,
    .cleanup = evp_cipher_cleanup
  },
  {
    .name = "aes256-ctr",
    .blocksize = AES_BLOCK_SIZE,
    .ciphertype = SSH_AES256_CTR,
    .keysize = 256,
    .set_encrypt_key = evp_cipher_set_encrypt_key,
    .set_decrypt_key = evp_cipher_set_decrypt_key,
    .encrypt = evp_cipher_encrypt,
    .decrypt = evp_cipher_decrypt,
    .cleanup = evp_cipher_cleanup
  },
#else /* HAVE_OPENSSL_EVP_AES_CTR */
  {
    .name = "aes128-ctr",
    .blocksize = AES_BLOCK_SIZE,
    .ciphertype = SSH_AES128_CTR,
    .keysize = 128,
    .set_encrypt_key = aes_ctr_set_key,
    .set_decrypt_key = aes_ctr_set_key,
    .encrypt = aes_ctr_encrypt,
    .decrypt = aes_ctr_encrypt,
    .cleanup = aes_ctr_cleanup
  },
  {
    .name = "aes192-ctr",
    .blocksize = AES_BLOCK_SIZE,
    .ciphertype = SSH_AES192_CTR,
    .keysize = 192,
    .set_encrypt_key = aes_ctr_set_key,
    .set_decrypt_key = aes_ctr_set_key,
    .encrypt = aes_ctr_encrypt,
    .decrypt = aes_ctr_encrypt,
    .cleanup = aes_ctr_cleanup
  },
  {
    .name = "aes256-ctr",
    .blocksize = AES_BLOCK_SIZE,
    .ciphertype = SSH_AES256_CTR,
    .keysize = 256,
    .set_encrypt_key = aes_ctr_set_key,
    .set_decrypt_key = aes_ctr_set_key,
    .encrypt = aes_ctr_encrypt,
    .decrypt = aes_ctr_encrypt,
    .cleanup = aes_ctr_cleanup
  },
#endif /* HAVE_OPENSSL_EVP_AES_CTR */
  {
    .name = "aes128-cbc",
    .blocksize = AES_BLOCK_SIZE,
    .ciphertype = SSH_AES128_CBC,
    .keysize = 128,
    .set_encrypt_key = evp_cipher_set_encrypt_key,
    .set_decrypt_key = evp_cipher_set_decrypt_key,
    .encrypt = evp_cipher_encrypt,
    .decrypt = evp_cipher_decrypt,
    .cleanup = evp_cipher_cleanup
  },
  {
    .name = "aes192-cbc",
    .blocksize = AES_BLOCK_SIZE,
    .ciphertype = SSH_AES192_CBC,
    .keysize = 192,
    .set_encrypt_key = evp_cipher_set_encrypt_key,
    .set_decrypt_key = evp_cipher_set_decrypt_key,
    .encrypt = evp_cipher_encrypt,
    .decrypt = evp_cipher_decrypt,
    .cleanup = evp_cipher_cleanup
  },
  {
    .name = "aes256-cbc",
    .blocksize = AES_BLOCK_SIZE,
    .ciphertype = SSH_AES256_CBC,
    .keysize = 256,
    .set_encrypt_key = evp_cipher_set_encrypt_key,
    .set_decrypt_key = evp_cipher_set_decrypt_key,
    .encrypt = evp_cipher_encrypt,
    .decrypt = evp_cipher_decrypt,
    .cleanup = evp_cipher_cleanup
  },
#ifdef HAVE_OPENSSL_EVP_AES_GCM
  {
    .name = "aes128-gcm@openssh.com",
    .blocksize = AES_BLOCK_SIZE,
    .lenfield_blocksize = 4, /* not encrypted, but authenticated */
    .ciphertype = SSH_AEAD_AES128_GCM,
    .keysize = 128,
    .tag_size = AES_GCM_TAGLEN,
    .set_encrypt_key = evp_cipher_set_encrypt_key,
    .set_decrypt_key = evp_cipher_set_decrypt_key,
    .aead_encrypt = evp_cipher_aead_encrypt,
    .aead_decrypt_length = evp_cipher_aead_get_length,
    .aead_decrypt = evp_cipher_aead_decrypt,
    .cleanup = evp_cipher_cleanup
  },
  {
    .name = "aes256-gcm@openssh.com",
    .blocksize = AES_BLOCK_SIZE,
    .lenfield_blocksize = 4, /* not encrypted, but authenticated */
    .ciphertype = SSH_AEAD_AES256_GCM,
    .keysize = 256,
    .tag_size = AES_GCM_TAGLEN,
    .set_encrypt_key = evp_cipher_set_encrypt_key,
    .set_decrypt_key = evp_cipher_set_decrypt_key,
    .aead_encrypt = evp_cipher_aead_encrypt,
    .aead_decrypt_length = evp_cipher_aead_get_length,
    .aead_decrypt = evp_cipher_aead_decrypt,
    .cleanup = evp_cipher_cleanup
  },
#endif /* HAVE_OPENSSL_EVP_AES_GCM */
#endif /* HAS_AES */
#ifdef HAS_DES
  {
    .name = "3des-cbc",
    .blocksize = 8,
    .ciphertype = SSH_3DES_CBC,
    .keysize = 192,
    .set_encrypt_key = evp_cipher_set_encrypt_key,
    .set_decrypt_key = evp_cipher_set_decrypt_key,
    .encrypt = evp_cipher_encrypt,
    .decrypt = evp_cipher_decrypt,
    .cleanup = evp_cipher_cleanup
  },
#endif /* HAS_DES */
  {
#if defined(HAVE_OPENSSL_EVP_CHACHA20) && defined(HAVE_OPENSSL_EVP_POLY1305)
    .ciphertype = SSH_AEAD_CHACHA20_POLY1305,
    .name = "chacha20-poly1305@openssh.com",
    .blocksize = CHACHA20_BLOCKSIZE/8,
    .lenfield_blocksize = 4,
    .keylen = sizeof(struct chacha20_poly1305_keysched),
    .keysize = 2 * CHACHA20_KEYLEN * 8,
    .tag_size = POLY1305_TAGLEN,
    .set_encrypt_key = chacha20_poly1305_set_key,
    .set_decrypt_key = chacha20_poly1305_set_key,
    .aead_encrypt = chacha20_poly1305_aead_encrypt,
    .aead_decrypt_length = chacha20_poly1305_aead_decrypt_length,
    .aead_decrypt = chacha20_poly1305_aead_decrypt,
    .cleanup = chacha20_poly1305_cleanup
#else
    .name = "chacha20-poly1305@openssh.com"
#endif /* defined(HAVE_OPENSSL_EVP_CHACHA20) && defined(HAVE_OPENSSL_EVP_POLY1305) */
  },
#ifdef WITH_INSECURE_NONE
  {
    .name = "none",
    .blocksize = 8,
    .keysize = 0,
    .encrypt = none_crypt,
    .decrypt = none_crypt,
  },
#endif /* WITH_INSECURE_NONE */
  {
    .name = NULL
  }
};

struct ssh_cipher_struct *ssh_get_ciphertab(void)
{
  return ssh_ciphertab;
}

/**
 * @internal
 * @brief Initialize libcrypto's subsystem
 */
int ssh_crypto_init(void)
{
    UNUSED_VAR(size_t i);

    if (libcrypto_initialized) {
        return SSH_OK;
    }
    if (OpenSSL_version_num() != OPENSSL_VERSION_NUMBER){
        SSH_LOG(SSH_LOG_WARNING, "libssh compiled with %s "
            "headers, currently running with %s.",
            OPENSSL_VERSION_TEXT,
            OpenSSL_version(OpenSSL_version_num())
        );
    }
#ifdef CAN_DISABLE_AESNI
    /*
     * disable AES-NI when running within Valgrind, because they generate
     * too many "uninitialized memory access" false positives
     */
    if (RUNNING_ON_VALGRIND){
        SSH_LOG(SSH_LOG_INFO, "Running within Valgrind, disabling AES-NI");
        /* Bit #57 denotes AES-NI instruction set extension */
        OPENSSL_ia32cap &= ~(1LL << 57);
    }
#endif
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    OpenSSL_add_all_algorithms();
#endif

#if !defined(HAVE_OPENSSL_EVP_CHACHA20) || !defined(HAVE_OPENSSL_EVP_POLY1305)
    for (i = 0; ssh_ciphertab[i].name != NULL; i++) {
        int cmp;

        cmp = strcmp(ssh_ciphertab[i].name, "chacha20-poly1305@openssh.com");
        if (cmp == 0) {
            memcpy(&ssh_ciphertab[i],
                   ssh_get_chacha20poly1305_cipher(),
                   sizeof(struct ssh_cipher_struct));
            break;
        }
    }
#endif /* !defined(HAVE_OPENSSL_EVP_CHACHA20) || !defined(HAVE_OPENSSL_EVP_POLY1305) */

    libcrypto_initialized = 1;

    return SSH_OK;
}

/**
 * @internal
 * @brief Finalize libcrypto's subsystem
 */
void ssh_crypto_finalize(void)
{
    if (!libcrypto_initialized) {
        return;
    }

    ENGINE_cleanup();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
#endif

    libcrypto_initialized = 0;
}

#endif /* LIBCRYPTO */
