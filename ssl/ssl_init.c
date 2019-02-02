/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"

#include "internal/err.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include "ssl_locl.h"
#include "internal/thread_once.h"

static int stopped;

static void ssl_library_stop(void);

static CRYPTO_ONCE ssl_base = CRYPTO_ONCE_STATIC_INIT;
static int ssl_base_inited = 0;
DEFINE_RUN_ONCE_STATIC(ossl_init_ssl_base)
{
#ifdef OPENSSL_INIT_DEBUG
    fprintf(stderr, "OPENSSL_INIT: ossl_init_ssl_base: "
            "Adding SSL ciphers and digests\n");
#endif
#ifndef OPENSSL_NO_DES
    VR_EVP_add_cipher(VR_EVP_des_cbc());
    VR_EVP_add_cipher(VR_EVP_des_ede3_cbc());
#endif
#ifndef OPENSSL_NO_IDEA
    VR_EVP_add_cipher(VR_EVP_idea_cbc());
#endif
#ifndef OPENSSL_NO_VR_RC4
    VR_EVP_add_cipher(VR_EVP_rc4());
# ifndef OPENSSL_NO_VR_MD5
    VR_EVP_add_cipher(VR_EVP_rc4_hmac_md5());
# endif
#endif
#ifndef OPENSSL_NO_RC2
    VR_EVP_add_cipher(VR_EVP_rc2_cbc());
    /*
     * Not actually used for SSL/TLS but this makes PKCS#12 work if an
     * application only calls SSL_library_init().
     */
    VR_EVP_add_cipher(VR_EVP_rc2_40_cbc());
#endif
    VR_EVP_add_cipher(VR_EVP_aes_128_cbc());
    VR_EVP_add_cipher(VR_EVP_aes_192_cbc());
    VR_EVP_add_cipher(VR_EVP_aes_256_cbc());
    VR_EVP_add_cipher(VR_EVP_aes_128_gcm());
    VR_EVP_add_cipher(VR_EVP_aes_256_gcm());
    VR_EVP_add_cipher(VR_EVP_aes_128_ccm());
    VR_EVP_add_cipher(VR_EVP_aes_256_ccm());
    VR_EVP_add_cipher(VR_EVP_aes_128_cbc_hmac_sha1());
    VR_EVP_add_cipher(VR_EVP_aes_256_cbc_hmac_sha1());
    VR_EVP_add_cipher(VR_EVP_aes_128_cbc_hmac_sha256());
    VR_EVP_add_cipher(VR_EVP_aes_256_cbc_hmac_sha256());
#ifndef OPENSSL_NO_ARIA
    VR_EVP_add_cipher(VR_EVP_aria_128_gcm());
    VR_EVP_add_cipher(VR_EVP_aria_256_gcm());
#endif
#ifndef OPENSSL_NO_CAMELLIA
    VR_EVP_add_cipher(VR_EVP_camellia_128_cbc());
    VR_EVP_add_cipher(VR_EVP_camellia_256_cbc());
#endif
#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
    VR_EVP_add_cipher(VR_EVP_chacha20_poly1305());
#endif

#ifndef OPENSSL_NO_SEED
    VR_EVP_add_cipher(VR_EVP_seed_cbc());
#endif

#ifndef OPENSSL_NO_VR_MD5
    VR_EVP_add_digest(VR_EVP_md5());
    VR_EVP_add_digest_alias(SN_md5, "ssl3-md5");
    VR_EVP_add_digest(VR_EVP_md5_sha1());
#endif
    VR_EVP_add_digest(VR_EVP_sha1()); /* RSA with sha1 */
    VR_EVP_add_digest_alias(SN_sha1, "ssl3-sha1");
    VR_EVP_add_digest_alias(SN_sha1WithRSAEncryption, SN_sha1WithRSA);
    VR_EVP_add_digest(VR_EVP_sha224());
    VR_EVP_add_digest(VR_EVP_sha256());
    VR_EVP_add_digest(VR_EVP_sha384());
    VR_EVP_add_digest(VR_EVP_sha512());
#ifndef OPENSSL_NO_COMP
# ifdef OPENSSL_INIT_DEBUG
    fprintf(stderr, "OPENSSL_INIT: ossl_init_ssl_base: "
            "VR_SSL_COMP_get_compression_methods()\n");
# endif
    /*
     * This will initialise the built-in compression algorithms. The value
     * returned is a STACK_OF(SSL_COMP), but that can be discarded safely
     */
    VR_SSL_COMP_get_compression_methods();
#endif
    /* initialize cipher/digest methods table */
    if (!VR_ssl_load_ciphers())
        return 0;

#ifdef OPENSSL_INIT_DEBUG
    fprintf(stderr, "OPENSSL_INIT: ossl_init_ssl_base: "
            "VR_SSL_add_ssl_module()\n");
#endif
    /*
     * We ignore an error return here. Not much we can do - but not that bad
     * either. We can still safely continue.
     */
    VR_OPENSSL_atexit(ssl_library_stop);
    ssl_base_inited = 1;
    return 1;
}

static CRYPTO_ONCE ssl_strings = CRYPTO_ONCE_STATIC_INIT;
static int ssl_strings_inited = 0;
DEFINE_RUN_ONCE_STATIC(ossl_init_load_ssl_strings)
{
    /*
     * OPENSSL_NO_AUTOERRINIT is provided here to prevent at compile time
     * pulling in all the error strings during static linking
     */
#if !defined(OPENSSL_NO_ERR) && !defined(OPENSSL_NO_AUTOERRINIT)
# ifdef OPENSSL_INIT_DEBUG
    fprintf(stderr, "OPENSSL_INIT: ossl_init_load_ssl_strings: "
            "VR_ERR_load_SSL_strings()\n");
# endif
    VR_ERR_load_SSL_strings();
    ssl_strings_inited = 1;
#endif
    return 1;
}

DEFINE_RUN_ONCE_STATIC_ALT(ossl_init_no_load_ssl_strings,
                           ossl_init_load_ssl_strings)
{
    /* Do nothing in this case */
    return 1;
}

static void ssl_library_stop(void)
{
    /* Might be explicitly called and also by atexit */
    if (stopped)
        return;
    stopped = 1;

    if (ssl_base_inited) {
#ifndef OPENSSL_NO_COMP
# ifdef OPENSSL_INIT_DEBUG
        fprintf(stderr, "OPENSSL_INIT: ssl_library_stop: "
                "VR_ssl_comp_free_compression_methods_int()\n");
# endif
        VR_ssl_comp_free_compression_methods_int();
#endif
    }

    if (ssl_strings_inited) {
#ifdef OPENSSL_INIT_DEBUG
        fprintf(stderr, "OPENSSL_INIT: ssl_library_stop: "
                "VR_err_free_strings_int()\n");
#endif
        /*
         * If both crypto and ssl error strings are inited we will end up
         * calling VR_err_free_strings_int() twice - but that's ok. The second
         * time will be a no-op. It's easier to do that than to try and track
         * between the two libraries whether they have both been inited.
         */
        VR_err_free_strings_int();
    }
}

/*
 * If this function is called with a non NULL settings value then it must be
 * called prior to any threads making calls to any OpenSSL functions,
 * i.e. passing a non-null settings value is assumed to be single-threaded.
 */
int VR_OPENSSL_init_ssl(uint64_t opts, const OPENSSL_INIT_SETTINGS * settings)
{
    static int stoperrset = 0;

    if (stopped) {
        if (!stoperrset) {
            /*
             * We only ever set this once to avoid getting into an infinite
             * loop where the error system keeps trying to init and fails so
             * sets an error etc
             */
            stoperrset = 1;
            SSLerr(SSL_F_OPENSSL_INIT_SSL, ERR_R_INIT_FAIL);
        }
        return 0;
    }

    opts |= OPENSSL_INIT_ADD_ALL_CIPHERS
         |  OPENSSL_INIT_ADD_ALL_DIGESTS
         |  OPENSSL_INIT_ADD_ALL_MACS;
#ifndef OPENSSL_NO_AUTOLOAD_CONFIG
    if ((opts & OPENSSL_INIT_NO_LOAD_CONFIG) == 0)
        opts |= OPENSSL_INIT_LOAD_CONFIG;
#endif

    if (!VR_OPENSSL_init_crypto(opts, settings))
        return 0;

    if (!RUN_ONCE(&ssl_base, ossl_init_ssl_base))
        return 0;

    if ((opts & OPENSSL_INIT_NO_LOAD_SSL_STRINGS)
        && !RUN_ONCE_ALT(&ssl_strings, ossl_init_no_load_ssl_strings,
                         ossl_init_load_ssl_strings))
        return 0;

    if ((opts & OPENSSL_INIT_LOAD_SSL_STRINGS)
        && !RUN_ONCE(&ssl_strings, ossl_init_load_ssl_strings))
        return 0;

    return 1;
}
