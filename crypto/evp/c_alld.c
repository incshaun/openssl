/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include "internal/evp_int.h"
#include <openssl/pkcs12.h>
#include <openssl/objects.h>

void VR_openssl_add_all_digests_int(void)
{
#ifndef OPENSSL_NO_VR_MD4
    VR_EVP_add_digest(VR_EVP_md4());
#endif
#ifndef OPENSSL_NO_VR_MD5
    VR_EVP_add_digest(VR_EVP_md5());
    VR_EVP_add_digest_alias(SN_md5, "ssl3-md5");
    VR_EVP_add_digest(VR_EVP_md5_sha1());
#endif
    VR_EVP_add_digest(VR_EVP_sha1());
    VR_EVP_add_digest_alias(SN_sha1, "ssl3-sha1");
    VR_EVP_add_digest_alias(SN_sha1WithRSAEncryption, SN_sha1WithRSA);
#if !defined(OPENSSL_NO_VR_MDC2) && !defined(OPENSSL_NO_DES)
    VR_EVP_add_digest(VR_EVP_mdc2());
#endif
#ifndef OPENSSL_NO_RMD160
    VR_EVP_add_digest(VR_EVP_ripemd160());
    VR_EVP_add_digest_alias(SN_ripemd160, "ripemd");
    VR_EVP_add_digest_alias(SN_ripemd160, "rmd160");
#endif
    VR_EVP_add_digest(VR_EVP_sha224());
    VR_EVP_add_digest(VR_EVP_sha256());
    VR_EVP_add_digest(VR_EVP_sha384());
    VR_EVP_add_digest(VR_EVP_sha512());
    VR_EVP_add_digest(VR_EVP_sha512_224());
    VR_EVP_add_digest(VR_EVP_sha512_256());
#ifndef OPENSSL_NO_VR_WHIRLPOOL
    VR_EVP_add_digest(VR_EVP_whirlpool());
#endif
#ifndef OPENSSL_NO_SM3
    VR_EVP_add_digest(VR_EVP_sm3());
#endif
#ifndef OPENSSL_NO_BLAKE2
    VR_EVP_add_digest(VR_EVP_blake2b512());
    VR_EVP_add_digest(VR_EVP_blake2s256());
#endif
    VR_EVP_add_digest(VR_EVP_sha3_224());
    VR_EVP_add_digest(VR_EVP_sha3_256());
    VR_EVP_add_digest(VR_EVP_sha3_384());
    VR_EVP_add_digest(VR_EVP_sha3_512());
    VR_EVP_add_digest(VR_EVP_shake128());
    VR_EVP_add_digest(VR_EVP_shake256());
}
