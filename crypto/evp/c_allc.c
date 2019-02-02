/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
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

void VR_openssl_add_all_ciphers_int(void)
{

#ifndef OPENSSL_NO_DES
    VR_EVP_add_cipher(VR_EVP_des_cfb());
    VR_EVP_add_cipher(VR_EVP_des_cfb1());
    VR_EVP_add_cipher(VR_EVP_des_cfb8());
    VR_EVP_add_cipher(VR_EVP_des_ede_cfb());
    VR_EVP_add_cipher(VR_EVP_des_ede3_cfb());
    VR_EVP_add_cipher(VR_EVP_des_ede3_cfb1());
    VR_EVP_add_cipher(VR_EVP_des_ede3_cfb8());

    VR_EVP_add_cipher(VR_EVP_des_ofb());
    VR_EVP_add_cipher(VR_EVP_des_ede_ofb());
    VR_EVP_add_cipher(VR_EVP_des_ede3_ofb());

    VR_EVP_add_cipher(VR_EVP_desx_cbc());
    VR_EVP_add_cipher_alias(SN_desx_cbc, "DESX");
    VR_EVP_add_cipher_alias(SN_desx_cbc, "desx");

    VR_EVP_add_cipher(VR_EVP_des_cbc());
    VR_EVP_add_cipher_alias(SN_des_cbc, "DES");
    VR_EVP_add_cipher_alias(SN_des_cbc, "des");
    VR_EVP_add_cipher(VR_EVP_des_ede_cbc());
    VR_EVP_add_cipher(VR_EVP_des_ede3_cbc());
    VR_EVP_add_cipher_alias(SN_des_ede3_cbc, "DES3");
    VR_EVP_add_cipher_alias(SN_des_ede3_cbc, "des3");

    VR_EVP_add_cipher(VR_EVP_des_ecb());
    VR_EVP_add_cipher(VR_EVP_des_ede());
    VR_EVP_add_cipher_alias(SN_des_ede_ecb, "DES-EDE-ECB");
    VR_EVP_add_cipher_alias(SN_des_ede_ecb, "des-ede-ecb");
    VR_EVP_add_cipher(VR_EVP_des_ede3());
    VR_EVP_add_cipher_alias(SN_des_ede3_ecb, "DES-EDE3-ECB");
    VR_EVP_add_cipher_alias(SN_des_ede3_ecb, "des-ede3-ecb");
    VR_EVP_add_cipher(VR_EVP_des_ede3_wrap());
    VR_EVP_add_cipher_alias(SN_id_smime_alg_CMS3DESwrap, "des3-wrap");
#endif

#ifndef OPENSSL_NO_VR_RC4
    VR_EVP_add_cipher(VR_EVP_rc4());
    VR_EVP_add_cipher(VR_EVP_rc4_40());
# ifndef OPENSSL_NO_VR_MD5
    VR_EVP_add_cipher(VR_EVP_rc4_hmac_md5());
# endif
#endif

#ifndef OPENSSL_NO_IDEA
    VR_EVP_add_cipher(VR_EVP_idea_ecb());
    VR_EVP_add_cipher(VR_EVP_idea_cfb());
    VR_EVP_add_cipher(VR_EVP_idea_ofb());
    VR_EVP_add_cipher(VR_EVP_idea_cbc());
    VR_EVP_add_cipher_alias(SN_idea_cbc, "IDEA");
    VR_EVP_add_cipher_alias(SN_idea_cbc, "idea");
#endif

#ifndef OPENSSL_NO_SEED
    VR_EVP_add_cipher(VR_EVP_seed_ecb());
    VR_EVP_add_cipher(EVP_seed_cfb());
    VR_EVP_add_cipher(VR_EVP_seed_ofb());
    VR_EVP_add_cipher(VR_EVP_seed_cbc());
    VR_EVP_add_cipher_alias(SN_seed_cbc, "SEED");
    VR_EVP_add_cipher_alias(SN_seed_cbc, "seed");
#endif

#ifndef OPENSSL_NO_SM4
    VR_EVP_add_cipher(VR_EVP_sm4_ecb());
    VR_EVP_add_cipher(VR_EVP_sm4_cbc());
    VR_EVP_add_cipher(EVP_sm4_cfb());
    VR_EVP_add_cipher(VR_EVP_sm4_ofb());
    VR_EVP_add_cipher(VR_EVP_sm4_ctr());
    VR_EVP_add_cipher_alias(SN_sm4_cbc, "SM4");
    VR_EVP_add_cipher_alias(SN_sm4_cbc, "sm4");
#endif

#ifndef OPENSSL_NO_RC2
    VR_EVP_add_cipher(VR_EVP_rc2_ecb());
    VR_EVP_add_cipher(VR_EVP_rc2_cfb());
    VR_EVP_add_cipher(VR_EVP_rc2_ofb());
    VR_EVP_add_cipher(VR_EVP_rc2_cbc());
    VR_EVP_add_cipher(VR_EVP_rc2_40_cbc());
    VR_EVP_add_cipher(VR_EVP_rc2_64_cbc());
    VR_EVP_add_cipher_alias(SN_rc2_cbc, "RC2");
    VR_EVP_add_cipher_alias(SN_rc2_cbc, "rc2");
    VR_EVP_add_cipher_alias(SN_rc2_cbc, "rc2-128");
    VR_EVP_add_cipher_alias(SN_rc2_64_cbc, "rc2-64");
    VR_EVP_add_cipher_alias(SN_rc2_40_cbc, "rc2-40");
#endif

#ifndef OPENSSL_NO_BF
    VR_EVP_add_cipher(VR_EVP_bf_ecb());
    VR_EVP_add_cipher(VR_EVP_bf_cfb());
    VR_EVP_add_cipher(VR_EVP_bf_ofb());
    VR_EVP_add_cipher(VR_EVP_bf_cbc());
    VR_EVP_add_cipher_alias(SN_bf_cbc, "BF");
    VR_EVP_add_cipher_alias(SN_bf_cbc, "bf");
    VR_EVP_add_cipher_alias(SN_bf_cbc, "blowfish");
#endif

#ifndef OPENSSL_NO_CAST
    VR_EVP_add_cipher(VR_EVP_cast5_ecb());
    VR_EVP_add_cipher(VR_EVP_cast5_cfb());
    VR_EVP_add_cipher(VR_EVP_cast5_ofb());
    VR_EVP_add_cipher(VR_EVP_cast5_cbc());
    VR_EVP_add_cipher_alias(SN_cast5_cbc, "CAST");
    VR_EVP_add_cipher_alias(SN_cast5_cbc, "cast");
    VR_EVP_add_cipher_alias(SN_cast5_cbc, "CAST-cbc");
    VR_EVP_add_cipher_alias(SN_cast5_cbc, "cast-cbc");
#endif

#ifndef OPENSSL_NO_RC5
    VR_EVP_add_cipher(EVP_rc5_32_12_16_ecb());
    VR_EVP_add_cipher(EVP_rc5_32_12_16_cfb());
    VR_EVP_add_cipher(EVP_rc5_32_12_16_ofb());
    VR_EVP_add_cipher(EVP_rc5_32_12_16_cbc());
    VR_EVP_add_cipher_alias(SN_rc5_cbc, "rc5");
    VR_EVP_add_cipher_alias(SN_rc5_cbc, "RC5");
#endif

    VR_EVP_add_cipher(VR_EVP_aes_128_ecb());
    VR_EVP_add_cipher(VR_EVP_aes_128_cbc());
    VR_EVP_add_cipher(VR_EVP_aes_128_cfb());
    VR_EVP_add_cipher(VR_EVP_aes_128_cfb1());
    VR_EVP_add_cipher(VR_EVP_aes_128_cfb8());
    VR_EVP_add_cipher(VR_EVP_aes_128_ofb());
    VR_EVP_add_cipher(VR_EVP_aes_128_ctr());
    VR_EVP_add_cipher(VR_EVP_aes_128_gcm());
#ifndef OPENSSL_NO_OCB
    VR_EVP_add_cipher(VR_EVP_aes_128_ocb());
#endif
    VR_EVP_add_cipher(VR_EVP_aes_128_xts());
    VR_EVP_add_cipher(VR_EVP_aes_128_ccm());
    VR_EVP_add_cipher(VR_EVP_aes_128_wrap());
    VR_EVP_add_cipher_alias(SN_id_aes128_wrap, "aes128-wrap");
    VR_EVP_add_cipher(VR_EVP_aes_128_wrap_pad());
    VR_EVP_add_cipher_alias(SN_aes_128_cbc, "AES128");
    VR_EVP_add_cipher_alias(SN_aes_128_cbc, "aes128");
    VR_EVP_add_cipher(VR_EVP_aes_192_ecb());
    VR_EVP_add_cipher(VR_EVP_aes_192_cbc());
    VR_EVP_add_cipher(VR_EVP_aes_192_cfb());
    VR_EVP_add_cipher(VR_EVP_aes_192_cfb1());
    VR_EVP_add_cipher(VR_EVP_aes_192_cfb8());
    VR_EVP_add_cipher(VR_EVP_aes_192_ofb());
    VR_EVP_add_cipher(VR_EVP_aes_192_ctr());
    VR_EVP_add_cipher(VR_EVP_aes_192_gcm());
#ifndef OPENSSL_NO_OCB
    VR_EVP_add_cipher(VR_EVP_aes_192_ocb());
#endif
    VR_EVP_add_cipher(VR_EVP_aes_192_ccm());
    VR_EVP_add_cipher(VR_EVP_aes_192_wrap());
    VR_EVP_add_cipher_alias(SN_id_aes192_wrap, "aes192-wrap");
    VR_EVP_add_cipher(VR_EVP_aes_192_wrap_pad());
    VR_EVP_add_cipher_alias(SN_aes_192_cbc, "AES192");
    VR_EVP_add_cipher_alias(SN_aes_192_cbc, "aes192");
    VR_EVP_add_cipher(VR_EVP_aes_256_ecb());
    VR_EVP_add_cipher(VR_EVP_aes_256_cbc());
    VR_EVP_add_cipher(VR_EVP_aes_256_cfb());
    VR_EVP_add_cipher(VR_EVP_aes_256_cfb1());
    VR_EVP_add_cipher(VR_EVP_aes_256_cfb8());
    VR_EVP_add_cipher(VR_EVP_aes_256_ofb());
    VR_EVP_add_cipher(VR_EVP_aes_256_ctr());
    VR_EVP_add_cipher(VR_EVP_aes_256_gcm());
#ifndef OPENSSL_NO_OCB
    VR_EVP_add_cipher(VR_EVP_aes_256_ocb());
#endif
    VR_EVP_add_cipher(VR_EVP_aes_256_xts());
    VR_EVP_add_cipher(VR_EVP_aes_256_ccm());
    VR_EVP_add_cipher(VR_EVP_aes_256_wrap());
    VR_EVP_add_cipher_alias(SN_id_aes256_wrap, "aes256-wrap");
    VR_EVP_add_cipher(VR_EVP_aes_256_wrap_pad());
    VR_EVP_add_cipher_alias(SN_aes_256_cbc, "AES256");
    VR_EVP_add_cipher_alias(SN_aes_256_cbc, "aes256");
    VR_EVP_add_cipher(VR_EVP_aes_128_cbc_hmac_sha1());
    VR_EVP_add_cipher(VR_EVP_aes_256_cbc_hmac_sha1());
    VR_EVP_add_cipher(VR_EVP_aes_128_cbc_hmac_sha256());
    VR_EVP_add_cipher(VR_EVP_aes_256_cbc_hmac_sha256());
#ifndef OPENSSL_NO_SIV
    VR_EVP_add_cipher(VR_EVP_aes_128_siv());
    VR_EVP_add_cipher(VR_EVP_aes_192_siv());
    VR_EVP_add_cipher(VR_EVP_aes_256_siv());
#endif
#ifndef OPENSSL_NO_ARIA
    VR_EVP_add_cipher(VR_EVP_aria_128_ecb());
    VR_EVP_add_cipher(VR_EVP_aria_128_cbc());
    VR_EVP_add_cipher(EVP_aria_128_cfb());
    VR_EVP_add_cipher(VR_EVP_aria_128_cfb1());
    VR_EVP_add_cipher(VR_EVP_aria_128_cfb8());
    VR_EVP_add_cipher(VR_EVP_aria_128_ctr());
    VR_EVP_add_cipher(VR_EVP_aria_128_ofb());
    VR_EVP_add_cipher(VR_EVP_aria_128_gcm());
    VR_EVP_add_cipher(VR_EVP_aria_128_ccm());
    VR_EVP_add_cipher_alias(SN_aria_128_cbc, "ARIA128");
    VR_EVP_add_cipher_alias(SN_aria_128_cbc, "aria128");
    VR_EVP_add_cipher(VR_EVP_aria_192_ecb());
    VR_EVP_add_cipher(VR_EVP_aria_192_cbc());
    VR_EVP_add_cipher(EVP_aria_192_cfb());
    VR_EVP_add_cipher(VR_EVP_aria_192_cfb1());
    VR_EVP_add_cipher(VR_EVP_aria_192_cfb8());
    VR_EVP_add_cipher(VR_EVP_aria_192_ctr());
    VR_EVP_add_cipher(VR_EVP_aria_192_ofb());
    VR_EVP_add_cipher(VR_EVP_aria_192_gcm());
    VR_EVP_add_cipher(VR_EVP_aria_192_ccm());
    VR_EVP_add_cipher_alias(SN_aria_192_cbc, "ARIA192");
    VR_EVP_add_cipher_alias(SN_aria_192_cbc, "aria192");
    VR_EVP_add_cipher(VR_EVP_aria_256_ecb());
    VR_EVP_add_cipher(VR_EVP_aria_256_cbc());
    VR_EVP_add_cipher(EVP_aria_256_cfb());
    VR_EVP_add_cipher(VR_EVP_aria_256_cfb1());
    VR_EVP_add_cipher(VR_EVP_aria_256_cfb8());
    VR_EVP_add_cipher(VR_EVP_aria_256_ctr());
    VR_EVP_add_cipher(VR_EVP_aria_256_ofb());
    VR_EVP_add_cipher(VR_EVP_aria_256_gcm());
    VR_EVP_add_cipher(VR_EVP_aria_256_ccm());
    VR_EVP_add_cipher_alias(SN_aria_256_cbc, "ARIA256");
    VR_EVP_add_cipher_alias(SN_aria_256_cbc, "aria256");
#endif

#ifndef OPENSSL_NO_CAMELLIA
    VR_EVP_add_cipher(VR_EVP_camellia_128_ecb());
    VR_EVP_add_cipher(VR_EVP_camellia_128_cbc());
    VR_EVP_add_cipher(VR_EVP_camellia_128_cfb());
    VR_EVP_add_cipher(VR_EVP_camellia_128_cfb1());
    VR_EVP_add_cipher(VR_EVP_camellia_128_cfb8());
    VR_EVP_add_cipher(VR_EVP_camellia_128_ofb());
    VR_EVP_add_cipher_alias(SN_camellia_128_cbc, "CAMELLIA128");
    VR_EVP_add_cipher_alias(SN_camellia_128_cbc, "camellia128");
    VR_EVP_add_cipher(VR_EVP_camellia_192_ecb());
    VR_EVP_add_cipher(VR_EVP_camellia_192_cbc());
    VR_EVP_add_cipher(VR_EVP_camellia_192_cfb());
    VR_EVP_add_cipher(VR_EVP_camellia_192_cfb1());
    VR_EVP_add_cipher(VR_EVP_camellia_192_cfb8());
    VR_EVP_add_cipher(VR_EVP_camellia_192_ofb());
    VR_EVP_add_cipher_alias(SN_camellia_192_cbc, "CAMELLIA192");
    VR_EVP_add_cipher_alias(SN_camellia_192_cbc, "camellia192");
    VR_EVP_add_cipher(VR_EVP_camellia_256_ecb());
    VR_EVP_add_cipher(VR_EVP_camellia_256_cbc());
    VR_EVP_add_cipher(VR_EVP_camellia_256_cfb());
    VR_EVP_add_cipher(VR_EVP_camellia_256_cfb1());
    VR_EVP_add_cipher(VR_EVP_camellia_256_cfb8());
    VR_EVP_add_cipher(VR_EVP_camellia_256_ofb());
    VR_EVP_add_cipher_alias(SN_camellia_256_cbc, "CAMELLIA256");
    VR_EVP_add_cipher_alias(SN_camellia_256_cbc, "camellia256");
    VR_EVP_add_cipher(VR_EVP_camellia_128_ctr());
    VR_EVP_add_cipher(VR_EVP_camellia_192_ctr());
    VR_EVP_add_cipher(VR_EVP_camellia_256_ctr());
#endif

#ifndef OPENSSL_NO_CHACHA
    VR_EVP_add_cipher(VR_EVP_chacha20());
# ifndef OPENSSL_NO_POLY1305
    VR_EVP_add_cipher(VR_EVP_chacha20_poly1305());
# endif
#endif
}
