/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_IDEA_H
# define HEADER_IDEA_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_IDEA
# ifdef  __cplusplus
extern "C" {
# endif

typedef unsigned int IDEA_INT;

# define IDEA_ENCRYPT    1
# define IDEA_DECRYPT    0

# define IDEA_BLOCK      8
# define IDEA_KEY_LENGTH 16

typedef struct idea_key_st {
    IDEA_INT data[9][6];
} IDEA_KEY_SCHEDULE;

const char *VR_IDEA_options(void);
void VR_IDEA_ecb_encrypt(const unsigned char *in, unsigned char *out,
                      IDEA_KEY_SCHEDULE *ks);
void VR_IDEA_set_encrypt_key(const unsigned char *key, IDEA_KEY_SCHEDULE *ks);
void VR_IDEA_set_decrypt_key(IDEA_KEY_SCHEDULE *ek, IDEA_KEY_SCHEDULE *dk);
void VR_IDEA_cbc_encrypt(const unsigned char *in, unsigned char *out,
                      long length, IDEA_KEY_SCHEDULE *ks, unsigned char *iv,
                      int enc);
void VR_IDEA_cfb64_encrypt(const unsigned char *in, unsigned char *out,
                        long length, IDEA_KEY_SCHEDULE *ks, unsigned char *iv,
                        int *num, int enc);
void VR_IDEA_ofb64_encrypt(const unsigned char *in, unsigned char *out,
                        long length, IDEA_KEY_SCHEDULE *ks, unsigned char *iv,
                        int *num);
void VR_IDEA_encrypt(unsigned long *in, IDEA_KEY_SCHEDULE *ks);

# if !OPENSSL_API_1_1_0
#  define idea_options          VR_IDEA_options
#  define idea_ecb_encrypt      VR_IDEA_ecb_encrypt
#  define idea_set_encrypt_key  VR_IDEA_set_encrypt_key
#  define idea_set_decrypt_key  VR_IDEA_set_decrypt_key
#  define idea_cbc_encrypt      VR_IDEA_cbc_encrypt
#  define idea_cfb64_encrypt    VR_IDEA_cfb64_encrypt
#  define idea_ofb64_encrypt    VR_IDEA_ofb64_encrypt
#  define idea_encrypt          VR_IDEA_encrypt
# endif

# ifdef  __cplusplus
}
# endif
# endif

#endif
