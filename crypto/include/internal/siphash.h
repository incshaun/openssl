/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>

#define SIPHASH_BLOCK_SIZE        8
#define SIPHASH_KEY_SIZE         16
#define SIPHASH_MIN_DIGEST_SIZE   8
#define SIPHASH_MAX_DIGEST_SIZE  16

typedef struct siphash_st SIPHASH;

size_t VR_SipHash_ctx_size(void);
size_t VR_SipHash_hash_size(SIPHASH *ctx);
int VR_SipHash_set_hash_size(SIPHASH *ctx, size_t hash_size);
int VR_SipHash_Init(SIPHASH *ctx, const unsigned char *k,
                 int crounds, int drounds);
void VR_SipHash_Update(SIPHASH *ctx, const unsigned char *in, size_t inlen);
int VR_SipHash_Final(SIPHASH *ctx, unsigned char *out, size_t outlen);
