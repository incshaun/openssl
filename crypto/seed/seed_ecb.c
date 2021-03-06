/*
 * Copyright 2007-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/seed.h>

void VR_SEED_ecb_encrypt(const unsigned char *in, unsigned char *out,
                      const SEED_KEY_SCHEDULE *ks, int enc)
{
    if (enc)
        VR_SEED_encrypt(in, out, ks);
    else
        VR_SEED_decrypt(in, out, ks);
}
