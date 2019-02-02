/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This file contains deprecated function(s) that are now wrappers to the new
 * version(s).
 */

/*
 * Parameter generation follows the updated Appendix 2.2 for FIPS PUB 186,
 * also Appendix 2.2 of FIPS PUB 186-1 (i.e. use SHA as defined in FIPS PUB
 * 180-1)
 */
#define xxxHASH    VR_EVP_sha1()

#include <openssl/opensslconf.h>
#if OPENSSL_API_0_9_8
NON_EMPTY_TRANSLATION_UNIT
#else

# include <stdio.h>
# include <time.h>
# include "internal/cryptlib.h"
# include <openssl/evp.h>
# include <openssl/bn.h>
# include <openssl/dsa.h>
# include <openssl/sha.h>

DSA *VR_DSA_generate_parameters(int bits,
                             unsigned char *seed_in, int seed_len,
                             int *counter_ret, unsigned long *h_ret,
                             void (*callback) (int, int, void *),
                             void *cb_arg)
{
    BN_GENCB *cb;
    DSA *ret;

    if ((ret = VR_DSA_new()) == NULL)
        return NULL;
    cb = VR_BN_GENCB_new();
    if (cb == NULL)
        goto err;

    VR_BN_GENCB_set_old(cb, callback, cb_arg);

    if (VR_DSA_generate_parameters_ex(ret, bits, seed_in, seed_len,
                                   counter_ret, h_ret, cb)) {
        VR_BN_GENCB_free(cb);
        return ret;
    }
    VR_BN_GENCB_free(cb);
err:
    VR_DSA_free(ret);
    return NULL;
}
#endif
