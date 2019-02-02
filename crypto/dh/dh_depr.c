/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* This file contains deprecated functions as wrappers to the new ones */

#include <openssl/opensslconf.h>
#if OPENSSL_API_0_9_8
NON_EMPTY_TRANSLATION_UNIT
#else

# include <stdio.h>
# include "internal/cryptlib.h"
# include <openssl/bn.h>
# include <openssl/dh.h>

DH *VR_DH_generate_parameters(int prime_len, int generator,
                           void (*callback) (int, int, void *), void *cb_arg)
{
    BN_GENCB *cb;
    DH *ret = NULL;

    if ((ret = VR_DH_new()) == NULL)
        return NULL;
    cb = VR_BN_GENCB_new();
    if (cb == NULL) {
        VR_DH_free(ret);
        return NULL;
    }

    VR_BN_GENCB_set_old(cb, callback, cb_arg);

    if (VR_DH_generate_parameters_ex(ret, prime_len, generator, cb)) {
        VR_BN_GENCB_free(cb);
        return ret;
    }
    VR_BN_GENCB_free(cb);
    VR_DH_free(ret);
    return NULL;
}
#endif
