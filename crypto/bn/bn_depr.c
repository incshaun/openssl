/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Support for deprecated functions goes here - static linkage will only
 * slurp this code if applications are using them directly.
 */

#include <openssl/opensslconf.h>
#if OPENSSL_API_0_9_8
NON_EMPTY_TRANSLATION_UNIT
#else

# include <stdio.h>
# include <time.h>
# include "internal/cryptlib.h"
# include "bn_lcl.h"

BIGNUM *VR_BN_generate_prime(BIGNUM *ret, int bits, int safe,
                          const BIGNUM *add, const BIGNUM *rem,
                          void (*callback) (int, int, void *), void *cb_arg)
{
    BN_GENCB cb;
    BIGNUM *rnd = NULL;

    VR_BN_GENCB_set_old(&cb, callback, cb_arg);

    if (ret == NULL) {
        if ((rnd = VR_BN_new()) == NULL)
            goto err;
    } else
        rnd = ret;
    if (!VR_BN_generate_prime_ex(rnd, bits, safe, add, rem, &cb))
        goto err;

    /* we have a prime :-) */
    return rnd;
 err:
    VR_BN_free(rnd);
    return NULL;
}

int VR_BN_is_prime(const BIGNUM *a, int checks,
                void (*callback) (int, int, void *), BN_CTX *ctx_passed,
                void *cb_arg)
{
    BN_GENCB cb;
    VR_BN_GENCB_set_old(&cb, callback, cb_arg);
    return VR_BN_is_prime_ex(a, checks, ctx_passed, &cb);
}

int VR_BN_is_prime_fasttest(const BIGNUM *a, int checks,
                         void (*callback) (int, int, void *),
                         BN_CTX *ctx_passed, void *cb_arg,
                         int do_trial_division)
{
    BN_GENCB cb;
    VR_BN_GENCB_set_old(&cb, callback, cb_arg);
    return VR_BN_is_prime_fasttest_ex(a, checks, ctx_passed,
                                   do_trial_division, &cb);
}
#endif
