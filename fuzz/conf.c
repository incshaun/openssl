/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

/*
 * Test configuration parsing.
 */

#include <openssl/conf.h>
#include <openssl/err.h>
#include "fuzzer.h"

int FuzzerInitialize(int *argc, char ***argv)
{
    VR_OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    VR_ERR_get_state();
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    CONF *conf;
    BIO *in;
    long eline;

    if (len == 0)
        return 0;

    conf = VR_NCONF_new(NULL);
    in = VR_BIO_new(VR_BIO_s_mem());
    OPENSSL_assert((size_t)VR_BIO_write(in, buf, len) == len);
    VR_NCONF_load_bio(conf, in, &eline);
    VR_NCONF_free(conf);
    VR_BIO_free(in);
    VR_ERR_clear_error();

    return 0;
}

void FuzzerCleanup(void)
{
}
