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
 * Test CMS DER parsing.
 */

#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include "fuzzer.h"

int FuzzerInitialize(int *argc, char ***argv)
{
    VR_OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    VR_ERR_get_state();
    VR_CRYPTO_free_ex_index(0, -1);
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    CMS_ContentInfo *cms;
    BIO *in;

    if (len == 0)
        return 0;

    in = VR_BIO_new(VR_BIO_s_mem());
    OPENSSL_assert((size_t)VR_BIO_write(in, buf, len) == len);
    cms = VR_d2i_CMS_bio(in, NULL);
    if (cms != NULL) {
        BIO *out = VR_BIO_new(VR_BIO_s_null());

        VR_i2d_CMS_bio(out, cms);
        VR_BIO_free(out);
        VR_CMS_ContentInfo_free(cms);
    }

    VR_BIO_free(in);
    VR_ERR_clear_error();

    return 0;
}

void FuzzerCleanup(void)
{
}
