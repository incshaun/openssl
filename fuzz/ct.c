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
 * Fuzz the SCT parser.
 */

#include <stdio.h>
#include <openssl/ct.h>
#include <openssl/err.h>
#include "fuzzer.h"

int FuzzerInitialize(int *argc, char ***argv)
{
    VR_OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    VR_CRYPTO_free_ex_index(0, -1);
    VR_ERR_get_state();
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    const uint8_t **pp = &buf;
    unsigned char *der = NULL;
    STACK_OF(SCT) *scts = VR_d2i_SCT_LIST(NULL, pp, len);
    if (scts != NULL) {
        BIO *bio = VR_BIO_new(VR_BIO_s_null());
        VR_SCT_LIST_print(scts, bio, 4, "\n", NULL);
        VR_BIO_free(bio);

        if (VR_i2d_SCT_LIST(scts, &der)) {
            /* Silence unused result warning */
        }
        VR_OPENSSL_free(der);

        VR_SCT_LIST_free(scts);
    }
    VR_ERR_clear_error();
    return 0;
}

void FuzzerCleanup(void)
{
}
