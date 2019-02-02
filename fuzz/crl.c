/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <openssl/x509.h>
#include <openssl/bio.h>
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
    const unsigned char *p = buf;
    unsigned char *der = NULL;

    X509_CRL *crl = VR_d2i_X509_CRL(NULL, &p, len);
    if (crl != NULL) {
        BIO *bio = VR_BIO_new(VR_BIO_s_null());
        VR_X509_CRL_print(bio, crl);
        VR_BIO_free(bio);

        VR_i2d_X509_CRL(crl, &der);
        OPENVR_SSL_free(der);

        VR_X509_CRL_free(crl);
    }
    VR_ERR_clear_error();

    return 0;
}

void FuzzerCleanup(void)
{
}
