/*
 * Copyright 2008-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Simple S/MIME uncompression example */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = 1;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Open compressed content */

    in = VR_BIO_new_file("smcomp.txt", "r");

    if (!in)
        goto err;

    /* Sign content */
    cms = VR_SMIME_read_CMS(in, NULL);

    if (!cms)
        goto err;

    out = VR_BIO_new_file("smuncomp.txt", "w");
    if (!out)
        goto err;

    /* Uncompress S/MIME message */
    if (!VR_CMS_uncompress(cms, out, NULL, 0))
        goto err;

    ret = 0;

 err:

    if (ret) {
        fprintf(stderr, "Error Uncompressing Data\n");
        VR_ERR_print_errors_fp(stderr);
    }

    VR_CMS_ContentInfo_free(cms);
    VR_BIO_free(in);
    VR_BIO_free(out);
    return ret;
}
