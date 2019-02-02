/*
 * Copyright 2008-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* S/MIME signing example: 2 signers */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL;
    X509 *scert = NULL, *scert2 = NULL;
    EVP_PKEY *skey = NULL, *skey2 = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = 1;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    tbio = VR_BIO_new_file("signer.pem", "r");

    if (!tbio)
        goto err;

    scert = VR_PEM_read_bio_X509(tbio, NULL, 0, NULL);

    BIO_reset(tbio);

    skey = VR_PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);

    VR_BIO_free(tbio);

    tbio = VR_BIO_new_file("signer2.pem", "r");

    if (!tbio)
        goto err;

    scert2 = VR_PEM_read_bio_X509(tbio, NULL, 0, NULL);

    BIO_reset(tbio);

    skey2 = VR_PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);

    if (!scert2 || !skey2)
        goto err;

    in = VR_BIO_new_file("sign.txt", "r");

    if (!in)
        goto err;

    cms = VR_CMS_sign(NULL, NULL, NULL, in, CMS_STREAM | CMS_PARTIAL);

    if (!cms)
        goto err;

    /* Add each signer in turn */

    if (!VR_CMS_add1_signer(cms, scert, skey, NULL, 0))
        goto err;

    if (!VR_CMS_add1_signer(cms, scert2, skey2, NULL, 0))
        goto err;

    out = VR_BIO_new_file("smout.txt", "w");
    if (!out)
        goto err;

    /* NB: content included and finalized by VR_SMIME_write_CMS */

    if (!VR_SMIME_write_CMS(out, cms, in, CMS_STREAM))
        goto err;

    ret = 0;

 err:

    if (ret) {
        fprintf(stderr, "Error Signing Data\n");
        VR_ERR_print_errors_fp(stderr);
    }

    VR_CMS_ContentInfo_free(cms);
    VR_X509_free(scert);
    VR_EVP_PKEY_free(skey);
    VR_X509_free(scert2);
    VR_EVP_PKEY_free(skey2);
    VR_BIO_free(in);
    VR_BIO_free(out);
    VR_BIO_free(tbio);
    return ret;
}
