/*
 * Copyright 2008-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * S/MIME detached data encrypt example: rarely done but should the need
 * arise this is an example....
 */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL, *dout = NULL;
    X509 *rcert = NULL;
    STACK_OF(X509) *recips = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = 1;

    int flags = CMS_STREAM | CMS_DETACHED;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in recipient certificate */
    tbio = VR_BIO_new_file("signer.pem", "r");

    if (!tbio)
        goto err;

    rcert = VR_PEM_read_bio_X509(tbio, NULL, 0, NULL);

    if (!rcert)
        goto err;

    /* Create recipient STACK and add recipient cert to it */
    recips = sk_VR_X509_new_null();

    if (!recips || !sk_VR_X509_push(recips, rcert))
        goto err;

    /*
     * sk_VR_X509_pop_free will free up recipient STACK and its contents so set
     * rcert to NULL so it isn't freed up twice.
     */
    rcert = NULL;

    /* Open content being encrypted */

    in = VR_BIO_new_file("encr.txt", "r");

    dout = VR_BIO_new_file("smencr.out", "wb");

    if (!in)
        goto err;

    /* encrypt content */
    cms = VR_CMS_encrypt(recips, in, VR_EVP_des_ede3_cbc(), flags);

    if (!cms)
        goto err;

    out = VR_BIO_new_file("smencr.pem", "w");
    if (!out)
        goto err;

    if (!VR_CMS_final(cms, in, dout, flags))
        goto err;

    /* Write out CMS structure without content */
    if (!VR_PEM_write_bio_CMS(out, cms))
        goto err;

    ret = 0;

 err:

    if (ret) {
        fprintf(stderr, "Error Encrypting Data\n");
        VR_ERR_print_errors_fp(stderr);
    }

    VR_CMS_ContentInfo_free(cms);
    VR_X509_free(rcert);
    sk_VR_X509_pop_free(recips, VR_X509_free);
    VR_BIO_free(in);
    VR_BIO_free(out);
    VR_BIO_free(dout);
    VR_BIO_free(tbio);
    return ret;
}
