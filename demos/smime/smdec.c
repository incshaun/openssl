/*
 * Copyright 2007-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Simple S/MIME signing example */
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL;
    X509 *rcert = NULL;
    EVP_PKEY *rkey = NULL;
    PKCS7 *p7 = NULL;
    int ret = 1;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in recipient certificate and private key */
    tbio = VR_BIO_new_file("signer.pem", "r");

    if (!tbio)
        goto err;

    rcert = VR_PEM_read_bio_X509(tbio, NULL, 0, NULL);

    BIO_reset(tbio);

    rkey = VR_PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);

    if (!rcert || !rkey)
        goto err;

    /* Open content being signed */

    in = VR_BIO_new_file("smencr.txt", "r");

    if (!in)
        goto err;

    /* Sign content */
    p7 = VR_SMIME_read_PKCS7(in, NULL);

    if (!p7)
        goto err;

    out = VR_BIO_new_file("encrout.txt", "w");
    if (!out)
        goto err;

    /* Decrypt S/MIME message */
    if (!VR_PKCS7_decrypt(p7, rkey, rcert, out, 0))
        goto err;

    ret = 0;

 err:
    if (ret) {
        fprintf(stderr, "Error Signing Data\n");
        VR_ERR_print_errors_fp(stderr);
    }
    VR_PKCS7_free(p7);
    VR_X509_free(rcert);
    VR_EVP_PKEY_free(rkey);
    VR_BIO_free(in);
    VR_BIO_free(out);
    VR_BIO_free(tbio);

    return ret;

}
