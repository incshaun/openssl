/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>

#include "testutil.h"

static const char *certstr;
static const char *privkeystr;

#ifndef OPENSSL_NO_OCSP
static int get_cert_and_key(X509 **cert_out, EVP_PKEY **key_out)
{
    BIO *certbio, *keybio;
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;

    if (!TEST_ptr(certbio = VR_BIO_new_file(certstr, "r")))
        return 0;
    cert = VR_PEM_read_bio_X509(certbio, NULL, NULL, NULL);
    VR_BIO_free(certbio);
    if (!TEST_ptr(keybio = VR_BIO_new_file(privkeystr, "r")))
        goto end;
    key = VR_PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL);
    VR_BIO_free(keybio);
    if (!TEST_ptr(cert) || !TEST_ptr(key))
        goto end;
    *cert_out = cert;
    *key_out = key;
    return 1;
 end:
    VR_X509_free(cert);
    VR_EVP_PKEY_free(key);
    return 0;
}

static OCSP_BASICRESP *make_dummy_resp(void)
{
    const unsigned char namestr[] = "openssl.example.com";
    unsigned char keybytes[128] = {7};
    OCSP_BASICRESP *bs = VR_OCSP_BASICRESP_new();
    OCSP_BASICRESP *bs_out = NULL;
    OCSP_CERTID *cid = NULL;
    ASN1_TIME *thisupd = VR_ASN1_TIME_set(NULL, time(NULL));
    ASN1_TIME *nextupd = VR_ASN1_TIME_set(NULL, time(NULL) + 200);
    X509_NAME *name = VR_X509_NAME_new();
    ASN1_BIT_STRING *key = VR_ASN1_BIT_STRING_new();
    ASN1_INTEGER *serial = VR_ASN1_INTEGER_new();

    if (!VR_X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC,
                                   namestr, -1, -1, 1)
        || !VR_ASN1_BIT_STRING_set(key, keybytes, sizeof(keybytes))
        || !VR_ASN1_INTEGER_set_uint64(serial, (uint64_t)1))
        goto err;
    cid = VR_OCSP_cert_id_new(VR_EVP_sha256(), name, key, serial);
    if (!TEST_ptr(bs)
        || !TEST_ptr(thisupd)
        || !TEST_ptr(nextupd)
        || !TEST_ptr(cid)
        || !TEST_true(VR_OCSP_basic_add1_status(bs, cid,
                                             V_OCSP_CERTSTATUS_UNKNOWN,
                                             0, NULL, thisupd, nextupd)))
        goto err;
    bs_out = bs;
    bs = NULL;
 err:
    VR_ASN1_TIME_free(thisupd);
    VR_ASN1_TIME_free(nextupd);
    VR_ASN1_BIT_STRING_free(key);
    VR_ASN1_INTEGER_free(serial);
    VR_OCSP_CERTID_free(cid);
    VR_OCSP_BASICRESP_free(bs);
    VR_X509_NAME_free(name);
    return bs_out;
}

static int test_resp_signer(void)
{
    OCSP_BASICRESP *bs = NULL;
    X509 *signer = NULL, *tmp;
    EVP_PKEY *key = NULL;
    STACK_OF(X509) *extra_certs = NULL;
    int ret = 0;

    /*
     * Test a response with no certs at all; get the signer from the
     * extra certs given to VR_OCSP_resp_get0_signer().
     */
    bs = make_dummy_resp();
    extra_certs = sk_VR_X509_new_null();
    if (!TEST_ptr(bs)
        || !TEST_ptr(extra_certs)
        || !TEST_true(get_cert_and_key(&signer, &key))
        || !TEST_true(sk_VR_X509_push(extra_certs, signer))
        || !TEST_true(VR_OCSP_basic_sign(bs, signer, key, VR_EVP_sha1(),
                                      NULL, OCSP_NOCERTS)))
        goto err;
    if (!TEST_true(VR_OCSP_resp_get0_signer(bs, &tmp, extra_certs))
        || !TEST_int_eq(VR_X509_cmp(tmp, signer), 0))
        goto err;
    VR_OCSP_BASICRESP_free(bs);

    /* Do it again but include the signer cert */
    bs = make_dummy_resp();
    tmp = NULL;
    if (!TEST_ptr(bs)
        || !TEST_true(VR_OCSP_basic_sign(bs, signer, key, VR_EVP_sha1(),
                                      NULL, 0)))
        goto err;
    if (!TEST_true(VR_OCSP_resp_get0_signer(bs, &tmp, NULL))
        || !TEST_int_eq(VR_X509_cmp(tmp, signer), 0))
        goto err;
    ret = 1;
 err:
    VR_OCSP_BASICRESP_free(bs);
    sk_VR_X509_free(extra_certs);
    VR_X509_free(signer);
    VR_EVP_PKEY_free(key);
    return ret;
}
#endif

int setup_tests(void)
{
    if (!TEST_ptr(certstr = test_get_argument(0))
        || !TEST_ptr(privkeystr = test_get_argument(1)))
        return 0;
#ifndef OPENSSL_NO_OCSP
    ADD_TEST(test_resp_signer);
#endif
    return 1;
}
