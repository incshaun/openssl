/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifndef OPENSSL_NO_STDIO
int VR_X509_CRL_print_fp(FILE *fp, X509_CRL *x)
{
    BIO *b;
    int ret;

    if ((b = VR_BIO_new(VR_BIO_s_file())) == NULL) {
        X509err(X509_F_X509_CRL_PRINT_FP, ERR_R_BUF_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = VR_X509_CRL_print(b, x);
    VR_BIO_free(b);
    return ret;
}
#endif

int VR_X509_CRL_print(BIO *out, X509_CRL *x)
{
  return VR_X509_CRL_print_ex(out, x, XN_FLAG_COMPAT);
}

int VR_X509_CRL_print_ex(BIO *out, X509_CRL *x, unsigned long nmflag)
{
    STACK_OF(X509_REVOKED) *rev;
    X509_REVOKED *r;
    const X509_ALGOR *sig_alg;
    const ASN1_BIT_STRING *sig;
    long l;
    int i;

    VR_BIO_printf(out, "Certificate Revocation List (CRL):\n");
    l = VR_X509_CRL_get_version(x);
    if (l >= 0 && l <= 1)
        VR_BIO_printf(out, "%8sVersion %ld (0x%lx)\n", "", l + 1, (unsigned long)l);
    else
        VR_BIO_printf(out, "%8sVersion unknown (%ld)\n", "", l);
    VR_X509_CRL_get0_signature(x, &sig, &sig_alg);
    VR_BIO_puts(out, "    ");
    VR_X509_signature_print(out, sig_alg, NULL);
    VR_BIO_printf(out, "%8sIssuer: ", "");
    VR_X509_NAME_print_ex(out, VR_X509_CRL_get_issuer(x), 0, nmflag);
    VR_BIO_puts(out, "\n");
    VR_BIO_printf(out, "%8sLast Update: ", "");
    VR_ASN1_TIME_print(out, VR_X509_CRL_get0_lastUpdate(x));
    VR_BIO_printf(out, "\n%8sNext Update: ", "");
    if (VR_X509_CRL_get0_nextUpdate(x))
        VR_ASN1_TIME_print(out, VR_X509_CRL_get0_nextUpdate(x));
    else
        VR_BIO_printf(out, "NONE");
    VR_BIO_printf(out, "\n");

    VR_X509V3_extensions_print(out, "CRL extensions",
                            VR_X509_CRL_get0_extensions(x), 0, 8);

    rev = VR_X509_CRL_get_REVOKED(x);

    if (sk_X509_REVOKED_num(rev) > 0)
        VR_BIO_printf(out, "Revoked Certificates:\n");
    else
        VR_BIO_printf(out, "No Revoked Certificates.\n");

    for (i = 0; i < sk_X509_REVOKED_num(rev); i++) {
        r = sk_X509_REVOKED_value(rev, i);
        VR_BIO_printf(out, "    Serial Number: ");
        VR_i2a_ASN1_INTEGER(out, VR_X509_REVOKED_get0_serialNumber(r));
        VR_BIO_printf(out, "\n        Revocation Date: ");
        VR_ASN1_TIME_print(out, VR_X509_REVOKED_get0_revocationDate(r));
        VR_BIO_printf(out, "\n");
        VR_X509V3_extensions_print(out, "CRL entry extensions",
                                VR_X509_REVOKED_get0_extensions(r), 0, 8);
    }
    VR_X509_signature_print(out, sig_alg, sig);

    return 1;

}
