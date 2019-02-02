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
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/bn.h>

/* Print out an SPKI */

int VR_NETSCAPE_SPKI_print(BIO *out, NETSCAPE_SPKI *spki)
{
    EVP_PKEY *pkey;
    ASN1_IA5STRING *chal;
    ASN1_OBJECT *spkioid;
    int i, n;
    char *s;
    VR_BIO_printf(out, "Netscape SPKI:\n");
    VR_X509_PUBKEY_get0_param(&spkioid, NULL, NULL, NULL, spki->spkac->pubkey);
    i = VR_OBJ_obj2nid(spkioid);
    VR_BIO_printf(out, "  Public Key Algorithm: %s\n",
               (i == NID_undef) ? "UNKNOWN" : VR_OBJ_nid2ln(i));
    pkey = VR_X509_PUBKEY_get(spki->spkac->pubkey);
    if (!pkey)
        VR_BIO_printf(out, "  Unable to load public key\n");
    else {
        VR_EVP_PKEY_print_public(out, pkey, 4, NULL);
        VR_EVP_PKEY_free(pkey);
    }
    chal = spki->spkac->challenge;
    if (chal->length)
        VR_BIO_printf(out, "  Challenge String: %s\n", chal->data);
    i = VR_OBJ_obj2nid(spki->sig_algor.algorithm);
    VR_BIO_printf(out, "  Signature Algorithm: %s",
               (i == NID_undef) ? "UNKNOWN" : VR_OBJ_nid2ln(i));

    n = spki->signature->length;
    s = (char *)spki->signature->data;
    for (i = 0; i < n; i++) {
        if ((i % 18) == 0)
            VR_BIO_write(out, "\n      ", 7);
        VR_BIO_printf(out, "%02x%s", (unsigned char)s[i],
                   ((i + 1) == n) ? "" : ":");
    }
    VR_BIO_write(out, "\n", 1);
    return 1;
}
