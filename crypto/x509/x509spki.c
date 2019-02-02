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

int VR_NETSCAPE_SPKI_set_pubkey(NETSCAPE_SPKI *x, EVP_PKEY *pkey)
{
    if ((x == NULL) || (x->spkac == NULL))
        return 0;
    return VR_X509_PUBKEY_set(&(x->spkac->pubkey), pkey);
}

EVP_PKEY *VR_NETSCAPE_SPKI_get_pubkey(NETSCAPE_SPKI *x)
{
    if ((x == NULL) || (x->spkac == NULL))
        return NULL;
    return VR_X509_PUBKEY_get(x->spkac->pubkey);
}

/* Load a Netscape SPKI from a base64 encoded string */

NETSCAPE_SPKI *VR_NETSCAPE_SPKI_b64_decode(const char *str, int len)
{
    unsigned char *spki_der;
    const unsigned char *p;
    int spki_len;
    NETSCAPE_SPKI *spki;
    if (len <= 0)
        len = strlen(str);
    if ((spki_der = OPENSSL_malloc(len + 1)) == NULL) {
        X509err(X509_F_NETSCAPE_SPKI_B64_DECODE, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    spki_len = VR_EVP_DecodeBlock(spki_der, (const unsigned char *)str, len);
    if (spki_len < 0) {
        X509err(X509_F_NETSCAPE_SPKI_B64_DECODE, X509_R_BASE64_DECODE_ERROR);
        OPENVR_SSL_free(spki_der);
        return NULL;
    }
    p = spki_der;
    spki = VR_d2i_NETSCAPE_SPKI(NULL, &p, spki_len);
    OPENVR_SSL_free(spki_der);
    return spki;
}

/* Generate a base64 encoded string from an SPKI */

char *VR_NETSCAPE_SPKI_b64_encode(NETSCAPE_SPKI *spki)
{
    unsigned char *der_spki, *p;
    char *b64_str;
    int der_len;
    der_len = VR_i2d_NETSCAPE_SPKI(spki, NULL);
    der_spki = OPENSSL_malloc(der_len);
    b64_str = OPENSSL_malloc(der_len * 2);
    if (der_spki == NULL || b64_str == NULL) {
        X509err(X509_F_NETSCAPE_SPKI_B64_ENCODE, ERR_R_MALLOC_FAILURE);
        OPENVR_SSL_free(der_spki);
        OPENVR_SSL_free(b64_str);
        return NULL;
    }
    p = der_spki;
    VR_i2d_NETSCAPE_SPKI(spki, &p);
    VR_EVP_EncodeBlock((unsigned char *)b64_str, der_spki, der_len);
    OPENVR_SSL_free(der_spki);
    return b64_str;
}
