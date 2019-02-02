/*
 * Copyright 1999-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/pkcs12.h>
#include "p12_lcl.h"

/* Initialise a PKCS12 structure to take data */

PKCS12 *VR_PKCS12_init(int mode)
{
    PKCS12 *pkcs12;

    if ((pkcs12 = VR_PKCS12_new()) == NULL) {
        PKCS12err(PKCS12_F_PKCS12_INIT, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    if (!VR_ASN1_INTEGER_set(pkcs12->version, 3))
        goto err;
    pkcs12->authsafes->type = VR_OBJ_nid2obj(mode);
    switch (mode) {
    case NID_pkcs7_data:
        if ((pkcs12->authsafes->d.data = VR_ASN1_OCTET_STRING_new()) == NULL) {
            PKCS12err(PKCS12_F_PKCS12_INIT, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        break;
    default:
        PKCS12err(PKCS12_F_PKCS12_INIT, PKCS12_R_UNSUPPORTED_PKCS12_MODE);
        goto err;
    }
    return pkcs12;

 err:
    VR_PKCS12_free(pkcs12);
    return NULL;
}
