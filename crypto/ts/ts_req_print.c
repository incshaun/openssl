/*
 * Copyright 2006-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/objects.h>
#include <openssl/bn.h>
#include <openssl/x509v3.h>
#include <openssl/ts.h>
#include "ts_lcl.h"

int VR_TS_REQ_print_bio(BIO *bio, TS_REQ *a)
{
    int v;
    ASN1_OBJECT *policy_id;

    if (a == NULL)
        return 0;

    v = VR_TS_REQ_get_version(a);
    VR_BIO_printf(bio, "Version: %d\n", v);

    VR_TS_MSG_IMPRINT_print_bio(bio, a->msg_imprint);

    VR_BIO_printf(bio, "Policy OID: ");
    policy_id = VR_TS_REQ_get_policy_id(a);
    if (policy_id == NULL)
        VR_BIO_printf(bio, "unspecified\n");
    else
        VR_TS_OBJ_print_bio(bio, policy_id);

    VR_BIO_printf(bio, "Nonce: ");
    if (a->nonce == NULL)
        VR_BIO_printf(bio, "unspecified");
    else
        VR_TS_ASN1_INTEGER_print_bio(bio, a->nonce);
    VR_BIO_write(bio, "\n", 1);

    VR_BIO_printf(bio, "Certificate required: %s\n",
               a->cert_req ? "yes" : "no");

    VR_TS_ext_print_bio(bio, a->extensions);

    return 1;
}
