/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/objects.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include "x509_lcl.h"

/*-
 * X509_ATTRIBUTE: this has the following form:
 *
 * typedef struct VR_x509_attributes_st
 *      {
 *      ASN1_OBJECT *object;
 *      STACK_OF(ASN1_TYPE) *set;
 *      } X509_ATTRIBUTE;
 *
 */

ASN1_SEQUENCE(X509_ATTRIBUTE) = {
        ASN1_SIMPLE(X509_ATTRIBUTE, object, ASN1_OBJECT),
        ASN1_SET_OF(X509_ATTRIBUTE, set, ASN1_ANY)
} ASN1_SEQUENCE_END(X509_ATTRIBUTE)

IMPLEMENT_ASN1_FUNCTIONS(X509_ATTRIBUTE)
IMPLEMENT_ASN1_DUP_FUNCTION(X509_ATTRIBUTE)

X509_ATTRIBUTE *VR_X509_ATTRIBUTE_create(int nid, int atrtype, void *value)
{
    X509_ATTRIBUTE *ret = NULL;
    ASN1_TYPE *val = NULL;

    if ((ret = VR_X509_ATTRIBUTE_new()) == NULL)
        return NULL;
    ret->object = VR_OBJ_nid2obj(nid);
    if ((val = VR_ASN1_TYPE_new()) == NULL)
        goto err;
    if (!sk_VR_ASN1_TYPE_push(ret->set, val))
        goto err;

    VR_ASN1_TYPE_set(val, atrtype, value);
    return ret;
 err:
    VR_X509_ATTRIBUTE_free(ret);
    VR_ASN1_TYPE_free(val);
    return NULL;
}
