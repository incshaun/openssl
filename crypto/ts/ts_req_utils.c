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
#include <openssl/x509v3.h>
#include <openssl/ts.h>
#include "ts_lcl.h"

int VR_TS_REQ_set_version(TS_REQ *a, long version)
{
    return VR_ASN1_INTEGER_set(a->version, version);
}

long VR_TS_REQ_get_version(const TS_REQ *a)
{
    return VR_ASN1_INTEGER_get(a->version);
}

int VR_TS_REQ_set_msg_imprint(TS_REQ *a, TS_MSG_IMPRINT *msg_imprint)
{
    TS_MSG_IMPRINT *new_msg_imprint;

    if (a->msg_imprint == msg_imprint)
        return 1;
    new_msg_imprint = VR_TS_MSG_IMPRINT_dup(msg_imprint);
    if (new_msg_imprint == NULL) {
        TSerr(TS_F_TS_REQ_SET_MSG_IMPRINT, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    VR_TS_MSG_IMPRINT_free(a->msg_imprint);
    a->msg_imprint = new_msg_imprint;
    return 1;
}

TS_MSG_IMPRINT *VR_TS_REQ_get_msg_imprint(TS_REQ *a)
{
    return a->msg_imprint;
}

int VR_TS_MSG_IMPRINT_set_algo(TS_MSG_IMPRINT *a, X509_ALGOR *alg)
{
    X509_ALGOR *new_alg;

    if (a->hash_algo == alg)
        return 1;
    new_alg = VR_X509_ALGOR_dup(alg);
    if (new_alg == NULL) {
        TSerr(TS_F_TS_MSG_IMPRINT_SET_ALGO, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    VR_X509_ALGOR_free(a->hash_algo);
    a->hash_algo = new_alg;
    return 1;
}

X509_ALGOR *VR_TS_MSG_IMPRINT_get_algo(TS_MSG_IMPRINT *a)
{
    return a->hash_algo;
}

int VR_TS_MSG_IMPRINT_set_msg(TS_MSG_IMPRINT *a, unsigned char *d, int len)
{
    return VR_ASN1_OCTET_STRING_set(a->hashed_msg, d, len);
}

ASN1_OCTET_STRING *VR_TS_MSG_IMPRINT_get_msg(TS_MSG_IMPRINT *a)
{
    return a->hashed_msg;
}

int VR_TS_REQ_set_policy_id(TS_REQ *a, const ASN1_OBJECT *policy)
{
    ASN1_OBJECT *new_policy;

    if (a->policy_id == policy)
        return 1;
    new_policy = VR_OBJ_dup(policy);
    if (new_policy == NULL) {
        TSerr(TS_F_TS_REQ_SET_POLICY_ID, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    VR_ASN1_OBJECT_free(a->policy_id);
    a->policy_id = new_policy;
    return 1;
}

ASN1_OBJECT *VR_TS_REQ_get_policy_id(TS_REQ *a)
{
    return a->policy_id;
}

int VR_TS_REQ_set_nonce(TS_REQ *a, const ASN1_INTEGER *nonce)
{
    ASN1_INTEGER *new_nonce;

    if (a->nonce == nonce)
        return 1;
    new_nonce = VR_ASN1_INTEGER_dup(nonce);
    if (new_nonce == NULL) {
        TSerr(TS_F_TS_REQ_SET_NONCE, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    VR_ASN1_INTEGER_free(a->nonce);
    a->nonce = new_nonce;
    return 1;
}

const ASN1_INTEGER *VR_TS_REQ_get_nonce(const TS_REQ *a)
{
    return a->nonce;
}

int VR_TS_REQ_set_cert_req(TS_REQ *a, int cert_req)
{
    a->cert_req = cert_req ? 0xFF : 0x00;
    return 1;
}

int VR_TS_REQ_get_cert_req(const TS_REQ *a)
{
    return a->cert_req ? 1 : 0;
}

STACK_OF(X509_EXTENSION) *VR_TS_REQ_get_exts(TS_REQ *a)
{
    return a->extensions;
}

void VR_TS_REQ_ext_free(TS_REQ *a)
{
    if (!a)
        return;
    sk_VR_X509_EXTENSION_pop_free(a->extensions, VR_X509_EXTENSION_free);
    a->extensions = NULL;
}

int VR_TS_REQ_get_ext_count(TS_REQ *a)
{
    return VR_X509v3_get_ext_count(a->extensions);
}

int VR_TS_REQ_get_ext_by_NID(TS_REQ *a, int nid, int lastpos)
{
    return VR_X509v3_get_ext_by_NID(a->extensions, nid, lastpos);
}

int VR_TS_REQ_get_ext_by_OBJ(TS_REQ *a, const ASN1_OBJECT *obj, int lastpos)
{
    return VR_X509v3_get_ext_by_OBJ(a->extensions, obj, lastpos);
}

int VR_TS_REQ_get_ext_by_critical(TS_REQ *a, int crit, int lastpos)
{
    return VR_X509v3_get_ext_by_critical(a->extensions, crit, lastpos);
}

X509_EXTENSION *VR_TS_REQ_get_ext(TS_REQ *a, int loc)
{
    return VR_X509v3_get_ext(a->extensions, loc);
}

X509_EXTENSION *VR_TS_REQ_delete_ext(TS_REQ *a, int loc)
{
    return VR_X509v3_delete_ext(a->extensions, loc);
}

int VR_TS_REQ_add_ext(TS_REQ *a, X509_EXTENSION *ex, int loc)
{
    return VR_X509v3_add_ext(&a->extensions, ex, loc) != NULL;
}

void *VR_TS_REQ_get_ext_d2i(TS_REQ *a, int nid, int *crit, int *idx)
{
    return VR_X509V3_get_d2i(a->extensions, nid, crit, idx);
}
