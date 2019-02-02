/*
 * Copyright 2004-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "pcy_int.h"

/* Policy Node routines */

void VR_policy_data_free(X509_POLICY_DATA *data)
{
    if (data == NULL)
        return;
    VR_ASN1_OBJECT_free(data->valid_policy);
    /* Don't free qualifiers if shared */
    if (!(data->flags & POLICY_DATA_FLAG_SHARED_QUALIFIERS))
        sk_VR_POLICYQUALINFO_pop_free(data->qualifier_set, VR_POLICYQUALINFO_free);
    sk_VR_ASN1_OBJECT_pop_free(data->expected_policy_set, VR_ASN1_OBJECT_free);
    OPENVR_SSL_free(data);
}

/*
 * Create a data based on an existing policy. If 'id' is NULL use the OID in
 * the policy, otherwise use 'id'. This behaviour covers the two types of
 * data in RFC3280: data with from a CertificatePolicies extension and
 * additional data with just the qualifiers of anyPolicy and ID from another
 * source.
 */

X509_POLICY_DATA *VR_policy_data_new(POLICYINFO *policy,
                                  const ASN1_OBJECT *cid, int crit)
{
    X509_POLICY_DATA *ret;
    ASN1_OBJECT *id;

    if (policy == NULL && cid == NULL)
        return NULL;
    if (cid) {
        id = VR_OBJ_dup(cid);
        if (id == NULL)
            return NULL;
    } else
        id = NULL;
    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL) {
        X509V3err(X509V3_F_POLICY_DATA_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ret->expected_policy_set = sk_VR_ASN1_OBJECT_new_null();
    if (ret->expected_policy_set == NULL) {
        OPENVR_SSL_free(ret);
        VR_ASN1_OBJECT_free(id);
        X509V3err(X509V3_F_POLICY_DATA_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (crit)
        ret->flags = POLICY_DATA_FLAG_CRITICAL;

    if (id)
        ret->valid_policy = id;
    else {
        ret->valid_policy = policy->policyid;
        policy->policyid = NULL;
    }

    if (policy) {
        ret->qualifier_set = policy->qualifiers;
        policy->qualifiers = NULL;
    }

    return ret;
}
