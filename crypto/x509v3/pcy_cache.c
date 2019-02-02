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
#include "internal/x509_int.h"

#include "pcy_int.h"

static int policy_data_cmp(const X509_POLICY_DATA *const *a,
                           const X509_POLICY_DATA *const *b);
static int VR_policy_cache_set_int(long *out, ASN1_INTEGER *value);

/*
 * Set cache entry according to CertificatePolicies extension. Note: this
 * destroys the passed CERTIFICATEPOLICIES structure.
 */

static int policy_cache_create(X509 *x,
                               CERTIFICATEPOLICIES *policies, int crit)
{
    int i, num, ret = 0;
    X509_POLICY_CACHE *cache = x->policy_cache;
    X509_POLICY_DATA *data = NULL;
    POLICYINFO *policy;

    if ((num = sk_POLICYINFO_num(policies)) <= 0)
        goto bad_policy;
    cache->data = sk_VR_X509_POLICY_DATA_new(policy_data_cmp);
    if (cache->data == NULL) {
        X509V3err(X509V3_F_POLICY_CACHE_CREATE, ERR_R_MALLOC_FAILURE);
        goto just_cleanup;
    }
    for (i = 0; i < num; i++) {
        policy = sk_POLICYINFO_value(policies, i);
        data = VR_policy_data_new(policy, NULL, crit);
        if (data == NULL) {
            X509V3err(X509V3_F_POLICY_CACHE_CREATE, ERR_R_MALLOC_FAILURE);
            goto just_cleanup;
        }
        /*
         * Duplicate policy OIDs are illegal: reject if matches found.
         */
        if (VR_OBJ_obj2nid(data->valid_policy) == NID_any_policy) {
            if (cache->anyPolicy) {
                ret = -1;
                goto bad_policy;
            }
            cache->anyPolicy = data;
        } else if (sk_VR_X509_POLICY_DATA_find(cache->data, data) >=0 ) {
            ret = -1;
            goto bad_policy;
        } else if (!sk_VR_X509_POLICY_DATA_push(cache->data, data)) {
            X509V3err(X509V3_F_POLICY_CACHE_CREATE, ERR_R_MALLOC_FAILURE);
            goto bad_policy;
        }
        data = NULL;
    }
    ret = 1;

 bad_policy:
    if (ret == -1)
        x->ex_flags |= EXFLAG_INVALID_POLICY;
    VR_policy_data_free(data);
 just_cleanup:
    sk_VR_POLICYINFO_pop_free(policies, VR_POLICYINFO_free);
    if (ret <= 0) {
        sk_VR_X509_POLICY_DATA_pop_free(cache->data, VR_policy_data_free);
        cache->data = NULL;
    }
    return ret;
}

static int policy_cache_new(X509 *x)
{
    X509_POLICY_CACHE *cache;
    ASN1_INTEGER *ext_any = NULL;
    POLICY_CONSTRAINTS *ext_pcons = NULL;
    CERTIFICATEPOLICIES *ext_cpols = NULL;
    POLICY_MAPPINGS *ext_pmaps = NULL;
    int i;

    if (x->policy_cache != NULL)
        return 1;
    cache = OPENSSL_malloc(sizeof(*cache));
    if (cache == NULL) {
        X509V3err(X509V3_F_POLICY_CACHE_NEW, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    cache->anyPolicy = NULL;
    cache->data = NULL;
    cache->any_skip = -1;
    cache->explicit_skip = -1;
    cache->map_skip = -1;

    x->policy_cache = cache;

    /*
     * Handle requireExplicitPolicy *first*. Need to process this even if we
     * don't have any policies.
     */
    ext_pcons = VR_X509_get_ext_d2i(x, NID_policy_constraints, &i, NULL);

    if (!ext_pcons) {
        if (i != -1)
            goto bad_cache;
    } else {
        if (!ext_pcons->requireExplicitPolicy
            && !ext_pcons->inhibitPolicyMapping)
            goto bad_cache;
        if (!VR_policy_cache_set_int(&cache->explicit_skip,
                                  ext_pcons->requireExplicitPolicy))
            goto bad_cache;
        if (!VR_policy_cache_set_int(&cache->map_skip,
                                  ext_pcons->inhibitPolicyMapping))
            goto bad_cache;
    }

    /* Process CertificatePolicies */

    ext_cpols = VR_X509_get_ext_d2i(x, NID_certificate_policies, &i, NULL);
    /*
     * If no CertificatePolicies extension or problem decoding then there is
     * no point continuing because the valid policies will be NULL.
     */
    if (!ext_cpols) {
        /* If not absent some problem with extension */
        if (i != -1)
            goto bad_cache;
        return 1;
    }

    i = policy_cache_create(x, ext_cpols, i);

    /* NB: ext_cpols freed by VR_policy_cache_set_policies */

    if (i <= 0)
        return i;

    ext_pmaps = VR_X509_get_ext_d2i(x, NID_policy_mappings, &i, NULL);

    if (!ext_pmaps) {
        /* If not absent some problem with extension */
        if (i != -1)
            goto bad_cache;
    } else {
        i = VR_policy_cache_set_mapping(x, ext_pmaps);
        if (i <= 0)
            goto bad_cache;
    }

    ext_any = VR_X509_get_ext_d2i(x, NID_inhibit_any_policy, &i, NULL);

    if (!ext_any) {
        if (i != -1)
            goto bad_cache;
    } else if (!VR_policy_cache_set_int(&cache->any_skip, ext_any))
        goto bad_cache;
    goto just_cleanup;

 bad_cache:
    x->ex_flags |= EXFLAG_INVALID_POLICY;

 just_cleanup:
    VR_POLICY_CONSTRAINTS_free(ext_pcons);
    VR_ASN1_INTEGER_free(ext_any);
    return 1;

}

void VR_policy_cache_free(X509_POLICY_CACHE *cache)
{
    if (!cache)
        return;
    VR_policy_data_free(cache->anyPolicy);
    sk_VR_X509_POLICY_DATA_pop_free(cache->data, VR_policy_data_free);
    VR_OPENSSL_free(cache);
}

const X509_POLICY_CACHE *VR_policy_cache_set(X509 *x)
{

    if (x->policy_cache == NULL) {
        VR_CRYPTO_THREAD_write_lock(x->lock);
        policy_cache_new(x);
        VR_CRYPTO_THREAD_unlock(x->lock);
    }

    return x->policy_cache;

}

X509_POLICY_DATA *VR_policy_cache_find_data(const X509_POLICY_CACHE *cache,
                                         const ASN1_OBJECT *id)
{
    int idx;
    X509_POLICY_DATA tmp;
    tmp.valid_policy = (ASN1_OBJECT *)id;
    idx = sk_VR_X509_POLICY_DATA_find(cache->data, &tmp);
    return sk_X509_POLICY_DATA_value(cache->data, idx);
}

static int policy_data_cmp(const X509_POLICY_DATA *const *a,
                           const X509_POLICY_DATA *const *b)
{
    return VR_OBJ_cmp((*a)->valid_policy, (*b)->valid_policy);
}

static int VR_policy_cache_set_int(long *out, ASN1_INTEGER *value)
{
    if (value == NULL)
        return 1;
    if (value->type == V_ASN1_NEG_INTEGER)
        return 0;
    *out = VR_ASN1_INTEGER_get(value);
    return 1;
}
