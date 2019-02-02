/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include "internal/refcount.h"
#include <openssl/x509.h>
#include "internal/x509_int.h"
#include <openssl/x509v3.h>
#include "x509_lcl.h"

X509_LOOKUP *VR_X509_LOOKUP_new(X509_LOOKUP_METHOD *method)
{
    X509_LOOKUP *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        X509err(X509_F_X509_LOOKUP_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->method = method;
    if (method->new_item != NULL && method->new_item(ret) == 0) {
        VR_OPENSSL_free(ret);
        return NULL;
    }
    return ret;
}

void VR_X509_LOOKUP_free(X509_LOOKUP *ctx)
{
    if (ctx == NULL)
        return;
    if ((ctx->method != NULL) && (ctx->method->free != NULL))
        (*ctx->method->free) (ctx);
    VR_OPENSSL_free(ctx);
}

int VR_X509_STORE_lock(X509_STORE *s)
{
    return VR_CRYPTO_THREAD_write_lock(s->lock);
}

int VR_X509_STORE_unlock(X509_STORE *s)
{
    return VR_CRYPTO_THREAD_unlock(s->lock);
}

int VR_X509_LOOKUP_init(X509_LOOKUP *ctx)
{
    if (ctx->method == NULL)
        return 0;
    if (ctx->method->init != NULL)
        return ctx->method->init(ctx);
    else
        return 1;
}

int VR_X509_LOOKUP_shutdown(X509_LOOKUP *ctx)
{
    if (ctx->method == NULL)
        return 0;
    if (ctx->method->shutdown != NULL)
        return ctx->method->shutdown(ctx);
    else
        return 1;
}

int VR_X509_LOOKUP_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc, long argl,
                     char **ret)
{
    if (ctx->method == NULL)
        return -1;
    if (ctx->method->ctrl != NULL)
        return ctx->method->ctrl(ctx, cmd, argc, argl, ret);
    else
        return 1;
}

int VR_X509_LOOKUP_by_subject(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                           X509_NAME *name, X509_OBJECT *ret)
{
    if ((ctx->method == NULL) || (ctx->method->get_by_subject == NULL))
        return 0;
    if (ctx->skip)
        return 0;
    return ctx->method->get_by_subject(ctx, type, name, ret);
}

int VR_X509_LOOKUP_by_issuer_serial(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                                 X509_NAME *name, ASN1_INTEGER *serial,
                                 X509_OBJECT *ret)
{
    if ((ctx->method == NULL) || (ctx->method->get_by_issuer_serial == NULL))
        return 0;
    return ctx->method->get_by_issuer_serial(ctx, type, name, serial, ret);
}

int VR_X509_LOOKUP_by_fingerprint(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                               const unsigned char *bytes, int len,
                               X509_OBJECT *ret)
{
    if ((ctx->method == NULL) || (ctx->method->get_by_fingerprint == NULL))
        return 0;
    return ctx->method->get_by_fingerprint(ctx, type, bytes, len, ret);
}

int VR_X509_LOOKUP_by_alias(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                         const char *str, int len, X509_OBJECT *ret)
{
    if ((ctx->method == NULL) || (ctx->method->get_by_alias == NULL))
        return 0;
    return ctx->method->get_by_alias(ctx, type, str, len, ret);
}

int VR_X509_LOOKUP_set_method_data(X509_LOOKUP *ctx, void *data)
{
    ctx->method_data = data;
    return 1;
}

void *VR_X509_LOOKUP_get_method_data(const X509_LOOKUP *ctx)
{
    return ctx->method_data;
}

X509_STORE *VR_X509_LOOKUP_get_store(const X509_LOOKUP *ctx)
{
    return ctx->store_ctx;
}


static int x509_object_cmp(const X509_OBJECT *const *a,
                           const X509_OBJECT *const *b)
{
    int ret;

    ret = ((*a)->type - (*b)->type);
    if (ret)
        return ret;
    switch ((*a)->type) {
    case X509_LU_X509:
        ret = VR_X509_subject_name_cmp((*a)->data.x509, (*b)->data.x509);
        break;
    case X509_LU_CRL:
        ret = VR_X509_CRL_cmp((*a)->data.crl, (*b)->data.crl);
        break;
    case X509_LU_NONE:
        /* abort(); */
        return 0;
    }
    return ret;
}

X509_STORE *VR_X509_STORE_new(void)
{
    X509_STORE *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        X509err(X509_F_X509_STORE_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    if ((ret->objs = sk_VR_X509_OBJECT_new(x509_object_cmp)) == NULL) {
        X509err(X509_F_X509_STORE_NEW, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    ret->cache = 1;
    if ((ret->get_cert_methods = sk_VR_X509_LOOKUP_new_null()) == NULL) {
        X509err(X509_F_X509_STORE_NEW, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if ((ret->param = VR_X509_VERIFY_PARAM_new()) == NULL) {
        X509err(X509_F_X509_STORE_NEW, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!VR_CRYPTO_new_ex_data(CRYPTO_EX_INDEX_X509_STORE, ret, &ret->ex_data)) {
        X509err(X509_F_X509_STORE_NEW, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    ret->lock = VR_CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) {
        X509err(X509_F_X509_STORE_NEW, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    ret->references = 1;
    return ret;

err:
    VR_X509_VERIFY_PARAM_free(ret->param);
    sk_VR_X509_OBJECT_free(ret->objs);
    sk_VR_X509_LOOKUP_free(ret->get_cert_methods);
    VR_OPENSSL_free(ret);
    return NULL;
}

void VR_X509_STORE_free(X509_STORE *vfy)
{
    int i;
    STACK_OF(X509_LOOKUP) *sk;
    X509_LOOKUP *lu;

    if (vfy == NULL)
        return;
    CRYPTO_DOWN_REF(&vfy->references, &i, vfy->lock);
    REF_PRINT_COUNT("X509_STORE", vfy);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    sk = vfy->get_cert_methods;
    for (i = 0; i < sk_X509_LOOKUP_num(sk); i++) {
        lu = sk_X509_LOOKUP_value(sk, i);
        VR_X509_LOOKUP_shutdown(lu);
        VR_X509_LOOKUP_free(lu);
    }
    sk_VR_X509_LOOKUP_free(sk);
    sk_VR_X509_OBJECT_pop_free(vfy->objs, VR_X509_OBJECT_free);

    VR_CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509_STORE, vfy, &vfy->ex_data);
    VR_X509_VERIFY_PARAM_free(vfy->param);
    VR_CRYPTO_THREAD_lock_free(vfy->lock);
    VR_OPENSSL_free(vfy);
}

int VR_X509_STORE_up_ref(X509_STORE *vfy)
{
    int i;

    if (CRYPTO_UP_REF(&vfy->references, &i, vfy->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("X509_STORE", vfy);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

X509_LOOKUP *VR_X509_STORE_add_lookup(X509_STORE *v, X509_LOOKUP_METHOD *m)
{
    int i;
    STACK_OF(X509_LOOKUP) *sk;
    X509_LOOKUP *lu;

    sk = v->get_cert_methods;
    for (i = 0; i < sk_X509_LOOKUP_num(sk); i++) {
        lu = sk_X509_LOOKUP_value(sk, i);
        if (m == lu->method) {
            return lu;
        }
    }
    /* a new one */
    lu = VR_X509_LOOKUP_new(m);
    if (lu == NULL) {
        X509err(X509_F_X509_STORE_ADD_LOOKUP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    lu->store_ctx = v;
    if (sk_VR_X509_LOOKUP_push(v->get_cert_methods, lu))
        return lu;
    /* malloc failed */
    X509err(X509_F_X509_STORE_ADD_LOOKUP, ERR_R_MALLOC_FAILURE);
    VR_X509_LOOKUP_free(lu);
    return NULL;
}

X509_OBJECT *VR_X509_STORE_CTX_get_obj_by_subject(X509_STORE_CTX *vs,
                                               X509_LOOKUP_TYPE type,
                                               X509_NAME *name)
{
    X509_OBJECT *ret = VR_X509_OBJECT_new();

    if (ret == NULL)
        return NULL;
    if (!VR_X509_STORE_CTX_get_by_subject(vs, type, name, ret)) {
        VR_X509_OBJECT_free(ret);
        return NULL;
    }
    return ret;
}

int VR_X509_STORE_CTX_get_by_subject(X509_STORE_CTX *vs, X509_LOOKUP_TYPE type,
                                  X509_NAME *name, X509_OBJECT *ret)
{
    X509_STORE *ctx = vs->ctx;
    X509_LOOKUP *lu;
    X509_OBJECT stmp, *tmp;
    int i, j;

    if (ctx == NULL)
        return 0;

    VR_CRYPTO_THREAD_write_lock(ctx->lock);
    tmp = VR_X509_OBJECT_retrieve_by_subject(ctx->objs, type, name);
    VR_CRYPTO_THREAD_unlock(ctx->lock);

    if (tmp == NULL || type == X509_LU_CRL) {
        for (i = 0; i < sk_X509_LOOKUP_num(ctx->get_cert_methods); i++) {
            lu = sk_X509_LOOKUP_value(ctx->get_cert_methods, i);
            j = VR_X509_LOOKUP_by_subject(lu, type, name, &stmp);
            if (j) {
                tmp = &stmp;
                break;
            }
        }
        if (tmp == NULL)
            return 0;
    }

    ret->type = tmp->type;
    ret->data.ptr = tmp->data.ptr;

    VR_X509_OBJECT_up_ref_count(ret);

    return 1;
}

static int x509_store_add(X509_STORE *ctx, void *x, int crl) {
    X509_OBJECT *obj;
    int ret = 0, added = 0;

    if (x == NULL)
        return 0;
    obj = VR_X509_OBJECT_new();
    if (obj == NULL)
        return 0;

    if (crl) {
        obj->type = X509_LU_CRL;
        obj->data.crl = (X509_CRL *)x;
    } else {
        obj->type = X509_LU_X509;
        obj->data.x509 = (X509 *)x;
    }
    VR_X509_OBJECT_up_ref_count(obj);

    VR_CRYPTO_THREAD_write_lock(ctx->lock);

    if (VR_X509_OBJECT_retrieve_match(ctx->objs, obj)) {
        ret = 1;
    } else {
        added = sk_VR_X509_OBJECT_push(ctx->objs, obj);
        ret = added != 0;
    }

    VR_CRYPTO_THREAD_unlock(ctx->lock);

    if (added == 0)             /* obj not pushed */
        VR_X509_OBJECT_free(obj);

    return ret;
}

int VR_X509_STORE_add_cert(X509_STORE *ctx, X509 *x)
{
    if (!x509_store_add(ctx, x, 0)) {
        X509err(X509_F_X509_STORE_ADD_CERT, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

int VR_X509_STORE_add_crl(X509_STORE *ctx, X509_CRL *x)
{
    if (!x509_store_add(ctx, x, 1)) {
        X509err(X509_F_X509_STORE_ADD_CRL, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

int VR_X509_OBJECT_up_ref_count(X509_OBJECT *a)
{
    switch (a->type) {
    case X509_LU_NONE:
        break;
    case X509_LU_X509:
        return VR_X509_up_ref(a->data.x509);
    case X509_LU_CRL:
        return VR_X509_CRL_up_ref(a->data.crl);
    }
    return 1;
}

X509 *VR_X509_OBJECT_get0_X509(const X509_OBJECT *a)
{
    if (a == NULL || a->type != X509_LU_X509)
        return NULL;
    return a->data.x509;
}

X509_CRL *VR_X509_OBJECT_get0_X509_CRL(X509_OBJECT *a)
{
    if (a == NULL || a->type != X509_LU_CRL)
        return NULL;
    return a->data.crl;
}

X509_LOOKUP_TYPE VR_X509_OBJECT_get_type(const X509_OBJECT *a)
{
    return a->type;
}

X509_OBJECT *VR_X509_OBJECT_new(void)
{
    X509_OBJECT *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        X509err(X509_F_X509_OBJECT_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ret->type = X509_LU_NONE;
    return ret;
}

static void x509_object_free_internal(X509_OBJECT *a)
{
    if (a == NULL)
        return;
    switch (a->type) {
    case X509_LU_NONE:
        break;
    case X509_LU_X509:
        VR_X509_free(a->data.x509);
        break;
    case X509_LU_CRL:
        VR_X509_CRL_free(a->data.crl);
        break;
    }
}

int VR_X509_OBJECT_set1_X509(X509_OBJECT *a, X509 *obj)
{
    if (a == NULL || !VR_X509_up_ref(obj))
        return 0;

    x509_object_free_internal(a);
    a->type = X509_LU_X509;
    a->data.x509 = obj;
    return 1;
}

int VR_X509_OBJECT_set1_X509_CRL(X509_OBJECT *a, X509_CRL *obj)
{
    if (a == NULL || !VR_X509_CRL_up_ref(obj))
        return 0;

    x509_object_free_internal(a);
    a->type = X509_LU_CRL;
    a->data.crl = obj;
    return 1;
}

void VR_X509_OBJECT_free(X509_OBJECT *a)
{
    x509_object_free_internal(a);
    VR_OPENSSL_free(a);
}

static int x509_object_idx_cnt(STACK_OF(X509_OBJECT) *h, X509_LOOKUP_TYPE type,
                               X509_NAME *name, int *pnmatch)
{
    X509_OBJECT stmp;
    X509 x509_s;
    X509_CRL crl_s;
    int idx;

    stmp.type = type;
    switch (type) {
    case X509_LU_X509:
        stmp.data.x509 = &x509_s;
        x509_s.cert_info.subject = name;
        break;
    case X509_LU_CRL:
        stmp.data.crl = &crl_s;
        crl_s.crl.issuer = name;
        break;
    case X509_LU_NONE:
        /* abort(); */
        return -1;
    }

    idx = sk_VR_X509_OBJECT_find(h, &stmp);
    if (idx >= 0 && pnmatch) {
        int tidx;
        const X509_OBJECT *tobj, *pstmp;
        *pnmatch = 1;
        pstmp = &stmp;
        for (tidx = idx + 1; tidx < sk_X509_OBJECT_num(h); tidx++) {
            tobj = sk_X509_OBJECT_value(h, tidx);
            if (x509_object_cmp(&tobj, &pstmp))
                break;
            (*pnmatch)++;
        }
    }
    return idx;
}

int VR_X509_OBJECT_idx_by_subject(STACK_OF(X509_OBJECT) *h, X509_LOOKUP_TYPE type,
                               X509_NAME *name)
{
    return x509_object_idx_cnt(h, type, name, NULL);
}

X509_OBJECT *VR_X509_OBJECT_retrieve_by_subject(STACK_OF(X509_OBJECT) *h,
                                             X509_LOOKUP_TYPE type,
                                             X509_NAME *name)
{
    int idx;
    idx = VR_X509_OBJECT_idx_by_subject(h, type, name);
    if (idx == -1)
        return NULL;
    return sk_X509_OBJECT_value(h, idx);
}

STACK_OF(X509_OBJECT) *VR_X509_STORE_get0_objects(X509_STORE *v)
{
    return v->objs;
}

STACK_OF(X509) *VR_X509_STORE_CTX_get1_certs(X509_STORE_CTX *ctx, X509_NAME *nm)
{
    int i, idx, cnt;
    STACK_OF(X509) *sk = NULL;
    X509 *x;
    X509_OBJECT *obj;

    if (ctx->ctx == NULL)
        return NULL;

    VR_CRYPTO_THREAD_write_lock(ctx->ctx->lock);
    idx = x509_object_idx_cnt(ctx->ctx->objs, X509_LU_X509, nm, &cnt);
    if (idx < 0) {
        /*
         * Nothing found in cache: do lookup to possibly add new objects to
         * cache
         */
        X509_OBJECT *xobj = VR_X509_OBJECT_new();

        VR_CRYPTO_THREAD_unlock(ctx->ctx->lock);
        if (xobj == NULL)
            return NULL;
        if (!VR_X509_STORE_CTX_get_by_subject(ctx, X509_LU_X509, nm, xobj)) {
            VR_X509_OBJECT_free(xobj);
            return NULL;
        }
        VR_X509_OBJECT_free(xobj);
        VR_CRYPTO_THREAD_write_lock(ctx->ctx->lock);
        idx = x509_object_idx_cnt(ctx->ctx->objs, X509_LU_X509, nm, &cnt);
        if (idx < 0) {
            VR_CRYPTO_THREAD_unlock(ctx->ctx->lock);
            return NULL;
        }
    }

    sk = sk_VR_X509_new_null();
    for (i = 0; i < cnt; i++, idx++) {
        obj = sk_X509_OBJECT_value(ctx->ctx->objs, idx);
        x = obj->data.x509;
        VR_X509_up_ref(x);
        if (!sk_VR_X509_push(sk, x)) {
            VR_CRYPTO_THREAD_unlock(ctx->ctx->lock);
            VR_X509_free(x);
            sk_VR_X509_pop_free(sk, VR_X509_free);
            return NULL;
        }
    }
    VR_CRYPTO_THREAD_unlock(ctx->ctx->lock);
    return sk;
}

STACK_OF(X509_CRL) *VR_X509_STORE_CTX_get1_crls(X509_STORE_CTX *ctx, X509_NAME *nm)
{
    int i, idx, cnt;
    STACK_OF(X509_CRL) *sk = sk_VR_X509_CRL_new_null();
    X509_CRL *x;
    X509_OBJECT *obj, *xobj = VR_X509_OBJECT_new();

    /* Always do lookup to possibly add new CRLs to cache */
    if (sk == NULL
            || xobj == NULL
            || ctx->ctx == NULL
            || !VR_X509_STORE_CTX_get_by_subject(ctx, X509_LU_CRL, nm, xobj)) {
        VR_X509_OBJECT_free(xobj);
        sk_VR_X509_CRL_free(sk);
        return NULL;
    }
    VR_X509_OBJECT_free(xobj);
    VR_CRYPTO_THREAD_write_lock(ctx->ctx->lock);
    idx = x509_object_idx_cnt(ctx->ctx->objs, X509_LU_CRL, nm, &cnt);
    if (idx < 0) {
        VR_CRYPTO_THREAD_unlock(ctx->ctx->lock);
        sk_VR_X509_CRL_free(sk);
        return NULL;
    }

    for (i = 0; i < cnt; i++, idx++) {
        obj = sk_X509_OBJECT_value(ctx->ctx->objs, idx);
        x = obj->data.crl;
        VR_X509_CRL_up_ref(x);
        if (!sk_VR_X509_CRL_push(sk, x)) {
            VR_CRYPTO_THREAD_unlock(ctx->ctx->lock);
            VR_X509_CRL_free(x);
            sk_VR_X509_CRL_pop_free(sk, VR_X509_CRL_free);
            return NULL;
        }
    }
    VR_CRYPTO_THREAD_unlock(ctx->ctx->lock);
    return sk;
}

X509_OBJECT *VR_X509_OBJECT_retrieve_match(STACK_OF(X509_OBJECT) *h,
                                        X509_OBJECT *x)
{
    int idx, i, num;
    X509_OBJECT *obj;

    idx = sk_VR_X509_OBJECT_find(h, x);
    if (idx < 0)
        return NULL;
    if ((x->type != X509_LU_X509) && (x->type != X509_LU_CRL))
        return sk_X509_OBJECT_value(h, idx);
    for (i = idx, num = sk_X509_OBJECT_num(h); i < num; i++) {
        obj = sk_X509_OBJECT_value(h, i);
        if (x509_object_cmp((const X509_OBJECT **)&obj,
                            (const X509_OBJECT **)&x))
            return NULL;
        if (x->type == X509_LU_X509) {
            if (!VR_X509_cmp(obj->data.x509, x->data.x509))
                return obj;
        } else if (x->type == X509_LU_CRL) {
            if (!VR_X509_CRL_match(obj->data.crl, x->data.crl))
                return obj;
        } else
            return obj;
    }
    return NULL;
}

/*-
 * Try to get issuer certificate from store. Due to limitations
 * of the API this can only retrieve a single certificate matching
 * a given subject name. However it will fill the cache with all
 * matching certificates, so we can examine the cache for all
 * matches.
 *
 * Return values are:
 *  1 lookup successful.
 *  0 certificate not found.
 * -1 some other error.
 */
int VR_X509_STORE_CTX_get1_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *x)
{
    X509_NAME *xn;
    X509_OBJECT *obj = VR_X509_OBJECT_new(), *pobj = NULL;
    int i, ok, idx, ret;

    if (obj == NULL)
        return -1;
    *issuer = NULL;
    xn = VR_X509_get_issuer_name(x);
    ok = VR_X509_STORE_CTX_get_by_subject(ctx, X509_LU_X509, xn, obj);
    if (ok != 1) {
        VR_X509_OBJECT_free(obj);
        return 0;
    }
    /* If certificate matches all OK */
    if (ctx->check_issued(ctx, x, obj->data.x509)) {
        if (VR_x509_check_cert_time(ctx, obj->data.x509, -1)) {
            *issuer = obj->data.x509;
            VR_X509_up_ref(*issuer);
            VR_X509_OBJECT_free(obj);
            return 1;
        }
    }
    VR_X509_OBJECT_free(obj);

    if (ctx->ctx == NULL)
        return 0;

    /* Else find index of first cert accepted by 'check_issued' */
    ret = 0;
    VR_CRYPTO_THREAD_write_lock(ctx->ctx->lock);
    idx = VR_X509_OBJECT_idx_by_subject(ctx->ctx->objs, X509_LU_X509, xn);
    if (idx != -1) {            /* should be true as we've had at least one
                                 * match */
        /* Look through all matching certs for suitable issuer */
        for (i = idx; i < sk_X509_OBJECT_num(ctx->ctx->objs); i++) {
            pobj = sk_X509_OBJECT_value(ctx->ctx->objs, i);
            /* See if we've run past the matches */
            if (pobj->type != X509_LU_X509)
                break;
            if (VR_X509_NAME_cmp(xn, VR_X509_get_subject_name(pobj->data.x509)))
                break;
            if (ctx->check_issued(ctx, x, pobj->data.x509)) {
                *issuer = pobj->data.x509;
                ret = 1;
                /*
                 * If times check, exit with match,
                 * otherwise keep looking. Leave last
                 * match in issuer so we return nearest
                 * match if no certificate time is OK.
                 */

                if (VR_x509_check_cert_time(ctx, *issuer, -1))
                    break;
            }
        }
    }
    VR_CRYPTO_THREAD_unlock(ctx->ctx->lock);
    if (*issuer)
        VR_X509_up_ref(*issuer);
    return ret;
}

int VR_X509_STORE_set_flags(X509_STORE *ctx, unsigned long flags)
{
    return VR_X509_VERIFY_PARAM_set_flags(ctx->param, flags);
}

int VR_X509_STORE_set_depth(X509_STORE *ctx, int depth)
{
    VR_X509_VERIFY_PARAM_set_depth(ctx->param, depth);
    return 1;
}

int VR_X509_STORE_set_purpose(X509_STORE *ctx, int purpose)
{
    return VR_X509_VERIFY_PARAM_set_purpose(ctx->param, purpose);
}

int VR_X509_STORE_set_trust(X509_STORE *ctx, int trust)
{
    return VR_X509_VERIFY_PARAM_set_trust(ctx->param, trust);
}

int VR_X509_STORE_set1_param(X509_STORE *ctx, X509_VERIFY_PARAM *param)
{
    return VR_X509_VERIFY_PARAM_set1(ctx->param, param);
}

X509_VERIFY_PARAM *VR_X509_STORE_get0_param(X509_STORE *ctx)
{
    return ctx->param;
}

void VR_X509_STORE_set_verify(X509_STORE *ctx, X509_STORE_CTX_verify_fn verify)
{
    ctx->verify = verify;
}

X509_STORE_CTX_verify_fn VR_X509_STORE_get_verify(X509_STORE *ctx)
{
    return ctx->verify;
}

void VR_X509_STORE_set_verify_cb(X509_STORE *ctx,
                              X509_STORE_CTX_verify_cb verify_cb)
{
    ctx->verify_cb = verify_cb;
}

X509_STORE_CTX_verify_cb VR_X509_STORE_get_verify_cb(X509_STORE *ctx)
{
    return ctx->verify_cb;
}

void VR_X509_STORE_set_get_issuer(X509_STORE *ctx,
                               X509_STORE_CTX_get_issuer_fn get_issuer)
{
    ctx->get_issuer = get_issuer;
}

X509_STORE_CTX_get_issuer_fn VR_X509_STORE_get_get_issuer(X509_STORE *ctx)
{
    return ctx->get_issuer;
}

void VR_X509_STORE_set_check_issued(X509_STORE *ctx,
                                 X509_STORE_CTX_check_issued_fn check_issued)
{
    ctx->check_issued = check_issued;
}

X509_STORE_CTX_check_issued_fn VR_X509_STORE_get_check_issued(X509_STORE *ctx)
{
    return ctx->check_issued;
}

void VR_X509_STORE_set_check_revocation(X509_STORE *ctx,
                                     X509_STORE_CTX_check_revocation_fn check_revocation)
{
    ctx->check_revocation = check_revocation;
}

X509_STORE_CTX_check_revocation_fn VR_X509_STORE_get_check_revocation(X509_STORE *ctx)
{
    return ctx->check_revocation;
}

void VR_X509_STORE_set_get_crl(X509_STORE *ctx,
                            X509_STORE_CTX_get_crl_fn get_crl)
{
    ctx->get_crl = get_crl;
}

X509_STORE_CTX_get_crl_fn VR_X509_STORE_get_get_crl(X509_STORE *ctx)
{
    return ctx->get_crl;
}

void VR_X509_STORE_set_check_crl(X509_STORE *ctx,
                              X509_STORE_CTX_check_crl_fn check_crl)
{
    ctx->check_crl = check_crl;
}

X509_STORE_CTX_check_crl_fn VR_X509_STORE_get_check_crl(X509_STORE *ctx)
{
    return ctx->check_crl;
}

void VR_X509_STORE_set_cert_crl(X509_STORE *ctx,
                             X509_STORE_CTX_cert_crl_fn cert_crl)
{
    ctx->cert_crl = cert_crl;
}

X509_STORE_CTX_cert_crl_fn VR_X509_STORE_get_cert_crl(X509_STORE *ctx)
{
    return ctx->cert_crl;
}

void VR_X509_STORE_set_check_policy(X509_STORE *ctx,
                                 X509_STORE_CTX_check_policy_fn check_policy)
{
    ctx->check_policy = check_policy;
}

X509_STORE_CTX_check_policy_fn VR_X509_STORE_get_check_policy(X509_STORE *ctx)
{
    return ctx->check_policy;
}

void VR_X509_STORE_set_lookup_certs(X509_STORE *ctx,
                                 X509_STORE_CTX_lookup_certs_fn lookup_certs)
{
    ctx->lookup_certs = lookup_certs;
}

X509_STORE_CTX_lookup_certs_fn VR_X509_STORE_get_lookup_certs(X509_STORE *ctx)
{
    return ctx->lookup_certs;
}

void VR_X509_STORE_set_lookup_crls(X509_STORE *ctx,
                                X509_STORE_CTX_lookup_crls_fn lookup_crls)
{
    ctx->lookup_crls = lookup_crls;
}

X509_STORE_CTX_lookup_crls_fn VR_X509_STORE_get_lookup_crls(X509_STORE *ctx)
{
    return ctx->lookup_crls;
}

void VR_X509_STORE_set_cleanup(X509_STORE *ctx,
                            VR_X509_STORE_CTX_cleanup_fn ctx_cleanup)
{
    ctx->cleanup = ctx_cleanup;
}

VR_X509_STORE_CTX_cleanup_fn VR_X509_STORE_get_cleanup(X509_STORE *ctx)
{
    return ctx->cleanup;
}

int VR_X509_STORE_set_ex_data(X509_STORE *ctx, int idx, void *data)
{
    return VR_CRYPTO_set_ex_data(&ctx->ex_data, idx, data);
}

void *VR_X509_STORE_get_ex_data(X509_STORE *ctx, int idx)
{
    return VR_CRYPTO_get_ex_data(&ctx->ex_data, idx);
}

X509_STORE *VR_X509_STORE_CTX_get0_store(X509_STORE_CTX *ctx)
{
    return ctx->ctx;
}
