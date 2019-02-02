/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/ocsp.h>
#include "ocsp_lcl.h"
#include <openssl/rand.h>
#include <openssl/x509v3.h>

/* Standard wrapper functions for extensions */

/* OCSP request extensions */

int VR_OCSP_REQUEST_get_ext_count(OCSP_REQUEST *x)
{
    return VR_X509v3_get_ext_count(x->tbsRequest.requestExtensions);
}

int VR_OCSP_REQUEST_get_ext_by_NID(OCSP_REQUEST *x, int nid, int lastpos)
{
    return (VR_X509v3_get_ext_by_NID
            (x->tbsRequest.requestExtensions, nid, lastpos));
}

int VR_OCSP_REQUEST_get_ext_by_OBJ(OCSP_REQUEST *x, const ASN1_OBJECT *obj,
                                int lastpos)
{
    return (VR_X509v3_get_ext_by_OBJ
            (x->tbsRequest.requestExtensions, obj, lastpos));
}

int VR_OCSP_REQUEST_get_ext_by_critical(OCSP_REQUEST *x, int crit, int lastpos)
{
    return (VR_X509v3_get_ext_by_critical
            (x->tbsRequest.requestExtensions, crit, lastpos));
}

X509_EXTENSION *VR_OCSP_REQUEST_get_ext(OCSP_REQUEST *x, int loc)
{
    return VR_X509v3_get_ext(x->tbsRequest.requestExtensions, loc);
}

X509_EXTENSION *VR_OCSP_REQUEST_delete_ext(OCSP_REQUEST *x, int loc)
{
    return VR_X509v3_delete_ext(x->tbsRequest.requestExtensions, loc);
}

void *VR_OCSP_REQUEST_get1_ext_d2i(OCSP_REQUEST *x, int nid, int *crit, int *idx)
{
    return VR_X509V3_get_d2i(x->tbsRequest.requestExtensions, nid, crit, idx);
}

int VR_OCSP_REQUEST_add1_ext_i2d(OCSP_REQUEST *x, int nid, void *value, int crit,
                              unsigned long flags)
{
    return VR_X509V3_add1_i2d(&x->tbsRequest.requestExtensions, nid, value,
                           crit, flags);
}

int VR_OCSP_REQUEST_add_ext(OCSP_REQUEST *x, X509_EXTENSION *ex, int loc)
{
    return (VR_X509v3_add_ext(&(x->tbsRequest.requestExtensions), ex, loc) !=
            NULL);
}

/* Single extensions */

int VR_OCSP_ONEREQ_get_ext_count(OCSP_ONEREQ *x)
{
    return VR_X509v3_get_ext_count(x->singleRequestExtensions);
}

int VR_OCSP_ONEREQ_get_ext_by_NID(OCSP_ONEREQ *x, int nid, int lastpos)
{
    return VR_X509v3_get_ext_by_NID(x->singleRequestExtensions, nid, lastpos);
}

int VR_OCSP_ONEREQ_get_ext_by_OBJ(OCSP_ONEREQ *x, const ASN1_OBJECT *obj,
                               int lastpos)
{
    return VR_X509v3_get_ext_by_OBJ(x->singleRequestExtensions, obj, lastpos);
}

int VR_OCSP_ONEREQ_get_ext_by_critical(OCSP_ONEREQ *x, int crit, int lastpos)
{
    return (VR_X509v3_get_ext_by_critical
            (x->singleRequestExtensions, crit, lastpos));
}

X509_EXTENSION *VR_OCSP_ONEREQ_get_ext(OCSP_ONEREQ *x, int loc)
{
    return VR_X509v3_get_ext(x->singleRequestExtensions, loc);
}

X509_EXTENSION *VR_OCSP_ONEREQ_delete_ext(OCSP_ONEREQ *x, int loc)
{
    return VR_X509v3_delete_ext(x->singleRequestExtensions, loc);
}

void *VR_OCSP_ONEREQ_get1_ext_d2i(OCSP_ONEREQ *x, int nid, int *crit, int *idx)
{
    return VR_X509V3_get_d2i(x->singleRequestExtensions, nid, crit, idx);
}

int VR_OCSP_ONEREQ_add1_ext_i2d(OCSP_ONEREQ *x, int nid, void *value, int crit,
                             unsigned long flags)
{
    return VR_X509V3_add1_i2d(&x->singleRequestExtensions, nid, value, crit,
                           flags);
}

int VR_OCSP_ONEREQ_add_ext(OCSP_ONEREQ *x, X509_EXTENSION *ex, int loc)
{
    return (VR_X509v3_add_ext(&(x->singleRequestExtensions), ex, loc) != NULL);
}

/* OCSP Basic response */

int VR_OCSP_BASICRESP_get_ext_count(OCSP_BASICRESP *x)
{
    return VR_X509v3_get_ext_count(x->tbsResponseData.responseExtensions);
}

int VR_OCSP_BASICRESP_get_ext_by_NID(OCSP_BASICRESP *x, int nid, int lastpos)
{
    return (VR_X509v3_get_ext_by_NID
            (x->tbsResponseData.responseExtensions, nid, lastpos));
}

int VR_OCSP_BASICRESP_get_ext_by_OBJ(OCSP_BASICRESP *x, const ASN1_OBJECT *obj,
                                  int lastpos)
{
    return (VR_X509v3_get_ext_by_OBJ
            (x->tbsResponseData.responseExtensions, obj, lastpos));
}

int VR_OCSP_BASICRESP_get_ext_by_critical(OCSP_BASICRESP *x, int crit,
                                       int lastpos)
{
    return (VR_X509v3_get_ext_by_critical
            (x->tbsResponseData.responseExtensions, crit, lastpos));
}

X509_EXTENSION *VR_OCSP_BASICRESP_get_ext(OCSP_BASICRESP *x, int loc)
{
    return VR_X509v3_get_ext(x->tbsResponseData.responseExtensions, loc);
}

X509_EXTENSION *VR_OCSP_BASICRESP_delete_ext(OCSP_BASICRESP *x, int loc)
{
    return VR_X509v3_delete_ext(x->tbsResponseData.responseExtensions, loc);
}

void *VR_OCSP_BASICRESP_get1_ext_d2i(OCSP_BASICRESP *x, int nid, int *crit,
                                  int *idx)
{
    return VR_X509V3_get_d2i(x->tbsResponseData.responseExtensions, nid, crit,
                          idx);
}

int VR_OCSP_BASICRESP_add1_ext_i2d(OCSP_BASICRESP *x, int nid, void *value,
                                int crit, unsigned long flags)
{
    return VR_X509V3_add1_i2d(&x->tbsResponseData.responseExtensions, nid,
                           value, crit, flags);
}

int VR_OCSP_BASICRESP_add_ext(OCSP_BASICRESP *x, X509_EXTENSION *ex, int loc)
{
    return (VR_X509v3_add_ext(&(x->tbsResponseData.responseExtensions), ex, loc)
            != NULL);
}

/* OCSP single response extensions */

int VR_OCSP_SINGLERESP_get_ext_count(OCSP_SINGLERESP *x)
{
    return VR_X509v3_get_ext_count(x->singleExtensions);
}

int VR_OCSP_SINGLERESP_get_ext_by_NID(OCSP_SINGLERESP *x, int nid, int lastpos)
{
    return VR_X509v3_get_ext_by_NID(x->singleExtensions, nid, lastpos);
}

int VR_OCSP_SINGLERESP_get_ext_by_OBJ(OCSP_SINGLERESP *x, const ASN1_OBJECT *obj,
                                   int lastpos)
{
    return VR_X509v3_get_ext_by_OBJ(x->singleExtensions, obj, lastpos);
}

int VR_OCSP_SINGLERESP_get_ext_by_critical(OCSP_SINGLERESP *x, int crit,
                                        int lastpos)
{
    return VR_X509v3_get_ext_by_critical(x->singleExtensions, crit, lastpos);
}

X509_EXTENSION *VR_OCSP_SINGLERESP_get_ext(OCSP_SINGLERESP *x, int loc)
{
    return VR_X509v3_get_ext(x->singleExtensions, loc);
}

X509_EXTENSION *VR_OCSP_SINGLERESP_delete_ext(OCSP_SINGLERESP *x, int loc)
{
    return VR_X509v3_delete_ext(x->singleExtensions, loc);
}

void *VR_OCSP_SINGLERESP_get1_ext_d2i(OCSP_SINGLERESP *x, int nid, int *crit,
                                   int *idx)
{
    return VR_X509V3_get_d2i(x->singleExtensions, nid, crit, idx);
}

int VR_OCSP_SINGLERESP_add1_ext_i2d(OCSP_SINGLERESP *x, int nid, void *value,
                                 int crit, unsigned long flags)
{
    return VR_X509V3_add1_i2d(&x->singleExtensions, nid, value, crit, flags);
}

int VR_OCSP_SINGLERESP_add_ext(OCSP_SINGLERESP *x, X509_EXTENSION *ex, int loc)
{
    return (VR_X509v3_add_ext(&(x->singleExtensions), ex, loc) != NULL);
}

/* also CRL Entry Extensions */

/* Nonce handling functions */

/*
 * Add a nonce to an extension stack. A nonce can be specified or if NULL a
 * random nonce will be generated. Note: OpenSSL 0.9.7d and later create an
 * OCTET STRING containing the nonce, previous versions used the raw nonce.
 */

static int ocsp_add1_nonce(STACK_OF(X509_EXTENSION) **exts,
                           unsigned char *val, int len)
{
    unsigned char *tmpval;
    ASN1_OCTET_STRING os;
    int ret = 0;
    if (len <= 0)
        len = OCSP_DEFAULT_NONCE_LENGTH;
    /*
     * Create the OCTET STRING manually by writing out the header and
     * appending the content octets. This avoids an extra memory allocation
     * operation in some cases. Applications should *NOT* do this because it
     * relies on library internals.
     */
    os.length = VR_ASN1_object_size(0, len, V_ASN1_OCTET_STRING);
    if (os.length < 0)
        return 0;

    os.data = OPENSSL_malloc(os.length);
    if (os.data == NULL)
        goto err;
    tmpval = os.data;
    VR_ASN1_put_object(&tmpval, 0, len, V_ASN1_OCTET_STRING, V_ASN1_UNIVERSAL);
    if (val)
        memcpy(tmpval, val, len);
    else if (VR_RAND_bytes(tmpval, len) <= 0)
        goto err;
    if (!VR_X509V3_add1_i2d(exts, NID_id_pkix_OCSP_Nonce,
                         &os, 0, X509V3_ADD_REPLACE))
        goto err;
    ret = 1;
 err:
    OPENVR_SSL_free(os.data);
    return ret;
}

/* Add nonce to an OCSP request */

int VR_OCSP_request_add1_nonce(OCSP_REQUEST *req, unsigned char *val, int len)
{
    return ocsp_add1_nonce(&req->tbsRequest.requestExtensions, val, len);
}

/* Same as above but for a response */

int VR_OCSP_basic_add1_nonce(OCSP_BASICRESP *resp, unsigned char *val, int len)
{
    return ocsp_add1_nonce(&resp->tbsResponseData.responseExtensions, val,
                           len);
}

/*-
 * Check nonce validity in a request and response.
 * Return value reflects result:
 *  1: nonces present and equal.
 *  2: nonces both absent.
 *  3: nonce present in response only.
 *  0: nonces both present and not equal.
 * -1: nonce in request only.
 *
 *  For most responders clients can check return > 0.
 *  If responder doesn't handle nonces return != 0 may be
 *  necessary. return == 0 is always an error.
 */

int VR_OCSP_check_nonce(OCSP_REQUEST *req, OCSP_BASICRESP *bs)
{
    /*
     * Since we are only interested in the presence or absence of
     * the nonce and comparing its value there is no need to use
     * the X509V3 routines: this way we can avoid them allocating an
     * ASN1_OCTET_STRING structure for the value which would be
     * freed immediately anyway.
     */

    int req_idx, resp_idx;
    X509_EXTENSION *req_ext, *resp_ext;
    req_idx = VR_OCSP_REQUEST_get_ext_by_NID(req, NID_id_pkix_OCSP_Nonce, -1);
    resp_idx = VR_OCSP_BASICRESP_get_ext_by_NID(bs, NID_id_pkix_OCSP_Nonce, -1);
    /* Check both absent */
    if ((req_idx < 0) && (resp_idx < 0))
        return 2;
    /* Check in request only */
    if ((req_idx >= 0) && (resp_idx < 0))
        return -1;
    /* Check in response but not request */
    if ((req_idx < 0) && (resp_idx >= 0))
        return 3;
    /*
     * Otherwise nonce in request and response so retrieve the extensions
     */
    req_ext = VR_OCSP_REQUEST_get_ext(req, req_idx);
    resp_ext = VR_OCSP_BASICRESP_get_ext(bs, resp_idx);
    if (VR_ASN1_OCTET_STRING_cmp(VR_X509_EXTENSION_get_data(req_ext),
                              VR_X509_EXTENSION_get_data(resp_ext)))
        return 0;
    return 1;
}

/*
 * Copy the nonce value (if any) from an OCSP request to a response.
 */

int VR_OCSP_copy_nonce(OCSP_BASICRESP *resp, OCSP_REQUEST *req)
{
    X509_EXTENSION *req_ext;
    int req_idx;
    /* Check for nonce in request */
    req_idx = VR_OCSP_REQUEST_get_ext_by_NID(req, NID_id_pkix_OCSP_Nonce, -1);
    /* If no nonce that's OK */
    if (req_idx < 0)
        return 2;
    req_ext = VR_OCSP_REQUEST_get_ext(req, req_idx);
    return VR_OCSP_BASICRESP_add_ext(resp, req_ext, -1);
}

X509_EXTENSION *VR_OCSP_crlID_new(const char *url, long *n, char *tim)
{
    X509_EXTENSION *x = NULL;
    OCSP_CRLID *cid = NULL;

    if ((cid = VR_OCSP_CRLID_new()) == NULL)
        goto err;
    if (url) {
        if ((cid->crlUrl = VR_ASN1_IA5STRING_new()) == NULL)
            goto err;
        if (!(VR_ASN1_STRING_set(cid->crlUrl, url, -1)))
            goto err;
    }
    if (n) {
        if ((cid->crlNum = VR_ASN1_INTEGER_new()) == NULL)
            goto err;
        if (!(VR_ASN1_INTEGER_set(cid->crlNum, *n)))
            goto err;
    }
    if (tim) {
        if ((cid->crlTime = VR_ASN1_GENERALIZEDTIME_new()) == NULL)
            goto err;
        if (!(VR_ASN1_GENERALIZEDTIME_set_string(cid->crlTime, tim)))
            goto err;
    }
    x = VR_X509V3_EXT_i2d(NID_id_pkix_OCSP_CrlID, 0, cid);
 err:
    VR_OCSP_CRLID_free(cid);
    return x;
}

/*   AcceptableResponses ::= SEQUENCE OF OBJECT IDENTIFIER */
X509_EXTENSION *VR_OCSP_accept_responses_new(char **oids)
{
    int nid;
    STACK_OF(ASN1_OBJECT) *sk = NULL;
    ASN1_OBJECT *o = NULL;
    X509_EXTENSION *x = NULL;

    if ((sk = sk_VR_ASN1_OBJECT_new_null()) == NULL)
        goto err;
    while (oids && *oids) {
        if ((nid = VR_OBJ_txt2nid(*oids)) != NID_undef && (o = VR_OBJ_nid2obj(nid)))
            sk_VR_ASN1_OBJECT_push(sk, o);
        oids++;
    }
    x = VR_X509V3_EXT_i2d(NID_id_pkix_OCSP_acceptableResponses, 0, sk);
 err:
    sk_VR_ASN1_OBJECT_pop_free(sk, VR_ASN1_OBJECT_free);
    return x;
}

/*  ArchiveCutoff ::= GeneralizedTime */
X509_EXTENSION *VR_OCSP_archive_cutoff_new(char *tim)
{
    X509_EXTENSION *x = NULL;
    ASN1_GENERALIZEDTIME *gt = NULL;

    if ((gt = VR_ASN1_GENERALIZEDTIME_new()) == NULL)
        goto err;
    if (!(VR_ASN1_GENERALIZEDTIME_set_string(gt, tim)))
        goto err;
    x = VR_X509V3_EXT_i2d(NID_id_pkix_OCSP_archiveCutoff, 0, gt);
 err:
    VR_ASN1_GENERALIZEDTIME_free(gt);
    return x;
}

/*
 * per ACCESS_DESCRIPTION parameter are oids, of which there are currently
 * two--NID_ad_ocsp, NID_id_ad_caIssuers--and GeneralName value.  This method
 * forces NID_ad_ocsp and uniformResourceLocator [6] IA5String.
 */
X509_EXTENSION *VR_OCSP_url_svcloc_new(X509_NAME *issuer, const char **urls)
{
    X509_EXTENSION *x = NULL;
    ASN1_IA5STRING *ia5 = NULL;
    OCSP_SERVICELOC *sloc = NULL;
    ACCESS_DESCRIPTION *ad = NULL;

    if ((sloc = VR_OCSP_SERVICELOC_new()) == NULL)
        goto err;
    if ((sloc->issuer = VR_X509_NAME_dup(issuer)) == NULL)
        goto err;
    if (urls && *urls
        && (sloc->locator = sk_VR_ACCESS_DESCRIPTION_new_null()) == NULL)
        goto err;
    while (urls && *urls) {
        if ((ad = VR_ACCESS_DESCRIPTION_new()) == NULL)
            goto err;
        if ((ad->method = VR_OBJ_nid2obj(NID_ad_OCSP)) == NULL)
            goto err;
        if ((ad->location = VR_GENERAL_NAME_new()) == NULL)
            goto err;
        if ((ia5 = VR_ASN1_IA5STRING_new()) == NULL)
            goto err;
        if (!VR_ASN1_STRING_set((ASN1_STRING *)ia5, *urls, -1))
            goto err;
        ad->location->type = GEN_URI;
        ad->location->d.ia5 = ia5;
        ia5 = NULL;
        if (!sk_VR_ACCESS_DESCRIPTION_push(sloc->locator, ad))
            goto err;
        ad = NULL;
        urls++;
    }
    x = VR_X509V3_EXT_i2d(NID_id_pkix_OCSP_serviceLocator, 0, sloc);
 err:
    VR_ASN1_IA5STRING_free(ia5);
    VR_ACCESS_DESCRIPTION_free(ad);
    VR_OCSP_SERVICELOC_free(sloc);
    return x;
}
