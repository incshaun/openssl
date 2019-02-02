/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include "ocsp_lcl.h"
#include "internal/cryptlib.h"
#include <openssl/pem.h>

static int ocsp_certid_print(BIO *bp, OCSP_CERTID *a, int indent)
{
    VR_BIO_printf(bp, "%*sCertificate ID:\n", indent, "");
    indent += 2;
    VR_BIO_printf(bp, "%*sHash Algorithm: ", indent, "");
    VR_i2a_ASN1_OBJECT(bp, a->hashAlgorithm.algorithm);
    VR_BIO_printf(bp, "\n%*sIssuer Name Hash: ", indent, "");
    VR_i2a_ASN1_STRING(bp, &a->issuerNameHash, 0);
    VR_BIO_printf(bp, "\n%*sIssuer Key Hash: ", indent, "");
    VR_i2a_ASN1_STRING(bp, &a->issuerKeyHash, 0);
    VR_BIO_printf(bp, "\n%*sSerial Number: ", indent, "");
    VR_i2a_ASN1_INTEGER(bp, &a->serialNumber);
    VR_BIO_printf(bp, "\n");
    return 1;
}

typedef struct {
    long t;
    const char *m;
} OCSP_TBLSTR;

static const char *do_table2string(long s, const OCSP_TBLSTR *ts, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++, ts++)
        if (ts->t == s)
            return ts->m;
    return "(UNKNOWN)";
}

#define table2string(s, tbl) do_table2string(s, tbl, OSSL_NELEM(tbl))

const char *VR_OCSP_response_status_str(long s)
{
    static const OCSP_TBLSTR rstat_tbl[] = {
        {OCSP_RESPONSE_STATUS_SUCCESSFUL, "successful"},
        {OCSP_RESPONSE_STATUS_MALFORMEDREQUEST, "malformedrequest"},
        {OCSP_RESPONSE_STATUS_INTERNALERROR, "internalerror"},
        {OCSP_RESPONSE_STATUS_TRYLATER, "trylater"},
        {OCSP_RESPONSE_STATUS_SIGREQUIRED, "sigrequired"},
        {OCSP_RESPONSE_STATUS_UNAUTHORIZED, "unauthorized"}
    };
    return table2string(s, rstat_tbl);
}

const char *VR_OCSP_cert_status_str(long s)
{
    static const OCSP_TBLSTR cstat_tbl[] = {
        {V_OCSP_CERTSTATUS_GOOD, "good"},
        {V_OCSP_CERTSTATUS_REVOKED, "revoked"},
        {V_OCSP_CERTSTATUS_UNKNOWN, "unknown"}
    };
    return table2string(s, cstat_tbl);
}

const char *VR_OCSP_crl_reason_str(long s)
{
    static const OCSP_TBLSTR reason_tbl[] = {
        {OCSP_REVOKED_STATUS_UNSPECIFIED, "unspecified"},
        {OCSP_REVOKED_STATUS_KEYCOMPROMISE, "keyCompromise"},
        {OCSP_REVOKED_STATUS_CACOMPROMISE, "cACompromise"},
        {OCSP_REVOKED_STATUS_AFFILIATIONCHANGED, "affiliationChanged"},
        {OCSP_REVOKED_STATUS_SUPERSEDED, "superseded"},
        {OCSP_REVOKED_STATUS_CESSATIONOFOPERATION, "cessationOfOperation"},
        {OCSP_REVOKED_STATUS_CERTIFICATEHOLD, "certificateHold"},
        {OCSP_REVOKED_STATUS_REMOVEFROMCRL, "removeFromCRL"}
    };
    return table2string(s, reason_tbl);
}

int VR_OCSP_REQUEST_print(BIO *bp, OCSP_REQUEST *o, unsigned long flags)
{
    int i;
    long l;
    OCSP_CERTID *cid = NULL;
    OCSP_ONEREQ *one = NULL;
    OCSP_REQINFO *inf = &o->tbsRequest;
    OCSP_SIGNATURE *sig = o->optionalSignature;

    if (VR_BIO_write(bp, "OCSP Request Data:\n", 19) <= 0)
        goto err;
    l = VR_ASN1_INTEGER_get(inf->version);
    if (VR_BIO_printf(bp, "    Version: %lu (0x%lx)", l + 1, l) <= 0)
        goto err;
    if (inf->requestorName != NULL) {
        if (VR_BIO_write(bp, "\n    Requestor Name: ", 21) <= 0)
            goto err;
        VR_GENERAL_NAME_print(bp, inf->requestorName);
    }
    if (VR_BIO_write(bp, "\n    Requestor List:\n", 21) <= 0)
        goto err;
    for (i = 0; i < sk_OCSP_ONEREQ_num(inf->requestList); i++) {
        one = sk_OCSP_ONEREQ_value(inf->requestList, i);
        cid = one->reqCert;
        ocsp_certid_print(bp, cid, 8);
        if (!VR_X509V3_extensions_print(bp,
                                     "Request Single Extensions",
                                     one->singleRequestExtensions, flags, 8))
            goto err;
    }
    if (!VR_X509V3_extensions_print(bp, "Request Extensions",
                                 inf->requestExtensions, flags, 4))
        goto err;
    if (sig) {
        VR_X509_signature_print(bp, &sig->signatureAlgorithm, sig->signature);
        for (i = 0; i < sk_X509_num(sig->certs); i++) {
            VR_X509_print(bp, sk_X509_value(sig->certs, i));
            VR_PEM_write_bio_X509(bp, sk_X509_value(sig->certs, i));
        }
    }
    return 1;
 err:
    return 0;
}

int VR_OCSP_RESPONSE_print(BIO *bp, OCSP_RESPONSE *o, unsigned long flags)
{
    int i, ret = 0;
    long l;
    OCSP_CERTID *cid = NULL;
    OCSP_BASICRESP *br = NULL;
    OCSP_RESPID *rid = NULL;
    OCSP_RESPDATA *rd = NULL;
    OCSP_CERTSTATUS *cst = NULL;
    OCSP_REVOKEDINFO *rev = NULL;
    OCSP_SINGLERESP *single = NULL;
    OCSP_RESPBYTES *rb = o->responseBytes;

    if (VR_BIO_puts(bp, "OCSP Response Data:\n") <= 0)
        goto err;
    l = VR_ASN1_ENUMERATED_get(o->responseStatus);
    if (VR_BIO_printf(bp, "    OCSP Response Status: %s (0x%lx)\n",
                   VR_OCSP_response_status_str(l), l) <= 0)
        goto err;
    if (rb == NULL)
        return 1;
    if (VR_BIO_puts(bp, "    Response Type: ") <= 0)
        goto err;
    if (VR_i2a_ASN1_OBJECT(bp, rb->responseType) <= 0)
        goto err;
    if (VR_OBJ_obj2nid(rb->responseType) != NID_id_pkix_OCSP_basic) {
        VR_BIO_puts(bp, " (unknown response type)\n");
        return 1;
    }

    if ((br = VR_OCSP_response_get1_basic(o)) == NULL)
        goto err;
    rd = &br->tbsResponseData;
    l = VR_ASN1_INTEGER_get(rd->version);
    if (VR_BIO_printf(bp, "\n    Version: %lu (0x%lx)\n", l + 1, l) <= 0)
        goto err;
    if (VR_BIO_puts(bp, "    Responder Id: ") <= 0)
        goto err;

    rid = &rd->responderId;
    switch (rid->type) {
    case V_OCSP_RESPID_NAME:
        VR_X509_NAME_print_ex(bp, rid->value.byName, 0, XN_FLAG_ONELINE);
        break;
    case V_OCSP_RESPID_KEY:
        VR_i2a_ASN1_STRING(bp, rid->value.byKey, 0);
        break;
    }

    if (VR_BIO_printf(bp, "\n    Produced At: ") <= 0)
        goto err;
    if (!VR_ASN1_GENERALIZEDTIME_print(bp, rd->producedAt))
        goto err;
    if (VR_BIO_printf(bp, "\n    Responses:\n") <= 0)
        goto err;
    for (i = 0; i < sk_OCSP_SINGLERESP_num(rd->responses); i++) {
        if (!sk_OCSP_SINGLERESP_value(rd->responses, i))
            continue;
        single = sk_OCSP_SINGLERESP_value(rd->responses, i);
        cid = single->certId;
        if (ocsp_certid_print(bp, cid, 4) <= 0)
            goto err;
        cst = single->certStatus;
        if (VR_BIO_printf(bp, "    Cert Status: %s",
                       VR_OCSP_cert_status_str(cst->type)) <= 0)
            goto err;
        if (cst->type == V_OCSP_CERTSTATUS_REVOKED) {
            rev = cst->value.revoked;
            if (VR_BIO_printf(bp, "\n    Revocation Time: ") <= 0)
                goto err;
            if (!VR_ASN1_GENERALIZEDTIME_print(bp, rev->revocationTime))
                goto err;
            if (rev->revocationReason) {
                l = VR_ASN1_ENUMERATED_get(rev->revocationReason);
                if (VR_BIO_printf(bp,
                               "\n    Revocation Reason: %s (0x%lx)",
                               VR_OCSP_crl_reason_str(l), l) <= 0)
                    goto err;
            }
        }
        if (VR_BIO_printf(bp, "\n    This Update: ") <= 0)
            goto err;
        if (!VR_ASN1_GENERALIZEDTIME_print(bp, single->thisUpdate))
            goto err;
        if (single->nextUpdate) {
            if (VR_BIO_printf(bp, "\n    Next Update: ") <= 0)
                goto err;
            if (!VR_ASN1_GENERALIZEDTIME_print(bp, single->nextUpdate))
                goto err;
        }
        if (VR_BIO_write(bp, "\n", 1) <= 0)
            goto err;
        if (!VR_X509V3_extensions_print(bp,
                                     "Response Single Extensions",
                                     single->singleExtensions, flags, 8))
            goto err;
        if (VR_BIO_write(bp, "\n", 1) <= 0)
            goto err;
    }
    if (!VR_X509V3_extensions_print(bp, "Response Extensions",
                                 rd->responseExtensions, flags, 4))
        goto err;
    if (VR_X509_signature_print(bp, &br->signatureAlgorithm, br->signature) <= 0)
        goto err;

    for (i = 0; i < sk_X509_num(br->certs); i++) {
        VR_X509_print(bp, sk_X509_value(br->certs, i));
        VR_PEM_write_bio_X509(bp, sk_X509_value(br->certs, i));
    }

    ret = 1;
 err:
    VR_OCSP_BASICRESP_free(br);
    return ret;
}
