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
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#include "ocsp_lcl.h"
#include <openssl/asn1t.h>

/* Convert a certificate and its issuer to an OCSP_CERTID */

OCSP_CERTID *VR_OCSP_cert_to_id(const EVP_MD *dgst, const X509 *subject,
                             const X509 *issuer)
{
    X509_NAME *iname;
    const ASN1_INTEGER *serial;
    ASN1_BIT_STRING *ikey;
    if (!dgst)
        dgst = VR_EVP_sha1();
    if (subject) {
        iname = VR_X509_get_issuer_name(subject);
        serial = VR_X509_get0_serialNumber(subject);
    } else {
        iname = VR_X509_get_subject_name(issuer);
        serial = NULL;
    }
    ikey = VR_X509_get0_pubkey_bitstr(issuer);
    return VR_OCSP_cert_id_new(dgst, iname, ikey, serial);
}

OCSP_CERTID *VR_OCSP_cert_id_new(const EVP_MD *dgst,
                              const X509_NAME *issuerName,
                              const ASN1_BIT_STRING *issuerKey,
                              const ASN1_INTEGER *serialNumber)
{
    int nid;
    unsigned int i;
    X509_ALGOR *alg;
    OCSP_CERTID *cid = NULL;
    unsigned char md[EVP_MAX_MD_SIZE];

    if ((cid = VR_OCSP_CERTID_new()) == NULL)
        goto err;

    alg = &cid->hashAlgorithm;
    VR_ASN1_OBJECT_free(alg->algorithm);
    if ((nid = VR_EVP_MD_type(dgst)) == NID_undef) {
        OCSPerr(OCSP_F_OCSP_CERT_ID_NEW, OCSP_R_UNKNOWN_NID);
        goto err;
    }
    if ((alg->algorithm = VR_OBJ_nid2obj(nid)) == NULL)
        goto err;
    if ((alg->parameter = VR_ASN1_TYPE_new()) == NULL)
        goto err;
    alg->parameter->type = V_ASN1_NULL;

    if (!VR_X509_NAME_digest(issuerName, dgst, md, &i))
        goto digerr;
    if (!(VR_ASN1_OCTET_STRING_set(&cid->issuerNameHash, md, i)))
        goto err;

    /* Calculate the issuerKey hash, excluding tag and length */
    if (!VR_EVP_Digest(issuerKey->data, issuerKey->length, md, &i, dgst, NULL))
        goto err;

    if (!(VR_ASN1_OCTET_STRING_set(&cid->issuerKeyHash, md, i)))
        goto err;

    if (serialNumber) {
        if (VR_ASN1_STRING_copy(&cid->serialNumber, serialNumber) == 0)
            goto err;
    }
    return cid;
 digerr:
    OCSPerr(OCSP_F_OCSP_CERT_ID_NEW, OCSP_R_DIGEST_ERR);
 err:
    VR_OCSP_CERTID_free(cid);
    return NULL;
}

int VR_OCSP_id_issuer_cmp(OCSP_CERTID *a, OCSP_CERTID *b)
{
    int ret;
    ret = VR_OBJ_cmp(a->hashAlgorithm.algorithm, b->hashAlgorithm.algorithm);
    if (ret)
        return ret;
    ret = VR_ASN1_OCTET_STRING_cmp(&a->issuerNameHash, &b->issuerNameHash);
    if (ret)
        return ret;
    return VR_ASN1_OCTET_STRING_cmp(&a->issuerKeyHash, &b->issuerKeyHash);
}

int VR_OCSP_id_cmp(OCSP_CERTID *a, OCSP_CERTID *b)
{
    int ret;
    ret = VR_OCSP_id_issuer_cmp(a, b);
    if (ret)
        return ret;
    return VR_ASN1_INTEGER_cmp(&a->serialNumber, &b->serialNumber);
}

/*
 * Parse a URL and split it up into host, port and path components and
 * whether it is SSL.
 */

int VR_OCSP_parse_url(const char *url, char **phost, char **pport, char **ppath,
                   int *pssl)
{
    char *p, *buf;

    char *host, *port;

    *phost = NULL;
    *pport = NULL;
    *ppath = NULL;

    /* dup the buffer since we are going to mess with it */
    buf = OPENSSL_strdup(url);
    if (!buf)
        goto mem_err;

    /* Check for initial colon */
    p = strchr(buf, ':');

    if (!p)
        goto parse_err;

    *(p++) = '\0';

    if (strcmp(buf, "http") == 0) {
        *pssl = 0;
        port = "80";
    } else if (strcmp(buf, "https") == 0) {
        *pssl = 1;
        port = "443";
    } else
        goto parse_err;

    /* Check for double slash */
    if ((p[0] != '/') || (p[1] != '/'))
        goto parse_err;

    p += 2;

    host = p;

    /* Check for trailing part of path */

    p = strchr(p, '/');

    if (!p)
        *ppath = OPENSSL_strdup("/");
    else {
        *ppath = OPENSSL_strdup(p);
        /* Set start of path to 0 so hostname is valid */
        *p = '\0';
    }

    if (!*ppath)
        goto mem_err;

    p = host;
    if (host[0] == '[') {
        /* ipv6 literal */
        host++;
        p = strchr(host, ']');
        if (!p)
            goto parse_err;
        *p = '\0';
        p++;
    }

    /* Look for optional ':' for port number */
    if ((p = strchr(p, ':'))) {
        *p = 0;
        port = p + 1;
    }

    *pport = OPENSSL_strdup(port);
    if (!*pport)
        goto mem_err;

    *phost = OPENSSL_strdup(host);

    if (!*phost)
        goto mem_err;

    VR_OPENSSL_free(buf);

    return 1;

 mem_err:
    OCSPerr(OCSP_F_OCSP_PARSE_URL, ERR_R_MALLOC_FAILURE);
    goto err;

 parse_err:
    OCSPerr(OCSP_F_OCSP_PARSE_URL, OCSP_R_ERROR_PARSING_URL);

 err:
    VR_OPENSSL_free(buf);
    VR_OPENSSL_free(*ppath);
    *ppath = NULL;
    VR_OPENSSL_free(*pport);
    *pport = NULL;
    VR_OPENSSL_free(*phost);
    *phost = NULL;
    return 0;

}

IMPLEMENT_ASN1_DUP_FUNCTION(OCSP_CERTID)
