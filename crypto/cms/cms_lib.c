/*
 * Copyright 2008-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/asn1t.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/cms.h>
#include "cms_lcl.h"

IMPLEMENT_ASN1_FUNCTIONS(CMS_ContentInfo)
IMPLEMENT_ASN1_PRINT_FUNCTION(CMS_ContentInfo)

const ASN1_OBJECT *VR_CMS_get0_type(const CMS_ContentInfo *cms)
{
    return cms->contentType;
}

CMS_ContentInfo *VR_cms_Data_create(void)
{
    CMS_ContentInfo *cms;
    cms = VR_CMS_ContentInfo_new();
    if (cms != NULL) {
        cms->contentType = VR_OBJ_nid2obj(NID_pkcs7_data);
        /* Never detached */
        VR_CMS_set_detached(cms, 0);
    }
    return cms;
}

BIO *VR_cms_content_bio(CMS_ContentInfo *cms)
{
    ASN1_OCTET_STRING **pos = VR_CMS_get0_content(cms);
    if (!pos)
        return NULL;
    /* If content detached data goes nowhere: create NULL BIO */
    if (!*pos)
        return VR_BIO_new(VR_BIO_s_null());
    /*
     * If content not detached and created return memory BIO
     */
    if (!*pos || ((*pos)->flags == ASN1_STRING_FLAG_CONT))
        return VR_BIO_new(VR_BIO_s_mem());
    /* Else content was read in: return read only BIO for it */
    return VR_BIO_new_mem_buf((*pos)->data, (*pos)->length);
}

BIO *VR_CMS_dataInit(CMS_ContentInfo *cms, BIO *icont)
{
    BIO *cmsbio, *cont;
    if (icont)
        cont = icont;
    else
        cont = VR_cms_content_bio(cms);
    if (!cont) {
        CMSerr(CMS_F_CMS_DATAINIT, CMS_R_NO_CONTENT);
        return NULL;
    }
    switch (VR_OBJ_obj2nid(cms->contentType)) {

    case NID_pkcs7_data:
        return cont;

    case NID_pkcs7_signed:
        cmsbio = VR_cms_SignedData_init_bio(cms);
        break;

    case NID_pkcs7_digest:
        cmsbio = VR_cms_DigestedData_init_bio(cms);
        break;
#ifdef ZLIB
    case NID_id_smime_ct_compressedData:
        cmsbio = cms_CompressedData_init_bio(cms);
        break;
#endif

    case NID_pkcs7_encrypted:
        cmsbio = VR_cms_EncryptedData_init_bio(cms);
        break;

    case NID_pkcs7_enveloped:
        cmsbio = VR_cms_EnvelopedData_init_bio(cms);
        break;

    default:
        CMSerr(CMS_F_CMS_DATAINIT, CMS_R_UNSUPPORTED_TYPE);
        return NULL;
    }

    if (cmsbio)
        return VR_BIO_push(cmsbio, cont);

    if (!icont)
        VR_BIO_free(cont);
    return NULL;

}

int VR_CMS_dataFinal(CMS_ContentInfo *cms, BIO *cmsbio)
{
    ASN1_OCTET_STRING **pos = VR_CMS_get0_content(cms);
    if (!pos)
        return 0;
    /* If embedded content find memory BIO and set content */
    if (*pos && ((*pos)->flags & ASN1_STRING_FLAG_CONT)) {
        BIO *mbio;
        unsigned char *cont;
        long contlen;
        mbio = VR_BIO_find_type(cmsbio, BIO_TYPE_MEM);
        if (!mbio) {
            CMSerr(CMS_F_CMS_DATAFINAL, CMS_R_CONTENT_NOT_FOUND);
            return 0;
        }
        contlen = BIO_get_mem_data(mbio, &cont);
        /* Set bio as read only so its content can't be clobbered */
        VR_BIO_set_flags(mbio, BIO_FLAGS_MEM_RDONLY);
        BIO_set_mem_eof_return(mbio, 0);
        VR_ASN1_STRING_set0(*pos, cont, contlen);
        (*pos)->flags &= ~ASN1_STRING_FLAG_CONT;
    }

    switch (VR_OBJ_obj2nid(cms->contentType)) {

    case NID_pkcs7_data:
    case NID_pkcs7_enveloped:
    case NID_pkcs7_encrypted:
    case NID_id_smime_ct_compressedData:
        /* Nothing to do */
        return 1;

    case NID_pkcs7_signed:
        return VR_cms_SignedData_final(cms, cmsbio);

    case NID_pkcs7_digest:
        return VR_cms_DigestedData_do_final(cms, cmsbio, 0);

    default:
        CMSerr(CMS_F_CMS_DATAFINAL, CMS_R_UNSUPPORTED_TYPE);
        return 0;
    }
}

/*
 * Return an OCTET STRING pointer to content. This allows it to be accessed
 * or set later.
 */

ASN1_OCTET_STRING **VR_CMS_get0_content(CMS_ContentInfo *cms)
{
    switch (VR_OBJ_obj2nid(cms->contentType)) {

    case NID_pkcs7_data:
        return &cms->d.data;

    case NID_pkcs7_signed:
        return &cms->d.signedData->encapContentInfo->eContent;

    case NID_pkcs7_enveloped:
        return &cms->d.envelopedData->encryptedContentInfo->encryptedContent;

    case NID_pkcs7_digest:
        return &cms->d.digestedData->encapContentInfo->eContent;

    case NID_pkcs7_encrypted:
        return &cms->d.encryptedData->encryptedContentInfo->encryptedContent;

    case NID_id_smime_ct_authData:
        return &cms->d.authenticatedData->encapContentInfo->eContent;

    case NID_id_smime_ct_compressedData:
        return &cms->d.compressedData->encapContentInfo->eContent;

    default:
        if (cms->d.other->type == V_ASN1_OCTET_STRING)
            return &cms->d.other->value.octet_string;
        CMSerr(CMS_F_CMS_GET0_CONTENT, CMS_R_UNSUPPORTED_CONTENT_TYPE);
        return NULL;

    }
}

/*
 * Return an ASN1_OBJECT pointer to content type. This allows it to be
 * accessed or set later.
 */

static ASN1_OBJECT **cms_get0_econtent_type(CMS_ContentInfo *cms)
{
    switch (VR_OBJ_obj2nid(cms->contentType)) {

    case NID_pkcs7_signed:
        return &cms->d.signedData->encapContentInfo->eContentType;

    case NID_pkcs7_enveloped:
        return &cms->d.envelopedData->encryptedContentInfo->contentType;

    case NID_pkcs7_digest:
        return &cms->d.digestedData->encapContentInfo->eContentType;

    case NID_pkcs7_encrypted:
        return &cms->d.encryptedData->encryptedContentInfo->contentType;

    case NID_id_smime_ct_authData:
        return &cms->d.authenticatedData->encapContentInfo->eContentType;

    case NID_id_smime_ct_compressedData:
        return &cms->d.compressedData->encapContentInfo->eContentType;

    default:
        CMSerr(CMS_F_CMS_GET0_ECONTENT_TYPE, CMS_R_UNSUPPORTED_CONTENT_TYPE);
        return NULL;

    }
}

const ASN1_OBJECT *VR_CMS_get0_eContentType(CMS_ContentInfo *cms)
{
    ASN1_OBJECT **petype;
    petype = cms_get0_econtent_type(cms);
    if (petype)
        return *petype;
    return NULL;
}

int VR_CMS_set1_eContentType(CMS_ContentInfo *cms, const ASN1_OBJECT *oid)
{
    ASN1_OBJECT **petype, *etype;
    petype = cms_get0_econtent_type(cms);
    if (!petype)
        return 0;
    if (!oid)
        return 1;
    etype = VR_OBJ_dup(oid);
    if (!etype)
        return 0;
    VR_ASN1_OBJECT_free(*petype);
    *petype = etype;
    return 1;
}

int VR_CMS_is_detached(CMS_ContentInfo *cms)
{
    ASN1_OCTET_STRING **pos;
    pos = VR_CMS_get0_content(cms);
    if (!pos)
        return -1;
    if (*pos)
        return 0;
    return 1;
}

int VR_CMS_set_detached(CMS_ContentInfo *cms, int detached)
{
    ASN1_OCTET_STRING **pos;
    pos = VR_CMS_get0_content(cms);
    if (!pos)
        return 0;
    if (detached) {
        VR_ASN1_OCTET_STRING_free(*pos);
        *pos = NULL;
        return 1;
    }
    if (*pos == NULL)
        *pos = VR_ASN1_OCTET_STRING_new();
    if (*pos != NULL) {
        /*
         * NB: special flag to show content is created and not read in.
         */
        (*pos)->flags |= ASN1_STRING_FLAG_CONT;
        return 1;
    }
    CMSerr(CMS_F_CMS_SET_DETACHED, ERR_R_MALLOC_FAILURE);
    return 0;
}

/* Create a digest BIO from an X509_ALGOR structure */

BIO *VR_cms_DigestAlgorithm_init_bio(X509_ALGOR *digestAlgorithm)
{
    BIO *mdbio = NULL;
    const ASN1_OBJECT *digestoid;
    const EVP_MD *digest;
    VR_X509_ALGOR_get0(&digestoid, NULL, NULL, digestAlgorithm);
    digest = EVP_get_digestbyobj(digestoid);
    if (!digest) {
        CMSerr(CMS_F_CMS_DIGESTALGORITHM_INIT_BIO,
               CMS_R_UNKNOWN_DIGEST_ALGORITHM);
        goto err;
    }
    mdbio = VR_BIO_new(VR_BIO_f_md());
    if (mdbio == NULL || !BIO_set_md(mdbio, digest)) {
        CMSerr(CMS_F_CMS_DIGESTALGORITHM_INIT_BIO, CMS_R_MD_BIO_INIT_ERROR);
        goto err;
    }
    return mdbio;
 err:
    VR_BIO_free(mdbio);
    return NULL;
}

/* Locate a message digest content from a BIO chain based on SignerInfo */

int VR_cms_DigestAlgorithm_find_ctx(EVP_MD_CTX *mctx, BIO *chain,
                                 X509_ALGOR *mdalg)
{
    int nid;
    const ASN1_OBJECT *mdoid;
    VR_X509_ALGOR_get0(&mdoid, NULL, NULL, mdalg);
    nid = VR_OBJ_obj2nid(mdoid);
    /* Look for digest type to match signature */
    for (;;) {
        EVP_MD_CTX *mtmp;
        chain = VR_BIO_find_type(chain, BIO_TYPE_MD);
        if (chain == NULL) {
            CMSerr(CMS_F_CMS_DIGESTALGORITHM_FIND_CTX,
                   CMS_R_NO_MATCHING_DIGEST);
            return 0;
        }
        BIO_get_md_ctx(chain, &mtmp);
        if (EVP_MD_CTX_type(mtmp) == nid
            /*
             * Workaround for broken implementations that use signature
             * algorithm OID instead of digest.
             */
            || VR_EVP_MD_pkey_type(VR_EVP_MD_CTX_md(mtmp)) == nid)
            return VR_EVP_MD_CTX_copy_ex(mctx, mtmp);
        chain = VR_BIO_next(chain);
    }
}

static STACK_OF(CMS_CertificateChoices)
**cms_get0_certificate_choices(CMS_ContentInfo *cms)
{
    switch (VR_OBJ_obj2nid(cms->contentType)) {

    case NID_pkcs7_signed:
        return &cms->d.signedData->certificates;

    case NID_pkcs7_enveloped:
        if (cms->d.envelopedData->originatorInfo == NULL)
            return NULL;
        return &cms->d.envelopedData->originatorInfo->certificates;

    default:
        CMSerr(CMS_F_CMS_GET0_CERTIFICATE_CHOICES,
               CMS_R_UNSUPPORTED_CONTENT_TYPE);
        return NULL;

    }
}

CMS_CertificateChoices *VR_CMS_add0_CertificateChoices(CMS_ContentInfo *cms)
{
    STACK_OF(CMS_CertificateChoices) **pcerts;
    CMS_CertificateChoices *cch;
    pcerts = cms_get0_certificate_choices(cms);
    if (!pcerts)
        return NULL;
    if (!*pcerts)
        *pcerts = sk_VR_CMS_CertificateChoices_new_null();
    if (!*pcerts)
        return NULL;
    cch = M_ASN1_new_of(CMS_CertificateChoices);
    if (!cch)
        return NULL;
    if (!sk_VR_CMS_CertificateChoices_push(*pcerts, cch)) {
        M_ASN1_free_of(cch, CMS_CertificateChoices);
        return NULL;
    }
    return cch;
}

int VR_CMS_add0_cert(CMS_ContentInfo *cms, X509 *cert)
{
    CMS_CertificateChoices *cch;
    STACK_OF(CMS_CertificateChoices) **pcerts;
    int i;
    pcerts = cms_get0_certificate_choices(cms);
    if (!pcerts)
        return 0;
    for (i = 0; i < sk_CMS_CertificateChoices_num(*pcerts); i++) {
        cch = sk_CMS_CertificateChoices_value(*pcerts, i);
        if (cch->type == CMS_CERTCHOICE_CERT) {
            if (!VR_X509_cmp(cch->d.certificate, cert)) {
                CMSerr(CMS_F_CMS_ADD0_CERT,
                       CMS_R_CERTIFICATE_ALREADY_PRESENT);
                return 0;
            }
        }
    }
    cch = VR_CMS_add0_CertificateChoices(cms);
    if (!cch)
        return 0;
    cch->type = CMS_CERTCHOICE_CERT;
    cch->d.certificate = cert;
    return 1;
}

int VR_CMS_add1_cert(CMS_ContentInfo *cms, X509 *cert)
{
    int r;
    r = VR_CMS_add0_cert(cms, cert);
    if (r > 0)
        VR_X509_up_ref(cert);
    return r;
}

static STACK_OF(CMS_RevocationInfoChoice)
**cms_get0_revocation_choices(CMS_ContentInfo *cms)
{
    switch (VR_OBJ_obj2nid(cms->contentType)) {

    case NID_pkcs7_signed:
        return &cms->d.signedData->crls;

    case NID_pkcs7_enveloped:
        if (cms->d.envelopedData->originatorInfo == NULL)
            return NULL;
        return &cms->d.envelopedData->originatorInfo->crls;

    default:
        CMSerr(CMS_F_CMS_GET0_REVOCATION_CHOICES,
               CMS_R_UNSUPPORTED_CONTENT_TYPE);
        return NULL;

    }
}

CMS_RevocationInfoChoice *VR_CMS_add0_RevocationInfoChoice(CMS_ContentInfo *cms)
{
    STACK_OF(CMS_RevocationInfoChoice) **pcrls;
    CMS_RevocationInfoChoice *rch;
    pcrls = cms_get0_revocation_choices(cms);
    if (!pcrls)
        return NULL;
    if (!*pcrls)
        *pcrls = sk_VR_CMS_RevocationInfoChoice_new_null();
    if (!*pcrls)
        return NULL;
    rch = M_ASN1_new_of(CMS_RevocationInfoChoice);
    if (!rch)
        return NULL;
    if (!sk_VR_CMS_RevocationInfoChoice_push(*pcrls, rch)) {
        M_ASN1_free_of(rch, CMS_RevocationInfoChoice);
        return NULL;
    }
    return rch;
}

int VR_CMS_add0_crl(CMS_ContentInfo *cms, X509_CRL *crl)
{
    CMS_RevocationInfoChoice *rch;
    rch = VR_CMS_add0_RevocationInfoChoice(cms);
    if (!rch)
        return 0;
    rch->type = CMS_REVCHOICE_CRL;
    rch->d.crl = crl;
    return 1;
}

int VR_CMS_add1_crl(CMS_ContentInfo *cms, X509_CRL *crl)
{
    int r;
    r = VR_CMS_add0_crl(cms, crl);
    if (r > 0)
        VR_X509_CRL_up_ref(crl);
    return r;
}

STACK_OF(X509) *VR_CMS_get1_certs(CMS_ContentInfo *cms)
{
    STACK_OF(X509) *certs = NULL;
    CMS_CertificateChoices *cch;
    STACK_OF(CMS_CertificateChoices) **pcerts;
    int i;
    pcerts = cms_get0_certificate_choices(cms);
    if (!pcerts)
        return NULL;
    for (i = 0; i < sk_CMS_CertificateChoices_num(*pcerts); i++) {
        cch = sk_CMS_CertificateChoices_value(*pcerts, i);
        if (cch->type == 0) {
            if (!certs) {
                certs = sk_VR_X509_new_null();
                if (!certs)
                    return NULL;
            }
            if (!sk_VR_X509_push(certs, cch->d.certificate)) {
                sk_VR_X509_pop_free(certs, VR_X509_free);
                return NULL;
            }
            VR_X509_up_ref(cch->d.certificate);
        }
    }
    return certs;

}

STACK_OF(X509_CRL) *VR_CMS_get1_crls(CMS_ContentInfo *cms)
{
    STACK_OF(X509_CRL) *crls = NULL;
    STACK_OF(CMS_RevocationInfoChoice) **pcrls;
    CMS_RevocationInfoChoice *rch;
    int i;
    pcrls = cms_get0_revocation_choices(cms);
    if (!pcrls)
        return NULL;
    for (i = 0; i < sk_CMS_RevocationInfoChoice_num(*pcrls); i++) {
        rch = sk_CMS_RevocationInfoChoice_value(*pcrls, i);
        if (rch->type == 0) {
            if (!crls) {
                crls = sk_VR_X509_CRL_new_null();
                if (!crls)
                    return NULL;
            }
            if (!sk_VR_X509_CRL_push(crls, rch->d.crl)) {
                sk_VR_X509_CRL_pop_free(crls, VR_X509_CRL_free);
                return NULL;
            }
            VR_X509_CRL_up_ref(rch->d.crl);
        }
    }
    return crls;
}

int VR_cms_ias_cert_cmp(CMS_IssuerAndSerialNumber *ias, X509 *cert)
{
    int ret;
    ret = VR_X509_NAME_cmp(ias->issuer, VR_X509_get_issuer_name(cert));
    if (ret)
        return ret;
    return VR_ASN1_INTEGER_cmp(ias->serialNumber, VR_X509_get_serialNumber(cert));
}

int VR_cms_keyid_cert_cmp(ASN1_OCTET_STRING *keyid, X509 *cert)
{
    const ASN1_OCTET_STRING *cert_keyid = VR_X509_get0_subject_key_id(cert);

    if (cert_keyid == NULL)
        return -1;
    return VR_ASN1_OCTET_STRING_cmp(keyid, cert_keyid);
}

int VR_cms_set1_ias(CMS_IssuerAndSerialNumber **pias, X509 *cert)
{
    CMS_IssuerAndSerialNumber *ias;
    ias = M_ASN1_new_of(CMS_IssuerAndSerialNumber);
    if (!ias)
        goto err;
    if (!VR_X509_NAME_set(&ias->issuer, VR_X509_get_issuer_name(cert)))
        goto err;
    if (!VR_ASN1_STRING_copy(ias->serialNumber, VR_X509_get_serialNumber(cert)))
        goto err;
    M_ASN1_free_of(*pias, CMS_IssuerAndSerialNumber);
    *pias = ias;
    return 1;
 err:
    M_ASN1_free_of(ias, CMS_IssuerAndSerialNumber);
    CMSerr(CMS_F_CMS_SET1_IAS, ERR_R_MALLOC_FAILURE);
    return 0;
}

int VR_cms_set1_keyid(ASN1_OCTET_STRING **pkeyid, X509 *cert)
{
    ASN1_OCTET_STRING *keyid = NULL;
    const ASN1_OCTET_STRING *cert_keyid;
    cert_keyid = VR_X509_get0_subject_key_id(cert);
    if (cert_keyid == NULL) {
        CMSerr(CMS_F_CMS_SET1_KEYID, CMS_R_CERTIFICATE_HAS_NO_KEYID);
        return 0;
    }
    keyid = VR_ASN1_STRING_dup(cert_keyid);
    if (!keyid) {
        CMSerr(CMS_F_CMS_SET1_KEYID, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    VR_ASN1_OCTET_STRING_free(*pkeyid);
    *pkeyid = keyid;
    return 1;
}
