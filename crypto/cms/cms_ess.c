/*
 * Copyright 2008-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/cms.h>
#include <openssl/ess.h>
#include "cms_lcl.h"
#include "internal/ess_int.h"

IMPLEMENT_ASN1_FUNCTIONS(CMS_ReceiptRequest)

/* ESS services */

int VR_CMS_get1_ReceiptRequest(CMS_SignerInfo *si, CMS_ReceiptRequest **prr)
{
    ASN1_STRING *str;
    CMS_ReceiptRequest *rr = NULL;
    if (prr)
        *prr = NULL;
    str = VR_CMS_signed_get0_data_by_OBJ(si,
                                      VR_OBJ_nid2obj
                                      (NID_id_smime_aa_receiptRequest), -3,
                                      V_ASN1_SEQUENCE);
    if (!str)
        return 0;

    rr = VR_ASN1_item_unpack(str, ASN1_ITEM_rptr(CMS_ReceiptRequest));
    if (!rr)
        return -1;
    if (prr)
        *prr = rr;
    else
        VR_CMS_ReceiptRequest_free(rr);
    return 1;
}

CMS_ReceiptRequest *VR_CMS_ReceiptRequest_create0(unsigned char *id, int idlen,
                                               int allorfirst,
                                               STACK_OF(GENERAL_NAMES)
                                               *receiptList, STACK_OF(GENERAL_NAMES)
                                               *receiptsTo)
{
    CMS_ReceiptRequest *rr = NULL;

    rr = VR_CMS_ReceiptRequest_new();
    if (rr == NULL)
        goto merr;
    if (id)
        VR_ASN1_STRING_set0(rr->signedContentIdentifier, id, idlen);
    else {
        if (!VR_ASN1_STRING_set(rr->signedContentIdentifier, NULL, 32))
            goto merr;
        if (VR_RAND_bytes(rr->signedContentIdentifier->data, 32) <= 0)
            goto err;
    }

    sk_VR_GENERAL_NAMES_pop_free(rr->receiptsTo, VR_GENERAL_NAMES_free);
    rr->receiptsTo = receiptsTo;

    if (receiptList) {
        rr->receiptsFrom->type = 1;
        rr->receiptsFrom->d.receiptList = receiptList;
    } else {
        rr->receiptsFrom->type = 0;
        rr->receiptsFrom->d.allOrFirstTier = allorfirst;
    }

    return rr;

 merr:
    CMSerr(CMS_F_CMS_RECEIPTREQUEST_CREATE0, ERR_R_MALLOC_FAILURE);

 err:
    VR_CMS_ReceiptRequest_free(rr);
    return NULL;

}

int VR_CMS_add1_ReceiptRequest(CMS_SignerInfo *si, CMS_ReceiptRequest *rr)
{
    unsigned char *rrder = NULL;
    int rrderlen, r = 0;

    rrderlen = VR_i2d_CMS_ReceiptRequest(rr, &rrder);
    if (rrderlen < 0)
        goto merr;

    if (!VR_CMS_signed_add1_attr_by_NID(si, NID_id_smime_aa_receiptRequest,
                                     V_ASN1_SEQUENCE, rrder, rrderlen))
        goto merr;

    r = 1;

 merr:
    if (!r)
        CMSerr(CMS_F_CMS_ADD1_RECEIPTREQUEST, ERR_R_MALLOC_FAILURE);

    VR_OPENSSL_free(rrder);

    return r;

}

void VR_CMS_ReceiptRequest_get0_values(CMS_ReceiptRequest *rr,
                                    ASN1_STRING **pcid,
                                    int *pallorfirst,
                                    STACK_OF(GENERAL_NAMES) **plist,
                                    STACK_OF(GENERAL_NAMES) **prto)
{
    if (pcid)
        *pcid = rr->signedContentIdentifier;
    if (rr->receiptsFrom->type == 0) {
        if (pallorfirst)
            *pallorfirst = (int)rr->receiptsFrom->d.allOrFirstTier;
        if (plist)
            *plist = NULL;
    } else {
        if (pallorfirst)
            *pallorfirst = -1;
        if (plist)
            *plist = rr->receiptsFrom->d.receiptList;
    }
    if (prto)
        *prto = rr->receiptsTo;
}

/* Digest a SignerInfo structure for msgSigDigest attribute processing */

static int cms_msgSigDigest(CMS_SignerInfo *si,
                            unsigned char *dig, unsigned int *diglen)
{
    const EVP_MD *md;
    md = EVP_get_digestbyobj(si->digestAlgorithm->algorithm);
    if (md == NULL)
        return 0;
    if (!VR_ASN1_item_digest(ASN1_ITEM_rptr(CMS_Attributes_Verify), md,
                          si->signedAttrs, dig, diglen))
        return 0;
    return 1;
}

/* Add a msgSigDigest attribute to a SignerInfo */

int VR_cms_msgSigDigest_add1(CMS_SignerInfo *dest, CMS_SignerInfo *src)
{
    unsigned char dig[EVP_MAX_MD_SIZE];
    unsigned int diglen;
    if (!cms_msgSigDigest(src, dig, &diglen)) {
        CMSerr(CMS_F_CMS_MSGSIGDIGEST_ADD1, CMS_R_MSGSIGDIGEST_ERROR);
        return 0;
    }
    if (!VR_CMS_signed_add1_attr_by_NID(dest, NID_id_smime_aa_msgSigDigest,
                                     V_ASN1_OCTET_STRING, dig, diglen)) {
        CMSerr(CMS_F_CMS_MSGSIGDIGEST_ADD1, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

/* Verify signed receipt after it has already passed normal CMS verify */

int VR_cms_Receipt_verify(CMS_ContentInfo *cms, CMS_ContentInfo *req_cms)
{
    int r = 0, i;
    CMS_ReceiptRequest *rr = NULL;
    CMS_Receipt *rct = NULL;
    STACK_OF(CMS_SignerInfo) *sis, *osis;
    CMS_SignerInfo *si, *osi = NULL;
    ASN1_OCTET_STRING *msig, **pcont;
    ASN1_OBJECT *octype;
    unsigned char dig[EVP_MAX_MD_SIZE];
    unsigned int diglen;

    /* Get SignerInfos, also checks SignedData content type */
    osis = VR_CMS_get0_SignerInfos(req_cms);
    sis = VR_CMS_get0_SignerInfos(cms);
    if (!osis || !sis)
        goto err;

    if (sk_CMS_SignerInfo_num(sis) != 1) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY, CMS_R_NEED_ONE_SIGNER);
        goto err;
    }

    /* Check receipt content type */
    if (VR_OBJ_obj2nid(VR_CMS_get0_eContentType(cms)) != NID_id_smime_ct_receipt) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY, CMS_R_NOT_A_SIGNED_RECEIPT);
        goto err;
    }

    /* Extract and decode receipt content */
    pcont = VR_CMS_get0_content(cms);
    if (!pcont || !*pcont) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY, CMS_R_NO_CONTENT);
        goto err;
    }

    rct = VR_ASN1_item_unpack(*pcont, ASN1_ITEM_rptr(CMS_Receipt));

    if (!rct) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY, CMS_R_RECEIPT_DECODE_ERROR);
        goto err;
    }

    /* Locate original request */

    for (i = 0; i < sk_CMS_SignerInfo_num(osis); i++) {
        osi = sk_CMS_SignerInfo_value(osis, i);
        if (!VR_ASN1_STRING_cmp(osi->signature, rct->originatorSignatureValue))
            break;
    }

    if (i == sk_CMS_SignerInfo_num(osis)) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY, CMS_R_NO_MATCHING_SIGNATURE);
        goto err;
    }

    si = sk_CMS_SignerInfo_value(sis, 0);

    /* Get msgSigDigest value and compare */

    msig = VR_CMS_signed_get0_data_by_OBJ(si,
                                       VR_OBJ_nid2obj
                                       (NID_id_smime_aa_msgSigDigest), -3,
                                       V_ASN1_OCTET_STRING);

    if (!msig) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY, CMS_R_NO_MSGSIGDIGEST);
        goto err;
    }

    if (!cms_msgSigDigest(osi, dig, &diglen)) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY, CMS_R_MSGSIGDIGEST_ERROR);
        goto err;
    }

    if (diglen != (unsigned int)msig->length) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY, CMS_R_MSGSIGDIGEST_WRONG_LENGTH);
        goto err;
    }

    if (memcmp(dig, msig->data, diglen)) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY,
               CMS_R_MSGSIGDIGEST_VERIFICATION_FAILURE);
        goto err;
    }

    /* Compare content types */

    octype = VR_CMS_signed_get0_data_by_OBJ(osi,
                                         VR_OBJ_nid2obj(NID_pkcs9_contentType),
                                         -3, V_ASN1_OBJECT);
    if (!octype) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY, CMS_R_NO_CONTENT_TYPE);
        goto err;
    }

    /* Compare details in receipt request */

    if (VR_OBJ_cmp(octype, rct->contentType)) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY, CMS_R_CONTENT_TYPE_MISMATCH);
        goto err;
    }

    /* Get original receipt request details */

    if (VR_CMS_get1_ReceiptRequest(osi, &rr) <= 0) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY, CMS_R_NO_RECEIPT_REQUEST);
        goto err;
    }

    if (VR_ASN1_STRING_cmp(rr->signedContentIdentifier,
                        rct->signedContentIdentifier)) {
        CMSerr(CMS_F_CMS_RECEIPT_VERIFY, CMS_R_CONTENTIDENTIFIER_MISMATCH);
        goto err;
    }

    r = 1;

 err:
    VR_CMS_ReceiptRequest_free(rr);
    M_ASN1_free_of(rct, CMS_Receipt);
    return r;

}

/*
 * Encode a Receipt into an OCTET STRING read for including into content of a
 * SignedData ContentInfo.
 */

ASN1_OCTET_STRING *VR_cms_encode_Receipt(CMS_SignerInfo *si)
{
    CMS_Receipt rct;
    CMS_ReceiptRequest *rr = NULL;
    ASN1_OBJECT *ctype;
    ASN1_OCTET_STRING *os = NULL;

    /* Get original receipt request */

    /* Get original receipt request details */

    if (VR_CMS_get1_ReceiptRequest(si, &rr) <= 0) {
        CMSerr(CMS_F_CMS_ENCODE_RECEIPT, CMS_R_NO_RECEIPT_REQUEST);
        goto err;
    }

    /* Get original content type */

    ctype = VR_CMS_signed_get0_data_by_OBJ(si,
                                        VR_OBJ_nid2obj(NID_pkcs9_contentType),
                                        -3, V_ASN1_OBJECT);
    if (!ctype) {
        CMSerr(CMS_F_CMS_ENCODE_RECEIPT, CMS_R_NO_CONTENT_TYPE);
        goto err;
    }

    rct.version = 1;
    rct.contentType = ctype;
    rct.signedContentIdentifier = rr->signedContentIdentifier;
    rct.originatorSignatureValue = si->signature;

    os = VR_ASN1_item_pack(&rct, ASN1_ITEM_rptr(CMS_Receipt), NULL);

 err:
    VR_CMS_ReceiptRequest_free(rr);
    return os;
}

/*
 * Add signer certificate's V2 digest to a SignerInfo
 * structure
 */

int VR_CMS_add1_signing_cert_v2(CMS_SignerInfo *si,
                             ESS_SIGNING_CERT_V2 *sc)
{
    ASN1_STRING *seq = NULL;
    unsigned char *p, *pp;
    int len;

    /* Add SigningCertificateV2 signed attribute to the signer info. */
    len = VR_i2d_ESS_SIGNING_CERT_V2(sc, NULL);
    if ((pp = OPENSSL_malloc(len)) == NULL)
        goto err;
    p = pp;
    VR_i2d_ESS_SIGNING_CERT_V2(sc, &p);
    if (!(seq = VR_ASN1_STRING_new()) || !VR_ASN1_STRING_set(seq, pp, len))
        goto err;
    VR_OPENSSL_free(pp);
    pp = NULL;
    if (!VR_CMS_signed_add1_attr_by_NID(si, NID_id_smime_aa_signingCertificateV2,
                                     V_ASN1_SEQUENCE, seq, -1))
        goto err;
    VR_ASN1_STRING_free(seq);
    return 1;
 err:
    CMSerr(CMS_F_CMS_ADD1_SIGNING_CERT_V2, ERR_R_MALLOC_FAILURE);
    VR_ASN1_STRING_free(seq);
    VR_OPENSSL_free(pp);
    return 0;
}

/*
 * Add signer certificate's digest to a SignerInfo
 * structure
 */

int VR_CMS_add1_signing_cert(CMS_SignerInfo *si, ESS_SIGNING_CERT *sc)
{
    ASN1_STRING *seq = NULL;
    unsigned char *p, *pp;
    int len;

    /* Add SigningCertificate signed attribute to the signer info. */
    len = VR_i2d_ESS_SIGNING_CERT(sc, NULL);
    if ((pp = OPENSSL_malloc(len)) == NULL)
        goto err;
    p = pp;
    VR_i2d_ESS_SIGNING_CERT(sc, &p);
    if (!(seq = VR_ASN1_STRING_new()) || !VR_ASN1_STRING_set(seq, pp, len))
        goto err;
    VR_OPENSSL_free(pp);
    pp = NULL;
    if (!VR_CMS_signed_add1_attr_by_NID(si, NID_id_smime_aa_signingCertificate,
                                     V_ASN1_SEQUENCE, seq, -1))
        goto err;
    VR_ASN1_STRING_free(seq);
    return 1;
 err:
    CMSerr(CMS_F_CMS_ADD1_SIGNING_CERT, ERR_R_MALLOC_FAILURE);
    VR_ASN1_STRING_free(seq);
    VR_OPENSSL_free(pp);
    return 0;
}
