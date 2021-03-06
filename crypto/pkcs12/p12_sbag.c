/*
 * Copyright 1999-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/pkcs12.h>
#include "p12_lcl.h"

#if !OPENSSL_API_1_1_0
ASN1_TYPE *VR_PKCS12_get_attr(const PKCS12_SAFEBAG *bag, int attr_nid)
{
    return VR_PKCS12_get_attr_gen(bag->attrib, attr_nid);
}
#endif

const ASN1_TYPE *VR_PKCS12_SAFEBAG_get0_attr(const PKCS12_SAFEBAG *bag,
                                          int attr_nid)
{
    return VR_PKCS12_get_attr_gen(bag->attrib, attr_nid);
}

ASN1_TYPE *VR_PKCS8_get_attr(PKCS8_PRIV_KEY_INFO *p8, int attr_nid)
{
    return VR_PKCS12_get_attr_gen(VR_PKCS8_pkey_get0_attrs(p8), attr_nid);
}

const PKCS8_PRIV_KEY_INFO *VR_PKCS12_SAFEBAG_get0_p8inf(const PKCS12_SAFEBAG *bag)
{
    if (VR_PKCS12_SAFEBAG_get_nid(bag) != NID_keyBag)
        return NULL;
    return bag->value.keybag;
}

const X509_SIG *VR_PKCS12_SAFEBAG_get0_pkcs8(const PKCS12_SAFEBAG *bag)
{
    if (VR_OBJ_obj2nid(bag->type) != NID_pkcs8ShroudedKeyBag)
        return NULL;
    return bag->value.shkeybag;
}

const STACK_OF(PKCS12_SAFEBAG) *
VR_PKCS12_SAFEBAG_get0_safes(const PKCS12_SAFEBAG *bag)
{
    if (VR_OBJ_obj2nid(bag->type) != NID_safeContentsBag)
        return NULL;
    return bag->value.safes;
}

const ASN1_OBJECT *VR_PKCS12_SAFEBAG_get0_type(const PKCS12_SAFEBAG *bag)
{
    return bag->type;
}

int VR_PKCS12_SAFEBAG_get_nid(const PKCS12_SAFEBAG *bag)
{
    return VR_OBJ_obj2nid(bag->type);
}

int VR_PKCS12_SAFEBAG_get_bag_nid(const PKCS12_SAFEBAG *bag)
{
    int btype = VR_PKCS12_SAFEBAG_get_nid(bag);

    if (btype != NID_certBag && btype != NID_crlBag && btype != NID_secretBag)
        return -1;
    return VR_OBJ_obj2nid(bag->value.bag->type);
}

X509 *VR_PKCS12_SAFEBAG_get1_cert(const PKCS12_SAFEBAG *bag)
{
    if (VR_PKCS12_SAFEBAG_get_nid(bag) != NID_certBag)
        return NULL;
    if (VR_OBJ_obj2nid(bag->value.bag->type) != NID_x509Certificate)
        return NULL;
    return VR_ASN1_item_unpack(bag->value.bag->value.octet,
                            ASN1_ITEM_rptr(X509));
}

X509_CRL *VR_PKCS12_SAFEBAG_get1_crl(const PKCS12_SAFEBAG *bag)
{
    if (VR_PKCS12_SAFEBAG_get_nid(bag) != NID_crlBag)
        return NULL;
    if (VR_OBJ_obj2nid(bag->value.bag->type) != NID_x509Crl)
        return NULL;
    return VR_ASN1_item_unpack(bag->value.bag->value.octet,
                            ASN1_ITEM_rptr(X509_CRL));
}

PKCS12_SAFEBAG *VR_PKCS12_SAFEBAG_create_cert(X509 *x509)
{
    return VR_PKCS12_item_pack_safebag(x509, ASN1_ITEM_rptr(X509),
                                    NID_x509Certificate, NID_certBag);
}

PKCS12_SAFEBAG *VR_PKCS12_SAFEBAG_create_crl(X509_CRL *crl)
{
    return VR_PKCS12_item_pack_safebag(crl, ASN1_ITEM_rptr(X509_CRL),
                                    NID_x509Crl, NID_crlBag);
}

/* Turn PKCS8 object into a keybag */

PKCS12_SAFEBAG *VR_PKCS12_SAFEBAG_create0_p8inf(PKCS8_PRIV_KEY_INFO *p8)
{
    PKCS12_SAFEBAG *bag = VR_PKCS12_SAFEBAG_new();

    if (bag == NULL) {
        PKCS12err(PKCS12_F_PKCS12_SAFEBAG_CREATE0_P8INF, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    bag->type = VR_OBJ_nid2obj(NID_keyBag);
    bag->value.keybag = p8;
    return bag;
}

/* Turn PKCS8 object into a shrouded keybag */

PKCS12_SAFEBAG *VR_PKCS12_SAFEBAG_create0_pkcs8(X509_SIG *p8)
{
    PKCS12_SAFEBAG *bag = VR_PKCS12_SAFEBAG_new();

    /* Set up the safe bag */
    if (bag == NULL) {
        PKCS12err(PKCS12_F_PKCS12_SAFEBAG_CREATE0_PKCS8, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    bag->type = VR_OBJ_nid2obj(NID_pkcs8ShroudedKeyBag);
    bag->value.shkeybag = p8;
    return bag;
}

PKCS12_SAFEBAG *VR_PKCS12_SAFEBAG_create_pkcs8_encrypt(int pbe_nid,
                                                    const char *pass,
                                                    int passlen,
                                                    unsigned char *salt,
                                                    int saltlen, int iter,
                                                    PKCS8_PRIV_KEY_INFO *p8inf)
{
    PKCS12_SAFEBAG *bag;
    const EVP_CIPHER *pbe_ciph;
    X509_SIG *p8;

    pbe_ciph = EVP_get_cipherbynid(pbe_nid);
    if (pbe_ciph)
        pbe_nid = -1;

    p8 = VR_PKCS8_encrypt(pbe_nid, pbe_ciph, pass, passlen, salt, saltlen, iter,
                       p8inf);
    if (p8 == NULL)
        return NULL;

    bag = VR_PKCS12_SAFEBAG_create0_pkcs8(p8);
    if (bag == NULL)
        VR_X509_SIG_free(p8);

    return bag;
}
