/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "internal/asn1_int.h"

#ifndef OPENSSL_NO_STDIO
int VR_X509_print_fp(FILE *fp, X509 *x)
{
    return VR_X509_print_ex_fp(fp, x, XN_FLAG_COMPAT, X509_FLAG_COMPAT);
}

int VR_X509_print_ex_fp(FILE *fp, X509 *x, unsigned long nmflag,
                     unsigned long cflag)
{
    BIO *b;
    int ret;

    if ((b = VR_BIO_new(VR_BIO_s_file())) == NULL) {
        X509err(X509_F_X509_PRINT_EX_FP, ERR_R_BUF_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = VR_X509_print_ex(b, x, nmflag, cflag);
    VR_BIO_free(b);
    return ret;
}
#endif

int VR_X509_print(BIO *bp, X509 *x)
{
    return VR_X509_print_ex(bp, x, XN_FLAG_COMPAT, X509_FLAG_COMPAT);
}

int VR_X509_print_ex(BIO *bp, X509 *x, unsigned long nmflags,
                  unsigned long cflag)
{
    long l;
    int ret = 0, i;
    char *m = NULL, mlch = ' ';
    int nmindent = 0;
    ASN1_INTEGER *bs;
    EVP_PKEY *pkey = NULL;
    const char *neg;

    if ((nmflags & XN_FLAG_SEP_MASK) == XN_FLAG_SEP_MULTILINE) {
        mlch = '\n';
        nmindent = 12;
    }

    if (nmflags == X509_FLAG_COMPAT)
        nmindent = 16;

    if (!(cflag & X509_FLAG_NO_HEADER)) {
        if (VR_BIO_write(bp, "Certificate:\n", 13) <= 0)
            goto err;
        if (VR_BIO_write(bp, "    Data:\n", 10) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_VERSION)) {
        l = VR_X509_get_version(x);
        if (l >= 0 && l <= 2) {
            if (VR_BIO_printf(bp, "%8sVersion: %ld (0x%lx)\n", "", l + 1, (unsigned long)l) <= 0)
                goto err;
        } else {
            if (VR_BIO_printf(bp, "%8sVersion: Unknown (%ld)\n", "", l) <= 0)
                goto err;
        }
    }
    if (!(cflag & X509_FLAG_NO_SERIAL)) {

        if (VR_BIO_write(bp, "        Serial Number:", 22) <= 0)
            goto err;

        bs = VR_X509_get_serialNumber(x);
        if (bs->length <= (int)sizeof(long)) {
                VR_ERR_set_mark();
                l = VR_ASN1_INTEGER_get(bs);
                VR_ERR_pop_to_mark();
        } else {
            l = -1;
        }
        if (l != -1) {
            unsigned long ul;
            if (bs->type == V_ASN1_NEG_INTEGER) {
                ul = 0 - (unsigned long)l;
                neg = "-";
            } else {
                ul = l;
                neg = "";
            }
            if (VR_BIO_printf(bp, " %s%lu (%s0x%lx)\n", neg, ul, neg, ul) <= 0)
                goto err;
        } else {
            neg = (bs->type == V_ASN1_NEG_INTEGER) ? " (Negative)" : "";
            if (VR_BIO_printf(bp, "\n%12s%s", "", neg) <= 0)
                goto err;

            for (i = 0; i < bs->length; i++) {
                if (VR_BIO_printf(bp, "%02x%c", bs->data[i],
                               ((i + 1 == bs->length) ? '\n' : ':')) <= 0)
                    goto err;
            }
        }

    }

    if (!(cflag & X509_FLAG_NO_SIGNAME)) {
        const X509_ALGOR *tsig_alg = VR_X509_get0_tbs_sigalg(x);

        if (VR_BIO_puts(bp, "    ") <= 0)
            goto err;
        if (VR_X509_signature_print(bp, tsig_alg, NULL) <= 0)
            goto err;
    }

    if (!(cflag & X509_FLAG_NO_ISSUER)) {
        if (VR_BIO_printf(bp, "        Issuer:%c", mlch) <= 0)
            goto err;
        if (VR_X509_NAME_print_ex(bp, VR_X509_get_issuer_name(x), nmindent, nmflags)
            < 0)
            goto err;
        if (VR_BIO_write(bp, "\n", 1) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_VALIDITY)) {
        if (VR_BIO_write(bp, "        Validity\n", 17) <= 0)
            goto err;
        if (VR_BIO_write(bp, "            Not Before: ", 24) <= 0)
            goto err;
        if (!VR_ASN1_TIME_print(bp, VR_X509_get0_notBefore(x)))
            goto err;
        if (VR_BIO_write(bp, "\n            Not After : ", 25) <= 0)
            goto err;
        if (!VR_ASN1_TIME_print(bp, VR_X509_get0_notAfter(x)))
            goto err;
        if (VR_BIO_write(bp, "\n", 1) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_SUBJECT)) {
        if (VR_BIO_printf(bp, "        Subject:%c", mlch) <= 0)
            goto err;
        if (VR_X509_NAME_print_ex
            (bp, VR_X509_get_subject_name(x), nmindent, nmflags) < 0)
            goto err;
        if (VR_BIO_write(bp, "\n", 1) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_PUBKEY)) {
        X509_PUBKEY *xpkey = VR_X509_get_X509_PUBKEY(x);
        ASN1_OBJECT *xpoid;
        VR_X509_PUBKEY_get0_param(&xpoid, NULL, NULL, NULL, xpkey);
        if (VR_BIO_write(bp, "        Subject Public Key Info:\n", 33) <= 0)
            goto err;
        if (VR_BIO_printf(bp, "%12sPublic Key Algorithm: ", "") <= 0)
            goto err;
        if (VR_i2a_ASN1_OBJECT(bp, xpoid) <= 0)
            goto err;
        if (VR_BIO_puts(bp, "\n") <= 0)
            goto err;

        pkey = VR_X509_get0_pubkey(x);
        if (pkey == NULL) {
            VR_BIO_printf(bp, "%12sUnable to load Public Key\n", "");
            VR_ERR_print_errors(bp);
        } else {
            VR_EVP_PKEY_print_public(bp, pkey, 16, NULL);
        }
    }

    if (!(cflag & X509_FLAG_NO_IDS)) {
        const ASN1_BIT_STRING *iuid, *suid;
        VR_X509_get0_uids(x, &iuid, &suid);
        if (iuid != NULL) {
            if (VR_BIO_printf(bp, "%8sIssuer Unique ID: ", "") <= 0)
                goto err;
            if (!VR_X509_signature_dump(bp, iuid, 12))
                goto err;
        }
        if (suid != NULL) {
            if (VR_BIO_printf(bp, "%8sSubject Unique ID: ", "") <= 0)
                goto err;
            if (!VR_X509_signature_dump(bp, suid, 12))
                goto err;
        }
    }

    if (!(cflag & X509_FLAG_NO_EXTENSIONS))
        VR_X509V3_extensions_print(bp, "X509v3 extensions",
                                VR_X509_get0_extensions(x), cflag, 8);

    if (!(cflag & X509_FLAG_NO_SIGDUMP)) {
        const X509_ALGOR *sig_alg;
        const ASN1_BIT_STRING *sig;
        VR_X509_get0_signature(&sig, &sig_alg, x);
        if (VR_X509_signature_print(bp, sig_alg, sig) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_AUX)) {
        if (!VR_X509_aux_print(bp, x, 0))
            goto err;
    }
    ret = 1;
 err:
    VR_OPENSSL_free(m);
    return ret;
}

int VR_X509_ocspid_print(BIO *bp, X509 *x)
{
    unsigned char *der = NULL;
    unsigned char *dertmp;
    int derlen;
    int i;
    unsigned char VR_SHA1md[SHA_DIGEST_LENGTH];
    ASN1_BIT_STRING *keybstr;
    X509_NAME *subj;

    /*
     * display the hash of the subject as it would appear in OCSP requests
     */
    if (VR_BIO_printf(bp, "        Subject OCSP hash: ") <= 0)
        goto err;
    subj = VR_X509_get_subject_name(x);
    derlen = VR_i2d_X509_NAME(subj, NULL);
    if ((der = dertmp = OPENSSL_malloc(derlen)) == NULL)
        goto err;
    VR_i2d_X509_NAME(subj, &dertmp);

    if (!VR_EVP_Digest(der, derlen, VR_SHA1md, NULL, VR_EVP_sha1(), NULL))
        goto err;
    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        if (VR_BIO_printf(bp, "%02X", VR_SHA1md[i]) <= 0)
            goto err;
    }
    VR_OPENSSL_free(der);
    der = NULL;

    /*
     * display the hash of the public key as it would appear in OCSP requests
     */
    if (VR_BIO_printf(bp, "\n        Public key OCSP hash: ") <= 0)
        goto err;

    keybstr = VR_X509_get0_pubkey_bitstr(x);

    if (keybstr == NULL)
        goto err;

    if (!VR_EVP_Digest(VR_ASN1_STRING_get0_data(keybstr),
                    VR_ASN1_STRING_length(keybstr), VR_SHA1md, NULL, VR_EVP_sha1(),
                    NULL))
        goto err;
    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        if (VR_BIO_printf(bp, "%02X", VR_SHA1md[i]) <= 0)
            goto err;
    }
    VR_BIO_printf(bp, "\n");

    return 1;
 err:
    VR_OPENSSL_free(der);
    return 0;
}

int VR_X509_signature_dump(BIO *bp, const ASN1_STRING *sig, int indent)
{
    const unsigned char *s;
    int i, n;

    n = sig->length;
    s = sig->data;
    for (i = 0; i < n; i++) {
        if ((i % 18) == 0) {
            if (VR_BIO_write(bp, "\n", 1) <= 0)
                return 0;
            if (VR_BIO_indent(bp, indent, indent) <= 0)
                return 0;
        }
        if (VR_BIO_printf(bp, "%02x%s", s[i], ((i + 1) == n) ? "" : ":") <= 0)
            return 0;
    }
    if (VR_BIO_write(bp, "\n", 1) != 1)
        return 0;

    return 1;
}

int VR_X509_signature_print(BIO *bp, const X509_ALGOR *sigalg,
                         const ASN1_STRING *sig)
{
    int sig_nid;
    if (VR_BIO_puts(bp, "    Signature Algorithm: ") <= 0)
        return 0;
    if (VR_i2a_ASN1_OBJECT(bp, sigalg->algorithm) <= 0)
        return 0;

    sig_nid = VR_OBJ_obj2nid(sigalg->algorithm);
    if (sig_nid != NID_undef) {
        int pkey_nid, dig_nid;
        const EVP_PKEY_ASN1_METHOD *ameth;
        if (VR_OBJ_find_sigid_algs(sig_nid, &dig_nid, &pkey_nid)) {
            ameth = VR_EVP_PKEY_asn1_find(NULL, pkey_nid);
            if (ameth && ameth->sig_print)
                return ameth->sig_print(bp, sigalg, sig, 9, 0);
        }
    }
    if (sig)
        return VR_X509_signature_dump(bp, sig, 9);
    else if (VR_BIO_puts(bp, "\n") <= 0)
        return 0;
    return 1;
}

int VR_X509_aux_print(BIO *out, X509 *x, int indent)
{
    char oidstr[80], first;
    STACK_OF(ASN1_OBJECT) *trust, *reject;
    const unsigned char *alias, *keyid;
    int keyidlen;
    int i;
    if (VR_X509_trusted(x) == 0)
        return 1;
    trust = VR_X509_get0_trust_objects(x);
    reject = VR_X509_get0_reject_objects(x);
    if (trust) {
        first = 1;
        VR_BIO_printf(out, "%*sTrusted Uses:\n%*s", indent, "", indent + 2, "");
        for (i = 0; i < sk_ASN1_OBJECT_num(trust); i++) {
            if (!first)
                VR_BIO_puts(out, ", ");
            else
                first = 0;
            VR_OBJ_obj2txt(oidstr, sizeof(oidstr),
                        sk_ASN1_OBJECT_value(trust, i), 0);
            VR_BIO_puts(out, oidstr);
        }
        VR_BIO_puts(out, "\n");
    } else
        VR_BIO_printf(out, "%*sNo Trusted Uses.\n", indent, "");
    if (reject) {
        first = 1;
        VR_BIO_printf(out, "%*sRejected Uses:\n%*s", indent, "", indent + 2, "");
        for (i = 0; i < sk_ASN1_OBJECT_num(reject); i++) {
            if (!first)
                VR_BIO_puts(out, ", ");
            else
                first = 0;
            VR_OBJ_obj2txt(oidstr, sizeof(oidstr),
                        sk_ASN1_OBJECT_value(reject, i), 0);
            VR_BIO_puts(out, oidstr);
        }
        VR_BIO_puts(out, "\n");
    } else
        VR_BIO_printf(out, "%*sNo Rejected Uses.\n", indent, "");
    alias = VR_X509_alias_get0(x, NULL);
    if (alias)
        VR_BIO_printf(out, "%*sAlias: %s\n", indent, "", alias);
    keyid = VR_X509_keyid_get0(x, &keyidlen);
    if (keyid) {
        VR_BIO_printf(out, "%*sKey Id: ", indent, "");
        for (i = 0; i < keyidlen; i++)
            VR_BIO_printf(out, "%s%02X", i ? ":" : "", keyid[i]);
        VR_BIO_write(out, "\n", 1);
    }
    return 1;
}
