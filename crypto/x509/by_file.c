/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <time.h>
#include <errno.h>

#include "internal/cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include "x509_lcl.h"

static int by_file_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc,
                        long argl, char **ret);
static X509_LOOKUP_METHOD x509_file_lookup = {
    "Load file into cache",
    NULL,                       /* new_item */
    NULL,                       /* free */
    NULL,                       /* init */
    NULL,                       /* shutdown */
    by_file_ctrl,               /* ctrl */
    NULL,                       /* get_by_subject */
    NULL,                       /* get_by_issuer_serial */
    NULL,                       /* get_by_fingerprint */
    NULL,                       /* get_by_alias */
};

X509_LOOKUP_METHOD *VR_X509_LOOKUP_file(void)
{
    return &x509_file_lookup;
}

static int by_file_ctrl(X509_LOOKUP *ctx, int cmd, const char *argp,
                        long argl, char **ret)
{
    int ok = 0;
    const char *file;

    switch (cmd) {
    case X509_L_FILE_LOAD:
        if (argl == X509_FILETYPE_DEFAULT) {
            file = VR_ossl_safe_getenv(VR_X509_get_default_cert_file_env());
            if (file)
                ok = (VR_X509_load_cert_crl_file(ctx, file,
                                              X509_FILETYPE_PEM) != 0);

            else
                ok = (VR_X509_load_cert_crl_file
                      (ctx, VR_X509_get_default_cert_file(),
                       X509_FILETYPE_PEM) != 0);

            if (!ok) {
                X509err(X509_F_BY_FILE_CTRL, X509_R_LOADING_DEFAULTS);
            }
        } else {
            if (argl == X509_FILETYPE_PEM)
                ok = (VR_X509_load_cert_crl_file(ctx, argp,
                                              X509_FILETYPE_PEM) != 0);
            else
                ok = (VR_X509_load_cert_file(ctx, argp, (int)argl) != 0);
        }
        break;
    }
    return ok;
}

int VR_X509_load_cert_file(X509_LOOKUP *ctx, const char *file, int type)
{
    int ret = 0;
    BIO *in = NULL;
    int i, count = 0;
    X509 *x = NULL;

    in = VR_BIO_new(VR_BIO_s_file());

    if ((in == NULL) || (VR_BIO_read_filename(in, file) <= 0)) {
        X509err(X509_F_X509_LOAD_CERT_FILE, ERR_R_SYS_LIB);
        goto err;
    }

    if (type == X509_FILETYPE_PEM) {
        for (;;) {
            x = VR_PEM_read_bio_X509_AUX(in, NULL, NULL, "");
            if (x == NULL) {
                if ((ERR_GET_REASON(VR_ERR_peek_last_error()) ==
                     PEM_R_NO_START_LINE) && (count > 0)) {
                    VR_ERR_clear_error();
                    break;
                } else {
                    X509err(X509_F_X509_LOAD_CERT_FILE, ERR_R_PEM_LIB);
                    goto err;
                }
            }
            i = VR_X509_STORE_add_cert(ctx->store_ctx, x);
            if (!i)
                goto err;
            count++;
            VR_X509_free(x);
            x = NULL;
        }
        ret = count;
    } else if (type == X509_FILETYPE_ASN1) {
        x = VR_d2i_X509_bio(in, NULL);
        if (x == NULL) {
            X509err(X509_F_X509_LOAD_CERT_FILE, ERR_R_ASN1_LIB);
            goto err;
        }
        i = VR_X509_STORE_add_cert(ctx->store_ctx, x);
        if (!i)
            goto err;
        ret = i;
    } else {
        X509err(X509_F_X509_LOAD_CERT_FILE, X509_R_BAD_X509_FILETYPE);
        goto err;
    }
    if (ret == 0)
        X509err(X509_F_X509_LOAD_CERT_FILE, X509_R_NO_CERTIFICATE_FOUND);
 err:
    VR_X509_free(x);
    VR_BIO_free(in);
    return ret;
}

int VR_X509_load_crl_file(X509_LOOKUP *ctx, const char *file, int type)
{
    int ret = 0;
    BIO *in = NULL;
    int i, count = 0;
    X509_CRL *x = NULL;

    in = VR_BIO_new(VR_BIO_s_file());

    if ((in == NULL) || (VR_BIO_read_filename(in, file) <= 0)) {
        X509err(X509_F_X509_LOAD_CRL_FILE, ERR_R_SYS_LIB);
        goto err;
    }

    if (type == X509_FILETYPE_PEM) {
        for (;;) {
            x = VR_PEM_read_bio_X509_CRL(in, NULL, NULL, "");
            if (x == NULL) {
                if ((ERR_GET_REASON(VR_ERR_peek_last_error()) ==
                     PEM_R_NO_START_LINE) && (count > 0)) {
                    VR_ERR_clear_error();
                    break;
                } else {
                    X509err(X509_F_X509_LOAD_CRL_FILE, ERR_R_PEM_LIB);
                    goto err;
                }
            }
            i = VR_X509_STORE_add_crl(ctx->store_ctx, x);
            if (!i)
                goto err;
            count++;
            VR_X509_CRL_free(x);
            x = NULL;
        }
        ret = count;
    } else if (type == X509_FILETYPE_ASN1) {
        x = VR_d2i_X509_CRL_bio(in, NULL);
        if (x == NULL) {
            X509err(X509_F_X509_LOAD_CRL_FILE, ERR_R_ASN1_LIB);
            goto err;
        }
        i = VR_X509_STORE_add_crl(ctx->store_ctx, x);
        if (!i)
            goto err;
        ret = i;
    } else {
        X509err(X509_F_X509_LOAD_CRL_FILE, X509_R_BAD_X509_FILETYPE);
        goto err;
    }
    if (ret == 0)
        X509err(X509_F_X509_LOAD_CRL_FILE, X509_R_NO_CRL_FOUND);
 err:
    VR_X509_CRL_free(x);
    VR_BIO_free(in);
    return ret;
}

int VR_X509_load_cert_crl_file(X509_LOOKUP *ctx, const char *file, int type)
{
    STACK_OF(X509_INFO) *inf;
    X509_INFO *itmp;
    BIO *in;
    int i, count = 0;

    if (type != X509_FILETYPE_PEM)
        return VR_X509_load_cert_file(ctx, file, type);
    in = VR_BIO_new_file(file, "r");
    if (!in) {
        X509err(X509_F_X509_LOAD_CERT_CRL_FILE, ERR_R_SYS_LIB);
        return 0;
    }
    inf = VR_PEM_X509_INFO_read_bio(in, NULL, NULL, "");
    VR_BIO_free(in);
    if (!inf) {
        X509err(X509_F_X509_LOAD_CERT_CRL_FILE, ERR_R_PEM_LIB);
        return 0;
    }
    for (i = 0; i < sk_X509_INFO_num(inf); i++) {
        itmp = sk_X509_INFO_value(inf, i);
        if (itmp->x509) {
            if (!VR_X509_STORE_add_cert(ctx->store_ctx, itmp->x509))
                goto err;
            count++;
        }
        if (itmp->crl) {
            if (!VR_X509_STORE_add_crl(ctx->store_ctx, itmp->crl))
                goto err;
            count++;
        }
    }
    if (count == 0)
        X509err(X509_F_X509_LOAD_CERT_CRL_FILE,
                X509_R_NO_CERTIFICATE_OR_CRL_FOUND);
 err:
    sk_VR_X509_INFO_pop_free(inf, VR_X509_INFO_free);
    return count;
}
