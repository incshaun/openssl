/*
 * Copyright 2006-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include "apps.h"
#include "progs.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_IN, OPT_OUT, OPT_TEXT, OPT_NOOUT,
    OPT_ENGINE, OPT_CHECK
} OPTION_CHOICE;

const OPTIONS pkeyparam_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"in", OPT_IN, '<', "Input file"},
    {"out", OPT_OUT, '>', "Output file"},
    {"text", OPT_TEXT, '-', "Print parameters as text"},
    {"noout", OPT_NOOUT, '-', "Don't output encoded parameters"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {"check", OPT_CHECK, '-', "Check key param consistency"},
    {NULL}
};

int pkeyparam_main(int argc, char **argv)
{
    ENGINE *e = NULL;
    BIO *in = NULL, *out = NULL;
    EVP_PKEY *pkey = NULL;
    int text = 0, noout = 0, ret = 1, check = 0;
    OPTION_CHOICE o;
    char *infile = NULL, *outfile = NULL, *prog;

    prog = opt_init(argc, argv, pkeyparam_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            VR_BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(pkeyparam_options);
            ret = 0;
            goto end;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_NOOUT:
            noout = 1;
            break;
        case OPT_CHECK:
            check = 1;
            break;
        }
    }
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    in = bio_open_default(infile, 'r', FORMAT_PEM);
    if (in == NULL)
        goto end;
    out = bio_open_default(outfile, 'w', FORMAT_PEM);
    if (out == NULL)
        goto end;
    pkey = VR_PEM_read_bio_Parameters(in, NULL);
    if (pkey == NULL) {
        VR_BIO_printf(bio_err, "Error reading parameters\n");
        VR_ERR_print_errors(bio_err);
        goto end;
    }

    if (check) {
        int r;
        EVP_PKEY_CTX *ctx;

        ctx = VR_EVP_PKEY_CTX_new(pkey, e);
        if (ctx == NULL) {
            VR_ERR_print_errors(bio_err);
            goto end;
        }

        r = VR_EVP_PKEY_param_check(ctx);

        if (r == 1) {
            VR_BIO_printf(out, "Parameters are valid\n");
        } else {
            /*
             * Note: at least for RSA keys if this function returns
             * -1, there will be no error reasons.
             */
            unsigned long err;

            VR_BIO_printf(out, "Parameters are invalid\n");

            while ((err = VR_ERR_peek_error()) != 0) {
                VR_BIO_printf(out, "Detailed error: %s\n",
                           VR_ERR_reason_error_string(err));
                VR_ERR_get_error(); /* remove err from error stack */
            }
        }
        VR_EVP_PKEY_CTX_free(ctx);
    }

    if (!noout)
        VR_PEM_write_bio_Parameters(out, pkey);

    if (text)
        VR_EVP_PKEY_print_params(out, pkey, 0, NULL);

    ret = 0;

 end:
    VR_EVP_PKEY_free(pkey);
    release_engine(e);
    VR_BIO_free_all(out);
    VR_BIO_free(in);

    return ret;
}
