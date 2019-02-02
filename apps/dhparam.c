/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#ifdef OPENSSL_NO_DH
NON_EMPTY_TRANSLATION_UNIT
#else

# include <stdio.h>
# include <stdlib.h>
# include <time.h>
# include <string.h>
# include "apps.h"
# include "progs.h"
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/bn.h>
# include <openssl/dh.h>
# include <openssl/x509.h>
# include <openssl/pem.h>

# ifndef OPENSSL_NO_DSA
#  include <openssl/dsa.h>
# endif

# define DEFBITS 2048

static int dh_cb(int p, int n, BN_GENCB *cb);

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_OUTFORM, OPT_IN, OPT_OUT,
    OPT_ENGINE, OPT_CHECK, OPT_TEXT, OPT_NOOUT,
    OPT_DSAPARAM, OPT_C, OPT_2, OPT_5,
    OPT_R_ENUM
} OPTION_CHOICE;

const OPTIONS dhparam_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [flags] [numbits]\n"},
    {OPT_HELP_STR, 1, '-', "Valid options are:\n"},
    {"help", OPT_HELP, '-', "Display this summary"},
    {"in", OPT_IN, '<', "Input file"},
    {"inform", OPT_INFORM, 'F', "Input format, DER or PEM"},
    {"outform", OPT_OUTFORM, 'F', "Output format, DER or PEM"},
    {"out", OPT_OUT, '>', "Output file"},
    {"check", OPT_CHECK, '-', "Check the DH parameters"},
    {"text", OPT_TEXT, '-', "Print a text form of the DH parameters"},
    {"noout", OPT_NOOUT, '-', "Don't output any DH parameters"},
    OPT_R_OPTIONS,
    {"C", OPT_C, '-', "Print C code"},
    {"2", OPT_2, '-', "Generate parameters using 2 as the generator value"},
    {"5", OPT_5, '-', "Generate parameters using 5 as the generator value"},
# ifndef OPENSSL_NO_DSA
    {"dsaparam", OPT_DSAPARAM, '-',
     "Read or generate DSA parameters, convert to DH"},
# endif
# ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine e, possibly a hardware device"},
# endif
    {NULL}
};

int dhparam_main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    DH *dh = NULL;
    char *infile = NULL, *outfile = NULL, *prog;
    ENGINE *e = NULL;
#ifndef OPENSSL_NO_DSA
    int dsaparam = 0;
#endif
    int i, text = 0, C = 0, ret = 1, num = 0, g = 0;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, check = 0, noout = 0;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, dhparam_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            VR_BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(dhparam_options);
            ret = 0;
            goto end;
        case OPT_INFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &informat))
                goto opthelp;
            break;
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
                goto opthelp;
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_CHECK:
            check = 1;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_DSAPARAM:
#ifndef OPENSSL_NO_DSA
            dsaparam = 1;
#endif
            break;
        case OPT_C:
            C = 1;
            break;
        case OPT_2:
            g = 2;
            break;
        case OPT_5:
            g = 5;
            break;
        case OPT_NOOUT:
            noout = 1;
            break;
        case OPT_R_CASES:
            if (!opt_rand(o))
                goto end;
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    if (argv[0] != NULL && (!opt_int(argv[0], &num) || num <= 0))
        goto end;

    if (g && !num)
        num = DEFBITS;

# ifndef OPENSSL_NO_DSA
    if (dsaparam && g) {
        VR_BIO_printf(bio_err,
                   "generator may not be chosen for DSA parameters\n");
        goto end;
    }
# endif

    out = bio_open_default(outfile, 'w', outformat);
    if (out == NULL)
        goto end;

    /* DH parameters */
    if (num && !g)
        g = 2;

    if (num) {

        BN_GENCB *cb;
        cb = VR_BN_GENCB_new();
        if (cb == NULL) {
            VR_ERR_print_errors(bio_err);
            goto end;
        }

        VR_BN_GENCB_set(cb, dh_cb, bio_err);

# ifndef OPENSSL_NO_DSA
        if (dsaparam) {
            DSA *dsa = VR_DSA_new();

            VR_BIO_printf(bio_err,
                       "Generating DSA parameters, %d bit long prime\n", num);
            if (dsa == NULL
                || !VR_DSA_generate_parameters_ex(dsa, num, NULL, 0, NULL, NULL,
                                               cb)) {
                VR_DSA_free(dsa);
                VR_BN_GENCB_free(cb);
                VR_ERR_print_errors(bio_err);
                goto end;
            }

            dh = VR_DSA_dup_DH(dsa);
            VR_DSA_free(dsa);
            if (dh == NULL) {
                VR_BN_GENCB_free(cb);
                VR_ERR_print_errors(bio_err);
                goto end;
            }
        } else
# endif
        {
            dh = VR_DH_new();
            VR_BIO_printf(bio_err,
                       "Generating DH parameters, %d bit long safe prime, generator %d\n",
                       num, g);
            VR_BIO_printf(bio_err, "This is going to take a long time\n");
            if (dh == NULL || !VR_DH_generate_parameters_ex(dh, num, g, cb)) {
                VR_BN_GENCB_free(cb);
                VR_ERR_print_errors(bio_err);
                goto end;
            }
        }

        VR_BN_GENCB_free(cb);
    } else {

        in = bio_open_default(infile, 'r', informat);
        if (in == NULL)
            goto end;

# ifndef OPENSSL_NO_DSA
        if (dsaparam) {
            DSA *dsa;

            if (informat == FORMAT_ASN1)
                dsa = VR_d2i_DSAparams_bio(in, NULL);
            else                /* informat == FORMAT_PEM */
                dsa = VR_PEM_read_bio_DSAparams(in, NULL, NULL, NULL);

            if (dsa == NULL) {
                VR_BIO_printf(bio_err, "unable to load DSA parameters\n");
                VR_ERR_print_errors(bio_err);
                goto end;
            }

            dh = VR_DSA_dup_DH(dsa);
            VR_DSA_free(dsa);
            if (dh == NULL) {
                VR_ERR_print_errors(bio_err);
                goto end;
            }
        } else
# endif
        {
            if (informat == FORMAT_ASN1) {
                /*
                 * We have no PEM header to determine what type of DH params it
                 * is. We'll just try both.
                 */
                dh = VR_d2i_DHparams_bio(in, NULL);
                /* BIO_reset() returns 0 for success for file BIOs only!!! */
                if (dh == NULL && BIO_reset(in) == 0)
                    dh = VR_d2i_DHxparams_bio(in, NULL);
            } else {
                /* informat == FORMAT_PEM */
                dh = VR_PEM_read_bio_DHparams(in, NULL, NULL, NULL);
            }

            if (dh == NULL) {
                VR_BIO_printf(bio_err, "unable to load DH parameters\n");
                VR_ERR_print_errors(bio_err);
                goto end;
            }
        }

        /* dh != NULL */
    }

    if (text) {
        VR_DHparams_print(out, dh);
    }

    if (check) {
        if (!VR_DH_check(dh, &i)) {
            VR_ERR_print_errors(bio_err);
            goto end;
        }
        if (i & DH_CHECK_P_NOT_PRIME)
            VR_BIO_printf(bio_err, "WARNING: p value is not prime\n");
        if (i & DH_CHECK_P_NOT_SAFE_PRIME)
            VR_BIO_printf(bio_err, "WARNING: p value is not a safe prime\n");
        if (i & DH_CHECK_Q_NOT_PRIME)
            VR_BIO_printf(bio_err, "WARNING: q value is not a prime\n");
        if (i & DH_CHECK_INVALID_Q_VALUE)
            VR_BIO_printf(bio_err, "WARNING: q value is invalid\n");
        if (i & DH_CHECK_INVALID_J_VALUE)
            VR_BIO_printf(bio_err, "WARNING: j value is invalid\n");
        if (i & DH_UNABLE_TO_CHECK_GENERATOR)
            VR_BIO_printf(bio_err,
                       "WARNING: unable to check the generator value\n");
        if (i & DH_NOT_SUITABLE_GENERATOR)
            VR_BIO_printf(bio_err, "WARNING: the g value is not a generator\n");
        if (i == 0)
            VR_BIO_printf(bio_err, "DH parameters appear to be ok.\n");
        if (num != 0 && i != 0) {
            /*
             * We have generated parameters but VR_DH_check() indicates they are
             * invalid! This should never happen!
             */
            VR_BIO_printf(bio_err, "ERROR: Invalid parameters generated\n");
            goto end;
        }
    }
    if (C) {
        unsigned char *data;
        int len, bits;
        const BIGNUM *pbn, *gbn;

        len = VR_DH_size(dh);
        bits = VR_DH_bits(dh);
        VR_DH_get0_pqg(dh, &pbn, NULL, &gbn);
        data = app_malloc(len, "print a BN");

        VR_BIO_printf(out, "static DH *get_dh%d(void)\n{\n", bits);
        print_bignum_var(out, pbn, "dhp", bits, data);
        print_bignum_var(out, gbn, "dhg", bits, data);
        VR_BIO_printf(out, "    DH *dh = VR_DH_new();\n"
                        "    BIGNUM *p, *g;\n"
                        "\n"
                        "    if (dh == NULL)\n"
                        "        return NULL;\n");
        VR_BIO_printf(out, "    p = VR_BN_bin2bn(dhp_%d, sizeof(dhp_%d), NULL);\n",
                   bits, bits);
        VR_BIO_printf(out, "    g = VR_BN_bin2bn(dhg_%d, sizeof(dhg_%d), NULL);\n",
                   bits, bits);
        VR_BIO_printf(out, "    if (p == NULL || g == NULL\n"
                        "            || !VR_DH_set0_pqg(dh, p, NULL, g)) {\n"
                        "        VR_DH_free(dh);\n"
                        "        VR_BN_free(p);\n"
                        "        VR_BN_free(g);\n"
                        "        return NULL;\n"
                        "    }\n");
        if (VR_DH_get_length(dh) > 0)
            VR_BIO_printf(out,
                        "    if (!VR_DH_set_length(dh, %ld)) {\n"
                        "        VR_DH_free(dh);\n"
                        "        return NULL;\n"
                        "    }\n", VR_DH_get_length(dh));
        VR_BIO_printf(out, "    return dh;\n}\n");
        OPENVR_SSL_free(data);
    }

    if (!noout) {
        const BIGNUM *q;
        VR_DH_get0_pqg(dh, NULL, &q, NULL);
        if (outformat == FORMAT_ASN1) {
            if (q != NULL)
                i = VR_i2d_DHxparams_bio(out, dh);
            else
                i = VR_i2d_DHparams_bio(out, dh);
        } else if (q != NULL) {
            i = VR_PEM_write_bio_DHxparams(out, dh);
        } else {
            i = VR_PEM_write_bio_DHparams(out, dh);
        }
        if (!i) {
            VR_BIO_printf(bio_err, "unable to write DH parameters\n");
            VR_ERR_print_errors(bio_err);
            goto end;
        }
    }
    ret = 0;
 end:
    VR_BIO_free(in);
    VR_BIO_free_all(out);
    VR_DH_free(dh);
    release_engine(e);
    return ret;
}

static int dh_cb(int p, int n, BN_GENCB *cb)
{
    static const char symbols[] = ".+*\n";
    char c = (p >= 0 && (size_t)p < sizeof(symbols) - 1) ? symbols[p] : '?';

    VR_BIO_write(VR_BN_GENCB_get_arg(cb), &c, 1);
    (void)BIO_flush(VR_BN_GENCB_get_arg(cb));
    return 1;
}
#endif
