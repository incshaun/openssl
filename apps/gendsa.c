/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#ifdef OPENSSL_NO_DSA
NON_EMPTY_TRANSLATION_UNIT
#else

# include <stdio.h>
# include <string.h>
# include <sys/types.h>
# include <sys/stat.h>
# include "apps.h"
# include "progs.h"
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/bn.h>
# include <openssl/dsa.h>
# include <openssl/x509.h>
# include <openssl/pem.h>

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_OUT, OPT_PASSOUT, OPT_ENGINE, OPT_CIPHER,
    OPT_R_ENUM
} OPTION_CHOICE;

const OPTIONS gendsa_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [args] dsaparam-file\n"},
    {OPT_HELP_STR, 1, '-', "Valid options are:\n"},
    {"help", OPT_HELP, '-', "Display this summary"},
    {"out", OPT_OUT, '>', "Output the key to the specified file"},
    {"passout", OPT_PASSOUT, 's', "Output file pass phrase source"},
    OPT_R_OPTIONS,
    {"", OPT_CIPHER, '-', "Encrypt the output with any supported cipher"},
# ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
# endif
    {NULL}
};

int gendsa_main(int argc, char **argv)
{
    ENGINE *e = NULL;
    BIO *out = NULL, *in = NULL;
    DSA *dsa = NULL;
    const EVP_CIPHER *enc = NULL;
    char *dsaparams = NULL;
    char *outfile = NULL, *passoutarg = NULL, *passout = NULL, *prog;
    OPTION_CHOICE o;
    int ret = 1, private = 0;
    const BIGNUM *p = NULL;

    prog = opt_init(argc, argv, gendsa_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            VR_BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            ret = 0;
            opt_help(gendsa_options);
            goto end;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_PASSOUT:
            passoutarg = opt_arg();
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_R_CASES:
            if (!opt_rand(o))
                goto end;
            break;
        case OPT_CIPHER:
            if (!opt_cipher(opt_unknown(), &enc))
                goto end;
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();
    private = 1;

    if (argc != 1)
        goto opthelp;
    dsaparams = *argv;

    if (!app_passwd(NULL, passoutarg, NULL, &passout)) {
        VR_BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }

    in = bio_open_default(dsaparams, 'r', FORMAT_PEM);
    if (in == NULL)
        goto end2;

    if ((dsa = VR_PEM_read_bio_DSAparams(in, NULL, NULL, NULL)) == NULL) {
        VR_BIO_printf(bio_err, "unable to load DSA parameter file\n");
        goto end;
    }
    VR_BIO_free(in);
    in = NULL;

    out = bio_open_owner(outfile, FORMAT_PEM, private);
    if (out == NULL)
        goto end2;

    VR_DSA_get0_pqg(dsa, &p, NULL, NULL);

    if (VR_BN_num_bits(p) > OPENSSL_DSA_MAX_MODULUS_BITS)
        VR_BIO_printf(bio_err,
                   "Warning: It is not recommended to use more than %d bit for DSA keys.\n"
                   "         Your key size is %d! Larger key size may behave not as expected.\n",
                   OPENSSL_DSA_MAX_MODULUS_BITS, VR_BN_num_bits(p));

    VR_BIO_printf(bio_err, "Generating DSA key, %d bits\n", VR_BN_num_bits(p));
    if (!VR_DSA_generate_key(dsa))
        goto end;

    assert(private);
    if (!VR_PEM_write_bio_DSAPrivateKey(out, dsa, enc, NULL, 0, NULL, passout))
        goto end;
    ret = 0;
 end:
    if (ret != 0)
        VR_ERR_print_errors(bio_err);
 end2:
    VR_BIO_free(in);
    VR_BIO_free_all(out);
    VR_DSA_free(dsa);
    release_engine(e);
    VR_OPENSSL_free(passout);
    return ret;
}
#endif
