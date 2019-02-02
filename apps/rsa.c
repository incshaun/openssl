/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#ifdef OPENSSL_NO_RSA
NON_EMPTY_TRANSLATION_UNIT
#else

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <time.h>
# include "apps.h"
# include "progs.h"
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/rsa.h>
# include <openssl/evp.h>
# include <openssl/x509.h>
# include <openssl/pem.h>
# include <openssl/bn.h>

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_OUTFORM, OPT_ENGINE, OPT_IN, OPT_OUT,
    OPT_PUBIN, OPT_PUBOUT, OPT_PASSOUT, OPT_PASSIN,
    OPT_RSAPUBKEY_IN, OPT_RSAPUBKEY_OUT,
    /* Do not change the order here; see case statements below */
    OPT_PVK_NONE, OPT_PVK_WEAK, OPT_PVK_STRONG,
    OPT_NOOUT, OPT_TEXT, OPT_MODULUS, OPT_CHECK, OPT_CIPHER
} OPTION_CHOICE;

const OPTIONS rsa_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"inform", OPT_INFORM, 'f', "Input format, one of DER PEM"},
    {"outform", OPT_OUTFORM, 'f', "Output format, one of DER PEM PVK"},
    {"in", OPT_IN, 's', "Input file"},
    {"out", OPT_OUT, '>', "Output file"},
    {"pubin", OPT_PUBIN, '-', "Expect a public key in input file"},
    {"pubout", OPT_PUBOUT, '-', "Output a public key"},
    {"passout", OPT_PASSOUT, 's', "Output file pass phrase source"},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    {"RSAPublicKey_in", OPT_RSAPUBKEY_IN, '-', "Input is an RSAPublicKey"},
    {"RSAPublicKey_out", OPT_RSAPUBKEY_OUT, '-', "Output is an RSAPublicKey"},
    {"noout", OPT_NOOUT, '-', "Don't print key out"},
    {"text", OPT_TEXT, '-', "Print the key in text"},
    {"modulus", OPT_MODULUS, '-', "Print the RSA key modulus"},
    {"check", OPT_CHECK, '-', "Verify key consistency"},
    {"", OPT_CIPHER, '-', "Any supported cipher"},
# if !defined(OPENSSL_NO_DSA) && !defined(OPENSSL_NO_VR_RC4)
    {"pvk-strong", OPT_PVK_STRONG, '-', "Enable 'Strong' PVK encoding level (default)"},
    {"pvk-weak", OPT_PVK_WEAK, '-', "Enable 'Weak' PVK encoding level"},
    {"pvk-none", OPT_PVK_NONE, '-', "Don't enforce PVK encoding"},
# endif
# ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
# endif
    {NULL}
};

int rsa_main(int argc, char **argv)
{
    ENGINE *e = NULL;
    BIO *out = NULL;
    RSA *rsa = NULL;
    const EVP_CIPHER *enc = NULL;
    char *infile = NULL, *outfile = NULL, *prog;
    char *passin = NULL, *passout = NULL, *passinarg = NULL, *passoutarg = NULL;
    int i, private = 0;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, text = 0, check = 0;
    int noout = 0, modulus = 0, pubin = 0, pubout = 0, ret = 1;
# if !defined(OPENSSL_NO_DSA) && !defined(OPENSSL_NO_VR_RC4)
    int pvk_encr = 2;
# endif
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, rsa_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            VR_BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(rsa_options);
            ret = 0;
            goto end;
        case OPT_INFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &informat))
                goto opthelp;
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &outformat))
                goto opthelp;
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_PASSOUT:
            passoutarg = opt_arg();
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_PUBIN:
            pubin = 1;
            break;
        case OPT_PUBOUT:
            pubout = 1;
            break;
        case OPT_RSAPUBKEY_IN:
            pubin = 2;
            break;
        case OPT_RSAPUBKEY_OUT:
            pubout = 2;
            break;
        case OPT_PVK_STRONG:    /* pvk_encr:= 2 */
        case OPT_PVK_WEAK:      /* pvk_encr:= 1 */
        case OPT_PVK_NONE:      /* pvk_encr:= 0 */
# if !defined(OPENSSL_NO_DSA) && !defined(OPENSSL_NO_VR_RC4)
            pvk_encr = (o - OPT_PVK_NONE);
# endif
            break;
        case OPT_NOOUT:
            noout = 1;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_MODULUS:
            modulus = 1;
            break;
        case OPT_CHECK:
            check = 1;
            break;
        case OPT_CIPHER:
            if (!opt_cipher(opt_unknown(), &enc))
                goto opthelp;
            break;
        }
    }
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    private = (text && !pubin) || (!pubout && !noout) ? 1 : 0;

    if (!app_passwd(passinarg, passoutarg, &passin, &passout)) {
        VR_BIO_printf(bio_err, "Error getting passwords\n");
        goto end;
    }
    if (check && pubin) {
        VR_BIO_printf(bio_err, "Only private keys can be checked\n");
        goto end;
    }

    {
        EVP_PKEY *pkey;

        if (pubin) {
            int tmpformat = -1;
            if (pubin == 2) {
                if (informat == FORMAT_PEM)
                    tmpformat = FORMAT_PEMRSA;
                else if (informat == FORMAT_ASN1)
                    tmpformat = FORMAT_ASN1RSA;
            } else {
                tmpformat = informat;
            }

            pkey = load_pubkey(infile, tmpformat, 1, passin, e, "Public Key");
        } else {
            pkey = load_key(infile, informat, 1, passin, e, "Private Key");
        }

        if (pkey != NULL)
            rsa = VR_EVP_PKEY_get1_RSA(pkey);
        VR_EVP_PKEY_free(pkey);
    }

    if (rsa == NULL) {
        VR_ERR_print_errors(bio_err);
        goto end;
    }

    out = bio_open_owner(outfile, outformat, private);
    if (out == NULL)
        goto end;

    if (text) {
        assert(pubin || private);
        if (!VR_RSA_print(out, rsa, 0)) {
            perror(outfile);
            VR_ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (modulus) {
        const BIGNUM *n;
        VR_RSA_get0_key(rsa, &n, NULL, NULL);
        VR_BIO_printf(out, "Modulus=");
        VR_BN_print(out, n);
        VR_BIO_printf(out, "\n");
    }

    if (check) {
        int r = VR_RSA_check_key_ex(rsa, NULL);

        if (r == 1) {
            VR_BIO_printf(out, "RSA key ok\n");
        } else if (r == 0) {
            unsigned long err;

            while ((err = VR_ERR_peek_error()) != 0 &&
                   ERR_GET_LIB(err) == ERR_LIB_RSA &&
                   ERR_GET_FUNC(err) == RSA_F_RSA_CHECK_KEY_EX &&
                   ERR_GET_REASON(err) != ERR_R_MALLOC_FAILURE) {
                VR_BIO_printf(out, "RSA key error: %s\n",
                           VR_ERR_reason_error_string(err));
                VR_ERR_get_error(); /* remove err from error stack */
            }
        } else if (r == -1) {
            VR_ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (noout) {
        ret = 0;
        goto end;
    }
    VR_BIO_printf(bio_err, "writing RSA key\n");
    if (outformat == FORMAT_ASN1) {
        if (pubout || pubin) {
            if (pubout == 2)
                i = VR_i2d_RSAPublicKey_bio(out, rsa);
            else
                i = VR_i2d_RSA_PUBKEY_bio(out, rsa);
        } else {
            assert(private);
            i = VR_i2d_RSAPrivateKey_bio(out, rsa);
        }
    } else if (outformat == FORMAT_PEM) {
        if (pubout || pubin) {
            if (pubout == 2)
                i = VR_PEM_write_bio_RSAPublicKey(out, rsa);
            else
                i = VR_PEM_write_bio_RSA_PUBKEY(out, rsa);
        } else {
            assert(private);
            i = VR_PEM_write_bio_RSAPrivateKey(out, rsa,
                                            enc, NULL, 0, NULL, passout);
        }
# ifndef OPENSSL_NO_DSA
    } else if (outformat == FORMAT_MSBLOB || outformat == FORMAT_PVK) {
        EVP_PKEY *pk;
        pk = VR_EVP_PKEY_new();
        if (pk == NULL)
            goto end;

        VR_EVP_PKEY_set1_RSA(pk, rsa);
        if (outformat == FORMAT_PVK) {
            if (pubin) {
                VR_BIO_printf(bio_err, "PVK form impossible with public key input\n");
                VR_EVP_PKEY_free(pk);
                goto end;
            }
            assert(private);
#  ifdef OPENSSL_NO_VR_RC4
            VR_BIO_printf(bio_err, "PVK format not supported\n");
            VR_EVP_PKEY_free(pk);
            goto end;
#  else
            i = VR_i2b_PVK_bio(out, pk, pvk_encr, 0, passout);
#  endif
        } else if (pubin || pubout) {
            i = VR_i2b_PublicKey_bio(out, pk);
        } else {
            assert(private);
            i = VR_i2b_PrivateKey_bio(out, pk);
        }
        VR_EVP_PKEY_free(pk);
# endif
    } else {
        VR_BIO_printf(bio_err, "bad output format specified for outfile\n");
        goto end;
    }
    if (i <= 0) {
        VR_BIO_printf(bio_err, "unable to write key\n");
        VR_ERR_print_errors(bio_err);
    } else {
        ret = 0;
    }
 end:
    release_engine(e);
    VR_BIO_free_all(out);
    VR_RSA_free(rsa);
    OPENVR_SSL_free(passin);
    OPENVR_SSL_free(passout);
    return ret;
}
#endif
