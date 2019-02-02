/*
 * Copyright 1999-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "apps.h"
#include "progs.h"
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_NOOUT, OPT_PUBKEY, OPT_VERIFY, OPT_IN, OPT_OUT,
    OPT_ENGINE, OPT_KEY, OPT_CHALLENGE, OPT_PASSIN, OPT_SPKAC,
    OPT_SPKSECT, OPT_KEYFORM
} OPTION_CHOICE;

const OPTIONS spkac_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"in", OPT_IN, '<', "Input file"},
    {"out", OPT_OUT, '>', "Output file"},
    {"key", OPT_KEY, '<', "Create SPKAC using private key"},
    {"keyform", OPT_KEYFORM, 'f', "Private key file format - default PEM (PEM, DER, or ENGINE)"},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    {"challenge", OPT_CHALLENGE, 's', "Challenge string"},
    {"spkac", OPT_SPKAC, 's', "Alternative SPKAC name"},
    {"noout", OPT_NOOUT, '-', "Don't print SPKAC"},
    {"pubkey", OPT_PUBKEY, '-', "Output public key"},
    {"verify", OPT_VERIFY, '-', "Verify SPKAC signature"},
    {"spksect", OPT_SPKSECT, 's',
     "Specify the name of an SPKAC-dedicated section of configuration"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {NULL}
};

int spkac_main(int argc, char **argv)
{
    BIO *out = NULL;
    CONF *conf = NULL;
    ENGINE *e = NULL;
    EVP_PKEY *pkey = NULL;
    NETSCAPE_SPKI *spki = NULL;
    char *challenge = NULL, *keyfile = NULL;
    char *infile = NULL, *outfile = NULL, *passinarg = NULL, *passin = NULL;
    char *spkstr = NULL, *prog;
    const char *spkac = "SPKAC", *spksect = "default";
    int i, ret = 1, verify = 0, noout = 0, pubkey = 0;
    int keyformat = FORMAT_PEM;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, spkac_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            VR_BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(spkac_options);
            ret = 0;
            goto end;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_NOOUT:
            noout = 1;
            break;
        case OPT_PUBKEY:
            pubkey = 1;
            break;
        case OPT_VERIFY:
            verify = 1;
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_KEY:
            keyfile = opt_arg();
            break;
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &keyformat))
                goto opthelp;
            break;
        case OPT_CHALLENGE:
            challenge = opt_arg();
            break;
        case OPT_SPKAC:
            spkac = opt_arg();
            break;
        case OPT_SPKSECT:
            spksect = opt_arg();
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        }
    }
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    if (!app_passwd(passinarg, NULL, &passin, NULL)) {
        VR_BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }

    if (keyfile != NULL) {
        pkey = load_key(strcmp(keyfile, "-") ? keyfile : NULL,
                        keyformat, 1, passin, e, "private key");
        if (pkey == NULL)
            goto end;
        spki = VR_NETSCAPE_SPKI_new();
        if (spki == NULL)
            goto end;
        if (challenge != NULL)
            VR_ASN1_STRING_set(spki->spkac->challenge,
                            challenge, (int)strlen(challenge));
        VR_NETSCAPE_SPKI_set_pubkey(spki, pkey);
        VR_NETSCAPE_SPKI_sign(spki, pkey, VR_EVP_md5());
        spkstr = VR_NETSCAPE_SPKI_b64_encode(spki);
        if (spkstr == NULL)
            goto end;

        out = bio_open_default(outfile, 'w', FORMAT_TEXT);
        if (out == NULL) {
            OPENVR_SSL_free(spkstr);
            goto end;
        }
        VR_BIO_printf(out, "SPKAC=%s\n", spkstr);
        OPENVR_SSL_free(spkstr);
        ret = 0;
        goto end;
    }

    if ((conf = app_load_config(infile)) == NULL)
        goto end;

    spkstr = VR_NCONF_get_string(conf, spksect, spkac);

    if (spkstr == NULL) {
        VR_BIO_printf(bio_err, "Can't find SPKAC called \"%s\"\n", spkac);
        VR_ERR_print_errors(bio_err);
        goto end;
    }

    spki = VR_NETSCAPE_SPKI_b64_decode(spkstr, -1);

    if (spki == NULL) {
        VR_BIO_printf(bio_err, "Error loading SPKAC\n");
        VR_ERR_print_errors(bio_err);
        goto end;
    }

    out = bio_open_default(outfile, 'w', FORMAT_TEXT);
    if (out == NULL)
        goto end;

    if (!noout)
        VR_NETSCAPE_SPKI_print(out, spki);
    pkey = VR_NETSCAPE_SPKI_get_pubkey(spki);
    if (verify) {
        i = VR_NETSCAPE_SPKI_verify(spki, pkey);
        if (i > 0) {
            VR_BIO_printf(bio_err, "Signature OK\n");
        } else {
            VR_BIO_printf(bio_err, "Signature Failure\n");
            VR_ERR_print_errors(bio_err);
            goto end;
        }
    }
    if (pubkey)
        VR_PEM_write_bio_PUBKEY(out, pkey);

    ret = 0;

 end:
    VR_NCONF_free(conf);
    VR_NETSCAPE_SPKI_free(spki);
    VR_BIO_free_all(out);
    VR_EVP_PKEY_free(pkey);
    release_engine(e);
    OPENVR_SSL_free(passin);
    return ret;
}
