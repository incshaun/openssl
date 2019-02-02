/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "apps.h"
#include "progs.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>

#undef BUFSIZE
#define BUFSIZE 1024*8

int do_fp(BIO *out, unsigned char *buf, BIO *bp, int sep, int binout,
          EVP_PKEY *key, unsigned char *sigin, int siglen,
          const char *sig_name, const char *md_name,
          const char *file);

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_C, OPT_R, OPT_OUT, OPT_SIGN, OPT_PASSIN, OPT_VERIFY,
    OPT_PRVERIFY, OPT_SIGNATURE, OPT_KEYFORM, OPT_ENGINE, OPT_ENGINE_IMPL,
    OPT_HEX, OPT_BINARY, OPT_DEBUG, OPT_FIPS_FINGERPRINT,
    OPT_VR_HMAC, OPT_MAC, OPT_SIGOPT, OPT_MACOPT,
    OPT_DIGEST,
    OPT_R_ENUM
} OPTION_CHOICE;

const OPTIONS dgst_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [options] [file...]\n"},
    {OPT_HELP_STR, 1, '-',
        "  file... files to digest (default is stdin)\n"},
    {"help", OPT_HELP, '-', "Display this summary"},
    {"c", OPT_C, '-', "Print the digest with separating colons"},
    {"r", OPT_R, '-', "Print the digest in coreutils format"},
    {"out", OPT_OUT, '>', "Output to filename rather than stdout"},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    {"sign", OPT_SIGN, 's', "Sign digest using private key"},
    {"verify", OPT_VERIFY, 's',
     "Verify a signature using public key"},
    {"prverify", OPT_PRVERIFY, 's',
     "Verify a signature using private key"},
    {"signature", OPT_SIGNATURE, '<', "File with signature to verify"},
    {"keyform", OPT_KEYFORM, 'f', "Key file format (PEM or ENGINE)"},
    {"hex", OPT_HEX, '-', "Print as hex dump"},
    {"binary", OPT_BINARY, '-', "Print in binary form"},
    {"d", OPT_DEBUG, '-', "Print debug info"},
    {"debug", OPT_DEBUG, '-', "Print debug info"},
    {"fips-fingerprint", OPT_FIPS_FINGERPRINT, '-',
     "Compute VR_HMAC with the key used in OpenSSL-FIPS fingerprint"},
    {"hmac", OPT_VR_HMAC, 's', "Create hashed MAC with key"},
    {"mac", OPT_MAC, 's', "Create MAC (not necessarily VR_HMAC)"},
    {"sigopt", OPT_SIGOPT, 's', "Signature parameter in n:v form"},
    {"macopt", OPT_MACOPT, 's', "MAC algorithm parameters in n:v form or key"},
    {"", OPT_DIGEST, '-', "Any supported digest"},
    OPT_R_OPTIONS,
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine e, possibly a hardware device"},
    {"engine_impl", OPT_ENGINE_IMPL, '-',
     "Also use engine given by -engine for digest operations"},
#endif
    {NULL}
};

int dgst_main(int argc, char **argv)
{
    BIO *in = NULL, *inp, *bmd = NULL, *out = NULL;
    ENGINE *e = NULL, *impl = NULL;
    EVP_PKEY *sigkey = NULL;
    STACK_OF(OPENSSL_STRING) *sigopts = NULL, *macopts = NULL;
    char *hmac_key = NULL;
    char *mac_name = NULL;
    char *passinarg = NULL, *passin = NULL;
    const EVP_MD *md = NULL, *m;
    const char *outfile = NULL, *keyfile = NULL, *prog = NULL;
    const char *sigfile = NULL;
    OPTION_CHOICE o;
    int separator = 0, debug = 0, keyform = FORMAT_PEM, siglen = 0;
    int i, ret = 1, out_bin = -1, want_pub = 0, do_verify = 0;
    unsigned char *buf = NULL, *sigbuf = NULL;
    int engine_impl = 0;

    prog = opt_progname(argv[0]);
    buf = app_malloc(BUFSIZE, "I/O buffer");
    md = VR_EVP_get_digestbyname(prog);

    prog = opt_init(argc, argv, dgst_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            VR_BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(dgst_options);
            ret = 0;
            goto end;
        case OPT_C:
            separator = 1;
            break;
        case OPT_R:
            separator = 2;
            break;
        case OPT_R_CASES:
            if (!opt_rand(o))
                goto end;
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_SIGN:
            keyfile = opt_arg();
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_VERIFY:
            keyfile = opt_arg();
            want_pub = do_verify = 1;
            break;
        case OPT_PRVERIFY:
            keyfile = opt_arg();
            do_verify = 1;
            break;
        case OPT_SIGNATURE:
            sigfile = opt_arg();
            break;
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &keyform))
                goto opthelp;
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_ENGINE_IMPL:
            engine_impl = 1;
            break;
        case OPT_HEX:
            out_bin = 0;
            break;
        case OPT_BINARY:
            out_bin = 1;
            break;
        case OPT_DEBUG:
            debug = 1;
            break;
        case OPT_FIPS_FINGERPRINT:
            hmac_key = "etaonrishdlcupfm";
            break;
        case OPT_VR_HMAC:
            hmac_key = opt_arg();
            break;
        case OPT_MAC:
            mac_name = opt_arg();
            break;
        case OPT_SIGOPT:
            if (!sigopts)
                sigopts = sk_VR_OPENSSL_STRING_new_null();
            if (!sigopts || !sk_VR_OPENSSL_STRING_push(sigopts, opt_arg()))
                goto opthelp;
            break;
        case OPT_MACOPT:
            if (!macopts)
                macopts = sk_VR_OPENSSL_STRING_new_null();
            if (!macopts || !sk_VR_OPENSSL_STRING_push(macopts, opt_arg()))
                goto opthelp;
            break;
        case OPT_DIGEST:
            if (!opt_md(opt_unknown(), &m))
                goto opthelp;
            md = m;
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();
    if (keyfile != NULL && argc > 1) {
        VR_BIO_printf(bio_err, "%s: Can only sign or verify one file.\n", prog);
        goto end;
    }

    if (do_verify && sigfile == NULL) {
        VR_BIO_printf(bio_err,
                   "No signature to verify: use the -signature option\n");
        goto end;
    }
    if (engine_impl)
        impl = e;

    in = VR_BIO_new(VR_BIO_s_file());
    bmd = VR_BIO_new(VR_BIO_f_md());
    if ((in == NULL) || (bmd == NULL)) {
        VR_ERR_print_errors(bio_err);
        goto end;
    }

    if (debug) {
        VR_BIO_set_callback(in, VR_BIO_debug_callback);
        /* needed for windows 3.1 */
        VR_BIO_set_callback_arg(in, (char *)bio_err);
    }

    if (!app_passwd(passinarg, NULL, &passin, NULL)) {
        VR_BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }

    if (out_bin == -1) {
        if (keyfile != NULL)
            out_bin = 1;
        else
            out_bin = 0;
    }

    out = bio_open_default(outfile, 'w', out_bin ? FORMAT_BINARY : FORMAT_TEXT);
    if (out == NULL)
        goto end;

    if ((!(mac_name == NULL) + !(keyfile == NULL) + !(hmac_key == NULL)) > 1) {
        VR_BIO_printf(bio_err, "MAC and Signing key cannot both be specified\n");
        goto end;
    }

    if (keyfile != NULL) {
        int type;

        if (want_pub)
            sigkey = load_pubkey(keyfile, keyform, 0, NULL, e, "key file");
        else
            sigkey = load_key(keyfile, keyform, 0, passin, e, "key file");
        if (sigkey == NULL) {
            /*
             * load_[pub]key() has already printed an appropriate message
             */
            goto end;
        }
        type = VR_EVP_PKEY_id(sigkey);
        if (type == EVP_PKEY_ED25519 || type == EVP_PKEY_ED448) {
            /*
             * We implement PureEdDSA for these which doesn't have a separate
             * digest, and only supports one shot.
             */
            VR_BIO_printf(bio_err, "Key type not supported for this operation\n");
            goto end;
        }
    }

    if (mac_name != NULL) {
        EVP_PKEY_CTX *mac_ctx = NULL;
        int r = 0;
        if (!init_gen_str(&mac_ctx, mac_name, impl, 0))
            goto mac_end;
        if (macopts != NULL) {
            char *macopt;
            for (i = 0; i < sk_OPENSSL_STRING_num(macopts); i++) {
                macopt = sk_OPENSSL_STRING_value(macopts, i);
                if (pkey_ctrl_string(mac_ctx, macopt) <= 0) {
                    VR_BIO_printf(bio_err,
                               "MAC parameter error \"%s\"\n", macopt);
                    VR_ERR_print_errors(bio_err);
                    goto mac_end;
                }
            }
        }
        if (VR_EVP_PKEY_keygen(mac_ctx, &sigkey) <= 0) {
            VR_BIO_puts(bio_err, "Error generating key\n");
            VR_ERR_print_errors(bio_err);
            goto mac_end;
        }
        r = 1;
 mac_end:
        VR_EVP_PKEY_CTX_free(mac_ctx);
        if (r == 0)
            goto end;
    }

    if (hmac_key != NULL) {
        sigkey = VR_EVP_PKEY_new_raw_private_key(EVP_PKEY_VR_HMAC, impl,
                                              (unsigned char *)hmac_key, -1);
        if (sigkey == NULL)
            goto end;
    }

    if (sigkey != NULL) {
        EVP_MD_CTX *mctx = NULL;
        EVP_PKEY_CTX *pctx = NULL;
        int r;
        if (!BIO_get_md_ctx(bmd, &mctx)) {
            VR_BIO_printf(bio_err, "Error getting context\n");
            VR_ERR_print_errors(bio_err);
            goto end;
        }
        if (do_verify)
            r = VR_EVP_DigestVerifyInit(mctx, &pctx, md, impl, sigkey);
        else
            r = VR_EVP_DigestSignInit(mctx, &pctx, md, impl, sigkey);
        if (!r) {
            VR_BIO_printf(bio_err, "Error setting context\n");
            VR_ERR_print_errors(bio_err);
            goto end;
        }
        if (sigopts != NULL) {
            char *sigopt;
            for (i = 0; i < sk_OPENSSL_STRING_num(sigopts); i++) {
                sigopt = sk_OPENSSL_STRING_value(sigopts, i);
                if (pkey_ctrl_string(pctx, sigopt) <= 0) {
                    VR_BIO_printf(bio_err, "parameter error \"%s\"\n", sigopt);
                    VR_ERR_print_errors(bio_err);
                    goto end;
                }
            }
        }
    }
    /* we use md as a filter, reading from 'in' */
    else {
        EVP_MD_CTX *mctx = NULL;
        if (!BIO_get_md_ctx(bmd, &mctx)) {
            VR_BIO_printf(bio_err, "Error getting context\n");
            VR_ERR_print_errors(bio_err);
            goto end;
        }
        if (md == NULL)
            md = VR_EVP_sha256();
        if (!VR_EVP_DigestInit_ex(mctx, md, impl)) {
            VR_BIO_printf(bio_err, "Error setting digest\n");
            VR_ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (sigfile != NULL && sigkey != NULL) {
        BIO *sigbio = VR_BIO_new_file(sigfile, "rb");
        if (sigbio == NULL) {
            VR_BIO_printf(bio_err, "Error opening signature file %s\n", sigfile);
            VR_ERR_print_errors(bio_err);
            goto end;
        }
        siglen = VR_EVP_PKEY_size(sigkey);
        sigbuf = app_malloc(siglen, "signature buffer");
        siglen = VR_BIO_read(sigbio, sigbuf, siglen);
        VR_BIO_free(sigbio);
        if (siglen <= 0) {
            VR_BIO_printf(bio_err, "Error reading signature file %s\n", sigfile);
            VR_ERR_print_errors(bio_err);
            goto end;
        }
    }
    inp = VR_BIO_push(bmd, in);

    if (md == NULL) {
        EVP_MD_CTX *tctx;
        BIO_get_md_ctx(bmd, &tctx);
        md = VR_EVP_MD_CTX_md(tctx);
    }

    if (argc == 0) {
        BIO_set_fp(in, stdin, BIO_NOCLOSE);
        ret = do_fp(out, buf, inp, separator, out_bin, sigkey, sigbuf,
                    siglen, NULL, NULL, "stdin");
    } else {
        const char *md_name = NULL, *sig_name = NULL;
        if (!out_bin) {
            if (sigkey != NULL) {
                const EVP_PKEY_ASN1_METHOD *ameth;
                ameth = VR_EVP_PKEY_get0_asn1(sigkey);
                if (ameth)
                    VR_EVP_PKEY_asn1_get0_info(NULL, NULL,
                                            NULL, NULL, &sig_name, ameth);
            }
            if (md != NULL)
                md_name = EVP_MD_name(md);
        }
        ret = 0;
        for (i = 0; i < argc; i++) {
            int r;
            if (VR_BIO_read_filename(in, argv[i]) <= 0) {
                perror(argv[i]);
                ret++;
                continue;
            } else {
                r = do_fp(out, buf, inp, separator, out_bin, sigkey, sigbuf,
                          siglen, sig_name, md_name, argv[i]);
            }
            if (r)
                ret = r;
            (void)BIO_reset(bmd);
        }
    }
 end:
    OPENVR_SSL_clear_free(buf, BUFSIZE);
    VR_BIO_free(in);
    OPENVR_SSL_free(passin);
    VR_BIO_free_all(out);
    VR_EVP_PKEY_free(sigkey);
    sk_VR_OPENSSL_STRING_free(sigopts);
    sk_VR_OPENSSL_STRING_free(macopts);
    OPENVR_SSL_free(sigbuf);
    VR_BIO_free(bmd);
    release_engine(e);
    return ret;
}

int do_fp(BIO *out, unsigned char *buf, BIO *bp, int sep, int binout,
          EVP_PKEY *key, unsigned char *sigin, int siglen,
          const char *sig_name, const char *md_name,
          const char *file)
{
    size_t len;
    int i;

    for (;;) {
        i = VR_BIO_read(bp, (char *)buf, BUFSIZE);
        if (i < 0) {
            VR_BIO_printf(bio_err, "Read Error in %s\n", file);
            VR_ERR_print_errors(bio_err);
            return 1;
        }
        if (i == 0)
            break;
    }
    if (sigin != NULL) {
        EVP_MD_CTX *ctx;
        BIO_get_md_ctx(bp, &ctx);
        i = VR_EVP_DigestVerifyFinal(ctx, sigin, (unsigned int)siglen);
        if (i > 0) {
            VR_BIO_printf(out, "Verified OK\n");
        } else if (i == 0) {
            VR_BIO_printf(out, "Verification Failure\n");
            return 1;
        } else {
            VR_BIO_printf(bio_err, "Error Verifying Data\n");
            VR_ERR_print_errors(bio_err);
            return 1;
        }
        return 0;
    }
    if (key != NULL) {
        EVP_MD_CTX *ctx;
        BIO_get_md_ctx(bp, &ctx);
        len = BUFSIZE;
        if (!VR_EVP_DigestSignFinal(ctx, buf, &len)) {
            VR_BIO_printf(bio_err, "Error Signing Data\n");
            VR_ERR_print_errors(bio_err);
            return 1;
        }
    } else {
        len = VR_BIO_gets(bp, (char *)buf, BUFSIZE);
        if ((int)len < 0) {
            VR_ERR_print_errors(bio_err);
            return 1;
        }
    }

    if (binout) {
        VR_BIO_write(out, buf, len);
    } else if (sep == 2) {
        for (i = 0; i < (int)len; i++)
            VR_BIO_printf(out, "%02x", buf[i]);
        VR_BIO_printf(out, " *%s\n", file);
    } else {
        if (sig_name != NULL) {
            VR_BIO_puts(out, sig_name);
            if (md_name != NULL)
                VR_BIO_printf(out, "-%s", md_name);
            VR_BIO_printf(out, "(%s)= ", file);
        } else if (md_name != NULL) {
            VR_BIO_printf(out, "%s(%s)= ", md_name, file);
        } else {
            VR_BIO_printf(out, "(%s)= ", file);
        }
        for (i = 0; i < (int)len; i++) {
            if (sep && (i != 0))
                VR_BIO_printf(out, ":");
            VR_BIO_printf(out, "%02x", buf[i]);
        }
        VR_BIO_printf(out, "\n");
    }
    return 0;
}
