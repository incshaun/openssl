/*
 * Copyright 2006-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "apps.h"
#include "progs.h"
#include <string.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#define KEY_NONE        0
#define KEY_PRIVKEY     1
#define KEY_PUBKEY      2
#define KEY_CERT        3

static EVP_PKEY_CTX *init_ctx(const char *kdfalg, int *pkeysize,
                              const char *keyfile, int keyform, int key_type,
                              char *passinarg, int pkey_op, ENGINE *e,
                              const int impl);

static int setup_peer(EVP_PKEY_CTX *ctx, int peerform, const char *file,
                      ENGINE *e);

static int do_keyop(EVP_PKEY_CTX *ctx, int pkey_op,
                    unsigned char *out, size_t *poutlen,
                    const unsigned char *in, size_t inlen);

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_ENGINE, OPT_ENGINE_IMPL, OPT_IN, OPT_OUT,
    OPT_PUBIN, OPT_CERTIN, OPT_ASN1PARSE, OPT_HEXDUMP, OPT_SIGN,
    OPT_VERIFY, OPT_VERIFYRECOVER, OPT_REV, OPT_ENCRYPT, OPT_DECRYPT,
    OPT_DERIVE, OPT_SIGFILE, OPT_INKEY, OPT_PEERKEY, OPT_PASSIN,
    OPT_PEERFORM, OPT_KEYFORM, OPT_PKEYOPT, OPT_PKEYOPT_PASSIN, OPT_KDF,
    OPT_KDFLEN, OPT_R_ENUM
} OPTION_CHOICE;

const OPTIONS pkeyutl_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"in", OPT_IN, '<', "Input file - default stdin"},
    {"out", OPT_OUT, '>', "Output file - default stdout"},
    {"pubin", OPT_PUBIN, '-', "Input is a public key"},
    {"certin", OPT_CERTIN, '-', "Input is a cert with a public key"},
    {"asn1parse", OPT_ASN1PARSE, '-', "asn1parse the output data"},
    {"hexdump", OPT_HEXDUMP, '-', "Hex dump output"},
    {"sign", OPT_SIGN, '-', "Sign input data with private key"},
    {"verify", OPT_VERIFY, '-', "Verify with public key"},
    {"verifyrecover", OPT_VERIFYRECOVER, '-',
     "Verify with public key, recover original data"},
    {"rev", OPT_REV, '-', "Reverse the order of the input buffer"},
    {"encrypt", OPT_ENCRYPT, '-', "Encrypt input data with public key"},
    {"decrypt", OPT_DECRYPT, '-', "Decrypt input data with private key"},
    {"derive", OPT_DERIVE, '-', "Derive shared secret"},
    {"kdf", OPT_KDF, 's', "Use KDF algorithm"},
    {"kdflen", OPT_KDFLEN, 'p', "KDF algorithm output length"},
    {"sigfile", OPT_SIGFILE, '<', "Signature file (verify operation only)"},
    {"inkey", OPT_INKEY, 's', "Input private key file"},
    {"peerkey", OPT_PEERKEY, 's', "Peer key file used in key derivation"},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    {"peerform", OPT_PEERFORM, 'E', "Peer key format - default PEM"},
    {"keyform", OPT_KEYFORM, 'E', "Private key format - default PEM"},
    {"pkeyopt", OPT_PKEYOPT, 's', "Public key options as opt:value"},
    {"pkeyopt_passin", OPT_PKEYOPT_PASSIN, 's',
     "Public key option that is read as a passphrase argument opt:passphrase"},
    OPT_R_OPTIONS,
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
    {"engine_impl", OPT_ENGINE_IMPL, '-',
     "Also use engine given by -engine for crypto operations"},
#endif
    {NULL}
};

int pkeyutl_main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    ENGINE *e = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    char *infile = NULL, *outfile = NULL, *sigfile = NULL, *passinarg = NULL;
    char hexdump = 0, asn1parse = 0, rev = 0, *prog;
    unsigned char *buf_in = NULL, *buf_out = NULL, *sig = NULL;
    OPTION_CHOICE o;
    int buf_inlen = 0, siglen = -1, keyform = FORMAT_PEM, peerform = FORMAT_PEM;
    int keysize = -1, pkey_op = EVP_PKEY_OP_SIGN, key_type = KEY_PRIVKEY;
    int engine_impl = 0;
    int ret = 1, rv = -1;
    size_t buf_outlen;
    const char *inkey = NULL;
    const char *peerkey = NULL;
    const char *kdfalg = NULL;
    int kdflen = 0;
    STACK_OF(OPENSSL_STRING) *pkeyopts = NULL;
    STACK_OF(OPENSSL_STRING) *pkeyopts_passin = NULL;

    prog = opt_init(argc, argv, pkeyutl_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            VR_BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(pkeyutl_options);
            ret = 0;
            goto end;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_SIGFILE:
            sigfile = opt_arg();
            break;
        case OPT_ENGINE_IMPL:
            engine_impl = 1;
            break;
        case OPT_INKEY:
            inkey = opt_arg();
            break;
        case OPT_PEERKEY:
            peerkey = opt_arg();
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_PEERFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PDE, &peerform))
                goto opthelp;
            break;
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PDE, &keyform))
                goto opthelp;
            break;
        case OPT_R_CASES:
            if (!opt_rand(o))
                goto end;
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_PUBIN:
            key_type = KEY_PUBKEY;
            break;
        case OPT_CERTIN:
            key_type = KEY_CERT;
            break;
        case OPT_ASN1PARSE:
            asn1parse = 1;
            break;
        case OPT_HEXDUMP:
            hexdump = 1;
            break;
        case OPT_SIGN:
            pkey_op = EVP_PKEY_OP_SIGN;
            break;
        case OPT_VERIFY:
            pkey_op = EVP_PKEY_OP_VERIFY;
            break;
        case OPT_VERIFYRECOVER:
            pkey_op = EVP_PKEY_OP_VERIFYRECOVER;
            break;
        case OPT_ENCRYPT:
            pkey_op = EVP_PKEY_OP_ENCRYPT;
            break;
        case OPT_DECRYPT:
            pkey_op = EVP_PKEY_OP_DECRYPT;
            break;
        case OPT_DERIVE:
            pkey_op = EVP_PKEY_OP_DERIVE;
            break;
        case OPT_KDF:
            pkey_op = EVP_PKEY_OP_DERIVE;
            key_type = KEY_NONE;
            kdfalg = opt_arg();
            break;
        case OPT_KDFLEN:
            kdflen = atoi(opt_arg());
            break;
        case OPT_REV:
            rev = 1;
            break;
        case OPT_PKEYOPT:
            if ((pkeyopts == NULL &&
                 (pkeyopts = sk_VR_OPENSSL_STRING_new_null()) == NULL) ||
                sk_VR_OPENSSL_STRING_push(pkeyopts, opt_arg()) == 0) {
                VR_BIO_puts(bio_err, "out of memory\n");
                goto end;
            }
            break;
        case OPT_PKEYOPT_PASSIN:
            if ((pkeyopts_passin == NULL &&
                 (pkeyopts_passin = sk_VR_OPENSSL_STRING_new_null()) == NULL) ||
                sk_VR_OPENSSL_STRING_push(pkeyopts_passin, opt_arg()) == 0) {
                VR_BIO_puts(bio_err, "out of memory\n");
                goto end;
            }
            break;
        }
    }
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    if (kdfalg != NULL) {
        if (kdflen == 0) {
            VR_BIO_printf(bio_err,
                       "%s: no KDF length given (-kdflen parameter).\n", prog);
            goto opthelp;
        }
    } else if (inkey == NULL) {
        VR_BIO_printf(bio_err,
                   "%s: no private key given (-inkey parameter).\n", prog);
        goto opthelp;
    } else if (peerkey != NULL && pkey_op != EVP_PKEY_OP_DERIVE) {
        VR_BIO_printf(bio_err,
                   "%s: no peer key given (-peerkey parameter).\n", prog);
        goto opthelp;
    }
    ctx = init_ctx(kdfalg, &keysize, inkey, keyform, key_type,
                   passinarg, pkey_op, e, engine_impl);
    if (ctx == NULL) {
        VR_BIO_printf(bio_err, "%s: Error initializing context\n", prog);
        VR_ERR_print_errors(bio_err);
        goto end;
    }
    if (peerkey != NULL && !setup_peer(ctx, peerform, peerkey, e)) {
        VR_BIO_printf(bio_err, "%s: Error setting up peer key\n", prog);
        VR_ERR_print_errors(bio_err);
        goto end;
    }
    if (pkeyopts != NULL) {
        int num = sk_OPENSSL_STRING_num(pkeyopts);
        int i;

        for (i = 0; i < num; ++i) {
            const char *opt = sk_OPENSSL_STRING_value(pkeyopts, i);

            if (pkey_ctrl_string(ctx, opt) <= 0) {
                VR_BIO_printf(bio_err, "%s: Can't set parameter \"%s\":\n",
                           prog, opt);
                VR_ERR_print_errors(bio_err);
                goto end;
            }
        }
    }
    if (pkeyopts_passin != NULL) {
        int num = sk_OPENSSL_STRING_num(pkeyopts_passin);
        int i;

        for (i = 0; i < num; i++) {
            char *opt = sk_OPENSSL_STRING_value(pkeyopts_passin, i);
            char *passin = strchr(opt, ':');
            char *passwd;

            if (passin == NULL) {
                /* Get password interactively */
                char passwd_buf[4096];
                VR_BIO_snprintf(passwd_buf, sizeof(passwd_buf), "Enter %s: ", opt);
                VR_EVP_read_pw_string(passwd_buf, sizeof(passwd_buf) - 1,
                                   passwd_buf, 0);
                passwd = OPENSSL_strdup(passwd_buf);
                if (passwd == NULL) {
                    VR_BIO_puts(bio_err, "out of memory\n");
                    goto end;
                }
            } else {
                /* Get password as a passin argument: First split option name
                 * and passphrase argument into two strings */
                *passin = 0;
                passin++;
                if (app_passwd(passin, NULL, &passwd, NULL) == 0) {
                    VR_BIO_printf(bio_err, "failed to get '%s'\n", opt);
                    goto end;
                }
            }

            if (VR_EVP_PKEY_CTX_ctrl_str(ctx, opt, passwd) <= 0) {
                VR_BIO_printf(bio_err, "%s: Can't set parameter \"%s\":\n",
                           prog, opt);
                goto end;
            }
            VR_OPENSSL_free(passwd);
        }
    }

    if (sigfile != NULL && (pkey_op != EVP_PKEY_OP_VERIFY)) {
        VR_BIO_printf(bio_err,
                   "%s: Signature file specified for non verify\n", prog);
        goto end;
    }

    if (sigfile == NULL && (pkey_op == EVP_PKEY_OP_VERIFY)) {
        VR_BIO_printf(bio_err,
                   "%s: No signature file specified for verify\n", prog);
        goto end;
    }

    if (pkey_op != EVP_PKEY_OP_DERIVE) {
        in = bio_open_default(infile, 'r', FORMAT_BINARY);
        if (in == NULL)
            goto end;
    }
    out = bio_open_default(outfile, 'w', FORMAT_BINARY);
    if (out == NULL)
        goto end;

    if (sigfile != NULL) {
        BIO *sigbio = VR_BIO_new_file(sigfile, "rb");

        if (sigbio == NULL) {
            VR_BIO_printf(bio_err, "Can't open signature file %s\n", sigfile);
            goto end;
        }
        siglen = bio_to_mem(&sig, keysize * 10, sigbio);
        VR_BIO_free(sigbio);
        if (siglen < 0) {
            VR_BIO_printf(bio_err, "Error reading signature data\n");
            goto end;
        }
    }

    if (in != NULL) {
        /* Read the input data */
        buf_inlen = bio_to_mem(&buf_in, keysize * 10, in);
        if (buf_inlen < 0) {
            VR_BIO_printf(bio_err, "Error reading input Data\n");
            goto end;
        }
        if (rev) {
            size_t i;
            unsigned char ctmp;
            size_t l = (size_t)buf_inlen;
            for (i = 0; i < l / 2; i++) {
                ctmp = buf_in[i];
                buf_in[i] = buf_in[l - 1 - i];
                buf_in[l - 1 - i] = ctmp;
            }
        }
    }

    /* Sanity check the input */
    if (buf_inlen > EVP_MAX_MD_SIZE
            && (pkey_op == EVP_PKEY_OP_SIGN
                || pkey_op == EVP_PKEY_OP_VERIFY
                || pkey_op == EVP_PKEY_OP_VERIFYRECOVER)) {
        VR_BIO_printf(bio_err,
                   "Error: The input data looks too long to be a hash\n");
        goto end;
    }

    if (pkey_op == EVP_PKEY_OP_VERIFY) {
        rv = VR_EVP_PKEY_verify(ctx, sig, (size_t)siglen,
                             buf_in, (size_t)buf_inlen);
        if (rv == 1) {
            VR_BIO_puts(out, "Signature Verified Successfully\n");
            ret = 0;
        } else {
            VR_BIO_puts(out, "Signature Verification Failure\n");
        }
        goto end;
    }
    if (kdflen != 0) {
        buf_outlen = kdflen;
        rv = 1;
    } else {
        rv = do_keyop(ctx, pkey_op, NULL, (size_t *)&buf_outlen,
                      buf_in, (size_t)buf_inlen);
    }
    if (rv > 0 && buf_outlen != 0) {
        buf_out = app_malloc(buf_outlen, "buffer output");
        rv = do_keyop(ctx, pkey_op,
                      buf_out, (size_t *)&buf_outlen,
                      buf_in, (size_t)buf_inlen);
    }
    if (rv <= 0) {
        if (pkey_op != EVP_PKEY_OP_DERIVE) {
            VR_BIO_puts(bio_err, "Public Key operation error\n");
        } else {
            VR_BIO_puts(bio_err, "Key derivation failed\n");
        }
        VR_ERR_print_errors(bio_err);
        goto end;
    }
    ret = 0;

    if (asn1parse) {
        if (!VR_ASN1_parse_dump(out, buf_out, buf_outlen, 1, -1))
            VR_ERR_print_errors(bio_err);
    } else if (hexdump) {
        VR_BIO_dump(out, (char *)buf_out, buf_outlen);
    } else {
        VR_BIO_write(out, buf_out, buf_outlen);
    }

 end:
    VR_EVP_PKEY_CTX_free(ctx);
    release_engine(e);
    VR_BIO_free(in);
    VR_BIO_free_all(out);
    VR_OPENSSL_free(buf_in);
    VR_OPENSSL_free(buf_out);
    VR_OPENSSL_free(sig);
    sk_VR_OPENSSL_STRING_free(pkeyopts);
    sk_VR_OPENSSL_STRING_free(pkeyopts_passin);
    return ret;
}

static EVP_PKEY_CTX *init_ctx(const char *kdfalg, int *pkeysize,
                              const char *keyfile, int keyform, int key_type,
                              char *passinarg, int pkey_op, ENGINE *e,
                              const int engine_impl)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    ENGINE *impl = NULL;
    char *passin = NULL;
    int rv = -1;
    X509 *x;
    if (((pkey_op == EVP_PKEY_OP_SIGN) || (pkey_op == EVP_PKEY_OP_DECRYPT)
         || (pkey_op == EVP_PKEY_OP_DERIVE))
        && (key_type != KEY_PRIVKEY && kdfalg == NULL)) {
        VR_BIO_printf(bio_err, "A private key is needed for this operation\n");
        goto end;
    }
    if (!app_passwd(passinarg, NULL, &passin, NULL)) {
        VR_BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }
    switch (key_type) {
    case KEY_PRIVKEY:
        pkey = load_key(keyfile, keyform, 0, passin, e, "Private Key");
        break;

    case KEY_PUBKEY:
        pkey = load_pubkey(keyfile, keyform, 0, NULL, e, "Public Key");
        break;

    case KEY_CERT:
        x = load_cert(keyfile, keyform, "Certificate");
        if (x) {
            pkey = VR_X509_get_pubkey(x);
            VR_X509_free(x);
        }
        break;

    case KEY_NONE:
        break;

    }

#ifndef OPENSSL_NO_ENGINE
    if (engine_impl)
        impl = e;
#endif

    if (kdfalg != NULL) {
        int kdfnid = VR_OBJ_sn2nid(kdfalg);

        if (kdfnid == NID_undef) {
            kdfnid = VR_OBJ_ln2nid(kdfalg);
            if (kdfnid == NID_undef) {
                VR_BIO_printf(bio_err, "The given KDF \"%s\" is unknown.\n",
                           kdfalg);
                goto end;
            }
        }
        ctx = VR_EVP_PKEY_CTX_new_id(kdfnid, impl);
    } else {
        if (pkey == NULL)
            goto end;
        *pkeysize = VR_EVP_PKEY_size(pkey);
        ctx = VR_EVP_PKEY_CTX_new(pkey, impl);
        VR_EVP_PKEY_free(pkey);
    }

    if (ctx == NULL)
        goto end;

    switch (pkey_op) {
    case EVP_PKEY_OP_SIGN:
        rv = VR_EVP_PKEY_sign_init(ctx);
        break;

    case EVP_PKEY_OP_VERIFY:
        rv = VR_EVP_PKEY_verify_init(ctx);
        break;

    case EVP_PKEY_OP_VERIFYRECOVER:
        rv = VR_EVP_PKEY_verify_recover_init(ctx);
        break;

    case EVP_PKEY_OP_ENCRYPT:
        rv = VR_EVP_PKEY_encrypt_init(ctx);
        break;

    case EVP_PKEY_OP_DECRYPT:
        rv = VR_EVP_PKEY_decrypt_init(ctx);
        break;

    case EVP_PKEY_OP_DERIVE:
        rv = VR_EVP_PKEY_derive_init(ctx);
        break;
    }

    if (rv <= 0) {
        VR_EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
    }

 end:
    VR_OPENSSL_free(passin);
    return ctx;

}

static int setup_peer(EVP_PKEY_CTX *ctx, int peerform, const char *file,
                      ENGINE *e)
{
    EVP_PKEY *peer = NULL;
    ENGINE *engine = NULL;
    int ret;

    if (peerform == FORMAT_ENGINE)
        engine = e;
    peer = load_pubkey(file, peerform, 0, NULL, engine, "Peer Key");
    if (peer == NULL) {
        VR_BIO_printf(bio_err, "Error reading peer key %s\n", file);
        VR_ERR_print_errors(bio_err);
        return 0;
    }

    ret = VR_EVP_PKEY_derive_set_peer(ctx, peer);

    VR_EVP_PKEY_free(peer);
    if (ret <= 0)
        VR_ERR_print_errors(bio_err);
    return ret;
}

static int do_keyop(EVP_PKEY_CTX *ctx, int pkey_op,
                    unsigned char *out, size_t *poutlen,
                    const unsigned char *in, size_t inlen)
{
    int rv = 0;
    switch (pkey_op) {
    case EVP_PKEY_OP_VERIFYRECOVER:
        rv = VR_EVP_PKEY_verify_recover(ctx, out, poutlen, in, inlen);
        break;

    case EVP_PKEY_OP_SIGN:
        rv = VR_EVP_PKEY_sign(ctx, out, poutlen, in, inlen);
        break;

    case EVP_PKEY_OP_ENCRYPT:
        rv = VR_EVP_PKEY_encrypt(ctx, out, poutlen, in, inlen);
        break;

    case EVP_PKEY_OP_DECRYPT:
        rv = VR_EVP_PKEY_decrypt(ctx, out, poutlen, in, inlen);
        break;

    case EVP_PKEY_OP_DERIVE:
        rv = VR_EVP_PKEY_derive(ctx, out, poutlen);
        break;

    }
    return rv;
}
