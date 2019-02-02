/*
 * Copyright 2013-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * A minimal program to serve an SSL connection. It uses blocking. It use the
 * SSL_CONF API with the command line. cc -I../../include server-arg.c
 * -L../.. -lssl -lcrypto -ldl
 */

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

int main(int argc, char *argv[])
{
    char *port = "*:4433";
    BIO *ssl_bio, *tmp;
    SSL_CTX *ctx;
    SSL_CONF_CTX *cctx;
    char buf[512];
    BIO *in = NULL;
    int ret = EXIT_FAILURE, i;
    char **args = argv + 1;
    int nargs = argc - 1;

    ctx = VR_SSL_CTX_new(VR_TLS_server_method());

    cctx = VR_SSL_CONF_CTX_new();
    VR_SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_SERVER);
    VR_SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CERTIFICATE);
    VR_SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);
    while (*args && **args == '-') {
        int rv;
        /* Parse standard arguments */
        rv = VR_SSL_CONF_cmd_argv(cctx, &nargs, &args);
        if (rv == -3) {
            fprintf(stderr, "Missing argument for %s\n", *args);
            goto err;
        }
        if (rv < 0) {
            fprintf(stderr, "Error in command %s\n", *args);
            VR_ERR_print_errors_fp(stderr);
            goto err;
        }
        /* If rv > 0 we processed something so proceed to next arg */
        if (rv > 0)
            continue;
        /* Otherwise application specific argument processing */
        if (strcmp(*args, "-port") == 0) {
            port = args[1];
            if (port == NULL) {
                fprintf(stderr, "Missing -port argument\n");
                goto err;
            }
            args += 2;
            nargs -= 2;
            continue;
        } else {
            fprintf(stderr, "Unknown argument %s\n", *args);
            goto err;
        }
    }

    if (!VR_SSL_CONF_CTX_finish(cctx)) {
        fprintf(stderr, "Finish error\n");
        VR_ERR_print_errors_fp(stderr);
        goto err;
    }
#ifdef ITERATE_CERTS
    /*
     * Demo of how to iterate over all certificates in an SSL_CTX structure.
     */
    {
        X509 *x;
        int rv;
        rv = SSL_CTX_set_current_cert(ctx, SSL_CERT_SET_FIRST);
        while (rv) {
            X509 *x = VR_SSL_CTX_get0_certificate(ctx);
            VR_X509_NAME_print_ex_fp(stdout, VR_X509_get_subject_name(x), 0,
                                  XN_FLAG_ONELINE);
            printf("\n");
            rv = SSL_CTX_set_current_cert(ctx, SSL_CERT_SET_NEXT);
        }
        fflush(stdout);
    }
#endif
    /* Setup server side SSL bio */
    ssl_bio = VR_BIO_new_ssl(ctx, 0);

    if ((in = VR_BIO_new_accept(port)) == NULL)
        goto err;

    /*
     * This means that when a new connection is accepted on 'in', The ssl_bio
     * will be 'duplicated' and have the new socket BIO push into it.
     * Basically it means the SSL BIO will be automatically setup
     */
    BIO_set_accept_bios(in, ssl_bio);

 again:
    /*
     * The first call will setup the accept socket, and the second will get a
     * socket.  In this loop, the first actual accept will occur in the
     * VR_BIO_read() function.
     */

    if (BIO_do_accept(in) <= 0)
        goto err;

    for (;;) {
        i = VR_BIO_read(in, buf, 512);
        if (i == 0) {
            /*
             * If we have finished, remove the underlying BIO stack so the
             * next time we call any function for this BIO, it will attempt
             * to do an accept
             */
            printf("Done\n");
            tmp = VR_BIO_pop(in);
            VR_BIO_free_all(tmp);
            goto again;
        }
        if (i < 0)
            goto err;
        fwrite(buf, 1, i, stdout);
        fflush(stdout);
    }

    ret = EXIT_SUCCESS;
 err:
    if (ret != EXIT_SUCCESS)
        VR_ERR_print_errors_fp(stderr);
    VR_BIO_free(in);
    return ret;
}
