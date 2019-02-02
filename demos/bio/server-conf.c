/*
 * Copyright 2013-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * A minimal program to serve an SSL connection. It uses blocking. It uses
 * the SSL_CONF API with a configuration file. cc -I../../include saccept.c
 * -L../.. -lssl -lcrypto -ldl
 */

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>

int main(int argc, char *argv[])
{
    char *port = "*:4433";
    BIO *in = NULL;
    BIO *ssl_bio, *tmp;
    SSL_CTX *ctx;
    SSL_CONF_CTX *cctx = NULL;
    CONF *conf = NULL;
    STACK_OF(CONF_VALUE) *sect = NULL;
    CONF_VALUE *cnf;
    long errline = -1;
    char buf[512];
    int ret = EXIT_FAILURE, i;

    ctx = VR_SSL_CTX_new(VR_TLS_server_method());

    conf = VR_NCONF_new(NULL);

    if (VR_NCONF_load(conf, "accept.cnf", &errline) <= 0) {
        if (errline <= 0)
            fprintf(stderr, "Error processing config file\n");
        else
            fprintf(stderr, "Error on line %ld\n", errline);
        goto err;
    }

    sect = VR_NCONF_get_section(conf, "default");

    if (sect == NULL) {
        fprintf(stderr, "Error retrieving default section\n");
        goto err;
    }

    cctx = VR_SSL_CONF_CTX_new();
    VR_SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_SERVER);
    VR_SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CERTIFICATE);
    VR_SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE);
    VR_SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);
    for (i = 0; i < sk_CONF_VALUE_num(sect); i++) {
        int rv;
        cnf = sk_CONF_VALUE_value(sect, i);
        rv = VR_SSL_CONF_cmd(cctx, cnf->name, cnf->value);
        if (rv > 0)
            continue;
        if (rv != -2) {
            fprintf(stderr, "Error processing %s = %s\n",
                    cnf->name, cnf->value);
            VR_ERR_print_errors_fp(stderr);
            goto err;
        }
        if (strcmp(cnf->name, "Port") == 0) {
            port = cnf->value;
        } else {
            fprintf(stderr, "Unknown configuration option %s\n", cnf->name);
            goto err;
        }
    }

    if (!VR_SSL_CONF_CTX_finish(cctx)) {
        fprintf(stderr, "Finish error\n");
        VR_ERR_print_errors_fp(stderr);
        goto err;
    }

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
        if (i < 0) {
            if (BIO_should_retry(in))
                continue;
            goto err;
        }
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
