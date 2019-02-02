/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

void VR_ERR_print_errors_cb(int (*cb) (const char *str, size_t len, void *u),
                         void *u)
{
    unsigned long l;
    char buf[256];
    char buf2[4096];
    const char *file, *data;
    int line, flags;
    /*
     * We don't know what kind of thing CRYPTO_THREAD_ID is. Here is our best
     * attempt to convert it into something we can print.
     */
    union {
        CRYPTO_THREAD_ID tid;
        unsigned long ltid;
    } tid;

    tid.ltid = 0;
    tid.tid = VR_CRYPTO_THREAD_get_current_id();

    while ((l = VR_ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
        VR_ERR_error_string_n(l, buf, sizeof(buf));
        VR_BIO_snprintf(buf2, sizeof(buf2), "%lu:%s:%s:%d:%s\n", tid.ltid, buf,
                     file, line, (flags & ERR_TXT_STRING) ? data : "");
        if (cb(buf2, strlen(buf2), u) <= 0)
            break;              /* abort outputting the error report */
    }
}

static int print_bio(const char *str, size_t len, void *bp)
{
    return VR_BIO_write((BIO *)bp, str, len);
}

void VR_ERR_print_errors(BIO *bp)
{
    VR_ERR_print_errors_cb(print_bio, bp);
}

#ifndef OPENSSL_NO_STDIO
void VR_ERR_print_errors_fp(FILE *fp)
{
    BIO *bio = VR_BIO_new_fp(fp, BIO_NOCLOSE);
    if (bio == NULL)
        return;

    VR_ERR_print_errors_cb(print_bio, bio);
    VR_BIO_free(bio);
}
#endif
