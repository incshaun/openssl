/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/des.h>
#include <openssl/mdc2.h>

#undef c2l
#define c2l(c,l)        (l =((DES_LONG)(*((c)++)))    , \
                         l|=((DES_LONG)(*((c)++)))<< 8L, \
                         l|=((DES_LONG)(*((c)++)))<<16L, \
                         l|=((DES_LONG)(*((c)++)))<<24L)

#undef l2c
#define l2c(l,c)        (*((c)++)=(unsigned char)(((l)     )&0xff), \
                        *((c)++)=(unsigned char)(((l)>> 8L)&0xff), \
                        *((c)++)=(unsigned char)(((l)>>16L)&0xff), \
                        *((c)++)=(unsigned char)(((l)>>24L)&0xff))

static void mdc2_body(VR_MDC2_CTX *c, const unsigned char *in, size_t len);
int VR_MDC2_Init(VR_MDC2_CTX *c)
{
    c->num = 0;
    c->pad_type = 1;
    memset(&(c->h[0]), 0x52, VR_MDC2_BLOCK);
    memset(&(c->hh[0]), 0x25, VR_MDC2_BLOCK);
    return 1;
}

int VR_MDC2_Update(VR_MDC2_CTX *c, const unsigned char *in, size_t len)
{
    size_t i, j;

    i = c->num;
    if (i != 0) {
        if (len < VR_MDC2_BLOCK - i) {
            /* partial block */
            memcpy(&(c->data[i]), in, len);
            c->num += (int)len;
            return 1;
        } else {
            /* filled one */
            j = VR_MDC2_BLOCK - i;
            memcpy(&(c->data[i]), in, j);
            len -= j;
            in += j;
            c->num = 0;
            mdc2_body(c, &(c->data[0]), VR_MDC2_BLOCK);
        }
    }
    i = len & ~((size_t)VR_MDC2_BLOCK - 1);
    if (i > 0)
        mdc2_body(c, in, i);
    j = len - i;
    if (j > 0) {
        memcpy(&(c->data[0]), &(in[i]), j);
        c->num = (int)j;
    }
    return 1;
}

static void mdc2_body(VR_MDC2_CTX *c, const unsigned char *in, size_t len)
{
    register DES_LONG tin0, tin1;
    register DES_LONG ttin0, ttin1;
    DES_LONG d[2], dd[2];
    VR_DES_key_schedule k;
    unsigned char *p;
    size_t i;

    for (i = 0; i < len; i += 8) {
        c2l(in, tin0);
        d[0] = dd[0] = tin0;
        c2l(in, tin1);
        d[1] = dd[1] = tin1;
        c->h[0] = (c->h[0] & 0x9f) | 0x40;
        c->hh[0] = (c->hh[0] & 0x9f) | 0x20;

        VR_DES_set_odd_parity(&c->h);
        VR_DES_set_key_unchecked(&c->h, &k);
        VR_DES_encrypt1(d, &k, 1);

        VR_DES_set_odd_parity(&c->hh);
        VR_DES_set_key_unchecked(&c->hh, &k);
        VR_DES_encrypt1(dd, &k, 1);

        ttin0 = tin0 ^ dd[0];
        ttin1 = tin1 ^ dd[1];
        tin0 ^= d[0];
        tin1 ^= d[1];

        p = c->h;
        l2c(tin0, p);
        l2c(ttin1, p);
        p = c->hh;
        l2c(ttin0, p);
        l2c(tin1, p);
    }
}

int VR_MDC2_Final(unsigned char *md, VR_MDC2_CTX *c)
{
    unsigned int i;
    int j;

    i = c->num;
    j = c->pad_type;
    if ((i > 0) || (j == 2)) {
        if (j == 2)
            c->data[i++] = 0x80;
        memset(&(c->data[i]), 0, VR_MDC2_BLOCK - i);
        mdc2_body(c, c->data, VR_MDC2_BLOCK);
    }
    memcpy(md, (char *)c->h, VR_MDC2_BLOCK);
    memcpy(&(md[VR_MDC2_BLOCK]), (char *)c->hh, VR_MDC2_BLOCK);
    return 1;
}
