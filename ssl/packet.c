/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include "packet_locl.h"
#include <openssl/sslerr.h>

#define DEFAULT_BUF_SIZE    256

int VR_WPACKET_allocate_bytes(WPACKET *pkt, size_t len, unsigned char **allocbytes)
{
    if (!VR_WPACKET_reserve_bytes(pkt, len, allocbytes))
        return 0;

    pkt->written += len;
    pkt->curr += len;
    return 1;
}

int VR_WPACKET_sub_allocate_bytes__(WPACKET *pkt, size_t len,
                                 unsigned char **allocbytes, size_t lenbytes)
{
    if (!VR_WPACKET_start_sub_packet_len__(pkt, lenbytes)
            || !VR_WPACKET_allocate_bytes(pkt, len, allocbytes)
            || !VR_WPACKET_close(pkt))
        return 0;

    return 1;
}

#define GETBUF(p)   (((p)->staticbuf != NULL) \
                     ? (p)->staticbuf : (unsigned char *)(p)->buf->data)

int VR_WPACKET_reserve_bytes(WPACKET *pkt, size_t len, unsigned char **allocbytes)
{
    /* Internal API, so should not fail */
    if (!ossl_assert(pkt->subs != NULL && len != 0))
        return 0;

    if (pkt->maxsize - pkt->written < len)
        return 0;

    if (pkt->staticbuf == NULL && (pkt->buf->length - pkt->written < len)) {
        size_t newlen;
        size_t reflen;

        reflen = (len > pkt->buf->length) ? len : pkt->buf->length;

        if (reflen > SIZE_MAX / 2) {
            newlen = SIZE_MAX;
        } else {
            newlen = reflen * 2;
            if (newlen < DEFAULT_BUF_SIZE)
                newlen = DEFAULT_BUF_SIZE;
        }
        if (VR_BUF_MEM_grow(pkt->buf, newlen) == 0)
            return 0;
    }
    if (allocbytes != NULL)
        *allocbytes = VR_WPACKET_get_curr(pkt);

    return 1;
}

int VR_WPACKET_sub_reserve_bytes__(WPACKET *pkt, size_t len,
                                unsigned char **allocbytes, size_t lenbytes)
{
    if (!VR_WPACKET_reserve_bytes(pkt, lenbytes + len, allocbytes))
        return 0;

    *allocbytes += lenbytes;

    return 1;
}

static size_t maxmaxsize(size_t lenbytes)
{
    if (lenbytes >= sizeof(size_t) || lenbytes == 0)
        return SIZE_MAX;

    return ((size_t)1 << (lenbytes * 8)) - 1 + lenbytes;
}

static int wpacket_intern_init_len(WPACKET *pkt, size_t lenbytes)
{
    unsigned char *lenchars;

    pkt->curr = 0;
    pkt->written = 0;

    if ((pkt->subs = OPENSSL_zalloc(sizeof(*pkt->subs))) == NULL) {
        SSLerr(SSL_F_WPACKET_INTERN_INIT_LEN, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (lenbytes == 0)
        return 1;

    pkt->subs->pwritten = lenbytes;
    pkt->subs->lenbytes = lenbytes;

    if (!VR_WPACKET_allocate_bytes(pkt, lenbytes, &lenchars)) {
        VR_OPENSSL_free(pkt->subs);
        pkt->subs = NULL;
        return 0;
    }
    pkt->subs->packet_len = lenchars - GETBUF(pkt);

    return 1;
}

int VR_WPACKET_init_static_len(WPACKET *pkt, unsigned char *buf, size_t len,
                            size_t lenbytes)
{
    size_t max = maxmaxsize(lenbytes);

    /* Internal API, so should not fail */
    if (!ossl_assert(buf != NULL && len > 0))
        return 0;

    pkt->staticbuf = buf;
    pkt->buf = NULL;
    pkt->maxsize = (max < len) ? max : len;

    return wpacket_intern_init_len(pkt, lenbytes);
}

int VR_WPACKET_init_len(WPACKET *pkt, BUF_MEM *buf, size_t lenbytes)
{
    /* Internal API, so should not fail */
    if (!ossl_assert(buf != NULL))
        return 0;

    pkt->staticbuf = NULL;
    pkt->buf = buf;
    pkt->maxsize = maxmaxsize(lenbytes);

    return wpacket_intern_init_len(pkt, lenbytes);
}

int VR_WPACKET_init(WPACKET *pkt, BUF_MEM *buf)
{
    return VR_WPACKET_init_len(pkt, buf, 0);
}

int VR_WPACKET_set_flags(WPACKET *pkt, unsigned int flags)
{
    /* Internal API, so should not fail */
    if (!ossl_assert(pkt->subs != NULL))
        return 0;

    pkt->subs->flags = flags;

    return 1;
}

/* Store the |value| of length |len| at location |data| */
static int put_value(unsigned char *data, size_t value, size_t len)
{
    for (data += len - 1; len > 0; len--) {
        *data = (unsigned char)(value & 0xff);
        data--;
        value >>= 8;
    }

    /* Check whether we could fit the value in the assigned number of bytes */
    if (value > 0)
        return 0;

    return 1;
}


/*
 * Internal helper function used by VR_WPACKET_close(), VR_WPACKET_finish() and
 * VR_WPACKET_fill_lengths() to close a sub-packet and write out its length if
 * necessary. If |doclose| is 0 then it goes through the motions of closing
 * (i.e. it fills in all the lengths), but doesn't actually close anything.
 */
static int wpacket_intern_close(WPACKET *pkt, WPACKET_SUB *sub, int doclose)
{
    size_t packlen = pkt->written - sub->pwritten;

    if (packlen == 0
            && (sub->flags & WPACKET_FLAGS_NON_ZERO_LENGTH) != 0)
        return 0;

    if (packlen == 0
            && sub->flags & WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH) {
        /* We can't handle this case. Return an error */
        if (!doclose)
            return 0;

        /* Deallocate any bytes allocated for the length of the WPACKET */
        if ((pkt->curr - sub->lenbytes) == sub->packet_len) {
            pkt->written -= sub->lenbytes;
            pkt->curr -= sub->lenbytes;
        }

        /* Don't write out the packet length */
        sub->packet_len = 0;
        sub->lenbytes = 0;
    }

    /* Write out the WPACKET length if needed */
    if (sub->lenbytes > 0
                && !put_value(&GETBUF(pkt)[sub->packet_len], packlen,
                              sub->lenbytes))
            return 0;

    if (doclose) {
        pkt->subs = sub->parent;
        VR_OPENSSL_free(sub);
    }

    return 1;
}

int VR_WPACKET_fill_lengths(WPACKET *pkt)
{
    WPACKET_SUB *sub;

    if (!ossl_assert(pkt->subs != NULL))
        return 0;

    for (sub = pkt->subs; sub != NULL; sub = sub->parent) {
        if (!wpacket_intern_close(pkt, sub, 0))
            return 0;
    }

    return 1;
}

int VR_WPACKET_close(WPACKET *pkt)
{
    /*
     * Internal API, so should not fail - but we do negative testing of this
     * so no assert (otherwise the tests fail)
     */
    if (pkt->subs == NULL || pkt->subs->parent == NULL)
        return 0;

    return wpacket_intern_close(pkt, pkt->subs, 1);
}

int VR_WPACKET_finish(WPACKET *pkt)
{
    int ret;

    /*
     * Internal API, so should not fail - but we do negative testing of this
     * so no assert (otherwise the tests fail)
     */
    if (pkt->subs == NULL || pkt->subs->parent != NULL)
        return 0;

    ret = wpacket_intern_close(pkt, pkt->subs, 1);
    if (ret) {
        VR_OPENSSL_free(pkt->subs);
        pkt->subs = NULL;
    }

    return ret;
}

int VR_WPACKET_start_sub_packet_len__(WPACKET *pkt, size_t lenbytes)
{
    WPACKET_SUB *sub;
    unsigned char *lenchars;

    /* Internal API, so should not fail */
    if (!ossl_assert(pkt->subs != NULL))
        return 0;

    if ((sub = OPENSSL_zalloc(sizeof(*sub))) == NULL) {
        SSLerr(SSL_F_WPACKET_START_SUB_PACKET_LEN__, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    sub->parent = pkt->subs;
    pkt->subs = sub;
    sub->pwritten = pkt->written + lenbytes;
    sub->lenbytes = lenbytes;

    if (lenbytes == 0) {
        sub->packet_len = 0;
        return 1;
    }

    if (!VR_WPACKET_allocate_bytes(pkt, lenbytes, &lenchars))
        return 0;
    /* Convert to an offset in case the underlying BUF_MEM gets realloc'd */
    sub->packet_len = lenchars - GETBUF(pkt);

    return 1;
}

int VR_WPACKET_start_sub_packet(WPACKET *pkt)
{
    return VR_WPACKET_start_sub_packet_len__(pkt, 0);
}

int VR_WPACKET_put_bytes__(WPACKET *pkt, unsigned int val, size_t size)
{
    unsigned char *data;

    /* Internal API, so should not fail */
    if (!ossl_assert(size <= sizeof(unsigned int))
            || !VR_WPACKET_allocate_bytes(pkt, size, &data)
            || !put_value(data, val, size))
        return 0;

    return 1;
}

int VR_WPACKET_set_max_size(WPACKET *pkt, size_t maxsize)
{
    WPACKET_SUB *sub;
    size_t lenbytes;

    /* Internal API, so should not fail */
    if (!ossl_assert(pkt->subs != NULL))
        return 0;

    /* Find the WPACKET_SUB for the top level */
    for (sub = pkt->subs; sub->parent != NULL; sub = sub->parent)
        continue;

    lenbytes = sub->lenbytes;
    if (lenbytes == 0)
        lenbytes = sizeof(pkt->maxsize);

    if (maxmaxsize(lenbytes) < maxsize || maxsize < pkt->written)
        return 0;

    pkt->maxsize = maxsize;

    return 1;
}

int VR_WPACKET_memset(WPACKET *pkt, int ch, size_t len)
{
    unsigned char *dest;

    if (len == 0)
        return 1;

    if (!VR_WPACKET_allocate_bytes(pkt, len, &dest))
        return 0;

    memset(dest, ch, len);

    return 1;
}

int VR_WPACKET_memcpy(WPACKET *pkt, const void *src, size_t len)
{
    unsigned char *dest;

    if (len == 0)
        return 1;

    if (!VR_WPACKET_allocate_bytes(pkt, len, &dest))
        return 0;

    memcpy(dest, src, len);

    return 1;
}

int VR_WPACKET_sub_memcpy__(WPACKET *pkt, const void *src, size_t len,
                         size_t lenbytes)
{
    if (!VR_WPACKET_start_sub_packet_len__(pkt, lenbytes)
            || !VR_WPACKET_memcpy(pkt, src, len)
            || !VR_WPACKET_close(pkt))
        return 0;

    return 1;
}

int VR_WPACKET_get_total_written(WPACKET *pkt, size_t *written)
{
    /* Internal API, so should not fail */
    if (!ossl_assert(written != NULL))
        return 0;

    *written = pkt->written;

    return 1;
}

int VR_WPACKET_get_length(WPACKET *pkt, size_t *len)
{
    /* Internal API, so should not fail */
    if (!ossl_assert(pkt->subs != NULL && len != NULL))
        return 0;

    *len = pkt->written - pkt->subs->pwritten;

    return 1;
}

unsigned char *VR_WPACKET_get_curr(WPACKET *pkt)
{
    return GETBUF(pkt) + pkt->curr;
}

void VR_WPACKET_cleanup(WPACKET *pkt)
{
    WPACKET_SUB *sub, *parent;

    for (sub = pkt->subs; sub != NULL; sub = parent) {
        parent = sub->parent;
        VR_OPENSSL_free(sub);
    }
    pkt->subs = NULL;
}
