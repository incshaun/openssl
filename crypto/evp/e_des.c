/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#ifndef OPENSSL_NO_DES
# include <openssl/evp.h>
# include <openssl/objects.h>
# include "internal/evp_int.h"
# include <openssl/des.h>
# include <openssl/rand.h>

typedef struct {
    union {
        double align;
        VR_DES_key_schedule ks;
    } ks;
    union {
        void (*cbc) (const void *, void *, size_t,
                     const VR_DES_key_schedule *, unsigned char *);
    } stream;
} EVP_DES_KEY;

# if defined(AES_ASM) && (defined(__sparc) || defined(__sparc__))
/* ----------^^^ this is not a typo, just a way to detect that
 * assembler support was in general requested... */
#  include "sparc_arch.h"

extern unsigned int OPENSSL_sparcv9cap_P[];

#  define SPARC_DES_CAPABLE       (OPENSSL_sparcv9cap_P[1] & CFR_DES)

void des_t4_key_expand(const void *key, VR_DES_key_schedule *ks);
void des_t4_cbc_encrypt(const void *inp, void *out, size_t len,
                        const VR_DES_key_schedule *ks, unsigned char iv[8]);
void des_t4_cbc_decrypt(const void *inp, void *out, size_t len,
                        const VR_DES_key_schedule *ks, unsigned char iv[8]);
# endif

static int des_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc);
static int des_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr);

/*
 * Because of various casts and different names can't use
 * IMPLEMENT_BLOCK_CIPHER
 */

static int des_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t inl)
{
    BLOCK_CIPHER_ecb_loop()
        VR_DES_ecb_encrypt((DES_cblock *)(in + i), (DES_cblock *)(out + i),
                        VR_EVP_CIPHER_CTX_get_cipher_data(ctx),
                        VR_EVP_CIPHER_CTX_encrypting(ctx));
    return 1;
}

static int des_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t inl)
{
    while (inl >= EVP_MAXCHUNK) {
        int num = VR_EVP_CIPHER_CTX_num(ctx);
        VR_DES_ofb64_encrypt(in, out, (long)EVP_MAXCHUNK,
                          VR_EVP_CIPHER_CTX_get_cipher_data(ctx),
                          (DES_cblock *)VR_EVP_CIPHER_CTX_iv_noconst(ctx), &num);
        VR_EVP_CIPHER_CTX_set_num(ctx, num);
        inl -= EVP_MAXCHUNK;
        in += EVP_MAXCHUNK;
        out += EVP_MAXCHUNK;
    }
    if (inl) {
        int num = VR_EVP_CIPHER_CTX_num(ctx);
        VR_DES_ofb64_encrypt(in, out, (long)inl,
                          VR_EVP_CIPHER_CTX_get_cipher_data(ctx),
                          (DES_cblock *)VR_EVP_CIPHER_CTX_iv_noconst(ctx), &num);
        VR_EVP_CIPHER_CTX_set_num(ctx, num);
    }
    return 1;
}

static int des_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t inl)
{
    EVP_DES_KEY *dat = (EVP_DES_KEY *) VR_EVP_CIPHER_CTX_get_cipher_data(ctx);

    if (dat->stream.cbc != NULL) {
        (*dat->stream.cbc) (in, out, inl, &dat->ks.ks,
                            VR_EVP_CIPHER_CTX_iv_noconst(ctx));
        return 1;
    }
    while (inl >= EVP_MAXCHUNK) {
        VR_DES_ncbc_encrypt(in, out, (long)EVP_MAXCHUNK,
                         VR_EVP_CIPHER_CTX_get_cipher_data(ctx),
                         (DES_cblock *)VR_EVP_CIPHER_CTX_iv_noconst(ctx),
                         VR_EVP_CIPHER_CTX_encrypting(ctx));
        inl -= EVP_MAXCHUNK;
        in += EVP_MAXCHUNK;
        out += EVP_MAXCHUNK;
    }
    if (inl)
        VR_DES_ncbc_encrypt(in, out, (long)inl,
                         VR_EVP_CIPHER_CTX_get_cipher_data(ctx),
                         (DES_cblock *)VR_EVP_CIPHER_CTX_iv_noconst(ctx),
                         VR_EVP_CIPHER_CTX_encrypting(ctx));
    return 1;
}

static int des_cfb64_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            const unsigned char *in, size_t inl)
{
    while (inl >= EVP_MAXCHUNK) {
        int num = VR_EVP_CIPHER_CTX_num(ctx);
        VR_DES_cfb64_encrypt(in, out, (long)EVP_MAXCHUNK,
                          VR_EVP_CIPHER_CTX_get_cipher_data(ctx),
                          (DES_cblock *)VR_EVP_CIPHER_CTX_iv_noconst(ctx), &num,
                          VR_EVP_CIPHER_CTX_encrypting(ctx));
        VR_EVP_CIPHER_CTX_set_num(ctx, num);
        inl -= EVP_MAXCHUNK;
        in += EVP_MAXCHUNK;
        out += EVP_MAXCHUNK;
    }
    if (inl) {
        int num = VR_EVP_CIPHER_CTX_num(ctx);
        VR_DES_cfb64_encrypt(in, out, (long)inl,
                          VR_EVP_CIPHER_CTX_get_cipher_data(ctx),
                          (DES_cblock *)VR_EVP_CIPHER_CTX_iv_noconst(ctx), &num,
                          VR_EVP_CIPHER_CTX_encrypting(ctx));
        VR_EVP_CIPHER_CTX_set_num(ctx, num);
    }
    return 1;
}

/*
 * Although we have a CFB-r implementation for DES, it doesn't pack the right
 * way, so wrap it here
 */
static int des_cfb1_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t inl)
{
    size_t n, chunk = EVP_MAXCHUNK / 8;
    unsigned char c[1], d[1];

    if (inl < chunk)
        chunk = inl;

    while (inl && inl >= chunk) {
        for (n = 0; n < chunk * 8; ++n) {
            c[0] = (in[n / 8] & (1 << (7 - n % 8))) ? 0x80 : 0;
            VR_DES_cfb_encrypt(c, d, 1, 1, VR_EVP_CIPHER_CTX_get_cipher_data(ctx),
                            (DES_cblock *)VR_EVP_CIPHER_CTX_iv_noconst(ctx),
                            VR_EVP_CIPHER_CTX_encrypting(ctx));
            out[n / 8] =
                (out[n / 8] & ~(0x80 >> (unsigned int)(n % 8))) |
                ((d[0] & 0x80) >> (unsigned int)(n % 8));
        }
        inl -= chunk;
        in += chunk;
        out += chunk;
        if (inl < chunk)
            chunk = inl;
    }

    return 1;
}

static int des_cfb8_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t inl)
{
    while (inl >= EVP_MAXCHUNK) {
        VR_DES_cfb_encrypt(in, out, 8, (long)EVP_MAXCHUNK,
                        VR_EVP_CIPHER_CTX_get_cipher_data(ctx),
                        (DES_cblock *)VR_EVP_CIPHER_CTX_iv_noconst(ctx),
                        VR_EVP_CIPHER_CTX_encrypting(ctx));
        inl -= EVP_MAXCHUNK;
        in += EVP_MAXCHUNK;
        out += EVP_MAXCHUNK;
    }
    if (inl)
        VR_DES_cfb_encrypt(in, out, 8, (long)inl,
                        VR_EVP_CIPHER_CTX_get_cipher_data(ctx),
                        (DES_cblock *)VR_EVP_CIPHER_CTX_iv_noconst(ctx),
                        VR_EVP_CIPHER_CTX_encrypting(ctx));
    return 1;
}

BLOCK_CIPHER_defs(des, EVP_DES_KEY, NID_des, 8, 8, 8, 64,
                  EVP_CIPH_RAND_KEY, des_init_key, NULL,
                  VR_EVP_CIPHER_set_asn1_iv, VR_EVP_CIPHER_get_asn1_iv, des_ctrl)

    BLOCK_CIPHER_def_cfb(des, EVP_DES_KEY, NID_des, 8, 8, 1,
                     EVP_CIPH_RAND_KEY, des_init_key, NULL,
                     VR_EVP_CIPHER_set_asn1_iv, VR_EVP_CIPHER_get_asn1_iv, des_ctrl)

    BLOCK_CIPHER_def_cfb(des, EVP_DES_KEY, NID_des, 8, 8, 8,
                     EVP_CIPH_RAND_KEY, des_init_key, NULL,
                     VR_EVP_CIPHER_set_asn1_iv, VR_EVP_CIPHER_get_asn1_iv, des_ctrl)

static int des_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc)
{
    DES_cblock *deskey = (DES_cblock *)key;
    EVP_DES_KEY *dat = (EVP_DES_KEY *) VR_EVP_CIPHER_CTX_get_cipher_data(ctx);

    dat->stream.cbc = NULL;
# if defined(SPARC_DES_CAPABLE)
    if (SPARC_DES_CAPABLE) {
        int mode = EVP_CIPHER_CTX_mode(ctx);

        if (mode == EVP_CIPH_CBC_MODE) {
            des_t4_key_expand(key, &dat->ks.ks);
            dat->stream.cbc = enc ? des_t4_cbc_encrypt : des_t4_cbc_decrypt;
            return 1;
        }
    }
# endif
    VR_DES_set_key_unchecked(deskey, VR_EVP_CIPHER_CTX_get_cipher_data(ctx));
    return 1;
}

static int des_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{

    switch (type) {
    case EVP_CTRL_RAND_KEY:
        if (VR_RAND_priv_bytes(ptr, 8) <= 0)
            return 0;
        VR_DES_set_odd_parity((DES_cblock *)ptr);
        return 1;

    default:
        return -1;
    }
}

#endif
