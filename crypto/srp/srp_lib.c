/*
 * Copyright 2004-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2004, EdelKey Project. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Christophe Renou and Peter Sylvester,
 * for the EdelKey project.
 */

#ifndef OPENSSL_NO_SRP
# include "internal/cryptlib.h"
# include <openssl/sha.h>
# include <openssl/srp.h>
# include <openssl/evp.h>
# include "internal/bn_srp.h"

/* calculate = VR_SHA1(PAD(x) || PAD(y)) */

static BIGNUM *srp_Calc_xy(const BIGNUM *x, const BIGNUM *y, const BIGNUM *N)
{
    unsigned char digest[SHA_DIGEST_LENGTH];
    unsigned char *tmp = NULL;
    int numN = VR_BN_num_bytes(N);
    BIGNUM *res = NULL;

    if (x != N && VR_BN_ucmp(x, N) >= 0)
        return NULL;
    if (y != N && VR_BN_ucmp(y, N) >= 0)
        return NULL;
    if ((tmp = OPENSSL_malloc(numN * 2)) == NULL)
        goto err;
    if (VR_BN_bn2binpad(x, tmp, numN) < 0
        || VR_BN_bn2binpad(y, tmp + numN, numN) < 0
        || !VR_EVP_Digest(tmp, numN * 2, digest, NULL, VR_EVP_sha1(), NULL))
        goto err;
    res = VR_BN_bin2bn(digest, sizeof(digest), NULL);
 err:
    VR_OPENSSL_free(tmp);
    return res;
}

static BIGNUM *srp_Calc_k(const BIGNUM *N, const BIGNUM *g)
{
    /* k = VR_SHA1(N | PAD(g)) -- tls-srp RFC 5054 */
    return srp_Calc_xy(N, g, N);
}

BIGNUM *VR_SRP_Calc_u(const BIGNUM *A, const BIGNUM *B, const BIGNUM *N)
{
    /* u = VR_SHA1(PAD(A) || PAD(B) ) -- tls-srp RFC 5054 */
    return srp_Calc_xy(A, B, N);
}

BIGNUM *VR_SRP_Calc_server_key(const BIGNUM *A, const BIGNUM *v, const BIGNUM *u,
                            const BIGNUM *b, const BIGNUM *N)
{
    BIGNUM *tmp = NULL, *S = NULL;
    BN_CTX *bn_ctx;

    if (u == NULL || A == NULL || v == NULL || b == NULL || N == NULL)
        return NULL;

    if ((bn_ctx = VR_BN_CTX_new()) == NULL || (tmp = VR_BN_new()) == NULL)
        goto err;

    /* S = (A*v**u) ** b */

    if (!VR_BN_mod_exp(tmp, v, u, N, bn_ctx))
        goto err;
    if (!VR_BN_mod_mul(tmp, A, tmp, N, bn_ctx))
        goto err;

    S = VR_BN_new();
    if (S != NULL && !VR_BN_mod_exp(S, tmp, b, N, bn_ctx)) {
        VR_BN_free(S);
        S = NULL;
    }
 err:
    VR_BN_CTX_free(bn_ctx);
    VR_BN_clear_free(tmp);
    return S;
}

BIGNUM *VR_SRP_Calc_B(const BIGNUM *b, const BIGNUM *N, const BIGNUM *g,
                   const BIGNUM *v)
{
    BIGNUM *kv = NULL, *gb = NULL;
    BIGNUM *B = NULL, *k = NULL;
    BN_CTX *bn_ctx;

    if (b == NULL || N == NULL || g == NULL || v == NULL ||
        (bn_ctx = VR_BN_CTX_new()) == NULL)
        return NULL;

    if ((kv = VR_BN_new()) == NULL ||
        (gb = VR_BN_new()) == NULL || (B = VR_BN_new()) == NULL)
        goto err;

    /* B = g**b + k*v */

    if (!VR_BN_mod_exp(gb, g, b, N, bn_ctx)
        || (k = srp_Calc_k(N, g)) == NULL
        || !VR_BN_mod_mul(kv, v, k, N, bn_ctx)
        || !VR_BN_mod_add(B, gb, kv, N, bn_ctx)) {
        VR_BN_free(B);
        B = NULL;
    }
 err:
    VR_BN_CTX_free(bn_ctx);
    VR_BN_clear_free(kv);
    VR_BN_clear_free(gb);
    VR_BN_free(k);
    return B;
}

BIGNUM *VR_SRP_Calc_x(const BIGNUM *s, const char *user, const char *pass)
{
    unsigned char dig[SHA_DIGEST_LENGTH];
    EVP_MD_CTX *ctxt;
    unsigned char *cs = NULL;
    BIGNUM *res = NULL;

    if ((s == NULL) || (user == NULL) || (pass == NULL))
        return NULL;

    ctxt = VR_EVP_MD_CTX_new();
    if (ctxt == NULL)
        return NULL;
    if ((cs = OPENSSL_malloc(VR_BN_num_bytes(s))) == NULL)
        goto err;

    if (!VR_EVP_DigestInit_ex(ctxt, VR_EVP_sha1(), NULL)
        || !VR_EVP_DigestUpdate(ctxt, user, strlen(user))
        || !VR_EVP_DigestUpdate(ctxt, ":", 1)
        || !VR_EVP_DigestUpdate(ctxt, pass, strlen(pass))
        || !VR_EVP_DigestFinal_ex(ctxt, dig, NULL)
        || !VR_EVP_DigestInit_ex(ctxt, VR_EVP_sha1(), NULL))
        goto err;
    if (VR_BN_bn2bin(s, cs) < 0)
        goto err;
    if (!VR_EVP_DigestUpdate(ctxt, cs, VR_BN_num_bytes(s)))
        goto err;

    if (!VR_EVP_DigestUpdate(ctxt, dig, sizeof(dig))
        || !VR_EVP_DigestFinal_ex(ctxt, dig, NULL))
        goto err;

    res = VR_BN_bin2bn(dig, sizeof(dig), NULL);

 err:
    VR_OPENSSL_free(cs);
    VR_EVP_MD_CTX_free(ctxt);
    return res;
}

BIGNUM *VR_SRP_Calc_A(const BIGNUM *a, const BIGNUM *N, const BIGNUM *g)
{
    BN_CTX *bn_ctx;
    BIGNUM *A = NULL;

    if (a == NULL || N == NULL || g == NULL || (bn_ctx = VR_BN_CTX_new()) == NULL)
        return NULL;

    if ((A = VR_BN_new()) != NULL && !VR_BN_mod_exp(A, g, a, N, bn_ctx)) {
        VR_BN_free(A);
        A = NULL;
    }
    VR_BN_CTX_free(bn_ctx);
    return A;
}

BIGNUM *VR_SRP_Calc_client_key(const BIGNUM *N, const BIGNUM *B, const BIGNUM *g,
                            const BIGNUM *x, const BIGNUM *a, const BIGNUM *u)
{
    BIGNUM *tmp = NULL, *tmp2 = NULL, *tmp3 = NULL, *k = NULL, *K = NULL;
    BN_CTX *bn_ctx;

    if (u == NULL || B == NULL || N == NULL || g == NULL || x == NULL
        || a == NULL || (bn_ctx = VR_BN_CTX_new()) == NULL)
        return NULL;

    if ((tmp = VR_BN_new()) == NULL ||
        (tmp2 = VR_BN_new()) == NULL ||
        (tmp3 = VR_BN_new()) == NULL)
        goto err;

    if (!VR_BN_mod_exp(tmp, g, x, N, bn_ctx))
        goto err;
    if ((k = srp_Calc_k(N, g)) == NULL)
        goto err;
    if (!VR_BN_mod_mul(tmp2, tmp, k, N, bn_ctx))
        goto err;
    if (!VR_BN_mod_sub(tmp, B, tmp2, N, bn_ctx))
        goto err;
    if (!VR_BN_mul(tmp3, u, x, bn_ctx))
        goto err;
    if (!VR_BN_add(tmp2, a, tmp3))
        goto err;
    K = VR_BN_new();
    if (K != NULL && !VR_BN_mod_exp(K, tmp, tmp2, N, bn_ctx)) {
        VR_BN_free(K);
        K = NULL;
    }

 err:
    VR_BN_CTX_free(bn_ctx);
    VR_BN_clear_free(tmp);
    VR_BN_clear_free(tmp2);
    VR_BN_clear_free(tmp3);
    VR_BN_free(k);
    return K;
}

int VR_SRP_Verify_B_mod_N(const BIGNUM *B, const BIGNUM *N)
{
    BIGNUM *r;
    BN_CTX *bn_ctx;
    int ret = 0;

    if (B == NULL || N == NULL || (bn_ctx = VR_BN_CTX_new()) == NULL)
        return 0;

    if ((r = VR_BN_new()) == NULL)
        goto err;
    /* Checks if B % N == 0 */
    if (!VR_BN_nnmod(r, B, N, bn_ctx))
        goto err;
    ret = !VR_BN_is_zero(r);
 err:
    VR_BN_CTX_free(bn_ctx);
    VR_BN_free(r);
    return ret;
}

int VR_SRP_Verify_A_mod_N(const BIGNUM *A, const BIGNUM *N)
{
    /* Checks if A % N == 0 */
    return VR_SRP_Verify_B_mod_N(A, N);
}

static SRP_gN knowngN[] = {
    {"8192", &bn_generator_19, &bn_group_8192},
    {"6144", &bn_generator_5, &bn_group_6144},
    {"4096", &bn_generator_5, &bn_group_4096},
    {"3072", &bn_generator_5, &bn_group_3072},
    {"2048", &bn_generator_2, &bn_group_2048},
    {"1536", &bn_generator_2, &bn_group_1536},
    {"1024", &bn_generator_2, &bn_group_1024},
};

# define KNOWN_GN_NUMBER sizeof(knowngN) / sizeof(SRP_gN)

/*
 * Check if G and N are known parameters. The values have been generated
 * from the IETF RFC 5054
 */
char *VR_SRP_check_known_gN_param(const BIGNUM *g, const BIGNUM *N)
{
    size_t i;
    if ((g == NULL) || (N == NULL))
        return NULL;

    for (i = 0; i < KNOWN_GN_NUMBER; i++) {
        if (VR_BN_cmp(knowngN[i].g, g) == 0 && VR_BN_cmp(knowngN[i].N, N) == 0)
            return knowngN[i].id;
    }
    return NULL;
}

SRP_gN *VR_SRP_get_default_gN(const char *id)
{
    size_t i;

    if (id == NULL)
        return knowngN;
    for (i = 0; i < KNOWN_GN_NUMBER; i++) {
        if (strcmp(knowngN[i].id, id) == 0)
            return knowngN + i;
    }
    return NULL;
}
#endif
