/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_DSA_H
# define HEADER_DSA_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_DSA
# ifdef  __cplusplus
extern "C" {
# endif
# include <openssl/e_os2.h>
# include <openssl/bio.h>
# include <openssl/crypto.h>
# include <openssl/ossl_typ.h>
# include <openssl/bn.h>
# if !OPENSSL_API_1_1_0
#  include <openssl/dh.h>
# endif
# include <openssl/dsaerr.h>

# ifndef OPENSSL_DSA_MAX_MODULUS_BITS
#  define OPENSSL_DSA_MAX_MODULUS_BITS   10000
# endif

# define OPENSSL_DSA_FIPS_MIN_MODULUS_BITS 1024

# define DSA_FLAG_CACHE_MONT_P   0x01
# if !OPENSSL_API_1_1_0
/*
 * Does nothing. Previously this switched off constant time behaviour.
 */
#  define DSA_FLAG_NO_EXP_CONSTTIME       0x00
# endif

/*
 * If this flag is set the DSA method is FIPS compliant and can be used in
 * FIPS mode. This is set in the validated module method. If an application
 * sets this flag in its own methods it is its responsibility to ensure the
 * result is compliant.
 */

# define DSA_FLAG_FIPS_METHOD                    0x0400

/*
 * If this flag is set the operations normally disabled in FIPS mode are
 * permitted it is then the applications responsibility to ensure that the
 * usage is compliant.
 */

# define DSA_FLAG_NON_FIPS_ALLOW                 0x0400
# define DSA_FLAG_FIPS_CHECKED                   0x0800

/* Already defined in ossl_typ.h */
/* typedef struct dsa_st DSA; */
/* typedef struct dsa_method DSA_METHOD; */

typedef struct DSA_SIG_st DSA_SIG;

# define VR_d2i_DSAparams_fp(fp,x) (DSA *)VR_ASN1_d2i_fp((char *(*)())VR_DSA_new, \
                (char *(*)())VR_d2i_DSAparams,(fp),(unsigned char **)(x))
# define VR_i2d_DSAparams_fp(fp,x) VR_ASN1_i2d_fp(VR_i2d_DSAparams,(fp), \
                (unsigned char *)(x))
# define VR_d2i_DSAparams_bio(bp,x) VR_ASN1_d2i_bio_of(DSA,VR_DSA_new,VR_d2i_DSAparams,bp,x)
# define VR_i2d_DSAparams_bio(bp,x) VR_ASN1_i2d_bio_of_const(DSA,VR_i2d_DSAparams,bp,x)

DSA *VR_DSAparams_dup(DSA *x);
DSA_SIG *VR_DSA_SIG_new(void);
void VR_DSA_SIG_free(DSA_SIG *a);
int VR_i2d_DSA_SIG(const DSA_SIG *a, unsigned char **pp);
DSA_SIG *VR_d2i_DSA_SIG(DSA_SIG **v, const unsigned char **pp, long length);
void VR_DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
int VR_DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s);

DSA_SIG *VR_DSA_do_sign(const unsigned char *dgst, int dlen, DSA *dsa);
int VR_DSA_do_verify(const unsigned char *dgst, int dgst_len,
                  DSA_SIG *sig, DSA *dsa);

const DSA_METHOD *VR_DSA_OpenSSL(void);

void VR_DSA_set_default_method(const DSA_METHOD *);
const DSA_METHOD *VR_DSA_get_default_method(void);
int VR_DSA_set_method(DSA *dsa, const DSA_METHOD *);
const DSA_METHOD *VR_DSA_get_method(DSA *d);

DSA *VR_DSA_new(void);
DSA *VR_DSA_new_method(ENGINE *engine);
void VR_DSA_free(DSA *r);
/* "up" the DSA object's reference count */
int VR_DSA_up_ref(DSA *r);
int VR_DSA_size(const DSA *);
int VR_DSA_bits(const DSA *d);
int VR_DSA_security_bits(const DSA *d);
        /* next 4 return -1 on error */
DEPRECATEDIN_3(int VR_DSA_sign_setup(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp))
int VR_DSA_sign(int type, const unsigned char *dgst, int dlen,
             unsigned char *sig, unsigned int *siglen, DSA *dsa);
int VR_DSA_verify(int type, const unsigned char *dgst, int dgst_len,
               const unsigned char *sigbuf, int siglen, DSA *dsa);
#define DSA_get_ex_new_index(l, p, newf, dupf, freef) \
    VR_CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DSA, l, p, newf, dupf, freef)
int VR_DSA_set_ex_data(DSA *d, int idx, void *arg);
void *VR_DSA_get_ex_data(DSA *d, int idx);

DSA *VR_d2i_DSAPublicKey(DSA **a, const unsigned char **pp, long length);
DSA *VR_d2i_DSAPrivateKey(DSA **a, const unsigned char **pp, long length);
DSA *VR_d2i_DSAparams(DSA **a, const unsigned char **pp, long length);

/* Deprecated version */
DEPRECATEDIN_0_9_8(DSA *VR_DSA_generate_parameters(int bits,
                                                unsigned char *seed,
                                                int seed_len,
                                                int *counter_ret,
                                                unsigned long *h_ret, void
                                                 (*callback) (int, int,
                                                              void *),
                                                void *cb_arg))

/* New version */
int VR_DSA_generate_parameters_ex(DSA *dsa, int bits,
                               const unsigned char *seed, int seed_len,
                               int *counter_ret, unsigned long *h_ret,
                               BN_GENCB *cb);

int VR_DSA_generate_key(DSA *a);
int VR_i2d_DSAPublicKey(const DSA *a, unsigned char **pp);
int VR_i2d_DSAPrivateKey(const DSA *a, unsigned char **pp);
int VR_i2d_DSAparams(const DSA *a, unsigned char **pp);

int VR_DSAparams_print(BIO *bp, const DSA *x);
int VR_DSA_print(BIO *bp, const DSA *x, int off);
# ifndef OPENSSL_NO_STDIO
int VR_DSAparams_print_fp(FILE *fp, const DSA *x);
int VR_DSA_print_fp(FILE *bp, const DSA *x, int off);
# endif

# define DSS_prime_checks 64
/*
 * Primality test according to FIPS PUB 186-4, Appendix C.3. Since we only
 * have one value here we set the number of checks to 64 which is the 128 bit
 * security level that is the highest level and valid for creating a 3072 bit
 * DSA key.
 */
# define DSA_is_prime(n, callback, cb_arg) \
        VR_BN_is_prime(n, DSS_prime_checks, callback, NULL, cb_arg)

# ifndef OPENSSL_NO_DH
/*
 * Convert DSA structure (key or just parameters) into DH structure (be
 * careful to avoid small subgroup attacks when using this!)
 */
DH *VR_DSA_dup_DH(const DSA *r);
# endif

# define EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, nbits) \
        VR_EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN, \
                                EVP_PKEY_CTRL_DSA_PARAMGEN_BITS, nbits, NULL)
# define EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ctx, qbits) \
        VR_EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN, \
                                EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS, qbits, NULL)
# define EVP_PKEY_CTX_set_dsa_paramgen_md(ctx, md) \
        VR_EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN, \
                                EVP_PKEY_CTRL_DSA_PARAMGEN_MD, 0, (void *)(md))

# define EVP_PKEY_CTRL_DSA_PARAMGEN_BITS         (EVP_PKEY_ALG_CTRL + 1)
# define EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS       (EVP_PKEY_ALG_CTRL + 2)
# define EVP_PKEY_CTRL_DSA_PARAMGEN_MD           (EVP_PKEY_ALG_CTRL + 3)

void VR_DSA_get0_pqg(const DSA *d,
                  const BIGNUM **p, const BIGNUM **q, const BIGNUM **g);
int VR_DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g);
void VR_DSA_get0_key(const DSA *d,
                  const BIGNUM **pub_key, const BIGNUM **priv_key);
int VR_DSA_set0_key(DSA *d, BIGNUM *pub_key, BIGNUM *priv_key);
const BIGNUM *VR_DSA_get0_p(const DSA *d);
const BIGNUM *VR_DSA_get0_q(const DSA *d);
const BIGNUM *VR_DSA_get0_g(const DSA *d);
const BIGNUM *VR_DSA_get0_pub_key(const DSA *d);
const BIGNUM *VR_DSA_get0_priv_key(const DSA *d);
void VR_DSA_clear_flags(DSA *d, int flags);
int VR_DSA_test_flags(const DSA *d, int flags);
void VR_DSA_set_flags(DSA *d, int flags);
ENGINE *VR_DSA_get0_engine(DSA *d);

DSA_METHOD *VR_DSA_meth_new(const char *name, int flags);
void VR_DSA_meth_free(DSA_METHOD *dsam);
DSA_METHOD *VR_DSA_meth_dup(const DSA_METHOD *dsam);
const char *VR_DSA_meth_get0_name(const DSA_METHOD *dsam);
int VR_DSA_meth_set1_name(DSA_METHOD *dsam, const char *name);
int VR_DSA_meth_get_flags(const DSA_METHOD *dsam);
int VR_DSA_meth_set_flags(DSA_METHOD *dsam, int flags);
void *VR_DSA_meth_get0_app_data(const DSA_METHOD *dsam);
int VR_DSA_meth_set0_app_data(DSA_METHOD *dsam, void *app_data);
DSA_SIG *(*VR_DSA_meth_get_sign(const DSA_METHOD *dsam))
        (const unsigned char *, int, DSA *);
int VR_DSA_meth_set_sign(DSA_METHOD *dsam,
                       DSA_SIG *(*sign) (const unsigned char *, int, DSA *));
int (*VR_DSA_meth_get_sign_setup(const DSA_METHOD *dsam))
        (DSA *, BN_CTX *, BIGNUM **, BIGNUM **);
int VR_DSA_meth_set_sign_setup(DSA_METHOD *dsam,
        int (*sign_setup) (DSA *, BN_CTX *, BIGNUM **, BIGNUM **));
int (*VR_DSA_meth_get_verify(const DSA_METHOD *dsam))
        (const unsigned char *, int, DSA_SIG *, DSA *);
int VR_DSA_meth_set_verify(DSA_METHOD *dsam,
    int (*verify) (const unsigned char *, int, DSA_SIG *, DSA *));
int (*VR_DSA_meth_get_mod_exp(const DSA_METHOD *dsam))
        (DSA *, BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *,
         const BIGNUM *, const BIGNUM *, BN_CTX *, BN_MONT_CTX *);
int VR_DSA_meth_set_mod_exp(DSA_METHOD *dsam,
    int (*mod_exp) (DSA *, BIGNUM *, const BIGNUM *, const BIGNUM *,
                    const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *,
                    BN_MONT_CTX *));
int (*VR_DSA_meth_get_bn_mod_exp(const DSA_METHOD *dsam))
    (DSA *, BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *,
     BN_CTX *, BN_MONT_CTX *);
int VR_DSA_meth_set_bn_mod_exp(DSA_METHOD *dsam,
    int (*bn_mod_exp) (DSA *, BIGNUM *, const BIGNUM *, const BIGNUM *,
                       const BIGNUM *, BN_CTX *, BN_MONT_CTX *));
int (*VR_DSA_meth_get_init(const DSA_METHOD *dsam))(DSA *);
int VR_DSA_meth_set_init(DSA_METHOD *dsam, int (*init)(DSA *));
int (*VR_DSA_meth_get_finish(const DSA_METHOD *dsam)) (DSA *);
int VR_DSA_meth_set_finish(DSA_METHOD *dsam, int (*finish) (DSA *));
int (*VR_DSA_meth_get_paramgen(const DSA_METHOD *dsam))
        (DSA *, int, const unsigned char *, int, int *, unsigned long *,
         BN_GENCB *);
int VR_DSA_meth_set_paramgen(DSA_METHOD *dsam,
        int (*paramgen) (DSA *, int, const unsigned char *, int, int *,
                         unsigned long *, BN_GENCB *));
int (*VR_DSA_meth_get_keygen(const DSA_METHOD *dsam)) (DSA *);
int VR_DSA_meth_set_keygen(DSA_METHOD *dsam, int (*keygen) (DSA *));


#  ifdef  __cplusplus
}
#  endif
# endif
#endif
