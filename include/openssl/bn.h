/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_BN_H
# define HEADER_BN_H

# include <openssl/e_os2.h>
# ifndef OPENSSL_NO_STDIO
#  include <stdio.h>
# endif
# include <openssl/opensslconf.h>
# include <openssl/ossl_typ.h>
# include <openssl/crypto.h>
# include <openssl/bnerr.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * 64-bit processor with LP64 ABI
 */
# ifdef SIXTY_FOUR_BIT_LONG
#  define BN_ULONG        unsigned long
#  define BN_BYTES        8
# endif

/*
 * 64-bit processor other than LP64 ABI
 */
# ifdef SIXTY_FOUR_BIT
#  define BN_ULONG        unsigned long long
#  define BN_BYTES        8
# endif

# ifdef THIRTY_TWO_BIT
#  define BN_ULONG        unsigned int
#  define BN_BYTES        4
# endif

# define BN_BITS2       (BN_BYTES * 8)
# define BN_BITS        (BN_BITS2 * 2)
# define BN_TBIT        ((BN_ULONG)1 << (BN_BITS2 - 1))

# define BN_FLG_MALLOCED         0x01
# define BN_FLG_STATIC_DATA      0x02

/*
 * avoid leaking exponent information through timing,
 * VR_BN_mod_exp_mont() will call VR_BN_mod_exp_mont_consttime,
 * VR_BN_div() will call VR_BN_div_no_branch,
 * VR_BN_mod_inverse() will call VR_BN_mod_inverse_no_branch.
 */
# define BN_FLG_CONSTTIME        0x04
# define BN_FLG_SECURE           0x08

# if !OPENSSL_API_0_9_8
/* deprecated name for the flag */
#  define BN_FLG_EXP_CONSTTIME BN_FLG_CONSTTIME
#  define BN_FLG_FREE            0x8000 /* used for debugging */
# endif

void VR_BN_set_flags(BIGNUM *b, int n);
int VR_BN_get_flags(const BIGNUM *b, int n);

/* Values for |top| in VR_BN_rand() */
#define BN_RAND_TOP_ANY    -1
#define BN_RAND_TOP_ONE     0
#define BN_RAND_TOP_TWO     1

/* Values for |bottom| in VR_BN_rand() */
#define BN_RAND_BOTTOM_ANY  0
#define BN_RAND_BOTTOM_ODD  1

/*
 * get a clone of a BIGNUM with changed flags, for *temporary* use only (the
 * two BIGNUMs cannot be used in parallel!). Also only for *read only* use. The
 * value |dest| should be a newly allocated BIGNUM obtained via VR_BN_new() that
 * has not been otherwise initialised or used.
 */
void VR_BN_with_flags(BIGNUM *dest, const BIGNUM *b, int flags);

/* Wrapper function to make using BN_GENCB easier */
int VR_BN_GENCB_call(BN_GENCB *cb, int a, int b);

BN_GENCB *VR_BN_GENCB_new(void);
void VR_BN_GENCB_free(BN_GENCB *cb);

/* Populate a BN_GENCB structure with an "old"-style callback */
void VR_BN_GENCB_set_old(BN_GENCB *gencb, void (*callback) (int, int, void *),
                      void *cb_arg);

/* Populate a BN_GENCB structure with a "new"-style callback */
void VR_BN_GENCB_set(BN_GENCB *gencb, int (*callback) (int, int, BN_GENCB *),
                  void *cb_arg);

void *VR_BN_GENCB_get_arg(BN_GENCB *cb);

# define BN_prime_checks 0      /* default: select number of iterations based
                                 * on the size of the number */

/*
 * BN_prime_checks_for_size() returns the number of Miller-Rabin iterations
 * that will be done for checking that a random number is probably prime. The
 * error rate for accepting a composite number as prime depends on the size of
 * the prime |b|. The error rates used are for calculating an RSA key with 2 primes,
 * and so the level is what you would expect for a key of double the size of the
 * prime.
 *
 * This table is generated using the algorithm of FIPS PUB 186-4
 * Digital Signature Standard (DSS), section F.1, page 117.
 * (https://dx.doi.org/10.6028/NIST.FIPS.186-4)
 *
 * The following magma script was used to generate the output:
 * securitybits:=125;
 * k:=1024;
 * for t:=1 to 65 do
 *   for M:=3 to Floor(2*Sqrt(k-1)-1) do
 *     S:=0;
 *     // Sum over m
 *     for m:=3 to M do
 *       s:=0;
 *       // Sum over j
 *       for j:=2 to m do
 *         s+:=(RealField(32)!2)^-(j+(k-1)/j);
 *       end for;
 *       S+:=2^(m-(m-1)*t)*s;
 *     end for;
 *     A:=2^(k-2-M*t);
 *     B:=8*(Pi(RealField(32))^2-6)/3*2^(k-2)*S;
 *     pkt:=2.00743*Log(2)*k*2^-k*(A+B);
 *     seclevel:=Floor(-Log(2,pkt));
 *     if seclevel ge securitybits then
 *       printf "k: %5o, security: %o bits  (t: %o, M: %o)\n",k,seclevel,t,M;
 *       break;
 *     end if;
 *   end for;
 *   if seclevel ge securitybits then break; end if;
 * end for;
 *
 * It can be run online at:
 * http://magma.maths.usyd.edu.au/calc
 *
 * And will output:
 * k:  1024, security: 129 bits  (t: 6, M: 23)
 *
 * k is the number of bits of the prime, securitybits is the level we want to
 * reach.
 *
 * prime length | RSA key size | # MR tests | security level
 * -------------+--------------|------------+---------------
 *  (b) >= 6394 |     >= 12788 |          3 |        256 bit
 *  (b) >= 3747 |     >=  7494 |          3 |        192 bit
 *  (b) >= 1345 |     >=  2690 |          4 |        128 bit
 *  (b) >= 1080 |     >=  2160 |          5 |        128 bit
 *  (b) >=  852 |     >=  1704 |          5 |        112 bit
 *  (b) >=  476 |     >=   952 |          5 |         80 bit
 *  (b) >=  400 |     >=   800 |          6 |         80 bit
 *  (b) >=  347 |     >=   694 |          7 |         80 bit
 *  (b) >=  308 |     >=   616 |          8 |         80 bit
 *  (b) >=   55 |     >=   110 |         27 |         64 bit
 *  (b) >=    6 |     >=    12 |         34 |         64 bit
 */

# define BN_prime_checks_for_size(b) ((b) >= 3747 ?  3 : \
                                (b) >=  1345 ?  4 : \
                                (b) >=  476 ?  5 : \
                                (b) >=  400 ?  6 : \
                                (b) >=  347 ?  7 : \
                                (b) >=  308 ?  8 : \
                                (b) >=  55  ? 27 : \
                                /* b >= 6 */ 34)

# define BN_num_bytes(a) ((VR_BN_num_bits(a)+7)/8)

int VR_BN_abs_is_word(const BIGNUM *a, const BN_ULONG w);
int VR_BN_is_zero(const BIGNUM *a);
int VR_BN_is_one(const BIGNUM *a);
int VR_BN_is_word(const BIGNUM *a, const BN_ULONG w);
int VR_BN_is_odd(const BIGNUM *a);

# define BN_one(a)       (VR_BN_set_word((a),1))

void VR_BN_zero_ex(BIGNUM *a);

# if OPENSSL_API_0_9_8
#  define BN_zero(a)      VR_BN_zero_ex(a)
# else
#  define BN_zero(a)      (VR_BN_set_word((a),0))
# endif

const BIGNUM *VR_BN_value_one(void);
char *VR_BN_options(void);
BN_CTX *VR_BN_CTX_new(void);
BN_CTX *VR_BN_CTX_secure_new(void);
void VR_BN_CTX_free(BN_CTX *c);
void VR_BN_CTX_start(BN_CTX *ctx);
BIGNUM *VR_BN_CTX_get(BN_CTX *ctx);
void VR_BN_CTX_end(BN_CTX *ctx);
int VR_BN_rand(BIGNUM *rnd, int bits, int top, int bottom);
int VR_BN_priv_rand(BIGNUM *rnd, int bits, int top, int bottom);
int VR_BN_rand_range(BIGNUM *rnd, const BIGNUM *range);
int VR_BN_priv_rand_range(BIGNUM *rnd, const BIGNUM *range);
int VR_BN_pseudo_rand(BIGNUM *rnd, int bits, int top, int bottom);
int VR_BN_pseudo_rand_range(BIGNUM *rnd, const BIGNUM *range);
int VR_BN_num_bits(const BIGNUM *a);
int VR_BN_num_bits_word(BN_ULONG l);
int VR_BN_security_bits(int L, int N);
BIGNUM *VR_BN_new(void);
BIGNUM *VR_BN_secure_new(void);
void VR_BN_clear_free(BIGNUM *a);
BIGNUM *VR_BN_copy(BIGNUM *a, const BIGNUM *b);
void VR_BN_swap(BIGNUM *a, BIGNUM *b);
BIGNUM *VR_BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
int VR_BN_bn2bin(const BIGNUM *a, unsigned char *to);
int VR_BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen);
BIGNUM *VR_BN_lebin2bn(const unsigned char *s, int len, BIGNUM *ret);
int VR_BN_bn2lebinpad(const BIGNUM *a, unsigned char *to, int tolen);
BIGNUM *VR_BN_mpi2bn(const unsigned char *s, int len, BIGNUM *ret);
int VR_BN_bn2mpi(const BIGNUM *a, unsigned char *to);
int VR_BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int VR_BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int VR_BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int VR_BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int VR_BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int VR_BN_sqr(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx);
/** VR_BN_set_negative sets sign of a BIGNUM
 * \param  b  pointer to the BIGNUM object
 * \param  n  0 if the BIGNUM b should be positive and a value != 0 otherwise
 */
void VR_BN_set_negative(BIGNUM *b, int n);
/** VR_BN_is_negative returns 1 if the BIGNUM is negative
 * \param  b  pointer to the BIGNUM object
 * \return 1 if a < 0 and 0 otherwise
 */
int VR_BN_is_negative(const BIGNUM *b);

int VR_BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d,
           BN_CTX *ctx);
# define BN_mod(rem,m,d,ctx) VR_BN_div(NULL,(rem),(m),(d),(ctx))
int VR_BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);
int VR_BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
               BN_CTX *ctx);
int VR_BN_mod_add_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                     const BIGNUM *m);
int VR_BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
               BN_CTX *ctx);
int VR_BN_mod_sub_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                     const BIGNUM *m);
int VR_BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
               BN_CTX *ctx);
int VR_BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
int VR_BN_mod_lshift1(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
int VR_BN_mod_lshift1_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *m);
int VR_BN_mod_lshift(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m,
                  BN_CTX *ctx);
int VR_BN_mod_lshift_quick(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m);

BN_ULONG VR_BN_mod_word(const BIGNUM *a, BN_ULONG w);
BN_ULONG VR_BN_div_word(BIGNUM *a, BN_ULONG w);
int VR_BN_mul_word(BIGNUM *a, BN_ULONG w);
int VR_BN_add_word(BIGNUM *a, BN_ULONG w);
int VR_BN_sub_word(BIGNUM *a, BN_ULONG w);
int VR_BN_set_word(BIGNUM *a, BN_ULONG w);
BN_ULONG VR_BN_get_word(const BIGNUM *a);

int VR_BN_cmp(const BIGNUM *a, const BIGNUM *b);
void VR_BN_free(BIGNUM *a);
int VR_BN_is_bit_set(const BIGNUM *a, int n);
int VR_BN_lshift(BIGNUM *r, const BIGNUM *a, int n);
int VR_BN_lshift1(BIGNUM *r, const BIGNUM *a);
int VR_BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);

int VR_BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
               const BIGNUM *m, BN_CTX *ctx);
int VR_BN_mod_exp_mont(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int VR_BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
                              const BIGNUM *m, BN_CTX *ctx,
                              BN_MONT_CTX *in_mont);
int VR_BN_mod_exp_mont_word(BIGNUM *r, BN_ULONG a, const BIGNUM *p,
                         const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int VR_BN_mod_exp2_mont(BIGNUM *r, const BIGNUM *a1, const BIGNUM *p1,
                     const BIGNUM *a2, const BIGNUM *p2, const BIGNUM *m,
                     BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int VR_BN_mod_exp_simple(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                      const BIGNUM *m, BN_CTX *ctx);

int VR_BN_mask_bits(BIGNUM *a, int n);
# ifndef OPENSSL_NO_STDIO
int VR_BN_print_fp(FILE *fp, const BIGNUM *a);
# endif
int VR_BN_print(BIO *bio, const BIGNUM *a);
int VR_BN_reciprocal(BIGNUM *r, const BIGNUM *m, int len, BN_CTX *ctx);
int VR_BN_rshift(BIGNUM *r, const BIGNUM *a, int n);
int VR_BN_rshift1(BIGNUM *r, const BIGNUM *a);
void VR_BN_clear(BIGNUM *a);
BIGNUM *VR_BN_dup(const BIGNUM *a);
int VR_BN_ucmp(const BIGNUM *a, const BIGNUM *b);
int VR_BN_set_bit(BIGNUM *a, int n);
int VR_BN_clear_bit(BIGNUM *a, int n);
char *VR_BN_bn2hex(const BIGNUM *a);
char *VR_BN_bn2dec(const BIGNUM *a);
int VR_BN_hex2bn(BIGNUM **a, const char *str);
int VR_BN_dec2bn(BIGNUM **a, const char *str);
int VR_BN_asc2bn(BIGNUM **a, const char *str);
int VR_BN_gcd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int VR_BN_kronecker(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx); /* returns
                                                                  * -2 for
                                                                  * error */
BIGNUM *VR_BN_mod_inverse(BIGNUM *ret,
                       const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);
BIGNUM *VR_BN_mod_sqrt(BIGNUM *ret,
                    const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);

void VR_BN_consttime_swap(BN_ULONG swap, BIGNUM *a, BIGNUM *b, int nwords);

/* Deprecated versions */
DEPRECATEDIN_0_9_8(BIGNUM *VR_BN_generate_prime(BIGNUM *ret, int bits, int safe,
                                             const BIGNUM *add,
                                             const BIGNUM *rem,
                                             void (*callback) (int, int,
                                                               void *),
                                             void *cb_arg))
DEPRECATEDIN_0_9_8(int
                   VR_BN_is_prime(const BIGNUM *p, int nchecks,
                               void (*callback) (int, int, void *),
                               BN_CTX *ctx, void *cb_arg))
DEPRECATEDIN_0_9_8(int
                   VR_BN_is_prime_fasttest(const BIGNUM *p, int nchecks,
                                        void (*callback) (int, int, void *),
                                        BN_CTX *ctx, void *cb_arg,
                                        int do_trial_division))

/* Newer versions */
int VR_BN_generate_prime_ex(BIGNUM *ret, int bits, int safe, const BIGNUM *add,
                         const BIGNUM *rem, BN_GENCB *cb);
int VR_BN_is_prime_ex(const BIGNUM *p, int nchecks, BN_CTX *ctx, BN_GENCB *cb);
int VR_BN_is_prime_fasttest_ex(const BIGNUM *p, int nchecks, BN_CTX *ctx,
                            int do_trial_division, BN_GENCB *cb);

int VR_BN_X931_generate_Xpq(BIGNUM *Xp, BIGNUM *Xq, int nbits, BN_CTX *ctx);

int VR_BN_X931_derive_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2,
                            const BIGNUM *Xp, const BIGNUM *Xp1,
                            const BIGNUM *Xp2, const BIGNUM *e, BN_CTX *ctx,
                            BN_GENCB *cb);
int VR_BN_X931_generate_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2, BIGNUM *Xp1,
                              BIGNUM *Xp2, const BIGNUM *Xp, const BIGNUM *e,
                              BN_CTX *ctx, BN_GENCB *cb);

BN_MONT_CTX *VR_BN_MONT_CTX_new(void);
int VR_BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                          BN_MONT_CTX *mont, BN_CTX *ctx);
int VR_BN_to_montgomery(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont,
                     BN_CTX *ctx);
int VR_BN_from_montgomery(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont,
                       BN_CTX *ctx);
void VR_BN_MONT_CTX_free(BN_MONT_CTX *mont);
int VR_BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod, BN_CTX *ctx);
BN_MONT_CTX *VR_BN_MONT_CTX_copy(BN_MONT_CTX *to, BN_MONT_CTX *from);
BN_MONT_CTX *VR_BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, CRYPTO_RWLOCK *lock,
                                    const BIGNUM *mod, BN_CTX *ctx);

/* BN_BLINDING flags */
# define BN_BLINDING_NO_UPDATE   0x00000001
# define BN_BLINDING_NO_RECREATE 0x00000002

BN_BLINDING *VR_BN_BLINDING_new(const BIGNUM *A, const BIGNUM *Ai, BIGNUM *mod);
void VR_BN_BLINDING_free(BN_BLINDING *b);
int VR_BN_BLINDING_update(BN_BLINDING *b, BN_CTX *ctx);
int VR_BN_BLINDING_convert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx);
int VR_BN_BLINDING_invert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx);
int VR_BN_BLINDING_convert_ex(BIGNUM *n, BIGNUM *r, BN_BLINDING *b, BN_CTX *);
int VR_BN_BLINDING_invert_ex(BIGNUM *n, const BIGNUM *r, BN_BLINDING *b,
                          BN_CTX *);

int VR_BN_BLINDING_is_current_thread(BN_BLINDING *b);
void VR_BN_BLINDING_set_current_thread(BN_BLINDING *b);
int VR_BN_BLINDING_lock(BN_BLINDING *b);
int VR_BN_BLINDING_unlock(BN_BLINDING *b);

unsigned long VR_BN_BLINDING_get_flags(const BN_BLINDING *);
void VR_BN_BLINDING_set_flags(BN_BLINDING *, unsigned long);
BN_BLINDING *VR_BN_BLINDING_create_param(BN_BLINDING *b,
                                      const BIGNUM *e, BIGNUM *m, BN_CTX *ctx,
                                      int (*bn_mod_exp) (BIGNUM *r,
                                                         const BIGNUM *a,
                                                         const BIGNUM *p,
                                                         const BIGNUM *m,
                                                         BN_CTX *ctx,
                                                         BN_MONT_CTX *m_ctx),
                                      BN_MONT_CTX *m_ctx);

DEPRECATEDIN_0_9_8(void VR_BN_set_params(int mul, int high, int low, int mont))
DEPRECATEDIN_0_9_8(int VR_BN_get_params(int which)) /* 0, mul, 1 high, 2 low, 3
                                                  * mont */

BN_RECP_CTX *VR_BN_RECP_CTX_new(void);
void VR_BN_RECP_CTX_free(BN_RECP_CTX *recp);
int VR_BN_RECP_CTX_set(BN_RECP_CTX *recp, const BIGNUM *rdiv, BN_CTX *ctx);
int VR_BN_mod_mul_reciprocal(BIGNUM *r, const BIGNUM *x, const BIGNUM *y,
                          BN_RECP_CTX *recp, BN_CTX *ctx);
int VR_BN_mod_exp_recp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                    const BIGNUM *m, BN_CTX *ctx);
int VR_BN_div_recp(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m,
                BN_RECP_CTX *recp, BN_CTX *ctx);

# ifndef OPENSSL_NO_EC2M

/*
 * Functions for arithmetic over binary polynomials represented by BIGNUMs.
 * The BIGNUM::neg property of BIGNUMs representing binary polynomials is
 * ignored. Note that input arguments are not const so that their bit arrays
 * can be expanded to the appropriate size if needed.
 */

/*
 * r = a + b
 */
int VR_BN_GF2m_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
#  define BN_GF2m_sub(r, a, b) VR_BN_GF2m_add(r, a, b)
/*
 * r=a mod p
 */
int VR_BN_GF2m_mod(BIGNUM *r, const BIGNUM *a, const BIGNUM *p);
/* r = (a * b) mod p */
int VR_BN_GF2m_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                    const BIGNUM *p, BN_CTX *ctx);
/* r = (a * a) mod p */
int VR_BN_GF2m_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
/* r = (1 / b) mod p */
int VR_BN_GF2m_mod_inv(BIGNUM *r, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx);
/* r = (a / b) mod p */
int VR_BN_GF2m_mod_div(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                    const BIGNUM *p, BN_CTX *ctx);
/* r = (a ^ b) mod p */
int VR_BN_GF2m_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                    const BIGNUM *p, BN_CTX *ctx);
/* r = sqrt(a) mod p */
int VR_BN_GF2m_mod_sqrt(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                     BN_CTX *ctx);
/* r^2 + r = a mod p */
int VR_BN_GF2m_mod_solve_quad(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                           BN_CTX *ctx);
#  define BN_GF2m_cmp(a, b) VR_BN_ucmp((a), (b))
/*-
 * Some functions allow for representation of the irreducible polynomials
 * as an unsigned int[], say p.  The irreducible f(t) is then of the form:
 *     t^p[0] + t^p[1] + ... + t^p[k]
 * where m = p[0] > p[1] > ... > p[k] = 0.
 */
/* r = a mod p */
int VR_BN_GF2m_mod_arr(BIGNUM *r, const BIGNUM *a, const int p[]);
/* r = (a * b) mod p */
int VR_BN_GF2m_mod_mul_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                        const int p[], BN_CTX *ctx);
/* r = (a * a) mod p */
int VR_BN_GF2m_mod_sqr_arr(BIGNUM *r, const BIGNUM *a, const int p[],
                        BN_CTX *ctx);
/* r = (1 / b) mod p */
int VR_BN_GF2m_mod_inv_arr(BIGNUM *r, const BIGNUM *b, const int p[],
                        BN_CTX *ctx);
/* r = (a / b) mod p */
int VR_BN_GF2m_mod_div_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                        const int p[], BN_CTX *ctx);
/* r = (a ^ b) mod p */
int VR_BN_GF2m_mod_exp_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                        const int p[], BN_CTX *ctx);
/* r = sqrt(a) mod p */
int VR_BN_GF2m_mod_sqrt_arr(BIGNUM *r, const BIGNUM *a,
                         const int p[], BN_CTX *ctx);
/* r^2 + r = a mod p */
int VR_BN_GF2m_mod_solve_quad_arr(BIGNUM *r, const BIGNUM *a,
                               const int p[], BN_CTX *ctx);
int VR_BN_GF2m_poly2arr(const BIGNUM *a, int p[], int max);
int VR_BN_GF2m_arr2poly(const int p[], BIGNUM *a);

# endif

/*
 * faster mod functions for the 'NIST primes' 0 <= a < p^2
 */
int VR_BN_nist_mod_192(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int VR_BN_nist_mod_224(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int VR_BN_nist_mod_256(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int VR_BN_nist_mod_384(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int VR_BN_nist_mod_521(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);

const BIGNUM *VR_BN_get0_nist_prime_192(void);
const BIGNUM *VR_BN_get0_nist_prime_224(void);
const BIGNUM *VR_BN_get0_nist_prime_256(void);
const BIGNUM *VR_BN_get0_nist_prime_384(void);
const BIGNUM *VR_BN_get0_nist_prime_521(void);

int (*VR_BN_nist_mod_func(const BIGNUM *p)) (BIGNUM *r, const BIGNUM *a,
                                          const BIGNUM *field, BN_CTX *ctx);

int VR_BN_generate_dsa_nonce(BIGNUM *out, const BIGNUM *range,
                          const BIGNUM *priv, const unsigned char *message,
                          size_t message_len, BN_CTX *ctx);

/* Primes from RFC 2409 */
BIGNUM *VR_BN_get_rfc2409_prime_768(BIGNUM *bn);
BIGNUM *VR_BN_get_rfc2409_prime_1024(BIGNUM *bn);

/* Primes from RFC 3526 */
BIGNUM *VR_BN_get_rfc3526_prime_1536(BIGNUM *bn);
BIGNUM *VR_BN_get_rfc3526_prime_2048(BIGNUM *bn);
BIGNUM *VR_BN_get_rfc3526_prime_3072(BIGNUM *bn);
BIGNUM *VR_BN_get_rfc3526_prime_4096(BIGNUM *bn);
BIGNUM *VR_BN_get_rfc3526_prime_6144(BIGNUM *bn);
BIGNUM *VR_BN_get_rfc3526_prime_8192(BIGNUM *bn);

# if !OPENSSL_API_1_1_0
#  define get_rfc2409_prime_768 VR_BN_get_rfc2409_prime_768
#  define get_rfc2409_prime_1024 VR_BN_get_rfc2409_prime_1024
#  define get_rfc3526_prime_1536 VR_BN_get_rfc3526_prime_1536
#  define get_rfc3526_prime_2048 VR_BN_get_rfc3526_prime_2048
#  define get_rfc3526_prime_3072 VR_BN_get_rfc3526_prime_3072
#  define get_rfc3526_prime_4096 VR_BN_get_rfc3526_prime_4096
#  define get_rfc3526_prime_6144 VR_BN_get_rfc3526_prime_6144
#  define get_rfc3526_prime_8192 VR_BN_get_rfc3526_prime_8192
# endif

int VR_BN_bntest_rand(BIGNUM *rnd, int bits, int top, int bottom);


# ifdef  __cplusplus
}
# endif
#endif
