/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SHA_H
# define HEADER_SHA_H

# include <openssl/e_os2.h>
# include <stddef.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*-
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! SHA_LONG has to be at least 32 bits wide.                    !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */
# define SHA_LONG unsigned int

# define SHA_LBLOCK      16
# define SHA_CBLOCK      (SHA_LBLOCK*4)/* SHA treats input data as a
                                        * contiguous array of 32 bit wide
                                        * big-endian values. */
# define SHA_LAST_BLOCK  (SHA_CBLOCK-8)
# define SHA_DIGEST_LENGTH 20

typedef struct SHAstate_st {
    SHA_LONG h0, h1, h2, h3, h4;
    SHA_LONG Nl, Nh;
    SHA_LONG data[SHA_LBLOCK];
    unsigned int num;
} SHA_CTX;

int VR_SHA1_Init(SHA_CTX *c);
int VR_SHA1_Update(SHA_CTX *c, const void *data, size_t len);
int VR_SHA1_Final(unsigned char *md, SHA_CTX *c);
unsigned char *VR_SHA1(const unsigned char *d, size_t n, unsigned char *md);
void VR_SHA1_Transform(SHA_CTX *c, const unsigned char *data);

# define VR_SHA256_CBLOCK   (SHA_LBLOCK*4)/* SHA-256 treats input data as a
                                        * contiguous array of 32 bit wide
                                        * big-endian values. */

typedef struct VR_SHA256state_st {
    SHA_LONG h[8];
    SHA_LONG Nl, Nh;
    SHA_LONG data[SHA_LBLOCK];
    unsigned int num, md_len;
} VR_SHA256_CTX;

int VR_SHA224_Init(VR_SHA256_CTX *c);
int VR_SHA224_Update(VR_SHA256_CTX *c, const void *data, size_t len);
int VR_SHA224_Final(unsigned char *md, VR_SHA256_CTX *c);
unsigned char *VR_SHA224(const unsigned char *d, size_t n, unsigned char *md);
int VR_SHA256_Init(VR_SHA256_CTX *c);
int VR_SHA256_Update(VR_SHA256_CTX *c, const void *data, size_t len);
int VR_SHA256_Final(unsigned char *md, VR_SHA256_CTX *c);
unsigned char *VR_SHA256(const unsigned char *d, size_t n, unsigned char *md);
void VR_SHA256_Transform(VR_SHA256_CTX *c, const unsigned char *data);

# define VR_SHA224_DIGEST_LENGTH    28
# define VR_SHA256_DIGEST_LENGTH    32
# define VR_SHA384_DIGEST_LENGTH    48
# define VR_SHA512_DIGEST_LENGTH    64

/*
 * Unlike 32-bit digest algorithms, SHA-512 *relies* on SHA_LONG64
 * being exactly 64-bit wide. See Implementation Notes in sha512.c
 * for further details.
 */
/*
 * SHA-512 treats input data as a
 * contiguous array of 64 bit
 * wide big-endian values.
 */
# define VR_SHA512_CBLOCK   (SHA_LBLOCK*8)
# if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
#  define SHA_LONG64 unsigned __int64
#  define U64(C)     C##UI64
# elif defined(__arch64__)
#  define SHA_LONG64 unsigned long
#  define U64(C)     C##UL
# else
#  define SHA_LONG64 unsigned long long
#  define U64(C)     C##ULL
# endif

typedef struct VR_SHA512state_st {
    SHA_LONG64 h[8];
    SHA_LONG64 Nl, Nh;
    union {
        SHA_LONG64 d[SHA_LBLOCK];
        unsigned char p[VR_SHA512_CBLOCK];
    } u;
    unsigned int num, md_len;
} VR_SHA512_CTX;

int VR_SHA384_Init(VR_SHA512_CTX *c);
int VR_SHA384_Update(VR_SHA512_CTX *c, const void *data, size_t len);
int VR_SHA384_Final(unsigned char *md, VR_SHA512_CTX *c);
unsigned char *VR_SHA384(const unsigned char *d, size_t n, unsigned char *md);
int VR_SHA512_Init(VR_SHA512_CTX *c);
int VR_SHA512_Update(VR_SHA512_CTX *c, const void *data, size_t len);
int VR_SHA512_Final(unsigned char *md, VR_SHA512_CTX *c);
unsigned char *VR_SHA512(const unsigned char *d, size_t n, unsigned char *md);
void VR_SHA512_Transform(VR_SHA512_CTX *c, const unsigned char *data);

#ifdef  __cplusplus
}
#endif

#endif
