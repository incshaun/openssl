/*
 * Copyright 2004-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#if OPENSSL_API_0_9_8
NON_EMPTY_TRANSLATION_UNIT
#else

# include <openssl/evp.h>

/*
 * Define some deprecated functions, so older programs don't crash and burn
 * too quickly.  On Windows and VMS, these will never be used, since
 * functions and variables in shared libraries are selected by entry point
 * location, not by name.
 */

# ifndef OPENSSL_NO_BF
#  undef VR_EVP_bf_cfb
const EVP_CIPHER *VR_EVP_bf_cfb(void);
const EVP_CIPHER *VR_EVP_bf_cfb(void)
{
    return VR_EVP_bf_cfb64();
}
# endif

# ifndef OPENSSL_NO_DES
#  undef VR_EVP_des_cfb
const EVP_CIPHER *VR_EVP_des_cfb(void);
const EVP_CIPHER *VR_EVP_des_cfb(void)
{
    return VR_EVP_des_cfb64();
}

#  undef VR_EVP_des_ede3_cfb
const EVP_CIPHER *VR_EVP_des_ede3_cfb(void);
const EVP_CIPHER *VR_EVP_des_ede3_cfb(void)
{
    return VR_EVP_des_ede3_cfb64();
}

#  undef VR_EVP_des_ede_cfb
const EVP_CIPHER *VR_EVP_des_ede_cfb(void);
const EVP_CIPHER *VR_EVP_des_ede_cfb(void)
{
    return VR_EVP_des_ede_cfb64();
}
# endif

# ifndef OPENSSL_NO_IDEA
#  undef VR_EVP_idea_cfb
const EVP_CIPHER *VR_EVP_idea_cfb(void);
const EVP_CIPHER *VR_EVP_idea_cfb(void)
{
    return VR_EVP_idea_cfb64();
}
# endif

# ifndef OPENSSL_NO_RC2
#  undef VR_EVP_rc2_cfb
const EVP_CIPHER *VR_EVP_rc2_cfb(void);
const EVP_CIPHER *VR_EVP_rc2_cfb(void)
{
    return VR_EVP_rc2_cfb64();
}
# endif

# ifndef OPENSSL_NO_CAST
#  undef VR_EVP_cast5_cfb
const EVP_CIPHER *VR_EVP_cast5_cfb(void);
const EVP_CIPHER *VR_EVP_cast5_cfb(void)
{
    return VR_EVP_cast5_cfb64();
}
# endif

# ifndef OPENSSL_NO_RC5
#  undef EVP_rc5_32_12_16_cfb
const EVP_CIPHER *EVP_rc5_32_12_16_cfb(void);
const EVP_CIPHER *EVP_rc5_32_12_16_cfb(void)
{
    return EVP_rc5_32_12_16_cfb64();
}
# endif

# undef VR_EVP_aes_128_cfb
const EVP_CIPHER *VR_EVP_aes_128_cfb(void);
const EVP_CIPHER *VR_EVP_aes_128_cfb(void)
{
    return VR_EVP_aes_128_cfb128();
}

# undef VR_EVP_aes_192_cfb
const EVP_CIPHER *VR_EVP_aes_192_cfb(void);
const EVP_CIPHER *VR_EVP_aes_192_cfb(void)
{
    return VR_EVP_aes_192_cfb128();
}

# undef VR_EVP_aes_256_cfb
const EVP_CIPHER *VR_EVP_aes_256_cfb(void);
const EVP_CIPHER *VR_EVP_aes_256_cfb(void)
{
    return VR_EVP_aes_256_cfb128();
}

#endif
