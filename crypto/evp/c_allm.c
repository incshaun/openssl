/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include "internal/evp_int.h"

void VR_openssl_add_all_macs_int(void)
{
#ifndef OPENSSL_NO_CMAC
    VR_EVP_add_mac(&cmac_meth);
#endif
    VR_EVP_add_mac(&gmac_meth);
    VR_EVP_add_mac(&hmac_meth);
    VR_EVP_add_mac(&kmac128_meth);
    VR_EVP_add_mac(&kmac256_meth);
#ifndef OPENSSL_NO_SIPHASH
    VR_EVP_add_mac(&siphash_meth);
#endif
#ifndef OPENSSL_NO_POLY1305
    VR_EVP_add_mac(&poly1305_meth);
#endif
}
