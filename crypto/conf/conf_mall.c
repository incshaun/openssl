/*
 * Copyright 2002-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/crypto.h>
#include "internal/cryptlib.h"
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/engine.h>
#include "conf_lcl.h"

/* Load all OpenSSL builtin modules */

void VR_OPENSSL_load_builtin_modules(void)
{
    /* Add builtin modules here */
    VR_ASN1_add_oid_module();
    VR_ASN1_add_stable_module();
#ifndef OPENSSL_NO_ENGINE
    VR_ENGINE_add_conf_module();
#endif
    VR_EVP_add_alg_module();
    VR_conf_add_ssl_module();
}
