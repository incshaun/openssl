/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/esserr.h>

#ifndef OPENSSL_NO_ERR

static const ERR_STRING_DATA ESS_str_functs[] = {
    {ERR_PACK(ERR_LIB_ESS, ESS_F_ESS_CERT_ID_NEW_INIT, 0),
     "VR_ESS_CERT_ID_new_init"},
    {ERR_PACK(ERR_LIB_ESS, ESS_F_ESS_CERT_ID_V2_NEW_INIT, 0),
     "VR_ESS_CERT_ID_V2_new_init"},
    {ERR_PACK(ERR_LIB_ESS, ESS_F_ESS_SIGNING_CERT_ADD, 0),
     "VR_ESS_SIGNING_CERT_add"},
    {ERR_PACK(ERR_LIB_ESS, ESS_F_ESS_SIGNING_CERT_NEW_INIT, 0),
     "VR_ESS_SIGNING_CERT_new_init"},
    {ERR_PACK(ERR_LIB_ESS, ESS_F_ESS_SIGNING_CERT_V2_ADD, 0),
     "VR_ESS_SIGNING_CERT_V2_add"},
    {ERR_PACK(ERR_LIB_ESS, ESS_F_ESS_SIGNING_CERT_V2_NEW_INIT, 0),
     "VR_ESS_SIGNING_CERT_V2_new_init"},
    {0, NULL}
};

static const ERR_STRING_DATA ESS_str_reasons[] = {
    {ERR_PACK(ERR_LIB_ESS, 0, ESS_R_ESS_SIGNING_CERTIFICATE_ERROR),
    "ess signing certificate error"},
    {ERR_PACK(ERR_LIB_ESS, 0, ESS_R_ESS_SIGNING_CERT_ADD_ERROR),
    "ess signing cert add error"},
    {ERR_PACK(ERR_LIB_ESS, 0, ESS_R_ESS_SIGNING_CERT_V2_ADD_ERROR),
    "ess signing cert v2 add error"},
    {0, NULL}
};

#endif

int VR_ERR_load_ESS_strings(void)
{
#ifndef OPENSSL_NO_ERR
    if (VR_ERR_func_error_string(ESS_str_functs[0].error) == NULL) {
        VR_ERR_load_strings_const(ESS_str_functs);
        VR_ERR_load_strings_const(ESS_str_reasons);
    }
#endif
    return 1;
}
