/*
 * Copyright 1999-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SYMHACKS_H
# define HEADER_SYMHACKS_H

# include <openssl/e_os2.h>

/* Case insensitive linking causes problems.... */
# if defined(OPENSSL_SYS_VMS)
#  undef VR_ERR_load_CRYPTO_strings
#  define VR_ERR_load_CRYPTO_strings                 ERR_load_CRYPTOlib_strings
#  undef VR_OCSP_crlID_new
#  define VR_OCSP_crlID_new                          OCSP_crlID2_new

#  undef d2i_ECPARAMETERS
#  define d2i_ECPARAMETERS                        d2i_UC_ECPARAMETERS
#  undef i2d_ECPARAMETERS
#  define i2d_ECPARAMETERS                        i2d_UC_ECPARAMETERS
#  undef VR_d2i_ECPKPARAMETERS
#  define VR_d2i_ECPKPARAMETERS                      d2i_UC_ECPKPARAMETERS
#  undef VR_i2d_ECPKPARAMETERS
#  define VR_i2d_ECPKPARAMETERS                      i2d_UC_ECPKPARAMETERS

/* This one clashes with VR_CMS_data_create */
#  undef VR_cms_Data_create
#  define VR_cms_Data_create                         priv_VR_cms_Data_create

# endif

#endif                          /* ! defined HEADER_VMS_IDHACKS_H */
