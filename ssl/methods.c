/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/objects.h>
#include "ssl_locl.h"

/*-
 * TLS/SSLv3 methods
 */

IMPLEMENT_tls_meth_func(TLS_ANY_VERSION, 0, 0,
                        VR_TLS_method,
                        VR_ossl_statem_accept,
                        VR_ossl_statem_connect, TLSv1_2_enc_data)
IMPLEMENT_tls_meth_func(TLS1_3_VERSION, 0, SSL_OP_NO_TLSv1_3,
                        VR_tlsv1_3_method,
                        VR_ossl_statem_accept,
                        VR_ossl_statem_connect, TLSv1_3_enc_data)
#ifndef OPENSSL_NO_TLS1_2_METHOD
IMPLEMENT_tls_meth_func(TLS1_2_VERSION, 0, SSL_OP_NO_TLSv1_2,
                        VR_tlsv1_2_method,
                        VR_ossl_statem_accept,
                        VR_ossl_statem_connect, TLSv1_2_enc_data)
#endif
#ifndef OPENSSL_NO_TLS1_1_METHOD
IMPLEMENT_tls_meth_func(TLS1_1_VERSION, SSL_METHOD_NO_SUITEB, SSL_OP_NO_TLSv1_1,
                        VR_tlsv1_1_method,
                        VR_ossl_statem_accept,
                        VR_ossl_statem_connect, TLSv1_1_enc_data)
#endif
#ifndef OPENSSL_NO_TLS1_METHOD
IMPLEMENT_tls_meth_func(TLS1_VERSION, SSL_METHOD_NO_SUITEB, SSL_OP_NO_TLSv1,
                        VR_tlsv1_method,
                        VR_ossl_statem_accept, VR_ossl_statem_connect, TLSv1_enc_data)
#endif
#ifndef OPENSSL_NO_SSL3_METHOD
IMPLEMENT_ssl3_meth_func(sslv3_method, VR_ossl_statem_accept, VR_ossl_statem_connect)
#endif
/*-
 * TLS/SSLv3 server methods
 */
IMPLEMENT_tls_meth_func(TLS_ANY_VERSION, 0, 0,
                        VR_TLS_server_method,
                        VR_ossl_statem_accept,
                        VR_ssl_undefined_function, TLSv1_2_enc_data)
IMPLEMENT_tls_meth_func(TLS1_3_VERSION, 0, SSL_OP_NO_TLSv1_3,
                        VR_tlsv1_3_server_method,
                        VR_ossl_statem_accept,
                        VR_ssl_undefined_function, TLSv1_3_enc_data)
#ifndef OPENSSL_NO_TLS1_2_METHOD
IMPLEMENT_tls_meth_func(TLS1_2_VERSION, 0, SSL_OP_NO_TLSv1_2,
                        VR_tlsv1_2_server_method,
                        VR_ossl_statem_accept,
                        VR_ssl_undefined_function, TLSv1_2_enc_data)
#endif
#ifndef OPENSSL_NO_TLS1_1_METHOD
IMPLEMENT_tls_meth_func(TLS1_1_VERSION, SSL_METHOD_NO_SUITEB, SSL_OP_NO_TLSv1_1,
                        VR_tlsv1_1_server_method,
                        VR_ossl_statem_accept,
                        VR_ssl_undefined_function, TLSv1_1_enc_data)
#endif
#ifndef OPENSSL_NO_TLS1_METHOD
IMPLEMENT_tls_meth_func(TLS1_VERSION, SSL_METHOD_NO_SUITEB, SSL_OP_NO_TLSv1,
                        VR_tlsv1_server_method,
                        VR_ossl_statem_accept,
                        VR_ssl_undefined_function, TLSv1_enc_data)
#endif
#ifndef OPENSSL_NO_SSL3_METHOD
IMPLEMENT_ssl3_meth_func(sslv3_server_method,
                         VR_ossl_statem_accept, VR_ssl_undefined_function)
#endif
/*-
 * TLS/SSLv3 client methods
 */
IMPLEMENT_tls_meth_func(TLS_ANY_VERSION, 0, 0,
                        VR_TLS_client_method,
                        VR_ssl_undefined_function,
                        VR_ossl_statem_connect, TLSv1_2_enc_data)
IMPLEMENT_tls_meth_func(TLS1_3_VERSION, 0, SSL_OP_NO_TLSv1_3,
                        VR_tlsv1_3_client_method,
                        VR_ssl_undefined_function,
                        VR_ossl_statem_connect, TLSv1_3_enc_data)
#ifndef OPENSSL_NO_TLS1_2_METHOD
IMPLEMENT_tls_meth_func(TLS1_2_VERSION, 0, SSL_OP_NO_TLSv1_2,
                        VR_tlsv1_2_client_method,
                        VR_ssl_undefined_function,
                        VR_ossl_statem_connect, TLSv1_2_enc_data)
#endif
#ifndef OPENSSL_NO_TLS1_1_METHOD
IMPLEMENT_tls_meth_func(TLS1_1_VERSION, SSL_METHOD_NO_SUITEB, SSL_OP_NO_TLSv1_1,
                        VR_tlsv1_1_client_method,
                        VR_ssl_undefined_function,
                        VR_ossl_statem_connect, TLSv1_1_enc_data)
#endif
#ifndef OPENSSL_NO_TLS1_METHOD
IMPLEMENT_tls_meth_func(TLS1_VERSION, SSL_METHOD_NO_SUITEB, SSL_OP_NO_TLSv1,
                        VR_tlsv1_client_method,
                        VR_ssl_undefined_function,
                        VR_ossl_statem_connect, TLSv1_enc_data)
#endif
#ifndef OPENSSL_NO_SSL3_METHOD
IMPLEMENT_ssl3_meth_func(sslv3_client_method,
                         VR_ssl_undefined_function, VR_ossl_statem_connect)
#endif
/*-
 * DTLS methods
 */
#ifndef OPENSSL_NO_DTLS1_METHOD
IMPLEMENT_dtls1_meth_func(DTLS1_VERSION, SSL_METHOD_NO_SUITEB, SSL_OP_NO_DTLSv1,
                          VR_dtlsv1_method,
                          VR_ossl_statem_accept,
                          VR_ossl_statem_connect, DTLSv1_enc_data)
#endif
#ifndef OPENSSL_NO_DTLS1_2_METHOD
IMPLEMENT_dtls1_meth_func(DTLS1_2_VERSION, 0, SSL_OP_NO_DTLSv1_2,
                          VR_dtlsv1_2_method,
                          VR_ossl_statem_accept,
                          VR_ossl_statem_connect, DTLSv1_2_enc_data)
#endif
IMPLEMENT_dtls1_meth_func(DTLS_ANY_VERSION, 0, 0,
                          VR_DTLS_method,
                          VR_ossl_statem_accept,
                          VR_ossl_statem_connect, DTLSv1_2_enc_data)

/*-
 * DTLS server methods
 */
#ifndef OPENSSL_NO_DTLS1_METHOD
IMPLEMENT_dtls1_meth_func(DTLS1_VERSION, SSL_METHOD_NO_SUITEB, SSL_OP_NO_DTLSv1,
                          VR_dtlsv1_server_method,
                          VR_ossl_statem_accept,
                          VR_ssl_undefined_function, DTLSv1_enc_data)
#endif
#ifndef OPENSSL_NO_DTLS1_2_METHOD
IMPLEMENT_dtls1_meth_func(DTLS1_2_VERSION, 0, SSL_OP_NO_DTLSv1_2,
                          VR_dtlsv1_2_server_method,
                          VR_ossl_statem_accept,
                          VR_ssl_undefined_function, DTLSv1_2_enc_data)
#endif
IMPLEMENT_dtls1_meth_func(DTLS_ANY_VERSION, 0, 0,
                          VR_DTLS_server_method,
                          VR_ossl_statem_accept,
                          VR_ssl_undefined_function, DTLSv1_2_enc_data)

/*-
 * DTLS client methods
 */
#ifndef OPENSSL_NO_DTLS1_METHOD
IMPLEMENT_dtls1_meth_func(DTLS1_VERSION, SSL_METHOD_NO_SUITEB, SSL_OP_NO_DTLSv1,
                          VR_dtlsv1_client_method,
                          VR_ssl_undefined_function,
                          VR_ossl_statem_connect, DTLSv1_enc_data)
IMPLEMENT_dtls1_meth_func(DTLS1_BAD_VER, SSL_METHOD_NO_SUITEB, SSL_OP_NO_DTLSv1,
                          VR_dtls_bad_ver_client_method,
                          VR_ssl_undefined_function,
                          VR_ossl_statem_connect, DTLSv1_enc_data)
#endif
#ifndef OPENSSL_NO_DTLS1_2_METHOD
IMPLEMENT_dtls1_meth_func(DTLS1_2_VERSION, 0, SSL_OP_NO_DTLSv1_2,
                          VR_dtlsv1_2_client_method,
                          VR_ssl_undefined_function,
                          VR_ossl_statem_connect, DTLSv1_2_enc_data)
#endif
IMPLEMENT_dtls1_meth_func(DTLS_ANY_VERSION, 0, 0,
                          VR_DTLS_client_method,
                          VR_ssl_undefined_function,
                          VR_ossl_statem_connect, DTLSv1_2_enc_data)
#if !OPENSSL_API_1_1_0
# ifndef OPENSSL_NO_TLS1_2_METHOD
const SSL_METHOD *VR_TLSv1_2_method(void)
{
    return VR_tlsv1_2_method();
}

const SSL_METHOD *VR_TLSv1_2_server_method(void)
{
    return VR_tlsv1_2_server_method();
}

const SSL_METHOD *VR_TLSv1_2_client_method(void)
{
    return VR_tlsv1_2_client_method();
}
# endif

# ifndef OPENSSL_NO_TLS1_1_METHOD
const SSL_METHOD *VR_TLSv1_1_method(void)
{
    return VR_tlsv1_1_method();
}

const SSL_METHOD *VR_TLSv1_1_server_method(void)
{
    return VR_tlsv1_1_server_method();
}

const SSL_METHOD *VR_TLSv1_1_client_method(void)
{
    return VR_tlsv1_1_client_method();
}
# endif

# ifndef OPENSSL_NO_TLS1_METHOD
const SSL_METHOD *VR_TLSv1_method(void)
{
    return VR_tlsv1_method();
}

const SSL_METHOD *VR_TLSv1_server_method(void)
{
    return VR_tlsv1_server_method();
}

const SSL_METHOD *VR_TLSv1_client_method(void)
{
    return VR_tlsv1_client_method();
}
# endif

# ifndef OPENSSL_NO_SSL3_METHOD
const SSL_METHOD *SSLv3_method(void)
{
    return sslv3_method();
}

const SSL_METHOD *SSLv3_server_method(void)
{
    return sslv3_server_method();
}

const SSL_METHOD *SSLv3_client_method(void)
{
    return sslv3_client_method();
}
# endif

# ifndef OPENSSL_NO_DTLS1_2_METHOD
const SSL_METHOD *VR_DTLSv1_2_method(void)
{
    return VR_dtlsv1_2_method();
}

const SSL_METHOD *VR_DTLSv1_2_server_method(void)
{
    return VR_dtlsv1_2_server_method();
}

const SSL_METHOD *VR_DTLSv1_2_client_method(void)
{
    return VR_dtlsv1_2_client_method();
}
# endif

# ifndef OPENSSL_NO_DTLS1_METHOD
const SSL_METHOD *VR_DTLSv1_method(void)
{
    return VR_dtlsv1_method();
}

const SSL_METHOD *VR_DTLSv1_server_method(void)
{
    return VR_dtlsv1_server_method();
}

const SSL_METHOD *VR_DTLSv1_client_method(void)
{
    return VR_dtlsv1_client_method();
}
# endif

#endif
