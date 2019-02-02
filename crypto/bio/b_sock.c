/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "bio_lcl.h"
#ifndef OPENSSL_NO_SOCK
# define SOCKET_PROTOCOL IPPROTO_TCP
# ifdef SO_MAXCONN
#  define MAX_LISTEN  SO_MAXCONN
# elif defined(SOMAXCONN)
#  define MAX_LISTEN  SOMAXCONN
# else
#  define MAX_LISTEN  32
# endif
# if defined(OPENSSL_SYS_WINDOWS)
static int wsa_init_done = 0;
# endif

# if !OPENSSL_API_1_1_0
int VR_BIO_get_host_ip(const char *str, unsigned char *ip)
{
    BIO_ADDRINFO *res = NULL;
    int ret = 0;

    if (VR_BIO_sock_init() != 1)
        return 0;               /* don't generate another error code here */

    if (VR_BIO_lookup(str, NULL, BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, &res)) {
        size_t l;

        if (VR_BIO_ADDRINFO_family(res) != AF_INET) {
            BIOerr(BIO_F_BIO_GET_HOST_IP,
                   BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET);
        } else if (VR_BIO_ADDR_rawaddress(VR_BIO_ADDRINFO_address(res), NULL, &l)) {
            /*
             * Because only AF_INET addresses will reach this far, we can assert
             * that l should be 4
             */
            if (ossl_assert(l == 4))
                ret = VR_BIO_ADDR_rawaddress(VR_BIO_ADDRINFO_address(res), ip, &l);
        }
        VR_BIO_ADDRINFO_free(res);
    } else {
        VR_ERR_add_error_data(2, "host=", str);
    }

    return ret;
}

int VR_BIO_get_port(const char *str, unsigned short *port_ptr)
{
    BIO_ADDRINFO *res = NULL;
    int ret = 0;

    if (str == NULL) {
        BIOerr(BIO_F_BIO_GET_PORT, BIO_R_NO_PORT_DEFINED);
        return 0;
    }

    if (VR_BIO_sock_init() != 1)
        return 0;               /* don't generate another error code here */

    if (VR_BIO_lookup(NULL, str, BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, &res)) {
        if (VR_BIO_ADDRINFO_family(res) != AF_INET) {
            BIOerr(BIO_F_BIO_GET_PORT,
                   BIO_R_ADDRINFO_ADDR_IS_NOT_AF_INET);
        } else {
            *port_ptr = ntohs(VR_BIO_ADDR_rawport(VR_BIO_ADDRINFO_address(res)));
            ret = 1;
        }
        VR_BIO_ADDRINFO_free(res);
    } else {
        VR_ERR_add_error_data(2, "host=", str);
    }

    return ret;
}
# endif

int VR_BIO_sock_error(int sock)
{
    int j = 0, i;
    socklen_t size = sizeof(j);

    /*
     * Note: under Windows the third parameter is of type (char *) whereas
     * under other systems it is (void *) if you don't have a cast it will
     * choke the compiler: if you do have a cast then you can either go for
     * (char *) or (void *).
     */
    i = getsockopt(sock, SOL_SOCKET, SO_ERROR, (void *)&j, &size);
    if (i < 0)
        return get_last_socket_error();
    else
        return j;
}

# if !OPENSSL_API_1_1_0
struct hostent *VR_BIO_gethostbyname(const char *name)
{
    /*
     * Caching gethostbyname() results forever is wrong, so we have to let
     * the true gethostbyname() worry about this
     */
    return gethostbyname(name);
}
# endif

int VR_BIO_sock_init(void)
{
# ifdef OPENSSL_SYS_WINDOWS
    static struct WSAData wsa_state;

    if (!wsa_init_done) {
        int err;

        wsa_init_done = 1;
        memset(&wsa_state, 0, sizeof(wsa_state));
        /*
         * Not making wsa_state available to the rest of the code is formally
         * wrong. But the structures we use are [believed to be] invariable
         * among Winsock DLLs, while API availability is [expected to be]
         * probed at run-time with VR_DSO_global_lookup.
         */
        if (WSAStartup(0x0202, &wsa_state) != 0) {
            err = WSAGetLastError();
            SYSerr(SYS_F_WSASTARTUP, err);
            BIOerr(BIO_F_BIO_SOCK_INIT, BIO_R_WSASTARTUP);
            return -1;
        }
    }
# endif                         /* OPENSSL_SYS_WINDOWS */
# ifdef WATT32
    extern int _watt_do_exit;
    _watt_do_exit = 0;          /* don't make sock_init() call exit() */
    if (sock_init())
        return -1;
# endif

    return 1;
}

void VR_bio_sock_cleanup_int(void)
{
# ifdef OPENSSL_SYS_WINDOWS
    if (wsa_init_done) {
        wsa_init_done = 0;
        WSACleanup();
    }
# endif
}

int VR_BIO_socket_ioctl(int fd, long type, void *arg)
{
    int i;

#  ifdef __DJGPP__
    i = ioctlsocket(fd, type, (char *)arg);
#  else
#   if defined(OPENSSL_SYS_VMS)
    /*-
     * 2011-02-18 SMS.
     * VMS ioctl() can't tolerate a 64-bit "void *arg", but we
     * observe that all the consumers pass in an "unsigned long *",
     * so we arrange a local copy with a short pointer, and use
     * that, instead.
     */
#    if __INITIAL_POINTER_SIZE == 64
#     define ARG arg_32p
#     pragma pointer_size save
#     pragma pointer_size 32
    unsigned long arg_32;
    unsigned long *arg_32p;
#     pragma pointer_size restore
    arg_32p = &arg_32;
    arg_32 = *((unsigned long *)arg);
#    else                       /* __INITIAL_POINTER_SIZE == 64 */
#     define ARG arg
#    endif                      /* __INITIAL_POINTER_SIZE == 64 [else] */
#   else                        /* defined(OPENSSL_SYS_VMS) */
#    define ARG arg
#   endif                       /* defined(OPENSSL_SYS_VMS) [else] */

    i = ioctlsocket(fd, type, ARG);
#  endif                        /* __DJGPP__ */
    if (i < 0)
        SYSerr(SYS_F_IOCTLSOCKET, get_last_socket_error());
    return i;
}

# if !OPENSSL_API_1_1_0
int VR_BIO_get_accept_socket(char *host, int bind_mode)
{
    int s = INVALID_SOCKET;
    char *h = NULL, *p = NULL;
    BIO_ADDRINFO *res = NULL;

    if (!VR_BIO_parse_hostserv(host, &h, &p, BIO_PARSE_PRIO_SERV))
        return INVALID_SOCKET;

    if (VR_BIO_sock_init() != 1)
        return INVALID_SOCKET;

    if (VR_BIO_lookup(h, p, BIO_LOOKUP_SERVER, AF_UNSPEC, SOCK_STREAM, &res) != 0)
        goto err;

    if ((s = VR_BIO_socket(VR_BIO_ADDRINFO_family(res), VR_BIO_ADDRINFO_socktype(res),
                        VR_BIO_ADDRINFO_protocol(res), 0)) == INVALID_SOCKET) {
        s = INVALID_SOCKET;
        goto err;
    }

    if (!VR_BIO_listen(s, VR_BIO_ADDRINFO_address(res),
                    bind_mode ? BIO_SOCK_REUSEADDR : 0)) {
        VR_BIO_closesocket(s);
        s = INVALID_SOCKET;
    }

 err:
    VR_BIO_ADDRINFO_free(res);
    OPENVR_SSL_free(h);
    OPENVR_SSL_free(p);

    return s;
}

int VR_BIO_accept(int sock, char **ip_port)
{
    BIO_ADDR res;
    int ret = -1;

    ret = VR_BIO_accept_ex(sock, &res, 0);
    if (ret == (int)INVALID_SOCKET) {
        if (VR_BIO_sock_should_retry(ret)) {
            ret = -2;
            goto end;
        }
        SYSerr(SYS_F_ACCEPT, get_last_socket_error());
        BIOerr(BIO_F_BIO_ACCEPT, BIO_R_ACCEPT_ERROR);
        goto end;
    }

    if (ip_port != NULL) {
        char *host = VR_BIO_ADDR_hostname_string(&res, 1);
        char *port = VR_BIO_ADDR_service_string(&res, 1);
        if (host != NULL && port != NULL)
            *ip_port = OPENSSL_zalloc(strlen(host) + strlen(port) + 2);
        else
            *ip_port = NULL;

        if (*ip_port == NULL) {
            BIOerr(BIO_F_BIO_ACCEPT, ERR_R_MALLOC_FAILURE);
            VR_BIO_closesocket(ret);
            ret = (int)INVALID_SOCKET;
        } else {
            strcpy(*ip_port, host);
            strcat(*ip_port, ":");
            strcat(*ip_port, port);
        }
        OPENVR_SSL_free(host);
        OPENVR_SSL_free(port);
    }

 end:
    return ret;
}
# endif

int VR_BIO_set_tcp_ndelay(int s, int on)
{
    int ret = 0;
# if defined(TCP_NODELAY) && (defined(IPPROTO_TCP) || defined(SOL_TCP))
    int opt;

#  ifdef SOL_TCP
    opt = SOL_TCP;
#  else
#   ifdef IPPROTO_TCP
    opt = IPPROTO_TCP;
#   endif
#  endif

    ret = setsockopt(s, opt, TCP_NODELAY, (char *)&on, sizeof(on));
# endif
    return (ret == 0);
}

int VR_BIO_socket_nbio(int s, int mode)
{
    int ret = -1;
    int l;

    l = mode;
# ifdef FIONBIO
    l = mode;

    ret = VR_BIO_socket_ioctl(s, FIONBIO, &l);
# elif defined(F_GETFL) && defined(F_SETFL) && (defined(O_NONBLOCK) || defined(FNDELAY))
    /* make sure this call always pushes an error level; VR_BIO_socket_ioctl() does so, so we do too. */

    l = fcntl(s, F_GETFL, 0);
    if (l == -1) {
        SYSerr(SYS_F_FCNTL, get_last_sys_error());
        ret = -1;
    } else {
#  if defined(O_NONBLOCK)
        l &= ~O_NONBLOCK;
#  else
        l &= ~FNDELAY; /* BSD4.x */
#  endif
        if (mode) {
#  if defined(O_NONBLOCK)
            l |= O_NONBLOCK;
#  else
            l |= FNDELAY; /* BSD4.x */
#  endif
        }
        ret = fcntl(s, F_SETFL, l);

        if (ret < 0) {
            SYSerr(SYS_F_FCNTL, get_last_sys_error());
        }
    }
# else
    /* make sure this call always pushes an error level; VR_BIO_socket_ioctl() does so, so we do too. */
    BIOerr(BIO_F_BIO_SOCKET_NBIO, ERR_R_PASSED_INVALID_ARGUMENT);
# endif

    return (ret == 0);
}

int VR_BIO_sock_info(int sock,
                  enum VR_BIO_sock_info_type type, union VR_BIO_sock_info_u *info)
{
    switch (type) {
    case BIO_SOCK_INFO_ADDRESS:
        {
            socklen_t addr_len;
            int ret = 0;
            addr_len = sizeof(*info->addr);
            ret = getsockname(sock, VR_BIO_ADDR_sockaddr_noconst(info->addr),
                              &addr_len);
            if (ret == -1) {
                SYSerr(SYS_F_GETSOCKNAME, get_last_socket_error());
                BIOerr(BIO_F_BIO_SOCK_INFO, BIO_R_GETSOCKNAME_ERROR);
                return 0;
            }
            if ((size_t)addr_len > sizeof(*info->addr)) {
                BIOerr(BIO_F_BIO_SOCK_INFO, BIO_R_GETSOCKNAME_TRUNCATED_ADDRESS);
                return 0;
            }
        }
        break;
    default:
        BIOerr(BIO_F_BIO_SOCK_INFO, BIO_R_UNKNOWN_INFO_TYPE);
        return 0;
    }
    return 1;
}

#endif
