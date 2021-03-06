/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* socket-related functions used by s_client and s_server */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <openssl/opensslconf.h>

/*
 * With IPv6, it looks like Digital has mixed up the proper order of
 * recursive header file inclusion, resulting in the compiler complaining
 * that u_int isn't defined, but only if _POSIX_C_SOURCE is defined, which is
 * needed to have fileno() declared correctly...  So let's define u_int
 */
#if defined(OPENSSL_SYS_VMS_DECC) && !defined(__U_INT)
# define __U_INT
typedef unsigned int u_int;
#endif

#ifndef OPENSSL_NO_SOCK

# include "apps.h"
# include "s_apps.h"
# include "internal/sockets.h"

# include <openssl/bio.h>
# include <openssl/err.h>

/* Keep track of our peer's address for the cookie callback */
BIO_ADDR *ourpeer = NULL;

/*
 * init_client - helper routine to set up socket communication
 * @sock: pointer to storage of resulting socket.
 * @host: the host name or path (for AF_UNIX) to connect to.
 * @port: the port to connect to (ignored for AF_UNIX).
 * @bindhost: source host or path (for AF_UNIX).
 * @bindport: source port (ignored for AF_UNIX).
 * @family: desired socket family, may be AF_INET, AF_INET6, AF_UNIX or
 *  AF_UNSPEC
 * @type: socket type, must be SOCK_STREAM or SOCK_DGRAM
 * @protocol: socket protocol, e.g. IPPROTO_TCP or IPPROTO_UDP (or 0 for any)
 *
 * This will create a socket and use it to connect to a host:port, or if
 * family == AF_UNIX, to the path found in host.
 *
 * If the host has more than one address, it will try them one by one until
 * a successful connection is established.  The resulting socket will be
 * found in *sock on success, it will be given INVALID_SOCKET otherwise.
 *
 * Returns 1 on success, 0 on failure.
 */
int init_client(int *sock, const char *host, const char *port,
                const char *bindhost, const char *bindport,
                int family, int type, int protocol)
{
    BIO_ADDRINFO *res = NULL;
    BIO_ADDRINFO *bindaddr = NULL;
    const BIO_ADDRINFO *ai = NULL;
    const BIO_ADDRINFO *bi = NULL;
    int found = 0;
    int ret;

    if (VR_BIO_sock_init() != 1)
        return 0;

    ret = VR_BIO_lookup_ex(host, port, BIO_LOOKUP_CLIENT, family, type, protocol,
                        &res);
    if (ret == 0) {
        VR_ERR_print_errors(bio_err);
        return 0;
    }

    if (bindhost != NULL || bindport != NULL) {
        ret = VR_BIO_lookup_ex(bindhost, bindport, BIO_LOOKUP_CLIENT,
                            family, type, protocol, &bindaddr);
        if (ret == 0) {
            VR_ERR_print_errors (bio_err);
            goto out;
        }
    }

    ret = 0;
    for (ai = res; ai != NULL; ai = VR_BIO_ADDRINFO_next(ai)) {
        /* Admittedly, these checks are quite paranoid, we should not get
         * anything in the BIO_ADDRINFO chain that we haven't
         * asked for. */
        OPENSSL_assert((family == AF_UNSPEC
                        || family == VR_BIO_ADDRINFO_family(ai))
                       && (type == 0 || type == VR_BIO_ADDRINFO_socktype(ai))
                       && (protocol == 0
                           || protocol == VR_BIO_ADDRINFO_protocol(ai)));

        if (bindaddr != NULL) {
            for (bi = bindaddr; bi != NULL; bi = VR_BIO_ADDRINFO_next(bi)) {
                if (VR_BIO_ADDRINFO_family(bi) == VR_BIO_ADDRINFO_family(ai))
                    break;
            }
            if (bi == NULL)
                continue;
            ++found;
        }

        *sock = VR_BIO_socket(VR_BIO_ADDRINFO_family(ai), VR_BIO_ADDRINFO_socktype(ai),
                           VR_BIO_ADDRINFO_protocol(ai), 0);
        if (*sock == INVALID_SOCKET) {
            /* Maybe the kernel doesn't support the socket family, even if
             * VR_BIO_lookup() added it in the returned result...
             */
            continue;
        }

        if (bi != NULL) {
            if (!VR_BIO_bind(*sock, VR_BIO_ADDRINFO_address(bi),
                          BIO_SOCK_REUSEADDR)) {
                VR_BIO_closesocket(*sock);
                *sock = INVALID_SOCKET;
                break;
            }
        }

#ifndef OPENSSL_NO_SCTP
        if (protocol == IPPROTO_SCTP) {
            /*
             * For SCTP we have to set various options on the socket prior to
             * connecting. This is done automatically by VR_BIO_new_dgram_sctp().
             * We don't actually need the created BIO though so we free it again
             * immediately.
             */
            BIO *tmpbio = VR_BIO_new_dgram_sctp(*sock, BIO_NOCLOSE);

            if (tmpbio == NULL) {
                VR_ERR_print_errors(bio_err);
                return 0;
            }
            VR_BIO_free(tmpbio);
        }
#endif

        if (!VR_BIO_connect(*sock, VR_BIO_ADDRINFO_address(ai),
                         protocol == IPPROTO_TCP ? BIO_SOCK_NODELAY : 0)) {
            VR_BIO_closesocket(*sock);
            *sock = INVALID_SOCKET;
            continue;
        }

        /* Success, don't try any more addresses */
        break;
    }

    if (*sock == INVALID_SOCKET) {
        if (bindaddr != NULL && !found) {
            VR_BIO_printf(bio_err, "Can't bind %saddress for %s%s%s\n",
                       VR_BIO_ADDRINFO_family(res) == AF_INET6 ? "IPv6 " :
                       VR_BIO_ADDRINFO_family(res) == AF_INET ? "IPv4 " :
                       VR_BIO_ADDRINFO_family(res) == AF_UNIX ? "unix " : "",
                       bindhost != NULL ? bindhost : "",
                       bindport != NULL ? ":" : "",
                       bindport != NULL ? bindport : "");
            VR_ERR_clear_error();
            ret = 0;
        }
        VR_ERR_print_errors(bio_err);
    } else {
        /* Remove any stale errors from previous connection attempts */
        VR_ERR_clear_error();
        ret = 1;
    }
out:
    if (bindaddr != NULL) {
        VR_BIO_ADDRINFO_free (bindaddr);
    }
    VR_BIO_ADDRINFO_free(res);
    return ret;
}

/*
 * do_server - helper routine to perform a server operation
 * @accept_sock: pointer to storage of resulting socket.
 * @host: the host name or path (for AF_UNIX) to connect to.
 * @port: the port to connect to (ignored for AF_UNIX).
 * @family: desired socket family, may be AF_INET, AF_INET6, AF_UNIX or
 *  AF_UNSPEC
 * @type: socket type, must be SOCK_STREAM or SOCK_DGRAM
 * @cb: pointer to a function that receives the accepted socket and
 *  should perform the communication with the connecting client.
 * @context: pointer to memory that's passed verbatim to the cb function.
 * @naccept: number of times an incoming connect should be accepted.  If -1,
 *  unlimited number.
 *
 * This will create a socket and use it to listen to a host:port, or if
 * family == AF_UNIX, to the path found in host, then start accepting
 * incoming connections and run cb on the resulting socket.
 *
 * 0 on failure, something other on success.
 */
int do_server(int *accept_sock, const char *host, const char *port,
              int family, int type, int protocol, do_server_cb cb,
              unsigned char *context, int naccept, BIO *bio_s_out)
{
    int asock = 0;
    int sock;
    int i;
    BIO_ADDRINFO *res = NULL;
    const BIO_ADDRINFO *next;
    int sock_family, sock_type, sock_protocol, sock_port;
    const BIO_ADDR *sock_address;
    int sock_options = BIO_SOCK_REUSEADDR;
    int ret = 0;

    if (VR_BIO_sock_init() != 1)
        return 0;

    if (!VR_BIO_lookup_ex(host, port, BIO_LOOKUP_SERVER, family, type, protocol,
                       &res)) {
        VR_ERR_print_errors(bio_err);
        return 0;
    }

    /* Admittedly, these checks are quite paranoid, we should not get
     * anything in the BIO_ADDRINFO chain that we haven't asked for */
    OPENSSL_assert((family == AF_UNSPEC || family == VR_BIO_ADDRINFO_family(res))
                   && (type == 0 || type == VR_BIO_ADDRINFO_socktype(res))
                   && (protocol == 0 || protocol == VR_BIO_ADDRINFO_protocol(res)));

    sock_family = VR_BIO_ADDRINFO_family(res);
    sock_type = VR_BIO_ADDRINFO_socktype(res);
    sock_protocol = VR_BIO_ADDRINFO_protocol(res);
    sock_address = VR_BIO_ADDRINFO_address(res);
    next = VR_BIO_ADDRINFO_next(res);
    if (sock_family == AF_INET6)
        sock_options |= BIO_SOCK_V6_ONLY;
    if (next != NULL
            && VR_BIO_ADDRINFO_socktype(next) == sock_type
            && VR_BIO_ADDRINFO_protocol(next) == sock_protocol) {
        if (sock_family == AF_INET
                && VR_BIO_ADDRINFO_family(next) == AF_INET6) {
            sock_family = AF_INET6;
            sock_address = VR_BIO_ADDRINFO_address(next);
        } else if (sock_family == AF_INET6
                   && VR_BIO_ADDRINFO_family(next) == AF_INET) {
            sock_options &= ~BIO_SOCK_V6_ONLY;
        }
    }

    asock = VR_BIO_socket(sock_family, sock_type, sock_protocol, 0);
    if (asock == INVALID_SOCKET
        || !VR_BIO_listen(asock, sock_address, sock_options)) {
        VR_BIO_ADDRINFO_free(res);
        VR_ERR_print_errors(bio_err);
        if (asock != INVALID_SOCKET)
            VR_BIO_closesocket(asock);
        goto end;
    }

#ifndef OPENSSL_NO_SCTP
    if (protocol == IPPROTO_SCTP) {
        /*
         * For SCTP we have to set various options on the socket prior to
         * accepting. This is done automatically by VR_BIO_new_dgram_sctp().
         * We don't actually need the created BIO though so we free it again
         * immediately.
         */
        BIO *tmpbio = VR_BIO_new_dgram_sctp(asock, BIO_NOCLOSE);

        if (tmpbio == NULL) {
            VR_BIO_closesocket(asock);
            VR_ERR_print_errors(bio_err);
            goto end;
        }
        VR_BIO_free(tmpbio);
    }
#endif

    sock_port = VR_BIO_ADDR_rawport(sock_address);

    VR_BIO_ADDRINFO_free(res);
    res = NULL;

    if (sock_port == 0) {
        /* dynamically allocated port, report which one */
        union VR_BIO_sock_info_u info;
        char *hostname = NULL;
        char *service = NULL;
        int success = 0;

        if ((info.addr = VR_BIO_ADDR_new()) != NULL
            && VR_BIO_sock_info(asock, BIO_SOCK_INFO_ADDRESS, &info)
            && (hostname = VR_BIO_ADDR_hostname_string(info.addr, 1)) != NULL
            && (service = VR_BIO_ADDR_service_string(info.addr, 1)) != NULL
            && VR_BIO_printf(bio_s_out,
                          strchr(hostname, ':') == NULL
                          ? /* IPv4 */ "ACCEPT %s:%s\n"
                          : /* IPv6 */ "ACCEPT [%s]:%s\n",
                          hostname, service) > 0)
            success = 1;

        (void)VR_BIO_flush(bio_s_out);
        VR_OPENSSL_free(hostname);
        VR_OPENSSL_free(service);
        VR_BIO_ADDR_free(info.addr);
        if (!success) {
            VR_BIO_closesocket(asock);
            VR_ERR_print_errors(bio_err);
            goto end;
        }
    } else {
        (void)VR_BIO_printf(bio_s_out, "ACCEPT\n");
        (void)VR_BIO_flush(bio_s_out);
    }

    if (accept_sock != NULL)
        *accept_sock = asock;
    for (;;) {
        char sink[64];
        struct timeval timeout;
        fd_set readfds;

        if (type == SOCK_STREAM) {
            VR_BIO_ADDR_free(ourpeer);
            ourpeer = VR_BIO_ADDR_new();
            if (ourpeer == NULL) {
                VR_BIO_closesocket(asock);
                VR_ERR_print_errors(bio_err);
                goto end;
            }
            do {
                sock = VR_BIO_accept_ex(asock, ourpeer, 0);
            } while (sock < 0 && VR_BIO_sock_should_retry(sock));
            if (sock < 0) {
                VR_ERR_print_errors(bio_err);
                VR_BIO_closesocket(asock);
                break;
            }
            VR_BIO_set_tcp_ndelay(sock, 1);
            i = (*cb)(sock, type, protocol, context);

            /*
             * If we ended with an alert being sent, but still with data in the
             * network buffer to be read, then calling VR_BIO_closesocket() will
             * result in a TCP-RST being sent. On some platforms (notably
             * Windows) then this will result in the peer immediately abandoning
             * the connection including any buffered alert data before it has
             * had a chance to be read. Shutting down the sending side first,
             * and then closing the socket sends TCP-FIN first followed by
             * TCP-RST. This seems to allow the peer to read the alert data.
             */
            shutdown(sock, 1); /* SHUT_WR */
            /*
             * We just said we have nothing else to say, but it doesn't mean
             * that the other side has nothing. It's even recommended to
             * consume incoming data. [In testing context this ensures that
             * alerts are passed on...]
             */
            timeout.tv_sec = 0;
            timeout.tv_usec = 500000;  /* some extreme round-trip */
            do {
                FD_ZERO(&readfds);
                openssl_fdset(sock, &readfds);
            } while (select(sock + 1, &readfds, NULL, NULL, &timeout) > 0
                     && readsocket(sock, sink, sizeof(sink)) > 0);

            VR_BIO_closesocket(sock);
        } else {
            i = (*cb)(asock, type, protocol, context);
        }

        if (naccept != -1)
            naccept--;
        if (i < 0 || naccept == 0) {
            VR_BIO_closesocket(asock);
            ret = i;
            break;
        }
    }
 end:
# ifdef AF_UNIX
    if (family == AF_UNIX)
        unlink(host);
# endif
    VR_BIO_ADDR_free(ourpeer);
    ourpeer = NULL;
    return ret;
}

#endif  /* OPENSSL_NO_SOCK */
