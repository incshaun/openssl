/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_BIO_H
# define HEADER_BIO_H

# include <openssl/e_os2.h>

# ifndef OPENSSL_NO_STDIO
#  include <stdio.h>
# endif
# include <stdarg.h>

# include <openssl/crypto.h>
# include <openssl/bioerr.h>

# ifndef OPENSSL_NO_SCTP
#  include <openssl/e_os2.h>
# endif

#ifdef  __cplusplus
extern "C" {
#endif

/* There are the classes of BIOs */
# define BIO_TYPE_DESCRIPTOR     0x0100 /* socket, fd, connect or accept */
# define BIO_TYPE_FILTER         0x0200
# define BIO_TYPE_SOURCE_SINK    0x0400

/* These are the 'types' of BIOs */
# define BIO_TYPE_NONE             0
# define BIO_TYPE_MEM            ( 1|BIO_TYPE_SOURCE_SINK)
# define BIO_TYPE_FILE           ( 2|BIO_TYPE_SOURCE_SINK)

# define BIO_TYPE_FD             ( 4|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR)
# define BIO_TYPE_SOCKET         ( 5|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR)
# define BIO_TYPE_NULL           ( 6|BIO_TYPE_SOURCE_SINK)
# define BIO_TYPE_SSL            ( 7|BIO_TYPE_FILTER)
# define BIO_TYPE_MD             ( 8|BIO_TYPE_FILTER)
# define BIO_TYPE_BUFFER         ( 9|BIO_TYPE_FILTER)
# define BIO_TYPE_CIPHER         (10|BIO_TYPE_FILTER)
# define BIO_TYPE_BASE64         (11|BIO_TYPE_FILTER)
# define BIO_TYPE_CONNECT        (12|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR)
# define BIO_TYPE_ACCEPT         (13|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR)

# define BIO_TYPE_NBIO_TEST      (16|BIO_TYPE_FILTER)/* server proxy BIO */
# define BIO_TYPE_NULL_FILTER    (17|BIO_TYPE_FILTER)
# define BIO_TYPE_BIO            (19|BIO_TYPE_SOURCE_SINK)/* half a BIO pair */
# define BIO_TYPE_LINEBUFFER     (20|BIO_TYPE_FILTER)
# define BIO_TYPE_DGRAM          (21|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR)
# define BIO_TYPE_ASN1           (22|BIO_TYPE_FILTER)
# define BIO_TYPE_COMP           (23|BIO_TYPE_FILTER)
# ifndef OPENSSL_NO_SCTP
#  define BIO_TYPE_DGRAM_SCTP    (24|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR)
# endif

#define BIO_TYPE_START           128

/*
 * BIO_FILENAME_READ|BIO_CLOSE to open or close on free.
 * BIO_set_fp(in,stdin,BIO_NOCLOSE);
 */
# define BIO_NOCLOSE             0x00
# define BIO_CLOSE               0x01

/*
 * These are used in the following macros and are passed to VR_BIO_ctrl()
 */
# define BIO_CTRL_RESET          1/* opt - rewind/zero etc */
# define BIO_CTRL_EOF            2/* opt - are we at the eof */
# define BIO_CTRL_INFO           3/* opt - extra tit-bits */
# define BIO_CTRL_SET            4/* man - set the 'IO' type */
# define BIO_CTRL_GET            5/* man - get the 'IO' type */
# define BIO_CTRL_PUSH           6/* opt - internal, used to signify change */
# define BIO_CTRL_POP            7/* opt - internal, used to signify change */
# define BIO_CTRL_GET_CLOSE      8/* man - set the 'close' on free */
# define BIO_CTRL_SET_CLOSE      9/* man - set the 'close' on free */
# define BIO_CTRL_PENDING        10/* opt - is their more data buffered */
# define BIO_CTRL_FLUSH          11/* opt - 'flush' buffered output */
# define BIO_CTRL_DUP            12/* man - extra stuff for 'duped' BIO */
# define BIO_CTRL_WPENDING       13/* opt - number of bytes still to write */
# define BIO_CTRL_SET_CALLBACK   14/* opt - set callback function */
# define BIO_CTRL_GET_CALLBACK   15/* opt - set callback function */

# define BIO_CTRL_PEEK           29/* VR_BIO_f_buffer special */
# define BIO_CTRL_SET_FILENAME   30/* VR_BIO_s_file special */

/* dgram BIO stuff */
# define BIO_CTRL_DGRAM_CONNECT       31/* BIO dgram special */
# define BIO_CTRL_DGRAM_SET_CONNECTED 32/* allow for an externally connected
                                         * socket to be passed in */
# define BIO_CTRL_DGRAM_SET_RECV_TIMEOUT 33/* setsockopt, essentially */
# define BIO_CTRL_DGRAM_GET_RECV_TIMEOUT 34/* getsockopt, essentially */
# define BIO_CTRL_DGRAM_SET_SEND_TIMEOUT 35/* setsockopt, essentially */
# define BIO_CTRL_DGRAM_GET_SEND_TIMEOUT 36/* getsockopt, essentially */

# define BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP 37/* flag whether the last */
# define BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP 38/* I/O operation tiemd out */

/* #ifdef IP_MTU_DISCOVER */
# define BIO_CTRL_DGRAM_MTU_DISCOVER       39/* set DF bit on egress packets */
/* #endif */

# define BIO_CTRL_DGRAM_QUERY_MTU          40/* as kernel for current MTU */
# define BIO_CTRL_DGRAM_GET_FALLBACK_MTU   47
# define BIO_CTRL_DGRAM_GET_MTU            41/* get cached value for MTU */
# define BIO_CTRL_DGRAM_SET_MTU            42/* set cached value for MTU.
                                              * want to use this if asking
                                              * the kernel fails */

# define BIO_CTRL_DGRAM_MTU_EXCEEDED       43/* check whether the MTU was
                                              * exceed in the previous write
                                              * operation */

# define BIO_CTRL_DGRAM_GET_PEER           46
# define BIO_CTRL_DGRAM_SET_PEER           44/* Destination for the data */

# define BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT   45/* Next DTLS handshake timeout
                                              * to adjust socket timeouts */
# define BIO_CTRL_DGRAM_SET_DONT_FRAG      48

# define BIO_CTRL_DGRAM_GET_MTU_OVERHEAD   49

/* Deliberately outside of OPENSSL_NO_SCTP - used in bss_dgram.c */
#  define BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE    50
# ifndef OPENSSL_NO_SCTP
/* SCTP stuff */
#  define BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY                51
#  define BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY               52
#  define BIO_CTRL_DGRAM_SCTP_AUTH_CCS_RCVD               53
#  define BIO_CTRL_DGRAM_SCTP_GET_SNDINFO         60
#  define BIO_CTRL_DGRAM_SCTP_SET_SNDINFO         61
#  define BIO_CTRL_DGRAM_SCTP_GET_RCVINFO         62
#  define BIO_CTRL_DGRAM_SCTP_SET_RCVINFO         63
#  define BIO_CTRL_DGRAM_SCTP_GET_PRINFO                  64
#  define BIO_CTRL_DGRAM_SCTP_SET_PRINFO                  65
#  define BIO_CTRL_DGRAM_SCTP_SAVE_SHUTDOWN               70
# endif

# define BIO_CTRL_DGRAM_SET_PEEK_MODE      71

/* internal BIO see include/internal/bio.h:
 * # define BIO_CTRL_SET_KTLS_SEND                 72
 * # define BIO_CTRL_SET_KTLS_SEND_CTRL_MSG        74
 * # define BIO_CTRL_CLEAR_KTLS_CTRL_MSG      75
 */

#  define BIO_CTRL_GET_KTLS_SEND                 73
#  define BIO_get_ktls_send(b)         \
     VR_BIO_ctrl(b, BIO_CTRL_GET_KTLS_SEND, 0, NULL)

/* modifiers */
# define BIO_FP_READ             0x02
# define BIO_FP_WRITE            0x04
# define BIO_FP_APPEND           0x08
# define BIO_FP_TEXT             0x10

# define BIO_FLAGS_READ          0x01
# define BIO_FLAGS_WRITE         0x02
# define BIO_FLAGS_IO_SPECIAL    0x04
# define BIO_FLAGS_RWS (BIO_FLAGS_READ|BIO_FLAGS_WRITE|BIO_FLAGS_IO_SPECIAL)
# define BIO_FLAGS_SHOULD_RETRY  0x08
# ifndef BIO_FLAGS_UPLINK
/*
 * "UPLINK" flag denotes file descriptors provided by application. It
 * defaults to 0, as most platforms don't require UPLINK interface.
 */
#  define BIO_FLAGS_UPLINK        0
# endif

# define BIO_FLAGS_BASE64_NO_NL  0x100

/*
 * This is used with memory BIOs:
 * BIO_FLAGS_MEM_RDONLY means we shouldn't free up or change the data in any way;
 * BIO_FLAGS_NONCLEAR_RST means we shouldn't clear data on reset.
 */
# define BIO_FLAGS_MEM_RDONLY    0x200
# define BIO_FLAGS_NONCLEAR_RST  0x400

typedef union bio_addr_st BIO_ADDR;
typedef struct bio_addrinfo_st BIO_ADDRINFO;

int VR_BIO_get_new_index(void);
void VR_BIO_set_flags(BIO *b, int flags);
int VR_BIO_test_flags(const BIO *b, int flags);
void VR_BIO_clear_flags(BIO *b, int flags);

# define BIO_get_flags(b) VR_BIO_test_flags(b, ~(0x0))
# define BIO_set_retry_special(b) \
                VR_BIO_set_flags(b, (BIO_FLAGS_IO_SPECIAL|BIO_FLAGS_SHOULD_RETRY))
# define BIO_set_retry_read(b) \
                VR_BIO_set_flags(b, (BIO_FLAGS_READ|BIO_FLAGS_SHOULD_RETRY))
# define BIO_set_retry_write(b) \
                VR_BIO_set_flags(b, (BIO_FLAGS_WRITE|BIO_FLAGS_SHOULD_RETRY))

/* These are normally used internally in BIOs */
# define VR_BIO_clear_retry_flags(b) \
                VR_BIO_clear_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))
# define BIO_get_retry_flags(b) \
                VR_BIO_test_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))

/* These should be used by the application to tell why we should retry */
# define VR_BIO_should_read(a)              VR_BIO_test_flags(a, BIO_FLAGS_READ)
# define VR_BIO_should_write(a)             VR_BIO_test_flags(a, BIO_FLAGS_WRITE)
# define BIO_should_io_special(a)        VR_BIO_test_flags(a, BIO_FLAGS_IO_SPECIAL)
# define BIO_retry_type(a)               VR_BIO_test_flags(a, BIO_FLAGS_RWS)
# define VR_BIO_should_retry(a)             VR_BIO_test_flags(a, BIO_FLAGS_SHOULD_RETRY)

/*
 * The next three are used in conjunction with the BIO_should_io_special()
 * condition.  After this returns true, BIO *VR_BIO_get_retry_BIO(BIO *bio, int
 * *reason); will walk the BIO stack and return the 'reason' for the special
 * and the offending BIO. Given a BIO, VR_BIO_get_retry_reason(bio) will return
 * the code.
 */
/*
 * Returned from the SSL bio when the certificate retrieval code had an error
 */
# define BIO_RR_SSL_X509_LOOKUP          0x01
/* Returned from the connect BIO when a connect would have blocked */
# define BIO_RR_CONNECT                  0x02
/* Returned from the accept BIO when an accept would have blocked */
# define BIO_RR_ACCEPT                   0x03

/* These are passed by the BIO callback */
# define BIO_CB_FREE     0x01
# define BIO_CB_READ     0x02
# define BIO_CB_WRITE    0x03
# define BIO_CB_PUTS     0x04
# define BIO_CB_GETS     0x05
# define BIO_CB_CTRL     0x06

/*
 * The callback is called before and after the underling operation, The
 * BIO_CB_RETURN flag indicates if it is after the call
 */
# define BIO_CB_RETURN   0x80
# define BIO_CB_return(a) ((a)|BIO_CB_RETURN)
# define BIO_cb_pre(a)   (!((a)&BIO_CB_RETURN))
# define BIO_cb_post(a)  ((a)&BIO_CB_RETURN)

typedef long (*BIO_callback_fn)(BIO *b, int oper, const char *argp, int argi,
                                long argl, long ret);
typedef long (*BIO_callback_fn_ex)(BIO *b, int oper, const char *argp,
                                   size_t len, int argi,
                                   long argl, int ret, size_t *processed);
BIO_callback_fn VR_BIO_get_callback(const BIO *b);
void VR_BIO_set_callback(BIO *b, BIO_callback_fn callback);

BIO_callback_fn_ex VR_BIO_get_callback_ex(const BIO *b);
void VR_BIO_set_callback_ex(BIO *b, BIO_callback_fn_ex callback);

char *VR_BIO_get_callback_arg(const BIO *b);
void VR_BIO_set_callback_arg(BIO *b, char *arg);

typedef struct bio_method_st BIO_METHOD;

const char *VR_BIO_method_name(const BIO *b);
int VR_BIO_method_type(const BIO *b);

typedef int BIO_info_cb(BIO *, int, int);
typedef BIO_info_cb bio_info_cb;  /* backward compatibility */

DEFINE_STACK_OF(BIO)

/* Prefix and suffix callback in ASN1 BIO */
typedef int asn1_ps_func (BIO *b, unsigned char **pbuf, int *plen,
                          void *parg);

# ifndef OPENSSL_NO_SCTP
/* SCTP parameter structs */
struct bio_dgram_sctp_sndinfo {
    uint16_t snd_sid;
    uint16_t snd_flags;
    uint32_t snd_ppid;
    uint32_t snd_context;
};

struct bio_dgram_sctp_rcvinfo {
    uint16_t rcv_sid;
    uint16_t rcv_ssn;
    uint16_t rcv_flags;
    uint32_t rcv_ppid;
    uint32_t rcv_tsn;
    uint32_t rcv_cumtsn;
    uint32_t rcv_context;
};

struct bio_dgram_sctp_prinfo {
    uint16_t pr_policy;
    uint32_t pr_value;
};
# endif

/*
 * #define BIO_CONN_get_param_hostname VR_BIO_ctrl
 */

# define BIO_C_SET_CONNECT                       100
# define BIO_C_DO_STATE_MACHINE                  101
# define BIO_C_SET_NBIO                          102
/* # define BIO_C_SET_PROXY_PARAM                   103 */
# define BIO_C_SET_FD                            104
# define BIO_C_GET_FD                            105
# define BIO_C_SET_FILE_PTR                      106
# define BIO_C_GET_FILE_PTR                      107
# define BIO_C_SET_FILENAME                      108
# define BIO_C_SET_SSL                           109
# define BIO_C_GET_SSL                           110
# define BIO_C_SET_MD                            111
# define BIO_C_GET_MD                            112
# define BIO_C_GET_CIPHER_STATUS                 113
# define BIO_C_SET_BUF_MEM                       114
# define BIO_C_GET_BUF_MEM_PTR                   115
# define BIO_C_GET_BUFF_NUM_LINES                116
# define BIO_C_SET_BUFF_SIZE                     117
# define BIO_C_SET_ACCEPT                        118
# define BIO_C_SSL_MODE                          119
# define BIO_C_GET_MD_CTX                        120
/* # define BIO_C_GET_PROXY_PARAM                   121 */
# define BIO_C_SET_BUFF_READ_DATA                122/* data to read first */
# define BIO_C_GET_CONNECT                       123
# define BIO_C_GET_ACCEPT                        124
# define BIO_C_SET_SSL_RENEGOTIATE_BYTES         125
# define BIO_C_GET_SSL_NUM_RENEGOTIATES          126
# define BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT       127
# define BIO_C_FILE_SEEK                         128
# define BIO_C_GET_CIPHER_CTX                    129
# define BIO_C_SET_BUF_MEM_EOF_RETURN            130/* return end of input
                                                     * value */
# define BIO_C_SET_BIND_MODE                     131
# define BIO_C_GET_BIND_MODE                     132
# define BIO_C_FILE_TELL                         133
# define BIO_C_GET_SOCKS                         134
# define BIO_C_SET_SOCKS                         135

# define BIO_C_SET_WRITE_BUF_SIZE                136/* for VR_BIO_s_bio */
# define BIO_C_GET_WRITE_BUF_SIZE                137
# define BIO_C_MAKE_BIO_PAIR                     138
# define BIO_C_DESTROY_BIO_PAIR                  139
# define BIO_C_GET_WRITE_GUARANTEE               140
# define BIO_C_GET_READ_REQUEST                  141
# define BIO_C_SHUTDOWN_WR                       142
# define BIO_C_NREAD0                            143
# define BIO_C_NREAD                             144
# define BIO_C_NWRITE0                           145
# define BIO_C_NWRITE                            146
# define BIO_C_RESET_READ_REQUEST                147
# define BIO_C_SET_MD_CTX                        148

# define BIO_C_SET_PREFIX                        149
# define BIO_C_GET_PREFIX                        150
# define BIO_C_SET_SUFFIX                        151
# define BIO_C_GET_SUFFIX                        152

# define BIO_C_SET_EX_ARG                        153
# define BIO_C_GET_EX_ARG                        154

# define BIO_C_SET_CONNECT_MODE                  155

# define BIO_set_app_data(s,arg)         VR_BIO_set_ex_data(s,0,arg)
# define BIO_get_app_data(s)             VR_BIO_get_ex_data(s,0)

# define BIO_set_nbio(b,n)             VR_BIO_ctrl(b,BIO_C_SET_NBIO,(n),NULL)

# ifndef OPENSSL_NO_SOCK
/* IP families we support, for VR_BIO_s_connect() and VR_BIO_s_accept() */
/* Note: the underlying operating system may not support some of them */
#  define BIO_FAMILY_IPV4                         4
#  define BIO_FAMILY_IPV6                         6
#  define BIO_FAMILY_IPANY                        256

/* VR_BIO_s_connect() */
#  define BIO_set_conn_hostname(b,name) VR_BIO_ctrl(b,BIO_C_SET_CONNECT,0, \
                                                 (char *)(name))
#  define BIO_set_conn_port(b,port)     VR_BIO_ctrl(b,BIO_C_SET_CONNECT,1, \
                                                 (char *)(port))
#  define BIO_set_conn_address(b,addr)  VR_BIO_ctrl(b,BIO_C_SET_CONNECT,2, \
                                                 (char *)(addr))
#  define BIO_set_conn_ip_family(b,f)   VR_BIO_int_ctrl(b,BIO_C_SET_CONNECT,3,f)
#  define BIO_get_conn_hostname(b)      ((const char *)VR_BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,0))
#  define BIO_get_conn_port(b)          ((const char *)VR_BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,1))
#  define BIO_get_conn_address(b)       ((const BIO_ADDR *)VR_BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,2))
#  define BIO_get_conn_ip_family(b)     VR_BIO_ctrl(b,BIO_C_GET_CONNECT,3,NULL)
#  define BIO_set_conn_mode(b,n)        VR_BIO_ctrl(b,BIO_C_SET_CONNECT_MODE,(n),NULL)

/* VR_BIO_s_accept() */
#  define BIO_set_accept_name(b,name)   VR_BIO_ctrl(b,BIO_C_SET_ACCEPT,0, \
                                                 (char *)(name))
#  define BIO_set_accept_port(b,port)   VR_BIO_ctrl(b,BIO_C_SET_ACCEPT,1, \
                                                 (char *)(port))
#  define BIO_get_accept_name(b)        ((const char *)VR_BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,0))
#  define BIO_get_accept_port(b)        ((const char *)VR_BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,1))
#  define BIO_get_peer_name(b)          ((const char *)VR_BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,2))
#  define BIO_get_peer_port(b)          ((const char *)VR_BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,3))
/* #define BIO_set_nbio(b,n)    VR_BIO_ctrl(b,BIO_C_SET_NBIO,(n),NULL) */
#  define BIO_set_nbio_accept(b,n)      VR_BIO_ctrl(b,BIO_C_SET_ACCEPT,2,(n)?(void *)"a":NULL)
#  define BIO_set_accept_bios(b,bio)    VR_BIO_ctrl(b,BIO_C_SET_ACCEPT,3, \
                                                 (char *)(bio))
#  define BIO_set_accept_ip_family(b,f) VR_BIO_int_ctrl(b,BIO_C_SET_ACCEPT,4,f)
#  define BIO_get_accept_ip_family(b)   VR_BIO_ctrl(b,BIO_C_GET_ACCEPT,4,NULL)

/* Aliases kept for backward compatibility */
#  define BIO_BIND_NORMAL                 0
#  define BIO_BIND_REUSEADDR              BIO_SOCK_REUSEADDR
#  define BIO_BIND_REUSEADDR_IF_UNUSED    BIO_SOCK_REUSEADDR
#  define BIO_set_bind_mode(b,mode) VR_BIO_ctrl(b,BIO_C_SET_BIND_MODE,mode,NULL)
#  define BIO_get_bind_mode(b)    VR_BIO_ctrl(b,BIO_C_GET_BIND_MODE,0,NULL)

/* VR_BIO_s_accept() and VR_BIO_s_connect() */
#  define BIO_do_connect(b)       VR_BIO_do_handshake(b)
#  define BIO_do_accept(b)        VR_BIO_do_handshake(b)
# endif /* OPENSSL_NO_SOCK */

# define VR_BIO_do_handshake(b)     VR_BIO_ctrl(b,BIO_C_DO_STATE_MACHINE,0,NULL)

/* VR_BIO_s_datagram(), VR_BIO_s_fd(), VR_BIO_s_socket(), VR_BIO_s_accept() and VR_BIO_s_connect() */
# define VR_BIO_set_fd(b,fd,c)      VR_BIO_int_ctrl(b,BIO_C_SET_FD,c,fd)
# define VR_BIO_get_fd(b,c)         VR_BIO_ctrl(b,BIO_C_GET_FD,0,(char *)(c))

/* VR_BIO_s_file() */
# define BIO_set_fp(b,fp,c)      VR_BIO_ctrl(b,BIO_C_SET_FILE_PTR,c,(char *)(fp))
# define BIO_get_fp(b,fpp)       VR_BIO_ctrl(b,BIO_C_GET_FILE_PTR,0,(char *)(fpp))

/* VR_BIO_s_fd() and VR_BIO_s_file() */
# define BIO_seek(b,ofs) (int)VR_BIO_ctrl(b,BIO_C_FILE_SEEK,ofs,NULL)
# define BIO_tell(b)     (int)VR_BIO_ctrl(b,BIO_C_FILE_TELL,0,NULL)

/*
 * name is cast to lose const, but might be better to route through a
 * function so we can do it safely
 */
# ifdef CONST_STRICT
/*
 * If you are wondering why this isn't defined, its because CONST_STRICT is
 * purely a compile-time kludge to allow const to be checked.
 */
int VR_BIO_read_filename(BIO *b, const char *name);
# else
#  define VR_BIO_read_filename(b,name) (int)VR_BIO_ctrl(b,BIO_C_SET_FILENAME, \
                BIO_CLOSE|BIO_FP_READ,(char *)(name))
# endif
# define VR_BIO_write_filename(b,name) (int)VR_BIO_ctrl(b,BIO_C_SET_FILENAME, \
                BIO_CLOSE|BIO_FP_WRITE,name)
# define BIO_append_filename(b,name) (int)VR_BIO_ctrl(b,BIO_C_SET_FILENAME, \
                BIO_CLOSE|BIO_FP_APPEND,name)
# define BIO_rw_filename(b,name) (int)VR_BIO_ctrl(b,BIO_C_SET_FILENAME, \
                BIO_CLOSE|BIO_FP_READ|BIO_FP_WRITE,name)

/*
 * WARNING WARNING, this ups the reference count on the read bio of the SSL
 * structure.  This is because the ssl read BIO is now pointed to by the
 * next_bio field in the bio.  So when you free the BIO, make sure you are
 * doing a VR_BIO_free_all() to catch the underlying BIO.
 */
# define VR_BIO_set_ssl(b,ssl,c)    VR_BIO_ctrl(b,BIO_C_SET_SSL,c,(char *)(ssl))
# define VR_BIO_get_ssl(b,sslp)     VR_BIO_ctrl(b,BIO_C_GET_SSL,0,(char *)(sslp))
# define VR_BIO_set_ssl_mode(b,client)      VR_BIO_ctrl(b,BIO_C_SSL_MODE,client,NULL)
# define VR_BIO_set_ssl_renegotiate_bytes(b,num) \
        VR_BIO_ctrl(b,BIO_C_SET_SSL_RENEGOTIATE_BYTES,num,NULL)
# define BIO_get_num_renegotiates(b) \
        VR_BIO_ctrl(b,BIO_C_GET_SSL_NUM_RENEGOTIATES,0,NULL)
# define VR_BIO_set_ssl_renegotiate_timeout(b,seconds) \
        VR_BIO_ctrl(b,BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT,seconds,NULL)

/* defined in evp.h */
/* #define BIO_set_md(b,md)     VR_BIO_ctrl(b,BIO_C_SET_MD,1,(char *)(md)) */

# define BIO_get_mem_data(b,pp)  VR_BIO_ctrl(b,BIO_CTRL_INFO,0,(char *)(pp))
# define BIO_set_mem_buf(b,bm,c) VR_BIO_ctrl(b,BIO_C_SET_BUF_MEM,c,(char *)(bm))
# define BIO_get_mem_ptr(b,pp)   VR_BIO_ctrl(b,BIO_C_GET_BUF_MEM_PTR,0, \
                                          (char *)(pp))
# define BIO_set_mem_eof_return(b,v) \
                                VR_BIO_ctrl(b,BIO_C_SET_BUF_MEM_EOF_RETURN,v,NULL)

/* For the VR_BIO_f_buffer() type */
# define BIO_get_buffer_num_lines(b)     VR_BIO_ctrl(b,BIO_C_GET_BUFF_NUM_LINES,0,NULL)
# define BIO_set_buffer_size(b,size)     VR_BIO_ctrl(b,BIO_C_SET_BUFF_SIZE,size,NULL)
# define BIO_set_read_buffer_size(b,size) VR_BIO_int_ctrl(b,BIO_C_SET_BUFF_SIZE,size,0)
# define BIO_set_write_buffer_size(b,size) VR_BIO_int_ctrl(b,BIO_C_SET_BUFF_SIZE,size,1)
# define BIO_set_buffer_read_data(b,buf,num) VR_BIO_ctrl(b,BIO_C_SET_BUFF_READ_DATA,num,buf)

/* Don't use the next one unless you know what you are doing :-) */
# define BIO_dup_state(b,ret)    VR_BIO_ctrl(b,BIO_CTRL_DUP,0,(char *)(ret))

# define BIO_reset(b)            (int)VR_BIO_ctrl(b,BIO_CTRL_RESET,0,NULL)
# define BIO_eof(b)              (int)VR_BIO_ctrl(b,BIO_CTRL_EOF,0,NULL)
# define BIO_set_close(b,c)      (int)VR_BIO_ctrl(b,BIO_CTRL_SET_CLOSE,(c),NULL)
# define BIO_get_close(b)        (int)VR_BIO_ctrl(b,BIO_CTRL_GET_CLOSE,0,NULL)
# define VR_BIO_pending(b)          (int)VR_BIO_ctrl(b,BIO_CTRL_PENDING,0,NULL)
# define BIO_wpending(b)         (int)VR_BIO_ctrl(b,BIO_CTRL_WPENDING,0,NULL)
/* ...pending macros have inappropriate return type */
size_t VR_BIO_ctrl_pending(BIO *b);
size_t VR_BIO_ctrl_wpending(BIO *b);
# define VR_BIO_flush(b)            (int)VR_BIO_ctrl(b,BIO_CTRL_FLUSH,0,NULL)
# define BIO_get_info_callback(b,cbp) (int)VR_BIO_ctrl(b,BIO_CTRL_GET_CALLBACK,0, \
                                                   cbp)
# define BIO_set_info_callback(b,cb) (int)VR_BIO_callback_ctrl(b,BIO_CTRL_SET_CALLBACK,cb)

/* For the VR_BIO_f_buffer() type */
# define BIO_buffer_get_num_lines(b) VR_BIO_ctrl(b,BIO_CTRL_GET,0,NULL)
# define BIO_buffer_peek(b,s,l) VR_BIO_ctrl(b,BIO_CTRL_PEEK,(l),(s))

/* For VR_BIO_s_bio() */
# define VR_BIO_set_write_buf_size(b,size) (int)VR_BIO_ctrl(b,BIO_C_SET_WRITE_BUF_SIZE,size,NULL)
# define BIO_get_write_buf_size(b,size) (size_t)VR_BIO_ctrl(b,BIO_C_GET_WRITE_BUF_SIZE,size,NULL)
# define VR_BIO_make_bio_pair(b1,b2)   (int)VR_BIO_ctrl(b1,BIO_C_MAKE_BIO_PAIR,0,b2)
# define BIO_destroy_bio_pair(b)    (int)VR_BIO_ctrl(b,BIO_C_DESTROY_BIO_PAIR,0,NULL)
# define BIO_shutdown_wr(b) (int)VR_BIO_ctrl(b, BIO_C_SHUTDOWN_WR, 0, NULL)
/* macros with inappropriate type -- but ...pending macros use int too: */
# define BIO_get_write_guarantee(b) (int)VR_BIO_ctrl(b,BIO_C_GET_WRITE_GUARANTEE,0,NULL)
# define BIO_get_read_request(b)    (int)VR_BIO_ctrl(b,BIO_C_GET_READ_REQUEST,0,NULL)
size_t VR_BIO_ctrl_get_write_guarantee(BIO *b);
size_t VR_BIO_ctrl_get_read_request(BIO *b);
int VR_BIO_ctrl_reset_read_request(BIO *b);

/* ctrl macros for dgram */
# define VR_BIO_ctrl_dgram_connect(b,peer)  \
                     (int)VR_BIO_ctrl(b,BIO_CTRL_DGRAM_CONNECT,0, (char *)(peer))
# define VR_BIO_ctrl_set_connected(b,peer) \
         (int)VR_BIO_ctrl(b, BIO_CTRL_DGRAM_SET_CONNECTED, 0, (char *)(peer))
# define BIO_dgram_recv_timedout(b) \
         (int)VR_BIO_ctrl(b, BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL)
# define BIO_dgram_send_timedout(b) \
         (int)VR_BIO_ctrl(b, BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP, 0, NULL)
# define BIO_dgram_get_peer(b,peer) \
         (int)VR_BIO_ctrl(b, BIO_CTRL_DGRAM_GET_PEER, 0, (char *)(peer))
# define BIO_dgram_set_peer(b,peer) \
         (int)VR_BIO_ctrl(b, BIO_CTRL_DGRAM_SET_PEER, 0, (char *)(peer))
# define BIO_dgram_get_mtu_overhead(b) \
         (unsigned int)VR_BIO_ctrl((b), BIO_CTRL_DGRAM_GET_MTU_OVERHEAD, 0, NULL)

#define BIO_get_ex_new_index(l, p, newf, dupf, freef) \
    VR_CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_BIO, l, p, newf, dupf, freef)
int VR_BIO_set_ex_data(BIO *bio, int idx, void *data);
void *VR_BIO_get_ex_data(BIO *bio, int idx);
uint64_t VR_BIO_number_read(BIO *bio);
uint64_t VR_BIO_number_written(BIO *bio);

/* For VR_BIO_f_asn1() */
int VR_BIO_asn1_set_prefix(BIO *b, asn1_ps_func *prefix,
                        asn1_ps_func *prefix_free);
int VR_BIO_asn1_get_prefix(BIO *b, asn1_ps_func **pprefix,
                        asn1_ps_func **pprefix_free);
int VR_BIO_asn1_set_suffix(BIO *b, asn1_ps_func *suffix,
                        asn1_ps_func *suffix_free);
int VR_BIO_asn1_get_suffix(BIO *b, asn1_ps_func **psuffix,
                        asn1_ps_func **psuffix_free);

const BIO_METHOD *VR_BIO_s_file(void);
BIO *VR_BIO_new_file(const char *filename, const char *mode);
# ifndef OPENSSL_NO_STDIO
BIO *VR_BIO_new_fp(FILE *stream, int close_flag);
# endif
BIO *VR_BIO_new(const BIO_METHOD *type);
int VR_BIO_free(BIO *a);
void VR_BIO_set_data(BIO *a, void *ptr);
void *VR_BIO_get_data(BIO *a);
void VR_BIO_set_init(BIO *a, int init);
int VR_BIO_get_init(BIO *a);
void VR_BIO_set_shutdown(BIO *a, int shut);
int VR_BIO_get_shutdown(BIO *a);
void VR_BIO_vfree(BIO *a);
int VR_BIO_up_ref(BIO *a);
int VR_BIO_read(BIO *b, void *data, int dlen);
int VR_BIO_read_ex(BIO *b, void *data, size_t dlen, size_t *readbytes);
int VR_BIO_gets(BIO *bp, char *buf, int size);
int VR_BIO_write(BIO *b, const void *data, int dlen);
int VR_BIO_write_ex(BIO *b, const void *data, size_t dlen, size_t *written);
int VR_BIO_puts(BIO *bp, const char *buf);
int VR_BIO_indent(BIO *b, int indent, int max);
long VR_BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);
long VR_BIO_callback_ctrl(BIO *b, int cmd, BIO_info_cb *fp);
void *VR_BIO_ptr_ctrl(BIO *bp, int cmd, long larg);
long VR_BIO_int_ctrl(BIO *bp, int cmd, long larg, int iarg);
BIO *VR_BIO_push(BIO *b, BIO *append);
BIO *VR_BIO_pop(BIO *b);
void VR_BIO_free_all(BIO *a);
BIO *VR_BIO_find_type(BIO *b, int bio_type);
BIO *VR_BIO_next(BIO *b);
void VR_BIO_set_next(BIO *b, BIO *next);
BIO *VR_BIO_get_retry_BIO(BIO *bio, int *reason);
int VR_BIO_get_retry_reason(BIO *bio);
void VR_BIO_set_retry_reason(BIO *bio, int reason);
BIO *VR_BIO_dup_chain(BIO *in);

int VR_BIO_nread0(BIO *bio, char **buf);
int VR_BIO_nread(BIO *bio, char **buf, int num);
int VR_BIO_nwrite0(BIO *bio, char **buf);
int VR_BIO_nwrite(BIO *bio, char **buf, int num);

long VR_BIO_debug_callback(BIO *bio, int cmd, const char *argp, int argi,
                        long argl, long ret);

const BIO_METHOD *VR_BIO_s_mem(void);
const BIO_METHOD *VR_BIO_s_secmem(void);
BIO *VR_BIO_new_mem_buf(const void *buf, int len);
# ifndef OPENSSL_NO_SOCK
const BIO_METHOD *VR_BIO_s_socket(void);
const BIO_METHOD *VR_BIO_s_connect(void);
const BIO_METHOD *VR_BIO_s_accept(void);
# endif
const BIO_METHOD *VR_BIO_s_fd(void);
const BIO_METHOD *VR_BIO_s_log(void);
const BIO_METHOD *VR_BIO_s_bio(void);
const BIO_METHOD *VR_BIO_s_null(void);
const BIO_METHOD *VR_BIO_f_null(void);
const BIO_METHOD *VR_BIO_f_buffer(void);
const BIO_METHOD *VR_BIO_f_linebuffer(void);
const BIO_METHOD *VR_BIO_f_nbio_test(void);
# ifndef OPENSSL_NO_DGRAM
const BIO_METHOD *VR_BIO_s_datagram(void);
int VR_BIO_dgram_non_fatal_error(int error);
BIO *VR_BIO_new_dgram(int fd, int close_flag);
#  ifndef OPENSSL_NO_SCTP
const BIO_METHOD *VR_BIO_s_datagram_sctp(void);
BIO *VR_BIO_new_dgram_sctp(int fd, int close_flag);
int BIO_dgram_is_sctp(BIO *bio);
int BIO_dgram_sctp_notification_cb(BIO *b,
                                   void (*handle_notifications) (BIO *bio,
                                                                 void *context,
                                                                 void *buf),
                                   void *context);
int BIO_dgram_sctp_wait_for_dry(BIO *b);
int BIO_dgram_sctp_msg_waiting(BIO *b);
#  endif
# endif

# ifndef OPENSSL_NO_SOCK
int VR_BIO_sock_should_retry(int i);
int VR_BIO_sock_non_fatal_error(int error);
# endif

int VR_BIO_fd_should_retry(int i);
int VR_BIO_fd_non_fatal_error(int error);
int VR_BIO_dump_cb(int (*cb) (const void *data, size_t len, void *u),
                void *u, const void *s, int len);
int VR_BIO_dump_indent_cb(int (*cb) (const void *data, size_t len, void *u),
                       void *u, const void *s, int len, int indent);
int VR_BIO_dump(BIO *b, const void *bytes, int len);
int VR_BIO_dump_indent(BIO *b, const void *bytes, int len, int indent);
# ifndef OPENSSL_NO_STDIO
int VR_BIO_dump_fp(FILE *fp, const void *s, int len);
int VR_BIO_dump_indent_fp(FILE *fp, const void *s, int len, int indent);
# endif
int VR_BIO_hex_string(BIO *out, int indent, int width, const void *data,
                   int datalen);

# ifndef OPENSSL_NO_SOCK
BIO_ADDR *VR_BIO_ADDR_new(void);
int VR_BIO_ADDR_rawmake(BIO_ADDR *ap, int family,
                     const void *where, size_t wherelen, unsigned short port);
void VR_BIO_ADDR_free(BIO_ADDR *);
void VR_BIO_ADDR_clear(BIO_ADDR *ap);
int VR_BIO_ADDR_family(const BIO_ADDR *ap);
int VR_BIO_ADDR_rawaddress(const BIO_ADDR *ap, void *p, size_t *l);
unsigned short VR_BIO_ADDR_rawport(const BIO_ADDR *ap);
char *VR_BIO_ADDR_hostname_string(const BIO_ADDR *ap, int numeric);
char *VR_BIO_ADDR_service_string(const BIO_ADDR *ap, int numeric);
char *VR_BIO_ADDR_path_string(const BIO_ADDR *ap);

const BIO_ADDRINFO *VR_BIO_ADDRINFO_next(const BIO_ADDRINFO *bai);
int VR_BIO_ADDRINFO_family(const BIO_ADDRINFO *bai);
int VR_BIO_ADDRINFO_socktype(const BIO_ADDRINFO *bai);
int VR_BIO_ADDRINFO_protocol(const BIO_ADDRINFO *bai);
const BIO_ADDR *VR_BIO_ADDRINFO_address(const BIO_ADDRINFO *bai);
void VR_BIO_ADDRINFO_free(BIO_ADDRINFO *bai);

enum BIO_hostserv_priorities {
    BIO_PARSE_PRIO_HOST, BIO_PARSE_PRIO_SERV
};
int VR_BIO_parse_hostserv(const char *hostserv, char **host, char **service,
                       enum BIO_hostserv_priorities hostserv_prio);
enum VR_BIO_lookup_type {
    BIO_LOOKUP_CLIENT, BIO_LOOKUP_SERVER
};
int VR_BIO_lookup(const char *host, const char *service,
               enum VR_BIO_lookup_type lookup_type,
               int family, int socktype, BIO_ADDRINFO **res);
int VR_BIO_lookup_ex(const char *host, const char *service,
                  int lookup_type, int family, int socktype, int protocol,
                  BIO_ADDRINFO **res);
int VR_BIO_sock_error(int sock);
int VR_BIO_socket_ioctl(int fd, long type, void *arg);
int VR_BIO_socket_nbio(int fd, int mode);
int VR_BIO_sock_init(void);
# if !OPENSSL_API_1_1_0
#  define BIO_sock_cleanup() while(0) continue
# endif
int VR_BIO_set_tcp_ndelay(int sock, int turn_on);

DEPRECATEDIN_1_1_0(struct hostent *VR_BIO_gethostbyname(const char *name))
DEPRECATEDIN_1_1_0(int VR_BIO_get_port(const char *str, unsigned short *port_ptr))
DEPRECATEDIN_1_1_0(int VR_BIO_get_host_ip(const char *str, unsigned char *ip))
DEPRECATEDIN_1_1_0(int VR_BIO_get_accept_socket(char *host_port, int mode))
DEPRECATEDIN_1_1_0(int VR_BIO_accept(int sock, char **ip_port))

union VR_BIO_sock_info_u {
    BIO_ADDR *addr;
};
enum VR_BIO_sock_info_type {
    BIO_SOCK_INFO_ADDRESS
};
int VR_BIO_sock_info(int sock,
                  enum VR_BIO_sock_info_type type, union VR_BIO_sock_info_u *info);

#  define BIO_SOCK_REUSEADDR    0x01
#  define BIO_SOCK_V6_ONLY      0x02
#  define BIO_SOCK_KEEPALIVE    0x04
#  define BIO_SOCK_NONBLOCK     0x08
#  define BIO_SOCK_NODELAY      0x10

int VR_BIO_socket(int domain, int socktype, int protocol, int options);
int VR_BIO_connect(int sock, const BIO_ADDR *addr, int options);
int VR_BIO_bind(int sock, const BIO_ADDR *addr, int options);
int VR_BIO_listen(int sock, const BIO_ADDR *addr, int options);
int VR_BIO_accept_ex(int accept_sock, BIO_ADDR *addr, int options);
int VR_BIO_closesocket(int sock);

BIO *VR_BIO_new_socket(int sock, int close_flag);
BIO *VR_BIO_new_connect(const char *host_port);
BIO *VR_BIO_new_accept(const char *host_port);
# endif /* OPENSSL_NO_SOCK*/

BIO *VR_BIO_new_fd(int fd, int close_flag);

int VR_BIO_new_bio_pair(BIO **bio1, size_t writebuf1,
                     BIO **bio2, size_t writebuf2);
/*
 * If successful, returns 1 and in *bio1, *bio2 two BIO pair endpoints.
 * Otherwise returns 0 and sets *bio1 and *bio2 to NULL. Size 0 uses default
 * value.
 */

void VR_BIO_copy_next_retry(BIO *b);

/*
 * long BIO_ghbn_ctrl(int cmd,int iarg,char *parg);
 */

# define ossl_bio__attr__(x)
# if defined(__GNUC__) && defined(__STDC_VERSION__) \
    && !defined(__APPLE__)
    /*
     * Because we support the 'z' modifier, which made its appearance in C99,
     * we can't use __attribute__ with pre C99 dialects.
     */
#  if __STDC_VERSION__ >= 199901L
#   undef ossl_bio__attr__
#   define ossl_bio__attr__ __attribute__
#   if __GNUC__*10 + __GNUC_MINOR__ >= 44
#    define ossl_bio__printf__ __gnu_printf__
#   else
#    define ossl_bio__printf__ __printf__
#   endif
#  endif
# endif
int VR_BIO_printf(BIO *bio, const char *format, ...)
ossl_bio__attr__((__format__(ossl_bio__printf__, 2, 3)));
int VR_BIO_vprintf(BIO *bio, const char *format, va_list args)
ossl_bio__attr__((__format__(ossl_bio__printf__, 2, 0)));
int VR_BIO_snprintf(char *buf, size_t n, const char *format, ...)
ossl_bio__attr__((__format__(ossl_bio__printf__, 3, 4)));
int VR_BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
ossl_bio__attr__((__format__(ossl_bio__printf__, 3, 0)));
# undef ossl_bio__attr__
# undef ossl_bio__printf__


BIO_METHOD *VR_BIO_meth_new(int type, const char *name);
void VR_BIO_meth_free(BIO_METHOD *biom);
int (*VR_BIO_meth_get_write(const BIO_METHOD *biom)) (BIO *, const char *, int);
int (*VR_BIO_meth_get_write_ex(const BIO_METHOD *biom)) (BIO *, const char *, size_t,
                                                size_t *);
int VR_BIO_meth_set_write(BIO_METHOD *biom,
                       int (*write) (BIO *, const char *, int));
int VR_BIO_meth_set_write_ex(BIO_METHOD *biom,
                       int (*bwrite) (BIO *, const char *, size_t, size_t *));
int (*VR_BIO_meth_get_read(const BIO_METHOD *biom)) (BIO *, char *, int);
int (*VR_BIO_meth_get_read_ex(const BIO_METHOD *biom)) (BIO *, char *, size_t, size_t *);
int VR_BIO_meth_set_read(BIO_METHOD *biom,
                      int (*read) (BIO *, char *, int));
int VR_BIO_meth_set_read_ex(BIO_METHOD *biom,
                         int (*bread) (BIO *, char *, size_t, size_t *));
int (*VR_BIO_meth_get_puts(const BIO_METHOD *biom)) (BIO *, const char *);
int VR_BIO_meth_set_puts(BIO_METHOD *biom,
                      int (*puts) (BIO *, const char *));
int (*VR_BIO_meth_get_gets(const BIO_METHOD *biom)) (BIO *, char *, int);
int VR_BIO_meth_set_gets(BIO_METHOD *biom,
                      int (*gets) (BIO *, char *, int));
long (*VR_BIO_meth_get_ctrl(const BIO_METHOD *biom)) (BIO *, int, long, void *);
int VR_BIO_meth_set_ctrl(BIO_METHOD *biom,
                      long (*ctrl) (BIO *, int, long, void *));
int (*VR_BIO_meth_get_create(const BIO_METHOD *bion)) (BIO *);
int VR_BIO_meth_set_create(BIO_METHOD *biom, int (*create) (BIO *));
int (*VR_BIO_meth_get_destroy(const BIO_METHOD *biom)) (BIO *);
int VR_BIO_meth_set_destroy(BIO_METHOD *biom, int (*destroy) (BIO *));
long (*VR_BIO_meth_get_callback_ctrl(const BIO_METHOD *biom))
                                 (BIO *, int, BIO_info_cb *);
int VR_BIO_meth_set_callback_ctrl(BIO_METHOD *biom,
                               long (*callback_ctrl) (BIO *, int,
                                                      BIO_info_cb *));

# ifdef  __cplusplus
}
# endif
#endif
