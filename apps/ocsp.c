/*
 * Copyright 2001-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#ifdef OPENSSL_NO_OCSP
NON_EMPTY_TRANSLATION_UNIT
#else
# ifdef OPENSSL_SYS_VMS
#  define _XOPEN_SOURCE_EXTENDED/* So fd_set and friends get properly defined
                                 * on OpenVMS */
# endif

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <time.h>
# include <ctype.h>

/* Needs to be included before the openssl headers */
# include "apps.h"
# include "progs.h"
# include "internal/sockets.h"
# include <openssl/e_os2.h>
# include <openssl/crypto.h>
# include <openssl/err.h>
# include <openssl/ssl.h>
# include <openssl/evp.h>
# include <openssl/bn.h>
# include <openssl/x509v3.h>
# include <openssl/rand.h>

# if defined(OPENSSL_SYS_UNIX) && !defined(OPENSSL_NO_SOCK) \
     && !defined(OPENSSL_NO_POSIX_IO)
#  define OCSP_DAEMON
#  include <sys/types.h>
#  include <sys/wait.h>
#  include <syslog.h>
#  include <signal.h>
#  define MAXERRLEN 1000 /* limit error text sent to syslog to 1000 bytes */
# else
#  undef LOG_INFO
#  undef LOG_WARNING
#  undef LOG_ERR
#  define LOG_INFO      0
#  define LOG_WARNING   1
#  define LOG_ERR       2
# endif

# if defined(OPENSSL_SYS_VXWORKS)
/* not supported */
int setpgid(pid_t pid, pid_t pgid)
{
    errno = ENOSYS;
    return 0;
}
/* not supported */
pid_t fork(void)
{
    errno = ENOSYS;
    return (pid_t) -1;
}
# endif
/* Maximum leeway in validity period: default 5 minutes */
# define MAX_VALIDITY_PERIOD    (5 * 60)

static int add_ocsp_cert(OCSP_REQUEST **req, X509 *cert,
                         const EVP_MD *cert_id_md, X509 *issuer,
                         STACK_OF(OCSP_CERTID) *ids);
static int add_ocsp_serial(OCSP_REQUEST **req, char *serial,
                           const EVP_MD *cert_id_md, X509 *issuer,
                           STACK_OF(OCSP_CERTID) *ids);
static void print_ocsp_summary(BIO *out, OCSP_BASICRESP *bs, OCSP_REQUEST *req,
                              STACK_OF(OPENSSL_STRING) *names,
                              STACK_OF(OCSP_CERTID) *ids, long nsec,
                              long maxage);
static void make_ocsp_response(BIO *err, OCSP_RESPONSE **resp, OCSP_REQUEST *req,
                              CA_DB *db, STACK_OF(X509) *ca, X509 *rcert,
                              EVP_PKEY *rkey, const EVP_MD *md,
                              STACK_OF(OPENSSL_STRING) *sigopts,
                              STACK_OF(X509) *rother, unsigned long flags,
                              int nmin, int ndays, int badsig);

static char **lookup_serial(CA_DB *db, ASN1_INTEGER *ser);
static BIO *init_responder(const char *port);
static int do_responder(OCSP_REQUEST **preq, BIO **pcbio, BIO *acbio, int timeout);
static int send_ocsp_response(BIO *cbio, OCSP_RESPONSE *resp);
static void log_message(int level, const char *fmt, ...);
static char *prog;
static int multi = 0;

# ifdef OCSP_DAEMON
static int acfd = (int) INVALID_SOCKET;
static int index_changed(CA_DB *);
static void spawn_loop(void);
static int print_syslog(const char *str, size_t len, void *levPtr);
static void sock_timeout(int signum);
# endif

# ifndef OPENSSL_NO_SOCK
static OCSP_RESPONSE *query_responder(BIO *cbio, const char *host,
                                      const char *path,
                                      const STACK_OF(CONF_VALUE) *headers,
                                      OCSP_REQUEST *req, int req_timeout);
# endif

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_OUTFILE, OPT_TIMEOUT, OPT_URL, OPT_HOST, OPT_PORT,
    OPT_IGNORE_ERR, OPT_NOVERIFY, OPT_NONCE, OPT_NO_NONCE,
    OPT_RESP_NO_CERTS, OPT_RESP_KEY_ID, OPT_NO_CERTS,
    OPT_NO_SIGNATURE_VERIFY, OPT_NO_CERT_VERIFY, OPT_NO_CHAIN,
    OPT_NO_CERT_CHECKS, OPT_NO_EXPLICIT, OPT_TRUST_OTHER,
    OPT_NO_INTERN, OPT_BADSIG, OPT_TEXT, OPT_REQ_TEXT, OPT_RESP_TEXT,
    OPT_REQIN, OPT_RESPIN, OPT_SIGNER, OPT_VAFILE, OPT_SIGN_OTHER,
    OPT_VERIFY_OTHER, OPT_CAFILE, OPT_CAPATH, OPT_NOCAFILE, OPT_NOCAPATH,
    OPT_VALIDITY_PERIOD, OPT_STATUS_AGE, OPT_SIGNKEY, OPT_REQOUT,
    OPT_RESPOUT, OPT_PATH, OPT_ISSUER, OPT_CERT, OPT_SERIAL,
    OPT_INDEX, OPT_CA, OPT_NMIN, OPT_REQUEST, OPT_NDAYS, OPT_RSIGNER,
    OPT_RKEY, OPT_ROTHER, OPT_RMD, OPT_RSIGOPT, OPT_HEADER,
    OPT_V_ENUM,
    OPT_MD,
    OPT_MULTI
} OPTION_CHOICE;

const OPTIONS ocsp_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"out", OPT_OUTFILE, '>', "Output filename"},
    {"timeout", OPT_TIMEOUT, 'p',
     "Connection timeout (in seconds) to the OCSP responder"},
    {"url", OPT_URL, 's', "Responder URL"},
    {"host", OPT_HOST, 's', "TCP/IP hostname:port to connect to"},
    {"port", OPT_PORT, 'p', "Port to run responder on"},
    {"ignore_err", OPT_IGNORE_ERR, '-',
     "Ignore error on OCSP request or response and continue running"},
    {"noverify", OPT_NOVERIFY, '-', "Don't verify response at all"},
    {"nonce", OPT_NONCE, '-', "Add OCSP nonce to request"},
    {"no_nonce", OPT_NO_NONCE, '-', "Don't add OCSP nonce to request"},
    {"resp_no_certs", OPT_RESP_NO_CERTS, '-',
     "Don't include any certificates in response"},
    {"resp_key_id", OPT_RESP_KEY_ID, '-',
     "Identify response by signing certificate key ID"},
# ifdef OCSP_DAEMON
    {"multi", OPT_MULTI, 'p', "run multiple responder processes"},
# endif
    {"no_certs", OPT_NO_CERTS, '-',
     "Don't include any certificates in signed request"},
    {"no_signature_verify", OPT_NO_SIGNATURE_VERIFY, '-',
     "Don't check signature on response"},
    {"no_cert_verify", OPT_NO_CERT_VERIFY, '-',
     "Don't check signing certificate"},
    {"no_chain", OPT_NO_CHAIN, '-', "Don't chain verify response"},
    {"no_cert_checks", OPT_NO_CERT_CHECKS, '-',
     "Don't do additional checks on signing certificate"},
    {"no_explicit", OPT_NO_EXPLICIT, '-',
     "Do not explicitly check the chain, just verify the root"},
    {"trust_other", OPT_TRUST_OTHER, '-',
     "Don't verify additional certificates"},
    {"no_intern", OPT_NO_INTERN, '-',
     "Don't search certificates contained in response for signer"},
    {"badsig", OPT_BADSIG, '-',
        "Corrupt last byte of loaded OSCP response signature (for test)"},
    {"text", OPT_TEXT, '-', "Print text form of request and response"},
    {"req_text", OPT_REQ_TEXT, '-', "Print text form of request"},
    {"resp_text", OPT_RESP_TEXT, '-', "Print text form of response"},
    {"reqin", OPT_REQIN, 's', "File with the DER-encoded request"},
    {"respin", OPT_RESPIN, 's', "File with the DER-encoded response"},
    {"signer", OPT_SIGNER, '<', "Certificate to sign OCSP request with"},
    {"VAfile", OPT_VAFILE, '<', "Validator certificates file"},
    {"sign_other", OPT_SIGN_OTHER, '<',
     "Additional certificates to include in signed request"},
    {"verify_other", OPT_VERIFY_OTHER, '<',
     "Additional certificates to search for signer"},
    {"CAfile", OPT_CAFILE, '<', "Trusted certificates file"},
    {"CApath", OPT_CAPATH, '<', "Trusted certificates directory"},
    {"no-CAfile", OPT_NOCAFILE, '-',
     "Do not load the default certificates file"},
    {"no-CApath", OPT_NOCAPATH, '-',
     "Do not load certificates from the default certificates directory"},
    {"validity_period", OPT_VALIDITY_PERIOD, 'u',
     "Maximum validity discrepancy in seconds"},
    {"status_age", OPT_STATUS_AGE, 'p', "Maximum status age in seconds"},
    {"signkey", OPT_SIGNKEY, 's', "Private key to sign OCSP request with"},
    {"reqout", OPT_REQOUT, 's', "Output file for the DER-encoded request"},
    {"respout", OPT_RESPOUT, 's', "Output file for the DER-encoded response"},
    {"path", OPT_PATH, 's', "Path to use in OCSP request"},
    {"issuer", OPT_ISSUER, '<', "Issuer certificate"},
    {"cert", OPT_CERT, '<', "Certificate to check"},
    {"serial", OPT_SERIAL, 's', "Serial number to check"},
    {"index", OPT_INDEX, '<', "Certificate status index file"},
    {"CA", OPT_CA, '<', "CA certificate"},
    {"nmin", OPT_NMIN, 'p', "Number of minutes before next update"},
    {"nrequest", OPT_REQUEST, 'p',
     "Number of requests to accept (default unlimited)"},
    {"ndays", OPT_NDAYS, 'p', "Number of days before next update"},
    {"rsigner", OPT_RSIGNER, '<',
     "Responder certificate to sign responses with"},
    {"rkey", OPT_RKEY, '<', "Responder key to sign responses with"},
    {"rother", OPT_ROTHER, '<', "Other certificates to include in response"},
    {"rmd", OPT_RMD, 's', "Digest Algorithm to use in signature of OCSP response"},
    {"rsigopt", OPT_RSIGOPT, 's', "OCSP response signature parameter in n:v form"},
    {"header", OPT_HEADER, 's', "key=value header to add"},
    {"", OPT_MD, '-', "Any supported digest algorithm (sha1,sha256, ... )"},
    OPT_V_OPTIONS,
    {NULL}
};

int ocsp_main(int argc, char **argv)
{
    BIO *acbio = NULL, *cbio = NULL, *derbio = NULL, *out = NULL;
    const EVP_MD *cert_id_md = NULL, *rsign_md = NULL;
    STACK_OF(OPENSSL_STRING) *rsign_sigopts = NULL;
    int trailing_md = 0;
    CA_DB *rdb = NULL;
    EVP_PKEY *key = NULL, *rkey = NULL;
    OCSP_BASICRESP *bs = NULL;
    OCSP_REQUEST *req = NULL;
    OCSP_RESPONSE *resp = NULL;
    STACK_OF(CONF_VALUE) *headers = NULL;
    STACK_OF(OCSP_CERTID) *ids = NULL;
    STACK_OF(OPENSSL_STRING) *reqnames = NULL;
    STACK_OF(X509) *sign_other = NULL, *verify_other = NULL, *rother = NULL;
    STACK_OF(X509) *issuers = NULL;
    X509 *issuer = NULL, *cert = NULL;
    STACK_OF(X509) *rca_cert = NULL;
    X509 *signer = NULL, *rsigner = NULL;
    X509_STORE *store = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    const char *CAfile = NULL, *CApath = NULL;
    char *header, *value;
    char *host = NULL, *port = NULL, *path = "/", *outfile = NULL;
    char *rca_filename = NULL, *reqin = NULL, *respin = NULL;
    char *reqout = NULL, *respout = NULL, *ridx_filename = NULL;
    char *rsignfile = NULL, *rkeyfile = NULL;
    char *sign_certfile = NULL, *verify_certfile = NULL, *rcertfile = NULL;
    char *signfile = NULL, *keyfile = NULL;
    char *thost = NULL, *tport = NULL, *tpath = NULL;
    int noCAfile = 0, noCApath = 0;
    int accept_count = -1, add_nonce = 1, noverify = 0, use_ssl = -1;
    int vpmtouched = 0, badsig = 0, i, ignore_err = 0, nmin = 0, ndays = -1;
    int req_text = 0, resp_text = 0, ret = 1;
    int req_timeout = -1;
    long nsec = MAX_VALIDITY_PERIOD, maxage = -1;
    unsigned long sign_flags = 0, verify_flags = 0, rflags = 0;
    OPTION_CHOICE o;

    reqnames = sk_VR_OPENSSL_STRING_new_null();
    if (reqnames == NULL)
        goto end;
    ids = sk_VR_OCSP_CERTID_new_null();
    if (ids == NULL)
        goto end;
    if ((vpm = VR_X509_VERIFY_PARAM_new()) == NULL)
        return 1;

    prog = opt_init(argc, argv, ocsp_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            VR_BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            ret = 0;
            opt_help(ocsp_options);
            goto end;
        case OPT_OUTFILE:
            outfile = opt_arg();
            break;
        case OPT_TIMEOUT:
#ifndef OPENSSL_NO_SOCK
            req_timeout = atoi(opt_arg());
#endif
            break;
        case OPT_URL:
            OPENVR_SSL_free(thost);
            OPENVR_SSL_free(tport);
            OPENVR_SSL_free(tpath);
            thost = tport = tpath = NULL;
            if (!VR_OCSP_parse_url(opt_arg(), &host, &port, &path, &use_ssl)) {
                VR_BIO_printf(bio_err, "%s Error parsing URL\n", prog);
                goto end;
            }
            thost = host;
            tport = port;
            tpath = path;
            break;
        case OPT_HOST:
            host = opt_arg();
            break;
        case OPT_PORT:
            port = opt_arg();
            break;
        case OPT_IGNORE_ERR:
            ignore_err = 1;
            break;
        case OPT_NOVERIFY:
            noverify = 1;
            break;
        case OPT_NONCE:
            add_nonce = 2;
            break;
        case OPT_NO_NONCE:
            add_nonce = 0;
            break;
        case OPT_RESP_NO_CERTS:
            rflags |= OCSP_NOCERTS;
            break;
        case OPT_RESP_KEY_ID:
            rflags |= OCSP_RESPID_KEY;
            break;
        case OPT_NO_CERTS:
            sign_flags |= OCSP_NOCERTS;
            break;
        case OPT_NO_SIGNATURE_VERIFY:
            verify_flags |= OCSP_NOSIGS;
            break;
        case OPT_NO_CERT_VERIFY:
            verify_flags |= OCSP_NOVERIFY;
            break;
        case OPT_NO_CHAIN:
            verify_flags |= OCSP_NOCHAIN;
            break;
        case OPT_NO_CERT_CHECKS:
            verify_flags |= OCSP_NOCHECKS;
            break;
        case OPT_NO_EXPLICIT:
            verify_flags |= OCSP_NOEXPLICIT;
            break;
        case OPT_TRUST_OTHER:
            verify_flags |= OCSP_TRUSTOTHER;
            break;
        case OPT_NO_INTERN:
            verify_flags |= OCSP_NOINTERN;
            break;
        case OPT_BADSIG:
            badsig = 1;
            break;
        case OPT_TEXT:
            req_text = resp_text = 1;
            break;
        case OPT_REQ_TEXT:
            req_text = 1;
            break;
        case OPT_RESP_TEXT:
            resp_text = 1;
            break;
        case OPT_REQIN:
            reqin = opt_arg();
            break;
        case OPT_RESPIN:
            respin = opt_arg();
            break;
        case OPT_SIGNER:
            signfile = opt_arg();
            break;
        case OPT_VAFILE:
            verify_certfile = opt_arg();
            verify_flags |= OCSP_TRUSTOTHER;
            break;
        case OPT_SIGN_OTHER:
            sign_certfile = opt_arg();
            break;
        case OPT_VERIFY_OTHER:
            verify_certfile = opt_arg();
            break;
        case OPT_CAFILE:
            CAfile = opt_arg();
            break;
        case OPT_CAPATH:
            CApath = opt_arg();
            break;
        case OPT_NOCAFILE:
            noCAfile = 1;
            break;
        case OPT_NOCAPATH:
            noCApath = 1;
            break;
        case OPT_V_CASES:
            if (!opt_verify(o, vpm))
                goto end;
            vpmtouched++;
            break;
        case OPT_VALIDITY_PERIOD:
            opt_long(opt_arg(), &nsec);
            break;
        case OPT_STATUS_AGE:
            opt_long(opt_arg(), &maxage);
            break;
        case OPT_SIGNKEY:
            keyfile = opt_arg();
            break;
        case OPT_REQOUT:
            reqout = opt_arg();
            break;
        case OPT_RESPOUT:
            respout = opt_arg();
            break;
        case OPT_PATH:
            path = opt_arg();
            break;
        case OPT_ISSUER:
            issuer = load_cert(opt_arg(), FORMAT_PEM, "issuer certificate");
            if (issuer == NULL)
                goto end;
            if (issuers == NULL) {
                if ((issuers = sk_VR_X509_new_null()) == NULL)
                    goto end;
            }
            sk_VR_X509_push(issuers, issuer);
            break;
        case OPT_CERT:
            VR_X509_free(cert);
            cert = load_cert(opt_arg(), FORMAT_PEM, "certificate");
            if (cert == NULL)
                goto end;
            if (cert_id_md == NULL)
                cert_id_md = VR_EVP_sha1();
            if (!add_ocsp_cert(&req, cert, cert_id_md, issuer, ids))
                goto end;
            if (!sk_VR_OPENSSL_STRING_push(reqnames, opt_arg()))
                goto end;
            trailing_md = 0;
            break;
        case OPT_SERIAL:
            if (cert_id_md == NULL)
                cert_id_md = VR_EVP_sha1();
            if (!add_ocsp_serial(&req, opt_arg(), cert_id_md, issuer, ids))
                goto end;
            if (!sk_VR_OPENSSL_STRING_push(reqnames, opt_arg()))
                goto end;
            trailing_md = 0;
            break;
        case OPT_INDEX:
            ridx_filename = opt_arg();
            break;
        case OPT_CA:
            rca_filename = opt_arg();
            break;
        case OPT_NMIN:
            opt_int(opt_arg(), &nmin);
            if (ndays == -1)
                ndays = 0;
            break;
        case OPT_REQUEST:
            opt_int(opt_arg(), &accept_count);
            break;
        case OPT_NDAYS:
            ndays = atoi(opt_arg());
            break;
        case OPT_RSIGNER:
            rsignfile = opt_arg();
            break;
        case OPT_RKEY:
            rkeyfile = opt_arg();
            break;
        case OPT_ROTHER:
            rcertfile = opt_arg();
            break;
        case OPT_RMD:   /* Response MessageDigest */
            if (!opt_md(opt_arg(), &rsign_md))
                goto end;
            break;
        case OPT_RSIGOPT:
            if (rsign_sigopts == NULL)
                rsign_sigopts = sk_VR_OPENSSL_STRING_new_null();
            if (rsign_sigopts == NULL || !sk_VR_OPENSSL_STRING_push(rsign_sigopts, opt_arg()))
                goto end;
            break;
        case OPT_HEADER:
            header = opt_arg();
            value = strchr(header, '=');
            if (value == NULL) {
                VR_BIO_printf(bio_err, "Missing = in header key=value\n");
                goto opthelp;
            }
            *value++ = '\0';
            if (!VR_X509V3_add_value(header, value, &headers))
                goto end;
            break;
        case OPT_MD:
            if (trailing_md) {
                VR_BIO_printf(bio_err,
                           "%s: Digest must be before -cert or -serial\n",
                           prog);
                goto opthelp;
            }
            if (!opt_md(opt_unknown(), &cert_id_md))
                goto opthelp;
            trailing_md = 1;
            break;
        case OPT_MULTI:
# ifdef OCSP_DAEMON
            multi = atoi(opt_arg());
# endif
            break;
        }
    }
    if (trailing_md) {
        VR_BIO_printf(bio_err, "%s: Digest must be before -cert or -serial\n",
                   prog);
        goto opthelp;
    }
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    /* Have we anything to do? */
    if (req == NULL && reqin == NULL
        && respin == NULL && !(port != NULL && ridx_filename != NULL))
        goto opthelp;

    out = bio_open_default(outfile, 'w', FORMAT_TEXT);
    if (out == NULL)
        goto end;

    if (req == NULL && (add_nonce != 2))
        add_nonce = 0;

    if (req == NULL && reqin != NULL) {
        derbio = bio_open_default(reqin, 'r', FORMAT_ASN1);
        if (derbio == NULL)
            goto end;
        req = VR_d2i_OCSP_REQUEST_bio(derbio, NULL);
        VR_BIO_free(derbio);
        if (req == NULL) {
            VR_BIO_printf(bio_err, "Error reading OCSP request\n");
            goto end;
        }
    }

    if (req == NULL && port != NULL) {
        acbio = init_responder(port);
        if (acbio == NULL)
            goto end;
    }

    if (rsignfile != NULL) {
        if (rkeyfile == NULL)
            rkeyfile = rsignfile;
        rsigner = load_cert(rsignfile, FORMAT_PEM, "responder certificate");
        if (rsigner == NULL) {
            VR_BIO_printf(bio_err, "Error loading responder certificate\n");
            goto end;
        }
        if (!load_certs(rca_filename, &rca_cert, FORMAT_PEM,
                        NULL, "CA certificate"))
            goto end;
        if (rcertfile != NULL) {
            if (!load_certs(rcertfile, &rother, FORMAT_PEM, NULL,
                            "responder other certificates"))
                goto end;
        }
        rkey = load_key(rkeyfile, FORMAT_PEM, 0, NULL, NULL,
                        "responder private key");
        if (rkey == NULL)
            goto end;
    }

    if (ridx_filename != NULL
        && (rkey == NULL || rsigner == NULL || rca_cert == NULL)) {
        VR_BIO_printf(bio_err,
                   "Responder mode requires certificate, key, and CA.\n");
        goto end;
    }

    if (ridx_filename != NULL) {
        rdb = load_index(ridx_filename, NULL);
        if (rdb == NULL || index_index(rdb) <= 0) {
            ret = 1;
            goto end;
        }
    }

# ifdef OCSP_DAEMON
    if (multi && acbio != NULL)
        spawn_loop();
    if (acbio != NULL && req_timeout > 0)
        signal(SIGALRM, sock_timeout);
#endif

    if (acbio != NULL)
        log_message(LOG_INFO, "waiting for OCSP client connections...");

redo_accept:

    if (acbio != NULL) {
# ifdef OCSP_DAEMON
        if (index_changed(rdb)) {
            CA_DB *newrdb = load_index(ridx_filename, NULL);

            if (newrdb != NULL && index_index(newrdb) > 0) {
                free_index(rdb);
                rdb = newrdb;
            } else {
                free_index(newrdb);
                log_message(LOG_ERR, "error reloading updated index: %s",
                            ridx_filename);
            }
        }
# endif

        req = NULL;
        if (!do_responder(&req, &cbio, acbio, req_timeout))
            goto redo_accept;

        if (req == NULL) {
            resp =
                VR_OCSP_response_create(OCSP_RESPONSE_STATUS_MALFORMEDREQUEST,
                                     NULL);
            send_ocsp_response(cbio, resp);
            goto done_resp;
        }
    }

    if (req == NULL
        && (signfile != NULL || reqout != NULL
            || host != NULL || add_nonce || ridx_filename != NULL)) {
        VR_BIO_printf(bio_err, "Need an OCSP request for this operation!\n");
        goto end;
    }

    if (req != NULL && add_nonce)
        VR_OCSP_request_add1_nonce(req, NULL, -1);

    if (signfile != NULL) {
        if (keyfile == NULL)
            keyfile = signfile;
        signer = load_cert(signfile, FORMAT_PEM, "signer certificate");
        if (signer == NULL) {
            VR_BIO_printf(bio_err, "Error loading signer certificate\n");
            goto end;
        }
        if (sign_certfile != NULL) {
            if (!load_certs(sign_certfile, &sign_other, FORMAT_PEM, NULL,
                            "signer certificates"))
                goto end;
        }
        key = load_key(keyfile, FORMAT_PEM, 0, NULL, NULL,
                       "signer private key");
        if (key == NULL)
            goto end;

        if (!VR_OCSP_request_sign
            (req, signer, key, NULL, sign_other, sign_flags)) {
            VR_BIO_printf(bio_err, "Error signing OCSP request\n");
            goto end;
        }
    }

    if (req_text && req != NULL)
        VR_OCSP_REQUEST_print(out, req, 0);

    if (reqout != NULL) {
        derbio = bio_open_default(reqout, 'w', FORMAT_ASN1);
        if (derbio == NULL)
            goto end;
        VR_i2d_OCSP_REQUEST_bio(derbio, req);
        VR_BIO_free(derbio);
    }

    if (rdb != NULL) {
        make_ocsp_response(bio_err, &resp, req, rdb, rca_cert, rsigner, rkey,
                               rsign_md, rsign_sigopts, rother, rflags, nmin, ndays, badsig);
        if (cbio != NULL)
            send_ocsp_response(cbio, resp);
    } else if (host != NULL) {
# ifndef OPENSSL_NO_SOCK
        resp = process_responder(req, host, path,
                                 port, use_ssl, headers, req_timeout);
        if (resp == NULL)
            goto end;
# else
        VR_BIO_printf(bio_err,
                   "Error creating connect BIO - sockets not supported.\n");
        goto end;
# endif
    } else if (respin != NULL) {
        derbio = bio_open_default(respin, 'r', FORMAT_ASN1);
        if (derbio == NULL)
            goto end;
        resp = VR_d2i_OCSP_RESPONSE_bio(derbio, NULL);
        VR_BIO_free(derbio);
        if (resp == NULL) {
            VR_BIO_printf(bio_err, "Error reading OCSP response\n");
            goto end;
        }
    } else {
        ret = 0;
        goto end;
    }

 done_resp:

    if (respout != NULL) {
        derbio = bio_open_default(respout, 'w', FORMAT_ASN1);
        if (derbio == NULL)
            goto end;
        VR_i2d_OCSP_RESPONSE_bio(derbio, resp);
        VR_BIO_free(derbio);
    }

    i = VR_OCSP_response_status(resp);
    if (i != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        VR_BIO_printf(out, "Responder Error: %s (%d)\n",
                   VR_OCSP_response_status_str(i), i);
        if (!ignore_err)
                goto end;
    }

    if (resp_text)
        VR_OCSP_RESPONSE_print(out, resp, 0);

    /* If running as responder don't verify our own response */
    if (cbio != NULL) {
        /* If not unlimited, see if we took all we should. */
        if (accept_count != -1 && --accept_count <= 0) {
            ret = 0;
            goto end;
        }
        VR_BIO_free_all(cbio);
        cbio = NULL;
        VR_OCSP_REQUEST_free(req);
        req = NULL;
        VR_OCSP_RESPONSE_free(resp);
        resp = NULL;
        goto redo_accept;
    }
    if (ridx_filename != NULL) {
        ret = 0;
        goto end;
    }

    if (store == NULL) {
        store = setup_verify(CAfile, CApath, noCAfile, noCApath);
        if (!store)
            goto end;
    }
    if (vpmtouched)
        VR_X509_STORE_set1_param(store, vpm);
    if (verify_certfile != NULL) {
        if (!load_certs(verify_certfile, &verify_other, FORMAT_PEM, NULL,
                        "validator certificate"))
            goto end;
    }

    bs = VR_OCSP_response_get1_basic(resp);
    if (bs == NULL) {
        VR_BIO_printf(bio_err, "Error parsing response\n");
        goto end;
    }

    ret = 0;

    if (!noverify) {
        if (req != NULL && ((i = VR_OCSP_check_nonce(req, bs)) <= 0)) {
            if (i == -1)
                VR_BIO_printf(bio_err, "WARNING: no nonce in response\n");
            else {
                VR_BIO_printf(bio_err, "Nonce Verify error\n");
                ret = 1;
                goto end;
            }
        }

        i = VR_OCSP_basic_verify(bs, verify_other, store, verify_flags);
        if (i <= 0 && issuers) {
            i = VR_OCSP_basic_verify(bs, issuers, store, OCSP_TRUSTOTHER);
            if (i > 0)
                VR_ERR_clear_error();
        }
        if (i <= 0) {
            VR_BIO_printf(bio_err, "Response Verify Failure\n");
            VR_ERR_print_errors(bio_err);
            ret = 1;
        } else {
            VR_BIO_printf(bio_err, "Response verify OK\n");
        }
    }

    print_ocsp_summary(out, bs, req, reqnames, ids, nsec, maxage);

 end:
    VR_ERR_print_errors(bio_err);
    VR_X509_free(signer);
    VR_X509_STORE_free(store);
    VR_X509_VERIFY_PARAM_free(vpm);
    sk_VR_OPENSSL_STRING_free(rsign_sigopts);
    VR_EVP_PKEY_free(key);
    VR_EVP_PKEY_free(rkey);
    VR_X509_free(cert);
    sk_VR_X509_pop_free(issuers, VR_X509_free);
    VR_X509_free(rsigner);
    sk_VR_X509_pop_free(rca_cert, VR_X509_free);
    free_index(rdb);
    VR_BIO_free_all(cbio);
    VR_BIO_free_all(acbio);
    VR_BIO_free_all(out);
    VR_OCSP_REQUEST_free(req);
    VR_OCSP_RESPONSE_free(resp);
    VR_OCSP_BASICRESP_free(bs);
    sk_VR_OPENSSL_STRING_free(reqnames);
    sk_VR_OCSP_CERTID_free(ids);
    sk_VR_X509_pop_free(sign_other, VR_X509_free);
    sk_VR_X509_pop_free(verify_other, VR_X509_free);
    sk_VR_CONF_VALUE_pop_free(headers, VR_X509V3_conf_free);
    OPENVR_SSL_free(thost);
    OPENVR_SSL_free(tport);
    OPENVR_SSL_free(tpath);

    return ret;
}

static void
log_message(int level, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
# ifdef OCSP_DAEMON
    if (multi) {
        char buf[1024];
        if (vsnprintf(buf, sizeof(buf), fmt, ap) > 0) {
            syslog(level, "%s", buf);
        }
        if (level >= LOG_ERR)
            VR_ERR_print_errors_cb(print_syslog, &level);
    }
# endif
    if (!multi) {
        VR_BIO_printf(bio_err, "%s: ", prog);
        VR_BIO_vprintf(bio_err, fmt, ap);
        VR_BIO_printf(bio_err, "\n");
    }
    va_end(ap);
}

# ifdef OCSP_DAEMON

static int print_syslog(const char *str, size_t len, void *levPtr)
{
    int level = *(int *)levPtr;
    int ilen = (len > MAXERRLEN) ? MAXERRLEN : len;

    syslog(level, "%.*s", ilen, str);

    return ilen;
}

static int index_changed(CA_DB *rdb)
{
    struct stat sb;

    if (rdb != NULL && stat(rdb->dbfname, &sb) != -1) {
        if (rdb->dbst.st_mtime != sb.st_mtime
            || rdb->dbst.st_ctime != sb.st_ctime
            || rdb->dbst.st_ino != sb.st_ino
            || rdb->dbst.st_dev != sb.st_dev) {
            syslog(LOG_INFO, "index file changed, reloading");
            return 1;
        }
    }
    return 0;
}

static void killall(int ret, pid_t *kidpids)
{
    int i;

    for (i = 0; i < multi; ++i)
        if (kidpids[i] != 0)
            (void)kill(kidpids[i], SIGTERM);
    OPENVR_SSL_free(kidpids);
    sleep(1);
    exit(ret);
}

static int termsig = 0;

static void noteterm (int sig)
{
    termsig = sig;
}

/*
 * Loop spawning up to `multi` child processes, only child processes return
 * from this function.  The parent process loops until receiving a termination
 * signal, kills extant children and exits without returning.
 */
static void spawn_loop(void)
{
    pid_t *kidpids = NULL;
    int status;
    int procs = 0;
    int i;

    openlog(prog, LOG_PID, LOG_DAEMON);

    if (setpgid(0, 0)) {
        syslog(LOG_ERR, "fatal: error detaching from parent process group: %s",
               strerror(errno));
        exit(1);
    }
    kidpids = app_malloc(multi * sizeof(*kidpids), "child PID array");
    for (i = 0; i < multi; ++i)
        kidpids[i] = 0;

    signal(SIGINT, noteterm);
    signal(SIGTERM, noteterm);

    while (termsig == 0) {
        pid_t fpid;

        /*
         * Wait for a child to replace when we're at the limit.
         * Slow down if a child exited abnormally or waitpid() < 0
         */
        while (termsig == 0 && procs >= multi) {
            if ((fpid = waitpid(-1, &status, 0)) > 0) {
                for (i = 0; i < procs; ++i) {
                    if (kidpids[i] == fpid) {
                        kidpids[i] = 0;
                        --procs;
                        break;
                    }
                }
                if (i >= multi) {
                    syslog(LOG_ERR, "fatal: internal error: "
                           "no matching child slot for pid: %ld",
                           (long) fpid);
                    killall(1, kidpids);
                }
                if (status != 0) {
                    if (WIFEXITED(status))
                        syslog(LOG_WARNING, "child process: %ld, exit status: %d",
                               (long)fpid, WEXITSTATUS(status));
                    else if (WIFSIGNALED(status))
                        syslog(LOG_WARNING, "child process: %ld, term signal %d%s",
                               (long)fpid, WTERMSIG(status),
#ifdef WCOREDUMP
                               WCOREDUMP(status) ? " (core dumped)" :
#endif
                               "");
                    sleep(1);
                }
                break;
            } else if (errno != EINTR) {
                syslog(LOG_ERR, "fatal: waitpid(): %s", strerror(errno));
                killall(1, kidpids);
            }
        }
        if (termsig)
            break;

        switch(fpid = fork()) {
        case -1:            /* error */
            /* System critically low on memory, pause and try again later */
            sleep(30);
            break;
        case 0:             /* child */
            OPENVR_SSL_free(kidpids);
            signal(SIGINT, SIG_DFL);
            signal(SIGTERM, SIG_DFL);
            if (termsig)
                _exit(0);
            if (VR_RAND_poll() <= 0) {
                syslog(LOG_ERR, "fatal: VR_RAND_poll() failed");
                _exit(1);
            }
            return;
        default:            /* parent */
            for (i = 0; i < multi; ++i) {
                if (kidpids[i] == 0) {
                    kidpids[i] = fpid;
                    procs++;
                    break;
                }
            }
            if (i >= multi) {
                syslog(LOG_ERR, "fatal: internal error: no free child slots");
                killall(1, kidpids);
            }
            break;
        }
    }

    /* The loop above can only break on termsig */
    syslog(LOG_INFO, "terminating on signal: %d", termsig);
    killall(0, kidpids);
}
# endif

static int add_ocsp_cert(OCSP_REQUEST **req, X509 *cert,
                         const EVP_MD *cert_id_md, X509 *issuer,
                         STACK_OF(OCSP_CERTID) *ids)
{
    OCSP_CERTID *id;

    if (issuer == NULL) {
        VR_BIO_printf(bio_err, "No issuer certificate specified\n");
        return 0;
    }
    if (*req == NULL)
        *req = VR_OCSP_REQUEST_new();
    if (*req == NULL)
        goto err;
    id = VR_OCSP_cert_to_id(cert_id_md, cert, issuer);
    if (id == NULL || !sk_VR_OCSP_CERTID_push(ids, id))
        goto err;
    if (!VR_OCSP_request_add0_id(*req, id))
        goto err;
    return 1;

 err:
    VR_BIO_printf(bio_err, "Error Creating OCSP request\n");
    return 0;
}

static int add_ocsp_serial(OCSP_REQUEST **req, char *serial,
                           const EVP_MD *cert_id_md, X509 *issuer,
                           STACK_OF(OCSP_CERTID) *ids)
{
    OCSP_CERTID *id;
    X509_NAME *iname;
    ASN1_BIT_STRING *ikey;
    ASN1_INTEGER *sno;

    if (issuer == NULL) {
        VR_BIO_printf(bio_err, "No issuer certificate specified\n");
        return 0;
    }
    if (*req == NULL)
        *req = VR_OCSP_REQUEST_new();
    if (*req == NULL)
        goto err;
    iname = VR_X509_get_subject_name(issuer);
    ikey = VR_X509_get0_pubkey_bitstr(issuer);
    sno = VR_s2i_ASN1_INTEGER(NULL, serial);
    if (sno == NULL) {
        VR_BIO_printf(bio_err, "Error converting serial number %s\n", serial);
        return 0;
    }
    id = VR_OCSP_cert_id_new(cert_id_md, iname, ikey, sno);
    VR_ASN1_INTEGER_free(sno);
    if (id == NULL || !sk_VR_OCSP_CERTID_push(ids, id))
        goto err;
    if (!VR_OCSP_request_add0_id(*req, id))
        goto err;
    return 1;

 err:
    VR_BIO_printf(bio_err, "Error Creating OCSP request\n");
    return 0;
}

static void print_ocsp_summary(BIO *out, OCSP_BASICRESP *bs, OCSP_REQUEST *req,
                              STACK_OF(OPENSSL_STRING) *names,
                              STACK_OF(OCSP_CERTID) *ids, long nsec,
                              long maxage)
{
    OCSP_CERTID *id;
    const char *name;
    int i, status, reason;
    ASN1_GENERALIZEDTIME *rev, *thisupd, *nextupd;

    if (bs == NULL || req == NULL || !sk_OPENSSL_STRING_num(names)
        || !sk_OCSP_CERTID_num(ids))
        return;

    for (i = 0; i < sk_OCSP_CERTID_num(ids); i++) {
        id = sk_OCSP_CERTID_value(ids, i);
        name = sk_OPENSSL_STRING_value(names, i);
        VR_BIO_printf(out, "%s: ", name);

        if (!VR_OCSP_resp_find_status(bs, id, &status, &reason,
                                   &rev, &thisupd, &nextupd)) {
            VR_BIO_puts(out, "ERROR: No Status found.\n");
            continue;
        }

        /*
         * Check validity: if invalid write to output BIO so we know which
         * response this refers to.
         */
        if (!VR_OCSP_check_validity(thisupd, nextupd, nsec, maxage)) {
            VR_BIO_puts(out, "WARNING: Status times invalid.\n");
            VR_ERR_print_errors(out);
        }
        VR_BIO_printf(out, "%s\n", VR_OCSP_cert_status_str(status));

        VR_BIO_puts(out, "\tThis Update: ");
        VR_ASN1_GENERALIZEDTIME_print(out, thisupd);
        VR_BIO_puts(out, "\n");

        if (nextupd) {
            VR_BIO_puts(out, "\tNext Update: ");
            VR_ASN1_GENERALIZEDTIME_print(out, nextupd);
            VR_BIO_puts(out, "\n");
        }

        if (status != V_OCSP_CERTSTATUS_REVOKED)
            continue;

        if (reason != -1)
            VR_BIO_printf(out, "\tReason: %s\n", VR_OCSP_crl_reason_str(reason));

        VR_BIO_puts(out, "\tRevocation Time: ");
        VR_ASN1_GENERALIZEDTIME_print(out, rev);
        VR_BIO_puts(out, "\n");
    }
}

static void make_ocsp_response(BIO *err, OCSP_RESPONSE **resp, OCSP_REQUEST *req,
                              CA_DB *db, STACK_OF(X509) *ca, X509 *rcert,
                              EVP_PKEY *rkey, const EVP_MD *rmd,
                              STACK_OF(OPENSSL_STRING) *sigopts,
                              STACK_OF(X509) *rother, unsigned long flags,
                              int nmin, int ndays, int badsig)
{
    ASN1_TIME *thisupd = NULL, *nextupd = NULL;
    OCSP_CERTID *cid;
    OCSP_BASICRESP *bs = NULL;
    int i, id_count;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pkctx = NULL;

    id_count = VR_OCSP_request_onereq_count(req);

    if (id_count <= 0) {
        *resp =
            VR_OCSP_response_create(OCSP_RESPONSE_STATUS_MALFORMEDREQUEST, NULL);
        goto end;
    }

    bs = VR_OCSP_BASICRESP_new();
    thisupd = VR_X509_gmtime_adj(NULL, 0);
    if (ndays != -1)
        nextupd = VR_X509_time_adj_ex(NULL, ndays, nmin * 60, NULL);

    /* Examine each certificate id in the request */
    for (i = 0; i < id_count; i++) {
        OCSP_ONEREQ *one;
        ASN1_INTEGER *serial;
        char **inf;
        int jj;
        int found = 0;
        ASN1_OBJECT *cert_id_md_oid;
        const EVP_MD *cert_id_md;
        one = VR_OCSP_request_onereq_get0(req, i);
        cid = VR_OCSP_onereq_get0_id(one);

        VR_OCSP_id_get0_info(NULL, &cert_id_md_oid, NULL, NULL, cid);

        cert_id_md = EVP_get_digestbyobj(cert_id_md_oid);
        if (cert_id_md == NULL) {
            *resp = VR_OCSP_response_create(OCSP_RESPONSE_STATUS_INTERNALERROR,
                                         NULL);
            goto end;
        }
        for (jj = 0; jj < sk_X509_num(ca) && !found; jj++) {
            X509 *ca_cert = sk_X509_value(ca, jj);
            OCSP_CERTID *ca_id = VR_OCSP_cert_to_id(cert_id_md, NULL, ca_cert);

            if (VR_OCSP_id_issuer_cmp(ca_id, cid) == 0)
                found = 1;

            VR_OCSP_CERTID_free(ca_id);
        }

        if (!found) {
            VR_OCSP_basic_add1_status(bs, cid,
                                   V_OCSP_CERTSTATUS_UNKNOWN,
                                   0, NULL, thisupd, nextupd);
            continue;
        }
        VR_OCSP_id_get0_info(NULL, NULL, NULL, &serial, cid);
        inf = lookup_serial(db, serial);
        if (inf == NULL) {
            VR_OCSP_basic_add1_status(bs, cid,
                                   V_OCSP_CERTSTATUS_UNKNOWN,
                                   0, NULL, thisupd, nextupd);
        } else if (inf[DB_type][0] == DB_TYPE_VAL) {
            VR_OCSP_basic_add1_status(bs, cid,
                                   V_OCSP_CERTSTATUS_GOOD,
                                   0, NULL, thisupd, nextupd);
        } else if (inf[DB_type][0] == DB_TYPE_REV) {
            ASN1_OBJECT *inst = NULL;
            ASN1_TIME *revtm = NULL;
            ASN1_GENERALIZEDTIME *invtm = NULL;
            OCSP_SINGLERESP *single;
            int reason = -1;
            unpack_revinfo(&revtm, &reason, &inst, &invtm, inf[DB_rev_date]);
            single = VR_OCSP_basic_add1_status(bs, cid,
                                            V_OCSP_CERTSTATUS_REVOKED,
                                            reason, revtm, thisupd, nextupd);
            if (invtm != NULL)
                VR_OCSP_SINGLERESP_add1_ext_i2d(single, NID_invalidity_date,
                                             invtm, 0, 0);
            else if (inst != NULL)
                VR_OCSP_SINGLERESP_add1_ext_i2d(single,
                                             NID_hold_instruction_code, inst,
                                             0, 0);
            VR_ASN1_OBJECT_free(inst);
            VR_ASN1_TIME_free(revtm);
            VR_ASN1_GENERALIZEDTIME_free(invtm);
        }
    }

    VR_OCSP_copy_nonce(bs, req);

    mctx = VR_EVP_MD_CTX_new();
    if ( mctx == NULL || !VR_EVP_DigestSignInit(mctx, &pkctx, rmd, NULL, rkey)) {
        *resp = VR_OCSP_response_create(OCSP_RESPONSE_STATUS_INTERNALERROR, NULL);
        goto end;
    }
    for (i = 0; i < sk_OPENSSL_STRING_num(sigopts); i++) {
        char *sigopt = sk_OPENSSL_STRING_value(sigopts, i);

        if (pkey_ctrl_string(pkctx, sigopt) <= 0) {
            VR_BIO_printf(err, "parameter error \"%s\"\n", sigopt);
            VR_ERR_print_errors(bio_err);
            *resp = VR_OCSP_response_create(OCSP_RESPONSE_STATUS_INTERNALERROR,
                                         NULL);
            goto end;
        }
    }
    VR_OCSP_basic_sign_ctx(bs, rcert, mctx, rother, flags);

    if (badsig) {
        const ASN1_OCTET_STRING *sig = VR_OCSP_resp_get0_signature(bs);
        corrupt_signature(sig);
    }

    *resp = VR_OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, bs);

 end:
    VR_EVP_MD_CTX_free(mctx);
    VR_ASN1_TIME_free(thisupd);
    VR_ASN1_TIME_free(nextupd);
    VR_OCSP_BASICRESP_free(bs);
}

static char **lookup_serial(CA_DB *db, ASN1_INTEGER *ser)
{
    int i;
    BIGNUM *bn = NULL;
    char *itmp, *row[DB_NUMBER], **rrow;
    for (i = 0; i < DB_NUMBER; i++)
        row[i] = NULL;
    bn = VR_ASN1_INTEGER_to_BN(ser, NULL);
    OPENSSL_assert(bn);         /* FIXME: should report an error at this
                                 * point and abort */
    if (VR_BN_is_zero(bn))
        itmp = OPENSSL_strdup("00");
    else
        itmp = VR_BN_bn2hex(bn);
    row[DB_serial] = itmp;
    VR_BN_free(bn);
    rrow = VR_TXT_DB_get_by_index(db->db, DB_serial, row);
    OPENVR_SSL_free(itmp);
    return rrow;
}

/* Quick and dirty OCSP server: read in and parse input request */

static BIO *init_responder(const char *port)
{
# ifdef OPENSSL_NO_SOCK
    VR_BIO_printf(bio_err,
               "Error setting up accept BIO - sockets not supported.\n");
    return NULL;
# else
    BIO *acbio = NULL, *bufbio = NULL;

    bufbio = VR_BIO_new(VR_BIO_f_buffer());
    if (bufbio == NULL)
        goto err;
    acbio = VR_BIO_new(VR_BIO_s_accept());
    if (acbio == NULL
        || BIO_set_bind_mode(acbio, BIO_BIND_REUSEADDR) < 0
        || BIO_set_accept_port(acbio, port) < 0) {
        log_message(LOG_ERR, "Error setting up accept BIO");
        goto err;
    }

    BIO_set_accept_bios(acbio, bufbio);
    bufbio = NULL;
    if (BIO_do_accept(acbio) <= 0) {
        log_message(LOG_ERR, "Error starting accept");
        goto err;
    }

    return acbio;

 err:
    VR_BIO_free_all(acbio);
    VR_BIO_free(bufbio);
    return NULL;
# endif
}

# ifndef OPENSSL_NO_SOCK
/*
 * Decode %xx URL-decoding in-place. Ignores mal-formed sequences.
 */
static int urldecode(char *p)
{
    unsigned char *out = (unsigned char *)p;
    unsigned char *save = out;

    for (; *p; p++) {
        if (*p != '%')
            *out++ = *p;
        else if (isxdigit(_UC(p[1])) && isxdigit(_UC(p[2]))) {
            /* Don't check, can't fail because of ixdigit() call. */
            *out++ = (VR_OPENSSL_hexchar2int(p[1]) << 4)
                   | VR_OPENSSL_hexchar2int(p[2]);
            p += 2;
        }
        else
            return -1;
    }
    *out = '\0';
    return (int)(out - save);
}
# endif

# ifdef OCSP_DAEMON
static void sock_timeout(int signum)
{
    if (acfd != (int)INVALID_SOCKET)
        (void)shutdown(acfd, SHUT_RD);
}
# endif

static int do_responder(OCSP_REQUEST **preq, BIO **pcbio, BIO *acbio,
                        int timeout)
{
# ifdef OPENSSL_NO_SOCK
    return 0;
# else
    int len;
    OCSP_REQUEST *req = NULL;
    char inbuf[2048], reqbuf[2048];
    char *p, *q;
    BIO *cbio = NULL, *getbio = NULL, *b64 = NULL;
    const char *client;

    *preq = NULL;

    /* Connection loss before accept() is routine, ignore silently */
    if (BIO_do_accept(acbio) <= 0)
        return 0;

    cbio = VR_BIO_pop(acbio);
    *pcbio = cbio;
    client = BIO_get_peer_name(cbio);

#  ifdef OCSP_DAEMON
    if (timeout > 0) {
        (void) BIO_get_fd(cbio, &acfd);
        alarm(timeout);
    }
#  endif

    /* Read the request line. */
    len = VR_BIO_gets(cbio, reqbuf, sizeof(reqbuf));
    if (len <= 0)
        goto out;

    if (strncmp(reqbuf, "GET ", 4) == 0) {
        /* Expecting GET {sp} /URL {sp} HTTP/1.x */
        for (p = reqbuf + 4; *p == ' '; ++p)
            continue;
        if (*p != '/') {
            log_message(LOG_INFO, "Invalid request -- bad URL: %s", client);
            goto out;
        }
        p++;

        /* Splice off the HTTP version identifier. */
        for (q = p; *q; q++)
            if (*q == ' ')
                break;
        if (strncmp(q, " HTTP/1.", 8) != 0) {
            log_message(LOG_INFO,
                        "Invalid request -- bad HTTP version: %s", client);
            goto out;
        }
        *q = '\0';

        /*
         * Skip "GET / HTTP..." requests often used by load-balancers
         */
        if (p[1] == '\0')
            goto out;

        len = urldecode(p);
        if (len <= 0) {
            log_message(LOG_INFO,
                        "Invalid request -- bad URL encoding: %s", client);
            goto out;
        }
        if ((getbio = VR_BIO_new_mem_buf(p, len)) == NULL
            || (b64 = VR_BIO_new(VR_BIO_f_base64())) == NULL) {
            log_message(LOG_ERR, "Could not allocate base64 bio: %s", client);
            goto out;
        }
        VR_BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        getbio = VR_BIO_push(b64, getbio);
    } else if (strncmp(reqbuf, "POST ", 5) != 0) {
        log_message(LOG_INFO, "Invalid request -- bad HTTP verb: %s", client);
        goto out;
    }

    /* Read and skip past the headers. */
    for (;;) {
        len = VR_BIO_gets(cbio, inbuf, sizeof(inbuf));
        if (len <= 0)
            goto out;
        if ((inbuf[0] == '\r') || (inbuf[0] == '\n'))
            break;
    }

#  ifdef OCSP_DAEMON
    /* Clear alarm before we close the client socket */
    alarm(0);
    timeout = 0;
#  endif

    /* Try to read OCSP request */
    if (getbio != NULL) {
        req = VR_d2i_OCSP_REQUEST_bio(getbio, NULL);
        VR_BIO_free_all(getbio);
    } else {
        req = VR_d2i_OCSP_REQUEST_bio(cbio, NULL);
    }

    if (req == NULL)
        log_message(LOG_ERR, "Error parsing OCSP request");

    *preq = req;

out:
#  ifdef OCSP_DAEMON
    if (timeout > 0)
        alarm(0);
    acfd = (int)INVALID_SOCKET;
#  endif
    return 1;
# endif
}

static int send_ocsp_response(BIO *cbio, OCSP_RESPONSE *resp)
{
    char http_resp[] =
        "HTTP/1.0 200 OK\r\nContent-type: application/ocsp-response\r\n"
        "Content-Length: %d\r\n\r\n";
    if (cbio == NULL)
        return 0;
    VR_BIO_printf(cbio, http_resp, VR_i2d_OCSP_RESPONSE(resp, NULL));
    VR_i2d_OCSP_RESPONSE_bio(cbio, resp);
    (void)BIO_flush(cbio);
    return 1;
}

# ifndef OPENSSL_NO_SOCK
static OCSP_RESPONSE *query_responder(BIO *cbio, const char *host,
                                      const char *path,
                                      const STACK_OF(CONF_VALUE) *headers,
                                      OCSP_REQUEST *req, int req_timeout)
{
    int fd;
    int rv;
    int i;
    int add_host = 1;
    OCSP_REQ_CTX *ctx = NULL;
    OCSP_RESPONSE *rsp = NULL;
    fd_set confds;
    struct timeval tv;

    if (req_timeout != -1)
        BIO_set_nbio(cbio, 1);

    rv = BIO_do_connect(cbio);

    if ((rv <= 0) && ((req_timeout == -1) || !BIO_should_retry(cbio))) {
        VR_BIO_puts(bio_err, "Error connecting BIO\n");
        return NULL;
    }

    if (BIO_get_fd(cbio, &fd) < 0) {
        VR_BIO_puts(bio_err, "Can't get connection fd\n");
        goto err;
    }

    if (req_timeout != -1 && rv <= 0) {
        FD_ZERO(&confds);
        openssl_fdset(fd, &confds);
        tv.tv_usec = 0;
        tv.tv_sec = req_timeout;
        rv = select(fd + 1, NULL, (void *)&confds, NULL, &tv);
        if (rv == 0) {
            VR_BIO_puts(bio_err, "Timeout on connect\n");
            return NULL;
        }
    }

    ctx = VR_OCSP_sendreq_new(cbio, path, NULL, -1);
    if (ctx == NULL)
        return NULL;

    for (i = 0; i < sk_CONF_VALUE_num(headers); i++) {
        CONF_VALUE *hdr = sk_CONF_VALUE_value(headers, i);
        if (add_host == 1 && strcasecmp("host", hdr->name) == 0)
            add_host = 0;
        if (!VR_OCSP_REQ_CTX_add1_header(ctx, hdr->name, hdr->value))
            goto err;
    }

    if (add_host == 1 && VR_OCSP_REQ_CTX_add1_header(ctx, "Host", host) == 0)
        goto err;

    if (!VR_OCSP_REQ_CTX_set1_req(ctx, req))
        goto err;

    for (;;) {
        rv = VR_OCSP_sendreq_nbio(&rsp, ctx);
        if (rv != -1)
            break;
        if (req_timeout == -1)
            continue;
        FD_ZERO(&confds);
        openssl_fdset(fd, &confds);
        tv.tv_usec = 0;
        tv.tv_sec = req_timeout;
        if (BIO_should_read(cbio)) {
            rv = select(fd + 1, (void *)&confds, NULL, NULL, &tv);
        } else if (BIO_should_write(cbio)) {
            rv = select(fd + 1, NULL, (void *)&confds, NULL, &tv);
        } else {
            VR_BIO_puts(bio_err, "Unexpected retry condition\n");
            goto err;
        }
        if (rv == 0) {
            VR_BIO_puts(bio_err, "Timeout on request\n");
            break;
        }
        if (rv == -1) {
            VR_BIO_puts(bio_err, "Select error\n");
            break;
        }

    }
 err:
    VR_OCSP_REQ_CTX_free(ctx);

    return rsp;
}

OCSP_RESPONSE *process_responder(OCSP_REQUEST *req,
                                 const char *host, const char *path,
                                 const char *port, int use_ssl,
                                 STACK_OF(CONF_VALUE) *headers,
                                 int req_timeout)
{
    BIO *cbio = NULL;
    SSL_CTX *ctx = NULL;
    OCSP_RESPONSE *resp = NULL;

    cbio = VR_BIO_new_connect(host);
    if (cbio == NULL) {
        VR_BIO_printf(bio_err, "Error creating connect BIO\n");
        goto end;
    }
    if (port != NULL)
        BIO_set_conn_port(cbio, port);
    if (use_ssl == 1) {
        BIO *sbio;
        ctx = VR_SSL_CTX_new(VR_TLS_client_method());
        if (ctx == NULL) {
            VR_BIO_printf(bio_err, "Error creating SSL context.\n");
            goto end;
        }
        SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
        sbio = VR_BIO_new_ssl(ctx, 1);
        cbio = VR_BIO_push(sbio, cbio);
    }

    resp = query_responder(cbio, host, path, headers, req, req_timeout);
    if (resp == NULL)
        VR_BIO_printf(bio_err, "Error querying OCSP responder\n");
 end:
    VR_BIO_free_all(cbio);
    VR_SSL_CTX_free(ctx);
    return resp;
}
# endif

#endif
