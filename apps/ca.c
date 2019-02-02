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
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <openssl/conf.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/txt_db.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>

#ifndef W_OK
# ifdef OPENSSL_SYS_VMS
#  include <unistd.h>
# elif !defined(OPENSSL_SYS_VXWORKS) && !defined(OPENSSL_SYS_WINDOWS)
#  include <sys/file.h>
# endif
#endif

#include "apps.h"
#include "progs.h"

#ifndef W_OK
# define F_OK 0
# define W_OK 2
# define R_OK 4
#endif

#ifndef PATH_MAX
# define PATH_MAX 4096
#endif

#define BASE_SECTION            "ca"

#define ENV_DEFAULT_CA          "default_ca"

#define STRING_MASK             "string_mask"
#define UTF8_IN                 "utf8"

#define ENV_NEW_CERTS_DIR       "new_certs_dir"
#define ENV_CERTIFICATE         "certificate"
#define ENV_SERIAL              "serial"
#define ENV_RAND_SERIAL         "rand_serial"
#define ENV_CRLNUMBER           "crlnumber"
#define ENV_PRIVATE_KEY         "private_key"
#define ENV_DEFAULT_DAYS        "default_days"
#define ENV_DEFAULT_STARTDATE   "default_startdate"
#define ENV_DEFAULT_ENDDATE     "default_enddate"
#define ENV_DEFAULT_CRL_DAYS    "default_crl_days"
#define ENV_DEFAULT_CRL_HOURS   "default_crl_hours"
#define ENV_DEFAULT_MD          "default_md"
#define ENV_DEFAULT_EMAIL_DN    "email_in_dn"
#define ENV_PRESERVE            "preserve"
#define ENV_POLICY              "policy"
#define ENV_EXTENSIONS          "x509_extensions"
#define ENV_CRLEXT              "crl_extensions"
#define ENV_MSIE_HACK           "msie_hack"
#define ENV_NAMEOPT             "name_opt"
#define ENV_CERTOPT             "cert_opt"
#define ENV_EXTCOPY             "copy_extensions"
#define ENV_UNIQUE_SUBJECT      "unique_subject"

#define ENV_DATABASE            "database"

/* Additional revocation information types */
typedef enum {
    REV_VALID             = -1, /* Valid (not-revoked) status */
    REV_NONE              = 0, /* No additional information */
    REV_CRL_REASON        = 1, /* Value is CRL reason code */
    REV_HOLD              = 2, /* Value is hold instruction */
    REV_KEY_COMPROMISE    = 3, /* Value is cert key compromise time */
    REV_CA_COMPROMISE     = 4  /* Value is CA key compromise time */
} REVINFO_TYPE;

static char *lookup_conf(const CONF *conf, const char *group, const char *tag);

static int certify(X509 **xret, const char *infile, EVP_PKEY *pkey, X509 *x509,
                   const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
                   STACK_OF(CONF_VALUE) *policy, CA_DB *db,
                   BIGNUM *serial, const char *subj, unsigned long chtype,
                   int multirdn, int email_dn, const char *startdate,
                   const char *enddate,
                   long days, int batch, const char *ext_sect, CONF *conf,
                   int verbose, unsigned long certopt, unsigned long nameopt,
                   int default_op, int ext_copy, int selfsign);
static int certify_cert(X509 **xret, const char *infile, EVP_PKEY *pkey, X509 *x509,
                        const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
                        STACK_OF(CONF_VALUE) *policy, CA_DB *db,
                        BIGNUM *serial, const char *subj, unsigned long chtype,
                        int multirdn, int email_dn, const char *startdate,
                        const char *enddate, long days, int batch, const char *ext_sect,
                        CONF *conf, int verbose, unsigned long certopt,
                        unsigned long nameopt, int default_op, int ext_copy);
static int certify_spkac(X509 **xret, const char *infile, EVP_PKEY *pkey,
                         X509 *x509, const EVP_MD *dgst,
                         STACK_OF(OPENSSL_STRING) *sigopts,
                         STACK_OF(CONF_VALUE) *policy, CA_DB *db,
                         BIGNUM *serial, const char *subj, unsigned long chtype,
                         int multirdn, int email_dn, const char *startdate,
                         const char *enddate, long days, const char *ext_sect, CONF *conf,
                         int verbose, unsigned long certopt,
                         unsigned long nameopt, int default_op, int ext_copy);
static int do_body(X509 **xret, EVP_PKEY *pkey, X509 *x509,
                   const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
                   STACK_OF(CONF_VALUE) *policy, CA_DB *db, BIGNUM *serial,
                   const char *subj, unsigned long chtype, int multirdn,
                   int email_dn, const char *startdate, const char *enddate, long days,
                   int batch, int verbose, X509_REQ *req, const char *ext_sect,
                   CONF *conf, unsigned long certopt, unsigned long nameopt,
                   int default_op, int ext_copy, int selfsign);
static int get_certificate_status(const char *ser_status, CA_DB *db);
static int do_updatedb(CA_DB *db);
static int check_time_format(const char *str);
static int do_revoke(X509 *x509, CA_DB *db, REVINFO_TYPE rev_type,
                     const char *extval);
static char *make_revocation_str(REVINFO_TYPE rev_type, const char *rev_arg);
static int make_revoked(X509_REVOKED *rev, const char *str);
static int old_entry_print(const ASN1_OBJECT *obj, const ASN1_STRING *str);
static void write_new_certificate(BIO *bp, X509 *x, int output_der, int notext);

static CONF *extconf = NULL;
static int preserve = 0;
static int msie_hack = 0;

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_ENGINE, OPT_VERBOSE, OPT_CONFIG, OPT_NAME, OPT_SUBJ, OPT_UTF8,
    OPT_CREATE_SERIAL, OPT_MULTIVALUE_RDN, OPT_STARTDATE, OPT_ENDDATE,
    OPT_DAYS, OPT_MD, OPT_POLICY, OPT_KEYFILE, OPT_KEYFORM, OPT_PASSIN,
    OPT_KEY, OPT_CERT, OPT_SELFSIGN, OPT_IN, OPT_OUT, OPT_OUTDIR,
    OPT_SIGOPT, OPT_NOTEXT, OPT_BATCH, OPT_PRESERVEDN, OPT_NOEMAILDN,
    OPT_GENCRL, OPT_MSIE_HACK, OPT_CRLDAYS, OPT_CRLHOURS, OPT_CRLSEC,
    OPT_INFILES, OPT_SS_CERT, OPT_SPKAC, OPT_REVOKE, OPT_VALID,
    OPT_EXTENSIONS, OPT_EXTFILE, OPT_STATUS, OPT_UPDATEDB, OPT_CRLEXTS,
    OPT_RAND_SERIAL,
    OPT_R_ENUM,
    /* Do not change the order here; see related case statements below */
    OPT_CRL_REASON, OPT_CRL_HOLD, OPT_CRL_COMPROMISE, OPT_CRL_CA_COMPROMISE
} OPTION_CHOICE;

const OPTIONS ca_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"verbose", OPT_VERBOSE, '-', "Verbose output during processing"},
    {"config", OPT_CONFIG, 's', "A config file"},
    {"name", OPT_NAME, 's', "The particular CA definition to use"},
    {"subj", OPT_SUBJ, 's', "Use arg instead of request's subject"},
    {"utf8", OPT_UTF8, '-', "Input characters are UTF8 (default ASCII)"},
    {"create_serial", OPT_CREATE_SERIAL, '-',
     "If reading serial fails, create a new random serial"},
    {"rand_serial", OPT_RAND_SERIAL, '-',
     "Always create a random serial; do not store it"},
    {"multivalue-rdn", OPT_MULTIVALUE_RDN, '-',
     "Enable support for multivalued RDNs"},
    {"startdate", OPT_STARTDATE, 's', "Cert notBefore, YYMMDDHHMMSSZ"},
    {"enddate", OPT_ENDDATE, 's',
     "YYMMDDHHMMSSZ cert notAfter (overrides -days)"},
    {"days", OPT_DAYS, 'p', "Number of days to certify the cert for"},
    {"md", OPT_MD, 's', "md to use; one of md2, md5, sha or sha1"},
    {"policy", OPT_POLICY, 's', "The CA 'policy' to support"},
    {"keyfile", OPT_KEYFILE, 's', "Private key"},
    {"keyform", OPT_KEYFORM, 'f', "Private key file format (PEM or ENGINE)"},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    {"key", OPT_KEY, 's', "Key to decode the private key if it is encrypted"},
    {"cert", OPT_CERT, '<', "The CA cert"},
    {"selfsign", OPT_SELFSIGN, '-',
     "Sign a cert with the key associated with it"},
    {"in", OPT_IN, '<', "The input PEM encoded cert request(s)"},
    {"out", OPT_OUT, '>', "Where to put the output file(s)"},
    {"outdir", OPT_OUTDIR, '/', "Where to put output cert"},
    {"sigopt", OPT_SIGOPT, 's', "Signature parameter in n:v form"},
    {"notext", OPT_NOTEXT, '-', "Do not print the generated certificate"},
    {"batch", OPT_BATCH, '-', "Don't ask questions"},
    {"preserveDN", OPT_PRESERVEDN, '-', "Don't re-order the DN"},
    {"noemailDN", OPT_NOEMAILDN, '-', "Don't add the EMAIL field to the DN"},
    {"gencrl", OPT_GENCRL, '-', "Generate a new CRL"},
    {"msie_hack", OPT_MSIE_HACK, '-',
     "msie modifications to handle all those universal strings"},
    {"crldays", OPT_CRLDAYS, 'p', "Days until the next CRL is due"},
    {"crlhours", OPT_CRLHOURS, 'p', "Hours until the next CRL is due"},
    {"crlsec", OPT_CRLSEC, 'p', "Seconds until the next CRL is due"},
    {"infiles", OPT_INFILES, '-', "The last argument, requests to process"},
    {"ss_cert", OPT_SS_CERT, '<', "File contains a self signed cert to sign"},
    {"spkac", OPT_SPKAC, '<',
     "File contains DN and signed public key and challenge"},
    {"revoke", OPT_REVOKE, '<', "Revoke a cert (given in file)"},
    {"valid", OPT_VALID, 's',
     "Add a Valid(not-revoked) DB entry about a cert (given in file)"},
    {"extensions", OPT_EXTENSIONS, 's',
     "Extension section (override value in config file)"},
    {"extfile", OPT_EXTFILE, '<',
     "Configuration file with X509v3 extensions to add"},
    {"status", OPT_STATUS, 's', "Shows cert status given the serial number"},
    {"updatedb", OPT_UPDATEDB, '-', "Updates db for expired cert"},
    {"crlexts", OPT_CRLEXTS, 's',
     "CRL extension section (override value in config file)"},
    {"crl_reason", OPT_CRL_REASON, 's', "revocation reason"},
    {"crl_hold", OPT_CRL_HOLD, 's',
     "the hold instruction, an OID. Sets revocation reason to certificateHold"},
    {"crl_compromise", OPT_CRL_COMPROMISE, 's',
     "sets compromise time to val and the revocation reason to keyCompromise"},
    {"crl_CA_compromise", OPT_CRL_CA_COMPROMISE, 's',
     "sets compromise time to val and the revocation reason to CACompromise"},
    OPT_R_OPTIONS,
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {NULL}
};

int ca_main(int argc, char **argv)
{
    CONF *conf = NULL;
    ENGINE *e = NULL;
    BIGNUM *crlnumber = NULL, *serial = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *in = NULL, *out = NULL, *Sout = NULL;
    ASN1_INTEGER *tmpser;
    ASN1_TIME *tmptm;
    CA_DB *db = NULL;
    DB_ATTR db_attr;
    STACK_OF(CONF_VALUE) *attribs = NULL;
    STACK_OF(OPENSSL_STRING) *sigopts = NULL;
    STACK_OF(X509) *cert_sk = NULL;
    X509_CRL *crl = NULL;
    const EVP_MD *dgst = NULL;
    char *configfile = default_config_file, *section = NULL;
    char *md = NULL, *policy = NULL, *keyfile = NULL;
    char *certfile = NULL, *crl_ext = NULL, *crlnumberfile = NULL, *key = NULL;
    const char *infile = NULL, *spkac_file = NULL, *ss_cert_file = NULL;
    const char *extensions = NULL, *extfile = NULL, *passinarg = NULL;
    char *outdir = NULL, *outfile = NULL, *rev_arg = NULL, *ser_status = NULL;
    const char *serialfile = NULL, *subj = NULL;
    char *prog, *startdate = NULL, *enddate = NULL;
    char *dbfile = NULL, *f;
    char new_cert[PATH_MAX];
    char tmp[10 + 1] = "\0";
    char *const *pp;
    const char *p;
    size_t outdirlen = 0;
    int create_ser = 0, free_key = 0, total = 0, total_done = 0;
    int batch = 0, default_op = 1, doupdatedb = 0, ext_copy = EXT_COPY_NONE;
    int keyformat = FORMAT_PEM, multirdn = 0, notext = 0, output_der = 0;
    int ret = 1, email_dn = 1, req = 0, verbose = 0, gencrl = 0, dorevoke = 0;
    int rand_ser = 0, i, j, selfsign = 0, def_nid, def_ret;
    long crldays = 0, crlhours = 0, crlsec = 0, days = 0;
    unsigned long chtype = MBSTRING_ASC, certopt = 0;
    X509 *x509 = NULL, *x509p = NULL, *x = NULL;
    REVINFO_TYPE rev_type = REV_NONE;
    X509_REVOKED *r = NULL;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, ca_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
opthelp:
            VR_BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(ca_options);
            ret = 0;
            goto end;
        case OPT_IN:
            req = 1;
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_VERBOSE:
            verbose = 1;
            break;
        case OPT_CONFIG:
            configfile = opt_arg();
            break;
        case OPT_NAME:
            section = opt_arg();
            break;
        case OPT_SUBJ:
            subj = opt_arg();
            /* preserve=1; */
            break;
        case OPT_UTF8:
            chtype = MBSTRING_UTF8;
            break;
        case OPT_RAND_SERIAL:
            rand_ser = 1;
            break;
        case OPT_CREATE_SERIAL:
            create_ser = 1;
            break;
        case OPT_MULTIVALUE_RDN:
            multirdn = 1;
            break;
        case OPT_STARTDATE:
            startdate = opt_arg();
            break;
        case OPT_ENDDATE:
            enddate = opt_arg();
            break;
        case OPT_DAYS:
            days = atoi(opt_arg());
            break;
        case OPT_MD:
            md = opt_arg();
            break;
        case OPT_POLICY:
            policy = opt_arg();
            break;
        case OPT_KEYFILE:
            keyfile = opt_arg();
            break;
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &keyformat))
                goto opthelp;
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_R_CASES:
            if (!opt_rand(o))
                goto end;
            break;
        case OPT_KEY:
            key = opt_arg();
            break;
        case OPT_CERT:
            certfile = opt_arg();
            break;
        case OPT_SELFSIGN:
            selfsign = 1;
            break;
        case OPT_OUTDIR:
            outdir = opt_arg();
            break;
        case OPT_SIGOPT:
            if (sigopts == NULL)
                sigopts = sk_VR_OPENSSL_STRING_new_null();
            if (sigopts == NULL || !sk_VR_OPENSSL_STRING_push(sigopts, opt_arg()))
                goto end;
            break;
        case OPT_NOTEXT:
            notext = 1;
            break;
        case OPT_BATCH:
            batch = 1;
            break;
        case OPT_PRESERVEDN:
            preserve = 1;
            break;
        case OPT_NOEMAILDN:
            email_dn = 0;
            break;
        case OPT_GENCRL:
            gencrl = 1;
            break;
        case OPT_MSIE_HACK:
            msie_hack = 1;
            break;
        case OPT_CRLDAYS:
            crldays = atol(opt_arg());
            break;
        case OPT_CRLHOURS:
            crlhours = atol(opt_arg());
            break;
        case OPT_CRLSEC:
            crlsec = atol(opt_arg());
            break;
        case OPT_INFILES:
            req = 1;
            goto end_of_options;
        case OPT_SS_CERT:
            ss_cert_file = opt_arg();
            req = 1;
            break;
        case OPT_SPKAC:
            spkac_file = opt_arg();
            req = 1;
            break;
        case OPT_REVOKE:
            infile = opt_arg();
            dorevoke = 1;
            break;
        case OPT_VALID:
            infile = opt_arg();
            dorevoke = 2;
            break;
        case OPT_EXTENSIONS:
            extensions = opt_arg();
            break;
        case OPT_EXTFILE:
            extfile = opt_arg();
            break;
        case OPT_STATUS:
            ser_status = opt_arg();
            break;
        case OPT_UPDATEDB:
            doupdatedb = 1;
            break;
        case OPT_CRLEXTS:
            crl_ext = opt_arg();
            break;
        case OPT_CRL_REASON:   /* := REV_CRL_REASON */
        case OPT_CRL_HOLD:
        case OPT_CRL_COMPROMISE:
        case OPT_CRL_CA_COMPROMISE:
            rev_arg = opt_arg();
            rev_type = (o - OPT_CRL_REASON) + REV_CRL_REASON;
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        }
    }
end_of_options:
    argc = opt_num_rest();
    argv = opt_rest();

    VR_BIO_printf(bio_err, "Using configuration from %s\n", configfile);

    if ((conf = app_load_config(configfile)) == NULL)
        goto end;
    if (configfile != default_config_file && !app_load_modules(conf))
        goto end;

    /* Lets get the config section we are using */
    if (section == NULL
        && (section = lookup_conf(conf, BASE_SECTION, ENV_DEFAULT_CA)) == NULL)
        goto end;

    p = VR_NCONF_get_string(conf, NULL, "oid_file");
    if (p == NULL)
        VR_ERR_clear_error();
    if (p != NULL) {
        BIO *oid_bio = VR_BIO_new_file(p, "r");

        if (oid_bio == NULL) {
            VR_ERR_clear_error();
        } else {
            VR_OBJ_create_objects(oid_bio);
            VR_BIO_free(oid_bio);
        }
    }
    if (!add_oid_section(conf)) {
        VR_ERR_print_errors(bio_err);
        goto end;
    }

    app_RAND_load_conf(conf, BASE_SECTION);

    f = VR_NCONF_get_string(conf, section, STRING_MASK);
    if (f == NULL)
        VR_ERR_clear_error();

    if (f != NULL && !VR_ASN1_STRING_set_default_mask_asc(f)) {
        VR_BIO_printf(bio_err, "Invalid global string mask setting %s\n", f);
        goto end;
    }

    if (chtype != MBSTRING_UTF8) {
        f = VR_NCONF_get_string(conf, section, UTF8_IN);
        if (f == NULL)
            VR_ERR_clear_error();
        else if (strcmp(f, "yes") == 0)
            chtype = MBSTRING_UTF8;
    }

    db_attr.unique_subject = 1;
    p = VR_NCONF_get_string(conf, section, ENV_UNIQUE_SUBJECT);
    if (p != NULL)
        db_attr.unique_subject = parse_yesno(p, 1);
    else
        VR_ERR_clear_error();

    /*****************************************************************/
    /* report status of cert with serial number given on command line */
    if (ser_status) {
        dbfile = lookup_conf(conf, section, ENV_DATABASE);
        if (dbfile == NULL)
            goto end;

        db = load_index(dbfile, &db_attr);
        if (db == NULL)
            goto end;

        if (index_index(db) <= 0)
            goto end;

        if (get_certificate_status(ser_status, db) != 1)
            VR_BIO_printf(bio_err, "Error verifying serial %s!\n", ser_status);
        goto end;
    }

    /*****************************************************************/
    /* we definitely need a private key, so let's get it */

    if (keyfile == NULL
        && (keyfile = lookup_conf(conf, section, ENV_PRIVATE_KEY)) == NULL)
        goto end;

    if (key == NULL) {
        free_key = 1;
        if (!app_passwd(passinarg, NULL, &key, NULL)) {
            VR_BIO_printf(bio_err, "Error getting password\n");
            goto end;
        }
    }
    pkey = load_key(keyfile, keyformat, 0, key, e, "CA private key");
    if (key != NULL)
        VR_OPENSSL_cleanse(key, strlen(key));
    if (pkey == NULL)
        /* load_key() has already printed an appropriate message */
        goto end;

    /*****************************************************************/
    /* we need a certificate */
    if (!selfsign || spkac_file || ss_cert_file || gencrl) {
        if (certfile == NULL
            && (certfile = lookup_conf(conf, section, ENV_CERTIFICATE)) == NULL)
            goto end;

        x509 = load_cert(certfile, FORMAT_PEM, "CA certificate");
        if (x509 == NULL)
            goto end;

        if (!VR_X509_check_private_key(x509, pkey)) {
            VR_BIO_printf(bio_err,
                       "CA certificate and CA private key do not match\n");
            goto end;
        }
    }
    if (!selfsign)
        x509p = x509;

    f = VR_NCONF_get_string(conf, BASE_SECTION, ENV_PRESERVE);
    if (f == NULL)
        VR_ERR_clear_error();
    if ((f != NULL) && ((*f == 'y') || (*f == 'Y')))
        preserve = 1;
    f = VR_NCONF_get_string(conf, BASE_SECTION, ENV_MSIE_HACK);
    if (f == NULL)
        VR_ERR_clear_error();
    if ((f != NULL) && ((*f == 'y') || (*f == 'Y')))
        msie_hack = 1;

    f = VR_NCONF_get_string(conf, section, ENV_NAMEOPT);

    if (f != NULL) {
        if (!set_nameopt(f)) {
            VR_BIO_printf(bio_err, "Invalid name options: \"%s\"\n", f);
            goto end;
        }
        default_op = 0;
    }

    f = VR_NCONF_get_string(conf, section, ENV_CERTOPT);

    if (f != NULL) {
        if (!set_cert_ex(&certopt, f)) {
            VR_BIO_printf(bio_err, "Invalid certificate options: \"%s\"\n", f);
            goto end;
        }
        default_op = 0;
    } else {
        VR_ERR_clear_error();
    }

    f = VR_NCONF_get_string(conf, section, ENV_EXTCOPY);

    if (f != NULL) {
        if (!set_ext_copy(&ext_copy, f)) {
            VR_BIO_printf(bio_err, "Invalid extension copy option: \"%s\"\n", f);
            goto end;
        }
    } else {
        VR_ERR_clear_error();
    }

    /*****************************************************************/
    /* lookup where to write new certificates */
    if ((outdir == NULL) && (req)) {

        outdir = VR_NCONF_get_string(conf, section, ENV_NEW_CERTS_DIR);
        if (outdir == NULL) {
            VR_BIO_printf(bio_err,
                       "there needs to be defined a directory for new certificate to be placed in\n");
            goto end;
        }
#ifndef OPENSSL_SYS_VMS
        /*
         * outdir is a directory spec, but access() for VMS demands a
         * filename.  We could use the DEC C routine to convert the
         * directory syntax to Unix, and give that to app_isdir,
         * but for now the fopen will catch the error if it's not a
         * directory
         */
        if (app_isdir(outdir) <= 0) {
            VR_BIO_printf(bio_err, "%s: %s is not a directory\n", prog, outdir);
            perror(outdir);
            goto end;
        }
#endif
    }

    /*****************************************************************/
    /* we need to load the database file */
    dbfile = lookup_conf(conf, section, ENV_DATABASE);
    if (dbfile == NULL)
        goto end;

    db = load_index(dbfile, &db_attr);
    if (db == NULL)
        goto end;

    /* Lets check some fields */
    for (i = 0; i < sk_OPENSSL_PSTRING_num(db->db->data); i++) {
        pp = sk_OPENSSL_PSTRING_value(db->db->data, i);
        if ((pp[DB_type][0] != DB_TYPE_REV) && (pp[DB_rev_date][0] != '\0')) {
            VR_BIO_printf(bio_err,
                       "entry %d: not revoked yet, but has a revocation date\n",
                       i + 1);
            goto end;
        }
        if ((pp[DB_type][0] == DB_TYPE_REV) &&
            !make_revoked(NULL, pp[DB_rev_date])) {
            VR_BIO_printf(bio_err, " in entry %d\n", i + 1);
            goto end;
        }
        if (!check_time_format((char *)pp[DB_exp_date])) {
            VR_BIO_printf(bio_err, "entry %d: invalid expiry date\n", i + 1);
            goto end;
        }
        p = pp[DB_serial];
        j = strlen(p);
        if (*p == '-') {
            p++;
            j--;
        }
        if ((j & 1) || (j < 2)) {
            VR_BIO_printf(bio_err, "entry %d: bad serial number length (%d)\n",
                       i + 1, j);
            goto end;
        }
        for ( ; *p; p++) {
            if (!isxdigit(_UC(*p))) {
                VR_BIO_printf(bio_err,
                           "entry %d: bad char 0%o '%c' in serial number\n",
                           i + 1, *p, *p);
                goto end;
            }
        }
    }
    if (verbose) {
        VR_TXT_DB_write(bio_out, db->db);
        VR_BIO_printf(bio_err, "%d entries loaded from the database\n",
                   sk_OPENSSL_PSTRING_num(db->db->data));
        VR_BIO_printf(bio_err, "generating index\n");
    }

    if (index_index(db) <= 0)
        goto end;

    /*****************************************************************/
    /* Update the db file for expired certificates */
    if (doupdatedb) {
        if (verbose)
            VR_BIO_printf(bio_err, "Updating %s ...\n", dbfile);

        i = do_updatedb(db);
        if (i == -1) {
            VR_BIO_printf(bio_err, "Malloc failure\n");
            goto end;
        } else if (i == 0) {
            if (verbose)
                VR_BIO_printf(bio_err, "No entries found to mark expired\n");
        } else {
            if (!save_index(dbfile, "new", db))
                goto end;

            if (!rotate_index(dbfile, "new", "old"))
                goto end;

            if (verbose)
                VR_BIO_printf(bio_err, "Done. %d entries marked as expired\n", i);
        }
    }

    /*****************************************************************/
    /* Read extensions config file                                   */
    if (extfile) {
        if ((extconf = app_load_config(extfile)) == NULL) {
            ret = 1;
            goto end;
        }

        if (verbose)
            VR_BIO_printf(bio_err, "Successfully loaded extensions file %s\n",
                       extfile);

        /* We can have sections in the ext file */
        if (extensions == NULL) {
            extensions = VR_NCONF_get_string(extconf, "default", "extensions");
            if (extensions == NULL)
                extensions = "default";
        }
    }

    /*****************************************************************/
    if (req || gencrl) {
        if (spkac_file != NULL) {
            output_der = 1;
            batch = 1;
        }
    }

    def_ret = VR_EVP_PKEY_get_default_digest_nid(pkey, &def_nid);
    /*
     * VR_EVP_PKEY_get_default_digest_nid() returns 2 if the digest is
     * mandatory for this algorithm.
     */
    if (def_ret == 2 && def_nid == NID_undef) {
        /* The signing algorithm requires there to be no digest */
        dgst = VR_EVP_md_null();
    } else if (md == NULL
               && (md = lookup_conf(conf, section, ENV_DEFAULT_MD)) == NULL) {
        goto end;
    } else {
        if (strcmp(md, "default") == 0) {
            if (def_ret <= 0) {
                VR_BIO_puts(bio_err, "no default digest\n");
                goto end;
            }
            md = (char *)VR_OBJ_nid2sn(def_nid);
        }

        if (!opt_md(md, &dgst))
            goto end;
    }

    if (req) {
        if (email_dn == 1) {
            char *tmp_email_dn = NULL;

            tmp_email_dn = VR_NCONF_get_string(conf, section, ENV_DEFAULT_EMAIL_DN);
            if (tmp_email_dn != NULL && strcmp(tmp_email_dn, "no") == 0)
                email_dn = 0;
        }
        if (verbose)
            VR_BIO_printf(bio_err, "message digest is %s\n",
                       VR_OBJ_nid2ln(VR_EVP_MD_type(dgst)));
        if (policy == NULL
            && (policy = lookup_conf(conf, section, ENV_POLICY)) == NULL)
            goto end;

        if (verbose)
            VR_BIO_printf(bio_err, "policy is %s\n", policy);

        if (VR_NCONF_get_string(conf, section, ENV_RAND_SERIAL) != NULL) {
            rand_ser = 1;
        } else {
            serialfile = lookup_conf(conf, section, ENV_SERIAL);
            if (serialfile == NULL)
                goto end;
        }

        if (extconf == NULL) {
            /*
             * no '-extfile' option, so we look for extensions in the main
             * configuration file
             */
            if (extensions == NULL) {
                extensions = VR_NCONF_get_string(conf, section, ENV_EXTENSIONS);
                if (extensions == NULL)
                    VR_ERR_clear_error();
            }
            if (extensions != NULL) {
                /* Check syntax of file */
                X509V3_CTX ctx;
                VR_X509V3_set_ctx_test(&ctx);
                VR_X509V3_set_nconf(&ctx, conf);
                if (!VR_X509V3_EXT_add_nconf(conf, &ctx, extensions, NULL)) {
                    VR_BIO_printf(bio_err,
                               "Error Loading extension section %s\n",
                               extensions);
                    ret = 1;
                    goto end;
                }
            }
        }

        if (startdate == NULL) {
            startdate = VR_NCONF_get_string(conf, section, ENV_DEFAULT_STARTDATE);
            if (startdate == NULL)
                VR_ERR_clear_error();
        }
        if (startdate != NULL && !VR_ASN1_TIME_set_string_X509(NULL, startdate)) {
            VR_BIO_printf(bio_err,
                       "start date is invalid, it should be YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ\n");
            goto end;
        }
        if (startdate == NULL)
            startdate = "today";

        if (enddate == NULL) {
            enddate = VR_NCONF_get_string(conf, section, ENV_DEFAULT_ENDDATE);
            if (enddate == NULL)
                VR_ERR_clear_error();
        }
        if (enddate != NULL && !VR_ASN1_TIME_set_string_X509(NULL, enddate)) {
            VR_BIO_printf(bio_err,
                       "end date is invalid, it should be YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ\n");
            goto end;
        }

        if (days == 0) {
            if (!NVR_CONF_get_number(conf, section, ENV_DEFAULT_DAYS, &days))
                days = 0;
        }
        if (enddate == NULL && days == 0) {
            VR_BIO_printf(bio_err, "cannot lookup how many days to certify for\n");
            goto end;
        }

        if (rand_ser) {
            if ((serial = VR_BN_new()) == NULL || !rand_serial(serial, NULL)) {
                VR_BIO_printf(bio_err, "error generating serial number\n");
                goto end;
            }
        } else {
            if ((serial = load_serial(serialfile, create_ser, NULL)) == NULL) {
                VR_BIO_printf(bio_err, "error while loading serial number\n");
                goto end;
            }
            if (verbose) {
                if (VR_BN_is_zero(serial)) {
                    VR_BIO_printf(bio_err, "next serial number is 00\n");
                } else {
                    if ((f = VR_BN_bn2hex(serial)) == NULL)
                        goto end;
                    VR_BIO_printf(bio_err, "next serial number is %s\n", f);
                    OPENVR_SSL_free(f);
                }
            }
        }

        if ((attribs = VR_NCONF_get_section(conf, policy)) == NULL) {
            VR_BIO_printf(bio_err, "unable to find 'section' for %s\n", policy);
            goto end;
        }

        if ((cert_sk = sk_VR_X509_new_null()) == NULL) {
            VR_BIO_printf(bio_err, "Memory allocation failure\n");
            goto end;
        }
        if (spkac_file != NULL) {
            total++;
            j = certify_spkac(&x, spkac_file, pkey, x509, dgst, sigopts,
                              attribs, db, serial, subj, chtype, multirdn,
                              email_dn, startdate, enddate, days, extensions,
                              conf, verbose, certopt, get_nameopt(), default_op,
                              ext_copy);
            if (j < 0)
                goto end;
            if (j > 0) {
                total_done++;
                VR_BIO_printf(bio_err, "\n");
                if (!VR_BN_add_word(serial, 1))
                    goto end;
                if (!sk_VR_X509_push(cert_sk, x)) {
                    VR_BIO_printf(bio_err, "Memory allocation failure\n");
                    goto end;
                }
            }
        }
        if (ss_cert_file != NULL) {
            total++;
            j = certify_cert(&x, ss_cert_file, pkey, x509, dgst, sigopts,
                             attribs,
                             db, serial, subj, chtype, multirdn, email_dn,
                             startdate, enddate, days, batch, extensions,
                             conf, verbose, certopt, get_nameopt(), default_op,
                             ext_copy);
            if (j < 0)
                goto end;
            if (j > 0) {
                total_done++;
                VR_BIO_printf(bio_err, "\n");
                if (!VR_BN_add_word(serial, 1))
                    goto end;
                if (!sk_VR_X509_push(cert_sk, x)) {
                    VR_BIO_printf(bio_err, "Memory allocation failure\n");
                    goto end;
                }
            }
        }
        if (infile != NULL) {
            total++;
            j = certify(&x, infile, pkey, x509p, dgst, sigopts, attribs, db,
                        serial, subj, chtype, multirdn, email_dn, startdate,
                        enddate, days, batch, extensions, conf, verbose,
                        certopt, get_nameopt(), default_op, ext_copy, selfsign);
            if (j < 0)
                goto end;
            if (j > 0) {
                total_done++;
                VR_BIO_printf(bio_err, "\n");
                if (!VR_BN_add_word(serial, 1))
                    goto end;
                if (!sk_VR_X509_push(cert_sk, x)) {
                    VR_BIO_printf(bio_err, "Memory allocation failure\n");
                    goto end;
                }
            }
        }
        for (i = 0; i < argc; i++) {
            total++;
            j = certify(&x, argv[i], pkey, x509p, dgst, sigopts, attribs, db,
                        serial, subj, chtype, multirdn, email_dn, startdate,
                        enddate, days, batch, extensions, conf, verbose,
                        certopt, get_nameopt(), default_op, ext_copy, selfsign);
            if (j < 0)
                goto end;
            if (j > 0) {
                total_done++;
                VR_BIO_printf(bio_err, "\n");
                if (!VR_BN_add_word(serial, 1)) {
                    VR_X509_free(x);
                    goto end;
                }
                if (!sk_VR_X509_push(cert_sk, x)) {
                    VR_BIO_printf(bio_err, "Memory allocation failure\n");
                    VR_X509_free(x);
                    goto end;
                }
            }
        }
        /*
         * we have a stack of newly certified certificates and a data base
         * and serial number that need updating
         */

        if (sk_X509_num(cert_sk) > 0) {
            if (!batch) {
                VR_BIO_printf(bio_err,
                           "\n%d out of %d certificate requests certified, commit? [y/n]",
                           total_done, total);
                (void)BIO_flush(bio_err);
                tmp[0] = '\0';
                if (fgets(tmp, sizeof(tmp), stdin) == NULL) {
                    VR_BIO_printf(bio_err, "CERTIFICATION CANCELED: I/O error\n");
                    ret = 0;
                    goto end;
                }
                if (tmp[0] != 'y' && tmp[0] != 'Y') {
                    VR_BIO_printf(bio_err, "CERTIFICATION CANCELED\n");
                    ret = 0;
                    goto end;
                }
            }

            VR_BIO_printf(bio_err, "Write out database with %d new entries\n",
                       sk_X509_num(cert_sk));

            if (serialfile != NULL
                    && !save_serial(serialfile, "new", serial, NULL))
                goto end;

            if (!save_index(dbfile, "new", db))
                goto end;
        }

        outdirlen = VR_OPENSSL_strlcpy(new_cert, outdir, sizeof(new_cert));
#ifndef OPENSSL_SYS_VMS
        outdirlen = VR_OPENSSL_strlcat(new_cert, "/", sizeof(new_cert));
#endif

        if (verbose)
            VR_BIO_printf(bio_err, "writing new certificates\n");

        for (i = 0; i < sk_X509_num(cert_sk); i++) {
            BIO *Cout = NULL;
            X509 *xi = sk_X509_value(cert_sk, i);
            ASN1_INTEGER *serialNumber = VR_X509_get_serialNumber(xi);
            const unsigned char *psn = VR_ASN1_STRING_get0_data(serialNumber);
            const int snl = VR_ASN1_STRING_length(serialNumber);
            const int filen_len = 2 * (snl > 0 ? snl : 1) + sizeof(".pem");
            char *n = new_cert + outdirlen;

            if (outdirlen + filen_len > PATH_MAX) {
                VR_BIO_printf(bio_err, "certificate file name too long\n");
                goto end;
            }

            if (snl > 0) {
                static const char HEX_DIGITS[] = "0123456789ABCDEF";

                for (j = 0; j < snl; j++, psn++) {
                    *n++ = HEX_DIGITS[*psn >> 4];
                    *n++ = HEX_DIGITS[*psn & 0x0F];
                }
            } else {
                *(n++) = '0';
                *(n++) = '0';
            }
            *(n++) = '.';
            *(n++) = 'p';
            *(n++) = 'e';
            *(n++) = 'm';
            *n = '\0';          /* closing new_cert */
            if (verbose)
                VR_BIO_printf(bio_err, "writing %s\n", new_cert);

            Sout = bio_open_default(outfile, 'w',
                                    output_der ? FORMAT_ASN1 : FORMAT_TEXT);
            if (Sout == NULL)
                goto end;

            Cout = VR_BIO_new_file(new_cert, "w");
            if (Cout == NULL) {
                perror(new_cert);
                goto end;
            }
            write_new_certificate(Cout, xi, 0, notext);
            write_new_certificate(Sout, xi, output_der, notext);
            VR_BIO_free_all(Cout);
            VR_BIO_free_all(Sout);
            Sout = NULL;
        }

        if (sk_X509_num(cert_sk)) {
            /* Rename the database and the serial file */
            if (serialfile != NULL
                    && !rotate_serial(serialfile, "new", "old"))
                goto end;

            if (!rotate_index(dbfile, "new", "old"))
                goto end;

            VR_BIO_printf(bio_err, "Data Base Updated\n");
        }
    }

    /*****************************************************************/
    if (gencrl) {
        int crl_v2 = 0;
        if (crl_ext == NULL) {
            crl_ext = VR_NCONF_get_string(conf, section, ENV_CRLEXT);
            if (crl_ext == NULL)
                VR_ERR_clear_error();
        }
        if (crl_ext != NULL) {
            /* Check syntax of file */
            X509V3_CTX ctx;
            VR_X509V3_set_ctx_test(&ctx);
            VR_X509V3_set_nconf(&ctx, conf);
            if (!VR_X509V3_EXT_add_nconf(conf, &ctx, crl_ext, NULL)) {
                VR_BIO_printf(bio_err,
                           "Error Loading CRL extension section %s\n", crl_ext);
                ret = 1;
                goto end;
            }
        }

        if ((crlnumberfile = VR_NCONF_get_string(conf, section, ENV_CRLNUMBER))
            != NULL)
            if ((crlnumber = load_serial(crlnumberfile, 0, NULL)) == NULL) {
                VR_BIO_printf(bio_err, "error while loading CRL number\n");
                goto end;
            }

        if (!crldays && !crlhours && !crlsec) {
            if (!NVR_CONF_get_number(conf, section,
                                  ENV_DEFAULT_CRL_DAYS, &crldays))
                crldays = 0;
            if (!NVR_CONF_get_number(conf, section,
                                  ENV_DEFAULT_CRL_HOURS, &crlhours))
                crlhours = 0;
            VR_ERR_clear_error();
        }
        if ((crldays == 0) && (crlhours == 0) && (crlsec == 0)) {
            VR_BIO_printf(bio_err,
                       "cannot lookup how long until the next CRL is issued\n");
            goto end;
        }

        if (verbose)
            VR_BIO_printf(bio_err, "making CRL\n");
        if ((crl = VR_X509_CRL_new()) == NULL)
            goto end;
        if (!VR_X509_CRL_set_issuer_name(crl, VR_X509_get_subject_name(x509)))
            goto end;

        tmptm = VR_ASN1_TIME_new();
        if (tmptm == NULL
                || VR_X509_gmtime_adj(tmptm, 0) == NULL
                || !VR_X509_CRL_set1_lastUpdate(crl, tmptm)
                || VR_X509_time_adj_ex(tmptm, crldays, crlhours * 60 * 60 + crlsec,
                                    NULL) == NULL) {
            VR_BIO_puts(bio_err, "error setting CRL nextUpdate\n");
            VR_ASN1_TIME_free(tmptm);
            goto end;
        }
        VR_X509_CRL_set1_nextUpdate(crl, tmptm);

        VR_ASN1_TIME_free(tmptm);

        for (i = 0; i < sk_OPENSSL_PSTRING_num(db->db->data); i++) {
            pp = sk_OPENSSL_PSTRING_value(db->db->data, i);
            if (pp[DB_type][0] == DB_TYPE_REV) {
                if ((r = VR_X509_REVOKED_new()) == NULL)
                    goto end;
                j = make_revoked(r, pp[DB_rev_date]);
                if (!j)
                    goto end;
                if (j == 2)
                    crl_v2 = 1;
                if (!VR_BN_hex2bn(&serial, pp[DB_serial]))
                    goto end;
                tmpser = VR_BN_to_ASN1_INTEGER(serial, NULL);
                VR_BN_free(serial);
                serial = NULL;
                if (!tmpser)
                    goto end;
                VR_X509_REVOKED_set_serialNumber(r, tmpser);
                VR_ASN1_INTEGER_free(tmpser);
                VR_X509_CRL_add0_revoked(crl, r);
            }
        }

        /*
         * sort the data so it will be written in serial number order
         */
        VR_X509_CRL_sort(crl);

        /* we now have a CRL */
        if (verbose)
            VR_BIO_printf(bio_err, "signing CRL\n");

        /* Add any extensions asked for */

        if (crl_ext != NULL || crlnumberfile != NULL) {
            X509V3_CTX crlctx;
            VR_X509V3_set_ctx(&crlctx, x509, NULL, NULL, crl, 0);
            VR_X509V3_set_nconf(&crlctx, conf);

            if (crl_ext != NULL)
                if (!VR_X509V3_EXT_CRL_add_nconf(conf, &crlctx, crl_ext, crl))
                    goto end;
            if (crlnumberfile != NULL) {
                tmpser = VR_BN_to_ASN1_INTEGER(crlnumber, NULL);
                if (!tmpser)
                    goto end;
                VR_X509_CRL_add1_ext_i2d(crl, NID_crl_number, tmpser, 0, 0);
                VR_ASN1_INTEGER_free(tmpser);
                crl_v2 = 1;
                if (!VR_BN_add_word(crlnumber, 1))
                    goto end;
            }
        }
        if (crl_ext != NULL || crl_v2) {
            if (!VR_X509_CRL_set_version(crl, 1))
                goto end;       /* version 2 CRL */
        }

        /* we have a CRL number that need updating */
        if (crlnumberfile != NULL
                && !save_serial(crlnumberfile, "new", crlnumber, NULL))
            goto end;

        VR_BN_free(crlnumber);
        crlnumber = NULL;

        if (!do_VR_X509_CRL_sign(crl, pkey, dgst, sigopts))
            goto end;

        Sout = bio_open_default(outfile, 'w',
                                output_der ? FORMAT_ASN1 : FORMAT_TEXT);
        if (Sout == NULL)
            goto end;

        VR_PEM_write_bio_X509_CRL(Sout, crl);

        /* Rename the crlnumber file */
        if (crlnumberfile != NULL
                && !rotate_serial(crlnumberfile, "new", "old"))
            goto end;

    }
    /*****************************************************************/
    if (dorevoke) {
        if (infile == NULL) {
            VR_BIO_printf(bio_err, "no input files\n");
            goto end;
        } else {
            X509 *revcert;
            revcert = load_cert(infile, FORMAT_PEM, infile);
            if (revcert == NULL)
                goto end;
            if (dorevoke == 2)
                rev_type = REV_VALID;
            j = do_revoke(revcert, db, rev_type, rev_arg);
            if (j <= 0)
                goto end;
            VR_X509_free(revcert);

            if (!save_index(dbfile, "new", db))
                goto end;

            if (!rotate_index(dbfile, "new", "old"))
                goto end;

            VR_BIO_printf(bio_err, "Data Base Updated\n");
        }
    }
    ret = 0;

 end:
    if (ret)
        VR_ERR_print_errors(bio_err);
    VR_BIO_free_all(Sout);
    VR_BIO_free_all(out);
    VR_BIO_free_all(in);
    sk_VR_X509_pop_free(cert_sk, VR_X509_free);

    if (free_key)
        OPENVR_SSL_free(key);
    VR_BN_free(serial);
    VR_BN_free(crlnumber);
    free_index(db);
    sk_VR_OPENSSL_STRING_free(sigopts);
    VR_EVP_PKEY_free(pkey);
    VR_X509_free(x509);
    VR_X509_CRL_free(crl);
    VR_NCONF_free(conf);
    VR_NCONF_free(extconf);
    release_engine(e);
    return ret;
}

static char *lookup_conf(const CONF *conf, const char *section, const char *tag)
{
    char *entry = VR_NCONF_get_string(conf, section, tag);
    if (entry == NULL)
        VR_BIO_printf(bio_err, "variable lookup failed for %s::%s\n", section, tag);
    return entry;
}

static int certify(X509 **xret, const char *infile, EVP_PKEY *pkey, X509 *x509,
                   const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
                   STACK_OF(CONF_VALUE) *policy, CA_DB *db,
                   BIGNUM *serial, const char *subj, unsigned long chtype,
                   int multirdn, int email_dn, const char *startdate,
                   const char *enddate,
                   long days, int batch, const char *ext_sect, CONF *lconf,
                   int verbose, unsigned long certopt, unsigned long nameopt,
                   int default_op, int ext_copy, int selfsign)
{
    X509_REQ *req = NULL;
    BIO *in = NULL;
    EVP_PKEY *pktmp = NULL;
    int ok = -1, i;

    in = VR_BIO_new_file(infile, "r");
    if (in == NULL) {
        VR_ERR_print_errors(bio_err);
        goto end;
    }
    if ((req = VR_PEM_read_bio_X509_REQ(in, NULL, NULL, NULL)) == NULL) {
        VR_BIO_printf(bio_err, "Error reading certificate request in %s\n",
                   infile);
        goto end;
    }
    if (verbose)
        VR_X509_REQ_print_ex(bio_err, req, nameopt, X509_FLAG_COMPAT);

    VR_BIO_printf(bio_err, "Check that the request matches the signature\n");

    if (selfsign && !VR_X509_REQ_check_private_key(req, pkey)) {
        VR_BIO_printf(bio_err,
                   "Certificate request and CA private key do not match\n");
        ok = 0;
        goto end;
    }
    if ((pktmp = VR_X509_REQ_get0_pubkey(req)) == NULL) {
        VR_BIO_printf(bio_err, "error unpacking public key\n");
        goto end;
    }
    i = VR_X509_REQ_verify(req, pktmp);
    pktmp = NULL;
    if (i < 0) {
        ok = 0;
        VR_BIO_printf(bio_err, "Signature verification problems....\n");
        VR_ERR_print_errors(bio_err);
        goto end;
    }
    if (i == 0) {
        ok = 0;
        VR_BIO_printf(bio_err,
                   "Signature did not match the certificate request\n");
        VR_ERR_print_errors(bio_err);
        goto end;
    } else {
        VR_BIO_printf(bio_err, "Signature ok\n");
    }

    ok = do_body(xret, pkey, x509, dgst, sigopts, policy, db, serial, subj,
                 chtype, multirdn, email_dn, startdate, enddate, days, batch,
                 verbose, req, ext_sect, lconf, certopt, nameopt, default_op,
                 ext_copy, selfsign);

 end:
    VR_X509_REQ_free(req);
    VR_BIO_free(in);
    return ok;
}

static int certify_cert(X509 **xret, const char *infile, EVP_PKEY *pkey, X509 *x509,
                        const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
                        STACK_OF(CONF_VALUE) *policy, CA_DB *db,
                        BIGNUM *serial, const char *subj, unsigned long chtype,
                        int multirdn, int email_dn, const char *startdate,
                        const char *enddate, long days, int batch, const char *ext_sect,
                        CONF *lconf, int verbose, unsigned long certopt,
                        unsigned long nameopt, int default_op, int ext_copy)
{
    X509 *req = NULL;
    X509_REQ *rreq = NULL;
    EVP_PKEY *pktmp = NULL;
    int ok = -1, i;

    if ((req = load_cert(infile, FORMAT_PEM, infile)) == NULL)
        goto end;
    if (verbose)
        VR_X509_print(bio_err, req);

    VR_BIO_printf(bio_err, "Check that the request matches the signature\n");

    if ((pktmp = VR_X509_get0_pubkey(req)) == NULL) {
        VR_BIO_printf(bio_err, "error unpacking public key\n");
        goto end;
    }
    i = VR_X509_verify(req, pktmp);
    if (i < 0) {
        ok = 0;
        VR_BIO_printf(bio_err, "Signature verification problems....\n");
        goto end;
    }
    if (i == 0) {
        ok = 0;
        VR_BIO_printf(bio_err, "Signature did not match the certificate\n");
        goto end;
    } else {
        VR_BIO_printf(bio_err, "Signature ok\n");
    }

    if ((rreq = VR_X509_to_X509_REQ(req, NULL, NULL)) == NULL)
        goto end;

    ok = do_body(xret, pkey, x509, dgst, sigopts, policy, db, serial, subj,
                 chtype, multirdn, email_dn, startdate, enddate, days, batch,
                 verbose, rreq, ext_sect, lconf, certopt, nameopt, default_op,
                 ext_copy, 0);

 end:
    VR_X509_REQ_free(rreq);
    VR_X509_free(req);
    return ok;
}

static int do_body(X509 **xret, EVP_PKEY *pkey, X509 *x509,
                   const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
                   STACK_OF(CONF_VALUE) *policy, CA_DB *db, BIGNUM *serial,
                   const char *subj, unsigned long chtype, int multirdn,
                   int email_dn, const char *startdate, const char *enddate, long days,
                   int batch, int verbose, X509_REQ *req, const char *ext_sect,
                   CONF *lconf, unsigned long certopt, unsigned long nameopt,
                   int default_op, int ext_copy, int selfsign)
{
    X509_NAME *name = NULL, *CAname = NULL, *subject = NULL;
    const ASN1_TIME *tm;
    ASN1_STRING *str, *str2;
    ASN1_OBJECT *obj;
    X509 *ret = NULL;
    X509_NAME_ENTRY *ne, *tne;
    EVP_PKEY *pktmp;
    int ok = -1, i, j, last, nid;
    const char *p;
    CONF_VALUE *cv;
    OPENSSL_STRING row[DB_NUMBER];
    OPENSSL_STRING *irow = NULL;
    OPENSSL_STRING *rrow = NULL;
    char buf[25];

    for (i = 0; i < DB_NUMBER; i++)
        row[i] = NULL;

    if (subj) {
        X509_NAME *n = parse_name(subj, chtype, multirdn);

        if (!n) {
            VR_ERR_print_errors(bio_err);
            goto end;
        }
        VR_X509_REQ_set_subject_name(req, n);
        VR_X509_NAME_free(n);
    }

    if (default_op)
        VR_BIO_printf(bio_err, "The Subject's Distinguished Name is as follows\n");

    name = VR_X509_REQ_get_subject_name(req);
    for (i = 0; i < VR_X509_NAME_entry_count(name); i++) {
        ne = VR_X509_NAME_get_entry(name, i);
        str = VR_X509_NAME_ENTRY_get_data(ne);
        obj = VR_X509_NAME_ENTRY_get_object(ne);
        nid = VR_OBJ_obj2nid(obj);

        if (msie_hack) {
            /* assume all type should be strings */

            if (str->type == V_ASN1_UNIVERSALSTRING)
                VR_ASN1_UNIVERSALSTRING_to_string(str);

            if (str->type == V_ASN1_IA5STRING && nid != NID_pkcs9_emailAddress)
                str->type = V_ASN1_T61STRING;

            if (nid == NID_pkcs9_emailAddress
                && str->type == V_ASN1_PRINTABLESTRING)
                str->type = V_ASN1_IA5STRING;
        }

        /* If no EMAIL is wanted in the subject */
        if (nid == NID_pkcs9_emailAddress && !email_dn)
            continue;

        /* check some things */
        if (nid == NID_pkcs9_emailAddress && str->type != V_ASN1_IA5STRING) {
            VR_BIO_printf(bio_err,
                       "\nemailAddress type needs to be of type IA5STRING\n");
            goto end;
        }
        if (str->type != V_ASN1_BMPSTRING && str->type != V_ASN1_UTF8STRING) {
            j = VR_ASN1_PRINTABLE_type(str->data, str->length);
            if ((j == V_ASN1_T61STRING && str->type != V_ASN1_T61STRING) ||
                (j == V_ASN1_IA5STRING && str->type == V_ASN1_PRINTABLESTRING))
            {
                VR_BIO_printf(bio_err,
                           "\nThe string contains characters that are illegal for the ASN.1 type\n");
                goto end;
            }
        }

        if (default_op)
            old_entry_print(obj, str);
    }

    /* Ok, now we check the 'policy' stuff. */
    if ((subject = VR_X509_NAME_new()) == NULL) {
        VR_BIO_printf(bio_err, "Memory allocation failure\n");
        goto end;
    }

    /* take a copy of the issuer name before we mess with it. */
    if (selfsign)
        CAname = VR_X509_NAME_dup(name);
    else
        CAname = VR_X509_NAME_dup(VR_X509_get_subject_name(x509));
    if (CAname == NULL)
        goto end;
    str = str2 = NULL;

    for (i = 0; i < sk_CONF_VALUE_num(policy); i++) {
        cv = sk_CONF_VALUE_value(policy, i); /* get the object id */
        if ((j = VR_OBJ_txt2nid(cv->name)) == NID_undef) {
            VR_BIO_printf(bio_err,
                       "%s:unknown object type in 'policy' configuration\n",
                       cv->name);
            goto end;
        }
        obj = VR_OBJ_nid2obj(j);

        last = -1;
        for (;;) {
            X509_NAME_ENTRY *push = NULL;

            /* lookup the object in the supplied name list */
            j = VR_X509_NAME_get_index_by_OBJ(name, obj, last);
            if (j < 0) {
                if (last != -1)
                    break;
                tne = NULL;
            } else {
                tne = VR_X509_NAME_get_entry(name, j);
            }
            last = j;

            /* depending on the 'policy', decide what to do. */
            if (strcmp(cv->value, "optional") == 0) {
                if (tne != NULL)
                    push = tne;
            } else if (strcmp(cv->value, "supplied") == 0) {
                if (tne == NULL) {
                    VR_BIO_printf(bio_err,
                               "The %s field needed to be supplied and was missing\n",
                               cv->name);
                    goto end;
                } else {
                    push = tne;
                }
            } else if (strcmp(cv->value, "match") == 0) {
                int last2;

                if (tne == NULL) {
                    VR_BIO_printf(bio_err,
                               "The mandatory %s field was missing\n",
                               cv->name);
                    goto end;
                }

                last2 = -1;

 again2:
                j = VR_X509_NAME_get_index_by_OBJ(CAname, obj, last2);
                if ((j < 0) && (last2 == -1)) {
                    VR_BIO_printf(bio_err,
                               "The %s field does not exist in the CA certificate,\n"
                               "the 'policy' is misconfigured\n", cv->name);
                    goto end;
                }
                if (j >= 0) {
                    push = VR_X509_NAME_get_entry(CAname, j);
                    str = VR_X509_NAME_ENTRY_get_data(tne);
                    str2 = VR_X509_NAME_ENTRY_get_data(push);
                    last2 = j;
                    if (VR_ASN1_STRING_cmp(str, str2) != 0)
                        goto again2;
                }
                if (j < 0) {
                    VR_BIO_printf(bio_err,
                               "The %s field is different between\n"
                               "CA certificate (%s) and the request (%s)\n",
                               cv->name,
                               ((str2 == NULL) ? "NULL" : (char *)str2->data),
                               ((str == NULL) ? "NULL" : (char *)str->data));
                    goto end;
                }
            } else {
                VR_BIO_printf(bio_err,
                           "%s:invalid type in 'policy' configuration\n",
                           cv->value);
                goto end;
            }

            if (push != NULL) {
                if (!VR_X509_NAME_add_entry(subject, push, -1, 0)) {
                    VR_BIO_printf(bio_err, "Memory allocation failure\n");
                    goto end;
                }
            }
            if (j < 0)
                break;
        }
    }

    if (preserve) {
        VR_X509_NAME_free(subject);
        /* subject=VR_X509_NAME_dup(VR_X509_REQ_get_subject_name(req)); */
        subject = VR_X509_NAME_dup(name);
        if (subject == NULL)
            goto end;
    }

    /* We are now totally happy, lets make and sign the certificate */
    if (verbose)
        VR_BIO_printf(bio_err,
                   "Everything appears to be ok, creating and signing the certificate\n");

    if ((ret = VR_X509_new()) == NULL)
        goto end;

#ifdef X509_V3
    /* Make it an X509 v3 certificate. */
    if (!VR_X509_set_version(ret, 2))
        goto end;
#endif

    if (VR_BN_to_ASN1_INTEGER(serial, VR_X509_get_serialNumber(ret)) == NULL)
        goto end;
    if (selfsign) {
        if (!VR_X509_set_issuer_name(ret, subject))
            goto end;
    } else {
        if (!VR_X509_set_issuer_name(ret, VR_X509_get_subject_name(x509)))
            goto end;
    }

    if (!set_cert_times(ret, startdate, enddate, days))
        goto end;

    if (enddate != NULL) {
        int tdays;

        if (!VR_ASN1_TIME_diff(&tdays, NULL, NULL, VR_X509_get0_notAfter(ret)))
            goto end;
        days = tdays;
    }

    if (!VR_X509_set_subject_name(ret, subject))
        goto end;

    pktmp = VR_X509_REQ_get0_pubkey(req);
    i = VR_X509_set_pubkey(ret, pktmp);
    if (!i)
        goto end;

    /* Lets add the extensions, if there are any */
    if (ext_sect) {
        X509V3_CTX ctx;

        /* Initialize the context structure */
        if (selfsign)
            VR_X509V3_set_ctx(&ctx, ret, ret, req, NULL, 0);
        else
            VR_X509V3_set_ctx(&ctx, x509, ret, req, NULL, 0);

        if (extconf != NULL) {
            if (verbose)
                VR_BIO_printf(bio_err, "Extra configuration file found\n");

            /* Use the extconf configuration db LHASH */
            VR_X509V3_set_nconf(&ctx, extconf);

            /* Test the structure (needed?) */
            /* VR_X509V3_set_ctx_test(&ctx); */

            /* Adds exts contained in the configuration file */
            if (!VR_X509V3_EXT_add_nconf(extconf, &ctx, ext_sect, ret)) {
                VR_BIO_printf(bio_err,
                           "ERROR: adding extensions in section %s\n",
                           ext_sect);
                VR_ERR_print_errors(bio_err);
                goto end;
            }
            if (verbose)
                VR_BIO_printf(bio_err,
                           "Successfully added extensions from file.\n");
        } else if (ext_sect) {
            /* We found extensions to be set from config file */
            VR_X509V3_set_nconf(&ctx, lconf);

            if (!VR_X509V3_EXT_add_nconf(lconf, &ctx, ext_sect, ret)) {
                VR_BIO_printf(bio_err,
                           "ERROR: adding extensions in section %s\n",
                           ext_sect);
                VR_ERR_print_errors(bio_err);
                goto end;
            }

            if (verbose)
                VR_BIO_printf(bio_err,
                           "Successfully added extensions from config\n");
        }
    }

    /* Copy extensions from request (if any) */

    if (!copy_extensions(ret, req, ext_copy)) {
        VR_BIO_printf(bio_err, "ERROR: adding extensions from request\n");
        VR_ERR_print_errors(bio_err);
        goto end;
    }

    {
        const STACK_OF(X509_EXTENSION) *exts = VR_X509_get0_extensions(ret);

        if (exts != NULL && sk_X509_EXTENSION_num(exts) > 0)
            /* Make it an X509 v3 certificate. */
            if (!VR_X509_set_version(ret, 2))
                goto end;
    }

    if (verbose)
        VR_BIO_printf(bio_err,
                   "The subject name appears to be ok, checking data base for clashes\n");

    /* Build the correct Subject if no e-mail is wanted in the subject. */
    if (!email_dn) {
        X509_NAME_ENTRY *tmpne;
        X509_NAME *dn_subject;

        /*
         * Its best to dup the subject DN and then delete any email addresses
         * because this retains its structure.
         */
        if ((dn_subject = VR_X509_NAME_dup(subject)) == NULL) {
            VR_BIO_printf(bio_err, "Memory allocation failure\n");
            goto end;
        }
        i = -1;
        while ((i = VR_X509_NAME_get_index_by_NID(dn_subject,
                                               NID_pkcs9_emailAddress,
                                               i)) >= 0) {
            tmpne = VR_X509_NAME_delete_entry(dn_subject, i--);
            VR_X509_NAME_ENTRY_free(tmpne);
        }

        if (!VR_X509_set_subject_name(ret, dn_subject)) {
            VR_X509_NAME_free(dn_subject);
            goto end;
        }
        VR_X509_NAME_free(dn_subject);
    }

    row[DB_name] = VR_X509_NAME_oneline(VR_X509_get_subject_name(ret), NULL, 0);
    if (row[DB_name] == NULL) {
        VR_BIO_printf(bio_err, "Memory allocation failure\n");
        goto end;
    }

    if (VR_BN_is_zero(serial))
        row[DB_serial] = OPENSSL_strdup("00");
    else
        row[DB_serial] = VR_BN_bn2hex(serial);
    if (row[DB_serial] == NULL) {
        VR_BIO_printf(bio_err, "Memory allocation failure\n");
        goto end;
    }

    if (row[DB_name][0] == '\0') {
        /*
         * An empty subject! We'll use the serial number instead. If
         * unique_subject is in use then we don't want different entries with
         * empty subjects matching each other.
         */
        OPENVR_SSL_free(row[DB_name]);
        row[DB_name] = OPENSSL_strdup(row[DB_serial]);
        if (row[DB_name] == NULL) {
            VR_BIO_printf(bio_err, "Memory allocation failure\n");
            goto end;
        }
    }

    if (db->attributes.unique_subject) {
        OPENSSL_STRING *crow = row;

        rrow = VR_TXT_DB_get_by_index(db->db, DB_name, crow);
        if (rrow != NULL) {
            VR_BIO_printf(bio_err,
                       "ERROR:There is already a certificate for %s\n",
                       row[DB_name]);
        }
    }
    if (rrow == NULL) {
        rrow = VR_TXT_DB_get_by_index(db->db, DB_serial, row);
        if (rrow != NULL) {
            VR_BIO_printf(bio_err,
                       "ERROR:Serial number %s has already been issued,\n",
                       row[DB_serial]);
            VR_BIO_printf(bio_err,
                       "      check the database/serial_file for corruption\n");
        }
    }

    if (rrow != NULL) {
        VR_BIO_printf(bio_err, "The matching entry has the following details\n");
        if (rrow[DB_type][0] == DB_TYPE_EXP)
            p = "Expired";
        else if (rrow[DB_type][0] == DB_TYPE_REV)
            p = "Revoked";
        else if (rrow[DB_type][0] == DB_TYPE_VAL)
            p = "Valid";
        else
            p = "\ninvalid type, Data base error\n";
        VR_BIO_printf(bio_err, "Type          :%s\n", p);;
        if (rrow[DB_type][0] == DB_TYPE_REV) {
            p = rrow[DB_exp_date];
            if (p == NULL)
                p = "undef";
            VR_BIO_printf(bio_err, "Was revoked on:%s\n", p);
        }
        p = rrow[DB_exp_date];
        if (p == NULL)
            p = "undef";
        VR_BIO_printf(bio_err, "Expires on    :%s\n", p);
        p = rrow[DB_serial];
        if (p == NULL)
            p = "undef";
        VR_BIO_printf(bio_err, "Serial Number :%s\n", p);
        p = rrow[DB_file];
        if (p == NULL)
            p = "undef";
        VR_BIO_printf(bio_err, "File name     :%s\n", p);
        p = rrow[DB_name];
        if (p == NULL)
            p = "undef";
        VR_BIO_printf(bio_err, "Subject Name  :%s\n", p);
        ok = -1;                /* This is now a 'bad' error. */
        goto end;
    }

    if (!default_op) {
        VR_BIO_printf(bio_err, "Certificate Details:\n");
        /*
         * Never print signature details because signature not present
         */
        certopt |= X509_FLAG_NO_SIGDUMP | X509_FLAG_NO_SIGNAME;
        VR_X509_print_ex(bio_err, ret, nameopt, certopt);
    }

    VR_BIO_printf(bio_err, "Certificate is to be certified until ");
    VR_ASN1_TIME_print(bio_err, VR_X509_get0_notAfter(ret));
    if (days)
        VR_BIO_printf(bio_err, " (%ld days)", days);
    VR_BIO_printf(bio_err, "\n");

    if (!batch) {

        VR_BIO_printf(bio_err, "Sign the certificate? [y/n]:");
        (void)BIO_flush(bio_err);
        buf[0] = '\0';
        if (fgets(buf, sizeof(buf), stdin) == NULL) {
            VR_BIO_printf(bio_err,
                       "CERTIFICATE WILL NOT BE CERTIFIED: I/O error\n");
            ok = 0;
            goto end;
        }
        if (!(buf[0] == 'y' || buf[0] == 'Y')) {
            VR_BIO_printf(bio_err, "CERTIFICATE WILL NOT BE CERTIFIED\n");
            ok = 0;
            goto end;
        }
    }

    pktmp = VR_X509_get0_pubkey(ret);
    if (VR_EVP_PKEY_missing_parameters(pktmp) &&
        !VR_EVP_PKEY_missing_parameters(pkey))
        VR_EVP_PKEY_copy_parameters(pktmp, pkey);

    if (!do_VR_X509_sign(ret, pkey, dgst, sigopts))
        goto end;

    /* We now just add it to the database as DB_TYPE_VAL('V') */
    row[DB_type] = OPENSSL_strdup("V");
    tm = VR_X509_get0_notAfter(ret);
    row[DB_exp_date] = app_malloc(tm->length + 1, "row expdate");
    memcpy(row[DB_exp_date], tm->data, tm->length);
    row[DB_exp_date][tm->length] = '\0';
    row[DB_rev_date] = NULL;
    row[DB_file] = OPENSSL_strdup("unknown");
    if ((row[DB_type] == NULL) || (row[DB_exp_date] == NULL) ||
        (row[DB_file] == NULL) || (row[DB_name] == NULL)) {
        VR_BIO_printf(bio_err, "Memory allocation failure\n");
        goto end;
    }

    irow = app_malloc(sizeof(*irow) * (DB_NUMBER + 1), "row space");
    for (i = 0; i < DB_NUMBER; i++)
        irow[i] = row[i];
    irow[DB_NUMBER] = NULL;

    if (!VR_TXT_DB_insert(db->db, irow)) {
        VR_BIO_printf(bio_err, "failed to update database\n");
        VR_BIO_printf(bio_err, "TXT_DB error number %ld\n", db->db->error);
        goto end;
    }
    irow = NULL;
    ok = 1;
 end:
    if (ok != 1) {
        for (i = 0; i < DB_NUMBER; i++)
            OPENVR_SSL_free(row[i]);
    }
    OPENVR_SSL_free(irow);

    VR_X509_NAME_free(CAname);
    VR_X509_NAME_free(subject);
    if (ok <= 0)
        VR_X509_free(ret);
    else
        *xret = ret;
    return ok;
}

static void write_new_certificate(BIO *bp, X509 *x, int output_der, int notext)
{

    if (output_der) {
        (void)VR_i2d_X509_bio(bp, x);
        return;
    }
    if (!notext)
        VR_X509_print(bp, x);
    VR_PEM_write_bio_X509(bp, x);
}

static int certify_spkac(X509 **xret, const char *infile, EVP_PKEY *pkey,
                         X509 *x509, const EVP_MD *dgst,
                         STACK_OF(OPENSSL_STRING) *sigopts,
                         STACK_OF(CONF_VALUE) *policy, CA_DB *db,
                         BIGNUM *serial, const char *subj, unsigned long chtype,
                         int multirdn, int email_dn, const char *startdate,
                         const char *enddate, long days, const char *ext_sect,
                         CONF *lconf, int verbose, unsigned long certopt,
                         unsigned long nameopt, int default_op, int ext_copy)
{
    STACK_OF(CONF_VALUE) *sk = NULL;
    LHASH_OF(CONF_VALUE) *parms = NULL;
    X509_REQ *req = NULL;
    CONF_VALUE *cv = NULL;
    NETSCAPE_SPKI *spki = NULL;
    char *type, *buf;
    EVP_PKEY *pktmp = NULL;
    X509_NAME *n = NULL;
    X509_NAME_ENTRY *ne = NULL;
    int ok = -1, i, j;
    long errline;
    int nid;

    /*
     * Load input file into a hash table.  (This is just an easy
     * way to read and parse the file, then put it into a convenient
     * STACK format).
     */
    parms = VR_CONF_load(NULL, infile, &errline);
    if (parms == NULL) {
        VR_BIO_printf(bio_err, "error on line %ld of %s\n", errline, infile);
        VR_ERR_print_errors(bio_err);
        goto end;
    }

    sk = VR_CONF_get_section(parms, "default");
    if (sk_CONF_VALUE_num(sk) == 0) {
        VR_BIO_printf(bio_err, "no name/value pairs found in %s\n", infile);
        goto end;
    }

    /*
     * Now create a dummy X509 request structure.  We don't actually
     * have an X509 request, but we have many of the components
     * (a public key, various DN components).  The idea is that we
     * put these components into the right X509 request structure
     * and we can use the same code as if you had a real X509 request.
     */
    req = VR_X509_REQ_new();
    if (req == NULL) {
        VR_ERR_print_errors(bio_err);
        goto end;
    }

    /*
     * Build up the subject name set.
     */
    n = VR_X509_REQ_get_subject_name(req);

    for (i = 0;; i++) {
        if (sk_CONF_VALUE_num(sk) <= i)
            break;

        cv = sk_CONF_VALUE_value(sk, i);
        type = cv->name;
        /*
         * Skip past any leading X. X: X, etc to allow for multiple instances
         */
        for (buf = cv->name; *buf; buf++)
            if ((*buf == ':') || (*buf == ',') || (*buf == '.')) {
                buf++;
                if (*buf)
                    type = buf;
                break;
            }

        buf = cv->value;
        if ((nid = VR_OBJ_txt2nid(type)) == NID_undef) {
            if (strcmp(type, "SPKAC") == 0) {
                spki = VR_NETSCAPE_SPKI_b64_decode(cv->value, -1);
                if (spki == NULL) {
                    VR_BIO_printf(bio_err,
                               "unable to load Netscape SPKAC structure\n");
                    VR_ERR_print_errors(bio_err);
                    goto end;
                }
            }
            continue;
        }

        if (!VR_X509_NAME_add_entry_by_NID(n, nid, chtype,
                                        (unsigned char *)buf, -1, -1, 0))
            goto end;
    }
    if (spki == NULL) {
        VR_BIO_printf(bio_err, "Netscape SPKAC structure not found in %s\n",
                   infile);
        goto end;
    }

    /*
     * Now extract the key from the SPKI structure.
     */

    VR_BIO_printf(bio_err, "Check that the SPKAC request matches the signature\n");

    if ((pktmp = VR_NETSCAPE_SPKI_get_pubkey(spki)) == NULL) {
        VR_BIO_printf(bio_err, "error unpacking SPKAC public key\n");
        goto end;
    }

    j = VR_NETSCAPE_SPKI_verify(spki, pktmp);
    if (j <= 0) {
        VR_EVP_PKEY_free(pktmp);
        VR_BIO_printf(bio_err,
                   "signature verification failed on SPKAC public key\n");
        goto end;
    }
    VR_BIO_printf(bio_err, "Signature ok\n");

    VR_X509_REQ_set_pubkey(req, pktmp);
    VR_EVP_PKEY_free(pktmp);
    ok = do_body(xret, pkey, x509, dgst, sigopts, policy, db, serial, subj,
                 chtype, multirdn, email_dn, startdate, enddate, days, 1,
                 verbose, req, ext_sect, lconf, certopt, nameopt, default_op,
                 ext_copy, 0);
 end:
    VR_X509_REQ_free(req);
    VR_CONF_free(parms);
    VR_NETSCAPE_SPKI_free(spki);
    VR_X509_NAME_ENTRY_free(ne);

    return ok;
}

static int check_time_format(const char *str)
{
    return VR_ASN1_TIME_set_string(NULL, str);
}

static int do_revoke(X509 *x509, CA_DB *db, REVINFO_TYPE rev_type,
                     const char *value)
{
    const ASN1_TIME *tm = NULL;
    char *row[DB_NUMBER], **rrow, **irow;
    char *rev_str = NULL;
    BIGNUM *bn = NULL;
    int ok = -1, i;

    for (i = 0; i < DB_NUMBER; i++)
        row[i] = NULL;
    row[DB_name] = VR_X509_NAME_oneline(VR_X509_get_subject_name(x509), NULL, 0);
    bn = VR_ASN1_INTEGER_to_BN(VR_X509_get_serialNumber(x509), NULL);
    if (!bn)
        goto end;
    if (VR_BN_is_zero(bn))
        row[DB_serial] = OPENSSL_strdup("00");
    else
        row[DB_serial] = VR_BN_bn2hex(bn);
    VR_BN_free(bn);
    if (row[DB_name] != NULL && row[DB_name][0] == '\0') {
        /* Entries with empty Subjects actually use the serial number instead */
        OPENVR_SSL_free(row[DB_name]);
        row[DB_name] = OPENSSL_strdup(row[DB_serial]);
    }
    if ((row[DB_name] == NULL) || (row[DB_serial] == NULL)) {
        VR_BIO_printf(bio_err, "Memory allocation failure\n");
        goto end;
    }
    /*
     * We have to lookup by serial number because name lookup skips revoked
     * certs
     */
    rrow = VR_TXT_DB_get_by_index(db->db, DB_serial, row);
    if (rrow == NULL) {
        VR_BIO_printf(bio_err,
                   "Adding Entry with serial number %s to DB for %s\n",
                   row[DB_serial], row[DB_name]);

        /* We now just add it to the database as DB_TYPE_REV('V') */
        row[DB_type] = OPENSSL_strdup("V");
        tm = VR_X509_get0_notAfter(x509);
        row[DB_exp_date] = app_malloc(tm->length + 1, "row exp_data");
        memcpy(row[DB_exp_date], tm->data, tm->length);
        row[DB_exp_date][tm->length] = '\0';
        row[DB_rev_date] = NULL;
        row[DB_file] = OPENSSL_strdup("unknown");

        if (row[DB_type] == NULL || row[DB_file] == NULL) {
            VR_BIO_printf(bio_err, "Memory allocation failure\n");
            goto end;
        }

        irow = app_malloc(sizeof(*irow) * (DB_NUMBER + 1), "row ptr");
        for (i = 0; i < DB_NUMBER; i++)
            irow[i] = row[i];
        irow[DB_NUMBER] = NULL;

        if (!VR_TXT_DB_insert(db->db, irow)) {
            VR_BIO_printf(bio_err, "failed to update database\n");
            VR_BIO_printf(bio_err, "TXT_DB error number %ld\n", db->db->error);
            OPENVR_SSL_free(irow);
            goto end;
        }

        for (i = 0; i < DB_NUMBER; i++)
            row[i] = NULL;

        /* Revoke Certificate */
        if (rev_type == REV_VALID)
            ok = 1;
        else
            /* Retry revocation after DB insertion */
            ok = do_revoke(x509, db, rev_type, value);

        goto end;

    } else if (index_name_cmp_noconst(row, rrow)) {
        VR_BIO_printf(bio_err, "ERROR:name does not match %s\n", row[DB_name]);
        goto end;
    } else if (rev_type == REV_VALID) {
        VR_BIO_printf(bio_err, "ERROR:Already present, serial number %s\n",
                   row[DB_serial]);
        goto end;
    } else if (rrow[DB_type][0] == DB_TYPE_REV) {
        VR_BIO_printf(bio_err, "ERROR:Already revoked, serial number %s\n",
                   row[DB_serial]);
        goto end;
    } else {
        VR_BIO_printf(bio_err, "Revoking Certificate %s.\n", rrow[DB_serial]);
        rev_str = make_revocation_str(rev_type, value);
        if (!rev_str) {
            VR_BIO_printf(bio_err, "Error in revocation arguments\n");
            goto end;
        }
        rrow[DB_type][0] = DB_TYPE_REV;
        rrow[DB_type][1] = '\0';
        rrow[DB_rev_date] = rev_str;
    }
    ok = 1;
 end:
    for (i = 0; i < DB_NUMBER; i++)
        OPENVR_SSL_free(row[i]);
    return ok;
}

static int get_certificate_status(const char *serial, CA_DB *db)
{
    char *row[DB_NUMBER], **rrow;
    int ok = -1, i;
    size_t serial_len = strlen(serial);

    /* Free Resources */
    for (i = 0; i < DB_NUMBER; i++)
        row[i] = NULL;

    /* Malloc needed char spaces */
    row[DB_serial] = app_malloc(serial_len + 2, "row serial#");

    if (serial_len % 2) {
        /*
         * Set the first char to 0
         */
        row[DB_serial][0] = '0';

        /* Copy String from serial to row[DB_serial] */
        memcpy(row[DB_serial] + 1, serial, serial_len);
        row[DB_serial][serial_len + 1] = '\0';
    } else {
        /* Copy String from serial to row[DB_serial] */
        memcpy(row[DB_serial], serial, serial_len);
        row[DB_serial][serial_len] = '\0';
    }

    /* Make it Upper Case */
    make_uppercase(row[DB_serial]);

    ok = 1;

    /* Search for the certificate */
    rrow = VR_TXT_DB_get_by_index(db->db, DB_serial, row);
    if (rrow == NULL) {
        VR_BIO_printf(bio_err, "Serial %s not present in db.\n", row[DB_serial]);
        ok = -1;
        goto end;
    } else if (rrow[DB_type][0] == DB_TYPE_VAL) {
        VR_BIO_printf(bio_err, "%s=Valid (%c)\n",
                   row[DB_serial], rrow[DB_type][0]);
        goto end;
    } else if (rrow[DB_type][0] == DB_TYPE_REV) {
        VR_BIO_printf(bio_err, "%s=Revoked (%c)\n",
                   row[DB_serial], rrow[DB_type][0]);
        goto end;
    } else if (rrow[DB_type][0] == DB_TYPE_EXP) {
        VR_BIO_printf(bio_err, "%s=Expired (%c)\n",
                   row[DB_serial], rrow[DB_type][0]);
        goto end;
    } else if (rrow[DB_type][0] == DB_TYPE_SUSP) {
        VR_BIO_printf(bio_err, "%s=Suspended (%c)\n",
                   row[DB_serial], rrow[DB_type][0]);
        goto end;
    } else {
        VR_BIO_printf(bio_err, "%s=Unknown (%c).\n",
                   row[DB_serial], rrow[DB_type][0]);
        ok = -1;
    }
 end:
    for (i = 0; i < DB_NUMBER; i++) {
        OPENVR_SSL_free(row[i]);
    }
    return ok;
}

static int do_updatedb(CA_DB *db)
{
    ASN1_UTCTIME *a_tm = NULL;
    int i, cnt = 0;
    int db_y2k, a_y2k;          /* flags = 1 if y >= 2000 */
    char **rrow, *a_tm_s;

    a_tm = VR_ASN1_UTCTIME_new();
    if (a_tm == NULL)
        return -1;

    /* get actual time and make a string */
    if (VR_X509_gmtime_adj(a_tm, 0) == NULL) {
        VR_ASN1_UTCTIME_free(a_tm);
        return -1;
    }
    a_tm_s = app_malloc(a_tm->length + 1, "time string");

    memcpy(a_tm_s, a_tm->data, a_tm->length);
    a_tm_s[a_tm->length] = '\0';

    if (strncmp(a_tm_s, "49", 2) <= 0)
        a_y2k = 1;
    else
        a_y2k = 0;

    for (i = 0; i < sk_OPENSSL_PSTRING_num(db->db->data); i++) {
        rrow = sk_OPENSSL_PSTRING_value(db->db->data, i);

        if (rrow[DB_type][0] == DB_TYPE_VAL) {
            /* ignore entries that are not valid */
            if (strncmp(rrow[DB_exp_date], "49", 2) <= 0)
                db_y2k = 1;
            else
                db_y2k = 0;

            if (db_y2k == a_y2k) {
                /* all on the same y2k side */
                if (strcmp(rrow[DB_exp_date], a_tm_s) <= 0) {
                    rrow[DB_type][0] = DB_TYPE_EXP;
                    rrow[DB_type][1] = '\0';
                    cnt++;

                    VR_BIO_printf(bio_err, "%s=Expired\n", rrow[DB_serial]);
                }
            } else if (db_y2k < a_y2k) {
                rrow[DB_type][0] = DB_TYPE_EXP;
                rrow[DB_type][1] = '\0';
                cnt++;

                VR_BIO_printf(bio_err, "%s=Expired\n", rrow[DB_serial]);
            }

        }
    }

    VR_ASN1_UTCTIME_free(a_tm);
    OPENVR_SSL_free(a_tm_s);
    return cnt;
}

static const char *crl_reasons[] = {
    /* CRL reason strings */
    "unspecified",
    "keyCompromise",
    "CACompromise",
    "affiliationChanged",
    "superseded",
    "cessationOfOperation",
    "certificateHold",
    "removeFromCRL",
    /* Additional pseudo reasons */
    "holdInstruction",
    "keyTime",
    "CAkeyTime"
};

#define NUM_REASONS OSSL_NELEM(crl_reasons)

/*
 * Given revocation information convert to a DB string. The format of the
 * string is: revtime[,reason,extra]. Where 'revtime' is the revocation time
 * (the current time). 'reason' is the optional CRL reason and 'extra' is any
 * additional argument
 */

static char *make_revocation_str(REVINFO_TYPE rev_type, const char *rev_arg)
{
    char *str;
    const char *reason = NULL, *other = NULL;
    ASN1_OBJECT *otmp;
    ASN1_UTCTIME *revtm = NULL;
    int i;

    switch (rev_type) {
    case REV_NONE:
    case REV_VALID:
        break;

    case REV_CRL_REASON:
        for (i = 0; i < 8; i++) {
            if (strcasecmp(rev_arg, crl_reasons[i]) == 0) {
                reason = crl_reasons[i];
                break;
            }
        }
        if (reason == NULL) {
            VR_BIO_printf(bio_err, "Unknown CRL reason %s\n", rev_arg);
            return NULL;
        }
        break;

    case REV_HOLD:
        /* Argument is an OID */
        otmp = VR_OBJ_txt2obj(rev_arg, 0);
        VR_ASN1_OBJECT_free(otmp);

        if (otmp == NULL) {
            VR_BIO_printf(bio_err, "Invalid object identifier %s\n", rev_arg);
            return NULL;
        }

        reason = "holdInstruction";
        other = rev_arg;
        break;

    case REV_KEY_COMPROMISE:
    case REV_CA_COMPROMISE:
        /* Argument is the key compromise time  */
        if (!VR_ASN1_GENERALIZEDTIME_set_string(NULL, rev_arg)) {
            VR_BIO_printf(bio_err,
                       "Invalid time format %s. Need YYYYMMDDHHMMSSZ\n",
                       rev_arg);
            return NULL;
        }
        other = rev_arg;
        if (rev_type == REV_KEY_COMPROMISE)
            reason = "keyTime";
        else
            reason = "CAkeyTime";

        break;
    }

    revtm = VR_X509_gmtime_adj(NULL, 0);

    if (!revtm)
        return NULL;

    i = revtm->length + 1;

    if (reason)
        i += strlen(reason) + 1;
    if (other)
        i += strlen(other) + 1;

    str = app_malloc(i, "revocation reason");
    VR_OPENSSL_strlcpy(str, (char *)revtm->data, i);
    if (reason) {
        VR_OPENSSL_strlcat(str, ",", i);
        VR_OPENSSL_strlcat(str, reason, i);
    }
    if (other) {
        VR_OPENSSL_strlcat(str, ",", i);
        VR_OPENSSL_strlcat(str, other, i);
    }
    VR_ASN1_UTCTIME_free(revtm);
    return str;
}

/*-
 * Convert revocation field to X509_REVOKED entry
 * return code:
 * 0 error
 * 1 OK
 * 2 OK and some extensions added (i.e. V2 CRL)
 */

static int make_revoked(X509_REVOKED *rev, const char *str)
{
    char *tmp = NULL;
    int reason_code = -1;
    int i, ret = 0;
    ASN1_OBJECT *hold = NULL;
    ASN1_GENERALIZEDTIME *comp_time = NULL;
    ASN1_ENUMERATED *rtmp = NULL;

    ASN1_TIME *revDate = NULL;

    i = unpack_revinfo(&revDate, &reason_code, &hold, &comp_time, str);

    if (i == 0)
        goto end;

    if (rev && !VR_X509_REVOKED_set_revocationDate(rev, revDate))
        goto end;

    if (rev && (reason_code != OCSP_REVOKED_STATUS_NOSTATUS)) {
        rtmp = VR_ASN1_ENUMERATED_new();
        if (rtmp == NULL || !VR_ASN1_ENUMERATED_set(rtmp, reason_code))
            goto end;
        if (!VR_X509_REVOKED_add1_ext_i2d(rev, NID_crl_reason, rtmp, 0, 0))
            goto end;
    }

    if (rev && comp_time) {
        if (!VR_X509_REVOKED_add1_ext_i2d
            (rev, NID_invalidity_date, comp_time, 0, 0))
            goto end;
    }
    if (rev && hold) {
        if (!VR_X509_REVOKED_add1_ext_i2d
            (rev, NID_hold_instruction_code, hold, 0, 0))
            goto end;
    }

    if (reason_code != OCSP_REVOKED_STATUS_NOSTATUS)
        ret = 2;
    else
        ret = 1;

 end:

    OPENVR_SSL_free(tmp);
    VR_ASN1_OBJECT_free(hold);
    VR_ASN1_GENERALIZEDTIME_free(comp_time);
    VR_ASN1_ENUMERATED_free(rtmp);
    VR_ASN1_TIME_free(revDate);

    return ret;
}

static int old_entry_print(const ASN1_OBJECT *obj, const ASN1_STRING *str)
{
    char buf[25], *pbuf;
    const char *p;
    int j;

    j = VR_i2a_ASN1_OBJECT(bio_err, obj);
    pbuf = buf;
    for (j = 22 - j; j > 0; j--)
        *(pbuf++) = ' ';
    *(pbuf++) = ':';
    *(pbuf++) = '\0';
    VR_BIO_puts(bio_err, buf);

    if (str->type == V_ASN1_PRINTABLESTRING)
        VR_BIO_printf(bio_err, "PRINTABLE:'");
    else if (str->type == V_ASN1_T61STRING)
        VR_BIO_printf(bio_err, "T61STRING:'");
    else if (str->type == V_ASN1_IA5STRING)
        VR_BIO_printf(bio_err, "IA5STRING:'");
    else if (str->type == V_ASN1_UNIVERSALSTRING)
        VR_BIO_printf(bio_err, "UNIVERSALSTRING:'");
    else
        VR_BIO_printf(bio_err, "ASN.1 %2d:'", str->type);

    p = (const char *)str->data;
    for (j = str->length; j > 0; j--) {
        if ((*p >= ' ') && (*p <= '~'))
            VR_BIO_printf(bio_err, "%c", *p);
        else if (*p & 0x80)
            VR_BIO_printf(bio_err, "\\0x%02X", *p);
        else if ((unsigned char)*p == 0xf7)
            VR_BIO_printf(bio_err, "^?");
        else
            VR_BIO_printf(bio_err, "^%c", *p + '@');
        p++;
    }
    VR_BIO_printf(bio_err, "'\n");
    return 1;
}

int unpack_revinfo(ASN1_TIME **prevtm, int *preason, ASN1_OBJECT **phold,
                   ASN1_GENERALIZEDTIME **pinvtm, const char *str)
{
    char *tmp;
    char *rtime_str, *reason_str = NULL, *arg_str = NULL, *p;
    int reason_code = -1;
    int ret = 0;
    unsigned int i;
    ASN1_OBJECT *hold = NULL;
    ASN1_GENERALIZEDTIME *comp_time = NULL;

    tmp = OPENSSL_strdup(str);
    if (!tmp) {
        VR_BIO_printf(bio_err, "memory allocation failure\n");
        goto end;
    }

    p = strchr(tmp, ',');

    rtime_str = tmp;

    if (p) {
        *p = '\0';
        p++;
        reason_str = p;
        p = strchr(p, ',');
        if (p) {
            *p = '\0';
            arg_str = p + 1;
        }
    }

    if (prevtm) {
        *prevtm = VR_ASN1_UTCTIME_new();
        if (*prevtm == NULL) {
            VR_BIO_printf(bio_err, "memory allocation failure\n");
            goto end;
        }
        if (!VR_ASN1_UTCTIME_set_string(*prevtm, rtime_str)) {
            VR_BIO_printf(bio_err, "invalid revocation date %s\n", rtime_str);
            goto end;
        }
    }
    if (reason_str) {
        for (i = 0; i < NUM_REASONS; i++) {
            if (strcasecmp(reason_str, crl_reasons[i]) == 0) {
                reason_code = i;
                break;
            }
        }
        if (reason_code == OCSP_REVOKED_STATUS_NOSTATUS) {
            VR_BIO_printf(bio_err, "invalid reason code %s\n", reason_str);
            goto end;
        }

        if (reason_code == 7) {
            reason_code = OCSP_REVOKED_STATUS_REMOVEFROMCRL;
        } else if (reason_code == 8) { /* Hold instruction */
            if (!arg_str) {
                VR_BIO_printf(bio_err, "missing hold instruction\n");
                goto end;
            }
            reason_code = OCSP_REVOKED_STATUS_CERTIFICATEHOLD;
            hold = VR_OBJ_txt2obj(arg_str, 0);

            if (!hold) {
                VR_BIO_printf(bio_err, "invalid object identifier %s\n", arg_str);
                goto end;
            }
            if (phold)
                *phold = hold;
            else
                VR_ASN1_OBJECT_free(hold);
        } else if ((reason_code == 9) || (reason_code == 10)) {
            if (!arg_str) {
                VR_BIO_printf(bio_err, "missing compromised time\n");
                goto end;
            }
            comp_time = VR_ASN1_GENERALIZEDTIME_new();
            if (comp_time == NULL) {
                VR_BIO_printf(bio_err, "memory allocation failure\n");
                goto end;
            }
            if (!VR_ASN1_GENERALIZEDTIME_set_string(comp_time, arg_str)) {
                VR_BIO_printf(bio_err, "invalid compromised time %s\n", arg_str);
                goto end;
            }
            if (reason_code == 9)
                reason_code = OCSP_REVOKED_STATUS_KEYCOMPROMISE;
            else
                reason_code = OCSP_REVOKED_STATUS_CACOMPROMISE;
        }
    }

    if (preason)
        *preason = reason_code;
    if (pinvtm) {
        *pinvtm = comp_time;
        comp_time = NULL;
    }

    ret = 1;

 end:

    OPENVR_SSL_free(tmp);
    VR_ASN1_GENERALIZEDTIME_free(comp_time);

    return ret;
}
