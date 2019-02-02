/*
 * Copyright 2000-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"
#include <stdio.h>
#include <string.h>
#include "internal/conf.h"
#include "internal/ctype.h"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/conf_api.h>
#include <openssl/lhash.h>

static CONF_METHOD *default_CONF_method = NULL;

/* Init a 'CONF' structure from an old LHASH */

void VR_CONF_set_nconf(CONF *conf, LHASH_OF(CONF_VALUE) *hash)
{
    if (default_CONF_method == NULL)
        default_CONF_method = VR_NCONF_default();

    default_CONF_method->init(conf);
    conf->data = hash;
}

/*
 * The following section contains the "CONF classic" functions, rewritten in
 * terms of the new CONF interface.
 */

int VR_CONF_set_default_method(CONF_METHOD *meth)
{
    default_CONF_method = meth;
    return 1;
}

LHASH_OF(CONF_VALUE) *VR_CONF_load(LHASH_OF(CONF_VALUE) *conf, const char *file,
                                long *eline)
{
    LHASH_OF(CONF_VALUE) *ltmp;
    BIO *in = NULL;

#ifdef OPENSSL_SYS_VMS
    in = VR_BIO_new_file(file, "r");
#else
    in = VR_BIO_new_file(file, "rb");
#endif
    if (in == NULL) {
        CONFerr(CONF_F_CONF_LOAD, ERR_R_SYS_LIB);
        return NULL;
    }

    ltmp = VR_CONF_load_bio(conf, in, eline);
    VR_BIO_free(in);

    return ltmp;
}

#ifndef OPENSSL_NO_STDIO
LHASH_OF(CONF_VALUE) *VR_CONF_load_fp(LHASH_OF(CONF_VALUE) *conf, FILE *fp,
                                   long *eline)
{
    BIO *btmp;
    LHASH_OF(CONF_VALUE) *ltmp;
    if ((btmp = VR_BIO_new_fp(fp, BIO_NOCLOSE)) == NULL) {
        CONFerr(CONF_F_CONF_LOAD_FP, ERR_R_BUF_LIB);
        return NULL;
    }
    ltmp = VR_CONF_load_bio(conf, btmp, eline);
    VR_BIO_free(btmp);
    return ltmp;
}
#endif

LHASH_OF(CONF_VALUE) *VR_CONF_load_bio(LHASH_OF(CONF_VALUE) *conf, BIO *bp,
                                    long *eline)
{
    CONF ctmp;
    int ret;

    VR_CONF_set_nconf(&ctmp, conf);

    ret = VR_NCONF_load_bio(&ctmp, bp, eline);
    if (ret)
        return ctmp.data;
    return NULL;
}

STACK_OF(CONF_VALUE) *VR_CONF_get_section(LHASH_OF(CONF_VALUE) *conf,
                                       const char *section)
{
    if (conf == NULL) {
        return NULL;
    } else {
        CONF ctmp;
        VR_CONF_set_nconf(&ctmp, conf);
        return VR_NCONF_get_section(&ctmp, section);
    }
}

char *VR_CONF_get_string(LHASH_OF(CONF_VALUE) *conf, const char *group,
                      const char *name)
{
    if (conf == NULL) {
        return VR_NCONF_get_string(NULL, group, name);
    } else {
        CONF ctmp;
        VR_CONF_set_nconf(&ctmp, conf);
        return VR_NCONF_get_string(&ctmp, group, name);
    }
}

long VR_CONF_get_number(LHASH_OF(CONF_VALUE) *conf, const char *group,
                     const char *name)
{
    int status;
    long result = 0;

    VR_ERR_set_mark();
    if (conf == NULL) {
        status = VR_NCONF_get_number_e(NULL, group, name, &result);
    } else {
        CONF ctmp;
        VR_CONF_set_nconf(&ctmp, conf);
        status = VR_NCONF_get_number_e(&ctmp, group, name, &result);
    }
    VR_ERR_pop_to_mark();
    return status == 0 ? 0L : result;
}

void VR_CONF_free(LHASH_OF(CONF_VALUE) *conf)
{
    CONF ctmp;
    VR_CONF_set_nconf(&ctmp, conf);
    VR_NCONF_free_data(&ctmp);
}

#ifndef OPENSSL_NO_STDIO
int VR_CONF_dump_fp(LHASH_OF(CONF_VALUE) *conf, FILE *out)
{
    BIO *btmp;
    int ret;

    if ((btmp = VR_BIO_new_fp(out, BIO_NOCLOSE)) == NULL) {
        CONFerr(CONF_F_CONF_DUMP_FP, ERR_R_BUF_LIB);
        return 0;
    }
    ret = VR_CONF_dump_bio(conf, btmp);
    VR_BIO_free(btmp);
    return ret;
}
#endif

int VR_CONF_dump_bio(LHASH_OF(CONF_VALUE) *conf, BIO *out)
{
    CONF ctmp;
    VR_CONF_set_nconf(&ctmp, conf);
    return VR_NCONF_dump_bio(&ctmp, out);
}

/*
 * The following section contains the "New CONF" functions.  They are
 * completely centralised around a new CONF structure that may contain
 * basically anything, but at least a method pointer and a table of data.
 * These functions are also written in terms of the bridge functions used by
 * the "CONF classic" functions, for consistency.
 */

CONF *VR_NCONF_new(CONF_METHOD *meth)
{
    CONF *ret;

    if (meth == NULL)
        meth = VR_NCONF_default();

    ret = meth->create(meth);
    if (ret == NULL) {
        CONFerr(CONF_F_NCONF_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    return ret;
}

void VR_NCONF_free(CONF *conf)
{
    if (conf == NULL)
        return;
    conf->meth->destroy(conf);
}

void VR_NCONF_free_data(CONF *conf)
{
    if (conf == NULL)
        return;
    conf->meth->destroy_data(conf);
}

int VR_NCONF_load(CONF *conf, const char *file, long *eline)
{
    if (conf == NULL) {
        CONFerr(CONF_F_NCONF_LOAD, CONF_R_NO_CONF);
        return 0;
    }

    return conf->meth->load(conf, file, eline);
}

#ifndef OPENSSL_NO_STDIO
int VR_NCONF_load_fp(CONF *conf, FILE *fp, long *eline)
{
    BIO *btmp;
    int ret;
    if ((btmp = VR_BIO_new_fp(fp, BIO_NOCLOSE)) == NULL) {
        CONFerr(CONF_F_NCONF_LOAD_FP, ERR_R_BUF_LIB);
        return 0;
    }
    ret = VR_NCONF_load_bio(conf, btmp, eline);
    VR_BIO_free(btmp);
    return ret;
}
#endif

int VR_NCONF_load_bio(CONF *conf, BIO *bp, long *eline)
{
    if (conf == NULL) {
        CONFerr(CONF_F_NCONF_LOAD_BIO, CONF_R_NO_CONF);
        return 0;
    }

    return conf->meth->load_bio(conf, bp, eline);
}

STACK_OF(CONF_VALUE) *VR_NCONF_get_section(const CONF *conf, const char *section)
{
    if (conf == NULL) {
        CONFerr(CONF_F_NCONF_GET_SECTION, CONF_R_NO_CONF);
        return NULL;
    }

    if (section == NULL) {
        CONFerr(CONF_F_NCONF_GET_SECTION, CONF_R_NO_SECTION);
        return NULL;
    }

    return VR__CONF_get_section_values(conf, section);
}

char *VR_NCONF_get_string(const CONF *conf, const char *group, const char *name)
{
    char *s = VR__CONF_get_string(conf, group, name);

    /*
     * Since we may get a value from an environment variable even if conf is
     * NULL, let's check the value first
     */
    if (s)
        return s;

    if (conf == NULL) {
        CONFerr(CONF_F_NCONF_GET_STRING,
                CONF_R_NO_CONF_OR_ENVIRONMENT_VARIABLE);
        return NULL;
    }
    CONFerr(CONF_F_NCONF_GET_STRING, CONF_R_NO_VALUE);
    VR_ERR_add_error_data(4, "group=", group, " name=", name);
    return NULL;
}

static int default_is_number(const CONF *conf, char c)
{
    return ossl_isdigit(c);
}

static int default_to_int(const CONF *conf, char c)
{
    return (int)(c - '0');
}

int VR_NCONF_get_number_e(const CONF *conf, const char *group, const char *name,
                       long *result)
{
    char *str;
    long res;
    int (*is_number)(const CONF *, char) = &default_is_number;
    int (*to_int)(const CONF *, char) = &default_to_int;

    if (result == NULL) {
        CONFerr(CONF_F_NCONF_GET_NUMBER_E, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    str = VR_NCONF_get_string(conf, group, name);

    if (str == NULL)
        return 0;

    if (conf != NULL) {
        if (conf->meth->is_number != NULL)
            is_number = conf->meth->is_number;
        if (conf->meth->to_int != NULL)
            to_int = conf->meth->to_int;
    }
    for (res = 0; is_number(conf, *str); str++) {
        const int d = to_int(conf, *str);

        if (res > (LONG_MAX - d) / 10L) {
            CONFerr(CONF_F_NCONF_GET_NUMBER_E, CONF_R_NUMBER_TOO_LARGE);
            return 0;
        }
        res = res * 10 + d;
    }

    *result = res;
    return 1;
}

#ifndef OPENSSL_NO_STDIO
int VR_NCONF_dump_fp(const CONF *conf, FILE *out)
{
    BIO *btmp;
    int ret;
    if ((btmp = VR_BIO_new_fp(out, BIO_NOCLOSE)) == NULL) {
        CONFerr(CONF_F_NCONF_DUMP_FP, ERR_R_BUF_LIB);
        return 0;
    }
    ret = VR_NCONF_dump_bio(conf, btmp);
    VR_BIO_free(btmp);
    return ret;
}
#endif

int VR_NCONF_dump_bio(const CONF *conf, BIO *out)
{
    if (conf == NULL) {
        CONFerr(CONF_F_NCONF_DUMP_BIO, CONF_R_NO_CONF);
        return 0;
    }

    return conf->meth->dump(conf, out);
}

/*
 * These routines call the C malloc/free, to avoid intermixing with
 * OpenSSL function pointers before the library is initialized.
 */
OPENSSL_INIT_SETTINGS *VR_OPENSSL_INIT_new(void)
{
    OPENSSL_INIT_SETTINGS *ret = malloc(sizeof(*ret));

    if (ret != NULL)
        memset(ret, 0, sizeof(*ret));
    ret->flags = DEFAULT_CONF_MFLAGS;

    return ret;
}


#ifndef OPENSSL_NO_STDIO
int VR_OPENSSL_INIT_set_config_filename(OPENSSL_INIT_SETTINGS *settings,
                                     const char *filename)
{
    char *newfilename = NULL;

    if (filename != NULL) {
        newfilename = strdup(filename);
        if (newfilename == NULL)
            return 0;
    }

    free(settings->filename);
    settings->filename = newfilename;

    return 1;
}

void VR_OPENSSL_INIT_set_config_file_flags(OPENSSL_INIT_SETTINGS *settings,
                                        unsigned long flags)
{
    settings->flags = flags;
}

int VR_OPENSSL_INIT_set_config_appname(OPENSSL_INIT_SETTINGS *settings,
                                    const char *appname)
{
    char *newappname = NULL;

    if (appname != NULL) {
        newappname = strdup(appname);
        if (newappname == NULL)
            return 0;
    }

    free(settings->appname);
    settings->appname = newappname;

    return 1;
}
#endif

void VR_OPENSSL_INIT_free(OPENSSL_INIT_SETTINGS *settings)
{
    free(settings->filename);
    free(settings->appname);
    free(settings);
}
