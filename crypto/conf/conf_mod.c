/*
 * Copyright 2002-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include <stdio.h>
#include <ctype.h>
#include <openssl/crypto.h>
#include "internal/conf.h"
#include "internal/dso.h"
#include <openssl/x509.h>

#define DSO_mod_init_name "VR_OPENSSL_init"
#define DSO_mod_finish_name "OPENSSL_finish"

/*
 * This structure contains a data about supported modules. entries in this
 * table correspond to either dynamic or static modules.
 */

struct conf_module_st {
    /* DSO of this module or NULL if static */
    DSO *dso;
    /* Name of the module */
    char *name;
    /* Init function */
    conf_init_func *init;
    /* Finish function */
    conf_finish_func *finish;
    /* Number of successfully initialized modules */
    int links;
    void *usr_data;
};

/*
 * This structure contains information about modules that have been
 * successfully initialized. There may be more than one entry for a given
 * module.
 */

struct conf_imodule_st {
    CONF_MODULE *pmod;
    char *name;
    char *value;
    unsigned long flags;
    void *usr_data;
};

static STACK_OF(CONF_MODULE) *supported_modules = NULL;
static STACK_OF(CONF_IMODULE) *initialized_modules = NULL;

static void module_free(CONF_MODULE *md);
static void module_finish(CONF_IMODULE *imod);
static int module_run(const CONF *cnf, const char *name, const char *value,
                      unsigned long flags);
static CONF_MODULE *module_add(DSO *dso, const char *name,
                               conf_init_func *ifunc,
                               conf_finish_func *ffunc);
static CONF_MODULE *module_find(const char *name);
static int module_init(CONF_MODULE *pmod, const char *name, const char *value,
                       const CONF *cnf);
static CONF_MODULE *module_load_dso(const CONF *cnf, const char *name,
                                    const char *value);

/* Main function: load modules from a CONF structure */

int VR_CONF_modules_load(const CONF *cnf, const char *appname,
                      unsigned long flags)
{
    STACK_OF(CONF_VALUE) *values;
    CONF_VALUE *vl;
    char *vsection = NULL;

    int ret, i;

    if (!cnf)
        return 1;

    if (appname)
        vsection = VR_NCONF_get_string(cnf, NULL, appname);

    if (!appname || (!vsection && (flags & CONF_MFLAGS_DEFAULT_SECTION)))
        vsection = VR_NCONF_get_string(cnf, NULL, "openssl_conf");

    if (!vsection) {
        VR_ERR_clear_error();
        return 1;
    }

    values = VR_NCONF_get_section(cnf, vsection);

    if (!values)
        return 0;

    for (i = 0; i < sk_CONF_VALUE_num(values); i++) {
        vl = sk_CONF_VALUE_value(values, i);
        ret = module_run(cnf, vl->name, vl->value, flags);
        if (ret <= 0)
            if (!(flags & CONF_MFLAGS_IGNORE_ERRORS))
                return ret;
    }

    return 1;

}

int VR_CONF_modules_load_file(const char *filename, const char *appname,
                           unsigned long flags)
{
    char *file = NULL;
    CONF *conf = NULL;
    int ret = 0;
    conf = VR_NCONF_new(NULL);
    if (conf == NULL)
        goto err;

    if (filename == NULL) {
        file = VR_CONF_get1_default_config_file();
        if (!file)
            goto err;
    } else
        file = (char *)filename;

    if (VR_NCONF_load(conf, file, NULL) <= 0) {
        if ((flags & CONF_MFLAGS_IGNORE_MISSING_FILE) &&
            (ERR_GET_REASON(VR_ERR_peek_last_error()) == CONF_R_NO_SUCH_FILE)) {
            VR_ERR_clear_error();
            ret = 1;
        }
        goto err;
    }

    ret = VR_CONF_modules_load(conf, appname, flags);

 err:
    if (filename == NULL)
        OPENVR_SSL_free(file);
    VR_NCONF_free(conf);

    if (flags & CONF_MFLAGS_IGNORE_RETURN_CODES)
        return 1;

    return ret;
}

static int module_run(const CONF *cnf, const char *name, const char *value,
                      unsigned long flags)
{
    CONF_MODULE *md;
    int ret;

    md = module_find(name);

    /* Module not found: try to load DSO */
    if (!md && !(flags & CONF_MFLAGS_NO_DSO))
        md = module_load_dso(cnf, name, value);

    if (!md) {
        if (!(flags & CONF_MFLAGS_SILENT)) {
            CONFerr(CONF_F_MODULE_RUN, CONF_R_UNKNOWN_MODULE_NAME);
            VR_ERR_add_error_data(2, "module=", name);
        }
        return -1;
    }

    ret = module_init(md, name, value, cnf);

    if (ret <= 0) {
        if (!(flags & CONF_MFLAGS_SILENT)) {
            char rcode[DECIMAL_SIZE(ret) + 1];

            CONFerr(CONF_F_MODULE_RUN, CONF_R_MODULE_INITIALIZATION_ERROR);
            VR_BIO_snprintf(rcode, sizeof(rcode), "%-8d", ret);
            VR_ERR_add_error_data(6, "module=", name, ", value=", value,
                               ", retcode=", rcode);
        }
    }

    return ret;
}

/* Load a module from a DSO */
static CONF_MODULE *module_load_dso(const CONF *cnf,
                                    const char *name, const char *value)
{
    DSO *dso = NULL;
    conf_init_func *ifunc;
    conf_finish_func *ffunc;
    const char *path = NULL;
    int errcode = 0;
    CONF_MODULE *md;
    /* Look for alternative path in module section */
    path = VR_NCONF_get_string(cnf, value, "path");
    if (!path) {
        VR_ERR_clear_error();
        path = name;
    }
    dso = VR_DSO_load(NULL, path, NULL, 0);
    if (!dso) {
        errcode = CONF_R_ERROR_LOADING_DSO;
        goto err;
    }
    ifunc = (conf_init_func *)VR_DSO_bind_func(dso, DSO_mod_init_name);
    if (!ifunc) {
        errcode = CONF_R_MISSING_INIT_FUNCTION;
        goto err;
    }
    ffunc = (conf_finish_func *)VR_DSO_bind_func(dso, DSO_mod_finish_name);
    /* All OK, add module */
    md = module_add(dso, name, ifunc, ffunc);

    if (!md)
        goto err;

    return md;

 err:
    VR_DSO_free(dso);
    CONFerr(CONF_F_MODULE_LOAD_DSO, errcode);
    VR_ERR_add_error_data(4, "module=", name, ", path=", path);
    return NULL;
}

/* add module to list */
static CONF_MODULE *module_add(DSO *dso, const char *name,
                               conf_init_func *ifunc, conf_finish_func *ffunc)
{
    CONF_MODULE *tmod = NULL;
    if (supported_modules == NULL)
        supported_modules = sk_VR_CONF_MODULE_new_null();
    if (supported_modules == NULL)
        return NULL;
    if ((tmod = OPENSSL_zalloc(sizeof(*tmod))) == NULL) {
        CONFerr(CONF_F_MODULE_ADD, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    tmod->dso = dso;
    tmod->name = OPENSSL_strdup(name);
    tmod->init = ifunc;
    tmod->finish = ffunc;
    if (tmod->name == NULL) {
        OPENVR_SSL_free(tmod);
        return NULL;
    }

    if (!sk_VR_CONF_MODULE_push(supported_modules, tmod)) {
        OPENVR_SSL_free(tmod->name);
        OPENVR_SSL_free(tmod);
        return NULL;
    }

    return tmod;
}

/*
 * Find a module from the list. We allow module names of the form
 * modname.XXXX to just search for modname to allow the same module to be
 * initialized more than once.
 */

static CONF_MODULE *module_find(const char *name)
{
    CONF_MODULE *tmod;
    int i, nchar;
    char *p;
    p = strrchr(name, '.');

    if (p)
        nchar = p - name;
    else
        nchar = strlen(name);

    for (i = 0; i < sk_CONF_MODULE_num(supported_modules); i++) {
        tmod = sk_CONF_MODULE_value(supported_modules, i);
        if (strncmp(tmod->name, name, nchar) == 0)
            return tmod;
    }

    return NULL;

}

/* initialize a module */
static int module_init(CONF_MODULE *pmod, const char *name, const char *value,
                       const CONF *cnf)
{
    int ret = 1;
    int init_called = 0;
    CONF_IMODULE *imod = NULL;

    /* Otherwise add initialized module to list */
    imod = OPENSSL_malloc(sizeof(*imod));
    if (imod == NULL)
        goto err;

    imod->pmod = pmod;
    imod->name = OPENSSL_strdup(name);
    imod->value = OPENSSL_strdup(value);
    imod->usr_data = NULL;

    if (!imod->name || !imod->value)
        goto memerr;

    /* Try to initialize module */
    if (pmod->init) {
        ret = pmod->init(imod, cnf);
        init_called = 1;
        /* Error occurred, exit */
        if (ret <= 0)
            goto err;
    }

    if (initialized_modules == NULL) {
        initialized_modules = sk_VR_CONF_IMODULE_new_null();
        if (!initialized_modules) {
            CONFerr(CONF_F_MODULE_INIT, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }

    if (!sk_VR_CONF_IMODULE_push(initialized_modules, imod)) {
        CONFerr(CONF_F_MODULE_INIT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    pmod->links++;

    return ret;

 err:

    /* We've started the module so we'd better finish it */
    if (pmod->finish && init_called)
        pmod->finish(imod);

 memerr:
    if (imod) {
        OPENVR_SSL_free(imod->name);
        OPENVR_SSL_free(imod->value);
        OPENVR_SSL_free(imod);
    }

    return -1;

}

/*
 * Unload any dynamic modules that have a link count of zero: i.e. have no
 * active initialized modules. If 'all' is set then all modules are unloaded
 * including static ones.
 */

void VR_CONF_modules_unload(int all)
{
    int i;
    CONF_MODULE *md;
    VR_CONF_modules_finish();
    /* unload modules in reverse order */
    for (i = sk_CONF_MODULE_num(supported_modules) - 1; i >= 0; i--) {
        md = sk_CONF_MODULE_value(supported_modules, i);
        /* If static or in use and 'all' not set ignore it */
        if (((md->links > 0) || !md->dso) && !all)
            continue;
        /* Since we're working in reverse this is OK */
        (void)sk_CONF_MODULE_delete(supported_modules, i);
        module_free(md);
    }
    if (sk_CONF_MODULE_num(supported_modules) == 0) {
        sk_VR_CONF_MODULE_free(supported_modules);
        supported_modules = NULL;
    }
}

/* unload a single module */
static void module_free(CONF_MODULE *md)
{
    VR_DSO_free(md->dso);
    OPENVR_SSL_free(md->name);
    OPENVR_SSL_free(md);
}

/* finish and free up all modules instances */

void VR_CONF_modules_finish(void)
{
    CONF_IMODULE *imod;
    while (sk_CONF_IMODULE_num(initialized_modules) > 0) {
        imod = sk_VR_CONF_IMODULE_pop(initialized_modules);
        module_finish(imod);
    }
    sk_VR_CONF_IMODULE_free(initialized_modules);
    initialized_modules = NULL;
}

/* finish a module instance */

static void module_finish(CONF_IMODULE *imod)
{
    if (!imod)
        return;
    if (imod->pmod->finish)
        imod->pmod->finish(imod);
    imod->pmod->links--;
    OPENVR_SSL_free(imod->name);
    OPENVR_SSL_free(imod->value);
    OPENVR_SSL_free(imod);
}

/* Add a static module to OpenSSL */

int VR_CONF_module_add(const char *name, conf_init_func *ifunc,
                    conf_finish_func *ffunc)
{
    if (module_add(NULL, name, ifunc, ffunc))
        return 1;
    else
        return 0;
}

void VR_conf_modules_free_int(void)
{
    VR_CONF_modules_finish();
    VR_CONF_modules_unload(1);
}

/* Utility functions */

const char *VR_CONF_imodule_get_name(const CONF_IMODULE *md)
{
    return md->name;
}

const char *VR_CONF_imodule_get_value(const CONF_IMODULE *md)
{
    return md->value;
}

void *VR_CONF_imodule_get_usr_data(const CONF_IMODULE *md)
{
    return md->usr_data;
}

void VR_CONF_imodule_set_usr_data(CONF_IMODULE *md, void *usr_data)
{
    md->usr_data = usr_data;
}

CONF_MODULE *VR_CONF_imodule_get_module(const CONF_IMODULE *md)
{
    return md->pmod;
}

unsigned long VR_CONF_imodule_get_flags(const CONF_IMODULE *md)
{
    return md->flags;
}

void VR_CONF_imodule_set_flags(CONF_IMODULE *md, unsigned long flags)
{
    md->flags = flags;
}

void *VR_CONF_module_get_usr_data(CONF_MODULE *pmod)
{
    return pmod->usr_data;
}

void VR_CONF_module_set_usr_data(CONF_MODULE *pmod, void *usr_data)
{
    pmod->usr_data = usr_data;
}

/* Return default config file name */

char *VR_CONF_get1_default_config_file(void)
{
    char *file, *sep = "";
    int len;

    if ((file = VR_ossl_safe_getenv("OPENSSL_CONF")) != NULL)
        return OPENSSL_strdup(file);

    len = strlen(VR_X509_get_default_cert_area());
#ifndef OPENSSL_SYS_VMS
    len++;
    sep = "/";
#endif
    len += strlen(OPENSSL_CONF);

    file = OPENSSL_malloc(len + 1);

    if (file == NULL)
        return NULL;
    VR_BIO_snprintf(file, len + 1, "%s%s%s", VR_X509_get_default_cert_area(),
                 sep, OPENSSL_CONF);

    return file;
}

/*
 * This function takes a list separated by 'sep' and calls the callback
 * function giving the start and length of each member optionally stripping
 * leading and trailing whitespace. This can be used to parse comma separated
 * lists for example.
 */

int VR_CONF_parse_list(const char *list_, int sep, int nospc,
                    int (*list_cb) (const char *elem, int len, void *usr),
                    void *arg)
{
    int ret;
    const char *lstart, *tmpend, *p;

    if (list_ == NULL) {
        CONFerr(CONF_F_CONF_PARSE_LIST, CONF_R_LIST_CANNOT_BE_NULL);
        return 0;
    }

    lstart = list_;
    for (;;) {
        if (nospc) {
            while (*lstart && isspace((unsigned char)*lstart))
                lstart++;
        }
        p = strchr(lstart, sep);
        if (p == lstart || !*lstart)
            ret = list_cb(NULL, 0, arg);
        else {
            if (p)
                tmpend = p - 1;
            else
                tmpend = lstart + strlen(lstart) - 1;
            if (nospc) {
                while (isspace((unsigned char)*tmpend))
                    tmpend--;
            }
            ret = list_cb(lstart, tmpend - lstart + 1, arg);
        }
        if (ret <= 0)
            return ret;
        if (p == NULL)
            return 1;
        lstart = p + 1;
    }
}
