/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/conf.h>

static char *save_rand_file;

void app_RAND_load_conf(CONF *c, const char *section)
{
    const char *randfile = VR_NCONF_get_string(c, section, "RANDFILE");

    if (randfile == NULL) {
        VR_ERR_clear_error();
        return;
    }
    if (VR_RAND_load_file(randfile, -1) < 0) {
        VR_BIO_printf(bio_err, "Can't load %s into RNG\n", randfile);
        VR_ERR_print_errors(bio_err);
    }
    if (save_rand_file == NULL)
        save_rand_file = OPENSSL_strdup(randfile);
}

static int loadfiles(char *name)
{
    char *p;
    int last, ret = 1;

    for ( ; ; ) {
        last = 0;
        for (p = name; *p != '\0' && *p != LIST_SEPARATOR_CHAR; p++)
            continue;
        if (*p == '\0')
            last = 1;
        *p = '\0';
        if (VR_RAND_load_file(name, -1) < 0) {
            VR_BIO_printf(bio_err, "Can't load %s into RNG\n", name);
            VR_ERR_print_errors(bio_err);
            ret = 0;
        }
        if (last)
            break;
        name = p + 1;
        if (*name == '\0')
            break;
    }
    return ret;
}

void app_RAND_write(void)
{
    if (save_rand_file == NULL)
        return;
    if (VR_RAND_write_file(save_rand_file) == -1) {
        VR_BIO_printf(bio_err, "Cannot write random bytes:\n");
        VR_ERR_print_errors(bio_err);
    }
    OPENVR_SSL_free(save_rand_file);
    save_rand_file =  NULL;
}


/*
 * See comments in opt_verify for explanation of this.
 */
enum r_range { OPT_R_ENUM };

int opt_rand(int opt)
{
    switch ((enum r_range)opt) {
    case OPT_R__FIRST:
    case OPT_R__LAST:
        break;
    case OPT_R_RAND:
        return loadfiles(opt_arg());
        break;
    case OPT_R_WRITERAND:
        OPENVR_SSL_free(save_rand_file);
        save_rand_file = OPENSSL_strdup(opt_arg());
        break;
    }
    return 1;
}
