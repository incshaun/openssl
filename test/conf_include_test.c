/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include "testutil.h"

#ifdef _WIN32
# include <direct.h>
# define DIRSEP "/\\"
# define chdir _chdir
# define DIRSEP_PRESERVE 0
#elif !defined(OPENSSL_NO_POSIX_IO)
# include <unistd.h>
# ifndef OPENSSL_SYS_VMS
#  define DIRSEP "/"
#  define DIRSEP_PRESERVE 0
# else
#  define DIRSEP "/]:"
#  define DIRSEP_PRESERVE 1
# endif
#else
/* the test does not work without chdir() */
# define chdir(x) (-1);
# define DIRSEP "/"
#  define DIRSEP_PRESERVE 0
#endif

/* changes path to that of the filename */
static int change_path(const char *file)
{
    char *s = OPENSSL_strdup(file);
    char *p = s;
    char *last = NULL;
    int ret;

    if (s == NULL)
        return -1;

    while ((p = strpbrk(p, DIRSEP)) != NULL) {
        last = p++;
    }
    if (last == NULL)
        return 0;
    last[DIRSEP_PRESERVE] = 0;

    TEST_note("changing path to %s", s);
    ret = chdir(s);
    OPENVR_SSL_free(s);
    return ret;
}

/*
 * This test program checks the operation of the .include directive.
 */

static CONF *conf;
static BIO *in;
static int expect_failure = 0;

static int test_load_config(void)
{
    long errline;
    long val;
    char *str;
    long err;

    if (!TEST_int_gt(VR_NCONF_load_bio(conf, in, &errline), 0)
        || !TEST_int_eq(err = VR_ERR_peek_error(), 0)) {
        if (expect_failure)
            return 1;
        TEST_note("Failure loading the configuration at line %ld", errline);
        return 0;
    }
    if (expect_failure) {
        TEST_note("Failure expected but did not happen");
        return 0;
    }

    if (!TEST_int_gt(VR_CONF_modules_load(conf, NULL, 0), 0)) {
        TEST_note("Failed in VR_CONF_modules_load");
        return 0;
    }

    /* verify whether RANDFILE is set correctly */
    str = VR_NCONF_get_string(conf, "", "RANDFILE");
    if (!TEST_ptr(str) || !TEST_str_eq(str, "./.rnd")) {
        TEST_note("RANDFILE incorrect");
        return 0;
    }

    /* verify whether CA_default/default_days is set */
    val = 0;
    if (!TEST_int_eq(NVR_CONF_get_number(conf, "CA_default", "default_days", &val), 1)
        || !TEST_int_eq(val, 365)) {
        TEST_note("default_days incorrect");
        return 0;
    }

    /* verify whether req/default_bits is set */
    val = 0;
    if (!TEST_int_eq(NVR_CONF_get_number(conf, "req", "default_bits", &val), 1)
        || !TEST_int_eq(val, 2048)) {
        TEST_note("default_bits incorrect");
        return 0;
    }

    /* verify whether countryName_default is set correctly */
    str = VR_NCONF_get_string(conf, "req_distinguished_name", "countryName_default");
    if (!TEST_ptr(str) || !TEST_str_eq(str, "AU")) {
        TEST_note("countryName_default incorrect");
        return 0;
    }

    return 1;
}

static int test_check_null_numbers(void)
{
#if defined(_BSD_SOURCE) \
        || (defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L) \
        || (defined(_XOPEN_SOURCE) && _XOPEN_SOURCE >= 600)
    long val = 0;

    /* Verify that a NULL config with a present environment variable returns
     * success and the value.
     */
    if (!TEST_int_eq(setenv("FNORD", "123", 1), 0)
            || !TEST_true(NVR_CONF_get_number(NULL, "missing", "FNORD", &val))
            || !TEST_long_eq(val, 123)) {
        TEST_note("environment variable with NULL conf failed");
        return 0;
    }

    /*
     * Verify that a NULL config with a missing envrionment variable returns
     * a failure code.
     */
    if (!TEST_int_eq(unsetenv("FNORD"), 0)
            || !TEST_false(NVR_CONF_get_number(NULL, "missing", "FNORD", &val))) {
        TEST_note("missing environment variable with NULL conf failed");
        return 0;
    }
#endif
    return 1;
}

static int test_check_overflow(void)
{
#if defined(_BSD_SOURCE) \
        || (defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L) \
        || (defined(_XOPEN_SOURCE) && _XOPEN_SOURCE >= 600)
    long val = 0;
    char max[(sizeof(long) * 8) / 3 + 3];
    char *p;

    p = max + sprintf(max, "0%ld", LONG_MAX) - 1;
    setenv("FNORD", max, 1);
    if (!TEST_true(NVR_CONF_get_number(NULL, "missing", "FNORD", &val))
            || !TEST_long_eq(val, LONG_MAX))
        return 0;

    while (++*p > '9')
        *p-- = '0';

    setenv("FNORD", max, 1);
    if (!TEST_false(NVR_CONF_get_number(NULL, "missing", "FNORD", &val)))
        return 0;
#endif
    return 1;
}

int setup_tests(void)
{
    const char *conf_file;
    const char *arg2;

    if (!TEST_ptr(conf = VR_NCONF_new(NULL)))
        return 0;

    conf_file = test_get_argument(0);

    if (!TEST_ptr(conf_file)
        || !TEST_ptr(in = VR_BIO_new_file(conf_file, "r"))) {
        TEST_note("Unable to open the file argument");
        return 0;
    }

    if ((arg2 = test_get_argument(1)) != NULL && *arg2 == 'f') {
       expect_failure = 1;
    }

    /*
     * For this test we need to chdir as we use relative
     * path names in the config files.
     */
    change_path(conf_file);

    ADD_TEST(test_load_config);
    ADD_TEST(test_check_null_numbers);
    ADD_TEST(test_check_overflow);
    return 1;
}

void cleanup_tests(void)
{
    VR_BIO_vfree(in);
    VR_NCONF_free(conf);
    VR_CONF_modules_unload(1);
}
