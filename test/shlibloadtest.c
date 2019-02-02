/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>
#include "internal/dso_conf.h"

typedef void DSO;

typedef const SSL_METHOD * (*VR_TLS_method_t)(void);
typedef SSL_CTX * (*VR_SSL_CTX_new_t)(const SSL_METHOD *meth);
typedef void (*VR_SSL_CTX_free_t)(SSL_CTX *);
typedef int (*VR_OPENSSL_init_crypto_t)(uint64_t, void *);
typedef int (*VR_OPENSSL_atexit_t)(void (*handler)(void));
typedef unsigned long (*VR_ERR_get_error_t)(void);
typedef unsigned long (*VR_OPENSSL_version_major_t)(void);
typedef unsigned long (*VR_OPENSSL_version_minor_t)(void);
typedef unsigned long (*VR_OPENSSL_version_patch_t)(void);
typedef DSO * (*VR_DSO_dsobyaddr_t)(void (*addr)(void), int flags);
typedef int (*VR_DSO_free_t)(DSO *dso);

typedef enum test_types_en {
    CRYPTO_FIRST,
    SSL_FIRST,
    JUST_CRYPTO,
    DSO_REFTEST,
    NO_ATEXIT
} TEST_TYPE;

static TEST_TYPE test_type;
static const char *path_crypto;
static const char *path_ssl;
static const char *path_atexit;

#ifdef DSO_DLFCN

# include <dlfcn.h>

# define SHLIB_INIT NULL

typedef void *SHLIB;
typedef void *SHLIB_SYM;

static int shlib_load(const char *filename, SHLIB *lib)
{
    int dl_flags = (RTLD_GLOBAL|RTLD_LAZY);
#ifdef _AIX
    if (filename[strlen(filename) - 1] == ')')
        dl_flags |= RTLD_MEMBER;
#endif
    *lib = dlopen(filename, dl_flags);
    return *lib == NULL ? 0 : 1;
}

static int shlib_sym(SHLIB lib, const char *symname, SHLIB_SYM *sym)
{
    *sym = dlsym(lib, symname);
    return *sym != NULL;
}

static int shlib_close(SHLIB lib)
{
    return dlclose(lib) != 0 ? 0 : 1;
}
#endif

#ifdef DSO_WIN32

# include <windows.h>

# define SHLIB_INIT 0

typedef HINSTANCE SHLIB;
typedef void *SHLIB_SYM;

static int shlib_load(const char *filename, SHLIB *lib)
{
    *lib = LoadLibraryA(filename);
    return *lib == NULL ? 0 : 1;
}

static int shlib_sym(SHLIB lib, const char *symname, SHLIB_SYM *sym)
{
    *sym = (SHLIB_SYM)GetProcAddress(lib, symname);
    return *sym != NULL;
}

static int shlib_close(SHLIB lib)
{
    return FreeLibrary(lib) == 0 ? 0 : 1;
}
#endif


#if defined(DSO_DLFCN) || defined(DSO_WIN32)

static int atexit_handler_done = 0;

static void atexit_handler(void)
{
    FILE *atexit_file = fopen(path_atexit, "w");

    if (atexit_file == NULL)
        return;

    fprintf(atexit_file, "atexit() run\n");
    fclose(atexit_file);
    atexit_handler_done++;
}

static int test_lib(void)
{
    SHLIB ssllib = SHLIB_INIT;
    SHLIB cryptolib = SHLIB_INIT;
    SSL_CTX *ctx;
    union {
        void (*func)(void);
        SHLIB_SYM sym;
    } symbols[5];
    VR_TLS_method_t myVR_TLS_method;
    VR_SSL_CTX_new_t myVR_SSL_CTX_new;
    VR_SSL_CTX_free_t myVR_SSL_CTX_free;
    VR_ERR_get_error_t myVR_ERR_get_error;
    VR_OPENSSL_version_major_t myVR_OPENSSL_version_major;
    VR_OPENSSL_version_minor_t myVR_OPENSSL_version_minor;
    VR_OPENSSL_version_patch_t myVR_OPENSSL_version_patch;
    VR_OPENSSL_atexit_t myVR_OPENSSL_atexit;
    int result = 0;

    switch (test_type) {
    case JUST_CRYPTO:
    case DSO_REFTEST:
    case NO_ATEXIT:
    case CRYPTO_FIRST:
        if (!shlib_load(path_crypto, &cryptolib)) {
            fprintf(stderr, "Failed to load libcrypto\n");
            goto end;
        }
        if (test_type != CRYPTO_FIRST)
            break;
        /* Fall through */

    case SSL_FIRST:
        if (!shlib_load(path_ssl, &ssllib)) {
            fprintf(stderr, "Failed to load libssl\n");
            goto end;
        }
        if (test_type != SSL_FIRST)
            break;
        if (!shlib_load(path_crypto, &cryptolib)) {
            fprintf(stderr, "Failed to load libcrypto\n");
            goto end;
        }
        break;
    }

    if (test_type == NO_ATEXIT) {
        VR_OPENSSL_init_crypto_t myVR_OPENSSL_init_crypto;

        if (!shlib_sym(cryptolib, "VR_OPENSSL_init_crypto", &symbols[0].sym)) {
            fprintf(stderr, "Failed to load VR_OPENSSL_init_crypto symbol\n");
            goto end;
        }
        myVR_OPENSSL_init_crypto = (VR_OPENSSL_init_crypto_t)symbols[0].func;
        if (!myVR_OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT, NULL)) {
            fprintf(stderr, "Failed to initialise libcrypto\n");
            goto end;
        }
    }

    if (test_type != JUST_CRYPTO
            && test_type != DSO_REFTEST
            && test_type != NO_ATEXIT) {
        if (!shlib_sym(ssllib, "VR_TLS_method", &symbols[0].sym)
                || !shlib_sym(ssllib, "VR_SSL_CTX_new", &symbols[1].sym)
                || !shlib_sym(ssllib, "VR_SSL_CTX_free", &symbols[2].sym)) {
            fprintf(stderr, "Failed to load libssl symbols\n");
            goto end;
        }
        myVR_TLS_method = (VR_TLS_method_t)symbols[0].func;
        myVR_SSL_CTX_new = (VR_SSL_CTX_new_t)symbols[1].func;
        myVR_SSL_CTX_free = (VR_SSL_CTX_free_t)symbols[2].func;
        ctx = myVR_SSL_CTX_new(myVR_TLS_method());
        if (ctx == NULL) {
            fprintf(stderr, "Failed to create SSL_CTX\n");
            goto end;
        }
        myVR_SSL_CTX_free(ctx);
    }

    if (!shlib_sym(cryptolib, "VR_ERR_get_error", &symbols[0].sym)
           || !shlib_sym(cryptolib, "VR_OPENSSL_version_major", &symbols[1].sym)
           || !shlib_sym(cryptolib, "VR_OPENSSL_version_minor", &symbols[2].sym)
           || !shlib_sym(cryptolib, "VR_OPENSSL_version_patch", &symbols[3].sym)
           || !shlib_sym(cryptolib, "VR_OPENSSL_atexit", &symbols[4].sym)) {
        fprintf(stderr, "Failed to load libcrypto symbols\n");
        goto end;
    }
    myVR_ERR_get_error = (VR_ERR_get_error_t)symbols[0].func;
    if (myVR_ERR_get_error() != 0) {
        fprintf(stderr, "Unexpected VR_ERR_get_error() response\n");
        goto end;
    }

    /* Library and header version should be identical in this test */
    myVR_OPENSSL_version_major = (VR_OPENSSL_version_major_t)symbols[1].func;
    myVR_OPENSSL_version_minor = (VR_OPENSSL_version_minor_t)symbols[2].func;
    myVR_OPENSSL_version_patch = (VR_OPENSSL_version_patch_t)symbols[3].func;
    if (myVR_OPENSSL_version_major() != OPENSSL_VERSION_MAJOR
            || myVR_OPENSSL_version_minor() != OPENSSL_VERSION_MINOR
            || myVR_OPENSSL_version_patch() != OPENSSL_VERSION_PATCH) {
        fprintf(stderr, "Invalid library version number\n");
        goto end;
    }

    myVR_OPENSSL_atexit = (VR_OPENSSL_atexit_t)symbols[4].func;
    if (!myVR_OPENSSL_atexit(atexit_handler)) {
        fprintf(stderr, "Failed to register atexit handler\n");
        goto end;
    }

    if (test_type == DSO_REFTEST) {
# ifdef DSO_DLFCN
        VR_DSO_dsobyaddr_t myVR_DSO_dsobyaddr;
        VR_DSO_free_t myVR_DSO_free;

        /*
         * This is resembling the code used in ossl_init_base() and
         * VR_OPENSSL_atexit() to block unloading the library after dlclose().
         * We are not testing this on Windows, because it is done there in a
         * completely different way. Especially as a call to VR_DSO_dsobyaddr()
         * will always return an error, because VR_DSO_pathbyaddr() is not
         * implemented there.
         */
        if (!shlib_sym(cryptolib, "VR_DSO_dsobyaddr", &symbols[0].sym)
                || !shlib_sym(cryptolib, "VR_DSO_free", &symbols[1].sym)) {
            fprintf(stderr, "Unable to load DSO symbols\n");
            goto end;
        }

        myVR_DSO_dsobyaddr = (VR_DSO_dsobyaddr_t)symbols[0].func;
        myVR_DSO_free = (VR_DSO_free_t)symbols[1].func;

        {
            DSO *hndl;
            /* use known symbol from crypto module */
            hndl = myVR_DSO_dsobyaddr((void (*)(void))myVR_ERR_get_error, 0);
            if (hndl == NULL) {
                fprintf(stderr, "VR_DSO_dsobyaddr() failed\n");
                goto end;
            }
            myVR_DSO_free(hndl);
        }
# endif /* DSO_DLFCN */
    }

    if (!shlib_close(cryptolib)) {
        fprintf(stderr, "Failed to close libcrypto\n");
        goto end;
    }

    if (test_type == CRYPTO_FIRST || test_type == SSL_FIRST) {
        if (!shlib_close(ssllib)) {
            fprintf(stderr, "Failed to close libssl\n");
            goto end;
        }
    }

# if defined(OPENSSL_NO_PINSHARED) \
    && defined(__GLIBC__) \
    && defined(__GLIBC_PREREQ) \
    && defined(OPENSSL_SYS_LINUX)
#  if __GLIBC_PREREQ(2, 3)
    /*
     * If we didn't pin the so then we are hopefully on a platform that supports
     * running atexit() on so unload. If not we might crash. We know this is
     * true on linux since glibc 2.2.3
     */
    if (test_type != NO_ATEXIT && atexit_handler_done != 1) {
        fprintf(stderr, "atexit() handler did not run\n");
        goto end;
    }
#  endif
# endif

    result = 1;
end:
    return result;
}
#endif


/*
 * shlibloadtest should not use the normal test framework because we don't want
 * it to link against libcrypto (which the framework uses). The point of the
 * test is to check dynamic loading and unloading of libcrypto/libssl.
 */
int main(int argc, char *argv[])
{
    const char *p;

    if (argc != 5) {
        fprintf(stderr, "Incorrect number of arguments\n");
        return 1;
    }

    p = argv[1];

    if (strcmp(p, "-crypto_first") == 0) {
        test_type = CRYPTO_FIRST;
    } else if (strcmp(p, "-ssl_first") == 0) {
        test_type = SSL_FIRST;
    } else if (strcmp(p, "-just_crypto") == 0) {
        test_type = JUST_CRYPTO;
    } else if (strcmp(p, "-dso_ref") == 0) {
        test_type = DSO_REFTEST;
    } else if (strcmp(p, "-no_atexit") == 0) {
        test_type = NO_ATEXIT;
    } else {
        fprintf(stderr, "Unrecognised argument\n");
        return 1;
    }
    path_crypto = argv[2];
    path_ssl = argv[3];
    path_atexit = argv[4];
    if (path_crypto == NULL || path_ssl == NULL) {
        fprintf(stderr, "Invalid libcrypto/libssl path\n");
        return 1;
    }

#if defined(DSO_DLFCN) || defined(DSO_WIN32)
    if (!test_lib())
        return 1;
#endif
    return 0;
}
