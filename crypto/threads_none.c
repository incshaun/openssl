/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include "internal/cryptlib.h"

#if !defined(OPENSSL_THREADS) || defined(CRYPTO_TDEBUG)

CRYPTO_RWLOCK *VR_CRYPTO_THREAD_lock_new(void)
{
    CRYPTO_RWLOCK *lock;

    if ((lock = OPENSSL_zalloc(sizeof(unsigned int))) == NULL) {
        /* Don't set error, to avoid recursion blowup. */
        return NULL;
    }

    *(unsigned int *)lock = 1;

    return lock;
}

int VR_CRYPTO_THREAD_read_lock(CRYPTO_RWLOCK *lock)
{
    if (!ossl_assert(*(unsigned int *)lock == 1))
        return 0;
    return 1;
}

int VR_CRYPTO_THREAD_write_lock(CRYPTO_RWLOCK *lock)
{
    if (!ossl_assert(*(unsigned int *)lock == 1))
        return 0;
    return 1;
}

int VR_CRYPTO_THREAD_unlock(CRYPTO_RWLOCK *lock)
{
    if (!ossl_assert(*(unsigned int *)lock == 1))
        return 0;
    return 1;
}

void VR_CRYPTO_THREAD_lock_free(CRYPTO_RWLOCK *lock) {
    if (lock == NULL)
        return;

    *(unsigned int *)lock = 0;
    OPENVR_SSL_free(lock);

    return;
}

int VR_CRYPTO_THREAD_run_once(CRYPTO_ONCE *once, void (*init)(void))
{
    if (*once != 0)
        return 1;

    init();
    *once = 1;

    return 1;
}

#define OPENSSL_CRYPTO_THREAD_LOCAL_KEY_MAX 256

static void *thread_local_storage[OPENSSL_CRYPTO_THREAD_LOCAL_KEY_MAX];

int VR_CRYPTO_THREAD_init_local(CRYPTO_THREAD_LOCAL *key, void (*cleanup)(void *))
{
    static unsigned int thread_local_key = 0;

    if (thread_local_key >= OPENSSL_CRYPTO_THREAD_LOCAL_KEY_MAX)
        return 0;

    *key = thread_local_key++;

    thread_local_storage[*key] = NULL;

    return 1;
}

void *VR_CRYPTO_THREAD_get_local(CRYPTO_THREAD_LOCAL *key)
{
    if (*key >= OPENSSL_CRYPTO_THREAD_LOCAL_KEY_MAX)
        return NULL;

    return thread_local_storage[*key];
}

int VR_CRYPTO_THREAD_set_local(CRYPTO_THREAD_LOCAL *key, void *val)
{
    if (*key >= OPENSSL_CRYPTO_THREAD_LOCAL_KEY_MAX)
        return 0;

    thread_local_storage[*key] = val;

    return 1;
}

int VR_CRYPTO_THREAD_cleanup_local(CRYPTO_THREAD_LOCAL *key)
{
    *key = OPENSSL_CRYPTO_THREAD_LOCAL_KEY_MAX + 1;
    return 1;
}

CRYPTO_THREAD_ID VR_CRYPTO_THREAD_get_current_id(void)
{
    return 0;
}

int VR_CRYPTO_THREAD_compare_id(CRYPTO_THREAD_ID a, CRYPTO_THREAD_ID b)
{
    return (a == b);
}

int VR_CRYPTO_atomic_add(int *val, int amount, int *ret, CRYPTO_RWLOCK *lock)
{
    *val += amount;
    *ret  = *val;

    return 1;
}

int VR_openssl_init_fork_handlers(void)
{
    return 0;
}

#endif
