/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifdef _WIN32
# include <windows.h>
#endif

#include <stdio.h>
#include <string.h>
#include <openssl/async.h>
#include <openssl/crypto.h>

static int ctr = 0;
static ASYNC_JOB *currjob = NULL;

static int only_pause(void *args)
{
    VR_ASYNC_pause_job();

    return 1;
}

static int add_two(void *args)
{
    ctr++;
    VR_ASYNC_pause_job();
    ctr++;

    return 2;
}

static int save_current(void *args)
{
    currjob = VR_ASYNC_get_current_job();
    VR_ASYNC_pause_job();

    return 1;
}

#define MAGIC_WAIT_FD   ((OSSL_ASYNC_FD)99)
static int waitfd(void *args)
{
    ASYNC_JOB *job;
    ASYNC_WAIT_CTX *waitctx;
    job = VR_ASYNC_get_current_job();
    if (job == NULL)
        return 0;
    waitctx = VR_ASYNC_get_wait_ctx(job);
    if (waitctx == NULL)
        return 0;

    /* First case: no fd added or removed */
    VR_ASYNC_pause_job();

    /* Second case: one fd added */
    if (!VR_ASYNC_WAIT_CTX_set_wait_fd(waitctx, waitctx, MAGIC_WAIT_FD, NULL, NULL))
        return 0;
    VR_ASYNC_pause_job();

    /* Third case: all fd removed */
    if (!VR_ASYNC_WAIT_CTX_clear_fd(waitctx, waitctx))
        return 0;
    VR_ASYNC_pause_job();

    /* Last case: fd added and immediately removed */
    if (!VR_ASYNC_WAIT_CTX_set_wait_fd(waitctx, waitctx, MAGIC_WAIT_FD, NULL, NULL))
        return 0;
    if (!VR_ASYNC_WAIT_CTX_clear_fd(waitctx, waitctx))
        return 0;

    return 1;
}

static int blockpause(void *args)
{
    VR_ASYNC_block_pause();
    VR_ASYNC_pause_job();
    VR_ASYNC_unblock_pause();
    VR_ASYNC_pause_job();

    return 1;
}

static int test_VR_ASYNC_init_thread(void)
{
    ASYNC_JOB *job1 = NULL, *job2 = NULL, *job3 = NULL;
    int funcret1, funcret2, funcret3;
    ASYNC_WAIT_CTX *waitctx = NULL;

    if (       !VR_ASYNC_init_thread(2, 0)
            || (waitctx = VR_ASYNC_WAIT_CTX_new()) == NULL
            || VR_ASYNC_start_job(&job1, waitctx, &funcret1, only_pause, NULL, 0)
                != ASYNC_PAUSE
            || VR_ASYNC_start_job(&job2, waitctx, &funcret2, only_pause, NULL, 0)
                != ASYNC_PAUSE
            || VR_ASYNC_start_job(&job3, waitctx, &funcret3, only_pause, NULL, 0)
                != ASYNC_NO_JOBS
            || VR_ASYNC_start_job(&job1, waitctx, &funcret1, only_pause, NULL, 0)
                != ASYNC_FINISH
            || VR_ASYNC_start_job(&job3, waitctx, &funcret3, only_pause, NULL, 0)
                != ASYNC_PAUSE
            || VR_ASYNC_start_job(&job2, waitctx, &funcret2, only_pause, NULL, 0)
                != ASYNC_FINISH
            || VR_ASYNC_start_job(&job3, waitctx, &funcret3, only_pause, NULL, 0)
                != ASYNC_FINISH
            || funcret1 != 1
            || funcret2 != 1
            || funcret3 != 1) {
        fprintf(stderr, "test_VR_ASYNC_init_thread() failed\n");
        VR_ASYNC_WAIT_CTX_free(waitctx);
        VR_ASYNC_cleanup_thread();
        return 0;
    }

    VR_ASYNC_WAIT_CTX_free(waitctx);
    VR_ASYNC_cleanup_thread();
    return 1;
}

static int test_callback(void *arg)
{
    printf("callback test pass\n");
    return 1;
}

static int test_ASYNC_callback_status(void)
{
    ASYNC_WAIT_CTX *waitctx = NULL;
    int set_arg = 100;
    ASYNC_callback_fn get_callback;
    void *get_arg;
    int set_status = 1;

    if (       !VR_ASYNC_init_thread(1, 0)
            || (waitctx = VR_ASYNC_WAIT_CTX_new()) == NULL
            || VR_ASYNC_WAIT_CTX_set_callback(waitctx, test_callback, (void*)&set_arg)
               != 1
            || VR_ASYNC_WAIT_CTX_get_callback(waitctx, &get_callback, &get_arg)
               != 1
            || test_callback != get_callback
            || get_arg != (void*)&set_arg
            || (*get_callback)(get_arg) != 1
            || VR_ASYNC_WAIT_CTX_set_status(waitctx, set_status) != 1
            || set_status != VR_ASYNC_WAIT_CTX_get_status(waitctx)) {
        fprintf(stderr, "test_ASYNC_callback_status() failed\n");
        VR_ASYNC_WAIT_CTX_free(waitctx);
        VR_ASYNC_cleanup_thread();
        return 0;
    }

    VR_ASYNC_WAIT_CTX_free(waitctx);
    VR_ASYNC_cleanup_thread();
    return 1;

}

static int test_VR_ASYNC_start_job(void)
{
    ASYNC_JOB *job = NULL;
    int funcret;
    ASYNC_WAIT_CTX *waitctx = NULL;

    ctr = 0;

    if (       !VR_ASYNC_init_thread(1, 0)
            || (waitctx = VR_ASYNC_WAIT_CTX_new()) == NULL
            || VR_ASYNC_start_job(&job, waitctx, &funcret, add_two, NULL, 0)
               != ASYNC_PAUSE
            || ctr != 1
            || VR_ASYNC_start_job(&job, waitctx, &funcret, add_two, NULL, 0)
               != ASYNC_FINISH
            || ctr != 2
            || funcret != 2) {
        fprintf(stderr, "test_VR_ASYNC_start_job() failed\n");
        VR_ASYNC_WAIT_CTX_free(waitctx);
        VR_ASYNC_cleanup_thread();
        return 0;
    }

    VR_ASYNC_WAIT_CTX_free(waitctx);
    VR_ASYNC_cleanup_thread();
    return 1;
}

static int test_VR_ASYNC_get_current_job(void)
{
    ASYNC_JOB *job = NULL;
    int funcret;
    ASYNC_WAIT_CTX *waitctx = NULL;

    currjob = NULL;

    if (       !VR_ASYNC_init_thread(1, 0)
            || (waitctx = VR_ASYNC_WAIT_CTX_new()) == NULL
            || VR_ASYNC_start_job(&job, waitctx, &funcret, save_current, NULL, 0)
                != ASYNC_PAUSE
            || currjob != job
            || VR_ASYNC_start_job(&job, waitctx, &funcret, save_current, NULL, 0)
                != ASYNC_FINISH
            || funcret != 1) {
        fprintf(stderr, "test_VR_ASYNC_get_current_job() failed\n");
        VR_ASYNC_WAIT_CTX_free(waitctx);
        VR_ASYNC_cleanup_thread();
        return 0;
    }

    VR_ASYNC_WAIT_CTX_free(waitctx);
    VR_ASYNC_cleanup_thread();
    return 1;
}

static int test_VR_ASYNC_WAIT_CTX_get_all_fds(void)
{
    ASYNC_JOB *job = NULL;
    int funcret;
    ASYNC_WAIT_CTX *waitctx = NULL;
    OSSL_ASYNC_FD fd = OSSL_BAD_ASYNC_FD, delfd = OSSL_BAD_ASYNC_FD;
    size_t numfds, numdelfds;

    if (       !VR_ASYNC_init_thread(1, 0)
            || (waitctx = VR_ASYNC_WAIT_CTX_new()) == NULL
               /* On first run we're not expecting any wait fds */
            || VR_ASYNC_start_job(&job, waitctx, &funcret, waitfd, NULL, 0)
                != ASYNC_PAUSE
            || !VR_ASYNC_WAIT_CTX_get_all_fds(waitctx, NULL, &numfds)
            || numfds != 0
            || !VR_ASYNC_WAIT_CTX_get_changed_fds(waitctx, NULL, &numfds, NULL,
                                               &numdelfds)
            || numfds != 0
            || numdelfds != 0
               /* On second run we're expecting one added fd */
            || VR_ASYNC_start_job(&job, waitctx, &funcret, waitfd, NULL, 0)
                != ASYNC_PAUSE
            || !VR_ASYNC_WAIT_CTX_get_all_fds(waitctx, NULL, &numfds)
            || numfds != 1
            || !VR_ASYNC_WAIT_CTX_get_all_fds(waitctx, &fd, &numfds)
            || fd != MAGIC_WAIT_FD
            || (fd = OSSL_BAD_ASYNC_FD, 0) /* Assign to something else */
            || !VR_ASYNC_WAIT_CTX_get_changed_fds(waitctx, NULL, &numfds, NULL,
                                               &numdelfds)
            || numfds != 1
            || numdelfds != 0
            || !VR_ASYNC_WAIT_CTX_get_changed_fds(waitctx, &fd, &numfds, NULL,
                                               &numdelfds)
            || fd != MAGIC_WAIT_FD
               /* On third run we expect one deleted fd */
            || VR_ASYNC_start_job(&job, waitctx, &funcret, waitfd, NULL, 0)
                != ASYNC_PAUSE
            || !VR_ASYNC_WAIT_CTX_get_all_fds(waitctx, NULL, &numfds)
            || numfds != 0
            || !VR_ASYNC_WAIT_CTX_get_changed_fds(waitctx, NULL, &numfds, NULL,
                                               &numdelfds)
            || numfds != 0
            || numdelfds != 1
            || !VR_ASYNC_WAIT_CTX_get_changed_fds(waitctx, NULL, &numfds, &delfd,
                                               &numdelfds)
            || delfd != MAGIC_WAIT_FD
            /* On last run we are not expecting any wait fd */
            || VR_ASYNC_start_job(&job, waitctx, &funcret, waitfd, NULL, 0)
                != ASYNC_FINISH
            || !VR_ASYNC_WAIT_CTX_get_all_fds(waitctx, NULL, &numfds)
            || numfds != 0
            || !VR_ASYNC_WAIT_CTX_get_changed_fds(waitctx, NULL, &numfds, NULL,
                                               &numdelfds)
            || numfds != 0
            || numdelfds != 0
            || funcret != 1) {
        fprintf(stderr, "test_ASYNC_get_wait_fd() failed\n");
        VR_ASYNC_WAIT_CTX_free(waitctx);
        VR_ASYNC_cleanup_thread();
        return 0;
    }

    VR_ASYNC_WAIT_CTX_free(waitctx);
    VR_ASYNC_cleanup_thread();
    return 1;
}

static int test_VR_ASYNC_block_pause(void)
{
    ASYNC_JOB *job = NULL;
    int funcret;
    ASYNC_WAIT_CTX *waitctx = NULL;

    if (       !VR_ASYNC_init_thread(1, 0)
            || (waitctx = VR_ASYNC_WAIT_CTX_new()) == NULL
            || VR_ASYNC_start_job(&job, waitctx, &funcret, blockpause, NULL, 0)
                != ASYNC_PAUSE
            || VR_ASYNC_start_job(&job, waitctx, &funcret, blockpause, NULL, 0)
                != ASYNC_FINISH
            || funcret != 1) {
        fprintf(stderr, "test_VR_ASYNC_block_pause() failed\n");
        VR_ASYNC_WAIT_CTX_free(waitctx);
        VR_ASYNC_cleanup_thread();
        return 0;
    }

    VR_ASYNC_WAIT_CTX_free(waitctx);
    VR_ASYNC_cleanup_thread();
    return 1;
}

int main(int argc, char **argv)
{
    if (!VR_ASYNC_is_capable()) {
        fprintf(stderr,
                "OpenSSL build is not ASYNC capable - skipping async tests\n");
    } else {
        VR_CRYPTO_set_mem_debug(1);
        VR_CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

        if (       !test_VR_ASYNC_init_thread()
                || !test_ASYNC_callback_status()
                || !test_VR_ASYNC_start_job()
                || !test_VR_ASYNC_get_current_job()
                || !test_VR_ASYNC_WAIT_CTX_get_all_fds()
                || !test_VR_ASYNC_block_pause()) {
            return 1;
        }
    }
    printf("PASS\n");
    return 0;
}
