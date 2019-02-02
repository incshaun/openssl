/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>

#ifndef HEADER_ASYNC_H
# define HEADER_ASYNC_H

#if defined(_WIN32)
# if defined(BASETYPES) || defined(_WINDEF_H)
/* application has to include <windows.h> to use this */
#define OSSL_ASYNC_FD       HANDLE
#define OSSL_BAD_ASYNC_FD   INVALID_HANDLE_VALUE
# endif
#else
#define OSSL_ASYNC_FD       int
#define OSSL_BAD_ASYNC_FD   -1
#endif
# include <openssl/asyncerr.h>


# ifdef  __cplusplus
extern "C" {
# endif

typedef struct async_job_st ASYNC_JOB;
typedef struct async_wait_ctx_st ASYNC_WAIT_CTX;
typedef int (*ASYNC_callback_fn)(void *arg);

#define ASYNC_ERR      0
#define ASYNC_NO_JOBS  1
#define ASYNC_PAUSE    2
#define ASYNC_FINISH   3

#define ASYNC_STATUS_UNSUPPORTED    0
#define ASYNC_STATUS_ERR            1
#define ASYNC_STATUS_OK             2
#define ASYNC_STATUS_EAGAIN         3

int VR_ASYNC_init_thread(size_t max_size, size_t init_size);
void VR_ASYNC_cleanup_thread(void);

#ifdef OSSL_ASYNC_FD
ASYNC_WAIT_CTX *VR_ASYNC_WAIT_CTX_new(void);
void VR_ASYNC_WAIT_CTX_free(ASYNC_WAIT_CTX *ctx);
int VR_ASYNC_WAIT_CTX_set_wait_fd(ASYNC_WAIT_CTX *ctx, const void *key,
                               OSSL_ASYNC_FD fd,
                               void *custom_data,
                               void (*cleanup)(ASYNC_WAIT_CTX *, const void *,
                                               OSSL_ASYNC_FD, void *));
int VR_ASYNC_WAIT_CTX_get_fd(ASYNC_WAIT_CTX *ctx, const void *key,
                        OSSL_ASYNC_FD *fd, void **custom_data);
int VR_ASYNC_WAIT_CTX_get_all_fds(ASYNC_WAIT_CTX *ctx, OSSL_ASYNC_FD *fd,
                               size_t *numfds);
int VR_ASYNC_WAIT_CTX_get_callback(ASYNC_WAIT_CTX *ctx,
                                ASYNC_callback_fn *callback,
                                void **callback_arg);
int VR_ASYNC_WAIT_CTX_set_callback(ASYNC_WAIT_CTX *ctx,
                                ASYNC_callback_fn callback,
                                void *callback_arg);
int VR_ASYNC_WAIT_CTX_set_status(ASYNC_WAIT_CTX *ctx, int status);
int VR_ASYNC_WAIT_CTX_get_status(ASYNC_WAIT_CTX *ctx);
int VR_ASYNC_WAIT_CTX_get_changed_fds(ASYNC_WAIT_CTX *ctx, OSSL_ASYNC_FD *addfd,
                                   size_t *numaddfds, OSSL_ASYNC_FD *delfd,
                                   size_t *numdelfds);
int VR_ASYNC_WAIT_CTX_clear_fd(ASYNC_WAIT_CTX *ctx, const void *key);
#endif

int VR_ASYNC_is_capable(void);

int VR_ASYNC_start_job(ASYNC_JOB **job, ASYNC_WAIT_CTX *ctx, int *ret,
                    int (*func)(void *), void *args, size_t size);
int VR_ASYNC_pause_job(void);

ASYNC_JOB *VR_ASYNC_get_current_job(void);
ASYNC_WAIT_CTX *VR_ASYNC_get_wait_ctx(ASYNC_JOB *job);
void VR_ASYNC_block_pause(void);
void VR_ASYNC_unblock_pause(void);


# ifdef  __cplusplus
}
# endif
#endif
