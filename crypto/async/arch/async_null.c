/*
 * Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* This must be the first #include file */
#include "../async_locl.h"

#ifdef ASYNC_NULL
int VR_ASYNC_is_capable(void)
{
    return 0;
}

void VR_async_local_cleanup(void)
{
}
#endif

