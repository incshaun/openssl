/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef INTERNAL_ERR_INT_H
# define INTERNAL_ERR_INT_H

int VR_err_load_crypto_strings_int(void);
void VR_err_cleanup(void);
void VR_err_delete_thread_state(void);
int VR_err_shelve_state(void **);
void VR_err_unshelve_state(void *);

#endif
