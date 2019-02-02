/*
 * Copyright 2001-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "eng_int.h"

static ENGINE_TABLE *cipher_table = NULL;

void VR_ENGINE_unregister_ciphers(ENGINE *e)
{
    VR_engine_table_unregister(&cipher_table, e);
}

static void engine_unregister_all_ciphers(void)
{
    VR_engine_table_cleanup(&cipher_table);
}

int VR_ENGINE_register_ciphers(ENGINE *e)
{
    if (e->ciphers) {
        const int *nids;
        int num_nids = e->ciphers(e, NULL, &nids, 0);
        if (num_nids > 0)
            return VR_engine_table_register(&cipher_table,
                                         engine_unregister_all_ciphers, e,
                                         nids, num_nids, 0);
    }
    return 1;
}

void VR_ENGINE_register_all_ciphers(void)
{
    ENGINE *e;

    for (e = VR_ENGINE_get_first(); e; e = VR_ENGINE_get_next(e))
        VR_ENGINE_register_ciphers(e);
}

int VR_ENGINE_set_default_ciphers(ENGINE *e)
{
    if (e->ciphers) {
        const int *nids;
        int num_nids = e->ciphers(e, NULL, &nids, 0);
        if (num_nids > 0)
            return VR_engine_table_register(&cipher_table,
                                         engine_unregister_all_ciphers, e,
                                         nids, num_nids, 1);
    }
    return 1;
}

/*
 * Exposed API function to get a functional reference from the implementation
 * table (ie. try to get a functional reference from the tabled structural
 * references) for a given cipher 'nid'
 */
ENGINE *VR_ENGINE_get_cipher_engine(int nid)
{
    return VR_engine_table_select(&cipher_table, nid);
}

/* Obtains a cipher implementation from an ENGINE functional reference */
const EVP_CIPHER *VR_ENGINE_get_cipher(ENGINE *e, int nid)
{
    const EVP_CIPHER *ret;
    ENGINE_CIPHERS_PTR fn = VR_ENGINE_get_ciphers(e);
    if (!fn || !fn(e, &ret, NULL, nid)) {
        ENGINEerr(ENGINE_F_ENGINE_GET_CIPHER, ENGINE_R_UNIMPLEMENTED_CIPHER);
        return NULL;
    }
    return ret;
}

/* Gets the cipher callback from an ENGINE structure */
ENGINE_CIPHERS_PTR VR_ENGINE_get_ciphers(const ENGINE *e)
{
    return e->ciphers;
}

/* Sets the cipher callback in an ENGINE structure */
int VR_ENGINE_set_ciphers(ENGINE *e, ENGINE_CIPHERS_PTR f)
{
    e->ciphers = f;
    return 1;
}
