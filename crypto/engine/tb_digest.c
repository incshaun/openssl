/*
 * Copyright 2001-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "eng_int.h"

static ENGINE_TABLE *digest_table = NULL;

void VR_ENGINE_unregister_digests(ENGINE *e)
{
    VR_engine_table_unregister(&digest_table, e);
}

static void engine_unregister_all_digests(void)
{
    VR_engine_table_cleanup(&digest_table);
}

int VR_ENGINE_register_digests(ENGINE *e)
{
    if (e->digests) {
        const int *nids;
        int num_nids = e->digests(e, NULL, &nids, 0);
        if (num_nids > 0)
            return VR_engine_table_register(&digest_table,
                                         engine_unregister_all_digests, e,
                                         nids, num_nids, 0);
    }
    return 1;
}

void VR_ENGINE_register_all_digests(void)
{
    ENGINE *e;

    for (e = VR_ENGINE_get_first(); e; e = VR_ENGINE_get_next(e))
        VR_ENGINE_register_digests(e);
}

int VR_ENGINE_set_default_digests(ENGINE *e)
{
    if (e->digests) {
        const int *nids;
        int num_nids = e->digests(e, NULL, &nids, 0);
        if (num_nids > 0)
            return VR_engine_table_register(&digest_table,
                                         engine_unregister_all_digests, e,
                                         nids, num_nids, 1);
    }
    return 1;
}

/*
 * Exposed API function to get a functional reference from the implementation
 * table (ie. try to get a functional reference from the tabled structural
 * references) for a given digest 'nid'
 */
ENGINE *VR_ENGINE_get_digest_engine(int nid)
{
    return VR_engine_table_select(&digest_table, nid);
}

/* Obtains a digest implementation from an ENGINE functional reference */
const EVP_MD *VR_ENGINE_get_digest(ENGINE *e, int nid)
{
    const EVP_MD *ret;
    ENGINE_DIGESTS_PTR fn = VR_ENGINE_get_digests(e);
    if (!fn || !fn(e, &ret, NULL, nid)) {
        ENGINEerr(ENGINE_F_ENGINE_GET_DIGEST, ENGINE_R_UNIMPLEMENTED_DIGEST);
        return NULL;
    }
    return ret;
}

/* Gets the digest callback from an ENGINE structure */
ENGINE_DIGESTS_PTR VR_ENGINE_get_digests(const ENGINE *e)
{
    return e->digests;
}

/* Sets the digest callback in an ENGINE structure */
int VR_ENGINE_set_digests(ENGINE *e, ENGINE_DIGESTS_PTR f)
{
    e->digests = f;
    return 1;
}
