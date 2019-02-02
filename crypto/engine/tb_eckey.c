/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "eng_int.h"

static ENGINE_TABLE *dh_table = NULL;
static const int dummy_nid = 1;

void VR_ENGINE_unregister_EC(ENGINE *e)
{
    VR_engine_table_unregister(&dh_table, e);
}

static void engine_unregister_all_EC(void)
{
    VR_engine_table_cleanup(&dh_table);
}

int VR_ENGINE_register_EC(ENGINE *e)
{
    if (e->ec_meth != NULL)
        return VR_engine_table_register(&dh_table,
                                     engine_unregister_all_EC, e, &dummy_nid,
                                     1, 0);
    return 1;
}

void VR_ENGINE_register_all_EC(void)
{
    ENGINE *e;

    for (e = VR_ENGINE_get_first(); e; e = VR_ENGINE_get_next(e))
        VR_ENGINE_register_EC(e);
}

int VR_ENGINE_set_default_EC(ENGINE *e)
{
    if (e->ec_meth != NULL)
        return VR_engine_table_register(&dh_table,
                                     engine_unregister_all_EC, e, &dummy_nid,
                                     1, 1);
    return 1;
}

/*
 * Exposed API function to get a functional reference from the implementation
 * table (ie. try to get a functional reference from the tabled structural
 * references).
 */
ENGINE *VR_ENGINE_get_default_EC(void)
{
    return VR_engine_table_select(&dh_table, dummy_nid);
}

/* Obtains an EC_KEY implementation from an ENGINE functional reference */
const EC_KEY_METHOD *VR_ENGINE_get_EC(const ENGINE *e)
{
    return e->ec_meth;
}

/* Sets an EC_KEY implementation in an ENGINE structure */
int VR_ENGINE_set_EC(ENGINE *e, const EC_KEY_METHOD *ec_meth)
{
    e->ec_meth = ec_meth;
    return 1;
}
