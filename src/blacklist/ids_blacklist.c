/*
 *
 * Copyright (c) 2020 The University of Waikato, Hamilton, New Zealand.
 *
 * This file is part of netstinky-ids.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-2-Clause
 *
 *
 */
#include "../error/ids_error.h"
#include "ids_blacklist.h"

int setup_ip_blacklist(ip_blacklist **bl)
{
    assert(bl);

    *bl = new_ip_blacklist();
    if (!*bl) goto error;

    return NSIDS_OK;
error:
    free_ip_blacklist(bl);
    return NSIDS_MEM;
}

/**
 * Open the domain blacklist provided at the command line and insert all domains into the blacklist
 * structure. Should only be run once. Checks that dn_bl is NULL so an existing data structure is
 * not leaked.
 */
int setup_domain_blacklist(domain_blacklist **bl)
{
    assert(bl);

    *bl = new_domain_blacklist();
    if (!*bl) goto error;

    return NSIDS_OK;

error:
    return NSIDS_MEM;
}
