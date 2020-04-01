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
#include <stdio.h>
#include <string.h>

#include "../blacklist/ids_storedvalues.h"
#include "../blacklist/domain_blacklist.h"


static char * DOMAINS[] = {
    "nooblan.net",
    "reddit.com",
    "twitter.com"
};

static int
test_domain_blacklist_with_contents_releases_mem_on_cleanup()
{
    int i;
    domain_blacklist *bl = new_domain_blacklist();

    for (i = 0; i < 3; i++)
    {
        ids_ioc_value_t *val = new_ids_ioc_value(0xFF);
        domain_blacklist_add(bl, DOMAINS[i], val);
    }

    domain_blacklist_clear(bl);

    return 1;
}


int main(int argc, char **argv)
{
    int test_result = 1;
    test_result = test_result && test_domain_blacklist_with_contents_releases_mem_on_cleanup();

    return !test_result;
}
