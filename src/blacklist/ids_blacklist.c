/*
 * ids_blacklist.c
 *
 *  Created on: 30/04/2019
 *      Author: mfletche
 */

#include "ids_blacklist.h"

int setup_ip_blacklist(ip_blacklist **bl)
{
    if (!bl) goto error;

    *bl = new_ip_blacklist();
    if (!*bl) goto error;

    return (1);
error:
    free_ip_blacklist(bl);
    return (0);
}

/**
 * Open the domain blacklist provided at the command line and insert all domains into the blacklist
 * structure. Should only be run once. Checks that dn_bl is NULL so an existing data structure is
 * not leaked.
 */
int setup_domain_blacklist(domain_blacklist **bl)
{

	if (!bl) goto error;
    *bl = new_domain_blacklist();
    if (!*bl) goto error;

	DPRINT("domain blacklist setup complete...\n");
	return 1;

error:
	return 0;
}
