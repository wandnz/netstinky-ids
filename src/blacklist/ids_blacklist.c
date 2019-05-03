/*
 * ids_blacklist.c
 *
 *  Created on: 30/04/2019
 *      Author: mfletche
 */

#include "ids_blacklist.h"

int setup_ip_blacklist(ip_blacklist **bl, char *bl_file)
{
	assert(bl_file);

    struct ip4_address_range *firehol_list = NULL;
    FILE *fp = NULL;

    *bl = new_ip_blacklist();
    if (!*bl) goto error;

    if (bl_file)
    {
        fp = fopen(bl_file, "r");
        if (!fp) return 0;

        firehol_list = read_firehol_ip_blacklist(fp);
        fclose(fp);
        fp = NULL;

        struct ip4_address_range *ip4_iter = firehol_list;
        while (ip4_iter)
        {
            /* Don't add really large address ranges */
            if (ip4_iter->prefix_len >= 28)
            {
                uint32_t addr_iter;
                uint32_t max_addr = ip4_address_range_get_max_addr(ip4_iter);

                for (addr_iter = ip4_address_range_get_min_addr(ip4_iter); addr_iter < max_addr; addr_iter++)
                {
                    if (!ip_blacklist_add(*bl, addr_iter)) goto error;
                }

                if (!ip_blacklist_add(*bl, max_addr)) goto error;
            }

            ip4_iter = ip4_iter->next;
        }

        free_ip4_address_range(&firehol_list);
    }

    return (1);
error:
    if (fp) fclose(fp);
    free_ip4_address_range(&firehol_list);
    free_ip_blacklist(bl);
    return (0);
}

/**
 * Open the domain blacklist provided at the command line and insert all domains into the blacklist
 * structure. Should only be run once. Checks that dn_bl is NULL so an existing data structure is
 * not leaked.
 */
int setup_domain_blacklist(domain_blacklist **bl, char *bl_file)
{
	assert(bl_file);

	FILE *bl_fp = NULL;
	if (bl_file)
	{
		assert(!*bl);
	    *bl = new_domain_blacklist();
	    if (!*bl) goto error;

		bl_fp = fopen(bl_file, "r");
		if (!bl_fp) goto error;

		char *domain = NULL;
		while (NULL != (domain = urlhaus_get_next_domain(bl_fp)))
		{
			domain_blacklist_add(*bl, domain);
			free(domain);
		}
		fclose(bl_fp);
	}

	DPRINT("domain blacklist setup complete...\n");
	return 1;

error:
	if (bl_fp) fclose(bl_fp);
	return 0;
}
