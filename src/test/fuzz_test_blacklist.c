/*
 * fuzz_test_blacklist.c
 * Function that loads both an IP blacklist and a domain blacklist into their
 * respective data structures and exits.
 *
 * Used for fuzz testing the blacklist inputs.
 *
 *  Created on: 1/05/2019
 *      Author: mfletche
 */

#include "fuzz_test_blacklist.h"

int fuzz_test_blacklists(const char *ip_file, const char *domain_file)
{
	ip_blacklist *ip_bl = NULL;
	domain_blacklist *domain_bl = NULL;

	if (ip_file)
		if (!setup_ip_blacklist(&ip_bl, (char *)ip_file)) {
			DPRINT("setup_ip_blacklist() failed\n");
			goto error;
		}

	if (domain_file)
		if (!setup_domain_blacklist(&domain_bl, (char *)domain_file)) {
			DPRINT("setup_domain_blacklist() failed\n");
			goto error;
		}

    if (ip_bl) free_ip_blacklist(&ip_bl);
    if (domain_bl) free_domain_blacklist(&domain_bl);
    return (1);

error:
	if (ip_bl) free_ip_blacklist(&ip_bl);
	if (domain_bl) free_domain_blacklist(&domain_bl);
	return (0);
}
