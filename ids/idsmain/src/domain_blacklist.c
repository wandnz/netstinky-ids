/*
 * domain_blacklist.c
 *
 *  Created on: 1/11/2018
 *      Author: mfletche
 */

#include <string.h>

#include <assert.h>

#include "domain_blacklist.h"

int
domain_blacklist_add(domain_blacklist *b, char *domain)
{
	assert(b);
	assert(domain);

	hattrie_t *h = (hattrie_t *)b;
	value_t *result = NULL;
	size_t len;

	if (b && domain)
	{
		len = strlen(domain);
		result = hattrie_get(h, domain, len);
	}

	return (result ? 1 : 0);
}

int
domain_blacklist_is_blacklisted(domain_blacklist *b, char *domain)
{
	assert(b);
	assert(domain);

	hattrie_t *h = (hattrie_t *)b;
	size_t len;
	value_t *result = NULL;

	if (b && domain)
	{
		len = strlen(domain);
		result = hattrie_tryget(h, domain, len);
	}

	return (result ? 1 : 0);
}

domain_blacklist *new_domain_blacklist()
{
	hattrie_t *h = hattrie_create();
	return (h);
}
