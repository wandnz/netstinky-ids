/*
 * domain_blacklist.c
 *
 *  Created on: 1/11/2018
 *      Author: mfletche
 */
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "domain_blacklist.h"

/**
 * At least for the HAT-trie, extra compression can be attained by reversing the labels so that
 * TLDs come first.
 *
 * When checking domain names, they will also need to be reversed before lookup.
 *
 * Does not modify original domain string. Returns a dynamically allocated string.
 *
 * Will return NULL if memory allocation failed (there are a few extra strings required for this
 * operation).
 */
char *
_domain_blacklist_reverse_labels(char * domain)
{
	assert(domain);
	int reversed_idx = -1;
	char *delim = ".";

	// token_cpy is the copy which will be destroyed by strtok
	char *token_cpy = strdup(domain), *reversed = NULL;
	if (!token_cpy) goto error;

	char *tok = NULL;
	size_t tok_len;

	size_t reversed_sz = strlen(domain) + 1;
	reversed = malloc(reversed_sz);
	if (!reversed) return NULL;	// Memory allocation error

	// Counts back from end as domain labels are prepended
	reversed_idx = reversed_sz - 1;
	if (reversed_idx < 0) goto error;
	reversed[reversed_idx] = '\0';

	if (NULL != (tok = strtok(token_cpy, delim)))
	{
		do {
			tok_len = strlen(tok);
			reversed_idx -= tok_len;
			assert(reversed_idx >= 0);
			strncpy(reversed + reversed_idx, tok, tok_len);

			// prepend '.'
			if (--reversed_idx >= 0) reversed[reversed_idx] = '.';
		} while (NULL != (tok = strtok(NULL, delim)));
	}

	free(token_cpy);
	return reversed;

error:
	if (token_cpy) free(token_cpy);
	if (reversed) free(reversed);
	return NULL;
}

int
domain_blacklist_add(domain_blacklist *b, char *domain, ids_ioc_value_t *value)
{
	assert(b);
	assert(domain);

	// Reverse domain label order before inserting.
	char *reversed = _domain_blacklist_reverse_labels(domain);
	if (!reversed) return 0;

	hattrie_t *h = (hattrie_t *)b;
	value_t *result = NULL;
	size_t len;

	len = strlen(reversed);
	result = hattrie_get(h, reversed, len);
	*result = (uintptr_t)value;
	free(reversed);

	return (result ? 1 : 0);
}

ids_ioc_value_t *
domain_blacklist_is_blacklisted(domain_blacklist *b, char *domain)
{
	assert(b);
	assert(domain);

	hattrie_t *h = (hattrie_t *)b;
	size_t len;
	value_t *result = NULL;

	char *reversed = _domain_blacklist_reverse_labels(domain);
	if (!reversed)
	{
		// This is a serious error since we can't check the blacklist. Definitely log it.
		fprintf(stderr, "Could not reverse domain name when checking blacklist: %s\n", domain);
		return 0;
	}

	if (b && domain)
	{
		len = strlen(domain);
		result = hattrie_tryget(h, reversed, len);
	}

	free(reversed);

	return (ids_ioc_value_t *)result;
}

void
domain_blacklist_clear(domain_blacklist *b)
{
	assert(b);
	hattrie_t *h = (hattrie_t *)b;

	hattrie_free(h);
}

void
free_domain_blacklist(domain_blacklist **b)
{
	assert(b);
	hattrie_t **h = (hattrie_t **)b;

	if (h && *h)
	{
		hattrie_free(*h);
		*h = NULL;
	}
}

domain_blacklist *new_domain_blacklist()
{
	hattrie_t *h = hattrie_create();
	return (h);
}
