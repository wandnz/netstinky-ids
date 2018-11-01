/*
 * domain_blacklist.h
 *
 *  Created on: 1/11/2018
 *      Author: mfletche
 */

#ifndef DOMAIN_BLACKLIST_H_
#define DOMAIN_BLACKLIST_H_

#include "data_structures/hat/hat-trie.h"

/**
 * Hide the specific implementation details of the domain
 * blacklist */
typedef hattrie_t domain_blacklist;

/**
 * Add a domain to the blacklist.
 * @param b The blacklist structure.
 * @param domain The domain to add to the blacklist.
 * @return 1 if successful, 0 if unsuccessful.
 */
int
domain_blacklist_add(domain_blacklist *b, char *domain);

/**
 * Lookup a domain in the blacklist.
 * @param b The blacklist structure.
 * @param domain The domain to lookup.
 * @return 1 if the domain is blacklisted, 0 if it is not.
 */
int
domain_blacklist_is_blacklisted(domain_blacklist *b, char *domain);

/**
 * Initialize a new domain blacklist and return the result.
 * @return An initialized domain blacklist or NULL if the operation
 * failed.
 */
domain_blacklist *new_domain_blacklist();

#endif /* DOMAIN_BLACKLIST_H_ */
