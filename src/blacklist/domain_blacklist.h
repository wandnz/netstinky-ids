/*
 * domain_blacklist.h
 *
 *  Created on: 1/11/2018
 *      Author: mfletche
 */

#ifndef DOMAIN_BLACKLIST_H_
#define DOMAIN_BLACKLIST_H_

#include "../utils/hat/hat-trie.h"

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
 * Empty all domains in the blacklist.
 * @param b The blacklist structure.
 */
void
domain_blacklist_clear(domain_blacklist *b);

/*
 * Free memory associated with the domain blacklist and set the pointer at
 * B to NULL.
 */
void
free_domain_blacklist(domain_blacklist **b);

/**
 * Initialize a new domain blacklist and return the result.
 * @return An initialized domain blacklist or NULL if the operation
 * failed.
 */
domain_blacklist *new_domain_blacklist(void);

#endif /* DOMAIN_BLACKLIST_H_ */
