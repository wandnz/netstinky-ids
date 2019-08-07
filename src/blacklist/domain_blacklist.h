/*
 * domain_blacklist.h
 *
 *  Created on: 1/11/2018
 *      Author: mfletche
 */

#ifndef DOMAIN_BLACKLIST_H_
#define DOMAIN_BLACKLIST_H_

#include "ids_storedvalues.h"
#include "../utils/hat/hat-trie.h"

/**
 * Hide the specific implementation details of the domain
 * blacklist */
typedef hattrie_t domain_blacklist;

/**
 * Add a domain to the blacklist. The value structure should not be freed until
 * the key is removed from the blacklist. The address of the structure is
 * stored in the hat-trie, rather than making a copy.
 *
 * @param b The blacklist structure.
 * @param domain The domain to add to the blacklist.
 * @param value: The value to associate with the domain.
 * @return 1 if successful, 0 if unsuccessful.
 */
int
domain_blacklist_add(domain_blacklist *b, char *domain, ids_ioc_value_t *value);

/**
 * Lookup a domain in the blacklist.
 * @param b The blacklist structure.
 * @param domain The domain to lookup.
 * @return The address of the value struct if the name is blacklisted, or NULL
 * if the key is not in the blacklist.
 */
ids_ioc_value_t *
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
