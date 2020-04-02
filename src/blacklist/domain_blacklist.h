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
/** @file
 *
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
 * Domain names that get stored in the hat-trie get stored in reverse label
 * order but this is handled by this function. DO NOT reverse domains prior.
 *
 * @param b The blacklist structure.
 * @param domain The domain to add to the blacklist.
 * @param value The value to associate with the domain.
 * @return 1 if successful, 0 if unsuccessful.
 */
int
domain_blacklist_add(domain_blacklist *b, const char *domain, ids_ioc_value_t *value);

/**
 * Lookup a domain in the blacklist. Will handle reversing the labels of the
 * domain which is being looked up.
 * @param b The blacklist structure.
 * @param domain The domain to lookup.
 * @return The address of the value struct if the name is blacklisted, or NULL
 * if the key is not in the blacklist.
 */
ids_ioc_value_t *
domain_blacklist_is_blacklisted(domain_blacklist *b, const char *domain);

/**
 * Empty all domains in the blacklist.
 * @param b The blacklist structure.
 */
void
domain_blacklist_clear(domain_blacklist *b);

/**
 * Free memory associated with the domain blacklist and set the pointer at
 * B to NULL.
 *
 * @param b A double-pointer to a domain_blacklist to be freed
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
