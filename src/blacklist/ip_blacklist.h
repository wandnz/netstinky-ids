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
#ifndef IP_BLACKLIST_H_
#define IP_BLACKLIST_H_

#include <stdint.h>

#include "ids_storedvalues.h"

/** Hide ebvbl implementation from dependent modules */
typedef struct ebvbl ip_blacklist;

/** @brief The key data structure for blacklist lookups */
typedef struct
{
    uint32_t ip_addr;       ///< The IPv4 address of the record
    uint16_t port;          ///< The TCP port of the record
    ids_ioc_value_t value;  ///< A value to associate with this entry
} ip_key_value_t;

/**
 * @brief Empty all entries in the blacklist
 *
 * @param b A pointer to an #ip_blacklist
 */
void
ip_blacklist_clear(ip_blacklist *b);

/**
 * @brief Free the memory used by the ip_blacklist
 *
 * Frees the memory used by the blacklist and sets the value pointed to by \p b
 * to be NULL
 */
void
free_ip_blacklist(ip_blacklist **b);

/**
 * @brief Add a key-value to the IP blacklist
 *
 * The key-value is copied into the blacklist so the original structure can be
 * freed
 * @param b A pointer to an #ip_blacklist
 * @param addr A key_value struct to copy into the blacklist
 * @return 0 if successful, 1 on error
 */
int
ip_blacklist_add(ip_blacklist *b, ip_key_value_t *addr);

/**
 * Return the key-value struct if it exists
 * @param b A pointer to an #ip_blacklist
 * @param ip_addr The IP address to look up.
 * @param port The port to look up. A value of 0 will ignore the port number
 * and return a match if just the IP address matches a key in the blacklist.
 * @return The address of the key-value struct within the blacklist or NULL if
 * the IP address/port is not in the data structure. Do not modify the
 * key-value struct.
 */
const ip_key_value_t *
ip_blacklist_lookup(ip_blacklist *b, uint32_t ip_addr, uint16_t port);

/**
 * Allocate a new, empty blacklist
 *
 * @return A pointer to an empty #ip_blacklist
 */
ip_blacklist *
new_ip_blacklist(void);

#endif /* IP_BLACKLIST_H_ */
