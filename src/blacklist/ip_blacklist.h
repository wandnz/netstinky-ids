/*
 * ip_blacklist.h
 *
 *  Created on: 30/10/2018
 *      Author: mfletche
 */

#ifndef IP_BLACKLIST_H_
#define IP_BLACKLIST_H_

#include <stdint.h>

#include "ids_storedvalues.h"

/* Do not want other modules to depend on ebvbl */
typedef struct ebvbl ip_blacklist;

typedef struct
{
	uint32_t ip_addr;
	uint16_t port;
	ids_ioc_value_t value;
} ip_key_value_t;

/**
 * Empty all entries in the blacklist.
 */
void
ip_blacklist_clear(ip_blacklist *b);

void
free_ip_blacklist(ip_blacklist **b);

/**
 * Add a key-value to the IP blacklist.
 *
 * The key-value is copied into the blacklist so the original structure can be
 * freed.
 * @param b: The blacklist.
 * @addr: A key_value struct to copy into the blacklist.
 * @return: 0 if successful.
 */
int
ip_blacklist_add(ip_blacklist *b, ip_key_value_t *addr);

/**
 * Return the key-value struct if it exists.
 * @param b: The blacklist.
 * @param ip_addr: The IP address to look up.
 * @param port: The port to look up.
 * @return: The address of the key-value struct within the blacklist or NULL if
 * the IP address/port is not in the data structure. Do not modify the
 * key-value struct.
 */
const ip_key_value_t *
ip_blacklist_lookup(ip_blacklist *b, uint32_t ip_addr, uint16_t port);

ip_blacklist *
new_ip_blacklist(void);

#endif /* IP_BLACKLIST_H_ */
