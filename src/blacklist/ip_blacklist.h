/*
 * ip_blacklist.h
 *
 *  Created on: 30/10/2018
 *      Author: mfletche
 */

#ifndef IP_BLACKLIST_H_
#define IP_BLACKLIST_H_

#include <stdint.h>

#include "firehol_ip_blacklist.h"

/* Do not want other modules to depend on ebvbl */
typedef struct ebvbl ip_blacklist;

/**
 * Empty all entries in the blacklist.
 */
void
ip_blacklist_clear(ip_blacklist *b);

void
free_ip_blacklist(ip_blacklist **b);

int
ip_blacklist_add(ip_blacklist *b, uint32_t a);

int
ip_blacklist_lookup(ip_blacklist *b, uint32_t addr);

ip_blacklist *
new_ip_blacklist(void);

#endif /* IP_BLACKLIST_H_ */
