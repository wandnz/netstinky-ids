/*
 * ip_blacklist.h
 *
 *  Created on: 30/10/2018
 *      Author: mfletche
 */

#ifndef IP_BLACKLIST_H_
#define IP_BLACKLIST_H_

#include <stdint.h>

typedef uint32_t ip4_addr;

/* Do not want other modules to depend on ebvbl */
typedef struct ebvbl ip_blacklist;

void
free_ip_blacklist(ip_blacklist **b);

int ip_blacklist_lookup(ip_blacklist *b, ip4_addr a);

ip_blacklist *
new_ip_blacklist();

#endif /* IP_BLACKLIST_H_ */
