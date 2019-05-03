/**
 * Functions for extracting IP addresses from the IP blacklists which are
 * obtainable from http://iplists.firehol.org/
 *
 * Firehol blacklists may contain IP address ranges
 */

#include <stdio.h>

#ifndef FIREHOL_IP_BLACKLIST_H_
#define FIREHOL_IP_BLACKLIST_H_

/* Going to construct a list so will have a NEXT pointer */
struct ip4_address_range
{
	uint32_t addr;
	uint8_t prefix_len;
	struct ip4_address_range *next;
};

void
free_ip4_address_range(struct ip4_address_range **r);

uint32_t
ip4_address_range_get_max_addr(struct ip4_address_range *r);

uint32_t
ip4_address_range_get_min_addr(struct ip4_address_range *r);

struct ip4_address_range *
new_ip4_address_range(uint32_t addr, uint8_t p_len);

struct ip4_address_range *
read_firehol_ip_blacklist(FILE *fp);

#endif /* FIREHOL_IP_BLACKLIST_H_ */
