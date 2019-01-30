/*
 * firehol_ip_blacklist.c
 *
 *  Created on: 30/10/2018
 *      Author: mfletche
 */

#ifndef FIREHOL_IP_BLACKLIST_C_
#define FIREHOL_IP_BLACKLIST_C_

#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include <arpa/inet.h>

#include "firehol_ip_blacklist.h"

const static unsigned int MAX_PREFIX_LEN = 32;

void
free_ip4_address_range(struct ip4_address_range **r)
{
	assert(r);
	if (r && *r)
	{
		while (*r)
		{
			struct ip4_address_range *tmp = (*r)->next;
			free(*r);
			*r = tmp;
		}
	}
}

int
ip4_address_range_add(struct ip4_address_range **list, struct ip4_address_range *r)
{
	assert(list);
	assert(r);

	if (list && r)
	{
		if (*list)
		{
			struct ip4_address_range *list_tail = *list;
			while (list_tail->next) list_tail = list_tail->next;
			list_tail->next = r;
		}
		else
		{
			*list = r;
		}

		return (1);
	}

	return (0);
}

uint32_t
ip4_address_range_get_mask(uint8_t prefix_len)
{
	assert(prefix_len > 0 && prefix_len <= MAX_PREFIX_LEN);

	uint32_t mask = 0;

	if (prefix_len > 0 && prefix_len <= MAX_PREFIX_LEN)
	{
		mask=0xFFFFFFFF & ~((1 << (MAX_PREFIX_LEN - prefix_len)) - 1);
	}

	return (mask);
}

uint32_t
ip4_address_range_get_max_addr(struct ip4_address_range *r)
{
	assert(r);

	uint32_t mask = 0;
	uint32_t max_addr = 0;

	if (r)
	{
		assert(0 != (mask = ip4_address_range_get_mask(r->prefix_len)));
		max_addr = ip4_address_range_get_min_addr(r) + ~mask;
	}

	return (max_addr);
}

uint32_t
ip4_address_range_get_min_addr(struct ip4_address_range *r)
{
	assert(r);

	uint32_t mask = 0;
	uint32_t min_addr = 0;

	if (r)
	{
		assert(0 != (mask = ip4_address_range_get_mask(r->prefix_len)));
		min_addr = r->addr & mask;
	}

	return (min_addr);
}

void
ip4_address_range_set_addr(struct ip4_address_range *r, uint32_t addr)
{
	assert(r);
	if (r) r->addr = addr;
}

int
ip4_address_range_set_prefix_len(struct ip4_address_range *r, uint8_t len)
{
	assert(r);
	if (r && len > 0 && len <= MAX_PREFIX_LEN)
	{
		r->prefix_len = len;
		return (1);
	}

	return (0);
}

struct ip4_address_range *
new_ip4_address_range(uint32_t addr, uint8_t p_len)
{
	struct ip4_address_range *r = malloc(sizeof(*r));
	if (r)
	{
		ip4_address_range_set_addr(r, addr);
		if (!ip4_address_range_set_prefix_len(r, p_len)) goto error;

		r->next = NULL;
	}

	return (r);

error:
	if (r) free(r);
	return (NULL);
}

struct ip4_address_range *
read_firehol_ip_blacklist(FILE *fp)
{
	assert(fp);

	struct ip4_address_range *list = NULL;
	if (fp)
	{
		char *line_buf = NULL;
		size_t buf_len = 0;

		struct in_addr addr;
		uint8_t prefix_len;

		ssize_t result;
		while (-1 != (result = getline(&line_buf, &buf_len, fp)))
		{
			/* First token is IP address */
			char *token = strtok(line_buf, "/\n");
			if (!token || !inet_pton(AF_INET, token, &addr)) continue;

			/* Second token is prefix length */
			token = strtok(NULL, "/\n");
			if (token)
			{
				prefix_len = atoi(token);
				if (!prefix_len) prefix_len = 32;
			}
			else prefix_len = 32;

			ip4_address_range_add(&list, new_ip4_address_range(ntohl(addr.s_addr), prefix_len));
		}

		if (line_buf) free(line_buf);
	}

	return (list);
}

#endif /* FIREHOL_IP_BLACKLIST_C_ */
