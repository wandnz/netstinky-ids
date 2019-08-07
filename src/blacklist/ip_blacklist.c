#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ip_blacklist.h"

#include "firehol_ip_blacklist.h"
#include "../utils/ebvbl/ebvbl.h"

int ip_blacklist_cmp(void *a, void *b)
{
	assert(a);
	assert(b);

	// This error state will not result in a segfault but will still cause
	// serious problems
	if (!a || !b) return 0;

	long diff;
	ip_key_value_t *a_val, *b_val;

	a_val = a;
	b_val = b;

	// Rank by IP addresses, and then by ports. Both must be equal to get
	// a 0 result.
	diff = a_val->ip_addr - b_val->ip_addr;
	if (!diff)
		diff = a_val->port - b_val->port;

	return diff;
}

unsigned int ip_blacklist_get_first_bits(void *item, unsigned int bff)
{
	unsigned int shift = (32 - bff);
	ip_key_value_t *key = (ip_key_value_t *)item;

	unsigned int p = key->ip_addr >> shift;
	return (p);
}

ip_blacklist *
new_ip_blacklist()
{
	ip_blacklist *bl = (ip_blacklist *)ebvbl_init(
			sizeof(ip_key_value_t),
			ip_blacklist_cmp,
			16,
			ip_blacklist_get_first_bits
			);

	return (bl);
}

void
free_ip_blacklist(ip_blacklist **b)
{
	assert(b);
	if (*b)	ebvbl_free((EBVBL *)*b, NULL);
	*b = NULL;
}

void
ip_blacklist_clear(ip_blacklist *b)
{
	assert(b);

	ebvbl_clear((EBVBL *)b, NULL);
}

int
ip_blacklist_add(ip_blacklist *b, ip_key_value_t *addr)
{
	assert(b);
	assert(addr);

	if (!b || !addr) return 0;

	if (-1 == ebvbl_insert_element((EBVBL *)b, addr)) return 0;
	return 1;
}

void
ip_blacklist_remove(ip_blacklist *b, void *element)
{
	assert(b);
	assert(element);

	assert(false);	// Not implemented, may not be necessary
}

const ip_key_value_t *
ip_blacklist_lookup(ip_blacklist *b, uint32_t addr, uint16_t port)
{
	assert(b);
	ip_key_value_t key;	// Only key fields will be filled

	// Should be safe to ignore (not even zero) non-key fields
	key.ip_addr = addr;
	key.port = port;

	return (const ip_key_value_t *)ebvbl_lookup((EBVBL *)b, &key);
}
