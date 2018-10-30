#include "ip_blacklist.h"

#include "sortedarray.h"
#include "ebvbl.h"

static const unsigned int element_realloc = 10;

void
free_ip_blacklist(ip_blacklist **b)
{
	assert(b);
	ebvbl_free(b, NULL);
}

int ip_blacklist_cmp(element_ptr a, element_ptr b)
{
	ip4_addr *a_ptr = (ip4_addr *)a, *b_ptr = (ip4_addr *)b;

	/* Don't subtract, since unsigned */
	if (*a_ptr == *b_ptr) return (0);
	else if (*a_ptr > *b_ptr) return (1);
	else return (-1);
}

element_prefix ip_blacklist_get_first_bits(element_ptr item, ebvbl_bff bff)
{
	unsigned int shift = (32 - bff - 1);
	ip4_addr *addr = (ip4_addr *)item;

	element_prefix p = (*addr) >> shift;
	return (p);
}

int ip_blacklist_lookup(ip_blacklist *b, ip4_addr a)
{
	assert(b);

	if (ebvbl_contains_element(b, (element_ptr)&a)) return (1);
	else return (0);
}

ip_blacklist *
new_ip_blacklist()
{
	ip_blacklist *bl = (ip_blacklist *)ebvbl_create(sizeof(ip4_addr), ip_blacklist_cmp, 16, ip_blacklist_get_first_bits,
			element_realloc);

	return (bl);
}
