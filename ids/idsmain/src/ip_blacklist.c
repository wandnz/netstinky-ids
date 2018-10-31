#include "ip_blacklist.h"

#include "firehol_ip_blacklist.h"
#include "sortedarray.h"
#include "ebvbl.h"

static const unsigned int element_realloc = 10;

void
free_ip_blacklist(ip_blacklist **b)
{
	assert(b);
	ebvbl_free(b, NULL);
}

int
ip_blacklist_add(ip_blacklist *b, uint32_t a)
{
	assert(b);

	int success = 0;
	if (b)
	{
		if (EBVBL_SUCCESS == ebvbl_insert_element(b, &a, sizeof(a)))
			success = 1;
	}

	return (success);
}

int ip_blacklist_cmp(element_ptr a, element_ptr b)
{
	assert(a);
	assert(b);

	uint32_t a_val, b_val;
	if (a && b)
	{
		a_val = *(uint32_t *)a;
		b_val = *(uint32_t *)b;

		if (a_val > b_val) return (1);
		if (a_val < b_val) return (-1);
		return (0);
	}

	return (0);
}

element_prefix ip_blacklist_get_first_bits(element_ptr item, ebvbl_bff bff)
{
	unsigned int shift = (32 - bff);
	uint32_t *addr = (uint32_t *)item;

	element_prefix p = (*addr) >> shift;
	return (p);
}

int ip_blacklist_lookup(ip_blacklist *b, uint32_t a)
{
	assert(b);

	if (ebvbl_contains_element(b, (element_ptr)&a)) return (1);
	else return (0);
}

ip_blacklist *
new_ip_blacklist()
{
	ip_blacklist *bl = (ip_blacklist *)ebvbl_create(sizeof(uint32_t), ip_blacklist_cmp, 16, ip_blacklist_get_first_bits,
			element_realloc);

	return (bl);
}
