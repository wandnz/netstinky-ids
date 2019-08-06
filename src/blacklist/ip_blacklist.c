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

unsigned int ip_blacklist_get_first_bits(void *item, unsigned int bff)
{
	unsigned int shift = (32 - bff);
	unsigned int *addr = (uint32_t *)item;

	unsigned int p = (*addr) >> shift;
	return (p);
}

ip_blacklist *
new_ip_blacklist()
{
	ip_blacklist *bl = (ip_blacklist *)ebvbl_init(sizeof(uint32_t), ip_blacklist_cmp, 16, ip_blacklist_get_first_bits);

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
ip_blacklist_add(ip_blacklist *b, uint32_t a)
{
	assert(b);

	int success = 0;
	if (b)
	{
		if (-1 != ebvbl_insert_element((EBVBL *)b, &a))
		{
			success = 1;
		}
	}

	return (success);
}

void
ip_blacklist_remove(ip_blacklist *b, void *element)
{
	assert(b);
	assert(element);


}

int ip_blacklist_lookup(ip_blacklist *b, uint32_t a)
{
	assert(b);

	return (ebvbl_contains((EBVBL *)b, &a));
}