/*
 * iface.c
 *
 *  Created on: 26/10/2018
 *      Author: mfletche
 */

#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include "iface.h"

/* -- DEBUGGING -- */
#define DEBUG 1
#define DPRINT(...) do { if (DEBUG) fprintf(stdout, __VA_ARGS__); } while (0)

void
print_network_interfaces(FILE *stream)
{
	assert(stream);
	struct ifaddrs *if_list = NULL, *iter = NULL;

	if (stream)
	{
		if (-1 == getifaddrs(&if_list))
		{
			DPRINT("getifaddr() failed\n");
			return;
		}

		/* print interfaces which are type AF_PACKET */
		iter = if_list;
		while (iter)
		{
			if (iter->ifa_addr && iter->ifa_addr->sa_family == AF_PACKET)
				fprintf(stream, "%s\n", iter->ifa_name);

			iter = iter->ifa_next;
		}

		freeifaddrs(if_list);
	}
}
