/*
 * mdns.c
 *
 *  Created on: 19/10/2018
 *      Author: mfletche
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define DEBUG 1	/* Must be 1 or 0 */
#define debug_print(...) if (DEBUG) fprintf(stderr, __VA_ARGS__)

/* todo: be cautious about responding to unicast requests. make sure
 * they are on the local-link. */

/* receiving a request for PTR records with this qname will prompt
 * sending all RRs that the server has */
static const char *MDNS_SD_META_REQUEST = "_services._dns-sd._udp.local";

static const int MDNS_PORT = 5353;
static const char *MDNS_IP = "224.0.0.251";

int
mdns_get_socket()
{
	int sock_fd = -1;

	struct sockaddr_in sin;
	bzero(&sin, sizeof(sin));

	struct ip_mreqn mreq;

	if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		debug_print("socket() failed: %s\n", strerror(errno));
		return (0);
	}

	/* Allow address reuse */
	int int_enable = 1;
	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &int_enable, sizeof(int)) == -1)
	{
		debug_print("Could not setsockopt(SO_REUSEADDR) %s\n", strerror(errno));
		return (0);
	}

	/* Add to multicast group */
	mreq.imr_multiaddr.s_addr = inet_addr(MDNS_IP);
	mreq.imr_address.s_addr = htonl(INADDR_ANY);
	mreq.imr_ifindex = 0;
	if (setsockopt(sock_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) == -1)
	{
		debug_print("Could not setsockopt(IP_ADD_MEMBERSHIP) %s", strerror(errno));
		return (0);
	}

	/* Enable multicast loopback */
	unsigned char char_enable = 1;
	if (setsockopt(sock_fd, IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&char_enable, sizeof(char_enable)) == -1)
	{
		debug_print("Could not setsockopt(IP_MULTICAST_LOOP) %s\n", strerror(errno));
		return (0);
	}

	/* Bind to port */
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(MDNS_PORT);
	if (bind(sock_fd, (struct sockaddr *)&sin, sizeof(sin)) == -1)
	{
		debug_print("Could not bind socket: %s\n", strerror(errno));
		return (0);
	}

	return (sock_fd);
}
