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
#include <arpa/inet.h>

#include <assert.h>

#include "dns.h"

#define DEBUG 1	/* Must be 1 or 0 */
#define DPRINT(...) if (DEBUG) fprintf(stderr, __VA_ARGS__)

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
		DPRINT("socket() failed: %s\n", strerror(errno));
		return (0);
	}

	/* Allow address reuse */
	int int_enable = 1;
	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &int_enable, sizeof(int)) == -1)
	{
		DPRINT("Could not setsockopt(SO_REUSEADDR) %s\n", strerror(errno));
		return (0);
	}

	/* Add to multicast group */
	mreq.imr_multiaddr.s_addr = inet_addr(MDNS_IP);
	mreq.imr_address.s_addr = htonl(INADDR_ANY);
	mreq.imr_ifindex = 0;
	if (setsockopt(sock_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) == -1)
	{
		DPRINT("Could not setsockopt(IP_ADD_MEMBERSHIP) %s", strerror(errno));
		return (0);
	}

	/* Enable multicast loopback */
	unsigned char char_enable = 1;
	if (setsockopt(sock_fd, IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&char_enable, sizeof(char_enable)) == -1)
	{
		DPRINT("Could not setsockopt(IP_MULTICAST_LOOP) %s\n", strerror(errno));
		return (0);
	}

	/* Bind to port */
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(MDNS_PORT);
	if (bind(sock_fd, (struct sockaddr *)&sin, sizeof(sin)) == -1)
	{
		DPRINT("Could not bind socket: %s\n", strerror(errno));
		return (0);
	}

	return (sock_fd);
}

struct dns_packet *
mdns_construct_reply(struct dns_packet *p, struct dns_answer *record_list)
{
	assert(p);

	int i;
	struct dns_question *q;
	struct dns_packet *reply = NULL;
	struct dns_answer *record_iter = NULL;

	struct dns_answer **reply_tail = NULL;

	/* Search list of records for records matching queries. */
	if (p && record_list)
	{
		if (!(reply = malloc(sizeof(*reply)))) goto error;
		memset(reply, 0, sizeof(*reply));
		reply->header.id = p->header.id;
		reply->header.qr = 1;
		reply->header.aa = 1;	/* Change if authoritative answer is not correct */

		reply_tail = &(reply->answers);

		q = p->questions;
		for (i = 0; i < p->header.qdcount; i++)
		{
			if (!q) goto error;

			/* This special domain name will be sent all records */
			int all_services = dns_compare_names(q->qname,
					dns_domain_to_name(MDNS_SD_META_REQUEST)) == 0 ? 1 : 0;
			if (all_services)
			{
				/* Add entire record_list */
				if (NULL == (*reply_tail = dns_answer_list_copy(record_list))) goto error;
				while ((*reply_tail)->next) reply_tail = &((*reply_tail)->next->next);
				break;
			}
			else
			{
				record_iter = record_list;
				while (record_iter)
				{
					if (!dns_compare_names(q->qname, record_iter->name)
							&& q->qclass == record_iter->class
							&& q->qtype == record_iter->type)
					{
						/* Add record to answer list */
						if (NULL == (*reply_tail = dns_answer_copy(record_iter))) goto error;
						reply_tail = &((*reply_tail)->next->next);
					}
				}
			}
		}

		/* Don't bother writing a packet with zero responses */
		if (!(reply->answers)) free_dns_packet(&reply);

		return (reply);
	}

error:
	free_dns_packet(&reply);
	return (NULL);
}

int
mdns_send_reply(int fd, uint8_t *packet_buf, size_t buf_len, struct dns_packet *p)
{
	assert(fd >= 0);
	assert(p);

	size_t packet_len;

	if (fd >= 0 && p)
	{
		struct sockaddr_in replyto_addr;

		memset(&replyto_addr, 0, sizeof(replyto_addr));
		replyto_addr.sin_family = AF_INET;
		replyto_addr.sin_port = htons(MDNS_PORT);
		replyto_addr.sin_addr.s_addr = inet_addr(MDNS_IP);

		if (!(packet_len = dns_write(packet_buf, buf_len, p))) goto error;

		struct dns_packet *test_packet = dns_parse(packet_buf, packet_len);
		dns_print(test_packet, stdout);
		free_dns_packet(&test_packet);

		if (-1 == sendto(fd, (void *)packet_buf, packet_len, 0,
				(struct sockaddr *)&replyto_addr, sizeof(replyto_addr)))
		{
			DPRINT("mdns_send_reply(): sendto() failed with message: %s\n",
					strerror(errno));
			goto error;
		}

		return (1);
	}

error:
	return (0);
}

void
mdns_advertise()
{

}

/* Construct a new dns_answer structure.
 * Assumes class is IN. Does not fill in rdata or rlength.
 *
 * NAME is now the responsibility of the answer and it will be freed when
 * the dns_answer is freed.
 */
struct dns_answer *
new_mdns_answer(uint8_t *name, uint16_t type, uint32_t ttl)
{
	struct dns_answer *a = NULL;
	if (name)
	{
		if ((a = malloc(sizeof(*a))) != NULL)
		{
			memset(a, 0, sizeof(*a));
			a->name = name;
			a->class = IN;
			a->type = type;
			a->ttl = ttl;
		}
		else
		{
			/* Can't use name so free it */
			free(name);
		}
	}

	return (a);
}
