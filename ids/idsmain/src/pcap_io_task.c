/*
 * pcap_io_task.c
 *
 *  Created on: 29/10/2018
 *      Author: mfletche
 */

#include <stdlib.h>
#include <assert.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "dns.h"

#include "ids_pcap.h"
#include "io_task.h"
#include "pcap_io_task.h"

/* -- DEBUGGING -- */
#define DEBUG 1
#define DPRINT(...) do { if (DEBUG) fprintf(stdout, __VA_ARGS__); } while (0)

struct pcap_io_task_state
{
	int fd;
	pcap_t *p;
};

int
pcap_io_task_write(TASK_STRUCT state);

void
free_pcap_io_task_state(TASK_STRUCT *state)
{
	assert(state);

	struct pcap_io_task_state **s = (struct pcap_io_task_state **)state;

	if (s && *s)
	{
		if ((*s)->p) pcap_close((*s)->p);

		/* fd is part of pcap_t so don't free separately */

		free(*s);
		*s = NULL;
	}
}

int
pcap_io_task_read(TASK_STRUCT state)
{
	/* Get pcap from state struct */
	struct pcap_io_task_state *s = (struct pcap_io_task_state *)state;
	pcap_t *p = s->p;

	struct pcap_pkthdr *pcap_hdr = NULL;
	const u_char *pcap_data = NULL;

	struct ether_header *eth_hdr = NULL;
	struct ip *ip_hdr = NULL;
	struct tcphdr *tcp_hdr = NULL;
	struct udphdr *udp_hdr = NULL;
	struct dns_packet *dns_pkt = NULL;
	struct dns_question *query = NULL;

	uint8_t *payload_pos = NULL;
	struct in_addr ip_addr;

	/* Get next packet */
	if (PCAP_ERROR == pcap_next_ex(p, &pcap_hdr, &pcap_data))
	{
		DPRINT("pcap_io_task_read(): pcap_next_ex() failed with message: %s\n",
				pcap_geterr(p));
		goto error;
	}

	/* Crash immediately during debugging if pcap_data is not a valid pointer */
	assert(pcap_data);
	if (pcap_data)
	{
		if (!pcap_hdr)
		{
			DPRINT("pcap_io_task_read(): pcap header was NULL\n");
			goto error;
		}
		if (pcap_hdr->len < sizeof(*eth_hdr))
		{
			DPRINT("pcap_io_task_read(): pcap length too small to contain ethernet header: %d\n",
					pcap_hdr->len);
			goto error;
		}
		eth_hdr = (struct ether_header *)pcap_data;

		/* Not an error if not IP but not interested in it. */
		if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) return (1);

		if (pcap_hdr->len < (sizeof(*eth_hdr) + sizeof(*ip_hdr)))
		{
			DPRINT("pcap_io_task_read(): pcap length too small to contain IP header: %d\n",
					pcap_hdr->len);
			goto error;
		}
		ip_hdr = (struct ip *)(pcap_data + sizeof(*eth_hdr));
		DPRINT("pcap_io_task_read(): destination IP: %s\n", inet_ntoa(ip_hdr->ip_dst));

		switch (ip_hdr->ip_p)
		{
			case 6:
				DPRINT("pcap_io_task_read(): tcp packet\n");
				tcp_hdr = (struct tcphdr *)(pcap_data + sizeof(*ip_hdr));
				assert(tcp_hdr->th_flags & TH_SYN);
				/* TODO: Perform extra checks while debugging */

				ip_addr = ip_hdr->ip_dst;
				/* TODO: Send to blacklist */

				DPRINT("pcap_io_task_read(): checking blacklist for IP address %s\n",
						inet_ntoa(ip_addr));

				break;
			case 17:
				DPRINT("pcap_io_task_read(): udp packet\n");
				udp_hdr = (struct udphdr *)(pcap_data + (sizeof(*eth_hdr) + sizeof(*ip_hdr)));
				payload_pos = (uint8_t *)(pcap_data + (sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(*udp_hdr)));
				/* TODO: Perform extra checks while debugging */
				dns_pkt = dns_parse(payload_pos,
						pcap_hdr->len - (sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(*udp_hdr)));

				if (!dns_pkt)
				{
					DPRINT("pcap_io_task_read(): dns_parse() failed\n");
					goto error;
				}

				/* Check if this is a query */
				if (dns_pkt->header.qdcount)
				{
					for (query = dns_pkt->questions; query; query = query->next)
					{
						/* TODO: Look up query in blacklist */
						DPRINT("pcap_io_task_read(): checking blacklist for domain name: %s\n", query->qname);
					}
				}

				free_dns_packet(&dns_pkt);
				break;
			default:
				/* This shouldn't happen */
				DPRINT("pcap_io_task_read(): captured packet with protocol %d\n", ip_hdr->ip_p);
				goto error;
		}
	}

error:
	free_dns_packet(&dns_pkt);
	return (0);
}

struct io_task *
pcap_io_task_setup(const char *if_name)
{
	int pcap_fd = -1;
	struct pcap_io_task_state *state = NULL;
	struct io_task *task = NULL;

	if (!(state = malloc(sizeof(*state))))
	{
		DPRINT("pcap_io_task_setup(%s): malloc() failed\n", if_name);
		goto error;
	}

	if (!(state->p = ids_pcap_get_pcap(if_name)))
	{
		DPRINT("pcap_io_task_setup(%s): ids_pcap_get_pcap() failed\n", if_name);
		goto error;
	}

	if (PCAP_ERROR == (pcap_fd = pcap_get_selectable_fd(state->p)))
	{
		DPRINT("pcap_io_task_setup(): pcap_get_selectable_fd() failed\n");
		goto error;
	}

	/* Bundle into an io_task */
	if (!(task = new_io_task(pcap_fd, state, pcap_io_task_read, NULL,
			free_pcap_io_task_state)))
	{
		DPRINT("pcap_io_task_setup(): new_io_task() failed\n");
		goto error;
	}

	return (task);

error:
	free_pcap_io_task_state((TASK_STRUCT *)&state);
	return (NULL);
}

int
pcap_io_task_write(TASK_STRUCT state)
{
	/* TODO: Implement */
	return (0);
}
