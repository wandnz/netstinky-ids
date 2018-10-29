/*
 * ids_pcap.c
 *
 *  Created on: 29/10/2018
 *      Author: mfletche
 */

#include <assert.h>
#include <pcap/pcap.h>

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

/* -- DEBUGGING -- */
#define DEBUG 1
#define DPRINT(...) do { if (DEBUG) fprintf(stdout, __VA_ARGS__); } while (0)

static const char *pcap_filter = "(udp dst port 53) or (tcp[tcpflags] & tcp-syn != 0)";
static const int promisc_enabled = 0;
static const int immediate_mode_enabled = 1;

pcap_t *
ids_pcap_get_pcap(const char *if_name)
{
	assert(if_name);

	char err_buf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;
	pcap_t *pcap = NULL;
	int tmp_result = 0;

	/* Create pcap device */
	if (!(pcap = pcap_create( if_name, err_buf)))
	{
		DPRINT("ids_pcap_get_pcap(%s): pcap_create() failed with message: %s\n",
				if_name, err_buf);
		goto error;
	}

	/* These functions will only fail if the pcap has already been activated.
	 * They return 0 on success. */
	tmp_result = pcap_set_promisc(pcap, promisc_enabled);
	assert(!tmp_result);	/* During debugging, crash immediately */
	if (PCAP_ERROR_ACTIVATED == tmp_result)
	{
		DPRINT("ids_pcap_get_pcap(%s): pcap_set_promisc() failed\n", if_name);
		goto error;
	}

	assert(!pcap_set_immediate_mode(pcap, immediate_mode_enabled));
	assert(!tmp_result);	/* During debugging, crash immediately */
	if (PCAP_ERROR_ACTIVATED == tmp_result)
	{
		DPRINT("ids_pcap_get_pcap(%s): pcap_set_immediate_mode() failed\n",
				if_name);
		goto error;
	}

	tmp_result = pcap_activate(pcap);
	if (tmp_result < 0)
	{
		/* Check for programming errors */
		assert(PCAP_ERROR_ACTIVATED != tmp_result);
		assert(PCAP_ERROR_NO_SUCH_DEVICE != tmp_result);

		DPRINT("ids_pcap_get_pcap(%s): pcap_activate() failed with message: %s\n",
				if_name, pcap_geterr(pcap));
		goto error;
	}
	else if (tmp_result > 0)
	{
		/* Display warning message */
		DPRINT("ids_pcap_get_pcap(%s): pcap_activate() warning: %s\n",
				if_name, pcap_geterr(pcap));
	}

	/* Set up filter */
	if (PCAP_ERROR == pcap_compile(pcap, &filter, pcap_filter, 0, 0))
	{
		DPRINT("ids_pcap_get_pcap(%s): pcap_compile() failed with message: %s\n",
				if_name, pcap_geterr(pcap));
		goto error;
	}

	if (PCAP_ERROR == pcap_setfilter(pcap, &filter))
	{
		DPRINT("ids_pcap_get_pcap(%s): pcap_setfilter() failed with message: %s\n",
				if_name, pcap_geterr(pcap));
		goto error;
	}

	DPRINT("ids_pcap_get_pcap(%s): successfully completed \n", if_name);
	return (pcap);

error:
	if (pcap) pcap_close(pcap);
	pcap = NULL;
	return (pcap);
}

int
ids_pcap_read_packet(pcap_t *p)
{
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
		DPRINT("ids_pcap_read_packet(): pcap_next_ex() failed with message: %s\n",
				pcap_geterr(p));
		goto error;
	}

	/* Crash immediately during debugging if pcap_data is not a valid pointer */
	assert(pcap_data);
	if (pcap_data)
	{
		if (!pcap_hdr)
		{
			DPRINT("ids_pcap_read_packet(): pcap header was NULL\n");
			goto error;
		}
		if (pcap_hdr->len < sizeof(*eth_hdr))
		{
			DPRINT("ids_pcap_read_packet(): pcap length too small to contain ethernet header: %d\n",
					pcap_hdr->len);
			goto error;
		}
		eth_hdr = (struct ether_header *)pcap_data;

		/* Not an error if not IP but not interested in it. */
		if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) return (1);

		if (pcap_hdr->len < (sizeof(*eth_hdr) + sizeof(*ip_hdr)))
		{
			DPRINT("ids_pcap_read_packet(): pcap length too small to contain IP header: %d\n",
					pcap_hdr->len);
			goto error;
		}
		ip_hdr = (struct ip *)(pcap_data + sizeof(*eth_hdr));
		DPRINT("ids_pcap_read_packet(): destination IP: %s\n", inet_ntoa(ip_hdr->ip_dst));

		switch (ip_hdr->ip_p)
		{
			case 6:
				DPRINT("ids_pcap_read_packet(): tcp packet\n");
				tcp_hdr = (struct tcphdr *)(pcap_data + sizeof(*ip_hdr));

				/* This assert was failing so allow packets through
				 * while I work out what is wrong */
				/* assert(tcp_hdr->th_flags & TH_SYN); */
				if (!(tcp_hdr->th_flags & TH_SYN))
				{
					DPRINT("ids_pcap_read_packet(): tcp packet did not have SYN flag set\n");
					goto error;
				}

				ip_addr = ip_hdr->ip_dst;
				/* TODO: Send to blacklist */

				DPRINT("ids_pcap_read_packet(): checking blacklist for IP address %s\n",
						inet_ntoa(ip_addr));

				break;
			case 17:
				DPRINT("ids_pcap_read_packet(): udp packet\n");
				udp_hdr = (struct udphdr *)(pcap_data + (sizeof(*eth_hdr) + sizeof(*ip_hdr)));
				payload_pos = (uint8_t *)(pcap_data + (sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(*udp_hdr)));
				dns_pkt = dns_parse(payload_pos,
						pcap_hdr->len - (sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(*udp_hdr)));

				if (!dns_pkt)
				{
					DPRINT("ids_pcap_read_packet(): dns_parse() failed\n");
					goto error;
				}

				/* Check if this is a query */
				if (dns_pkt->header.qdcount)
				{
					for (query = dns_pkt->questions; query; query = query->next)
					{
						/* TODO: Look up query in blacklist */
						char *readable_domain = dns_name_to_readable(query->qname);
						if (readable_domain)
						{
							DPRINT("ids_pcap_read_packet(): checking blacklist for domain name: %s\n",
									readable_domain);
							free(readable_domain);
						}
					}
				}

				free_dns_packet(&dns_pkt);
				break;
			default:
				/* This shouldn't happen */
				DPRINT("ids_pcap_read_packet(): captured packet with protocol %d\n", ip_hdr->ip_p);
				goto error;
		}
	}

	return (1);

error:
	free_dns_packet(&dns_pkt);
	return (0);
}
