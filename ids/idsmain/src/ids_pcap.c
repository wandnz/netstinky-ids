/*
 * ids_pcap.c
 *
 *  Created on: 29/10/2018
 *      Author: mfletche
 */

#include <stdlib.h>
#include <string.h>

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

#include "ip_blacklist.h"
#include "domain_blacklist.h"
#include "dns.h"
#include "ids_pcap.h"

/* -- DEBUGGING -- */
#define DEBUG 1
#define DPRINT(...) do { if (DEBUG) fprintf(stdout, __VA_ARGS__); } while (0)

static const char *pcap_filter = "(udp dst port 53) or (tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0)";
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
ids_pcap_lookup_ip(ip_blacklist *b, uint32_t a)
{
	assert(b);
	return (ip_blacklist_lookup(b, a));
}

int
ids_pcap_read_packet(pcap_t *p, struct ids_pcap_fields *out)
{
	struct pcap_pkthdr *pcap_hdr = NULL;
	const u_char *pcap_data = NULL;

	struct ether_header *eth_hdr = NULL;
	struct ip *ip_hdr = NULL;
	struct tcphdr *tcp_hdr = NULL;
	struct udphdr *udp_hdr = NULL;
	struct dns_packet *dns_pkt = NULL;

	uint8_t *payload_pos = NULL;

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
		if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) return (0);

		if (pcap_hdr->len < (sizeof(*eth_hdr) + sizeof(*ip_hdr)))
		{
			DPRINT("ids_pcap_read_packet(): pcap length too small to contain IP header: %d\n",
					pcap_hdr->len);
			goto error;
		}
		ip_hdr = (struct ip *)(pcap_data + sizeof(*eth_hdr));
		DPRINT("ids_pcap_read_packet(): destination IP: %s\n", inet_ntoa(ip_hdr->ip_dst));
		DPRINT("ids_pcap_read_packet(): source IP: %s\n", inet_ntoa(ip_hdr->ip_src));
		out->dest_ip = ntohl(ip_hdr->ip_dst.s_addr);
		out->src_ip = ntohl(ip_hdr->ip_src.s_addr);

		switch (ip_hdr->ip_p)
		{
			case 6:
				DPRINT("ids_pcap_read_packet(): tcp packet\n");
				tcp_hdr = (struct tcphdr *)(pcap_data + sizeof(*eth_hdr) + sizeof(*ip_hdr));

				/* Check header is correct */
				assert((tcp_hdr->th_flags & TH_SYN) && !(tcp_hdr->th_flags & TH_ACK));

				out->domain = NULL;
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
					/* TODO: Check multiple questions */
					out->domain = dns_name_to_readable(dns_pkt->questions->qname);
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
	return (-1);
}

int
ids_pcap_is_blacklisted(struct ids_pcap_fields *f, ip_blacklist *ip_bl, domain_blacklist *dn_bl)
{
	struct in_addr src_ip_buf, dst_ip_buf;
	src_ip_buf.s_addr = htonl(f->src_ip);
	dst_ip_buf.s_addr = htonl(f->dest_ip);

	char *src = strdup(inet_ntoa(src_ip_buf));

	/* Can only have one inet_ntoa call per line because it will over-write the buffer */
	DPRINT("%s -> %s: %s ", src, inet_ntoa(dst_ip_buf), f->domain);
	free(src);

	if (f->domain)
	{
		return (domain_blacklist_is_blacklisted(dn_bl, f->domain));
	}
	else return (ip_blacklist_lookup(ip_bl, f->dest_ip));

	return (0);
}
