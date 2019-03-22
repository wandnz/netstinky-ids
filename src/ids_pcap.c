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

#include "utils/common.h"
#include "ip_blacklist.h"
#include "domain_blacklist.h"
#include "dns.h"
#include "ids_pcap.h"

/**
 * TODO: Refactor references to global state into a struct pointed to by
 * \s user_dat instead.
 */
extern ip_blacklist *ip_bl;
extern domain_blacklist *dn_bl;
extern struct ids_event_list *event_queue;

void packet_handler(unsigned char *user_dat,
                    const struct pcap_pkthdr* pcap_hdr,
                    const unsigned char *packet)
{
    int result;
    struct ids_pcap_fields fields;
    memset(&fields, 0, sizeof(fields));
    result = ids_pcap_read_packet(pcap_hdr, packet, &fields);
    if (result == 1) {
        if (ids_pcap_is_blacklisted(&fields, ip_bl, dn_bl)) {
            struct in_addr ip;
            char *iface_name = strdup("eth0");  // TODO: Fix this
            char *ioc_str;
            struct ids_event *ev;

            ip.s_addr = htonl(fields.dest_ip);
            ioc_str = fields.domain ? fields.domain : strdup(inet_ntoa(ip));
            ev = new_ids_event(iface_name, fields.src_ip, ioc_str);

            if (!ids_event_list_add_event(event_queue, ev)) {
                DPRINT("packet_handler: ids_event_list_add() failed\n");
                return;
            }

            DPRINT("pcap_io_task_read(): NEW DETECTED INTRUSION\n");
        } else {
            DPRINT("Safe!\n");
        }
    } else if (result == -1) {
        DPRINT("pcap_io_task_read(): ids_pcap_read_packet() failed\n");
    }

    if (fields.domain != NULL) {
        free(fields.domain);
    }
}

int
ids_pcap_lookup_ip(ip_blacklist *b, uint32_t a)
{
	assert(b);
	return (ip_blacklist_lookup(b, a));
}

int
ids_pcap_read_packet(const struct pcap_pkthdr *pcap_hdr,
                     const unsigned char *pcap_data,
                     struct ids_pcap_fields *out)
{
    struct ether_header *eth_hdr = NULL;
    struct ip *ip_hdr = NULL;
    struct tcphdr *tcp_hdr = NULL;
    struct udphdr *udp_hdr = NULL;
    struct dns_packet *dns_pkt = NULL;

    uint8_t *payload_pos = NULL;
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
			case IPPROTO_TCP:
				DPRINT("ids_pcap_read_packet(): tcp packet\n");
				tcp_hdr = (struct tcphdr *)(pcap_data + sizeof(*eth_hdr) + sizeof(*ip_hdr));

				/* Check header is correct */
				assert((tcp_hdr->th_flags & TH_SYN) && !(tcp_hdr->th_flags & TH_ACK));

				out->domain = NULL;
				break;
			case IPPROTO_UDP:
				DPRINT("ids_pcap_read_packet(): udp packet\n");
				udp_hdr = (struct udphdr *)(pcap_data + (sizeof(*eth_hdr) + sizeof(*ip_hdr)));
				payload_pos = (uint8_t *)(pcap_data + (sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(*udp_hdr)));
				dns_pkt = dns_parse(payload_pos,
						(uint8_t *) payload_pos + (pcap_hdr->len - (sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(*udp_hdr))));

				if (!dns_pkt)
				{
					DPRINT("ids_pcap_read_packet(): dns_parse() failed\n");
					goto error;
				}

				/* Check if this is a query */
				if (dns_pkt->header.qdcount)
				{
					/* TODO: Check multiple questions */
					out->domain = dns_name_to_readable((unsigned char *)
                            dns_pkt->questions->qname);
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
