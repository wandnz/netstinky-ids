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

    // Value retrieved from blacklist
    const ids_ioc_value_t *ioc_value;

    struct ids_pcap_fields fields;
    memset(&fields, 0, sizeof(fields));
    result = ids_pcap_read_packet(pcap_hdr, packet, &fields);
    if (result == 1) {

    	// Value will be non-NULL if the domain/IP is blacklisted
        if (NULL != (ioc_value = ids_pcap_is_blacklisted(&fields, ip_bl, dn_bl))) {
            struct in_addr ip;
            // TODO: A name is required, but has proved difficult to get
            char *iface_name = "placeholder";
            char *ioc_str;
            struct ids_event *ev;

            ip.s_addr = fields.dest_ip;
            ioc_str = fields.domain ? fields.domain : strdup(inet_ntoa(ip));
            ev = new_ids_event(
            		iface_name,
					fields.src_ip,
					ioc_str,
					fields.src_mac,
					*ioc_value);

            if (!ids_event_list_add_event(event_queue, ev)) {
                DPRINT("packet_handler: ids_event_list_add() failed\n");
                goto end;
            }

            DPRINT("pcap_io_task_read(): NEW DETECTED INTRUSION\n");
            // Don't free domain name because it is added to event list
            return;

        } else {
            DPRINT("Safe!\n");
        }
    } else if (result == -1) {
        DPRINT("pcap_io_task_read(): ids_pcap_read_packet() failed\n");
    }

end:
	// If domain name is not added to event list, free it
    if (fields.domain != NULL) {
        free(fields.domain);
    }
}

const ip_key_value_t *
ids_pcap_lookup_ip(ip_blacklist *b, uint32_t addr, uint16_t port)
{
	assert(b);
	return (ip_blacklist_lookup(b, addr, port));
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
        char src_str[18];
        char dst_str[18];
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

		// These are stored Most Significant Byte first
		eth_hdr = (struct ether_header *)pcap_data;
		out->src_mac = *(mac_addr *)eth_hdr->ether_shost;
		out->dest_mac = *(mac_addr *)eth_hdr->ether_dhost;

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
		out->dest_ip = ip_hdr->ip_dst.s_addr;
		out->src_ip = ip_hdr->ip_src.s_addr;

		switch (ip_hdr->ip_p)
		{
			case IPPROTO_TCP:
				DPRINT("ids_pcap_read_packet(): tcp packet\n");
				tcp_hdr = (struct tcphdr *)(pcap_data + sizeof(*eth_hdr) + sizeof(*ip_hdr));
				out->dest_port = tcp_hdr->dest;
				out->src_port = tcp_hdr->source;

				/* Check header is correct */
				assert((tcp_hdr->th_flags & TH_SYN) && !(tcp_hdr->th_flags & TH_ACK));

				out->domain = NULL;
				break;
			case IPPROTO_UDP:
				DPRINT("ids_pcap_read_packet(): udp packet\n");
				udp_hdr = (struct udphdr *)(pcap_data + (sizeof(*eth_hdr) + sizeof(*ip_hdr)));
				out->dest_port = udp_hdr->dest;
				out->src_port = udp_hdr->source;
				payload_pos = (uint8_t *)(pcap_data + (sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(*udp_hdr)));

				uint8_t *payload_end = (uint8_t *) payload_pos + (pcap_hdr->len - (sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(*udp_hdr)));
				if (payload_pos >= payload_end) goto error;
				dns_pkt = dns_parse(payload_pos, payload_end);

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
					DPRINT("ids_pcap_read_packet(): domain %s\n", out->domain);
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

const ids_ioc_value_t *
ids_pcap_is_blacklisted(struct ids_pcap_fields *f, ip_blacklist *ip_bl, domain_blacklist *dn_bl)
{
	struct in_addr src_ip_buf, dst_ip_buf;
	src_ip_buf.s_addr = f->src_ip;
	dst_ip_buf.s_addr = f->dest_ip;

	char *src = strdup(inet_ntoa(src_ip_buf));

	/* Can only have one inet_ntoa call per line because it will over-write the buffer */
	DPRINT("%s -> %s: %s ", src, inet_ntoa(dst_ip_buf), f->domain);
	free(src);

	if (f->domain)
	{
		return (domain_blacklist_is_blacklisted(dn_bl, f->domain));
	}
	else return (&ip_blacklist_lookup(ip_bl, f->dest_ip, f->dest_port)->value);

	return (NULL);
}

int set_filter(pcap_t *pcap, const char *filter, char *err)
{
    int rc = -1;
    struct bpf_program fp;

    if (pcap == NULL || filter == NULL) return 0;

    memset(&fp, 0, sizeof(fp));

    if ((rc = pcap_compile(pcap, &fp, filter, 0, PCAP_NETMASK_UNKNOWN)) != 0) {
        fprintf(stderr, "Error in filter expression: %s\n", err);
        goto done;
    }
    if ((rc = pcap_setfilter(pcap, &fp)) != 0) {
        fprintf(stderr, "Can't set filter expression: %s\n", err);
        goto done;
    }

    pcap_freecode(&fp);
    rc = 0;
done:
    return rc;
}

/**
 * Called when an event occurs on the pcap file descriptor.
 * @param handle: The handle of the libuv poll handle.
 * @param status: status < 0 indicates that an error occurred, 0 means success.
 * @param events: A bitmask of events.
 */
static void pcap_data_cb(uv_poll_t *handle, int status, int events)
{
	int pkt_num = 0, cnt = -1;
	pcap_t *pcap = (pcap_t *)handle->data;

    if (status < 0) {
        fprintf(stderr, "Error while polling fd: %s\n", uv_strerror(status));
        return;
    }

    assert(status==0);

    if (events & UV_READABLE) {
        // If we are here, the fd is ready to read
        // cnt = 0 or -1 means read all packets (but -1 will work with older versions of pcap,
        // where 0 does not)
        pkt_num = pcap_dispatch(pcap, cnt, packet_handler, NULL);

        if (pkt_num == PCAP_ERROR) {
            fprintf(stderr, "Error processing packet\n%s\n",
                    pcap_geterr(pcap));
        } else if (pkt_num == PCAP_ERROR_BREAK) {
            fprintf(stderr, "Pcap requested loop close.\n");
            uv_stop(handle->loop);
        }
    }
}

bool setup_pcap_handle(uv_loop_t *loop, uv_poll_t *pcap_handle, pcap_t *pcap)
{
	assert(loop);
	assert(pcap_handle);
	assert(pcap);

	int fd;

	if (PCAP_ERROR == (fd = pcap_get_selectable_fd(pcap))) return false;

    if (0 > uv_poll_init(loop, pcap_handle, fd))
    {
    	printf("polling could not be initialized\n");
    	return false;
    }

    if (0 > uv_poll_start(pcap_handle, UV_READABLE, pcap_data_cb))
    {
    	printf("could not start polling\n");
    	return false;
    }

    pcap_handle->data = pcap;

    return true;
}

int configure_pcap(pcap_t **pcap, const char *filter, const char *dev, char *err)
{
    int retval = -1;
    int pcap_fd;
    if ((*pcap = pcap_create(dev, err)) == NULL) {
        fprintf(stderr, "Can't open %s: %s\n", dev, err);
        retval = -2;
        goto error;
    }
    if (pcap_set_promisc(*pcap, 1) != 0) {
        fprintf(stderr, "pcap_set_promisc failed\n");
        retval = -4;
        goto error;
    }
    if (pcap_activate(*pcap) != 0) {
        fprintf(stderr, "pcap_activate failed\n");
        retval = -5;
        goto error;
    }
    if (set_filter(*pcap, filter, err) != 0) {
        fprintf(stderr, "Who even cares?\n");
        retval = -3;
        goto error;
    }

    pcap_fd = pcap_get_selectable_fd(*pcap);
    if (pcap_fd == -1) {
        fprintf(stderr, "pcap_get_sel_fd failed\n");
        retval = -6;
        goto error;
    }

    retval = 0;
    return retval;
error:
	if (*pcap) pcap_close(*pcap);
	*pcap = NULL;
	return retval;
}
