/**
 * Sets up packet capture for an IDS.
 */

#ifndef IDS_PCAP_H_
#define IDS_PCAP_H_

#include "ip_blacklist.h"
#include "ids_event_queue.h"

struct ids_pcap_fields
{
	uint32_t src_ip;
	uint32_t dest_ip;
	char *domain;
	char *iface;	/* Not set in the read_packet function */
};

void
ids_pcap_check(struct ids_pcap_fields *f, ip_blacklist *ip_bl, struct ids_event_list *events);

pcap_t *
ids_pcap_get_pcap(const char *if_name);

int
ids_pcap_read_packet(pcap_t *p, struct ids_pcap_fields *out);

#endif /* IDS_PCAP_H_ */
