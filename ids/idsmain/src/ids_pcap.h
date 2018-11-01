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

/**
 * Checks the domain name blacklist if a domain name is present in F, otherwise
 * checks the IP address blacklist.
 * @param f The relevant fields from a packet capture.
 * @param ip_bl The ip_blacklist structure to check.
 * @return 1 if an IP address or domain name was in the blacklist
 */
int
ids_pcap_is_blacklisted(struct ids_pcap_fields *f, ip_blacklist *ip_bl);

pcap_t *
ids_pcap_get_pcap(const char *if_name);

/**
 * Puts fields from the incoming packet into an ids_pcap_fields structure. If
 * the packet was a DNS query, the query will be in the DOMAIN attribute.
 *
 * This does not change the IFACE attribute.
 * @param p The pcap device to read a packet from
 * @param out The structure to write the fields into
 * @return 1 if reading was successful and the packet was one that we are
 * interested in, 0 if packet was not one we are interested in, -1 if there
 * was an error
 */
int
ids_pcap_read_packet(pcap_t *p, struct ids_pcap_fields *out);

#endif /* IDS_PCAP_H_ */
