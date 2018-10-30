/**
 * Sets up packet capture for an IDS.
 */

#ifndef IDS_PCAP_H_
#define IDS_PCAP_H_

#include "ip_blacklist.h"

pcap_t *
ids_pcap_get_pcap(const char *if_name);

int
ids_pcap_read_packet(pcap_t *p, ip_blacklist *b);

#endif /* IDS_PCAP_H_ */
