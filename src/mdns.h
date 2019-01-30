/*
 * mdns.h
 *
 *  Created on: 24/10/2018
 *      Author: mfletche
 */

#ifndef MDNS_H_
#define MDNS_H_

#include "dns.h"

/* Construct a reply packet from a query packet and a list of records. */
struct dns_packet *
mdns_construct_reply(struct dns_packet *p, struct dns_answer *record_list);

/**
 * Set up a multicast socket which listens to the MDNS IP address and
 * port number.
 *
 * If the multicast socket could not be created, it will return 0,
 * otherwise it will be a socket file descriptor.
 */
int
mdns_get_socket();

/**
 * Send an MDNS multicast reply by constructing a packet in PACKET_BUF from P.
 */
int
mdns_send_reply(int fd, uint8_t *packet_buf, size_t buf_len, struct dns_packet *p);

struct dns_answer *
new_mdns_answer(uint8_t *name, uint16_t type, uint32_t ttl);

#endif /* MDNS_H_ */
