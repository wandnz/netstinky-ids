/*
 * mdns.h
 *
 *  Created on: 24/10/2018
 *      Author: mfletche
 */

#ifndef MDNS_H_
#define MDNS_H_

#include "dns.h"

/**
 * Set up a multicast socket which listens to the MDNS IP address and
 * port number.
 *
 * If the multicast socket could not be created, it will return 0,
 * otherwise it will be a socket file descriptor.
 */
int
mdns_get_socket();

#endif /* MDNS_H_ */
