/*
 * ids_mdns.h
 *
 *  Created on: 11/04/2019
 *      Author: mfletche
 */

#ifndef SRC_IDS_MDNS_H_
#define SRC_IDS_MDNS_H_

#include <stdbool.h>

#include <poll.h>
#include <avahi-common/cdecl.h>
#include <avahi-client/client.h>
#include <avahi-client/publish.h>
#include <avahi-common/simple-watch.h>

/**
 * Encapsulates the variables required for the Avahi client library. Can be
 * provided as userdata to Avahi callback functions, instead of declaring these
 * as global variables.
 */
typedef struct AvahiMdnsContext
{
	AvahiSimplePoll *simple_poll;
	char *name;
	int port;
	AvahiClient *client;
	AvahiEntryGroup *group;
} AvahiMdnsContext;

int ids_mdns_setup_mdns(AvahiMdnsContext *mdns, int port);

/**
 * Perform one non-blocking iteration of the Avahi event loop.
 */
void ids_mdns_walk(AvahiSimplePoll *poll);

/**
 * Free resources needed for MDNS.
 */
void ids_mdns_free_mdns(AvahiMdnsContext *mdns);

#endif /* SRC_IDS_MDNS_H_ */
