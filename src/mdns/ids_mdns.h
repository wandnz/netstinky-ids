/*
 * ids_mdns.h
 *
 *  Created on: 11/04/2019
 *      Author: mfletche
 */

#include <poll.h>
#include <avahi-common/cdecl.h>
#include <avahi-common/simple-watch.h>

#ifndef SRC_IDS_MDNS_H_
#define SRC_IDS_MDNS_H_

/**
 * Encapsulates the variables required for the Avahi client library. Can be
 * provided as userdata to Avahi callback functions, instead of declaring these
 * as global variables.
 */
typedef struct AvahiMdnsContext
{
	AvahiSimplePoll *simple_poll;
	char *name;
	AvahiClient *client;
	AvahiEntryGroup *group;
} AvahiMdnsContext;

#endif /* SRC_IDS_MDNS_H_ */
