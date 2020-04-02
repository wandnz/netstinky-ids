/*
 *
 * Copyright (c) 2020 The University of Waikato, Hamilton, New Zealand.
 *
 * This file is part of netstinky-ids.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-2-Clause
 *
 *
 */
/** @file
 *
 */
#ifndef SRC_IDS_MDNS_H_
#define SRC_IDS_MDNS_H_

#include <stdbool.h>

#include <poll.h>
#include <avahi-common/cdecl.h>
#include <avahi-client/client.h>
#include <avahi-client/publish.h>
#include <avahi-common/simple-watch.h>

/** The name of the service to advertise */
#define MDNS_SVC_NAME "_netstinky._tcp"

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

/**
 * Initialize an #AvahiMdnsContext an start an avahi client
 * @param mdns An uninitialized context
 * @param port The TCP port to advertise
 */
int
ids_mdns_setup_mdns(AvahiMdnsContext *mdns, int port);

/**
 * Perform one non-blocking iteration of the Avahi event loop.
 */
void
ids_mdns_walk(AvahiSimplePoll *poll);

/**
 * Free resources needed for MDNS.
 */
void
ids_mdns_free_mdns(AvahiMdnsContext *mdns);

#endif /* SRC_IDS_MDNS_H_ */
