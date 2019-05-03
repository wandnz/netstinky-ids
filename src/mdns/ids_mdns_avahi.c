/*
 * Set up MDNS using the Avahi library.
 *
 * Publishes the connection details of the IDS server which transmits IDS
 * events.
 *
 * ids_mdns.c
 *
 *  Created on: 11/04/2019
 *      Author: mfletche
 */
#include "ids_mdns_avahi.h"

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <avahi-common/alternative.h>
#include <avahi-common/domain.h>
#include <avahi-common/error.h>
#include <avahi-common/malloc.h>


void create_services(AvahiMdnsContext *mdns);

/**
 * Run on an AvahiMdnsContext when the service name clashes with another
 * service advertising on the network.
 *
 * It will replace the name field in the AvahiMdnsContext.
 */
static bool AvahiMdnsContext_use_alternative_service_name(AvahiMdnsContext *mdns)
{
	char *n;

	assert(mdns);
	assert(mdns->name);
	assert(avahi_is_valid_service_name(mdns->name));

	// This can fail if c->name is not a valid service name or memory cannot be
	// allocated
	n = avahi_alternative_service_name(mdns->name);
	if (!n) return false;

	avahi_free(mdns->name);
	mdns->name = n;

	return true;
}

static void entry_group_callback(AvahiEntryGroup *g, AvahiEntryGroupState state, void *userdata)
{
	AvahiMdnsContext *mdns = (AvahiMdnsContext *)userdata;
	assert(mdns);
	assert(g == mdns->group || mdns->group == NULL);
	mdns->group = g;

	switch(state)
	{
	case AVAHI_ENTRY_GROUP_ESTABLISHED:
		break;
	case AVAHI_ENTRY_GROUP_COLLISION:
		if (!AvahiMdnsContext_use_alternative_service_name(mdns))
		{
			fprintf(stderr, "Could not use alternative service name for service '%s'\n",
					mdns->name);
		}
		else
		{
			fprintf(stderr, "Using alternative service name: '%s'\n", mdns->name);
			create_services(mdns);
		}
		break;
	case AVAHI_ENTRY_GROUP_FAILURE:
		fprintf(stderr, "entry_group_callback: %s\n",
				avahi_strerror(avahi_client_errno(avahi_entry_group_get_client(g))));
		avahi_simple_poll_quit(mdns->simple_poll);
		break;
	case AVAHI_ENTRY_GROUP_UNCOMMITED:
		break;
	case AVAHI_ENTRY_GROUP_REGISTERING:
		break;
	}
}

/**
 * Sets up all services when the client state changes to running.
 */
void create_services(AvahiMdnsContext *mdns)
{
	int ret;
	//assert(mdns->client);

	// Check if first time running
	if (!mdns->group)
		if (!(mdns->group = avahi_entry_group_new(mdns->client, entry_group_callback, mdns)))
		{
			fprintf(stderr, "create_services: %s\n",
					avahi_strerror(avahi_client_errno(mdns->client)));
			goto error;
		}

	if (avahi_entry_group_is_empty(mdns->group))
	{
		if (0 > (ret = avahi_entry_group_add_service(mdns->group, AVAHI_IF_UNSPEC,
				AVAHI_PROTO_UNSPEC, 0, mdns->name, "_ids._tcp", NULL, NULL, mdns->port, NULL)))
		{
			if (AVAHI_ERR_COLLISION == ret)
				goto collision;
			fprintf(stderr, "create_services: %s\n", avahi_strerror(ret));
			goto error;
		}
	}

	if (0 > (ret = avahi_entry_group_commit(mdns->group)))
	{
		fprintf(stderr, "create_services: %s\n", avahi_strerror(ret));
		goto error;
	}

	return;
collision:
	AvahiMdnsContext_use_alternative_service_name(mdns);

	fprintf(stdout, "Renaming service to %s\n", mdns->name);
	avahi_entry_group_reset(mdns->group);
	create_services(mdns);
	return;

error:
	avahi_simple_poll_quit(mdns->simple_poll);
}

/**
 * Callback for when AvahiClient changes state.
 */
static void
client_callback(AvahiClient *c, AvahiClientState state, void *userdata)
{
	AvahiMdnsContext *mdns = (AvahiMdnsContext *)userdata;

	// The first time this runs, client may not have been assigned yet
	if (!mdns->client) mdns->client = c;

	switch(state)
	{
	case AVAHI_CLIENT_S_RUNNING:
		printf("AVAHI_CLIENT_S_RUNNING\n");
		create_services(mdns);
		break;
	case AVAHI_CLIENT_FAILURE:
		fprintf(stderr, "client_callback: %s\n", avahi_strerror(avahi_client_errno(c)));
		avahi_simple_poll_quit(mdns->simple_poll);
		break;
	case AVAHI_CLIENT_S_COLLISION:
		printf("AVAHI_CLIENT_S_COLLISION\n");
		// continue
	case AVAHI_CLIENT_S_REGISTERING:
		printf("AVAHI_CLIENT_S_REGISTERING\n");
		if (mdns->group) avahi_entry_group_reset(mdns->group);
		break;
	case AVAHI_CLIENT_CONNECTING:
		printf("AVAHI_CLIENT_CONNECTING");
		break;
	}
}

bool ids_mdns_setup_mdns(AvahiMdnsContext *mdns, int port)
{
	int error;

	mdns->name = avahi_strdup("NetStinky");
	mdns->port = port;
	mdns->simple_poll = avahi_simple_poll_new();
	if (!mdns->simple_poll) return false;

	mdns->client = avahi_client_new(avahi_simple_poll_get(mdns->simple_poll),
			0, client_callback, mdns, &error);
	if (!mdns->client)
	{
		fprintf(stderr, "ids_mdns_setup_mdns: %s\n", avahi_strerror(error));
		goto error;
	}

	return true;

error:
	if (mdns->client)
	{
		avahi_client_free(mdns->client);
		mdns->client = NULL;
	}
	if (mdns->simple_poll)
	{
		avahi_simple_poll_free(mdns->simple_poll);
		mdns->simple_poll = NULL;
	}
	if (mdns->name)
	{
		avahi_free(mdns->name);
		mdns->name = NULL;
	}

	return false;
}

/**
 * Runs a single iteration of the Avahi event loop (non-blocking).
 */
void ids_mdns_walk(AvahiSimplePoll *poll)
{
	assert(poll);
	int sleep_time = 0;	// 0 means do not block at all
	avahi_simple_poll_iterate(poll, sleep_time);
}

void ids_mdns_free_mdns(AvahiMdnsContext *mdns)
{
	assert(mdns);

	// freeing avahi_client will free group
	if (mdns->client) avahi_client_free(mdns->client);
	if (mdns->simple_poll) avahi_simple_poll_free(mdns->simple_poll);
	if (mdns->name) avahi_free(mdns->name);

	memset(mdns, 0, sizeof(*mdns));
}
