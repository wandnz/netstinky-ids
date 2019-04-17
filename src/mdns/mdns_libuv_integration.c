/*
 * uv_mdns_check.c
 *
 *  Created on: 18/04/2019
 *      Author: mfletche
 */

#include "ids_mdns_avahi.h"

#include "mdns_libuv_integration.h"

bool mdns_check_setup(uv_loop_t *loop, uv_check_t *check, AvahiSimplePoll *poll)
{
	int r;
	assert(loop);
	assert(check);
	assert(poll);

	r = uv_check_init(loop, check);

	// Store address of poll in check handle.
	check->data = poll;
	return (r == 0);
}

static void mdns_check_cb(uv_check_t *handle)
{
	assert(handle);
	assert(handle->data);

	// Do a single non-blocking Avahi event loop.
	AvahiSimplePoll *poll = (AvahiSimplePoll *)handle->data;
	ids_mdns_walk(poll);
}

bool mdns_check_start(uv_check_t *check)
{
	int r;
	assert(check);

	r = uv_check_start(check, mdns_check_cb);
	return (r == 0);
}

bool mdns_check_stop(uv_check_t *check)
{
	int r;
	assert(check);

	r = uv_check_stop(check);
	return (r == 0);
}
