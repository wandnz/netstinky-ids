/*
 * uv_mdns_check.c
 *
 * Sets up a handle that will allow the Avahi MDNS library functions to be
 * called from within a libuv event loop.
 *
 * The Avahi library does not allow direct access to the file descriptors that
 * it uses, so using a uv_poll_t handle will not work, but it does have a
 * non-blocking function which should be safe to call once per event loop
 * iteration.
 *
 * This code uses a uv_check_t handle, which will be called once per event loop
 * after polling has taken place. Unfortunately the check handle is not
 * well-documented so it may not be intended to be used for this purpose. If
 * the documentation is updated and it becomes clear that the check handle was
 * intended for something different, updates to libuv will need to be monitored
 * for changes that break this.
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
