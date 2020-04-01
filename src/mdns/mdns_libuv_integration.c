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
 * @brief Sets up a handle that will allow the Avahi MDNS library functions to
 * be called from within a libuv event loop.
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
 */
#include <stdio.h>

#include "ids_mdns_avahi.h"

#include "error/ids_error.h"
#include "mdns_libuv_integration.h"

int mdns_setup_event_handle(uv_loop_t *loop, uv_check_t *check, AvahiSimplePoll *poll)
{
    assert(loop);
    assert(check);
    assert(poll);
    int r;

    if (0 > (r = uv_check_init(loop, check)))
    {
        fprintf(stderr, "Failed to initialize the MDNS event handle: %s\n",
            uv_strerror(r));
        return NSIDS_UV;
    }

    // Store address of poll in check handle.
    check->data = poll;
    return NSIDS_OK;
}

static void mdns_check_cb(uv_check_t *handle)
{
    assert(handle);
    assert(handle->data);

    // Do a single non-blocking Avahi event loop.
    AvahiSimplePoll *poll = (AvahiSimplePoll *)handle->data;
    ids_mdns_walk(poll);
}

int mdns_check_start(uv_check_t *check)
{
    assert(check);

    int r;

    if (0 > (r = uv_check_start(check, mdns_check_cb)))
    {
        fprintf(stderr, "Failed to start MDNS event handle: %s\n", uv_strerror(r));
        return NSIDS_UV;
    }

    return NSIDS_OK;
}

bool mdns_check_stop(uv_check_t *check)
{
    int r;
    assert(check);

    r = uv_check_stop(check);
    return (r == 0);
}
