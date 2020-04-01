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
#ifndef SRC_MDNS_MDNS_LIBUV_INTEGRATION_H_
#define SRC_MDNS_MDNS_LIBUV_INTEGRATION_H_

#include <assert.h>
#include <stdbool.h>

#include <avahi-common/simple-watch.h>

#include <uv.h>

/**
 * Setup the libuv handles that will be responsible for running MDNS functions.
 * @param loop The main libuv event loop.
 * @param check An uninitialized uv_check_t handle.
 * @returns True if successful.
 */
int mdns_setup_event_handle(uv_loop_t *loop, uv_check_t *check, AvahiSimplePoll *poll);

/**
 * Start calling the MDNS functions within the event loop.
 * @param check An initialized uv_check_t structure.
 * @returns True if successful.
 */
int mdns_check_start(uv_check_t *check);

/**
 * Stop running the MDNS functions within the event loop.
 * @param check An initialized uv_check_t structure.
 * @returns True if successful.
 */
bool mdns_check_stop(uv_check_t *check);

#endif /* SRC_MDNS_MDNS_LIBUV_INTEGRATION_H_ */
