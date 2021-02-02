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
 * @author Andrew Mackintosh
 */
#ifndef SRC_MDNS_UV_WATCH_H_
#define SRC_MDNS_UV_WATCH_H_

#include <uv.h>
#include <avahi-common/watch.h>

typedef struct AvahiUvPoll AvahiUvPoll;

AvahiUvPoll *avahi_uv_poll_new(uv_loop_t *loop);

void avahi_uv_poll_free(AvahiUvPoll *g);

const AvahiPoll *avahi_uv_poll_get(AvahiUvPoll *g);

#endif
