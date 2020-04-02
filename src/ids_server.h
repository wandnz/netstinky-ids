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
#ifndef SRC_IDS_SERVER_H_
#define SRC_IDS_SERVER_H_

#include <assert.h>
#include <stdlib.h>

#include <uv.h>

#include "ids_event_list.h"

/**
 * Sets up libuv variables for the IDS event server.
 *
 * @param loop The main event loop of the IDS
 * @param handle The address of an uninitialized uv_tcp_t structure
 * @param port the TCP port for the server to listen on
 * @param list a pointer to the #ids_event_list to send to clients
 * @return 0 if successful, -1 on error
 */
int
setup_event_server(uv_loop_t *loop, uv_tcp_t *handle, int port, struct ids_event_list *list);

#endif /* SRC_IDS_SERVER_H_ */
