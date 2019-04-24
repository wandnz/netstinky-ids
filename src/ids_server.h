/*
 * ids_server.h
 *
 *  Created on: 24/04/2019
 *      Author: mfletche
 */

#ifndef SRC_IDS_SERVER_H_
#define SRC_IDS_SERVER_H_

#include <assert.h>
#include <stdlib.h>

#include <uv.h>

/**
 * Sets up libuv variables for the IDS event server.
 *
 * @param loop: The main event loop of the IDS
 * @param handle: The address of an uninitialized uv_tcp_t structure
 * @param server_addr: The interface and port of the server
 * @return 0 if successful, -1 on error
 */
int
setup_event_server(uv_loop_t *loop, uv_tcp_t *handle, int port);

#endif /* SRC_IDS_SERVER_H_ */
