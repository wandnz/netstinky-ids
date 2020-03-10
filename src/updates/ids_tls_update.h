/*
 * ids_tls_update.h
 *
 *  Created on: Jul 22, 2019
 *      Author: mfletche
 */

#ifndef SRC_BLACKLIST_UPDATES_IDS_TLS_UPDATE_H_
#define SRC_BLACKLIST_UPDATES_IDS_TLS_UPDATE_H_

#include <stdlib.h>

#include "uv_tls.h"
#include "../blacklist/domain_blacklist.h"
#include "../blacklist/ip_blacklist.h"
#include "../error/ids_error.h"

typedef enum
{
	NS_PROTO_VERSION_WAITING,
	NS_PROTO_OP_SENDING,
	NS_PROTO_IOCS_WAITING,
	NS_PROTO_CONF_SENDING,
	NS_PROTO_CLOSE
} ns_cli_state_t;

typedef enum
{
	NS_ACTION_NOP,
	NS_ACTION_WRITE,
	NS_ACTION_CLOSE
} ns_action_type_t;

typedef struct
{
	ns_action_type_t type;
	uv_buf_t send_buffer;
} ns_action_t;

typedef struct
{
	ns_cli_state_t state;
} ns_cli_proto_t;

typedef struct
{
	const char *server_host;
	uint16_t server_port;
	SSL_CTX *ctx;	// May only be needed once
	tls_stream_t stream;
	ns_cli_proto_t proto;
	domain_blacklist **domain;
	ip_blacklist **ip;
	domain_blacklist *new_domain;
	ip_blacklist *new_ip;
} ids_update_ctx_t;

int
ns_cl_proto_on_recv(ns_action_t *action, ns_cli_state_t *state,
		tls_stream_t *stream, const uv_buf_t *buf);

int
ns_cl_proto_on_send(ns_action_t *action, ns_cli_state_t *state,
		tls_stream_t *stream, int status);

ns_action_t
ns_cl_proto_on_handshake(ns_cli_state_t *state, tls_stream_t *stream);

/**
 * Initialize an ids_update_ctx_t.
 * @param update_ctx: Uninitialized ids_update_ctx_t. May not be NULL.
 * @param loop: Libuv event loop. May not be NULL.
 * @param update_host: Hostname of the update server to connect to.
 * @param update_port: TCP port number of the update server to connect to.
 * @param domain: Domain blacklist which will be updated.
 * @param ip: IP blacklist which will be updated.
 * @return: 0 if successful
 */
int
setup_update_context(ids_update_ctx_t *update_ctx, uv_loop_t *loop,
		const char *update_host, const uint16_t update_port,
		domain_blacklist **domain, ip_blacklist **ip);

/**
 * Teardown an ids_update_ctx_t. This function starts the teardown process but
 * closing the tls_stream will not be completed immediately.
 * @param update_ctx: Address of the update_ctx.
 * @return: 0 if successful.
 */
int
teardown_update_context(ids_update_ctx_t *update_ctx);

/**
 * Setup the timer handle for updating the blacklists.
 * @param timer: An uninitialized timer handle.
 * @param loop: The event loop to add the handle to.
 * @param ctx: The update context.
 */
int
setup_update_timer(uv_timer_t *timer, uv_loop_t *loop, ids_update_ctx_t *ctx);

#endif /* SRC_BLACKLIST_UPDATES_IDS_TLS_UPDATE_H_ */
