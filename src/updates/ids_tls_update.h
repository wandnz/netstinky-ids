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
#ifndef SRC_BLACKLIST_UPDATES_IDS_TLS_UPDATE_H_
#define SRC_BLACKLIST_UPDATES_IDS_TLS_UPDATE_H_

#include <stdlib.h>

#include "../utils/uvtls/uv_tls.h"
#include "../blacklist/domain_blacklist.h"
#include "../blacklist/ip_blacklist.h"
#include "../error/ids_error.h"

/** Client states */
typedef enum
{
    /** Awaiting server to send protocol version */
    NS_PROTO_VERSION_WAITING,
    /** Sending a query to the server */
    NS_PROTO_OP_SENDING,
    /** Awaiting receiving IoCs from server */
    NS_PROTO_IOCS_WAITING,
    /** Sending update confirmation to server */
    NS_PROTO_CONF_SENDING,
    /** Close connection */
    NS_PROTO_CLOSE
} ns_cli_state_t;

/** Server action states */
typedef enum
{
    /** No-operation **/
    NS_ACTION_NOP,
    /** Perform a write **/
    NS_ACTION_WRITE,
    /** Perform a read **/
    NS_ACTION_CLOSE
} ns_action_type_t;

/** Server action state machine */
typedef struct
{
    /** Current server action state */
    ns_action_type_t type;
    /** Buffer to use for write actions */
    uv_buf_t send_buffer;
} ns_action_t;

/** Client protocol state machine */
typedef struct
{
    ns_cli_state_t state;   ///< Current state
} ns_cli_proto_t;

/**
 * @brief IoC update context
 *
 * Holds the relevant context for updating the internal IoC blacklists from a
 * remote source
 */
typedef struct
{
    /** Host of the update server */
    const char *server_host;
    /** Port of the update server */
    uint16_t server_port;
    /** SSL/TLS library context object to use when starting connections */
    struct ssl_context *ctx;
    /** The active TLS stream for communicating with the remote server */
    tls_stream_t stream;
    /** The current state of the client protocol state-machine */
    ns_cli_proto_t proto;
    /** Pointer to the active #domain_blacklist pointer */
    domain_blacklist **domain;
    /** Pointer to the active #ip_blacklist pointer */
    ip_blacklist **ip;
    /** Pointer to the staging #domain_blacklist */
    domain_blacklist *new_domain;
    /** Pointer to the staging #ip_blacklist */
    ip_blacklist *new_ip;
} ids_update_ctx_t;

/**
 * @brief Callback function called when data is received from the server
 *
 * @param[out] action Pointer to an action state struct that will be updated
 * @param[in, out] state The client state, will be both read and updated
 * @param stream The data stream between the server and the IDS
 * @param buf A buffer of data received from the server
 *
 * @return 0 on success, -1 on error
 */
int
ns_cl_proto_on_recv(ns_action_t *action, ns_cli_state_t *state,
        tls_stream_t *stream, const uv_buf_t *buf);

/**
 * @brief Callback function called when data needs to be written to the server
 *
 * @param[out] action Pointer to an action state struct that will be updated
 * @param[in, out] state The client state, will be both read and updated
 * @param stream The data stream between the server and the IDS
 * @param status The status of the write operation
 *
 * @return 0 on success, -1 on error
 */
int
ns_cl_proto_on_send(ns_action_t *action, ns_cli_state_t *state,
        tls_stream_t *stream, int status);

/**
 * @brief Callback function called when the handshake is completed
 *
 * @param state The current client state
 * @param stream The data stream between the server and the IDS
 */
ns_action_t
ns_cl_proto_on_handshake(ns_cli_state_t *state, tls_stream_t *stream);

/**
 * Initialize an ids_update_ctx_t
 * @param update_ctx Uninitialized ids_update_ctx_t. May not be NULL
 * @param loop Libuv event loop. May not be NULL
 * @param update_host Hostname of the update server to connect to
 * @param update_port TCP port number of the update server to connect to
 * @param ssl_no_verify Skip verifying TLS certificates
 * @param domain Domain blacklist which will be updated
 * @param ip IP blacklist which will be updated
 * @return 0 if successful
 */
int
setup_update_context(ids_update_ctx_t *update_ctx, uv_loop_t *loop,
        const char *update_host, const uint16_t update_port,
        int ssl_no_verify,
        domain_blacklist **domain, ip_blacklist **ip);

/**
 * Teardown an ids_update_ctx_t. This function starts the teardown process but
 * closing the tls_stream will not be completed immediately.
 * @param update_ctx Address of the update_ctx
 * @return 0 if successful
 */
int
teardown_update_context(ids_update_ctx_t *update_ctx);

/**
 * Setup the timer handle for updating the blacklists
 * @param timer An uninitialized timer handle
 * @param loop The event loop to add the handle to
 * @param ctx The update context
 */
int
setup_update_timer(uv_timer_t *timer, uv_loop_t *loop, ids_update_ctx_t *ctx);

#endif /* SRC_BLACKLIST_UPDATES_IDS_TLS_UPDATE_H_ */
