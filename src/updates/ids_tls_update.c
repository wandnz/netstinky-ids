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
#include <config.h>

#include <assert.h>
#include <string.h>

#include "utils/logging.h"
#include "ids_tls_update.h"

#include "utils/uvtls/uv_tls.h"

#ifndef UPDATE_FREQUENCY_MINS
#define UPDATE_FREQUENCY_MINS 60
#endif

static const uint64_t update_interval_ms = UPDATE_FREQUENCY_MINS * 60 * 1000;

static void
update_timer_cb(uv_timer_t *timer);

static void
update_timer_on_shutdown(tls_stream_t *stream, int status);

static void
update_timer_on_write(tls_stream_t *stream, int status, uv_buf_t *bufs,
        unsigned int nbufs);

int
setup_update_context(ids_update_ctx_t *update_ctx, uv_loop_t *loop,
        const char *update_host, const uint16_t update_port,
        int ssl_no_verify,
        domain_blacklist **domain, ip_blacklist **ip)
{
    assert(update_ctx);
    assert(loop);
    assert(domain);
    assert(ip);

    memset(update_ctx, 0, sizeof(*update_ctx));

    // Setup SSL context
    NetStinky_ssl->init(&update_ctx->ctx, update_host, ssl_no_verify);
    if (NULL == update_ctx->ctx) return NSIDS_SSL;

    update_ctx->server_host = update_host;
    update_ctx->server_port = update_port;

    // Save blacklist pointers
    update_ctx->domain = domain;
    update_ctx->ip = ip;
    update_ctx->proto.state = NS_PROTO_VERSION_WAITING;
    update_ctx->stream.data = update_ctx;

    // Prepare new blacklist pointers
    update_ctx->new_domain = NULL;
    update_ctx->new_ip = NULL;

    return NSIDS_OK;
}

static void
teardown_update_context_close_cb(tls_stream_t *stream)
{
    tls_stream_fini(stream);
}

int
teardown_update_context(ids_update_ctx_t *update_ctx)
{
    int rc;

    if (!update_ctx) return -1;

    
    // If the current domain structure equals the new domain structure,
    // do not free it!
    if (update_ctx->domain != NULL &&
            *update_ctx->domain == update_ctx->new_domain)
        update_ctx->new_domain = NULL;

    // If the current ip structure equals the new ip structure,
    // do not free it!
    if (update_ctx->ip != NULL &&
            *update_ctx->ip == update_ctx->new_ip)
        update_ctx->new_ip = NULL;

    // Not managed by the update ctx, user responsible for freeing
    update_ctx->domain = NULL;
    update_ctx->ip = NULL;

    // If the `new` structures are non-NULL, they haven't been set as the
    // active blacklist structures and therefore need to be freed
    if (update_ctx->new_domain)
        domain_blacklist_clear(update_ctx->new_domain);
    if (update_ctx->new_ip)
        ip_blacklist_clear(update_ctx->new_ip);

    update_ctx->proto.state = 0;

    if (update_ctx->ctx)
        NetStinky_ssl->cleanup(update_ctx->ctx);

    // Check if stream is currently initialized and active
    if (update_ctx->stream.tcp.type == UV_TCP)
    {
        rc = tls_stream_close(&update_ctx->stream,
                teardown_update_context_close_cb);
        if (rc != 0)
            memset(&update_ctx->stream, 0,sizeof(update_ctx->stream));
    }

    return 0;
}

static int
perform_protocol_action(tls_stream_t *stream, ns_action_t action)
{
    int rc;

    if (stream == NULL)
        logger(L_ERROR, "perform_protocol_action(): stream was NULL");
    if (!stream) return -1;

    switch (action.type)
    {
    case NS_ACTION_NOP:
        break;
    case NS_ACTION_WRITE:
        rc = tls_stream_write(stream, (const uv_buf_t *)&action.send_buffer, 1,
                update_timer_on_write);
        if (TLS_STR_OK != rc) return -1;
        break;
    case NS_ACTION_CLOSE:
        rc = tls_stream_shutdown(stream, update_timer_on_shutdown);
        if (TLS_STR_OK != rc) return -1;
        break;
    }

    return 0;
}

static void
update_timer_on_write(tls_stream_t *stream, int status, uv_buf_t *bufs,
        unsigned int nbufs)
{
    int rc;
    unsigned int buf_idx;
    ns_action_t action;
    ids_update_ctx_t *ctx = NULL;

    if (stream->data == NULL)
        logger(L_ERROR, "update_timer_on_write(): stream->data was NULL");
    ctx = stream->data;

    // Free buffers
    if (bufs)
    {
        for (buf_idx = 0; buf_idx < nbufs; buf_idx++)
        {
            if (bufs[buf_idx].base) free(bufs[buf_idx].base);
        }
    }

    if (status)
    {
        // Error state
        rc = tls_stream_shutdown(stream, update_timer_on_shutdown);
        // Ignore return value
    }

    rc = ns_cl_proto_on_send(&action, &ctx->proto.state, stream, status);
    if (rc != 0) return;
    rc = perform_protocol_action(stream, action);
}

/**
 * Finalizes the update timer after the stream is closed.
 */
static void
update_timer_on_close(tls_stream_t *stream)
{
    tls_stream_fini(stream);
    memset(&stream->tcp, 0, sizeof(stream->tcp));
}

static void
update_timer_on_shutdown(tls_stream_t *stream,
                         int status __attribute__((unused)))
{
    if (!stream) return;

    // Have tried keeping the structure for the next connection but get an
    // 'operation not permitted' error from uv_connect.
    tls_stream_close(stream, update_timer_on_close);
}

static void
update_timer_on_read(tls_stream_t *stream, int status, const uv_buf_t *buf)
{
    int rc;
    ns_action_t action;
    ids_update_ctx_t *ctx = NULL;

    if (stream == NULL)
        logger(L_ERROR, "update_timer_on_read(): stream was NULL");
    if (!stream) return;

    if (TLS_STR_OK != status)
    {
        if (buf) free(buf->base);
        rc = tls_stream_shutdown(stream, update_timer_on_shutdown);
        return;
    }

    if (!buf) return;
    ctx = stream->data;

    if (!buf->base) return;

    logger(L_DEBUG, "Rx'd buffer of len: %lu", buf->len);

    rc = ns_cl_proto_on_recv(&action, &ctx->proto.state, stream, buf);
    free(buf->base);
    if (0 != rc)
    {
        rc = tls_stream_shutdown(stream, update_timer_on_shutdown);
        return;
    }

    switch(action.type)
    {
    case NS_ACTION_WRITE:
        rc = tls_stream_write(stream, &action.send_buffer, 1, update_timer_on_write);
        if (rc) tls_stream_shutdown(stream, update_timer_on_shutdown);
        break;
    case NS_ACTION_CLOSE:
        rc = tls_stream_shutdown(stream, update_timer_on_shutdown);
        break;
    default:
        break;
    }
}

static void
update_timer_on_handshake(tls_stream_t *stream, int status)
{
    int rc;
    ns_action_t action;

    if (stream == NULL)
        logger(L_ERROR, "update_timer_on_handshake(): stream was NULL");
    if (!stream) return;

    if (status)
    {
        rc = tls_stream_shutdown(stream, update_timer_on_shutdown);
        // Don't think error code matters

        return;
    }

    action = ns_cl_proto_on_handshake(stream->data, stream);
    rc = perform_protocol_action(stream, action);
    if (rc)
        logger(L_WARN, "Could not perform protocol action");

    return;
}

static int
hostname_tls_connect(tls_stream_t *stream, int status, struct sockaddr *sa)
{
    int rc;
    if (status != 0) goto error;
    rc = tls_stream_connect(stream, sa,
            update_timer_on_handshake, update_timer_on_read);
    if (0 != rc) goto error;
    return 0;
error:
    rc = tls_stream_close(stream, update_timer_on_close);
    if (rc)
    {
        tls_stream_fini(stream);
        memset(stream, 0, sizeof(*stream));
    }
    return -1;
}

static void
on_resolved(uv_getaddrinfo_t *req, int status, struct addrinfo *res)
{
    ids_update_ctx_t *ctx = req->data;
    struct sockaddr *sockaddr;
    struct addrinfo *rp;
    int rc;
    if (status != 0)
    {
        logger(L_WARN, "getaddrinfo: %s", uv_strerror(status));
    }

    /**
     * TODO: Should attempt to connect to _each_ addrinfo in turn if the first
             connection does not succeed.
    **/
    for (rp = res; rp != NULL; rp = rp->ai_next)
    {
        struct sockaddr_in *sain;
        sockaddr = rp->ai_addr;
        /** TODO: Change this to support IPv6 **/
        sain = (struct sockaddr_in *) sockaddr;
        sain->sin_port = htons(ctx->server_port);
        rc = hostname_tls_connect(&ctx->stream, status, sockaddr);
        if (rc == 0) break; /** TODO: As per the previous todo note **/
    }

    uv_freeaddrinfo(res);
    free(req);
}

static int
hostname_lookup(ids_update_ctx_t *ctx, uv_loop_t *loop)
{
    uv_getaddrinfo_t *resolver;
    struct addrinfo hints;
    int status;
    const char *hostname = ctx->server_host;

    if (hostname == NULL)
        return UV_EINVAL;

    resolver = malloc(sizeof(*resolver));
    memset(resolver, 0, sizeof(*resolver));
    resolver->data = ctx;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    hints.ai_protocol = 0;

    status = uv_getaddrinfo(loop, resolver, on_resolved,
            hostname, NULL, &hints);
    
    return status;
}

static void
update_timer_cb(uv_timer_t *timer)
{
    assert(timer);

    int rc;
    ids_update_ctx_t *ctx = NULL;

    // Connect to the IOC server
    ctx = timer->data;

    // Re-init protocol
    ctx->proto.state = NS_PROTO_VERSION_WAITING;

    // When not initialized, the handle type will be UNKNOWN. Check if the previous TCP
    // handle is still open.
    if (ctx->stream.tcp.type == UV_TCP)
    {
        if (uv_is_active((uv_handle_t *)&ctx->stream.tcp))
        {
            // Close properly, but might mean cannot update until next timeout.
            rc = tls_stream_close(&ctx->stream, update_timer_on_close);
            if (rc)
            {
                // Callback is not going to happen, so free and continue
                tls_stream_fini(&ctx->stream);
                memset(&ctx->stream, 0, sizeof(ctx->stream));
            }
            else
                // Can't clean up until after the callback
                return;
        }
        else
        {
            // Inactive handle still exists.
            tls_stream_fini(&ctx->stream);
            memset(&ctx->stream, 0, sizeof(ctx->stream));
        }
    }
    rc = tls_stream_init(&ctx->stream, timer->loop, ctx->ctx);
    if (rc)
    {
        logger(L_ERROR, "Could not initialize TLS stream");
        goto error;
    }
    ctx->stream.data = ctx;

    /**
     * TODO: Look-up the given hostname here, then perform the stream connection
    **/
    rc = hostname_lookup(ctx, timer->loop);
    if (0 != rc) goto error;
    return;
error:
    // Clear stream
    rc = tls_stream_close(&ctx->stream, update_timer_on_close);
    if (rc)
    {
        tls_stream_fini(&ctx->stream);
        memset(&ctx->stream, 0, sizeof(ctx->stream));
    }
}

int
teardown_timer(uv_timer_t *timer)
{
    uv_timer_stop(timer);
    uv_close((uv_handle_t *)timer, NULL);

    return NSIDS_OK;
}

int
setup_update_timer(uv_timer_t *timer, uv_loop_t *loop, ids_update_ctx_t *ctx)
{
    assert(timer);
    assert(loop);
    assert(ctx);

    int uv_rc;

    uv_rc = uv_timer_init(loop, timer);
    if (uv_rc < 0)
    {
        logger(L_ERROR, "Failed to setup update timer handle: %s",
                uv_strerror(uv_rc));
        return NSIDS_UV;
    }

    timer->data = ctx;
    uv_rc = uv_timer_start(timer, update_timer_cb, 0, update_interval_ms);
    if (uv_rc < 0)
    {
        logger(L_ERROR, "Failed to setup update timer handle: %s",
                uv_strerror(uv_rc));
        teardown_timer(timer);
        return NSIDS_UV;
    }

    return NSIDS_OK;
}
