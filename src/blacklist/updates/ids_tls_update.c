/*
 * Each connection requires a TLS context.
 *
 * ids_tls_update.c
 *
 *  Created on: Jul 22, 2019
 *      Author: mfletche
 */

#include <string.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "ids_tls_update.h"

// 15 minute interval
const static uint64_t update_interval_ms = 15 * 60 * 1000;
const static char *server_ip = "192.168.122.104";
const static int server_port = 15000;

static void
update_timer_cb(uv_timer_t *timer);

static void
update_timer_on_shutdown(tls_stream_t *stream, int status);

SSL_CTX *
setup_context()
{
	SSL_CTX *ctx = NULL;
	const SSL_METHOD *method = SSLv23_method();
	print_if_NULL(method);
	if (!method) return NULL;

	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	//method = TLS_server_method();

	ctx = SSL_CTX_new(method);
	print_if_NULL(ctx);
	if (!ctx) return NULL;

	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY
			| SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
			| SSL_MODE_ENABLE_PARTIAL_WRITE);

	SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);

	return ctx;
}

int
setup_update_context(ids_update_ctx_t *update_ctx, uv_loop_t *loop,
		domain_blacklist **domain, ip_blacklist **ip)
{
	int rc;

	print_if_NULL(update_ctx);
	print_if_NULL(loop);
	print_if_NULL(domain);
	print_if_NULL(ip);
	if (!update_ctx || !loop || !domain || !ip) return -1;

	// Setup SSL context
	update_ctx->ctx = setup_context();
	print_if_NULL(update_ctx->ctx);
	if (NULL == update_ctx->ctx) return -1;

	// Setup actual TLS stream
	rc = tls_stream_init(&update_ctx->stream, loop, update_ctx->ctx);
	if (0 != rc) return -1;

	// Save blacklist pointers
	update_ctx->domain = domain;
	update_ctx->ip = ip;

	update_ctx->proto.state = NS_PROTO_VERSION_WAITING;

	update_ctx->stream.data = update_ctx;

	return 0;
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

	// Not managed by the update ctx, user responsible for freeing
	update_ctx->domain = NULL;
	update_ctx->ip = NULL;

	update_ctx->proto.state = 0;

	if (update_ctx->ctx)
		SSL_CTX_free(update_ctx->ctx);

	// If stream cannot be closed by conventional means, wipe it now
	rc = tls_stream_close(&update_ctx->stream,
			teardown_update_context_close_cb);
	if (rc != 0)
		memset(&update_ctx->stream, 0,sizeof(update_ctx->stream));

	return 0;
}

static void
update_timer_on_write(uv_write_t *req, int status);

static int
perform_protocol_action(tls_stream_t *stream, ns_action_t action)
{
	int rc;

	print_if_NULL(stream);
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
		rc = tls_stream_shutdown(stream, NULL);
		if (TLS_STR_OK != rc) return -1;
		break;
	}

	return 0;
}

static void
update_timer_on_write(uv_write_t *req, int status, uv_buf_t *bufs, unsigned int nbufs)
{
	int rc, buf_idx;
	ns_action_t action;
	ids_update_ctx_t *ctx = NULL;
	tls_stream_t *stream = NULL;

	if (!req) return;

	stream = req->data;
	print_if_NULL(stream->data);
	ctx = stream->data;

	// Free buffers
	if (bufs)
	{
		for (buf_idx = 0; buf_idx < nbufs; buf_idx++)
		{
			if (&bufs[buf_idx]) free(&bufs[buf_idx]);
		}
	}

	if (status)
	{
		// Error state
		rc = tls_stream_shutdown(&ctx->stream, update_timer_on_shutdown);
		// Ignore return value
	}

	rc = ns_cl_proto_on_send(&action, &ctx->proto.state, &ctx->stream, status);
	if (rc != 0) return;
	rc = perform_protocol_action(stream, action);
}

static void
update_timer_on_shutdown(tls_stream_t *stream, int status)
{
	if (!stream) return;

	/**
	 * Do not finalize or free the stream as it will be re-used for the next
	 * update.
	 */
}

static void
update_timer_on_read(tls_stream_t *stream, int status, const uv_buf_t *buf)
{
	int rc;
	ns_action_t action;
	ids_update_ctx_t *ctx = NULL;

	print_if_NULL(stream);
	if (!stream) return;

	if (TLS_STR_OK != status)
	{
		rc = tls_stream_shutdown(stream, update_timer_on_shutdown);
		return;
	}

	if (!buf) return;
	ctx = stream->data;

	if (!buf->base) return;
	fwrite(buf->base, buf->len, 1, stdout);
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

	print_if_NULL(stream);
	if (!stream) return;

	if (status)
	{
		rc = tls_stream_shutdown(stream, update_timer_on_shutdown);
		// Don't think error code matters

		return;
	}

	action = ns_cl_proto_on_handshake(stream->data, stream);

	return;
}

static void
update_timer_cb(uv_timer_t *timer)
{

	//TODO: Check that tls stream is not currently active. (Shouldn't be still
	// active after 15 minutes but something odd might happen.)
	int rc;
	ids_update_ctx_t *ctx = NULL;
	struct sockaddr_in addr;

	// Connect to the IOC server
	print_if_NULL(timer);
	if (!timer) return;
	ctx = timer->data;

	rc = uv_ip4_addr(server_ip, server_port, &addr);
	print_error(check_uv_error(rc));
	if (0 != rc) return;

	rc = tls_stream_connect(&ctx->stream, (const struct sockaddr *)&addr,
			update_timer_on_handshake, update_timer_on_read);
	if (0 != rc) return;
}

int
setup_timer(uv_timer_t *timer, uv_loop_t *loop, ids_update_ctx_t *ctx)
{
	int uv_rc;

	uv_rc = uv_timer_init(loop, timer);
	print_error(check_uv_error(uv_rc));
	if (uv_rc < 0) return -1;

	timer->data = ctx;
	uv_rc = uv_timer_start(timer, update_timer_cb, 0, update_interval_ms);
	print_error(check_uv_error(uv_rc));
	if (uv_rc < 0) return -1;

	return 0;
}

int
teardown_timer(uv_timer_t *timer)
{
	int rc;

	rc = uv_timer_stop(timer);
	print_error(check_uv_error(rc));
	if (rc < 0) return -1;

	uv_close((uv_handle_t *)timer, NULL);

	return 0;
}
