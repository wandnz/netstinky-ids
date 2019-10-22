/*
 * Each connection requires a TLS context.
 *
 * ids_tls_update.c
 *
 *  Created on: Jul 22, 2019
 *      Author: mfletche
 */
#include <assert.h>
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

static void
update_timer_on_write(tls_stream_t *stream, int status, uv_buf_t *bufs,
		unsigned int nbufs);

SSL_CTX *
setup_context()
{
	SSL_CTX *ctx = NULL;
	const SSL_METHOD *method = SSLv23_method();
	if (!method) return NULL;

	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	ctx = SSL_CTX_new(method);
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
	assert(update_ctx);
	assert(loop);
	assert(domain);
	assert(ip);

	int rc;

	// Setup SSL context
	update_ctx->ctx = setup_context();
	if (NULL == update_ctx->ctx) return NSIDS_SSL;

	// Setup actual TLS stream
	rc = tls_stream_init(&update_ctx->stream, loop, update_ctx->ctx);
	if (0 != rc) goto error;

	// Save blacklist pointers
	update_ctx->domain = domain;
	update_ctx->ip = ip;
	update_ctx->proto.state = NS_PROTO_VERSION_WAITING;
	update_ctx->stream.data = update_ctx;

	return NSIDS_OK;

error:
	if (update_ctx->ctx) SSL_CTX_free(update_ctx->ctx);

	// Determine where the error occurred
	if (TLS_STR_NEED_CLOSE) return NSIDS_UV;
	return NSIDS_SSL;
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
update_timer_on_write(tls_stream_t *stream, int status, uv_buf_t *bufs,
		unsigned int nbufs)
{
	int rc, buf_idx;
	ns_action_t action;
	ids_update_ctx_t *ctx = NULL;

	print_if_NULL(stream->data);
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
update_timer_on_shutdown(tls_stream_t *stream, int status)
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
	rc = perform_protocol_action(stream, action);
	if (rc)
		print_error("Could not perform protocol action");

	return;
}

static void
update_timer_cb(uv_timer_t *timer)
{
	int rc;
	ids_update_ctx_t *ctx = NULL;
	struct sockaddr_in addr;

	// Connect to the IOC server
	print_if_NULL(timer);
	if (!timer) return;
	ctx = timer->data;

	// Re-init protocol
	ctx->proto.state = NS_PROTO_VERSION_WAITING;

	// Close the uv_handle and return if the previous update is still running.
	// uv_is_active will return 0 if the tcp handle has been zeroed, so this
	// works even if the handle hasn't been properly initialized.
	if (uv_is_active((uv_handle_t *)&ctx->stream.tcp))
	{
		rc = tls_stream_close(&ctx->stream, update_timer_on_close);
		if (rc)
			// Callback is not going to happen, so free and continue
			tls_stream_fini(&ctx->stream);
		else
			// Must wait for callback
			return;
	}
	rc = tls_stream_init(&ctx->stream, timer->loop, ctx->ctx);
	if (rc)
	{
		print_error("Could not initialize TLS stream");
		return;
	}
	ctx->stream.data = ctx;

	rc = uv_ip4_addr(server_ip, server_port, &addr);
	print_error(check_uv_error(rc));
	if (0 != rc) return;

	rc = tls_stream_connect(&ctx->stream, (const struct sockaddr *)&addr,
			update_timer_on_handshake, update_timer_on_read);
	if (0 != rc) return;
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
		fprintf(stderr, "Failed to setup update timer handle: %s\n",
				uv_strerror(uv_rc));
		return NSIDS_UV;
	}

	timer->data = ctx;
	uv_rc = uv_timer_start(timer, update_timer_cb, 0, update_interval_ms);
	if (uv_rc < 0)
	{
		fprintf(stderr, "Failed to setup update timer handle: %s\n",
				uv_strerror(uv_rc));
		teardown_timer(timer);
		return NSIDS_UV;
	}

	return NSIDS_OK;
}

int
teardown_timer(uv_timer_t *timer)
{
	int rc;

	uv_timer_stop(timer);
	uv_close((uv_handle_t *)timer, NULL);

	return NSIDS_OK;
}
