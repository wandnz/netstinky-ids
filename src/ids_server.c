/*
 * ids_server.c
 *
 *  Created on: 24/04/2019
 *      Author: mfletche
 */

#include "ids_server.h"

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
	assert(buf);
	buf->base = malloc(suggested_size);
	if (buf->base) buf->len = suggested_size;
	else buf->len = 0;
}

void echo_write(uv_write_t *req, int status)
{
	printf("server write\n");
	if (status) fprintf(stderr, "write error: %s\n", uv_strerror(status));
	if (req) free(req);
}

static void echo_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf)
{
	uv_write_t *req;
	uv_buf_t wrbuf;
	int err;

	printf("server read\n");
	if (nread < 0)
	{
		if (UV_EOF != (err = nread)) goto msg;
	}
	else if (nread > 0)
	{
		if (NULL == (req = malloc(sizeof(*req)))) goto error;
		wrbuf = uv_buf_init(buf->base, nread);
		if (0 > (err = uv_write(req, client, &wrbuf, 1, echo_write))) goto msg;
	}

	goto finally;

msg:
	fprintf(stderr, "read error: %s\n", uv_strerror(err));
error:
	uv_close((uv_handle_t *)client, NULL);

// Free the buffer in all cases
finally:
	if (buf->base) free(buf->base);
}

static void on_new_connection(uv_stream_t *server, int status)
{
	int err;
	uv_tcp_t *client;
	uv_loop_t *loop;

	printf("new connection\n");
	loop = ((uv_handle_t *)server)->loop;
	if (0 > (err = status)) goto msg;
	if (NULL == (client = (uv_tcp_t *)malloc(sizeof(*client)))) goto error;
	if (0 != (err = uv_tcp_init(loop, client))) goto msg;
	if (0 != (err = uv_accept(server, (uv_stream_t *)client))) goto msg;
	if (0 != (err = uv_read_start((uv_stream_t *)client, alloc_buffer, echo_read))) goto msg;
	return;

// For error cases where a specific libuv error message can be printed
msg:
	fprintf(stderr, "connection error: %s\n", uv_strerror(err));
error:
	if (client) uv_close((uv_handle_t *)client, NULL);
}

int
setup_event_server(uv_loop_t *loop, uv_tcp_t *handle, int port)
{
	int ret;
	struct sockaddr_in server_addr;

	assert(loop);
	assert(handle);
	assert(port);

	if (0 != uv_tcp_init(loop, handle)) goto error;
	if (0 != uv_ip4_addr("0.0.0.0", port, &server_addr)) goto error;
	if (0 != uv_tcp_bind(handle, (const struct sockaddr *)&server_addr, 0)) goto error;
	ret = uv_listen((uv_stream_t *)handle, 128, on_new_connection);
	if (ret) goto error;
	return 0;

error:
	fprintf(stderr, "Could not setup uv_tcp_t handle for server\n");
	return -1;
}
