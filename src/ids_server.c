/*
 * ids_server.c
 *
 *  Created on: 24/04/2019
 *      Author: mfletche
 */

#include "ids_server.h"

static char *fmt_ioc = "IOC: %s\n";
static char *fmt_timestamp = "Last seen: %11d\n";
static char *fmt_event_count = "Number of times seen: %d\n";
static char *fmt_iface = "Interface: %s\n";
static char *fmt_src_ip = "Source IP: %s\n";
static char *fmt_src_mac = "Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n\n";

/**
 * Frees write requests. This should only be called after the request has been
 * handled (i.e. the write callback called when writing is complete).
 */
static void free_write_req(uv_write_t **req)
{
	assert(req);

	// TODO: Check how to release uv_write_t properly
}

void echo_write(uv_write_t *req, int status);

/**
 * Calculates the length of a string required to hold an IDS event (excluding
 * termination character).
 */
static size_t ids_event_len(struct ids_event *event)
{
	struct in_addr ip;
	char ip_str[30];
	size_t char_count = 0;
	int ret;

	char buf[30];

	ret = snprintf(buf, 30, fmt_ioc, event->ioc);
	if (ret >= 0) char_count += ret;

	ret = snprintf(buf, 30, fmt_timestamp,
			(long long)event->times_seen->tm_stamp.tv_sec);
	if (ret >= 0) char_count += ret;

	ret = snprintf(buf, 30, fmt_event_count, event->num_times);
	if (ret >= 0) char_count += ret;

	ret = snprintf(buf, 30, fmt_iface, event->iface);
	if (ret >= 0) char_count += ret;

	ip.s_addr = event->src_ip;
	ret = snprintf(buf, 30, fmt_src_ip, inet_ntop(AF_INET, &ip, ip_str, 30));
	if (ret >= 0) char_count += ret;

	ret = snprintf(buf, 30, fmt_src_mac, event->mac.m_addr[0], event->mac.m_addr[1],
			event->mac.m_addr[2], event->mac.m_addr[3], event->mac.m_addr[4], event->mac.m_addr[5]);
	if (ret >= 0) char_count += ret;

	return char_count;
}

/**
 * IOC: <domain name or IP address>
 * Last seen: <timestamp>
 * Number of times seen: <unsigned int>
 * Interface: <iface name>
 * Source IP: <IP address of infected machine>
 */
void write_ids_event(uv_stream_t *stream, struct ids_event *event)
{
	// This buffer will be strdup'd so that the contents will outlast this function
	char *buffer;
	size_t buf_idx = 0;
	struct in_addr ip;
	char ip_str[20];
	int ret;

	uv_write_t *ioc_req;
	uv_buf_t ioc_buf;

	size_t buf_sz = ids_event_len(event) + 1;
	if (NULL == (buffer = malloc(buf_sz)))
	{
		fprintf(stderr, "write_ids_event: could not allocate buffer\n");
		return;
	}

	ret = snprintf(buffer + buf_idx, buf_sz - buf_idx, fmt_ioc, event->ioc);
	assert(ret < buf_sz - buf_idx);
	buf_idx += ret;

	ret = snprintf(buffer + buf_idx, buf_sz - buf_idx, fmt_timestamp,
			(long long)event->times_seen->tm_stamp.tv_sec);
	assert(ret < buf_sz - buf_idx);
	buf_idx += ret;

	ret = snprintf(buffer + buf_idx, buf_sz - buf_idx, fmt_event_count,
			event->num_times);
	assert(ret < buf_sz - buf_idx);
	buf_idx += ret;

	ret = snprintf(buffer + buf_idx, buf_sz - buf_idx, fmt_iface, event->iface);
	assert(ret < buf_sz - buf_idx);
	buf_idx += ret;

	ip.s_addr = event->src_ip;

	ret = snprintf(buffer + buf_idx, buf_sz - buf_idx, fmt_src_ip,
			inet_ntop(AF_INET, &ip, ip_str, 20));
	assert(ret < buf_sz - buf_idx);
	buf_idx += ret;

	ret = snprintf(buffer + buf_idx, buf_sz - buf_idx, fmt_src_mac,
			event->mac.m_addr[0], event->mac.m_addr[1], event->mac.m_addr[2], event->mac.m_addr[3],
			event->mac.m_addr[4], event->mac.m_addr[5]);
	assert(ret < buf_sz - buf_idx);
	buf_idx += ret;

	ioc_buf = uv_buf_init(buffer, buf_sz);
	if (NULL == (ioc_req = malloc(sizeof(*ioc_req))))
	{
		fprintf(stderr, "write_ids_event: could not allocate uv_write_t\n");
		return;
	}
	if (0 > (ret = uv_write(ioc_req, stream, &ioc_buf, 1, echo_write)))
	{
		fprintf(stderr, "write_ids_event: write error occurred\n");
		return;
	}
}

void write_ids_event_list(uv_stream_t *stream)
{
	struct ids_event *event_iter;
	struct ids_event_list *list = (struct ids_event_list *)stream->data;
	for (event_iter = list->head; event_iter; event_iter = event_iter->next)
	{
		write_ids_event(stream, event_iter);
	}
}

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
	if (req) free_write_req(&req);
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

	// Copy pointer to event list from server to client
	client->data = server->data;

	if (0 != (err = uv_accept(server, (uv_stream_t *)client))) goto msg;
	if (0 != (err = uv_read_start((uv_stream_t *)client, alloc_buffer, echo_read))) goto msg;

	write_ids_event_list((uv_stream_t *)client);
	// Write the current list to the new connection
	return;

// For error cases where a specific libuv error message can be printed
msg:
	fprintf(stderr, "connection error: %s\n", uv_strerror(err));
error:
	if (client) uv_close((uv_handle_t *)client, NULL);
}

int
setup_event_server(uv_loop_t *loop, uv_tcp_t *handle, int port, struct ids_event_list *list)
{
	int ret;
	struct sockaddr_in server_addr;

	assert(loop);
	assert(handle);
	assert(port);

	if (0 != uv_tcp_init(loop, handle)) goto error;
	// Put a pointer to the ids_event_list in the data field of the tcp handle
	handle->data = list;
	if (0 != uv_ip4_addr("0.0.0.0", port, &server_addr)) goto error;
	if (0 != uv_tcp_bind(handle, (const struct sockaddr *)&server_addr, 0)) goto error;
	ret = uv_listen((uv_stream_t *)handle, 128, on_new_connection);
	if (ret) goto error;
	return 0;

error:
	fprintf(stderr, "Could not setup uv_tcp_t handle for server\n");
	return -1;
}
