/*
 * ids_server.c
 *
 *  Created on: 24/04/2019
 *      Author: mfletche
 */

#include <string.h>

#include "ids_server.h"
#include "error/ids_error.h"

#define MAX_CONNS 128

static char *fmt_ioc = "IOC: %s\n";
static char *fmt_timestamp = "Timestamp: %11lu\n";
static char *fmt_event_count = "Occurrences: %d\n";
static char *fmt_iface = "Interface: %s\n";
static char *fmt_src_ip = "Src-IP: %s\n";
static char *fmt_src_mac = "Src-MAC: %02X-%02X-%02X-%02X-%02X-%02X\n\n";

/**
 * A datatype to store the location of buffers used by uv_write. This should be
 * initialized and stored in the 'data' field of a write request so that the
 * write callback can free the buffers.
 */
typedef struct evs_usr_data_s
{
	uv_buf_t *bufs;
	unsigned int nbufs;
} evs_usr_data_t;

void ids_server_write_cb(uv_write_t *req, int status);
static void on_client_close(uv_handle_t *handle);

/**
 * Bundle the write buffers into a single data structure. Copies all uv_buf_t
 * in case they were allocated on the stack.
 */
static evs_usr_data_t *
new_usr_data(uv_buf_t *bufs, unsigned int nbufs)
{
	evs_usr_data_t *data = NULL;
	uv_buf_t *buf_copy = NULL;

	// There must be at least one buffer
	if (!bufs || !nbufs) return NULL;

	// Allocate main struct
	data = malloc(sizeof(*data));
	if (!data) return NULL;

	// Create copy of bufs
	buf_copy = malloc(sizeof(*buf_copy) * nbufs);
	if (!data)
	{
		free(data);
		return NULL;
	}
	memcpy(buf_copy, bufs, sizeof(*buf_copy) * nbufs);

	data->bufs = buf_copy;
	data->nbufs = nbufs;

	return data;
}

/**
 * Clean up a user data structure. Does NOT free the buffers themselves as that
 * is the job of the user in the write callback.
 */
static void
free_usr_data(evs_usr_data_t *data)
{
	if (!data) return;

	// Free copy of bufs
	if (data->bufs) free(data->bufs);

	// Free struct itself
	free(data);
}

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
	evs_usr_data_t *write_req_data = NULL;

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
			(long) event->times_seen->tm_stamp.tv_sec);
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

	// Keep a copy of buffers to free after the callback
	write_req_data = new_usr_data(&ioc_buf, 1);
	if (!write_req_data)
	{
		free(buffer);
		return;
	}

	// Attach write data to write request to ensure it gets freed later
	ioc_req->data = (void *) write_req_data;

	if (0 > (ret = uv_write(ioc_req, stream, &ioc_buf, 1, ids_server_write_cb)))
	{
		fprintf(stderr, "write_ids_event: write error occurred\n");
		free(buffer);
		free_usr_data(write_req_data);
		return;
	}
}

static void write_sock_shutdown(uv_shutdown_t *req, int status) {
    if (status < 0) {
        fprintf(stderr, "Failed to close write socket");
    }
    if (req != NULL) {
		uv_stream_t *stream = req->handle;
        free(req);
		if (stream) uv_close((uv_handle_t *) stream, (uv_close_cb) on_client_close);
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
    uv_shutdown_t *req =
            (uv_shutdown_t *) malloc(sizeof(uv_shutdown_t));
    uv_shutdown(req, stream, write_sock_shutdown);
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
	assert(buf);
	buf->base = malloc(suggested_size);
	if (buf->base) buf->len = suggested_size;
	else buf->len = 0;
}

/**
 * Check the status of a completed write and free the buffers.
 */
void ids_server_write_cb(uv_write_t *req, int status)
{
	unsigned int buf_idx;
	evs_usr_data_t *usr_data = NULL;

	if (status) fprintf(stderr, "write error: %s\n", uv_strerror(status));

	if (!req) return;

	usr_data = req->data;
	free(req);

	if (usr_data) {
		if (usr_data->bufs)
		{
			for (buf_idx = 0; buf_idx < usr_data->nbufs; buf_idx++)
			{
				void *buf_base = usr_data->bufs[buf_idx].base;
				if (buf_base)
					free(buf_base);
			}
		}

		free_usr_data(usr_data);
	}
}

static void
on_client_close(uv_handle_t *handle)
{
	if (handle->type == UV_TCP)
	{
		uv_tcp_t *client = (uv_tcp_t *) handle;
		// Assume client->data will be freed elsewhere
		free(client);
	}
}

static void on_new_connection(uv_stream_t *server, int status)
{
	int err;
	uv_tcp_t *client = NULL;
	uv_loop_t *loop;

	printf("new connection\n");
	loop = ((uv_handle_t *)server)->loop;
	if (0 > (err = status)) goto msg;
	if (NULL == (client = (uv_tcp_t *)malloc(sizeof(*client)))) goto error;
	if (0 != (err = uv_tcp_init(loop, client))) goto msg;

	// Copy pointer to event list from server to client
	client->data = server->data;

	if (0 != (err = uv_accept(server, (uv_stream_t *)client))) goto msg;

	write_ids_event_list((uv_stream_t *)client);
	// Write the current list to the new connection
	return;

// For error cases where a specific libuv error message can be printed
msg:
	fprintf(stderr, "connection error: %s\n", uv_strerror(err));
error:
	if (client) uv_close((uv_handle_t *)client, (uv_close_cb) on_client_close);
}

int
setup_event_server(uv_loop_t *loop, uv_tcp_t *handle, int port, struct ids_event_list *list)
{
	assert(loop);
	assert(handle);
	assert(port);
	assert(list);

	int ret;
	struct sockaddr_in server_addr;

	if (0 != uv_tcp_init(loop, handle)) goto error;
	// Put a pointer to the ids_event_list in the data field of the tcp handle
	handle->data = list;
	if (0 != uv_ip4_addr("0.0.0.0", port, &server_addr)) goto error;
	if (0 != uv_tcp_bind(handle, (const struct sockaddr *)&server_addr, 0)) goto error;
	ret = uv_listen((uv_stream_t *)handle, MAX_CONNS, on_new_connection);
	if (ret) goto error;
	return 0;

error:

	fprintf(stderr, "Could not setup uv_tcp_t handle for server\n");
	return -1;
}

static void
event_server_close_cb(uv_tcp_t *handle)
{
	memset(handle, 0, sizeof(*handle));
}

static void
event_server_shutdown_cb(uv_shutdown_t *req, int status)
{
	// Ignore status and close handle
	uv_close((uv_handle_t *)req->handle, (uv_close_cb)event_server_close_cb);
	free(req);
}


int
teardown_event_server(uv_tcp_t *handle)
{
	assert(handle);

	uv_shutdown_t *req = malloc(sizeof(*req));
	int uv_rc;

	// Ignore return codes because we'll carry on if a failure occurs
	uv_read_stop((uv_stream_t *)handle);
	if (req)
	{
		// If this works, the close operation must wait for the callback
		uv_rc = uv_shutdown(req, (uv_stream_t *)handle,
				event_server_shutdown_cb);
	}

	// If shutdown failed, just close
	if (!req || 0 > uv_rc)
		uv_close((uv_handle_t *)handle, (uv_close_cb)event_server_close_cb);

	return NSIDS_OK;
}
