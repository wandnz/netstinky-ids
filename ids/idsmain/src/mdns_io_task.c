/*
 * mdns_io_task.c
 *
 *  Created on: 29/10/2018
 *      Author: mfletche
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <sys/socket.h>

#include "mdns.h"
#include "io_task.h"
#include "mdns_io_task.h"

/* -- DEBUGGING -- */
#define DEBUG 1
#define DPRINT(...) do { if (DEBUG) fprintf(stdout, __VA_ARGS__); } while (0)

static const size_t PACKET_BUF_LEN = 9000;

int
mdns_io_task_write(TASK_STRUCT task_state);

struct mdns_io_task_state
{
	int fd;
	void *packet_buffer;
};

void
free_mdns_io_task_state(TASK_STRUCT *task_state)
{
	assert(task_state);

	struct mdns_io_task_state **state = (struct mdns_io_task_state **)task_state;

	if (*state)
	{
		if ((*state)->packet_buffer) free((*state)->packet_buffer);
		free(*state);
	}
	*state = NULL;
}

int
mdns_io_task_read(TASK_STRUCT task_state)
{
	struct mdns_io_task_state *mdns = (struct mdns_io_task_state *)task_state;
	struct sockaddr mdns_recv_addr;
	socklen_t mdns_recv_addr_len;
	ssize_t packet_len = recvfrom(mdns->fd, mdns->packet_buffer,
					PACKET_BUF_LEN, 0, &mdns_recv_addr, &mdns_recv_addr_len);
	int result = 0;

	if (packet_len < 1)
	{
		DPRINT("recvfrom() failed: %s\n", strerror(errno));
	}
	else if (packet_len == 0)
	{
		/* It was an orderly shut down */
		result = 1;
	}
	else
	{
		struct dns_packet *packet = dns_parse(mdns->packet_buffer, PACKET_BUF_LEN);
		if (packet)
		{
			dns_print(packet, stdout);
			free_dns_packet(packet);
			result = 1;
		}
		else
			DPRINT("dns_parse() failed\n");
	}

	return (result);
}

struct io_task *
mdns_io_task_setup()
{
	struct mdns_io_task_state *mdns = malloc(sizeof(*mdns));
	struct io_task *task = NULL;
	if (mdns)
	{
		mdns->fd = mdns_get_socket();
		if (!mdns->fd) goto error;

		mdns->packet_buffer = malloc(PACKET_BUF_LEN);
		if (!(mdns->packet_buffer)) goto error;

		if (!(task = new_io_task(mdns->fd, mdns, mdns_io_task_read,
				NULL, free_mdns_io_task_state))) goto error;
	}

	return (task);

error:
	free_mdns_io_task_state((void *)&mdns);
	return (task);
}

int
mdns_io_task_write(TASK_STRUCT task_state)
{
	struct mdns_io_task_state *mdns = (struct mdns_io_task_state *)task_state;

	/* TODO: Implement */

	return (0);
}
