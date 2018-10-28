/*
 * mdns_io_task.c
 *
 *  Created on: 29/10/2018
 *      Author: mfletche
 */

#include "io_task.h"

void
free_mdns_io_task(struct mdns_io_task *task_state)
{
	if (task_state) free(task_state);
}

void
mdns_io_task_read(TASK_STRUCT task_state)
{
	struct mdns_io_task *mdns = (struct mdns_io_task *)task_state;

	/* TODO: Implement */
}

struct mdns_io_task *
mdns_io_task_setup()
{
	struct mdns_io_task *mdns = malloc(sizeof(*mdns));
	if (mdns)
	{
		mdns->fd = mdns_get_socket();
		if (!mdns->fd) goto error;
	}

	return (mdns);

error:
	free_mdns_io_task(&mdns);
	return (mdns);
}

void
mdns_io_task_write(TASK_STRUCT task_state)
{
	struct mdns_io_task *mdns = (struct mdns_io_task *)task_state;

	/* TODO: Implement */
}
