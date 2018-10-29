/*
 * pcap_io_task.c
 *
 *  Created on: 29/10/2018
 *      Author: mfletche
 */

#include <stdlib.h>

#include <pcap/pcap.h>

#include "ids_pcap.h"

#include "io_task.h"
#include "pcap_io_task.h"

struct pcap_io_task_state
{
	int fd;
	pcap_t *p;
};

void
free_pcap_io_task_state(TASK_STRUCT *state)
{
	assert(state);

	struct pcap_io_task_state *s = (struct pcap_io_task_state *)state;

	if (s && *s)
	{
		if ((*s)->p) pcap_close((*s)->p);

		/* fd is part of pcap_t so don't free separately */
		(*s)->fd = NULL;

		free(*s);
		*s = NULL;
	}
}

int
pcap_io_task_read(TASK_STRUCT state)
{
	/* TODO: Implement */
	return (0);
}

struct io_task *
pcap_io_task_setup(const char *if_name)
{
	int pcap_fd = -1;
	struct pcap_io_task_state *state = NULL;
	struct io_task *task = NULL;

	if (!(state = malloc(sizeof(*state))))
	{
		DPRINT("pcap_io_task_setup(%s): malloc() failed\n");
		goto error;
	}

	if (!(state->p = ids_pcap_get_pcap(if_name)))
	{
		DPRINT("pcap_io_task_setup(%s): ids_pcap_get_pcap() failed\n");
		goto error;
	}

	if (PCAP_ERROR == (pcap_fd = pcap_get_selectable_fd(state->p)))
	{
		DPRINT("pcap_io_task_setup(): pcap_get_selectable_fd() failed\n");
		goto error;
	}

	/* Bundle into an io_task */
	if (!(task = new_io_task(pcap_fd, state, pcap_io_task_read, pcap_io_task_write,
			free_pcap_io_task_state)))
	{
		DPRINT("pcap_io_task_setup(): new_io_task() failed\n");
		goto error;
	}

	return (task);

error:
	free_pcap_io_task_state(&state);
	return (NULL);
}

int
pcap_io_task_write(TASK_STRUCT state)
{
	/* TODO: Implement */
	return (0);
}
