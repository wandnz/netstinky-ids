/*
 * pcap_io_task.c
 *
 *  Created on: 29/10/2018
 *      Author: mfletche
 */

#include <stdlib.h>
#include <assert.h>

#include <pcap/pcap.h>
#include "ids_pcap.h"
#include "io_task.h"
#include "pcap_io_task.h"
#include "ip_blacklist.h"

/* -- DEBUGGING -- */
#define DEBUG 1
#define DPRINT(...) do { if (DEBUG) fprintf(stdout, __VA_ARGS__); } while (0)

struct pcap_io_task_state
{
	int fd;
	pcap_t *p;
	ip_blacklist *ip_bl;
};

int
pcap_io_task_write(TASK_STRUCT state);

void
free_pcap_io_task_state(TASK_STRUCT *state)
{
	assert(state);

	struct pcap_io_task_state **s = (struct pcap_io_task_state **)state;

	if (s && *s)
	{
		if ((*s)->p) pcap_close((*s)->p);

		/* fd is a derivative of pcap_t so don't free separately */

		free(*s);
		*s = NULL;
	}
}

int
pcap_io_task_read(TASK_STRUCT state)
{
	struct pcap_io_task_state *s = (struct pcap_io_task_state *)state;
	if (!ids_pcap_read_packet(s->p, s->ip_bl))
	{
		DPRINT("pcap_io_task_read(): ids_pcap_read_packet() failed\n");
		return (0);
	}

	return (1);
}

struct io_task *
pcap_io_task_setup(const char *if_name, ip_blacklist *b)
{
	assert(if_name);
	assert(b);

	int pcap_fd = -1;
	struct pcap_io_task_state *state = NULL;
	struct io_task *task = NULL;


	if (!(state = malloc(sizeof(*state))))
	{
		DPRINT("pcap_io_task_setup(%s): malloc() failed\n", if_name);
		goto error;
	}

	if (!(state->p = ids_pcap_get_pcap(if_name)))
	{
		DPRINT("pcap_io_task_setup(%s): ids_pcap_get_pcap() failed\n", if_name);
		goto error;
	}

	if (PCAP_ERROR == (pcap_fd = pcap_get_selectable_fd(state->p)))
	{
		DPRINT("pcap_io_task_setup(): pcap_get_selectable_fd() failed\n");
		goto error;
	}

	/* Bundle into an io_task */
	if (!(task = new_io_task(pcap_fd, state, pcap_io_task_read, NULL,
			free_pcap_io_task_state)))
	{
		DPRINT("pcap_io_task_setup(): new_io_task() failed\n");
		goto error;
	}

	state->ip_bl = b;

	return (task);

error:
	free_pcap_io_task_state((TASK_STRUCT *)&state);
	return (NULL);
}

int
pcap_io_task_write(TASK_STRUCT state)
{
	/* Don't think this is needed at all. */
	return (0);
}
