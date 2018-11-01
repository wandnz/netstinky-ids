/*
 * pcap_io_task.c
 *
 *  Created on: 29/10/2018
 *      Author: mfletche
 */

#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include <pcap/pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ids_pcap.h"
#include "io_task.h"
#include "pcap_io_task.h"
#include "ip_blacklist.h"
#include "domain_blacklist.h"

#include "ids_event_queue.h"

/* -- DEBUGGING -- */
#define DEBUG 1
#define DPRINT(...) do { if (DEBUG) fprintf(stdout, __VA_ARGS__); } while (0)

struct pcap_io_task_state
{
	int fd;
	pcap_t *p;
	char *iface;
	ip_blacklist *ip_bl;
	domain_blacklist *dn_bl;
	struct ids_event_list *event_queue;
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
	struct ids_pcap_fields f;
	struct in_addr ip;

	f.iface = s->iface;
	int read_result;
	if (-1 == (read_result = ids_pcap_read_packet(s->p, &f)))
	{
		DPRINT("pcap_io_task_read(): ids_pcap_read_packet() failed\n");
		return (0);
	}
	else if (1 == read_result)
	{
		if (ids_pcap_is_blacklisted(&f, s->ip_bl))
		{
			ip.s_addr = htonl(f.dest_ip);
			if (!ids_event_list_add(s->event_queue, new_ids_event(s->iface, f.src_ip,
					f.domain ? f.domain : strdup(inet_ntoa(ip)))))
			{
				DPRINT("pcap_io_task_read(): ids_event_list_add() failed\n");
				return (0);
			}

			DPRINT("pcap_io_task_read(): NEW DETECTED INTRUSION\n");
		}
	}

	return (1);
}

struct io_task *
pcap_io_task_setup(char *if_name, ip_blacklist *b)
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

	state->iface = if_name;

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
