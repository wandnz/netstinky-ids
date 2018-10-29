/*
 * pcap_io_task.c
 *
 *  Created on: 29/10/2018
 *      Author: mfletche
 */

#include <stdlib.h>
#include "io_task.h"
#include "pcap_io_task.h"

struct pcap_io_task_state
{
	int fd;
};

void
free_pcap_io_task_state(TASK_STRUCT *state)
{
	/* TODO: Keep up-to-date with changes */
}

int
pcap_io_task_read(TASK_STRUCT state)
{
	/* TODO: Implement */
	return (0);
}

struct io_task *
pcap_io_task_setup()
{
	/* TODO: Implement */
	return (NULL);
}

int
pcap_io_task_write(TASK_STRUCT state)
{
	/* TODO: Implement */
	return (0);
}
