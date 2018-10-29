/*
 * main.c
 *
 *  Created on: 26/10/2018
 *      Author: mfletche
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#include "iface.h"
#include "linked_list.h"
#include "io_task.h"
#include "mdns_io_task.h"

/* -- DEBUGGING -- */
#define DEBUG 1
#define DPRINT(...) do { if (DEBUG) fprintf(stdout, __VA_ARGS__); } while (0)

/* -- COMMAND LINE ARGUMENTS -- */
const static char *getopt_args = "hp:i:";
const static char *getopt_usage = "\nRun as: %s -p port -i device1 -i device2 -i devicen.\n\n";

/* A list of interface names taken from the command line */
struct linked_list *iface_list = NULL;

/* Server port which will send clients a list of recent detected intrusions */
static int server_port = -1;

/*
 * Free all the global variables prior to exiting the program.
 */
void
on_exit_callback()
{
	DPRINT("Performing graceful exit.\n");

	/* Interface names are from the argv array and do not need to be freed */
	if (iface_list) free_linked_list(&iface_list, NULL);
}

int
parse_args(int argc, char **argv)
{
	char *program = NULL;
	int option_char, iface_num = 0, success = 1;

	if (argc < 1) return (0);

	program = argv[0];

	while (-1 != (option_char = getopt (argc, argv, getopt_args))) {
		switch (option_char)
		{
			case 'h':
				fprintf(stderr, getopt_usage, program);
				return (1);

			case 'i':
				/* -i requires an argument */
				if (!optarg)
				{
					fprintf(stderr, "-i requires an argument\n");
					success = 0;
				}

				iface_num++;
				linked_list_add_item(&iface_list, optarg);

				DPRINT("Argument -i (interface): %s\n", optarg);

				break;

			case 'p':
				/* -p requires an argument */
				if (!optarg)
				{
					fprintf(stderr, "-p requires an argument\n");
					success = 0;
				}

				/* -p must be given a port number > 0 */
				server_port = atoi(optarg);
				if (server_port <= 0)
				{
					fprintf(stderr, "-p was given an invalid argument: %s\n",
							optarg);
					success = 0;
				}

				DPRINT("Argument -p (port number): %d\n", server_port);
				break;

			/* in case option that was not expected arrives or last option did
			 * not have a required argument */
			case '?':
				/* options which require an argument */
				if (optopt == 'p' || optopt == 'i')
					fprintf(stderr, "-%c requires an argument\n", optopt);

				/* unknown options */
				else if (isprint (optopt))
					fprintf(stderr, "Unknown option received: -%c\n", optopt);
				else
					fprintf(stderr, "Unknown option received: -0x%x\n", optopt);

				success = 0;
				break;

			default:
				success = 0;
		}
	}

	if (iface_num <= 0)
	{
		fprintf(stderr, "Required argument -i not received\n");
		success = 0;
	}

	/* check every required option has been received */
	if (server_port <= 0)
	{
		fprintf(stderr, "Required argument -p not received\n");
		success = 0;
	}

	return (success);
}

int
main(int argc, char **argv)
{
	if (atexit(on_exit_callback))
	{
		DPRINT("atexit() failed to register on_exit_callback\n");
		exit(EXIT_FAILURE);
	}

	if (!parse_args(argc, argv))
	{
		DPRINT("parse_args() failed\n");
		exit(EXIT_FAILURE);
	}

	print_network_interfaces(stdout);

	struct io_task *tasks = NULL;
	struct io_task *mdns_task = mdns_io_task_setup();
	if (mdns_task && !io_task_add(&tasks, mdns_task))
		DPRINT("io_task_add() failed\n");

	DPRINT("Waiting for MDNS packets.\n");
	while (1)
	{
		struct io_task_fdsets *fdset = io_task_select(tasks);
		io_task_do_io(tasks, fdset);
	}

	exit(EXIT_SUCCESS);
}
