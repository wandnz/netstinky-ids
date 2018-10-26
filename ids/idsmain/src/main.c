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

#include "linked_list.h"

/* -- DEBUGGING -- */
#define DEBUG 1
#define DPRINT(...) do { if (DEBUG) fprintf(stdout, __VA_ARGS__); } while (0)

/* -- COMMAND LINE ARGUMENTS -- */
const static char *getopt_args = "hp:i:";
const static char *getopt_usage = "\nRun as: %s -p port -i device1 -i device2 -i devicen.\n\n";

struct linked_list *iface_list = NULL;

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
	int option_char, port, iface_num = 0, success = 1;

	if (argv) DPRINT("parse_args(%d, %x)\n", argc, argv);
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
				port = atoi(optarg);
				if (port <= 0)
				{
					fprintf(stderr, "-p was given an invalid argument: %s\n",
							optarg);
					success = 0;
				}

				DPRINT("Argument -p (port number): %d\n", port);
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
	if (port <= 0)
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

	exit(EXIT_SUCCESS);
}
