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

#include <getopt.h>

#include "iface.h"
#include "linked_list.h"
#include "io_task.h"
#include "mdns_io_task.h"
#include "pcap_io_task.h"
#include "ip_blacklist.h"
#include "firehol_ip_blacklist.h"
#include "ids_event_queue.h"

/* -- DEBUGGING -- */
#define DEBUG 1
#define DPRINT(...) do { if (DEBUG) fprintf(stdout, __VA_ARGS__); } while (0)

/* -- COMMAND LINE ARGUMENTS -- */
const static char *getopt_args = "hp:i:";
const static struct option long_options[] = {
		{"ipbl", 1, 0, 0 },
};
const static char *getopt_usage = "\nRun as: %s -p port -i device1 -i device2 -i devicen.\n\n";

const static int MAX_EVENTS = 5;
const static int MAX_TS = 5;

/* A list of interface names taken from the command line */
struct linked_list *iface_list = NULL;

/* Server port which will send clients a list of recent detected intrusions */
static int server_port = -1;

/* IO tasks to be performed in event loop. */
struct io_task *tasks = NULL;

/* Blacklist */
char *ip_bl_file = NULL;
ip_blacklist *ip_bl = NULL;
domain_blacklist *dn_bl = NULL;

/* Event queue */
struct ids_event_list *ids_events = NULL;

/*
 * Free all the global variables prior to exiting the program.
 */
void
on_exit_callback()
{
	DPRINT("Performing graceful exit.\n");

	/* These functions to free structures will handle NULL arguments, so this
	 * doesn't need to be checked. */
	free_linked_list(&iface_list, NULL);
	free_io_task(&tasks);
	free_ip_blacklist(&ip_bl);
	free_domain_blacklist(&dn_bl);
	free_ids_event_list(&ids_events);
}

int
parse_args(int argc, char **argv)
{
	char *program = NULL;
	int option_char, iface_num = 0, success = 1, option_index = 0;

	if (argc < 1) return (0);

	program = argv[0];

	while (-1 != (option_char = getopt_long (argc, argv, getopt_args, long_options, &option_index))) {
		switch (option_char)
		{
			case 0:
				/* Is a long option */

				/* Only one long option: ipbl */
				if (!optarg)
				{
					DPRINT("Did not receive an option for option %s\n", long_options[option_index].name);
					break;
				}
				else
				{
					DPRINT("Argument --ipbl (IP blacklist file): %s\n", optarg);
					ip_bl_file = optarg;
				}
				break;
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
setup_blacklists()
{
	struct ip4_address_range *firehol_list = NULL;
	FILE *fp = NULL;

	if (!(ids_events = new_ids_event_list(MAX_EVENTS, MAX_TS)))
	{
		DPRINT("setup_blacklists(): new_ids_event_list() failed\n");
		goto error;
	}

	dn_bl = new_domain_blacklist();
	if (!dn_bl) goto error;

	ip_bl = new_ip_blacklist();
	if (!ip_bl) goto error;

	if (ip_bl_file)
	{
		fp = fopen(ip_bl_file, "r");
		if (!fp) exit(EXIT_FAILURE);

		firehol_list = read_firehol_ip_blacklist(fp);
		fclose(fp);
		fp = NULL;

		struct ip4_address_range *ip4_iter = firehol_list;
		while (ip4_iter)
		{
			/* Don't add really large address ranges */
			if (ip4_iter->prefix_len >= 24)
			{
				uint32_t addr_iter;
				uint32_t max_addr = ip4_address_range_get_max_addr(ip4_iter);

				for (addr_iter = ip4_address_range_get_min_addr(ip4_iter); addr_iter < max_addr; addr_iter++)
				{
					if (!ip_blacklist_add(ip_bl, addr_iter)) goto error;
				}

				if (!ip_blacklist_add(ip_bl, max_addr)) goto error;
			}

			ip4_iter = ip4_iter->next;
		}

		free_ip4_address_range(&firehol_list);
	}

	return (1);
error:
	if (fp) fclose(fp);
	free_ip4_address_range(&firehol_list);
	free_ip_blacklist(&ip_bl);
	free_domain_blacklist(&dn_bl);
	return (0);
}

int
main(int argc, char **argv)
{
 	struct io_task *mdns_task = NULL, *pcap_task = NULL;
	struct linked_list *iter = NULL;

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
	if (!setup_blacklists())
	{
		DPRINT("setup_blacklists() failed\n");
		exit(EXIT_FAILURE);
	}

	mdns_task = mdns_io_task_setup();
	if (mdns_task && !io_task_add(&tasks, mdns_task))
		DPRINT("io_task_add() failed\n");

	for (iter = iface_list; iter; iter = iter->next)
	{
		pcap_task = pcap_io_task_setup((char *)iter->item, ip_bl);
		if (!pcap_task || !io_task_add(&tasks, pcap_task))
			DPRINT("io_task_add() failed\n");
	}

	DPRINT("Waiting for MDNS packets.\n");
	while (1)
	{
		struct io_task_fdsets *fdset = io_task_select(tasks);
		io_task_do_io(tasks, fdset);
	}

	exit(EXIT_SUCCESS);
}
