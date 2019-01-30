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
#include <netinet/in.h>
#include <arpa/inet.h>

#include "mfletche-common.h"

#include "linked_list.h"
#include "mdns.h"
#include "io_task.h"
#include "mdns_io_task.h"

/* -- DEBUGGING -- */
#define DEBUG 1
#define DPRINT(...) do { if (DEBUG) fprintf(stdout, __VA_ARGS__); } while (0)

static const size_t PACKET_BUF_LEN = 9000;
static const char *fqsn = "_netstinky._tcp.local.";
static const char *router_domain = "omnia.wand.waikato.ac.nz";

int
mdns_io_task_write(TASK_STRUCT task_state);

struct mdns_io_task_state
{
	int fd;
	void *packet_buffer;
	struct dns_answer *record_list;
	struct linked_list *reply_queue;
};

void
free_mdns_io_task_state(TASK_STRUCT *task_state)
{
	assert(task_state);

	struct mdns_io_task_state **state = (struct mdns_io_task_state **)task_state;

	if (*state)
	{
		if ((*state)->packet_buffer) free((*state)->packet_buffer);
		free_dns_answer(((*state)->record_list));
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
		struct dns_packet *packet = dns_parse(mdns->packet_buffer, mdns->packet_buffer + packet_len);
		if (packet)
		{
			dns_print(packet, stdout);

			/* Check if any questions are relevant */
			struct dns_packet *reply = mdns_construct_reply(packet, mdns->record_list);
			if (reply)
			{
				if (!linked_list_add_item(&(mdns->reply_queue), reply))
				{
					DPRINT("mdns_io_task_read(): linked_list_add() failed\n");
				}
			}

			free_dns_packet(&packet);
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
	struct mdns_io_task_state *mdns;
	struct io_task *task = NULL;

	MALLOC_ZERO(mdns);

	if (mdns)
	{
		mdns->fd = mdns_get_socket();
		if (!mdns->fd) goto error;

		mdns->packet_buffer = malloc(PACKET_BUF_LEN);
		if (!(mdns->packet_buffer)) goto error;

		/* Set up RRs */
		struct dns_answer *ptr_rr = new_mdns_answer(dns_domain_to_name("_ids._tcp.local."), PTR, 120);
		ptr_rr->rdata.ptr.name = dns_domain_to_name(router_domain);
		ptr_rr->rdlength = strlen(ptr_rr->rdata.ptr.name) + 1;
		mdns->record_list = ptr_rr;

		struct dns_answer *a_rr = new_mdns_answer(dns_domain_to_name(router_domain), A, 120);

		/* TODO: Dynamically get IP address and port */
		struct in_addr ip_addr;
		assert(inet_aton("10.1.18.146", &ip_addr));
		a_rr->rdata.a.ip_address = ntohl(ip_addr.s_addr);
		a_rr->rdlength = 4;

		ptr_rr->next = a_rr;

		struct dns_answer *svc_rr = new_mdns_answer(dns_domain_to_name(fqsn), SRV, 120);
		svc_rr->rdata.srv.target = dns_domain_to_name(router_domain);
		svc_rr->rdlength = 6 + strlen(svc_rr->rdata.srv.target) + 1;
		svc_rr->rdata.srv.priority = 0;
		svc_rr->rdata.srv.weight = 0;

		/* Todo: Change advertising port */
		svc_rr->rdata.srv.port = 5000;
		/* Todo: Define a hostname */

		a_rr->next = svc_rr;

		if (!(task = new_io_task(mdns->fd, mdns, mdns_io_task_read,
				mdns_io_task_write, free_mdns_io_task_state))) goto error;

		/* TODO: Send first advertisement packet */
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
	struct dns_packet *reply = NULL;

	while (NULL != (reply = (struct dns_packet *)linked_list_pop(&(mdns->reply_queue))))
	{
		DPRINT("Sending DNS reply...\n");
		if (!mdns_send_reply(mdns->fd, mdns->packet_buffer, PACKET_BUF_LEN, reply))
		{
			DPRINT("Could not send an MDNS reply");
		}

		free_dns_packet(&reply);
	}

	/* TODO: Do I care if I only do multicast replies? */

	return (0);
}
