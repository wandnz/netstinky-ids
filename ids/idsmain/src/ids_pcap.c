/*
 * ids_pcap.c
 *
 *  Created on: 29/10/2018
 *      Author: mfletche
 */

#include <assert.h>
#include <pcap/pcap.h>
#include "ids_pcap.h"

/* -- DEBUGGING -- */
#define DEBUG 1
#define DPRINT(...) do { if (DEBUG) fprintf(stdout, __VA_ARGS__); } while (0)

static const char *pcap_filter = "udp dst port 53 or tcp[tcpflags] == tcp-syn";
static const int promisc_enabled = 0;
static const int immediate_mode_enabled = 1;

pcap_t *
ids_pcap_get_pcap(const char *if_name)
{
	assert(if_name);

	char err_buf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;
	pcap_t *pcap = NULL;
	int tmp_result = 0;

	/* Create pcap device */
	if (!(pcap = pcap_create( if_name, err_buf)))
	{
		DPRINT("ids_pcap_get_pcap(%s): pcap_create() failed with message: %s\n",
				if_name, err_buf);
		goto error;
	}

	/* These functions will only fail if the pcap has already been activated.
	 * They return 0 on success. */
	tmp_result = pcap_set_promisc(pcap, promisc_enabled);
	assert(!tmp_result);	/* During debugging, crash immediately */
	if (PCAP_ERROR_ACTIVATED == tmp_result)
	{
		DPRINT("ids_pcap_get_pcap(%s): pcap_set_promisc() failed\n", if_name);
		goto error;
	}

	assert(!pcap_set_immediate_mode(pcap, immediate_mode_enabled));
	assert(!tmp_result);	/* During debugging, crash immediately */
	if (PCAP_ERROR_ACTIVATED == tmp_result)
	{
		DPRINT("ids_pcap_get_pcap(%s): pcap_set_immediate_mode() failed\n",
				if_name);
		goto error;
	}

	tmp_result = pcap_activate(pcap);
	if (tmp_result < 0)
	{
		/* Check for programming errors */
		assert(PCAP_ERROR_ACTIVATED != tmp_result);
		assert(PCAP_ERROR_NO_SUCH_DEVICE != tmp_result);

		DPRINT("ids_pcap_get_pcap(%s): pcap_activate() failed with message: %s\n",
				if_name, pcap_geterr(pcap));
		goto error;
	}
	else if (tmp_result > 0)
	{
		/* Display warning message */
		DPRINT("ids_pcap_get_pcap(%s): pcap_activate() warning: %s\n",
				if_name, pcap_geterr(pcap));
	}

	/* Set up filter */
	if (PCAP_ERROR == pcap_compile(pcap, &filter, pcap_filter, 0, 0))
	{
		DPRINT("ids_pcap_get_pcap(%s): pcap_compile() failed with message: %s\n",
				if_name, pcap_geterr(pcap));
		goto error;
	}

	if (PCAP_ERROR == pcap_setfilter(pcap, &filter))
	{
		DPRINT("ids_pcap_get_pcap(%s): pcap_setfilter() failed with message: %s\n",
				if_name, pcap_geterr(pcap));
		goto error;
	}

	DPRINT("ids_pcap_get_pcap(%s): successfully completed \n", if_name);
	return (pcap);

error:
	if (pcap) pcap_close(pcap);
	pcap = NULL;
	return (pcap);
}
