/*
 * pcap_io_task.h
 *
 *  Created on: 29/10/2018
 *      Author: mfletche
 */

#ifndef PCAP_IO_TASK_H_
#define PCAP_IO_TASK_H_

#include "ip_blacklist.h"
#include "domain_blacklist.h"

struct pcap_io_task_state;

/*
 * Creates an io_task structure for a pcap IO task. This structure can be added
 * to an io_task list which will handle checking if reading/writing will block,
 * and calling the appropriate IO functions.
 *
 * The result may be NULL if the device could not be set up for packet capture.
 */
struct io_task *
pcap_io_task_setup(char *if_name, ip_blacklist *b, domain_blacklist *d);

#endif /* PCAP_IO_TASK_H_ */
