/*
 * mdns_io_task.h
 *
 *  Created on: 29/10/2018
 *      Author: mfletche
 */

#ifndef MDNS_IO_TASK_H_
#define MDNS_IO_TASK_H_

#include <stdint.h>

struct mdns_io_task_state;

/*
 * Gets an io_task structure that will listen for MDNS packets on the MDNS
 * multicast IP address and respond with an advertisement for the IDS server.
 *
 * The result may be NULL if the socket could not be initialized. */
struct io_task *
mdns_io_task_setup();

#endif /* MDNS_IO_TASK_H_ */
