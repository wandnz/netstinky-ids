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

struct io_task *
mdns_io_task_setup();

#endif /* MDNS_IO_TASK_H_ */
