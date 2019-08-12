/*
 * A data structure that will be the value stored for each IOC key.
 *
 * Currently stores an ID which uniquely identifies the botnet associated with
 * an IOC. This allows the operator of a home network to find instructions to
 * remove a particular botnets' malware without sending sensitive information
 * to the Netstinky server.
 *
 * ids_storedvalues.h
 *
 *  Created on: Aug 7, 2019
 *      Author: mfletche
 */

#ifndef SRC_BLACKLIST_IDS_STOREDVALUES_H_
#define SRC_BLACKLIST_IDS_STOREDVALUES_H_

typedef struct
{
	int botnet_id;
} ids_ioc_value_t;

/**
 * Allocate and initialize a new value struct.
 */
ids_ioc_value_t *
new_ids_ioc_value(int botnet_id);

/**
 * Free a value struct.
 */
void
free_ids_ioc_value(ids_ioc_value_t *value);

#endif /* SRC_BLACKLIST_IDS_STOREDVALUES_H_ */
