/*
 * Callbacks which can be used with libuv to update blacklists periodically.
 *
 * ids_blacklist_update.h
 *
 *  Created on: 11/04/2019
 *      Author: mfletche
 */

#ifndef SRC_IDS_BLACKLIST_UPDATE_H_
#define SRC_IDS_BLACKLIST_UPDATE_H_

void ids_blacklist_timer_cb(uv_timer_t *handle)
{
	/**
	 * 1. Download new blacklist. Is it a file? Is it delivered by a stream?
	 * 2. If file, load it into memory/parse it. If not, should probably archive it somewhere so
	 * that if the IDS is restarted, the latest list is immediately available.
	 * 3. If enough memory, create new list, replace blacklist pointer with new address.
	 * 4. Clean up old blacklist.
	 */
}

int
ids_blacklist_update_setup_timer(uv_timer_t *handle, uint64_t period)
{
	uv_timer_init(loop, handle);
	uv_timer_start(handle, ids_blacklist_timer_cb, period, period);
}

#endif /* SRC_IDS_BLACKLIST_UPDATE_H_ */
