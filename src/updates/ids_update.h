/*
 * ids_update.h
 *
 *  Created on: May 17, 2019
 *      Author: mfletche
 */

#ifndef SRC_BLACKLIST_UPDATES_IDS_UPDATE_H_
#define SRC_BLACKLIST_UPDATES_IDS_UPDATE_H_

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#include "multi_uv.h"
#include "../blacklist/ids_blacklist.h"

/**
 * Setup a repeating uv_timer_t which will start a download of the latest
 * blacklists.
 * @param loop The main event loop
 * @param ctx Context containing a curl multi handle
 * @param ip_bl IP blacklist which will be updated when timer runs out
 * @param domain_bl Domain blacklist which will be updated when timer runs out
 * @returns An initialized uv_timer_t or NULL if unsuccessful.
 */
uv_timer_t *
ids_update_setup_timer(uv_loop_t *loop, curl_globals_t *ctx,
		ip_blacklist **ip_bl, domain_blacklist **domain_bl);

#endif /* SRC_BLACKLIST_UPDATES_IDS_UPDATE_H_ */
