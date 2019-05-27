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

uv_timer_t *
ids_update_setup_timer(uv_loop_t *loop, curl_globals_t *ctx);

#endif /* SRC_BLACKLIST_UPDATES_IDS_UPDATE_H_ */
