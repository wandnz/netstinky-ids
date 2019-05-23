/*
 * multi_uv.h
 *
 *  Created on: May 23, 2019
 *      Author: mfletche
 */

#ifndef SRC_BLACKLIST_UPDATES_MULTI_UV_H_
#define SRC_BLACKLIST_UPDATES_MULTI_UV_H_

#include <assert.h>
#include <string.h>

#include <uv.h>

typedef struct curl_globals_s curl_globals_t;

void
add_download(curl_globals_t *globals, const char *url, int num);

curl_globals_t *
multi_uv_setup(uv_loop_t *loop);

void
multi_uv_free(curl_globals_t **globals);

#endif /* SRC_BLACKLIST_UPDATES_MULTI_UV_H_ */
