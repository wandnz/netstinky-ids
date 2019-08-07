/*
 * fetch_update.h
 *
 * Uses the libcurl multi interface with the libuv event loop to download
 * blacklists via HTTP(S).
 *
 * Based on: https://github.com/libuv/libuv/blob/v1.x/docs/code/uvwget/main.c
 *
 *  Created on: 6/05/2019
 *      Author: mfletche
 */

#ifndef SRC_BLACKLIST_UPDATES_CURL_UV_IFACE_H_
#define SRC_BLACKLIST_UPDATES_CURL_UV_IFACE_H_

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <uv.h>

/*
 * A bundle of handles which will be passed as user data to callback functions.
 */
typedef struct curl_context_s {
	CURLM *curl_multi;
	uv_loop_t *loop;
	uv_timer_t *timeout;
} curl_context_t;

/**
 * Perform global setup for libcurl. Should be run before running any update
 * functions.
 * @returns True if successful
 */
bool
setup_http_library();

/**
 * Sets up the multi handle for libcurl. This is required before any specific
 * downloads are set up. This is used to integrate libcurl into the libuv event
 * loop.
 * @param loop: An initialized libuv loop. Timeout timers will be added to the loop.
 * @returns: A pointer to a curl context struct.
 */
curl_context_t *
setup_curl_multi_handle(uv_loop_t *loop);

/**
 * Begin to download a new file to DEST_FILENAME. Creates a new curl easy handle
 * and adds it to the multi handle provided.
 * @param curl_handle A curl multi handle
 * @param url The url to download the file from
 * @param dest_filename The location of the output file
 */
void
download_file(CURLM *curl_handle, const char *url, const char *dest_filename);

void
destroy_curl_context(curl_context_t *ctx);

#endif /* SRC_BLACKLIST_UPDATES_CURL_UV_IFACE_H_ */
