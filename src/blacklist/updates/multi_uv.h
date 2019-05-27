/*
 * multi_uv.h
 *
 *  Created on: May 23, 2019
 *      Author: mfletche
 */

#ifndef SRC_BLACKLIST_UPDATES_MULTI_UV_H_
#define SRC_BLACKLIST_UPDATES_MULTI_UV_H_

#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include <uv.h>

typedef struct curl_globals_s curl_globals_t;

/**
 * Buffer for holding downloads to memory.
 */
typedef struct multi_uv_mem_buff_s {
	unsigned char *buff;
	size_t size;
} multi_uv_mem_buff_t;

/**
 * A callback that can be registered to run when a download completes
 * successfully.
 * @param result Status of the finished download
 * @param userdata Data passed in via add_download_to_file function
 */
typedef void (*multi_uv_download_complete_cb)(CURLcode result, void *userdata);

/**
 * A callback that can be registered to run when a download has fully loaded
 * into memory.
 * @param result Status of the finished download
 * @param buff Memory buffer containing downloaded bytes
 * @param userdata Data passed in via download_to_memory function
 */
typedef void (*multi_uv_download_to_memory_cb)(CURLcode result, multi_uv_mem_buff_t buff,
		void *userdata);

/**
 * Begin a download to a file and register a callback to run on completion.
 * @param globals Curl_globals, may not be NULL.
 * @param url The remote location of the file.
 * @param target_file The local location to save the file.
 * @param cb Callback to run when download is complete, may be NULL.
 * @param userdata Data to provide to the callback, may be NULL.
 */
void add_download_to_file(curl_globals_t *globals, const char *url,
		const char *target_file, multi_uv_download_complete_cb cb, void *userdata);

curl_globals_t *
multi_uv_setup(uv_loop_t *loop);

void
multi_uv_free(curl_globals_t **globals);

#endif /* SRC_BLACKLIST_UPDATES_MULTI_UV_H_ */
