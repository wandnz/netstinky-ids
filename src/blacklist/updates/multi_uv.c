/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2018, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

/* <DESC>
 * multi_socket API using libuv
 * </DESC>
 */
/* Example application using the multi socket interface to download multiple
   files in parallel, powered by libuv.

   Requires libuv and (of course) libcurl.

   See https://nikhilm.github.io/uvbook/ for more information on libuv.
 */

#include <stdio.h>
#include <stdlib.h>
#include <uv.h>
#include <curl/curl.h>

#include "multi_uv.h"

typedef struct curl_globals_s {
	uv_loop_t *loop;
	CURLM *curl_handle;
	uv_timer_t *timeout;	// must be dynamically allocated to be compatible
						// with the rest of the IDS handles
} curl_globals_t;

typedef struct curl_context_s {
	uv_poll_t *poll_handle;
	curl_socket_t sockfd;
	curl_globals_t *globals;
} curl_context_t;

/**
 * The following warning functions can be used to wrap around functions which
 * return a error code, when the execution will not be changed if the function
 * fails.
 */
static void
uv_warning(int uv_error)
{
	if (0 > uv_error)
		fprintf(stderr, "warning: %s\n", uv_strerror(uv_error));
}

static void
curl_easy_warning(CURLcode error)
{
	if (CURLE_OK != error)
		fprintf(stderr, "WARNING: %s\n", curl_easy_strerror(error));
}

static void
curl_multi_warning(CURLMcode error)
{
	if (CURLM_OK != error)
		fprintf(stderr, "WARNING: %s\n", curl_multi_strerror(error));
}

/**
 * Allocate a new curl context for a curl socket.
 * @param sockfd The socket file descriptor.
 * @returns Address of a new curl_context struct. Must be freed after use.
 */
static curl_context_t* create_curl_context(curl_globals_t *globals, curl_socket_t sockfd)
{
	int uv_result = 0;
	curl_context_t *context = NULL;

	context = (curl_context_t *) malloc(sizeof(*context));
	if (NULL == context) goto error;

	context->sockfd = sockfd;
	context->globals = globals;


	context->poll_handle = malloc(sizeof(*context->poll_handle));
	if (NULL == context->poll_handle) goto error;
	memset(context->poll_handle, 0, sizeof(*context->poll_handle));

	uv_result = uv_poll_init_socket(globals->loop, context->poll_handle, sockfd);
	if (0 > uv_result) goto error;

	context->poll_handle->data = context;

	return context;

error:
	if (NULL != context)
	{
		if (context->poll_handle)
			free(context->poll_handle);
		free(context);
	}
	return NULL;
}

/**
 * Callback when uv_close(handle) has completed.
 * @param handle The handle that was closed.
 */
static void curl_close_cb(uv_handle_t *handle)
{
	curl_context_t *context = (curl_context_t *) handle->data;
	if (NULL != context) free(context);
}

/**
 * Free a curl_context struct.
 * @param context The context to free.
 */
static void destroy_curl_context(curl_context_t *context)
{
	uv_close((uv_handle_t *)context->poll_handle, curl_close_cb);
}

/**
 * Start a download to a file using curl.
 * @param url The url of the file to download
 * @param target_file String containing path or name of file
 */
void add_download_to_file(curl_globals_t *globals, const char *url, const char *target_file)
{
	int result = 0;
	char filename[50];
	FILE *file = NULL;
	CURL *handle = NULL;
	CURLcode easy_result = CURLE_OK;
	CURLMcode multi_result = CURLM_OK;

	assert(NULL != globals);
	assert(NULL != url);

	file = fopen(target_file, "wb");
	if(!file) {
		fprintf(stderr, "Error opening %s\n", filename);
		return;
	}

	handle = curl_easy_init();
	if (NULL == handle) goto error;

	easy_result = curl_easy_setopt(handle, CURLOPT_WRITEDATA, file);
	if (CURLE_OK != easy_result) goto error;

	easy_result = curl_easy_setopt(handle, CURLOPT_PRIVATE, file);
	if (CURLE_OK != easy_result) goto error;

	easy_result = curl_easy_setopt(handle, CURLOPT_URL, url);
	if (CURLE_OK != easy_result) goto error;

	multi_result = curl_multi_add_handle(globals->curl_handle, handle);
	if (CURLM_OK != multi_result) goto error;

	fprintf(stderr, "Added download %s -> %s\n", url, target_file);
	return;

error:
	if (NULL != handle) curl_easy_cleanup(handle);
	if (NULL != file) fclose(file);
}

static void check_multi_info(curl_globals_t *globals)
{
	char *done_url = NULL;
	CURLMsg *message = NULL;
	int pending;
	CURL *easy_handle = NULL;
	FILE *file = NULL;

	while((message = curl_multi_info_read(globals->curl_handle, &pending))) {
		switch(message->msg) {
		case CURLMSG_DONE:
			/* Do not use message data after calling curl_multi_remove_handle() and
         curl_easy_cleanup(). As per curl_multi_info_read() docs:
         "WARNING: The data the returned pointer points to will not survive
         calling curl_multi_cleanup, curl_multi_remove_handle or
         curl_easy_cleanup." */
			easy_handle = message->easy_handle;

			curl_easy_warning(curl_easy_getinfo(easy_handle, CURLINFO_EFFECTIVE_URL, &done_url));
			curl_easy_warning(curl_easy_getinfo(easy_handle, CURLINFO_PRIVATE, &file));

			if (NULL != done_url) printf("%s DONE\n", done_url);
			curl_multi_warning(curl_multi_remove_handle(globals->curl_handle, easy_handle));

			curl_easy_cleanup(easy_handle);
			if(file) {
				fclose(file);
			}
			break;

		default:
			fprintf(stderr, "CURLMSG default\n");
			break;
		}
	}
}

static void curl_perform(uv_poll_t *req, int status, int events)
{
	int running_handles;
	int flags = 0;
	curl_context_t *context;

	if(events & UV_READABLE)
		flags |= CURL_CSELECT_IN;
	if(events & UV_WRITABLE)
		flags |= CURL_CSELECT_OUT;

	context = (curl_context_t *) req->data;

	curl_multi_socket_action(context->globals->curl_handle, context->sockfd, flags,
			&running_handles);

	check_multi_info(context->globals);
}

/**
 * Callback when a socket timeout should occur.
 *
 * The req->data field should contain a curl_globals_t field
 * (set in multi_uv_setup).
 */
static void on_timeout(uv_timer_t *req)
{
	int running_handles;
	CURLMcode multi_result = CURLM_OK;
	curl_globals_t *context = (curl_globals_t *)req->data;

	multi_result = curl_multi_socket_action(context->curl_handle, CURL_SOCKET_TIMEOUT, 0,
			&running_handles);
	if (CURLM_OK != multi_result) printf("%s\n", curl_multi_strerror(multi_result));

	check_multi_info(context);
}

static int start_timeout(CURLM *multi, long timeout_ms, void *userp)
{
	curl_globals_t *globals = (curl_globals_t *)userp;
	assert(globals);
	assert(globals->timeout);

	if(timeout_ms < 0) {
		uv_timer_stop(globals->timeout);
	}
	else {
		if(timeout_ms == 0)
			timeout_ms = 1; /* 0 means directly call socket_action, but we'll do it
                         in a bit */
		uv_timer_start(globals->timeout, on_timeout, timeout_ms, 0);
	}
	return 0;
}

static int handle_socket(CURL *easy, curl_socket_t s, int action, void *userp,
		void *socketp)
{
	int uv_result = 0;
	CURLMcode multi_result = CURLM_OK;
	curl_globals_t *globals = NULL;
	curl_context_t *curl_context = NULL;
	int events = 0;

	globals = (curl_globals_t *)userp;

	switch(action) {
	case CURL_POLL_IN:
	case CURL_POLL_OUT:
	case CURL_POLL_INOUT:
		curl_context = socketp ?
				(curl_context_t *) socketp : create_curl_context(globals, s);

		multi_result = curl_multi_assign(globals->curl_handle, s, (void *) curl_context);
		if (CURLM_OK != multi_result) curl_multi_warning(multi_result);

		if(action != CURL_POLL_IN)
			events |= UV_WRITABLE;
		if(action != CURL_POLL_OUT)
			events |= UV_READABLE;

		uv_result = uv_poll_start(curl_context->poll_handle, events, curl_perform);
		if (0 > uv_result) uv_warning(uv_result);

		break;
	case CURL_POLL_REMOVE:
		if(socketp) {
			uv_result = uv_poll_stop(((curl_context_t*)socketp)->poll_handle);
			if (0 > uv_result) uv_warning(uv_result);

			destroy_curl_context((curl_context_t*) socketp);
			multi_result = curl_multi_assign(globals->curl_handle, s, NULL);
			if (CURLM_OK != multi_result) curl_multi_warning(multi_result);
		}
		break;
	default:
		abort();
	}

	return 0;
}

curl_globals_t *
multi_uv_setup(uv_loop_t *loop)
{
	assert(loop);
	int uv_result = 0;
	CURLcode easy_result = CURLE_OK;
	CURLMcode multi_result = CURLM_OK;
	curl_globals_t *globals = NULL;

	easy_result = curl_global_init(CURL_GLOBAL_ALL);
	if (CURLE_OK != easy_result) goto error;

	globals = malloc(sizeof *globals);
	if (NULL == globals) goto error;
	memset(globals, 0, sizeof *globals);

	// Prepare curl multi handle
	globals->curl_handle = curl_multi_init();
	if (NULL == globals->curl_handle) goto error;

	multi_result = curl_multi_setopt(globals->curl_handle, CURLMOPT_SOCKETDATA, globals);
	if (CURLM_OK != multi_result) goto error;

	multi_result = curl_multi_setopt(globals->curl_handle, CURLMOPT_SOCKETFUNCTION, handle_socket);
	if (CURLM_OK != multi_result) goto error;

	multi_result = curl_multi_setopt(globals->curl_handle, CURLMOPT_TIMERDATA, globals);
	if (CURLM_OK != multi_result) goto error;

	multi_result = curl_multi_setopt(globals->curl_handle, CURLMOPT_TIMERFUNCTION, start_timeout);
	if (CURLM_OK != multi_result) goto error;

	// Prepare timer handle
	globals->timeout = malloc(sizeof *globals->timeout);
	if (NULL == globals->timeout) goto error;
	globals->loop = loop;

	uv_result = uv_timer_init(loop, globals->timeout);
	if (0 > uv_result) goto error;

	// Allows access to globals in on_timeout
	globals->timeout->data = globals;

	return globals;

error:
	if (NULL != globals)
	{
		if (globals->curl_handle)
			curl_multi_warning(curl_multi_cleanup(globals->curl_handle));
		if (globals->timeout)
			free(globals->timeout);
		free(globals);
	}
	fprintf(stderr, "Error: multi_uv_setup(): ");
	if (0 > uv_result) fprintf(stderr, "%s\n", uv_strerror(uv_result));
	if (CURLE_OK != easy_result) fprintf(stderr, "%s\n", curl_easy_strerror(easy_result));
	return NULL;
}

static void
multi_uv_free_cb(uv_handle_t *handle)
{
	assert(UV_TIMER == handle->type);
	curl_globals_t **globals = handle->data;

	if (*globals)
	{
		free(*globals);
		*globals = NULL;
	}
}

/**
 * The timeout handle cannot be freed until a callback is triggered, which will
 * be at least until the next event loop iteration.
 */
void
multi_uv_free(curl_globals_t **globals)
{
	if (*globals)
	{
		curl_multi_warning(curl_multi_cleanup((*globals)->curl_handle));
		(*globals)->curl_handle = NULL;
		(*globals)->loop = NULL;	// Will be freed in main program

		// Must have address of globals pointer to free after the handle
		(*globals)->timeout->data = globals;
		uv_close((uv_handle_t *)(*globals)->timeout, multi_uv_free_cb);
	}
}
