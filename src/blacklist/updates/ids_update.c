/*
 * ids_update.c
 *
 *  Created on: May 17, 2019
 *      Author: mfletche
 */

#include "ids_update.h"

static const uint64_t update_interval_ms = 600000;	// 10 minutes
static const char ip_blacklist_src[] = "https://iplists.firehol.org/files/firehol_level1.netset";
static const char domain_blacklist_src[] = "https://urlhaus.abuse.ch/downloads/text/";

static void
on_complete_cb(CURLcode result, void *userdata)
{
	printf("Download completed with CURLcode (%d)\n", result);
}

/**
 * Begin downloading of blacklists. Called when update interval has passed.
 */
static void
update_timer_cb(uv_timer_t *handle)
{
	curl_globals_t *ctx = (curl_globals_t *)handle->data;
	assert(ctx);

	add_download_to_file(ctx, ip_blacklist_src, "ip_blacklist", on_complete_cb, NULL);
	add_download_to_file(ctx, domain_blacklist_src, "domain_blacklist", on_complete_cb, NULL);
}

static void
close_cb(uv_handle_t *handle)
{
	assert(UV_TIMER == handle->type);
	uv_timer_t *timer = (uv_timer_t *)handle;
	if (timer)
		free(timer);
}

/**
 * Setup a repeating uv_timer_t which will start a download of the latest
 * blacklists.
 * @param loop The main event loop
 * @param ctx Context containing a curl multi handle
 * @returns An initialized uv_timer_t or NULL if unsuccessful.
 */
uv_timer_t *
ids_update_setup_timer(uv_loop_t *loop, curl_globals_t *ctx)
{
	int uv_result = 0;
	uv_timer_t *timer = NULL;

	// Prepare memory
	timer = malloc(sizeof *timer);
	if (NULL == timer) goto error;
	memset(timer, 0, sizeof *timer);

	// Prepare timer
	uv_result = uv_timer_init(loop, timer);
	if (0 > uv_result) goto pre_init_err;
	timer->data = ctx;

	// Start timer
	uv_result = uv_timer_start(timer, update_timer_cb,
			0, update_interval_ms);
	if (0 > uv_result) goto post_init_err;

	return timer;


pre_init_err:
	if (timer)
	{
		free(timer);
	}
	goto error;
post_init_err:
	// Must wait for callback to free timer
	if (timer)
	{
		uv_close((uv_handle_t *)timer, close_cb);
	}
error:
	fprintf(stderr, "Error: ids_update_setup_timer(): %s\n",
			uv_strerror(uv_result));
	return NULL;
}
