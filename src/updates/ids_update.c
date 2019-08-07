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

#define IP_BLACKLIST_FILE "ip_blacklist.temp"
#define DOMAIN_BLACKLIST_FILE "domain_blacklist.temp"

/**
 * This will be stored in the update timer's data field. It should be freed
 * when the update timer is closed.
 * TODO: Find a way to close the update_timer_data. This is not a high priority
 * because the update timer should run until the program ends.
 */
typedef struct
update_timer_data
{
	curl_globals_t *ctx;
	ip_blacklist **ip_blacklist;
	domain_blacklist **domain_blacklist;
} update_timer_data_t;

static update_timer_data_t *
bundle_update_timer_data(curl_globals_t *ctx, ip_blacklist **ip_blacklist,
		domain_blacklist **domain_blacklist)
{
	update_timer_data_t *bundle = NULL;

	bundle = malloc(sizeof *bundle);
	if (bundle)
	{
		bundle->ctx = ctx;
		bundle->ip_blacklist = ip_blacklist;
		bundle->domain_blacklist = domain_blacklist;
	}

	return bundle;
}

static void
on_ip_blacklist_complete(CURLcode result, void *userdata)
{
	ip_blacklist **old_blacklist = userdata;

	if (CURLE_OK == result)
	{
		free_ip_blacklist(old_blacklist);

		if (0 == setup_ip_blacklist(old_blacklist, IP_BLACKLIST_FILE))
		{
			fprintf(stderr, "ERROR: Could not load IP blacklist.\n");
			exit(EXIT_FAILURE);
		}
	}
}

static void
on_domain_blacklist_complete(CURLcode result, void *userdata)
{
	domain_blacklist **old_blacklist = userdata;

	if (CURLE_OK == result)
	{
		free_domain_blacklist(old_blacklist);

		if (0 == setup_domain_blacklist(old_blacklist, DOMAIN_BLACKLIST_FILE))
		{
			fprintf(stderr, "ERROR: Could not load domain blacklist.\n");
			exit(EXIT_FAILURE);
		}
	}
}

/**
 * Begin downloading of blacklists. Called when update interval has passed.
 */
static void
update_timer_cb(uv_timer_t *handle)
{
	update_timer_data_t *data = (update_timer_data_t *)handle->data;
	curl_globals_t *ctx = data->ctx;
	assert(ctx);

	add_download_to_file(ctx, ip_blacklist_src, IP_BLACKLIST_FILE,
			on_ip_blacklist_complete, data->ip_blacklist);
	add_download_to_file(ctx, domain_blacklist_src, DOMAIN_BLACKLIST_FILE,
			on_domain_blacklist_complete, data->domain_blacklist);
}

static void
close_cb(uv_handle_t *handle)
{
	assert(UV_TIMER == handle->type);
	uv_timer_t *timer = (uv_timer_t *)handle;
	if (timer)
		free(timer);
}

uv_timer_t *
ids_update_setup_timer(uv_loop_t *loop, curl_globals_t *ctx,
		ip_blacklist **ip_bl, domain_blacklist **domain_bl)
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

	update_timer_data_t *bundle = bundle_update_timer_data(ctx, ip_bl, domain_bl);
	if (NULL == bundle) goto pre_init_err;
	timer->data = bundle;

	// Start timer
	uv_result = uv_timer_start(timer, update_timer_cb,
			0, update_interval_ms);
	if (0 > uv_result) goto post_init_err;

	return timer;

pre_init_err:
// If error occurred before adding timer to event loop
	if (timer)
	{
		free(timer);
	}
	goto error;
post_init_err:
/* If error occurred after adding timer to event loop, the handle must be freed
 * during a callback */
	if (timer)
	{
		uv_close((uv_handle_t *)timer, close_cb);
	}
error:
	if (bundle) free(bundle);
	fprintf(stderr, "Error: ids_update_setup_timer(): %s\n",
			uv_strerror(uv_result));
	return NULL;
}
