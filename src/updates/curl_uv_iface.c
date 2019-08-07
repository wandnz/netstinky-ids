/*
 * fetch_update.c
 *
 *  Created on: 6/05/2019
 *      Author: mfletche
 */

#include "curl_uv_iface.h"

/**
 * A bundle of handles which are related to a specific socket.
 */
typedef struct curl_socket_baton_s {
	curl_socket_t sockfd;
	uv_poll_t *poll_handle;
	curl_context_t *main_context;
} curl_socket_baton_t;

bool
setup_http_library()
{
	if (curl_global_init(CURL_GLOBAL_DEFAULT))
	{
		fprintf(stderr, "ERROR: curl_global_init() failed\n");
		return false;
	}

	return true;
}

/**
 * Print a curl error message for one of the CURL error codes. Always includes
 * a new line, whether or not a curl error message is printed.
 *
 * This is intended to be used at the end of a function where an error occurred
 * but the specific error could be either an easy or multi error.
 *
 * Will raise an assertion error if both results are errors (mostly because not
 * sure how to format a message, but also shouldn't the calling function have
 * stopped after one error?).
 *
 * WARNING: To use this function, the results which are passed in should ALWAYS
 * be initialized to either CURLE_OK or CURLM_OK at the start of the calling
 * function.
 */
static void
print_curl_error_message(CURLcode easy_result, CURLMcode multi_result)
{
	assert(!(CURLE_OK == easy_result && CURLM_OK == multi_result));

	if (CURLE_OK != easy_result)
		fprintf(stderr, "%s", curl_easy_strerror(easy_result));
	else if (CURLM_OK != multi_result)
		fprintf(stderr, "%s", curl_easy_strerror(multi_result));
	fprintf(stderr, "\n");
}

/*
 * Begin downloading the most up-to-date IP and domain name blacklists.
 * @param curl_handle A curl multi handle. Curl easy handles will be added to
 * the multi handle for each blacklist.
 */
void
download_file(CURLM *curl_handle, const char *url, const char *dest_filename)
{
	FILE *file = NULL;
	CURL *easy_handle = NULL;
	CURLcode easy_result = CURLE_OK;
	CURLMcode multi_result = CURLM_OK;

	file = fopen(dest_filename, "w");
	if (NULL == file) goto error;

	// Set up easy handle for this specific download
	easy_handle = curl_easy_init();
	if (NULL == easy_handle) goto err_file;

	easy_result = curl_easy_setopt(easy_handle, CURLOPT_WRITEDATA, file);
	if (CURLE_OK != easy_result) goto err_easy_handle;

	// Store the file pointer so that it can be closed properly when download completes
	easy_result = curl_easy_setopt(easy_handle, CURLOPT_PRIVATE, file);
	if (CURLE_OK != easy_result) goto err_easy_handle;

	easy_result = curl_easy_setopt(easy_handle, CURLOPT_URL, url);
	if (CURLE_OK != easy_result) goto err_easy_handle;

	easy_result = curl_easy_setopt(easy_handle, CURLOPT_CONNECTTIMEOUT, 10L);
	if (CURLE_OK != easy_result) goto err_easy_handle;

	easy_result = curl_easy_setopt(easy_handle, CURLOPT_TIMEOUT, 10L);
	if (CURLE_OK != easy_result) goto err_easy_handle;

	// Add to existing multi handle
	multi_result = curl_multi_add_handle(curl_handle, easy_handle);
	if (CURLM_OK != multi_result) goto err_easy_handle;

	return;

// Free resources in case of error
err_easy_handle:
	curl_easy_cleanup(easy_handle);
err_file:
	fclose(file);
error:
	fprintf(stderr, "Error: download_file(): ");
	print_curl_error_message(easy_result, multi_result);
}

/**
 * Reads the message queue for the curl multi handle and prints a status message as
 * each download completes.
 */
static void
check_multi_info(CURLM *curl_handle)
{
	int pending;
	char *done_url;
	CURLMsg *message;
	CURLcode easy_err = CURLE_OK;
	CURLMcode multi_err = CURLM_OK;

	while (NULL != (message = curl_multi_info_read(curl_handle, &pending)))
	{
		// libcurl does not have any other message types defined (as of 7.61.0)
		assert(CURLMSG_DONE == message->msg);

		// Print status message about completed download
		easy_err = curl_easy_getinfo(message->easy_handle, CURLINFO_EFFECTIVE_URL, &done_url);
		if (CURLE_OK != easy_err) goto error;

		printf("%s complete\n", done_url);

		FILE *file = NULL;
		easy_err = curl_easy_getinfo(curl_handle, CURLINFO_PRIVATE, &file);
		if (CURLE_OK != easy_err) goto error;

		if (file)
		{
			fflush(file);
			fclose(file);
		}

		// Clean up completed handles
		multi_err = curl_multi_remove_handle(curl_handle, message->easy_handle);
		if (CURLM_OK != multi_err) goto error;

		curl_easy_cleanup(message->easy_handle);
	}

	return;

error:
	fprintf(stderr, "Error: check_multi_info(): ");
	print_curl_error_message(easy_err, multi_err);
}

/**
 * Callback for when timeout occurs on a libuv timer handle.
 *
 * The data field of the timer should contain a reference to a curl_context.
 */
static void
on_timeout(uv_timer_t *req)
{
	curl_context_t *ctx = (curl_context_t *)req->data;
	CURLMcode multi_err;
	int running_handles;	// Unused buffer for curl_multi_socket_action output

	assert(ctx->curl_multi);

	// Tell curl that a timeout has occurred
	multi_err = curl_multi_socket_action(ctx->curl_multi, CURL_SOCKET_TIMEOUT, 0, &running_handles);
	printf("%d running handles...\n", running_handles);
	if (CURLM_OK != multi_err) goto error;

	check_multi_info(ctx->curl_multi);

	return;

error:
	fprintf(stderr, "Error: on_timeout(): %s\n", curl_multi_strerror(multi_err));
}

/*
 * Callback for curl_multi_setopt(CURLMOPT_TIMERFUNCTION).
 *
 * Sets up a timer which will call curl_multi_socket_action or curl_multi_perform.
 * @param multi: A Curl multi interface handle
 * @param timeout_ms: The length of the timer in milliseconds, or -1 if the timer should be
 * deleted.
 * @param userp: Data set with CURLMOPT_TIMERDATA. Contains a curl_context_t.
 * @returns: 0 on success, -1 on error (required by libcurl).
 */
static int
start_timeout(CURLM *multi, long timeout_ms, void *userp)
{
	int uv_result = 0;
	curl_context_t *ctx = (curl_context_t *)userp;

	assert(ctx->timeout);
	if (-1 == timeout_ms)
	{
		uv_result = uv_timer_stop(ctx->timeout);
		if (0 > uv_result) goto error;
	}
	else
	{
		uv_result = uv_timer_start(ctx->timeout, on_timeout, timeout_ms, 0);
		if (0 > uv_result) goto error;
	}

	/*
	// Original example code which I believe is wrong, but just in case this doesn't
	// behave as I think it should...
	if (timeout_ms <= 0)
	{
		timeout_ms = 1;
		uv_timer_start(&timeout, on_timeout, timeout_ms, 0);
	}
	*/

	return 0;

error:
	fprintf(stderr, "Error: start_timeout(): %s\n", uv_strerror(uv_result));
	return -1;
}

// callback added by uv_poll_start
void
curl_perform(uv_poll_t *req, int status, int events)
{
	int running_handles;
	int flags = 0;

	curl_socket_baton_t *baton;
	CURLMcode multi_result = 0;

	// data field contains curl_context_t
	assert(req->data);
	baton = (curl_socket_baton_t *)req->data;

	// Set flags for socket action
	if (status < 0) flags = CURL_CSELECT_ERR;
	if (!status && (events & UV_READABLE)) flags |= CURL_CSELECT_IN;
	if (!status && (events & UV_WRITABLE)) flags |= CURL_CSELECT_OUT;

	assert(baton->main_context);
	assert(baton->main_context->curl_multi);
	assert(baton->sockfd >= 0);
	multi_result = curl_multi_socket_action(baton->main_context->curl_multi, baton->sockfd, flags, &running_handles);
	if (CURLM_OK != multi_result) goto error;

	check_multi_info(baton->main_context->curl_multi);

	return;

error:
	fprintf(stderr, "Error: curl_perform(): %s\n", curl_multi_strerror(multi_result));
}

/**
 * Creates a context for curl multi operations using the provided loop. Also creates
 * a timer handle.
 */
static curl_context_t *
create_curl_context(uv_loop_t *loop)
{
	int uv_result = 0;
	curl_context_t *ctx = NULL;

	ctx = (curl_context_t *)malloc(sizeof *ctx);
	if (NULL == ctx) goto error;

	memset(ctx, 0, sizeof *ctx);
	ctx->loop = loop;

	ctx->timeout = malloc(sizeof *ctx->timeout);
	if (NULL == ctx->timeout) goto err_free_ctx;

	memset(ctx->timeout, 0, sizeof *ctx->timeout);
	uv_result = uv_timer_init(loop, ctx->timeout);
	if (0 > uv_result) goto err_free_timer;

	ctx->timeout->data = ctx;

	return ctx;

err_free_timer:
	free(ctx->timeout);
err_free_ctx:
	free(ctx);
error:
	fprintf(stderr, "Error: create_curl_context(): ");
	if (uv_result) fprintf(stderr, "%s", uv_strerror(uv_result));
	fprintf(stderr, "\n");
	return NULL;
}

/**
 * Frees the closed handle (which is the timeout timer) and frees the context.
 * @param handle: The closed handle.
 */
static void
curl_close_curl_context_cb(uv_handle_t *handle)
{
	curl_context_t *context = (curl_context_t *)handle->data;

	// There is only one handle to release in a curl_context_t
	assert(UV_TIMER == handle->type);
	free((uv_timer_t *)handle);
	free(context);
}

static void
curl_close_socket_baton_cb(uv_handle_t *handle)
{
	uv_poll_t *poll_handle;

	curl_socket_baton_t *baton = (curl_socket_baton_t *)handle->data;

	// Each libuv handle in the socket baton is of a different type, so can
	// use type to distinguish them
	switch (handle->type)
	{
		case UV_POLL:
			poll_handle = (uv_poll_t *)handle;
			free(poll_handle);
			baton->poll_handle = NULL;
			break;
		default:
			// Something very wrong happened
			assert(false);
	}

	// All handles freed
	free(baton);
}

void
destroy_curl_context(curl_context_t *ctx)
{
	uv_close((uv_handle_t *)ctx->timeout, curl_close_curl_context_cb);
}

/**
 * Allocate memory for a curl_context struct and initialize it (means setting
 * most fields to NULL).
 *
 * Initializes a socket through libuv.
 *
 * @param sockfd: The file descriptor of the socket.
 * @param loop: The main event loop.
 * @returns: An initialized curl_socket_baton.
 */
static curl_socket_baton_t *
create_curl_socket_baton(curl_socket_t sockfd, uv_loop_t *loop)
{
	int uv_result = 0;
	curl_socket_baton_t *baton = NULL;

	baton = (curl_socket_baton_t *)malloc(sizeof *baton);
	if (NULL == baton) goto error;

	memset(baton, 0, sizeof *baton);
	baton->sockfd = sockfd;

	baton->poll_handle = malloc(sizeof *baton->poll_handle);
	if (NULL == baton->poll_handle) goto err_free_context;

	uv_result = uv_poll_init_socket(loop, baton->poll_handle, sockfd);
	if (0 > uv_result) goto err_free_poll;

	baton->poll_handle->data = baton;

	return baton;

err_free_poll:
	free(baton->poll_handle);
err_free_context:
	free(baton);
error:
	fprintf(stderr, "Error: create_curl_context(): ");
	if (uv_result) fprintf(stderr, "%s", uv_strerror(uv_result));
	fprintf(stderr, "\n");

	return NULL;
}

static void
destroy_socket_baton(curl_socket_baton_t *baton)
{
	uv_close((uv_handle_t *)baton->poll_handle, curl_close_socket_baton_cb);
}

static int
handle_socket(CURL *easy, curl_socket_t s, int what, void *userp, void *socketp)
{
	curl_context_t *curl_context = (curl_context_t *)userp;
	curl_socket_baton_t *baton = (curl_socket_baton_t *)socketp;
	int events = 0;

	switch(what)
	{
	case CURL_POLL_IN:
	case CURL_POLL_OUT:
	case CURL_POLL_INOUT:
		baton = socketp ? (curl_socket_baton_t *)socketp : create_curl_socket_baton(s, curl_context->loop);
		baton->main_context = curl_context;

		curl_multi_assign(curl_context->curl_multi, s, (void *)baton);

		if (what != CURL_POLL_IN) events |= UV_WRITABLE;
		if (what != CURL_POLL_OUT) events |= UV_READABLE;

		uv_poll_start(baton->poll_handle, events, curl_perform);
		break;
	case CURL_POLL_REMOVE:
		if (socketp)
		{
			uv_poll_stop(baton->poll_handle);
			destroy_socket_baton(baton);
			curl_multi_assign(curl_context->curl_multi, s, NULL);
		}
		break;
	default:
		assert(false);
	}

	return 0;

	/*int uv_result = 0;

	CURLMcode multi_result = CURLM_OK;
	CURLcode easy_result = CURLE_OK;

	// userp contains a curl_context_t, socketp contains curl_socket_baton_t
	curl_context_t *ctx = (curl_context_t *)userp;
	curl_socket_baton_t *socket_ctx = (curl_socket_baton_t *)socketp;

	if (CURL_POLL_IN == what || CURL_POLL_OUT == what)
	{
		// Initialize socket context if it doesn't exist
		if (NULL == socket_ctx)
		{
			socket_ctx = create_curl_socket_baton(s, ctx->loop);
			if (NULL == socket_ctx) goto error;
			socket_ctx->main_context = ctx;

			// Store socket context
			multi_result = curl_multi_assign(ctx->curl_multi, s, (void *)socket_ctx);
			if (CURLM_OK != multi_result) goto err_release_socket;
		}
	}

	switch (what)
	{
		case CURL_POLL_IN:
			uv_result = uv_poll_start(socket_ctx->poll_handle, UV_READABLE, curl_perform);
			if (0 > uv_result) goto error;
			break;
		case CURL_POLL_OUT:
			uv_result = uv_poll_start(socket_ctx->poll_handle, UV_WRITABLE, curl_perform);
			if (0 > uv_result) goto error;
			break;
		case CURL_POLL_REMOVE:
			// Release socket context
			if (socket_ctx)
			{
				uv_result = uv_poll_stop(socket_ctx->poll_handle);
				if (0 > uv_result) goto err_release_socket_ctx;

				multi_result = curl_multi_assign(ctx->curl_multi, s, NULL);
				if (CURLM_OK != multi_result) goto error;

				/*char *done_url = NULL;
				// Do not free done_url
				easy_result = curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &done_url);
				fprintf(stderr, "Removing handle for: %s\n", done_url);

				// TODO: Ensure this is correct. Should I remove the handle later?
				multi_result = curl_multi_remove_handle(ctx->curl_multi, easy);
				if (CURLM_OK != multi_result) goto error;

				destroy_socket_baton(socket_ctx);
			}
			break;
		default:
			// No other valid options
			assert(false);
	}

	return 0;

err_release_socket:
	// This requires the socket_ctx to be released in a callback, instead of
	// immediately
	uv_close((uv_handle_t *)&socket_ctx->poll_handle, curl_close_curl_context_cb);
	goto error;
err_release_socket_ctx:
	destroy_socket_baton(socket_ctx);
	multi_result = curl_multi_assign(ctx->curl_multi, s, NULL);
	assert(CURLM_OK == multi_result);
error:
	fprintf(stderr, "Error: handle_socket(): ");
	if (0 > uv_result) fprintf(stderr, "%s", uv_strerror(uv_result));
	if (CURLM_OK != multi_result) fprintf(stderr, "%s", curl_multi_strerror(multi_result));
	fprintf(stderr, "\n");
	return -1;*/
}

curl_context_t *
setup_curl_multi_handle(uv_loop_t *loop)
{
	CURLM *curl_handle;
	CURLMcode err;

	curl_context_t *curl_ctx = NULL;

	assert(loop);

	curl_handle = curl_multi_init();
	if (curl_handle)
	{
		curl_ctx = create_curl_context(loop);
		if (NULL == curl_ctx) goto error;

		curl_ctx->curl_multi = curl_handle;
		err = curl_multi_setopt(curl_handle, CURLMOPT_SOCKETDATA, curl_ctx);
		if (CURLM_OK != err) goto err_free_ctx;

		err = curl_multi_setopt(curl_handle, CURLMOPT_SOCKETFUNCTION, handle_socket);
		if (CURLM_OK != err) goto err_free_ctx;

		err = curl_multi_setopt(curl_handle, CURLMOPT_TIMERDATA, curl_ctx);
		if (CURLM_OK != err) goto err_free_ctx;

		err = curl_multi_setopt(curl_handle, CURLMOPT_TIMERFUNCTION, start_timeout);
		if (CURLM_OK != err) goto err_free_ctx;

		return curl_ctx;
	}

	goto error;

err_free_ctx:
	destroy_curl_context(curl_ctx);
error:
	curl_multi_cleanup(curl_handle);

	fprintf(stderr, "Error: setup_fetch_handle(): ");
	if (CURLM_OK != err) fprintf(stderr, "%s", curl_multi_strerror(err));
	fprintf(stderr, "\n");

	return NULL;
}

void
cleanup_fetch_handle(CURLM *multi_handle)
{
	assert(multi_handle);

	curl_multi_cleanup(multi_handle);
}
