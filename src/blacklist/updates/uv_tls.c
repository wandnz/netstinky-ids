/*
 * uv_tls.c
 *
 *  Created on: Jul 18, 2019
 *      Author: mfletche
 */

/*
 * libuv_tls.h
 *
 *  Created on: Jul 18, 2019
 *      Author: mfletche
 */

#include <assert.h>
#include <string.h>
#include <openssl/bio.h>

#include "uv_tls.h"

int
tls_stream_init(tls_stream_t *stream, uv_loop_t *loop, SSL_CTX *ctx)
{
	int uv_rc;
	int bio_rc;

	// default error code if going to the fail label
	int err_ret = TLS_STR_FAIL;

	if (!stream || !loop || !ctx) return TLS_STR_FAIL;

	memset(stream, 0, sizeof(*stream));

	stream->ssl = SSL_new(ctx);
	if (!stream->ssl) return TLS_STR_FAIL;

	bio_rc = BIO_new_bio_pair(&stream->internal, 0, &stream->network, 0);
	if (1 != bio_rc) goto fail;

	SSL_set_bio(stream->ssl, stream->network, stream->network);

	uv_rc = uv_tcp_init(loop, &stream->tcp);
	if (uv_rc < 0)
	{
		err_ret = TLS_STR_NEED_CLOSE;
		goto fail;
	}

	stream->tcp.data = stream;

	return TLS_STR_OK;

fail:
	if (stream->internal) BIO_free(stream->internal);
	if (stream->network) BIO_free(stream->network);
	if (stream->ssl) SSL_free(stream->ssl);
	return err_ret;
}

int
tls_stream_fini(tls_stream_t *stream)
{
	int bio_rc;
	int ret = TLS_STR_OK;

	bio_rc = BIO_free(stream->internal);
	if (1 != bio_rc) ret = TLS_STR_FAIL;

	bio_rc = BIO_free(stream->network);
	if (1 != bio_rc) ret = TLS_STR_FAIL;

	SSL_free(stream->ssl);

	return ret;
}

int
tls_stream_bind(tls_stream_t *stream, const struct sockaddr *addr,
		unsigned int flags)
{
	int uv_rc;

	uv_rc = uv_tcp_bind(&stream->tcp, addr, flags);
	if (uv_rc < 0) return TLS_STR_FAIL;

	return TLS_STR_OK;
}

/**
 * Read pending data from the BIO and send it using libuv.
 */
static int
tls_stream_send_pending(tls_stream_t *stream, uv_write_cb cb)
{
	int pending, read, uv_rc;
	uv_buf_t buf = {.base = NULL, .len = 0};
	uv_write_t *req = NULL;
	int ret = TLS_STR_FAIL;

	if (!stream) return TLS_STR_FAIL;

	pending = BIO_pending(stream->internal);
	if (pending <= 0) return TLS_STR_FAIL;

	buf.base = malloc(pending);
	if (!buf.base)
	{
		ret = TLS_STR_MEM;
		goto fail;
	}
	buf.len = pending;

	read = BIO_read(stream->internal, buf.base, buf.len);
	if (read != pending) goto fail;

	req = malloc(sizeof(*req));
	if (!req)
	{
		ret = TLS_STR_MEM;
		goto fail;
	}

	req->data = stream;
	uv_rc = uv_write(req, (uv_stream_t *)&stream->tcp, &buf, 1, cb);
	if (uv_rc) goto fail;

	return TLS_STR_OK;

fail:
	if (req) free(req);
	if (buf.base) free(buf.base);
	return ret;
}

/**
 * Notify user if handshake write was unsuccessful, or when it is completed.
 * There will be some intermediate writes which will not trigger a call to the
 * user callback when they are successful.
 */
static void
tls_stream_handshake_write_cb(uv_write_t *req, int status)
{
	tls_stream_t *stream = NULL;

	stream = req->data;

	// Notify user of failure
	if (status) stream->on_handshake(stream, status);

	// Check if finished, then notify user of success
	if (SSL_is_init_finished(stream->ssl)) stream->on_handshake(stream, status);

	free(req);

}

/**
 * Return value must be checked carefully.
 * -1 -- Error occurred
 * 0 -- Success, handshake finished
 * 1 -- Success, but handshake must continue
 */
static int
tls_stream_do_handshake(tls_stream_t *stream)
{
	int ssl_rc, rc;
	int ssl_err;

	int ret;	// return code from this function

	// Because we are not blocking we need to check the return code even in
	// case of error, because it might be expected behaviour.
	ssl_rc = SSL_do_handshake(stream->ssl);
	ssl_err = SSL_get_error(stream->ssl, ssl_rc);

	/*
	 * SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE mean that the handshake
	 * hasn't failed but must continue after a new read or write.
	 */
	if (SSL_ERROR_NONE == ssl_err)
		ret = TLS_STR_OK;
	else if (SSL_ERROR_WANT_READ == ssl_err || SSL_ERROR_WANT_WRITE == ssl_err)
		ret = TLS_STR_HANDSHAKE_INCOMPLETE;
	else
		return TLS_STR_FAIL;

	rc = tls_stream_send_pending(stream, tls_stream_handshake_write_cb);
	if (rc) return TLS_STR_FAIL;

	// Return either TLS_STR_OK or TLS_STR_HANDSHAKE_INCOMPLETE
	return ret;
}

static int
tls_stream_check_handshake(tls_stream_t *stream)
{
	int handshake_rc;
	int send_rc;

	// Do handshake if still required
	if (0 == SSL_is_init_finished(stream->ssl))
	{
		handshake_rc = tls_stream_do_handshake(stream);
		if (TLS_STR_OK == handshake_rc
				|| TLS_STR_HANDSHAKE_INCOMPLETE == handshake_rc)
		{
			send_rc = tls_stream_send_pending(stream,
					tls_stream_handshake_write_cb);
			if (TLS_STR_OK != send_rc)
			{
				stream->on_handshake(stream, send_rc);
				return send_rc;
			}
		}
		else
		{
			// handshake operation failed
			stream->on_handshake(stream, handshake_rc);
		}
	}

	return handshake_rc;
}

/**
 * BIO_write must have already been used to write the latest data into the BIO
 * device. That function is not contained in this function because it needs to
 * be run prior to handshaking, too.
 *
 * Puts the decrypted data that is contained in the BIO into the decrypted
 * variable.
 */
static int
tls_stream_decrypt_data(tls_stream_t *stream, uv_buf_t *decrypted)
{
	int pending, nread;
	if (!stream || !decrypted) return TLS_STR_FAIL;

	memset(&decrypted, 0, sizeof(decrypted));
	pending = SSL_pending(stream->ssl);

	// TODO: Should I create a new error code for "no data available"?
	if (!pending) return TLS_STR_FAIL;

	// Create new buffer for decrypted data.
	decrypted->base = malloc(pending);
	decrypted->len = pending;
	nread = SSL_read(stream->ssl, decrypted, pending);

	if (nread != pending)
	{
		free(decrypted->base);
		decrypted->len = 0;
		return TLS_STR_FAIL;
	}

	return TLS_STR_OK;
}

/**
 * This occurs when TLS data is received from the stream. This data must be
 * decoded before being passed to the user.
 */
static void
tls_stream_on_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
	tls_stream_t *tls = NULL;
	int nwrite;
	int decrypt_rc;
	int handshake_rc;
	uv_buf_t decrypted;

	if (!stream) return;
	tls = stream->data;

	// If an error occured, there is no data to decrypt, so send as is.
	if (nread <= 0)
	{
		tls->on_read(tls, nread, buf);
		return;
	}

	nwrite = BIO_write(tls->internal, buf->base, nread);

	// Encrypted buffer is no longer needed
	free(buf->base);

	handshake_rc = tls_stream_check_handshake(tls);
	// Handshake callback will be used for handshake error so just return if
	// error occurred.
	if (handshake_rc != TLS_STR_OK) return;

	assert(nwrite == nread);
	if (nwrite != nread)
	{
		// TODO: This will currently return a freed buffer and nread could be
		// larger than 0. So protected with an assert for now, as I don't know
		// quite how to handle this.
		tls->on_read(tls, nread, &decrypted);
		return;
	}

	// Decrypt
	decrypt_rc = tls_stream_decrypt_data(tls, &decrypted);
	if (TLS_STR_OK != decrypt_rc)
	{
		tls->on_read(tls, decrypt_rc, &decrypted);
		return;
	}

	// Send back to main program
	if (tls->on_read) tls->on_read(tls, TLS_STR_OK, &decrypted);
	return;
}

static void
tls_stream_connect_cb(uv_connect_t *req, int status)
{
	int rc;
	tls_stream_t *stream;

	if (!req) return;

	stream = req->data;

	if (!status)
	{
		// Reading must start immediately so that the handshake can occur
		SSL_set_connect_state(stream->ssl);
		rc = tls_stream_read_start(stream, tls_stream_on_read_cb);
	}

	if (status || rc < 0)
		if (stream->on_handshake) stream->on_handshake(stream, TLS_STR_FAIL);
}

int
tls_stream_connect(tls_stream_t *stream, const struct sockaddr *addr,
		tls_str_handshake_cb handshake_cb, tls_str_read_cb read_cb)
{
	uv_connect_t *req = NULL;
	int uv_rc;

	if (!stream || !addr) return TLS_STR_FAIL;

	stream->on_handshake = handshake_cb;
	stream->on_read = read_cb;

	req = malloc(sizeof(*req));
	if (!req) return TLS_STR_MEM;

	req->data = stream;
	uv_rc = uv_tcp_connect(req, &stream->tcp, addr, tls_stream_connect_cb);
	if (uv_rc) return TLS_STR_FAIL;

	return TLS_STR_OK;
}

/**
 * Called when tcp shutdown operation has completed. This is the final stage
 * of the shutdown process.
 */
static void
tls_stream_tcp_shutdown_cb(uv_shutdown_t *req, int status)
{
	tls_stream_t *stream = NULL;
	int rc;

	if (!req) return;

	stream = req->data;
	free(req);

	if (status < 0)
		rc = TLS_STR_FAIL;
	else
		rc = TLS_STR_OK;

	// Notify user of result
	stream->on_shutdown(stream, rc);
}

/**
 * Helper function for use in tls_stream_shutdown().
 * Shutsdown the tcp stream in the tls_stream_t. Uses the
 * tls_stream_tcp_shutdown_cb.
 * @param stream The stream to shutdown the tcp handle.
 * @returns TLS_STR_OK if successful.
 */
static int
tls_stream_shutdown_tcp(tls_stream_t *stream)
{
	uv_shutdown_t *req = NULL;
	int rc;

	if (!stream) return TLS_STR_FAIL;

	req = malloc(sizeof(*req));
	if (!req) return TLS_STR_MEM;

	req->data = stream;
	rc = uv_shutdown(req, (uv_stream_t *)&stream->tcp, tls_stream_tcp_shutdown_cb);
	if (rc < 0)
	{
		free(req);
		return TLS_STR_FAIL;
	}

	return TLS_STR_OK;
}

/**
 * The SSL shutdown write is complete.
 */
static void
tls_stream_ssl_shutdown_write_cb(uv_write_t *req, int status)
{
	tls_stream_t *stream = NULL;
	int shutdown_rc;

	if (!req) return;

	stream = req->data;
	free(req);

	// Status doesn't really matter, as if write failed we'll shutdown the
	// tcp handle anyway
	shutdown_rc = tls_stream_shutdown_tcp(stream);
	if (shutdown_rc != TLS_STR_OK)
	{
		stream->on_shutdown(stream, shutdown_rc);
	}
}

int
tls_stream_shutdown(tls_stream_t *stream, tls_str_shutdown_cb cb)
{
	int shutdown_rc, send_rc;

	if (!stream) return TLS_STR_FAIL;

	stream->on_shutdown = cb;

	// TODO: I do not perform a bidirectional shutdown as it doesn't look like
	// it is required by the standard. Double check.
	shutdown_rc = SSL_shutdown(stream->ssl);
	if (shutdown_rc < 0)
	{
		// Error shutting down SSL, immediately shutdown tcp handle
		shutdown_rc = tls_stream_shutdown_tcp(stream);
		return shutdown_rc;
	}

	send_rc = tls_stream_send_pending(stream, tls_stream_ssl_shutdown_write_cb);
	if (send_rc != TLS_STR_OK)
	{
		shutdown_rc = tls_stream_shutdown_tcp(stream);
		return shutdown_rc;
	}

	return TLS_STR_OK;
}

int
tls_stream_listen(tls_stream_t *stream, int backlog, uv_connection_cb cb)
{
	return -1;
}

int
tls_stream_accept(tls_stream_t *server, tls_stream_t *client, uv_read_cb cb)
{
	return -1;
}

/**
 * Allocation function for buffers. Almost exactly the same as example
 * allocation function example from libuv documentation.
 * @param handle: The handle that will be receiving data.
 * @param suggested_size: A suggested size for the new memory allocation.
 * @param buf: The buf structure to contain the new memory and length.
 */
static void
tls_stream_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
	buf->len = 0;
	buf->base = malloc(suggested_size);
	if (buf->base)
		buf->len = suggested_size;
}

/**
 * Deallocate the buffer. Since the allocation method is a static method within
 * this module, this deallocation function must be provided to the user.
 * @param buf: The buffer to free.
 */
void
tls_stream_dealloc(uv_buf_t *buf)
{
	if (!buf) return;

	if (buf->base)
		free(buf->base);
	buf->len = 0;
}

int
tls_stream_read_start(tls_stream_t *stream, uv_read_cb cb)
{
	int rc;
	if (!stream) return TLS_STR_FAIL;

	rc = uv_read_start((uv_stream_t *)&stream->tcp, tls_stream_alloc_cb, cb);
	if (0 != rc) return TLS_STR_FAIL;
	return TLS_STR_OK;
}

int
tls_stream_read_stop(tls_stream_t *stream)
{
	int rc;

	if (!stream) return TLS_STR_FAIL;

	rc = uv_read_stop((uv_stream_t *)&stream->tcp);
	if (0 != rc) return TLS_STR_FAIL;

	return TLS_STR_OK;
}

/**
 * Encrypts a buffer. The result might be contained in multiple
 * uv_buf_t's depending on the buffer size of the BIO.
 */
static int
tls_stream_encrypt_buffer(tls_stream_t *stream, const uv_buf_t *buf,
		uv_buf_t **encrypted, unsigned int *nbufs)
{
	int rc, i;
	int bytes_written = 0;
	int written = 0;

	uv_buf_t *buf_array = NULL;
	unsigned int array_len = 0;

	unsigned int req_bufs;
	void *alloced = NULL;

	int pending;

	if (!stream || !buf) return TLS_STR_FAIL;

	// Write chunks of uv_buffer into SSL_buffer
	while (bytes_written < buf->len)
	{
		written = SSL_write(stream->ssl, buf->base + bytes_written,
				buf->len - bytes_written);
		if (written <= 0) break;

		// Create array of uv_buf_t
		req_bufs = array_len + 1;
		alloced = realloc(buf_array, req_bufs * sizeof(*buf_array));
		if (alloced)
		{
			array_len += 1;

			// Zero last uv_buf_t
			buf_array[array_len - 1].base = NULL;
			buf_array[array_len - 1].len = 0;

			buf_array = alloced;
			pending = BIO_pending(stream->internal);
			buf_array[array_len - 1].base = malloc(pending);
			if (NULL == buf_array[array_len - 1].base)
				goto error;
			rc = BIO_read(stream->internal, buf_array[array_len - 1].base,
					buf_array[array_len - 1].len);
			if (rc < pending) goto error;
		}
	}

	*encrypted = buf_array;
	*nbufs = array_len;

	return TLS_STR_OK;

error:
	// Free up array
	if (buf_array)
	{
		for (i = 0; i < array_len; i++)
		{
			if (buf_array[array_len].base)
				free(buf_array[array_len].base);
		}
		free(buf_array);
	}

	*encrypted = NULL;
	*nbufs = 0;
	return TLS_STR_MEM;
}

/*static int
tls_stream_write_buffer(tls_stream_t *stream, const uv_buf_t *buf,
		uv_write_cb cb)
{
	int total_written = 0;
	int written = 0;
	int rc;
	int ret = TLS_STR_FAIL;
	uv_write_t *req = NULL;
	uv_buf_t *buf_array = NULL;
	unsigned int array_len = 0;


	if (!stream || !buf) return TLS_STR_FAIL;

	rc = tls_stream_encrypt_buffer(stream, buf, &buf_array, &array_len);
	if (TLS_STR_OK != rc) return rc;

	req = malloc(sizeof(*req));
	if (!req)
	{
		ret = TLS_STR_MEM;
		goto error;
	}
	rc = uv_write(stream->tcp, buf_array, array_len, cb);
	if (rc < 0) goto error;

	// The array doesn't need to be kept
	free(buf_array);

	return TLS_STR_OK;

error:
	if (buf_array) free(buf_array);
	if (req) free(req);
	return ret;
}*/

/**
 * Encrypt an array of buffers and add it to the ENCRYPTED array of buffers.
 * Will realloc ENCRYPTED and update NENCRYPTED as necessary.
 *
 * There may be more encrypted buffers than unencrypted buffers, which is why
 * this cannot encrypt them in place. This can occur if the buffer size is
 * larger than the BIO buffer size within the tls_stream.
 */
static int
tls_stream_encrypt_buffers(tls_stream_t *stream, const uv_buf_t bufs[],
		unsigned int nbufs, uv_buf_t **encrypted,
		unsigned int *nencrypted)
{
	int rc;
	unsigned int buf_idx;
	int ret = TLS_STR_OK;	// Return code from this function

	// Results from tls_stream_encrypt_buffer before they are added to the
	// output array
	uv_buf_t *temp_encrypted;
	unsigned int temp_nencrypted;
	uv_buf_t *temp_alloc = NULL;

	if (!stream || !bufs || !encrypted || !nencrypted) return TLS_STR_FAIL;

	for (buf_idx = 0; buf_idx < nbufs; buf_idx++)
	{
		rc = tls_stream_encrypt_buffer(stream, &bufs[buf_idx], &temp_encrypted,
				&temp_nencrypted);
		if (rc != TLS_STR_OK)
		{
			ret = rc;
			goto error;
		}

		// Reallocate enough space for the new encrypted buffers
		temp_alloc = realloc(*encrypted,
				(*nencrypted + temp_nencrypted) * sizeof(bufs[0]));
		if (!temp_alloc)
		{
			ret = TLS_STR_MEM;
			goto error;
		}

		// Copy new buffers into main array of buffers
		*encrypted = temp_alloc;
		memcpy(*encrypted + *nencrypted, temp_encrypted,
				temp_nencrypted * sizeof(*temp_encrypted));
		free(temp_encrypted);
		temp_encrypted = NULL;
		temp_nencrypted = 0;
	}

	return TLS_STR_OK;

error:
	if (*encrypted) free(*encrypted);
	*encrypted = NULL;
	*nencrypted = 0;
	if (temp_encrypted) free(temp_encrypted);

	return ret;
}

int
tls_stream_write(tls_stream_t *stream, const uv_buf_t bufs[],
		unsigned int nbufs, uv_write_cb cb)
{
	int rc;
	int ret = TLS_STR_OK;

	uv_write_t *req = NULL;
	uv_buf_t *encrypted = NULL;
	unsigned int nencrypted = 0;

	if (!stream || !bufs) return TLS_STR_FAIL;

	rc = tls_stream_encrypt_buffers(stream, bufs, nbufs, &encrypted,
			&nencrypted);
	if (TLS_STR_OK != rc)
		return rc;

	req = malloc(sizeof(*req));
	if (!req)
	{
		rc = TLS_STR_MEM;
		goto final;
	}

	rc = uv_write(req, (uv_stream_t *)&stream->tcp, encrypted, nencrypted, cb);
	if (rc < 0) ret = TLS_STR_FAIL;

final:
	if (encrypted) free(encrypted);
	return ret;
}

/**
 * Callback that is run when a handle has been closed using tls_stream_close().
 */
static void
tls_stream_close_close_cb(uv_handle_t *handle)
{
	tls_stream_t *stream;

	if (!handle) return;

	stream = handle->data;

	// Notify user that stream is closed
	if (stream->on_close) stream->on_close(stream);
}

/**
 * Callback that is run when a stream has been closed using
 * tls_stream_close(). This is an intermediate stage before the tcp handle has
 * been closed.
 */
static void
tls_stream_close_shutdown_cb(uv_shutdown_t *req, int status)
{
	uv_stream_t *handle = NULL;

	if (!req) return;

	handle = req->handle;

	free(req);

	uv_close((uv_handle_t *)handle, tls_stream_close_close_cb);
}

int
tls_stream_close(tls_stream_t *stream, tls_str_close_cb cb)
{
	int uv_rc, shutdown_rc;
	uv_shutdown_t *req = NULL;

	if (!stream) return TLS_STR_FAIL;

	stream->on_close = cb;

	// tcp
	uv_rc = uv_read_stop((uv_stream_t *)&stream->tcp);
	req = malloc(sizeof(*req));
	if (req)
	{
		req->data = stream;
		shutdown_rc = uv_shutdown(req, (uv_stream_t *)&stream->tcp,
				tls_stream_close_shutdown_cb);
		if (uv_rc < 0) free(req);
	}
	// Immediately close if request couldn't be allocated or shutdown was
	// unsuccessful
	if (!req || shutdown_rc < 0)
		uv_close((uv_handle_t *)&stream->tcp, tls_stream_close_close_cb);

	return TLS_STR_OK;
}
