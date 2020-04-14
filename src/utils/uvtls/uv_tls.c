/*
 *
 * Copyright (c) 2020 The University of Waikato, Hamilton, New Zealand.
 *
 * This file is part of netstinky-ids.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-2-Clause
 *
 *
 */
#include <config.h>

#include <assert.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "utils/logging.h"
#include "uv_tls.h"

/**
 * When decrypting data, the SSL_pending() function cannot be relied upon when
 * allocating a size. This is the size of the buffer that will be allocated.
 */
static const size_t DEFAULT_BUF_SZ = 65535;

/** FORWARD DECLARATIONS FOR STATIC FUNCTIONS **/

static int
buf_array_append(buf_array_t *array, uv_buf_t *buf);

static int
buf_array_concatenate(buf_array_t *restrict result,
        const buf_array_t *restrict first,
        const buf_array_t *restrict second);

static void
buf_array_free_all_buffers(buf_array_t *array);

static int
buf_array_wrap(buf_array_t *result, const uv_buf_t *bufs, unsigned int nbufs);

static void fini_buf_array(buf_array_t *array);

static void
free_write_cb_data(write_cb_data_t *data);

static int
init_buf_array(buf_array_t *array);

static write_cb_data_t *
new_write_cb_data(tls_stream_t *stream, buf_array_t *plaintext,
        buf_array_t *encrypted, tls_str_write_cb hshake_cb);

static void
tls_stream_write_cb(uv_write_t *req, int status);

static void
tls_stream_close_close_cb(uv_handle_t *handle);

static void
tls_stream_close_err_cb(tls_stream_t *stream);

#ifdef HAVE_SSL_CTX_SET_KEYLOG_CALLBACK
static void
keylog_callback(const SSL *ssl __attribute__((unused)), const char *line)
{
    logger(L_DEBUG, "%s", line);
}
#endif

int
tls_stream_init(tls_stream_t *stream, uv_loop_t *loop, SSL_CTX *ctx)
{
    int uv_rc;
    int bio_rc;

    assert(stream);
    assert(loop);
    assert(ctx);

    // default error code if going to the fail label
    int err_ret = TLS_STR_FAIL;

    memset(stream, 0, sizeof(*stream));

    stream->ssl = SSL_new(ctx);
    if (!stream->ssl) return TLS_STR_FAIL;

    bio_rc = BIO_new_bio_pair(&stream->internal, 0, &stream->network, 0);
    if (1 != bio_rc) goto fail;

    SSL_set_bio(stream->ssl, stream->network, stream->network);
#ifdef HAVE_SSL_CTX_SET_KEYLOG_CALLBACK
    SSL_CTX_set_keylog_callback(ctx, keylog_callback);
#endif

    uv_rc = uv_tcp_init(loop, &stream->tcp);
    if (uv_rc < 0)
    {
        // Begin to close the stream, but warn user not to free it
        logger(L_ERROR, "Could not establish a TCP stream: %s",
                uv_strerror(uv_rc));
        err_ret = TLS_STR_NEED_CLOSE;
        stream->tcp.data = stream;
        tls_stream_close(stream, tls_stream_close_err_cb);
        goto fail;
    }

    stream->tcp.data = stream;
    stream->handshake_complete = 0;

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
    int ret = TLS_STR_OK;

    // One of the BIOs is freed implicitly by SSL_free
    SSL_free(stream->ssl);
    BIO_free(stream->internal);

    memset(stream, 0, sizeof(*stream));

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
 * Read encrypted data which is yet to be sent from the stream buffers.
 * This function may succeed but return a buffer with a NULL base and a 0
 * length if there is no pending data.
 */
static int
tls_stream_read_pending(uv_buf_t *buf, tls_stream_t *stream)
{
    int pending, nread;

    if (!buf || !stream) return TLS_STR_FAIL;

    // Default value is NULL buf with 0 len.
    memset(buf, 0, sizeof(*buf));

    pending = BIO_pending(stream->internal);
    if (!pending) return TLS_STR_OK;
    if (pending < 0) return TLS_STR_FAIL;

    buf->base = malloc(pending);
    if (!buf->base) return TLS_STR_MEM;

    nread = BIO_read(stream->internal, buf->base, pending);
    if (nread < pending)
    {
        // Read failed, undo all changes
        free(buf->base);
        return TLS_STR_FAIL;
    }

    buf->len = pending;
    return TLS_STR_OK;
}

/**
 * Read pending data from the BIO and send it using libuv.
 */
static int
tls_stream_send_pending(tls_stream_t *stream, tls_str_write_cb cb)
{
    int pending, read, uv_rc, rc;
    uv_buf_t buf = {.base = NULL, .len = 0};
    buf_array_t array;
    uv_write_t *req = NULL;
    write_cb_data_t *data = NULL;
    int ret = TLS_STR_FAIL;

    if (!stream) return TLS_STR_FAIL;

    pending = BIO_pending(stream->internal);
    if (pending <= 0) return TLS_STR_OK;

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

    rc = buf_array_wrap(&array, &buf, 1);
    if (rc)
    {
        ret = rc;
        goto fail;
    }

    // No plaintext buffers
    data = new_write_cb_data(stream, NULL, &array, cb);
    if (!data) goto fail;

    req->data = data;
    uv_rc = uv_write(req, (uv_stream_t *)&stream->tcp, array.bufs, array.nbufs, tls_stream_write_cb);
    if (uv_rc) goto fail;

    return TLS_STR_OK;

fail:
    // Free all allocated variables
    if (data) free_write_cb_data(data);
    fini_buf_array(&array);
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
tls_stream_handshake_write_cb(tls_stream_t *stream, int status, uv_buf_t *buf,
        unsigned int nbufs)
{
    // There should be no plaintext buffers for handshake writes
    assert(!buf);
    assert(!nbufs);

    /**
     * It is possible that the handshake callback will be called twice. This is
     * if this endpoint was responsible for the last write. Once that is
     * started, the OpenSSL library will return 1 for SSL_is_init_finished even
     * if the write is going to fail.
     *
     * If the write then fails, the handshake callback will be called again.
     * The user should shutdown the stream if an error occurs.
     */
    if (status)
    {
        stream->on_handshake(stream, status);
        stream->handshake_complete = 1;
    }

    // Check if finished, then notify user of success
    if (SSL_is_init_finished(stream->ssl) && !stream->handshake_complete)
    {
        stream->on_handshake(stream, status);
        stream->handshake_complete = 1;
    }
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
    else if (SSL_ERROR_WANT_READ == ssl_err)
    {
        // Don't send anything
        ret = TLS_STR_HANDSHAKE_INCOMPLETE;
    }
    else if (SSL_ERROR_WANT_WRITE == ssl_err)
    {
        // Continue through to sending data
        ret = TLS_STR_HANDSHAKE_INCOMPLETE;
    }
    else
    {
        unsigned long err;
        while( (err = ERR_get_error()) != 0)
        {
            tls_stream_print_err(stderr, err);
        }
        return TLS_STR_FAIL;
    }

    rc = tls_stream_send_pending(stream, tls_stream_handshake_write_cb);
    if (rc) return TLS_STR_FAIL;

    // Return either TLS_STR_OK or TLS_STR_HANDSHAKE_INCOMPLETE
    return ret;
}

static int
tls_stream_check_handshake(tls_stream_t *stream)
{
    int handshake_rc;

    // Do handshake if still required
    if (0 == SSL_is_init_finished(stream->ssl))
    {
        handshake_rc = tls_stream_do_handshake(stream);
        if (TLS_STR_OK == handshake_rc && !stream->handshake_complete)
        {
            stream->on_handshake(stream, handshake_rc);
            stream->handshake_complete = 1;
        }
        else if (TLS_STR_HANDSHAKE_INCOMPLETE != handshake_rc && !stream->handshake_complete)
        {
            // handshake operation failed
            stream->on_handshake(stream, handshake_rc);
            stream->handshake_complete = 1;
        }
    }
    else
    {
        handshake_rc = TLS_STR_OK;
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
    int nread, ssl_err;
    if (!stream || !decrypted) return TLS_STR_FAIL;

    memset(decrypted, 0, sizeof(*decrypted));

    /**
     * Do not use SSL_pending to determine if there is data to be read in this
     * function. It often returns 0 even if SSL_read successfully reads bytes.
     */

    // Create new buffer for decrypted data.
    decrypted->base = malloc(DEFAULT_BUF_SZ);
    nread = SSL_read(stream->ssl, decrypted->base, DEFAULT_BUF_SZ);
    if (nread < 0)
    {
        decrypted->len = 0;
        free(decrypted->base);
        decrypted->base = NULL;
    }
    else decrypted->len = nread;

    ssl_err = SSL_get_error(stream->ssl, nread);
    if (ssl_err != 0 && ssl_err != 2) return TLS_STR_FAIL;

    return TLS_STR_OK;
}

static int
tls_stream_decrypt_buffer(uv_buf_t *decrypted, tls_stream_t *stream, ssize_t nread,
        const uv_buf_t *buf)
{
    // total_written keeps a running total in case multiple writes to the
    // buffer are required
    int total_written = 0;
    int nwrite, rc;
    uv_buf_t temp_buf;
    char *temp_alloc;
    int ret = TLS_STR_FAIL;

    if (!decrypted || !stream || nread < 0 || !buf) return TLS_STR_FAIL;

    // This buffer will be the buffer returned
    decrypted->base = NULL;
    decrypted->len = 0;
    temp_buf.base = NULL;
    temp_buf.len = 0;

    while (total_written < nread)
    {
        nwrite = BIO_write(stream->internal, buf->base + total_written,
                nread - total_written);
        if (nwrite <= 0) goto error;

        total_written += nwrite;

        if (!SSL_is_init_finished(stream->ssl))
        {
            // If error occurs in handshake, on_handshake_cb will be called

            // Ignore return value, as we only care about the side-effects of
            // running the on_handshake callbacks
            tls_stream_check_handshake(stream);
        }

        rc = tls_stream_decrypt_data(stream, &temp_buf);
        if (TLS_STR_OK != rc)
        {
            ret = rc;
            goto error;
        }

        // Concatenate onto end of decrypted buff
        if (temp_buf.len > 0)
        {
            temp_alloc = realloc(decrypted->base, decrypted->len + temp_buf.len);
            if (!temp_alloc)
            {
                ret = TLS_STR_MEM;
                goto error;
            }
            decrypted->base = temp_alloc;
            memcpy(decrypted->base + decrypted->len, temp_buf.base, temp_buf.len);
            decrypted->len = decrypted->len + temp_buf.len;
            free(temp_buf.base);
            temp_buf.base = NULL;	// Helps error section know if needs freeing
        }
    }

    return TLS_STR_OK;

error:
    if (decrypted->base) free(decrypted->base);
    decrypted->base = NULL;
    decrypted->len = 0;

    if (temp_buf.base) free(temp_buf.base);

    return ret;
}

/**
 * This occurs when TLS data is received from the stream. This data must be
 * decoded before being passed to the user.
 */
static void
tls_stream_on_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    tls_stream_t *tls = NULL;
    int decrypt_rc;
    uv_buf_t decrypted;

    if (!stream) return;
    tls = stream->data;

    // If an error occured, there is no data to decrypt, so send as is.
    if (nread < 0)
    {
        tls->on_read(tls, nread, buf);
        return;
    }

    decrypt_rc = tls_stream_decrypt_buffer(&decrypted, tls, nread, buf);
    // We are finished with this buffer now
    free(buf->base);
    if (decrypt_rc == TLS_STR_OK && decrypted.len == 0) return;

    tls->on_read(tls, decrypt_rc, &decrypted);
    return;
}

static void
tls_stream_connect_cb(uv_connect_t *req, int status)
{
    int rc;
    tls_stream_t *stream;

    if (!req) return;

    stream = req->data;
    free(req);

    if (!status)
    {
        // Reading must start immediately so that the handshake can occur
        rc = tls_stream_read_start(stream, tls_stream_on_read_cb);
    }

    if (status || rc < 0)
    {
        if (stream->on_handshake) stream->on_handshake(stream, TLS_STR_FAIL);
        return;
    }

    SSL_set_connect_state(stream->ssl);
    rc = tls_stream_do_handshake(stream);
    if (rc != TLS_STR_OK && rc != TLS_STR_HANDSHAKE_INCOMPLETE)
        stream->on_handshake(stream, rc);
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
    if (stream->on_shutdown) stream->on_shutdown(stream, rc);
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
tls_stream_ssl_shutdown_write_cb(tls_stream_t *stream,
        int status __attribute__((unused)),
        uv_buf_t *bufs, unsigned int nbufs)
{
    int shutdown_rc;
    unsigned int buf_idx;

    if (!stream) return;

    // Free buffers
    if (bufs)
    {
        for (buf_idx = 0; buf_idx < nbufs; buf_idx++)
        {
            if (bufs[buf_idx].base) free(bufs[buf_idx].base);
        }
    }

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
tls_stream_listen(tls_stream_t *stream, int backlog __attribute__((unused)),
                  uv_connection_cb cb)
{
    int rc;

    if (!stream) return -1;

    rc = uv_listen((uv_stream_t *)&stream->tcp, 128, cb);
    if (0 > rc)
        return -1;

    return 0;
}

int
tls_stream_accept(tls_stream_t *server, tls_stream_t *client,
        tls_str_handshake_cb hshake_cb, tls_str_read_cb read_cb)
{
    int rc;

    if (!server || !client || !hshake_cb) return -1;

    // Save callbacks for later
    client->on_handshake = hshake_cb;
    client->on_read = read_cb;

    rc = uv_accept((uv_stream_t *)&server->tcp, (uv_stream_t *)&client->tcp);
    if (rc) return -1;

    SSL_set_accept_state(client->ssl);

    rc = tls_stream_read_start(client, tls_stream_on_read_cb);
    if (rc) return -1;
    rc = tls_stream_do_handshake(client);
    if (rc != TLS_STR_OK && rc != TLS_STR_HANDSHAKE_INCOMPLETE)
        return rc;

    return 0;
}

/**
 * Allocation function for buffers. Almost exactly the same as example
 * allocation function example from libuv documentation.
 * @param handle: The handle that will be receiving data.
 * @param suggested_size: A suggested size for the new memory allocation.
 * @param buf: The buf structure to contain the new memory and length.
 */
static void
tls_stream_alloc_cb(uv_handle_t *handle __attribute__((unused)),
                    size_t suggested_size, uv_buf_t *buf)
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
tls_stream_encrypt_buffer(buf_array_t *encrypted, tls_stream_t *stream,
        const uv_buf_t *plaintext)
{
    int rc;
    unsigned int bytes_written = 0;
    int nwrite;

    uv_buf_t enc_buf;

    if (!encrypted || !stream || !plaintext) return TLS_STR_FAIL;

    rc = init_buf_array(encrypted);
    if (rc) return rc;

    // Write chunks of uv_buffer into SSL_buffer
    while (bytes_written < plaintext->len)
    {
        nwrite = SSL_write(stream->ssl, plaintext->base + bytes_written,
                plaintext->len - bytes_written);
        if (nwrite <= 0) goto error;

        rc = tls_stream_read_pending(&enc_buf, stream);
        if (rc) goto error;

        /* Copy details about the buffer containing newly encrypted data into
         * the buf_array. */
        rc = buf_array_append(encrypted, &enc_buf);
        if (rc) goto error;

        bytes_written += (unsigned int) nwrite;
    }

    return TLS_STR_OK;

error:
    buf_array_free_all_buffers(encrypted);
    fini_buf_array(encrypted);
    return TLS_STR_FAIL;
}

/**
 * Encrypt an array of buffers and add it to the ENCRYPTED array of buffers.
 * Will realloc ENCRYPTED and update NENCRYPTED as necessary.
 *
 * There may be more encrypted buffers than unencrypted buffers, which is why
 * this cannot encrypt them in place. This can occur if the buffer size is
 * larger than the BIO buffer size within the tls_stream.
 */
static int
tls_stream_encrypt_buffers(buf_array_t *result, tls_stream_t *stream, const uv_buf_t bufs[],
        unsigned int nbufs)
{
    unsigned int buf_idx;
    int rc;

    buf_array_t result_array;
    buf_array_t single_encrypted;
    buf_array_t temp;

    if (!stream || !bufs) return TLS_STR_FAIL;

    init_buf_array(&result_array);
    init_buf_array(&single_encrypted);

    /* Encrypt buffers one by one. Each buffer might be split if their size is
     * too large for the BIO buffer. */
    for (buf_idx = 0; buf_idx < nbufs; buf_idx++)
    {
        rc = tls_stream_encrypt_buffer(&single_encrypted, stream, &bufs[buf_idx]);
        if (rc) goto error;

        // Add new array onto the current result array
        rc = init_buf_array(&temp);
        if (rc) goto error;

        // Concatenate COPIES the buffers in the array into a new one. It is
        // safe to finalize result_array and single_encrypted because the bufs
        // still exist.
        rc = buf_array_concatenate(&temp, &result_array, &single_encrypted);
        if (rc) goto error;
        fini_buf_array(&result_array);
        fini_buf_array(&single_encrypted);

        result_array = temp;

        // Don't finalize temp because that will free the memory pointed to by
        // the main result array
    }

    *result = result_array;
    return TLS_STR_OK;

error:
    fini_buf_array(&result_array);
    fini_buf_array(&single_encrypted);
    fini_buf_array(&temp);

    return TLS_STR_FAIL;
}

/**
 * Frees the encrypted buffers now that the write is completed. Calls the
 * user callback so that they can free the plaintext buffers.
 */
static void
tls_stream_write_cb(uv_write_t *req, int status)
{
    write_cb_data_t *usr_data = NULL;

    if (!req) return;

    usr_data = req->data;

    // Free encrypted buffers
    buf_array_free_all_buffers(&usr_data->encrypted);
    fini_buf_array(&usr_data->encrypted);

    // Notify user of write completion
    if (usr_data->cb)
        usr_data->cb(
                usr_data->stream,
                status,
                usr_data->plaintext.bufs,
                usr_data->plaintext.nbufs);

    // Free memory containing the plaintext bufs
    fini_buf_array(&usr_data->plaintext);

    free_write_cb_data(usr_data);
    free(req);
}

int
tls_stream_write(tls_stream_t *stream, const uv_buf_t bufs[],
        unsigned int nbufs, tls_str_write_cb cb)
{
    int rc;
    int ret = TLS_STR_FAIL;

    uv_write_t *req = NULL;
    buf_array_t plaintext;
    buf_array_t encrypted;
    write_cb_data_t *usr_data = NULL;

    if (!stream || !bufs) return TLS_STR_FAIL;

    // Prepare encrypted buffers
    init_buf_array(&plaintext);
    init_buf_array(&encrypted);
    rc = tls_stream_encrypt_buffers(&encrypted, stream, bufs, nbufs);
    if (rc)
    {
        ret = rc;
        goto error;
    }

    // Prepare user data to bundle with the request
    rc = buf_array_wrap(&plaintext, bufs, nbufs);
    if (rc)
    {
        ret = rc;
        goto error;
    }
    usr_data = new_write_cb_data(stream, &plaintext, &encrypted, cb);
    if (!usr_data)
    {
        goto error;
    }

    // Prepare request
    req = malloc(sizeof(*req));
    if (!req)
    {
        ret = TLS_STR_MEM;
        goto error;
    }
    req->data = usr_data;

    // Send
    rc = uv_write(req, (uv_stream_t *)&stream->tcp, usr_data->encrypted.bufs,
            usr_data->encrypted.nbufs, tls_stream_write_cb);
    if (rc) goto error;

    return TLS_STR_OK;

error:
    if (req) free(req);
    if (usr_data) free_write_cb_data(usr_data);

    // Only free encrypted buffers, not plaintext (user can free those)
    buf_array_free_all_buffers(&encrypted);
    fini_buf_array(&encrypted);

    // Do free memory where buffer addresses would have been copied to
    fini_buf_array(&plaintext);

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
    memset(stream, 0, sizeof(*stream));
}

/*
 * Function to run when there was an error setting up the TLS stream
 * Implements type tls_str_close_cb from uv_tls.h
 */
static void
tls_stream_close_err_cb(tls_stream_t *stream)
{
    if (!stream) return;

    // Notify the user that the stream is closed
    if (stream->on_close) stream->on_close(stream);
    memset(stream, 0, sizeof(*stream));
}


/**
 * Callback that is run when a stream has been closed using
 * tls_stream_close(). This is an intermediate stage before the tcp handle has
 * been closed.
 */
static void
tls_stream_close_shutdown_cb(uv_shutdown_t *req,
                             int status __attribute__((unused)))
{
    uv_stream_t *handle = NULL;

    if (!req) return;

    handle = req->handle;

    free(req);

    if (!uv_is_closing((uv_handle_t *)handle))
        uv_close((uv_handle_t *)handle, tls_stream_close_close_cb);
}

int
tls_stream_close(tls_stream_t *stream, tls_str_close_cb cb)
{
    int shutdown_rc;
    uv_shutdown_t *req = NULL;
    const uv_stream_t *tcp_stream;

    if (!stream) return TLS_STR_FAIL;

    stream->on_close = cb;

    // tcp
    tcp_stream = (uv_stream_t *) &stream->tcp;
    uv_read_stop((uv_stream_t *) tcp_stream);
    req = malloc(sizeof(*req));
    if (req)
    {
        req->data = stream;
        shutdown_rc = uv_shutdown(req, (uv_stream_t *) tcp_stream,
                tls_stream_close_shutdown_cb);
        if (shutdown_rc < 0) free(req);
    }
    // Immediately close if request couldn't be allocated or shutdown was
    // unsuccessful
    if (!req || shutdown_rc < 0)
    {
        if (!uv_is_closing((uv_handle_t *) tcp_stream))
        {
            uv_close((uv_handle_t *) tcp_stream, tls_stream_close_close_cb);
        }
    }

    return TLS_STR_OK;
}

static int
init_buf_array(buf_array_t *array)
{
    if (!array) return TLS_STR_FAIL;

    memset(array, 0, sizeof(*array));
    return TLS_STR_OK;
}

/**
 * Initialize a buf_array with existing buffers.
 */
int
buf_array_copy_bufs(buf_array_t *array, uv_buf_t *bufs, unsigned int nbufs)
{
    if (!array || !bufs || !nbufs) return TLS_STR_FAIL;

    memset(array, 0, sizeof(*array));

    array->bufs = malloc(nbufs * sizeof(*bufs));
    if (array->bufs)
    {
        memcpy(array->bufs, bufs, nbufs * sizeof(*bufs));
        array->nbufs = nbufs;
        return TLS_STR_OK;
    }

    return TLS_STR_MEM;
}

/**
 * Free a buf_array_t. Does not free the actual buffers as that is supposed to
 * be the job of the user.
 */
static void fini_buf_array(buf_array_t *array)
{
    if (!array) return;

    if (array->bufs)
        free(array->bufs);

    memset(array, 0, sizeof(*array));
}

/**
 * Append a buffer to the end of the buf_array.
 */
static int
buf_array_append(buf_array_t *array, uv_buf_t *buf)
{
    unsigned int array_len;
    size_t alloc_sz;
    void *new_alloc = NULL;

    if (!array || !buf) return TLS_STR_FAIL;

    /**If this occurs, the buf_array_t may not have been initialized. It's not
     * in a valid state. */
    if (array->nbufs && !array->bufs) return TLS_STR_FAIL;

    // Allocate space for one extra buffer
    array_len = array->nbufs + 1;
    alloc_sz = array_len * sizeof(*buf);
    new_alloc = realloc(array->bufs, alloc_sz);
    if (new_alloc)
    {
        array->bufs = new_alloc;
        array->nbufs = array_len;

        // Copy buffer into last array position
        array->bufs[array_len - 1] = *buf;

        return TLS_STR_OK;
    }

    return TLS_STR_MEM;

}

static void
buf_array_free_all_buffers(buf_array_t *array)
{
    unsigned int idx;

    if (!array || !array->bufs) return;

    for (idx = 0; idx < array->nbufs; idx++)
    {
        if (array->bufs[idx].base) free(array->bufs[idx].base);
        memset(&array->bufs[idx], 0, sizeof(uv_buf_t));
    }
}

/**
 * Concatenate two buf_arrays and put into RESULT. Does not destroy or free
 * either input array.
 */
static int
buf_array_concatenate(buf_array_t *restrict result,
        const buf_array_t *restrict first,
        const buf_array_t *restrict second)
{
    unsigned int nbufs;
    uv_buf_t *new_alloc = NULL;

    if (!result || !first || !second) return TLS_STR_FAIL;

    nbufs = first->nbufs + second->nbufs;
    new_alloc = malloc(nbufs * sizeof(*new_alloc));
    if (!new_alloc) return TLS_STR_MEM;

    memcpy(new_alloc, first->bufs, first->nbufs * sizeof(*first->bufs));
    memcpy(&new_alloc[first->nbufs], second->bufs,
            second->nbufs * sizeof(*second->bufs));

    result->bufs = new_alloc;
    result->nbufs = nbufs;

    return TLS_STR_OK;
}

/**
 * Copy buffer information from an array of existing uv_buf_ts.
 */
static int
buf_array_wrap(buf_array_t *result, const uv_buf_t *bufs, unsigned int nbufs)
{
    uv_buf_t *new_alloc = NULL;

    if (!result || !bufs) return TLS_STR_FAIL;

    new_alloc = malloc(nbufs * sizeof(*bufs));
    if (!new_alloc) return TLS_STR_MEM;

    memcpy(new_alloc, bufs, nbufs * sizeof(*bufs));
    result->bufs = new_alloc;
    result->nbufs = nbufs;

    return TLS_STR_OK;
}

/**
 * Allocate a new memory block for the callback data and copy the address of
 * the stream, and the contents of the buf_array structs.
 *
 * @param stream: The TLS stream that the data is being written to.
 * @param plaintext: Array of buffers containing the plaintext. May be NULL
 * when write is related to the TLS handshake.
 * @param encrypted: Array of buffers containing the encrypted data.
 * @param cb: User callback when write is complete.
 */
static write_cb_data_t *
new_write_cb_data(tls_stream_t *stream, buf_array_t *plaintext,
        buf_array_t *encrypted, tls_str_write_cb hshake_cb)
{
    write_cb_data_t *data = NULL;

    if (!stream || !encrypted || !hshake_cb) return NULL;

    data = malloc(sizeof(*data));
    if (data)
    {
        data->stream = stream;
        memset(&data->plaintext, 0, sizeof(data->plaintext));
        if (plaintext)
            data->plaintext = *plaintext;
        data->encrypted = *encrypted;
        data->cb = hshake_cb;
    }

    return data;
}

/**
 * Frees only the data bundle structure. Does not free the arrays. They should
 * be copied to another location, or freed prior to calling this function.
 */
static void
free_write_cb_data(write_cb_data_t *data)
{
    if (!data) return;

    free(data);
}

void
tls_stream_print_err(FILE *fp, unsigned long code)
{
    char buf[256];
    ERR_error_string_n(code, buf, sizeof(buf));
    fprintf(fp, "%s\n", buf);
}
