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
/** @file
 *
 * @brief OpenSSL support for libuv tcp_handle_t handles
 *
 * @author Marianne Fletcher
 */

#ifndef UV_TLS_H_
#define UV_TLS_H_

#include <openssl/ssl.h>

#include <uv.h>

typedef struct tls_stream_s tls_stream_t;

/**
 * CALLBACKS FOR USERS
 */
typedef void (*tls_str_handshake_cb)(tls_stream_t *, int status);
typedef void (*tls_str_read_cb)(tls_stream_t *, int status,
        const uv_buf_t *buf);

/**
 * Called when a write operation has completed. Status will be 0 if the
 * operation was successful. The buffers which were written will be returned
 * to the user. The user must free the base field of each buffer.
 */
typedef void (*tls_str_write_cb)(tls_stream_t *, int status, uv_buf_t *buf,
        unsigned int nbufs);
typedef void (*tls_str_shutdown_cb)(tls_stream_t *, int status);
typedef void (*tls_str_close_cb) (tls_stream_t *);

/**
 * In addition to the fields shown here, the 'data' field of the tcp handle is
 * the address of the tls_stream itself.
 */
struct tls_stream_s
{
    uv_tcp_t tcp;
    SSL *ssl;
    BIO *internal;
    BIO *network;
    uv_alloc_cb on_alloc;
    tls_str_handshake_cb on_handshake;
    tls_str_shutdown_cb on_shutdown;
    tls_str_close_cb on_close;
    tls_str_read_cb on_read;
    uv_write_cb on_write;
    void *data;	// user data
    int handshake_complete;
};

/**
 * Libuv will discard references to the buffers submitted to uv_write. This
 * data structure will be used for keeping references to the written buffers
 * until the write_cb is called
 */
typedef struct buf_array_s
{
    /** The number of buffers in the buf array */
    unsigned int nbufs;
    /** A dynamically allocated array of buffers associated with the write
    request */
    uv_buf_t *bufs;
} buf_array_t;

/**
 * Keeps references to both the plaintext buffers and the encrypted buffers.
 * The encrypted buffers will be freed internally within tls_stream functions
 * but the plaintext buffers will be returned to the user within the write_cb.
 */
typedef struct write_cb_data_s
{
    tls_stream_t *stream;
    buf_array_t plaintext;
    buf_array_t encrypted;
    tls_str_write_cb cb;
} write_cb_data_t;

enum
{
    TLS_STR_OK = 0,
    TLS_STR_FAIL = -1,
    TLS_STR_MEM = -2,
    TLS_STR_HANDSHAKE_INCOMPLETE = -3,
    TLS_STR_NEED_CLOSE = -4
};

/**
 * Initialize a TLS stream. If TLS_STR_NEED_CLOSE is returned, the stream must
 * be closed by the user.
 * @param stream An uninitialized tls_stream_t.
 * @param loop A libuv event loop.
 * @param ctx The SSL context.
 * @return TLS_STR_OK if successful, or TLS_STR_FAIL or TLS_STR_NEED_CLOSE.
 */
int
tls_stream_init(tls_stream_t *stream, uv_loop_t *loop, SSL_CTX *ctx);

/**
 * Clean up a closed TLS stream.
 * @param stream A closed tls_stream_t.
 */
int
tls_stream_fini(tls_stream_t *stream);


/**
 * Bind the stream to an IP address and a port.
 * @param stream An initialized tls_stream_t.
 * @param addr Struct containing IP address and port.
 * @param flags Flags for the socket.
 */
int
tls_stream_bind(tls_stream_t *stream, const struct sockaddr *addr,
        unsigned int flags);

/**
 * Connect to a server.
 * @param stream An initialized tls_stream_t.
 * @param addr The address to connect to.
 * @param handshake_cb Callback to call when handshake is complete.
 * @param read_cb Callback to call when application data is received.
 */
int
tls_stream_connect(tls_stream_t *stream, const struct sockaddr *addr,
        tls_str_handshake_cb handshake_cb, tls_str_read_cb read_cb);

int
tls_stream_shutdown(tls_stream_t *stream, tls_str_shutdown_cb cb);

int
tls_stream_listen(tls_stream_t *stream, int backlog, uv_connection_cb cb);

/**
 * Accept a client connection.
 * @param server: The server tls_stream_t.
 * @param client: An initialized tls_stream_t for the client connection.
 * @param hshake_cb: A callback to be called when the handshake is complete.
 * @param read_cb: A callback to be called when data is received.
 */
int
tls_stream_accept(tls_stream_t *server, tls_stream_t *client,
        tls_str_handshake_cb hshake_cb, tls_str_read_cb read_cb);

int
tls_stream_read_start(tls_stream_t *stream, uv_read_cb cb);

int
tls_stream_read_stop(tls_stream_t *stream);

/**
 * Encrypt and write the data in the buffers through the stream. The memory
 * allocated to each buffer must remain valid until the callback is called, but
 * the uv_buf_t structs themselves can be freed as the memory address and
 * length of each buffer is copied within the function.
 *
 * The write callback will receive the written buffers when the operation is
 * complete, so that the user knows which write succeeded or failed, and so
 * the user can free the base field of each buffer.
 */
int
tls_stream_write(tls_stream_t *stream, const uv_buf_t bufs[],
        unsigned int nbufs, tls_str_write_cb cb);

/**
 * Closes a stream. Will shutdown first if necessary.
 * @param stream: The stream to close.
 * @param cb: A callback which will be called when the stream has been closed.
 * @return: 0 if successful.
 */
int
tls_stream_close(tls_stream_t *stream, tls_str_close_cb cb);

#endif /* UV_TLS_H_ */
