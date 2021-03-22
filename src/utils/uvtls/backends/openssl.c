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

#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>

#include "utils/uvtls/uv_tls.h"
#include "utils/logging.h"


struct ssl_context {
    SSL_CTX *ctx;
};

struct ssl_connection {
    SSL *handle;
    BIO *internal;
    BIO *network;
    struct ssl_context *ctx;
};


#ifdef HAVE_SSL_CTX_SET_KEYLOG_CALLBACK
static void
keylog_callback(const SSL *ssl __attribute__((unused)), const char *line)
{
    logger(L_DEBUG, "%s", line);
}
#endif

static void
tls_stream_print_err(unsigned long code)
{
    char buf[256];
    ERR_error_string_n(code, buf, sizeof(buf));
    logger(L_ERROR, "OpenSSL error: %s", buf);
}

static int
verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    if (!preverify_ok)
    {
        char buf[256];
        X509 *err_cert;
        int err;

        err_cert = X509_STORE_CTX_get_current_cert(ctx);
        err = X509_STORE_CTX_get_error(ctx);

        X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

        logger(L_DEBUG, "%s for %s\n", X509_verify_cert_error_string(err), buf);
    }

    return preverify_ok;
}

static SSL_CTX *
setup_context(const char *hostname, int ssl_no_verify)
{
    SSL_CTX *ctx = NULL;
    const SSL_METHOD *method;
    X509_VERIFY_PARAM *param = NULL;
    long ssl_opts;
    int rc;
    unsigned long ssl_err = 0;

#ifdef HAVE_TLS_METHOD
    method = TLS_method();
#else
    method = SSLv23_method();
#endif
    if (!method) return NULL;

    ctx = SSL_CTX_new(method);
    if (!ctx) return NULL;

    ssl_opts = (SSL_OP_ALL
        | SSL_OP_NO_TICKET
        | SSL_OP_NO_COMPRESSION
        | SSL_OP_NO_SSLv2
        | SSL_OP_NO_SSLv3
        | SSL_OP_NO_TLSv1
        | SSL_OP_NO_TLSv1_1)
        & ~SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
        & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;

/* OpenSSL v1.1.0+ */
#ifdef HAVE_SSL_CTX_SET_MINMAX_PROTO_VERSION
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, 0); // Use highest available version
#endif

    SSL_CTX_set_options(ctx, ssl_opts);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY
            | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
            | SSL_MODE_ENABLE_PARTIAL_WRITE
            | SSL_MODE_RELEASE_BUFFERS);

    param = SSL_CTX_get0_param(ctx);
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (!X509_VERIFY_PARAM_set1_host(param, hostname, strnlen(hostname, 253)))
    {
        logger(L_ERROR,
                "Failed to set the hostname as a verification parameter");
        return NULL;
    }
    if (!X509_VERIFY_PARAM_set_flags(param,
            X509_V_FLAG_POLICY_CHECK
            | X509_V_FLAG_TRUSTED_FIRST
            ))
    {
        logger(L_ERROR, "Failed to set the verify parameter flags");
        return NULL;
    }

    SSL_CTX_set_verify(
            ctx,
            ssl_no_verify == 0 ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
            verify_callback);
    rc = SSL_CTX_set_default_verify_paths(ctx);

    ssl_err = ERR_get_error();
    if (rc != 1)
    {
        char buf[256];
        ERR_error_string_n(ssl_err, buf, sizeof(buf));
        logger(L_ERROR, "Failed to load default verify paths. ssl_err: %s");
        return NULL;
    }

    return ctx;
}

static int
openssl_library_init(void)
{
    // OpenSSL > 1.1.0 automatically inits itself on first use
    return 0;
}


static int
openssl_init(struct ssl_context **result, const char *hostname,
             int ssl_no_verify)
{
    struct ssl_context *ctx_ptr = NULL;
    SSL_CTX *ctx = setup_context(hostname, ssl_no_verify);
    if (ctx == NULL) {
        *result = NULL;
        return TLS_STR_FAIL;
    }
    if ((ctx_ptr = malloc(sizeof(*ctx_ptr))) == NULL) {
        *result = NULL;
        return TLS_STR_FAIL;
    }
    ctx_ptr->ctx = ctx;
    *result = ctx_ptr;
    return TLS_STR_OK;
}

static struct ssl_connection *
openssl_alloc(struct ssl_context *ssl_ctx)
{
    struct ssl_connection *res = NULL;
    res = malloc(sizeof(*res));
    res->handle = NULL;
    res->internal = NULL;
    res->network = NULL;
    res->ctx = ssl_ctx;
    return res;
}

static int
openssl_connect(tls_stream_t *stream)
{
    int bio_rc;
    struct ssl_connection *conn = stream->ssl;
    SSL_CTX *ctx = stream->ssl->ctx->ctx;
    SSL *ssl = NULL;

    if ((ssl = SSL_new(ctx)) == NULL) {
        logger(L_ERROR, "uvtls_openssl: failed to create SSL object");
    }
    conn->handle = ssl;
    
    bio_rc = BIO_new_bio_pair(&conn->internal, 0, &conn->network, 0);
    if (1 != bio_rc) goto fail;

    SSL_set_bio(conn->handle, conn->network, conn->network);
#ifdef HAVE_SSL_CTX_SET_KEYLOG_CALLBACK
    SSL_CTX_set_keylog_callback(ctx, keylog_callback);
#endif
    SSL_set_connect_state(ssl);

    return TLS_STR_OK;

fail:
    if (conn->internal) BIO_free(conn->internal);
    if (conn->network) BIO_free(conn->network);
    if (ssl) SSL_free(ssl);
    return TLS_STR_FAIL;
}

static void
openssl_session_free(struct ssl_connection *conn)
{
    // One of the BIOs is freed implicitly by SSL_free
    SSL_free(conn->handle);
    conn->handle = NULL;
    BIO_free(conn->internal);
    conn->internal = NULL;
    conn->network = NULL;
    free(conn);
}

static int
openssl_data_pending(tls_stream_t *stream)
{
    return BIO_pending(stream->ssl->internal);
}

static int
openssl_read(tls_stream_t *stream, char *buf, int len)
{
    BIO *internal = stream->ssl->internal;
    return BIO_read(internal, buf, len);
}

static int
openssl_write(tls_stream_t *stream, const char *buf, int len)
{
    BIO *internal = stream->ssl->internal;
    return BIO_write(internal, buf, len);
}

static int
openssl_recv(tls_stream_t *stream, char *buf, int len, int *nread)
{
    int ssl_err;
    SSL *ssl = stream->ssl->handle;
    int read_bytes = SSL_read(ssl, buf, len);
    *nread = read_bytes;
    if (read_bytes < 0) {
        ssl_err = SSL_get_error(ssl, read_bytes);
        switch (ssl_err)
        {
        case SSL_ERROR_NONE:
        case SSL_ERROR_WANT_READ:
            return TLS_STR_OK;
        default:
            return TLS_STR_FAIL;
        }
    }
    return TLS_STR_OK;
}

static int
openssl_send(tls_stream_t *stream, const char *buf, int len)
{
    SSL *ssl = stream->ssl->handle;
    return SSL_write(ssl, buf, len);
}

static int
openssl_is_init_finished(tls_stream_t *stream)
{
    return SSL_is_init_finished(stream->ssl->handle);
}

static void
openssl_library_close(void)
{
    // Openssl > 1.1.0 automatically frees itself
}

static void
openssl_cleanup(struct ssl_context *context)
{
    SSL_CTX_free(context->ctx);
    free(context);
}

static int
openssl_do_handshake(tls_stream_t *stream)
{
    int ssl_rc;
    int ssl_err;

    int ret;	// return code from this function
    SSL *ssl = stream->ssl->handle;

    // Because we are not blocking we need to check the return code even in
    // case of error, because it might be expected behaviour.
    ssl_rc = SSL_do_handshake(ssl);
    ssl_err = SSL_get_error(ssl, ssl_rc);

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
            tls_stream_print_err(err);
        }
        return TLS_STR_FAIL;
    }

    return ret;
}

static int
openssl_shut_down(tls_stream_t *stream)
{
    return SSL_shutdown(stream->ssl->handle);
}

const struct NetStinky_ssl NetStinky_ssl_openssl = {
    .library_init = openssl_library_init,
    .init = openssl_init,
    .alloc = openssl_alloc,
    .cleanup = openssl_cleanup,
    .shut_down = openssl_shut_down,
    .data_pending = openssl_data_pending,
    .is_init_finished = openssl_is_init_finished,
    .do_handshake = openssl_do_handshake,
    .connect = openssl_connect,
    .session_free = openssl_session_free,
    .read = openssl_read,
    .write = openssl_write,
    .recv = openssl_recv,
    .send = openssl_send,
    .library_close = openssl_library_close
};
