/*
 * Copyright (C) 2025 Bilal
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "net/sock/tcp.h"
#include "include/tls.h"
#include "cert_data.h"
#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#include "ztimer.h"
#include "log.h"

#define ENABLE_DEBUG 0
#include "debug.h"

/* Default TLS read/write timeout in milliseconds -> 30 sec*/
#define TLS_DEFAULT_TIMEOUT 30000

/* Callbacks for wolfSSL I/O operations */
static GetTcpRecvTimeoutCallback get_tcp_recv_timeout_callback = NULL;

/**
 * @brief Set callback function for TCP receive timeout (man bekommt den Timeout dynamisch)
 */
void sock_tls_tcp_set_recv_timeout_callback(GetTcpRecvTimeoutCallback callback)
{
    get_tcp_recv_timeout_callback = callback;
}

/**
 * @brief Custom I/O receive function for wolfSSL
 */
static int _wolfssl_tcp_receive(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    sock_tls_tcp_t *sock = (sock_tls_tcp_t *)(ssl->gnrcCtx);

    if (!sock) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* Uses the default timeout or the one provided by the callback*/
    int timeout = TLS_DEFAULT_TIMEOUT;
    if (get_tcp_recv_timeout_callback) {
        timeout = get_tcp_recv_timeout_callback(ctx);
    }

    int recv_len = 0;
    ztimer_now_t end_time = ztimer_now(ZTIMER_MSEC) + timeout;
    ssize_t bytes_read;

    do {
        /* Tries to read data from the TCP socket with a 1-second timeout -> smaller timeout data */
        bytes_read = sock_tcp_read(&sock->tcp_sock, buf + recv_len, sz - recv_len, 1000);

        if (bytes_read > 0) {
            recv_len += bytes_read;
        }

        /* Continue reading if we still have time and haven't filled the buffer. Continues reading until: The buffer is full. No more data is available. The timeout is reached. */
    } while ((recv_len < sz) && (bytes_read > 0) && (ztimer_now(ZTIMER_MSEC) < end_time));

    if (recv_len > 0) {
        return recv_len;
    }
    else {
        switch (bytes_read) {
            case -ETIMEDOUT:
                return WOLFSSL_CBIO_ERR_WANT_READ;
            case -EAGAIN:
                return WOLFSSL_CBIO_ERR_WANT_READ;
            case 0:
                DEBUG("Connection closed by peer\n");
                return WOLFSSL_CBIO_ERR_CONN_CLOSE;
            default:
                DEBUG("Error while receiving data: %d\n", (int)bytes_read);
                break;
        }
    }

    return bytes_read;
}

/**
 * @brief Custom I/O send function for wolfSSL
 */
static int _wolfssl_tcp_send(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    sock_tls_tcp_t *sock = (sock_tls_tcp_t *)(ssl->gnrcCtx);

    if (!sock) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    ssize_t bytes_written = sock_tcp_write(&sock->tcp_sock, buf, sz);

    if (bytes_written >= 0) {
        return bytes_written;
    }
    else {
        switch (bytes_written) {
            case -EAGAIN:
                return WOLFSSL_CBIO_ERR_WANT_WRITE;
            case -ECONNRESET:
                return WOLFSSL_CBIO_ERR_CONN_CLOSE;
            default:
                DEBUG("Error while sending data: %d\n", (int)bytes_written);
                return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
}

/**
 * @brief Creates a WolfSSL session with custom I/O functions and stores it in the sock_tls_tcp_t object.
 */
int sock_tls_tcp_create(sock_tls_tcp_t *sock, WOLFSSL_METHOD *method)
{
    if (!sock || !method) {
        return -EINVAL;
    }

    memset(sock, 0, sizeof(sock_tls_tcp_t));

    /* Create the WolfSSL Context */
    sock->ctx = wolfSSL_CTX_new(method);
    if (!sock->ctx) {
        DEBUG("Failed to create WolfSSL context\n");
        return -ENOMEM;
    }

    /* Create a new SSL session */
    sock->ssl = wolfSSL_new(sock->ctx);
    if (!sock->ssl) {
        DEBUG("Failed to create WolfSSL session\n");
        wolfSSL_CTX_free(sock->ctx);
        sock->ctx = NULL;
        return -ENOMEM;
    }

    /* Set the custom I/O functions */
    wolfSSL_SetIORecv(sock->ssl, _wolfssl_tcp_receive);
    wolfSSL_SetIOSend(sock->ssl, _wolfssl_tcp_send);

    /* Set the custom context object */
    wolfSSL_SetIOReadCtx(sock->ssl, sock);
    wolfSSL_SetIOWriteCtx(sock->ssl, sock);

    return 0;
}

/**
 * @brief First establishes a normal TCP connection, then links the WolfSSL session with the TCP socket,
 * and executes the TLS handshake.
 */
int sock_tls_tcp_connect(sock_tls_tcp_t *sock, const sock_tcp_ep_t *remote,
                         uint16_t local_port, uint16_t flags)
{
    if (!sock || !remote) {
        return -EINVAL;
    }

    /* Establish a TCP connection */
    if (sock_tcp_connect(&sock->tcp_sock, remote, local_port, flags) < 0) {
        DEBUG("Failed to establish TCP connection\n");
        return -ETIMEDOUT;
    }

    /* Set the TCP socket in WolfSSL */
    wolfSSL_set_fd(sock->ssl, sock->tcp_sock.fd);

    /* Start the TLS handshake */
    if (wolfSSL_connect(sock->ssl) != WOLFSSL_SUCCESS) {
        DEBUG("TLS handshake failed\n");
        sock_tcp_disconnect(&sock->tcp_sock);
        return -ECONNRESET;
    }

    return 0;
}

/**
 * @brief This function only calls the TCP listen function. The TLS handshake happens later in sock_tls_tcp_accept.
 */
int sock_tls_tcp_listen(sock_tcp_queue_t *queue, const sock_tcp_ep_t *local,
                        sock_tcp_t *queue_array, unsigned queue_len, uint16_t flags,
                        WOLFSSL_METHOD *method)
{
    if (!queue || !local || !queue_array || queue_len == 0 || !method) {
        return -EINVAL;
    }

    /* Store the method for later use in accept */
    queue->user_data = method;

    /* Start the TCP listener */
    if (sock_tcp_listen(queue, local, queue_array, queue_len, flags) < 0) {
        DEBUG("Failed to start TCP listening\n");
        return -EADDRINUSE;
    }

    return 0;
}

/**
 * @brief This function waits for a new connection, creates a TLS session and performs the TLS handshake with the client.
 */
int sock_tls_tcp_accept(sock_tcp_queue_t *queue, sock_tls_tcp_t **sock, uint32_t timeout)
{
    if (!queue || !sock) {
        return -EINVAL;
    }

    /* Get the method stored during listen */
    WOLFSSL_METHOD *method = (WOLFSSL_METHOD *)queue->user_data;
    if (!method) {
        DEBUG("No SSL method provided for TLS accept\n");
        return -EINVAL;
    }

    /* Accept a new TCP connection */
    sock_tcp_t *new_sock;
    if (sock_tcp_accept(queue, &new_sock, timeout) < 0) {
        return -ETIMEDOUT;
    }

    /* Create a new TLS socket */
    *sock = malloc(sizeof(sock_tls_tcp_t));
    if (!*sock) {
        sock_tcp_disconnect(new_sock);
        return -ENOMEM;
    }

    memset(*sock, 0, sizeof(sock_tls_tcp_t));
    (*sock)->tcp_sock = *new_sock;

    /* Create a new WolfSSL context */
    (*sock)->ctx = wolfSSL_CTX_new(method);
    if (!(*sock)->ctx) {
        DEBUG("Failed to create WolfSSL context\n");
        sock_tcp_disconnect(&(*sock)->tcp_sock);
        free(*sock);
        return -ENOMEM;
    }

    /* Load certificates from cert_data.h */
    sock_tls_tcp_set_cert_key(*sock,
                             tls_cert_data, tls_cert_len,
                             tls_key_data, tls_key_len,
                             SSL_FILETYPE_PEM);

    /* Create a new SSL session */
    (*sock)->ssl = wolfSSL_new((*sock)->ctx);
    if (!(*sock)->ssl) {
        DEBUG("Failed to create WolfSSL session\n");
        wolfSSL_CTX_free((*sock)->ctx);
        sock_tcp_disconnect(&(*sock)->tcp_sock);
        free(*sock);
        return -ENOMEM;
    }

    /* Set the custom I/O functions */
    wolfSSL_SetIORecv((*sock)->ssl, _wolfssl_tcp_receive);
    wolfSSL_SetIOSend((*sock)->ssl, _wolfssl_tcp_send);

    /* Set the custom context object */
    wolfSSL_SetIOReadCtx((*sock)->ssl, *sock);
    wolfSSL_SetIOWriteCtx((*sock)->ssl, *sock);

    /* Set the TCP socket in WolfSSL */
    wolfSSL_set_fd((*sock)->ssl, (*sock)->tcp_sock.fd);

    /* TLS handshake with client */
    if (wolfSSL_accept((*sock)->ssl) != WOLFSSL_SUCCESS) {
        DEBUG("TLS handshake failed\n");
        wolfSSL_free((*sock)->ssl);
        wolfSSL_CTX_free((*sock)->ctx);
        sock_tcp_disconnect(&(*sock)->tcp_sock);
        free(*sock);
        return -ECONNRESET;
    }

    return 0;
}

/**
 * @brief Read data from the TLS connection.
 */
ssize_t sock_tls_tcp_read(sock_tls_tcp_t *sock, void *data, size_t max_len, uint32_t timeout)
{
    if (!sock || !data || max_len == 0) {
        return -EINVAL;
    }

    /* Set non-blocking mode temporarily to handle timeouts manually */
    wolfSSL_set_using_nonblock(sock->ssl, 1);

    ztimer_now_t end_time = ztimer_now(ZTIMER_MSEC) + timeout;
    int ret;

    do {
        ret = wolfSSL_read(sock->ssl, data, max_len);

        if (ret > 0) {
            /* Success, data read */
            wolfSSL_set_using_nonblock(sock->ssl, 0);
            return ret;
        }

        if (wolfSSL_want_read(sock->ssl)) {
            /* Need to wait for more data */
            ztimer_sleep(ZTIMER_MSEC, 10); /* Small sleep to avoid busy waiting */
        } else {
            /* An error occurred */
            int err = wolfSSL_get_error(sock->ssl, ret);
            DEBUG("SSL read error: %d\n", err);
            wolfSSL_set_using_nonblock(sock->ssl, 0);
            return -EIO;
        }
    } while (ztimer_now(ZTIMER_MSEC) < end_time);

    /* Timeout occurred */
    wolfSSL_set_using_nonblock(sock->ssl, 0);
    return -ETIMEDOUT;
}

/**
 * @brief Write data to the TLS connection.
 */
ssize_t sock_tls_tcp_write(sock_tls_tcp_t *sock, const void *data, size_t len)
{
    if (!sock || !data || len == 0) {
        return -EINVAL;
    }

    int ret = wolfSSL_write(sock->ssl, data, len);

    if (ret > 0) {
        return ret;
    } else {
        int err = wolfSSL_get_error(sock->ssl, ret);
        if (err == SSL_ERROR_WANT_WRITE) {
            return -EAGAIN;
        } else {
            DEBUG("SSL write error: %d\n", err);
            return -EIO;
        }
    }
}

/**
 * @brief Disconnect and clean up the TLS connection.
 */
void sock_tls_tcp_disconnect(sock_tls_tcp_t *sock)
{
    if (!sock) {
        return;
    }

    /* Properly close the TLS connection */
    if (sock->ssl) {
        wolfSSL_shutdown(sock->ssl);
        wolfSSL_free(sock->ssl);
    }

    /* Clean up the context */
    if (sock->ctx) {
        wolfSSL_CTX_free(sock->ctx);
    }

    /* Close the TCP connection */
    sock_tcp_disconnect(&sock->tcp_sock);

    /* Free the memory */
    free(sock);
}

/**
 * @brief Set the certificate and private key for the TLS connection.
 */


// Later in your code to call the function sock_tls_tcp_set_cert_key(&tls_sock, riot_cert_pem, riot_cert_pem_len,  riot_key_pem, riot_key_pem_len, SSL_FILETYPE_PEM); the parameters are from the cert_data.h

int sock_tls_tcp_set_cert_key(sock_tls_tcp_t *sock,
                             const unsigned char *cert_buf, unsigned int cert_len,
                             const unsigned char *key_buf, unsigned int key_len,
                             int type)
{
    if (!sock || !sock->ctx || !cert_buf || cert_len == 0 || !key_buf || key_len == 0) {
        return -EINVAL;
    }

    /* Load certificate from buffer */
    int ret = wolfSSL_CTX_use_certificate_buffer(sock->ctx, cert_buf, cert_len, type);
    if (ret != SSL_SUCCESS) {
        DEBUG("Failed to load certificate: %d\n", ret);
        return -EINVAL;
    }

    /* Load private key from buffer */
    ret = wolfSSL_CTX_use_PrivateKey_buffer(sock->ctx, key_buf, key_len, type);
    if (ret != SSL_SUCCESS) {
        DEBUG("Failed to load private key: %d\n", ret);
        return -EINVAL;
    }

    return 0;
}
