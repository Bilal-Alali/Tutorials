/*
 * Copyright (C) 2025 Bilal Alali
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    net_sock_tls_tcp TLS sock API
 * @ingroup     net_sock
 * @brief       Sock submodule for TLS over TCP
 *
 * This module provides an API for using TLS over TCP through the
 * sock interface.
 *
 */

#ifndef SOCK_TLS_TCP_H
#define SOCK_TLS_TCP_H

#include <stdint.h>
#include "net/sock/tcp.h"
#include <wolfssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Type for a TLS TCP sock object
 *
 * @note    API implementers: `struct sock_tls_tcp` needs to be defined by
 *          implementation-specific `sock_types.h`.
 */
typedef struct sock_tls_tcp {
    sock_tcp_t tcp_sock;        /**< Underlying TCP socket */
    WOLFSSL_CTX *ctx;           /**< WolfSSL context */
    WOLFSSL *ssl;               /**< WolfSSL session */
    void *app_ctx;              /**< Application context */
} sock_tls_tcp_t;

/**
 * @brief   Creates a new TLS TCP sock object
 *
 * @pre     (sock != NULL)
 *
 * @param[out] sock      The resulting TLS TCP sock object
 * @param[in]  method    Defines the SSL or TLS protocol for the client or server to use.
 *                       For example, wolfTLSv1_2_client_method().
 *
 * @return  0 on success
 * @return  -ENOMEM, if not enough resources could be provided for sock
 * @return  -EINVAL, if sock is NULL
 */
int sock_tls_tcp_create(sock_tls_tcp_t *sock, WOLFSSL_METHOD *method);

/**
 * @brief   Establishes a TLS connection to a server
 *
 * @pre     (sock != NULL) && (remote != NULL) && (remote->port != 0)
 *
 * @param[in,out] sock       The sock object to connect with
 * @param[in] remote         Remote endpoint to connect to
 * @param[in] local_port     Local port to bind to (0 for random port)
 * @param[in] flags          Flags for the sock object
 *
 * @return  0 on success
 * @return  -EADDRINUSE, if @p local_port is already used
 * @return  -EAFNOSUPPORT, if sock_tcp_ep_t::family of @p remote is not supported
 * @return  -EINVAL, invalid parameters
 * @return  -ENOMEM, not enough memory to establish connection
 * @return  -ETIMEDOUT, if the connection attempt timed out
 */
int sock_tls_tcp_connect(sock_tls_tcp_t *sock, const sock_tcp_ep_t *remote,
                        uint16_t local_port, uint16_t flags);

/**
 * @brief   Creates a listening TLS TCP socket waiting for incoming connections
 *
 * @pre     (queue != NULL) && (local != NULL) && (local->port != 0) &&
 *          (queue_array != NULL) && (queue_len != 0)
 *
 * @param[out] queue         The resulting listening queue
 * @param[in] local          Local endpoint to listen on
 * @param[in] queue_array    Array of sock objects to accept connections with
 * @param[in] queue_len      Length of @p queue_array
 * @param[in] flags          Flags for the listening queue. See also
 *                           [sock flags](@ref net_sock_flags).
 * @param[in] method         TLS method to use (e.g. wolfTLSv1_2_server_method())
 *
 * @return  0 on success
 * @return  -EADDRINUSE, if @p local is already used elsewhere
 * @return  -EAFNOSUPPORT, if sock_tcp_ep_t::family of @p local is not supported
 * @return  -EINVAL, if sock_tcp_ep_t::netif of @p local is not a valid interface
 * @return  -ENOMEM, if no memory was available to listen on @p queue
 */
int sock_tls_tcp_listen(sock_tcp_queue_t *queue, const sock_tcp_ep_t *local,
                       sock_tcp_t *queue_array, unsigned queue_len, uint16_t flags,
                       WOLFSSL_METHOD *method);

/**
 * @brief   Accepts an incoming TLS connection from a listening queue
 *
 * @pre     (queue != NULL) && (sock != NULL)
 *
 * @param[in] queue          A TCP listening queue
 * @param[out] sock          A new TLS sock object for the established connection
 * @param[in] timeout        Timeout for accept in microseconds.
 *                           If 0 and no data is available, the function returns
 *                           immediately. May be SOCK_NO_TIMEOUT for no timeout.
 *
 * @return  0 on success
 * @return  -EAGAIN, if @p timeout is 0 and no data is available
 * @return  -EINVAL, if @p queue was not initialized using sock_tls_tcp_listen()
 * @return  -ENOMEM, if system was not able to allocate sufficient memory
 * @return  -ETIMEDOUT, if the operation timed out
 */
int sock_tls_tcp_accept(sock_tcp_queue_t *queue, sock_tls_tcp_t **sock, uint32_t timeout);

/**
 * @brief   Reads data from an established TLS connection
 *
 * @pre     (sock != NULL) && (data != NULL) && (max_len > 0)
 *
 * @param[in] sock           A TLS sock object
 * @param[out] data          Pointer where the read data should be stored
 * @param[in] max_len        Maximum space available at @p data
 * @param[in] timeout        Timeout for receive in microseconds.
 *                           If 0 and no data is available, the function
 *                           returns immediately. May be SOCK_NO_TIMEOUT for no
 *                           timeout.
 *
 * @return  The number of bytes read on success
 * @return  0, if no read data is available or connection was closed
 * @return  -EAGAIN, if @p timeout is 0 and no data is available
 * @return  -ECONNRESET, if the connection was forcibly closed
 * @return  -ETIMEDOUT, if @p timeout expired
 */
ssize_t sock_tls_tcp_read(sock_tls_tcp_t *sock, void *data, size_t max_len,
                         uint32_t timeout);

/**
 * @brief   Writes data to an established TLS connection
 *
 * @pre     (sock != NULL) && (data != NULL) && (len > 0)
 *
 * @param[in] sock           A TLS sock object
 * @param[in] data           Pointer to the data to send
 * @param[in] len            Length of @p data
 *
 * @return  The number of bytes sent on success
 * @return  -ECONNRESET, if the connection was forcibly closed
 * @return  -ENOMEM, if no memory was available to write @p data
 */
ssize_t sock_tls_tcp_write(sock_tls_tcp_t *sock, const void *data, size_t len);

/**
 * @brief   Disconnect a TLS connection
 *
 * @pre     (sock != NULL)
 *
 * @param[in] sock           A TLS sock object
 */
void sock_tls_tcp_disconnect(sock_tls_tcp_t *sock);

/**
 * @brief   Sets certificate and private key for TLS endpoint
 *
 * @pre     (sock != NULL) && (cert_buf != NULL) && (cert_len > 0) &&
 *          (key_buf != NULL) && (key_len > 0)
 *
 * @param[in] sock           A TLS sock object
 * @param[in] cert_buf       Buffer containing the certificate
 * @param[in] cert_len       Length of certificate buffer
 * @param[in] key_buf        Buffer containing the private key
 * @param[in] key_len        Length of private key buffer
 * @param[in] type           Format type, e.g. SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM
 *
 * @return  0 on success
 * @return  -EINVAL on invalid parameters
 * @return  -ENOMEM if not enough memory
 */
int sock_tls_tcp_set_cert_key(sock_tls_tcp_t *sock,
                             const unsigned char *cert_buf, unsigned int cert_len,
                             const unsigned char *key_buf, unsigned int key_len,
                             int type);

/**
 * @brief   Sets the TLS session timeout
 *
 * @pre     (sock != NULL)
 *
 * @param[in] sock           A TLS sock object
 * @param[in] timeout        Timeout in milliseconds
 */
void sock_tls_tcp_set_timeout(sock_tls_tcp_t *sock, unsigned int timeout);

#ifdef __cplusplus
}
#endif

#endif /* SOCK_TLS_TCP_H */
