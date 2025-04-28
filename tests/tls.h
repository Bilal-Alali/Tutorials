/**
 * @file tls.h
 * @brief TLS over TCP socket implementation using wolfSSL for RIOT OS
 * @author Bilal-Alali
 * @date 2025-04-24 16:56:29
 */

#ifndef SOCK_TLS_TCP_H
#define SOCK_TLS_TCP_H

#include "net/sock/tcp.h"
#include <wolfssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief TLS Socket structure for TCP
 */
typedef struct sock_tls_tcp {
    sock_tcp_t tcp_sock;        /**< Underlying TCP socket */
    WOLFSSL_CTX *ctx;           /**< WolfSSL context */
    WOLFSSL *ssl;               /**< WolfSSL session */
} sock_tls_tcp_t;

/**
 * @brief TLS Socket queue structure for TCP
 */
typedef struct sock_tls_tcp_queue {
    sock_tcp_queue_t tcp_queue;  /**< Underlying TCP queue */
    WOLFSSL_CTX *ctx;           /**< WolfSSL context */
} sock_tls_tcp_queue_t;

/**
 * @brief Creates a new TLS socket for TCP connections
 *
 * @param[out] sock    The socket to create
 * @param[in]  method  The WolfSSL method to use (e.g., client or server)
 *
 * @return 0 on success
 * @return -EINVAL if sock or method is NULL
 * @return -ENOMEM if resources could not be allocated
 */
int sock_tls_tcp_create(sock_tls_tcp_t *sock, WOLFSSL_METHOD *method);

/**
 * @brief Connect to a remote TLS server
 *
 * @param[in,out] sock       Socket to use for connection
 * @param[in] remote         Remote endpoint to connect to
 * @param[in] local_port     Local port to bind to (0 for random)
 * @param[in] flags          Flags for the sock_tcp_connect()
 *
 * @return 0 on success
 * @return -EINVAL if sock or remote is NULL
 * @return -ECONNRESET if the connection was reset
 * @return -ETIMEDOUT if the connection timed out
 */
int sock_tls_tcp_connect(sock_tls_tcp_t *sock, const sock_tcp_ep_t *remote,
                        uint16_t local_port, uint16_t flags);

/**
 * @brief Initialize TLS server and start listening
 *
 * @param[in,out] queue      Queue object to initialize
 * @param[in] local          Local endpoint to listen on
 * @param[in] queue_array    Array of sock_tcp_t objects for the TCP queue
 * @param[in] queue_len      Length of queue_array
 * @param[in] flags          Flags for sock_tcp_listen()
 * @param[in] method         WolfSSL method to use (must be server method)
 * @param[in] cert_buf       Server certificate buffer in PEM format
 * @param[in] cert_len       Length of certificate buffer
 * @param[in] key_buf        Server private key buffer in PEM format
 * @param[in] key_len        Length of private key buffer
 *
 * @return 0 on success
 * @return -EINVAL if parameters are invalid
 * @return -ENOMEM if resources could not be allocated
 */
int sock_tls_tcp_listen(sock_tls_tcp_queue_t *queue, const sock_tcp_ep_t *local,
                       sock_tcp_t *queue_array, unsigned queue_len, uint16_t flags,
                       WOLFSSL_METHOD *method, const unsigned char *cert_buf,
                       unsigned int cert_len, const unsigned char *key_buf,
                       unsigned int key_len);

/**
 * @brief Accept a new TLS connection
 *
 * @param[in] queue    Queue to accept connection from
 * @param[out] sock    Pointer to allocated sock_tls_tcp_t structure pointer
 * @param[in] timeout  Timeout for accept operation in microseconds
 *
 * @return 0 on success
 * @return -EINVAL if queue or sock is NULL
 * @return -ENOMEM if resources could not be allocated
 * @return -ETIMEDOUT if accept timed out
 */
int sock_tls_tcp_accept(sock_tls_tcp_queue_t *queue, sock_tls_tcp_t **sock,
                       uint32_t timeout);

/**
 * @brief Read data from a TLS connection
 *
 * @param[in] sock     Socket to read from
 * @param[out] data    Buffer to read into
 * @param[in] max_len  Maximum number of bytes to read
 *
 * @return Number of bytes read on success
 * @return -EINVAL if parameters are invalid
 * @return -ECONNRESET if connection was reset
 */
ssize_t sock_tls_tcp_read(sock_tls_tcp_t *sock, void *data, size_t max_len);

/**
 * @brief Write data to a TLS connection
 *
 * @param[in] sock    Socket to write to
 * @param[in] data    Data to write
 * @param[in] len     Length of data to write
 *
 * @return Number of bytes written on success
 * @return -EINVAL if parameters are invalid
 * @return -ECONNRESET if connection was reset
 */
ssize_t sock_tls_tcp_write(sock_tls_tcp_t *sock, const void *data, size_t len);

/**
 * @brief Disconnect and cleanup a TLS connection
 *
 * @param[in] sock    Socket to disconnect
 */
void sock_tls_tcp_disconnect(sock_tls_tcp_t *sock);

#ifdef __cplusplus
}
#endif

#endif /* SOCK_TLS_TCP_H */
