/*
 * RIOT OS TLS over TCP Socket Header
 */

#ifndef SOCK_TLS_TCP_H
#define SOCK_TLS_TCP_H

#include "net/sock/tcp.h"
#include "wolfssl/ssl.h"

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
    void *app_ctx;              /**< Application context */
} sock_tls_tcp_t;

/**
 * @brief TLS Socket queue structure for TCP
 */
typedef struct sock_tls_tcp_queue {
    sock_tcp_queue_t tcp_queue;  /**< Underlying TCP queue */
    WOLFSSL_METHOD *method;      /**< SSL method */
    WOLFSSL_CTX *ctx;            /**< Pre-created context for accepted connections */
} sock_tls_tcp_queue_t;

/**
 * @brief   Creates a new TLS socket for TCP connections
 *
 * @param[out] sock      The socket to create
 * @param[in]  method    The WolfSSL method to use (e.g., client or server)
 *
 * @return  0 on success
 * @return  -EINVAL if @p sock or @p method is NULL
 * @return  -ENOMEM if resources could not be allocated
 */
int sock_tls_tcp_create(sock_tls_tcp_t *sock, WOLFSSL_METHOD *method);

/**
 * @brief   Connect to a remote TLS server
 *
 * @param[in,out] sock      Socket to use for connection
 * @param[in] remote        Remote endpoint to connect to
 * @param[in] local_port    Local port to bind to (0 for random)
 * @param[in] flags         Flags for the sock_tcp_connect()
 *
 * @return  0 on success
 * @return  -EINVAL if @p sock or @p remote is NULL
 * @return  -ECONNRESET if the connection or TLS handshake failed
 */
int sock_tls_tcp_connect(sock_tls_tcp_t *sock, const sock_tcp_ep_t *remote,
                        uint16_t local_port, uint16_t flags);

/**
 * @brief   Start listening for TLS connections
 *
 * @param[in,out] queue     Queue object to initialize
 * @param[in] local         Local endpoint to listen on
 * @param[in] queue_array   Array of sock_tcp_t objects for the TCP queue
 * @param[in] queue_len     Length of @p queue_array
 * @param[in] flags         Flags for sock_tcp_listen()
 * @param[in] method        WolfSSL method to use (must be server method)
 *
 * @return  0 on success
 * @return  -EINVAL if any parameter is invalid
 * @return  -ENOMEM if resources could not be allocated
 */
int sock_tls_tcp_listen(sock_tls_tcp_queue_t *queue, const sock_tcp_ep_t *local,
                       sock_tcp_t *queue_array, unsigned queue_len, uint16_t flags,
                       WOLFSSL_METHOD *method);

/**
 * @brief   Accept an incoming TLS connection
 *
 * @param[in] queue     Queue object to accept from
 * @param[out] sock     Pointer to allocated sock object on success
 * @param[in] timeout   Timeout for accept in microseconds, 0 for no timeout
 *
 * @return  0 on success
 * @return  -EINVAL if @p queue or @p sock is NULL
 * @return  -ETIMEDOUT if no connection request was received in @p timeout
 * @return  -ENOMEM if no memory for connection is available
 */
int sock_tls_tcp_accept(sock_tls_tcp_queue_t *queue, sock_tls_tcp_t **sock,
                       uint32_t timeout);

/**
 * @brief   Read data from a TLS connection
 *
 * @param[in] sock      Socket to read from
 * @param[out] data     Buffer to read into
 * @param[in] max_len   Maximum number of bytes to read
 * @param[in] timeout   Timeout in microseconds, 0 for no timeout
 *
 * @return  Number of bytes read on success
 * @return  0 if the connection was closed by the peer
 * @return  -EINVAL if @p sock or @p data is NULL or @p max_len is 0
 * @return  -EAGAIN if no data is available but connection is still active
 * @return  -ECONNRESET if the connection was closed unexpectedly
 */
ssize_t sock_tls_tcp_read(sock_tls_tcp_t *sock, void *data, size_t max_len,
                         uint32_t timeout);

/**
 * @brief   Write data to a TLS connection
 *
 * @param[in] sock      Socket to write to
 * @param[in] data      Data to write
 * @param[in] len       Length of @p data
 *
 * @return  Number of bytes written on success
 * @return  -EINVAL if @p sock or @p data is NULL or @p len is 0
 * @return  -EAGAIN if not all data could be written
 * @return  -ECONNRESET if the connection was closed unexpectedly
 */
ssize_t sock_tls_tcp_write(sock_tls_tcp_t *sock, const void *data, size_t len);

/**
 * @brief   Disconnect and free resources of a TLS connection
 *
 * @param[in] sock      Socket to disconnect
 */
void sock_tls_tcp_disconnect(sock_tls_tcp_t *sock);

/**
 * @brief   Set certificate and private key for a TLS connection
 *
 * @param[in] sock      Socket to configure
 * @param[in] cert_buf  Buffer containing certificate
 * @param[in] cert_len  Length of certificate buffer
 * @param[in] key_buf   Buffer containing private key
 * @param[in] key_len   Length of private key buffer
 * @param[in] type      Format of certificate and key (e.g., SSL_FILETYPE_PEM)
 *
 * @return  0 on success
 * @return  -EINVAL if any parameter is invalid
 */
int sock_tls_tcp_set_cert_key(sock_tls_tcp_t *sock,
                             const unsigned char *cert_buf, unsigned int cert_len,
                             const unsigned char *key_buf, unsigned int key_len,
                             int type);

/**
 * @brief   Set timeout for a TLS connection
 *
 * @param[in] sock      Socket to configure
 * @param[in] timeout   New timeout value in microseconds
 */
void sock_tls_tcp_set_timeout(sock_tls_tcp_t *sock, unsigned int timeout);

typedef int (*GetTcpRecvTimeoutCallback)(void *ctx);


#ifdef __cplusplus
}
#endif

#endif /* SOCK_TLS_TCP_H */
