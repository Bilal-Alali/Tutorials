#ifndef SOCK_TLS_TCP_H
#define SOCK_TLS_TCP_H

#include "net/sock/tcp.h"
#include "wolfssl/ssl.h"

/**
 * @brief TLS Socket structure for TCP
 */
typedef struct sock_tls_tcp_t{
    sock_tcp_t tcp_sock;        /**< Underlying TCP socket */
    WOLFSSL_CTX *ctx;           /**< WolfSSL context */
    WOLFSSL *ssl;               /**< WolfSSL session */
    void *app_ctx;              /**< Application context */
} sock_tls_tcp_t;

/**
 * @brief Initialize the TLS module
 * @return 0 on success, -1 on failure
 */
int sock_tls_tcp_init(void);

/**
 * @brief Create a new TLS socket
 * @param[out] sock Pointer to the TLS socket structure
 * @param[in] method WolfSSL method (client or server)
 * @param[in] ca_cert CA certificate in PEM format
 * @param[in] device_cert Device certificate in PEM format
 * @param[in] private_key Private key in PEM format
 * @return 0 on success, -1 on failure
 */
int sock_tls_tcp_create(sock_tls_tcp_t *sock, WOLFSSL_METHOD *method,
                        const char *ca_cert, const char *device_cert, const char *private_key);

/**
 * @brief Accept a new TLS connection (server-side)
 * @param[in] server_sock Pointer to the server TLS socket
 * @param[out] client_sock Pointer to the client TLS socket
 * @return 0 on success, -1 on failure
 */
int sock_tls_tcp_accept(sock_tls_tcp_t *server_sock, sock_tls_tcp_t *client_sock);

/**
 * @brief Establish a TLS connection to a remote host (client-side)
 * @param[in] sock Pointer to the TLS socket structure
 * @param[in] host Remote host address (IPv6)
 * @param[in] port Remote port
 * @return 0 on success, -1 on failure
 */
int sock_tls_tcp_connect(sock_tls_tcp_t *sock, const char *host, uint16_t port);

/**
 * @brief Send data over the TLS connection
 * @param[in] sock Pointer to the TLS socket structure
 * @param[in] data Data buffer to send
 * @param[in] len Length of the data buffer
 * @return Number of bytes sent on success, -1 on failure
 */
int sock_tls_tcp_send(sock_tls_tcp_t *sock, const unsigned char *data, size_t len);

/**
 * @brief Receive data over the TLS connection
 * @param[in] sock Pointer to the TLS socket structure
 * @param[out] buffer Buffer to store received data
 * @param[in] len Length of the buffer
 * @return Number of bytes received on success, -1 on failure
 */
int sock_tls_tcp_receive(sock_tls_tcp_t *sock, unsigned char *buffer, size_t len);

/**
 * @brief Disconnect the TLS socket
 * @param[in] sock Pointer to the TLS socket structure
 */
void sock_tls_tcp_disconnect(sock_tls_tcp_t *sock);

/**
 * @brief Destroy the TLS socket and free resources
 * @param[in] sock Pointer to the TLS socket structure
 */
void sock_tls_tcp_destroy(sock_tls_tcp_t *sock);

/**
 * @brief Cleanup the TLS module
 */
void sock_tls_tcp_cleanup(void);

#endif /* SOCK_TLS_TCP_H */
