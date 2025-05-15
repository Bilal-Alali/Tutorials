#ifndef SOCK_TLS_TCP_H
#define SOCK_TLS_TCP_H

#include "net/sock/tcp.h"
#include "wolfssl/ssl.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Default TLS read/write timeout in milliseconds -> 30 sec */
#define TLS_DEFAULT_TIMEOUT 30000

/**
 * @brief TLS Socket structure for TCP
 */
typedef struct sock_tls_tcp {
    sock_tcp_t tcp_sock;        /**< Underlying TCP socket */
    WOLFSSL_CTX *ctx;           /**< WolfSSL context */
    WOLFSSL *ssl;               /**< WolfSSL session */
    void *app_ctx;              /**< Application context */
    bool is_handshake_done;     /**< Flag to track handshake status */
    bool is_connecting;         /**< Flag to track connection status */
} sock_tls_tcp_t;

/**
 * @brief TLS Socket queue structure for TCP
 */
typedef struct sock_tls_tcp_queue {
    sock_tcp_queue_t tcp_queue;  /**< Underlying TCP queue */
    WOLFSSL_METHOD *method;      /**< SSL method */
    WOLFSSL_CTX *ctx;           /**< Pre-created context for accepted connections */
} sock_tls_tcp_queue_t;

/**
 * @brief Creates a new TLS socket for TCP connections
 */
int sock_tls_tcp_create(sock_tls_tcp_t *sock, WOLFSSL_METHOD *method);

/**
 * @brief Connect to a remote TLS server (non-blocking)
 */
int sock_tls_tcp_connect(sock_tls_tcp_t *sock, const sock_tcp_ep_t *remote,
                        uint16_t local_port, uint16_t flags,
                        const unsigned char *cert_buf, unsigned int cert_len,
                        const unsigned char *key_buf, unsigned int key_len);

/**
 * @brief Continue TLS handshake process (non-blocking)
 */
int sock_tls_tcp_handshake(sock_tls_tcp_t *sock);

/**
 * @brief Start listening for TLS connections
 */
int sock_tls_tcp_listen(sock_tls_tcp_queue_t *queue, const sock_tcp_ep_t *local,
                       sock_tcp_t *queue_array, unsigned queue_len, uint16_t flags,
                       WOLFSSL_METHOD *method);

/**
 * @brief Accept an incoming TLS connection (non-blocking)
 */
int sock_tls_tcp_accept(sock_tls_tcp_queue_t *queue, sock_tls_tcp_t **sock,
                       uint32_t timeout);

/**
 * @brief Read data from a TLS connection (non-blocking)
 */
ssize_t sock_tls_tcp_read(sock_tls_tcp_t *sock, void *data, size_t max_len);

/**
 * @brief Write data to a TLS connection (non-blocking)
 */
ssize_t sock_tls_tcp_write(sock_tls_tcp_t *sock, const void *data, size_t len);

/**
 * @brief Disconnect and free resources of a TLS connection
 */
void sock_tls_tcp_disconnect(sock_tls_tcp_t *sock);

/**
 * @brief Set certificate and private key for a TLS connection
 */
int sock_tls_tcp_set_cert_key(sock_tls_tcp_t *sock,
                             const unsigned char *cert_buf, unsigned int cert_len,
                             const unsigned char *key_buf, unsigned int key_len);

/**
 * @brief Disable certificate verification (for testing only)
 */
void sock_tls_tcp_disable_cert_verify(sock_tls_tcp_t *sock);

/**
 * @brief Set timeout for a TLS connection
 */
void sock_tls_tcp_set_timeout(sock_tls_tcp_t *sock, unsigned int timeout);

#ifdef __cplusplus
}
#endif

#endif /* SOCK_TLS_TCP_H */
