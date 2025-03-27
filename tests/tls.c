#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "net/sock/tcp.h"
#include "tls.h"
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include "ztimer.h"


/* Default TLS read/write timeout in milliseconds -> 30 sec */
#define TLS_DEFAULT_TIMEOUT 30000

int sock_tls_tcp_create(sock_tls_tcp_t *sock, WOLFSSL_METHOD *method)
{
    if (!sock || !method) {
        return -EINVAL;
    }

    memset(sock, 0, sizeof(sock_tls_tcp_t));

    /* Create the WolfSSL Context */
    sock->ctx = wolfSSL_CTX_new(method);
    if (!sock->ctx) {
        DEBUG("Failed to create sock context\n");
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

    /* Set the timeout for the SSL session */
    wolfSSL_set_timeout(sock->ssl, TLS_DEFAULT_TIMEOUT);

    return 0;
}

int sock_tls_tcp_connect(sock_tls_tcp_t *sock, const sock_tcp_ep_t *remote, uint16_t local_port, uint16_t flags)
{
    if (!sock || !remote) {
        return -EINVAL;
    }

    int ret;

    /* Establish a TCP connection */
    ret = sock_tcp_connect(&sock->tcp_sock, remote, local_port, flags);
    if (ret < 0) {
        DEBUG("Failed to establish TCP connection: %d\n", ret);
        return ret;  // Return the actual error code from sock_tcp_connect
    }

    /* Associate the socket file descriptor with the SSL object */
    wolfSSL_set_fd(sock->ssl, sock->tcp_sock.conn);

    /* Start the TLS handshake */
    ret = wolfSSL_connect(sock->ssl);
    if (ret != SSL_SUCCESS) {
        int err = wolfSSL_get_error(sock->ssl, ret);
        DEBUG("TLS handshake failed: %d\n", err);
        sock_tcp_disconnect(&sock->tcp_sock);
        return -ECONNRESET;
    }

    return 0;
}

int sock_tls_tcp_listen(sock_tls_tcp_queue_t *tls_queue, const sock_tcp_ep_t *local,
                       sock_tcp_t *queue_array, unsigned queue_len, uint16_t flags,
                       WOLFSSL_METHOD *method)
{
    if (!tls_queue || !local || !queue_array || queue_len == 0 || !method) {
        return -EINVAL;
    }

    int ret;

    /* Store the method and create a context */
    tls_queue->method = method;
    tls_queue->ctx = wolfSSL_CTX_new(method);
    if (!tls_queue->ctx) {
        DEBUG("Failed to create wolfSSL context\n");
        return -ENOMEM;
    }

    /* Start the TCP listener */
    ret = sock_tcp_listen(&tls_queue->tcp_queue, local, queue_array, queue_len, flags);
    if (ret < 0) {
        DEBUG("Failed to start TCP listening: %d\n", ret);
        wolfSSL_CTX_free(tls_queue->ctx);
        tls_queue->ctx = NULL;
        return ret;
    }

    return 0;
}

int sock_tls_tcp_accept(sock_tls_tcp_queue_t *tls_queue, sock_tls_tcp_t **sock, uint32_t timeout)
{
    if (!tls_queue || !sock) {
        return -EINVAL;
    }

    /* Get the method stored during listen */
    WOLFSSL_METHOD *method = tls_queue->method;
    if (!method) {
        DEBUG("No SSL method provided for TLS accept\n");
        return -EINVAL;
    }

    /* Accept a new TCP connection */
    sock_tcp_t *new_sock;
    int ret = sock_tcp_accept(&tls_queue->tcp_queue, &new_sock, timeout);
    if (ret < 0) {
        DEBUG("TCP accept failed: %d\n", ret);
        return ret;  // Return actual error code
    }

    /* Create a new TLS socket */
    *sock = malloc(sizeof(sock_tls_tcp_t));
    if (!*sock) {
        sock_tcp_disconnect(new_sock);
        return -ENOMEM;
    }
    memset(*sock, 0, sizeof(sock_tls_tcp_t));
    (*sock)->tcp_sock = *new_sock;

    /* Use the pre-created context from the queue */
    (*sock)->ctx = wolfSSL_CTX_new(method);
    if (!(*sock)->ctx) {
        DEBUG("Failed to create WolfSSL context\n");
        sock_tcp_disconnect(&(*sock)->tcp_sock);
        free(*sock);
        return -ENOMEM;
    }

    /* Create a new SSL session */
    (*sock)->ssl = wolfSSL_new((*sock)->ctx);
    if (!(*sock)->ssl) {
        DEBUG("Failed to create WolfSSL session\n");
        wolfSSL_CTX_free((*sock)->ctx);
        sock_tcp_disconnect(&(*sock)->tcp_sock);
        free(*sock);
        return -ENOMEM;
    }

    /* Associate the socket file descriptor with the SSL object */
    wolfSSL_set_fd((*sock)->ssl, (*sock)->tcp_sock.conn);

    /* Set the timeout for the SSL session */
    wolfSSL_set_timeout((*sock)->ssl, TLS_DEFAULT_TIMEOUT);

    /* Accept TLS connection (perform handshake) */
    ret = wolfSSL_accept((*sock)->ssl);
    if (ret != SSL_SUCCESS) {
        int err = wolfSSL_get_error((*sock)->ssl, ret);
        DEBUG("TLS handshake failed: %d\n", err);
        wolfSSL_free((*sock)->ssl);
        wolfSSL_CTX_free((*sock)->ctx);
        sock_tcp_disconnect(&(*sock)->tcp_sock);
        free(*sock);
        return -ECONNRESET;
    }

    return 0;
}

ssize_t sock_tls_tcp_read(sock_tls_tcp_t *sock, void *data, size_t max_len, uint32_t timeout)
{
    if (!sock || !data || max_len == 0) {
        return -EINVAL;
    }

    /* Read data using wolfSSL_read */
    ssize_t bytes_read = wolfSSL_read(sock->ssl, data, max_len);
    if (bytes_read < 0) {
        int err = wolfSSL_get_error(sock->ssl, bytes_read);
        DEBUG("Error while reading data: %d\n", err);
        return -ECONNRESET;
    }

    return bytes_read;
}

ssize_t sock_tls_tcp_write(sock_tls_tcp_t *sock, const void *data, size_t len)
{
    if (!sock || !data || len == 0) {
        return -EINVAL;
    }

    /* Write data using wolfSSL_write */
    ssize_t bytes_written = wolfSSL_write(sock->ssl, data, len);
    if (bytes_written < 0) {
        int err = wolfSSL_get_error(sock->ssl, bytes_written);
        DEBUG("Error while writing data: %d\n", err);
        return -ECONNRESET;
    }

    return bytes_written;
}

void sock_tls_tcp_disconnect(sock_tls_tcp_t *sock)
{
    if (sock) {
        wolfSSL_shutdown(sock->ssl);
        wolfSSL_free(sock->ssl);
        wolfSSL_CTX_free(sock->ctx);
        sock_tcp_disconnect(&sock->tcp_sock);
        free(sock);
    }
}

int sock_tls_tcp_set_cert_key(sock_tls_tcp_t *sock, const unsigned char *cert_buf, unsigned int cert_len, const unsigned char *key_buf, unsigned int key_len, int type)
{
    if (!sock || !cert_buf || cert_len == 0 || !key_buf || key_len == 0) {
        return -EINVAL;
    }

    /* Load certificate and key */
    int ret = wolfSSL_use_certificate_buffer(sock->ssl, cert_buf, cert_len, type);
    if (ret != SSL_SUCCESS) {
        DEBUG("Failed to load certificate: %d\n", ret);
        return -EINVAL;
    }

    ret = wolfSSL_use_PrivateKey_buffer(sock->ssl, key_buf, key_len, type);
    if (ret != SSL_SUCCESS) {
        DEBUG("Failed to load private key: %d\n", ret);
        return -EINVAL;
    }

    return 0;
}

void sock_tls_tcp_set_timeout(sock_tls_tcp_t *sock, unsigned int timeout)
{
    if (sock) {
        wolfSSL_set_timeout(sock->ssl, timeout);
    }
}
