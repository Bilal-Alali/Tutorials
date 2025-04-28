/**
 * @file tls.c
 * @brief Implementation of TLS over TCP socket using wolfSSL for RIOT OS
 * @author Bilal-Alali
 * @date 2025-04-25 09:15:30
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "net/sock/tcp.h"
#include "tls.h"
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include "ztimer.h"
#include "debug.h"

#define TLS_DEFAULT_TIMEOUT (60000)  // 30 seconds

static int _wolfssl_tcp_receive(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    sock_tls_tcp_t *sock = (sock_tls_tcp_t *)ctx;
    int ret;

    ret = sock_tcp_read(&sock->tcp_sock, buf, sz, TLS_DEFAULT_TIMEOUT);

    if (ret < 0) {
        if (ret == -ETIMEDOUT) {
            printf("TCP Read timeout after %d ms\n", (int)TLS_DEFAULT_TIMEOUT);
            return WOLFSSL_CBIO_ERR_WANT_READ;  // Changed from GENERAL to WANT_READ
        }
        printf("TCP Read error: %d\n", ret);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    return ret;
}

static int _wolfssl_tcp_send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    sock_tls_tcp_t *sock = (sock_tls_tcp_t *)ctx;
    int ret;

    ret = sock_tcp_write(&sock->tcp_sock, buf, sz);

    if (ret < 0) {
        printf("TCP Send error: %d\n", ret);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    return ret;
}

int sock_tls_tcp_create(sock_tls_tcp_t *sock, WOLFSSL_METHOD *method)
{
    if (!sock || !method) {
        return -EINVAL;
    }

    memset(sock, 0, sizeof(sock_tls_tcp_t));

    sock->ctx = wolfSSL_CTX_new(method);
    if (!sock->ctx) {
        return -ENOMEM;
    }

    wolfSSL_SetIORecv(sock->ctx, _wolfssl_tcp_receive);
    wolfSSL_SetIOSend(sock->ctx, _wolfssl_tcp_send);

    /* For clients: disable certificate verification */
    if (method == wolfTLSv1_2_client_method()) {
        wolfSSL_CTX_set_verify(sock->ctx, SSL_VERIFY_NONE, NULL);
    }

    sock->ssl = wolfSSL_new(sock->ctx);
    if (!sock->ssl) {
        wolfSSL_CTX_free(sock->ctx);
        sock->ctx = NULL;
        return -ENOMEM;
    }

    return 0;
}


int sock_tls_tcp_connect(sock_tls_tcp_t *sock, const sock_tcp_ep_t *remote,
                        uint16_t local_port, uint16_t flags)
{
    if (!sock || !remote) {
        return -EINVAL;
    }

    printf("Client: Attempting TCP connection...\n");
    int ret = sock_tcp_connect(&sock->tcp_sock, remote, local_port, flags);
    if (ret < 0) {
        printf("Client: TCP connection failed: %d\n", ret);
        return ret;
    }
    printf("Client: TCP connection established\n");

    // Setup SSL/TLS
    wolfSSL_SetIOReadCtx(sock->ssl, sock);
    wolfSSL_SetIOWriteCtx(sock->ssl, sock);

    // Disable certificate verification
    wolfSSL_set_verify(sock->ssl, SSL_VERIFY_NONE, 0);

    // Set cipher suite
    const char* cipher_list = "AES128-SHA256";
    if (wolfSSL_set_cipher_list(sock->ssl, cipher_list) != SSL_SUCCESS) {
        printf("Client: Failed to set cipher list\n");
        sock_tcp_disconnect(&sock->tcp_sock);
        return -EINVAL;
    }

    printf("Client: Starting TLS handshake...\n");
    ret = wolfSSL_connect(sock->ssl);
    if (ret != SSL_SUCCESS) {
        int err = wolfSSL_get_error(sock->ssl, ret);
        printf("Client: SSL connect error: %d (0x%x)\n", err, err);
        char error_string[80];
        wolfSSL_ERR_error_string(err, error_string);
        printf("Client: Error details: %s\n", error_string);
        sock_tcp_disconnect(&sock->tcp_sock);
        return -ECONNRESET;
    }

    printf("Client: TLS connection established\n");
    printf("Client: Using cipher: %s\n", wolfSSL_get_cipher(sock->ssl));
    return 0;
}
int sock_tls_tcp_listen(sock_tls_tcp_queue_t *queue, const sock_tcp_ep_t *local,
                       sock_tcp_t *queue_array, unsigned queue_len, uint16_t flags,
                       WOLFSSL_METHOD *method, const unsigned char *cert_buf,
                       unsigned int cert_len, const unsigned char *key_buf,
                       unsigned int key_len)
{
    if (!queue || !local || !queue_array || queue_len == 0 || !method ||
        !cert_buf || !cert_len || !key_buf || !key_len) {
        return -EINVAL;
    }

    queue->ctx = wolfSSL_CTX_new(method);
    if (!queue->ctx) {
        return -ENOMEM;
    }

    // Set cipher list first
    if (wolfSSL_CTX_set_cipher_list(queue->ctx, "AES128-SHA256") != SSL_SUCCESS) {
        wolfSSL_CTX_free(queue->ctx);
        return -EINVAL;
    }

    // Set IO callbacks
    wolfSSL_SetIORecv(queue->ctx, _wolfssl_tcp_receive);
    wolfSSL_SetIOSend(queue->ctx, _wolfssl_tcp_send);

    // Disable certificate verification
    wolfSSL_CTX_set_verify(queue->ctx, SSL_VERIFY_NONE, 0);

    // Load certificate
    if (wolfSSL_CTX_use_certificate_buffer(queue->ctx, cert_buf, cert_len,
                                         SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        wolfSSL_CTX_free(queue->ctx);
        return -EINVAL;
    }

    // Load private key
    if (wolfSSL_CTX_use_PrivateKey_buffer(queue->ctx, key_buf, key_len,
                                         SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        wolfSSL_CTX_free(queue->ctx);
        return -EINVAL;
    }

    return sock_tcp_listen(&queue->tcp_queue, local, queue_array, queue_len, flags);
}

int sock_tls_tcp_accept(sock_tls_tcp_queue_t *queue, sock_tls_tcp_t **sock,
                       uint32_t timeout)
{
    int ret;
    sock_tcp_t *tcp_sock = NULL;

    if (!queue || !sock) {
        return -EINVAL;
    }

    printf("Server: Waiting for TCP connection...\n");
    ret = sock_tcp_accept(&queue->tcp_queue, &tcp_sock, timeout);
    if (ret < 0) {
        printf("Server: TCP accept failed: %d\n", ret);
        return ret;
    }
    printf("Server: TCP connection accepted\n");

    *sock = malloc(sizeof(sock_tls_tcp_t));
    if (!*sock) {
        sock_tcp_disconnect(tcp_sock);
        return -ENOMEM;
    }

    (*sock)->tcp_sock = *tcp_sock;
    (*sock)->ssl = wolfSSL_new(queue->ctx);
    if (!(*sock)->ssl) {
        free(*sock);
        sock_tcp_disconnect(tcp_sock);
        return -ENOMEM;
    }

    wolfSSL_SetIOReadCtx((*sock)->ssl, *sock);
    wolfSSL_SetIOWriteCtx((*sock)->ssl, *sock);

    printf("Server: Starting TLS handshake...\n");
    ret = wolfSSL_accept((*sock)->ssl);
    if (ret != SSL_SUCCESS) {
        int err = wolfSSL_get_error((*sock)->ssl, ret);
        printf("Server: SSL accept error: %d\n", err);
        wolfSSL_free((*sock)->ssl);
        free(*sock);
        sock_tcp_disconnect(tcp_sock);
        return -EPROTO;
    }

    printf("Server: TLS handshake successful\n");
    printf("Server: Using cipher: %s\n", wolfSSL_get_cipher((*sock)->ssl));
    return 0;
}

ssize_t sock_tls_tcp_read(sock_tls_tcp_t *sock, void *data, size_t max_len)
{
    if (!sock || !data || max_len == 0) {
        return -EINVAL;
    }

    int ret = wolfSSL_read(sock->ssl, data, max_len);
    if (ret <= 0) {
        int err = wolfSSL_get_error(sock->ssl, ret);
        if (err == SSL_ERROR_ZERO_RETURN) {
            return 0;  /* Connection closed normally */
        }
        return -ECONNRESET;
    }

    return ret;
}

ssize_t sock_tls_tcp_write(sock_tls_tcp_t *sock, const void *data, size_t len)
{
    if (!sock || !data || len == 0) {
        return -EINVAL;
    }

    int ret = wolfSSL_write(sock->ssl, data, len);
    if (ret <= 0) {
        return -ECONNRESET;
    }

    return ret;
}

void sock_tls_tcp_disconnect(sock_tls_tcp_t *sock)
{
    if (!sock) {
        return;
    }

    if (sock->ssl) {
        wolfSSL_shutdown(sock->ssl);
        wolfSSL_free(sock->ssl);
        sock->ssl = NULL;
    }

    sock_tcp_disconnect(&sock->tcp_sock);
}
