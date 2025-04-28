#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "net/sock/tcp.h"
#include "tls.h"
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include "ztimer.h"
#include "debug.h"

/* Custom I/O functions for WolfSSL to work with RIOT OS sockets */
static int _wolfssl_tcp_receive(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    sock_tls_tcp_t* sock = (sock_tls_tcp_t*)ctx;

    /* Use RIOT's sock TCP API for reading (non-blocking) */
    int ret = sock_tcp_read(&sock->tcp_sock, buf, sz, 0);

    if (ret < 0) {
        switch (ret) {
            case -EAGAIN:
                return WOLFSSL_CBIO_ERR_WANT_READ;
            case -ETIMEDOUT:
                return WOLFSSL_CBIO_ERR_TIMEOUT;
            case -ECONNRESET:
            case -ECONNABORTED:
                return WOLFSSL_CBIO_ERR_CONN_RST;
            case -ECONNREFUSED:
                return WOLFSSL_CBIO_ERR_WANT_READ;
            default:
                return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    return ret;
}

static int _wolfssl_tcp_send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    sock_tls_tcp_t* sock = (sock_tls_tcp_t*)ctx;

    /* Use RIOT's sock TCP API for writing (non-blocking) */
    int ret = sock_tcp_write(&sock->tcp_sock, buf, sz);

    if (ret < 0) {
        switch (ret) {
            case -EAGAIN:
                return WOLFSSL_CBIO_ERR_WANT_WRITE;
            case -ETIMEDOUT:
                return WOLFSSL_CBIO_ERR_TIMEOUT;
            case -ECONNRESET:
            case -ECONNABORTED:
                return WOLFSSL_CBIO_ERR_CONN_RST;
            default:
                return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    return ret;
}

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

    /* Register the custom I/O functions with the context */
    wolfSSL_SetIORecv(sock->ctx, _wolfssl_tcp_receive);
    wolfSSL_SetIOSend(sock->ctx, _wolfssl_tcp_send);

    /* Create a new SSL session */
    sock->ssl = wolfSSL_new(sock->ctx);
    if (!sock->ssl) {
        DEBUG("Failed to create WolfSSL session\n");
        wolfSSL_CTX_free(sock->ctx);
        sock->ctx = NULL;
        return -ENOMEM;
    }

    sock->is_handshake_done = false;
    sock->is_connecting = false;

    return 0;
}

int sock_tls_tcp_connect(sock_tls_tcp_t *sock, const sock_tcp_ep_t *remote,
                        uint16_t local_port, uint16_t flags,
                        const unsigned char *cert_buf, unsigned int cert_len,
                        const unsigned char *key_buf, unsigned int key_len)
{
    if (!sock || !remote) {
        return -EINVAL;
    }

    int ret;

    /* Start TCP connection (non-blocking) */
    ret = sock_tcp_connect(&sock->tcp_sock, remote, local_port, flags);
    if (ret < 0 && ret != -EINPROGRESS) {
        printf("Failed to establish TCP connection: %d\n", ret);
        return ret;
    }

    sock->is_connecting = true;

    /* Set the custom I/O context for WolfSSL */
    wolfSSL_SetIOReadCtx(sock->ssl, sock);
    wolfSSL_SetIOWriteCtx(sock->ssl, sock);

    return -EINPROGRESS;
}

int sock_tls_tcp_handshake(sock_tls_tcp_t *sock)
{
    if (!sock || !sock->ssl) {
        return -EINVAL;
    }

    if (sock->is_handshake_done) {
        return 0;  /* Handshake already completed */
    }

    /* Check if TCP connection is still in progress by trying a zero-length read */
    if (sock->is_connecting) {
        char dummy;
        int ret = sock_tcp_read(&sock->tcp_sock, &dummy, 0, 0);
        if (ret == -EAGAIN) {
            return -EAGAIN;  /* Connection still in progress */
        }
        else if (ret < 0 && ret != -ECONNRESET) {
            /* Connection failed */
            return ret;
        }
        /* Connection established */
        sock->is_connecting = false;
    }

    /* Perform TLS handshake step */
    int ret = wolfSSL_connect(sock->ssl);
    if (ret != SSL_SUCCESS) {
        int err = wolfSSL_get_error(sock->ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return -EAGAIN;
        }
        printf("TLS handshake failed: %d, error: %s\n",
               err, wolfSSL_ERR_reason_error_string(err));
        return -ECONNRESET;
    }

    sock->is_handshake_done = true;
    return 0;
}

ssize_t sock_tls_tcp_read(sock_tls_tcp_t *sock, void *data, size_t max_len)
{
    if (!sock || !data || max_len == 0) {
        return -EINVAL;
    }

    if (!sock->is_handshake_done) {
        return -ENOTCONN;
    }

    ssize_t ret = wolfSSL_read(sock->ssl, data, max_len);
    if (ret < 0) {
        int err = wolfSSL_get_error(sock->ssl, ret);
        if (err == SSL_ERROR_WANT_READ) {
            return -EAGAIN;
        }
        DEBUG("Error while reading data: %d\n", err);
        return -ECONNRESET;
    }

    return ret;
}

ssize_t sock_tls_tcp_write(sock_tls_tcp_t *sock, const void *data, size_t len)
{
    if (!sock || !data || len == 0) {
        return -EINVAL;
    }

    if (!sock->is_handshake_done) {
        return -ENOTCONN;
    }

    ssize_t ret = wolfSSL_write(sock->ssl, data, len);
    if (ret < 0) {
        int err = wolfSSL_get_error(sock->ssl, ret);
        if (err == SSL_ERROR_WANT_WRITE) {
            return -EAGAIN;
        }
        DEBUG("Error while writing data: %d\n", err);
        return -ECONNRESET;
    }

    return ret;
}

void sock_tls_tcp_disable_cert_verify(sock_tls_tcp_t *sock)
{
    if (sock && sock->ctx) {
        wolfSSL_CTX_set_verify(sock->ctx, SSL_VERIFY_NONE, NULL);
        printf("Warning: Certificate verification disabled!\n");
    }
}
