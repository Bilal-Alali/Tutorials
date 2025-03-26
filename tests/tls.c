
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "net/sock/tcp.h"
#include "tls.h"
#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#include "ztimer.h"
#include "log.h"
#include <errno.h>
#include "debug.h"
#include "wolfssl/ssl.h"
#include "wolfssl/error-ssl.h"
/* Default TLS read/write timeout in milliseconds -> 30 sec*/
#define TLS_DEFAULT_TIMEOUT 30000

static int _wolfssl_tcp_receive(WOLFSSL *ssl, char *buf, int sz, void *ctx);
static int _wolfssl_tcp_send(WOLFSSL *ssl, char *buf, int sz, void *ctx);

/* Callbacks for wolfSSL I/O operations */
static GetTcpRecvTimeoutCallback get_tcp_recv_timeout_callback = NULL;

/**
 * @brief Set callback function for TCP receive timeout (man bekommt den Timeout dynamisch)
 */
void sock_tls_tcp_set_recv_timeout_callback(GetTcpRecvTimeoutCallback callback)
{
    get_tcp_recv_timeout_callback = callback;
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

    /* Create a new SSL session */
    sock->ssl = wolfSSL_new(sock->ctx);
    if (!sock->ssl) {
        DEBUG("Failed to create WolfSSL session\n");
        wolfSSL_CTX_free(sock->ctx);
        sock->ctx = NULL;
        return -ENOMEM;
    }

    /* Set the custom I/O functions */
    wolfSSL_CTX_SetIORecv(sock->ctx, _wolfssl_tcp_receive);
    wolfSSL_CTX_SetIOSend(sock->ctx, _wolfssl_tcp_send);


    /* Set the custom context object */
    wolfSSL_SetIOReadCtx(sock->ssl, sock);
    wolfSSL_SetIOWriteCtx(sock->ssl, sock);

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

    /* Set the custom I/O functions */
    wolfSSL_CTX_SetIORecv((*sock)->ctx, _wolfssl_tcp_receive);
    wolfSSL_CTX_SetIOSend((*sock)->ctx, _wolfssl_tcp_send);

    /* Set the custom context object */
    wolfSSL_SetIOReadCtx((*sock)->ssl, *sock);
    wolfSSL_SetIOWriteCtx((*sock)->ssl, *sock);

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
    (void)ctx; // Marked 'ctx' as unused
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
