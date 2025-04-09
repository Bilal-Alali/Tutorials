#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "net/sock/tcp.h"
#include "tls.h"
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include "ztimer.h"
#include "debug.h"

/* Default TLS read/write timeout in milliseconds -> 30 sec */
#define TLS_DEFAULT_TIMEOUT 30000

/* Custom I/O functions for WolfSSL to work with RIOT OS sockets */
static int _wolfssl_tcp_receive(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    sock_tls_tcp_t* sock = (sock_tls_tcp_t*)ctx;

    /* Use RIOT's sock TCP API for reading */
    int ret = sock_tcp_read(&sock->tcp_sock, buf, sz, 0);

    if (ret < 0) {
        /* Map RIOT OS error codes to WolfSSL error codes */
        switch (ret) {
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

    return ret; /* Return number of bytes read */
}

static int _wolfssl_tcp_send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    sock_tls_tcp_t* sock = (sock_tls_tcp_t*)ctx;

    /* Use RIOT's sock TCP API for writing */
    int ret = sock_tcp_write(&sock->tcp_sock, buf, sz);

    if (ret < 0) {
        /* Map RIOT OS error codes to WolfSSL error codes */
        switch (ret) {
            case -ETIMEDOUT:
                return WOLFSSL_CBIO_ERR_TIMEOUT;
            case -ECONNRESET:
            case -ECONNABORTED:
                return WOLFSSL_CBIO_ERR_CONN_RST;
            default:
                return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }

    return ret; /* Return number of bytes written */
}

int sock_tls_tcp_create(sock_tls_tcp_t *sock, WOLFSSL_METHOD *method)
{
    if (!sock || !method) {
        return -EINVAL;
    }

    memset(sock, 0, sizeof(sock_tls_tcp_t));

    // Set default values for essential fields
    sock->tcp_sock.address_family= AF_INET6; // Set to IPv6 (or AF_INET for IPv4)
    sock->tcp_sock.local_port = 0;         // Use 0 for random local port

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

    return 0;
}

/* Complete connection function */
int sock_tls_tcp_connect(sock_tls_tcp_t *sock, const sock_tcp_ep_t *remote,
                         uint16_t local_port, uint16_t flags,
                         const unsigned char *cert_buf, unsigned int cert_len,
                         const unsigned char *key_buf, unsigned int key_len)
{
    if (!sock || !remote) {
        return -EINVAL;
    }

    int ret;

    /* Debugging: Show target details */
    char addr_str[IPV6_ADDR_MAX_STR_LEN];
    ipv6_addr_to_str(addr_str, (ipv6_addr_t *)&remote->addr.ipv6, sizeof(addr_str));
    printf("Connecting to remote server at [%s]:%d\n", addr_str, remote->port);

    /* Establish a TCP connection */
    ret = sock_tcp_connect(&sock->tcp_sock, remote, local_port, flags);
    if (ret < 0) {
        printf("Failed to establish TCP connection: %d\n", ret);
        return ret; // Return the actual error code from sock_tcp_connect
    }

    printf("TCP connection established.\n");

    /* Set the certificate and private key */
    ret = sock_tls_tcp_set_cert_key(sock, cert_buf, cert_len, key_buf, key_len);
    if (ret != 0) {
        printf("Failed to set certificate and private key: %d\n", ret);
        sock_tcp_disconnect(&sock->tcp_sock); // Clean up the TCP connection
        return ret;
    }

    /* Set the custom I/O context for WolfSSL */
    wolfSSL_SetIOReadCtx(sock->ssl, sock);
    wolfSSL_SetIOWriteCtx(sock->ssl, sock);

    /* Set the timeout for the SSL session */
    wolfSSL_set_timeout(sock->ssl, TLS_DEFAULT_TIMEOUT / 1000); // Convert ms to seconds

    /* Start the TLS handshake */
    printf("Starting TLS handshake...\n");
    ret = wolfSSL_connect(sock->ssl);
    if (ret != SSL_SUCCESS) {
        int err = wolfSSL_get_error(sock->ssl, ret);
        printf("TLS handshake failed: %d, error: %s\n", err, wolfSSL_ERR_reason_error_string(err));
        sock_tcp_disconnect(&sock->tcp_sock); // Clean up the TCP connection
        return -ECONNRESET; // Return connection reset
    }

    printf("TLS handshake completed successfully!\n");
    return 0; // Success
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

    /* Register the custom I/O functions with the context */
    wolfSSL_SetIORecv(tls_queue->ctx, _wolfssl_tcp_receive);
    wolfSSL_SetIOSend(tls_queue->ctx, _wolfssl_tcp_send);

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
    (*sock)->ctx = tls_queue->ctx;

    /* Create a new SSL session */
    (*sock)->ssl = wolfSSL_new((*sock)->ctx);
    if (!(*sock)->ssl) {
        DEBUG("Failed to create WolfSSL session\n");
        sock_tcp_disconnect(&(*sock)->tcp_sock);
        free(*sock);
        *sock = NULL;
        return -ENOMEM;
    }

    /* Set the custom context object */
    wolfSSL_SetIOReadCtx((*sock)->ssl, *sock);
    wolfSSL_SetIOWriteCtx((*sock)->ssl, *sock);

    /* Set the timeout for the SSL session */
    wolfSSL_set_timeout((*sock)->ssl, TLS_DEFAULT_TIMEOUT / 1000); // Convert ms to seconds

    /* Accept TLS connection (perform handshake) */
    ret = wolfSSL_accept((*sock)->ssl);
    if (ret != SSL_SUCCESS) {
        int err = wolfSSL_get_error((*sock)->ssl, ret);
        DEBUG("TLS handshake failed: %d\n", err);
        wolfSSL_free((*sock)->ssl);
        sock_tcp_disconnect(&(*sock)->tcp_sock);
        free(*sock);
        *sock = NULL;
        return -ECONNRESET;
    }

    return 0;
}

ssize_t sock_tls_tcp_read(sock_tls_tcp_t *sock, void *data, size_t max_len)
{
    if (!sock || !data || max_len == 0) {
        return -EINVAL;
    }

    // Since our header doesn't include timeout parameter, we'll need to adapt
    // Set a read timeout for the underlying TCP socket if needed
    // This would require RIOT OS support for socket-level timeouts

    /* Read data using wolfSSL_read */
    ssize_t bytes_read = wolfSSL_read(sock->ssl, data, max_len);
    if (bytes_read < 0) {
        int err = wolfSSL_get_error(sock->ssl, bytes_read);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            // Would block, could be handled with timeout
            return -ETIMEDOUT;
        }
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
        if (sock->ssl) {
            wolfSSL_shutdown(sock->ssl);
            wolfSSL_free(sock->ssl);
            sock->ssl = NULL;
        }

        if (sock->ctx) {
            wolfSSL_CTX_free(sock->ctx);
            sock->ctx = NULL;
        }

        sock_tcp_disconnect(&sock->tcp_sock);
    }
}

int sock_tls_tcp_set_cert_key(sock_tls_tcp_t *sock,
                             const unsigned char *cert_buf, unsigned int cert_len,
                             const unsigned char *key_buf, unsigned int key_len)
{
    if (!sock || !cert_buf || cert_len == 0 || !key_buf || key_len == 0) {
        return -EINVAL;
    }

    /* Load certificate */
    int ret = wolfSSL_use_certificate_buffer(sock->ssl, cert_buf, cert_len, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        printf("Failed to load certificate: %d, error: %s\n", ret, wolfSSL_ERR_reason_error_string(ret));
        return ret; // Return specific WolfSSL error code
    }

    /* Load private key */
    ret = wolfSSL_use_PrivateKey_buffer(sock->ssl, key_buf, key_len, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        printf("Failed to load private key: %d, error: %s\n", ret, wolfSSL_ERR_reason_error_string(ret));
        return ret; // Return specific WolfSSL error code
    }

    /* Verify that the certificate and private key match */
    if (wolfSSL_CTX_check_private_key(sock->ctx) != SSL_SUCCESS) {
        printf("Certificate and private key do not match\n");
        return -EINVAL;
    }

    printf("Certificate and private key successfully loaded and verified.\n");
    return 0;
}

void sock_tls_tcp_set_timeout(sock_tls_tcp_t *sock, unsigned int timeout)
{
    if (sock && sock->ssl) {
        // WolfSSL expects timeout in seconds, so convert if needed
        unsigned int timeout_sec = timeout / 1000; // Convert from ms to seconds
        wolfSSL_set_timeout(sock->ssl, timeout_sec);
    }
}
