#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "net/sock/tcp.h"
#include "ztimer.h"
#include "tls_tcp.h"

/**
 * @brief Global state for module initialization
 */
static int initialized = 0;

/* Custom send and receive functions for WolfSSL */
static int wolfssl_send(WOLFSSL *ssl, char *buf, int sz, void *ctx);
static int wolfssl_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx);

/**
 * @brief Initialize the TLS module
 */
int sock_tls_tcp_init(void)
{
    if (initialized) {
        printf("[TLS]: Module already initialized\n");
        return 0;
    }

    wolfSSL_Init();
    printf("[TLS]: WolfSSL initialized\n");

    initialized = 1;
    return 0;
}

/**
 * @brief Create a new TLS socket
 */
int sock_tls_tcp_create(sock_tls_tcp_t *sock, WOLFSSL_METHOD *method,
                        const char *ca_cert, const char *device_cert, const char *private_key)
{
    if (!initialized) {
        printf("[TLS]: Module not initialized\n");
        return -1;
    }

    if (!sock || !method) {
        printf("[TLS]: Invalid socket structure or method\n");
        return -1;
    }

    /* Initialize the TCP socket */
    memset(sock, 0, sizeof(sock_tls_tcp_t));
    if (sock_tcp_create(&sock->tcp_sock) < 0) {
        printf("[TLS]: Failed to create TCP socket\n");
        return -1;
    }

    /* Create the WolfSSL context */
    sock->ctx = wolfSSL_CTX_new(method);
    if (!sock->ctx) {
        printf("[TLS]: Failed to create WolfSSL context\n");
        sock_tcp_destroy(&sock->tcp_sock);
        return -1;
    }

    /* Load certificates and private key */
    if (ca_cert && wolfSSL_CTX_load_verify_buffer(sock->ctx, (const unsigned char *)ca_cert,
                                                  strlen(ca_cert), SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        printf("[TLS]: Failed to load CA certificate\n");
        sock_tls_tcp_destroy(sock);
        return -1;
    }

    if (device_cert && wolfSSL_CTX_use_certificate_buffer(sock->ctx, (const unsigned char *)device_cert,
                                                          strlen(device_cert), SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        printf("[TLS]: Failed to load device certificate\n");
        sock_tls_tcp_destroy(sock);
        return -1;
    }

    if (private_key && wolfSSL_CTX_use_PrivateKey_buffer(sock->ctx, (const unsigned char *)private_key,
                                                         strlen(private_key), SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        printf("[TLS]: Failed to load private key\n");
        sock_tls_tcp_destroy(sock);
        return -1;
    }

    printf("[TLS]: TLS socket created successfully\n");
    return 0;
}

/**
 * @brief Accept a new TLS connection (server-side)
 */
int sock_tls_tcp_accept(sock_tls_tcp_t *server_sock, sock_tls_tcp_t *client_sock)
{
    if (!server_sock || !client_sock) {
        printf("[TLS]: Invalid server or client socket\n");
        return -1;
    }

    /* Accept a new TCP connection */
    if (sock_tcp_accept(&server_sock->tcp_sock, &client_sock->tcp_sock) < 0) {
        printf("[TLS]: Failed to accept TCP connection\n");
        return -1;
    }

    /* Create a new WolfSSL session for the client */
    client_sock->ssl = wolfSSL_new(server_sock->ctx);
    if (!client_sock->ssl) {
        printf("[TLS]: Failed to create WolfSSL session for client\n");
        sock_tcp_disconnect(&client_sock->tcp_sock);
        return -1;
    }

    /* Set the custom I/O callbacks */
    wolfSSL_SetIO_Send(client_sock->ssl, wolfssl_send);
    wolfSSL_SetIO_Recv(client_sock->ssl, wolfssl_recv);

    /* Associate the client socket with the WolfSSL session */
    wolfSSL_SetIOReadCtx(client_sock->ssl, &client_sock->tcp_sock);
    wolfSSL_SetIOWriteCtx(client_sock->ssl, &client_sock->tcp_sock);

    /* Perform the SSL/TLS handshake */
    if (wolfSSL_accept(client_sock->ssl) != SSL_SUCCESS) {
        int err = wolfSSL_get_error(client_sock->ssl, 0);
        char err_str[80];
        wolfSSL_ERR_error_string(err, err_str);
        printf("[TLS]: SSL handshake failed: %s\n", err_str);
        sock_tls_tcp_disconnect(client_sock);
        return -1;
    }

    printf("[TLS]: Client connection accepted successfully\n");
    return 0;
}

/**
 * @brief Establish a TLS connection to the given host and port (client-side)
 */
int sock_tls_tcp_connect(sock_tls_tcp_t *sock, const char *host, uint16_t port)
{
    if (!sock) {
        printf("[TLS]: Invalid socket structure\n");
        return -1;
    }

    sock_tcp_ep_t remote = SOCK_IPV6_EP_ANY;
    remote.port = port;

    if (ipv6_addr_from_str((ipv6_addr_t *)&remote.addr, host) == NULL) {
        printf("[TLS]: Invalid host address\n");
        return -1;
    }

    /* Connect the TCP socket */
    printf("[TLS]: Connecting to %s:%d\n", host, port);
    if (sock_tcp_connect(&sock->tcp_sock, &remote, 0, 0) < 0) {
        printf("[TLS]: Failed to connect TCP socket\n");
        return -1;
    }

    /* Create a new WolfSSL session */
    sock->ssl = wolfSSL_new(sock->ctx);
    if (!sock->ssl) {
        printf("[TLS]: Failed to create WolfSSL session\n");
        sock_tcp_disconnect(&sock->tcp_sock);
        return -1;
    }

    /* Set the custom I/O callbacks */
    wolfSSL_SetIO_Send(sock->ssl, wolfssl_send);
    wolfSSL_SetIO_Recv(sock->ssl, wolfssl_recv);

    /* Associate the TCP socket with the WolfSSL session */
    wolfSSL_SetIOReadCtx(sock->ssl, &sock->tcp_sock);
    wolfSSL_SetIOWriteCtx(sock->ssl, &sock->tcp_sock);

    /* Perform the SSL/TLS handshake */
    if (wolfSSL_connect(sock->ssl) != SSL_SUCCESS) {
        int err = wolfSSL_get_error(sock->ssl, 0);
        char err_str[80];
        wolfSSL_ERR_error_string(err, err_str);
        printf("[TLS]: SSL handshake failed: %s\n", err_str);
        sock_tls_tcp_disconnect(sock);
        return -1;
    }

    printf("[TLS]: Connected successfully\n");
    return 0;
}

/**
 * @brief Send data over the TLS connection
 */
int sock_tls_tcp_send(sock_tls_tcp_t *sock, const unsigned char *data, size_t len)
{
    if (!sock || !sock->ssl) {
        printf("[TLS]: Invalid TLS socket\n");
        return -1;
    }

    int ret = wolfSSL_write(sock->ssl, data, len);
    if (ret <= 0) {
        int err = wolfSSL_get_error(sock->ssl, ret);
        char err_str[80];
        wolfSSL_ERR_error_string(err, err_str);
        printf("[TLS]: Failed to send data: %s\n", err_str);
        return -1;
    }

    return ret;
}

/**
 * @brief Receive data over the TLS connection
 */
int sock_tls_tcp_receive(sock_tls_tcp_t *sock, unsigned char *buffer, size_t len)
{
    if (!sock || !sock->ssl) {
        printf("[TLS]: Invalid TLS socket\n");
        return -1;
    }

    int ret = wolfSSL_read(sock->ssl, buffer, len);
    if (ret <= 0) {
        int err = wolfSSL_get_error(sock->ssl, ret);
        char err_str[80];
        wolfSSL_ERR_error_string(err, err_str);
        printf("[TLS]: Failed to receive data: %s\n", err_str);
        return -1;
    }

    return ret;
}

/**
 * @brief Disconnect and clean up the TLS socket
 */
void sock_tls_tcp_disconnect(sock_tls_tcp_t *sock)
{
    if (sock && sock->ssl) {
        wolfSSL_free(sock->ssl);
        sock->ssl = NULL;
    }

    sock_tcp_disconnect(&sock->tcp_sock);
    printf("[TLS]: TLS socket disconnected\n");
}

/**
 * @brief Destroy the TLS socket and free resources
 */
void sock_tls_tcp_destroy(sock_tls_tcp_t *sock)
{
    if (sock) {
        if (sock->ssl) {
            wolfSSL_free(sock->ssl);
        }

        if (sock->ctx) {
            wolfSSL_CTX_free(sock->ctx);
        }

        sock_tcp_destroy(&sock->tcp_sock);
        printf("[TLS]: TLS socket destroyed\n");
    }
}

/**
 * @brief Cleanup the TLS module
 */
void sock_tls_tcp_cleanup(void)
{
    if (initialized) {
        wolfSSL_Cleanup();
        initialized = 0;
        printf("[TLS]: WolfSSL cleaned up\n");
    }
}

/* Custom send callback for WolfSSL */
static int wolfssl_send(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    sock_tcp_t *tcp_sock = (sock_tcp_t *)ctx;
    return sock_tcp_send(tcp_sock, buf, sz);
}

/* Custom receive callback for WolfSSL */
static int wolfssl_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    sock_tcp_t *tcp_sock = (sock_tcp_t *)ctx;
    return sock_tcp_recv(tcp_sock, buf, sz, 0);
}
