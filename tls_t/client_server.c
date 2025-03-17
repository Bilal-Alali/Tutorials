#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <wolfssl/ssl.h>
#include "cert_data.h"  // Contains your certificate and key arrays
#include "sock_tls_tcp.h"
#include "net/sock/tcp.h"
#include "ztimer.h"

#define SERVER_PORT 4433
#define QUEUE_LENGTH 5

// Function prototypes
void example_tls_client(const char* server_ip);
void example_tls_server(void);

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <server|client> [server_ip]\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "server") == 0) {
        example_tls_server();
    } else if (strcmp(argv[1], "client") == 0 && argc == 3) {
        example_tls_client(argv[2]);
    } else {
        fprintf(stderr, "Invalid arguments.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void example_tls_client(const char* server_ip) {
    sock_tls_tcp_t tls_sock;
    int ret;
    char buffer[256];

    /* Initialize wolfSSL */
    wolfSSL_Init();

    /* Create TLS socket with client method */
    ret = sock_tls_tcp_create(&tls_sock, wolfTLSv1_2_client_method());
    if (ret != 0) {
        printf("Error creating TLS socket: %d\n", ret);
        return;
    }

    /* Connect to the server */
    printf("Connecting to server %s...\n", server_ip);
    sock_tcp_ep_t remote = {
        .family = AF_INET,
        .port = SERVER_PORT,
        .addr.ipv4 = { .u32 = inet_addr(server_ip) }
    };

    ret = sock_tls_tcp_connect(&tls_sock, &remote, 0, 0);
    if (ret != 0) {
        printf("Error connecting: %d\n", ret);
        sock_tls_tcp_disconnect(&tls_sock);
        return;
    }

    printf("Connected, sending request...\n");

    /* Send HTTP request over TLS */
    const char *request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    ret = sock_tls_tcp_write(&tls_sock, request, strlen(request));
    if (ret < 0) {
        printf("Error writing data: %d\n", ret);
        sock_tls_tcp_disconnect(&tls_sock);
        return;
    }

    /* Read response */
    ret = sock_tls_tcp_read(&tls_sock, buffer, sizeof(buffer) - 1, 5000);
    if (ret > 0) {
        buffer[ret] = '\0';  /* Null-terminate the response */
        printf("Received %d bytes: %s\n", ret, buffer);
    } else {
        printf("Error reading data: %d\n", ret);
    }

    /* Clean up */
    sock_tls_tcp_disconnect(&tls_sock);
    wolfSSL_Cleanup();
}

void example_tls_server(void) {
    sock_tls_tcp_t *tls_sock;
    sock_tcp_queue_t queue;
    sock_tcp_t tcp_sock_queue[1];
    int ret;
    char buffer[256];

    /* Local endpoint for listening */
    sock_tcp_ep_t local = {
        .family = AF_INET,
        .port = SERVER_PORT,
        .addr.ipv4 = { .u32 = INADDR_ANY }
    };

    /* Initialize wolfSSL */
    wolfSSL_Init();

    /* Create TLS server method */
    WOLFSSL_METHOD *server_method = wolfTLSv1_2_server_method();

    /* Set up the listening queue */
    ret = sock_tls_tcp_listen(&queue, &local, tcp_sock_queue,
                             sizeof(tcp_sock_queue)/sizeof(tcp_sock_queue[0]),
                             0, server_method);
    if (ret != 0) {
        printf("Error creating server: %d\n", ret);
        return;
    }

    printf("TLS Server listening on port %d\n", SERVER_PORT);

    /* Accept connections */
    while (1) {
        printf("Waiting for connections...\n");
        ret = sock_tls_tcp_accept(&queue, &tls_sock, SOCK_NO_TIMEOUT);
        if (ret < 0) {
            printf("Error accepting connection: %d\n", ret);
            continue;
        }

        printf("New connection accepted\n");

        /* Set certificate and key for this connection */
        ret = sock_tls_tcp_set_cert_key(tls_sock,
                                      tls_cert_data, tls_cert_len,
                                      tls_key_data, tls_key_len,
                                      SSL_FILETYPE_PEM);
        if (ret != 0) {
            printf("Error setting certificate/key: %d\n", ret);
            sock_tls_tcp_disconnect(tls_sock);
            free(tls_sock);
            continue;
        }

        /* Read request */
        ret = sock_tls_tcp_read(tls_sock, buffer, sizeof(buffer) - 1, 5000);
        if (ret > 0) {
            buffer[ret] = '\0';
            printf("Received: %s\n", buffer);

            /* Send response */
            const char *response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, TLS!\r\n";
            sock_tls_tcp_write(tls_sock, response, strlen(response));
        }

        /* Clean up connection */
        sock_tls_tcp_disconnect(tls_sock);
        free(tls_sock);
    }

    /* Clean up (this point is never reached in this example) */
    wolfSSL_Cleanup();
}
