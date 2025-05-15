/**
 * @file main.c
 * @brief Example application using TLS over TCP with wolfSSL in RIOT OS
 * @author Bilal-Alali
 * @date 2025-04-24 22:13:24
 */

#include <stdio.h>
#include <string.h>
#include "shell.h"
#include "msg.h"
#include "net/sock/tcp.h"
#include "net/gnrc.h"
#include "net/ipv6/addr.h"
#include "tls.h"
#include <wolfssl/ssl.h>
#include "ztimer.h"
#include "cert_data.h"

#define SERVER_PORT 12345
#define SERVER_ADDR "fe80::ad76:27ff:fe38:993e"
#define BUFFER_SIZE 1024

static int tls_server(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    sock_tls_tcp_queue_t tls_queue;
    sock_tcp_ep_t local = {
        .family = AF_INET6,
        .port = SERVER_PORT,
        .netif = SOCK_ADDR_ANY_NETIF
    };
    sock_tcp_t queue_array[1];

    wolfSSL_Init();
    wolfSSL_Debugging_ON();

    printf("Server: Starting TLS server on port %d...\n", SERVER_PORT);

    int ret = sock_tls_tcp_listen(&tls_queue, &local, queue_array, 1, 0,
                                 wolfTLSv1_2_server_method(),
                                 riot_cert_pem, riot_cert_pem_len,
                                 riot_key_pem, riot_key_pem_len);
    if (ret < 0) {
        printf("Server: Failed to start TLS server: %d\n", ret);
        return 1;
    }

    printf("Server: Listening for connections...\n");

    while (1) {
        sock_tls_tcp_t *client_sock = NULL;
        printf("Server: Waiting for incoming connection...\n");

        ret = sock_tls_tcp_accept(&tls_queue, &client_sock, SOCK_NO_TIMEOUT);
        if (ret < 0) {
            printf("Server: Accept failed: %d\n", ret);
            // Add delay before retry to prevent tight loop on errors
            ztimer_sleep(ZTIMER_MSEC, 1000);
            continue;
        }

        printf("Server: Client connected, waiting for data...\n");

        char buffer[256];  // Smaller buffer size
        ssize_t received = sock_tls_tcp_read(client_sock, buffer, sizeof(buffer));

        if (received > 0) {
            printf("Server: Received %d bytes: %.*s\n",
                   (int)received, (int)received, buffer);

            const char *response = "Hello from TLS server!";
            ssize_t sent = sock_tls_tcp_write(client_sock, response, strlen(response));

            if (sent < 0) {
                printf("Server: Failed to send response: %d\n", (int)sent);
            } else {
                printf("Server: Sent response successfully\n");
            }
        } else {
            printf("Server: Failed to receive data: %d\n", (int)received);
        }

        sock_tls_tcp_disconnect(client_sock);
        free(client_sock);
        printf("Server: Connection closed\n");
    }

    return 0;
}

static int tls_client(int argc, char **argv)
{
    if (argc < 2) {
    printf("Usage: tls_client <IPv6 address>\n");
    return 1;
    }

    const char *server_ip = argv[1];
    sock_tls_tcp_t tls_sock;
    sock_tcp_ep_t remote = {
        .family = AF_INET6,
        .port = SERVER_PORT,
        .netif = SOCK_ADDR_ANY_NETIF
    };

    if (ipv6_addr_from_str((ipv6_addr_t *)&remote.addr.ipv6, server_ip) == NULL) {
        puts("Client: Error parsing IPv6 address");
        return 1;
    }

    /* Initialize wolfSSL */
    wolfSSL_Init();
    wolfSSL_Debugging_ON();

    printf("Client: Creating TLS socket...\n");
    int ret = sock_tls_tcp_create(&tls_sock, wolfTLSv1_2_client_method());
    if (ret < 0) {
        printf("Client: Failed to create TLS socket: %d\n", ret);
        return 1;
    }

    printf("Client: Connecting to server at %s...\n", server_ip);
    ret = sock_tls_tcp_connect(&tls_sock, &remote, 0, 0);
    if (ret < 0) {
        printf("Client: Connection failed: %d\n", ret);
        return 1;
    }

    printf("Client: Connected successfully\n");

    const char *message = "Hello from TLS client!";
    ssize_t sent = sock_tls_tcp_write(&tls_sock, message, strlen(message));
    if (sent < 0) {
        printf("Client: Failed to send message: %d\n", (int)sent);
        sock_tls_tcp_disconnect(&tls_sock);
        return 1;
    }

    printf("Client: Message sent, waiting for response...\n");

    char buffer[BUFFER_SIZE];
    ssize_t received = sock_tls_tcp_read(&tls_sock, buffer, sizeof(buffer));
    if (received > 0) {
        printf("Client: Received %d bytes: %.*s\n",
               (int)received, (int)received, buffer);
    } else {
        printf("Client: Failed to receive response: %d\n", (int)received);
    }

    sock_tls_tcp_disconnect(&tls_sock);
    printf("Client: Connection closed\n");
    return 0;
}

static const shell_command_t shell_commands[] = {
    { "tls_server", "Start TLS server", tls_server },
    { "tls_client", "Start TLS client", tls_client },
    { NULL, NULL, NULL }
};

int main(void)
{
    puts("RIOT TLS over TCP example application");

    /* Initialize wolfSSL */
    wolfSSL_Init();

    /* Start the shell */
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}
