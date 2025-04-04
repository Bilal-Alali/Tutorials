#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "net/sock/tcp.h"
#include "tls.h"
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include "ztimer.h"
#include "shell.h"

#define SERVER_PORT 12345
#define SERVER_ADDR "2001:db8::1" // Replace with your server address
#define BUFFER_SIZE 1024

static int run_tls_client(int argc, char **argv);
static int run_tls_server(int argc, char **argv);

static const shell_command_t shell_commands[] = {
    {"tls_client", "Run the TLS client", run_tls_client},
    {"tls_server", "Run the TLS server", run_tls_server},
    {NULL, NULL, NULL}
};

static int run_tls_client(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    sock_tls_tcp_t tls_sock;
    sock_tcp_ep_t remote = { .family = AF_INET6, .port = SERVER_PORT };
    ipv6_addr_from_str((ipv6_addr_t *)&remote.addr.ipv6, SERVER_ADDR);

    if (sock_tls_tcp_create(&tls_sock, wolfTLSv1_2_client_method()) < 0) {
        puts("Failed to create TLS socket");
        return 1;
    }

    if (sock_tls_tcp_connect(&tls_sock, &remote, 0, 0) < 0) {
        puts("Failed to connect to server");
        sock_tls_tcp_disconnect(&tls_sock);
        return 1;
    }

    const char *msg = "Hello, TLS Server!";
    if (sock_tls_tcp_write(&tls_sock, msg, strlen(msg)) < 0) {
        puts("Failed to send message");
        sock_tls_tcp_disconnect(&tls_sock);
        return 1;
    }

    char buffer[BUFFER_SIZE];
    ssize_t len = sock_tls_tcp_read(&tls_sock, buffer, sizeof(buffer));
    if (len < 0) {
        puts("Failed to read message");
    } else {
        printf("Received from server: %.*s\n", (int)len, buffer);
    }

    sock_tls_tcp_disconnect(&tls_sock);
    return 0;
}

static int run_tls_server(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    sock_tls_tcp_queue_t tls_queue;
    sock_tcp_ep_t local = { .family = AF_INET6, .port = SERVER_PORT };
    sock_tcp_t queue_array[1];

    if (sock_tls_tcp_listen(&tls_queue, &local, queue_array, 1, 0, wolfTLSv1_2_server_method()) < 0) {
        puts("Failed to start TLS server");
        return 1;
    }

    puts("TLS server is listening...");

    while (1) {
        sock_tls_tcp_t *tls_sock;
        if (sock_tls_tcp_accept(&tls_queue, &tls_sock, 0) < 0) {
            puts("Failed to accept connection");
            continue;
        }

        char buffer[BUFFER_SIZE];
        ssize_t len = sock_tls_tcp_read(tls_sock, buffer, sizeof(buffer));
        if (len < 0) {
            puts("Failed to read message");
        } else {
            printf("Received from client: %.*s\n", (int)len, buffer);

            const char *response = "Hello, TLS Client!";
            if (sock_tls_tcp_write(tls_sock, response, strlen(response)) < 0) {
                puts("Failed to send response");
            }
        }

        sock_tls_tcp_disconnect(tls_sock);
    }

    return 0;
}

int main(void)
{
    puts("RIOT TLS over TCP example application");

    /* Initialize WolfSSL */
    wolfSSL_Init();

    /* Start the shell */
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* Cleanup WolfSSL */
    wolfSSL_Cleanup();

    return 0;
}
