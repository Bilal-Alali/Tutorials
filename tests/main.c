#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "net/sock/tcp.h"
#include "tls.h"
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include "shell.h"
#include "cert_data.h"

#define SERVER_PORT 12345
#define SERVER_ADDR "fe80::b8dc:e6ff:fefd:61e"
#define BUFFER_SIZE 1024

static int tls_client(int argc, char **argv);
static int tls_server(int argc, char **argv);

static const shell_command_t shell_commands[] = {
    {"tls_client", "Run the TLS client", tls_client},
    {"tls_server", "Run the TLS server", tls_server},
    {NULL, NULL, NULL}
};

static int tls_client(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    sock_tls_tcp_t tls_sock;
    sock_tcp_ep_t remote = { .family = AF_INET6, .port = SERVER_PORT };
    ipv6_addr_from_str((ipv6_addr_t *)&remote.addr.ipv6, SERVER_ADDR);

    printf("Client: Creating TLS socket...\n");
    if (sock_tls_tcp_create(&tls_sock, wolfTLSv1_2_client_method()) < 0) {
        puts("Client: Failed to create TLS socket");
        return 1;
    }

    printf("Client: Connecting to server at %s...\n", SERVER_ADDR);
    if (sock_tls_tcp_connect(&tls_sock, &remote, 0, 0,
                             riot_cert_pem, riot_cert_pem_len,
                             riot_key_pem, riot_key_pem_len) < 0) {
        puts("Client: Failed to connect to server");
        sock_tls_tcp_disconnect(&tls_sock);
        return 1;
    }

    const char *msg = "Hello, TLS Server!";
    printf("Client: Sending message to server...\n");
    if (sock_tls_tcp_write(&tls_sock, msg, strlen(msg)) < 0) {
        puts("Client: Failed to send message");
        sock_tls_tcp_disconnect(&tls_sock);
        return 1;
    }

    printf("Client: Waiting for response from server...\n");
    char buffer[BUFFER_SIZE];
    ssize_t len = sock_tls_tcp_read(&tls_sock, buffer, sizeof(buffer));
    if (len < 0) {
        puts("Client: Failed to read message");
    } else {
        printf("Client: Received from server: %.*s\n", (int)len, buffer);
    }

    sock_tls_tcp_disconnect(&tls_sock);
    return 0;
}

static int tls_server(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    sock_tls_tcp_queue_t tls_queue;
    sock_tcp_ep_t local = { .family = AF_INET6, .port = SERVER_PORT };
    sock_tcp_t queue_array[1];

    printf("Server: Starting TLS server on %s:%d...\n", SERVER_ADDR, SERVER_PORT);
    if (sock_tls_tcp_listen(&tls_queue, &local, queue_array, 1, 0, wolfTLSv1_2_server_method()) < 0) {
        puts("Server: Failed to start TLS server");
        return 1;
    }

    printf("Server: TLS server is listening...\n");

    while (1) {
        sock_tls_tcp_t *tls_sock;
        printf("Server: Waiting for incoming connections...\n");
        int ret = sock_tls_tcp_accept(&tls_queue, &tls_sock, 0);
        if (ret < 0) {
            printf("Server: Failed to accept connection: %d\n", ret);
            continue;
        }

        printf("Server: Connection accepted. Waiting for message...\n");
        char buffer[BUFFER_SIZE];
        ssize_t len = sock_tls_tcp_read(tls_sock, buffer, sizeof(buffer));
        if (len < 0) {
            puts("Server: Failed to read message");
        } else {
            printf("Server: Received from client: %.*s\n", (int)len, buffer);

            const char *response = "Hello, TLS Client!";
            printf("Server: Sending response to client...\n");
            if (sock_tls_tcp_write(tls_sock, response, strlen(response)) < 0) {
                puts("Server: Failed to send response");
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

    /* Debugging statements to verify shell command registration */
    puts("Registering shell commands...");

    /* Start the shell */
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    puts("Shell started. Type 'tls_client' or 'tls_server' to run the respective commands.");

    /* Cleanup WolfSSL */
    wolfSSL_Cleanup();

    return 0;
}
