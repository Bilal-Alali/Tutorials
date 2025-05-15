#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "net/sock/tcp.h"
#include "tls.h"
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include "shell.h"
#include "ztimer.h"

#define SERVER_PORT 12345
#define SERVER_ADDR "fe80::8a2:81ff:fecd:3113"
#define BUFFER_SIZE 1024
#define RETRY_TIMEOUT_US 100000  /* 100ms */

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

    /* Disable certificate verification for testing */
    sock_tls_tcp_disable_cert_verify(&tls_sock);

    printf("Client: Connecting to server at %s...\n", SERVER_ADDR);
    int ret = sock_tls_tcp_connect(&tls_sock, &remote, 0, 0, NULL, 0, NULL, 0);
    if (ret < 0 && ret != -EINPROGRESS) {
        puts("Client: Failed to initiate connection");
        sock_tls_tcp_disconnect(&tls_sock);
        return 1;
    }

    /* Handle connection and handshake */
    while ((ret = sock_tls_tcp_handshake(&tls_sock)) == -EAGAIN) {
        ztimer_sleep(ZTIMER_USEC, RETRY_TIMEOUT_US);
    }
    if (ret < 0) {
        printf("Client: Handshake failed with error %d\n", ret);
        sock_tls_tcp_disconnect(&tls_sock);
        return 1;
    }

    const char *msg = "Hello, TLS Server!";
    printf("Client: Sending message to server...\n");

    /* Non-blocking write loop */
    size_t sent = 0;
    while (sent < strlen(msg)) {
        ret = sock_tls_tcp_write(&tls_sock, msg + sent, strlen(msg) - sent);
        if (ret < 0) {
            if (ret == -EAGAIN) {
                ztimer_sleep(ZTIMER_USEC, RETRY_TIMEOUT_US);
                continue;
            }
            puts("Client: Failed to send message");
            sock_tls_tcp_disconnect(&tls_sock);
            return 1;
        }
        sent += ret;
    }

    /* Non-blocking read loop */
    printf("Client: Waiting for response from server...\n");
    char buffer[BUFFER_SIZE];
    size_t received = 0;
    while (received < sizeof(buffer) - 1) {
        ret = sock_tls_tcp_read(&tls_sock, buffer + received,
                               sizeof(buffer) - received - 1);
        if (ret < 0) {
            if (ret == -EAGAIN) {
                ztimer_sleep(ZTIMER_USEC, RETRY_TIMEOUT_US);
                continue;
            }
            puts("Client: Failed to read message");
            break;
        }
        else if (ret == 0) {
            /* Connection closed by peer */
            break;
        }
        received += ret;
        buffer[received] = '\0';
        if (strchr(buffer, '\n') != NULL) {
            break;  /* Got complete message */
        }
    }

    if (received > 0) {
        printf("Client: Received from server: %.*s\n", (int)received, buffer);
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

    printf("Server: Starting TLS server on port %d...\n", SERVER_PORT);
    if (sock_tls_tcp_listen(&tls_queue, &local, queue_array, 1, 0,
                           wolfTLSv1_2_server_method()) < 0) {
        puts("Server: Failed to start TLS server");
        return 1;
    }

    /* Disable certificate verification */
    wolfSSL_CTX_set_verify(tls_queue.ctx, SSL_VERIFY_NONE, NULL);

    printf("Server: TLS server is listening...\n");

    while (1) {
        sock_tls_tcp_t *tls_sock = NULL;
        printf("Server: Waiting for incoming connections...\n");

        /* Non-blocking accept loop */
        int ret;
        while ((ret = sock_tls_tcp_accept(&tls_queue, &tls_sock, 0)) == -EAGAIN) {
            ztimer_sleep(ZTIMER_USEC, RETRY_TIMEOUT_US);
        }
        if (ret < 0) {
            printf("Server: Failed to accept connection: %d\n", ret);
            continue;
        }

        /* Handle TLS handshake */
        while ((ret = sock_tls_tcp_handshake(tls_sock)) == -EAGAIN) {
            ztimer_sleep(ZTIMER_USEC, RETRY_TIMEOUT_US);
        }
        if (ret < 0) {
            printf("Server: Handshake failed: %d\n", ret);
            sock_tls_tcp_disconnect(tls_sock);
            free(tls_sock);
            continue;
        }

        printf("Server: Connection accepted. Waiting for message...\n");
        char buffer[BUFFER_SIZE];
        size_t received = 0;

        /* Non-blocking read loop */
        while (received < sizeof(buffer) - 1) {
            ret = sock_tls_tcp_read(tls_sock, buffer + received,
                                  sizeof(buffer) - received - 1);
            if (ret < 0) {
                if (ret == -EAGAIN) {
                    ztimer_sleep(ZTIMER_USEC, RETRY_TIMEOUT_US);
                    continue;
                }
                puts("Server: Failed to read message");
                break;
            }
            else if (ret == 0) {
                break;  /* Connection closed by peer */
            }
            received += ret;
            buffer[received] = '\0';
            if (strchr(buffer, '\n') != NULL) {
                break;  /* Got complete message */
            }
        }

        if (received > 0) {
            printf("Server: Received from client: %.*s\n", (int)received, buffer);

            /* Send response */
            const char *response = "Hello, TLS Client!";
            size_t sent = 0;
            while (sent < strlen(response)) {
                ret = sock_tls_tcp_write(tls_sock, response + sent,
                                       strlen(response) - sent);
                if (ret < 0) {
                    if (ret == -EAGAIN) {
                        ztimer_sleep(ZTIMER_USEC, RETRY_TIMEOUT_US);
                        continue;
                    }
                    puts("Server: Failed to send response");
                    break;
                }
                sent += ret;
            }
        }

        sock_tls_tcp_disconnect(tls_sock);
        free(tls_sock);
    }

    return 0;
}

int main(void)
{
    puts("RIOT TLS over TCP example application");

    /* Initialize WolfSSL */
    wolfSSL_Init();
    wolfSSL_Debugging_ON();

    /* Start the shell */
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* Cleanup WolfSSL */
    wolfSSL_Cleanup();

    return 0;
}
