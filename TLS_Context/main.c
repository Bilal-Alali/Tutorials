#include <stdio.h>
#include <string.h>
#include "shell.h"
#include "sock_tls_tcp.h"

/* Server and client certificates and keys */
extern const char *ca_cert;       /* CA certificate */
extern const char *server_cert;   /* Server certificate */
extern const char *server_key;    /* Server private key */
extern const char *client_cert;   /* Client certificate */
extern const char *client_key;    /* Client private key */

#define SERVER_PORT 12345
#define BUFFER_SIZE 1024

static void run_tls_server(void);
static void run_tls_client(const char *server_ip);

/* Shell command to start the TLS server */
static int tls_server_cmd(int argc, char **argv) {
    (void)argc; (void)argv; // Unused parameters
    run_tls_server();
    return 0;
}

/* Shell command to start the TLS client */
static int tls_client_cmd(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: tls_client <server_ip>\n");
        return -1;
    }

    const char *server_ip = argv[1];
    run_tls_client(server_ip);
    return 0;
}

/* Shell command definitions */
static const shell_command_t shell_commands[] = {
    { "tls_server", "Start the TLS server", tls_server_cmd },
    { "tls_client", "Start the TLS client", tls_client_cmd },
    { NULL, NULL, NULL }
};

/* Main entry point */
int main(void) {
    printf("TLS over TCP Test Application\n");
    printf("Available commands:\n");
    printf("  tls_server - Start the TLS server\n");
    printf("  tls_client <server_ip> - Start the TLS client\n");

    /* Start the shell */
    shell_run(shell_commands, NULL);
    return 0;
}

/* Run the TLS server */
static void run_tls_server(void) {
    sock_tls_tcp_t server_sock;
    sock_tls_tcp_t client_sock;

    /* Initialize TLS module */
    if (sock_tls_tcp_init() < 0) {
        printf("[Server]: Failed to initialize TLS module\n");
        return;
    }

    /* Create the server socket */
    if (sock_tls_tcp_create(&server_sock, wolfTLSv1_2_server_method(),
                            ca_cert, server_cert, server_key) < 0) {
        printf("[Server]: Failed to create server socket\n");
        return;
    }

    /* Bind the server socket to the port */
    if (sock_tcp_bind(&server_sock.tcp_sock, SOCK_IPV6_EP_ANY, SERVER_PORT) < 0) {
        printf("[Server]: Failed to bind server socket\n");
        sock_tls_tcp_destroy(&server_sock);
        return;
    }

    printf("[Server]: Listening on port %d...\n", SERVER_PORT);

    /* Accept incoming connections */
    while (1) {
        if (sock_tls_tcp_accept(&server_sock, &client_sock) == 0) {
            printf("[Server]: Client connected!\n");

            /* Receive data from the client */
            unsigned char buffer[BUFFER_SIZE];
            int received = sock_tls_tcp_receive(&client_sock, buffer, sizeof(buffer));

            if (received > 0) {
                printf("[Server]: Received %d bytes: %s\n", received, buffer);

                /* Echo the data back to the client */
                sock_tls_tcp_send(&client_sock, buffer, received);
            }

            /* Disconnect and clean up the client socket */
            sock_tls_tcp_disconnect(&client_sock);
            sock_tls_tcp_destroy(&client_sock);
        } else {
            printf("[Server]: Failed to accept client connection\n");
        }
    }

    /* Clean up the server socket */
    sock_tls_tcp_destroy(&server_sock);
    sock_tls_tcp_cleanup();
}

/* Run the TLS client */
static void run_tls_client(const char *server_ip) {
    sock_tls_tcp_t client_sock;

    /* Initialize TLS module */
    if (sock_tls_tcp_init() < 0) {
        printf("[Client]: Failed to initialize TLS module\n");
        return;
    }

    /* Create the client socket */
    if (sock_tls_tcp_create(&client_sock, wolfTLSv1_2_client_method(),
                            ca_cert, client_cert, client_key) < 0) {
        printf("[Client]: Failed to create client socket\n");
        return;
    }

    /* Connect to the server */
    if (sock_tls_tcp_connect(&client_sock, server_ip, SERVER_PORT) == 0) {
        printf("[Client]: Connected to server at %s:%d\n", server_ip, SERVER_PORT);

        /* Send a message to the server */
        const char *message = "Hello, Server!";
        sock_tls_tcp_send(&client_sock, (const unsigned char *)message, strlen(message));

        /* Receive the server's response */
        unsigned char buffer[BUFFER_SIZE];
        int received = sock_tls_tcp_receive(&client_sock, buffer, sizeof(buffer));

        if (received > 0) {
            printf("[Client]: Received %d bytes: %s\n", received, buffer);
        } else {
            printf("[Client]: Failed to receive data from the server\n");
        }

        /* Disconnect and clean up the client socket */
        sock_tls_tcp_disconnect(&client_sock);
        sock_tls_tcp_destroy(&client_sock);
    } else {
        printf("[Client]: Failed to connect to server at %s:%d\n", server_ip, SERVER_PORT);
    }

    /* Clean up the TLS module */
    sock_tls_tcp_cleanup();
}
