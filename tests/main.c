#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "net/sock/tcp.h"
#include "net/af.h"
#include "tls.h"
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>

#define SERVER_PORT 11111
#define BUFFER_SIZE 1024

// Function to run TLS server
int run_tls_server(void) {
    sock_tcp_ep_t local_ep = {
        .port = SERVER_PORT,
        .addr = {{ 0 }},  // Correct initialization of address
        .family = AF_INET6
    };

    // Prepare queue array for incoming connections
    sock_tcp_t queue_array[1];
    sock_tls_tcp_queue_t tls_queue;

    // Create server SSL method
    WOLFSSL_METHOD *method = wolfTLSv1_2_server_method();
    if (!method) {
        printf("Failed to create server method\n");
        return -1;
    }

    // Start TLS listener
    int ret = sock_tls_tcp_listen(&tls_queue, &local_ep,
                                  queue_array, sizeof(queue_array)/sizeof(queue_array[0]),
                                  SOCK_FLAGS_REUSE_EP, method);
    if (ret < 0) {
        printf("Failed to start TLS listener: %d\n", ret);
        return ret;
    }

    printf("Server listening on port %d\n", SERVER_PORT);

    // Accept incoming connection
    sock_tls_tcp_t *client_sock = NULL;
    ret = sock_tls_tcp_accept(&tls_queue, &client_sock, 0);
    if (ret < 0) {
        printf("Failed to accept connection: %d\n", ret);
        return ret;
    }

    printf("Connection accepted\n");

    // Read message from client
    char recv_buffer[BUFFER_SIZE];
    ssize_t bytes_read = sock_tls_tcp_read(client_sock, recv_buffer, sizeof(recv_buffer));
    if (bytes_read < 0) {
        printf("Failed to read from client: %d\n", bytes_read);
        sock_tls_tcp_disconnect(client_sock);
        return bytes_read;
    }

    recv_buffer[bytes_read] = '\0';
    printf("Received from client: %s\n", recv_buffer);

    // Send response
    const char *response = "Hello from Server!";
    ssize_t bytes_written = sock_tls_tcp_write(client_sock, response, strlen(response));
    if (bytes_written < 0) {
        printf("Failed to write to client: %d\n", bytes_written);
        sock_tls_tcp_disconnect(client_sock);
        return bytes_written;
    }

    // Cleanup
    sock_tls_tcp_disconnect(client_sock);
    return 0;
}

// Function to run TLS client
int run_tls_client(void) {
    sock_tcp_ep_t remote_ep = {
        .port = SERVER_PORT,
        .addr = {{ 0 }},  // Correct initialization of address
        .family = AF_INET6
    };

    // Set a loopback address for local testing
    remote_ep.addr.ipv6[15] = 1;  // ::1 (IPv6 loopback)

    // Create client SSL method
    WOLFSSL_METHOD *method = wolfTLSv1_2_client_method();
    if (!method) {
        printf("Failed to create client method\n");
        return -1;
    }

    // Create TLS socket
    sock_tls_tcp_t client_sock;
    int ret = sock_tls_tcp_create(&client_sock, method);
    if (ret < 0) {
        printf("Failed to create TLS socket: %d\n", ret);
        return ret;
    }

    // Connect to server
    ret = sock_tls_tcp_connect(&client_sock, &remote_ep, 0, 0);
    if (ret < 0) {
        printf("Failed to connect to server: %d\n", ret);
        return ret;
    }

    printf("Connected to server\n");

    // Send message to server
    const char *message = "Hello from Client!";
    ssize_t bytes_written = sock_tls_tcp_write(&client_sock, message, strlen(message));
    if (bytes_written < 0) {
        printf("Failed to write to server: %d\n", bytes_written);
        sock_tls_tcp_disconnect(&client_sock);
        return bytes_written;
    }

    // Read response from server
    char recv_buffer[BUFFER_SIZE];
    ssize_t bytes_read = sock_tls_tcp_read(&client_sock, recv_buffer, sizeof(recv_buffer));
    if (bytes_read < 0) {
        printf("Failed to read from server: %d\n", bytes_read);
        sock_tls_tcp_disconnect(&client_sock);
        return bytes_read;
    }

    recv_buffer[bytes_read] = '\0';
    printf("Received from server: %s\n", recv_buffer);

    // Cleanup
    sock_tls_tcp_disconnect(&client_sock);
    return 0;
}

// Main function to demonstrate TLS communication
int main(void) {
    // Initialize WolfSSL
    wolfSSL_Init();

    // Uncomment the function you want to test
    // Server test
    // int result = run_tls_server();

    // Client test
    int result = run_tls_client();

    // Cleanup WolfSSL
    wolfSSL_Cleanup();

    return result;
}
