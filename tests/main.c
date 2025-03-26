#include <stdio.h>
#include "tls.h"

#define SERVER_PORT 4433
#define QUEUE_LEN 4
#define FLAGS 0

void test_sock_tls_tcp_create(void) {
    sock_tls_tcp_t sock;
    int res = sock_tls_tcp_create(&sock, wolfTLSv1_2_client_method());
    if (res == 0) {
        printf("sock_tls_tcp_create: SUCCESS\n");
    } else {
        printf("sock_tls_tcp_create: FAILED (Error: %d)\n", res);
    }
}

void test_sock_tls_tcp_listen(void) {
    sock_tls_tcp_queue_t tls_queue;
    sock_tcp_t tcp_queue[QUEUE_LEN];
    sock_tcp_ep_t local_ep = { .port = SERVER_PORT, .family = AF_INET6 };

    sock_tls_tcp_create(&tls_queue, wolfTLSv1_2_server_method());
    int res = sock_tls_tcp_listen(&tls_queue, &local_ep, tcp_queue, QUEUE_LEN, FLAGS, wolfTLSv1_2_server_method());
    if (res == 0) {
        printf("sock_tls_tcp_listen: SUCCESS\n");
    } else {
        printf("sock_tls_tcp_listen: FAILED (Error: %d)\n", res);
    }
}

int main(void) {
    printf("Starting TLS tests...\n");
    test_sock_tls_tcp_create();
    test_sock_tls_tcp_listen();
    printf("Tests finished.\n");
    return 0;
}
