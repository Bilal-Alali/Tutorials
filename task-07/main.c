#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "msg.h"
#include "shell.h"
#include "net/ipv6/addr.h"
#include "net/gnrc.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/pktbuf.h"
#include "net/gnrc/udp.h"
#include "xtimer.h"

#define MSG_QUEUE_SIZE (16)
#define MSG_BUFFER_SIZE  (64)
#define DEFAULT_DELAY (1000000) // 1 second

static msg_t msg_queue[MSG_QUEUE_SIZE];
static char buffer[MSG_BUFFER_SIZE];
static gnrc_netreg_entry_t server;

/* Function to send UDP packets */
static void send_udp(char *addr_str, char *port_str, char *data, unsigned int num, unsigned int delay) {
    gnrc_netif_t *netif = NULL;
    char *iface;
    uint16_t port;
    ipv6_addr_t addr;

    iface = ipv6_addr_split_iface(addr_str);
    if ((!iface) && (gnrc_netif_numof() == 1)) {
        netif = gnrc_netif_iter(NULL);
    } else if (iface) {
        netif = gnrc_netif_get_by_pid(atoi(iface));
    }

    if (ipv6_addr_from_str(&addr, addr_str) == NULL) {
        puts("Error: invalid destination address");
        return;
    }

    port = atoi(port_str);
    if (port == 0) {
        puts("Error: invalid port");
        return;
    }

    for (unsigned int i = 0; i < num; i++) {
        gnrc_pktsnip_t *payload, *udp, *ip;
        unsigned payload_size;

        payload = gnrc_pktbuf_add(NULL, data, strlen(data), GNRC_NETTYPE_UNDEF);
        if (!payload) {
            puts("Error: could not allocate packet buffer");
            return;
        }

        payload_size = (unsigned)payload->size;
        udp = gnrc_udp_hdr_build(payload, port, port);
        if (!udp) {
            puts("Error: could not allocate UDP header");
            gnrc_pktbuf_release(payload);
            return;
        }

        ip = gnrc_ipv6_hdr_build(udp, NULL, &addr);
        if (!ip) {
            puts("Error: could not allocate IPv6 header");
            gnrc_pktbuf_release(udp);
            return;
        }

        if (netif) {
            gnrc_pktsnip_t *netif_hdr = gnrc_netif_hdr_build(NULL, 0, NULL, 0);
            if (!netif_hdr) {
                puts("Error: could not allocate netif header");
                gnrc_pktbuf_release(ip);
                return;
            }
            gnrc_netif_hdr_set_netif(netif_hdr->data, netif);
            ip = gnrc_pkt_prepend(ip, netif_hdr);
        }

        if (!gnrc_netapi_dispatch_send(GNRC_NETTYPE_UDP, GNRC_NETREG_DEMUX_CTX_ALL, ip)) {
            puts("Error: could not send packet");
            gnrc_pktbuf_release(ip);
            return;
        }

        printf("Sent %u bytes to [%s]:%u\n", payload_size, addr_str, port);
        xtimer_usleep(delay);
    }
}

/* Function to start UDP server */
static void start_server(uint16_t port) {
    if (server.target.pid != KERNEL_PID_UNDEF) {
        printf("Error: Server already running on port %" PRIu16 "\n", server.demux_ctx);
        return;
    }

    server.target.pid = thread_getpid();
    server.demux_ctx = port;
    gnrc_netreg_register(GNRC_NETTYPE_UDP, &server);

    printf("UDP Server started on port %" PRIu16 "\n", port);
}

/* UDP receive loop */
static void udp_receive_loop(void) {
    int packet_count = 0;
    while (1) {
        msg_t msg;
        msg_receive(&msg);

        gnrc_pktsnip_t *pkt = (gnrc_pktsnip_t *)msg.content.ptr;
        if (pkt) {
            packet_count++;
            size_t len = pkt->size < MSG_BUFFER_SIZE - 1 ? pkt->size : MSG_BUFFER_SIZE - 1;
            strncpy(buffer, (char *)pkt->data, len);
            buffer[len] = '\0';

            printf("Received UDP packet #%d on port 8888: %s\n", packet_count, buffer);
            gnrc_pktbuf_release(pkt);
        }
    }
}

/* UDP shell command */
static int _udp_cmd(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s [send|server]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "send") == 0) {
        if (argc < 5) {
            printf("Usage: %s send <addr> <port> <data> [<num> [<delay in us>]]\n", argv[0]);
            return 1;
        }
        uint32_t num = (argc > 5) ? atoi(argv[5]) : 1;
        uint32_t delay = (argc > 6) ? atoi(argv[6]) : DEFAULT_DELAY;
        send_udp(argv[2], argv[3], argv[4], num, delay);
    }
    else if (strcmp(argv[1], "server") == 0) {
        if (argc < 3) {
            printf("Usage: %s server start|stop\n", argv[0]);
            return 1;
        }
        if (strcmp(argv[2], "start") == 0) {
            if (argc < 4) {
                printf("Usage: %s server start <port>\n", argv[0]);
                return 1;
            }
            start_server(atoi(argv[3]));
        }
        else if (strcmp(argv[2], "stop") == 0) {
            if (server.target.pid == KERNEL_PID_UNDEF) {
                puts("Error: Server is not running");
                return 1;
            }
            gnrc_netreg_unregister(GNRC_NETTYPE_UDP, &server);
            server.target.pid = KERNEL_PID_UNDEF;
            puts("UDP server stopped");
        }
        else {
            puts("Error: Invalid command");
            return 1;
        }
    }
    else {
        puts("Error: Invalid command");
        return 1;
    }
    return 0;
}

/* Register the shell command */
SHELL_COMMAND(udp, "Send/receive UDP messages", _udp_cmd);

int main(void) {
    puts("RIOT UDP Application");

    msg_init_queue(msg_queue, MSG_QUEUE_SIZE);

    /* Print IPv6 addresses */
    printf("{\"IPv6 addresses\": [\"");
    netifs_print_ipv6("\", \"");
    puts("\"]}");

    /* Start server automatically */
    start_server(8888);

    /* Start receiving loop */
    udp_receive_loop();

    return 0;
}
