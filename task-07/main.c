/*
 * Copyright (C) 2015 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Showing minimum memory footprint of gnrc network stack
 *
 * @author      Oliver Hahm <oliver.hahm@inria.fr>
 *
 * @}
 */

#include <stdio.h>

#include "msg.h"
#include "net/ipv6/addr.h"
#include "net/gnrc.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/pktbuf.h"
#include "net/netif.h"

#define MSG_QUEUE_SIZE (16)
#define MSG_BUFFER_SIZE  (64)

/* Initialize message queue */
static msg_t msg_queue[MSG_QUEUE_SIZE];
static char buffer[MSG_BUFFER_SIZE];

int main(void)
{

    puts("RIOT network stack example application");

    msg_init_queue(msg_queue, MSG_QUEUE_SIZE);

    /* Print all IPv6 addresses */
    printf("{\"IPv6 addresses\": [\"");
    netifs_print_ipv6("\", \"");
    puts("\"]}");

    /* Register this thread to receive UDP packets on port 8888 */
    gnrc_netreg_entry_t server = GNRC_NETREG_ENTRY_INIT_PID(8888, thread_getpid());
    gnrc_netreg_register(GNRC_NETTYPE_UDP, &server);

    /* Packet reception loop */
    int packet_count = 0;
    while (1) {
        msg_t msg;
        msg_receive(&msg);  // Wait for message

        /* Extract packet */
        gnrc_pktsnip_t *pkt = (gnrc_pktsnip_t *)msg.content.ptr;
        if (pkt) {
            packet_count++;  // counter plus 1

            /* Daten ins statische buffer kopieren */
            size_t len = pkt->size < MSG_BUFFER_SIZE - 1 ? pkt->size : MSG_BUFFER_SIZE - 1;
            strncpy(buffer, (char *)pkt->data, len);
            buffer[len] = '\0';  // Null-terminieren

            printf("Received UDP packet #%d on port 8888: %s\n", packet_count, buffer);
            gnrc_pktbuf_release(pkt);  // Free memory
        }
    }
}
