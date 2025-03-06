#include <stdio.h>
#include <string.h>

#include "msg.h"
#include "net/gnrc/netreg.h"
#include "net/gnrc/pktdump.h"
#include "shell.h"
#include "xtimer.h"

static char line_buf[SHELL_DEFAULT_BUFSIZE];

void *thread_handler(void *arg)
{
    (void)arg;

    // Print a message and give user instructions
    printf("This is Task-05 networking application.\n");
    printf("Use 'txtsnd' to send messages.\n");

    // Initialize and register pktdump to print received packets
    gnrc_netreg_entry_t dump = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL,
                                 gnrc_pktdump_pid);
    gnrc_netreg_register(GNRC_NETTYPE_UNDEF, &dump);

    // Loop to keep the thread alive and ready to handle commands
    while (1) {
        xtimer_sleep(1);
    }

    return NULL;
}

int main(void)
{
    puts("This is Task-05");

     // Create a thread to handle network operations
    thread_create(NULL, 0, THREAD_PRIORITY_MAIN - 1, THREAD_CREATE_STACKTEST, thread_handler, NULL, "network-thread");

    shell_run(NULL, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}
