#include <stdio.h>
#include <string.h>

#include "shell.h"
#include "thread.h"
#include "xtimer.h"

char stack[THREAD_STACKSIZE_MAIN];

void *thread_handler(void *arg)
{
            (void)arg;

    // Print current system time in microseconds
    uint64_t start_time = xtimer_now_usec();
    printf("Current time (start): %" PRIu64 " microseconds\n", start_time);

    // Sleep for 5 seconds
    printf("Sleeping for 5 seconds...\n");
    xtimer_sleep(5);

    // Print current time again after sleeping for 2 seconds
    uint64_t end_time = xtimer_now_usec();
    printf("Current time (after sleep): %" PRIu64 " microseconds\n", end_time);

    // Calculate the difference in time
    uint64_t elapsed_time = end_time - start_time;
    printf("Elapsed time: %" PRIu64 " microseconds\n", elapsed_time);

    // Sleep for another 1 second (1000000 microseconds)
    printf("Sleeping for 1 second...\n");
    xtimer_usleep(1000000);

    // Print time again after usleep
    uint64_t final_time = xtimer_now_usec();
    printf("Final time (after usleep): %" PRIu64 " microseconds\n", final_time);

    return NULL;
}

int main(void)
{
    puts("This is Task-04");

    thread_create(stack, sizeof(stack),
                  THREAD_PRIORITY_MAIN - 1,
                  THREAD_CREATE_STACKTEST,
                  thread_handler, NULL,
                  "thread");

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(NULL, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}
