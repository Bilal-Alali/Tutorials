#include <stdio.h>
#include <string.h>
#include "led.h"
#include "shell.h"

int echo(int argc, char **argv)
{
    if (argc > 1){
            printf("%s\n", argv[1]);
    }
    else {
            printf("No Arguments\n");
    }

    return 0;
}

int toggle(int argc, char **argv){
        (void) argc;
        (void) argv;

        LED0_TOGGLE;
        printf("LED0 on\n");
        return 0;
}

static const shell_command_t commands[] = {
        {"echo", "Prints the first argument", echo},
        {"toggle", "lights the LED", toggle},
        { NULL, NULL, NULL }
};

int main(void)
{
    puts("This is Task-02");

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}
