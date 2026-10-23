// level: basic
// mode: static
// expect: signal-unsafe-call
// what: a SIGINT handler prints with printf
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static void on_sigint(int sig) {
    printf("caught signal %d\n", sig);
}

int main(void) {
    signal(SIGINT, on_sigint);
    for (;;)
        pause();
}
