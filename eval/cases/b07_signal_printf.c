// level: basic
// mode: dynamic
// expect: signal-unsafe-call
// what: a SIGINT handler calls printf
#include <signal.h>
#include <stdio.h>

static void on_int(int sig) { printf("caught %d\n", sig); }

int main(void) {
    signal(SIGINT, on_int);
    raise(SIGINT);
    return 0;
}
