// level: hard
// mode: static
// expect: signal-unsafe-call
// what: a SIGTERM handler installed with sigaction frees the cache and calls exit
#include <signal.h>
#include <stdlib.h>
#include <string.h>

static char *cache;

static void on_term(int sig) {
    (void)sig;
    free(cache); // "clean shutdown"
    exit(0);
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_term;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    cache = malloc(1 << 20);
    for (;;)
        memset(cache, 0, 1 << 20);
}
