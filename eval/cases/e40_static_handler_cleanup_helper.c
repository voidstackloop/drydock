// level: expert
// mode: static
// expect: signal-unsafe-call
// what: a SIGINT handler calls the shared cleanup routine, defined further down, which frees buffers
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

static char *buffers[8];
static void release_buffers(void);

static void on_int(int sig) {
    release_buffers(); // "so nothing leaks on Ctrl+C"
    _exit(128 + sig);
}

int main(void) {
    signal(SIGINT, on_int);
    for (int i = 0; i < 8; i++)
        buffers[i] = malloc(4096);
    pause();
    release_buffers();
    return 0;
}

static void release_buffers(void) {
    for (int i = 0; i < 8; i++) {
        free(buffers[i]);
        buffers[i] = NULL;
    }
}
