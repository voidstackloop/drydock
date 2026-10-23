// level: hard
// mode: dynamic
// expect: signal-unsafe-call
// what: a timer handler logs through a helper that allocates
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char *last_event;

static void log_event(const char *what) {
    free(last_event);
    last_event = strdup(what); // malloc inside a signal handler
}

static void on_alarm(int sig) {
    (void)sig;
    log_event("tick");
}

int main(void) {
    struct sigaction sa = {0};
    sa.sa_handler = on_alarm;
    sigaction(SIGALRM, &sa, NULL);
    alarm(1);
    pause();
    free(last_event);
    return 0;
}
