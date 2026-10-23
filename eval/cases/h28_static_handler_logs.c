// level: hard
// mode: static
// expect: signal-unsafe-call
// what: a SIGHUP handler only flags a reload, but also calls the program's own log helper, which uses fprintf
#include <signal.h>
#include <stdio.h>
#include <time.h>

static volatile sig_atomic_t reload;

static void log_msg(const char *what) {
    fprintf(stderr, "[%ld] %s\n", (long)time(NULL), what);
}

static void on_hup(int sig) {
    (void)sig;
    reload = 1;
    log_msg("reload requested");
}

int main(void) {
    signal(SIGHUP, on_hup);
    log_msg("started");
    for (;;) {
        if (reload) {
            reload = 0;
            log_msg("reloading");
        }
    }
}
