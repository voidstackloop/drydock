// level: expert
// mode: static
// expect: none
// what: trap: handlers that only set a flag, write to a pipe or _exit; printf only in a function never installed
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t stop;
static int wake_fd = -1;

static void on_int(int sig) {
    (void)sig;
    stop = 1;
}

static void on_chld(int sig) {
    const char c = (char)sig;
    if (write(wake_fd, &c, 1) < 0) {
    }
}

static void on_quit(int sig) {
    static const char msg[] = "quit\n";
    if (write(2, msg, sizeof msg - 1) < 0) {
    }
    _exit(128 + sig);
}

static void report_status(int code) { // called from the main loop only
    printf("status %d\n", code);
}

int main(void) {
    int fds[2];
    if (pipe(fds) < 0)
        return 1;
    wake_fd = fds[1];
    signal(SIGINT, on_int);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, SIG_DFL);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_chld;
    sigaction(SIGCHLD, &sa, NULL);
    sa.sa_handler = on_quit;
    sigaction(SIGQUIT, &sa, NULL);
    while (!stop)
        report_status(0);
    return 0;
}
