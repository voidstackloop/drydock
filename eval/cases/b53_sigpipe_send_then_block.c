// level: basic
// mode: dynamic
// expect: sigpipe-exposure
// what: the first reply is sent while SIGPIPE can still kill the process; the thread blocks it only afterwards
#define _GNU_SOURCE
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int conn[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, conn) != 0)
        return 1;
    send(conn[0], "ok\n", 3, 0); // first look: still the default
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    sigprocmask(SIG_BLOCK, &set, NULL);
    send(conn[0], "ok\n", 3, 0); // blocked now: not a second bug
    close(conn[0]);
    close(conn[1]);
    return 0;
}
