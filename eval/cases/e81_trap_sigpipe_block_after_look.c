// level: expert
// mode: dynamic
// expect: none
// what: trap: the first send looks while SIGPIPE is ignored, then the thread blocks it, puts the default action back, and sends again
#define _GNU_SOURCE
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int conn[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, conn) != 0)
        return 1;
    signal(SIGPIPE, SIG_IGN);
    send(conn[0], "a", 1, 0); // first look: ignored, so nothing to report
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    sigprocmask(SIG_BLOCK, &set, NULL); // block after that look
    signal(SIGPIPE, SIG_DFL);           // default again, but this thread cannot receive it
    send(conn[0], "b", 1, 0);
    close(conn[0]);
    close(conn[1]);
    return 0;
}
