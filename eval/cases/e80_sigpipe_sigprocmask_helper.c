// level: expert
// mode: dynamic
// expect: sigpipe-exposure
// what: a helper blocks SIGPIPE around a probe sendto, then clears that block and sendto's the body
#define _GNU_SOURCE
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void reply(int fd, const char *text) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    sigprocmask(SIG_BLOCK, &set, NULL);
    sendto(fd, ".", 1, 0, NULL, 0); // first look, while blocked
    sigprocmask(SIG_UNBLOCK, &set, NULL);
    sendto(fd, text, strlen(text), 0, NULL, 0);
}

int main(void) {
    int conn[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, conn) != 0)
        return 1;
    reply(conn[0], "pong\n");
    close(conn[0]);
    close(conn[1]);
    return 0;
}
