// level: expert
// mode: dynamic
// expect: none
// what: trap: 999 EAGAIN reads stay under the line, and a non-blocking pipe is not a socket
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return 1;
    fcntl(sv[0], F_SETFL, O_NONBLOCK);
    char buf[8];
    for (int i = 0; i < 999; i++)
        recv(sv[0], buf, sizeof buf, 0);
    int p[2];
    if (pipe(p) != 0)
        return 1;
    fcntl(p[0], F_SETFL, O_NONBLOCK);
    for (int i = 0; i < 1200; i++)
        read(p[0], buf, sizeof buf);
    close(sv[0]);
    close(sv[1]);
    close(p[0]);
    close(p[1]);
    return 0;
}
