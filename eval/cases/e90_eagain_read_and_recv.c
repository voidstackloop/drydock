// level: expert
// mode: dynamic
// expect: socket-eagain-spin
// what: half the spins are read() and half are recv(); they share one counter on the socket
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
    for (int i = 0; i < 500; i++)
        read(sv[0], buf, sizeof buf);
    for (int i = 0; i < 500; i++)
        recv(sv[0], buf, sizeof buf, 0);
    close(sv[0]);
    close(sv[1]);
    return 0;
}
