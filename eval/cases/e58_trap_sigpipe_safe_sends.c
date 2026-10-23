// level: expert
// mode: dynamic
// expect: none
// what: trap: sends that cannot kill the process: a datagram socket, MSG_NOSIGNAL, and a stream send after SIGPIPE was ignored
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int dgram[2], stream[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, dgram) != 0 ||
        socketpair(AF_UNIX, SOCK_STREAM, 0, stream) != 0)
        return 1;

    send(dgram[0], "tick", 4, 0); // no SIGPIPE for datagrams
    send(stream[0], "a", 1, MSG_NOSIGNAL);
    signal(SIGPIPE, SIG_IGN);     // what a server does once at startup
    send(stream[0], "b", 1, 0);

    char buf[16];
    ssize_t n = read(stream[1], buf, sizeof buf);
    printf("read %zd bytes\n", n);
    close(dgram[0]);
    close(dgram[1]);
    close(stream[0]);
    close(stream[1]);
    return 0;
}
