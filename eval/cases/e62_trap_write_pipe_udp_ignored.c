// level: expert
// mode: dynamic
// expect: none
// what: trap: write() on a pipe (its writer is meant to die with the reader), on a UDP socket, and on a TCP socket after SIGPIPE was ignored with sigaction()
#include <netinet/in.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int p[2];
    pipe(p);
    write(p[1], "log line\n", 9); // a pipe: not a socket

    int udp[2];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, udp);
    write(udp[0], "tick", 4);     // datagrams cannot raise SIGPIPE

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL); // what a server does at startup

    int tcp[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, tcp);
    write(tcp[0], "hello", 5);     // fine now

    close(p[0]);
    close(p[1]);
    close(udp[0]);
    close(udp[1]);
    close(tcp[0]);
    close(tcp[1]);
    return 0;
}
