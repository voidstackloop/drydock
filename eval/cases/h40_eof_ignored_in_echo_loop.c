// level: hard
// mode: dynamic
// expect: socket-eof-spin
// what: an echo loop treats only errors as the end of the connection, so after the client hangs up it spins on read() returning 0
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

static long echo(int conn) {
    char buf[256];
    long echoed = 0;
    int idle = 0;
    for (;;) {
        ssize_t n = read(conn, buf, sizeof buf);
        if (n < 0)
            break;               // error: leave the loop
        if (n == 0 && ++idle > 5000)
            break;               // watchdog added after the CPU alarm; the bug is still there
        if (n > 0)
            echoed += send(conn, buf, (size_t)n, MSG_NOSIGNAL);
    }
    return echoed;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN); // a server ignores SIGPIPE; that is not the bug here
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return 1;
    write(sv[0], "hello\n", 6);
    close(sv[0]); // the client is gone
    printf("echoed %ld bytes\n", echo(sv[1]));
    close(sv[1]);
    return 0;
}
