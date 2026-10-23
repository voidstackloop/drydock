// level: basic
// mode: dynamic
// expect: sigpipe-exposure
// what: a server replies with send(fd, buf, n, 0) and never deals with SIGPIPE: a client that hangs up kills it
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int reply(int fd, const char *text) {
    return (int)send(fd, text, strlen(text), 0);
}

int main(void) {
    int conn[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, conn) != 0)
        return 1;
    reply(conn[0], "HTTP/1.0 200 OK\r\n\r\nhello\n");
    char buf[64];
    ssize_t n = read(conn[1], buf, sizeof buf);
    printf("client got %zd bytes\n", n);
    close(conn[0]);
    close(conn[1]);
    return 0;
}
