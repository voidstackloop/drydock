// level: basic
// mode: dynamic
// expect: sigpipe-exposure
// what: a tiny HTTP server answers with write() on the accepted socket and leaves SIGPIPE alone: a client that hangs up kills it
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int srv = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(srv, (struct sockaddr *)&addr, sizeof addr); // any free port
    listen(srv, 4);
    socklen_t len = sizeof addr;
    getsockname(srv, (struct sockaddr *)&addr, &len);

    int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    connect(client, (struct sockaddr *)&addr, sizeof addr);
    int conn = accept(srv, NULL, NULL);

    const char *reply = "HTTP/1.0 200 OK\r\n\r\nhello\n";
    write(conn, reply, strlen(reply));

    close(conn);
    close(client);
    close(srv);
    return 0;
}
