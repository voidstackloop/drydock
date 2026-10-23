// level: basic
// mode: dynamic
// expect: use-after-close
// what: a server closes a connection on a bad request and then writes the error reply to the closed descriptor
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    signal(SIGPIPE, SIG_IGN); // a server ignores SIGPIPE; that is not the bug here
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return 1;
    int client = sv[0], conn = sv[1];
    write(client, "BREW coffee\n", 12);

    char request[64];
    ssize_t n = read(conn, request, sizeof request - 1);
    if (n > 0 && strncmp(request, "GET ", 4) != 0) {
        close(conn);                             // bad request: drop the connection
        write(conn, "400 Bad Request\r\n", 17);  // ... and still answer it
    }
    close(client);
    return 0;
}
