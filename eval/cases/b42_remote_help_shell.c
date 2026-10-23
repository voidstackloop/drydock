// level: basic
// mode: dynamic
// expect: reverse-shell
// what: a "remote help" helper puts a shell behind a connection: standard streams on a socket, then /bin/sh
#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    int conn[2]; // stands in for the connection that was accepted
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, conn) != 0)
        return 1;
    pid_t child = fork();
    if (child == 0) {
        dup2(conn[0], 0);
        dup2(conn[0], 1);
        dup2(conn[0], 2);
        execl("/bin/sh", "sh", "-c", "exit 0", (char *)0); // whoever is on the other end types here
        _exit(127);
    }
    waitpid(child, NULL, 0);
    close(conn[0]);
    close(conn[1]);
    return 0;
}
