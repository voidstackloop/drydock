// level: expert
// mode: dynamic
// expect: sigpipe-exposure
// what: SIGPIPE is ignored at startup, then put back to its default before starting a helper process and never ignored again
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static void run_helper(void) {
    signal(SIGPIPE, SIG_DFL); // children should start with default dispositions
    if (fork() == 0) {
        execlp("true", "true", (char *)NULL);
        _exit(127);
    }
    int status;
    wait(&status);
}

int main(void) {
    int conn[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, conn) != 0)
        return 1;
    signal(SIGPIPE, SIG_IGN);
    send(conn[0], "hello\n", 6, 0); // safe at this point
    run_helper();
    send(conn[0], "bye\n", 4, 0);   // the default is back
    char buf[32];
    ssize_t n = read(conn[1], buf, sizeof buf);
    printf("read %zd bytes\n", n);
    close(conn[0]);
    close(conn[1]);
    return 0;
}
