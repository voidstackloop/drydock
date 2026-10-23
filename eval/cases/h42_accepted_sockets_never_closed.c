// level: hard
// mode: dynamic
// expect: descriptor-limit resource-leak
// what: an accept loop closes the connection only after a normal reply; clients that send nothing leak the accepted socket until accept() fails
#define _GNU_SOURCE
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

static void limit_descriptors(char **argv, rlim_t n) {
    if (getenv("LC_EVAL_LIMITED"))
        return;
    struct rlimit rl = {n, n};
    setrlimit(RLIMIT_NOFILE, &rl);
    setenv("LC_EVAL_LIMITED", "1", 1);
    execv("/proc/self/exe", argv);
}

static void serve_one(int srv) {
    int conn = accept(srv, NULL, NULL);
    if (conn < 0)
        return;
    char buf[16];
    ssize_t n = recv(conn, buf, sizeof buf, MSG_DONTWAIT);
    if (n > 0) {
        send(conn, "ok\n", 3, MSG_NOSIGNAL);
        close(conn);
    }
    // n <= 0: the client sent nothing (yet): return without closing conn
}

int main(int argc, char **argv) {
    (void)argc;
    limit_descriptors(argv, 40);
    signal(SIGPIPE, SIG_IGN);
    int srv = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(srv, (struct sockaddr *)&addr, sizeof addr); // any free port
    listen(srv, 64);
    socklen_t len = sizeof addr;
    getsockname(srv, (struct sockaddr *)&addr, &len);

    // 60 stays under the backlog of 64: connect() would block once accept()
    // stops taking connections off a full queue
    for (int i = 0; i < 60; i++) {
        // a client connects and says nothing, then goes away on its own side
        int c = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (c < 0)
            break;
        connect(c, (struct sockaddr *)&addr, sizeof addr);
        serve_one(srv);
        close(c);
    }
    close(srv);
    return 0;
}
