// level: basic
// mode: dynamic
// expect: resource-leak
// what: a client retries connect() on a port nobody listens on and returns without closing the socket of each failed attempt
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int dial(const struct sockaddr_in *addr, int tries) {
    for (int i = 0; i < tries; i++) {
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
            return -1;
        if (connect(fd, (const struct sockaddr *)addr, sizeof *addr) == 0)
            return fd;
        // failed: try again with a fresh socket
    }
    return -1;
}

int main(void) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int probe = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); // find a port that is free, then leave it unused
    bind(probe, (struct sockaddr *)&addr, sizeof addr);
    socklen_t len = sizeof addr;
    getsockname(probe, (struct sockaddr *)&addr, &len);
    close(probe);

    int fd = dial(&addr, 3);
    printf("connected: %s\n", fd >= 0 ? "yes" : "no");
    return 0;
}
