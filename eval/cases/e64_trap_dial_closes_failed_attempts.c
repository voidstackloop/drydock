// level: expert
// mode: dynamic
// expect: none
// what: trap: the same retrying client, closing the socket of every failed attempt and keeping the successful one, which is closed at the end
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
        close(fd);
    }
    return -1;
}

int main(void) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int server = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int one = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    bind(server, (struct sockaddr *)&addr, sizeof addr); // any free port
    listen(server, 4);
    socklen_t len = sizeof addr;
    getsockname(server, (struct sockaddr *)&addr, &len);

    int fd = dial(&addr, 3);        // connects to the listener
    int missing = dial(&addr, 0);   // no attempt at all
    printf("connected: %s %d\n", fd >= 0 ? "yes" : "no", missing);
    if (fd >= 0)
        close(fd);
    close(server);
    return 0;
}
