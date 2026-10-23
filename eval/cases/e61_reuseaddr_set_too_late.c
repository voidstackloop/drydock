// level: expert
// mode: dynamic
// expect: bind-without-reuseaddr
// what: SO_REUSEADDR is set after bind(), which is too late to matter, so the restart problem remains
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int open_server(int port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int rc = bind(fd, (struct sockaddr *)&addr, sizeof addr);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one); // after bind: no effect on it
    if (rc != 0 || listen(fd, 8) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int main(void) {
    int fd = open_server(41103);
    if (fd >= 0)
        close(fd);
    return 0;
}
