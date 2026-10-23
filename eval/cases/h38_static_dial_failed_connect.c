// level: hard
// mode: static
// expect: resource-leak
// what: a client tries every address; the socket of each failed connect is never closed
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int dial(const char *host, const char *port) {
    struct addrinfo hints, *res, *p;
    int fd = -1;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0)
        return -1;
    for (p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0)
            break;
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}
