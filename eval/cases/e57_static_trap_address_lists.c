// level: expert
// mode: static
// expect: none
// what: trap: address lists freed on every path, in a loop, by the caller, or by an error label; sockets closed on a failed connect
#include <ifaddrs.h>
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
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

int resolve(const char *host, struct addrinfo **out) {
    return getaddrinfo(host, "80", NULL, out); // the caller frees *out
}

int family_of(const char *host, int limit) {
    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, "80", NULL, &res);
    if (rc != 0)
        return -1;
    int family = res->ai_family;
    freeaddrinfo(res);
    return family > limit ? -2 : family;
}

int scoped(void) {
    struct ifaddrs *ifa, *list;
    int n = 0;
    if (getifaddrs(&list) == 0) {
        for (ifa = list; ifa; ifa = ifa->ifa_next)
            n++;
        freeifaddrs(list);
    }
    return n;
}

int by_label(const char *host, int k) {
    struct addrinfo *res;
    int ret = -1;
    if (getaddrinfo(host, "80", NULL, &res) != 0)
        return -1;
    if (k < 0)
        goto out;
    ret = res->ai_family;
out:
    freeaddrinfo(res);
    return ret;
}
