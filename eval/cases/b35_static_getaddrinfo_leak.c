// level: basic
// mode: static
// expect: memory-leak
// what: the address list from getaddrinfo is not freed when the function returns early
#include <netdb.h>
#include <string.h>

int family_of(const char *host, int limit) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    if (getaddrinfo(host, "80", &hints, &res) != 0)
        return -1;
    if (res->ai_family > limit)
        return -2;
    int family = res->ai_family;
    freeaddrinfo(res);
    return family;
}
