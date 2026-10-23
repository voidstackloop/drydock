// level: expert
// mode: static
// expect: alloc-dealloc-mismatch memory-leak
// what: the interface list is released with free(), and another function forgets it on an error path
#include <ifaddrs.h>
#include <stdlib.h>
#include <net/if.h>

int count_up(void) {
    struct ifaddrs *list, *ifa;
    int n = 0;
    if (getifaddrs(&list) != 0)
        return -1;
    for (ifa = list; ifa; ifa = ifa->ifa_next)
        if (ifa->ifa_flags & IFF_UP)
            n++;
    free(list);
    return n;
}

int first_flags(int want_loopback) {
    struct ifaddrs *list;
    if (getifaddrs(&list) == -1)
        return -1;
    if (want_loopback)
        return -2;
    int flags = list->ifa_flags;
    freeifaddrs(list);
    return flags;
}
