// level: expert
// mode: dynamic
// expect: select-overflow
// what: a helper computes nfds as one past the highest descriptor it was given, and that descriptor is past FD_SETSIZE
#include <stddef.h>
#include <sys/select.h>

static int watch(int highest) {
    struct timeval tv = {0, 0};
    return select(highest + 1, NULL, NULL, NULL, &tv);
}

int main(void) {
    return watch(FD_SETSIZE) == -1 ? 0 : 0;
}
