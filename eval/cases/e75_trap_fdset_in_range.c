// level: expert
// mode: dynamic
// expect: none
// what: trap: select() and pselect() with nfds at FD_SETSIZE and below, the sets empty, a zero timeout
#include <stddef.h>
#include <sys/select.h>

int main(void) {
    fd_set set;
    FD_ZERO(&set);
    struct timeval tv = {0, 0};
    struct timespec ts = {0, 0};
    select(1, &set, NULL, NULL, &tv);
    select(FD_SETSIZE, NULL, NULL, NULL, &tv);
    pselect(FD_SETSIZE, NULL, NULL, NULL, &ts, NULL);
    return 0;
}
