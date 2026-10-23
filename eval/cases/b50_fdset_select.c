// level: basic
// mode: dynamic
// expect: select-overflow
// what: select() is asked to watch more descriptors than an fd_set can hold
#include <stddef.h>
#include <sys/select.h>
#include <sys/time.h>

int main(void) {
    struct timeval tv = {0, 0};
    // NULL sets: nothing is copied, the too-large count is still the bug
    select(FD_SETSIZE + 1, NULL, NULL, NULL, &tv);
    return 0;
}
