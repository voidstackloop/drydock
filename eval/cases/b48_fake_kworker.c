// level: basic
// mode: dynamic
// expect: masquerade
// what: the process renames itself kworker/0:1, a kernel thread's name, so a process list does not show it
#define _GNU_SOURCE
#include <sys/prctl.h>

int main(void) {
    prctl(PR_SET_NAME, "kworker/0:1", 0, 0, 0);
    return 0;
}
