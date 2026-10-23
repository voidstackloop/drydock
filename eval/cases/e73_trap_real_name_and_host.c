// level: expert
// mode: dynamic
// expect: none
// what: trap: a process named worker-3, and a download from the real github.com, are what they say they are
#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/prctl.h>

int main(void) {
    prctl(PR_SET_NAME, "worker-3", 0, 0, 0);
    system("curl -fsSL https://github.com/octocat/Hello-World");
    return 0;
}
