// level: expert
// mode: dynamic
// expect: none
// what: trap: a program that opens 200 files at once under a raised limit and closes them all, then reuses the numbers; no limit is reached and nothing leaks
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>

int main(void) {
    struct rlimit rl;
    getrlimit(RLIMIT_NOFILE, &rl);
    rl.rlim_cur = rl.rlim_max < 4096 ? rl.rlim_max : 4096;
    setrlimit(RLIMIT_NOFILE, &rl); // raise the soft limit, as servers do

    int fds[200];
    int n = 0;
    for (; n < 200; n++) {
        fds[n] = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (fds[n] < 0)
            break;
    }
    for (int i = 0; i < n; i++)
        close(fds[i]);
    int again = open("/dev/null", O_RDONLY | O_CLOEXEC);
    printf("opened %d, then %d\n", n, again);
    close(again);
    return 0;
}
