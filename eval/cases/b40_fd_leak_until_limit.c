// level: basic
// mode: dynamic
// expect: descriptor-limit resource-leak
// what: a request handler opens a log file per request and never closes it, until open() fails with EMFILE
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>

// like `ulimit -n 40` in the service's start script: lower the limit, start again
static void limit_descriptors(char **argv, rlim_t n) {
    if (getenv("LC_EVAL_LIMITED"))
        return;
    struct rlimit rl = {n, n};
    setrlimit(RLIMIT_NOFILE, &rl);
    setenv("LC_EVAL_LIMITED", "1", 1);
    execv("/proc/self/exe", argv);
}

static int handle_request(int id) {
    int log = open("/dev/null", O_WRONLY | O_APPEND); // the access log
    if (log < 0)
        return -1;
    dprintf(log, "request %d\n", id);
    return 0; // forgot close(log)
}

int main(int argc, char **argv) {
    (void)argc;
    limit_descriptors(argv, 40);
    int served = 0;
    for (int id = 0; id < 1000; id++) {
        if (handle_request(id) != 0)
            break;
        served++;
    }
    printf("served %d requests\n", served);
    return 0;
}
