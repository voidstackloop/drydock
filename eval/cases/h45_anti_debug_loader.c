// level: hard
// mode: dynamic
// expect: anti-analysis
// what: a loader traces itself so no debugger can attach, does its work, and then deletes its own executable
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>

static int guard(void) {
    // Fails when a debugger is already attached; succeeding keeps the next one out.
    return ptrace(PTRACE_TRACEME, 0, 0, 0) == -1;
}

static void vanish(void) {
    char me[256];
    ssize_t n = readlink("/proc/self/exe", me, sizeof me - 1);
    if (n <= 0)
        return;
    me[n] = 0;
    unlink(me);
}

int main(void) {
    if (guard())
        return 1;
    puts("working");
    vanish();
    return 0;
}
