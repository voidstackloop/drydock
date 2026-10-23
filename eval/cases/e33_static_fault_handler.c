// level: expert
// mode: static
// expect: signal-unsafe-call
// what: a crash handler set through a designated initializer logs with fprintf before dying
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static void on_fault(int sig, siginfo_t *info, void *ctx) {
    (void)ctx;
    fprintf(stderr, "fatal signal %d at %p\n", sig, info->si_addr);
    _exit(128 + sig);
}

void install_crash_handler(void) {
    struct sigaction sa = {.sa_sigaction = on_fault, .sa_flags = SA_SIGINFO};
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
}
