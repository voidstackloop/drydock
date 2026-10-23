// Signal handlers that call what they must not: works almost always, hangs
// when the signal lands inside the same call.
// usage: signals <case>
#define _GNU_SOURCE
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t g_hits;
static sigjmp_buf g_jump;

static void safe(int sig) {
    g_hits++;
    (void)!write(1, "", 0);
    (void)sig;
}

static void safe_info(int sig, siginfo_t *si, void *ctx) {
    g_hits += si->si_signo == sig;
    (void)ctx;
}

static void jump_out(int sig) { siglongjmp(g_jump, sig); }

static void allocates(int sig) {
    char *p = malloc(32);
    free(p);
    (void)sig;
}

static void prints(int sig) { printf("got signal %d\n", sig); }

static void exits(int sig) { exit(sig == SIGTERM ? 0 : 1); }

static void install(int sig, void (*fn)(int)) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = fn;
    sigaction(sig, &sa, NULL);
}

// Async-signal-safe handlers, the old handler handed back as the
// program's own, and a handler left with siglongjmp: no findings.
static int clean(void) {
    signal(SIGUSR1, safe);
    raise(SIGUSR1);
    struct sigaction sa, old;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = safe_info;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR2, &sa, NULL);
    raise(SIGUSR2);
    if (sigaction(SIGUSR2, NULL, &old) != 0 || !(old.sa_flags & SA_SIGINFO) ||
        old.sa_sigaction != safe_info)
        return 3;
    if (signal(SIGUSR1, SIG_DFL) != safe)
        return 4;
    install(SIGUSR1, jump_out);
    if (sigsetjmp(g_jump, 1) == 0)
        raise(SIGUSR1);
    char *after = malloc(16); // outside any handler now
    free(after);
    return g_hits == 2 ? 0 : 5;
}

int main(int argc, char **argv) {
    const char *c = argc > 1 ? argv[1] : "clean";
    if (!strcmp(c, "clean"))
        return clean();
    if (!strcmp(c, "malloc"))
        install(SIGUSR1, allocates);
    else if (!strcmp(c, "printf"))
        install(SIGUSR1, prints);
    else if (!strcmp(c, "exit"))
        install(SIGTERM, exits);
    else
        return 64;
    raise(!strcmp(c, "exit") ? SIGTERM : SIGUSR1);
    return 0;
}
