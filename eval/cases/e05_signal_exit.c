// level: expert
// mode: dynamic
// expect: signal-unsafe-call
// what: a SIGTERM handler calls exit(), which runs atexit handlers and flushes stdio inside the handler
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static FILE *journal;

static void close_journal(void) {
    if (journal)
        fclose(journal);
}

static void on_term(int sig) {
    (void)sig;
    exit(0); // should be _exit(): atexit handlers are not async-signal-safe
}

int main(void) {
    journal = fopen("/dev/null", "w");
    atexit(close_journal);
    signal(SIGTERM, on_term);
    raise(SIGTERM);
    return 1;
}
