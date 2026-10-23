// level: hard
// mode: dynamic
// expect: use-after-close
// what: shutdown calls fcloseall, and the logger still fprintf's the message it was holding
#define _GNU_SOURCE
#include <stdio.h>

static FILE *logf;

static void open_log(void) { logf = fopen("/dev/null", "w"); }

static void shutdown_logs(void) { fcloseall(); }

static void write_log(const char *text) { fprintf(logf, "%s\n", text); }

int main(void) {
    open_log();
    if (!logf)
        return 1;
    shutdown_logs();
    write_log("late");
    return 0;
}
