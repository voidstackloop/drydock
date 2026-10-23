// level: hard
// mode: dynamic
// expect: use-after-close
// what: shutdown closes the log and a helper still fflush'es it
#include <stdio.h>

static FILE *logf;

static void open_log(void) { logf = fopen("/dev/null", "w"); }

static void shutdown_log(void) { fclose(logf); }

static void flush_log(void) { fflush(logf); }

int main(void) {
    open_log();
    if (!logf)
        return 1;
    shutdown_log();
    flush_log();
    return 0;
}
