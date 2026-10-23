// level: hard
// mode: dynamic
// expect: use-after-close
// what: the log is closed on the error path and the helper still writes the message to it
#include <stdio.h>

static void log_line(FILE *f, const char *msg) { fprintf(f, "%s\n", msg); }

int main(void) {
    FILE *log = fopen("/dev/null", "w");
    if (!log)
        return 1;
    fclose(log); // error path: stop logging
    log_line(log, "request failed");
    return 0;
}
