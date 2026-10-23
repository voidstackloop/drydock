// level: expert
// mode: dynamic
// expect: use-after-close
// what: one helper fclose's the stream; another fputs's and fflush'es it
#include <stdio.h>

static void finish(FILE *f) { fclose(f); }

static void write_late(FILE *f) {
    int (*p)(const char *, FILE *) = fputs;
    p("late\n", f);
    fflush(f);
}

int main(void) {
    FILE *f = fopen("/dev/null", "w");
    if (!f)
        return 1;
    finish(f);
    write_late(f);
    return 0;
}
