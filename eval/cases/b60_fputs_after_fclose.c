// level: basic
// mode: dynamic
// expect: use-after-close
// what: the log is closed and then written with fputs
#include <stdio.h>

int main(void) {
    FILE *f = fopen("/dev/null", "w");
    if (!f)
        return 1;
    fclose(f);
    int (*p)(const char *, FILE *) = fputs;
    p("late\n", f);
    return 0;
}
