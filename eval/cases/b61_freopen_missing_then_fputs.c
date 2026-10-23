// level: basic
// mode: dynamic
// expect: memory-leak use-after-close
// what: freopen to a missing path closes the stream; a later fputs is use-after-close, and glibc leaks the FILE
#include <stdio.h>

int main(void) {
    FILE *f = fopen("/dev/null", "r");
    if (!f)
        return 1;
    if (!freopen("/no/such/lc_eval_b61", "r", f)) {
        int (*p)(const char *, FILE *) = fputs;
        p("late\n", f);
    }
    return 0;
}
