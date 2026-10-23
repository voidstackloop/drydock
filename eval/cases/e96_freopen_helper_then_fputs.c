// level: expert
// mode: dynamic
// expect: memory-leak use-after-close
// what: a helper freopen's the log onto a missing path; the caller still fputs's the old pointer
#include <stdio.h>

static int swap_log(FILE *f) { return freopen("/no/such/lc_eval_e96", "w", f) != NULL; }

int main(void) {
    FILE *f = fopen("/dev/null", "w");
    if (!f)
        return 1;
    if (!swap_log(f)) {
        int (*p)(const char *, FILE *) = fputs;
        p("late\n", f);
    }
    return 0;
}
