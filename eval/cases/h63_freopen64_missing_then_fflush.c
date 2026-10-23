// level: hard
// mode: dynamic
// expect: memory-leak use-after-close
// what: freopen64 to a missing path closes the stream; fflush on it is use-after-close, and glibc leaks the FILE
#define _GNU_SOURCE
#include <stdio.h>

int main(void) {
    FILE *f = fopen("/dev/null", "r");
    if (!f)
        return 1;
    if (!freopen64("/no/such/lc_eval_h63", "r", f))
        fflush(f);
    return 0;
}
