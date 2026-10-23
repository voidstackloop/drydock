// level: basic
// mode: dynamic
// expect: use-after-close
// what: fcloseall closes the log, and the next fread still uses that FILE*
#define _GNU_SOURCE
#include <stdio.h>

int main(void) {
    FILE *f = fopen("/dev/null", "r");
    if (!f)
        return 1;
    fcloseall();
    char buf[8];
    fread(buf, 1, sizeof buf, f);
    return 0;
}
