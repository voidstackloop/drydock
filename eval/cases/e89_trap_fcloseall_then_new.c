// level: expert
// mode: dynamic
// expect: none
// what: trap: fcloseall runs, then a new stream is opened, read and closed; the old pointer is not used
#define _GNU_SOURCE
#include <stdio.h>

int main(void) {
    FILE *old = fopen("/dev/null", "r");
    if (!old)
        return 1;
    fcloseall();
    FILE *n = fopen("/dev/null", "r");
    if (!n)
        return 1;
    char buf[8];
    fread(buf, 1, 1, n);
    fclose(n);
    return 0;
}
