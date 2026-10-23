// level: basic
// mode: dynamic
// expect: use-after-close
// what: a file is closed and then read again through the same FILE*
#include <stdio.h>

int main(void) {
    FILE *f = fopen("/dev/null", "r");
    if (!f)
        return 1;
    fclose(f);
    char buf[8];
    fread(buf, 1, sizeof buf, f);
    return 0;
}
