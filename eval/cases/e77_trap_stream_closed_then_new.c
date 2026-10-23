// level: expert
// mode: dynamic
// expect: none
// what: trap: a stream is read and written, closed, and a new stream is used the same way; stderr is never closed
#include <stdio.h>

int main(void) {
    FILE *f = fopen("/dev/null", "r+");
    if (!f)
        return 1;
    char buf[8];
    fread(buf, 1, sizeof buf, f);
    fwrite("x", 1, 1, f);
    fgets(buf, sizeof buf, f);
    fprintf(f, "ok\n");
    fclose(f);
    FILE *g = fopen("/dev/null", "r");
    if (!g)
        return 1;
    fread(buf, 1, 1, g);
    fclose(g);
    fprintf(stderr, "done\n");
    return 0;
}
