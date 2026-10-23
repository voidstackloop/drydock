// level: basic
// mode: static
// expect: none
// what: trap: every path frees and closes
#include <stdio.h>
#include <stdlib.h>

int count_lines(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char *buf = malloc(256);
    if (!buf) {
        fclose(f);
        return -1;
    }
    int n = 0;
    while (fgets(buf, 256, f))
        n++;
    free(buf);
    fclose(f);
    return n;
}
