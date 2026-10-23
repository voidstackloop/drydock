// level: basic
// mode: static
// expect: resource-leak
// what: a FILE stream not closed when reading fails
#include <stdio.h>

int first_line(const char *path, char *out, int n) {
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    if (!fgets(out, n, f))
        return -1; // f stays open
    fclose(f);
    return 0;
}
