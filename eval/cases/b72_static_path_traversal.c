// level: basic
// mode: static
// expect: path-traversal
// what: snprintf joins argv onto /var/data and fopen opens it, with no check that rejects ".."
#include <stdio.h>

int main(int argc, char **argv) {
    char path[128];
    if (argc < 2)
        return 1;
    snprintf(path, sizeof path, "/var/data/%.64s", argv[1]);
    FILE *f = fopen(path, "r");
    if (f)
        fclose(f);
    return 0;
}
