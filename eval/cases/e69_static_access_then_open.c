// level: expert
// mode: static
// expect: toctou-race
// what: access() checks that the caller may read a path, then fopen() opens it: the file can be replaced in between
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2)
        return 1;
    if (access(argv[1], R_OK) == 0) {
        FILE *f = fopen(argv[1], "r");
        if (f)
            fclose(f);
    }
    return 0;
}
