// level: hard
// mode: static
// expect: unbounded-copy
// what: a file name from the command line is copied with strcpy into a 16-byte array
#include <string.h>

void take(int argc, char **argv) {
    char name[16];
    if (argc < 2)
        return;
    strcpy(name, argv[1]);
    (void)name;
}
