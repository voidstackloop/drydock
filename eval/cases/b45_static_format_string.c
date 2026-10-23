// level: basic
// mode: static
// expect: format-string
// what: a greeting is printed with printf(argv[1]), so a %n in the argument writes to memory
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2)
        return 1;
    printf(argv[1]);
    return 0;
}
