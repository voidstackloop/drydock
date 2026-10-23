// level: basic
// mode: static
// expect: memory-leak
// what: an early return forgets the buffer
#include <stdlib.h>
#include <string.h>

int parse(const char *in) {
    char *copy = malloc(strlen(in) + 1);
    if (!copy)
        return -1;
    strcpy(copy, in);
    if (copy[0] == '#')
        return 0; // comment line: copy is lost
    free(copy);
    return 1;
}
