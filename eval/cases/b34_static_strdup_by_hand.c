// level: basic
// mode: static
// expect: heap-buffer-overflow
// what: a hand-written strdup allocates strlen(s) bytes and copies strlen(s) + 1
#include <stdlib.h>
#include <string.h>

char *my_strdup(const char *s) {
    char *copy = malloc(strlen(s));
    if (!copy)
        return NULL;
    strcpy(copy, s);
    return copy;
}
