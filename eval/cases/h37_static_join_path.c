// level: hard
// mode: static
// expect: heap-buffer-overflow
// what: a path join sizes the buffer as the two lengths and then needs a separator and a terminator
#include <stdlib.h>
#include <string.h>

char *join_path(const char *dir, const char *name) {
    char *out = malloc(strlen(dir) + strlen(name));
    if (!out)
        return NULL;
    strcpy(out, dir);
    strcat(out, name);
    return out;
}
