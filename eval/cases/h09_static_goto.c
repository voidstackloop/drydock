// level: hard
// mode: static
// expect: memory-leak
// what: a goto cleanup block that frees one buffer on one of the paths only
#include <stdlib.h>
#include <string.h>

int load(const char *a, const char *b) {
    int rc = -1;
    char *first = strdup(a);
    char *second = NULL;
    if (!first)
        goto out;
    second = strdup(b);
    if (!second)
        goto out_first;
    if (strcmp(first, second) == 0)
        goto out; // skips freeing both
    rc = 0;
    free(second);
out_first:
    free(first);
out:
    return rc;
}
