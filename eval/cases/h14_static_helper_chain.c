// level: hard
// mode: static
// expect: memory-leak
// what: two levels of helpers (path_join -> xmalloc) and a leak on one error path only
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *xmalloc(size_t n) {
    void *p = malloc(n);
    if (!p)
        abort();
    return p;
}

static char *path_join(const char *dir, const char *name) {
    char *p = xmalloc(strlen(dir) + strlen(name) + 2);
    sprintf(p, "%s/%s", dir, name);
    return p;
}

int size_of(const char *dir, const char *name, long *out) {
    char *path = path_join(dir, name);
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1; // path is lost here
    fseek(f, 0, SEEK_END);
    *out = ftell(f);
    fclose(f);
    free(path);
    return 0;
}

int exists(const char *dir, const char *name) { // correct
    char *path = path_join(dir, name);
    FILE *f = fopen(path, "rb");
    free(path);
    if (!f)
        return 0;
    fclose(f);
    return 1;
}
