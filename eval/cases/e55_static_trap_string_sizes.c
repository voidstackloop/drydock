// level: expert
// mode: static
// expect: none
// what: trap: string buffers sized correctly or copied differently: strlen + 1, two lengths + 2, a copy of another string, memcpy without the terminator, a product size
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *dup_ok(const char *s) {
    char *p = malloc(strlen(s) + 1);
    if (p)
        strcpy(p, s);
    return p;
}

char *join_ok(const char *dir, const char *name) {
    char *out = malloc(strlen(dir) + 1 + strlen(name) + 1);
    if (!out)
        return NULL;
    strcpy(out, dir);
    strcat(out, "/");
    strcat(out, name);
    return out;
}

char *copy_of_other(const char *s, const char *fallback) {
    char *p = malloc(strlen(s));
    if (!p)
        return NULL;
    strcpy(p, fallback); // the caller guarantees fallback is shorter than s
    return p;
}

char *no_terminator(const char *s) {
    char *p = malloc(strlen(s));
    if (!p)
        return NULL;
    memcpy(p, s, strlen(s));
    return p;
}

char *grown(const char *s) {
    char *p = malloc(strlen(s));
    if (!p)
        return NULL;
    free(p);
    p = malloc(strlen(s) + 1);
    if (p)
        strcpy(p, s);
    return p;
}

char *formatted(const char *s) {
    size_t n = strlen(s) + 8;
    char *p = malloc(n);
    if (p)
        snprintf(p, n, "<%s>", s);
    return p;
}
