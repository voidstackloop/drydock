// One program, one bug class per command-line argument.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int global_int;

__attribute__((noinline)) static void double_free(void) {
    char *p = malloc(16);
    free(p);
    free(p);
}

__attribute__((noinline)) static void double_free_after_reuse(void) {
    char *p = malloc(32);
    free(p);
    char *q = malloc(32); // the same chunk would be reused without quarantine
    q[0] = 1;
    free(p);
    free(q);
}

__attribute__((noinline)) static void overflow(void) {
    char *p = malloc(10);
    memset(p, 'x', 11); // one byte too many
    free(p);
}

__attribute__((noinline)) static void underflow(void) {
    char *p = malloc(10);
    p[-1] = 'x';
    free(p);
}

__attribute__((noinline)) static void overflow_never_freed(void) {
    static char *keep;
    keep = malloc(8);
    keep[8] = 'x';
}

__attribute__((noinline)) static void use_after_free_write(void) {
    char *p = malloc(24);
    free(p);
    p[5] = 'x';
}

__attribute__((noinline)) static void use_after_free_read(void) {
    volatile char *p = malloc(24);
    free((void *)p);
    printf("%d\n", p[3]);
}

__attribute__((noinline)) static void invalid_free_stack(void) {
    int local = 0;
    free(&local);
}

__attribute__((noinline)) static void invalid_free_global(void) { free(&global_int); }

__attribute__((noinline)) static void invalid_free_interior(void) {
    char *p = malloc(32);
    free(p + 4);
    free(p);
}

__attribute__((noinline)) static void realloc_stale(void) {
    char *p = malloc(16);
    char *q = realloc(p, 4096);
    p[0] = 'x'; // p may have moved
    free(q);
}

__attribute__((noinline)) static void realloc_freed(void) {
    char *p = malloc(16);
    free(p);
    p = realloc(p, 32);
    free(p);
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        const char *c = argv[i];
        if (!strcmp(c, "double-free")) double_free();
        else if (!strcmp(c, "double-free-reuse")) double_free_after_reuse();
        else if (!strcmp(c, "overflow")) overflow();
        else if (!strcmp(c, "underflow")) underflow();
        else if (!strcmp(c, "overflow-live")) overflow_never_freed();
        else if (!strcmp(c, "uaf-write")) use_after_free_write();
        else if (!strcmp(c, "uaf-read")) use_after_free_read();
        else if (!strcmp(c, "free-stack")) invalid_free_stack();
        else if (!strcmp(c, "free-global")) invalid_free_global();
        else if (!strcmp(c, "free-interior")) invalid_free_interior();
        else if (!strcmp(c, "realloc-stale")) realloc_stale();
        else if (!strcmp(c, "realloc-freed")) realloc_freed();
        else { fprintf(stderr, "unknown case %s\n", c); return 64; }
    }
    return 0;
}
