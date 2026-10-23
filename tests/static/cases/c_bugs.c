// Each "expect:" comment names the finding the static engine must report on
// that line. Lines without one must stay silent.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *g_keep;

int leak_on_return(int n) {
    char *buf = malloc(n);
    if (!buf)
        return -1;
    memset(buf, 0, n);
    return 0; // expect: memory-leak
}

int leak_on_error_path(const char *path) {
    char *buf = malloc(64);
    FILE *f = fopen(path, "r");
    if (!f)
        return -1; // expect: memory-leak
    fclose(f);
    free(buf);
    return 0;
}

void double_free(void) {
    char *p = malloc(10);
    free(p);
    free(p); // expect: double-free
}

void use_after_free(void) {
    int *p = malloc(sizeof *p);
    *p = 1;
    free(p);
    printf("%d\n", *p); // expect: heap-use-after-free
}

void free_list(struct node { struct node *next; } *head) {
    for (struct node *p = head; p; p = p->next) // expect: heap-use-after-free
        free(p);
}

void overwrite(void) {
    char *p = malloc(10);
    p = malloc(20); // expect: memory-leak
    free(p);
}

void loop_leak(int n) {
    for (int i = 0; i < n; i++) {
        char *tmp = malloc(16);
        tmp[0] = 0;
    } // expect: memory-leak
}

void bad_frees(void) {
    int local = 0;
    char arr[16];
    free(&local); // expect: invalid-free
    free(arr);    // expect: invalid-free
    char *s = malloc(8);
    free(s + 1); // expect: invalid-free
    free(s);
}

void grow(size_t n) {
    char *p = malloc(4);
    p = realloc(p, n); // expect: memory-leak
    free(p);
}

int *dangling(void) {
    int x = 5;
    return &x; // expect: dangling-pointer
}

// ---- idioms that must not be reported ----

char *returns_ownership(size_t n) {
    char *p = malloc(n);
    if (p)
        p[0] = 0;
    return p;
}

void stored_globally(void) { g_keep = malloc(32); }

void out_param(char **out) {
    char *p = strdup("x");
    *out = p;
}

int goto_cleanup(int n) {
    int rc = -1;
    char *a = malloc(n);
    if (!a)
        goto out;
    char *b = malloc(n);
    if (!b)
        goto free_a;
    rc = 0;
    free(b);
free_a:
    free(a);
out:
    return rc;
}

void freed_on_all_paths(int c) {
    char *p = malloc(4);
    if (c) {
        free(p);
        return;
    }
    free(p);
}

void handed_off(void (*sink)(void *)) {
    void *p = malloc(8);
    sink(p);
}

void null_checked(void) {
    char *p = NULL;
    if (p)
        free(p);
    p = malloc(3);
    free(p);
    p = NULL;
    free(p);
}

void aligned(void) {
    void *p;
    if (posix_memalign(&p, 64, 128))
        return;
    free(p);
}

int calls_exit(void) {
    char *p = malloc(10);
    if (!p)
        exit(1);
    exit(0);
}

void walk(char *s) {
    char *copy = strdup(s);
    char *c = copy;
    while (*c)
        c++;
    free(copy);
}
