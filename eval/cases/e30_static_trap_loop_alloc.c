// level: expert
// mode: static
// expect: none
// what: trap: allocations in loops that are freed, handed on, chained, grown through a temporary, or made once
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct list;
void list_push(struct list *l, char *item);

void collect(struct list *l, FILE *in) {
    char buf[128];
    char *item;
    while (fgets(buf, sizeof buf, in)) {
        item = strdup(buf);
        list_push(l, item);
    }
}

void each_file(const char **paths, int n) {
    char buf[64];
    int fd;
    for (int i = 0; i < n; i++) {
        fd = open(paths[i], O_RDONLY);
        if (fd < 0)
            continue;
        if (read(fd, buf, sizeof buf) < 0)
            perror("read");
        close(fd);
    }
}

void rotate(int n) {
    char *cur, *prev = NULL;
    for (int i = 0; i < n; i++) {
        cur = malloc(32);
        free(prev);
        prev = cur;
    }
    free(prev);
}

char *grow(const char *parts[], int n) {
    char *out = NULL;
    size_t len = 0;
    for (int i = 0; i < n; i++) {
        size_t add = strlen(parts[i]);
        char *bigger = realloc(out, len + add + 1);
        if (!bigger) {
            free(out);
            return NULL;
        }
        out = bigger;
        memcpy(out + len, parts[i], add + 1);
        len += add;
    }
    return out;
}

void labels(int n) {
    char *label;
    for (int i = 0; i < n; i++) {
        if (asprintf(&label, "item-%d", i) < 0)
            continue;
        puts(label);
        free(label);
    }
}

void scratch_once(int n) {
    char *buf = NULL;
    for (int i = 0; i < n; i++) {
        if (!buf)
            buf = malloc(256);
        buf[0] = (char)i;
    }
    free(buf);
}
