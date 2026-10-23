// level: hard
// mode: static
// expect: heap-use-after-free
// what: a list destroyed by a helper, then read for a log message
#include <stdio.h>
#include <stdlib.h>

struct list {
    int count;
    int *items;
};

static struct list *list_new(int n) {
    struct list *l = malloc(sizeof *l);
    l->count = n;
    l->items = calloc(n, sizeof(int));
    return l;
}

static void list_destroy(struct list *l) {
    if (!l)
        return;
    free(l->items);
    free(l);
}

int import(int n) {
    struct list *l = list_new(n);
    if (n > 1000) {
        list_destroy(l);
        fprintf(stderr, "too many items: %d\n", l->count); // after destroy
        return -1;
    }
    list_destroy(l);
    return 0;
}
