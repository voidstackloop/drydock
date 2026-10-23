// level: expert
// mode: static
// expect: none
// what: trap: unref() frees only when the last reference goes, so two unrefs are fine
#include <stdlib.h>

struct buf {
    int refs;
    char *data;
};

static struct buf *buf_new(void) {
    struct buf *b = calloc(1, sizeof *b);
    b->refs = 1;
    return b;
}

static struct buf *buf_ref(struct buf *b) {
    b->refs++;
    return b;
}

static void buf_unref(struct buf *b) {
    if (--b->refs > 0)
        return;
    free(b->data);
    free(b);
}

void share(void) {
    struct buf *b = buf_new();
    struct buf *other = buf_ref(b);
    buf_unref(other);
    buf_unref(b);
}
