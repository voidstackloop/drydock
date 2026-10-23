// level: hard
// mode: dynamic
// expect: heap-use-after-free
// what: a pointer into a growing buffer is kept across realloc() and written
#include <stdlib.h>
#include <string.h>

struct buf {
    char *data;
    size_t len, cap;
};

static char *append(struct buf *b, const char *s) {
    size_t n = strlen(s);
    if (b->len + n + 1 > b->cap) {
        b->cap = (b->len + n + 1) * 2;
        b->data = realloc(b->data, b->cap);
    }
    char *at = b->data + b->len;
    memcpy(at, s, n + 1);
    b->len += n;
    return at; // where this piece starts
}

int main(void) {
    struct buf b = {0};
    char *first = append(&b, "name=");
    for (int i = 0; i < 20; i++)
        append(&b, "0123456789"); // grows: the block moves
    first[0] = 'N'; // still points into the old block
    free(b.data);
    return 0;
}
