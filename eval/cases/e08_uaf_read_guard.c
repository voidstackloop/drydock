// level: expert
// mode: dynamic
// expect: heap-use-after-free
// args: --guard-every 1
// what: a freed block only read, never written (needs guard pages)
#include <stdlib.h>

struct session {
    int id;
    int expired;
};

static int is_expired(const struct session *s) { return s->expired; }

int main(void) {
    struct session *s = calloc(1, sizeof *s);
    free(s);
    return is_expired(s); // a read: the bytes are still there
}
