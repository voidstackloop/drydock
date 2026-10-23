// level: expert
// mode: dynamic
// expect: dangling-pointer
// env: LEAKCHECK_DANGLING=1
// what: a cache evicts an entry but its index still points at it: a crash waiting for a lookup
#include <stdlib.h>
#include <string.h>

struct entry {
    char key[16];
    int value;
};

static struct entry *slots[8];  // the cache
static struct entry *by_hash[8]; // an index into it

static void put(int i, const char *key, int value) {
    struct entry *e = calloc(1, sizeof *e);
    strncpy(e->key, key, sizeof e->key - 1);
    e->value = value;
    slots[i] = e;
    by_hash[strlen(key) % 8] = e;
}

static void evict(int i) {
    free(slots[i]);
    slots[i] = NULL; // the index entry is forgotten
}

int main(void) {
    put(0, "alpha", 1);
    put(1, "be", 2);
    evict(0);
    // no lookup through by_hash happens in this run: nothing fails yet
    return slots[1]->value == 2 ? 0 : 1;
}
