// level: hard
// mode: static
// expect: foreign-unlock
// what: an error path unlocks, then jumps to the cleanup label that unlocks again
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

struct table {
    pthread_mutex_t mu;
    int used, cap;
    int *slots;
};

int table_add(struct table *t, int v) {
    int rc = 0;
    pthread_mutex_lock(&t->mu);
    if (t->used == t->cap) {
        int *grown = realloc(t->slots, 2 * t->cap * sizeof *grown);
        if (!grown) {
            pthread_mutex_unlock(&t->mu);
            fprintf(stderr, "table_add: out of memory\n");
            rc = -1;
            goto out;
        }
        t->slots = grown;
        t->cap *= 2;
    }
    t->slots[t->used++] = v;
out:
    pthread_mutex_unlock(&t->mu);
    return rc;
}
