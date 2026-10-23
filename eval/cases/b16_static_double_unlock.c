// level: basic
// mode: static
// expect: foreign-unlock
// what: a counter's mutex unlocked twice in a row
#include <pthread.h>

struct counter {
    pthread_mutex_t mu;
    long n;
};

void bump(struct counter *c) {
    pthread_mutex_lock(&c->mu);
    c->n++;
    pthread_mutex_unlock(&c->mu);
    pthread_mutex_unlock(&c->mu);
}
