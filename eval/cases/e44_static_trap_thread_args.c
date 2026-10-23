// level: expert
// mode: static
// expect: none
// what: trap: thread arguments done right: a shared context, an element per thread, a heap copy, the value itself, and start-then-join in one iteration
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

struct ctx {
    int shared_counter;
    pthread_mutex_t mu;
};

static void *worker(void *arg) {
    (void)arg;
    return NULL;
}

void shared(struct ctx *c) {
    pthread_t t[4];
    for (int i = 0; i < 4; i++)
        pthread_create(&t[i], NULL, worker, c);
    for (int i = 0; i < 4; i++)
        pthread_join(t[i], NULL);
}

void shared_local(void) {
    pthread_t t[4];
    struct ctx c = {0, PTHREAD_MUTEX_INITIALIZER};
    for (int i = 0; i < 4; i++)
        pthread_create(&t[i], NULL, worker, &c);
    for (int i = 0; i < 4; i++)
        pthread_join(t[i], NULL);
}

void element_each(void) {
    pthread_t t[4];
    int ids[4];
    for (int i = 0; i < 4; i++) {
        ids[i] = i;
        pthread_create(&t[i], NULL, worker, &ids[i]);
    }
    for (int i = 0; i < 4; i++)
        pthread_join(t[i], NULL);
}

void heap_copy(void) {
    pthread_t t[4];
    for (int i = 0; i < 4; i++) {
        int *id = malloc(sizeof *id);
        *id = i;
        pthread_create(&t[i], NULL, worker, id);
    }
    for (int i = 0; i < 4; i++)
        pthread_join(t[i], NULL);
}

void by_value(void) {
    pthread_t t[4];
    for (int i = 0; i < 4; i++)
        pthread_create(&t[i], NULL, worker, (void *)(intptr_t)i);
    for (int i = 0; i < 4; i++)
        pthread_join(t[i], NULL);
}

void one_by_one(void) {
    pthread_t t;
    for (int i = 0; i < 4; i++) {
        pthread_create(&t, NULL, worker, &i);
        pthread_join(t, NULL);
    }
}
