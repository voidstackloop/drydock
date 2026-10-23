// level: hard
// mode: dynamic
// expect: destroy-locked
// what: shutdown destroys the stats mutex while a worker is still inside its critical section
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

struct stats {
    pthread_mutex_t mu;
    long hits;
};

static int started;

static void *flush_worker(void *arg) {
    struct stats *s = arg;
    pthread_mutex_lock(&s->mu);
    __atomic_store_n(&started, 1, __ATOMIC_RELEASE);
    struct timespec d = {0, 30000000}; // a slow flush, under the lock
    nanosleep(&d, NULL);
    s->hits = 0;
    pthread_mutex_unlock(&s->mu);
    return NULL;
}

int main(void) {
    struct stats *s = malloc(sizeof *s);
    pthread_mutex_init(&s->mu, NULL);
    pthread_t t;
    pthread_create(&t, NULL, flush_worker, s);
    while (!__atomic_load_n(&started, __ATOMIC_ACQUIRE)) {
        struct timespec d = {0, 1000000};
        nanosleep(&d, NULL);
    }
    pthread_mutex_destroy(&s->mu); // the worker still holds it
    pthread_join(t, NULL);         // joined too late
    free(s);
    return 0;
}
