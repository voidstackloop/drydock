// level: expert
// mode: dynamic
// expect: none
// what: trap: main locks, unlocks, and only then returns; a worker does the same
#include <pthread.h>

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

static void *worker(void *arg) {
    (void)arg;
    pthread_mutex_lock(&mu);
    pthread_mutex_unlock(&mu);
    return NULL;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    pthread_join(t, NULL);
    pthread_mutex_lock(&mu);
    pthread_mutex_unlock(&mu);
    return 0;
}
