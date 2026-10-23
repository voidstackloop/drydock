// level: hard
// mode: dynamic
// expect: double-join
// what: a pool's stop function runs from main and again from an atexit handler
#include <pthread.h>
#include <stdlib.h>

#define WORKERS 4

static pthread_t workers[WORKERS];
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wake = PTHREAD_COND_INITIALIZER;
static int stopping;

static void *worker(void *arg) {
    pthread_mutex_lock(&mu);
    while (!stopping)
        pthread_cond_wait(&wake, &mu);
    pthread_mutex_unlock(&mu);
    return arg;
}

static void pool_stop(void) {
    pthread_mutex_lock(&mu);
    stopping = 1;
    pthread_cond_broadcast(&wake);
    pthread_mutex_unlock(&mu);
    for (int i = 0; i < WORKERS; i++)
        pthread_join(workers[i], NULL); // the handles are not cleared
}

int main(void) {
    for (int i = 0; i < WORKERS; i++)
        pthread_create(&workers[i], NULL, worker, NULL);
    atexit(pool_stop); // "in case main forgets"
    pool_stop();
    return 0;
}
