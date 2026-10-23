// level: hard
// mode: dynamic
// expect: foreign-unlock
// what: a mutex used as a one-shot signal: locked by main, unlocked by the worker
#include <pthread.h>

static pthread_mutex_t done = PTHREAD_MUTEX_INITIALIZER;
static int result;

static void *worker(void *arg) {
    result = 42;
    pthread_mutex_unlock(&done); // "tell main we are finished"
    return arg;
}

int main(void) {
    pthread_mutex_lock(&done);
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    pthread_join(t, NULL);
    pthread_mutex_lock(&done); // "wait for the worker"
    pthread_mutex_unlock(&done);
    return result == 42 ? 0 : 1;
}
