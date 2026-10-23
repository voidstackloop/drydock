// level: expert
// mode: dynamic
// expect: lock-leak
// what: a worker locks and unlocks its own mutex; main still holds another when it returns
#include <pthread.h>

static pthread_mutex_t job = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t done = PTHREAD_MUTEX_INITIALIZER;

static void *worker(void *arg) {
    (void)arg;
    pthread_mutex_lock(&job);
    pthread_mutex_unlock(&job);
    return NULL;
}

int main(void) {
    pthread_mutex_lock(&done);
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    pthread_join(t, NULL);
    return 0;
}
