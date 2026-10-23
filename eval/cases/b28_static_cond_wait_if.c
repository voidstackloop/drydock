// level: basic
// mode: static
// expect: spurious-wakeup
// what: the waiter checks the flag with an if, then waits once: a spurious wakeup goes on without the flag
#include <pthread.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static int ready;

void wait_until_ready(void) {
    pthread_mutex_lock(&lock);
    if (!ready)
        pthread_cond_wait(&cond, &lock);
    pthread_mutex_unlock(&lock);
}

void set_ready(void) {
    pthread_mutex_lock(&lock);
    ready = 1;
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&lock);
}
