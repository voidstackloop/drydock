// level: hard
// mode: dynamic
// expect: none
// what: trap: the reverse order only as a try-lock with back-off, plus a condition wait
#include <pthread.h>
#include <sched.h>

static pthread_mutex_t a = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t b = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ready = PTHREAD_COND_INITIALIZER;
static int done;

static void *forward(void *arg) {
    pthread_mutex_lock(&a);
    pthread_mutex_lock(&b);
    pthread_mutex_unlock(&b);
    pthread_mutex_unlock(&a);
    return arg;
}

static void *backward(void *arg) {
    for (;;) { // b then a, but never waits for a while holding b
        pthread_mutex_lock(&b);
        if (pthread_mutex_trylock(&a) == 0)
            break;
        pthread_mutex_unlock(&b);
        sched_yield();
    }
    pthread_mutex_unlock(&a);
    pthread_mutex_unlock(&b);
    pthread_mutex_lock(&a);
    done = 1;
    pthread_cond_signal(&ready);
    pthread_mutex_unlock(&a);
    return arg;
}

int main(void) {
    pthread_t t1, t2;
    pthread_create(&t1, NULL, forward, NULL);
    pthread_create(&t2, NULL, backward, NULL);
    pthread_mutex_lock(&a);
    while (!done)
        pthread_cond_wait(&ready, &a);
    pthread_mutex_unlock(&a);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    return 0;
}
