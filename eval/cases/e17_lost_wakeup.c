// level: expert
// mode: dynamic
// expect: unlocked-wait
// what: a worker drops the lock for slow work and, on one path, waits without taking it back
#include <pthread.h>
#include <time.h>

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t more = PTHREAD_COND_INITIALIZER;
static int queued = 1, stopping;

static void slow_work(void) {
    struct timespec d = {0, 1000000};
    nanosleep(&d, NULL);
}

static void *worker(void *arg) {
    pthread_mutex_lock(&mu);
    for (int rounds = 0; rounds < 2 && !stopping; rounds++) {
        if (queued) {
            queued--;
            pthread_mutex_unlock(&mu); // work without the lock...
            slow_work();
            if (queued) {
                pthread_mutex_lock(&mu); // ...retaken only on this path
                continue;
            }
        }
        struct timespec until; // the queue is empty: wait for more
        clock_gettime(CLOCK_REALTIME, &until);
        until.tv_nsec = (until.tv_nsec + 20000000) % 1000000000;
        until.tv_sec += 1;
        pthread_cond_timedwait(&more, &mu, &until); // mu not held after work
    }
    pthread_mutex_unlock(&mu);
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    pthread_join(t, NULL);
    return 0;
}
