// level: basic
// mode: dynamic
// expect: unlocked-wait
// what: a condition wait without locking its mutex first
#include <pthread.h>
#include <time.h>

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ready = PTHREAD_COND_INITIALIZER;

int main(void) {
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_sec += 1;
    pthread_cond_timedwait(&ready, &mu, &until); // mu was never locked
    pthread_mutex_unlock(&mu);
    return 0;
}
