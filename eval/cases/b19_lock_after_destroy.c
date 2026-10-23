// level: basic
// mode: dynamic
// expect: use-after-destroy
// what: a mutex locked after it was destroyed
#include <pthread.h>

static long counter;

int main(void) {
    pthread_mutex_t mu;
    pthread_mutex_init(&mu, NULL);
    pthread_mutex_destroy(&mu);
    pthread_mutex_lock(&mu); // EINVAL, ignored
    counter++;
    pthread_mutex_unlock(&mu);
    return 0;
}
