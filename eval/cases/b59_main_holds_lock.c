// level: basic
// mode: dynamic
// expect: lock-leak
// what: main locks a mutex and returns without unlocking
#include <pthread.h>

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

int main(void) {
    pthread_mutex_lock(&mu);
    return 0;
}
