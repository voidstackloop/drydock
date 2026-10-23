// level: expert
// mode: static
// expect: none
// what: trap: a lock taken and released under the same condition
#include <pthread.h>

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static int shared_value;

int update(int value, int locked) {
    if (locked)
        pthread_mutex_lock(&mu);
    shared_value = value;
    if (locked)
        pthread_mutex_unlock(&mu);
    return 0;
}

int update_or_fail(int value) {
    if (pthread_mutex_trylock(&mu) != 0)
        return -1; // not locked: nothing to unlock
    shared_value = value;
    pthread_mutex_unlock(&mu);
    return 0;
}
