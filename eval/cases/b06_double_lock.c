// level: basic
// mode: dynamic
// expect: double-lock
// what: a function that holds a mutex calls one that locks it again (hangs)
#include <pthread.h>

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static int counter;

static void bump(void) {
    pthread_mutex_lock(&mu);
    counter++;
    pthread_mutex_unlock(&mu);
}

int main(void) {
    pthread_mutex_lock(&mu);
    bump(); // already holding mu
    pthread_mutex_unlock(&mu);
    return 0;
}
