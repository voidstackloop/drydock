// level: basic
// mode: dynamic
// expect: destroy-locked
// what: a mutex destroyed while still locked
#include <pthread.h>
#include <stdio.h>

int main(void) {
    pthread_mutex_t mu;
    pthread_mutex_init(&mu, NULL);
    pthread_mutex_lock(&mu);
    puts("work");
    pthread_mutex_destroy(&mu); // forgot to unlock: EBUSY, ignored
    return 0;
}
