// level: basic
// mode: static
// expect: double-join
// what: the same thread joined twice
#include <pthread.h>

static void *work(void *arg) { return arg; }

void run(void) {
    pthread_t t;
    pthread_create(&t, NULL, work, NULL);
    pthread_join(t, NULL);
    pthread_join(t, NULL);
}
