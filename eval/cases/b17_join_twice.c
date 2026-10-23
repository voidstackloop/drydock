// level: basic
// mode: dynamic
// expect: double-join
// what: a thread joined twice
#include <pthread.h>

static void *work(void *arg) { return arg; }

int main(void) {
    pthread_t t;
    pthread_create(&t, NULL, work, NULL);
    pthread_join(t, NULL);
    pthread_join(t, NULL);
    return 0;
}
