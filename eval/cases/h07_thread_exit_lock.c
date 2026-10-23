// level: hard
// mode: dynamic
// expect: lock-leak
// what: a worker's error path returns without unlocking
#include <pthread.h>
#include <stdlib.h>

static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
static int queue[8], queued;

static int work(int item) { return item % 3 == 0 ? -1 : item; }

static void *worker(void *arg) {
    pthread_mutex_lock(&queue_lock);
    int item = queued ? queue[--queued] : 0;
    if (work(item) < 0)
        return NULL; // error: queue_lock stays locked forever
    pthread_mutex_unlock(&queue_lock);
    return arg;
}

int main(void) {
    queue[queued++] = 3;
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    pthread_join(t, NULL);
    return 0;
}
