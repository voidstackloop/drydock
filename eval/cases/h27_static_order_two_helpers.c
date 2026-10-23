// level: hard
// mode: static
// expect: lock-order-inversion
// what: both orders go through helpers: each side holds its own lock and calls a helper that takes the other
#include <pthread.h>

static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t pool_lock = PTHREAD_MUTEX_INITIALIZER;
static int queued, idle_workers;

static void wake_worker(void) {
    pthread_mutex_lock(&pool_lock);
    idle_workers--;
    pthread_mutex_unlock(&pool_lock);
}

static void requeue(void) {
    pthread_mutex_lock(&queue_lock);
    queued++;
    pthread_mutex_unlock(&queue_lock);
}

void submit(void) {
    pthread_mutex_lock(&queue_lock);
    queued++;
    wake_worker(); // queue -> pool
    pthread_mutex_unlock(&queue_lock);
}

void worker_gives_up(void) {
    pthread_mutex_lock(&pool_lock);
    idle_workers++;
    requeue(); // pool -> queue
    pthread_mutex_unlock(&pool_lock);
}
