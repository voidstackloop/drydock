// level: basic
// mode: static
// expect: lock-order-inversion
// what: two files lock the same two global mutexes in opposite orders
// with: parts/b22_reader.c
#include <pthread.h>

pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;
int queued, pushes;

void push(void) {
    pthread_mutex_lock(&queue_lock);
    queued++;
    pthread_mutex_lock(&stats_lock);
    pushes++;
    pthread_mutex_unlock(&stats_lock);
    pthread_mutex_unlock(&queue_lock);
}
