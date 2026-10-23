#include <pthread.h>

extern pthread_mutex_t queue_lock, stats_lock;
extern int queued, pushes;

int snapshot(void) {
    pthread_mutex_lock(&stats_lock);
    int p = pushes;
    pthread_mutex_lock(&queue_lock);
    int q = queued;
    pthread_mutex_unlock(&queue_lock);
    pthread_mutex_unlock(&stats_lock);
    return p - q;
}
