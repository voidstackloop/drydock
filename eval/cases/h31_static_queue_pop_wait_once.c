// level: hard
// mode: static
// expect: spurious-wakeup
// what: a blocking queue pops right after one wait; a second consumer can take the item first, or the wakeup was spurious, and the pop reads an empty queue
#include <pthread.h>
#include <stdlib.h>

struct queue {
    pthread_mutex_t lock;
    pthread_cond_t nonempty;
    int items[64];
    int count;
};

void queue_push(struct queue *q, int v) {
    pthread_mutex_lock(&q->lock);
    q->items[q->count++] = v;
    pthread_cond_signal(&q->nonempty);
    pthread_mutex_unlock(&q->lock);
}

int queue_pop(struct queue *q) {
    pthread_mutex_lock(&q->lock);
    if (q->count == 0) {
        pthread_cond_wait(&q->nonempty, &q->lock);
    }
    int v = q->items[--q->count];
    pthread_mutex_unlock(&q->lock);
    return v;
}
