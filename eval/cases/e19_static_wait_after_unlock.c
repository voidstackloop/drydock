// level: expert
// mode: static
// expect: foreign-unlock unlocked-wait
// what: a consumer drops the queue lock to process a batch, waits without holding it, and unlocks it again
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

struct item {
    struct item *next;
    int v;
};

struct queue {
    pthread_mutex_t mu;
    pthread_cond_t more;
    struct item *head;
    int closed;
};

void consume_once(struct queue *q) {
    pthread_mutex_lock(&q->mu);
    struct item *batch = q->head;
    q->head = NULL;
    pthread_mutex_unlock(&q->mu); // process without the lock
    while (batch) {
        struct item *next = batch->next;
        printf("%d\n", batch->v);
        free(batch);
        batch = next;
    }
    while (!q->head && !q->closed)
        pthread_cond_wait(&q->more, &q->mu); // q->mu is not held here
    pthread_mutex_unlock(&q->mu);
}
