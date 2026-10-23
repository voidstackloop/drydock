// level: expert
// mode: static
// expect: none
// what: trap: mutexes unlocked and then retaken through a helper, a tested lock, or a reload hook
#include <pthread.h>
#include <sched.h>

struct item {
    struct item *next;
};

struct queue {
    pthread_mutex_t mu;
    pthread_cond_t more;
    struct item *head;
    long pushes;
};

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static long g_gen;

static void queue_lock(struct queue *q) { pthread_mutex_lock(&q->mu); }
static void lock_all(void) { pthread_mutex_lock(&g_mu); }

void push(struct queue *q, struct item *it) {
    pthread_mutex_lock(&q->mu);
    it->next = q->head;
    q->head = it;
    pthread_mutex_unlock(&q->mu);
    pthread_cond_signal(&q->more);
    queue_lock(q); // retaken through the helper
    q->pushes++;
    pthread_mutex_unlock(&q->mu);
}

int pop_retry(struct queue *q) {
    pthread_mutex_lock(&q->mu);
    while (!q->head) {
        pthread_mutex_unlock(&q->mu);
        sched_yield();
        if (pthread_mutex_lock(&q->mu) != 0)
            return -1;
    }
    q->head = q->head->next;
    pthread_mutex_unlock(&q->mu);
    return 0;
}

void reconfigure(void) {
    pthread_mutex_lock(&g_mu);
    g_gen++;
    pthread_mutex_unlock(&g_mu);
    lock_all(); // takes g_mu again
    g_gen++;
    pthread_mutex_unlock(&g_mu);
}
