// Mutexes: held on a return, locked twice.
#include <mutex>
#include <pthread.h>

struct queue {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int items;
};

int take(struct queue *q) {
    pthread_mutex_lock(&q->mu);
    if (q->items == 0)
        return -1; // expect: lock-leak
    q->items--;
    pthread_mutex_unlock(&q->mu);
    return 0;
}

int take_ok(struct queue *q) {
    pthread_mutex_lock(&q->mu);
    while (q->items == 0)
        pthread_cond_wait(&q->cv, &q->mu);
    q->items--;
    pthread_mutex_unlock(&q->mu);
    return 0;
}

void put_twice(struct queue *q) {
    pthread_mutex_lock(&q->mu);
    q->items++;
    pthread_mutex_lock(&q->mu); // expect: double-lock
    q->items++;
    pthread_mutex_unlock(&q->mu);
}

std::mutex g_mu;
int g_count;

bool bump(int limit) {
    g_mu.lock();
    if (g_count >= limit)
        return false; // expect: lock-leak
    g_count++;
    g_mu.unlock();
    return true;
}

bool bump_ok(int limit) {
    std::lock_guard<std::mutex> guard(g_mu);
    if (g_count >= limit)
        return false;
    g_count++;
    return true;
}

// Two functions, two global mutexes, opposite orders: fine one at a time,
// a deadlock when two threads run them together.
pthread_mutex_t g_accounts = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_journal = PTHREAD_MUTEX_INITIALIZER;

void transfer(int amount) {
    pthread_mutex_lock(&g_accounts);
    pthread_mutex_lock(&g_journal);
    g_count += amount;
    pthread_mutex_unlock(&g_journal);
    pthread_mutex_unlock(&g_accounts);
}

void rotate_journal() {
    pthread_mutex_lock(&g_journal);
    pthread_mutex_lock(&g_accounts); // expect: lock-order-inversion
    g_count = 0;
    pthread_mutex_unlock(&g_accounts);
    pthread_mutex_unlock(&g_journal);
}
