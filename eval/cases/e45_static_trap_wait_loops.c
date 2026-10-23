// level: expert
// mode: static
// expect: none
// what: trap: condition waits that do test the condition again: while, do-while, for(;;) with break, a goto retry, a wait inside an if inside the loop
#include <pthread.h>
#include <stdbool.h>

struct gate {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    bool open;
    int waiters;
    bool stop;
};

void gate_wait(struct gate *g) {
    pthread_mutex_lock(&g->mu);
    while (!g->open)
        pthread_cond_wait(&g->cv, &g->mu);
    pthread_mutex_unlock(&g->mu);
}

void gate_wait_do(struct gate *g) {
    pthread_mutex_lock(&g->mu);
    do {
        pthread_cond_wait(&g->cv, &g->mu);
    } while (!g->open);
    pthread_mutex_unlock(&g->mu);
}

bool gate_wait_or_stop(struct gate *g) {
    bool opened;
    pthread_mutex_lock(&g->mu);
    for (;;) {
        if (g->open || g->stop) {
            opened = g->open;
            break;
        }
        g->waiters++;
        pthread_cond_wait(&g->cv, &g->mu);
        g->waiters--;
    }
    pthread_mutex_unlock(&g->mu);
    return opened;
}

void gate_wait_goto(struct gate *g) {
    pthread_mutex_lock(&g->mu);
retry:
    if (!g->open) {
        pthread_cond_wait(&g->cv, &g->mu);
        goto retry;
    }
    pthread_mutex_unlock(&g->mu);
}

void gate_wait_nested(struct gate *g, int rounds) {
    pthread_mutex_lock(&g->mu);
    while (rounds-- > 0) {
        if (!g->open) {
            if (!g->stop)
                pthread_cond_wait(&g->cv, &g->mu);
        }
    }
    pthread_mutex_unlock(&g->mu);
}
