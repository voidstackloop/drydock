// level: expert
// mode: dynamic
// expect: lock-order-inversion
// what: three threads, each correct on its own, form the cycle A->B, B->C, C->A
#include <pthread.h>

static pthread_mutex_t users = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t orders = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t stock = PTHREAD_MUTEX_INITIALIZER;

static void both(pthread_mutex_t *x, pthread_mutex_t *y) {
    pthread_mutex_lock(x);
    pthread_mutex_lock(y);
    pthread_mutex_unlock(y);
    pthread_mutex_unlock(x);
}

static void *signup(void *a) { both(&users, &orders); return a; }   // users -> orders
static void *checkout(void *a) { both(&orders, &stock); return a; } // orders -> stock
static void *restock(void *a) { both(&stock, &users); return a; }   // stock -> users

int main(void) {
    void *(*jobs[])(void *) = {signup, checkout, restock};
    for (int i = 0; i < 3; i++) { // one after another: no two pairs ever clash
        pthread_t t;
        pthread_create(&t, NULL, jobs[i], NULL);
        pthread_join(t, NULL);
    }
    return 0;
}
