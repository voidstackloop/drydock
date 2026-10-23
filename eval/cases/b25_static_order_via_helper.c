// level: basic
// mode: static
// expect: lock-order-inversion
// what: holding the cache lock, a function calls a helper that takes the stats lock; another takes them the other way
#include <pthread.h>

pthread_mutex_t cache_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;
static long hits, entries;

static void count_hit(void) {
    pthread_mutex_lock(&stats_lock);
    hits++;
    pthread_mutex_unlock(&stats_lock);
}

void cache_get(void) {
    pthread_mutex_lock(&cache_lock);
    count_hit();
    pthread_mutex_unlock(&cache_lock);
}

void report(void) {
    pthread_mutex_lock(&stats_lock);
    pthread_mutex_lock(&cache_lock);
    entries = hits;
    pthread_mutex_unlock(&cache_lock);
    pthread_mutex_unlock(&stats_lock);
}
