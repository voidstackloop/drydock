// level: expert
// mode: static
// expect: lock-order-inversion
// what: a real inversion between two files, next to a third file whose static mutexes share the names
// with: parts/e31_index.c parts/e31_tool.c
#include <pthread.h>

pthread_mutex_t cache_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t index_lock = PTHREAD_MUTEX_INITIALIZER;
int cache_size, index_size;

void cache_insert(void) {
    pthread_mutex_lock(&cache_lock);
    cache_size++;
    pthread_mutex_lock(&index_lock);
    index_size++;
    pthread_mutex_unlock(&index_lock);
    pthread_mutex_unlock(&cache_lock);
}
