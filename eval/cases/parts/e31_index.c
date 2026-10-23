#include <pthread.h>

extern pthread_mutex_t cache_lock, index_lock;
extern int cache_size, index_size;

void index_compact(void) {
    pthread_mutex_lock(&index_lock);
    index_size /= 2;
    pthread_mutex_lock(&cache_lock); // the cache refers to index slots
    cache_size = index_size;
    pthread_mutex_unlock(&cache_lock);
    pthread_mutex_unlock(&index_lock);
}
