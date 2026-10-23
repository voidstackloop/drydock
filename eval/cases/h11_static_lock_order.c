// level: hard
// mode: static
// expect: lock-order-inversion
// what: two functions take the same two global mutexes in opposite orders
#include <pthread.h>

static pthread_mutex_t cache_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t disk_lock = PTHREAD_MUTEX_INITIALIZER;
static int cached, on_disk;

void flush(void) {
    pthread_mutex_lock(&cache_lock);
    pthread_mutex_lock(&disk_lock);
    on_disk = cached;
    pthread_mutex_unlock(&disk_lock);
    pthread_mutex_unlock(&cache_lock);
}

void reload(void) {
    pthread_mutex_lock(&disk_lock);
    pthread_mutex_lock(&cache_lock);
    cached = on_disk;
    pthread_mutex_unlock(&cache_lock);
    pthread_mutex_unlock(&disk_lock);
}
