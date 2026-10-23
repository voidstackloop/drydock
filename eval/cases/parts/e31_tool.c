#include <pthread.h>

// A separate tool with its own locks that happen to share the names.
static pthread_mutex_t index_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t cache_lock = PTHREAD_MUTEX_INITIALIZER;
static int rebuilt;

void tool_rebuild(void) {
    pthread_mutex_lock(&index_lock);
    pthread_mutex_lock(&cache_lock);
    rebuilt++;
    pthread_mutex_unlock(&cache_lock);
    pthread_mutex_unlock(&index_lock);
}
