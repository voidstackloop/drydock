// level: expert
// mode: static
// expect: lock-order-inversion
// what: a helper defined later in the file takes the log lock under the config lock; another file locks log then config
// with: parts/e37_logger.c
#include <pthread.h>

pthread_mutex_t config_lock = PTHREAD_MUTEX_INITIALIZER;
extern pthread_mutex_t log_lock;
int level;
static void note_change(int v);

void set_level(int v) {
    pthread_mutex_lock(&config_lock);
    level = v;
    note_change(v); // takes log_lock
    pthread_mutex_unlock(&config_lock);
}

static void note_change(int v) {
    pthread_mutex_lock(&log_lock);
    (void)v;
    pthread_mutex_unlock(&log_lock);
}
