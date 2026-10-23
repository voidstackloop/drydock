#include <pthread.h>
#include <stdio.h>

pthread_mutex_t config_lock = PTHREAD_MUTEX_INITIALIZER;
int log_level = 1;
extern pthread_mutex_t log_lock;
static int generation;

void config_reload(int level) {
    pthread_mutex_lock(&config_lock);
    log_level = level;
    generation++;
    pthread_mutex_lock(&log_lock); // a log line, written by hand
    fprintf(stderr, "config generation %d\n", generation);
    pthread_mutex_unlock(&log_lock);
    pthread_mutex_unlock(&config_lock);
}
