#include <pthread.h>
#include <stdio.h>

pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
extern pthread_mutex_t config_lock;
extern int level;

void log_line(const char *s) {
    pthread_mutex_lock(&log_lock);
    pthread_mutex_lock(&config_lock); // reads the level under both
    if (level > 0)
        fputs(s, stderr);
    pthread_mutex_unlock(&config_lock);
    pthread_mutex_unlock(&log_lock);
}
