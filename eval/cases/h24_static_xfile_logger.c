// level: hard
// mode: static
// expect: lock-order-inversion
// what: the logger holds its lock while reading the config; the config reload logs while holding its own
// with: parts/h24_config.c
#include <pthread.h>
#include <stdio.h>

pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
extern pthread_mutex_t config_lock;
extern int log_level;
static FILE *log_file;

void log_msg(int level, const char *msg) {
    pthread_mutex_lock(&log_lock);
    if (!log_file)
        log_file = stderr;
    pthread_mutex_lock(&config_lock); // the level may change under us
    int enabled = level >= log_level;
    pthread_mutex_unlock(&config_lock);
    if (enabled)
        fprintf(log_file, "%s\n", msg);
    pthread_mutex_unlock(&log_lock);
}
