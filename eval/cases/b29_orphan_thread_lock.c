// level: basic
// mode: dynamic
// expect: lock-leak orphaned-lock
// what: a worker returns without unlocking the config mutex, and main then locks it and waits forever
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>

static pthread_mutex_t config_lock = PTHREAD_MUTEX_INITIALIZER;
static int config_version;

static void *reload(void *arg) {
    pthread_mutex_lock(&config_lock);
    config_version++;
    if (!arg)
        return NULL; // forgot to unlock on this path
    pthread_mutex_unlock(&config_lock);
    return NULL;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, NULL, reload, NULL);
    pthread_join(t, NULL);
    pthread_mutex_lock(&config_lock);
    printf("version %d\n", config_version);
    pthread_mutex_unlock(&config_lock);
    return 0;
}
