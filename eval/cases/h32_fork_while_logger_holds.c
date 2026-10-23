// level: hard
// mode: dynamic
// expect: orphaned-lock
// what: a flusher thread keeps the log mutex most of the time; the main thread forks a helper that logs, and the child waits for a lock nobody can release
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int stop;

static void nap_ms(int ms) {
    struct timespec ts = {0, ms * 1000000L};
    nanosleep(&ts, NULL);
}

static void log_line(const char *msg) {
    pthread_mutex_lock(&log_lock);
    fprintf(stderr, "%s\n", msg);
    pthread_mutex_unlock(&log_lock);
}

static void *flusher(void *arg) {
    (void)arg;
    while (!stop) {
        pthread_mutex_lock(&log_lock);
        nap_ms(30); // "write to disk" while holding the lock
        pthread_mutex_unlock(&log_lock);
        nap_ms(1);
    }
    return NULL;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, NULL, flusher, NULL);
    nap_ms(100);
    pid_t child = fork();
    if (child == 0) {
        log_line("helper started");
        _exit(0);
    }
    waitpid(child, NULL, 0);
    stop = 1;
    pthread_join(t, NULL);
    return 0;
}
