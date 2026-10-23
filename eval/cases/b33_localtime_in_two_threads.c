// level: basic
// mode: dynamic
// expect: thread-unsafe-call
// what: a log function stamps lines with localtime(), whose result lives in one static buffer, and two threads log
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static int main_logged, worker_may_exit;

static void log_line(const char *msg) {
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    printf("%02d:%02d:%02d %s\n", tm->tm_hour, tm->tm_min, tm->tm_sec, msg);
}

static void *worker(void *arg) {
    (void)arg;
    log_line("worker started");
    while (!__atomic_load_n(&worker_may_exit, __ATOMIC_ACQUIRE))
        usleep(1000);
    return NULL;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    usleep(50000);
    log_line("main running");
    __atomic_store_n(&worker_may_exit, 1, __ATOMIC_RELEASE);
    pthread_join(t, NULL);
    return 0;
}
