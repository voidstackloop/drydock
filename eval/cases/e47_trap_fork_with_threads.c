// level: expert
// mode: dynamic
// expect: none
// what: trap: fork in a threaded program done safely: atfork handlers take the log lock around fork, a child that only execs, locks released by ending threads, and a recursive lock
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t rec_lock;
static volatile int g_holding;
static volatile int g_stop;

static void nap_ms(int ms) {
    struct timespec ts = {0, ms * 1000000L};
    nanosleep(&ts, NULL);
}

static void log_line(const char *msg) {
    pthread_mutex_lock(&log_lock);
    fprintf(stderr, "%s\n", msg);
    pthread_mutex_unlock(&log_lock);
}

// The whole log lock is taken before fork() and given back on both sides, so
// the child never sees it held by a thread that is not there.
static void before_fork(void) { pthread_mutex_lock(&log_lock); }
static void after_fork(void) { pthread_mutex_unlock(&log_lock); }

static void *flusher(void *arg) {
    (void)arg;
    while (!g_stop) {
        pthread_mutex_lock(&log_lock);
        g_holding = 1;
        nap_ms(20);
        g_holding = 0;
        pthread_mutex_unlock(&log_lock);
        nap_ms(1);
    }
    return NULL;
}

static void *short_lived(void *arg) {
    pthread_mutex_lock(&state_lock);
    pthread_mutex_unlock(&state_lock);
    return arg;
}

int main(void) {
    pthread_atfork(before_fork, after_fork, after_fork);
    pthread_mutexattr_t at;
    pthread_mutexattr_init(&at);
    pthread_mutexattr_settype(&at, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&rec_lock, &at);

    pthread_t t, s;
    pthread_create(&t, NULL, flusher, NULL);
    while (!g_holding)
        nap_ms(1);

    // a helper thread that ended after unlocking: its lock is free again
    pthread_create(&s, NULL, short_lived, NULL);
    pthread_join(s, NULL);
    pthread_mutex_lock(&state_lock);
    pthread_mutex_unlock(&state_lock);

    pid_t child = fork();
    if (child == 0) {
        log_line("child logs after fork"); // fine: the atfork handlers
        pthread_mutex_lock(&rec_lock);
        pthread_mutex_lock(&rec_lock);
        pthread_mutex_unlock(&rec_lock);
        pthread_mutex_unlock(&rec_lock);
        execlp("true", "true", (char *)NULL);
        _exit(127);
    }
    waitpid(child, NULL, 0);

    g_stop = 1;
    pthread_join(t, NULL);
    return 0;
}
