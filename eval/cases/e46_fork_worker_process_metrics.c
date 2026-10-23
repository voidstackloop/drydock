// level: expert
// mode: dynamic
// expect: orphaned-lock
// what: a runner forks an isolated worker process; the worker records a metric under a lock that the reporter thread held at the moment of the fork
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct metrics {
    pthread_mutex_t lock;
    long jobs_started;
    long jobs_failed;
};

static struct metrics g_metrics = {PTHREAD_MUTEX_INITIALIZER, 0, 0};
static volatile int g_reporting;
static volatile int g_stop;

static void nap_ms(int ms) {
    struct timespec ts = {0, ms * 1000000L};
    nanosleep(&ts, NULL);
}

static void metrics_job_started(void) {
    pthread_mutex_lock(&g_metrics.lock);
    g_metrics.jobs_started++;
    pthread_mutex_unlock(&g_metrics.lock);
}

static void *reporter(void *arg) {
    (void)arg;
    while (!g_stop) {
        pthread_mutex_lock(&g_metrics.lock);
        g_reporting = 1;
        printf("started=%ld failed=%ld\n", g_metrics.jobs_started,
               g_metrics.jobs_failed);
        nap_ms(50);
        g_reporting = 0;
        pthread_mutex_unlock(&g_metrics.lock);
        nap_ms(2);
    }
    return NULL;
}

static int run_isolated(void (*job)(void)) {
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        metrics_job_started(); // the child counts its own start
        job();
        _exit(0);
    }
    int status = 0;
    waitpid(child, &status, 0);
    return status;
}

static void job(void) { puts("job ran"); }

int main(void) {
    pthread_t t;
    pthread_create(&t, NULL, reporter, NULL);
    while (!g_reporting)
        nap_ms(1);
    run_isolated(job);
    g_stop = 1;
    pthread_join(t, NULL);
    return 0;
}
