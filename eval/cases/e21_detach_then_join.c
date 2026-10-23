// level: expert
// mode: dynamic
// expect: double-join
// what: background jobs are detached, but the shutdown loop joins every stored handle
#include <pthread.h>
#include <time.h>

struct job {
    pthread_t thread;
    int background;
};

static void *run(void *arg) {
    struct timespec d = {0, 2000000};
    nanosleep(&d, NULL);
    return arg;
}

static void start(struct job *j, int background) {
    j->background = background;
    pthread_create(&j->thread, NULL, run, j);
    if (background)
        pthread_detach(j->thread); // nobody waits for these
}

static void shutdown_jobs(struct job *jobs, int n) {
    for (int i = 0; i < n; i++)
        pthread_join(jobs[i].thread, NULL); // also the detached ones
}

int main(void) {
    struct job jobs[4];
    for (int i = 0; i < 4; i++)
        start(&jobs[i], i == 2);
    struct timespec d = {0, 20000000};
    nanosleep(&d, NULL);
    shutdown_jobs(jobs, 4);
    return 0;
}
