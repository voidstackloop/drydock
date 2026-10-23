// level: hard
// mode: static
// expect: double-join
// what: on timeout the worker is detached, then the common exit path joins it anyway
#include <pthread.h>
#include <stdio.h>

static void *job(void *arg) { return arg; }

static int wait_done(int seconds) { return seconds > 0; }

int run_job(int seconds) {
    pthread_t t;
    int rc = 0;
    if (pthread_create(&t, NULL, job, NULL) != 0)
        return -1;
    if (!wait_done(seconds)) {
        fprintf(stderr, "job timed out\n");
        pthread_detach(t); // give up on it
        rc = -1;
        goto out;
    }
    puts("job done");
out:
    pthread_join(t, NULL); // also on the timeout path
    return rc;
}
