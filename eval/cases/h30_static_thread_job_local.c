// level: hard
// mode: static
// expect: thread-stack-argument
// what: the job is built in a local inside the loop body, so each iteration reuses the same stack slot the earlier thread still reads
#include <pthread.h>
#include <stdio.h>

struct job {
    int id;
    const char *path;
};

static void *run(void *arg) {
    const struct job *j = arg;
    printf("job %d: %s\n", j->id, j->path);
    return NULL;
}

int start_all(const char *paths[], int n, pthread_t *threads) {
    for (int i = 0; i < n; i++) {
        struct job job = {i, paths[i]};
        if (pthread_create(&threads[i], NULL, run, &job) != 0)
            return -1;
    }
    return 0;
}
