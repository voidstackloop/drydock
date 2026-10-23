// level: expert
// mode: static
// expect: thread-stack-argument
// what: one task struct is refilled field by field for each thread while an earlier thread may not have read it yet
#include <pthread.h>
#include <stdio.h>
#include <string.h>

struct task {
    int id;
    char name[32];
    int retries;
};

static void *run(void *arg) {
    struct task *t = arg;
    printf("%d %s %d\n", t->id, t->name, t->retries);
    return NULL;
}

static const char *kNames[] = {"index", "compact", "backup", "report"};

int launch(pthread_t out[4]) {
    struct task tk;
    memset(&tk, 0, sizeof tk);
    for (int i = 0; i < 4; i++) {
        tk.id = i;
        strncpy(tk.name, kNames[i], sizeof tk.name - 1);
        tk.retries = 3;
        if (pthread_create(&out[i], NULL, run, &tk) != 0)
            return -1;
    }
    return 0;
}
