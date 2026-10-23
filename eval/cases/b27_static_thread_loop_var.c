// level: basic
// mode: static
// expect: thread-stack-argument
// what: every worker is given &i, and the loop keeps changing i, so the workers print the wrong numbers
#include <pthread.h>
#include <stdio.h>

static void *worker(void *arg) {
    printf("worker %d\n", *(int *)arg);
    return NULL;
}

int main(void) {
    pthread_t t[4];
    for (int i = 0; i < 4; i++)
        pthread_create(&t[i], NULL, worker, &i);
    for (int i = 0; i < 4; i++)
        pthread_join(t[i], NULL);
    return 0;
}
