// level: expert
// mode: static
// expect: none
// what: trap: detached by attributes, pools in arrays and structs, failures handled, handles passed on
#include <pthread.h>
#include <stdio.h>

struct pool {
    pthread_t workers[4];
    pthread_t reaper;
};

static void *work(void *arg) { return arg; }

void fire_and_forget(void) {
    pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    pthread_t t;
    pthread_create(&t, &a, work, NULL);
    pthread_attr_destroy(&a);
}

int pool_start(struct pool *p) {
    for (int i = 0; i < 4; i++)
        if (pthread_create(&p->workers[i], NULL, work, p) != 0)
            return -1;
    pthread_t r;
    int rc = pthread_create(&r, NULL, work, p);
    if (rc != 0)
        return rc;
    p->reaper = r;
    return 0;
}

void pool_stop(struct pool *p) {
    for (int i = 0; i < 4; i++)
        pthread_join(p->workers[i], NULL);
    pthread_join(p->reaper, NULL);
}

static void wait_and_report(pthread_t t) {
    void *ret;
    pthread_join(t, &ret);
    printf("worker returned %p\n", ret);
}

void run_one(void) {
    pthread_t t;
    if (pthread_create(&t, NULL, work, NULL)) {
        perror("pthread_create");
        return;
    }
    wait_and_report(t);
}

void self_detaching(void) {
    pthread_t t;
    if (pthread_create(&t, NULL, work, NULL) == 0)
        pthread_detach(t);
}
