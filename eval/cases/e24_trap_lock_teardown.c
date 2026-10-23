// level: expert
// mode: dynamic
// expect: none
// what: trap: correct teardowns, a last reference freed under its own lock, and a mutex re-initialised while held
#include <pthread.h>
#include <stdlib.h>

struct obj {
    pthread_mutex_t mu;
    int refs;
};

static void obj_unref(struct obj *o) {
    pthread_mutex_lock(&o->mu);
    if (--o->refs == 0) {
        free(o); // nobody else can reach it: its lock goes with it
        return;
    }
    pthread_mutex_unlock(&o->mu);
}

static void *user(void *arg) {
    obj_unref(arg);
    return NULL;
}

int main(void) {
    struct obj *o = malloc(sizeof *o);
    pthread_mutex_init(&o->mu, NULL);
    o->refs = 3;
    pthread_t ts[3];
    for (int i = 0; i < 3; i++)
        pthread_create(&ts[i], NULL, user, o);
    for (int i = 0; i < 3; i++)
        pthread_join(ts[i], NULL);

    pthread_rwlock_t rw;
    pthread_rwlock_init(&rw, NULL);
    pthread_rwlock_rdlock(&rw);
    pthread_rwlock_rdlock(&rw);
    pthread_rwlock_unlock(&rw);
    pthread_rwlock_unlock(&rw);
    pthread_rwlock_destroy(&rw);

    pthread_spinlock_t spin;
    pthread_spin_init(&spin, PTHREAD_PROCESS_PRIVATE);
    pthread_spin_lock(&spin);
    pthread_spin_unlock(&spin);
    pthread_spin_destroy(&spin);

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_t r;
    pthread_mutex_init(&r, &attr);
    pthread_mutex_lock(&r);
    pthread_mutex_lock(&r);
    pthread_mutex_unlock(&r);
    pthread_mutex_unlock(&r);
    pthread_mutex_destroy(&r);

    static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&m);
    pthread_mutex_init(&m, NULL); // reset while held, as a fork child does
    pthread_mutex_lock(&m);
    pthread_mutex_unlock(&m);
    return 0;
}
