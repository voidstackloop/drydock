// level: hard
// mode: dynamic
// expect: lock-order-inversion
// what: a reader that takes a mutex, and a writer that already holds it
#include <pthread.h>

static pthread_rwlock_t table = PTHREAD_RWLOCK_INITIALIZER;
static pthread_mutex_t stats = PTHREAD_MUTEX_INITIALIZER;
static int lookups, entries;

static void *reader(void *arg) {
    pthread_rwlock_rdlock(&table);
    pthread_mutex_lock(&stats); // count the lookup
    lookups++;
    pthread_mutex_unlock(&stats);
    pthread_rwlock_unlock(&table);
    return arg;
}

static void *rebuild(void *arg) {
    pthread_mutex_lock(&stats);
    pthread_rwlock_wrlock(&table); // waits for every reader
    entries = lookups;
    pthread_rwlock_unlock(&table);
    pthread_mutex_unlock(&stats);
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, NULL, reader, NULL);
    pthread_join(t, NULL);
    pthread_create(&t, NULL, rebuild, NULL);
    pthread_join(t, NULL);
    return 0;
}
