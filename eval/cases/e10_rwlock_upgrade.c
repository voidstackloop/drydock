// level: expert
// mode: dynamic
// expect: double-lock
// what: a reader tries to upgrade to a writer while still reading: it waits for itself
#include <pthread.h>

static pthread_rwlock_t config = PTHREAD_RWLOCK_INITIALIZER;
static int version;

static void refresh_if_stale(void) {
    pthread_rwlock_rdlock(&config);
    if (version < 2) {
        pthread_rwlock_wrlock(&config); // never returns
        version = 2;
        pthread_rwlock_unlock(&config);
    }
    pthread_rwlock_unlock(&config);
}

int main(void) {
    refresh_if_stale();
    return 0;
}
