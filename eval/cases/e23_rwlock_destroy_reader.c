// level: expert
// mode: dynamic
// expect: destroy-locked
// what: a cache's read-write lock is destroyed while a reader thread still holds it for reading
#include <pthread.h>
#include <time.h>

struct cache {
    pthread_rwlock_t lock;
    int entries[16];
};

static struct cache g_cache = {PTHREAD_RWLOCK_INITIALIZER, {0}};
static int reading;

static void *reader(void *arg) {
    pthread_rwlock_rdlock(&g_cache.lock);
    __atomic_store_n(&reading, 1, __ATOMIC_RELEASE);
    long sum = 0;
    for (int round = 0; round < 20; round++) {
        for (int i = 0; i < 16; i++)
            sum += g_cache.entries[i];
        struct timespec d = {0, 1000000};
        nanosleep(&d, NULL);
    }
    pthread_rwlock_unlock(&g_cache.lock);
    return (void *)sum;
}

static void cache_teardown(void) {
    pthread_rwlock_destroy(&g_cache.lock); // a reader is still inside
}

int main(void) {
    pthread_t t;
    pthread_create(&t, NULL, reader, NULL);
    while (!__atomic_load_n(&reading, __ATOMIC_ACQUIRE)) {
        struct timespec d = {0, 1000000};
        nanosleep(&d, NULL);
    }
    cache_teardown();
    pthread_join(t, NULL);
    return 0;
}
