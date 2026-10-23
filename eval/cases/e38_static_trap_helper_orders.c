// level: expert
// mode: static
// expect: none
// what: trap: helpers called with nothing held, after unlocking, or taking locks in the one global order
#include <pthread.h>

static pthread_mutex_t a = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t b = PTHREAD_MUTEX_INITIALIZER;
static int x, y;

static void bump_b(void) {
    pthread_mutex_lock(&b);
    y++;
    pthread_mutex_unlock(&b);
}

static void bump_a(void) {
    pthread_mutex_lock(&a);
    x++;
    pthread_mutex_unlock(&a);
}

void ordered(void) {
    pthread_mutex_lock(&a);
    bump_b(); // a -> b, the only order
    pthread_mutex_unlock(&a);
}

void after_unlock(void) {
    pthread_mutex_lock(&b);
    y--;
    pthread_mutex_unlock(&b);
    bump_a(); // b is no longer held
}

void nothing_held(void) {
    bump_b();
    bump_a();
}
