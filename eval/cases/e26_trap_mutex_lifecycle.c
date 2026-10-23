// level: expert
// mode: dynamic
// expect: none
// what: trap: mutexes destroyed and made again in place: init, initializer copy, and a pool that re-initialises
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct session {
    pthread_mutex_t mu;
    int requests;
    struct session *next_free;
};

static struct session *free_list;

static struct session *session_new(void) {
    struct session *s = free_list;
    if (s)
        free_list = s->next_free;
    else
        s = calloc(1, sizeof *s);
    pthread_mutex_init(&s->mu, NULL); // every time, recycled or not
    s->requests = 0;
    return s;
}

static void session_release(struct session *s) {
    pthread_mutex_destroy(&s->mu);
    s->next_free = free_list;
    free_list = s;
}

int main(void) {
    for (int round = 0; round < 5; round++) {
        struct session *s = session_new();
        pthread_mutex_lock(&s->mu);
        s->requests++;
        pthread_mutex_unlock(&s->mu);
        session_release(s);
    }
    while (free_list) {
        struct session *s = free_list;
        free_list = s->next_free;
        free(s);
    }

    pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
    for (int i = 0; i < 3; i++) {
        pthread_mutex_lock(&m);
        pthread_mutex_unlock(&m);
        pthread_mutex_destroy(&m);
        pthread_mutex_t fresh = PTHREAD_MUTEX_INITIALIZER;
        memcpy(&m, &fresh, sizeof m); // made again by copying the initializer
    }
    pthread_mutex_lock(&m);
    pthread_mutex_unlock(&m);
    pthread_mutex_destroy(&m);
    return 0;
}
