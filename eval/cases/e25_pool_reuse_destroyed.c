// level: expert
// mode: dynamic
// expect: use-after-destroy
// what: an object pool destroys a session's mutex on release but recycles the session without initialising it again
#include <pthread.h>
#include <stdlib.h>

struct session {
    pthread_mutex_t mu;
    int requests;
    struct session *next_free;
};

static struct session *free_list;

static struct session *session_new(void) {
    struct session *s = free_list;
    if (s) {
        free_list = s->next_free; // recycled: mu is still destroyed
        s->requests = 0;
        return s;
    }
    s = calloc(1, sizeof *s);
    pthread_mutex_init(&s->mu, NULL);
    return s;
}

static void session_release(struct session *s) {
    pthread_mutex_destroy(&s->mu);
    s->next_free = free_list;
    free_list = s;
}

static void handle(struct session *s) {
    pthread_mutex_lock(&s->mu);
    s->requests++;
    pthread_mutex_unlock(&s->mu);
}

int main(void) {
    struct session *a = session_new();
    handle(a);
    session_release(a);
    struct session *b = session_new(); // gets a back
    handle(b);
    session_release(b);
    while (free_list) {
        struct session *s = free_list;
        free_list = s->next_free;
        free(s);
    }
    return 0;
}
