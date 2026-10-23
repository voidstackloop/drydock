// level: hard
// mode: dynamic
// expect: select-overflow
// what: a worker waits with pselect() and an nfds taken from a descriptor past FD_SETSIZE
#include <pthread.h>
#include <sys/select.h>

static int g_nfds;

static void *wait_for(void *arg) {
    (void)arg;
    struct timespec ts = {0, 0};
    pselect(g_nfds, NULL, NULL, NULL, &ts, NULL);
    return NULL;
}

int main(void) {
    g_nfds = FD_SETSIZE + 8;
    pthread_t t;
    pthread_create(&t, NULL, wait_for, NULL);
    pthread_join(t, NULL);
    return 0;
}
