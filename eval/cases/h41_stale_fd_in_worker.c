// level: hard
// mode: dynamic
// expect: use-after-close
// what: a shutdown path closes the connection while a heartbeat thread keeps writing to the saved descriptor number
#define _GNU_SOURCE
#include <pthread.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

struct conn {
    int fd;
    volatile int closed;
};

static void nap(long ms) {
    struct timespec ts = {0, ms * 1000000L};
    nanosleep(&ts, NULL);
}

static void conn_close(struct conn *c) {
    close(c->fd); // fd is not reset to -1
    c->closed = 1;
}

static void *heartbeat(void *arg) {
    struct conn *c = arg;
    while (!c->closed)
        nap(1);
    nap(5);
    write(c->fd, "ping\n", 5); // the result is ignored
    return NULL;
}

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return 1;
    struct conn c = {sv[0], 0};
    pthread_t t;
    pthread_create(&t, NULL, heartbeat, &c);
    nap(10);
    conn_close(&c);
    pthread_join(t, NULL);
    close(sv[1]);
    return 0;
}
