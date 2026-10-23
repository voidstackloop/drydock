// level: hard
// mode: dynamic
// expect: sigpipe-exposure
// what: main blocks SIGPIPE "for safety", but the reply thread started before that still has it unblocked
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int conn[2];
static volatile int ready;

static void *reply_thread(void *arg) {
    (void)arg;
    struct timespec ts = {0, 1000000};
    while (!ready)
        nanosleep(&ts, NULL);
    send(conn[0], "pong\n", 5, 0);
    return NULL;
}

int main(void) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, conn) != 0)
        return 1;
    pthread_t t;
    pthread_create(&t, NULL, reply_thread, NULL);

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &set, NULL); // only this thread
    send(conn[0], "ping\n", 5, 0);           // fine: blocked here
    ready = 1;
    pthread_join(t, NULL);

    char buf[32];
    ssize_t n = read(conn[1], buf, sizeof buf);
    printf("read %zd bytes\n", n);
    close(conn[0]);
    close(conn[1]);
    return 0;
}
