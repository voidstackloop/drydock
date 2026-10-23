// level: hard
// mode: dynamic
// expect: sigpipe-exposure
// what: a worker blocks SIGPIPE, sends a probe (that look is safe), then unblocks it and sends the real reply
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

static int conn;

static void *worker(void *arg) {
    (void)arg;
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    send(conn, "p", 1, 0); // first look: blocked
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);
    send(conn, "q", 1, 0); // the default is back for this thread
    return NULL;
}

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return 1;
    conn = sv[0];
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    pthread_join(t, NULL);
    close(sv[0]);
    close(sv[1]);
    return 0;
}
