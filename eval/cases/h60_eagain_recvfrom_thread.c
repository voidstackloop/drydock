// level: hard
// mode: dynamic
// expect: socket-eagain-spin
// what: a worker's recvfrom loop never waits, so every call returns EAGAIN
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

static int fd;

static void *worker(void *arg) {
    (void)arg;
    char buf[8];
    for (int i = 0; i < 1000; i++)
        recvfrom(fd, buf, sizeof buf, 0, NULL, NULL);
    return NULL;
}

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return 1;
    fcntl(sv[0], F_SETFL, O_NONBLOCK);
    fd = sv[0];
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    pthread_join(t, NULL);
    close(sv[0]);
    close(sv[1]);
    return 0;
}
