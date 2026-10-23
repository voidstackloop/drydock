// level: hard
// mode: dynamic
// expect: resource-leak
// what: a worker receives an SCM_RIGHTS descriptor and returns without closing it
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int recv_end;

static void *worker(void *arg) {
    (void)arg;
    char buf[8], cbuf[CMSG_SPACE(sizeof(int))];
    struct iovec iov = {buf, sizeof buf};
    struct msghdr msg;
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof cbuf;
    recvmsg(recv_end, &msg, 0);
    return NULL;
}

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return 1;
    int pass = open("/dev/null", O_RDONLY);
    if (pass < 0)
        return 1;
    char buf[8], cbuf[CMSG_SPACE(sizeof(int))];
    struct iovec iov = {buf, sizeof buf};
    struct msghdr msg;
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof cbuf;
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &pass, sizeof pass);
    sendmsg(sv[0], &msg, MSG_NOSIGNAL);
    close(pass);
    recv_end = sv[1];
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    pthread_join(t, NULL);
    close(sv[0]);
    close(sv[1]);
    return 0;
}
