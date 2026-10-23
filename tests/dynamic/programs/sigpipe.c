// Sending on a stream socket while SIGPIPE can still kill the process.
// usage: sigpipe <case>
// The peer end stays open, so no case ever raises the signal: the check is on
// what would happen if it hung up.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

static void call_vdprintf(int fd, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vdprintf(fd, fmt, ap);
    va_end(ap);
}

static void on_pipe(int sig) { (void)sig; }

static volatile int go;
static int worker_fd;

static void *worker(void *arg) {
    (void)arg;
    struct timespec ts = {0, 1000000};
    while (!go)
        nanosleep(&ts, NULL);
    send(worker_fd, "x", 1, 0);
    return NULL;
}

int main(int argc, char **argv) {
    const char *c = argc > 1 ? argv[1] : "send";
    int sv[2];
    int type = strcmp(c, "datagram") == 0 ? SOCK_DGRAM : SOCK_STREAM;
    if (socketpair(AF_UNIX, type, 0, sv) != 0)
        return 1;
    if (strcmp(c, "sendfile") == 0 || strcmp(c, "sendfile_file") == 0) {
        int in = open("/etc/hostname", O_RDONLY);
        int out = sv[0];
        if (strcmp(c, "sendfile_file") == 0)
            out = open("/dev/null", O_WRONLY); // not a socket: no SIGPIPE
        sendfile(out, in, NULL, 32);
        if (out != sv[0])
            close(out);
        close(in);
        close(sv[0]);
        close(sv[1]);
        return 0;
    }
    if (strcmp(c, "dprintf") == 0 || strcmp(c, "vdprintf") == 0) {
        if (c[0] == 'v')
            call_vdprintf(sv[0], "hi\n");
        else
            dprintf(sv[0], "hi %d\n", 1);
        close(sv[0]);
        close(sv[1]);
        return 0;
    }
    if (strcmp(c, "dprintf_file") == 0) {
        int out = open("/dev/null", O_WRONLY);
        dprintf(out, "hi\n");
        close(out);
        close(sv[0]);
        close(sv[1]);
        return 0;
    }
    if (strncmp(c, "write", 5) == 0) { // write() or writev() instead of send()
        const char *w = "hello";
        struct iovec iov = {(void *)w, 5};
        if (strcmp(c, "writev") == 0) { // one end of a socketpair
            writev(sv[0], &iov, 1);
        } else if (strcmp(c, "writev_pipe") == 0) { // a pipe is meant to kill its writer
            int p[2];
            pipe(p);
            writev(p[1], &iov, 1);
            close(p[0]);
            close(p[1]);
        } else if (strcmp(c, "writev_ignored") == 0) {
            signal(SIGPIPE, SIG_IGN);
            writev(sv[0], &iov, 1);
        } else if (strcmp(c, "write") == 0) { // one end of a socketpair
            write(sv[0], w, 5);
        } else if (strcmp(c, "write_pipe") == 0) { // a pipe is meant to kill its writer
            int p[2];
            pipe(p);
            write(p[1], w, 5);
            close(p[0]);
            close(p[1]);
        } else if (strcmp(c, "write_reopened") == 0) { // a socket's number, reopened unseen
            close(sv[0]);
            int again = (int)syscall(SYS_openat, AT_FDCWD, "/dev/null", O_WRONLY);
            write(again, w, 5);
            syscall(SYS_close, again);
            close(sv[1]);
            return 0;
        } else if (strcmp(c, "write_ignored") == 0) {
            signal(SIGPIPE, SIG_IGN);
            write(sv[0], w, 5);
        } else { // write_client, write_accepted, write_accept4: a loopback TCP connection
            int srv = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in a;
            memset(&a, 0, sizeof a);
            a.sin_family = AF_INET;
            a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            bind(srv, (struct sockaddr *)&a, sizeof a); // port 0
            listen(srv, 1);
            socklen_t al = sizeof a;
            getsockname(srv, (struct sockaddr *)&a, &al);
            int cli = socket(AF_INET, SOCK_STREAM, 0);
            connect(cli, (struct sockaddr *)&a, sizeof a);
            int acc = strcmp(c, "write_accept4") == 0 ? accept4(srv, NULL, NULL, SOCK_CLOEXEC)
                                                      : accept(srv, NULL, NULL);
            write(strcmp(c, "write_client") == 0 ? cli : acc, w, 5);
            close(acc);
            close(cli);
            close(srv);
        }
        close(sv[0]);
        close(sv[1]);
        return 0;
    }
    int flags = 0;
    if (strcmp(c, "ignored") == 0)
        signal(SIGPIPE, SIG_IGN);
    else if (strcmp(c, "handled") == 0)
        signal(SIGPIPE, on_pipe);
    else if (strcmp(c, "blocked") == 0) {
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGPIPE);
        pthread_sigmask(SIG_BLOCK, &set, NULL);
    } else if (strcmp(c, "block_after") == 0) {
        send(sv[0], "x", 1, 0); // first look: SIGPIPE still the default
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGPIPE);
        pthread_sigmask(SIG_BLOCK, &set, NULL); // later sends are not a second report
    } else if (strcmp(c, "unblock_after") == 0) {
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGPIPE);
        pthread_sigmask(SIG_BLOCK, &set, NULL);
        send(sv[0], "x", 1, 0); // first look: blocked
        pthread_sigmask(SIG_UNBLOCK, &set, NULL);
    } else if (strcmp(c, "nosignal") == 0)
        flags = MSG_NOSIGNAL;
    else if (strcmp(c, "late") == 0) { // ignored for a while, then back to the default
        signal(SIGPIPE, SIG_IGN);
        send(sv[0], "x", 1, 0);
        signal(SIGPIPE, SIG_DFL);
    }
    pthread_t t;
    if (strcmp(c, "threads") == 0) { // two threads send unprotected: still one report
        worker_fd = sv[0];
        go = 1;
        for (int i = 0; i < 2; i++) {
            pthread_create(&t, NULL, worker, NULL);
            pthread_join(t, NULL);
        }
    }
    if (strcmp(c, "thread") == 0) { // main blocks the signal, but the worker started before that
        worker_fd = sv[0];
        pthread_create(&t, NULL, worker, NULL);
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGPIPE);
        pthread_sigmask(SIG_BLOCK, &set, NULL);
        send(sv[0], "y", 1, 0);
        go = 1;
        pthread_join(t, NULL);
    }
    const char *msg = "hello";
    if (strcmp(c, "sendto") == 0)
        sendto(sv[0], msg, 5, flags, NULL, 0);
    else if (strcmp(c, "sendmsg") == 0) {
        struct iovec iov = {(void *)msg, 5};
        struct msghdr mh;
        memset(&mh, 0, sizeof mh);
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        sendmsg(sv[0], &mh, flags);
    } else if (strcmp(c, "sendmmsg") == 0 || strcmp(c, "sendmmsg_nosignal") == 0) {
        if (c[8] == '_')
            flags = MSG_NOSIGNAL;
        struct iovec iov = {(void *)msg, 5};
        struct mmsghdr mm;
        memset(&mm, 0, sizeof mm);
        mm.msg_hdr.msg_iov = &iov;
        mm.msg_hdr.msg_iovlen = 1;
        sendmmsg(sv[0], &mm, 1, flags);
    } else
        send(sv[0], msg, 5, flags);
    send(sv[0], msg, 5, flags); // a second send: reported once
    close(sv[0]);
    close(sv[1]);
    return 0;
}
