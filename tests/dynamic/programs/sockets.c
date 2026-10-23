// Descriptor and socket use that goes wrong: calls on a closed descriptor, a
// read loop that ignores end of file, bind() without SO_REUSEADDR, select()
// with nfds past FD_SETSIZE.
// usage: sockets <case>
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/sendfile.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

static void call_vdprintf(int fd, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vdprintf(fd, fmt, ap);
    va_end(ap);
}

static struct sockaddr_in loopback(int port) {
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return a;
}

// bind a TCP socket to `port`; the options say what to set first
static void listen_on(int port, int reuse, int reuse_port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    if (reuse)
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (reuse_port)
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
    struct sockaddr_in a = loopback(port);
    bind(fd, (struct sockaddr *)&a, sizeof a);
    close(fd);
}

static int leak_open(void) { return open("/dev/null", O_RDONLY); }
static int leak_socket(void) { return socket(AF_UNIX, SOCK_STREAM, 0); }
static int leak_pipe(void) {
    int p[2];
    return pipe(p);
}
static int leak_fopen(void) { return fopen("/dev/null", "r") ? 0 : -1; }
static void *g_kept; // reachable through a global: found only by reading the memory map
static __attribute__((noinline)) void leak_block(void) {
    malloc(77);
    g_kept = malloc(33);
}

int main(int argc, char **argv) {
    const char *c = argc > 1 ? argv[1] : "write_closed";
    signal(SIGPIPE, SIG_IGN); // these cases are not about SIGPIPE (tests/dynamic/programs/sigpipe.c is)
    // select/pselect. NULL sets and a zero timeout: the kernel copies nothing,
    // so a too-large nfds is reported and does not smash this stack.
    if (!strncmp(c, "select_", 7) || !strncmp(c, "pselect_", 8)) {
        struct timeval tv = {0, 0};
        struct timespec ts = {0, 0};
        if (!strcmp(c, "select_big") || !strcmp(c, "select_loop")) {
            int rounds = !strcmp(c, "select_loop") ? 2 : 1;
            for (int i = 0; i < rounds; i++)
                select(FD_SETSIZE + 1, NULL, NULL, NULL, &tv);
        } else if (!strcmp(c, "select_edge"))
            select(FD_SETSIZE, NULL, NULL, NULL, &tv);
        else if (!strcmp(c, "select_ok")) {
            fd_set set;
            FD_ZERO(&set);
            select(1, &set, NULL, NULL, &tv);
        } else if (!strcmp(c, "pselect_big"))
            pselect(FD_SETSIZE + 1, NULL, NULL, NULL, &ts, NULL);
        else if (!strcmp(c, "pselect_ok"))
            pselect(1, NULL, NULL, NULL, &ts, NULL);
        return 0;
    }
    if (strncmp(c, "exhaust_", 8) == 0) { // leak descriptors until the limit (ulimit -n 40, set by the test)
        open("/dev/null", O_RDONLY); // one from somewhere else: not the top opener
        leak_block();                // a heap leak the exit scan must still find
        for (int i = 0; i < 100; i++) {
            int fd = !strcmp(c + 8, "open")     ? leak_open()
                     : !strcmp(c + 8, "socket") ? leak_socket()
                     : !strcmp(c + 8, "fopen")  ? leak_fopen()
                                                : leak_pipe();
            if (fd < 0)
                break;
        }
        // the program goes on trying: reported once all the same
        leak_open();
        leak_open();
        return 0;
    }
    int sv[2];
    char buf[16];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return 1;

    // ---- calls on a descriptor that close() released
    if (strncmp(c, "closed_", 7) == 0) {
        const char *call = c + 7;
        int fd = sv[0];
        close(fd);
        if (!strcmp(call, "write"))
            write(fd, "x", 1);
        else if (!strcmp(call, "writev")) {
            struct iovec iov = {(void *)"x", 1};
            writev(fd, &iov, 1);
        }
        else if (!strcmp(call, "read"))
            read(fd, buf, sizeof buf);
        else if (!strcmp(call, "readv")) {
            struct iovec iov = {buf, sizeof buf};
            readv(fd, &iov, 1);
        } else if (!strcmp(call, "pread"))
            pread(fd, buf, sizeof buf, 0);
        else if (!strcmp(call, "pread64"))
            pread64(fd, buf, sizeof buf, 0);
        else if (!strcmp(call, "pwrite"))
            pwrite(fd, "x", 1, 0);
        else if (!strcmp(call, "pwrite64"))
            pwrite64(fd, "x", 1, 0);
        else if (!strcmp(call, "preadv")) {
            struct iovec iov = {buf, sizeof buf};
            preadv(fd, &iov, 1, 0);
        } else if (!strcmp(call, "preadv64")) {
            struct iovec iov = {buf, sizeof buf};
            preadv64(fd, &iov, 1, 0);
        } else if (!strcmp(call, "pwritev")) {
            struct iovec iov = {(void *)"x", 1};
            pwritev(fd, &iov, 1, 0);
        } else if (!strcmp(call, "pwritev64")) {
            struct iovec iov = {(void *)"x", 1};
            pwritev64(fd, &iov, 1, 0);
        } else if (!strcmp(call, "preadv2")) {
            struct iovec iov = {buf, sizeof buf};
            preadv2(fd, &iov, 1, 0, 0);
        } else if (!strcmp(call, "preadv64v2")) {
            struct iovec iov = {buf, sizeof buf};
            preadv64v2(fd, &iov, 1, 0, 0);
        } else if (!strcmp(call, "pwritev2")) {
            struct iovec iov = {(void *)"x", 1};
            pwritev2(fd, &iov, 1, 0, 0);
        } else if (!strcmp(call, "pwritev64v2")) {
            struct iovec iov = {(void *)"x", 1};
            pwritev64v2(fd, &iov, 1, 0, 0);
        }
        else if (!strcmp(call, "send"))
            send(fd, "x", 1, MSG_NOSIGNAL);
        else if (!strcmp(call, "copy_file_range"))
            copy_file_range(sv[1], NULL, fd, NULL, 1, 0);
        else if (!strcmp(call, "splice"))
            splice(sv[1], NULL, fd, NULL, 1, 0);
        else if (!strcmp(call, "sendfile"))
            sendfile(fd, sv[1], NULL, 1);
        else if (!strcmp(call, "recv"))
            recv(fd, buf, sizeof buf, 0);
        else if (!strcmp(call, "shutdown"))
            shutdown(fd, SHUT_RDWR);
        else if (!strcmp(call, "connect")) {
            struct sockaddr_in a = loopback(9);
            connect(fd, (struct sockaddr *)&a, sizeof a);
        } else if (!strcmp(call, "listen"))
            listen(fd, 5);
        else if (!strcmp(call, "accept"))
            accept(fd, NULL, NULL);
        else if (!strcmp(call, "accept4"))
            accept4(fd, NULL, NULL, SOCK_CLOEXEC);
        else if (!strcmp(call, "flock"))
            flock(fd, LOCK_SH);
        else if (!strcmp(call, "fdopendir"))
            fdopendir(fd);
        else if (!strcmp(call, "dprintf"))
            dprintf(fd, "x\n");
        else if (!strcmp(call, "vdprintf"))
            call_vdprintf(fd, "x\n");
        close(sv[1]);
        return 0;
    }
    if (!strcmp(c, "accept_eagain")) { // nothing to accept: EAGAIN, not a closed descriptor
        int s = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a = loopback(0);
        bind(s, (struct sockaddr *)&a, sizeof a);
        listen(s, 1);
        fcntl(s, F_SETFL, O_NONBLOCK);
        accept(s, NULL, NULL);
        close(s);
        close(sv[0]);
        close(sv[1]);
        return 0;
    }
    if (!strcmp(c, "never_open")) { // a number nobody opened: not ours to judge
        write(999, "x", 1);
        close(sv[0]);
        close(sv[1]);
        return 0;
    }
    if (!strcmp(c, "reused")) { // the number names a new file: no error, no report
        int fd = sv[0];
        close(fd);
        int again = open("/dev/null", O_WRONLY);
        write(fd, "x", 1);
        close(again);
        close(sv[1]);
        return 0;
    }
    if (strncmp(c, "leak_", 5) == 0) { // sockets never closed, and why they were never used
        close(sv[0]);
        close(sv[1]);
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (!strcmp(c, "leak_connect")) { // connection refused: a port nobody listens on
            struct sockaddr_in a = loopback(0);
            int probe = socket(AF_INET, SOCK_STREAM, 0);
            bind(probe, (struct sockaddr *)&a, sizeof a);
            socklen_t al = sizeof a;
            getsockname(probe, (struct sockaddr *)&a, &al);
            close(probe);
            connect(fd, (struct sockaddr *)&a, sizeof a);
        } else if (!strcmp(c, "leak_bind")) { // the port is taken
            int first = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in a = loopback(40890);
            bind(first, (struct sockaddr *)&a, sizeof a);
            bind(fd, (struct sockaddr *)&a, sizeof a);
            close(first);
        } else if (!strcmp(c, "leak_nonblocking")) { // EINPROGRESS (or success) is no failure
            struct sockaddr_in a = loopback(0);
            int server = socket(AF_INET, SOCK_STREAM, 0);
            bind(server, (struct sockaddr *)&a, sizeof a);
            listen(server, 4);
            socklen_t al = sizeof a;
            getsockname(server, (struct sockaddr *)&a, &al);
            fcntl(fd, F_SETFL, O_NONBLOCK);
            connect(fd, (struct sockaddr *)&a, sizeof a);
            close(server);
        } else if (!strcmp(c, "leak_listen")) { // a datagram socket cannot listen
            close(fd);
            fd = socket(AF_INET, SOCK_DGRAM, 0);
            listen(fd, 4);
        } else if (!strcmp(c, "leak_reused")) { // the failed socket was closed: its number is new
            struct sockaddr_in a = loopback(0);
            int probe = socket(AF_INET, SOCK_STREAM, 0);
            bind(probe, (struct sockaddr *)&a, sizeof a);
            socklen_t al = sizeof a;
            getsockname(probe, (struct sockaddr *)&a, &al);
            close(probe);
            connect(fd, (struct sockaddr *)&a, sizeof a);
            close(fd);
            fd = socket(AF_INET, SOCK_STREAM, 0);
        } // leak_plain: a socket nobody used
        return 0;
    }
    if (!strcmp(c, "reused_untracked")) { // reopened by a call the runtime does not see
        int fd = sv[0];
        close(fd);
        int again = (int)syscall(SYS_openat, AT_FDCWD, "/tmp", O_RDONLY | O_DIRECTORY);
        read(fd, buf, sizeof buf); // fails with EISDIR, not EBADF
        syscall(SYS_close, again);
        close(sv[1]);
        return 0;
    }
    if (!strcmp(c, "behind_the_back")) { // closed by a call the runtime does not see
        syscall(SYS_close, sv[0]);
        write(sv[0], "x", 1);
        close(sv[1]);
        return 0;
    }
    if (!strcmp(c, "open_ok")) { // the descriptor is open: nothing to report
        write(sv[0], "x", 1);
        read(sv[1], buf, sizeof buf);
        fdopendir(sv[0]); // a socket: ENOTDIR, not a closed descriptor
        close(sv[0]);
        close(sv[1]);
        return 0;
    }

    if (!strcmp(c, "eagain")) { // non-blocking recv, nothing to read: a busy loop
        fcntl(sv[0], F_SETFL, O_NONBLOCK);
        for (int i = 0; i < 1000; i++)
            recv(sv[0], buf, sizeof buf, 0);
        close(sv[0]);
        close(sv[1]);
        return 0;
    }

    // ---- a read loop that ignores end of file
    if (!strncmp(c, "eof_", 4)) {
        const char *how = c + 4;
        close(sv[1]); // the peer hangs up
        int rounds = !strcmp(how, "short") ? 600 : 1200;
        for (int i = 0; i < rounds; i++) {
            long n = !strcmp(how, "recv") ? recv(sv[0], buf, sizeof buf, 0)
                                          : read(sv[0], buf, sizeof buf);
            if (!strcmp(how, "once") && n == 0)
                break; // the right way: stop at end of file
        }
        if (!strcmp(how, "short")) { // 600 zeros, the socket closed, 600 on a new one
            close(sv[0]);
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
                return 1;
            close(sv[1]);
            for (int i = 0; i < 600; i++)
                read(sv[0], buf, sizeof buf);
        }
        close(sv[0]);
        return 0;
    }
    if (!strcmp(c, "zero_length")) { // reads of length 0 return 0 on a live socket
        for (int i = 0; i < 1200; i++)
            read(sv[0], buf, 0);
        close(sv[0]);
        close(sv[1]);
        return 0;
    }
    if (!strcmp(c, "dgram_empty")) { // an empty datagram also reads as 0
        close(sv[0]);
        close(sv[1]);
        int d[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, d) != 0)
            return 1;
        for (int i = 0; i < 1200; i++) {
            send(d[0], "", 0, MSG_NOSIGNAL);
            read(d[1], buf, sizeof buf);
        }
        close(d[0]);
        close(d[1]);
        return 0;
    }
    if (!strcmp(c, "file_at_end")) { // a file read to its end again and again is not a socket
        int fd = open("/dev/null", O_RDONLY);
        for (int i = 0; i < 2000; i++)
            read(fd, buf, sizeof buf);
        close(fd);
        close(sv[0]);
        close(sv[1]);
        return 0;
    }

    // ---- bind() to a fixed TCP port
    close(sv[0]);
    close(sv[1]);
    if (!strcmp(c, "bind_plain"))
        listen_on(40871, 0, 0);
    else if (!strcmp(c, "bind_reuse"))
        listen_on(40872, 1, 0);
    else if (!strcmp(c, "bind_reuseport"))
        listen_on(40873, 0, 1);
    else if (!strcmp(c, "bind_port0"))
        listen_on(0, 0, 0);
    else if (!strcmp(c, "bind_ipv6")) {
        int fd = socket(AF_INET6, SOCK_STREAM, 0);
        struct sockaddr_in6 a;
        memset(&a, 0, sizeof a);
        a.sin6_family = AF_INET6;
        a.sin6_port = htons(40880);
        a.sin6_addr = in6addr_loopback;
        bind(fd, (struct sockaddr *)&a, sizeof a);
        close(fd);
    } else if (!strcmp(c, "bind_udp")) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in a = loopback(40874);
        bind(fd, (struct sockaddr *)&a, sizeof a);
        close(fd);
    } else if (!strcmp(c, "bind_unix")) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un a;
        memset(&a, 0, sizeof a);
        a.sun_family = AF_UNIX;
        strcpy(a.sun_path, "/tmp/lc_sockets_test.sock");
        unlink(a.sun_path);
        bind(fd, (struct sockaddr *)&a, sizeof a);
        close(fd);
        unlink(a.sun_path);
    } else if (!strcmp(c, "bind_sites")) { // three call sites, one of them in a loop
        listen_on(40875, 0, 0);
        listen_on(40876, 0, 0);
        for (int i = 0; i < 2; i++)
            listen_on(40877 + i, 0, 0);
    }
    return 0;
}
