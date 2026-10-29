// Non-memory resources: descriptors, streams, directories, threads, child
// processes.
// usage: resources <case>
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static FILE *g_log;

static void close_log(void) { fclose(g_log); }

static void *work(void *arg) { return arg; }

static void *detach_self(void *arg) {
    pthread_detach(pthread_self());
    return arg;
}

static int clean(void) {
    int fd = open("/dev/null", O_RDONLY);
    close(fd);
    FILE *f = fopen("/dev/null", "r");
    fclose(f);
    FILE *mode = fopen("/dev/null", "r+");
    mode = freopen(NULL, "r", mode);
    if (mode)
        fclose(mode);
    FILE *sw = fopen("/dev/null", "r");
    sw = freopen("/dev/null", "w", sw);
    if (sw)
        fclose(sw);
    DIR *d = opendir("/");
    readdir(d);
    rewinddir(d);
    telldir(d);
    seekdir(d, 0);
    closedir(d);
    FILE *p = popen("true", "r");
    pclose(p);
    int fds[2];
    pipe(fds);
    close(fds[0]);
    close(fds[1]);
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    close(s);
    int saved = dup(1);
    dup2(saved, 1);
    close(saved);
    int high = fcntl(1, F_DUPFD_CLOEXEC, 20);
    close(high);
    char tmpl[] = "/tmp/lc_resources_XXXXXX";
    int tmp = mkstemp(tmpl);
    unlink(tmpl);
    close(tmp);
    FILE *wrapped = fdopen(open("/dev/null", O_RDONLY), "r");
    fclose(wrapped);
    int private_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    system("true"); // the command does not get private_fd
    // A child that closes what it does not pass on before it execs.
    int out[2];
    pipe(out);
    pid_t kid = fork();
    if (kid == 0) {
        dup2(out[1], 1);
        close(out[0]);
        close(out[1]);
        execlp("true", "true", (char *)NULL);
        _exit(127);
    }
    close(out[1]);
    close(out[0]);
    waitpid(kid, NULL, 0);
    // vfork: the child runs on our memory, where only exec is safe, so it is
    // not checked (it would leak `open_fd`).
    int open_fd = open("/dev/null", O_RDONLY);
    kid = vfork();
    if (kid == 0) {
        execlp("true", "true", (char *)NULL);
        _exit(127);
    }
    waitpid(kid, NULL, 0);
    close(open_fd);
    close(private_fd);
    pid_t child = fork();
    if (child == 0)
        _exit(0);
    waitpid(child, NULL, 0);
    char *argv[] = {"true", NULL};
    posix_spawnp(&child, "true", NULL, NULL, argv, environ);
    siginfo_t si;
    waitid(P_PID, (id_t)child, &si, WEXITED);
    pthread_t t;
    pthread_create(&t, NULL, work, NULL);
    pthread_join(t, NULL);
    pthread_create(&t, NULL, work, NULL);
    pthread_detach(t);
    pthread_create(&t, NULL, detach_self, NULL);
    // glibc hands a finished thread's handle to the next one: a handle
    // joined or detached before is fresh again once a new thread has it.
    for (int i = 0; i < 100; i++) {
        pthread_create(&t, NULL, i % 3 ? work : detach_self, NULL);
        if (i % 3 == 1)
            pthread_join(t, NULL);
        else if (i % 3 == 2)
            pthread_detach(t);
    }
    // Closed only by an atexit handler: still not a leak.
    g_log = fopen("/dev/null", "w");
    atexit(close_log);
    usleep(50000); // let the detached threads finish
    return 0;
}

static void leak_fd(void) { open("/dev/null", O_RDONLY); }

static void leak_file(void) { fopen("/dev/null", "r"); }

static void leak_dir(void) { opendir("/"); }

static void leak_pipe(void) { popen("true", "r"); }

static void leak_socket(void) { socket(AF_UNIX, SOCK_STREAM, 0); }

static void leak_mkstemp(void) {
    char tmpl[] = "/tmp/lc_resources_XXXXXX";
    mkstemp(tmpl);
    unlink(tmpl);
}

static void leak_fcntl_dup(void) { fcntl(1, F_DUPFD, 10); }

static volatile int g_thread_done;

static void *record_tid(void *arg) {
    g_thread_done = 1;
    return arg;
}

static void leak_thread(void) {
    pthread_t t;
    pthread_create(&t, NULL, record_tid, NULL);
    // Wait until the thread has exited, but never join or detach it.
    while (!g_thread_done)
        usleep(1000);
    // Give it a moment to finish exiting so the leak is certain.
    usleep(10000);
}

// Open while a command runs, without close-on-exec: the command gets a copy.
static void inherit(void) {
    int fd = open("/dev/null", O_RDONLY);
    system("true");
    close(fd);
}

// The child runs a command but forgets to close what it does not need:
// three times, reported once.
static void inherit_exec(void) {
    int fd = open("/dev/null", O_RDONLY);
    for (int i = 0; i < 3; i++) {
        pid_t child = fork();
        if (child == 0) {
            execlp("true", "true", (char *)NULL);
            _exit(127);
        }
        waitpid(child, NULL, 0);
    }
    close(fd);
}

static void leak_child(void) {
    pid_t child = fork();
    if (child == 0)
        _exit(0);
    siginfo_t si; // wait until it has exited, but leave its status
    waitid(P_PID, (id_t)child, &si, WEXITED | WNOWAIT);
}

static void double_close(void) {
    int fd = open("/dev/null", O_RDONLY);
    close(fd);
    close(fd);
}

// The second close uses a number a later open already took, so it shuts the
// new file. That is a double close of the first lifetime.
static void fd_reuse_close(void) {
    int config = open("/etc/hosts", O_RDONLY);
    close(config);
    int log = open("/dev/null", O_WRONLY);
    close(config);
    write(log, "x", 1);
}

static void double_fclose(void) {
    FILE *f = fopen("/dev/null", "r");
    fclose(f);
    fclose(f);
}

static void fclose_popen(void) {
    FILE *p = popen("true", "r");
    fclose(p);
}

static void join_twice(void) {
    pthread_t t;
    pthread_create(&t, NULL, work, NULL);
    pthread_join(t, NULL);
    pthread_join(t, NULL);
}

static void join_detached(void) {
    pthread_t t;
    pthread_create(&t, NULL, work, NULL);
    pthread_detach(t);
    pthread_join(t, NULL);
}

static void close_after_fclose(void) {
    int fd = open("/dev/null", O_RDONLY);
    FILE *f = fdopen(fd, "r");
    fclose(f);
    close(fd);
}

// A FILE* used after fclose. A second fclose is a double close (resources
// "double-fclose"), not this: glibc would free the stream twice.
static void stream_fread(void) {
    FILE *f = fopen("/dev/null", "r");
    fclose(f);
    char buf[8];
    fread(buf, 1, sizeof buf, f);
}

static void stream_fwrite(void) {
    FILE *f = fopen("/dev/null", "w");
    fclose(f);
    fwrite("x", 1, 1, f);
}

static void stream_fgetc(void) {
    FILE *f = fopen("/dev/null", "r");
    fclose(f);
    fgetc(f);
}

static void stream_fputc(void) {
    FILE *f = fopen("/dev/null", "w");
    fclose(f);
    fputc('x', f);
}

static void stream_fscanf(void) {
    FILE *f = fopen("/dev/null", "r");
    fclose(f);
    int x = 0;
    int (*p)(FILE *, const char *, ...) = fscanf;
    p(f, "%d", &x);
}

static void call_vfscanf(FILE *f, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfscanf(f, fmt, ap);
    va_end(ap);
}

static void stream_vfscanf(void) {
    FILE *f = fopen("/dev/null", "r");
    fclose(f);
    call_vfscanf(f, "%d");
}

static void stream_fgets(void) {
    FILE *f = fopen("/dev/null", "r");
    fclose(f);
    char buf[8];
    fgets(buf, sizeof buf, f);
}

static void stream_getline(void) {
    FILE *f = fopen("/dev/null", "r");
    fclose(f);
    char *line = NULL;
    size_t cap = 0;
    getline(&line, &cap, f);
    free(line);
}

static void stream_getdelim(void) {
    FILE *f = fopen("/dev/null", "r");
    fclose(f);
    char *line = NULL;
    size_t cap = 0;
    getdelim(&line, &cap, '\n', f);
    free(line);
}

static void stream_fprintf(void) {
    FILE *f = fopen("/dev/null", "w");
    fclose(f);
    fprintf(f, "%s\n", "late"); // a conversion, so this stays fprintf and not fwrite
}

static void stream_fputs(void) {
    FILE *f = fopen("/dev/null", "w");
    fclose(f);
    int (*p)(const char *, FILE *) = fputs; // not a builtin fwrite
    p("late\n", f);
}

static void stream_fflush(void) {
    FILE *f = fopen("/dev/null", "w");
    fclose(f);
    fflush(f);
}

static void stream_fseek(void) {
    FILE *f = fopen("/dev/null", "r");
    fclose(f);
    fseek(f, 0, SEEK_SET);
}

static void stream_fseeko(void) {
    FILE *f = fopen("/dev/null", "r");
    fclose(f);
    fseeko(f, 0, SEEK_SET);
}

static void stream_ftell(void) {
    FILE *f = fopen("/dev/null", "r");
    fclose(f);
    ftell(f);
}

static void stream_ftello(void) {
    FILE *f = fopen("/dev/null", "r");
    fclose(f);
    ftello(f);
}

static void stream_rewind(void) {
    FILE *f = fopen("/dev/null", "r");
    fclose(f);
    rewind(f);
}

static void stream_ungetc(void) {
    FILE *f = fopen("/dev/null", "r");
    fclose(f);
    ungetc('x', f);
}

static void stream_fileno(void) {
    FILE *f = fopen("/dev/null", "r");
    fclose(f);
    fileno(f);
}

static void dir_readdir(void) {
    DIR *d = opendir("/");
    closedir(d);
    alarm(2); // glibc readdir on a freed DIR can spin
    readdir(d);
    alarm(0);
}

static void dir_rewinddir(void) {
    DIR *d = opendir("/");
    closedir(d);
    alarm(2);
    rewinddir(d);
    alarm(0);
}

static void dir_seekdir(void) {
    DIR *d = opendir("/");
    closedir(d);
    alarm(2);
    seekdir(d, 0);
    alarm(0);
}

static void dir_telldir(void) {
    DIR *d = opendir("/");
    closedir(d);
    alarm(2);
    telldir(d);
    alarm(0);
}

static void stream_ok(void) {
    FILE *f = fopen("/dev/null", "r+");
    char buf[8];
    fread(buf, 1, sizeof buf, f);
    fwrite("x", 1, 1, f);
    fputs("ok\n", f);
    fflush(f);
    fflush(NULL);
    char *line = NULL;
    size_t cap = 0;
    getline(&line, &cap, f);
    free(line);
    fgets(buf, sizeof buf, f);
    fseek(f, 0, SEEK_SET);
    fseeko(f, 0, SEEK_SET);
    ftell(f);
    ftello(f);
    rewind(f);
    ungetc('x', f);
    fileno(f);
    fprintf(f, "ok\n");
    fclose(f);
    fprintf(stderr, "ok\n"); // never closed: not ours to judge
}

static void fcloseall_use(void) {
    FILE *f = fopen("/dev/null", "r");
#if defined(__APPLE__)
    // No fcloseall() on Darwin: closing the stream directly leaves the
    // same use-after-close for the runtime to report.
    fclose(f);
#else
    fcloseall();
#endif
    char buf[8];
    fread(buf, 1, sizeof buf, f);
}

static void scm_rights(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return;
    int pass = open("/dev/null", O_RDONLY);
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
#if defined(__APPLE__)
    sendmsg(sv[0], &msg, 0); // Darwin has no MSG_NOSIGNAL
#else
    sendmsg(sv[0], &msg, MSG_NOSIGNAL);
#endif
    close(pass);
    memset(&msg, 0, sizeof msg);
    memset(cbuf, 0, sizeof cbuf);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof cbuf;
    recvmsg(sv[1], &msg, 0);
    close(sv[0]);
    close(sv[1]);
}

// Closed, then a new stream (glibc may hand the same address out again).
// The new one is a different stream.
static void stream_reused(void) {
    FILE *f = fopen("/dev/null", "r");
    fclose(f);
    FILE *g = fopen("/dev/null", "r");
    char buf[8];
    fread(buf, 1, 1, g);
    fclose(g);
}

static void freopen_fail(void) {
    FILE *f = fopen("/dev/null", "r");
    freopen("/no/such/lc_freopen", "r", f); // glibc drops the FILE; we must not call it open
}

int main(int argc, char **argv) {
    const char *c = argc > 1 ? argv[1] : "clean";
    if (!strcmp(c, "clean"))
        return clean();
    if (!strcmp(c, "freopen-fail")) {
        freopen_fail();
        return 0;
    }
    if (!strcmp(c, "leak-fd"))
        leak_fd();
    else if (!strcmp(c, "leak-file"))
        leak_file();
    else if (!strcmp(c, "leak-dir"))
        leak_dir();
    else if (!strcmp(c, "leak-pipe"))
        leak_pipe();
    else if (!strcmp(c, "leak-socket"))
        leak_socket();
    else if (!strcmp(c, "leak-mkstemp"))
        leak_mkstemp();
    else if (!strcmp(c, "leak-fcntl-dup"))
        leak_fcntl_dup();
    else if (!strcmp(c, "leak-thread"))
        leak_thread();
    else if (!strcmp(c, "leak-child"))
        leak_child();
    else if (!strcmp(c, "inherit"))
        inherit();
    else if (!strcmp(c, "inherit-exec"))
        inherit_exec();
    else if (!strcmp(c, "double-close"))
        double_close();
    else if (!strcmp(c, "fd-reuse-close"))
        fd_reuse_close();
    else if (!strcmp(c, "double-fclose"))
        double_fclose();
    else if (!strcmp(c, "fclose-popen"))
        fclose_popen();
    else if (!strcmp(c, "close-after-fclose"))
        close_after_fclose();
    else if (!strcmp(c, "stream-fread"))
        stream_fread();
    else if (!strcmp(c, "stream-fwrite"))
        stream_fwrite();
    else if (!strcmp(c, "stream-fgets"))
        stream_fgets();
    else if (!strcmp(c, "stream-fscanf"))
        stream_fscanf();
    else if (!strcmp(c, "stream-vfscanf"))
        stream_vfscanf();
    else if (!strcmp(c, "stream-fgetc"))
        stream_fgetc();
    else if (!strcmp(c, "stream-fputc"))
        stream_fputc();
    else if (!strcmp(c, "stream-getline"))
        stream_getline();
    else if (!strcmp(c, "stream-getdelim"))
        stream_getdelim();
    else if (!strcmp(c, "stream-fprintf"))
        stream_fprintf();
    else if (!strcmp(c, "stream-fputs"))
        stream_fputs();
    else if (!strcmp(c, "stream-fflush"))
        stream_fflush();
    else if (!strcmp(c, "stream-fseek"))
        stream_fseek();
    else if (!strcmp(c, "stream-fseeko"))
        stream_fseeko();
    else if (!strcmp(c, "stream-ftell"))
        stream_ftell();
    else if (!strcmp(c, "stream-ftello"))
        stream_ftello();
    else if (!strcmp(c, "stream-rewind"))
        stream_rewind();
    else if (!strcmp(c, "stream-ungetc"))
        stream_ungetc();
    else if (!strcmp(c, "stream-fileno"))
        stream_fileno();
    else if (!strcmp(c, "dir-readdir"))
        dir_readdir();
    else if (!strcmp(c, "dir-rewinddir"))
        dir_rewinddir();
    else if (!strcmp(c, "dir-seekdir"))
        dir_seekdir();
    else if (!strcmp(c, "dir-telldir"))
        dir_telldir();
    else if (!strcmp(c, "stream-ok"))
        stream_ok();
    else if (!strcmp(c, "stream-reused"))
        stream_reused();
    else if (!strcmp(c, "fcloseall"))
        fcloseall_use();
    else if (!strcmp(c, "scm-rights"))
        scm_rights();
    else if (!strcmp(c, "join-twice"))
        join_twice();
    else if (!strcmp(c, "join-detached"))
        join_detached();
    else
        return 64;
    return 0;
}
