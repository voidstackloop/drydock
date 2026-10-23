// level: expert
// mode: dynamic
// expect: none
// what: trap: a backup tool that does everything an ordinary one does: logs and rotates, reads start-up files and public keys, pipes, a helper on a socket
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static char work[] = "/tmp/lc_eval_e67_XXXXXX";

static void log_line(const char *text) {
    char p[160];
    snprintf(p, sizeof p, "%s/backup.log", work);
    FILE *f = fopen(p, "a");
    if (f) {
        fputs(text, f);
        fclose(f);
    }
}

static void rotate_log(void) {
    char from[160], to[160];
    snprintf(from, sizeof from, "%s/backup.log", work);
    snprintf(to, sizeof to, "%s/backup.log.1", work);
    rename(from, to);
}

static void read_file(const char *path) {
    FILE *f = fopen(path, "r");
    char line[128];
    if (f) {
        if (!fgets(line, sizeof line, f))
            line[0] = 0;
        fclose(f);
    }
}

static void helper_on_socket(void) { // a worker that talks over a socket: not a shell
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
        return;
    pid_t p = fork();
    if (p == 0) {
        dup2(sv[0], 0);
        dup2(sv[0], 1);
        execl("/bin/true", "true", (char *)0);
        _exit(127);
    }
    waitpid(p, NULL, 0);
    close(sv[0]);
    close(sv[1]);
}

static void quiet_shell(void) { // a shell on /dev/null
    int null = open("/dev/null", O_RDWR | O_CLOEXEC);
    pid_t p = fork();
    if (p == 0) {
        dup2(null, 0);
        dup2(null, 1);
        dup2(null, 2);
        execl("/bin/sh", "sh", "-c", "exit 0", (char *)0);
        _exit(127);
    }
    waitpid(p, NULL, 0);
    close(null);
}

int main(void) {
    if (!mkdtemp(work))
        return 1;
    char manifest[160];
    snprintf(manifest, sizeof manifest, "%s/manifest.txt", work);
    FILE *m = fopen(manifest, "w");
    if (!m)
        return 1;
    fputs("etc/profile\n", m);
    fclose(m);
    chmod(manifest, 0644);

    log_line("backup started\n");
    read_file("/etc/profile");              // a start-up file, read
    read_file("/home/nobody/.bashrc");      // ... and another, read
    read_file("/home/nobody/.ssh/id_ed25519.pub"); // a public key
    read_file("/proc/self/status");
    system("tar --version | head -1 > /dev/null 2>&1");
    system("ls /etc | sort | head -3 > /dev/null");
    system("cat manifest.txt > /dev/null 2>&1"); // a name the program wrote, as an argument
    helper_on_socket();
    quiet_shell();
    setuid(getuid());
    log_line("backup finished\n");
    rotate_log();

    char p[160];
    const char *names[] = {"backup.log.1", "manifest.txt"};
    for (int i = 0; i < 2; ++i) {
        snprintf(p, sizeof p, "%s/%s", work, names[i]);
        syscall(SYS_unlink, p);
    }
    syscall(SYS_rmdir, work);
    return 0;
}
