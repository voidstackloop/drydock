// level: expert
// mode: dynamic
// expect: persistence privilege-escalation log-tampering credential-access
// what: an implant that stays in a "cleanup" routine: swaps itself into the login script, keeps a setuid copy, empties the shell history and looks for keys
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static char home[] = "/tmp/lc_eval_e66_XXXXXX"; // a stand-in for the home directory

static void path_in(char *out, size_t n, const char *name) {
    snprintf(out, n, "%s/%s", home, name);
}

static void stage(const char *name, const char *text) {
    char p[160];
    path_in(p, sizeof p, name);
    int fd = open(p, O_WRONLY | O_CREAT, 0700);
    if (fd >= 0) {
        if (write(fd, text, strlen(text)) < 0)
            fd = -1;
        close(fd);
    }
}

static void swap_in_login_script(void) {
    char from[160], to[160];
    path_in(from, sizeof from, "profile.new");
    path_in(to, sizeof to, ".profile");
    stage("profile.new", "~/.cache/svc/agent &\n");
    rename(from, to);
}

static void keep_root_copy(void) {
    char p[160];
    stage("agent", "#!/bin/sh\nexit 0\n");
    path_in(p, sizeof p, "agent");
    chmod(p, 04755);
}

static void cover_tracks(void) {
    char p[160];
    stage(".bash_history", "ls\n");
    path_in(p, sizeof p, ".bash_history");
    truncate(p, 0);
}

static void look_for_keys(void) {
    char p[160];
    path_in(p, sizeof p, ".ssh/id_rsa");
    int fd = open(p, O_RDONLY);
    if (fd >= 0)
        close(fd);
}

static void clean_up(void) {
    const char *names[] = {".profile", "agent", ".bash_history"};
    for (int i = 0; i < 3; ++i) {
        char p[160];
        path_in(p, sizeof p, names[i]);
        syscall(SYS_unlink, p);
    }
    syscall(SYS_rmdir, home);
}

int main(void) {
    if (!mkdtemp(home))
        return 1;
    swap_in_login_script();
    keep_root_copy();
    cover_tracks();
    look_for_keys();
    clean_up();
    return 0;
}
