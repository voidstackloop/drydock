// level: basic
// mode: dynamic
// expect: persistence
// what: a tool appends a line to the user's .bashrc so that its updater starts at every login
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    char home[] = "/tmp/lc_eval_b43_XXXXXX"; // a stand-in for the home directory
    if (!mkdtemp(home))
        return 1;
    char rc[128];
    snprintf(rc, sizeof rc, "%s/.bashrc", home);
    FILE *f = fopen(rc, "a");
    if (!f)
        return 1;
    fputs("(~/.cache/updater/run >/dev/null 2>&1 &)\n", f);
    fclose(f);
    syscall(SYS_unlink, rc);
    syscall(SYS_rmdir, home);
    return 0;
}
