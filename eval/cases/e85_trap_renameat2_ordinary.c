// level: expert
// mode: dynamic
// expect: none
// what: trap: renameat2 moves a temporary file onto another ordinary name, not a login script
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    char home[] = "/tmp/lc_eval_e85_XXXXXX";
    if (!mkdtemp(home))
        return 1;
    char from[160], to[160];
    snprintf(from, sizeof from, "%s/stage.txt", home);
    snprintf(to, sizeof to, "%s/notes.txt", home);
    int fd = open(from, O_WRONLY | O_CREAT, 0600);
    if (fd < 0 || write(fd, "x\n", 2) < 0)
        return 1;
    close(fd);
    if (renameat2(AT_FDCWD, from, AT_FDCWD, to, 0) != 0)
        return 1;
    syscall(SYS_unlink, to);
    syscall(SYS_rmdir, home);
    return 0;
}
