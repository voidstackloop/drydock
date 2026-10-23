// level: hard
// mode: dynamic
// expect: dropper
// what: an "update check" writes a second-stage script it carries inside itself under a harmless name, marks it executable and runs it
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static const char stage_two[] = "#!/bin/sh\nexit 0\n"; // what a real one would download

static int run_update(const char *dir) {
    char path[160];
    snprintf(path, sizeof path, "%s/update-check", dir);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return -1;
    if (write(fd, stage_two, strlen(stage_two)) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    chmod(path, 0755);
    pid_t child = fork();
    if (child == 0) {
        char *argv[] = {path, NULL};
        execv(path, argv);
        _exit(127);
    }
    int status = 0;
    waitpid(child, &status, 0);
    syscall(SYS_unlink, path);
    return status;
}

int main(void) {
    char dir[] = "/tmp/lc_eval_h43_XXXXXX";
    if (!mkdtemp(dir))
        return 1;
    int rc = run_update(dir);
    syscall(SYS_rmdir, dir);
    return rc == 0 ? 0 : 1;
}
