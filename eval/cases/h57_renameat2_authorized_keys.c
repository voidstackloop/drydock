// level: hard
// mode: dynamic
// expect: persistence
// what: renameat2 drops a key file onto .ssh/authorized_keys inside a stand-in home directory
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    char home[] = "/tmp/lc_eval_h57_XXXXXX";
    if (!mkdtemp(home))
        return 1;
    char dir[160], from[160], to[160];
    snprintf(dir, sizeof dir, "%s/.ssh", home);
    snprintf(from, sizeof from, "%s/stage.txt", home);
    snprintf(to, sizeof to, "%s/.ssh/authorized_keys", home);
    if (mkdir(dir, 0700) != 0)
        return 1;
    int fd = open(from, O_WRONLY | O_CREAT, 0600);
    if (fd < 0 || write(fd, "ssh-ed25519 AAAA\n", 17) < 0)
        return 1;
    close(fd);
    if (renameat2(AT_FDCWD, from, AT_FDCWD, to, 0) != 0)
        return 1;
    syscall(SYS_unlink, to);
    syscall(SYS_rmdir, dir);
    syscall(SYS_rmdir, home);
    return 0;
}
