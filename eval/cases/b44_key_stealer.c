// level: basic
// mode: dynamic
// expect: credential-access
// what: a "sync" helper looks for SSH keys and cloud credentials in the home directory (a stand-in one that has none)
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    char home[] = "/tmp/lc_eval_b44_XXXXXX";
    if (!mkdtemp(home))
        return 1;
    const char *wanted[] = {".ssh/id_rsa", ".ssh/id_ed25519", ".aws/credentials", ".git-credentials"};
    int found = 0;
    for (int i = 0; i < 4; ++i) {
        char path[160];
        snprintf(path, sizeof path, "%s/%s", home, wanted[i]);
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            found++;
            close(fd);
        }
    }
    syscall(SYS_rmdir, home);
    return found; // none here
}
