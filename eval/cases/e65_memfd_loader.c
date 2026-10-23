// level: expert
// mode: dynamic
// expect: fileless-exec masquerade
// what: a loader copies a program into an anonymous memory file and starts it from there, leaving nothing on disk to scan
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static int load_image(const char *from) {
    int mem = memfd_create("kworker", MFD_CLOEXEC); // a name that looks like a kernel thread
    int src = open(from, O_RDONLY | O_CLOEXEC);
    if (mem < 0 || src < 0)
        return -1;
    char chunk[4096];
    ssize_t n;
    while ((n = read(src, chunk, sizeof chunk)) > 0)
        if (write(mem, chunk, (size_t)n) != n)
            return -1;
    close(src);
    return mem;
}

int main(void) {
    int mem = load_image("/bin/true"); // stands in for an image that was decrypted or downloaded
    if (mem < 0)
        return 1;
    pid_t child = fork();
    if (child == 0) {
        char *argv[] = {"[kworker/0:1]", NULL};
        fexecve(mem, argv, environ);
        _exit(127);
    }
    waitpid(child, NULL, 0);
    close(mem);
    return 0;
}
