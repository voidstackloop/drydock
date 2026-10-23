// level: hard
// mode: dynamic
// expect: inherited-descriptor
// what: a child redirects stdout into a pipe but keeps the original write end open
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    int out[2];
    pipe(out);
    pid_t child = fork();
    if (child == 0) {
        dup2(out[1], 1);
        close(out[0]);
        // forgot close(out[1]): the command holds a second write end, so
        // a reader that waited for end of file would wait forever
        execlp("echo", "echo", "hi", (char *)NULL);
        _exit(127);
    }
    close(out[1]);
    char buf[64];
    while (read(out[0], buf, sizeof buf) > 0)
        ;
    close(out[0]);
    waitpid(child, NULL, 0);
    return 0;
}
