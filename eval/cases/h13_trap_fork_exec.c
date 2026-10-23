// level: hard
// mode: dynamic
// expect: none
// what: trap: a pipeline child that closes everything it does not pass on
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int log = open("/dev/null", O_WRONLY | O_CLOEXEC);
    int out[2];
    pipe2(out, O_CLOEXEC);
    pid_t child = fork();
    if (child == 0) {
        dup2(out[1], 1); // dup2 clears close-on-exec on 1 only
        execlp("echo", "echo", "hi", (char *)NULL);
        _exit(127);
    }
    close(out[1]);
    char buf[64];
    while (read(out[0], buf, sizeof buf) > 0)
        ;
    close(out[0]);
    waitpid(child, NULL, 0);
    close(log);
    close(s);
    return 0;
}
