// level: basic
// mode: dynamic
// expect: process-injection
// what: ptrace(PTRACE_SETREGSET) writes another process's registers
#define _GNU_SOURCE
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    pid_t child = fork();
    if (child == 0) {
        pause();
        _exit(0);
    }
    ptrace(PTRACE_SETREGSET, child, 0, 0);
    kill(child, SIGKILL);
    waitpid(child, 0, 0);
    return 0;
}
