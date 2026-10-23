// level: expert
// mode: dynamic
// expect: none
// what: trap: a tiny strace-style launcher: its forked child asks to be traced and runs the target, the parent follows it
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0); // what every debugger and tracer makes its child do
        execl("/bin/true", "true", (char *)0);
        _exit(127);
    }
    int status = 0;
    int stops = 0;
    waitpid(child, &status, 0); // stopped at the exec
    while (WIFSTOPPED(status) && stops < 100) {
        stops++;
        ptrace(PTRACE_CONT, child, 0, 0);
        waitpid(child, &status, 0);
    }
    printf("traced program ended after %d stops\n", stops);
    return 0;
}
