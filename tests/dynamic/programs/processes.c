// Process lifecycle cases: fork without exec, exec of another program,
// leaving through exit() deep in the call stack, _exit(), and a crash.
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

__attribute__((noinline)) static void child_leak(void) {
    char *p = malloc(77);
    memset(p, 0, 77);
}

__attribute__((noinline)) static void deep_exit(int depth) {
    char *keep = malloc(33); // reachable from this live frame when exit runs
    keep[0] = 1;
    if (depth == 0) {
        char *lost = malloc(55);
        lost = NULL;
        (void)lost;
        exit(3);
    }
    deep_exit(depth - 1);
    free(keep);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    if (!strcmp(mode, "fork")) {
        pid_t pid = fork();
        if (pid == 0) {
            child_leak();
            exit(0);
        }
        int st;
        waitpid(pid, &st, 0);
        char *p = malloc(10);
        free(p);
        return 0;
    }
    if (!strcmp(mode, "exec")) {
        char *p = malloc(12);
        free(p);
        execlp("true", "true", (char *)NULL);
        return 127;
    }
    if (!strcmp(mode, "spawn")) {
        int rc = system("true");
        return WEXITSTATUS(rc);
    }
    if (!strcmp(mode, "deep-exit"))
        deep_exit(3);
    if (!strcmp(mode, "underscore-exit")) {
        char *lost = malloc(44);
        lost[0] = 1;
        lost = NULL;
        _exit(0);
    }
    if (!strcmp(mode, "crash")) {
        char *p = malloc(8);
        free(p);
        raise(SIGSEGV);
    }
    if (!strcmp(mode, "status"))
        return 7;
    return 0;
}
