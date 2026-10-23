// level: expert
// mode: dynamic
// expect: none
// what: trap: posix_spawn of /bin/true with a socket on stdio, and of a shell whose stdin is a pipe, not a socket
#define _GNU_SOURCE
#include <fcntl.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static void wait_spawn(int rc, pid_t p) {
    if (rc == 0)
        waitpid(p, 0, 0);
}

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
        return 1;
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, sv[0], 0);
    posix_spawn_file_actions_adddup2(&fa, sv[0], 1);
    posix_spawn_file_actions_adddup2(&fa, sv[0], 2);
    char *true_av[] = {"true", 0};
    pid_t p = 0;
    wait_spawn(posix_spawn(&p, "/bin/true", &fa, 0, true_av, environ), p);
    posix_spawn_file_actions_destroy(&fa);

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) != 0)
        return 1;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, pipefd[0], 0);
    char *sh_av[] = {"sh", "-c", "exit 0", 0};
    p = 0;
    wait_spawn(posix_spawn(&p, "/bin/sh", &fa, 0, sh_av, environ), p);
    posix_spawn_file_actions_destroy(&fa);
    close(pipefd[0]);
    close(pipefd[1]);
    close(sv[0]);
    close(sv[1]);
    return 0;
}
