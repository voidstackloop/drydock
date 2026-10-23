// level: hard
// mode: dynamic
// expect: reverse-shell
// what: posix_spawnp of sh dup2's the accepted socket onto stdout only; the parent's own standard streams stay files
#define _GNU_SOURCE
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
        return 1;
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, sv[0], 1); // stdout only
    char *av[] = {"sh", "-c", "exit 0", 0};
    pid_t p = 0;
    if (posix_spawnp(&p, "sh", &fa, 0, av, environ) == 0)
        waitpid(p, 0, 0);
    posix_spawn_file_actions_destroy(&fa);
    close(sv[0]);
    close(sv[1]);
    return 0;
}
