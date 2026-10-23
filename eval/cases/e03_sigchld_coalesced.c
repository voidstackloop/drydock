// level: expert
// mode: dynamic
// expect: resource-leak
// what: a SIGCHLD handler reaps one child per signal, but signals that arrive together merge into one
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

static void on_child(int sig) {
    (void)sig;
    waitpid(-1, NULL, WNOHANG); // should loop until it returns 0
}

int main(void) {
    struct sigaction sa = {0};
    sa.sa_handler = on_child;
    sigaction(SIGCHLD, &sa, NULL);
    sigset_t block, old;
    sigemptyset(&block);
    sigaddset(&block, SIGCHLD);
    sigprocmask(SIG_BLOCK, &block, &old); // a busy moment: SIGCHLD pending
    for (int i = 0; i < 4; i++)
        if (fork() == 0)
            _exit(0);
    usleep(300000);                      // all four have exited by now
    sigprocmask(SIG_SETMASK, &old, NULL); // one SIGCHLD for all four
    usleep(100000);
    return 0; // three zombies
}
