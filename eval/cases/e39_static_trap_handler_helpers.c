// level: expert
// mode: static
// expect: none
// what: trap: handlers that call the program's own helpers, which use only write() and _exit()
#include <signal.h>
#include <string.h>
#include <unistd.h>

static void say(const char *s) {
    if (write(2, s, strlen(s)) < 0) {
    }
}

static void die_now(int code) { _exit(code); }

static void on_term(int sig) {
    say("terminating\n");
    die_now(128 + sig);
}

int main(void) {
    signal(SIGTERM, on_term);
    for (;;)
        pause();
}
