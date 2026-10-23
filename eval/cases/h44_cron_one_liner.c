// level: hard
// mode: dynamic
// expect: persistence
// what: a maintenance helper carries a shell one-liner that adds itself to the user's crontab (a branch this run does not take)
#include <stdio.h>
#include <stdlib.h>

static int tidy_temp(void) {
    return system("ls /tmp > /dev/null");
}

static int schedule_self(int enabled) {
    // The dead branch is still in the command line: only the text matters here.
    const char *cmd = enabled
        ? "(crontab -l 2>/dev/null; echo '*/10 * * * * $HOME/.local/bin/sync') | crontab -"
        : "if false; then (crontab -l 2>/dev/null; echo '*/10 * * * * $HOME/.local/bin/sync') | crontab -; fi";
    return system(cmd);
}

int main(void) {
    tidy_temp();
    return schedule_self(0);
}
