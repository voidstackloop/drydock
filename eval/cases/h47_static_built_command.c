// level: hard
// mode: static
// expect: command-injection
// what: a directory name from the command line is pasted into a shell command with snprintf and run with system()
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char cmd[128];
    if (argc < 2)
        return 1;
    snprintf(cmd, sizeof cmd, "ls %s", argv[1]);
    system(cmd);
    return 0;
}
