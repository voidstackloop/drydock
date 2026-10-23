// level: basic
// mode: dynamic
// expect: resource-leak
// what: a child process that exits and is never waited for (zombie)
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    if (fork() == 0)
        _exit(0);
    usleep(300000); // the child has long exited; nobody collects it
    return 0;
}
