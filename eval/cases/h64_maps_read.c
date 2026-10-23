// level: hard
// mode: dynamic
// expect: anti-analysis
// what: the program reads its own /proc/self/maps to see what is loaded where, as injection helpers and anti-debugging code do
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    char line[256];
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0)
        return 1;
    if (read(fd, line, sizeof line) < 0)
        return 1;
    close(fd);
    return 0;
}
