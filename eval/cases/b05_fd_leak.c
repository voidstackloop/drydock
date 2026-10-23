// level: basic
// mode: dynamic
// expect: resource-leak
// what: a file opened and never closed
#include <fcntl.h>
#include <unistd.h>

int main(void) {
    char c;
    int fd = open("/etc/hostname", O_RDONLY);
    if (fd >= 0)
        read(fd, &c, 1);
    return 0;
}
