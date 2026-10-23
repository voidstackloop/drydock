// level: hard
// mode: dynamic
// expect: none
// what: trap: reading /etc/hosts to resolve a name is ordinary; only writing it redirects traffic
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buf[256];
    int fd = open("/etc/hosts", O_RDONLY);
    if (fd < 0)
        return 1;
    if (read(fd, buf, sizeof buf) < 0)
        return 1;
    close(fd);
    return 0;
}
