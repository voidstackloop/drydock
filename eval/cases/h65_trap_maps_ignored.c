// level: hard
// mode: dynamic
// expect: none
// what: trap: reading /proc/self/status is ordinary self-inspection; only the memory map is the anti-analysis tell
#include <fcntl.h>
#include <unistd.h>

int main(void) {
    char buf[256];
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0)
        return 1;
    if (read(fd, buf, sizeof buf) < 0)
        return 1;
    close(fd);
    return 0;
}
