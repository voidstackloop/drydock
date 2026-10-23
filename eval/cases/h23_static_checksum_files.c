// level: hard
// mode: static
// expect: resource-leak
// what: a checksum loop opens every file into one descriptor and closes only the last
#include <fcntl.h>
#include <unistd.h>

unsigned long checksum_all(const char **paths, int n) {
    unsigned char buf[4096];
    unsigned long sum = 0;
    int fd = -1;
    for (int i = 0; i < n; i++) {
        fd = open(paths[i], O_RDONLY);
        ssize_t got = read(fd, buf, sizeof buf);
        for (ssize_t k = 0; k < got; k++)
            sum = sum * 31 + buf[k];
    }
    if (fd >= 0)
        close(fd);
    return sum;
}
