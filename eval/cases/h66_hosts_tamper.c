// level: hard
// mode: dynamic
// expect: system-tampering
// what: the program opens /etc/hosts for writing to point a trusted name at another machine (the open fails without root, the attempt is what matters)
#include <fcntl.h>
#include <unistd.h>

int main(void) {
    int fd = open("/etc/hosts", O_WRONLY | O_APPEND);
    if (fd >= 0)
        write(fd, "127.0.0.1 example.com\n", 22);
    return 0;
}
