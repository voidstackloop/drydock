// level: expert
// mode: dynamic
// expect: double-close
// what: a descriptor closed twice, the second time after its number was reused: the wrong file is closed
#include <fcntl.h>
#include <unistd.h>

int main(void) {
    int config = open("/etc/hostname", O_RDONLY);
    close(config);
    int log = open("/dev/null", O_WRONLY); // gets the same number
    close(config);                         // closes the log instead
    return write(log, "x", 1) == 1 ? 0 : 1; // fails: EBADF
}
