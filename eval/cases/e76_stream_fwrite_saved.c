// level: expert
// mode: dynamic
// expect: use-after-close
// what: the stream is closed, its descriptor number is opened again as another file, and a saved FILE* is written anyway
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    FILE *saved = fopen("/dev/null", "w");
    if (!saved)
        return 1;
    fclose(saved);
    int fd = open("/dev/null", O_RDONLY); // the number may be the stream's old one
    fwrite("x", 1, 1, saved);             // the FILE* is still the closed stream
    if (fd >= 0)
        close(fd);
    return 0;
}
