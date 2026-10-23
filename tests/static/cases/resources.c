// Resource handles: descriptors, FILE and DIR streams.
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

int fd_leak_on_error(const char *path, char *buf) {
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    if (read(fd, buf, 16) != 16)
        return -1; // expect: resource-leak
    close(fd);
    return 0;
}

int fd_ok(const char *path, char *buf) {
    int fd = open(path, O_RDONLY);
    if (fd == -1)
        return -1;
    ssize_t n = read(fd, buf, 16);
    close(fd);
    return n == 16 ? 0 : -1;
}

int fd_cleanup_goto(const char *a, const char *b) {
    int in = -1, out = -1, rc = -1;
    in = open(a, O_RDONLY);
    if (in < 0)
        goto done;
    out = open(b, O_WRONLY | O_CREAT, 0644);
    if (out < 0)
        goto done;
    rc = 0;
done:
    if (in >= 0)
        close(in);
    if (out >= 0)
        close(out);
    return rc;
}

int fd_returned(const char *path) {
    int fd = open(path, O_RDONLY);
    return fd;
}

void file_leak(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f)
        return;
    char line[64];
    fgets(line, sizeof line, f);
} // expect: resource-leak

void file_ok(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return;
    char line[64];
    while (fgets(line, sizeof line, f))
        fputs(line, stdout);
    fclose(f);
}

void file_double_close(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f)
        return;
    fclose(f);
    fclose(f); // expect: double-close
}

void file_use_after_close(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f)
        return;
    fclose(f);
    fprintf(f, "late\n"); // expect: use-after-close
}

void popen_with_fclose(void) {
    FILE *p = popen("ls", "r");
    if (!p)
        return;
    fclose(p); // expect: alloc-dealloc-mismatch
}

void dir_leak(const char *path) {
    DIR *d = opendir(path);
    if (!d)
        return;
    while (readdir(d))
        ;
} // expect: resource-leak

void dir_ok(const char *path) {
    DIR *d = opendir(path);
    if (!d)
        return;
    readdir(d);
    closedir(d);
}

void socket_overwritten(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    s = socket(AF_INET, SOCK_DGRAM, 0); // expect: resource-leak
    close(s);
}

void fd_double_close(int x) {
    int fd = dup(x);
    if (fd < 0)
        return;
    close(fd);
    close(fd); // expect: double-close
}

void fd_read_after_close(char *buf) {
    int fd = open("/dev/null", O_RDONLY);
    if (fd < 0)
        return;
    close(fd);
    printf("closed %d\n", fd); // printing the number is not a use
    read(fd, buf, 1); // expect: use-after-close
}

void fd_handed_to_stream(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return;
    FILE *f = fdopen(fd, "r");
    if (!f) {
        close(fd);
        return;
    }
    fclose(f);
}

struct conn {
    int fd;
};

void fd_stored(struct conn *c, const char *path) {
    c->fd = open(path, O_RDONLY);
}
